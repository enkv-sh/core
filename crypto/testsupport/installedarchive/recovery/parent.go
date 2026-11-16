package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type PrivateDecryptFactory func(context.Context, installedarchive.Archive, installedarchive.RecoveryInput) (func([]byte) ([]byte, error), func(), error)

func RunParent(t *testing.T, family contract.Family, name string) { runParent(t, family, name, nil) }
func RunParentWithPrivateDecrypt(t *testing.T, family contract.Family, name string, factory PrivateDecryptFactory, live ...LiveParentConstructors) {
	if path := os.Getenv("ENKV_RECOVERY_LIVE_PARENT_INPUT"); path != "" {
		if len(live) != 1 {
			t.Fatal("ordinary live Store constructor unavailable")
		}
		runLiveParent(t, family, name, path, live[0].Store, factory, live[0].Credentials)
		return
	}
	runParent(t, family, name, factory)
}
func runParent(t *testing.T, family contract.Family, name string, factory PrivateDecryptFactory) {
	provider := "aws"
	if family == contract.GCP {
		provider = "gcp"
	}
	var resources installedarchive.RecoveryResources
	if path := os.Getenv("ENKV_RECOVERY_PARENT_RESOURCES"); path != "" {
		ReadParentJSON(t, path, &resources)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	} else {
		resources.Normal = fixedSigningResource(t, family)
	}
	archive := installedarchive.Load(t, provider)
	values := []installedarchive.ExpectedValue{{Name: "installed-positive-secret", Bytes: []byte("enkv first secret test value")}}
	secrets := 1
	var oracles []installedarchive.PrivateValue
	if path := os.Getenv("ENKV_RECOVERY_PARENT_FIXTURE"); path != "" {
		fixture := installedarchive.ReadRecoveryFixture(t, path)
		archive, values, secrets, oracles = fixture.Archive, fixture.Values, fixture.Secrets, fixture.Oracles
	}
	wantSecrets := installedarchive.RecoverySecretCount(os.Getenv("ENKV_RECOVERY_PARENT_CONDITION"))
	if len(oracles) > 0 && os.Getenv("ENKV_RECOVERY_PARENT_CONDITION") == "complete" {
		wantSecrets = 3
	}
	if os.Getenv("ENKV_RECOVERY_PARENT_FIXTURE") != "" && secrets != wantSecrets {
		t.Fatal("writer secret count differs from independent case")
	}
	if resources.Location.Provider.Valid() && resources.Location != archive.Location {
		t.Fatal("writer changed independently chosen console location")
	}
	if !resources.Location.Provider.Valid() {
		resources.Location = archive.Location
	}
	authorityIndex := 0
	if history, ok := installedarchive.ReplacementFor(os.Getenv("ENKV_RECOVERY_PARENT_CONDITION")); ok {
		normal, recovery, authority, nextKey := 0, 0, 0, 2
		if resources.RecoveryEnabled {
			nextKey = 3
		}
		for _, step := range history.Steps {
			if step.Mask&1 != 0 {
				normal++
			}
			if step.Mask&4 != 0 && step.Operation != 2 {
				recovery++
			}
			if step.Mask&2 != 0 {
				authority = nextKey
				nextKey++
			}
			if step.Mask&8 != 0 {
				nextKey++
			}
		}
		if normal != 0 {
			resources.Normal = resources.NormalSuccessors[normal-1]
		}
		if recovery != 0 {
			resources.Recovery = resources.RecoverySuccessors[recovery-1]
		}
		authorityIndex = authority
		if authority >= len(resources.AuthorityPublicKeys) || !bytes.Equal(archive.AuthorityBinding.SPKI, resources.AuthorityPublicKeys[authority]) {
			t.Fatal("writer changed independently expected Authority key")
		}
	}
	if len(resources.AuthorityPublicKeys) != 0 && !bytes.Equal(archive.AuthorityBinding.SPKI, resources.AuthorityPublicKeys[authorityIndex]) {
		t.Fatal("writer changed independently expected Authority key")
	}
	if archive.SignerSelector != resources.Normal.Selector || !bytes.Equal(archive.SignerPublicKey, resources.Normal.PublicKey) {
		t.Fatal("writer changed independently chosen normal resource")
	}
	condition := os.Getenv("ENKV_RECOVERY_PARENT_CONDITION")
	remoteArchive := archive
	if condition == "copied-location" {
		remoteArchive = copiedLocationArchive(archive)
	}
	responder := NewRecoveryResponder(t, remoteArchive, resources)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("bounded recovery requests: %v; counts: %+v", responder.Requests(), responder.Counts())
		}
	})
	base := t.TempDir()
	cwd, home, temporary := filepath.Join(base, "cwd"), filepath.Join(base, "home"), filepath.Join(base, "tmp")
	for _, directory := range []string{cwd, home, temporary} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	input := installedarchive.RecoveryInput{Provider: provider, Bucket: resources.Location.Bucket, Region: resources.Location.Region, Prefix: resources.Location.PrefixBeforeHEAD,
		NormalSigner: resources.Normal.Selector, NormalRegion: resources.Normal.Region, ReadRoute: "new-console-read", SignRoute: "new-console-sign", PrivateRoute: "new-console-private",
		AccessKey: "AKIDFIXTURE", SecretKey: "fixture-secret", TimeoutMillis: 10000, Output: filepath.Join(cwd, "returned.json"), Responder: responder.Address(), TLSCertificate: responder.Certificate()}
	if family == contract.GCP {
		input.AccessKey, input.SecretKey, input.Token = "", "", "restricted-test-token"
		input.TLSCertificate = nil
	}
	policy, refused := configureCondition(t, condition, &input, resources.Normal.Selector, resources.Recovery.Selector, resources.Recovery.Region)
	if condition == "selected-object-disappears" {
		parts, err := archive.SelectedParts()
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range parts {
			if part.Kind == "value page" {
				policy.RemoveObjectAfterPublic, err = format.Key(archive.Location.PrefixBeforeHEAD, part.Ref)
				break
			}
		}
		if err != nil || policy.RemoveObjectAfterPublic == "" {
			t.Fatal("controlled external object mutation missing")
		}
	}
	responder.SetPolicy(policy)
	if condition == "prior-domain-pin" {
		input.ExpectedDomain = &resources.PriorDomain
	}
	if condition == "matching-domain-pin" {
		if resources.Domain.IsZero() {
			t.Fatal("independent Domain pin missing")
		}
		input.ExpectedDomain = &resources.Domain
	}
	if condition == "matching-kek-pin" {
		input.ExpectedKEK = archive.AuthorityBinding.KeySelector
	}
	before, err := responder.RemoteBytes()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.v=test2json", "-test.count=1", "-test.run=^"+name+"$")
	command.Dir = cwd
	command.Env = RecoveryEnvironment(home, temporary)
	command.Stdin = bytes.NewReader(encoded)
	var output installedarchive.ChildOutput
	command.Stdout, command.Stderr = &output, &output
	childErr := command.Run()
	if path := os.Getenv("ENKV_RECOVERY_CHILD_TERMINALS"); path != "" {
		if err := os.WriteFile(path, output.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := childErr; err != nil {
		t.Fatal("restricted provider child did not join successfully", err, string(output.Bytes()))
	}
	if err := output.Completed(name); err != nil {
		t.Fatal(err, string(output.Bytes()))
	}
	t.Logf("restricted child terminals:\n%s", output.Bytes())
	counts := responder.Counts()
	if refused == nil {
		wantNormal, wantRecovery := uint64(1), uint64(0)
		history, replaced := installedarchive.ReplacementFor(condition)
		if condition == "recovery-proof-recovery-only" || condition == "recovery-proof-both" || replaced && len(history.Steps) > 0 && history.Steps[len(history.Steps)-1].Approval == 2 && history.Steps[len(history.Steps)-1].Mask&1 == 0 {
			wantNormal, wantRecovery = 0, 1
		}
		if condition == "adequate-anchor-fallback" {
			wantRecovery = 1
		}
		if counts.Reads == 0 || counts.NormalLookups != wantNormal || counts.RecoveryLookups != wantRecovery || counts.PublicLookups != wantNormal+wantRecovery || counts.RecoveryMetadata != wantRecovery || counts.AuthorityDecrypts != uint64(secrets) {
			t.Fatal("restricted provider required calls missing", counts)
		}
	}
	if refused != nil {
		wantNormal, wantRecovery, wantMetadata, wantDecrypts := uint64(0), uint64(0), uint64(0), uint64(0)
		switch condition {
		case "required-public-denied":
			wantNormal = 1
		case "required-authority-denied", "recovery-key-only":
			wantNormal, wantDecrypts = 1, 1
		case "later-secret-denied":
			wantNormal, wantDecrypts = 1, 5
		case "wrong-kek-pin", "selected-object-disappears":
			wantNormal = 1
		}
		if counts.NormalLookups != wantNormal || counts.RecoveryLookups != wantRecovery || counts.RecoveryMetadata != wantMetadata || counts.AuthorityDecrypts != wantDecrypts || counts.PublicLookups != wantNormal+wantRecovery {
			t.Fatal("refusal used unexpected required or unused routes", counts)
		}
	}
	allowed := counts
	allowed.Reads, allowed.PublicLookups, allowed.AuthorityDecrypts, allowed.NormalLookups, allowed.RecoveryLookups, allowed.RecoveryMetadata = 0, 0, 0, 0, 0, 0
	after, err := responder.RemoteBytes()
	if err != nil {
		t.Fatal(err)
	}
	expectedAfter := before
	if condition == "selected-object-disappears" {
		expectedAfter, err = remoteBytes(withoutRemoteObject(remoteArchive, policy.RemoveObjectAfterPublic), resources, policy)
		if err != nil || responder.ExternalMutations() != 1 {
			t.Fatal("controlled external mutation did not occur", err)
		}
	}
	if allowed != (installedarchive.RecoveryCounts{}) || !bytes.Equal(expectedAfter, after) {
		t.Fatal("restricted provider remote effects", counts)
	}
	if directory := os.Getenv("ENKV_RECOVERY_RETAINED_OBSERVATIONS"); directory != "" {
		body, err := os.ReadFile(input.Output)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "returned-observations.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "restricted-input.json"), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "remote-before.json"), before, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "remote-after.json"), after, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var opened uint32
	var oracleCounts installedarchive.RecoveryCounts
	if refused != nil {
		if err := CheckRefusedResult(input.Output, *refused); err != nil {
			t.Log(err)
			t.Fatal("bounded refusal differs")
		}
	} else {
		if len(oracles) > 0 {
			if factory == nil {
				t.Fatal("private provider oracle absent")
			}
			responder.StartOracleEpoch()
			decrypt, closeOracle, createErr := factory(t.Context(), archive, input)
			if createErr != nil || decrypt == nil || closeOracle == nil {
				t.Fatal("private provider oracle construction refused")
			}
			opened, err = CheckReturnedPartsWithPrivateOracle(archive, input.Output, oracles, decrypt)
			closeOracle()
			oracleCounts = responder.Counts()
			allowedOracle := oracleCounts
			allowedOracle.AuthorityDecrypts = 0
			if allowedOracle != (installedarchive.RecoveryCounts{}) || oracleCounts.AuthorityDecrypts != uint64(secrets) {
				t.Fatal("private oracle epoch differs", oracleCounts)
			}
		} else {
			opened, err = CheckReturnedParts(archive, input.Output, values)
		}
		if err != nil || opened != uint32(secrets) {
			t.Fatal("exited provider child's private content", opened, err)
		}
	}
	if path := os.Getenv("ENKV_RECOVERY_PARENT_REPORT"); path != "" {
		body, err := json.Marshal(installedarchive.RecoveryReport{ChildStarted: true, ChildJoined: true, ChildTerminalsSHA256: fmt.Sprintf("%x", sha256.Sum256(output.Bytes())), Counts: counts, OracleCounts: oracleCounts, Opened: int(opened), RemoteEffectsZero: true, ExternalMutations: responder.ExternalMutations(), OracleEpochSeparate: true, Refused: refused != nil, Result: func() installedarchive.RecoveryResult {
			if refused != nil {
				return *refused
			}
			return ObservedResult{Outcome: 2, Evidence: 1}
		}()})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if path := os.Getenv("ENKV_RECOVERY_PUBLICATION_CONTINUATION"); path != "" {
		if refused != nil || condition != "complete" || secrets != 5 || opened != 5 || !resources.Location.Provider.Valid() {
			t.Fatal("publication continuation requires complete verified recovery")
		}
		continuation, err := verifiedPublicationContinuation(archive, input.Output)
		if err != nil {
			t.Fatal("verified publication continuation", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("fresh publication continuation carrier unavailable")
		}
		encodeErr := json.NewEncoder(file).Encode(continuation)
		closeErr := file.Close()
		if encodeErr != nil || closeErr != nil {
			t.Fatal("publication continuation carrier incomplete")
		}
	}
	if len(oracles) == 0 && responder.Counts() != counts {
		t.Fatal("parent private oracle used recovery epoch")
	}
}

func verifiedPublicationContinuation(archive installedarchive.Archive, path string) (installedarchive.PublicationLossContinuation, error) {
	headObject, ok := archive.Object(archive.Location.PrefixBeforeHEAD + "/HEAD")
	head, err := format.DecodeHead(headObject.Body)
	parts, partsErr := archive.SelectedParts()
	if !ok || err != nil || partsErr != nil || archive.HeadDigest != contract.Hash(headObject.Body) {
		return installedarchive.PublicationLossContinuation{}, fmt.Errorf("verified archive selection unavailable")
	}
	provenance := Provenance{Domain: archive.Domain, Revision: archive.Revision, Snapshot: head.Core.Root.Object, HEADDigest: archive.HeadDigest, HEADToken: headObject.Token}
	want, err := json.Marshal(Observation{Provenance: provenance, Parts: parts, Result: ObservedResult{Outcome: 2, Evidence: 1}})
	if err != nil {
		return installedarchive.PublicationLossContinuation{}, err
	}
	want = append(want, '\n')
	file, err := os.Open(path)
	if err != nil {
		return installedarchive.PublicationLossContinuation{}, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, int64(len(want))+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(body, want) {
		return installedarchive.PublicationLossContinuation{}, fmt.Errorf("verified observation unavailable")
	}
	return installedarchive.PublicationLossContinuation{Location: archive.Location, Domain: provenance.Domain, Revision: provenance.Revision, Snapshot: provenance.Snapshot, HEADDigest: provenance.HEADDigest, HEADToken: provenance.HEADToken, Parts: parts, Result: ObservedResult{Outcome: 2, Evidence: 1}, Objects: archive.Objects}, nil
}

func copiedLocationArchive(archive installedarchive.Archive) installedarchive.Archive {
	// Keep the authenticated location unchanged so reconstruction refuses the copy.
	archive.Objects = append([]installedarchive.Object(nil), archive.Objects...)
	archive.ObjectFileBytes = 0
	for i := range archive.Objects {
		object := &archive.Objects[i]
		object.Key = archive.Location.PrefixBeforeHEAD + "-copied" + strings.TrimPrefix(object.Key, archive.Location.PrefixBeforeHEAD)
		archive.ObjectFileBytes += uint64(28) + uint64(len(object.Key)) + uint64(len(object.TokenWire)) + uint64(len(object.Body))
	}
	return archive
}
