package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

type LiveCredentialFactory func(context.Context, *installedarchive.LiveRecoveryParentInput) error
type LiveParentConstructors struct {
	Store       LiveStoreFactory
	Credentials LiveCredentialFactory
}

type LiveStoreFactory func(context.Context, installedarchive.RecoveryInput, contract.ID) (contract.Store, func(), error)

type parentReadRelay interface {
	Address() string
	Certificate() []byte
	Evidence() ReadTransportEvidence
	ExternalMutations() uint8
}

func liveParentRelay(t testing.TB, input installedarchive.RecoveryInput, resources installedarchive.RecoveryResources, authority string, policy ResponderPolicy, removal *ExactRemoval, afterPublic func(context.Context) error) (parentReadRelay, error) {
	if input.Provider == "gcp" {
		return NewGCPReadRelay(t, GCPRelayConfig{Bucket: input.Bucket, Prefix: input.Prefix, Region: input.Region, Normal: resources.Normal, Recovery: resources.Recovery, AuthoritySelector: authority, Requests: input.Requests, BodyBytes: input.BodyBytes, ResponseBytes: input.ResponseBytes, Policy: policy, Removal: removal, AfterPublic: afterPublic})
	}
	parts := strings.Split(authority, ":")
	if len(parts) != 6 {
		return nil, errors.New("parent Authority resource refused")
	}
	return NewAWSReadRelay(t, AWSRelayConfig{Bucket: input.Bucket, Prefix: input.Prefix, Region: input.Region, Normal: resources.Normal, Recovery: resources.Recovery, AuthoritySelector: authority, AuthorityRegion: parts[3], Requests: input.Requests, BodyBytes: input.BodyBytes, ResponseBytes: input.ResponseBytes, Policy: policy, Removal: removal, AfterPublic: afterPublic})
}

func checkLiveRemoteObjects(ctx context.Context, store contract.Store, archive installedarchive.Archive, relay parentReadRelay) error {
	for index, object := range archive.Objects {
		if len(object.Body) == 0 || len(object.Body) > 32<<20 {
			return errors.New("parent object length refused")
		}
		observed := store.Read(ctx, object.Key, uint32(len(object.Body)))
		if observed.Status != contract.ReadOK || observed.Token != object.Token || !bytes.Equal(observed.Body, object.Body) {
			return liveSnapshotReadFailure(ctx, index, contract.ReadOK, observed, object, relay)
		}
	}
	return nil
}

func liveSnapshotReadFailure(ctx context.Context, index int, expected contract.ReadStatus, observed contract.ReadResult, object installedarchive.Object, relay parentReadRelay) error {
	contextErr := ctx.Err()
	facts := relay.Evidence()
	return fmt.Errorf("parent snapshot read differs: object=%d expected_status=%d status=%d reason=%d context_cancelled=%t context_deadline=%t token_match=%t body_match=%t observed_bytes=%d expected_bytes=%d attempted=%+v sent=%+v refused=%+v injected=%+v failures=%d reserved_requests=%d reserved_bytes=%d", index, expected, observed.Status, observed.Reason, errors.Is(contextErr, context.Canceled), errors.Is(contextErr, context.DeadlineExceeded), observed.Token == object.Token, bytes.Equal(observed.Body, object.Body), len(observed.Body), len(object.Body), facts.Attempted, facts.Sent, facts.Refused, facts.Injected, facts.Failures, facts.ReservedRequests, facts.ReservedBytes)
}

// RunLiveParentControl exercises the same parent and ordinary child with only
// the parent relay's upstream TCP route changed to the local fixture owner.
func RunLiveParentControl(t *testing.T, family contract.Family, name, path string, storeFactory LiveStoreFactory, oracleFactory PrivateDecryptFactory) {
	t.Helper()
	if family != contract.AWS && family != contract.GCP {
		t.Fatal("local live-parent control family refused")
	}
	runLiveParent(t, family, name, path, storeFactory, oracleFactory, nil, true)
}

func runLiveParent(t *testing.T, family contract.Family, name, path string, storeFactory LiveStoreFactory, oracleFactory PrivateDecryptFactory, credentialFactory LiveCredentialFactory, localControl ...bool) {
	t.Helper()
	if storeFactory == nil || oracleFactory == nil {
		t.Fatal("ordinary live parent constructors unavailable")
	}
	var owner installedarchive.LiveRecoveryParentInput
	ReadParentJSON(t, path, &owner)
	if err := os.Remove(path); err != nil {
		t.Fatal("private parent input retirement failed")
	}
	if credentialFactory != nil {
		if err := credentialFactory(t.Context(), &owner); err != nil {
			t.Fatal("explicit live working credentials refused")
		}
	}
	fixture := installedarchive.ReadRecoveryFixture(t, owner.Fixture)
	archive, resources := fixture.Archive, owner.Resources
	if !owner.Locations.Valid(owner.Condition, resources.Location.PrefixBeforeHEAD, resources.Domain) || owner.Locations.PriorDomain != (contract.ID{}) && owner.Locations.PriorDomain != resources.PriorDomain || archive.Family != family || archive.Domain != resources.Domain || archive.Location != resources.Location || archive.SignerSelector != resources.Normal.Selector || !bytes.Equal(archive.SignerPublicKey, resources.Normal.PublicKey) || archive.AuthorityBinding.KeySelector != owner.AuthoritySelector || !bytes.Equal(archive.AuthorityBinding.SPKI, owner.AuthorityPublicKey) || len(fixture.Oracles) != len(archiveMustNames(t, archive)) || len(fixture.Values) != 0 {
		t.Fatal("writer differs from independent live resources or capture")
	}
	control := len(localControl) == 1 && localControl[0]
	if len(localControl) > 1 {
		t.Fatal("parent control selection refused")
	}
	var upstream *http.Transport
	var remote *RecoveryResponder
	if control {
		remote = newRecoveryResponder(t, archive, resources, true)
		var err error
		upstream, err = GCPResponderTransport(remote.Address(), remote.Certificate())
		if err != nil {
			t.Fatal("local upstream transport refused")
		}
		defer upstream.CloseIdleConnections()
	}
	makeRelay := func(input installedarchive.RecoveryInput, policy ResponderPolicy, removal *ExactRemoval, afterPublic func(context.Context) error) (parentReadRelay, error) {
		if !control {
			return liveParentRelay(t, input, resources, owner.AuthoritySelector, policy, removal, afterPublic)
		}
		if family == contract.GCP {
			transport, err := newGCPReadTransport(upstream.Clone(), input.Bucket, input.Prefix, input.Region, resources.Normal.Selector, resources.Recovery.Selector, input.Requests, input.BodyBytes, input.ResponseBytes)
			if err != nil {
				return nil, err
			}
			return newGCPReadRelay(t, GCPRelayConfig{Bucket: input.Bucket, Prefix: input.Prefix, Region: input.Region, Normal: resources.Normal, Recovery: resources.Recovery, AuthoritySelector: owner.AuthoritySelector, Requests: input.Requests, BodyBytes: input.BodyBytes, ResponseBytes: input.ResponseBytes, Policy: policy, Removal: removal, AfterPublic: afterPublic}, transport)
		}
		parts := strings.Split(owner.AuthoritySelector, ":")
		if len(parts) != 6 {
			return nil, errors.New("local Authority resource refused")
		}
		return newAWSReadRelay(t, AWSRelayConfig{Bucket: input.Bucket, Prefix: input.Prefix, Region: input.Region, Normal: resources.Normal, Recovery: resources.Recovery, AuthoritySelector: owner.AuthoritySelector, AuthorityRegion: parts[3], Requests: input.Requests, BodyBytes: input.BodyBytes, ResponseBytes: input.ResponseBytes, Policy: policy, Removal: removal, AfterPublic: afterPublic}, upstream.Clone())
	}
	input := owner.Input
	requestAllowance, byteAllowance := input.Requests, input.BodyBytes
	input.ExpectedDomain, input.ExpectedKEK = nil, ""
	input.Bucket, input.Region, input.Prefix = resources.Location.Bucket, resources.Location.Region, resources.Location.PrefixBeforeHEAD
	input.NormalSigner, input.NormalRegion = resources.Normal.Selector, resources.Normal.Region
	input.RecoverySigner, input.RecoveryRegion = "", ""
	if input.Provider == "aws" && family != contract.AWS || input.Provider == "gcp" && family != contract.GCP || input.Requests == 0 || input.Requests > 4096 || input.ResponseBytes == 0 || input.ResponseBytes > 8<<20 || input.BodyBytes < input.ResponseBytes {
		t.Fatal("parent live provider or finite allowance refused")
	}
	// Four fixed epochs share one cumulative allowance by reserving disjoint
	// portions before the first request. Unused portions are not transferred.
	epochs := uint64(4)
	if owner.Condition == "selected-object-disappears" {
		epochs = 5
	}
	input.Requests /= epochs
	input.BodyBytes /= epochs
	if input.Requests == 0 || input.BodyBytes < input.ResponseBytes {
		t.Fatal("live recovery cumulative allowance is insufficient")
	}
	policy, refused := configureCondition(t, owner.Condition, &input, resources.Normal.Selector, resources.Recovery.Selector, resources.Recovery.Region)
	if owner.ProviderDenial {
		switch owner.Condition {
		case "required-public-denied":
			policy.DenyNormal = false
		case "required-authority-denied", "recovery-key-only":
			policy.DenyAuthority = false
		default:
			t.Fatal("parent credential-denial condition refused")
		}
	}

	if owner.Condition == "prior-domain-pin" {
		input.ExpectedDomain = &owner.Locations.PriorDomain
	}
	if owner.Condition == "copied-location" {
		input.Prefix = owner.Locations.CopiedPrefix
	}
	if owner.Condition == "matching-domain-pin" {
		input.ExpectedDomain = &resources.Domain
	}
	if owner.Condition == "matching-kek-pin" {
		input.ExpectedKEK = owner.AuthoritySelector
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, object := range archive.Objects {
		if _, _, ok := owner.Locations.Target(family, resources.Location.PrefixBeforeHEAD, resources.Domain, object.Key); !ok || len(object.Body) == 0 || len(object.Body) > 32<<20 || !object.Token.Valid() {
			t.Fatal("recorded snapshot ownership refused")
		}
	}
	// Snapshot and oracle transports have their own client caches and epochs.
	snapshot := func(removed string) ReadTransportEvidence {
		observed := input
		observed.Bucket, observed.Region, observed.Prefix, observed.Owner = resources.Location.Bucket, resources.Location.Region, resources.Location.PrefixBeforeHEAD, resources.Location.ExpectedOwner
		relay, err := makeRelay(observed, ResponderPolicy{}, nil, nil)
		if err != nil {
			t.Fatal("parent snapshot transport refused")
		}
		observed.Responder, observed.TLSCertificate = relay.Address(), relay.Certificate()
		type snapshotStore struct {
			prefix string
			domain contract.ID
			store  contract.Store
			close  func()
		}
		var stores []snapshotStore
		defer func() {
			for _, owned := range stores {
				owned.close()
			}
		}()
		for index, object := range archive.Objects {
			prefix, domain, ok := owner.Locations.Target(family, resources.Location.PrefixBeforeHEAD, resources.Domain, object.Key)
			if !ok {
				t.Fatal("recorded snapshot target refused")
			}
			var store contract.Store
			for _, owned := range stores {
				if owned.prefix == prefix && owned.domain == domain {
					store = owned.store
					break
				}
			}
			if store == nil {
				location := observed
				location.Prefix = prefix
				created, closeStore, err := storeFactory(ctx, location, domain)
				if err != nil || created == nil || closeStore == nil {
					t.Fatal("ordinary parent snapshot constructor refused")
				}
				stores = append(stores, snapshotStore{prefix, domain, created, closeStore})
				store = created
			}
			single := archive
			single.Objects = []installedarchive.Object{object}
			if removed == object.Key {
				if observed := store.Read(ctx, object.Key, uint32(len(object.Body))); observed.Status != contract.ReadMissing {
					t.Fatal("independently expected removal missing", liveSnapshotReadFailure(ctx, index, contract.ReadMissing, observed, object, relay))
				}
			} else if err := checkLiveRemoteObjects(ctx, store, single, relay); err != nil {
				t.Fatal("complete remote object state changed", index, err)
			}
		}
		facts := relay.Evidence()
		allowed := facts.Attempted
		allowed.Reads, allowed.Authentication = 0, 0
		if allowed != (RecoveryCounts{}) || facts.Refused != (RecoveryCounts{}) || facts.Injected != (RecoveryCounts{}) || facts.Failures != 0 || facts.Sent.Reads != uint64(len(archive.Objects)) {
			t.Fatal("parent snapshot epoch incomplete")
		}
		return facts
	}
	before := snapshot("")
	var mutation ReadTransportEvidence
	var removal *ExactRemoval
	var mutate func(context.Context) error
	if owner.Condition == "selected-object-disappears" {
		parts, err := archive.SelectedParts()
		if err != nil {
			t.Fatal("selected mutation reference unavailable")
		}
		for _, part := range parts {
			if part.Kind != "value page" {
				continue
			}
			key, err := format.Key(resources.Location.PrefixBeforeHEAD, part.Ref)
			if err != nil {
				t.Fatal("selected mutation target refused")
			}
			for _, object := range archive.Objects {
				if object.Key == key {
					removal = &ExactRemoval{Key: key, Token: object.Token}
					break
				}
			}
			break
		}
		if removal == nil || !removal.valid(family, resources.Location.PrefixBeforeHEAD) {
			t.Fatal("selected mutation object unavailable")
		}
		if remote != nil && remote.AllowRemoval(*removal) != nil {
			t.Fatal("fixture mutation admission refused")
		}
		mutationInput := input
		mutationInput.Prefix, mutationInput.Owner = resources.Location.PrefixBeforeHEAD, resources.Location.ExpectedOwner
		mutationRelay, err := makeRelay(mutationInput, ResponderPolicy{}, removal, nil)
		if err != nil {
			t.Fatal("separate mutation transport refused")
		}
		mutationInput.Responder, mutationInput.TLSCertificate = mutationRelay.Address(), mutationRelay.Certificate()
		store, closeStore, err := storeFactory(ctx, mutationInput, resources.Domain)
		if err != nil || store == nil || closeStore == nil {
			t.Fatal("ordinary mutation Store unavailable")
		}
		defer closeStore()
		deleter, ok := store.(contract.ConditionalDeleteStore)
		if !ok {
			t.Fatal("ordinary conditional deletion unavailable")
		}
		mutate = func(ctx context.Context) error {
			result := deleter.DeleteIfToken(ctx, removal.Key, removal.Token)
			mutation = mutationRelay.Evidence()
			allowed := mutation.Sent
			allowed.Delete, allowed.Authentication = 0, 0
			if result.Status != contract.WriteAcknowledged || allowed != (RecoveryCounts{}) || mutation.Attempted != mutation.Sent || mutation.Sent.Delete != 1 || mutation.Refused != (RecoveryCounts{}) || mutation.Injected != (RecoveryCounts{}) || mutation.Failures != 0 {
				return errors.New("exact external deletion was not acknowledged")
			}
			return nil
		}
	}
	directGCP := family == contract.GCP && policy == (ResponderPolicy{}) && mutate == nil && !control
	var relay parentReadRelay
	if !directGCP {
		var err error
		relay, err = makeRelay(input, policy, nil, mutate)
		if err != nil {
			t.Fatal("reconstruction transport refused")
		}
	}
	base := t.TempDir()
	cwd, home, temporary := filepath.Join(base, "cwd"), filepath.Join(base, "home"), filepath.Join(base, "tmp")
	for _, directory := range []string{cwd, home, temporary} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal("restricted child directory creation failed")
		}
	}
	if input.NormalSigner == "" {
		input.NormalAccessKey, input.NormalSecretKey, input.NormalSessionToken, input.NormalServiceAccountFile = "", "", "", ""
	}
	if input.RecoverySigner == "" {
		input.RecoveryAccessKey, input.RecoverySecretKey, input.RecoverySessionToken, input.RecoveryServiceAccountFile = "", "", "", ""
	}
	input.Output = filepath.Join(cwd, "returned.json")
	if relay != nil {
		input.Responder, input.TLSCertificate = relay.Address(), relay.Certificate()
	} else {
		input.Responder, input.TLSCertificate = "", nil
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal("restricted console encoding refused")
	}
	defer clear(body)
	// Decode at the same strict boundary before any child starts.
	if _, err := DecodeRecoveryInput(bytes.NewReader(body)); err != nil {
		t.Fatal("restricted live console shape refused")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("ordinary provider executable unavailable")
	}
	command := exec.CommandContext(ctx, executable, "-test.v=test2json", "-test.count=1", "-test.run=^"+name+"$")
	command.Dir, command.Env, command.Stdin = cwd, RecoveryEnvironment(home, temporary), bytes.NewReader(body)
	var output installedarchive.ChildOutput
	command.Stdout, command.Stderr = &output, &output
	childErr := command.Run()
	if err := os.WriteFile(owner.ChildTerminals, output.Bytes(), 0600); err != nil {
		t.Fatal("child terminal evidence unavailable")
	}
	if childErr != nil || output.Completed(name) != nil {
		t.Fatal("restricted ordinary live child did not complete")
	}
	var facts ReadTransportEvidence
	if relay != nil {
		facts = relay.Evidence()
	}
	if directGCP {
		ReadParentJSON(t, input.Output+".calls.json", &facts)
		if facts.Attempted.AuthorityDecrypts > 0 && CheckGCPPrivateRequests(facts, owner.AuthoritySelector) != nil {
			t.Fatal("current Authority physical request evidence differs")
		}
	}
	allowed := facts.Attempted
	allowed.Reads, allowed.Authentication, allowed.PublicLookups, allowed.NormalLookups, allowed.RecoveryLookups, allowed.RecoveryMetadata, allowed.AuthorityDecrypts = 0, 0, 0, 0, 0, 0, 0
	if allowed != (RecoveryCounts{}) || facts.Failures != 0 {
		t.Fatalf("reconstruction used a forbidden or incomplete request: attempted=%+v refused=%+v failures=%d", facts.Attempted, facts.Refused, facts.Failures)
	}
	if refused == nil && (facts.Attempted.AuthorityDecrypts != uint64(fixture.Secrets) || facts.Sent.AuthorityDecrypts != uint64(fixture.Secrets) || facts.Refused != (RecoveryCounts{}) || facts.Injected != expectedLiveSuccessInjection(owner.Condition)) {
		t.Fatalf("complete live secret authentication missing: expected=%d attempted=%+v sent=%+v refused=%+v injected=%+v", fixture.Secrets, facts.Attempted, facts.Sent, facts.Refused, facts.Injected)
	}
	removed := ""
	var mutations uint8
	if removal != nil {
		mutations = relay.ExternalMutations()
		if mutations != 1 || mutation.Sent.Delete != 1 {
			t.Fatal("external mutation did not positively join")
		}
		removed = removal.Key
	}
	after := snapshot(removed)
	var opened uint32
	var oracle ReadTransportEvidence
	if refused != nil {
		if err := CheckRefusedResult(input.Output, *refused); err != nil {
			t.Log(err)
			t.Fatal("live refusal released unexpected observations")
		}
	} else {
		oracleRelay, err := makeRelay(input, ResponderPolicy{}, nil, nil)
		if err != nil {
			t.Fatal("private oracle transport refused")
		}
		oracleInput := input
		oracleInput.Responder, oracleInput.TLSCertificate = oracleRelay.Address(), oracleRelay.Certificate()
		decrypt, closeOracle, err := oracleFactory(ctx, archive, oracleInput)
		if err != nil || decrypt == nil || closeOracle == nil {
			t.Fatal("ordinary private oracle constructor refused")
		}
		opened, err = CheckReturnedPartsWithPrivateOracle(archive, input.Output, fixture.Oracles, decrypt)
		closeOracle()
		oracle = oracleRelay.Evidence()
		allowedOracle := oracle.Attempted
		allowedOracle.AuthorityDecrypts, allowedOracle.Authentication = 0, 0
		if err != nil || opened != uint32(fixture.Secrets) || allowedOracle != (RecoveryCounts{}) || oracle.Sent.AuthorityDecrypts != uint64(fixture.Secrets) || oracle.Refused != (RecoveryCounts{}) || oracle.Failures != 0 {
			t.Fatal("exited child's actual private values differ")
		}
	}
	result := installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}
	if refused != nil {
		result = *refused
	}
	report := installedarchive.RecoveryReport{ProviderDenial: owner.ProviderDenial, ChildStarted: true, ChildJoined: true, ChildTerminalsSHA256: fmt.Sprintf("%x", sha256.Sum256(output.Bytes())), Result: result, Refused: refused != nil, Counts: facts.Sent, Attempted: facts.Attempted, RefusedRequests: facts.Refused, Injected: facts.Injected, OracleCounts: oracle.Sent, Opened: int(opened), RemoteEffectsZero: true, OracleEpochSeparate: true,
		ExternalMutations: mutations, MutationJoined: mutations == 1, MutationCounts: mutation.Sent,
		ReservedRequests: before.ReservedRequests + facts.ReservedRequests + after.ReservedRequests + oracle.ReservedRequests + mutation.ReservedRequests,
		ReservedBytes:    before.ReservedBytes + facts.ReservedBytes + after.ReservedBytes + oracle.ReservedBytes + mutation.ReservedBytes}
	report.SnapshotReadsBefore, report.SnapshotReadsAfter = before.Sent.Reads, after.Sent.Reads
	if report.ReservedRequests > requestAllowance || report.ReservedBytes > byteAllowance {
		t.Fatal("four-epoch cumulative allowance exceeded")
	}
	WriteParentJSON(t, owner.Report, report)
}

func archiveMustNames(t testing.TB, archive installedarchive.Archive) []format.NameEntry {
	t.Helper()
	parts, err := archive.SelectedParts()
	if err != nil {
		t.Fatal("selected live archive refused")
	}
	for _, part := range parts {
		if part.Kind == "root" {
			root, err := format.DecodeRoot(part.Body)
			if err == nil {
				return root.Names
			}
		}
	}
	t.Fatal("selected live root missing")
	return nil
}

func expectedLiveSuccessInjection(condition string) RecoveryCounts {
	if condition == "adequate-anchor-fallback" {
		return RecoveryCounts{PublicLookups: 1, NormalLookups: 1}
	}
	return RecoveryCounts{}
}
