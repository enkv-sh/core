package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

func runPublicOutputRecoveryCleanup(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	t.Helper()
	if !publicProcessAdmitted(inv, input) {
		t.Fatal("public output recovery admission refused")
	}
	r := input.OutputRecovery
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("public output recovery worker unavailable")
	}
	worker.Result.Actor = input.Participants["cleanup"]
	worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved"}
	limits := input.Limits
	limits.Requests, limits.BodyBytes = limits.CleanupRequests, limits.CleanupBytes
	limits.Objects, limits.ObjectBytes = r.CleanupObjectsRemaining, r.CleanupObjectBytesRemaining
	limits.GeneratorCreates, limits.GeneratorRetires = 0, 0
	budget := &runBudget{limits: limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("public output recovery owner unavailable")
	}
	defer lease.Close()
	originalLock, err := borrowPublicOutputRecoveryLock(r.OriginalState)
	if err != nil {
		t.Fatal("public output recovery original owner is unavailable")
	}
	defer originalLock.Close()
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), time.Duration(input.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal("public output recovery input unavailable")
	}
	proof := records.PublicOutputRecoveryProof{Version: 1, InputSHA256: bodyDigest(body)}
	owner := records.PublicOutputRecoveryCaptureOwner{Version: 1, RunID: inv.RunID, OriginalRunID: input.RunID, InputSHA256: proof.InputSHA256}
	ownerPath := filepath.Join(inv.StateDir, "public-output-recovery-captures.json")
	proofPath := filepath.Join(inv.StateDir, "public-output-recovery.json")
	if _, err := os.Lstat(ownerPath); !os.IsNotExist(err) || records.WriteJSON(ownerPath, owner, 0600) != nil {
		t.Fatal("public output recovery capture owner already exists or could not be saved")
	}
	save := func() error {
		if r.VerifyFiles() != nil {
			return errInventory
		}
		return records.WriteJSON(proofPath, proof, 0600)
	}
	stage := func(name string, action func()) {
		if publicOutputRecoveryStage(&proof, name, save, action) != nil {
			t.Fatal("public output recovery stage could not be retained; original state retained")
		}
	}
	stage("intake", func() {
		if _, unknown := publicOutputRecoveryCapturedKeys(r.Captures); unknown != 0 {
			t.Fatal("original public Store effects are unresolved; original state retained")
		}
	})
	var selected *StateSession
	var configuration contract.OutputConfiguration
	stage("authenticated-discovery", func() {
		selected, configuration, proof.Initial = publicOutputRecoveryObserve(t, ctx, inv, input, budget, "authenticated-discovery")
		proof.Domain, proof.Revision, proof.Snapshot = selected.root.Domain, selected.head.Core.Revision, selected.root.Snapshot
		proof.HeadSHA256 = bodyDigest(selected.body)
	})
	source := filepath.Join(inv.StateDir, "public-source", "configuration.json")
	stage("prepare-pair", func() {
		if os.Mkdir(filepath.Dir(source), 0700) != nil {
			t.Fatal("public output recovery pair owner unavailable")
		}
		prepared := publicCLI(t, ctx, inv, input, budget, "authority", false, nativeprocess.Policy{}, nil,
			"prepare", "--source", source, "--source-format", "json", "--name", "cleanup", "--provider", input.Settings.Provider,
			"--bucket", input.Settings.Bucket, "--region", input.Settings.Region, "--prefix", input.Prefix, "--normal-signing-key", input.Settings.KeyID, "--json")
		defer clear(prepared.Body)
		pair := publicOutputRecoveryPairImage(t, *r)
		if _, ok := publicOutputRecoveryPreparedMatches(prepared, configuration, proof, pair); !ok {
			t.Fatal("public output recovery pair does not match authenticated current state")
		}
		publicPrepareReadOnly(t, prepared.Capture)
		if publicReadDomain(t, source) != proof.Domain {
			t.Fatal("prepared recovery dependency has another Domain")
		}
		retained := records.PublicOutputRecoveryPreparedPair{Version: 1, InputSHA256: proof.InputSHA256, StageSHA256: records.PublicOutputRecoveryStageBinding(proof.InputSHA256, "prepare-pair"), CommandDirectory: filepath.Base(filepath.Dir(prepared.CapturePath)), HeadSHA256: proof.HeadSHA256, Result: bytes.Clone(prepared.Body), Pair: pair}
		if records.WriteJSON(filepath.Join(inv.StateDir, "public-output-recovery-prepared-pair.json"), retained, 0400) != nil {
			t.Fatal("prepared recovery pair could not be retained")
		}
	})
	stage("retire-bindings", func() {
		var prepared records.PublicOutputRecoveryPreparedPair
		if records.ReadJSON(filepath.Join(inv.StateDir, "public-output-recovery-prepared-pair.json"), &prepared) != nil || !reflect.DeepEqual(publicOutputRecoveryPairImage(t, *r), prepared.Pair) {
			t.Fatal("prepared recovery pair changed before output retirement")
		}
		if !publicOutputRecoveryRetireSource(t, *r, prepared.Pair, configuration) {
			return
		}
		image := publicSourceImage(t, source)
		applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
		defer clear(applied.Body)
		product := publicProduct(t, applied, "apply-declaration")
		if !publicApplyMatches(applied, product, "success") && !publicApplyMatches(applied, product, "no-op") {
			t.Fatal("public output recovery binding retirement is unresolved")
		}
		publicImageUnchanged(t, image)
	})
	stage("remaining-deletions", func() {
		_, current, rows := publicOutputRecoveryObserve(t, ctx, inv, input, budget, "remaining-deletions")
		if len(current.Bindings) != 0 || !publicOutputRecoverySameTargets(proof.Initial, rows) {
			t.Fatal("public output recovery selected identity changed before deletion")
		}
		var remaining []publicOutputCoordinate
		for _, row := range rows {
			if row.Disposition == "remaining" {
				remaining = append(remaining, row.Target)
			}
		}
		if len(remaining) == 0 {
			return
		}
		args := []string{"publish", "--source", source, "--source-format", "json", "--json"}
		for _, target := range remaining {
			args = append(args, "--delete-coordinate", target.CoordinateID+"="+publicOutputDeletionPlugin(t, target))
		}
		image := publicSourceImage(t, source)
		deleted := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, args...)
		defer clear(deleted.Body)
		publicOutputPublication(t, deleted, remaining, false, false, true)
		publicImageUnchanged(t, image)
	})
	stage("current-disposition", func() {
		var final *StateSession
		var current contract.OutputConfiguration
		final, current, proof.Final = publicOutputRecoveryObserve(t, ctx, inv, input, budget, "current-disposition")
		if len(current.Bindings) != 0 || !publicOutputRecoverySameTargets(proof.Initial, proof.Final) {
			t.Fatal("public output recovery final target set changed; Store retained")
		}
		for _, row := range proof.Final {
			if row.Validate(proof.Domain, true, *r) != nil {
				t.Fatal("public output recovery current disposition is unresolved; Store retained")
			}
		}
		proof.Revision, proof.Snapshot, proof.HeadSHA256 = final.head.Core.Revision, final.root.Snapshot, bodyDigest(final.body)
	})
	proof.Stages = append(proof.Stages, records.PublicOutputRecoveryStage{Name: "store-cleanup", Outcome: "entered"})
	if save() != nil {
		t.Fatal("public output recovery Store barrier could not be retained")
	}
	if records.ReadJSON(ownerPath, &owner) != nil {
		t.Fatal("public output recovery joined captures unavailable; Store retained")
	}
	allowed, unknown := publicOutputRecoveryCapturedKeys(append(slices.Clone(r.Captures), owner.Captures...))
	worker.Result.Cleanup.UnknownEffects = &unknown
	if unknown != 0 {
		t.Fatal("public output recovery Store effects unresolved; Store retained")
	}
	cleaner, err := openPublicPrefixCleaner(ctx, input, proof.Domain, inv.StateDir, allowed)
	if err != nil {
		t.Fatal("public cleanup context unavailable")
	}
	publicCleanupOwnedPrefix(t, ctx, inv, input, budget, worker, cleaner, allowed, unknown, proof.Domain, true, func() error {
		store, _, err := publicInventoryEvidence(filepath.Join(inv.StateDir, "public-cleanup-inventory.json"))
		if err != nil {
			return errInventory
		}
		proof.Store = &store
		proof.Stages[len(proof.Stages)-1].Outcome = "complete"
		if save() != nil {
			return errInventory
		}
		if proof.Validate(*r) != nil {
			return errInventory
		}
		return nil
	})
}

func publicOutputRecoveryRetireSource(t testing.TB, input records.PublicOutputRecoveryInput, prepared records.PublicOutputRecoveryPair, configuration contract.OutputConfiguration) bool {
	t.Helper()
	document := publicSourceDocument(t, prepared.Source)
	document["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	publicWriteSource(t, prepared.Source, document)
	if !publicOutputRecoveryPairImage(t, input).OutputsRemovedFrom(prepared) {
		t.Fatal("recovery edit changed more than the output declaration")
	}
	return len(configuration.Bindings) != 0
}

// full_only: false
func TestPublicOutputRecoveryRetiresEmptySourceBeforeDeletion(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(fmt.Sprint(active), func(t *testing.T) {
			input := records.PublicOutputRecoveryInput{StateDir: t.TempDir()}
			source := filepath.Join(input.StateDir, "public-source/configuration.json")
			if os.MkdirAll(filepath.Join(filepath.Dir(source), ".enkv"), 0700) != nil || os.WriteFile(filepath.Join(filepath.Dir(source), ".enkv/cleanup.generated.json"), []byte(`{}`), 0600) != nil {
				t.Fatal("retirement fixture unavailable")
			}
			publicWriteSource(t, source, map[string]any{"generated": ".enkv/cleanup.generated.json", "entries": map[string]any{"plain": map[string]any{"source": "retained"}}, "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}, "groups": []any{}}})
			prepared := publicOutputRecoveryPairImage(t, input)
			configuration := contract.OutputConfiguration{}
			if active {
				configuration.Bindings = []contract.OutputBinding{{}}
			}
			if publicOutputRecoveryRetireSource(t, input, prepared, configuration) != active || !publicOutputRecoveryPairImage(t, input).OutputsRemovedFrom(prepared) {
				t.Fatal("empty selected bindings bypassed the local retirement needed by deletion")
			}
		})
	}
}

func publicOutputRecoveryPreparedMatches(child publicChildResult, configuration contract.OutputConfiguration, proof records.PublicOutputRecoveryProof, pair records.PublicOutputRecoveryPair) (publicPrepareResult, bool) {
	var result publicPrepareResult
	contracts := make([]string, 0, len(configuration.Bindings))
	for _, binding := range configuration.Bindings {
		contracts = append(contracts, binding.Destination.ConfigContractID)
	}
	slices.Sort(contracts)
	contracts = slices.Compact(contracts)
	pairContracts, err := pair.OutputContracts()
	if err != nil || !slices.Equal(contracts, pairContracts) {
		return result, false
	}
	if len(contracts) == 0 {
		if _, ok := publicPreparedResultMatches(child, "reconstruction"); !ok {
			return result, false
		}
	}
	prepared := records.PublicOutputRecoveryPreparedPair{HeadSHA256: proof.HeadSHA256, Result: child.Body, Pair: pair}
	if prepared.ValidateResult(child.Code, proof.Domain, contracts) != nil || json.Unmarshal(child.Body, &result) != nil {
		return result, false
	}
	return result, true
}

// full_only: false
func TestPublicOutputRecoveryPrepareRequiresAuthenticatedDependencies(t *testing.T) {
	configuration := contract.OutputConfiguration{Bindings: []contract.OutputBinding{
		{Destination: contract.OutputDestination{ConfigContractID: "github-actions/repository-config/v1"}},
		{Destination: contract.OutputDestination{ConfigContractID: "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1"}},
		{Destination: contract.OutputDestination{ConfigContractID: "github-actions/repository-config/v1"}},
	}}
	proof := records.PublicOutputRecoveryProof{Domain: contract.ID{1}, HeadSHA256: strings.Repeat("2", 64)}
	// Independently framed Binding/v1: destination name, config/service/settings,
	// empty policy, six action bits, and zero target and encoding counts.
	const source = `{"generated":".enkv/cleanup.generated.json","outputs":{"destinations":{"cloud":{"plugin":null,"canonical":{"binding_base64":"AAEAAAAFY2xvdWQAAABOAAAAKUVOS1YvT1VUUFVUL0FXUy1TRUNSRVRTLU1BTkFHRVIvQ09ORklHL3YxAAAAEmZpeHR1cmUvc2VydmljZS92MQAAAAJ7fQAAAAA/AAAAAA=="}},"github":{"plugin":null,"canonical":{"binding_base64":"AAEAAAAGZ2l0aHViAAAASAAAACNnaXRodWItYWN0aW9ucy9yZXBvc2l0b3J5LWNvbmZpZy92MQAAABJmaXh0dXJlL3NlcnZpY2UvdjEAAAACe30AAAAAPwAAAAA="}}}}}`
	pair := records.PublicOutputRecoveryPair{Source: "/recovery/configuration.json", Files: []records.PublicOutputRecoveryPairFile{
		{Path: "configuration.json", Data: []byte(source), SHA256: strings.Repeat("3", 64)},
		{Path: ".enkv/cleanup.generated.json", SHA256: strings.Repeat("4", 64)},
	}}
	body := []byte(`{"schema":"enkv/prepare-result/v2","operation":"prepare","request_id":"1111111111111111111111111111111111111111111111111111111111111111","branch":"reconstruction","recovery":{"status":"complete","domain":"0100000000000000000000000000000000000000000000000000000000000000","head":"2222222222222222222222222222222222222222222222222222222222222222"},"local_delivery":{"outcome":"recorded","editable_path":"/recovery/configuration.json","generated_path":"/recovery/.enkv/cleanup.generated.json","cleanup_failed":false,"readback":{"editable_digest":"3333333333333333333333333333333333333333333333333333333333333333","generated_digest":"4444444444444444444444444444444444444444444444444444444444444444"}},"dependencies":{"assessment":"complete","minimum_administrative_ready":true,"all_declared_ready":false,"requirements":[{"role":"output","plugin":null,"contract":"ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1","protocol_version":4,"artifact":null,"status":"missing","reason":"not-installed"},{"role":"output","plugin":null,"contract":"github-actions/repository-config/v1","protocol_version":4,"artifact":null,"status":"missing","reason":"not-installed"}],"installations":[]},"diagnostics":[{"reason":"dependency-missing","subject":"dependencies"}],"outcome":"incomplete"}`)
	if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Code: 2, Body: body}, configuration, proof, pair); !ok {
		t.Fatal("recovery prepare refused exact delivered state with unselected output dependencies")
	}
	for name, changedSource := range map[string]string{
		"missing-destinations": `{"generated":".enkv/cleanup.generated.json"}`,
		"empty-destinations":   `{"generated":".enkv/cleanup.generated.json","outputs":{"destinations":{}}}`,
		"selected-plugin":      strings.Replace(source, `"plugin":null`, `"plugin":"installed"`, 1),
		"different-contract":   strings.Replace(source, "AAEAAAAFY2xvdWQAAABOAAAAKUVOS1YvT1VUUFVUL0FXUy1TRUNSRVRTLU1BTkFHRVIvQ09ORklHL3YxAAAAEmZpeHR1cmUvc2VydmljZS92MQAAAAJ7fQAAAAA/AAAAAA==", "AAEAAAAFY2xvdWQAAAA2AAAAEWZpeHR1cmUvY29uZmlnL3YxAAAAEmZpeHR1cmUvc2VydmljZS92MQAAAAJ7fQAAAAA/AAAAAA==", 1),
	} {
		t.Run(name, func(t *testing.T) {
			changed := pair
			changed.Files = slices.Clone(pair.Files)
			changed.Files[0].Data = []byte(changedSource)
			if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Code: 2, Body: body}, configuration, proof, changed); ok {
				t.Fatal("live prepare accepted pair contracts the retained verifier cannot accept")
			}
		})
	}
	for _, change := range []struct{ name, before, after string }{
		{"schema", "prepare-result/v2", "prepare-result/v1"},
		{"branch", `"branch":"reconstruction"`, `"branch":"existing"`},
		{"request", `"request_id":"11`, `"request_id":"zz`},
		{"recovery-status", `"status":"complete"`, `"status":"failed"`},
		{"domain", `"domain":"01`, `"domain":"02`},
		{"head", `"head":"22`, `"head":"33`},
		{"delivery", `"outcome":"recorded"`, `"outcome":"not-recorded"`},
		{"editable-path", `"editable_path":"/recovery/`, `"editable_path":"/other/`},
		{"generated-path", `"generated_path":"/recovery/`, `"generated_path":"/other/`},
		{"editable-digest", `"editable_digest":"33`, `"editable_digest":"55`},
		{"generated-digest", `"generated_digest":"44`, `"generated_digest":"55`},
		{"cleanup", `"cleanup_failed":false`, `"cleanup_failed":true`},
		{"recovery-source", `"cleanup_failed":false`, `"cleanup_failed":false,"recovery_source":"old"`},
		{"assessment", `"assessment":"complete"`, `"assessment":"not-attempted"`},
		{"minimum-ready", `"minimum_administrative_ready":true`, `"minimum_administrative_ready":false`},
		{"all-ready", `"all_declared_ready":false`, `"all_declared_ready":true`},
		{"role", `"role":"output"`, `"role":"generator"`},
		{"contract", `"contract":"ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1"`, `"contract":"undeclared/config/v1"`},
		{"duplicate-contract", `"contract":"github-actions/repository-config/v1"`, `"contract":"ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1"`},
		{"protocol", `"protocol_version":4`, `"protocol_version":3`},
		{"plugin", `"plugin":null`, `"plugin":"local-available"`},
		{"missing-plugin", `"plugin":null,`, ``},
		{"artifact", `"artifact":null`, `"artifact":"installed-artifact"`},
		{"missing-artifact", `"artifact":null,`, ``},
		{"status", `"status":"missing"`, `"status":"verified"`},
		{"reason", `"reason":"not-installed"`, `"reason":"unavailable"`},
		{"installations", `"installations":[]`, `"installations":[{}]`},
		{"null-installations", `"installations":[]`, `"installations":null`},
		{"diagnostic", `"reason":"dependency-missing"`, `"reason":"contention"`},
		{"diagnostic-subject", `"subject":"dependencies"`, `"subject":"recovery"`},
		{"outcome", `"outcome":"incomplete"`, `"outcome":"complete"`},
		{"unknown-member", `"installations":[]`, `"installations":[],"unknown":[]`},
		{"case-alias", `"installations":[]`, `"Installations":[]`},
		{"duplicate-member", `"assessment":"complete"`, `"assessment":"complete","assessment":"complete"`},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := bytes.Replace(body, []byte(change.before), []byte(change.after), 1)
			if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Code: 2, Body: changed}, configuration, proof, pair); bytes.Equal(body, changed) || ok {
				t.Fatal("recovery prepare accepted a different delivery or dependency contract")
			}
		})
	}
	for _, code := range []int{0, 1, 3} {
		if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Code: code, Body: body}, configuration, proof, pair); ok {
			t.Fatal("recovery prepare accepted another command exit", code)
		}
	}
	start := bytes.Index(body, []byte(`"requirements":[`))
	end := bytes.Index(body[start:], []byte(`],"installations"`)) + start + 1
	zero := append(bytes.Clone(body[:start]), append([]byte(`"requirements":[]`), body[end:]...)...)
	zero = bytes.Replace(zero, []byte(`"all_declared_ready":false`), []byte(`"all_declared_ready":true`), 1)
	zero = bytes.Replace(zero, []byte(`[{"reason":"dependency-missing","subject":"dependencies"}]`), []byte(`[]`), 1)
	zero = bytes.Replace(zero, []byte(`"outcome":"incomplete"`), []byte(`"outcome":"complete"`), 1)
	zeroPair := pair
	zeroPair.Files = slices.Clone(pair.Files)
	zeroPair.Files[0].Data = []byte(`{"generated":".enkv/cleanup.generated.json","outputs":{"destinations":{}}}`)
	if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Body: zero}, contract.OutputConfiguration{}, proof, zeroPair); !ok {
		t.Fatal("dependency-free reconstruction was refused")
	}
	if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Code: 2, Body: body}, contract.OutputConfiguration{}, proof, pair); ok {
		t.Fatal("dependency-free reconstruction accepted undeclared dependencies")
	}
	if _, ok := publicOutputRecoveryPreparedMatches(publicChildResult{Body: zero}, configuration, proof, pair); ok {
		t.Fatal("output reconstruction erased its authenticated requirements")
	}
}

func publicOutputRecoveryStage(proof *records.PublicOutputRecoveryProof, name string, save func() error, action func()) error {
	proof.Stages = append(proof.Stages, records.PublicOutputRecoveryStage{Name: name, Outcome: "entered"})
	if err := save(); err != nil {
		return err
	}
	action()
	proof.Stages[len(proof.Stages)-1].Outcome = "complete"
	return save()
}

func borrowPublicOutputRecoveryLock(state string) (*os.File, error) {
	path, err := records.SafePath(state, "inventory.lock")
	if err != nil {
		return nil, errInventory
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, errInventory
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errInventory
	}
	opened, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !records.SameLocalFile(before, opened) || !records.SameLocalFile(before, current) || syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, errInventory
	}
	return file, nil
}

func publicOutputRecoveryCapturedKeys(captures []publicCaptureReceipt) (map[string]bool, int64) {
	allowed := map[string]bool{}
	var unknown int64
	for _, capture := range captures {
		keys, unresolved := publicCapturedObjectKeys(filepath.Dir(filepath.Dir(capture.Path)), []publicCaptureReceipt{capture})
		unknown += unresolved
		for key := range keys {
			allowed[key] = true
		}
	}
	return allowed, unknown
}

func publicOutputRecoverySameTargets(first, last []records.PublicOutputRecoveryDisposition) bool {
	if len(first) != len(last) {
		return false
	}
	for i, row := range first {
		if row.Target != last[i].Target || row.Coordinate.LastEntryIncarnationID != last[i].Coordinate.LastEntryIncarnationID {
			return false
		}
	}
	return true
}

func publicOutputRecoveryObserve(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, stage string) (*StateSession, contract.OutputConfiguration, []records.PublicOutputRecoveryDisposition) {
	t.Helper()
	r := input.OutputRecovery
	if r == nil || r.VerifyFiles() != nil {
		t.Fatal("public output recovery original evidence changed")
	}
	basis, descriptor := publicOperatorGenesis(t, r.Source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("public output recovery GET-only context unavailable")
	}
	selected := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget})
	configuration, coordinates, markers := publicSelectedOutputs(t, ctx, selected)
	return publicOutputRecoveryClassify(t, inv, input, stage, selected, configuration, coordinates, markers)
}

func publicOutputRecoveryClassify(t testing.TB, inv records.Invocation, input liveRunInput, stage string, selected *StateSession, configuration contract.OutputConfiguration, coordinates map[string]contract.PublicationCoordinate, markers map[contract.ID]contract.PublicationMarker) (*StateSession, contract.OutputConfiguration, []records.PublicOutputRecoveryDisposition) {
	t.Helper()
	publicOutputRecoverySaveObservation(t, inv, input, stage, selected, coordinates, markers)
	r := input.OutputRecovery
	var ledger publicOwnership
	if records.ReadJSON(filepath.Join(r.OriginalState, "public-ownership.json"), &ledger) != nil || ledger.Domain != "" && ledger.Domain != hex.EncodeToString(selected.root.Domain[:]) {
		t.Fatal("public output recovery original Domain differs from authenticated state")
	}
	if selected.root.WarningBits != 0 || !selected.root.Generated.ActiveOwner.IsZero() || !selected.root.ActiveGC.IsZero() {
		t.Fatal("public output recovery has selected warnings or unfinished work")
	}
	cloud := "aws-secrets-manager"
	if input.Settings.Provider == "gcp" {
		cloud = "gcp-secret-manager"
	}
	expected := publicExpectedOutputCoordinatesForScopes(input, []string{cloud, "github-repository", "github-organization", "github-environment"})
	wanted := map[string]bool{}
	facts := selectedPublication{coordinates: map[contract.ID]contract.PublicationCoordinate{}, markers: markers}
	for _, coordinate := range coordinates {
		facts.coordinates[coordinate.CoordinateID] = coordinate
	}
	var rows []records.PublicOutputRecoveryDisposition
	for _, target := range expected {
		key := target.ServiceContractID + "\x00" + target.PhysicalTarget
		wanted[key] = true
		coordinate, present := coordinates[key]
		row := records.PublicOutputRecoveryDisposition{Target: target, Coordinate: coordinate}
		if !present {
			id, err := contract.PublicationCoordinateID(selected.root.Domain, target.ServiceContractID, target.PhysicalTarget)
			if err != nil {
				t.Fatal("public output recovery target identity unavailable")
			}
			row.Target.CoordinateID, row.Disposition = hex.EncodeToString(id[:]), "absent-no-effect"
		} else {
			row.Target.CoordinateID, row.Target.BindingID = hex.EncodeToString(coordinate.CoordinateID[:]), hex.EncodeToString(coordinate.LastBindingIncarnationID[:])
			for _, order := range selected.adminIndex.PublicationOrder {
				if order.CoordinateID == coordinate.CoordinateID {
					row.Incarnations = slices.Clone(order.Incarnations)
				}
			}
			for _, marker := range markers {
				if marker.CoordinateID == coordinate.CoordinateID {
					row.Markers = append(row.Markers, marker)
				}
			}
			slices.SortFunc(row.Markers, func(a, b contract.PublicationMarker) int { return bytes.Compare(a.AttemptID[:], b.AttemptID[:]) })
			switch {
			case records.PublicOutputRecoveryPassive(coordinate, row.Markers):
				row.Disposition = "passive"
			case !coordinate.LastDeleteAckAttemptID.IsZero():
				row.Disposition = "deletion-acknowledged"
			default:
				row.Disposition = "remaining"
			}
			if len(publicationBlockers(facts, coordinate.CoordinateID)) != 0 {
				t.Fatal("public output recovery target has unresolved publication blockers")
			}
		}
		if row.Validate(selected.root.Domain, false, *r) != nil {
			t.Fatal("public output recovery current target cannot be classified")
		}
		rows = append(rows, row)
	}
	for key := range coordinates {
		if !wanted[key] {
			t.Fatal("public output recovery has an additional selected coordinate")
		}
	}
	for _, binding := range configuration.Bindings {
		if !slices.Contains([]string{cloud, "github-repository", "github-organization", "github-environment"}, binding.DestinationID) || len(binding.Targets) != 2 {
			t.Fatal("public output recovery has an additional selected binding")
		}
		for _, target := range binding.Targets {
			key := target.ServiceContractID + "\x00" + target.CanonicalTarget
			coordinate, present := coordinates[key]
			if !wanted[key] || !present || coordinate.BindingState != contract.PublicationBindingActive || coordinate.ActiveBindingIncarnationID != binding.IncarnationID ||
				coordinate.LastBindingIncarnationID != binding.IncarnationID || coordinate.LastEntryIncarnationID != target.EntryIncarnationID {
				t.Fatal("public output recovery selected binding differs from its complete coordinate")
			}
		}
	}
	if _, err := os.Lstat(filepath.Join(r.OriginalState, "after.json")); err == nil {
		var historical publicProcessFacts
		if records.ReadJSON(filepath.Join(r.OriginalState, "after.json"), &historical) != nil || historical.RunID != input.RunID || historical.Prefix != input.Prefix || historical.Domain != hex.EncodeToString(selected.root.Domain[:]) {
			t.Fatal("public output recovery historical target facts changed")
		}
		for _, target := range historical.Outputs {
			matched := false
			for _, row := range rows {
				if row.Target == target {
					matched = true
				}
			}
			if !matched {
				t.Fatal("public output recovery historical target identity differs")
			}
		}
		if historical.Manifest != nil {
			for _, entry := range historical.Manifest.Entries {
				for _, destination := range entry.Destinations {
					matched := false
					for _, row := range rows {
						matched = matched || row.Target.ServiceContractID == destination.Service && row.Target.PhysicalTarget == destination.CanonicalTarget &&
							row.Target.BindingID == destination.Binding && hex.EncodeToString(row.Coordinate.LastEntryIncarnationID[:]) == entry.Incarnation
					}
					if !matched {
						t.Fatal("public output recovery historical passive identity differs")
					}
				}
			}
		}
	}
	return selected, configuration, rows
}

// full_only: false
func TestPublicOutputRecoveryPreservesOriginalCaptureOwner(t *testing.T) {
	inv, _ := liveProtocolInvocation(t, "cleanup")
	inv = liveProtocolBindInvocation(t, inv, "public-configuration.output-standalone/output_standalone")
	inv = liveProtocolRecoveryOutput(t, inv)
	original := publicOwnership{Version: 1, RunID: liveProtocolRun, PreflightEmpty: true}
	path := publicLedgerPath(inv)
	if records.WriteJSON(path, original, 0600) != nil {
		t.Fatal("original capture owner unavailable")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(inv.StateDir, "public-command-recovery", "capture.jsonl")
	if os.Mkdir(filepath.Dir(capture), 0700) != nil || os.WriteFile(capture, []byte("{\"kind\":\"footer\"}\n"), 0600) != nil {
		t.Fatal("original-owner capture control unavailable")
	}
	registration := publicCaptureReceipt{Path: capture, ParentWorker: inv.Worker, ParentNonce: inv.Nonce,
		ParentRole: inv.Role, Actor: "apply", NativeKind: "cli"}
	if err := publicCaptureReceiptUpdate(inv, registration, false); err == nil {
		t.Error("new recovery intent entered the original capture owner")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery changed the original capture ledger", err)
	}
}

// full_only: false
func TestPublicOutputCurrentStateRequiresCompletePublicationRelation(t *testing.T) {
	domain := contract.ID{1}
	configuration, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: 4, DomainID: domain})
	if err != nil {
		t.Fatal("empty selected output configuration unavailable", err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, configuration)
	if err != nil || len(parts) != 1 {
		t.Fatal("selected output configuration slice unavailable", err)
	}
	body, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	sliceID, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	service, target := "github-actions/service/v1", "repos/owner/repository/actions/secrets/ENKV_ORIGINAL"
	// Coordinate/v3 hashes Domain and two u32-length-prefixed strings.
	preimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), domain[:]...)
	for _, value := range []string{service, target} {
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(value)))
		preimage = append(preimage, value...)
	}
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: domain, CoordinateID: sha256.Sum256(preimage),
		ServiceContractID: service, CanonicalTarget: target, BindingState: contract.PublicationBindingRetired,
		OwnerState: contract.PublicationOwnerNone, LastBindingIncarnationID: contract.ID{2},
		LastEntryIncarnationID: contract.ID{3}, CurrentPublicationIncarnationID: contract.ID{4}}
	coordinateBody, err := contract.EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal("retired passive coordinate unavailable", err)
	}
	page := format.RequiredSupportPageView{Domain: domain, Object: contract.ID{5}, Records: []contract.SupportRecordView{
		{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: sliceID, Body: body},
		{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: coordinateBody},
	}}
	selected := &StateSession{}
	selected.admission.domain = domain
	selected.root.Domain, selected.root.OutputConfiguration = domain, descriptor
	selected.root.Generated = format.EmptyGeneratedClosure()
	selected.adminIndex.SliceSnapshot = domain
	selected.support = []format.RequiredSupportPageView{page}
	selected.root.RequiredSupport = []format.Ref{{Object: page.Object}}
	selected.root.RequiredSupportRecordCount = uint32(len(page.Records))
	if _, err := selectedPublicationRelation(selected.selectedImage()); err == nil {
		t.Fatal("negative control unexpectedly has complete publication ownership")
	}
	var refusal any
	func() {
		defer func() { refusal = recover() }()
		publicSelectedOutputs(recoveryCustodyRefusalTB{TB: t}, t.Context(), selected)
	}()
	if _, ok := refusal.(recoveryCustodyRefusal); !ok {
		t.Fatal("output discovery accepted individually valid rows without complete publication ownership", refusal)
	}
}

// full_only: false
func TestPublicOutputRecoveryStageRequiresDurableIntent(t *testing.T) {
	for _, failure := range []string{"none", "intent", "completion"} {
		t.Run(failure, func(t *testing.T) {
			proof := records.PublicOutputRecoveryProof{Version: 1}
			path := filepath.Join(t.TempDir(), "stage.json")
			writes, effects := 0, 0
			err := publicOutputRecoveryStage(&proof, "retire-bindings", func() error {
				writes++
				if failure == "intent" && writes == 1 || failure == "completion" && writes == 2 {
					return errors.New("controlled stage save failure")
				}
				return records.WriteJSON(path, proof, 0600)
			}, func() {
				var retained records.PublicOutputRecoveryProof
				if records.ReadJSON(path, &retained) != nil || len(retained.Stages) != 1 || retained.Stages[0].Outcome != "entered" {
					t.Fatal("effect entered without durable intent")
				}
				effects++
			})
			wantEffects := 1
			if failure == "intent" {
				wantEffects = 0
			}
			if effects != wantEffects || (err == nil) != (failure == "none") {
				t.Fatal("failed stage persistence changed effect entry", effects, err)
			}
			if failure == "completion" {
				var retained records.PublicOutputRecoveryProof
				if records.ReadJSON(path, &retained) != nil || retained.Stages[0].Outcome != "entered" {
					t.Fatal("failed completion save invented a terminal stage")
				}
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryDeletionAdmitsRetiredPassiveCoordinates(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	p := newPublicationScenario(t, ctx, env, "separate-values-and-noop")
	p.execute(contract.PublicationCreateWithValue, "", contract.PublicationSummaryComplete)
	p.assertJoins(2, false)
	output := p.output([]uint64{1, 9})
	for scope := 0; scope < 3; scope++ {
		binding := outputApplyBinding{destinationID: fmt.Sprintf("passive-%d", scope)}
		for entry := 0; entry < 2; entry++ {
			target := output.bindings[0].targets[entry]
			target.target.CanonicalTarget = fmt.Sprintf("passive-%d-%d", scope, entry)
			target.target.ConsumerLocator = target.target.CanonicalTarget
			target.target.TargetData = []byte("target:" + target.target.CanonicalTarget)
			binding.targets = append(binding.targets, target)
		}
		output.bindings = append(output.bindings, binding)
		output.routes[0].destinations = append(output.routes[0].destinations, binding.destinationID)
	}
	p.selectEntries(p.entries, output)
	p.selectEntries(p.entries, &outputApplyInput{})
	before, err := selectedPublicationRelation(p.fixture.session.selectedImage())
	if err != nil || len(before.coordinates) != 8 {
		t.Fatal("complete retired publication set unavailable", err)
	}
	passive := map[contract.ID]contract.PublicationCoordinate{}
	for id, coordinate := range before.coordinates {
		if coordinate.OwnerState == contract.PublicationOwnerNone {
			if !records.PublicOutputRecoveryPassive(coordinate, nil) || coordinate.BindingState != contract.PublicationBindingRetired {
				t.Fatal("passive retirement acquired effect facts")
			}
			passive[id] = coordinate
		}
	}
	if len(passive) != 6 {
		t.Fatal("retired passive coordinate set differs")
	}
	p.input.names = nil
	for _, slot := range p.slots {
		p.input.deletes = append(p.input.deletes, publicationScenarioCoordinate(env.Domain, slot))
	}
	p.execute(contract.PublicationDeleteOwned, "", contract.PublicationSummaryComplete)
	p.assertJoins(2, false)
	after, err := selectedPublicationRelation(p.fixture.session.selectedImage())
	if err != nil || len(after.coordinates) != 8 {
		t.Fatal("deletion lost complete coordinate ownership", err)
	}
	for id, before := range passive {
		if !after.coordinates[id].Equal(before) {
			t.Fatal("exact deletion changed a retired passive coordinate")
		}
	}
	for _, id := range p.input.deletes {
		coordinate := after.coordinates[id]
		if coordinate.LastDeleteAckAttemptID.IsZero() || coordinate.PossibleRemoteObject != 1 || coordinate.LateEffectRisk != 0 {
			t.Fatal("deletion changed its acknowledgement ceiling")
		}
	}
}

// full_only: false
func TestPublicOutputRecoveryObserverRejectsManifestGithubEffects(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	p := newPublicationScenario(t, ctx, env, "separate-values-and-noop")
	p.execute(contract.PublicationCreateWithValue, "", contract.PublicationSummaryComplete)
	p.assertJoins(2, false)
	p.selectEntries(p.entries, &outputApplyInput{})
	p.input.names = nil
	for _, slot := range p.slots {
		p.input.deletes = append(p.input.deletes, publicationScenarioCoordinate(env.Domain, slot))
	}
	p.execute(contract.PublicationDeleteOwned, "", contract.PublicationSummaryComplete)
	p.assertJoins(2, false)
	facts, err := selectedPublicationRelation(p.fixture.session.selectedImage())
	if err != nil {
		t.Fatal("authenticated publication fixture unavailable", err)
	}
	originalID := p.input.deletes[0]
	c := facts.coordinates[originalID]
	r := records.PublicOutputRecoveryInput{Provider: liveProvider(), Prefix: "scope-fixture", Region: "region", Account: "123456789012", ProjectNumber: "123456789", Outputs: &records.PublicOutputScopes{Repository: records.PublicOutputScope{Owner: "owner", Repository: "repository"}, Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101}}, Environment: records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"}}}
	target := records.PublicOutputFixtureCoordinates(r.Provider, r.Region, r.Account, r.ProjectNumber, r.Prefix, r.Outputs, []string{"github-repository"})[0]
	id, err := contract.PublicationCoordinateID(env.Domain, target.ServiceContractID, target.PhysicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	target.CoordinateID, target.BindingID = hex.EncodeToString(id[:]), hex.EncodeToString(c.LastBindingIncarnationID[:])
	c.CoordinateID, c.ServiceContractID, c.CanonicalTarget = id, target.ServiceContractID, target.PhysicalTarget
	c.DeletionTargetContractID = target.TargetContractID
	row := records.PublicOutputRecoveryDisposition{Target: target, Coordinate: c, Disposition: "deletion-acknowledged"}
	for _, order := range p.fixture.session.adminIndex.PublicationOrder {
		if order.CoordinateID == originalID {
			row.Incarnations = slices.Clone(order.Incarnations)
		}
	}
	for _, marker := range facts.markers {
		if marker.CoordinateID != originalID {
			continue
		}
		marker.CoordinateID, marker.Projection.CoordinateID = id, id
		marker.ProjectionCommitment, err = contract.PublicationProjectionCommitment(marker.Projection)
		if err != nil {
			t.Fatal(err)
		}
		if marker.AttemptID == c.OwnedBirthAttemptID {
			marker.BirthServiceContractID, marker.BirthTargetContractID = target.ServiceContractID, target.TargetContractID
			row.Coordinate.OwnedInstanceDigest, err = contract.PublicationOwnedInstanceDigest(env.Domain, id, c.LastBindingIncarnationID, c.LastEntryIncarnationID, c.DeletionTargetRowDigest, c.OwnedBirthAttemptID, marker.Evidence.SafeResourceID)
			if err != nil {
				t.Fatal(err)
			}
		}
		row.Markers = append(row.Markers, marker)
	}
	for _, scenario := range []string{"public-configuration.manifest/atomic_public_file", "public-configuration.output-standalone/output_standalone", "public-configuration.output-combined/output_combined"} {
		for _, disposition := range []string{"passive", "absent-no-effect", "remaining", "deletion-acknowledged"} {
			t.Run(scenario+"/"+disposition, func(t *testing.T) {
				r.OriginalEntry.Scenario = scenario
				v := row
				final := true
				if disposition == "passive" {
					v.Disposition, v.Markers = "passive", nil
					v.Incarnations = []contract.ID{c.CurrentPublicationIncarnationID}
					v.Coordinate = contract.PublicationCoordinate{Schema: 5, DomainID: env.Domain, CoordinateID: id, ServiceContractID: target.ServiceContractID, CanonicalTarget: target.PhysicalTarget, BindingState: contract.PublicationBindingRetired, LastBindingIncarnationID: c.LastBindingIncarnationID, LastEntryIncarnationID: c.LastEntryIncarnationID, CurrentPublicationIncarnationID: c.CurrentPublicationIncarnationID}
				} else if disposition == "absent-no-effect" {
					v.Target.BindingID = ""
					v.Disposition, v.Markers, v.Incarnations, v.Coordinate = disposition, nil, nil, contract.PublicationCoordinate{}
				} else if disposition == "remaining" {
					final, v.Disposition = false, "remaining"
					v.Markers = nil
					for _, marker := range row.Markers {
						if marker.AttemptID != c.LastDeleteAckAttemptID {
							v.Markers = append(v.Markers, marker)
						}
					}
					v.Coordinate.LastDeleteAckAttemptID, v.Coordinate.LastDeleteAckIncarnationID, v.Coordinate.LastDeleteAckOrdinal = contract.ID{}, contract.ID{}, 0
				}
				want := scenario != "public-configuration.manifest/atomic_public_file" || disposition == "passive" || disposition == "absent-no-effect"
				if (v.Validate(env.Domain, final, r) == nil) != want {
					t.Fatal("observer classification changed the catalog's exact publication effect scope", disposition)
				}
			})
		}
	}
}

func publicOutputRecoveryPairImage(t testing.TB, input records.PublicOutputRecoveryInput) records.PublicOutputRecoveryPair {
	t.Helper()
	source := filepath.Join(input.StateDir, "public-source/configuration.json")
	inventory, err := publicSourceInventory(filepath.Dir(source))
	if err != nil {
		t.Fatal("recovery source inventory unavailable")
	}
	pair := records.PublicOutputRecoveryPair{Version: 1, Source: source}
	for _, relative := range inventory {
		if strings.HasSuffix(relative, "/") {
			continue
		}
		path, err := records.SafePath(filepath.Dir(source), filepath.FromSlash(relative))
		if err != nil {
			t.Fatal("recovery dependency path refused")
		}
		before, err := os.Lstat(path)
		if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > 8<<20 {
			t.Fatal("recovery dependency image unavailable")
		}
		file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal("recovery dependency could not be opened")
		}
		opened, openErr := file.Stat()
		body, readErr := io.ReadAll(io.LimitReader(file, 8<<20+1))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		current, currentErr := os.Lstat(path)
		if openErr != nil || readErr != nil || afterErr != nil || closeErr != nil || currentErr != nil || !records.SameLocalFile(before, opened) || !records.SameLocalFile(before, after) || !records.SameLocalFile(before, current) || before.Mode() != current.Mode() || before.Mode() != after.Mode() || before.Size() != int64(len(body)) || before.Size() != current.Size() || before.Size() != after.Size() || !before.ModTime().Equal(current.ModTime()) || !before.ModTime().Equal(after.ModTime()) {
			t.Fatal("recovery dependency changed while taking its image")
		}
		pair.Files = append(pair.Files, records.PublicOutputRecoveryPairFile{Path: relative, SHA256: bodyDigest(body), Bytes: uint64(len(body)), Mode: uint32(before.Mode().Perm()), Data: body})
	}
	slices.SortFunc(pair.Files, func(a, b records.PublicOutputRecoveryPairFile) int { return strings.Compare(a.Path, b.Path) })
	if pair.Validate(input) != nil {
		t.Fatal("recovery source pair is incomplete or outside its finite bounds")
	}
	return pair
}

// full_only: false
func TestPublicOutputRecoveryPairImageOrdersCompleteDirectoryInventory(t *testing.T) {
	state := t.TempDir()
	directory := filepath.Join(state, "public-source")
	files := map[string]string{
		"configuration.json":                       `{"generated":".enkv/cleanup.generated.json"}`,
		".enkv/cleanup.generated.json":             `{}`,
		".enkv/.enkv-locks/cleanup.generated.json": "",
		".enkv-locks/configuration.json":           "",
		"init.files/plain":                         "retained source bytes",
	}
	for name, body := range files {
		path := filepath.Join(directory, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, []byte(body), 0600) != nil {
			t.Fatal("prepared source fixture unavailable")
		}
	}
	input := records.PublicOutputRecoveryInput{StateDir: state}
	pair := publicOutputRecoveryPairImage(t, input)
	want := []string{".enkv-locks/configuration.json", ".enkv/.enkv-locks/cleanup.generated.json", ".enkv/cleanup.generated.json", "configuration.json", "init.files/plain"}
	if len(pair.Files) != len(want) || pair.Validate(input) != nil {
		t.Fatal("prepared pair omitted a dependency or lock file")
	}
	for i, file := range pair.Files {
		if file.Path != want[i] || string(file.Data) != files[want[i]] || file.Mode != 0600 {
			t.Fatal("prepared pair changed path order, bytes or mode")
		}
	}
}
