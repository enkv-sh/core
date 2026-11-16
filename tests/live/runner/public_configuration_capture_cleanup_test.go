package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// This ledger is independent of private fixture admission. An empty preflight
// and each originally joined child capture delimit this run's possible creates.
// A pending or damaged capture prevents cleanup from claiming a settled result.
type publicOwnership = records.PublicConfigurationOwnership
type publicCaptureReceipt = records.PublicConfigurationCaptureRegistration

// Competing empty initializations have independent Domain identities. Cleanup
// may read their exact captured creates without treating either as an admitted
// Product domain or permitting a key outside the original run prefix.
func publicObjectDomain(prefix, key string) (contract.ID, bool) {
	var id contract.ID
	suffix, ok := strings.CutPrefix(key, prefix+"/")
	if !ok {
		return id, false
	}
	text, _, ok := strings.Cut(suffix, "/")
	if !ok {
		return id, false
	}
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != len(id) || hex.EncodeToString(raw) != text {
		return id, false
	}
	copy(id[:], raw)
	return id, !id.IsZero()
}
func publicObjectKeyLimit(prefix, key string) uint32 {
	if key == prefix+"/HEAD" {
		return contract.MaxHeadLength
	}
	domain, ok := publicObjectDomain(prefix, key)
	if !ok {
		return 0
	}
	return liveFixtureKeyLimit(prefix+"/HEAD", fmt.Sprintf("%s/%x/", prefix, domain), key)
}
func publicOwnedKey(prefix, key string, allowed map[string]bool) bool {
	sum := sha256.Sum256([]byte(key))
	return publicObjectKeyLimit(prefix, key) > 0 && allowed[hex.EncodeToString(sum[:])]
}

type publicCleanupReadStore struct {
	contract.Store
	prefix  string
	allowed map[string]bool
	open    func(contract.ID) (contract.Store, error)
}

type publicCleanupReadProbe struct {
	contract.Store
	keys []string
}

func (p *publicCleanupReadProbe) Read(_ context.Context, key string, _ uint32) contract.ReadResult {
	p.keys = append(p.keys, key)
	return contract.ReadResult{Status: contract.ReadMissing}
}

// full_only: false
func TestPublicConfigurationCleanupRequiresCapturedKeyForEveryProposedDomain(t *testing.T) {
	prefix := "enkv-test/0123456789abcdef0123456789abcdef/public"
	a, b, object := contract.Hash([]byte("independent proposal a")), contract.Hash([]byte("independent proposal b")), contract.Hash([]byte("root object"))
	first, second := fmt.Sprintf("%s/%x/root/0/%x", prefix, a, object), fmt.Sprintf("%s/%x/root/0/%x", prefix, b, object)
	allowed := map[string]bool{}
	for _, key := range []string{first, second, prefix + "/HEAD"} {
		digest := sha256.Sum256([]byte(key))
		allowed[hex.EncodeToString(digest[:])] = true
	}
	base, left, right := &publicCleanupReadProbe{}, &publicCleanupReadProbe{}, &publicCleanupReadProbe{}
	opened := []contract.ID{}
	route := &publicCleanupReadStore{Store: base, prefix: prefix, allowed: allowed, open: func(domain contract.ID) (contract.Store, error) {
		opened = append(opened, domain)
		switch domain {
		case a:
			return left, nil
		case b:
			return right, nil
		default:
			return nil, errInventory
		}
	}}
	for _, key := range []string{first, second, prefix + "/HEAD"} {
		if route.Read(context.Background(), key, 1024).Status != contract.ReadMissing {
			t.Fatal("captured proposal object did not use its exact read route")
		}
	}
	if !slices.Equal(opened, []contract.ID{a, b}) || !slices.Equal(base.keys, []string{prefix + "/HEAD"}) || !slices.Equal(left.keys, []string{first}) || !slices.Equal(right.keys, []string{second}) {
		t.Fatal("competing proposal read routes were mixed")
	}
	for _, key := range []string{first + "x", strings.Replace(first, "/root/", "/unknown/", 1), strings.Replace(first, prefix, prefix+"-other", 1), fmt.Sprintf("%s/%064x/root/0/%x", prefix, 0, object), fmt.Sprintf("%s/%x/member/0/%x", prefix, a, object)} {
		if publicOwnedKey(prefix, key, allowed) || route.Read(context.Background(), key, 1024).Status != contract.ReadInvalid {
			t.Fatal("uncaptured or malformed object acquired cleanup authority")
		}
	}
	if len(opened) != 2 || len(base.keys) != 1 || len(left.keys) != 1 || len(right.keys) != 1 {
		t.Fatal("refused cleanup key entered a provider route")
	}
}

func (s *publicCleanupReadStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if !publicOwnedKey(s.prefix, key, s.allowed) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonProof}
	}
	if key == s.prefix+"/HEAD" {
		return s.Store.Read(ctx, key, limit)
	}
	domain, ok := publicObjectDomain(s.prefix, key)
	if !ok {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonProof}
	}
	selected, err := s.open(domain)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonConstruction}
	}
	return selected.Read(ctx, key, limit)
}

func publicLedgerPath(inv records.Invocation) string {
	return filepath.Join(inv.StateDir, "public-ownership.json")
}
func publicCaptureImage(path string, code int) (string, uint64, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() < 0 || before.Size() > nativeprocess.MaxCaptureBytes {
		return "", 0, errInventory
	}
	capture, sum, err := nativeprocess.ReadCaptureWithDigest(path)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !records.SameLocalFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || len(capture.Events) == 0 || capture.Events[len(capture.Events)-1].Code != code {
		return "", 0, errInventory
	}
	return hex.EncodeToString(sum[:]), uint64(before.Size()), nil
}

func publicCaptureReceiptUpdate(inv records.Invocation, registration publicCaptureReceipt, complete bool) error {
	_, originalRunID, valid := publicInvocationOwner(inv)
	if !valid {
		return errInventory
	}
	if row, known := catalog.PublicConfiguration(inv.Scenario); known && row.Output && inv.RunID != originalRunID {
		return errInventory
	}
	lock, err := os.OpenFile(filepath.Join(inv.StateDir, "public-captures.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errInventory
	}
	defer lock.Close()
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX) != nil {
		return errInventory
	}
	var ledger publicOwnership
	save := func(value publicOwnership) error { return records.WriteJSON(publicLedgerPath(inv), value, 0600) }
	var recovery records.PublicOutputRecoveryInput
	recoveryPath := filepath.Join(inv.StateDir, "public-output-recovery-input.json")
	if _, err := os.Lstat(recoveryPath); err == nil {
		var owner records.PublicOutputRecoveryCaptureOwner
		ownerPath := filepath.Join(inv.StateDir, "public-output-recovery-captures.json")
		if records.ReadJSON(recoveryPath, &recovery) != nil || recovery.VerifyFiles() != nil || recovery.StateDir != inv.StateDir || recovery.RecoveryRunID != inv.RunID || inv.Role != "cleanup" ||
			records.ReadJSON(ownerPath, &owner) != nil || owner.Version != 1 || owner.RunID != inv.RunID || owner.OriginalRunID != recovery.OriginalRunID {
			return errInventory
		}
		body, err := json.Marshal(recovery)
		if err != nil || owner.InputSHA256 != bodyDigest(body) {
			return errInventory
		}
		ledger.Captures = owner.Captures
		save = func(value publicOwnership) error {
			owner.Captures = value.Captures
			return records.WriteJSON(ownerPath, owner, 0600)
		}
	} else if !errors.Is(err, os.ErrNotExist) || records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || ledger.Version != 1 || ledger.RunID != originalRunID || !ledger.PreflightEmpty {
		return errInventory
	}
	relative, err := filepath.Rel(inv.StateDir, registration.Path)
	if err != nil || filepath.Dir(filepath.Dir(relative)) != "." || filepath.Base(relative) != "capture.jsonl" || !strings.HasPrefix(filepath.Base(filepath.Dir(relative)), "public-command-") {
		return errInventory
	}
	exact, err := records.SafePath(inv.StateDir, relative)
	if err != nil || exact != registration.Path || registration.ParentWorker != inv.Worker || registration.ParentNonce != inv.Nonce || registration.ParentRole != inv.Role || inv.Worker == "" || inv.Nonce == "" || inv.Role == "" || registration.Actor == "" || registration.NativeKind != "cli" && registration.NativeKind != "consumer" {
		return errInventory
	}
	index := slices.IndexFunc(ledger.Captures, func(row publicCaptureReceipt) bool { return row.Path == registration.Path })
	if !complete {
		if index >= 0 || len(ledger.Captures) >= records.MaximumPublicConfigurationCaptures || registration.Ordinal != 0 || registration.Complete || registration.SHA256 != "" || registration.Bytes != 0 || registration.ExitCode != 0 {
			return errInventory
		}
		registration.Ordinal = uint16(len(ledger.Captures))
		ledger.Captures = append(ledger.Captures, registration)
	} else {
		if index < 0 || ledger.Captures[index].Complete || registration.ExitCode < 0 || registration.ExitCode > 255 {
			return errInventory
		}
		original := ledger.Captures[index]
		if original.Ordinal != uint16(index) || original.ParentWorker != registration.ParentWorker || original.ParentNonce != registration.ParentNonce || original.ParentRole != registration.ParentRole || original.Actor != registration.Actor || original.NativeKind != registration.NativeKind || registration.Ordinal != 0 && registration.Ordinal != original.Ordinal {
			return errInventory
		}
		sum, size, err := publicCaptureImage(registration.Path, registration.ExitCode)
		if err != nil {
			return errInventory
		}
		original.SHA256, original.Bytes, original.Complete, original.ExitCode = sum, size, true, registration.ExitCode
		ledger.Captures[index] = original
	}
	return save(ledger)
}

func runPublicConfigurationCleanup(t testing.TB, inv records.Invocation, input liveRunInput, failure *records.FailureRecorder) {
	if input.OutputRecovery != nil {
		runPublicOutputRecoveryCleanup(t, inv, input, failure)
		return
	}
	worker, err := records.NewWorker(inv, liveProvider(), input.Scenarios[0], failure)
	if err != nil {
		t.Fatal("public cleanup worker unavailable")
	}
	worker.Result.Actor = input.Participants["cleanup"]
	worker.Result.Cleanup = &records.Cleanup{Outcome: "unresolved"}
	limits := input.Limits
	limits.Requests, limits.BodyBytes = limits.CleanupRequests, limits.CleanupBytes
	if input.Generator != nil {
		limits.GeneratorRetires = min(limits.GeneratorRetires, 6)
	}
	budget := &runBudget{limits: limits, keys: map[string]bool{}}
	defer finishLiveWorker(t, worker, budget)
	lease, err := lockInventory(inv.StateDir)
	if err != nil {
		t.Fatal("public cleanup ownership unavailable")
	}
	defer lease.Close()
	var ledger publicOwnership
	if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || ledger.Version != 1 || ledger.RunID != input.RunID || ledger.Prefix != input.Prefix || ledger.Binding != settingsBinding(input.Settings) || !ledger.PreflightEmpty || ledger.Source != filepath.Join(inv.StateDir, "public-source", "configuration.json") {
		t.Fatal("public cleanup ledger refused")
	}
	allowed, unknown := publicCapturedObjectKeys(inv.StateDir, ledger.Captures)
	controlled, controlledUnknown, controlledErr := publicControlledObjectKeys(inv, input, ledger)
	if controlledErr != nil {
		worker.Result.Cleanup.UnknownEffects = nil
		t.Fatal("controlled administrative inventory is unavailable; evidence retained")
	}
	unknown += controlledUnknown
	for _, key := range controlled {
		sum := sha256.Sum256([]byte(key))
		allowed[hex.EncodeToString(sum[:])] = true
	}
	worker.Result.Cleanup.UnknownEffects = &unknown
	if unknown != 0 {
		t.Fatal("public child creates remain unresolved; evidence retained")
	}
	domain := contract.Hash([]byte(input.Prefix))
	hasDomain := ledger.Domain != ""
	if hasDomain {
		raw, err := hex.DecodeString(ledger.Domain)
		if err != nil || len(raw) != len(domain) {
			t.Fatal("public cleanup Domain malformed")
		}
		copy(domain[:], raw)
	} else if observed, err := publicSourceDomain(ledger.Source); err == nil {
		domain, hasDomain = observed, true
	}
	ctx, cancel := context.WithTimeout(worker.Context(context.Background()), time.Duration(input.Limits.CleanupSeconds)*time.Second)
	defer cancel()
	if row, ok := catalog.PublicConfiguration(input.Scenarios[0]); ok && row.Output {
		publicCleanupOutputs(t, ctx, inv, input, budget, ledger.Source, ledger)
		if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil {
			t.Fatal("public output cleanup original captures unavailable; domain retained")
		}
		allowed, unknown = publicCapturedObjectKeys(inv.StateDir, ledger.Captures)
		worker.Result.Cleanup.UnknownEffects = &unknown
		if unknown != 0 {
			t.Fatal("public output cleanup Store effects unresolved; domain retained")
		}
	}
	// Generator custody is settled before any run-prefix deletion. Local join
	// alone never settles a provider request with a missing terminal result.
	if input.Generator != nil {
		if generatorErr := cleanupCloudflareFixture(ctx, input, budget); generatorErr != nil {
			fact := liveHarnessFailure(generatorErr, "generator_cleanup", "ledger", "evidence_unavailable", "unknown")
			worker.Result.HarnessFailure = &fact
			worker.Result.Cleanup.HarnessFailure = &fact
			worker.Result.Cleanup.UnknownEffects = nil
			t.Fatal("public generator cleanup unresolved; domain prefix retained")
		}
		generated, err := records.ReadGeneratorFixtureLedger(input.GeneratorCleanupLedger, input.RunID, input.Generator.Account)
		if err != nil || !generated.Clean() {
			t.Fatal("public generator ownership remains; domain prefix retained")
		}
	}
	cleaner, err := openPublicPrefixCleaner(ctx, input, domain, inv.StateDir, allowed)
	if err != nil {
		t.Fatal("public cleanup context unavailable")
	}
	publicCleanupOwnedPrefix(t, ctx, inv, input, budget, worker, cleaner, allowed, unknown, domain, hasDomain, func() error {
		return publicWriteEvidence(inv, input)
	})
}

func publicCleanupOwnedPrefix(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, worker *records.WorkerRecorder, cleaner *livePrefixCleaner, allowed map[string]bool, unknown int64, domain contract.ID, hasDomain bool, complete func() error) {
	t.Helper()
	worker.Result.Cleanup.UnknownEffects = &unknown
	sequence := liveBeginPhase(t, worker, "cleanup", true)
	defer func() { liveEndPhase(t, worker, sequence, !t.Failed()) }()
	keys, err := scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
	if err != nil {
		worker.Result.Cleanup.UnknownEffects = nil
		t.Fatal("public cleanup complete scan unavailable")
	}
	remaining := int64(len(keys))
	worker.Result.Cleanup.RemainingOwnedObjects = &remaining
	if !hasDomain && len(keys) != 0 {
		worker.Result.Cleanup.UnknownEffects = nil
		t.Fatal("public failed setup has unexplained prefix objects")
	}
	store := recordedStore{Store: cleaner.Store, budget: budget}
	// Import only keys proved by original native create attempts, a complete
	// preflight and this complete independent LIST. An unknown key is preserved.
	inventory := &objectInventory{path: filepath.Join(inv.StateDir, "public-cleanup-inventory.json"), stopped: true, image: inventoryImage{Version: 1, RunID: input.RunID, Binding: settingsBinding(input.Settings), Prefix: input.Prefix, Domain: domain, Deleted: map[string]int{}}}
	if _, err := os.Lstat(inventory.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("public cleanup requires explicit retained-inventory recovery")
	}
	if inventory.save() != nil {
		t.Fatal("public cleanup original source unavailable")
	}
	if publicAdoptCapturedObjects(ctx, inventory, cleaner, budget, keys, allowed) != nil {
		t.Fatal("public cleanup owned object observation unavailable; unknown objects preserved")
	}
	remove := func(ctx context.Context, key string, token contract.Token) error {
		if !budget.reserve(2, operationBodyAllowance, "", 0) {
			return errRunLimit
		}
		return cleaner.Delete(ctx, key, token)
	}
	if inventory.cleanup(ctx, store, remove) != nil {
		observed, err := inventory.image.unknownEffects()
		if err != nil {
			worker.Result.Cleanup.UnknownEffects = nil
		} else {
			unknown = observed
		}
		owned, err := inventory.owned(true)
		if err != nil {
			worker.Result.Cleanup.RemainingOwnedObjects = nil
		} else {
			remaining = int64(len(owned))
		}
		t.Fatal("public cleanup conditional deletion unresolved")
	}
	final, err := scanOperatorPrefix(ctx, cleaner, budget, input.Prefix+"/")
	if err != nil || len(final) != 0 {
		worker.Result.Cleanup.UnknownEffects = nil
		t.Fatal("public cleanup final absence unavailable")
	}
	remaining = 0
	if complete() != nil {
		t.Fatal("public cleanup evidence handoff unavailable; originals retained")
	}
	worker.Result.Cleanup.Outcome = "passed"
}
func publicControlledObjectKeys(inv records.Invocation, input liveRunInput, ledger publicOwnership) ([]string, int64, error) {
	if ledger.ControlledInventory == "" {
		return nil, 0, nil
	}
	if !publicAuthorityOperator(input) || ledger.ControlledInventory != filepath.Join(inv.StateDir, "public-controlled-inventory.json") {
		return nil, 0, errInventory
	}
	var image inventoryImage
	if records.ReadJSON(ledger.ControlledInventory, &image) != nil || image.Version != 1 || image.RunID != input.RunID || image.Prefix != input.Prefix || image.Binding != settingsBinding(input.Settings) || image.Domain.IsZero() || image.RecoveryLocations != nil {
		return nil, 0, errInventory
	}
	domain, err := publicSourceDomain(ledger.Source)
	if err != nil || image.Domain != domain || ledger.Domain != "" && ledger.Domain != operatorIDText(domain) {
		return nil, 0, errInventory
	}
	unknown, err := image.unknownEffects()
	if err != nil {
		return nil, 0, errInventory
	}
	keys := make([]string, 0, len(image.Intents))
	for _, intent := range image.Intents {
		if publicObjectKeyLimit(input.Prefix, intent.Key) == 0 {
			return nil, 0, errInventory
		}
		if intent.State != "not_sent" && intent.State != "refused" {
			keys = append(keys, intent.Key)
		}
	}
	return keys, unknown, nil
}

func publicAdoptCapturedObjects(ctx context.Context, inventory *objectInventory, cleaner *livePrefixCleaner, budget *runBudget, keys []string, allowed map[string]bool) error {
	store := recordedStore{Store: cleaner.Store, budget: budget}
	for _, key := range keys {
		limit := publicObjectKeyLimit(inventory.image.Prefix, key)
		if limit == 0 || !publicOwnedKey(inventory.image.Prefix, key, allowed) || !cleaner.ValidKey(key) {
			return errInventory
		}
		read, _ := cleanupRead(ctx, store, key, limit)
		if read.Status != contract.ReadOK || !read.Token.Valid() {
			return errInventory
		}
		inventory.image.Intents = append(inventory.image.Intents, objectIntent{Key: key, Digest: bodyDigest(read.Body), Bytes: uint64(len(read.Body)), Kind: "fixture_create", State: "acknowledged"})
	}
	return inventory.save()
}

func publicCapturedObjectKeys(directory string, receipts []publicCaptureReceipt) (map[string]bool, int64) {
	allowed := map[string]bool{}
	var unknown int64
	for _, receipt := range receipts {
		if !receipt.Complete || !strings.HasPrefix(receipt.Path, directory+string(os.PathSeparator)) || filepath.Clean(receipt.Path) != receipt.Path {
			unknown++
			continue
		}
		capture, sum, err := nativeprocess.ReadCaptureWithDigest(receipt.Path)
		if err != nil || hex.EncodeToString(sum[:]) != receipt.SHA256 {
			unknown++
			continue
		}
		mutations := map[uint64]nativeprocess.Event{}
		terminals := map[uint64]nativeprocess.Event{}
		for _, event := range capture.Events {
			if event.Kind == "http-start" && event.Sent && (event.Operation == "store-write" || event.Operation == "head-write") {
				if !validInventoryDigest(event.ObjectKeySHA256) {
					unknown++
					continue
				}
				allowed[event.ObjectKeySHA256] = true
				mutations[event.Sequence] = event
			}
			if event.Kind == "store-result" && event.Sent {
				terminals[event.Sequence] = event
			}
		}
		for sequence, original := range mutations {
			terminal, present := terminals[sequence]
			// HTTP success cannot settle a Store write: response intake can fail
			// after a physical send, including with a successful HTTP status.
			// The parser checks every present terminal's exact join and uniqueness.
			if !present || terminal.Operation != original.Operation || terminal.ObjectKeySHA256 != original.ObjectKeySHA256 ||
				contract.WriteStatus(terminal.WriteStatus) == contract.WriteUnknown {
				unknown++
			}
		}
	}
	return allowed, unknown
}

// full_only: false
func TestPublicCaptureOwnershipRequiresOriginalJoinedEvidence(t *testing.T) {
	directory := t.TempDir()
	key := bodyDigest([]byte("owned key"))
	write := func(name string, events []nativeprocess.Event) publicCaptureReceipt {
		t.Helper()
		var body strings.Builder
		encoder := json.NewEncoder(&body)
		for _, event := range events {
			if encoder.Encode(event) != nil {
				t.Fatal("capture fixture encoding failed")
			}
		}
		path := filepath.Join(directory, name)
		if os.WriteFile(path, []byte(body.String()), 0600) != nil {
			t.Fatal("capture fixture unavailable")
		}
		return publicCaptureReceipt{Path: path, SHA256: bodyDigest([]byte(body.String())), Complete: true}
	}
	mutation := func(status int, terminal contract.WriteStatus) []nativeprocess.Event {
		return []nativeprocess.Event{
			{Kind: "http-start", Sequence: 1, Operation: "store-write", ObjectKeySHA256: key, Sent: true, LogicalConditionKind: "absent", WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("0")},
			{Kind: "http-return", Sequence: 1, Operation: "store-write", ObjectKeySHA256: key, Sent: true, Status: status},
			{Kind: "store-result", Sequence: 1, Operation: "store-write", ObjectKeySHA256: key, Sent: true, WriteStatus: uint8(terminal), LogicalConditionKind: "absent", WireConditionKind: "gcp-generation-match", WireConditionValue: []byte("0")},
			{Kind: "footer"},
		}
	}
	t.Run("sent-HTTP-success-without-Store-result", func(t *testing.T) {
		receipt := write("missing-store-result.jsonl", []nativeprocess.Event{
			{Kind: "http-start", Sequence: 1, Operation: "store-write", ObjectKeySHA256: key, Sent: true},
			{Kind: "http-return", Sequence: 1, Operation: "store-write", ObjectKeySHA256: key, Sent: true, Status: 200},
			{Kind: "footer"},
		})
		keys, unknown := publicCapturedObjectKeys(directory, []publicCaptureReceipt{receipt})
		if !keys[key] || unknown != 1 {
			t.Fatal("HTTP success without the original typed Store result erased write uncertainty", unknown)
		}
	})
	ack := write("ack.jsonl", mutation(200, contract.WriteAcknowledged))
	uncertain := write("unknown.jsonl", mutation(0, contract.WriteUnknown))
	for _, outcome := range []string{"error", "no-error"} {
		t.Run("callback-"+outcome+"-then-ack", func(t *testing.T) {
			events := mutation(0, contract.WriteUnknown)
			events[1].TransportTrace = &nativeprocess.TransportTrace{
				TLSDone: nativeprocess.TraceCallback{Observed: true, Outcome: outcome},
			}
			receipt := write("callback-"+outcome+".jsonl", events)
			if _, err := nativeprocess.ReadCapture(receipt.Path); err != nil {
				t.Fatal("closed callback capture was refused", err)
			}
			keys, unknown := publicCapturedObjectKeys(directory, []publicCaptureReceipt{receipt, ack})
			if unknown != 1 || !keys[key] || len(keys) != 1 {
				t.Fatal("callback outcome changed typed write uncertainty", unknown, len(keys))
			}
		})
	}
	serverFailure := write("server-failure.jsonl", mutation(500, contract.WriteUnknown))
	malformedSuccess := write("malformed-success.jsonl", mutation(200, contract.WriteUnknown))
	sentForbidden := write("sent-forbidden.jsonl", mutation(403, contract.WriteUnknown))
	incomplete := write("incomplete.jsonl", mutation(200, contract.WriteAcknowledged)[:3])
	wrongDigest := ack
	wrongDigest.SHA256 = bodyDigest([]byte("changed"))
	pending := publicCaptureReceipt{Path: filepath.Join(directory, "not-yet-started.jsonl")}
	for _, row := range []struct {
		name        string
		receipts    []publicCaptureReceipt
		wantUnknown int64
		wantKey     bool
	}{
		{"ack", []publicCaptureReceipt{ack}, 0, true},
		{"joined-zero-effect", []publicCaptureReceipt{write("readonly.jsonl", []nativeprocess.Event{{Kind: "footer"}})}, 0, false},
		{"pending-before-entry", []publicCaptureReceipt{pending}, 1, false},
		{"missing-footer", []publicCaptureReceipt{incomplete}, 1, false},
		{"changed-evidence", []publicCaptureReceipt{wrongDigest}, 1, false},
		{"unknown-then-ack", []publicCaptureReceipt{uncertain, ack}, 1, true},
		{"malformed-success-then-ack", []publicCaptureReceipt{malformedSuccess, ack}, 1, true},
		{"sent-forbidden-then-ack", []publicCaptureReceipt{sentForbidden, ack}, 1, true},
		{"not-sent", []publicCaptureReceipt{write("not-sent.jsonl", []nativeprocess.Event{{Kind: "store-result", Operation: "store-write", ObjectKeySHA256: key, WriteStatus: uint8(contract.WriteRefused), LogicalConditionKind: "absent"}, {Kind: "footer"}})}, 0, false},
		{"server-failure-then-ack", []publicCaptureReceipt{serverFailure, ack}, 1, true},
		{"incomplete-then-ack", []publicCaptureReceipt{incomplete, ack}, 1, true},
		{"pending-then-ack", []publicCaptureReceipt{pending, ack}, 1, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			keys, unknown := publicCapturedObjectKeys(directory, row.receipts)
			if unknown != row.wantUnknown || keys[key] != row.wantKey || len(keys) != int(boolInt(row.wantKey)) {
				t.Fatal("later success or absence replaced original child evidence", unknown, len(keys))
			}
		})
	}
}

// full_only: false
func TestPublicCaptureReceiptRequiresIntentBeforeChildEntry(t *testing.T) {
	for _, preflight := range []bool{false, true} {
		t.Run(fmt.Sprint(preflight), func(t *testing.T) {
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			inv := records.Invocation{StateDir: directory, RunID: liveProtocolRun, Worker: "writer", Nonce: strings.Repeat("a", 32), Role: "writer"}
			ledger := publicOwnership{Version: 1, RunID: inv.RunID, PreflightEmpty: preflight}
			if records.WriteJSON(publicLedgerPath(inv), ledger, 0600) != nil {
				t.Fatal("capture ledger fixture unavailable")
			}
			captureDirectory := filepath.Join(inv.StateDir, "public-command-1")
			if os.Mkdir(captureDirectory, 0700) != nil {
				t.Fatal("capture directory fixture unavailable")
			}
			capture := filepath.Join(captureDirectory, "capture.jsonl")
			registration := publicCaptureReceipt{Path: capture, ParentWorker: inv.Worker, ParentNonce: inv.Nonce, ParentRole: inv.Role, Actor: "operator", NativeKind: "cli"}
			if os.WriteFile(capture, []byte("{\"kind\":\"footer\"}\n"), 0600) != nil {
				t.Fatal("capture fixture unavailable")
			}
			if publicCaptureReceiptUpdate(inv, registration, true) == nil {
				t.Fatal("child return acquired ownership without original pre-entry intent")
			}
			err = publicCaptureReceiptUpdate(inv, registration, false)
			if (err == nil) != preflight {
				t.Fatal("capture entry did not require empty-prefix ownership")
			}
			if !preflight {
				return
			}
			if publicCaptureReceiptUpdate(inv, registration, false) == nil || publicCaptureReceiptUpdate(inv, registration, true) != nil || publicCaptureReceiptUpdate(inv, registration, true) == nil {
				t.Fatal("capture intent or normal return was duplicated or lost")
			}
			if records.ReadJSON(publicLedgerPath(inv), &ledger) != nil || len(ledger.Captures) != 1 || !ledger.Captures[0].Complete {
				t.Fatal("joined capture receipt unavailable")
			}
			keys, unknown := publicCapturedObjectKeys(inv.StateDir, ledger.Captures)
			if unknown != 0 || len(keys) != 0 {
				t.Fatal("joined zero-effect child did not settle exactly its own intent")
			}
		})
	}
}

// full_only: false
func TestPublicControlledInventoryPreservesOriginalUnknownWrites(t *testing.T) {
	for _, condition := range []string{"ack", "unknown-then-ack", "missing", "foreign-run", "foreign-domain", "foreign-binding", "foreign-path", "invalid-state"} {
		t.Run(condition, func(t *testing.T) {
			inv := records.Invocation{StateDir: t.TempDir(), RunID: liveProtocolRun}
			input := liveRunInput{RunID: inv.RunID, Prefix: "enkv-test/" + inv.RunID + "/administrative", Scenarios: []string{"operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt"}, Settings: liveSettings{Provider: liveProvider()}}
			domain := contract.Hash([]byte("independently initialized domain"))
			source := filepath.Join(inv.StateDir, "configuration.json")
			publicWriteSource(t, source, map[string]any{"generated": "generated.json"})
			body, err := json.Marshal(map[string]any{"domain": map[string]any{"id": operatorIDText(domain)}})
			if err != nil || os.WriteFile(filepath.Join(inv.StateDir, "generated.json"), body, 0600) != nil {
				t.Fatal("public domain fixture unavailable")
			}
			path := filepath.Join(inv.StateDir, "public-controlled-inventory.json")
			ledger := publicOwnership{ControlledInventory: path, Source: source}
			key := fmt.Sprintf("%s/%x/root/0/%x", input.Prefix, domain, contract.Hash([]byte("root")))
			intent := objectIntent{Key: key, Kind: "fixture_create", State: "acknowledged", Digest: bodyDigest([]byte("body")), Bytes: 4}
			image := inventoryImage{Version: 1, RunID: input.RunID, Prefix: input.Prefix, Binding: settingsBinding(input.Settings), Domain: domain, Deleted: map[string]int{}, Intents: []objectIntent{intent}}
			switch condition {
			case "unknown-then-ack":
				image.Intents[0].State = "unknown"
				image.Intents = append(image.Intents, intent)
			case "foreign-run":
				image.RunID = "another-run"
			case "foreign-domain":
				image.Domain = contract.Hash([]byte("another initialized domain"))
			case "foreign-binding":
				image.Binding = "another provider configuration"
			case "foreign-path":
				ledger.ControlledInventory = filepath.Join(inv.StateDir, "another-inventory.json")
			case "invalid-state":
				image.Intents[0].State = "invented"
			}
			if condition != "missing" && records.WriteJSON(path, image, 0600) != nil {
				t.Fatal("controlled inventory fixture unavailable")
			}
			keys, unknown, err := publicControlledObjectKeys(inv, input, ledger)
			good := condition == "ack" || condition == "unknown-then-ack"
			if (err == nil) != good {
				t.Fatal("controlled ownership accepted another run, domain, source or incomplete evidence", err)
			}
			if good && (len(keys) != len(image.Intents) || keys[0] != key || unknown != int64(boolInt(condition == "unknown-then-ack"))) {
				t.Fatal("controlled ownership changed exact keys or erased original uncertainty")
			}
		})
	}
}
