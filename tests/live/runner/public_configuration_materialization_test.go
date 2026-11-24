package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// Expected application bytes are literal records derived from the two supplied
// fixture values and the declared dotenv emission rules, without the emitter.
const publicMaterializationPlain = "PLAIN=live plain\n"
const publicMaterializationMixed = "PLAIN=live plain\nSECRET='live #secret\nline'\n"

type publicMaterializationEntry struct {
	Name            string `json:"name"`
	Slot            uint16 `json:"slot"`
	Incarnation     string `json:"entry_incarnation_id"`
	Value           string `json:"value_state_id"`
	Source          uint8  `json:"value_source"`
	Confidentiality uint8  `json:"confidentiality_class"`
}

type publicMaterializationBinding struct {
	ID          string `json:"binding_id"`
	Incarnation string `json:"binding_incarnation_id"`
	Serial      uint64 `json:"binding_serial"`
	Provider    uint8  `json:"provider"`
	Wrap        uint16 `json:"wrap_profile"`
	Protection  uint8  `json:"protection_class"`
	Selector    string `json:"key_selector"`
	SPKI        []byte `json:"public_key_spki"`
	Fingerprint string `json:"fingerprint"`
}

// Only authenticated public identities and bounded structural observations cross
// the writer's process boundary. No application bytes or their hashes are saved.
type publicMaterializationFacts struct {
	Domain, Revision, Snapshot, Recipient                                       string
	Binding                                                                     publicMaterializationBinding
	Entries                                                                     []publicMaterializationEntry
	MixedVerified, PlainVerified, DeniedVerified, SourcePreserved, FilesRemoved bool
}

type publicMaterializationResult struct {
	Schema          string          `json:"schema"`
	Operation       string          `json:"operation_kind"`
	State           string          `json:"state_result"`
	Effect          string          `json:"effect_summary"`
	Output          string          `json:"output_summary"`
	PayloadKind     string          `json:"operation_payload"`
	Receipt         json.RawMessage `json:"receipt_hex"`
	RequestID       string          `json:"request_id"`
	OperationID     string          `json:"operation_id"`
	RequestIdentity string          `json:"request_identity"`
	Replay          string          `json:"replay_identity"`
	Domain          string          `json:"domain_id"`
	Evidence        string          `json:"evidence_ceiling"`
	Result          struct {
		Outcome  uint8  `json:"outcome"`
		Reason   uint8  `json:"reason"`
		Evidence uint8  `json:"evidence"`
		Revision string `json:"observed_revision_id"`
		Snapshot string `json:"observed_snapshot_id"`
	} `json:"result"`
	Failure  *struct{ Stage, Reason string } `json:"failure"`
	Effects  []json.RawMessage               `json:"effects"`
	Outputs  []json.RawMessage               `json:"outputs"`
	Duties   []json.RawMessage               `json:"duties"`
	Hazards  []json.RawMessage               `json:"hazards"`
	Warnings []json.RawMessage               `json:"warning_summary"`
	Capsule  string                          `json:"capsule_policy"`
	Payload  struct {
		Schema    string `json:"schema"`
		Identity  string `json:"request_identity"`
		Domain    string `json:"domain_id"`
		Revision  string `json:"head_revision_id"`
		Snapshot  string `json:"snapshot_id"`
		Recipient struct {
			Kind    uint8                        `json:"subject_kind"`
			ID      string                       `json:"recipient_id"`
			Binding publicMaterializationBinding `json:"binding"`
		} `json:"recipient"`
		Target struct {
			Path    string `json:"path"`
			Surface string `json:"surface_id"`
			Format  string `json:"format"`
			Profile string `json:"native_profile"`
		} `json:"target"`
		Entries []publicMaterializationEntry `json:"entries"`
		Facts   struct {
			Replacement    string                          `json:"replacement"`
			Candidate      string                          `json:"candidate_verification"`
			Installed      string                          `json:"installed_verification"`
			Completion     string                          `json:"native_completion"`
			Disclosure     string                          `json:"plaintext_disk_disclosure"`
			Cleanup        string                          `json:"candidate_cleanup"`
			Failure        *struct{ Stage, Reason string } `json:"failure"`
			CleanupFailure json.RawMessage                 `json:"cleanup_failure"`
			Residue        string                          `json:"residue_path"`
		} `json:"facts"`
	} `json:"payload"`
}

func runPublicMaterialization(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string) *publicMaterializationFacts {
	t.Helper()
	if input.RecoveryMode != "enabled" {
		t.Fatal("materialization live fixture requires enabled Recovery")
	}
	document := publicSourceDocument(t, source)
	document["entries"] = map[string]any{
		"PLAIN":  map[string]any{"confidentiality": "plain", "recipients": []string{"consumer"}, "source": map[string]any{"kind": "supplied", "value": "live plain"}},
		"SECRET": map[string]any{"confidentiality": "secret", "recipients": []string{"consumer"}, "source": map[string]any{"kind": "supplied"}},
	}
	publicWriteSource(t, source, document)
	secret := []byte("live #secret\nline")
	defer clear(secret)
	set := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{NoKMS: true}, secret, "set", "--source", source, "--source-format", "json", "--name", "SECRET", "--json")
	publicAssertSet(t, set, source, "SECRET")
	clear(set.Body)
	image := publicSourceImage(t, source)
	applied := publicCLI(t, ctx, inv, input, budget, "apply", false, nativeprocess.Policy{}, nil, "apply", "--source", source, "--source-format", "json", "--json")
	if !publicApplyMatches(applied, publicProduct(t, applied, "apply-declaration"), "success") {
		clear(applied.Body)
		t.Fatal("materialization setup did not select the complete supplied set")
	}
	clear(applied.Body)
	publicAssertNoRecovery(t, applied.Capture)
	publicImageUnchanged(t, image)
	basis, descriptor := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("materialization independent GET-only Store unavailable")
	}
	current := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget})
	facts := publicMaterializationExpected(t, current, descriptor, input.Settings.ReaderKEKID)
	// These edits are deliberately left unapplied. The explicit command must use
	// current authenticated values and membership, including its ordinary identity.
	document = publicSourceDocument(t, source)
	entries := document["entries"].(map[string]any)
	entries["PLAIN"].(map[string]any)["source"] = map[string]any{"kind": "supplied", "value": "pending plain"}
	entries["SECRET"].(map[string]any)["recipients"] = []string{}
	entries["UNSELECTED"] = map[string]any{"confidentiality": "plain", "recipients": []string{"consumer"}, "source": map[string]any{"kind": "supplied", "value": "pending unselected"}}
	document["recipients"].(map[string]any)["consumer"].(map[string]any)["display_name"] = "Pending Consumer"
	publicWriteSource(t, source, document)
	publicMaterializationCommand(t, ctx, inv, input, budget, source, *facts, "recipient-consumer", false, false)
	facts.MixedVerified = true
	publicMaterializationCommand(t, ctx, inv, input, budget, source, *facts, "reader", true, false)
	facts.PlainVerified = true
	publicMaterializationCommand(t, ctx, inv, input, budget, source, *facts, "reader", false, true)
	facts.DeniedVerified, facts.SourcePreserved, facts.FilesRemoved = true, true, true
	publicObserveMaterializationPair(t, ctx, inv, input, budget, source, *facts)
	return facts
}

func publicObserveMaterializationPair(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicMaterializationFacts) {
	t.Helper()
	publicObservePairVerdict(t, ctx, inv, input, budget, source, "mismatch", &publicComparisonObservation{Domain: facts.Domain, Revision: facts.Revision, Snapshot: facts.Snapshot})
}

func publicMaterializationExpected(t testing.TB, current *StateSession, descriptor contract.GenesisDescriptorCore, selector string) *publicMaterializationFacts {
	t.Helper()
	id := func(value contract.ID) string { return hex.EncodeToString(value[:]) }
	facts := &publicMaterializationFacts{Domain: id(current.root.Domain), Revision: id(current.head.Core.Revision), Snapshot: id(current.root.Snapshot)}
	if current.root.CurrentAccess.Core.CurrentControl.Recovery == nil || len(current.root.Names) != 2 || current.root.ValueEntryCount != 2 || current.root.SecretCount != 1 {
		t.Fatal("materialization current fixture lacks its exact set or available Recovery")
	}
	for _, recipient := range descriptor.Recipients {
		if recipient.RecipientID == descriptor.AuthorityRecipientID {
			continue
		}
		b := recipient.CurrentBinding
		if facts.Recipient != "" || recipient.Status != contract.CurrentRecipient || b == nil || b.KeySelector != selector {
			t.Fatal("materialization current ordinary Recipient differs")
		}
		facts.Recipient = id(recipient.RecipientID)
		facts.Binding = publicMaterializationBinding{ID: id(b.BindingID), Incarnation: id(b.BindingIncarnationID), Serial: b.BindingSerial, Provider: uint8(b.Provider), Wrap: b.WrapProfile, Protection: uint8(b.ProtectionClass), Selector: b.KeySelector, SPKI: bytes.Clone(b.SPKI), Fingerprint: id(b.Fingerprint)}
	}
	if facts.Recipient == "" {
		t.Fatal("materialization current ordinary Recipient unavailable")
	}
	for i, named := range current.root.Names {
		entry := current.valueEntry(named.Slot)
		name := []string{"PLAIN", "SECRET"}[i]
		if entry == nil || named.Name != name || entry.Name != name || entry.ValueSource != contract.Supplied || (entry.ConfidentialityClass == contract.Secret) != (i == 1) || len(entry.Recipients) != 2 {
			t.Fatal("materialization current selection differs from literal whole set")
		}
		members := []string{id(entry.Recipients[0]), id(entry.Recipients[1])}
		if !slices.Contains(members, facts.Recipient) || !slices.Contains(members, id(descriptor.AuthorityRecipientID)) || i == 0 && !bytes.Equal(entry.ValueBytes, []byte("live plain")) {
			t.Fatal("materialization current membership or plain bytes differ")
		}
		facts.Entries = append(facts.Entries, publicMaterializationEntry{Name: name, Slot: named.Slot, Incarnation: id(entry.Incarnation), Value: id(entry.ValueState), Source: uint8(entry.ValueSource), Confidentiality: uint8(entry.ConfidentialityClass)})
	}
	return facts
}

func publicMaterializationFreshFactsValid(condition string, facts publicProcessFacts) bool {
	if condition != "materialization" {
		return facts.Materialization == nil
	}
	f := facts.Materialization
	if f == nil || !facts.ExpectReady || facts.Domain != f.Domain || facts.Operator != nil || facts.Replacement != nil || facts.Inspection != nil || facts.CapacityGC != nil || len(facts.Outputs) != 0 || !f.MixedVerified || !f.PlainVerified || !f.DeniedVerified || !f.SourcePreserved || !f.FilesRemoved {
		return false
	}
	if !publicIdentityHex(f.Domain) || !publicIdentityHex(f.Revision) || !publicIdentityHex(f.Snapshot) || !publicIdentityHex(f.Recipient) || !publicIdentityHex(f.Binding.ID) || !publicIdentityHex(f.Binding.Incarnation) || f.Binding.Serial == 0 || !publicIdentityHex(f.Binding.Fingerprint) || len(f.Binding.SPKI) == 0 || len(f.Entries) != 2 {
		return false
	}
	for i, e := range f.Entries {
		if e.Name != []string{"PLAIN", "SECRET"}[i] || !publicIdentityHex(e.Incarnation) || !publicIdentityHex(e.Value) || e.Source != uint8(contract.Supplied) || e.Confidentiality != []uint8{uint8(contract.Plain), uint8(contract.Secret)}[i] || e.Slot >= contract.CryptoMaxValueEntries {
			return false
		}
	}
	return f.Entries[0].Slot != f.Entries[1].Slot
}

func publicMaterializationFresh(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicMaterializationFacts) {
	t.Helper()
	basis, descriptor := publicOperatorGenesis(t, source)
	store, err := openPublicReaderStore(ctx, input, descriptor.DomainID, inv.StateDir)
	if err != nil {
		t.Fatal("fresh materialization independent Store unavailable")
	}
	current := publicOperatorOpen(t, ctx, descriptor.DomainID, basis, recordedStore{Store: store, budget: budget})
	expected := publicMaterializationExpected(t, current, descriptor, input.Settings.ReaderKEKID)
	expected.MixedVerified, expected.PlainVerified, expected.DeniedVerified, expected.SourcePreserved, expected.FilesRemoved = true, true, true, true, true
	if !reflect.DeepEqual(*expected, facts) {
		t.Fatal("fresh materialization public selection differs")
	}
	publicMaterializationCommand(t, ctx, inv, input, budget, source, facts, "reader", true, false)
	publicMaterializationCommand(t, ctx, inv, input, budget, source, facts, "reader", false, true)
	publicObserveMaterializationPair(t, ctx, inv, input, budget, source, facts)
}

func publicMaterializationCommand(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, facts publicMaterializationFacts, role string, plain, denied bool) {
	t.Helper()
	// Application bytes stay outside retained run evidence. Exact file cleanup is
	// registered before the joined child can create any native candidate.
	directory, err := os.MkdirTemp("", "enkv-live-materialization-")
	if err != nil {
		t.Fatal("private materialization directory unavailable")
	}
	target := filepath.Join(directory, "application.env")
	defer func() {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			t.Error("private materialization exact file removal failed")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Error("private materialization file remains")
		}
		if err := os.Remove(directory); err != nil {
			t.Error("private materialization candidate or directory remains")
		}
	}()
	image := publicSourceImage(t, source)
	args := []string{"materialize", "--source", source, "--source-format", "json", "--recipient-id", facts.Recipient, "--name", "PLAIN"}
	expected := facts.Entries
	want := []byte(publicMaterializationPlain)
	if !plain {
		args = append(args, "--name", "SECRET")
		want = []byte(publicMaterializationMixed)
	} else {
		expected = expected[:1]
	}
	defer clear(want)
	args = append(args, "--out", target, "--json")
	child := publicCLI(t, ctx, inv, input, budget, role, false, nativeprocess.Policy{NoKMS: plain, RecipientKEK: input.Settings.ReaderKEKID}, nil, args...)
	defer clear(child.Body)
	if !publicMaterializationResultMatches(child, facts, expected, target, denied) || !publicMaterializationCapture(child.Capture, plain, denied) {
		t.Fatal("materialization result or exact Recipient capability evidence differs")
	}
	publicImageUnchanged(t, image)
	if denied {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatal("denied materialization created a file or candidate")
		}
		return
	}
	if !publicMaterializationFileMatches(target, want) {
		t.Fatal("materialization complete bytes, mode or whole file set differs")
	}
	if os.Remove(target) != nil {
		t.Fatal("materialization exact file removal failed")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("materialization exact file removal not observed")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("materialization left a native candidate")
	}
}

func publicMaterializationFileMatches(path string, want []byte) bool {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode() != 0600 || before.Size() != int64(len(want)) {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	opened, statErr := file.Stat()
	got, readErr := io.ReadAll(io.LimitReader(file, int64(len(want)+1)))
	defer clear(got)
	closeErr := file.Close()
	entries, dirErr := os.ReadDir(filepath.Dir(path))
	return statErr == nil && records.SameLocalFile(before, opened) && readErr == nil && closeErr == nil && bytes.Equal(got, want) && dirErr == nil && len(entries) == 1 && entries[0].Name() == filepath.Base(path) && entries[0].Type().IsRegular()
}

func publicMaterializationResultMatches(child publicChildResult, want publicMaterializationFacts, entries []publicMaterializationEntry, target string, denied bool) bool {
	var result publicMaterializationResult
	d := json.NewDecoder(bytes.NewReader(child.Body))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || d.Decode(new(any)) != io.EOF || result.Schema != "ProductResult/v1" || result.Operation != "materialize" || result.Effect != "not-applicable" || result.Output != "not-applicable" || result.PayloadKind != "MaterializationPayload/v1" || len(result.Receipt) != 0 {
		return false
	}
	if result.Result.Evidence != 1 || result.Result.Revision != want.Revision || result.Result.Snapshot != want.Snapshot || result.Evidence != "canonical" {
		return false
	}
	if !publicIdentityHex(result.RequestID) || !publicIdentityHex(result.OperationID) || !publicIdentityHex(result.RequestIdentity) || result.Replay != "none" || result.Domain != want.Domain || len(result.Effects) != 0 || len(result.Outputs) != 0 || len(result.Duties) != 0 || len(result.Hazards) != 0 || len(result.Warnings) != 0 || result.Capsule != "none" {
		return false
	}
	p := result.Payload
	if p.Identity != result.RequestIdentity || p.Schema != "MaterializationPayload/v1" || !publicIdentityHex(p.Identity) || p.Domain != want.Domain || p.Revision != want.Revision || p.Snapshot != want.Snapshot || p.Recipient.Kind != uint8(contract.OrdinaryWrapSubject) || p.Recipient.ID != want.Recipient || !reflect.DeepEqual(p.Recipient.Binding, want.Binding) || !reflect.DeepEqual(p.Entries, entries) || p.Target.Path != target || !publicIdentityHex(p.Target.Surface) || p.Target.Format != "application-dotenv/v1" || p.Target.Profile != "native-atomic-file/v1" || p.Facts.Residue != "" || !bytes.Equal(bytes.TrimSpace(p.Facts.CleanupFailure), []byte("null")) {
		return false
	}
	f := p.Facts
	if denied {
		return child.Code != 0 && result.Result.Outcome == 6 && result.Result.Reason == 17 && result.State == "unavailable" && f.Replacement == "not-replaced" && f.Candidate == "not-observed" && f.Installed == "not-observed" && f.Completion == "not-observed" && f.Disclosure == "none" && f.Cleanup == "not-created" && f.Failure != nil && f.Failure.Stage == "authentication" && f.Failure.Reason == "private-route-unavailable" && result.Failure != nil && *result.Failure == *f.Failure
	}
	return child.Code == 0 && child.DiagnosticBytes == 0 && result.Result.Outcome == 2 && result.Result.Reason == 0 && result.State == "success" && f.Replacement == "replaced" && f.Candidate == "verified" && f.Installed == "verified" && f.Completion == "complete" && f.Disclosure == "occurred" && f.Cleanup == "renamed" && f.Failure == nil && result.Failure == nil
}

func publicMaterializationCapture(capture nativeprocess.Capture, plain, denied bool) bool {
	reads, opens, returned, refused, constructed := 0, 0, 0, 0, 0
	footer := false
	for _, e := range capture.Events {
		if footer {
			return false
		}
		switch e.Kind {
		case "source-kind":
			if !e.Matched || e.Count != 1 {
				return false
			}
		case "construction":
			if plain || e.Operation != "key-access" || e.Role != "recipient-private" || e.Count != 1 {
				return false
			}
			constructed++
		case "http-start", "http-return":
			switch e.Operation {
			case "head-read", "store-read":
				if e.Kind == "http-return" && e.Sent && e.Status >= 200 && e.Status < 300 {
					reads++
				}
			case "kms-decrypt":
				if plain || e.Role != "recipient-private" || !e.Sent {
					return false
				}
				if e.Kind == "http-start" {
					opens++
				} else {
					returned++
					if e.PermissionDenied {
						refused++
					} else if e.Status < 200 || e.Status >= 300 {
						return false
					}
				}
			default:
				return false
			}
		case "footer":
			footer = (!denied && e.Code == 0 || denied && e.Code != 0)
		default:
			return false
		}
	}
	return footer && reads > 0 && (plain && constructed == 0 && opens == 0 && returned == 0 || !plain && constructed == 1 && opens == 1 && returned == 1 && (denied && refused == 1 || !denied && refused == 0))
}

// full_only: false
func TestPublicMaterializationFileObservationChecksExactBytesModeAndWholeSet(t *testing.T) {
	for _, condition := range []string{"exact", "different-bytes", "prefix", "wide-mode", "special-mode", "extra-file", "symlink"} {
		t.Run(condition, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "application.env")
			want := []byte(publicMaterializationMixed)
			body := bytes.Clone(want)
			if condition == "different-bytes" {
				body[len(body)-2] = 'X'
			}
			if condition == "prefix" {
				body = body[:len(body)-1]
			}
			if os.WriteFile(path, body, 0600) != nil {
				t.Fatal("synthetic materialization fixture unavailable")
			}
			switch condition {
			case "wide-mode":
				if os.Chmod(path, 0644) != nil {
					t.Fatal("synthetic mode unavailable")
				}
			case "special-mode":
				if os.Chmod(path, os.ModeSticky|0600) != nil {
					t.Fatal("synthetic special mode unavailable")
				}
			case "extra-file":
				if os.WriteFile(filepath.Join(filepath.Dir(path), "candidate"), nil, 0600) != nil {
					t.Fatal("synthetic candidate unavailable")
				}
			case "symlink":
				if os.Rename(path, path+".target") != nil || os.Symlink(path+".target", path) != nil {
					t.Fatal("synthetic alias unavailable")
				}
			}
			if publicMaterializationFileMatches(path, want) != (condition == "exact") {
				t.Fatal("materialization file evidence missed a complete-byte, mode or whole-set difference")
			}
		})
	}
}

// full_only: false
func TestPublicMaterializationCaptureRequiresExactRecipientRoute(t *testing.T) {
	for _, mode := range []string{"plain", "secret", "denied"} {
		base := nativeprocess.Capture{Events: []nativeprocess.Event{{Kind: "http-start", Operation: "head-read", Sent: true}, {Kind: "http-return", Operation: "head-read", Sent: true, Status: 200}}}
		if mode != "plain" {
			base.Events = append(base.Events, nativeprocess.Event{Kind: "construction", Count: 1, Operation: "key-access", Role: "recipient-private"}, nativeprocess.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "recipient-private", Sent: true}, nativeprocess.Event{Kind: "http-return", Operation: "kms-decrypt", Role: "recipient-private", Sent: true, Status: 200})
			if mode == "denied" {
				base.Events[len(base.Events)-1].PermissionDenied = true
				base.Events[len(base.Events)-1].Status = 403
			}
		}
		code := 0
		if mode == "denied" {
			code = 1
		}
		base.Events = append(base.Events, nativeprocess.Event{Kind: "footer", Code: code})
		for _, condition := range []string{"exact", "no-read", "no-footer", "wrong-exit", "recovery", "authority", "signer", "write", "extra-decrypt", "unsent", "no-denial", "wrong-construction", "extra-construction", "no-construction"} {
			t.Run(mode+"/"+condition, func(t *testing.T) {
				capture := nativeprocess.Capture{Events: slices.Clone(base.Events)}
				switch condition {
				case "no-read":
					capture.Events = capture.Events[2:]
				case "no-footer":
					capture.Events = capture.Events[:len(capture.Events)-1]
				case "wrong-exit":
					capture.Events[len(capture.Events)-1].Code = 1 - code
				case "recovery", "authority", "signer", "write", "extra-decrypt":
					e := nativeprocess.Event{Kind: "http-start", Operation: "kms-decrypt", Role: "recipient-private", Sent: true}
					switch condition {
					case "recovery":
						e.Role = "recovery-private"
					case "authority":
						e.Role = "authority"
					case "signer":
						e.Operation = "kms-sign"
					case "write":
						e.Operation = "store-write"
					}
					capture.Events = append(capture.Events[:len(capture.Events)-1], e, capture.Events[len(capture.Events)-1])
				case "wrong-construction", "extra-construction", "no-construction":
					if mode == "plain" {
						capture.Events = append([]nativeprocess.Event{{Kind: "construction", Count: 1, Operation: "key-access", Role: "recipient-private"}}, capture.Events...)
					} else {
						switch condition {
						case "wrong-construction":
							capture.Events[2].Role = "recovery-private"
						case "extra-construction":
							capture.Events = append([]nativeprocess.Event{capture.Events[2]}, capture.Events...)
						case "no-construction":
							capture.Events = append(capture.Events[:2], capture.Events[3:]...)
						}
					}
				case "unsent":
					for i := range capture.Events {
						if capture.Events[i].Operation == "kms-decrypt" {
							capture.Events[i].Sent = false
						}
					}
					if mode == "plain" {
						capture.Events[0].Operation = "kms-decrypt"
					}
				case "no-denial":
					if mode == "denied" {
						capture.Events[len(capture.Events)-2].PermissionDenied = false
					} else {
						capture.Events = nil
					}
				}
				if publicMaterializationCapture(capture, mode == "plain", mode == "denied") != (condition == "exact") {
					t.Fatal("materialization capture accepted an incomplete or alternate capability route")
				}
			})
		}
	}
}

// This independent result literal names every admitted public field. Repeated
// digits identify synthetic public records; SPKI is the literal word public.
const publicMaterializationSuccessJSON = `{"schema":"ProductResult/v1","operation_kind":"materialize","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","operation_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","request_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","replay_identity":"none","domain_id":"1111111111111111111111111111111111111111111111111111111111111111","evidence_ceiling":"canonical","result":{"outcome":2,"reason":0,"evidence":1,"observed_revision_id":"2222222222222222222222222222222222222222222222222222222222222222","observed_snapshot_id":"3333333333333333333333333333333333333333333333333333333333333333"},"failure":null,"effects":[],"outputs":[],"duties":[],"hazards":[],"warning_summary":[],"capsule_policy":"none","operation_payload":"MaterializationPayload/v1","payload":{"schema":"MaterializationPayload/v1","request_identity":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","domain_id":"1111111111111111111111111111111111111111111111111111111111111111","head_revision_id":"2222222222222222222222222222222222222222222222222222222222222222","snapshot_id":"3333333333333333333333333333333333333333333333333333333333333333","recipient":{"subject_kind":1,"recipient_id":"4444444444444444444444444444444444444444444444444444444444444444","binding":{"binding_id":"5555555555555555555555555555555555555555555555555555555555555555","binding_incarnation_id":"6666666666666666666666666666666666666666666666666666666666666666","binding_serial":7,"provider":1,"wrap_profile":2,"protection_class":1,"key_selector":"synthetic-selector","public_key_spki":"cHVibGlj","fingerprint":"7777777777777777777777777777777777777777777777777777777777777777"}},"target":{"path":"/private/application.env","surface_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","format":"application-dotenv/v1","native_profile":"native-atomic-file/v1"},"entries":[{"name":"PLAIN","slot":0,"entry_incarnation_id":"8888888888888888888888888888888888888888888888888888888888888888","value_state_id":"9999999999999999999999999999999999999999999999999999999999999999","value_source":1,"confidentiality_class":1},{"name":"SECRET","slot":1,"entry_incarnation_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","value_state_id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","value_source":1,"confidentiality_class":2}],"facts":{"replacement":"replaced","candidate_verification":"verified","installed_verification":"verified","native_completion":"complete","plaintext_disk_disclosure":"occurred","candidate_cleanup":"renamed","failure":null,"cleanup_failure":null}}}`

func publicMaterializationSyntheticFacts() publicMaterializationFacts {
	return publicMaterializationFacts{Domain: strings.Repeat("1", 64), Revision: strings.Repeat("2", 64), Snapshot: strings.Repeat("3", 64), Recipient: strings.Repeat("4", 64),
		Binding:       publicMaterializationBinding{ID: strings.Repeat("5", 64), Incarnation: strings.Repeat("6", 64), Serial: 7, Provider: 1, Wrap: 2, Protection: 1, Selector: "synthetic-selector", SPKI: []byte("public"), Fingerprint: strings.Repeat("7", 64)},
		Entries:       []publicMaterializationEntry{{Name: "PLAIN", Slot: 0, Incarnation: strings.Repeat("8", 64), Value: strings.Repeat("9", 64), Source: 1, Confidentiality: 1}, {Name: "SECRET", Slot: 1, Incarnation: strings.Repeat("e", 64), Value: strings.Repeat("f", 64), Source: 1, Confidentiality: 2}},
		MixedVerified: true, PlainVerified: true, DeniedVerified: true, SourcePreserved: true, FilesRemoved: true}
}

// full_only: false
func TestPublicMaterializationEvidenceRequiresExactSelectionAndNativeFacts(t *testing.T) {
	facts := publicMaterializationSyntheticFacts()
	// Declaration tags are independent wire literals. Check them explicitly so a
	// contract change cannot silently change this result consumer's expectations.
	if uint8(contract.OrdinaryWrapSubject) != 1 || uint8(contract.Supplied) != 1 || uint8(contract.Plain) != 1 || uint8(contract.Secret) != 2 {
		t.Fatal("synthetic materialization wire tags require explicit review")
	}
	for _, condition := range []string{"exact", "wrong-domain", "wrong-revision", "wrong-snapshot", "wrong-recipient", "wrong-binding", "wrong-entry", "missing-entry", "extra-entry", "incomplete", "not-replaced", "unverified", "not-cleaned", "cleanup-failed", "receipt", "secret-field", "nonzero-exit", "source-identity"} {
		t.Run(condition, func(t *testing.T) {
			child := publicChildResult{Body: []byte(publicMaterializationSuccessJSON)}
			replace := func(from, to string) {
				changed := bytes.Replace(child.Body, []byte(from), []byte(to), 1)
				if bytes.Equal(changed, child.Body) {
					t.Fatal("synthetic result damage did not change fixture")
				}
				child.Body = changed
			}
			switch condition {
			case "wrong-domain":
				replace(`"domain_id":"`+facts.Domain, `"domain_id":"`+strings.Repeat("a", 64))
			case "wrong-revision":
				replace(`"head_revision_id":"`+facts.Revision, `"head_revision_id":"`+strings.Repeat("a", 64))
			case "wrong-snapshot":
				replace(`"snapshot_id":"`+facts.Snapshot, `"snapshot_id":"`+strings.Repeat("a", 64))
			case "wrong-recipient":
				replace(`"recipient_id":"`+facts.Recipient, `"recipient_id":"`+strings.Repeat("a", 64))
			case "wrong-binding":
				replace(`"binding_serial":7`, `"binding_serial":8`)
			case "wrong-entry":
				replace(`"value_state_id":"`+facts.Entries[1].Value, `"value_state_id":"`+strings.Repeat("a", 64))
			case "missing-entry":
				var body map[string]any
				if json.Unmarshal(child.Body, &body) != nil {
					t.Fatal("synthetic result unavailable")
				}
				payload := body["payload"].(map[string]any)
				payload["entries"] = payload["entries"].([]any)[:1]
				var err error
				child.Body, err = json.Marshal(body)
				if err != nil {
					t.Fatal("synthetic result encoding unavailable")
				}
			case "extra-entry":
				var body map[string]any
				if json.Unmarshal(child.Body, &body) != nil {
					t.Fatal("synthetic result unavailable")
				}
				payload := body["payload"].(map[string]any)
				entries := payload["entries"].([]any)
				payload["entries"] = append(entries, entries[0])
				var err error
				child.Body, err = json.Marshal(body)
				if err != nil {
					t.Fatal("synthetic result encoding unavailable")
				}
			case "incomplete":
				replace(`"native_completion":"complete"`, `"native_completion":"incomplete"`)
			case "not-replaced":
				replace(`"replacement":"replaced"`, `"replacement":"not-replaced"`)
			case "unverified":
				replace(`"installed_verification":"verified"`, `"installed_verification":"not-observed"`)
			case "not-cleaned":
				replace(`"candidate_cleanup":"renamed"`, `"candidate_cleanup":"unknown"`)
			case "cleanup-failed":
				replace(`"cleanup_failure":null`, `"cleanup_failure":{"stage":"cleanup","reason":"cleanup-failure"}`)
			case "receipt":
				replace(`"capsule_policy":"none"`, `"receipt_hex":"0102","capsule_policy":"none"`)
			case "secret-field":
				replace(`"native_completion":"complete"`, `"native_completion":"complete","plaintext":"forbidden"`)
			case "nonzero-exit":
				child.Code = 1
			case "source-identity":
				replace(`"request_identity":"cccc`, `"request_identity":"aaaa`)
			}
			if publicMaterializationResultMatches(child, facts, facts.Entries, "/private/application.env", false) != (condition == "exact") {
				t.Fatal("materialization accepted a partial, different or unsafe result")
			}
		})
	}
	t.Run("denied", func(t *testing.T) {
		failure := `{"stage":"authentication","reason":"private-route-unavailable"}`
		body := strings.Replace(publicMaterializationSuccessJSON, `"state_result":"success"`, `"state_result":"unavailable"`, 1)
		body = strings.Replace(body, `"outcome":2,"reason":0`, `"outcome":6,"reason":17`, 1)
		body = strings.ReplaceAll(body, `"failure":null`, `"failure":`+failure)
		for _, pair := range [][2]string{{`"replacement":"replaced"`, `"replacement":"not-replaced"`}, {`"candidate_verification":"verified"`, `"candidate_verification":"not-observed"`}, {`"installed_verification":"verified"`, `"installed_verification":"not-observed"`}, {`"native_completion":"complete"`, `"native_completion":"not-observed"`}, {`"plaintext_disk_disclosure":"occurred"`, `"plaintext_disk_disclosure":"none"`}, {`"candidate_cleanup":"renamed"`, `"candidate_cleanup":"not-created"`}} {
			body = strings.Replace(body, pair[0], pair[1], 1)
		}
		if !publicMaterializationResultMatches(publicChildResult{Code: 3, Body: []byte(body)}, facts, facts.Entries, "/private/application.env", true) {
			t.Fatal("materialization actual private-route denial result refused")
		}
	})
	for _, condition := range []string{"exact", "missing", "incomplete", "other-condition", "mixed-variant", "different-domain", "missing-entry", "duplicate-slot"} {
		t.Run("fresh/"+condition, func(t *testing.T) {
			f := publicMaterializationSyntheticFacts()
			process := publicProcessFacts{Domain: f.Domain, ExpectReady: true, Materialization: &f}
			selected := "materialization"
			switch condition {
			case "missing":
				process.Materialization = nil
			case "incomplete":
				f.FilesRemoved = false
			case "other-condition":
				selected = "inspection-receipts"
			case "mixed-variant":
				process.Inspection = &publicInspectionFacts{}
			case "different-domain":
				process.Domain = strings.Repeat("a", 64)
			case "missing-entry":
				f.Entries = f.Entries[:1]
			case "duplicate-slot":
				f.Entries[1].Slot = f.Entries[0].Slot
			}
			if publicMaterializationFreshFactsValid(selected, process) != (condition == "exact") {
				t.Fatal("fresh materialization facts admitted incomplete or foreign evidence")
			}
		})
	}
}
