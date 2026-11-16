package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

func materializationRenderingResult(t *testing.T) core.MaterializationResult {
	t.Helper()
	_, basis := installedarchive.LoadReader(t, "aws")
	var image struct{ Descriptor []byte }
	if json.Unmarshal(basis, &image) != nil {
		t.Fatal("fixture basis unavailable")
	}
	descriptor, err := contract.DecodeGenesisDescriptorCore(image.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := descriptor.BindingTable()
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.ID{1}
	opID := contract.Hash(append([]byte("ENKV/materialization-operation/v1\x00"), identity[:]...))
	p := &contract.MaterializationPayload{Schema: contract.MaterializationPayloadSchema, RequestIdentity: identity, DomainID: descriptor.DomainID,
		HEADRevision: contract.ID{2}, SnapshotID: contract.ID{3}, Recipient: bindings[0],
		Target:  contract.MaterializationTarget{Path: "/private/application.env", SurfaceID: contract.ID{4}, Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile},
		Entries: []contract.MaterializationEntryIdentity{{Name: "ALPHA", EntryIncarnationID: contract.ID{5}, ValueStateID: contract.ID{6}, ValueSource: 1, ConfidentialityClass: 1}, {Name: "OMEGA", Slot: 1, EntryIncarnationID: contract.ID{7}, ValueStateID: contract.ID{8}, ValueSource: 2, ConfidentialityClass: 2}},
		Facts:   contract.MaterializationFacts{Replacement: contract.MaterializationReplaced, CandidateVerification: contract.MaterializationVerified, InstalledVerification: contract.MaterializationVerified, NativeCompletion: contract.MaterializationComplete, Disclosure: contract.MaterializationDisclosureOccurred, Cleanup: contract.MaterializationCandidateRenamed}}
	r := core.MaterializationResult{Operation: contract.MaterializationOperation, RequestID: contract.ID{9}, OperationID: opID, RequestIdentity: identity, DomainID: descriptor.DomainID, StateResult: contract.MaterializationSuccess, Payload: p,
		Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: p.HEADRevision, ObservedSnapshotID: p.SnapshotID}}
	if err := r.Validate(); err != nil {
		t.Fatal("synthetic safe result refused", err)
	}
	return r
}

func materializationRenderingDocument(t *testing.T, r core.MaterializationResult) map[string]json.RawMessage {
	t.Helper()
	var out bytes.Buffer
	if err := WriteMaterializationJSON(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	var record map[string]json.RawMessage
	if json.Unmarshal(out.Bytes(), &record) != nil {
		t.Fatal("incomplete result record")
	}
	return record
}

func materializationRenderingCleanupResult(t *testing.T) core.MaterializationResult {
	t.Helper()
	r := materializationRenderingResult(t)
	r.StateResult = contract.MaterializationUnavailable
	r.Result.Outcome, r.Result.Reason = core.EvidenceUnavailable, core.CustodyUnavailable
	r.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationStaging, Reason: contract.MaterializationIOFailure}
	r.Payload.Facts = contract.InitialMaterializationFacts()
	r.Payload.Facts.NativeCompletion = contract.MaterializationIncomplete
	r.Payload.Facts.Disclosure = contract.MaterializationDisclosureOccurred
	r.Payload.Facts.Cleanup = contract.MaterializationCandidateCleanupFailed
	r.Payload.Facts.Failure = r.Failure
	r.Payload.Facts.CleanupFailure = &contract.MaterializationFailure{Stage: contract.MaterializationCleanup, Reason: contract.MaterializationCleanupFailure}
	r.Payload.Facts.ResiduePath = "/private/.enkv-materialize-owned-candidate"
	return r
}

// full_only: false
func TestMaterializationRenderingPreservesCompleteSafeFacts(t *testing.T) {
	for _, late := range []bool{false, true} {
		r := materializationRenderingResult(t)
		if late {
			r.StateResult = contract.MaterializationUnavailable
			r.Result.Outcome, r.Result.Reason = core.EvidenceUnavailable, core.CustodyUnavailable
			r.Failure = &contract.MaterializationFailure{Stage: contract.MaterializationInstalledClose, Reason: contract.MaterializationIOFailure}
			r.Payload.Facts.Failure, r.Payload.Facts.NativeCompletion = r.Failure, contract.MaterializationIncomplete
		}
		machine := materializationRenderingDocument(t, r)
		var human bytes.Buffer
		if err := WriteMaterializationHuman(t.Context(), &human, r); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"materialize: " + string(r.StateResult) + "\n", "Replacement: replaced; installed verification=verified; completion=", "Entry: \"ALPHA\"; slot=0.\n", "Entry: \"OMEGA\"; slot=1.\n", "Plaintext disk disclosure: occurred.\n", "Candidate cleanup: renamed.\n"} {
			if !strings.Contains(human.String(), want) {
				t.Error("human result lost selected delivery facts", want, human.String())
			}
		}
		if late && !strings.Contains(human.String(), "Failure: installed-close / io-failure.\n") {
			t.Error("human result lost late failure", human.String())
		}
		if len(machine) != 21 || string(machine["operation_payload"]) != `"MaterializationPayload/v1"` || string(machine["replay_identity"]) != `"none"` {
			t.Fatal("envelope lost closed fields", len(machine))
		}
		for _, name := range []string{"effects", "outputs", "duties", "hazards", "warning_summary"} {
			if string(machine[name]) != "[]" {
				t.Fatal("unexpected vector", name)
			}
		}
		for _, name := range []string{"effect_summary", "output_summary"} {
			if string(machine[name]) != `"not-applicable"` {
				t.Fatal("invalid summary", name)
			}
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal(machine["payload"], &payload) != nil || len(payload) != 9 {
			t.Fatal("payload fields lost", len(payload))
		}
		var entries []map[string]json.RawMessage
		if json.Unmarshal(payload["entries"], &entries) != nil || len(entries) != 2 || len(entries[0]) != 6 || string(entries[0]["name"]) != `"ALPHA"` || string(entries[1]["value_state_id"]) != `"`+readerID(contract.ID{8})+`"` {
			t.Fatal("complete sorted identities lost")
		}
		var facts map[string]json.RawMessage
		if json.Unmarshal(payload["facts"], &facts) != nil || len(facts) != 8 || string(facts["replacement"]) != `"replaced"` || string(facts["installed_verification"]) != `"verified"` {
			t.Fatal("native facts lost")
		}
		var recipient map[string]json.RawMessage
		if json.Unmarshal(payload["recipient"], &recipient) != nil || len(recipient) != 3 {
			t.Fatal("recipient fields lost")
		}
		var binding map[string]json.RawMessage
		current := r.Payload.Recipient.Binding
		wantBinding := map[string]any{
			"binding_id":             hex.EncodeToString(current.BindingID[:]),
			"binding_incarnation_id": hex.EncodeToString(current.BindingIncarnationID[:]),
			"binding_serial":         current.BindingSerial,
			"provider":               current.Provider,
			"wrap_profile":           current.WrapProfile,
			"protection_class":       current.ProtectionClass,
			"key_selector":           current.KeySelector,
			"public_key_spki":        current.SPKI,
			"fingerprint":            hex.EncodeToString(current.Fingerprint[:]),
		}
		if json.Unmarshal(recipient["binding"], &binding) != nil || len(binding) != len(wantBinding) {
			t.Fatal("public binding fields lost")
		}
		for name, value := range wantBinding {
			want, err := json.Marshal(value)
			if err != nil || !bytes.Equal(binding[name], want) {
				t.Fatal("public binding field changed or omitted", name)
			}
		}
		encoded, _ := json.Marshal(machine)
		for _, forbidden := range []string{"receipt", "plaintext_digest", "raw-error", "secret-sentinel"} {
			if bytes.Contains(encoded, []byte(forbidden)) {
				t.Fatal("unsafe result field", forbidden)
			}
		}
	}
	t.Run("cleanup-failure-and-exact-residue", func(t *testing.T) {
		r := materializationRenderingCleanupResult(t)
		machine := materializationRenderingDocument(t, r)
		var payload struct {
			Facts map[string]json.RawMessage `json:"facts"`
		}
		if json.Unmarshal(machine["payload"], &payload) != nil || len(payload.Facts) != 9 ||
			string(payload.Facts["replacement"]) != `"not-replaced"` || string(payload.Facts["candidate_verification"]) != `"not-observed"` ||
			string(payload.Facts["installed_verification"]) != `"not-observed"` || string(payload.Facts["native_completion"]) != `"incomplete"` ||
			string(payload.Facts["plaintext_disk_disclosure"]) != `"occurred"` || string(payload.Facts["candidate_cleanup"]) != `"failed"` ||
			!resultJSONFactsEqual(payload.Facts["failure"], []byte(`{"stage":"staging","reason":"io-failure"}`)) ||
			!resultJSONFactsEqual(payload.Facts["cleanup_failure"], []byte(`{"stage":"cleanup","reason":"cleanup-failure"}`)) ||
			string(payload.Facts["residue_path"]) != `"/private/.enkv-materialize-owned-candidate"` {
			t.Fatal("cleanup failure erased original failure, disclosure or exact private residue")
		}
	})
	t.Run("complete-bounded-metadata", func(t *testing.T) {
		r := materializationRenderingCleanupResult(t)
		r.Payload.Entries = make([]contract.MaterializationEntryIdentity, 512)
		for at := range r.Payload.Entries {
			r.Payload.Entries[at] = contract.MaterializationEntryIdentity{Name: fmt.Sprintf("VALUE%03d", at) + strings.Repeat("N", 248), Slot: uint16(at), EntryIncarnationID: contract.ID{byte(at), byte(at >> 8), 0x41}, ValueStateID: contract.ID{byte(at), byte(at >> 8), 0x42}, ValueSource: 1, ConfidentialityClass: 1}
		}
		r.Payload.Target.Path = "/" + strings.Repeat("x/", 2047) + "x"
		r.Payload.Facts.ResiduePath = "/" + strings.Repeat("y/", 2047) + "y"
		for _, human := range []bool{false, true} {
			var output bytes.Buffer
			var err error
			if human {
				err = WriteMaterializationHuman(t.Context(), &output, r)
			} else {
				err = WriteMaterializationJSON(t.Context(), &output, r)
			}
			if err != nil || uint64(output.Len()) > MaxMaterializationResultJSONBytes {
				t.Fatal("bounded complete result did not fit", err, output.Len())
			}
			body := output.Bytes()
			if human {
				text := output.String()
				if strings.Count(text, "Entry: ") != 512 || !strings.Contains(text, "Entry: \"VALUE000"+strings.Repeat("N", 248)+"\"; slot=0.\n") || !strings.Contains(text, "Entry: \"VALUE511"+strings.Repeat("N", 248)+"\"; slot=511.\n") || !strings.Contains(text, "Materialize file: \"/"+strings.Repeat("x/", 2047)+"x\"") || !strings.Contains(text, "Private residue: \"/"+strings.Repeat("y/", 2047)+"y\".\n") {
					t.Fatal("maximum human metadata lost a selected entry or exact path")
				}
				continue
			}
			var record struct {
				Payload struct {
					Entries []struct {
						Name  string `json:"name"`
						Slot  uint16 `json:"slot"`
						Entry string `json:"entry_incarnation_id"`
						Value string `json:"value_state_id"`
					} `json:"entries"`
					Target struct {
						Path string `json:"path"`
					} `json:"target"`
					Facts struct {
						Residue string `json:"residue_path"`
					} `json:"facts"`
				} `json:"payload"`
			}
			if json.Unmarshal(body, &record) != nil || len(record.Payload.Entries) != 512 || record.Payload.Target.Path != "/"+strings.Repeat("x/", 2047)+"x" || record.Payload.Facts.Residue != "/"+strings.Repeat("y/", 2047)+"y" {
				t.Fatal("maximum metadata lost members or exact bounded paths")
			}
			for at, entry := range record.Payload.Entries {
				if entry.Name != fmt.Sprintf("VALUE%03d", at)+strings.Repeat("N", 248) || entry.Slot != uint16(at) || entry.Entry != fmt.Sprintf("%02x%02x41", byte(at), byte(at>>8))+strings.Repeat("00", 29) || entry.Value != fmt.Sprintf("%02x%02x42", byte(at), byte(at>>8))+strings.Repeat("00", 29) {
					t.Fatal("bounded metadata changed or omitted an identity", at)
				}
			}
		}
	})
}

// full_only: false
func TestMaterializationRenderingRejectsInvalidUnionBeforeOutput(t *testing.T) {
	for _, damage := range []string{"state", "generic-reason", "selection-order", "native-success", "request", "stage", "pre-admission-code", "pre-admission-correlation"} {
		t.Run(damage, func(t *testing.T) {
			r := materializationRenderingResult(t)
			switch damage {
			case "state":
				r.StateResult = "exact-resume"
			case "generic-reason":
				r.Result.Reason = core.ReadUnavailable
			case "selection-order":
				r.Payload.Entries[1].Name = "ALPHA"
			case "native-success":
				r.Payload.Facts.NativeCompletion = contract.MaterializationIncomplete
			case "request":
				r.RequestIdentity[0]++
			case "stage":
				r.Payload.Facts.CleanupFailure = &contract.MaterializationFailure{Stage: "raw-error-sentinel", Reason: contract.MaterializationIOFailure}
			default:
				var err error
				r, err = NewMaterializationRefusal(configuration.JSON)
				if err != nil {
					t.Fatal(err)
				}
				if damage == "pre-admission-code" {
					r.PreAdmission.Code = "raw-error-sentinel"
				} else {
					r.PreAdmission.RequestNonce = contract.ID{1}
				}
			}
			for _, human := range []bool{false, true} {
				var out bytes.Buffer
				var err error
				if human {
					err = WriteMaterializationHuman(t.Context(), &out, r)
				} else {
					err = WriteMaterializationJSON(t.Context(), &out, r)
				}
				if err == nil || out.Len() != 0 {
					t.Fatal("damaged result emitted bytes", out.Len())
				}
			}
		})
	}
	refused, err := NewMaterializationRefusal(configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	record := materializationRenderingDocument(t, refused)
	if string(record["operation_payload"]) != `"none"` || string(record["payload"]) != "null" || MaterializationExitCode(refused) != 2 {
		t.Fatal("local refusal lost correlation")
	}
}

type materializationResultSink struct {
	kind  string
	calls int
}

func (s *materializationResultSink) Write(p []byte) (int, error) {
	s.calls++
	if s.kind == "short" {
		return len(p) - 1, nil
	}
	return 0, errors.New("private-writer-error")
}

// full_only: false
func TestMaterializationRenderingReportsDeliveryFailure(t *testing.T) {
	r := materializationRenderingResult(t)
	for _, human := range []bool{false, true} {
		for _, kind := range []string{"short", "error", "canceled"} {
			ctx, cancel := context.WithCancel(t.Context())
			if kind == "canceled" {
				cancel()
			}
			sink := &materializationResultSink{kind: kind}
			var err error
			if human {
				err = WriteMaterializationHuman(ctx, sink, r)
			} else {
				err = WriteMaterializationJSON(ctx, sink, r)
			}
			cancel()
			if err == nil || r.StateResult != contract.MaterializationSuccess || r.Payload.Facts.Replacement != contract.MaterializationReplaced {
				t.Fatal("presentation changed completed facts")
			}
			if kind == "canceled" && sink.calls != 0 {
				t.Fatal("canceled renderer wrote")
			}
			if kind == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write not retained", err)
			}
		}
	}
	if MaterializationExitCode(r) != 0 {
		t.Fatal("complete operation exit")
	}
	if materializationCompactResultLimit > 2<<20 || MaxMaterializationResultJSONBytes != 67*materializationCompactResultLimit || strings.Contains(ErrMaterializationResult.Error(), "private-writer-error") {
		t.Fatal("unbounded or unsafe rendering")
	}
}
