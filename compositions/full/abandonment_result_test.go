package compositionfull

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type administrativeCountingSink struct {
	bytes        uint64
	largest, ids int
	quoted       bool
	escaped      bool
	hexadecimal  bool
	length       int
	token        [64]byte
	idCounts     map[string]int
}

func (w *administrativeCountingSink) Write(b []byte) (int, error) {
	w.bytes += uint64(len(b))
	w.largest = max(w.largest, len(b))
	for _, c := range b {
		if !w.quoted {
			if c == '"' {
				w.quoted, w.hexadecimal, w.length = true, true, 0
			}
			continue
		}
		if !w.escaped && c == '"' {
			if w.hexadecimal && w.length == len(w.token) {
				w.ids++
				if w.idCounts == nil {
					w.idCounts = make(map[string]int)
				}
				w.idCounts[string(w.token[:])]++
			}
			w.quoted = false
			continue
		}
		if w.length < len(w.token) {
			w.token[w.length] = c
		}
		w.length = min(w.length+1, len(w.token)+1)
		w.hexadecimal = w.hexadecimal && (c >= '0' && c <= '9' || c >= 'a' && c <= 'f')
		if w.escaped {
			w.escaped = false
		} else {
			w.escaped = c == '\\'
		}
	}
	return len(b), nil
}
func administrativeListResult(groups int) AbandonmentResult {
	id := func(n uint32) (out contract.ID) { out[0] = 1; binary.BigEndian.PutUint32(out[28:], n); return out }
	pins := core.AdministrativeSourcePins{FileID: id(1), Format: 1, EditableDigest: id(2), GeneratedDigest: id(3), EditableLength: 1, GeneratedLength: 1, HasGenerated: true}
	q := &core.AdministrativeQueryIdentity{Schema: "QueryRequestIdentity/v1", Operation: core.AdministrativeList, SemanticOperation: 15, ExpectedDomain: id(4), StoreID: id(5), CoordinateID: id(6), NonBodyID: id(7), StoreDescriptorDigest: id(8), PublicBasisDigest: id(9), SourcePins: pins, Observation: &core.AdministrativeObservation{DomainID: id(4), Revision: id(10), Snapshot: id(11)}, RequestNonce: id(12), Digest: id(13)}
	view := &core.AuthorityInspection{Revision: id(10), Snapshot: id(11), Groups: make([]core.AuthorityGroup, groups)}
	for i := range view.Groups {
		g := core.AuthorityGroup{GroupID: id(uint32(i + 100)), OwnerID: id(20), TargetID: id(21), OwnerKind: contract.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing}
		g.RelatedGroupIndexes = make([]uint16, i)
		for j := range g.RelatedGroupIndexes {
			g.RelatedGroupIndexes[j] = uint16(j)
		}
		view.Groups[i] = g
	}
	return AbandonmentResult{Operation: core.PublicAdministrativeResult{Operation: core.AdministrativeList, RequestID: q.RequestNonce, OperationID: id(14), RequestIdentity: q.Digest, DomainID: q.ExpectedDomain, Query: q, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure}, StateResult: "success", List: view}}
}

// full_only: false
func TestAdministrativeListStreamsCompleteRelationshipsBeyondEightMiB(t *testing.T) {
	r := administrativeListResult(512)
	edges := 512 * 511 / 2
	for _, human := range []bool{false, true} {
		var out administrativeCountingSink
		var err error
		if human {
			err = WriteAdministrativeHuman(t.Context(), &out, r)
		} else {
			err = WriteAdministrativeJSON(t.Context(), &out, r)
		}
		want := make(map[string]int)
		for at := 0; at < 512; at++ {
			count := 511 - at
			if !human {
				count++
			}
			if count != 0 {
				want[administrativeGCResultHex(uint32(100+at))] = count
			}
		}
		if !human {
			for n, count := range map[uint32]int{1: 1, 2: 1, 3: 1, 4: 3, 5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 2, 11: 2, 12: 2, 13: 1, 14: 1, 20: 512, 21: 512} {
				want[administrativeGCResultHex(n)] = count
			}
		}
		if err != nil || out.bytes <= 8<<20 || out.largest > 8192 || !reflect.DeepEqual(out.idCounts, want) {
			t.Fatal("stream lost complete edges or materialized full result", human, out.bytes, out.largest, out.ids, edges, err)
		}
	}
}

// full_only: false
func TestAdministrativeListPreflightRejectsDamagedOwnedFactsBeforeOutput(t *testing.T) {
	for _, damage := range []string{"range", "self", "order", "tuple", "snapshot", "receipt-kind"} {
		t.Run(damage, func(t *testing.T) {
			r := administrativeListResult(3)
			switch damage {
			case "range":
				r.Operation.List.Groups[2].RelatedGroupIndexes[1] = 3
			case "self":
				r.Operation.List.Groups[2].RelatedGroupIndexes[1] = 2
			case "order":
				r.Operation.List.Groups[2].RelatedGroupIndexes = []uint16{1, 0}
			case "tuple":
				r.Operation.StateResult = "work-ended"
			case "snapshot":
				r.Operation.List.Snapshot = contract.ID{}
			case "receipt-kind":
				r.Operation.Query.RequiredStoredKind = contract.OperationEndSelectedWork
			}
			for _, write := range []func(context.Context, io.Writer, AbandonmentResult) error{WriteAdministrativeJSON, WriteAdministrativeHuman} {
				var out bytes.Buffer
				if err := write(t.Context(), &out, r); err == nil || out.Len() != 0 {
					t.Fatal("damaged result escaped preflight", damage, err, out.Len())
				}
			}
		})
	}
}

func administrativeEndedResult(t *testing.T) AbandonmentResult {
	t.Helper()
	fixture := installedarchive.LoadAdministrative(t, "aws")
	receipt, err := contract.InspectCompactMutationReceipt(fixture.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	object, ok := fixture.After.Archive.Object(fixture.After.Archive.Location.PrefixBeforeHEAD + "/HEAD")
	if !ok {
		t.Fatal("fixture HEAD")
	}
	head, err := format.DecodeHead(object.Body)
	if err != nil || head.EndWork == nil {
		t.Fatal("fixture ending", err)
	}
	q := head.EndWork
	preview := core.EndWorkPreview{Identity: fixture.PreviewIdentity, PredecessorRevision: q.PredecessorRevisionID, TargetGroupID: q.TargetGroupID, EndedGroupIDs: []contract.ID{q.TargetGroupID}, TargetOwnerID: q.TargetOwnerID, TargetID: q.TargetID, TargetKind: q.TargetKind, DutyKind: q.DutyKind, SelectedEvidenceSummary: q.SelectedEvidenceSummary, DependentGroups: q.DependentGroups, RemovedSupport: q.RemovedSupport, PreservedCurrent: q.PreservedCurrent, BeforeWarningBits: q.BeforeWarningBits, WarningBits: q.AfterWarningBits, BeforeChildCount: q.BeforeChildCount, AfterChildCount: q.AfterChildCount, BeforeChildBytes: q.BeforeChildBytes, AfterChildBytes: q.AfterChildBytes}
	return AbandonmentResult{Operation: core.PublicAdministrativeResult{Operation: core.AdministrativeApply, RequestID: contract.Hash([]byte("render request")), OperationID: receipt.OperationID, RequestIdentity: receipt.RequestIdentityDigest, DomainID: receipt.DomainID, Result: core.Result{Outcome: core.ObservedCurrent, ObservedRevision: receipt.ObservedRevisionID, RequestedRevision: receipt.RequestedRevisionID, Evidence: core.AuthenticatedClosure}, StateResult: "work-ended", CurrentWarningBits: uint8(receipt.WarningBits), End: &core.AdministrativeEndPayload{Preview: preview, Receipt: receipt, ReceiptBytes: bytes.Clone(fixture.Receipt)}}}
}

// full_only: false
func TestAdministrativeKnownEndingSurvivesLocalCleanupAndDeliveryFailure(t *testing.T) {
	r := administrativeEndedResult(t)
	r.Delivery.CleanupFailed = true
	var out bytes.Buffer
	if err := WriteAdministrativeJSON(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	var result struct {
		State    string              `json:"state_result"`
		Identity string              `json:"request_identity"`
		Replay   string              `json:"replay_identity"`
		Delivery AbandonmentDelivery `json:"delivery"`
		Payload  json.RawMessage     `json:"payload"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || result.State != "work-ended" || result.Identity != readerID(r.Operation.RequestIdentity) || result.Replay != result.Identity || !result.Delivery.CleanupFailed || string(result.Payload) == "null" || AbandonmentExitCode(r) != 2 {
		t.Fatal("cleanup failure erased known selected mutation or claimed successful local completion")
	}
	failure := errors.New("controlled result delivery failure")
	if err := WriteAdministrativeJSON(t.Context(), administrativeFailingSink{failure}, r); !errors.Is(err, failure) {
		t.Fatal("delivery error cause lost", err)
	}
	if r.Operation.StateResult != "work-ended" || r.Operation.End == nil {
		t.Fatal("output failure rewrote known mutation")
	}
}

type administrativeFailingSink struct{ err error }

func (w administrativeFailingSink) Write([]byte) (int, error) { return 0, w.err }

// full_only: false
func TestAdministrativeReceiptKeepsHistoricalWarningsSeparateFromCurrentWarnings(t *testing.T) {
	r := administrativeEndedResult(t)
	receipt := r.Operation.End.Receipt
	raw := bytes.Clone(r.Operation.End.ReceiptBytes)
	list := administrativeListResult(0)
	list.Operation.Operation = core.AdministrativeReceipt
	list.Operation.Query.Operation = core.AdministrativeReceipt
	list.Operation.Query.SemanticOperation = 16
	list.Operation.Query.RequestedOperationID = receipt.OperationID
	list.Operation.Query.RequiredStoredKind = contract.OperationEndSelectedWork
	list.Operation.DomainID = receipt.DomainID
	list.Operation.Query.ExpectedDomain = receipt.DomainID
	list.Operation.Query.Observation.DomainID = receipt.DomainID
	list.Operation.CurrentWarningBits = 31
	list.Operation.List = nil
	list.Operation.Receipt = &core.AuthorityAbandonment{Receipt: receipt, ReceiptBytes: raw}
	var out bytes.Buffer
	if err := WriteAdministrativeJSON(t.Context(), &out, list); err != nil {
		t.Fatal(err)
	}
	var rendered struct {
		Current []string `json:"warning_summary"`
		State   string   `json:"state_result"`
		Replay  string   `json:"replay_identity"`
		Payload struct {
			State      string   `json:"stored_state_result"`
			Historical []string `json:"historical_warning_summary"`
			Evidence   []string `json:"original_evidence_facts"`
		} `json:"payload"`
	}
	if json.Unmarshal(out.Bytes(), &rendered) != nil || len(rendered.Current) != 5 || len(rendered.Payload.Historical) == 0 {
		t.Fatal("current and historical warning summaries lost")
	}
	if rendered.Payload.State != "work-ended" || rendered.State != "success" || rendered.Replay != "none" || !bytes.Equal(raw, list.Operation.Receipt.ReceiptBytes) {
		t.Fatal("receipt lookup changed stored meaning or borrowed replay rights")
	}
	list.Operation.Receipt.Receipt.WarningBits ^= 1
	out.Reset()
	if err := WriteAdministrativeJSON(t.Context(), &out, list); err == nil || out.Len() != 0 {
		t.Fatal("raw/decoded receipt mismatch escaped preflight")
	}
}

// full_only: false
func TestAdministrativeStreamingPropagatesCancellationAndShortWrite(t *testing.T) {
	r := administrativeListResult(2)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out bytes.Buffer
	if err := WriteAdministrativeJSON(ctx, &out, r); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("cancellation was silenced", err)
	}
	if err := WriteAdministrativeJSON(t.Context(), shortAdministrativeSink{}, r); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write was silenced", err)
	}
}

type shortAdministrativeSink struct{}

func (shortAdministrativeSink) Write(b []byte) (int, error) { return len(b) - 1, nil }

// full_only: false
func TestAdministrativeAcknowledgementDoesNotClaimConfirmation(t *testing.T) {
	facts := abandonEvidence(contract.AdministrativeEvidenceAcknowledged)
	warnings := abandonRowWarnings(0, contract.AdministrativeEvidenceAcknowledged)
	if len(facts) != 1 || facts[0] != "qualified-acknowledgement" || len(warnings) != 1 || warnings[0] != "An effect was acknowledged; invalidation is not confirmed for every original effect." {
		t.Fatal("acknowledgement promoted beyond its evidence ceiling", facts, warnings)
	}
	for _, warning := range abandonRowWarnings(0, contract.AdministrativeEvidencePossibleLive) {
		if strings.Contains(warning, "cleanup path") && !strings.Contains(warning, "No qualified cleanup path") {
			t.Fatal("unqualified cleanup advice", warning)
		}
	}
}

// full_only: false
func TestAdministrativeReadTuplesCannotBorrowMutationUncertainty(t *testing.T) {
	for _, operation := range []core.AdministrativeOperation{core.AdministrativeList, core.AdministrativePlan, core.AdministrativeReceipt} {
		for _, damage := range []string{"possible-write", "unknown", "contention", "snapshot-size"} {
			r := administrativeListResult(0)
			r.Operation.Operation = operation
			r.Operation.Query.Operation = operation
			switch operation {
			case core.AdministrativePlan:
				r.Operation.Query.TargetGroupID = contract.Hash([]byte("requested target"))
				r.Operation.Query.ArtifactPath = "/fixed/plan.json"
			case core.AdministrativeReceipt:
				r.Operation.Query.SemanticOperation = 16
				r.Operation.Query.RequestedOperationID = contract.Hash([]byte("requested operation"))
				r.Operation.Query.RequiredStoredKind = contract.OperationEndSelectedWork
			}
			if !administrativeQueryShape(r.Operation.Query) {
				t.Fatal("malformed query regression fixture", operation)
			}
			r.Operation.List = nil
			r.Operation.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable, CommitMayHaveOccurred: true}
			r.Operation.StateResult = "unavailable"
			switch damage {
			case "unknown":
				r.Operation.Result.Outcome = core.UnresolvedCommit
				r.Operation.StateResult = "commit-outcome-unknown"
			case "contention":
				r.Operation.Result = core.Result{Outcome: core.Contention}
				r.Operation.StateResult = "contention"
			case "snapshot-size":
				r.Operation.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.CapacityExceeded}
				r.Operation.StateResult = "snapshot-size-refusal"
			}
			var out bytes.Buffer
			if err := WriteAdministrativeJSON(t.Context(), &out, r); err == nil || out.Len() != 0 {
				t.Fatal("GET-only query emitted mutation uncertainty", operation, damage, err)
			}
		}
	}
}

// full_only: false
func TestAdministrativeGenericEvidenceRenderingKeepsItsActualMeaning(t *testing.T) {
	for _, tc := range []struct {
		name            string
		owner, duty     uint8
		evidence        uint16
		facts, warnings []string
	}{
		{"complete-create", contract.AdministrativeGeneratedDuty, contract.GeneratedDutyCreate, contract.AdministrativeEvidenceAcknowledged, []string{"qualified-acknowledgement"}, []string{"An effect was acknowledged; invalidation is not confirmed for every original effect."}},
		{"publication-ack", contract.AdministrativePublicationMarker, 0, contract.AdministrativeEvidenceAcknowledged, []string{"qualified-acknowledgement"}, []string{"An effect was acknowledged; invalidation is not confirmed for every original effect."}},
		{"create-no-effect", contract.AdministrativeGeneratedDuty, contract.GeneratedDutyCreate, contract.AdministrativeEvidenceConfirmed, []string{"qualified-no-effect-or-scoped-unusability"}, []string{}},
		{"retirement-ack", contract.AdministrativeGeneratedDuty, contract.GeneratedDutyRetirement, contract.AdministrativeEvidenceAcknowledged, []string{"qualified-acknowledgement"}, []string{"An effect was acknowledged; invalidation is not confirmed for every original effect."}},
		{"scoped-unusability", contract.AdministrativeGeneratedHazard, 0, contract.AdministrativeEvidenceConfirmed, []string{"qualified-no-effect-or-scoped-unusability"}, []string{}},
		{"mixed-history", contract.AdministrativeGeneratedDuty, contract.GeneratedDutyRetirement, contract.AdministrativeEvidenceQualifiedUnknown | contract.AdministrativeEvidenceAcknowledged | contract.AdministrativeEvidenceContradiction | contract.AdministrativeEvidencePossibleLive,
			[]string{"qualified-unknown", "qualified-acknowledgement", "contradiction", "possible-live"}, []string{"The old effect can still be live; a successful frontier does not close it. No qualified cleanup path is established by this administrative view.", "An effect was acknowledged; invalidation is not confirmed for every original effect."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			list := administrativeListResult(1)
			list.Operation.List.Groups[0].OwnerKind, list.Operation.List.Groups[0].DutyKind = tc.owner, tc.duty
			list.Operation.List.Groups[0].SelectedEvidenceSummary = tc.evidence
			plan, store, pins, basis := abandonPlanVector()
			plan.Plan.Preview.SelectedEvidenceSummary, plan.Plan.Preview.BeforeWarningBits, plan.Plan.Preview.WarningBits = tc.evidence, 0, 0
			body, err := encodeAbandonPlan(plan, store, pins, basis)
			if err != nil {
				t.Fatal("qualified plan fixture refused", err)
			}
			var artifact struct {
				Risk struct {
					Facts      []string `json:"original_evidence"`
					Warnings   []string `json:"warnings"`
					Completion string   `json:"original_completion"`
					Cleanup    string   `json:"physical_cleanup"`
				} `json:"risk"`
			}
			if json.Unmarshal(body, &artifact) != nil || !reflect.DeepEqual(artifact.Risk.Facts, tc.facts) || !reflect.DeepEqual(artifact.Risk.Warnings, tc.warnings) || artifact.Risk.Completion != "not-established" || artifact.Risk.Cleanup != "not-established" {
				t.Error("plan artifact changed generic evidence meaning", string(body))
			}
			ended := administrativeEndedResult(t)
			receipt := ended.Operation.End.Receipt
			receipt.AdministrativeOriginalEvidence, receipt.WarningBits, receipt.AdministrativeWarningChanges = tc.evidence, 0, 0
			raw, err := contract.EncodeCompactMutationReceipt(receipt)
			if err != nil {
				t.Fatal("qualified receipt fixture refused", err)
			}
			lookup := administrativeListResult(0)
			lookup.Operation.Operation, lookup.Operation.Query.Operation = core.AdministrativeReceipt, core.AdministrativeReceipt
			lookup.Operation.Query.SemanticOperation, lookup.Operation.Query.RequestedOperationID, lookup.Operation.Query.RequiredStoredKind = 16, receipt.OperationID, contract.OperationEndSelectedWork
			lookup.Operation.DomainID, lookup.Operation.Query.ExpectedDomain, lookup.Operation.Query.Observation.DomainID = receipt.DomainID, receipt.DomainID, receipt.DomainID
			lookup.Operation.List = nil
			lookup.Operation.Receipt = &core.AuthorityAbandonment{Receipt: receipt, ReceiptBytes: raw}
			for _, human := range []bool{false, true} {
				for _, input := range []AbandonmentResult{list, lookup} {
					var out bytes.Buffer
					var err error
					if human {
						err = WriteAdministrativeHuman(t.Context(), &out, input)
					} else {
						err = WriteAdministrativeJSON(t.Context(), &out, input)
					}
					if err != nil {
						t.Fatal("qualified administrative view refused", err)
					}
					encoded := out.Bytes()
					if human {
						prefix := []byte(string(input.Operation.Operation) + ": success\n")
						if !bytes.HasPrefix(encoded, prefix) || !strings.Contains(out.String(), "Evidence: "+strings.Join(tc.facts, ", ")+".\n") {
							t.Fatal("human result prefix", out.String())
						}
						for _, warning := range tc.warnings {
							if !strings.Contains(out.String(), warning+"\n") {
								t.Error("human result lost evidence warning", warning)
							}
						}
						if strings.Contains(out.String(), `"schema"`) || !bytes.Equal(raw, lookup.Operation.Receipt.ReceiptBytes) {
							t.Fatal("human result dumped or changed historical receipt")
						}
						continue
					}
					var rendered struct {
						Payload struct {
							Targets []struct {
								Facts    []string `json:"original_evidence_facts"`
								Warnings []string `json:"warnings"`
							} `json:"targets"`
							Facts    []string `json:"original_evidence_facts"`
							Warnings []string `json:"historical_warning_summary"`
						} `json:"payload"`
					}
					if json.Unmarshal(encoded, &rendered) != nil {
						t.Fatal("result encoding", out.String())
					}
					facts, warnings := rendered.Payload.Facts, rendered.Payload.Warnings
					if input.Operation.Operation == core.AdministrativeList {
						if len(rendered.Payload.Targets) != 1 {
							t.Fatal("list target omitted")
						}
						facts, warnings = rendered.Payload.Targets[0].Facts, rendered.Payload.Targets[0].Warnings
					}
					if !reflect.DeepEqual(facts, tc.facts) || !reflect.DeepEqual(warnings, tc.warnings) {
						t.Error("generic evidence acquired an action claim", human, facts, warnings)
					}
					if !bytes.Equal(raw, lookup.Operation.Receipt.ReceiptBytes) {
						t.Fatal("rendering changed historical receipt")
					}
				}
			}
		})
	}
}
