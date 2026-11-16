package compositionfull

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func suppliedApplyResultFixture(t testing.TB) core.PublicApplyResult {
	t.Helper()
	id := func(n byte) contract.ID { return contract.ID{n} }
	subjects := contract.GeneratorDescriptor{Digest: id(8), Length: 42, Count: 1}
	row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationApplyDeclaration, StateResult: contract.ReceiptStateSuccess,
		EffectSummary: contract.ReceiptEffectNoChange, OutputSummary: contract.ReceiptOutputNotApplicable, EvidenceCeiling: contract.ReceiptEvidenceCanonical,
		DomainID: id(1), OperationID: id(2), RequestIdentityDigest: id(3), PredecessorRevisionID: id(4), RequestedRevisionID: id(5), ObservedRevisionID: id(5),
		CanonicalOutcome: contract.ReceiptCanonicalSelected, ChangedSubjects: subjects, CompleteResult: contract.GeneratorDescriptor{Digest: id(9), Length: 8 + contract.MutationResultProjectionLength, Count: 1}}
	body, err := contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	return core.PublicApplyResult{RequestID: id(6), OperationID: id(2), RequestIdentity: id(3), DomainID: id(1), Receipt: body,
		Result:  core.Result{Outcome: core.ObservedCurrent, RequestedRevision: id(5), ObservedRevision: id(5), Evidence: core.AuthenticatedClosure},
		Payload: &core.TransitionPayload{PredecessorRevisionID: id(4), RequestedRevisionID: id(5), ObservedRevisionID: id(5), ChangedSubjects: core.ChangedSubjectCommitment{Count: 1, IdentityRootDigest: id(8)}}}
}

// full_only: false
func TestApplyResultUsesExactTransitionPayloadAndSeparateDiagnostics(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable,
		SourceLocation: &contract.SourceLocation{SourceID: "source.generated", Line: 2, Column: 16}}}
	body, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Schema  string
		Effect  string `json:"effect_summary"`
		Payload struct {
			Schema      string
			Predecessor string `json:"predecessor_revision_id"`
			Requested   string `json:"requested_revision_id"`
			Observed    string `json:"observed_revision_id"`
			Subjects    struct {
				Count  uint32
				Digest string `json:"identity_root_digest"`
			} `json:"changed_subject_commitment"`
		}
		Diagnostics []map[string]any
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Schema != "ProductResult/v1" || v.Payload.Schema != "TransitionPayload/v1" || v.Effect != "effect-no-change" || v.Payload.Predecessor != readerID(r.Payload.PredecessorRevisionID) || v.Payload.Requested != readerID(r.Payload.RequestedRevisionID) || v.Payload.Observed != readerID(r.Payload.ObservedRevisionID) || v.Payload.Subjects.Count != 1 || v.Payload.Subjects.Digest != readerID(r.Payload.ChangedSubjects.IdentityRootDigest) || len(v.Diagnostics) != 1 {
		t.Fatal("transition result differs", string(body))
	}
	for _, literal := range [][]byte{[]byte(`"live_duty_ids": []`), []byte(`"live_hazard_ids": []`)} {
		if !bytes.Contains(body, literal) {
			t.Fatal("typed result lost exact empty live set or safe location", string(body))
		}
	}
	if bytes.Contains(body, []byte("ApplyPayload")) || bytes.Contains(body, []byte("SourceID")) {
		t.Fatal("untyped payload escaped")
	}
	location, locationErr := json.Marshal(v.Diagnostics[0]["source_location"])
	if locationErr != nil || !resultJSONFactsEqual(location, []byte(`{"source_id":"source.generated","line":2,"column":16}`)) {
		t.Fatal("safe source location changed", locationErr, string(location))
	}
	human, err := RenderApplyHuman(r)
	if err != nil || !bytes.Contains(human, []byte("Apply: success\n")) || !bytes.Contains(human, []byte("Operation ID: "+readerID(r.OperationID)+"\n")) || bytes.Contains(human, []byte("Changed subjects:")) || !bytes.Contains(human, []byte(`source "source.generated" location 2:16`)) {
		t.Fatal("human transition result differs", err)
	}
}

// full_only: false
func TestApplyResultNoopAndRefusalHaveNoPayloadOrReceipt(t *testing.T) {
	for _, outcome := range []core.Outcome{core.Unchanged, core.AdmissionRefused} {
		r := suppliedApplyNoopResultFixture()
		r.Result.Outcome = outcome
		body, err := RenderApplyJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte(`"payload": null`)) || bytes.Contains(body, []byte("TransitionPayload")) || bytes.Contains(body, []byte("receipt_hex")) {
			t.Fatal("nontransition result carried mutation payload", string(body))
		}
		human, err := RenderApplyHuman(r)
		want := "No transition details are available.\n"
		if outcome == core.Unchanged {
			want = "No changes were applied."
		}
		if err != nil || !bytes.Contains(human, []byte(want)) {
			t.Fatal("human nontransition payload differs", err)
		}
	}
}

// full_only: false
func TestTransitionHumanAnswersOperationStateAndBlockers(t *testing.T) {
	r := retirementBlockedResultFixture(t)
	body, err := RenderRecipientRetirementHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Recipient retirement: refused\n", "Operation ID: " + readerID(r.OperationID), "Retirement blockers: 3\n", "Material " + readerID(contract.ID{1}) + "; parent " + readerID(contract.ID{4}), "Material " + readerID(contract.ID{1}) + "; duty " + readerID(contract.ID{5}), "Material " + readerID(contract.ID{2}) + "; hazard " + readerID(contract.ID{6})} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("human transition omitted a decision fact", want, string(body))
		}
	}
	if bytes.Contains(body, []byte("TransitionPayload/v1")) || bytes.Contains(body, []byte("ProductResult/v1")) {
		t.Fatal("human transition exposed an internal envelope")
	}
}

// full_only: false
func TestApplyResultRefusesInconsistentTransitionFacts(t *testing.T) {
	for _, condition := range []string{"no-op payload", "refusal payload", "success missing payload", "success missing receipt", "success missing identity without receipt", "success missing domain without receipt", "receipt erases inherited warnings", "requested mismatch", "observed mismatch", "missing subject digest", "subject ceiling", "unexpected duty", "receipt mismatch"} {
		t.Run(condition, func(t *testing.T) {
			r := suppliedApplyResultFixture(t)
			switch condition {
			case "no-op payload":
				r.Result.Outcome = core.Unchanged
			case "refusal payload":
				r.Result.Outcome = core.AdmissionRefused
			case "success missing payload":
				r.Payload = nil
			case "success missing receipt":
				r.Receipt = nil
			case "success missing identity without receipt":
				r.Receipt = nil
				r.RequestIdentity = contract.ID{}
			case "success missing domain without receipt":
				r.Receipt = nil
				r.DomainID = contract.ID{}
			case "receipt erases inherited warnings":
				r.WarningBits = 1
			case "requested mismatch":
				r.Payload.RequestedRevisionID = contract.ID{99}
			case "observed mismatch":
				r.Payload.ObservedRevisionID = contract.ID{99}
			case "missing subject digest":
				r.Payload.ChangedSubjects.IdentityRootDigest = contract.ID{}
			case "subject ceiling":
				r.Payload.ChangedSubjects.Count = contract.MutationChangedSubjectLimit + 1
			case "unexpected duty":
				r.Payload.LiveDutyIDs = []contract.ID{{99}}
			case "receipt mismatch":
				r.RequestIdentity = contract.ID{99}
			}
			if _, err := RenderApplyJSON(r); err == nil {
				t.Fatal("inconsistent result accepted")
			}
			if _, err := RenderApplyHuman(r); err == nil {
				t.Fatal("inconsistent human result accepted")
			}
		})
	}
	r := suppliedApplyResultFixture(t)
	r.Result.Outcome = core.UnresolvedCommit
	r.Result.CommitMayHaveOccurred = true
	r.Receipt = nil
	r.Result.Evidence = core.NoEvidence
	body, err := RenderApplyJSON(r)
	if err != nil || !bytes.Contains(body, []byte("commit-outcome-unknown")) || bytes.Contains(body, []byte("receipt_hex")) || !bytes.Contains(body, []byte(`"evidence_ceiling": "unavailable"`)) {
		t.Fatal("uncertain selection overstated receipt", err)
	}
}

// full_only: false
func TestApplyResultPreservesMandatoryWarningSummary(t *testing.T) {
	r := suppliedApplyNoopResultFixture()
	r.WarningBits = 31
	body, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Warnings []string `json:"warning_summary"`
	}
	if json.Unmarshal(body, &result) != nil || len(result.Warnings) != 5 {
		t.Fatal("incomplete mandatory warning set", string(body))
	}
	human, err := RenderApplyHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range result.Warnings {
		if !bytes.Contains(human, []byte("Warning: "+warning)) {
			t.Fatal("human result omitted mandatory warning")
		}
	}
	r.WarningBits = 32
	if _, err := RenderApplyJSON(r); err == nil {
		t.Fatal("unknown warning semantics accepted")
	}
}

// full_only: false
func TestApplyNoopObservationIdentityHasNoReplay(t *testing.T) {
	r := suppliedApplyNoopResultFixture()
	body, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		OperationID string           `json:"operation_id"`
		Identity    string           `json:"request_identity"`
		Replay      string           `json:"replay_identity"`
		Payload     *json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.OperationID != readerID(r.OperationID) || result.Identity != readerID(r.RequestIdentity) || result.Replay != "none" || result.Payload != nil || bytes.Contains(body, []byte("receipt_hex")) {
		t.Fatal("no-work observation lost identity or acquired replay", string(body))
	}
	human, err := RenderApplyHuman(r)
	if err != nil || !bytes.Contains(human, []byte("This observation does not authorize replay.\n")) {
		t.Fatal("human no-work observation replay differs", err)
	}
}

func suppliedApplyNoopResultFixture() core.PublicApplyResult {
	return core.PublicApplyResult{RequestID: contract.ID{1}, OperationID: contract.ID{2}, RequestIdentity: contract.ID{3}, DomainID: contract.ID{4},
		Result: core.Result{Outcome: core.Unchanged, Evidence: core.AuthenticatedClosure, ObservedRevision: contract.ID{5}}}
}

func suppliedApplyRetainedWorkResultFixture(t testing.TB, duties, hazards []contract.ID, domainWarnings uint8) core.PublicApplyResult {
	t.Helper()
	r := suppliedApplyResultFixture(t)
	r.Payload.LiveDutyIDs = slices.Clone(duties)
	r.Payload.LiveHazardIDs = slices.Clone(hazards)
	r.WarningBits = domainWarnings
	row, err := contract.InspectCompactMutationReceipt(r.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	row.SummaryCounts[contract.ReceiptDutyCount] = uint32(len(r.Payload.LiveDutyIDs))
	row.SummaryCounts[contract.ReceiptHazardCount] = uint32(len(r.Payload.LiveHazardIDs))
	var operationWarnings uint64
	if len(hazards) != 0 {
		operationWarnings = contract.ReceiptWarningPossibleLive
	}
	row.WarningBits, err = contract.EncodeReceiptWarningBits(contract.OperationApplyDeclaration, domainWarnings, operationWarnings)
	if err != nil {
		t.Fatal(err)
	}
	r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// full_only: false
func TestApplyResultPreservesCanonicalRetainedWorkIDsAndReceiptCounts(t *testing.T) {
	// This is trusted Core result-shape validation. Authentication of the
	// committed support bodies belongs to Core and Crypto before selection.
	for _, outcome := range []core.Outcome{core.ObservedCurrent, core.Contention, core.UnresolvedCommit} {
		t.Run(map[core.Outcome]string{core.ObservedCurrent: "success", core.Contention: "contention", core.UnresolvedCommit: "unknown"}[outcome], func(t *testing.T) {
			r := suppliedApplyRetainedWorkResultFixture(t, []contract.ID{{10}, {11}}, []contract.ID{{12}, {13}}, 0)
			r.Result.Outcome = outcome
			if outcome != core.ObservedCurrent {
				r.Receipt = nil
			}
			if outcome == core.UnresolvedCommit {
				r.Result.CommitMayHaveOccurred = true
				r.Result.Evidence = core.NoEvidence
			}
			body, err := RenderApplyJSON(r)
			if err != nil {
				t.Fatal("valid preserved work result refused", err)
			}
			var result struct {
				State    string   `json:"state_result"`
				Warnings []string `json:"warning_summary"`
				Payload  struct {
					Duties  []string `json:"live_duty_ids"`
					Hazards []string `json:"live_hazard_ids"`
				}
			}
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
			expectedState := map[core.Outcome]string{core.ObservedCurrent: "success", core.Contention: "contention", core.UnresolvedCommit: "commit-outcome-unknown"}[outcome]
			if result.State != expectedState || !slices.Equal(result.Warnings, []string{"An old generated effect may still be live."}) {
				t.Fatal("retained work changed invocation state or lost its mandatory warning")
			}
			wantDuties := []string{readerID(contract.ID{10}), readerID(contract.ID{11})}
			wantHazards := []string{readerID(contract.ID{12}), readerID(contract.ID{13})}
			if !slices.Equal(result.Payload.Duties, wantDuties) || !slices.Equal(result.Payload.Hazards, wantHazards) {
				t.Fatal("public result changed preserved work identity or order")
			}
			human, err := RenderApplyHuman(r)
			if err != nil || !bytes.Contains(human, []byte("Apply: "+expectedState+"\n")) || bytes.Count(human, []byte("Warning: An old generated effect may still be live.\n")) != 1 {
				t.Fatal("human preserved work state or warning differs", err)
			}
			for _, rows := range []struct {
				field string
				ids   []string
			}{{"live_duty_ids", wantDuties}, {"live_hazard_ids", wantHazards}} {
				label := map[string]string{"live_duty_ids": "Current duty", "live_hazard_ids": "Current hazard"}[rows.field]
				for _, id := range rows.ids {
					if !bytes.Contains(human, []byte(label+": "+id+"\n")) {
						t.Fatal("human result lost an exact preserved work identity", label, id)
					}
				}
			}
		})
	}
	for _, condition := range []string{"duty-count", "hazard-count", "duty-duplicate", "hazard-duplicate", "duty-order", "hazard-order", "duty-zero", "hazard-zero", "duty-limit", "hazard-limit"} {
		t.Run(condition, func(t *testing.T) {
			r := suppliedApplyRetainedWorkResultFixture(t, []contract.ID{{10}, {11}}, []contract.ID{{12}, {13}}, 0)
			switch condition {
			case "duty-count":
				r.Payload.LiveDutyIDs = r.Payload.LiveDutyIDs[:1]
			case "hazard-count":
				r.Payload.LiveHazardIDs = r.Payload.LiveHazardIDs[:1]
			case "duty-duplicate":
				r.Payload.LiveDutyIDs[1] = r.Payload.LiveDutyIDs[0]
			case "hazard-duplicate":
				r.Payload.LiveHazardIDs[1] = r.Payload.LiveHazardIDs[0]
			case "duty-order":
				slices.Reverse(r.Payload.LiveDutyIDs)
			case "hazard-order":
				slices.Reverse(r.Payload.LiveHazardIDs)
			case "duty-zero":
				r.Payload.LiveDutyIDs[0] = contract.ID{}
			case "hazard-zero":
				r.Payload.LiveHazardIDs[0] = contract.ID{}
			case "duty-limit":
				r.Payload.LiveDutyIDs = make([]contract.ID, 65536)
			case "hazard-limit":
				r.Payload.LiveHazardIDs = make([]contract.ID, 65536)
			}
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
				if _, err := render(r); err == nil {
					t.Fatal("inconsistent retained work result accepted")
				}
			}
		})
	}
}

// full_only: false
func TestApplyResultRetainedWarningsSeparateOperationAndDomainFacts(t *testing.T) {
	const possibleLive = "An old generated effect may still be live."
	for _, work := range []struct {
		name            string
		duties, hazards []contract.ID
	}{{"none", nil, nil}, {"duties", []contract.ID{{10}, {11}}, nil}, {"hazards", nil, []contract.ID{{12}, {13}}}, {"both", []contract.ID{{10}, {11}}, []contract.ID{{12}, {13}}}} {
		for _, domainWarnings := range []uint8{0, 31} {
			t.Run(fmt.Sprintf("%s/domain-%d", work.name, domainWarnings), func(t *testing.T) {
				r := suppliedApplyRetainedWorkResultFixture(t, work.duties, work.hazards, domainWarnings)
				body, err := RenderApplyJSON(r)
				if err != nil {
					t.Fatal("valid inherited work receipt refused", err)
				}
				var wire struct {
					State    string   `json:"state_result"`
					Warnings []string `json:"warning_summary"`
					Payload  struct {
						Duties  []string `json:"live_duty_ids"`
						Hazards []string `json:"live_hazard_ids"`
					}
				}
				if err := json.Unmarshal(body, &wire); err != nil || wire.State != "success" || len(wire.Payload.Duties) != len(work.duties) || len(wire.Payload.Hazards) != len(work.hazards) {
					t.Fatal("inherited work changed canonical success or live vectors", err)
				}
				warningCount := 0
				for _, warning := range wire.Warnings {
					if warning == possibleLive {
						warningCount++
					}
				}
				expectedWarnings, expectedPossibleLive := 0, 0
				if domainWarnings != 0 {
					expectedWarnings, expectedPossibleLive = 5, 1
				} else if len(work.hazards) != 0 {
					expectedWarnings, expectedPossibleLive = 1, 1
				}
				if len(wire.Warnings) != expectedWarnings || warningCount != expectedPossibleLive {
					t.Fatal("inherited domain and operation warnings were lost or conflated")
				}
				human, err := RenderApplyHuman(r)
				if err != nil || !bytes.Contains(human, []byte("Apply: success\n")) || bytes.Contains(human, []byte("retirement-pending")) || bytes.Count(human, []byte("Warning: "+possibleLive+"\n")) != expectedPossibleLive {
					t.Fatal("human result changed canonical state or possible-live warning", err)
				}
				for _, warning := range wire.Warnings {
					if !bytes.Contains(human, []byte("Warning: "+warning+"\n")) {
						t.Fatal("human result omitted an inherited warning")
					}
				}
			})
		}
	}
	for _, condition := range []string{"missing-possible-live", "extra-possible-live", "domain-warning-mismatch", "forged-retirement-pending"} {
		t.Run(condition, func(t *testing.T) {
			hazards := []contract.ID{{12}, {13}}
			if condition == "extra-possible-live" {
				hazards = nil
			}
			r := suppliedApplyRetainedWorkResultFixture(t, []contract.ID{{10}, {11}}, hazards, 31)
			row, err := contract.InspectCompactMutationReceipt(r.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			warnings := contract.ReceiptWarningPossibleLive
			domain := r.WarningBits
			switch condition {
			case "missing-possible-live":
				warnings = 0
			case "domain-warning-mismatch":
				domain = 0
			case "forged-retirement-pending":
				row.StateResult = contract.ReceiptStateRetirementPending
			}
			row.WarningBits, err = contract.EncodeReceiptWarningBits(contract.OperationApplyDeclaration, domain, warnings)
			if err != nil {
				t.Fatal(err)
			}
			r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
			if err != nil {
				t.Fatal("mismatch did not retain a valid compact receipt shape", err)
			}
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
				if _, err := render(r); err == nil {
					t.Fatal("inconsistent operation receipt accepted")
				}
			}
		})
	}
}
