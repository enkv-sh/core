package compositionfull

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/crypto/testsupport/installedarchive"
	"io"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func replacementResultFixture(t *testing.T, target configuration.ReplacementTarget) ReplacementCommandResult {
	t.Helper()
	a := suppliedApplyResultFixture(t)
	r := core.PublicReplacementResult{RequestID: a.RequestID, OperationID: a.OperationID, RequestIdentity: a.RequestIdentity, DomainID: a.DomainID, Result: a.Result, Payload: a.Payload}
	r.Result.ObservedSnapshotID = contract.ID{20}
	r.Payload.LiveDutyIDs = []contract.ID{{21}, {22}}
	r.Payload.LiveHazardIDs = []contract.ID{{23}}
	if target != configuration.ReplaceAuthority {
		row, err := contract.InspectCompactMutationReceipt(a.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		row.OperationKind = contract.OperationReplaceRecoveryKeysAndRoot
		row.EffectSummary = contract.ReceiptEffectNotApplicable
		if target == configuration.ReplaceRecipient {
			row.EffectSummary = contract.ReceiptEffectNoChange
			row.OperationKind = contract.OperationRotateRecipientKeyBinding
		}
		r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal(err)
		}
	}
	out := replacementCommandFresh(target, r)
	out.Delivery = ReplacementCommandDelivery{Path: "/successor.json", Status: "delivered"}
	return out
}

// full_only: false
func TestReplacementHumanRetainsDiagnosticSubjectAndQueryTarget(t *testing.T) {
	t.Run("diagnostic", func(t *testing.T) {
		r := replacementResultFixture(t, configuration.ReplaceAuthority)
		r.Authority.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "ROW"}, Path: []contract.DiagnosticField{contract.FieldGenerated, contract.FieldCompletion}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable}}
		var body bytes.Buffer
		if err := WriteReplacementHuman(t.Context(), &body, r); err != nil {
			t.Fatal("valid diagnostic control refused", err)
		}
		if !bytes.Contains(body.Bytes(), []byte(`Issue entry "ROW"; field generated.completion: unable to verify; evidence-unavailable`)) {
			t.Fatal("replacement human lost the diagnostic subject/path", body.String())
		}
	})
	t.Run("query-target", func(t *testing.T) {
		for _, test := range []struct {
			target core.ReplacementTarget
			name   string
		}{{core.ReplacementTargetAuthority, "authority"}, {core.ReplacementTargetRecovery, "recovery"}, {core.ReplacementTargetRecipient, "recipient"}} {
			t.Run(test.name, func(t *testing.T) {
				// The recovery and recipient literals include the authenticated
				// observation, as do their existing receipt-query controls.
				q := replacementRenderedQuery(t, test.target, test.target != core.ReplacementTargetAuthority)
				if !q.Valid() {
					t.Fatal("independent query control is invalid")
				}
				read := replacementRenderedRead(q)
				read.Result, read.StateResult = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}, contract.ReaderUnavailable
				r := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
				var body bytes.Buffer
				if err := WriteReplacementHuman(t.Context(), &body, r); err != nil {
					t.Fatal("valid unavailable observation control refused", err)
				}
				for _, want := range []string{"Requested replacement target: " + test.name, "Requested original operation: " + readerID(q.OriginalOperationID)} {
					if !bytes.Contains(body.Bytes(), []byte(want)) {
						t.Fatal("replacement observation lost its request scope", want, body.String())
					}
				}
			})
		}
	})
}

func replacementFresh(r *ReplacementCommandResult) *core.PublicReplacementResult {
	if r.Authority != nil {
		return r.Authority
	}
	if r.Recovery != nil {
		return r.Recovery
	}
	return r.Recipient
}

// full_only: false
func TestReplacementResultsPreserveThreeChangedFormsAndDelivery(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceAuthority, configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		t.Run(string(target), func(t *testing.T) {
			r := replacementResultFixture(t, target)
			fresh := replacementFresh(&r)
			var structured, human bytes.Buffer
			if err := WriteReplacementJSON(context.Background(), &structured, r); err != nil {
				t.Fatal(err)
			}
			if err := WriteReplacementHuman(context.Background(), &human, r); err != nil {
				t.Fatal(err)
			}
			projected, err := replacementProjection(r)
			if err != nil {
				t.Fatal(err)
			}
			var wire replacementResultRecord
			if err := json.Unmarshal(structured.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(human.String(), "Key replacement: success\n") || !strings.Contains(human.String(), "Operation ID: "+readerID(fresh.OperationID)+"\n") || !strings.Contains(human.String(), "Successor files: "+r.Delivery.Status+"\n") || wire.Operation != "keys-replace-"+string(target) || wire.OperationPayload != "TransitionPayload/v1" || wire.State != "success" || wire.Replay != readerID(fresh.RequestIdentity) || len(projected.Transition.Duties) != 2 || len(projected.Transition.Hazards) != 1 || ReplacementCommandExitCode(r) != 0 {
				t.Fatal("changed form lost its payload or human operation facts", structured.String(), human.String())
			}
			if (wire.StoredReceipt != nil) != (target != configuration.ReplaceAuthority) {
				t.Fatal("receipt policy changed")
			}
			if wire.StoredReceipt != nil && wire.StoredReceipt.Bytes == "" {
				t.Fatal("raw original receipt absent")
			}
			r.Delivery.CleanupFailed = true
			r.Delivery.Failed = true
			structured.Reset()
			if err := WriteReplacementJSON(context.Background(), &structured, r); err != nil || !bytes.Contains(structured.Bytes(), []byte(`"state_result": "success"`)) || ReplacementCommandExitCode(r) != 2 {
				t.Fatal("cleanup failure erased known selected mutation", err, structured.String())
			}
		})
	}
}

// full_only: false
func TestReplacementAuthorityNoWorkHasObservationIdentityAndNoReplay(t *testing.T) {
	id := func(n byte) contract.ID { return contract.ID{n} }
	fresh := core.PublicReplacementResult{RequestID: id(1), OperationID: id(2), RequestIdentity: id(3), DomainID: id(4), Result: core.Result{Outcome: core.Unchanged, ObservedRevision: id(5), ObservedSnapshotID: id(6), Evidence: core.AuthenticatedClosure}, NoWorkObservation: &core.AuthorityReplacementNoWorkObservation{OperationID: id(2), RequestIdentity: id(3), RequestCoreDigest: id(7)}}
	r := ReplacementCommandResult{Authority: &fresh, Delivery: ReplacementCommandDelivery{Path: "/successor.json", Status: "not-created"}}
	var out bytes.Buffer
	if err := WriteReplacementJSON(context.Background(), &out, r); err != nil || ReplacementCommandExitCode(r) != 0 {
		t.Fatal("no-work observation refused", err, out.String())
	}
	var v replacementResultRecord
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.OperationPayload != "none" || v.State != "no-op" || v.Replay != "none" || v.NoWork == nil || v.NoWork.Schema != "NoWorkObservationIdentity/v1" || v.Receipt != nil || v.Transition != nil || string(v.RequestIdentity) == `"none"` {
		t.Fatal("no-op invented mutation or lost identity", out.String())
	}
	for _, change := range []func(*ReplacementCommandResult, *core.PublicReplacementResult){func(r *ReplacementCommandResult, f *core.PublicReplacementResult) { f.NoWorkObservation = nil }, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) { f.RequestIdentity = contract.ID{} }, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) {
		f.NoWorkObservation.OperationID = id(8)
	}, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) { r.Delivery.Status = "delivered" }, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) { r.Authority = nil; r.Recovery = f }} {
		copy := fresh
		observation := *fresh.NoWorkObservation
		copy.NoWorkObservation = &observation
		bad := r
		bad.Authority = &copy
		change(&bad, &copy)
		out.Reset()
		if err := WriteReplacementJSON(context.Background(), &out, bad); err == nil || out.Len() != 0 {
			t.Fatal("invalid no-op rendered", out.String())
		}
	}
}

// full_only: false
func TestReplacementResultRejectsTransplantsAndPreservesUnknown(t *testing.T) {
	for _, change := range []func(*ReplacementCommandResult, *core.PublicReplacementResult){func(r *ReplacementCommandResult, f *core.PublicReplacementResult) { r.Authority = f }, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) {
		f.RequestIdentity = contract.ID{99}
	}, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) {
		f.Payload.RequestedRevisionID = contract.ID{99}
	}, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) {
		f.Payload.LiveDutyIDs = append(f.Payload.LiveDutyIDs, f.Payload.LiveDutyIDs[0])
	}, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) { r.Delivery.Status = "unproved" }, func(r *ReplacementCommandResult, f *core.PublicReplacementResult) {
		f.Receipt = f.Receipt[:len(f.Receipt)-1]
	}} {
		r := replacementResultFixture(t, configuration.ReplaceRecovery)
		fresh := replacementFresh(&r)
		change(&r, fresh)
		var out bytes.Buffer
		if err := WriteReplacementJSON(context.Background(), &out, r); err == nil || out.Len() != 0 {
			t.Fatal("malformed replacement emitted semantic prefix", out.String())
		}
	}
	r := replacementResultFixture(t, configuration.ReplaceRecipient)
	f := r.Recipient
	f.Result = core.Result{Outcome: core.UnresolvedCommit, Reason: core.WriteUncertain, RequestedRevision: f.Payload.RequestedRevisionID, CommitMayHaveOccurred: true}
	f.Payload.ObservedRevisionID = contract.ID{}
	f.Receipt = nil
	var out bytes.Buffer
	if err := WriteReplacementJSON(context.Background(), &out, r); err != nil || !bytes.Contains(out.Bytes(), []byte(`"state_result": "commit-outcome-unknown"`)) || !bytes.Contains(out.Bytes(), []byte(`"commit_may_have_occurred": true`)) || ReplacementCommandExitCode(r) != 3 {
		t.Fatal("unknown selection erased or overstated", err, out.String())
	}
}

// full_only: false
func TestReplacementRecognizedRefusalsRetainClosedTargetAndReadMeaning(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceAuthority, configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		r, err := NewReplacementCommandRefusal(target, contract.ID{1}, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := WriteReplacementJSON(context.Background(), &out, r); err != nil || !bytes.Contains(out.Bytes(), []byte("keys-replace-"+string(target))) || !bytes.Contains(out.Bytes(), []byte("PreAdmissionRequestIdentity/v1")) || !bytes.Contains(out.Bytes(), []byte(`"operation_payload": "none"`)) || ReplacementCommandExitCode(r) != 2 {
			t.Fatal("fresh refusal lost target", err, out.String())
		}
		fixed, _ := replacementCommandTarget(target)
		read, err := NewReplacementObservationRefusal(fixed, contract.ID{2}, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		read.PreAdmission.Code = string(contract.ReasonInvalidInput)
		observed := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
		out.Reset()
		if err := WriteReplacementJSON(context.Background(), &out, observed); err != nil {
			t.Fatal("read refusal lost recognized operation", err)
		}
		want := "keys-replace-receipt"
		if target == configuration.ReplaceAuthority {
			want = "keys-replace-observe"
		}
		if !bytes.Contains(out.Bytes(), []byte(want)) || !bytes.Contains(out.Bytes(), []byte(`"replay_identity": "none"`)) || !bytes.Contains(out.Bytes(), []byte(`"operation_payload": "none"`)) || bytes.Contains(out.Bytes(), []byte("commit-outcome-unknown")) {
			t.Fatal("existing output relabeled fresh mutation", out.String())
		}
	}
}

type replacementResultShortWriter struct{}

func (replacementResultShortWriter) Write(body []byte) (int, error) { return len(body) / 2, nil }

// full_only: false
func TestReplacementResultOutputFailureAndContextAreExplicit(t *testing.T) {
	r := replacementResultFixture(t, configuration.ReplaceAuthority)
	if err := WriteReplacementJSON(context.Background(), replacementResultShortWriter{}, r); err != io.ErrShortWrite {
		t.Fatal("short write accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	if err := WriteReplacementHuman(ctx, &out, r); err != context.Canceled || out.Len() != 0 {
		t.Fatal("canceled delivery emitted result", err, out.String())
	}
}

// These public rendering inputs reuse the independent query literals recorded
// with their derivation in the owning work evidence. They grant no admission or proof.
func replacementRenderedQuery(t *testing.T, target core.ReplacementTarget, observed bool) core.ReplacementQueryIdentity {
	t.Helper()
	q := core.ReplacementQueryIdentity{Schema: "QueryRequestIdentity/v1", Target: target, ExpectedDomain: contract.ID{1}, StoreID: contract.ID{2}, CoordinateID: contract.ID{3}, NonBodyID: contract.ID{4}, StoreDescriptorDigest: contract.ID{5}, SourceBasisDigest: contract.ID{6}, SuccessorBasisDigest: contract.ID{7}, SourcePins: core.AdministrativeSourcePins{FileID: contract.ID{11}, Format: 1, EditableDigest: contract.ID{12}, GeneratedDigest: contract.ID{13}, EditableLength: 101, GeneratedLength: 202, HasGenerated: true}, OutputPins: core.AdministrativeSourcePins{FileID: contract.ID{11}, Format: 1, EditableDigest: contract.ID{14}, GeneratedDigest: contract.ID{15}, EditableLength: 303, GeneratedLength: 404, HasGenerated: true}, RequestNonce: contract.ID{16}, OriginalOperationID: contract.ID{17}, OriginalRequestIdentity: contract.ID{18}, CandidateDigest: contract.ID{19}, RequestedRevisionID: contract.ID{20}, Goal: core.RoleReplacementGoal{ApprovalRole: 1, SigningSelector: "sign-next"}}
	literal := ""
	switch target {
	case core.ReplacementTargetAuthority:
		q.Operation = core.ReplacementObserve
		q.SemanticOperation = 15
		literal = "e2ad724f96dddfd94f9fbf6effe7ba51ae53325a3286d90ccee3b3598ef71f47"
		if observed {
			literal = "3e82ad19b7a187f45bc05fde905cffac08f59bdd6d6bfa7ec717e1f3e189a3b7"
		}
	case core.ReplacementTargetRecovery:
		q.Operation = core.ReplacementReceipt
		q.SemanticOperation = 16
		q.RequiredStoredKind = 36
		q.Goal.ApprovalRole = 2
		q.Goal.EncryptionSelector = "enc-next"
		q.Goal.MaterialSource = core.ReplacementMaterialRecovery
		literal = "23c6cc9f1c5aa2d50167731f6a6ea6105fbcf69068ce3020e7f28e8e8a0c32aa"
	case core.ReplacementTargetRecipient:
		q.Operation = core.ReplacementReceipt
		q.SemanticOperation = 16
		q.RequiredStoredKind = 9
		q.RecipientID = contract.ID{21}
		q.Goal.SigningSelector = ""
		q.Goal.EncryptionSelector = "enc-next"
		q.Goal.MaterialSource = core.ReplacementMaterialAuthority
		literal = "0490523e389660fac235560480d3345fff2a8a2b4da705a6b85d7cbaeb9f4c48"
	}
	if observed {
		q.AuthenticatedBasisDigest = contract.ID{8}
		q.Observation = &core.AdministrativeObservation{DomainID: contract.ID{1}, Revision: contract.ID{22}, Snapshot: contract.ID{23}}
	}
	raw, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	copy(q.Digest[:], raw)
	return q
}
func replacementRenderedRead(q core.ReplacementQueryIdentity) core.PublicReplacementObservationResult {
	underlying := uint16(25)
	if q.Target == core.ReplacementTargetRecovery {
		underlying = 36
	}
	if q.Target == core.ReplacementTargetRecipient {
		underlying = 9
	}
	result := core.PublicReplacementObservationResult{Operation: q.Operation, Target: q.Target, UnderlyingOperation: underlying, RequestID: q.RequestNonce, OperationID: contract.ID{24}, RequestIdentity: q.Digest, DomainID: q.ExpectedDomain, Query: &q, StateResult: contract.ReaderSuccess, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure}}
	if q.Observation != nil {
		result.Result.ObservedRevision = q.Observation.Revision
		result.Result.ObservedSnapshotID = q.Observation.Snapshot
	}
	return result
}

// full_only: false
func TestReplacementReadResultsKeepExactRawKindAndHistoricalState(t *testing.T) {
	for _, target := range []core.ReplacementTarget{core.ReplacementTargetRecovery, core.ReplacementTargetRecipient} {
		t.Run(string(rune('0'+target)), func(t *testing.T) {
			q := replacementRenderedQuery(t, target, true)
			read := replacementRenderedRead(q)
			a := suppliedApplyResultFixture(t)
			row, err := contract.InspectCompactMutationReceipt(a.Receipt)
			if err != nil {
				t.Fatal(err)
			}
			row.OperationKind = q.RequiredStoredKind
			if target == core.ReplacementTargetRecovery {
				row.EffectSummary = contract.ReceiptEffectNotApplicable
			}
			row.DomainID = q.ExpectedDomain
			row.OperationID = q.OriginalOperationID
			row.RequestIdentityDigest = q.OriginalRequestIdentity
			row.RequestedRevisionID = q.RequestedRevisionID
			row.ObservedRevisionID = q.RequestedRevisionID
			raw, err := contract.EncodeCompactMutationReceipt(row)
			if err != nil {
				t.Fatal(err)
			}
			read.Receipt = &core.ReplacementReceiptObservation{Receipt: row, ReceiptBytes: raw, EvidenceLimit: "retained-original-receipt-currentness-separate"}
			r := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
			var out bytes.Buffer
			if err := WriteReplacementJSON(context.Background(), &out, r); err != nil {
				t.Fatal(err)
			}
			var wire replacementResultRecord
			if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
				t.Fatal(err)
			}
			var payload replacementReceiptRecord
			if err := json.Unmarshal(wire.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if wire.OperationPayload != "ReceiptPayload/v1" || wire.Operation != "keys-replace-receipt" || wire.State != "success" || wire.Replay != "none" || payload.Bytes != hex.EncodeToString(raw) || payload.State != row.StateResult || payload.CandidateSelected || wire.Query.RequiredKind != q.RequiredStoredKind || wire.Query.OriginalIdentity != readerID(row.RequestIdentityDigest) || wire.Observed == readerID(row.ObservedRevisionID) {
				t.Fatal("historical receipt relabeled current mutation", out.String())
			}
			observedSnapshot := read.Result.ObservedSnapshotID
			read.Result.ObservedSnapshotID = contract.ID{99}
			out.Reset()
			if err := WriteReplacementJSON(context.Background(), &out, r); err == nil || out.Len() != 0 {
				t.Fatal("receipt read contradicted query observation")
			}
			read.Result.ObservedSnapshotID = observedSnapshot
			read.Receipt.CandidateSelected = true
			out.Reset()
			if err := WriteReplacementJSON(context.Background(), &out, r); err == nil || out.Len() != 0 {
				t.Fatal("receipt fabricated candidate currentness")
			}
			read.Receipt.CandidateSelected = false
			read.Receipt.Receipt.OperationKind = 2
			out.Reset()
			if err := WriteReplacementJSON(context.Background(), &out, r); err == nil || out.Len() != 0 {
				t.Fatal("wrong typed historical receipt rendered")
			}
		})
	}
}

// full_only: false
func TestReplacementAuthorityReadSeparatesUsabilityFromCandidateAndAbsentObservation(t *testing.T) {
	q := replacementRenderedQuery(t, core.ReplacementTargetAuthority, false)
	read := replacementRenderedRead(q)
	read.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
	read.StateResult = contract.ReaderUnavailable
	r := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
	var out bytes.Buffer
	if err := WriteReplacementJSON(context.Background(), &out, r); err != nil || !bytes.Contains(out.Bytes(), []byte(`"observation": null`)) || bytes.Contains(out.Bytes(), []byte(`"replay_identity": "`+readerID(q.OriginalRequestIdentity)+`"`)) {
		t.Fatal("absent observation became historical success", err, out.String())
	}
	q = replacementRenderedQuery(t, core.ReplacementTargetAuthority, true)
	read = replacementRenderedRead(q)
	fixture, basis := installedarchive.LoadReader(t, "aws")
	var public struct {
		Descriptor []byte `json:"descriptor"`
	}
	if err := json.Unmarshal(basis, &public); err != nil {
		t.Fatal(err)
	}
	d, err := contract.DecodeGenesisDescriptorCore(public.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	control := contract.ControlCore{CurrentControl: d.CurrentControl(), AuthorityKMSBinding: fixture.Archive.AuthorityBinding}
	// Change only public fixture coordinates to the independent query vector.
	// Structural validation still runs; this is not an authority constructor.
	control.DomainID = q.ExpectedDomain
	control.StoreID = q.StoreID
	control.CoordinateID = q.CoordinateID
	control.NonBodyID = q.NonBodyID
	control.NormalSigning.Binding.Domain = q.ExpectedDomain
	control.NormalSigning.Binding.Store = q.StoreID
	control.NormalSigning.Binding.Coordinate = q.CoordinateID
	if control.Recovery != nil {
		copy := *control.Recovery
		copy.Signing.Binding.Domain = q.ExpectedDomain
		copy.Signing.Binding.Store = q.StoreID
		copy.Signing.Binding.Coordinate = q.CoordinateID
		control.Recovery = &copy
	}
	current := control
	current.AccessGeneration++
	read.Selection = &core.ReplacementCurrentSelection{RequestedControl: control, CurrentControl: current, SuccessorSourceUsable: true, CandidateSelected: false, EvidenceLimit: "historical-attribution-unavailable"}
	r.Observation = &read
	out.Reset()
	if err := WriteReplacementJSON(context.Background(), &out, r); err != nil {
		t.Fatal("ordinary access progression refused usable source", err)
	}
	var wire replacementResultRecord
	if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	var selection replacementSelectionRecord
	if err := json.Unmarshal(wire.Payload, &selection); err != nil {
		t.Fatal(err)
	}
	if wire.Replay != "none" || !selection.SourceUsable || selection.CandidateSelected || selection.View != "current-selection" || wire.OperationPayload != "InspectionPayload/v1" || selection.Schema != "InspectionPayload/v1" || wire.State != "success" {
		t.Fatal("basis usability conflated with candidate or historical mutation", out.String())
	}
	read.Selection.CandidateSelected = true
	out.Reset()
	if err := WriteReplacementJSON(context.Background(), &out, r); err == nil || out.Len() != 0 {
		t.Fatal("different current revision claimed exact candidate")
	}
	read.Selection.CandidateSelected = false
	read.Query.Digest[1]++
	out.Reset()
	if err := WriteReplacementJSON(context.Background(), &out, r); err == nil || out.Len() != 0 {
		t.Fatal("changed query identity rendered")
	}
}

// full_only: false
func TestReplacementReadPreservesRootAndCapacityRefusals(t *testing.T) {
	for _, test := range []struct {
		result core.Result
		state  contract.ReaderStateResult
	}{{core.Result{Outcome: core.RootLossUnsupported, Reason: core.InvalidProof}, core.ReplacementRootLossUnsupported}, {core.Result{Outcome: core.AdmissionRefused, Reason: core.CapacityExceeded}, contract.ReaderRefused}} {
		q := replacementRenderedQuery(t, core.ReplacementTargetAuthority, false)
		read := replacementRenderedRead(q)
		read.Result = test.result
		read.StateResult = test.state
		result := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
		var out bytes.Buffer
		if err := WriteReplacementJSON(context.Background(), &out, result); err != nil || !bytes.Contains(out.Bytes(), []byte(`"state_result": "`+string(test.state)+`"`)) {
			t.Fatal("read refusal lost its actual state", err, out.String())
		}
		read.StateResult = contract.ReaderUnavailable
		out.Reset()
		if err := WriteReplacementJSON(context.Background(), &out, result); err == nil || out.Len() != 0 {
			t.Fatal("root or capacity refusal normalized to unavailable")
		}
	}
}

// full_only: false
func TestReplacementAuthoritySuccessRequiresExactSelectedFacts(t *testing.T) {
	for _, change := range []func(*core.PublicReplacementResult){func(r *core.PublicReplacementResult) {
		r.Result.ObservedRevision = contract.ID{}
		r.Payload.ObservedRevisionID = contract.ID{}
	}, func(r *core.PublicReplacementResult) {
		r.Result.ObservedRevision = contract.ID{99}
		r.Payload.ObservedRevisionID = contract.ID{99}
	}, func(r *core.PublicReplacementResult) { r.Result.ObservedSnapshotID = contract.ID{} }, func(r *core.PublicReplacementResult) { r.Result.StoreReason = contract.ReasonTransport }, func(r *core.PublicReplacementResult) { r.Result.Reason = core.SigningUnavailable }} {
		result := replacementResultFixture(t, configuration.ReplaceAuthority)
		change(result.Authority)
		var out bytes.Buffer
		if err := WriteReplacementJSON(context.Background(), &out, result); err == nil || out.Len() != 0 {
			t.Fatal("contradictory selected success escaped preflight", out.String())
		}
	}
	result := replacementResultFixture(t, configuration.ReplaceAuthority)
	result.Authority.Result.Reason = core.CustodyUnavailable
	result.Delivery.Failed = true
	var out bytes.Buffer
	if err := WriteReplacementJSON(context.Background(), &out, result); err != nil || !bytes.Contains(out.Bytes(), []byte(`"state_result": "success"`)) || ReplacementCommandExitCode(result) != 2 {
		t.Fatal("postselection custody problem erased known selection", err, out.String())
	}
}

// full_only: false
func TestReplacementReadsRejectMutationOnlyPublicStates(t *testing.T) {
	for _, state := range []contract.ReaderStateResult{"contention", "snapshot-size-refusal", "commit-outcome-unknown", "exact-resume"} {
		q := replacementRenderedQuery(t, core.ReplacementTargetAuthority, false)
		read := replacementRenderedRead(q)
		read.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.StalePrecondition}
		read.StateResult = state
		result := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
		var out bytes.Buffer
		if err := WriteReplacementJSON(context.Background(), &out, result); err == nil || out.Len() != 0 {
			t.Fatal("query accepted mutation-only state", state, out.String())
		}
	}
	q := replacementRenderedQuery(t, core.ReplacementTargetAuthority, false)
	read := replacementRenderedRead(q)
	read.Result = core.Result{Outcome: core.Contention, Reason: core.DifferentSelection}
	read.StateResult = contract.ReaderUnavailable
	result := ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
	var out bytes.Buffer
	if err := WriteReplacementJSON(context.Background(), &out, result); err == nil || out.Len() != 0 {
		t.Fatal("renderer repaired unnormalized owner contention")
	}
	read.Result.Outcome = core.EvidenceUnavailable
	if err := WriteReplacementJSON(context.Background(), &out, result); err != nil || !bytes.Contains(out.Bytes(), []byte(`"state_result": "unavailable"`)) || !bytes.Contains(out.Bytes(), []byte(`"reason": "different_selection"`)) {
		t.Fatal("allowed read family lost owning cause", err, out.String())
	}
}

// full_only: false
func TestReplacementReceiptSummaryMatchesStoredOperation(t *testing.T) {
	for _, target := range []configuration.ReplacementTarget{configuration.ReplaceRecovery, configuration.ReplaceRecipient} {
		for _, historical := range []bool{false, true} {
			mode := "fresh"
			if historical {
				mode = "historical"
			}
			t.Run(string(target)+"/"+mode, func(t *testing.T) {
				result := replacementResultFixture(t, target)
				fresh := replacementFresh(&result)
				row, err := contract.InspectCompactMutationReceipt(fresh.Receipt)
				if err != nil {
					t.Fatal(err)
				}
				// Schema 3 puts the effect summary at bytes 6:8. The canonical
				// Recovery writer stores not-applicable 0; Recipient stores
				// its existing no-change 1. These literals do not come from
				// the renderer or a relabelled Apply result.
				want := uint16(0)
				if target == configuration.ReplaceRecipient {
					want = 1
				}
				if row.EffectSummary != want || fresh.Receipt[6] != 0 || fresh.Receipt[7] != byte(want) {
					t.Fatal("fixture does not have the operation's stored summary")
				}
				if historical {
					fixed, ok := replacementCommandTarget(target)
					if !ok {
						t.Fatal("closed target unavailable")
					}
					q := replacementRenderedQuery(t, fixed, true)
					read := replacementRenderedRead(q)
					row.DomainID = q.ExpectedDomain
					row.OperationID = q.OriginalOperationID
					row.RequestIdentityDigest = q.OriginalRequestIdentity
					row.RequestedRevisionID = q.RequestedRevisionID
					row.ObservedRevisionID = q.RequestedRevisionID
					raw, err := contract.EncodeCompactMutationReceipt(row)
					if err != nil {
						t.Fatal(err)
					}
					read.Receipt = &core.ReplacementReceiptObservation{Receipt: row, ReceiptBytes: raw, EvidenceLimit: "retained-original-receipt-currentness-separate"}
					result = ReplacementCommandResult{Observation: &read, Delivery: ReplacementCommandDelivery{Status: "existing", Path: "/successor.json"}}
				}
				var valid bytes.Buffer
				if err := WriteReplacementJSON(context.Background(), &valid, result); err != nil || valid.Len() == 0 {
					t.Fatal("exact stored operation summary refused", err)
				}
				var raw []byte
				if historical {
					raw = bytes.Clone(result.Observation.Receipt.ReceiptBytes)
				} else {
					raw = bytes.Clone(fresh.Receipt)
				}
				raw[7] ^= 1
				wrong, err := contract.InspectCompactMutationReceipt(raw)
				if err != nil || wrong.EffectSummary != (want^1) {
					t.Fatal("damage must remain generically canonical and change only the summary", err)
				}
				if historical {
					result.Observation.Receipt.Receipt = wrong
					result.Observation.Receipt.ReceiptBytes = raw
				} else {
					fresh.Receipt = raw
				}
				if ReplacementCommandExitCode(result) != 2 {
					t.Fatal("wrong stored operation summary has no refusal exit")
				}
				for _, human := range []bool{false, true} {
					var output bytes.Buffer
					var err error
					if human {
						err = WriteReplacementHuman(context.Background(), &output, result)
					} else {
						err = WriteReplacementJSON(context.Background(), &output, result)
					}
					if err == nil || output.Len() != 0 {
						t.Fatal("another operation's compact summary passed semantic preflight")
					}
				}
			})
		}
	}
}
