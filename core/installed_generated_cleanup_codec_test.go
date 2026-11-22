package core

import (
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedCleanupDiagnosticCountAndExactCanonicalAccount(t *testing.T) {
	r := cleanupCommitmentLiteral()
	diagnostic := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, Name: strings.Repeat("\x00", 256), DestinationID: strings.Repeat("\x00", 256)},
		Path: []contract.DiagnosticField{contract.FieldLocatorRequiresCreation}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable,
		SourceLocation: &contract.SourceLocation{SourceID: strings.Repeat("a", 64), Line: math.MaxUint64, Column: math.MaxUint64}}
	w := cleanupHashWriter{}
	writeCleanupDiagnostic(&w, diagnostic)
	if w.err != nil || w.length != 719 {
		t.Fatal("independent canonical diagnostic account", w.length, w.err)
	}
	r.Diagnostics = make([]contract.Diagnostic, 3081)
	for i := range r.Diagnostics {
		r.Diagnostics[i] = diagnostic
	}
	if err := RefreshGeneratedCleanupResult(&r); err != nil {
		t.Fatal("finite complete diagnostic account refused", err)
	}
	w = cleanupHashWriter{}
	writeGeneratedCleanupRow(&w, r)
	if w.err != nil || w.length != 2216095 {
		t.Error("complete cleanup row account", w.length, w.err)
	}
	r.Diagnostics = append(r.Diagnostics, diagnostic)
	before := r.Result
	if err := RefreshGeneratedCleanupResult(&r); err == nil || r.Result != before || !r.Cleanup.SiblingResults.RootDigest.IsZero() {
		t.Error("one-over count changed selection or kept a valid delivery commitment", err)
	}
}

// The cleanup encoding recipe in spec/057 uses I(n)=n followed by 31 zero
// bytes, BE framing and one owned target. Independent Python SHA-256 with
// Snapshot Ref format 10 gives target/basis/row/vector lengths 273/441/856/1002;
// Target schema2 binds config/resource/digest and lifecycle; the outer domain is v3.
func cleanupCommitmentLiteral() PublicApplyResult {
	id := func(n byte) (v contract.ID) { v[0] = n; return }
	empty := contract.EmptyMutationResultDescriptors()
	target := &contract.GeneratorTarget{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratorTargetSchema, Name: "x", IncarnationID: id(14), ResourceID: id(15), ResourceDigest: id(17), ConfigContractID: id(18), ResourceContractID: id(19), OriginalOperationID: id(6), OriginalAttemptID: id(7), ResultContractID: id(20), CompletionClass: 1}
	return PublicApplyResult{DomainID: id(1), OperationID: id(2), RequestIdentity: id(3), RequestID: id(8), Result: Result{Outcome: Contention, RequestedRevision: id(10), ObservedRevision: id(11)},
		Cleanup:   &GeneratedCleanupPayload{Schema: 1, Basis: GeneratedCleanupBasis{Kind: GeneratedCleanupOwnedTarget, PlanGraphID: id(4), SourceKind: 10, SourceID: id(5), OriginalOwnerID: id(5), OriginalOperationID: id(6), OriginalAttemptID: id(7), Target: target}, PredecessorRevisionID: id(9), RemainingWorkBasis: GeneratedCleanupWorkBasis{HeadRevisionID: id(9), Snapshot: contract.Ref{Kind: 3, Format: contract.CanonicalSchema, Domain: id(1), Object: id(12), Digest: id(13), Length: 123}}, RemainingDutyIDs: []contract.ID{id(5)}},
		Generated: &GeneratedInvocationResult{OperationKind: 31, StateResult: "contention", CanonicalOutcome: 2, EffectSummary: 1, EvidenceCeiling: 1, SummaryCountsAvailable: true, EffectsAvailable: true, EffectsCommitment: &empty[1]}}
}

// full_only: false
func TestGeneratedCleanupSiblingIndependentLiterals(t *testing.T) {
	r := cleanupCommitmentLiteral()
	w := cleanupHashWriter{}
	writeGeneratedCleanupRow(&w, r)
	if w.err != nil || w.length != 856 {
		t.Fatal("independent row length", w.length, w.err)
	}
	got, err := GeneratedCleanupSiblingResults(r)
	if err != nil || got.Count != 1 || hex.EncodeToString(got.RootDigest[:]) != "b4e3dae254830a25ffd607fde3ec063887a95c50a9f778df3003b895f78ac0a0" {
		t.Fatal("independent one-row commitment", got, err)
	}
	r.Cleanup.Basis = GeneratedCleanupBasis{Kind: GeneratedCleanupNoWork}
	r.Generated.StateResult = "no-op"
	r.Result = Result{Outcome: Unchanged, Evidence: AuthenticatedClosure, ObservedRevision: r.Cleanup.RemainingWorkBasis.HeadRevisionID}
	empty := contract.EmptyMutationResultDescriptors()
	r.Generated.RelatedWorkAvailable = true
	r.Generated.RelatedDutiesCommitment, r.Generated.RelatedHazardsCommitment = &empty[3], &empty[4]
	got, err = GeneratedCleanupSiblingResults(r)
	if err != nil || got.Count != 0 || hex.EncodeToString(got.RootDigest[:]) != "71f0781a155ab7bfc303170a1e6d9ad175fdbfcaa6b19e6f3124a63dd1fe2cd2" {
		t.Fatal("independent empty commitment", got, err)
	}
}

// full_only: false
func TestGeneratedCleanupSiblingRetainsPreparationInterruptionAndDeliveryDiagnostics(t *testing.T) {
	r := cleanupCommitmentLiteral()
	before := r.Result
	r.Diagnostics = []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedObjectUnavailable},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonExpired},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable},
	}
	conflict := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonImmutableConflict}
	r.Diagnostics = append(r.Diagnostics, conflict)
	other := conflict
	other.Subject.Kind = contract.SubjectEntry
	if cleanupDiagnosticValid(other) {
		t.Fatal("non-Store subject claimed an immutable write conflict")
	}
	if err := RefreshGeneratedCleanupResult(&r); err != nil {
		t.Fatal("complete cleanup result cannot commit its admissible diagnostic sequence", err)
	}
	commitment := r.Cleanup.SiblingResults
	if r.Result != before || commitment.Count != 1 || commitment.RootDigest.IsZero() {
		t.Fatal("cleanup diagnostic refresh replaced selection or lost the sibling")
	}
	for i := range r.Diagnostics {
		old := r.Diagnostics[i].Reason
		r.Diagnostics[i].Reason = contract.ReasonCancelled
		got, err := GeneratedCleanupSiblingResults(r)
		if err != nil || got == commitment {
			t.Error("cleanup commitment omitted a diagnostic", i, err)
		}
		r.Diagnostics[i].Reason = old
	}
}

// full_only: false
func TestGeneratedCleanupSiblingBindsCompleteProductFacts(t *testing.T) {
	baseline, err := GeneratedCleanupSiblingResults(cleanupCommitmentLiteral())
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*PublicApplyResult){
		"source":              func(r *PublicApplyResult) { r.Cleanup.Basis.SourceID[1] = 1 },
		"target token":        func(r *PublicApplyResult) { r.Cleanup.Basis.Target.ResourceDigest[1] = 1 },
		"state":               func(r *PublicApplyResult) { r.Generated.StateResult = "refused"; r.Result = refused(AdmissionInvalid) },
		"evidence":            func(r *PublicApplyResult) { r.Generated.EvidenceCeiling = 2 },
		"warnings":            func(r *PublicApplyResult) { r.WarningBits = 1 },
		"generated warnings":  func(r *PublicApplyResult) { r.Generated.Warnings.LateEffect = true },
		"count availability":  func(r *PublicApplyResult) { r.Generated.SummaryCountsAvailable = false },
		"remaining hazards":   func(r *PublicApplyResult) { r.Cleanup.RemainingHazardIDs = []contract.ID{generatedVectorID(33)} },
		"request correlation": func(r *PublicApplyResult) { r.RequestID[1] = 1 },
		"commit uncertainty": func(r *PublicApplyResult) {
			r.Generated.StateResult = "commit-outcome-unknown"
			r.Result.Outcome = UnresolvedCommit
			r.Result.CommitMayHaveOccurred = true
		},
		"diagnostic": func(r *PublicApplyResult) {
			r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := cleanupCommitmentLiteral()
			change(&r)
			got, err := GeneratedCleanupSiblingResults(r)
			if err != nil || got == baseline {
				t.Fatal("complete Product fact was not committed", got, err)
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupSiblingRejectsContradictionsAndRefreshesDiagnostics(t *testing.T) {
	for name, change := range map[string]func(*PublicApplyResult){
		"unavailable nonzero counts": func(r *PublicApplyResult) {
			r.Generated.SummaryCountsAvailable = false
			r.Generated.SummaryCounts[0] = 1
		},
		"wrong count":                         func(r *PublicApplyResult) { r.Generated.SummaryCounts[0] = 1 },
		"wrong support descriptor":            func(r *PublicApplyResult) { r.Generated.EffectsCommitment.Digest[1] = 1 },
		"available vector without descriptor": func(r *PublicApplyResult) { r.Generated.EffectsCommitment = nil },
		"unavailable descriptor":              func(r *PublicApplyResult) { r.Generated.EffectsAvailable = false },
		"duplicate remaining ID": func(r *PublicApplyResult) {
			r.Cleanup.RemainingDutyIDs = append(r.Cleanup.RemainingDutyIDs, r.Cleanup.RemainingDutyIDs[0])
		},
		"wrong remaining domain": func(r *PublicApplyResult) { r.Cleanup.RemainingWorkBasis.Snapshot.Domain[1] = 1 },
		"wrong schema":           func(r *PublicApplyResult) { r.Cleanup.Schema = 2 },
		"contention selected canonical outcome": func(r *PublicApplyResult) {
			r.Generated.CanonicalOutcome = contract.ReceiptCanonicalSelected
		},
		"unknown commit selected canonical outcome": func(r *PublicApplyResult) {
			r.Result.Outcome, r.Result.CommitMayHaveOccurred = UnresolvedCommit, true
			r.Generated.StateResult, r.Generated.CanonicalOutcome = "commit-outcome-unknown", contract.ReceiptCanonicalSelected
		},
		"refusal selected canonical outcome": func(r *PublicApplyResult) {
			r.Result = refused(AdmissionInvalid)
			r.Generated.StateResult, r.Generated.CanonicalOutcome = "refused", contract.ReceiptCanonicalSelected
		},
		"integrity failure selected canonical outcome": func(r *PublicApplyResult) {
			r.Result = failure(IntegrityFailure, InvalidRelation)
			r.Generated.StateResult, r.Generated.CanonicalOutcome = "positive-defect", contract.ReceiptCanonicalSelected
		},
		"unavailable selected canonical outcome": func(r *PublicApplyResult) {
			r.Result = failure(EvidenceUnavailable, MissingSelectedObject)
			r.Generated.StateResult, r.Generated.CanonicalOutcome = "unavailable", contract.ReceiptCanonicalSelected
		},
		"transition": func(r *PublicApplyResult) { r.Payload = &TransitionPayload{} },
		"receipt":    func(r *PublicApplyResult) { r.Receipt = []byte{1} },
		"raw diagnostic": func(r *PublicApplyResult) {
			r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: "raw error"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := cleanupCommitmentLiteral()
			change(&r)
			if _, err := GeneratedCleanupSiblingResults(r); err == nil {
				t.Fatal("contradictory result accepted")
			}
		})
	}
	r := cleanupCommitmentLiteral()
	if err := RefreshGeneratedCleanupResult(&r); err != nil {
		t.Fatal(err)
	}
	before := r.Cleanup.SiblingResults
	r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable}}
	if err := RefreshGeneratedCleanupResult(&r); err != nil || r.Cleanup.SiblingResults == before {
		t.Fatal("delivery diagnostic did not refresh", err)
	}
	actual := r.Result
	r.Generated.SummaryCounts[0] = 1
	if err := RefreshGeneratedCleanupResult(&r); err == nil || r.Cleanup.SiblingResults != (GeneratedCleanupSiblingCommitment{}) || r.Result != actual || r.Generated == nil {
		t.Fatal("invalid delivery changed actual commit or kept stale hash", err)
	}
}

// full_only: false
func TestGeneratedCleanupPayloadAccountsDistinctOwnedBacking(t *testing.T) {
	first := cleanupCommitmentLiteral().Cleanup
	second := *first
	second.Basis = ownedGeneratedCleanupBasis(first.Basis)
	second.RemainingDutyIDs = append([]contract.ID(nil), first.RemainingDutyIDs...)
	got, err := generatedCleanupPayloadBackingBytes(first, &second)
	want := 2*uint64(unsafe.Sizeof(*first)) + 2*uint64(unsafe.Sizeof(*first.Basis.Target)) + 2 + 64
	if err != nil || got != want {
		t.Fatal("distinct before/selected backing", got, want, err)
	}
	reused, err := generatedCleanupPayloadBackingBytes(first, first)
	if err != nil || reused*2 != got {
		t.Fatal("shared backing counted twice", reused, got, err)
	}
}

// full_only: false
func TestGeneratedCleanupPayloadFixedLayout(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("cleanup backing account requires supported 64-bit application layout")
	}
	if unsafe.Sizeof(GeneratedCleanupPayload{}) != 472 || unsafe.Sizeof(GeneratedCleanupBasis{}) != 184 || unsafe.Sizeof(contract.GeneratorTarget{}) != 296 || unsafe.Sizeof(contract.GeneratorResultReference{}) != 72 || unsafe.Sizeof(generatedCleanupResultCapture{}) != 56 {
		t.Fatal("cleanup owned backing layout changed")
	}
}

// full_only: false
func TestGeneratedCleanupSiblingRejectsResultStateContradictions(t *testing.T) {
	for name, change := range map[string]func(*PublicApplyResult){
		"contention with refusal":         func(r *PublicApplyResult) { r.Generated.StateResult = "refused" },
		"contention with possible commit": func(r *PublicApplyResult) { r.Result.CommitMayHaveOccurred = true },
		"unknown commit with contention":  func(r *PublicApplyResult) { r.Result.Outcome = UnresolvedCommit; r.Result.CommitMayHaveOccurred = true },
		"ordinary selection with no-op": func(r *PublicApplyResult) {
			r.Result = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: r.Cleanup.RemainingWorkBasis.HeadRevisionID, ObservedRevision: r.Cleanup.RemainingWorkBasis.HeadRevisionID}
			r.Generated.StateResult = "no-op"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := cleanupCommitmentLiteral()
			change(&r)
			if _, err := GeneratedCleanupSiblingResults(r); err == nil {
				t.Fatal("contradictory actual Result and Product state accepted")
			}
		})
	}
}

// full_only: false
func TestCleanupDiagnosticCoalescesExactRowAndKeepsCommittedResult(t *testing.T) {
	r := cleanupCommitmentLiteral()
	beforeResult, beforeGenerated := r.Result, *r.Generated
	r.Diagnostics = []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable, SourceLocation: &contract.SourceLocation{SourceID: strings.Repeat("a", 64), Line: 1, Column: 1}},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable},
	}
	unrelated := append([]contract.Diagnostic(nil), r.Diagnostics...)
	if err := RefreshGeneratedCleanupResult(&r); err != nil {
		t.Fatal(err)
	}
	beforeCommitment := r.Cleanup.SiblingResults
	r.AddCleanupDiagnostic()
	r.AddCleanupDiagnostic()
	if len(r.Diagnostics) != 3 || !reflect.DeepEqual(r.Diagnostics[:2], unrelated) || r.Result != beforeResult || !reflect.DeepEqual(*r.Generated, beforeGenerated) || len(r.Receipt) != 0 {
		t.Fatal("cleanup diagnostic replaced a result, receipt, fact, or unrelated row")
	}
	if err := RefreshGeneratedCleanupResult(&r); err != nil {
		t.Fatal(err)
	}
	if r.Cleanup.SiblingResults == beforeCommitment {
		t.Fatal("cleanup diagnostic was not committed")
	}
	commitment := r.Cleanup.SiblingResults
	r.AddCleanupDiagnostic()
	if err := RefreshGeneratedCleanupResult(&r); err != nil || r.Cleanup.SiblingResults != commitment {
		t.Fatal("repeated cleanup changed committed result", err)
	}
}
