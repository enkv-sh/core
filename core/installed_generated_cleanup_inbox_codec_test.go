package core

import (
	"encoding/hex"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func cleanupInboxCommitmentFixture() PublicApplyResult {
	r := cleanupCommitmentLiteral()
	b := &r.Cleanup.Basis
	b.Kind, b.SourceKind, b.Target = GeneratedCleanupInboxRelease, contract.PendingInboxReleaseSupportKind, nil
	b.OriginalResult = &contract.GeneratorResultReference{Schema: contract.GeneratorRecordSchema, ResultID: contract.ID{20}, ResultBodyDigest: contract.ID{21}, ResultLength: 128}
	b.SourceID, _ = contract.GeneratorInboxID(r.DomainID, b.OriginalOperationID, b.OriginalAttemptID, b.OriginalResult.ResultID)
	r.Cleanup.RemainingDutyIDs = nil
	r.Cleanup.RemainingInboxIDs = []contract.ID{b.SourceID, {22}}
	slices.SortFunc(r.Cleanup.RemainingInboxIDs, compareGeneratedIDs)
	empty := contract.EmptyMutationResultDescriptors()
	r.Generated.RelatedWorkAvailable = true
	r.Generated.RelatedDutiesCommitment, r.Generated.RelatedHazardsCommitment = &empty[3], &empty[4]
	return r
}

// full_only: false
func TestGeneratedCleanupInboxReleaseBindsOnlyNamedMapping(t *testing.T) {
	// Manual BE concatenation with I(n)=n then 31 zero bytes gives an
	// encoded result reference of 70 bytes, basis 238 and complete row 685.
	// Python hashlib.sha256 over the 831-byte v3 vector supplies this literal.
	literal, err := GeneratedCleanupSiblingResults(cleanupInboxCommitmentFixture())
	if err != nil || hex.EncodeToString(literal.RootDigest[:]) != "441e0bbf854b4b1c14ccff477fbc98246a0ca4768971328242c7175d29e3817d" {
		t.Fatal("independent named inbox commitment differs", literal, err)
	}
	for _, state := range []string{"unavailable", "contention", "commit-outcome-unknown", "success", "effect-unknown"} {
		t.Run(state, func(t *testing.T) {
			r := cleanupInboxCommitmentFixture()
			r.Generated.StateResult = state
			switch state {
			case "unavailable":
				r.Result = Result{Outcome: EvidenceUnavailable}
			case "commit-outcome-unknown":
				r.Result.Outcome, r.Result.CommitMayHaveOccurred = UnresolvedCommit, true
			case "success", "effect-unknown":
				r.Result = Result{Outcome: ObservedCurrent, Evidence: AuthenticatedClosure, RequestedRevision: contract.ID{23}, ObservedRevision: contract.ID{23}}
				r.Cleanup.RemainingWorkBasis.HeadRevisionID = contract.ID{23}
				r.Generated.CanonicalOutcome = contract.ReceiptCanonicalSelected
				if state == "success" {
					r.Cleanup.RemainingInboxIDs = []contract.ID{{22}}
				}
			}
			first, err := GeneratedCleanupSiblingResults(r)
			if err != nil || first.Count != 1 || first.RootDigest.IsZero() {
				t.Fatal("exact named release result refused", err)
			}
			r.Cleanup.Basis.OriginalResult.ResultBodyDigest[1] = 1
			changed, err := GeneratedCleanupSiblingResults(r)
			if err != nil || changed == first {
				t.Fatal("original result is absent from the commitment", err)
			}
			if state == "success" || state == "effect-unknown" {
				if state == "success" {
					r.Cleanup.RemainingInboxIDs = []contract.ID{r.Cleanup.Basis.SourceID}
				} else {
					r.Cleanup.RemainingInboxIDs = nil
				}
				if _, err := GeneratedCleanupSiblingResults(r); err == nil {
					t.Fatal("selected result contradicts its named remaining mapping")
				}
			}
		})
	}
	for name, change := range map[string]func(*PublicApplyResult){
		"other source kind":                     func(r *PublicApplyResult) { r.Cleanup.Basis.SourceKind = contract.GeneratedDutySupportKind },
		"missing source":                        func(r *PublicApplyResult) { r.Cleanup.Basis.SourceID = contract.ID{} },
		"missing original":                      func(r *PublicApplyResult) { r.Cleanup.Basis.OriginalResult = nil },
		"unrelated original operation":          func(r *PublicApplyResult) { r.Cleanup.Basis.OriginalOperationID[1] = 1 },
		"unrelated original result":             func(r *PublicApplyResult) { r.Cleanup.Basis.OriginalResult.ResultID[1] = 1 },
		"missing predecessor":                   func(r *PublicApplyResult) { r.Cleanup.PredecessorRevisionID = contract.ID{} },
		"invented provider effect":              func(r *PublicApplyResult) { r.Generated.SummaryCounts[contract.ReceiptEffectCount] = 1 },
		"unknown provider effect":               func(r *PublicApplyResult) { r.Generated.UnknownCount = 1 },
		"missing mapping on contention":         func(r *PublicApplyResult) { r.Cleanup.RemainingInboxIDs = nil },
		"current work claimed after contention": func(r *PublicApplyResult) { r.Cleanup.RemainingWorkBasis.HeadRevisionID = contract.ID{23} },
		"invented target":                       func(r *PublicApplyResult) { r.Cleanup.Basis.Target = cleanupCommitmentLiteral().Cleanup.Basis.Target },
		"incomplete observation": func(r *PublicApplyResult) {
			r.Generated.RelatedWorkAvailable = false
			r.Generated.RelatedDutiesCommitment = nil
			r.Generated.RelatedHazardsCommitment = nil
		},
		"invented receipt":  func(r *PublicApplyResult) { r.Receipt = []byte{1} },
		"wrong clean state": func(r *PublicApplyResult) { r.Generated.StateResult = "effect-pending" },
	} {
		t.Run(name, func(t *testing.T) {
			r := cleanupInboxCommitmentFixture()
			change(&r)
			before := r.Result
			if err := RefreshGeneratedCleanupResult(&r); err == nil || !reflect.DeepEqual(before, r.Result) || !r.Cleanup.SiblingResults.RootDigest.IsZero() {
				t.Fatal("contradictory named release result was published", err)
			}
		})
	}
}
