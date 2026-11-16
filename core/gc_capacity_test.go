package core

import (
	"encoding/binary"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCCapacityMaximumPlanAndFixedProgressWidths(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	plan := gcTestPlan(t, s, "capacity-maximum")
	plan.PredecessorToken = contract.Token{Family: contract.AWS, Value: `"` + strings.Repeat("x", 254) + `"`}
	plan.InputProviderCursor, plan.NextProviderCursor = strings.Repeat("a", 4096), strings.Repeat("b", 4096)
	plan.Targets = make([]contract.GCTarget, 256)
	plan.Candidates = make([]contract.GCCandidate, 256)
	for i := range plan.Targets {
		var id contract.ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		plan.Targets[i] = contract.GCTarget{Object: contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: format.ValueEntryPageKind, ObjectID: id}, Length: 2 << 20, Digest: gcTestID("capacity-obsolete"), Token: plan.PredecessorToken}
		plan.Candidates[i] = contract.GCCandidate{KeyDigest: id, Classification: contract.GCCandidateEligible, TargetIndex: uint16(i), ListedLength: 2 << 20}
	}
	descriptor, err := contract.GCTargetsDescriptor(plan.Targets)
	if err != nil {
		t.Fatal(err)
	}
	plan.TargetsDigest = descriptor.Digest
	charge, err := gcPlanCapacity(plan)
	// A maximum target is333 bytes, a candidate44 bytes; both4096-byte
	// cursors include4-byte lengths. The nonvector plan portion is709.
	// Progress is150 fixed bytes plus34 bytes per selected target.
	want := gcCapacityCharge{Targets: 256, PlanBytes: 709 + 8192 + 256*(333+44), FramedPlanBytes: 105413 + 37, PlanPageBytes: 105413 + 37 + 75, ProgressBytes: 150 + 256*34}
	if err != nil || charge != want {
		t.Fatal("independent maximum capacity differs", charge, want, err)
	}
	progress := gcTestProgress(t, plan)
	progress.Targets = make([]contract.GCTargetProgress, 256)
	progress.RemainingCount = 256
	for _, outcome := range []contract.GCTargetDisposition{contract.GCTargetPending, contract.GCTargetUnknown, contract.GCTargetAbsent} {
		progress.Ordinal++
		for i := range progress.Targets {
			progress.Targets[i] = contract.GCTargetProgress{Consumed: 1, Disposition: outcome}
			if outcome == contract.GCTargetAbsent {
				progress.Targets[i].EvidenceDigest = gcTestID("capacity-absent")
			}
		}
		progress.RemainingCount = 256
		if outcome == contract.GCTargetAbsent {
			progress.RemainingCount = 0
		}
		body, err := contract.EncodeGCProgress(progress)
		if err != nil || uint64(len(body)) != want.ProgressBytes {
			t.Fatal("selected outcome changed fixed progress width", outcome, len(body), err)
		}
	}
}

// full_only: false
func TestGCCapacityEmptyPlanIsOnlyAnArtifact(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	plan := gcTestPlan(t, s, "capacity-empty")
	plan.Targets = nil
	plan.TargetsDigest = contract.GCTargetsEmptyDescriptor().Digest
	plan.Candidates[0].Classification = contract.GCCandidateProtected
	plan.Candidates[0].TargetIndex = 65535
	charge, err := gcPlanCapacity(plan)
	body, encodeErr := contract.EncodeGCPlan(plan)
	if err != nil || encodeErr != nil || charge.PlanBytes != uint64(len(body)) || charge.Targets != 0 || charge.ProgressBytes != 0 || charge.FramedPlanBytes != 0 || charge.PlanPageBytes != 0 {
		t.Fatal("empty preview acquired selected support or progress", charge, err, encodeErr)
	}
}
