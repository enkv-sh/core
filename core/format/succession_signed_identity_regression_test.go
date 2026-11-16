package format

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestSuccessionActualAuthorizationCommitsDerivedRequestIdentity(t *testing.T) {
	first := successionNonemptyIdentityRegressionPlan(t)
	second := first
	second.AfterAccess.Digest = contract.Hash([]byte("a different complete output vector"))
	a, err := DeriveSuccessionIdentity(first)
	if err != nil {
		t.Fatal("first typed graph refused", err)
	}
	b, err := DeriveSuccessionIdentity(second)
	if err != nil {
		t.Fatal("second typed graph refused", err)
	}
	if a.RequestIdentityDigest == b.RequestIdentityDigest || a.Graph == b.Graph {
		t.Fatal("fixture did not change final graph identity")
	}
	left := successionActualIdentityRegressionRequest(t, first, a.RequestIdentityDigest)
	right := successionActualIdentityRegressionRequest(t, second, b.RequestIdentityDigest)
	if left.Purpose() != right.Purpose() || left.Purpose() != contract.K2SuccessionPurpose {
		t.Fatal("fixture changed signing authority")
	}
	if left.Digest() == right.Digest() {
		t.Fatal("different derived mutation identities reuse the same actual K2 succession signing request")
	}
}

// This regression exercises the graph/actual-signing contract, not selected
// closure admission. Format validates shapes; Core owns actual record-derived
// descriptor admission. The existing nonempty scalar test uses the same bound.
func successionNonemptyIdentityRegressionPlan(t testing.TB) SuccessionIdentityPlan {
	t.Helper()
	base := successionRecoveryIdentityFixture(t, contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK, contract.NormalSigningRole)
	root := base.Snapshot
	const payload = 102 + 2*489
	page := Ref{Kind: AccessKind, Format: Version, Domain: base.Request.DomainID, Object: fid(190), Digest: fid(191), Length: 75 + payload, Index: 0}
	root.CurrentAccess.Core.AccessPageRefs = []Ref{page}
	root.CurrentAccess.Core.AccessRecordsDescriptor = contract.DescriptorVector{Digest: fid(192), Length: uint64(len("ENKV/CRYPTO/v2/access-records\x00") + 32 + 4 + 4 + payload), Count: 1}
	root.AccessRecordCount = 1
	root.ChildCount++
	root.ChildEncodedBytes += uint64(page.Length)
	request := base.Request
	request.IdentityPlan.Pages = append(append([]contract.IdentityPage(nil), request.IdentityPlan.Pages...), contract.IdentityPage{Kind: AccessKind, Index: 0, Object: page.Object})
	plan := successionIdentityForRequest(t, request, root, base.Authorization.Subject.ReceiptDeltaDigest)
	plan.Coverage = contract.DescriptorVector{Digest: fid(193), Length: 178 + 168, Count: 1}
	plan.Unchanged = contract.DescriptorVector{Digest: fid(194), Length: 144 + 162, Count: 1}
	plan.AfterAccess = contract.DescriptorVector{Digest: fid(195), Length: 181 + 70 + payload, Count: 1}
	plan.Authorization.Subject.CoverageDigest = plan.Coverage.Digest
	plan.Authorization.Subject.CoverageCount = 1
	return plan
}

func successionActualIdentityRegressionRequest(t testing.TB, plan SuccessionIdentityPlan, identity contract.ID) contract.SignRequest {
	t.Helper()
	root, err := EncodeRoot(plan.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	head := HeadCore(plan.Head)
	head.Root.Digest = contract.Hash(root)
	core, err := EncodeHeadCore(head)
	if err != nil {
		t.Fatal(err)
	}
	condition := ConditionalPlan(plan.Conditional)
	condition.HeadCore = contract.Hash(core)
	encodedCondition, err := EncodeConditionalPlan(condition)
	if err != nil {
		t.Fatal(err)
	}
	subject := contract.SuccessionSubject(plan.Authorization.Subject)
	subject.RequestIdentityDigest = identity
	subject.HeadCoreDigest = contract.Hash(core)
	subject.ConditionalPlanDigest = contract.Hash(encodedCondition)
	actual := make([]contract.SuccessorEvidenceRow, len(plan.Evidence))
	for i, row := range plan.Evidence {
		actual[i] = contract.SuccessorEvidenceRow{TargetRole: row.TargetRole, EvidenceKind: row.EvidenceKind, KEK: row.KEK}
	}
	subject.SuccessorEvidenceDigest, err = contract.SuccessorEvidenceDigest(actual)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := contract.NewK2SuccessionRequest(subject)
	if err != nil {
		t.Fatal("actual typed succession signing request refused", err)
	}
	return signed
}
