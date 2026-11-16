package format

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestSuccessionGraphCommitsZeroMaterialAndPartialEqualityRoutes(t *testing.T) {
	for _, mask := range []uint8{1, 2, 3} {
		p := successionRecoveryIdentityFixture(t, 1, mask, 1)
		q := p.Request
		q.MaterialSourceRole = contract.SuccessionMaterialAuthority
		a := successionIdentityForRequest(t, q, p.Snapshot, p.Authorization.Subject.ReceiptDeltaDigest)
		first, err := DeriveSuccessionIdentity(a)
		if err != nil {
			t.Fatal(err)
		}
		q.MaterialSourceRole = contract.SuccessionMaterialRecovery
		b := successionIdentityForRequest(t, q, p.Snapshot, p.Authorization.Subject.ReceiptDeltaDigest)
		second, err := DeriveSuccessionIdentity(b)
		if err != nil {
			t.Fatal(err)
		}
		if a.Coverage.Count != 0 || b.Coverage.Count != 0 || first.RequestIdentityDigest == second.RequestIdentityDigest || first.PhaseEntry == second.PhaseEntry || first.Graph == second.Graph {
			t.Fatal("fixed zero-material routes shared identity", mask)
		}
		if a.Authorization.Subject.MaterialSourceRole != contract.SuccessionMaterialAuthority || b.Authorization.Subject.MaterialSourceRole != contract.SuccessionMaterialRecovery {
			t.Fatal("plan omitted exact route")
		}
		if mask == 1 {
			q.MaterialSourceRole = contract.SuccessionMaterialNone
			c := successionIdentityForRequest(t, q, p.Snapshot, p.Authorization.Subject.ReceiptDeltaDigest)
			third, err := DeriveSuccessionIdentity(c)
			if err != nil || third.RequestIdentityDigest == first.RequestIdentityDigest || third.RequestIdentityDigest == second.RequestIdentityDigest {
				t.Fatal("truly signing-only and declared equal encryption routes merged", err)
			}
		}
		b.Authorization.Subject.MaterialSourceRole = contract.SuccessionMaterialAuthority
		if _, err := DeriveSuccessionIdentity(b); err == nil {
			t.Fatal("request/authorization role disagreement admitted")
		}
		b.Authorization.Subject.MaterialSourceRole = contract.SuccessionMaterialRecovery
		b.Authorization.Subject.RequestIdentityDigest = second.RequestIdentityDigest
		if _, err := DeriveSuccessionIdentity(b); err == nil {
			t.Fatal("graph accepted its own final identity as input")
		}
	}
}
