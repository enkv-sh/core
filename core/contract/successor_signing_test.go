package contract

import "testing"

// full_only: false
func TestSigningPurposesSeparateRoles(t *testing.T) {
	for _, tc := range []struct {
		purpose          Purpose
		normal, recovery bool
	}{
		{1, true, false}, {3, true, false}, {4, true, false}, {5, false, true},
		{7, true, true}, {8, false, true}, {10, true, false}, {11, false, true}, {12, true, false}, {13, true, false}, {14, true, true}, {15, true, false}, {16, true, false}, {17, true, false},
	} {
		q := SignRequest{purpose: tc.purpose, digest: Hash([]byte("typed subject"))}
		if !q.Valid() || SigningPurposeAllowed(NormalSigningRole, tc.purpose) != tc.normal || SigningPurposeAllowed(RecoverySigningRole, tc.purpose) != tc.recovery {
			t.Fatalf("purpose %d has incorrect role admission", tc.purpose)
		}
	}
	for _, p := range []Purpose{0, 2, 6, 9, 255} {
		if (SignRequest{purpose: p, digest: Hash([]byte("typed subject"))}).Valid() || SigningPurposeAllowed(NormalSigningRole, p) || SigningPurposeAllowed(RecoverySigningRole, p) {
			t.Fatalf("unregistered purpose %d admitted", p)
		}
	}
}
