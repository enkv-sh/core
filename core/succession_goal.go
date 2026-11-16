package core

import (
	"bytes"
	"context"
	"time"

	"enkv.sh/core/contract"
)

// The requested meaning omits replacement identities, serials and epochs.
// They are assigned only if the complete current binding differs.
type signingGoal struct {
	Provider    contract.Family
	Profile     uint16
	KeySelector string
	SPKI        []byte
	Fingerprint contract.ID
	PublicKey   contract.ID
	Trust       contract.ID
}

type kmsGoal struct {
	Provider        contract.Family
	WrapProfile     uint16
	ProtectionClass uint8
	KeySelector     string
	SPKI            []byte
	Fingerprint     contract.ID
}

type authorityGoal struct {
	Domain, Store, Coordinate, NonBody, Trust, Interpretation contract.ID
	ApprovalRole, Roles                                       uint8
	Signing                                                   *signingGoal
	KMS                                                       *kmsGoal
}

type admittedAuthorityGoal struct {
	session  *StateSession
	goal     authorityGoal
	deadline time.Time
}

// compareAuthorityGoal returns the requested roles that need fresh transition
// admission. An equal goal is only an authenticated current-state observation.
func (s *StateSession) compareAuthorityGoal(ctx context.Context, admitted *admittedAuthorityGoal) (uint8, Result) {
	if s == nil || ctx == nil || ctx.Err() != nil || admitted == nil || admitted.session != s || !time.Now().Before(admitted.deadline) || !s.admission.valid(s.store) || s.authority() == nil {
		return 0, refused(AdmissionInvalid)
	}
	g := admitted.goal
	if g.Domain != s.admission.domain || g.Store != s.admission.store.Identity || g.Coordinate != s.admission.store.Coordinate || g.NonBody != s.admission.store.NonBody || g.Trust != s.admission.trust || g.Interpretation != s.admission.interpretation || g.Roles == 0 || g.Roles&^3 != 0 || (g.Roles&1 != 0) != (g.Signing != nil) || (g.Roles&2 != 0) != (g.KMS != nil) || g.ApprovalRole != contract.NormalSigningRole && g.ApprovalRole != contract.RecoverySigningRole || g.ApprovalRole == contract.RecoverySigningRole && s.root.CurrentAccess.Core.Recovery == nil {
		return 0, refused(AdmissionInvalid)
	}
	control := currentControlOf(s)
	var changed uint8
	if g.Signing != nil && !signingGoalMatches(*g.Signing, control.NormalSigning, g, s.admission.store.Family) {
		changed |= contract.SuccessionChangeNormalSigner
	}
	if g.KMS != nil && !kmsGoalMatches(*g.KMS, control.AuthorityKMSBinding, s.admission.store.Family) {
		changed |= contract.SuccessionChangeAuthorityKEK
	}
	if changed == 0 {
		return 0, s.observed(Unchanged)
	}
	return changed, s.observed(ObservedCurrent)
}

func signingGoalMatches(g signingGoal, current contract.PublicSigningBinding, request authorityGoal, family contract.Family) bool {
	b := current.Binding
	return current.Role == contract.NormalSigningRole && g.Provider == family && current.Provider == g.Provider && current.SigningProfile == g.Profile && current.KeySelector == g.KeySelector && bytes.Equal(current.SPKI, g.SPKI) && current.Fingerprint == g.Fingerprint && b.PublicKey == g.PublicKey && b.Trust == g.Trust && b.Domain == request.Domain && b.Store == request.Store && b.Coordinate == request.Coordinate && b.Interpretation == request.Interpretation
}

func kmsGoalMatches(g kmsGoal, current contract.KMSBinding, family contract.Family) bool {
	return g.Provider == family && current.Provider == g.Provider && current.WrapProfile == g.WrapProfile && current.ProtectionClass == g.ProtectionClass && current.KeySelector == g.KeySelector && bytes.Equal(current.SPKI, g.SPKI) && current.Fingerprint == g.Fingerprint
}
