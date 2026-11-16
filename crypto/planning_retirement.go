package crypto

import (
	"slices"

	"enkv.sh/core/contract"
)

func planningRetirementAdmission(a contract.PlanningAdmission) bool {
	if a.Retirement == nil || a.Options.Purpose != contract.PlanningRetirementFeasibility ||
		a.Retirement.Recipient.RecipientID.IsZero() || a.Retirement.Recipient.PublicBindingDigest.IsZero() ||
		a.Retirement.Recipient.RecipientID == a.Authority.SubjectID || len(a.Targets) == 0 {
		return false
	}
	retired := a.Retirement.Recipient
	for _, target := range a.Targets {
		if target.Input.Form != contract.PlanningSealed || !target.CurrentPresent || target.Current == nil ||
			target.CurrentValueSource != contract.Supplied || target.CurrentConfidentialityClass != contract.Secret ||
			slices.Contains(target.ProposedRecipients, retired.RecipientID) {
			return false
		}
		for _, id := range target.ProposedRecipients {
			if !slices.Contains(target.Current.Entry.Recipients, id) {
				return false
			}
		}
		for _, wrap := range target.Current.Access.Wraps {
			if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID == retired.RecipientID && wrap.PublicBindingDigest != retired.PublicBindingDigest {
				return false
			}
		}
	}
	return true
}

func planningRetirementRelation(relation contract.PlanningPrivateRelation, code contract.CryptoResultCode) (contract.PlanningPrivateRelation, contract.CryptoResultCode) {
	if code == contract.CryptoSuccess && relation != contract.PlanningEqual {
		return contract.PlanningFailed, contract.CryptoSourceAuthenticationFailed
	}
	return relation, code
}
