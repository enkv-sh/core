package format

import "enkv.sh/core/contract"

// RecipientReplacementIdentityPlan fixes the ordinary lifecycle successor and
// its one receipt request-identity hole. Stored readers accept no hole.
type RecipientReplacementIdentityPlan SuppliedApplyIdentityPlan

func DeriveRecipientReplacementIdentity(p RecipientReplacementIdentityPlan) (ID, error) {
	if len(p.Identity.Rows) != 0 {
		return ID{}, ErrFormat
	}
	recipientPages := 0
	for _, page := range p.Identity.Pages {
		if page.Kind == ValueEntryPageKind {
			return ID{}, ErrFormat
		}
		if page.Kind == RecipientKind {
			recipientPages++
		}
	}
	if recipientPages != 1 {
		return ID{}, ErrFormat
	}
	return deriveLifecycleReceiptIdentity(SuppliedApplyIdentityPlan(p), contract.OperationRotateRecipientKeyBinding, "recipient-replacement-transition-graph-v1")
}
