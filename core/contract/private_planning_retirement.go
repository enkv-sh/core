package contract

// PlanningRetirementBinding fixes the exact live identity whose removal makes
// the captured original sealed input require a private equality check.
type PlanningRetirementBinding struct {
	Recipient RecipientBindingReference
}
