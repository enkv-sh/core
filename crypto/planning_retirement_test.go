package crypto

import (
	"enkv.sh/core/contract"
	"testing"
)

// full_only: false
func TestPlanningRetirementFeasibilityRequiresExactEqualRead(t *testing.T) {
	for _, condition := range []string{"equal", "changed", "missing-binding", "authority-target", "retained-input", "proposed-retired", "binding-transplant", "retirement-on-equality"} {
		t.Run(condition, func(t *testing.T) {
			a, route := planningFixture(t)
			retired := contract.RecipientBindingReference{RecipientID: consumerID("retirement feasibility recipient"), PublicBindingDigest: consumerID("retirement feasibility binding")}
			for _, target := range a.Targets {
				for _, wrap := range target.Current.Access.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject && wrap.SubjectID != a.Authority.SubjectID {
						retired = contract.RecipientBindingReference{RecipientID: wrap.SubjectID, PublicBindingDigest: wrap.PublicBindingDigest}
						break
					}
				}
			}
			a.Options.Purpose = contract.PlanningRetirementFeasibility
			a.Retirement = &contract.PlanningRetirementBinding{Recipient: retired}
			for i := range a.Targets {
				proposed := a.Targets[i].ProposedRecipients[:0]
				for _, id := range a.Targets[i].ProposedRecipients {
					if id != retired.RecipientID {
						proposed = append(proposed, id)
					}
				}
				a.Targets[i].ProposedRecipients = proposed
			}
			switch condition {
			case "changed":
				planningReseal(t, &a, 0, []byte("different retirement source"))
			case "missing-binding":
				a.Retirement = nil
			case "authority-target":
				a.Retirement.Recipient.RecipientID = a.Authority.SubjectID
			case "retained-input":
				planningRetain(&a)
			case "proposed-retired":
				a.Targets[0].ProposedRecipients = append(a.Targets[0].ProposedRecipients, retired.RecipientID)
			case "binding-transplant":
				a.Retirement.Recipient.PublicBindingDigest = consumerID("wrong retired binding")
			case "retirement-on-equality":
				a.Options.Purpose = contract.PlanningEquality
			}
			ctx := planningContext(t)
			owner, err := NewPlanningCustody(ctx, route, a)
			if condition != "equal" && condition != "changed" {
				if err == nil || owner != nil {
					if owner != nil {
						owner.Close()
					}
					t.Fatal("malformed feasibility admission opened private read")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			result := owner.Check(ctx)
			owner.Close()
			if condition == "equal" {
				if result.Code != contract.CryptoSuccess || !result.Complete {
					t.Fatal(result)
				}
				for _, row := range result.Rows {
					if row.Relation != contract.PlanningEqual {
						t.Fatal(row)
					}
				}
			} else if result.Code == contract.CryptoSuccess || result.Complete {
				t.Fatal("non-equal retirement source became a permit", result)
			}
		})
	}
}
