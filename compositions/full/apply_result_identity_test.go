package compositionfull

import (
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyUnknownResultRequiresIdentityAndDomainWithoutReceipt(t *testing.T) {
	valid := suppliedApplyResultFixture(t)
	valid.Receipt = nil
	valid.Result = core.Result{Outcome: core.UnresolvedCommit, RequestedRevision: valid.Payload.RequestedRevisionID, CommitMayHaveOccurred: true}
	valid.Payload.ObservedRevisionID = contract.ID{}
	for name, render := range map[string]func(core.PublicApplyResult) ([]byte, error){"json": RenderApplyJSON, "human": RenderApplyHuman} {
		t.Run(name, func(t *testing.T) {
			if body, err := render(valid); err != nil || len(body) == 0 {
				t.Fatal("complete receipt-free unknown result refused", err)
			}
			for _, field := range []string{"identity", "domain"} {
				t.Run(field, func(t *testing.T) {
					invalid := valid
					if field == "identity" {
						invalid.RequestIdentity = contract.ID{}
					} else {
						invalid.DomainID = contract.ID{}
					}
					if _, err := render(invalid); err == nil {
						t.Fatal("receipt-free unknown result lost required identity")
					}
				})
			}
		})
	}
}
