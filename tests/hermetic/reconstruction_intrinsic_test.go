package core

import (
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestIntrinsicSuccessionChecksSelectedFactsWithoutOrdinaryPredecessor(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, f.session, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, contract.NormalSigningRole)
	permit := admitAuthorityReplacement(t, f.session, actors.Keys, actors.After, contract.SuccessionReplaceRecoveryBasis, contract.NormalSigningRole, contract.SuccessionChangeRecoverySigner, actors.Source)
	candidate, result := f.session.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("changed recovery signer preparation", result)
	}
	_ = deliverSuccessionBasis(t, candidate)
	selected, result := f.session.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent || !selected.validSuccessionSelection() {
		t.Fatal("ordinary selected succession", result)
	}
	control, ok := selectedControlFrom(selected.root, &selected.recipients, selected.root.CurrentAccess.Core.AuthorityRecipientID)
	if !ok || !selectedHeadProofs(selected.head, control, nil) ||
		!intrinsicSuccessionSelection(selected.head, selected.root, control) {
		t.Fatal("authenticated successor facts require an ordinary predecessor pin")
	}
	withoutBasis := *selected
	withoutBasis.admission.current = nil
	if withoutBasis.validSuccessionSelection() {
		t.Fatal("selected bytes created ordinary predecessor admission")
	}
	for _, tc := range []struct {
		name string
		edit func(*format.Head, *format.Root)
	}{
		{"after control digest", func(h *format.Head, _ *format.Root) {
			p := *h.Succession
			p.Subject.AfterControlDigest[0] ^= 1
			h.Succession = &p
		}},
		{"after access root", func(h *format.Head, _ *format.Root) {
			p := *h.Succession
			p.Subject.AfterAccessRoot[0] ^= 1
			h.Succession = &p
		}},
		{"successor evidence", func(h *format.Head, _ *format.Root) {
			p := *h.Succession
			p.Subject.SuccessorEvidenceDigest[0] ^= 1
			h.Succession = &p
		}},
		{"missing changed signer acceptance", func(h *format.Head, _ *format.Root) {
			p := *h.Succession
			p.Acceptances = nil
			h.Succession = &p
		}},
		{"different selected access", func(_ *format.Head, root *format.Root) {
			root.CurrentAccess.AccessRoot[0] ^= 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, root := selected.head, selected.root
			tc.edit(&h, &root)
			if intrinsicSuccessionSelection(h, root, control) {
				t.Fatal("changed selected successor facts passed intrinsic checks")
			}
		})
	}
}
