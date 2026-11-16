package core

import (
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationCurrentPredecessorWarningsPreserveFixedActionChain(t *testing.T) {
	for _, when := range []string{"between_actions", "before_close"} {
		t.Run(when, func(t *testing.T) {
			publicationCurrentPredecessorWarning(t, when)
		})
	}
}

func publicationCurrentPredecessorWarning(t *testing.T, when string) *fixture {
	t.Helper()
	f, input, oldPrivate := publicationEngineFixture(t)
	oldPrivate.evidence = contract.PublicationUnproved
	earlier := publicationEnginePlan(t, f, input, oldPrivate).execute(t.Context(), oldPrivate.callbacks(), publicationEngineCurrent(f))
	oldMarker := earlier.output.Entries[0].Actions[0].AttemptID
	if earlier.summary != contract.PublicationSummaryUnknown {
		t.Fatal("unrelated unknown setup", earlier.state)
	}
	publicationEngineReopen(t, f)
	entries := f.session.currentEntryInputs()
	target := publicationEngineTarget(entries[0].Name, "fresh-coordinate")
	target.target.PayloadEncoding = contract.OutputEncodingRaw
	selectOutputConfiguration(t, f, entries, &outputApplyInput{
		bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}},
		routes:   []outputApplyRoute{{defaultRoute: true, destinations: []string{"publication"}}},
	})
	f.admission.admission.publicationNamespaces = append(f.admission.admission.publicationNamespaces, publicationNamespace{
		domain: f.session.root.Domain, service: "controlled-provider", physical: "fresh-coordinate", premise: contract.Hash([]byte("independently qualified fresh namespace")),
	})
	f.session.admission.publicationNamespaces = f.admission.admission.publicationNamespaces
	p := newPublicationControlledPrivate()
	hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
		target.Capabilities &^= contract.OutputCapabilityCreateWithValue
		target.Capabilities |= contract.OutputCapabilityCreateEmpty
		target.CreateValueBounds = contract.OutputPayloadBounds{}
		target.Capabilities |= contract.OutputCapabilityCreateSetsPolicy
	})
	plan := publicationEnginePlan(t, f, input, p)
	if len(plan.targets) != 1 || len(plan.targets[0].actions) != 2 || plan.targets[0].actions[0] != contract.PublicationCreateEmpty || plan.targets[0].actions[1] != contract.PublicationWriteValue || plan.vector.DomainWideWarning != 0 {
		t.Fatal("fixed two-action setup")
	}
	fixed := plan.targets[0]
	ended := false
	endUnrelated := func() {
		if ended {
			t.Fatal("duplicate unrelated exit")
		}
		admin, result := openAdministrative(t.Context(), f.admission, f.store)
		if admin == nil {
			t.Fatal("exit current predecessor", result)
		}
		candidate, result := prepareTestEndSelectedWork(t, admin, t.Context(), oldMarker, f.trust)
		if candidate == nil {
			t.Fatal("exit prepare", result)
		}
		after, result := admin.selectCandidate(t.Context(), candidate)
		if after == nil {
			t.Fatal("exit select", result)
		}
		if after.root.WarningBits&(WarningPublicationOrderValue|WarningDiscardedExactEvidence) == 0 {
			t.Fatal("exit omitted permanent warning")
		}
		ended = true
	}
	sends := 0
	p.configureOwner = func(o *publicationControlledOwner) {
		o.onSend = func() {
			sends++
			if when == "before_close" && sends == 2 {
				endUnrelated()
			}
		}
		o.onRetire = func() {
			if when == "between_actions" && sends == 1 && !ended {
				endUnrelated()
			}
		}
	}
	got := plan.execute(t.Context(), p.callbacks(), publicationEngineCurrent(f))
	if !ended || got.summary != contract.PublicationSummaryComplete || got.output.DomainWideWarning != 1 || len(p.owners) != 2 || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 2 {
		t.Fatal("later result lost predecessor warning", got.state, got.output)
	}
	selected := publicationEngineReopen(t, f)
	if _, ok := selected.markers[oldMarker]; ok {
		t.Fatal("unrelated exit marker restored")
	}
	for i, row := range got.output.Entries[0].Actions {
		marker := selected.markers[row.AttemptID]
		owner := p.owners[i]
		if row.Disposition != contract.PublicationOutcomeAcknowledged || marker.State != contract.PublicationAcknowledged || owner.sent != 1 || owner.retired != 1 {
			t.Fatal("action completion", i, row)
		}
		if owner.input.Projection.TargetRowDigest != fixed.targetDigest || !reflect.DeepEqual(owner.input.Target, fixed.target) || marker.Projection != owner.input.Projection {
			t.Fatal("warning retargeted fixed action", i)
		}
		if i == 1 && (marker.Projection.ValueBasisDigest != fixed.valueBasisDigest || row.LateWriteRisk != 1 || marker.LateEffectRisk != 1 || selected.coordinates[fixed.coordinate].LateEffectRisk != 1) {
			t.Fatal("later action lost fixed value or current warning", row)
		}
	}
	if got.output.SnapshotID != plan.vector.SnapshotID || got.output.SelectionDigest != plan.vector.SelectionDigest {
		t.Fatal("warning replaced original selection")
	}
	return f
}
