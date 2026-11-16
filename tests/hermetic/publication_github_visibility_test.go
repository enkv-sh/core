package core

import (
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationGitHubVisibilityChangeUsesValueAndListChangeUsesPolicy(t *testing.T) {
	names := map[string]string{"all": "all", "private": "private", "selected": "selected"}
	type transition struct {
		prior, next         string
		changedRepositories bool
		action              uint8
	}
	var transitions []transition
	for _, prior := range []string{"all", "private", "selected"} {
		for _, next := range []string{"all", "private", "selected"} {
			action := uint8(contract.PublicationUpdatePolicy)
			if prior != next {
				action = contract.PublicationWriteValue
			}
			transitions = append(transitions, transition{prior: prior, next: next, action: action})
		}
	}
	transitions = append(transitions, transition{prior: "selected", next: "selected", changedRepositories: true, action: contract.PublicationUpdatePolicy})
	for _, change := range transitions {
		prior, next := change.prior, change.next
		name := names[prior] + "_to_" + names[next]
		if change.changedRepositories {
			name += "_changed_repositories"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, false, 1)
			entries := f.session.currentEntryInputs()
			subjects := []uint64{7, 11}
			output := func(mode string) *outputApplyInput {
				// Independent v1 policy bytes: schema u16, mode u8, count u16,
				// then sorted repository IDs as big-endian u64 values.
				var body []byte
				switch mode {
				case "all":
					body = []byte{0, 1, 1, 0, 0}
				case "private":
					body = []byte{0, 1, 2, 0, 0}
				case "selected":
					body = []byte{0, 1, 3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, byte(subjects[1])}
				default:
					t.Fatal("unknown fixture visibility")
				}
				policy := contract.OutputPolicy{ContractID: "github-actions/org-visibility/v1", Data: body}
				facts := outputFixtureTarget("github-actions", "orgs/owner/actions/secrets/TOKEN", "orgs/owner/actions/secrets/TOKEN", contract.OutputEncodingRaw, (contract.OutputCapabilityCreateWithValue|contract.OutputCapabilityWriteValue|contract.OutputCapabilityUpdatePolicy|contract.OutputCapabilityDeleteOwned|contract.OutputCapabilityDeleteReservedSlot)|contract.OutputCapabilityCreateSetsPolicy|contract.OutputCapabilityWriteSetsPolicy, policy)
				facts.CreateValueBounds.Maximum, facts.WriteValueBounds.Maximum = 48000, 48000
				target := outputApplyTarget{entryName: entries[0].Name, target: facts}

				return &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "github", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{defaultRoute: true, destinations: []string{"github"}}}}
			}
			selectOutputConfiguration(t, f, entries, output(prior))
			original := f.session.currentEntryInputs()[0]
			namespace := publicationNamespace{domain: f.session.root.Domain, service: "github-actions", physical: "orgs/owner/actions/secrets/TOKEN", premise: contract.Hash([]byte("independent namespace"))}
			f.admission.admission.publicationNamespaces = []publicationNamespace{namespace}
			f.session.admission.publicationNamespaces = []publicationNamespace{namespace}
			input := publicationInput{names: []string{entries[0].Name}, acting: f.session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
			p := newPublicationControlledPrivate()
			// The fake public plugin supplies the case's semantic decision. The
			// concrete GitHub profile's classification has its own plugin tests.
			p.selectPolicyAction = func(_ context.Context, in publicationPolicyActionInput) (uint8, error) {
				if prior == next && !change.changedRepositories {
					t.Fatal("exact no-op entered policy selector")
				}
				if in.DomainID != f.session.root.Domain || !in.HasPreviousPolicyDigest || in.PreviousPolicyDigest.IsZero() {
					t.Fatal("selector lost qualified previous policy", in)
				}
				return change.action, nil
			}

			callbacks := p.callbacks
			plan, result := f.session.planPublication(t.Context(), input, callbacks())
			if plan == nil {
				t.Fatal("birth plan", result)
			}
			created := plan.execute(t.Context(), callbacks(), publicationEngineCurrent(f))
			if created.summary != contract.PublicationSummaryComplete {
				t.Fatal("birth", created.state)
			}
			before := publicationEngineReopen(t, f)
			id := created.output.Entries[0].CoordinateID
			if change.changedRepositories {
				subjects = []uint64{7, 12}
			}
			if prior != next || change.changedRepositories {
				selectOutputConfiguration(t, f, entries, output(next))
			}
			if !reflect.DeepEqual(f.session.currentEntryInputs()[0], original) {
				t.Fatal("policy change modified canonical value")
			}
			ownerCount := len(p.owners)
			plan, result = f.session.planPublication(t.Context(), input, callbacks())
			if plan == nil {
				t.Fatal("visibility plan", result)
			}
			wantAction := change.action
			if prior != next || change.changedRepositories {
				if len(plan.targets) != 1 {
					t.Fatalf("policy transition selected %d targets; want one", len(plan.targets))
				}
				if !reflect.DeepEqual(plan.targets[0].actions, []uint8{wantAction}) {
					t.Fatalf("policy transition selected actions %v; want exactly %d", plan.targets[0].actions, wantAction)
				}
			}

			previewCtx, cancelPreview := context.WithTimeout(t.Context(), 30*time.Second)
			validator := NewPublicConfigurationValidator(f.session.admission.outputInterpreter)
			authority := f.session.root.CurrentAccess.Core.AuthorityRecipientID
			actual, failed := projectSelectedPublicConfiguration(previewCtx, f.session.selectedImage(), f.session.selectedObjectReader(), f.store.StoreConfiguration(), authority, validator)
			if failed.Outcome != 0 || !actual.Valid || !actual.Complete {
				cancelPreview()
				t.Fatal("current preview configuration", failed, actual.Diagnostics)
			}
			selected := publicSelection{complete: true, image: *f.session.selectedImage(), authorityID: authority, basis: publicReadBasis{reader: f.session.selectedObjectReader()}}
			reader := ReaderEngine{selectPolicyAction: callbacks().SelectPolicyAction}
			preview, refinements, failed := reader.projectPublicationPreview(previewCtx, &selected, actual, actual)
			cancelPreview()
			if failed.Outcome != 0 || !preview.Complete || len(preview.Entries) != 1 {
				t.Fatal("passive policy preview", preview, failed)
			}
			previewActions := preview.Entries[0].Actions
			if preview.Entries[0].Conditional {
				if len(refinements) != 1 {
					t.Fatal("secret comparison lost equal-value alternative", refinements)
				}
				previewActions = refinements[0].actions
			}
			if !reflect.DeepEqual(previewActions, plan.targets[0].actions) {
				t.Fatal("preview and execution chose different policy actions", previewActions, plan.targets[0].actions)
			}
			var stale *publicationPlan
			if prior == "all" && next == "selected" {
				stale = plan
				plan, result = f.session.planPublication(t.Context(), input, callbacks())
				if plan == nil {
					t.Fatal("concurrent policy plan", result)
				}
			}
			changed := plan.execute(t.Context(), callbacks(), publicationEngineCurrent(f))
			if prior == next && !change.changedRepositories {
				if changed.summary != contract.PublicationSummaryNoChange || len(p.owners) != ownerCount {
					t.Fatal("unchanged policy acquired a private owner", changed.state)
				}
				return
			}
			if changed.summary != contract.PublicationSummaryComplete || len(changed.output.Entries) != 1 || len(changed.output.Entries[0].Actions) != 1 {
				t.Fatal("visibility result", changed.state)
			}
			row := changed.output.Entries[0].Actions[0]
			if row.Action != wantAction || row.Disposition != contract.PublicationOutcomeAcknowledged || len(p.owners) != ownerCount+1 {
				t.Fatal("policy transition did not use exactly one selected send", row)
			}
			owner := p.owners[ownerCount]
			if owner.prepared != 1 || owner.armed != 1 || owner.sent != 1 || owner.retired != 1 {
				t.Fatal("policy owner lifetime", owner)
			}
			after := publicationEngineReopen(t, f)
			coordinate := after.coordinates[id]
			wantValueAttempt, wantValueIncarnation, wantValueOrdinal := before.coordinates[id].LastValueAckAttemptID, before.coordinates[id].LastValueAckIncarnationID, before.coordinates[id].LastValueAckOrdinal
			if wantAction == contract.PublicationWriteValue {
				wantValueAttempt, wantValueIncarnation, wantValueOrdinal = row.AttemptID, after.markers[row.AttemptID].PublicationIncarnationID, after.markers[row.AttemptID].AdmissionOrdinal
			}
			if coordinate.OwnedBirthAttemptID != before.coordinates[id].OwnedBirthAttemptID || coordinate.OwnedInstanceDigest != before.coordinates[id].OwnedInstanceDigest || coordinate.LastPolicyAckAttemptID != row.AttemptID || coordinate.LastPolicyAckIncarnationID != after.markers[row.AttemptID].PublicationIncarnationID || coordinate.LastPolicyAckOrdinal != after.markers[row.AttemptID].AdmissionOrdinal || coordinate.LastValueAckAttemptID != wantValueAttempt || coordinate.LastValueAckIncarnationID != wantValueIncarnation || coordinate.LastValueAckOrdinal != wantValueOrdinal || coordinate.LastValueDigest != before.coordinates[id].LastValueDigest || coordinate.LastPolicyDigest != after.markers[row.AttemptID].Projection.PolicyDigest {
				t.Fatal("selected ACK lost policy, value or birth")
			}
			if stale != nil {
				checks, owners := p.checks, len(p.owners)
				refused := stale.execute(t.Context(), callbacks(), publicationEngineCurrent(f))
				if refused.state.Reason != DifferentSelection || p.checks != checks || len(p.owners) != owners {
					t.Fatal("completed concurrent ACK did not refuse stale choice before private work", refused.state, p.checks, checks, len(p.owners), owners)
				}
			}
			owners := len(p.owners)
			plan, result = f.session.planPublication(t.Context(), input, callbacks())
			if plan == nil {
				t.Fatal("post-ACK plan", result)
			}
			noOp := plan.execute(t.Context(), callbacks(), publicationEngineCurrent(f))
			if noOp.summary != contract.PublicationSummaryNoChange || len(p.owners) != owners {
				t.Fatal("selected visibility ACK did not establish equality", noOp.state)
			}
		})
	}
}
