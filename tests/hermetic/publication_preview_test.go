package core

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationPreviewUsesSelectedObservationWithoutEffects(t *testing.T) {
	ctx, cancel, env, session, input, validator := comparisonOutputFixture(t)
	defer cancel()
	f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &session.admission}, session: session}
	hermeticPublicationTargetFacts(t, f, func(target *contract.OutputTarget) {
		target.Capabilities = (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)
		target.CreateValueBounds = contract.OutputPayloadBounds{}
	})
	session = f.session
	input.OutputBindings.Value[0].Destination.Value.Capabilities = (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)
	input.OutputBindings.Value[0].Targets.Value[0].Capabilities = publicPresent((contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot))
	input.OutputBindings.Value[0].Targets.Value[0].CreateValueBounds = publicPresent(contract.OutputPayloadBounds{})

	reader, _, _ := readerEngineFixture(t, env, session)
	reader.validator = validator
	public, private := env.Custody.Calls()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	result := reader.Compare(ctx, contract.Hash([]byte("passive configured output")), input, contract.ComparisonOptions{Publish: true})
	if result.StateResult != contract.ReaderSuccess || result.Verdict != contract.ComparisonMatch || result.Observation == nil || result.Publication == nil || !result.Publication.Complete || len(result.Publication.Entries) != 1 {
		t.Fatal("unchanged declaration lost unfinished publication", result)
	}
	row := result.Publication.Entries[0]
	if row.Origin != "both" || row.CoordinateID.IsZero() || row.BindingID.IsZero() || row.ServiceContractID != "aws" || row.PhysicalTarget != "slot" || row.EntryName == nil || *row.EntryName != "/\nα" || row.ConsumerLocator != nil || !reflect.DeepEqual(row.Actions, []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}) || row.Conditional || row.Basis != "unpublished" {
		t.Fatal("unpublished selected coordinate projection differs", row)
	}
	if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
		t.Fatal("passive publication reached private or mutation routes")
	}
	before := bytes.Clone(session.valueEntry(session.root.Names[0].Slot).ValueBytes)
	desired := ownPublicConfiguration(input)
	desired.OutputBindings = publicPresent([]contract.PublicOutputBinding(nil))
	desired.Routing = publicPresent([]contract.PublicRoutingRule(nil))
	removed := reader.Compare(ctx, contract.Hash([]byte("passive removed output")), desired, contract.ComparisonOptions{Publish: true})
	if removed.Publication == nil || !removed.Publication.Complete || len(removed.Publication.Entries) != 1 || removed.Publication.Entries[0].Origin != "observed" || removed.Publication.Entries[0].CoordinateID != row.CoordinateID || len(removed.Publication.Entries[0].Actions) != 0 || removed.Publication.Entries[0].Basis != "acknowledged-equal" {
		t.Fatal("removed never-published target disappeared or invented deletion", removed)
	}
	if !bytes.Equal(before, session.valueEntry(session.root.Names[0].Slot).ValueBytes) {
		t.Fatal("preview changed selected value")
	}
}

// full_only: false
func TestPublicationPreviewPrivateEqualityKeepsSafetyFacts(t *testing.T) {
	for _, basis := range []string{"secret-unchecked", "blocked", "warning", "capacity", "conflict"} {
		t.Run(basis, func(t *testing.T) {
			row := contract.PublicationPreviewEntry{Basis: basis, Conditional: true, Origin: "both", Actions: []uint8{contract.PublicationWriteValue}, BlockerIDs: []contract.ID{{1}}, RemoteValueMayRemain: true, LateWriteRisk: true}
			if basis == "capacity" {
				row.ReasonCode = uint8(CapacityExceeded)
			}
			if basis == "secret-unchecked" {
				row.BlockerIDs = nil
				row.RemoteValueMayRemain = false
				row.LateWriteRisk = false
			}
			preview := &contract.PublicationPreview{Complete: true, DomainWideWarning: basis != "secret-unchecked", Entries: []contract.PublicationPreviewEntry{row}}
			refinePublicationPreview(preview, []publicationPreviewRefinement{{index: 0, name: "secret", basis: "acknowledged-equal"}}, []contract.PlanningRelation{{Name: "secret", Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}})
			got := preview.Entries[0]
			if got.Conditional || got.RemoteValueMayRemain != row.RemoteValueMayRemain || got.LateWriteRisk != row.LateWriteRisk || !reflect.DeepEqual(got.BlockerIDs, row.BlockerIDs) || preview.DomainWideWarning != (basis != "secret-unchecked") {
				t.Fatal("private equality cleared safety facts", got)
			}
			if basis != "secret-unchecked" && (got.Basis != basis || !reflect.DeepEqual(got.Actions, row.Actions)) {
				t.Fatal("private equality changed independent blocker or warning", got)
			}
		})
	}

	for _, safety := range []string{"none", "domain-warning", "late-write", "blocked", "conflict"} {
		t.Run("equal-capacity/"+safety, func(t *testing.T) {
			row := contract.PublicationPreviewEntry{Basis: "secret-unchecked", Conditional: true, Origin: "both", Actions: []uint8{contract.PublicationWriteValue}, RemoteValueMayRemain: true}
			preview := &contract.PublicationPreview{Complete: true}
			wantBasis, wantReason := "capacity", uint8(CapacityExceeded)
			switch safety {
			case "domain-warning":
				preview.DomainWideWarning, row.Basis = true, "warning"
				wantBasis = "warning"
			case "late-write":
				row.LateWriteRisk, row.Basis = true, "warning"
				wantBasis = "warning"
			case "blocked":
				row.Basis, row.ReasonCode, row.BlockerIDs = "blocked", uint8(DifferentSelection), []contract.ID{{1}}
				wantBasis, wantReason = "blocked", uint8(DifferentSelection)
			case "conflict":
				row.Basis, row.ReasonCode = "conflict", uint8(InvalidIntent)
				wantBasis, wantReason = "conflict", uint8(InvalidIntent)
			}
			preview.Entries = []contract.PublicationPreviewEntry{row}
			refinePublicationPreview(preview, []publicationPreviewRefinement{{index: 0, name: "secret", actions: row.Actions, basis: "acknowledged-equal", equalReason: CapacityExceeded}}, []contract.PlanningRelation{{Name: "secret", Relation: contract.PlanningEqual, Code: contract.CryptoSuccess}})
			got := preview.Entries[0]
			if got.Conditional || got.Basis != wantBasis || got.ReasonCode != wantReason || got.RemoteValueMayRemain != row.RemoteValueMayRemain || got.LateWriteRisk != row.LateWriteRisk || !reflect.DeepEqual(got.BlockerIDs, row.BlockerIDs) || !reflect.DeepEqual(got.Actions, row.Actions) || preview.DomainWideWarning != (safety == "domain-warning") {
				t.Fatal("checked equal size lost capacity or selected safety facts", got)
			}
		})
	}
}

// full_only: false
func TestPublicationPreviewRetainsSelectedDeletionAndBlockers(t *testing.T) {
	for _, mode := range []string{"acknowledged-active", "unknown-active", "acknowledged-retired", "unknown-retired", "delete-acknowledged"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel, env, session, input, validator := comparisonOutputFixture(t)
			defer cancel()
			controlled := newPublicationControlledPrivate()
			factsFixture := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: OpenContext{admission: &session.admission}, session: session}
			hermeticPublicationTargetFacts(t, factsFixture, func(target *contract.OutputTarget) {
				target.Capabilities = contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy
			})
			session = factsFixture.session
			input.OutputBindings.Value[0].Destination.Value.Capabilities = contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy
			input.OutputBindings.Value[0].Targets.Value[0].Capabilities = publicPresent(contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy)

			if mode == "unknown-active" || mode == "unknown-retired" {
				controlled.evidence = contract.PublicationUnproved
			}
			f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), session: session}
			f.session.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "aws", physical: "slot", premise: contract.Hash([]byte("managed namespace"))}}
			f.admission = OpenContext{admission: &f.session.admission}
			publication := publicationInput{names: []string{"/\nα"}, acting: session.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
			first := publicationEnginePlan(t, f, publication, controlled).execute(ctx, controlled.callbacks(), publicationEngineCurrent(f))
			publicationEngineReopen(t, f)
			coordinate := first.output.Entries[0].CoordinateID
			attempt := first.output.Entries[0].Actions[0].AttemptID
			if mode == "acknowledged-retired" || mode == "unknown-retired" || mode == "delete-acknowledged" {
				selectOutputConfiguration(t, f, f.session.currentEntryInputs(), &outputApplyInput{})
				publicationEngineReopen(t, f)
				input.OutputBindings = publicPresent([]contract.PublicOutputBinding(nil))
				input.Routing = publicPresent([]contract.PublicRoutingRule(nil))
			}
			if mode == "delete-acknowledged" {
				publication.names = nil
				publication.deletes = []contract.ID{coordinate}
				publicationEnginePlan(t, f, publication, controlled).execute(ctx, controlled.callbacks(), publicationEngineCurrent(f))
				publicationEngineReopen(t, f)
			}
			reader, _, _ := readerEngineFixture(t, env, f.session)
			reader.validator = validator
			public, private := env.Custody.Calls()
			creates, cas, signs, owners := f.store.creates, f.store.cas, f.trust.signs, len(controlled.owners)
			result := reader.Compare(ctx, contract.Hash([]byte(mode)), input, contract.ComparisonOptions{Publish: true})
			if result.Publication == nil || !result.Publication.Complete || len(result.Publication.Entries) != 1 {
				t.Fatal("selected publication discovery incomplete", result)
			}
			row := result.Publication.Entries[0]
			if row.CoordinateID != coordinate || row.BindingID.IsZero() || row.PhysicalTarget != "slot" || row.TargetContractID != "fixture/target/v1" {
				t.Fatal("selected target identity changed", row)
			}
			switch mode {
			case "acknowledged-active":
				if row.Basis != "acknowledged-equal" || len(row.Actions) != 0 || row.ConsumerLocator == nil {
					t.Fatal("acknowledged equality lost", row)
				}
			case "unknown-active":
				if row.Basis != "blocked" || !reflect.DeepEqual(row.BlockerIDs, []contract.ID{attempt}) || len(row.Actions) != 0 {
					t.Fatal("current blocker lost", row)
				}
			case "acknowledged-retired":
				if row.Origin != "observed" || row.Basis != "retained-deletion" || !reflect.DeepEqual(row.Actions, []uint8{contract.PublicationDeleteOwned}) {
					t.Fatal("owned deletion disappeared with source destination", row)
				}
			case "unknown-retired":
				if row.Origin != "observed" || row.Basis != "blocked" || !reflect.DeepEqual(row.BlockerIDs, []contract.ID{attempt}) || !reflect.DeepEqual(row.Actions, []uint8{contract.PublicationDeleteReservedSlot}) {
					t.Fatal("uncertain deletion lost exact retained blocker", row)
				}
			case "delete-acknowledged":
				if len(row.Actions) != 0 || !row.RemoteValueMayRemain || row.Basis != "warning" {
					t.Fatal("exact delete acknowledgment was repeated or cleared safety facts", row)
				}
			}
			if p, k := env.Custody.Calls(); p != public || k != private || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || len(controlled.owners) != owners {
				t.Fatal("preview acquired effect or private authority")
			}
		})
	}
}
