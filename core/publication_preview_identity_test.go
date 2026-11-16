package core

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func publicationPreviewUnitSelection(t *testing.T) (*StateSession, publicSelection, contract.PublicConfiguration) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	selected := publicSelection{complete: true, image: *state.selectedImage(), authorityID: state.root.CurrentAccess.Core.AuthorityRecipientID,
		basis: publicReadBasis{reader: selectedObjectReader{domain: state.root.Domain, descriptor: state.admission.store, source: state.store}}}
	input := publicConfigurationFixture(t)
	input.Authority.RecipientID = publicPresent(selected.authorityID)
	input.Recipients.Value[0].RecipientID = selected.authorityID
	return state, selected, input
}

func publicationPreviewUnitValidation(t *testing.T, ctx context.Context, input contract.PublicConfiguration) PublicConfigurationValidation {
	t.Helper()
	validator := NewPublicConfigurationValidator(func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
		return contract.OutputTarget{}, nil
	})
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	validated := validator.Validate(ctx, input)
	if !validated.Valid || !validated.Complete {
		t.Fatal("preview declaration fixture refused", validated.Diagnostics)
	}
	return validated
}

// full_only: false
func TestPublicationPreviewKeepsExactCoordinatePairs(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	state, selected, input := publicationPreviewUnitSelection(t)
	entry := publicFixtureEntry(input, "entry")
	entry.Class, entry.PlainValue = publicPresent(contract.Plain), publicPresent([]byte("value"))
	input.Entries = publicPresent([]contract.PublicEntry{entry})
	for _, row := range []struct{ destination, service, target string }{{"first", "a", "b\x00c"}, {"second", "a\x00b", "c"}} {
		target := publicFixtureTarget("entry", row.target)
		target.ServiceContractID = publicPresent(row.service)
		binding := publicFixtureBinding(row.destination, target)
		binding.Destination.Value.ServiceContractID = row.service
		input.OutputBindings.Value = append(input.OutputBindings.Value, binding)
	}
	publicFixtureRouteTargets(&input)
	desired := publicationPreviewUnitValidation(t, ctx, input)
	before := append([]byte(nil), state.body...)
	reader := ReaderEngine{}
	preview, _, failed := reader.projectPublicationPreview(ctx, &selected, desired, PublicConfigurationValidation{Valid: true, Complete: true})
	if failed.Outcome != 0 || !preview.Complete || preview.ReasonCode != 0 || len(preview.Entries) != 2 {
		t.Fatal("distinct exact coordinate pairs were merged", preview, failed)
	}
	sortPublicationPreview(preview)
	for i, want := range [][2]string{{"a", "b\x00c"}, {"a\x00b", "c"}} {
		row := preview.Entries[i]
		if row.ServiceContractID != want[0] || row.PhysicalTarget != want[1] || row.Origin != "proposed" || row.Basis != "unpublished" || row.ReasonCode != 0 || !slices.Equal(row.Actions, []uint8{contract.PublicationCreateEmpty, contract.PublicationUpdatePolicy, contract.PublicationWriteValue}) {
			t.Error("preview changed an exact pair or its action set", row)
		}
	}
	if !reflect.DeepEqual(state.body, before) {
		t.Error("passive preview changed selected state")
	}
	input.OutputBindings.Value[1].Destination.Value.ServiceContractID = "a"
	input.OutputBindings.Value[1].Targets.Value[0].ServiceContractID.Value = "a"
	input.OutputBindings.Value[1].Targets.Value[0].CanonicalTarget.Value = "b\x00c"
	validator := NewPublicConfigurationValidator(nil)
	duplicate := validator.Validate(ctx, input)
	if duplicate.Valid || duplicate.Complete || !slices.ContainsFunc(duplicate.Diagnostics, func(row contract.Diagnostic) bool {
		return row.Reason == contract.ReasonDuplicateKey && slices.Contains(row.Path, contract.FieldCanonicalTarget)
	}) {
		t.Fatal("an actual duplicate physical coordinate was admitted")
	}
}

// full_only: false
func TestPublicationPreviewUsesSharedEffectiveRoute(t *testing.T) {
	for _, condition := range []string{"inherited", "replacement", "explicit-empty"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			_, selected, input := publicationPreviewUnitSelection(t)
			authority, other := input.Authority.RecipientID.Value, input.Recipients.Value[1].RecipientID
			entry := publicFixtureEntry(input, "entry")
			entry.Class, entry.PlainValue = publicPresent(contract.Plain), publicPresent([]byte("value"))
			entry.Memberships = publicPresent([]contract.ID{authority, other})
			input.Entries = publicPresent([]contract.PublicEntry{entry})
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("authority", publicFixtureTarget("entry", "authority-slot")), publicFixtureBinding("other", publicFixtureTarget("entry", "other-slot"))})
			input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string{"authority"})}})
			if condition != "inherited" {
				destinations := []string{"other"}
				if condition == "explicit-empty" {
					destinations = []string{}
				}
				input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "entry"}, Destinations: publicPresent(destinations)})
			}
			desired := publicationPreviewUnitValidation(t, ctx, input)
			reader := ReaderEngine{}
			preview, _, failed := reader.projectPublicationPreview(ctx, &selected, desired, PublicConfigurationValidation{Valid: true, Complete: true})
			want := 1
			if condition == "explicit-empty" {
				want = 0
			}
			if failed.Outcome != 0 || !preview.Complete || preview.ReasonCode != 0 || len(preview.Entries) != want {
				t.Fatal("preview changed shared effective routing", condition, preview, failed)
			}
			destination := "authority"
			if condition == "replacement" {
				destination = "other"
			}
			if want == 1 && (preview.Entries[0].DestinationID == nil || *preview.Entries[0].DestinationID != destination || preview.Entries[0].PhysicalTarget != destination+"-slot") {
				t.Fatal("preview changed the shared exact target", preview.Entries)
			}
		})
	}
}
