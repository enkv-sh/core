package core

import (
	"bytes"
	"context"
	"reflect"
	"runtime"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestPublicationCandidateConstructionKeepsPredecessorProofFacts(t *testing.T) {
	t.Run("output-only admission", func(t *testing.T) {
		s, _ := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
		// The read-only image fixture has no mutation admission. Match the
		// existing observation fixture's finite composition admission here.
		s.admission.composition = generatedVectorID(97)
		s.admission.expires = time.Now().Add(time.Hour)
		if !s.admission.valid(s.store) {
			t.Fatal("publication fixture has no valid mutation admission")
		}
		selected := *s.valueEntry(0)
		selected.ValueBytes = bytes.Clone(selected.ValueBytes)
		selected.Recipients = slices.Clone(selected.Recipients)
		before := s.root.OutputConfiguration
		configuration, result := s.currentOutputConfigurationForApply(t.Context())
		if result.Outcome != 0 {
			t.Fatal("selected publication output baseline", result)
		}
		for _, encoding := range []uint8{contract.OutputEncodingRaw, contract.OutputEncodingBase64} {
			input := []ApplyEntryInput{{Name: selected.Name, Recipients: slices.Clone(selected.Recipients), ValueSource: selected.ValueSource,
				ConfidentialityClass: selected.ConfidentialityClass, InputEncoding: selected.InputEncoding, OutputEncoding: encoding, InputBytes: bytes.Clone(selected.ValueBytes)}}
			output, err := s.outputSourceInput(configuration, input)
			if err != nil || len(output.bindings) != 1 || len(output.bindings[0].targets) != 1 {
				t.Fatal("selected publication source baseline", err)
			}
			output.bindings[0].targets[0].target.PayloadEncoding = encoding
			comparison, result := s.compareEntryInputsForMutation(t.Context(), input, currentApplyRecipients(s.registry()), nil, nil, nil)
			changed := encoding != selected.OutputEncoding
			if comparison == nil || result.Outcome != ObservedCurrent || len(comparison.changed)+len(comparison.added)+len(comparison.removed)+len(comparison.recipientChanges) != 0 || comparison.entryConfigurationChanged != changed {
				t.Fatal("publication entry admission lost unchanged material", encoding, result)
			}
			if result := s.compareOutput(t.Context(), comparison, output); result.Outcome != 0 || comparison.outputChanged != changed {
				t.Fatal("publication output-only admission", encoding, result)
			}
			if !reflect.DeepEqual(*s.valueEntry(0), selected) || s.root.OutputConfiguration != before {
				t.Fatal("output admission changed selected material or output configuration", encoding)
			}
		}
	})
	for _, condition := range []string{"complete", "refused", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			before, _ := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
			original := *before
			next := *before
			next.root.Transition = publicationRelationID(96)
			if err := before.bindPreservedOutputConfiguration(&next); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if condition == "cancelled" {
				cancel()
			}
			if condition == "refused" {
				next.pages[0] = nil
			}
			err := before.bindPreservedPublication(ctx, &next)
			if (err == nil) != (condition == "complete") || !reflect.DeepEqual(*before, original) || !before.selectedOutputComplete() {
				t.Fatal("candidate construction changed or disabled its predecessor", err)
			}
			if proof, result, err := validateSelectedPublicationConfiguration(t.Context(), before.selectedImage(), nil); err != nil || result.Outcome != 0 || proof == nil {
				t.Fatal("predecessor was unusable after candidate construction", result, err)
			}
		})
	}
}

func publicationConfiguredImage(t *testing.T, binding, currentEntry, activeBinding contract.ID) (*StateSession, selectedImage) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	coordinate.ActiveBindingIncarnationID = activeBinding
	entry := contract.ValueEntry{Name: "plain", Incarnation: currentEntry,
		ValueState: publicationRelationID(80), OriginSnapshot: state.root.Snapshot,
		OriginTransition: state.root.Transition, ValueSource: contract.Supplied,
		ConfidentialityClass: contract.Plain, Recipients: []contract.ID{state.admission.recipient},
		ValueBytes: []byte("v"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("v"))), RetainedLength: uint32(len([]byte("v")))}
	valuePage := format.ValueEntryPage{Domain: state.root.Domain, Object: publicationRelationID(81)}
	valuePage.Slots[0] = &entry
	valueBody, err := format.EncodeValueEntryPage(valuePage)
	if err != nil {
		t.Fatal(err)
	}
	valueRef, err := format.Reference(format.ValueEntryPageKind, state.root.Domain, valuePage.Object, 0, valueBody)
	if err != nil {
		t.Fatal(err)
	}
	state.pages[0], state.root.ValueEntryPages[0] = &valuePage, &valueRef
	state.root.Names = []format.NameEntry{{Name: entry.Name, Slot: 0}}
	state.root.ValueEntryCount, state.root.MembershipCount, state.root.RawBytes = 1, 1, 1
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: state.root.Domain,
		Bindings: []contract.OutputBinding{{DestinationID: "destination", IncarnationID: binding,
			Targets: []contract.OutputTarget{{EntryIncarnationID: entry.Incarnation,
				ServiceContractID: coordinate.ServiceContractID, CanonicalTarget: coordinate.CanonicalTarget,
				ConsumerLocator: "locator", TargetContractID: "profile",
				TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536},
				Policy: contract.OutputPolicy{}}}}}}
	for i := range configuration.Bindings {
		configuration.Bindings[i].Destination = contract.OutputDestination{ConfigContractID: "2", ServiceContractID: "provider", CanonicalSettings: []byte("{}"), Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), Policy: contract.OutputPolicy{}}
	}
	configuration.DefaultDestinations = []string{"destination"}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(state.root.Domain, image)
	if err != nil || len(parts) != 1 {
		t.Fatalf("split output configuration parts=%d err=%v", len(parts), err)
	}
	body, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.OutputConfigurationSliceID(state.root.Domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	publicationFixtureReplaceConfiguration(t, state, contract.SupportRecordView{Kind: contract.OutputConfigurationSliceSupportKind,
		RecordID: id, Body: body})
	state.root.OutputConfiguration = descriptor
	state.supportFacts = nil
	state.publicationProof = nil
	rows := publicationRelationRows(t, coordinate, marker)
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain,
		Object: publicationRelationID(20), Index: 1,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	generatedRefreshSupport(t, state)
	state.recountChildren()
	rootBody, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal(err)
	}
	state.head.Core.Root, err = format.Reference(format.RootKind, state.root.Domain, state.root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	if !state.indexSelectedMaterials() {
		t.Fatal("configured selected material index invalid")
	}
	selected := *state.selectedImage()
	if !state.selectedOutputComplete() {
		t.Fatal("configured output image incomplete")
	}
	if _, err := selectedPublicationRelation(&selected); err != nil {
		t.Fatalf("configured publication relation invalid: %v", err)
	}
	return state, selected
}

func publicationEmptyConfigurationImage(t *testing.T, retired bool) (*StateSession, selectedImage) {
	t.Helper()
	state := generatedEmptyPredecessor(t)
	_, coordinate, marker, _ := publicationRelationFixtureForDomain(t, state.root.Domain)
	if retired {
		coordinate.BindingState = contract.PublicationBindingRetired
		coordinate.ActiveBindingIncarnationID = contract.ID{}
	}
	rows := publicationRelationRows(t, coordinate, marker)
	state.support = append(state.support, format.RequiredSupportPageView{Domain: state.root.Domain,
		Object: publicationRelationID(20), Index: 1,
		Records: []contract.SupportRecordView{contract.SupportRecordView(rows[0]), contract.SupportRecordView(rows[1])}})
	generatedRefreshSupport(t, state)
	state.recountChildren()
	if !state.indexSelectedMaterials() {
		t.Fatal("selected material index invalid before publication relation")
	}
	image := *state.selectedImage()
	if !state.selectedOutputComplete() {
		t.Fatal("explicit empty output configuration is not selected")
	}
	if _, err := selectedPublicationRelation(&image); err != nil {
		t.Fatalf("publication row/index relation invalid before configuration check: %v", err)
	}
	return state, image
}

func publicationRoutedMemberImage(t *testing.T, member bool) (*StateSession, selectedImage) {
	t.Helper()
	bindingID, entryID := publicationRelationID(2), publicationRelationID(3)
	state, _ := publicationConfiguredImage(t, bindingID, entryID, bindingID)
	domain := state.root.Domain
	otherID := publicationRelationID(101)
	other := *state.recipients[0].Slots[0]
	other.RecipientID = otherID
	currentBinding := *other.CurrentBinding
	currentBinding.BindingID = publicationRelationID(102)
	other.CurrentBinding = &currentBinding
	state.recipients[0].Slots[1] = &other
	recipientBody, err := format.EncodeRecipientPage(*state.recipients[0])
	if err != nil {
		t.Fatal(err)
	}
	recipientRef, err := format.Reference(format.RecipientKind, domain, state.recipients[0].Object, 0, recipientBody)
	if err != nil {
		t.Fatal(err)
	}
	state.root.Recipients[0], state.root.RecipientCount = &recipientRef, 2
	state.root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{
		DomainID: domain, Refs: []contract.Ref{recipientRef}})
	if err != nil {
		t.Fatal(err)
	}
	state.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(state.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	if member {
		state.pages[0].Slots[0].Recipients = []contract.ID{state.admission.recipient, otherID}
		state.root.MembershipCount = 2
		valueBody, err := format.EncodeValueEntryPage(*state.pages[0])
		if err != nil {
			t.Fatal(err)
		}
		valueRef, err := format.Reference(format.ValueEntryPageKind, domain, state.pages[0].Object, 0, valueBody)
		if err != nil {
			t.Fatal(err)
		}
		state.root.ValueEntryPages[0] = &valueRef
	}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain,
		Bindings: []contract.OutputBinding{{DestinationID: "destination", IncarnationID: bindingID,
			Targets: []contract.OutputTarget{{EntryIncarnationID: entryID, ServiceContractID: "provider", CanonicalTarget: "account/slot",
				ConsumerLocator: "locator", TargetContractID: "profile", TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536},
				Policy: contract.OutputPolicy{}}}}},
		Routes: []contract.OutputRoute{{EntryIncarnationID: entryID, Destinations: []string{"destination"}}}}
	for i := range configuration.Bindings {
		configuration.Bindings[i].Destination = contract.OutputDestination{ConfigContractID: "2", ServiceContractID: "provider", CanonicalSettings: []byte("{}"), Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), Policy: contract.OutputPolicy{}}
	}
	configurationImage, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, configurationImage)
	if err != nil || len(parts) != 1 {
		t.Fatal("routed output configuration", err)
	}
	outputBody, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	outputID, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	publicationFixtureReplaceConfiguration(t, state, contract.SupportRecordView{Kind: contract.OutputConfigurationSliceSupportKind,
		RecordID: outputID, Body: outputBody})
	state.root.OutputConfiguration = descriptor
	generatedRefreshSupport(t, state)
	state.recountChildren()
	rootBody, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal(err)
	}
	state.head.Core.Root, err = format.Reference(format.RootKind, domain, state.root.Snapshot, 0, rootBody)
	if err != nil || !state.indexSelectedMaterials() {
		t.Fatal("routed selected material index", err)
	}
	image := *state.selectedImage()
	if _, err := selectedPublicationRelation(&image); err != nil {
		t.Fatalf("routed row/index relation: %v", err)
	}
	return state, image
}

// full_only: false
func TestCompleteSelectedPublicationRoutingMembership(t *testing.T) {
	for _, member := range []bool{false, true} {
		name := "nonmember"
		if member {
			name = "member"
		}
		t.Run(name, func(t *testing.T) {
			state, image := publicationRoutedMemberImage(t, member)
			if !publicationCompleteFixtureAccepted(t, &image) {
				t.Fatal("shared entry route depends on recipient membership")
			}
			other := publicationRelationID(101)
			selection, _, err := state.publicationConsumer(0, other)
			if (err == nil && selection != nil) != member {
				t.Fatalf("publication consumer membership allowed=%v want=%v", err == nil, member)
			}
			if selection, _, err := state.publicationConsumer(0, state.admission.recipient); err != nil || selection == nil {
				t.Fatal("authorized authority consumer refused", err)
			}
		})
	}
}

// full_only: false
func TestSelectedPublicationRouteIsIndependentOfRetiredRecipient(t *testing.T) {
	state, image := publicationRoutedMemberImage(t, true)
	page := *image.recipients[0]
	retired := *page.Slots[1]
	retired.Status, retired.CurrentBinding = contract.RetiredRecipient, nil
	page.Slots[1] = &retired
	image.recipients[0], state.recipients[0] = &page, &page
	if !publicationCompleteFixtureAccepted(t, &image) {
		t.Fatal("retired recipient changed the shared entry route")
	}
	if selection, _, err := state.publicationConsumer(0, retired.RecipientID); err == nil || selection != nil {
		t.Fatal("retired recipient retained publication consumer access")
	}
}

func publicationDefaultRouteImage(t *testing.T, override bool) (*StateSession, selectedImage) {
	t.Helper()
	bindingA, entryA := publicationRelationID(2), publicationRelationID(3)
	state, _ := publicationConfiguredImage(t, bindingA, entryA, bindingA)
	domain := state.root.Domain
	bindingB, entryB := publicationRelationID(110), publicationRelationID(111)
	second := contract.ValueEntry{Name: "second", Incarnation: entryB, ValueState: publicationRelationID(112),
		OriginSnapshot: state.root.Snapshot, OriginTransition: state.root.Transition, ValueSource: contract.Supplied,
		ConfidentialityClass: contract.Plain, Recipients: []contract.ID{state.admission.recipient}, ValueBytes: []byte("w"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("w"))), RetainedLength: uint32(len([]byte("w")))}
	state.pages[0].Slots[1] = &second
	valueBody, err := format.EncodeValueEntryPage(*state.pages[0])
	if err != nil {
		t.Fatal(err)
	}
	valueRef, err := format.Reference(format.ValueEntryPageKind, domain, state.pages[0].Object, 0, valueBody)
	if err != nil {
		t.Fatal(err)
	}
	state.root.ValueEntryPages[0] = &valueRef
	state.root.Names = []format.NameEntry{{Name: "plain", Slot: 0}, {Name: "second", Slot: 1}}
	state.root.ValueEntryCount, state.root.MembershipCount, state.root.RawBytes = 2, 2, 2
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain,
		Bindings: []contract.OutputBinding{{DestinationID: "a", IncarnationID: bindingA, Targets: []contract.OutputTarget{{EntryIncarnationID: entryA,
			ServiceContractID: "provider", CanonicalTarget: "account/slot", ConsumerLocator: "locator", TargetContractID: "profile", TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}}}},
		DefaultDestinations: []string{"a"}}
	if override {
		coordinateB, err := contract.PublicationCoordinateID(domain, "provider", "account/slot-b")
		if err != nil {
			t.Fatal(err)
		}
		coordinateBody, err := contract.EncodePublicationCoordinate(contract.PublicationCoordinate{Schema: 5,
			DomainID: domain, CoordinateID: coordinateB, CurrentPublicationIncarnationID: publicationRelationID(115), ServiceContractID: "provider", CanonicalTarget: "account/slot-b",
			BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerNone,
			ActiveBindingIncarnationID: bindingB, LastBindingIncarnationID: bindingB, LastEntryIncarnationID: entryB})
		if err != nil {
			t.Fatal(err)
		}
		coordinateA, err := contract.PublicationCoordinateID(domain, "provider", "account/slot")
		if err != nil {
			t.Fatal(err)
		}
		coordinatePage := -1
		for i, page := range state.support {
			for _, row := range page.Records {
				if row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == coordinateA {
					if coordinatePage >= 0 {
						t.Fatal("duplicate selected first coordinate")
					}
					coordinatePage = i
				}
			}
		}
		if coordinatePage < 0 {
			t.Fatal("selected first coordinate is missing")
		}
		state.support[coordinatePage].Records = append(slices.Clone(state.support[coordinatePage].Records),
			contract.SupportRecordView{Kind: contract.PublicationCoordinateSupportKind, RecordID: coordinateB, Body: coordinateBody})
		configuration.Bindings = append(configuration.Bindings, contract.OutputBinding{DestinationID: "b", IncarnationID: bindingB,
			Targets: []contract.OutputTarget{{EntryIncarnationID: entryB, ServiceContractID: "provider", CanonicalTarget: "account/slot-b",
				ConsumerLocator: "locator-b", TargetContractID: "profile", TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536},
				Policy: contract.OutputPolicy{}}}})
		entryRoute := contract.OutputRoute{EntryIncarnationID: entryB, Destinations: []string{"b"}}
		configuration.Routes = append(configuration.Routes, entryRoute)
	}
	for i := range configuration.Bindings {
		configuration.Bindings[i].Destination = contract.OutputDestination{ConfigContractID: "2", ServiceContractID: "provider", CanonicalSettings: []byte("{}"), Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), Policy: contract.OutputPolicy{}}
	}
	configurationImage, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, configurationImage)
	if err != nil || len(parts) != 1 {
		t.Fatal("default output configuration", err)
	}
	outputBody, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	outputID, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	publicationFixtureReplaceConfiguration(t, state, contract.SupportRecordView{Kind: contract.OutputConfigurationSliceSupportKind,
		RecordID: outputID, Body: outputBody})
	state.root.OutputConfiguration = descriptor
	generatedRefreshSupport(t, state)
	state.recountChildren()
	rootBody, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal(err)
	}
	state.head.Core.Root, err = format.Reference(format.RootKind, domain, state.root.Snapshot, 0, rootBody)
	if err != nil || !state.indexSelectedMaterials() {
		t.Fatal("default selected material index", err)
	}
	image := *state.selectedImage()
	if _, err := selectedPublicationRelation(&image); err != nil {
		t.Fatalf("default row/index relation: %v", err)
	}
	return state, image
}

// full_only: false
func TestCompleteSelectedPublicationDefaultTargets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		override bool
		allowed  bool
	}{{name: "default_missing_entry_target", allowed: false},
		{name: "entry_override_replaces_default", override: true, allowed: true}} {
		t.Run(tc.name, func(t *testing.T) {
			_, image := publicationDefaultRouteImage(t, tc.override)
			if accepted := publicationCompleteFixtureAccepted(t, &image); accepted != tc.allowed {
				t.Fatalf("default target relation accepted=%v want=%v", accepted, tc.allowed)
			}
			if !tc.allowed {
				return
			}
			checks, err := newSelectedPublicationChecks(&image)
			if err != nil {
				t.Fatal(err)
			}
			if err := publicationFixtureVisit(&image, checks.visitor(&image)); err != nil {
				t.Fatal(err)
			}
			if checks.routes[contract.ID{}] != checks.destinations["a"] || checks.routes[publicationRelationID(111)] != checks.destinations["b"] {
				t.Fatal("shared default and entry replacement did not remain separate")
			}
		})
	}
}

// full_only: false
func TestCompleteSelectedPublicationSharedRouteTargetsMatchSelectedDestinations(t *testing.T) {
	firstBinding, entryID := publicationRelationID(2), publicationRelationID(3)
	state, _ := publicationRoutedMemberImage(t, true)
	domain := state.root.Domain
	_, firstCoordinate, _, _ := publicationRelationFixtureForDomain(t, domain)
	secondBinding := publicationRelationID(110)
	secondSlot := firstCoordinate.CanonicalTarget + "-second"
	secondID, err := contract.PublicationCoordinateID(domain, firstCoordinate.ServiceContractID, secondSlot)
	if err != nil {
		t.Fatal(err)
	}
	secondCoordinate := contract.PublicationCoordinate{Schema: 5, DomainID: domain,
		CoordinateID: secondID, CurrentPublicationIncarnationID: publicationRelationID(116), ServiceContractID: firstCoordinate.ServiceContractID, CanonicalTarget: secondSlot,
		BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerNone,
		ActiveBindingIncarnationID: secondBinding, LastBindingIncarnationID: secondBinding,
		LastEntryIncarnationID: entryID}
	secondBody, err := contract.EncodePublicationCoordinate(secondCoordinate)
	if err != nil {
		t.Fatal(err)
	}
	coordinatePage := -1
	for i, page := range state.support {
		for _, row := range page.Records {
			if row.Kind == contract.PublicationCoordinateSupportKind && row.RecordID == firstCoordinate.CoordinateID {
				coordinatePage = i
			}
		}
	}
	if coordinatePage < 0 {
		t.Fatal("selected coordinate page missing")
	}
	state.support[coordinatePage].Records = append(slices.Clone(state.support[coordinatePage].Records),
		contract.SupportRecordView{Kind: contract.PublicationCoordinateSupportKind, RecordID: secondID, Body: secondBody})
	target := func(slot string) contract.OutputTarget {
		return contract.OutputTarget{EntryIncarnationID: entryID, ServiceContractID: firstCoordinate.ServiceContractID,
			CanonicalTarget: slot, ConsumerLocator: "locator", TargetContractID: "profile",
			TargetData: []byte("single"), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: contract.OutputPolicy{}}
	}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: domain,
		Bindings: []contract.OutputBinding{
			{DestinationID: "a", IncarnationID: firstBinding, Targets: []contract.OutputTarget{target(firstCoordinate.CanonicalTarget)}},
			{DestinationID: "b", IncarnationID: secondBinding, Targets: []contract.OutputTarget{target(secondSlot)}},
		},
		DefaultDestinations: []string{"a"},
		Routes:              []contract.OutputRoute{{EntryIncarnationID: entryID, Destinations: []string{"a", "b"}}}}
	for i := range configuration.Bindings {
		configuration.Bindings[i].Destination = contract.OutputDestination{ConfigContractID: "2", ServiceContractID: "provider", CanonicalSettings: []byte("{}"), Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityWriteValue | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot), Policy: contract.OutputPolicy{}}
	}
	configurationImage, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(domain, configurationImage)
	if err != nil || len(parts) != 1 {
		t.Fatalf("two-destination configuration: parts=%d err=%v", len(parts), err)
	}
	outputBody, err := contract.EncodeOutputConfigurationSlice(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	outputID, err := contract.OutputConfigurationSliceID(domain, descriptor.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	outputPage, outputRow := -1, -1
	for i, page := range state.support {
		for j, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				outputPage, outputRow = i, j
			}
		}
	}
	if outputPage < 0 {
		t.Fatal("selected configuration slice missing")
	}
	state.support[outputPage].Records[outputRow] = contract.SupportRecordView{
		Kind: contract.OutputConfigurationSliceSupportKind, RecordID: outputID, Body: outputBody}
	state.root.OutputConfiguration = descriptor
	generatedRefreshSupport(t, state)
	state.recountChildren()
	rootBody, err := format.EncodeRoot(state.root)
	if err != nil {
		t.Fatal(err)
	}
	state.head.Core.Root, err = format.Reference(format.RootKind, domain, state.root.Snapshot, 0, rootBody)
	if err != nil || !state.indexSelectedMaterials() {
		t.Fatalf("two-destination selected index: %v", err)
	}
	image := *state.selectedImage()
	if accepted := publicationCompleteFixtureAccepted(t, &image); !accepted {
		t.Fatal("valid two-destination selected route was refused")
	}
	checks, err := newSelectedPublicationChecks(&image)
	if err != nil {
		t.Fatal(err)
	}
	if err := publicationFixtureVisit(&image, checks.visitor(&image)); err != nil {
		t.Fatal(err)
	}
	mask, present := checks.routes[entryID]
	if !present {
		t.Fatal("shared entry route missing")
	}
	var resolved []string
	for name, bit := range checks.destinations {
		if mask&bit != 0 {
			resolved = append(resolved, name)
		}
	}
	slices.Sort(resolved)
	if !slices.Equal(resolved, []string{"a", "b"}) {
		t.Fatalf("shared route lost a selected destination: %v", resolved)
	}
}

// full_only: false
func TestCompleteSelectedPublicationRejectsActiveCoordinateAbsentFromConfiguration(t *testing.T) {
	_, image := publicationEmptyConfigurationImage(t, false)
	if publicationCompleteFixtureAccepted(t, &image) {
		t.Fatal("active publication coordinate absent from authenticated configuration was accepted")
	}
}

// full_only: false
func TestCompleteSelectedPublicationAcceptsRetiredCoordinateAbsentFromConfiguration(t *testing.T) {
	_, image := publicationEmptyConfigurationImage(t, true)
	if !publicationCompleteFixtureAccepted(t, &image) {
		t.Fatal("valid retained retired coordinate was refused with no current target")
	}
}

// full_only: false
func TestCompleteSelectedPublicationBindsActiveConfiguration(t *testing.T) {
	state, image := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
	if !publicationCompleteFixtureAccepted(t, &image) || !image.publicationProof.validFor(&image) {
		t.Fatal("valid complete proof refused")
	}
	changed := image
	changed.root.Transition = publicationRelationID(96)
	if image.publicationProof.validFor(&changed) {
		t.Fatal("proof survived changed Root")
	}
	changed = image
	changed.root.RequiredSupport = slices.Clone(image.root.RequiredSupport)
	changed.root.RequiredSupport[0].Object = publicationRelationID(97)
	if image.publicationProof.validFor(&changed) {
		t.Fatal("proof survived changed selected Ref")
	}
	state.pages[0], state.root.ValueEntryPages[0] = nil, nil
	state.root.Names = nil
	state.root.ValueEntryCount, state.root.MembershipCount, state.root.RawBytes = 0, 0, 0
	state.recountChildren()
	removed := *state.selectedImage()
	if publicationCompleteFixtureAccepted(t, &removed) {
		t.Fatal("dangling target accepted after removing its entry")
	}
}

// full_only: false
func TestCompleteSelectedPublicationRejectsWrongActiveBinding(t *testing.T) {
	_, image := publicationConfiguredImage(t, publicationRelationID(98), publicationRelationID(3), publicationRelationID(2))
	if publicationCompleteFixtureAccepted(t, &image) {
		t.Fatal("configuration target with wrong binding incarnation was accepted")
	}
}

// full_only: false
func TestPublicationBodyBackedProofUsesSelectedPhysicalOrdinals(t *testing.T) {
	image := publicationSelectedImageFixture(t)
	_, _, marker, _ := publicationRelationFixture(t)
	marker.AttemptID = publicationRelationID(100)
	obsoleteBody, err := contract.EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	obsolete := contract.SupportRecord{Kind: contract.PublicationMarkerSupportKind,
		RecordID: marker.AttemptID, Body: obsoleteBody}
	physical := format.RequiredSupportPage{Domain: image.root.Domain, Object: image.support[0].Object,
		Index: image.support[0].Index, Records: []contract.SupportRecord{
			obsolete, contract.SupportRecord(image.support[0].Records[0]), contract.SupportRecord(image.support[0].Records[1]),
		}}
	body, err := format.EncodeRequiredSupportPage(physical)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, physical.Domain, physical.Object, physical.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	image.root.RequiredSupport[0] = ref
	image.adminIndex.Pages[0].Ref = ref
	for i := range image.adminIndex.Pages[0].Spans {
		image.adminIndex.Pages[0].Spans[i].First++
	}
	if !image.adminIndex.Valid() {
		t.Fatal("sparse selected index invalid")
	}
	if _, err := selectedPublicationRelation(&image); err != nil {
		t.Fatalf("sparse selected relation invalid: %v", err)
	}
	proofs, err := publicationSelectedRowProofs(&image)
	if err != nil || len(proofs) != 2 {
		t.Fatalf("selected publication row proofs=%d err=%v", len(proofs), err)
	}
	if _, present := proofs[generatedRecordKey{kind: obsolete.Kind, id: obsolete.RecordID}]; present {
		t.Fatal("unselected physical row entered the proof")
	}
	for i, row := range image.support[0].Records {
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		proof, present := proofs[key]
		if !present || proof.ref != ref || proof.physical != uint16(i+1) ||
			proof.length != uint32(len(row.Body)) || proof.bodyDigest != contract.Hash(row.Body) {
			t.Fatalf("selected physical ordinal %d was not retained", i+1)
		}
	}
}

// full_only: false
func TestCompleteSelectedPublicationAllowsNewCurrentEntryWithOldOwner(t *testing.T) {
	_, image := publicationConfiguredImage(t, publicationRelationID(98), publicationRelationID(99), publicationRelationID(98))
	if !publicationCompleteFixtureAccepted(t, &image) {
		t.Fatal("current binding and entry were rejected because the retained old owner names another entry")
	}
}

func publicationCompleteFixtureAccepted(t *testing.T, image *selectedImage) bool {
	t.Helper()
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), image, nil)
	if err != nil || result.Outcome != 0 || proof == nil {
		return false
	}
	image.publicationProof = proof
	return true
}

func publicationFixtureVisit(image *selectedImage, visit contract.OutputConfigurationVisit) error {
	state := StateSession{root: image.root, support: image.support}
	source, err := state.outputConfigurationBodySource()
	if err != nil {
		return err
	}
	return contract.VisitOutputConfigurationSource(image.root.Domain, image.root.OutputConfiguration, source, visit)
}

func publicationFixtureReplaceConfiguration(t testing.TB, state *StateSession, replacement contract.SupportRecordView) {
	t.Helper()
	count := 0
	for i, page := range state.support {
		for j, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				state.support[i].Records[j] = replacement
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("single-slice fixture had %d configuration rows", count)
	}
}

// full_only: false
func TestSelectedPublicationGeneratedWorkPreservesQualifiedImage(t *testing.T) {
	state, _ := publicationConfiguredImage(t, publicationRelationID(2), publicationRelationID(3), publicationRelationID(2))
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), state.selectedImage(), nil)
	if err != nil || result.Outcome != 0 || proof == nil {
		t.Fatal("fixture publication proof", result, err)
	}
	state.publicationProof = proof
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	for range 512 {
		selected, err := state.selectedGeneratedWork(t.Context())
		if err != nil || selected == nil || !proof.validFor(state.selectedImage()) {
			t.Fatal("complete publication lost generated closure qualification", err)
		}
	}
	runtime.ReadMemStats(&after)
	t.Logf("same qualified fixture: elapsed=%s allocations=%d bytes=%d", time.Since(started), after.Mallocs-before.Mallocs, after.TotalAlloc-before.TotalAlloc)
}
