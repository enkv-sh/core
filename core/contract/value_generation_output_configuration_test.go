package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

func generatedOutputFixture(t *testing.T) (*GeneratedOutputTransition, PublicState, PublicationCoordinate, PublicationMarker) {
	t.Helper()
	coordinate, marker := publicationRecordFixture(t)
	w := &GeneratedOutputTransition{Before: OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: coordinate.DomainID, Routes: []OutputRoute{},
		Bindings: []OutputBinding{{DestinationID: "dest", IncarnationID: coordinate.ActiveBindingIncarnationID,
			Targets: []OutputTarget{{EntryIncarnationID: coordinate.LastEntryIncarnationID, ServiceContractID: coordinate.ServiceContractID,
				CanonicalTarget: coordinate.CanonicalTarget, ConsumerLocator: "locator", TargetContractID: "profile", Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot,
				PayloadEncoding: OutputEncodingRaw, Policy: OutputPolicy{ContractID: "provider", Data: []byte("none")}}}}}}}
	entry := ValueEntry{Name: "entry", Incarnation: coordinate.LastEntryIncarnationID, ValueState: publicationTestID(84),
		OriginSnapshot: publicationTestID(85), OriginTransition: publicationTestID(86), ValueSource: Supplied, ConfidentialityClass: Plain,
		Recipients: []ID{publicationTestID(5)}, ValueBytes: []byte("value"), InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, ContentLength: uint32(len([]byte("value"))), RetainedLength: uint32(len([]byte("value")))}
	body, err := EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	entryDigest, err := PublicValueEntryDigest(coordinate.DomainID, 0, entry)
	if err != nil {
		t.Fatal(err)
	}
	w.Before.DefaultDestinations = []string{"dest"}
	w.EntriesBefore = []MembershipRow{{Name: "entry", Slot: 0, Incarnation: coordinate.LastEntryIncarnationID,
		EntryDigest: entryDigest, Recipients: entry.Recipients}}
	w.EntryBodies = [][]byte{body}
	fixtureOutputSources(w)
	image, err := EncodeOutputConfiguration(w.Before)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := SplitOutputConfiguration(coordinate.DomainID, image)
	if err != nil {
		t.Fatal(err)
	}
	w.BeforeDescriptor = descriptor
	coordinateBody, err := EncodePublicationCoordinate(coordinate)
	if err != nil {
		t.Fatal(err)
	}
	markerBody, err := EncodePublicationMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	w.Rows.Records = []SupportRecord{{Kind: PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: coordinateBody},
		{Kind: PublicationMarkerSupportKind, RecordID: marker.AttemptID, Body: markerBody}}
	for _, part := range parts {
		body, err := EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal(err)
		}
		id, err := OutputConfigurationSliceID(coordinate.DomainID, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Records = append(w.Rows.Records, SupportRecord{Kind: OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	for _, row := range w.Rows.Records {
		fact, err := InspectSupportRecordDigest(coordinate.DomainID, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Facts = append(w.Rows.Facts, fact)
	}
	support, err := RequiredSupportDescriptorFromDigests(coordinate.DomainID, w.Rows.Facts)
	if err != nil {
		t.Fatal(err)
	}
	public := PublicState{Domain: coordinate.DomainID, AccessRoot: publicationTestID(81), RequiredSupport: support,
		Rows: []PublicStateRow{{Name: "entry", Slot: 0, EntryDigest: entryDigest}}}
	fixtureGeneratedOutputMeaning(w, []GeneratorValueEntryPlan{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: "entry", Slot: 0, EntryIncarnationID: coordinate.LastEntryIncarnationID}})
	return w, public, coordinate, marker
}

// full_only: false
func TestGeneratedOutputTransition(t *testing.T) {
	witness, public, coordinate, marker := generatedOutputFixture(t)
	w, err := witness.Own(public)
	if err != nil {
		t.Fatal("own selected output", err)
	}
	witness.Before.Bindings[0].Targets[0].CanonicalTarget = "changed caller slot"
	witness.EntriesBefore[0].Recipients[0] = publicationTestID(99)
	witness.Rows.Records[0].Body[0] ^= 1
	witness.EntryBodies[0][len(witness.EntryBodies[0])-1] ^= 1
	if w.Inspect(public) != nil {
		t.Fatal("private witness retained mutable input")
	}
	operation, entry := publicationTestID(82), publicationTestID(83)
	plans := []GeneratorValueEntryPlan{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: "entry", Slot: 0, EntryIncarnationID: entry}}
	fixtureGeneratedOutputMeaning(w, plans)
	rows, descriptor, err := w.Rebind(operation, plans)
	if err != nil || descriptor == w.BeforeDescriptor {
		t.Fatal("source conversion did not rebind", err)
	}
	binding := coordinate.ActiveBindingIncarnationID
	want := coordinate
	want.ActiveBindingIncarnationID = binding
	for _, row := range rows.Records {
		switch row.Kind {
		case PublicationCoordinateSupportKind:
			got, err := InspectPublicationCoordinate(row.Body)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("rebind changed old ownership/deletion inputs", err)
			}
		case PublicationMarkerSupportKind:
			got, err := InspectPublicationMarker(row.Body)
			if err != nil || !reflect.DeepEqual(got, marker) {
				t.Fatal("rebind changed unresolved marker", err)
			}
		case OutputConfigurationSliceSupportKind:
			part, err := InspectOutputConfigurationSlice(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			image, err := JoinOutputConfiguration(public.Domain, descriptor, []OutputConfigurationSlice{part})
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := InspectOutputConfiguration(public.Domain, image)
			if err != nil || got.Bindings[0].IncarnationID != binding || got.Bindings[0].Targets[0].EntryIncarnationID != entry {
				t.Fatal("wrong complete final configuration", err)
			}
		}
	}
	if !w.CandidateMatches(operation, plans, true, rows.Records) || w.CandidateMatches(operation, plans, false, rows.Records) ||
		!w.CandidateMatches(operation, plans, false, w.Rows.Records) {
		t.Fatal("phase preservation/rebind distinction lost")
	}
	if (*GeneratedOutputTransition)(nil).CandidateMatches(operation, plans, false, w.Rows.Records) {
		t.Fatal("output witness omission accepted")
	}
	for _, kind := range []uint8{PublicationCoordinateSupportKind, PublicationMarkerSupportKind, OutputConfigurationSliceSupportKind} {
		bad := slices.Clone(rows.Records)
		index := slices.IndexFunc(bad, func(row SupportRecord) bool { return row.Kind == kind })
		bad[index].Body = bytes.Clone(bad[index].Body)
		bad[index].Body[len(bad[index].Body)-1] ^= 1
		if w.CandidateMatches(operation, plans, true, bad) {
			t.Fatal("altered selected output body admitted", kind)
		}
	}
	fixtureGeneratedOutputMeaning(w, nil)
	retired, _, err := w.Rebind(operation, nil)
	if err != nil {
		t.Fatal(err)
	}
	want.BindingState, want.ActiveBindingIncarnationID = PublicationBindingRetired, ID{}
	for _, row := range retired.Records {
		if row.Kind == PublicationCoordinateSupportKind {
			got, err := InspectPublicationCoordinate(row.Body)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("retirement lost uncertain ownership or deletion input", err)
			}
		}
	}
	t.Run("canonical empty policy ownership", func(t *testing.T) {
		caller, state, _, _ := generatedOutputFixture(t)
		caller.Before.Bindings[0].Targets[0].Policy = OutputPolicy{ContractID: "provider"}
		refreshGeneratedOutputFixture(t, caller, &state)
		owned, err := caller.Own(state)
		if err != nil || owned.Before.Bindings[0].Targets[0].Policy.ContractID != "provider" || len(owned.Before.Bindings[0].Targets[0].Policy.Data) != 0 || owned.Before.Routes == nil {
			t.Fatal("empty policy ownership", err)
		}
	})
	t.Run("complete caller ownership", func(t *testing.T) {
		for _, kind := range []uint8{1, 2} {
			caller, state, _, _ := generatedOutputFixture(t)
			p := &caller.Before.Bindings[0].Targets[0].Policy
			p.Data = []byte{kind, 0, 255}
			caller.Before.DefaultDestinations = []string{"dest"}
			refreshGeneratedOutputFixture(t, caller, &state)
			first, err := caller.Own(state)
			if err != nil {
				t.Fatal(err)
			}
			second, err := caller.Own(state)
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(caller)
			if err != nil {
				t.Fatal(err)
			}
			mutateOutputConfigurationCaller(&caller.Before)
			caller.EntriesBefore[0].Recipients[0] = ID{}
			caller.EntriesBefore[0].Name = "changed"
			caller.EntriesBefore[0] = MembershipRow{}
			caller.EntryBodies[0][0] ^= 1
			caller.EntryBodies[0] = nil
			caller.Rows.Records[0].Body[0] ^= 1
			caller.Rows.Records[0] = SupportRecord{}
			caller.Rows.Facts[0] = SupportRecordDigest{}
			for _, owned := range []*GeneratedOutputTransition{first, second} {
				got, err := json.Marshal(owned)
				if err != nil || !bytes.Equal(got, want) || owned.Inspect(state) != nil {
					t.Fatal("complete witness changed through caller slices", kind, err)
				}
			}
			mutateOutputConfigurationCaller(&first.Before)
			first.EntriesBefore[0].Recipients[0] = ID{}
			first.EntryBodies[0][0] ^= 1
			first.Rows.Records[0].Body[0] ^= 1
			first.Rows.Facts[0] = SupportRecordDigest{}
			got, err := json.Marshal(second)
			if err != nil || !bytes.Equal(got, want) || second.Inspect(state) != nil {
				t.Fatal("separate ownership calls share writable data", kind, err)
			}
		}
	})
	for _, fault := range []string{"descriptor", "entry-name", "entry-slot", "entry-digest", "entry-incarnation", "entry-body", "missing-entry-body", "support", "missing-row", "coordinate-body", "marker-body"} {
		t.Run(fault, func(t *testing.T) {
			bad, err := w.Own(public)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "descriptor":
				bad.BeforeDescriptor.ConfigurationDigest[0] ^= 1
			case "entry-name":
				bad.EntriesBefore[0].Name = "wrong"
			case "entry-slot":
				bad.EntriesBefore[0].Slot++
			case "entry-digest":
				bad.EntriesBefore[0].EntryDigest[0] ^= 1
			case "entry-incarnation":
				bad.EntriesBefore[0].Incarnation = publicationTestID(98)
			case "entry-body":
				bad.EntryBodies[0][len(bad.EntryBodies[0])-1] ^= 1
			case "missing-entry-body":
				bad.EntryBodies = nil
			case "support":
				bad.Rows.Facts = bad.Rows.Facts[1:]
			case "missing-row":
				bad.Rows.Records = bad.Rows.Records[1:]
			case "coordinate-body", "marker-body":
				kind := uint8(PublicationCoordinateSupportKind)
				if fault == "marker-body" {
					kind = PublicationMarkerSupportKind
				}
				index := slices.IndexFunc(bad.Rows.Records, func(row SupportRecord) bool { return row.Kind == kind })
				bad.Rows.Records[index].Body[0] ^= 1
			}
			if bad.Inspect(public) == nil {
				t.Fatal("wrong phase predecessor accepted")
			}
		})
	}
}

func refreshGeneratedOutputFixture(t *testing.T, w *GeneratedOutputTransition, public *PublicState) {
	t.Helper()
	fixtureOutputSources(w)
	image, err := EncodeOutputConfiguration(w.Before)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, parts, err := SplitOutputConfiguration(w.Before.DomainID, image)
	if err != nil {
		t.Fatal(err)
	}
	w.BeforeDescriptor = descriptor
	w.Rows.Records = slices.DeleteFunc(w.Rows.Records, func(row SupportRecord) bool { return row.Kind == OutputConfigurationSliceSupportKind })
	for _, part := range parts {
		body, err := EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal(err)
		}
		id, err := OutputConfigurationSliceID(w.Before.DomainID, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Records = append(w.Rows.Records, SupportRecord{Kind: OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	slices.SortFunc(w.Rows.Records, func(a, b SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	w.Rows.Facts = nil
	for _, row := range w.Rows.Records {
		fact, err := InspectSupportRecordDigest(w.Before.DomainID, row)
		if err != nil {
			t.Fatal(err)
		}
		w.Rows.Facts = append(w.Rows.Facts, fact)
	}
	var plans []GeneratorValueEntryPlan
	for _, entry := range w.EntriesBefore {
		plans = append(plans, GeneratorValueEntryPlan{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: entry.Name, Slot: entry.Slot, EntryIncarnationID: entry.Incarnation})
	}
	fixtureGeneratedOutputMeaning(w, plans)
	public.RequiredSupport, err = RequiredSupportDescriptorFromDigests(w.Before.DomainID, w.Rows.Facts)
	if err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestGeneratedOutputEmptyEntryRouting(t *testing.T) {
	w, public, _, _ := generatedOutputFixture(t)
	view, err := InspectValueEntry(w.EntryBodies[0])
	if err != nil {
		t.Fatal(err)
	}
	entry, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	entry.Name = ""
	w.EntryBodies[0], err = EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PublicValueEntryDigest(public.Domain, 0, entry)
	if err != nil {
		t.Fatal(err)
	}
	w.EntriesBefore[0].Name, w.EntriesBefore[0].EntryDigest = "", digest
	public.Rows[0].Name, public.Rows[0].EntryDigest = "", digest
	w.Before.DefaultDestinations = nil
	w.Before.Routes = []OutputRoute{{EntryIncarnationID: entry.Incarnation, Destinations: []string{"dest"}}}
	refreshGeneratedOutputFixture(t, w, &public)
	w, err = w.Own(public)
	if err != nil {
		t.Fatal("empty entry predecessor did not authenticate", err)
	}
	incarnation := publicationTestID(96)
	plans := []GeneratorValueEntryPlan{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: "", Slot: 0, EntryIncarnationID: incarnation}}
	fixtureGeneratedOutputMeaning(w, plans)
	rows, descriptor, err := w.Rebind(publicationTestID(95), plans)
	if err != nil {
		t.Fatal("empty entry successor refused", err)
	}
	var parts []OutputConfigurationSlice
	for _, row := range rows.Records {
		if row.Kind == OutputConfigurationSliceSupportKind {
			part, err := InspectOutputConfigurationSlice(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			parts = append(parts, part)
		}
	}
	image, err := JoinOutputConfiguration(public.Domain, descriptor, parts)
	if err != nil {
		t.Fatal(err)
	}
	configuration, _, err := InspectOutputConfiguration(public.Domain, image)
	want := []OutputRoute{{EntryIncarnationID: incarnation, Destinations: []string{"dest"}}}
	if err != nil || !reflect.DeepEqual(configuration.Routes, want) {
		t.Fatal("generated exact empty entry route became fallback", configuration.Routes, err)
	}
	t.Run("successor_routing_does_not_leak_to_another_entry", func(t *testing.T) {
		operation := publicationTestID(95)
		declaration := GeneratorDeclaration{Schema: GeneratorRecordSchema, DomainID: public.Domain, OperationID: operation,
			Entries: []GeneratorDeclarationEntry{
				{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationPlain, Name: "", Recipients: entry.Recipients, Payload: []byte("empty")},
				{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationPlain, Name: "other", Recipients: entry.Recipients, Payload: []byte("other")},
			}}
		body, err := EncodeGeneratorDeclaration(declaration)
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectGeneratorDeclaration(body)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, err := view.Descriptor()
		if err != nil {
			t.Fatal(err)
		}
		membership, err := GeneratorIntendedMembershipDescriptor(entry.Recipients)
		if err != nil {
			t.Fatal(err)
		}
		graph := GeneratorPlanBundle{Header: GeneratorGraphHeader{OperationID: operation},
			Request: GeneratorRequestCore{OperationKind: OperationApplyDeclaration, Declaration: descriptor},
			ValueEntryPlans: []GeneratorValueEntryPlan{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: "", Slot: 0, EntryIncarnationID: incarnation, IntendedMembership: membership},
				{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: "other", Slot: 1, EntryIncarnationID: publicationTestID(97), IntendedMembership: membership}}}
		fixtureGeneratedOutputMeaning(w, graph.ValueEntryPlans)
		if err := w.ValidateSuccessorRouting(graph, view); err != nil {
			t.Fatal("exact empty route leaked to an uncovered sibling", err)
		}
	})
}

// full_only: false
func TestGeneratedOutputMandatoryConfiguration(t *testing.T) {
	domain := publicationTestID(91)
	w := &GeneratedOutputTransition{Before: OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: domain}}
	public := PublicState{Domain: domain, AccessRoot: publicationTestID(92)}
	refreshGeneratedOutputFixture(t, w, &public)
	owned, err := w.Own(public)
	if err != nil || len(owned.Rows.Records) != 1 {
		t.Fatal("canonical mandatory empty slice", err)
	}
	if owned.Before.Bindings == nil || owned.Before.Routes == nil {
		t.Fatal("owned canonical empty configuration has noncanonical nil tables")
	}
	if !owned.CandidateMatches(publicationTestID(93), nil, false, owned.Rows.Records) || owned.CandidateMatches(publicationTestID(93), nil, false, nil) {
		t.Fatal("candidate did not bind the mandatory empty slice")
	}
	t.Run("missing selected commitment", func(t *testing.T) {
		w.Rows = GeneratedSupportRows{}
		public.RequiredSupport, err = EmptyRequiredSupportDescriptor(domain)
		if err != nil {
			t.Fatal(err)
		}
		if w.Inspect(public) == nil {
			t.Fatal("missing configuration was interpreted as canonical empty state")
		}
	})
	t.Run("missing rebound slice", func(t *testing.T) {
		owned.Rows.Records = nil
		if _, _, err := owned.Rebind(publicationTestID(93), nil); err == nil {
			t.Fatal("rebind omitted mandatory empty configuration")
		}
	})
}

// full_only: false
func TestGeneratedOutputRebindRoutes(t *testing.T) {
	for _, level := range []string{"default", "entry"} {
		t.Run(level, func(t *testing.T) {
			w, public, coordinate, marker := generatedOutputFixture(t)
			w.Before.DefaultDestinations = nil
			if level == "default" {
				w.Before.DefaultDestinations = []string{"dest"}
			} else {
				w.Before.Routes = []OutputRoute{{EntryIncarnationID: w.EntriesBefore[0].Incarnation, Destinations: []string{"dest"}}}
			}
			refreshGeneratedOutputFixture(t, w, &public)
			w, err := w.Own(public)
			if err != nil {
				t.Fatal(err)
			}
			fixtureGeneratedOutputMeaning(w, nil)
			rows, descriptor, err := w.Rebind(publicationTestID(94), nil)
			if err != nil {
				t.Fatal("whole-set target removal retained an empty route", err)
			}
			for _, row := range rows.Records {
				switch row.Kind {
				case OutputConfigurationSliceSupportKind:
					part, err := InspectOutputConfigurationSlice(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					image, err := JoinOutputConfiguration(public.Domain, descriptor, []OutputConfigurationSlice{part})
					if err != nil {
						t.Fatal(err)
					}
					configuration, _, err := InspectOutputConfiguration(public.Domain, image)
					var defaults []string
					if level == "default" {
						defaults = []string{"dest"}
					}
					if err != nil || len(configuration.Bindings) != 1 || len(configuration.Bindings[0].Targets) != 0 || configuration.Bindings[0].IncarnationID != w.Before.Bindings[0].IncarnationID || len(configuration.Routes) != 0 || !slices.Equal(configuration.DefaultDestinations, defaults) {
						t.Fatal("retained destination or default changed", err)
					}
				case PublicationCoordinateSupportKind:
					want := coordinate
					want.BindingState, want.ActiveBindingIncarnationID = PublicationBindingRetired, ID{}
					got, err := InspectPublicationCoordinate(row.Body)
					if err != nil || !reflect.DeepEqual(got, want) {
						t.Fatal("route removal lost owned coordinate facts", err)
					}
				case PublicationMarkerSupportKind:
					got, err := InspectPublicationMarker(row.Body)
					if err != nil || !reflect.DeepEqual(got, marker) {
						t.Fatal("route removal changed unresolved marker", err)
					}
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedOutputRetainsDestinationIncarnation(t *testing.T) {
	for _, change := range []string{"unchanged-entry", "replaced-entry", "removed-entry"} {
		t.Run(change, func(t *testing.T) {
			for _, operation := range []ID{publicationTestID(82), publicationTestID(92)} {
				w, public, coordinate, marker := generatedOutputFixture(t)
				owned, err := w.Own(public)
				if err != nil {
					t.Fatal(err)
				}
				entry := owned.EntriesBefore[0].Incarnation
				if change == "replaced-entry" {
					entry = publicationTestID(83)
				}
				plans := []GeneratorValueEntryPlan{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: "entry", Slot: 0, EntryIncarnationID: entry}}
				if change == "removed-entry" {
					plans = nil
					coordinate.BindingState, coordinate.ActiveBindingIncarnationID = PublicationBindingRetired, ID{}
				}
				fixtureGeneratedOutputMeaning(owned, plans)
				rows, descriptor, err := owned.Rebind(operation, plans)
				if err != nil {
					t.Fatal(err)
				}
				var parts []OutputConfigurationSlice
				coordinates, markers := 0, 0
				for _, row := range rows.Records {
					switch row.Kind {
					case PublicationCoordinateSupportKind:
						coordinates++
						got, err := InspectPublicationCoordinate(row.Body)
						if err != nil || row.RecordID != coordinate.CoordinateID || !reflect.DeepEqual(got, coordinate) {
							t.Fatal("rebind changed retained coordinate history", err)
						}
					case PublicationMarkerSupportKind:
						markers++
						got, err := InspectPublicationMarker(row.Body)
						if err != nil || row.RecordID != marker.AttemptID || !reflect.DeepEqual(got, marker) {
							t.Fatal("rebind changed retained marker", err)
						}
					case OutputConfigurationSliceSupportKind:
						part, err := InspectOutputConfigurationSlice(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						parts = append(parts, part)
					}
				}
				if coordinates != 1 || markers != 1 {
					t.Fatal("rebind lost or duplicated publication history")
				}
				image, err := JoinOutputConfiguration(public.Domain, descriptor, parts)
				if err != nil {
					t.Fatal(err)
				}
				configuration, _, err := InspectOutputConfiguration(public.Domain, image)
				if err != nil || len(configuration.Bindings) != 1 {
					t.Fatal("rebind lost retained destination", err)
				}
				got, want := configuration.Bindings[0], owned.Before.Bindings[0]
				if got.DestinationID != want.DestinationID || got.IncarnationID != want.IncarnationID || !reflect.DeepEqual(got.Destination, want.Destination) {
					t.Fatal("rebind changed retained destination incarnation or settings")
				}
				if change == "removed-entry" {
					if len(got.Targets) != 0 {
						t.Fatal("removed entry retained an output target")
					}
				} else {
					target := want.Targets[0]
					target.EntryIncarnationID = entry
					if len(got.Targets) != 1 || !reflect.DeepEqual(got.Targets[0], target) {
						t.Fatal("rebind changed target facts beyond the entry incarnation")
					}
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedOutputRebindPartialRoute(t *testing.T) {
	for _, test := range []struct {
		name                  string
		entryRoute, emptyName bool
	}{{"default", false, false}, {"entry", true, false}, {"empty-default", false, true}, {"empty-entry", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			entryRoute := test.entryRoute
			w, public, coordinate, _ := generatedOutputFixture(t)
			view, err := InspectValueEntry(w.EntryBodies[0])
			if err != nil {
				t.Fatal(err)
			}
			entry, err := view.Own()
			if err != nil {
				t.Fatal(err)
			}
			if test.emptyName {
				entry.Name = ""
				w.EntryBodies[0], err = EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				digest, err := PublicValueEntryDigest(public.Domain, 0, entry)
				if err != nil {
					t.Fatal(err)
				}
				w.EntriesBefore[0].Name, w.EntriesBefore[0].EntryDigest = "", digest
				public.Rows[0].Name, public.Rows[0].EntryDigest = "", digest
			}
			entry.Name, entry.Incarnation, entry.ValueState = "kept", publicationTestID(95), publicationTestID(96)
			body, err := EncodeValueEntry(entry)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := PublicValueEntryDigest(public.Domain, 1, entry)
			if err != nil {
				t.Fatal(err)
			}
			w.EntryBodies = append(w.EntryBodies, body)
			w.EntriesBefore = append(w.EntriesBefore, MembershipRow{Name: entry.Name, Slot: 1, Incarnation: entry.Incarnation, EntryDigest: digest, Recipients: entry.Recipients})
			public.Rows = append(public.Rows, PublicStateRow{Name: entry.Name, Slot: 1, EntryDigest: digest})
			target := w.Before.Bindings[0].Targets[0]
			target.EntryIncarnationID, target.CanonicalTarget = entry.Incarnation, "kept-slot"
			binding := OutputBinding{DestinationID: "keep", IncarnationID: publicationTestID(97), Targets: []OutputTarget{target}}
			w.Before.Bindings = append(w.Before.Bindings, binding)
			w.Before.DefaultDestinations = nil
			w.Before.Routes = nil
			destinations := []string{"dest", "keep"}
			if entryRoute {
				w.Before.Routes = []OutputRoute{{EntryIncarnationID: w.EntriesBefore[0].Incarnation, Destinations: []string{"dest"}}, {EntryIncarnationID: entry.Incarnation, Destinations: destinations}}
				slices.SortFunc(w.Before.Routes, func(a, b OutputRoute) int { return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:]) })
			} else {
				w.Before.DefaultDestinations = destinations
				if test.emptyName {
					w.Before.Routes = []OutputRoute{{EntryIncarnationID: w.EntriesBefore[0].Incarnation, Destinations: []string{"dest"}}}
				}
			}
			coordinate.CoordinateID, err = PublicationCoordinateID(public.Domain, coordinate.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			coordinate.CanonicalTarget = target.CanonicalTarget
			coordinate.ActiveBindingIncarnationID, coordinate.LastBindingIncarnationID, coordinate.LastEntryIncarnationID = binding.IncarnationID, binding.IncarnationID, entry.Incarnation
			coordinate.OwnerState, coordinate.LastAdmissionOrdinal, coordinate.LatestUnresolvedAttemptID, coordinate.PossibleRemoteObject = PublicationOwnerNone, 0, ID{}, 0
			coordinate.DeletionDestinationID, coordinate.DeletionConsumerLocator, coordinate.DeletionTargetContractID, coordinate.DeletionCredentialRouteContractID = "", "", "", ""
			coordinate.DeletionTargetData = nil
			coordinate.DeletionConfigContractID = ""
			coordinate.DeletionPayloadEncoding = 0
			coordinate.LocatorRequiresCreation = false
			coordinate.DeletionTargetRowDigest = ID{}
			coordinate.CurrentPublicationIncarnationID = publicationTestID(98)
			body, err = EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal(err)
			}
			w.Rows.Records = append(w.Rows.Records, SupportRecord{Kind: PublicationCoordinateSupportKind, RecordID: coordinate.CoordinateID, Body: body})
			refreshGeneratedOutputFixture(t, w, &public)
			w, err = w.Own(public)
			if err != nil {
				t.Fatal(err)
			}
			plans := []GeneratorValueEntryPlan{{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Name: entry.Name, Slot: 1, EntryIncarnationID: entry.Incarnation}}
			fixtureGeneratedOutputMeaning(w, plans)
			rows, descriptor, err := w.Rebind(publicationTestID(99), plans)
			if err != nil {
				t.Fatal(err)
			}
			var parts []OutputConfigurationSlice
			for _, row := range rows.Records {
				if row.Kind == OutputConfigurationSliceSupportKind {
					part, err := InspectOutputConfigurationSlice(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					parts = append(parts, part)
				}
			}
			image, err := JoinOutputConfiguration(public.Domain, descriptor, parts)
			if err != nil {
				t.Fatal(err)
			}
			configuration, _, err := InspectOutputConfiguration(public.Domain, image)
			var wantRoutes []OutputRoute
			var wantDefaults []string
			if entryRoute {
				wantRoutes = []OutputRoute{{EntryIncarnationID: entry.Incarnation, Destinations: destinations}}
			} else {
				wantDefaults = destinations
			}
			if err != nil || len(configuration.Bindings) != 2 || configuration.Bindings[0].IncarnationID != w.Before.Bindings[0].IncarnationID || configuration.Bindings[1].IncarnationID != binding.IncarnationID || !slices.EqualFunc(configuration.Routes, wantRoutes, func(a, b OutputRoute) bool {
				return a.EntryIncarnationID == b.EntryIncarnationID && slices.Equal(a.Destinations, b.Destinations)
			}) || !slices.Equal(configuration.DefaultDestinations, wantDefaults) {
				t.Fatal("partial entry removal lost retained destination or declared routing", err)
			}
			for _, declared := range configuration.Bindings {
				if len(declared.Targets) != 1 || declared.Targets[0].EntryIncarnationID != entry.Incarnation {
					t.Fatal("complete routing did not derive surviving pair", declared.DestinationID)
				}
			}

		})
	}
}

func mutateOutputConfigurationCaller(v *OutputConfiguration) {
	for i := range v.DefaultDestinations {
		v.DefaultDestinations[i] = "changed"
	}
	for i := range v.Bindings {
		b := &v.Bindings[i]
		clear(b.Destination.Policy.Data)
		clear(b.Destination.CanonicalSettings)
		for j := range b.Targets {
			clear(b.Targets[j].Policy.Data)
			clear(b.Targets[j].TargetData)
			b.Targets[j] = OutputTarget{}
		}
		v.Bindings[i] = OutputBinding{}
	}
	for i := range v.Routes {
		v.Routes[i].Destinations[0] = "changed"
		v.Routes[i] = OutputRoute{}
	}
}

// full_only: false
func TestGeneratedOutputTransitionChecksSelectedConfigurationBytes(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {0, 255}, []byte("private-policy")} {
		w, state, _, _ := generatedOutputFixture(t)
		policy := OutputPolicy{ContractID: "provider", Data: data}
		w.Before.Bindings[0].Targets[0].Policy = policy
		refreshGeneratedOutputFixture(t, w, &state)
		if err := w.Inspect(state); err != nil {
			t.Fatal("exact opaque policy", err)
		}
		w.Before.Bindings[0].Targets[0].Policy.ContractID = "provides"
		w.Before.Bindings[0].Destination.Policy.ContractID = "provides"
		if w.Inspect(state) == nil {
			t.Fatal("same length policy identity accepted")
		}
	}
	w, state, _, _ := generatedOutputFixture(t)
	data := bytes.Repeat([]byte{1}, 16384)
	base := w.Before.Bindings[0]
	w.Before.Bindings = make([]OutputBinding, 33)
	for i := range w.Before.Bindings {
		binding := base
		binding.DestinationID = fmt.Sprintf("dest-%02d", i)
		binding.IncarnationID = publicationTestID(byte(100 + i))
		binding.Targets = slices.Clone(base.Targets)
		binding.Targets[0].CanonicalTarget = fmt.Sprintf("slot-%02d", i)
		binding.Targets[0].Policy = OutputPolicy{ContractID: "provider", Data: data}
		w.Before.Bindings[i] = binding
	}
	// Five entries preserve all 33 target pairs within eight destinations each.
	original, err := DecodeValueEntry(w.EntryBodies[0])
	if err != nil {
		t.Fatal(err)
	}
	w.Before.DefaultDestinations = nil
	w.Before.Routes, w.EntryBodies, w.EntriesBefore, state.Rows = nil, nil, nil, nil
	for first := 0; first < len(w.Before.Bindings); first += 8 {
		entry := original
		group := first / 8
		if group != 0 {
			entry.Name = fmt.Sprintf("entry-%d", group)
			entry.Incarnation = publicationTestID(byte(150 + group))
		}
		body, err := EncodeValueEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := PublicValueEntryDigest(state.Domain, uint16(group), entry)
		if err != nil {
			t.Fatal(err)
		}
		w.EntryBodies = append(w.EntryBodies, body)
		w.EntriesBefore = append(w.EntriesBefore, MembershipRow{Name: entry.Name, Slot: uint16(group), Incarnation: entry.Incarnation, EntryDigest: digest, Recipients: entry.Recipients})
		state.Rows = append(state.Rows, PublicStateRow{Name: entry.Name, Slot: uint16(group), EntryDigest: digest})
		route := OutputRoute{EntryIncarnationID: entry.Incarnation}
		for b := first; b < min(first+8, len(w.Before.Bindings)); b++ {
			w.Before.Bindings[b].Targets[0].EntryIncarnationID = entry.Incarnation
			route.Destinations = append(route.Destinations, w.Before.Bindings[b].DestinationID)
		}
		w.Before.Routes = append(w.Before.Routes, route)
	}
	slices.SortFunc(w.Before.Routes, func(a, b OutputRoute) int { return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:]) })
	refreshGeneratedOutputFixture(t, w, &state)
	if w.BeforeDescriptor.SliceCount != 2 || w.Inspect(state) != nil {
		t.Fatal("real two-slice selected configuration refused")
	}
	for _, name := range []string{"exact", "typed invalid order", "typed invalid route", "descriptor", "slice schema", "slice domain", "slice digest", "slice ordinal", "slice count", "slice total", "slice id", "before boundary", "after boundary", "missing slice", "extra slice", "duplicate slice", "record order"} {
		t.Run(name, func(t *testing.T) {
			bad, err := w.Own(state)
			if err != nil {
				t.Fatal(err)
			}
			config := slices.IndexFunc(bad.Rows.Records, func(row SupportRecord) bool { return row.Kind == OutputConfigurationSliceSupportKind })
			switch name {
			case "typed invalid order":
				bad.Before.Bindings[0], bad.Before.Bindings[1] = bad.Before.Bindings[1], bad.Before.Bindings[0]
			case "typed invalid route":
				bad.Before.Routes = []OutputRoute{{Destinations: []string{"missing"}}}
			case "descriptor":
				bad.BeforeDescriptor.RoutingLength++
			case "slice schema":
				bad.Rows.Records[config].Body[1]++
			case "slice domain":
				bad.Rows.Records[config].Body[2] ^= 1
			case "slice digest":
				bad.Rows.Records[config].Body[34] ^= 1
			case "slice ordinal":
				bad.Rows.Records[config].Body[67] = 2
			case "slice count":
				bad.Rows.Records[config].Body[69]++
			case "slice total":
				bad.Rows.Records[config].Body[73]++
			case "slice id":
				bad.Rows.Records[config].RecordID[0] ^= 1
			case "before boundary", "after boundary":
				index := slices.IndexFunc(bad.Rows.Records, func(row SupportRecord) bool {
					if row.Kind != OutputConfigurationSliceSupportKind {
						return false
					}
					v, err := InspectOutputConfigurationSlice(row.Body)
					return err == nil && (name == "before boundary" && v.SliceIndex == 0 || name == "after boundary" && v.SliceIndex == 1)
				})
				at := OutputConfigurationSliceBodyOverhead
				if name == "before boundary" {
					at = len(bad.Rows.Records[index].Body) - 1
				}
				bad.Rows.Records[index].Body[at] ^= 1
			case "missing slice":
				bad.Rows.Records = slices.Delete(bad.Rows.Records, config, config+1)
			case "extra slice", "duplicate slice":
				row := bad.Rows.Records[config]
				if name == "extra slice" {
					row.RecordID = publicationTestID(240)
				}
				bad.Rows.Records = append(bad.Rows.Records, row)
			case "record order":
				bad.Rows.Records[config], bad.Rows.Records[config+1] = bad.Rows.Records[config+1], bad.Rows.Records[config]
			}
			// Valid changed rows can reach comparison under their own selected facts.
			reauthenticate := name == "exact" || name == "typed invalid order" || name == "typed invalid route" || name == "descriptor" ||
				name == "before boundary" || name == "after boundary" || name == "missing slice"
			if reauthenticate {
				slices.SortFunc(bad.Rows.Records, func(a, b SupportRecord) int {
					if a.Kind != b.Kind {
						return int(a.Kind) - int(b.Kind)
					}
					return bytes.Compare(a.RecordID[:], b.RecordID[:])
				})
				bad.Rows.Facts = nil
				for _, row := range bad.Rows.Records {
					fact, err := InspectSupportRecordDigest(state.Domain, row)
					if err != nil {
						t.Fatal(err)
					}
					bad.Rows.Facts = append(bad.Rows.Facts, fact)
				}
			}
			before := state
			if reauthenticate {
				before.RequiredSupport, err = RequiredSupportDescriptorFromDigests(state.Domain, bad.Rows.Facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := bad.Inspect(before) == nil; got != (name == "exact") {
				t.Fatalf("selected configuration: accepted=%t want=%t", got, name == "exact")
			}
		})
	}
	t.Run("nested prefix splits", func(t *testing.T) {
		w, _, _, _ := generatedOutputFixture(t)
		binding := w.Before.Bindings[0]
		target := binding.Targets[0]
		fixtureOutputSources(w)
		image, err := EncodeOutputConfiguration(w.Before)
		if err != nil {
			t.Fatal(err)
		}
		// Formats: schema/count, B(destination), incarnation, source,
		// target count, target ID, four text blobs, target-data blob,
		// three typed flags, four u32 value bounds, B(Policy),
		// group count, then B(routing). Routing has five fixed bytes, default blobs, then 33 bytes and B(names) per entry.
		policyOffset := 2 + 2 + 4 + len(binding.DestinationID) + 32 + fixtureDestinationWireLength(binding.Destination) + 2 + 32
		for _, field := range []string{target.ServiceContractID, target.TargetContractID, target.CanonicalTarget, target.ConsumerLocator} {
			policyOffset += 4 + len(field)
		}
		policyOffset += 4 + len(target.TargetData) + 3 + 16
		policyLength := 2 + 4 + len(target.Policy.ContractID) + 4 + len(target.Policy.Data)
		routingOffset, routingLength := policyOffset+4+policyLength+2, 5
		for _, name := range w.Before.DefaultDestinations {
			routingLength += 4 + len(name)
		}
		for _, route := range w.Before.Routes {
			routingLength += 33
			for _, name := range route.Destinations {
				routingLength += 4 + len(name)
			}
		}
		for _, section := range []struct {
			name           string
			offset, length int
		}{{"policy", policyOffset, policyLength}, {"routing", routingOffset, routingLength}} {
			t.Run(section.name, func(t *testing.T) {
				if binary.BigEndian.Uint32(image[section.offset:section.offset+4]) != uint32(section.length) {
					t.Fatal("independent nested prefix offset or length")
				}
				for split := 1; split <= 3; split++ {
					t.Run(fmt.Sprintf("%d+%d", split, 4-split), func(t *testing.T) {
						cut := section.offset + split
						// This exercises the byte cursor, not selected-slice header admission.
						parts := [][]byte{image[:cut], image[cut:]}
						if err := matchOutputConfiguration(w.Before, w.BeforeDescriptor, parts); err != nil {
							t.Fatal("exact cross-part prefix refused", err)
						}
						for byteIndex := 0; byteIndex < 4; byteIndex++ {
							bad := bytes.Clone(image)
							bad[section.offset+byteIndex] ^= 1
							if err := matchOutputConfiguration(w.Before, w.BeforeDescriptor, [][]byte{bad[:cut], bad[cut:]}); !errors.Is(err, ErrRecord) {
								t.Fatal("changed cross-part prefix accepted or wrong error", byteIndex, err)
							}
						}
					})
				}
			})
		}
	})
	t.Run("combined input errors", func(t *testing.T) {
		w, state, _, _ := generatedOutputFixture(t)
		binding := w.Before.Bindings[0]
		binding.DestinationID = "later"
		binding.IncarnationID = publicationTestID(120)
		binding.Targets = slices.Clone(binding.Targets)
		binding.Targets[0].CanonicalTarget = "later slot"
		w.Before.Bindings = append(w.Before.Bindings, binding)
		refreshGeneratedOutputFixture(t, w, &state)
		data := bytes.Repeat([]byte{255}, MaxOutputPolicyBytes+1)
		for _, name := range []string{"descriptor and capacity", "slice metadata and capacity", "missing records and capacity", "byte mismatch and later capacity", "prefix mismatch and later capacity", "prefix mismatch and later malformed policy"} {
			t.Run(name, func(t *testing.T) {
				bad, err := w.Own(state)
				if err != nil {
					t.Fatal(err)
				}
				bad.Before.Bindings[1].Targets[0].Policy = OutputPolicy{ContractID: "provider", Data: data}
				bad.Before.Bindings[1].Destination.Policy = cloneOutputPolicy(bad.Before.Bindings[1].Targets[0].Policy)
				want := ErrRecordCapacity
				config := slices.IndexFunc(bad.Rows.Records, func(row SupportRecord) bool { return row.Kind == OutputConfigurationSliceSupportKind })
				before := state
				switch name {
				case "descriptor and capacity":
					bad.BeforeDescriptor.SliceCount++
				case "slice metadata and capacity":
					bad.Rows.Records[config].Body[1]++
				case "missing records and capacity":
					bad.Rows.Records = nil
				default:
					at := OutputConfigurationSliceBodyOverhead
					if name != "byte mismatch and later capacity" {
						target := bad.Before.Bindings[0].Targets[0]
						at += 2 + 2 + 4 + len(bad.Before.Bindings[0].DestinationID) + 32 + fixtureDestinationWireLength(bad.Before.Bindings[0].Destination) + 2 + 32
						for _, field := range []string{target.ServiceContractID, target.TargetContractID, target.CanonicalTarget, target.ConsumerLocator} {
							at += 4 + len(field)
						}
						at += 4 + len(target.TargetData) + 3
					}
					bad.Rows.Records[config].Body[at] ^= 1
					fact, err := InspectSupportRecordDigest(state.Domain, bad.Rows.Records[config])
					if err != nil {
						t.Fatal(err)
					}
					bad.Rows.Facts[config] = fact
					before.RequiredSupport, err = RequiredSupportDescriptorFromDigests(state.Domain, bad.Rows.Facts)
					if err != nil {
						t.Fatal(err)
					}
					if name == "prefix mismatch and later malformed policy" {
						want = ErrRecord
						bad.Before.Bindings[1].Targets[0].Policy = OutputPolicy{Data: []byte{2, 1}}
						bad.Before.Bindings[1].Destination.Policy = cloneOutputPolicy(bad.Before.Bindings[1].Targets[0].Policy)
					}
				}
				if err := bad.Inspect(before); !errors.Is(err, want) {
					t.Fatal("earlier selected-byte failure hid owning typed error", err, want)
				}
			})
		}
	})

}

// These fixture declarations are explicit source inputs for the synthetic
// installed profile used by this contract suite.
func fixtureOutputSources(w *GeneratedOutputTransition) {
	for i := range w.Before.Bindings {
		b := &w.Before.Bindings[i]
		if len(b.Targets) == 0 {
			continue
		}
		t := b.Targets[0]
		b.Destination = OutputDestination{ServiceContractID: t.ServiceContractID, ConfigContractID: "config", CanonicalSettings: []byte("{}"), Capabilities: t.Capabilities, Policy: cloneOutputPolicy(t.Policy)}
	}
}

func fixtureGeneratedOutputMeaning(w *GeneratedOutputTransition, plans []GeneratorValueEntryPlan) {
	names := make(map[string]bool, len(plans))
	oldNames := make(map[ID]string, len(w.EntriesBefore))
	for _, p := range plans {
		names[p.Name] = true
	}
	for _, e := range w.EntriesBefore {
		oldNames[e.Incarnation] = e.Name
	}
	w.Bindings = nil
	w.Routes = nil
	w.Groups = nil
	w.Routes = append(w.Routes, NormalOutputRoute{Default: true, Destinations: slices.Clone(w.Before.DefaultDestinations)})
	for _, route := range w.Before.Routes {
		name := oldNames[route.EntryIncarnationID]
		if names[name] {
			w.Routes = append(w.Routes, NormalOutputRoute{Name: name, Destinations: slices.Clone(route.Destinations)})
		}
	}
	slices.SortFunc(w.Routes, func(a, b NormalOutputRoute) int {
		if a.Default != b.Default {
			if a.Default {
				return 1
			}
			return -1
		}
		return bytes.Compare([]byte(a.Name), []byte(b.Name))
	})
	for _, b := range w.Before.Bindings {
		desired := NormalOutputBinding{DestinationID: b.DestinationID, Destination: b.Destination}
		for _, p := range plans {
			destinations := w.Before.DefaultDestinations
			for _, r := range w.Routes {
				if !r.Default && r.Name == p.Name {
					destinations = r.Destinations
				}
			}
			if !slices.Contains(destinations, b.DestinationID) {
				continue
			}
			var target OutputTarget
			for _, t := range b.Targets {
				if oldNames[t.EntryIncarnationID] == p.Name {
					target = t
					break
				}
			}
			if target.ServiceContractID == "" {
				target = OutputTarget{ServiceContractID: b.Destination.ServiceContractID, TargetContractID: "profile", Capabilities: b.Destination.Capabilities, CanonicalTarget: b.DestinationID + "-" + p.Name, ConsumerLocator: b.DestinationID + "-" + p.Name, PayloadEncoding: OutputEncodingRaw, Policy: b.Destination.Policy}
			}
			target.EntryIncarnationID = ID{}
			desired.Targets = append(desired.Targets, NormalOutputTarget{Name: p.Name, Target: target})
		}
		w.Bindings = append(w.Bindings, desired)
	}
	for _, g := range w.Before.Groups {
		var group []string
		for _, id := range g {
			name := oldNames[id]
			if names[name] {
				group = append(group, name)
			}
		}
		if len(group) > 1 {
			w.Groups = append(w.Groups, group)
		}
	}
}

func fixtureDestinationWireLength(d OutputDestination) int {
	n := 4 + len(d.ConfigContractID) + 4 + len(d.ServiceContractID) + 4 + len(d.CanonicalSettings) + 4 + 1
	if d.Policy.ContractID != "" {
		n += 2 + 4 + len(d.Policy.ContractID) + 4 + len(d.Policy.Data)
	}
	return n
}

// full_only: false
func TestGeneratedOutputTransitionChecksCurrentRawSetBoundary(t *testing.T) {
	for _, excess := range []int{0, 1} {
		t.Run(fmt.Sprintf("excess=%d", excess), func(t *testing.T) {
			witness, public, _, _ := generatedOutputFixture(t)
			original, err := DecodeValueEntry(witness.EntryBodies[0])
			if err != nil {
				t.Fatal(err)
			}
			witness.EntryBodies = nil
			witness.EntriesBefore = nil
			public.Rows = nil
			for i := 0; i < 129; i++ {
				entry := original
				slot := uint16(i)
				if i == 0 {
					entry.ValueBytes = make([]byte, excess)
				} else {
					entry.Name = fmt.Sprintf("raw-%03d", i)
					entry.Incarnation = Hash([]byte(entry.Name + " incarnation"))
					entry.ValueState = Hash([]byte(entry.Name + " value"))
					entry.ValueBytes = make([]byte, 65536)
				}
				entry.ContentLength, entry.RetainedLength = uint32(len(entry.ValueBytes)), uint32(len(entry.ValueBytes))
				body, err := EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				digest, err := PublicValueEntryDigest(public.Domain, slot, entry)
				if err != nil {
					t.Fatal(err)
				}
				witness.EntryBodies = append(witness.EntryBodies, body)
				witness.EntriesBefore = append(witness.EntriesBefore, MembershipRow{Name: entry.Name, Slot: slot, Incarnation: entry.Incarnation, EntryDigest: digest, Recipients: entry.Recipients})
				public.Rows = append(public.Rows, PublicStateRow{Name: entry.Name, Slot: slot, EntryDigest: digest})
			}
			inspected := witness.Inspect(public)
			owned, err := witness.Own(public)
			if excess != 0 {
				if inspected != ErrRecordCapacity || err != ErrRecordCapacity || owned != nil {
					t.Fatal("old-current raw excess reached ownership", inspected, err)
				}
				return
			}
			if inspected != nil || err != nil || owned == nil {
				t.Fatal("exact old-current 8 MiB raw set refused", inspected, err)
			}
			// Ownership is independent of the caller, not an RSS/allocation measurement.
			witness.EntryBodies[1][len(witness.EntryBodies[1])-1] ^= 1
			if owned.Inspect(public) != nil {
				t.Fatal("exact boundary retained caller-owned EntryBodies")
			}
		})
	}
}

// full_only: false
func TestGeneratedOutputConfigurationBindsPlannedEntryEncoding(t *testing.T) {
	for _, encoding := range []uint8{OutputEncodingRaw, OutputEncodingBase64} {
		t.Run(fmt.Sprint(encoding), func(t *testing.T) {
			w, _, _, _ := generatedOutputFixture(t)
			configuration := w.Before
			configuration.Bindings[0].Targets[0].PayloadEncoding = encoding
			image, err := EncodeOutputConfiguration(configuration)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, _, err := SplitOutputConfiguration(configuration.DomainID, image)
			if err != nil {
				t.Fatal(err)
			}
			plan := GeneratorPlanBundle{Request: GeneratorRequestCore{Schema: GeneratorApplyRequestCoreSchema, OperationKind: OperationApplyDeclaration, DomainID: configuration.DomainID, OutputConfiguration: descriptor},
				ValueEntryPlans: []GeneratorValueEntryPlan{{Name: "entry", EntryIncarnationID: w.EntriesBefore[0].Incarnation, InputEncoding: InputEncodingRaw, OutputEncoding: encoding}}}
			if _, err := InspectGeneratedOutputConfiguration(plan, image); err != nil {
				t.Fatal("matching selected output image refused", err)
			}
			plan.ValueEntryPlans[0].OutputEncoding = OutputEncodingRaw
			if encoding == OutputEncodingRaw {
				plan.ValueEntryPlans[0].OutputEncoding = OutputEncodingBase64
			}
			if _, err := InspectGeneratedOutputConfiguration(plan, image); err == nil {
				t.Fatal("selected output image ignored planned entry encoding")
			}
		})
	}
}
