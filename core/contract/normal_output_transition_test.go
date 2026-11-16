package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
)

// full_only: false
func TestOutputChangedSubjectsIncludeShadowedDefaultDestination(t *testing.T) {
	witness, _, _, _ := generatedOutputFixture(t)
	before := cloneOutputConfiguration(witness.Before)
	peer := before.Bindings[0]
	peer.DestinationID, peer.IncarnationID = "peer", publicationTestID(201)
	peer.Targets = slices.Clone(peer.Targets)
	peer.Targets[0].CanonicalTarget, peer.Targets[0].ConsumerLocator = "peer-slot", "peer-locator"
	before.Bindings = append(before.Bindings, peer)
	before.DefaultDestinations = []string{"dest", "peer"}
	after := cloneOutputConfiguration(before)
	after.Routes = append(after.Routes, OutputRoute{EntryIncarnationID: peer.Targets[0].EntryIncarnationID, Destinations: []string{"peer"}})
	got, err := OutputConfigurationChangedSubjects(before, after)
	if err != nil {
		t.Fatal(err)
	}
	var want []ChangedSubjectIdentity
	for _, binding := range before.Bindings {
		material := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), before.DomainID[:]...)
		material = append(material, byte(5))
		material = append(material, binding.IncarnationID[:]...)
		material = append(material, make([]byte, 32)...)
		want = append(want, ChangedSubjectIdentity{Kind: ChangedSubjectOutputBinding, Change: ChangedSubjectUpdated, Identity: ID(sha256.Sum256(material))})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("shadowing changed both effective destinations but receipt omitted one", got, want)
	}
}

// full_only: false
func TestNormalOutputEntrySelectors(t *testing.T) {
	t.Run("named_empty", func(t *testing.T) {
		witness, _, _, _ := generatedOutputFixture(t)
		target := witness.Before.Bindings[0].Targets[0]
		target.EntryIncarnationID = ID{}
		incarnation := publicationTestID(96)
		normal := &NormalOutputTransition{Before: witness.Before, BeforeDescriptor: witness.BeforeDescriptor,
			Intent: []CryptoIntentRow{{Name: "", Recipients: witness.EntriesBefore[0].Recipients, ValueSource: Supplied, ConfidentialityClass: Plain}}, Slots: []uint16{0},
			Bindings: []NormalOutputBinding{{DestinationID: "dest", Destination: witness.Before.Bindings[0].Destination, Targets: []NormalOutputTarget{{Name: "", Target: target}}}},
			Routes:   []NormalOutputRoute{{Name: "", Destinations: []string{"dest"}}}}
		plan := IdentityPlan{Operation: publicationTestID(95), Rows: []IdentityRow{{Name: "", Slot: 0, Incarnation: incarnation}}}
		after, _, _, err := normal.ConfigurationAfter(plan)
		want := []OutputRoute{{EntryIncarnationID: incarnation, Destinations: []string{"dest"}}}
		if err != nil || !reflect.DeepEqual(after.Routes, want) {
			t.Fatal("exact empty entry route became defaults", after.Routes, err)
		}
	})
	t.Run("ownership_equality_and_invalid_selectors", func(t *testing.T) {
		witness, _, _, _ := generatedOutputFixture(t)
		normal := &NormalOutputTransition{Before: witness.Before, BeforeDescriptor: witness.BeforeDescriptor,
			Routes: []NormalOutputRoute{{Name: "", Destinations: []string{"dest"}}}}
		owned, err := normal.Own()
		if err != nil || !normal.Equal(owned) {
			t.Fatal("named empty route ownership changed meaning", err)
		}
		normal.Routes[0].Destinations[0] = "changed"
		normal.Routes[0].Name = "changed"
		if owned.Routes[0].Name != "" || !slices.Equal(owned.Routes[0].Destinations, []string{"dest"}) {
			t.Fatal("owned route retained caller metadata")
		}
		defaults, err := owned.Own()
		if err != nil {
			t.Fatal(err)
		}
		defaults.Routes[0].Default = true
		if owned.Equal(defaults) || defaults.Equal(owned) {
			t.Fatal("named empty route equals defaults")
		}
		for _, route := range []NormalOutputRoute{{Default: true, Name: "entry", Destinations: []string{"dest"}}} {
			invalid := *owned
			invalid.Routes = []NormalOutputRoute{route}
			if _, err := invalid.Own(); err == nil {
				t.Fatal("invalid route selector was retained", route)
			}
			if _, _, _, err := invalid.ConfigurationAfter(IdentityPlan{Operation: publicationTestID(95)}); err == nil {
				t.Fatal("invalid route selector was encoded", route)
			}
			if invalid.Inspect(GeneratedSupportRows{Records: witness.Rows.Records, Facts: witness.Rows.Facts}) == nil {
				t.Fatal("invalid route selector was inspected", route)
			}
		}
	})
}

// full_only: false
func TestNormalOutputFreshIDsAndGroups(t *testing.T) {
	domain, operation := publicationTestID(91), publicationTestID(92)
	destination := "destination"
	input := append([]byte("ENKV/OUTPUT/APPLY-BINDING/v1\x00"), domain[:]...)
	input = append(input, operation[:]...)
	input = binary.BigEndian.AppendUint32(input, uint32(len(destination)))
	input = append(input, destination...)
	want := ID(sha256.Sum256(input))
	binding, err := NormalOutputBindingID(domain, operation, destination)
	if err != nil || binding != want {
		t.Fatal("framed binding identity", err)
	}
	coordinate := publicationTestID(93)
	input = append([]byte("ENKV/OUTPUT/APPLY-PUBLICATION/v1\x00"), domain[:]...)
	input = append(input, operation[:]...)
	input = append(input, coordinate[:]...)
	publication, err := NormalOutputPublicationID(domain, operation, coordinate)
	if err != nil || publication != ID(sha256.Sum256(input)) || publication == binding {
		t.Fatal("purpose-separated publication identity", err)
	}
	for _, fault := range []string{"domain", "operation", "destination"} {
		d, o, name := domain, operation, destination
		switch fault {
		case "domain":
			d = ID{}
		case "operation":
			o = ID{}
		case "destination":
			name = ""
		}
		if _, err := NormalOutputBindingID(d, o, name); err == nil {
			t.Fatal("invalid binding identity admitted", fault)
		}
	}
	before := []OutputBinding{{DestinationID: "group", IncarnationID: binding, Targets: []OutputTarget{{EntryIncarnationID: publicationTestID(1)}, {EntryIncarnationID: publicationTestID(2)}}}}
	same := before[0]
	if !OutputBindingIncarnationPreserved(before, same) {
		t.Fatal("unchanged declared destination not retained")
	}
	for _, fault := range []string{"destination", "membership", "partial", "incarnation"} {
		t.Run(fault, func(t *testing.T) {
			changed := same
			changed.Targets = slices.Clone(same.Targets)
			switch fault {
			case "destination":
				changed.DestinationID = "other"
			case "membership":
				changed.Targets[1].EntryIncarnationID = publicationTestID(3)
			case "partial":
				changed.Targets = changed.Targets[:1]
			case "incarnation":
				changed.IncarnationID = publicationTestID(4)
			}
			wantPreserved := fault == "membership" || fault == "partial"
			if OutputBindingIncarnationPreserved(before, changed) != wantPreserved {
				t.Fatal("destination incarnation changed independently of its identity", fault)
			}
		})
	}
}

// full_only: false
func TestNormalOutputFreshBindingCollisions(t *testing.T) {
	witness, _, _, _ := generatedOutputFixture(t)
	operation, incarnation := publicationTestID(95), publicationTestID(96)
	target := witness.Before.Bindings[0].Targets[0]
	target.EntryIncarnationID = ID{}
	normal := &NormalOutputTransition{Before: witness.Before, BeforeDescriptor: witness.BeforeDescriptor, EntriesBefore: witness.EntriesBefore,
		Intent: []CryptoIntentRow{{Name: "entry", Recipients: witness.EntriesBefore[0].Recipients, ValueSource: Supplied, ConfidentialityClass: Plain, InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw}}, Slots: []uint16{0},
		Bindings: []NormalOutputBinding{{DestinationID: "new", Destination: witness.Before.Bindings[0].Destination, Targets: []NormalOutputTarget{{Name: "entry", Target: target}}}}, Routes: []NormalOutputRoute{{Default: true, Destinations: []string{"new"}}}}
	plan := IdentityPlan{Operation: operation, Rows: []IdentityRow{{Name: "entry", Slot: 0, Incarnation: incarnation}}}
	selected := GeneratedSupportRows{Records: witness.Rows.Records, Facts: witness.Rows.Facts}
	if normal.Inspect(selected) != nil {
		t.Fatal("normal output fixture not structurally admitted")
	}
	binding, err := NormalOutputBindingID(witness.Before.DomainID, operation, "new")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normal.SupportAfter(plan, selected); err != nil {
		t.Fatal("valid normal rebind", err)
	}
	t.Run("canonical empty policy ownership", func(t *testing.T) {
		before, _, _, _ := generatedOutputFixture(t)
		policy := OutputPolicy{ContractID: "private-policy/v1", Data: []byte{}}
		before.Before.Bindings[0].Targets[0].Policy = policy
		before.Before.Bindings[0].Destination.Policy = cloneOutputPolicy(policy)
		caller := &NormalOutputTransition{Before: before.Before, Bindings: []NormalOutputBinding{{Targets: []NormalOutputTarget{{Target: OutputTarget{Policy: policy}}}}}}
		owned, err := caller.Own()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(owned.Before.Bindings[0].Targets[0].Policy, policy) || !reflect.DeepEqual(owned.Bindings[0].Targets[0].Target.Policy, policy) || owned.Before.Routes == nil {
			t.Fatal("normal ownership changed canonical empty policy")
		}
	})
	t.Run("complete caller ownership", func(t *testing.T) {
		for _, data := range [][]byte{{0, 255, 1}, []byte("first,second")} {
			before, _, _, _ := generatedOutputFixture(t)
			policy := OutputPolicy{ContractID: "private-policy/v1", Data: bytes.Clone(data)}
			before.Before.Bindings[0].Targets[0].Policy = policy
			before.Before.Bindings[0].Destination.Policy = cloneOutputPolicy(policy)
			before.Before.Routes = []OutputRoute{{EntryIncarnationID: before.Before.Bindings[0].Targets[0].EntryIncarnationID, Destinations: []string{"dest"}}}
			target := before.Before.Bindings[0].Targets[0]
			target.EntryIncarnationID = ID{}
			caller := &NormalOutputTransition{Before: before.Before, EntriesBefore: before.EntriesBefore,
				Intent: []CryptoIntentRow{{Name: "entry", Recipients: []ID{publicationTestID(5)}}}, Slots: []uint16{0},
				Bindings: []NormalOutputBinding{{DestinationID: "dest", Destination: before.Before.Bindings[0].Destination, Targets: []NormalOutputTarget{{Name: "entry", Target: target}}}},
				Routes:   []NormalOutputRoute{{Name: "entry", Destinations: []string{"dest"}}}}
			first, err := caller.Own()
			if err != nil {
				t.Fatal(err)
			}
			second, err := caller.Own()
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(caller)
			if err != nil {
				t.Fatal(err)
			}
			mutateOutputConfigurationCaller(&caller.Before)
			caller.EntriesBefore[0].Recipients[0] = ID{}
			caller.EntriesBefore[0] = MembershipRow{}
			caller.Intent[0].Recipients[0] = ID{}
			caller.Intent[0] = CryptoIntentRow{}
			caller.Slots[0]++
			p := &caller.Bindings[0].Targets[0].Target.Policy
			p.Data[0]++
			caller.Bindings[0].Targets[0] = NormalOutputTarget{}
			caller.Bindings[0] = NormalOutputBinding{}
			caller.Routes[0].Destinations[0] = "changed"
			caller.Routes[0] = NormalOutputRoute{}
			for _, owned := range []*NormalOutputTransition{first, second} {
				got, err := json.Marshal(owned)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("normal ownership retained caller slices", data, err)
				}
			}
			first.Before.Bindings[0].Targets[0].Policy = OutputPolicy{}
			first.EntriesBefore[0].Recipients[0] = ID{}
			first.Intent[0].Recipients[0] = ID{}
			first.Slots[0]++
			first.Bindings[0].Targets[0] = NormalOutputTarget{}
			first.Routes[0].Destinations[0] = "changed"
			got, err := json.Marshal(second)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("normal ownership calls share writable data", data, err)
			}
		}
	})
	for _, fault := range []string{"plan-row", "plan-page", "retained-binding", "retained-entry"} {
		t.Run(fault, func(t *testing.T) {
			bad := plan
			bad.Rows = slices.Clone(plan.Rows)
			v, err := normal.Own()
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "plan-row":
				bad.Rows[0].ValueState = binding
			case "plan-page":
				bad.Pages = []IdentityPage{{Object: binding}}
			case "retained-binding":
				v.Before.Bindings[0].IncarnationID = binding
			case "retained-entry":
				v.EntriesBefore[0].Incarnation = binding
			}
			if _, err := v.SupportAfter(bad, selected); err == nil {
				t.Fatal("fresh output binding reused an occupied identity")
			}
		})
	}
}
