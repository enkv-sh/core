package contract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func publicationTestID(b byte) ID {
	var v ID
	for i := range v {
		v[i] = b
	}
	return v
}

// full_only: false
func TestOutputConfigurationEmptyRoutingHasExactDeclaredFraming(t *testing.T) {
	value := OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: publicationTestID(1)}
	// Schema 5, zero bindings, zero groups, five-byte routing section:
	// routing schema 3, zero default destinations, zero entry replacements.
	want := []byte{0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 3, 0, 0, 0}
	got, err := EncodeOutputConfiguration(value)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("empty declared routing image: got %x, want %x: %v", got, want, err)
	}
	parsed, routing, err := InspectOutputConfiguration(value.DomainID, want)
	if err != nil || routing != 5 || len(parsed.Routes) != 0 {
		t.Fatal("empty declared routing image did not round trip", routing, err)
	}
	old := []byte{0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 2, 0, 0, 0, 0}
	if _, _, err := InspectOutputConfiguration(value.DomainID, old); err == nil {
		t.Fatal("superseded routing image accepted")
	}
}

// full_only: false
func TestOutputConfigurationPreservesDeclaredReplacementPresence(t *testing.T) {
	value := OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: publicationTestID(1), DefaultDestinations: []string{"a"},
		Bindings: []OutputBinding{{DestinationID: "a", IncarnationID: publicationTestID(2), Destination: outputTestDestination(OutputPolicy{}), Targets: []OutputTarget{}}},
		Routes:   []OutputRoute{{EntryIncarnationID: publicationTestID(3)}, {EntryIncarnationID: publicationTestID(4), Destinations: []string{"a"}}}}
	// Routing schema/default/list, then two sorted exact-entry replacements.
	want := []byte{0, 3, 1, 0, 0, 0, 1, 'a', 0, 2}
	want = append(want, bytes.Repeat([]byte{3}, 32)...)
	want = append(want, 0)
	want = append(want, bytes.Repeat([]byte{4}, 32)...)
	want = append(want, 1, 0, 0, 0, 1, 'a')
	image, err := EncodeOutputConfiguration(value)
	if err != nil || len(image) < len(want) || !bytes.Equal(image[len(image)-len(want):], want) {
		t.Fatal("declared replacement framing differs", err)
	}
	parsed, length, err := InspectOutputConfiguration(value.DomainID, image)
	if err != nil || int(length) != len(want) || !reflect.DeepEqual(parsed, value) {
		t.Fatal("empty or equal-to-default replacement lost", err)
	}
	descriptor, parts, err := SplitOutputConfiguration(value.DomainID, image)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	visit := OutputConfigurationVisit{Route: func(entry ID, destinations []string) error {
		switch seen {
		case 0:
			if !entry.IsZero() || !reflect.DeepEqual(destinations, []string{"a"}) {
				t.Fatal("streamed default differs")
			}
		case 1:
			if entry != publicationTestID(3) || len(destinations) != 0 {
				t.Fatal("streamed explicit empty replacement differs")
			}
		case 2:
			if entry != publicationTestID(4) || !reflect.DeepEqual(destinations, []string{"a"}) {
				t.Fatal("streamed equal-to-default replacement differs")
			}
		default:
			t.Fatal("unexpected route callback")
		}
		seen++
		return nil
	}}
	if err := VisitOutputConfigurationSource(value.DomainID, descriptor, func(i uint16) (OutputConfigurationSlice, error) { return parts[i], nil }, visit); err != nil || seen != 3 {
		t.Fatal("streamed replacement presence differs", seen, err)
	}
	for _, condition := range []string{"zero-entry", "duplicate-entry", "unsorted-entries", "duplicate-destination", "unknown-destination", "too-many-destinations", "too-many-entries"} {
		t.Run(condition, func(t *testing.T) {
			invalid := cloneOutputConfiguration(value)
			switch condition {
			case "zero-entry":
				invalid.Routes[0].EntryIncarnationID = ID{}
			case "duplicate-entry":
				invalid.Routes[1].EntryIncarnationID = invalid.Routes[0].EntryIncarnationID
			case "unsorted-entries":
				invalid.Routes[0], invalid.Routes[1] = invalid.Routes[1], invalid.Routes[0]
			case "duplicate-destination":
				invalid.DefaultDestinations = []string{"a", "a"}
			case "unknown-destination":
				invalid.Routes[0].Destinations = []string{"missing"}
			case "too-many-destinations":
				invalid.DefaultDestinations = make([]string, 9)
			case "too-many-entries":
				invalid.Routes = make([]OutputRoute, CryptoMaxValueEntries+1)
			}
			if _, err := EncodeOutputConfiguration(invalid); err == nil {
				t.Fatal("invalid declared routing accepted")
			}
		})
	}
}

func outputTestTarget(entry byte, slot string, policy OutputPolicy) OutputTarget {
	return OutputTarget{EntryIncarnationID: publicationTestID(entry), ServiceContractID: "p", TargetContractID: "q", CanonicalTarget: slot, ConsumerLocator: "c", TargetData: []byte("public"), PayloadEncoding: OutputEncodingRaw, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot, Policy: policy}
}
func outputTestPolicy() OutputPolicy { return OutputPolicy{ContractID: "class", Data: []byte("none")} }
func outputTestDestination(policy OutputPolicy) OutputDestination {
	return OutputDestination{ConfigContractID: "config", ServiceContractID: "p", CanonicalSettings: []byte(`{"k":"v"}`), Policy: policy, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}
}

// full_only: false
func TestOutputConfigurationV5IndependentTargetFraming(t *testing.T) {
	domain := publicationTestID(1)
	target := outputTestTarget(3, "s", OutputPolicy{ContractID: "c", Data: []byte{0, 255}})
	target.ConsumerLocator = "l"
	target.TargetData = []byte{7}
	v := OutputConfiguration{Schema: 5, DomainID: domain, Bindings: []OutputBinding{{DestinationID: "d", IncarnationID: publicationTestID(2), Destination: outputTestDestination(target.Policy), Targets: []OutputTarget{target}}}, Routes: []OutputRoute{}}
	putB := func(dst []byte, s string) []byte {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
		return append(dst, s...)
	}
	// Independent schema5 field order: destination/config/settings/policy/capabilities,
	// no overrides, one target with raw bytes and typed flags, then groups/routing.
	policy := putB([]byte{0, 3}, "c")
	policy = putB(policy, string([]byte{0, 255}))
	want := putB([]byte{0, 5, 0, 1}, "d")
	want = append(want, bytes.Repeat([]byte{2}, 32)...)
	want = putB(want, "config")
	want = putB(want, "p")
	want = putB(want, `{"k":"v"}`)
	want = putB(want, string(policy))
	want = append(want, 63, 0, 1)
	want = append(want, bytes.Repeat([]byte{3}, 32)...)
	for _, field := range []string{"p", "q", "s", "l", string([]byte{7})} {
		want = putB(want, field)
	}
	want = append(want, 1, 63, 0)
	want = append(want, make([]byte, 16)...) // Four zero u32 interval endpoints.
	want = putB(want, string(policy))
	want = append(want, 0, 0)
	want = putB(want, string([]byte{0, 3, 0, 0, 0}))
	got, err := EncodeOutputConfiguration(v)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("independent configuration framing", err)
	}
	parsed, _, err := InspectOutputConfiguration(domain, want)
	if err != nil || !reflect.DeepEqual(parsed, v) {
		t.Fatal("independent image meaning", err)
	}
	descriptor, rows, err := SplitOutputConfiguration(domain, got)
	preimage := append([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"), domain[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(want)))
	digest := sha256.Sum256(append(preimage, want...))
	wantDescriptor := OutputConfigurationDescriptor{Schema: 5, ConfigurationDigest: digest, TotalLength: uint32(len(want)), SliceCount: 1, BindingCount: 1, RoutingLength: 5}
	if err != nil || descriptor != wantDescriptor || len(rows) != 1 || !bytes.Equal(rows[0].SliceBytes, want) {
		t.Fatal("independent descriptor", err)
	}
	slicePreimage := append([]byte("ENKV/OUTPUT/CONFIGURATION-SLICE/v5\x00"), domain[:]...)
	slicePreimage = append(slicePreimage, digest[:]...)
	slicePreimage = append(slicePreimage, 0, 0)
	if id, err := OutputConfigurationSliceID(domain, digest, 0); err != nil || id != sha256.Sum256(slicePreimage) {
		t.Fatal("independent slice identity", err)
	}
	counted, routing, err := writeOutputConfiguration(v, false)
	if err != nil || counted.b != nil || counted.length != len(want) || routing != 5 {
		t.Fatal("counter framing", err)
	}
	encodedDescriptor, encodedRows, err := encodedOutputConfiguration(v)
	if err != nil || encodedDescriptor != wantDescriptor || !reflect.DeepEqual(encodedRows, rows) {
		t.Fatal("encoded split", err)
	}
	got[0] ^= 1
	if !bytes.Equal(rows[0].SliceBytes, want) {
		t.Fatal("split retained caller backing")
	}
}

// full_only: false
func TestOutputConfigurationV5CanonicalEmpty(t *testing.T) {
	domain := publicationTestID(1)
	image, err := EncodeOutputConfiguration(OutputConfiguration{Schema: 5, DomainID: domain})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 5, 0, 0, 0, 0, 0, 0, 0, 5, 0, 3, 0, 0, 0}
	if !bytes.Equal(image, want) {
		t.Fatalf("empty v5 image = %x want %x", image, want)
	}
	counted, routingLength, err := writeOutputConfiguration(OutputConfiguration{Schema: 5, DomainID: domain}, false)
	if err != nil || counted.b != nil || counted.length != 15 || routingLength != 5 {
		t.Fatal("counted empty image", err)
	}
	descriptor, rows, err := SplitOutputConfiguration(domain, image)
	if err != nil || descriptor.Schema != 5 || descriptor.TotalLength != 15 || descriptor.SliceCount != 1 ||
		descriptor.BindingCount != 0 || descriptor.RoutingLength != 5 || len(rows) != 1 {
		t.Fatalf("descriptor=%#v rows=%d err=%v", descriptor, len(rows), err)
	}
	input := append([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"), domain[:]...)
	input = binary.BigEndian.AppendUint32(input, uint32(len(want)))
	input = append(input, want...)
	if got := sha256.Sum256(input); descriptor.ConfigurationDigest != got {
		t.Fatalf("digest=%x want=%x", descriptor.ConfigurationDigest, got)
	}
	if err := ValidateOutputConfigurationSource(domain, descriptor, func(uint16) (OutputConfigurationSlice, error) { return rows[0], nil }); err != nil {
		t.Fatal(err)
	}
	if joined, err := JoinOutputConfiguration(domain, descriptor, rows); err != nil || !bytes.Equal(joined, want) {
		t.Fatalf("join=%x err=%v", joined, err)
	}
	if _, err := JoinOutputConfiguration(domain, descriptor, nil); err == nil {
		t.Fatal("missing mandatory empty slice accepted")
	}
}

// full_only: false
func TestOutputConfigurationStreamRelationVisitorBindsOnlyValidatedSource(t *testing.T) {
	domain := publicationTestID(1)
	binding := publicationTestID(2)
	entry := publicationTestID(3)
	configuration := OutputConfiguration{Schema: 5, DomainID: domain,
		Bindings: []OutputBinding{{DestinationID: "d", IncarnationID: binding,
			Destination: outputTestDestination(outputTestPolicy()), Targets: []OutputTarget{outputTestTarget(3, "slot", outputTestPolicy())}}},
		Routes: []OutputRoute{{EntryIncarnationID: entry, Destinations: []string{"d"}}}}
	image, err := EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, slices, err := SplitOutputConfiguration(domain, image)
	if err != nil || len(slices) != 1 {
		t.Fatalf("split slices=%d err=%v", len(slices), err)
	}
	coordinate, err := PublicationCoordinateID(domain, "p", "slot")
	if err != nil {
		t.Fatal(err)
	}
	var targets, routes int
	visit := OutputConfigurationVisit{
		Target: func(gotBinding, gotEntry, gotCoordinate ID, destination string) error {
			if gotBinding != binding || gotEntry != entry || gotCoordinate != coordinate || destination != "d" {
				t.Fatal("target relation differs from selected declaration")
			}
			targets++
			return nil
		},
		Route: func(gotEntry ID, destinations []string) error {
			if gotEntry.IsZero() {
				if len(destinations) != 0 {
					t.Fatal("unexpected default destinations")
				}
				routes++
				return nil
			}
			if gotEntry != entry || !reflect.DeepEqual(destinations, []string{"d"}) {
				t.Fatal("route relation differs from selected declaration")
			}
			routes++
			return nil
		},
	}
	next := func(index uint16) (OutputConfigurationSlice, error) { return slices[index], nil }
	if err := VisitOutputConfigurationSource(domain, descriptor, next, visit); err != nil || targets != 1 || routes != 2 {
		t.Fatalf("valid relation targets=%d routes=%d err=%v", targets, routes, err)
	}
	wrong := descriptor
	wrong.ConfigurationDigest = publicationTestID(99)
	wrongNext := func(index uint16) (OutputConfigurationSlice, error) {
		row := slices[index]
		row.ConfigurationDigest = wrong.ConfigurationDigest
		return row, nil
	}
	targets, routes = 0, 0
	if err := VisitOutputConfigurationSource(domain, wrong, wrongNext, visit); err == nil || targets != 1 || routes != 2 {
		t.Fatalf("final digest rejection/callback order targets=%d routes=%d err=%v", targets, routes, err)
	}
	// Keep the declared full length and all target bytes. The source ends
	// after the routing length, so the parser reaches Target before EOF.
	lateEOF := bytes.NewReader(image[:len(image)-int(descriptor.RoutingLength)])
	targets, routes = 0, 0
	if _, _, err := parseOutputConfiguration(domain, lateEOF, len(image), false, nil, &visit); err == nil || targets != 1 || routes != 0 {
		t.Fatalf("late EOF rejection targets=%d routes=%d err=%v", targets, routes, err)
	}
	// A callback is provisional. It cannot publish these counts when the
	// complete descriptor fails, even if it observed a valid target first.
}

// full_only: false
func TestOutputConfigurationStreamVisitorOwnsPublicFields(t *testing.T) {
	domain, binding := publicationTestID(1), publicationTestID(2)
	want := []OutputTarget{
		outputTestTarget(3, "first-slot", OutputPolicy{ContractID: "numbers", Data: []byte{7, 11}}),
		outputTestTarget(4, "second-slot", OutputPolicy{ContractID: "texts", Data: []byte("principal:a,principal:z")}),
	}
	configuration := OutputConfiguration{Schema: 5, DomainID: domain,
		Bindings: []OutputBinding{
			{DestinationID: "d", IncarnationID: binding, Destination: outputTestDestination(want[0].Policy), Targets: want[:1]},
			{DestinationID: "e", IncarnationID: publicationTestID(6), Destination: outputTestDestination(want[1].Policy), Targets: want[1:]},
		},
		Routes: []OutputRoute{
			{EntryIncarnationID: publicationTestID(3), Destinations: []string{"d"}},
			{EntryIncarnationID: publicationTestID(4), Destinations: []string{"e"}},
		}}
	body, err := EncodeOutputConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, pieces, err := SplitOutputConfiguration(domain, body)
	if err != nil || len(pieces) != 1 {
		t.Fatal("small complete fixture", err)
	}
	var got []OutputTarget
	routes := 0
	visit := OutputConfigurationVisit{
		TargetFields: func(gotBinding ID, destination string, target OutputTarget) error {
			wantBinding, wantDestination := binding, "d"
			if target.EntryIncarnationID == publicationTestID(4) {
				wantBinding, wantDestination = publicationTestID(6), "e"
			}
			if gotBinding != wantBinding || destination != wantDestination {
				t.Fatal("target context differs")
			}
			got = append(got, target)
			return nil
		},
		Route: func(entry ID, destinations []string) error {
			if entry.IsZero() {
				if len(destinations) != 0 {
					t.Fatal("unexpected default destinations")
				}
				routes++
				return nil
			}
			wantDestination := "d"
			if entry == publicationTestID(4) {
				wantDestination = "e"
			} else if entry != publicationTestID(3) {
				t.Fatal("route entry differs")
			}
			if !reflect.DeepEqual(destinations, []string{wantDestination}) {
				t.Fatal("route context differs")
			}
			routes++
			return nil
		},
	}
	next := func(index uint16) (OutputConfigurationSlice, error) { return pieces[index], nil }
	if err := VisitOutputConfigurationSource(domain, descriptor, next, visit); err != nil || !reflect.DeepEqual(got, want) || routes != 3 {
		t.Fatalf("full public fields differ: targets=%d routes=%d err=%v", len(got), routes, err)
	}
	owned := got
	if len(owned[0].Policy.Data) != 2 || len(owned[1].Policy.Data) != 23 {
		t.Fatal("policy backing is not exact")
	}
	callbackFailure := errors.New("target visitor stopped")
	stopped := visit
	stopped.TargetFields = func(ID, string, OutputTarget) error { return callbackFailure }
	routes = 0
	if err := VisitOutputConfigurationSource(domain, descriptor, next, stopped); !errors.Is(err, callbackFailure) || routes != 0 {
		t.Fatal("callback failure was lost or traversal continued", err)
	}
	wrong := descriptor
	wrong.ConfigurationDigest = publicationTestID(99)
	wrongNext := func(index uint16) (OutputConfigurationSlice, error) {
		row := pieces[index]
		row.ConfigurationDigest = wrong.ConfigurationDigest
		return row, nil
	}
	got, routes = nil, 0
	if err := VisitOutputConfigurationSource(domain, wrong, wrongNext, visit); err == nil || len(got) != 2 || routes != 3 {
		t.Fatal("provisional fields escaped final digest refusal", err)
	}
	got, routes = nil, 0
	short := bytes.NewReader(body[:len(body)-int(descriptor.RoutingLength)])
	if _, _, err := parseOutputConfiguration(domain, short, len(body), false, nil, &visit); err == nil || len(got) != 2 || routes != 0 {
		t.Fatal("provisional fields escaped late grammar refusal", err)
	}
	for i := range pieces {
		clear(pieces[i].SliceBytes)
	}
	clear(body)
	if !reflect.DeepEqual(owned, want) {
		t.Fatal("visitor retained borrowed source bytes")
	}
	t.Run("decoded-collections-exact-backing", func(t *testing.T) {
		for _, count := range []int{0, 3} {
			want := OutputConfiguration{Schema: 5, DomainID: domain, Bindings: []OutputBinding{{DestinationID: "d", IncarnationID: binding, Destination: outputTestDestination(outputTestPolicy())}}, Routes: []OutputRoute{}}
			for i := 0; i < 3; i++ {
				target := outputTestTarget(byte(i+3), fmt.Sprintf("slot-%d", i), outputTestPolicy())
				if count != 0 {
					target.PayloadEncoding = OutputEncodingBase64
					want.Groups = append(want.Groups, []ID{target.EntryIncarnationID})
				}
				want.Bindings[0].Targets = append(want.Bindings[0].Targets, target)
			}
			body, err := EncodeOutputConfiguration(want)
			if err != nil {
				t.Fatal(err)
			}
			descriptor, parts, err := SplitOutputConfiguration(domain, body)
			if err != nil {
				t.Fatal(err)
			}
			next := func(i uint16) (OutputConfigurationSlice, error) { return parts[i], nil }
			for _, read := range []func() (OutputConfiguration, error){func() (OutputConfiguration, error) {
				v, _, err := InspectOutputConfiguration(domain, body)
				return v, err
			}, func() (OutputConfiguration, error) { return InspectOutputConfigurationSource(domain, descriptor, next) }} {
				got, err := read()
				if err != nil || !reflect.DeepEqual(got, want) {
					t.Fatal("collection meaning", err)
				}
				if len(got.Groups) != count || cap(got.Groups) != count {
					t.Fatal("collection backing")
				}
				if count == 0 && got.Groups != nil {
					t.Fatal("empty collection nil meaning")
				}
			}
			var retained OutputDestination
			calls := 0
			err = VisitOutputConfigurationSource(domain, descriptor, next, OutputConfigurationVisit{Binding: func(_ ID, _ string, v OutputDestination) error {
				calls++
				retained = v
				return nil
			}})
			if err != nil || calls != 1 {
				t.Fatal("binding visitor", err)
			}
			clear(body)
			for i := range parts {
				clear(parts[i].SliceBytes)
			}
			if !reflect.DeepEqual(retained, want.Bindings[0].Destination) {
				t.Fatal("binding visitor borrowed source backing")
			}
		}
	})
}

// full_only: false
func TestOutputPolicyOpaqueDataExactBoundary(t *testing.T) {
	p := OutputPolicy{ContractID: strings.Repeat("x", 256), Data: bytes.Repeat([]byte{255}, 524546)}
	body, err := EncodeOutputPolicy(p)
	if err != nil || len(body) != 524812 {
		t.Fatal("policy maximum", len(body), err)
	}
	counted, err := writeOutputPolicy(p, false)
	if err != nil || counted.b != nil || counted.length != 2+4+256+4+524546 {
		t.Fatal("policy counter maximum", err)
	}
	got, err := InspectOutputPolicy(body)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("opaque policy bytes", err)
	}
	p.Data = append(p.Data, 0)
	if _, err := EncodeOutputPolicy(p); err == nil {
		t.Fatal("policy data max+1")
	}
	if _, err := InspectOutputPolicy(append(body, 0)); err == nil {
		t.Fatal("policy record max+1")
	}
}

// full_only: false
func TestOutputPolicyPresenceIdentityAndOpaqueBytes(t *testing.T) {
	absent, err := EncodeOutputPolicy(OutputPolicy{})
	if err != nil || len(absent) != 0 {
		t.Fatal("absent policy", err)
	}
	present, err := EncodeOutputPolicy(OutputPolicy{ContractID: "private-policy"})
	if err != nil || len(present) == 0 {
		t.Fatal("present empty policy", err)
	}
	if _, err := EncodeOutputPolicy(OutputPolicy{Data: []byte{1}}); err == nil {
		t.Fatal("data without identity")
	}
	p := OutputPolicy{ContractID: "private-policy", Data: []byte{0, 255, 10, 0}}
	body, err := EncodeOutputPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := InspectOutputPolicy(body)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("opaque bytes interpreted", err)
	}
	domain := publicationTestID(1)
	preimage := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), domain[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, 14)
	preimage = append(preimage, "private-policy"...)
	preimage = binary.BigEndian.AppendUint32(preimage, 4)
	preimage = append(preimage, 0, 255, 10, 0)
	digest, err := OutputPolicyDigest(domain, p)
	if err != nil || digest != sha256.Sum256(preimage) {
		t.Fatal("independent policy digest", err)
	}
	p.ContractID = "other"
	if other, err := OutputPolicyDigest(domain, p); err != nil || other == digest {
		t.Fatal("policy identity omitted", err)
	}
}

// full_only: false
func TestOutputConfigurationSliceExactPagePairBoundary(t *testing.T) {
	page := RequiredSupportPageHeaderLength + 2*(OutputConfigurationSliceFramedOverhead+MaxOutputConfigurationSliceBytes)
	if page != MaxRequiredSupportPageLength-1 || page+2 <= MaxRequiredSupportPageLength {
		t.Fatalf("two slices use %d of %d", page, MaxRequiredSupportPageLength)
	}
	if got := (MaxOutputConfigurationBytes + MaxOutputConfigurationSliceBytes - 1) / MaxOutputConfigurationSliceBytes; got != MaxOutputConfigurationSlices {
		t.Fatalf("full image needs %d slices, allowed %d", got, MaxOutputConfigurationSlices)
	}
	row := OutputConfigurationSlice{Schema: 5, DomainID: publicationTestID(1), ConfigurationDigest: publicationTestID(2),
		SliceCount: 1, TotalLength: MaxOutputConfigurationSliceBytes, SliceBytes: make([]byte, MaxOutputConfigurationSliceBytes)}
	if encoded, err := EncodeOutputConfigurationSlice(row); err != nil || len(encoded)+SupportRecordOverhead != OutputConfigurationSliceFramedOverhead+MaxOutputConfigurationSliceBytes {
		t.Fatalf("slice encoded=%d err=%v", len(encoded), err)
	}
	row.TotalLength++
	row.SliceCount = 2
	row.SliceBytes = make([]byte, MaxOutputConfigurationSliceBytes+1)
	if _, err := EncodeOutputConfigurationSlice(row); err == nil {
		t.Fatal("oversize slice accepted")
	}
	descriptor := OutputConfigurationDescriptor{Schema: 5, ConfigurationDigest: publicationTestID(2),
		TotalLength: MaxOutputConfigurationBytes, SliceCount: MaxOutputConfigurationSlices, RoutingLength: MaxOutputRoutingBytes - 4}
	if _, err := EncodeOutputConfigurationDescriptor(descriptor); err != nil {
		t.Fatal(err)
	}
	descriptor.TotalLength++
	if _, err := EncodeOutputConfigurationDescriptor(descriptor); err == nil {
		t.Fatal("image max+1 accepted")
	}
}

// full_only: false
func TestOutputConfigurationV5TargetsRoutingAndAliases(t *testing.T) {
	domain := publicationTestID(1)
	base := OutputConfiguration{Schema: 5, DomainID: domain, Bindings: []OutputBinding{
		{IncarnationID: publicationTestID(2), DestinationID: "a", Destination: outputTestDestination(outputTestPolicy()), Targets: []OutputTarget{outputTestTarget(10, "slot-a", outputTestPolicy())}},
		{IncarnationID: publicationTestID(3), DestinationID: "b", Destination: outputTestDestination(outputTestPolicy()), Targets: []OutputTarget{outputTestTarget(10, "slot-b", outputTestPolicy())}},
	}, Routes: []OutputRoute{{EntryIncarnationID: publicationTestID(10), Destinations: []string{"a", "b"}}}}
	image, err := EncodeOutputConfiguration(base)
	if err != nil {
		t.Fatal(err)
	}
	parsed, routing, err := InspectOutputConfiguration(domain, image)
	if err != nil || len(parsed.Bindings) != 2 || len(parsed.Bindings[0].Targets) != 1 || routing == 0 {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	desc, rows, err := SplitOutputConfiguration(domain, image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := JoinOutputConfiguration(domain, desc, rows); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.Bindings = append([]OutputBinding(nil), base.Bindings...)
	changed.Bindings[1].Targets = []OutputTarget{outputTestTarget(10, "slot-a", outputTestPolicy())}
	changed.Bindings[1].Targets[0].TargetContractID = "another-target-schema"
	changed.Bindings[1].Destination.ConfigContractID = "another-config-contract"
	if _, _, err := writeOutputConfiguration(changed, false); !errors.Is(err, ErrRecord) {
		t.Fatal("counted invalid configuration", err)
	}
	if _, err := EncodeOutputConfiguration(changed); err == nil {
		t.Fatal("duplicate physical slot accepted")
	}
	changed.Bindings[1].Targets = []OutputTarget{outputTestTarget(11, "slot-b", outputTestPolicy())}
	// Effective membership needs Core's complete entry and recipient table.
	// The codec preserves these distinct typed facts for that admission check.
	if _, _, err := writeOutputConfiguration(changed, false); err != nil {
		t.Fatal("structurally valid route and target facts refused", err)
	}
	if image, err := EncodeOutputConfiguration(changed); err != nil {
		t.Fatal("typed route and target facts refused", err)
	} else if parsed, _, err := InspectOutputConfiguration(domain, image); err != nil || parsed.Bindings[1].Targets[0].EntryIncarnationID != publicationTestID(11) || parsed.Routes[0].EntryIncarnationID != publicationTestID(10) {
		t.Fatal("codec repaired distinct route and target entry facts", err)
	}
	changed = base
	changed.DefaultDestinations = []string{"missing"}
	if _, _, err := writeOutputConfiguration(changed, false); !errors.Is(err, ErrRecord) {
		t.Fatal("counted invalid configuration", err)
	}
	if _, err := EncodeOutputConfiguration(changed); err == nil {
		t.Fatal("unknown route destination accepted")
	}
	changed = base
	changed.Bindings = append([]OutputBinding(nil), base.Bindings...)
	changed.Bindings[0].Targets = []OutputTarget{outputTestTarget(10, "slot-a", OutputPolicy{Data: []byte{9, 7}})}
	changed.Bindings[0].Destination.Policy = changed.Bindings[0].Targets[0].Policy
	if _, _, err := writeOutputConfiguration(changed, false); !errors.Is(err, ErrRecord) {
		t.Fatal("counted invalid configuration", err)
	}
	if _, err := EncodeOutputConfiguration(changed); err == nil {
		t.Fatal("policy without identity accepted")
	}
}

// full_only: true
// Proves the complete 32 MiB declaration bound with 1,024 targets.
func TestOutputConfigurationDeclarationExactLimit(t *testing.T) {
	const limit = 32 << 20
	domain := publicationTestID(1)
	v := OutputConfiguration{Schema: 5, DomainID: domain, Bindings: make([]OutputBinding, 2)}
	for b := range v.Bindings {
		policy := OutputPolicy{ContractID: "a", Data: bytes.Repeat([]byte{1}, 32605)}
		v.Bindings[b] = OutputBinding{IncarnationID: publicationTestID(byte(b + 2)), DestinationID: string(rune('a' + b)), Destination: outputTestDestination(policy), Targets: make([]OutputTarget, 512)}
		for j := range v.Bindings[b].Targets {
			v.Bindings[b].Targets[j] = outputTestTarget(byte(j%255+1), fmt.Sprintf("%04d", b*512+j), policy)
			binary.BigEndian.PutUint32(v.Bindings[b].Targets[j].EntryIncarnationID[:4], uint32(j+1))
		}
	}
	first := &v.Bindings[0].Targets[0]
	first.ConsumerLocator = strings.Repeat("c", 155)
	// Independent schema5 lengths: policy P=11+n (one-byte identity), target=88+P,
	// destination=33+P, binding=39+(33+P)+512*(88+P).
	// Header/groups add 6; the chosen opaque data and locator fill exactly 32 MiB.
	counted, routingLength, err := writeOutputConfiguration(v, false)
	if err != nil || counted.b != nil || counted.length != limit+9 || routingLength != 5 {
		t.Fatal("counted declaration boundary", counted.length, err)
	}
	image, err := EncodeOutputConfiguration(v)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(image) - 9; got != limit {
		t.Fatalf("declaration=%d want=%d", got, limit)
	}
	if _, _, err := InspectOutputConfiguration(domain, image); err != nil {
		t.Fatal(err)
	}
	desc, _, err := SplitOutputConfiguration(domain, image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeOutputConfigurationDescriptor(desc); err != nil {
		t.Fatal(err)
	}
	first.ConsumerLocator += "c"
	if _, _, err := writeOutputConfiguration(v, false); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("counted declaration max+1", err)
	}
	if _, err := EncodeOutputConfiguration(v); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("declaration max+1 accepted by encoder", err)
	}
	marker := []byte(strings.Repeat("c", 155))
	i := bytes.Index(image, marker)
	if i < 4 {
		t.Fatal("locator bytes missing")
	}
	oversize := append([]byte(nil), image[:i-4]...)
	oversize = binary.BigEndian.AppendUint32(oversize, 156)
	oversize = append(oversize, image[i:i+155]...)
	oversize = append(oversize, 'c')
	oversize = append(oversize, image[i+155:]...)
	if _, _, err := InspectOutputConfiguration(domain, oversize); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("declaration max+1 accepted by inspector", err)
	}
}

// full_only: false
func TestOutputConfigurationSourceUsesCompleteSharedGrammar(t *testing.T) {
	domain := publicationTestID(1)
	policy := OutputPolicy{ContractID: "class", Data: bytes.Repeat([]byte{255}, MaxOutputPolicyBytes)}
	v := OutputConfiguration{Schema: 5, DomainID: domain, Routes: []OutputRoute{}}
	for i := 0; i < 3; i++ {
		v.Bindings = append(v.Bindings, OutputBinding{IncarnationID: publicationTestID(byte(i + 2)), DestinationID: string(rune('a' + i)), Destination: outputTestDestination(policy),
			Targets: []OutputTarget{outputTestTarget(20, fmt.Sprintf("slot-%d", i), policy)}})
	}
	v.DefaultDestinations = []string{"a", "b"}
	image, err := EncodeOutputConfiguration(v)
	if err != nil {
		t.Fatal(err)
	}
	desc, rows, err := SplitOutputConfiguration(domain, image)
	if err != nil || len(rows) < 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	read := func(rows []OutputConfigurationSlice) func(uint16) (OutputConfigurationSlice, error) {
		return func(i uint16) (OutputConfigurationSlice, error) { return rows[i], nil }
	}
	if err := ValidateOutputConfigurationSource(domain, desc, read(rows)); err != nil {
		t.Fatal(err)
	}
	if got, err := InspectOutputConfigurationSource(domain, desc, read(rows)); err != nil || !reflect.DeepEqual(got, v) {
		t.Fatal("materialized source differs from the complete canonical declaration", err)
	}
	badImage := bytes.Clone(image)
	badImage[len(badImage)-3] = 'a'
	if _, _, err := InspectOutputConfiguration(domain, badImage); err == nil {
		t.Fatal("duplicate route accepted in contiguous parser")
	}
	if _, _, err := SplitOutputConfiguration(domain, badImage); err == nil {
		t.Fatal("duplicate route accepted when splitting")
	}
	badDesc := desc
	badDesc.ConfigurationDigest = outputConfigurationDigest(domain, badImage)
	badRows := append([]OutputConfigurationSlice(nil), rows...)
	for i := range badRows {
		badRows[i].ConfigurationDigest = badDesc.ConfigurationDigest
	}
	badRows[len(badRows)-1].SliceBytes = bytes.Clone(badRows[len(badRows)-1].SliceBytes)
	badRows[len(badRows)-1].SliceBytes[len(badRows[len(badRows)-1].SliceBytes)-3] = 'a'
	if err := ValidateOutputConfigurationSource(domain, badDesc, read(badRows)); err == nil {
		t.Fatal("duplicate route accepted in streaming parser")
	}
	if got, err := InspectOutputConfigurationSource(domain, badDesc, read(badRows)); err == nil || got.Schema != 0 {
		t.Fatal("invalid source exposed provisional typed rows", err)
	}
	for _, sourceErr := range []error{context.Canceled, errors.New("Store read failed")} {
		if err := ValidateOutputConfigurationSource(domain, desc, func(i uint16) (OutputConfigurationSlice, error) {
			if i == desc.SliceCount-1 {
				return OutputConfigurationSlice{}, sourceErr
			}
			return rows[i], nil
		}); !errors.Is(err, sourceErr) {
			t.Fatalf("late callback cause lost: %v", err)
		}
		if got, err := InspectOutputConfigurationSource(domain, desc, func(i uint16) (OutputConfigurationSlice, error) {
			if i == desc.SliceCount-1 {
				return OutputConfigurationSlice{}, sourceErr
			}
			return rows[i], nil
		}); !errors.Is(err, sourceErr) || got.Schema != 0 {
			t.Fatalf("materialized source lost late callback cause or exposed partial rows: %v", err)
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := ValidateOutputConfigurationSource(domain, desc, read(rows)); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= uint64(len(image))/2 {
		t.Fatalf("validation allocated %d for %d-byte image", allocated, len(image))
	}
	runtime.ReadMemStats(&before)
	splitDescriptor, splitRows, err := SplitOutputConfiguration(domain, image)
	runtime.ReadMemStats(&after)
	// Splitting owns the encoded slices and bounded validation scratch. A
	// second complete opaque-policy image is unnecessary typed storage.
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated >= uint64(len(image))+uint64(len(image))/2 {
		t.Fatalf("split allocated %d for %d-byte image", allocated, len(image))
	}
	if err != nil || splitDescriptor != desc || len(splitRows) != len(rows) {
		t.Fatalf("split descriptor=%#v rows=%d err=%v", splitDescriptor, len(splitRows), err)
	}
	for i := range rows {
		if !reflect.DeepEqual(splitRows[i], rows[i]) {
			t.Fatalf("split slice %d differs", i)
		}
	}
	t.Logf("split allocated %d for %d-byte image", allocated, len(image))
}

// full_only: false
func TestOutputPolicyLengthRefusesBeforeAllocation(t *testing.T) {
	// schema3 + one-byte identity + claimed maximum data, with no data body.
	malformed := []byte{0, 3, 0, 0, 0, 1, 'a', 0, 8, 1, 2}
	for _, read := range []func() error{func() error { _, err := InspectOutputPolicy(malformed); return err }, func() error {
		body := binary.BigEndian.AppendUint32(nil, uint32(len(malformed)))
		body = append(body, malformed...)
		r := outputImageReader{source: bytes.NewReader(body), remaining: len(body), section: -1}
		r.policy(true)
		return r.err
	}} {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		err := read()
		runtime.ReadMemStats(&after)
		if err == nil || after.TotalAlloc-before.TotalAlloc >= 256<<10 {
			t.Fatal("truncated policy allocated or accepted", err)
		}
	}
}
