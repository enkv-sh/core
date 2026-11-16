package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The complete stored declaration reaches 32 MiB. The separate named source
// carrier and its Base64 form are larger and retain the same exact meaning.
// full_only: true
func TestNormalOutputBindingStoredDeclarationBoundary(t *testing.T) {
	policy := OutputPolicy{ContractID: "p", Data: bytes.Repeat([]byte{7}, 516098)}
	capabilities := OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot
	binding := NormalOutputBinding{DestinationID: "d", Destination: OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(`{}`), Policy: policy, Capabilities: capabilities}}
	for i := 0; i < 64; i++ {
		suffix := strconv.Itoa(100 + i)[1:]
		name := strings.Repeat("n", 254) + suffix
		target := OutputTarget{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: "t" + suffix, PayloadEncoding: OutputEncodingBase64, LocatorRequiresCreation: true, Policy: policy, Capabilities: capabilities}
		if i == 0 {
			target.TargetData = bytes.Repeat([]byte{11}, 2161)
		}
		binding.Targets = append(binding.Targets, NormalOutputTarget{Name: name, Target: target})
	}
	// Destination21+policy; binding ID5+incarnation32+target count2;
	// target80+policy. Schema/binding/group counts total6.
	const stored = 6 + 60 + 64*80 + 65*516109 + 2161
	const carrier = (stored - 6) - 26 + 64*(8+256)
	const encoded = 4 * ((carrier + 2) / 3)
	if stored != 33554432 || carrier != 33571296 || encoded != 44761728 {
		t.Fatal("independent stored/carrier/Base64 algebra changed")
	}
	length, err := NormalOutputBindingDeclarationLength(binding)
	if err != nil || length != 33554426 {
		t.Fatal("stored contribution differs from independent field account", length, err)
	}
	body, err := EncodeNormalOutputBinding(binding)
	if err != nil || len(body) != carrier {
		t.Fatal("valid stored declaration cannot be represented by its named carrier", len(body), err)
	}
	if base64.StdEncoding.EncodedLen(len(body)) != encoded {
		t.Fatal("Base64 length differs from independent padding calculation")
	}
	decoded, err := InspectNormalOutputBinding(body)
	if err != nil || !reflect.DeepEqual(decoded, binding) {
		t.Fatal("exact stored-bound carrier meaning changed", err)
	}
	before := append(binary.BigEndian.AppendUint32(nil, 2161), bytes.Repeat([]byte{11}, 2161)...)
	after := append(binary.BigEndian.AppendUint32(nil, 2162), bytes.Repeat([]byte{11}, 2162)...)
	if bytes.Count(body, before) != 1 {
		t.Fatal("target-data framing is not unique")
	}
	oneOver := bytes.Replace(body, before, after, 1)
	if len(oneOver) != 33571297 || base64.StdEncoding.EncodedLen(len(oneOver)) != 44761732 {
		t.Fatal("independent one-over carrier dimensions changed")
	}
	if _, err := InspectNormalOutputBinding(oneOver); err == nil {
		t.Fatal("decoder admitted oversized stored declaration inside a bounded carrier")
	}
	// The extra target byte fits the source-carrier allowance. It must still
	// refuse because the complete interpreted stored declaration is one over.
	binding.Targets[0].Target.TargetData = append(binding.Targets[0].Target.TargetData, 13)
	if _, err := EncodeNormalOutputBinding(binding); err == nil {
		t.Fatal("source allowance admitted an oversized stored declaration")
	}
	// The carrier ceiling is conservative; passing this length check alone
	// supplies no schema or valid stored declaration.
	limit := make([]byte, 33806337)
	if _, err := InspectNormalOutputBinding(limit[:33806336]); err != ErrRecord {
		t.Fatal("exact source-carrier byte ceiling refused before shape validation", err)
	}
	if _, err := InspectNormalOutputBinding(limit); err != ErrRecordCapacity {
		t.Fatal("source-carrier ceiling plus one reached shape validation", err)
	}
}

// full_only: false
func TestNormalOutputBindingIndependentSourceCarrier(t *testing.T) {
	target := OutputTarget{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: "p", LocatorRequiresCreation: true, PayloadEncoding: OutputEncodingRaw, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}
	binding := NormalOutputBinding{DestinationID: "d", Destination: OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte(`{"n":1.00}`), Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}, Targets: []NormalOutputTarget{{Name: "entry", Target: target}}}
	blob := func(dst []byte, value []byte) []byte {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
		return append(dst, value...)
	}
	// Independently framed: destination exact JSON bytes; target has the absent
	// 32-byte incarnation, four text blobs, target data, encoding/capabilities/flag,
	// and absent policy. The source uses entry names and has no binding incarnation.
	destination := blob(nil, []byte("c"))
	destination = blob(destination, []byte("s"))
	destination = blob(destination, []byte(`{"n":1.00}`))
	destination = blob(destination, nil)
	destination = append(destination, 63)
	row := make([]byte, 32)
	for _, value := range []string{"s", "t", "p", "", ""} {
		row = blob(row, []byte(value))
	}
	row = append(row, 1, 63, 1)
	row = append(row, make([]byte, 16)...) // Absent create/write interval endpoints.
	row = blob(row, nil)
	want := blob([]byte{0, 2}, []byte("d"))
	want = blob(want, destination)
	want = append(want, 0, 1)
	want = blob(want, []byte("entry"))
	want = blob(want, row)
	got, err := EncodeNormalOutputBinding(binding)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("independent source framing", err)
	}
	decoded, err := InspectNormalOutputBinding(want)
	if err != nil || !reflect.DeepEqual(decoded, binding) {
		t.Fatal("source carrier meaning", err)
	}
	clear(want)
	if !reflect.DeepEqual(decoded, binding) {
		t.Fatal("source carrier retained caller backing")
	}
	for _, mutate := range []func(*NormalOutputBinding){func(v *NormalOutputBinding) { v.Targets[0].Target.EntryIncarnationID = publicationTestID(1) }, func(v *NormalOutputBinding) { v.Targets[0].Target.ConsumerLocator = "later-assigned" }, func(v *NormalOutputBinding) { v.Targets[0].Name = strings.Repeat("n", 257) }, func(v *NormalOutputBinding) { v.Targets = append(v.Targets, v.Targets[0]) }, func(v *NormalOutputBinding) { v.Destination.ServiceContractID = "other" }, func(v *NormalOutputBinding) { v.Targets[0].Target.Capabilities = 128 }} {
		bad := binding
		bad.Targets = append([]NormalOutputTarget(nil), binding.Targets...)
		mutate(&bad)
		if _, err := EncodeNormalOutputBinding(bad); err == nil {
			t.Fatal("invalid source carrier accepted")
		}
	}
	for _, bad := range [][]byte{got[:len(got)-1], append(bytes.Clone(got), 0), append([]byte{0, 1}, got[2:]...)} {
		if _, err := InspectNormalOutputBinding(bad); err == nil {
			t.Fatal("malformed carrier accepted")
		}
	}
}

// full_only: false
func TestOutputPublicFieldLimitsAndCanonicalSettingsBytes(t *testing.T) {
	target := OutputTarget{ServiceContractID: strings.Repeat("s", 256), TargetContractID: strings.Repeat("t", 256), CanonicalTarget: strings.Repeat("p", 1024), ConsumerLocator: strings.Repeat("l", 1024), TargetData: bytes.Repeat([]byte{255}, 4096), PayloadEncoding: OutputEncodingBase64, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}
	target.EntryIncarnationID = publicationTestID(1)
	if _, err := OutputTargetRowLength(target); err != nil {
		t.Fatal("maximum target fields", err)
	}
	for _, mutate := range []func(*OutputTarget){func(v *OutputTarget) { v.ServiceContractID += "s" }, func(v *OutputTarget) { v.TargetContractID += "t" }, func(v *OutputTarget) { v.CanonicalTarget += "p" }, func(v *OutputTarget) { v.ConsumerLocator += "l" }, func(v *OutputTarget) { v.TargetData = append(v.TargetData, 0) }, func(v *OutputTarget) { v.Capabilities = 64 }} {
		bad := target
		mutate(&bad)
		if _, err := OutputTargetRowLength(bad); err == nil {
			t.Fatal("target max+1 accepted")
		}
	}
	destination := OutputDestination{ConfigContractID: strings.Repeat("c", 256), ServiceContractID: target.ServiceContractID, CanonicalSettings: []byte(`"` + strings.Repeat("x", 65534) + `"`), Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}
	if _, err := OutputDestinationLength(destination); err != nil {
		t.Fatal("maximum settings JSON", err)
	}
	destination.CanonicalSettings = []byte(`"` + strings.Repeat("x", 65535) + `"`)
	if _, err := OutputDestinationLength(destination); err == nil {
		t.Fatal("settings max+1 accepted")
	}
	for _, settings := range []string{"", "{", "null trailing"} {
		destination.CanonicalSettings = []byte(settings)
		if _, err := OutputDestinationLength(destination); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}

// full_only: false
func TestNormalOutputSourceNamesUseUTF8ByteBound(t *testing.T) {
	makeBinding := func(name string) NormalOutputBinding {
		capabilities := OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot
		return NormalOutputBinding{DestinationID: "destination",
			Destination: OutputDestination{ConfigContractID: "config", ServiceContractID: "service", CanonicalSettings: []byte(`{}`), Capabilities: capabilities},
			Targets: []NormalOutputTarget{{Name: name, Target: OutputTarget{ServiceContractID: "service", TargetContractID: "target-contract", CanonicalTarget: "physical-target",
				LocatorRequiresCreation: true, PayloadEncoding: OutputEncodingBase64, Capabilities: capabilities}}}}
	}
	frame := func(name string) []byte {
		return append(binary.BigEndian.AppendUint32(nil, uint32(len(name))), name...)
	}
	base, err := EncodeNormalOutputBinding(makeBinding("entry"))
	if err != nil || bytes.Count(base, frame("entry")) != 1 {
		t.Fatal("invalid source-name test carrier", err)
	}
	for _, test := range []struct {
		name, value string
		valid       bool
	}{
		{"empty", "", true},
		{"ascii-255", strings.Repeat("n", 255), true},
		{"ascii-256", strings.Repeat("n", 256), true},
		{"ascii-257", strings.Repeat("n", 257), false},
		{"utf8-254", strings.Repeat("é", 127), true},
		{"utf8-256", strings.Repeat("é", 128), true},
		{"utf8-258", strings.Repeat("é", 129), false},
		{"invalid-utf8", string([]byte{0xff}), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := bytes.ReplaceAll(base, frame("entry"), frame(test.value))
			encoded, encodeErr := EncodeNormalOutputBinding(makeBinding(test.value))
			decoded, decodeErr := InspectNormalOutputBinding(raw)
			if (encodeErr == nil) != test.valid || (decodeErr == nil) != test.valid {
				t.Fatal("source name boundary differs", encodeErr, decodeErr)
			}
			if test.valid && (!bytes.Equal(encoded, raw) || decoded.Targets[0].Name != test.value) {
				t.Fatal("source name bytes changed")
			}
		})
	}
}
