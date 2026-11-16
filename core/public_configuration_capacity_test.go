package core

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// publicCapacityBacking counts declared application owners, not allocator or
// runtime overhead. A caller's hidden allocation extent is not inferred from
// a slice or substring. The maximum fixture constructs all its owners itself.
func publicCapacityBacking(t *testing.T, value any, exact bool) uint64 {
	t.Helper()
	type owner struct {
		pointer uintptr
		bytes   uint64
	}
	seen := make(map[owner]bool)
	var total uint64
	charge := func(pointer uintptr, bytes uint64) bool {
		key := owner{pointer, bytes}
		if bytes == 0 || seen[key] {
			return false
		}
		seen[key] = true
		total += bytes
		return true
	}
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Struct:
			for i := range v.NumField() {
				walk(v.Field(i))
			}
		case reflect.Pointer:
			if !v.IsNil() && charge(v.Pointer(), uint64(v.Type().Elem().Size())) {
				walk(v.Elem())
			}
		case reflect.Slice:
			if exact && v.Cap() != v.Len() {
				t.Fatalf("%s backing len=%d cap=%d", v.Type(), v.Len(), v.Cap())
			}
			if charge(v.Pointer(), uint64(v.Cap())*uint64(v.Type().Elem().Size())) {
				for i := range v.Len() {
					walk(v.Index(i))
				}
			}
		case reflect.String:
			charge(v.Pointer(), uint64(v.Len()))
		}
	}
	v := reflect.ValueOf(value)
	total = uint64(v.Type().Size())
	walk(v)
	return total
}

func publicCapacityDetached(t *testing.T, offered, captured reflect.Value) {
	t.Helper()
	if offered.Type() != captured.Type() {
		t.Fatal("capture type changed")
	}
	switch offered.Kind() {
	case reflect.Struct:
		for i := range offered.NumField() {
			publicCapacityDetached(t, offered.Field(i), captured.Field(i))
		}
	case reflect.Pointer:
		if !offered.IsNil() && !captured.IsNil() {
			if offered.Pointer() == captured.Pointer() {
				t.Fatalf("capture borrows %s pointee", offered.Type())
			}
			publicCapacityDetached(t, offered.Elem(), captured.Elem())
		}
	case reflect.Slice:
		if offered.Len() != captured.Len() || captured.Len() != captured.Cap() {
			t.Fatalf("%s offered=%d capture=%d/%d", offered.Type(), offered.Len(), captured.Len(), captured.Cap())
		}
		if offered.Len() != 0 && offered.Pointer() == captured.Pointer() {
			t.Fatalf("capture borrows %s backing", offered.Type())
		}
		for i := range offered.Len() {
			publicCapacityDetached(t, offered.Index(i), captured.Index(i))
		}
	case reflect.String:
		if offered.Len() != 0 && offered.String() == captured.String() && offered.Pointer() == captured.Pointer() {
			t.Fatal("capture borrows string backing")
		}
	}
}

// full_only: false
func TestPublicConfigurationDetachedCapacityAndKnownOwners(t *testing.T) {
	outputCalls, generatorCalls := 0, 0
	validator := publicFixtureValidator(t, &outputCalls, &generatorCalls)
	input := publicConfigurationFixture(t)
	publicRecoveryFixture(t, &input)
	// The complete owner is independently known here. The view deliberately
	// conceals its prefix and suffix through a three-index slice.
	byteOwner := make([]byte, 4096)
	intent := publicFixtureIntent(contract.GeneratorLifecycleManaged, []byte("{}"))
	copy(byteOwner[100:], intent)
	textOwner := strings.Repeat("x", 100) + "entry" + strings.Repeat("x", 100)
	name := textOwner[100:105]
	entryOwner := make([]contract.PublicEntry, 1, 4)
	entryOwner[0] = publicFixtureEntry(input, name)
	entryOwner[0].Source = publicPresent(contract.Generated)
	entryOwner[0].Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
	entryOwner[0].Generated.ContentIntent = publicPresent(byteOwner[100 : 100+len(intent) : 100+len(intent)])
	membershipOwner := make([]contract.ID, 1, 4)
	membershipOwner[0] = input.Authority.RecipientID.Value
	entryOwner[0].Memberships = publicPresent(membershipOwner)
	input.Entries = publicPresent(entryOwner)
	recipientOwner := make([]contract.PublicRecipient, 2, 5)
	copy(recipientOwner, input.Recipients.Value)
	keyOwner := make([]byte, len(recipientOwner[0].Encryption.PublicKey.Value), 1024)
	copy(keyOwner, recipientOwner[0].Encryption.PublicKey.Value)
	recipientOwner[0].Encryption.PublicKey = publicPresent(keyOwner)
	input.Recipients = publicPresent(recipientOwner)
	targetOwner := make([]contract.PublicOutputTarget, 2, 5)
	targetOwner[0] = publicFixtureTarget(name, "number-slot")
	targetOwner[1] = publicFixtureTarget("plain", "text-slot")
	policyOwner := make([]byte, 2, 8)
	copy(policyOwner, []byte{3, 7})
	targetOwner[0].ConsumerPolicy.Value.Data = policyOwner
	otherPolicyOwner := make([]byte, 2, 8)
	copy(otherPolicyOwner, []byte{8, 9})
	targetOwner[1].ConsumerPolicy.Value.Data = otherPolicyOwner
	// Keep target and entry order canonical so each corresponding owner can be
	// checked directly after the validator sorts complete sets.
	plainOwner := make([]byte, 2, 16)
	copy(plainOwner, []byte{0, 255})
	entryOwner = append(entryOwner, publicFixtureEntry(input, "plain"))
	entryOwner[1].Class = publicPresent(contract.Plain)
	entryOwner[1].PlainValue = publicPresent(plainOwner)
	input.Entries.Value = entryOwner
	bindingOwner := make([]contract.PublicOutputBinding, 2, 4)
	bindingOwner[0] = contract.PublicOutputBinding{DestinationID: "d", Targets: publicPresent(targetOwner[:1:1])}
	bindingOwner[1] = contract.PublicOutputBinding{DestinationID: "e", Targets: publicPresent(targetOwner[1:2:2])}
	for i := range bindingOwner {
		bindingOwner[i] = publicFixtureBinding(bindingOwner[i].DestinationID, bindingOwner[i].Targets.Value...)
	}
	input.OutputBindings = publicPresent(bindingOwner)
	settingOwner := make([]byte, len(bindingOwner[0].Destination.Value.CanonicalSettings), 64)
	copy(settingOwner, bindingOwner[0].Destination.Value.CanonicalSettings)
	bindingOwner[0].Destination.Value.CanonicalSettings = settingOwner
	targetOwner[0].PayloadEncoding = publicPresent(contract.OutputEncodingBase64)
	entryOwner[0].OutputEncoding = publicPresent(contract.OutputEncodingBase64)
	groupOwner := make([][]string, 2, 4)
	groupNameOwner := make([]string, 1, 4)
	groupNameOwner[0] = name
	groupOwner[0], groupOwner[1] = groupNameOwner, []string{"plain"}
	input.Groups = publicPresent(groupOwner)
	destinationOwner := make([]string, 1, 6)
	destinationOwner[0] = "d"
	routeOwner := make([]contract.PublicRoutingRule, 3, 4)
	routeOwner[0] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: name}, Destinations: publicPresent(destinationOwner)}
	routeOwner[1] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "plain"}, Destinations: publicPresent([]string{"e"})}
	routeOwner[2] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string(nil))}
	input.Routing = publicPresent(routeOwner)
	location := &contract.SourceLocation{SourceID: textOwner[100:105], Line: 1, Column: 1}
	input.Entries.SourceLocation = location
	knownSpareOwners := uint64(cap(byteOwner)+len(textOwner)+cap(plainOwner)+cap(keyOwner)) + uint64(cap(entryOwner))*uint64(unsafe.Sizeof(contract.PublicEntry{})) + uint64(cap(recipientOwner))*uint64(unsafe.Sizeof(contract.PublicRecipient{})) + uint64(cap(targetOwner))*uint64(unsafe.Sizeof(contract.PublicOutputTarget{})) + uint64(cap(bindingOwner))*uint64(unsafe.Sizeof(contract.PublicOutputBinding{})) + uint64(cap(routeOwner))*uint64(unsafe.Sizeof(contract.PublicRoutingRule{})) + uint64(cap(membershipOwner))*32 + uint64(cap(policyOwner)+cap(otherPolicyOwner)+cap(settingOwner)) + uint64(cap(destinationOwner)+cap(groupNameOwner))*16 + uint64(cap(groupOwner))*24
	if unsafe.Sizeof(contract.PublicEntry{}) != 168 || knownSpareOwners != 10277 {
		t.Fatalf("independently known spare owners=%d", knownSpareOwners)
	}
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	got := validator.Validate(context.Background(), input)
	if !got.Valid || !got.Complete || len(got.Diagnostics) != 0 || outputCalls != 0 || generatorCalls != 0 {
		t.Fatal("valid spare-capacity input refused", got.Diagnostics)
	}
	publicCapacityDetached(t, reflect.ValueOf(input), reflect.ValueOf(got.Configuration))
	_ = publicCapacityBacking(t, got.Configuration, true)
	before, err := json.Marshal(got.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	byteOwner[100], plainOwner[0], keyOwner[0] = 99, 99, 99
	membershipOwner[0] = contract.ID{99}
	settingOwner[0], entryOwner[0].OutputEncoding.Value, groupNameOwner[0] = 99, 99, "changed"
	policyOwner[0], otherPolicyOwner[0], destinationOwner[0] = 99, 99, "changed"
	targetOwner[0].CanonicalTarget.Value = "changed"
	bindingOwner[0].DestinationID, routeOwner[0].Key.EntryName = "changed", "changed"
	recipientOwner[0].DisplayName.Value, entryOwner[0].Name = "changed", "changed"
	location.SourceID = "changed"
	input.Recovery.Signing.PublicKey.Value[0] = 99
	input.Recovery.Encryption.PublicKey.Value[0] = 99
	after, err := json.Marshal(got.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(after, before) {
		t.Fatal("caller mutation changed the detached capture")
	}
}

// full_only: false
func TestPublicConfigurationDestinationAndPolicyByteBoundaries(t *testing.T) {
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "entry")})
	input.OutputBindings.Value = make([]contract.PublicOutputBinding, 8)
	destinations := make([]string, 8)
	for i := range input.OutputBindings.Value {
		name := fmt.Sprintf("d%d", i)
		target := publicFixtureTarget("entry", "slot-"+name)
		target.ConsumerPolicy.Value = contract.OutputPolicy{ContractID: strings.Repeat("p", 256), Data: make([]byte, 524546)}
		input.OutputBindings.Value[i] = publicFixtureBinding(name, target)
		destinations[i] = name
	}
	input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent(destinations)}})
	outputs, generators := 0, 0
	validator := publicFixtureValidator(t, &outputs, &generators)
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	got := validator.Validate(context.Background(), input)
	if !got.Valid || !got.Complete || outputs != 0 || generators != 0 || len(got.Configuration.Routing.Value[0].Destinations.Value) != 8 {
		t.Fatal("exact destination/policy bounds refused", got.Diagnostics)
	}
	for _, binding := range got.Configuration.OutputBindings.Value {
		if len(binding.Targets.Value[0].ConsumerPolicy.Value.ContractID) != 256 || len(binding.Targets.Value[0].ConsumerPolicy.Value.Data) != 524546 {
			t.Fatal("maximum opaque policy changed")
		}
	}
	for _, name := range []string{"destination-count", "policy-data-bytes", "policy-contract-bytes"} {
		t.Run(name, func(t *testing.T) {
			offered := input
			if name == "destination-count" {
				offered.Routing.Value = slices.Clone(input.Routing.Value)
				offered.Routing.Value[0].Destinations.Value = append(slices.Clone(destinations), "extra")
			} else {
				offered.OutputBindings.Value = slices.Clone(input.OutputBindings.Value)
				offered.OutputBindings.Value[0].Targets.Value = slices.Clone(input.OutputBindings.Value[0].Targets.Value)
				policy := offered.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value
				if name == "policy-data-bytes" {
					policy.Data = make([]byte, 524547)
				} else {
					policy.ContractID += "p"
				}
				offered.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value = policy
				offered.OutputBindings.Value[0].Destination.Value.Policy = policy
			}
			before := outputs
			refused := validator.Validate(context.Background(), offered)
			if refused.Valid || refused.Complete || !reflect.DeepEqual(refused.Configuration, contract.PublicConfiguration{}) || outputs != before || len(refused.Diagnostics) == 0 {
				t.Fatal("one-over reached capture", refused.Diagnostics)
			}
			for _, d := range refused.Diagnostics {
				if d.Reason != contract.ReasonLimitExceeded {
					t.Fatal("one-over lost capacity reason", d)
				}
			}
		})
	}
}

func publicCapacityID(n int) contract.ID {
	var id contract.ID
	binary.BigEndian.PutUint32(id[28:], uint32(n+1))
	return id
}

func publicCapacitySourceLocations(value reflect.Value) int {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0
		}
		return publicCapacitySourceLocations(value.Elem())
	}
	count := 0
	switch value.Kind() {
	case reflect.Struct:
		if field := value.FieldByName("SourceLocation"); field.IsValid() {
			field.Set(reflect.ValueOf(&contract.SourceLocation{SourceID: strings.Repeat("s", 64), Line: 1, Column: 1}))
			count++
		}
		for i := range value.NumField() {
			if value.Type().Field(i).Name == "SourceLocation" {
				continue
			}
			// Secret entries cannot offer plain-value source metadata.
			if value.Type() == reflect.TypeOf(contract.PublicEntry{}) && value.Type().Field(i).Name == "PlainValue" && value.FieldByName("Class").FieldByName("Value").Uint() == uint64(contract.Secret) {
				continue
			}
			count += publicCapacitySourceLocations(value.Field(i))
		}
	case reflect.Slice:
		for i := range value.Len() {
			count += publicCapacitySourceLocations(value.Index(i))
		}
	}
	return count
}

// Independent generic output framing account. The declaration has the header and
// final group count (6 bytes), then destination/encoding/target/group frames.
func publicCapacityPolicyLength(policy contract.OutputPolicy) int {
	if policy.ContractID == "" && len(policy.Data) == 0 {
		return 0
	}
	return 10 + len(policy.ContractID) + len(policy.Data)
}

func publicCapacityOutputLengths(input contract.PublicConfiguration) (declaration, routing int) {
	declaration, routing = 6, 5
	for _, binding := range input.OutputBindings.Value {
		destination := binding.Destination.Value
		// Binding key blob32, incarnation32, destination3 blob headers +policy blob header +cap1,
		// followed by the target u16 count.
		declaration += 4 + len(binding.DestinationID) + 32 + 17 + len(destination.ConfigContractID) + len(destination.ServiceContractID) + len(destination.CanonicalSettings) + publicCapacityPolicyLength(destination.Policy) + 2
		for _, target := range binding.Targets.Value {
			// Incarnation32, five blob headers20, three tags3, bounds16, policy blob4.
			declaration += 75 + len(target.ServiceContractID.Value) + len(target.TargetContractID.Value) + len(target.CanonicalTarget.Value) + len(target.ConsumerLocator.Value) + len(target.TargetData.Value) + publicCapacityPolicyLength(target.ConsumerPolicy.Value)
		}
	}
	for _, group := range input.Groups.Value {
		declaration += 2 + 32*len(group)
	}
	for _, route := range input.Routing.Value {
		if route.Key.EntrySelector != contract.PublicDefaultRoute {
			routing += 33
		}
		for _, destination := range route.Destinations.Value {
			routing += 4 + len(destination)
		}
	}
	return declaration, routing
}

// A destination owns one policy, also repeated in each target frame.
func publicCapacitySetPolicy(binding *contract.PublicOutputBinding, policy contract.OutputPolicy) {
	binding.Destination.Value.Policy = policy
	for i := range binding.Targets.Value {
		binding.Targets.Value[i].ConsumerPolicy = publicPresent(policy)
	}
}

func publicCapacityDesiredFixture(t *testing.T) contract.PublicConfiguration {
	t.Helper()
	input := publicConfigurationFixture(t)
	publicRecoveryFixture(t, &input)
	input.Authority.RecipientID.Value = publicCapacityID(0)
	baseRecipient := input.Recipients.Value[0]
	selector := baseRecipient.Encryption.Selector.Value
	selector = strings.Replace(selector, "central", strings.Repeat("a", 1024-len(selector)+len("central")), 1)
	if len(selector) != 1024 || !contract.PublicKeySelectorValid(contract.GCP, selector, false) {
		t.Fatal("maximum fixture selector must retain the admitted region grammar")
	}
	baseRecipient.Encryption.Selector = publicPresent(selector)
	input.Recipients.Value = make([]contract.PublicRecipient, 256)
	for i := range input.Recipients.Value {
		row := baseRecipient
		row.RecipientID = publicCapacityID(i)
		row.DisplayName = publicPresent(fmt.Sprintf("%0256d", i))
		row.Encryption.PublicKey.Value = slices.Clone(baseRecipient.Encryption.PublicKey.Value)
		input.Recipients.Value[i] = row
	}
	input.Entries.Value = make([]contract.PublicEntry, 512)
	for i := range input.Entries.Value {
		entry := publicFixtureEntry(input, fmt.Sprintf("%0256d", i))
		members := 1
		if i >= 128 && i < 192 {
			members = 32
		} else if i >= 192 && i < 217 {
			members = 64
		} else if i == 217 {
			members = 26
		}
		entry.Memberships = publicPresent(make([]contract.ID, members))
		for j := range entry.Memberships.Value {
			entry.Memberships.Value[j] = publicCapacityID(j)
		}
		if i < 128 {
			entry.Source = publicPresent(contract.Generated)
			settings := []byte("\"" + strings.Repeat("a", 393143) + "\"")
			intent := publicFixtureIntent(contract.GeneratorLifecycleManaged, settings)
			entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
			entry.Generated.ContentIntent = publicPresent(intent)
		} else {
			entry.Class = publicPresent(contract.Plain)
			size := 0
			if i < 256 {
				size = 65536
			}
			entry.PlainValue = publicPresent(make([]byte, size))
			for j := range entry.PlainValue.Value {
				entry.PlainValue.Value[j] = byte(i + j)
			}
		}
		entry.InputEncoding = publicPresent(contract.InputEncodingRaw)
		entry.OutputEncoding = publicPresent(contract.OutputEncodingBase64)
		input.Entries.Value[i] = entry
	}
	input.OutputBindings.Value = make([]contract.PublicOutputBinding, 64)
	for b := range input.OutputBindings.Value {
		name := fmt.Sprintf("j%02d", b)
		var indexes []int
		if b < 8 {
			name = strings.Repeat(string(rune('a'+b)), 256)
			if b == 0 {
				for e := range input.Entries.Value {
					indexes = append(indexes, e)
				}
			} else {
				indexes = append(indexes, 0)
				first, count := 1+(b-1)*72, 72
				if b == 7 {
					count++
				}
				for e := first; e < first+count; e++ {
					indexes = append(indexes, e)
				}
			}
		}
		targets := make([]contract.PublicOutputTarget, len(indexes))
		for j, e := range indexes {
			targets[j] = publicFixtureTarget(input.Entries.Value[e].Name, fmt.Sprintf("slot-%02d-%03d", b, e))
			targets[j].ConsumerPolicy.Value = contract.OutputPolicy{ContractID: "p", Data: []byte{}}
			targets[j].PayloadEncoding = publicPresent(contract.OutputEncodingBase64)
		}
		binding := publicFixtureBinding(name, targets...)
		if len(targets) == 0 {
			binding.Targets = publicPresent(make([]contract.PublicOutputTarget, 0))
		}
		publicCapacitySetPolicy(&binding, contract.OutputPolicy{ContractID: "p", Data: []byte{}})
		input.OutputBindings.Value[b] = binding
	}
	group := make([]string, 512)
	for i := range group {
		group[i] = input.Entries.Value[i].Name
	}
	input.Groups = publicPresent([][]string{group})
	defaults := make([]string, 8)
	for b := range defaults {
		defaults[b] = input.OutputBindings.Value[b].DestinationID
	}
	input.Routing.Value = make([]contract.PublicRoutingRule, 0, 513)
	for _, entry := range input.Entries.Value {
		destinations := []string{}
		for _, binding := range input.OutputBindings.Value {
			for _, target := range binding.Targets.Value {
				if target.EntryName == entry.Name {
					destinations = append(destinations, binding.DestinationID)
				}
			}
		}
		input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: entry.Name}, Destinations: publicPresent(destinations)})
	}
	input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent(defaults)})
	slices.SortFunc(input.Routing.Value, func(a, b contract.PublicRoutingRule) int { return comparePublicRoutingKeys(a.Key, b.Key) })
	input.Routing.Value = slices.Clip(input.Routing.Value)
	maximum := contract.OutputPolicy{ContractID: strings.Repeat("p", 256), Data: make([]byte, 524546)}
	publicCapacitySetPolicy(&input.OutputBindings.Value[9], maximum)
	declaration, _ := publicCapacityOutputLengths(input)
	remaining := 33554432 - declaration
	for b := range input.OutputBindings.Value {
		if b == 9 {
			continue
		}
		binding := &input.OutputBindings.Value[b]
		weight := 1 + len(binding.Targets.Value)
		count := min(524546, remaining/weight)
		policy := binding.Destination.Value.Policy
		policy.Data = make([]byte, count)
		for i := range policy.Data {
			policy.Data[i] = byte(i + 1)
		}
		publicCapacitySetPolicy(binding, policy)
		remaining -= weight * count
	}
	if remaining != 0 {
		t.Fatal("opaque policy filler did not consume exact declaration", remaining)
	}
	declaration, routing := publicCapacityOutputLengths(input)
	if remaining != 0 || declaration != 33554432 || routing != 285221 || declaration+4+routing != 33839657 {
		t.Fatalf("independent output lengths=%d+4+%d remainder=%d", declaration, routing, remaining)
	}
	locations := publicCapacitySourceLocations(reflect.ValueOf(&input))
	// Per-field source locations include entry encodings and destinations, while
	// generated secret entries omit the inapplicable plain-value location.
	if locations != 32+512*6+256*7+64*2+1024*11+513+128*7-128 {
		t.Fatalf("source-location owners=%d", locations)
	}
	return input
}

// full_only: true
func TestPublicConfigurationMaximumDesiredCapacity(t *testing.T) {
	for _, layout := range []struct {
		name      string
		got, want uintptr
	}{
		{"configuration", unsafe.Sizeof(contract.PublicConfiguration{}), 656},
		{"entry", unsafe.Sizeof(contract.PublicEntry{}), 168},
		{"generated settings", unsafe.Sizeof(contract.PublicGeneratedSettings{}), 208},
		{"recipient", unsafe.Sizeof(contract.PublicRecipient{}), 232},
		{"output binding", unsafe.Sizeof(contract.PublicOutputBinding{}), 176},
		{"output target", unsafe.Sizeof(contract.PublicOutputTarget{}), 336},
		{"routing rule", unsafe.Sizeof(contract.PublicRoutingRule{}), 64},
		{"signing settings", unsafe.Sizeof(contract.PublicSigningSettings{}), 168},
		{"encryption settings", unsafe.Sizeof(contract.PublicEncryptionSettings{}), 168},
		{"source location", unsafe.Sizeof(contract.SourceLocation{}), 32},
	} {
		if layout.got != layout.want {
			t.Fatalf("%s layout=%d want=%d", layout.name, layout.got, layout.want)
		}
	}
	const typed = 656 + 512*168 + 128*208 + 256*232 + 64*176 + 1024*336 + 513*64 + 336 +
		4096*32 + 512*24 + 512*16 + 513*8*16
	const registry = 6 + 256*(41+256+(32+32+8+1+2+1+4+422+32+1024))
	const semantic = 8<<20 + 48<<20 + registry + 36<<20 + 512*4096 + (1024+513)*232 + 512*224 + 64<<10
	const validSources = 32 + 512*6 + 128*7 + 256*7 + 64*2 + 1024*11 + 513 - 128
	const sourceBacking = validSources * (32 + 64)
	if typed != 778400 || registry != 474886 || semantic != 99577838 || sourceBacking != 1686624 {
		t.Fatal("independent public configuration accounts changed", typed, registry, semantic, sourceBacking)
	}
	if typed > contract.MaxPublicTypedConfigurationBytes || semantic > contract.MaxPublicConfigurationBytes || sourceBacking > contract.MaxPublicSourceLocationBytes {
		t.Fatal("current public configuration owners exceed admitted accounts")
	}
	input := publicCapacityDesiredFixture(t)
	outputCalls, generatorCalls := 0, 0
	validator := publicFixtureValidator(t, &outputCalls, &generatorCalls)
	raw, intents, memberships, targets, encodings := 0, 0, 0, 0, 0
	for _, entry := range input.Entries.Value {
		raw += len(entry.PlainValue.Value)
		if entry.OutputEncoding.Value == contract.OutputEncodingBase64 {
			encodings++
		}
		memberships += len(entry.Memberships.Value)
		if entry.Generated != nil {
			intents += len(entry.Generated.ContentIntent.Value)
		}
	}
	for _, binding := range input.OutputBindings.Value {
		targets += len(binding.Targets.Value)
	}
	if raw != 8388608 || intents != 50331648 || memberships != 4096 || targets != 1024 || encodings != 512 || len(input.Groups.Value[0]) != 512 || len(input.Routing.Value) != 513 {
		t.Fatalf("independent desired facts raw=%d intents=%d memberships=%d targets=%d encodings=%d", raw, intents, memberships, targets, encodings)
	}
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	got := validator.Validate(context.Background(), input)
	if !got.Valid || !got.Complete || len(got.Diagnostics) != 0 || outputCalls != 0 || generatorCalls != 0 {
		t.Fatalf("maximum desired refused valid%t complete%t diagnostics%+v outputs%d generators%d semantic-bounded%t backing-bounded%t", got.Valid, got.Complete, got.Diagnostics, outputCalls, generatorCalls, publicConfigurationBounded(input), publicConfigurationBackingBounded(input))
	}
	if !reflect.DeepEqual(got.Configuration, input) {
		t.Fatal("maximum desired public facts changed during capture")
	}
	publicCapacityDetached(t, reflect.ValueOf(input), reflect.ValueOf(got.Configuration))
	const oneImage = uint64(contract.MaxPublicConfigurationBytes + contract.MaxPublicTypedConfigurationBytes + contract.MaxPublicSourceLocationBytes)
	original := publicCapacityBacking(t, input, false)
	captured := publicCapacityBacking(t, got.Configuration, true)
	if original > oneImage || captured > oneImage || original+captured > 2*oneImage {
		t.Fatalf("overlapping owners original%d capture%d ceiling%d", original, captured, oneImage)
	}
	t.Logf("known application backing original%d capture%d overlap%d", original, captured, original+captured)
	firstPolicy := input.OutputBindings.Value[9].Destination.Value.Policy
	if len(firstPolicy.Data) != 524546 || 10+len(firstPolicy.ContractID)+len(firstPolicy.Data) != 524812 {
		t.Fatal("independent opaque policy and complete record ceilings not reached")
	}
	t.Run("independent-declaration-ceiling", func(t *testing.T) {
		declaration, routing := publicCapacityOutputLengths(input)
		if declaration != 33554432 || routing != 285221 || declaration+4+routing >= 37748736 || !publicConfigurationBounded(input) {
			t.Fatal("independent exact declaration ceiling refused")
		}
		offered := input
		offered.OutputBindings.Value = slices.Clone(input.OutputBindings.Value)
		offered.OutputBindings.Value[63].Destination.Value.Policy.ContractID += "p"
		declaration, routing = publicCapacityOutputLengths(offered)
		if declaration != 33554433 || routing != 285221 || declaration+4+routing >= 37748736 || publicConfigurationBounded(offered) {
			t.Fatal("one-over declaration passed while the combined account fits")
		}
		beforeOutput, beforeGenerator := outputCalls, generatorCalls
		refused := validator.Validate(context.Background(), offered)
		if refused.Valid || refused.Complete || outputCalls != beforeOutput || generatorCalls != beforeGenerator || len(refused.Diagnostics) != 1 || refused.Diagnostics[0].Reason != contract.ReasonLimitExceeded {
			t.Fatal("one-over declaration reached passive interpretation", refused.Diagnostics)
		}
	})
	// Count axes and byte axes are tested before passive interpretation and
	// immutable capture. These desired rules are not an installed-state claim.
	for _, test := range []struct {
		name   string
		change func(*contract.PublicConfiguration)
	}{
		{"entry-count", func(v *contract.PublicConfiguration) {
			v.Entries.Value = append(slices.Clone(v.Entries.Value), contract.PublicEntry{})
		}},
		{"recipient-count", func(v *contract.PublicConfiguration) {
			v.Recipients.Value = append(slices.Clone(v.Recipients.Value), contract.PublicRecipient{})
		}},
		{"binding-count", func(v *contract.PublicConfiguration) {
			v.OutputBindings.Value = append(slices.Clone(v.OutputBindings.Value), contract.PublicOutputBinding{})
		}},
		{"routing-count", func(v *contract.PublicConfiguration) {
			v.Routing.Value = make([]contract.PublicRoutingRule, contract.MaxPublicRoutingRules+1)
		}},
		{"destinations-per-route", func(v *contract.PublicConfiguration) {
			v.Routing.Value = slices.Clone(v.Routing.Value)
			v.Routing.Value[0].Destinations.Value = append(slices.Clone(v.Routing.Value[0].Destinations.Value), "extra")
		}},
		{"total-targets", func(v *contract.PublicConfiguration) {
			v.OutputBindings.Value = slices.Clone(v.OutputBindings.Value)
			v.OutputBindings.Value[63].Targets.Value = append(slices.Clone(v.OutputBindings.Value[63].Targets.Value), publicFixtureTarget(input.Entries.Value[9].Name, "extra"))
		}},
		{"targets-per-binding", func(v *contract.PublicConfiguration) {
			v.OutputBindings.Value = slices.Clone(v.OutputBindings.Value)
			v.OutputBindings.Value[0].Targets.Value = append(slices.Clone(v.OutputBindings.Value[0].Targets.Value), contract.PublicOutputTarget{})
		}},
		{"memberships-per-entry", func(v *contract.PublicConfiguration) {
			v.Entries.Value = slices.Clone(v.Entries.Value)
			v.Entries.Value[192].Memberships.Value = append(slices.Clone(v.Entries.Value[192].Memberships.Value), publicCapacityID(64))
		}},
		{"total-memberships", func(v *contract.PublicConfiguration) {
			v.Entries.Value = slices.Clone(v.Entries.Value)
			v.Entries.Value[218].Memberships.Value = append(slices.Clone(v.Entries.Value[218].Memberships.Value), publicCapacityID(1))
		}},
		{"raw-set", func(v *contract.PublicConfiguration) {
			v.Entries.Value = slices.Clone(v.Entries.Value)
			v.Entries.Value[256].PlainValue.Value = []byte{1}
		}},
		{"intent-bytes", func(v *contract.PublicConfiguration) {
			v.Entries.Value = slices.Clone(v.Entries.Value)
			g := *v.Entries.Value[0].Generated
			g.ContentIntent.Value = append(slices.Clone(g.ContentIntent.Value), 0)
			v.Entries.Value[0].Generated = &g
			other := *v.Entries.Value[1].Generated
			other.ContentIntent.Value = other.ContentIntent.Value[:len(other.ContentIntent.Value)-1]
			v.Entries.Value[1].Generated = &other
		}},
		{"generated-count", func(v *contract.PublicConfiguration) {
			v.Entries.Value = slices.Clone(v.Entries.Value)
			g := *v.Entries.Value[0].Generated
			g.ContentIntent.Value = g.ContentIntent.Value[:len(g.ContentIntent.Value)-1]
			v.Entries.Value[0].Generated = &g
			extra := *input.Entries.Value[0].Generated
			extra.ContentIntent.Value = []byte{0}
			v.Entries.Value[256].Class = publicPresent(contract.Secret)
			v.Entries.Value[256].Source = publicPresent(contract.Generated)
			v.Entries.Value[256].PlainValue = contract.PublicField[[]byte]{}
			v.Entries.Value[256].Generated = &extra
		}},
		{"policy-data-bytes", func(v *contract.PublicConfiguration) {
			v.OutputBindings.Value = slices.Clone(v.OutputBindings.Value)
			policy := v.OutputBindings.Value[9].Destination.Value.Policy
			policy.Data = append(slices.Clone(policy.Data), 0)
			publicCapacitySetPolicy(&v.OutputBindings.Value[9], policy)
		}},
		{"group-members", func(v *contract.PublicConfiguration) {
			v.Groups.Value = [][]string{append(slices.Clone(v.Groups.Value[0]), "extra")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			offered := input
			test.change(&offered)
			beforeOutput, beforeGenerator := outputCalls, generatorCalls
			refused := validator.Validate(context.Background(), offered)
			if refused.Valid || refused.Complete || !reflect.DeepEqual(refused.Configuration, contract.PublicConfiguration{}) || outputCalls != beforeOutput || generatorCalls != beforeGenerator || len(refused.Diagnostics) == 0 {
				t.Fatalf("over-limit input reached capture or passive interpretation valid=%t complete=%t diagnostics=%d output-calls=%d generator-calls=%d", refused.Valid, refused.Complete, len(refused.Diagnostics), outputCalls-beforeOutput, generatorCalls-beforeGenerator)
			}
			for _, diagnostic := range refused.Diagnostics {
				if diagnostic.Reason != contract.ReasonLimitExceeded {
					t.Fatal("one-over input lost its capacity reason", diagnostic.Reason)
				}
			}
		})
	}
	input.Entries.Value[0].Generated.ContentIntent.Value[0] = 99
	input.Entries.Value[128].PlainValue.Value[0] = 99
	input.Entries.Value[0].Memberships.Value[0] = contract.ID{99}
	input.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data[0] = 99
	firstDestination := input.Routing.Value[0].Destinations.Value[0]
	input.Routing.Value[0].Destinations.Value[0] = "changed"
	input.Entries.Value[0].OutputEncoding.Value = 99
	input.Groups.Value[0][0] = "changed"
	input.OutputBindings.Value[63].Destination.Value.CanonicalSettings[0] = 99
	input.Entries.SourceLocation.SourceID = "changed"
	if got.Configuration.Entries.Value[0].Generated.ContentIntent.Value[0] != 0 || got.Configuration.Entries.Value[128].PlainValue.Value[0] != 128 || got.Configuration.Entries.Value[0].Memberships.Value[0] != publicCapacityID(0) || got.Configuration.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data[0] != 1 || got.Configuration.Routing.Value[0].Destinations.Value[0] != firstDestination || got.Configuration.Entries.Value[0].OutputEncoding.Value != contract.OutputEncodingBase64 || got.Configuration.Groups.Value[0][0] != fmt.Sprintf("%0256d", 0) || string(got.Configuration.OutputBindings.Value[63].Destination.Value.CanonicalSettings) != `{"fixture":"j63"}` || got.Configuration.Entries.SourceLocation.SourceID != strings.Repeat("s", 64) {
		t.Fatal("maximum capture changed after caller mutation")
	}
}
