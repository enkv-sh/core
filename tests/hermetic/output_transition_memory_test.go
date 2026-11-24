package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestRetainedOutputBacking(t *testing.T) {
	backing, independent := make([]byte, 97), make([]byte, 31)
	clone := bytes.Clone(backing)
	output := &contract.GeneratedOutputTransition{EntryBodies: [][]byte{backing[:0], backing[13:29:49]},
		Rows: contract.GeneratedSupportRows{Records: []contract.SupportRecord{{Body: backing[41:]}, {Body: independent}}}}
	c := &Comparison{normalSupportRows: output.Rows, normalPackedPages: []normalSupportPage{{records: output.Rows.Records}},
		outputAfter: &outputApplySelection{records: []contract.SupportRecord{{Body: clone}}}}
	buffers := retainedByteBuffers(nil, c, nil, nil)
	buffers.addGeneratedOutput(output)
	if got, want := buffers.capacity(), uint64(cap(backing)+cap(independent)+cap(clone)); got != want {
		t.Fatalf("output byte backing = %d, want %d", got, want)
	}
	text := strings.Repeat("s", 83)
	copied := strings.Clone(text)
	configuration := contract.OutputConfiguration{Bindings: []contract.OutputBinding{{DestinationID: text,
		Targets: []contract.OutputTarget{{CanonicalTarget: text[13:27], Policy: contract.OutputPolicy{ContractID: copied}}}}},
		DefaultDestinations: []string{text[37:]}}
	witness := &contract.NormalOutputTransition{Before: configuration, Bindings: []contract.NormalOutputBinding{{DestinationID: text[9:]}}}
	c.outputAfter.transition = witness
	c.support = &contract.GeneratedSupportTransition{Output: witness}
	if got, want := retainedOutputStrings(c).capacity(), uint64(2*len(text)); got != want {
		t.Fatalf("output string backing = %d, want %d", got, want)
	}
	opaque := make([]byte, 113)
	witness.Before.Bindings[0].Destination.CanonicalSettings = opaque[:0]
	witness.Before.Bindings[0].Destination.Policy.Data = opaque[11:37:49]
	witness.Before.Bindings[0].Targets[0].TargetData = make([]byte, 29)
	witness.Before.Bindings[0].Targets[0].Policy.Data = make([]byte, 31)
	witness.Bindings[0].Destination.CanonicalSettings = make([]byte, 59)
	witness.Bindings[0].Destination.Policy.Data = make([]byte, 61)
	witness.Bindings[0].Targets = []contract.NormalOutputTarget{{Target: contract.OutputTarget{TargetData: make([]byte, 67), Policy: contract.OutputPolicy{Data: make([]byte, 71)}}}}
	c.outputIntent = &outputApplyInput{bindings: []outputApplyBinding{{destination: contract.OutputDestination{CanonicalSettings: make([]byte, 19), Policy: contract.OutputPolicy{Data: make([]byte, 37)}},
		targets: []outputApplyTarget{{target: contract.OutputTarget{TargetData: make([]byte, 41), Policy: contract.OutputPolicy{Data: make([]byte, 43)}}}}}}}
	c.outputAfter.departedTargets = []outputTargetDifference{{target: contract.OutputTarget{TargetData: make([]byte, 47), Policy: contract.OutputPolicy{Data: make([]byte, 53)}}}}
	// The zero-length settings retain113 bytes; its policy aliases that owner.
	// All other opaque fields have independent exact-capacity owners.
	wantOpaque := uint64(113 + 29 + 31 + 59 + 61 + 67 + 71 + 19 + 37 + 41 + 43 + 47 + 53)
	opaqueBuffers := retainedByteBuffers(nil, c, nil, nil)
	opaqueBuffers.addGeneratedOutput(output)
	if got, want := opaqueBuffers.capacity(), uint64(cap(backing)+cap(independent)+cap(clone))+wantOpaque; got != want {
		t.Fatalf("opaque output byte backing = %d, want %d", got, want)
	}
	runtime.KeepAlive(output)
	runtime.KeepAlive(c)
	runtime.KeepAlive(configuration)
}

// full_only: false
func TestRetainedOutputObserverWorkspace(t *testing.T) {
	text, copied := strings.Clone("abcdefghijk"), strings.Clone("abcdefghijk")
	witness := func(text, copied string) *contract.NormalOutputTransition {
		return &contract.NormalOutputTransition{
			Before: contract.OutputConfiguration{
				Bindings: []contract.OutputBinding{{DestinationID: text[:7], Targets: []contract.OutputTarget{{
					CanonicalTarget: text[3:9], TargetContractID: text[8:], Policy: contract.OutputPolicy{ContractID: copied},
				}}}}, DefaultDestinations: []string{text[6:], ""},
			},
			EntriesBefore: []contract.MembershipRow{{Name: text[4:]}}, Intent: []contract.CryptoIntentRow{{Name: text[5:]}},
			Bindings: []contract.NormalOutputBinding{{DestinationID: text[2:], Targets: []contract.NormalOutputTarget{{
				Name: text[:3], Target: contract.OutputTarget{ServiceContractID: text[1:5]},
			}}}}, Routes: []contract.NormalOutputRoute{{Name: text[:2], Destinations: []string{text[7:]}}},
		}
	}
	first := witness(text, copied)
	second := witness(strings.Clone(text), strings.Clone(copied))
	alias := *first
	c := &Comparison{
		outputIntent: &outputApplyInput{
			bindings: []outputApplyBinding{{destinationID: text[:4], targets: []outputApplyTarget{{
				entryName: text[2:6], target: contract.OutputTarget{Policy: contract.OutputPolicy{ContractID: copied[1:]}},
			}}}}, routes: []outputApplyRoute{{entryName: text[:1], destinations: []string{text[5:]}}},
		},
		outputAfter: &outputApplySelection{transition: first, departedTargets: []outputTargetDifference{{
			destinationID: text[3:6], target: contract.OutputTarget{TargetContractID: text[:2]},
		}}}, support: &contract.GeneratedSupportTransition{Output: first},
	}
	// Each witness has 12 nonempty fields. Input adds five; departed adds two.
	// Each independently cloned pair owns 22 accessible bytes. Empty fields add none.
	t.Run("string_roots", func(t *testing.T) {
		for _, row := range []struct {
			name       string
			comparison *Comparison
			count      int
			union      uint64
		}{
			{"identical_witness", c, 19, 22},
			{"empty", nil, 0, 0},
			{"distinct_alias_witnesses", &Comparison{outputAfter: &outputApplySelection{transition: first},
				support: &contract.GeneratedSupportTransition{Output: &alias}}, 24, 22},
			{"independent_equal_witnesses", &Comparison{outputAfter: &outputApplySelection{transition: first},
				support: &contract.GeneratedSupportTransition{Output: second}}, 24, 44},
		} {
			t.Run(row.name, func(t *testing.T) {
				buffers := retainedOutputStrings(row.comparison)
				if got := buffers.capacity(); got != row.union {
					t.Errorf("string union = %d, want %d", got, row.union)
				}
				if len(buffers) != row.count || cap(buffers) != row.count {
					t.Errorf("string intervals len/cap = %d/%d, want %d/%d", len(buffers), cap(buffers), row.count, row.count)
				}
				runtime.KeepAlive(row.comparison)
			})
		}
	})
	t.Run("samples_and_restart", func(t *testing.T) {
		backing, observedBody, extraBody := make([]byte, 97), make([]byte, 31), make([]byte, 17)
		before := &StateSession{body: backing[:0], cache: map[format.Ref][]byte{{}: backing[13:40:49]}}
		observed := &StateSession{body: observedBody}
		candidate := &Candidate{session: before, body: backing[41:50:97]}
		memory := startOrdinaryOutputAccounting(&ordinaryOutputProof{})
		check := func(phase string, comparison *Comparison, observation *StateSession, extras [][]byte, count int, bytes, strings uint64) {
			memory.sample(phase, before, comparison, candidate, observation, extras...)
			sample := memory.samples[len(memory.samples)-1]
			if sample.ByteCapacity != bytes || sample.StringBacking != strings {
				t.Errorf("%s byte/string union = %d/%d, want %d/%d", phase, sample.ByteCapacity, sample.StringBacking, bytes, strings)
			}
			if len(memory.stringBuffers) != count {
				t.Errorf("%s string intervals = %d, want %d", phase, len(memory.stringBuffers), count)
			}
		}
		check("first", c, observed, [][]byte{backing[2:8:17], extraBody}, 19, 145, 22)
		byteStart, stringStart := unsafe.SliceData(memory.byteBuffers), unsafe.SliceData(memory.stringBuffers)
		byteCap, stringCap := cap(memory.byteBuffers), cap(memory.stringBuffers)
		if len(memory.byteBuffers) != 6 || byteCap < 6 || stringCap != 19 {
			t.Errorf("first byte interval len/cap = %d/%d (want len6, cap>=6); string cap = %d, want19", len(memory.byteBuffers), byteCap, stringCap)
		}
		check("same", c, observed, [][]byte{backing[2:8:17], extraBody}, 19, 145, 22)
		if unsafe.SliceData(memory.byteBuffers) != byteStart || unsafe.SliceData(memory.stringBuffers) != stringStart {
			t.Error("same roots allocated new observer backing")
		}
		memory.restartOrdinaryOutputAccounting()
		if len(memory.samples) != 0 {
			t.Error("baseline restart retained old samples")
		}
		check("smaller", &Comparison{support: &contract.GeneratedSupportTransition{Output: first}}, before, nil, 12, 97, 22)
		if unsafe.SliceData(memory.byteBuffers) != byteStart || unsafe.SliceData(memory.stringBuffers) != stringStart ||
			cap(memory.byteBuffers) != byteCap || cap(memory.stringBuffers) != stringCap {
			t.Error("smaller roots or baseline restart replaced scratch")
		}
		larger := *c
		larger.support = &contract.GeneratedSupportTransition{Output: second}
		newObserved, newExtra := &StateSession{body: make([]byte, 43)}, make([]byte, 23)
		check("larger", &larger, newObserved, [][]byte{newExtra, newExtra[:0]}, 31, 163, 44)
		if cap(memory.stringBuffers) != 31 || unsafe.SliceData(memory.stringBuffers) == stringStart {
			t.Error("larger roots did not reserve exactly their required string intervals")
		}
		if unsafe.SliceData(memory.byteBuffers) != byteStart {
			t.Error("changed equal-count byte roots replaced scratch")
		}
		check("empty_strings", nil, nil, nil, 0, 97, 0)
		aliasSession := *before
		check("distinct_alias_sessions", nil, &aliasSession, nil, 0, 97, 0)
		if len(memory.byteBuffers) != 5 {
			t.Errorf("distinct alias sessions collapsed: %d intervals, want5", len(memory.byteBuffers))
		}
		runtime.KeepAlive(c)
		runtime.KeepAlive(first)
		runtime.KeepAlive(second)
		runtime.KeepAlive(backing)
		runtime.KeepAlive(observed)
		runtime.KeepAlive(extraBody)
		runtime.KeepAlive(newObserved)
		runtime.KeepAlive(newExtra)
	})
}

// Synthetic roots measure observer allocation separately from Product capacity.
// full_only: false
func TestRetainedOutputObserverAllocation(t *testing.T) {
	selected := &StateSession{root: format.Root{Domain: testID("observer allocation domain")}, body: make([]byte, 37)}
	for i := 0; i < 512; i++ {
		name := fmt.Sprintf("observer-%03d", i)
		index, slot := i/format.PageSlots, i%format.PageSlots
		if selected.pages[index] == nil {
			selected.pages[index] = &format.ValueEntryPage{}
		}
		entry := &contract.ValueEntry{Name: name, Incarnation: fixtureID(selected.root.Domain, name), ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
		if i < 128 {
			entry.ValueSource = contract.Generated
			for r := 0; r < 16; r++ {
				entry.Recipients = append(entry.Recipients, fixtureID(selected.root.Domain, fmt.Sprintf("recipient-%d", r)))
			}
		}
		selected.pages[index].Slots[slot] = entry
		selected.root.Names = append(selected.root.Names, format.NameEntry{Name: name, Slot: uint16(i)})
	}
	configuration := capacityOutputConfiguration(t, selected, true)
	declaration, routing := capacityConfigurationLengths(t, configuration)
	if declaration != 33_554_432 || routing != 284_869 || declaration+4+routing != 33_839_305 {
		t.Fatal("observer fixture must reach the independent current logical dimensions", declaration, routing)
	}
	input := maximumOutputApplyInput(t, selected, configuration)
	template := &contract.NormalOutputTransition{Before: configuration, Groups: input.groups}
	for _, row := range selected.root.Names {
		template.EntriesBefore = append(template.EntriesBefore, contract.MembershipRow{Name: row.Name})
		template.Intent = append(template.Intent, contract.CryptoIntentRow{Name: row.Name})
	}
	for _, binding := range input.bindings {
		row := contract.NormalOutputBinding{DestinationID: binding.destinationID, Destination: binding.destination}
		for _, target := range binding.targets {
			row.Targets = append(row.Targets, contract.NormalOutputTarget{Name: target.entryName, Target: target.target})
		}
		template.Bindings = append(template.Bindings, row)
	}
	for _, route := range input.routes {
		template.Routes = append(template.Routes, contract.NormalOutputRoute{Default: route.defaultRoute, Name: route.entryName, Destinations: route.destinations})
	}
	first, err := template.Own()
	if err != nil {
		t.Fatal("first observer witness", err)
	}
	second, err := template.Own()
	if err != nil {
		t.Fatal("second observer witness", err)
	}
	// One extra desired target byte exceeds the declaration ceiling.
	// Refuse it before allocating another owned witness.
	// Binding 0 fills the first eight targets to their individual limit.
	target := &template.Bindings[0].Targets[8].Target
	data := target.TargetData
	if len(data)+1 > contract.MaxOutputTargetDataBytes {
		t.Fatal("observer overflow must remain within the individual target bound")
	}
	target.TargetData = append(bytes.Clone(data), 0)
	if owned, err := template.Own(); owned != nil || err != contract.ErrRecordCapacity {
		t.Fatal("one declaration byte over the bound was retained", owned != nil, err)
	}
	target.TargetData = data
	c := &Comparison{outputIntent: input, outputAfter: &outputApplySelection{transition: first}, support: &contract.GeneratedSupportTransition{Output: second}}
	// Independent nonempty string counts: configuration =64 binding IDs
	// +64*3 destination fields +1,024*5 target fields +1,032 routing names
	// =6,408. Input adds1,024 target names +512 entry-route names +512
	// group names =8,456. Each witness contains both forms plus512 prior-entry
	// and512 intent names =15,888.
	const intervals = 40232

	memory := startOrdinaryOutputAccounting(&ordinaryOutputProof{})
	extra := make([]byte, 19)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	memory.sample("observer-first", selected, c, nil, nil, extra)
	runtime.ReadMemStats(&after)
	firstAllocation := after.TotalAlloc - before.TotalAlloc
	firstSample := memory.samples[len(memory.samples)-1]
	byteStart, stringStart := unsafe.SliceData(memory.byteBuffers), unsafe.SliceData(memory.stringBuffers)
	if len(memory.stringBuffers) != intervals || cap(memory.stringBuffers) != intervals {
		t.Fatal("full observer interval count/reservation", len(memory.stringBuffers), cap(memory.stringBuffers), intervals)
	}
	// Input target policies alias their destination policy. Each independently
	// owned witness clones its Before and current binding bytes separately.
	wantBytes := uint64(56)
	for _, binding := range input.bindings {
		wantBytes += uint64(cap(binding.destination.CanonicalSettings) + cap(binding.destination.Policy.Data))
		for _, target := range binding.targets {
			wantBytes += uint64(cap(target.target.TargetData))
		}
	}
	for _, witness := range []*contract.NormalOutputTransition{first, second} {
		for _, binding := range witness.Before.Bindings {
			wantBytes += uint64(cap(binding.Destination.CanonicalSettings) + cap(binding.Destination.Policy.Data))
			for _, target := range binding.Targets {
				wantBytes += uint64(cap(target.TargetData) + cap(target.Policy.Data))
			}
		}
		for _, binding := range witness.Bindings {
			wantBytes += uint64(cap(binding.Destination.CanonicalSettings) + cap(binding.Destination.Policy.Data))
			for _, target := range binding.Targets {
				wantBytes += uint64(cap(target.Target.TargetData) + cap(target.Target.Policy.Data))
			}
		}
	}
	if firstSample.ByteCapacity != wantBytes {
		t.Fatal("fixed observer byte union", firstSample.ByteCapacity, wantBytes)
	}
	runtime.ReadMemStats(&before)
	memory.sample("observer-repeated", selected, c, nil, nil, extra)
	runtime.ReadMemStats(&after)
	secondAllocation := after.TotalAlloc - before.TotalAlloc
	secondSample := memory.samples[len(memory.samples)-1]
	if unsafe.SliceData(memory.byteBuffers) != byteStart || unsafe.SliceData(memory.stringBuffers) != stringStart ||
		len(memory.stringBuffers) != intervals || cap(memory.stringBuffers) != intervals {
		t.Fatal("full observer repeated backing/reservation changed")
	}
	if firstSample.ByteCapacity != secondSample.ByteCapacity || firstSample.StringBacking != secondSample.StringBacking {
		t.Fatal("full observer repeated union changed", firstSample, secondSample)
	}
	t.Logf("observer only; intervals %d; first/repeated TotalAlloc delta bytes %d/%d; byte scratch len/cap %d/%d; string scratch len/cap %d/%d; byte/string unions %d/%d",
		intervals, firstAllocation, secondAllocation, len(memory.byteBuffers), cap(memory.byteBuffers), len(memory.stringBuffers), cap(memory.stringBuffers), secondSample.ByteCapacity, secondSample.StringBacking)
	runtime.KeepAlive(selected)
	runtime.KeepAlive(c)
	runtime.KeepAlive(configuration)
	runtime.KeepAlive(template)
	runtime.KeepAlive(extra)
}

func maximumOutputApplyInput(t *testing.T, s *StateSession, configuration contract.OutputConfiguration) *outputApplyInput {
	t.Helper()
	names := make(map[contract.ID]string, len(s.root.Names))
	for _, row := range s.root.Names {
		names[s.valueEntry(row.Slot).Incarnation] = row.Name
	}
	input := &outputApplyInput{}
	for _, binding := range configuration.Bindings {
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination}
		for _, target := range binding.Targets {
			name, present := names[target.EntryIncarnationID]
			if !present {
				t.Fatal("configured target has no current name")
			}
			target.EntryIncarnationID = contract.ID{}
			row.targets = append(row.targets, outputApplyTarget{entryName: name, target: target})
		}
		input.bindings = append(input.bindings, row)
	}
	input.routes = append(input.routes, outputApplyRoute{defaultRoute: true, destinations: slices.Clone(configuration.DefaultDestinations)})
	for _, route := range configuration.Routes {
		name, present := names[route.EntryIncarnationID]
		if !present {
			t.Fatal("configured route has no current entry")
		}
		input.routes = append(input.routes, outputApplyRoute{entryName: name, destinations: slices.Clone(route.Destinations)})
	}
	for _, members := range configuration.Groups {
		group := make([]string, 0, len(members))
		for _, member := range members {
			name, present := names[member]
			if !present {
				t.Fatal("configured group has no current name")
			}
			group = append(group, name)
		}
		input.groups = append(input.groups, group)
	}
	return input
}

func maximumOutputEntryInputs(t *testing.T, env fixtureEnvironment, s *StateSession, convert string) []ApplyEntryInput {
	t.Helper()
	input := s.currentEntryInputs()
	for i := range input {
		if input[i].ValueSource == contract.Generated && input[i].Name != convert {
			continue
		}
		choice := uint8(custody.EmptyValue)
		if input[i].Name == convert {
			choice = custody.MaximumValue
		}
		label := "output maximum input " + input[i].Name
		core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{
			Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
			DomainID: env.Domain, FileIdentity: fixtureID(env.Domain, label+" file"), SourceID: fixtureID(env.Domain, label+" source"),

			DataKeyID: fixtureID(env.Domain, label+" key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: input[i].Name}
		body, code := env.Custody.SealInput(t.Context(), core, input[i].Recipients, choice)
		if code != contract.CryptoSuccess {
			t.Fatal("maximum supplied input", code)
		}
		input[i].ValueSource, input[i].InputBytes = contract.Supplied, body
	}
	return input
}

// This closed fixture class uses file-backed immutable objects and a cold
// predecessor that omits opaque payloads. Constructor checks establish the
// authenticated dimensions; these guards protect the bound's runtime inputs.
func maximumOutputOwnedUpper(proof *ordinaryOutputProof, before *StateSession, entries []ApplyEntryInput) (uint64, error) {
	if proof == nil || proof.StaticUpper == 0 || before == nil {
		return 0, fmt.Errorf("source proof missing predecessor or mapped image")
	}
	parent, child := custody.GeneratorProcessOwnedByteCeilings()
	if parent != 5212790 || child != 8943845 {
		return 0, fmt.Errorf("unsupported native owners: parent=%d child=%d", parent, child)
	}
	if contract.CryptoRequestLimit != 31573219 || contract.GeneratedEntryMetadataMaxLength != 460 {
		return 0, fmt.Errorf("unsupported private request or entry owners")
	}
	store, ok := underlyingAdmittedMemoryStore(before.store)
	if !ok || store.fileBodies == nil {
		return 0, fmt.Errorf("source proof requires file-backed store")
	}
	for key, object := range store.objects {
		if key != store.desc.HeadKey && (object.Body != nil || object.bodyPath == "") {
			return 0, fmt.Errorf("source proof has resident immutable backing")
		}
	}
	r := before.root
	g := r.Generated
	if !g.ActiveOwner.IsZero() || !g.ActivePhase.IsZero() || !g.ActiveGraph.IsZero() ||
		g.Graphs.Count != 0 || g.LiveOwners.Count != 0 || g.Retiring != 0 || g.Attempts != 0 ||
		g.Duties != 0 || g.Hazards != 0 || g.Results != 0 || g.Materials != 0 || g.PendingReleases != 0 || len(before.generatedGraphs) != 0 {
		return 0, fmt.Errorf("source proof has unsupported active or retained work")
	}
	if r.ValueEntryCount > 512 || r.SecretCount > r.ValueEntryCount || r.RawBytes > 8<<20 ||
		r.MembershipCount > 4096 || r.SecretOrdinaryWrapCount > 4096 || r.RecipientCount > 256 ||
		r.ChildCount > 256 || len(r.RequiredSupport) > 256 || len(before.support) != len(r.RequiredSupport) || len(before.supportFacts) != len(r.RequiredSupport) || len(g.Fragments) > 512 ||
		g.GeneratedCurrent > 128 || g.SuccessWindow.Count > 256 || g.FailureWindow.Count > 256 ||
		len(r.CurrentAccess.Core.AccessPageRefs) > 32 || len(r.Names) != int(r.ValueEntryCount) ||
		len(entries) != len(r.Names) || len(before.generatedSliceLocations) != int(g.Slices.Count) || g.Slices.Count > 128 {
		return 0, fmt.Errorf("source proof dimensions: entries=%d inputs=%d children=%d slices=%d", r.ValueEntryCount, len(entries), r.ChildCount, g.Slices.Count)
	}
	d := r.OutputConfiguration
	if d.Schema != contract.OutputConfigurationSchema || d.TotalLength == 0 || d.TotalLength > 36<<20 || d.RoutingLength > 4<<20 ||
		d.TotalLength < d.RoutingLength+4 || d.TotalLength-d.RoutingLength-4 > 32<<20 ||
		d.SliceCount == 0 || d.SliceCount > 37 || d.BindingCount > 64 {
		return 0, fmt.Errorf("source proof output dimensions: length=%d routing=%d slices=%d bindings=%d", d.TotalLength, d.RoutingLength, d.SliceCount, d.BindingCount)
	}
	var intents uint64
	for _, location := range before.generatedSliceLocations {
		if location.ContentKind != contract.GeneratorContentIntent || location.Length > 393216 {
			return 0, fmt.Errorf("source proof unsupported logical content: kind=%d length=%d", location.ContentKind, location.Length)
		}
		var err error
		intents, err = checkedOutputMemorySum(intents, uint64(location.Length))
		if err != nil {
			return 0, err
		}
	}
	rows, coordinates := 0, 0
	for i, page := range before.support {
		if i >= len(r.RequiredSupport) {
			return 0, fmt.Errorf("source proof support correspondence missing")
		}
		opaque := false
		for _, row := range page.Records {
			rows++
			switch row.Kind {
			case contract.MutationReceiptSupportKind, contract.GeneratorVectorSupportKind, contract.GeneratedCreateEvidenceSupportKind:
				// Bounded current indexes, terminal receipts and historical source evidence.
			case contract.PublicationMarkerSupportKind:
				return 0, fmt.Errorf("source proof has publication marker")
			case contract.PublicationCoordinateSupportKind:
				coordinates++
			case contract.GeneratedFragmentSupportKind, contract.OutputConfigurationSliceSupportKind:
				opaque = true
				if row.Body != nil {
					return 0, fmt.Errorf("source proof retains opaque body: kind=%d bytes=%d", row.Kind, cap(row.Body))
				}
			default:
				return 0, fmt.Errorf("source proof unsupported support owner: kind=%d", row.Kind)
			}
		}
		if opaque {
			if _, present := before.cache[r.RequiredSupport[i]]; present {
				return 0, fmt.Errorf("source proof retains opaque page backing")
			}
		}
	}
	incarnations := 0
	for _, order := range before.adminIndex.PublicationOrder {
		incarnations += len(order.Incarnations)
	}
	// Closed constructor: 512 receipts + 128 carriers + 128 current source
	// records + 512 fragments + 37 configuration slices + 1024 coordinates
	// = 2341 predecessor rows. One handoff adds at most two, hence 2343.
	if rows > 2343 || coordinates > 1024 || len(before.adminIndex.PublicationOrder) > 1024 || incarnations > 6144 {
		return 0, fmt.Errorf("source proof support counts: rows=%d coordinates=%d incarnations=%d", rows, coordinates, incarnations)
	}
	if cached := before.generatedWork; cached != nil {
		selection := cached.selection
		if selection == nil || selection.parent != nil || selection.phase != nil || len(selection.bundles) != 0 ||
			len(selection.protected) != 0 || len(selection.canonical) != 0 {
			return 0, fmt.Errorf("source proof has extra cached generated owners")
		}
		if selection.content != nil {
			for _, fragments := range selection.content.fragments {
				for _, fragment := range fragments {
					if fragment.Payload != nil {
						return 0, fmt.Errorf("source proof retains fragment payload")
					}
				}
			}
		}
	}
	for _, page := range before.recipients {
		if page == nil {
			continue
		}
		for _, recipient := range page.Slots {
			if recipient != nil && (len(recipient.DisplayName) > 256 ||
				recipient.CurrentBinding != nil && (len(recipient.CurrentBinding.KeySelector) > contract.MaxKeySelector || len(recipient.CurrentBinding.SPKI) > 448)) {
				return 0, fmt.Errorf("source proof recipient width exceeds envelope")
			}
		}
	}
	departed := 0
	inputBuffers := retainedByteBuffers(nil, nil, nil, nil)
	members := 0
	for i, input := range entries {
		entry := before.valueEntry(r.Names[i].Slot)
		if entry == nil || input.Name != r.Names[i].Name || len(input.Name) > 256 ||
			len(input.Recipients) > 64 || input.ConfidentialityClass != entry.ConfidentialityClass ||
			!slices.Equal(input.Recipients, entry.Recipients) {
			return 0, fmt.Errorf("source proof changed input dimensions: index=%d", i)
		}
		members += len(input.Recipients)
		switch input.ValueSource {
		case contract.Generated:
			if entry.ValueSource != contract.Generated || len(input.InputBytes) != len(entry.ValueBytes) {
				return 0, fmt.Errorf("source proof has new original input: index=%d", i)
			}
		case contract.Supplied:
			if entry.ValueSource == contract.Generated {
				departed++
			}
		default:
			return 0, fmt.Errorf("source proof unsupported value source: index=%d", i)
		}
		inputBuffers.add(input.InputBytes)
	}
	if departed > 1 || members > 4096 || inputBuffers.capacity() > 15930368 {
		return 0, fmt.Errorf("source proof input envelope: departed=%d memberships=%d bytes=%d", departed, members, inputBuffers.capacity())
	}
	c, err := checkedOutputMemorySum(r.ChildEncodedBytes, uint64(before.head.Core.Root.Length), uint64(len(before.body)))
	if err != nil || c > 537198592 {
		return 0, fmt.Errorf("source proof encoded closure outside envelope: bytes=%d", c)
	}
	bounds, err := maximumOutputOwnedRows(c, uint64(d.TotalLength), intents, proof.StaticUpper)
	if err != nil {
		return 0, err
	}
	runtime.KeepAlive(entries)
	return max(bounds[0], bounds[1], bounds[2], bounds[3]), nil
}

// Fixed terms are conservative owner envelopes; C, L, omitted intent bytes and
// the checked mapped main image are inputs. No successor output is subtracted.
func maximumOutputOwnedRows(c, output, intents, static uint64) ([4]uint64, error) {
	const (
		// Clone capacity is at most ceil(5*n/4)+7 for each opaque byte field.
		// Each configuration has at most two fields per binding and target.
		cloneFields      = 2*64 + 2*1024
		cloneRounding    = ((32 << 20) + 31*cloneFields) / 4
		witness          = 91360768 + 2*cloneRounding
		ownedInput       = 53349888 // Configuration plus target/route names.
		departedTargets  = 38010880 // Configuration plus 1024 destination names.
		configuration    = 36 << 20
		permitKeys       = 64 * 256
		beforeWrites     = 4*witness + ownedInput + departedTargets + 3*configuration + permitKeys
		persisting       = 3*witness + ownedInput + departedTargets + configuration + permitKeys
		consumedCold     = 2*witness + departedTargets + 2*configuration + permitKeys
		earlyRefusalCold = 3*witness + ownedInput + departedTargets + 2*configuration + permitKeys
		// Fixed packing excluding dynamic support objects; private retained and
		// AccessAfter; parent; frame/input; read; native; serial/cold consumer;
		// separate ordinary encoding; HEAD/signature. Main image is dynamic.
		// Full retained Base64 maxima are independent of the raw-only fixture.
		retained         = 11186176
		requestBody      = 31573219 - 71
		prepared         = 4 + (14+154+215+102+2*256+489)*512 + (32+489)*4096 + retained + 128*460
		inputPopulation  = retained + 512*(819+256+8191)
		generatedClones  = 128 * 98304 // 90,517-byte entry rounded to an 8KiB allocation page.
		privateNonOutput = requestBody + prepared + generatedClones + 5*512*256 + 2*6697
		parentGenerated  = 2*generatedClones + 2*6697
		coreFrame        = 2*inputPopulation + 3*512*256 + prepared + requestBody + 371780 + 8192
		indexEncoded     = 115 + 247*1025 + 2*1025*1025 + 108*256 + (7+2*1025+37)*2343 + 34*1024 + 32*6144 + 256*116
		valueEncoded     = (154+256)*512 + 32*4096 + 215*512 + retained + 128*460
		ordinaryEncoded  = valueEncoded + 32*75 + 4630272 + indexEncoded + 327680
		ordinaryObjects  = (5*ordinaryEncoded+3)/4 + 8383*258 + (5*indexEncoded+3)/4 + 8383 + indexEncoded
		commonFixed      = 303906779 + privateNonOutput + 1769472 + parentGenerated + coreFrame + 6356535 + 14156635 + 2*2097152 + ordinaryObjects + 221181
		// Retained/name/registry/RSA owners at 512 entries, 256 recipients
		// and 4608 predecessor / 9216 successor wraps.
		beforeDecoded = retained + 215*512 + 2*256*512 + 256*(256+1024+422) + 384*4608
		afterDecoded  = retained + 215*512 + 2*256*512 + 256*(256+1024+422) + 384*9216
		// Descriptor + five HEAD/name roots + four control roots + small roots.
		admission = (4 << 20) + 8191 + 5*(65536+8191) + 4*(6697+8191) + 8192
		// Page/root/small-neighbor allocation rounding, with 2341+2 row margin.
		stateRounding = 8191 * (256 + 1 + 2343)
	)
	var rows [4]uint64
	if output > c || intents > c-output {
		return rows, fmt.Errorf("source memory subtraction underflow: closure=%d output=%d intents=%d", c, output, intents)
	}
	// Full retained value/support/access/index/Root/HEAD additions are at
	// most 70,400,141 bytes, below the independently derived 68MiB reserve.
	after, err := checkedOutputMemorySum(c, 68<<20)
	if err != nil {
		return rows, err
	}
	if after > (^uint64(0)-3)/5 {
		return rows, fmt.Errorf("source memory object multiplication overflow")
	}
	o, err := checkedOutputMemorySum((5*after+3)/4, 8383*256)
	if err != nil {
		return rows, err
	}
	j, err := checkedOutputMemorySum(after, 8191*257)
	if err != nil {
		return rows, err
	}
	beforeState, err := checkedOutputMemorySum(c-output-intents, stateRounding, beforeDecoded, admission)
	if err != nil {
		return rows, err
	}
	afterState, err := checkedOutputMemorySum(after-intents, stateRounding, afterDecoded, admission)
	if err != nil {
		return rows, err
	}
	common, err := checkedOutputMemorySum(commonFixed, o, static)
	if err != nil {
		return rows, err
	}
	for i, terms := range [][]uint64{
		{common, beforeWrites, beforeState, afterState},
		{common, persisting, beforeState, afterState, j},
		{common, consumedCold, beforeState, afterState, afterState, j},
		{common, earlyRefusalCold, beforeState, afterState},
	} {
		rows[i], err = checkedOutputMemorySum(terms...)
		if err != nil {
			return [4]uint64{}, err
		}
	}
	return rows, nil
}

// The outer allowance uses the same lifetime rows at all physical-child,
// Root and HEAD maxima, with no predecessor-output or intent subtraction.
// The mapped image remains a checked input, not a saved binary-size constant.
func maximumOutputOuterUpper(static uint64) (uint64, error) {
	rows, err := maximumOutputOwnedRows(256*(2<<20)+(256<<10)+(64<<10), 0, 0, static)
	if err != nil {
		return 0, err
	}
	return max(rows[0], rows[1], rows[2], rows[3]), nil
}

func assertMaximumOutputStatePreserved(t *testing.T, before, after *StateSession, changed string) {
	t.Helper()
	for _, field := range []struct {
		name string
		same bool
	}{
		{"names and slots", reflect.DeepEqual(before.root.Names, after.root.Names)},
		{"raw bytes", before.root.RawBytes == after.root.RawBytes},
		{"memberships", before.root.MembershipCount == after.root.MembershipCount},
		{"recipient count", before.root.RecipientCount == after.root.RecipientCount},
		{"warnings", before.root.WarningBits == after.root.WarningBits},
		{"recipient pages", reflect.DeepEqual(before.recipients, after.recipients)},
		{"success window", before.root.Generated.SuccessWindow == after.root.Generated.SuccessWindow},
		{"failure window", before.root.Generated.FailureWindow == after.root.Generated.FailureWindow},
		{"receipt order", before.root.Generated.ReceiptOrder == after.root.Generated.ReceiptOrder},
	} {
		if !field.same {
			t.Errorf("output transition changed preserved %s", field.name)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	for _, named := range before.root.Names {
		old, next := before.valueEntry(named.Slot), after.valueEntry(named.Slot)
		if named.Name == changed {
			oldPayload, oldErr := contract.InspectCanonicalPayload(old.ValueBytes)
			nextPayload, nextErr := contract.InspectCanonicalPayload(next.ValueBytes)
			if old.ValueSource != contract.Generated || next.ValueSource != contract.Supplied || old.Incarnation == next.Incarnation ||
				old.ValueState == next.ValueState || bytes.Equal(old.ValueBytes, next.ValueBytes) || !slices.Equal(old.Recipients, next.Recipients) ||
				oldErr != nil || nextErr != nil || oldPayload.DataKeyID == nextPayload.DataKeyID ||
				oldPayload.ContentLength != 64<<10 || nextPayload.ContentLength != oldPayload.ContentLength ||
				oldPayload.InputEncoding != contract.InputEncodingRaw || nextPayload.InputEncoding != contract.InputEncodingRaw ||
				oldPayload.RetainedLength != oldPayload.ContentLength || nextPayload.RetainedLength != nextPayload.ContentLength {
				t.Fatal("equal source conversion did not renew complete current identity")
			}
		} else if !reflect.DeepEqual(old, next) {
			t.Fatal("maximum transition changed an unrelated entry", named.Slot)
		}
	}
	if changed == "" && !reflect.DeepEqual(before.root.CurrentAccess, after.root.CurrentAccess) {
		t.Fatal("output-only transition changed current access")
	}
	if after.root.ChildCount > 252 || after.root.ChildEncodedBytes > contract.MaxChildPages*contract.MaxRequiredSupportPageLength {
		t.Fatal("maximum ordinary selected closure exceeds its child budget")
	}
}

func maximumConfiguredGeneratedInput(t *testing.T, before *StateSession, declarationLength int) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	t.Helper()
	var names []string
	var sources []contract.GeneratorDeclarationEntry
	var canonical []custody.GeneratedCanonicalSelection
	incarnations := make(map[string]contract.ID)
	retiring := make(map[string]contract.ValueEntry)
	var recipients []contract.ID
	fixed := 70
	for _, named := range before.root.Names {
		entry := before.valueEntry(named.Slot)
		fixed += 19 + len(entry.Name) + 32*len(entry.Recipients)
		if entry.ValueSource == contract.Generated {
			names = append(names, entry.Name)
			incarnations[entry.Name], retiring[entry.Name] = entry.Incarnation, *entry
			if recipients == nil {
				recipients = slices.Clone(entry.Recipients)
			}
			if !slices.Equal(entry.Recipients, recipients) {
				t.Fatal("replacement fixture has distinct generated memberships")
			}
			fixed += 2 + 8 + 1 + 32 + 32 + 1 + 1 + 4 // Current generated metadata, including Intent framing.
			continue
		}
		record := contract.RetainedCanonicalRecord{OriginalSlot: named.Slot, Entry: ownScenarioValueEntry(*entry)}
		body, err := contract.EncodeRetainedCanonicalRecord(record)
		if err != nil {
			t.Fatal("maximum retained supplied record", err)
		}
		// Retained envelope(8), supplied entry framing(154), name/members and
		// empty secret payload(215). Derive the division independently of Encode.
		retainedLength := 8 + 154 + len(entry.Name) + 32*len(entry.Recipients) + 215
		payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil || payload.ContentLength != 0 || payload.RetainedLength != 0 || payload.InputEncoding != entry.InputEncoding || len(body) != retainedLength {
			t.Fatal("maximum retained supplied framing", len(body), retainedLength, err)
		}
		fixed += retainedLength
		sources = append(sources, contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding,
			Name: named.Name, Recipients: slices.Clone(entry.Recipients), Payload: body})
		canonical = append(canonical, ownScenarioCanonicalSelection(custody.GeneratedCanonicalSelection{
			Selection: sessionConsumerSelection(t, before, before.admission.recipient, named.Name), Record: record}))
	}
	if len(names) != 128 || len(sources) != 384 {
		t.Fatal("maximum generated replacement dimensions", len(names), len(sources))
	}
	// Header, entry envelopes, generated metadata, retained supplied records and
	// the supplied entries' 2048 recipient memberships are independent accounts.
	const fixedBytes = 70 + 512*(19+256) + 32*4096 + 128*(2+8+1+32+32+1+1+4) + 384*(8+154+256+215) + 32*2048
	if fixed != fixedBytes || declarationLength <= fixed || declarationLength > 32<<20-8 {
		t.Fatal("maximum declaration fixed framing or requested length", fixed, declarationLength)
	}
	intentLength, remainder := (declarationLength-fixed)/len(names), (declarationLength-fixed)%len(names)
	if intentLength <= 0 || intentLength+remainder > 384<<10 {
		t.Fatal("maximum declaration intent division", fixed, intentLength, remainder)
	}
	intent := hermeticSizedGeneratorIntent("", 'x', intentLength)
	lastIntent := hermeticSizedGeneratorIntent("", 'x', intentLength+remainder)
	profile := defaultGeneratedFixtureProfile()
	profile.OutputEncoding = contract.OutputEncodingBase64
	operation := fixtureID(before.root.Domain, "maximum configured generation operation")
	bound := generatedReservationInputForMembershipStateIntents(t, before, operation, recipients, names,
		func(name string) []byte {
			if name == names[len(names)-1] {
				return lastIntent
			}
			return intent
		}, profile, 2, incarnations, retiring, sources...)
	if len(bound.declaration) != declarationLength || len(bound.declaration) != fixed+128*intentLength+remainder {
		t.Fatal("independent maximum retained declaration framing", len(bound.declaration), declarationLength, fixed, intentLength, remainder)
	}
	input := generatedPlanInputForGenerations(t, before, operation, names, profile)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	return input, canonical
}

// Parallel originals have no qualified aggregate Product ceiling. Report the
// concrete Core backing and the whole Go allocation envelope, with the existing
// native fixed charge per original; concurrent-child qualification stays open.
// Core name strings are a separate observed set. Private/transient strings and
// typed output decoding are covered by the Go envelope, not this string set.
func logMaximumGeneratedOutputPhase(t *testing.T, phase string, memory *memoryAccounting,
	before *StateSession, candidate *Candidate, observed *StateSession, producers []*generatedPreparation,
	returned []parallelOriginalResult, nativeOriginals int, extra ...[]byte) {
	t.Helper()
	memory.sample(phase, before, nil, candidate, observed)
	buffers := retainedByteBuffers(before, nil, candidate, observed)
	for _, producer := range producers {
		buffers.addGeneratedPreparation(producer)
	}
	for _, original := range returned {
		buffers.add(original.result)
	}
	for _, body := range extra {
		buffers.add(body)
	}
	var names byteBuffers
	sessions := []*StateSession{before, observed}
	if candidate != nil {
		sessions = append(sessions, candidate.session)
		if candidate.generated != nil && candidate.generated.reservation != nil {
			sessions = append(sessions, candidate.generated.reservation.state)
		}
	}
	for _, session := range sessions {
		if session == nil {
			continue
		}
		for _, named := range session.root.Names {
			names.addString(named.Name)
		}
		for _, page := range session.pages {
			if page != nil {
				for _, entry := range page.Slots {
					if entry != nil {
						names.addString(entry.Name)
					}
				}
			}
		}
		if session.generatedWork != nil {
			for _, bundle := range session.generatedWork.selection.bundles {
				for _, entry := range bundle.ValueEntryPlans {
					names.addString(entry.Name)
				}
				for _, lineage := range bundle.Lineages {
					names.addString(lineage.Name)
				}
			}
			for _, retained := range session.generatedWork.selection.canonical {
				names.addString(retained.record.Entry.Name)
				names.addString(retained.core.Name)
			}
		}
	}
	sample := &memory.samples[len(memory.samples)-1]
	sample.ByteCapacity = buffers.capacity()
	if sample.GoHeapUpperBound < sample.ByteCapacity || nativeOriginals < 0 || nativeOriginals > 128 {
		t.Fatal("generated phase envelope does not cover concrete owners", *sample, nativeOriginals)
	}
	parent, child := custody.GeneratorProcessOwnedByteCeilings()
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	selected := before
	if observed != nil {
		selected = observed
	}
	t.Logf("generated output phase %s; selected encoded bytes %d; logical output/raw bytes %d/%d; observed Core name string backing %d; phase baseline heap/allocation delta %d/%d; charged native original count %d; native fixed backing per parent/child %d/%d; aggregate native fixed backing %d; concurrent-child qualification pending; memory %s",
		phase, selected.root.ChildEncodedBytes+uint64(selected.head.Core.Root.Length)+uint64(len(selected.body)),
		selected.root.OutputConfiguration.TotalLength, selected.root.RawBytes, names.capacity(), memory.baseline.HeapAlloc,
		sample.GoHeapUpperBound-memory.baseline.HeapAlloc, nativeOriginals, parent, child,
		uint64(nativeOriginals)*(parent+child), body)
	runtime.KeepAlive(producers)
	runtime.KeepAlive(sessions)
	runtime.KeepAlive(returned)
	runtime.KeepAlive(extra)
}

func freshGeneratedSequenceContext(t *testing.T, s *StateSession, label string, previous *contract.ApplyContext) contract.ApplyContext {
	t.Helper()
	admitted := generatedPlanInputFixture(t, s).context
	admitted.AdmissionID = fixtureID(s.root.Domain, label+" admission")
	admitted.SessionID = fixtureID(s.root.Domain, label+" session")
	if admitted.AdmissionID.IsZero() || admitted.SessionID.IsZero() ||
		admitted.AdmissionID == previous.AdmissionID || admitted.SessionID == previous.SessionID {
		t.Fatal("generated sequence reused admission or session identity", label)
	}
	*previous = admitted
	return admitted
}

func assertMaximumGeneratedCanceled(t *testing.T, operationCtx context.Context, env fixtureEnvironment, s *StateSession, prepare func(context.Context) (bool, Result), used *bool, cut string) *StateSession {
	t.Helper()
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	if s.prepared {
		t.Fatal("generated cancellation predecessor already prepared")
	}
	head := store.objects[store.desc.HeadKey]
	creates, cas, signs := store.creates, store.cas, trust.signs
	public, private := env.Custody.Calls()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	want := refused(AdmissionInvalid)
	interrupted := false
	if cut == "selected_read" {
		keys := generatedSelectedFragmentKeys(t, s)
		store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
			if keys[key] {
				interrupted = true
				cancel()
			}
			return result
		}
		want = failure(EvidenceUnavailable, ReadUnavailable)
	} else {
		cancel()
	}
	present, result := prepare(ctx)
	store.readHook = nil
	if present || result != want || !*used || s.prepared || cut == "selected_read" && !interrupted {
		t.Fatal("maximum canceled accepted permit", present, result, *used, s.prepared, interrupted)
	}
	reads := store.reads
	if present, result := prepare(t.Context()); present || result != refused(AdmissionInvalid) || store.reads != reads {
		t.Fatal("maximum canceled permit was reusable", result)
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("canceled selected read entered private operation")
	}
	current := store.objects[store.desc.HeadKey]
	if creates != store.creates || cas != store.cas || signs != trust.signs || head.Token != current.Token || !bytes.Equal(head.Body, current.Body) {
		t.Fatal("canceled generated preparation changed immutable objects or selection")
	}
	env.Custody.RetireGenerated()
	cold := generatedLifecycleReopen(t, operationCtx, s, env.Store)
	if cold.prepared || cold.token != s.token || !bytes.Equal(cold.body, s.body) ||
		!reflect.DeepEqual(cold.head, s.head) || !reflect.DeepEqual(cold.root, s.root) {
		t.Fatal("canceled generated preparation changed cold selected state")
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("canceled generated cold open entered private operation")
	}
	return cold
}

func generatedControlPreservationError(before, after *StateSession, accessAdvances uint64) error {
	want := currentControlOf(before)
	if want.AccessGeneration == 0 || accessAdvances > ^uint64(0)-want.AccessGeneration {
		return fmt.Errorf("generated control fixture cannot advance access generation by %d", accessAdvances)
	}
	want.AccessGeneration += accessAdvances
	got := currentControlOf(after)
	if got.AccessGeneration != want.AccessGeneration {
		return fmt.Errorf("generated access generation = %d, want %d", got.AccessGeneration, want.AccessGeneration)
	}
	if got.AccessIncarnationID != want.AccessIncarnationID {
		return fmt.Errorf("generated phase changed the retained access incarnation")
	}
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("generated phase changed stable control fields")
	}
	return nil
}

func assertMaximumGeneratedPermanentState(t *testing.T, before, after *StateSession, accessAdvances uint64) {
	t.Helper()
	assertCapacityConfigurationFactsPreserved(t, before, after)
	for _, field := range []struct {
		name      string
		got, want uint64
	}{
		{"entries", uint64(after.root.ValueEntryCount), 512},
		{"secrets", uint64(after.root.SecretCount), 512},
		{"raw bytes", after.root.RawBytes, 8 << 20},
		{"memberships", uint64(after.root.MembershipCount), 4096},
		{"ordinary wraps", uint64(after.root.SecretOrdinaryWrapCount), 4096},
		{"recipients", uint64(after.root.RecipientCount), 256},
		{"current generated", uint64(after.root.Generated.GeneratedCurrent), 128},
		{"permanent warnings", uint64(after.root.WarningBits), uint64(before.root.WarningBits)},
	} {
		if field.got != field.want {
			t.Fatalf("generated maximum %s = %d, want %d", field.name, field.got, field.want)
		}
	}
	if !reflect.DeepEqual(before.root.Names, after.root.Names) {
		t.Fatal("generated maximum changed retained names or slots")
	}
	if !reflect.DeepEqual(before.recipients, after.recipients) {
		t.Fatal("generated maximum changed retained recipient pages")
	}
	if err := generatedControlPreservationError(before, after, accessAdvances); err != nil {
		t.Fatal(err)
	}
}

func assertMaximumGeneratedRetainedState(t *testing.T, before, after *StateSession, seed contract.AccessRecord,
	windows contract.MutationReceiptWindows) {
	t.Helper()
	assertMaximumGeneratedPermanentState(t, before, after, 1)
	for _, named := range before.root.Names {
		old := before.valueEntry(named.Slot)
		if !reflect.DeepEqual(old, after.valueEntry(named.Slot)) {
			t.Fatal("generated phase changed a retained entry or its memberships", named.Slot)
		}
		oldAccess, oldPresent := before.materialAccess(contract.ValueMaterialKind, old.ValueState)
		access, present := after.materialAccess(contract.ValueMaterialKind, old.ValueState)
		if !oldPresent || !present || !reflect.DeepEqual(oldAccess, access) {
			t.Fatal("generated phase changed retained value material access", named.Slot)
		}
	}
	access, present := after.materialAccess(contract.OperationSeedMaterialKind, seed.MaterialID)
	if len(before.accessRecords()) != 512 || len(after.accessRecords()) != 513 || after.root.AccessRecordCount != 513 ||
		!present || !reflect.DeepEqual(seed, access) {
		t.Fatal("generated phase lost current access or the exact admitted operation seed")
	}
	actual, err := after.receiptWindows(t.Context())
	if err != nil || len(actual.Successes) != 256 || len(actual.Failures) != 256 || !reflect.DeepEqual(actual, windows) ||
		after.root.Generated.SuccessWindow != before.root.Generated.SuccessWindow || after.root.Generated.FailureWindow != before.root.Generated.FailureWindow || after.root.Generated.ReceiptOrder != before.root.Generated.ReceiptOrder {
		t.Fatal("generated phase changed full retained receipt windows", err)
	}
}

// The maximum fixture has one successful original per generated replacement.
// Frame those authenticated rows directly; no terminal receipt/delta writer
// supplies the expected commitment or chooses the expected window contents.
func maximumGeneratedReceiptDescriptor(label string, rows []contract.SupportRecord) contract.GeneratorDescriptor {
	body := binary.BigEndian.AppendUint32(nil, uint32(len(rows)))
	for _, row := range rows {
		body = binary.BigEndian.AppendUint32(body, uint32(37+len(row.Body)))
		body = append(body, row.Kind)
		body = append(body, row.RecordID[:]...)
		body = binary.BigEndian.AppendUint32(body, uint32(len(row.Body)))
		body = append(body, row.Body...)
	}
	framed := append([]byte("ENKV/GENERATOR/v1/"+label+"\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
	framed = append(framed, body...)
	return contract.GeneratorDescriptor{Digest: sha256.Sum256(framed), Length: uint64(len(body)), Count: uint32(len(rows))}
}

// The frozen retirement plan supplies every semantic field. Target bytes may
// enter a descriptor only after their complete typed record matches that plan.
func generatedRetirementDutyError(domain contract.ID, retirement generatedFinalRetirement,
	capacity contract.GeneratorDescriptor, actual contract.GeneratedDutyRecord, targets [][]byte) error {
	if len(targets) != 1 {
		return fmt.Errorf("retirement targets = %d, want 1", len(targets))
	}
	target, err := contract.InspectGeneratorTarget(targets[0])
	if err != nil || target != retirement.target {
		return fmt.Errorf("retirement target differs from frozen predecessor target")
	}
	vector := binary.BigEndian.AppendUint32(nil, 1)
	vector = binary.BigEndian.AppendUint32(vector, uint32(len(targets[0])))
	vector = append(vector, targets[0]...)
	framed := append([]byte("ENKV/GENERATOR/v1/targets\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(vector)))...)
	x := retirement.template
	want := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, DomainID: domain, DutyID: x.DutyID, OwnerID: x.DutyID,
		OriginalOperationID: retirement.target.OriginalOperationID, OriginalAttemptID: retirement.target.OriginalAttemptID,
		ResourceID: retirement.target.ResourceID, ConfigContractID: retirement.target.ConfigContractID, ResourceContractID: retirement.target.ResourceContractID, LifecycleMode: retirement.target.LifecycleMode,
		DescriptorID: x.DescriptorID,
		ExecutorID:   x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		ResultContractID: x.ResultContractID, Kind: contract.GeneratedDutyRetirement, CompletionClass: retirement.target.CompletionClass,
		Step: 1, Status: contract.GeneratedEffectNotStarted, CapacityReservation: capacity,
		Target:   contract.GeneratorDescriptor{Digest: sha256.Sum256(append(framed, vector...)), Length: uint64(len(vector)), Count: 1},
		Progress: maximumGeneratedReceiptDescriptor("progress", nil), History: maximumGeneratedReceiptDescriptor("history", nil),
		Support: retirement.support, Consumers: maximumGeneratedReceiptDescriptor("consumers", nil)}
	gotFields, wantFields := reflect.ValueOf(actual), reflect.ValueOf(want)
	for i := range gotFields.NumField() {
		if gotFields.Field(i).Interface() != wantFields.Field(i).Interface() {
			return fmt.Errorf("retirement Duty field %s differs from frozen plan", wantFields.Type().Field(i).Name)
		}
	}
	return nil
}

func checkGeneratedRetirementDuty(t *testing.T, domain contract.ID, work *generatedSelection,
	retirement generatedFinalRetirement, capacity contract.GeneratorDescriptor, row contract.SupportRecord) {
	t.Helper()
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil || row.Kind != contract.GeneratedDutySupportKind || row.RecordID != retirement.template.DutyID {
		t.Fatalf("retirement Duty row: parsed=%t kind=%d want%d id_same=%t", err == nil, row.Kind, contract.GeneratedDutySupportKind, row.RecordID == retirement.template.DutyID)
	}
	targets, err := work.vectors.resolve(contract.GeneratedDutySupportKind, retirement.template.DutyID, contract.GeneratorVectorTargets, duty.Target)
	if err != nil {
		t.Fatal("retirement target carrier", err)
	}
	if err := generatedRetirementDutyError(domain, retirement, capacity, duty, targets); err != nil {
		t.Fatal(err)
	}
}

func expectedMaximumGeneratedReceipt(t *testing.T, before, terminal, after *StateSession, input generatedPlanInput,
	plan *generatedFinalPlan) contract.CompactMutationReceipt {
	t.Helper()
	if len(plan.entryPlans) != 128 || len(plan.retirements) != 128 {
		t.Fatal("maximum terminal receipt needs 128 replacements and retirements")
	}
	row := expectedGeneratedReplacementReceipt(t, before, terminal, after, input, plan, 128)
	if row.ChangedSubjects.Count != 384 || row.SummaryCounts != ([12]uint32{0: 128, 2: 128, 5: 128}) {
		t.Fatal("maximum terminal receipt changed the expected result cardinalities")
	}
	return row
}

func expectedGeneratedReplacementReceipt(t *testing.T, before, terminal, after *StateSession, input generatedPlanInput,
	plan *generatedFinalPlan, replacements int) contract.CompactMutationReceipt {
	t.Helper()
	var subjects [][]byte
	for _, entry := range plan.entryPlans {
		old := before.valueEntry(entry.Slot)
		for _, change := range []struct {
			kind, action byte
			id           contract.ID
		}{{1, 3, old.Incarnation}, {4, 2, old.Generated.GenerationID}, {4, 1, entry.Generated.GenerationID}} {
			preimage := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), before.root.Domain[:]...)
			preimage = append(preimage, change.kind)
			preimage = append(preimage, change.id[:]...)
			preimage = append(preimage, make([]byte, 32)...)
			digest := sha256.Sum256(preimage)
			subjects = append(subjects, append([]byte{change.kind, change.action}, digest[:]...))
		}
	}
	slices.SortFunc(subjects, bytes.Compare)
	body := binary.BigEndian.AppendUint32(nil, uint32(3*replacements))
	for _, subject := range subjects {
		body = binary.BigEndian.AppendUint32(body, 34)
		body = append(body, subject...)
	}
	framed := append([]byte("ENKV/GENERATOR/v1/changed-subjects\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
	changed := contract.GeneratorDescriptor{Digest: sha256.Sum256(append(framed, body...)), Length: uint64(4 + 38*3*replacements), Count: uint32(3 * replacements)}
	oldWork, newWork := mustSelectedGeneratedWork(t, terminal), mustSelectedGeneratedWork(t, after)
	var effects, duties []contract.SupportRecord
	for _, lineage := range input.graph.Lineages {
		if lineage.Purpose != contract.GeneratorLineageCreate {
			continue
		}
		row := oldWork.records[generatedRecordKey{kind: contract.GeneratedAttemptSupportKind, id: lineage.Templates[0].AttemptID}]
		attempt, err := contract.InspectGeneratedAttemptRecord(row.Body)
		if err != nil || attempt.State != contract.GeneratedEffectSucceeded || attempt.OperationID != input.graph.Request.OperationID {
			t.Fatal("maximum terminal receipt lacks the expected successful original", err)
		}
		effects = append(effects, row)
	}
	for _, retirement := range plan.retirements {
		row := newWork.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: retirement.template.DutyID}]
		checkGeneratedRetirementDuty(t, before.root.Domain, newWork, retirement, plan.request.Parent.Capacity, row)
		duties = append(duties, row)
	}
	slices.SortFunc(duties, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	if len(subjects) != 3*replacements || len(effects) != replacements || len(duties) != replacements {
		t.Fatal("maximum terminal receipt changed the expected result cardinalities")
	}
	row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationApplyDeclaration,
		StateResult: contract.ReceiptStateRetirementPending, EffectSummary: contract.ReceiptEffectComplete,
		EvidenceCeiling: contract.ReceiptEvidenceProviderFacts, CanonicalOutcome: contract.ReceiptCanonicalSelected,
		DomainID: input.graph.Request.DomainID, OperationID: input.graph.Request.OperationID,
		RequestIdentityDigest: oldWork.parent.RequestIdentityDigest,
		PredecessorRevisionID: input.graph.Request.PredecessorRevisionID, RequestedRevisionID: maximumGeneratedActualFinalRevision(t, terminal, plan),
		ObservedRevisionID: maximumGeneratedActualFinalRevision(t, terminal, plan), ChangedSubjects: changed,
		SummaryCounts: [12]uint32{0: uint32(replacements), 2: uint32(replacements), 5: uint32(replacements)}}
	// The fixed projection is 647 bytes. Five 44-byte descriptors precede the
	// final zero administrative group. Absent access changes, outputs and
	// hazards are distinct empty vectors. Fresh material IDs are additions.
	projection := binary.BigEndian.AppendUint32(nil, 1)
	projection = binary.BigEndian.AppendUint32(projection, 647)
	projection = binary.BigEndian.AppendUint16(projection, row.Schema)
	projection = binary.BigEndian.AppendUint16(projection, row.OperationKind)
	for _, id := range []contract.ID{row.DomainID, row.OperationID, input.graph.Header.RequestCoreDigest,
		row.PredecessorRevisionID, row.RequestedRevisionID, row.ObservedRevisionID} {
		projection = append(projection, id[:]...)
	}
	for _, field := range []uint16{7, 2, 0, 2} {
		projection = binary.BigEndian.AppendUint16(projection, field)
	}
	projection = append(projection, 1)
	appendDescriptor := func(descriptor contract.GeneratorDescriptor) {
		projection = append(projection, descriptor.Digest[:]...)
		projection = binary.BigEndian.AppendUint64(projection, descriptor.Length)
		projection = binary.BigEndian.AppendUint32(projection, descriptor.Count)
	}
	appendDescriptor(changed)
	projection = binary.BigEndian.AppendUint64(projection, 0)
	for _, count := range row.SummaryCounts {
		projection = binary.BigEndian.AppendUint32(projection, count)
	}
	projection = append(projection, make([]byte, 12+1+32+32+2+1+2+8)...)
	for _, descriptor := range []contract.GeneratorDescriptor{maximumGeneratedReceiptDescriptor("changed-access", nil),
		maximumGeneratedReceiptDescriptor("effect-results", effects), maximumGeneratedReceiptDescriptor("output-results", nil),
		maximumGeneratedReceiptDescriptor("result-duties", duties), maximumGeneratedReceiptDescriptor("result-hazards", nil)} {
		appendDescriptor(descriptor)
	}
	projection = append(projection, make([]byte, 32)...)
	if len(projection) != 655 {
		t.Fatal("independent maximum terminal projection length", len(projection))
	}
	framed = append([]byte("ENKV/GENERATOR/v1/complete-result\x00"), binary.BigEndian.AppendUint32(nil, 655)...)
	row.CompleteResult = contract.GeneratorDescriptor{Digest: sha256.Sum256(append(framed, projection...)), Length: 655, Count: 1}
	return row
}

func assertMaximumGeneratedFinalState(t *testing.T, before, after *StateSession, plan *generatedFinalPlan) {
	t.Helper()
	assertMaximumGeneratedPermanentState(t, before, after, 2)
	if after.root.Generated.Retiring != 128 || after.root.AccessRecordCount != 512 || len(after.accessRecords()) != 512 {
		t.Fatal("maximum final lost current material access or old retirement dimensions")
	}
	plans := make(map[uint16]contract.CryptoGeneratedValueEntryPlan, 128)
	for _, entry := range plan.entryPlans {
		plans[entry.Slot] = entry
	}
	supplied, generated := 0, 0
	for _, named := range before.root.Names {
		old, next := before.valueEntry(named.Slot), after.valueEntry(named.Slot)
		oldAccess, oldPresent := before.materialAccess(contract.ValueMaterialKind, old.ValueState)
		if next == nil || !oldPresent {
			t.Fatal("maximum final lost an entry or its predecessor access", named.Slot)
		}
		access, present := after.materialAccess(contract.ValueMaterialKind, next.ValueState)
		if old.ValueSource == contract.Supplied {
			supplied++
			if !reflect.DeepEqual(old, next) || !present || !reflect.DeepEqual(oldAccess, access) {
				t.Fatal("maximum final changed a supplied entry, membership or material access", named.Slot)
			}
			continue
		}
		generated++
		entry, planned := plans[named.Slot]
		payload, err := contract.InspectCanonicalPayload(next.ValueBytes)
		core := entry.ValueCore
		materialBody := binary.BigEndian.AppendUint16(nil, core.Schema)
		materialBody = binary.BigEndian.AppendUint16(materialBody, core.Profile)
		for _, id := range []contract.ID{core.CompatibilityID, core.CryptoSupportID, core.DomainID} {
			materialBody = append(materialBody, id[:]...)
		}
		materialBody = binary.BigEndian.AppendUint32(materialBody, uint32(len(core.Name)))
		materialBody = append(materialBody, core.Name...)
		for _, id := range []contract.ID{core.EntryIncarnationID, core.ValueStateID, core.OriginSnapshotID, core.OriginTransitionID, core.DataKeyID} {
			materialBody = append(materialBody, id[:]...)
		}
		materialBody = binary.BigEndian.AppendUint64(materialBody, core.DataKeyEpoch)
		materialBody = append(materialBody, core.CommitmentKeyID[:]...)
		materialBody = binary.BigEndian.AppendUint64(materialBody, core.CommitmentKeyEpoch)
		materialBody = binary.BigEndian.AppendUint32(materialBody, core.ContentLength)
		materialBody = append(materialBody, core.InputEncoding)
		materialBody = binary.BigEndian.AppendUint32(materialBody, core.RetainedLength)
		materialBody = append(materialBody, core.ValueSource)
		materialBody = append(materialBody, core.GeneratedBindingDigest[:]...)
		materialFrame := append([]byte("ENKV/CRYPTO/v2/material\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(materialBody)))...)
		materialContext := contract.ID(sha256.Sum256(append(materialFrame, materialBody...)))
		if !planned || err != nil || next.Name != old.Name || next.ValueSource != contract.Generated ||
			next.ConfidentialityClass != old.ConfidentialityClass || next.Incarnation != old.Incarnation ||
			next.ValueState != entry.ValueCore.ValueStateID || next.ValueState == old.ValueState || next.Generated != entry.Generated ||
			!slices.Equal(next.Recipients, entry.Recipients) || !slices.Equal(next.Recipients, old.Recipients) ||
			next.OriginSnapshot != core.OriginSnapshotID || next.OriginTransition != core.OriginTransitionID ||
			payload.DataKeyID != core.DataKeyID || payload.DataKeyEpoch != core.DataKeyEpoch ||
			payload.CommitmentKeyID != core.CommitmentKeyID || payload.CommitmentKeyEpoch != core.CommitmentKeyEpoch || payload.ContentLength != core.ContentLength ||
			payload.InputEncoding != core.InputEncoding || payload.RetainedLength != core.RetainedLength ||
			next.InputEncoding != core.InputEncoding || next.OutputEncoding != entry.OutputEncoding ||
			next.ContentLength != core.ContentLength || next.RetainedLength != core.RetainedLength || !present || access.MaterialKind != contract.ValueMaterialKind ||
			access.MaterialID != entry.ValueCore.ValueStateID || access.PackageCheck != payload.PackageCheck ||
			access.MaterialContextDigest != materialContext || access.MaterialContextDigest == oldAccess.MaterialContextDigest || len(access.Wraps) != len(oldAccess.Wraps) {
			t.Fatal("maximum final changed signed generated membership or fresh material access", named.Slot, err)
		}
		for i, wrap := range access.Wraps {
			prior := oldAccess.Wraps[i]
			if wrap.SubjectKind != prior.SubjectKind || wrap.SubjectID != prior.SubjectID || wrap.BindingID != prior.BindingID ||
				wrap.BindingSerial != prior.BindingSerial || wrap.PublicBindingDigest != prior.PublicBindingDigest ||
				len(wrap.RSACiphertext) != len(prior.RSACiphertext) || bytes.Equal(wrap.RSACiphertext, prior.RSACiphertext) {
				t.Fatal("maximum final lost exact readers/bindings or retained old material wrap", named.Slot, i)
			}
		}
	}
	if supplied != 384 || generated != 128 || len(plans) != 128 {
		t.Fatal("maximum final entry/source dimensions", supplied, generated, len(plans))
	}
}

func maximumGeneratedActualFinalRevision(t *testing.T, terminal *StateSession, plan *generatedFinalPlan) contract.ID {
	t.Helper()
	phase := plan.phase
	phase.ObservedHEADDigest = contract.Hash(terminal.body)
	phase.ConditionDigest = generatedPlanInputFixture(t, terminal).context.OriginalConditionDigest
	phase.BeforePhase = mustSelectedGeneratedWork(t, terminal).phase.Phase
	phase.AfterPhase = phase.BeforePhase + 1
	phaseID, err := contract.GeneratorPhaseID(phase)
	if err != nil {
		t.Fatal("maximum actual Final phase expectation", err)
	}
	revision, err := contract.GeneratorPhaseRevisionID(phaseID)
	if err != nil {
		t.Fatal("maximum actual Final revision expectation", err)
	}
	return revision
}

func assertMaximumGeneratedFinalReceipts(t *testing.T, before, terminal, after *StateSession, input generatedPlanInput,
	plan *generatedFinalPlan, windows contract.MutationReceiptWindows) {
	t.Helper()
	actual, err := after.receiptWindows(t.Context())
	expected := expectedMaximumGeneratedReceipt(t, before, terminal, after, input, plan)
	// The full success window evicts exactly its oldest row and appends one
	// terminal result. The failure window has no insertion or eviction.
	wantSuccess := append(slices.Clone(windows.Successes[1:]), expected)
	wantOrder := make([]contract.ID, 0, len(windows.Order))
	for _, id := range windows.Order {
		if id != windows.Successes[0].OperationID {
			wantOrder = append(wantOrder, id)
		}
	}
	wantOrder = append(wantOrder, expected.OperationID)
	if err != nil || actual.DomainID != windows.DomainID || len(actual.Successes) != 256 || len(actual.Failures) != 256 ||
		!reflect.DeepEqual(actual.Failures, windows.Failures) || !reflect.DeepEqual(actual.Successes, wantSuccess) ||
		after.root.Generated.FailureWindow != before.root.Generated.FailureWindow || !slices.Equal(actual.Order, wantOrder) || after.head.Core.Revision != maximumGeneratedActualFinalRevision(t, terminal, plan) {
		t.Fatalf("maximum final receipt: read_error=%v domain_equal=%t successes=%d failures=%d failure_rows_equal=%t success_rows_equal=%t failure_descriptor_equal=%t order_equal=%t revision_equal=%t first_success_difference=%s first_failure_difference=%s",
			err, actual.DomainID == windows.DomainID, len(actual.Successes), len(actual.Failures),
			reflect.DeepEqual(actual.Failures, windows.Failures), reflect.DeepEqual(actual.Successes, wantSuccess),
			after.root.Generated.FailureWindow == before.root.Generated.FailureWindow, slices.Equal(actual.Order, wantOrder),
			after.head.Core.Revision == maximumGeneratedActualFinalRevision(t, terminal, plan),
			generatedReceiptFirstDifference(actual.Successes, wantSuccess), generatedReceiptFirstDifference(actual.Failures, windows.Failures))
	}
}

func generatedReceiptFirstDifference(got, want []contract.CompactMutationReceipt) string {
	if len(got) != len(want) {
		return fmt.Sprintf("count:%d/%d", len(got), len(want))
	}
	for i := range want {
		actual, expected := reflect.ValueOf(got[i]), reflect.ValueOf(want[i])
		for field := range actual.NumField() {
			if actual.Field(field).Interface() != expected.Field(field).Interface() {
				return fmt.Sprintf("row%d.%s", i, actual.Type().Field(field).Name)
			}
		}
	}
	return "none"
}

// full_only: false
func TestGeneratedReplacementFinalReceiptMatchesIndependentProjection(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	env.GenesisIDs = genesisIDs{Init: testID("receipt retirement order init"), Domain: testID("receipt retirement order domain"),
		DescriptorArtifact: testID("receipt retirement order descriptor"), ManifestArtifact: testID("receipt retirement order manifest")}
	env.Domain = env.GenesisIDs.Domain
	env.Store.(*memoryStore).configure(t, contract.GCP, env.Domain)
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "custody"), false,
		[]contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")})
	env.Custody, env.Bindings, env.Crypto = keys, keys.Bindings(), keys.Crypto()
	env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
	f := newEnvironmentFixture(t, t.Context(), env, nil, false)
	names := []string{"alpha", "beta"}
	profile := defaultGeneratedFixtureProfile()
	original := generatedPlanInputForGenerations(t, f.session, testID("receipt retirement order origin 1"), names, profile)
	before := selectGeneratedWriterBatch(t, env, f.session, original, "receipt originals", custody.StandardValue)
	incarnations := make(map[string]contract.ID, 2)
	retiring := make(map[string]contract.ValueEntry, 2)
	for _, name := range names {
		old := before.valueEntry(entrySlot(t, before, name))
		incarnations[name], retiring[name] = old.Incarnation, *old
	}
	operation := testID("receipt retirement order replacement")
	bound := generatedReservationInputForMembershipStateIntent(t, before, operation, []contract.ID{before.admission.recipient},
		names, []byte("replacement"), profile, 1, incarnations, retiring)
	input := generatedPlanInputForGenerations(t, before, operation, names, profile)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	current, originals := sendParallelOriginals(t, t.Context(), env, before, reservation, custody.StandardValue)
	if len(originals) != 2 {
		t.Fatal("replacement receipt fixture needs two real successful originals", len(originals))
	}
	previous := input.context
	for i, original := range originals {
		admitted := freshGeneratedSequenceContext(t, current, fmt.Sprintf("receipt replacement record %d", i), &previous)
		record, err := current.generatedRecordRequest(t.Context(), original.expected.Template.AttemptID, original.result, admitted)
		if err != nil {
			t.Fatal("replacement receipt Record request", i, err)
		}
		prepared := preparePrivateGeneratedRecord(t, env, current, record)
		var result Result
		current, result = current.selectCandidate(t.Context(), prepared.reservation.candidate)
		if current == nil || result.Outcome != ObservedCurrent {
			t.Fatal("replacement receipt Record selection", i, result)
		}
		keys.RetireGenerated()
	}
	admitted := freshGeneratedSequenceContext(t, current, "receipt replacement final", &previous)
	plan, err := current.generatedFinalRequest(t.Context(), admitted)
	if err != nil || plan == nil || !plan.selecting || len(plan.entryPlans) != 2 || len(plan.retirements) != 2 {
		t.Fatal("replacement receipt selecting Final", err)
	}
	wantDuties := []string{"db79c32912945ceff41d11dd8dc375bcd6689282e307b31fb1b399d073943dcc", "7e3e2053d3b45f3f9998e286460597a808d496c04d0d4dd3215741944e9a2b68"}
	for i, retirement := range plan.retirements {
		if retirement.target.Name != names[i] || fmt.Sprintf("%x", retirement.template.DutyID) != wantDuties[i] {
			t.Fatal("replacement receipt fixture lost independently derived opposite Duty order", i)
		}
	}
	current, final := preparePrivateGeneratedFinal(t, env, current, plan)
	selected, result := current.selectCandidate(t.Context(), final.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("replacement receipt Final selection", result)
	}
	keys.RetireGenerated()
	cold := generatedLifecycleReopen(t, t.Context(), selected, env.Store)
	for _, state := range []struct {
		name    string
		session *StateSession
	}{{"selected", selected}, {"cold", cold}} {
		windows, err := state.session.receiptWindows(t.Context())
		if err != nil || len(windows.Successes) == 0 {
			t.Fatal(state.name, "replacement receipt windows", err)
		}
		want := expectedGeneratedReplacementReceipt(t, before, current, state.session, input, plan, 2)
		got := windows.Successes[len(windows.Successes)-1]
		if difference := generatedReceiptFirstDifference([]contract.CompactMutationReceipt{got}, []contract.CompactMutationReceipt{want}); difference != "none" {
			t.Errorf("%s replacement receipt differs from independent projection: %s", state.name, difference)
		}
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestOutputConfigurationGeneratedMaximumTransitionMemory(t *testing.T) {
	seed := newConfiguredSuccessionMemorySeed(t, true)
	t.Run("joint_publication_exits", func(t *testing.T) {
		publicationJointMixedExits(t, t.Context(), seed)
	})
	t.Run("lifecycle", func(t *testing.T) {
		env, f, keys := seed.openCase(t)
		before := f.session
		capacityConfigurationSupportRefs(t, before)
		// The other groups reserve 190 pages, including 18 for 384 maximum
		// CREATE results (22 per page). The remaining 35 Intent pages hold
		// 49 selected fragments and 19 new ones: ceil((49+19)/2)+1.
		// With 27 index shards this fills 252 children. One more byte needs 253.
		const declarationBoundary = 19 * (1<<20 - 256)
		store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
		if len(before.adminIndex.Groups) != 1024 {
			t.Fatal("maximum predecessor administrative group count", len(before.adminIndex.Groups))
		}
		for _, group := range before.adminIndex.Groups {
			if group.OwnerKind != format.AdministrativePublicationCoordinate {
				t.Fatal("maximum predecessor has an unexpected administrative owner", group.OwnerKind)
			}
		}
		for _, tc := range []struct {
			name   string
			length int
		}{{"full_declaration_refused", 33_554_374}, {"one_byte_over_declaration_refused", declarationBoundary + 1}} {
			if !t.Run(tc.name, func(t *testing.T) {
				input, _ := maximumConfiguredGeneratedInput(t, before, tc.length)
				if before.prepared {
					t.Fatal("capacity refusal predecessor is already prepared")
				}
				public, private := keys.Calls()
				creates, cas, signs, objects := store.creates, store.cas, trust.signs, len(store.objects)
				head := store.objects[store.desc.HeadKey]
				head.Body = bytes.Clone(head.Body)
				body, token := bytes.Clone(before.body), before.token
				root, err := format.EncodeRoot(before.root)
				if err != nil {
					t.Fatal("capacity refusal predecessor root", err)
				}
				plan, err := before.generatedPlanRequest(t.Context(), input)
				if plan != nil || err != contract.ErrRecordCapacity || before.prepared {
					t.Fatal("over-budget complete reservation reached preparation", tc.length, plan != nil, err, before.prepared)
				}
				afterRoot, err := format.EncodeRoot(before.root)
				current := store.objects[store.desc.HeadKey]
				p, k := keys.Calls()
				if err != nil || !bytes.Equal(root, afterRoot) || p != public || k != private ||
					store.creates != creates || store.cas != cas || trust.signs != signs || len(store.objects) != objects ||
					head.Token != current.Token || !bytes.Equal(head.Body, current.Body) || before.token != token || !bytes.Equal(before.body, body) {
					t.Fatalf("capacity refusal changed private work or selected state: length=%d public=%d private=%d creates=%d CAS=%d signs=%d objects=%d root_error=%v", tc.length, p-public, k-private, store.creates-creates, store.cas-cas, trust.signs-signs, len(store.objects)-objects, err)
				}
			}) {
				return
			}
		}
		input, canonical := maximumConfiguredGeneratedInput(t, before, declarationBoundary)
		plan, err := before.generatedPlanRequest(t.Context(), input)
		if err != nil || plan == nil || before.prepared || !plan.intents.changed || !plan.intents.emit || plan.intents.fragments != 49 {
			declaration, declarationErr := contract.InspectGeneratorDeclaration(input.declaration)
			selected, selectedErr := before.selectedGeneratedWork(t.Context())
			t.Logf("reservation capacity input: declaration-bytes=%d declaration-error=%v selected-error=%v", len(input.declaration), declarationErr, selectedErr)
			if declarationErr == nil && selectedErr == nil {
				shape, shapeErr := before.generatedAdmissionShape(t.Context(), input.graph, declaration, selected)
				t.Logf("reservation capacity shape: entries=%d pages=%d recipients=%d secrets=%d memberships=%d secret-memberships=%d generated=%d old-generated=%d creates=%d retirements=%d controlled-retirements=%d plans=%d sources=%d retained-sources=%d cleanups=%d controlled-cleanups=%d old-intent-bytes=%d recovery=%t error=%v",
					shape.ValueEntryCount, shape.ValueEntryPageCount, shape.Recipients, shape.Secrets, shape.Memberships, shape.SecretMemberships, shape.Generated, shape.OldGenerated,
					shape.Creates, shape.Retirements, shape.ControlledRetirements, shape.ValueEntryPlanCount, shape.Sources, shape.RetainedSources, shape.Cleanups, shape.ControlledCleanups, shape.OldIntentBytes, shape.Recovery, shapeErr)
				projection, projectionErr := planGeneratedCurrentIntents(t.Context(), before, selected, selectedGeneratedLocations(selected))
				t.Logf("reservation capacity projection: fragments=%d bytes=%d changed=%t emit=%t error=%v", projection.fragments, projection.total, projection.changed, projection.emit, projectionErr)
				if shapeErr == nil && projectionErr == nil {
					shape.DeclarationBytes = uint64(len(input.declaration))
					if projection.changed && projection.emit {
						shape.ProjectedCurrentIntentFragments = uint64(projection.fragments)
					}
					groups, groupsErr := generatedCapacityWithProjectedBacklog(shape, selected, &projection)
					t.Logf("reservation capacity backlog: groups=%+v error=%v", groups, groupsErr)
					if groupsErr == nil {
						groups, publicationErr := before.generatedPublicationCapacity(t.Context(), groups)
						t.Logf("reservation capacity publication: groups=%+v error=%v", groups, publicationErr)
						oldBytes, oldErr := format.AdministrativeIndexEncodedLength(before.adminIndex)
						indexBytes, indexErr := before.generatedAdministrativeReservedLength(shape)
						shards, shardsErr := before.generatedAdministrativeShardReserve(shape)
						exitShards, exitErr := before.generatedAdministrativeFirstExitShardReserve(shape)
						var pages uint32
						for _, group := range groups {
							pages += group.MaxPages
						}
						t.Logf("reservation capacity totals: group-pages=%d old-index-bytes=%d old-index-error=%v index-bytes=%d index-error=%v shards=%d shards-error=%v exit-shards=%d exit-error=%v",
							pages, oldBytes, oldErr, indexBytes, indexErr, shards, shardsErr, exitShards, exitErr)
					}
				}
			}
			t.Fatal("exact complete reservation boundary", err, before.prepared)
		}
		if got := plan.capacity.Groups[contract.GeneratorCapacityIntents]; got != (contract.GeneratorCapacityGroup{MaxCount: 68, MaxFramedBytes: 70_258_092, MaxPages: 35}) {
			t.Fatal("exact declaration and retained Intent charge", got)
		}
		if got := plan.capacity.Groups[contract.GeneratorCapacityAuxiliary]; got != (contract.GeneratorCapacityGroup{MaxCount: 54, MaxFramedBytes: 55_397_548, MaxPages: 30}) {
			t.Fatal("complete prepared image and retained configuration charge", got)
		}
		declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
		if err != nil {
			t.Fatal("exact boundary declaration", err)
		}
		shape, err := before.generatedAdmissionShape(t.Context(), input.graph, declaration, mustSelectedGeneratedWork(t, before))
		if err != nil {
			t.Fatal("exact boundary selected shape", err)
		}
		// The 384 supplied rows have 64 + 8*1 + 101*6 + 274*5 readers.
		// Their exact preserved-material union is separate from the 128 fresh
		// generated rows, whose 16 readers each are already in current access.
		if shape.finalImageReaders == nil || *shape.finalImageReaders != 2048 {
			t.Fatal("exact supplied material reader allowance", shape.finalImageReaders)
		}
		shape.DeclarationBytes, shape.ProjectedCurrentIntentFragments = uint64(len(input.declaration)), 49
		indexBytes, err := before.generatedAdministrativeReservedLength(shape)
		// Retained canonical summaries add 384*32 material-association bytes
		// after the shared fragment-row and owner-reference reservation.
		if err != nil || indexBytes != 54_876_988 {
			t.Fatal("exact boundary administrative reserve", indexBytes, err)
		}
		shards, err := before.generatedAdministrativeShardReserve(shape)
		if err != nil || shards != 27 {
			t.Fatal("exact boundary prospective index shards", shards, err)
		}
		exitShards, err := before.generatedAdministrativeFirstExitShardReserve(shape)
		if err != nil || exitShards != 27 {
			t.Fatal("exact boundary first-exit index shards", exitShards, err)
		}
		var reservedPages uint32
		for _, group := range plan.capacity.Groups {
			reservedPages += group.MaxPages
		}
		if reservedPages != 225 || reservedPages+shards != ordinaryChildPageLimit || reservedPages+2+exitShards != 254 {
			t.Fatal("exact complete reservation and first-exit boundary", reservedPages, shards, exitShards)
		}
		windows, err := before.receiptWindows(t.Context())
		if err != nil || len(windows.Successes) != 256 || len(windows.Failures) != 256 {
			t.Fatal("maximum predecessor full receipt windows", err)
		}
		memory := startMemoryAccounting()
		reservation, permit := preparePrivateGeneratedReservation(t, env, before, input, canonical)
		logMaximumGeneratedOutputPhase(t, "generated-reservation", memory, before, reservation.reservation.candidate, nil, nil, nil, 1, input.declaration)
		seedAccess, present := reservation.reservation.state.materialAccess(contract.OperationSeedMaterialKind, input.graph.Header.MaterialID)
		if !present || seedAccess.Schema != contract.CanonicalSchema || seedAccess.MaterialID != input.graph.Header.MaterialID ||
			seedAccess.MaterialContextDigest.IsZero() || seedAccess.PackageCheck.IsZero() || len(seedAccess.Wraps) != 2 ||
			seedAccess.Wraps[0].SubjectKind != 1 || seedAccess.Wraps[0].SubjectID != before.admission.recipient ||
			seedAccess.Wraps[1].SubjectKind != 2 || seedAccess.Wraps[1].SubjectID != before.root.CurrentAccess.Core.Recovery.RoleID {
			t.Fatal("maximum reservation lost exact operation seed identity/readers")
		}
		assertMaximumGeneratedRetainedState(t, before, reservation.reservation.state, seedAccess, windows)
		memory = startMemoryAccounting()
		frontiers := []string{"prepared", "claimed", "returned", "selected", "retired"}
		frontier := 0
		current, originals := sendParallelOriginals(t, t.Context(), env, before, reservation, custody.MaximumValue,
			func(phase string, producers []*generatedPreparation, selected *StateSession, returned []parallelOriginalResult) {
				if frontier >= len(frontiers) || phase != frontiers[frontier] || len(producers) != 128 || len(returned) != 128 {
					t.Fatal("maximum original frontier/order/count", phase, frontier, len(producers), len(returned))
				}
				frontier++
				for _, producer := range producers {
					if producer == nil || !producer.claimed || producer.reservation != reservation.reservation {
						t.Fatal("maximum original frontier lacks a claimed producer from this reservation", phase)
					}
				}
				candidate := reservation.reservation.candidate
				if phase == "prepared" {
					if candidate.generated.originalsComplete {
						t.Fatal("maximum preparation frontier already claimed the complete set")
					}
				} else if !candidate.generated.originalsComplete || len(candidate.originalProducers) != 128 || len(candidate.generated.originalClaims) != 128 {
					t.Fatal("maximum original frontier lacks complete-set Claim", phase)
				}
				if phase == "returned" || phase == "selected" || phase == "retired" {
					for _, original := range returned {
						if original.code != contract.CryptoSuccess || original.persist.Outcome != 0 || len(original.result) == 0 {
							t.Fatal("maximum original frontier lacks a joined durable result", phase)
						}
					}
				}
				nativeOriginals := 128
				if phase == "retired" {
					nativeOriginals = 0
				}
				logMaximumGeneratedOutputPhase(t, "generated-originals-"+phase, memory, before,
					reservation.reservation.candidate, selected, producers, returned, nativeOriginals, input.declaration)
				if selected != nil {
					capacityConfigurationSupportRefs(t, selected)
					assertMaximumGeneratedRetainedState(t, before, selected, seedAccess, windows)
				}
				if phase != "retired" {
					memory = startMemoryAccounting()
				}
			})
		if frontier != len(frontiers) || len(originals) != 128 {
			t.Fatal("maximum originals omitted a joined frontier or effect", frontier, len(originals))
		}
		selectedOriginals := current
		memory = startMemoryAccounting()
		current = generatedLifecycleReopen(t, t.Context(), selectedOriginals, env.Store)
		logMaximumGeneratedOutputPhase(t, "generated-originals-cold-retired", memory, selectedOriginals,
			reservation.reservation.candidate, current, nil, originals, 0, input.declaration)
		capacityConfigurationSupportRefs(t, current)
		assertMaximumGeneratedRetainedState(t, before, current, seedAccess, windows)
		if reservation.reservation.candidate.firstSend != nil {
			t.Fatal("cold open acquired first-send rights")
		}
		previous := input.context
		for _, cut := range []string{"pre_canceled", "selected_read"} {
			if !t.Run("record_"+cut, func(t *testing.T) {
				admitted := freshGeneratedSequenceContext(t, current, "maximum configured record "+cut, &previous)
				admitted.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
				original := originals[0]
				plan, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, admitted)
				if err != nil {
					t.Fatal("maximum configured canceled Record request", err)
				}
				memory := startMemoryAccounting()
				permit := admitPrivateGeneratedRecord(t.Context(), t, keys, current, plan)
				predecessor := current
				current = assertMaximumGeneratedCanceled(t, t.Context(), env, predecessor, func(ctx context.Context) (bool, Result) {
					p, result := predecessor.PrepareGeneratedRecord(ctx, permit)
					return p != nil, result
				}, &permit.used, cut)
				logMaximumGeneratedOutputPhase(t, "generated-record-canceled-retired", memory, predecessor, nil, current, nil, originals, 0, plan.result, input.declaration)
				capacityConfigurationSupportRefs(t, current)
				assertMaximumGeneratedRetainedState(t, before, current, seedAccess, windows)
			}) {
				return
			}
		}
		// Selecting only a Record failure must not execute the full Record prefix.
		t.Run("records_and_final", func(t *testing.T) {
			for i, original := range originals {
				admitted := freshGeneratedSequenceContext(t, current, fmt.Sprintf("maximum configured record %d", i), &previous)
				admitted.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
				plan, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, admitted)
				if err != nil {
					t.Fatal("maximum configured record request", i, err)
				}
				memory = startMemoryAccounting()
				prepared := preparePrivateGeneratedRecord(t, env, current, plan)
				selected, result := current.selectCandidate(t.Context(), prepared.reservation.candidate)
				if selected == nil || result.Outcome != ObservedCurrent || selected.root.ChildCount > 256 {
					t.Fatal("maximum configured record selection", i, result)
				}
				logMaximumGeneratedOutputPhase(t, "generated-record", memory, current, prepared.reservation.candidate, selected, nil, originals, 1, plan.result, input.declaration)
				capacityConfigurationSupportRefs(t, selected)
				assertMaximumGeneratedRetainedState(t, before, selected, seedAccess, windows)
				memory = startMemoryAccounting()
				keys.RetireGenerated()
				current = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				logMaximumGeneratedOutputPhase(t, "generated-record-cold-retired", memory, selected,
					prepared.reservation.candidate, current, nil, originals, 0, plan.result, input.declaration)
				capacityConfigurationSupportRefs(t, current)
				assertMaximumGeneratedRetainedState(t, before, current, seedAccess, windows)
			}
			for _, cut := range []string{"pre_canceled", "selected_read"} {
				if !t.Run("final_"+cut, func(t *testing.T) {
					admitted := freshGeneratedSequenceContext(t, current, "maximum configured final "+cut, &previous)
					admitted.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
					plan, err := current.generatedFinalRequest(t.Context(), admitted)
					if err != nil || !plan.selecting || len(plan.entryPlans) != 128 {
						t.Fatal("maximum configured canceled selecting Final", err)
					}
					memory := startMemoryAccounting()
					permit := admitPrivateGeneratedFinal(t, env, current, plan)
					predecessor := current
					current = assertMaximumGeneratedCanceled(t, t.Context(), env, predecessor, func(ctx context.Context) (bool, Result) {
						p, result := predecessor.PrepareGeneratedFinal(ctx, permit)
						return p != nil, result
					}, &permit.used, cut)
					logMaximumGeneratedOutputPhase(t, "generated-final-canceled-retired", memory, predecessor, nil, current, nil, originals, 0, input.declaration)
					capacityConfigurationSupportRefs(t, current)
					assertMaximumGeneratedRetainedState(t, before, current, seedAccess, windows)
				}) {
					return
				}
			}
			t.Run("complete", func(t *testing.T) {
				admitted := freshGeneratedSequenceContext(t, current, "maximum configured final complete", &previous)
				admitted.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
				plan, err := current.generatedFinalRequest(t.Context(), admitted)
				if err != nil || !plan.selecting || len(plan.entryPlans) != 128 {
					t.Fatal("maximum configured selecting final", err)
				}
				memory = startMemoryAccounting()
				current, final := preparePrivateGeneratedFinal(t, env, current, plan)
				selected, result := current.selectCandidate(t.Context(), final.reservation.candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("maximum configured final selection", result)
				}
				logMaximumGeneratedOutputPhase(t, "generated-final-selected", memory, current, final.reservation.candidate, selected, nil, originals, 1, input.declaration)
				capacityConfigurationSupportRefs(t, selected)
				assertMaximumGeneratedFinalState(t, before, selected, plan)
				assertMaximumGeneratedFinalReceipts(t, before, current, selected, input, plan, windows)
				memory = startMemoryAccounting()
				keys.RetireGenerated()
				cold := generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				logMaximumGeneratedOutputPhase(t, "generated-final-cold-retired", memory, selected,
					final.reservation.candidate, cold, nil, originals, 0, input.declaration)
				capacityConfigurationSupportRefs(t, cold)
				assertMaximumGeneratedFinalState(t, before, cold, plan)
				assertMaximumGeneratedFinalReceipts(t, before, current, cold, input, plan, windows)
				if cold.root.Generated.GeneratedCurrent != 128 || cold.root.ValueEntryCount != 512 || cold.root.Generated.Retiring != 128 ||
					cold.root.RawBytes != 8<<20 || cold.root.MembershipCount != 4096 || cold.root.SecretOrdinaryWrapCount != 4096 ||
					cold.root.RecipientCount != 256 || !reflect.DeepEqual(cold.root.Names, before.root.Names) ||
					!reflect.DeepEqual(cold.recipients, before.recipients) {
					t.Fatal("maximum final current or retirement dimensions", cold.root.Generated, cold.root.ValueEntryCount, cold.root.RawBytes, cold.root.MembershipCount)
				}
				oldGenerated := make(map[string]*contract.ValueEntry)
				for _, named := range before.root.Names {
					old := before.valueEntry(named.Slot)
					if old.ValueSource == contract.Generated {
						oldGenerated[named.Name] = old
					} else if !reflect.DeepEqual(old, cold.valueEntry(named.Slot)) {
						t.Fatal("maximum final changed a retained supplied entry", named.Slot)
					}
				}
				work := mustSelectedGeneratedWork(t, cold)
				for _, row := range work.records {
					if row.Kind != contract.GeneratedDutySupportKind {
						continue
					}
					duty, err := contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil {
						t.Fatal("maximum final retirement duty", err)
					}
					if duty.Kind != contract.GeneratedDutyRetirement {
						continue
					}
					target, err := work.retirementTarget(t.Context(), duty)
					old := oldGenerated[target.Name]
					if err != nil || old == nil || target.IncarnationID != old.Incarnation || target.Epoch != old.Generated.Epoch ||
						target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest ||
						target.LifecycleMode != old.Generated.LifecycleMode || target.ConfigContractID != old.Generated.ConfigContractID ||
						target.ResourceContractID != old.Generated.ResourceContractID || target.OriginalOperationID != old.Generated.OriginOperationID ||
						target.OriginalAttemptID != old.Generated.OriginAttemptID || target.CompletionClass != old.Generated.CompletionClass ||
						duty.Support != old.Generated.RequiredSupport {
						t.Fatal("maximum final changed an old retirement target or required support", err)
					}
					intent, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, old.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
					if err != nil {
						t.Fatal("maximum final lost an old signed retirement intent", err)
					}
					assertCapacityIntentBytes(t, old.Name, intent)
					delete(oldGenerated, target.Name)
				}
				if len(oldGenerated) != 0 {
					t.Fatal("maximum final omitted an old retirement obligation", len(oldGenerated))
				}
				for _, entryPlan := range plan.entryPlans {
					old, next := before.valueEntry(entryPlan.Slot), cold.valueEntry(entryPlan.Slot)
					payload, err := contract.InspectCanonicalPayload(next.ValueBytes)
					oldPayload, oldErr := contract.InspectCanonicalPayload(old.ValueBytes)
					if err != nil || oldErr != nil || next.Incarnation != old.Incarnation || next.ValueState != entryPlan.ValueCore.ValueStateID ||
						next.ValueState == old.ValueState || payload.DataKeyID == oldPayload.DataKeyID || next.Generated != entryPlan.Generated {
						t.Fatal("maximum final signed entry identity or fresh material", entryPlan.Slot, err, oldErr)
					}
					if check := keys.Consume(t.Context(), sessionConsumerSelection(t, cold, cold.admission.recipient, next.Name), custody.MaximumValue); check.Code != contract.CryptoSuccess || !check.ValueMatched {
						t.Fatal("maximum final private value", check.Code)
					}
				}
				runtime.KeepAlive(permit)
				runtime.KeepAlive(originals)
			})
		})
	})
}

func assertMaximumPublicationTransition(t *testing.T, before, after *StateSession, configuration contract.OutputConfiguration) {
	t.Helper()
	coordinates := make(map[contract.ID]contract.PublicationCoordinate)
	markers := make(map[contract.ID][]byte)
	for _, page := range before.support {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.PublicationCoordinateSupportKind:
				coordinate, err := contract.InspectPublicationCoordinate(row.Body)
				if err != nil {
					t.Fatal("predecessor coordinate", err)
				}
				coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
				for _, binding := range configuration.Bindings {
					for _, target := range binding.Targets {
						if coordinate.ServiceContractID == target.ServiceContractID && coordinate.CanonicalTarget == target.CanonicalTarget {
							coordinate.BindingState, coordinate.ActiveBindingIncarnationID = contract.PublicationBindingActive, binding.IncarnationID
						}
					}
				}
				coordinates[row.RecordID] = coordinate
			case contract.PublicationMarkerSupportKind:
				markers[row.RecordID] = row.Body
			}
		}
	}
	for _, page := range after.support {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.PublicationCoordinateSupportKind:
				actual, err := contract.InspectPublicationCoordinate(row.Body)
				want, present := coordinates[row.RecordID]
				if err != nil || !present || !reflect.DeepEqual(actual, want) {
					t.Fatal("selected coordinate changed retained deletion, birth, marker or ordinal facts", err)
				}
				delete(coordinates, row.RecordID)
			case contract.PublicationMarkerSupportKind:
				if want, present := markers[row.RecordID]; !present || !bytes.Equal(want, row.Body) {
					t.Fatal("selected output changed retained marker")
				}
				delete(markers, row.RecordID)
			}
		}
	}
	if len(coordinates) != 0 || len(markers) != 0 || !reflect.DeepEqual(before.adminIndex.PublicationOrder, after.adminIndex.PublicationOrder) {
		t.Fatal("selected output omitted retained publication facts")
	}
}

// full_only: false
func TestOutputConfigurationPreparationAdmissionKeepsPermit(t *testing.T) {
	for _, mode := range []string{"memory", "file"} {
		t.Run(mode, func(t *testing.T) {
			testOutputConfigurationPreparationAdmissionKeepsPermit(t, mode == "file")
		})
	}
}

func testOutputConfigurationPreparationAdmissionKeepsPermit(t *testing.T, fileBacked bool) {
	t.Helper()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	defer keys.RetireApply()
	f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
	entries := firstSecretInput(t, env, f.session)
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "app")}}}}
	output.bindings[0].targets[0].target.Policy = contract.OutputPolicy{ContractID: "test-policy", Data: []byte(`{}`)}
	before := selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, keys, entries, output)
	if fileBacked {
		if err := env.Store.(*memoryStore).useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
			t.Fatal("enable file bodies", err)
		}
	}
	output.bindings[0].targets[0].target.Policy.Data = []byte(`{"scope":"whole"}`)
	output.bindings[0].destination.Policy = output.bindings[0].targets[0].target.Policy
	parent := admitSuppliedOutputComparison(t, before, keys, entries, output)
	c, result := before.compareWithOutput(t.Context(), entries, output, parent)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("small output comparison", result)
	}
	permit := admit(t, before, c)
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	reads, creates, cas, signs := store.reads, store.creates, store.cas, trust.signs
	public, private := keys.Calls()
	input, projection, transition := c.outputIntent, c.outputAfter, c.outputAfter.transition
	if fileBacked {
		// Fixed scalar allowance checks method admission and visible arithmetic
		// before the extra witness; it is not runtime image/arena qualification.
		proof := &ordinaryOutputProof{StaticUpper: 116572160}
		upper, err := maximumOutputOwnedUpper(proof, before, entries)
		if err != nil {
			t.Fatal("small file method admission unavailable", err)
		}
		memory := startOrdinaryOutputAccounting(nil)
		memory.sample("portable-method-admission-before-independent-witness", before, c, nil, nil)
		sample := memory.samples[0]
		sample.SourceOwnedUpper = upper
		if err := checkVisibleOutputSource(sample, proof.StaticUpper); err != nil {
			t.Fatal("small file visible arithmetic", err)
		}
		t.Logf("portable method admission only: source allowance=%d static allowance=%d visible bytes/strings=%d/%d", upper, proof.StaticUpper, sample.ByteCapacity, sample.StringBacking)
	}
	witness, err := parent.support.Output.Own()
	if err != nil {
		t.Fatal(err)
	}
	want, result := before.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 {
		t.Fatal("small predecessor configuration", result)
	}
	want.Bindings[0].Targets[0].Policy.Data = []byte(`{"scope":"whole"}`)
	want.Bindings[0].Destination.Policy = want.Bindings[0].Targets[0].Policy
	reads = store.reads
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, row := range []struct {
		name string
		ctx  context.Context
	}{{"pre_canceled", ctx}, {"nil_context", nil}} {
		t.Run(row.name, func(t *testing.T) {
			candidate, result := before.Prepare(row.ctx, c, permit, env.Trust)
			if candidate != nil || result != refused(AdmissionInvalid) || permit.used || before.prepared {
				t.Fatalf("pre-admission refusal: candidate=%t result=%+v permit_used=%t session_prepared=%t", candidate != nil, result, permit.used, before.prepared)
			}
			if p, k := keys.Calls(); p != public || k != private || store.reads != reads || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatalf("pre-admission call deltas: public=%d private=%d reads=%d creates=%d CAS=%d signs=%d", p-public, k-private, store.reads-reads, store.creates-creates, store.cas-cas, trust.signs-signs)
			}
			if c.outputIntent != input || c.outputAfter != projection || projection.transition != transition || c.operation.terminal || !reflect.DeepEqual(parent.support.Output, witness) {
				t.Fatalf("pre-admission ownership: input_same=%t projection_same=%t transition_same=%t private_terminal=%t witness_same=%t", c.outputIntent == input, c.outputAfter == projection, projection.transition == transition, c.operation.terminal, reflect.DeepEqual(parent.support.Output, witness))
			}
		})
	}
	// The public guard refused admission, so no preparation attempt was accepted.
	candidate, result := before.Prepare(t.Context(), c, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("valid preparation after pre-admission refusal", result)
	}
	checkConsumedOutputComparison(t, before, c, permit, parent, witness, projection.descriptor, projection.records)
	reads, creates, cas, signs = store.reads, store.creates, store.cas, trust.signs
	public, private = keys.Calls()
	for _, invalid := range []context.Context{ctx, nil} {
		if result := before.Select(invalid, candidate); result != refused(AdmissionInvalid) || candidate.used {
			t.Fatalf("pre-admission selection refusal: result=%+v candidate_used=%t", result, candidate.used)
		}
		if p, k := keys.Calls(); p != public || k != private || store.reads != reads || store.creates != creates || store.cas != cas || trust.signs != signs {
			t.Fatalf("pre-admission selection call deltas: public=%d private=%d reads=%d creates=%d CAS=%d signs=%d", p-public, k-private, store.reads-reads, store.creates-creates, store.cas-cas, trust.signs-signs)
		}
	}
	if result := before.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
		t.Fatal("valid selection after pre-admission refusal", result)
	}
	keys.RetireApply()
	cold, result := Open(t.Context(), f.admission, store)
	if cold == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold output after pre-admission refusal", result)
	}
	assertMaximumOutputStatePreserved(t, before, cold, "")
	actual, result := cold.currentOutputConfigurationForApply(t.Context())
	if result.Outcome != 0 || !reflect.DeepEqual(actual, want) {
		t.Fatalf("cold configuration: result=%+v configuration_same=%t", result, reflect.DeepEqual(actual, want))
	}
	assertMaximumPublicationTransition(t, before, cold, want)
}

// full_only: false
func TestOutputConfigurationCancellationPreservesSelectedState(t *testing.T) {
	for _, mode := range []string{"memory", "file"} {
		t.Run(mode, func(t *testing.T) {
			testOutputConfigurationCancellationPreservesSelectedState(t, mode == "file")
		})
	}
}

func testOutputConfigurationCancellationPreservesSelectedState(t *testing.T, fileBacked bool) {
	t.Helper()
	for _, cut := range []string{"last_configuration_read", "immutable_readback", "signing_refused", "selection_pre_canceled", "selection_unknown_with_effect", "selection_unknown_without_effect"} {
		t.Run(cut, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			defer keys.RetireApply()
			f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
			entries := firstSecretInput(t, env, f.session)
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "app")}}}}
			output.bindings[0].targets[0].target.Policy = contract.OutputPolicy{ContractID: "test-policy", Data: []byte(`{}`)}
			before := selectAdmittedOutputConfiguration(t, t.Context(), f.session, env, keys, entries, output)
			if cut == "last_configuration_read" {
				current := *before
				current.support = nil
				mixed := format.RequiredSupportPageView{Domain: env.Domain, Object: fixtureID(env.Domain, "small mixed support"), Index: generatedFixtureFreeSupportIndex(t, before)}
				for _, ref := range before.root.RequiredSupport {
					body, result := before.readObjectBorrowedUncached(t.Context(), ref)
					if result.Outcome != 0 {
						t.Fatal("small mixed support read", result)
					}
					page, err := format.InspectRequiredSupportPage(body)
					if err != nil {
						t.Fatal("small mixed support page", err)
					}
					var retained []contract.SupportRecordView
					for _, row := range page.Records {
						if row.Kind == contract.OutputConfigurationSliceSupportKind || row.Kind == contract.PublicationCoordinateSupportKind {
							mixed.Records = append(mixed.Records, row)
						} else {
							retained = append(retained, row)
						}
					}
					if len(retained) == 0 {
						continue
					}
					if len(retained) != len(page.Records) {
						page.Object = fixtureID(env.Domain, fmt.Sprintf("small mixed retained support/%d", page.Index))
						page.Records = retained
					}
					current.support = append(current.support, page)
				}
				if len(mixed.Records) != 2 {
					t.Fatal("small mixed support needs one configuration and one coordinate", len(mixed.Records))
				}
				current.root.Snapshot, current.root.Transition = fixtureID(env.Domain, "small mixed snapshot"), fixtureID(env.Domain, "small mixed transition")
				current.support = append(current.support, mixed)
				slices.SortFunc(current.support, func(a, b format.RequiredSupportPageView) int { return int(a.Index) - int(b.Index) })
				generatedRefreshSupport(t, &current)
				store := env.Store.(*memoryStore)
				put := func(ref format.Ref, body []byte) {
					if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
						t.Fatal("small mixed support write", err)
					}
				}
				for i, page := range current.support {
					storedRows := make([]contract.SupportRecord, len(page.Records))
					for j, row := range page.Records {
						storedRows[j] = contract.SupportRecord(row)
					}
					body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: page.Domain, Object: page.Object, Index: page.Index, Records: storedRows})
					if err != nil {
						t.Fatal("small mixed support encoding", err)
					}
					put(current.root.RequiredSupport[i], body)
				}
				shards, err := format.EncodeAdministrativeIndexPages(current.adminIndex)
				if err != nil {
					t.Fatal("small mixed support index", err)
				}
				for _, shard := range shards {
					put(shard.Ref, shard.Body)
				}
				_, before = writeSignedCurrentIntentImage(t, env, before, before, &current, store, "small mixed configuration cancellation", put)
				refs := capacityConfigurationSupportRefs(t, before)
				if len(refs) != 1 {
					t.Fatal("small mixed configuration page count", len(refs))
				}
				position, found := before.selectedSupportPosition(refs[0])
				if !found || len(before.supportFacts[position].rows) <= 1 {
					t.Fatal("small fixture needs configuration and other selected rows on the same page")
				}
			}
			if fileBacked {
				if err := env.Store.(*memoryStore).useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
					t.Fatal("enable file bodies", err)
				}
			}
			want, result := before.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 {
				t.Fatal("small predecessor configuration", result)
			}
			output.bindings[0].targets[0].target.Policy.Data = []byte(`{"scope":"whole"}`)
			output.bindings[0].destination.Policy = output.bindings[0].targets[0].target.Policy
			parent := admitSuppliedOutputComparison(t, before, keys, entries, output)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			head := store.objects[store.desc.HeadKey]
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if cut == "last_configuration_read" {
				if before.root.OutputConfiguration.SliceCount != 1 {
					t.Fatal("small fixture needs one complete configuration slice")
				}
				target, visits := outputConfigurationCancellationTarget(t, before, store, 0)
				if visits != 1 {
					t.Fatalf("small configuration visits=%d, want1", visits)
				}
				reads, creates, cas, signs := store.reads, store.creates, store.cas, trust.signs
				public, private := keys.Calls()
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if key == target {
						cancel()
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
					}
					return read
				}
				c, result := before.compareWithOutput(ctx, entries, output, parent)
				store.readHook = nil
				expected := Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonLimit}
				p, k := keys.Calls()
				if c != nil || result != expected || parent.used || ctx.Err() != context.Canceled || store.reads-reads != 1 || p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs {
					t.Fatalf("configuration read refusal: comparison=%t result=%+v parent_used=%t canceled=%t reads=%d public=%d private=%d creates=%d CAS=%d signs=%d", c != nil, result, parent.used, ctx.Err() == context.Canceled, store.reads-reads, p-public, k-private, store.creates-creates, store.cas-cas, trust.signs-signs)
				}
			} else {
				c, result := before.compareWithOutput(t.Context(), entries, output, parent)
				if c == nil || result.Outcome != ObservedCurrent {
					t.Fatal("small comparison", result)
				}
				permit := admit(t, before, c)
				cas := store.cas
				signer := env.Trust
				var fault *preparationFaultStore
				switch cut {
				case "immutable_readback":
					if len(c.normalSupportObjects) == 0 {
						t.Fatal("small output candidate lacks support object")
					}
					object := c.normalSupportObjects[len(c.normalSupportObjects)-1]
					fault = &preparationFaultStore{memoryStore: store, target: mustKey(t, store.desc.Prefix, object.ref), mode: "readback-unavailable"}
					before.store = fault
				case "signing_refused":
					signer = &signResultTrust{Trust: env.Trust, result: contract.SignResult{Reason: contract.ReasonProof}}
				}
				candidate, result := before.Prepare(ctx, c, permit, signer)
				if cut == "immutable_readback" || cut == "signing_refused" {
					expected := failure(IntegrityFailure, InvalidProof)
					if fault != nil {
						expected = Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}
						writes, reads := 0, 0
						for _, event := range fault.events {
							if event.key == fault.target && event.write != 0 {
								writes++
							}
							if event.key == fault.target && event.read == contract.ReadUnavailable {
								reads++
							}
						}
						if writes != 1 || reads != 3 {
							t.Fatalf("exact immutable fault: writes=%d unavailable_reads=%d", writes, reads)
						}
					} else if calls := signer.(*signResultTrust).calls; calls != 1 {
						t.Fatalf("sign refusal calls=%d, want1", calls)
					}
					if candidate != nil || result != expected || !permit.used || !before.prepared || store.cas != cas {
						t.Fatalf("accepted failure: candidate=%t result=%+v permit_used=%t prepared=%t CAS=%d", candidate != nil, result, permit.used, before.prepared, store.cas-cas)
					}
					reads, creates, signs := store.reads, store.creates, trust.signs
					public, private := keys.Calls()
					if retry, result := before.Prepare(t.Context(), c, permit, signer); retry != nil || result != refused(AdmissionInvalid) {
						t.Fatal("accepted failed preparation permit reused", result)
					}
					if p, k := keys.Calls(); reads != store.reads || creates != store.creates || cas != store.cas || signs != trust.signs || p != public || k != private {
						t.Fatal("accepted failed preparation reuse caused effects")
					}
					for ref, body := range before.cache {
						if err := format.CheckReference(ref, body); err != nil {
							t.Fatal("unverified failed cache", err)
						}
					}
				} else {
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("small selection preparation", result)
					}
					wrapper := &recordingCASStore{Store: store, cancelledReads: true}
					wrapper.write = func(call context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
						if cut == "selection_unknown_with_effect" {
							if write := store.CompareAndSwap(call, key, token, body); write.Status != contract.WriteAcknowledged {
								t.Fatal("small entered selection", write.Status)
							}
						}
						cancel()
						return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
					}
					before.store = wrapper
					expected := Result{Outcome: UnresolvedCommit, Reason: ReadUnavailable, RequestedRevision: candidate.head.Core.Revision, CommitMayHaveOccurred: true, StoreReason: contract.ReasonLimit}
					calls := 1
					if cut == "selection_pre_canceled" {
						cancel()
						expected = refused(AdmissionInvalid)
						calls = 0
					}
					result = before.Select(ctx, candidate)
					if result != expected || wrapper.calls != calls || wrapper.readCalls != 0 || candidate.used != (calls == 1) {
						t.Fatalf("selection boundary: result=%+v calls=%d reads=%d candidate_used=%t", result, wrapper.calls, wrapper.readCalls, candidate.used)
					}
					if calls == 1 {
						assertExactSelectionRequest(t, wrapper, store.desc.HeadKey, head.Token, candidate.body)
					}
					if cut == "selection_unknown_with_effect" {
						want.Bindings[0].Targets[0].Policy.Data = []byte(`{"scope":"whole"}`)
						want.Bindings[0].Destination.Policy = want.Bindings[0].Targets[0].Policy
					}
				}
			}
			keys.RetireApply()
			cold, result := Open(t.Context(), f.admission, store)
			if cold == nil || result.Outcome != ObservedCurrent {
				t.Fatal("small cold output", result)
			}
			assertMaximumOutputStatePreserved(t, before, cold, "")
			actual, result := cold.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 || !reflect.DeepEqual(actual, want) {
				t.Fatalf("small cold configuration: result=%+v same=%t", result, reflect.DeepEqual(actual, want))
			}
			current := store.objects[store.desc.HeadKey]
			if cut == "selection_unknown_with_effect" {
				if current.Token == head.Token || !bytes.Equal(current.Body, cold.body) || cold.head.Core.Revision == before.head.Core.Revision {
					t.Fatal("unknown effect lost exact cold successor")
				}
				assertMaximumPublicationTransition(t, before, cold, want)
			} else {
				if current.Token != head.Token || !bytes.Equal(current.Body, head.Body) || !bytes.Equal(cold.body, before.body) {
					t.Fatal("failed attempt changed selected HEAD")
				}
				assertCapacityConfigurationPreserved(t, before, cold)
			}
		})
	}
}

func outputConfigurationCancellationTarget(t *testing.T, selected *StateSession, store *memoryStore, last uint16) (string, int) {
	t.Helper()
	capacityConfigurationSupportRefs(t, selected)
	if last+1 != selected.root.OutputConfiguration.SliceCount {
		t.Fatal("configuration interruption target is not the final slice")
	}
	id, err := contract.OutputConfigurationSliceID(selected.root.Domain, selected.root.OutputConfiguration.ConfigurationDigest, last)
	if err != nil {
		t.Fatal("configuration interruption identity", err)
	}
	for _, facts := range selected.supportFacts {
		visits, target := 0, false
		for _, fact := range facts.rows {
			if fact.Kind() == contract.OutputConfigurationSliceSupportKind {
				visits++
				target = target || fact.RecordID() == id
			}
		}
		if !target {
			continue
		}
		key := mustKey(t, store.desc.Prefix, facts.ref)
		value, present := store.objects[key]
		if !present {
			t.Fatal("configuration interruption object missing")
		}
		read := readFixtureStoredBody(value, facts.ref.Length)
		if read.Status != contract.ReadOK {
			t.Fatalf("configuration interruption read: status=%d reason=%d", read.Status, read.Reason)
		}
		if err := format.CheckReference(facts.ref, read.Body); err != nil {
			t.Fatal("configuration interruption reference", err)
		}
		page, err := format.InspectRequiredSupportPage(read.Body)
		if err != nil {
			t.Fatal("configuration interruption fixture", err)
		}
		for i, fact := range facts.rows {
			if fact.Kind() != contract.OutputConfigurationSliceSupportKind || fact.RecordID() != id {
				continue
			}
			row := page.Records[facts.ordinals[i]]
			part, err := contract.InspectOutputConfigurationSlice(row.Body)
			if err != nil || row.Kind != fact.Kind() || row.RecordID != id || part.SliceIndex != last {
				t.Fatal("configuration interruption slice", err)
			}
			t.Logf("configuration interruption target: last_slice=%d selected_configuration_visits=%d physical_rows=%d", last, visits, len(page.Records))
			return key, visits
		}
	}
	t.Fatal("no last authenticated configuration slice")
	return "", 0
}

// full_only: false
func TestOutputConfigurationGeneratedControlPreservesStableFields(t *testing.T) {
	for _, outputEncoding := range []uint8{contract.OutputEncodingRaw, contract.OutputEncodingBase64} {
		t.Run(fmt.Sprint(outputEncoding), func(t *testing.T) {
			testOutputConfigurationGeneratedControlPreservesStableFields(t, outputEncoding)
		})
	}
}

func testOutputConfigurationGeneratedControlPreservesStableFields(t *testing.T, outputEncoding uint8) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newNamedEnvironmentFixture(t, t.Context(), env, []int{1}, false, []string{"configuration-seed"})
	sources, _ := generatedCurrentDeclaration(t, f.session)
	recipients := capacityRecipients(t, f.session, 2)
	selected := signedFullIntentSource(t, t.Context(), env, f.session, fixtureID(env.Domain, "control original"),
		[]string{"configured-generated"}, sources, recipients, custody.StandardValue, outputEncoding, "control original", nil)
	configuration := capacityOutputConfiguration(t, selected, false)
	if len(selected.root.Names) != 2 || len(configuration.Groups) != 0 {
		t.Fatal("configured control needs two entries and no inherited groups")
	}
	var group []contract.ID
	for _, named := range selected.root.Names {
		group = append(group, selected.valueEntry(named.Slot).Incarnation)
	}
	slices.SortFunc(group, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if outputEncoding == contract.OutputEncodingRaw {
		configuration.Groups = [][]contract.ID{{group[0]}, {group[1]}}
	} else {
		configuration.Groups = [][]contract.ID{group}
	}
	store, before := signedCapacityConfigurationImage(t, env, f.session, selected, "configured control", false, configuration)
	env.Store = store
	beforeOutput, outputResult := before.currentOutputConfigurationForApply(t.Context())
	if outputResult.Outcome != 0 || !reflect.DeepEqual(beforeOutput, configuration) {
		t.Fatal("configured control changed its complete selected output baseline", outputResult)
	}
	old := before.valueEntry(entrySlot(t, before, "configured-generated"))
	operation := fixtureID(env.Domain, "control replacement")
	profile := defaultGeneratedFixtureProfile()
	profile.OutputEncoding = outputEncoding
	bound := generatedReservationInputForMembershipStateIntent(t, before, operation, recipients,
		[]string{old.Name}, []byte("replacement"), profile, old.Generated.Epoch+1,
		map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old}, sources...)
	input := generatedPlanInputForGenerations(t, before, operation, []string{old.Name}, profile)
	input.graph, input.declaration = bound.graph, bound.declaration
	input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
	input.requestBindings = slices.Clone(bound.requestBindings)
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	after := reservation.reservation.state
	t.Logf("real reservation retained fields: entries %d/%d; secrets %d/%d; raw %d/%d; membership %d/%d; wraps %d/%d; registry %d/%d; generated %d/%d; names equal %t; recipient pages equal %t; warnings %d/%d; access generation %d/%d; access incarnation equal %t",
		before.root.ValueEntryCount, after.root.ValueEntryCount, before.root.SecretCount, after.root.SecretCount,
		before.root.RawBytes, after.root.RawBytes, before.root.MembershipCount, after.root.MembershipCount,
		before.root.SecretOrdinaryWrapCount, after.root.SecretOrdinaryWrapCount, before.root.RecipientCount, after.root.RecipientCount,
		before.root.Generated.GeneratedCurrent, after.root.Generated.GeneratedCurrent,
		reflect.DeepEqual(before.root.Names, after.root.Names), reflect.DeepEqual(before.recipients, after.recipients),
		before.root.WarningBits, after.root.WarningBits, before.root.CurrentAccess.Core.AccessGeneration, after.root.CurrentAccess.Core.AccessGeneration,
		before.root.CurrentAccess.Core.AccessIncarnationID == after.root.CurrentAccess.Core.AccessIncarnationID)
	assertCapacityConfigurationFactsPreserved(t, before, after)
	if err := generatedControlPreservationError(before, after, 1); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"missing advance", "extra advance", "incarnation", "domain", "normal signer", "recovery"} {
		t.Run(damage, func(t *testing.T) {
			changed := *after
			want := "generated phase changed stable control fields"
			switch damage {
			case "missing advance":
				changed.root.CurrentAccess.Core.AccessGeneration--
				want = fmt.Sprintf("generated access generation = %d, want %d", before.root.CurrentAccess.Core.AccessGeneration, before.root.CurrentAccess.Core.AccessGeneration+1)
			case "extra advance":
				changed.root.CurrentAccess.Core.AccessGeneration++
				want = fmt.Sprintf("generated access generation = %d, want %d", before.root.CurrentAccess.Core.AccessGeneration+2, before.root.CurrentAccess.Core.AccessGeneration+1)
			case "incarnation":
				changed.root.CurrentAccess.Core.AccessIncarnationID[0] ^= 1
				want = "generated phase changed the retained access incarnation"
			case "domain":
				changed.root.CurrentAccess.Core.DomainID[0] ^= 1
			case "normal signer":
				changed.root.CurrentAccess.Core.NormalSigning.KeySelector += "-changed"
			case "recovery":
				recovery := *changed.root.CurrentAccess.Core.Recovery
				recovery.RoleID[0] ^= 1
				changed.root.CurrentAccess.Core.Recovery = &recovery
			}
			if err := generatedControlPreservationError(before, &changed, 1); err == nil || err.Error() != want {
				t.Fatal("generated control preservation accepted damage or failed for the wrong reason", err, want)
			}
		})
	}
	entered, record, _, _ := selectActualGeneratedPacketRecord(t, env, before, reservation, custody.StandardValue, false, nil)
	for _, phase := range []struct {
		name  string
		state *StateSession
	}{
		{"entered", entered}, {"prepared record", record.reservation.state},
	} {
		if err := generatedControlPreservationError(before, phase.state, 1); err != nil {
			t.Fatal(phase.name, err)
		}
	}
	current, result := entered.selectCandidate(t.Context(), record.reservation.candidate)
	if current == nil || result.Outcome != ObservedCurrent {
		t.Fatal("configured control record selection", result)
	}
	env.Custody.RetireGenerated()
	current = generatedLifecycleReopen(t, t.Context(), current, env.Store)
	if err := generatedControlPreservationError(before, current, 1); err != nil {
		t.Fatal("cold record", err)
	}
	admitted := generatedPlanInputFixture(t, current).context
	admitted.AdmissionID = fixtureID(env.Domain, "control final admission")
	admitted.SessionID = fixtureID(env.Domain, "control final session")
	plan, err := current.generatedFinalRequest(t.Context(), admitted)
	if err != nil || !plan.selecting {
		t.Fatal("configured control selecting final", err)
	}
	current, final := preparePrivateGeneratedFinal(t, env, current, plan)
	closed, result := current.selectCandidate(t.Context(), final.reservation.candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("configured control final selection", result)
	}
	env.Custody.RetireGenerated()
	cold := generatedLifecycleReopen(t, t.Context(), closed, env.Store)
	if len(plan.retirements) != 1 {
		t.Fatal("small generated control needs exactly one frozen retirement")
	}
	work := mustSelectedGeneratedWork(t, cold)
	row := work.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: plan.retirements[0].template.DutyID}]
	duty, err := contract.InspectGeneratedDutyRecord(row.Body)
	if err != nil {
		t.Fatal("small retirement duty", err)
	}
	retirement := plan.retirements[0]
	targets, err := work.vectors.resolve(contract.GeneratedDutySupportKind, retirement.template.DutyID, contract.GeneratorVectorTargets, duty.Target)
	if err != nil {
		t.Fatal("small retirement target carrier", err)
	}
	for _, state := range []*StateSession{final.reservation.state, closed, cold} {
		stateWork := mustSelectedGeneratedWork(t, state)
		stateRow := stateWork.records[generatedRecordKey{kind: contract.GeneratedDutySupportKind, id: retirement.template.DutyID}]
		checkGeneratedRetirementDuty(t, before.root.Domain, stateWork, retirement, plan.request.Parent.Capacity, stateRow)
	}
	for _, field := range []string{"ExecutorID", "CredentialRouteID", "DescriptorID", "ResultContractID", "CapacityReservation", "Target", "Progress", "History", "Support", "Consumers", "target_carrier", "missing_target_carrier"} {
		t.Run("retirement_"+field, func(t *testing.T) {
			damaged, targetRows := duty, slices.Clone(targets)
			want := "retirement Duty field " + field + " differs from frozen plan"
			switch field {
			case "target_carrier":
				target, err := contract.InspectGeneratorTarget(targetRows[0])
				if err != nil {
					t.Fatal(err)
				}
				target.ResourceDigest[0] ^= 1
				targetRows[0], err = contract.EncodeGeneratorTarget(target)
				if err != nil {
					t.Fatal(err)
				}
				want = "retirement target differs from frozen predecessor target"
			case "missing_target_carrier":
				targetRows = nil
				want = "retirement targets = 0, want 1"
			default:
				value := reflect.ValueOf(&damaged).Elem().FieldByName(field)
				if value.Type() == reflect.TypeFor[contract.GeneratorDescriptor]() {
					value = value.FieldByName("Digest")
				}
				value.Index(0).SetUint(value.Index(0).Uint() ^ 1)
			}
			if err := generatedRetirementDutyError(before.root.Domain, retirement, plan.request.Parent.Capacity, damaged, targetRows); err == nil || err.Error() != want {
				t.Fatalf("retirement damage %s: error=%v, want %s", field, err, want)
			}
		})
	}
	for _, state := range []*StateSession{final.reservation.state, closed, cold} {
		currentOutput, outputResult := state.currentOutputConfigurationForApply(t.Context())
		if outputResult.Outcome != 0 {
			t.Fatal("configured control final output read", outputResult)
		}
		if !reflect.DeepEqual(currentOutput, beforeOutput) {
			t.Errorf("configured control final output differs: groups %d/%d equal=%t bindings=%t defaults=%t routes=%t",
				len(currentOutput.Groups), len(beforeOutput.Groups), reflect.DeepEqual(currentOutput.Groups, beforeOutput.Groups),
				reflect.DeepEqual(currentOutput.Bindings, beforeOutput.Bindings), slices.Equal(currentOutput.DefaultDestinations, beforeOutput.DefaultDestinations),
				reflect.DeepEqual(currentOutput.Routes, beforeOutput.Routes))
		}
		if err := generatedControlPreservationError(before, state, 2); err != nil {
			t.Fatal("selecting final", err)
		}
		assertCapacityConfigurationFactsPreserved(t, before, state)
	}
	t.Logf("real generated control stages: predecessor/reservation/entered/prepared-record/cold-record/final/cold-final generation %d/%d/%d/%d/%d/%d/%d",
		before.root.CurrentAccess.Core.AccessGeneration, after.root.CurrentAccess.Core.AccessGeneration,
		entered.root.CurrentAccess.Core.AccessGeneration, record.reservation.state.root.CurrentAccess.Core.AccessGeneration,
		current.root.CurrentAccess.Core.AccessGeneration, closed.root.CurrentAccess.Core.AccessGeneration, cold.root.CurrentAccess.Core.AccessGeneration)
}
