package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func capacityRecipients(t *testing.T, selected *StateSession, count int) []contract.ID {
	t.Helper()
	recipients := []contract.ID{selected.admission.recipient}
	for _, page := range selected.recipients {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row != nil && row.Status == contract.CurrentRecipient && row.RecipientID != selected.admission.recipient && len(recipients) < count {
				recipients = append(recipients, row.RecipientID)
			}
		}
	}
	if len(recipients) != count {
		t.Fatal("capacity current recipient count", len(recipients), count)
	}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	return recipients
}

// The same selected-state construction is used for the small relationship
// check and the complete capacity fixtures. Provider effects are not exercised.
func capacityOutputConfiguration(t *testing.T, selected *StateSession, full bool) contract.OutputConfiguration {
	t.Helper()
	var entries []*contract.ValueEntry
	for _, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		if entry == nil {
			t.Fatal("configuration selected entry")
		}
		if entry.ValueSource == contract.Generated {
			entries = append(entries, entry)
		}
	}
	slices.SortFunc(entries, func(a, b *contract.ValueEntry) int { return bytes.Compare(a.Incarnation[:], b.Incarnation[:]) })
	bindings, entriesPerBinding := 2, len(entries)
	if full {
		bindings, entriesPerBinding = 64, 16
		if len(selected.root.Names) > 512 {
			t.Fatal("configuration selected entry count", len(selected.root.Names))
		}
		if len(entries) != 128 {
			t.Fatal("configuration generated entry count", len(entries))
		}
		for _, entry := range entries {
			if len(entry.Recipients) != 16 {
				t.Fatal("configuration actual memberships", len(entry.Recipients))
			}
		}
	}
	if entriesPerBinding == 0 {
		t.Fatal("configuration has no generated entries")
	}
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: selected.root.Domain}
	for b := 0; b < bindings; b++ {
		name := fmt.Sprintf("destination-%02d", b)
		if full {
			length := 256
			if b == 63 {
				length = 234
			}
			name += "-" + strings.Repeat("d", length-len(name)-1)
		}
		binding := contract.OutputBinding{DestinationID: name, IncarnationID: fixtureID(selected.root.Domain, fmt.Sprintf("capacity binding %d", b))}
		var subjects []string
		members := 2
		if full {
			members = 384
			if b == 63 {
				members = 403
			}
		}
		for member := 0; member < members; member++ {
			padding := 70
			if full && member >= 10 {
				padding = 71
			}
			text := fmt.Sprintf("m%04d", member) + strings.Repeat("x", padding)
			if full && b == 63 && member == 402 {
				text += strings.Repeat("y", 45+2*(512-len(selected.root.Names)))
			}
			subjects = append(subjects, text)
		}
		policy := hermeticTextPolicy("test-capacity-members", subjects)
		var settings [][2]string
		binding.Destination = contract.OutputDestination{ConfigContractID: "TEST/OUTPUT/CAPACITY/v3", ServiceContractID: "test-capacity", Policy: policy, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}
		for key := 0; key < 3; key++ {
			keyName := fmt.Sprintf("setting-%d", key)
			value := fmt.Sprintf("fixture-value-%02d", b)
			if full {
				keyName += strings.Repeat("k", 256-len(keyName))
				length := 1024
				if b == 63 && key == 2 {
					length = 998
				}
				value = fmt.Sprintf("b%02d", b) + strings.Repeat("v", length-3)
			}
			settings = append(settings, [2]string{keyName, value})
		}
		binding.Destination.CanonicalSettings = hermeticDestinationSettings(settings)
		first := 0
		if full {
			first = (b / 8) * 16
		}
		for e := 0; e < entriesPerBinding; e++ {
			slot := fmt.Sprintf("capacity/b%02d/e%03d", b, e)
			encoding := entries[first+e].OutputEncoding
			data := []byte("target:" + slot)
			if full && b == 0 && e < 9 {
				length := 4096
				if e == 8 {
					length = 1368
				}
				data = append(data, bytes.Repeat([]byte{'x'}, length-len(data))...)
			}
			binding.Targets = append(binding.Targets, contract.OutputTarget{
				EntryIncarnationID: entries[first+e].Incarnation, ServiceContractID: binding.Destination.ServiceContractID,
				TargetContractID: "test-capacity-target", CanonicalTarget: slot, ConsumerLocator: slot + "/current", TargetData: data,
				PayloadEncoding: encoding, Capabilities: binding.Destination.Capabilities,
				CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: policy,
			})
		}
		configuration.Bindings = append(configuration.Bindings, binding)
	}
	if full {
		var ids []contract.ID
		for _, named := range selected.root.Names {
			ids = append(ids, selected.valueEntry(named.Slot).Incarnation)
		}
		slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		for _, id := range ids {
			configuration.Groups = append(configuration.Groups, []contract.ID{id})
		}
	}
	for index, entry := range entries {
		route := contract.OutputRoute{EntryIncarnationID: entry.Incarnation}
		first, count := 0, bindings
		if full {
			first, count = (index/16)*8, 8
		}
		for b := first; b < first+count; b++ {
			route.Destinations = append(route.Destinations, configuration.Bindings[b].DestinationID)
		}
		configuration.Routes = append(configuration.Routes, route)
	}
	if full {
		for _, binding := range configuration.Bindings[:8] {
			configuration.DefaultDestinations = append(configuration.DefaultDestinations, binding.DestinationID)
		}
		for _, named := range selected.root.Names {
			entry := selected.valueEntry(named.Slot)
			if entry.ValueSource != contract.Generated {
				configuration.Routes = append(configuration.Routes, contract.OutputRoute{EntryIncarnationID: entry.Incarnation, Destinations: []string{}})
			}
		}
	}
	slices.SortFunc(configuration.Routes, func(a, b contract.OutputRoute) int {
		return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
	})
	if full && len(configuration.Routes) != len(selected.root.Names) {
		t.Fatal("configuration actual routing dimensions")
	}
	return configuration
}

// full_only: true
func TestCapacityOutputConfigurationKeepsExactEffectiveTargetSet(t *testing.T) {
	// Only this fixture's public route authorship is under test. The signed
	// selected image and maximum private owners remain covered by the full roots.
	id := func(n int) contract.ID {
		var v contract.ID
		v[30], v[31] = byte(n>>8), byte(n)
		return v
	}
	for _, tc := range []struct {
		groups           int
		lastSubjectBytes int
		lastPolicyBytes  int
		policySHA256     string
		routingSHA256    string
	}{
		{128, 889, 32672, "e6cfebebd431b404b138b62d896b5e3a02f8bf8d6b85248a268bd779d98fa232", "c698892b4c1cce91d90741a83f8435884830d6828b3419095734930a0b13b4ad"},
		{129, 887, 32670, "2660c4b692d80cc9efbf22555111924c8433263042a2dae9b0b25cb497038200", "6d3ce787f5bb7fed19b3b6cf27880e310c2ba9f1e477099c0ed422cf3abc2b3e"},
		{512, 121, 31904, "7ec8befab2581e1ac45c0ad12822a0f5b93f632e689578bf4fa0fd20d6116cbe", "521a8a73dc56034312d23ed5dfc8c36ac0babdca018ac60ceb732dd7cd16bbfa"},
	} {
		t.Run(fmt.Sprintf("groups-%d", tc.groups), func(t *testing.T) {
			selected := &StateSession{root: format.Root{Domain: id(2000)}}
			for i := 0; i < tc.groups; i++ {
				page, slot := i/format.PageSlots, i%format.PageSlots
				if selected.pages[page] == nil {
					selected.pages[page] = &format.ValueEntryPage{}
				}
				name := fmt.Sprintf("entry-%03d", i)
				entry := &contract.ValueEntry{Name: name, Incarnation: id(i + 1), ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
				if i < 128 {
					entry.ValueSource = contract.Generated
					entry.OutputEncoding = contract.OutputEncodingBase64
					for r := 0; r < 16; r++ {
						entry.Recipients = append(entry.Recipients, id(1025+r))
					}
				}
				selected.pages[page].Slots[slot] = entry
				selected.root.Names = append(selected.root.Names, format.NameEntry{Name: name, Slot: uint16(i)})
			}
			configuration := capacityOutputConfiguration(t, selected, true)
			wantGroups := make([][]contract.ID, tc.groups)
			for i := range wantGroups {
				wantGroups[i] = []contract.ID{id(i + 1)}
			}
			if !reflect.DeepEqual(configuration.Groups, wantGroups) {
				t.Fatal("capacity fixture groups do not contain the exact selected singleton set", len(configuration.Groups), tc.groups)
			}
			if len(configuration.Bindings) != 64 {
				t.Fatal("capacity fixture binding count", len(configuration.Bindings))
			}
			// Each absent singleton costs 34 bytes. The final policy occurs 17 times,
			// so two extra opaque policy bytes per absent singleton retain the exact declaration.
			lastPolicy := configuration.Bindings[63].Destination.Policy
			var subjects []string
			if err := json.Unmarshal(lastPolicy.Data, &subjects); err != nil || len(subjects) != 403 || len(subjects[402]) != tc.lastSubjectBytes || capacityPolicyLength(t, lastPolicy) != tc.lastPolicyBytes {
				t.Fatal("capacity fixture final policy dimensions", len(subjects), tc.lastSubjectBytes, tc.lastPolicyBytes, err)
			}
			// Fixed hashes come from independent compact JSON serialization of
			// the ordinary fixture strings, without an ENKV encoder or helper.
			if got := fmt.Sprintf("%x", sha256.Sum256(lastPolicy.Data)); got != tc.policySHA256 {
				t.Fatal("capacity fixture exact policy bytes", got)
			}
			settingsBytes := configuration.Bindings[63].Destination.CanonicalSettings
			if got := fmt.Sprintf("%x", sha256.Sum256(settingsBytes)); len(settingsBytes) != 3833 || got != "3b8359463ed665e9d8cfd7d3a291b17465656272ceaad98f286dd6b910c8cfd7" {
				t.Fatal("capacity fixture exact settings bytes", len(settingsBytes), got)
			}
			type pair struct {
				entry       contract.ID
				destination string
			}
			want := make(map[pair]bool, 1024)
			for e := 0; e < 128; e++ {
				for b := (e / 16) * 8; b < (e/16)*8+8; b++ {
					padding := 241
					if b == 63 {
						padding = 219
					}
					destination := fmt.Sprintf("destination-%02d-", b) + strings.Repeat("d", padding)
					want[pair{id(e + 1), destination}] = true
				}
			}
			targets, effective := make(map[pair]bool), make(map[pair]bool)
			settings, encodedEntries, encodedTargets, targetRows := 0, 0, 0, 0
			for _, named := range selected.root.Names {
				if selected.valueEntry(named.Slot).OutputEncoding == contract.OutputEncodingBase64 {
					encodedEntries++
				}
			}
			for _, binding := range configuration.Bindings {
				var values map[string]string
				if err := json.Unmarshal(binding.Destination.CanonicalSettings, &values); err != nil {
					t.Fatal("capacity fixture settings", err)
				}
				settings += len(values)
				targetRows += len(binding.Targets)
				for _, target := range binding.Targets {
					if target.PayloadEncoding == contract.OutputEncodingBase64 {
						encodedTargets++
					}
					targets[pair{target.EntryIncarnationID, binding.DestinationID}] = true
				}
			}
			references := 0
			for _, route := range configuration.Routes {
				if route.EntryIncarnationID.IsZero() {
					t.Fatal("capacity fixture no longer uses explicit entry replacements")
				}
				for _, destination := range route.Destinations {
					effective[pair{route.EntryIncarnationID, destination}] = true
					references++
				}
			}
			if !reflect.DeepEqual(targets, want) || !reflect.DeepEqual(effective, want) {
				t.Fatalf("capacity fixture effective routes do not name its exact target set: targets=%d effective=%d want=%d", len(targets), len(effective), len(want))
			}
			declaration, routing := capacityConfigurationLengths(t, configuration)
			if settings != 192 || encodedEntries != 128 || encodedTargets != 1024 || targetRows != 1024 || len(configuration.Routes) != tc.groups || references != 1024 || declaration != 33554432 || routing != 267973+33*tc.groups {
				t.Fatal("capacity fixture lost its exact joint dimensions", len(configuration.Routes), references, declaration, routing)
			}
			// Independent Routing/v3 encoding with the fixed
			// IDs above gives this digest, without a production encoder or normalizer.
			image, err := contract.EncodeOutputConfiguration(configuration)
			if err != nil || len(image) != 33554436+routing {
				t.Fatal("capacity fixture image", len(image), err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(image[len(image)-routing:])); got != tc.routingSHA256 {
				t.Fatal("capacity fixture exact routing bytes", got)
			}
			_, parts, err := contract.SplitOutputConfiguration(selected.root.Domain, image)
			if err != nil || len(parts) != 33 {
				t.Fatal("capacity physical slice count", len(parts), err)
			}
			for first := 0; first < len(parts); first += 2 {
				var records []contract.SupportRecord
				for _, part := range parts[first:min(first+2, len(parts))] {
					body, err := contract.EncodeOutputConfigurationSlice(part)
					if err != nil {
						t.Fatal(err)
					}
					id, err := contract.OutputConfigurationSliceID(selected.root.Domain, part.ConfigurationDigest, part.SliceIndex)
					if err != nil {
						t.Fatal(err)
					}
					records = append(records, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
				}
				page, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: selected.root.Domain, Object: id(3000 + first), Index: uint16(first / 2), Records: records})
				// Independent widths: 75 page bytes, 37 row bytes and 78
				// slice-metadata bytes. Payloads are full except slice 32.
				want := 75 + 2*(37+78+1048423)
				if first == 32 {
					want = 75 + 37 + 78 + (33554436 + 267973 + 33*tc.groups - 32*1048423)
				}
				if err != nil || len(page) != want {
					t.Fatal("capacity physical page width", first/2, len(page), want, err)
				}
			}
		})
	}
}

// Independent schema5 widths: destination 3 blob32 fields, policy blob32 and
// capabilities; target 32-byte ID, 5 blob32 fields, 3 flags, 4 u32 bounds and policy blob32.
func capacityPolicyLength(t *testing.T, p contract.OutputPolicy) int {
	t.Helper()
	if p.ContractID == "" {
		if len(p.Data) != 0 {
			t.Fatal("partial absent policy")
		}
		return 0
	}
	if len(p.ContractID) > 256 || len(p.Data) > 524546 {
		t.Fatal("policy encoded bound")
	}
	return 2 + 4 + len(p.ContractID) + 4 + len(p.Data)
}
func capacityConfigurationLengths(t *testing.T, configuration contract.OutputConfiguration) (int, int) {
	t.Helper()
	declaration, routing := 4, 5
	for _, binding := range configuration.Bindings {
		d := binding.Destination
		source := 17 + len(d.ConfigContractID) + len(d.ServiceContractID) + len(d.CanonicalSettings) + capacityPolicyLength(t, d.Policy)
		if len(d.CanonicalSettings) > 65536 || !json.Valid(d.CanonicalSettings) {
			t.Fatal("independent canonical setting bound or JSON")
		}
		declaration += 4 + len(binding.DestinationID) + 32 + source + 2
		for _, target := range binding.Targets {
			if target.ServiceContractID != d.ServiceContractID || !reflect.DeepEqual(target.Policy, d.Policy) {
				t.Fatal("derived source relation")
			}
			declaration += 75 + len(target.ServiceContractID) + len(target.TargetContractID) + len(target.CanonicalTarget) + len(target.ConsumerLocator) + len(target.TargetData) + capacityPolicyLength(t, target.Policy)
		}
	}
	declaration += 2
	var groupMembers int
	for _, group := range configuration.Groups {
		declaration += 2 + 32*len(group)
		groupMembers += len(group)
	}
	if groupMembers > 512 {
		t.Fatal("group member bound")
	}
	for _, name := range configuration.DefaultDestinations {
		routing += 4 + len(name)
	}
	for _, route := range configuration.Routes {
		routing += 33
		for _, name := range route.Destinations {
			routing += 4 + len(name)
		}
	}
	return declaration, routing
}

func signedCapacityConfiguration(t *testing.T, env fixtureEnvironment, lifecycle, selected *StateSession, label string, full bool) (*memoryStore, *StateSession) {
	t.Helper()
	configuration := capacityOutputConfiguration(t, selected, full)
	return signedCapacityConfigurationImage(t, env, lifecycle, selected, label, full, configuration)
}

func signedCapacityConfigurationImage(t *testing.T, env fixtureEnvironment, lifecycle, selected *StateSession, label string, full bool, configuration contract.OutputConfiguration) (*memoryStore, *StateSession) {
	t.Helper()
	names := make(map[contract.ID]string)
	for _, named := range selected.root.Names {
		names[selected.valueEntry(named.Slot).Incarnation] = named.Name
	}
	source := &outputApplyInput{}
	for _, binding := range configuration.Bindings {
		row := outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination}
		for _, target := range binding.Targets {
			row.targets = append(row.targets, outputApplyTarget{entryName: names[target.EntryIncarnationID], target: target})
		}
		source.bindings = append(source.bindings, row)
	}
	installOutputFixtureSource(t, selected, source)
	declaration, routing := capacityConfigurationLengths(t, configuration)
	if full && (declaration != 33554432 || routing != 267973+33*len(configuration.Routes)) {
		t.Fatal("independent configuration lengths", declaration, routing)
	}
	image, err := contract.EncodeOutputConfiguration(configuration)
	if err != nil || len(image) != declaration+4+routing {
		t.Fatal("canonical configuration length", len(image), err)
	}
	descriptor, parts, err := contract.SplitOutputConfiguration(selected.root.Domain, image)
	if err != nil || descriptor.RoutingLength != uint32(routing) || descriptor.TotalLength != uint32(declaration+4+routing) {
		t.Fatal("configuration descriptor", descriptor, err)
	}
	if full && (descriptor.TotalLength != uint32(33554436+routing) || len(parts) != 33) {
		t.Fatal("full configuration slices", descriptor)
	}
	store := selectedMemoryStoreCopy(env.Store.(*memoryStore))
	put := func(ref format.Ref, body []byte) {
		t.Helper()
		if err := format.CheckReference(ref, body); err != nil {
			t.Fatal("configuration fixture reference", err)
		}
		key := mustKey(t, store.desc.Prefix, ref)
		if err := store.putSelected(key, body); err != nil {
			t.Fatal("configuration fixture immutable body", err)
		}
	}
	current := *selected
	current.store = store
	current.clearSelectedSupportFacts()
	current.root.Snapshot, current.root.Transition = fixtureID(selected.root.Domain, label+" snapshot"), fixtureID(selected.root.Domain, label+" transition")
	current.root.OutputConfiguration = descriptor
	current.root.RequiredSupport = nil
	current.root.RequiredSupportRecordCount = 0
	current.support = nil
	var pages []format.RequiredSupportPage
	used := make(map[uint16]bool)
	for _, ref := range selected.root.RequiredSupport {
		used[ref.Index] = true
		position, found := selected.selectedSupportPosition(ref)
		if !found || position >= len(selected.support) {
			t.Fatal("configuration predecessor support identity")
		}
		body, result := selected.readObjectBorrowedUncached(t.Context(), ref)
		if result.Outcome != 0 {
			t.Fatal("configuration predecessor support read", result)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal("configuration predecessor support page", err)
		}
		page := format.RequiredSupportPage{Domain: view.Domain, Object: view.Object, Index: view.Index}
		for _, ordinal := range selected.supportFacts[position].ordinals {
			if int(ordinal) >= len(view.Records) {
				t.Fatal("configuration predecessor physical ordinal")
			}
			if view.Records[ordinal].Kind != contract.OutputConfigurationSliceSupportKind {
				page.Records = append(page.Records, contract.SupportRecord(view.Records[ordinal]))
			}
		}
		if len(page.Records) == 0 {
			continue
		}
		pages = append(pages, page)
		current.root.RequiredSupport = append(current.root.RequiredSupport, ref)
	}
	nextIndex := uint16(0)
	addPage := func(rows []contract.SupportRecord) {
		for used[nextIndex] {
			nextIndex++
		}
		used[nextIndex] = true
		page := format.RequiredSupportPage{Domain: selected.root.Domain, Object: fixtureID(selected.root.Domain, fmt.Sprintf("%s support %d", label, nextIndex)), Index: nextIndex, Records: rows}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal("configuration support encoding", err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
		if err != nil {
			t.Fatal("configuration support reference", err)
		}
		put(ref, body)
		pages = append(pages, page)
		current.root.RequiredSupport = append(current.root.RequiredSupport, ref)
	}
	var configurationRows []contract.SupportRecord
	for _, part := range parts {
		body, err := contract.EncodeOutputConfigurationSlice(part)
		if err != nil {
			t.Fatal("configuration slice", err)
		}
		id, err := contract.OutputConfigurationSliceID(selected.root.Domain, descriptor.ConfigurationDigest, part.SliceIndex)
		if err != nil {
			t.Fatal("configuration slice identity", err)
		}
		configurationRows = append(configurationRows, contract.SupportRecord{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: id, Body: body})
	}
	if !full && len(configurationRows) > 2 {
		// Use a legal predecessor grouping that differs from the generated
		// transition's sorted pairs, regardless of the slice digests.
		slices.SortFunc(configurationRows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
		configurationRows[1], configurationRows[len(configurationRows)-1] = configurationRows[len(configurationRows)-1], configurationRows[1]
	}
	for first := 0; first < len(configurationRows); first += 2 {
		rows := slices.Clone(configurationRows[first:min(first+2, len(configurationRows))])
		slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
		addPage(rows)
	}
	var coordinates []contract.SupportRecord
	var orders []format.PublicationCoordinateOrder
	for _, binding := range configuration.Bindings {
		for _, target := range binding.Targets {
			id, err := contract.PublicationCoordinateID(selected.root.Domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				t.Fatal("configuration coordinate identity", err)
			}
			incarnation := fixtureID(selected.root.Domain, fmt.Sprintf("%s coordinate %x", label, id))
			coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: selected.root.Domain, CoordinateID: id,
				ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, BindingState: contract.PublicationBindingActive,
				OwnerState: contract.PublicationOwnerNone, ActiveBindingIncarnationID: binding.IncarnationID,
				LastBindingIncarnationID: binding.IncarnationID, LastEntryIncarnationID: target.EntryIncarnationID, CurrentPublicationIncarnationID: incarnation}
			body, err := contract.EncodePublicationCoordinate(coordinate)
			if err != nil {
				t.Fatal("configuration coordinate body", err)
			}
			coordinates = append(coordinates, contract.SupportRecord{Kind: contract.PublicationCoordinateSupportKind, RecordID: id, Body: body})
			orders = append(orders, format.PublicationCoordinateOrder{CoordinateID: id, Incarnations: []contract.ID{incarnation}})
		}
	}
	slices.SortFunc(coordinates, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
	slices.SortFunc(orders, func(a, b format.PublicationCoordinateOrder) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	for first := 0; first < len(coordinates); first += 256 {
		addPage(slices.Clone(coordinates[first:min(first+256, len(coordinates))]))
	}
	// Root references and physical views retain the same order, including sparse
	// predecessor page indices. The production index builder keeps old ordinals.
	for i := range pages {
		for j := i + 1; j < len(pages); j++ {
			if pages[j].Index < pages[i].Index {
				pages[i], pages[j] = pages[j], pages[i]
				current.root.RequiredSupport[i], current.root.RequiredSupport[j] = current.root.RequiredSupport[j], current.root.RequiredSupport[i]
			}
		}
	}
	for _, page := range pages {
		view := format.RequiredSupportPageView{Domain: page.Domain, Object: page.Object, Index: page.Index}
		for _, row := range page.Records {
			view.Records = append(view.Records, contract.SupportRecordView(row))
		}
		current.support = append(current.support, view)
		current.root.RequiredSupportRecordCount += uint32(len(page.Records))
	}
	predecessor := *selected
	predecessor.adminIndex.PublicationOrder = orders
	index, err := predecessor.buildAdministrativeIndex(t.Context(), current.root, pages, nil, nil, &current)
	if err != nil {
		t.Fatal("configuration administrative index", err)
	}
	// Existing Slice carriers and their exact immutable references are retained.
	index.SliceSnapshot = selected.adminIndex.SliceSnapshot
	shards, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(shards) == 0 {
		t.Fatal("configuration index shards", err)
	}
	current.adminIndex = index
	current.root.AdministrativeIndex, current.root.AdministrativeIndexShards = shards[0].Ref, nil
	for i, shard := range shards {
		put(shard.Ref, shard.Body)
		if i != 0 {
			current.root.AdministrativeIndexShards = append(current.root.AdministrativeIndexShards, shard.Ref)
		}
	}
	current.recountChildren()
	if _, err := current.publicStateProjection(); err != nil {
		t.Fatal("configuration complete public-state projection", err)
	}
	t.Logf("configuration preflight: declaration=%d routing=%d image=%d slices=%d coordinates=%d children=%d child-bytes=%d index-shards=%d", declaration, routing, descriptor.TotalLength, len(parts), len(coordinates), current.root.ChildCount, current.root.ChildEncodedBytes, len(shards))
	if full {
		configurationPages := 0
		for _, page := range pages {
			if len(page.Records) == 0 || page.Records[0].Kind != contract.OutputConfigurationSliceSupportKind {
				continue
			}
			configurationPages++
			ref := current.root.RequiredSupport[slices.IndexFunc(pages, func(p format.RequiredSupportPage) bool { return p.Index == page.Index })]
			// Page header is 75 bytes; each slice has 37 bytes of row
			// framing and 78 bytes of slice metadata. The complete image
			// has 32 full payloads and one independently sized remainder.
			want := uint32(75 + 2*(37+78+1048423))
			if len(page.Records) == 1 {
				want = uint32(75 + 37 + 78 + (33554436 + 267973 + 33*len(configuration.Routes) - 32*1048423))
			}
			if ref.Length != want {
				t.Fatal("exact full configuration packing", ref.Length, want)
			}
		}
		if configurationPages != 17 || len(coordinates) != 1024 {
			t.Fatal("full configuration packing dimensions")
		}
	}
	return writeSignedCurrentIntentImage(t, env, lifecycle, selected, &current, store, label, put)
}

// Only exact selected immutable references and authenticated facts survive the
// cold reader; complete image and fragment bodies stay outside runtime owners.
func capacityConfigurationSupportRefs(t *testing.T, selected *StateSession) []format.Ref {
	t.Helper()
	refs := capacityConfigurationSelectedRefs(t, selected)
	for _, page := range selected.support {
		for _, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
				t.Fatal("capacity cold configuration body")
			}
			if row.Kind == contract.GeneratedFragmentSupportKind && row.Body != nil {
				t.Fatal("capacity cold fragment body")
			}
		}
	}
	return refs
}

func capacityConfigurationSelectedRefs(t *testing.T, selected *StateSession) []format.Ref {
	t.Helper()
	if !selected.selectedOutputComplete() || selected.publicationProof == nil {
		t.Fatal("capacity selected configuration/publication proof")
	}
	var refs []format.Ref
	count := 0
	for i, page := range selected.support {
		if i >= len(selected.supportFacts) {
			t.Fatal("capacity support facts")
		}
		facts := selected.supportFacts[i]
		found := false
		for j, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind {
				if j >= len(facts.rows) || row.RecordID != facts.rows[j].RecordID() || row.Kind != facts.rows[j].Kind() {
					t.Fatal("capacity configuration row identity")
				}
				count++
				found = true
			}
		}
		if found {
			refs = append(refs, facts.ref)
		}
	}
	if count != int(selected.root.OutputConfiguration.SliceCount) {
		t.Fatal("capacity complete configuration slice facts", count)
	}
	if selected.root.OutputConfiguration.TotalLength == 33839305 && (len(refs) != 17 || count != 33 || len(selected.adminIndex.PublicationOrder) != 1024) {
		t.Fatal("capacity full configuration dimensions", len(refs), count, len(selected.adminIndex.PublicationOrder))
	}
	return refs
}

func capacityPublicationBody(selected *StateSession, row contract.SupportRecord) ([]byte, error) {
	if row.Body != nil {
		return row.Body, nil
	}
	retained, err := selected.publicationRecord(row)
	if err != nil {
		return nil, err
	}
	return retained.body()
}

func capacityPublicationCoordinateFacts(t *testing.T, selected *StateSession) map[contract.ID]contract.SupportRecordDigest {
	t.Helper()
	facts := make(map[contract.ID]contract.SupportRecordDigest)
	for i, page := range selected.support {
		if i >= len(selected.supportFacts) {
			t.Fatal("capacity coordinate page facts")
		}
		selectedFacts := selected.supportFacts[i]
		if selectedFacts.ref.Domain != page.Domain || selectedFacts.ref.Object != page.Object || selectedFacts.ref.Index != page.Index || len(selectedFacts.rows) != len(page.Records) {
			t.Fatal("capacity coordinate selected page identity")
		}
		for j, row := range page.Records {
			if row.Kind != contract.PublicationCoordinateSupportKind {
				continue
			}
			fact := selectedFacts.rows[j]
			body, err := capacityPublicationBody(selected, contract.SupportRecord(row))
			if err != nil {
				t.Fatal("capacity coordinate exact canonical bytes", err)
			}
			if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID || fact.BodyLength() != uint32(len(body)) || fact.BodyDigest() != contract.Hash(body) {
				t.Fatal("capacity coordinate exact selected fact")
			}
			if _, duplicate := facts[row.RecordID]; duplicate {
				t.Fatal("capacity duplicate coordinate fact")
			}
			facts[row.RecordID] = fact
		}
	}
	if len(facts) != len(selected.adminIndex.PublicationOrder) {
		t.Fatal("capacity complete coordinate facts")
	}
	return facts
}

func assertCapacityPublicationPreserved(t *testing.T, before, after *StateSession) {
	t.Helper()
	if !maps.Equal(capacityPublicationCoordinateFacts(t, before), capacityPublicationCoordinateFacts(t, after)) || len(before.adminIndex.PublicationOrder) != len(after.adminIndex.PublicationOrder) {
		t.Fatal("capacity mutation changed complete coordinate facts")
	}
	for i, order := range before.adminIndex.PublicationOrder {
		next := after.adminIndex.PublicationOrder[i]
		if order.CoordinateID != next.CoordinateID || !slices.Equal(order.Incarnations, next.Incarnations) {
			t.Fatal("capacity mutation changed publication order")
		}
	}
}

func assertCapacityConfigurationPreserved(t *testing.T, before, after *StateSession) {
	t.Helper()
	capacityConfigurationSupportRefs(t, before)
	capacityConfigurationSupportRefs(t, after)
	assertCapacityConfigurationFactsPreserved(t, before, after)
}

func assertCapacityConfigurationFactsPreserved(t *testing.T, before, after *StateSession) {
	t.Helper()
	capacityConfigurationSelectedRefs(t, before)
	capacityConfigurationSelectedRefs(t, after)
	if err := capacityConfigurationPreservationError(t.Context(), before, after); err != nil {
		t.Fatal(err)
	}
	assertCapacityPublicationPreserved(t, before, after)
}

// Placement can change when a generated writer repacks a mixed page. Each
// selected row must still match its own immutable page and physical ordinal.
func capacityConfigurationPreservedFacts(ctx context.Context, selected *StateSession) (map[generatedRecordKey]selectedFragmentFact, error) {
	if !selected.selectedOutputComplete() || selected.publicationProof == nil ||
		len(selected.supportFacts) != len(selected.root.RequiredSupport) {
		return nil, fmt.Errorf("capacity incomplete configuration/publication proof")
	}
	facts := make(map[generatedRecordKey]selectedFragmentFact)
	slicesCount, coordinates := 0, 0
	for i, page := range selected.supportFacts {
		if page.ref != selected.root.RequiredSupport[i] || len(page.rows) != len(page.ordinals) ||
			len(page.rows) != len(selected.support[i].Records) {
			return nil, fmt.Errorf("capacity selected page facts")
		}
		needed := false
		for _, row := range page.rows {
			if row.Kind() == contract.OutputConfigurationSliceSupportKind || row.Kind() == contract.PublicationCoordinateSupportKind || row.Kind() == contract.PublicationMarkerSupportKind {
				needed = true
			}
		}
		if !needed {
			continue
		}
		body, result := selected.readObjectBorrowedUncached(ctx, page.ref)
		if result.Outcome != 0 {
			return nil, fmt.Errorf("capacity preserved page read: %v", result)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil || view.Domain != selected.root.Domain || view.Object != page.ref.Object || view.Index != page.ref.Index {
			return nil, fmt.Errorf("capacity preserved page identity")
		}
		for j, row := range page.rows {
			if row.Kind() != contract.OutputConfigurationSliceSupportKind && row.Kind() != contract.PublicationCoordinateSupportKind && row.Kind() != contract.PublicationMarkerSupportKind {
				continue
			}
			ordinal := page.ordinals[j]
			if int(ordinal) >= len(view.Records) {
				return nil, fmt.Errorf("capacity preserved physical ordinal")
			}
			physical, compact := view.Records[ordinal], selected.support[i].Records[j]
			if physical.Kind != row.Kind() || physical.RecordID != row.RecordID() ||
				uint32(len(physical.Body)) != row.BodyLength() || contract.Hash(physical.Body) != row.BodyDigest() ||
				compact.Kind != physical.Kind || compact.RecordID != physical.RecordID {
				return nil, fmt.Errorf("capacity preserved authenticated row")
			}
			if physical.Kind == contract.OutputConfigurationSliceSupportKind {
				if compact.Body != nil && !bytes.Equal(compact.Body, physical.Body) {
					return nil, fmt.Errorf("capacity preserved configuration body")
				}
				slicesCount++
			} else {
				body, err := capacityPublicationBody(selected, contract.SupportRecord(compact))
				if err != nil || !bytes.Equal(body, physical.Body) {
					return nil, fmt.Errorf("capacity preserved publication body")
				}
			}
			if physical.Kind == contract.PublicationCoordinateSupportKind {
				coordinates++
			}
			key := generatedRecordKey{physical.Kind, physical.RecordID}
			if _, duplicate := facts[key]; duplicate {
				return nil, fmt.Errorf("capacity duplicate preserved row")
			}
			facts[key] = selectedFragmentFact{ref: page.ref, row: row, physical: ordinal}
		}
	}
	if slicesCount != int(selected.root.OutputConfiguration.SliceCount) || coordinates != len(selected.adminIndex.PublicationOrder) {
		return nil, fmt.Errorf("capacity incomplete preserved rows")
	}
	return facts, nil
}

func capacityConfigurationPreservationError(ctx context.Context, before, after *StateSession) error {
	if before.root.OutputConfiguration != after.root.OutputConfiguration {
		return fmt.Errorf("capacity mutation changed configuration descriptor")
	}
	old, err := capacityConfigurationPreservedFacts(ctx, before)
	if err != nil {
		return err
	}
	next, err := capacityConfigurationPreservedFacts(ctx, after)
	if err != nil {
		return err
	}
	if len(old) != len(next) {
		return fmt.Errorf("capacity mutation changed preserved row count")
	}
	for key, row := range old {
		actual, present := next[key]
		if !present || row.row != actual.row {
			return fmt.Errorf("capacity mutation changed configuration/publication row")
		}
		if row.ref == actual.ref && row.physical != actual.physical {
			return fmt.Errorf("capacity mutation changed retained physical ordinal")
		}
	}
	if len(before.adminIndex.PublicationOrder) != len(after.adminIndex.PublicationOrder) {
		return fmt.Errorf("capacity mutation changed publication order count")
	}
	for i, order := range before.adminIndex.PublicationOrder {
		next := after.adminIndex.PublicationOrder[i]
		if order.CoordinateID != next.CoordinateID || !slices.Equal(order.Incarnations, next.Incarnations) {
			return fmt.Errorf("capacity mutation changed publication order")
		}
	}
	return nil
}

func capacityIntentBytes(t *testing.T, name string) []byte {
	t.Helper()
	quoted, err := json.Marshal(name)
	if err != nil {
		t.Fatal("capacity intent name", err)
	}
	settingsPrefix := append([]byte(`{"name":`), quoted...)
	settingsPrefix = append(settingsPrefix, []byte(`,"padding":"`)...)
	const completeLength = 393216
	// Schema 1, fixture config ID, managed lifecycle, fixture resource ID,
	// then the 393145-byte JSON settings length. This does not use the producer.
	header := []byte{0, 1}
	header = append(header, bytes.Repeat([]byte{0x29}, 32)...)
	header = append(header, 2)
	header = append(header, bytes.Repeat([]byte{0x2a}, 32)...)
	header = append(header, 0, 5, 0xff, 0xb9)
	if len(header)+len(settingsPrefix)+2 > completeLength {
		t.Fatal("capacity intent name exceeds settings body")
	}
	body := bytes.Repeat([]byte{'Z'}, completeLength)
	copy(body, header)
	copy(body[len(header):], settingsPrefix)
	body[completeLength-2], body[completeLength-1] = '"', '}'
	return body
}

func assertCapacityIntentBytes(t *testing.T, name string, intent []byte) {
	t.Helper()
	if !bytes.Equal(intent, capacityIntentBytes(t, name)) {
		t.Fatal("capacity exact current canonical intent bytes", len(intent))
	}
}

func assertCapacityCurrentIntents(t *testing.T, selected *StateSession, expected int) {
	t.Helper()
	work, err := selected.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("capacity selected current intents", err)
	}
	count, total := 0, uint64(0)
	for _, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		intent, err := work.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		if err != nil {
			t.Fatal("capacity exact current intent", err)
		}
		assertCapacityIntentBytes(t, named.Name, intent)
		count++
		total += uint64(len(intent))
	}
	if count != expected || total != uint64(expected)*(384<<10) {
		t.Fatal("capacity complete current intent dimensions", count, total)
	}
}

// full_only: false
func TestConfiguredGeneratedCapacityColdOpen(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newNamedEnvironmentFixture(t, t.Context(), env, []int{1}, false, []string{"configuration-seed"})
	sources, _ := generatedCurrentDeclaration(t, f.session)
	recipients := capacityRecipients(t, f.session, 2)
	selected := signedFullIntentSource(t, t.Context(), env, f.session, fixtureID(env.Domain, "configuration original"),
		[]string{"configured-generated"}, sources, recipients, custody.StandardValue, contract.OutputEncodingRaw, "configured original", nil)
	store, opened := signedCapacityConfiguration(t, env, f.session, selected, "small configured generated", false)
	if opened.root.Generated.GeneratedCurrent != 1 || opened.root.MembershipCount != 3 || opened.root.SecretOrdinaryWrapCount != 2 ||
		opened.root.OutputConfiguration.BindingCount != 2 || opened.root.OutputConfiguration.TotalLength != 1586 || opened.root.OutputConfiguration.RoutingLength != 74 ||
		len(opened.adminIndex.PublicationOrder) != 2 || !opened.selectedOutputComplete() || opened.publicationProof == nil {
		t.Fatal("small configured generated dimensions")
	}
	for _, recipient := range recipients {
		selection := sessionConsumerSelection(t, opened, recipient, "configured-generated")
		if result := env.Custody.Consume(t.Context(), selection, custody.StandardValue); result.Code != contract.CryptoSuccess || !result.ValueMatched {
			t.Fatal("configured member private consume", result)
		}
	}
	for _, page := range opened.support {
		for _, row := range page.Records {
			if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
				t.Fatal("cold configuration retains complete image")
			}
		}
	}
	admin, result := openAdministrative(t.Context(), OpenContext{admission: &opened.admission}, store)
	if admin == nil || result.Outcome != ObservedCurrent || !admin.selectedOutputComplete() {
		t.Fatal("configured administrative cold-open", result)
	}
	kept, err := admin.administrativeWorkWithoutOldReceipts(admin.adminIndex)
	if err != nil || len(kept.PublicationOrder) != 2 {
		t.Fatal("configured receipt filtering", err)
	}
	assertCapacityConfigurationPreserved(t, opened, opened)
	for _, damage := range []string{"descriptor", "slice-body", "missing-slice", "duplicate-slice", "physical-ordinal", "selected-reference", "coordinate-body", "publication-incarnation"} {
		t.Run(damage, func(t *testing.T) {
			changed := *opened
			changed.support = slices.Clone(opened.support)
			changed.supportFacts = slices.Clone(opened.supportFacts)
			for i := range changed.support {
				changed.support[i].Records = slices.Clone(opened.support[i].Records)
				changed.supportFacts[i].rows = slices.Clone(opened.supportFacts[i].rows)
				changed.supportFacts[i].ordinals = slices.Clone(opened.supportFacts[i].ordinals)
			}
			want := ""
			switch damage {
			case "descriptor":
				changed.root.OutputConfiguration.TotalLength++
				want = "changed configuration descriptor"
			case "publication-incarnation":
				changed.adminIndex.PublicationOrder = slices.Clone(opened.adminIndex.PublicationOrder)
				changed.adminIndex.PublicationOrder[0].Incarnations = []contract.ID{fixtureID(env.Domain, "damaged publication incarnation")}
				want = "changed publication order"
			default:
				kind := contract.OutputConfigurationSliceSupportKind
				if damage == "coordinate-body" {
					kind = contract.PublicationCoordinateSupportKind
				}
				found := false
				for i, page := range changed.support {
					for j, row := range page.Records {
						if row.Kind != kind {
							continue
						}
						found = true
						facts := &changed.supportFacts[i]
						switch damage {
						case "slice-body":
							body, result := opened.readObjectBorrowedUncached(t.Context(), facts.ref)
							if result.Outcome != 0 {
								t.Fatal("damage source read", result)
							}
							view, err := format.InspectRequiredSupportPage(body)
							if err != nil {
								t.Fatal("damage source page", err)
							}
							physical := view.Records[facts.ordinals[j]]
							physical.Body = slices.Clone(physical.Body)
							physical.Body[len(physical.Body)-1] ^= 1
							fact, err := contract.InspectSupportRecordDigest(env.Domain, contract.SupportRecord(physical))
							if err != nil {
								t.Fatal("damaged slice fact", err)
							}
							facts.rows[j] = fact
							want = "preserved authenticated row"
						case "missing-slice":
							facts.rows = slices.Delete(facts.rows, j, j+1)
							facts.ordinals = slices.Delete(facts.ordinals, j, j+1)
							changed.support[i].Records = slices.Delete(changed.support[i].Records, j, j+1)
							want = "incomplete preserved rows"
						case "duplicate-slice":
							facts.rows = append(facts.rows, facts.rows[j])
							facts.ordinals = append(facts.ordinals, facts.ordinals[j])
							changed.support[i].Records = append(changed.support[i].Records, row)
							want = "duplicate preserved row"
						case "physical-ordinal":
							facts.ordinals[j] = 65535
							want = "preserved physical ordinal"
						case "selected-reference":
							facts.ref.Index++
							want = "selected page facts"
						case "coordinate-body":
							body, err := capacityPublicationBody(opened, contract.SupportRecord(row))
							if err != nil || len(body) == 0 {
								t.Fatal("coordinate damage source", err)
							}
							changed.support[i].Records[j].Body = slices.Clone(body)
							changed.support[i].Records[j].Body[len(body)-1] ^= 1
							want = "preserved publication body"
						}
						break
					}
					if found {
						break
					}
				}
				if !found {
					t.Fatal("damage target missing")
				}
			}
			if err := capacityConfigurationPreservationError(t.Context(), opened, &changed); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal("preservation accepted damage or failed for the wrong reason", err, want)
			}
		})
	}
	replacementInput := func(t *testing.T, before *StateSession, label string) generatedPlanInput {
		t.Helper()
		name := "configured-generated"
		old := before.valueEntry(entrySlot(t, before, name))
		operation := fixtureID(env.Domain, label+" replacement")
		profile := defaultGeneratedFixtureProfile()
		bound := generatedReservationInputForMembershipStateIntent(t, before, operation, recipients, []string{name},
			[]byte("replacement"), profile, old.Generated.Epoch+1, map[string]contract.ID{name: old.Incarnation},
			map[string]contract.ValueEntry{name: *old}, sources...)
		input := generatedPlanInputForGenerations(t, before, operation, []string{name}, profile)
		input.context.AdmissionID = fixtureID(env.Domain, label+" replacement admission")
		input.context.SessionID = fixtureID(env.Domain, label+" replacement session")
		input.graph, input.declaration = bound.graph, bound.declaration
		input.registry, input.recoveryPolicy = bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID
		input.requestBindings = slices.Clone(bound.requestBindings)
		return input
	}
	prepareInput := func(t *testing.T) (fixtureEnvironment, *StateSession, generatedPlanInput) {
		t.Helper()
		caseEnv := env
		caseStore, before := signedCapacityConfiguration(t, caseEnv, f.session, selected, t.Name(), false)
		caseEnv.Store = caseStore
		return caseEnv, before, replacementInput(t, before, t.Name())
	}
	t.Run("reservation_preserves_warm_and_cold", func(t *testing.T) {
		configuration := capacityOutputConfiguration(t, selected, false)
		first := configuration.Bindings[0]
		configuration.Bindings = nil
		for b := 0; b < 5; b++ {
			binding := contract.OutputBinding{DestinationID: fmt.Sprintf("destination-%02d", b),
				IncarnationID: fixtureID(env.Domain, fmt.Sprintf("warm configuration binding %d", b)), Destination: first.Destination}
			target := first.Targets[0]
			target.CanonicalTarget = fmt.Sprintf("capacity/b%02d/e000", b)
			target.ConsumerLocator = target.CanonicalTarget + "/current"
			target.TargetData = []byte("target:" + target.CanonicalTarget)
			var subjects []string
			for member := 0; member < 1500; member++ {
				subjects = append(subjects, fmt.Sprintf("a%04d%s", member, strings.Repeat("x", 260)))
			}
			target.Policy = hermeticTextPolicy("test-capacity-members", subjects)
			binding.Destination.Policy = target.Policy
			binding.Destination.CanonicalSettings = hermeticDestinationSettings([][2]string{
				{"setting-0", fmt.Sprintf("warm-binding-%02d", b)}, {"setting-1", "fixture-value-00"}, {"setting-2", "fixture-value-00"},
			})
			binding.Targets = []contract.OutputTarget{target}
			configuration.Bindings = append(configuration.Bindings, binding)
		}
		for i := range configuration.Routes {
			configuration.Routes[i].Destinations = nil
			for _, binding := range configuration.Bindings {
				configuration.Routes[i].Destinations = append(configuration.Routes[i].Destinations, binding.DestinationID)
			}
		}
		caseEnv := env
		caseStore, before := signedCapacityConfigurationImage(t, caseEnv, f.session, selected, t.Name(), false, configuration)
		caseEnv.Store = caseStore
		// Five sources and five derived targets each retain the full 1500-subject
		// policy. Independent schema5 framing gives declaration4022196, routing128,
		// image4022328 and four payloads: 1048423/1048423/1048423/877059 bytes.
		if before.root.OutputConfiguration.TotalLength != 4022328 || before.root.OutputConfiguration.RoutingLength != 128 ||
			before.root.OutputConfiguration.SliceCount != 4 || before.root.OutputConfiguration.BindingCount != 5 {
			t.Fatal("warm configuration fixture dimensions", before.root.OutputConfiguration)
		}
		beforeRefs := capacityConfigurationSupportRefs(t, before)
		input := replacementInput(t, before, t.Name())
		reservation, _ := preparePrivateGeneratedReservation(t, caseEnv, before, input, nil)
		warm, candidate := reservation.reservation.state, reservation.reservation.candidate
		buffers := retainedByteBuffers(before, nil, candidate, nil)
		charged := buffers.capacity()
		fragments, configurations, configurationBytes, changedRefs := 0, 0, 0, 0
		for i, page := range warm.support {
			for j, row := range page.Records {
				if row.Kind == contract.OutputConfigurationSliceSupportKind {
					if row.RecordID != warm.supportFacts[i].rows[j].RecordID() || row.Kind != warm.supportFacts[i].rows[j].Kind() {
						t.Fatal("warm configuration row identity differs from authenticated fact")
					}
					if row.Body != nil {
						configurations++
						configurationBytes += len(row.Body)
						if !slices.Contains(beforeRefs, warm.supportFacts[i].ref) {
							changedRefs++
						}
						buffers.add(row.Body)
					}
				}
				if row.Kind == contract.GeneratedFragmentSupportKind && row.Body != nil {
					fragments++
					buffers.add(row.Body)
				}
			}
		}
		if fragments == 0 || configurations == 0 || changedRefs == 0 || buffers.capacity() != charged {
			t.Fatal("warm reservation backing is missing, retained or uncharged", fragments, configurations, changedRefs)
		}
		t.Logf("warm reservation authenticated identities match: configuration-bodies=%d configuration-body-bytes=%d changed-configuration-rows=%d fragment-bodies=%d charged-byte-capacity=%d", configurations, configurationBytes, changedRefs, fragments, charged)
		assertCapacityConfigurationFactsPreserved(t, before, warm)
		changed := *warm
		changed.support = slices.Clone(warm.support)
		damaged := false
		for i, page := range warm.support {
			for j, row := range page.Records {
				if row.Kind != contract.OutputConfigurationSliceSupportKind || row.Body == nil {
					continue
				}
				changed.support[i].Records = slices.Clone(page.Records)
				changed.support[i].Records[j].Body = slices.Clone(row.Body)
				changed.support[i].Records[j].Body[len(row.Body)-1] ^= 1
				damaged = true
				break
			}
			if damaged {
				break
			}
		}
		if err := capacityConfigurationPreservationError(t.Context(), before, &changed); err == nil || err.Error() != "capacity preserved configuration body" {
			t.Fatal("preservation accepted damaged warm configuration body or failed for the wrong reason", err)
		}
		observed, result := before.selectCandidate(t.Context(), candidate)
		if observed == nil || result.Outcome != ObservedCurrent {
			t.Fatal("configured reservation selection", result)
		}
		assertCapacityConfigurationPreserved(t, before, observed)
		caseEnv.Custody.RetireGenerated()
		cold := generatedLifecycleReopen(t, t.Context(), observed, caseEnv.Store)
		assertCapacityConfigurationPreserved(t, before, cold)
	})
	t.Run("sparse_fragment_key_mapping", func(t *testing.T) {
		domain := contract.ID{1}
		state := &StateSession{fragmentFacts: make(map[format.FragmentLocation]selectedFragmentFact)}
		state.root.Domain = domain
		state.admission.store.Prefix = "fragment-map"
		state.store = &memoryStore{desc: state.admission.store}
		for p, index := range []uint16{7, 9} {
			object := contract.ID{byte(2 + p)}
			var rows []contract.SupportRecord
			for r := 0; r < 2-p; r++ {
				blob := contract.ID{byte(10 + 2*p + r)}
				payload := []byte{byte(20 + 2*p + r)}
				body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob,
					Count: 1, TotalLength: 1, WholeDigest: contract.Hash(payload), Payload: payload})
				if err != nil {
					t.Fatal("sparse fragment body", err)
				}
				id, err := contract.GeneratorFragmentID(blob, 0)
				if err != nil {
					t.Fatal("sparse fragment identity", err)
				}
				rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
			}
			slices.SortFunc(rows, func(a, b contract.SupportRecord) int { return bytes.Compare(a.RecordID[:], b.RecordID[:]) })
			body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain, Object: object, Index: index, Records: rows})
			if err != nil {
				t.Fatal("sparse fragment page", err)
			}
			ref, err := format.Reference(contract.RequiredSupportKind, domain, object, index, body)
			if err != nil {
				t.Fatal("sparse fragment reference", err)
			}
			facts := selectedSupportPageFacts{ref: ref}
			view := format.RequiredSupportPageView{Domain: domain, Object: object, Index: index}
			for r, row := range rows {
				fact, err := contract.InspectSupportRecordDigest(domain, row)
				if err != nil {
					t.Fatal("sparse selected row fact", err)
				}
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal("sparse selected fragment", err)
				}
				location := format.FragmentLocation{BlobID: fragment.BlobID, SupportPageIndex: index, RowSlot: uint8(r)}
				state.root.Generated.Fragments = append(state.root.Generated.Fragments, location)
				state.fragmentFacts[location] = selectedFragmentFact{ref: ref, row: fact, physical: uint16(r), logical: uint16(r),
					blob: fragment.BlobID, count: 1, total: 1, whole: fragment.WholeDigest, payloadLength: 1}
				facts.rows = append(facts.rows, fact)
				facts.ordinals = append(facts.ordinals, uint16(r))
				view.Records = append(view.Records, contract.SupportRecordView{Kind: row.Kind, RecordID: row.RecordID})
			}
			state.root.RequiredSupport = append(state.root.RequiredSupport, ref)
			state.supportFacts = append(state.supportFacts, facts)
			state.support = append(state.support, view)
		}
		slices.SortFunc(state.root.Generated.Fragments, func(a, b format.FragmentLocation) int {
			return bytes.Compare(a.BlobID[:], b.BlobID[:])
		})
		want := map[string]bool{
			fmt.Sprintf("fragment-map/%x/support/7/%x", domain, contract.ID{2}): true,
			fmt.Sprintf("fragment-map/%x/support/9/%x", domain, contract.ID{3}): true,
		}
		if got := generatedSelectedFragmentKeys(t, state); !maps.Equal(got, want) {
			t.Fatal("sparse fragment keys differ from exact immutable page keys", got, want)
		}
	})
	t.Run("record_selected_read_cancellation", func(t *testing.T) {
		caseEnv, before, input := prepareInput(t)
		reservation, _ := preparePrivateGeneratedReservation(t, caseEnv, before, input, nil)
		current, _, expected, original := selectActualGeneratedPacketRecord(t, caseEnv, before, reservation, custody.StandardValue, false, nil)
		caseEnv.Custody.RetireGenerated()
		current = generatedLifecycleReopen(t, t.Context(), current, caseEnv.Store)
		assertCapacityConfigurationPreserved(t, before, current)
		plan := generatedRecordPlanForResult(t, current, expected.Template.AttemptID, original, t.Name())
		permit := admitPrivateGeneratedRecord(t.Context(), t, caseEnv.Custody, current, plan)
		assertMaximumGeneratedCanceled(t, t.Context(), caseEnv, current, func(ctx context.Context) (bool, Result) {
			prepared, result := current.PrepareGeneratedRecord(ctx, permit)
			return prepared != nil, result
		}, &permit.used, "selected_read")
	})
}
