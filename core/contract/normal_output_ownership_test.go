package contract

import (
	"fmt"
	"strings"
	"testing"
)

// full_only: false
func TestOutputOwnershipBoundsPrecedeDesiredClones(t *testing.T) {
	t.Run("canonical_declaration_boundary", func(t *testing.T) {
		w, state, _, _ := generatedOutputFixture(t)
		entry, err := DecodeValueEntry(w.EntryBodies[0])
		if err != nil {
			t.Fatal(err)
		}
		entry.Name = fmt.Sprintf("%0256d", 0)
		w.Before.DefaultDestinations = nil
		w.Before.Routes = []OutputRoute{{EntryIncarnationID: entry.Incarnation, Destinations: []string{"dest"}}}
		w.EntryBodies, w.EntriesBefore, state.Rows = nil, nil, nil
		var entries []ValueEntry
		var intents []CryptoIntentRow
		for i := 0; i < 8; i++ {
			current := entry
			current.Name = fmt.Sprintf("%0256d", i)
			if i != 0 {
				current.Incarnation = publicationTestID(byte(180 + i))
			}
			body, err := EncodeValueEntry(current)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := PublicValueEntryDigest(state.Domain, uint16(i), current)
			if err != nil {
				t.Fatal(err)
			}
			entries = append(entries, current)
			w.EntryBodies = append(w.EntryBodies, body)
			w.EntriesBefore = append(w.EntriesBefore, MembershipRow{Name: current.Name, Slot: uint16(i), Incarnation: current.Incarnation, EntryDigest: digest, Recipients: current.Recipients})
			state.Rows = append(state.Rows, PublicStateRow{Name: current.Name, Slot: uint16(i), EntryDigest: digest})
			intents = append(intents, CryptoIntentRow{Name: current.Name, Recipients: current.Recipients, ValueSource: Supplied, ConfidentialityClass: Plain, ContentLength: uint32(len(current.ValueBytes)), PayloadLength: uint32(len(current.ValueBytes)), PayloadDigest: Hash(current.ValueBytes), InputEncoding: InputEncodingRaw, RetainedLength: uint32(len(current.ValueBytes)), OutputEncoding: OutputEncodingRaw})
		}
		refreshGeneratedOutputFixture(t, w, &state)
		normal := &NormalOutputTransition{Before: w.Before, BeforeDescriptor: w.BeforeDescriptor, EntriesBefore: w.EntriesBefore,
			Intent: intents, Slots: []uint16{0, 1, 2, 3, 4, 5, 6, 7}}
		if _, err := CryptoIntentDescriptor(state.Domain, normal.Intent); err != nil {
			t.Fatal("canonical boundary intent", err)
		}
		if err := w.Inspect(state); err != nil {
			t.Fatal("canonical boundary selected predecessor", err)
		}
		canonical := OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: state.Domain}
		for i := 0; i < 64; i++ {
			entry := entries[i/8]
			policyLength := 262_062
			if i >= 29 {
				policyLength--
			}
			policy := OutputPolicy{ContractID: "p", Data: make([]byte, policyLength)}
			destination := OutputDestination{ConfigContractID: "c", ServiceContractID: "s", CanonicalSettings: []byte("{}"), Policy: policy, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}
			target := OutputTarget{ServiceContractID: "s", TargetContractID: "t", CanonicalTarget: fmt.Sprintf("s%02d", i), ConsumerLocator: "l",
				PayloadEncoding: OutputEncodingBase64, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot, Policy: policy}
			name := fmt.Sprintf("d%02d", i)
			normal.Bindings = append(normal.Bindings, NormalOutputBinding{DestinationID: name, Destination: destination,
				Targets: []NormalOutputTarget{{Name: entry.Name, Target: target}}})
			target.EntryIncarnationID = entry.Incarnation
			canonical.Bindings = append(canonical.Bindings, OutputBinding{DestinationID: name, IncarnationID: publicationTestID(byte(100 + i)), Destination: destination,
				Targets: []OutputTarget{target}})
		}
		for i, entry := range entries {
			var destinations []string
			for j := 0; j < 8; j++ {
				destinations = append(destinations, fmt.Sprintf("d%02d", i*8+j))
			}
			normal.Routes = append(normal.Routes, NormalOutputRoute{Name: entry.Name, Destinations: destinations})
			canonical.Routes = append(canonical.Routes, OutputRoute{EntryIncarnationID: entry.Incarnation, Destinations: destinations})
		}
		for _, variant := range []string{"base64", "raw_with_group"} {
			t.Run(variant, func(t *testing.T) {
				normal.Bindings[0].Targets[0].Target.TargetData = nil
				canonical.Bindings[0].Targets[0].TargetData = nil
				for i := range normal.Intent {
					normal.Intent[i].OutputEncoding = OutputEncodingBase64
					if variant == "raw_with_group" {
						normal.Intent[i].OutputEncoding = OutputEncodingRaw
					}
				}
				if variant == "raw_with_group" {
					for i := range normal.Bindings {
						normal.Bindings[i].Targets[0].Target.PayloadEncoding = OutputEncodingRaw
						canonical.Bindings[i].Targets[0].PayloadEncoding = OutputEncodingRaw
					}
					normal.Groups, canonical.Groups = [][]string{{entry.Name}}, [][]ID{{entry.Incarnation}}
					// Add 34 singleton-group bytes and remove 17 bytes from each
					// policy copy: the declaration stays at its limit.
					policy := normal.Bindings[0].Destination.Policy
					policy.Data = policy.Data[:len(policy.Data)-17]
					normal.Bindings[0].Destination.Policy, normal.Bindings[0].Targets[0].Target.Policy = policy, policy
					canonical.Bindings[0].Destination.Policy, canonical.Bindings[0].Targets[0].Policy = policy, policy
				}
				w.Bindings, w.Routes, w.Groups = normal.Bindings, normal.Routes, normal.Groups
				// Schema/count/group framing is 6 bytes. Each binding adds 165 fixed
				// bytes and two policy bodies. Names become 32-byte entry IDs.
				// Policies total 29*262062 + 35*262061 = 16771933 bytes.
				// Declaration: 6 + 64*165 + 2*16771933 = 33554432.
				// Routing: 5 + 8*(33 + 8*(4+3)) = 717; enclosing framing adds 4.
				const completeBytes = 33_555_153
				if length, err := OutputConfigurationLength(canonical); err != nil || length != completeBytes {
					t.Fatal("independent canonical declaration boundary", length, err)
				}
				for _, tc := range []struct {
					name string
					over bool
				}{{"at_limit", false}, {"one_byte_over", true}} {
					t.Run(tc.name, func(t *testing.T) {
						var want error
						if tc.over {
							want = ErrRecordCapacity
							normal.Bindings[0].Targets[0].Target.TargetData = []byte{1}
							canonical.Bindings[0].Targets[0].TargetData = []byte{1}
							if _, err := OutputConfigurationLength(canonical); err != want {
								t.Fatal("one canonical declaration byte over limit", err)
							}
						}
						if err := normalOutputOwnershipBounds(normal); err != want {
							t.Errorf("ownership guard: got %v, want %v", err, want)
						}
						if err := normal.Inspect(w.Rows); err != want {
							t.Errorf("normal Inspect: got %v, want %v", err, want)
						}
						if owned, err := normal.Own(); err != want || (owned == nil) != tc.over {
							t.Errorf("normal Own: retained=%t, got %v, want %v", owned != nil, err, want)
						}
						if err := w.Inspect(state); err != want {
							t.Errorf("generated Inspect: got %v, want %v", err, want)
						}
						if owned, err := w.Own(state); err != want || (owned == nil) != tc.over {
							t.Errorf("generated Own: retained=%t, got %v, want %v", owned != nil, err, want)
						}
					})
				}
			})
		}
	})
	cases := []struct {
		name   string
		change func(*NormalOutputTransition)
	}{
		{"bindings", func(v *NormalOutputTransition) { v.Bindings = make([]NormalOutputBinding, MaxOutputBindings+1) }},
		{"targets", func(v *NormalOutputTransition) {
			v.Bindings = []NormalOutputBinding{{Targets: make([]NormalOutputTarget, MaxOutputTargetsPerBinding+1)}}
		}},
		{"routes", func(v *NormalOutputTransition) { v.Routes = make([]NormalOutputRoute, CryptoMaxValueEntries+2) }},
		{"route_destinations", func(v *NormalOutputTransition) {
			v.Routes = []NormalOutputRoute{{Destinations: make([]string, MaxOutputRouteDestinations+1)}}
		}},
		{"groups", func(v *NormalOutputTransition) { v.Groups = make([][]string, CryptoMaxValueEntries+1) }},
		{"group_members", func(v *NormalOutputTransition) { v.Groups = [][]string{make([]string, CryptoMaxValueEntries+1)} }},
		{"entry_name", func(v *NormalOutputTransition) { v.Groups = [][]string{{strings.Repeat("x", CryptoMaxName+1)}} }},
		{"destination_settings", func(v *NormalOutputTransition) {
			v.Bindings = []NormalOutputBinding{{Destination: OutputDestination{CanonicalSettings: make([]byte, MaxOutputDestinationSettings+1)}}}
		}},
		{"target_data", func(v *NormalOutputTransition) {
			v.Bindings = []NormalOutputBinding{{Targets: []NormalOutputTarget{{Target: OutputTarget{TargetData: make([]byte, MaxOutputTargetDataBytes+1)}}}}}
		}},
		{"aggregate_policy", func(v *NormalOutputTransition) {
			policy := OutputPolicy{ContractID: "private-policy/v1", Data: make([]byte, MaxOutputPolicyBytes)}
			v.Bindings = make([]NormalOutputBinding, MaxOutputBindings)
			for i := range v.Bindings {
				v.Bindings[i].Destination.Policy = policy
			}
		}},
		{"intent", func(v *NormalOutputTransition) { v.Intent = make([]CryptoIntentRow, CryptoMaxValueEntries+1) }},
		{"before_memberships", func(v *NormalOutputTransition) {
			v.EntriesBefore = []MembershipRow{{Recipients: make([]ID, CryptoMaxValueEntryRecipients+1)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, state, _, _ := generatedOutputFixture(t)
			normal := &NormalOutputTransition{Before: w.Before}
			if _, err := normal.Own(); err != nil {
				t.Fatal("valid ownership baseline", err)
			}
			tc.change(normal)
			if owned, err := normal.Own(); err == nil || owned != nil {
				t.Fatal("unbounded desired normal fields were retained")
			}
			// Generated ownership must reject the same fields at Inspect, before
			// a cache equality hit or a complete output clone can accept them.
			w.Bindings, w.Routes, w.Groups = normal.Bindings, normal.Routes, normal.Groups
			if tc.name == "intent" || tc.name == "before_memberships" {
				return
			}
			if err := w.Inspect(state); err == nil {
				t.Fatal("unbounded desired generated fields were inspected")
			}
			if owned, err := w.Own(state); err == nil || owned != nil {
				t.Fatal("unbounded desired generated fields were retained")
			}
		})
	}
}
