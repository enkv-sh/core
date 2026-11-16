package compositionfull

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func maximumInspectionMetadata(t *testing.T, v *core.DomainInspection) {
	t.Helper()
	id := func(n uint32) (id contract.ID) { id[0] = 2; binary.BigEndian.PutUint32(id[28:], n); return id }
	for i := 0; i < 256; i++ {
		v.Recipients = append(v.Recipients, core.InspectionRecipient{RecipientID: id(uint32(i + 1)), Status: contract.CurrentRecipient, DisplayName: strings.Repeat("\x00", 256), BindingID: id(uint32(i + 300)), BindingSerial: math.MaxUint64, BindingFingerprint: id(uint32(i + 600))})
	}
	for i := 0; i < 512; i++ {
		row := core.InspectionEntry{Slot: uint16(i), Name: fmt.Sprintf("%04d", i) + strings.Repeat("\x00", 252), IncarnationID: id(uint32(i + 1000)), ValueStateID: id(uint32(i + 2000)), ValueSource: contract.Supplied}
		members := 7
		if i == 0 {
			members = 64
		} else if i <= 455 {
			members = 8
		}
		for j := 0; j < members; j++ {
			row.RecipientIDs = append(row.RecipientIDs, id(uint32(j+1)))
		}
		v.Entries = append(v.Entries, row)
	}
	if err := v.ValidateMetadataWorkOutput(); err != nil {
		t.Fatal("maximum metadata fixture violates owner contract", err)
	}
}

// full_only: true
// Proves the exact 524,546-byte opaque policy boundary, maximum escaped field
// widths, all 512 metadata entries and all 4,096 membership positions.
func TestPublicInspectionCompleteJSONRecoversMaximumPolicyAndMetadata(t *testing.T) {
	r := publicQueryRendererDomain(t)
	maximumInspectionMetadata(t, r.View)
	id := func(n uint32) (id contract.ID) { id[0] = 2; binary.BigEndian.PutUint32(id[28:], n); return id }
	policyData := make([]byte, 524546)
	for i := range policyData {
		policyData[i] = byte(i)
	}
	binary.BigEndian.PutUint64(policyData[len(policyData)-8:], math.MaxUint64)
	policy := contract.OutputPolicy{ContractID: strings.Repeat("\x00", 256), Data: policyData}
	// Schema u16 + contract blob(4+256) + data blob(4+524,546) = 524,812.
	if body, err := contract.EncodeOutputPolicy(policy); err != nil || len(body) != 524812 {
		t.Fatal("maximum policy setup", len(body), err)
	}
	target := contract.OutputTarget{EntryIncarnationID: r.View.Entries[0].IncarnationID, ServiceContractID: strings.Repeat("\x00", 256), CanonicalTarget: strings.Repeat("\x00", 1024), ConsumerLocator: strings.Repeat("\x00", 1024), TargetContractID: strings.Repeat("\x00", 256), TargetData: bytes.Repeat([]byte{255}, 4096), PayloadEncoding: contract.OutputEncodingRaw, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: policy}
	settings := []byte(`"` + strings.Repeat("x", 65534) + `"`)
	binding := contract.OutputBinding{IncarnationID: id(5001), DestinationID: strings.Repeat("\x00", 256), Destination: contract.OutputDestination{ConfigContractID: strings.Repeat("\x00", 256), ServiceContractID: target.ServiceContractID, CanonicalSettings: settings, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, Policy: policy}, Targets: []contract.OutputTarget{target}}
	config := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: r.DomainID, Bindings: []contract.OutputBinding{binding}}
	image, err := contract.EncodeOutputConfiguration(config)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _, err := contract.SplitOutputConfiguration(r.DomainID, image)
	if err != nil {
		t.Fatal(err)
	}
	coordinate, err := contract.PublicationCoordinateID(r.DomainID, target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	r.View.Output = core.InspectionOutput{Configuration: config, ConfigurationDescriptor: descriptor, CurrentTargets: []core.InspectionCurrentTarget{{CoordinateID: coordinate, LocatorBasis: core.InspectionConfiguredOnly}}}
	if err := r.ValidateMetadataWorkOutput(); err != nil {
		t.Fatal("maximum policy/metadata fixture violates owner contract", err)
	}
	var out bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Payload struct {
			Entries []struct {
				Name        string
				Incarnation string   `json:"incarnation_id"`
				Recipients  []string `json:"recipient_ids"`
			}
			Recipients []struct {
				DisplayName string `json:"display_name"`
			}
			Output struct {
				Configuration struct {
					Bindings []struct {
						Destination struct {
							Config   string `json:"config_contract_id"`
							Service  string `json:"service_contract_id"`
							Settings []byte `json:"canonical_settings_base64"`
							Policy   struct {
								Data []byte `json:"data_base64"`
							}
						}
						Targets []struct {
							Incarnation string `json:"entry_incarnation_id"`
							Consumer    string `json:"consumer_locator"`
							Service     string `json:"service_contract_id"`
							Target      string `json:"target_contract_id"`
							Canonical   string `json:"canonical_target"`
							Data        []byte `json:"target_data_base64"`
							Policy      struct {
								Contract string `json:"contract_id"`
								Data     []byte `json:"data_base64"`
							}
						}
					}
				}
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Payload.Entries) != 512 || len(doc.Payload.Recipients) != 256 || len(doc.Payload.Output.Configuration.Bindings) != 1 {
		t.Fatal("complete maximum tables lost")
	}
	memberships := 0
	for i, row := range doc.Payload.Entries {
		memberships += len(row.Recipients)
		if row.Name != fmt.Sprintf("%04d", i)+strings.Repeat("\x00", 252) || row.Incarnation != fmt.Sprintf("02%s%08x", strings.Repeat("00", 27), i+1000) {
			t.Fatal("escaped metadata changed", i)
		}
	}
	destination := doc.Payload.Output.Configuration.Bindings[0].Destination
	if destination.Config != strings.Repeat("\x00", 256) || destination.Service != strings.Repeat("\x00", 256) || !bytes.Equal(destination.Settings, settings) || !bytes.Equal(destination.Policy.Data, policyData) {
		t.Fatal("maximum public destination bytes changed")
	}
	decoded := doc.Payload.Output.Configuration.Bindings[0].Targets[0]
	if memberships != 4096 || decoded.Incarnation != "02"+strings.Repeat("00", 27)+"000003e8" || decoded.Incarnation != doc.Payload.Entries[0].Incarnation || decoded.Consumer != strings.Repeat("\x00", 1024) || decoded.Service != strings.Repeat("\x00", 256) || decoded.Target != strings.Repeat("\x00", 256) || decoded.Canonical != strings.Repeat("\x00", 1024) || !bytes.Equal(decoded.Data, bytes.Repeat([]byte{255}, 4096)) || !bytes.Equal(decoded.Policy.Data, policyData) || decoded.Policy.Contract != strings.Repeat("\x00", 256) || out.Len() <= 4096 {
		t.Fatal("bounded fields were truncated or rounded")
	}
}

// full_only: false
func TestPublicReceiptListStreamsAll512RowsWithoutEncodedReceiptCopies(t *testing.T) {
	r := publicQueryRendererList(t)
	r.Payload.Receipts = make([]core.ReceiptSummary, 512)
	for i := range r.Payload.Receipts {
		id := contract.ID{1}
		binary.BigEndian.PutUint32(id[28:], uint32(512-i))
		row := core.ReceiptSummary{OperationID: id, OperationKind: 2, CanonicalOutcome: 1, StateResult: 1, ObservedRevisionID: contract.ID{20}, RequestedRevisionID: contract.ID{20}, EvidenceCeiling: 1}
		if i%2 != 0 {
			row.CanonicalOutcome, row.StateResult, row.EvidenceCeiling = 2, 11, 2
			row.RequestedRevisionID = contract.ID{21}
		}
		r.Payload.Receipts[i] = row
	}
	var out bytes.Buffer
	if err := WriteReceiptListJSON(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Payload struct{ Receipts json.RawMessage }
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(doc.Payload.Receipts, &rows); err != nil {
		t.Fatal(err)
	}
	// The scalar list schema allows 393 bytes per row and 201,729 bytes for
	// the complete 512-row array, including brackets and all separators.
	var compactRows bytes.Buffer
	if err := json.Compact(&compactRows, doc.Payload.Receipts); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 512 || compactRows.Len() > 201729 || len(doc.Payload.Receipts) > 67*201729 || bytes.Contains(out.Bytes(), []byte("encoded_receipt")) {
		t.Fatal("complete retained set or numeric scalar bound changed", len(rows), compactRows.Len(), len(doc.Payload.Receipts))
	}
	var classes [2]int
	for i, encoded := range rows {
		var row struct {
			ID        string `json:"operation_id"`
			Kind      uint16 `json:"operation_kind"`
			Canonical uint8  `json:"canonical_outcome"`
			State     uint16 `json:"state_result"`
			Observed  string `json:"observed_revision_id"`
			Requested string `json:"requested_revision_id"`
			Warnings  uint64 `json:"warning_bits"`
			Evidence  uint16 `json:"evidence_ceiling"`
		}
		if err := json.Unmarshal(encoded, &row); err != nil {
			t.Fatal(err)
		}
		canonical, state, evidence := uint8(1), uint16(1), uint16(1)
		requested := "14" + strings.Repeat("00", 31)
		if i%2 != 0 {
			canonical, state, evidence = 2, 11, 2
			requested = "15" + strings.Repeat("00", 31)
		}
		wantID := fmt.Sprintf("01%s%08x", strings.Repeat("00", 27), 512-i)
		var compact bytes.Buffer
		if err := json.Compact(&compact, encoded); err != nil {
			t.Fatal(err)
		}
		if compact.Len() > 393 || len(encoded) > 67*393 || row.ID != wantID || row.Kind != 2 || row.Canonical != canonical || row.State != state || row.Observed != "14"+strings.Repeat("00", 31) || row.Requested != requested || row.Warnings != 0 || row.Evidence != evidence {
			t.Fatal("original receipt row, order or scalar representation changed", i, string(encoded))
		}
		classes[row.Canonical-1]++
	}
	if classes != [2]int{256, 256} {
		t.Fatal("independent retained classes changed", classes)
	}
	var human bytes.Buffer
	if err := WriteReceiptListHuman(t.Context(), &human, r); err != nil {
		t.Fatal(err)
	}
	_, humanRows, _ := strings.Cut(human.String(), "Receipts: 512 rows\n")
	if strings.Count(humanRows, "Operation id:") != 512 || strings.Count(humanRows, "Canonical outcome: selected\n") != 256 || strings.Count(humanRows, "Canonical outcome: not-selected\n") != 256 || strings.Count(humanRows, "State result: success\n") != 256 || strings.Count(humanRows, "State result: effect-terminal-failure\n") != 256 || strings.Count(humanRows, "Evidence ceiling: canonical\n") != 256 || strings.Count(humanRows, "Evidence ceiling: provider-facts\n") != 256 {
		t.Fatal("human output changed complete receipt counts or classes")
	}
	for i := range 512 {
		wantID := fmt.Sprintf("01%s%08x", strings.Repeat("00", 27), 512-i)
		at := strings.Index(humanRows, "Operation id: \""+wantID+"\"")
		if at < 0 {
			t.Fatal("human output lost receipt identity or order", i)
		}
		humanRows = humanRows[at+len("Operation id: \""+wantID+"\""):]
	}
	for _, cell := range []struct {
		name            string
		index           int
		canonical       uint8
		state, evidence uint16
		requested       contract.ID
	}{
		{"success-window-overflow", 1, 1, 1, 1, contract.ID{20}},
		{"failure-window-overflow", 0, 2, 11, 2, contract.ID{21}},
	} {
		t.Run(cell.name, func(t *testing.T) {
			damaged := r
			payload := *r.Payload
			payload.Receipts = append([]core.ReceiptSummary(nil), r.Payload.Receipts...)
			damaged.Payload = &payload
			row := &payload.Receipts[cell.index]
			row.CanonicalOutcome, row.StateResult, row.EvidenceCeiling, row.RequestedRevisionID = cell.canonical, cell.state, cell.evidence, cell.requested
			var refused bytes.Buffer
			if err := WriteReceiptListJSON(t.Context(), &refused, damaged); err == nil || refused.Len() != 0 {
				t.Fatal("257 receipts in one class crossed preflight", err, refused.Len())
			}
		})
	}
}

// full_only: false
func TestPublicQueryOutputAccountIncludesCompleteOwnerBounds(t *testing.T) {
	// Fixed group fields fit 2,048 bytes; each relation index contributes at
	// most six bytes including its separator. Other administrative frames fit
	// sixteen JSON bytes per canonical byte. The existing generated account
	// covers complete bounded attempts/work/progress and their warnings.
	const encodedSupport = uint64(256) * 2097152
	if contract.MaxChildPages != 256 || contract.MaxRequiredSupportPageLength != 2097152 || contract.MaxOutputConfigurationBytes != 37748736 || contract.MaxPublicationCoordinates != 1024 || contract.MaxPublicationMarkers != 2048 || contract.MaxOutputTargets != 1024 || contract.CryptoMaxMemberships != 4096 {
		t.Fatal("schema bounds changed; update the independent account")
	}
	minimum := generatedResultOutputLimit + 512*core.GeneratedResultAttemptLimit + 16*uint64(37748736) + 16*encodedSupport + 2048*65535 + 32768*1024 + 7168*1024 + 1024*1024 + 32768*2048 + 4096*768 + 67*4096 + 8192*512 + 65536
	if publicQueryOutputLimit != minimum {
		t.Fatal("complete representation account differs", publicQueryOutputLimit, minimum)
	}
	if publicQueryCompactOutputLimit != minimum+2048 {
		t.Fatal("native source singleton is not charged")
	}
	if publicQueryHumanOutputLimit != 67*(minimum+2048)+8192 {
		t.Fatal("human row layout and singleton account differs")
	}
}

// full_only: true
// Proves the reachable selected configuration, both 512-target binding
// tables, 64 bindings, 1,024 coordinates/current targets, 2,048 markers and
// all 2,048 current blocker indexes in one complete closed result.
func TestPublicInspectionCompleteJSONRecoversFullConfigurationAndPublicationTables(t *testing.T) {
	r := publicQueryRendererDomain(t)
	maximumInspectionMetadata(t, r.View)
	id := func(tag byte, n uint32) (id contract.ID) {
		id[0] = tag
		binary.BigEndian.PutUint32(id[28:], n)
		return id
	}
	policy := contract.OutputPolicy{ContractID: strings.Repeat("\x00", 256), Data: bytes.Repeat([]byte{255}, 20319)}
	config := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: r.DomainID}
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("%03d", i) + strings.Repeat("\x00", 253)
		if i == 0 {
			name = "00"
		}
		destination := contract.OutputDestination{ConfigContractID: strings.Repeat("\x00", 256), ServiceContractID: strings.Repeat("\x00", 256), CanonicalSettings: []byte(`"` + strings.Repeat("x", 65534) + `"`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, Policy: policy}
		if i == 63 {
			destination.Policy.Data = bytes.Repeat([]byte{255}, 21591)
		}
		binding := contract.OutputBinding{IncarnationID: id(3, uint32(i+1)), DestinationID: name, Destination: destination}
		if i < 2 {
			for j := 0; j < 512; j++ {
				target := contract.OutputTarget{EntryIncarnationID: r.View.Entries[j].IncarnationID, ServiceContractID: destination.ServiceContractID, CanonicalTarget: fmt.Sprintf("%06d", 512*i+j) + strings.Repeat("\x00", 1018), ConsumerLocator: strings.Repeat("\x00", 1024), TargetContractID: strings.Repeat("\x00", 256), TargetData: bytes.Repeat([]byte{255}, 4096), PayloadEncoding: contract.OutputEncodingBase64, Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: destination.Policy}
				binding.Targets = append(binding.Targets, target)
			}
		}
		config.Bindings = append(config.Bindings, binding)
	}
	// Declaration: 11,446,088 fixed bytes + 1,088*20,319 policy
	// bytes + 1,272 final-binding policy bytes = 33,554,432.
	for _, entry := range r.View.Entries {
		config.Groups = append(config.Groups, []contract.ID{entry.IncarnationID})
	}
	for _, binding := range config.Bindings[:8] {
		config.DefaultDestinations = append(config.DefaultDestinations, binding.DestinationID)
	}
	for _, entry := range r.View.Entries {
		config.Routes = append(config.Routes, contract.OutputRoute{EntryIncarnationID: entry.IncarnationID, Destinations: []string{config.Bindings[0].DestinationID, config.Bindings[1].DestinationID}})
	}
	// Routing: five fixed bytes + defaults(6+7*260) +512*(33+6+260).
	// The current entry rule ceiling makes a valid 36 MiB image unreachable.
	image, err := contract.EncodeOutputConfiguration(config)
	if err != nil {
		t.Fatal("full selected configuration setup", err)
	}
	if len(image) != 33709355 {
		t.Fatal("independent full-image calculation differs", len(image))
	}
	descriptor, _, err := contract.SplitOutputConfiguration(r.DomainID, image)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.TotalLength != 33709355 || descriptor.RoutingLength != 154919 || descriptor.SliceCount != 33 || descriptor.BindingCount != 64 {
		t.Fatal("full selected descriptor changed", descriptor)
	}
	output := core.InspectionOutput{ConfigurationDescriptor: descriptor, Configuration: config, Warnings: core.InspectionOutputWarnings{UnresolvedPublication: true, LateWriteRisk: true}}
	for bindingIndex, binding := range config.Bindings {
		for targetIndex, target := range binding.Targets {
			at := 512*bindingIndex + targetIndex
			coordinateID, err := contract.PublicationCoordinateID(r.DomainID, target.ServiceContractID, target.CanonicalTarget)
			if err != nil {
				t.Fatal(err)
			}
			targetDigest, err := contract.PublicationTargetRowDigest(r.DomainID, binding.DestinationID, binding.IncarnationID, target)
			if err != nil {
				t.Fatal(err)
			}
			incarnation := id(5, uint32(at+1))
			lastAttempt := id(4, uint32(2*at+2))
			coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: r.DomainID, CoordinateID: coordinateID, ServiceContractID: target.ServiceContractID, CanonicalTarget: target.CanonicalTarget, BindingState: contract.PublicationBindingActive, OwnerState: contract.PublicationOwnerUncertainCreate, ActiveBindingIncarnationID: binding.IncarnationID, LastBindingIncarnationID: binding.IncarnationID, LastEntryIncarnationID: target.EntryIncarnationID, CurrentPublicationIncarnationID: incarnation, LastAdmissionOrdinal: 2, LatestUnresolvedAttemptID: lastAttempt, PossibleRemoteObject: 1, LateEffectRisk: 1, DeletionDestinationID: binding.DestinationID, DeletionConsumerLocator: target.ConsumerLocator, DeletionTargetContractID: target.TargetContractID, DeletionConfigContractID: binding.Destination.ConfigContractID, DeletionCredentialRouteContractID: strings.Repeat("\x00", 256), DeletionTargetData: target.TargetData, DeletionPayloadEncoding: target.PayloadEncoding, DeletionTargetRowDigest: targetDigest}
			output.Coordinates = append(output.Coordinates, coordinate)
			for ordinal := uint64(1); ordinal <= 2; ordinal++ {
				projection := contract.PublicationProjection{Schema: 4, DomainID: r.DomainID, ConfigurationDigest: descriptor.ConfigurationDigest, CoordinateID: coordinateID, BindingIncarnationID: binding.IncarnationID, EntryIncarnationID: target.EntryIncarnationID, TargetRowDigest: targetDigest, Action: contract.PublicationCreateEmpty, PolicyDigest: id(6, 1), RequestContractDigest: id(6, 2), ActingRecipientID: r.View.Recipients[0].RecipientID}
				commitment, err := contract.PublicationProjectionCommitment(projection)
				if err != nil {
					t.Fatal(err)
				}
				marker := contract.PublicationMarker{Schema: 5, DomainID: r.DomainID, OperationID: id(6, uint32(at+3)), AttemptID: id(4, uint32(2*at)+uint32(ordinal)), CoordinateID: coordinateID, PublicationIncarnationID: incarnation, AdmissionOrdinal: ordinal, Projection: projection, ProjectionCommitment: commitment, AuthoritySubjectDigest: id(6, 2000), ExecutorID: strings.Repeat("\x00", 256), CredentialRouteID: strings.Repeat("\x00", 256), State: contract.PublicationUnknown, LateEffectRisk: 1, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: id(6, 2001)}, BirthServiceContractID: target.ServiceContractID, BirthTargetContractID: target.TargetContractID}
				output.Markers = append(output.Markers, marker)
			}
			output.CurrentTargets = append(output.CurrentTargets, core.InspectionCurrentTarget{BindingIndex: uint16(bindingIndex), TargetIndex: uint16(targetIndex), CoordinateID: coordinateID, LocatorBasis: core.InspectionConfiguredOnly})
		}
	}
	slices.SortFunc(output.Coordinates, func(a, b contract.PublicationCoordinate) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	positions := make(map[contract.ID]uint16, len(output.Coordinates))
	for i, coordinate := range output.Coordinates {
		positions[coordinate.CoordinateID] = uint16(i)
		r.View.Work.PublicationOrder = append(r.View.Work.PublicationOrder, format.PublicationCoordinateOrder{CoordinateID: coordinate.CoordinateID, Incarnations: []contract.ID{coordinate.CurrentPublicationIncarnationID}})
		output.CurrentBlockers = append(output.CurrentBlockers, core.InspectionCurrentBlockers{CoordinateIndex: uint16(i)})
	}
	for i := range output.CurrentTargets {
		position := positions[output.CurrentTargets[i].CoordinateID]
		output.CurrentTargets[i].CoordinateIndex = &position
	}
	for i, marker := range output.Markers {
		position := positions[marker.CoordinateID]
		output.CurrentBlockers[position].MarkerIndexes = append(output.CurrentBlockers[position].MarkerIndexes, uint16(i))
	}
	r.View.Output = output
	r.View.Warnings.Output = output.Warnings
	if err := r.ValidateMetadataWorkOutput(); err != nil {
		t.Fatal("full configuration/publication fixture violates owner contract", err)
	}
	var out bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), &out, r); err != nil {
		t.Fatal("complete maximum result", err)
	}
	var recovered struct {
		Payload struct {
			Entries []struct {
				Name        string
				Incarnation string `json:"incarnation_id"`
			}
			Work struct {
				PublicationOrder []struct {
					Coordinate   string `json:"coordinate_id"`
					Incarnations []string
				} `json:"publication_order"`
			}
			Output struct {
				Configuration struct {
					Bindings []struct {
						Destination string `json:"destination_id"`
						Facts       struct {
							Settings []byte `json:"canonical_settings_base64"`
							Policy   struct {
								Data []byte `json:"data_base64"`
							}
						} `json:"destination"`
						Targets []struct {
							Incarnation string `json:"entry_incarnation_id"`
							Slot        string `json:"canonical_target"`
							Consumer    string `json:"consumer_locator"`
							Data        []byte `json:"target_data_base64"`
							Policy      struct {
								Data []byte `json:"data_base64"`
							}
						}
					}
					DefaultDestinations []string `json:"default_destinations"`
					Routes              []struct {
						Entry        string `json:"entry_incarnation_id"`
						Destinations []string
					}
					Groups [][]string
				}
				Targets []struct {
					Binding    uint16  `json:"binding_index"`
					Target     uint16  `json:"target_index"`
					Coordinate string  `json:"coordinate_id"`
					Position   *uint16 `json:"coordinate_index"`
				} `json:"current_targets"`
				Coordinates []struct {
					ID   string `json:"coordinate_id"`
					Slot string `json:"canonical_target"`
				}
				Markers []struct {
					ID         string `json:"attempt_id"`
					Coordinate string `json:"coordinate_id"`
				}
				Blockers []struct {
					Coordinate uint16   `json:"coordinate_index"`
					Markers    []uint16 `json:"marker_indexes"`
				} `json:"current_blockers"`
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &recovered); err != nil {
		t.Fatal("complete maximum JSON", err)
	}
	got := recovered.Payload.Output
	if len(recovered.Payload.Entries) != 512 || len(got.Configuration.Bindings) != 64 || len(got.Configuration.Bindings[0].Targets) != 512 || len(got.Configuration.Bindings[1].Targets) != 512 || len(got.Configuration.DefaultDestinations) != 8 || len(got.Configuration.Routes) != 512 || len(got.Configuration.Groups) != 512 || len(got.Targets) != 1024 || len(got.Coordinates) != 1024 || len(got.Markers) != 2048 || len(got.Blockers) != 1024 || len(recovered.Payload.Work.PublicationOrder) != 1024 {
		t.Fatal("full result lost an owned table")
	}
	for i, entry := range recovered.Payload.Entries {
		if entry.Name != fmt.Sprintf("%04d", i)+strings.Repeat("\x00", 252) || entry.Incarnation != fmt.Sprintf("02%s%08x", strings.Repeat("00", 27), i+1000) {
			t.Fatal("full selected metadata set changed", i)
		}
	}
	for bindingIndex, binding := range got.Configuration.Bindings {
		policyLength := 20319
		if bindingIndex == 63 {
			policyLength = 21591
		}
		if binding.Destination != config.Bindings[bindingIndex].DestinationID || !bytes.Equal(binding.Facts.Settings, []byte(`"`+strings.Repeat("x", 65534)+`"`)) || !bytes.Equal(binding.Facts.Policy.Data, bytes.Repeat([]byte{255}, policyLength)) {
			t.Fatal("complete destination bytes changed", bindingIndex)
		}
		want := 0
		if bindingIndex < 2 {
			want = 512
		}
		if len(binding.Targets) != want {
			t.Fatal("binding target table changed", bindingIndex)
		}
		for targetIndex, target := range binding.Targets {
			if target.Incarnation != fmt.Sprintf("02%s%08x", strings.Repeat("00", 27), targetIndex+1000) || target.Incarnation != recovered.Payload.Entries[targetIndex].Incarnation || target.Slot != fmt.Sprintf("%06d", 512*bindingIndex+targetIndex)+strings.Repeat("\x00", 1018) || target.Consumer != strings.Repeat("\x00", 1024) || !bytes.Equal(target.Data, bytes.Repeat([]byte{255}, 4096)) || !bytes.Equal(target.Policy.Data, policy.Data) {
				t.Fatal("escaped target or repeated policy changed", bindingIndex, targetIndex)
			}
		}
	}
	for i, destination := range got.Configuration.DefaultDestinations {
		want := fmt.Sprintf("%03d", i) + strings.Repeat("\x00", 253)
		if i == 0 {
			want = "00"
		}
		if destination != want {
			t.Fatal("complete default destination order changed", i)
		}
	}
	for i, route := range got.Configuration.Routes {
		wantEntry := fmt.Sprintf("02%s%08x", strings.Repeat("00", 27), i+1000)
		wantDestinations := []string{"00", "001" + strings.Repeat("\x00", 253)}
		if route.Entry != wantEntry || !slices.Equal(route.Destinations, wantDestinations) {
			t.Fatal("complete entry route set changed", i)
		}
	}
	markerIDs := map[string]bool{}
	blocked := map[uint16]bool{}
	for i, marker := range got.Markers {
		want := id(4, uint32(i+1))
		if marker.ID != hex.EncodeToString(want[:]) || markerIDs[marker.ID] {
			t.Fatal("whole marker set changed", i)
		}
		markerIDs[marker.ID] = true
	}
	for i, coordinate := range got.Coordinates {
		if coordinate.ID != hex.EncodeToString(output.Coordinates[i].CoordinateID[:]) || coordinate.Slot != output.Coordinates[i].CanonicalTarget {
			t.Fatal("whole sorted coordinate set changed", i)
		}
		row := got.Blockers[i]
		if row.Coordinate != uint16(i) || len(row.Markers) != 2 {
			t.Fatal("compact blocker row changed", i)
		}
		for _, index := range row.Markers {
			if int(index) >= len(got.Markers) || blocked[index] || got.Markers[index].Coordinate != coordinate.ID {
				t.Fatal("blocker relation expanded, duplicated or moved", i, index)
			}
			blocked[index] = true
		}
	}
	for i, target := range got.Targets {
		want := output.CurrentTargets[i]
		if target.Binding != want.BindingIndex || target.Target != want.TargetIndex || target.Position == nil || target.Coordinate != hex.EncodeToString(want.CoordinateID[:]) || *target.Position != *want.CoordinateIndex {
			t.Fatal("current target compact relation changed", i)
		}
	}
	if len(blocked) != 2048 || uint64(out.Len()) > 67*publicQueryCompactOutputLimit {
		t.Fatal("complete maximum blocker relation or encoded bound changed", len(blocked), out.Len())
	}
	invalidIndex := uint16(65535)
	r.View.Output.CurrentTargets[len(r.View.Output.CurrentTargets)-1].CoordinateIndex = &invalidIndex
	var refused bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), &refused, r); err == nil || refused.Len() != 0 {
		t.Fatal("last maximum-table relation crossed preflight", err, refused.Len())
	}
}

// full_only: false
func TestPublicInspectionPublicationRowsPreserveMaximumEscapedEvidence(t *testing.T) {
	r := publicQueryRendererDomain(t)
	service, slot := strings.Repeat("\x00", 256), strings.Repeat("\x00", 1024)
	coordinateID, err := contract.PublicationCoordinateID(r.DomainID, service, slot)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: r.DomainID, CoordinateID: coordinateID, ServiceContractID: service, CanonicalTarget: slot, BindingState: contract.PublicationBindingRetired, OwnerState: contract.PublicationOwnerUncertainCreate, LastBindingIncarnationID: contract.ID{3}, LastEntryIncarnationID: contract.ID{12}, CurrentPublicationIncarnationID: contract.ID{40}, LastAdmissionOrdinal: 2, LatestUnresolvedAttemptID: contract.ID{21}, PossibleRemoteObject: 1, LateEffectRisk: 1, DeletionDestinationID: strings.Repeat("\x00", 256), DeletionConsumerLocator: slot, DeletionTargetContractID: service, DeletionConfigContractID: service, DeletionCredentialRouteContractID: service, DeletionTargetData: bytes.Repeat([]byte{255}, 4096), DeletionPayloadEncoding: 2, DeletionTargetRowDigest: contract.ID{14}}
	r.View.Output.Coordinates = []contract.PublicationCoordinate{coordinate}
	r.View.Output.CurrentBlockers = []core.InspectionCurrentBlockers{{MarkerIndexes: []uint16{1}}}
	r.View.Work.PublicationOrder = []format.PublicationCoordinateOrder{{CoordinateID: coordinateID, Incarnations: []contract.ID{{40}}}}
	for i := 0; i < 2; i++ {
		projection := contract.PublicationProjection{Schema: 4, DomainID: r.DomainID, ConfigurationDigest: contract.ID{13}, CoordinateID: coordinateID, BindingIncarnationID: contract.ID{3}, EntryIncarnationID: contract.ID{12}, TargetRowDigest: contract.ID{14}, Action: contract.PublicationCreateEmpty, PolicyDigest: contract.ID{15}, RequestContractDigest: contract.ID{16}, ActingRecipientID: contract.ID{5}}
		commitment, err := contract.PublicationProjectionCommitment(projection)
		if err != nil {
			t.Fatal(err)
		}
		marker := contract.PublicationMarker{Schema: 5, DomainID: r.DomainID, OperationID: contract.ID{byte(8 + i)}, AttemptID: contract.ID{byte(20 + i)}, CoordinateID: coordinateID, PublicationIncarnationID: contract.ID{40}, AdmissionOrdinal: uint64(i + 1), Projection: projection, ProjectionCommitment: commitment, AuthoritySubjectDigest: contract.ID{10}, ExecutorID: service, CredentialRouteID: service, State: contract.PublicationUnknown, LateEffectRisk: 1, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: contract.ID{11}}, BirthServiceContractID: service, BirthTargetContractID: service}
		if i == 0 {
			marker.State = contract.PublicationAcknowledged
			marker.Evidence.Class = contract.PublicationRequestAcknowledged
			marker.Evidence.NormalizedStatus = 201
			marker.Evidence.SafeRequestID = slot
			marker.Evidence.SafeResourceID = slot
			marker.Evidence.ConsumerLocator = slot
		}
		r.View.Output.Markers = append(r.View.Output.Markers, marker)
	}
	r.View.Output.Warnings = core.InspectionOutputWarnings{UnresolvedPublication: true, LateWriteRisk: true}
	r.View.Warnings.Output = r.View.Output.Warnings
	var out bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	var recovered struct {
		Payload struct {
			Output struct {
				Coordinates []struct {
					Slot     string `json:"canonical_target"`
					Deletion string `json:"deletion_consumer_locator"`
				}
				Markers []struct {
					Evidence struct {
						Request  string `json:"safe_request_id"`
						Resource string `json:"safe_resource_id"`
						Locator  string `json:"consumer_locator"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &recovered); err != nil {
		t.Fatal(err)
	}
	rows := recovered.Payload.Output
	if len(rows.Coordinates) != 1 || len(rows.Markers) != 2 || rows.Coordinates[0].Slot != slot || rows.Coordinates[0].Deletion != slot || rows.Markers[0].Evidence.Request != slot || rows.Markers[0].Evidence.Resource != slot || rows.Markers[0].Evidence.Locator != slot || rows.Markers[1].Evidence.Request != "" || rows.Markers[1].Evidence.Resource != "" || rows.Markers[1].Evidence.Locator != "" {
		t.Fatal("maximum escaped evidence changed")
	}
	var coordBytes, markerBytes resultStreamWriter
	coordBytes.ctx = t.Context()
	coordBytes.limit = publicQueryOutputLimit
	markerBytes.ctx = t.Context()
	markerBytes.limit = publicQueryOutputLimit
	q := queryBegin(&coordBytes)
	inspectionCoordinate(q, coordinate)
	q.end()
	q = queryBegin(&markerBytes)
	inspectionMarker(q, r.View.Output.Markers[0])
	q.end()
	if coordBytes.err != nil || markerBytes.err != nil || coordBytes.n+1 > 32768 || markerBytes.n+1 > 32768 {
		t.Fatal("complete publication row exceeds derived bound", coordBytes.n, markerBytes.n)
	}
}

// full_only: false
func TestPublicInspectionPendingReleasePreservesCompleteRecordWithinBound(t *testing.T) {
	r := publicQueryRendererDomain(t)
	row := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: r.DomainID, InboxID: contract.ID{2}, OriginalResultID: contract.ID{3}, SelectedHandoffDigest: contract.ID{4}, HandoffRevisionID: contract.ID{5}, CapacityReservation: contract.GeneratorDescriptor{Count: math.MaxUint32, Length: math.MaxUint64, Digest: contract.ID{6}}, ObjectLength: uint32(contract.GeneratedResultRecordMaxLength), State: contract.GeneratedReleasePending}
	cleanup, effect := generatedRendererRelease(row)
	r.View.Generated.PendingReleases = []core.GeneratedPendingResultCleanup{cleanup}
	r.View.Generated.Effects = []core.GeneratedEffectFact{effect}
	var out bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	var recovered struct {
		Payload struct {
			Generated struct {
				Releases []json.RawMessage `json:"pending_releases"`
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &recovered); err != nil {
		t.Fatal(err)
	}
	rows := recovered.Payload.Generated.Releases
	if len(rows) != 1 {
		t.Fatal("full release record omitted", len(rows))
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, rows[0]); err != nil {
		t.Fatal(err)
	}
	if compact.Len()+1 > 1024 || len(rows[0])+1 > 67*1024 {
		t.Fatal("full release record exceeds account or was omitted", len(rows))
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rows[0], &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 14 || fields["capacity_reservation"] == nil || fields["domain_id"] == nil || string(fields["schema"]) != "1" || fields["original_operation_id"] == nil || fields["original_attempt_id"] == nil || fields["effect_index"] != nil {
		t.Fatal("complete release fields lost", string(rows[0]))
	}
	const originalID = `"0100000000000000000000000000000000000000000000000000000000000000"`
	if string(fields["original_operation_id"]) != originalID || string(fields["original_attempt_id"]) != originalID || string(fields["action"]) != `"create"` || string(fields["effect_state"]) != `"succeeded"` || string(fields["completion_class"]) != `"deletion-acknowledged"` {
		t.Fatal("complete cleanup origin/status changed", string(rows[0]))
	}
}
