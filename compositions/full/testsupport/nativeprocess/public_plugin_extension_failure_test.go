package nativeprocess

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/examples/testservice"
)

func nativeExtensionLostOutput(t *testing.T, cli string, builds []artifact.LocalPlugin) {
	f := newNativeExtensionCase(t, cli, builds)
	subject := "consumer"
	f.declare(t, 0, "manual", &subject, true)
	credential := []string{"ENKV_EXAMPLE_TOKEN=" + nativeExtensionBearer}
	nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
	pair := workflowReadPair(t, f.path)
	physical := f.server.URL + "/values/extension/VE9LRU4"
	preimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), pair.descriptor.DomainID[:]...)
	for _, field := range []string{"local-values-service/v1", physical} {
		preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(field)))
		preimage = append(preimage, field...)
	}
	coordinate := workflowDigest(preimage)
	plainPhysical := f.server.URL + "/values/extension/UExBSU4"
	plainPreimage := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), pair.descriptor.DomainID[:]...)
	for _, field := range []string{"local-values-service/v1", plainPhysical} {
		plainPreimage = binary.BigEndian.AppendUint32(plainPreimage, uint32(len(field)))
		plainPreimage = append(plainPreimage, field...)
	}
	plainCoordinate := workflowDigest(plainPreimage)
	f.service.LoseNextValueReply()
	firstChild := f.run(t, "apply", false, credential, "publish", "--source", f.path, "--source-format", "json", "--name", "TOKEN", "--json")
	first := nativePublicationUnknown(t, firstChild, coordinate, []string{"create-with-value"})
	unknown := *first.Payload.Entries[0].Actions[0].Attempt
	beforeHead, _, _ := f.selected(t)
	beforeRows := nativePublicationRows(nativePublicationSelectedParts(t, f.store))
	plainRecord, err := contract.InspectPublicationCoordinate(beforeRows[fmt.Sprintf("%d/%s", contract.PublicationCoordinateSupportKind, plainCoordinate)])
	if err != nil || nativeExtensionID(plainRecord.CoordinateID) != plainCoordinate || plainRecord.CanonicalTarget != plainPhysical || plainRecord.BindingState != contract.PublicationBindingActive || plainRecord.OwnerState != contract.PublicationOwnerNone || plainRecord.PossibleRemoteObject != 0 || plainRecord.LateEffectRisk != 0 || !plainRecord.LastValueAckAttemptID.IsZero() || !plainRecord.LatestUnresolvedAttemptID.IsZero() {
		t.Fatal("Apply did not retain the exact active unpublished plain coordinate", err)
	}
	if f.service.Counts() != (testservice.Counts{Tokens: 1, Values: 1, TokenCreates: 1, ValueCreates: 1}) {
		t.Fatal("lost output reply did not preserve exactly one possible remote create")
	}
	secondChild := f.run(t, "apply", true, nil, "publish", "--source", f.path, "--source-format", "json", "--name", "TOKEN", "--json")
	second := nativePublicationUnknown(t, secondChild, coordinate, []string{"create-with-value"})
	workflowGETOnly(t, secondChild)
	afterHead, _, _ := f.selected(t)
	afterRows := nativePublicationRows(nativePublicationSelectedParts(t, f.store))
	if *second.Payload.Entries[0].Actions[0].Attempt != unknown || !reflect.DeepEqual(second.Payload.Entries[0].Actions[0].Blockers, []string{unknown}) || !reflect.DeepEqual(beforeHead, afterHead) || !reflect.DeepEqual(beforeRows, afterRows) || f.service.Counts() != (testservice.Counts{Tokens: 1, Values: 1, TokenCreates: 1, ValueCreates: 1}) {
		t.Fatal("a later process replayed or replaced the exact unknown output")
	}
	preview := f.run(t, "reader", true, nil, "plan", "--trusted", f.path, "--trusted-format", "json", "--publish", "--json")
	workflowGETOnly(t, preview)
	var planned struct {
		State   string `json:"state_result"`
		Payload struct {
			Publication struct {
				Schema   string
				Complete bool
				Warning  bool `json:"domain_wide_warning"`
				Entries  []struct {
					Coordinate    *string `json:"coordinate_id"`
					Name          *string `json:"entry_name"`
					Target        string  `json:"physical_target"`
					Origin, Basis string
					Actions       []string
					Blockers      []string `json:"blocker_ids"`
					Remote        bool     `json:"remote_value_may_remain"`
					Late          bool     `json:"late_write_risk"`
				}
			}
		}
	}
	decoded := json.Unmarshal(preview.out, &planned) == nil
	if !decoded || preview.code != 0 || planned.State != "success" || planned.Payload.Publication.Schema != "PublicationPreview/v2" || !planned.Payload.Publication.Complete || planned.Payload.Publication.Warning || len(planned.Payload.Publication.Entries) != 2 {
		t.Logf("lost-output preview facts: decoded=%t exit=%d success=%t schema=%t complete=%t warning=%t rows=%d", decoded, preview.code, planned.State == "success", planned.Payload.Publication.Schema == "PublicationPreview/v2", planned.Payload.Publication.Complete, planned.Payload.Publication.Warning, len(planned.Payload.Publication.Entries))
		t.Fatal("restart preview lost coordinate uncertainty or invented a domain-wide warning")
	}
	// Apply already selects coordinates for all targets. PLAIN remains
	// unpublished even though its selected binding and coordinate are observed.
	plain, token := planned.Payload.Publication.Entries[0], planned.Payload.Publication.Entries[1]
	if plain.Name == nil || *plain.Name != "PLAIN" || plain.Target != plainPhysical || plain.Origin != "both" || plain.Coordinate == nil || *plain.Coordinate != plainCoordinate || len(plain.Blockers) != 0 || plain.Remote || plain.Late || plain.Basis != "unpublished" || !reflect.DeepEqual(plain.Actions, []string{"create-with-value"}) || token.Name == nil || *token.Name != "TOKEN" || token.Target != physical || token.Origin != "both" || token.Basis != "blocked" || token.Coordinate == nil || *token.Coordinate != coordinate || !reflect.DeepEqual(token.Blockers, []string{unknown}) || !token.Remote || !token.Late || len(token.Actions) != 0 {
		t.Logf("lost-output preview rows: plain_name=%t plain_both=%t exact_plain_coordinate=%t plain_unpublished=%t plain_actions=%d token_name=%t token_both=%t token_blocked=%t exact_coordinate=%t exact_blocker=%t token_remote=%t token_late=%t token_actions=%d", plain.Name != nil && *plain.Name == "PLAIN", plain.Origin == "both", plain.Coordinate != nil && *plain.Coordinate == plainCoordinate, plain.Basis == "unpublished", len(plain.Actions), token.Name != nil && *token.Name == "TOKEN", token.Origin == "both", token.Basis == "blocked", token.Coordinate != nil && *token.Coordinate == coordinate, reflect.DeepEqual(token.Blockers, []string{unknown}), token.Remote, token.Late, len(token.Actions))
		t.Fatal("complete preview changed the unpublished plain row or exact unknown token row")
	}
	f.source["entries"] = map[string]any{}
	f.source["outputs"] = map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}
	nativeGeneratedWriteJSON(t, f.path, f.source)
	removed := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, nil, "apply", "--source", f.path, "--source-format", "json", "--retire-generator", "TOKEN=private-local-token", "--json"), "retirement-pending", 3)
	if len(removed.Duties) != 1 {
		t.Fatal("lost output cleanup lost its known generated resource")
	}
	nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "generated", "retire", "--source", f.path, "--source-format", "json", "--duty", removed.Duties[0].Facts.DutyID, "--json"), "success", 0)
	_, done, _ := f.selected(t)
	finalRows := nativePublicationRows(nativePublicationSelectedParts(t, f.store))
	markerKey := fmt.Sprintf("%d/%s", contract.PublicationMarkerSupportKind, unknown)
	if done.Generated.GeneratedCurrent != 0 || done.Generated.Duties != 0 || !bytes.Equal(finalRows[markerKey], beforeRows[markerKey]) || len(finalRows[markerKey]) == 0 || f.service.Counts() != (testservice.Counts{Values: 1, TokenCreates: 1, TokenRetires: 1, ValueCreates: 1}) {
		t.Fatal("known generator cleanup erased or adopted the unknown output")
	}
	// The unknown value remains unresolved in Product state. Closing this local
	// service during test disposal is not an admitted deletion or absence proof.
	f.finish(t, 7, "consumer/t1")
}

func nativeExtensionHazards(t *testing.T, f *nativeExtensionCase, root stateformat.Root) []contract.GeneratedHazardRecord {
	t.Helper()
	var hazards []contract.GeneratedHazardRecord
	for _, ref := range root.RequiredSupport {
		key, err := stateformat.Key(f.store.prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := stateformat.InspectRequiredSupportPage(f.store.object(t, key).body)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Records {
			if row.Kind == contract.GeneratedHazardSupportKind {
				hazard, err := contract.InspectGeneratedHazardRecord(row.Body)
				if err != nil || hazard.HazardID != row.RecordID {
					t.Fatal("selected independent Hazard is invalid", err)
				}
				hazards = append(hazards, hazard)
			}
		}
	}
	return hazards
}

func nativeExtensionLostGenerator(t *testing.T, cli string, builds []artifact.LocalPlugin) {
	f := newNativeExtensionCase(t, cli, builds)
	subject := "consumer"
	f.declare(t, 0, "manual", &subject, false)
	credential := []string{"ENKV_EXAMPLE_TOKEN=" + nativeExtensionBearer}
	f.service.LoseNextTokenReply()
	createdChild := f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json")
	created := nativeExtensionGeneratedOutcome(t, createdChild, "success", 0)
	var original, successor *nativeGeneratedFact
	for i := range created.Effects {
		switch created.Effects[i].Facts.State {
		case "closed-with-residue":
			if original != nil {
				t.Fatal("duplicate original unqualified effect")
			}
			original = &created.Effects[i]
		case "succeeded":
			if successor != nil {
				t.Fatal("duplicate qualified successor effect")
			}
			successor = &created.Effects[i]
		}
	}
	if len(created.Effects) != 2 || original == nil || successor == nil {
		t.Logf("lost-generator terminal facts: effects=%d original=%t successor=%t hazards=%d", len(created.Effects), original != nil, successor != nil, len(created.Hazards))
		t.Fatal("lost reply did not retain one closed residue and one qualified successor")
	}
	var planned struct {
		Effects []struct {
			Facts struct {
				Attempt  string `json:"attempt_id"`
				Resource string `json:"planned_resource_incarnation_id"`
			}
			Target json.RawMessage
		}
	}
	if json.Unmarshal(createdChild.out, &planned) != nil || len(planned.Effects) != 2 {
		t.Fatal("lost-generator planned facts are malformed")
	}
	var originalResource, successorResource string
	for _, row := range planned.Effects {
		switch row.Facts.Attempt {
		case original.Facts.AttemptID:
			if !bytes.Equal(row.Target, []byte("null")) || originalResource != "" {
				t.Fatal("unqualified original invented a target or duplicated its Attempt")
			}
			originalResource = row.Facts.Resource
		case successor.Facts.AttemptID:
			if bytes.Equal(row.Target, []byte("null")) || successorResource != "" {
				t.Fatal("qualified successor lost its target or duplicated its Attempt")
			}
			successorResource = row.Facts.Resource
		default:
			t.Fatal("lost-generator result added an unrelated Attempt")
		}
	}
	_, selected, entries := f.selected(t)
	hazards := nativeExtensionHazards(t, f, selected)
	if len(originalResource) != 64 || len(successorResource) != 64 || originalResource == successorResource || original.Facts.AttemptID == successor.Facts.AttemptID || original.Target.ResourceID != "" || successor.Target.ResourceID != successorResource || len(created.Hazards) != 1 || len(hazards) != 1 || created.Hazards[0].Facts.OriginalAttemptID != original.Facts.AttemptID || nativeExtensionID(hazards[0].OriginalAttemptID) != original.Facts.AttemptID || nativeExtensionID(hazards[0].ResourceID) != originalResource || nativeExtensionID(entries["TOKEN"].Generated.ResourceIncarnationID) != successorResource || selected.Generated.GeneratedCurrent != 1 || selected.Generated.Hazards != 1 || f.service.Counts() != (testservice.Counts{Tokens: 2, TokenCreates: 2}) {
		t.Logf("lost-generator selection facts: planned_original=%t planned_successor=%t distinct_resources=%t original_target_absent=%t exact_successor_target=%t public_hazards=%d stored_hazards=%d current=%d hazards=%d", len(originalResource) == 64, len(successorResource) == 64, originalResource != successorResource, original.Target.ResourceID == "", successor.Target.ResourceID == successorResource, len(created.Hazards), len(hazards), selected.Generated.GeneratedCurrent, selected.Generated.Hazards)
		t.Fatal("lost original was adopted or its qualified distinct successor/Hazard was lost")
	}
	nativeExtensionReadToken(t, f, "t2", []byte("\x00\xffextension/consumer/t2"))
	listed := nativeExtensionGeneratedOutcome(t, f.run(t, "reader", true, nil, "generated", "list", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
	if len(listed.Current) != 1 || listed.Current[0].ResourceID != successor.Target.ResourceID || len(listed.Hazards) != 1 || listed.Hazards[0].Facts.OriginalAttemptID != original.Facts.AttemptID || f.service.Counts() != (testservice.Counts{Tokens: 2, TokenCreates: 2}) {
		t.Fatal("fresh process lost original uncertainty or substituted its resource")
	}
	f.source["entries"] = map[string]any{}
	nativeGeneratedWriteJSON(t, f.path, f.source)
	removed := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, nil, "apply", "--source", f.path, "--source-format", "json", "--retire-generator", "TOKEN=private-local-token", "--json"), "retirement-pending", 3)
	if len(removed.Duties) != 1 || removed.Duties[0].Target.ResourceID != successor.Target.ResourceID {
		t.Fatal("known successor cleanup substituted the uncertain original")
	}
	nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "generated", "retire", "--source", f.path, "--source-format", "json", "--duty", removed.Duties[0].Facts.DutyID, "--json"), "success", 0)
	final := nativeExtensionGeneratedOutcome(t, f.run(t, "reader", true, nil, "generated", "list", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
	_, done, _ := f.selected(t)
	if len(final.Current) != 0 || len(final.Duties) != 0 || len(final.Hazards) != 1 || done.Generated.GeneratedCurrent != 0 || done.Generated.Duties != 0 || done.Generated.Hazards != 1 || !reflect.DeepEqual(hazards, nativeExtensionHazards(t, f, done)) || f.service.Counts() != (testservice.Counts{Tokens: 1, TokenCreates: 2, TokenRetires: 1}) {
		t.Fatal("known successor cleanup resolved or lost the original uncertainty")
	}
	f.finish(t, 6, "consumer/t1", "consumer/t2")
}
