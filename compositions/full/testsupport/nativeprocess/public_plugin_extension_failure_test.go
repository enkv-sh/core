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
	f.retire(t, credential, removed.Duties[0].Facts.DutyID)
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
	lostChild := f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json")
	lost := nativeExtensionGeneratedOutcome(t, lostChild, "effect-unknown", 3)
	var detail struct {
		Effects  []struct{ Target json.RawMessage }
		Warnings struct {
			PossibleLive bool `json:"possible_live_residue"`
		} `json:"effect_warnings"`
	}
	if json.Unmarshal(lostChild.out, &detail) != nil || len(detail.Effects) != 1 || !bytes.Equal(detail.Effects[0].Target, []byte("null")) || !detail.Warnings.PossibleLive || lost.Receipt == "" || len(lost.Effects) != 1 || len(lost.Hazards) != 1 {
		t.Fatal("lost CREATE reply did not close with one unqualified effect and a possible-live warning")
	}
	original := lost.Effects[0]
	_, firstRoot, firstEntries := f.selected(t)
	hazards := nativeExtensionHazards(t, f, firstRoot)
	if len(hazards) != 1 || original.Facts.Action != "create" || original.Facts.State != "closed-with-residue" || !firstRoot.Generated.ActiveOwner.IsZero() || len(firstEntries) != 0 || firstRoot.Generated.GeneratedCurrent != 0 || firstRoot.Generated.Duties != 0 || f.service.Counts() != (testservice.Counts{Tokens: 1, TokenCreates: 1}) {
		t.Fatal("uncertain CREATE changed current values, kept the operation active or sent another provider request")
	}
	hazard := hazards[0]
	if hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.Target.Count != 0 || hazard.ResourceID.IsZero() || hazard.OriginalAttemptID.IsZero() || hazard.OriginalOperationID.IsZero() ||
		nativeExtensionID(hazard.ResourceID) != original.Facts.PlannedResourceID || nativeExtensionID(hazard.OriginalAttemptID) != original.Facts.AttemptID ||
		nativeExtensionID(hazard.OriginalOperationID) != lost.Operation || lost.Hazards[0].Facts.HazardID != nativeExtensionID(hazard.HazardID) || lost.Hazards[0].Facts.OriginalAttemptID != original.Facts.AttemptID {
		t.Fatal("lost CREATE did not preserve the original operation, attempt and planned resource in its hazard")
	}
	list := func() nativeGeneratedOutput {
		child := f.run(t, "reader", true, nil, "generated", "list", "--source", f.path, "--source-format", "json", "--json")
		workflowGETOnly(t, child)
		return nativeExtensionGeneratedOutcome(t, child, "success", 0)
	}
	before := list()
	if len(before.Current) != 0 || len(before.Duties) != 0 || len(before.Hazards) != 1 || before.Hazards[0].Facts.HazardID != nativeExtensionID(hazard.HazardID) || before.Hazards[0].Facts.OriginalAttemptID != original.Facts.AttemptID || f.service.Counts() != (testservice.Counts{Tokens: 1, TokenCreates: 1}) {
		t.Fatal("fresh reader lost the original hazard or observed an unrequested replacement")
	}

	replacement := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, credential, "apply", "--source", f.path, "--source-format", "json", "--json"), "success", 0)
	if replacement.Operation == "" || replacement.Operation == lost.Operation || len(replacement.Effects) != 1 {
		t.Fatal("explicit replacement did not start one distinct CREATE operation")
	}
	successor := replacement.Effects[0]
	_, selected, entries := f.selected(t)
	if successor.Facts.Action != "create" || successor.Facts.State != "succeeded" || successor.Facts.AttemptID == "" || successor.Facts.AttemptID == original.Facts.AttemptID ||
		successor.Target.ResourceID == original.Facts.PlannedResourceID || successor.Target.ResourceID != successor.Facts.PlannedResourceID ||
		entries["TOKEN"].Generated.ResourceIncarnationID.IsZero() || nativeExtensionID(entries["TOKEN"].Generated.ResourceIncarnationID) != successor.Target.ResourceID ||
		selected.Generated.GeneratedCurrent != 1 || selected.Generated.Hazards != 1 || !reflect.DeepEqual(hazards, nativeExtensionHazards(t, f, selected)) || f.service.Counts() != (testservice.Counts{Tokens: 2, TokenCreates: 2}) {
		t.Fatal("explicit replacement did not select its own resource and preserve the original hazard")
	}
	nativeExtensionReadToken(t, f, "t2", []byte("\x00\xffextension/consumer/t2"))
	listed := list()
	if len(listed.Current) != 1 || listed.Current[0].ResourceID != successor.Target.ResourceID || len(listed.Hazards) != 1 || listed.Hazards[0].Facts.OriginalAttemptID != original.Facts.AttemptID || f.service.Counts() != (testservice.Counts{Tokens: 2, TokenCreates: 2}) {
		t.Fatal("fresh process lost original uncertainty or substituted its resource")
	}
	f.source["entries"] = map[string]any{}
	nativeGeneratedWriteJSON(t, f.path, f.source)
	removed := nativeExtensionGeneratedOutcome(t, f.run(t, "apply", false, nil, "apply", "--source", f.path, "--source-format", "json", "--retire-generator", "TOKEN=private-local-token", "--json"), "retirement-pending", 3)
	if len(removed.Duties) != 1 || removed.Duties[0].Target.ResourceID != successor.Target.ResourceID {
		t.Fatal("known successor cleanup substituted the uncertain original")
	}
	f.retire(t, credential, removed.Duties[0].Facts.DutyID)
	final := list()
	_, done, _ := f.selected(t)
	if len(final.Current) != 0 || len(final.Duties) != 0 || len(final.Hazards) != 1 || done.Generated.GeneratedCurrent != 0 || done.Generated.Duties != 0 || done.Generated.Hazards != 1 || !reflect.DeepEqual(hazards, nativeExtensionHazards(t, f, done)) || f.service.Counts() != (testservice.Counts{Tokens: 1, TokenCreates: 2, TokenRetires: 1}) {
		t.Fatal("known successor cleanup resolved or lost the original uncertainty")
	}
	nativeExtensionReadToken(t, f, "t1", []byte("\x00\xffextension/consumer/t1"))
	f.finish(t, 8, "consumer/t1", "consumer/t2")
}
