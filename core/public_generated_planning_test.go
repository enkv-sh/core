package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedPlanningUnitEntry(t *testing.T, name string) contract.PublicEntry {
	t.Helper()
	base := publicConfigurationFixture(t)
	entry := publicFixtureEntry(base, name)
	entry.Source = publicPresent(contract.Generated)
	entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
	entry.Generated.Epoch.Value = 3
	return entry
}

// full_only: false
func TestGeneratedPlanningKeepsExactObservedIncarnationsBeyondOneGraph(t *testing.T) {
	var state *StateSession
	var rows []contract.SupportRecord
	var owners []contract.ID
	var lastDuty contract.ID
	var lastTarget contract.GeneratorTarget
	for at := 0; at < 130; at++ {
		name := fmt.Sprintf("n%03d", at)
		operation := contract.Hash([]byte("old-operation/" + name))
		incarnation := contract.Hash([]byte("old-incarnation/" + name))
		old := generatedSelectedEntryOriginNamed(t, operation, incarnation, 0, name, generatedVectorID(18), generatedVectorID(12), operation)
		entry := old.pages[0].Slots[0]
		if state == nil {
			state = old
			rows = state.supportRecords()
		}
		if at != 0 {
			for _, row := range old.supportRecords() {
				if row.Kind == contract.GeneratedCreateEvidenceSupportKind {
					rows = append(rows, row)
				}
			}
		}
		dutyID, err := contract.GeneratorDutyID(old.root.Domain, operation, entry.Generated.OriginAttemptID, contract.GeneratedDutyRetirement)
		if err != nil {
			t.Fatal(err)
		}
		target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, Name: name, IncarnationID: incarnation, Epoch: 1, ResourceID: entry.Generated.ResourceIncarnationID,
			ConfigContractID: entry.Generated.ConfigContractID, ResourceContractID: entry.Generated.ResourceContractID, ResourceDigest: entry.Generated.ResourceDigest, LifecycleMode: entry.Generated.LifecycleMode,
			OriginalOperationID: operation, OriginalAttemptID: entry.Generated.OriginAttemptID, ResultContractID: generatedVectorID(20), CompletionClass: contract.GeneratedCompletionAcknowledged}
		targetBody, err := contract.EncodeGeneratorTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		descriptor, carriers := generatedVectorRows(t, contract.GeneratedDutySupportKind, dutyID, contract.GeneratorVectorTargets, [][]byte{targetBody})
		duty := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, DomainID: old.root.Domain, DutyID: dutyID, OwnerID: dutyID, OriginalOperationID: operation, OriginalAttemptID: target.OriginalAttemptID,
			ResourceID: target.ResourceID, DescriptorID: generatedVectorID(9), ConfigContractID: target.ConfigContractID, LifecycleMode: target.LifecycleMode, ExecutorID: generatedVectorID(40), CredentialRouteID: generatedVectorID(41),
			ResourceContractID: target.ResourceContractID, ResultContractID: generatedVectorID(43), Kind: contract.GeneratedDutyRetirement, CompletionClass: contract.GeneratedCompletionAcknowledged,
			Step: 1, Status: contract.GeneratedEffectNotStarted, CapacityReservation: generatedCapacityReservationFixture(), Target: descriptor,
			Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory),
			Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), Consumers: contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)}
		body, err := contract.EncodeGeneratedDutyRecord(duty)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: dutyID, Body: body})
		rows = append(rows, carriers...)
		owners = append(owners, dutyID)
		if at == 128 {
			lastDuty, lastTarget = dutyID, target
		}
	}
	current := generatedSelectedEntryOriginNamed(t, contract.Hash([]byte("new-operation/n128")), contract.Hash([]byte("new-incarnation/n128")), 0, "n128", generatedVectorID(18), generatedVectorID(12), generatedVectorID(211))
	current.pages[0].Slots[0].Generated.RetiringDutyPresent = 1
	current.pages[0].Slots[0].Generated.RetiringDutyID = lastDuty
	for _, row := range current.supportRecords() {
		if row.Kind == contract.GeneratedCreateEvidenceSupportKind {
			rows = append(rows, row)
		}
	}
	state.pages, state.access, state.root.Names = current.pages, current.access, current.root.Names
	state.root.ValueEntryCount, state.root.Generated.GeneratedCurrent = 1, 1
	state.root.Generated.Duties, state.root.Generated.Retiring = 130, 130
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var err error
	state.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRepackSupport(t, state, rows, nil)
	generatedSealSelectedFixture(t, state)
	if !state.indexSelectedMaterials() {
		t.Fatal("retained-name fixture material index")
	}
	g, err := state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("complete retained-name graph refused", err)
	}
	desired := PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}
	desired.Configuration.Entries = publicPresent([]contract.PublicEntry{})
	for at := 0; at < 128; at++ {
		entry := generatedPlanningUnitEntry(t, fmt.Sprintf("n%03d", at))
		entry.Generated.Epoch.Value = 0
		desired.Configuration.Entries.Value = append(desired.Configuration.Entries.Value, entry)
	}
	retirements, err := collectGeneratedPlanningRetirements(context.Background(), g, desired)
	if err != nil || len(retirements) != 129 || cap(retirements) > 256 || retirements[128].name != "n128" {
		t.Fatal("retained names were capped by one graph or irrelevant work leaked", len(retirements), err)
	}
	actual := PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true, Configuration: contract.PublicConfiguration{Entries: publicPresent([]contract.PublicEntry{generatedPlanningUnitEntry(t, "n128")})}}
	image := state.selectedImage()
	selected := publicSelection{image: *image, complete: true}
	planned := generatedPlanningEntries(desired, actual, &selected, retirements)
	if len(planned) != 129 {
		t.Fatal("complete generated-name union changed", len(planned))
	}
	last := planned[128]
	if last.Name != "n128" || last.CurrentIncarnation != current.pages[0].Slots[0].Incarnation || last.CurrentGeneration != current.pages[0].Slots[0].Generated.GenerationID ||
		last.RetiringDutyID != lastDuty || last.RetiringIncarnation != lastTarget.IncarnationID || last.RetiringResource != lastTarget.ResourceID ||
		last.RetiringOriginalOperation != lastTarget.OriginalOperationID || last.RetiringOriginalAttempt != lastTarget.OriginalAttemptID || last.RetiringEpoch != 1 ||
		last.CurrentIncarnation == last.RetiringIncarnation || last.Action != contract.GeneratedPlanningRemoval {
		t.Fatal("same-name new incarnation replaced the exact old retirement target")
	}
	if len(image.root.Names) != 1 || image.root.Names[0] != (format.NameEntry{Name: "n128"}) {
		t.Fatal("fixture lost its one current name")
	}
}

// full_only: false
func TestGeneratedPlanningClassifiesCompleteIntent(t *testing.T) {
	for _, item := range []struct {
		name             string
		action           contract.GeneratedPlanningAction
		retirement       contract.GeneratedPlanningRetirement
		fields, blockers uint16
	}{
		{"unchanged", contract.GeneratedPlanningUnchanged, contract.GeneratedPlanningNoRetirement, 0, 0},
		{"canonical-intent-copy", contract.GeneratedPlanningUnchanged, contract.GeneratedPlanningNoRetirement, 0, 0},
		{"create", contract.GeneratedPlanningCreate, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningPresence, 0},
		{"initial-epoch", contract.GeneratedPlanningCreate, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningPresence, contract.GeneratedPlanningInitialEpoch},
		{"rotation", contract.GeneratedPlanningRotate, contract.GeneratedPlanningRetireAfterSuccessor, contract.GeneratedPlanningEpoch, 0},
		{"lower-epoch", contract.GeneratedPlanningRotate, contract.GeneratedPlanningRetireAfterSuccessor, contract.GeneratedPlanningEpoch, contract.GeneratedPlanningStaleEpoch},
		{"same-epoch-content", contract.GeneratedPlanningRotate, contract.GeneratedPlanningRetireAfterSuccessor, contract.GeneratedPlanningContentIntent, contract.GeneratedPlanningIntentConflict},
		{"policy", contract.GeneratedPlanningPolicyChange, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningRetirementPolicy, contract.GeneratedPlanningIntentConflict},
		{"access", contract.GeneratedPlanningAccessChange, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningMemberships, 0},
		{"policy-access", contract.GeneratedPlanningPolicyAccessChange, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningRetirementPolicy | contract.GeneratedPlanningMemberships, contract.GeneratedPlanningIntentConflict},
		{"generated-to-supplied", contract.GeneratedPlanningSourceChange, contract.GeneratedPlanningRetireAfterSuccessor, contract.GeneratedPlanningSource, 0},
		{"supplied-to-generated", contract.GeneratedPlanningSourceChange, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningSource, 0},
		{"removal", contract.GeneratedPlanningRemoval, contract.GeneratedPlanningRetireAfterRemoval, contract.GeneratedPlanningPresence, 0},
		{"class-conversion", contract.GeneratedPlanningUnchanged, contract.GeneratedPlanningNoRetirement, contract.GeneratedPlanningClass, contract.GeneratedPlanningClassConflict},
	} {
		t.Run(item.name, func(t *testing.T) {
			before := generatedPlanningUnitEntry(t, "value/\n雪")
			after := before
			generated := *before.Generated
			after.Generated = &generated
			w, a := &after, &before
			switch item.name {
			case "canonical-intent-copy":
				after.Generated.ContentIntent.Value = bytes.Clone(before.Generated.ContentIntent.Value)
			case "create":
				a = nil
				after.Generated.Epoch.Value = 0
			case "initial-epoch":
				a = nil
			case "rotation":
				after.Generated.Epoch.Value = 4
			case "lower-epoch":
				after.Generated.Epoch.Value = 2
			case "same-epoch-content":
				after.Generated.ContentIntent.Value = publicFixtureIntent(contract.GeneratorLifecycleManaged, []byte(`{"size":4}`))
			case "policy":
				after.Generated.Retirement.Value = contract.GeneratedRetirementAuto
			case "access":
				after.Memberships.Value = append([]contract.ID{}, after.Memberships.Value[:len(after.Memberships.Value)-1]...)
			case "policy-access":
				after.Generated.Retirement.Value = contract.GeneratedRetirementAuto
				after.Memberships.Value = nil
			case "generated-to-supplied":
				after.Source.Value = contract.Supplied
				after.Generated = nil
			case "supplied-to-generated":
				before.Source.Value = contract.Supplied
				before.Generated = nil
				after.Generated.Epoch.Value = 0
			case "removal":
				w = nil
			case "class-conversion":
				after.Class.Value = contract.Plain
			}
			row := classifyGeneratedPlanningEntry(w, a)
			if row.Name != "value/\n雪" || row.Action != item.action || row.Retirement != item.retirement || row.ChangedFields != item.fields || row.Blockers != item.blockers {
				t.Fatalf("requested intent differs: action=%d retirement=%d changed=%x blockers=%x", row.Action, row.Retirement, row.ChangedFields, row.Blockers)
			}
			if !row.CurrentGeneration.IsZero() || !row.CurrentIncarnation.IsZero() || !row.ActiveOperation.IsZero() || !row.RetiringDutyID.IsZero() {
				t.Fatal("declaration-only classification fabricated observed identities")
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanningResultBoundsAndOwnedNames(t *testing.T) {
	if unsafe.Sizeof(contract.GeneratedPlanningEntry{}) != 312 || unsafe.Sizeof(generatedPlanningRetirement{}) != 184 || contract.MaxGeneratedPlanningEntries != 256 || contract.MaxComparisonResultJSONBytes != 2356478048 {
		t.Fatal("generated planning account changed without a new derivation")
	}
	before, after := PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}, PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}
	before.Configuration.Entries = publicPresent([]contract.PublicEntry{})
	after.Configuration.Entries = publicPresent([]contract.PublicEntry{})
	for at := 0; at < 128; at++ {
		before.Configuration.Entries.Value = append(before.Configuration.Entries.Value, generatedPlanningUnitEntry(t, fmt.Sprintf("a%03d", at)))
		entry := generatedPlanningUnitEntry(t, fmt.Sprintf("z%03d", at))
		entry.Generated.Epoch.Value = 0
		after.Configuration.Entries.Value = append(after.Configuration.Entries.Value, entry)
	}
	rows := generatedPlanningEntries(after, before, nil, nil)
	if len(rows) != 256 || cap(rows) > 256 || rows[0].Name != "a000" || rows[127].Name != "a127" || rows[128].Name != "z000" || rows[255].Name != "z127" {
		t.Fatal("complete disjoint union was truncated or reordered")
	}
	for at, row := range rows {
		want := contract.GeneratedPlanningRemoval
		if at >= 128 {
			want = contract.GeneratedPlanningCreate
		}
		if row.Action != want {
			t.Fatal("union action differs", at, row.Action)
		}
	}
	before.Configuration.Entries.Value[0].Name = "changed"
	after.Configuration.Entries.Value[0].Generated.ContentIntent.Value[0] ^= 1
	if rows[0].Name != "a000" || rows[128].Name != "z000" {
		t.Fatal("result retained mutable declaration rows")
	}
	large := strings.Repeat("private-backing", 1000) + "name"
	entry := generatedPlanningUnitEntry(t, large[len(large)-4:])
	row := classifyGeneratedPlanningEntry(&entry, nil)
	if row.Name != "name" || unsafe.StringData(row.Name) == unsafe.StringData(entry.Name) {
		t.Fatal("result retained larger source name backing")
	}
	entryType := reflect.TypeFor[contract.GeneratedPlanningEntry]()
	for at := 0; at < entryType.NumField(); at++ {
		if kind := entryType.Field(at).Type.Kind(); kind == reflect.Slice || kind == reflect.Map || kind == reflect.Pointer {
			t.Fatal("result gained uncharged variable backing", entryType.Field(at).Name)
		}
	}
	validator := NewPublicConfigurationValidator(nil)
	invalid := publicConfigurationFixture(t)
	for at := 0; at < 129; at++ {
		invalid.Entries.Value = append(invalid.Entries.Value, generatedPlanningUnitEntry(t, fmt.Sprintf("n%03d", at)))
	}
	refusal := validator.Validate(context.Background(), invalid)
	if refusal.Valid || len(refusal.Diagnostics) != 1 || refusal.Diagnostics[0].Reason != contract.ReasonLimitExceeded {
		t.Fatal("oversized generated source reached classification", refusal.Diagnostics)
	}
}
