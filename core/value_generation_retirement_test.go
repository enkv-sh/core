package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedDetachedRetirementState(t testing.TB, current string, branch uint8) (*StateSession, contract.GeneratedDutyRecord, contract.GeneratorTarget) {
	t.Helper()
	id := generatedVectorID
	s := generatedSelectedEntryOrigin(t, id(10), id(11), branch)
	selected, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("retirement selected predecessor", err)
	}
	old := *s.pages[0].Slots[0]
	m := old.Generated
	dutyID, err := contract.GeneratorDutyID(s.root.Domain, m.OriginOperationID, m.OriginAttemptID, 2)
	if err != nil {
		t.Fatal(err)
	}
	target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Name: old.Name, IncarnationID: old.Incarnation, Epoch: m.Epoch,
		ResourceID: m.ResourceIncarnationID, ResourceDigest: m.ResourceDigest, ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID,
		OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID, ResultContractID: id(20), CompletionClass: m.CompletionClass}
	body, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, carriers := generatedVectorRows(t, 10, dutyID, contract.GeneratorVectorTargets, [][]byte{body})
	duty := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, LifecycleMode: contract.GeneratorLifecycleManaged, DomainID: s.root.Domain, DutyID: dutyID, OwnerID: dutyID,
		OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID, ResourceID: m.ResourceIncarnationID,
		ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID, ExecutorID: id(40), CredentialRouteID: id(41), DescriptorID: id(42),
		ResultContractID: id(43), Kind: contract.GeneratedDutyRetirement, CompletionClass: m.CompletionClass, Step: 1,
		Status: contract.GeneratedEffectNotStarted, CapacityReservation: generatedCapacityReservationFixture(), Target: descriptor, Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress),
		History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory), Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport),
		Consumers: contract.EmptyGeneratorVector(contract.GeneratorVectorConsumers)}
	body, err = contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPageView{Domain: s.root.Domain, Object: id(44), Index: uint16(len(s.support)),
		Records: []contract.SupportRecordView{{Kind: 10, RecordID: dutyID, Body: body}}}
	for _, row := range carriers {
		page.Records = append(page.Records, contract.SupportRecordView(row))
	}
	s.support = append(s.support, page)
	s.root.Generated.Duties, s.root.Generated.Retiring = 1, 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{dutyID})
	if err != nil {
		t.Fatal(err)
	}
	var successorAccess *contract.AccessRecord
	switch current {
	case "absent":
		s.pages[0], s.root.Names = nil, nil
		s.root.ValueEntryCount, s.root.Generated.GeneratedCurrent = 0, 0
	case "supplied":
		entry := s.pages[0].Slots[0]
		entry.ValueSource, entry.ConfidentialityClass, entry.Generated = contract.Supplied, contract.Plain, contract.GeneratedEntryMetadata{}
		entry.Incarnation, entry.ValueState, entry.ValueBytes = id(50), id(51), []byte("supplied successor")
		entry.ContentLength, entry.RetainedLength = uint32(len(entry.ValueBytes)), uint32(len(entry.ValueBytes))
		s.root.Generated.GeneratedCurrent = 0
	case "generated", "new incarnation":
		incarnation := old.Incarnation
		if current == "new incarnation" {
			incarnation = id(50)
		}
		next := generatedSelectedEntryOrigin(t, id(52), incarnation, 0)
		entry := next.pages[0].Slots[0]
		entry.Generated.RetiringDutyPresent, entry.Generated.RetiringDutyID = 1, dutyID
		s.pages[0] = next.pages[0]
		access := *generatedFixtureMaterialAccess(t, next, contract.ValueMaterialKind, entry.ValueState)
		access.Wraps = slices.Clone(access.Wraps)
		successorAccess = &access
		for _, row := range next.supportRecords() {
			if row.Kind == 13 {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
		}
	default:
		t.Fatal("unknown current member shape")
	}
	// Only the exact old value can become obsolete in this constructor. Its
	// retained canonical/live consumers still require their original access.
	key := materialIdentity{contract.ValueMaterialKind, old.ValueState}
	_, retainedCanonical := selected.canonical[old.ValueState]
	retainedOwner := retainedCanonical || len(selected.consumers[key]) != 0
	var currentNeedsOld bool
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		currentNeedsOld = currentNeedsOld || entry != nil && entry.ConfidentialityClass == contract.Secret && entry.ValueState == old.ValueState
	}
	for i, page := range s.access {
		if page == nil {
			continue
		}
		if !currentNeedsOld && !retainedOwner {
			page.Records = slices.DeleteFunc(slices.Clone(page.Records), func(row contract.AccessRecord) bool { return row.MaterialKind == key.kind && row.MaterialID == key.id })
		}
		if successorAccess != nil {
			for j, row := range page.Records {
				if row.MaterialKind == successorAccess.MaterialKind && row.MaterialID == successorAccess.MaterialID {
					if retainedOwner && row.MaterialContextDigest != successorAccess.MaterialContextDigest {
						t.Fatal("successor reused retained material identity")
					}
					page.Records[j] = *successorAccess
					successorAccess = nil
					break
				}
			}
		}
		if len(page.Records) == 0 {
			s.access[i] = nil
		}
	}
	if successorAccess != nil {
		if s.access[0] == nil {
			s.access[0] = &format.AccessPage{}
		}
		s.access[0].Records = append(s.access[0].Records, *successorAccess)
	}
	generatedRepackSupport(t, s, s.supportRecords(), nil)
	generatedSealSelectedFixture(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("retirement material index")
	}
	return s, duty, target
}

// full_only: false
func TestGeneratedDetachedRetirementRootsOldResourceWithoutPrivateMaterial(t *testing.T) {
	for _, current := range []string{"absent", "supplied", "generated", "new incarnation"} {
		for branch := uint8(0); branch < 5; branch++ {
			t.Run(fmt.Sprintf("%s/branch%d", current, branch), func(t *testing.T) {
				s, duty, target := generatedDetachedRetirementState(t, current, branch)
				g, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal("exact detached retirement refused", err)
				}
				if g.parent != nil || g.phase != nil || len(g.attempts) != 0 || len(g.bundles) != 0 || len(g.sources) != 0 || len(g.consumers) != 0 {
					t.Fatal("detached retirement retained completed operation dependencies")
				}
				for key := range g.materials {
					if key.kind != 1 || key.id != s.pages[0].Slots[0].ValueState {
						t.Fatal("detached retirement retained private operation material")
					}
				}
				used := make(map[contract.ID]bool)
				if s.retainGeneratedIdentities(t.Context(), used) != nil {
					t.Fatal("detached retirement identity inventory")
				}
				for _, id := range []contract.ID{duty.DutyID, duty.OriginalOperationID, duty.OriginalAttemptID, duty.ResourceID,
					duty.ExecutorID, duty.CredentialRouteID, duty.DescriptorID, duty.ResultContractID,
					target.IncarnationID, target.ResourceContractID, target.ResourceDigest} {
					if !used[id] {
						t.Fatal("detached retirement made a retained identity reusable", id)
					}
				}
			})
		}
	}
}

func generatedReplaceRetirementTarget(t testing.TB, s *StateSession, duty contract.GeneratedDutyRecord, target contract.GeneratorTarget, refresh ...bool) {
	t.Helper()
	body, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, carriers := generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorTargets, [][]byte{body})
	duty.Target = descriptor
	for i := range s.support {
		rows := s.support[i].Records[:0]
		for _, row := range s.support[i].Records {
			if row.Kind == 14 {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if v.OwnerKind == 10 && v.OwnerID == duty.DutyID && v.VectorKind == contract.GeneratorVectorTargets {
					continue
				}
			}
			rows = append(rows, row)
		}
		s.support[i].Records = rows
	}
	for _, row := range carriers {
		s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
	}
	body, err = contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, 10, duty.DutyID, body)
	if len(refresh) == 0 || refresh[0] {
		generatedRefreshSupport(t, s)
	} else {
		s.generatedWork = nil
	}
}

// full_only: false
func TestGeneratedDetachedRetirementChecksExactTargetAfterDescriptorRebinding(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratedDutyRecord, *contract.GeneratorTarget){
		"name": func(_ *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) { v.Name = "another" },
		"incarnation": func(_ *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			v.IncarnationID = generatedVectorID(98)
		},
		"epoch": func(_ *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) { v.Epoch++ },
		"target resource contract": func(_ *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			v.ResourceContractID = generatedVectorID(98)
		},
		"resource digest": func(_ *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			v.ResourceDigest = generatedVectorID(98)
		},
		"create result contract": func(_ *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			v.ResultContractID = generatedVectorID(98)
		},
		"operation": func(d *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			d.OriginalOperationID, v.OriginalOperationID = generatedVectorID(98), generatedVectorID(98)
		},
		"attempt": func(d *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			d.OriginalAttemptID, v.OriginalAttemptID = generatedVectorID(98), generatedVectorID(98)
		},
		"resource": func(d *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			d.ResourceID, v.ResourceID = generatedVectorID(98), generatedVectorID(98)
		},
		"profile": func(d *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			d.ConfigContractID, v.ConfigContractID = generatedVectorID(98), generatedVectorID(98)
		},
		"assumption": func(d *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			d.ResourceContractID, v.ResourceContractID = generatedVectorID(98), generatedVectorID(98)
		},
		"completion class": func(d *contract.GeneratedDutyRecord, v *contract.GeneratorTarget) {
			d.CompletionClass, v.CompletionClass = contract.GeneratedCompletionConfirmed, contract.GeneratedCompletionConfirmed
		},
		"owner": func(d *contract.GeneratedDutyRecord, _ *contract.GeneratorTarget) { d.OwnerID = generatedVectorID(98) },
		"step":  func(d *contract.GeneratedDutyRecord, _ *contract.GeneratorTarget) { d.Step++ },
		"unknown without deleting attempt": func(d *contract.GeneratedDutyRecord, _ *contract.GeneratorTarget) {
			d.Status = contract.GeneratedEffectUnknown
		},
		"completion without evidence": func(d *contract.GeneratedDutyRecord, _ *contract.GeneratorTarget) {
			d.Status = contract.GeneratedEffectSucceeded
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, duty, target := generatedDetachedRetirementState(t, "absent", 0)
			change(&duty, &target)
			generatedReplaceRetirementTarget(t, s, duty, target, false)
			if generatedIndexRejectsAlteredSupport(t, s) {
				return
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("changed retirement accepted after rebinding its stored target")
			}
		})
	}
}

// full_only: false
func TestGeneratedRetirementRejectsPhysicalAliasAcrossNamesAndProfiles(t *testing.T) {
	s, _, target := generatedDetachedRetirementState(t, "absent", 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture := *g
	builder := &generatedSelectionBuilder{facts: &fixture, vectors: newGeneratedVectorValidation(&fixture.vectors)}
	alias := contract.ValueEntry{Name: "different", ValueSource: contract.Generated,
		Generated: contract.GeneratedEntryMetadata{Schema: contract.GeneratedEntryMetadataSchema, LifecycleMode: contract.GeneratorLifecycleManaged, ResourceContractID: target.ResourceContractID, ResourceDigest: target.ResourceDigest,
			ConfigContractID: generatedVectorID(98), ResourceIncarnationID: generatedVectorID(97),
			OriginOperationID: generatedVectorID(96), OriginAttemptID: generatedVectorID(95)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	if err := builder.validateResourceCoordinates(s.supportRecords(), []contract.ValueEntry{alias}); err == nil {
		t.Fatal("same semantic resource hid behind another name and configuration")
	}
	duplicate := alias
	duplicate.Name = "same origin, another name"
	duplicate.Generated.ResourceIncarnationID = target.ResourceID
	duplicate.Generated.OriginOperationID = target.OriginalOperationID
	duplicate.Generated.OriginAttemptID = target.OriginalAttemptID
	second := duplicate
	second.Name = "second current name"
	if err := builder.validateResourceCoordinates(s.supportRecords(), []contract.ValueEntry{duplicate, second}); err == nil {
		t.Fatal("two current names shared one physical coordinate and origin")
	}
	alias.Generated.ResourceDigest = generatedVectorID(94)
	if err := builder.validateResourceCoordinates(s.supportRecords(), []contract.ValueEntry{alias}); err != nil {
		t.Fatal("different resource digest was mistaken for the same resource", err)
	}
}

// full_only: false
func TestGeneratedSelectedRetirementRejectsCrossNamePhysicalAlias(t *testing.T) {
	for _, test := range []struct {
		name    string
		account contract.ID
		token   contract.ID
		refuse  bool
	}{
		{"same account and token", generatedVectorID(12), generatedVectorID(10), true},
		{"different account", generatedVectorID(94), generatedVectorID(10), false},
		{"different token", generatedVectorID(12), generatedVectorID(94), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, _, _ := generatedDetachedRetirementState(t, "absent", 0)
			other := generatedSelectedEntryOriginWithIntent(t, generatedVectorID(52), generatedVectorID(53), 0,
				"other name", generatedVectorID(98), test.account, test.token, generatedVectorID(21), generatedVectorID(99), []byte("{}"))
			s.pages, s.root.Names = other.pages, other.root.Names
			s.access = other.access
			s.root.ValueEntryCount, s.root.Generated.GeneratedCurrent = 1, 1
			rows, otherRows := s.supportRecords(), other.supportRecords()
			locations := append(generatedFixtureSliceLocations(t, rows), generatedFixtureSliceLocations(t, otherRows)...)
			locations, err := generatedUniqueLocations(locations)
			if err != nil {
				t.Fatal("combined original intents", err)
			}
			rows = slices.DeleteFunc(rows, func(row contract.SupportRecord) bool {
				if row.Kind != contract.GeneratorVectorSupportKind {
					return false
				}
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				return carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
			})
			for _, row := range otherRows {
				if row.Kind == contract.GeneratedCreateEvidenceSupportKind || row.Kind == contract.GeneratedFragmentSupportKind {
					rows = append(rows, row)
				}
			}
			var bodies [][]byte
			for _, location := range locations {
				body, err := contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			directory, carriers := generatedVectorRows(t, contract.GeneratorSnapshotOwner, s.root.Snapshot, contract.GeneratorVectorSlices, bodies)
			rows = append(rows, carriers...)
			s.root.Generated.Slices = directory
			generatedRepackSupportAtLocations(t, s, rows, nil, locations)
			generatedSealSelectedFixture(t, s)
			if !s.indexSelectedMaterials() {
				t.Fatal("physical alias fixture material index")
			}
			// Force the same cold selection path used after an authenticated reopen.
			s.generatedWork = nil
			selected, err := s.selectedGeneratedWork(context.Background())
			if test.refuse && (err == nil || selected != nil) {
				t.Fatal("selected state accepted a second resource at the retirement target coordinate")
			}
			if !test.refuse && (err != nil || selected == nil) {
				t.Fatal("distinct physical coordinate was refused", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedLateHazardEvidenceCannotAliasRetirementTarget(t *testing.T) {
	s, _, retired := generatedDetachedRetirementState(t, "absent", 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fixture := *g
	builder := &generatedSelectionBuilder{facts: &fixture, vectors: newGeneratedVectorValidation(&fixture.vectors)}
	late, _, hazard := generatedCreateHazardState(t, 0, 1)
	var target contract.GeneratorTarget
	for _, row := range late.supportRecords() {
		if row.Kind != 14 {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		if carrier.OwnerKind == 11 && carrier.OwnerID == hazard.HazardID && carrier.VectorKind == contract.GeneratorVectorTargets {
			target, err = contract.InspectGeneratorTarget(carrier.Row)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if target.ResourceID.IsZero() || target.ResourceID == retired.ResourceID {
		t.Fatal("late target did not describe another resource")
	}
	target.ResourceContractID, target.ResourceDigest = retired.ResourceContractID, retired.ResourceDigest
	body, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, carriers := generatedVectorRows(t, 11, hazard.HazardID, contract.GeneratorVectorTargets, [][]byte{body})
	hazard.Target = descriptor
	body, err = contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	rows := append(s.supportRecords(), contract.SupportRecord{Kind: 11, RecordID: hazard.HazardID, Body: body})
	rows = append(rows, carriers...)
	fixture.vectors, err = newGeneratedVectorSet(s.root.Domain, rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := builder.validateResourceCoordinates(rows, nil); err == nil {
		t.Fatal("late conflicting Hazard evidence made retirement deletion safe")
	}
	target.ResourceDigest = generatedVectorID(94)
	body, err = contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, carriers = generatedVectorRows(t, 11, hazard.HazardID, contract.GeneratorVectorTargets, [][]byte{body})
	hazard.Target = descriptor
	body, err = contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal(err)
	}
	rows[len(rows)-2] = contract.SupportRecord{Kind: 11, RecordID: hazard.HazardID, Body: body}
	rows[len(rows)-1] = carriers[0]
	fixture.vectors, err = newGeneratedVectorSet(s.root.Domain, rows)
	if err != nil || builder.validateResourceCoordinates(rows, nil) != nil {
		t.Fatal("different-account late evidence was treated as the same provider coordinate", err)
	}
}

// full_only: false
func TestGeneratedDetachedRetirementChecksLiveNameAndPointer(t *testing.T) {
	for name, change := range map[string]func(*StateSession, contract.GeneratedDutyRecord){
		"missing pointer": func(s *StateSession, _ contract.GeneratedDutyRecord) {
			s.pages[0].Slots[0].Generated.RetiringDutyPresent, s.pages[0].Slots[0].Generated.RetiringDutyID = 0, contract.ID{}
		},
		"wrong pointer": func(s *StateSession, _ contract.GeneratedDutyRecord) {
			s.pages[0].Slots[0].Generated.RetiringDutyID = generatedVectorID(98)
		},
		"wrong retiring count": func(s *StateSession, _ contract.GeneratedDutyRecord) { s.root.Generated.Retiring = 0 },
		"wrong duty count":     func(s *StateSession, _ contract.GeneratedDutyRecord) { s.root.Generated.Duties = 0 },
		"missing live owner": func(s *StateSession, _ contract.GeneratedDutyRecord) {
			s.root.Generated.LiveOwners = contract.EmptyGeneratorIndexes()[1]
		},
		"missing evidence": func(s *StateSession, d contract.GeneratedDutyRecord) {
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool {
					if row.Kind != 13 {
						return false
					}
					evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
					if err != nil {
						t.Fatal(err)
					}
					return core.OperationID == d.OriginalOperationID
				})
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, duty, _ := generatedDetachedRetirementState(t, "generated", 0)
			change(s, duty)
			// Missing evidence can leave an empty physical page; it is removed
			// here so rejection comes from the live relation, not page syntax.
			s.support = slices.DeleteFunc(s.support, func(p format.RequiredSupportPageView) bool { return len(p.Records) == 0 })
			for i := range s.support {
				s.support[i].Index = uint16(i)
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("incomplete retirement relation accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedDetachedRetirementRejectsTwoGenerationsOfOneName(t *testing.T) {
	s, first, _ := generatedDetachedRetirementState(t, "absent", 0)
	other, second, _ := generatedDetachedRetirementState(t, "absent", 1)
	for _, row := range other.supportRecords() {
		if row.Kind == 10 || row.Kind == 13 || row.Kind == 14 {
			if row.Kind == 14 {
				v, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if v.OwnerKind != 10 {
					continue
				}
			}
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
		}
	}
	s.root.Generated.Duties, s.root.Generated.Retiring = 2, 2
	owners := []contract.ID{first.DutyID, second.DutyID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var err error
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshSupport(t, s)
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("two old generations retired under one member name")
	}
}

// full_only: false
func TestGeneratedDetachedRetirementCannotTargetCurrentGeneration(t *testing.T) {
	for _, reusedToken := range []bool{false, true} {
		t.Run(fmt.Sprintf("reused-token-%t", reusedToken), func(t *testing.T) {
			s, duty, target := generatedDetachedRetirementState(t, "absent", 0)
			current := generatedSelectedEntryState(t)
			if reusedToken {
				current = generatedSelectedEntryOrigin(t, generatedVectorID(52), generatedVectorID(11), 0)
				entry := current.pages[0].Slots[0]
				entry.Generated.ResourceDigest = target.ResourceDigest
				for _, row := range current.supportRecords() {
					if row.Kind != 13 {
						continue
					}
					v, err := contract.InspectGeneratedCreateEvidence(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					evidence := contract.GeneratedCreateEvidence(v)
					facts, err := contract.DecodeGeneratorSafeFacts(evidence.SafeFacts)
					if err != nil {
						t.Fatal(err)
					}
					original, err := s.selectedGeneratedWork(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					originalFacts, err := original.createTargetEvidence(t.Context(), target)
					if err != nil {
						t.Fatal(err)
					}
					facts.Target, facts.ResourceData = bytes.Clone(originalFacts.Target), bytes.Clone(originalFacts.ResourceData)
					evidence.SafeFacts, err = contract.EncodeGeneratorSafeFacts(facts)
					if err != nil {
						t.Fatal(err)
					}
					core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
					if err != nil {
						t.Fatal(err)
					}
					core.SafeFactsDigest, err = contract.GeneratorSafeFactsDigest(facts)
					if err != nil {
						t.Fatal(err)
					}
					evidence.ResultCore, err = contract.EncodeGeneratedResultCore(core)
					if err != nil {
						t.Fatal(err)
					}
					entry.Generated.CreateEvidence, err = contract.GeneratedCreateEvidenceDescriptor(evidence)
					intent := generatedFixtureCanonicalIntent(t, []byte("{}"), generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged,
						ConfigContractID: generatedVectorID(9), ResourceContractID: generatedVectorID(7)})
					if err != nil || contract.ValidateGeneratedValueEntryEvidence(s.root.Domain, *entry, evidence, intent) != nil {
						t.Fatal("reused token must reach selected target correspondence", err)
					}
					body, err := contract.EncodeGeneratedCreateEvidence(evidence)
					if err != nil {
						t.Fatal(err)
					}
					s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView{Kind: 13, RecordID: row.RecordID, Body: body})
				}
			}
			s.pages, s.root.Names = current.pages, current.root.Names
			s.root.ValueEntryCount, s.root.Generated.GeneratedCurrent = 1, 1
			s.pages[0].Slots[0].Generated.RetiringDutyPresent, s.pages[0].Slots[0].Generated.RetiringDutyID = 1, duty.DutyID
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("retirement targeted the still-current generation")
			}
		})
	}
}

func generatedActiveRetirementState(t testing.TB) (*StateSession, contract.GeneratedDutyRecord) {
	t.Helper()
	s := generatedReservationState(t)
	active, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	old, duty, _ := generatedDetachedRetirementState(t, "absent", 0)
	if old.root.OutputConfiguration != s.root.OutputConfiguration {
		t.Fatal("merged retirement changed selected configuration")
	}
	configuration := make(map[contract.ID]contract.SupportRecord)
	for _, row := range s.supportRecords() {
		if row.Kind == contract.OutputConfigurationSliceSupportKind {
			configuration[row.RecordID] = row
		}
	}
	if len(configuration) != int(s.root.OutputConfiguration.SliceCount) {
		t.Fatal("merged retirement selected configuration rows")
	}
	var locations []contract.GeneratorSliceLocation
	var rows []contract.SupportRecord
	owners := []contract.ID{s.root.Generated.ActiveOwner}
	for _, state := range []*StateSession{s, old} {
		selected, err := format.ResolveGeneratedSlices(state.root.Domain, state.root.Snapshot, state.root.Generated, state.support)
		if err != nil {
			t.Fatal(err)
		}
		locations = append(locations, selected...)
		for _, row := range state.supportRecords() {
			if state == old && row.Kind == contract.OutputConfigurationSliceSupportKind {
				selected, ok := configuration[row.RecordID]
				if !ok || !bytes.Equal(selected.Body, row.Body) {
					t.Fatal("merged retirement substituted selected configuration row")
				}
				continue
			}
			_, directory, err := snapshotSliceRecord(row, state.root.Domain, state.root.Snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if !directory {
				rows = append(rows, row)
			}
			if row.Kind == 10 {
				owners = append(owners, row.RecordID)
			}
		}
	}
	slices.SortFunc(locations, func(a, b contract.GeneratorSliceLocation) int {
		if a.ContentKind != b.ContentKind {
			return int(a.ContentKind) - int(b.ContentKind)
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	var bodies [][]byte
	for _, location := range locations {
		body, err := contract.EncodeGeneratorSliceLocation(location)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	directory, carriers := generatedVectorRows(t, contract.GeneratorSnapshotOwner, s.root.Snapshot, contract.GeneratorVectorSlices, bodies)
	rows = append(rows, carriers...)
	groups, err := generatedReservationGroups(rows, locations, active.bundles)
	if err != nil {
		t.Fatal(err)
	}
	packed, err := format.PackRequiredSupportRows(s.root.Domain, groups, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.support = nil
	var pages []format.RequiredSupportPage
	for i, rows := range packed {
		page := format.RequiredSupportPage{Domain: s.root.Domain, Object: generatedVectorID(byte(80 + i)), Index: uint16(i), Records: rows}
		pages = append(pages, page)
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		view, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		s.support = append(s.support, view)
	}
	s.root.Generated.Fragments, err = generatedFragmentDirectory(pages)
	if err != nil {
		t.Fatal(err)
	}
	s.root.Generated.Slices, s.root.Generated.Duties, s.root.Generated.Retiring = directory, 2, 1
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedSealSelectedFixture(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil || g.parent == nil || len(g.materials) != 1 || len(g.attempts) != 1 || !g.hasRecord(generatedRecordKey{10, duty.DutyID}) {
		t.Fatal("active reservation lost or adopted unrelated retirement", err)
	}
	return s, duty
}

// full_only: false
func TestGeneratedDetachedRetirementRemainsSeparateFromActivePhase(t *testing.T) {
	s, _ := generatedActiveRetirementState(t)
	// Recompute the phase's set with both Duties. Its descriptor is valid,
	// but the older retirement is not owned by this create graph.
	generatedRefreshPhaseSets(t, s)
	if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
		t.Fatal("active phase claimed an unrelated older retirement")
	}
}

// full_only: false
func TestGeneratedRecordingPreservesOlderRetirementOutsidePhase(t *testing.T) {
	for _, disposition := range []uint8{1, 2} {
		t.Run(fmt.Sprint(disposition), func(t *testing.T) {
			s, retirement := generatedActiveRetirementState(t)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			a := g.attempts[g.phase.FrontierAttemptID]
			x := a.expected.Template
			result := generatedPublicResultFixture(t, a, disposition)
			phaseID := generatedVectorID(95)
			plan := &generatedRecordPlan{expected: a.expected, result: result, phase: contract.GeneratorPhaseIdentity{AfterPhase: g.phase.Phase + 1},
				reference: contract.GeneratorResultReference{Schema: 1, ResultID: x.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}
			rows, err := generatedRecordedRows(g, plan, phaseID)
			if err != nil {
				t.Fatal(err)
			}
			changed := make(map[generatedRecordKey]contract.SupportRecord)
			for _, row := range rows {
				changed[generatedRecordKey{row.Kind, row.RecordID}] = row
			}
			retiring := generatedRecordKey{10, retirement.DutyID}
			if !bytes.Equal(changed[retiring].Body, g.records[retiring].Body) {
				t.Fatal("recording changed the unrelated retirement obligation")
			}
			for i := range s.support {
				for j, old := range s.support[i].Records {
					key := generatedRecordKey{old.Kind, old.RecordID}
					s.support[i].Records[j] = contract.SupportRecordView(changed[key])
					delete(changed, key)
				}
			}
			page := format.RequiredSupportPageView{Domain: s.root.Domain, Object: generatedVectorID(96), Index: uint16(len(s.support))}
			for _, row := range rows {
				if _, present := changed[generatedRecordKey{row.Kind, row.RecordID}]; present {
					page.Records = append(page.Records, contract.SupportRecordView(row))
				}
			}
			s.support = append(s.support, page)
			s.root.Generated.ActivePhase, s.root.Generated.Results = phaseID, 1
			generatedRefreshSupport(t, s)
			after, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("recording included an older retirement in the active phase", err)
			}
			if after.phase.Duties.Count != 1 || s.root.Generated.Duties != 2 || s.root.Generated.Retiring != 1 ||
				!after.hasRecord(retiring) || !bytes.Equal(after.attempts[x.AttemptID].result, result) {
				t.Fatal("recording lost active or detached obligations")
			}
		})
	}
}
