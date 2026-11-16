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

func generatedUnselectedCleanupState(t testing.TB, mode uint8) (*StateSession, generatedAttempt) {
	t.Helper()
	var s *StateSession
	switch mode {
	case 0:
		s = generatedReservationState(t)
	case 1:
		s = generatedReservationState(t, generatedSealedSource(t, "source"))
	case 2:
		s, _, _ = generatedCanonicalState(t, true)
	default:
		t.Fatal("unknown source mode")
	}
	return generatedUnselectedCleanupFromReservation(t, s)
}

func generatedUnselectedCleanupFromReservation(t testing.TB, s *StateSession, packets ...[]byte) (*StateSession, generatedAttempt) {
	t.Helper()
	if len(packets) > 1 {
		t.Fatal("cleanup fixture accepts at most one exact result packet")
	}
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[g.phase.FrontierAttemptID]
	var result []byte
	if len(packets) == 1 {
		result = packets[0]
	} else {
		result = generatedPublicResultFixture(t, a, 1)
	}
	plan := &generatedRecordPlan{expected: a.expected, result: result, phase: contract.GeneratorPhaseIdentity{AfterPhase: 2},
		reference: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}
	rows, err := generatedRecordedRows(g, plan, generatedVectorID(95))
	if err != nil {
		t.Fatal(err)
	}
	var blobs []generatedContentFixtureBlob
	var locations []contract.GeneratorSliceLocation
	for _, key := range []generatedContentKey{{contract.GeneratorContentGraph, g.parent.PlanGraphID}, {contract.GeneratorContentIntent, a.expected.Template.IntentDigest}} {
		location := g.content.locations[key]
		body, err := g.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
		if err != nil {
			t.Fatal(err)
		}
		location.BlobID, location.Offset = contract.Hash(body), 0
		locations = append(locations, location)
		blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
	}
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
	s.support = content.support
	s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
	s.root.Generated.ActiveOwner, s.root.Generated.ActivePhase, s.root.Generated.ActiveGraph = contract.ID{}, contract.ID{}, contract.ID{}
	s.root.Generated.Results = 1
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{a.record.OwnerID})
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPageView{Domain: s.root.Domain, Object: generatedVectorID(96), Index: uint16(len(s.support))}
	var duty contract.GeneratedDutyRecord
	var consumers [][]byte
	for _, row := range rows {
		switch row.Kind {
		case 2, 3, 5, 8:
			continue
		case 10:
			duty, err = contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			continue
		case contract.GeneratorVectorSupportKind:
			v, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			if v.OwnerKind == contract.GeneratorSnapshotOwner || v.OwnerKind == 2 && v.VectorKind == contract.GeneratorVectorConsumers {
				continue
			}
			if v.OwnerKind == 10 && v.VectorKind == contract.GeneratorVectorConsumers {
				consumer, err := contract.InspectGeneratorConsumer(v.Row)
				if err != nil {
					t.Fatal(err)
				}
				if consumer.SubjectKind != 3 || consumer.Purpose != 3 {
					consumers = append(consumers, v.Row)
				}
				continue
			}
		}
		page.Records = append(page.Records, contract.SupportRecordView(row))
	}
	slices.SortFunc(consumers, bytes.Compare)
	descriptor, carriers := generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, consumers)
	duty.Kind, duty.Consumers = contract.GeneratedDutyUnselectedCleanup, descriptor
	body, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	page.Records = append(page.Records, contract.SupportRecordView{Kind: 10, RecordID: duty.DutyID, Body: body})
	for _, row := range carriers {
		page.Records = append(page.Records, contract.SupportRecordView(row))
	}
	s.support = append(s.support, page)
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), g.bundles, locations)
	if !s.indexSelectedMaterials() {
		t.Fatal("cleanup material index")
	}
	a.record.State, a.record.Stage, a.result = contract.GeneratedEffectSucceeded, contract.GeneratedStageTerminal, result
	return s, a
}

// full_only: false
func TestGeneratedReservationPreservesUnselectedCleanup(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	reserved, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
	if err != nil {
		t.Fatal(err)
	}
	s, original := generatedUnselectedCleanupFromReservation(t, reserved.state)
	s.recountChildren()
	prior, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("invalid cleanup predecessor", err)
	}
	if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
		t.Fatal("invalid cleanup predecessor", err)
	}
	input := generatedReservationInputForOperation(t, s, generatedVectorID(98))
	reservation, err := s.deriveGeneratedReservation(context.Background(), input)
	if err != nil {
		t.Fatal("reservation lost an older cleanup", err)
	}
	g, err := reservation.state.selectedGeneratedWork(context.Background())
	if err != nil || g.parent == nil || g.parent.OperationID != input.graph.Header.OperationID ||
		len(g.attempts) != 2 || len(g.bundles) != 2 || len(g.materials) != 2 ||
		g.phase.Attempts.Count != 1 || g.phase.Duties.Count != 1 || g.phase.AcceptedResults.Count != 0 ||
		reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("reservation lost older work or adopted it into its active phase", err)
	}
	for _, key := range []generatedRecordKey{{1, original.material.Core.OperationMaterialID}, {4, original.record.ResultID}, {9, original.record.AttemptID}, {10, original.record.OwnerID}} {
		if !g.hasRecord(key) || !bytes.Equal(prior.records[key].Body, g.records[key].Body) {
			t.Fatal("reservation changed the original cleanup dependency", key.kind)
		}
	}
}

// full_only: false
func TestGeneratedUnselectedCleanupKeepsOriginalResultWithoutActiveParent(t *testing.T) {
	for mode := uint8(0); mode < 3; mode++ {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			s, original := generatedUnselectedCleanupState(t, mode)
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("exact unselected cleanup refused", err)
			}
			retained := g.attempts[original.record.AttemptID]
			if g.parent != nil || g.phase != nil || len(g.attempts) != 1 || len(g.bundles) != 1 ||
				retained.expected != original.expected || !bytes.Equal(retained.result, original.result) ||
				!g.materials[materialIdentity{3, original.material.Core.OperationMaterialID}] || len(g.sources) != 0 || len(g.protected) != 0 {
				t.Fatal("cleanup lost original work or retained completed source preparation")
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr != nil {
				t.Fatal("cleanup lost original work or retained completed source preparation")
			}
			consumers := g.consumers[materialIdentity{3, original.material.Core.OperationMaterialID}]
			if len(consumers) != 1 || consumers[0].Purpose != 4 || consumers[0].SubjectID != original.record.ResultID {
				t.Fatal("cleanup retained selected derivation instead of only its original result consumer")
			}
			if mode == 2 {
				entry := s.valueEntry(s.root.Names[0].Slot)
				key := materialIdentity{1, entry.ValueState}
				if len(g.consumers[key]) != 1 || len(g.canonical) != 1 || !g.materials[key] {
					t.Fatal("cleanup lost its canonical reader union")
				}
			}
			target := contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)}
			coverage, err := s.replacementMaterialRows(t.Context(), 0, 1, target)
			if err != nil || len(coverage) != len(g.materials) {
				t.Fatal("key replacement omitted cleanup material")
			}
			used := make(map[contract.ID]bool)
			if s.retainGeneratedIdentities(t.Context(), used) != nil || !used[original.record.AttemptID] || !used[original.record.ResultID] || !used[original.material.Core.OperationMaterialID] {
				t.Fatal("cleanup identities became reusable")
			}
		})
	}
}

// full_only: false
func TestGeneratedUnselectedCleanupRejectsChangedOwnerAndAttempt(t *testing.T) {
	for name, change := range map[string]func(*contract.GeneratedDutyRecord, *contract.GeneratedAttemptRecord){
		"owner": func(d *contract.GeneratedDutyRecord, _ *contract.GeneratedAttemptRecord) {
			d.OwnerID = generatedVectorID(99)
		},
		"operation": func(d *contract.GeneratedDutyRecord, _ *contract.GeneratedAttemptRecord) {
			d.OriginalOperationID = generatedVectorID(99)
		},
		"attempt": func(d *contract.GeneratedDutyRecord, _ *contract.GeneratedAttemptRecord) {
			d.OriginalAttemptID = generatedVectorID(99)
		},
		"resource": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.ResourceID, a.ResourceID = generatedVectorID(99), generatedVectorID(99)
		},
		"profile": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.ConfigContractID, a.ConfigContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"assumptions": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.ResourceContractID, a.ResourceContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"executor": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.ExecutorID, a.ExecutorID = generatedVectorID(99), generatedVectorID(99)
		},
		"credential route": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.CredentialRouteID, a.CredentialRouteID = generatedVectorID(99), generatedVectorID(99)
		},
		"permission": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.DescriptorID, a.DescriptorID = generatedVectorID(99), generatedVectorID(99)
		},
		"result contract": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.ResultContractID, a.ResultContractID = generatedVectorID(99), generatedVectorID(99)
		},
		"class": func(d *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			d.CompletionClass, a.CompletionClass = 2, 2
		},
		"result": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			a.ResultID = generatedVectorID(99)
		},
		"request": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			a.RequestDigest = generatedVectorID(99)
		},
		"inbox": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			a.InboxID = generatedVectorID(99)
		},
		"transmission": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			a.TransmissionID = generatedVectorID(99)
		},
		"predecessor": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			a.PredecessorAttemptID = generatedVectorID(99)
		},
		"stage": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) {
			a.Stage = contract.GeneratedStageRetainedResult
		},
		"retry": func(_ *contract.GeneratedDutyRecord, a *contract.GeneratedAttemptRecord) { a.RetryUsed = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			s, original := generatedUnselectedCleanupState(t, 0)
			if _, err := s.selectedGeneratedWork(context.Background()); err != nil {
				t.Fatal("starting cleanup fixture is invalid", err)
			}
			var d contract.GeneratedDutyRecord
			var a contract.GeneratedAttemptRecord
			for _, row := range s.supportRecords() {
				var err error
				switch row.Kind {
				case 10:
					d, err = contract.InspectGeneratedDutyRecord(row.Body)
				case 9:
					a, err = contract.InspectGeneratedAttemptRecord(row.Body)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			change(&d, &a)
			body, err := contract.EncodeGeneratedDutyRecord(d)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 10, original.record.OwnerID, body)
			body, err = contract.EncodeGeneratedAttemptRecord(a)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 9, original.record.AttemptID, body)
			s.generatedWork = nil
			if _, err := s.supportDescriptor(); err != nil {
				t.Fatal("changed cleanup fixture is structurally invalid", err)
			}
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("repinned cleanup changed its original accepted relation")
			}
		})
	}
}

// full_only: false
func TestGeneratedUnselectedCleanupRequiresLiveResultAndConsumerCoverage(t *testing.T) {
	for _, missing := range []uint8{1, 4, 6, 9, 10} {
		t.Run(fmt.Sprintf("record%d", missing), func(t *testing.T) {
			s, _ := generatedUnselectedCleanupState(t, 2)
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool { return row.Kind == missing })
			}
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("cleanup silently released a required dependency")
			}
		})
	}
	for _, purpose := range []uint8{0, 3} {
		t.Run(fmt.Sprintf("result purpose%d", purpose), func(t *testing.T) {
			s, _ := generatedUnselectedCleanupState(t, 0)
			var duty contract.GeneratedDutyRecord
			var consumer contract.GeneratorConsumer
			for i := range s.support {
				kept := s.support[i].Records[:0]
				for _, row := range s.support[i].Records {
					if row.Kind == 10 {
						var err error
						duty, err = contract.InspectGeneratedDutyRecord(row.Body)
						if err != nil {
							t.Fatal(err)
						}
					}
					if row.Kind == 14 {
						v, err := contract.InspectGeneratorVectorCarrier(row.Body)
						if err != nil {
							t.Fatal(err)
						}
						if v.OwnerKind == 10 && v.VectorKind == contract.GeneratorVectorConsumers {
							consumer, err = contract.InspectGeneratorConsumer(v.Row)
							if err != nil {
								t.Fatal(err)
							}
							continue
						}
					}
					kept = append(kept, row)
				}
				s.support[i].Records = kept
			}
			var bodies [][]byte
			if purpose != 0 {
				consumer.Purpose = purpose
				body, err := contract.EncodeGeneratorConsumer(consumer)
				if err != nil {
					t.Fatal(err)
				}
				bodies = append(bodies, body)
			}
			descriptor, carriers := generatedVectorRows(t, 10, duty.DutyID, contract.GeneratorVectorConsumers, bodies)
			duty.Consumers = descriptor
			body, err := contract.EncodeGeneratedDutyRecord(duty)
			if err != nil {
				t.Fatal(err)
			}
			generatedReplaceRecord(t, s, 10, duty.DutyID, body)
			for _, row := range carriers {
				s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
			}
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("cleanup dropped its result consumer or restored selected derivation")
			}
		})
	}
	for _, seed := range []bool{false, true} {
		t.Run(fmt.Sprintf("access/seed%t", seed), func(t *testing.T) {
			s, _ := generatedUnselectedCleanupState(t, 2)
			if seed {
				s.access[0].Records = slices.DeleteFunc(slices.Clone(s.access[0].Records), func(row contract.AccessRecord) bool { return row.MaterialKind == contract.OperationSeedMaterialKind })
				s.root.AccessRecordCount--
			} else {
				access := generatedFixtureMaterialAccess(t, s, contract.ValueMaterialKind, generatedVectorID(82))
				access.Wraps = slices.Delete(access.Wraps, 1, 2)
			}
			generatedCommitFixtureAccess(t, s)
			if !s.indexSelectedMaterials() {
				t.Fatal("material index")
			}
			if _, err := format.EncodeRoot(s.root); err != nil {
				t.Fatal("missing-access fixture Root must be valid", err)
			}
			if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.access[0].Records); coverageErr == nil {
				t.Fatal("cleanup lost seed or retained-reader access")
			}
		})
	}
}
