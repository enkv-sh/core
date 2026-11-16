package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedInboxReleaseState(t testing.TB, mode, state uint8) (*StateSession, generatedAttempt, contract.PendingInboxReleaseRecord) {
	t.Helper()
	s, original := generatedUnselectedCleanupState(t, mode)
	return generatedInboxReleaseFromCleanup(t, s, original, state)
}

func generatedInboxReleaseFromCleanup(t testing.TB, s *StateSession, original generatedAttempt, state uint8) (*StateSession, generatedAttempt, contract.PendingInboxReleaseRecord) {
	t.Helper()
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a := g.attempts[original.record.AttemptID]
	dutyRow, ok := g.records[generatedRecordKey{kind: 10, id: a.record.OwnerID}]
	if !ok {
		t.Fatal("release fixture missing source Duty")
	}
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	if err != nil {
		t.Fatal(err)
	}
	location := g.content.locations[generatedContentKey{contract.GeneratorContentGraph, a.expected.Plan.PlanGraphID}]
	graph, err := g.readSelectedSlice(t.Context(), contract.GeneratorContentGraph, location.ContentID, location.Length)
	if err != nil {
		t.Fatal(err)
	}
	location.BlobID, location.Offset = contract.Hash(graph), 0
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, []generatedContentFixtureBlob{{location.BlobID, graph}}, []contract.GeneratorSliceLocation{location})
	s.support = content.support
	s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
	s.root.Generated.Duties, s.root.Generated.Results, s.root.Generated.Materials, s.root.Generated.PendingReleases = 0, 0, 0, 1
	release := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: a.record.DomainID, InboxID: a.record.InboxID,
		OriginalResultID: a.record.ResultID, SelectedHandoffDigest: contract.Hash(a.result), HandoffRevisionID: generatedVectorID(97),
		CapacityReservation: duty.CapacityReservation, ObjectLength: uint32(len(a.result)), State: state}
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{release.InboxID})
	if err != nil {
		t.Fatal(err)
	}
	a.record.Facts = contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)
	body, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	page := format.RequiredSupportPageView{Domain: s.root.Domain, Object: generatedVectorID(96), Index: uint16(len(s.support)),
		Records: []contract.SupportRecordView{{Kind: 9, RecordID: a.record.AttemptID, Body: body}}}
	body, err = contract.EncodePendingInboxReleaseRecord(release)
	if err != nil {
		t.Fatal(err)
	}
	page.Records = append(page.Records, contract.SupportRecordView{Kind: 12, RecordID: release.InboxID, Body: body})
	s.support = append(s.support, page)
	generatedRefreshSupport(t, s)
	if !s.indexSelectedMaterials() {
		t.Fatal("current-only reader index")
	}
	s.root.AccessRecordCount = 0
	for _, page := range s.access {
		if page == nil {
			continue
		}
		page.Records = slices.DeleteFunc(page.Records, func(row contract.AccessRecord) bool { return row.MaterialKind == 3 })
		for i := range page.Records {
			row := &page.Records[i]
			row.Wraps = slices.DeleteFunc(row.Wraps, func(w contract.WrapRow) bool {
				return w.SubjectKind == 1 && !slices.Contains(s.valueReaders[row.MaterialID], w.SubjectID)
			})
		}
		s.root.AccessRecordCount += uint32(len(page.Records))
	}
	if s.root.OutputConfiguration.SliceCount != 0 {
		s.root.CurrentAccess.Core.AccessPageRefs = nil
		var remaining []contract.AccessRecord
		for i, page := range s.access {
			if page == nil || len(page.Records) == 0 {
				s.access[i] = nil
				continue
			}
			body, err := format.EncodeAccessPage(*page)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := format.Reference(format.AccessKind, page.Domain, page.Object, uint16(i), body)
			if err != nil {
				t.Fatal(err)
			}
			s.root.CurrentAccess.Core.AccessPageRefs = append(s.root.CurrentAccess.Core.AccessPageRefs, ref)
			remaining = append(remaining, page.Records...)
		}
		s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, remaining)
		if err != nil {
			t.Fatal(err)
		}
		s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
		if err != nil {
			t.Fatal(err)
		}
	}
	s.recountChildren()
	if !s.indexSelectedMaterials() {
		t.Fatal("release access index")
	}
	return s, a, release
}

// full_only: false
func TestGeneratedInboxReleaseRetainsMappingWithoutAdoptionOrSeed(t *testing.T) {
	for mode := uint8(0); mode < 3; mode++ {
		for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
			t.Run(fmt.Sprintf("source%d/state%d", mode, state), func(t *testing.T) {
				s, a, release := generatedInboxReleaseState(t, mode, state)
				g, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal("release-only dependency refused", err)
				}
				if g.parent != nil || g.phase != nil || len(g.attempts) != 0 || len(g.bundles) != 1 || len(g.consumers) != 0 ||
					len(g.sources) != 0 || len(g.protected) != 0 || g.materials[materialIdentity{3, a.material.Core.OperationMaterialID}] ||
					!g.hasRecord(generatedRecordKey{9, a.record.AttemptID}) || !g.hasRecord(generatedRecordKey{12, release.InboxID}) {
					t.Fatal("release dropped its mapping or retained completed private work")
				}
				if _, coverageErr := s.validateGeneratedCoverage(t.Context(), s.generatedCoverageRecords()); coverageErr != nil {
					t.Fatal("release dropped its mapping or retained completed private work")
				}
				body, err := contract.EncodePendingInboxReleaseRecord(release)
				if err != nil || !bytes.Equal(body, g.records[generatedRecordKey{12, release.InboxID}].Body) {
					t.Fatal("release changed the frozen object or handoff")
				}
				coverage, err := s.replacementMaterialRows(t.Context(), 0, 1, contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: generatedPublicBinding(t, 95)})
				if err != nil || len(coverage) != int(s.root.AccessRecordCount) {
					t.Fatal("release retained a seed in key-replacement coverage")
				}
				if mode == 2 {
					_, _, access, ok := s.selectedValue(s.root.Names[0].Slot)
					if !ok || len(access.Wraps) != 65 || len(g.canonical) != 0 || len(g.materials) != 1 {
						t.Fatal("release changed current value access or kept retired consumer wraps")
					}
				}
				used := make(map[contract.ID]bool)
				if s.retainGeneratedIdentities(t.Context(), used) != nil || !used[a.record.AttemptID] || !used[a.record.ResultID] || !used[release.InboxID] || !used[release.HandoffRevisionID] {
					t.Fatal("release made an original coordinate or handoff revision reusable")
				}
			})
		}
	}
}

func generatedInboxReleaseTemplateState(t testing.TB, action, branch, state uint8) (*StateSession, generatedAttempt, contract.PendingInboxReleaseRecord) {
	t.Helper()
	s, a, release := generatedInboxReleaseState(t, 0, state)
	return generatedInboxReleaseWithTemplate(t, s, a, release, action, branch)
}

func generatedInboxReleaseWithTemplate(t testing.TB, s *StateSession, a generatedAttempt, release contract.PendingInboxReleaseRecord, action, branch uint8) (*StateSession, generatedAttempt, contract.PendingInboxReleaseRecord) {
	t.Helper()
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bundle := g.bundles[0]
	x := bundle.Lineages[0].Templates[branch]
	if action == 2 {
		create := x
		index := slices.IndexFunc(bundle.Lineages, func(lineage contract.GeneratorLineageTemplate) bool {
			return lineage.Purpose == 3 && lineage.Templates[0].TargetSourceID == create.ResultID
		})
		if index < 0 {
			t.Fatal("cleanup template absent")
		}
		x = bundle.Lineages[index].Templates[0]
		a.expected.TargetResourceDigest = generatedFixtureResourceDigest(x.ResourceContractID, generatedVectorID(97))
	}
	var ok bool
	x, a.expected.Use, ok = generatedTemplate(bundle, x.AttemptID)
	if !ok || x.Action != action {
		t.Fatal("release template differs")
	}
	a.expected.Template = x
	a.record.LineageID, a.record.AttemptID, a.record.PredecessorAttemptID = x.LineageID, x.AttemptID, x.PredecessorAttemptID
	a.record.TemplateDigest, err = contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	a.record.OwnerID, a.record.ResourceID = x.DutyID, x.ResourceIncarnationID
	a.record.TransmissionID, a.record.ResultID, a.record.InboxID = x.TransmissionID, x.ResultID, x.InboxID
	a.record.ConfigContractID, a.record.ResourceContractID, a.record.ExecutorID = x.ConfigContractID, x.ResourceContractID, x.ExecutorID
	a.record.CredentialRouteID, a.record.DescriptorID, a.record.ResultContractID = x.CredentialRouteID, x.DescriptorID, x.ResultContractID
	a.record.CompletionClass = x.CompletionClass
	disposition := uint8(1)
	if action == 2 {
		disposition = contract.GeneratorDispositionRetirementAcknowledged
		facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: action, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID, Disposition: disposition, RequestDigest: a.expected.RequestDigest, IntentDigest: x.IntentDigest, Target: []byte("fixture-target"), ResourceData: bytes.Repeat([]byte{97}, 32)}
		a.result = generatedPublicResultWithFacts(t, a, facts, 0)
	} else {
		a.result = generatedPublicResultFixture(t, a, disposition)
	}
	release.InboxID, release.OriginalResultID = x.InboxID, x.ResultID
	release.SelectedHandoffDigest, release.ObjectLength = contract.Hash(a.result), uint32(len(a.result))
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a.record)
	if err != nil {
		t.Fatal(err)
	}
	releaseBody, err := contract.EncodePendingInboxReleaseRecord(release)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.support {
		for j := range s.support[i].Records {
			row := &s.support[i].Records[j]
			switch row.Kind {
			case 9:
				*row = contract.SupportRecordView{Kind: 9, RecordID: x.AttemptID, Body: attemptBody}
			case 12:
				*row = contract.SupportRecordView{Kind: 12, RecordID: x.InboxID, Body: releaseBody}
			}
		}
	}
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{x.InboxID})
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshSupport(t, s)
	return s, a, release
}

// full_only: false
func TestGeneratedInboxReleasePreservesEveryOriginalTemplate(t *testing.T) {
	for _, action := range []uint8{1, 2} {
		for branch := uint8(0); branch < 5; branch++ {
			for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
				t.Run(fmt.Sprintf("action%d/create-branch%d/state%d", action, branch, state), func(t *testing.T) {
					s, a, r := generatedInboxReleaseTemplateState(t, action, branch, state)
					g, err := s.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal("original template release refused", err)
					}
					if len(g.attempts) != 0 || len(g.materials) != 0 || len(g.consumers) != 0 || len(g.bundles) != 1 ||
						!g.hasRecord(generatedRecordKey{9, a.record.AttemptID}) || !g.hasRecord(generatedRecordKey{12, r.InboxID}) {
						t.Fatal("release acquired adoption or lost its exact mapping")
					}
					used := make(map[contract.ID]bool)
					if s.retainGeneratedIdentities(t.Context(), used) != nil || !used[a.record.AttemptID] || !used[a.record.ResultID] || !used[a.record.InboxID] ||
						!a.record.PredecessorAttemptID.IsZero() && !used[a.record.PredecessorAttemptID] {
						t.Fatal("release made an original identity reusable")
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedDeleteReleaseKeepsAnotherOriginalResultConsumer(t *testing.T) {
	s, a := generatedUnselectedCleanupState(t, 0)
	before, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	a = before.attempts[a.record.AttemptID]
	released, deleted, r := generatedInboxReleaseTemplateState(t, 2, 0, contract.GeneratedReleaseUnknown)
	for _, row := range released.supportRecords() {
		if row.Kind == 9 || row.Kind == 12 {
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
		}
	}
	s.root.Generated.Attempts++
	s.root.Generated.PendingReleases++
	owners := []contract.ID{a.record.OwnerID, r.InboxID}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
	if err != nil {
		t.Fatal(err)
	}
	generatedRefreshSupport(t, s, before.bundles...)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("release discarded another original consumer", err)
	}
	if len(g.attempts) != 1 || g.attempts[a.record.AttemptID].record != a.record || len(g.bundles) != 1 ||
		!g.materials[materialIdentity{3, a.material.Core.OperationMaterialID}] ||
		!g.hasRecord(generatedRecordKey{9, deleted.record.AttemptID}) || !g.hasRecord(generatedRecordKey{12, r.InboxID}) {
		t.Fatal("release changed the other consumer or became adoptable")
	}
	if _, adoptable := g.attempts[deleted.record.AttemptID]; adoptable || !bytes.Equal(g.attempts[a.record.AttemptID].result, a.result) {
		t.Fatal("release changed the remaining original result")
	}
}

// full_only: false
func TestGeneratedReservationPreservesPendingInboxRelease(t *testing.T) {
	for _, template := range []struct{ action, branch uint8 }{{1, 0}, {1, 2}, {2, 2}} {
		for _, state := range []uint8{contract.GeneratedReleasePending, contract.GeneratedReleaseUnknown} {
			t.Run(fmt.Sprintf("action%d/branch%d/state%d", template.action, template.branch, state), func(t *testing.T) {
				before := generatedEmptyPredecessor(t)
				reserved, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputFixture(t, before))
				if err != nil {
					t.Fatal(err)
				}
				s, original := generatedUnselectedCleanupFromReservation(t, reserved.state)
				s, original, release := generatedInboxReleaseFromCleanup(t, s, original, state)
				s, original, release = generatedInboxReleaseWithTemplate(t, s, original, release, template.action, template.branch)
				s.access = [contract.MaxChildPages]*format.AccessPage{}
				s.root.CurrentAccess.Core.AccessPageRefs = nil
				s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, nil)
				if err != nil {
					t.Fatal(err)
				}
				s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
				if err != nil {
					t.Fatal(err)
				}
				s.recountChildren()
				prior, err := s.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal("invalid release predecessor", err)
				}
				if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
					t.Fatal("invalid release predecessor", err)
				}
				input := generatedReservationInputForOperation(t, s, generatedVectorID(98))
				reservation, err := s.deriveGeneratedReservation(context.Background(), input)
				if err != nil {
					t.Fatal("new reservation lost the pending release", err)
				}
				g, err := reservation.state.selectedGeneratedWork(context.Background())
				if err != nil || len(g.attempts) != 1 || len(g.bundles) != 2 || len(g.materials) != 1 ||
					g.phase.PendingReleases.Count != 0 || g.phase.Attempts.Count != 1 || reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
					t.Fatal("new reservation adopted the release or lost its mapping", err)
				}
				for _, key := range []generatedRecordKey{{9, original.record.AttemptID}, {12, release.InboxID}} {
					if !g.hasRecord(key) || !bytes.Equal(g.records[key].Body, prior.records[key].Body) {
						t.Fatal("new reservation changed the original release", key.kind)
					}
				}
				a := g.attempts[g.phase.FrontierAttemptID]
				result := generatedPublicResultFixture(t, a, 1)
				plan := &generatedRecordPlan{expected: a.expected, result: result, phase: contract.GeneratorPhaseIdentity{AfterPhase: g.phase.Phase + 1},
					reference: contract.GeneratorResultReference{Schema: 1, ResultID: a.record.ResultID, ResultBodyDigest: contract.Hash(result), ResultLength: uint32(len(result))}}
				rows, err := generatedRecordedRows(g, plan, generatedVectorID(95))
				if err != nil {
					t.Fatal("record with older release", err)
				}
				var foundRelease, foundAttempt, foundPhase bool
				for _, row := range rows {
					key := generatedRecordKey{row.Kind, row.RecordID}
					if row.Kind == 12 && row.RecordID == release.InboxID {
						foundRelease = bytes.Equal(row.Body, prior.records[key].Body)
					}
					if row.Kind == 9 && row.RecordID == original.record.AttemptID {
						foundAttempt = bytes.Equal(row.Body, prior.records[key].Body)
					}
					if row.Kind == 5 {
						phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
						if err != nil || phase.PendingReleases != contract.EmptyGeneratorRecordSet(contract.GeneratorPhaseReleases) ||
							phase.Attempts.Count != 1 || phase.AcceptedResults.Count != 1 {
							t.Fatal("record adopted an older release into the active phase", err)
						}
						foundPhase = true
					}
				}
				if !foundRelease || !foundAttempt || !foundPhase {
					t.Fatal("record dropped or changed the older release mapping")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedInboxReleaseCannotCoexistWithResultAdoption(t *testing.T) {
	for _, owner := range []string{"active", "cleanup", "hazard"} {
		t.Run(owner, func(t *testing.T) {
			var s *StateSession
			var a generatedAttempt
			switch owner {
			case "active":
				s = generatedReservationState(t)
			case "cleanup":
				s, _ = generatedUnselectedCleanupState(t, 0)
			case "hazard":
				s, _, _ = generatedCreateHazardState(t, 0, 0)
			}
			g, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range g.attempts {
				a = value
			}
			result := a.result
			if len(result) == 0 {
				result = generatedPublicResultFixture(t, a, 1)
			}
			r := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: s.root.Domain, InboxID: a.record.InboxID, OriginalResultID: a.record.ResultID,
				SelectedHandoffDigest: contract.Hash(result), HandoffRevisionID: generatedVectorID(97), CapacityReservation: generatedCapacityReservationFixture(), ObjectLength: uint32(len(result)), State: contract.GeneratedReleasePending}
			body, err := contract.EncodePendingInboxReleaseRecord(r)
			if err != nil {
				t.Fatal(err)
			}
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView{Kind: 12, RecordID: r.InboxID, Body: body})
			owners := []contract.ID{r.InboxID}
			if g.parent != nil {
				owners = append(owners, g.parent.OperationID)
			}
			for key := range g.records {
				if key.kind == 10 || key.kind == 11 {
					owners = append(owners, key.id)
				}
			}
			slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, owners)
			if err != nil {
				t.Fatal(err)
			}
			s.root.Generated.PendingReleases = 1
			s.generatedWork = nil
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("release coexisted with a still-adoptable original result")
			}
		})
	}
}

// full_only: false
func TestGeneratedInboxReleaseRejectsChangedMapping(t *testing.T) {
	for _, template := range []struct{ action, branch uint8 }{{1, 0}, {1, 2}, {2, 2}} {
		for name, change := range map[string]func(*contract.PendingInboxReleaseRecord, *contract.GeneratedAttemptRecord){
			"template": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.TemplateDigest = generatedVectorID(99)
			},
			"lineage": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.LineageID = generatedVectorID(99)
			},
			"result": func(r *contract.PendingInboxReleaseRecord, _ *contract.GeneratedAttemptRecord) {
				r.OriginalResultID = generatedVectorID(99)
			},
			"inbox": func(r *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				r.InboxID, a.InboxID = generatedVectorID(99), generatedVectorID(99)
			},
			"owner": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.OwnerID = generatedVectorID(99)
			},
			"resource": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.ResourceID = generatedVectorID(99)
			},
			"profile": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.ConfigContractID = generatedVectorID(99)
			},
			"result contract": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.ResultContractID = generatedVectorID(99)
			},
			"transmission": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.TransmissionID = generatedVectorID(99)
			},
			"predecessor": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.PredecessorAttemptID = generatedVectorID(99)
			},
			"stage": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.Stage = contract.GeneratedStageRetainedResult
			},
			"transmitted": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.State = contract.GeneratedEffectTransmitted
			},
			"unknown": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) {
				a.State = contract.GeneratedEffectUnknown
			},
			"retry": func(_ *contract.PendingInboxReleaseRecord, a *contract.GeneratedAttemptRecord) { a.RetryUsed = 1 },
		} {
			t.Run(fmt.Sprintf("action%d/branch%d/%s", template.action, template.branch, name), func(t *testing.T) {
				s, a, r := generatedInboxReleaseTemplateState(t, template.action, template.branch, contract.GeneratedReleasePending)
				inbox := r.InboxID
				change(&r, &a.record)
				body, err := contract.EncodePendingInboxReleaseRecord(r)
				if err != nil {
					t.Fatal(err)
				}
				generatedReplaceRecord(t, s, 12, inbox, body)
				body, err = contract.EncodeGeneratedAttemptRecord(a.record)
				if err != nil {
					t.Fatal(err)
				}
				generatedReplaceRecord(t, s, 9, a.record.AttemptID, body)
				for i := range s.support {
					for j := range s.support[i].Records {
						row := &s.support[i].Records[j]
						if row.Kind == 12 {
							row.RecordID = r.InboxID
						}
					}
				}
				s.root.Generated.LiveOwners, err = contract.GeneratorIndexDescriptor(contract.GeneratorLiveOwnerSet, []contract.ID{r.InboxID})
				if err != nil {
					t.Fatal(err)
				}
				generatedRefreshSupport(t, s)
				if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
					t.Fatal("release reinterpreted the original effect mapping")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedInboxReleaseRequiresExactLiveRoots(t *testing.T) {
	for _, kind := range []uint8{9, 12} {
		t.Run(fmt.Sprintf("missing%d", kind), func(t *testing.T) {
			s, _, _ := generatedInboxReleaseState(t, 0, contract.GeneratedReleaseUnknown)
			for i := range s.support {
				s.support[i].Records = slices.DeleteFunc(s.support[i].Records, func(row contract.SupportRecordView) bool { return row.Kind == kind })
			}
			if generatedIndexRejectsAlteredSupport(t, s) {
				return
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("release lost its selected mapping or obligation")
			}
		})
	}
	for _, kind := range []uint8{1, 4} {
		t.Run(fmt.Sprintf("orphan%d", kind), func(t *testing.T) {
			s, a, _ := generatedInboxReleaseState(t, 0, contract.GeneratedReleasePending)
			if _, err := s.selectedGeneratedWork(t.Context()); err != nil {
				t.Fatal("complete release-only baseline refused", err)
			}
			row := contract.SupportRecordView{Kind: kind, RecordID: a.record.ResultID, Body: a.result}
			if kind == 1 {
				var err error
				row.RecordID = a.material.Core.OperationMaterialID
				row.Body, err = contract.EncodeOperationMaterialRecord(a.material)
				if err != nil {
					t.Fatal(err)
				}
				s.root.Generated.Materials++
			} else {
				s.root.Generated.Results++
			}
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, row)
			if kind == contract.OperationMaterialSupportKind {
				indexChecked, err := generatedAlteredSupportIndexResult(t, s)
				if !indexChecked || !errors.Is(err, contract.ErrRecord) {
					t.Fatalf("orphan operation material requires administrative index refusal: indexChecked=%t err=%v", indexChecked, err)
				}
				return
			}
			generatedRefreshSupport(t, s)
			if _, err := s.selectedGeneratedWork(context.Background()); err == nil {
				t.Fatal("release revived discarded material or the original ciphertext")
			}
		})
	}
}
