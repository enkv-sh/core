package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type continuationReadOnlyStore struct {
	contract.Store
	creates, headCreates, swaps int
}

func (s *continuationReadOnlyStore) Create(context.Context, string, []byte) contract.WriteResult {
	s.creates++
	return contract.WriteResult{}
}
func (s *continuationReadOnlyStore) CreateHead(context.Context, contract.HeadCreateRequest) contract.WriteResult {
	s.headCreates++
	return contract.WriteResult{}
}
func (s *continuationReadOnlyStore) CompareAndSwap(context.Context, string, contract.Token, []byte) contract.WriteResult {
	s.swaps++
	return contract.WriteResult{}
}

func continuationTestSelectedDigest(t *testing.T, s *StateSession) contract.ID {
	t.Helper()
	var body []byte
	add := func(encoded []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		digest := contract.Hash(encoded)
		body = append(body, digest[:]...)
	}
	add(format.EncodeRoot(s.root))
	add(format.EncodeAdministrativeIndex(s.adminIndex))
	add(s.body, nil)
	for _, page := range s.pages {
		if page != nil {
			add(format.EncodeValueEntryPage(*page))
		}
	}
	for _, page := range s.recipients {
		if page != nil {
			add(format.EncodeRecipientPage(*page))
		}
	}
	for _, page := range s.access {
		if page != nil {
			add(format.EncodeAccessPage(*page))
		}
	}
	for _, page := range s.support {
		for _, row := range page.Records {
			body = append(body, row.RecordID[:]...)
			add(row.Body, nil)
		}
	}
	return contract.Hash(body)
}

func continuationTestReadOnly(t *testing.T, s *StateSession, visit func()) {
	t.Helper()
	before, prepared := continuationTestSelectedDigest(t, s), s.prepared
	store := &continuationReadOnlyStore{Store: s.store}
	s.store = store
	defer func() { s.store = store.Store }()
	visit()
	if store.creates != 0 || store.headCreates != 0 || store.swaps != 0 || s.prepared != prepared || continuationTestSelectedDigest(t, s) != before {
		t.Fatal("numeric inspection changed selected state or entered a mutation", store.creates, store.headCreates, store.swaps)
	}
}

func continuationTestFinalShape(t *testing.T, s *StateSession) continuationFinalShape {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	read, err := g.fragmentReader()
	if err != nil {
		t.Fatal(err)
	}
	var shape continuationFinalShape
	continuationTestReadOnly(t, s, func() {
		shape, err = selectedContinuationFinalShape(t.Context(), g.image, g, read)
		if err != nil {
			t.Fatal("selected Final capacity", err)
		}
	})
	return shape
}

// full_only: false
func TestContinuationCapacityAnchoredParentHasNoNewFinalImage(t *testing.T) {
	s := generatedAutomaticSelectedFixture(t)
	g := mustSelectedGeneratedWork(t, s)
	if !generatedSelectionAnchored(g) || g.preparation != nil {
		t.Fatal("fixture did not complete the canonical Final")
	}
	if plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 186, 187)); err == nil || plan != nil {
		t.Fatal("anchored parent unexpectedly retained canonical Final permission")
	}
	// The selected canonical pages and historical access remain current usage.
	// This assertion concerns only additional Final population: every term is
	// independently zero because another canonical Final is forbidden.
	if got := continuationTestFinalShape(t, s); got != (continuationFinalShape{}) {
		t.Fatalf("anchored parent acquired a fresh Final image: %+v", got)
	}
	population, err := selectedContinuationGroups(t.Context(), g.image, g)
	if err != nil {
		t.Fatal(err)
	}
	growth, err := selectedContinuationGrowth(t.Context(), g.image, g, population)
	if err != nil || growth.accessCount != 0 || growth.parts[continuationPartition{class: format.CreateContinuationSupport}].count != 0 || growth.parts[continuationPartition{class: format.DeleteContinuationSupport}].count == 0 {
		t.Fatal("anchor lost automatic retirement or acquired create rights", growth, err)
	}
}

func continuationTestFailedTerminal(t *testing.T) *StateSession {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base,
		generatedVectorID(10), []string{"alpha", "omega"}))
	if err != nil {
		t.Fatal(err)
	}
	s := reservation.state
	for i, disposition := range []uint8{contract.GeneratorDispositionCompleteCreate, contract.GeneratorDispositionOwnedUnusableCreate} {
		g := mustSelectedGeneratedWork(t, s)
		a := g.attempts[g.phase.FrontierAttemptID]
		var packet []byte
		if i == 0 {
			packet = generatedPublicResultFixture(t, a, disposition)
		} else {
			packet = generatedPublicResultFixtureWithRawToken(t, a, disposition, 0, generatedVectorID(98))
		}
		request, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID, packet,
			generatedContinuationContext(t, s, byte(170+2*i), byte(171+2*i)))
		if err != nil {
			t.Fatal(err)
		}
		next, err := s.deriveGeneratedRecord(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		s = next.state
	}
	return s
}

// full_only: false
func TestContinuationCapacityFailedTerminalHasNoNewFinalImage(t *testing.T) {
	s := continuationTestFailedTerminal(t)
	g := mustSelectedGeneratedWork(t, s)
	plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 174, 175))
	if err != nil || plan.selecting || len(plan.results) != 2 || g.phase.Stage != contract.GeneratedStageTerminal {
		t.Fatal("fixture must retain only a nonselecting Final", err)
	}
	// The CompleteCreate result, failed result, custody and closure stay live.
	// Neither result can be adopted into a new canonical Final population.
	if got := continuationTestFinalShape(t, s); got != (continuationFinalShape{}) {
		t.Fatalf("failed terminal aggregate acquired a selecting Final image: %+v", got)
	}
}

// full_only: false
func TestContinuationCapacityFailedFinalUsesLastPhaseAndPreservesCustody(t *testing.T) {
	s := continuationTestFailedTerminal(t)
	// The counter is a request-owner boundary on real recorded Results, not
	// a claimed authenticated history of billions of phase transitions.
	continuationTestPhase(t, s, math.MaxUint32-1)
	g := mustSelectedGeneratedWork(t, s)
	var creates []contract.GeneratorLineageTemplate
	for _, lineage := range g.bundles[0].Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			creates = append(creates, lineage)
		}
	}
	if len(g.bundles[0].Lineages) != 12 || len(creates) != 2 || creates[0].Name != "alpha" || creates[1].Name != "omega" || g.phase.Stage != contract.GeneratedStageTerminal {
		t.Fatal("fixture needs the real mixed terminal aggregate")
	}
	success := g.attempts[creates[0].Templates[0].AttemptID]
	failed := g.attempts[creates[1].Templates[0].AttemptID]
	dutyKey := generatedRecordKey{contract.GeneratedDutySupportKind, failed.record.OwnerID}
	hazardKey := generatedRecordKey{contract.GeneratedHazardSupportKind, failed.expected.Template.HazardID}
	duty, err := contract.InspectGeneratedDutyRecord(g.records[dutyKey].Body)
	if err != nil || duty.Status != contract.GeneratedEffectFailedTerminal || failed.record.State != contract.GeneratedEffectFailedTerminal || success.record.State != contract.GeneratedEffectSucceeded {
		t.Fatal("recorded OwnedUnusable must still have its failed Duty", err)
	}
	if _, present := g.records[hazardKey]; present {
		t.Fatal("Record created the Failed-Final Hazard prematurely")
	}
	before := continuationTestSelectedDigest(t, s)
	bound := continuationTestBound(t, s)
	growth := continuationPhaseTestGrowth(t, s)
	plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 174, 175))
	if err != nil || plan == nil || plan.selecting || len(plan.results) != 2 || plan.phase.BeforePhase != math.MaxUint32-1 || plan.phase.AfterPhase != math.MaxUint32 {
		t.Fatal("last-step nonselecting Final refused", err)
	}
	final, err := s.deriveGeneratedFinal(t.Context(), plan, nil)
	if err != nil {
		t.Fatal("derive last-step nonselecting Final", err)
	}
	continuationTestCandidateWithin(t, final.state, bound.Remaining)
	generatedInstallFixtureSupportReader(t, final.state)
	generatedVerifySelectedFixtureSlices(t, final.state)
	after := mustSelectedGeneratedWork(t, final.state)
	hazard, err := contract.InspectGeneratedHazardRecord(after.records[hazardKey].Body)
	if err != nil || hazard.HazardID != failed.expected.Template.HazardID || hazard.OriginalOperationID != duty.OriginalOperationID || hazard.OriginalAttemptID != duty.OriginalAttemptID || hazard.OwnerID != duty.OwnerID || hazard.ResourceID != duty.ResourceID || hazard.CapacityReservation != duty.CapacityReservation || hazard.Support != duty.Support || hazard.Fenced != 1 || hazard.Exposure != contract.GeneratedExposureLateEffect || hazard.Eligibility != contract.GeneratedExposureLateEffect {
		t.Fatal("Failed-Final did not install the exact owned-unusable Hazard", err)
	}
	if _, present := after.records[dutyKey]; present || after.parent != nil || after.phase != nil || final.state.root.Generated.GeneratedCurrent != s.root.Generated.GeneratedCurrent {
		t.Fatal("Failed-Final retained failed Duty/parent or selected a value")
	}
	results, err := contract.GeneratorRecordSetDescriptor(contract.GeneratorHazardResults, s.root.Domain, []contract.SupportRecord{{Kind: contract.GeneratedResultSupportKind, RecordID: failed.record.ResultID, Body: failed.result}})
	if err != nil || hazard.OriginalResults != results {
		t.Fatal("Hazard lost its exact failed Result", err)
	}
	cleanup, err := contract.InspectGeneratedDutyRecord(after.records[generatedRecordKey{contract.GeneratedDutySupportKind, success.record.OwnerID}].Body)
	if err != nil || cleanup.Kind != contract.GeneratedDutyUnselectedCleanup || cleanup.Status != contract.GeneratedEffectSucceeded || cleanup.OriginalAttemptID != success.record.AttemptID {
		t.Fatal("Failed-Final lost the successful sibling cleanup", err)
	}
	for _, key := range []generatedRecordKey{
		{contract.OperationMaterialSupportKind, failed.material.Core.OperationMaterialID},
		{contract.GeneratedResultSupportKind, failed.record.ResultID},
		{contract.GeneratedResultSupportKind, success.record.ResultID},
		{contract.GeneratedAttemptSupportKind, failed.record.AttemptID},
		{contract.GeneratedAttemptSupportKind, success.record.AttemptID},
	} {
		if !after.hasRecord(key) || !bytes.Equal(after.records[key].Body, g.records[key].Body) {
			t.Fatal("Failed-Final changed seed or sibling/failed result custody", key)
		}
	}
	groups, err := generatedReservationGroupsForState(final.state, final.state.supportRecords(), selectedGeneratedLocations(after), after.bundles)
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := after.image.selectedFragmentFactsByRecord()
	if err != nil {
		t.Fatal(err)
	}
	var measured [contract.GeneratorCapacityGroupCount]continuationGroupCharge
	for _, group := range groups {
		tag, ok := continuationTag(group.Class)
		if !ok {
			t.Fatal("unmapped actual support class", group.Class)
		}
		for _, row := range group.Records {
			length := uint64(len(row.Body))
			if row.Body == nil {
				fact, present := fragments[row.RecordID]
				if !present {
					t.Fatal("actual fragment row lacks its authenticated length")
				}
				length = uint64(fact.row.BodyLength())
			}
			measured[tag].count++
			measured[tag].framed += 37 + length
		}
	}
	for tag, actual := range measured {
		limit := bound.Remaining.Groups[tag]
		if limit.MaxCount < actual.count || limit.MaxFramedBytes < actual.framed {
			t.Fatal("actual Failed-Final class exceeds its original bound", tag, actual, limit)
		}
	}
	// The failed Duty becomes a Hazard only at Final. This equal-width
	// owner replacement need not increase the654-byte owner charge.
	evidence := growth.parts[continuationPartition{class: format.OldValueSupport, mandatory: true}]
	if evidence.count != 0 || evidence.framed != 0 || growth.accessCount != 0 || growth.accessBytes != 0 || continuationTestFinalShape(t, s) != (continuationFinalShape{}) {
		t.Fatal("nonselecting Final acquired canonical evidence/access")
	}
	if continuationTestSelectedDigest(t, s) != before || s.prepared || final.state.prepared {
		t.Fatal("Failed-Final construction changed its selected predecessor")
	}
}

func continuationTestBound(t *testing.T, s *StateSession) selectedContinuationCapacity {
	t.Helper()
	g, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal("continuation bound selected work", err)
	}
	read, err := g.fragmentReader()
	if err != nil {
		t.Fatal("continuation bound fragment reader", err)
	}
	var bound selectedContinuationCapacity
	continuationTestReadOnly(t, s, func() {
		bound, err = continuationCapacityFromSelected(t.Context(), g.image, g, read)
		if err != nil {
			t.Fatal("current continuation bound", err)
		}
	})
	return bound
}

func continuationTestCandidateWithin(t *testing.T, s *StateSession, bound selectedCapacityBound) {
	t.Helper()
	if bound.Status != capacitySufficient {
		t.Fatal("small authentic candidate lacks a sufficient bound", bound)
	}
	root, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal(err)
	}
	// Enumerate signed physical references; do not use the bound's groups or
	// the root's cached ChildEncodedBytes as the measurement oracle.
	refs := publicationBoundaryChildRefs(s.root)
	var bytes uint64
	for _, ref := range refs {
		bytes += uint64(ref.Length)
	}
	index, err := format.EncodeAdministrativeIndex(s.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(refs)) > bound.ChildPages || bytes > bound.ChildEncodedBytes || uint64(len(root)) > bound.RootBytes || uint64(len(index)) > bound.AdministrativeIndexBytes {
		t.Fatalf("actual candidate exceeds current bound: pages=%d bytes=%d root=%d index=%d bound=%+v", len(refs), bytes, len(root), len(index), bound)
	}
}

// full_only: false
func TestContinuationCapacityBoundsRealRecordAndNonselectingFinal(t *testing.T) {
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal(err)
	}
	s := reservation.state
	bound := continuationTestBound(t, s)
	g := mustSelectedGeneratedWork(t, s)
	a := g.attempts[g.phase.FrontierAttemptID]
	request, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID,
		generatedPublicResultFixture(t, a, contract.GeneratorDispositionOwnedUnusableCreate), generatedContinuationContext(t, s, 170, 171))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := s.deriveGeneratedRecord(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	continuationTestCandidateWithin(t, recorded.state, bound.Remaining)
	plan, err := recorded.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded.state, 172, 173))
	if err != nil || plan.selecting {
		t.Fatal("expected a real nonselecting Final", err)
	}
	final, err := recorded.state.deriveGeneratedFinal(t.Context(), plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	continuationTestCandidateWithin(t, final.state, bound.Remaining)
}

// full_only: false
func TestContinuationCapacityBoundsRealGCFirstExit(t *testing.T) {
	s, plan := gcStateFixture(t, true)
	bound := continuationTestBound(t, s)
	s.admission.endWorkInvocation = gcTestID("capacity-end-invocation")
	ids := endWorkIDs{operation: gcTestID("capacity-end-op"), transition: gcTestID("capacity-end-transition"), snapshot: gcTestID("capacity-end-snapshot"), revision: gcTestID("capacity-end-revision"), receipts: gcTestID("capacity-end-receipts"), receiptIndex: gcTestID("capacity-end-receipt-index")}
	_, next, err := s.deriveEndWorkCandidate(t.Context(), plan.OperationID, ids)
	if err != nil {
		t.Fatal(err)
	}
	continuationTestCandidateWithin(t, next, bound.FirstExit)
}

// full_only: false
func TestContinuationCapacitySelectingFinalAndSelectedPreparation(t *testing.T) {
	s, plan := observationFinalFixture(t, "generated")
	shape := continuationTestFinalShape(t, s)
	// One generated secret:154fixed+9name+32membership+215ciphertext
	// framing+65536allowed raw+1024metadata. The image adds one102-byte
	// access header, one489-byte reader and the preparation codec envelopes.
	if shape.values != (contract.GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: 66970, MaxPages: 1}) || shape.names != 15 || shape.preparationBytes != 70562 {
		t.Fatal("possible selecting Final lost its independent image charge", shape)
	}
	bound := continuationTestBound(t, s)
	rows := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, s, plan.entryPlans[0])}
	checkpoint, err := s.deriveGeneratedFinalPreparation(t.Context(), mustSelectedGeneratedWork(t, s), plan, rows, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	continuationTestCandidateWithin(t, checkpoint.state, bound.Remaining)
	generatedInstallFixtureSupportReader(t, checkpoint.state)
	g := mustSelectedGeneratedWork(t, checkpoint.state)
	if g.preparation == nil || g.preparation.Image.Length == 0 {
		t.Fatal("real preparation checkpoint absent")
	}
	before, err := g.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, g.preparation.Image.ContentID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	selectedBound := continuationTestBound(t, checkpoint.state)
	// No new image is materialized by inspection; exact selected image bytes
	// and its original commitment survive the borrowed calculation.
	after, err := g.readSelectedSlice(t.Context(), contract.GeneratorContentFinalPreparation, g.preparation.Image.ContentID, contract.GeneratedFinalPreparationMaxLength)
	if err != nil || !bytes.Equal(before, after) || uint32(len(after)) != g.preparation.Image.Length {
		t.Fatal("inspection replaced the selected preparation", err)
	}
	finalPlan, err := checkpoint.state.generatedFinalRequest(t.Context(), generatedContinuationContext(t, checkpoint.state, 134, 135))
	if err != nil || finalPlan.materialization == nil || !finalPlan.selecting {
		t.Fatal("selected preparation lost its existing selecting Final", err)
	}
	final, err := checkpoint.state.deriveGeneratedFinal(t.Context(), finalPlan, rows)
	if err != nil {
		t.Fatal(err)
	}
	continuationTestCandidateWithin(t, final.state, selectedBound.Remaining)
	continuationTestCandidateWithin(t, final.state, bound.Remaining)
}

// full_only: false
func TestContinuationCapacityFinalUsesEachLineageMaximum(t *testing.T) {
	before := generatedEmptyPredecessor(t)
	input := generatedReservationInputForGenerations(t, before, generatedVectorID(10), []string{"alpha", "omega"})
	for _, lineage := range input.graph.Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if template.Action != contract.GeneratorActionCreate {
				continue
			}
			maximum := uint32(7)
			if lineage.Name == "alpha" {
				maximum = 11
			}
			if template.Branch == 1 {
				maximum = 17
				if lineage.Name == "alpha" {
					maximum = 257
				}
			}
			for i := range input.graph.ResultUses {
				if input.graph.ResultUses[i].AttemptID == template.AttemptID {
					input.graph.ResultUses[i].MaxSecret = maximum
				}
			}
		}
	}
	var err error
	input.graph.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(input.graph.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.UsePlanDigest, err = contract.GeneratorUsePlanDigest(input.graph.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	input.parent.Graph, err = contract.GeneratorPlanBundleDescriptor(input.graph)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.Material.Core.UsePlanDigest = input.parent.UsePlanDigest
	access, err := contract.DecodeAccessRecord(input.finished.SeedAccess)
	if err != nil {
		t.Fatal(err)
	}
	access.MaterialContextDigest, err = contract.OperationMaterialContextDigest(input.finished.Material.Core)
	if err != nil {
		t.Fatal(err)
	}
	input.finished.SeedAccess, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := before.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("distinct generated result bounds", err)
	}
	shape := continuationTestFinalShape(t, reservation.state)
	// Each secret has 154 fixed bytes, a 5-byte name, one 32-byte reader,
	// 215 ciphertext framing bytes and 1024 metadata bytes. The latent
	// branch-1 maxima are 257 for alpha and 17 for omega; the entered and
	// last create branches permit only 11 and 7 respectively.
	const values = 2*(154+5+32+215+1024) + 257 + 17
	if shape.values != (contract.GeneratorCapacityGroup{MaxCount: 2, MaxFramedBytes: values, MaxPages: 1}) || shape.names != 22 {
		t.Fatal("Final capacity mixed lineage maxima or omitted a latent branch", shape)
	}
}

// full_only: false
func TestContinuationCapacityUsesExactHistoricalReaderUnion(t *testing.T) {
	s, _, _ := generatedCanonicalState(t, false)
	// Add an authenticated128th registry entry that reads neither alias.
	binding := generatedPublicBinding(t, 240)
	binding.Provider, binding.ProtectionClass = contract.AWS, contract.HardwareProtection
	binding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000240"
	binding.BindingID = contract.Hash([]byte("continuation unused registry binding"))
	binding.BindingIncarnationID = contract.Hash([]byte("continuation unused registry incarnation"))
	if s.recipients[15] == nil || s.recipients[15].Slots[7] != nil {
		t.Fatal("canonical fixture must leave its final registry slot free")
	}
	s.recipients[15].Slots[7] = &contract.RecipientRecord{RecipientID: generatedVectorID(240), Status: contract.CurrentRecipient, CurrentBinding: &binding}
	generatedSealSelectedFixture(t, s)
	basis, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	basis.Recipients = s.registry()
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
	if err != nil {
		t.Fatal(err)
	}
	shape := continuationTestFinalShape(t, s)
	// Current64 and retained64 share only Authority:127readers. The fresh
	// generated secret has one reader. Thus2headers+128wraps=62796bytes;
	// the unused registry entry contributes no wrap to this Final image.
	const values = (154 + 5 + 32 + 4 + 215) + (154 + 9 + 32 + 65536 + 215 + 1024)
	const access = 2*102 + 128*489
	const preparation = values + access + (512 + 256 + 1024 + 128) + 2*(256+64) + 138 + 37 + 318 + (37 + 120 + 111)
	if len(s.registry()) != 128 || shape.values.MaxFramedBytes != values || shape.preparationBytes != preparation || shape.accessGrowthBytes != 0 {
		t.Fatal("historical aliases duplicated a reader or charged the unused registry row", shape)
	}
	bound := continuationTestBound(t, s)
	if bound.Remaining.Status != capacitySufficient {
		t.Fatal("small historical union lacks a sufficient bound", bound.Remaining)
	}
	var currentAccess uint64
	for _, ref := range s.root.CurrentAccess.Core.AccessPageRefs {
		currentAccess += uint64(ref.Length - 75)
	}
	if got := bound.Remaining.Groups[contract.GeneratorCapacityCurrentAccess]; got.MaxCount != uint64(s.root.AccessRecordCount) || got.MaxFramedBytes != currentAccess {
		t.Fatal("selected127reader material was charged more than once", got, currentAccess)
	}
}

// full_only: false
func TestContinuationCapacityCountsWholeRetainedBlob(t *testing.T) {
	s := generatedEmptyPredecessor(t)
	old, _, _ := generatedDetachedRetirementState(t, "absent", 0)
	selected := mustSelectedGeneratedWork(t, old)
	var locations []contract.GeneratorSliceLocation
	var blobs []generatedContentFixtureBlob
	for key, location := range selected.content.locations {
		intent, err := selected.readSelectedSlice(t.Context(), key.kind, key.id, location.Length)
		if err != nil || key.kind != contract.GeneratorContentIntent {
			t.Fatal("retained intent", err)
		}
		body := bytes.Repeat([]byte{' '}, contract.GeneratedFragmentMaxPayload+256)
		copy(body[contract.GeneratedFragmentMaxPayload-1:], intent)
		location.BlobID, location.Offset = contract.Hash(body), contract.GeneratedFragmentMaxPayload-1
		locations = append(locations, location)
		blobs = append(blobs, generatedContentFixtureBlob{location.BlobID, body})
	}
	if len(blobs) != 1 {
		t.Fatal("expected one complete retained blob")
	}
	content := generatedContentStateAtSnapshot(t, s.root.Snapshot, blobs, locations)
	s.support, s.root.Generated = content.support, old.root.Generated
	s.root.Generated.Fragments, s.root.Generated.Slices = content.root.Generated.Fragments, content.root.Generated.Slices
	for _, row := range old.supportRecords() {
		_, carrier, err := snapshotSliceRecord(row, old.root.Domain, old.root.Snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if row.Kind != contract.GeneratedFragmentSupportKind && row.Kind != contract.OutputConfigurationSliceSupportKind && !carrier {
			s.support[len(s.support)-1].Records = append(s.support[len(s.support)-1].Records, contract.SupportRecordView(row))
		}
	}
	generatedRepackSupportAtLocations(t, s, s.supportRecords(), selected.bundles, locations)
	s.recountChildren()
	input := generatedReservationInputForOperation(t, s, generatedVectorID(98))
	reservation, err := s.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("actual reservation with complete retained blob", err)
	}
	bound := continuationTestBound(t, reservation.state)
	// Two old physical fragments and one new declaration fragment, each with
	//123framing bytes. The selected logical intent crosses the old boundary.
	want := uint64(len(blobs[0].body) + len(input.declaration) + 3*123)
	if got := bound.Remaining.Groups[contract.GeneratorCapacityIntents]; got.MaxCount != 3 || got.MaxPages != 2 || got.MaxFramedBytes != want {
		t.Fatal("logical slice replaced its complete physical blob", got, want)
	}
	g := mustSelectedGeneratedWork(t, reservation.state)
	a := g.attempts[g.phase.FrontierAttemptID]
	request, err := reservation.state.generatedRecordRequest(t.Context(), a.record.AttemptID, generatedPublicResultFixture(t, a, contract.GeneratorDispositionOwnedUnusableCreate), generatedContinuationContext(t, reservation.state, 170, 171))
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := reservation.state.deriveGeneratedRecord(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	continuationTestCandidateWithin(t, recorded.state, bound.Remaining)
}

// full_only: false
func TestContinuationCapacityPublicationRetainsMixedPeers(t *testing.T) {
	s := publicationMixedPeerState(t)
	generatedVerifySelectedFixtureSlices(t, s)
	proof, result, err := validateSelectedPublicationConfiguration(t.Context(), s.selectedImage(), nil)
	if err != nil || result.Outcome != 0 || proof == nil {
		t.Fatal("mixed publication complete relation", result, err)
	}
	s.publicationProof = proof
	var mixed format.Ref
	var peers uint64
	for _, page := range s.adminIndex.Pages {
		publication, other := false, page.ReadRequired
		for _, row := range page.Rows {
			publication = publication || row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind
			other = other || row.Kind != contract.PublicationCoordinateSupportKind && row.Kind != contract.PublicationMarkerSupportKind
		}
		if other {
			peers += uint64(page.Ref.Length)
		}
		if publication && other {
			mixed = page.Ref
		}
	}
	if mixed.Object.IsZero() {
		t.Fatal("real packer did not produce a mixed peer")
	}
	var extracted selectedPublicationCapacityBound
	continuationTestReadOnly(t, s, func() {
		var err error
		extracted, err = selectedPublicationCapacity(t.Context(), s.selectedImage())
		if err != nil {
			t.Fatal(err)
		}
	})
	var growth uint64
	for _, bytes := range extracted.growth {
		growth += bytes
	}
	// Signed coordinate/marker frames are 739 and 828 bytes. Three future
	// result strings add 3072; the two Owner groups each fit one page.
	if !extracted.unresolved || growth != 3072 || extracted.framedBytes != 4639 || extracted.pages != 2 || extracted.physicalBytes != peers+4639+2*75 {
		t.Fatal("mixed peer or future marker evidence was omitted", extracted, peers)
	}
	bound := continuationTestBound(t, s)
	next := *s
	next.root.Snapshot, next.root.Transition = publicationRelationID(90), publicationRelationID(91)
	candidate := Candidate{session: s}
	construction, err := s.preparePublicationConstruction(t.Context(), publicationNoEffectRows(t, s))
	if err == nil {
		err = s.materializePublicationRewriteConstruction(t.Context(), &next, &candidate, construction, []contract.ID{publicationRelationID(92), publicationRelationID(93)})
	}
	if err != nil || !slices.Contains(next.root.RequiredSupport, mixed) {
		t.Fatal("actual rewrite failed to retain mixed peer", err)
	}
	// This owner-level rewrite has not yet encoded a full successor root;
	// compare its complete support/index population directly.
	var supportBytes uint64
	for _, ref := range next.root.RequiredSupport {
		supportBytes += uint64(ref.Length)
	}
	index, err := format.EncodeAdministrativeIndex(next.adminIndex)
	if err != nil || supportBytes > bound.Remaining.ChildEncodedBytes || uint64(len(index)) > bound.Remaining.AdministrativeIndexBytes || bound.Remaining.Status != capacitySufficient {
		t.Fatal("mixed rewrite exceeded public remaining bound", supportBytes, len(index), err)
	}
}

func continuationTestPhase(t *testing.T, s *StateSession, phase uint32) {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	record := *g.phase
	record.Phase = phase
	body, err := contract.EncodeGeneratedPhaseRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	generatedReplaceRecord(t, s, contract.GeneratedPhaseSupportKind, record.OperationID, body)
	generatedRefreshSupport(t, s)
	generatedVerifySelectedFixtureSlices(t, s)
}

// full_only: false
func TestContinuationCapacityFinalFinitePhaseBudget(t *testing.T) {
	// These are request-owner finite counter inputs on real lifecycle facts.
	// They do not claim an authenticated history of billions of transitions.
	for _, tc := range []struct {
		name      string
		automatic bool
		remaining uint32
		possible  bool
	}{
		{"no_preparation_one", false, 1, false},
		{"no_preparation_two", false, 2, true},
		{"automatic_four", true, 4, false},
		{"automatic_five", true, 5, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s *StateSession
			if tc.automatic {
				s, _ = generatedAutomaticPreselectionFixture(t)
			} else {
				s, _ = observationFinalFixture(t, "generated")
			}
			continuationTestPhase(t, s, math.MaxUint32-tc.remaining)
			plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 186, 187))
			if (err == nil && plan != nil && plan.selecting) != tc.possible {
				t.Fatal("writer disagrees with independent finite step count", tc.remaining, err)
			}
			shape := continuationTestFinalShape(t, s)
			if (shape.values.MaxCount != 0) != tc.possible {
				t.Fatalf("capacity invented a Final beyond remaining phase rights: remaining=%d possible=%t shape=%+v", tc.remaining, tc.possible, shape)
			}
		})
	}
}

// full_only: false
func TestContinuationCapacityPendingPhaseBudget(t *testing.T) {
	// As above, only the supplied finite counter is synthetic. Each pending
	// owner and each transition comes from its actual lifecycle constructor.
	for _, tc := range []struct {
		name      string
		entries   int
		successor bool
		steps     uint32
	}{
		{"one_original", 1, false, 3},
		{"two_originals", 2, false, 4},
		{"planned_residue_successor", 1, true, 4},
	} {
		for _, enough := range []bool{false, true} {
			name := tc.name + "/short"
			remaining := tc.steps - 1
			if enough {
				name, remaining = tc.name+"/exact", tc.steps
			}
			t.Run(name, func(t *testing.T) {
				base := generatedEmptyPredecessor(t)
				names := []string{"alpha"}
				if tc.entries == 2 {
					names = append(names, "omega")
				}
				reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputForGenerations(t, base, generatedVectorID(10), names))
				if err != nil {
					t.Fatal(err)
				}
				s := reservation.state
				if tc.successor {
					s = generatedRetainedClosureResidue(t, s, 130)
				}
				continuationTestPhase(t, s, math.MaxUint32-remaining)
				if shape := continuationTestFinalShape(t, s); (shape.values.MaxCount != 0) != enough {
					t.Fatal("pending Reserve/Record cost omitted before possible Final", remaining, tc.steps, shape)
				}
				if !enough {
					return
				}
				if tc.successor {
					s = generatedReservePlannedSuccessor(t, s, 132)
				}
				for i := 0; ; i++ {
					g := mustSelectedGeneratedWork(t, s)
					if g.phase.Stage == contract.GeneratedStageTerminal {
						break
					}
					a := g.attempts[g.phase.FrontierAttemptID]
					request, err := s.generatedRecordRequest(t.Context(), a.record.AttemptID,
						generatedPublicResultFixtureWithRawToken(t, a, contract.GeneratorDispositionCompleteCreate, 1, generatedVectorID(byte(240+i))), generatedContinuationContext(t, s, byte(134+2*i), byte(135+2*i)))
					if err != nil {
						t.Fatal(err)
					}
					recorded, err := s.deriveGeneratedRecord(t.Context(), request)
					if err != nil {
						t.Fatal(err)
					}
					s = recorded.state
				}
				plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 188, 189))
				if err != nil || !plan.selecting || plan.materialization != nil {
					t.Fatal("exact minimum successful path lost its fresh Final pair", err)
				}
			})
		}
	}
}

func continuationTestCheckpointAt(t *testing.T, phase uint32) *StateSession {
	t.Helper()
	base := generatedEmptyPredecessor(t)
	peer := contract.RecipientRecord{RecipientID: generatedVectorID(206), Status: contract.CurrentRecipient, DisplayName: "independent peer"}
	peerBinding := *base.authority().CurrentBinding
	peerBinding.BindingID, peerBinding.BindingIncarnationID = generatedVectorID(207), generatedVectorID(208)
	peer.CurrentBinding = &peerBinding
	basis, err := contract.DecodeGenesisDescriptorCore(base.admission.descriptor)
	if err != nil {
		t.Fatal("checkpoint peer genesis basis", err)
	}
	basis.Recipients = append(basis.Recipients, peer)
	slices.SortFunc(basis.Recipients, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	base.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
	if err != nil {
		t.Fatal("checkpoint enrolled peer basis", err)
	}
	for i := range basis.Recipients {
		base.recipients[0].Slots[i] = &basis.Recipients[i]
	}
	generatedSealSelectedFixture(t, base)
	generatedInstallFixtureSupportReader(t, base)
	generatedVerifySelectedFixtureSlices(t, base)
	recipients := []contract.ID{base.admission.recipient, peer.RecipientID}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	// A real first canonical generation gives this peer a live material in
	// ordinary replacement coverage as well as its later preparation wrap.
	input := generatedReservationInputForMembershipStateIntent(t, base, generatedVectorID(10), recipients, []string{"generated"}, []byte(`{"name":"generated"}`), defaultGeneratedFixtureProfile(), 0, nil, nil)
	reservation, err := base.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("checkpoint initial two-reader reservation", err)
	}
	recorded := generatedAutomaticRecordCreatesFixture(t, reservation.state, 1, 160)
	initial, err := recorded.generatedFinalRequest(t.Context(), generatedContinuationContext(t, recorded, 180, 181))
	if err != nil {
		t.Fatal("checkpoint initial two-reader Final", err)
	}
	current := generatedAutomaticSelectFixture(t, recorded, initial)
	old := *current.valueEntry(0)
	input = generatedReservationInputForMembershipStateIntent(t, current, generatedVectorID(181), recipients, []string{"generated"}, []byte(`{"name":"rotated"}`), defaultGeneratedFixtureProfile(), 1, map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old})
	reservation, err = current.deriveGeneratedReservation(t.Context(), input)
	if err != nil {
		t.Fatal("checkpoint manual rotation reservation", err)
	}
	s := generatedAutomaticRecordCreatesFixture(t, reservation.state, 1, 199)
	observationProtectFixture(t, s)
	continuationTestPhase(t, s, phase)
	plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 186, 187))
	if err != nil {
		t.Fatal(err)
	}
	rows := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, s, plan.entryPlans[0])}
	checkpoint, err := s.deriveGeneratedFinalPreparation(t.Context(), mustSelectedGeneratedWork(t, s), plan, rows, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	generatedInstallFixtureSupportReader(t, checkpoint.state)
	generatedVerifySelectedFixtureSlices(t, checkpoint.state)
	return checkpoint.state
}

// full_only: false
func TestContinuationCapacityUsablePreparationLastStepAndPendingFinal(t *testing.T) {
	s := continuationTestCheckpointAt(t, math.MaxUint32-2)
	plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 188, 189))
	if err != nil || plan.materialization == nil || !plan.selecting {
		t.Fatal("compatible selected preparation lost its last Final step", err)
	}
	if shape := continuationTestFinalShape(t, s); shape.values.MaxCount != 1 {
		t.Fatal("usable selected preparation was treated as a fresh two-step request", shape)
	}
	base := generatedEmptyPredecessor(t)
	reservation, err := base.deriveGeneratedReservation(t.Context(), generatedReservationInputFixture(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if g := mustSelectedGeneratedWork(t, reservation.state); g.phase.Stage == contract.GeneratedStageTerminal {
		t.Fatal("fixture must still permit a future create result")
	}
	if shape := continuationTestFinalShape(t, reservation.state); shape.values.MaxCount != 1 || shape.preparationBytes != 70562 {
		t.Fatal("preterminal parent lost a possible future selecting Final", shape)
	}
}

func continuationTestReplaceCheckpointBinding(t *testing.T, s *StateSession) *StateSession {
	t.Helper()
	// Use the ordinary replacement projection and generic selected-snapshot
	// writer. The checkpoint bytes remain immutable across this control change.
	peer := s.recipientRecord(generatedVectorID(206))
	if peer == nil || peer.CurrentBinding == nil || peer.RecipientID == s.admission.recipient {
		t.Fatal("checkpoint replacement must target its enrolled non-Authority peer")
	}
	before := *peer.CurrentBinding
	successor := before
	successor.BindingID = generatedVectorID(210)
	successor.BindingSerial++
	digest, err := contract.PublicBindingDigest(successor)
	if err != nil {
		t.Fatal("checkpoint replacement successor binding", err)
	}
	intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: s.root.Domain, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, RecipientID: peer.RecipientID}, Before: before, Successor: successor}
	if err := s.replacementIntentValid(t.Context(), intent); err != nil {
		t.Fatal("checkpoint peer replacement admission", err)
	}
	target := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: peer.RecipientID, Binding: successor}
	coverage, err := s.replacementMaterialRows(t.Context(), 0, 1, target)
	if err != nil || len(coverage) == 0 {
		t.Fatal("replacement lost live preparation-parent material", err)
	}
	after := make(map[materialIdentity]contract.AccessRecord)
	for _, material := range coverage {
		row := material.BeforeAccessRecord
		row.Wraps = slices.Clone(row.Wraps)
		for i, wrap := range row.Wraps {
			if wrap.SubjectKind == target.SubjectKind && wrap.SubjectID == target.SubjectID {
				wrap.BindingID, wrap.BindingSerial, wrap.PublicBindingDigest = successor.BindingID, successor.BindingSerial, digest
				wrap.RSACiphertext = bytes.Repeat([]byte{211}, len(wrap.RSACiphertext))
				row.Wraps[i] = wrap
			}
		}
		after[materialIdentity{row.MaterialKind, row.MaterialID}] = row
	}
	p := transitionPlan{snapshot: generatedVectorID(212), transition: generatedVectorID(213)}
	p.recipientPages[0] = generatedVectorID(214)
	for i, page := range s.access {
		if page != nil {
			p.accessPages[i] = generatedVectorID(byte(215 + i))
		}
	}
	indexes, err := s.generatedSnapshotPageIndexes()
	if err != nil {
		t.Fatal("checkpoint replacement snapshot page indexes", err)
	}
	for i, index := range indexes {
		p.supportPages[index] = generatedVectorID(byte(220 + i))
	}
	next, ok := s.replacementSuccessor(intent, p, after)
	if !ok {
		t.Fatal("ordinary replacement projection")
	}
	if _, err := s.rebindGeneratedSnapshot(t.Context(), next, p); err != nil {
		t.Fatal("checkpoint replacement snapshot rewrite", err)
	}
	generatedInstallFixtureSupportReader(t, next)
	generatedVerifySelectedFixtureSlices(t, next)
	if err := s.installAdministrativeIndex(t.Context(), next, &Candidate{session: s}); err != nil {
		t.Fatal("checkpoint replacement administrative index", err)
	}
	root, err := format.EncodeRoot(next.root)
	if err != nil {
		t.Fatal("checkpoint replacement root encoding", err)
	}
	next.head.Core.Root, err = format.Reference(format.RootKind, next.root.Domain, next.root.Snapshot, 0, root)
	if err != nil {
		t.Fatal("checkpoint replacement root reference", err)
	}
	generatedInstallFixtureSupportReader(t, next)
	generatedVerifySelectedFixtureSlices(t, next)
	return next
}

func continuationTestAuxiliaryBytes(t *testing.T, s *StateSession) (uint64, uint64) {
	t.Helper()
	g := mustSelectedGeneratedWork(t, s)
	// Measure the actual encoder populations from closed row kinds. This
	// does not use continuation population, growth or packing arithmetic.
	nonAuxiliary := make(map[contract.ID]bool)
	for _, location := range g.content.locations {
		switch location.ContentKind {
		case contract.GeneratorContentGraph, contract.GeneratorContentIntent, contract.GeneratorContentDeclaration, contract.GeneratorContentSource:
			nonAuxiliary[location.BlobID] = true
		}
	}
	fragments := make(map[contract.ID]selectedFragmentFact)
	for _, fact := range s.fragmentFacts {
		fragments[fact.row.RecordID()] = fact
	}
	var count, framed uint64
	for _, row := range s.supportRecords() {
		auxiliary := row.Kind == contract.GCPlanSupportKind || row.Kind == contract.OutputConfigurationSliceSupportKind
		length := uint64(len(row.Body))
		switch row.Kind {
		case contract.GeneratedFragmentSupportKind:
			fact, present := fragments[row.RecordID]
			if !present {
				t.Fatal("actual fragment fact absent")
			}
			length = uint64(fact.row.BodyLength())
			auxiliary = !nonAuxiliary[fact.blob]
		case contract.GeneratorVectorSupportKind:
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal(err)
			}
			auxiliary = carrier.VectorKind == contract.GeneratorVectorConsumers || carrier.VectorKind == contract.GeneratorVectorSupport
		}
		if auxiliary {
			count++
			framed += 37 + length
		}
	}
	return count, framed
}

// full_only: false
func TestContinuationCapacityPreparationBlobOverlap(t *testing.T) {
	s := continuationTestCheckpointAt(t, 100)
	g := mustSelectedGeneratedWork(t, s)
	logical := generatedContentKey{contract.GeneratorContentFinalPreparation, g.preparation.Image.ContentID}
	location := g.content.locations[logical]
	for _, shared := range []bool{false, true} {
		t.Run(strconv.FormatBool(shared), func(t *testing.T) {
			population, err := selectedContinuationGroups(t.Context(), g.image, g)
			if err != nil {
				t.Fatal(err)
			}
			var beforeCount, beforeBytes uint64
			for key, row := range population {
				if key.class == format.AuxiliaryFragmentSupport {
					beforeCount += row.count
					beforeBytes += row.framed
				}
			}
			facts := *g
			if shared {
				// Calculator boundary only: lend one additional logical owner of
				// this physical blob. This does not claim a signed shared-blob
				// lifecycle or grant validity to the additional logical content.
				content := *g.content
				content.locations = make(map[generatedContentKey]contract.GeneratorSliceLocation, len(g.content.locations)+1)
				for key, row := range g.content.locations {
					content.locations[key] = row
				}
				content.locations[generatedContentKey{contract.GeneratorContentRecipientRegistry, gcTestID("capacity-shared-blob-owner")}] = location
				facts.content = &content
			}
			length := uint64(g.preparation.Image.Length) + 1
			if length > contract.GeneratedFragmentMaxPayload {
				t.Fatal("bounded fixture must have one image fragment")
			}
			if err := continuationPreparationPopulation(population, &facts, length); err != nil {
				t.Fatal(err)
			}
			var count, framed uint64
			for key, row := range population {
				if key.class == format.AuxiliaryFragmentSupport {
					count += row.count
					framed += row.framed
				}
			}
			wantCount, wantBytes := beforeCount, beforeBytes+1
			if shared {
				wantCount, wantBytes = beforeCount+1, beforeBytes+length+123
			}
			if count != wantCount || framed != wantBytes {
				t.Fatal("old physical blob received incorrect replacement credit", shared, count, framed, wantCount, wantBytes)
			}
		})
	}
}

// full_only: false
func TestContinuationCapacityIncompatiblePreparationNeedsFreshPair(t *testing.T) {
	for _, remaining := range []uint32{1, 2} {
		t.Run(strconv.Itoa(int(remaining)), func(t *testing.T) {
			s := continuationTestCheckpointAt(t, math.MaxUint32-remaining-1)
			g := mustSelectedGeneratedWork(t, s)
			before := *g.preparation
			s = continuationTestReplaceCheckpointBinding(t, s)
			g = mustSelectedGeneratedWork(t, s)
			bindings, err := s.generatedBindings(g)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := contract.GeneratedFinalPreparationBindingDigest(currentControlOf(s), bindings)
			if err != nil || g.preparation == nil || *g.preparation != before || digest == before.ControlBindingDigest {
				t.Fatal("fixture must retain an exact checkpoint under different current controls", err)
			}
			plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 188, 189))
			possible := remaining == 2
			if (err == nil && plan != nil && plan.selecting && plan.materialization == nil) != possible {
				t.Fatal("writer did not require a fresh preparation pair", remaining, err)
			}
			shape := continuationTestFinalShape(t, s)
			if (shape.values.MaxCount != 0) != possible {
				t.Fatal("incompatible selected preparation received one-step reuse", remaining, shape)
			}
			if !possible {
				return
			}
			// One two-reader generated secret has67002maximum value bytes.
			// Its image adds102+2*489access bytes,1920create-result overhead,
			//320entry framing and761fixed record/carrier/header bytes.
			if shape.values.MaxFramedBytes != 67002 || shape.preparationBytes != 67002+(102+2*489)+1920+320+761 {
				t.Fatal("replacement image omitted its independent future-width envelope", shape)
			}
			bound := continuationTestBound(t, s)
			unchanged := continuationTestSelectedDigest(t, s)
			rows := []contract.CryptoGeneratedValueEntryResult{generatedPreparedValueEntryFixture(t, s, plan.entryPlans[0])}
			replacement, err := s.deriveGeneratedFinalPreparation(t.Context(), g, plan, rows, nil, nil)
			if err != nil || continuationTestSelectedDigest(t, s) != unchanged {
				t.Fatal("actual replacement checkpoint or immutable predecessor", err)
			}
			continuationTestCandidateWithin(t, replacement.state, bound.Remaining)
			generatedInstallFixtureSupportReader(t, replacement.state)
			generatedVerifySelectedFixtureSlices(t, replacement.state)
			actualCount, actualBytes := continuationTestAuxiliaryBytes(t, replacement.state)
			auxiliary := bound.Remaining.Groups[contract.GeneratorCapacityAuxiliary]
			if actualCount > auxiliary.MaxCount || actualBytes > auxiliary.MaxFramedBytes {
				t.Fatal("actual replacement Auxiliary rows exceed their own group bound", actualCount, actualBytes, auxiliary)
			}
			after := mustSelectedGeneratedWork(t, replacement.state)
			rowBody, err := contract.EncodeCryptoGeneratedValueEntriesResult(contract.CryptoGeneratedValueEntriesResult{Final: 1, Rows: rows})
			if err != nil || after.preparation == nil || after.preparation.Image.Length != uint32(138+4+len(rowBody)) || after.preparation.Image.ContentID == before.Image.ContentID {
				t.Fatal("replacement image row/header widths or identity", err)
			}
		})
	}
}

// full_only: false
func TestContinuationCapacityArithmeticAndOwnerOverlap(t *testing.T) {
	if got := capacityCeiling(math.MaxUint64, 2); got != 1<<63 {
		t.Fatal("overflow-safe ceiling", got)
	}
	if _, err := capacityAdd(math.MaxUint64, 1); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatal("addition overflow lost", err)
	}
	if _, err := capacityMultiply(math.MaxUint64, 2); !errors.Is(err, contract.ErrRecordCapacity) {
		t.Fatal("multiplication overflow lost", err)
	}
	key := continuationGroupKey{class: format.OwnerSupport, owner: generatedVectorID(1)}
	other := key
	other.mandatory = true
	p := continuationPopulation{key: {count: 2, framed: 500}, other: {count: 1, framed: 300}}
	p.atLeastWholeGroup(key, 4, 1100)
	if p[key].count+p[other].count != 4 || p[key].framed+p[other].framed != 1100 {
		t.Fatal("one owner charged twice across partitions", p)
	}
	p.atLeastWholeGroup(key, 3, 1000)
	if p[key].count+p[other].count != 4 || p[key].framed+p[other].framed != 1100 {
		t.Fatal("smaller replacement erased selected population", p)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := generatedEmptyPredecessor(t)
	g := mustSelectedGeneratedWork(t, s)
	if _, err := continuationCapacityFromSelected(ctx, g.image, g, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("context error replaced by numeric refusal", err)
	}
}

// full_only: false
func TestContinuationCapacityUsesMergedFinalRecipientRows(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		current, added, selector int
		invalid                  bool
	}{
		{"no_additions", 8, 0, 1, false},
		{"unchanged_count_longer_binding", 8, 0, 1024, false},
		{"addition_and_longer_binding", 8, 1, 1024, false},
		{"one_over_binding_ceiling", 8, 1, 1025, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := observationFinalFixture(t, "generated")
			g := mustSelectedGeneratedWork(t, s)
			read, err := g.fragmentReader()
			if err != nil {
				t.Fatal(err)
			}
			image := *g.image
			image.recipients = [contract.MaxRecipientPages]*format.RecipientPage{}
			image.root.Recipients = [contract.MaxRecipientPages]*format.Ref{}
			current := s.registry()[0]
			proposal := contract.GeneratedRecipientRegistryImage{Schema: 1, DomainID: image.root.Domain,
				OperationID: g.parent.OperationID, OriginalPredecessorSnapshotID: image.root.Snapshot}
			var wantBytes uint64
			var wantRows []contract.RecipientRecord
			for i := 0; i < tc.current; i++ {
				row := current
				if i != 0 {
					row.RecipientID = contract.Hash([]byte("capacity existing " + strconv.Itoa(i)))
				}
				row.DisplayName = "accepted display"
				key := *row.CurrentBinding
				key.KeySelector = "s"
				row.CurrentBinding = &key
				proposal.Recipients = append(proposal.Recipients, contract.ApplyRecipientInput{Recipient: row})
				currentRow := row
				currentRow.DisplayName = "later display"
				currentKey := key
				currentKey.KeySelector = strings.Repeat("l", tc.selector)
				currentRow.CurrentBinding = &currentKey
				wantRow := row
				wantRow.CurrentBinding = &currentKey
				wantRows = append(wantRows, wantRow)
				page, slot := i/8, i%8
				if image.recipients[page] == nil {
					image.recipients[page] = &format.RecipientPage{}
				}
				image.recipients[page].Slots[slot] = &currentRow
				// Recipient framing is 41 bytes. The binding has two IDs,
				// serial, provider/profile/protection, selector length, 422-byte
				// SPKI and fingerprint: 534 bytes plus the selector.
				wantBytes += uint64(41 + len(row.DisplayName) + 534 + tc.selector)
			}
			image.root.RecipientCount = uint16(tc.current)
			for i := 0; i < tc.added; i++ {
				nonce := contract.Hash([]byte("capacity pending " + strconv.Itoa(i)))
				id, err := contract.RecipientCreationID(image.root.Domain, image.root.Snapshot, nonce)
				if err != nil {
					t.Fatal(err)
				}
				binding, incarnation, err := contract.RecipientInitialBindingIDs(image.root.Domain, id)
				if err != nil {
					t.Fatal(err)
				}
				key := *current.CurrentBinding
				key.BindingID, key.BindingIncarnationID, key.BindingSerial, key.KeySelector = binding, incarnation, 1, "n"
				row := contract.RecipientRecord{RecipientID: id, Status: contract.CurrentRecipient, DisplayName: "pending display", CurrentBinding: &key}
				proposal.Recipients = append(proposal.Recipients, contract.ApplyRecipientInput{Recipient: row,
					Creation: &contract.RecipientCreationProof{Snapshot: image.root.Snapshot, Nonce: nonce}})
				proposal.InitiallyAbsent = append(proposal.InitiallyAbsent, id)
				wantRows = append(wantRows, row)
				wantBytes += uint64(41 + len(row.DisplayName) + 534 + 1)
			}
			slices.SortFunc(proposal.Recipients, func(a, b contract.ApplyRecipientInput) int {
				return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
			})
			g.registry = &proposal
			shape, err := selectedContinuationFinalShape(t.Context(), &image, g, read)
			if tc.invalid {
				if !errors.Is(err, contract.ErrRecordCapacity) {
					t.Fatal("over-ceiling current binding reached Final sizing", err)
				}
				return
			}
			if err != nil {
				t.Fatal("merged Final shape", err)
			}
			count := tc.current + tc.added
			pages := uint32((count + 7) / 8)
			want := contract.GeneratorCapacityGroup{MaxCount: uint64(count), MaxPages: pages, MaxFramedBytes: wantBytes + uint64(8*pages)}
			if shape.registry != want {
				t.Fatal("Final bound does not measure accepted display and current existing bindings with pending rows", shape.registry, want)
			}
			slices.SortFunc(wantRows, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
			before := &StateSession{root: image.root, recipients: image.recipients}
			next := &StateSession{root: image.root}
			next.root.Snapshot, next.root.Transition = generatedVectorID(232), generatedVectorID(233)
			candidate := &Candidate{session: before}
			if err := next.installGeneratedRegistry(before, g, generatedVectorID(231), candidate); err != nil {
				t.Fatal("actual Final registry installation", err)
			}
			if next.root.RecipientCount != uint16(count) || !reflect.DeepEqual(next.registry(), wantRows) || len(candidate.objects) != int(pages) {
				t.Fatal("Final installer changed merged rows or count", next.root.RecipientCount, len(candidate.objects))
			}
			// The descriptor preimage is the fixed purpose label, domain, u16
			// page count, then each Ref's kind/version/domain/object/hash/length/index.
			projection := append([]byte("ENKV/CRYPTO/v2/recipient-refs\x00"), image.root.Domain[:]...)
			projection = binary.BigEndian.AppendUint16(projection, uint16(pages))
			var encoded uint64
			for i, object := range candidate.objects {
				ref := object.ref
				if ref.Kind != contract.RecipientKind || ref.Format != 11 || ref.Domain != image.root.Domain || ref.Index != uint16(i) ||
					ref.Length != uint32(len(object.body)) || ref.Digest != contract.ID(sha256.Sum256(object.body)) ||
					next.root.Recipients[i] == nil || *next.root.Recipients[i] != ref {
					t.Fatal("Final candidate object does not match its exact Root reference", i)
				}
				page, err := format.DecodeRecipientPage(object.body)
				if err != nil || page.Domain != ref.Domain || page.Object != ref.Object || page.Index != ref.Index {
					t.Fatal("Final candidate recipient page cannot be read", i, err)
				}
				var rowBytes uint64
				for slot, row := range page.Slots {
					at := 8*i + slot
					if at >= count {
						if row != nil {
							t.Fatal("Final candidate retained an extra recipient", i, slot)
						}
						continue
					}
					if row == nil || !reflect.DeepEqual(*row, wantRows[at]) {
						t.Fatal("Final candidate bytes changed an expected recipient", i, slot)
					}
					rowBytes += uint64(41 + len(wantRows[at].DisplayName) + 534 + len(wantRows[at].CurrentBinding.KeySelector))
				}
				if uint64(len(object.body)) != rowBytes+74 {
					t.Fatal("Final candidate has incorrect physical page bytes", i)
				}
				projection = append(projection, byte(ref.Kind))
				projection = binary.BigEndian.AppendUint16(projection, 11)
				projection = append(projection, ref.Domain[:]...)
				projection = append(projection, ref.Object[:]...)
				projection = append(projection, ref.Digest[:]...)
				projection = binary.BigEndian.AppendUint32(projection, ref.Length)
				projection = binary.BigEndian.AppendUint16(projection, ref.Index)
				encoded += uint64(len(object.body))
			}
			wantDescriptor := contract.DescriptorVector{Count: pages, Length: uint64(len(projection)), Digest: contract.ID(sha256.Sum256(projection))}
			if next.root.CurrentAccess.Core.RecipientRefsDescriptor != wantDescriptor {
				t.Fatal("Final installer did not bind its complete exact recipient pages", next.root.CurrentAccess.Core.RecipientRefsDescriptor, wantDescriptor)
			}
			// Physical recipient pages have a 74-byte header. The prospective
			// capacity group deliberately keeps its existing eight-byte/page
			// slack before the generic 75-byte page header is restored.
			wantEncoded := wantBytes + uint64(74*pages)
			if encoded != wantEncoded ||
				shape.registry.MaxFramedBytes+uint64(75*pages) != wantEncoded+uint64(9*pages) {
				t.Fatal("actual Final encoding differs from independent physical bytes or conservative capacity bound", len(candidate.objects), encoded, wantEncoded, want)
			}
		})
	}
}
