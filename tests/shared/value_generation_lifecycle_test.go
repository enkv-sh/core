package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type generatedReadbackStore struct {
	contract.Store
	memory *memoryStore
	body   []byte
}

func (s *generatedReadbackStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}

func (s generatedReadbackStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	result := s.Store.CompareAndSwap(ctx, key, token, body)
	if result.Status == contract.WriteAcknowledged {
		s.memory.mu.Lock()
		s.memory.put(key, s.body)
		s.memory.mu.Unlock()
	}
	return result
}

func generatedPrivateCandidate(t testing.TB, p *generatedPreparation) custody.GeneratedCandidate {
	t.Helper()
	s := p.reservation.state
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil || s.head.Generator == nil {
		t.Fatal("candidate selection", err)
	}
	c := custody.GeneratedCandidate{ActiveOwner: s.root.Generated.ActiveOwner, ActivePhase: s.root.Generated.ActivePhase, ActiveGraph: s.root.Generated.ActiveGraph,
		Subject: *s.head.Generator, CurrentAccess: s.root.CurrentAccess.Core, AccessRecords: s.accessRecords(), SupportRecords: selectedSupportRecordsForCustodyFixture(t, s)}
	if g.parent != nil {
		c.LiveSourceUses, c.SourceProtections = g.sources[g.parent.MaterialID], g.protected[g.parent.MaterialID]
	}
	c.PublicState, err = s.publicProjection()
	if err != nil {
		t.Fatal("candidate public projection", err)
	}
	for _, entry := range s.root.Names {
		c.Entries = append(c.Entries, custody.GeneratedCandidateEntry{Slot: entry.Slot, Entry: *s.valueEntry(entry.Slot)})
	}
	c.HeadCore, err = format.EncodeHeadCore(s.head.Core)
	if err != nil {
		t.Fatal(err)
	}
	c.Conditional, err = format.EncodeConditionalPlan(conditional(s.head.Core, c.HeadCore))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func generatedCanonicalInputs(t testing.TB, s *StateSession, g *generatedSelection, declarationBody []byte) []custody.GeneratedCanonicalSelection {
	t.Helper()
	if g.parent == nil || len(g.bundles) == 0 || g.bundles[0].UsePlan.PlanGraphID != g.parent.PlanGraphID {
		t.Fatal("canonical input active graph unavailable")
	}
	if generatedSelectionAnchored(g) {
		return nil
	}
	operation := g.bundles[0].Request.OperationKind
	if operation == contract.OperationCleanOwnedFailureResidue || operation == contract.OperationRetireGeneratedGeneration {
		declaration, err := contract.InspectGeneratorDeclaration(declarationBody)
		if err != nil {
			t.Fatal("delete current canonical declaration", err)
		}
		var out []custody.GeneratedCanonicalSelection
		for i := 0; i < declaration.EntryCount(); i++ {
			entry, _, err := declaration.Entry(i)
			if err != nil {
				t.Fatal("delete current canonical entry", err)
			}
			if entry.Kind != contract.GeneratorDeclarationRetained {
				continue
			}
			record, err := contract.DecodeRetainedCanonicalRecord(entry.Payload)
			if err != nil {
				t.Fatal("delete current canonical record", err)
			}
			selection := sessionConsumerSelection(t, s, s.admission.recipient, record.Entry.Name)
			current := contract.RetainedCanonicalRecord{OriginalSlot: selection.Slot, Entry: selection.Entry}
			body, err := contract.EncodeRetainedCanonicalRecord(current)
			if err != nil || !bytes.Equal(body, entry.Payload) {
				t.Fatal("delete current canonical differs from selected predecessor", err)
			}
			out = append(out, ownScenarioCanonicalSelection(custody.GeneratedCanonicalSelection{Selection: selection, Record: record}))
		}
		return out
	}
	var out []custody.GeneratedCanonicalSelection
	seen := make(map[contract.ID]bool)
	for value, source := range g.canonical {
		if !g.declaredCanonicals[value] {
			continue
		}
		// Legacy material-keyed and admission-keyed support can name the
		// same complete record. Its declaration needs one private selection;
		// both durable sources and their typed owners remain selected.
		sourceID, err := contract.AdmissionEntryDigest(source.record)
		if err != nil {
			t.Fatal("canonical input source identity", err)
		}
		if seen[sourceID] {
			continue
		}
		seen[sourceID] = true
		uses := slices.DeleteFunc(slices.Clone(g.consumers[materialIdentity{1, source.core.ValueStateID}]), func(row contract.GeneratorConsumer) bool { return row.SubjectID != value })
		if len(uses) == 0 {
			t.Fatal("canonical input has no consumer")
		}
		owner := generatedRecordKey{10, uses[0].OwnerID}
		if _, ok := g.records[owner]; !ok {
			owner.kind = 11
		}
		selection, err := g.canonicalConsumer(owner, source.core.ValueStateID, g.session.admission.recipient)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, selection)
	}
	slices.SortFunc(out, func(a, b custody.GeneratedCanonicalSelection) int {
		return int(a.Record.OriginalSlot) - int(b.Record.OriginalSlot)
	})
	return out
}

func generatedCurrentIntentInputs(ctx context.Context, t testing.TB, s *StateSession, graphBody, declarationBody []byte) []contract.GeneratedCurrentIntentSelection {
	t.Helper()
	graph, err := contract.DecodeGeneratorPlanBundle(graphBody)
	if err != nil {
		t.Fatal("private current intent graph", err)
	}
	declaration, err := contract.InspectGeneratorDeclaration(declarationBody)
	if err != nil {
		t.Fatal("private current intent declaration", err)
	}
	facts, err := s.generatedPlanCurrentIntents(ctx, graph, declaration)
	if err != nil {
		t.Fatal("private current intent selection", err)
	}
	return facts
}

func generatedCurrentValueInputs(t testing.TB, s *StateSession, graph contract.GeneratorPlanBundle, body []byte) []contract.ConsumerSelection {
	t.Helper()
	declaration, err := contract.InspectGeneratorDeclaration(body)
	if err != nil {
		t.Fatal(err)
	}
	var out []contract.ConsumerSelection
	for i, plan := range graph.ValueEntryPlans {
		if plan.ConfidentialityClass != contract.Secret {
			continue
		}
		entry, _, err := declaration.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		current := s.valueEntry(plan.Slot)
		if current == nil || current.Name != plan.Name || current.ConfidentialityClass != contract.Secret {
			continue
		}
		changed := plan.ChangeMask&contract.GeneratorValueChangeContent != 0
		readers := make([]contract.ID, len(entry.RecipientIDs)/32)
		for j := range readers {
			readers[j] = contract.ID(entry.RecipientIDs[j*32 : (j+1)*32])
		}
		unchangedSealed := !changed && plan.ValueSource == contract.Supplied && entry.Kind == contract.GeneratorDeclarationSealed && current.ValueSource == contract.Supplied
		changedExclusion := changed && entry.Kind != contract.GeneratorDeclarationRetained && generatedFinalExcludesReader(*current, readers)
		if unchangedSealed || changedExclusion {
			out = append(out, sessionConsumerSelection(t, s, s.admission.recipient, plan.Name))
		}
	}
	slices.SortFunc(out, func(a, b contract.ConsumerSelection) int { return int(a.Slot) - int(b.Slot) })
	return out
}

func selectedGeneratedCommonPrivateFacts(ctx context.Context, t testing.TB, s *StateSession, g *generatedSelection) (custody.GeneratedSessionInput, custody.GeneratedPlanInput, custody.GeneratedCustodyInput) {
	t.Helper()
	core := s.root.CurrentAccess.Core
	session := custody.GeneratedSessionInput{BeforeAccess: &core, BeforeAccessRecords: s.accessRecords()}
	for _, row := range s.supportRecords() {
		if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == s.root.Generated.ActiveOwner && row.RecordID == g.parent.OperationID {
			phase, err := contract.InspectGeneratedPhaseRecord(row.Body)
			if err != nil {
				t.Fatal("selected predecessor Phase", err)
			}
			session.SelectionPhase = &phase
		}
	}
	anchored := session.SelectionPhase != nil && !session.SelectionPhase.SelectionPhaseID.IsZero()
	plan := custody.GeneratedPlanInput{LiveSourceUses: g.sources[g.parent.MaterialID]}
	owned := custody.GeneratedCustodyInput{SourceProtections: g.protected[g.parent.MaterialID]}
	var err error
	if g.content.fragmentFacts != nil {
		session.Graph, err = g.readSelectedSlice(ctx, contract.GeneratorContentGraph, g.parent.PlanGraphID, contract.GeneratorGraphMaxLength-8)
	} else {
		session.Graph, err = g.content.read(contract.GeneratorContentGraph, g.parent.PlanGraphID, contract.GeneratorGraphMaxLength-8)
	}
	if err != nil {
		t.Fatal(err)
	}
	if g.content.fragmentFacts != nil {
		plan.Declaration, err = g.readSelectedSlice(ctx, contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	} else {
		plan.Declaration, err = g.content.read(contract.GeneratorContentDeclaration, g.parent.OperationID, contract.GeneratorDeclarationMaxLength)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !anchored {
		plan.CurrentIntents = generatedCurrentIntentInputs(ctx, t, s, session.Graph, plan.Declaration)
		plan.CurrentValues = generatedCurrentValueInputs(t, s, g.bundles[0], plan.Declaration)
	}
	seed, ok := g.session.materialAccess(3, g.parent.MaterialID)
	if !ok {
		t.Fatal("selected seed access")
	}
	owned.SeedAccess, err = contract.EncodeAccessRecord(seed)
	if err != nil {
		t.Fatal(err)
	}
	session.BeforePublic, err = s.publicProjection()
	if err != nil {
		t.Fatal(err)
	}
	var desiredOutput [][]ApplyEntryInput
	switch g.bundles[0].Request.OperationKind {
	case contract.OperationApplyDeclaration, contract.OperationRotateValueEntryValue:
		declaration, err := contract.InspectGeneratorDeclaration(plan.Declaration)
		if err != nil {
			t.Fatal("private selected desired declaration", err)
		}
		desired, err := generatedDeclarationOutputEntries(declaration)
		if err != nil {
			t.Fatal("private selected desired output entries", err)
		}
		desiredOutput = [][]ApplyEntryInput{desired}
	}
	session.Output, err = s.generatedOutputTransition(ctx, desiredOutput...)
	if err != nil {
		t.Fatal("private selected output transition", err)
	}
	return session, plan, owned
}

func selectedGeneratedPrivateFacts(ctx context.Context, t testing.TB, s *StateSession, g *generatedSelection, attempt contract.ID) (
	custody.GeneratedSessionInput, custody.GeneratedPlanInput, custody.GeneratedCustodyInput,
	contract.GeneratorResultExpectation, *contract.GeneratorTarget, *custody.GeneratedControlledPredecessor,
) {
	t.Helper()
	session, plan, owned := selectedGeneratedCommonPrivateFacts(ctx, t, s, g)
	a := g.attempts[attempt]
	owned.Material = a.material
	var target *contract.GeneratorTarget
	var controlled *custody.GeneratedControlledPredecessor
	if a.record.CompletionClass == contract.GeneratedCompletionConfirmed && a.expected.Template.Action == 2 {
		selected := mustSelectedGeneratedWork(t, s)
		source, e := selected.generatedDeleteSource(a.record.OwnerID)
		if e != nil {
			t.Fatal(e)
		}
		predecessor := generatedControlledSourcePredecessorInput(t, s, selected, source)
		controlled = &predecessor
		graph, e := g.retainedGraph(a.record.OperationID)
		if e != nil {
			t.Fatal(e)
		}
		deleteTarget, e := g.generatedDeleteAttemptTarget(ctx, graph, a.record)
		if e != nil {
			t.Fatal(e)
		}
		target = &deleteTarget
	}
	return session, plan, owned, a.expected, target, controlled
}

func generatedProducerInput(ctx context.Context, t testing.TB, s *StateSession, g *generatedSelection, attempt contract.ID) custody.GeneratedProducerInput {
	session, plan, owned, expected, target, controlled := selectedGeneratedPrivateFacts(ctx, t, s, g, attempt)
	input := custody.GeneratedProducerInput{Session: session, Plan: plan, Custody: owned, Expected: expected,
		Target: target, ControlledPredecessor: controlled}
	if target != nil {
		original, err := g.createTargetEvidence(ctx, *target)
		if err != nil {
			t.Fatal(err)
		}
		input.OriginalFacts, err = contract.EncodeGeneratorSafeFacts(original.GeneratorSafeFacts)
		if err != nil {
			t.Fatal(err)
		}
	}
	return input
}

func generatedAdoptionInput(ctx context.Context, t testing.TB, s *StateSession, g *generatedSelection, attempt contract.ID) custody.GeneratedAdoptionInput {
	session, plan, owned, expected, target, controlled := selectedGeneratedPrivateFacts(ctx, t, s, g, attempt)
	return custody.GeneratedAdoptionInput{Session: session, Plan: plan, Custody: owned, Expected: expected,
		Target: target, ControlledPredecessor: controlled}
}

// The trusted fixture parent borrows only authenticated selected predecessor
// facts for this synchronous private handoff. Runtime owns its access copies;
// these value bodies are already owned by the selected closure and its census.
func generatedFinalCanonicalAccess(t testing.TB, s *StateSession, g *generatedSelection, output *contract.GeneratedOutputTransition) []contract.ConsumerSelection {
	t.Helper()
	reader := s.recipientRecord(s.admission.recipient)
	if reader == nil || reader.CurrentBinding == nil {
		t.Fatal("canonical access acting binding")
	}
	byMaterial := make(map[contract.ID]contract.ConsumerSelection)
	for _, row := range output.Retained {
		source, ok := g.canonical[row.RecordID]
		if !ok {
			t.Fatal("selected canonical access source missing")
		}
		if _, present := byMaterial[source.core.ValueStateID]; present {
			continue
		}
		digest, err := contract.PublicValueEntryDigest(s.root.Domain, source.record.OriginalSlot, source.record.Entry)
		if err != nil {
			t.Fatal(err)
		}
		byMaterial[source.core.ValueStateID] = contract.ConsumerSelection{DomainID: s.root.Domain,
			SnapshotID: s.root.Snapshot, HEADDigest: contract.Hash(s.body), AccessRoot: s.root.CurrentAccess.AccessRoot,
			Root: s.head.Core.Root, HEADRevision: s.head.Core.Revision, HEADToken: s.token,
			Slot: source.record.OriginalSlot, EntryDigest: digest, Entry: source.record.Entry, Core: source.core,
			Payload: source.payload, Access: source.access,
			Binding: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: s.admission.recipient, Binding: *reader.CurrentBinding}}
	}
	out := make([]contract.ConsumerSelection, 0, len(byMaterial))
	for _, selection := range byMaterial {
		out = append(out, selection)
	}
	slices.SortFunc(out, func(a, b contract.ConsumerSelection) int {
		return bytes.Compare(a.Core.ValueStateID[:], b.Core.ValueStateID[:])
	})
	return out
}

func generatedFinalInput(ctx context.Context, t testing.TB, s *StateSession, g *generatedSelection, attempt contract.ID) custody.GeneratedFinalInput {
	session, plan, owned, expected, target, controlled := selectedGeneratedPrivateFacts(ctx, t, s, g, attempt)
	input := custody.GeneratedFinalInput{Session: session, Plan: plan, Custody: owned, CanonicalAccess: generatedFinalCanonicalAccess(t, s, g, session.Output),
		ExpectedResults: []contract.GeneratorResultExpectation{expected}, Target: target, ControlledPredecessor: controlled}
	for _, entryPlan := range g.bundles[0].ValueEntryPlans {
		if entryPlan.ConfidentialityClass != contract.Secret || entryPlan.ChangeMask&contract.GeneratorValueChangeMembership == 0 || entryPlan.ChangeMask&contract.GeneratorValueChangeContent != 0 {
			continue
		}
		selection := custody.GeneratedMembershipSelection{Selection: sessionConsumerSelection(t, s, s.admission.recipient, entryPlan.Name)}
		input.Membership = append(input.Membership, selection)
	}
	slices.SortFunc(input.Membership, func(a, b custody.GeneratedMembershipSelection) int {
		return int(a.Selection.Slot) - int(b.Selection.Slot)
	})
	return input
}

func admitPrivateGeneratedRecord(ctx context.Context, t testing.TB, keys *custody.Fixture, s *StateSession, plan *generatedRecordPlan) *admittedGeneratedRecord {
	t.Helper()
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	input := generatedAdoptionInput(ctx, t, s, g, plan.expected.Template.AttemptID)
	input.Plan.Canonical = generatedCanonicalInputs(t, s, g, input.Plan.Declaration)
	deadline := time.Unix(0, int64(plan.request.Context.Expiry))
	if err := keys.AdmitGeneratedRecord(plan.request, currentControlOf(s), input, plan.phase, plan.reference, deadline); err != nil {
		t.Fatal("record private admission", err)
	}
	return &admittedGeneratedRecord{session: s, plan: plan, crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), deadline: deadline}
}

func preparePrivateGeneratedRecord(t testing.TB, env fixtureEnvironment, s *StateSession, plan *generatedRecordPlan) *generatedPreparation {
	t.Helper()
	ctx, keys := env.operationContext(), env.Custody
	permit := admitPrivateGeneratedRecord(ctx, t, keys, s, plan)
	p, res := s.PrepareGeneratedRecord(ctx, permit)
	if p == nil || res.Outcome != ObservedCurrent {
		t.Fatal("record private preparation", res)
	}
	if code := keys.BindGeneratedCandidate(ctx, plan.request.Context.AdmissionID, generatedPrivateCandidate(t, p)); code != contract.CryptoSuccess {
		t.Fatal("record private candidate", code)
	}
	if candidate, res := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust); candidate == nil || res.Outcome != ObservedCurrent {
		t.Fatal("record claim", res)
	}
	return p
}

func preparePrivateGeneratedSuccessorReservation(t *testing.T, env fixtureEnvironment, s *StateSession) *generatedPreparation {
	t.Helper()
	env.Custody.RetireGenerated()
	admitted := generatedPlanInputFixture(t, s).context
	phase := fmt.Sprintf("%x", s.root.Generated.ActivePhase)
	admitted.AdmissionID, admitted.SessionID = testID("generated successor reserve admission"+phase), testID("generated successor reserve session"+phase)
	plan, err := s.generatedSuccessorReservationRequest(t.Context(), admitted)
	if err != nil {
		t.Fatal("successor reservation request", err)
	}
	permit := &admittedGeneratedSuccessorReservation{session: s, plan: plan}
	prior, result := s.PrepareGeneratedSuccessorReservation(env.operationContext(), permit)
	if prior == nil || result.Outcome != ObservedCurrent || prior.producerPhase == nil ||
		prior.producerPhase.TransitionKind != contract.GeneratorAuthorityReservation || prior.reservation.candidate.firstSend != nil {
		t.Fatal("successor reservation preparation granted the wrong phase or a send", result)
	}
	return prior
}

func generatedFinalCheckpointSupport(t testing.TB, s *StateSession, g *generatedSelection) []contract.SupportRecord {
	t.Helper()
	rows, err := s.workSupportRecords(t.Context())
	if err != nil {
		t.Fatal("Final checkpoint selected support", err)
	}
	fragments, err := s.selectedFragmentFactsByRecord()
	if err != nil {
		t.Fatal("Final checkpoint selected fragment facts", err)
	}
	oldBlobs := make(map[contract.ID]bool)
	if g.preparation != nil {
		for key, location := range g.content.locations {
			if key.kind == contract.GeneratorContentFinalPreparation && key.id == g.preparation.Image.ContentID {
				shared := false
				for other, selected := range g.content.locations {
					shared = shared || other != key && selected.BlobID == location.BlobID
				}
				if !shared {
					oldBlobs[location.BlobID] = true
				}
			}
		}
	}
	var selected []contract.SupportRecord
	for _, row := range rows {
		keep := (row.Kind == contract.GeneratedPhaseSupportKind || row.Kind == contract.GeneratedFinalPreparationSupportKind) && row.RecordID == g.parent.OperationID
		if row.Kind == contract.GeneratorVectorSupportKind {
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				t.Fatal("Final checkpoint selected vector", err)
			}
			keep = carrier.OwnerKind == contract.GeneratorSnapshotOwner && carrier.VectorKind == contract.GeneratorVectorSlices
		}
		if row.Kind == contract.GeneratedFragmentSupportKind {
			blob, err := generatedSelectedFragmentBlob(row, fragments)
			if err != nil {
				t.Fatal("Final checkpoint selected fragment", err)
			}
			keep = oldBlobs[blob]
		}
		if !keep {
			continue
		}
		if row.Body == nil {
			found := false
			for _, page := range s.supportFacts {
				for logical, fact := range page.rows {
					if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
						continue
					}
					if found {
						t.Fatal("duplicate Final checkpoint support fact")
					}
					found = true
					result, err := withAuthenticatedSupportRow(t.Context(), s.readObjectBorrowedUncached, s.root.Domain, page, uint16(logical), func(view contract.SupportRecordView) error {
						actual, err := contract.InspectSupportRecordDigest(s.root.Domain, contract.SupportRecord(view))
						if err != nil || actual != fact {
							return contract.ErrRecord
						}
						row.Body = bytes.Clone(view.Body)
						return nil
					})
					if err != nil || result != (Result{}) {
						t.Fatal("Final checkpoint authenticated support", result, err)
					}
				}
			}
			if !found || row.Body == nil {
				t.Fatal("Final checkpoint support unavailable")
			}
		}
		selected = append(selected, row)
	}
	return selected
}

func admitPrivateGeneratedFinal(t testing.TB, env fixtureEnvironment, s *StateSession, plan *generatedFinalPlan, capture ...contract.Crypto) *admittedGeneratedFinal {
	t.Helper()
	keys := env.Custody
	keys.RetireGenerated()
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("final selected work", err)
	}
	attempt := g.phase.FrontierAttemptID
	if len(plan.results) != 0 {
		attempt = plan.results[0].attempt.record.AttemptID
	}
	input := generatedFinalInput(env.operationContext(), t, s, g, attempt)
	if plan.selecting && len(plan.entryPlans) != 0 && plan.materialization == nil {
		input.CheckpointSupport = generatedFinalCheckpointSupport(t, s, g)
	}
	if plan.materialization != nil || plan.qualifyLegacy {
		image, err := s.generatedFinalPreparationImage(t.Context(), g)
		if err != nil {
			t.Fatal("selected Final preparation image", err)
		}
		input.PreparedImage, err = contract.EncodeGeneratedFinalPreparationImage(image)
		image.Clear()
		if err != nil {
			t.Fatal("selected Final preparation codec", err)
		}
		preparation, phase := *g.preparation, *g.phase
		input.Preparation, input.PreparationPhase = &preparation, &phase
		input.QualifyLegacy = plan.qualifyLegacy
	}
	input.Plan.Canonical = generatedCanonicalInputs(t, s, g, input.Plan.Declaration)
	input.ExpectedResults = make([]contract.GeneratorResultExpectation, len(plan.results))
	input.ResultBodies = make([][]byte, len(plan.results))
	references := make([]contract.GeneratorResultReference, len(plan.results))
	for i := range plan.results {
		input.ExpectedResults[i], references[i] = plan.results[i].attempt.expected, plan.results[i].reference
		input.ResultBodies[i] = plan.results[i].attempt.result
	}
	if !plan.selecting {
		input.Membership = nil
	}
	entryAdmissions := make([]custody.GeneratedEntryAdmission, len(plan.entryPlans))
	for i := range plan.entryPlans {
		entryAdmissions[i] = custody.GeneratedEntryAdmission{Slot: plan.entryPlans[i].Slot, Generated: plan.entryPlans[i].Generated}
	}
	for i, expected := range input.ExpectedResults {
		if err := expected.Validate(input.Custody.Material); err != nil || expected.Plan != g.bundles[0].UsePlan ||
			references[i].ResultID != expected.Use.ResultID {
			t.Fatal("final result private preflight", i, err)
		}
		if !plan.selecting {
			r, err := contract.DecodeGeneratedResultRecord(input.ResultBodies[i])
			if err != nil || contract.ValidateGeneratedResult(expected, input.Custody.Material, r) != nil {
				t.Fatal("final sealed result private preflight", i, expected.Template.Branch, r.SafeFacts.Disposition, err)
			}
		}
	}
	for i, entryAdmission := range entryAdmissions {
		if _, err := contract.GeneratedEntryMetadataLength(entryAdmission.Generated); err != nil {
			t.Fatal("final member private preflight", i, err)
		}
	}
	deadline := time.Unix(0, int64(plan.request.Context.Expiry))
	defer clear(input.PreparedImage[:cap(input.PreparedImage)])
	if err := keys.AdmitGeneratedValueEntries(plan.request, currentControlOf(s), input, plan.phase, references, entryAdmissions, deadline); err != nil {
		t.Fatal("final private admission", err)
	}
	permit := &admittedGeneratedFinal{session: s, plan: plan, crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), deadline: deadline}
	if len(capture) > 1 {
		t.Fatal("multiple final capture clients")
	}
	if len(capture) == 1 {
		permit.crypto = capture[0]
	}
	return permit
}

func preparePrivateGeneratedFinal(t testing.TB, env fixtureEnvironment, s *StateSession, plan *generatedFinalPlan, capture ...contract.Crypto) (*StateSession, *generatedPreparation) {
	t.Helper()
	return preparePrivateGeneratedFinalWithCheckpoint(t, env, s, plan, nil, capture...)
}

// The fresh-process fixture uses this collector to retain the exact checkpoint
// object set before selection, separately from the actual Final object set.
func preparePrivateGeneratedFinalWithCheckpoint(t testing.TB, env fixtureEnvironment, s *StateSession, plan *generatedFinalPlan, observeCheckpoint func(*Candidate), capture ...contract.Crypto) (*StateSession, *generatedPreparation) {
	t.Helper()
	ctx, keys := env.operationContext(), env.Custody
	expiry := plan.request.Context.Expiry
	// Selecting generated Final has one durable preparation selection followed
	// by actual Final. Direct and nonselecting paths keep their original base.
	for stage := range 2 {
		permit := admitPrivateGeneratedFinal(t, env, s, plan, capture...)
		p, res := s.PrepareGeneratedFinal(ctx, permit)
		if p == nil || res.Outcome != ObservedCurrent {
			t.Fatal("final private preparation", res)
		}
		if code := keys.BindGeneratedCandidate(ctx, plan.request.Context.AdmissionID, generatedPrivateCandidate(t, p)); code != contract.CryptoSuccess {
			t.Fatal("final private candidate", code)
		}
		if candidate, res := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust); candidate == nil || res.Outcome != ObservedCurrent {
			t.Fatal("final claim", res)
		}
		if generator := p.reservation.candidate.head.Generator; generator == nil || generator.Purpose != contract.GeneratorAuthorityFinalPreparation {
			return s, p
		}
		if stage != 0 {
			t.Fatal("actual Final repeated its preparation checkpoint")
		}
		if observeCheckpoint != nil {
			observeCheckpoint(p.reservation.candidate)
		}
		base, result := s.selectCandidate(ctx, p.reservation.candidate)
		if base == nil || base == s || result.Outcome != ObservedCurrent || !bytes.Equal(base.body, p.reservation.candidate.body) ||
			base.root.Generated.ActiveOwner != s.root.Generated.ActiveOwner || base.root.Generated.ActiveOwner.IsZero() ||
			!reflect.DeepEqual(base.currentEntryInputs(), s.currentEntryInputs()) || !reflect.DeepEqual(base.accessRecords(), s.accessRecords()) ||
			!reflect.DeepEqual(base.root.CurrentAccess, s.root.CurrentAccess) || !reflect.DeepEqual(base.root.ValueEntryPages, s.root.ValueEntryPages) ||
			!reflect.DeepEqual(base.root.Recipients, s.root.Recipients) {
			t.Fatal("Final preparation checkpoint changed current state or failed selection", result)
		}
		work := mustSelectedGeneratedWork(t, base)
		if work.parent == nil || work.phase == nil || work.preparation == nil || work.parent.OperationID != base.root.Generated.ActiveOwner ||
			work.phase.FinalPreparationID.IsZero() || work.phase.FinalPreparationID != work.preparation.Image.ContentID {
			t.Fatal("selected checkpoint lost exact active-parent preparation association")
		}
		keys.RetireGenerated()
		admitted := generatedPlanInputFixture(t, base).context
		identity := fmt.Sprintf("%x", base.root.Generated.ActivePhase)
		admitted.AdmissionID, admitted.SessionID = testID("generated final after preparation admission "+identity), testID("generated final after preparation session "+identity)
		admitted.Expiry = expiry
		freshPlan, err := base.generatedFinalRequest(ctx, admitted)
		if err != nil || freshPlan == nil || freshPlan.request.Context.Expiry != expiry {
			t.Fatal("fresh actual Final request did not retain its admitted deadline", err)
		}
		s, plan = base, freshPlan
	}
	t.Fatal("Final preparation checkpoint did not produce actual Final")
	return nil, nil
}

func preparePrivateGeneratedReservation(t testing.TB, env fixtureEnvironment, s *StateSession, input generatedPlanInput, canonical []custody.GeneratedCanonicalSelection) (*generatedPreparation, *admittedGeneratedPlan) {
	t.Helper()
	p, permit := prepareUnclaimedGeneratedReservation(t, env, s, input, canonical)
	ctx, keys := env.operationContext(), env.Custody
	if code := keys.BindGeneratedCandidate(ctx, p.operation.context.AdmissionID, generatedPrivateCandidate(t, p)); code != contract.CryptoSuccess {
		t.Fatal("private candidate binding", code)
	}
	if candidate, res := claimGeneratedScenarioPreparation(ctx, s, p, env.Trust); candidate == nil || res.Outcome != ObservedCurrent {
		t.Fatal("private claim", res)
	}
	return p, permit
}

func admitUnclaimedGeneratedReservation(t testing.TB, env fixtureEnvironment, s *StateSession, input generatedPlanInput, canonical []custody.GeneratedCanonicalSelection) (*admittedGeneratedPlan, error) {
	t.Helper()
	ctx, keys := env.operationContext(), env.Custody
	plan, err := s.generatedPlanRequest(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("generated Core plan: %w", err)
	}
	graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
	if err != nil {
		t.Fatal("private graph encoding", err)
	}
	public, err := s.publicProjection()
	if err != nil {
		t.Fatal("private public projection", err)
	}
	var desiredOutput [][]ApplyEntryInput
	switch input.graph.Request.OperationKind {
	case contract.OperationApplyDeclaration, contract.OperationRotateValueEntryValue:
		declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
		if err != nil {
			t.Fatal("private reservation desired declaration", err)
		}
		desired, err := generatedDeclarationOutputEntries(declaration)
		if err != nil {
			t.Fatal("private reservation desired output entries", err)
		}
		desiredOutput = [][]ApplyEntryInput{desired}
	}
	output, err := s.generatedOutputTransition(ctx, desiredOutput...)
	if err != nil {
		t.Fatal("private reservation desired output transition", err)
	}
	currentIntents := generatedCurrentIntentInputs(ctx, t, s, graph, input.declaration)
	currentValues := generatedCurrentValueInputs(t, s, input.graph, input.declaration)
	deadline := time.Unix(0, int64(input.context.Expiry))
	var admitErr error
	if plan.phase != nil {
		selected, err := s.selectedGeneratedWork(ctx)
		if err != nil {
			t.Fatal("private delete predecessor", err)
		}
		deletion, ok, selectionErr := s.generatedDeleteReservationSelection(ctx, input.graph, selected)
		if selectionErr != nil || !ok || deletion.phase != *plan.phase {
			t.Fatal("private delete target differs from the selected obligation")
		}
		if deletion.source.CompletionClass == contract.GeneratedCompletionConfirmed {
			predecessor := generatedControlledSourcePredecessorInput(t, s, selected, deletion.source)
			admitErr = keys.AdmitGeneratedControlledDeletePlan(plan.request, currentControlOf(s),
				custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output},
				custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: canonical, CurrentIntents: currentIntents, CurrentValues: currentValues}, *plan.phase, deletion.target, predecessor, deadline)
		} else {
			admitErr = keys.AdmitGeneratedDeletePlan(plan.request, currentControlOf(s),
				custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output},
				custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: canonical, CurrentIntents: currentIntents, CurrentValues: currentValues}, *plan.phase, deletion.target, deadline)
		}
	} else {
		admitErr = keys.AdmitGeneratedPlan(plan.request, currentControlOf(s),
			custody.GeneratedSessionInput{Graph: graph, BeforePublic: public, Output: output},
			custody.GeneratedPlanInput{Declaration: input.declaration, Canonical: canonical, CurrentIntents: currentIntents, CurrentValues: currentValues}, deadline)
	}
	if admitErr != nil {
		return nil, fmt.Errorf("generated private admission: %w", admitErr)
	}
	t.Cleanup(keys.RetireGenerated)
	permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), deadline: deadline}
	return permit, nil
}

func prepareUnclaimedGeneratedReservation(t testing.TB, env fixtureEnvironment, s *StateSession, input generatedPlanInput, canonical []custody.GeneratedCanonicalSelection) (*generatedPreparation, *admittedGeneratedPlan) {
	t.Helper()
	permit, err := admitUnclaimedGeneratedReservation(t, env, s, input, canonical)
	if err != nil {
		t.Fatal("reservation admission", err)
	}
	ctx := env.operationContext()
	p, res := s.PrepareGeneratedPlan(ctx, permit)
	if p == nil || res.Outcome != ObservedCurrent {
		t.Fatal("private preparation", res)
	}
	spy := &scenarioSpy{}
	store := s.store
	s.store = scenarioStore{Store: store, spy: spy}
	candidate, _ := s.persistCandidate(ctx, p.reservation.candidate, scenarioTrust{Trust: env.Trust, spy: spy})
	s.store = store
	if candidate != nil || spy.StoreCreate != 0 || spy.StoreCAS != 0 || spy.TrustSign != 0 {
		t.Fatal("unclaimed candidate reached persistence")
	}
	return p, permit
}

// full_only: false
func TestGeneratedSelectionProtectsExactSources(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for mode := uint8(0); mode < 3; mode++ {
			cases := []string{"exact", "authority seed", "seed context", "seed binding", "missing seed"}
			if recovery {
				cases = append(cases, "recovery seed")
			}
			if mode == 2 {
				cases = append(cases, "canonical packet", "canonical context", "canonical binding", "missing canonical")
			}
			for _, damage := range cases {
				t.Run(fmt.Sprintf("recovery%t/source%d/%s", recovery, mode, damage), func(t *testing.T) {
					ctx := context.Background()
					env, keys := genesisEnvironment(t, contract.GCP, recovery)
					run := newScenarioRun(t, ctx, env)
					f := newEnvironmentFixture(t, ctx, run.env, nil, false)
					input, canonical := generatedSourcePlanInput(t, run, f, mode)
					s := f.session
					store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
					creates, cas, signs, before := store.creates, store.cas, trust.signs, bytes.Clone(s.body)
					p, _ := prepareUnclaimedGeneratedReservation(t, env, s, input, canonical)
					admitted := p.operation.context
					admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("unclaimed producer admission"), testID("unclaimed producer session"), contract.DescriptorVector{}
					if _, _, err := s.generatedProducerRequest(context.Background(), p, admitted); err == nil {
						t.Fatal("unclaimed preparation granted producer admission")
					}
					candidate := generatedPrivateCandidate(t, p)
					// The caller owns these test inputs independently of Core's candidate.
					for i, row := range candidate.AccessRecords {
						body, err := contract.EncodeAccessRecord(row)
						if err != nil {
							t.Fatal(err)
						}
						candidate.AccessRecords[i], err = contract.DecodeAccessRecord(body)
						if err != nil {
							t.Fatal(err)
						}
					}
					if damage != "exact" {
						kind, material := uint16(3), input.graph.Header.MaterialID
						if damage == "canonical packet" || damage == "canonical context" || damage == "canonical binding" || damage == "missing canonical" {
							kind, material = 1, canonical[0].Record.Entry.ValueState
						}
						index := slices.IndexFunc(candidate.AccessRecords, func(row contract.AccessRecord) bool {
							return row.MaterialKind == kind && row.MaterialID == material
						})
						if index < 0 {
							t.Fatal("fixture has no requested access")
						}
						row := &candidate.AccessRecords[index]
						switch damage {
						case "missing seed", "missing canonical":
							candidate.AccessRecords = slices.Delete(candidate.AccessRecords, index, index+1)
						case "seed context", "canonical context":
							row.MaterialContextDigest[0] ^= 1
						case "seed binding", "canonical binding":
							row.Wraps[0].BindingID[0] ^= 1
						default:
							subjectKind := uint8(1)
							if damage == "recovery seed" {
								subjectKind = 2
							}
							wrap := slices.IndexFunc(row.Wraps, func(v contract.WrapRow) bool { return v.SubjectKind == subjectKind })
							if wrap < 0 {
								t.Fatal("fixture has no requested wrap")
							}
							row.Wraps[wrap].RSACiphertext[0] ^= 1
						}
						// An omission contradicts the committed count. Other damage has
						// valid descriptors, so rejection must check the bound material.
						if damage != "missing seed" && damage != "missing canonical" {
							var err error
							candidate.CurrentAccess.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(env.Domain, candidate.AccessRecords)
							if err != nil {
								t.Fatal(err)
							}
							candidate.PublicState.AccessRoot, err = contract.AccessRoot(candidate.CurrentAccess)
							if err != nil {
								t.Fatal(err)
							}
							candidate.Subject.AfterAccessDigest = candidate.PublicState.AccessRoot
						}
					}
					code := keys.BindGeneratedCandidate(ctx, p.operation.context.AdmissionID, candidate)
					if damage != "exact" {
						if code == contract.CryptoSuccess {
							t.Fatal("changed protected candidate passed private binding")
						}
						if claimed, _ := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust); claimed != nil || p.claimed ||
							store.creates != creates || store.cas != cas || trust.signs != signs {
							t.Fatal("changed protected candidate reached persistence or signing")
						}
						if _, _, err := s.generatedProducerRequest(context.Background(), p, admitted); err == nil || p.reservation.candidate.bindFirstSend(p, func(context.Context, contract.ID) contract.CryptoResultCode {
							return contract.CryptoSuccess
						}) {
							t.Fatal("refused candidate gained producer admission or dispatch")
						}
						if result, _, code := keys.InvokeGeneratedProducer(ctx, p.operation.context.AdmissionID, testID("unadmitted locator"), testID("unadmitted authority")); code == contract.CryptoSuccess || len(result) != 0 {
							t.Fatal("refused candidate returned a producer result")
						}
						cold, res := Open(ctx, f.admission, env.Store)
						if cold == nil || res.Outcome != ObservedCurrent || !bytes.Equal(cold.body, before) {
							t.Fatal("refused candidate changed selected state", res)
						}
						return
					}
					if code != contract.CryptoSuccess {
						t.Fatal("exact candidate refused", code)
					}
					for i := range candidate.AccessRecords {
						candidate.AccessRecords[i].Wraps[0].RSACiphertext[0] ^= 1
					}
					if claimed, res := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust); claimed == nil || res.Outcome != ObservedCurrent {
						t.Fatal("caller mutation changed privately bound candidate", res)
					}
					producer, expected := preparePrivateGeneratedProducer(t, env, s, p, nil)
					calls := 0
					var result []byte
					if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
						calls++
						var code contract.CryptoResultCode
						result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
						return code
					}) || calls != 0 || store.cas != cas {
						t.Fatal("unselected candidate gained effect entry")
					}
					selected, res := s.selectCandidate(ctx, producer.reservation.candidate)
					if selected == nil || res.Outcome != ObservedCurrent || calls != 1 || len(result) == 0 {
						t.Fatal("exact selected producer failed", res)
					}
					cold, res := Open(ctx, f.admission, env.Store)
					if cold == nil || res.Outcome != ObservedCurrent {
						t.Fatal("pending result cold selection", res)
					}
					g, err := cold.selectedGeneratedWork(context.Background())
					if err != nil || g.phase.Phase != 1 || len(g.attempts) != 1 {
						t.Fatal("selected work lost its exact initial phase", err)
					}
					a := g.attempts[expected.Template.AttemptID]
					if a.expected != expected || len(a.result) != 0 || a.record.State != contract.GeneratedEffectTransmitted || a.record.RetryUsed != 0 {
						t.Fatal("absent selected result changed original work")
					}
					if mode == 2 {
						reader := fixtureID(env.Domain, "reader")
						retained, res := cold.generatedConsumerSelection(ctx, 10, a.record.OwnerID, canonical[0].Record.Entry.ValueState, reader)
						if res.Outcome != ObservedCurrent {
							t.Fatal("retained reader selection", res)
						}
						keys.SetDenied(cold.admission.recipient, true)
						check := keys.ConsumeGenerated(ctx, retained, custody.StandardValue)
						keys.SetDenied(cold.admission.recipient, false)
						if check.Code != contract.CryptoSuccess || !check.ValueMatched || check.SinkCalls != 1 || len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != reader {
							t.Fatal("retained consumer needed authority decryption", check)
						}
					}
					public, private := keys.Calls()
					want := cold.observed(Unchanged)
					if mode == 2 {
						want = refused(AdmissionInvalid) // Current secrets require private comparison admission.
					}
					var parent *AdmittedParentComparison
					if mode != 2 {
						parent = admitSuppliedComparison(t, cold, keys, nil)
					}
					if comparison, res := cold.Compare(ctx, nil, parent); comparison != nil || res != want {
						t.Fatal("occupied work changed the exact empty comparison outcome", res)
					}
					if p, k := keys.Calls(); p != public || k != private {
						t.Fatal("empty comparison entered custody without private admission")
					}
					used, err := cold.closureIDsMode(ctx, false)
					if err != nil {
						t.Fatal("selected collision set could not read retained identities", err)
					}
					for _, id := range []contract.ID{a.record.OperationID, a.record.AttemptID, a.record.ResultID, a.record.TransmissionID, a.record.InboxID,
						a.record.ResourceID, a.material.Core.OperationMaterialID, expected.Template.PlannedValueSlotID} {
						if !used[id] {
							t.Fatal("pending-result identity omitted from collision set")
						}
					}
					record, err := contract.DecodeGeneratedResultRecord(result)
					if err != nil || contract.ValidateGeneratedResult(expected, a.material, record) != nil {
						t.Fatal("original result context changed", err)
					}
					if body, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(body) != 0 || calls != 1 {
						t.Fatal("original producer regenerated its result")
					}
				})
			}
		}
	}
}

type generatedOrdinaryComparisonCrypto struct {
	inner       contract.Crypto
	kinds       []contract.CryptoKind
	discardFail bool
}

func (c *generatedOrdinaryComparisonCrypto) InstanceID() contract.ID { return c.inner.InstanceID() }
func (c *generatedOrdinaryComparisonCrypto) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	c.kinds = append(c.kinds, q.Kind)
	reply := c.inner.Exchange(ctx, q)
	if q.Kind == contract.CryptoDiscard && c.discardFail {
		reply.ResultCode, reply.Body = contract.CryptoCustodyUnavailable, nil
	}
	return reply
}

// full_only: false
func TestGeneratedActiveOwnerAllowsOnlySemanticNoop(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, name := range []string{"empty", "plain-addition", "equal-secret", "changed-secret", "equal-secret-discard-failure", "changed-secret-discard-failure"} {
			t.Run(fmt.Sprintf("recovery%t/%s", recovery, name), func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, nil, false)
				secret := name != "empty" && name != "plain-addition"
				mode := uint8(0)
				if secret {
					mode = 2
				}
				input, canonical := generatedSourcePlanInput(t, run, f, mode)
				reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
				producer, _ := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
				sends := 0
				if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					sends++
					_, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					return code
				}) {
					t.Fatal("active-owner test producer handoff")
				}
				s, outcome := f.session.selectCandidate(ctx, producer.reservation.candidate)
				if s == nil || outcome.Outcome != ObservedCurrent || sends != 1 || s.root.Generated.ActiveOwner.IsZero() {
					t.Fatal("active-owner test selection", outcome)
				}
				keys.RetireGenerated()
				var desired []ApplyEntryInput
				var parent *AdmittedParentComparison
				var exchange *generatedOrdinaryComparisonCrypto
				want := s.observed(Unchanged)
				if name == "plain-addition" {
					desired = []ApplyEntryInput{{Name: "ordinary", Recipients: []contract.ID{s.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("new")}}
					want = s.observed(Contention)
					want.Reason = DifferentSelection
				} else if secret {
					desired = []ApplyEntryInput{sharingSecret(t, env, "fresh active-owner equal source", s.valueEntry(0).Recipients)}
					if name == "changed-secret" || name == "changed-secret-discard-failure" {
						core, err := contract.InspectSealedInputEnvelope(desired[0].InputBytes)
						if err != nil {
							t.Fatal(err)
						}
						sourceCore, err := core.Core.Own()
						if err != nil {
							t.Fatal(err)
						}
						sourceCore.SourceID = fixtureID(env.Domain, "fresh active-owner changed source")
						sourceCore.DataKeyID = fixtureID(env.Domain, "fresh active-owner changed source key")
						sealed, outcomeCode := keys.SealInput(ctx, sourceCore, desired[0].Recipients, custody.EmptyValue)
						if outcomeCode != contract.CryptoSuccess {
							t.Fatal("active-owner changed source sealing", outcomeCode)
						}
						desired[0].InputBytes = sealed
						want = s.observed(Contention)
						want.Reason = DifferentSelection
					}
					parent = admitSuppliedComparison(t, s, keys, desired)
					exchange = &generatedOrdinaryComparisonCrypto{inner: parent.crypto,
						discardFail: name == "equal-secret-discard-failure" || name == "changed-secret-discard-failure"}
					parent.crypto = exchange
					if exchange.discardFail {
						want = failure(EvidenceUnavailable, CustodyUnavailable)
					}
					t.Cleanup(keys.RetireApply)
				}
				if !secret {
					parent = admitSuppliedComparison(t, s, keys, desired)
				}
				beforeWork, err := s.preservedWorkSupportRecords(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				beforeRoot, beforeBody, beforeToken := s.root, bytes.Clone(s.body), s.token
				store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
				creates, cas, signs := store.creates, store.cas, trust.signs
				public, private := keys.Calls()
				entropy := bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32))
				s.admission.entropy = entropy
				comparison, result := s.Compare(ctx, desired, parent)
				if comparison != nil || result != want {
					t.Errorf("active owner allowed a changed apply or refused semantic no-op: %v, want %v", result, want)
				}
				if secret && (!parent.used || !slices.Equal(exchange.kinds, []contract.CryptoKind{contract.CryptoCompare, contract.CryptoDiscard})) {
					t.Error("active owner did not perform only authenticated comparison and discard", exchange.kinds)
				}
				wantPrivate := private
				if secret {
					wantPrivate += 2
				}
				if p, k := keys.Calls(); p != public || k != wantPrivate {
					t.Error("active-owner comparison changed exact custody use", p-public, k-private)
				}
				afterWork, err := s.preservedWorkSupportRecords(t.Context())
				if err != nil || !reflect.DeepEqual(beforeWork, afterWork) || !reflect.DeepEqual(beforeRoot, s.root) ||
					!bytes.Equal(beforeBody, s.body) || beforeToken != s.token || entropy.Len() != 32 || s.prepared || sends != 1 ||
					store.creates != creates || store.cas != cas || trust.signs != signs {
					t.Fatal("active-owner comparison changed identities, state, work, authority or effects", err)
				}
				checkFreshGeneratedProcess(t, store, s)
			})
		}
	}
}

// full_only: false
func TestGeneratedActiveOwnerRefusesDirectOrdinaryPlan(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	desired := []ApplyEntryInput{{Name: "ordinary", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("new")}}
	beforeComparison, result := f.session.Compare(ctx, desired, admitSuppliedComparison(t, f.session, nil, desired))
	if beforeComparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("direct ordinary baseline comparison", result)
	}
	plan, err := planTransition(t.Context(), beforeComparison)
	if err != nil {
		t.Fatal("direct ordinary baseline plan")
	}
	if f.session.validPlan(t.Context(), beforeComparison, plan) != nil {
		t.Fatal("direct ordinary baseline plan validation")
	}
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, generatedPlanInputFixture(t, f.session), nil)
	producer, _ := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		_, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("direct-plan test producer handoff")
	}
	s, result := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if s == nil || result.Outcome != ObservedCurrent || s.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("direct-plan test selected owner", result)
	}
	keys.RetireGenerated()
	c, result := s.compareEntryInputs(desired)
	if c == nil || result.Outcome != ObservedCurrent {
		t.Fatal("direct-plan public comparison", result)
	}
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	creates, cas, signs := store.creates, store.cas, trust.signs
	public, private := keys.Calls()
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32))
	s.admission.entropy = entropy
	if _, err := planTransition(t.Context(), c); err == nil || entropy.Len() != 32 {
		t.Error("active owner reached ordinary identity allocation")
	}
	if s.validPlan(t.Context(), c, plan) == nil || s.validPlan(t.Context(), beforeComparison, plan) == nil || f.session.validPlan(t.Context(), c, plan) == nil {
		t.Error("active owner or different session admitted an ordinary plan")
	}
	if next, err := s.deriveSuccessor(t.Context(), c, plan); next != nil || err == nil {
		t.Error("active owner derived an ordinary successor")
	}
	permit := &AdmittedParentTransition{session: s, comparison: c, predecessorDigest: contract.Hash(s.body),
		predecessorRevision: s.head.Core.Revision, predecessorToken: s.token, plan: plan}
	if candidate, result := s.Prepare(ctx, c, permit, env.Trust); candidate != nil || result != refused(AdmissionInvalid) || permit.used || s.prepared {
		t.Fatal("active owner reached direct ordinary preparation", result)
	}
	if p, k := keys.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs {
		t.Fatal("direct ordinary plan guard reached custody, signing or writes")
	}
	checkFreshGeneratedProcess(t, store, s)
}

// full_only: false
func TestGeneratedUnownedCanonicalCandidateCannotClaim(t *testing.T) {
	for _, mode := range []uint8{0, 1} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			run.suppliedSelection(f, []ApplyEntryInput{suppliedSecret(t, env, "secret", "current value outside the generated declaration", custody.StandardValue)})
			input, canonical := generatedSourcePlanInput(t, run, f, mode)
			s := f.session
			p, _ := prepareUnclaimedGeneratedReservation(t, env, s, input, canonical)
			candidate := generatedPrivateCandidate(t, p)
			slot, entry := lifecycleEntry(t, s, "secret")
			body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: slot, Entry: *entry})
			if err != nil {
				t.Fatal(err)
			}
			candidate.SupportRecords = append(candidate.SupportRecords, contract.SupportRecord{Kind: 6, RecordID: entry.ValueState, Body: body})
			slices.SortFunc(candidate.SupportRecords, func(a, b contract.SupportRecord) int {
				if a.Kind != b.Kind {
					return int(a.Kind) - int(b.Kind)
				}
				return bytes.Compare(a.RecordID[:], b.RecordID[:])
			})
			candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(env.Domain, candidate.SupportRecords)
			if err != nil {
				t.Fatal(err)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			code := keys.BindGeneratedCandidate(ctx, p.operation.context.AdmissionID, candidate)
			if code != contract.CryptoSuccess && code != contract.CryptoInvalidAdmission {
				t.Fatal("unexpected candidate validation result", code)
			}
			// Public owner closure belongs to Core. Even if Crypto binds these
			// different public facts, they cannot claim Core's actual candidate.
			if claimed, _ := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust); claimed != nil || p.claimed ||
				store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("unowned canonical candidate reached signing or persistence")
			}
			admitted := p.operation.context
			admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("extra canonical producer admission"), testID("extra canonical producer session"), contract.DescriptorVector{}
			if _, _, err := s.generatedProducerRequest(context.Background(), p, admitted); err == nil {
				t.Fatal("unowned canonical candidate restored producer admission")
			}
			cold, res := Open(ctx, f.admission, env.Store)
			if cold == nil || res.Outcome != ObservedCurrent || !bytes.Equal(cold.body, s.body) {
				t.Fatal("unowned canonical candidate changed selected state", res)
			}
		})
	}
}

// full_only: false
func TestGeneratedReservationPrivateClaimAndColdSelection(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			for _, sourceCount := range []int{0, 1, 2} {
				t.Run(fmt.Sprintf("family%d/recovery%t/sources%d", family, recovery, sourceCount), func(t *testing.T) {
					ctx := context.Background()
					env, keys := genesisEnvironment(t, family, recovery)
					f := newEnvironmentFixture(t, ctx, env, nil, false)
					s := f.session
					var sources []contract.GeneratorDeclarationEntry
					for i := 0; i < sourceCount; i++ {
						name := fmt.Sprintf("source-%d", i)
						value := suppliedSecret(t, env, name, name, custody.StandardValue)
						sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
							Name: name, Recipients: value.Recipients, Payload: value.InputBytes})
					}
					input := generatedPlanInputFixture(t, s, sources...)
					p, permit := preparePrivateGeneratedReservation(t, env, s, input, nil)
					candidate := p.reservation.candidate
					selected, res := s.selectCandidate(ctx, candidate)
					if selected == nil || res.Outcome != ObservedCurrent {
						t.Fatal("reservation selection", res)
					}
					keys.RetireGenerated()
					cold, res := Open(ctx, f.admission, env.Store)
					if cold == nil || res.Outcome != ObservedCurrent || cold.head.Core != selected.head.Core || cold.validateGeneratedSelection(ctx, nil) != nil {
						t.Fatal("reservation cold verification", res)
					}
					checkFreshGeneratedProcess(t, env.Store.(*memoryStore), cold)
					if again, _ := s.PrepareGeneratedPlan(ctx, permit); again != nil {
						t.Fatal("private plan admission reused")
					}
					if again, _ := s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust); again != nil {
						t.Fatal("private claim reused")
					}
				})
			}
		}
	}
}

// full_only: false
func TestSuccessionLateSelectedSliceReadKeepsStoreResult(t *testing.T) {
	for _, tc := range []struct {
		name    string
		faultAt int
		read    contract.ReadResult
		want    Result
	}{
		{"missing-projection", 1, contract.ReadResult{Status: contract.ReadMissing}, failure(EvidenceUnavailable, MissingSelectedObject)},
		{"invalid-projection", 1, contract.ReadResult{Status: contract.ReadInvalid}, failure(IntegrityFailure, InvalidFormat)},
		{"invalid-body-projection", 1, contract.ReadResult{Status: contract.ReadOK, Body: []byte{1}}, failure(IntegrityFailure, InvalidReference)},
		{"unavailable-projection", 1, contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
		{"missing-derivation", 2, contract.ReadResult{Status: contract.ReadMissing}, failure(EvidenceUnavailable, MissingSelectedObject)},
		{"invalid-derivation", 2, contract.ReadResult{Status: contract.ReadInvalid}, failure(IntegrityFailure, InvalidFormat)},
		{"invalid-body-derivation", 2, contract.ReadResult{Status: contract.ReadOK, Body: []byte{1}}, failure(IntegrityFailure, InvalidReference)},
		{"unavailable-derivation", 2, contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, false)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input, canonical := generatedSourcePlanInput(t, run, f, 0)
			prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
			selected, result := f.session.selectCandidate(ctx, prior.reservation.candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("selected reservation", result)
			}
			keys.RetireGenerated()
			cold, result := Open(ctx, f.admission, env.Store)
			if cold == nil || result.Outcome != ObservedCurrent || len(cold.fragmentFacts) == 0 {
				t.Fatal("complete cold selected predecessor", result)
			}
			indexes, err := cold.generatedSnapshotPageIndexes()
			if err != nil || len(indexes) == 0 {
				t.Fatal("selected Slice carrier", err)
			}
			ref := cold.root.RequiredSupport[indexes[0]]
			key, err := format.Key(cold.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal("selected Slice key", err)
			}
			actors := env.ReplacementActors(t, ctx, cold, 1, 3, 1)
			permit := admitAuthorityReplacement(t, cold, actors.Keys, actors.After, 1, 1, 3, actors.Source)
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			selectedReads := 0
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					selectedReads++
					if selectedReads >= tc.faultAt {
						return tc.read
					}
				}
				return read
			}
			defer func() { store.readHook = nil }()
			candidate, result := cold.PrepareSuccession(ctx, permit, actors.Signers)
			if candidate != nil || result != tc.want || selectedReads < tc.faultAt || store.creates != creates || store.cas != cas {
				t.Fatal("late selected Slice read lost its Store result or reached a write", result, selectedReads)
			}
		})
	}
}

// full_only: false
func TestSuccessionSelectedReceiptReadKeepsStoreResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		read   contract.ReadResult
		want   Result
		cancel bool
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, failure(EvidenceUnavailable, MissingSelectedObject), false},
		{"invalid", contract.ReadResult{Status: contract.ReadInvalid}, failure(IntegrityFailure, InvalidFormat), false},
		{"invalid-body", contract.ReadResult{Status: contract.ReadOK, Body: []byte{1}}, failure(IntegrityFailure, InvalidReference), false},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, false},
		{"canceled", contract.ReadResult{}, failure(EvidenceUnavailable, ReadUnavailable), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			cold := generatedLifecycleReopen(t, ctx, selected, env.Store)
			blob, err := cold.receiptIndexID()
			if err != nil || blob.IsZero() {
				t.Fatal("selected receipt index", err)
			}
			var ref format.Ref
			for _, location := range cold.root.Generated.Fragments {
				if location.BlobID != blob {
					continue
				}
				for _, candidate := range cold.root.RequiredSupport {
					if candidate.Index == location.SupportPageIndex {
						ref = candidate
						break
					}
				}
			}
			if ref.Kind != contract.RequiredSupportKind {
				t.Fatal("selected receipt index has no fragment Ref")
			}
			key, err := format.Key(cold.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			cold.selectedReceiptRoot = format.Ref{}
			env = syntheticAuthorityScenarioEnvironment(t, env)
			actors := env.ReplacementActors(t, ctx, cold, 1, 3, 1)
			permit := admitAuthorityReplacement(t, cold, actors.Keys, actors.After, 1, 1, 3, actors.Source)
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			reads := 0
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
					if reads >= 8 {
						if tc.cancel {
							cancel()
							return read
						}
						return tc.read
					}
				}
				return read
			}
			defer func() { store.readHook = nil }()
			candidate, result := cold.PrepareSuccession(ctx, permit, actors.Signers)
			if candidate != nil || result.Outcome != tc.want.Outcome || result.Reason != tc.want.Reason ||
				result.StoreReason != tc.want.StoreReason || reads < 8 || store.creates != creates || store.cas != cas {
				t.Fatal("selected receipt read lost its Store result or reached a write", result, reads)
			}
		})
	}
}

// full_only: false
func TestRecoverySignerReplacementKeepsLateReceiptReadResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		read   contract.ReadResult
		want   Result
		cancel bool
		reads  int
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, failure(EvidenceUnavailable, MissingSelectedObject), false, 2},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, false, 4},
		{"canceled", contract.ReadResult{}, failure(EvidenceUnavailable, ReadUnavailable), true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, true, 0)
			cold := generatedLifecycleReopen(t, ctx, selected, env.Store)
			blob, err := cold.receiptIndexID()
			if err != nil || blob.IsZero() {
				t.Fatal("selected receipt index", err)
			}
			var ref format.Ref
			for _, location := range cold.root.Generated.Fragments {
				if location.BlobID != blob {
					continue
				}
				for _, candidate := range cold.root.RequiredSupport {
					if candidate.Index == location.SupportPageIndex {
						ref = candidate
						break
					}
				}
			}
			if ref.Kind != contract.RequiredSupportKind {
				t.Fatal("selected receipt index has no fragment Ref")
			}
			key, err := format.Key(cold.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			env = syntheticAuthorityScenarioEnvironment(t, env)
			actors := env.ReplacementActors(t, ctx, cold, contract.SuccessionReplaceRecoveryBasis,
				contract.SuccessionChangeRecoverySigner, contract.NormalSigningRole)
			permit := admitAuthorityReplacement(t, cold, actors.Keys, actors.After,
				contract.SuccessionReplaceRecoveryBasis, contract.NormalSigningRole,
				contract.SuccessionChangeRecoverySigner, actors.Source)
			if cold.generatedWork == nil || cold.generatedWork.session != cold ||
				cold.generatedWork.selection == nil || len(cold.generatedWork.selection.sources) != 0 {
				t.Fatal("receipt fixture lacks retained selected work without source reads")
			}
			cold.selectedReceiptRoot = format.Ref{}
			store := env.Store.(*memoryStore)
			reads := 0
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
				}
				return read
			}
			defer func() { store.readHook = nil }()
			if used, err := cold.closureIDsMode(ctx, false); err != nil || used == nil || reads != 1 {
				t.Fatal("healthy identity closure did not complete one receipt read", err, reads)
			}
			creates, cas := store.creates, store.cas
			public, private := actors.Keys.Calls()
			authorizer := actors.Signers.Authorizer.(interface{ Calls() int })
			successor := actors.Signers.RecoverySuccessor.(interface {
				Calls() int
				QualificationCalls() int
			})
			signs, successorSigns, qualifications := authorizer.Calls(), successor.Calls(), successor.QualificationCalls()
			token, head := cold.token, bytes.Clone(cold.body)
			root, err := format.EncodeRoot(cold.root)
			if err != nil {
				t.Fatal(err)
			}
			reads = 0
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
					// Closure reads first; the receipt-page identity plan reads second.
					if reads >= 2 {
						if tc.cancel {
							cancel()
							return read
						}
						return tc.read
					}
				}
				return read
			}
			candidate, result := cold.PrepareSuccession(ctx, permit, actors.Signers)
			afterRoot, err := format.EncodeRoot(cold.root)
			afterPublic, afterPrivate := actors.Keys.Calls()
			if candidate != nil || result != tc.want || reads != tc.reads || permit.used || cold.prepared ||
				store.creates != creates || store.cas != cas || afterPublic != public || afterPrivate != private ||
				authorizer.Calls() != signs || successor.Calls() != successorSigns || successor.QualificationCalls() != qualifications ||
				cold.token != token || !bytes.Equal(cold.body, head) || err != nil || !bytes.Equal(afterRoot, root) {
				t.Fatalf("late receipt validation result=%+v reads=%d candidate=%t permit_used=%t prepared=%t creates=%d cas=%d public=%d private=%d signs=%d successor_signs=%d qualifications=%d selected_unchanged=%t",
					result, reads, candidate != nil, permit.used, cold.prepared, store.creates-creates, store.cas-cas,
					afterPublic-public, afterPrivate-private, authorizer.Calls()-signs, successor.Calls()-successorSigns,
					successor.QualificationCalls()-qualifications, cold.token == token && bytes.Equal(cold.body, head) && err == nil && bytes.Equal(afterRoot, root))
			}
		})
	}
}

// full_only: false
func TestGeneratedReservationRetainsExactCanonicalInput(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("family%d/recovery%t", family, recovery), func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, family, recovery)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, nil, false)
				run.suppliedSelection(f, []ApplyEntryInput{suppliedSecret(t, env, "source", "canonical source", custody.StandardValue)})
				s := f.session
				selection := sessionConsumerSelection(t, s, s.admission.recipient, "source")
				record := contract.RetainedCanonicalRecord{OriginalSlot: selection.Slot, Entry: selection.Entry}
				body, err := contract.EncodeRetainedCanonicalRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				input := generatedPlanInputFixture(t, s, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
					Name: "source", Recipients: selection.Entry.Recipients, Payload: body})
				prior, _ := preparePrivateGeneratedReservation(t, env, s, input, []custody.GeneratedCanonicalSelection{{Selection: selection, Record: record}})
				p, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
				var result []byte
				if !p.reservation.candidate.bindFirstSend(p, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
					var code contract.CryptoResultCode
					result, _, code = keys.InvokeGeneratedProducer(ctx, p.operation.context.AdmissionID, p.producerLocator, authority)
					return code
				}) {
					t.Fatal("canonical producer handoff")
				}
				selected, res := s.selectCandidate(ctx, p.reservation.candidate)
				if selected == nil || res.Outcome != ObservedCurrent {
					t.Fatal("canonical source reservation", res)
				}
				keys.RetireGenerated()
				cold, res := Open(ctx, f.admission, env.Store)
				if cold == nil || res.Outcome != ObservedCurrent {
					t.Fatal("canonical source cold selection", res)
				}
				g, err := cold.selectedGeneratedWork(context.Background())
				if err != nil {
					t.Fatal("canonical source work", err)
				}
				sourceID := contract.ID(sha256.Sum256(append([]byte("ENKV/CRYPTO/v2/retained-member-admission-v1\x00"), body...)))
				_, present := g.canonical[sourceID]
				consumers := g.consumers[materialIdentity{contract.ValueMaterialKind, record.Entry.ValueState}]
				if len(g.canonical) != 1 || !present || len(consumers) != 1 || consumers[0].SubjectID != sourceID || consumers[0].MaterialID != record.Entry.ValueState {
					t.Fatal("canonical source lost its exact consumer")
				}
				retained, present := g.records[generatedRecordKey{contract.RetainedCanonicalSupportKind, sourceID}]
				if !present || !bytes.Equal(retained.Body, body) {
					t.Fatal("canonical source bytes changed")
				}
				admitted := generatedPlanInputFixture(t, cold).context
				admitted.AdmissionID, admitted.SessionID = testID("canonical record admission"), testID("canonical record session")
				plan, err := cold.generatedRecordRequest(context.Background(), expected.Template.AttemptID, result, admitted)
				if err != nil {
					t.Fatal("canonical record request", err)
				}
				recorded := preparePrivateGeneratedRecord(t, env, cold, plan)
				if selected, res := cold.selectCandidate(ctx, recorded.reservation.candidate); selected == nil || res.Outcome != ObservedCurrent {
					t.Fatal("canonical record selection", res)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedFinalDropsConsumedRetainedCanonicalOwner(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input, canonical := generatedSourcePlanInput(t, run, f, 2)
	prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
	sourceID, err := contract.AdmissionEntryDigest(canonical[0].Record)
	if err != nil {
		t.Fatal(err)
	}
	producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
	var result []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("producer handoff")
	}
	selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || len(result) == 0 {
		t.Fatal("producer selection", res)
	}
	keys.RetireGenerated()
	recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, expected.Template.AttemptID, result)
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID, finalContext.SessionID = testID("retained canonical final admission"), testID("retained canonical final session")
	if !mustSelectedGeneratedWork(t, recorded).hasRecord(generatedRecordKey{contract.RetainedCanonicalSupportKind, sourceID}) {
		t.Fatal("exact source absent before Final")
	}
	finalPlan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal("final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
	closed, res := recorded.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || res.Outcome != ObservedCurrent || !closed.root.Generated.ActiveOwner.IsZero() ||
		closed.root.ValueEntryCount != 2 || closed.root.Generated.GeneratedCurrent != 1 {
		t.Fatal("retained canonical final selection", res)
	}
	for _, row := range closed.supportRecords() {
		if row.Kind == contract.RetainedCanonicalSupportKind && row.RecordID == sourceID {
			t.Fatal("consumed retained canonical owner survived final selection")
		}
	}
	if entry := closed.valueEntry(canonical[0].Record.OriginalSlot); entry == nil || !sameRetainedEntryValue(*entry, canonical[0].Record.Entry) {
		t.Fatal("final selection changed the retained member")
	}
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
}

func generatedSelectedFragmentRef(t testing.TB, selected *StateSession, location format.FragmentLocation) format.Ref {
	t.Helper()
	fact, found := selected.fragmentFacts[location]
	position, pageOK := selected.selectedSupportPosition(fact.ref)
	if !found || !pageOK || fact.ref.Index != location.SupportPageIndex || fact.logical != uint16(location.RowSlot) ||
		fact.blob != location.BlobID || fact.index != location.FragmentIndex {
		t.Fatal("selected fragment reference or directory")
	}
	page := selected.supportFacts[position]
	if int(fact.logical) >= len(page.rows) || int(fact.logical) >= len(page.ordinals) ||
		page.rows[fact.logical] != fact.row || page.ordinals[fact.logical] != fact.physical {
		t.Fatal("selected fragment row or physical ordinal")
	}
	return fact.ref
}

func generatedSelectedFragmentKeys(t testing.TB, selected *StateSession) map[string]bool {
	t.Helper()
	keys := make(map[string]bool)
	for _, location := range selected.root.Generated.Fragments {
		ref := generatedSelectedFragmentRef(t, selected, location)
		key, err := format.Key(selected.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal("selected fragment key", err)
		}
		keys[key] = true
	}
	if len(keys) == 0 {
		t.Fatal("fixture has no selected fragment")
	}
	return keys
}

// full_only: false
func TestGeneratedFinalKeepsLateSelectedReadResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		read contract.ReadResult
		want Result
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, failure(EvidenceUnavailable, MissingSelectedObject)},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input, canonical := generatedSourcePlanInput(t, run, f, 2)
			prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
			selected, _, _, _ := selectActualGeneratedPacketRecord(t, env, f.session, prior, custody.StandardValue, true, nil)
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			finalContext := generatedPlanInputFixture(t, selected).context
			finalContext.AdmissionID, finalContext.SessionID = testID("late final admission"), testID("late final session")
			finalPlan, err := selected.generatedFinalRequest(ctx, finalContext)
			if err != nil {
				t.Fatal("final request", err)
			}
			permit := admitPrivateGeneratedFinal(t, env, selected, finalPlan)
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			fragmentKeys := generatedSelectedFragmentKeys(t, selected)
			creates, cas, signs := store.creates, store.cas, trust.signs
			reads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if fragmentKeys[key] {
					reads++
					return tc.read
				}
				return read
			}
			defer func() { store.readHook = nil }()
			candidate, result := selected.PrepareGeneratedFinal(ctx, permit)
			if candidate != nil || result != tc.want || reads == 0 || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("late selected Final read lost Store result or reached a write", result, reads)
			}
			keys.RetireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedFailedFinalDropsUnownedRetainedCanonical(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input, canonical := generatedSourcePlanInput(t, run, f, 2)
	prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
	sourceID, err := contract.AdmissionEntryDigest(canonical[0].Record)
	if err != nil {
		t.Fatal(err)
	}
	selected, prior, _, _ := selectActualGeneratedPacketRecord(t, env, f.session, prior, custody.GeneratedConfirmedNoEffect, false, nil)
	planned, result := selected.selectCandidate(context.Background(), prior.reservation.candidate)
	if planned == nil || result.Outcome != ObservedCurrent {
		t.Fatal("select no-effect successor plan", result)
	}
	prior = preparePrivateGeneratedSuccessorReservation(t, env, planned)
	selected, _, _, _ = selectActualGeneratedPacketRecord(t, env, planned, prior, custody.GeneratedConfirmedNoEffect, true, nil)
	if !mustSelectedGeneratedWork(t, selected).hasRecord(generatedRecordKey{contract.RetainedCanonicalSupportKind, sourceID}) {
		t.Fatal("exact source absent before Final")
	}
	finalContext := generatedPlanInputFixture(t, selected).context
	finalContext.AdmissionID, finalContext.SessionID = testID(t.Name()+" final admission"), testID(t.Name()+" final session")
	plan, err := selected.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || plan.selecting {
		t.Fatal("all-no-effect final plan", err)
	}
	beforeEntries := selected.currentEntryInputs()
	beforeAccess := make(map[contract.ID]contract.AccessRecord)
	for _, row := range selected.accessRecords() {
		if row.MaterialKind == contract.ValueMaterialKind {
			beforeAccess[row.MaterialID] = row
		}
	}
	selected, final := preparePrivateGeneratedFinal(t, env, selected, plan)
	closed, result := selected.selectCandidate(t.Context(), final.reservation.candidate)
	if closed == nil || result.Outcome != ObservedCurrent {
		t.Fatal("private all-no-effect Final selection", result)
	}
	closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
	if !reflect.DeepEqual(closed.currentEntryInputs(), beforeEntries) {
		t.Fatal("failed private Final changed current entries")
	}
	afterAccess := make(map[contract.ID]contract.AccessRecord)
	for _, row := range closed.accessRecords() {
		if row.MaterialKind == contract.ValueMaterialKind {
			afterAccess[row.MaterialID] = row
		}
	}
	if !reflect.DeepEqual(afterAccess, beforeAccess) {
		t.Fatal("failed private Final changed current value access")
	}
	env.Custody.RetireGenerated()
	if entry := closed.valueEntry(canonical[0].Record.OriginalSlot); entry == nil || !sameRetainedEntryValue(*entry, canonical[0].Record.Entry) {
		t.Fatal("failed final changed the selected supplied value")
	}
	if _, ok := closed.materialAccess(1, canonical[0].Record.Entry.ValueState); !ok {
		t.Fatal("failed final removed current value access")
	}
	for _, row := range closed.supportRecords() {
		if row.Kind == contract.RetainedCanonicalSupportKind && row.RecordID == sourceID {
			t.Fatal("failed final retained canonical support without a consumer")
		}
	}
}

func preparePrivateGeneratedProducer(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation, beforeReturn func()) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProducerValue(t, env, s, prior, custody.StandardValue, beforeReturn)
}

func preparePrivateGeneratedProducerValue(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation, value uint8, beforeReturn func()) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProducerProbe(t, env, s, prior, value, beforeReturn, nil)
}

func preparePrivateGeneratedProducerProbe(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation, value uint8, beforeReturn func(), probe func(context.Context, contract.GeneratedProducerCommand) []byte) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProducerForAttempt(t, env, s, prior, env.Custody, contract.ID{}, value, beforeReturn, probe)
}

func preparePrivateGeneratedProducerForAttempt(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, value uint8, beforeReturn func(), probe func(context.Context, contract.GeneratedProducerCommand) []byte) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProducerWithAdmission(t, env, s, prior, keys, attempt, value, beforeReturn, probe,
		generatedProducerFixtureSteps{request: s.generatedProducerRequestForAttempt, prepare: s.PrepareGeneratedProducer,
			claim: func(ctx context.Context, p *generatedPreparation) (*Candidate, Result) {
				return s.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust)
			}})
}

func preparePrivateGeneratedOriginalProducerForAttempt(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, facts *generatedProducerFixtureFacts, value uint8, beforeReturn func(), probe func(context.Context, contract.GeneratedProducerCommand) []byte) (*generatedPreparation, contract.GeneratorResultExpectation) {
	return preparePrivateGeneratedProducerWithAdmission(t, env, s, prior, keys, attempt, value, beforeReturn, probe,
		generatedProducerFixtureSteps{request: s.generatedOriginalProducerRequest, prepare: s.PrepareGeneratedOriginalProducer,
			claim: s.ClaimGeneratedOriginalProducer, facts: facts})
}

type generatedProducerFixtureFacts struct {
	selection *generatedSelection
	session   custody.GeneratedSessionInput
	plan      custody.GeneratedPlanInput
	owned     custody.GeneratedCustodyInput
	candidate custody.GeneratedCandidate
}

// These caller-owned facts remain read-only until every private preparation joins.
func acquireGeneratedProducerFixtureFacts(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation) *generatedProducerFixtureFacts {
	t.Helper()
	ctx := env.operationContext()
	stage := time.Now()
	g, err := prior.reservation.state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session, plan, owned := selectedGeneratedCommonPrivateFacts(ctx, t, s, g)
	plan.Canonical = generatedCanonicalInputs(t, s, g, plan.Declaration)
	// Initial producer admission precedes selection. Its source observation
	// comes from the predecessor, while its owner belongs to the fixed candidate.
	for i := range plan.Canonical {
		source := &plan.Canonical[i]
		selection := sessionConsumerSelection(t, s, s.admission.recipient, source.Record.Entry.Name)
		if selection.Slot == source.Record.OriginalSlot && reflect.DeepEqual(selection.Entry, source.Record.Entry) {
			source.Selection = selection
			continue
		}
		retained, result := s.generatedConsumerSelection(ctx, source.Owner.Kind, source.Owner.RecordID,
			source.Record.Entry.ValueState, s.admission.recipient)
		if result.Outcome != ObservedCurrent || retained.Record.OriginalSlot != source.Record.OriginalSlot ||
			!reflect.DeepEqual(retained.Record.Entry, source.Record.Entry) {
			t.Fatal("initial producer historical source differs from the selected predecessor", result)
		}
		source.Selection = retained.Selection
	}

	t.Logf("producer phase=common-input-acquire duration-ms=%d", time.Since(stage).Milliseconds())
	stage = time.Now()
	candidate := generatedPrivateCandidate(t, prior)
	t.Logf("producer phase=common-candidate-acquire duration-ms=%d", time.Since(stage).Milliseconds())
	return &generatedProducerFixtureFacts{g, session, plan, owned, candidate}
}

func generatedProducerFixtureAttemptInput(t testing.TB, s *StateSession, prior *generatedPreparation, facts *generatedProducerFixtureFacts, attempt contract.ID) custody.GeneratedProducerInput {
	t.Helper()
	g := facts.selection
	a := g.attempts[attempt]
	input := custody.GeneratedProducerInput{Session: facts.session, Plan: facts.plan, Custody: facts.owned, Expected: a.expected, Phase: prior.producerPhase}
	input.Custody.Material = a.material
	var err error
	input.Attempt = a.record
	input.Intent, err = g.readSelectedSlice(t.Context(), contract.GeneratorContentIntent, a.expected.Template.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		t.Fatal(err)
	}
	source, err := g.generatedDeleteSource(a.record.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if source.Record.Kind == 10 {
		input.Duty = source.Duty
	} else {
		input.Source = source.Record
	}
	if a.expected.Template.Action == 2 {
		bundle, err := g.retainedGraph(a.record.OperationID)
		if err != nil {
			t.Fatal("producer original delete graph", err)
		}
		target, _, err := g.generatedDeleteAttemptTargetAndSource(t.Context(), bundle, a.record)
		if err != nil {
			t.Fatal("producer original delete target", err)
		}
		input.Target = &target
		original, err := g.createTargetEvidence(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		input.OriginalFacts, err = contract.EncodeGeneratorSafeFacts(original.GeneratorSafeFacts)
		if err != nil {
			t.Fatal(err)
		}
		if source.CompletionClass == contract.GeneratedCompletionConfirmed {
			progress, e := g.controlledDeleteSourceProgress(source, nil, true)
			if e != nil {
				t.Fatal(e)
			}
			input.Progress = progress.rows
		} else if source.Record.Kind == 10 {
			input.Progress, err = g.vectors.resolve(10, input.Duty.DutyID, contract.GeneratorVectorProgress, input.Duty.Progress)
		}
		if err != nil {
			t.Fatal(err)
		}
		if source.CompletionClass == contract.GeneratedCompletionConfirmed {
			selected := mustSelectedGeneratedWork(t, s)
			beforeSource, e := selected.generatedDeleteSource(source.OwnerID)
			if e != nil {
				t.Fatal(e)
			}
			p := generatedControlledSourcePredecessorInput(t, s, selected, beforeSource)
			input.ControlledPredecessor = &p
		}
	}
	input.Consumers, err = g.vectors.resolve(source.Record.Kind, source.SourceID, contract.GeneratorVectorConsumers, source.Consumers)
	if err != nil {
		t.Fatal(err)
	}

	return input
}

type generatedProducerFixtureSteps struct {
	request    generatedProducerRequestFunction
	prepare    func(context.Context, *admittedGeneratedProducer) (*generatedPreparation, Result)
	claim      func(context.Context, *generatedPreparation) (*Candidate, Result)
	inputReady func(custody.GeneratedProducerInput)
	facts      *generatedProducerFixtureFacts
}

func preparePrivateGeneratedProducerWithAdmission(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, value uint8, beforeReturn func(), probe func(context.Context, contract.GeneratedProducerCommand) []byte,
	steps generatedProducerFixtureSteps) (*generatedPreparation, contract.GeneratorResultExpectation) {
	t.Helper()
	if steps.facts == nil {
		steps.facts = acquireGeneratedProducerFixtureFacts(t, env, s, prior)
	}
	permit, expected := admitPrivateGeneratedProducerWithAdmission(t, env, s, prior, keys, attempt, value, beforeReturn, probe, steps)
	ctx := env.operationContext()
	stage := time.Now()
	p, res := steps.prepare(ctx, permit)
	logGeneratedProducerStage(t, "core-prepare", stage, permit.preparation)
	if p == nil || res.Outcome != ObservedCurrent {
		t.Fatal("producer preparation", res)
	}
	stage = time.Now()
	if code := keys.BindGeneratedCandidate(ctx, permit.request.Context.AdmissionID, steps.facts.candidate); code != contract.CryptoSuccess {
		t.Fatal("producer candidate binding", code)
	}
	logGeneratedProducerStage(t, "candidate-bind", stage, permit.preparation)
	stage = time.Now()
	candidate, res := steps.claim(ctx, p)
	logGeneratedProducerStage(t, "individual-claim", stage, permit.preparation)
	if candidate == nil || res.Outcome != ObservedCurrent {
		t.Fatal("producer claim", res)
	}
	return p, expected
}

func admitPrivateGeneratedProducerWithAdmission(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation,
	keys *custody.Fixture, attempt contract.ID, value uint8, beforeReturn func(), probe func(context.Context, contract.GeneratedProducerCommand) []byte,
	steps generatedProducerFixtureSteps) (*admittedGeneratedProducer, contract.GeneratorResultExpectation) {
	t.Helper()
	ctx := env.operationContext()
	keys.RetireGenerated()
	admitted := prior.producerBaseContext
	if !prior.plannedSuccessor {
		admitted = prior.operation.context
	}
	if attempt.IsZero() {
		selected, err := prior.reservation.state.selectedGeneratedWork(context.Background())
		if err != nil || selected.phase == nil {
			t.Fatal("producer admission has no selected frontier", err)
		}
		attempt = selected.phase.FrontierAttemptID
	}
	label := fmt.Sprintf("%x", attempt)
	admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("generated producer admission"+label), testID("generated producer session"+label), contract.DescriptorVector{}
	if steps.facts == nil {
		steps.facts = acquireGeneratedProducerFixtureFacts(t, env, s, prior)
	}
	stage := time.Now()
	input := generatedProducerFixtureAttemptInput(t, s, prior, steps.facts, attempt)
	t.Logf("producer phase=attempt-input-acquire duration-ms=%d", time.Since(stage).Milliseconds())
	if steps.inputReady != nil {
		steps.inputReady(input)
	}
	stage = time.Now()
	q, preparation, err := steps.request(ctx, prior, attempt, admitted)
	if err != nil {
		t.Fatal("producer public admission", err)
	}
	input.Preparation, input.BeforeReturn, input.Probe = preparation, beforeReturn, probe
	logGeneratedProducerStage(t, "preparation-bind", stage, preparation)

	stage = time.Now()
	deadline := time.Unix(0, int64(q.Context.Expiry))
	if err := keys.AdmitGeneratedProducer(q, currentControlOf(s), input, value, deadline); err != nil {
		t.Fatal("producer private admission", err)
	}
	logGeneratedProducerStage(t, "crypto-admit", stage, preparation)
	permit := &admittedGeneratedProducer{session: s, prior: prior, attempt: preparation.AttemptID, request: q, preparation: preparation,
		crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), deadline: deadline}
	return permit, input.Expected
}

// full_only: false
func TestGeneratedOriginalPreparationAndClaimRunConcurrently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		env, _ := genesisEnvironment(t, contract.GCP, true)
		fixture := newEnvironmentFixture(t, ctx, env, nil, false)
		before := fixture.session
		input := generatedPlanInputForGenerations(t, before, generatedVectorID(10), []string{"alpha", "omega"}, defaultGeneratedFixtureProfile())
		// Preparation and complete-set Claim use the finite parent lifetime.
		input.context.Expiry = uint64(time.Now().Add(5 * time.Minute).UnixNano())
		if len(input.requestBindings) != 2 || input.requestBindings[0].AttemptID == input.requestBindings[1].AttemptID {
			t.Fatal("expected two distinct original attempts")
		}
		reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
		if !slices.Equal(reservation.reservation.originalAttempts, []contract.ID{input.requestBindings[0].AttemptID, input.requestBindings[1].AttemptID}) {
			t.Fatal("reservation changed original attempt membership")
		}
		keys := [2]*custody.Fixture{env.Custody, env.Custody.ForkGenerated(t)}
		var permits [2]*admittedGeneratedProducer
		var producers [2]*generatedPreparation
		var expected [2]contract.GeneratorResultExpectation
		var effects [2]atomic.Int32
		for i := range permits {
			permits[i], expected[i] = admitPrivateGeneratedProducerWithAdmission(t, env, before, reservation, keys[i],
				input.requestBindings[i].AttemptID, custody.StandardValue, func() { effects[i].Add(1) }, nil,
				generatedProducerFixtureSteps{request: before.generatedOriginalProducerRequest})
			if i == 0 {
				admitted := permits[i].request.Context
				admitted.IntentDescriptor = contract.DescriptorVector{}
				if _, _, err := before.generatedProducerRequestForAttempt(ctx, reservation, input.requestBindings[i].AttemptID, admitted); err == nil {
					t.Fatal("complete-set parent admitted a separate single producer")
				}
			}
		}
		// Each hold exceeds the child command bound while the parent stays live.
		// An early command cannot survive these phases; first entry must issue it.
		holdBeforeEntry := func() {
			time.Sleep(91 * time.Second)
			if !time.Now().Before(time.Unix(0, int64(input.context.Expiry))) {
				t.Fatal("producer parent expired during preparation or complete-set Claim")
			}
			for i := range effects {
				if effects[i].Load() != 0 {
					t.Fatal("original entered before complete-set Claim and selection", i)
				}
			}
		}
		holdBeforeEntry()
		prepareEntered, claimEntered := make(chan int, 2), make(chan int, 2)
		prepareRelease, claimRelease := make(chan struct{}), make(chan struct{})
		var prepareReleaseOnce, claimReleaseOnce sync.Once
		var joined sync.WaitGroup
		defer func() {
			prepareReleaseOnce.Do(func() { close(prepareRelease) })
			claimReleaseOnce.Do(func() { close(claimRelease) })
			joined.Wait()
		}()
		waitForBoth := func(name string, entered <-chan int, release chan struct{}, once *sync.Once) {
			seen := [2]bool{}
			for range 2 {
				select {
				case i := <-entered:
					if i < 0 || i >= len(seen) || seen[i] {
						t.Fatal("duplicate original entered", name, i)
					}
					seen[i] = true
				case <-time.After(10 * time.Second):
					t.Fatal("both originals did not enter", name)
				}
			}
			once.Do(func() { close(release) })
		}
		type preparationResult struct {
			index  int
			value  *generatedPreparation
			result Result
		}
		prepared := make(chan preparationResult, 2)
		for i := range producers {
			joined.Add(1)
			go func(i int) {
				defer joined.Done()
				prepareEntered <- i
				<-prepareRelease
				value, result := before.PrepareGeneratedOriginalProducer(ctx, permits[i])
				prepared <- preparationResult{index: i, value: value, result: result}
			}(i)
		}
		waitForBoth("preparation", prepareEntered, prepareRelease, &prepareReleaseOnce)
		for range 2 {
			select {
			case outcome := <-prepared:
				if outcome.value == nil || outcome.result.Outcome != ObservedCurrent {
					t.Fatal("concurrent original preparation", outcome.index, outcome.result)
				}
				producers[outcome.index] = outcome.value
			case <-time.After(10 * time.Second):
				t.Fatal("concurrent original preparation did not finish")
			}
		}
		joined.Wait()
		for i, p := range producers {
			if code := keys[i].BindGeneratedCandidate(ctx, permits[i].request.Context.AdmissionID, generatedPrivateCandidate(t, p)); code != contract.CryptoSuccess {
				t.Fatal("concurrent original candidate binding", i, code)
			}
		}
		type claimResult struct {
			index  int
			value  *Candidate
			result Result
		}
		claimed := make(chan claimResult, 2)
		for i := range producers {
			joined.Add(1)
			go func(i int) {
				defer joined.Done()
				claimEntered <- i
				<-claimRelease
				value, result := before.ClaimGeneratedOriginalProducer(ctx, producers[i])
				claimed <- claimResult{index: i, value: value, result: result}
			}(i)
		}
		waitForBoth("claim", claimEntered, claimRelease, &claimReleaseOnce)
		for range 2 {
			select {
			case outcome := <-claimed:
				if outcome.value == nil || outcome.result.Outcome != ObservedCurrent {
					t.Fatal("concurrent original claim", outcome.index, outcome.result)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("concurrent original claim did not finish")
			}
		}
		joined.Wait()
		for i, p := range producers {
			if p == nil || !p.claimed || p.attempt != input.requestBindings[i].AttemptID ||
				expected[i].Template.AttemptID != p.attempt || p.reservation != reservation.reservation {
				t.Fatal("concurrent original claim changed membership", i)
			}
			if candidate, result := before.ClaimGeneratedOriginalProducer(ctx, p); candidate != nil || result.Outcome != AdmissionRefused {
				t.Fatal("original producer claim was reusable", i, result)
			}
		}
		candidate, result := before.ClaimGeneratedOriginalSet(ctx, producers[:], env.Trust)
		if candidate == nil || result.Outcome != ObservedCurrent || len(candidate.originalProducers) != 2 ||
			len(candidate.generated.originalClaims) != 2 {
			t.Fatal("complete original set claim", result)
		}
		for i, p := range producers {
			if candidate.originalProducers[p.attempt] != p || candidate.generated.originalClaims[p.attempt] != candidate.generated.authority {
				t.Fatal("claimed original is absent from exact candidate set", i)
			}
		}
		holdBeforeEntry()
		var results [2][]byte
		if !candidate.bindFirstSend(producers[0], func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
			for i, p := range producers {
				body, _, code := keys[i].InvokeGeneratedProducer(ctx, p.operation.context.AdmissionID, p.producerLocator, authority)
				if code != contract.CryptoSuccess || len(body) == 0 {
					return code
				}
				results[i] = body
				if persisted := reservation.reservation.state.persistGeneratedResult(ctx, generatedResultWrite{attempt: p.attempt, body: body}); persisted.Outcome != 0 {
					return contract.CryptoCustodyUnavailable
				}
			}
			return contract.CryptoSuccess
		}) || candidate.bindFirstSend(producers[1], func(context.Context, contract.ID) contract.CryptoResultCode { return contract.CryptoSuccess }) {
			t.Fatal("original first-send right was not exclusive")
		}
		selected, result := before.selectCandidate(ctx, candidate)
		if selected == nil || result.Outcome != ObservedCurrent {
			t.Fatal("complete original selection", result)
		}
		for i, p := range producers {
			body, present, read := selected.readGeneratedResult(ctx, p.attempt)
			if !present || read.Outcome != 0 || !bytes.Equal(body, results[i]) {
				t.Fatal("original result was not retained", i, read)
			}
			if again, _, code := keys[i].InvokeGeneratedProducer(ctx, p.operation.context.AdmissionID, p.producerLocator, candidate.generated.authority); code == contract.CryptoSuccess || len(again) != 0 {
				t.Fatal("original producer right was reusable", i, code)
			}
			if effects[i].Load() != 1 {
				t.Fatal("original provider effect count", i, effects[i].Load())
			}
		}
	})
}

// full_only: false
func TestGeneratedNonOriginalPreparationRemainsUsable(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	fixture := newEnvironmentFixture(t, ctx, env, nil, false)
	reservation, _ := preparePrivateGeneratedReservation(t, env, fixture.session, generatedPlanInputFixture(t, fixture.session), nil)
	admitted := reservation.operation.context
	admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = testID("single mode admission"), testID("single mode session"), contract.DescriptorVector{}
	attempt := reservation.reservation.originalAttempts[0]
	if _, _, err := fixture.session.generatedProducerRequestForAttempt(ctx, reservation, attempt, admitted); err != nil {
		t.Fatal("single mode request", err)
	}
	if _, _, err := fixture.session.generatedOriginalProducerRequest(ctx, reservation, attempt, admitted); err == nil {
		t.Fatal("single-producer parent admitted complete-original mode")
	}
	effects := 0
	producer, expected := preparePrivateGeneratedProducer(t, env, fixture.session, reservation, func() { effects++ })
	if producer == nil || !producer.claimed || producer.attempt != expected.Template.AttemptID ||
		producer.reservation.candidate.producer != producer || !producer.reservation.candidate.generatedReady() {
		t.Fatal("normal generated producer preparation or claim is unusable")
	}
	candidate := producer.reservation.candidate
	if !candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		body, _, code := env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		if code == contract.CryptoSuccess {
			if result := producer.reservation.state.persistGeneratedResult(ctx, generatedResultWrite{attempt: producer.attempt, body: body}); result.Outcome != 0 {
				return contract.CryptoCustodyUnavailable
			}
		}
		return code
	}) {
		t.Fatal("single producer lost its first-send right")
	}
	if selected, result := fixture.session.selectCandidate(ctx, candidate); selected == nil || result.Outcome != ObservedCurrent || effects != 1 {
		t.Fatal("single mode did not complete one effect", result, effects)
	}
}

func generatedControlledPredecessorInput(t *testing.T, s *StateSession, g *generatedSelection, d contract.GeneratedDutyRecord) custody.GeneratedControlledPredecessor {
	t.Helper()
	selected := mustSelectedGeneratedWork(t, s)
	source, err := selected.generatedDeleteSource(d.OwnerID)
	if err != nil {
		t.Fatal("actual selected controlled source", err)
	}
	return generatedControlledSourcePredecessorInput(t, s, selected, source)
}

func generatedControlledSourcePredecessorInput(t testing.TB, s *StateSession, g *generatedSelection, source contract.GeneratedDeleteSource) custody.GeneratedControlledPredecessor {
	t.Helper()
	input := custody.GeneratedControlledPredecessor{Source: source.Record, BeforeRecords: selectedSupportRecordsForCustodyFixture(t, s)}
	progress, err := g.controlledDeleteSourceProgress(source, nil, true)
	if err != nil {
		t.Fatal("exact selected controlled source progress", err)
	}
	if len(progress.rows) == 0 {
		return input
	}
	if err != nil || progress.ack.record.AttemptID.IsZero() {
		t.Fatal("exact controlled predecessor", err)
	}
	a := progress.ack
	input.Expected, input.Material, input.Result = a.expected, a.material, bytes.Clone(a.result)
	graph, err := g.retainedGraph(a.record.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	input.Graph, err = contract.EncodeGeneratorPlanBundle(graph)
	if err != nil {
		t.Fatal(err)
	}
	access, ok := s.materialAccess(3, a.material.Core.OperationMaterialID)
	if !ok {
		t.Fatal("current original ACK seed access")
	}
	input.SeedAccess, err = contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

// The independent custody fixture checks complete predecessor support bytes.
// Ordinary Core keeps authenticated row facts after a cold read. This test
// adapter copies owned prospective bodies and reads only opaque selected pages
// through their exact authenticated Refs; prospective pages are not yet stored.
func selectedSupportRecordsForCustodyFixture(t testing.TB, s *StateSession) []contract.SupportRecord {
	t.Helper()
	var rows []contract.SupportRecord
	for index, page := range s.support {
		if !slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool { return row.Body == nil }) {
			for _, row := range page.Records {
				rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
			}
			continue
		}
		if index >= len(s.supportFacts) || index >= len(s.root.RequiredSupport) ||
			s.supportFacts[index].ref != s.root.RequiredSupport[index] ||
			page.Domain != s.root.Domain || page.Object != s.root.RequiredSupport[index].Object || page.Index != s.root.RequiredSupport[index].Index ||
			len(s.supportFacts[index].rows) != len(page.Records) {
			t.Fatal("custody fixture selected support Ref")
		}
		facts := s.supportFacts[index]
		for logical, fact := range facts.rows {
			if fact.Kind() != page.Records[logical].Kind || fact.RecordID() != page.Records[logical].RecordID {
				t.Fatal("custody fixture selected support row")
			}
		}
		result, err := withAuthenticatedSupportRows(t.Context(), s.readObjectBorrowedUncached, s.root.Domain, facts,
			func(_ uint16, _ uint16, row contract.SupportRecordView) error {
				rows = append(rows, contract.SupportRecord{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)})
				return nil
			})
		if err != nil || result != (Result{}) {
			t.Fatal("custody fixture selected support read", result, err)
		}
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	return rows
}

// ownSelectedSupportForMutationFixture prepares deliberate support mutations
// from a complete cold selection without retaining predecessor row facts.
func ownSelectedSupportForMutationFixture(t testing.TB, ctx context.Context, session *StateSession) {
	t.Helper()
	// The deliberate mutation needs owned bodies for every selected row. A cold
	// Open keeps fragment facts, so read each authenticated page before replacing
	// its logical rows or clearing the predecessor's facts.
	if len(session.supportFacts) != len(session.support) || len(session.supportFacts) != len(session.root.RequiredSupport) {
		t.Fatal("mutation fixture selected support count")
	}
	support := slices.Clone(session.support)
	for index, facts := range session.supportFacts {
		if facts.ref != session.root.RequiredSupport[index] || len(facts.rows) != len(support[index].Records) ||
			support[index].Domain != session.root.Domain || support[index].Object != facts.ref.Object || support[index].Index != facts.ref.Index {
			t.Fatal("mutation fixture selected support Ref")
		}
		support[index].Records = make([]contract.SupportRecordView, len(facts.rows))
		result, err := withAuthenticatedSupportRows(ctx, session.readObjectBorrowedUncached, session.root.Domain, facts,
			func(logical uint16, _ uint16, row contract.SupportRecordView) error {
				support[index].Records[logical] = contract.SupportRecordView{Kind: row.Kind, RecordID: row.RecordID, Body: bytes.Clone(row.Body)}
				return nil
			})
		if err != nil || result != (Result{}) {
			t.Fatal("mutation fixture selected support read", result, err)
		}
	}
	session.support = support
	session.clearSelectedSupportFacts()
	session.generatedWork, session.generatedGraphs = nil, nil
}

func generatedSourcePlanInput(t *testing.T, run *scenarioRun, f *environmentFixture, mode uint8) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	return generatedSourcePlanInputForProfile(t, run, f, mode, defaultGeneratedFixtureProfile())
}

func generatedSourcePlanInputForProfile(t *testing.T, run *scenarioRun, f *environmentFixture, mode uint8, profile generatedFixtureProfile) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	t.Helper()
	env := run.env
	var sources []contract.GeneratorDeclarationEntry
	var canonical []custody.GeneratedCanonicalSelection
	switch mode {
	case 0:
	case 1:
		source := suppliedSecret(t, env, "source", "generated source", custody.StandardValue)
		sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
			Name: source.Name, Recipients: source.Recipients, Payload: source.InputBytes})
	case 2:
		readers := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
		slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		run.suppliedSelection(f, []ApplyEntryInput{sharingSecret(t, env, "generated canonical source", readers)})
		selection := sessionConsumerSelection(t, f.session, f.session.admission.recipient, "secret")
		record := contract.RetainedCanonicalRecord{OriginalSlot: selection.Slot, Entry: selection.Entry}
		body, err := contract.EncodeRetainedCanonicalRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			Name: "secret", Recipients: record.Entry.Recipients, Payload: body})
		canonical = append(canonical, custody.GeneratedCanonicalSelection{Selection: selection, Record: record})
	default:
		t.Fatal("unknown generated source mode")
	}
	return generatedPlanInputForProfile(t, f.session, generatedVectorID(10), profile, sources...), canonical
}

func generatedAlternateProofBody(t *testing.T, env fixtureEnvironment, s *StateSession, candidate *Candidate, proof string) []byte {
	t.Helper()
	head := candidate.head
	var request contract.SignRequest
	var err error
	signer := env.Trust
	var before, after *[]byte
	switch proof {
	case "k1":
		before, after = &candidate.head.K1, &head.K1
		request, err = contract.NewBindingRequest(binding(s.admission))
	case "k2":
		before, after = &candidate.head.AuthorizationSignature, &head.AuthorizationSignature
		request, err = contract.NewGeneratorRequest(*head.Generator)
	case "k3":
		control := currentControlOf(s)
		if control.Recovery == nil || env.Recovery == nil {
			t.Fatal("recovery proof requested without recovery")
		}
		before, after, signer = &candidate.head.K3, &head.K3, env.Recovery
		request, err = contract.NewK3BasisRequest(control.Recovery.Signing)
	default:
		t.Fatal("unknown generated proof")
	}
	if err != nil {
		t.Fatal(err)
	}
	result := signer.Sign(context.Background(), request)
	if result.Reason != contract.ReasonNone || len(result.Signature) == 0 {
		t.Fatal("alternate generated proof signing", result.Reason)
	}
	*after = result.Signature
	if bytes.Equal(*before, *after) || head.Core != candidate.head.Core || *head.Generator != *candidate.head.Generator {
		t.Fatal("alternate proof did not preserve the generated selection")
	}
	body, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestGeneratedFirstSendNeedsDirectAckAndExactReadback(t *testing.T) {
	type selectionCase struct {
		name, mode, proof string
		cancel, late      bool
		outcome           Outcome
		sends             int
	}
	for _, recovery := range []bool{false, true} {
		cases := []selectionCase{
			{name: "ack", mode: "ack", outcome: ObservedCurrent, sends: 1},
			{name: "lost-before", mode: "lost-before", outcome: EvidenceUnavailable},
			{name: "lost-after", mode: "lost-after", outcome: ObservedCurrent},
			{name: "ack-before", mode: "ack-before", late: true, outcome: UnresolvedCommit},
			{name: "refused", mode: "refused", outcome: AdmissionRefused},
			{name: "cancelled", mode: "lost-before", cancel: true, outcome: EvidenceUnavailable},
			{name: "alternate-k1", mode: "ack", proof: "k1", outcome: ObservedCurrent, sends: 1},
			{name: "alternate-k2", mode: "ack", proof: "k2", outcome: ObservedCurrent, sends: 1},
		}
		if recovery {
			cases = append(cases, selectionCase{name: "alternate-k3", mode: "ack", proof: "k3", outcome: ObservedCurrent, sends: 1})
		}
		for _, sourceMode := range []uint8{0, 1, 2} {
			for _, tc := range cases {
				t.Run(fmt.Sprintf("recovery%t/source%d/%s", recovery, sourceMode, tc.name), func(t *testing.T) {
					ctx := context.Background()
					env, keys := genesisEnvironment(t, contract.GCP, recovery)
					run := newScenarioRun(t, ctx, env)
					f := newEnvironmentFixture(t, ctx, run.env, nil, false)
					input, canonical := generatedSourcePlanInput(t, run, f, sourceMode)
					beforeHead, beforeToken := bytes.Clone(f.session.body), f.session.token
					store := env.Store.(*memoryStore)
					beforeCAS := store.cas
					prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
					p, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
					if store.cas != beforeCAS || !bytes.Equal(store.objects[store.desc.HeadKey].Body, beforeHead) {
						t.Fatal("preparation selected the unfinished successor")
					}
					calls := 0
					var result []byte
					if !p.reservation.candidate.bindFirstSend(p, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
						calls++
						var code contract.CryptoResultCode
						result, _, code = keys.InvokeGeneratedProducer(ctx, p.operation.context.AdmissionID, p.producerLocator, authority)
						return code
					}) {
						t.Fatal("first-send handoff refused")
					}
					store.casMode = tc.mode
					candidate := p.reservation.candidate
					if tc.proof != "" {
						readback := generatedAlternateProofBody(t, env, f.session, candidate, tc.proof)
						f.session.store = generatedReadbackStore{Store: f.session.store, memory: store, body: readback}
					}
					selectContext := ctx
					if tc.cancel {
						cancelled, cancel := context.WithCancel(ctx)
						cancel()
						selectContext = cancelled
					}
					selected, res := f.session.selectCandidate(selectContext, candidate)
					if res.Outcome != tc.outcome || calls != tc.sends {
						t.Fatal("wrong effect-entry count", calls, res)
					}
					if tc.sends == 1 {
						if selected == nil || res.Outcome != ObservedCurrent || res.Reason != NoReason {
							t.Fatal("direct selection", res)
						}
						if store.cas != beforeCAS+1 || selected.head.Core.PreviousToken != beforeToken || selected.head.Core.PreviousDigest != contract.Hash(beforeHead) {
							t.Fatal("reservation did not use its original conditional selection")
						}
						if tc.proof != "" && bytes.Equal(selected.body, candidate.body) {
							t.Fatal("alternate valid proof was not read back")
						}
						record, err := contract.DecodeGeneratedResultRecord(result)
						g, selectedErr := selected.selectedGeneratedWork(context.Background())
						if err != nil || selectedErr != nil || contract.ValidateGeneratedResult(expected, g.attempts[expected.Template.AttemptID].material, record) != nil {
							t.Fatal("original producer result", err, selectedErr)
						}
					} else if len(result) != 0 {
						t.Fatal("unentered producer returned a result")
					}
					if tc.mode == "lost-after" && (selected == nil || res.Outcome != ObservedCurrent) {
						t.Fatal("lost ACK did not distinguish observed current state", res)
					}
					if tc.late {
						store.mu.Lock()
						store.put(store.desc.HeadKey, candidate.body)
						store.mu.Unlock()
						selected, res = Open(ctx, f.admission, env.Store)
						if selected == nil || res.Outcome != ObservedCurrent {
							t.Fatal("later independent state observation", res)
						}
					}
					if _, res := f.session.selectCandidate(ctx, candidate); res.Outcome != AdmissionRefused || calls != tc.sends {
						t.Fatal("selection restored send permission", res)
					}
					if selected != nil {
						cold, res := Open(ctx, f.admission, env.Store)
						if cold == nil || res.Outcome != ObservedCurrent {
							t.Fatal("cold state", res)
						}
						admitted := prior.operation.context
						admitted.IntentDescriptor = contract.DescriptorVector{}
						if _, _, err := cold.generatedProducerRequest(context.Background(), prior, admitted); err == nil {
							t.Fatal("cold selection acquired original producer admission")
						}
					}
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedRecordConstructionPreservesAcceptedRequest(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	prior, _ := preparePrivateGeneratedReservation(t, env, f.session, generatedPlanInputFixture(t, f.session), nil)
	producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
	var result []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("producer handoff")
	}
	selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || len(result) == 0 {
		t.Fatal("original result", res)
	}
	keys.RetireGenerated()
	admitted := generatedPlanInputFixture(t, selected).context
	admitted.AdmissionID, admitted.SessionID = testID("generated record admission"), testID("generated record session")
	plan, err := selected.generatedRecordRequest(context.Background(), expected.Template.AttemptID, result, admitted)
	if err != nil {
		t.Fatal("record admission", err)
	}
	next, err := selected.deriveGeneratedRecord(context.Background(), plan)
	if err != nil {
		t.Fatal("record construction", err)
	}
	before, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, err := next.state.selectedGeneratedWork(context.Background())
	if err != nil || *after.parent != *before.parent || after.phase.Phase != before.phase.Phase+1 ||
		after.phase.AcceptedResultID != expected.Use.ResultID || next.state.root.CurrentAccess.AccessRoot != selected.root.CurrentAccess.AccessRoot ||
		next.state.validateGeneratedSelection(t.Context(), nil) != nil {
		t.Fatal("record changed accepted meaning, access or cold authority", err)
	}
	if next.candidate.generated != nil || len(next.candidate.body) != 0 || len(next.candidate.head.AuthorizationSignature) != 0 || next.candidate.firstSend != nil {
		t.Fatal("public record construction gained private authority or send permission")
	}
	if _, err := next.state.generatedRecordRequest(context.Background(), expected.Template.AttemptID, result, admitted); err == nil {
		t.Fatal("recorded result readmitted")
	}
	if body, present, res := selected.ReadGeneratedResult(ctx, expected.Template.AttemptID); present || body != nil || res.Outcome != 0 {
		t.Fatal("absent rooted inbox changed into a result", res)
	}
	p := preparePrivateGeneratedRecord(t, env, selected, plan)
	candidate := p.reservation.candidate
	if p.reservation.candidate.bindFirstSend(p, func(context.Context, contract.ID) contract.CryptoResultCode {
		t.Fatal("record dispatched")
		return contract.CryptoInvalidAdmission
	}) {
		t.Fatal("record gained first-send permission")
	}
	recorded, res := selected.selectCandidate(ctx, candidate)
	if recorded == nil || res.Outcome != ObservedCurrent {
		t.Fatal("record selection", res)
	}
	keys.RetireGenerated()
	cold, res := Open(ctx, f.admission, env.Store)
	if cold == nil || res.Outcome != ObservedCurrent || cold.head.Core != recorded.head.Core || cold.validateGeneratedSelection(ctx, nil) != nil {
		t.Fatal("record cold state", res)
	}
	if body, present, res := cold.ReadGeneratedResult(ctx, expected.Template.AttemptID); !present || !bytes.Equal(body, result) || res.Outcome != 0 {
		t.Fatal("record did not retain the exact original inbox body", res)
	}
}

// full_only: false
func TestGeneratedKeyReplacementBeforeFirstEntryPreservesOriginalProducer(t *testing.T) {
	for _, mode := range []uint8{0, 1, 2} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("source%d/recovery%t", mode, recovery), func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				replacementKeys := custody.New(t, contract.GCP, fixtureID(env.Domain, "custody"), recovery,
					[]contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")})
				if !reflect.DeepEqual(keys.Bindings(), replacementKeys.Bindings()) || keys.Crypto().InstanceID() == replacementKeys.Crypto().InstanceID() {
					t.Fatal("replacement needs the same configured keys and a distinct private session")
				}
				replacementEnv := env
				replacementEnv.Custody = replacementKeys
				replacementEnv = syntheticAuthorityScenarioEnvironment(t, replacementEnv)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, nil, false)
				input, canonical := generatedSourcePlanInput(t, run, f, mode)
				prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
				entries := 0
				producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, func() { entries++ })
				var successor *StateSession
				var result []byte
				if !producer.reservation.candidate.bindFirstSend(producer, func(dispatchContext context.Context, authority contract.ID) contract.CryptoResultCode {
					if entries != 0 || len(result) != 0 {
						t.Fatal("producer entered before key replacement")
					}
					before, res := Open(ctx, f.admission, env.Store)
					if before == nil || res.Outcome != ObservedCurrent {
						t.Fatal("original reservation did not precede key replacement", res)
					}
					work, err := before.preservedWorkSupportRecords(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					approval := uint8(contract.NormalSigningRole)
					if recovery {
						approval = contract.RecoverySigningRole
					}
					actors := replacementEnv.ReplacementActors(t, ctx, before, 1, 2, approval)
					public, private := replacementKeys.Calls()
					permit := admitAuthorityReplacement(t, before, replacementKeys, actors.After, 1, approval, 2, actors.Source)
					candidate, res := before.PrepareSuccession(ctx, permit, actors.Signers)
					if candidate == nil || res.Outcome != ObservedCurrent {
						t.Fatal("replacement before original entry", res)
					}
					if p, k := replacementKeys.Calls(); p-public != 1 || k-private != int(before.root.AccessRecordCount)+1 {
						t.Fatal("replacement omitted a live material or repeated its private open", p-public, k-private)
					}
					admission := deliverSuccessionBasis(t, candidate)
					if res := before.Select(ctx, candidate); res.Outcome != ObservedCurrent {
						t.Fatal("replacement selection before original entry", res)
					}
					successor, res = Open(ctx, admission, env.Store)
					if successor == nil || res.Outcome != ObservedCurrent {
						t.Fatal("replacement cold selection before original entry", res)
					}
					replacementKeys.RetireAccess()
					actors.Activate(t, successor)
					f.admission = admission
					afterWork, err := successor.preservedWorkSupportRecords(t.Context())
					if err != nil || !reflect.DeepEqual(work, afterWork) || !reflect.DeepEqual(before.root.ValueEntryPages, successor.root.ValueEntryPages) ||
						before.root.AccessRecordCount != successor.root.AccessRecordCount || !controlEqual(currentControlOf(successor), actors.After) {
						t.Fatal("key replacement changed reserved work or current members", err)
					}
					public, private = keys.Calls()
					keys.SetUnavailable(true)
					var code contract.CryptoResultCode
					result, _, code = keys.InvokeGeneratedProducer(dispatchContext, producer.operation.context.AdmissionID, producer.producerLocator, authority)
					if p, k := keys.Calls(); p != public || k != private {
						t.Fatal("original entry reopened an unavailable KMS route", p-public, k-private)
					}
					return code
				}) {
					t.Fatal("original producer handoff")
				}
				selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
				if selected == nil || res.Outcome != ObservedCurrent || successor == nil || entries != 1 || len(result) == 0 {
					t.Fatal("key replacement lost the original producer permission", res)
				}
				if body, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(body) != 0 || entries != 1 {
					t.Fatal("replacement made the original producer reusable")
				}
				keys.RetireGenerated()
				recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), successor, expected.Template.AttemptID, result)
				g, err := recorded.selectedGeneratedWork(context.Background())
				if err != nil || g.phase.Phase != 2 || !bytes.Equal(g.attempts[expected.Template.AttemptID].result, result) || entries != 1 {
					t.Fatal("current private access lost the original result", err)
				}
				checkFreshGeneratedProcess(t, env.Store.(*memoryStore), recorded)
			})
		}
	}
}

// full_only: false
func TestGeneratedSignerOnlyReplacementOpensNoPrivateMaterial(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, recovery)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			input, canonical := generatedSourcePlanInput(t, run, f, 2)
			prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
			var producer *generatedPreparation
			var successor *StateSession
			var result []byte
			calls, returns, public, private := 0, 0, 0, 0
			beforeReturn := func() {
				returns++
				if returns != 1 || calls != 1 || len(result) != 0 {
					t.Fatal("signer replacement did not precede the original return")
				}
				public, private = keys.Calls()
				before, res := Open(ctx, f.admission, env.Store)
				if before == nil || res.Outcome != ObservedCurrent {
					t.Fatal("occupied signer predecessor", res)
				}
				work, err := before.preservedWorkSupportRecords(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				approval := uint8(contract.NormalSigningRole)
				if recovery {
					approval = contract.RecoverySigningRole
				}
				actors := env.ReplacementActors(t, ctx, before, 1, 1, approval)
				if actors.Signers.NormalSuccessor == nil {
					t.Fatal("successor signer missing")
				}
				permit := admitAuthorityReplacement(t, before, actors.Keys, actors.After, 1, approval, 1, actors.Source)
				candidate, res := before.PrepareSuccession(ctx, permit, actors.Signers)
				if candidate == nil || res.Outcome != ObservedCurrent {
					t.Fatal("occupied signer preparation", res)
				}
				admission := deliverSuccessionBasis(t, candidate)
				if res := before.Select(ctx, candidate); res.Outcome != ObservedCurrent {
					t.Fatal("occupied signer selection", res)
				}
				successor, res = Open(ctx, admission, env.Store)
				if successor == nil || res.Outcome != ObservedCurrent {
					t.Fatal("occupied signer cold selection", res)
				}
				actors.Activate(t, successor)
				f.admission = admission
				afterWork, err := successor.preservedWorkSupportRecords(t.Context())
				if err != nil || !reflect.DeepEqual(work, afterWork) || !reflect.DeepEqual(before.root.ValueEntryPages, successor.root.ValueEntryPages) ||
					!reflect.DeepEqual(before.accessRecords(), successor.accessRecords()) || !controlEqual(currentControlOf(successor), actors.After) {
					t.Fatal("signer replacement changed accepted work, values or encrypted material", err)
				}
				if p, k := keys.Calls(); p != public || k != private {
					t.Fatal("signer-only replacement entered private material", p-public, k-private)
				}
				if body, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(body) != 0 {
					t.Fatal("signer replacement restored the entered producer")
				}
			}
			var expected contract.GeneratorResultExpectation
			producer, expected = preparePrivateGeneratedProducer(t, env, f.session, prior, beforeReturn)
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				calls++
				var code contract.CryptoResultCode
				result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("original producer handoff")
			}
			selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
			if selected == nil || res.Outcome != ObservedCurrent || successor == nil || calls != 1 || returns != 1 || len(result) == 0 {
				t.Fatal("original producer lost its return after signer replacement", res)
			}
			if p, k := keys.Calls(); p != public || k != private {
				t.Fatal("late original return reopened private material", p-public, k-private)
			}
			keys.RetireGenerated()
			recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), successor, expected.Template.AttemptID, result)
			g, err := recorded.selectedGeneratedWork(context.Background())
			if err != nil || g.phase.Phase != 2 || !bytes.Equal(g.attempts[expected.Template.AttemptID].result, result) || calls != 1 || returns != 1 {
				t.Fatal("current signer did not preserve the original result", err)
			}
			if body, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(body) != 0 {
				t.Fatal("fresh record restored the original producer")
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), recorded)
		})
	}
}

// full_only: false
func TestGeneratedResultSurvivesCurrentKeyReplacement(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			for _, mode := range []uint8{0, 1, 2} {
				t.Run(fmt.Sprintf("family%d/recovery%t/source%d", family, recovery, mode), func(t *testing.T) {
					ctx := context.Background()
					env, keys := genesisEnvironment(t, family, recovery)
					env = syntheticAuthorityScenarioEnvironment(t, env)
					run := newScenarioRun(t, ctx, env)
					f := newEnvironmentFixture(t, ctx, run.env, nil, false)
					input, canonical := generatedSourcePlanInput(t, run, f, mode)
					prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
					producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
					var result []byte
					calls := 0
					if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
						calls++
						var code contract.CryptoResultCode
						result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
						return code
					}) {
						t.Fatal("producer handoff")
					}
					selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
					if selected == nil || res.Outcome != ObservedCurrent || calls != 1 || len(result) == 0 {
						t.Fatal("original result", res)
					}
					keys.RetireGenerated()
					original, err := selected.selectedGeneratedWork(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					if mode == 2 {
						reader := fixtureID(env.Domain, "reader")
						successor := keys.RecipientSuccessor(t, reader)
						keys.LoseRecipientPredecessor(reader)
						permit := admitReaderReplacement(t, selected, keys, reader, successor)
						candidate, res := selected.PrepareRecipientReplacement(ctx, permit, env.Trust)
						if candidate == nil || res.Outcome != ObservedCurrent {
							t.Fatal("generated source reader replacement", res)
						}
						if res := selected.Select(ctx, candidate); res.Outcome != ObservedCurrent {
							t.Fatal("generated source reader selection", res)
						}
						keys.RetireAccess()
						if err := keys.ActivateRecipientSuccessor(reader); err != nil {
							t.Fatal(err)
						}
						selected, res = Open(ctx, f.admission, env.Store)
						if selected == nil || res.Outcome != ObservedCurrent {
							t.Fatal("generated reader cold selection", res)
						}
						checkFreshGeneratedProcess(t, env.Store.(*memoryStore), selected)
						selection, res := selected.generatedConsumerSelection(ctx, 10, expected.Template.DutyID, canonical[0].Record.Entry.ValueState, reader)
						if res.Outcome != ObservedCurrent || selection.Selection.Binding.Binding.BindingID != successor.BindingID {
							t.Fatal("generated retained source selection", res)
						}
						bindings, err := selected.currentBindings()
						if err != nil {
							t.Fatal(err)
						}
						control := currentControlOf(selected)
						var recoveryID contract.ID
						if control.Recovery != nil {
							recoveryID = control.Recovery.RoleID
						}
						fresh := custody.NewCurrentConsumer(t, fixtureID(env.Domain, "generated retained reader successor"), control.AuthorityRecipientID,
							recoveryID, bindings, selection.Selection.Binding)
						check := fresh.ConsumeGenerated(ctx, selection, custody.StandardValue)
						if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 ||
							len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != reader || check.KeyUses[0].BindingID != successor.BindingID {
							t.Fatal("generated reader successor lost the canonical source", check)
						}
					}
					for _, target := range []uint8{1, 2} {
						if target == 2 && !recovery {
							continue
						}
						operation, mask, approval := uint8(1), uint8(3), uint8(1)
						if recovery {
							approval = 2
						}
						if target == 2 {
							operation, mask, approval = 3, 12, 1
						}
						actors := env.ReplacementActors(t, ctx, selected, operation, mask, approval)
						permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, operation, approval, mask, actors.Source)
						public, private := keys.Calls()
						candidate, res := selected.PrepareSuccession(ctx, permit, actors.Signers)
						if candidate == nil || res.Outcome != ObservedCurrent {
							t.Fatal("generated key replacement", res)
						}
						if p, k := keys.Calls(); p-public != 1 || k-private != int(selected.root.AccessRecordCount)+1 {
							t.Fatal("replacement omitted a live material or repeated an open", p-public, k-private)
						}
						admission := deliverSuccessionBasis(t, candidate)
						if res := selected.Select(ctx, candidate); res.Outcome != ObservedCurrent {
							t.Fatal("generated replacement selection", res)
						}
						keys.RetireAccess()
						selected, res = Open(ctx, admission, env.Store)
						if selected == nil || res.Outcome != ObservedCurrent {
							t.Fatal("generated replacement cold selection", res)
						}
						actors.Activate(t, selected)
						if actors.Signers.NormalSuccessor != nil {
							env.Trust = actors.Signers.NormalSuccessor
						}
						checkFreshGeneratedProcess(t, env.Store.(*memoryStore), selected)
						after, err := selected.selectedGeneratedWork(ctx)
						if err != nil || *after.parent != *original.parent || *after.phase != *original.phase ||
							!bytes.Equal(after.protected[after.parent.MaterialID], original.protected[original.parent.MaterialID]) ||
							after.attempts[expected.Template.AttemptID].record != original.attempts[expected.Template.AttemptID].record {
							t.Fatal("replacement changed accepted work", err)
						}
						if again, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, producer.reservation.candidate.generated.authority); code == contract.CryptoSuccess || len(again) != 0 || calls != 1 {
							t.Fatal("replacement restored original send permission")
						}
					}
					recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, expected.Template.AttemptID, result)
					if calls != 1 {
						t.Fatal("recovered result restored original producer entry")
					}
					g, err := recorded.selectedGeneratedWork(context.Background())
					if err != nil || !bytes.Equal(g.attempts[expected.Template.AttemptID].result, result) {
						t.Fatal("recovered result changed original ciphertext", err)
					}
					checkFreshGeneratedProcess(t, env.Store.(*memoryStore), recorded)
				})
			}
		}
	}
}

// full_only: false
func TestGeneratedRecordedResultSurvivesReciprocalCurrentKeyReplacement(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			for _, mode := range []uint8{0, 1, 2} {
				t.Run(fmt.Sprintf("family%d/recovery%t/source%d", family, recovery, mode), func(t *testing.T) {
					ctx := context.Background()
					env, keys := genesisEnvironment(t, family, recovery)
					env = syntheticAuthorityScenarioEnvironment(t, env)
					run := newScenarioRun(t, ctx, env)
					f := newEnvironmentFixture(t, ctx, run.env, nil, false)
					input, canonical := generatedSourcePlanInput(t, run, f, mode)
					prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, canonical)
					producer, expected := preparePrivateGeneratedProducer(t, env, f.session, prior, nil)
					var result []byte
					if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
						var code contract.CryptoResultCode
						result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
						return code
					}) {
						t.Fatal("producer handoff")
					}
					selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
					if selected == nil || res.Outcome != ObservedCurrent || len(result) == 0 {
						t.Fatal("original result", res)
					}
					keys.RetireGenerated()
					recorded := selectFreshGeneratedRecord(t, env.Store.(*memoryStore), selected, expected.Template.AttemptID, result)
					original, err := recorded.selectedGeneratedWork(context.Background())
					if err != nil || !bytes.Equal(original.attempts[expected.Template.AttemptID].result, result) {
						t.Fatal("recorded result", err)
					}

					frozenContext := generatedPlanInputFixture(t, recorded).context
					frozenContext.AdmissionID, frozenContext.SessionID = testID("generated frozen final admission"), testID("generated frozen final session")
					frozenPlan, err := recorded.generatedFinalRequest(t.Context(), frozenContext)
					if err != nil {
						t.Fatal("generated frozen final request", err)
					}
					recorded, frozen := preparePrivateGeneratedFinal(t, env, recorded, frozenPlan)
					original = mustSelectedGeneratedWork(t, recorded)
					frozenBody, frozenToken := bytes.Clone(frozen.reservation.candidate.body), recorded.token
					keys.RetireGenerated()
					selected, res = Open(ctx, OpenContext{admission: &recorded.admission}, env.Store)
					if selected == nil || res.Outcome != ObservedCurrent {
						t.Fatal("generated recorded-result reopen", res)
					}
					for _, target := range []uint8{2, 1} {
						if target == 2 && !recovery {
							continue
						}
						operation, mask, approval := uint8(1), uint8(3), uint8(1)
						if recovery {
							approval = 2
						}
						if target == 2 {
							operation, mask, approval = 3, 12, 1
						}
						actors := env.ReplacementActors(t, ctx, selected, operation, mask, approval)
						permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, operation, approval, mask, actors.Source)
						candidate, outcome := selected.PrepareSuccession(ctx, permit, actors.Signers)
						if candidate == nil || outcome.Outcome != ObservedCurrent {
							t.Fatal("recorded generated replacement", outcome)
						}
						admission := deliverSuccessionBasis(t, candidate)
						if outcome = selected.Select(ctx, candidate); outcome.Outcome != ObservedCurrent {
							t.Fatal("recorded generated replacement selection", outcome)
						}
						keys.RetireAccess()
						selected, outcome = Open(ctx, admission, env.Store)
						if selected == nil || outcome.Outcome != ObservedCurrent {
							t.Fatal("recorded generated replacement reopen", outcome)
						}
						actors.Activate(t, selected)
						if actors.Signers.NormalSuccessor != nil {
							env.Trust = actors.Signers.NormalSuccessor
						}
						checkFreshGeneratedProcess(t, env.Store.(*memoryStore), selected)
						after, selectErr := selected.selectedGeneratedWork(context.Background())
						if selectErr != nil || *after.parent != *original.parent || *after.phase != *original.phase ||
							!bytes.Equal(after.attempts[expected.Template.AttemptID].result, result) {
							t.Fatal("recorded replacement changed the original result", selectErr)
						}
					}
					if stale, outcome := recorded.selectCandidate(ctx, frozen.reservation.candidate); stale != nil || outcome.Outcome != Contention ||
						outcome.Reason != StalePrecondition || recorded.token != frozenToken || !bytes.Equal(frozen.reservation.candidate.body, frozenBody) {
						t.Fatal("frozen generated final rebased after replacement", outcome)
					}

					finalContext := generatedPlanInputFixture(t, selected).context
					finalContext.AdmissionID, finalContext.SessionID = testID("generated replacement final admission"), testID("generated replacement final session")
					finalPlan, err := selected.generatedFinalRequest(t.Context(), finalContext)
					if err != nil {
						t.Fatal("generated replacement final request", err)
					}
					selected, final := preparePrivateGeneratedFinal(t, env, selected, finalPlan)
					closed, res := selected.selectCandidate(ctx, final.reservation.candidate)
					wantEntryCount := uint32(1)
					if mode != 0 {
						wantEntryCount = 2
					}
					if closed == nil || res.Outcome != ObservedCurrent || !closed.root.Generated.ActiveOwner.IsZero() ||
						closed.root.ValueEntryCount != wantEntryCount || closed.root.Generated.GeneratedCurrent != 1 {
						t.Fatal("generated replacement final selection", res)
					}
					checkFreshGeneratedProcess(t, env.Store.(*memoryStore), closed)
				})
			}
		}
	}
}

func generatedStatePlanInput(t testing.TB, s *StateSession, operation contract.ID, names []string, profile generatedFixtureProfile,
	epoch uint64, incarnations map[string]contract.ID, retiring map[string]contract.ValueEntry) generatedPlanInput {
	t.Helper()
	input := generatedReservationInputForState(t, s, operation, names, profile, epoch, incarnations, retiring)
	plan := generatedPlanInputForGenerations(t, s, operation, names, profile)
	plan.graph, plan.declaration, plan.registry, plan.recoveryPolicy, plan.requestBindings = input.graph, input.declaration,
		input.graph.Request.Registry, input.graph.Request.RecoveryPolicyID, slices.Clone(input.requestBindings)
	plan.context.AdmissionID = contract.Hash(append([]byte("generated state plan admission"), operation[:]...))
	plan.context.SessionID = contract.Hash(append([]byte("generated state plan session"), operation[:]...))
	return plan
}

func selectPrivateGeneratedOperation(t testing.TB, env fixtureEnvironment, s *StateSession, input generatedPlanInput, label string) *StateSession {
	t.Helper()
	closed := selectPrivateGeneratedValueSet(t, env, s, input, label)
	if !closed.root.Generated.ActiveOwner.IsZero() {
		t.Fatal(label, " final selection retained its parent")
	}
	return closed
}

func selectPrivateGeneratedValueSet(t testing.TB, env fixtureEnvironment, s *StateSession, input generatedPlanInput, label string) *StateSession {
	t.Helper()
	ctx, keys := env.operationContext(), env.Custody
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
	producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
	var result []byte
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var code contract.CryptoResultCode
		result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal(label, " producer handoff")
	}
	selected, outcome := s.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || outcome.Outcome != ObservedCurrent || len(result) == 0 {
		t.Fatal(label, " producer selection", outcome)
	}
	keys.RetireGenerated()
	if env.FreshGeneratedRecord == nil {
		t.Fatal(label, " requires a fresh-record hook")
	}
	recorded := env.FreshGeneratedRecord(t, selected, expected.Template.AttemptID, result)
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID, finalContext.SessionID = testID(label+" final admission"), testID(label+" final session")
	finalPlan, err := recorded.generatedFinalRequest(ctx, finalContext)
	if err != nil {
		t.Fatal(label, " final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
	closed, outcome := recorded.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal(label, " final selection", outcome)
	}
	keys.RetireGenerated()
	return closed
}

func selectPrivateGeneratedOperationInProcess(t testing.TB, env fixtureEnvironment, s *StateSession, input generatedPlanInput, label string) *StateSession {
	t.Helper()
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
	recorded, _, _, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, nil)
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID, finalContext.SessionID = testID(label+" final admission"), testID(label+" final session")
	finalPlan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
	if err != nil {
		t.Fatal(label, " final request", err)
	}
	recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan)
	closed, outcome := recorded.selectCandidate(env.operationContext(), final.reservation.candidate)
	if closed == nil || outcome.Outcome != ObservedCurrent || !closed.root.Generated.ActiveOwner.IsZero() {
		t.Fatal(label, " final selection", outcome)
	}
	env.Custody.RetireGenerated()
	return closed
}

// full_only: false
func TestGeneratedSelectedRetirementDutySurvivesCurrentKeyLoss(t *testing.T) {
	cases := []struct {
		name                string
		recovery            bool
		operation, approval uint8
		mask                uint8
		targetRole          uint8
	}{
		{"normal-signer", true, 1, contract.RecoverySigningRole, 1, 1},
		{"normal-kek", true, 1, contract.RecoverySigningRole, 2, 1},
		{"normal-both", true, 1, contract.RecoverySigningRole, 3, 1},
		{"recovery-signer", true, 3, contract.NormalSigningRole, 4, contract.SuccessorRecoverySigner},
		{"recovery-kek", true, 3, contract.NormalSigningRole, 8, contract.SuccessorRecoverySigner},
		{"recovery-both", true, 3, contract.NormalSigningRole, 12, contract.SuccessorRecoverySigner},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, tc.recovery)
			env = syntheticFreshAuthorityReplacementEnvironment(t, env)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			selected := selectPrivateGeneratedOperation(t, env, f.session,
				generatedPlanInputForGenerations(t, f.session, generatedVectorID(210), []string{"generated"}, defaultGeneratedFixtureProfile()), tc.name+" initial")
			old := *selected.valueEntry(0)
			profile := defaultGeneratedFixtureProfile()
			profile.ConfigContractID, profile.ResourceContractID = generatedVectorID(211), generatedVectorID(212)
			selected = selectPrivateGeneratedOperation(t, env, selected,
				generatedStatePlanInput(t, selected, generatedVectorID(214), []string{old.Name}, profile, old.Generated.Epoch+1,
					map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), tc.name+" rotation")
			current := selected.valueEntry(0)
			if current == nil || current.Generated.RetiringDutyPresent != 1 || selected.root.Generated.Retiring != 1 {
				t.Fatal("rotation did not select an exact retirement Duty")
			}
			work, err := selected.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			dutyRow, ok := work.records[generatedRecordKey{kind: 10, id: current.Generated.RetiringDutyID}]
			if !ok {
				t.Fatal("selected rotation omitted its retirement Duty")
			}
			duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
			if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.Status != contract.GeneratedEffectNotStarted {
				t.Fatal("selected rotation changed its retirement Duty", err)
			}
			control := currentControlOf(selected)
			oldTarget := control.AuthorityKMSBinding
			if tc.mask&8 != 0 {
				oldTarget = control.Recovery.KMS
			}
			var retired contract.Trust
			if tc.targetRole == 1 {
				retired = env.Trust
			} else {
				retired = env.Recovery
			}
			actors := env.ReplacementActors(t, ctx, selected, tc.operation, tc.mask, tc.approval)
			permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, tc.operation, tc.approval, tc.mask, actors.Source)
			if tc.mask&(2|8) != 0 {
				for _, route := range []*custody.Fixture{keys, actors.Keys} {
					if witness := route.PrivateWitness(ctx, oldTarget.BindingID, oldTarget, oldTarget); witness.Outcome == contract.CryptoSuccess || witness.Completed != 0 {
						t.Fatal("lost retirement KEK route was available before replacement", witness)
					}
				}
			}
			if tc.mask&(1|4) != 0 {
				probe, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: 1,
					TargetRole: tc.targetRole, DomainID: actors.After.DomainID, CoordinateID: actors.After.CoordinateID,
					AdmissionID: permit.request.AdmissionID, PredecessorFullHEADDigest: permit.request.PredecessorFullHEADDigest,
					RequestCoreDigest: permit.descriptor.Digest, SuccessorBindingDigest: permit.descriptor.Digest,
					ProbeAttemptID: fixtureID(actors.After.DomainID, tc.name+" pre-replacement signing refusal")})
				if err != nil || retired.Sign(ctx, probe).Reason != contract.ReasonAccess {
					t.Fatal("lost retirement signer route was available before replacement", err)
				}
			}
			candidate, outcome := selected.PrepareSuccession(ctx, permit, actors.Signers)
			if candidate == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("retirement Duty replacement preparation", outcome)
			}
			admission := deliverSuccessionBasis(t, candidate)
			if outcome = selected.Select(ctx, candidate); outcome.Outcome != ObservedCurrent {
				t.Fatal("retirement Duty replacement selection", outcome)
			}
			keys.RetireAccess()
			currentState, outcome := Open(ctx, admission, env.Store)
			if currentState == nil || outcome.Outcome != ObservedCurrent {
				t.Fatal("retirement Duty replacement reopen", outcome)
			}
			actors.Activate(t, currentState)
			if tc.mask&(2|8) != 0 {
				if witness := keys.PrivateWitness(ctx, oldTarget.BindingID, oldTarget, oldTarget); witness.Outcome == contract.CryptoSuccess || witness.Completed != 0 {
					t.Fatal("retired KEK route remained available", witness)
				}
			}
			if tc.mask&(1|4) != 0 {
				probe, err := contract.NewSuccessorSignerProbeRequest(contract.SuccessorProbeCore{Schema: 1, EvidenceKind: 1,
					TargetRole: tc.targetRole, DomainID: actors.After.DomainID, CoordinateID: actors.After.CoordinateID,
					AdmissionID: permit.request.AdmissionID, PredecessorFullHEADDigest: permit.request.PredecessorFullHEADDigest,
					RequestCoreDigest: permit.descriptor.Digest, SuccessorBindingDigest: permit.descriptor.Digest,
					ProbeAttemptID: fixtureID(actors.After.DomainID, tc.name+" retired signing refusal")})
				if err != nil || retired.Sign(ctx, probe).Reason != contract.ReasonAccess {
					t.Fatal("retired signer remained available", err)
				}
			}
			checkFreshGeneratedProcess(t, env.Store.(*memoryStore), currentState)
			after, err := currentState.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal("replacement lost the selected retirement Duty", err)
			}
			afterDuty, present := after.records[generatedRecordKey{kind: 10, id: current.Generated.RetiringDutyID}]
			beforeTarget, beforeTargetErr := work.retirementTarget(t.Context(), duty)
			afterDutyRecord, afterDutyErr := contract.InspectGeneratedDutyRecord(afterDuty.Body)
			afterTarget, afterTargetErr := after.retirementTarget(t.Context(), afterDutyRecord)
			if !present || beforeTargetErr != nil || afterDutyErr != nil || afterTargetErr != nil ||
				!bytes.Equal(dutyRow.Body, afterDuty.Body) || beforeTarget != afterTarget || currentState.root.Generated.Retiring != 1 {
				t.Fatal("replacement changed the selected retirement Duty", err)
			}
			fresh := currentGeneratedEnvironment(t, env.Store, currentState)
			input, inputCanonical := generatedDeletePlanInput(t, currentState, generatedVectorID(215), afterDutyRecord, afterTarget, 2)
			prior, _ := preparePrivateGeneratedReservation(t, fresh, currentState, input, inputCanonical)
			recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, fresh, currentState, prior, custody.StandardValue, true, nil)
			fresh.Custody.RetireGenerated()
			closed := selectControlledRetirementClose(t, ctx, fresh, recorded, expected.Template.AttemptID)
			closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
			if closed.root.Generated.Retiring != 0 || closed.root.Generated.Duties != 0 || closed.root.Generated.Hazards != 0 {
				t.Fatal("current replacement authority did not close the exact retirement Duty")
			}
		})
	}
}

func generatedDeletePlanInput(t testing.TB, s *StateSession, operation contract.ID, duty contract.GeneratedDutyRecord,
	target contract.GeneratorTarget, purpose contract.GeneratorLineagePurpose) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	return generatedDeletePlanInputForIdentity(t, s, operation, target, purpose, duty.OwnerID, duty.ConfigContractID, duty.ResourceContractID,
		duty.ExecutorID, duty.CredentialRouteID, duty.DescriptorID, duty.ResultContractID, duty.CompletionClass)
}

func generatedDeletePlanInputForSource(t testing.TB, s *StateSession, operation contract.ID, row contract.SupportRecord, target contract.GeneratorTarget) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	t.Helper()
	source, err := contract.InspectGeneratedDeleteSource(row)
	if err != nil || row.Kind == 10 && source.Duty.Kind != contract.GeneratedDutyUnselectedCleanup {
		t.Fatal("actual ordinary cleanup source", err)
	}
	// Bind the delete contract recorded by the fixed graph, not the separate
	// create contract retained on the original Target.
	work := mustSelectedGeneratedWork(t, s)
	var deleteContract contract.ID
	if original, ok := work.attempts[source.OriginalAttemptID]; ok && original.expected.Template.Action == 2 {
		deleteContract = source.ResultContractID
	} else {
		graph, err := work.retainedGraph(target.OriginalOperationID)
		if err != nil {
			t.Fatal(err)
		}
		for _, lineage := range graph.Lineages {
			for _, x := range lineage.Templates[:lineage.TemplateCount] {
				if lineage.Purpose == 3 && x.ResourceIncarnationID == target.ResourceID && x.DutyID == source.OwnerID {
					deleteContract = x.ResultContractID
				}
			}
		}
	}
	if deleteContract.IsZero() {
		t.Fatal("source has no recorded exact cleanup contract")
	}
	return generatedDeletePlanInputForIdentity(t, s, operation, target, 3, source.OwnerID, source.ConfigContractID, source.ResourceContractID,
		source.ExecutorID, source.CredentialRouteID, source.DescriptorID, deleteContract, source.CompletionClass)
}

func generatedDeletePlanInputForIdentity(t testing.TB, s *StateSession, operation contract.ID, target contract.GeneratorTarget,
	purpose contract.GeneratorLineagePurpose, owner, profileID, assumption, executor, route, permission, resultContract contract.ID, completion uint8) (generatedPlanInput, []custody.GeneratedCanonicalSelection) {
	t.Helper()
	if purpose != contract.GeneratorLineageRetirement && purpose != contract.GeneratorLineageCleanup {
		t.Fatal("invalid delete purpose")
	}
	work, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	facts, err := work.createTargetEvidence(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	var reader contract.ID
	switch facts.Schema {
	case contract.GeneratorSafeFactsSchema:
		if facts.LifecycleMode != contract.GeneratorLifecycleManaged {
			t.Fatal("delete fixture has no Cloudflare create evidence")
		}
		reader = contract.GeneratorResultReaderID()
	default:
		t.Fatal("delete fixture create evidence reader is unsupported")
	}
	profile := generatedFixtureProfile{LifecycleMode: contract.GeneratorLifecycleManaged, ResultReaderID: reader, ConfigContractID: profileID, ResourceContractID: assumption,
		ExecutorID: executor, CredentialRouteID: route, DescriptorID: permission}
	sources, canonical := generatedCurrentDeclaration(t, s)
	input := generatedPlanInputForGenerations(t, s, operation, nil, profile, sources...)
	input.context.AdmissionID = contract.Hash(append([]byte("generated delete plan admission"), operation[:]...))
	input.context.SessionID = contract.Hash(append([]byte("generated delete plan session"), operation[:]...))
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, Purpose: purpose, DomainID: s.root.Domain, OperationID: operation,
		Name: target.Name, EntryIncarnationID: target.IncarnationID, Epoch: target.Epoch, IntentDigest: facts.IntentDigest,
		ResourceIncarnationID: target.ResourceID, TemplateCount: 1}
	lineage.LineageID, err = contract.GeneratorObligationLineageID(lineage.DomainID, operation, target.ResourceID, purpose)
	if err != nil {
		t.Fatal(err)
	}
	x := contract.GeneratorAttemptTemplate{Schema: contract.GeneratorAttemptTemplateSchema, LifecycleMode: contract.GeneratorLifecycleManaged, ResultReaderID: reader, Action: 2, LineageID: lineage.LineageID,
		ResourceIncarnationID: target.ResourceID, DutyID: owner, ConfigContractID: profileID,
		ResourceContractID: assumption, ExecutorID: executor, CredentialRouteID: route,
		DescriptorID: permission, ResultContractID: resultContract, IntentDigest: facts.IntentDigest,
		ResourceDigest: target.ResourceDigest, TargetKind: 2, TargetSourceID: target.ResourceID, CompletionClass: completion,
		RequiredAuthoritySet: 1}
	if purpose == contract.GeneratorLineageCleanup {
		x.TargetKind = 3
		x.TargetSourceID, err = generatedCreateResultID(s.root.Domain, target.OriginalOperationID, target.OriginalAttemptID)
		if err != nil {
			t.Fatal(err)
		}
	}
	x.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, 0)
	if err != nil {
		t.Fatal(err)
	}
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(s.root.Domain, operation, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.HazardID, err = contract.GeneratorHazardID(s.root.Domain, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, 2)
	if err != nil {
		t.Fatal(err)
	}
	x.ResultID, err = contract.GeneratorResultID(s.root.Domain, operation, x.AttemptID, x.TransmissionID, 2)
	if err != nil {
		t.Fatal(err)
	}
	x.InboxID, err = contract.GeneratorInboxID(s.root.Domain, operation, x.AttemptID, x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(x)
	if err != nil {
		t.Fatal(err)
	}
	lineage.Templates[0] = x
	input.graph.Lineages = []contract.GeneratorLineageTemplate{lineage}
	input.graph.Header.LineageCount, input.graph.Header.TemplateCount = 0, 1
	input.graph.Request.OperationKind = 38
	if purpose == 3 {
		input.graph.Request.OperationKind = 31
	}
	for i := range input.graph.ValueEntryPlans {
		input.graph.ValueEntryPlans[i].ChangeMask = 0
	}
	input.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(input.graph.Request)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(input.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.Edges = nil
	for _, guard := range []uint8{3, 4} {
		input.graph.Edges = append(input.graph.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template,
			DestinationTemplateID: join, Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: 1})
	}
	use := contract.GeneratorResultUse{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID, InboxID: x.InboxID,
		ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID,
		MaterialID: input.graph.Header.MaterialID, Purpose: 1, MaxFacts: 4096}
	input.graph.ResultUses = []contract.GeneratorResultUse{use}
	input.graph.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(input.graph.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	input.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(input.graph.Header, input.graph.ValueEntryPlans, input.graph.Lineages, input.graph.Edges)
	if err != nil {
		t.Fatal("delete graph identity", err)
	}
	if err := contract.ValidateGeneratorEffectGraph(input.graph); err != nil {
		t.Fatal("delete graph closure", err)
	}
	requestDigest := contract.Hash(append([]byte("generated delete request"), operation[:]...))
	if len(input.requestBindings) != 0 {
		requestDigest = input.requestBindings[0].Digest
	}
	input.requestBindings = generatedFixtureRequestBindings(input.graph, requestDigest)
	input.registry, input.recoveryPolicy = input.graph.Request.Registry, input.graph.Request.RecoveryPolicyID
	return input, canonical
}

// full_only: false
func TestGeneratedFreshRetirementReservationClaimsAndSendsOnce(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	selected := selectPrivateGeneratedOperation(t, env, f.session,
		generatedPlanInputForGenerations(t, f.session, generatedVectorID(220), []string{"generated"}, defaultGeneratedFixtureProfile()), "delete initial")
	old := *selected.valueEntry(0)
	profile := defaultGeneratedFixtureProfile()
	profile.ConfigContractID, profile.ResourceContractID = generatedVectorID(221), generatedVectorID(222)
	selected = selectPrivateGeneratedOperation(t, env, selected,
		generatedStatePlanInput(t, selected, generatedVectorID(224), []string{old.Name}, profile, old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "delete rotation")
	work, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current := selected.valueEntry(0)
	dutyRow := work.records[generatedRecordKey{kind: 10, id: current.Generated.RetiringDutyID}]
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	if err != nil {
		t.Fatal(err)
	}
	target, err := work.retirementTarget(t.Context(), duty)
	if err != nil {
		t.Fatal(err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, selected, generatedVectorID(225), duty, target, 2)
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
	if prior.producerPhase == nil || prior.producerPhase.TransitionKind != contract.GeneratorAuthorityRetireReserve {
		t.Fatal("retirement reserve lost its producer phase")
	}
	producer, expected := preparePrivateGeneratedProducer(t, env, selected, prior, nil)
	calls := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		calls++
		_, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("retirement producer handoff")
	}
	entered, outcome := selected.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || outcome.Outcome != ObservedCurrent || calls != 1 {
		t.Fatal("retirement reserve selection and first send", outcome, calls)
	}
	keys.RetireGenerated()
	reopened, outcome := Open(ctx, OpenContext{admission: &entered.admission}, env.Store)
	if reopened == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("retirement reserve reopen", outcome)
	}
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), reopened)
	g, err := reopened.selectedGeneratedWork(context.Background())
	if err != nil || g.attempts[expected.Template.AttemptID].record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("reopened retirement reserve lost entered delete", err)
	}
}

func selectPrivateFailedGeneratedAggregate(t *testing.T, env fixtureEnvironment, s *StateSession) *StateSession {
	closed, _ := selectPrivateOwnedUnusableAggregate(t, env, s, []string{"alpha", "omega"})
	return closed
}

// The owned failure is produced and sealed inside custody, recorded by its
// actual invocation and handed off by the nonselecting Final. No fixture
// installs a Hazard or changes an effect state to obtain cleanup permission.
func selectPrivateOwnedUnusableAggregate(t *testing.T, env fixtureEnvironment, s *StateSession, names []string, operations ...contract.ID) (*StateSession, generatedAttempt) {
	return selectPrivateOwnedUnusableAggregateForProfile(t, env, s, names, defaultGeneratedFixtureProfile(), operations...)
}

func selectPrivateOwnedUnusableAggregateForProfile(t *testing.T, env fixtureEnvironment, s *StateSession, names []string, profile generatedFixtureProfile, operations ...contract.ID) (*StateSession, generatedAttempt) {
	t.Helper()
	operation := generatedVectorID(230)
	if len(operations) == 1 {
		operation = operations[0]
	}
	input := generatedPlanInputForGenerations(t, s, operation, names, profile)
	return selectPrivateOwnedUnusableAggregateFromInput(t, env, s, names, input, nil)
}

func selectPrivateOwnedUnusableAggregateFromInput(t *testing.T, env fixtureEnvironment, s *StateSession, names []string, input generatedPlanInput, canonical []custody.GeneratedCanonicalSelection) (*StateSession, generatedAttempt) {
	t.Helper()
	ctx, keys := env.operationContext(), env.Custody
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, canonical)
	facts := acquireGeneratedProducerFixtureFacts(t, env, s, prior)
	if len(names) == 0 || len(input.requestBindings) != len(names) {
		t.Fatal("owned aggregate requires the complete original create set")
	}
	producerKeys := make([]*custody.Fixture, len(names))
	producers := make([]*generatedPreparation, len(names))
	expectedResults := make([]contract.GeneratorResultExpectation, len(names))
	packets := make([][]byte, len(names))
	for i := range names {
		producerKeys[i] = keys
		if i != 0 {
			producerKeys[i] = keys.ForkGenerated(t)
		}
		t.Cleanup(producerKeys[i].RetireGenerated)
		choice := uint8(custody.StandardValue)
		if i == len(names)-1 {
			choice = custody.GeneratedTerminalFailure
		}
		producers[i], expectedResults[i] = preparePrivateGeneratedOriginalProducerForAttempt(t, env, s, prior, producerKeys[i],
			input.requestBindings[i].AttemptID, facts, choice, nil, nil)
	}
	if candidate, outcome := s.ClaimGeneratedOriginalSet(ctx, producers, env.Trust); candidate == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("owned aggregate complete original set Claim", outcome)
	}
	if !producers[0].reservation.candidate.bindFirstSend(producers[0], func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		for i, producer := range producers {
			var code contract.CryptoResultCode
			packets[i], _, code = producerKeys[i].InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
			if code != contract.CryptoSuccess {
				return code
			}
		}
		return contract.CryptoSuccess
	}) {
		t.Fatal("owned aggregate complete original handoff")
	}
	selected, outcome := s.selectCandidate(ctx, producers[0].reservation.candidate)
	if selected == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("owned aggregate complete original selection", outcome)
	}
	for _, producer := range producerKeys {
		producer.RetireGenerated()
	}
	var owned generatedAttempt
	for i := range names {
		expected, packet := expectedResults[i], packets[i]
		if len(packet) == 0 {
			t.Fatal("owned aggregate original produced no packet", i)
		}
		admitted := generatedPlanInputFixture(t, selected).context
		label := fmt.Sprintf("owned aggregate %x original %d Record", input.graph.Request.OperationID, i)
		admitted.AdmissionID, admitted.SessionID = testID(label+" admission"), testID(label+" session")
		plan, err := selected.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, admitted)
		if err != nil {
			t.Fatal("owned aggregate pre-Final Record request construction", err)
		}
		prior = preparePrivateGeneratedRecord(t, env, selected, plan)
		selected, outcome = selected.selectCandidate(ctx, prior.reservation.candidate)
		if selected == nil || outcome.Outcome != ObservedCurrent {
			t.Fatal("owned aggregate record selection", outcome)
		}
		keys.RetireGenerated()
		if i == len(names)-1 {
			work := mustSelectedGeneratedWork(t, selected)
			owned = work.attempts[expected.Template.AttemptID]
			r, err := contract.InspectGeneratedResultRecord(owned.result)
			d, dutyErr := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, owned.record.OwnerID}].Body)
			target, targetErr := work.generatedCleanupTarget(10, d.DutyID, d.Target)
			wantConsumers := uint32(2) // Independent derive and late-adoption uses.
			if i == 0 {
				wantConsumers += uint32(len(canonical))
			}
			if err != nil || dutyErr != nil || targetErr != nil || r.SafeFacts.Disposition != 2 || len(r.SafeFacts.ResourceData) == 0 ||
				owned.record.State != contract.GeneratedEffectFailedTerminal || d.Status != owned.record.State ||
				target.ResourceDigest != generatedFactsResourceDigest(r.SafeFacts.GeneratorSafeFacts) || target.OriginalAttemptID != owned.record.AttemptID ||
				owned.record.History != d.History || d.Consumers.Count != wantConsumers {
				t.Fatal("owned aggregate Record lost exact failed ownership", err, dutyErr, targetErr, r.SafeFacts.Disposition, (len(r.SafeFacts.ResourceData) > 0), owned.record.State, d.Status, target.ResourceDigest == generatedFactsResourceDigest(r.SafeFacts.GeneratorSafeFacts), target.OriginalAttemptID == owned.record.AttemptID, owned.record.History.Count, d.Consumers.Count)
			}
		}
	}
	finalContext := generatedPlanInputFixture(t, selected).context
	finalLabel := fmt.Sprintf("owned aggregate %x Final", input.graph.Request.OperationID)
	finalContext.AdmissionID = testID(finalLabel + " admission")
	finalContext.SessionID = testID(finalLabel + " session")
	finalPlan, err := selected.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || finalPlan.selecting {
		t.Fatal("failed aggregate final request", err)
	}
	selected, final := preparePrivateGeneratedFinal(t, env, selected, finalPlan)
	closed, outcome := selected.selectCandidate(ctx, final.reservation.candidate)
	if closed == nil || outcome.Outcome != ObservedCurrent || closed.root.ValueEntryCount != s.root.ValueEntryCount || closed.root.Generated.Duties != s.root.Generated.Duties+uint32(len(names)-1) ||
		!closed.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("failed aggregate final selection", outcome)
	}
	keys.RetireGenerated()
	return closed, owned
}

// full_only: false
func TestGeneratedActualOwnedUnusableFinalRootsExactHazard(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, names := range [][]string{{"omega"}, {"alpha", "omega"}} {
			t.Run(fmt.Sprintf("recovery=%t/siblings=%d", recovery, len(names)-1), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, recovery)
				f := newEnvironmentFixture(t, context.Background(), env, nil, false)
				closed, original := selectPrivateOwnedUnusableAggregate(t, env, f.session, names)
				closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
				work := mustSelectedGeneratedWork(t, closed)
				row, ok := work.records[generatedRecordKey{11, original.expected.Template.HazardID}]
				if !ok {
					t.Fatal("owned-unusable Final lost exact fixed-template Hazard")
				}
				h, err := contract.InspectGeneratedHazardRecord(row.Body)
				target, targetErr := work.generatedCleanupTarget(11, h.HazardID, h.Target)
				a, retained := work.attempts[original.record.AttemptID]
				if err != nil || targetErr != nil || h.OwnerID != original.record.OwnerID || h.OriginalOperationID != original.record.OperationID ||
					h.OriginalAttemptID != original.record.AttemptID || h.Exposure != contract.GeneratedExposureLateEffect ||
					target.OriginalAttemptID != original.record.AttemptID || target.ResourceID != original.record.ResourceID ||
					!retained || a.record.State != contract.GeneratedEffectFailedTerminal || !bytes.Equal(a.result, original.result) ||
					a.record.History != original.record.History || h.Consumers.Count != 1 {
					t.Fatal("owned-unusable Final changed exact target, failed identity or original readers", err, targetErr)
				}
				if _, ok := closed.materialAccess(3, original.material.Core.OperationMaterialID); !ok {
					t.Fatal("owned-unusable Final lost current original Seed Access")
				}
				if _, ok := work.records[generatedRecordKey{10, original.record.OwnerID}]; ok {
					t.Fatal("owned-unusable Final invented succeeded cleanup Duty")
				}
				// Close only the succeeded sibling first, when present. The failed
				// resource remains its actual Hazard, never a fabricated Duty.
				if len(names) == 1 {
					selection, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
					if err != nil || !ok || selection.kind != generatedCleanupHazard || selection.hazard.HazardID != h.HazardID {
						t.Fatal("owned-unusable actual Hazard is not exact cleanup source", err)
					}
					input, inputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(234), row, target)
					prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
					producer, expected := preparePrivateGeneratedProducer(t, env, closed, prior, nil)
					var packet []byte
					calls := 0
					if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
						calls++
						var code contract.CryptoResultCode
						packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
						return code
					}) {
						t.Fatal("actual Hazard cleanup first-send handoff")
					}
					entered, result := closed.selectCandidate(context.Background(), producer.reservation.candidate)
					if entered == nil || result.Outcome != ObservedCurrent || calls != 1 || len(packet) == 0 || expected.TargetResourceDigest != target.ResourceDigest {
						t.Fatal("actual Hazard cleanup exact dispatch", result)
					}
					env.Custody.RetireGenerated()
					recordPlan, err := entered.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, generatedPlanInputFixture(t, entered).context)
					if err != nil {
						t.Fatal("actual Hazard cleanup Record request", err)
					}
					recorded := preparePrivateGeneratedRecord(t, env, entered, recordPlan)
					selected, outcome := entered.selectCandidate(context.Background(), recorded.reservation.candidate)
					if selected == nil || outcome.Outcome != ObservedCurrent {
						t.Fatal("actual Hazard cleanup Record selection", outcome)
					}
					env.Custody.RetireGenerated()
					permit, err := selected.admitGeneratedOrdinaryCleanupClose(context.Background(), expected.Template.AttemptID, generatedPlanInputFixture(t, selected).context)
					if err != nil {
						t.Fatal("actual Hazard receipt-free cleanup close admission", err)
					}
					candidate, outcome := selected.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
					if candidate == nil || outcome.Outcome != ObservedCurrent {
						t.Fatal("actual Hazard receipt-free cleanup close preparation", outcome)
					}
					cleaned, outcome := selected.selectCandidate(context.Background(), candidate)
					if cleaned == nil || outcome.Outcome != ObservedCurrent || !cleaned.root.Generated.ActiveOwner.IsZero() {
						t.Fatal("actual Hazard receipt-free cleanup close selection", outcome)
					}
					cleaned = generatedLifecycleReopen(t, t.Context(), cleaned, env.Store)
					checkGeneratedReceiptRowsUnchanged(t, selected, cleaned)
					cleanWork := mustSelectedGeneratedWork(t, cleaned)
					if _, present := cleanWork.records[generatedRecordKey{11, h.HazardID}]; present {
						t.Fatal("actual Hazard cleanup did not remove closed source")
					}
					for id, observed := range map[contract.ID]struct {
						inbox, result contract.ID
						body          []byte
					}{original.record.AttemptID: {original.record.InboxID, original.record.ResultID, original.result},
						expected.Template.AttemptID: {expected.Template.InboxID, expected.Template.ResultID, packet}} {
						released, present := cleanWork.releases[id]
						if !present || released.release.State != contract.GeneratedReleasePending || released.release.ObjectLength != uint32(len(observed.body)) ||
							released.release.InboxID != observed.inbox || released.release.OriginalResultID != observed.result ||
							released.release.SelectedHandoffDigest != contract.Hash(observed.body) || released.release.HandoffRevisionID != cleaned.head.Core.Revision ||
							released.release.CapacityReservation != h.CapacityReservation {
							t.Fatal("actual Hazard cleanup lost exact observed release")
						}
						key, err := format.GeneratedResultKey(cleaned.admission.store.Prefix, cleaned.root.Domain, observed.inbox)
						stored := env.Store.(*memoryStore).objects[key]
						if err != nil || !bytes.Equal(stored.Body, observed.body) {
							t.Fatal("ordinary close changed the exact original result coordinate or bytes", err)
						}
					}
					deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
					cleaned = selectActualGeneratedInboxRelease(t, t.Context(), env, cleaned, deleteStore, expected.Template.AttemptID, false)
					cleaned = selectActualGeneratedInboxRelease(t, t.Context(), env, cleaned, deleteStore, original.record.AttemptID, true)
					remaining := mustSelectedGeneratedWork(t, cleaned).releases[original.record.AttemptID]
					if remaining.release.State != contract.GeneratedReleaseUnknown || remaining.release.ObjectLength != uint32(len(original.result)) || remaining.release.SelectedHandoffDigest != contract.Hash(original.result) {
						t.Fatal("lost actual release reply lost exact possible-garbage mapping")
					}
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedActualOwnedUnusableFinalPreservesOlderOwners(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			f := newEnvironmentFixture(t, context.Background(), env, nil, false)
			older, _ := selectPrivateOwnedUnusableAggregate(t, env, f.session, []string{"alpha", "omega"})
			before := mustSelectedGeneratedWork(t, older)
			var preserved []contract.SupportRecord
			for _, row := range older.supportRecords() {
				if row.Kind == 9 || row.Kind == 10 || row.Kind == 11 {
					preserved = append(preserved, row)
				}
				if row.Kind == contract.GeneratorVectorSupportKind {
					v, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						t.Fatal(err)
					}
					if v.OwnerKind == 9 || v.OwnerKind == 10 || v.OwnerKind == 11 {
						preserved = append(preserved, row)
					}
				}
			}
			closed, _ := selectPrivateOwnedUnusableAggregate(t, env, older, []string{"eta"}, generatedVectorID(235))
			closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
			after := mustSelectedGeneratedWork(t, closed)
			for _, row := range preserved {
				got, ok := after.records[generatedRecordKey{row.Kind, row.RecordID}]
				if !ok || !bytes.Equal(got.Body, row.Body) {
					t.Fatal("failed Final changed older owner or complete carrier", row.Kind)
				}
			}
			for key := range before.consumers {
				// The aggregate is map-derived, not a wire-ordered vector. Compare
				// every encoded field and its multiplicity; carriers above remain
				// byte-identical, including their canonical wire order.
				encode := func(consumers []contract.GeneratorConsumer) [][]byte {
					bodies := make([][]byte, len(consumers))
					for i, consumer := range consumers {
						var err error
						bodies[i], err = contract.EncodeGeneratorConsumer(consumer)
						if err != nil {
							t.Fatal(err)
						}
					}
					slices.SortFunc(bodies, bytes.Compare)
					return bodies
				}
				if !reflect.DeepEqual(encode(before.consumers[key]), encode(after.consumers[key])) {
					t.Fatalf("failed Final changed older retained reader: material=%+v before=%+v after=%+v", key, before.consumers[key], after.consumers[key])
				}
			}
		})
	}
}

func selectActualGeneratedPacketRecord(t testing.TB, env fixtureEnvironment, s *StateSession, prior *generatedPreparation, choice uint8, selectRecord bool, probe func(context.Context, contract.GeneratedProducerCommand) []byte) (*StateSession, *generatedPreparation, contract.GeneratorResultExpectation, []byte) {
	t.Helper()
	producer, expected := preparePrivateGeneratedProducerProbe(t, env, s, prior, choice, nil, probe)
	var packet []byte
	calls := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		calls++
		var code contract.CryptoResultCode
		packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("actual packet first-send handoff")
	}
	entered, result := s.selectCandidate(env.operationContext(), producer.reservation.candidate)
	if entered == nil || result.Outcome != ObservedCurrent || calls != 1 || len(packet) == 0 {
		t.Fatal("actual packet first-send selection", result, calls)
	}
	env.Custody.RetireGenerated()
	plan, err := entered.generatedRecordRequest(context.Background(), expected.Template.AttemptID, packet, generatedPlanInputFixture(t, entered).context)
	if err != nil {
		t.Fatal("actual packet Record request", err)
	}
	record := preparePrivateGeneratedRecord(t, env, entered, plan)
	if !selectRecord {
		return entered, record, expected, packet
	}
	selected, result := entered.selectCandidate(env.operationContext(), record.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual packet Record selection", result)
	}
	env.Custody.RetireGenerated()
	return selected, record, expected, packet
}

// full_only: false
func TestGeneratedActualOwnedUnusableRetryCleanupPreservesCreateAncestry(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, class := range []uint8{contract.GeneratedCompletionAcknowledged, contract.GeneratedCompletionConfirmed} {
			t.Run(fmt.Sprintf("recovery%t/class%d", recovery, class), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, recovery)
				f := newEnvironmentFixture(t, context.Background(), env, nil, false)
				profile := defaultGeneratedFixtureProfile()
				profile.CompletionClass = class
				input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), []string{"omega"}, profile)
				prior, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
				selected, prior, first, packet := selectActualGeneratedPacketRecord(t, env, f.session, prior, custody.GeneratedConfirmedNoEffect, false, nil)
				packetResult, err := contract.InspectGeneratedResultRecord(packet)
				if err != nil || packetResult.SafeFacts.Disposition != contract.GeneratorDispositionConfirmedNoEffect || (len(packetResult.SafeFacts.ResourceData) > 0) {
					t.Fatal("actual qualified no-effect", err)
				}
				planned, selectedResult := selected.selectCandidate(context.Background(), prior.reservation.candidate)
				if planned == nil || selectedResult.Outcome != ObservedCurrent {
					t.Fatal("select no-effect successor plan", selectedResult)
				}
				prior = preparePrivateGeneratedSuccessorReservation(t, env, planned)
				selected, _, retry, packet := selectActualGeneratedPacketRecord(t, env, planned, prior, custody.GeneratedTerminalFailure, true, nil)
				work := mustSelectedGeneratedWork(t, selected)
				original := work.attempts[retry.Template.AttemptID]
				ancestry, err := work.vectors.resolve(9, original.record.AttemptID, contract.GeneratorVectorHistory, original.record.History)
				if err != nil || len(ancestry) != 2 || retry.Template.PredecessorAttemptID != first.Template.AttemptID || original.record.State != contract.GeneratedEffectFailedTerminal || !bytes.Equal(original.result, packet) {
					t.Fatal("actual failed retry ancestry", err)
				}
				finalContext := generatedPlanInputFixture(t, selected).context
				finalContext.AdmissionID, finalContext.SessionID = testID("actual failed retry final admission"), testID("actual failed retry final session")
				finalPlan, err := selected.generatedFinalRequest(t.Context(), finalContext)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := selected.deriveGeneratedFinal(t.Context(), finalPlan, nil, nil); err != nil {
					t.Fatal("actual retry nonselecting Final derivation", err)
				}
				selected, final := preparePrivateGeneratedFinal(t, env, selected, finalPlan)
				closed, outcome := selected.selectCandidate(context.Background(), final.reservation.candidate)
				if closed == nil || outcome.Outcome != ObservedCurrent {
					t.Fatal("actual retry nonselecting Final", outcome)
				}
				env.Custody.RetireGenerated()
				closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
				work = mustSelectedGeneratedWork(t, closed)
				row := work.records[generatedRecordKey{11, retry.Template.HazardID}]
				h, err := contract.InspectGeneratedHazardRecord(row.Body)
				if err != nil || h.History != original.record.History {
					t.Fatal("actual retry Final lost full source ancestry", err)
				}
				target, err := work.generatedCleanupTarget(11, h.HazardID, h.Target)
				if err != nil {
					t.Fatal(err)
				}
				deletion, deletionCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(234), row, target)
				prior, _ = preparePrivateGeneratedReservation(t, env, closed, deletion, deletionCanonical)
				candidate := mustSelectedGeneratedWork(t, prior.reservation.state)
				retained := candidate.attempts[original.record.AttemptID]
				if retained.record.History != original.record.History || !bytes.Equal(retained.result, original.result) {
					t.Fatal("cleanup rewrote immutable actual create ancestry")
				}
				source, err := candidate.generatedDeleteSource(h.OwnerID)
				if err != nil || source.History.Count != original.record.History.Count+1 {
					t.Fatal("cleanup did not retain whole create/delete source history", err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedActualStrongerOwnedUnusableHazardRecordsOwnAck(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			f := newEnvironmentFixture(t, context.Background(), env, nil, false)
			profile := defaultGeneratedFixtureProfile()
			profile.CompletionClass = contract.GeneratedCompletionConfirmed
			closed, original := selectPrivateOwnedUnusableAggregateForProfile(t, env, f.session, []string{"omega"}, profile)
			closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
			work := mustSelectedGeneratedWork(t, closed)
			row := work.records[generatedRecordKey{11, original.expected.Template.HazardID}]
			source, err := contract.InspectGeneratedDeleteSource(row)
			if err != nil || source.Record.Kind != 11 || source.CompletionClass != contract.GeneratedCompletionConfirmed {
				t.Fatal("actual stronger Hazard source", err)
			}
			target, err := work.generatedCleanupTarget(11, source.SourceID, source.Target)
			if err != nil {
				t.Fatal(err)
			}
			input, inputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(234), row, target)
			prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
			recorded, _, expected, packet := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
			work = mustSelectedGeneratedWork(t, recorded)
			source, err = work.generatedDeleteSource(source.OwnerID)
			if err != nil {
				t.Fatal(err)
			}
			progress, err := work.controlledDeleteSourceProgress(source, nil, true)
			if err != nil || len(progress.rows) != 1 || progress.ack.record.AttemptID != expected.Template.AttemptID || !bytes.Equal(progress.ack.result, packet) || source.Hazard.OriginalAttemptID != original.record.AttemptID {
				t.Fatal("actual stronger Hazard lost own ACK or original anchor", err)
			}
			if _, invented := work.records[generatedRecordKey{10, source.OwnerID}]; invented {
				t.Fatal("stronger Hazard invented a prior Duty")
			}
			env.Custody.RetireGenerated()
			parked := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, expected.Template.AttemptID)
			parked = generatedLifecycleReopen(t, t.Context(), parked, env.Store)
			work = mustSelectedGeneratedWork(t, parked)
			parkedSource, err := work.generatedDeleteSource(source.OwnerID)
			if err != nil || parkedSource.Record.Kind != 11 || parkedSource.Hazard.OriginalAttemptID != original.record.AttemptID ||
				parkedSource.History != source.History || len(work.releases) != 0 || work.parent != nil || work.phase != nil ||
				parked.root.Generated.SuccessWindow != recorded.root.Generated.SuccessWindow || parked.root.Generated.FailureWindow != recorded.root.Generated.FailureWindow || parked.root.Generated.ReceiptOrder != recorded.root.Generated.ReceiptOrder {
				t.Fatal("stronger ordinary ACK parking lost exact source or created release/receipt", err)
			}
			f.session = parked
			actual := &generatedActualOperation{env: env, fixture: f}
			env = selectActualGeneratedLoss(t, actual, generatedActualLoss{name: "ordinary-cleanup-current-authority-kek", operation: 1, approval: contract.NormalSigningRole, mask: 2})
			parked = actual.fixture.session
			work = mustSelectedGeneratedWork(t, parked)
			parkedSource, err = work.generatedDeleteSource(source.OwnerID)
			if err != nil || !bytes.Equal(work.attempts[expected.Template.AttemptID].result, packet) {
				t.Fatal("current key replacement changed retained ordinary ACK", err)
			}
			input, inputCanonical = generatedDeletePlanInputForSource(t, parked, generatedVectorID(233), parkedSource.Record, target)
			deleteContract := input.graph.Lineages[0].Templates[0].ResultContractID
			scope := contract.GeneratorControlledRetirementScope(source.DescriptorID, source.ConfigContractID, deleteContract)
			input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, target.ResourceDigest, scope, expected.Template.ResultID, contract.Hash(packet))
			responder := custody.NewControlledRetirementResponder(source.ResourceID, target.ResourceDigest, scope)
			defer responder.Close()
			responder.DeleteExact(target.ResourceDigest)
			prior, _ = preparePrivateGeneratedReservation(t, env, parked, input, inputCanonical)
			probes := 0
			recorded, _, remaining, finalPacket := selectActualGeneratedPacketRecord(t, env, parked, prior, custody.StandardValue, true, func(ctx context.Context, command contract.GeneratedProducerCommand) []byte {
				probes++
				return responder.Probe(ctx, command)
			})
			if probes != 1 {
				t.Fatal("stronger ordinary remaining step did not use one qualified probe", probes)
			}
			env.Custody.RetireGenerated()
			finished := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, remaining.Template.AttemptID)
			finished = generatedLifecycleReopen(t, t.Context(), finished, env.Store)
			work = mustSelectedGeneratedWork(t, finished)
			if _, present := work.records[generatedRecordKey{11, source.SourceID}]; present || work.parent != nil || work.phase != nil || len(work.releases) != 3 ||
				finished.root.Generated.SuccessWindow != recorded.root.Generated.SuccessWindow || finished.root.Generated.FailureWindow != recorded.root.Generated.FailureWindow || finished.root.Generated.ReceiptOrder != recorded.root.Generated.ReceiptOrder {
				t.Fatal("qualified stronger ordinary completion lost receipt-free exact release closure", present, len(work.releases))
			}
			for id, body := range map[contract.ID][]byte{original.record.AttemptID: original.result, expected.Template.AttemptID: packet, remaining.Template.AttemptID: finalPacket} {
				mapping, ok := work.releases[id]
				if !ok || mapping.release.ObjectLength != uint32(len(body)) || mapping.release.SelectedHandoffDigest != contract.Hash(body) || mapping.release.OriginalResultID != mapping.attempt.ResultID ||
					mapping.release.InboxID != mapping.attempt.InboxID || mapping.release.State != contract.GeneratedReleasePending || mapping.release.HandoffRevisionID != finished.head.Core.Revision {
					t.Fatal("stronger ordinary completion changed exact observed release mapping", id, mapping.release)
				}
			}
			deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
			for _, id := range []contract.ID{remaining.Template.AttemptID, expected.Template.AttemptID, original.record.AttemptID} {
				finished = selectActualGeneratedInboxRelease(t, t.Context(), env, finished, deleteStore, id, false)
			}
			if work := mustSelectedGeneratedWork(t, finished); len(work.releases) != 0 || len(work.attempts) != 0 || len(work.materials) != 0 {
				t.Fatal("stronger ordinary full observed Release retained dead source custody")
			}
		})
	}
}

// full_only: false
func TestGeneratedActualFailedAggregateCleanupPreservesSiblings(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, class := range []uint8{contract.GeneratedCompletionAcknowledged, contract.GeneratedCompletionConfirmed} {
			t.Run(fmt.Sprintf("recovery=%t/class=%d", recovery, class), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, recovery)
				run := newScenarioRun(t, t.Context(), env)
				f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
				run.suppliedSelection(f, []ApplyEntryInput{
					{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
						Recipients: []contract.ID{f.session.admission.recipient}, InputBytes: []byte("preserved cleanup plain")},
					suppliedSecret(t, env, "secret", "preserved cleanup empty secret", custody.EmptyValue, f.session.admission.recipient),
				})
				wantNames := slices.Clone(f.session.root.Names)
				wantEntries := make(map[uint16][]byte, len(wantNames))
				wantAccess := make(map[contract.ID][]byte)
				for _, named := range wantNames {
					entry := f.session.valueEntry(named.Slot)
					body, err := contract.EncodeValueEntry(*entry)
					if err != nil {
						t.Fatal("cleanup predecessor entry", err)
					}
					wantEntries[named.Slot] = body
					if entry.ConfidentialityClass == contract.Secret {
						access, present := f.session.materialAccess(contract.ValueMaterialKind, entry.ValueState)
						if !present {
							t.Fatal("cleanup predecessor current access")
						}
						body, err := contract.EncodeAccessRecord(access)
						if err != nil {
							t.Fatal("cleanup predecessor access", err)
						}
						wantAccess[entry.ValueState] = body
					}
				}
				checkCurrent := func(selected *StateSession) {
					t.Helper()
					if !slices.Equal(selected.root.Names, wantNames) || selected.root.ValueEntryCount != uint32(len(wantNames)) {
						t.Fatal("cleanup changed the complete supplied current set")
					}
					for slot, want := range wantEntries {
						entry := selected.valueEntry(slot)
						if entry == nil {
							t.Fatal("cleanup removed a supplied current entry", slot)
						}
						body, err := contract.EncodeValueEntry(*entry)
						if err != nil || !bytes.Equal(body, want) {
							t.Fatal("cleanup changed an exact supplied current entry", slot, err)
						}
					}
					for material, want := range wantAccess {
						access, present := selected.materialAccess(contract.ValueMaterialKind, material)
						body, err := contract.EncodeAccessRecord(access)
						if !present || err != nil || !bytes.Equal(body, want) {
							t.Fatal("cleanup changed exact supplied current access", err)
						}
					}
				}
				sources, canonical := generatedCurrentDeclaration(t, f.session)
				profile := defaultGeneratedFixtureProfile()
				profile.CompletionClass = class
				names := []string{"alpha", "omega"}
				input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(230), names, profile, sources...)
				closed, failed := selectPrivateOwnedUnusableAggregateFromInput(t, env, f.session, names, input, canonical)
				closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
				checkCurrent(closed)
				work := mustSelectedGeneratedWork(t, closed)
				selection, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
				if err != nil || !ok || selection.kind != generatedCleanupDuty {
					t.Fatal("failed aggregate lost actual succeeded cleanup Duty", err)
				}
				dutyID := selection.duty.DutyID
				hazardID := failed.expected.Template.HazardID
				hazardBody := bytes.Clone(work.records[generatedRecordKey{11, hazardID}].Body)
				material := failed.material.Core.OperationMaterialID
				deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
				for index, key := range []generatedRecordKey{{10, dutyID}, {11, hazardID}} {
					work = mustSelectedGeneratedWork(t, closed)
					source, err := contract.InspectGeneratedDeleteSource(work.records[key])
					target, targetErr := work.generatedCleanupTarget(key.kind, key.id, source.Target)
					original := work.attempts[source.OriginalAttemptID]
					if err != nil || targetErr != nil || original.record.AttemptID.IsZero() {
						t.Fatal("actual source or immutable original lost", err, targetErr)
					}
					input, inputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(byte(210+index*2)), source.Record, target)
					graph, err := work.retainedGraph(target.OriginalOperationID)
					var recordedContract contract.ID
					for _, lineage := range graph.Lineages {
						for _, x := range lineage.Templates[:lineage.TemplateCount] {
							if lineage.Purpose == 3 && x.DutyID == source.OwnerID && x.ResourceIncarnationID == source.ResourceID {
								recordedContract = x.ResultContractID
							}
						}
					}
					if err != nil || recordedContract.IsZero() || input.graph.Lineages[0].Templates[0].ResultContractID != recordedContract {
						t.Fatal("ordinary cleanup changed the recorded delete contract", err)
					}
					prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
					recorded, _, expected, packet := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
					env.Custody.RetireGenerated()
					closed = selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, expected.Template.AttemptID)
					closed = generatedLifecycleReopen(t, t.Context(), closed, deleteStore)
					ids := []contract.ID{expected.Template.AttemptID, original.record.AttemptID}
					bodies := map[contract.ID][]byte{expected.Template.AttemptID: packet, original.record.AttemptID: original.result}
					if class == contract.GeneratedCompletionConfirmed {
						parked := mustSelectedGeneratedWork(t, closed)
						actualSource, err := parked.generatedDeleteSource(source.OwnerID)
						if err != nil || len(parked.releases) != 0 || actualSource.Record.Kind != key.kind || actualSource.SourceID != key.id {
							t.Fatal("ordinary own ACK did not park actual source without Release", err)
						}
						input, inputCanonical = generatedDeletePlanInputForSource(t, closed, generatedVectorID(byte(211+index*2)), actualSource.Record, target)
						scope := contract.GeneratorControlledRetirementScope(source.DescriptorID, source.ConfigContractID, recordedContract)
						input.requestBindings[0].Digest = contract.GeneratorControlledRetirementProbeDigest(source.DomainID, source.ResourceID, target.ResourceDigest, scope, expected.Template.ResultID, contract.Hash(packet))
						responder := custody.NewControlledRetirementResponder(source.ResourceID, target.ResourceDigest, scope)
						defer responder.Close()
						responder.DeleteExact(target.ResourceDigest)
						prior, _ = preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
						recorded, _, remaining, finalPacket := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, responder.Probe)
						env.Custody.RetireGenerated()
						closed = selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, remaining.Template.AttemptID)
						closed = generatedLifecycleReopen(t, t.Context(), closed, deleteStore)
						ids = append([]contract.ID{remaining.Template.AttemptID}, ids...)
						bodies[remaining.Template.AttemptID] = finalPacket
					}
					for _, id := range ids {
						mapping := mustSelectedGeneratedWork(t, closed).releases[id]
						if mapping.release.State != contract.GeneratedReleasePending || mapping.release.ObjectLength != uint32(len(bodies[id])) || mapping.release.SelectedHandoffDigest != contract.Hash(bodies[id]) {
							t.Fatal("sibling-safe ordinary close changed exact release body mapping")
						}
						closed = selectActualGeneratedInboxRelease(t, t.Context(), env, closed, deleteStore, id, false)
					}
					checkCurrent(closed)
					if index == 0 {
						after := mustSelectedGeneratedWork(t, closed)
						if !bytes.Equal(after.records[generatedRecordKey{11, hazardID}].Body, hazardBody) || !bytes.Equal(after.attempts[failed.record.AttemptID].result, failed.result) ||
							after.attempts[failed.record.AttemptID].record != failed.record || !after.materials[materialIdentity{3, material}] {
							t.Fatal("closing succeeded sibling changed failed original, Hazard or shared material")
						}
						if _, current := closed.materialAccess(3, material); !current {
							t.Fatal("closing succeeded sibling removed current shared Seed Access")
						}
					}
				}
				remaining := mustSelectedGeneratedWork(t, closed)
				if len(remaining.attempts) != 0 || len(remaining.releases) != 0 || len(remaining.materials) != len(wantAccess) {
					t.Fatalf("full failed aggregate cleanup changed retained material closure: attempts=%d releases=%d materials=%d want-current=%d",
						len(remaining.attempts), len(remaining.releases), len(remaining.materials), len(wantAccess))
				}
				for material := range wantAccess {
					if !remaining.materials[materialIdentity{contract.ValueMaterialKind, material}] {
						t.Fatal("full failed aggregate cleanup lost current supplied material")
					}
				}
			})
		}
	}
}

func selectOrdinaryGeneratedCleanupClose(t testing.TB, ctx context.Context, env fixtureEnvironment, s *StateSession, attempt contract.ID) *StateSession {
	t.Helper()
	permit, err := s.admitGeneratedOrdinaryCleanupClose(ctx, attempt, generatedPlanInputFixture(t, s).context)
	if err != nil {
		t.Fatal("ordinary cleanup close admission", err)
	}
	candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary cleanup close preparation", result)
	}
	selected, result := s.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary cleanup close selection", result)
	}
	checkGeneratedReceiptRowsUnchanged(t, s, selected)
	return selected
}

func checkGeneratedReceiptRowsUnchanged(t testing.TB, before, after *StateSession) {
	t.Helper()
	if before.root.Generated.SuccessWindow != after.root.Generated.SuccessWindow || before.root.Generated.FailureWindow != after.root.Generated.FailureWindow || before.root.Generated.ReceiptOrder != after.root.Generated.ReceiptOrder {
		t.Fatal("ordinary cleanup changed receipt windows")
	}
	rows := func(s *StateSession) []contract.SupportRecord {
		var receipts []contract.SupportRecord
		for _, row := range s.supportRecords() {
			if row.Kind == 7 {
				receipts = append(receipts, row)
			}
		}
		return receipts
	}
	if !reflect.DeepEqual(rows(before), rows(after)) {
		t.Fatal("ordinary cleanup changed complete prior receipt IDs or bodies")
	}
}

func actualGeneratedReceipt(t *testing.T, s *StateSession, operation contract.ID, outcome uint8) []byte {
	t.Helper()
	body, result := s.MutationReceipt(context.Background(), operation)
	receipt, err := contract.InspectCompactMutationReceipt(body)
	if result.Outcome != ObservedCurrent || err != nil || receipt.OperationID != operation || receipt.CanonicalOutcome != outcome {
		t.Fatal("actual generated receipt", result, err, receipt.OperationID == operation, receipt.CanonicalOutcome)
	}
	return bytes.Clone(body)
}

func assertActualGeneratedReceipts(t *testing.T, s *StateSession, operations []contract.ID, bodies [][]byte) {
	t.Helper()
	if len(operations) != len(bodies) {
		t.Fatal("actual receipt expectation shape")
	}
	for i, operation := range operations {
		body, result := s.MutationReceipt(context.Background(), operation)
		if result.Outcome != ObservedCurrent || !bytes.Equal(body, bodies[i]) {
			t.Fatal("actual retained receipt replay", i, result)
		}
	}
}

func assertGeneratedWorkRowsRemain(t *testing.T, s *StateSession, want []contract.SupportRecord) {
	t.Helper()
	actual, err := s.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal("actual retained work", err)
	}
	rows := make(map[generatedRecordKey][]byte, len(actual))
	for _, row := range actual {
		rows[generatedRecordKey{kind: row.Kind, id: row.RecordID}] = row.Body
	}
	for _, row := range want {
		// Carriers may be repacked when another owner is added. Their owner
		// descriptors remain fixed in the exact Duty/Hazard rows checked here.
		if row.Kind == contract.GeneratorVectorSupportKind {
			continue
		}
		if !bytes.Equal(rows[generatedRecordKey{kind: row.Kind, id: row.RecordID}], row.Body) {
			t.Fatal("receipt eviction changed live generated work", row.Kind, row.RecordID)
		}
	}
}

func selectActualTerminalFailureReceipt(t *testing.T, operationCtx context.Context, env fixtureEnvironment, s *StateSession, operation contract.ID, label string, lostFinal bool, sources ...contract.GeneratorDeclarationEntry) (*StateSession, generatedAttempt) {
	t.Helper()
	input := generatedPlanInputForGenerations(t, s, operation, []string{"receipt-failure"}, defaultGeneratedFixtureProfile(), sources...)
	input.context.AdmissionID = fixtureID(s.root.Domain, label+" reservation admission")
	input.context.SessionID = fixtureID(s.root.Domain, label+" reservation session")
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
	recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.GeneratedTerminalFailure, true, nil)
	work := mustSelectedGeneratedWork(t, recorded)
	original := work.attempts[expected.Template.AttemptID]
	finalContext := generatedPlanInputFixture(t, recorded).context
	finalContext.AdmissionID = fixtureID(s.root.Domain, label+" final admission")
	finalContext.SessionID = fixtureID(s.root.Domain, label+" final session")
	plan, err := recorded.generatedFinalRequest(t.Context(), finalContext)
	if err != nil || plan.selecting || len(plan.results) != 1 {
		t.Fatal("actual failure Final request", err)
	}
	recorded, prepared := preparePrivateGeneratedFinal(t, env, recorded, plan)
	store, memory := recorded.store, env.Store.(*memoryStore)
	cas := memory.cas
	if lostFinal {
		memory.casMode = "lost-after"
	}
	closed, result := recorded.selectCandidate(context.Background(), prepared.reservation.candidate)
	memory.casMode = ""
	if closed == nil || result.Outcome != ObservedCurrent || memory.cas != cas+1 || !closed.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("actual failure Final selection", result, memory.cas-cas)
	}
	env.Custody.RetireGenerated()
	if lostFinal {
		closed = generatedLifecycleReopen(t, operationCtx, closed, store)
	}
	return closed, original
}

func closeAndReleaseActualCleanup(t *testing.T, env fixtureEnvironment, s *StateSession, store *generatedCleanupDeleteStore,
	original generatedAttempt, ownerKind uint8, ownerID contract.ID, index int) *StateSession {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	row, present := work.records[generatedRecordKey{kind: ownerKind, id: ownerID}]
	source, err := contract.InspectGeneratedDeleteSource(row)
	target, targetErr := work.generatedCleanupTarget(ownerKind, ownerID, source.Target)
	if !present || err != nil || targetErr != nil || source.OriginalAttemptID != original.record.AttemptID {
		t.Fatal("actual cleanup source", index, err, targetErr)
	}
	operation := fixtureID(s.root.Domain, fmt.Sprintf("actual receipt cleanup %03d", index))
	input, inputCanonical := generatedDeletePlanInputForSource(t, s, operation, row, target)
	inputs := captureGeneratedScenarioInputs(t, input, target.ResourceDigest)
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	recorded, _, cleanup, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, nil)
	observedTarget, present, err := observeGeneratedDeleteTarget(recorded, inputs.expected.Template.AttemptID)
	if err != nil || !present || observedTarget != target || cleanup != inputs.expected {
		t.Fatal("actual cleanup changed its original target or attempt", err)
	}
	closed := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, cleanup.Template.AttemptID)
	closed = selectActualGeneratedInboxRelease(t, t.Context(), env, closed, store, cleanup.Template.AttemptID, false)
	closed = selectActualGeneratedInboxRelease(t, t.Context(), env, closed, store, original.record.AttemptID, false)
	if attempt, err := observeGeneratedAttempt(t.Context(), closed, inputs.expected.Template.AttemptID); err != nil || attempt.present {
		t.Fatal("released cleanup retained its original live attempt", err)
	}
	return closed
}

func closeAndReleaseActualFailure(t *testing.T, env fixtureEnvironment, s *StateSession, store *generatedCleanupDeleteStore, original generatedAttempt, index int) *StateSession {
	t.Helper()
	return closeAndReleaseActualCleanup(t, env, s, store, original, 11, original.expected.Template.HazardID, index)
}

func selectActualRetirementReceipt(t *testing.T, env fixtureEnvironment, s *StateSession, operation contract.ID, label string) (*StateSession, contract.ID) {
	t.Helper()
	_, entry := lifecycleEntry(t, s, "receipt-rotating")
	work := mustSelectedGeneratedWork(t, s)
	dutyRow, present := work.records[generatedRecordKey{kind: 10, id: entry.Generated.RetiringDutyID}]
	duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
	target, targetErr := work.retirementTarget(t.Context(), duty)
	if !present || err != nil || targetErr != nil || duty.Kind != contract.GeneratedDutyRetirement {
		t.Fatal("actual receipt retirement source", err, targetErr)
	}
	input, inputCanonical := generatedDeletePlanInput(t, s, operation, duty, target, 2)
	input.context.AdmissionID = fixtureID(s.root.Domain, label+" reservation admission")
	input.context.SessionID = fixtureID(s.root.Domain, label+" reservation session")
	prior, _ := preparePrivateGeneratedReservation(t, env, s, input, inputCanonical)
	recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, s, prior, custody.StandardValue, true, nil)
	admitted := generatedPlanInputFixture(t, recorded).context
	admitted.AdmissionID = fixtureID(s.root.Domain, label+" close admission")
	admitted.SessionID = fixtureID(s.root.Domain, label+" close session")
	permit, err := recorded.admitGeneratedRetirementClose(context.Background(), expected.Template.AttemptID, admitted)
	if err != nil {
		t.Fatal("actual receipt retirement close admission", err)
	}
	candidate, result := recorded.PrepareGeneratedLifecycle(context.Background(), permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual receipt retirement close preparation", result)
	}
	closed, result := recorded.selectCandidate(context.Background(), candidate)
	if closed == nil || result.Outcome != ObservedCurrent || closed.root.Generated.Retiring != 0 {
		t.Fatal("actual receipt retirement close selection", result)
	}
	env.Custody.RetireGenerated()
	return closed, expected.Template.AttemptID
}

func releaseAllActualGeneratedInboxes(t *testing.T, env fixtureEnvironment, s *StateSession, store *generatedCleanupDeleteStore) *StateSession {
	t.Helper()
	for {
		work := mustSelectedGeneratedWork(t, s)
		var attempts []contract.ID
		for attempt, release := range work.releases {
			if release.release.State == contract.GeneratedReleasePending {
				attempts = append(attempts, attempt)
			}
		}
		if len(attempts) == 0 {
			return s
		}
		slices.SortFunc(attempts, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		s = selectActualGeneratedInboxRelease(t, t.Context(), env, s, store, attempts[0], false)
	}
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
func TestGeneratedTerminalReceiptWindowsReplayAndEvictIndependentlyWithoutReleasingWork(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, false)
		f := newEnvironmentFixture(t, context.Background(), env, nil, false)
		deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
		s := f.session
		operations := make([]contract.ID, 0, contract.MutationReceiptWindowLimit+1)
		bodies := make([][]byte, 0, contract.MutationReceiptWindowLimit+1)

		operation := fixtureID(env.Domain, "actual success receipt 000")
		input := generatedPlanInputForGenerations(t, s, operation, []string{"receipt-rotating"}, defaultGeneratedFixtureProfile())
		input.context.AdmissionID = fixtureID(env.Domain, "actual success receipt 000 admission")
		input.context.SessionID = fixtureID(env.Domain, "actual success receipt 000 session")
		s = selectPrivateGeneratedOperationInProcess(t, env, s, input, "actual success receipt 000")
		operations = append(operations, operation)
		bodies = append(bodies, actualGeneratedReceipt(t, s, operation, 1))

		for len(operations) < contract.MutationReceiptWindowLimit-1 {
			index := len(operations)
			label := fmt.Sprintf("actual success rotation %03d", index)
			operation = fixtureID(env.Domain, label)
			_, old := lifecycleEntry(t, s, "receipt-rotating")
			input = generatedStatePlanInput(t, s, operation, []string{old.Name}, defaultGeneratedFixtureProfile(), old.Generated.Epoch+1,
				map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old})
			s = selectPrivateGeneratedOperationInProcess(t, env, s, input, label)
			operations = append(operations, operation)
			bodies = append(bodies, actualGeneratedReceipt(t, s, operation, 1))
			s = releaseAllActualGeneratedInboxes(t, env, s, deleteStore)

			label = fmt.Sprintf("actual success retirement %03d", len(operations))
			operation = fixtureID(env.Domain, label)
			var retirementAttempt contract.ID
			s, retirementAttempt = selectActualRetirementReceipt(t, env, s, operation, label)
			operations = append(operations, operation)
			bodies = append(bodies, actualGeneratedReceipt(t, s, operation, 1))
			s = selectActualGeneratedInboxRelease(t, t.Context(), env, s, deleteStore, retirementAttempt, false)
		}
		label := "actual success rotation 255"
		operation = fixtureID(env.Domain, label)
		_, old := lifecycleEntry(t, s, "receipt-rotating")
		input = generatedStatePlanInput(t, s, operation, []string{old.Name}, defaultGeneratedFixtureProfile(), old.Generated.Epoch+1,
			map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: *old})
		s = selectPrivateGeneratedOperationInProcess(t, env, s, input, label)
		operations = append(operations, operation)
		bodies = append(bodies, actualGeneratedReceipt(t, s, operation, 1))
		s = releaseAllActualGeneratedInboxes(t, env, s, deleteStore)
		s = generatedLifecycleReopen(t, t.Context(), s, deleteStore)
		checkFreshGeneratedProcess(t, deleteStore.memoryStore, s)
		window, err := s.receiptWindows(t.Context())
		if err != nil || len(window.Successes) != contract.MutationReceiptWindowLimit || len(window.Failures) != 0 {
			t.Fatal("actual success receipt full window", err, len(window.Successes), len(window.Failures))
		}
		assertActualGeneratedReceipts(t, s, operations, bodies)
		_, current := lifecycleEntry(t, s, "receipt-rotating")
		dutyID := current.Generated.RetiringDutyID
		work := mustSelectedGeneratedWork(t, s)
		dutyRow, present := work.records[generatedRecordKey{kind: 10, id: dutyID}]
		duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
		retirementTarget, targetErr := work.retirementTarget(t.Context(), duty)
		if !present || err != nil || targetErr != nil || duty.Kind != contract.GeneratedDutyRetirement || retirementTarget.Name != current.Name {
			t.Fatal("actual success receipt live Duty", err, targetErr)
		}

		label = "actual success retirement 256"
		operation = fixtureID(env.Domain, label)
		var retirementAttempt contract.ID
		s, retirementAttempt = selectActualRetirementReceipt(t, env, s, operation, label)
		operations = append(operations, operation)
		bodies = append(bodies, actualGeneratedReceipt(t, s, operation, 1))
		work = mustSelectedGeneratedWork(t, s)
		liveRelease, present := work.releases[retirementAttempt]
		if !present || liveRelease.release.State != contract.GeneratedReleasePending {
			t.Fatal("257th actual success lost its live result release")
		}
		liveRows := make([]contract.SupportRecord, 0, 2)
		for _, key := range []generatedRecordKey{{kind: 9, id: retirementAttempt}, {kind: 12, id: liveRelease.release.InboxID}} {
			row, present := work.records[key]
			if !present {
				t.Fatal("257th actual success missing live result owner", key.kind)
			}
			liveRows = append(liveRows, row)
		}
		liveResultKey, err := format.GeneratedResultKey(s.admission.store.Prefix, s.root.Domain, liveRelease.release.InboxID)
		liveResult := deleteStore.objects[liveResultKey]
		if err != nil || len(liveResult.Body) == 0 || contract.Hash(liveResult.Body) != liveRelease.release.SelectedHandoffDigest {
			t.Fatal("257th actual success missing live result object", err)
		}
		liveResultBody, liveResultToken := bytes.Clone(liveResult.Body), liveResult.Token
		s = generatedLifecycleReopen(t, t.Context(), s, deleteStore)
		if body, result := s.MutationReceipt(context.Background(), operations[0]); body != nil || result != refused(AdmissionInvalid) {
			t.Fatal("evicted actual success receipt replayed", result)
		}
		assertActualGeneratedReceipts(t, s, operations[1:], bodies[1:])
		assertGeneratedWorkRowsRemain(t, s, liveRows)
		work = mustSelectedGeneratedWork(t, s)
		if release, present := work.releases[retirementAttempt]; !present || !reflect.DeepEqual(release, liveRelease) {
			t.Fatal("success receipt eviction changed the live result owner")
		}
		liveResult = deleteStore.objects[liveResultKey]
		if liveResult.Token != liveResultToken || !bytes.Equal(liveResult.Body, liveResultBody) {
			t.Fatal("success receipt eviction released or changed a live original result")
		}
		_, after := lifecycleEntry(t, s, "receipt-rotating")
		if s.root.Generated.Retiring != 0 || after.Generated.RetiringDutyPresent != 0 || !after.Generated.RetiringDutyID.IsZero() {
			t.Fatal("257th actual success did not close its exact Duty")
		}
		selectActualGeneratedInboxRelease(t, t.Context(), env, s, deleteStore, retirementAttempt, false)
	})

	t.Run("failure", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, false)
		f := newEnvironmentFixture(t, context.Background(), env, nil, false)
		deleteStore := &generatedCleanupDeleteStore{memoryStore: env.Store.(*memoryStore)}
		operations := make([]contract.ID, 0, contract.MutationReceiptWindowLimit+1)
		bodies := make([][]byte, 0, contract.MutationReceiptWindowLimit+1)
		s := generatedLifecycleReopen(t, t.Context(), f.session, deleteStore)
		initial, err := s.receiptWindows(t.Context())
		if err != nil || initial.DomainID != env.Domain || len(initial.Successes) != 1 ||
			initial.Successes[0].OperationKind != contract.OperationInitializeDomain || len(initial.Failures) != 0 ||
			!slices.Equal(initial.Order, []contract.ID{initial.Successes[0].OperationID}) {
			t.Fatal("failure receipt fixture lacks its exact initialization history", err)
		}
		initial.Successes, initial.Order = slices.Clone(initial.Successes), slices.Clone(initial.Order)
		initialBodies := [][]byte{actualGeneratedReceipt(t, s, initial.Order[0], contract.ReceiptCanonicalSelected)}
		checkWindow := func(current *StateSession, failures []contract.ID) {
			t.Helper()
			window, err := current.receiptWindows(t.Context())
			order := append(slices.Clone(initial.Order), failures...)
			if err != nil || window.DomainID != initial.DomainID || !slices.Equal(window.Successes, initial.Successes) ||
				len(window.Failures) != len(failures) || !slices.Equal(window.Order, order) {
				t.Fatal("actual failure receipt window changed initialization or failure order", err)
			}
			assertActualGeneratedReceipts(t, current, initial.Order, initialBodies)
		}
		configuration := s.root.OutputConfiguration
		configurationFacts, err := s.selectedOutputFactsByRecord()
		if err != nil || configuration.SliceCount != 1 || len(configurationFacts) != 1 {
			t.Fatal("failure receipt fixture lacks its exact empty configuration", err)
		}
		type scheduledFailure struct {
			label     string
			operation contract.ID
		}
		schedule := make([]scheduledFailure, contract.MutationReceiptWindowLimit+1)
		for i := range schedule {
			schedule[i].label = fmt.Sprintf("actual failure receipt %03d", i)
			schedule[i].operation = fixtureID(env.Domain, schedule[i].label)
		}
		slices.SortFunc(schedule, func(a, b scheduledFailure) int { return bytes.Compare(a.operation[:], b.operation[:]) })
		preservedFailure := schedule[len(schedule)-1]
		schedule = schedule[:len(schedule)-1]
		var preserved generatedAttempt
		var preservedRows []contract.SupportRecord
		var preservedAccess []byte
		var preservedResultKey string
		var preservedResultBody []byte
		var preservedResultToken contract.Token
		for i := 0; i < contract.MutationReceiptWindowLimit; i++ {
			failure := preservedFailure
			if i != 0 {
				failure = schedule[i-1]
			}
			var failed generatedAttempt
			s, failed = selectActualTerminalFailureReceipt(t, t.Context(), env, s, failure.operation, failure.label, false)
			operations = append(operations, failure.operation)
			bodies = append(bodies, actualGeneratedReceipt(t, s, failure.operation, 2))
			if i == 0 {
				preserved = failed
				var workErr error
				preservedRows, workErr = s.preservedWorkSupportRecords(t.Context())
				access, present := s.materialAccess(3, failed.material.Core.OperationMaterialID)
				var accessErr error
				preservedAccess, accessErr = contract.EncodeAccessRecord(access)
				var keyErr error
				preservedResultKey, keyErr = format.GeneratedResultKey(s.admission.store.Prefix, s.root.Domain, failed.record.InboxID)
				object := deleteStore.objects[preservedResultKey]
				if workErr != nil || !present || accessErr != nil || keyErr != nil || len(preservedRows) == 0 || len(object.Body) == 0 || !bytes.Equal(object.Body, failed.result) {
					t.Fatal("first actual failure did not retain exact live work", workErr, accessErr, keyErr)
				}
				preservedResultBody, preservedResultToken = bytes.Clone(object.Body), object.Token
				continue
			}
			s = closeAndReleaseActualFailure(t, env, s, deleteStore, failed, i)
			assertGeneratedWorkRowsRemain(t, s, preservedRows)
			access, present := s.materialAccess(3, preserved.material.Core.OperationMaterialID)
			accessBody, err := contract.EncodeAccessRecord(access)
			object := deleteStore.objects[preservedResultKey]
			if !present || err != nil || !bytes.Equal(accessBody, preservedAccess) || object.Token != preservedResultToken || !bytes.Equal(object.Body, preservedResultBody) {
				t.Fatal("later failure cleanup changed the first live failure", i, err)
			}
		}
		s = generatedLifecycleReopen(t, t.Context(), s, deleteStore)
		checkWindow(s, operations)
		assertActualGeneratedReceipts(t, s, operations, bodies)

		failure := schedule[len(schedule)-1]
		var last generatedAttempt
		s, last = selectActualTerminalFailureReceipt(t, t.Context(), env, s, failure.operation, failure.label, true)
		operations = append(operations, failure.operation)
		bodies = append(bodies, actualGeneratedReceipt(t, s, failure.operation, 2))
		if body, result := s.MutationReceipt(context.Background(), operations[0]); body != nil || result != refused(AdmissionInvalid) {
			t.Fatal("evicted actual failure receipt replayed", result)
		}
		checkWindow(s, operations[1:])
		assertActualGeneratedReceipts(t, s, operations[1:], bodies[1:])
		work := mustSelectedGeneratedWork(t, s)
		assertGeneratedWorkRowsRemain(t, s, preservedRows)
		preservedHazard, hazardPresent := work.records[generatedRecordKey{kind: 11, id: preserved.expected.Template.HazardID}]
		access, present := s.materialAccess(3, preserved.material.Core.OperationMaterialID)
		accessBody, accessErr := contract.EncodeAccessRecord(access)
		preservedResult := deleteStore.objects[preservedResultKey]
		if !hazardPresent || preservedHazard.RecordID != preserved.expected.Template.HazardID || !present || accessErr != nil ||
			!bytes.Equal(accessBody, preservedAccess) || preservedResult.Token != preservedResultToken || !bytes.Equal(preservedResult.Body, preservedResultBody) {
			t.Fatal("failure receipt eviction changed its own live Hazard, reader or result", accessErr)
		}
		hazardRow := work.records[generatedRecordKey{kind: 11, id: last.expected.Template.HazardID}]
		hazard, err := contract.InspectGeneratedHazardRecord(hazardRow.Body)
		currentSeed, present := s.materialAccess(3, last.material.Core.OperationMaterialID)
		currentSeedBody, accessErr := contract.EncodeAccessRecord(currentSeed)
		resultKey, keyErr := format.GeneratedResultKey(s.admission.store.Prefix, s.root.Domain, last.record.InboxID)
		resultObject := deleteStore.objects[resultKey]
		if err != nil || !present || accessErr != nil || keyErr != nil || hazard.OriginalAttemptID != last.record.AttemptID ||
			len(currentSeedBody) == 0 || !bytes.Equal(resultObject.Body, last.result) {
			t.Fatal("257th actual failure lost Hazard, ordered progress, reader or original result", err, accessErr, keyErr)
		}

		s = closeAndReleaseActualFailure(t, env, s, deleteStore, last, contract.MutationReceiptWindowLimit)
		assertGeneratedWorkRowsRemain(t, s, preservedRows)
		s = closeAndReleaseActualFailure(t, env, s, deleteStore, preserved, 0)
		finalWork, err := s.preservedWorkSupportRecords(t.Context())
		finalConfiguration, configurationErr := s.selectedOutputFactsByRecord()
		if err != nil || configurationErr != nil || s.root.OutputConfiguration != configuration ||
			len(finalConfiguration) != len(configurationFacts) || len(finalWork) != len(configurationFacts) {
			t.Fatal("safe observed release changed mandatory configuration or retained dead work", err, configurationErr, len(finalWork))
		}
		for id, before := range configurationFacts {
			if after, present := finalConfiguration[id]; !present || after.row != before.row {
				t.Fatal("safe observed release changed an exact configuration slice", id)
			}
		}
		for _, row := range finalWork {
			if _, present := configurationFacts[row.RecordID]; row.Kind != contract.OutputConfigurationSliceSupportKind || !present {
				t.Fatal("safe observed release retained non-configuration work", row.Kind)
			}
		}
	})
}

// This local store performs the actual conditional object deletion. A lost
// reply changes only the returned observation, not the physical delete effect.
type generatedCleanupDeleteStore struct {
	contract.Store
	*memoryStore
	lost        bool
	deleteKey   string
	deleteToken contract.Token
	deletes     int
}

func (s *generatedCleanupDeleteStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.storage())
}

func (s *generatedCleanupDeleteStore) storage() contract.Store {
	if s.Store != nil {
		return s.Store
	}
	return s.memoryStore
}

func (s *generatedCleanupDeleteStore) Descriptor() contract.Descriptor {
	return s.storage().Descriptor()
}

func (s *generatedCleanupDeleteStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	return s.storage().Read(ctx, key, limit)
}

func (s *generatedCleanupDeleteStore) Create(ctx context.Context, key string, body []byte) contract.WriteResult {
	return s.storage().Create(ctx, key, body)
}

func (s *generatedCleanupDeleteStore) CreateHead(ctx context.Context, request contract.HeadCreateRequest) contract.WriteResult {
	return s.storage().CreateHead(ctx, request)
}

func (s *generatedCleanupDeleteStore) CompareAndSwap(ctx context.Context, key string, token contract.Token, body []byte) contract.WriteResult {
	return s.storage().CompareAndSwap(ctx, key, token, body)
}

func (s *generatedCleanupDeleteStore) DeleteIfToken(_ context.Context, key string, token contract.Token) contract.WriteResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	s.deleteKey, s.deleteToken = key, token
	object, present := s.objects[key]
	if !present || object.Token != token {
		return contract.WriteResult{Status: contract.WriteConflict}
	}
	delete(s.objects, key)
	if s.lost {
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	return contract.WriteResult{Status: contract.WriteAcknowledged}
}

func selectActualGeneratedInboxRelease(t testing.TB, operationCtx context.Context, env fixtureEnvironment, s *StateSession, store *generatedCleanupDeleteStore, attempt contract.ID, lost bool) *StateSession {
	t.Helper()
	s = generatedLifecycleReopen(t, operationCtx, s, store)
	mapping, present := mustSelectedGeneratedWork(t, s).releases[attempt]
	if !present || mapping.release.State != contract.GeneratedReleasePending {
		t.Fatal("actual Release has no exact Pending source mapping")
	}
	key, err := format.GeneratedResultKey(store.desc.Prefix, s.root.Domain, mapping.release.InboxID)
	if err != nil {
		t.Fatal("actual Release source coordinate", err)
	}
	object, present := store.objects[key]
	if !present {
		t.Fatal("actual Release source object is missing")
	}
	read := readFixtureStoredBody(object, mapping.release.ObjectLength)
	if read.Status != contract.ReadOK {
		t.Fatal("actual Release source body is unreadable", read.Status, read.Reason)
	}
	if uint32(len(read.Body)) != mapping.release.ObjectLength || contract.Hash(read.Body) != mapping.release.SelectedHandoffDigest {
		t.Fatal("actual Release source body does not match recorded mapping")
	}
	store.lost = lost
	deletes := store.deletes
	ctx := env.operationContext()
	permit, err := s.admitGeneratedInboxRelease(ctx, mapping.release.InboxID, generatedPlanInputFixture(t, s).context)
	if err != nil || store.deletes != deletes+1 || store.deleteKey != key || store.deleteToken != object.Token {
		t.Fatalf("actual Release did not condition exact coordinate/token: error=%v deletes=%d/%d key=%q/%q token=%+v/%+v", err, store.deletes, deletes+1, store.deleteKey, key, store.deleteToken, object.Token)
	}
	if _, present := store.objects[key]; present {
		t.Fatal("actual conditional inbox delete did not remove its exact object")
	}
	candidate, result := s.PrepareGeneratedLifecycle(ctx, permit, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual Release preparation", result)
	}
	selected, result := s.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual Release selection", result)
	}
	selected = generatedLifecycleReopen(t, operationCtx, selected, store)
	checkGeneratedReceiptRowsUnchanged(t, s, selected)
	_, retained := mustSelectedGeneratedWork(t, selected).releases[attempt]
	if retained != lost {
		t.Fatal("actual Release selected wrong lost/observed mapping outcome", retained, lost)
	}
	return selected
}

// full_only: false
func TestGeneratedActualInboxReleasePreservesExactMappingAcrossBodyStorage(t *testing.T) {
	for _, mode := range []string{"memory", "file"} {
		for _, lost := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/lost=%t", mode, lost), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, true)
				store := env.Store.(*memoryStore)
				if mode == "file" {
					if err := store.useFileBodies(filepath.Join(t.TempDir(), "bodies")); err != nil {
						t.Fatal(err)
					}
				}
				f := newEnvironmentFixture(t, t.Context(), env, nil, false)
				closed := selectPrivateFailedGeneratedAggregate(t, env, f.session)
				work := mustSelectedGeneratedWork(t, closed)
				cleanup, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
				if err != nil || !ok || cleanup.kind != generatedCleanupDuty {
					t.Fatal("exact release cleanup source", err)
				}
				input, inputCanonical := generatedDeletePlanInput(t, closed, generatedVectorID(231), cleanup.duty, cleanup.target, 3)
				prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
				recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
				env.Custody.RetireGenerated()
				cleaned := selectOrdinaryGeneratedCleanupClose(t, t.Context(), env, recorded, expected.Template.AttemptID)
				original := cleanup.attempt.record.AttemptID
				mapping := mustSelectedGeneratedWork(t, cleaned).releases[original].release
				if mapping.State != contract.GeneratedReleasePending || mapping.ObjectLength != uint32(len(cleanup.attempt.result)) ||
					mapping.SelectedHandoffDigest != contract.Hash(cleanup.attempt.result) {
					t.Fatal("exact release starting mapping changed")
				}
				deleteStore := &generatedCleanupDeleteStore{memoryStore: store}
				cleaned = selectActualGeneratedInboxRelease(t, t.Context(), env, cleaned, deleteStore, expected.Template.AttemptID, false)
				cleaned = selectActualGeneratedInboxRelease(t, t.Context(), env, cleaned, deleteStore, original, lost)
				after := mustSelectedGeneratedWork(t, cleaned)
				if _, present := after.releases[expected.Template.AttemptID]; present || (lost && len(after.releases) != 1) || (!lost && len(after.releases) != 0) {
					t.Fatal("exact release retained an acknowledged inbox")
				}
				if lost {
					mapping.State = contract.GeneratedReleaseUnknown
					if after.releases[original].release != mapping {
						t.Fatal("lost exact release changed mapping beyond its observation state")
					}
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedFreshCleanupReservationClaimsAndSendsOnce(t *testing.T) {
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	selected := selectPrivateFailedGeneratedAggregate(t, env, f.session)
	work, err := selected.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cleanup, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
	if err != nil || !ok || cleanup.kind != generatedCleanupDuty {
		t.Fatal("select detached cleanup Duty", err)
	}
	input, inputCanonical := generatedDeletePlanInput(t, selected, generatedVectorID(231), cleanup.duty, cleanup.target, 3)
	inputs := captureGeneratedScenarioInputs(t, input, cleanup.target.ResourceDigest)
	prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
	if prior.producerPhase == nil || prior.producerPhase.TransitionKind != contract.GeneratorAuthorityCleanupReserve {
		t.Fatal("cleanup reserve lost its producer phase")
	}
	producer, expected := preparePrivateGeneratedProducer(t, env, selected, prior, nil)
	if expected != inputs.expected {
		t.Fatal("cleanup preparation changed its original admitted attempt")
	}
	calls := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		calls++
		_, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("cleanup producer handoff")
	}
	entered, outcome := selected.selectCandidate(ctx, producer.reservation.candidate)
	if entered == nil || outcome.Outcome != ObservedCurrent || calls != 1 {
		t.Fatal("cleanup reserve selection and first send", outcome, calls)
	}
	keys.RetireGenerated()
	reopened, outcome := Open(ctx, OpenContext{admission: &entered.admission}, env.Store)
	if reopened == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("cleanup reserve reopen", outcome)
	}
	checkFreshGeneratedProcess(t, env.Store.(*memoryStore), reopened)
	observedTarget, present, err := observeGeneratedDeleteTarget(reopened, inputs.expected.Template.AttemptID)
	if err != nil || !present || observedTarget != cleanup.target {
		t.Fatal("cleanup observation changed the independently retained target", err)
	}
	g, err := reopened.selectedGeneratedWork(context.Background())
	if err != nil || g.attempts[expected.Template.AttemptID].record.State != contract.GeneratedEffectTransmitted {
		t.Fatal("reopened cleanup reserve lost entered delete", err)
	}
	original := g.attempts[expected.Template.AttemptID].record
	ownSelectedSupportForMutationFixture(t, ctx, reopened)
	for _, damage := range []string{"owner", "result contract"} {
		changed := original
		if damage == "owner" {
			changed.OwnerID = generatedVectorID(96)
		} else {
			changed.ResultContractID = generatedVectorID(96)
		}
		body, err := contract.EncodeGeneratedAttemptRecord(changed)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, reopened, 9, changed.AttemptID, body)
		generatedRefreshPhaseSets(t, reopened)
		reopened.generatedWork = nil
		if wrong, err := reopened.selectedGeneratedWork(context.Background()); wrong != nil || err == nil || calls != 1 {
			t.Fatal("cold cleanup read accepted changed owner or result contract", damage, err, calls)
		}
		body, err = contract.EncodeGeneratedAttemptRecord(original)
		if err != nil {
			t.Fatal(err)
		}
		generatedReplaceRecord(t, reopened, 9, original.AttemptID, body)
		generatedRefreshPhaseSets(t, reopened)
	}
}

// full_only: false
func TestGeneratedCleanupReservationReplyLossNeverRestoresFirstSend(t *testing.T) {
	for _, mode := range []string{"lost-before", "lost-after"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			selected := selectPrivateFailedGeneratedAggregate(t, env, f.session)
			work := mustSelectedGeneratedWork(t, selected)
			cleanup, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
			if err != nil || !ok || cleanup.kind != generatedCleanupDuty {
				t.Fatal("select cleanup Duty", err)
			}
			input, inputCanonical := generatedDeletePlanInput(t, selected, generatedVectorID(231), cleanup.duty, cleanup.target, 3)
			inputs := captureGeneratedScenarioInputs(t, input, cleanup.target.ResourceDigest)
			prior, _ := preparePrivateGeneratedReservation(t, env, selected, input, inputCanonical)
			producer, _ := preparePrivateGeneratedProducer(t, env, selected, prior, nil)
			sends := 0
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				sends++
				_, _, code := keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("cleanup first-send handoff")
			}
			store := env.Store.(*memoryStore)
			store.casMode = mode
			_, outcome := selected.selectCandidate(ctx, producer.reservation.candidate)
			wantSends, wantOutcome := 0, EvidenceUnavailable
			if mode == "lost-after" {
				wantOutcome = ObservedCurrent
			}
			if outcome.Outcome != wantOutcome || sends != wantSends {
				t.Fatal("cleanup reservation reply-loss outcome", outcome, sends)
			}
			if duplicate, result := selected.selectCandidate(ctx, producer.reservation.candidate); duplicate != nil || result.Outcome != AdmissionRefused || sends != wantSends {
				t.Fatal("cleanup reservation reply loss restored first-send permission", result, sends)
			}
			cold, result := Open(ctx, f.admission, env.Store)
			if cold == nil || result.Outcome != ObservedCurrent {
				t.Fatal("cleanup reply-loss cold open", result)
			}
			attempt, err := observeGeneratedAttempt(ctx, cold, inputs.expected.Template.AttemptID)
			observedTarget, targetPresent, targetErr := observeGeneratedDeleteTarget(cold, inputs.expected.Template.AttemptID)
			wantPresent := mode == "lost-after"
			if err != nil || targetErr != nil || attempt.present != wantPresent || targetPresent != wantPresent ||
				wantPresent && (attempt.expected != inputs.expected || observedTarget != cleanup.target) {
				t.Fatal("cleanup reply loss changed exact attempt or retained target observations", err, targetErr)
			}
			admitted := prior.operation.context
			admitted.IntentDescriptor = contract.DescriptorVector{}
			if _, _, err := cold.generatedProducerRequest(context.Background(), prior, admitted); err == nil {
				t.Fatal("cold cleanup state restored the original first-send path")
			}
		})
	}
}

// full_only: false
func TestGeneratedOrdinaryCleanupCloseLostReplyReopensSameEffectFreeOutcome(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			closed, _ := selectPrivateOwnedUnusableAggregateForProfile(t, env, f.session, []string{"omega"}, defaultGeneratedFixtureProfile())
			closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
			work := mustSelectedGeneratedWork(t, closed)
			selection, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
			if err != nil || !ok || selection.kind != generatedCleanupHazard {
				t.Fatal("select ordinary cleanup Hazard", err)
			}
			row := work.records[generatedRecordKey{11, selection.hazard.HazardID}]
			input, inputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(234), row, selection.target)
			inputs := captureGeneratedScenarioInputs(t, input, selection.target.ResourceDigest)
			prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
			recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
			observedTarget, present, err := observeGeneratedDeleteTarget(recorded, inputs.expected.Template.AttemptID)
			if err != nil || !present || observedTarget != selection.target || expected != inputs.expected {
				t.Fatal("ordinary cleanup changed its exact original target or attempt", err)
			}
			env.Custody.RetireGenerated()

			permit, err := recorded.admitGeneratedOrdinaryCleanupClose(context.Background(), expected.Template.AttemptID, generatedPlanInputFixture(t, recorded).context)
			if err != nil {
				t.Fatal("ordinary cleanup close admission", err)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			store.cas, trust.signs = 0, 0
			candidate, prepared := recorded.PrepareGeneratedLifecycle(ctx, permit, trust)
			if candidate == nil || prepared.Outcome != ObservedCurrent || store.cas != 0 || trust.signs != 1 {
				t.Fatal("effect-free ordinary cleanup close preparation", prepared, store.cas, trust.signs)
			}
			store.casMode = "lost-after"
			next, outcome := recorded.selectCandidate(ctx, candidate)
			if next == nil || outcome.Outcome != ObservedCurrent || store.cas != 1 || trust.signs != 1 {
				t.Fatal("lost ordinary cleanup close reply did not read back one selected CAS", outcome, store.cas, trust.signs)
			}
			cold := generatedLifecycleReopen(t, ctx, next, store)
			checkGeneratedReceiptRowsUnchanged(t, recorded, cold)
			if attempt, err := observeGeneratedAttempt(ctx, cold, inputs.expected.Template.AttemptID); err != nil || attempt.present {
				t.Fatal("closed ordinary cleanup retained a live result consumer", err)
			}
			after := mustSelectedGeneratedWork(t, cold)
			if after.parent != nil || after.phase != nil || !cold.root.Generated.ActiveOwner.IsZero() ||
				len(after.releases) != 2 || cold.root.Generated.PendingReleases != 2 {
				t.Fatal("lost ordinary cleanup close reply changed its effect-free outcome")
			}
		})
	}
}

// full_only: false
func TestGeneratedOrdinaryCleanupCloseKeepsLateSelectedReadResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		read contract.ReadResult
		want Result
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, failure(EvidenceUnavailable, MissingSelectedObject)},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport},
			Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			closed, _ := selectPrivateOwnedUnusableAggregateForProfile(t, env, f.session, []string{"omega"}, defaultGeneratedFixtureProfile())
			closed = generatedLifecycleReopen(t, ctx, closed, env.Store)
			work := mustSelectedGeneratedWork(t, closed)
			selection, ok, err := work.selectGeneratedCleanup(context.Background(), nil)
			if err != nil || !ok || selection.kind != generatedCleanupHazard {
				t.Fatal("select ordinary cleanup Hazard", err)
			}
			row := work.records[generatedRecordKey{11, selection.hazard.HazardID}]
			input, inputCanonical := generatedDeletePlanInputForSource(t, closed, generatedVectorID(234), row, selection.target)
			prior, _ := preparePrivateGeneratedReservation(t, env, closed, input, inputCanonical)
			recorded, _, expected, _ := selectActualGeneratedPacketRecord(t, env, closed, prior, custody.StandardValue, true, nil)
			recorded = generatedLifecycleReopen(t, ctx, recorded, env.Store)
			permit, err := recorded.admitGeneratedOrdinaryCleanupClose(context.Background(), expected.Template.AttemptID, generatedPlanInputFixture(t, recorded).context)
			if err != nil {
				t.Fatal("ordinary cleanup close admission", err)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			fragmentKeys := generatedSelectedFragmentKeys(t, recorded)
			creates, cas, signs := store.creates, store.cas, trust.signs
			reads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if fragmentKeys[key] {
					reads++
					return tc.read
				}
				return read
			}
			defer func() { store.readHook = nil }()
			candidate, result := recorded.PrepareGeneratedLifecycle(ctx, permit, trust)
			if candidate != nil || result != tc.want || reads == 0 || store.creates != creates || store.cas != cas || trust.signs != signs {
				t.Fatal("late selected cleanup read lost Store result or reached a write", result, reads)
			}
		})
	}
}

// This is a refused-state ownership test. The Format index is valid, but its
// generated groups are not a valid Core history.
// full_only: false
func TestGeneratedInitialIdentityRefusalDoesNotMutateAdministrativeShards(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	before := newEnvironmentFixture(t, context.Background(), env, nil, false).session
	prepared, _ := prepareUnclaimedGeneratedReservation(t, env, before, generatedPlanInputFixture(t, before), nil)
	s := prepared.reservation.state
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Supply actual owned configuration bytes without granting a new proof.
	rows := selectedSupportRecordsForCustodyFixture(t, s)
	for p := range s.support {
		s.support[p].Records = slices.Clone(s.support[p].Records)
		for i := range s.support[p].Records {
			row := &s.support[p].Records[i]
			if row.Body != nil {
				continue
			}
			for _, owned := range rows {
				if owned.Kind == row.Kind && owned.RecordID == row.RecordID {
					row.Body = bytes.Clone(owned.Body)
				}
			}
			if row.Body == nil {
				t.Fatal("refusal fixture missing actual support body")
			}
		}
	}
	// The independently specified 247-byte group frame makes this small
	// Format-only index cross one 2 MiB shard. No generated history is built.
	const groupFrameLength = 247
	groups := make([]format.AdministrativeGroup, contract.MaxRequiredSupportPageLength/groupFrameLength+1)
	descriptor := contract.GeneratorDescriptor{Digest: testID("refused shard descriptor"), Length: 4}
	for i := range groups {
		var id contract.ID
		binary.BigEndian.PutUint32(id[28:], uint32(i+1))
		groups[i] = format.AdministrativeGroup{GroupID: id, OwnerID: id, TargetID: id,
			OwnerKind: format.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate,
			Affected: descriptor, Dependencies: descriptor, Disposable: descriptor,
			SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing}
	}
	s.adminIndex.Groups = groups
	encoded, err := format.EncodeAdministrativeIndexPages(s.adminIndex)
	if err != nil || len(encoded) != 2 {
		t.Fatal("refusal fixture must have exactly two valid Format shards", len(encoded), err)
	}
	s.root.AdministrativeIndex = encoded[0].Ref
	s.root.AdministrativeIndexShards = []format.Ref{encoded[1].Ref}
	s.recountChildren()
	rootBefore, err := format.EncodeRoot(s.root)
	if err != nil {
		t.Fatal("refusal fixture Root framing", err)
	}
	shardsBefore := slices.Clone(s.root.AdministrativeIndexShards)
	if _, err := s.generatedInitialIdentity(g); err == nil {
		t.Fatal("unowned Format groups accepted as original selected identity")
	}
	rootAfter, err := format.EncodeRoot(s.root)
	if err != nil || !bytes.Equal(rootAfter, rootBefore) || !slices.Equal(s.root.AdministrativeIndexShards, shardsBefore) {
		t.Fatal("refused initial identity mutated the selected Root or its administrative shard refs", err)
	}
}

func logGeneratedProducerStage(t testing.TB, phase string, started time.Time, preparation contract.GeneratedProducerPreparation) {
	t.Helper()
	t.Logf("producer phase=%s attempt=%x duration-ms=%d", phase, preparation.AttemptID, time.Since(started).Milliseconds())
}

// full_only: false
func TestGeneratedProducerFixtureAcquiresInputBeforePreparation(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, true)
	before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, generatedPlanInputFixture(t, before), nil)
	acquired := false
	steps := generatedProducerFixtureSteps{
		inputReady: func(input custody.GeneratedProducerInput) {
			acquired = len(input.Session.Graph) > 0 && len(input.Plan.Declaration) > 0 && input.Preparation.AttemptID.IsZero()
		},
		request: func(ctx context.Context, p *generatedPreparation, attempt contract.ID, admitted contract.ApplyContext) (contract.CryptoGeneratedCompareRequest, contract.GeneratedProducerPreparation, error) {
			if !acquired {
				t.Fatal("producer preparation preceded acquired selected input")
			}
			return before.generatedProducerRequestForAttempt(ctx, p, attempt, admitted)
		},
		prepare: before.PrepareGeneratedProducer,
		claim: func(ctx context.Context, p *generatedPreparation) (*Candidate, Result) {
			return before.ClaimGeneratedPreparation(ctx, p.reservation.candidate, env.Trust)
		},
	}
	preparePrivateGeneratedProducerWithAdmission(t, env, before, reservation, env.Custody, contract.ID{}, custody.StandardValue, nil, nil, steps)
	env.Custody.RetireGenerated()
}
