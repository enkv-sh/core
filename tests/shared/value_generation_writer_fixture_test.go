package core

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func generatedReferenceDeclaration(t testing.TB, entry *contract.ValueEntry, work *generatedSelection) contract.GeneratorDeclarationEntry {
	t.Helper()
	location, ok := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, entry.Generated.IntentDigest}]
	if !ok {
		t.Fatal("writer fixture selected intent missing")
	}
	meta := entry.Generated
	reference := contract.GeneratorDeclaredGenerationReference{
		Epoch: meta.Epoch, RetirementMode: meta.RetirementMode, ConfigContractID: meta.ConfigContractID, ResourceContractID: meta.ResourceContractID,
		CompletionClass: meta.CompletionClass, Intent: location.Logical()}
	schema := contract.GeneratorDeclarationEntrySchema
	reference.Schema, reference.LifecycleMode = contract.GeneratorDeclaredReferenceSchema, meta.LifecycleMode
	payload, err := contract.EncodeGeneratorDeclaredGenerationReference(reference)
	if err != nil {
		t.Fatal("writer fixture reference", err)
	}
	return contract.GeneratorDeclarationEntry{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: schema, Kind: contract.GeneratorDeclarationGeneratedReference,
		Name: entry.Name, Recipients: slices.Clone(entry.Recipients), Payload: payload}
}

func generatedWriterCurrentDeclarations(t testing.TB, s *StateSession, changing []string) []contract.GeneratorDeclarationEntry {
	t.Helper()
	work := mustSelectedGeneratedWork(t, s)
	var out []contract.GeneratorDeclarationEntry
	for _, name := range s.root.Names {
		if slices.Contains(changing, name.Name) {
			continue
		}
		entry := s.valueEntry(name.Slot)
		if entry.ValueSource == contract.Supplied && entry.ConfidentialityClass == contract.Plain {
			out = append(out, contract.GeneratorDeclarationEntry{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
				Name: entry.Name, Recipients: slices.Clone(entry.Recipients), Payload: bytes.Clone(entry.ValueBytes)})
			continue
		}
		if entry.ValueSource != contract.Generated {
			t.Fatal("writer fixture requires generated or plain current entries")
		}
		out = append(out, generatedReferenceDeclaration(t, entry, work))
	}
	return out
}

func generatedWriterPlanInput(t testing.TB, s *StateSession, operation contract.ID, names []string, intentForName func(string) []byte,
	epoch uint64, retiring map[string]contract.ValueEntry) generatedPlanInput {
	t.Helper()
	sources := generatedWriterCurrentDeclarations(t, s, names)
	profile := defaultGeneratedFixtureProfile()
	bound := generatedReservationInputForMembershipStateIntents(t, s, operation, []contract.ID{s.admission.recipient},
		names, intentForName, profile, epoch, nil, retiring, sources...)
	input := generatedPlanInputForGenerations(t, s, operation, names, profile, sources...)
	input.graph, input.declaration, input.registry, input.recoveryPolicy, input.requestBindings = bound.graph, bound.declaration,
		bound.graph.Request.Registry, bound.graph.Request.RecoveryPolicyID, slices.Clone(bound.requestBindings)
	input.context.AdmissionID = fixtureID(s.root.Domain, fmt.Sprintf("writer plan admission %x", operation))
	input.context.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	input.context.SessionID = fixtureID(s.root.Domain, fmt.Sprintf("writer plan session %x", operation))
	return input
}

type generatedWriterInput struct {
	Operation contract.ID
	Names     []string
	Intents   map[string][]byte
	Epoch     uint64
	Directory string
}

// Only writer children use these explicit local body facts. Historical objects
// stay file-backed and are not expanded into the JSON process fixture.
type generatedWriterObject struct {
	Token  contract.Token
	Body   []byte      `json:",omitempty"`
	Path   string      `json:",omitempty"`
	Length uint64      `json:",omitempty"`
	Digest contract.ID `json:",omitempty"`
}

func generatedWriterObjectFacts(value stored) generatedWriterObject {
	return generatedWriterObject{Token: value.Token, Body: value.Body, Path: value.bodyPath, Length: value.bodyLength, Digest: value.bodyDigest}
}

func (value generatedWriterObject) stored() stored {
	return stored{Token: value.Token, Body: value.Body, bodyPath: value.Path, bodyLength: value.Length, bodyDigest: value.Digest}
}

type generatedWriterWrite struct {
	Key       string
	Condition contract.Token
	Object    generatedWriterObject
}

func generatedWriterRetiringEntries(s *StateSession, names []string) map[string]contract.ValueEntry {
	var retiring map[string]contract.ValueEntry
	for _, row := range s.root.Names {
		if slices.Contains(names, row.Name) {
			if retiring == nil {
				retiring = make(map[string]contract.ValueEntry)
			}
			retiring[row.Name] = *s.valueEntry(row.Slot)
		}
	}
	return retiring
}

func generatedWriterInFreshProcess(t *testing.T, s *StateSession, store *memoryStore, input generatedWriterInput) generatedRecordOutput {
	t.Helper()
	if len(input.Names) == 0 || len(input.Intents) != len(input.Names) || !filepath.IsAbs(input.Directory) {
		t.Fatal("invalid writer child input")
	}
	if err := store.useFileBodies(input.Directory); err != nil {
		t.Fatal("writer child body store", err)
	}
	var writes []generatedWriterWrite
	store.writerWrites = &writes
	t.Cleanup(func() { store.writerWrites = nil })
	keys := memoryCurrentAuthorityKeys(t, s)
	env := fixtureEnvironment{Store: store, Trust: memoryCurrentAuthoritySigner(t, s), Custody: keys, Domain: s.root.Domain}
	retiring := generatedWriterRetiringEntries(s, input.Names)
	plan := generatedWriterPlanInput(t, s, input.Operation, input.Names, func(name string) []byte { return input.Intents[name] }, input.Epoch, retiring)
	if len(plan.declaration) > int(contract.GeneratorDeclarationMaxLength) {
		t.Fatal("writer declaration exceeded bound")
	}
	selected := selectGeneratedWriterBatch(t, env, s, plan, "fresh writer", custody.StandardValue)
	if selected == nil || selected.root.Generated.ActiveOwner != (contract.ID{}) {
		t.Fatal("writer child left active work")
	}
	keys.RetireGenerated()
	return generatedRecordOutput{BeforeToken: s.token, BeforeHead: bytes.Clone(s.body), Generation: store.generation, WriterWrites: writes}
}

func selectFreshGeneratedWriter(t *testing.T, store *memoryStore, s *StateSession, operation contract.ID, name string, intent []byte, epoch uint64) *StateSession {
	t.Helper()
	return selectFreshGeneratedWriterBatch(t, store, s, operation, []string{name}, map[string][]byte{name: intent}, epoch)
}

func selectFreshGeneratedWriterBatch(t *testing.T, store *memoryStore, s *StateSession, operation contract.ID, names []string, intents map[string][]byte, epoch uint64) *StateSession {
	t.Helper()
	input := selectedProcessFacts(t, OpenContext{admission: &s.admission}, s)
	compactFreshProcessWork(&input)
	plan := generatedWriterPlanInput(t, s, operation, names, func(name string) []byte { return intents[name] }, epoch,
		generatedWriterRetiringEntries(s, names))
	declaration, err := contract.InspectGeneratorDeclaration(plan.declaration)
	if err != nil {
		t.Fatal("fresh writer desired declaration", err)
	}
	desired, err := generatedDeclarationOutputEntries(declaration)
	if err != nil {
		t.Fatal("fresh writer desired output entries", err)
	}
	transition, err := s.generatedOutputTransition(t.Context(), desired)
	if err != nil {
		t.Fatal("fresh writer parent output sources", err)
	}
	input.GeneratedOutputBindings = transition.Bindings
	input.GeneratedWriter = &generatedWriterInput{Operation: operation, Names: names, Intents: intents, Epoch: epoch,
		Directory: filepath.Join(t.TempDir(), "writer-bodies")}
	input.Generation = store.generation
	input.WriterObjects = make(map[string]generatedWriterObject, len(store.objects))
	for key, object := range store.objects {
		input.WriterObjects[key] = generatedWriterObjectFacts(object)
	}
	return importFreshGeneratedSelection(t, s, input.Generation, checkFreshProcessInput(t, input))
}

func importFreshGeneratedWriterWrites(t testing.TB, s *StateSession, generation int, output *generatedRecordOutput) *StateSession {
	t.Helper()
	ctx := t.Context()
	headKey := s.admission.store.HeadKey
	before := s.store.Read(ctx, headKey, uint32(len(output.BeforeHead)))
	if before.Status != contract.ReadOK || before.Token != output.BeforeToken || output.BeforeToken != s.token ||
		!bytes.Equal(before.Body, output.BeforeHead) || !bytes.Equal(s.body, output.BeforeHead) || output.Generation != generation+len(output.WriterWrites) {
		t.Fatal("writer child predecessor or complete write count differs")
	}
	selections := 0
	for _, write := range output.WriterWrites {
		body := readFixtureStoredBody(write.Object.stored(), ^uint32(0))
		if body.Status != contract.ReadOK {
			t.Fatal("writer child body cannot be read and verified")
		}
		var result contract.WriteResult
		if write.Key == headKey {
			selections++
			current := s.store.Read(ctx, headKey, contract.MaxHeadLength)
			if current.Status != contract.ReadOK || current.Token != write.Condition {
				t.Fatal("writer child HEAD condition differs")
			}
			result = s.store.CompareAndSwap(ctx, write.Key, write.Condition, body.Body)
		} else {
			if write.Condition != (contract.Token{}) || s.store.Read(ctx, write.Key, uint32(len(body.Body))).Status != contract.ReadMissing {
				t.Fatal("writer child immutable overwrite")
			}
			result = s.store.Create(ctx, write.Key, body.Body)
		}
		observed := s.store.Read(ctx, write.Key, uint32(len(body.Body)))
		if result.Status != contract.WriteAcknowledged || observed.Status != contract.ReadOK || observed.Token != write.Object.Token || !bytes.Equal(observed.Body, body.Body) {
			t.Fatal("writer child selected write replay differs")
		}
	}
	if selections < 3 {
		t.Fatal("writer child did not complete normal producer, record and final selections")
	}
	selected, result := Open(ctx, OpenContext{admission: &s.admission}, s.store)
	if selected == nil || result.Outcome != ObservedCurrent || !selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("writer child final cold Open", result)
	}
	return selected
}

const maximumCapacityAdmissionLifetime = 30 * time.Minute

type parallelOriginalResult struct {
	expected           contract.GeneratorResultExpectation
	result             []byte
	code               contract.CryptoResultCode
	persist            Result
	preparationStarted time.Time
	entered            int
}

// Each original is still prepared before the one complete-set Claim. Keep the
// full declaration reads bounded while making progress on three originals.
func runBoundedGeneratedOriginalPreparations(count int, prepare func(int)) {
	const concurrent = 3
	slots := make(chan struct{}, concurrent)
	var joined sync.WaitGroup
	joined.Add(count)
	for i := 0; i < count; i++ {
		go func(i int) {
			defer joined.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			prepare(i)
		}(i)
	}
	joined.Wait()
}

func sendParallelOriginals(t *testing.T, ctx context.Context, env fixtureEnvironment, before *StateSession,
	reservation *generatedPreparation, value uint8,
	observer ...func(string, []*generatedPreparation, *StateSession, []parallelOriginalResult)) (*StateSession, []parallelOriginalResult) {
	t.Helper()
	if len(observer) > 1 {
		t.Fatal("parallel originals accept at most one observer")
	}
	g, err := reservation.reservation.state.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var attempts []contract.ID
	for _, lineage := range g.bundles[0].Lineages {
		if lineage.Purpose == contract.GeneratorLineageCreate {
			attempts = append(attempts, lineage.Templates[0].AttemptID)
		}
	}
	if len(attempts) == 0 {
		t.Fatal("no generated originals")
	}
	keys := make([]*custody.Fixture, len(attempts))
	producers := make([]*generatedPreparation, len(attempts))
	returned := make([]parallelOriginalResult, len(attempts))
	// An observer can fail after complete admission or entered effects. Always
	// join private ownership, including partially constructed key forks.
	t.Cleanup(func() {
		for _, key := range keys {
			if key != nil {
				key.RetireGenerated()
			}
		}
	})
	observe := func(phase string, selected *StateSession) {
		if len(observer) == 1 {
			observer[0](phase, producers, selected, returned)
		}
	}
	for i := range attempts {
		keys[i] = env.Custody
		if i != 0 {
			keys[i] = env.Custody.ForkGenerated(t)
		}
	}
	facts := acquireGeneratedProducerFixtureFacts(t, env, before, reservation)
	runBoundedGeneratedOriginalPreparations(len(attempts), func(i int) {
		attempt := attempts[i]
		returned[i].preparationStarted = time.Now()
		producers[i], returned[i].expected = preparePrivateGeneratedProducerWithAdmission(t, env, before, reservation, keys[i], attempt, value, func() { returned[i].entered++ }, nil, generatedProducerFixtureSteps{request: before.generatedOriginalProducerRequest, prepare: before.PrepareGeneratedOriginalProducer, claim: before.ClaimGeneratedOriginalProducer, facts: facts})
	})
	facts = nil
	for i, producer := range producers {
		if producer == nil {
			t.Fatal("parallel original preparation failed", i)
		}
	}
	observe("prepared", nil)
	stage := time.Now()
	if candidate, outcome := before.ClaimGeneratedOriginalSet(ctx, producers, env.Trust); candidate == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("parallel original set claim", outcome)
	}
	t.Logf("producer phase=whole-set-claim duration-ms=%d originals=%d", time.Since(stage).Milliseconds(), len(producers))
	observe("claimed", nil)
	anchor := producers[0]
	if !anchor.reservation.candidate.bindFirstSend(anchor, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		var joined sync.WaitGroup
		joined.Add(len(producers))
		for i, producer := range producers {
			go func(i int, producer *generatedPreparation) {
				defer joined.Done()
				invokeStarted := time.Now()
				returned[i].result, _, returned[i].code = keys[i].InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				t.Logf("producer phase=invoke index=%d duration-ms=%d preparation-age-ms=%d entered=%d code=%d result-bytes=%d", i, time.Since(invokeStarted).Milliseconds(), invokeStarted.Sub(returned[i].preparationStarted).Milliseconds(), returned[i].entered, returned[i].code, len(returned[i].result))
				if returned[i].code == contract.CryptoSuccess && len(returned[i].result) != 0 {
					returned[i].persist = reservation.reservation.state.persistGeneratedResult(ctx,
						generatedResultWrite{attempt: returned[i].expected.Template.AttemptID, body: returned[i].result})
				}
				t.Logf("producer result index=%d entered=%d code=%d result-bytes=%d persist-outcome=%d persist-reason=%d attempt-equal=%t", i, returned[i].entered, returned[i].code, len(returned[i].result), returned[i].persist.Outcome, returned[i].persist.Reason, returned[i].expected.Template.AttemptID == attempts[i])
			}(i, producer)
		}
		joined.Wait()
		observe("returned", nil)
		for _, result := range returned {
			if result.code != contract.CryptoSuccess || result.persist.Outcome != 0 {
				if result.persist.Outcome != 0 {
					return contract.CryptoCustodyUnavailable
				}
				return result.code
			}
		}
		return contract.CryptoSuccess
	}) {
		t.Fatal("parallel originals handoff")
	}
	stage = time.Now()
	selected, outcome := before.selectCandidate(ctx, anchor.reservation.candidate)
	t.Logf("producer phase=selection duration-ms=%d outcome=%d reason=%d", time.Since(stage).Milliseconds(), outcome.Outcome, outcome.Reason)
	observe("selected", selected)
	for _, key := range keys {
		key.RetireGenerated()
	}
	observe("retired", selected)
	if selected == nil || outcome.Outcome != ObservedCurrent {
		t.Fatal("parallel originals selection", outcome)
	}
	for i, result := range returned {
		if result.code != contract.CryptoSuccess || result.persist.Outcome != 0 || len(result.result) == 0 || result.expected.Template.AttemptID != attempts[i] {
			t.Fatal("parallel original lacks durable qualified result", i, result.code, result.persist.Outcome)
		}
	}
	return selected, returned
}

func selectGeneratedWriterBatch(t *testing.T, env fixtureEnvironment, before *StateSession, input generatedPlanInput, label string, value uint8) *StateSession {
	t.Helper()
	if len(input.declaration)+8 > 33554432 {
		t.Fatal("writer framed declaration exceeds 32 MiB")
	}
	t.Logf("writer operation=%s entries=%d originals=%d framed-declaration-bytes=%d", label, len(input.graph.ValueEntryPlans), len(input.requestBindings), len(input.declaration)+8)
	plan, err := before.generatedPlanRequest(t.Context(), input)
	if err != nil || plan == nil {
		t.Fatal("writer capacity admission", err)
	}
	work := mustSelectedGeneratedWork(t, before)
	var logical uint64
	for _, named := range before.root.Names {
		entry := before.valueEntry(named.Slot)
		if entry.ValueSource == contract.Generated {
			logical += uint64(work.content.locations[generatedContentKey{contract.GeneratorContentIntent, entry.Generated.IntentDigest}].Length)
		}
	}
	charged := plan.capacity.Groups[contract.GeneratorCapacityIntents]
	if charged.MaxFramedBytes < logical+uint64(len(input.declaration)) {
		t.Fatal("writer capacity omitted retained intent or new declaration bytes", charged, logical)
	}
	t.Logf("writer retained-intent-bytes=%d reserved-framed-bytes=%d reserved-pages=%d", logical, charged.MaxFramedBytes, charged.MaxPages)
	reservation, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
	current, originals := sendParallelOriginals(t, t.Context(), env, before, reservation, value)
	if len(originals) != len(input.requestBindings) {
		t.Fatal("writer original whole-set count")
	}
	for i, original := range originals {
		if original.entered != 1 {
			t.Fatal("writer original effect count", i, original.entered)
		}
		admitted := generatedPlanInputFixture(t, current).context
		admitted.AdmissionID = fixtureID(env.Domain, fmt.Sprintf("%s record admission %d", label, i))
		admitted.SessionID = fixtureID(env.Domain, fmt.Sprintf("%s record session %d", label, i))
		admitted.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
		record, err := current.generatedRecordRequest(context.Background(), original.expected.Template.AttemptID, original.result, admitted)
		if err != nil {
			t.Fatal("writer record request", i, err)
		}
		prepared := preparePrivateGeneratedRecord(t, env, current, record)
		var result Result
		current, result = current.selectCandidate(t.Context(), prepared.reservation.candidate)
		if current == nil || result.Outcome != ObservedCurrent {
			t.Fatal("writer record selection", i, result)
		}
		env.Custody.RetireGenerated()
	}
	admitted := generatedPlanInputFixture(t, current).context
	admitted.AdmissionID, admitted.SessionID = fixtureID(env.Domain, label+" final admission"), fixtureID(env.Domain, label+" final session")
	admitted.Expiry = uint64(time.Now().Add(maximumCapacityAdmissionLifetime).UnixNano())
	final, err := current.generatedFinalRequest(t.Context(), admitted)
	if err != nil {
		t.Fatal("writer final request", err)
	}
	current, prepared := preparePrivateGeneratedFinal(t, env, current, final)
	selected, result := current.selectCandidate(t.Context(), prepared.reservation.candidate)
	if selected == nil || result.Outcome != ObservedCurrent || !selected.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("writer final selection", result)
	}
	env.Custody.RetireGenerated()
	return selected
}
