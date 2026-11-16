package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestGeneratedWriterBatchReconstructionAndPreservation(t *testing.T) {
	generatedWriterReconstructionAndPreservation(t, 2, 128)
}

// full_only: true
// Normal completed operations reach 128 distinct 384 KiB intents, then preserve,
// update, retire and reconstruct that exact 48 MiB set in both recovery modes.
func TestGeneratedWriterMaximumCurrentIntentsAndReconstruction(t *testing.T) {
	generatedWriterReconstructionAndPreservation(t, 64, 393216)
}

// Ordinary fixture inputs are plugin settings. The independent wrapper commits
// their JSON bytes with the family framing before the fixture issues work.
func hermeticGeneratorIntent(settings []byte) []byte {
	if len(settings) >= 71 && settings[0] == 0 && settings[1] == 1 && int(binary.BigEndian.Uint32(settings[67:71])) == len(settings)-71 {
		return bytes.Clone(settings)
	}
	if !json.Valid(settings) {
		body, err := json.Marshal(string(settings))
		if err != nil {
			panic(err)
		}
		settings = body
	}
	profile := defaultGeneratedFixtureProfile()
	body := append([]byte{0, 1}, profile.ConfigContractID[:]...)
	body = append(body, byte(profile.LifecycleMode))
	body = append(body, profile.ResourceContractID[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	return append(body, settings...)
}

// This fixture writes the specified schema1 intent framing independently.
// Settings are one JSON object. The complete intent retains the requested width.
func hermeticSizedGeneratorIntent(name string, fill byte, length int) []byte {
	quoted, err := json.Marshal(name)
	if err != nil {
		panic(err)
	}
	prefix := append([]byte(`{"name":`), quoted...)
	prefix = append(prefix, []byte(`,"padding":"`)...)
	padding := length - 71 - len(prefix) - 2
	if padding < 0 {
		panic("fixture intent width is too small")
	}
	settings := append(prefix, bytes.Repeat([]byte{fill}, padding)...)
	settings = append(settings, '"', '}')
	profile := defaultGeneratedFixtureProfile()
	body := append([]byte{0, 1}, profile.ConfigContractID[:]...)
	body = append(body, byte(profile.LifecycleMode))
	body = append(body, profile.ResourceContractID[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(settings)))
	return append(body, settings...)
}
func generatedWriterIntent(name string, epoch uint64, length int) []byte {
	return hermeticSizedGeneratorIntent(fmt.Sprintf("%s epoch %d", name, epoch), byte('a'+epoch%26), max(length, 128))
}

func generatedWriterIntentTotal(intents map[string][]byte) uint64 {
	var total uint64
	for _, intent := range intents {
		total += uint64(len(intent))
	}
	return total
}

func assertGeneratedWriterReconstruction(t *testing.T, env fixtureEnvironment, selected *StateSession, intents map[string][]byte) *StateSession {
	t.Helper()
	store := env.Store.(*memoryStore)
	public, private := env.Custody.Calls()
	projection := reconstructProjectionFixture(t, env, selected, store)
	afterPublic, afterPrivate := env.Custody.Calls()
	if afterPublic != public || afterPrivate-private != len(intents) {
		t.Fatal("writer reconstruction did not verify every current secret", afterPublic-public, afterPrivate-private)
	}
	assertReconstructionProjectionExact(t, projection, selected, store)
	returned := reconstructionReturnedSession(t, projection, selected)
	// Content must come from the returned support rows, with no predecessor
	// logical locations, fragments or decoded graph available to the oracle.
	returned.generatedWork, returned.generatedGraphs, returned.generatedSliceLocations = nil, nil, nil
	returned.generatedSlicesRoot, returned.outputConfigurationRoot = contract.ID{}, contract.ID{}
	returned.supportFacts, returned.fragmentFacts = nil, nil
	assertReconstructionReturnedIntentBytes(t, returned, len(intents), generatedWriterIntentTotal(intents), func(name string) []byte { return intents[name] })
	assertGeneratedWriterState(t, returned, intents)
	if returned.root.OutputConfiguration != selected.root.OutputConfiguration || returned.root.WarningBits != selected.root.WarningBits {
		t.Fatal("writer reconstruction lost output or warnings")
	}

	source, err := returned.outputConfigurationBodySource()
	if err != nil {
		t.Fatal("returned writer output source", err)
	}
	returnedOutput, err := contract.InspectOutputConfigurationSource(returned.root.Domain, returned.root.OutputConfiguration, source)
	selectedOutput, result := selected.currentOutputConfigurationForApply(t.Context())
	if err != nil || result.Outcome != 0 || !reflect.DeepEqual(returnedOutput, selectedOutput) || !reflect.DeepEqual(generatedWriterOutputRows(t, returned), generatedWriterOutputRows(t, selected)) {
		t.Fatal("returned writer complete output or marker differs", err, result)
	}
	projection.Close()
	if projection.PartCount() != 0 {
		t.Fatal("writer reconstruction retained closed buffers")
	}
	return generatedLifecycleReopen(t, t.Context(), returned, env.Store)
}

func generatedWriterOutputRows(t *testing.T, s *StateSession) map[generatedRecordKey][]byte {
	t.Helper()
	rows := make(map[generatedRecordKey][]byte)
	for _, row := range s.supportRecords() {
		if row.Kind == contract.PublicationCoordinateSupportKind || row.Kind == contract.PublicationMarkerSupportKind {
			rows[generatedRecordKey{row.Kind, row.RecordID}] = bytes.Clone(row.Body)
		}
	}
	return rows
}

func selectGeneratedWriterUnsentMarker(t *testing.T, env fixtureEnvironment, s *StateSession, name string) (*StateSession, contract.ID, *publicationControlledPrivate) {
	t.Helper()
	private := newPublicationControlledPrivate()
	s.admission.publicationNamespaces = []publicationNamespace{{domain: env.Domain, service: "aws", physical: "publication", premise: contract.Hash([]byte("independently qualified namespace"))}}
	input := publicationInput{names: []string{name}, acting: s.admission.recipient, deadline: time.Now().Add(30 * time.Second)}
	plan, result := s.planPublication(t.Context(), input, private.callbacks())
	if plan == nil {
		t.Fatal("writer output marker plan", result)
	}
	store := env.Store.(*memoryStore)
	store.casMode = "lost-after"
	t.Cleanup(func() { store.casMode = "" })
	got := plan.execute(t.Context(), private.callbacks(), func(ctx context.Context) (*StateSession, contract.Trust, Result) {
		current, result := Open(ctx, OpenContext{admission: &s.admission}, env.Store)
		return current, env.Trust, result
	})
	store.casMode = ""
	if len(private.owners) != 1 || private.owners[0].prepared != 1 || private.owners[0].armed != 0 || private.owners[0].sent != 0 || private.owners[0].retired != 1 || len(got.output.Entries) != 1 || len(got.output.Entries[0].Actions) != 1 || got.output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeUnknown {
		t.Fatal("writer output reservation did not select an unsent marker", got.state)
	}
	selected := generatedLifecycleReopen(t, t.Context(), s, env.Store)
	relation, err := selectedPublicationRelation(selected.selectedImage())
	attempt := got.output.Entries[0].Actions[0].AttemptID
	if err != nil || len(relation.markers) != 1 || relation.markers[attempt].State != contract.PublicationMayHaveEntered {
		t.Fatal("writer unsent selected marker missing", err)
	}
	return selected, attempt, private
}

func generatedWriterReconstructionAndPreservation(t *testing.T, batch, intentLength int) {
	t.Helper()
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery%t", recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			env.Context = t.Context()
			initial := newEnvironmentFixture(t, t.Context(), env, nil, false)
			s := initial.session
			store := env.Store.(*memoryStore)
			if err := store.useFileBodies(t.TempDir() + "/bodies"); err != nil {
				t.Fatal(err)
			}
			names := make([]string, 2*batch)
			intents := make(map[string][]byte, len(names))
			for i := range names {
				names[i] = fmt.Sprintf("writer-%03d", i)
				intents[names[i]] = generatedWriterIntent(names[i], 1, intentLength)
			}
			first := generatedWriterPlanInput(t, s, fixtureID(env.Domain, "writer first batch"), names[:batch], func(name string) []byte { return intents[name] }, 0, nil)
			s = selectGeneratedWriterBatch(t, env, s, first, "writer first batch", custody.StandardValue)
			s = generatedLifecycleReopen(t, t.Context(), s, env.Store)
			half := make(map[string][]byte, batch)
			unchanged := make(map[string]contract.ValueEntry, batch)
			for _, name := range names[:batch] {
				half[name] = intents[name]
				unchanged[name] = *s.valueEntry(namedSlot(t, s, name))
			}
			assertGeneratedWriterState(t, s, half)
			targetName := names[batch-1]
			target := outputConfigurationTarget(targetName, "publication")

			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "publication", targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: targetName, destinations: []string{"publication"}}}}
			s = selectAdmittedOutputConfiguration(t, t.Context(), s, env, env.Custody, s.currentEntryInputs(), output)
			outputDescriptor := s.root.OutputConfiguration
			outputConfiguration, result := s.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 || outputDescriptor.BindingCount != 1 {
				t.Fatal("writer selected output incomplete", result)
			}
			s, marker, private := selectGeneratedWriterUnsentMarker(t, env, s, targetName)
			outputRows := generatedWriterOutputRows(t, s)
			checkOutput := func(s *StateSession) {
				t.Helper()
				current, result := s.currentOutputConfigurationForApply(t.Context())
				if result.Outcome != 0 || s.root.OutputConfiguration != outputDescriptor || !reflect.DeepEqual(current, outputConfiguration) || !reflect.DeepEqual(generatedWriterOutputRows(t, s), outputRows) || private.owners[0].sent != 0 {
					t.Fatal("writer preservation lost output metadata/marker or sent output", result)
				}
			}
			second := make(map[string][]byte, batch)
			for _, name := range names[batch:] {
				second[name] = intents[name]
			}
			s = selectFreshGeneratedWriterBatch(t, store, s, fixtureID(env.Domain, "writer second batch"), names[batch:], second, 0)
			for name, entry := range unchanged {
				if !reflect.DeepEqual(*s.valueEntry(namedSlot(t, s, name)), entry) {
					t.Fatal("writer carried generation changed", name)
				}
			}
			assertGeneratedWriterState(t, s, intents)
			if generatedWriterIntentTotal(intents) != uint64(2*batch*intentLength) {
				t.Fatal("writer whole intent byte count")
			}
			checkOutput(s)
			checkFreshGeneratedProcess(t, store, s)
			s = assertGeneratedWriterReconstruction(t, env, s, intents)
			checkOutput(s)

			// An administrative exit can discard unreadable auxiliary marker detail;
			// every current intent and selected configuration byte stays mandatory.
			_, scope, err := s.administrativeWorkClosure(marker)
			if err != nil || len(scope) != 1 {
				t.Fatal("writer marker discard scope", err)
			}
			var missing format.Ref
			for _, page := range s.adminIndex.Pages {
				if page.ReadRequired || slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
					continue
				}
				if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
					return row.Kind == contract.PublicationMarkerSupportKind && row.RecordID == marker
				}) {
					missing = page.Ref
					break
				}
			}
			if missing.Object.IsZero() {
				t.Fatal("writer marker has no discardable detail page")
			}
			missingKey := mustKey(t, store.desc.Prefix, missing)
			if _, present := store.objects[missingKey]; !present {
				t.Fatal("writer marker detail was absent before loss")
			}
			delete(store.objects, missingKey)
			if ordinary, result := Open(t.Context(), OpenContext{admission: &s.admission}, store); ordinary != nil || result.Outcome != EvidenceUnavailable {
				t.Fatal("writer ordinary Open accepted missing selected marker", result)
			}
			admin, result := openAdministrative(t.Context(), OpenContext{admission: &s.admission}, store)
			if admin == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer administrative marker Open needed discardable detail", result)
			}

			candidate, result := prepareTestEndSelectedWork(t, admin, t.Context(), marker, env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent || candidate.firstSend != nil {
				t.Fatal("writer marker exit preparation", result)
			}
			s, result = admin.selectCandidate(t.Context(), candidate)
			if s == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer marker exit selection", result)
			}
			s = generatedLifecycleReopen(t, t.Context(), s, env.Store)
			if s.root.WarningBits != WarningDiscardedExactEvidence|WarningPublicationOrderValue|WarningPossibleStoreGarbage {
				t.Fatal("writer marker exit warnings", s.root.WarningBits)
			}
			if private.owners[0].sent != 0 {
				t.Fatal("writer exit emitted output")
			}
			s, _, private = selectGeneratedWriterUnsentMarker(t, env, s, targetName)
			outputRows = generatedWriterOutputRows(t, s)
			checkOutput(s)
			for epoch := uint64(2); epoch <= 3; epoch++ {
				old := *s.valueEntry(namedSlot(t, s, names[0]))
				kept := make(map[string]contract.ValueEntry, len(names)-1)
				for _, name := range names[1:] {
					kept[name] = *s.valueEntry(namedSlot(t, s, name))
				}
				intents[names[0]] = generatedWriterIntent(names[0], epoch, intentLength)
				s = selectFreshGeneratedWriter(t, store, s, fixtureID(env.Domain, fmt.Sprintf("writer replace %d", epoch)), names[0], intents[names[0]], epoch)
				changed := s.valueEntry(namedSlot(t, s, names[0]))
				if changed.Incarnation != old.Incarnation || changed.ValueState == old.ValueState || changed.Generated.Epoch != epoch || changed.Generated.RetiringDutyPresent != 1 {
					t.Fatal("writer replacement identity or retirement")
				}
				for name, entry := range kept {
					if !reflect.DeepEqual(*s.valueEntry(namedSlot(t, s, name)), entry) {
						t.Fatal("writer replacement changed carried identity", name)
					}
				}
				assertGeneratedWriterState(t, s, intents)
				checkOutput(s)
				s = closeGeneratedWriterRetirement(t, env, s, names[0], fixtureID(env.Domain, fmt.Sprintf("writer close retirement %d", epoch)))
				work := mustSelectedGeneratedWork(t, s)
				if _, retained := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, old.Generated.IntentDigest}]; retained {
					t.Fatal("writer retired dead intent remains selected")
				}
				assertGeneratedWriterState(t, s, intents)
				checkOutput(s)
				checkFreshGeneratedProcess(t, store, s)
			}
			// Grant the existing reader, then replace that exact key through ordinary APIs.
			entries := s.currentEntryInputs()
			entries[0].Recipients = append(entries[0].Recipients, fixtureID(env.Domain, "reader"))
			slices.SortFunc(entries[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			parent := admitSuppliedComparison(t, s, env.Custody, entries)
			comparison, result := s.Compare(t.Context(), entries, parent)
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer reader grant comparison", result)
			}
			candidate, result = s.Prepare(t.Context(), comparison, admit(t, s, comparison), env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer reader grant preparation", result)
			}
			s, result = s.selectCandidate(t.Context(), candidate)
			if s == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer reader grant selection", result)
			}
			env.Custody.RetireApply()
			s = generatedLifecycleReopen(t, t.Context(), s, env.Store)
			run := newScenarioRun(t, t.Context(), env)
			f := &environmentFixture{admission: OpenContext{admission: &s.admission}, session: s}
			before, after := replaceReaderInSelectedForName(t, t.Context(), run, f, names[0])
			if !env.Custody.MaterialPreserved(before, after) {
				t.Fatal("writer reader replacement changed private value")
			}
			s = f.session
			assertGeneratedWriterState(t, s, intents)
			checkOutput(s)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			actors := env.ReplacementActors(t, t.Context(), s, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner|contract.SuccessionChangeAuthorityKEK, contract.NormalSigningRole)
			permit := admitAuthorityReplacement(t, s, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeNormalSigner|contract.SuccessionChangeAuthorityKEK, actors.Source)
			candidate, result = s.PrepareSuccession(t.Context(), permit, actors.Signers)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer authority replacement preparation", result)
			}
			admission := deliverSuccessionBasis(t, candidate)
			if result = s.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
				t.Fatal("writer authority replacement selection", result)
			}
			actors.Keys.RetireAccess()
			s, result = Open(t.Context(), admission, store)
			if s == nil || result.Outcome != ObservedCurrent {
				t.Fatal("writer replacement cold Open", result)
			}
			actors.Activate(t, s)
			env.Custody = actors.Keys
			env.Trust = actors.Signers.NormalSuccessor
			checkOutput(s)
			assertGeneratedWriterState(t, s, intents)
			s = assertGeneratedWriterReconstruction(t, env, s, intents)
			checkOutput(s)
			entries = s.currentEntryInputs()
			parent = admitSuppliedComparison(t, s, env.Custody, entries)
			creates, cas := store.creates, store.cas
			if comparison, result := s.Compare(t.Context(), entries, parent); comparison != nil || result.Outcome != Unchanged || store.creates != creates || store.cas != cas {
				t.Fatal("reconstructed writer state refused normal no-op admission", result)
			}
			env.Custody.RetireApply()
			if private.owners[0].sent != 0 {
				t.Fatal("writer preservation emitted output")
			}
			t.Logf("writer complete current entries=%d exact-intent-bytes=%d recovery=%t", len(intents), generatedWriterIntentTotal(intents), recovery)
		})
	}
}

// full_only: false
func TestGeneratedWriterReconstructionRefusesMissingOrCorruptReferencedIntent(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, corrupt := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery%t/corrupt%t", recovery, corrupt), func(t *testing.T) {
				env, _ := genesisEnvironment(t, contract.GCP, recovery)
				s := newEnvironmentFixture(t, t.Context(), env, nil, false).session
				store := env.Store.(*memoryStore)
				if err := store.useFileBodies(t.TempDir() + "/bodies"); err != nil {
					t.Fatal(err)
				}
				intents := map[string][]byte{"alpha": hermeticGeneratorIntent([]byte("first exact intent")), "beta": hermeticGeneratorIntent([]byte("second exact intent"))}
				first := generatedWriterPlanInput(t, s, fixtureID(env.Domain, "missing writer first"), []string{"alpha"}, func(name string) []byte { return intents[name] }, 0, nil)
				s = selectGeneratedWriterBatch(t, env, s, first, "missing writer first", custody.StandardValue)
				s = selectFreshGeneratedWriter(t, store, s, fixtureID(env.Domain, "missing writer carry"), "beta", intents["beta"], 0)
				work := mustSelectedGeneratedWork(t, s)
				old := s.valueEntry(namedSlot(t, s, "alpha"))
				location := work.content.locations[generatedContentKey{contract.GeneratorContentIntent, old.Generated.IntentDigest}]
				facts, err := s.selectedFragmentFactsByRecord()
				if err != nil {
					t.Fatal(err)
				}
				var ref format.Ref
				for _, fact := range facts {
					if fact.blob == location.BlobID {
						ref = fact.ref
						break
					}
				}
				if ref.Object.IsZero() {
					t.Fatal("referenced intent has no physical page")
				}
				key := mustKey(t, store.desc.Prefix, ref)
				damaged := selectedMemoryStoreCopy(store)
				if corrupt {
					read := damaged.Read(t.Context(), key, ref.Length)
					if read.Status != contract.ReadOK || len(read.Body) == 0 {
						t.Fatal("intent damage source missing")
					}
					body := bytes.Clone(read.Body)
					body[len(body)-1] ^= 1
					damaged.put(key, body)
				} else {
					delete(damaged.objects, key)
				}
				private := 0
				engine, err := NewInstalledReconstruction(ReconstructionInstallation{Candidate: candidateProbeForSelected(t, env, s), Normal: &candidateQualifierProbe{}, Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return &constructedReadProbe{store: damaged, descriptor: damaged.Descriptor(), configuration: configuration}, Result{}
				}, Verify: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (ReconstructionVerifier, error) {
					private++
					return env.Custody.ReconstructionVerifier(ctx, pins, deadline)
				}, CloseInstalled: func() {}})
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				creates, cas := damaged.creates, damaged.cas
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				projection, result := engine.Reconstruct(ctx)
				if projection != nil {
					projection.Close()
					t.Fatal("damaged referenced content returned usable projection")
				}
				want := Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}
				if corrupt {
					want = failure(IntegrityFailure, InvalidReference)
				}
				if result != want || private != 0 || damaged.creates != creates || damaged.cas != cas {
					t.Fatal("damaged referenced intent did not refuse before private work or writes", result, private)
				}
			})
		}
	}
}
