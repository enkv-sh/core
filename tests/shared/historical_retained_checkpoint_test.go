package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// These immutable checkpoints were selected by the historical producer named
// in testdata/retained-checkpoints/README.md, before any actual Final attempt.
type historicalRetainedCheckpointCapture struct {
	Checkpoint          processFixture
	PreparedImage       []byte
	CheckpointArtifacts map[string][]byte
	Original            contract.ValueEntry
	OriginalAccess      contract.AccessRecord
	OlderOwners         []contract.ID
	PreparedReaders     []contract.ID
	Mask                uint8
}

// full_only: false
func TestAdministrativeEndWorkChecksNoncurrentCanonicalMeanings(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		t.Run(fmt.Sprintf("distinct=%t", distinct), func(t *testing.T) {
			f, ended := noncurrentRetainedReaderFixture(t, distinct)
			variants := []string{"exact legacy source", "unsupported generated source", "changed Crypto support"}
			if distinct {
				variants = []string{"exact legacy source", "missing Authority", "conflicting retained payload"}
			}
			for _, variant := range variants {
				t.Run(variant, func(t *testing.T) {
					store, ref := retainedReaderSignedCanonical(t, f, variant)
					observed := &retainedReaderObservingStore{memoryStore: store}
					key := mustKey(t, store.desc.Prefix, ref)
					partial, result := openAdministrative(t.Context(), OpenContext{admission: &f.selected.admission}, observed)
					if partial == nil || result.Outcome != ObservedCurrent || len(observed.readsFor(key)) != 0 {
						t.Fatal("partial admission did not omit noncurrent source", result)
					}
					creates, cas := store.creates, store.cas
					candidate, result := prepareTestEndSelectedWork(t, partial, t.Context(), ended, f.env.Trust)
					reads := observed.readsFor(key)
					if len(reads) == 0 || reads[len(reads)-1].status != contract.ReadOK || reads[len(reads)-1].digest != ref.Digest {
						t.Fatal("EndWork did not authenticate the surviving noncurrent source")
					}
					if variant != "exact legacy source" {
						if candidate != nil || result != refused(InvalidRelation) || store.creates != creates || store.cas != cas {
							t.Fatal("EndWork accepted invalid noncurrent source semantics", result)
						}
						return
					}
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("EndWork refused matching noncurrent sources", result)
					}
					next, result := partial.selectCandidate(t.Context(), candidate)
					if next == nil || result.Outcome != ObservedCurrent {
						t.Fatal("select healthy noncurrent sources", result)
					}
					next = retainedReaderColdOpen(t, next, observed)
					if len(mustSelectedGeneratedWork(t, next).canonical) != 1+boolInt(distinct) {
						t.Fatal("EndWork lost a surviving noncurrent source")
					}
				})
			}
		})
	}
}

func noncurrentRetainedReaderFixture(t *testing.T, distinct bool) (retainedReaderFixture, contract.ID) {
	t.Helper()
	var selected *StateSession
	var capture historicalRetainedCheckpointCapture
	if distinct {
		selected, capture, _ = loadHistoricalRetainedCheckpoint(t, "content-surviving-owner")
	} else {
		// Safe replay selects the real generated member used by the
		// unsupported-generated-source semantic mutation below.
		selected, capture = replayHistoricalRetainedCheckpoint(t, "content-surviving-owner")
	}
	env := fixtureEnvironment{Store: selected.store, Trust: memoryCurrentAuthoritySigner(t, selected), Custody: memoryCurrentAuthorityKeys(t, selected), Domain: selected.root.Domain}
	if distinct {
		work := mustSelectedGeneratedWork(t, selected)
		if work.parent == nil || work.parent.OperationID != selected.root.Generated.ActiveOwner {
			t.Fatal("historical fixture requires the selected active parent")
		}
		// End the pending operation before its unsafe Final. EndWork preserves
		// current V1 and the unrelated legacy owner. A later operation can then
		// declare exact CURRENT V1 under its normal source admission contract.
		selected = retainedReaderEndWork(t, selected, work.parent.OperationID, env.Trust)
		selected = retainedReaderColdOpen(t, selected, env.Store)
		_, current := lifecycleEntry(t, selected, capture.Original.Name)
		if !selected.root.Generated.ActiveOwner.IsZero() || !reflect.DeepEqual(*current, capture.Original) {
			t.Fatal("ending the historical parent changed current V1")
		}
		work = mustSelectedGeneratedWork(t, selected)
		if len(work.canonical) != 1 || !sameRetainedEntryValue(work.canonical[capture.Original.ValueState].record.Entry, capture.Original) {
			t.Fatal("ending the historical parent lost the exact legacy source")
		}
		for _, owner := range capture.OlderOwners {
			_, duty := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, owner}]
			_, hazard := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, owner}]
			if !duty && !hazard {
				t.Fatal("ending the historical parent dropped an unrelated older owner")
			}
		}
		sources, canonical := generatedCurrentDeclaration(t, selected)
		var original contract.RetainedCanonicalRecord
		for _, source := range canonical {
			if source.Record.Entry.Name == capture.Original.Name {
				original = source.Record
			}
		}
		if !reflect.DeepEqual(original.Entry, capture.Original) {
			t.Fatal("new failed owner did not declare exact current V1")
		}
		names := []string{"newer-failed"}
		input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" newer"), names, defaultGeneratedFixtureProfile(), sources...)
		selected, _ = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
		selected = retainedReaderColdOpen(t, selected, env.Store)
		newSourceID, err := contract.AdmissionEntryDigest(original)
		if err != nil || newSourceID == capture.Original.ValueState {
			t.Fatal("distinct historical source identity", err)
		}
		shared := make(map[contract.ID]bool)
		for sourceID, source := range mustSelectedGeneratedWork(t, selected).canonical {
			if source.record.Entry.ValueState == capture.Original.ValueState {
				if !sameRetainedEntryValue(source.record.Entry, capture.Original) {
					t.Fatal("same-material sources changed historical value meaning")
				}
				shared[sourceID] = true
			}
		}
		if len(shared) != 2 || !shared[capture.Original.ValueState] || !shared[newSourceID] {
			t.Fatal("fixture requires legacy and AdmissionEntryDigest source IDs for one old material", len(shared))
		}
	}
	apply := slices.DeleteFunc(selected.currentEntryInputs(), func(entry ApplyEntryInput) bool { return entry.Name == "shared" })
	parent := admitSuppliedComparison(t, selected, env.Custody, apply)
	comparison, result := selected.Compare(t.Context(), apply, parent)
	if comparison == nil {
		t.Fatal("remove current value comparison", result)
	}
	candidate, result := selected.Prepare(t.Context(), comparison, admit(t, selected, comparison), env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("remove current value preparation", result)
	}
	selected, result = selected.selectCandidate(t.Context(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("remove current value selection", result)
	}
	env.Custody.RetireApply()
	selected = retainedReaderColdOpen(t, selected, env.Store)
	sources, canonical := generatedCurrentDeclaration(t, selected)
	names := []string{"independent-failed"}
	input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" independent"), names, defaultGeneratedFixtureProfile(), sources...)
	var attempt generatedAttempt
	selected, attempt = selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
	selected = retainedReaderColdOpen(t, selected, env.Store)
	if len(mustSelectedGeneratedWork(t, selected).canonical) != 1+boolInt(distinct) {
		t.Fatal("fixture retained source count")
	}
	for _, named := range selected.root.Names {
		if selected.valueEntry(named.Slot).ValueState == capture.Original.ValueState {
			t.Fatal("retained material is still current")
		}
	}
	var ref format.Ref
	for _, page := range selected.adminIndex.Pages {
		if slices.ContainsFunc(page.Rows, func(row format.AdministrativeRowSummary) bool {
			return row.Kind == contract.RetainedCanonicalSupportKind && row.RecordID == capture.Original.ValueState
		}) {
			ref = page.Ref
		}
	}
	if ref.Object.IsZero() {
		t.Fatal("historical canonical page absent")
	}
	return retainedReaderFixture{env: env, selected: selected, value: capture.Original, retainedRef: ref}, attempt.expected.Template.HazardID
}

// full_only: false
func TestHistoricalRetainedContentCheckpointReplacesUnsafeProtection(t *testing.T) {
	replayHistoricalRetainedCheckpoint(t, "content-surviving-owner")
}

// full_only: false
func TestHistoricalLastMembershipOwnerCheckpointReplacesUnsafeProtection(t *testing.T) {
	replayHistoricalRetainedCheckpoint(t, "membership-last-owner")
}

func readHistoricalRetainedCheckpoint(t *testing.T, name string) (historicalRetainedCheckpointCapture, processFixture) {
	t.Helper()
	path := filepath.Join("tests", "shared", "testdata", "retained-checkpoints", name+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("historical checkpoint evidence", err)
	}
	want := map[string]string{
		"content-surviving-owner": "29075a7c6896260c0a62957a22dd1cc4bf29eeef465974c6d526bb85b4656f2d",
		"membership-last-owner":   "18c33438f815eee0062089ec05f83a3deff5546bb517393f123f4141083b5ef3",
	}[name]
	if want == "" || fmt.Sprintf("%x", contract.Hash(body)) != want {
		t.Fatal("historical checkpoint capture digest changed")
	}
	var capture historicalRetainedCheckpointCapture
	if err := json.Unmarshal(body, &capture); err != nil {
		t.Fatal("historical checkpoint evidence codec", err)
	}
	input := capture.Checkpoint
	expected := input.GeneratedFinalCheckpoint
	if !input.GeneratedFinal || expected == nil || expected.Mode != "reuse" || expected.ImageID.IsZero() || expected.MaterializationPhaseID.IsZero() || len(capture.PreparedImage) == 0 || len(capture.CheckpointArtifacts) == 0 {
		t.Fatal("capture does not contain exact selected immutable preparation")
	}
	for key, want := range capture.CheckpointArtifacts {
		object, ok := input.Objects[key]
		if !ok || !bytes.Equal(object.Body, want) {
			t.Fatal("saved selected immutable checkpoint object changed", key)
		}
	}
	return capture, input
}

// Preserve the historical bytes as archival refusal evidence. The deep checks
// below use a separately built current state and never rewrite those captures.
func loadHistoricalRetainedCheckpoint(t *testing.T, name string) (*StateSession, historicalRetainedCheckpointCapture, processFixture) {
	t.Helper()
	_, original := readHistoricalRetainedCheckpoint(t, name)
	store := &memoryStore{desc: original.Descriptor, configuration: original.Configuration, objects: original.Objects, generation: original.Generation}
	admission := processPublicAdmission(original.Domain, original.Trust, original.Descriptor, original.PublicKey, original.DomainBasis)
	if original.CurrentBasis != nil {
		admission.admission.current, admission.admission.epoch = original.CurrentBasis.owned(), original.Epoch
	}
	if admitted, result := Open(t.Context(), admission, store); admitted != nil || result != refused(AdmissionInvalid) || store.reads != 0 {
		t.Fatal("obsolete captured assembly gained current admission", result)
	}
	return currentUnsafeRetainedCheckpoint(t, name)
}

func replayHistoricalRetainedCheckpoint(t *testing.T, name string) (*StateSession, historicalRetainedCheckpointCapture) {
	t.Helper()
	checkpoint, capture, input := loadHistoricalRetainedCheckpoint(t, name)
	store := requireAdmittedMemoryStore(t, checkpoint.store)
	expected := *input.GeneratedFinalCheckpoint
	expected.Mode = "replace"
	input.GeneratedFinalCheckpoint = &expected
	// The controlled current legacy image stays immutable. The fresh process
	// must select a safe replacement before it can select current values.
	output := checkFreshProcessInput(t, input)
	if output == nil || output.CheckpointHead == nil || len(output.CheckpointObjects) == 0 {
		t.Fatal("unsafe selected preparation was not replaced")
	}
	selected := importFreshGeneratedSelection(t, checkpoint, input.Generation, output)
	_, current := lifecycleEntry(t, selected, "shared")
	assertPublicExclusionProtection(t, capture.Original, *current)
	if len(current.Recipients) != 1 {
		t.Fatal("replacement Final did not establish fresh current protection")
	}
	access, ok := selected.materialAccess(contract.ValueMaterialKind, current.ValueState)
	if !ok || len(access.Wraps) != len(current.Recipients) {
		t.Fatal("new current access relation")
	}
	for i, id := range current.Recipients {
		if access.Wraps[i].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[i].SubjectID != id {
			t.Fatal("new current reader relation")
		}
	}
	oldAccess, oldPresent := selected.materialAccess(contract.ValueMaterialKind, capture.Original.ValueState)
	if oldPresent != (len(capture.OlderOwners) != 0) {
		t.Fatal("old material lifetime")
	}
	if oldPresent && !reflect.DeepEqual(oldAccess, capture.OriginalAccess) {
		t.Fatal("replacement changed required old access")
	}
	for key, want := range capture.CheckpointArtifacts {
		got := store.objects[key]
		if !bytes.Equal(got.Body, want) {
			t.Fatal("replacement overwrote original immutable checkpoint", key)
		}
	}
	keys := memoryCurrentAuthorityKeys(t, selected)
	if check := keys.Consume(t.Context(), sessionConsumerSelection(t, selected, current.Recipients[0], "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("continued current material cannot be consumed", check)
	}
	for _, owner := range capture.OlderOwners {
		consumed := 0
		for _, reader := range capture.Original.Recipients {
			if slices.Contains(current.Recipients, reader) {
				continue
			}
			selection, result := selected.generatedConsumerSelection(t.Context(), contract.GeneratedHazardSupportKind, owner, capture.Original.ValueState, reader)
			if result.Outcome != ObservedCurrent {
				t.Fatal("continued older owner lost its retained-only reader", result)
			}
			bindings, err := selected.currentBindings()
			if err != nil {
				t.Fatal("continued retained reader bindings", err)
			}
			control := currentControlOf(selected)
			var recovery contract.ID
			if control.Recovery != nil {
				recovery = control.Recovery.RoleID
			}
			retainedKeys := custody.NewCurrentConsumer(t, fixtureID(selected.admission.domain, "historical retained reader"), control.AuthorityRecipientID, recovery, bindings, selection.Selection.Binding)
			if check := retainedKeys.ConsumeGenerated(t.Context(), selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 ||
				len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != reader || check.KeyUses[0].BindingID != selection.Selection.Binding.Binding.BindingID {
				t.Fatal("continued older owner cannot consume the exact retained value", check)
			}
			consumed++
		}
		if consumed == 0 {
			t.Fatal("historical surviving-owner capture has no retained-only reader")
		}
	}
	return selected, capture
}

// full_only: false
func TestHistoricalAndCurrentRetainedSourcesSurviveEitherRemovalOrder(t *testing.T) {
	for _, newestFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(newestFirst), func(t *testing.T) {
			selected, capture := replayHistoricalRetainedCheckpoint(t, "content-surviving-owner")
			env := fixtureEnvironment{Store: selected.store, Trust: memoryCurrentAuthoritySigner(t, selected), Custody: memoryCurrentAuthorityKeys(t, selected), Domain: selected.root.Domain}
			originalAccess, _ := selected.materialAccess(contract.ValueMaterialKind, capture.Original.ValueState)
			legacy := mustSelectedGeneratedWork(t, selected)
			old, ok := legacy.canonical[capture.Original.ValueState]
			if !ok || len(legacy.canonical) != 1 {
				t.Fatal("capture lost historical material-keyed source")
			}
			sources, canonical := generatedCurrentDeclaration(t, selected)
			names := []string{"newer-failed"}
			input := generatedPlanInputForGenerations(t, selected, testID(t.Name()+" newer"), names, defaultGeneratedFixtureProfile(), sources...)
			selected, attempt := selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, names, input, canonical)
			selected = retainedReaderColdOpen(t, selected, env.Store)
			work := mustSelectedGeneratedWork(t, selected)
			if len(work.canonical) != 2 || !reflect.DeepEqual(work.canonical[capture.Original.ValueState], old) {
				t.Fatal("new source changed historical source")
			}
			newer := attempt.expected.Template.HazardID
			order := append(slices.Clone(capture.OlderOwners), newer)
			if newestFirst {
				order = append([]contract.ID{newer}, capture.OlderOwners...)
			}
			oldRemaining := len(capture.OlderOwners)
			for _, owner := range order {
				selected = retainedReaderEndWork(t, selected, owner, env.Trust)
				selected = retainedReaderColdOpen(t, selected, env.Store)
				if owner != newer {
					oldRemaining--
				}
				want := capture.Original.Recipients
				access, ok := selected.materialAccess(contract.ValueMaterialKind, capture.Original.ValueState)
				if oldRemaining == 0 {
					if ok {
						t.Fatal("last historical owner retained old material")
					}
					continue
				}
				if !ok || len(access.Wraps) != len(want) {
					t.Fatal("mixed source removal reader count")
				}
				for i, reader := range want {
					original := slices.IndexFunc(originalAccess.Wraps, func(w contract.WrapRow) bool { return w.SubjectID == reader })
					if original < 0 || !reflect.DeepEqual(access.Wraps[i], originalAccess.Wraps[original]) {
						t.Fatal("mixed source removal changed surviving wrap")
					}
				}
				if oldRemaining != 0 && !reflect.DeepEqual(mustSelectedGeneratedWork(t, selected).canonical[capture.Original.ValueState], old) {
					t.Fatal("removal changed surviving historical source")
				}
			}
		})
	}
}

// full_only: false
func TestHistoricalExclusionCannotBecomeNewCheckpointOrLoseAuthority(t *testing.T) {
	for _, name := range []string{"content-surviving-owner", "membership-last-owner"} {
		t.Run(name, func(t *testing.T) {
			checkpoint, _, _ := loadHistoricalRetainedCheckpoint(t, name)
			g := mustSelectedGeneratedWork(t, checkpoint)
			context := generatedPlanInputFixture(t, checkpoint).context
			context.AdmissionID, context.SessionID = testID(t.Name()+" admission"), testID(t.Name()+" session")
			saved, err := checkpoint.generatedFinalRequestWithPreparation(t.Context(), context, true)
			if err != nil || saved.materialization == nil {
				t.Fatal("historical semantic challenge setup", err)
			}
			image, err := checkpoint.generatedFinalPreparationImage(t.Context(), g)
			if err != nil {
				t.Fatal(err)
			}
			defer image.Clear()
			// All rows retain their exact historical phase and framing. Only their
			// eligibility to become a NEW checkpoint differs from read-only admission.
			strict := *saved
			strict.materialization = nil
			store := requireAdmittedMemoryStore(t, checkpoint.store)
			creates, cas := store.creates, store.cas
			if candidate, err := checkpoint.deriveGeneratedFinalPreparation(t.Context(), g, &strict, image.Generated, image.Supplied, image.GrantSeals); err == nil || candidate != nil {
				t.Fatal("old protected removal accepted as new prepared output")
			}
			if store.creates != creates || store.cas != cas {
				t.Fatal("old-protection refusal wrote Store")
			}
			plan, err := checkpoint.generatedFinalRequest(t.Context(), context)
			if err != nil || plan.materialization != nil {
				t.Fatal("known old image did not select safe replacement", err)
			}
			env := fixtureEnvironment{Store: store, Trust: memoryCurrentAuthoritySigner(t, checkpoint), Custody: memoryCurrentAuthorityKeys(t, checkpoint)}
			qualified := &historicalSiblingQualificationCrypto{inner: env.Custody.Crypto()}
			permit := admitPrivateGeneratedFinal(t, env, checkpoint, plan, qualified)
			prepared, result := checkpoint.PrepareGeneratedFinal(t.Context(), permit)
			if prepared == nil || result.Outcome != ObservedCurrent {
				t.Fatal("safe replacement preparation", result)
			}
			if qualified.compares != 1 || qualified.compareCode != contract.CryptoSuccess || qualified.compareOpens != 4 {
				t.Fatal("historical qualification must open seed, both saved rows and exact old source", qualified.compares, qualified.compareCode, qualified.compareOpens)
			}
			subject := prepared.reservation.candidate.head.Generator
			if subject == nil || subject.RequiredAuthoritySet&contract.GeneratorAuthorityExclusion == 0 || prepared.reservation.state.validateGeneratedSelection(t.Context(), nil) != nil {
				t.Fatal("healthy checkpoint lacks exact exclusion authority")
			}
			subject.RequiredAuthoritySet &^= contract.GeneratorAuthorityExclusion
			if _, err := contract.NewGeneratorRequest(*subject); err != nil {
				t.Fatal("missing-exclusion challenge is not a well-formed authority subject", err)
			}
			if prepared.reservation.state.validateGeneratedSelection(t.Context(), nil) == nil {
				t.Fatal("public checkpoint gate accepted missing exclusion authority")
			}
			creates, cas = store.creates, store.cas
			if candidate, result := checkpoint.ClaimGeneratedPreparation(t.Context(), prepared.reservation.candidate, env.Trust); candidate != nil || result.Outcome != AdmissionRefused {
				t.Fatal("checkpoint without exclusion authority reached persistence", result)
			}
			if store.creates != creates || store.cas != cas {
				t.Fatal("missing-exclusion-authority refusal wrote Store")
			}
			env.Custody.RetireGenerated()
		})
	}
}

// full_only: false
func TestHistoricalUnsafeExclusionRejectsMalformedSibling(t *testing.T) {
	checkpoint, _, _ := loadHistoricalRetainedCheckpoint(t, "content-surviving-owner")
	env := fixtureEnvironment{Store: checkpoint.store, Trust: memoryCurrentAuthoritySigner(t, checkpoint), Custody: memoryCurrentAuthorityKeys(t, checkpoint)}
	fixture := finalizationCheckpointFixture{env: env, store: requireAdmittedMemoryStore(t, checkpoint.store)}
	damaged := recommitCheckpointAssociationFixture(t, fixture, checkpoint, "different-prepared-result")
	opened, result := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, damaged)
	if opened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("signed complete-image challenge did not reach reuse classification", result)
	}
	creates, cas := damaged.creates, damaged.cas
	keys := memoryCurrentAuthorityKeys(t, opened)
	public, private := keys.Calls()
	context := generatedPlanInputFixture(t, opened).context
	if plan, err := opened.generatedFinalRequest(t.Context(), context); err == nil || plan != nil {
		t.Fatal("malformed sibling became replacement permission")
	}
	p, k := keys.Calls()
	if opened.prepared || damaged.creates != creates || damaged.cas != cas || p != public || k != private {
		t.Fatal("malformed image reached private work or Store writes")
	}
}

// full_only: false
func TestHistoricalUnsafeExclusionAuthenticatesEverySavedSibling(t *testing.T) {
	for _, damage := range []string{"private-sibling-ciphertext", "private-sibling-authority-wrap"} {
		t.Run(damage, func(t *testing.T) {
			checkpoint, capture, _ := loadHistoricalRetainedCheckpoint(t, "content-surviving-owner")
			env := fixtureEnvironment{Store: checkpoint.store, Trust: memoryCurrentAuthoritySigner(t, checkpoint), Custody: memoryCurrentAuthorityKeys(t, checkpoint)}
			fixture := finalizationCheckpointFixture{env: env, store: requireAdmittedMemoryStore(t, checkpoint.store)}
			store := recommitCheckpointAssociationFixture(t, fixture, checkpoint, damage)
			opened, result := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, store)
			if opened == nil || result.Outcome != ObservedCurrent {
				t.Fatal("signed private-row challenge did not cold-open", result)
			}
			g := mustSelectedGeneratedWork(t, opened)
			image, err := opened.generatedFinalPreparationImage(t.Context(), g)
			if err != nil {
				t.Fatal("private-row challenge lost its exact selected image", err)
			}
			defer image.Clear()
			original, err := contract.DecodeGeneratedFinalPreparationImage(capture.PreparedImage)
			if err != nil {
				t.Fatal("historical source image", err)
			}
			defer original.Clear()
			if len(image.Supplied) == 0 || !reflect.DeepEqual(image.Supplied, original.Supplied) || reflect.DeepEqual(image.Generated, original.Generated) {
				t.Fatal("private sibling challenge changed the legacy row or missed its sibling")
			}
			input := generatedPlanInputFixture(t, opened).context
			input.AdmissionID, input.SessionID = testID(t.Name()+" admission"), testID(t.Name()+" session")
			saved, err := opened.generatedFinalRequestWithPreparation(t.Context(), input, true)
			if err != nil || saved == nil || saved.materialization == nil {
				t.Fatal("private-row challenge did not reach saved-plan classification", err)
			}
			defer saved.clearOwnedInputs()
			legacy, err := opened.generatedFinalPreparationNeedsReplacement(t.Context(), g, saved)
			if err != nil || !legacy {
				t.Fatal("private-row damage failed the required public legacy precondition", legacy, err)
			}
			plan, err := opened.generatedFinalRequest(t.Context(), input)
			if err != nil || plan == nil || plan.materialization != nil {
				t.Fatal("private-row challenge did not reach replacement admission", err)
			}
			defer plan.clearOwnedInputs()
			env = fixtureEnvironment{Store: store, Trust: memoryCurrentAuthoritySigner(t, opened), Custody: memoryCurrentAuthorityKeys(t, opened)}
			observed := &historicalSiblingQualificationCrypto{inner: env.Custody.Crypto()}
			permit := admitPrivateGeneratedFinal(t, env, opened, plan, observed)
			if permit == nil {
				t.Fatal("private-row challenge did not receive actual private admission")
			}
			t.Log("signed image, public legacy classification and private admission succeeded")
			defer env.Custody.RetireGenerated()
			creates, cas := store.creates, store.cas
			prepared, result := opened.PrepareGeneratedFinal(t.Context(), permit)
			if observed.compares != 1 || observed.compareCode != contract.CryptoStoredAuthenticationFailed || prepared != nil || result.Outcome != IntegrityFailure || result.Reason != InvalidProof {
				t.Fatal("privately damaged sibling became replacement permission", observed.compares, observed.compareCode, observed.prepares, prepared != nil, result)
			}
			if observed.prepares != 0 || observed.wraps != 0 || store.creates != creates || store.cas != cas {
				t.Fatal("private-image refusal reached fresh preparation or Store writes", observed.prepares, observed.wraps)
			}
		})
	}
}

type historicalSiblingQualificationCrypto struct {
	inner        contract.Crypto
	compares     int
	compareCode  contract.CryptoResultCode
	compareOpens uint32
	prepares     int
	wraps        uint32
}

func (c *historicalSiblingQualificationCrypto) InstanceID() contract.ID { return c.inner.InstanceID() }

func (c *historicalSiblingQualificationCrypto) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	reply := c.inner.Exchange(ctx, request)
	if request.Kind == contract.CryptoCompare {
		c.compares++
		c.compareCode = reply.ResultCode
	}
	if request.Kind == contract.CryptoPrepare {
		c.prepares++
	}
	for _, row := range reply.KeyUseRows {
		if request.Kind == contract.CryptoCompare && row.Purpose == contract.KeyUseMaterialOpen {
			c.compareOpens += row.Count
		}
		if row.Purpose == contract.KeyUseMaterialWrap {
			c.wraps += row.Count
		}
	}
	return reply
}

// full_only: false
func TestHistoricalExclusionPhaseBudgetKeepsAdministrativeExit(t *testing.T) {
	// These signed local copies change counter/association and public row
	// identities together. They prove request/exit boundaries, not private replay
	// authentication or a historical execution through all counter values.
	for _, name := range []string{"content-surviving-owner", "membership-last-owner"} {
		for _, condition := range []string{"last-two-steps", "last-step", "exhausted"} {
			t.Run(name+"/"+condition, func(t *testing.T) {
				checkpoint, capture, _ := loadHistoricalRetainedCheckpoint(t, name)
				env := fixtureEnvironment{Store: checkpoint.store, Trust: memoryCurrentAuthoritySigner(t, checkpoint), Custody: memoryCurrentAuthorityKeys(t, checkpoint)}
				fixture := finalizationCheckpointFixture{env: env, store: requireAdmittedMemoryStore(t, checkpoint.store)}
				store := recommitCheckpointAssociationFixture(t, fixture, checkpoint, condition)
				opened, result := Open(t.Context(), OpenContext{admission: &checkpoint.admission}, store)
				if opened == nil || result.Outcome != ObservedCurrent {
					t.Fatal("coherent counter association did not reach request admission", result)
				}
				work := mustSelectedGeneratedWork(t, opened)
				want := ^uint32(0)
				if condition == "last-two-steps" {
					want -= 2
				}
				if condition == "last-step" {
					want--
				}
				if work.phase.Phase != want || work.preparation.MaterializationPhase.AfterPhase != want {
					t.Fatal("counter fixture missed its intended boundary")
				}
				context := generatedPlanInputFixture(t, opened).context
				keys := memoryCurrentAuthorityKeys(t, opened)
				pub, priv := keys.Calls()
				creates, cas := store.creates, store.cas
				plan, err := opened.generatedFinalRequest(t.Context(), context)
				if condition == "last-two-steps" {
					if err != nil || plan == nil || plan.materialization != nil || plan.phase.BeforePhase != want || plan.phase.AfterPhase != want+1 {
						t.Fatal("last safe replacement pair refused", err)
					}
				} else if err == nil || plan != nil {
					t.Fatal("unsafe image bypassed finite replacement budget")
				}
				p, k := keys.Calls()
				if opened.prepared || store.creates != creates || store.cas != cas || p != pub || k != priv {
					t.Fatal("counter request entered private work or wrote Store")
				}
				admin, result := openAdministrative(t.Context(), OpenContext{admission: &opened.admission}, store)
				if admin == nil || result.Outcome != ObservedCurrent {
					t.Fatal("counter boundary lost administrative reading", result)
				}
				candidate, result := prepareTestEndSelectedWork(t, admin, t.Context(), work.parent.OperationID, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("counter exhaustion prevented administrative ending", result)
				}
				ended, result := admin.selectCandidate(t.Context(), candidate)
				if ended == nil || result.Outcome != ObservedCurrent {
					t.Fatal("counter-bound administrative selection", result)
				}
				ended = retainedReaderColdOpen(t, ended, store)
				if !ended.root.Generated.ActiveOwner.IsZero() || !sameRetainedEntryValue(*ended.valueEntry(entrySlot(t, ended, "shared")), capture.Original) {
					t.Fatal("administrative ending changed current material or retained the parent")
				}
				remaining := mustSelectedGeneratedWork(t, ended)
				for _, owner := range capture.OlderOwners {
					if _, ok := remaining.records[generatedRecordKey{contract.GeneratedHazardSupportKind, owner}]; !ok {
						t.Fatal("counter-bound ending dropped unrelated old owner")
					}
				}
			})
		}
	}
}
