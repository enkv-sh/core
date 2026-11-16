package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func readerTypedBasisFixture(t *testing.T, selected *StateSession) PublicBasis {
	t.Helper()
	basis, err := ReadLocalPublicBasis(readerBasisFixture(t, selected))
	if err != nil {
		t.Fatal("typed public fixture basis", err)
	}
	return basis
}

func readerEngineWithPublicBasisFixture(t *testing.T, env fixtureEnvironment, selected *StateSession, basis PublicBasis) (*ReaderEngine, *candidateReadProbe, *constructedReadProbe) {
	t.Helper()
	candidate := candidateProbeForSelected(t, env, selected)
	source := &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(), configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	validator := NewPublicConfigurationValidator(nil)
	engine, err := NewInstalledReader(ReaderInstallation{Candidate: candidate, ExpectedDomain: env.Domain, ExpectedStore: source.descriptor, PublicBasis: basis, Validator: validator, PrepareManifestRenderer: func(context.Context, contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
		return genericjson.Render, ""
	}, Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return source, Result{}
	}, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return engine, candidate, source
}

// full_only: false
func TestReaderCompactAndFragmentedCurrentMeaning(t *testing.T) {
	base, _ := genesisEnvironment(t, contract.GCP, false)
	empty := selectedMemoryStoreCopy(base.Store.(*memoryStore))
	var desired contract.PublicConfiguration
	for _, fragmented := range []bool{false, true} {
		name := "compact"
		if fragmented {
			name = "fragmented"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env := base
			env.Store = selectedMemoryStoreCopy(empty)
			env.Custody = base.Custody.ForkGenerated(t)
			env.Crypto, env.Bindings = env.Custody.Crypto(), env.Custody.Bindings()
			env.AdmitInit, env.RetireInit = env.Custody.AdmitInit, env.Custody.RetireInit
			f := newNamedEnvironmentFixture(t, ctx, env, []int{0, 3, 4096}, fragmented, []string{"", "a/\n雪", "z"})
			defer readerCapacityNoEffects(t, env)()
			pages := 0
			for _, ref := range f.session.root.ValueEntryPages {
				if ref != nil {
					pages++
				}
			}
			wantPages := 1
			if fragmented {
				wantPages = 3
			}
			if pages != wantPages {
				t.Fatal("fixture did not establish physical layout", pages, wantPages)
			}
			e, _, source := readerEngineFixture(t, env, f.session)
			if !fragmented {
				desired = comparisonCurrentInput(t, env, f.session)
			}
			request := contract.Hash([]byte("same compact/fragmented public meaning"))
			readerCapacityComparison(t, e.Compare(ctx, request, desired), f.session, request, nil)
			got := e.Manifest(ctx, contract.ID{8}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"z", "", "a/\n雪"}}))
			doc := readerCapacityManifest(t, got, f.session, f.session.admission.recipient)
			if source.closes != 2 || len(doc.Entries) != 3 {
				t.Fatal("small history did not settle both operations")
			}
			for i, expected := range []struct{ name, base64 string }{{"", ""}, {"a/\n雪", "AQEB"}, {"z", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 4096))}} {
				row := doc.Entries[i]
				entry := f.session.valueEntry(namedSlot(t, f.session, expected.name))
				if row.Name != expected.name || row.Content.Kind != "plain" || row.Content.Plain != expected.base64 || row.Incarnation != hex.EncodeToString(entry.Incarnation[:]) || row.Content.Destinations != nil {
					t.Fatal("physical layout changed exact manifest bytes or mapping", i)
				}
			}
		})
	}
}

// full_only: false
func TestReaderCurrentIntentLateFragmentLoss(t *testing.T) {
	env, f, _ := configuredSuccessionMemoryFixture(t, false)
	input := readerCapacityInput(t, env, f.session, capacityOutputConfiguration(t, f.session, false))
	defer readerCapacityNoEffects(t, env)()
	readerHistoryMissingCurrentIntent(t, env, f.session, input)
}

func readerHistoryMissingCurrentIntent(t *testing.T, env fixtureEnvironment, selected *StateSession, input contract.PublicConfiguration) {
	t.Helper()
	content, err := newGeneratedContent(selected)
	if err != nil {
		t.Fatal(err)
	}
	var generated *contract.ValueEntry
	for _, named := range selected.root.Names {
		if entry := selected.valueEntry(named.Slot); entry.ValueSource == contract.Generated {
			generated = entry
		}
	}
	location, ok := content.locations[generatedContentKey{contract.GeneratorContentIntent, generated.Generated.IntentDigest}]
	fragments := content.fragmentLocations[location.BlobID]
	if !ok || len(fragments) != 1 {
		t.Fatal("exact current intent location", ok, len(fragments))
	}
	fact, ok := selected.fragmentFacts[fragments[0]]
	if !ok {
		t.Fatal("current intent fragment has no authenticated ref")
	}
	key := readerFixtureKey(t, env.Store.Descriptor().Prefix, fact.ref)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	e, _, source := readerEngineFixture(t, env, selected)
	e.validator = readerCapacityValidator(t, selected)
	baseline := &comparisonReadGate{PublicSelectedReader: source, key: key}
	e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return baseline, Result{}
	}
	if got := e.Compare(ctx, contract.ID{9}, input); got.Verdict != contract.ComparisonMatch || baseline.reads < 2 {
		t.Fatal("current intent reread baseline", got, baseline.reads)
	}
	t.Run("late-missing-current-intent-fragment", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		e, _, source := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		gate := &comparisonReadGate{PublicSelectedReader: source, key: key, failAt: baseline.reads, kind: "missing"}
		e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return gate, Result{}
		}
		desired := input
		desired.Recipients.Value = slices.Clone(input.Recipients.Value)
		desired.Recipients.Value[0].DisplayName = publicPresent("untrusted provisional difference")
		got := e.Compare(ctx, contract.ID{10}, desired)
		want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedObjectUnavailable}}
		if got.Verdict != contract.ComparisonUnable || got.StateResult != contract.ReaderUnavailable || got.Observation == nil || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, want) || gate.reads != baseline.reads || source.closes != 1 || e.activeDone != nil {
			t.Fatal("late fragment loss mixed selections or retained differences", got, gate.reads)
		}
		readerCapacityScope(t, got.CheckedScope, contract.ScopeUnchecked)
	})
}

// full_only: false
func TestReaderCallableOperationsAfterSignerAndRecipientReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newNamedEnvironmentFixture(t, ctx, run.env, []int{2}, false, []string{"replacement plain"})
	target := fixtureID(env.Domain, "reader")
	entries := f.session.currentEntryInputs()
	entries[0].Recipients = []contract.ID{f.session.admission.recipient, target}
	slices.SortFunc(entries[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run.suppliedSelection(f, entries)
	beforeReplacement, err := f.session.receiptWindows(ctx)
	if err != nil || len(beforeReplacement.Order) == 0 {
		t.Fatal("replacement history has no selected receipt", err)
	}
	oldOperation := beforeReplacement.Order[len(beforeReplacement.Order)-1]
	oldReceipt, oldResult := f.session.MutationReceipt(ctx, oldOperation)
	if oldResult.Outcome != ObservedCurrent {
		t.Fatal("original receipt is unavailable before replacement", oldResult)
	}
	env = syntheticAuthorityScenarioEnvironment(t, env)
	successor, _ := selectReaderSuccessionFixture(t, ctx, env, f.session, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
	basis := readerTypedBasisFixture(t, successor)
	binding := keys.RecipientSuccessor(t, target)
	permit := admitReaderReplacement(t, successor, keys, target, binding)
	currentSigner := testtrust.NewCurrent(t, currentControlOf(successor).NormalSigning)
	candidate, result := successor.PrepareRecipientReplacement(ctx, permit, currentSigner)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("replacement setup", result)
	}
	later, result := successor.selectCandidate(ctx, candidate)
	if later == nil || result.Outcome != ObservedCurrent || later.head.AuthKind == format.SuccessionAuth || later.recipientRecord(target).CurrentBinding.BindingID != binding.BindingID {
		t.Fatal("replacement selection", result)
	}
	defer readerCapacityNoEffects(t, env)()
	signs, qualification := currentSigner.Calls(), currentSigner.QualificationCalls()
	e, _, source := readerEngineWithPublicBasisFixture(t, env, later, basis)
	input := comparisonCurrentInput(t, env, later)
	request := contract.ID{11}
	readerCapacityComparison(t, e.Compare(ctx, request, input), later, request, nil)
	got := e.Manifest(ctx, contract.ID{12}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"replacement plain"}}))
	doc := readerCapacityManifest(t, got, later, target)
	if len(doc.Entries) != 1 || doc.Entries[0].Name != "replacement plain" || doc.Entries[0].Content.Kind != "plain" || doc.Entries[0].Content.Plain != "AAA=" || source.closes != 2 || currentSigner.Calls() != signs || currentSigner.QualificationCalls() != qualification {
		t.Fatal("replacement Reader reached a key or lost requested mapping")
	}
	receipts, receiptSource := installedReceiptFixture(t, installedApplyTestFixture{env: env, basis: basis, composition: later.admission.composition})
	detail := receipts.Detail(ctx, ReceiptDetailRequest{RequestNonce: contract.ID{15}, OperationID: oldOperation})
	if detail.StateResult != PublicQuerySuccess || detail.Payload == nil || !bytes.Equal(detail.Payload.EncodedReceipt, oldReceipt) || detail.Payload.Observation.HeadRevisionID != later.head.Core.Revision || detail.Validate() != nil || receiptSource.closes != 1 || currentSigner.Calls() != signs || currentSigner.QualificationCalls() != qualification {
		t.Fatal("current public basis lost exact old receipt after signer and Recipient replacement", detail.StateResult, detail.FailureReason)
	}
}

// full_only: false
func TestReaderManifestDuringActiveGeneratedWork(t *testing.T) {
	a := newGeneratedResultFixture(t, contract.GeneratedRetirementManual, false)
	if a.f.session.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("fixture lacks active generated work")
	}
	defer readerCapacityNoEffects(t, a.env)()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	e, _, source := readerEngineFixture(t, a.env, a.f.session)
	request := contract.ID{13}
	readerCapacityComparison(t, e.Compare(ctx, request, comparisonCurrentInput(t, a.env, a.f.session)), a.f.session, request, nil)
	names := make([]string, len(a.f.session.root.Names))
	for i, named := range a.f.session.root.Names {
		names[i] = named.Name
	}
	got := e.Manifest(ctx, contract.ID{14}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: a.f.session.admission.recipient, EntryNames: names}))
	doc := readerCapacityManifest(t, got, a.f.session, a.f.session.admission.recipient)
	if len(doc.Entries) != len(names) || source.closes != 2 {
		t.Fatal("active generated work changed current entry selection")
	}
}

// full_only: false
func TestReaderCallableOperationsWithSelectedOutputHistory(t *testing.T) {
	for _, kind := range []uint8{format.OutputReserveAuth, format.OutputCloseAuth} {
		name := "reservation"
		if kind == format.OutputCloseAuth {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			env, f, coordinate, marker := signedPublicationSelectionFixture(t, kind, true)
			if coordinate.OwnerState != contract.PublicationOwnerUncertainCreate || marker.AttemptID.IsZero() || len(f.session.adminIndex.PublicationOrder) != 1 || f.session.head.AuthKind != kind {
				t.Fatal("fixture lacks selected output history")
			}
			defer readerCapacityNoEffects(t, env)()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			e, _, source := readerEngineFixture(t, env, f.session)
			request := contract.ID{15}
			readerCapacityComparison(t, e.Compare(ctx, request, comparisonCurrentInput(t, env, f.session)), f.session, request, nil)
			got := e.Manifest(ctx, contract.ID{16}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: f.session.admission.recipient, EntryNames: []string{"member-000"}}))
			doc := readerCapacityManifest(t, got, f.session, f.session.admission.recipient)
			entry := f.session.valueEntry(namedSlot(t, f.session, "member-000"))
			if len(doc.Entries) != 1 || doc.Entries[0].Name != "member-000" || doc.Entries[0].Incarnation != hex.EncodeToString(entry.Incarnation[:]) || doc.Entries[0].Content.Kind != "plain" || doc.Entries[0].Content.Plain != "AA==" || source.closes != 2 || e.activeDone != nil {
				t.Fatal("selected output history changed callable public meaning")
			}
		})
	}
}
