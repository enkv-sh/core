package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func gcInterleavingInspection(t *testing.T, selected *StateSession, candidate contract.Store, source PublicSelectedReader) *InstalledInspectionReader {
	t.Helper()
	validator := NewPublicConfigurationValidator(nil)
	reader, err := NewInstalledInspectionReader(InspectionReadInstallation{Candidate: gcInterleavingCandidate{store: candidate},
		Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return source, Result{}
		},
		ExpectedDomain: selected.root.Domain, ExpectedStore: candidate.Descriptor(), PublicBasis: selected.admission.publicBasis(), Validator: validator,
		SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	return reader
}

// full_only: false
func TestGCUnreadSelectionLossKeepsQueryFixedAndRestartsConsumer(t *testing.T) {
	for _, consumer := range []bool{false, true} {
		name := "fixed_query"
		if consumer {
			name = "consumer_restart"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f := newConsumerLoadingFixture(t, ctx, false)
			before := sessionStateImage(t, f.f.session)
			original := f.f.session
			candidate, want := prepareConsumerLoadingSuccessor(t, ctx, f)
			prefix := consumerLoadingPrefix(t, f.store, before)
			store := newGCInterleavingStore(f.store)
			source := &consumerRestartReadStore{memoryStore: f.store}
			entered, returned := 0, 0
			var current *StateSession
			trigger := prefix[0].Key
			source.after = func(_ context.Context, key string, read contract.ReadResult) {
				if key != trigger || entered != 0 {
					return
				}
				entered++
				if read.Status != contract.ReadOK {
					t.Fatal("GC reader cut did not retain its earlier successful read")
				}
				selectConsumerLoadingSuccessor(t, ctx, f, candidate, want)
				plan, encoded := gcInterleavingPreview(t, ctx, f.f.session, store, []string{prefix[2].Key}, name)
				if len(plan.Targets) != 1 {
					t.Fatal("GC reader cut did not select the exact unread obsolete child")
				}
				engine := gcInterleavingEngine(t, f.f.session, store, []string{prefix[2].Key}, f.env.Trust)
				cleaned := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(f.env.Domain, name+" apply"), EncodedPlan: encoded})
				if err := engine.Close(); err != nil {
					t.Fatal("GC reader invocation did not join", err)
				}
				if cleaned.Validate() != nil || cleaned.StateResult != "success" || cleaned.Payload == nil || !cleaned.Payload.Closed || len(store.deleteCalls) != 1 {
					t.Fatal("GC reader cut did not confirm exact absence and close", cleaned.Result)
				}
				current = gcInterleavingCurrent(t, ctx, f.f.admission, store)
				returned++
			}
			t.Cleanup(func() {
				logConsumerLoadingReads(t, source)
				t.Logf("GC reader joins: entered=%d returned=%d deletes=%d", entered, returned, len(store.deleteCalls))
			})
			public, private := f.env.Custody.Calls()
			if consumer {
				image, selected, result := loadPublicConsumerFixture(t, ctx, f.env, f.f.session, f.f.admission.admission.publicBasis(), source, []string{before.Root.Names[0].Name}, original.admission.recipient)
				if !image.complete || selected == nil || result.Outcome != 0 || current == nil || image.basis.anchor.head.Core.Revision != current.head.Core.Revision || !bytes.Equal(image.image.valueEntry(0).ValueBytes, want.Pages[0].Slots[0].ValueBytes) {
					t.Fatal("consumer did not load the current complete image after actual GC", result)
				}
				wantReads := append(append([]processStoreRequest{}, consumerSelectedLoadingPrefix(t, f.store, before)...), publicConsumerReadRequests(t, f.store.desc, sessionStateImage(t, current))...)
				if !reflect.DeepEqual(source.reads, wantReads) || source.statuses[1] != contract.ReadMissing {
					t.Fatal("consumer did not reuse its one authenticated changed HEAD gate")
				}
			} else {
				readOnly := &constructedReadProbe{store: source, descriptor: f.store.desc, configuration: fixtureStoreConfiguration(f.store)}
				reader := gcInterleavingInspection(t, original, store, readOnly)
				result := reader.Inspect(ctx, DomainInspectionRequest{fixtureID(f.env.Domain, "fixed GC query")})
				if result.StateResult != PublicQueryUnavailable || result.View != nil || result.Result.Reason != MissingSelectedObject || result.ValidateMetadataWorkOutput() != nil || readOnly.closes != 1 ||
					!reflect.DeepEqual(source.reads, []processStoreRequest{prefix[0], prefix[2]}) || source.statuses[1] != contract.ReadMissing {
					t.Fatal("fixed query refreshed its image or returned incomplete metadata", result.Result)
				}
			}
			if entered != 1 || returned != 1 || len(store.deleteCalls) != 1 {
				t.Fatal("GC reader effects were not positively joined")
			}
			if p, q := f.env.Custody.Calls(); p != public || q != private {
				t.Fatal("public reader loss entered private custody")
			}
		})
	}
}

// full_only: false
func TestGCLoadedQueryAndConsumerKeepOriginalOwnedObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	env := memoryScenarioEnvironment(t)
	env.Context = ctx
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input := []ApplyEntryInput{suppliedSecret(t, env, "secret", "GC loaded original", custody.StandardValue)}
	run.suppliedSelection(f, input)
	before := f.session
	store := newGCInterleavingStore(env.Store.(*memoryStore))
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: fixtureStoreConfiguration(store)}
	reader := gcInterleavingInspection(t, before, store, source)
	query := reader.Inspect(ctx, DomainInspectionRequest{fixtureID(env.Domain, "loaded GC inspection")})
	if query.View == nil || query.StateResult != PublicQuerySuccess || query.ValidateMetadataWorkOutput() != nil || source.closes != 1 {
		t.Fatal("GC fixture did not load complete query custody", query.Result)
	}
	image, selected, result := loadPublicConsumerFixture(t, ctx, env, f.session, f.admission.admission.publicBasis(), store, []string{"secret"}, before.admission.recipient)
	if !image.complete || selected == nil || result.Outcome != 0 {
		t.Fatal("GC fixture did not load consumer custody", result)
	}
	owned := materializationConsumerRecord(t, selected, 0)
	oldKey := mustKey(t, store.desc.Prefix, *before.root.ValueEntryPages[0])
	input[0] = suppliedSecret(t, env, "secret", "GC loaded successor", custody.EmptyValue)
	run.suppliedSelection(f, input)
	if oldKey == mustKey(t, store.desc.Prefix, *f.session.root.ValueEntryPages[0]) {
		t.Fatal("GC loaded fixture reused the old physical child")
	}
	plan, encoded := gcInterleavingPreview(t, ctx, f.session, store, []string{oldKey}, "loaded GC custody")
	if len(plan.Targets) != 1 {
		t.Fatal("loaded custody incorrectly protected an obsolete child")
	}
	engine := gcInterleavingEngine(t, f.session, store, []string{oldKey}, env.Trust)
	cleaned := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(env.Domain, "loaded GC apply"), EncodedPlan: encoded})
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if cleaned.Validate() != nil || cleaned.StateResult != "success" || len(store.deleteCalls) != 1 {
		t.Fatal("loaded GC did not confirm absence", cleaned.Result)
	}
	store.mu.Lock()
	_, present := store.objects[oldKey]
	store.mu.Unlock()
	reads, creates, cas, signs := store.reads, store.creates, store.cas, env.Trust.(*fixtureTrust).signs
	public, private := env.Custody.Calls()
	check := env.Custody.Consume(ctx, owned, custody.StandardValue)
	if present || check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched ||
		query.ValidateMetadataWorkOutput() != nil || query.View.Observation.HeadRevisionID != before.head.Core.Revision || query.View.Observation.SnapshotID != before.root.Snapshot ||
		store.reads != reads || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
		t.Fatal("loaded custody acquired a lease or lost original owned bytes", check)
	}
	if p, q := env.Custody.Calls(); p != public || q != private+1 {
		t.Fatal("loaded consumer did not join exactly one private open")
	}
}
