package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestReconstructionExportsPortablePublicBasisWithoutSavedTrust(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	store := env.Store.(*memoryStore)
	input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session), normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
		construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}, Result{}
		}, verifier: func(context.Context, contract.ReconstructionVerificationPins, time.Time) (reconstructionVerifier, error) {
			return &reconstructionVerifyProbe{}, nil
		}}
	projection, result := reconstructOwnedCurrent(ctx, input)
	if result.Outcome != ObservedCurrent || projection == nil {
		t.Fatal("complete independent reconstruction", result)
	}
	defer projection.Close()
	if err := projection.CheckPublicBasis(ctx, PublicBasis{}); err == nil {
		t.Fatal("missing saved trust passed normalizer")
	}
	exporter, ok := any(projection).(interface {
		CopyPublicBasis(context.Context) (PublicBasis, error)
	})
	if !ok {
		t.Fatal("committed reconstruction has no portable public basis handoff")
	}
	basis, err := exporter.CopyPublicBasis(ctx)
	if err != nil {
		t.Fatal("committed public basis", err)
	}
	control, err := basis.ControlCore(env.Domain, store.Descriptor())
	expected, valid := f.session.selectedControl()
	if err != nil || !valid || !controlEqual(control, expected) {
		t.Fatal("portable basis lost exact current control", err)
	}
	admitted, res := admitPublicNormal(ctx, env.Domain, store.Descriptor(), basis, store, contract.ID{1}, nil)
	if res.Outcome != ObservedCurrent {
		t.Fatal("ordinary admission from recovered evidence", res)
	}
	opened, res := Open(ctx, admitted, store)
	if opened == nil || res.Outcome != ObservedCurrent {
		t.Fatal("fresh ordinary caller refused recovered evidence", res)
	}
	projection.Close()
	if _, err := exporter.CopyPublicBasis(ctx); err == nil {
		t.Fatal("closed projection exported basis")
	}
	if _, err := basis.ControlCore(env.Domain, store.Descriptor()); err != nil {
		t.Fatal("Close damaged owned evidence", err)
	}
}

func reconstructedBasisFixture(t *testing.T, ctx context.Context, env fixtureEnvironment, selected *StateSession) (*ReconstructionProjection, PublicBasis) {
	t.Helper()
	projection := reconstructProjectionFixture(t, env, selected, env.Store.(*memoryStore))
	basis, err := projection.CopyPublicBasis(ctx)
	if err != nil {
		t.Fatal("export committed observation", err)
	}
	if err := projection.CheckPublicBasis(ctx, basis); err != nil {
		t.Fatal("normalizer refused reconstructed witness", err)
	}
	return projection, basis
}

func assertReconstructedBasisRead(t *testing.T, ctx context.Context, env fixtureEnvironment, selected *StateSession, basis PublicBasis) {
	t.Helper()
	store := env.Store.(*memoryStore)
	public, private := env.Custody.Calls()
	creates, cas := store.creates, store.cas
	engine, _, _ := readerEngineWithPublicBasisFixture(t, env, selected, basis)
	inv := readerInvocationFixture(t, engine, ctx)
	observed, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
	if result.Outcome != 0 || !observed.complete || observed.image.root.Snapshot != selected.root.Snapshot {
		t.Fatal("fresh public read from observation", result)
	}
	inv.Close()
	engine.Close()
	admitted, result2 := admitPublicNormal(ctx, env.Domain, store.Descriptor(), basis, store, selected.admission.composition, nil)
	if result2.Outcome != ObservedCurrent {
		t.Fatal("admit ordinary observation", result2)
	}
	opened, result2 := Open(ctx, admitted, store)
	if opened == nil || result2.Outcome != ObservedCurrent || opened.root.Snapshot != selected.root.Snapshot {
		t.Fatal("ordinary fresh open from observation", result2)
	}
	if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
		t.Fatal("public qualification reached KMS or mutation")
	}
}

// full_only: false
func TestReconstructedObservationAuthenticatesGenesisAndOrdinaryAdvance(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("provider=%d/recovery=%t", family, recovery), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				env, _ := genesisEnvironment(t, family, recovery)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, nil, false)
				if f.session.head.AuthKind != format.GenesisAuth {
					t.Fatal("fixture is not actual genesis")
				}
				projection, basis := reconstructedBasisFixture(t, ctx, env, f.session)
				if len(basis.Descriptor) != 0 || len(basis.Control) != 0 || len(basis.Selection) != 0 || len(basis.Enrollment) != 0 {
					t.Fatal("observation manufactured another basis alternative")
				}
				qualified, reason := qualifyReaderPublicBasis(basis, env.Domain, env.Store.Descriptor())
				if reason != "" || qualified.current != nil || len(qualified.descriptor) != 0 || qualified.observation == nil {
					t.Fatal("observation fabricated a private predecessor", reason)
				}
				assertReconstructedBasisRead(t, ctx, env, f.session, basis)
				projection.Close()
				run.suppliedSelection(f, []ApplyEntryInput{{Name: "later", Recipients: []contract.ID{f.session.admission.recipient},
					ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw,
					OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte("ordinary advance")}})
				if f.session.head.AuthKind != format.LifecycleAuth {
					t.Fatal("ordinary progression fixture changed")
				}
				assertReconstructedBasisRead(t, ctx, env, f.session, basis)
				_, ordinary := reconstructedBasisFixture(t, ctx, env, f.session)
				if head, err := format.DecodeHead(ordinary.HEAD); err != nil || head.AuthKind != format.LifecycleAuth {
					t.Fatal("ordinary observation synthesized genesis or succession", err)
				}
				assertReconstructedBasisRead(t, ctx, env, f.session, ordinary)
			})
		}
	}
}

// full_only: false
func TestReconstructedObservationPinsSuccessionAndPermitsLaterAccess(t *testing.T) {
	for _, approval := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		t.Run(fmt.Sprintf("approval=%d", approval), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			selected, _ := selectReaderSuccessionFixture(t, ctx, env, f.session, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, approval)
			var projection *ReconstructionProjection
			var basis PublicBasis
			if approval == contract.NormalSigningRole {
				projection, basis = reconstructedBasisFixture(t, ctx, env, selected)
			} else {
				store := env.Store.(*memoryStore)
				input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, selected), recovery: &candidateQualifierProbe{}, expectedDomain: env.Domain,
					construct: func(_ context.Context, config contract.StoreConfiguration) (PublicSelectedReader, Result) {
						return &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: config}, Result{}
					},
					verifier: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (reconstructionVerifier, error) {
						return env.Custody.ReconstructionVerifier(ctx, pins, deadline)
					}}
				var result Result
				projection, result = reconstructOwnedCurrent(ctx, input)
				if projection == nil || result.Outcome != ObservedCurrent {
					t.Fatal("recovery-only independent anchor", result)
				}
				defer projection.Close()
				var err error
				basis, err = projection.CopyPublicBasis(ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			anchor, err := contract.DecodePublicSigningBinding(basis.SigningAnchor)
			if err != nil || anchor.Role != approval {
				t.Fatal("export lost successful independently qualified role", err)
			}

			projection.Close()
			assertReconstructedBasisRead(t, ctx, env, selected, basis)
			admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), basis, env.Store, selected.admission.composition, nil)
			if result.Outcome != ObservedCurrent {
				t.Fatal("recovered ordinary predecessor admission", result)
			}
			selected, result = Open(ctx, admitted, env.Store)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("recovered ordinary predecessor open", result)
			}

			reader := fixtureID(env.Domain, "reader")
			binding := keys.RecipientSuccessor(t, reader)
			permit := admitReaderReplacement(t, selected, keys, reader, binding)
			currentSigner := testtrust.NewCurrent(t, currentControlOf(selected).NormalSigning)
			candidate, result := selected.PrepareRecipientReplacement(ctx, permit, currentSigner)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("prepare later ordinary access", result)
			}
			later, result := selected.selectCandidate(ctx, candidate)
			if later == nil || result.Outcome != ObservedCurrent || later.head.AuthKind != format.LifecycleAuth {
				t.Fatal("select later ordinary access", result)
			}
			assertReconstructedBasisRead(t, ctx, env, later, basis)
			future, _ := selectReaderSuccessionFixture(t, ctx, env, later, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, contract.NormalSigningRole)
			engine, _, _ := readerEngineWithPublicBasisFixture(t, env, future, basis)
			inv := readerInvocationFixture(t, engine, ctx)
			observed, failed := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
			if failed.Outcome != EvidenceUnavailable || failed.Reason != SigningUnavailable || observed.complete {
				t.Fatal("future succession selected its own basis", failed)
			}
			inv.Close()
			engine.Close()
			admitted, result = admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), basis, env.Store, selected.admission.composition, nil)
			if result.Outcome != ObservedCurrent {
				t.Fatal(result)
			}
			if opened, result := Open(ctx, admitted, env.Store); opened != nil || result.Outcome != EvidenceUnavailable || result.Reason != SigningUnavailable {
				t.Fatal("ordinary caller accepted unpinned future succession", result)
			}
		})
	}
}

// full_only: false
func TestReconstructedObservationRejectsChangedWitnessAndOwnsCopies(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	projection, basis := reconstructedBasisFixture(t, ctx, env, f.session)
	for _, condition := range []string{"anchor", "anchor-role", "helper", "head", "root", "authority-page", "missing-page", "extra-page", "domain", "coordinate", "prefix"} {
		t.Run(condition, func(t *testing.T) {
			offered, err := basis.OwnedCopy()
			if err != nil {
				t.Fatal(err)
			}
			domain, store := env.Domain, env.Store.Descriptor()
			switch condition {
			case "anchor":
				offered.SigningAnchor[len(offered.SigningAnchor)-1] ^= 1
			case "anchor-role":
				offered.SigningAnchor, err = contract.EncodePublicSigningBinding(f.session.root.CurrentAccess.Core.Recovery.Signing)
			case "helper":
				offered.StoreConfiguration[len(offered.StoreConfiguration)-1] ^= 1
			case "head":
				offered.HEAD[len(offered.HEAD)-1] ^= 1
			case "root":
				offered.Root[len(offered.Root)-1] ^= 1
			case "authority-page":
				offered.RecipientPages[0][len(offered.RecipientPages[0])-1] ^= 1
			case "missing-page":
				offered.RecipientPages = nil
			case "extra-page":
				offered.RecipientPages = append(offered.RecipientPages, bytes.Clone(offered.RecipientPages[0]))
			case "domain":
				domain[0] ^= 1
			case "coordinate":
				store.Coordinate[0] ^= 1
			case "prefix":
				store.Prefix += "other"
				store.HeadKey = store.Prefix + "/HEAD"
			}
			if err != nil {
				t.Fatal("structural changed witness", err)
			}
			if _, err := offered.ControlCore(domain, store); err == nil {
				t.Fatal("changed witness qualified")
			}
			if condition != "domain" && condition != "coordinate" && condition != "prefix" {
				if err := projection.CheckPublicBasis(ctx, offered); err == nil {
					t.Fatal("changed witness passed saved-basis normalizer")
				}
			}
		})
	}
	// Reopen the exact standalone record, then close every prior evidence owner.
	body, err := json.Marshal(localBasisImage{Schema: 3, Kind: "observation", SigningAnchor: basis.SigningAnchor, StoreConfiguration: basis.StoreConfiguration, HEAD: basis.HEAD, Root: basis.Root, RecipientPages: basis.RecipientPages})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := ReadLocalPublicBasis(localAdmissionPath(t, "reconstructed-basis", body))
	if err != nil {
		t.Fatal(err)
	}
	if !sameReplacementBasis(reopened, basis) {
		t.Fatal("standalone reopening changed complete observation")
	}
	cancelledExport, stopExport := context.WithCancel(ctx)
	stopExport()
	if p, err := projection.CopyPublicBasis(cancelledExport); err == nil || !reflect.DeepEqual(p, PublicBasis{}) {
		t.Fatal("cancelled live export returned evidence")
	}
	admitted, result := admitPublicNormal(ctx, env.Domain, env.Store.Descriptor(), basis, env.Store, f.session.admission.composition, nil)
	if result.Outcome != ObservedCurrent || admitted.admission.observation == nil {
		t.Fatal("private admission did not own observation", result)
	}
	retained := admitted.admission.observation
	if &retained.observation.SigningAnchor[0] == &basis.SigningAnchor[0] {
		t.Fatal("external admission borrowed caller-owned evidence")
	}
	basis.clear()
	retainedAnchor := projection.signingAnchor
	projection.Close()
	if len(projection.signingAnchor) != 0 || !bytes.Equal(retainedAnchor, make([]byte, len(retainedAnchor))) {
		t.Fatal("Close retained successful signing evidence")
	}
	if !sameReplacementBasis(*retained.observation, reopened) {
		t.Fatal("private admission lost witness backing")
	}
	opened, result := Open(ctx, admitted, env.Store)
	if opened == nil || result.Outcome != ObservedCurrent || opened.admission.observation != retained {
		t.Fatal("session failed to retain private immutable admission evidence", result)
	}

	assertReconstructedBasisRead(t, ctx, env, f.session, reopened)
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if p, err := projection.CopyPublicBasis(cancelled); err == nil || !reflect.DeepEqual(p, PublicBasis{}) {
		t.Fatal("cancelled export returned evidence")
	}
}

// full_only: false
func TestReconstructedObservationPredecessorDeliversOrdinarySuccessorBasis(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole, 0)
	projection, basis := reconstructedBasisFixture(t, ctx, h.env, h.fixture.session)
	projection.Close()
	h.installation.PublicBasis = basis
	engine := h.engine(t)
	result := engine.Replace(ctx, testID("recovered predecessor replacement"))
	if result.Result.Outcome != ObservedCurrent || h.delivered != 1 || len(h.output.Basis.Control) == 0 || len(h.output.Basis.Selection) == 0 || len(h.output.Basis.SigningAnchor) != 0 {
		t.Fatal("replacement did not deliver ordinary complete successor", result.Result)
	}
	admitted, res := admitPublicNormal(ctx, h.env.Domain, h.env.Store.Descriptor(), h.output.Basis, h.env.Store, h.installation.CompositionID, nil)
	if res.Outcome != ObservedCurrent {
		t.Fatal("successor admission", res)
	}
	selected, res := Open(ctx, admitted, h.env.Store)
	if selected == nil || res.Outcome != ObservedCurrent {
		t.Fatal("successor fresh open", res)
	}
	assertReconstructedBasisRead(t, ctx, h.env, selected, h.output.Basis)
	reader := fixtureID(h.env.Domain, "reader")
	binding := h.keys.RecipientSuccessor(t, reader)
	permit := admitReaderReplacement(t, selected, h.keys, reader, binding)
	signer := h.successor
	currentSigning := currentControlOf(selected).NormalSigning
	if signer == nil || signer.Identity() != currentSigning.Binding.Trust || signer.KeySelector() != currentSigning.KeySelector || !bytes.Equal(signer.PublicKey(), currentSigning.SPKI) {
		t.Fatal("replacement fixture lost exact current signing route")
	}
	candidate, res := selected.PrepareRecipientReplacement(ctx, permit, signer)
	if candidate == nil || res.Outcome != ObservedCurrent {
		t.Fatal("successor later ordinary preparation", res)
	}
	later, res := selected.selectCandidate(ctx, candidate)
	if later == nil || res.Outcome != ObservedCurrent {
		t.Fatal("successor later ordinary selection", res)
	}
	assertReconstructedBasisRead(t, ctx, h.env, later, h.output.Basis)

}

// full_only: false
func TestReconstructedObservationMaterializationRefreshKeepsSavedSuccession(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	selected, _ := selectReaderSuccessionFixture(t, ctx, env, f.session, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
	projection, basis := reconstructedBasisFixture(t, ctx, env, selected)
	projection.Close()
	engine, _, _ := readerEngineWithPublicBasisFixture(t, env, selected, basis)
	request := testID("recovered materialization refresh")
	inv, failed := engine.beginReaderInvocation(ctx, contract.MaterializationOperation, request)
	if inv == nil || failed.Outcome != 0 {
		t.Fatal("materialization admission", failed)
	}
	defer inv.Close()
	previous, failed := inv.loadPublicReadBasis(ctx, contract.MaterializationOperation, request)
	if failed.Outcome != 0 {
		t.Fatal("saved exact succession", failed)
	}
	refreshed, failed := inv.refreshMaterializationBasis(ctx, previous)
	if failed.Outcome != 0 || refreshed.anchor.head.Core != selected.head.Core {
		t.Fatal("refresh lost saved exact succession", failed)
	}
	reader := fixtureID(env.Domain, "reader")
	binding := keys.RecipientSuccessor(t, reader)
	permit := admitReaderReplacement(t, selected, keys, reader, binding)
	signer := testtrust.NewCurrent(t, currentControlOf(selected).NormalSigning)
	candidate, result := selected.PrepareRecipientReplacement(ctx, permit, signer)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	later, result := selected.selectCandidate(ctx, candidate)
	if later == nil || result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	refreshed, failed = inv.refreshMaterializationBasis(ctx, previous)
	if failed.Outcome != 0 || refreshed.anchor.head.Core != later.head.Core {
		t.Fatal("materialization failed later ordinary access advance", failed)
	}
	observed, result := completePublicSelection(ctx, refreshed, nil)
	if result.Outcome != 0 {
		t.Fatal("refreshed complete selection", result)
	}
	observed, failed = inv.finishPublicSelection(ctx, contract.MaterializationOperation, request, observed)
	if failed.Outcome != 0 || !observed.complete || observed.image.root.Snapshot != later.root.Snapshot {
		t.Fatal("materialization refresh rejected fixed-control relation", failed)
	}
}

// full_only: false
func TestReconstructedObservationWaitsForLastSecretAndFinalHEAD(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{suppliedSecret(t, env, "first", "first private", custody.StandardValue), suppliedSecret(t, env, "last", "last private", custody.EmptyValue)})
	store := env.Store.(*memoryStore)
	for _, condition := range []string{"last-secret", "final-head"} {
		t.Run(condition, func(t *testing.T) {
			var verifiers []*reconstructionVerifyProbe
			var readers []*constructedReadProbe
			creates, cas := store.creates, store.cas
			input := reconstructionInputs{candidate: candidateProbeForSelected(t, env, f.session), normal: &candidateQualifierProbe{}, expectedDomain: env.Domain,
				construct: func(_ context.Context, config contract.StoreConfiguration) (PublicSelectedReader, Result) {
					reader := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: config}
					reads := 0
					reader.change = func(_ context.Context, read contract.ReadResult) contract.ReadResult {
						reads++
						if condition == "final-head" && reads == 2 {
							read.Token.Value = "9999"
						}
						return read
					}
					readers = append(readers, reader)
					return reader, Result{}
				}, verifier: func(context.Context, contract.ReconstructionVerificationPins, time.Time) (reconstructionVerifier, error) {
					verifier := &reconstructionVerifyProbe{}
					if condition == "last-secret" {
						verifier.failAt = 2
					}
					verifiers = append(verifiers, verifier)
					return verifier, nil
				}}
			projection, result := reconstructOwnedCurrent(ctx, input)
			wantOutcome, wantReason, attempts := IntegrityFailure, InvalidProof, 1
			if condition == "final-head" {
				wantOutcome, wantReason, attempts = Contention, DifferentSelection, 3
			}
			if projection != nil || result.Outcome != wantOutcome || result.Reason != wantReason || len(verifiers) != attempts || len(readers) != attempts || store.creates != creates || store.cas != cas {
				t.Fatal("incomplete verification released evidence", result)
			}
			for i, verifier := range verifiers {
				if verifier.calls != 2 || verifier.closes != 1 || readers[i].closes != 1 {
					t.Fatal("failed attempt skipped secret or cleanup", i)
				}
			}
			if basis, err := projection.CopyPublicBasis(ctx); err == nil || !reflect.DeepEqual(basis, PublicBasis{}) {
				t.Fatal("failed reconstruction exported basis")
			}
		})
	}
}

// full_only: false
func TestReconstructedObservationReaderSharesOneWitnessAcrossInvocations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	projection, basis := reconstructedBasisFixture(t, ctx, env, f.session)
	projection.Close()
	engine, _, _ := readerEngineWithPublicBasisFixture(t, env, f.session, basis)
	basis.clear()
	backing := engine.publicBasis.SigningAnchor
	closes := 0
	engine.closeInstalled = func() { closes++ }
	first := readerInvocationFixture(t, engine, ctx)
	if first.admission.basis.observation == nil || &first.admission.basis.observation.SigningAnchor[0] != &backing[0] {
		t.Fatal("invocation retained an extra complete witness")
	}
	if _, failed := first.loadPublicSelection(ctx, contract.ReaderCompareOperation, first.admission.request, nil); failed.Outcome != 0 {
		t.Fatal(failed)
	}
	first.Close()
	if bytes.Equal(backing, make([]byte, len(backing))) {
		t.Fatal("invocation cleared engine-owned evidence")
	}
	second := readerInvocationFixture(t, engine, ctx)
	if second.admission.basis.observation == nil || &second.admission.basis.observation.SigningAnchor[0] != &backing[0] {
		t.Fatal("sequential invocation copied or lost witness")
	}
	if _, failed := second.loadPublicSelection(ctx, contract.ReaderCompareOperation, second.admission.request, nil); failed.Outcome != 0 {
		t.Fatal("sequential public invocation refused", failed)
	}
	joined := make(chan struct{})
	go func() { engine.Close(); close(joined) }()
	waitUntil := time.Now().Add(5 * time.Second)
	for {
		engine.mu.Lock()
		closing := engine.closed
		engine.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(waitUntil) {
			t.Fatal("engine Close did not mark closing")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-joined:
		t.Fatal("engine closed before its active invocation")
	case <-time.After(20 * time.Millisecond):
	}
	second.Close()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("engine did not join closed invocation")
	}
	engine.Close()
	if closes != 1 || !bytes.Equal(backing, make([]byte, len(backing))) || !reflect.DeepEqual(engine.publicBasis, PublicBasis{}) {
		t.Fatal("engine did not clear its sole witness once", closes)
	}
}

// full_only: false
func TestReconstructedObservationReceiptAndMaterializationReuseWitness(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	projection, basis := reconstructedBasisFixture(t, ctx, env, f.session)
	projection.Close()
	source := &installedGeneratedReadSource{store: env.Store, configuration: fixtureStoreConfiguration(env.Store)}
	reader, err := NewInstalledReceiptReader(ReceiptReadInstallation{Candidate: source, Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return source, Result{}
	}, ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), PublicBasis: basis, CompositionID: f.session.admission.composition, SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	_, _, inv, failed := reader.begin(ctx, ReceiptListOperation, testID("recovered receipt lifetime"), contract.ID{})
	if inv == nil || failed.Outcome != 0 {
		t.Fatal("receipt admission", failed)
	}
	selected, failed := reader.load(ctx, inv)
	if selected == nil || failed.Outcome != 0 || selected.admission.observation == nil || &selected.admission.observation.observation.SigningAnchor[0] != &reader.reader.publicBasis.SigningAnchor[0] {
		t.Fatal("receipt loading copied the complete witness", failed)
	}
	if _, err := projectReceiptList(selected); err != nil {
		t.Fatal("receipt projection", err)
	}
	inv.Close()
	second := reader.List(ctx, ReceiptListRequest{RequestNonce: testID("recovered receipt next")})
	if second.Payload == nil || second.Result.Outcome != ObservedCurrent {
		t.Fatal("sequential public receipt read", second.Result)
	}
	public, private := env.Custody.Calls()
	admission, result := captureConsumerMaterialization(t, ctx, env, basis, []string{f.session.root.Names[0].Name}, f.session.admission.recipient)
	if admission == nil || result.Payload == nil || result.Validate() != nil || admission.SnapshotID != f.session.root.Snapshot {
		t.Fatal("materialization lost digest-only basis", result.StateResult, result.Failure)
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("public materialization/receipt qualification reached KMS")
	}
}

// full_only: false
func TestReconstructedObservationInstalledOwnersReuseOwnedWitness(t *testing.T) {
	t.Run("administrative", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		env, _ := genesisEnvironment(t, contract.GCP, false)
		f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
		projection, basis := reconstructedBasisFixture(t, ctx, env, f.session)
		projection.Close()
		source := &installedGeneratedReadSource{store: env.Store, configuration: fixtureStoreConfiguration(env.Store)}
		owner, err := NewInstalledAdministrativeReader(AdministrativeReadInstallation{ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), PublicBasis: basis, CompositionID: f.session.admission.composition, SourcePins: installedAdministrativeTestPins(), Source: source, CheckSource: func(context.Context) error { return nil }}, AdministrativeList)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		}()
		basis.clear()
		invocation, finish, _, ok := owner.beginInstalled(ctx, AdministrativeList, testID("observed administrative ownership"), contract.ID{}, contract.ID{}, "")
		if !ok {
			t.Fatal("installed administrative invocation refused")
		}
		defer finish()
		if result := owner.loadInstalled(invocation, AdministrativeList); result.Outcome != ObservedCurrent {
			t.Fatal(result)
		}
		observed := owner.state.admission.observation
		if observed == nil || &observed.observation.SigningAnchor[0] != &owner.installed.basis.SigningAnchor[0] {
			t.Fatal("installed administrative invocation copied its owned witness")
		}
	})
	t.Run("apply", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
		projection, basis := reconstructedBasisFixture(t, ctx, f.env, f.selected)
		projection.Close()
		f.basis = basis
		owner := f.engine(t, f.selected, installedApplyCurrentInput(f.selected), nil)
		basis.clear()
		invocation, ok := owner.beginInstalledGeneratedMutation(ctx, testID("observed apply ownership"), contract.OperationRetireGeneratedGeneration)
		defer invocation.close()
		if !ok || invocation.state == nil {
			t.Fatal("installed apply invocation refused", invocation.out.Result)
		}
		observed := invocation.state.admission.observation
		if observed == nil || &observed.observation.SigningAnchor[0] != &owner.installation.PublicBasis.SigningAnchor[0] {
			t.Fatal("installed apply invocation copied its owned witness")
		}

		joined := make(chan struct{})
		go func() { owner.Close(); close(joined) }()
		until := time.Now().Add(5 * time.Second)
		for {
			owner.mu.Lock()
			closing := owner.closed
			owner.mu.Unlock()
			if closing {
				break
			}
			if time.Now().After(until) {
				t.Fatal("apply Close did not start")
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case <-joined:
			t.Fatal("apply Close released borrowed witness during invocation")
		case <-time.After(20 * time.Millisecond):
		}
		invocation.close()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Fatal("apply Close did not join")
		}
	})
	t.Run("replacement observer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		f := replacementObservationPrepare(t, "recipient")
		projection, basis := reconstructedBasisFixture(t, ctx, f.env, f.before)
		projection.Close()
		input := f.installation
		input.SourceBasis, input.SuccessorBasis = basis, basis
		input.Source = &replacementObservationSource{store: f.env.Store}
		owner, err := NewInstalledReplacementObserver(input)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		}()
		basis.clear()
		if owner.before.observation == nil || owner.after.observation == nil || &owner.before.observation.SigningAnchor[0] != &owner.input.SourceBasis.SigningAnchor[0] || &owner.after.observation.SigningAnchor[0] != &owner.input.SuccessorBasis.SigningAnchor[0] {
			t.Fatal("replacement observer copied its already-owned witnesses")
		}
	})
	t.Run("maintenance observer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		f, delivered, _ := maintenanceObserverFixture(t, ctx, false)
		selected := f.open(t, ctx)
		projection, basis := reconstructedBasisFixture(t, ctx, f.env, selected)
		projection.Close()
		source := &replacementObservationSource{store: f.env.Store}
		input := maintenanceObserverInput(f, delivered, source)
		input.PublicBasis = basis
		owner, err := NewInstalledMaintenanceObserver(input)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := owner.Close(); err != nil {
				t.Error(err)
			}
		}()
		basis.clear()
		state, result := owner.base(ctx)
		if state == nil || result.Outcome != ObservedCurrent {
			t.Fatal("maintenance observer ordinary admission", result)
		}
		observed := state.admission.observation
		if observed == nil || &observed.observation.SigningAnchor[0] != &owner.input.PublicBasis.SigningAnchor[0] {
			t.Fatal("maintenance observer copied its owned witness")
		}
		entered := make(chan struct{})
		source.hook = func(readCtx context.Context, key string) (contract.ReadResult, bool) {
			if key != source.Descriptor().HeadKey {
				return contract.ReadResult{}, false
			}
			close(entered)
			<-readCtx.Done()
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}, true
		}
		returned := make(chan PublicMaintenanceObservationResult, 1)
		go func() { returned <- owner.Observe(ctx, testID("maintenance borrowed close")) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("maintenance observation did not start")
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case result := <-returned:
			if result.Result.Outcome == ObservedCurrent || source.closes.Load() != 1 {
				t.Fatal("maintenance Close returned before failed read cleanup", result.Result)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("maintenance Close did not join")
		}

	})
}

// full_only: false
func TestReconstructedObservationReplacementCallbackCannotChangeBasis(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, contract.NormalSigningRole, ReplacementMaterialAuthority)
	projection, basis := reconstructedBasisFixture(t, ctx, h.env, h.fixture.session)
	projection.Close()
	expected, err := basis.OwnedCopy()
	if err != nil {
		t.Fatal(err)
	}
	h.installation.PublicBasis = basis
	h.publish = func(_ context.Context, out ReplacementSuccessor) (ReplacementReadback, error) {
		control, err := out.Basis.ControlCore(h.env.Domain, h.env.Store.Descriptor())
		if err != nil {
			return ReplacementReadback{}, err
		}
		out.Basis.HEAD[len(out.Basis.HEAD)-1] ^= 1
		return ReplacementReadback{FileIdentity: h.installation.FileIdentity, Control: control, Basis: out.Basis, Recipients: out.Recipients, Correlation: out.Correlation}, nil
	}
	owner := h.engine(t)
	before := h.env.Store.(*memoryStore).cas
	result := owner.Replace(ctx, testID("mutated observation callback"))
	if result.Result.Outcome == ObservedCurrent || h.delivered != 1 || h.env.Store.(*memoryStore).cas != before {
		t.Fatal("callback selected modified observation", result.Result)
	}
	if !sameReplacementBasis(h.installation.PublicBasis, expected) {
		t.Fatal("callback changed independently owned source witness")
	}
}

// full_only: false
func TestReconstructedObservationPublicationCloseJoinsBorrowedBasis(t *testing.T) {
	f, env, input, private, _ := nativePublicationFixture(t, false)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	projection, basis := reconstructedBasisFixture(t, ctx, env, f.session)
	projection.Close()
	admitted, result := admitPublicNormal(ctx, env.Domain, f.store.Descriptor(), basis, f.store, f.session.admission.composition, f.session.admission.outputInterpreter)
	if result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	f.session.admission = *admitted.admission
	owner := installedPublicationEngine(t, f, private)
	basis.clear()
	selected, _, result := owner.installation.current(ctx)
	if selected == nil || result.Outcome != ObservedCurrent || selected.admission.observation == nil || &selected.admission.observation.observation.SigningAnchor[0] != &owner.installation.PublicBasis.SigningAnchor[0] {
		t.Fatal("publication copied installed witness", result)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce, enterOnce sync.Once
	defer func() { cancel(); releaseOnce.Do(func() { close(release) }) }()
	original := owner.installation.Check
	owner.installation.Check = func(ctx context.Context, input PublicationActionCheckInput) (PublicationActionCheckFacts, error) {
		facts, err := original(ctx, input)
		enterOnce.Do(func() { close(entered) })
		<-release
		return facts, err
	}
	closed := make(chan struct{})
	owner.installation.CloseInstalled = func() { close(closed) }
	returned := make(chan PublicPublicationResult, 1)
	go func() {
		returned <- owner.Publish(ctx, testID("publication borrowed close"), PublicationRequest{Names: input.names})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not enter passive check")
	}
	joined := make(chan struct{})
	go func() { owner.Close(); close(joined) }()
	until := time.Now().Add(5 * time.Second)
	for {
		owner.mu.Lock()
		closing := owner.closed
		owner.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(until) {
			t.Fatal("publication Close did not start")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("publication disposed installed evidence during invocation")
	case <-joined:
		t.Fatal("publication Close returned during invocation")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	releaseOnce.Do(func() { close(release) })
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("publication did not return")
	}
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("publication Close did not join")
	}
	select {
	case <-closed:
	default:
		t.Fatal("publication did not dispose joined installation")
	}
}
