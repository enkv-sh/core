package core

import (
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type reconstructionVerifyProbe struct {
	selections []contract.ConsumerSelection
	calls      int
	closes     int
	failAt     int
	failCode   contract.CryptoResultCode
}

// full_only: false
func TestReconstructionVerifyFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    contract.CryptoResultCode
		outcome Outcome
		reason  Reason
	}{
		{"stored authentication", contract.CryptoStoredAuthenticationFailed, IntegrityFailure, InvalidProof},
		{"invalid input", contract.CryptoInvalidInput, AdmissionRefused, InvalidIntent},
		{"invalid admission", contract.CryptoInvalidAdmission, AdmissionRefused, AdmissionInvalid},
		{"private route denied", contract.CryptoPrivateRouteUnavailable, EvidenceUnavailable, CustodyUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := reconstructionVerifyFailure(tc.code)
			if result.Outcome != tc.outcome || result.Reason != tc.reason {
				t.Fatal("Crypto failure was assigned to the wrong trust layer", result)
			}
		})
	}
}

func (p *reconstructionVerifyProbe) Verify(_ context.Context, selection contract.ConsumerSelection) contract.CryptoResultCode {
	p.calls++
	p.selections = append(p.selections, selection)
	if p.calls == p.failAt {
		if p.failCode != 0 {
			return p.failCode
		}
		return contract.CryptoStoredAuthenticationFailed
	}
	return contract.CryptoSuccess
}

func (p *reconstructionVerifyProbe) Close() { p.closes++ }

// full_only: false
func TestCompleteReconstructionVerifiesEverySecretBeforeFinalHEAD(t *testing.T) {
	setup := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, setup, env)
	f := newEnvironmentFixture(t, setup, run.env, []int{1}, false)
	run.suppliedSelection(f, append(f.session.currentEntryInputs(),
		suppliedSecret(t, env, "secret A", "reconstruction private A", custody.StandardValue),
		suppliedSecret(t, env, "secret B", "reconstruction private B", custody.EmptyValue)))
	store := env.Store.(*memoryStore)
	ctx, cancel := context.WithTimeout(setup, time.Minute)
	defer cancel()
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, f.session), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("private test public anchor", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("private test normal read basis", result)
	}
	selected, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || selected.image.root.SecretCount != 2 {
		t.Fatal("private test complete selection", result)
	}
	beforeCreates, beforeCAS := store.creates, store.cas
	beforeReads := source.reads
	var pins contract.ReconstructionVerificationPins
	probe := &reconstructionVerifyProbe{}
	factory := func(factoryCtx context.Context, p contract.ReconstructionVerificationPins, deadline time.Time) (reconstructionVerifier, error) {
		pins = p
		if factoryCtx != ctx {
			t.Fatal("verifier factory did not receive the original invocation context")
		}
		if !deadline.Equal(mustDeadline(t, ctx)) {
			t.Fatal("verifier deadline changed")
		}
		return probe, nil
	}
	result = verifyReconstructionSelection(ctx, &selected, factory)
	if result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure ||
		result.ObservedRevision != selected.basis.anchor.head.Core.Revision ||
		result.ObservedSnapshotID != selected.image.root.Snapshot ||
		probe.calls != 2 || probe.closes != 1 || source.reads != beforeReads+1 ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("incomplete private verification or final HEAD observation", result, probe.calls, probe.closes)
	}
	if pins.DomainID != selected.image.root.Domain || pins.SnapshotID != selected.image.root.Snapshot ||
		pins.HEADRevision != selected.basis.anchor.head.Core.Revision || pins.AccessRoot != selected.image.root.CurrentAccess.AccessRoot ||
		pins.AuthorityRecipientID != selected.authorityID || pins.HEADDigest != contract.Hash(selected.basis.anchor.headBody) ||
		pins.HEADToken != selected.basis.anchor.headToken {
		t.Fatal("private verifier did not receive fresh exact selection pins")
	}
	seen := map[uint16]bool{}
	for _, choice := range probe.selections {
		if choice.Binding.SubjectID != selected.authorityID || !slices.Contains(choice.Entry.Recipients, selected.authorityID) ||
			choice.HEADDigest != pins.HEADDigest || choice.HEADToken != pins.HEADToken ||
			seen[choice.Slot] {
			t.Fatal("selected secret lost authority membership, local pins or unique slot")
		}
		seen[choice.Slot] = true
	}
	for _, tc := range []struct {
		code    contract.CryptoResultCode
		outcome Outcome
		reason  Reason
	}{
		{contract.CryptoInvalidInput, AdmissionRefused, InvalidIntent},
		{contract.CryptoInvalidAdmission, AdmissionRefused, AdmissionInvalid},
		{contract.CryptoStoredAuthenticationFailed, IntegrityFailure, InvalidProof},
		{contract.CryptoPrivateRouteUnavailable, EvidenceUnavailable, CustodyUnavailable},
	} {
		probe = &reconstructionVerifyProbe{failAt: 1, failCode: tc.code}
		beforeReads = source.reads
		result = verifyReconstructionSelection(ctx, &selected, factory)
		if result.Outcome != tc.outcome || result.Reason != tc.reason || probe.calls != 1 ||
			probe.closes != 1 || source.reads != beforeReads {
			t.Fatal("private Crypto refusal reached final HEAD or wrong trust result", tc.code, result)
		}
	}
	probe = &reconstructionVerifyProbe{failAt: 2}
	beforeReads = source.reads
	result = verifyReconstructionSelection(ctx, &selected, factory)
	if result.Outcome != IntegrityFailure || result.Reason != InvalidProof ||
		probe.calls != 2 || probe.closes != 1 || source.reads != beforeReads {
		t.Fatal("failed later secret reached final HEAD or escaped as partial success", result)
	}
	probe = &reconstructionVerifyProbe{}
	source.change = func(_ context.Context, read contract.ReadResult) contract.ReadResult {
		read.Token.Value = "9999"
		return read
	}
	result = verifyReconstructionSelection(ctx, &selected, factory)
	if result.Outcome != Contention || result.Reason != DifferentSelection ||
		probe.calls != 2 || probe.closes != 1 || store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("changed final HEAD token became complete recovery", result)
	}
	probe = &reconstructionVerifyProbe{}
	source.change = func(_ context.Context, read contract.ReadResult) contract.ReadResult {
		read.Body[0] ^= 1
		return read
	}
	result = verifyReconstructionSelection(ctx, &selected, factory)
	if result.Outcome != Contention || result.Reason != DifferentSelection ||
		probe.calls != 2 || probe.closes != 1 {
		t.Fatal("changed final HEAD body became complete recovery", result)
	}
	probe = &reconstructionVerifyProbe{}
	source.change = func(context.Context, contract.ReadResult) contract.ReadResult {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	result = verifyReconstructionSelection(ctx, &selected, factory)
	if result.Outcome != RootLossUnsupported || result.Reason != MissingSelectedObject ||
		probe.calls != 2 || probe.closes != 1 {
		t.Fatal("missing final HEAD became complete recovery", result)
	}
	if result := verifyReconstructionSelection(context.Background(), &selected, factory); result.Outcome == ObservedCurrent {
		t.Fatal("unbounded private reconstruction issued a complete result")
	}
	incomplete := selected
	incomplete.complete = false
	if result := verifyReconstructionSelection(ctx, &incomplete, factory); result.Outcome != AdmissionRefused {
		t.Fatal("unissued selected facts reached a private verifier", result)
	}
	originalDeadline := mustDeadline(t, ctx)
	withValue := context.WithValue(ctx, struct{ telemetry bool }{true}, "local observation")
	if !reconstructionInvocationCurrent(withValue, selected.basis.anchor) ||
		!publicReadInvocationCurrent(withValue, selected.basis.anchor) {
		t.Fatal("same cancellation domain lost its selected private invocation")
	}
	probe = &reconstructionVerifyProbe{}
	earlier, stopEarlier := context.WithDeadline(context.Background(), originalDeadline.Add(-time.Second))
	defer stopEarlier()
	beforeReads = source.reads
	if result := verifyReconstructionSelection(earlier, &selected, factory); result.Outcome != EvidenceUnavailable ||
		probe.calls != 0 || source.reads != beforeReads {
		t.Fatal("unrelated shorter invocation reached private verification", result)
	}
	reopened := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	if _, result := bindPublicReadBasis(earlier, public, reopened); result.Outcome != EvidenceUnavailable || reopened.reads != 0 {
		t.Fatal("unrelated shorter invocation reached normal Store", result)
	}
	if _, result := completePublicSelection(earlier, basis, nil); result.Outcome != EvidenceUnavailable {
		t.Fatal("unrelated shorter invocation reached selected children", result)
	}
	later, stopLater := context.WithDeadline(context.Background(), originalDeadline.Add(time.Minute))
	defer stopLater()
	if result := verifyReconstructionSelection(later, &selected, factory); result.Outcome == ObservedCurrent {
		t.Fatal("private reconstruction renewed the original deadline")
	}
	cancel()
	replacement, stopReplacement := context.WithDeadline(context.Background(), originalDeadline)
	defer stopReplacement()
	if result := verifyReconstructionSelection(replacement, &selected, factory); result.Outcome == ObservedCurrent {
		t.Fatal("private reconstruction ignored original invocation cancellation")
	}
	reopened = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	if _, result := bindPublicReadBasis(replacement, public, reopened); result.Outcome != EvidenceUnavailable || reopened.reads != 0 {
		t.Fatal("cancelled original invocation made another normal HEAD read", result)
	}
	if _, result := completePublicSelection(replacement, basis, nil); result.Outcome != EvidenceUnavailable {
		t.Fatal("cancelled original invocation made another complete selected read", result)
	}
}

func mustDeadline(t *testing.T, ctx context.Context) time.Time {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("private fixture lost its original deadline")
	}
	return deadline
}

// full_only: false
func TestCompleteReconstructionChecksFinalHEADWithNoSecrets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	store := env.Store.(*memoryStore)
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, f.session), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("plain-only public anchor", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("plain-only read basis", result)
	}
	selected, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || selected.image.root.SecretCount != 0 {
		t.Fatal("plain-only complete selection", result)
	}
	probe := &reconstructionVerifyProbe{}
	beforeReads, beforeCreates, beforeCAS := source.reads, store.creates, store.cas
	result = verifyReconstructionSelection(ctx, &selected, func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
		return probe, nil
	})
	if result.Outcome != ObservedCurrent || probe.calls != 0 || probe.closes != 1 ||
		source.reads != beforeReads+1 || store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("plain-only selection skipped final HEAD or caused a forbidden effect", result)
	}
}

// full_only: false
func TestReconstructionVerifierConstructionKeepsOriginalCancellation(t *testing.T) {
	ctx, cancel, selected, store := selectedProjectionFixture(t)
	defer cancel()
	source, ok := selected.basis.reader.source.(*constructedReadProbe)
	if !ok {
		t.Fatal("fixture lost the exact selected reader")
	}
	beforeReads, beforeCreates, beforeCAS := source.reads, store.creates, store.cas
	probe := &reconstructionVerifyProbe{}
	result := verifyReconstructionSelection(ctx, &selected,
		func(factoryCtx context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (reconstructionVerifier, error) {
			if factoryCtx != ctx {
				t.Fatal("constructor received a different cancellation domain")
			}
			cancel()
			return probe, nil
		})
	if result.Outcome != EvidenceUnavailable || result.Reason != CustodyUnavailable ||
		probe.calls != 0 || probe.closes != 1 || source.reads != beforeReads ||
		store.creates != beforeCreates || store.cas != beforeCAS {
		t.Fatal("cancelled construction reached Verify, retained its handle or read HEAD", result)
	}
}

// full_only: false
func TestCompleteReconstructionUsesPrivateVerifyDiscard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	run.suppliedSelection(f, []ApplyEntryInput{
		suppliedSecret(t, env, "selected secret", "private reconstruction source", custody.StandardValue),
	})
	store, signed := signedNonemptyOutputSelection(t, env, f.session)
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, signed), env.Domain,
		&candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("actual private public anchor", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("actual private read basis", result)
	}
	selected, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || selected.image.root.SecretCount != 1 ||
		selected.image.root.OutputConfiguration.BindingCount != 1 {
		t.Fatal("actual private complete selection", result)
	}
	keys.SetDenied(keys.RecoveryID(), true) // The unused recovery KEK is not needed.
	factory := func(factoryCtx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (reconstructionVerifier, error) {
		return keys.ReconstructionVerifier(factoryCtx, pins, deadline)
	}
	publicBefore, privateBefore := keys.Calls()
	creates, cas := store.creates, store.cas
	result = verifyReconstructionSelection(ctx, &selected, factory)
	publicAfter, privateAfter := keys.Calls()
	if result.Outcome != ObservedCurrent || privateAfter != privateBefore+1 || publicAfter != publicBefore ||
		store.creates != creates || store.cas != cas {
		t.Fatal("real private verify/discard failed or sent a forbidden effect", result, publicAfter-publicBefore, privateAfter-privateBefore)
	}
	keys.SetDenied(selected.authorityID, true)
	readBefore := source.reads
	result = verifyReconstructionSelection(ctx, &selected, factory)
	_, deniedCalls := keys.Calls()
	if result.Outcome != EvidenceUnavailable || result.Reason != CustodyUnavailable ||
		deniedCalls != privateAfter+1 || source.reads != readBefore || store.creates != creates || store.cas != cas {
		t.Fatal("required authority KEK denial reached final HEAD or complete result", result)
	}
}

// full_only: false
func TestReconstructionLaterBadSecretReturnsNoProjection(t *testing.T) {
	for _, damage := range []string{"semantic commitment", "AEAD ciphertext"} {
		t.Run(damage, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, t.Context(), env)
			f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
			run.suppliedSelection(f, []ApplyEntryInput{suppliedSecret(t, env, "secret A", "good earlier", custody.StandardValue), suppliedSecret(t, env, "secret B", "bad later", custody.StandardValue)})
			store := env.Store.(*memoryStore)
			state := observeSelectedState(t, f.session)
			slot := namedSlot(t, f.session, "secret B")
			entry := state.Pages[slot/format.PageSlots].Slots[slot%format.PageSlots]
			payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
			if err != nil {
				t.Fatal(err)
			}
			if damage == "semantic commitment" {
				payload.SemanticCommitment[0] ^= 1
			} else {
				payload.Ciphertext[0] ^= 1
			}
			entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			writer := &fixture{store: store, trust: env.Trust.(*fixtureTrust), admission: f.admission, session: f.session}
			storeContractClosure(t, writer, state)
			selected, result := Open(t.Context(), f.admission, store)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("private-damaged signed selection failed public admission", result)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var source *constructedReadProbe
			headReads := 0
			engine, err := NewInstalledReconstruction(ReconstructionInstallation{Candidate: candidateProbeForSelected(t, env, selected), Normal: &candidateQualifierProbe{},
				Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
					source = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration, change: func(_ context.Context, read contract.ReadResult) contract.ReadResult { headReads++; return read }}
					return source, Result{}
				},
				Verify: func(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (ReconstructionVerifier, error) {
					return keys.ReconstructionVerifier(ctx, pins, deadline)
				}, CloseInstalled: func() {}})
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			beforePublic, beforePrivate := keys.Calls()
			creates, cas := store.creates, store.cas
			projection, result := engine.Reconstruct(ctx)
			afterPublic, afterPrivate := keys.Calls()
			if projection != nil {
				projection.Close()
				t.Fatal("later bad private value exposed complete projection")
			}
			if result != (Result{Outcome: IntegrityFailure, Reason: InvalidProof}) || afterPrivate-beforePrivate != 2 || afterPublic != beforePublic || headReads != 1 || source.closes != 1 || store.creates != creates || store.cas != cas {
				t.Fatal("later real private failure reached completion or retained reader", result, afterPrivate-beforePrivate, headReads, source.closes)
			}
		})
	}
}
