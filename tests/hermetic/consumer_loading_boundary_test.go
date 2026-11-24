package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type consumerLoadingFixture struct {
	env   fixtureEnvironment
	f     *environmentFixture
	store *memoryStore
}

func newConsumerLoadingFixture(t *testing.T, ctx context.Context, recovery bool) consumerLoadingFixture {
	t.Helper()
	env := memoryScenarioEnvironmentMode(t, recovery)
	env.Context = ctx
	f := newEnvironmentFixture(t, ctx, env, []int{3}, false)
	return consumerLoadingFixture{env: env, f: f, store: env.Store.(*memoryStore)}
}

func prepareConsumerLoadingSuccessor(t *testing.T, ctx context.Context, f consumerLoadingFixture) (*Candidate, stateImage) {
	t.Helper()
	before := sessionStateImage(t, f.f.session)
	input := before.entryInputs()
	input[0].InputBytes = append(bytes.Clone(input[0].InputBytes), 0x7f)
	comparison, result := f.f.session.Compare(ctx, input, admitSuppliedComparison(t, f.f.session, nil, input))
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("consumer successor comparison", result)
	}
	permit := admit(t, f.f.session, comparison)
	want := expectedSuccessorImage(t, before, input, observeAllocatedTransitionInputs(permit))
	candidate, result := f.f.session.Prepare(ctx, comparison, permit, f.env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("consumer successor preparation", result)
	}
	return candidate, want
}

func selectConsumerLoadingSuccessor(t *testing.T, ctx context.Context, f consumerLoadingFixture, candidate *Candidate, want stateImage) {
	t.Helper()
	selected, result := f.f.session.selectObserved(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure {
		t.Fatal("consumer competing writer did not return its complete selection", result)
	}
	assertStateImage(t, selected, want)
	f.f.session = selected
}

func removeConsumerLoadingChild(t *testing.T, store *memoryStore, key string) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, present := store.objects[key]; !present {
		t.Fatal("consumer unread child was already absent")
	}
	delete(store.objects, key)
}

func consumerLoadingPrefix(t *testing.T, store *memoryStore, before stateImage) []processStoreRequest {
	t.Helper()
	return []processStoreRequest{
		{Method: "read", Key: store.desc.HeadKey, Maximum: contract.MaxHeadLength},
		{Method: "read", Key: mustKey(t, store.desc.Prefix, before.RootRef), Maximum: before.RootRef.Length},
		{Method: "read", Key: mustKey(t, store.desc.Prefix, *before.Root.ValueEntryPages[0]), Maximum: before.Root.ValueEntryPages[0].Length},
	}
}

func logConsumerLoadingReads(t *testing.T, source *consumerRestartReadStore) {
	t.Helper()
	for i, read := range source.reads {
		t.Logf("consumer boundary read: ordinal=%d key_digest=%x maximum=%d status=%d", i, contract.Hash([]byte(read.Key)), read.Maximum, source.statuses[i])
	}
}

// Changing s to n-s gives a different canonical DER proof for the same message.
// This separates signed-byte change from a new signed RevisionID.
func consumerSameRevisionHEAD(t *testing.T, s *StateSession) []byte {
	t.Helper()
	head, err := format.DecodeHead(s.body)
	if err != nil {
		t.Fatal("consumer same-revision HEAD", err)
	}
	var signature struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(head.K1, &signature); err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		t.Fatal("consumer binding proof fixture is not DER")
	}
	signature.S = new(big.Int).Sub(elliptic.P256().Params().N, signature.S)
	head.K1, err = asn1.Marshal(signature)
	if err != nil {
		t.Fatal("consumer alternate binding proof", err)
	}
	control, ok := s.admission.currentControl()
	request, err := contract.NewBindingRequest(control.NormalSigning.Binding)
	if !ok || err != nil {
		t.Fatal("consumer binding proof basis", err)
	}
	digest := request.Digest()
	if !ecdsa.VerifyASN1(s.key, digest[:], head.K1) {
		t.Fatal("alternate consumer binding proof does not verify")
	}
	body, err := format.EncodeHead(head)
	if err != nil || bytes.Equal(body, s.body) || head.Core.Revision != s.head.Core.Revision {
		t.Fatal("consumer same-revision fixture did not change only proof bytes", err)
	}
	return body
}

// full_only: false
func TestConsumerSelectionRequiresChangedAuthenticHEADBeforeRestart(t *testing.T) {
	for _, test := range []struct {
		name      string
		advance   bool
		want      Result
		gateReads int
	}{
		{"unchanged", false, failure(EvidenceUnavailable, MissingSelectedObject), 1},
		{"token_only", true, failure(EvidenceUnavailable, MissingSelectedObject), 1},
		{"same_revision_valid_proof_bytes", true, failure(EvidenceUnavailable, MissingSelectedObject), 1},
		{"same_token_changed_body", true, failure(IntegrityFailure, InvalidFormat), 1},
		{"forged_binding_proof", true, failure(IntegrityFailure, InvalidProof), 1},
		{"missing_gate_HEAD", true, failure(RootLossUnsupported, MissingSelectedObject), 1},
		{"access_refused", true, Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonAccess}, 1},
		{"transport_unavailable", true, Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newConsumerLoadingFixture(t, ctx, false)
			before := sessionStateImage(t, f.f.session)
			oldBody, oldToken := bytes.Clone(f.f.session.body), f.f.session.token
			alternateBody := consumerSameRevisionHEAD(t, f.f.session)
			candidate, want := prepareConsumerLoadingSuccessor(t, ctx, f)
			forged, err := format.DecodeHead(candidate.body)
			if err != nil {
				t.Fatal("consumer forged gate fixture", err)
			}
			forged.K1 = bytes.Clone(forged.K1)
			forged.K1[len(forged.K1)-1] ^= 1
			forgedBody, err := format.EncodeHead(forged)
			if err != nil {
				t.Fatal("consumer forged gate encoding", err)
			}
			prefix := consumerLoadingPrefix(t, f.store, before)
			source := &consumerRestartReadStore{memoryStore: f.store}
			writer, entered, returned, heads := false, 0, 0, 0
			f.store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if writer || key != f.store.desc.HeadKey {
					return read
				}
				heads++
				if heads == 1 {
					return read
				}
				switch test.name {
				case "token_only":
					read.Body = bytes.Clone(oldBody)
				case "same_revision_valid_proof_bytes":
					read.Body = bytes.Clone(alternateBody)
				case "same_token_changed_body":
					read.Token = oldToken
				case "forged_binding_proof":
					read.Body = bytes.Clone(forgedBody)
				case "missing_gate_HEAD":
					return contract.ReadResult{Status: contract.ReadMissing}
				case "access_refused":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				case "transport_unavailable":
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				}
				return read
			}
			defer func() { f.store.readHook = nil }()
			source.after = func(_ context.Context, key string, _ contract.ReadResult) {
				if entered != 0 || !consumerLoadingImageCut(source, key, prefix[1].Key, 1) {
					return
				}
				entered++
				if entered != 1 {
					t.Fatal("consumer retried the failed old image")
				}
				if test.advance {
					writer = true
					selectConsumerLoadingSuccessor(t, ctx, f, candidate, want)
					writer = false
				}
				removeConsumerLoadingChild(t, f.store, prefix[2].Key)
				returned++
			}
			creates, cas, signs := f.store.creates, f.store.cas, f.env.Trust.(*fixtureTrust).signs
			public, private := f.env.Custody.Calls()
			t.Cleanup(func() { logConsumerLoadingReads(t, source) })
			image, selected, result := loadPublicConsumerFixture(t, ctx, f.env, f.f.session, f.f.admission.admission.publicBasis(), source, []string{before.Root.Names[0].Name}, f.f.session.admission.recipient)
			if image.complete || selected != nil || result.Result != test.want {
				t.Fatal("consumer gate changed its exact failure or admitted an image", result)
			}
			wantReads := append([]processStoreRequest(nil), consumerSelectedLoadingPrefix(t, f.store, before)...)
			for range test.gateReads {
				wantReads = append(wantReads, processStoreRequest{Method: "read", Key: f.store.desc.HeadKey, Maximum: contract.MaxHeadLength})
			}
			switch test.name {
			case "unchanged", "token_only", "same_revision_valid_proof_bytes":
				wantReads = append(wantReads, processStoreRequest{Method: "read", Key: prefix[1].Key, Maximum: before.RootRef.Length})
			case "forged_binding_proof":
				wantReads = append(wantReads, processStoreRequest{Method: "read", Key: mustKey(t, f.store.desc.Prefix, want.RootRef), Maximum: want.RootRef.Length})
			}
			wantCAS := cas
			if test.advance {
				wantCAS++
			}
			if !reflect.DeepEqual(source.reads, wantReads) || heads != 1+test.gateReads || entered != 1 || returned != 1 ||
				f.store.creates != creates || f.store.cas != wantCAS || f.env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("consumer gate exceeded its exact reads or joined writer effects")
			}
			if gotPublic, gotPrivate := f.env.Custody.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("consumer gate used private custody")
			}
		})
	}
}

// full_only: false
func TestConsumerSelectionCorruptionDoesNotEnterChangedHEADGate(t *testing.T) {
	for _, invalidStatus := range []bool{false, true} {
		name := "wrong_hash"
		want := failure(IntegrityFailure, InvalidReference)
		if invalidStatus {
			name, want = "invalid_read", failure(IntegrityFailure, InvalidFormat)
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newConsumerLoadingFixture(t, ctx, false)
			before := sessionStateImage(t, f.f.session)
			prefix := consumerLoadingPrefix(t, f.store, before)
			f.store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == prefix[2].Key {
					if invalidStatus {
						return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
					}
					read.Body = bytes.Clone(read.Body)
					read.Body[len(read.Body)-1] ^= 1
				}
				return read
			}
			defer func() { f.store.readHook = nil }()
			source := &consumerRestartReadStore{memoryStore: f.store, after: func(context.Context, string, contract.ReadResult) {}}
			creates, cas, signs := f.store.creates, f.store.cas, f.env.Trust.(*fixtureTrust).signs
			t.Cleanup(func() { logConsumerLoadingReads(t, source) })
			image, selected, result := loadPublicConsumerFixture(t, ctx, f.env, f.f.session, f.f.admission.admission.publicBasis(), source, []string{before.Root.Names[0].Name}, f.f.session.admission.recipient)
			if image.complete || selected != nil || result.Result != want || !reflect.DeepEqual(source.reads, consumerSelectedLoadingPrefix(t, f.store, before)) ||
				f.store.creates != creates || f.store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("consumer retried corrupt selected bytes or reached effects", result)
			}
		})
	}
}

// full_only: false
func TestConsumerSelectionHEADProofDiagnosisMissingObjectIsTerminal(t *testing.T) {
	for _, gate := range []bool{false, true} {
		name := "initial_HEAD"
		if gate {
			name = "changed_HEAD_gate"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newConsumerLoadingFixture(t, ctx, true)
			before := sessionStateImage(t, f.f.session)
			prefix := consumerLoadingPrefix(t, f.store, before)
			var candidate *Candidate
			var want stateImage
			damaged := f.f.session.head
			diagnosisRoot := before.RootRef
			if gate {
				candidate, want = prepareConsumerLoadingSuccessor(t, ctx, f)
				damaged = candidate.head
				diagnosisRoot = want.RootRef
			}
			damaged.K3 = bytes.Clone(damaged.K3)
			if len(damaged.K3) == 0 {
				t.Fatal("consumer proof-diagnosis fixture has no Recovery proof")
			}
			damaged.K3[len(damaged.K3)-1] ^= 1
			damagedBody, err := format.EncodeHead(damaged)
			if err != nil {
				t.Fatal("consumer proof-diagnosis encoding", err)
			}
			diagnosisKey := mustKey(t, f.store.desc.Prefix, diagnosisRoot)
			writer, entered, returned, heads := false, 0, 0, 0
			f.store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if writer {
					return read
				}
				if key == f.store.desc.HeadKey {
					heads++
					if !gate || heads > 1 {
						read.Body = bytes.Clone(damagedBody)
					}
				}
				if key == diagnosisKey && (!gate || heads > 1) {
					return contract.ReadResult{Status: contract.ReadMissing}
				}
				return read
			}
			defer func() { f.store.readHook = nil }()
			source := &consumerRestartReadStore{memoryStore: f.store}
			source.after = func(_ context.Context, key string, _ contract.ReadResult) {
				if !gate || entered != 0 || !consumerLoadingImageCut(source, key, prefix[1].Key, 1) {
					return
				}
				entered++
				if entered != 1 {
					t.Fatal("consumer retried proof-diagnosis failure")
				}
				writer = true
				selectConsumerLoadingSuccessor(t, ctx, f, candidate, want)
				writer = false
				removeConsumerLoadingChild(t, f.store, prefix[2].Key)
				returned++
			}
			t.Cleanup(func() { logConsumerLoadingReads(t, source) })
			var image publicSelection
			var selected *contract.MaterializationAdmission
			var result readerFailure
			if gate {
				image, selected, result = loadPublicConsumerFixture(t, ctx, f.env, f.f.session, f.f.admission.admission.publicBasis(), source, []string{before.Root.Names[0].Name}, f.f.session.admission.recipient)
			} else {
				candidate := &installedGeneratedReadSource{store: source, configuration: fixtureStoreConfiguration(source)}
				image, selected, result = loadPublicConsumerCandidateFixture(t, ctx, f.env, f.f.admission.admission.publicBasis(), source, []string{before.Root.Names[0].Name}, f.f.session.admission.recipient, candidate)
			}
			wantReads := []processStoreRequest{{Method: "read", Key: f.store.desc.HeadKey, Maximum: contract.MaxHeadLength}}
			if gate {
				wantReads = append(append([]processStoreRequest(nil), consumerSelectedLoadingPrefix(t, f.store, before)...), wantReads[0])
			}
			wantReads = append(wantReads, processStoreRequest{Method: "read", Key: diagnosisKey, Maximum: diagnosisRoot.Length})
			wantHeads, wantWriters := 1, 0
			if gate {
				wantHeads, wantWriters = 2, 1
			}
			if image.complete || selected != nil || result.Result != failure(EvidenceUnavailable, MissingSelectedObject) ||
				!reflect.DeepEqual(source.reads, wantReads) || heads != wantHeads || entered != wantWriters || returned != wantWriters {
				t.Fatal("consumer treated HEAD proof diagnosis as image loss", result)
			}
		})
	}
}

// full_only: false
func TestMaterializationSelectionBoundsThreeImagesFourObservationsAndPublicHEADCalls(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, family, false)
			env.Context = ctx
			f := consumerLoadingFixture{env: env, f: newEnvironmentFixture(t, ctx, env, []int{3}, false), store: env.Store.(*memoryStore)}
			name, acting := f.f.session.root.Names[0].Name, f.f.session.admission.recipient
			source := &consumerRestartReadStore{memoryStore: f.store}
			deadline, _ := ctx.Deadline()
			entered, returned := 0, 0
			creates, cas, signs := f.store.creates, f.store.cas, f.env.Trust.(*fixtureTrust).signs
			var wantCreates uint64
			var wantReads []processStoreRequest
			source.after = func(readContext context.Context, key string, _ contract.ReadResult) {
				if actual, finite := readContext.Deadline(); !finite || !actual.Equal(deadline) {
					t.Fatal("consumer image attempt renewed its deadline")
				}
				current := sessionStateImage(t, f.f.session)
				if entered == 3 || !consumerLoadingImageCut(source, key, mustKey(t, f.store.desc.Prefix, current.RootRef), 1) {
					return
				}
				entered++
				if entered == 1 {
					wantReads = append(wantReads, consumerSelectedLoadingPrefix(t, f.store, current)...)
				} else {
					wantReads = append(wantReads, consumerLoadingPrefix(t, f.store, current)...)
				}
				candidate, want := prepareConsumerLoadingSuccessor(t, ctx, f)
				created, _ := successorObjectCounts(current, want)
				wantCreates += created
				selectConsumerLoadingSuccessor(t, ctx, f, candidate, want)
				removeConsumerLoadingChild(t, f.store, consumerLoadingPrefix(t, f.store, current)[2].Key)
				returned++
			}
			t.Cleanup(func() { logConsumerLoadingReads(t, source) })
			candidate := candidateProbeForSelected(t, f.env, f.f.session)
			image, selected, result := loadPublicConsumerCandidateFixture(t, ctx, f.env, f.f.admission.admission.publicBasis(), source, []string{name}, acting, candidate)
			wantReads = append(wantReads, processStoreRequest{Method: "read", Key: f.store.desc.HeadKey, Maximum: contract.MaxHeadLength}, processStoreRequest{Method: "read", Key: mustKey(t, f.store.desc.Prefix, f.f.session.head.Core.Root), Maximum: f.f.session.head.Core.Root.Length})
			if image.complete || selected != nil || result.Result != failure(Contention, DifferentSelection) || !reflect.DeepEqual(source.reads, wantReads) ||
				entered != 3 || returned != 3 || f.store.cas != cas+3 || f.env.Trust.(*fixtureTrust).signs != signs+3 || uint64(f.store.creates-creates) != wantCreates {
				t.Fatal("consumer exceeded three images or lost joined writer accounting", result)
			}
			sourceHEADs := 0
			for _, read := range source.reads {
				if read.Key == f.store.desc.HeadKey {
					sourceHEADs++
				}
			}
			candidateHEADs := 0
			for _, call := range candidate.calls {
				if call == "configuration" {
					t.Fatal("ordinary materialization requested the recovery helper")
				}
				if call == "HEAD" || call == "guarded HEAD" {
					candidateHEADs++
				}
			}
			maximum := 5
			if family == contract.AWS {
				maximum = 6
			}
			state, reason := materializationFailureClass(result)
			if sourceHEADs != 4 || candidateHEADs+sourceHEADs != maximum || state != contract.MaterializationUnavailable || reason != contract.MaterializationChangingSelection {
				t.Fatal("public image/HEAD ceiling or legal exhaustion result changed", sourceHEADs, candidateHEADs, state, reason)
			}
		})
	}
}

// The public loader is exercised under its installed independent basis. The
// static candidate's calls are distinct from selected-source HEAD observations.
func loadPublicConsumerFixture(t *testing.T, ctx context.Context, env fixtureEnvironment, selected *StateSession, basis PublicBasis, store contract.Store, names []string, acting contract.ID) (publicSelection, *contract.MaterializationAdmission, readerFailure) {
	t.Helper()
	return loadPublicConsumerCandidateFixture(t, ctx, env, basis, store, names, acting, candidateProbeForSelected(t, env, selected))
}

func loadPublicConsumerCandidateFixture(t *testing.T, ctx context.Context, env fixtureEnvironment, basis PublicBasis, store contract.Store, names []string, acting contract.ID, candidate PublicCandidateReader) (publicSelection, *contract.MaterializationAdmission, readerFailure) {
	t.Helper()
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: fixtureStoreConfiguration(store)}
	reader, err := newInstalledPublicReader(ReaderInstallation{Candidate: candidate, Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return source, Result{}
	}, ExpectedDomain: env.Domain, ExpectedStore: store.Descriptor(), PublicBasis: basis, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	request, err := contract.OwnMaterializationRequest(contract.MaterializationRequest{RequestNonce: fixtureID(env.Domain, "public load request"), Names: names, RecipientID: acting})
	if err != nil {
		return publicSelection{}, nil, readerRefusal(contract.ReasonInvalidInput)
	}
	inv, failed := reader.beginReaderInvocation(ctx, contract.MaterializationOperation, request.RequestNonce)
	if failed.Outcome != 0 {
		return publicSelection{}, nil, failed
	}
	defer inv.Close()
	image, failed := inv.loadMaterializationSelection(ctx, request.RequestNonce, nil)
	if failed.Outcome != 0 {
		return publicSelection{}, nil, failed
	}
	installation := MaterializationInstallation{SourcePins: installedAdministrativeTestPins(), CredentialRoute: fixtureID(env.Domain, "public load route"), Target: contract.MaterializationTarget{Path: "/private/unused-consumer.env", SurfaceID: fixtureID(env.Domain, "public load surface"), Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}}
	admission, _, failed := materializationAdmissionForSelection(ctx, &image, request.RequestNonce, inv.admission.basis.digest, installation, request)
	if failed.Outcome != 0 {
		return publicSelection{}, nil, failed
	}
	return image, &admission, readerFailure{}
}

func assertPublicConsumerImage(t testing.TB, image publicSelection, want stateImage) {
	t.Helper()
	view := &StateSession{root: image.image.root, pages: image.image.pages, recipients: image.image.recipients, access: image.image.access, adminIndex: image.image.adminIndex, head: image.basis.anchor.head, body: image.basis.anchor.headBody}
	for _, page := range image.image.recipients {
		if page != nil {
			for _, row := range page.Slots {
				if row != nil && row.RecipientID == image.authorityID {
					view.recipient = *page
				}
			}
		}
	}
	assertStateImage(t, view, want)
}

func consumerLoadingImageCut(source *consumerRestartReadStore, key, root string, initialHEADs int) bool {
	heads := 0
	for _, read := range source.reads {
		if read.Key == source.desc.HeadKey {
			heads++
		}
	}
	return key == source.desc.HeadKey && heads == initialHEADs || key == root && heads > initialHEADs
}
func consumerSelectedLoadingPrefix(t *testing.T, store *memoryStore, before stateImage) []processStoreRequest {
	prefix := consumerLoadingPrefix(t, store, before)
	return []processStoreRequest{prefix[0], prefix[2]}
}

// full_only: false
func TestMaterializationAdmissionHEADMismatchStopsBeforeSelectedChildren(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, family, false)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			store := env.Store.(*memoryStore)
			candidate := candidateProbeForSelected(t, env, f.session)
			source := &consumerRestartReadStore{memoryStore: store, after: func(context.Context, string, contract.ReadResult) {}}
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == store.desc.HeadKey {
					read.Token.Value = "900"
					if family == contract.AWS {
						read.Token.Value = `"different-token"`
					}
				}
				return read
			}
			defer func() { store.readHook = nil }()
			creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
			image, admission, failed := loadPublicConsumerCandidateFixture(t, ctx, env, f.admission.admission.publicBasis(), source, []string{f.session.root.Names[0].Name}, f.session.admission.recipient, candidate)
			candidateHEADs := 0
			for _, call := range candidate.calls {
				if call == "HEAD" || call == "guarded HEAD" {
					candidateHEADs++
				}
			}
			wantCandidateHEADs := 1
			if family == contract.AWS {
				wantCandidateHEADs = 2
			}
			state, reason := materializationFailureClass(failed)
			if image.complete || admission != nil || failed.Outcome != Contention || state != contract.MaterializationUnavailable || reason != contract.MaterializationChangingSelection || candidateHEADs != wantCandidateHEADs || !reflect.DeepEqual(source.reads, []processStoreRequest{{Method: "read", Key: store.desc.HeadKey, Maximum: contract.MaxHeadLength}}) || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).signs != signs {
				t.Fatal("mismatched public admission reached an image or renewed its budget", failed, candidateHEADs)
			}
		})
	}
}

// Public loading verifies fragment bytes during the physical scan, then reads
// the receipt index once. Its final receipt check reuses validated windows;
// ordinary Open has a third receipt-index pass under its own retention policy.
func publicConsumerReadRequests(t *testing.T, descriptor contract.Descriptor, image stateImage) []processStoreRequest {
	t.Helper()
	if image.Root.Generated.Slices.Count != 0 {
		t.Fatal("consumer fixture has generated logical slices")
	}
	reads := processReadRequests(t, descriptor, image)
	index := processPlainReceiptIndexReadRequests(t, descriptor, image)
	reads = append(reads, index...)
	return append(reads, index...)
}
