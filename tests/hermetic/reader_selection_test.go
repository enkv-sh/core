package core

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func readerBasisFixture(t *testing.T, selected *StateSession) string {
	t.Helper()
	image := localBasisImage{Schema: 3, Kind: "genesis", Descriptor: selected.admission.descriptor}
	if selected.admission.current != nil {
		var err error
		image, err = testSuccessorPublicBasisImage(selected.admission.current)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	return localAdmissionPath(t, "basis.json", body)
}

func readerEngineFixture(t *testing.T, env fixtureEnvironment, selected *StateSession) (*ReaderEngine, *candidateReadProbe, *constructedReadProbe) {
	t.Helper()
	return readerEngineWithPublicBasisFixture(t, env, selected, readerTypedBasisFixture(t, selected))
}

func readerInvocationFixture(t *testing.T, e *ReaderEngine, ctx context.Context) *readerInvocation {
	t.Helper()
	inv, r := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("complete public request")))
	if r.Outcome != 0 || inv == nil {
		t.Fatal("native Reader admission", r)
	}
	t.Cleanup(inv.Close)
	return inv
}

// full_only: false
func TestReaderAuthenticatesIndependentGenesisWithoutEnrollment(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			name := fmt.Sprint(family)
			if recovery {
				name += " recovery"
			}
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				env, _ := genesisEnvironment(t, family, recovery)
				f := newEnvironmentFixture(t, ctx, env, nil, false)
				e, candidate, source := readerEngineFixture(t, env, f.session)
				candidate.configuration = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				inv := readerInvocationFixture(t, e, ctx)
				store := env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				selected, r := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
				if r.Outcome != 0 || !selected.complete || selected.image.root.Snapshot != f.session.root.Snapshot {
					t.Fatal("complete public genesis", r)
				}
				if !selected.authorityID.IsZero() && selectedRecipientRecord(&selected.image.recipients, selected.authorityID) == nil {
					t.Fatal("selected authority enrollment absent")
				}
				if store.creates != creates || store.cas != cas {
					t.Fatal("Reader wrote state")
				}
				inv.Close()
				if source.closes != 1 || slices.Contains(candidate.calls, "configuration") {
					t.Fatal("ordinary read used the recovery helper or failed to close", candidate.calls, source.closes)
				}
			})
		}
	}
}

// full_only: false
func TestOrdinaryReaderRequiresTheExactLocalStoreSettings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.AWS, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	for _, owner := range []string{"", "111111111111"} {
		e, candidate, source := readerEngineFixture(t, env, f.session)
		if owner == candidate.location.ExpectedOwner {
			t.Fatal("expected a different AWS account")
		}
		candidate.location.ExpectedOwner = owner
		inv := readerInvocationFixture(t, e, ctx)
		_, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
		inv.Close()
		if result.Outcome == 0 || result.diagnostic != contract.ReasonStoreBasisInvalid || slices.Contains(candidate.calls, "configuration") || source.reads != 0 {
			t.Fatal("ordinary read accepted incomplete or different local ownership", result, candidate.calls)
		}
	}
}

// full_only: false
func TestReaderAdmissionRejectsForgedChangedAndExpiredContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	for _, name := range []string{"forged", "interpretation", "operation", "request", "expired", "cancelled", "closed"} {
		t.Run(name, func(t *testing.T) {
			e, candidate, _ := readerEngineFixture(t, env, f.session)
			inv := readerInvocationFixture(t, e, ctx)
			operation, request := contract.ReaderCompareOperation, inv.admission.request
			readctx := ctx
			switch name {
			case "forged":
				inv.admission.issued = false
			case "interpretation":
				inv.admission.interpretation[0] ^= 1
			case "operation":
				operation = contract.ReaderManifestOperation
			case "request":
				request[0] ^= 1
			case "expired":
				inv.admission.deadline = time.Now().Add(-time.Second)
			case "cancelled":
				var stop context.CancelFunc
				readctx, stop = context.WithCancel(ctx)
				stop()
			case "closed":
				inv.Close()
			}
			image, r := inv.loadPublicSelection(readctx, operation, request, nil)
			if r.Outcome == 0 || image.complete || len(candidate.calls) != 0 {
				t.Fatal("invalid admission reached public GET", r, candidate.calls)
			}
		})
	}
	e, _, _ := readerEngineFixture(t, env, f.session)
	e.Close()
	if inv, r := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("request"))); inv != nil || r.Outcome == 0 {
		t.Fatal("closed Reader admitted invocation", r)
	}
	if inv, r := e.beginReaderInvocation(context.Background(), contract.ReaderCompareOperation, contract.Hash([]byte("request"))); inv != nil || r.Outcome == 0 {
		t.Fatal("unbounded Reader admitted", r)
	}
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	e, probe, _ := readerEngineFixture(t, env, f.session)
	if inv, result := e.beginReaderInvocation(expired, contract.ReaderCompareOperation, contract.Hash([]byte("expired request"))); inv != nil || result.Outcome != AdmissionRefused || result.diagnostic != contract.ReasonExpired || len(probe.calls) != 0 {
		t.Fatal("expired native context reached reads or lost its exact reason", result)
	}

}

// full_only: false
func TestReaderSelectionRejectsWrongBasisAndIncompleteClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	for _, name := range []string{"domain", "location", "key", "proof", "selected bytes", "root missing", "child missing", "output slice missing", "construction"} {
		t.Run(name, func(t *testing.T) {
			e, candidate, source := readerEngineFixture(t, env, f.session)
			switch name {
			case "domain":
				e.expectedDomain[0] ^= 1
			case "location":
				candidate.location.Bucket += "-other"
			case "key":
				basis := readerTypedBasisFixture(t, f.session)
				d, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
				if err != nil {
					t.Fatal(err)
				}
				other := testtrust.NewWithIdentity(t, contract.GCP, fixtureID(env.Domain, "other public signing key"), d.TrustID, contract.NormalSigningRole)
				d.NormalSigning.SPKI = other.PublicKey()
				d.NormalSigning.KeySelector = other.KeySelector()
				d.NormalSigning.Fingerprint = contract.Hash(d.NormalSigning.SPKI)
				d.NormalSigning.Binding.PublicKey = d.NormalSigning.Fingerprint
				encoded, err := contract.EncodeGenesisDescriptorCore(d)
				if err != nil {
					t.Fatal(err)
				}
				basis.Descriptor = encoded
				e.Close()
				e, _, _ = readerEngineWithPublicBasisFixture(t, env, f.session, basis)
			case "proof":
				candidate.head.Body = append([]byte(nil), candidate.head.Body...)
				candidate.head.Body[len(candidate.head.Body)-1] ^= 1
			case "selected bytes":
				candidate.root.Body = append([]byte(nil), candidate.root.Body...)
				candidate.root.Body[len(candidate.root.Body)-1] ^= 1
			case "root missing":
				candidate.root = contract.ReadResult{Status: contract.ReadMissing}
			case "child missing":
				source.missingKey = readerFixtureKey(t, source.descriptor.Prefix, *f.session.root.Recipients[0])
			case "output slice missing":
				refs := capacityConfigurationSelectedRefs(t, f.session)
				source.missingKey = readerFixtureKey(t, source.descriptor.Prefix, refs[len(refs)-1])
			case "construction":
				source.configuration.DomainID[0] ^= 1
			}
			inv, r := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("request")))
			if name == "key" && r.Outcome != 0 {
				t.Fatal("valid independent alternative key failed before Store authentication", r)
			}
			if inv != nil {
				defer inv.Close()
			}
			if r.Outcome == 0 {
				image, read := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
				if read.Outcome == 0 || image.complete {
					t.Fatal("bad independent/selected evidence authenticated", name, read)
				}
			}
		})
	}
}

func readerFixtureKey(t *testing.T, prefix string, ref contract.Ref) string {
	t.Helper()
	key, err := format.Key(prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type readerCancellingCandidate struct {
	PublicCandidateReader
	cancel context.CancelFunc
}

func (c readerCancellingCandidate) ReadHEAD(ctx context.Context) contract.ReadResult {
	read := c.PublicCandidateReader.ReadHEAD(ctx)
	c.cancel()
	return read
}

// full_only: false
func TestReaderReadFailuresKeepExactSafeReasons(t *testing.T) {
	for _, name := range []string{"head", "domain", "root", "candidate cancellation", "selected cancellation"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			e, candidate, _ := readerEngineFixture(t, env, f.session)
			want := contract.ReasonSelectedObjectInvalid
			switch name {
			case "head":
				candidate.head.Body = []byte("malformed HEAD")
				want = contract.ReasonHeadInvalid
			case "domain":
				// The independently expected domain is distinct from this valid
				// signed HEAD; its original trust input remains independent.
				e.expectedDomain[0] ^= 1
				basis := readerTypedBasisFixture(t, f.session)
				d, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
				if err != nil {
					t.Fatal(err)
				}
				d.DomainID = e.expectedDomain
				d.NormalSigning.Binding.Domain = e.expectedDomain
				encoded, err := contract.EncodeGenesisDescriptorCore(d)
				if err != nil {
					t.Fatal(err)
				}
				basis.Descriptor = encoded
				expected := e.expectedDomain
				e.Close()
				otherEnv := env
				otherEnv.Domain = expected
				e, _, _ = readerEngineWithPublicBasisFixture(t, otherEnv, f.session, basis)
				want = contract.ReasonDomainBasisInvalid
			case "root":
				candidate.root.Body = append([]byte(nil), candidate.root.Body...)
				candidate.root.Body[len(candidate.root.Body)-1] ^= 1
			case "candidate cancellation":
				e.candidate = readerCancellingCandidate{PublicCandidateReader: candidate, cancel: cancel}
				want = contract.ReasonCancelled
			case "selected cancellation":
				store := env.Store.(*memoryStore)
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if key != store.desc.HeadKey {
						cancel()
					}
					return read
				}
				defer func() { store.readHook = nil }()
				want = contract.ReasonCancelled
			}
			inv, result := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("exact safe failure request")))
			if result.Outcome != 0 {
				t.Fatal("test admission failed before selected read", result)
			}
			defer inv.Close()
			observed, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
			if result.Outcome == 0 || result.diagnostic != want || observed.complete {
				t.Fatal("wrong safe reason or authenticated claim", result, want)
			}
			if want == contract.ReasonCancelled && result.Outcome != AdmissionRefused {
				t.Fatal("cancelled read became unavailable-only", result)
			}
		})
	}
}

// full_only: false
func TestReaderRejectsLateAuthenticatedPublicRelation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	state := sessionStateImage(t, f.session)
	foreign, _ := genesisEnvironment(t, contract.AWS, false)
	changed := false
	for _, row := range state.Recipient.Slots {
		if row != nil && row.RecipientID != f.session.root.CurrentAccess.Core.AuthorityRecipientID {
			binding := foreign.Bindings[1].Binding
			row.CurrentBinding = &binding
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("fixture lacks an unused Recipient")
	}
	store := env.Store.(*memoryStore)
	writer := &fixture{store: store, trust: env.Trust.(*fixtureTrust), admission: f.admission, session: f.session}
	storeContractClosure(t, writer, state)
	selected := *f.session
	selected.body = store.objects[store.desc.HeadKey].Body
	selected.token = store.objects[store.desc.HeadKey].Token
	var err error
	selected.head, err = format.DecodeHead(selected.body)
	if err != nil {
		t.Fatal(err)
	}
	selected.root, err = format.DecodeRoot(store.objects[readerFixtureKey(t, store.desc.Prefix, selected.head.Core.Root)].Body)
	if err != nil {
		t.Fatal(err)
	}
	e, _, source := readerEngineFixture(t, env, &selected)
	inv := readerInvocationFixture(t, e, ctx)
	public, private := keys.Calls()
	signs := env.Trust.(*fixtureTrust).Calls()
	creates, cas := store.creates, store.cas
	observed, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
	if result.Outcome != IntegrityFailure || result.Reason != InvalidRelation || result.diagnostic != contract.ReasonSelectedRelationInvalid || observed.complete || inv.selection.complete {
		t.Fatal("late signed registry relation escaped as an authenticated observation", result)
	}
	if source.reads < 1+int(selected.root.ChildCount) {
		t.Fatal("relation failure occurred before complete selected child reads", source.reads)
	}
	if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private || env.Trust.(*fixtureTrust).Calls() != signs || store.creates != creates || store.cas != cas {
		t.Fatal("late public failure reached private use or writes")
	}
}
