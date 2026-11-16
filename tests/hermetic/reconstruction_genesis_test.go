package core

import (
	"bytes"
	"context"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This relation test does not replace the selected HEAD signature check. A
// signer can choose a different well-formed closure, so the selected closure
// must still bind the actual canonical helper length.
// full_only: false
func TestGenesisSelectedConfigurationFactBindsExactLength(t *testing.T) {
	for _, tc := range []struct {
		name     string
		recovery bool
	}{{"normal", false}, {"recovery", true}} {
		t.Run(tc.name, func(t *testing.T) {
			env := memoryScenarioEnvironmentMode(t, tc.recovery)
			f := newEnvironmentFixture(t, context.Background(), env, nil, false)
			s := f.session
			if s.head.AuthKind != format.GenesisAuth || s.head.Genesis == nil {
				t.Fatal("fixture is not a selected genesis")
			}
			d, ok := s.admission.domainBasis()
			if !ok || !s.validGenesisSelection(d) {
				t.Fatal("valid genesis closure refused")
			}
			store := env.Store.(*memoryStore)
			encoded, err := contract.EncodeStoreConfiguration(store.configuration)
			if err != nil || s.head.Genesis.Closure.ConfigurationReadbackFact.BodyLength != uint64(len(encoded)) {
				t.Fatal("fixture helper fact does not match canonical bytes", err)
			}
			store.mu.Lock()
			readsBefore := store.reads
			store.mu.Unlock()
			image := s.selectedImageView()
			selected, ok := selectedGenesisClosure(s.head, &image, store.configuration)
			if !ok {
				t.Fatal("complete selected Genesis relation refused")
			}
			want, err := contract.EncodeGenesisDescriptorCore(d)
			if err != nil {
				t.Fatal(err)
			}
			got, err := contract.EncodeGenesisDescriptorCore(selected)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("selected Genesis descriptor differs from independent basis", err)
			}
			store.mu.Lock()
			readsAfter := store.reads
			store.mu.Unlock()
			if readsAfter != readsBefore {
				t.Fatal("selected Genesis relation read the Store")
			}
			changedRoot := image
			changedRoot.root.OutputConfiguration.ConfigurationDigest[0] ^= 1
			if _, ok := selectedGenesisClosure(s.head, &changedRoot, store.configuration); ok {
				t.Fatal("changed selected root passed Genesis relation")
			}
			changed := *s
			changed.head = s.head
			genesis := *s.head.Genesis
			genesis.Closure.ConfigurationReadbackFact.BodyLength++
			changed.head.Genesis = &genesis
			if changed.validGenesisSelection(d) {
				t.Fatal("changed helper readback length passed ordinary selected relation")
			}
			if _, ok := selectedGenesisClosure(changed.head, &image, store.configuration); ok {
				t.Fatal("changed helper readback length passed complete selected relation")
			}
		})
	}
}

// full_only: false
func TestGenesisHermeticReaderUsesIndependentConfiguration(t *testing.T) {
	env := memoryScenarioEnvironment(t)
	f := newEnvironmentFixture(t, context.Background(), env, nil, false)
	store := env.Store.(*memoryStore)
	reader := &hermeticReaderStore{store: store}
	selected, result := Open(context.Background(), f.admission, reader)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatalf("read-only configured Store refused selected Genesis: %+v", result)
	}
	if reader.writes != 0 {
		t.Fatal("read-only Genesis reader wrote to Store")
	}
}

// full_only: false
func TestSignedGenesisWrongConfigurationLengthRefusesCompleteReconstruction(t *testing.T) {
	ctx := context.Background()
	env := memoryScenarioEnvironmentMode(t, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	store := env.Store.(*memoryStore)
	head := f.session.head
	if head.AuthKind != format.GenesisAuth || head.Genesis == nil {
		t.Fatal("fixture did not select Genesis")
	}
	genesis := *head.Genesis
	genesis.Closure.ConfigurationReadbackFact.BodyLength++
	closureBody, err := contract.EncodeGenesisBootstrapClosureCore(genesis.Closure)
	if err != nil {
		t.Fatal("changed complete Genesis closure is not canonical", err)
	}
	genesis.Subject.BootstrapClosureDigest = contract.Hash(closureBody)
	request, err := contract.NewGenesisRequest(genesis.Subject)
	if err != nil {
		t.Fatal("changed complete Genesis subject is not canonical", err)
	}
	signed := env.Trust.Sign(ctx, request)
	if signed.Reason != contract.ReasonNone {
		t.Fatal("test signer did not sign changed complete subject", signed.Reason)
	}
	head.Genesis = &genesis
	head.AuthorizationSignature = signed.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal("re-signed changed HEAD is not canonical", err)
	}
	store.put(store.desc.HeadKey, headBody)
	candidate := candidateProbeForSelected(t, env, f.session)
	candidate.head.Body = bytes.Clone(headBody)
	candidate.head.Token = store.objects[store.desc.HeadKey].Token
	public, result := anchorPublicCandidate(ctx, candidate, env.Domain, &candidateQualifierProbe{}, nil)
	if result.Outcome != 0 {
		t.Fatal("independently qualified signed candidate refused before closure", result)
	}
	source := &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 || source.reads != 1 {
		t.Fatal("normal Store did not bind same signed HEAD", result)
	}
	creates, cas := store.creates, store.cas
	if _, result := completePublicSelection(ctx, basis, nil); result.Outcome != IntegrityFailure ||
		result.Reason != InvalidProof || source.reads <= 1 || store.creates != creates || store.cas != cas {
		t.Fatal("signed wrong helper length reached a complete reconstruction", result)
	}
}
