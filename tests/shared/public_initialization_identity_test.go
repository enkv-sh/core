package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type initializationIdentityStore struct {
	*memoryStore
	outcome            string
	headCalls          int
	headSends          int
	observationDenials int
}

// full_only: false
func TestPublicInitializationOccupiedHEADRefusesAndPreservesPreparation(t *testing.T) {
	for _, condition := range []string{"foreign", "malformed", "invalid-read", "unavailable-read"} {
		t.Run(condition, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			i, artifacts := publicInitializationInstallation(t, env, keys)
			store := &initializationIdentityStore{memoryStore: env.Store.(*memoryStore)}
			i.Store = store
			original := []byte("malformed occupied HEAD")
			if condition == "foreign" {
				a := installedarchive.Load(t, "gcp")
				if a.Domain == env.Domain {
					t.Fatal("foreign fixture unexpectedly has the new domain identity")
				}
				original = bytes.Clone(a.MustObject(t, a.Location.PrefixBeforeHEAD+"/HEAD").Body)
			}
			store.objects[store.desc.HeadKey] = stored{Body: bytes.Clone(original), Token: contract.Token{Family: contract.GCP, Value: "1"}}
			if condition == "invalid-read" || condition == "unavailable-read" {
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if key != store.desc.HeadKey {
						return read
					}
					if condition == "invalid-read" {
						return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonMalformed}
					}
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				}
			}
			custodyCalls, custodyCloses, installationCloses := 0, 0, 0
			admit := i.AdmitCustody
			i.AdmitCustody = func(ctx context.Context, q contract.CryptoQualifyInitKeysRequest) (contract.Crypto, func(), error) {
				custodyCalls++
				owner, closeOwner, err := admit(ctx, q)
				if err != nil || closeOwner == nil {
					return owner, closeOwner, err
				}
				return owner, func() { custodyCloses++; closeOwner() }, nil
			}
			i.CloseInstalled = func() { installationCloses++ }
			engine, err := NewInstalledInitializer(initializationAllocationForDescriptor(t, i.Descriptor), i)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			got := engine.Initialize(ctx)
			engine.Close()
			wantState, wantOutcome := contract.InitializationRefused, AdmissionRefused
			if condition == "unavailable-read" {
				wantState, wantOutcome = contract.InitializationUnavailable, EvidenceUnavailable
			}
			manifest, err := contract.DecodeGenesisBootstrapManifestCore(artifacts[2])
			if err != nil || len(artifacts[1]) == 0 || manifest.RequestCoreDigest.IsZero() || got.RequestIdentity != manifest.RequestCoreDigest || got.OperationID != i.Descriptor.InitID {
				t.Error("occupied destination lost already completed preparation or exact request identity", err, got)
			}
			if got.StateResult != wantState || got.Result.Outcome != wantOutcome || got.Result.CommitMayHaveOccurred || got.Payload != nil || got.PublicBasis != nil || len(got.Receipt) != 0 {
				t.Error("occupied destination returned the wrong fresh initialization result", got)
			}
			if custodyCalls != 1 || custodyCloses != 1 || installationCloses != 1 || store.creates != 0 || store.cas != 0 || store.headCalls != 0 || store.headSends != 0 || len(store.objects) != 1 || !bytes.Equal(store.objects[store.desc.HeadKey].Body, original) {
				t.Error("occupied refusal lost ownership or changed remote state", custodyCalls, custodyCloses, installationCloses, store.creates, store.cas, store.headCalls)
			}
			pub, private := keys.Calls()
			if pub != 0 || private != 0 || env.Trust.(*fixtureTrust).signs != 0 {
				t.Error("occupied refusal reached key qualification or signing", pub, private)
			}
			if condition == "malformed" || condition == "foreign" {
				observer, err := NewInstalledInitializationObserver(InitializationObservationInstallation{Descriptor: artifacts[1], Manifest: artifacts[2], Store: store, CompositionID: i.CompositionID, CloseInstalled: func() {}})
				if err != nil {
					t.Fatal(err)
				}
				observed := observer.Initialize(ctx)
				observer.Close()
				if observed.StateResult != contract.InitializationPositiveDefect || observed.Result.Outcome != IntegrityFailure || store.creates != 0 || store.cas != 0 {
					t.Error("fresh-init classification changed observation-only integrity behavior", observed)
				}
			}
		})
	}
}

func (s *initializationIdentityStore) CreateHead(ctx context.Context, q contract.HeadCreateRequest) contract.WriteResult {
	s.headCalls++
	if !q.Valid() || q.Descriptor() != s.Descriptor() {
		return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
	}
	if s.outcome == "contention" {
		return contract.WriteResult{Status: contract.WritePrecondition}
	}
	s.headSends++
	result := s.memoryStore.CreateHead(ctx, q)
	if s.outcome == "unknown" && result.Status == contract.WriteAcknowledged {
		s.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
			if key == s.desc.HeadKey {
				s.observationDenials++
				return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
			}
			return result
		}
		return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
	}
	return result
}

// full_only: false
func TestPublicInitializationConstructedRequestIdentitySurvivesFailure(t *testing.T) {
	for _, condition := range []string{"descriptor", "manifest", "custody", "contention", "unknown", "success"} {
		t.Run(condition, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, false)
			i, _ := publicInitializationInstallation(t, env, keys)
			store := &initializationIdentityStore{memoryStore: env.Store.(*memoryStore), outcome: condition}
			i.Store = store
			var expected contract.ID
			descriptor := i.PersistDescriptor
			i.PersistDescriptor = func(ctx context.Context, id contract.ID, body []byte) (contract.GenesisArtifactFact, error) {
				fact, err := descriptor(ctx, id, body)
				if condition == "descriptor" {
					fact.BodyDigest = contract.ID{}
				}
				return fact, err
			}
			manifest := i.PersistManifest
			i.PersistManifest = func(ctx context.Context, id contract.ID, body []byte) (contract.GenesisArtifactFact, error) {
				issued, err := contract.DecodeGenesisBootstrapManifestCore(body)
				if err != nil || issued.RequestCoreDigest.IsZero() {
					t.Fatal("issued manifest has no constructed request commitment", err)
				}
				// The issued artifact fixes the identity to preserve. This checks
				// preservation across outcomes, not independent encoder correctness.
				expected = issued.RequestCoreDigest
				fact, err := manifest(ctx, id, body)
				if condition == "manifest" {
					fact.BodyDigest = contract.ID{}
				}
				return fact, err
			}
			custodyCalls, custodyCloses, installedCloses := 0, 0, 0
			custody := i.AdmitCustody
			i.AdmitCustody = func(ctx context.Context, q contract.CryptoQualifyInitKeysRequest) (contract.Crypto, func(), error) {
				custodyCalls++
				if expected.IsZero() || q.Context.RequestDescriptor.Digest != expected {
					t.Fatal("custody received a different constructed request commitment")
				}
				if condition == "custody" {
					return nil, nil, contract.ErrRecord
				}
				owner, closeOwner, err := custody(ctx, q)
				if err != nil || closeOwner == nil {
					return owner, closeOwner, err
				}
				return owner, func() { custodyCloses++; closeOwner() }, nil
			}
			i.CloseInstalled = func() { installedCloses++ }
			engine, err := NewInstalledInitializer(initializationAllocationForDescriptor(t, i.Descriptor), i)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			result := engine.Initialize(ctx)
			engine.Close()
			if result.OperationID != i.Descriptor.InitID || result.RequestIdentity != expected {
				t.Errorf("initialization lost the exact constructed request identity: got %x, want %x", result.RequestIdentity, expected)
			}
			wantState, wantOutcome := contract.InitializationUnavailable, EvidenceUnavailable
			wantCustody, wantCloses, wantHeadCalls, wantHeadSends := 0, 0, 0, 0
			switch condition {
			case "descriptor":
				if !expected.IsZero() {
					t.Error("descriptor refusal reached request construction")
				}
			case "custody":
				wantState, wantOutcome = contract.InitializationRefused, AdmissionRefused
				wantCustody = 1
			case "contention", "unknown", "success":
				wantCustody, wantCloses, wantHeadCalls = 1, 1, 1
				wantState, wantOutcome = contract.InitializationContention, Contention
				if condition != "contention" {
					wantHeadSends = 1
				}
				switch condition {
				case "unknown":
					wantState, wantOutcome = contract.InitializationCommitUnknown, UnresolvedCommit
				case "success":
					wantState, wantOutcome = contract.InitializationSuccess, ObservedCurrent
				}
			}
			if condition != "descriptor" && expected.IsZero() {
				t.Error("case did not reach request construction")
			}
			if result.StateResult != wantState || result.Result.Outcome != wantOutcome || result.Result.CommitMayHaveOccurred != (condition == "unknown") {
				t.Errorf("initialization outcome differs: %s, %+v", result.StateResult, result.Result)
			}
			if custodyCalls != wantCustody || custodyCloses != wantCloses || installedCloses != 1 || store.headCalls != wantHeadCalls || store.headSends != wantHeadSends || store.cas != 0 {
				t.Errorf("initialization ownership or sends differ: custody %d/%d, installed closes %d, HEAD %d/%d, CAS %d", custodyCalls, custodyCloses, installedCloses, store.headCalls, store.headSends, store.cas)
			}
			if condition == "unknown" && store.observationDenials == 0 || condition != "unknown" && store.observationDenials != 0 {
				t.Error("unknown outcome did not retain its denied-observation boundary")
			}
			_, headInstalled := store.objects[store.desc.HeadKey]
			if headInstalled != (condition == "unknown" || condition == "success") {
				t.Error("actual HEAD installation differs from the controlled outcome")
			}
			if wantHeadCalls == 0 && store.creates != 0 {
				t.Error("early refusal reached Store writes")
			}
			if condition == "success" {
				receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
				if err != nil || receipt.RequestIdentityDigest != expected || result.Payload == nil || result.PublicBasis == nil || result.Payload.InitID != i.Descriptor.InitID || result.Result.Evidence != AuthenticatedClosure {
					t.Error("positive result lost its exact identity, payload, public basis or receipt", err)
				}
			} else if result.Payload != nil || result.PublicBasis != nil || len(result.Receipt) != 0 {
				t.Error("failed initialization claimed a success payload, public basis or receipt")
			}
		})
	}
}
