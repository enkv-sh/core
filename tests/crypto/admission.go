package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"io"
	"os"
	"time"

	"enkv.sh/core/contract"
	primitive "enkv.sh/crypto/internal/custody"
)

func TestAdmitInputSeal(r *Runtime, id contract.ID, core contract.SealedInputCore, authority contract.ID, bindings []contract.BindingTableRow, input io.ReadCloser, deadline time.Time) error {
	return r.admitInputSeal(id, core, authority, bindings, input, deadline)
}

func TestSealInput(r *Runtime, ctx context.Context, id contract.ID) ([]byte, contract.CryptoResultCode) {
	return r.sealInput(ctx, id)
}

func TestAdmitConsumer(r *Runtime, id, purpose, sinkID, routeID contract.ID, selection contract.ConsumerSelection, sink consumerSink, deadline time.Time) error {
	return r.admitConsumer(id, purpose, sinkID, routeID, selection, sink, deadline)
}

func TestConsume(r *Runtime, ctx context.Context, id contract.ID) (contract.CryptoResultCode, uint8, []contract.KeyUseRow) {
	result := r.consume(ctx, id)
	return result.code, uint8(result.delivery), result.keyUses
}

// TestAdmitInit exists only in test assemblies. The out-of-Core fixture parent
// supplies its independently fixed binding table, exact request and routes.
func TestAdmitInit(r *Runtime, q contract.CryptoQualifyInitKeysRequest, support contract.ID, publicRoutes, privateRoutes map[contract.ID]contract.ID, deadline time.Time) error {
	return r.admitInit(q, support, publicRoutes, privateRoutes, deadline)
}

func TestRetireInit(r *Runtime) { r.retireInit() }

func TestAdmitApply(r *Runtime, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, public map[contract.ID]PublicKeyQualifier, routeID contract.ID, accepted map[contract.ID]contract.SealedInputCore, plainBefore []contract.MembershipRow, support contract.DescriptorVector, deadline time.Time, witness ...*contract.GeneratedSupportTransition) error {
	return r.admitApply(q, control, current, public, routeID, accepted, plainBefore, support, deadline, witness...)
}

func TestRetireApply(r *Runtime) { r.retireApply() }

type TestGeneratedCandidate = generatedCandidate
type TestGeneratedCandidateEntry = generatedCandidateEntry
type TestGeneratedCanonicalSelection = generatedCanonicalSelection
type TestGeneratedSessionAdmissionInput = generatedSessionAdmissionInput
type TestGeneratedPlanAdmissionInput = generatedPlanAdmissionInput
type TestGeneratedReservationAdmissionInput = generatedReservationAdmissionInput
type TestGeneratedAdoptionAdmissionInput = generatedAdoptionAdmissionInput
type TestGeneratedFinalAdmissionInput = generatedFinalAdmissionInput
type TestGeneratedMembershipSelection = generatedMembershipSelection
type TestGeneratedProducerPreparationAdmissionInput = generatedProducerPreparationAdmissionInput
type TestGeneratedOriginalVerificationAdmissionInput = generatedOriginalVerificationAdmissionInput
type TestGeneratedProducerAdmissionInput = generatedProducerAdmissionInput
type TestGeneratedProducerReturn = generatedProducerReturn
type TestGeneratedResultAdmission = generatedResultAdmission
type TestGeneratedEntryAdmission = generatedEntryAdmission

func TestAdmitGeneratedConsumer(r *Runtime, id, purpose, sinkID, routeID contract.ID, selected TestGeneratedCanonicalSelection, sink consumerSink, deadline time.Time) error {
	return r.admitGeneratedConsumer(id, purpose, sinkID, routeID, selected, sink, deadline)
}

func TestAdmitGeneratedReservation(r *Runtime, q contract.CryptoGeneratedCompareRequest, input TestGeneratedReservationAdmissionInput, deadline time.Time) error {
	return r.admitGeneratedReservation(q, input, deadline)
}

func TestAdmitGeneratedAdoption(r *Runtime, q contract.CryptoGeneratedCompareRequest, input TestGeneratedAdoptionAdmissionInput, deadline time.Time) error {
	return r.admitGeneratedAdoption(q, input, deadline)
}

func TestAdmitGeneratedFinal(r *Runtime, q contract.CryptoGeneratedCompareRequest, input TestGeneratedFinalAdmissionInput, deadline time.Time) error {
	return r.admitGeneratedFinal(q, input, deadline)
}

func TestAdmitGeneratedProducer(r *Runtime, q contract.CryptoGeneratedCompareRequest, input TestGeneratedProducerPreparationAdmissionInput, deadline time.Time) error {
	return r.admitGeneratedProducer(q, input, deadline)
}

func TestAdmitGeneratedOriginalVerification(r *Runtime, q contract.CryptoGeneratedCompareRequest, input TestGeneratedOriginalVerificationAdmissionInput, deadline time.Time) error {
	return r.admitGeneratedOriginalVerification(q, input, deadline)
}

func TestBindGeneratedCandidate(r *Runtime, ctx context.Context, id contract.ID, candidate TestGeneratedCandidate) contract.CryptoResultCode {
	return r.bindGeneratedCandidate(ctx, id, candidate)
}

// TestRefuseGeneratedResultPipe installs a fault on a new, unpublished producer fork.
func TestRefuseGeneratedResultPipe(r *Runtime, observe func()) {
	r.openResultPipe = func() (*os.File, *os.File, error) {
		observe()
		return nil, nil, ErrAdmission
	}
}

func TestRetireGenerated(r *Runtime) { r.retireGenerated() }

type TestGeneratedProducerOutcome struct {
	Record   []byte
	Facts    contract.GeneratorSafeFacts
	Code     contract.CryptoResultCode
	Stage    string
	Category string
	Effect   string
}

func TestInvokeGeneratedProducerOutcome(r *Runtime, ctx context.Context, id, locator, authority contract.ID) TestGeneratedProducerOutcome {
	out := r.invokeGeneratedProducer(ctx, id, locator, authority)
	return TestGeneratedProducerOutcome{Record: out.Record, Facts: out.Facts, Code: out.code,
		Stage: string(out.stage), Category: string(out.category), Effect: string(out.effect)}
}

func TestInvokeGeneratedProducer(r *Runtime, ctx context.Context, id, locator, authority contract.ID) ([]byte, contract.GeneratorSafeFacts, contract.CryptoResultCode) {
	out := TestInvokeGeneratedProducerOutcome(r, ctx, id, locator, authority)
	return out.Record, out.Facts, out.Code
}

func TestAdmitAccess(r *Runtime, q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, control contract.ControlCore, rows []contract.CompactRow, routeID, publicRouteID contract.ID, deadline time.Time) error {
	if r == nil {
		return ErrAdmission
	}
	r.mu.Lock()
	public := r.routes[publicRouteID]
	r.mu.Unlock()
	return r.admitAccess(q, intent, request, control, rows, routeID, public, deadline)
}

func TestRetireAccess(r *Runtime) { r.retireAccess() }

func TestAdmitSuccessionAccess(r *Runtime, q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, before contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, sourceRoute, publicRoute, privateRoute contract.ID, deadline time.Time) error {
	return r.admitSuccessionAccess(q, request, before, source, probe, rows, sourceRoute, publicRoute, privateRoute, deadline)
}

func TestInstallKeyRoute(r *Runtime, route KeyAccess) error {
	if r == nil || route == nil {
		return ErrAdmission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil || route.Family() != r.family || route.CredentialRoute().IsZero() || r.routes[route.CredentialRoute()] != nil {
		return ErrAdmission
	}
	r.routes[route.CredentialRoute()] = route
	return nil
}

// TestRuntimeRoutes checks the installed private assembly without exposing its
// providers, credentials or key-access objects to the public test parent.
func TestRuntimeRoutes(r *Runtime, family contract.Family, routeIDs []contract.ID) error {
	if r == nil {
		return ErrAdmission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.family != family {
		return ErrAdmission
	}
	for _, id := range routeIDs {
		route := r.routes[id]
		if id.IsZero() || route == nil || route.Family() != family || route.CredentialRoute() != id {
			return ErrAdmission
		}
	}
	return nil
}

// TestObserveKeyCalls observes route invocations without exposing their inputs
// or results. Install it before admission; fresh consumers retain the observer.
func TestObserveKeyCalls(r *Runtime, observe func(private bool)) error {
	if r == nil || observe == nil {
		return ErrAdmission
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.slot != nil || !r.retiredID.IsZero() {
		return ErrAdmission
	}
	for _, route := range r.routes {
		if _, observed := route.(*testObservedKeyAccess); observed {
			return ErrAdmission
		}
	}
	for id, route := range r.routes {
		r.routes[id] = &testObservedKeyAccess{KeyAccess: route, observe: observe}
	}
	return nil
}

type testObservedKeyAccess struct {
	KeyAccess
	observe func(private bool)
}

func (r *testObservedKeyAccess) Qualify(ctx context.Context, binding contract.KMSBinding) KeyResult {
	r.observe(false)
	return r.KeyAccess.Qualify(ctx, binding)
}

func (r *testObservedKeyAccess) Decrypt(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
	r.observe(true)
	return r.KeyAccess.Decrypt(ctx, binding, ciphertext, length)
}

// TestNewConsumerRuntime retains exactly one installed route. Every consumer
// receives a fresh instance and its own independently admitted operation slot.
func TestNewConsumerRuntime(installed *Runtime, routeID contract.ID) (*Runtime, error) {
	if installed == nil || routeID.IsZero() {
		return nil, ErrAdmission
	}
	installed.mu.Lock()
	defer installed.mu.Unlock()
	route := installed.routes[routeID]
	if installed.closed || route == nil || route.Family() != installed.family || route.CredentialRoute() != routeID {
		return nil, ErrAdmission
	}
	return New(installed.family, []KeyAccess{route})
}

// TestPrivateRouteWitness is reachable only through the out-of-Core test
// facade. It reports status and actual uses, never private packet bytes.
func TestPrivateRouteWitness(r *Runtime, ctx context.Context, routeID contract.ID, target, wrappedUnder contract.KMSBinding) (contract.CryptoResultCode, KeyUses) {
	if r == nil || ctx == nil || routeID.IsZero() {
		return contract.CryptoInvalidAdmission, KeyUses{}
	}
	if ctx.Err() != nil {
		return contract.CryptoCancelled, KeyUses{}
	}
	targetDigest, err := contract.PublicBindingDigest(target)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	wrappedDigest, err := contract.PublicBindingDigest(wrappedUnder)
	if err != nil || target.Provider != wrappedUnder.Provider {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	target.SPKI, wrappedUnder.SPKI = bytes.Clone(target.SPKI), bytes.Clone(wrappedUnder.SPKI)
	r.mu.Lock()
	route := r.routes[routeID]
	if r.closed || r.family != target.Provider || route == nil || route.Family() != r.family || route.CredentialRoute() != routeID || r.slot != nil || r.init != nil || r.inputSeal != nil || r.consumer != nil || r.apply != nil || r.access != nil || !r.retiredID.IsZero() {
		r.mu.Unlock()
		return contract.CryptoInvalidAdmission, KeyUses{}
	}
	// This dedicated witness runtime cannot become an ENKV operation runtime.
	r.closed, r.routes = true, nil
	r.mu.Unlock()
	public, err := x509.ParsePKIXPublicKey(wrappedUnder.SPKI)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	challenge := make([]byte, 32)
	defer clear(challenge[:cap(challenge)])
	if _, err := rand.Read(challenge); err != nil {
		return contract.CryptoCustodyUnavailable, KeyUses{}
	}
	contextBytes := append([]byte("ENKV/TEST-ROUTE-WITNESS/v1\x00"), routeID[:]...)
	contextBytes = append(contextBytes, targetDigest[:]...)
	contextBytes = append(contextBytes, wrappedDigest[:]...)
	packetContext := contract.Hash(contextBytes)
	packet, err := primitive.EncodePacket(4, packetContext, challenge)
	if err != nil {
		return contract.CryptoInvalidInput, KeyUses{}
	}
	defer clear(packet[:cap(packet)])
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, packet, nil)
	if err != nil {
		return contract.CryptoCustodyUnavailable, KeyUses{}
	}
	result := route.Decrypt(ctx, target, ciphertext, 68)
	defer clear(result.Packet[:cap(result.Packet)])
	if result.Status != KeyOK {
		return keyResultCode(result.Status), result.Uses
	}
	if result.Uses != (KeyUses{Completed: 1}) {
		return contract.CryptoResponseUnknown, result.Uses
	}
	opened, err := primitive.PacketKeys(result.Packet, 4, packetContext)
	if err != nil || subtle.ConstantTimeCompare(opened, challenge) != 1 {
		return contract.CryptoPrivateRouteUnavailable, result.Uses
	}
	if ctx.Err() != nil {
		return contract.CryptoCancelled, result.Uses
	}
	return contract.CryptoSuccess, result.Uses
}

type TestPublicationPlainSelection = publicationPlainSelection
type TestPublicationSelectedValue = publicationSelectedValue
type TestPublicationDeletionSelection = publicationDeletionSelection

func TestPreparePublication(r *Runtime, ctx context.Context, id, sinkID, routeID contract.ID,
	projection contract.PublicationProjection, destinationID string, target contract.OutputTarget,
	deletion *TestPublicationDeletionSelection, selected *TestPublicationSelectedValue, minimum, maximum int, sink publicationSink, deadline time.Time) ([]contract.KeyUseRow, contract.CryptoResultCode) {
	return r.preparePublication(ctx, id, sinkID, routeID, projection, destinationID, target, deletion, selected, minimum, maximum, sink, deadline)
}

func TestArmPublication(r *Runtime, ctx context.Context, id contract.ID, dispatch contract.PublicationDispatch) error {
	return r.armPublication(ctx, id, dispatch)
}

func TestSendPublication(r *Runtime, ctx context.Context, id contract.ID) (contract.PublicationEvidence, contract.CryptoResultCode) {
	return r.sendPublication(ctx, id)
}

func TestRetirePublication(r *Runtime, ctx context.Context) { r.retirePublication(ctx) }

func TestNewRecipientReplacementCustody(r *Runtime, q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, before contract.ControlCore, rows []contract.CompactRow, sourceRoute, publicRoute contract.ID, deadline time.Time) (*ReplacementCustody, error) {
	r.mu.Lock()
	public := r.routes[publicRoute]
	r.mu.Unlock()
	if public == nil {
		return nil, ErrAdmission
	}
	return NewRecipientReplacementCustody(r, q, intent, request, before, rows, sourceRoute, public, deadline)
}
