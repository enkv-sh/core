// Package core implements the internal canonical-state component. Its local
// Authority adapter issues only protected, operation-scoped admissions. A zero
// OpenContext always refuses.
package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"maps"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type Outcome uint8

const (
	Unchanged Outcome = iota + 1
	ObservedCurrent
	Contention
	UnresolvedCommit
	IntegrityFailure
	EvidenceUnavailable
	RootLossUnsupported
	AdmissionRefused
)

type Reason uint8

const (
	NoReason Reason = iota
	AdmissionInvalid
	ConstructionMismatch
	InvalidFormat
	InvalidProof
	InvalidReference
	InvalidRelation
	MissingSelectedObject
	ReadUnavailable
	ImmutableConflict
	CapacityExceeded
	InvalidIntent
	SigningUnavailable
	WriteUncertain
	StalePrecondition
	DifferentSelection
	AlreadyUsed
	CustodyUnavailable
	StaleGeneratedEpoch
	GeneratedIntentConflict
)

type Evidence uint8

const (
	NoEvidence Evidence = iota
	AuthenticatedClosure
)

// Result contains bounded state facts only. Observations establish currentness
// at that read. CommitMayHaveOccurred retains uncertainty after a possible send.
type Result struct {
	Outcome                                                 Outcome
	Reason                                                  Reason
	RequestedRevision, ObservedRevision, ObservedSnapshotID contract.ID
	Evidence                                                Evidence
	CommitMayHaveOccurred                                   bool
	StoreReason                                             contract.Reason
}

type StateSession struct {
	installedReplacement *installedReplacementActor
	prepared             bool
	replacementRead      bool
	// Set only by an administrative open. Receipt refresh may use the same
	// authenticated partial read after HEAD changes.
	administrativeReceiptRead      bool
	admission                      openAdmission
	store                          contract.Store
	key                            *ecdsa.PublicKey
	head                           format.Head
	body                           []byte
	token                          contract.Token
	root                           format.Root
	pages                          [contract.MaxValueEntryPages]*format.ValueEntryPage
	recipient                      format.RecipientPage
	recipients                     [contract.MaxRecipientPages]*format.RecipientPage
	access                         [contract.MaxChildPages]*format.AccessPage
	accessFacts                    map[format.Ref]*format.AccessPage
	grantSources                   map[format.Ref]format.GrantPageSource
	support                        []format.RequiredSupportPageView
	supportFacts                   []selectedSupportPageFacts
	fragmentFacts                  map[format.FragmentLocation]selectedFragmentFact
	generatedSliceLocations        []contract.GeneratorSliceLocation
	generatedSlicesRoot            contract.ID
	normalReceiptSlices            *normalReceiptSlices
	outputConfigurationRoot        contract.ID
	publicationProof               *selectedPublicationProof
	publicationFacts               map[generatedRecordKey]selectedPublicationRecord
	accessLocations                map[materialIdentity]materialLocation
	valueReaders                   map[contract.ID][]contract.ID
	mutationReceipts               map[contract.ID]contract.CompactMutationReceipt
	selectedReceiptIndexes         contract.MutationReceiptIndexes
	selectedReceiptRoot            format.Ref
	generatedWork                  *validatedGeneratedSelection
	generatedGraphs                map[contract.ID]validatedGeneratorGraph
	adminIndex                     format.AdministrativeIndex
	administrativeIndexFacts       *selectedAdministrativeIndexFacts
	cachedAdministrativeIndexFacts *selectedAdministrativeIndexFacts
	// Only immutable bytes authenticated in this uninterrupted session are cached.
	cache map[format.Ref][]byte
}

func refused(reason Reason) Result                  { return Result{Outcome: AdmissionRefused, Reason: reason} }
func failure(outcome Outcome, reason Reason) Result { return Result{Outcome: outcome, Reason: reason} }
func unavailableStoreRead(read contract.ReadResult) Result {
	result := failure(EvidenceUnavailable, ReadUnavailable)
	result.StoreReason = read.Reason
	if read.Status < contract.ReadOK || read.Status > contract.ReadInvalid || read.Reason > contract.ReasonProof || read.Status == contract.ReadUnavailable && read.Reason == contract.ReasonNone {
		result.StoreReason = contract.ReasonMalformed
	}
	return result
}
func (s *StateSession) observed(outcome Outcome) Result {
	return Result{Outcome: outcome, ObservedRevision: s.head.Core.Revision, ObservedSnapshotID: s.root.Snapshot, Evidence: AuthenticatedClosure}
}
func open(ctx context.Context, admitted OpenContext, store contract.Store) (*StateSession, Result) {
	return openWithMode(ctx, admitted, store, false)
}

// openAdministrative uses the same independently supplied current basis and
// HEAD proof as ordinary open. It retains unreadable optional work commitments
// only for typed administrative transitions.
func openAdministrative(ctx context.Context, admitted OpenContext, store contract.Store) (*StateSession, Result) {
	return openWithMode(ctx, admitted, store, true)
}

func openWithMode(ctx context.Context, admitted OpenContext, store contract.Store, administrative bool) (*StateSession, Result) {
	s, result := newReadSession(ctx, admitted, store, false)
	if s == nil {
		return nil, result
	}
	s.administrativeReceiptRead = administrative
	if administrative {
		return s.readAdministrativeImage(ctx)
	}
	return s.readCurrent(ctx)
}

// openReplacementSession belongs to one installed replacement. Its selected
// facts cannot be reused as a general administrative writer session.
func openReplacementSession(ctx context.Context, admitted OpenContext, store contract.Store, administrative bool) (*StateSession, Result) {
	s, result := newReadSession(ctx, admitted, store, true)
	if s == nil {
		return nil, result
	}
	s.administrativeReceiptRead = administrative
	if administrative {
		return s.readAdministrativeImage(ctx)
	}
	return s.readCurrent(ctx)
}

func newReadSession(ctx context.Context, admitted OpenContext, store contract.Store, borrowBasis bool) (*StateSession, Result) {
	if ctx == nil || ctx.Err() != nil || admitted.admission == nil || !admitted.admission.valid(store) {
		return nil, refused(AdmissionInvalid)
	}
	a := *admitted.admission
	a.publicKey = bytes.Clone(a.publicKey)
	if !borrowBasis {
		a.descriptor = bytes.Clone(a.descriptor)
		a.current = a.current.clone()
	}
	// A private installed replacement borrows its constructor-owned immutable
	// basis until the invocation joins. Callback offered/readback copies keep
	// their separate ownership; ordinary reusable sessions still clone above.
	// The independently owned observation is published immutable evidence.
	// Admission and session share it; neither can clear the other owner's facts.
	key, ok := publicKey(a.publicKey)
	if !ok {
		return nil, refused(InvalidProof)
	}
	return &StateSession{admission: a, store: store, key: key, replacementRead: borrowBasis, cache: make(map[format.Ref][]byte)}, Result{}
}

func (s *StateSession) readCurrent(ctx context.Context) (*StateSession, Result) {
	return s.readCurrentImage(ctx, true)
}

type authenticatedHead struct {
	head  format.Head
	body  []byte
	token contract.Token
}

func (s *StateSession) readAuthenticatedHead(ctx context.Context) (authenticatedHead, Result) {
	return s.authenticateHeadResponse(ctx, s.storeRead(ctx, s.admission.store.HeadKey, contract.MaxHeadLength))
}

// authenticateHeadResponse preserves the ordinary checks for one captured HEAD.
// Public observation can test its two fixed independent bases on the same bytes.
func (s *StateSession) authenticateHeadResponse(ctx context.Context, r contract.ReadResult) (authenticatedHead, Result) {
	if r.Status != contract.ReadOK {
		switch r.Status {
		case contract.ReadMissing:
			return authenticatedHead{}, failure(RootLossUnsupported, MissingSelectedObject)
		case contract.ReadInvalid:
			return authenticatedHead{}, failure(IntegrityFailure, InvalidFormat)
		default:
			return authenticatedHead{}, unavailableStoreRead(r)
		}
	}
	if len(r.Body) > contract.MaxHeadLength || !r.Token.Valid() || r.Token.Family != s.admission.store.Family || (s.token.Valid() && r.Token == s.token && !bytes.Equal(r.Body, s.body)) {
		return authenticatedHead{}, failure(IntegrityFailure, InvalidFormat)
	}
	h, err := format.DecodeHead(r.Body)
	if err != nil {
		return authenticatedHead{}, failure(IntegrityFailure, InvalidFormat)
	}
	a := s.admission
	control, ok := a.currentControl()
	if !ok {
		return authenticatedHead{}, refused(AdmissionInvalid)
	}
	if h.Core.Domain != a.domain || h.Core.Store != a.store.Identity || h.Core.Trust != a.trust || h.Core.Coordinate != a.store.Coordinate || h.Core.NonBody != a.store.NonBody || h.Core.Interpretation != a.interpretation || (h.Core.Form == format.SuccessorHead && h.Core.PreviousToken.Family != a.store.Family) {
		return authenticatedHead{}, failure(IntegrityFailure, ConstructionMismatch)
	}
	if h.Core.Epoch != a.epoch || !s.headSuccessionPinned(h) {
		if !s.outOfBasisHeadKnownProofsValid(h, control) {
			return authenticatedHead{}, failure(IntegrityFailure, InvalidProof)
		}
		return authenticatedHead{}, failure(EvidenceUnavailable, SigningUnavailable)
	}
	if !s.verifyHeadProofs(h, control) {
		// A valid normal proof can authenticate changed recovery control even
		// when the old independent recovery binding cannot verify its K3.
		body := bytes.Clone(r.Body)
		ownedHead, err := format.DecodeHead(body)
		if err != nil {
			return authenticatedHead{}, failure(IntegrityFailure, InvalidFormat)
		}
		result := s.ordinaryHeadProofFailure(ctx, ownedHead, control)
		return authenticatedHead{}, result
	}
	return authenticatedHead{head: h, body: bytes.Clone(r.Body), token: r.Token}, Result{}
}

func (s *StateSession) ordinaryHeadProofFailure(ctx context.Context, head format.Head, expected contract.ControlCore) Result {
	invalid := failure(IntegrityFailure, InvalidProof)
	if head.AuthKind == format.GenesisAuth || head.AuthKind == format.SuccessionAuth {
		return invalid
	}
	key, ok := publicKey(expected.NormalSigning.SPKI)
	request, err := contract.NewBindingRequest(expected.NormalSigning.Binding)
	if !ok || err != nil || !verify(key, request, head.K1) || !selectedHeadAuthorizationProofs(head, expected, nil) {
		return invalid
	}
	body, result := s.readObject(ctx, head.Core.Root)
	if result.Outcome != 0 {
		return result
	}
	root, err := format.DecodeRoot(body)
	if err != nil || root.Domain != head.Core.Domain || root.Snapshot != head.Core.Root.Object {
		return failure(IntegrityFailure, InvalidReference)
	}
	if !validAggregate(root) {
		return failure(IntegrityFailure, InvalidRelation)
	}
	binding, valid := candidateSelectionSignature(head, root, contract.NormalSigningRole)
	if !valid || !signingBindingEqual(binding, expected.NormalSigning) {
		return invalid
	}
	actual := contract.ControlCore{CurrentControl: root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: expected.AuthorityKMSBinding}
	if CurrentControlMatches(actual, expected) {
		return invalid
	}
	return failure(EvidenceUnavailable, SigningUnavailable)
}

func (s *StateSession) readCurrentForReceipt(ctx context.Context) (*StateSession, Result) {
	current, res := s.readAuthenticatedHead(ctx)
	if res.Outcome != 0 {
		return nil, res
	}
	if current.token == s.token && bytes.Equal(current.body, s.body) && s.mutationReceipts != nil {
		return s, s.observed(ObservedCurrent)
	}
	if s.administrativeReceiptRead {
		return s.readImageFromHead(ctx, current, true, true)
	}
	return s.readCurrentImageFromHead(ctx, current, true)
}

// Selection needs the complete authenticated decoded image only for this call.
// It does not need to retain encoded children for future cache hits.
func (s *StateSession) readCurrentImage(ctx context.Context, retainObjects bool) (*StateSession, Result) {
	current, res := s.readAuthenticatedHead(ctx)
	if res.Outcome != 0 {
		return nil, res
	}
	return s.readCurrentImageFromHead(ctx, current, retainObjects)
}

func (s *StateSession) readCurrentImageFromHead(ctx context.Context, current authenticatedHead, retainObjects bool) (*StateSession, Result) {
	return s.readImageFromHead(ctx, current, retainObjects, false)
}

// readAdministrativeImage authenticates current authority and preserved
// mandatory state while retaining commitments to unreadable work detail.
func (s *StateSession) readAdministrativeImage(ctx context.Context) (*StateSession, Result) {
	current, res := s.readAuthenticatedHead(ctx)
	if res.Outcome != 0 {
		return nil, res
	}
	return s.readImageFromHead(ctx, current, true, true)
}

func (s *StateSession) readImageFromHead(ctx context.Context, current authenticatedHead, retainObjects, administrative bool) (*StateSession, Result) {
	h := current.head
	a := s.admission
	rootBytes, res := s.readObject(ctx, h.Core.Root)
	if res.Outcome != 0 {
		return nil, res
	}
	root, err := format.DecodeRoot(rootBytes)
	if err != nil || root.Domain != a.domain || root.Snapshot != h.Core.Root.Object {
		return nil, failure(IntegrityFailure, InvalidReference)
	}
	if !validAggregate(root) {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	if h.AuthKind == format.SuccessionAuth && !selectionAcceptanceValid(h, root) {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	n := &StateSession{admission: a, store: s.store, key: s.key, head: h, body: bytes.Clone(current.body), token: current.token, root: root,
		administrativeReceiptRead: administrative && s.administrativeReceiptRead,
		replacementRead:           s.replacementRead,
		generatedGraphs:           maps.Clone(s.generatedGraphs), cache: make(map[format.Ref][]byte),
		fragmentFacts: make(map[format.FragmentLocation]selectedFragmentFact)}
	if retainObjects {
		n.cache[h.Core.Root] = rootBytes
	} else {
		// The decoded Root is the last consumer in a one-use observation.
		rootBytes = nil
	}
	mode := selectedComplete
	if administrative {
		mode = selectedAdministrativePartial
	}
	reader := s.selectedObjectReader()
	reader.grantSources, err = root.GrantSources(h)
	if err != nil {
		return nil, failure(IntegrityFailure, InvalidReference)
	}
	n.grantSources = reader.grantSources
	image, result := scanSelectedImage(ctx, reader, root, retainObjects, mode, s.selectedImage())
	if result.Outcome != 0 {
		return nil, result
	}
	n.pages, n.recipients, n.access = image.pages, image.recipients, image.access
	n.accessFacts = image.accessFacts
	n.support, n.supportFacts, n.fragmentFacts = image.support, image.supportFacts, image.fragmentFacts
	n.generatedSliceLocations, n.adminIndex = image.generatedSliceLocations, image.adminIndex
	n.administrativeIndexFacts = image.administrativeIndexFacts
	n.cache, n.publicationProof, n.outputConfigurationRoot = image.cache, image.publicationProof, image.outputConfigurationRoot
	n.publicationFacts = image.publicationFacts
	if retainObjects {
		n.cache[h.Core.Root] = rootBytes
	}
	for _, p := range n.recipients {
		if p != nil {
			for _, row := range p.Slots {
				if row != nil && row.RecipientID == a.recipient {
					n.recipient = *p
				}
			}
		}
	}
	index := n.adminIndex
	if !administrative {
		if rootDigest, ok := n.generatedSelectionRoot(); ok {
			n.generatedSlicesRoot = rootDigest
		} else {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
	}
	if administrative {
		if _, err := format.ResolveGeneratedSliceLocations(a.domain, index.SliceSnapshot, root.Generated.Slices, n.support); err != nil {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		projected, selected, err := n.administrativeGeneratedProjection(index)
		if err != nil || selected != root.RequiredSupportRecordCount ||
			projected.Graphs != root.Generated.Graphs || projected.LiveOwners != root.Generated.LiveOwners ||
			projected.Slices != root.Generated.Slices || !slices.Equal(projected.Fragments, root.Generated.Fragments) ||
			projected.ActiveOwner != root.Generated.ActiveOwner || projected.ActivePhase != root.Generated.ActivePhase ||
			projected.ActiveGraph != root.Generated.ActiveGraph || projected.Attempts != root.Generated.Attempts ||
			projected.GeneratedCurrent != root.Generated.GeneratedCurrent || projected.Retiring != root.Generated.Retiring ||
			projected.Duties != root.Generated.Duties || projected.Hazards != root.Generated.Hazards ||
			projected.Results != root.Generated.Results || projected.Materials != root.Generated.Materials ||
			projected.PendingReleases != root.Generated.PendingReleases {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
	}
	if !administrative {
		evidence, err := administrativeSelectedEvidence(index, n.support, n.publicationFacts)
		if err != nil || len(evidence) != len(index.Groups) {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		for i, group := range index.Groups {
			if group.SelectedEvidenceSummary != evidence[i] {
				return nil, failure(IntegrityFailure, InvalidRelation)
			}
		}
	}
	// Relation coverage completes this image's generated facts. Keep them local
	// until the signed Generator proof accepts the same selected image.
	if h.AuthKind != format.GenesisAuth && h.AuthKind != format.SuccessionAuth {
		expected, ok := a.currentControl()
		actual, valid := n.selectedControl()
		if !ok || !valid {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		if !CurrentControlMatches(actual, expected) {
			binding, valid := candidateSelectionSignature(h, root, contract.NormalSigningRole)
			if !valid || !signingBindingEqual(binding, expected.NormalSigning) {
				return nil, failure(IntegrityFailure, InvalidProof)
			}
			return nil, failure(EvidenceUnavailable, SigningUnavailable)
		}
	}
	selectedGenerated, err := n.validateRelationsMode(ctx, administrative)
	if err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	if administrative {
		if _, err := n.publicationCoordinatesForDisposition(); err != nil {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		windows, err := n.receiptWindowsFromAdministrativeSupport()
		if err != nil {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		if h.AuthKind == format.GCAuth && !selectedGCSelection(h, n.selectedImage()) {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
		if h.AuthKind == format.AdministrativeAuth && !n.validEndWorkSelection() {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
		if n.recordSelectedReceiptWindows(windows) != nil {
			return nil, failure(IntegrityFailure, InvalidRelation)
		}
		if !selectedLifecycleReceiptKind(h, windows) {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
		return n, n.observed(ObservedCurrent)
	}
	if err := validateAdministrativeExposure(index, n.support, selectedGenerated, n.publicationFacts); err != nil {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	var windows contract.MutationReceiptWindows
	if n.fragmentFacts != nil {
		windows, err = n.receiptWindowsFromSelectedSupport(ctx)
	} else {
		windows, err = n.receiptWindowsFromValidatedSupport()
	}
	if result, ok := selectedReadResult(err); ok {
		return nil, result
	}
	if err != nil {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	if n.recordSelectedReceiptWindows(windows) != nil {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	if !selectedLifecycleReceiptKind(h, windows) {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	if h.AuthKind == format.GenesisAuth {
		basis, ok := a.domainBasis()
		if !ok || !n.validGenesisSelection(basis) {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
	} else if h.AuthKind == format.GeneratorAuth {
		if err := n.validateGeneratedSelection(ctx, selectedGenerated); err != nil {
			if result, ok := selectedReadResult(err); ok {
				return nil, result
			}
			return nil, failure(IntegrityFailure, InvalidProof)
		}
	} else if h.AuthKind == format.SuccessionAuth {
		if !n.validSuccessionSelection() {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
	} else if h.AuthKind == format.GCAuth {
		if !selectedGCSelection(h, n.selectedImage()) {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
	} else if h.AuthKind == format.AdministrativeAuth {
		if !n.validEndWorkSelection() {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
	} else if h.AuthKind == format.OutputReserveAuth || h.AuthKind == format.OutputCloseAuth {
		if !n.validOutputSelection() {
			return nil, failure(IntegrityFailure, InvalidProof)
		}
	} else if !n.validLifecycleSelection() {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	return n, n.observed(ObservedCurrent)
}

// headSuccessionPinned compares scope only. Different independently supplied
// signer evidence is unavailable; it is not proof that a live selection is bad.
func (s *StateSession) headSuccessionPinned(h format.Head) bool {
	if h.AuthKind != format.SuccessionAuth {
		return true
	}
	return s.admission.successionSelected(h)
}

// outOfBasisHeadKnownProofsValid preserves positive rejection of required
// proofs under independently known bindings. An embedded unfamiliar key is
// not an admitted basis. A known before-control commitment and authenticated
// change mask establish which unchanged signer proofs remain applicable.
func (s *StateSession) outOfBasisHeadKnownProofsValid(h format.Head, control contract.ControlCore) bool {
	if h.AuthKind != format.SuccessionAuth {
		return true
	}
	if h.Succession == nil {
		return false
	}
	p := h.Succession
	body, err := format.EncodeHeadCore(h.Core)
	if err != nil || p.Subject.HeadCoreDigest != contract.Hash(body) || p.Subject.HeadCoreLength != uint32(len(body)) {
		return false
	}
	condition, err := format.EncodeConditionalPlan(conditional(h.Core, body))
	if err != nil || p.Subject.ConditionalPlanDigest != contract.Hash(condition) || p.Subject.ApprovalRole != p.Authorizer.Role {
		return false
	}
	knownAuthorizer := signingBindingEqual(p.Authorizer, control.NormalSigning) ||
		control.Recovery != nil && signingBindingEqual(p.Authorizer, control.Recovery.Signing)
	if !knownAuthorizer {
		return true
	}
	if !successionProofValid(h) {
		return false
	}
	before, err := contract.ControlCoreDigest(control)
	if err != nil || p.Subject.BeforeControlDigest != before {
		return true
	}
	if p.Subject.ChangeMask&contract.SuccessionChangeNormalSigner == 0 {
		if h.Core.Epoch != control.NormalSigning.Binding.Epoch {
			return false
		}
		key, ok := publicKey(control.NormalSigning.SPKI)
		q, err := contract.NewBindingRequest(control.NormalSigning.Binding)
		if !ok || err != nil || !verify(key, q, h.K1) {
			return false
		}
	}
	if p.Subject.ChangeMask&contract.SuccessionChangeRecoverySigner == 0 {
		if control.Recovery == nil {
			return len(h.K3) == 0
		}
		key, ok := publicKey(control.Recovery.Signing.SPKI)
		q, err := contract.NewK3BasisRequest(control.Recovery.Signing)
		if !ok || err != nil || !verify(key, q, h.K3) {
			return false
		}
	}
	return true
}

func (s *StateSession) verifyHeadProofs(h format.Head, control contract.ControlCore) bool {
	if !s.headSuccessionPinned(h) {
		return false
	}
	var genesis *contract.GenesisDescriptorCore
	if h.AuthKind == format.GenesisAuth {
		d, ok := s.admission.domainBasis()
		if !ok {
			return false
		}
		genesis = &d
	}
	return selectedHeadProofs(h, control, genesis)
}

func (s *StateSession) readObject(ctx context.Context, ref format.Ref) ([]byte, Result) {
	if s != nil && ref.Domain != s.admission.domain {
		return nil, failure(IntegrityFailure, InvalidReference)
	}
	return s.selectedObjectReader().readOwned(ctx, ref)
}
func (s *StateSession) readObjectUncached(ctx context.Context, ref format.Ref) ([]byte, Result) {
	reader := s.selectedObjectReader()
	reader.cache, reader.accessFacts = nil, nil
	return reader.readOwned(ctx, ref)
}

func (s *StateSession) recipientRecord(id contract.ID) *contract.RecipientRecord {
	return selectedRecipientRecord(&s.recipients, id)
}

func (s *StateSession) authority() *contract.RecipientRecord {
	return s.recipientRecord(s.admission.recipient)
}
func (s *StateSession) registry() []contract.RecipientRecord {
	return selectedRecipientRegistry(&s.recipients, s.root.RecipientCount)
}

func (s *StateSession) validateRelationsMode(ctx context.Context, administrative bool) (*generatedSelection, error) {
	basis, ok := s.admission.currentControl()
	if !ok {
		return nil, contract.ErrRecord
	}
	return s.validateRelationsAgainst(ctx, basis, administrative)
}

// validateRelationsAgainst checks the authenticated current image against
// independently qualified control. It neither admits control nor issues a basis.
func (s *StateSession) validateRelationsAgainst(ctx context.Context, basis contract.ControlCore, administrative bool) (*generatedSelection, error) {
	indexed := false
	if administrative {
		indexed = s.indexAdministrativeMaterials()
	} else {
		indexed = s.indexSelectedMaterials()
	}
	if !indexed {
		return nil, contract.ErrRecord
	}
	registry := s.registry()
	selectedAccess := s.root.CurrentAccess.Core
	if len(registry) != int(s.root.RecipientCount) ||
		selectedAccess.AccessIncarnationID == basis.AccessIncarnationID && selectedAccess.AccessGeneration < basis.AccessGeneration ||
		s.head.AuthKind == format.GenesisAuth && selectedAccess.AccessIncarnationID != basis.AccessIncarnationID {
		return nil, contract.ErrRecord
	}
	authorityPresent := false
	for _, row := range registry {
		if row.Status != contract.CurrentRecipient || row.CurrentBinding == nil || row.CurrentBinding.Provider != basis.Provider {
			return nil, contract.ErrRecord
		}
		if row.RecipientID == basis.AuthorityRecipientID {
			authorityPresent = true
			if !kmsBindingEqual(*row.CurrentBinding, basis.AuthorityKMSBinding) {
				return nil, contract.ErrRecord
			}
		}
	}
	if !authorityPresent {
		return nil, contract.ErrRecord
	}
	control := s.root.CurrentAccess.Core
	actual, err := contract.EncodeCurrentAccessCore(control)
	if err != nil {
		return nil, contract.ErrRecord
	}
	control.CurrentControl = basis.CurrentControl
	control.AccessIncarnationID = selectedAccess.AccessIncarnationID
	control.AccessGeneration = s.root.CurrentAccess.Core.AccessGeneration
	expected, err := contract.EncodeCurrentAccessCore(control)
	if err != nil || !bytes.Equal(actual, expected) {
		return nil, contract.ErrRecord
	}
	if !administrative {
		support, err := s.supportDescriptor()
		if err != nil || support.Count != s.root.RequiredSupportRecordCount || (len(s.support) == 0) != (len(s.root.RequiredSupport) == 0) ||
			!s.selectedOutputComplete() {
			return nil, contract.ErrRecord
		}
	}
	image := s.selectedImage()
	gc, err := selectedGCState(image, !administrative)
	if err != nil {
		return nil, err
	}
	if err := selectedGCStore(gc, s.admission.store); err != nil {
		return nil, err
	}
	materials := selectedMaterialFacts{accessLocations: s.accessLocations, valueReaders: s.valueReaders}
	records, valid := selectedValueRelations(s.head, image, s.admission.recipient, materials)
	if !valid {
		return nil, contract.ErrRecord
	}
	if administrative {
		return nil, nil
	}
	return s.validateGeneratedCoverage(ctx, records)
}
func (s *StateSession) selectedValue(slot uint16) (contract.ValueCore, contract.CanonicalPayload, contract.AccessRecord, bool) {
	return selectedValueFrom(s.admission.domain, s.root, &s.pages, &s.recipients, &s.access, s.accessLocations, s.valueReaders, slot)
}
func selectedValueFrom(domain contract.ID, root format.Root, pages *[contract.MaxValueEntryPages]*format.ValueEntryPage, recipients *[contract.MaxRecipientPages]*format.RecipientPage, access *[contract.MaxChildPages]*format.AccessPage, locations map[materialIdentity]materialLocation, readers map[contract.ID][]contract.ID, slot uint16) (contract.ValueCore, contract.CanonicalPayload, contract.AccessRecord, bool) {
	m := selectedValueEntry(pages, slot)
	if m == nil || m.ConfidentialityClass != format.Secret {
		return contract.ValueCore{}, contract.CanonicalPayload{}, contract.AccessRecord{}, false
	}
	p, err := contract.DecodeCanonicalPayload(m.ValueBytes)
	if err != nil {
		return contract.ValueCore{}, contract.CanonicalPayload{}, contract.AccessRecord{}, false
	}
	c, err := contract.ValueCoreForEntry(domain, contract.CompatibilityID(), *m)
	if err != nil || p.CryptoSupportID != c.CryptoSupportID {
		return contract.ValueCore{}, contract.CanonicalPayload{}, contract.AccessRecord{}, false
	}
	selected, ok := selectedMaterialAccess(access, locations, contract.ValueMaterialKind, m.ValueState)
	if !ok || !selectedValueAccess(root, recipients, c, p, selected, readers[m.ValueState]) {
		return c, p, selected, false
	}
	return c, p, selected, true
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// Declared byte bounds reject impossible aggregates before page reads. Live
// canonical consumers can add wraps to an existing current value's one row;
// selected relation checks below verify the exact union of readers.
func validAggregate(root format.Root) bool {
	if root.AccessRecordCount < root.SecretCount {
		return false
	}
	var accessBytes uint64
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		accessBytes += uint64(ref.Length)
	}
	wraps := uint64(root.SecretOrdinaryWrapCount)
	if root.CurrentAccess.Core.Recovery != nil {
		wraps += uint64(root.SecretCount)
	}
	extra := uint64(root.AccessRecordCount - root.SecretCount)
	minimumAccess := contract.AccessPageHeaderLength*uint64(len(root.CurrentAccess.Core.AccessPageRefs)) + contract.AccessRecordFixedLength*uint64(root.AccessRecordCount) +
		contract.WrapRowWireLength*(wraps+extra*uint64(1+boolInt(root.CurrentAccess.Core.Recovery != nil)))
	if accessBytes < minimumAccess || accessBytes > uint64(len(root.CurrentAccess.Core.AccessPageRefs))*contract.MaxAccessPageLength ||
		extra == 0 && root.Generated.Duties == 0 && root.Generated.Hazards == 0 && accessBytes != minimumAccess {
		return false
	}
	var referenced uint64
	var pages uint64
	var names uint64
	for _, r := range root.ValueEntryPages {
		if r != nil {
			referenced += uint64(r.Length)
			pages++
		}
	}
	for _, e := range root.Names {
		names += uint64(len(e.Name))
	}
	base := contract.ValueEntryPageFixedLength*pages + uint64(contract.ValueEntryFixedLength)*uint64(root.ValueEntryCount) + names + root.RawBytes +
		uint64(len(contract.ID{}))*uint64(root.MembershipCount) + contract.CanonicalPayloadOverhead*uint64(root.SecretCount)
	generated := uint64(root.Generated.GeneratedCurrent)
	// Root has no lifecycle/pointer counts. This is the closed coarse envelope;
	// complete authenticated child inspection checks each actual row and total.
	nonempty := min(root.RawBytes, uint64(root.ValueEntryCount))
	maxRetained := min(uint64(contract.CryptoMaxRetainedSet), uint64(contract.CryptoMaxRetainedValue)*uint64(root.ValueEntryCount), 4*((root.RawBytes+2*nonempty)/3))
	if maxRetained < root.RawBytes {
		return false
	}
	return referenced >= base+contract.GeneratedEntryMetadataFixedLength*generated && referenced <= base+(maxRetained-root.RawBytes)+contract.GeneratedEntryMetadataMaxLength*generated
}
func (s *StateSession) validLifecycleSelection() bool {
	return selectedLifecycleSelection(s.head, s.selectedImage(), s.admission.recipient)
}
func selectedLifecycleSelection(head format.Head, s *selectedImage, authorityID contract.ID) bool {
	q := head.Subject
	r := selectedRecipientRecord(&s.recipients, authorityID)
	if r == nil || q.AfterValueEntryCount != s.root.ValueEntryCount || uint32(q.AfterSecretCount) != s.root.SecretCount || q.AfterRawBytes != s.root.RawBytes || q.AfterMembershipCount != s.root.MembershipCount || q.AfterAccessRoot != s.root.CurrentAccess.AccessRoot || q.Recipient != r.RecipientID || q.KeyBinding != r.CurrentBinding.BindingID || q.Fingerprint != r.CurrentBinding.Fingerprint || q.BindingVersion != r.CurrentBinding.BindingSerial || q.Normal.PublicState != s.publicState() {
		return false
	}
	if q.Grant.Grants.Count == 0 && q.Grant.Grants != grantCommitment(s.root.Domain, nil) {
		return false
	}
	if q.Exclusion.Exclusions.Count == 0 && q.Exclusion.Exclusions != exclusionCommitment(s.root.Domain, nil) {
		return false
	}
	if q.OperationKind != contract.OperationRetireRecipientIdentity && q.Exclusion.Retirements != retirementCommitment(s.root.Domain) {
		return false
	}

	return true
}

func selectedLifecycleReceiptKind(head format.Head, windows contract.MutationReceiptWindows) bool {
	if head.AuthKind != format.LifecycleAuth {
		return true
	}
	required := head.Subject.OperationKind == contract.OperationRemoveSecretValueEntryAccess || head.Subject.OperationKind == contract.OperationRetireRecipientIdentity || head.Subject.OperationKind == contract.OperationEnvelopeRekey
	found := false
	for at, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range rows {
			if row.OperationID != head.Subject.Operation {
				continue
			}
			if row.OperationKind != head.Subject.OperationKind || required && at != 0 {
				return false
			}
			found = true
		}
	}
	return !required || found
}
