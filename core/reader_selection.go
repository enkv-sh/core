package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type readerPublicBasis struct {
	control       contract.ControlCore
	genesis       bool
	descriptor    []byte
	enrollment    []recipientEnrollment
	current       *qualifiedCurrentBasis
	digest        contract.ID
	genesisDigest contract.ID
	observation   *PublicBasis
}

func qualifyReaderPublicBasis(image PublicBasis, domain contract.ID, store contract.Descriptor) (readerPublicBasis, contract.DiagnosticReason) {
	owned, err := image.own()
	if err != nil {
		return readerPublicBasis{}, contract.ReasonTrustBasisInvalid
	}
	return qualifyBorrowedReaderPublicBasis(owned, domain, store)
}

// The witness stays borrowed. Callers must keep it immutable for the returned
// facts' lifetime; externally retained admissions first take their own copy.
func qualifyBorrowedReaderPublicBasis(image PublicBasis, domain contract.ID, store contract.Descriptor) (readerPublicBasis, contract.DiagnosticReason) {
	var basis readerPublicBasis
	if err := image.check(); err != nil {
		return basis, contract.ReasonTrustBasisInvalid
	}
	switch {
	case len(image.Descriptor) != 0:
		d, err := contract.DecodeGenesisDescriptorCore(image.Descriptor)
		if err != nil {
			return basis, contract.ReasonTrustBasisInvalid
		}
		basis.genesis = true
		basis.descriptor = image.Descriptor
		for _, row := range d.Recipients {
			basis.enrollment = append(basis.enrollment, recipientEnrollment{id: row.RecipientID, status: row.Status, name: row.DisplayName})
		}
		basis.control.CurrentControl = d.CurrentControl()
		for _, row := range d.Recipients {
			if row.RecipientID == d.AuthorityRecipientID && row.CurrentBinding != nil {
				basis.control.AuthorityKMSBinding = *row.CurrentBinding
			}
		}
		if d.InterpretationID != contract.InterpretationID() || d.TrustID != d.NormalSigning.Binding.Trust {
			return readerPublicBasis{}, contract.ReasonUnsupportedProfile
		}
		basis.digest = contract.Hash(image.Descriptor)
		basis.genesisDigest = basis.digest
	case len(image.Control) != 0:
		control, err := contract.DecodeControlCore(image.Control)
		head, headErr := format.DecodeHead(image.Selection)
		if err != nil || headErr != nil || head.AuthKind != format.SuccessionAuth || head.Succession == nil {
			return basis, contract.ReasonTrustBasisInvalid
		}
		digest, err := contract.ControlCoreDigest(control)
		if err != nil || digest != head.Succession.Subject.AfterControlDigest || !currentSigningProofs(head, control) || !successionProofValid(head) || !successorEvidenceValid(head, control) {
			return basis, contract.ReasonTrustBasisInvalid
		}
		if head.Core.Domain != domain || head.Core.Store != store.Identity || head.Core.Coordinate != store.Coordinate || head.Core.NonBody != store.NonBody || head.Core.Trust != control.NormalSigning.Binding.Trust || head.Core.Epoch != control.NormalSigning.Binding.Epoch || head.Core.Interpretation != contract.InterpretationID() {
			return basis, contract.ReasonDomainBasisInvalid
		}
		for _, row := range image.Enrollment {
			basis.enrollment = append(basis.enrollment, recipientEnrollment{id: row.RecipientID, status: row.Status, name: row.DisplayName})
		}
		basis.control = control
		basis.current = &qualifiedCurrentBasis{issued: true, control: image.Control, selection: image.Selection, enrollment: basis.enrollment}
		// The control digest commits its exact canonical bytes; selection digest
		// additionally pins the independent replacement authorizer and subject.
		selectionDigest := contract.Hash(image.Selection)
		enrollmentDigest := publicBasisEnrollmentDigest(basis.enrollment)
		combined := [96]byte{}
		copy(combined[:32], digest[:])
		copy(combined[32:64], selectionDigest[:])
		copy(combined[64:], enrollmentDigest[:])
		basis.digest = contract.Hash(combined[:])
	case len(image.SigningAnchor) != 0:
		var reason contract.DiagnosticReason
		basis, reason = qualifyObservationBasis(image, domain, store)
		if reason != "" {
			return readerPublicBasis{}, reason
		}
	default:
		return basis, contract.ReasonTrustBasisInvalid
	}
	c := basis.control
	if c.DomainID != domain {
		return readerPublicBasis{}, contract.ReasonDomainBasisInvalid
	}
	if c.Provider != store.Family || c.StoreID != store.Identity || c.CoordinateID != store.Coordinate || c.NonBodyID != store.NonBody {
		return readerPublicBasis{}, contract.ReasonStoreBasisInvalid
	}
	if c.TrustInterpretationID != contract.TrustInterpretationID() || c.CompatibilityID != contract.CompatibilityID() || c.CryptoSupportID != contract.CryptoSupportID() || c.NormalSigning.Binding.Interpretation != contract.InterpretationID() {
		return readerPublicBasis{}, contract.ReasonUnsupportedProfile
	}
	if _, err := contract.ControlCoreLength(c); err != nil {
		return readerPublicBasis{}, contract.ReasonTrustBasisInvalid
	}
	return basis, ""
}

type readerSigningQualifier struct{ binding contract.PublicSigningBinding }

func (q readerSigningQualifier) QualifySigningBinding(ctx context.Context, offered contract.PublicSigningBinding) contract.SigningQualificationResult {
	return q.qualifyCandidateSigningBinding(ctx, offered).SigningQualificationResult
}

func (q readerSigningQualifier) qualifyCandidateSigningBinding(ctx context.Context, offered contract.PublicSigningBinding) candidateSigningQualification {
	if ctx == nil || ctx.Err() != nil {
		return candidateSigningQualification{SigningQualificationResult: contract.SigningQualificationResult{Reason: contract.ReasonLimit}}
	}
	if !signingBindingEqual(q.binding, offered) {
		return candidateSigningQualification{SigningQualificationResult: contract.SigningQualificationResult{Reason: contract.ReasonConstruction}, outOfBasis: true}
	}
	digest, err := contract.SigningBindingDigest(q.binding)
	if err != nil {
		return candidateSigningQualification{SigningQualificationResult: contract.SigningQualificationResult{Reason: contract.ReasonConstruction}}
	}
	role := uint8(contract.NormalSignerTarget)
	if q.binding.Role == contract.RecoverySigningRole {
		role = contract.RecoverySignerTarget
	}
	return candidateSigningQualification{SigningQualificationResult: contract.SigningQualificationResult{Qualified: 1, TargetRole: role, Provider: q.binding.Provider, SigningBindingDigest: digest, Reason: contract.ReasonNone}}
}

func readerSelectionFailure(result Result) readerFailure {
	reason := contract.ReasonProofInvalid
	switch {
	case result.Outcome == Contention:
		reason = contract.ReasonReadContention
	case result.Outcome == EvidenceUnavailable || result.Outcome == RootLossUnsupported:
		reason = contract.ReasonEvidenceUnavailable
		if result.Reason == MissingSelectedObject {
			reason = contract.ReasonSelectedObjectUnavailable
		}
	case result.Reason == InvalidRelation:
		reason = contract.ReasonSelectedRelationInvalid
	case result.Reason == InvalidFormat || result.Reason == InvalidReference:
		reason = contract.ReasonSelectedObjectInvalid
	case result.Reason == ConstructionMismatch:
		reason = contract.ReasonStoreBasisInvalid
	case result.Reason == CapacityExceeded:
		reason = contract.ReasonLimitExceeded
	case result.Outcome == AdmissionRefused && result.Reason != InvalidProof:
		reason = contract.ReasonInvalidInput
	}
	return readerFailure{Result: result, diagnostic: reason}
}

func (i *readerInvocation) loadPublicReadBasis(ctx context.Context, operation string, request contract.ID) (publicReadBasis, readerFailure) {
	var empty publicReadBasis
	if i == nil || i.closed || i.loaded || i.engine == nil {
		return empty, readerRefusal(contract.ReasonInvalidInput)
	}
	if reason := i.admission.failure(ctx, operation, request); reason != "" {
		return empty, readerRefusal(reason)
	}
	i.loaded = true
	e := i.engine
	basis := i.admission.basis
	location := e.candidate.CandidateLocation()
	if location.Provider != i.admission.store.Family || location.PrefixBeforeHEAD != i.admission.store.Prefix {
		return empty, readerRefusal(contract.ReasonStoreBasisInvalid)
	}
	normal := readerSigningQualifier{binding: basis.control.NormalSigning}
	var recovery candidateSigningQualifier
	if basis.control.Recovery != nil {
		recovery = readerSigningQualifier{binding: basis.control.Recovery.Signing}
	}
	anchor, result := anchorPublicCandidate(ctx, e.candidate, i.admission.domain, normal, recovery)
	if reason := i.admission.failure(ctx, operation, request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if result.Outcome != 0 {
		failed := readerSelectionFailure(result)
		if anchor.failureReason != "" {
			failed.diagnostic = anchor.failureReason
		}
		return empty, failed
	}
	// A succession is pinned to the independently supplied complete successor
	// basis. Its own signature and successor acceptance cannot choose that basis.
	if anchor.head.AuthKind == format.SuccessionAuth && !basis.successionSelected(anchor.head) {
		return empty, readerSelectionFailure(failure(EvidenceUnavailable, SigningUnavailable))
	}
	configID, err := contract.StoreConfigurationID(anchor.configuration)
	if err != nil || configID != i.admission.store.Identity || anchor.head.Core.Coordinate != i.admission.store.Coordinate || anchor.head.Core.NonBody != i.admission.store.NonBody {
		return empty, readerFailure{Result: failure(IntegrityFailure, ConstructionMismatch), diagnostic: contract.ReasonStoreBasisInvalid}
	}
	source, result := e.construct(ctx, anchor.configuration)
	i.source = source
	if reason := i.admission.failure(ctx, operation, request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if result != (Result{}) || source == nil {
		if result.Outcome == 0 || result.Outcome == ObservedCurrent || result.Outcome == Unchanged {
			result = refused(AdmissionInvalid)
		}
		return empty, readerSelectionFailure(result)
	}
	if source.Descriptor() != i.admission.store {
		return empty, readerFailure{Result: failure(IntegrityFailure, ConstructionMismatch), diagnostic: contract.ReasonStoreBasisInvalid}
	}
	readBasis, result := bindPublicReadBasis(ctx, anchor, source)
	if reason := i.admission.failure(ctx, operation, request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if result.Outcome != 0 {
		return empty, readerSelectionFailure(result)
	}
	return readBasis, readerFailure{}
}

func (i *readerInvocation) loadPublicSelection(ctx context.Context, operation string, request contract.ID, visitGenerated func(context.Context, *generatedSelection) error) (publicSelection, readerFailure) {
	var empty publicSelection
	readBasis, failed := i.loadPublicReadBasis(ctx, operation, request)
	if failed.Outcome != 0 {
		return empty, failed
	}
	selected, result := completePublicSelection(ctx, readBasis, visitGenerated)
	if reason := i.admission.failure(ctx, operation, request); reason != "" {
		return empty, readerRefusal(reason)
	}
	if result.Outcome != 0 {
		return empty, readerSelectionFailure(result)
	}
	return i.finishPublicSelection(ctx, operation, request, selected)
}

func (i *readerInvocation) finishPublicSelection(ctx context.Context, operation string, request contract.ID, selected publicSelection) (publicSelection, readerFailure) {
	var empty publicSelection
	basis, anchor := i.admission.basis, selected.basis.anchor
	// Enrollment in the independently trusted basis is historical. The complete
	// signed current closure owns recipient creation, metadata and retirement.
	for _, page := range selected.image.recipients {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row != nil && row.Status == contract.CurrentRecipient && (row.CurrentBinding == nil || row.CurrentBinding.Provider != basis.control.Provider) {
				return empty, readerFailure{Result: failure(IntegrityFailure, InvalidRelation), diagnostic: contract.ReasonTrustBasisInvalid}
			}
		}
	}
	actual, ok := selectedControlFrom(selected.image.root, &selected.image.recipients, selected.authorityID)
	if !ok {
		return empty, readerFailure{Result: failure(IntegrityFailure, InvalidRelation), diagnostic: contract.ReasonTrustBasisInvalid}
	}
	if !CurrentControlMatches(actual, basis.control) {
		return empty, readerSelectionFailure(failure(EvidenceUnavailable, SigningUnavailable))
	}
	if anchor.head.AuthKind == format.GenesisAuth {
		if !basis.genesisSelected(anchor.head) {
			return empty, readerFailure{Result: failure(IntegrityFailure, InvalidProof), diagnostic: contract.ReasonTrustBasisInvalid}
		}
	}
	if reason := i.admission.failure(ctx, operation, request); reason != "" {
		return empty, readerRefusal(reason)
	}
	// Retain authenticated positions and exact reference read reach, while
	// releasing support bodies already consumed by complete public validation.
	releasePublicSupportBodies(&selected)
	i.selection = selected
	return selected, readerFailure{}
}

func readerPublicBasisDigest(image PublicBasis, domain contract.ID, store contract.Descriptor) (contract.ID, contract.DiagnosticReason) {
	basis, reason := qualifyBorrowedReaderPublicBasis(image, domain, store)
	return basis.digest, reason
}
