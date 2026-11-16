package core

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The provider owns a fixed, independently supplied signing selector. Core
// gives it the selected binding only for equality and public-key qualification.
// This interface grants no Sign capability.
type candidateSigningQualifier = ReconstructionSigningAnchor

type candidateSigningQualification struct {
	contract.SigningQualificationResult
	outOfBasis bool
}

type candidateBasisQualifier interface {
	qualifyCandidateSigningBinding(context.Context, contract.PublicSigningBinding) candidateSigningQualification
}

func qualifyCandidateSigningBinding(ctx context.Context, qualifier candidateSigningQualifier, offered contract.PublicSigningBinding) candidateSigningQualification {
	if qualified, ok := qualifier.(candidateBasisQualifier); ok {
		return qualified.qualifyCandidateSigningBinding(ctx, offered)
	}
	return candidateSigningQualification{SigningQualificationResult: qualifier.QualifySigningBinding(ctx, offered)}
}

type qualifiedCandidateAnchor struct {
	binding contract.PublicSigningBinding
	role    uint8
}

// qualifyCandidateSelection tries only roles with a verified complete-selection
// signature. An unavailable normal lookup may fall through to an applicable
// recovery anchor; an adequate normal result stops before any recovery lookup.
func qualifyCandidateSelection(ctx context.Context, h format.Head, root format.Root, normal, recovery candidateSigningQualifier) (qualifiedCandidateAnchor, Result) {
	if ctx == nil || ctx.Err() != nil {
		return qualifiedCandidateAnchor{}, refused(AdmissionInvalid)
	}
	control := root.CurrentAccess.Core.CurrentControl
	if control.CompatibilityID != contract.CompatibilityID() || control.CryptoSupportID != contract.CryptoSupportID() ||
		control.NormalSigning.Binding.Interpretation != contract.InterpretationID() {
		return qualifiedCandidateAnchor{}, refused(AdmissionInvalid)
	}
	var eligibleProof, unavailable, invalid bool
	for _, row := range []struct {
		role      uint8
		qualifier candidateSigningQualifier
		target    uint8
	}{
		{contract.NormalSigningRole, normal, contract.NormalSignerTarget},
		{contract.RecoverySigningRole, recovery, contract.RecoverySignerTarget},
	} {
		binding, eligible := candidateSelectionSignature(h, root, row.role)
		if !eligible {
			continue
		}
		eligibleProof = true
		if row.qualifier == nil {
			unavailable = true
			continue
		}
		if ctx.Err() != nil {
			return qualifiedCandidateAnchor{}, failure(EvidenceUnavailable, SigningUnavailable)
		}
		digest, err := contract.SigningBindingDigest(binding)
		if err != nil {
			invalid = true
			continue
		}
		offered := binding
		offered.SPKI = bytes.Clone(binding.SPKI)
		result := qualifyCandidateSigningBinding(ctx, row.qualifier, offered)
		if ctx.Err() != nil {
			return qualifiedCandidateAnchor{}, failure(EvidenceUnavailable, SigningUnavailable)
		}
		if !result.outOfBasis && result.Qualified == 1 && result.Reason == contract.ReasonNone &&
			result.TargetRole == row.target && result.Provider == binding.Provider && result.SigningBindingDigest == digest {
			binding.SPKI = bytes.Clone(binding.SPKI)
			return qualifiedCandidateAnchor{binding: binding, role: row.role}, Result{}
		}
		if result.Qualified == 0 && (result.outOfBasis || result.Reason == contract.ReasonAccess || result.Reason == contract.ReasonTransport || result.Reason == contract.ReasonLimit) {
			unavailable = true
		} else {
			invalid = true
		}
	}
	if unavailable {
		return qualifiedCandidateAnchor{}, failure(EvidenceUnavailable, SigningUnavailable)
	}
	if !eligibleProof || invalid {
		return qualifiedCandidateAnchor{}, failure(IntegrityFailure, InvalidProof)
	}
	return qualifiedCandidateAnchor{}, failure(IntegrityFailure, InvalidProof)
}

// candidateSelectionSignature checks whether one selected current signer has a
// valid signature over this complete HEAD/root selection. The binding is still
// untrusted. A caller must qualify it against an independently supplied signing
// resource before treating this result as an anchor. Child and registry proof
// relations remain for the complete reader.
func candidateSelectionSignature(h format.Head, root format.Root, role uint8) (contract.PublicSigningBinding, bool) {
	var none contract.PublicSigningBinding
	if role != contract.NormalSigningRole && role != contract.RecoverySigningRole {
		return none, false
	}
	if _, err := format.EncodeHead(h); err != nil {
		return none, false
	}
	encodedRoot, err := format.EncodeRoot(root)
	if err != nil || format.CheckReference(h.Core.Root, encodedRoot) != nil || h.Core.Root.Kind != contract.RootKind ||
		h.Core.Root.Index != 0 || h.Core.Domain != root.Domain || h.Core.Root.Object != root.Snapshot {
		return none, false
	}
	access := root.CurrentAccess
	accessRoot, err := contract.AccessRoot(access.Core)
	if err != nil || accessRoot != access.AccessRoot {
		return none, false
	}
	control := access.Core.CurrentControl
	if control.TrustInterpretationID != contract.TrustInterpretationID() || h.Core.Store != control.StoreID || h.Core.Coordinate != control.CoordinateID ||
		h.Core.NonBody != control.NonBodyID || h.Core.Interpretation != control.NormalSigning.Binding.Interpretation ||
		h.Core.Trust != control.NormalSigning.Binding.Trust || h.Core.Epoch != control.NormalSigning.Binding.Epoch ||
		!currentSigningProofs(h, contract.ControlCore{CurrentControl: control}) {
		return none, false
	}
	binding := control.NormalSigning
	if role == contract.RecoverySigningRole {
		if control.Recovery == nil {
			return none, false
		}
		binding = control.Recovery.Signing
	}
	key, ok := publicKey(binding.SPKI)
	if !ok {
		return none, false
	}
	if h.AuthKind == format.SuccessionAuth {
		if h.Succession == nil || h.Succession.Subject.AfterAccessRoot != access.AccessRoot ||
			!successionProofValid(h) || !selectionAcceptanceValid(h, root) {
			return none, false
		}
		if signingBindingEqual(h.Succession.Authorizer, binding) {
			return binding, true
		}
		digest, err := contract.SigningBindingDigest(binding)
		if err != nil {
			return none, false
		}
		for _, proof := range h.Succession.Acceptances {
			if proof.Role == role && proof.BindingDigest == digest {
				return binding, true
			}
		}
		return none, false
	}
	if role != contract.NormalSigningRole {
		return none, false
	}
	var request contract.SignRequest
	switch h.AuthKind {
	case format.GenesisAuth:
		if h.Genesis == nil {
			return none, false
		}
		request, err = contract.NewGenesisRequest(h.Genesis.Subject)
	case format.GeneratorAuth:
		if h.Generator == nil {
			return none, false
		}
		request, err = contract.NewGeneratorRequest(*h.Generator)
	case format.GCAuth:
		if h.GC == nil {
			return none, false
		}
		request, err = contract.NewGCRequest(*h.GC)
	case format.AdministrativeAuth:
		if h.EndWork == nil {
			return none, false
		}
		request, err = contract.NewEndWorkRequest(*h.EndWork)
	case format.OutputReserveAuth:
		if h.OutputReserve == nil {
			return none, false
		}
		request, err = contract.NewOutputReserveRequest(*h.OutputReserve)
	case format.OutputCloseAuth:
		if h.OutputClose == nil {
			return none, false
		}
		request, err = contract.NewOutputCloseRequest(*h.OutputClose)
	case format.LifecycleAuth:
		if h.Subject.Request != requestCommitment(h.Core, h.Subject) {
			return none, false
		}
		request, err = contract.NewLifecycleRequest(h.Subject)
	default:
		return none, false
	}
	if err != nil || !verify(key, request, h.AuthorizationSignature) {
		return none, false
	}
	return binding, true
}
