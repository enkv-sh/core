package core

import (
	"bytes"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func observationSigningStep(before, after contract.PublicSigningBinding) bool {
	return before.BindingID != after.BindingID && before.KeySelector != after.KeySelector && !bytes.Equal(before.SPKI, after.SPKI) && before.Fingerprint != after.Fingerprint && contract.IncarnationCounterStep(before.Binding.ControlIncarnationID, before.Binding.Epoch, after.Binding.ControlIncarnationID, after.Binding.Epoch) && before.Schema == after.Schema && before.Role == after.Role && before.Provider == after.Provider && before.SigningProfile == after.SigningProfile && before.Binding.Domain == after.Binding.Domain && before.Binding.Store == after.Binding.Store && before.Binding.Coordinate == after.Binding.Coordinate && before.Binding.Trust == after.Binding.Trust && before.Binding.Interpretation == after.Binding.Interpretation
}
func observationKMSChange(before, after contract.KMSBinding) bool {
	return before.BindingID != after.BindingID && before.KeySelector != after.KeySelector && !bytes.Equal(before.SPKI, after.SPKI) && before.Fingerprint != after.Fingerprint && before.Provider == after.Provider && contract.IncarnationCounterStep(before.BindingIncarnationID, before.BindingSerial, after.BindingIncarnationID, after.BindingSerial)
}
func cloneReplacementObservationControl(control contract.ControlCore) (contract.ControlCore, error) {
	return replacementCallbackControl(control)
}
func qualifyReplacementObservation(i ReplacementObservationInstallation, before, after readerPublicBasis, head format.Head) bool {
	correlation, goal := i.Correlation, i.Goal
	if correlation.RequestIdentity.IsZero() || head.Core.Domain != i.ExpectedDomain || head.Core.Store != i.ExpectedStore.Identity || head.Core.Coordinate != i.ExpectedStore.Coordinate || head.Core.NonBody != i.ExpectedStore.NonBody || head.Core.Interpretation != contract.InterpretationID() {
		return false
	}
	b, a := before.control, after.control
	if goal.ApprovalRole != contract.NormalSigningRole && goal.ApprovalRole != contract.RecoverySigningRole || goal.ApprovalRole == contract.RecoverySigningRole && b.Recovery == nil || goal.SigningSelector == "" && goal.EncryptionSelector == "" {
		return false
	}
	if goal.SigningSelector != "" && !contract.PublicKeySelectorValid(b.Provider, goal.SigningSelector, true) || goal.EncryptionSelector != "" && !contract.PublicKeySelectorValid(b.Provider, goal.EncryptionSelector, false) {
		return false
	}
	if goal.EncryptionSelector == "" {
		if goal.MaterialSource != 0 {
			return false
		}
	} else if goal.MaterialSource != ReplacementMaterialAuthority && (goal.MaterialSource != ReplacementMaterialRecovery || b.Recovery == nil) {
		return false
	}
	if correlation.Target == ReplacementTargetRecipient {
		if correlation.RecipientID.IsZero() || goal.ApprovalRole != contract.NormalSigningRole || goal.SigningSelector != "" || goal.MaterialSource != ReplacementMaterialAuthority || head.AuthKind != format.LifecycleAuth || head.Subject.Recipient != b.AuthorityRecipientID || !controlEqual(b, a) || !selectedHeadProofs(head, b, nil) {
			return false
		}
		old, next := i.RecipientBefore, i.RecipientAfter
		if _, err := contract.KMSBindingLength(old); err != nil {
			return false
		}
		if _, err := contract.KMSBindingLength(next); err != nil {
			return false
		}
		if next.KeySelector != goal.EncryptionSelector || old.BindingID == next.BindingID || old.Provider != next.Provider || next.Provider != b.Provider || !contract.IncarnationCounterStep(old.BindingIncarnationID, old.BindingSerial, next.BindingIncarnationID, next.BindingSerial) {
			return false
		}
		intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: contract.RSAOAEPWrapProfile, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: i.ExpectedDomain, BeforeAccessRoot: head.Subject.BeforeAccessRoot, RecipientID: correlation.RecipientID}, Before: old, Successor: next}
		descriptor, err := contract.RecipientReplacementIntentDescriptor(intent)
		return err == nil && head.Subject.Normal.Intent == (contract.DigestLength{Digest: descriptor.Digest, Length: descriptor.Length})
	}
	if !correlation.RecipientID.IsZero() || head.AuthKind != format.SuccessionAuth || head.Succession == nil || !bytes.Equal(i.SuccessorBasis.Selection, correlation.SignedCandidate) || !successionProofValid(head) || !currentSigningProofs(head, a) || !successorEvidenceValid(head, a) {
		return false
	}
	subject := head.Succession.Subject
	material := uint8(contract.SuccessionMaterialNone)
	switch goal.MaterialSource {
	case ReplacementMaterialAuthority:
		material = contract.SuccessionMaterialAuthority
	case ReplacementMaterialRecovery:
		material = contract.SuccessionMaterialRecovery
	case 0:
	default:
		return false
	}
	if subject.RequestIdentityDigest != correlation.RequestIdentity || subject.MaterialSourceRole != material || subject.ApprovalRole != goal.ApprovalRole {
		return false
	}
	authorizer := b.NormalSigning
	if goal.ApprovalRole == contract.RecoverySigningRole {
		authorizer = b.Recovery.Signing
	}
	if !signingBindingEqual(authorizer, head.Succession.Authorizer) {
		return false
	}
	bf, af := b.CurrentControlFields, a.CurrentControlFields
	bf.AccessIncarnationID, af.AccessIncarnationID = contract.ID{}, contract.ID{}
	bf.AccessGeneration, af.AccessGeneration = 0, 0
	if bf != af || (b.Recovery == nil) != (a.Recovery == nil) {
		return false
	}
	var permitted, kind uint8
	switch correlation.Target {
	case ReplacementTargetAuthority:
		kind = contract.SuccessionReplaceAuthority
		if goal.SigningSelector != "" {
			permitted |= contract.SuccessionChangeNormalSigner
		}
		if goal.EncryptionSelector != "" {
			permitted |= contract.SuccessionChangeAuthorityKEK
		}
		if b.Recovery != nil && (!signingBindingEqual(b.Recovery.Signing, a.Recovery.Signing) || !kmsBindingEqual(b.Recovery.KMS, a.Recovery.KMS) || b.Recovery.RoleID != a.Recovery.RoleID) {
			return false
		}
	case ReplacementTargetRecovery:
		if b.Recovery == nil {
			return false
		}
		kind = contract.SuccessionReplaceRecoveryBasis
		if goal.SigningSelector != "" {
			permitted |= contract.SuccessionChangeRecoverySigner
		}
		if goal.EncryptionSelector != "" {
			permitted |= contract.SuccessionChangeRecoveryKEK
		}
		if !signingBindingEqual(b.NormalSigning, a.NormalSigning) || !kmsBindingEqual(b.AuthorityKMSBinding, a.AuthorityKMSBinding) || b.Recovery.RoleID != a.Recovery.RoleID {
			return false
		}
	default:
		return false
	}
	if subject.OperationKind != kind || subject.ChangeMask == 0 || subject.ChangeMask & ^permitted != 0 || correlation.Target == ReplacementTargetRecovery && subject.ChangeMask != permitted {
		return false
	}
	pairs := []struct {
		bit       uint8
		old, next contract.PublicSigningBinding
	}{{contract.SuccessionChangeNormalSigner, b.NormalSigning, a.NormalSigning}}
	keks := []struct {
		bit       uint8
		old, next contract.KMSBinding
	}{{contract.SuccessionChangeAuthorityKEK, b.AuthorityKMSBinding, a.AuthorityKMSBinding}}
	if b.Recovery != nil {
		pairs = append(pairs, struct {
			bit       uint8
			old, next contract.PublicSigningBinding
		}{contract.SuccessionChangeRecoverySigner, b.Recovery.Signing, a.Recovery.Signing})
		keks = append(keks, struct {
			bit       uint8
			old, next contract.KMSBinding
		}{contract.SuccessionChangeRecoveryKEK, b.Recovery.KMS, a.Recovery.KMS})
	}
	for _, pair := range pairs {
		if subject.ChangeMask&pair.bit != 0 {
			if !observationSigningStep(pair.old, pair.next) {
				return false
			}
		} else if !signingBindingEqual(pair.old, pair.next) {
			return false
		}
	}
	for _, pair := range keks {
		if subject.ChangeMask&pair.bit != 0 {
			if !observationKMSChange(pair.old, pair.next) {
				return false
			}
		} else if !kmsBindingEqual(pair.old, pair.next) {
			return false
		}
	}
	signing, encryption := a.NormalSigning, a.AuthorityKMSBinding
	if correlation.Target == ReplacementTargetRecovery {
		signing, encryption = a.Recovery.Signing, a.Recovery.KMS
	}
	return (goal.SigningSelector == "" || goal.SigningSelector == signing.KeySelector) && (goal.EncryptionSelector == "" || goal.EncryptionSelector == encryption.KeySelector)
}
