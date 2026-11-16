package core

import (
	"bytes"
	"context"
	"math"
	"time"

	"enkv.sh/core/contract"
)

func ownReplacementPublicGoal(request ReplacementPublicRequest, public ReplacementPublicGoal) (ReplacementPublicGoal, error) {
	if public.Provider != request.Provider || (request.SigningSelector != "") != (public.Signing != nil) || (request.EncryptionSelector != "") != (public.Encryption != nil) {
		return ReplacementPublicGoal{}, contract.ErrRecord
	}
	if key := public.Signing; key != nil {
		if key.Selector != request.SigningSelector || key.Profile != contract.P256SigningProfile || key.Trust.IsZero() || contract.ValidatePublicSigningKey(key.SPKI, key.Fingerprint) != nil {
			return ReplacementPublicGoal{}, contract.ErrRecord
		}
		own := *key
		own.SPKI = bytes.Clone(key.SPKI)
		public.Signing = &own
	}
	if key := public.Encryption; key != nil {
		if key.Selector != request.EncryptionSelector || key.Profile != contract.RSAOAEPWrapProfile || key.ProtectionClass != contract.HardwareProtection && key.ProtectionClass != contract.SoftwareProtection || contract.ValidatePublicEncryptionKey(key.SPKI, key.Fingerprint) != nil {
			return ReplacementPublicGoal{}, contract.ErrRecord
		}
		own := *key
		own.SPKI = bytes.Clone(key.SPKI)
		public.Encryption = &own
	}
	return public, nil
}

func (s *StateSession) installedAuthorityGoal(goal RoleReplacementGoal, public ReplacementPublicGoal, deadline time.Time) *admittedAuthorityGoal {
	g := authorityGoal{Domain: s.admission.domain, Store: s.admission.store.Identity, Coordinate: s.admission.store.Coordinate, NonBody: s.admission.store.NonBody, Trust: s.admission.trust, Interpretation: s.admission.interpretation, ApprovalRole: goal.ApprovalRole}
	if key := public.Signing; key != nil {
		g.Roles |= 1
		g.Signing = &signingGoal{Provider: public.Provider, Profile: key.Profile, KeySelector: key.Selector, SPKI: bytes.Clone(key.SPKI), Fingerprint: key.Fingerprint, PublicKey: key.Fingerprint, Trust: key.Trust}
	}
	if key := public.Encryption; key != nil {
		g.Roles |= 2
		g.KMS = &kmsGoal{Provider: public.Provider, WrapProfile: key.Profile, ProtectionClass: key.ProtectionClass, KeySelector: key.Selector, SPKI: bytes.Clone(key.SPKI), Fingerprint: key.Fingerprint}
	}
	return &admittedAuthorityGoal{session: s, goal: g, deadline: deadline}
}

func replacementKMS(before contract.KMSBinding, key *ReplacementEncryptionKey, allocate func() (contract.ID, error)) (contract.KMSBinding, error) {
	after := before
	var err error
	after.BindingID, err = allocate()
	if err != nil {
		return contract.KMSBinding{}, err
	}
	if before.BindingSerial == math.MaxUint64 {
		after.BindingIncarnationID, err = allocate()
		after.BindingSerial = 1
	} else {
		after.BindingSerial++
	}
	if err != nil {
		return contract.KMSBinding{}, err
	}
	after.KeySelector, after.SPKI, after.Fingerprint = key.Selector, bytes.Clone(key.SPKI), key.Fingerprint
	after.WrapProfile, after.ProtectionClass = key.Profile, key.ProtectionClass
	_, err = contract.EncodeKMSBinding(after)
	return after, err
}
func replacementSigning(before contract.PublicSigningBinding, key *ReplacementSigningKey, allocate func() (contract.ID, error)) (contract.PublicSigningBinding, error) {
	after := before
	var err error
	after.BindingID, err = allocate()
	if err != nil {
		return contract.PublicSigningBinding{}, err
	}
	if before.Binding.Epoch == math.MaxUint64 {
		after.Binding.ControlIncarnationID, err = allocate()
		after.Binding.Epoch = 1
	} else {
		after.Binding.Epoch++
	}
	if err != nil {
		return contract.PublicSigningBinding{}, err
	}
	after.KeySelector, after.SPKI, after.Fingerprint = key.Selector, bytes.Clone(key.SPKI), key.Fingerprint
	after.SigningProfile, after.Binding.PublicKey, after.Binding.Trust = key.Profile, key.Fingerprint, key.Trust
	_, err = contract.EncodePublicSigningBinding(after)
	return after, err
}

func (e *installedReplacement) prepareRole(ctx context.Context, s *StateSession, i ReplacementInstallation, guard *installedMutationGuard, public ReplacementPublicGoal, goal *admittedAuthorityGoal, mask uint8, actor *installedReplacementActor, session contract.ID, allocate func() (contract.ID, error)) (*Candidate, contract.GeneratorDescriptor, Result) {
	fail := func(err error) (*Candidate, contract.GeneratorDescriptor, Result) {
		return nil, contract.GeneratorDescriptor{}, installedApplyPreparationFailure(err)
	}
	before := currentControlOf(s)
	after, err := replacementCallbackControl(before)
	if err != nil {
		return fail(err)
	}
	var successor *contract.PublicSigningBinding
	if mask&contract.SuccessionChangeNormalSigner != 0 {
		after.NormalSigning, err = replacementSigning(before.NormalSigning, public.Signing, allocate)
		successor = &after.NormalSigning
	}
	if err != nil {
		return fail(err)
	}
	if mask&contract.SuccessionChangeAuthorityKEK != 0 {
		after.AuthorityKMSBinding, err = replacementKMS(before.AuthorityKMSBinding, public.Encryption, allocate)
	}
	if err != nil {
		return fail(err)
	}
	if mask&contract.SuccessionChangeRecoverySigner != 0 {
		after.Recovery.Signing, err = replacementSigning(before.Recovery.Signing, public.Signing, allocate)
		successor = &after.Recovery.Signing
	}
	if err != nil {
		return fail(err)
	}
	if mask&contract.SuccessionChangeRecoveryKEK != 0 {
		after.Recovery.KMS, err = replacementKMS(before.Recovery.KMS, public.Encryption, allocate)
	}
	if err != nil {
		return fail(err)
	}
	seed := actor.admission
	if before.AccessGeneration == math.MaxUint64 {
		seed, err = allocate()
		if err != nil {
			return fail(err)
		}
	}
	access := s.root.CurrentAccess.Core
	if err := contract.AdvanceAccessGeneration(&access, seed); err != nil {
		return fail(err)
	}
	after.AccessGeneration, after.AccessIncarnationID = access.AccessGeneration, access.AccessIncarnationID
	actor.after, err = replacementCallbackControl(after)
	if err != nil {
		return fail(err)
	}
	actor.mask = mask
	operation := uint8(contract.SuccessionReplaceAuthority)
	if e.target == ReplacementTargetRecovery {
		operation = contract.SuccessionReplaceRecoveryBasis
	}
	request, plan, ok := s.planSuccession(ctx, after, operation, e.goal.ApprovalRole, mask, actor.admission, replacementMaterialRole(e.goal.MaterialSource))
	if !ok {
		return fail(contract.ErrRecord)
	}
	if err := actor.pinPlan(s, plan); err != nil {
		return fail(err)
	}
	descriptor, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		return fail(err)
	}
	subjects, err := contract.SuccessionChangedSubjectDescriptor(request)
	if err != nil {
		return fail(err)
	}
	if _, err := s.projectedSuccessionRoot(ctx, request, plan, subjects); err != nil {
		return fail(err)
	}
	c, err := replacementApplyContext(s, actor.admission, session, actor.deadline)
	if err != nil {
		return fail(err)
	}
	var source contract.BindingTableRow
	if mask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 {
		source = contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: before.AuthorityRecipientID, Binding: before.AuthorityKMSBinding}
		if e.goal.MaterialSource == ReplacementMaterialRecovery {
			source = contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: before.Recovery.RoleID, Binding: before.Recovery.KMS}
		}
	}
	actor.source = source
	q, rows, err := s.successionAccessRequest(ctx, request, plan, c, source)
	if err != nil {
		return fail(err)
	}
	permit := &AdmittedSuccession{session: s, request: request, plan: plan, descriptor: descriptor, context: q.Context, source: source, deadline: actor.deadline}
	if e.target == ReplacementTargetAuthority {
		permit.goal = goal
	}
	authorizer := before.NormalSigning
	if e.goal.ApprovalRole == contract.RecoverySigningRole {
		authorizer = before.Recovery.Signing
	}
	if guard.check(ctx) != contract.ReasonNone {
		return fail(contract.ErrRecord)
	}
	expectedSuccessor := successor
	authorizer.SPKI = bytes.Clone(authorizer.SPKI)
	if successor != nil {
		owned := *successor
		owned.SPKI = bytes.Clone(successor.SPKI)
		successor = &owned
	}
	signers, closeSigners, err := i.ConstructSigners(ctx, authorizer, successor)
	if closeSigners != nil {
		defer closeSigners()
	}
	if err != nil || closeSigners == nil || !replacementSignersValid(signers, authorizer, expectedSuccessor) {
		return fail(contract.ErrRecord)
	}
	signers.Authorizer = guard.Trust(signers.Authorizer)
	if signers.NormalSuccessor != nil {
		signers.NormalSuccessor = guard.QualifyingTrust(signers.NormalSuccessor)
	}
	if signers.RecoverySuccessor != nil {
		signers.RecoverySuccessor = guard.QualifyingTrust(signers.RecoverySuccessor)
	}
	if mask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 {
		target, _, ok := successionTarget(request)
		if !ok {
			return fail(contract.ErrRecord)
		}
		probe := contract.SuccessorKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, Context: q.Context, SubjectKind: target.SubjectKind, SubjectID: target.SubjectID}
		probe.ProbeID, err = allocate()
		if err != nil {
			return fail(err)
		}
		probe.SuccessorBindingDigest, err = contract.PublicBindingDigest(target.Binding)
		if err != nil {
			return fail(err)
		}
		if guard.check(ctx) != contract.ReasonNone {
			return fail(contract.ErrRecord)
		}
		callbackQ, err := replacementCallbackAccess(q)
		if err != nil {
			return fail(err)
		}
		callbackRequest, err := replacementCallbackRoleRequest(request)
		if err != nil {
			return fail(err)
		}
		callbackSource := source
		callbackSource.Binding.SPKI = bytes.Clone(source.Binding.SPKI)
		custody, err := i.AdmitSuccessionCustody(ctx, callbackQ, callbackRequest, callbackRequest.BeforeControl, callbackSource, probe, replacementCallbackRows(rows), actor.deadline)
		if custody != nil && custody.Close != nil {
			defer custody.Close()
		}
		if err != nil || custody == nil || custody.Crypto == nil || custody.Close == nil || custody.Crypto.InstanceID().IsZero() {
			return fail(contract.ErrRecord)
		}
		permit.probe, permit.crypto, permit.instance = probe, custody.Crypto, custody.Crypto.InstanceID()
	}
	if guard.check(ctx) != contract.ReasonNone {
		return fail(contract.ErrRecord)
	}
	candidate, result := s.PrepareSuccession(ctx, permit, signers)
	return candidate, subjects, result
}

func (e *installedReplacement) prepareRecipient(ctx context.Context, s *StateSession, i ReplacementInstallation, guard *installedMutationGuard, public ReplacementPublicGoal, actor *installedReplacementActor, session contract.ID, allocate func() (contract.ID, error)) (*Candidate, contract.GeneratorDescriptor, Result) {
	fail := func(err error) (*Candidate, contract.GeneratorDescriptor, Result) {
		return nil, contract.GeneratorDescriptor{}, installedApplyPreparationFailure(err)
	}
	before := *s.recipientRecord(e.recipient).CurrentBinding
	successor, err := replacementKMS(before, public.Encryption, allocate)
	if err != nil {
		return fail(err)
	}
	intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: s.admission.domain, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, RecipientID: e.recipient}, Before: before, Successor: successor}
	actor.intent = intent
	actor.intent.Before.SPKI = bytes.Clone(intent.Before.SPKI)
	actor.intent.Successor.SPKI = bytes.Clone(intent.Successor.SPKI)
	plan, ok := s.planRecipientReplacement(ctx, intent)
	if !ok {
		return fail(contract.ErrRecord)
	}
	if err := actor.pinPlan(s, plan); err != nil {
		return fail(err)
	}
	c, err := replacementApplyContext(s, actor.admission, session, actor.deadline)
	if err != nil {
		return fail(err)
	}
	q, request, rows, err := s.replacementRequest(ctx, intent, plan, c)
	if err != nil {
		return fail(err)
	}
	actor.requestDigest, err = contract.RequestDigest(request)
	if err != nil {
		return fail(err)
	}
	subjects, err := s.recipientReplacementSubjects(ctx, intent, rows)
	if err != nil {
		return fail(err)
	}
	if _, err := s.projectedRecipientReplacementRoot(ctx, plan, subjects, q.Context.IntentDescriptor.Digest); err != nil {
		return fail(err)
	}
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		return fail(err)
	}
	if guard.check(ctx) != contract.ReasonNone {
		return fail(contract.ErrRecord)
	}
	authorizer := currentControlOf(s).NormalSigning
	authorizer.SPKI = bytes.Clone(authorizer.SPKI)
	signers, closeSigners, err := i.ConstructSigners(ctx, authorizer, nil)
	if closeSigners != nil {
		defer closeSigners()
	}
	if err != nil || closeSigners == nil || !replacementSignersValid(signers, authorizer, nil) {
		return fail(contract.ErrRecord)
	}
	if guard.check(ctx) != contract.ReasonNone {
		return fail(contract.ErrRecord)
	}
	callbackQ, err := replacementCallbackAccess(q)
	if err != nil {
		return fail(err)
	}
	callbackControl, err := replacementCallbackControl(currentControlOf(s))
	if err != nil {
		return fail(err)
	}
	callbackIntent := intent
	callbackIntent.Before.SPKI = bytes.Clone(intent.Before.SPKI)
	callbackIntent.Successor.SPKI = bytes.Clone(intent.Successor.SPKI)
	custody, err := i.AdmitRecipientCustody(ctx, callbackQ, callbackIntent, request, callbackControl, replacementCallbackRows(rows), actor.deadline)
	if custody != nil && custody.Close != nil {
		defer custody.Close()
	}
	if err != nil || custody == nil || custody.Crypto == nil || custody.Close == nil || custody.Crypto.InstanceID().IsZero() {
		return fail(contract.ErrRecord)
	}
	permit := &AdmittedRecipientReplacement{session: s, intent: intent, plan: plan, context: q.Context, requestDigest: contract.Hash(body), requestLength: len(body), crypto: custody.Crypto, instance: custody.Crypto.InstanceID(), deadline: actor.deadline}
	if guard.check(ctx) != contract.ReasonNone {
		return fail(contract.ErrRecord)
	}
	candidate, result := s.PrepareRecipientReplacement(ctx, permit, guard.Trust(signers.Authorizer))
	return candidate, subjects, result
}

func replacementApplyContext(s *StateSession, admission, session contract.ID, deadline time.Time) (contract.ApplyContext, error) {
	c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, AdmissionID: admission, SessionID: session, DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		return contract.ApplyContext{}, err
	}
	copy(c.PredecessorRootRef[:], root)
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	return c, err
}

func replacementSignersValid(signers SuccessionSigners, authorizer contract.PublicSigningBinding, successor *contract.PublicSigningBinding) bool {
	if signers.Authorizer == nil || signers.Authorizer.Family() != authorizer.Provider || signers.Authorizer.Identity() != authorizer.Binding.Trust {
		return false
	}
	if successor == nil {
		return signers.NormalSuccessor == nil && signers.RecoverySuccessor == nil
	}
	var route contract.QualifyingTrust
	switch successor.Role {
	case contract.NormalSigningRole:
		if signers.RecoverySuccessor != nil {
			return false
		}
		route = signers.NormalSuccessor
	case contract.RecoverySigningRole:
		if signers.NormalSuccessor != nil {
			return false
		}
		route = signers.RecoverySuccessor
	default:
		return false
	}
	return route != nil && route.Family() == successor.Provider && route.Identity() == successor.Binding.Trust
}
