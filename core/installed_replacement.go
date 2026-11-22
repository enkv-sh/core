package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"math"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type InstalledAuthorityReplacement struct{ owner *installedReplacement }
type InstalledRecoveryReplacement struct{ owner *installedReplacement }
type InstalledRecipientReplacement struct{ owner *installedReplacement }

type installedReplacement struct {
	mu           sync.Mutex
	installation ReplacementInstallation
	target       ReplacementTarget
	goal         RoleReplacementGoal
	recipient    contract.ID
	recipientRow uint16
	used, closed bool
	cancel       context.CancelFunc
	done         chan struct{}
	closeOnce    sync.Once
	entropy      io.Reader
}

func NewInstalledAuthorityReplacement(i AuthorityReplacementInstallation) (*InstalledAuthorityReplacement, error) {
	e, err := newInstalledReplacement(i.ReplacementInstallation, ReplacementTargetAuthority, i.Goal, contract.ID{}, 0)
	if err != nil {
		return nil, err
	}
	return &InstalledAuthorityReplacement{owner: e}, nil
}
func NewInstalledRecoveryReplacement(i RecoveryReplacementInstallation) (*InstalledRecoveryReplacement, error) {
	e, err := newInstalledReplacement(i.ReplacementInstallation, ReplacementTargetRecovery, i.Goal, contract.ID{}, 0)
	if err != nil {
		return nil, err
	}
	return &InstalledRecoveryReplacement{owner: e}, nil
}
func NewInstalledRecipientReplacement(i RecipientReplacementInstallation) (*InstalledRecipientReplacement, error) {
	goal := RoleReplacementGoal{ApprovalRole: contract.NormalSigningRole, EncryptionSelector: i.EncryptionSelector, MaterialSource: ReplacementMaterialAuthority}
	e, err := newInstalledReplacement(i.ReplacementInstallation, ReplacementTargetRecipient, goal, i.RecipientID, i.RecipientRow)
	if err != nil {
		return nil, err
	}
	return &InstalledRecipientReplacement{owner: e}, nil
}

func newInstalledReplacement(i ReplacementInstallation, target ReplacementTarget, goal RoleReplacementGoal, recipient contract.ID, row uint16) (*installedReplacement, error) {
	if i.Store == nil || i.Store.Descriptor() != i.ExpectedStore || i.ExpectedDomain.IsZero() || i.CompositionID.IsZero() || i.FileIdentity.IsZero() ||
		i.SourceUnchanged == nil || i.ResolvePublicGoal == nil || i.ConstructSigners == nil || i.PublishSuccessor == nil || i.CloseInstalled == nil ||
		goal.ApprovalRole != contract.NormalSigningRole && goal.ApprovalRole != contract.RecoverySigningRole || goal.SigningSelector == "" && goal.EncryptionSelector == "" {
		return nil, contract.ErrRecord
	}
	if !replacementSelector(i.ExpectedStore.Family, goal.SigningSelector, true) || !replacementSelector(i.ExpectedStore.Family, goal.EncryptionSelector, false) {
		return nil, contract.ErrRecord
	}
	if goal.EncryptionSelector == "" {
		if goal.MaterialSource != 0 || i.AdmitSuccessionCustody != nil || i.AdmitRecipientCustody != nil {
			return nil, contract.ErrRecord
		}
	} else if goal.MaterialSource != ReplacementMaterialAuthority && goal.MaterialSource != ReplacementMaterialRecovery {
		return nil, contract.ErrRecord
	}
	if target == ReplacementTargetRecipient {
		if recipient.IsZero() || int(row) >= len(i.CapturedRecipients) || i.CapturedRecipients[row].RecipientID != recipient || i.AdmitRecipientCustody == nil || i.AdmitSuccessionCustody != nil {
			return nil, contract.ErrRecord
		}
	} else if !recipient.IsZero() || i.AdmitRecipientCustody != nil || goal.EncryptionSelector != "" && i.AdmitSuccessionCustody == nil {
		return nil, contract.ErrRecord
	}
	basis, err := i.PublicBasis.own()
	if err != nil {
		return nil, err
	}
	control, err := basis.ControlCore(i.ExpectedDomain, i.ExpectedStore)
	if err != nil || !CurrentControlMatches(i.ExpectedControl, control) || goal.ApprovalRole == contract.RecoverySigningRole && control.Recovery == nil ||
		goal.MaterialSource == ReplacementMaterialRecovery && control.Recovery == nil || target == ReplacementTargetRecovery && control.Recovery == nil {
		return nil, contract.ErrRecord
	}
	i.ExpectedControl, err = replacementCallbackControl(i.ExpectedControl)
	if err != nil {
		return nil, err
	}
	i.CapturedRecipients, err = ownReplacementRecipients(i.CapturedRecipients)
	if err != nil {
		return nil, err
	}
	i.PublicBasis = basis
	return &installedReplacement{installation: i, target: target, goal: goal, recipient: recipient, recipientRow: row, entropy: rand.Reader}, nil
}

func replacementSelector(family contract.Family, selector string, signing bool) bool {
	if selector == "" {
		return true
	}
	if family == contract.GCP {
		_, ok := contract.ParseGCPKeySelector(selector, signing)
		return ok
	}
	if family == contract.AWS {
		_, ok := contract.ParseAWSKeySelector(selector, signing)
		return ok
	}
	return false
}

func ownReplacementRecipients(rows []ReplacementRecipientFact) ([]ReplacementRecipientFact, error) {
	// The nominated row uses a uint16 position. Preserve duplicate multiplicity
	// and order; pending local rows need not describe current selected members.
	if len(rows) > math.MaxUint16+1 {
		return nil, contract.ErrRecordCapacity
	}
	owned := make([]ReplacementRecipientFact, len(rows))
	for i, row := range rows {
		if row.RecipientID.IsZero() {
			return nil, contract.ErrRecord
		}
		body, err := contract.EncodeKMSBinding(row.Encryption)
		if err != nil {
			return nil, err
		}
		binding, err := contract.DecodeKMSBinding(body)
		if err != nil {
			return nil, err
		}
		owned[i] = ReplacementRecipientFact{RecipientID: row.RecipientID, Encryption: binding}
	}
	return owned, nil
}

func (e *InstalledAuthorityReplacement) Replace(ctx context.Context, id contract.ID) PublicReplacementResult {
	var owner *installedReplacement
	if e != nil {
		owner = e.owner
	}
	return owner.replace(ctx, id, telemetry.OpCoreReplaceAuthorityKeys)
}
func (e *InstalledRecoveryReplacement) Replace(ctx context.Context, id contract.ID) PublicReplacementResult {
	var owner *installedReplacement
	if e != nil {
		owner = e.owner
	}
	return owner.replace(ctx, id, telemetry.OpCoreReplaceRecoveryKeys)
}
func (e *InstalledRecipientReplacement) Replace(ctx context.Context, id contract.ID) PublicReplacementResult {
	var owner *installedReplacement
	if e != nil {
		owner = e.owner
	}
	return owner.replace(ctx, id, telemetry.OpCoreReplaceRecipientKey)
}
func (e *InstalledAuthorityReplacement) Close() {
	if e != nil {
		e.owner.close()
	}
}
func (e *InstalledRecoveryReplacement) Close() {
	if e != nil {
		e.owner.close()
	}
}
func (e *InstalledRecipientReplacement) Close() {
	if e != nil {
		e.owner.close()
	}
}
func (e *installedReplacement) close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		cancel, done := e.cancel, e.done
		e.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
		e.installation.CloseInstalled()
	})
}

func (e *installedReplacement) replace(ctx context.Context, id contract.ID, operation telemetry.Operation) (out PublicReplacementResult) {
	call := telemetry.Start(ctx, telemetry.ProviderCore, operation)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out = e.replaceAdmitted(ctx, id, call)
	finishCore(call, out.Result)
	return out
}

func (e *installedReplacement) replaceAdmitted(ctx context.Context, id contract.ID, call *telemetry.Call) (out PublicReplacementResult) {
	out.RequestID = id
	out.Result = refused(AdmissionInvalid)
	if e == nil || ctx == nil || id.IsZero() || ctx.Err() != nil {
		return out
	}
	deadline, ok := ctx.Deadline()
	if !ok || !validPrivateDeadline(deadline) {
		return out
	}
	ctx, cancel := context.WithDeadline(telemetry.CallContext(ctx, call), deadline)
	e.mu.Lock()
	if e.used || e.closed {
		e.mu.Unlock()
		cancel()
		return out
	}
	e.used = true
	e.cancel = cancel
	e.done = make(chan struct{})
	done := e.done
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		close(done)
		e.done = nil
		e.cancel = nil
		e.mu.Unlock()
	}()
	i := e.installation
	guard, err := newInstalledMutationGuard(i.Store, i.SourceUnchanged)
	if err != nil || guard.check(ctx) != contract.ReasonNone {
		return out
	}
	i.Store = guard.Store()
	admitted, result := admitReplacementPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.Store, i.CompositionID)
	if result.Outcome != ObservedCurrent {
		out.Result = result
		return out
	}
	var s *StateSession
	narrow := e.target == ReplacementTargetAuthority && e.goal.ApprovalRole == contract.RecoverySigningRole && e.goal.EncryptionSelector == ""
	s, result = openReplacementSession(ctx, admitted, i.Store, narrow)
	if s == nil {
		out.Result = result
		return out
	}
	if guard.check(ctx) != contract.ReasonNone {
		return out
	}
	if !CurrentControlMatches(currentControlOf(s), i.ExpectedControl) {
		out.Result = refused(ConstructionMismatch)
		return out
	}
	out.DomainID = s.root.Domain
	out.WarningBits = s.root.WarningBits
	if e.goal.ApprovalRole == contract.RecoverySigningRole && s.root.CurrentAccess.Core.Recovery == nil {
		return out
	}
	if e.target == ReplacementTargetRecipient {
		if !s.root.Generated.ActiveOwner.IsZero() {
			out.Result = refused(InvalidRelation)
			return out
		}
		r := s.recipientRecord(e.recipient)
		if r == nil || r.Status != contract.CurrentRecipient || r.CurrentBinding == nil || e.recipient == s.admission.recipient || !kmsBindingEqual(*r.CurrentBinding, i.CapturedRecipients[e.recipientRow].Encryption) {
			return out
		}
	}
	publicRequest := ReplacementPublicRequest{Provider: i.ExpectedStore.Family, SigningSelector: e.goal.SigningSelector, EncryptionSelector: e.goal.EncryptionSelector}
	if e.goal.SigningSelector != "" {
		publicRequest.SigningRole = contract.NormalSigningRole
		if e.target == ReplacementTargetRecovery {
			publicRequest.SigningRole = contract.RecoverySigningRole
		}
	}
	public, err := i.ResolvePublicGoal(ctx, publicRequest)
	if err != nil || guard.check(ctx) != contract.ReasonNone {
		return out
	}
	public, err = ownReplacementPublicGoal(publicRequest, public)
	if err != nil {
		return out
	}
	goal := s.installedAuthorityGoal(e.goal, public, deadline)
	var mask uint8
	switch e.target {
	case ReplacementTargetAuthority:
		mask, result = s.compareAuthorityGoal(ctx, goal)
		if result.Outcome != ObservedCurrent {
			out.Result = result
			if result.Outcome == Unchanged {
				observation, err := s.authorityReplacementNoWork(ctx, goal, e.goal.MaterialSource)
				if err != nil {
					out.Result = installedApplyPreparationFailure(err)
					return out
				}
				if guard.check(ctx) != contract.ReasonNone {
					out.Result = refused(AdmissionInvalid)
					return out
				}
				out.NoWorkObservation = observation
				out.OperationID = observation.OperationID
				out.RequestIdentity = observation.RequestIdentity
			}
			return out
		}
	case ReplacementTargetRecovery:
		recovery := currentControlOf(s).Recovery
		if recovery == nil {
			return out
		}
		if public.Signing != nil {
			if recovery.Signing.KeySelector == public.Signing.Selector || recovery.Signing.Fingerprint == public.Signing.Fingerprint || bytes.Equal(recovery.Signing.SPKI, public.Signing.SPKI) {
				out.Result = refused(InvalidIntent)
				return out
			}
			mask |= contract.SuccessionChangeRecoverySigner
		}
		if public.Encryption != nil {
			if recovery.KMS.KeySelector == public.Encryption.Selector || recovery.KMS.Fingerprint == public.Encryption.Fingerprint || bytes.Equal(recovery.KMS.SPKI, public.Encryption.SPKI) {
				out.Result = refused(InvalidIntent)
				return out
			}
			mask |= contract.SuccessionChangeRecoveryKEK
		}
	}
	s.admission.entropy = e.entropy
	ids, err := s.closureIDsMode(ctx, narrow)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	control := currentControlOf(s)
	ids[control.AccessIncarnationID] = true
	ids[control.NormalSigning.Binding.ControlIncarnationID] = true
	ids[control.AuthorityKMSBinding.BindingIncarnationID] = true
	if control.Recovery != nil {
		ids[control.Recovery.Signing.Binding.ControlIncarnationID] = true
		ids[control.Recovery.KMS.BindingIncarnationID] = true
	}
	for _, row := range s.registry() {
		if row.CurrentBinding != nil {
			ids[row.CurrentBinding.BindingIncarnationID] = true
		}
	}
	allocate := func() (contract.ID, error) {
		var id contract.ID
		if _, err := io.ReadFull(e.entropy, id[:]); err != nil {
			return contract.ID{}, err
		}
		if id.IsZero() || ids[id] {
			return contract.ID{}, contract.ErrRecord
		}
		ids[id] = true
		return id, nil
	}
	admissionID, err := allocate()
	if err != nil {
		return out
	}
	sessionID, err := allocate()
	if err != nil {
		return out
	}
	actor := &installedReplacementActor{session: s, owner: e, ctx: ctx, deadline: deadline, target: e.target, goal: e.goal, admission: admissionID, recipient: e.recipient,
		ids: ids, head: contract.Hash(s.body), token: s.token, access: s.root.CurrentAccess.AccessRoot, revision: s.head.Core.Revision, root: s.head.Core.Root}
	s.installedReplacement = actor
	var candidate *Candidate
	var subjects contract.GeneratorDescriptor
	if e.target == ReplacementTargetRecipient {
		candidate, subjects, result = e.prepareRecipient(ctx, s, i, guard, public, actor, sessionID, allocate)
	} else {
		candidate, subjects, result = e.prepareRole(ctx, s, i, guard, public, goal, mask, actor, sessionID, allocate)
	}
	out.OperationID = actor.operation
	if candidate == nil {
		out.Result = result
		return out
	}
	out.OperationID = candidate.head.Subject.Operation
	if candidate.head.Succession != nil {
		out.OperationID = candidate.head.Succession.Subject.OperationID
	}
	out.RequestIdentity = candidate.requestIdentity
	next := candidate.replacementState
	if next == nil || out.OperationID.IsZero() || out.RequestIdentity.IsZero() {
		out.Result = refused(AdmissionInvalid)
		return out
	}
	next.head = candidate.head
	next.body = bytes.Clone(candidate.body)
	duties, hazards, err := s.replacementWorkIDs()
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	var receipt []byte
	if e.target != ReplacementTargetAuthority {
		receipt, err = replacementCandidateReceipt(ctx, next, out.OperationID, out.RequestIdentity, e.target)
		if err != nil {
			out.Result = failure(IntegrityFailure, InvalidRelation)
			return out
		}
	}
	if result = e.deliver(ctx, s, candidate, i, guard); result.Outcome != 0 {
		out.Result = result
		return out
	}
	next = nil
	if guard.check(ctx) != contract.ReasonNone {
		return out
	}
	current, result := s.readAuthenticatedHead(ctx)
	if result.Outcome != 0 {
		out.Result = result
		return out
	}
	if guard.check(ctx) != contract.ReasonNone {
		return out
	}
	if current.token != s.token || !bytes.Equal(current.body, s.body) {
		out.Result = Result{Outcome: Contention, Reason: StalePrecondition, RequestedRevision: candidate.head.Core.Revision, ObservedRevision: current.head.Core.Revision, Evidence: AuthenticatedClosure}
	} else {
		_, out.Result = s.selectCandidate(ctx, candidate)
	}
	if out.Result.Outcome == ObservedCurrent {
		out.Receipt = bytes.Clone(receipt)
	}
	if out.Result.Outcome == ObservedCurrent || out.Result.Outcome == Contention || out.Result.Outcome == UnresolvedCommit {
		out.Payload = &TransitionPayload{PredecessorRevisionID: s.head.Core.Revision, RequestedRevisionID: candidate.head.Core.Revision, ObservedRevisionID: out.Result.ObservedRevision,
			ChangedSubjects: ChangedSubjectCommitment{Count: subjects.Count, IdentityRootDigest: subjects.Digest}, LiveDutyIDs: duties, LiveHazardIDs: hazards}
	}
	return out
}
