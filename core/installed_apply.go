package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
	"sync"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// ApplyInstallation fixes trusted verification and provider construction. The
// control is checked against the authenticated current selection. The desired
// registry is a separately admitted proposal, never key replacement authority.
type ApplyInstallation struct {
	Maintenance              *MaintenanceInstallation
	ExpectedDomain           contract.ID
	ExpectedStore            contract.Descriptor
	PublicBasis              PublicBasis
	ExpectedControl          contract.ControlCore
	DesiredRecipients        []contract.ApplyRecipientInput
	GeneratorImplementations []contract.GeneratorImplementation
	Generated                *GeneratedApplyInstallation
	PublicConfiguration      contract.PublicConfiguration
	ConfigurationValidator   *PublicConfigurationValidator
	Store                    contract.Store
	Trust                    contract.Trust
	CompositionID            contract.ID
	FileIdentity             contract.ID
	AdmitCustody             func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error)
	CloseInstalled           func()
}

// InstalledApplyCustody is constructed only by the static installation. The
// receipt callback has no source or public request representation.
type InstalledApplyCustody struct {
	Crypto      contract.Crypto
	BindReceipt func(context.Context, contract.CryptoApplyReceiptAdmission) error
	Close       func()
}

type InstalledApply struct {
	maintenanceGuard   *installedMutationGuard
	mu                 sync.Mutex
	installation       ApplyInstallation
	secretAccess       *installedSecretAccess
	retirement         *installedRecipientRetirement
	activeDone         chan struct{}
	publicationCapture *applyPublicationCapture
	used, closed       bool
	closeOnce          sync.Once
}

// MaxApplyResultDiagnostics covers one initial generated selection, two
// selection observations per finite driver step, one preparation stop, one
// return interruption, one publisher-construction failure and one coalesced
// local cleanup/File Close diagnostic.
// Cleanup's three selections, preparation stop, interruption, two refreshes and
// File Close fit within the same account. This grants no additional work.
const MaxApplyResultDiagnostics = 2*generatedInvocationStepLimit + 5

// PublicApplyResult carries the facts established by one invocation. Revision
// observations describe the captured selection, not a later HEAD. A selected
// generated checkpoint can be incomplete; its Generated state and Diagnostics
// remain necessary to interpret Result.
//
// PreAdmission is an alternative to RequestIdentity and grants no replay right.
// Early refusal can retain RequestID while the other operation identities are
// unavailable. Payload describes a prepared transition only for selected,
// contended or unresolved selection; no-op and pre-admission refusal have none.
// Intermediate generated selections can also have no terminal Payload or Receipt.
// A Receipt is checked terminal evidence, including an explicitly marked retained
// receipt observation; its presence does not make later state current.
// Cleanup is the cleanup-specific payload and excludes Payload and Receipt.
//
// WarningBits comes from the authenticated observed image. Diagnostics can report
// a later inability without replacing earlier selection or commit uncertainty.
// Successor and RetirementBlockers have their separate maintenance and blocking
// contracts. Returned public facts contain no private value or custody handle;
// their variable backing is retained independently of the installed owner.
type PublicApplyResult struct {
	Successor                                         *MaintenanceSuccessor
	PreAdmission                                      *PreAdmissionRequestIdentity
	Result                                            Result
	RequestID, OperationID, RequestIdentity, DomainID contract.ID
	Payload                                           *TransitionPayload
	Cleanup                                           *GeneratedCleanupPayload
	Preparation                                       *ApplyPreparationFacts
	WarningBits                                       uint8
	Receipt                                           []byte
	Diagnostics                                       []contract.Diagnostic
	RetirementBlockers                                *RecipientRetirementBlockers
	Generated                                         *GeneratedInvocationResult
}

// AddCleanupDiagnostic shares the one local cleanup slot across generated
// executable removal and captured File Close without changing selected facts.
func (r *PublicApplyResult) AddCleanupDiagnostic() {
	if r == nil {
		return
	}
	subject := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
	if slices.ContainsFunc(r.Diagnostics, func(d contract.Diagnostic) bool {
		return d.Subject == subject && len(d.Path) == 1 && d.Path[0] == contract.FieldPresence &&
			d.Outcome == contract.DiagnosticUnable && d.Reason == contract.ReasonEvidenceUnavailable && d.SourceLocation == nil
	}) {
		return
	}
	r.Diagnostics = append(r.Diagnostics, contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPresence},
		Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable})
}

func NewInstalledApply(i ApplyInstallation) (*InstalledApply, error) {
	return newInstalledApply(i, nil, nil)
}

func newInstalledApply(i ApplyInstallation, access *installedSecretAccess, retirement *installedRecipientRetirement) (*InstalledApply, error) {
	maintenance := access != nil || retirement != nil
	if maintenance != (i.Maintenance != nil) {
		return nil, contract.ErrRecord
	}
	if i.Store == nil || i.Trust == nil || i.ConfigurationValidator == nil || i.ExpectedDomain.IsZero() || i.CompositionID.IsZero() || access == nil && retirement == nil && i.FileIdentity.IsZero() ||
		i.Store.Descriptor() != i.ExpectedStore || i.AdmitCustody == nil && retirement == nil || i.CloseInstalled == nil {
		return nil, contract.ErrRecord
	}
	basis, err := i.PublicBasis.own()
	if err != nil {
		return nil, err
	}
	control, err := basis.ControlCore(i.ExpectedDomain, i.ExpectedStore)
	if err != nil || !CurrentControlMatches(i.ExpectedControl, control) || i.Trust.Identity() != control.NormalSigning.Binding.Trust || i.Trust.Family() != control.Provider {
		return nil, contract.ErrRecord
	}
	encoded, err := contract.EncodeControlCore(i.ExpectedControl)
	if err != nil {
		return nil, err
	}
	i.ExpectedControl, err = contract.DecodeControlCore(encoded)
	if err != nil || access == nil && retirement == nil && (len(i.DesiredRecipients) == 0 || len(i.DesiredRecipients) > contract.CryptoMaxRecipients) {
		return nil, contract.ErrRecord
	}
	var registryBytes uint64
	for _, input := range i.DesiredRecipients {
		n, err := contract.RecipientRecordLength(input.Recipient)
		if err != nil {
			return nil, err
		}
		registryBytes += uint64(n)
		if registryBytes > contract.MaxPublicRegistryBytes {
			return nil, contract.ErrRecordCapacity
		}
	}
	if i.Generated != nil {
		owned := *i.Generated
		i.Generated = &owned
	}
	i.DesiredRecipients = slices.Clone(i.DesiredRecipients)
	i.GeneratorImplementations = slices.Clone(i.GeneratorImplementations)
	for _, row := range i.GeneratorImplementations {
		if err := row.Validate(); err != nil {
			return nil, err
		}
	}
	for at, proposed := range i.DesiredRecipients {
		row := proposed.Recipient
		body, err := contract.EncodeRecipientRecord(row)
		if err != nil || row.Status != contract.CurrentRecipient {
			return nil, contract.ErrRecord
		}
		i.DesiredRecipients[at].Recipient, err = contract.DecodeRecipientRecord(body)
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(i.DesiredRecipients, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	for at, row := range i.DesiredRecipients {
		if row.Creation != nil {
			proof := *row.Creation
			i.DesiredRecipients[at].Creation = &proof
		}
		if at > 0 && row.Recipient.RecipientID == i.DesiredRecipients[at-1].Recipient.RecipientID {
			return nil, contract.ErrRecord
		}
	}
	if !publicConfigurationBounded(i.PublicConfiguration) || !publicConfigurationBackingBounded(i.PublicConfiguration) {
		return nil, contract.ErrRecordCapacity
	}
	i.PublicConfiguration = ownPublicConfiguration(i.PublicConfiguration)
	i.PublicBasis = basis
	var guard *installedMutationGuard
	if maintenance {
		i.Maintenance, err = ownMaintenanceInstallation(i.Maintenance)
		if err != nil {
			return nil, err
		}
		guard, err = newInstalledMutationGuard(i.Store, i.Maintenance.SourceUnchanged)
		if err != nil {
			return nil, err
		}
		i.Store, i.Trust = guard.Store(), guard.Trust(i.Trust)
	}
	return &InstalledApply{installation: i, secretAccess: access, retirement: retirement, maintenanceGuard: guard}, nil
}

// Apply borrows the complete input for this invocation. The caller must keep
// input bytes and membership vectors unchanged until return. No file writer or
// preparation callback is available through this installation.
func (e *InstalledApply) Apply(ctx context.Context, requestID contract.ID, input []ApplyEntryInput) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreApply)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.apply(ctx, requestID, input, call, nil)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledApply) apply(ctx context.Context, requestID contract.ID, input []ApplyEntryInput, call *telemetry.Call, capture *applyPublicationCapture) PublicApplyResult {
	out := PublicApplyResult{RequestID: requestID, Result: refused(AdmissionInvalid)}
	if e == nil || ctx == nil || ctx.Err() != nil || requestID.IsZero() {
		return out
	}
	deadline, finite := ctx.Deadline()
	if !finite || !validPrivateDeadline(deadline) {
		return out
	}
	i, done, acquired := e.beginApplyInvocation(capture)
	if !acquired {
		return out
	}
	defer e.endApplyInvocation(done, capture)
	ctx = telemetry.CallContext(ctx, call)
	out.DomainID = i.ExpectedDomain
	if e.maintenanceGuard != nil && e.maintenanceGuard.check(ctx) != contract.ReasonNone {
		return out
	}
	admitted, result := admitBorrowedPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, i.Store, i.CompositionID, i.ConfigurationValidator.interpret)
	if result.Outcome != ObservedCurrent {
		out.Result = result
		return out
	}
	s, result := Open(ctx, admitted, i.Store)
	if s == nil {
		out.Result = result
		return out
	}
	out.WarningBits = s.root.WarningBits
	if e.secretAccess == nil && e.retirement == nil {
		if result := s.installedApplySelectionResult(ctx, i); result.Outcome != 0 {
			out.Result = result
			return out
		}
	}
	var access *contract.CryptoSecretAccessIntent
	var retirement *contract.RecipientRetirementRow
	var output *outputApplyInput
	if e.retirement != nil {
		input, retirement, out.RetirementBlockers, result = s.installedRecipientRetirementInputs(ctx, i, e.retirement)
		if retirement != nil {
			i.DesiredRecipients = currentApplyRecipients(s.registry())
			i.DesiredRecipients = slices.DeleteFunc(i.DesiredRecipients, func(row contract.ApplyRecipientInput) bool {
				return row.Recipient.RecipientID == retirement.RecipientID
			})
		}
	} else if e.secretAccess != nil {
		input, access, result = s.installedSecretAccessInputs(ctx, i, e.secretAccess)
		i.DesiredRecipients = currentApplyRecipients(s.registry())
	} else {
		input, output, result = s.installedApplyInputs(ctx, i, input)
	}
	i.PublicConfiguration = contract.PublicConfiguration{}
	if result.Outcome != 0 {
		out.Result = result
		return out
	}
	if e.secretAccess == nil && e.retirement == nil && installedGeneratedCreates(input) {
		return e.applyGenerated(ctx, requestID, s, i, input, output, deadline)
	}
	var refusalDiagnostic *contract.Diagnostic
	c, result := s.compareEntryInputsForMutation(ctx, input, i.DesiredRecipients, access, retirement, &refusalDiagnostic)
	if c == nil {
		out.Result = result
		if refusalDiagnostic != nil {
			out.Diagnostics = []contract.Diagnostic{*refusalDiagnostic}
		}
		return out
	}
	if result := s.compareOutput(ctx, c, output); result.Outcome != 0 {
		out.Result = result
		return out
	}
	for _, entry := range c.desiredEntries {
		if entry.ValueSource == contract.Supplied && entry.ConfidentialityClass == contract.Secret && entry.Retained == nil {
			view, err := contract.InspectSealedInputEnvelope(entry.InputBytes)
			if err != nil || view.Core.FileIdentity != i.FileIdentity {
				out.Result = refused(InvalidIntent)
				return out
			}
		}
	}
	if i.Maintenance != nil {
		if result := s.maintenanceSourceFeasibility(ctx, requestID, i.Maintenance, c, e.retirement, i.ConfigurationValidator); result.Outcome != 0 {
			out.Result = result
			return out
		}
	}
	parent, custody, result := s.installedApplyComparison(ctx, c, i, e.retirement, deadline)
	if custody != nil {
		defer custody.Close()
	}
	if result.Outcome != 0 {
		out.Result = result
		return out
	}
	parent.trackNoWork = true
	c, result = s.Compare(ctx, input, parent)
	if c == nil {
		out.Result = result
		if result.Outcome == Unchanged {
			operation, identity, err := s.installedApplyNoWorkIdentity(ctx, parent)
			if err != nil {
				out.Result = installedApplyPreparationFailure(err)
				return out
			}
			out.OperationID, out.RequestIdentity = operation, identity
			e.captureApplyPublication(ctx, s, true)
		}
		return out
	}
	before, result := s.installedApplyReceiptWindows(ctx)
	if result.Outcome != 0 {
		out.Result = result
		return out
	}
	c.applyReceipt = &installedApplyReceipt{before: before}
	if custody != nil {
		c.applyReceipt.bind = custody.BindReceipt
	}
	p, err := planTransition(ctx, c)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	out.OperationID = p.operation
	subjects, err := installedApplyChangedSubjects(c, p)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	c.applyReceipt.subjects = subjects
	if err := s.reserveInstalledApplyReceipt(ctx, c, p); err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	if c.operation != nil {
		if result := s.prepareCompared(ctx, c, p); result.Outcome != 0 {
			out.Result = result
			return out
		}
	}
	preview, proposed, authority, result := s.encodeInstalledApply(ctx, c, p)
	if result.Outcome != 0 {
		out.Result = result
		return out
	}
	permit := &AdmittedParentTransition{session: s, comparison: c, predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision,
		predecessorToken: s.token, plan: p, authority: authority}
	work, err := c.retainedWorkResult(p)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	generatedResult, err := captureNormalGeneratedHandoffResult(ctx, s, c, p, proposed, preview, work)
	if err != nil {
		out.Result = installedApplyPreparationFailure(err)
		return out
	}
	candidate, result := s.Prepare(ctx, c, permit, i.Trust)
	if candidate == nil {
		out.Result = result
		return out
	}
	out.RequestIdentity = c.applyReceipt.identity
	if i.Maintenance != nil {
		successor, result := s.deliverMaintenanceSuccessor(ctx, c, candidate, i, e.maintenanceGuard)
		out.Successor = successor
		if result.Outcome != 0 {
			out.Result = result
			if result.Outcome == Contention || result.Outcome == UnresolvedCommit {
				out.Payload = &TransitionPayload{PredecessorRevisionID: s.head.Core.Revision, RequestedRevisionID: p.revision, ObservedRevisionID: result.ObservedRevision,
					ChangedSubjects: ChangedSubjectCommitment{Count: subjects.Count, IdentityRootDigest: subjects.Digest}}
				out.Payload.LiveDutyIDs, out.Payload.LiveHazardIDs = installedApplyObservedWorkIDs(s)
			}
			return out
		}
	}
	actual, result := s.selectObserved(ctx, candidate)
	out.Result = result
	if generatedResult != nil {
		out.Generated, err = generatedResult.observe(ctx, actual, result)
		if err != nil {
			out.Generated = nil
		}
	}
	observed := actual
	if observed == nil {
		observed = s
	}
	out.WarningBits = observed.root.WarningBits
	if out.Result.Outcome == ObservedCurrent {
		out.Receipt = bytes.Clone(c.applyReceipt.receipt)
	}
	if out.Result.Outcome == ObservedCurrent || out.Result.Outcome == Contention || out.Result.Outcome == UnresolvedCommit {
		out.Payload = &TransitionPayload{PredecessorRevisionID: s.head.Core.Revision, RequestedRevisionID: p.revision, ObservedRevisionID: out.Result.ObservedRevision,
			ChangedSubjects: ChangedSubjectCommitment{Count: subjects.Count, IdentityRootDigest: subjects.Digest}}
		out.Payload.LiveDutyIDs, out.Payload.LiveHazardIDs = installedApplyObservedWorkIDs(observed)
	}
	e.captureApplyPublication(ctx, actual, out.Result.Outcome == ObservedCurrent && (generatedResult == nil || out.Generated != nil) && applyPublicationComplete(out))
	return out
}

func (s *StateSession) installedApplySelectionResult(ctx context.Context, i ApplyInstallation) Result {
	if s == nil || !CurrentControlMatches(currentControlOf(s), i.ExpectedControl) {
		return refused(AdmissionInvalid)
	}
	if _, err := s.admitApplyRecipients(ctx, i.DesiredRecipients); err != nil {
		return refused(AdmissionInvalid)
	}

	if _, result := s.currentOutputConfigurationForApply(ctx); result.Outcome != 0 {
		return result
	}
	return Result{}
}

func (s *StateSession) installedApplyReceiptWindows(ctx context.Context) (contract.MutationReceiptWindows, Result) {
	before, err := s.receiptWindows(ctx)
	if err != nil {
		return contract.MutationReceiptWindows{}, installedApplyPreparationFailure(err)
	}
	return before, Result{}
}

func (s *StateSession) installedApplyComparison(ctx context.Context, c *Comparison, i ApplyInstallation, retirement *installedRecipientRetirement, deadline time.Time) (*AdmittedParentComparison, *InstalledApplyCustody, Result) {
	if c == nil || (retirement == nil) != (c.retirement == nil) {
		return nil, nil, refused(AdmissionInvalid)
	}
	if err := s.validateApplyRecipientIdentities(ctx, c); err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	implementations, err := s.installedGeneratedNormalImplementations(ctx, i, c)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	witness, err := s.generatedSupportTransition(ctx, c, implementations)
	if err != nil {
		return nil, nil, installedApplyPreparationFailure(err)
	}
	if witness == nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	secret := c.requiresCrypto()
	if !secret {
		return &AdmittedParentComparison{session: s, support: witness, output: ownOutputApplyInput(c.outputIntent), deadline: deadline, recipients: c.recipients, secretAccess: c.secretAccess, retirement: c.retirement}, nil, Result{}
	}
	var admissionID, sessionID contract.ID
	if _, err := rand.Read(admissionID[:]); err != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	if _, err := rand.Read(sessionID[:]); err != nil || admissionID.IsZero() || sessionID.IsZero() || admissionID == sessionID {
		return nil, nil, refused(AdmissionInvalid)
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	context := contract.ApplyContext{OperationClass: contract.CryptoOrdinaryLifecycle, AdmissionID: admissionID, SessionID: sessionID, DomainID: s.admission.domain,
		CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), PredecessorHEADDigest: contract.Hash(s.body), OriginalConditionDigest: condition,
		IntentDescriptor: contract.DescriptorVector{Digest: c.desired, Length: c.desiredLength, Count: uint32(len(c.intent))}, CurrentAccessRoot: s.root.CurrentAccess.AccessRoot}
	copy(context.PredecessorRootRef[:], root)
	q, ok := s.comparisonRequest(c, context)
	if !ok {
		return nil, nil, refused(AdmissionInvalid)
	}
	body, err := contract.EncodeCryptoCompareRequest(q)
	if err != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	support, err := s.supportDescriptor()
	if err != nil {
		return nil, nil, refused(AdmissionInvalid)
	}
	var plain []contract.MembershipRow
	for _, entry := range s.root.Names {
		value := s.valueEntry(entry.Slot)
		if value.ConfidentialityClass == contract.Plain {
			plain = append(plain, membership(s.admission.domain, entry.Slot, value))
		}
	}
	before, result := s.installedApplyReceiptWindows(ctx)
	if result.Outcome != 0 {
		return nil, nil, result
	}
	var custody *InstalledApplyCustody
	if retirement != nil && c.retirement != nil {
		custody, err = retirement.admit(ctx, q, currentControlOf(s), s.registry(), c.retirement.Slot, plain, support, witness, s.head.Core.Revision, before, s.root.WarningBits, deadline)
	} else {
		if i.AdmitCustody == nil {
			return nil, nil, refused(AdmissionInvalid)
		}
		custody, err = i.AdmitCustody(ctx, q, currentControlOf(s), s.registry(), plain, support, witness, s.head.Core.Revision, before, s.root.WarningBits, deadline)
	}
	if err != nil || custody == nil || custody.Crypto == nil || custody.Close == nil || custody.BindReceipt == nil {
		if custody != nil && custody.Close != nil {
			custody.Close()
		}
		return nil, nil, refused(CustodyUnavailable)
	}
	return &AdmittedParentComparison{session: s, crypto: custody.Crypto, instance: custody.Crypto.InstanceID(), context: context, requestDigest: contract.Hash(body), requestLength: len(body), deadline: deadline, support: witness, output: ownOutputApplyInput(c.outputIntent), recipients: c.recipients, secretAccess: c.secretAccess, retirement: c.retirement}, custody, Result{}
}

func (e *InstalledApply) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	done := e.activeDone
	e.mu.Unlock()
	if done != nil {
		<-done
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		closeInstalled := e.installation.CloseInstalled
		e.installation = ApplyInstallation{}
		e.mu.Unlock()
		if closeInstalled != nil {
			closeInstalled()
		}
	})
}
