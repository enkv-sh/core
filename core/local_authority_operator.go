package core

import (
	"context"
	"encoding/binary"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

// AuthoritySession is one authenticated, short-lived local operator view.
// Every command opens the current HEAD again with a fresh admission.
type AuthoritySession struct {
	installed *installedAdministrativeParent
	// Only the single End command owns this optional collector.
	closeReader func()
	observation *operationObservation
	state       *StateSession
	trust       contract.Trust
	mode        LocalAuthorityOperation
}

// DomainID is available only after the Authority session authenticated HEAD.
func (a *AuthoritySession) DomainID() contract.ID {
	if a == nil || a.state == nil {
		return contract.ID{}
	}
	return a.state.root.Domain
}

type AuthorityGroup struct {
	GroupID, OwnerID, TargetID contract.ID
	OwnerKind, DutyKind        uint8
	SelectedEvidenceSummary    uint16
	ChargedPages               uint16
	ChargedBytes               uint64
	BlocksChangedMutation      bool
	RelatedGroupIndexes        []uint16
	RequiredParentGroupID      contract.ID
	Selectable                 bool
	OriginalOperation          *AdministrativeOriginalOperation
	GC                         *contract.GCProgress
}

// AdministrativeOriginalOperation identifies a generated operation only when
// retained authenticated facts establish that typed relation.
type AdministrativeOriginalOperation struct {
	OperationID contract.ID
}

type AuthorityAbandonment struct {
	Receipt           contract.CompactMutationReceipt
	ReceiptBytes      []byte
	OriginalOperation *AdministrativeOriginalOperation
}

type AuthorityInspection struct {
	Revision, Snapshot contract.ID
	WarningBits        uint8
	ChildCount         uint16
	ChildBytes         uint64
	Groups             []AuthorityGroup
	Abandonments       []AuthorityAbandonment
}

type EndWorkPreview struct {
	DependentGroups, RemovedSupport    contract.GeneratorDescriptor
	PreservedCurrent                   contract.DigestLength
	Identity                           contract.ID
	PredecessorRevision, TargetGroupID contract.ID
	EndedGroupIDs                      []contract.ID
	TargetOwnerID, TargetID            contract.ID
	TargetKind, DutyKind               uint8
	SelectedEvidenceSummary            uint16
	BeforeWarningBits, WarningBits     uint8
	BeforeChildCount, AfterChildCount  uint16
	BeforeChildBytes, AfterChildBytes  uint64
}

type EndWorkOutcome struct {
	RequestIdentity contract.ID
	OperationID     contract.ID
	Revision        contract.ID
	Warnings        uint8
	Receipt         []byte
	Result          Result
}

func equalEndWorkPreview(a, b EndWorkPreview) bool {
	return a.Identity == b.Identity && a.DependentGroups == b.DependentGroups && a.RemovedSupport == b.RemovedSupport && a.PreservedCurrent == b.PreservedCurrent && a.PredecessorRevision == b.PredecessorRevision &&
		a.TargetGroupID == b.TargetGroupID && slices.Equal(a.EndedGroupIDs, b.EndedGroupIDs) &&
		a.TargetOwnerID == b.TargetOwnerID && a.TargetID == b.TargetID &&
		a.TargetKind == b.TargetKind && a.DutyKind == b.DutyKind &&
		a.SelectedEvidenceSummary == b.SelectedEvidenceSummary && a.BeforeWarningBits == b.BeforeWarningBits && a.WarningBits == b.WarningBits &&
		a.BeforeChildCount == b.BeforeChildCount && a.AfterChildCount == b.AfterChildCount &&
		a.BeforeChildBytes == b.BeforeChildBytes && a.AfterChildBytes == b.AfterChildBytes
}

func (a *AuthoritySession) Inspect(ctx context.Context) (AuthorityInspection, Result) {
	if a != nil && a.installed != nil {
		return AuthorityInspection{}, refused(AdmissionInvalid)
	}
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreInspectSelectedWork)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	view, result := a.inspect(ctx)
	finishCore(call, result)
	return view, result
}

func (a *AuthoritySession) inspect(ctx context.Context) (AuthorityInspection, Result) {
	if ctx == nil || ctx.Err() != nil || a == nil || a.state == nil || a.mode != LocalAuthorityInspect {
		return AuthorityInspection{}, refused(AdmissionInvalid)
	}
	s := a.state
	abandonments, err := s.retainedAdministrativeAbandonments()
	if err != nil {
		return AuthorityInspection{}, failure(IntegrityFailure, InvalidRelation)
	}
	coordinates, err := s.publicationCoordinatesForDisposition()
	if err != nil {
		return AuthorityInspection{}, failure(IntegrityFailure, InvalidRelation)
	}
	view := AuthorityInspection{Revision: s.head.Core.Revision, Snapshot: s.root.Snapshot,
		WarningBits: s.root.WarningBits, ChildCount: uint16(s.root.ChildCount), ChildBytes: s.root.ChildEncodedBytes,
		Groups: make([]AuthorityGroup, 0, len(s.adminIndex.Groups)), Abandonments: abandonments}
	originals := s.administrativeOriginalOperations()
	for _, group := range s.adminIndex.Groups {
		row := AuthorityGroup{GroupID: group.GroupID, OwnerID: group.OwnerID,
			TargetID: group.TargetID, OwnerKind: group.OwnerKind, DutyKind: group.DutyKind,
			SelectedEvidenceSummary: group.SelectedEvidenceSummary, ChargedPages: group.ChargedPages,
			ChargedBytes: group.ChargedBytes, BlocksChangedMutation: group.OwnerID == s.root.Generated.ActiveOwner || group.GroupID == s.root.ActiveGC,
			RequiredParentGroupID: administrativeRequiredParentTarget(s.root, s.adminIndex, group),
			Selectable:            administrativeTargetSelectable(s.root, s.adminIndex, group, coordinates)}
		if original, proved := originals[group.GroupID]; proved {
			row.OriginalOperation = &original
		}
		if group.GC != nil {
			v := group.GC.Own()
			row.GC = &v
		}
		row.RelatedGroupIndexes = slices.Clone(group.RelatedGroupIndexes)
		view.Groups = append(view.Groups, row)
	}
	return view, s.observed(ObservedCurrent)
}

func (s *StateSession) administrativeOriginalOperations() map[contract.ID]AdministrativeOriginalOperation {
	originals := make(map[contract.ID]AdministrativeOriginalOperation)
	for _, page := range s.adminIndex.Pages {
		if page.ReadRequired {
			continue
		}
		selected := 0
		for _, span := range page.Spans {
			for _, row := range page.Rows[selected : selected+int(span.Count)] {
				if row.Kind != contract.GeneratedParentSupportKind {
					continue
				}
				for _, groupIndex := range span.GroupIndexes {
					group := s.adminIndex.Groups[groupIndex]
					if group.OwnerKind == contract.AdministrativeGeneratedParent && group.GroupID == row.RecordID &&
						group.GroupID == group.OwnerID && group.GroupID == group.TargetID {
						originals[group.GroupID] = AdministrativeOriginalOperation{OperationID: group.GroupID}
					}
				}
			}
			selected += int(span.Count)
		}
	}
	return originals
}

func appendPreviewID(body []byte, id contract.ID) []byte { return append(body, id[:]...) }

func appendPreviewDescriptor(body []byte, d contract.GeneratorDescriptor) []byte {
	body = appendPreviewID(body, d.Digest)
	var number [8]byte
	binary.LittleEndian.PutUint64(number[:], d.Length)
	body = append(body, number[:]...)
	binary.LittleEndian.PutUint32(number[:4], d.Count)
	return append(body, number[:4]...)
}

// endWorkPreviewIdentity excludes the fresh invocation and candidate IDs and
// physical roots derived from them. It binds the independent Store and public
// basis facts and exact semantic disposition. End revalidates those facts.
func endWorkPreviewIdentity(q contract.EndWorkSubject, store contract.Descriptor, basisDigest contract.ID) (contract.ID, bool) {
	if !store.Valid() || basisDigest.IsZero() || !q.PredecessorToken.Valid() || len(q.PredecessorToken.Value) > 256 ||
		!q.DependentGroups.Valid() || !q.RemovedSupport.Valid() {
		return contract.ID{}, false
	}
	body := []byte("enkv/local-authority-end-preview/v2\x00")
	body = appendStoreDescriptorLocation(body, store)
	body = appendPreviewID(body, q.DomainID)
	body = appendStoreDescriptorIDs(body, store)
	for _, id := range []contract.ID{basisDigest, q.PredecessorRevisionID,
		q.PredecessorFullHEADDigest, q.TargetGroupID, q.TargetOwnerID, q.TargetID} {
		body = appendPreviewID(body, id)
	}
	body = append(body, byte(q.PredecessorToken.Family))
	var number [8]byte
	binary.LittleEndian.PutUint16(number[:2], uint16(len(q.PredecessorToken.Value)))
	body = append(body, number[:2]...)
	body = append(body, []byte(q.PredecessorToken.Value)...)
	body = append(body, q.TargetKind, q.DutyKind)
	binary.LittleEndian.PutUint16(number[:2], q.SelectedEvidenceSummary)
	body = append(body, number[:2]...)
	body = appendPreviewDescriptor(body, q.DependentGroups)
	body = appendPreviewDescriptor(body, q.RemovedSupport)
	body = appendPreviewID(body, q.PreservedCurrent.Digest)
	binary.LittleEndian.PutUint64(number[:], q.PreservedCurrent.Length)
	body = append(body, number[:]...)
	body = append(body, q.BeforeWarningBits, q.AfterWarningBits)
	for _, id := range []contract.ID{q.BeforeAccessRoot, q.BeforeAccessIncarnationID} {
		body = appendPreviewID(body, id)
	}
	binary.LittleEndian.PutUint64(number[:], q.BeforeAccessGeneration)
	body = append(body, number[:]...)
	binary.LittleEndian.PutUint64(number[:], q.AfterAccessGeneration)
	body = append(body, number[:]...)
	binary.LittleEndian.PutUint16(number[:2], q.BeforeChildCount)
	body = append(body, number[:2]...)
	binary.LittleEndian.PutUint16(number[:2], q.AfterChildCount)
	body = append(body, number[:2]...)
	binary.LittleEndian.PutUint64(number[:], q.BeforeChildBytes)
	body = append(body, number[:]...)
	binary.LittleEndian.PutUint64(number[:], q.AfterChildBytes)
	body = append(body, number[:]...)
	return contract.Hash(body), true
}

func previewFromCandidate(candidate *Candidate) (EndWorkPreview, bool) {
	if candidate == nil || candidate.session == nil || candidate.head.AuthKind != format.AdministrativeAuth || candidate.head.EndWork == nil {
		return EndWorkPreview{}, false
	}
	q := *candidate.head.EndWork
	_, groups, err := candidate.session.administrativeWorkClosure(q.TargetGroupID)
	if err != nil || len(groups) == 0 {
		return EndWorkPreview{}, false
	}
	ended := make([]contract.ID, len(groups))
	parts := make([][]byte, len(groups))
	for i, group := range groups {
		ended[i] = group.GroupID
		parts[i] = ended[i][:]
	}
	if administrativeDescriptor("ended-groups", parts...) != q.DependentGroups {
		return EndWorkPreview{}, false
	}
	basis, reason := qualifyBorrowedReaderPublicBasis(candidate.session.admission.publicBasis(), candidate.session.admission.domain, candidate.session.admission.store)
	if reason != "" {
		return EndWorkPreview{}, false
	}
	id, ok := endWorkPreviewIdentity(q, candidate.session.admission.store, basis.digest)
	if !ok {
		return EndWorkPreview{}, false
	}
	return EndWorkPreview{Identity: id, DependentGroups: q.DependentGroups, RemovedSupport: q.RemovedSupport, PreservedCurrent: q.PreservedCurrent, PredecessorRevision: q.PredecessorRevisionID,
		TargetGroupID: q.TargetGroupID, EndedGroupIDs: ended, TargetOwnerID: q.TargetOwnerID, TargetID: q.TargetID,
		TargetKind: q.TargetKind, DutyKind: q.DutyKind, SelectedEvidenceSummary: q.SelectedEvidenceSummary,
		BeforeWarningBits: q.BeforeWarningBits, WarningBits: q.AfterWarningBits,
		BeforeChildCount: q.BeforeChildCount, AfterChildCount: q.AfterChildCount,
		BeforeChildBytes: q.BeforeChildBytes, AfterChildBytes: q.AfterChildBytes}, true
}

func (a *AuthoritySession) Preview(ctx context.Context, groupID contract.ID) (EndWorkPreview, Result) {
	if a != nil && a.installed != nil {
		return EndWorkPreview{}, refused(AdmissionInvalid)
	}
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePrepareEndSelectedWork)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	ctx = telemetry.CallContext(ctx, call)
	view, result := a.preview(ctx, groupID)
	finishCore(call, result)
	return view, result
}

func (a *AuthoritySession) preview(ctx context.Context, groupID contract.ID) (EndWorkPreview, Result) {
	if ctx == nil || ctx.Err() != nil || a == nil || a.state == nil ||
		a.mode != LocalAuthorityPreview || groupID.IsZero() {
		return EndWorkPreview{}, refused(AdmissionInvalid)
	}
	ids, err := a.state.freshEndWorkIDs()
	if err != nil {
		return EndWorkPreview{}, refused(AdmissionInvalid)
	}
	candidate, next, err := a.state.deriveEndWorkCandidate(ctx, groupID, ids)
	if result, ok := selectedReadResult(err); ok {
		return EndWorkPreview{}, result
	}
	if err != nil || next == nil {
		return EndWorkPreview{}, refused(InvalidRelation)
	}
	if _, err := next.validateRelationsMode(ctx, true); err != nil {
		if result, ok := selectedReadResult(err); ok {
			return EndWorkPreview{}, result
		}
		return EndWorkPreview{}, refused(InvalidRelation)
	}
	view, ok := previewFromCandidate(candidate)
	if !ok {
		return EndWorkPreview{}, refused(InvalidRelation)
	}
	return view, a.state.observed(ObservedCurrent)
}

func (a *AuthoritySession) End(ctx context.Context, expected EndWorkPreview) EndWorkOutcome {
	if a != nil && a.installed != nil {
		return EndWorkOutcome{Result: refused(AdmissionInvalid)}
	}
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreSelectEndSelectedWork)
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	outcome := a.end(ctx, expected, call)
	finishCore(call, outcome.Result)
	return outcome
}

func (a *AuthoritySession) end(ctx context.Context, expected EndWorkPreview, call *telemetry.Call) EndWorkOutcome {
	if a == nil || a.state == nil || a.mode != LocalAuthorityEnd || ctx == nil || ctx.Err() != nil ||
		expected.Identity.IsZero() || expected.TargetGroupID.IsZero() ||
		a.state.prepared {
		return EndWorkOutcome{Result: refused(AdmissionInvalid)}
	}
	ctx = telemetry.CallContext(ctx, call)
	if expected.PredecessorRevision != a.state.head.Core.Revision {
		return EndWorkOutcome{Result: refused(StalePrecondition)}
	}
	if !a.state.admission.valid(a.state.store) {
		return EndWorkOutcome{Result: refused(AdmissionInvalid)}
	}
	ids, err := a.state.freshEndWorkIDs()
	if err != nil {
		return EndWorkOutcome{Result: refused(AdmissionInvalid)}
	}
	candidate, next, err := a.state.deriveEndWorkCandidate(ctx, expected.TargetGroupID, ids)
	if result, ok := selectedReadResult(err); ok {
		return EndWorkOutcome{Result: result}
	}
	if err != nil || next == nil {
		return EndWorkOutcome{Result: refused(InvalidRelation)}
	}
	if _, err := next.validateRelationsMode(ctx, true); err != nil {
		if result, ok := selectedReadResult(err); ok {
			return EndWorkOutcome{Result: result}
		}
		return EndWorkOutcome{Result: refused(InvalidRelation)}
	}
	actual, ok := previewFromCandidate(candidate)
	if !ok || !equalEndWorkPreview(actual, expected) {
		return EndWorkOutcome{Result: refused(StalePrecondition)}
	}
	candidate.bindObservation(a.observation, observationSource{DomainID: candidate.head.EndWork.DomainID, OperationID: candidate.head.EndWork.OperationID})
	if a.observation.enabled() {
		detail, err := administrativeObservation(candidate)
		if err != nil {
			a.observation.reject(ctx)
		} else {
			a.observation.offerChange(ctx, detail)
		}
	}
	receipt, err := contract.EncodeCompactMutationReceipt(candidate.endWorkReceipt)
	if err != nil {
		return EndWorkOutcome{Result: refused(InvalidRelation)}
	}
	a.state.prepared = true
	prepared, result := a.state.persistCandidate(ctx, candidate, a.trust)
	if prepared == nil {
		return EndWorkOutcome{OperationID: ids.operation, RequestIdentity: candidate.endWorkReceipt.RequestIdentityDigest, Result: result}
	}
	selected, result := a.state.selectCandidate(ctx, prepared)
	outcome := EndWorkOutcome{OperationID: ids.operation, RequestIdentity: candidate.endWorkReceipt.RequestIdentityDigest, Result: result}
	if selected != nil && result.Outcome == ObservedCurrent {
		outcome.Revision, outcome.Warnings = selected.head.Core.Revision, selected.root.WarningBits
		outcome.Receipt = receipt
	}
	return outcome
}

func (a *AuthoritySession) Recheck(ctx context.Context, operation contract.ID) (contract.CompactMutationReceipt, Result) {
	if a != nil && a.installed != nil {
		return contract.CompactMutationReceipt{}, refused(AdmissionInvalid)
	}
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreMutationReceipt)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	receipt, result := a.recheck(ctx, operation, call)
	finishCore(call, result)
	return receipt, result
}

func (a *AuthoritySession) recheck(ctx context.Context, operation contract.ID, call *telemetry.Call) (contract.CompactMutationReceipt, Result) {
	if ctx == nil || ctx.Err() != nil || a == nil || a.state == nil || a.mode != LocalAuthorityRecheck || operation.IsZero() {
		return contract.CompactMutationReceipt{}, refused(AdmissionInvalid)
	}
	ctx = telemetry.CallContext(ctx, call)
	body, result := a.state.mutationReceipt(ctx, operation)
	if result.Outcome != ObservedCurrent {
		return contract.CompactMutationReceipt{}, result
	}
	receipt, err := contract.InspectCompactMutationReceipt(body)
	if err != nil || receipt.OperationKind != contract.OperationEndSelectedWork {
		return contract.CompactMutationReceipt{}, refused(InvalidRelation)
	}
	return receipt, result
}

// Close releases invocation-owned read reach and state.
func (a *AuthoritySession) Close() error {
	if a == nil {
		return nil
	}
	if a.installed != nil {
		return a.installed.close(a)
	}
	if a.closeReader != nil {
		a.closeReader()
		a.closeReader = nil
	}
	a.state = nil
	a.trust = nil
	return nil
}
