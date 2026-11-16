package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"slices"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

type MaintenanceObservationInstallation struct {
	ExpectedDomain         contract.ID
	ExpectedStore          contract.Descriptor
	PublicBasis            PublicBasis
	SourcePins, OutputPins AdministrativeSourcePins
	OutputPath             string
	CompositionID          contract.ID
	Correlation            MaintenanceSuccessor
	Configuration          contract.PublicConfiguration
	Inputs                 []contract.PlanningInput
	Recipients             []contract.ApplyRecipientInput
	Source                 PublicSelectedReader
	CheckSourceOutput      func(context.Context) error
}

// MaintenanceQueryIdentity is an exact read request; it grants no replay.
type MaintenanceQueryIdentity struct {
	Schema                                   string
	Operation                                string
	ExpectedDomain, StoreID                  contract.ID
	StoreDescriptorDigest, PublicBasisDigest contract.ID
	SourcePins, OutputPins                   AdministrativeSourcePins
	OutputPath                               string
	RequestNonce                             contract.ID
	Correlation                              MaintenanceSuccessor
	Observation                              *AdministrativeObservation
	Digest                                   contract.ID
}

func (q MaintenanceQueryIdentity) digest() (contract.ID, bool) {
	if q.Schema != "QueryRequestIdentity/v1" || q.Operation != "maintenance-receipt" || q.ExpectedDomain.IsZero() || q.StoreID.IsZero() || q.RequestNonce.IsZero() || q.StoreDescriptorDigest.IsZero() || q.PublicBasisDigest.IsZero() ||
		!q.SourcePins.Valid() || !q.OutputPins.Valid() || q.SourcePins.FileID != q.OutputPins.FileID || q.SourcePins.Format != q.OutputPins.Format || !maintenanceOutputPathValid(q.OutputPath) ||
		q.Correlation.DomainID != q.ExpectedDomain || q.Correlation.FileIdentity != q.SourcePins.FileID || q.Correlation.OperationID.IsZero() || q.Correlation.RequestIdentity.IsZero() {
		return contract.ID{}, false
	}
	if !maintenanceCorrelationCapacity(q.Correlation, q.SourcePins, q.OutputPath) || !maintenanceCorrelationValid(q.Correlation, q.ExpectedDomain, q.StoreID, q.SourcePins.FileID) {
		return contract.ID{}, false
	}
	if q.Observation != nil && (q.Observation.DomainID != q.ExpectedDomain || q.Observation.Revision.IsZero() || q.Observation.Snapshot.IsZero()) {
		return contract.ID{}, false
	}
	q.Digest = contract.ID{}
	h := sha256.New()
	h.Write([]byte("ENKV/maintenance-query/v1\x00"))
	hashPublicSemantic(h, reflect.ValueOf(q))
	return contract.ID(h.Sum(nil)), true
}

func (q MaintenanceQueryIdentity) Valid() bool {
	digest, ok := q.digest()
	return ok && digest == q.Digest
}

type PublicMaintenanceObservationResult struct {
	RequestID, OperationID, RequestIdentity, DomainID      contract.ID
	Result                                                 Result
	StateResult                                            contract.ReaderStateResult
	Query                                                  *MaintenanceQueryIdentity
	PreAdmission                                           *PreAdmissionRequestIdentity
	Receipt                                                []byte
	CandidateCurrent, SourceUsable, SourceUsabilityChecked bool
	CurrentWarningBits                                     uint8
	Correlation                                            MaintenanceSuccessor
}

type MaintenanceObserver struct {
	mu           sync.Mutex
	input        MaintenanceObservationInstallation
	candidate    format.Head
	guard        *installedMutationGuard
	basisDigest  contract.ID
	used, closed bool
	cancel       context.CancelFunc
	done         chan struct{}
	closeOnce    sync.Once
	closeErr     error
}

func NewInstalledMaintenanceObserver(i MaintenanceObservationInstallation) (*MaintenanceObserver, error) {
	if i.Source == nil || i.CheckSourceOutput == nil || i.ExpectedDomain.IsZero() || !i.ExpectedStore.Valid() || i.Source.Descriptor() != i.ExpectedStore || i.CompositionID.IsZero() ||
		!i.SourcePins.Valid() || !i.OutputPins.Valid() || !i.SourcePins.HasGenerated || !i.OutputPins.HasGenerated || i.SourcePins.FileID != i.OutputPins.FileID || i.SourcePins.Format != i.OutputPins.Format || !maintenanceOutputPathValid(i.OutputPath) || !maintenanceCorrelationCapacity(i.Correlation, i.SourcePins, i.OutputPath) {
		return nil, contract.ErrRecord
	}
	basis, err := i.PublicBasis.own()
	if err != nil {
		return nil, err
	}
	qualified, reason := qualifyBorrowedReaderPublicBasis(basis, i.ExpectedDomain, i.ExpectedStore)
	if reason != "" {
		return nil, contract.ErrRecord
	}
	i.PublicBasis = basis
	if !maintenanceCorrelationValid(i.Correlation, i.ExpectedDomain, i.ExpectedStore.Identity, i.SourcePins.FileID) {
		return nil, contract.ErrRecord
	}
	i.Correlation = ownMaintenanceSuccessor(i.Correlation)
	h, err := format.DecodeHead(i.Correlation.SignedCandidate)
	if err != nil || len(i.Correlation.SignedCandidate) > contract.MaxHeadLength || h.Core.Form != format.SuccessorHead || h.AuthKind != format.LifecycleAuth ||
		h.Core.Domain != i.ExpectedDomain || h.Core.Store != i.ExpectedStore.Identity || h.Subject.Operation != i.Correlation.OperationID || h.Subject.OperationKind != i.Correlation.OperationKind ||
		i.Correlation.RequestIdentity.IsZero() || i.Correlation.FileIdentity != i.SourcePins.FileID || i.Correlation.DomainID != i.ExpectedDomain || !selectedHeadProofs(h, qualified.control, nil) {
		return nil, contract.ErrRecord
	}
	if !publicConfigurationBounded(i.Configuration) || !publicConfigurationBackingBounded(i.Configuration) {
		return nil, contract.ErrRecordCapacity
	}
	i.Configuration = ownPublicConfiguration(i.Configuration)
	i.Inputs, err = ownPlanningInputs(i.Inputs)
	if err != nil || !planningInputScopeMatches(i.Configuration, i.Inputs) {
		return nil, contract.ErrRecord
	}
	for _, input := range i.Inputs {
		for _, delta := range i.Correlation.PinDeltas {
			if input.Form == contract.PlanningRetained && input.Name == delta.Name && input.Retained != delta.After {
				return nil, contract.ErrRecord
			}
		}
	}
	i.Recipients, err = ownMaintenanceRecipients(i.Recipients)
	if err != nil {
		return nil, err
	}
	guard, err := newInstalledMutationGuard(administrativeReadStore{source: i.Source}, i.CheckSourceOutput)
	if err != nil {
		return nil, err
	}
	return &MaintenanceObserver{input: i, candidate: h, guard: guard, basisDigest: qualified.digest}, nil
}

func (p *MaintenanceObserver) base(ctx context.Context) (*StateSession, Result) {
	i := p.input
	admitted, result := admitBorrowedPublicNormal(ctx, i.ExpectedDomain, i.ExpectedStore, i.PublicBasis, p.guard.Store(), i.CompositionID, nil)
	if result.Outcome != ObservedCurrent {
		return nil, result
	}
	return openAdministrative(ctx, admitted, p.guard.Store())
}

func (p *MaintenanceObserver) Observe(ctx context.Context, nonce contract.ID) PublicMaintenanceObservationResult {
	out := PublicMaintenanceObservationResult{RequestID: nonce, Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused}
	if p == nil || ctx == nil || nonce.IsZero() || manifestContextFailure(ctx).Outcome != 0 {
		return out
	}
	p.mu.Lock()
	if p.closed || p.used {
		p.mu.Unlock()
		return out
	}
	p.used = true
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	p.cancel, p.done = cancel, done
	p.mu.Unlock()
	defer func() { cancel(); p.mu.Lock(); p.cancel, p.done = nil, nil; close(done); p.mu.Unlock() }()
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCoreMutationReceipt)
	defer func() { finishCore(call, out.Result) }()
	i := p.input
	out.DomainID, out.OperationID = i.ExpectedDomain, i.Correlation.OperationID
	out.Correlation = ownMaintenanceSuccessor(i.Correlation)
	out.Query = &MaintenanceQueryIdentity{Schema: "QueryRequestIdentity/v1", Operation: "maintenance-receipt", ExpectedDomain: i.ExpectedDomain, StoreID: i.ExpectedStore.Identity,
		StoreDescriptorDigest: administrativeStoreDescriptorDigest(i.ExpectedStore), PublicBasisDigest: p.basisDigest,
		SourcePins: i.SourcePins, OutputPins: i.OutputPins, OutputPath: i.OutputPath, RequestNonce: nonce, Correlation: ownMaintenanceSuccessor(i.Correlation)}
	if digest, valid := out.Query.digest(); valid {
		out.Query.Digest, out.RequestIdentity = digest, digest
	} else {
		out.Query = nil
		return out
	}
	if p.guard.check(ctx) != contract.ReasonNone {
		return out
	}
	state, result := p.base(ctx)
	out.Result = result
	if state != nil {
		out.CurrentWarningBits = state.root.WarningBits
		out.Query.Observation = &AdministrativeObservation{DomainID: state.root.Domain, Revision: state.head.Core.Revision, Snapshot: state.root.Snapshot}
		out.CandidateCurrent = bytes.Equal(state.body, i.Correlation.SignedCandidate)
		row, raw, found, err := state.retainedMutationReceipt(i.Correlation.OperationID)
		switch {
		case err != nil:
			out.Result = failure(IntegrityFailure, InvalidRelation)
		case !found && out.CandidateCurrent:
			out.Result = failure(IntegrityFailure, MissingSelectedObject)
		case !found:
			out.Result = state.observed(EvidenceUnavailable)
			out.Result.Reason = MissingSelectedObject
		case row.OperationKind != i.Correlation.OperationKind || row.DomainID != i.ExpectedDomain || row.RequestIdentityDigest != i.Correlation.RequestIdentity || row.PredecessorRevisionID != p.candidate.Core.PreviousRevision || row.RequestedRevisionID != p.candidate.Core.Revision || row.ObservedRevisionID != p.candidate.Core.Revision:
			out.Result = failure(IntegrityFailure, InvalidRelation)
		default:
			out.Result = state.observed(ObservedCurrent)
			if i.Correlation.OperationKind == contract.OperationEnvelopeRekey {
				out.Result = p.checkRekeyTarget(state, row)
			}
			if out.Result.Outcome == ObservedCurrent {
				out.Receipt = bytes.Clone(raw)
			}
		}
		out.SourceUsabilityChecked = true
		out.SourceUsable = maintenanceCurrentSourceUsable(state, i.SourcePins.FileID, i.Configuration, i.Inputs, i.Recipients)
	}
	if p.guard.check(ctx) != contract.ReasonNone {
		out.Result = refused(AdmissionInvalid)
		out.Receipt, out.SourceUsabilityChecked, out.SourceUsable = nil, false, false
		out.CandidateCurrent, out.CurrentWarningBits, out.Query.Observation = false, 0, nil
	}
	if digest, valid := out.Query.digest(); valid {
		out.Query.Digest, out.RequestIdentity = digest, digest
	} else {
		out.Query = nil
		out.RequestIdentity = contract.ID{}
		out.Result = refused(AdmissionInvalid)
		out.Receipt, out.SourceUsabilityChecked, out.SourceUsable = nil, false, false
		out.CandidateCurrent, out.CurrentWarningBits = false, 0
	}
	out.StateResult = replacementReadState(out.Result)
	return out
}

func (p *MaintenanceObserver) checkRekeyTarget(current *StateSession, receipt contract.CompactMutationReceipt) Result {
	c := p.input.Correlation
	target := c.RekeyTarget
	identity, err := contract.ChangedSubjectIdentityID(p.input.ExpectedDomain, contract.ChangedSubjectValueEntry, target.Incarnation, contract.ID{})
	if err != nil {
		return failure(IntegrityFailure, InvalidRelation)
	}
	rows := []contract.ChangedSubjectIdentity{{Kind: contract.ChangedSubjectValueEntry, Change: contract.ChangedSubjectUpdated, Identity: identity}}
	appendGeneration := func(id contract.ID, change uint8) bool {
		identity, err := contract.ChangedSubjectIdentityID(p.input.ExpectedDomain, contract.ChangedSubjectGeneratedValue, id, contract.ID{})
		if err != nil {
			return false
		}
		rows = append(rows, contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectGeneratedValue, Change: change, Identity: identity})
		return true
	}
	if !c.BeforeGeneration.IsZero() {
		if !appendGeneration(c.BeforeGeneration, contract.ChangedSubjectRemoved) || !appendGeneration(c.AfterGeneration, contract.ChangedSubjectAdded) {
			return failure(IntegrityFailure, InvalidRelation)
		}
	}
	descriptor, err := contract.ChangedSubjectDescriptor(rows)
	if err != nil || descriptor != receipt.ChangedSubjects {
		return failure(IntegrityFailure, InvalidRelation)
	}
	return current.observed(ObservedCurrent)
}

func maintenanceCurrentSourceUsable(s *StateSession, file contract.ID, public contract.PublicConfiguration, inputs []contract.PlanningInput, recipients []contract.ApplyRecipientInput) bool {
	if !planningInputScopeMatches(public, inputs) || !maintenanceCurrentRecipientsMatch(s, recipients) {
		return false
	}
	control := currentControlOf(s)
	for _, input := range inputs {
		var current *format.ValueEntry
		for _, named := range s.root.Names {
			if named.Name == input.Name {
				current = s.valueEntry(named.Slot)
				break
			}
		}
		if input.Form == contract.PlanningRetained {
			if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret || current.Incarnation != input.Retained.Incarnation || current.ValueState != input.Retained.Material {
				return false
			}
			continue
		}
		view, err := contract.InspectSealedInputEnvelope(input.SealedInput)
		binding, bindingErr := contract.PublicBindingDigest(control.AuthorityKMSBinding)
		if err != nil || bindingErr != nil || view.Core.DomainID != s.root.Domain || view.Core.FileIdentity != file || !bytes.Equal(view.Core.Name, []byte(input.Name)) || view.Core.CompatibilityID != control.CompatibilityID || view.Core.CryptoSupportID != control.CryptoSupportID || view.AuthorityWrap.SubjectID != control.AuthorityRecipientID || view.AuthorityWrap.PublicBindingDigest != binding ||
			view.AuthorityWrap.BindingID != control.AuthorityKMSBinding.BindingID || view.AuthorityWrap.BindingSerial != control.AuthorityKMSBinding.BindingSerial {
			return false
		}
		index := slices.IndexFunc(public.Entries.Value, func(row contract.PublicEntry) bool { return row.Name == input.Name })
		if index < 0 || public.Entries.Value[index].Memberships.State != contract.PublicPresent {
			return false
		}
		members := public.Entries.Value[index].Memberships.Value
		refs := make([]contract.RecipientBindingReference, len(members))
		for i, id := range members {
			_, row := s.selectedRecipientSlot(id)
			if row == nil || row.CurrentBinding == nil {
				return false
			}
			digest, err := contract.PublicBindingDigest(*row.CurrentBinding)
			if err != nil {
				return false
			}
			refs[i] = contract.RecipientBindingReference{RecipientID: id, PublicBindingDigest: digest}
		}
		digest, err := contract.IntendedRecipientBindingSetDigest(s.root.Domain, control.AuthorityRecipientID, refs)
		if err != nil {
			return false
		}
		if digest != view.Core.IntendedRecipientBindingSetDigest {
			if current == nil || current.ValueSource != contract.Supplied || current.ConfidentialityClass != contract.Secret {
				return false
			}
			for _, id := range members {
				if !slices.Contains(current.Recipients, id) {
					return false
				}
			}
		}
	}
	return true
}

func (p *MaintenanceObserver) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.closed = true
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	p.closeOnce.Do(func() { p.input.Source.Close(); p.closeErr = p.guard.SourceError() })
	return p.closeErr
}
