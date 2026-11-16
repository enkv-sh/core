package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

// PlanningCustody has private read reach only. The installed composition owns
// its construction; request data cannot install a custody factory or sink.
type PlanningCustody interface {
	Check(context.Context) contract.PlanningCheckResult
	Display(context.Context) contract.PlanningDisplayResult
	Close()
}

type PlanningInstallation struct {
	Reader                        ReaderInstallation
	Sources                       contract.PlanningSources
	FileIdentity, CredentialRoute contract.ID
	InputDigest                   contract.ID
	AdmitCustody                  func(context.Context, contract.PlanningAdmission) (PlanningCustody, error)
}

type PlanningResult struct {
	PreAdmission *PreAdmissionRequestIdentity
	Result       Result
	Context      ReaderOperationContext
	contract.PlanningPayload
	StateResult contract.ReaderStateResult
}

type InstalledPlanning struct {
	mu           sync.Mutex
	reader       *ReaderEngine
	installation PlanningInstallation
	used, closed bool
	activeDone   chan struct{}
	cancel       context.CancelFunc
	closeOnce    sync.Once
}

func NewInstalledPlanning(i PlanningInstallation) (*InstalledPlanning, error) {
	if i.Reader.Validator == nil || !i.Sources.Trusted.Valid() || !i.Sources.Proposed.Valid() || i.FileIdentity != i.Sources.Proposed.FileIdentity ||
		i.CredentialRoute.IsZero() || i.InputDigest.IsZero() || i.AdmitCustody == nil {
		return nil, contract.ErrRecord
	}
	reader, err := newInstalledPublicReader(i.Reader)
	if err != nil {
		return nil, err
	}
	i.Reader = ReaderInstallation{}
	return &InstalledPlanning{reader: reader, installation: i}, nil
}

// PlanningInputDigest binds the captured source owner's complete public model
// and exact supplied sources. It hashes sealed bytes, never secret plaintext.
// Source locations are presentation and do not alter the existing public meaning.
func PlanningInputDigest(public contract.PublicConfiguration, inputs []contract.PlanningInput) (contract.ID, error) {
	if !publicConfigurationBounded(public) || !publicConfigurationBackingBounded(public) {
		return contract.ID{}, contract.ErrRecordCapacity
	}
	ordered, err := sortPlanningInputs(inputs)
	if err != nil {
		return contract.ID{}, err
	}
	return planningInputDigest(ownPublicConfiguration(public), ordered), nil
}

func planningInputDigest(public contract.PublicConfiguration, ordered []contract.PlanningInput) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/planning-source-input/v1\x00"))
	hashPublicSemantic(h, reflect.ValueOf(public))
	hashPublicSemantic(h, reflect.ValueOf(ordered))
	return contract.ID(h.Sum(nil))
}

func sortPlanningInputs(inputs []contract.PlanningInput) ([]contract.PlanningInput, error) {
	if len(inputs) > contract.CryptoMaxValueEntries {
		return nil, contract.ErrRecordCapacity
	}
	var raw uint64
	for _, input := range inputs {
		if len(input.Name) > contract.CryptoMaxName || !utf8.ValidString(input.Name) {
			return nil, contract.ErrRecord
		}
		switch input.Form {
		case contract.PlanningSealed:
			if input.Retained != (contract.RetainedSecretInput{}) || len(input.SealedInput) > contract.CryptoMaxSealedInputLength {
				return nil, contract.ErrRecord
			}
			view, err := contract.InspectSealedInputEnvelope(input.SealedInput)
			if err != nil || !bytes.Equal(view.Core.Name, []byte(input.Name)) {
				return nil, contract.ErrRecord
			}
			raw += uint64(view.Core.ContentLength)
		case contract.PlanningRetained:
			if len(input.SealedInput) != 0 || input.Retained.Incarnation.IsZero() || input.Retained.Material.IsZero() {
				return nil, contract.ErrRecord
			}
		default:
			return nil, contract.ErrRecord
		}
		if raw > contract.CryptoMaxRawSet {
			return nil, contract.ErrRecordCapacity
		}
	}
	owned := slices.Clone(inputs)
	slices.SortFunc(owned, func(a, b contract.PlanningInput) int { return strings.Compare(a.Name, b.Name) })
	for i := range owned {
		if i > 0 && owned[i-1].Name == owned[i].Name {
			return nil, contract.ErrRecord
		}
	}
	return owned, nil
}

func ownPlanningInputs(inputs []contract.PlanningInput) ([]contract.PlanningInput, error) {
	owned, err := sortPlanningInputs(inputs)
	if err != nil {
		return nil, err
	}
	for i := range owned {
		owned[i].Name = strings.Clone(owned[i].Name)
		owned[i].SealedInput = bytes.Clone(owned[i].SealedInput)
	}
	return owned, nil
}

func newPlanningResult(requestID, domain contract.ID) PlanningResult {
	payload := newComparisonPayload(contract.ScopeUnchecked)
	payload.EvidenceLimit = contract.PlanningEvidenceLimit
	return PlanningResult{Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused,
		Context:         ReaderOperationContext{Operation: contract.PlanningOperation, RequestID: requestID, ExpectedDomain: domain},
		PlanningPayload: contract.PlanningPayload{ComparisonPayload: payload, DisplayDelivery: contract.PlanningNotRequested}}
}

// Plan borrows the source model only until its bounded copy. The installation's
// digest fixes the exact captured proposal independently of these arguments.
func (e *InstalledPlanning) Plan(ctx context.Context, requestID contract.ID, public contract.PublicConfiguration, inputs []contract.PlanningInput, options contract.PlanningOptions) PlanningResult {
	call := telemetry.Start(ctx, telemetry.ProviderCore, telemetry.OpCorePlanning)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := e.plan(telemetry.CallContext(ctx, call), requestID, public, inputs, options, call)
	var reason contract.DiagnosticReason
	for _, d := range out.Diagnostics {
		if d.Outcome == contract.DiagnosticUnable && comparisonState([]contract.Diagnostic{d}, true) == out.StateResult {
			reason = d.Reason
			break
		}
	}
	finishReaderCall(call, out.StateResult, reason)
	return out
}

func (e *InstalledPlanning) plan(ctx context.Context, requestID contract.ID, public contract.PublicConfiguration, inputs []contract.PlanningInput, options contract.PlanningOptions, call *telemetry.Call) (out PlanningResult) {
	out = newPlanningResult(requestID, contract.ID{})
	if options.Publish {
		defer func() {
			requestedPublicationPreview(&out.ComparisonPayload, out.Result.Reason)
			sortPublicationPreview(out.Publication)
		}()
	}

	if e == nil || ctx == nil || requestID.IsZero() {
		out.fail(readerRefusal(contract.ReasonInvalidInput))
		return out
	}
	if f := manifestContextFailure(ctx); f.Outcome != 0 {
		out.fail(f)
		return out
	}
	e.mu.Lock()
	if e.closed || e.used {
		e.mu.Unlock()
		out.fail(readerRefusal(contract.ReasonInvalidInput))
		return out
	}
	e.used = true
	i, reader := e.installation, e.reader
	out.Context.ExpectedDomain = reader.expectedDomain
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	e.cancel, e.activeDone = cancel, done
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		e.cancel, e.activeDone = nil, nil
		close(done)
		e.mu.Unlock()
	}()
	if !options.Valid() || options.Purpose != contract.PlanningEquality && options.Purpose != contract.PlanningDisplay {
		out.fail(readerRefusal(contract.ReasonInvalidInput))
		return out
	}
	options.SelectedNames = slices.Clone(options.SelectedNames)
	for n := range options.SelectedNames {
		options.SelectedNames[n] = strings.Clone(options.SelectedNames[n])
	}
	if options.Purpose == contract.PlanningDisplay {
		out.DisplayDelivery = contract.PlanningDeliveryNone
		out.SelectedRecords = uint32(len(options.SelectedNames))
	}
	if !publicConfigurationBounded(public) || !publicConfigurationBackingBounded(public) {
		out.fail(readerRefusal(contract.ReasonLimitExceeded))
		return out
	}
	capturedPublic := ownPublicConfiguration(public)
	owned, err := ownPlanningInputs(inputs)
	if err != nil {
		out.fail(readerRefusal(contract.ReasonInvalidInput))
		return out
	}
	digest := planningInputDigest(capturedPublic, owned)
	if digest != i.InputDigest {
		out.fail(readerRefusal(contract.ReasonInvalidInput))
		return out
	}
	desired := reader.validator.Validate(ctx, capturedPublic)
	if !desired.Valid || !desired.Complete || !desired.DiagnosticsComplete {
		refusal := RefusePublicComparisonSource(requestID, reader.expectedDomain, desired)
		out.ComparisonPayload, out.Result, out.StateResult = refusal.ComparisonPayload, refusal.Result, refusal.StateResult
		out.EvidenceLimit = contract.PlanningEvidenceLimit
		return out
	}
	if !planningInputScopeMatches(desired.Configuration, owned) {
		out.fail(readerRefusal(contract.ReasonInvalidInput))
		return out
	}
	out.PrivateEntries = make([]contract.PlanningRelation, len(owned))
	for at, input := range owned {
		out.PrivateEntries[at] = contract.PlanningRelation{Name: input.Name, Form: input.Form, Relation: contract.PlanningUnchecked}
	}
	for _, name := range options.SelectedNames {
		if !slices.ContainsFunc(owned, func(input contract.PlanningInput) bool { return input.Name == name }) {
			out.fail(readerRefusal(contract.ReasonInvalidInput))
			return out
		}
	}
	request := planningRequestDigest(requestID, i, digest, options)
	inv, f := reader.beginReaderInvocation(ctx, contract.ReaderCompareOperation, request)
	if f.Outcome != 0 {
		out.fail(f)
		return out
	}
	defer inv.Close()
	out.Context.OperationID = readerOperationID(inv.admission, contract.ID{}, contract.ID{})
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	var retirements []generatedPlanningRetirement
	selected, f := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, request, func(ctx context.Context, g *generatedSelection) error {
		var err error
		retirements, err = collectGeneratedPlanningRetirements(ctx, g, desired)
		return err
	})
	if f.Outcome != 0 {
		out.fail(f)
		return out
	}
	observation := &contract.ComparisonObservation{DomainID: selected.image.root.Domain, HeadRevisionID: selected.basis.anchor.head.Core.Revision, SnapshotID: selected.image.root.Snapshot}
	out.Observation = observation
	out.Context.OperationID = readerOperationID(inv.admission, observation.HeadRevisionID, observation.SnapshotID)
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	actual, f := reader.projectPublicConfiguration(ctx, selected)
	if reason := inv.admission.failure(ctx, contract.ReaderCompareOperation, request); reason != "" {
		f = readerRefusal(reason)
	}
	if f.Outcome != 0 {
		out.fail(f)
		return out
	}
	out.ComparisonPayload = comparePublicConfigurations(ctx, desired, actual)
	out.Observation, out.EvidenceLimit = observation, contract.PlanningEvidenceLimit
	out.StateResult = comparisonState(out.Diagnostics, out.DiagnosticsComplete)
	out.Result = readerCoreResult(out.StateResult)
	if out.StateResult != contract.ReaderSuccess || out.Verdict == contract.ComparisonUnable {
		return out
	}
	out.GeneratedEntries = generatedPlanningEntries(desired, actual, &selected, retirements)
	var publicationRefinements []publicationPreviewRefinement
	if options.Publish {
		out.Publication, publicationRefinements, f = reader.projectPublicationPreview(ctx, &selected, desired, actual)
		if f.Outcome != 0 {
			out.fail(f)
			return out
		}
	}

	admission, f := planningAdmissionForSelection(ctx, &selected, requestID, i, owned, desired.Configuration, options)
	if f.Outcome != 0 {
		out.fail(f)
		return out
	}
	if len(owned) != 0 {
		call.Checkpoint(telemetry.DiagnosticPrivateCustody, telemetry.DiagnosticReasonNone)
		custody, err := i.AdmitCustody(ctx, admission)
		var closeCustody func()
		if custody != nil {
			closeCustody = sync.OnceFunc(custody.Close)
			defer closeCustody()
		}
		if err != nil || custody == nil {
			code := contract.CryptoCustodyUnavailable
			var admissionError contract.PlanningAdmissionError
			if errors.As(err, &admissionError) && admissionError.Code.Valid() && admissionError.Code != contract.CryptoSuccess {
				code = admissionError.Code
			}
			out.fail(planningCryptoFailure(code))
			return out
		}
		checked := custody.Check(ctx)
		if len(checked.Rows) == 0 && !checked.Complete && checked.Code.Valid() && checked.Code != contract.CryptoSuccess {
			checked.Rows = slices.Clone(out.PrivateEntries)
		}
		if !planningCheckMatches(admission.Targets, checked) {
			out.fail(readerFailure{Result: failure(IntegrityFailure, InvalidRelation), diagnostic: contract.ReasonSelectedRelationInvalid})
			return out
		}
		out.PrivateEntries = slices.Clone(checked.Rows)
		if !checked.Complete || checked.Code != contract.CryptoSuccess {
			out.fail(planningCryptoFailure(checked.Code))
			return out
		}
		out.PrivateComplete = true
		if options.Publish {
			refinePublicationPreview(out.Publication, publicationRefinements, out.PrivateEntries)
		}
		if options.Purpose == contract.PlanningDisplay {
			if reason := inv.admission.failure(ctx, contract.ReaderCompareOperation, request); reason != "" {
				out.fail(readerRefusal(reason))
				return out
			}
			displayed := custody.Display(ctx)
			if !planningDisplayMatches(out.SelectedRecords, displayed) {
				out.DisplayDelivery = contract.PlanningDeliveryIncomplete
				out.fail(readerRefusal(contract.ReasonInvalidInput))
				return out
			}
			out.DisplayDelivery, out.CompletedRecords = displayed.Delivery, displayed.CompletedRecords
			if displayed.Delivery != contract.PlanningDeliveryComplete {
				if displayed.OutputFailed {
					out.fail(readerRefusal(contract.ReasonInvalidInput))
				} else {
					out.fail(planningCryptoFailure(displayed.Code))
				}
				return out
			}
		}
		closeCustody()
	}
	if len(owned) == 0 {
		out.PrivateComplete = true
	}
	if reason := inv.admission.failure(ctx, contract.ReaderCompareOperation, request); reason != "" {
		out.fail(readerRefusal(reason))
		return out
	}
	out.PrivateComplete = true
	for _, row := range out.PrivateEntries {
		if row.Relation == contract.PlanningChanged || row.Relation == contract.PlanningNew {
			out.Verdict = contract.ComparisonMismatch
		}
	}
	out.StateResult = contract.ReaderSuccess
	out.Result = Result{Outcome: ObservedCurrent, ObservedRevision: observation.HeadRevisionID, ObservedSnapshotID: observation.SnapshotID, Evidence: AuthenticatedClosure}
	return out
}

func planningInputScopeMatches(public contract.PublicConfiguration, inputs []contract.PlanningInput) bool {
	if public.Entries.State != contract.PublicPresent {
		return false
	}
	at := 0
	for _, entry := range public.Entries.Value {
		if entry.Source.State != contract.PublicPresent || entry.Class.State != contract.PublicPresent {
			return false
		}
		if entry.Source.Value != contract.Supplied || entry.Class.Value != contract.Secret {
			continue
		}
		if at >= len(inputs) || inputs[at].Name != entry.Name {
			return false
		}
		at++
	}
	return at == len(inputs)
}

func planningRequestDigest(requestID contract.ID, i PlanningInstallation, digest contract.ID, options contract.PlanningOptions) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/private-planning-request/v1\x00"))
	h.Write(requestID[:])
	h.Write(digest[:])
	h.Write(i.CredentialRoute[:])
	hashPublicSemantic(h, reflect.ValueOf(i.Sources))
	hashPublicSemantic(h, reflect.ValueOf(options))
	return contract.ID(h.Sum(nil))
}

func planningAdmissionForSelection(ctx context.Context, selected *publicSelection, requestID contract.ID, i PlanningInstallation, inputs []contract.PlanningInput, public contract.PublicConfiguration, options contract.PlanningOptions) (contract.PlanningAdmission, readerFailure) {
	var q contract.PlanningAdmission
	invalid := func() (contract.PlanningAdmission, readerFailure) {
		return contract.PlanningAdmission{}, readerRefusal(contract.ReasonInvalidInput)
	}
	if selected == nil || !selected.complete || !publicReadInvocationCurrent(ctx, selected.basis.anchor) {
		return invalid()
	}
	authority, ok := selected.authorityBinding()
	control, controlOK := selectedControlFrom(selected.image.root, &selected.image.recipients, selected.authorityID)
	if !ok || !controlOK {
		return contract.PlanningAdmission{}, readerFailure{Result: failure(IntegrityFailure, InvalidRelation), diagnostic: contract.ReasonSelectedRelationInvalid}
	}
	q = contract.PlanningAdmission{RequestID: requestID, DomainID: selected.image.root.Domain, HEADDigest: contract.Hash(selected.basis.anchor.headBody),
		HEADRevision: selected.basis.anchor.head.Core.Revision, SnapshotID: selected.image.root.Snapshot, Root: selected.basis.anchor.head.Core.Root,
		HEADToken: selected.basis.anchor.headToken, AccessRoot: selected.image.root.CurrentAccess.AccessRoot, CredentialRoute: i.CredentialRoute,
		Sources: i.Sources, Control: control, Authority: authority, Options: options, Targets: make([]contract.PlanningTarget, 0, len(inputs))}
	if _, err := rand.Read(q.SessionID[:]); err != nil || q.SessionID.IsZero() {
		return invalid()
	}
	var raw uint64
	for _, input := range inputs {
		target := contract.PlanningTarget{Input: input}
		index := slices.IndexFunc(public.Entries.Value, func(entry contract.PublicEntry) bool { return entry.Name == input.Name })
		if index < 0 || public.Entries.Value[index].Memberships.State != contract.PublicPresent {
			return invalid()
		}
		target.ProposedRecipients = slices.Clone(public.Entries.Value[index].Memberships.Value)
		before := slices.IndexFunc(selected.image.root.Names, func(row format.NameEntry) bool { return row.Name == input.Name })
		if before >= 0 {
			slot := selected.image.root.Names[before].Slot
			entry := selectedValueEntry(&selected.image.pages, slot)
			if entry == nil {
				return invalid()
			}
			target.CurrentPresent, target.CurrentValueSource, target.CurrentConfidentialityClass = true, entry.ValueSource, entry.ConfidentialityClass
			if entry.ValueSource == contract.Supplied && entry.ConfidentialityClass == contract.Secret {
				core, payload, access, ok := selectedValueFrom(q.DomainID, selected.image.root, &selected.image.pages, &selected.image.recipients,
					&selected.image.access, selected.materials.accessLocations, selected.materials.valueReaders, slot)
				digest, err := contract.PublicValueEntryDigest(q.DomainID, slot, *entry)
				if !ok || err != nil {
					return contract.PlanningAdmission{}, readerFailure{Result: failure(IntegrityFailure, InvalidRelation), diagnostic: contract.ReasonSelectedRelationInvalid}
				}
				target.Current = &contract.ConsumerSelection{DomainID: q.DomainID, SnapshotID: q.SnapshotID, HEADDigest: q.HEADDigest, AccessRoot: q.AccessRoot,
					EntryDigest: digest, Root: q.Root, HEADRevision: q.HEADRevision, HEADToken: q.HEADToken, Slot: slot,
					Entry: *entry, Core: core, Payload: payload, Access: access, Binding: authority}
			}
		}
		switch input.Form {
		case contract.PlanningSealed:
			view, err := contract.InspectSealedInputEnvelope(input.SealedInput)
			if err != nil || view.Core.DomainID != q.DomainID || view.Core.FileIdentity != i.FileIdentity || view.Core.CompatibilityID != contract.CompatibilityID() ||
				view.Core.CryptoSupportID != control.CryptoSupportID || !bytes.Equal(view.Core.Name, []byte(input.Name)) ||
				view.AuthorityWrap.SubjectKind != authority.SubjectKind || view.AuthorityWrap.SubjectID != authority.SubjectID ||
				view.AuthorityWrap.BindingID != authority.Binding.BindingID || view.AuthorityWrap.BindingSerial != authority.Binding.BindingSerial {
				return invalid()
			}
			bindingDigest, err := contract.PublicBindingDigest(authority.Binding)
			if err != nil || view.AuthorityWrap.PublicBindingDigest != bindingDigest {
				return invalid()
			}
			raw += uint64(view.Core.ContentLength)
		case contract.PlanningRetained:
			if target.Current == nil || target.Current.Entry.Incarnation != input.Retained.Incarnation || target.Current.Entry.ValueState != input.Retained.Material {
				return invalid()
			}
			raw += uint64(target.Current.Payload.ContentLength)
		default:
			return invalid()
		}
		if raw > contract.CryptoMaxRawSet {
			return contract.PlanningAdmission{}, readerRefusal(contract.ReasonLimitExceeded)
		}
		q.Targets = append(q.Targets, target)
	}
	return q, readerFailure{}
}

func planningCheckMatches(targets []contract.PlanningTarget, checked contract.PlanningCheckResult) bool {
	if len(targets) != len(checked.Rows) || !checked.Code.Valid() || checked.Complete != (checked.Code == contract.CryptoSuccess) {
		return false
	}
	unfinished := false
	for at, target := range targets {
		row := checked.Rows[at]
		if row.Name != target.Input.Name || row.Form != target.Input.Form {
			return false
		}
		if unfinished {
			if row.Relation != contract.PlanningUnchecked || row.Code != 0 {
				return false
			}
			continue
		}
		if row.Relation == contract.PlanningFailed {
			if checked.Complete || row.Code != checked.Code || row.Code == contract.CryptoSuccess {
				return false
			}
			unfinished = true
			continue
		}
		if !checked.Complete && row.Relation == contract.PlanningUnchecked && row.Code == 0 {
			unfinished = true
			continue
		}
		if row.Code != contract.CryptoSuccess {
			return false
		}
		switch {
		case !target.CurrentPresent:
			if row.Relation != contract.PlanningNew || target.Input.Form != contract.PlanningSealed {
				return false
			}
		case target.Current == nil:
			if row.Relation != contract.PlanningUnchecked || target.Input.Form != contract.PlanningSealed {
				return false
			}
		case target.Input.Form == contract.PlanningRetained:
			if row.Relation != contract.PlanningEqual {
				return false
			}
		default:
			if row.Relation != contract.PlanningEqual && row.Relation != contract.PlanningChanged {
				return false
			}
		}
	}
	return true
}

func planningCryptoFailure(code contract.CryptoResultCode) readerFailure {
	switch code {
	case contract.CryptoStoredAuthenticationFailed:
		return readerFailure{Result: failure(IntegrityFailure, InvalidProof), diagnostic: contract.ReasonSelectedObjectInvalid}
	case contract.CryptoCustodyUnavailable, contract.CryptoPrivateRouteUnavailable, contract.CryptoResponseUnknown:
		return readerFailure{Result: failure(EvidenceUnavailable, CustodyUnavailable), diagnostic: contract.ReasonEvidenceUnavailable}
	case contract.CryptoExpired:
		return readerRefusal(contract.ReasonExpired)
	case contract.CryptoCancelled:
		return readerRefusal(contract.ReasonCancelled)
	case contract.CryptoCapacityExceeded:
		return readerRefusal(contract.ReasonLimitExceeded)
	default:
		return readerRefusal(contract.ReasonInvalidInput)
	}
}

func (r *PlanningResult) fail(f readerFailure) {
	public := PublicComparisonResult{Result: r.Result, ComparisonPayload: r.ComparisonPayload, StateResult: r.StateResult}
	public.finishComparisonFailure(f)
	r.Result, r.StateResult, r.ComparisonPayload = public.Result, public.StateResult, public.ComparisonPayload
	r.EvidenceLimit = contract.PlanningEvidenceLimit
	r.Verdict = contract.ComparisonUnable
}

// Close stops further admission, cancels and joins the active read, then
// releases the installed GET-only source resources exactly once.
func (e *InstalledPlanning) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	cancel, done := e.cancel, e.activeDone
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	e.closeOnce.Do(func() {
		e.reader.Close()
		e.mu.Lock()
		e.installation = PlanningInstallation{}
		e.mu.Unlock()
	})
}

func planningDisplayMatches(selected uint32, result contract.PlanningDisplayResult) bool {
	if selected == 0 || selected > contract.CryptoMaxValueEntries || result.SelectedRecords != selected || result.CompletedRecords > selected || !result.Code.Valid() {
		return false
	}
	switch result.Delivery {
	case contract.PlanningDeliveryNone:
		return result.CompletedRecords == 0 && result.Code != contract.CryptoSuccess
	case contract.PlanningDeliveryComplete:
		return result.CompletedRecords == selected && result.Code == contract.CryptoSuccess && !result.OutputFailed
	case contract.PlanningDeliveryIncomplete:
		return result.Code != contract.CryptoSuccess
	}
	return false
}
