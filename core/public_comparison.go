package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"reflect"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

type ReaderOperationContext struct {
	Operation                              string
	OperationID, RequestID, ExpectedDomain contract.ID
}

type PublicComparisonResult struct {
	PreAdmission *PreAdmissionRequestIdentity
	Result       Result
	Context      ReaderOperationContext
	contract.ComparisonPayload
	StateResult contract.ReaderStateResult
}

// RefusePublicComparisonSource reports pure source validation before service
// construction. It owns the copied diagnostics and never reports authenticated
// success, an observation or checked scope. At most the trusted and candidate
// source validations may be supplied.
func RefusePublicComparisonSource(requestID, domain contract.ID, validations ...PublicConfigurationValidation) PublicComparisonResult {
	result := PublicComparisonResult{ComparisonPayload: newComparisonPayload(contract.ScopeUnchecked), Context: ReaderOperationContext{Operation: contract.ReaderCompareOperation, RequestID: requestID, ExpectedDomain: domain}, Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused}
	if len(validations) == 0 || len(validations) > 2 {
		result.addComparisonFailure(contract.ReasonInvalidInput)
		return result
	}
	count := 0
	for _, validation := range validations {
		count += min(len(validation.Diagnostics), contract.MaxPublicDiagnostics-count)
	}
	result.Diagnostics = make([]contract.Diagnostic, 0, count)
	for _, validation := range validations {
		result.DiagnosticsComplete = result.DiagnosticsComplete && validation.DiagnosticsComplete
		for _, diagnostic := range validation.Diagnostics {
			if len(result.Diagnostics) == contract.MaxPublicDiagnostics {
				appendComparisonDiagnostic(&result.ComparisonPayload, contract.Diagnostic{})
				break
			}
			owned := diagnostic
			owned.Path = make([]contract.DiagnosticField, len(diagnostic.Path))
			copy(owned.Path, diagnostic.Path)
			if diagnostic.SourceLocation != nil {
				location := *diagnostic.SourceLocation
				owned.SourceLocation = &location
			}
			appendComparisonDiagnostic(&result.ComparisonPayload, owned)
		}
	}
	slices.SortFunc(result.Diagnostics, comparePublicDiagnostics)
	result.StateResult = comparisonState(result.Diagnostics, result.DiagnosticsComplete)
	if result.StateResult == contract.ReaderSuccess {
		result.addComparisonFailure(contract.ReasonInvalidInput)
	} else {
		result.Result = readerCoreResult(result.StateResult)
	}
	return result
}

func (e *ReaderEngine) comparePublic(ctx context.Context, requestID contract.ID, input contract.PublicConfiguration, call *telemetry.Call, options ...contract.ComparisonOptions) (result PublicComparisonResult) {
	result = PublicComparisonResult{ComparisonPayload: newComparisonPayload(contract.ScopeUnchecked), Context: ReaderOperationContext{Operation: contract.ReaderCompareOperation, RequestID: requestID}, Result: refused(AdmissionInvalid), StateResult: contract.ReaderRefused}
	publish := false
	for _, option := range options {
		publish = publish || option.Publish
	}
	if publish {
		defer func() {
			requestedPublicationPreview(&result.ComparisonPayload, result.Result.Reason)
			sortPublicationPreview(result.Publication)
		}()
	}
	if len(options) > 1 {
		result.addComparisonFailure(contract.ReasonInvalidInput)
		return result
	}

	var validator *PublicConfigurationValidator
	if e != nil {
		e.mu.Lock()
		validator = e.validator
		result.Context.ExpectedDomain = e.expectedDomain
		e.mu.Unlock()
	}
	desired := validator.ValidateProposed(ctx, input)
	result.Diagnostics = desired.Diagnostics
	result.DiagnosticsComplete = desired.DiagnosticsComplete
	if !desired.Valid || !desired.Complete || !desired.DiagnosticsComplete {
		result = RefusePublicComparisonSource(requestID, result.Context.ExpectedDomain, desired)
	}
	if requestID.IsZero() {
		result.addComparisonFailure(contract.ReasonInvalidInput)
		return result
	}
	request := publicComparisonRequestDigest(requestID, desired)
	if publish {
		request = contract.Hash(append([]byte("ENKV/publication-preview-request/v1\x00"), request[:]...))
	}
	inv, failed := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, request)
	if failed.Outcome != 0 {
		result.finishComparisonFailure(failed)
		return result
	}
	defer inv.Close()
	result.Context.OperationID = readerOperationID(inv.admission, contract.ID{}, contract.ID{})
	call.Checkpoint(telemetry.DiagnosticStateLoading, telemetry.DiagnosticReasonNone)
	var retirements []generatedPlanningRetirement
	selected, failed := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, request, func(ctx context.Context, g *generatedSelection) error {
		var err error
		retirements, err = collectGeneratedPlanningRetirements(ctx, g, desired)
		return err
	})
	if failed.Outcome != 0 {
		result.finishComparisonFailure(failed)
		return result
	}
	result.Observation = &contract.ComparisonObservation{DomainID: selected.image.root.Domain, HeadRevisionID: selected.basis.anchor.head.Core.Revision, SnapshotID: selected.image.root.Snapshot}
	result.Context.OperationID = readerOperationID(inv.admission, result.Observation.HeadRevisionID, result.Observation.SnapshotID)
	call.Checkpoint(telemetry.DiagnosticAuthentication, telemetry.DiagnosticReasonNone)
	actual, failed := e.projectPublicConfiguration(ctx, selected)
	if reason := inv.admission.failure(ctx, contract.ReaderCompareOperation, request); reason != "" {
		failed = readerRefusal(reason)
	}
	if failed.Outcome != 0 {
		result.finishComparisonFailure(failed)
		return result
	}
	result.ComparisonPayload = comparePublicConfigurations(ctx, desired, actual)
	if result.Verdict != contract.ComparisonUnable {
		result.GeneratedEntries = generatedPlanningEntries(desired, actual, &selected, retirements)
		if publish {
			result.Publication, _, failed = e.projectPublicationPreview(ctx, &selected, desired, actual)
			if failed.Outcome != 0 {
				result.finishComparisonFailure(failed)
			}
		}

	}
	result.Observation = &contract.ComparisonObservation{DomainID: selected.image.root.Domain, HeadRevisionID: selected.basis.anchor.head.Core.Revision, SnapshotID: selected.image.root.Snapshot}
	if reason := inv.admission.failure(ctx, contract.ReaderCompareOperation, request); reason != "" {
		result.ComparisonPayload = newComparisonPayload(contract.ScopeUnchecked)
		result.Observation = &contract.ComparisonObservation{DomainID: selected.image.root.Domain, HeadRevisionID: selected.basis.anchor.head.Core.Revision, SnapshotID: selected.image.root.Snapshot}
		result.Diagnostics = desired.Diagnostics
		result.DiagnosticsComplete = desired.DiagnosticsComplete
		result.finishComparisonFailure(readerRefusal(reason))
		return result
	}
	if failed.Outcome != 0 {
		return result
	}
	result.StateResult = comparisonState(result.Diagnostics, result.DiagnosticsComplete)
	result.Result = readerCoreResult(result.StateResult)
	result.Result.ObservedRevision = result.Observation.HeadRevisionID
	result.Result.ObservedSnapshotID = result.Observation.SnapshotID
	result.Result.Evidence = AuthenticatedClosure
	return result
}

func newComparisonPayload(status contract.ComparisonScopeStatus) contract.ComparisonPayload {
	return contract.ComparisonPayload{Verdict: contract.ComparisonUnable, DiagnosticsComplete: true, EvidenceLimit: contract.ComparisonEvidenceLimit, CheckedScope: []contract.ComparisonScope{
		{Family: contract.ScopeEntries, Status: status}, {Family: contract.ScopePlainValues, Status: status}, {Family: contract.ScopeSecretSettings, Status: status}, {Family: contract.ScopeMemberships, Status: status}, {Family: contract.ScopeRecipients, Status: status}, {Family: contract.ScopeEncryption, Status: status}, {Family: contract.ScopeGenerated, Status: status}, {Family: contract.ScopeOutputs, Status: status}, {Family: contract.ScopeRouting, Status: status}, {Family: contract.ScopeDomainStore, Status: status}, {Family: contract.ScopeAuthorityRecovery, Status: status}, {Family: contract.ScopeCompatibilityProfiles, Status: status},
	}}
}

func (r *PublicComparisonResult) addComparisonFailure(reason contract.DiagnosticReason) {
	r.Verdict = contract.ComparisonUnable
	d := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}
	appendComparisonDiagnostic(&r.ComparisonPayload, d)
	slices.SortFunc(r.Diagnostics, comparePublicDiagnostics)
	r.StateResult = comparisonState(r.Diagnostics, r.DiagnosticsComplete)
	r.Result = readerCoreResult(r.StateResult)
}
func (r *PublicComparisonResult) finishComparisonFailure(failed readerFailure) {
	if failed.diagnostic == contract.ReasonProofInvalid || failed.diagnostic == contract.ReasonHeadInvalid {
		r.Changes, r.BeforeRecipients, r.AfterRecipients = nil, nil, nil
		for at := range r.CheckedScope {
			r.CheckedScope[at].Status = contract.ScopeUnchecked
		}
	}
	r.addComparisonFailure(failed.diagnostic)
	// Typed read classification retains Store failure facts; independent source
	// faults can have stronger precedence than this observation failure.
	classified := readerCoreResult(r.StateResult)
	if classified.Outcome == failed.Outcome {
		r.Result = failed.Result
	}
}

func comparisonState(rows []contract.Diagnostic, complete bool) contract.ReaderStateResult {
	state := contract.ReaderSuccess
	rank := 0
	if !complete {
		state = contract.ReaderRefused
		rank = 6
	}
	for _, d := range rows {
		if d.Outcome != contract.DiagnosticUnable {
			continue
		}
		next, n := contract.ReaderRefused, 6
		switch d.Reason {
		case contract.ReasonPublicFactUnavailable, contract.ReasonEvidenceUnavailable, contract.ReasonSelectedObjectUnavailable:
			next, n = contract.ReaderUnavailable, 2
		case contract.ReasonReadContention:
			next, n = contract.ReaderContention, 1
		case contract.ReasonHeadInvalid, contract.ReasonProofInvalid, contract.ReasonSelectedObjectInvalid, contract.ReasonSelectedRelationInvalid:
			next, n = contract.ReaderPositiveDefect, 4
		case contract.ReasonUnsupportedProfile, contract.ReasonUnsupportedSchema:
			next, n = contract.ReaderProfileBlocked, 5
		}
		if n > rank {
			state, rank = next, n
		}
	}
	return state
}
func readerCoreResult(state contract.ReaderStateResult) Result {
	switch state {
	case contract.ReaderSuccess:
		return Result{Outcome: ObservedCurrent}
	case contract.ReaderUnavailable:
		return failure(EvidenceUnavailable, ReadUnavailable)
	case contract.ReaderContention:
		return failure(Contention, StalePrecondition)
	case contract.ReaderPositiveDefect:
		return failure(IntegrityFailure, InvalidRelation)
	default:
		return refused(AdmissionInvalid)
	}
}

func publicComparisonRequestDigest(request contract.ID, validated PublicConfigurationValidation) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/public-comparison-request/v4\x00"))
	h.Write(request[:])
	hashPublicSemantic(h, reflect.ValueOf(validated.Configuration))
	hashPublicSemantic(h, reflect.ValueOf(newComparisonPayload(contract.ScopeUnchecked).CheckedScope))
	return contract.ID(h.Sum(nil))
}
func readerOperationID(a readerAdmission, revision, snapshot contract.ID) contract.ID {
	h := sha256.New()
	h.Write([]byte("ENKV/reader-operation/v2\x00"))
	hashPublicSemantic(h, reflect.ValueOf(a.operation))
	for _, id := range []contract.ID{a.request, a.domain, a.basis.digest, a.interpretation, a.trustInterpretation, a.compatibility, a.cryptoSupport, revision, snapshot} {
		h.Write(id[:])
	}
	hashPublicSemantic(h, reflect.ValueOf(a.store))
	var deadline [8]byte
	binary.BigEndian.PutUint64(deadline[:], uint64(a.deadline.UnixNano()))
	h.Write(deadline[:])
	return contract.ID(h.Sum(nil))
}

// Structural length framing hashes the closed typed public model directly.
// Source locations are presentation, so they cannot change semantic identity.
func hashPublicSemantic(h hash.Hash, v reflect.Value) {
	var number [8]byte
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			h.Write([]byte{0})
			return
		}
		h.Write([]byte{1})
		hashPublicSemantic(h, v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).Name != "SourceLocation" {
				hashPublicSemantic(h, v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		binary.BigEndian.PutUint64(number[:], uint64(v.Len()))
		h.Write(number[:])
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			h.Write(v.Bytes())
			return
		}
		for i := 0; i < v.Len(); i++ {
			hashPublicSemantic(h, v.Index(i))
		}
	case reflect.String:
		binary.BigEndian.PutUint64(number[:], uint64(v.Len()))
		h.Write(number[:])
		// hash.Hash writes cannot fail. Bound the string conversion workspace.
		var block [4096]byte
		for text := v.String(); text != ""; {
			n := copy(block[:], text)
			h.Write(block[:n])
			text = text[n:]
		}
	case reflect.Bool:
		if v.Bool() {
			number[7] = 1
		}
		h.Write(number[:])
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		binary.BigEndian.PutUint64(number[:], v.Uint())
		h.Write(number[:])
	}
}

type publicComparisonBuilder struct {
	payload                  contract.ComparisonPayload
	unavailable              map[publicDiagnosticFieldKey]bool
	counting                 bool
	differences              int
	constructionFailures     int
	wantAbsent, actualAbsent bool
}

func appendComparisonDiagnostic(p *contract.ComparisonPayload, d contract.Diagnostic) {
	if len(p.Diagnostics)+len(p.Changes) >= contract.MaxPublicDiagnostics {
		incompleteComparison(p)
		return
	}
	if len(p.Diagnostics) == cap(p.Diagnostics) {
		next := make([]contract.Diagnostic, len(p.Diagnostics), len(p.Diagnostics)+1)
		copy(next, p.Diagnostics)
		p.Diagnostics = next
	}
	d.Subject.Name = strings.Clone(d.Subject.Name)
	d.Subject.DestinationID = strings.Clone(d.Subject.DestinationID)
	d.Subject.RoutingKey.EntryName = strings.Clone(d.Subject.RoutingKey.EntryName)
	path := make([]contract.DiagnosticField, len(d.Path))
	copy(path, d.Path)
	d.Path = path
	if d.SourceLocation != nil {
		location := *d.SourceLocation
		location.SourceID = strings.Clone(location.SourceID)
		d.SourceLocation = &location
	}
	p.Diagnostics = append(p.Diagnostics, d)
}

func (b *publicComparisonBuilder) difference(subject contract.DiagnosticSubject, field contract.DiagnosticField, want, actual reflect.Value, source *contract.SourceLocation) {
	if b.unavailable[publicDiagnosticFieldKey{subject: subject, field: field}] {
		return
	}
	path := comparisonPath(subject, field)
	kind := contract.ComparisonFieldValueType(subject.Kind, path)
	if kind == "" || !b.wantAbsent && !comparisonValueSupported(kind, want) || !b.actualAbsent && !comparisonValueSupported(kind, actual) {
		if b.counting {
			b.constructionFailures++
			return
		}
		appendComparisonDiagnostic(&b.payload, contract.Diagnostic{Subject: subject, Path: path, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput})
		return
	}
	if b.counting {
		b.differences++
		return
	}
	if len(b.payload.Changes)+len(b.payload.Diagnostics) >= contract.MaxPublicDiagnostics {
		incompleteComparison(&b.payload)
		return
	}
	subject.Name = strings.Clone(subject.Name)
	subject.DestinationID = strings.Clone(subject.DestinationID)
	subject.RoutingKey.EntryName = strings.Clone(subject.RoutingKey.EntryName)
	change := contract.ComparisonChange{Subject: subject, Path: path, Action: contract.ComparisonChanged,
		Before: contract.ComparisonSide{State: contract.ComparisonAbsent}, After: contract.ComparisonSide{State: contract.ComparisonAbsent}}
	if source != nil {
		location := *source
		location.SourceID = strings.Clone(location.SourceID)
		change.SourceLocation = &location
	}
	if !b.actualAbsent {
		other := want
		if b.wantAbsent {
			other = reflect.Value{}
		}
		change.Before = contract.ComparisonSide{State: contract.ComparisonPresent, Value: b.ownValue(kind, subject, field, actual, other, false)}
	} else {
		change.Action = contract.ComparisonAdded
	}
	if !b.wantAbsent {
		other := actual
		if b.actualAbsent {
			other = reflect.Value{}
		}
		change.After = contract.ComparisonSide{State: contract.ComparisonPresent, Value: b.ownValue(kind, subject, field, want, other, true)}
	} else {
		change.Action = contract.ComparisonRemoved
	}
	if change.Before.State == contract.ComparisonPresent && change.Before.Value == nil || change.After.State == contract.ComparisonPresent && change.After.Value == nil {
		b.payload.DiagnosticsComplete = false
		appendComparisonDiagnostic(&b.payload, contract.Diagnostic{Subject: subject, Path: path, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput})
		return
	}
	b.payload.Changes = append(b.payload.Changes, change)
}

func comparePublicField[T any](b *publicComparisonBuilder, subject contract.DiagnosticSubject, field contract.DiagnosticField, want, actual contract.PublicField[T]) {
	if b.wantAbsent && b.actualAbsent || !b.wantAbsent && want.State != contract.PublicPresent || !b.actualAbsent && actual.State != contract.PublicPresent {
		return
	}
	w, a := reflect.ValueOf(want.Value), reflect.ValueOf(actual.Value)
	equal := false
	if !b.wantAbsent && !b.actualAbsent {
		if field == contract.FieldPlainValue && w.Type() == reflect.TypeFor[comparisonPlainValue]() {
			equal = plainComparisonEqual(w.Interface().(comparisonPlainValue), a.Interface().(comparisonPlainValue))
		} else if field == contract.FieldTargets && w.Type() == reflect.TypeFor[[]contract.PublicOutputTarget]() {
			x, y := w.Interface().([]contract.PublicOutputTarget), a.Interface().([]contract.PublicOutputTarget)
			equal = slices.EqualFunc(x, y, func(x, y contract.PublicOutputTarget) bool { return x.EntryName == y.EntryName })
		} else {
			equal = publicComparisonValueEqual(w, a)
		}
	}
	if !equal {
		b.difference(subject, field, w, a, want.SourceLocation)
	}
}

// Both lists have been normalized by their single validation owner. Merge them
// in place without an extra union image or a second large routing index.
func comparePublicRows[T any](b *publicComparisonBuilder, want, actual contract.PublicField[[]T], order func(T, T) int, subject func(T) contract.DiagnosticSubject, compare func(T, T)) {
	if !b.wantAbsent && want.State != contract.PublicPresent || !b.actualAbsent && actual.State != contract.PublicPresent {
		return
	}
	wantRows, actualRows := want.Value, actual.Value
	if b.wantAbsent {
		wantRows = nil
	}
	if b.actualAbsent {
		actualRows = nil
	}
	visit := func(w, a T, wantAbsent, actualAbsent bool) {
		s := subject(w)
		if wantAbsent {
			s = subject(a)
		}
		if b.unavailable[publicDiagnosticFieldKey{subject: s, field: contract.FieldPresence}] {
			return
		}
		b.withAbsence(wantAbsent, actualAbsent, func() {
			present := contract.PublicField[bool]{State: contract.PublicPresent, Value: true}
			comparePublicField(b, s, contract.FieldPresence, present, present)
			compare(w, a)
		})
	}
	i, j := 0, 0
	var zero T
	for i < len(wantRows) || j < len(actualRows) {
		if j == len(actualRows) || i < len(wantRows) && order(wantRows[i], actualRows[j]) < 0 {
			visit(wantRows[i], zero, false, true)
			i++
			continue
		}
		if i == len(wantRows) || order(wantRows[i], actualRows[j]) > 0 {
			visit(zero, actualRows[j], true, false)
			j++
			continue
		}
		visit(wantRows[i], actualRows[j], false, false)
		i++
		j++
	}
}

func comparePublicConfigurations(ctx context.Context, want, actual PublicConfigurationValidation) contract.ComparisonPayload {
	b := publicComparisonBuilder{payload: newComparisonPayload(contract.ScopeComplete), unavailable: make(map[publicDiagnosticFieldKey]bool)}
	b.payload.DiagnosticsComplete = want.DiagnosticsComplete && actual.DiagnosticsComplete
	faults := 0
	walkComparisonFaults(want.Diagnostics, actual.Diagnostics, func(d contract.Diagnostic) {
		faults++
		b.unavailable[publicDiagnosticFieldKey{subject: d.Subject, field: d.Path[len(d.Path)-1]}] = true
		b.markScope(d)
	})
	b.counting = true
	comparePublicConfigurationFields(&b, want, actual)
	b.counting = false
	failureCount := min(faults+b.constructionFailures, contract.MaxPublicDiagnostics)
	changeCount := min(b.differences, contract.MaxPublicDiagnostics-failureCount)
	b.payload.Diagnostics = make([]contract.Diagnostic, 0, failureCount)
	b.payload.Changes = make([]contract.ComparisonChange, 0, changeCount)
	if !hasGlobalConfigurationFailure(want.Diagnostics) && !hasGlobalConfigurationFailure(actual.Diagnostics) {
		b.payload.BeforeRecipients = comparisonRecipientLabels(actual.Configuration.Recipients)
		b.payload.AfterRecipients = comparisonRecipientLabels(want.Configuration.Recipients)
	}
	walkComparisonFaults(want.Diagnostics, actual.Diagnostics, func(d contract.Diagnostic) { appendComparisonDiagnostic(&b.payload, d) })
	comparePublicConfigurationFields(&b, want, actual)
	b.finish(ctx)
	return b.payload
}

func comparePublicConfigurationFields(b *publicComparisonBuilder, want, actual PublicConfigurationValidation) {
	w, a := want.Configuration, actual.Configuration
	if w.Entries.State != contract.PublicPresent || a.Entries.State != contract.PublicPresent {
		b.unchecked(contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeGenerated)
	}
	if w.Recipients.State != contract.PublicPresent || a.Recipients.State != contract.PublicPresent {
		b.unchecked(contract.ScopeRecipients, contract.ScopeEncryption)
	}
	if w.OutputBindings.State != contract.PublicPresent || a.OutputBindings.State != contract.PublicPresent {
		b.unchecked(contract.ScopeOutputs)
	}
	if w.Routing.State != contract.PublicPresent || a.Routing.State != contract.PublicPresent {
		b.unchecked(contract.ScopeRouting)
	}
	if hasGlobalConfigurationFailure(want.Diagnostics) || hasGlobalConfigurationFailure(actual.Diagnostics) {
		for i := range b.payload.CheckedScope {
			b.payload.CheckedScope[i].Status = contract.ScopeUnchecked
		}
		return
	}
	comparePublicRows(b, w.Entries, a.Entries, func(x, y contract.PublicEntry) int { return strings.Compare(x.Name, y.Name) }, func(x contract.PublicEntry) contract.DiagnosticSubject {
		return contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: x.Name}
	}, func(x, y contract.PublicEntry) {
		b.compareEntry(x, y)
	})
	comparePublicRows(b, w.Recipients, a.Recipients, func(x, y contract.PublicRecipient) int { return comparePublicIDs(x.RecipientID, y.RecipientID) }, func(x contract.PublicRecipient) contract.DiagnosticSubject {
		return contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: x.RecipientID}
	}, func(x, y contract.PublicRecipient) {
		s := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: x.RecipientID}
		if b.wantAbsent {
			s.RecipientID = y.RecipientID
		}
		comparePublicField(b, s, contract.FieldDisplayName, x.DisplayName, y.DisplayName)
		b.compareEncryption(s, x.Encryption, y.Encryption)
	})
	comparePublicRows(b, w.OutputBindings, a.OutputBindings, func(x, y contract.PublicOutputBinding) int { return strings.Compare(x.DestinationID, y.DestinationID) }, func(x contract.PublicOutputBinding) contract.DiagnosticSubject {
		return contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: x.DestinationID}
	}, func(x, y contract.PublicOutputBinding) { b.compareOutputBinding(x, y) })
	comparePublicRows(b, w.Routing, a.Routing, func(x, y contract.PublicRoutingRule) int { return comparePublicRoutingKeys(x.Key, y.Key) }, func(x contract.PublicRoutingRule) contract.DiagnosticSubject {
		return contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: x.Key}
	}, func(x, y contract.PublicRoutingRule) {
		key := x.Key
		if b.wantAbsent {
			key = y.Key
		}
		comparePublicField(b, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: key}, contract.FieldDestinations, x.Destinations, y.Destinations)
	})
	comparePublicField(b, contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldGroups, w.Groups, a.Groups)
	b.compareStore(w.Store, a.Store)
	authority := contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
	comparePublicField(b, authority, contract.FieldRecipientID, w.Authority.RecipientID, a.Authority.RecipientID)
	b.compareSigning(authority, w.Authority.Signing, a.Authority.Signing)
	recovery := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
	comparePublicField(b, recovery, contract.FieldEnabled, w.Recovery.Enabled, a.Recovery.Enabled)
	if w.Recovery.Enabled.State == contract.PublicPresent && a.Recovery.Enabled.State == contract.PublicPresent {
		wantAbsent, actualAbsent := !w.Recovery.Enabled.Value, !a.Recovery.Enabled.Value
		var ws, as contract.PublicSigningSettings
		var we, ae contract.PublicEncryptionSettings
		if w.Recovery.Signing != nil {
			ws = *w.Recovery.Signing
		}
		if a.Recovery.Signing != nil {
			as = *a.Recovery.Signing
		}
		if w.Recovery.Encryption != nil {
			we = *w.Recovery.Encryption
		}
		if a.Recovery.Encryption != nil {
			ae = *a.Recovery.Encryption
		}
		b.withAbsence(wantAbsent, actualAbsent, func() {
			if (wantAbsent || w.Recovery.Signing != nil) && (actualAbsent || a.Recovery.Signing != nil) {
				b.compareSigning(recovery, ws, as)
			} else {
				b.partial(contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles)
			}
			if (wantAbsent || w.Recovery.Encryption != nil) && (actualAbsent || a.Recovery.Encryption != nil) {
				b.compareEncryption(recovery, we, ae)
			} else {
				b.partial(contract.ScopeAuthorityRecovery, contract.ScopeEncryption, contract.ScopeCompatibilityProfiles)
			}
		})
	}
}

func hasGlobalConfigurationFailure(rows []contract.Diagnostic) bool {
	for _, d := range rows {
		if d.Subject.Kind == contract.SubjectConfiguration && d.Reason != contract.ReasonPublicFactUnavailable {
			return true
		}
	}
	return false
}
func (b *publicComparisonBuilder) finish(ctx context.Context) {
	if ctx == nil || ctx.Err() != nil {
		b.payload = newComparisonPayload(contract.ScopeUnchecked)
		appendComparisonDiagnostic(&b.payload, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonCancelled})
		return
	}
	slices.SortFunc(b.payload.Diagnostics, comparePublicDiagnostics)
	slices.SortFunc(b.payload.Changes, comparePublicChanges)
	b.payload.Verdict = contract.ComparisonMatch
	if len(b.payload.Changes) != 0 {
		b.payload.Verdict = contract.ComparisonMismatch
	}
	if !b.payload.DiagnosticsComplete {
		b.payload.Verdict = contract.ComparisonUnable
	}
	for _, d := range b.payload.Diagnostics {
		if d.Outcome == contract.DiagnosticUnable {
			b.payload.Verdict = contract.ComparisonUnable
			break
		}
		b.payload.Verdict = contract.ComparisonMismatch
	}
}
func (b *publicComparisonBuilder) unchecked(families ...contract.ComparisonFieldFamily) {
	for i := range b.payload.CheckedScope {
		if slices.Contains(families, b.payload.CheckedScope[i].Family) {
			b.payload.CheckedScope[i].Status = contract.ScopeUnchecked
		}
	}
}
func (b *publicComparisonBuilder) markScope(d contract.Diagnostic) {
	families := []contract.ComparisonFieldFamily{}
	field := d.Path[len(d.Path)-1]
	switch d.Subject.Kind {
	case contract.SubjectEntry:
		switch {
		case len(d.Path) == 2:
			families = append(families, contract.ScopeGenerated)
		case field == contract.FieldPlainValue:
			families = append(families, contract.ScopePlainValues)
		case field == contract.FieldMemberships:
			families = append(families, contract.ScopeMemberships)
		case field == contract.FieldClass:
			families = append(families, contract.ScopeEntries, contract.ScopeSecretSettings, contract.ScopePlainValues)
		case field == contract.FieldSource:
			families = append(families, contract.ScopeEntries, contract.ScopeSecretSettings, contract.ScopeGenerated, contract.ScopeCompatibilityProfiles)
		case field == contract.FieldPresence:
			families = append(families, contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeGenerated, contract.ScopeCompatibilityProfiles)
		default:
			families = append(families, contract.ScopeEntries, contract.ScopeSecretSettings)
		}
	case contract.SubjectRecipient:
		families = append(families, contract.ScopeRecipients)
		if field != contract.FieldDisplayName {
			families = append(families, contract.ScopeEncryption)
		}
		if field == contract.FieldPresence {
			families = append(families, contract.ScopeCompatibilityProfiles)
		}
	case contract.SubjectOutputBinding, contract.SubjectOutputTarget:
		families = append(families, contract.ScopeOutputs)
		if field == contract.FieldPresence || field == contract.FieldTargets || field == contract.FieldDestination {
			families = append(families, contract.ScopeCompatibilityProfiles)
		}
	case contract.SubjectRoutingRule:
		families = append(families, contract.ScopeRouting)
	case contract.SubjectStore, contract.SubjectDomain:
		families = append(families, contract.ScopeDomainStore)
	case contract.SubjectAuthority, contract.SubjectRecovery:
		families = append(families, contract.ScopeAuthorityRecovery)
		if field == contract.FieldEnabled {
			families = append(families, contract.ScopeEncryption, contract.ScopeCompatibilityProfiles)
		}
		switch field {
		case contract.FieldEncryptionProvider, contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey,
			contract.FieldEncryptionFingerprint, contract.FieldWrapProfile, contract.FieldProtectionClass:
			families = append(families, contract.ScopeEncryption)
		}
	case contract.SubjectConfiguration:
		if field == contract.FieldGroups {
			families = append(families, contract.ScopeOutputs)
			break
		}
		if d.Reason == contract.ReasonPublicFactUnavailable {
			b.unchecked(contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeGenerated)
			families = append(families, contract.ScopeCompatibilityProfiles)
			break
		}
		fallthrough
	case contract.SubjectObservation:
		for i := range b.payload.CheckedScope {
			b.payload.CheckedScope[i].Status = contract.ScopeUnchecked
		}
		return
	}
	if field == contract.FieldConfigContract || field == contract.FieldTargetContract || field == contract.FieldLifecycle || field == contract.FieldSigningProfile || field == contract.FieldWrapProfile || field == contract.FieldConstructionProfile || d.Reason == contract.ReasonUnsupportedSchema {
		families = append(families, contract.ScopeCompatibilityProfiles)
	}
	b.partial(families...)
}

func (b *publicComparisonBuilder) partial(families ...contract.ComparisonFieldFamily) {
	for i := range b.payload.CheckedScope {
		if slices.Contains(families, b.payload.CheckedScope[i].Family) && b.payload.CheckedScope[i].Status == contract.ScopeComplete {
			b.payload.CheckedScope[i].Status = contract.ScopePartial
		}
	}
}

func (b *publicComparisonBuilder) compareEncryption(subject contract.DiagnosticSubject, w, a contract.PublicEncryptionSettings) {
	comparePublicField(b, subject, contract.FieldEncryptionProvider, w.Provider, a.Provider)
	comparePublicField(b, subject, contract.FieldEncryptionSelector, w.Selector, a.Selector)
	comparePublicField(b, subject, contract.FieldEncryptionPublicKey, w.PublicKey, a.PublicKey)
	comparePublicField(b, subject, contract.FieldEncryptionFingerprint, w.Fingerprint, a.Fingerprint)
	comparePublicField(b, subject, contract.FieldWrapProfile, w.WrapProfile, a.WrapProfile)
	comparePublicField(b, subject, contract.FieldProtectionClass, w.ProtectionClass, a.ProtectionClass)
}

func (b *publicComparisonBuilder) compareSigning(subject contract.DiagnosticSubject, w, a contract.PublicSigningSettings) {
	comparePublicField(b, subject, contract.FieldSigningProvider, w.Provider, a.Provider)
	comparePublicField(b, subject, contract.FieldSigningSelector, w.Selector, a.Selector)
	comparePublicField(b, subject, contract.FieldSigningPublicKey, w.PublicKey, a.PublicKey)
	comparePublicField(b, subject, contract.FieldSigningFingerprint, w.Fingerprint, a.Fingerprint)
	comparePublicField(b, subject, contract.FieldSigningRole, w.Role, a.Role)
	comparePublicField(b, subject, contract.FieldSigningProfile, w.Profile, a.Profile)
}

func (b *publicComparisonBuilder) compareStoreFields(subject contract.DiagnosticSubject, w, a contract.PublicStoreSettings) {
	comparePublicField(b, contract.DiagnosticSubject{Kind: contract.SubjectDomain}, contract.FieldDomainID, w.DomainID, a.DomainID)
	comparePublicField(b, subject, contract.FieldProvider, w.Provider, a.Provider)
	comparePublicField(b, subject, contract.FieldConstructionProfile, w.ConstructionProfile, a.ConstructionProfile)
	comparePublicField(b, subject, contract.FieldRegion, w.Region, a.Region)
	comparePublicField(b, subject, contract.FieldBucket, w.Bucket, a.Bucket)
	comparePublicField(b, subject, contract.FieldPrefix, w.Prefix, a.Prefix)
	comparePublicField(b, subject, contract.FieldExpectedOwner, w.ExpectedOwner, a.ExpectedOwner)
}

func (b *publicComparisonBuilder) compareStore(w, a contract.PublicStoreSettings) {
	b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
}
func (b *publicComparisonBuilder) compareEntry(w, a contract.PublicEntry) {
	name := w.Name
	if b.wantAbsent {
		name = a.Name
	}
	subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: name}
	comparePublicField(b, subject, contract.FieldName, contract.PublicField[string]{State: contract.PublicPresent, Value: w.Name}, contract.PublicField[string]{State: contract.PublicPresent, Value: a.Name})
	comparePublicField(b, subject, contract.FieldClass, w.Class, a.Class)
	comparePublicField(b, subject, contract.FieldSource, w.Source, a.Source)
	comparePublicField(b, subject, contract.FieldInputEncoding, w.InputEncoding, a.InputEncoding)
	comparePublicField(b, subject, contract.FieldOutputEncoding, w.OutputEncoding, a.OutputEncoding)
	comparePublicField(b, subject, contract.FieldMemberships, w.Memberships, a.Memberships)
	if (b.wantAbsent || w.Class.State == contract.PublicPresent) && (b.actualAbsent || a.Class.State == contract.PublicPresent) {
		b.withAbsence(b.wantAbsent || w.Class.Value != contract.Plain, b.actualAbsent || a.Class.Value != contract.Plain, func() {
			comparePublicField(b, subject, contract.FieldPlainValue, publicPlainComparisonField(w.InputEncoding, w.PlainValue), publicPlainComparisonField(a.InputEncoding, a.PlainValue))
		})
	}
	if (!b.wantAbsent && w.Source.State != contract.PublicPresent) || (!b.actualAbsent && a.Source.State != contract.PublicPresent) {
		return
	}
	wantAbsent, actualAbsent := b.wantAbsent || w.Source.Value != contract.Generated, b.actualAbsent || a.Source.Value != contract.Generated
	if wantAbsent && actualAbsent {
		return
	}
	if !wantAbsent && w.Generated == nil || !actualAbsent && a.Generated == nil {
		b.partial(contract.ScopeGenerated)
		return
	}
	var x, y contract.PublicGeneratedSettings
	if w.Generated != nil {
		x = *w.Generated
	}
	if a.Generated != nil {
		y = *a.Generated
	}
	b.withAbsence(wantAbsent, actualAbsent, func() {
		comparePublicField(b, subject, contract.FieldEpoch, x.Epoch, y.Epoch)
		comparePublicField(b, subject, contract.FieldConfigContract, x.ConfigContractID, y.ConfigContractID)
		comparePublicField(b, subject, contract.FieldResourceContract, x.ResourceContractID, y.ResourceContractID)
		comparePublicField(b, subject, contract.FieldLifecycle, x.LifecycleMode, y.LifecycleMode)
		comparePublicField(b, subject, contract.FieldContentIntent, x.ContentIntent, y.ContentIntent)
		comparePublicField(b, subject, contract.FieldRetirement, x.Retirement, y.Retirement)
		comparePublicField(b, subject, contract.FieldCompletion, x.Completion, y.Completion)
	})
}

func (b *publicComparisonBuilder) compareOutputBinding(w, a contract.PublicOutputBinding) {
	destination := w.DestinationID
	if b.wantAbsent {
		destination = a.DestinationID
	}
	subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: destination}
	comparePublicField(b, subject, contract.FieldDestination, w.Destination, a.Destination)
	comparePublicField(b, subject, contract.FieldTargets, w.Targets, a.Targets)
	comparePublicRows(b, w.Targets, a.Targets, func(x, y contract.PublicOutputTarget) int { return strings.Compare(x.EntryName, y.EntryName) }, func(x contract.PublicOutputTarget) contract.DiagnosticSubject {
		return contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: destination, Name: x.EntryName}
	}, func(x, y contract.PublicOutputTarget) {
		name := x.EntryName
		if b.wantAbsent {
			name = y.EntryName
		}
		b.compareOutputTarget(contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: destination, Name: name}, x, y)
	})
}
func (b *publicComparisonBuilder) compareOutputTarget(subject contract.DiagnosticSubject, w, a contract.PublicOutputTarget) {
	comparePublicField(b, subject, contract.FieldServiceContract, w.ServiceContractID, a.ServiceContractID)
	comparePublicField(b, subject, contract.FieldTargetContract, w.TargetContractID, a.TargetContractID)
	comparePublicField(b, subject, contract.FieldCanonicalTarget, w.CanonicalTarget, a.CanonicalTarget)
	comparePublicField(b, subject, contract.FieldConsumerLocator, w.ConsumerLocator, a.ConsumerLocator)
	comparePublicField(b, subject, contract.FieldTargetData, w.TargetData, a.TargetData)
	comparePublicField(b, subject, contract.FieldPayloadEncoding, w.PayloadEncoding, a.PayloadEncoding)
	comparePublicField(b, subject, contract.FieldLocatorRequiresCreation, w.LocatorRequiresCreation, a.LocatorRequiresCreation)
	comparePublicField(b, subject, contract.FieldCapabilities, w.Capabilities, a.Capabilities)
	comparePublicField(b, subject, contract.FieldCreateValueBounds, w.CreateValueBounds, a.CreateValueBounds)
	comparePublicField(b, subject, contract.FieldWriteValueBounds, w.WriteValueBounds, a.WriteValueBounds)
	comparePublicField(b, subject, contract.FieldConsumerPolicy, w.ConsumerPolicy, a.ConsumerPolicy)
}

func publicComparisonValueEqual(a, b reflect.Value) bool {
	if a.Type() != b.Type() {
		return false
	}
	if a.Kind() == reflect.Slice {
		if a.Len() != b.Len() {
			return false
		}
		if a.Type().Elem().Kind() == reflect.Uint8 {
			return slices.Equal(a.Bytes(), b.Bytes())
		}
		for i := 0; i < a.Len(); i++ {
			if !publicComparisonValueEqual(a.Index(i), b.Index(i)) {
				return false
			}
		}
		return true
	}
	if a.Comparable() {
		return a.Interface() == b.Interface()
	}
	if a.Kind() == reflect.Struct {
		for i := 0; i < a.NumField(); i++ {
			if !publicComparisonValueEqual(a.Field(i), b.Field(i)) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a.Interface(), b.Interface())
}

func walkComparisonFaults(want, actual []contract.Diagnostic, visit func(contract.Diagnostic)) {
	i, j := 0, 0
	for i < len(want) || j < len(actual) {
		if j == len(actual) || i < len(want) && comparePublicDiagnostics(want[i], actual[j]) < 0 {
			visit(want[i])
			i++
			continue
		}
		if i == len(want) || comparePublicDiagnostics(want[i], actual[j]) > 0 {
			visit(actual[j])
			j++
			continue
		}
		visit(want[i])
		i++
		j++
	}
}
