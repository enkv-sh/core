package compositionfull

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"enkv.sh/sdk/artifact"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

var ErrReaderResult = errors.New("reader result rendering refused")

// Counting creates no output backing. The second traversal writes directly to
// one exact owned backing. Scratch is one bounded header or diagnostic at a time.
type readerResultWriter struct {
	body                          []byte
	at                            int
	failed                        bool
	maximum                       int
	layout                        *resultJSONLayout
	formattedAt, formattedMaximum int
}

func (w *readerResultWriter) literal(s string) {
	if w.failed {
		return
	}
	maximum := w.maximum
	if maximum == 0 {
		maximum = contract.MaxComparisonResultJSONBytes
	}
	if len(s) > maximum-w.at {
		w.failed = true
		return
	}
	start := w.at
	w.at += len(s)
	if w.layout != nil {
		if err := w.layout.write(s, w.formattedLiteral); err != nil {
			w.failed = true
		}
		return
	}
	if w.body != nil {
		if w.at > len(w.body) {
			w.failed = true
			return
		}
		copy(w.body[start:w.at], s)
	}
}

func (w *readerResultWriter) formattedLiteral(s string) {
	if w.failed {
		return
	}
	if len(s) > w.formattedMaximum-w.formattedAt {
		w.failed = true
		return
	}
	start := w.formattedAt
	w.formattedAt += len(s)
	if w.body != nil {
		if w.formattedAt > len(w.body) {
			w.failed = true
			return
		}
		copy(w.body[start:w.formattedAt], s)
	}
}

func (w *readerResultWriter) finishJSON() {
	if !w.failed && w.layout != nil {
		if err := w.layout.finish(w.formattedLiteral); err != nil {
			w.failed = true
		}
	}
}
func (w *readerResultWriter) json(v any, maximum int) {
	if w.failed {
		return
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > maximum {
		w.failed = true
		return
	}
	w.literal(string(b))
}
func renderReaderResult(write func(*readerResultWriter)) ([]byte, error) {
	return renderReaderResultBound(contract.MaxComparisonResultJSONBytes, write)
}
func renderReaderResultBound(maximum int, write func(*readerResultWriter)) ([]byte, error) {
	count := readerResultWriter{maximum: maximum}
	write(&count)
	if count.failed {
		return nil, ErrReaderResult
	}
	out := readerResultWriter{body: make([]byte, count.at), maximum: maximum}
	write(&out)
	if out.failed || out.at != count.at {
		clear(out.body)
		return nil, ErrReaderResult
	}
	return out.body, nil
}

func renderReadableReaderResultBound(maximum int, write func(*readerResultWriter)) ([]byte, error) {
	if maximum <= 0 || maximum > int(^uint(0)>>1)/67 {
		return nil, ErrReaderResult
	}
	return renderReaderResultJSONBound(maximum, 67*maximum, write)
}

func renderReaderResultJSONBound(maximum, formattedMaximum int, write func(*readerResultWriter)) ([]byte, error) {
	if maximum <= 0 || formattedMaximum <= 0 {
		return nil, ErrReaderResult
	}
	layout := resultJSONLayout{compactLimit: uint64(maximum)}
	count := readerResultWriter{maximum: maximum, formattedMaximum: formattedMaximum, layout: &layout}
	write(&count)
	count.finishJSON()
	if count.failed {
		return nil, ErrReaderResult
	}
	layout = resultJSONLayout{compactLimit: uint64(maximum)}
	out := readerResultWriter{body: make([]byte, count.formattedAt), maximum: maximum, formattedMaximum: count.formattedAt, layout: &layout}
	write(&out)
	out.finishJSON()
	if out.failed || out.at != count.at || out.formattedAt != count.formattedAt {
		clear(out.body)
		return nil, ErrReaderResult
	}
	return out.body, nil
}

func readerID(id contract.ID) string {
	if id.IsZero() {
		return ""
	}
	return hex.EncodeToString(id[:])
}

type readerContextRecord struct {
	Operation      string `json:"operation"`
	OperationID    string `json:"operation_id,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	ExpectedDomain string `json:"expected_domain_id,omitempty"`
}

func readerContext(c core.ReaderOperationContext) readerContextRecord {
	return readerContextRecord{c.Operation, readerID(c.OperationID), readerID(c.RequestID), readerID(c.ExpectedDomain)}
}

type readerObservationRecord struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
}

func readerObservation(domain, revision, snapshot contract.ID) *readerObservationRecord {
	return &readerObservationRecord{readerID(domain), readerID(revision), readerID(snapshot)}
}

type readerResultHeader struct {
	Schema          string                      `json:"schema"`
	Operation       string                      `json:"operation_kind"`
	State           contract.ReaderStateResult  `json:"state_result"`
	Effect          string                      `json:"effect_summary"`
	Output          string                      `json:"output_summary"`
	Context         readerContextRecord         `json:"context"`
	Observation     *readerObservationRecord    `json:"observation,omitempty"`
	Target          string                      `json:"target_recipient_id,omitempty"`
	OperationID     string                      `json:"operation_id,omitempty"`
	RequestIdentity *preAdmissionIdentityRecord `json:"request_identity,omitempty"`
	ReplayIdentity  string                      `json:"replay_identity,omitempty"`
}

type readerHumanFacts struct{ writer *readerResultWriter }

func (w readerHumanFacts) text(text string) { w.writer.literal(text) }
func (w readerHumanFacts) value(value any)  { w.writer.json(value, 4096) }

func writePlanningHumanHeader(w *readerResultWriter, h readerResultHeader, p contract.ComparisonPayload) {
	if h.State == contract.ReaderSuccess && p.DiagnosticsComplete {
		w.literal("Plan: " + string(h.State) + "\n")
	} else {
		w.literal("Plan incomplete: " + string(h.State) + "\n")
	}
	switch {
	case len(p.Changes) != 0:
		w.literal("Public configuration: proposed changes follow.\n")
	case h.State == contract.ReaderSuccess && p.DiagnosticsComplete:
		w.literal("Public configuration: unchanged.\n")
	default:
		w.literal("Public configuration: not fully checked.\n")
	}
	w.literal("Verdict: " + string(p.Verdict) + "\n")
	w.literal("Diagnostics complete: " + strconv.FormatBool(p.DiagnosticsComplete) + "; issues: " + strconv.Itoa(len(p.Diagnostics)) + "\n")
	w.literal("Evidence: " + p.EvidenceLimit + "\n")
	if h.Observation != nil {
		w.literal("Observation: domain " + h.Observation.Domain + "; revision " + h.Observation.Revision + "; snapshot " + h.Observation.Snapshot + "\n")
	}
	if h.Context.OperationID != "" {
		w.literal("Operation: " + h.Context.OperationID + "\n")
	}
	if h.Context.RequestID != "" {
		w.literal("Request: " + h.Context.RequestID + "\n")
	}
}

func validReaderState(state contract.ReaderStateResult) bool {
	switch state {
	case contract.ReaderSuccess, contract.ReaderRefused, contract.ReaderProfileBlocked, contract.ReaderPositiveDefect, contract.ReaderUnavailable, contract.ReaderContention:
		return true
	}
	return false
}
func (w *readerResultWriter) header(h readerResultHeader, human bool) {
	if human {
		w.literal("operation_kind: " + h.Operation + "\nstate_result: " + string(h.State) + "\neffect_summary: not-applicable\noutput_summary: not-applicable\ncontext: ")
		w.json(h.Context, 4096)
		w.literal("\n")
		if h.RequestIdentity != nil {
			w.literal("operation_id: " + h.OperationID + "\nrequest_identity: ")
			w.json(h.RequestIdentity, 4096)
			w.literal("\nreplay_identity: " + h.ReplayIdentity + "\n")
		}
		if h.Observation != nil {
			w.literal("observation: ")
			w.json(h.Observation, 4096)
			w.literal("\n")
		}
		if h.Target != "" {
			w.literal("target_recipient_id: " + h.Target + "\n")
		}
		return
	}
	b, err := json.Marshal(h)
	if err != nil || len(b) > 65536 {
		w.failed = true
		return
	}
	w.literal(string(b[:len(b)-1]))
}

// ComparisonExitCode maps the callable result. It does not install a CLI route.
func ComparisonExitCode(r ConfigurationComparisonResult) int {
	if !validInstallationRequirementComparison(r.InstallationRequirements) || !validComparisonFacts(r.ComparisonPayload) || !validPublicationPreview(r.ComparisonPayload) || !r.DiagnosticsComplete || !validGeneratedPlanningEntries(r.GeneratedEntries) || len(r.GeneratedEntries) != 0 && r.Observation == nil {
		return 2
	}
	switch r.StateResult {
	case contract.ReaderSuccess:
		switch r.Verdict {
		case contract.ComparisonMatch:
			return 0
		case contract.ComparisonMismatch:
			return 1
		}
	case contract.ReaderUnavailable, contract.ReaderContention:
		return 3
	}
	return 2
}
func RenderComparisonJSON(r ConfigurationComparisonResult) ([]byte, error) {
	return renderComparison(r, false)
}
func RenderComparisonHuman(r ConfigurationComparisonResult) ([]byte, error) {
	return renderComparison(r, true)
}
func renderComparison(r ConfigurationComparisonResult, human bool) ([]byte, error) {
	if !validConfigurationSourceFailure(r.SourceFailure) || !validSourceFailureDiagnostics(r.SourceFailure, r.Diagnostics) || r.SourceFailure != nil && (!validSourceFailureReaderState(r.Result, r.StateResult) || r.PreAdmission == nil || !validSourceAdmissionStage(r.PreAdmission.Stage) || r.Observation != nil || r.Verdict != contract.ComparisonUnable || r.StateResult == contract.ReaderSuccess || !validSourceFailureComparison(r.ComparisonPayload) || len(r.InstallationRequirements.Differences) != 0) {
		return nil, ErrReaderResult
	}
	if !validInstallationRequirementComparison(r.InstallationRequirements) || !validComparisonFacts(r.ComparisonPayload) || !validPublicationPreview(r.ComparisonPayload) || r.Context.Operation != contract.ReaderCompareOperation || !validReaderState(r.StateResult) || len(r.Diagnostics) > contract.MaxPublicDiagnostics || r.EvidenceLimit != contract.ComparisonEvidenceLimit || len(r.CheckedScope) > 12 || !validGeneratedPlanningEntries(r.GeneratedEntries) || len(r.GeneratedEntries) != 0 && r.Observation == nil {
		return nil, ErrReaderResult
	}
	if r.Verdict != contract.ComparisonMatch && r.Verdict != contract.ComparisonMismatch && r.Verdict != contract.ComparisonUnable {
		return nil, ErrReaderResult
	}
	h := readerResultHeader{Schema: "ProductResult/v1", Operation: contract.ReaderCompareOperation, State: r.StateResult, Effect: "not-applicable", Output: "not-applicable", Context: readerContext(r.Context)}
	if r.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(h.Operation, r.Context.OperationID, r.PreAdmission)
		if !ok || r.StateResult == contract.ReaderSuccess || r.Observation != nil || r.Verdict != contract.ComparisonUnable {
			return nil, ErrReaderResult
		}
		h.OperationID, h.RequestIdentity, h.ReplayIdentity = readerID(r.Context.OperationID), &identity, "none"
	}
	if r.Observation != nil {
		if r.Observation.DomainID.IsZero() || r.Observation.HeadRevisionID.IsZero() || r.Observation.SnapshotID.IsZero() {
			return nil, ErrReaderResult
		}
		h.Observation = readerObservation(r.Observation.DomainID, r.Observation.HeadRevisionID, r.Observation.SnapshotID)
	}
	maximum := contract.MaxComparisonResultJSONBytes
	if r.PublicationRequested {
		maximum = contract.MaxPublicationPlanningResultJSONBytes
	}
	return renderComparisonResultBound(maximum+configurationRequirementResultAllowance, !human, func(w *readerResultWriter) {
		if human {
			writePlanningHumanHeader(w, h, r.ComparisonPayload)
		} else {
			w.header(h, false)
		}
		w.sourceFailure(r.SourceFailure, human)
		if human {
			w.literal("Supplied secret equality: unchecked.\n")
		} else {
			w.literal(`,"payload":{"schema":"ComparisonPayload/v1","verdict":`)
			w.json(r.Verdict, 128)
			w.literal(`,"diagnostics_complete":` + strconv.FormatBool(r.DiagnosticsComplete) + `,"evidence_limit":`)
			w.json(r.EvidenceLimit, 4096)
			w.literal(`,"checked_scope":[`)
		}
		for i, scope := range r.CheckedScope {
			if !validReaderScope(scope) {
				w.failed = true
				return
			}
			if human {
				w.literal("Checked scope " + string(scope.Family) + ": " + string(scope.Status) + "\n")
				continue
			} else if i != 0 {
				w.literal(",")
			}
			w.json(struct {
				Family contract.ComparisonFieldFamily `json:"family"`
				Status contract.ComparisonScopeStatus `json:"status"`
			}{scope.Family, scope.Status}, 4096)
		}
		if !human {
			w.literal(`],"diagnostics":[`)
		}
		for i, d := range r.Diagnostics {
			record, ok := readerDiagnostic(d)
			if !ok {
				w.failed = true
				return
			}
			if human {
				writeDiagnosticHuman(readerHumanFacts{w}, d)
				continue
			} else if i != 0 {
				w.literal(",")
			}
			w.json(record, 4096)
		}
		if !human {
			w.literal("]")
		}
		renderProposedChanges(w, r.ComparisonPayload, human)
		renderGeneratedPlanningEntries(w, r.GeneratedEntries, human)
		renderPublicationPreview(w, r.Publication, human)
		if human {
			w.literal("No changes were applied or published.\n")
		}
		if !human {
			w.literal("}")
		}
		domainBytes := w.at
		requirementStart := w.at
		renderInstallationRequirementComparison(w, r.InstallationRequirements, human)
		if w.at-requirementStart > configurationRequirementResultAllowance {
			w.failed = true
		}
		if !human {
			w.literal("}")
			domainBytes++
		}
		if domainBytes > maximum {
			w.failed = true
		}
	})
}
func validReaderScope(s contract.ComparisonScope) bool {
	if s.Status != contract.ScopeComplete && s.Status != contract.ScopePartial && s.Status != contract.ScopeUnchecked {
		return false
	}
	switch s.Family {
	case contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeRecipients, contract.ScopeEncryption, contract.ScopeGenerated, contract.ScopeOutputs, contract.ScopeRouting, contract.ScopeDomainStore, contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles:
		return true
	}
	return false
}

type readerDiagnosticRecord struct {
	Subject map[string]any             `json:"subject"`
	Path    []readerFieldRecord        `json:"path"`
	Outcome contract.DiagnosticOutcome `json:"outcome"`
	Reason  contract.DiagnosticReason  `json:"reason"`
	Source  *readerSourceRecord        `json:"source_location,omitempty"`
}
type readerFieldRecord struct {
	Field contract.DiagnosticField `json:"field"`
}
type readerSourceRecord struct {
	SourceID string `json:"source_id"`
	Line     uint64 `json:"line"`
	Column   uint64 `json:"column"`
}

func boundedReaderText(s string, max int) bool { return len(s) <= max && utf8.ValidString(s) }
func readerDiagnostic(d contract.Diagnostic) (readerDiagnosticRecord, bool) {
	r := readerDiagnosticRecord{Subject: map[string]any{"kind": d.Subject.Kind}, Outcome: d.Outcome, Reason: d.Reason}
	if !validReaderReason(d.Reason) || d.Outcome != contract.DiagnosticUnable && d.Outcome != contract.DiagnosticDifference || len(d.Path) < 1 || len(d.Path) > 2 {
		return r, false
	}
	if d.Reason == contract.ReasonImmutableConflict && !d.ImmutableConflictShape() {
		return r, false
	}
	if d.Reason == contract.ReasonStaleSealedInputBinding && (d.Subject.Kind != contract.SubjectEntry || d.Outcome != contract.DiagnosticUnable || len(d.Path) != 1 || d.Path[0] != contract.FieldSource || d.SourceLocation != nil) {
		return r, false
	}
	if len(d.Path) == 2 && (d.Subject.Kind != contract.SubjectEntry || d.Path[0] != contract.FieldGenerated) {
		return r, false
	}
	for _, field := range d.Path {
		if !validReaderField(field) {
			return r, false
		}
		r.Path = append(r.Path, readerFieldRecord{field})
	}
	s := d.Subject
	if !boundedReaderText(s.Name, contract.CryptoMaxName) || !boundedReaderText(s.DestinationID, contract.CryptoMaxName) {
		return r, false
	}
	zeroRouting := contract.PublicRoutingKey{}
	switch s.Kind {
	case contract.SubjectEntry:
		r.Subject["name"] = s.Name
		if !s.RecipientID.IsZero() || s.DestinationID != "" || s.RoutingKey != zeroRouting {
			return r, false
		}
	case contract.SubjectRecipient:
		if s.Name != "" || s.DestinationID != "" || s.RoutingKey != zeroRouting {
			return r, false
		}
		if !s.RecipientID.IsZero() || len(d.Path) != 1 || d.Path[0] != contract.FieldPresence {
			r.Subject["recipient_id"] = hex.EncodeToString(s.RecipientID[:])
		}
	case contract.SubjectOutputBinding, contract.SubjectOutputTarget:
		if !s.RecipientID.IsZero() || s.RoutingKey != zeroRouting || s.Kind == contract.SubjectOutputBinding && s.Name != "" {
			return r, false
		}
		if s.DestinationID != "" {
			r.Subject["destination_id"] = s.DestinationID
		} else if s.Kind != contract.SubjectOutputBinding || len(d.Path) != 1 || d.Path[0] != contract.FieldPresence {
			return r, false
		}
		if s.Kind == contract.SubjectOutputTarget {
			r.Subject["name"] = s.Name
		}
	case contract.SubjectRoutingRule:
		if s.Name != "" || s.DestinationID != "" || !s.RecipientID.IsZero() {
			return r, false
		}
		k := s.RoutingKey
		if k == zeroRouting && len(d.Path) == 1 && d.Path[0] == contract.FieldPresence {
			break
		}
		entry := map[string]any{}
		switch k.EntrySelector {
		case contract.PublicNamedEntry:
			if !boundedReaderText(k.EntryName, contract.CryptoMaxName) {
				return r, false
			}
			entry["kind"] = "entry"
			entry["name"] = k.EntryName
		case contract.PublicDefaultRoute:
			if k.EntryName != "" {
				return r, false
			}
			entry["kind"] = "default"
		default:
			return r, false
		}
		r.Subject["entry"] = entry
	case contract.SubjectDomain, contract.SubjectStore, contract.SubjectAuthority, contract.SubjectRecovery, contract.SubjectConfiguration, contract.SubjectObservation:
		if s.Name != "" || s.DestinationID != "" || !s.RecipientID.IsZero() || s.RoutingKey != zeroRouting {
			return r, false
		}
	default:
		return r, false
	}
	if v := d.SourceLocation; v != nil {
		if len(v.SourceID) == 0 || len(v.SourceID) > 64 || v.Line == 0 || v.Column == 0 {
			return r, false
		}
		for _, b := range []byte(v.SourceID) {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", rune(b)) {
				return r, false
			}
		}
		r.Source = &readerSourceRecord{v.SourceID, v.Line, v.Column}
	}
	return r, true
}
func validReaderField(field contract.DiagnosticField) bool {
	switch field {
	case contract.FieldCreateValueBounds, contract.FieldWriteValueBounds, contract.FieldServiceContract, contract.FieldCanonicalSettings, contract.FieldCapabilities, contract.FieldLocatorRequiresCreation, contract.FieldPresence, contract.FieldName, contract.FieldClass, contract.FieldSource, contract.FieldPlainValue, contract.FieldMemberships, contract.FieldGenerated, contract.FieldEpoch, contract.FieldResourceContract, contract.FieldConfigContract, contract.FieldLifecycle, contract.FieldContentIntent, contract.FieldRetirement, contract.FieldCompletion, contract.FieldDisplayName, contract.FieldDestination, contract.FieldInputEncoding, contract.FieldOutputEncoding, contract.FieldGroups, contract.FieldEncryptionProvider, contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint, contract.FieldWrapProfile, contract.FieldProtectionClass, contract.FieldTargets, contract.FieldProvider, contract.FieldCanonicalTarget, contract.FieldConsumerLocator, contract.FieldTargetContract, contract.FieldTargetData, contract.FieldPayloadEncoding, contract.FieldConsumerPolicy, contract.FieldDestinations, contract.FieldDomainID, contract.FieldConstructionProfile, contract.FieldRegion, contract.FieldBucket, contract.FieldPrefix, contract.FieldExpectedOwner, contract.FieldRecipientID, contract.FieldSigningProvider, contract.FieldSigningSelector, contract.FieldSigningPublicKey, contract.FieldSigningFingerprint, contract.FieldSigningRole, contract.FieldSigningProfile, contract.FieldEnabled:
		return true
	}
	return false
}
func validReaderReason(reason contract.DiagnosticReason) bool {
	switch reason {
	case contract.ReasonExpectedEntryAbsent, contract.ReasonObservedEntryAbsent, contract.ReasonExpectedSettingAbsent, contract.ReasonObservedSettingAbsent, contract.ReasonFieldDiffers, contract.ReasonSetDiffers, contract.ReasonBytesDiffer, contract.ReasonPublicFactUnavailable, contract.ReasonInvalidInput, contract.ReasonMissingRequiredField, contract.ReasonDuplicateKey, contract.ReasonDuplicateMember, contract.ReasonUnresolvedReference, contract.ReasonInvalidUTF8, contract.ReasonLimitExceeded, contract.ReasonInvalidFieldCombination, contract.ReasonTrustBasisInvalid, contract.ReasonDomainBasisInvalid, contract.ReasonStoreBasisInvalid, contract.ReasonExpired, contract.ReasonCancelled, contract.ReasonUnsupportedSchema, contract.ReasonUnsupportedProfile, contract.ReasonHeadInvalid, contract.ReasonProofInvalid, contract.ReasonSelectedObjectInvalid, contract.ReasonSelectedRelationInvalid, contract.ReasonImmutableConflict, contract.ReasonEvidenceUnavailable, contract.ReasonSelectedObjectUnavailable, contract.ReasonReadContention, contract.ReasonDiagnosticsIncomplete, contract.ReasonStaleSealedInputBinding, contract.ReasonTargetAbsent, contract.ReasonEntryAbsent, contract.ReasonDuplicateEntry, contract.ReasonTargetNotAuthorized, contract.ReasonLocatorUnusable:
		return true
	}
	return false
}

func RenderManifestResultJSON(r core.PublicManifestResult) ([]byte, error) {
	return renderManifestResult(r)
}
func RenderManifestResultHuman(r core.PublicManifestResult) ([]byte, error) {
	if !validManifestRender(r) {
		return nil, ErrReaderResult
	}
	return renderReaderResultBound(contract.MaxManifestResultJSONBytes, func(w *readerResultWriter) { writeManifestHuman(w, r) })
}
func renderManifestResult(r core.PublicManifestResult) ([]byte, error) {
	return renderReadableReaderResultBound(contract.MaxManifestResultJSONBytes, func(w *readerResultWriter) { writeManifestResult(w, r, false) })
}

func writeManifestResult(w *readerResultWriter, r core.PublicManifestResult, human bool) {
	if r.Context.Operation != contract.ReaderManifestOperation || !validReaderState(r.StateResult) || r.FailureReason != "" && !validReaderReason(r.FailureReason) {
		w.failed = true
		return
	}
	if r.StateResult == contract.ReaderSuccess && (r.Payload == nil || r.FailureReason != "") || r.StateResult != contract.ReaderSuccess && (r.Payload != nil || r.Artifact != nil) || !r.TargetRecipientID.IsZero() && r.Observation == nil {
		w.failed = true
		return
	}
	if scope := r.RequestScope; scope != nil && !validManifestRequestScope(scope) {
		w.failed = true
		return
	}
	if p := r.Payload; p != nil && (r.RequestScope == nil || p.Selection != r.RequestScope.Selection || !sameManifestService(p.ServiceFilter, r.RequestScope.ServiceFilter) || !validManifestPayloadPartition(p) || p.Renderer != r.RequestScope.Renderer || p.FormatContractID != r.RequestScope.FormatContractID || p.ConfigContractID != r.RequestScope.ConfigContractID || !bytes.Equal(p.Settings, r.RequestScope.Settings) || p.EvidenceLimit != manifest.EvidenceLimit || p.TargetRecipientID.IsZero() || p.TargetRecipientID != r.TargetRecipientID || r.Observation == nil || p.Observation != *r.Observation || p.ArtifactDigest.IsZero() || p.ArtifactLength == 0 || p.ArtifactLength > manifest.MaxArtifactBytes) {
		w.failed = true
		return
	}
	h := readerResultHeader{Schema: "ProductResult/v1", Operation: contract.ReaderManifestOperation, State: r.StateResult, Effect: "not-applicable", Output: "not-applicable", Context: readerContext(r.Context), Target: readerID(r.TargetRecipientID)}
	if r.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(h.Operation, r.Context.OperationID, r.PreAdmission)
		if !ok || r.StateResult == contract.ReaderSuccess || r.Observation != nil || !r.TargetRecipientID.IsZero() || r.PreAdmission.RequestNonce != r.Context.RequestID {
			w.failed = true
			return
		}
		h.OperationID, h.RequestIdentity, h.ReplayIdentity = readerID(r.Context.OperationID), &identity, "none"
	}
	if r.Observation != nil {
		if r.Observation.DomainID.IsZero() || r.Observation.HEADRevisionID.IsZero() || r.Observation.SnapshotID.IsZero() {
			w.failed = true
			return
		}
		h.Observation = readerObservation(contract.ID(r.Observation.DomainID), contract.ID(r.Observation.HEADRevisionID), contract.ID(r.Observation.SnapshotID))
	}
	w.header(h, human)
	if r.FailureReason != "" {
		if human {
			w.literal("failure_reason: " + string(r.FailureReason) + "\n")
		} else {
			w.literal(`,"failure_reason":`)
			w.json(r.FailureReason, 128)
		}
	}
	if scope := r.RequestScope; scope != nil {
		if human {
			w.literal("request_scope: ")
		} else {
			w.literal(`,"request_scope":`)
		}
		w.json(manifestScopeRecord(scope), 32768)
		if human {
			w.literal("\n")
		}
	}
	if p := r.Payload; p != nil {

		payload := struct {
			Schema string `json:"schema"`
			readerManifestScopeRecord
			Length   uint64 `json:"artifact_length"`
			Digest   string `json:"artifact_digest"`
			Evidence string `json:"evidence_limit"`
		}{"ManifestPayload/v3", manifestScopeRecord(r.RequestScope), p.ArtifactLength, readerID(p.ArtifactDigest), p.EvidenceLimit}
		if human {
			w.literal("payload: ")
		} else {
			w.literal(`,"payload":`)
		}
		body, err := json.Marshal(payload)
		if err != nil || len(body) > 32768 {
			w.failed = true
			return
		}
		w.literal(string(body[:len(body)-1]))
		w.literal(`,"included_entries":[`)
		for i, row := range p.IncludedEntries {
			if i != 0 {
				w.literal(",")
			}
			w.json(struct {
				Name string `json:"name"`
				ID   string `json:"entry_incarnation_id"`
			}{row.Name, readerID(contract.ID(row.EntryIncarnationID))}, 4096)
		}
		w.literal(`],"excluded_entries":[`)
		for i, row := range p.ExcludedEntries {
			if i != 0 {
				w.literal(",")
			}
			w.json(struct {
				Name   string                   `json:"name"`
				ID     string                   `json:"entry_incarnation_id"`
				Reason manifest.ExclusionReason `json:"reason"`
			}{row.Name, readerID(contract.ID(row.EntryIncarnationID)), row.Reason}, 4096)
		}
		w.literal(`]}`)
		if human {
			w.literal("\n")
		}
	}
	if !human {
		w.literal("}")
	}
}

type readerManifestRendererRecord struct {
	Name                 string `json:"name"`
	Version              string `json:"version"`
	ProtocolID           string `json:"protocol_id"`
	DescriptorID         string `json:"descriptor_id"`
	ExecutorID           string `json:"executor_id"`
	ArtifactContractID   string `json:"artifact_contract_id"`
	DependencyManifestID string `json:"dependency_manifest_id"`
	ArtifactID           string `json:"artifact_id"`
	ArtifactSHA256       string `json:"artifact_sha256"`
	ArtifactLength       uint64 `json:"artifact_length"`
}
type readerManifestScopeRecord struct {
	Renderer         readerManifestRendererRecord `json:"renderer"`
	FormatContractID string                       `json:"format_contract_id"`
	ConfigContractID string                       `json:"config_contract_id"`
	Settings         []byte                       `json:"settings"`
	Selection        manifest.Selection           `json:"selection"`
	ServiceFilter    *string                      `json:"service_filter"`
}

func manifestScopeRecord(scope *contract.ManifestRequestScope) readerManifestScopeRecord {
	r := scope.Renderer
	return readerManifestScopeRecord{Renderer: readerManifestRendererRecord{r.Name, r.Version, readerID(r.ProtocolID), readerID(r.DescriptorID), readerID(r.ExecutorID), readerID(r.ArtifactContractID), readerID(r.DependencyManifestID), readerID(r.ArtifactID), readerID(r.ArtifactSHA256), r.ArtifactLength}, FormatContractID: scope.FormatContractID, ConfigContractID: scope.ConfigContractID, Settings: scope.Settings, Selection: scope.Selection, ServiceFilter: scope.ServiceFilter}
}
func validManifestRequestScope(scope *contract.ManifestRequestScope) bool {
	r := scope.Renderer
	if !artifact.ValidPluginID(r.Name) || !artifact.ValidVersion(r.Version) || r.ArtifactLength == 0 || r.ArtifactLength > artifact.MaxExecutableBytes || !scope.Selection.Valid() || manifest.ValidateSettings(scope.Settings) != "" {
		return false
	}
	for _, id := range [...]contract.ID{r.ProtocolID, r.DescriptorID, r.ExecutorID, r.ArtifactContractID, r.DependencyManifestID, r.ArtifactID, r.ArtifactSHA256} {
		if id.IsZero() {
			return false
		}
	}
	for _, value := range []string{scope.FormatContractID, scope.ConfigContractID} {
		if value == "" || !boundedReaderText(value, manifest.MaxContractBytes) {
			return false
		}
	}
	return scope.ServiceFilter == nil || *scope.ServiceFilter != "" && boundedReaderText(*scope.ServiceFilter, manifest.MaxContractBytes)
}
func sameManifestService(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func validManifestPayloadPartition(p *contract.ManifestPayload) bool {
	if !p.Selection.Valid() || p.ServiceFilter != nil && (*p.ServiceFilter == "" || !boundedReaderText(*p.ServiceFilter, manifest.MaxContractBytes)) || p.IncludedEntries == nil || p.ExcludedEntries == nil || len(p.IncludedEntries) > contract.CryptoMaxValueEntries || len(p.ExcludedEntries) > contract.CryptoMaxValueEntries-len(p.IncludedEntries) {
		return false
	}
	for i, row := range p.IncludedEntries {
		if !boundedReaderText(row.Name, contract.CryptoMaxName) || row.EntryIncarnationID.IsZero() || i > 0 && p.IncludedEntries[i-1].Name >= row.Name {
			return false
		}
	}
	for i, row := range p.ExcludedEntries {
		if !boundedReaderText(row.Name, contract.CryptoMaxName) || row.EntryIncarnationID.IsZero() || i > 0 && p.ExcludedEntries[i-1].Name >= row.Name || row.Reason != manifest.NoOutput && row.Reason != manifest.NoMatchingService || row.Reason == manifest.NoMatchingService && p.ServiceFilter == nil {
			return false
		}
		for _, included := range p.IncludedEntries {
			if row.Name == included.Name || row.EntryIncarnationID == included.EntryIncarnationID {
				return false
			}
		}
	}
	return true
}
