package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"go.opentelemetry.io/otel/trace"
)

// Severity numbers are the API-neutral diagnostic wire values. Off belongs to
// exporter configuration and is not a diagnostic severity.
const (
	SeverityTrace = 1
	SeverityDebug = 5
	SeverityInfo  = 9
	SeverityWarn  = 13
	SeverityError = 17
	SeverityFatal = 21
)

const (
	DiagnosticSchemaVersion = 2
	RecorderCaptureBytes    = 192 << 10
	diagnosticOverheadBytes = 512
	MaximumLogRecordBytes   = 16 << 10
	MaximumErrorBytes       = 8 << 10
)

type DiagnosticEvent string

const (
	DiagnosticStart      DiagnosticEvent = "start"
	DiagnosticCheckpoint DiagnosticEvent = "checkpoint"
	DiagnosticReturn     DiagnosticEvent = "return"
)

type DiagnosticStage string

const (
	DiagnosticAdmission            DiagnosticStage = "admission"
	DiagnosticStateLoading         DiagnosticStage = "state_loading"
	DiagnosticAuthentication       DiagnosticStage = "authentication"
	DiagnosticCandidatePersistence DiagnosticStage = "candidate_persistence"
	DiagnosticCommitObservation    DiagnosticStage = "commit_observation"
	DiagnosticPrivateCustody       DiagnosticStage = "private_custody"
	DiagnosticProviderCall         DiagnosticStage = "provider_call"
	DiagnosticLocalStaging         DiagnosticStage = "local_staging"
	DiagnosticLocalReplacement     DiagnosticStage = "local_replacement"
	DiagnosticLocalCompletion      DiagnosticStage = "local_completion"
)

type DiagnosticReason string

const (
	DiagnosticReasonSetupRequired         DiagnosticReason = "setup_required"
	DiagnosticReasonNone                  DiagnosticReason = ""
	DiagnosticReasonAdmissionRefused      DiagnosticReason = "admission_refused"
	DiagnosticReasonIntegrityFailure      DiagnosticReason = "integrity_failure"
	DiagnosticReasonEvidenceUnavailable   DiagnosticReason = "evidence_unavailable"
	DiagnosticReasonInvalid               DiagnosticReason = "invalid"
	DiagnosticReasonDenied                DiagnosticReason = "denied"
	DiagnosticReasonCancelled             DiagnosticReason = "cancelled"
	DiagnosticReasonUncertain             DiagnosticReason = "uncertain"
	DiagnosticReasonAdmissionInvalid      DiagnosticReason = "admission_invalid"
	DiagnosticReasonConstructionMismatch  DiagnosticReason = "construction_mismatch"
	DiagnosticReasonInvalidFormat         DiagnosticReason = "invalid_format"
	DiagnosticReasonInvalidProof          DiagnosticReason = "invalid_proof"
	DiagnosticReasonInvalidReference      DiagnosticReason = "invalid_reference"
	DiagnosticReasonInvalidRelation       DiagnosticReason = "invalid_relation"
	DiagnosticReasonMissingSelectedObject DiagnosticReason = "missing_selected_object"
	DiagnosticReasonReadUnavailable       DiagnosticReason = "read_unavailable"
	DiagnosticReasonImmutableConflict     DiagnosticReason = "immutable_conflict"
	DiagnosticReasonCapacityExceeded      DiagnosticReason = "capacity_exceeded"
	DiagnosticReasonInvalidIntent         DiagnosticReason = "invalid_intent"
	DiagnosticReasonSigningUnavailable    DiagnosticReason = "signing_unavailable"
	DiagnosticReasonWriteUncertain        DiagnosticReason = "write_uncertain"
	DiagnosticReasonStalePrecondition     DiagnosticReason = "stale_precondition"
	DiagnosticReasonDifferentSelection    DiagnosticReason = "different_selection"
	DiagnosticReasonAlreadyUsed           DiagnosticReason = "already_used"
	DiagnosticReasonCustodyUnavailable    DiagnosticReason = "custody_unavailable"
)

type DiagnosticRecord struct {
	SchemaVersion     int              `json:"schema_version"`
	OccurredAt        time.Time        `json:"occurred_at"`
	Component         string           `json:"component"`
	SeverityText      string           `json:"severity_text"`
	SeverityNumber    int              `json:"severity_number"`
	TraceID           string           `json:"trace_id,omitempty"`
	SpanID            string           `json:"span_id,omitempty"`
	TraceSampled      bool             `json:"trace_sampled,omitempty"`
	EntryName         string           `json:"member_name,omitempty"`
	KeyID             string           `json:"key_id,omitempty"`
	CommandID         string           `json:"command_id,omitempty"`
	AttemptID         string           `json:"attempt_id,omitempty"`
	InvocationID      string           `json:"invocation_id,omitempty"`
	WorkerID          string           `json:"worker_id,omitempty"`
	PathKind          string           `json:"path_kind,omitempty"`
	Path              string           `json:"path,omitempty"`
	ConfigField       string           `json:"config_field,omitempty"`
	ErrorClass        DiagnosticReason `json:"error_class,omitempty"`
	HTTPStatus        int              `json:"http_status,omitempty"`
	ErrorDetail       string           `json:"error_detail,omitempty"`
	ErrorDetailStatus string           `json:"error_detail_status,omitempty"`
	Sequence          uint64           `json:"sequence"`
	Call              uint64           `json:"call"`
	ParentCall        uint64           `json:"parent_call,omitempty"`
	Provider          Provider         `json:"provider"`
	Operation         Operation        `json:"operation"`
	Event             DiagnosticEvent  `json:"event"`
	Stage             DiagnosticStage  `json:"stage,omitempty"`
	Result            Result           `json:"result,omitempty"`
	Reason            DiagnosticReason `json:"reason,omitempty"`
	OffsetNanos       int64            `json:"offset_nanos"`
	ElapsedNanos      int64            `json:"elapsed_nanos,omitempty"`
}

func (record DiagnosticRecord) Validate() error {
	if record.SchemaVersion != DiagnosticSchemaVersion || record.OccurredAt.IsZero() || record.Component != string(record.Provider) || !validSeverity(record.SeverityText, record.SeverityNumber) || !validTraceLink(record.TraceID, record.SpanID, record.TraceSampled) || record.Sequence == 0 || record.Call == 0 || record.ParentCall == record.Call || record.OffsetNanos < 0 || record.ElapsedNanos < 0 ||
		!ValidOperationOwner(record.Provider, record.Operation) || !validDiagnosticReason(record.Reason) {
		return errors.New("invalid diagnostic record")
	}
	details := DiagnosticDetails{entryName: record.EntryName, keyID: record.KeyID, commandID: record.CommandID, attemptID: record.AttemptID, invocationID: record.InvocationID, workerID: record.WorkerID, pathKind: record.PathKind, path: record.Path, configField: record.ConfigField, errorClass: record.ErrorClass, httpStatus: record.HTTPStatus, errorText: record.ErrorDetail}
	if !validDetails(details) || record.ErrorDetail != errorDetail(details) || record.ErrorDetailStatus != errorDetailStatus(details) || len(record.ErrorDetail) > MaximumErrorBytes {
		return errors.New("invalid diagnostic detail")
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > MaximumLogRecordBytes {
		return errors.New("invalid diagnostic record")
	}
	switch record.Event {
	case DiagnosticStart:
		if record.Stage != "" || record.Result != "" || record.Reason != "" || record.ElapsedNanos != 0 {
			return errors.New("invalid diagnostic start")
		}
	case DiagnosticCheckpoint:
		if !validDiagnosticStageFor(record.Provider, record.Operation, record.Stage) || record.Result != "" {
			return errors.New("invalid diagnostic checkpoint")
		}
	case DiagnosticReturn:
		if record.Stage != "" || !AllowedAttribute("result", string(record.Result)) {
			return errors.New("invalid diagnostic return")
		}
	default:
		return errors.New("invalid diagnostic event")
	}
	return nil
}

func validTraceLink(traceID, spanID string, sampled bool) bool {
	if traceID == "" || spanID == "" {
		return traceID == "" && spanID == "" && !sampled
	}
	tid, traceErr := trace.TraceIDFromHex(traceID)
	sid, spanErr := trace.SpanIDFromHex(spanID)
	return traceErr == nil && spanErr == nil && tid.IsValid() && sid.IsValid()
}

func validSeverity(text string, number int) bool {
	switch text {
	case "TRACE":
		return number == SeverityTrace
	case "DEBUG":
		return number == SeverityDebug
	case "INFO":
		return number == SeverityInfo
	case "WARN":
		return number == SeverityWarn
	case "ERROR":
		return number == SeverityError
	case "FATAL":
		return number == SeverityFatal
	}
	return false
}

func diagnosticSeverity(record diagnosticRecord) (string, int) {
	if record.event == DiagnosticStart || record.event == DiagnosticCheckpoint && record.reason == DiagnosticReasonNone {
		return "DEBUG", SeverityDebug
	}
	if record.event == DiagnosticCheckpoint {
		return "WARN", SeverityWarn
	}
	if record.result == ResultSetupIncomplete && record.provider == ProviderApplication && (record.operation == OpConfigurationPrepare || record.operation == OpConfigurationPrepareDependencies || record.operation == OpApplicationInvocation) {
		return "DEBUG", SeverityDebug
	}
	if record.operation == OpCoreStoreCreate && record.result == ResultWriteUnknown {
		return "DEBUG", SeverityDebug
	}
	// Classify the returned outcome before its reason: a specific Core reason
	// must not hide uncertainty, and a generic uncertain reason cannot turn a
	// failed operation into a warning. Missing reads can be normal observations.
	switch record.result {
	case ResultFailure, ResultIntegrityFailure, ResultInvalid, ResultEvidenceUnavailable,
		ResultReadUnavailable, ResultReadInvalid, ResultSignUnavailable, ResultSignInvalid:
		return "ERROR", SeverityError
	case ResultUnknown, ResultContention, ResultUnresolvedCommit, ResultWritePrecondition,
		ResultWriteConflict, ResultWriteUnknown, ResultRootLossUnsupported, ResultAdmissionRefused,
		ResultDenied, ResultCancelled, ResultExpired, ResultAlreadyUsed, ResultCapacityExceeded, ResultWriteRefused:
		return "WARN", SeverityWarn
	}
	if record.reason == DiagnosticReasonNone || record.result == ResultReadMissing && record.reason == DiagnosticReasonEvidenceUnavailable {
		return "INFO", SeverityInfo
	}
	return "WARN", SeverityWarn
}

func validDiagnosticStage(stage DiagnosticStage) bool {
	switch stage {
	case DiagnosticAdmission, DiagnosticStateLoading, DiagnosticAuthentication, DiagnosticCandidatePersistence, DiagnosticCommitObservation, DiagnosticPrivateCustody, DiagnosticProviderCall, DiagnosticLocalStaging, DiagnosticLocalReplacement, DiagnosticLocalCompletion:
		return true
	}
	return false
}

func validDiagnosticStageFor(provider Provider, operation Operation, stage DiagnosticStage) bool {
	if !validDiagnosticStage(stage) {
		return false
	}
	switch provider {
	case ProviderCore:
		switch operation {
		case OpCorePlanning, OpCoreMaterialize:
			return stage == DiagnosticAdmission || stage == DiagnosticStateLoading || stage == DiagnosticAuthentication || stage == DiagnosticPrivateCustody
		case OpCoreOpen:
			return stage == DiagnosticAdmission || stage == DiagnosticStateLoading
		case OpCoreReaderCompare, OpCoreReaderManifest, OpCoreReaderRecipients, OpCoreGeneratedList, OpCoreReceiptList, OpCoreReceiptDetail, OpCoreInspect, OpCoreInspectRecipient, OpCoreInspectCapacity, OpCoreGCPlan, OpCoreGCValidatePlan:
			return stage == DiagnosticAdmission || stage == DiagnosticStateLoading || stage == DiagnosticAuthentication
		case OpCoreGeneratedRetire, OpCoreGeneratedAcceptRetirementRisk, OpCoreGeneratedCleanup:
			return stage == DiagnosticAdmission || stage == DiagnosticCommitObservation
		case OpCoreInitialize, OpCoreApply, OpCoreRekeyEnvelope, OpCoreRetireRecipient, OpCoreReplaceAuthorityKeys, OpCoreReplaceRecoveryKeys, OpCoreReplaceRecipientKey, OpCorePrepareRecipientReplacement, OpCorePrepareSuccession, OpCoreMutationReceipt, OpCoreReconstruct, OpCoreCompare, OpCorePrepare,
			OpCoreInspectSelectedWork, OpCorePrepareEndSelectedWork,
			OpCoreGeneratedPreparePlan, OpCoreGeneratedPrepareProducer, OpCoreGeneratedPrepareRecord, OpCoreGeneratedPrepareFinal,
			OpCoreGeneratedPrepareCreateResidue, OpCoreGeneratedPrepareLifecycle, OpCoreGeneratedPrepareSuccessorReservation,
			OpCoreGeneratedClaimPreparation, OpCoreGeneratedClaimDetachedProducer, OpCoreGeneratedClaimOriginalSet:
			return stage == DiagnosticAdmission
		case OpCorePublicationPlan, OpCorePublicationPrepareReservation:
			return stage == DiagnosticAdmission
		case OpCoreSelect, OpCoreSelectEndSelectedWork, OpCoreStoreCompareAndSwap, OpCoreStoreDeleteIfToken, OpCorePublicationExecute, OpCorePublicationPrepareClose:
			return stage == DiagnosticCommitObservation
		case OpCoreStoreRead, OpCoreGeneratedReadResult:
			return stage == DiagnosticStateLoading
		case OpCoreStorePersistImmutable, OpCoreStoreCreate, OpCoreStoreCreateHead:
			return stage == DiagnosticCandidatePersistence
		case OpCoreTrustSign:
			return stage == DiagnosticProviderCall
		}
	case ProviderCrypto:
		if operation == OpCryptoMaterialize {
			return stage == DiagnosticPrivateCustody || stage == DiagnosticLocalStaging || stage == DiagnosticLocalReplacement || stage == DiagnosticLocalCompletion
		}
		return stage == DiagnosticPrivateCustody
	case ProviderAWS, ProviderGCP:
		return stage == DiagnosticProviderCall
	case ProviderGeneratorHost:
		return stage == DiagnosticProviderCall
	case ProviderOutputHost:
		if operation == OpOutputHostPublicCheck {
			return stage == DiagnosticAdmission
		}
		return stage == DiagnosticProviderCall
	case ProviderManifestHost:
		if operation == OpManifestHostCheck {
			return stage == DiagnosticAdmission
		}
		return stage == DiagnosticProviderCall
	case ProviderApplication:
		switch operation {
		case OpPluginResolve, OpPluginCapture, OpPluginAcquire, OpPluginSelect, OpPluginRetained:
			return stage == DiagnosticAdmission
		case OpManifestFileWrite:
			return stage == DiagnosticAdmission || stage == DiagnosticLocalStaging || stage == DiagnosticLocalReplacement || stage == DiagnosticLocalCompletion
		case OpConfigurationCapture, OpConfigurationParse, OpConfigurationPrepare, OpConfigurationPrepareDependencies:
			return stage == DiagnosticAdmission
		case OpAdministrativePlanWrite, OpGCPlanWrite:
			return stage == DiagnosticCandidatePersistence
		case OpConfigurationWrite, OpInitializationManifest:
			return stage == DiagnosticCandidatePersistence || stage == DiagnosticCommitObservation
		}
	}
	return false
}

func validDiagnosticReason(reason DiagnosticReason) bool {
	switch reason {
	case "expected-entry-absent", "observed-entry-absent", "expected-setting-absent", "observed-setting-absent", "field-differs", "set-differs", "bytes-differ", "required-public-fact-unavailable", "invalid-input", "missing-required-field", "duplicate-key", "duplicate-member", "unresolved-reference", "invalid-utf8", "limit-exceeded", "invalid-field-combination", "caller-refused", "trust-basis-invalid", "domain-basis-invalid", "store-basis-invalid", "expired", "unsupported-schema", "unsupported-profile", "head-invalid", "proof-invalid", "selected-object-invalid", "selected-relation-invalid", "immutable-conflict", "evidence-unavailable", "selected-object-unavailable", "read-contention", "diagnostics-incomplete", "target-absent", "entry-absent", "duplicate-entry", "target-not-authorized", "locator-unusable":
		return true
	case DiagnosticReasonSetupRequired, DiagnosticReasonNone, DiagnosticReasonAdmissionRefused, DiagnosticReasonIntegrityFailure, DiagnosticReasonEvidenceUnavailable, DiagnosticReasonInvalid, DiagnosticReasonDenied, DiagnosticReasonCancelled, DiagnosticReasonUncertain,
		DiagnosticReasonAdmissionInvalid, DiagnosticReasonConstructionMismatch, DiagnosticReasonInvalidFormat, DiagnosticReasonInvalidProof, DiagnosticReasonInvalidReference, DiagnosticReasonInvalidRelation, DiagnosticReasonMissingSelectedObject,
		DiagnosticReasonReadUnavailable, DiagnosticReasonImmutableConflict, DiagnosticReasonCapacityExceeded, DiagnosticReasonInvalidIntent, DiagnosticReasonSigningUnavailable,
		DiagnosticReasonWriteUncertain, DiagnosticReasonStalePrecondition, DiagnosticReasonDifferentSelection, DiagnosticReasonAlreadyUsed, DiagnosticReasonCustodyUnavailable:
		return true
	}
	return false
}

func diagnosticReasonForResult(result Result) DiagnosticReason {
	switch result {
	case ResultSetupIncomplete:
		return DiagnosticReasonSetupRequired
	case ResultAdmissionRefused, ResultRootLossUnsupported, ResultCapacityExceeded:
		return DiagnosticReasonAdmissionRefused
	case ResultIntegrityFailure:
		return DiagnosticReasonIntegrityFailure
	case ResultEvidenceUnavailable, ResultReadMissing, ResultReadUnavailable, ResultSignUnavailable:
		return DiagnosticReasonEvidenceUnavailable
	case ResultInvalid, ResultReadInvalid, ResultSignInvalid:
		return DiagnosticReasonInvalid
	case ResultDenied, ResultWriteRefused, ResultAlreadyUsed:
		return DiagnosticReasonDenied
	case ResultCancelled, ResultExpired:
		return DiagnosticReasonCancelled
	case ResultFailure, ResultUnknown, ResultContention, ResultUnresolvedCommit, ResultWritePrecondition, ResultWriteConflict, ResultWriteUnknown:
		return DiagnosticReasonUncertain
	}
	return DiagnosticReasonNone
}

type diagnosticRecord struct {
	sequence, call, parent    uint64
	provider                  Provider
	operation                 Operation
	event                     DiagnosticEvent
	stage                     DiagnosticStage
	result                    Result
	reason                    DiagnosticReason
	details                   DiagnosticDetails
	traceID, spanID           string
	traceSampled              bool
	offsetNanos, elapsedNanos int64
}

const diagnosticRecordBytes = int(unsafe.Sizeof(diagnosticRecord{}))

// Reserve scratch inside the capture ceiling. A string-payload precheck keeps
// JSON admission below 18 KiB, including its fixed envelope; the encoder's
// growth buffer and returned copy then fit this 64 KiB reservation. The drain
// owner retains at most four records in the separate 64 KiB drain allowance.
const diagnosticEncodingBytes = 64 << 10
const diagnosticRetainedBytes = RecorderCaptureBytes - diagnosticEncodingBytes
const diagnosticSlotCount = (diagnosticRetainedBytes - diagnosticOverheadBytes) / (2 * diagnosticRecordBytes)

type RecorderStatus struct {
	Accepted          uint64 `json:"accepted"`
	DroppedContention uint64 `json:"dropped_contention"`
	DroppedFull       uint64 `json:"dropped_full"`
	DroppedClosed     uint64 `json:"dropped_closed"`
	Rejected          uint64 `json:"rejected"`
	Closed            bool   `json:"closed"`
}

type Recorder struct {
	mu                                                                sync.Mutex
	started                                                           time.Time
	minimumSeverity                                                   int
	slots                                                             [diagnosticSlotCount]diagnosticRecord
	head, count                                                       int
	payloadBytes                                                      int
	calls                                                             atomic.Uint64
	accepted, droppedContention, droppedFull, droppedClosed, rejected atomic.Uint64
	closed                                                            atomic.Bool
}

func NewRecorder() *Recorder { return NewRecorderWithMinimumSeverity(0) }

// NewRecorderWithMinimumSeverity applies the numeric severity threshold before
// capture. Valid records below minimum do not consume capacity or count as lost.
func NewRecorderWithMinimumSeverity(minimum int) *Recorder {
	return &Recorder{started: time.Now(), minimumSeverity: minimum}
}

type diagnosticContext struct {
	recorder *Recorder
	call     uint64
}

type diagnosticContextKey struct{}

// PrivateContext keeps the admitted lifetime in base and transfers only the
// invocation capability, parent call, and trace/span identity from source.
func PrivateContext(base, source context.Context) context.Context {
	if base == nil {
		base = context.Background()
	}
	diagnostic := diagnosticFromContext(source)
	if capability := capabilityFromContext(source); capability != nil {
		base = WithCapability(base, capability)
	}
	if diagnostic.recorder != nil {
		base = context.WithValue(base, diagnosticContextKey{}, diagnostic)
	}
	spanContext := trace.SpanContextFromContext(source)
	if spanContext.IsValid() {
		base = trace.ContextWithSpanContext(base, trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: spanContext.TraceID(), SpanID: spanContext.SpanID(), TraceFlags: spanContext.TraceFlags(),
		}))
	}
	return base
}

func diagnosticFromContext(ctx context.Context) diagnosticContext {
	if ctx == nil {
		return diagnosticContext{}
	}
	value, _ := ctx.Value(diagnosticContextKey{}).(diagnosticContext)
	if value.recorder == nil {
		if capability := capabilityFromContext(ctx); capability != nil {
			value.recorder = capability.Recorder()
		}
	}
	return value
}

func (recorder *Recorder) nextCall() uint64 {
	if recorder == nil {
		return 0
	}
	return recorder.calls.Add(1)
}

func (recorder *Recorder) emit(record diagnosticRecord) bool {
	if recorder == nil {
		return false
	}
	if !validDiagnosticInput(record) {
		recorder.rejected.Add(1)
		return false
	}
	if _, severity := diagnosticSeverity(record); severity < recorder.minimumSeverity {
		return false
	}
	if recorder.closed.Load() {
		recorder.droppedClosed.Add(1)
		return false
	}
	if !recorder.mu.TryLock() {
		recorder.droppedContention.Add(1)
		return false
	}
	defer recorder.mu.Unlock()
	if recorder.closed.Load() {
		recorder.droppedClosed.Add(1)
		return false
	}
	record.sequence = recorder.accepted.Load() + 1
	record.offsetNanos = time.Since(recorder.started).Nanoseconds()
	// Reject excessive escaping before allocating a JSON encoding buffer. This
	// lower bound cannot refuse a record whose complete JSON fits the wire bound.
	if record.escapedPayloadBytes() > MaximumLogRecordBytes || record.public(recorder.started).Validate() != nil {
		recorder.rejected.Add(1)
		return false
	}
	payloadBytes := record.stringBytes()
	if recorder.count == len(recorder.slots) || int(unsafe.Sizeof(*recorder))+recorder.payloadBytes+payloadBytes > diagnosticRetainedBytes {
		recorder.droppedFull.Add(1)
		return false
	}
	record = record.owned()
	record.sequence = recorder.accepted.Add(1)
	recorder.payloadBytes += payloadBytes
	index := (recorder.head + recorder.count) % len(recorder.slots)
	recorder.slots[index] = record
	recorder.count++
	return true
}

func validDiagnosticInput(record diagnosticRecord) bool {
	if record.call == 0 || record.parent == record.call || !ValidOperationOwner(record.provider, record.operation) || !validDiagnosticReason(record.reason) || !validDetails(record.details) || !validTraceLink(record.traceID, record.spanID, record.traceSampled) || record.elapsedNanos < 0 {
		return false
	}
	switch record.event {
	case DiagnosticStart:
		return record.stage == "" && record.result == "" && record.reason == "" && record.elapsedNanos == 0
	case DiagnosticCheckpoint:
		return validDiagnosticStageFor(record.provider, record.operation, record.stage) && record.result == ""
	case DiagnosticReturn:
		return record.stage == "" && AllowedAttribute("result", string(record.result))
	}
	return false
}

func (recorder *Recorder) Drain(dst []DiagnosticRecord) []DiagnosticRecord {
	if recorder == nil {
		return dst
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	available := cap(dst) - len(dst)
	if available > recorder.count {
		available = recorder.count
	}
	for i := range available {
		index := (recorder.head + i) % len(recorder.slots)
		record := recorder.slots[index]
		dst = append(dst, record.public(recorder.started))
		recorder.payloadBytes -= record.stringBytes()
		recorder.slots[index] = diagnosticRecord{}
	}
	recorder.head = (recorder.head + available) % len(recorder.slots)
	recorder.count -= available
	return dst
}

// public defines the emitted projection once, for both admission and draining.
func (record diagnosticRecord) public(started time.Time) DiagnosticRecord {
	severityText, severityNumber := diagnosticSeverity(record)
	return DiagnosticRecord{
		SchemaVersion: DiagnosticSchemaVersion, OccurredAt: started.Add(time.Duration(record.offsetNanos)).UTC(), Component: string(record.provider), SeverityText: severityText, SeverityNumber: severityNumber,
		TraceID: record.traceID, SpanID: record.spanID, TraceSampled: record.traceSampled,
		EntryName: record.details.entryName, KeyID: record.details.keyID, CommandID: record.details.commandID, AttemptID: record.details.attemptID, InvocationID: record.details.invocationID, WorkerID: record.details.workerID, PathKind: record.details.pathKind, Path: record.details.path, ConfigField: record.details.configField, ErrorClass: record.details.errorClass, HTTPStatus: record.details.httpStatus, ErrorDetail: errorDetail(record.details), ErrorDetailStatus: errorDetailStatus(record.details),
		Sequence: record.sequence, Call: record.call, ParentCall: record.parent,
		Provider: record.provider, Operation: record.operation, Event: record.event, Stage: record.stage, Result: record.result, Reason: record.reason,
		OffsetNanos: record.offsetNanos, ElapsedNanos: record.elapsedNanos,
	}
}

func (record diagnosticRecord) stringValues() [19]string {
	d := record.details
	return [19]string{string(record.provider), string(record.operation), string(record.event), string(record.stage), string(record.result), string(record.reason), record.traceID, record.spanID, d.entryName, d.keyID, d.commandID, d.attemptID, d.invocationID, d.workerID, d.pathKind, d.path, d.configField, string(d.errorClass), d.errorText}
}

func (record diagnosticRecord) stringBytes() int {
	total := 0
	for _, value := range record.stringValues() {
		total += len(value)
	}
	return total
}

func (record diagnosticRecord) escapedPayloadBytes() int {
	total := record.stringBytes()
	// Admitted fields contain valid UTF-8 and no controls. These are the only
	// remaining encodings that JSON expands beyond the original UTF-8 bytes.
	for _, value := range record.stringValues() {
		for _, r := range value {
			switch r {
			case '<', '>', '&':
				total += 5
			case '"', '\\':
				total++
			case '\u2028', '\u2029':
				total += 3
			}
		}
	}
	return total
}

func (record diagnosticRecord) owned() diagnosticRecord {
	record.provider = Provider(strings.Clone(string(record.provider)))
	record.operation = Operation(strings.Clone(string(record.operation)))
	record.event = DiagnosticEvent(strings.Clone(string(record.event)))
	record.stage = DiagnosticStage(strings.Clone(string(record.stage)))
	record.result = Result(strings.Clone(string(record.result)))
	record.reason = DiagnosticReason(strings.Clone(string(record.reason)))
	record.traceID = strings.Clone(record.traceID)
	record.spanID = strings.Clone(record.spanID)
	d := record.details
	d.entryName = strings.Clone(d.entryName)
	d.keyID = strings.Clone(d.keyID)
	d.commandID = strings.Clone(d.commandID)
	d.attemptID = strings.Clone(d.attemptID)
	d.invocationID = strings.Clone(d.invocationID)
	d.workerID = strings.Clone(d.workerID)
	d.pathKind = strings.Clone(d.pathKind)
	d.path = strings.Clone(d.path)
	d.configField = strings.Clone(d.configField)
	d.errorClass = DiagnosticReason(strings.Clone(string(d.errorClass)))
	d.errorText = strings.Clone(d.errorText)
	record.details = d
	return record
}

func (recorder *Recorder) Status() RecorderStatus {
	if recorder == nil {
		return RecorderStatus{}
	}
	return RecorderStatus{
		Accepted: recorder.accepted.Load(), DroppedContention: recorder.droppedContention.Load(), DroppedFull: recorder.droppedFull.Load(),
		DroppedClosed: recorder.droppedClosed.Load(), Rejected: recorder.rejected.Load(), Closed: recorder.closed.Load(),
	}
}

func (recorder *Recorder) Close() RecorderStatus {
	if recorder != nil {
		recorder.closed.Store(true)
	}
	return recorder.Status()
}
