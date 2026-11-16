package compositionfull

import (
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

const publicationCompactResultLimit = 108068919 + 2048

// MaxPublicationResultJSONBytes bounds the complete readable native result.
const MaxPublicationResultJSONBytes = 67 * publicationCompactResultLimit

var ErrPublicationResult = errors.New("publication result rendering refused")

func publicationNullableID(id contract.ID) *string {
	if id.IsZero() {
		return nil
	}
	text := readerID(id)
	return &text
}

func publicationState(r core.PublicPublicationResult) (state, summary string, err error) {
	if r.RequestID.IsZero() || r.Result.Reason > core.GeneratedIntentConflict || r.Result.Outcome < core.Unchanged || r.Result.Outcome > core.AdmissionRefused || !core.ValidPublicationDescriptions(r.DomainID, r.Output, r.Descriptions) {
		return "", "", ErrPublicationResult
	}
	if r.ExecutableCleanupFailed && (r.Output == nil || r.Result.Outcome == core.ObservedCurrent || r.Result.Outcome == core.Unchanged) {
		return "", "", ErrPublicationResult
	}
	state = "refused"
	summary = "output-no-change"
	switch r.Result.Outcome {
	case core.Contention:
		state = "contention"
	case core.EvidenceUnavailable:
		state = "unavailable"
	case core.RootLossUnsupported:
		state = "root-loss-unsupported"
	case core.IntegrityFailure:
		state = "positive-defect"
	case core.UnresolvedCommit:
		state = "commit-outcome-unknown"
	case core.AdmissionRefused:
		if r.Result.Reason == core.CapacityExceeded {
			state = "snapshot-size-refusal"
		}
	}
	if r.Output == nil {
		if r.Summary != 0 || r.Result.Outcome == core.Unchanged || r.Result.Outcome == core.ObservedCurrent {
			return "", "", ErrPublicationResult
		}
		return state, summary, nil
	}
	if r.DomainID.IsZero() || r.OperationID.IsZero() || r.RequestIdentity.IsZero() || r.Output.DomainID != r.DomainID || r.Output.OperationID != r.OperationID || r.Summary != contract.SummarizePublication(r.Output.Entries) {
		return "", "", ErrPublicationResult
	}
	if _, err := contract.EncodePublicationOutcomeVector(*r.Output); err != nil {
		return "", "", ErrPublicationResult
	}
	hasResult := false
	for _, target := range r.Output.Entries {
		for _, action := range target.Actions {
			if action.CoreReason > uint16(core.GeneratedIntentConflict) || !utf8.ValidString(action.Evidence.SafeRequestID) || !utf8.ValidString(action.Evidence.SafeResourceID) || len(action.Evidence.SafeRequestID) > 1024 || len(action.Evidence.SafeResourceID) > 1024 {
				return "", "", ErrPublicationResult
			}
			hasResult = hasResult || action.Disposition != contract.PublicationNotSent
		}
	}
	switch r.Summary {
	case contract.PublicationSummaryNoChange:
		state, summary = "no-op", "output-no-change"
	case contract.PublicationSummaryComplete:
		state, summary = "success", "output-complete"
	case contract.PublicationSummaryUnknown:
		state, summary = "effect-unknown", "output-unknown"
	case contract.PublicationSummaryMixedTerminal:
		state, summary = "effect-terminal-failure", "output-mixed-terminal"
	case contract.PublicationSummaryFailed:
		summary = "output-failed"
		if hasResult || r.Result.Outcome == core.ObservedCurrent || r.Result.Outcome == core.Unchanged {
			state = "effect-terminal-failure"
		}
	default:
		return "", "", ErrPublicationResult
	}
	if (r.Result.Reason == core.CustodyUnavailable || r.ExecutableCleanupFailed) && r.Summary != contract.PublicationSummaryUnknown {
		state = "effect-terminal-failure"
	}
	return state, summary, nil
}

func PublicationExitCode(r core.PublicPublicationResult) int {
	state, _, err := publicationState(r)
	if err != nil {
		return 2
	}
	if state == "effect-unknown" || r.Result.Outcome == core.Contention || r.Result.Outcome == core.EvidenceUnavailable || r.Result.Outcome == core.UnresolvedCommit {
		return 3
	}
	if r.CleanupFailed {
		return 2
	}
	if state == "success" || state == "no-op" {
		return 0
	}
	return 2
}

type publicationHeader struct {
	Schema                  string      `json:"schema"`
	Operation               string      `json:"operation_kind"`
	Request                 string      `json:"request_id"`
	Domain                  *string     `json:"domain_id"`
	OperationID             *string     `json:"operation_id"`
	Identity                *string     `json:"request_identity"`
	Replay                  string      `json:"replay_identity"`
	State                   string      `json:"state_result"`
	Effect                  string      `json:"effect_summary"`
	Output                  string      `json:"output_summary"`
	Evidence                string      `json:"evidence_ceiling"`
	Reason                  core.Reason `json:"reason_code"`
	ExecutableCleanupFailed bool        `json:"executable_cleanup_failed,omitempty"`
	CleanupFailed           bool        `json:"cleanup_failed,omitempty"`
}
type publicationEvidenceRecord struct {
	Schema   string `json:"schema"`
	Entry    string `json:"entry"`
	Class    string `json:"class"`
	Response string `json:"response_contract_digest"`
	Status   uint16 `json:"normalized_status"`
	Request  string `json:"safe_request_id"`
	Resource string `json:"safe_resource_id"`
	Locator  string `json:"consumer_locator"`
}
type publicationActionRecord struct {
	Action      *string                    `json:"action"`
	Projection  *string                    `json:"projection_commitment"`
	Attempt     *string                    `json:"attempt_id"`
	Disposition string                     `json:"disposition"`
	Reason      uint16                     `json:"reason_code"`
	Remote      bool                       `json:"remote_value_may_remain"`
	Late        bool                       `json:"late_write_risk"`
	Blockers    []string                   `json:"blocker_ids"`
	Evidence    *publicationEvidenceRecord `json:"evidence"`
}

type publicationTargetRecord struct {
	Origin            string  `json:"origin"`
	EntryName         *string `json:"entry_name"`
	DestinationID     *string `json:"destination_id"`
	ServiceContractID string  `json:"service_contract_id"`
	CanonicalTarget   string  `json:"canonical_target"`
}

func publicationTarget(row core.PublicationTargetDescription) publicationTargetRecord {
	origin := "current"
	if row.Origin == core.PublicationTargetRetainedDeletion {
		origin = "retained-deletion"
	}
	return publicationTargetRecord{origin, row.EntryName, row.DestinationID, row.ServiceContractID, row.CanonicalTarget}
}

func publicationActionName(action uint8) string {
	switch action {
	case contract.PublicationCreateEmpty:
		return "create-empty"
	case contract.PublicationCreateWithValue:
		return "create-with-value"
	case contract.PublicationWriteValue:
		return "write-value"
	case contract.PublicationUpdatePolicy:
		return "update-policy"
	case contract.PublicationDeleteOwned:
		return "delete-owned"
	case contract.PublicationDeleteReservedSlot:
		return "delete-reserved-slot"
	default:
		return ""
	}
}

func publicationAction(v contract.PublicationOutcome) publicationActionRecord {
	dispositions := []string{"", "no-op", "not-sent", "acknowledged", "rejected", "unknown"}
	out := publicationActionRecord{Projection: publicationNullableID(v.ProjectionCommitment), Attempt: publicationNullableID(v.AttemptID), Disposition: dispositions[v.Disposition], Reason: v.CoreReason, Remote: v.RemoteValueMayRemain != 0, Late: v.LateWriteRisk != 0, Blockers: make([]string, 0, len(v.BlockerIDs))}
	if v.Action != 0 {
		text := publicationActionName(v.Action)
		out.Action = &text
	}
	for _, id := range v.BlockerIDs {
		out.Blockers = append(out.Blockers, readerID(id))
	}
	if v.Evidence != (contract.PublicationEvidence{}) {
		e := v.Evidence
		out.Evidence = &publicationEvidenceRecord{Schema: "PublicationEvidence/v3", Entry: []string{"", "not-entered", "may-have-entered"}[e.Entry], Class: []string{"unproved", "acknowledged", "qualified-no-effect"}[e.Class], Response: readerID(e.ResponseContractDigest), Status: e.NormalizedStatus, Request: e.SafeRequestID, Resource: e.SafeResourceID, Locator: e.ConsumerLocator}
	}
	return out
}

func RenderPublicationJSON(r core.PublicPublicationResult) ([]byte, error) {
	return renderPublication(r, false, nil, "")
}
func RenderPublicationHuman(r core.PublicPublicationResult) ([]byte, error) {
	return renderPublication(r, true, nil, "")
}
func renderPublication(r core.PublicPublicationResult, human bool, sourceFailure *ConfigurationSourceFailure, sourceStage string) ([]byte, error) {
	if !validPublicationSourceFailure(r, sourceFailure, sourceStage) {
		return nil, ErrPublicationResult
	}
	state, summary, err := publicationState(r)
	if err != nil {
		return nil, err
	}
	if human {
		return renderPublicationHuman(r, state, summary, sourceFailure)
	}
	evidence := "unavailable"
	if r.Result.Evidence == core.AuthenticatedClosure {
		evidence = "canonical"
	}
	header := publicationHeader{"ProductResult/v1", "publish", readerID(r.RequestID), publicationNullableID(r.DomainID), publicationNullableID(r.OperationID), publicationNullableID(r.RequestIdentity), "none", state, "not-applicable", summary, evidence, r.Result.Reason, r.ExecutableCleanupFailed, r.CleanupFailed}
	write := func(w *readerResultWriter) {
		body, e := json.Marshal(header)
		if e != nil {
			w.failed = true
			return
		}
		w.literal(string(body[:len(body)-1]))
		if sourceFailure != nil {
			w.sourceFailure(sourceFailure, false)
		}
		w.literal(`,"payload":`)
		if r.Output == nil {
			w.literal("null}")
			return
		}
		v := r.Output
		w.literal(`{"schema":"OutputPayload/v3","domain_id":`)
		w.json(readerID(v.DomainID), publicationCompactResultLimit)
		w.literal(`,"operation_id":`)
		w.json(readerID(v.OperationID), publicationCompactResultLimit)
		w.literal(`,"snapshot_id":`)
		w.json(readerID(v.SnapshotID), publicationCompactResultLimit)
		w.literal(`,"selection_digest":`)
		w.json(readerID(v.SelectionDigest), publicationCompactResultLimit)
		w.literal(`,"domain_wide_warning":` + strconv.FormatBool(v.DomainWideWarning != 0) + `,"entries":[`)
		for i, target := range v.Entries {
			if i > 0 {
				w.literal(",")
			}
			w.literal(`{"coordinate_id":`)
			w.json(readerID(target.CoordinateID), publicationCompactResultLimit)
			w.literal(`,"target":`)
			w.json(publicationTarget(r.Descriptions[i]), 11264)
			w.literal(`,"actions":[`)
			for j, action := range target.Actions {
				if j > 0 {
					w.literal(",")
				}
				w.json(publicationAction(action), publicationCompactResultLimit)
			}
			w.literal("]}")
		}
		w.literal("]}}")
	}
	body, err := renderReadableReaderResultBound(publicationCompactResultLimit, write)
	if err != nil {
		return nil, ErrPublicationResult
	}
	return body, nil
}
