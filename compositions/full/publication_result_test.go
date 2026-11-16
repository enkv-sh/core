package compositionfull

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func publicPublicationResultFixture(action, disposition uint8) core.PublicPublicationResult {
	id := func(n byte) contract.ID { return contract.ID{n} }
	row := contract.PublicationOutcome{Action: action, ProjectionCommitment: id(6), AttemptID: id(7), Disposition: disposition,
		Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry,
			Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: id(8), NormalizedStatus: 201,
			SafeRequestID: "request", SafeResourceID: "resource"}}
	switch disposition {
	case contract.PublicationNoOp:
		row = contract.PublicationOutcome{Disposition: disposition}
	case contract.PublicationNotSent:
		row.AttemptID, row.Evidence, row.CoreReason = contract.ID{}, contract.PublicationEvidence{}, uint16(core.AdmissionInvalid)
	case contract.PublicationOutcomeQualifiedNoEffect:
		row.Evidence.Class = contract.PublicationQualifiedNoEffect
	case contract.PublicationOutcomeUnknown:
		row.Evidence.Class, row.Evidence.NormalizedStatus = contract.PublicationUnproved, 0
		row.Evidence.SafeRequestID, row.Evidence.SafeResourceID = "", ""
	}
	if disposition == contract.PublicationOutcomeAcknowledged && (action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue) {
		row.Evidence.ConsumerLocator = "consumer/resource"
	}
	name, destination := "entry", "destination"
	coordinate, _ := contract.PublicationCoordinateID(id(1), "service", "account/entry")
	description := core.PublicationTargetDescription{CoordinateID: coordinate, Origin: core.PublicationTargetCurrent, EntryName: &name, DestinationID: &destination, ServiceContractID: "service", CanonicalTarget: "account/entry"}
	vector := &contract.PublicationOutcomeVector{Schema: 2, DomainID: id(1), OperationID: id(2), SnapshotID: id(4), SelectionDigest: id(5),
		Entries: []contract.PublicationTargetOutcome{{CoordinateID: coordinate, Actions: []contract.PublicationOutcome{row}}}}
	return core.PublicPublicationResult{RequestID: id(3), DomainID: id(1), OperationID: id(2), RequestIdentity: id(10),
		Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure}, Output: vector, Descriptions: []core.PublicationTargetDescription{description}, Summary: contract.SummarizePublication(vector.Entries)}
}

// full_only: false
func TestPublicPublicationResultUsesClosedActionsDispositionsAndAbsentFields(t *testing.T) {
	actions := []string{"", "create-empty", "create-with-value", "write-value", "update-policy", "delete-owned", "delete-reserved-slot"}
	dispositions := []string{"", "no-op", "not-sent", "acknowledged", "rejected", "unknown"}
	for disposition := uint8(1); disposition <= 5; disposition++ {
		first, last := uint8(1), uint8(6)
		if disposition == contract.PublicationNoOp {
			first, last = 0, 0
		}
		for action := first; action <= last; action++ {
			t.Run(fmt.Sprintf("%s/%s", dispositions[disposition], actions[action]), func(t *testing.T) {
				r := publicPublicationResultFixture(action, disposition)
				body, err := RenderPublicationJSON(r)
				if err != nil {
					t.Fatal(err)
				}
				var record map[string]json.RawMessage
				if err := json.Unmarshal(body, &record); err != nil {
					t.Fatal(err)
				}
				keys := make([]string, 0, len(record))
				for key := range record {
					keys = append(keys, key)
				}
				slices.Sort(keys)
				wantKeys := []string{"domain_id", "effect_summary", "evidence_ceiling", "operation_id", "operation_kind", "output_summary", "payload", "reason_code", "replay_identity", "request_id", "request_identity", "schema", "state_result"}
				if !reflect.DeepEqual(keys, wantKeys) || string(record["operation_kind"]) != `"publish"` || string(record["schema"]) != `"ProductResult/v1"` || string(record["replay_identity"]) != `"none"` || string(record["effect_summary"]) != `"not-applicable"` {
					t.Fatal("publication envelope has unclosed or changed fields", string(body))
				}
				var payload struct {
					Schema  string `json:"schema"`
					Entries []struct {
						Actions []map[string]json.RawMessage `json:"actions"`
					} `json:"entries"`
				}
				if err := json.Unmarshal(record["payload"], &payload); err != nil || payload.Schema != "OutputPayload/v3" || len(payload.Entries) != 1 || len(payload.Entries[0].Actions) != 1 {
					t.Fatal("complete output vector lost", err)
				}
				row := payload.Entries[0].Actions[0]
				wantAction := `"` + actions[action] + `"`
				if action == 0 {
					wantAction = "null"
				}
				if string(row["action"]) != wantAction || string(row["disposition"]) != `"`+dispositions[disposition]+`"` {
					t.Fatal("binary enum changed public meaning", string(body))
				}
				absent := disposition == contract.PublicationNoOp || disposition == contract.PublicationNotSent
				if (string(row["attempt_id"]) == "null") != absent || (string(row["evidence"]) == "null") != absent || (string(row["projection_commitment"]) == "null") != (action == 0) || string(row["blocker_ids"]) != "[]" {
					t.Fatal("absent facts became zero-valued evidence", string(body))
				}
				if !absent {
					class, status, request, resource, locator := "acknowledged", float64(201), "request", "resource", ""
					if disposition == contract.PublicationOutcomeQualifiedNoEffect {
						class = "qualified-no-effect"
					} else if disposition == contract.PublicationOutcomeUnknown {
						class, status, request, resource = "unproved", 0, "", ""
					} else if action == contract.PublicationCreateEmpty || action == contract.PublicationCreateWithValue {
						locator = "consumer/resource"
					}
					wantEvidence := map[string]any{
						"schema": "PublicationEvidence/v3", "entry": "may-have-entered", "class": class,
						"response_contract_digest": "08" + strings.Repeat("0", 62), "normalized_status": status,
						"safe_request_id": request, "safe_resource_id": resource, "consumer_locator": locator,
					}
					var evidence map[string]any
					if err := json.Unmarshal(row["evidence"], &evidence); err != nil || !reflect.DeepEqual(evidence, wantEvidence) {
						t.Fatal("closed evidence fields or qualified creation locator changed", err, string(row["evidence"]))
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicPublicationResultPreservesUnknownBeforeLaterAcknowledgement(t *testing.T) {
	r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeUnknown)
	r.Output.Entries[0].Actions[0].BlockerIDs = []contract.ID{{20}, {21}}
	r.Output.Entries[0].Actions[0].LateWriteRisk = 1
	ack := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged).Output.Entries[0]
	description := r.Descriptions[0]
	description.CanonicalTarget = "account/other"
	description.CoordinateID, _ = contract.PublicationCoordinateID(r.DomainID, description.ServiceContractID, description.CanonicalTarget)
	ack.CoordinateID, ack.Actions[0].AttemptID = description.CoordinateID, contract.ID{31}
	r.Output.Entries = append(r.Output.Entries, ack)
	r.Descriptions = append(r.Descriptions, description)
	slices.SortFunc(r.Output.Entries, func(a, b contract.PublicationTargetOutcome) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	slices.SortFunc(r.Descriptions, func(a, b core.PublicationTargetDescription) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	r.Summary = contract.PublicationSummaryUnknown
	body, err := RenderPublicationJSON(r)
	if err != nil || !bytes.Contains(body, []byte(`"state_result": "effect-unknown"`)) || !bytes.Contains(body, []byte(`"output_summary": "output-unknown"`)) || PublicationExitCode(r) != 3 {
		t.Fatal("later acknowledgement erased unknown", err, string(body))
	}
	human, err := RenderPublicationHuman(r)
	if err != nil || !bytes.Contains(human, []byte(readerID(r.Output.Entries[0].CoordinateID))) || !bytes.Contains(human, []byte(readerID(contract.ID{7}))) || !strings.Contains(string(human), "late") || !strings.Contains(string(human), "unknown") {
		t.Fatal("human output lost exact uncertain coordinate or warning", err)
	}
}

// full_only: false
func TestPublicationHumanShowsEachActionAndUncertainty(t *testing.T) {
	r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeUnknown)
	body, err := RenderPublicationHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Publication: effect-unknown\n", "Coordinate: " + readerID(r.Output.Entries[0].CoordinateID), "Attempt: " + readerID(r.Output.Entries[0].Actions[0].AttemptID), "write-value: unknown", "Acknowledgement does not prove remote currentness"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("publication human omitted an action fact", want, string(body))
		}
	}
	if bytes.Contains(body, []byte("ProductResult/v1")) || bytes.Contains(body, []byte("OutputPayload/v3")) {
		t.Fatal("publication human exposed an internal envelope")
	}
}

// full_only: false
func TestPublicPublicationResultRejectsUnknownReasonsAndInvalidEvidence(t *testing.T) {
	for _, condition := range []string{"reason", "action-reason", "evidence-string", "evidence-utf8", "consumer-locator-byte", "consumer-locator-utf8", "coordinate-order", "summary"} {
		t.Run(condition, func(t *testing.T) {
			r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
			switch condition {
			case "reason":
				r.Result.Reason = core.Reason(20)
			case "action-reason":
				r = publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationNotSent)
				r.Output.Entries[0].Actions[0].CoreReason = 20
			case "evidence-string":
				r.Output.Entries[0].Actions[0].Evidence.SafeRequestID = strings.Repeat("x", 1025)
			case "evidence-utf8":
				r.Output.Entries[0].Actions[0].Evidence.SafeResourceID = string([]byte{255})
			case "consumer-locator-byte":
				r = publicPublicationResultFixture(contract.PublicationCreateWithValue, contract.PublicationOutcomeAcknowledged)
				r.Output.Entries[0].Actions[0].Evidence.ConsumerLocator = strings.Repeat("x", 1025)
			case "consumer-locator-utf8":
				r = publicPublicationResultFixture(contract.PublicationCreateWithValue, contract.PublicationOutcomeAcknowledged)
				r.Output.Entries[0].Actions[0].Evidence.ConsumerLocator = string([]byte{255})
			case "coordinate-order":
				r.Output.Entries = append(r.Output.Entries, r.Output.Entries[0])
			case "summary":
				r.Summary = contract.PublicationSummaryNoChange
			}
			if _, err := RenderPublicationJSON(r); err == nil {
				t.Fatal("invalid closed result rendered")
			}
			if _, err := RenderPublicationHuman(r); err == nil {
				t.Fatal("invalid human result rendered")
			}
		})
	}
}

// full_only: false
func TestPublicPublicationResultKeepsActualRefusalWithoutVector(t *testing.T) {
	for _, test := range []struct {
		outcome core.Outcome
		reason  core.Reason
		state   string
		exit    int
	}{
		{core.Contention, core.StalePrecondition, "contention", 3},
		{core.EvidenceUnavailable, core.ReadUnavailable, "unavailable", 3},
		{core.RootLossUnsupported, core.MissingSelectedObject, "root-loss-unsupported", 2},
		{core.IntegrityFailure, core.InvalidProof, "positive-defect", 2},
		{core.AdmissionRefused, core.InvalidIntent, "refused", 2},
		{core.AdmissionRefused, core.CapacityExceeded, "snapshot-size-refusal", 2},
	} {
		t.Run(test.state, func(t *testing.T) {
			r := core.PublicPublicationResult{RequestID: contract.ID{1}, Result: core.Result{Outcome: test.outcome, Reason: test.reason}}
			body, err := RenderPublicationJSON(r)
			if err != nil || !bytes.Contains(body, []byte(`"state_result": "`+test.state+`"`)) || !bytes.Contains(body, []byte(`"payload": null`)) || !bytes.Contains(body, []byte(`"operation_id": null`)) || !bytes.Contains(body, []byte(`"request_identity": null`)) || PublicationExitCode(r) != test.exit {
				t.Fatal("unstarted operation claimed a complete vector", err, string(body))
			}
		})
	}
}
