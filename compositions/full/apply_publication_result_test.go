package compositionfull

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestApplyPublicationResultPreservesCompleteStages(t *testing.T) {
	apply := suppliedApplyResultFixture(t)
	publication := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeUnknown)
	publication.Output.Entries[0].Actions[0].BlockerIDs = []contract.ID{{20}, {21}}
	publication.Output.Entries[0].Actions[0].LateWriteRisk = 1
	ack := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged).Output.Entries[0]
	description := publication.Descriptions[0]
	description.CanonicalTarget = "account/other"
	description.CoordinateID, _ = contract.PublicationCoordinateID(publication.DomainID, description.ServiceContractID, description.CanonicalTarget)
	ack.CoordinateID, ack.Actions[0].AttemptID = description.CoordinateID, contract.ID{31}
	publication.Output.Entries = append(publication.Output.Entries, ack)
	publication.Descriptions = append(publication.Descriptions, description)
	slices.SortFunc(publication.Output.Entries, func(a, b contract.PublicationTargetOutcome) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	slices.SortFunc(publication.Descriptions, func(a, b core.PublicationTargetDescription) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	publication.Summary = contract.PublicationSummaryUnknown
	result := core.PublicApplyPublicationResult{Apply: apply, Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &publication}}
	wantApply, err := RenderApplyJSON(apply)
	if err != nil {
		t.Fatal(err)
	}
	wantPublication, err := RenderPublicationJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := WriteApplyPublicationJSON(&output, result); err != nil {
		t.Fatal(err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(output.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(envelope))
	for key := range envelope {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !reflect.DeepEqual(keys, []string{"apply", "publication", "schema"}) || string(envelope["schema"]) != `"ApplyPublicationResult/v1"` || !resultJSONFactsEqual(envelope["apply"], wantApply) {
		t.Fatal("combined response changed the apply result or envelope", output.String())
	}
	var stage map[string]json.RawMessage
	if err := json.Unmarshal(envelope["publication"], &stage); err != nil {
		t.Fatal(err)
	}
	keys = keys[:0]
	for key := range stage {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	if !reflect.DeepEqual(keys, []string{"reason", "result", "stage"}) || string(stage["stage"]) != `"evaluated"` || string(stage["reason"]) != "null" || !resultJSONFactsEqual(stage["result"], wantPublication) {
		t.Fatal("combined response lost complete publication facts", output.String())
	}
	var human bytes.Buffer
	if err := WriteApplyPublicationHuman(&human, result); err != nil {
		t.Fatal(err)
	}
	wantApplyHuman, err := RenderApplyHuman(apply)
	if err != nil {
		t.Fatal(err)
	}
	wantPublicationHuman, err := RenderPublicationHuman(publication)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(human.Bytes(), wantApplyHuman) || !bytes.Contains(human.Bytes(), wantPublicationHuman) || !strings.Contains(human.String(), "apply") || !strings.Contains(human.String(), "publication") {
		t.Fatal("human response lost a stage or its complete facts")
	}
	if !bytes.Equal(result.Apply.Receipt, apply.Receipt) || !reflect.DeepEqual(result.Publication.Result.Output, publication.Output) {
		t.Fatal("rendering changed the owned stage facts")
	}
}

// full_only: false
func TestApplyPublicationResultUsesClosedUnstartedReasons(t *testing.T) {
	for _, reason := range []string{"apply-incomplete", "selection-unavailable", "selection-conflict", "deadline-expired"} {
		t.Run(reason, func(t *testing.T) {
			result := core.PublicApplyPublicationResult{Apply: suppliedApplyResultFixture(t), Publication: core.ApplyPublicationStage{Stage: "unstarted", Reason: reason}}
			var output bytes.Buffer
			if err := WriteApplyPublicationJSON(&output, result); err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Publication struct {
					Stage  string
					Reason string
					Result json.RawMessage
				}
			}
			if err := json.Unmarshal(output.Bytes(), &envelope); err != nil || envelope.Publication.Stage != "unstarted" || envelope.Publication.Reason != reason || string(envelope.Publication.Result) != "null" {
				t.Fatal("unstarted stage invented an operation result", err, output.String())
			}
			var human bytes.Buffer
			if err := WriteApplyPublicationHuman(&human, result); err != nil || !strings.Contains(human.String(), reason) {
				t.Fatal("human response lost unstarted reason", err)
			}
		})
	}
}

// full_only: false
func TestApplyPublicationResultRejectsInvalidStageRelations(t *testing.T) {
	publication := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
	for _, stage := range []core.ApplyPublicationStage{
		{},
		{Stage: "unknown", Reason: "selection-unavailable"},
		{Stage: "evaluated"},
		{Stage: "evaluated", Reason: "apply-incomplete", Result: &publication},
		{Stage: "unstarted"},
		{Stage: "unstarted", Reason: "latest-state"},
		{Stage: "unstarted", Reason: "selection-conflict", Result: &publication},
	} {
		t.Run(stage.Stage+"/"+stage.Reason, func(t *testing.T) {
			result := core.PublicApplyPublicationResult{Apply: suppliedApplyResultFixture(t), Publication: stage}
			var output bytes.Buffer
			if err := WriteApplyPublicationJSON(&output, result); err == nil || output.Len() != 0 {
				t.Fatal("invalid stage emitted a partial response", err, output.String())
			}
			if err := WriteApplyPublicationHuman(&output, result); err == nil || output.Len() != 0 {
				t.Fatal("invalid stage emitted partial human output", err)
			}
		})
	}
}
