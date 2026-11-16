package compositionfull

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func applyPublicationFramingID(kind byte, serial uint64) contract.ID {
	var id contract.ID
	id[0] = kind
	binary.BigEndian.PutUint64(id[24:], serial)
	return id
}

func applyPublicationMaximumFramingFixture() core.PublicApplyPublicationResult {
	contextID := applyPublicationFramingID(8, 1)
	vector := &contract.PublicationOutcomeVector{Schema: 2, DomainID: contextID, OperationID: contextID, SnapshotID: contextID, SelectionDigest: contextID, DomainWideWarning: 1,
		Entries: make([]contract.PublicationTargetOutcome, 1024)}
	safe := strings.Repeat("\x00", 1024)
	name, destination, service := strings.Repeat("\x00", 256), strings.Repeat("\x00", 256), strings.Repeat("\x00", 256)
	descriptions := make([]core.PublicationTargetDescription, len(vector.Entries))
	for i := range vector.Entries {
		n := uint64(i + 1)
		target := strings.Repeat("\x00", 1020) + fmt.Sprintf("%04d", i)
		coordinate, _ := contract.PublicationCoordinateID(contextID, service, target)
		descriptions[i] = core.PublicationTargetDescription{CoordinateID: coordinate, Origin: core.PublicationTargetCurrent, EntryName: &name, DestinationID: &destination, ServiceContractID: service, CanonicalTarget: target}
		vector.Entries[i] = contract.PublicationTargetOutcome{CoordinateID: coordinate, Actions: []contract.PublicationOutcome{{
			Action: contract.PublicationCreateWithValue, ProjectionCommitment: applyPublicationFramingID(4, n), AttemptID: applyPublicationFramingID(2, n), Disposition: contract.PublicationOutcomeAcknowledged,
			RemoteValueMayRemain: 1, LateWriteRisk: 1, BlockerIDs: []contract.ID{applyPublicationFramingID(3, 2*n-1), applyPublicationFramingID(3, 2*n)},
			Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: applyPublicationFramingID(5, 1), NormalizedStatus: 65535, SafeRequestID: safe, SafeResourceID: safe, ConsumerLocator: safe},
		}}}
	}
	slices.SortFunc(vector.Entries, func(a, b contract.PublicationTargetOutcome) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	slices.SortFunc(descriptions, func(a, b core.PublicationTargetDescription) int {
		return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
	})
	publication := core.PublicPublicationResult{Descriptions: descriptions, RequestID: contextID, DomainID: contextID, OperationID: contextID, RequestIdentity: contextID, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure}, Output: vector, Summary: contract.PublicationSummaryComplete}
	apply := suppliedApplyNoopResultFixture()
	apply.DomainID = contextID
	return core.PublicApplyPublicationResult{Apply: apply, Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &publication}}
}

type applyPublicationCountingWriter struct{ bytes uint64 }

func (w *applyPublicationCountingWriter) Write(body []byte) (int, error) {
	w.bytes += uint64(len(body))
	return len(body), nil
}

// full_only: false
func TestApplyPublicationCompleteVectorFieldLimitsAndFraming(t *testing.T) {
	result := applyPublicationMaximumFramingFixture()
	publication := *result.Publication.Result
	binaryBody, err := contract.EncodePublicationOutcomeVector(*publication.Output)
	// Binary grammar: 133-byte vector header; each target has 33 bytes,
	// one 76-byte action, two 32-byte blockers and 50+3*1024 evidence bytes.
	const binaryMaximum = 133 + 1024*(33+76+2*32+50+3*1024)
	if err != nil || len(binaryBody) != binaryMaximum || binaryMaximum != 3374213 {
		t.Fatal("independent complete binary framing differs", len(binaryBody), err)
	}
	publicationBody, err := RenderPublicationJSON(publication)
	if err != nil {
		t.Fatal(err)
	}
	// A 32-byte ID always renders to 64 characters. Each NUL uses exactly
	// six JSON bytes. These closed literals derive field/framing cost without
	// calling the production action projection or JSON encoder.
	id := strings.Repeat("0", 64)
	escaped := strings.Repeat(`\u0000`, 1024)
	prefix := `{"schema":"ProductResult/v1","operation_kind":"publish","request_id":"` + id + `","domain_id":"` + id + `","operation_id":"` + id + `","request_identity":"` + id + `","replay_identity":"none","state_result":"success","effect_summary":"not-applicable","output_summary":"output-complete","evidence_ceiling":"canonical","reason_code":0,"payload":{"schema":"OutputPayload/v3","domain_id":"` + id + `","operation_id":"` + id + `","snapshot_id":"` + id + `","selection_digest":"` + id + `","domain_wide_warning":true,"entries":[`
	label := strings.Repeat(`\u0000`, 256)
	target := strings.Repeat(`\u0000`, 1020) + "0000"
	row := `{"coordinate_id":"` + id + `","target":{"origin":"current","entry_name":"` + label + `","destination_id":"` + label + `","service_contract_id":"` + label + `","canonical_target":"` + target + `"},"actions":[{"action":"create-with-value","projection_commitment":"` + id + `","attempt_id":"` + id + `","disposition":"acknowledged","reason_code":0,"remote_value_may_remain":true,"late_write_risk":true,"blocker_ids":["` + id + `","` + id + `"],"evidence":{"schema":"PublicationEvidence/v3","entry":"may-have-entered","class":"acknowledged","response_contract_digest":"` + id + `","normalized_status":65535,"safe_request_id":"` + escaped + `","safe_resource_id":"` + escaped + `","consumer_locator":"` + escaped + `"}}]}`
	wantPublication := len(prefix) + 1024*len(row) + 1023 + len("]}}")
	var compactPublication bytes.Buffer
	if err := json.Compact(&compactPublication, publicationBody); err != nil || compactPublication.Len() != wantPublication || bytes.Count(publicationBody, []byte(`\u0000`)) != 1024*(3*1024+3*256+1020) {
		t.Fatal("complete JSON labels, evidence, blockers or framing were truncated", compactPublication.Len(), wantPublication, err)
	}
	var record struct {
		Payload struct {
			Entries []struct {
				Coordinate string                  `json:"coordinate_id"`
				Target     publicationTargetRecord `json:"target"`
				Actions    []struct {
					Blockers []string `json:"blocker_ids"`
					Evidence struct {
						Request  string `json:"safe_request_id"`
						Resource string `json:"safe_resource_id"`
						Locator  string `json:"consumer_locator"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(publicationBody, &record); err != nil || len(record.Payload.Entries) != 1024 {
		t.Fatal("maximum bounded projection is not a complete closed JSON vector", err)
	}
	for i, target := range record.Payload.Entries {
		wantCoordinate := publication.Output.Entries[i].CoordinateID
		description := publication.Descriptions[i]
		if target.Target.EntryName == nil || *target.Target.EntryName != strings.Repeat("\x00", 256) || target.Target.DestinationID == nil || *target.Target.DestinationID != description.ServiceContractID || target.Target.ServiceContractID != description.ServiceContractID || target.Target.CanonicalTarget != description.CanonicalTarget || target.Coordinate != hex.EncodeToString(wantCoordinate[:]) || len(target.Actions) != 1 || len(target.Actions[0].Blockers) != 2 || target.Actions[0].Evidence.Request != strings.Repeat("\x00", 1024) || target.Actions[0].Evidence.Resource != strings.Repeat("\x00", 1024) || target.Actions[0].Evidence.Locator != strings.Repeat("\x00", 1024) {
			t.Fatal("complete result lost a coordinate, blocker or safe evidence byte", i)
		}
	}
	applyBody, err := RenderApplyJSON(result.Apply)
	if err != nil {
		t.Fatal(err)
	}
	var compactApply bytes.Buffer
	if err := json.Compact(&compactApply, applyBody); err != nil {
		t.Fatal(err)
	}
	compactCombined := `{"schema":"ApplyPublicationResult/v1","apply":` + compactApply.String() + `,"publication":{"stage":"evaluated","reason":null,"result":` + compactPublication.String() + `}}`
	var expectedReadable bytes.Buffer
	if err := json.Indent(&expectedReadable, []byte(compactCombined), "", "  "); err != nil {
		t.Fatal(err)
	}
	var count applyPublicationCountingWriter
	if err := WriteApplyPublicationJSON(&count, result); err != nil || count.bytes != uint64(expectedReadable.Len()+1) {
		t.Fatal("combined JSON did not count both complete stages and its exact readable framing", count.bytes, expectedReadable.Len()+1, err)
	}
	applyHuman, err := RenderApplyHuman(result.Apply)
	if err != nil {
		t.Fatal(err)
	}
	publicationHuman, err := RenderPublicationHuman(publication)
	if err != nil {
		t.Fatal(err)
	}
	count = applyPublicationCountingWriter{}
	applyLF := 0
	if len(applyHuman) == 0 || applyHuman[len(applyHuman)-1] != '\n' {
		applyLF = 1
	}
	if err := WriteApplyPublicationHuman(&count, result); err != nil || count.bytes != uint64(len("apply:\n")+len(applyHuman)+applyLF+51+len(publicationHuman)) {
		t.Fatal("combined human output lost complete stage bytes", count.bytes, err)
	}
}

// full_only: false
func TestApplyPublicationCompleteVectorOneOverRefusesBeforeDelivery(t *testing.T) {
	for _, condition := range []string{"safe-evidence-byte", "consumer-locator-byte", "consumer-locator-utf8", "blocker-count", "coordinate-count"} {
		t.Run(condition, func(t *testing.T) {
			result := applyPublicationMaximumFramingFixture()
			vector := result.Publication.Result.Output
			switch condition {
			case "safe-evidence-byte":
				vector.Entries[0].Actions[0].Evidence.SafeRequestID += "\x00"
			case "consumer-locator-byte":
				vector.Entries[0].Actions[0].Evidence.ConsumerLocator += "\x00"
			case "consumer-locator-utf8":
				vector.Entries[0].Actions[0].Evidence.ConsumerLocator = string([]byte{255})
			case "blocker-count":
				vector.Entries[0].Actions[0].BlockerIDs = append(vector.Entries[0].Actions[0].BlockerIDs, applyPublicationFramingID(3, 2049))
			case "coordinate-count":
				vector.Entries = append(vector.Entries, contract.PublicationTargetOutcome{CoordinateID: applyPublicationFramingID(1, 1025), Actions: []contract.PublicationOutcome{{Disposition: contract.PublicationNoOp}}})
			}
			for _, human := range []bool{false, true} {
				var output applyPublicationCountingWriter
				write := WriteApplyPublicationJSON
				if human {
					write = WriteApplyPublicationHuman
				}
				if err := write(&output, result); err == nil || output.bytes != 0 {
					t.Fatal("one-over body escaped pre-delivery validation", output.bytes, err)
				}
			}
		})
	}
}
