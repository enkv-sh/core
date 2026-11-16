package compositionfull

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationResultRequiresTargetDescriptions(t *testing.T) {
	r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
	r.Descriptions = nil
	for _, render := range []func(core.PublicPublicationResult) ([]byte, error){RenderPublicationHuman, RenderPublicationJSON} {
		if body, err := render(r); err == nil || len(body) != 0 {
			t.Fatal("publication without its admitted target description reached output")
		}
	}
	combined := core.PublicApplyPublicationResult{Apply: suppliedApplyNoopResultFixture(), Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &r}}
	var out bytes.Buffer
	if err := WriteApplyPublicationHuman(&out, combined); err == nil || out.Len() != 0 {
		t.Fatal("combined result delivered an incomplete publication target")
	}
}

// full_only: false
func TestPublicationDescriptionsKeepCapturedLabelsAndEvidenceLimits(t *testing.T) {
	for _, kind := range []string{"current", "empty-current-name", "retained"} {
		retained := kind == "retained"
		r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
		r.Output.Entries[0].Actions[0].Evidence.SafeResourceID = ""
		want := `{"origin":"current","entry_name":"entry","destination_id":"destination","service_contract_id":"service","canonical_target":"account/entry"}`
		if kind == "empty-current-name" {
			empty := ""
			r.Descriptions[0].EntryName = &empty
			want = `{"origin":"current","entry_name":"","destination_id":"destination","service_contract_id":"service","canonical_target":"account/entry"}`
		}
		if retained {
			r.Descriptions[0].Origin, r.Descriptions[0].EntryName, r.Descriptions[0].DestinationID = core.PublicationTargetRetainedDeletion, nil, nil
			r.Output.Entries[0].Actions[0].Action = contract.PublicationDeleteOwned
			want = `{"origin":"retained-deletion","entry_name":null,"destination_id":null,"service_contract_id":"service","canonical_target":"account/entry"}`
		}
		body, err := RenderPublicationJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Payload struct {
				Schema  string
				Entries []struct{ Target json.RawMessage }
			}
		}
		if err := json.Unmarshal(body, &decoded); err != nil || decoded.Payload.Schema != "OutputPayload/v3" || len(decoded.Payload.Entries) != 1 {
			t.Fatal("complete description projection missing", err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, decoded.Payload.Entries[0].Target); err != nil || compact.String() != want {
			t.Fatal("description changed the available target facts", err, compact.String())
		}
		human, err := RenderPublicationHuman(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, fact := range []string{`Service: "service"`, `Target: "account/entry"`, "Coordinate: " + readerID(r.Descriptions[0].CoordinateID), "Acknowledgement does not prove remote currentness, absence, invalidation or ordering."} {
			if !bytes.Contains(human, []byte(fact)) {
				t.Fatal("human publication lost target or evidence ceiling", fact, string(human))
			}
		}
		if retained {
			if !bytes.Contains(human, []byte("Retained deletion target")) || bytes.Contains(human, []byte("Entry:")) || bytes.Contains(human, []byte("Destination:")) {
				t.Fatal("retained deletion invented a current label", string(human))
			}
		} else if !bytes.Contains(human, []byte("Entry: "+strconv.Quote(*r.Descriptions[0].EntryName))) || !bytes.Contains(human, []byte(`Destination: "destination"`)) {
			t.Fatal("acknowledgement without resource lost its captured labels", string(human))
		}
	}
}

// full_only: false
func TestPublicationDescriptionsRejectInvalidRelationsBeforeEitherOutput(t *testing.T) {
	for _, condition := range []string{"missing", "extra", "duplicate", "coordinate", "recomputed-coordinate", "origin", "name", "destination", "empty-destination", "retained-name", "long-name", "long-target", "invalid-text", "unowned-capacity", "absent-output"} {
		t.Run(condition, func(t *testing.T) {
			r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
			switch condition {
			case "missing":
				r.Descriptions = nil
			case "extra":
				r.Descriptions = append(r.Descriptions, r.Descriptions[0])
			case "duplicate":
				r.Descriptions = append(r.Descriptions, r.Descriptions[0])
				r.Output.Entries = append(r.Output.Entries, r.Output.Entries[0])
			case "coordinate":
				r.Descriptions[0].CoordinateID = contract.ID{99}
			case "recomputed-coordinate":
				r.Descriptions[0].CanonicalTarget = "account/different"
			case "origin":
				r.Descriptions[0].Origin = 3
			case "name":
				r.Descriptions[0].EntryName = nil
			case "destination":
				r.Descriptions[0].DestinationID = nil
			case "empty-destination":
				empty := ""
				r.Descriptions[0].DestinationID = &empty
			case "retained-name":
				r.Descriptions[0].Origin = core.PublicationTargetRetainedDeletion
			case "long-name":
				name := strings.Repeat("x", 257)
				r.Descriptions[0].EntryName = &name
			case "long-target":
				r.Descriptions[0].CanonicalTarget = strings.Repeat("x", 1025)
			case "invalid-text":
				r.Descriptions[0].ServiceContractID = string([]byte{255})
			case "unowned-capacity":
				rows := make([]core.PublicationTargetDescription, 1, 2)
				copy(rows, r.Descriptions)
				r.Descriptions = rows
			case "absent-output":
				r.Output, r.Summary, r.Result = nil, 0, core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}
			}
			for _, render := range []func(core.PublicPublicationResult) ([]byte, error){RenderPublicationHuman, RenderPublicationJSON} {
				if body, err := render(r); err == nil || len(body) != 0 {
					t.Fatal("invalid target relation reached output")
				}
			}
			combined := core.PublicApplyPublicationResult{Apply: suppliedApplyNoopResultFixture(), Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &r}}
			for _, write := range []func(*bytes.Buffer, core.PublicApplyPublicationResult) error{
				func(out *bytes.Buffer, result core.PublicApplyPublicationResult) error {
					return WriteApplyPublicationHuman(out, result)
				},
				func(out *bytes.Buffer, result core.PublicApplyPublicationResult) error {
					return WriteApplyPublicationJSON(out, result)
				},
			} {
				var out bytes.Buffer
				if err := write(&out, combined); err == nil || out.Len() != 0 {
					t.Fatal("combined result delivered bytes before target validation")
				}
			}
		})
	}
}
