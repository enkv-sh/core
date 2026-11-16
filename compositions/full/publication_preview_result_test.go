package compositionfull

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func publicationPreviewResultFixture() ConfigurationComparisonResult {
	id := contract.ID{1}
	empty, destination, locator := "", "destination", "resource/latest"
	return ConfigurationComparisonResult{PublicComparisonResult: core.PublicComparisonResult{
		Context:     core.ReaderOperationContext{Operation: contract.ReaderCompareOperation, RequestID: id},
		StateResult: contract.ReaderSuccess,
		ComparisonPayload: contract.ComparisonPayload{
			Verdict: contract.ComparisonMatch, DiagnosticsComplete: true, EvidenceLimit: contract.ComparisonEvidenceLimit,
			Observation:          &contract.ComparisonObservation{DomainID: id, HeadRevisionID: id, SnapshotID: id},
			PublicationRequested: true,
			Publication: &contract.PublicationPreview{Complete: true, Entries: []contract.PublicationPreviewEntry{{
				ServiceContractID: "provider", PhysicalTarget: "account/target", Origin: "both", CoordinateID: id, BindingID: id,
				EntryName: &empty, DestinationID: &destination, TargetContractID: "target/v1", ConsumerLocator: &locator,
				Actions: []uint8{contract.PublicationWriteValue}, Basis: "secret-unchecked", Conditional: true,
				BlockerIDs: []contract.ID{{2}}, RemoteValueMayRemain: true, LateWriteRisk: true,
			}}},
		},
	}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
}

// full_only: false
func TestPublicationPreviewHumanPreservesActionsAndWarnings(t *testing.T) {
	r := publicationPreviewResultFixture()
	row := &r.Publication.Entries[0]
	row.EntryName, row.DestinationID = nil, nil
	row.Origin, row.Basis = "observed", "retained-deletion"
	row.Actions = []uint8{contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot}
	body, err := RenderComparisonHuman(r)
	if err != nil || ComparisonExitCode(r) != 0 {
		t.Fatal("retained preview changed declaration comparison", err)
	}
	for _, want := range []string{"Public configuration: unchanged.", "Publication preview: complete; 1 target.", `Target "provider" / "account/target"`, "retained-deletion", "delete-owned, delete-reserved-slot", "conditional", "Blocker attempts:\n  02" + strings.Repeat("00", 31), "Remote value may remain.", "A late write may still arrive.", "No changes were applied or published."} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("missing preview fact %q in %s", want, body)
		}
	}
	if bytes.Contains(body, []byte(`publication: {`)) || bytes.Contains(body, []byte(`"actions":`)) {
		t.Fatal("human preview retained its JSON dump", string(body))
	}
}

// full_only: false
func TestPublicationPreviewJSONHasCompleteClosedRows(t *testing.T) {
	result := publicationPreviewResultFixture()
	body, err := RenderComparisonJSON(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Payload struct {
			Publication json.RawMessage `json:"publication"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	// The wire literal is independent of the renderer and its row encoding.
	id, blocker := "01"+strings.Repeat("00", 31), "02"+strings.Repeat("00", 31)
	want := `{"schema":"PublicationPreview/v2","complete":true,"reason_code":0,"domain_wide_warning":false,"entries":[{"service_contract_id":"provider","physical_target":"account/target","origin":"both","coordinate_id":"` + id + `","binding_id":"` + id + `","entry_name":"","destination_id":"destination","target_contract_id":"target/v1","consumer_locator":"resource/latest","actions":["write-value"],"basis":"secret-unchecked","conditional":true,"reason_code":0,"blocker_ids":["` + blocker + `"],"remote_value_may_remain":true,"late_write_risk":true}]}`
	var compact bytes.Buffer
	if err := json.Compact(&compact, decoded.Payload.Publication); err != nil || !bytes.Equal(compact.Bytes(), []byte(want)) {
		t.Fatalf("publication row differs\ngot: %s\nwant: %s", decoded.Payload.Publication, want)
	}
	result.Publication.Entries[0].Origin = "proposed"
	result.Publication.Entries[0].CoordinateID, result.Publication.Entries[0].BindingID = contract.ID{}, contract.ID{}
	result.Publication.Entries[0].EntryName, result.Publication.Entries[0].DestinationID, result.Publication.Entries[0].ConsumerLocator = nil, nil, nil
	result.Publication.Entries[0].BlockerIDs = nil
	result.Publication.Entries[0].Actions = nil
	body, err = RenderComparisonJSON(result)
	compact.Reset()
	if err != nil || json.Compact(&compact, body) != nil || !bytes.Contains(compact.Bytes(), []byte(`"coordinate_id":null,"binding_id":null,"entry_name":null,"destination_id":null`)) || !bytes.Contains(compact.Bytes(), []byte(`"consumer_locator":null,"actions":[]`)) || !bytes.Contains(compact.Bytes(), []byte(`"blocker_ids":[]`)) {
		t.Fatal("absent facts or no-action arrays changed meaning", err, string(body))
	}
	if contract.MaxPublicationPreviewJSONBytes != 2048*32768+2048*67+65536 || contract.MaxPublicationPlanningResultJSONBytes != contract.MaxComparisonResultJSONBytes+contract.MaxPublicationPreviewJSONBytes {
		t.Fatal("publication byte accounts differ from independent derivation")
	}
}

// full_only: false
func TestPublicationPreviewJSONRejectsInvalidRows(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*ConfigurationComparisonResult)
	}{
		{"absent-requested-preview", func(r *ConfigurationComparisonResult) { r.Publication = nil }},
		{"unrequested-preview", func(r *ConfigurationComparisonResult) { r.PublicationRequested = false }},
		{"unknown-reason", func(r *ConfigurationComparisonResult) { r.Publication.ReasonCode = 20 }},
		{"unknown-row-reason", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].ReasonCode = 20 }},
		{"unknown-basis", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].Basis = "raw-error-sentinel" }},
		{"unknown-origin", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].Origin = "future" }},
		{"invalid-utf8", func(r *ConfigurationComparisonResult) {
			r.Publication.Entries[0].ServiceContractID = string([]byte{255})
		}},
		{"service-contract-over-limit", func(r *ConfigurationComparisonResult) {
			r.Publication.Entries[0].ServiceContractID = strings.Repeat("p", 257)
		}},
		{"target-over-limit", func(r *ConfigurationComparisonResult) {
			r.Publication.Entries[0].PhysicalTarget = strings.Repeat("t", 1025)
		}},
		{"target-contract-over-limit", func(r *ConfigurationComparisonResult) {
			r.Publication.Entries[0].TargetContractID = strings.Repeat("v", 257)
		}},
		{"unknown-action", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].Actions = []uint8{7} }},
		{"too-many-actions", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].Actions = []uint8{1, 2, 3, 4} }},
		{"zero-blocker", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].BlockerIDs = []contract.ID{{}} }},
		{"duplicate-blocker", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].BlockerIDs = []contract.ID{{2}, {2}} }},
		{"unordered-blockers", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].BlockerIDs = []contract.ID{{3}, {2}} }},
		{"invented-proposed-coordinate", func(r *ConfigurationComparisonResult) { r.Publication.Entries[0].Origin = "proposed" }},
		{"duplicate-coordinate", func(r *ConfigurationComparisonResult) {
			r.Publication.Entries = append(r.Publication.Entries, r.Publication.Entries[0])
		}},
		{"shared-blocker-owner", func(r *ConfigurationComparisonResult) {
			row := r.Publication.Entries[0]
			row.PhysicalTarget, row.CoordinateID = "other/target", contract.ID{3}
			r.Publication.Entries = append(r.Publication.Entries, row)
		}},
		{"too-many-rows", func(r *ConfigurationComparisonResult) {
			r.Publication.Entries = make([]contract.PublicationPreviewEntry, 2049)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := publicationPreviewResultFixture()
			test.mutate(&result)
			for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
				if body, err := render(result); err != ErrReaderResult || body != nil {
					t.Fatal("invalid publication facts returned partial or valid output", err)
				}
			}
			if ComparisonExitCode(result) != 2 {
				t.Fatal("invalid publication facts received a pass")
			}
		})
	}
}

// full_only: false
func TestPublicationPreviewJSONAdmitsCompleteUnionAndBlockerBounds(t *testing.T) {
	result := publicationPreviewResultFixture()
	prototype := result.Publication.Entries[0]
	result.Publication.Entries = make([]contract.PublicationPreviewEntry, 2048)
	for i := range result.Publication.Entries {
		row := prototype
		row.PhysicalTarget = fmt.Sprintf("target/%04d", i)
		row.CoordinateID = contract.ID{1, byte(i >> 8), byte(i)}
		row.BlockerIDs = []contract.ID{{2, byte(i >> 8), byte(i)}}
		result.Publication.Entries[i] = row
	}
	body, err := RenderComparisonJSON(result)
	if err != nil || !json.Valid(body) {
		t.Fatal("complete bounded union refused", err)
	}
	var decoded struct {
		Payload struct {
			Publication struct {
				Complete bool
				Entries  []struct {
					BlockerIDs []string `json:"blocker_ids"`
				}
			}
		}
	}
	if err := json.Unmarshal(body, &decoded); err != nil || !decoded.Payload.Publication.Complete || len(decoded.Payload.Publication.Entries) != 2048 {
		t.Fatal("bounded union was truncated", err)
	}
	for i, row := range decoded.Payload.Publication.Entries {
		if len(row.BlockerIDs) != 1 || row.BlockerIDs[0] != fmt.Sprintf("02%02x%02x", i>>8, i&255)+strings.Repeat("00", 29) {
			t.Fatal("blocker ownership changed", i)
		}
	}
	human, err := RenderComparisonHuman(result)
	if err != nil || bytes.Count(human, []byte("Target \"provider\" / ")) != 2048 {
		t.Fatal("complete human target union refused or truncated", err)
	}
	for i := range result.Publication.Entries {
		target := fmt.Sprintf("Target \"provider\" / \"target/%04d\"\n", i)
		blocker := "  Blocker attempts:\n  " + fmt.Sprintf("02%02x%02x", i>>8, i&255) + strings.Repeat("00", 29) + "\n"
		if !bytes.Contains(human, []byte(target)) || !bytes.Contains(human, []byte(blocker)) {
			t.Fatal("human target or exact blocker missing", i)
		}
	}
	result.Publication.Entries[2047].BlockerIDs = append(result.Publication.Entries[2047].BlockerIDs, contract.ID{3})
	for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
		if body, err := render(result); err != ErrReaderResult || body != nil {
			t.Fatal("one-over blocker union rendered", err)
		}
	}
	result.Publication.Entries[2047].BlockerIDs = result.Publication.Entries[2047].BlockerIDs[:1]
	result.Publication.Entries = append(result.Publication.Entries, prototype)
	for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
		if body, err := render(result); err != ErrReaderResult || body != nil {
			t.Fatal("one-over target union rendered", err)
		}
	}
}
