package compositionfull

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func generatedPlanningResultFixture() ConfigurationComparisonResult {
	id := func(value byte) contract.ID { var out contract.ID; out[0] = value; return out }
	row := contract.GeneratedPlanningEntry{Name: "value/\n雪", CurrentIncarnation: id(1), CurrentGeneration: id(2), RetiringDutyID: id(3), RetiringIncarnation: id(4),
		RetiringResource: id(5), RetiringOriginalOperation: id(6), RetiringOriginalAttempt: id(7), ActiveOperation: id(8), CurrentEpoch: 3, RequestedEpoch: 4, RetiringEpoch: 2,
		ChangedFields: contract.GeneratedPlanningEpoch, Blockers: contract.GeneratedPlanningRetiring | contract.GeneratedPlanningActiveOperation,
		Action: contract.GeneratedPlanningRotate, Retirement: contract.GeneratedPlanningRetireAfterSuccessor,
		CurrentSource: contract.Generated, CurrentLifecycleMode: contract.GeneratorLifecycleManaged, ProposedSource: contract.Generated, ProposedLifecycleMode: contract.GeneratorLifecycleManaged, CurrentClass: contract.Secret, ProposedClass: contract.Secret,
		CurrentPolicy: contract.GeneratedRetirementManual, ProposedPolicy: contract.GeneratedRetirementManual}
	return ConfigurationComparisonResult{PublicComparisonResult: core.PublicComparisonResult{Context: core.ReaderOperationContext{Operation: contract.ReaderCompareOperation}, StateResult: contract.ReaderSuccess,
		ComparisonPayload: contract.ComparisonPayload{Observation: &contract.ComparisonObservation{DomainID: id(9), HeadRevisionID: id(10), SnapshotID: id(11)},
			Verdict: contract.ComparisonMismatch, DiagnosticsComplete: true, EvidenceLimit: contract.ComparisonEvidenceLimit,
			Changes:          []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: row.Name}, Path: []contract.DiagnosticField{contract.FieldGenerated, contract.FieldEpoch}, Action: contract.ComparisonChanged, Before: proposedSide(contract.ComparisonUint(3)), After: proposedSide(contract.ComparisonUint(4))}},
			GeneratedEntries: []contract.GeneratedPlanningEntry{row}}}, InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
}

// full_only: false
func TestGeneratedPlanningRenderersPreserveExactFacts(t *testing.T) {
	public := generatedPlanningResultFixture()
	private := configurationPlanningResult(public)
	private.PreAdmission = nil
	private.PrivateComplete = true
	var generated json.RawMessage
	for _, item := range []struct {
		name   string
		render func() ([]byte, error)
		human  bool
	}{
		{"public-json", func() ([]byte, error) { return RenderComparisonJSON(public) }, false},
		{"private-json", func() ([]byte, error) { return RenderPlanningJSON(private) }, false},
		{"public-human", func() ([]byte, error) { return RenderComparisonHuman(public) }, true},
		{"private-human", func() ([]byte, error) { return RenderPlanningHuman(private) }, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			body, err := item.render()
			if err != nil || len(body) != cap(body) {
				t.Fatal("complete generated rendering refused", err)
			}
			var rows []json.RawMessage
			if item.human {
				for _, want := range []string{`Generated entry "value/\n雪": rotate`, "Current: generated secret; epoch 3; lifecycle managed; retirement manual", "Requested: generated secret; epoch 4; lifecycle managed; retirement manual", "Changed public fields: epoch", "Retirement consequence: after-successor-selection", "Observed blockers: retiring-generation-present, active-operation-present", "Future content: unavailable; public secret content: unchecked.", "Current incarnation: 01" + strings.Repeat("00", 31), "Current generation: 02" + strings.Repeat("00", 31), "Retiring duty: 03" + strings.Repeat("00", 31), "Retiring incarnation: 04" + strings.Repeat("00", 31), "Retiring resource: 05" + strings.Repeat("00", 31), "Retiring original operation: 06" + strings.Repeat("00", 31), "Retiring original attempt: 07" + strings.Repeat("00", 31), "Active operation: 08" + strings.Repeat("00", 31), "Retiring epoch: 2; generation: unavailable"} {
					if !bytes.Contains(body, []byte(want)) {
						t.Fatalf("complete human intent fact missing %q in %s", want, body)
					}
				}
				if bytes.Contains(body, []byte("generated_entry: {")) || bytes.Contains(body, []byte("\n雪")) {
					t.Fatal("human intent is structural or unescaped", string(body))
				}
				return
			} else {
				var result struct {
					Payload struct {
						Entries []json.RawMessage `json:"generated_entries"`
					} `json:"payload"`
				}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatal(err)
				}
				rows = result.Payload.Entries
			}
			if len(rows) != 1 {
				t.Fatal("generated row missing", len(rows))
			}
			var compact bytes.Buffer
			if err := json.Compact(&compact, rows[0]); err != nil {
				t.Fatal("generated row JSON is malformed", err)
			}
			if generated == nil {
				generated = bytes.Clone(compact.Bytes())
			} else if !bytes.Equal(generated, compact.Bytes()) {
				t.Fatal("public and private/human facts differ")
			}
			var row map[string]any
			if err := json.Unmarshal(rows[0], &row); err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]any{"name": "value/\n雪", "requested_action": "rotate", "current_epoch": float64(3), "requested_epoch": float64(4), "retiring_epoch": float64(2),
				"retirement_consequence": "after-successor-selection", "current_lifecycle_mode": "managed", "requested_lifecycle_mode": "managed", "retiring_generation_id": nil, "future_content": "unavailable", "public_secret_content": "unchecked",
				"current_incarnation_id": "01" + strings.Repeat("00", 31), "current_generation_id": "02" + strings.Repeat("00", 31), "retiring_duty_id": "03" + strings.Repeat("00", 31),
				"retiring_incarnation_id": "04" + strings.Repeat("00", 31), "retiring_resource_id": "05" + strings.Repeat("00", 31), "retiring_original_operation_id": "06" + strings.Repeat("00", 31),
				"retiring_original_attempt_id": "07" + strings.Repeat("00", 31), "active_operation_id": "08" + strings.Repeat("00", 31)} {
				if got, present := row[key]; !present || !reflect.DeepEqual(got, want) {
					t.Fatal("exact intent fact differs", key, got)
				}
			}
			if !reflect.DeepEqual(row["changed_public_fields"], []any{"epoch"}) || !reflect.DeepEqual(row["observed_blockers"], []any{"retiring-generation-present", "active-operation-present"}) {
				t.Fatal("closed changes or observed blockers differ")
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanningRenderersRejectContradictoryRows(t *testing.T) {
	for _, condition := range []string{"action", "retirement", "current-generation", "current-lifecycle", "requested-lifecycle", "old-target", "active-owner", "blocker", "changed-mask", "epoch", "duplicate", "count", "current-side-count", "proposed-side-count", "observation"} {
		t.Run(condition, func(t *testing.T) {
			public := generatedPlanningResultFixture()
			row := &public.GeneratedEntries[0]
			switch condition {
			case "action":
				row.Action = contract.GeneratedPlanningUnchanged
			case "retirement":
				row.Retirement = contract.GeneratedPlanningNoRetirement
			case "current-generation":
				row.CurrentGeneration = contract.ID{}
			case "current-lifecycle":
				row.CurrentLifecycleMode = 0
			case "requested-lifecycle":
				row.ProposedLifecycleMode = 0
			case "old-target":
				row.RetiringIncarnation = contract.ID{}
			case "active-owner":
				row.ActiveOperation = contract.ID{}
			case "blocker":
				row.Blockers |= 1 << 15
			case "changed-mask":
				row.ChangedFields |= 1 << 15
			case "epoch":
				row.RequestedEpoch = 2
			case "duplicate":
				public.GeneratedEntries = append(public.GeneratedEntries, *row)
			case "count":
				public.GeneratedEntries = make([]contract.GeneratedPlanningEntry, 257)
			case "current-side-count", "proposed-side-count":
				value := *row
				value.ChangedFields = contract.GeneratedPlanningPresence
				if condition == "current-side-count" {
					value.Action, value.Retirement = contract.GeneratedPlanningRemoval, contract.GeneratedPlanningRetireAfterRemoval
					value.ProposedSource, value.ProposedClass, value.ProposedPolicy, value.RequestedEpoch, value.ProposedLifecycleMode = 0, 0, 0, 0, 0
				} else {
					value.Action, value.Retirement = contract.GeneratedPlanningCreate, contract.GeneratedPlanningNoRetirement
					value.CurrentSource, value.CurrentClass, value.CurrentPolicy, value.CurrentEpoch, value.RequestedEpoch, value.CurrentLifecycleMode = 0, 0, 0, 0, 0, 0
					value.CurrentIncarnation, value.CurrentGeneration = contract.ID{}, contract.ID{}
				}
				public.GeneratedEntries = make([]contract.GeneratedPlanningEntry, 129)
				for at := range public.GeneratedEntries {
					public.GeneratedEntries[at] = value
					public.GeneratedEntries[at].Name = fmt.Sprintf("n%03d", at)
				}
			case "observation":
				public.Observation = nil
			}
			private := configurationPlanningResult(public)
			private.PreAdmission, private.PrivateComplete = nil, true
			if ComparisonExitCode(public) != 2 || PlanningExitCode(private) != 2 {
				t.Fatal("contradictory generated rows received a success exit")
			}
			for _, render := range []func() ([]byte, error){func() ([]byte, error) { return RenderComparisonJSON(public) }, func() ([]byte, error) { return RenderComparisonHuman(public) }, func() ([]byte, error) { return RenderPlanningJSON(private) }, func() ([]byte, error) { return RenderPlanningHuman(private) }} {
				if body, err := render(); err != ErrReaderResult || body != nil {
					t.Fatal("contradictory generated result returned output", err)
				}
			}
		})
	}
}

// full_only: false
func TestGeneratedPlanningMaximumRowEncodingFitsAccount(t *testing.T) {
	public := generatedPlanningResultFixture()
	row := &public.GeneratedEntries[0]
	row.Name = strings.Repeat("\x00", 256)
	row.CurrentEpoch = math.MaxUint64
	row.RequestedEpoch = math.MaxUint64 - 1
	row.RetiringEpoch = math.MaxUint64
	row.ProposedClass = contract.Plain
	row.ProposedPolicy = contract.GeneratedRetirementAuto
	row.ChangedFields = contract.GeneratedPlanningClass | contract.GeneratedPlanningMemberships | contract.GeneratedPlanningEpoch | contract.GeneratedPlanningConfigContract | contract.GeneratedPlanningResourceContract | contract.GeneratedPlanningLifecycle | contract.GeneratedPlanningContentIntent | contract.GeneratedPlanningRetirementPolicy | contract.GeneratedPlanningCompletion
	row.Blockers |= contract.GeneratedPlanningStaleEpoch | contract.GeneratedPlanningClassConflict
	for _, human := range []bool{false, true} {
		writer := readerResultWriter{}
		renderGeneratedPlanningEntries(&writer, public.GeneratedEntries, human)
		if writer.failed || writer.at > 4096+32 {
			t.Fatal("maximum escaped row exceeds independently reserved framing", writer.at)
		}
	}
	const diagnostics = 160060
	const generated = 2*128*4096 + 32
	const compact = diagnostics*4096 + 65536 + generated
	// Readable complete changes add both public images' escaped values and
	// the bounded diagnostic indentation/subject expansion to the compact base.
	const readable = compact + 12*121158832 + diagnostics*(512+1024)
	if generated != 1048608 || compact != 656719904 || readable != 2356478048 {
		t.Fatal("independent complete generated/readable account changed")
	}
	if contract.MaxGeneratedPlanningEntries != 2*128 || contract.MaxGeneratedPlanningRowJSONBytes != 4096 || contract.MaxComparisonResultJSONBytes != readable {
		t.Fatal("complete generated result allowance differs")
	}
}
