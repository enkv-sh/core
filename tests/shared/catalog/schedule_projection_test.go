package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

type expectedScheduleCell struct {
	mode, provider, recovery         string
	scheduled, excluded, unsupported int
	digest                           string
}

type scheduleProjection struct {
	Name          string   `json:"scenario"`
	Status        string   `json:"status"`
	Fixture       Shape    `json:"fixture"`
	Roles         []string `json:"roles,omitempty"`
	Process       []Step   `json:"process,omitempty"`
	Writer        []Step   `json:"writer,omitempty"`
	Before        []Step   `json:"fresh_before,omitempty"`
	AfterRole     string   `json:"fresh_after_role,omitempty"`
	AfterExpected string   `json:"fresh_after_expected,omitempty"`
	AfterModes    []string `json:"fresh_after_modes,omitempty"`
	Measurements  []bool   `json:"measurements,omitempty"`
}

func fixedScheduleProjection(t *testing.T, cell expectedScheduleCell) (string, int, int, int) {
	t.Helper()
	rows := make([]scheduleProjection, 0, len(scenarios))
	scheduled, excluded, unsupported := 0, 0, 0
	var publicRows []scheduleProjection
	for _, definition := range HistoricalDefinitions() {
		row := scheduleProjection{Name: definition.Name, Fixture: definition.Fixture}
		switch {
		case !slices.Contains(definition.Modes, cell.mode) || !slices.Contains(definition.Providers, cell.provider):
			row.Status = "unsupported"
			unsupported++
		case len(definition.RolesForRecovery(cell.recovery)) == 0:
			row.Status = "excluded"
			excluded++
		default:
			row.Status = "scheduled"
			scheduled++
			execution, known := HistoricalExecutionFor(definition.Name, cell.mode)
			if !known {
				t.Fatalf("execution facts unavailable for %s/%s", definition.Name, cell.mode)
			}
			row.Roles = definition.RolesForRecovery(cell.recovery)
			for _, phase := range execution.Writer {
				row.Writer = append(row.Writer, phase.Step)
				row.Measurements = append(row.Measurements, phase.MeasurementsExpected)
			}
			for _, child := range execution.FreshBefore {
				for range child.Count {
					row.Before = append(row.Before, child.Step)
					row.Measurements = append(row.Measurements, child.MeasurementsExpected)
				}
			}
			for _, phase := range execution.Process {
				row.Process = append(row.Process, phase.Step)
			}
			if len(execution.FreshAfter) > 0 {
				row.AfterRole = execution.FreshAfter[0].Role
				row.AfterExpected = execution.FreshAfter[0].Step.Expected
				if cell.mode == "hermetic" {
					for _, child := range execution.FreshAfter {
						row.AfterModes = append(row.AfterModes, child.Step.RecoveryMode)
					}
				} else {
					row.AfterModes = []string{cell.recovery}
				}
			}
			for _, child := range execution.FreshAfter {
				for range child.Count {
					row.Measurements = append(row.Measurements, child.MeasurementsExpected)
				}
			}
		}
		if execution, ok := definition.Executions["live"]; ok && execution.Family == FamilyAuthorityOperator {
			if want := expectedAuthorityOperatorScheduleRow(cell, definition.Name); !reflect.DeepEqual(row, want) {
				t.Fatalf("administrative schedule projection differs: got %#v want %#v", row, want)
			}
		}
		if execution, ok := definition.Executions["live"]; ok && execution.Family == FamilyPublicConfiguration {
			publicRows = append(publicRows, row)
			switch row.Status {
			case "scheduled":
				scheduled--
			case "excluded":
				excluded--
			case "unsupported":
				unsupported--
			}
		} else {
			rows = append(rows, row)
		}
	}
	// The legacy checksum predates the public family. Every public row has a
	// separate exact oracle, including unsupported and excluded cells.
	if want := expectedPublicScheduleRows(cell); !reflect.DeepEqual(publicRows, want) {
		t.Fatalf("public schedule projection differs: got %#v want %#v", publicRows, want)
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), scheduled, excluded, unsupported
}

func expectedAuthorityOperatorScheduleRow(cell expectedScheduleCell, name string) scheduleProjection {
	row := scheduleProjection{Name: name, Fixture: Shape{Members: 1, SmallValueCount: 1, SmallValueBytes: 1, RawValueBytes: 1, ValueSeed: "member_index_modulo_256"}}
	transition, verification := "stale-plan-refused-fresh-plan-selected-history-discovered", "later-list-and-original-receipt-after-ordinary-progress"
	mode := "both"
	switch name {
	case "operator.replace-authority-then-abandon-through-cli":
		transition, mode = "recovery-signing-replacement-then-reviewed-abandonment", "enabled"
	case "operator.disabled-recovery-refuses-authority-replacement-through-cli":
		transition, verification, mode = "disabled-recovery-replacement-refused-without-private-work", "disabled-recovery-preserves-selected-work", "disabled"
	}
	switch {
	case cell.mode != "live" || cell.provider != "aws" && cell.provider != "gcp":
		row.Status = "unsupported"
	case mode != "both" && mode != cell.recovery:
		row.Status = "excluded"
	default:
		row.Status = "scheduled"
		row.Roles = []string{"authority", "reader", "cleanup", "recipient-consumer"}
		if mode == "enabled" {
			row.Roles = append(row.Roles, "successor")
		}
		row.Writer = []Step{{Name: "setup", Role: "authority", Expected: "selected-generated-work-ready"}, {Name: "transition", Role: "authority", Expected: transition}, {Name: "verification", Role: "authority", Expected: verification}}
		row.AfterRole, row.AfterExpected = "recipient-consumer", "success"
		row.AfterModes = []string{cell.recovery}
		row.Measurements = []bool{true, true, true, true}
	}
	return row
}

// The live publication inventory adds nine supported cases per cloud and two
// cases for the other cloud. All eleven are unsupported in memory. The fixed
// role, scope and phase assertions are in the publication catalog tests.
// Frozen baseline JSON preimages matched the prior hashes. Independent Python
// JSON and SHA-256 replace only the three reviewed administrative names and
// phase facts; every other row, status, field and ordering remains unchanged.
// full_only: false
func TestExpectedScheduleProjections(t *testing.T) {
	for _, cell := range []expectedScheduleCell{
		{mode: "hermetic", provider: "memory", recovery: "both", scheduled: 134, unsupported: 14, digest: "c06c98c886a09ff1420de7394611121cfa52651c781c93648e50d8e0f13bc701"},
		{mode: "live", provider: "gcp", recovery: "enabled", scheduled: 118, excluded: 1, unsupported: 29, digest: "2769bfcc5d56f45077d6271eeeded99e4c363359bb63e7de06926f1730a72cce"},
		{mode: "live", provider: "gcp", recovery: "disabled", scheduled: 81, excluded: 38, unsupported: 29, digest: "99344d1a67393bcca10b9beaaaa94d6dad2c1fa9be0798690adad806aa7a8df8"},
		{mode: "live", provider: "aws", recovery: "enabled", scheduled: 116, excluded: 1, unsupported: 31, digest: "088529519ad5a55a0cfd2d1cb6ba02e22bfeddf8e7e287d686b1593924304d30"},
		{mode: "live", provider: "aws", recovery: "disabled", scheduled: 79, excluded: 38, unsupported: 31, digest: "d9c1a29f9a605317a4a33c23abf84036a9b56abcf9288ffd8d561fd1073da533"},
	} {
		name := fmt.Sprintf("%s/%s/%s", cell.mode, cell.provider, cell.recovery)
		t.Run(name, func(t *testing.T) {
			digest, scheduled, excluded, unsupported := fixedScheduleProjection(t, cell)
			if digest != cell.digest || scheduled != cell.scheduled || excluded != cell.excluded || unsupported != cell.unsupported {
				t.Fatalf("schedule projection = scheduled:%d excluded:%d unsupported:%d sha256:%s", scheduled, excluded, unsupported, digest)
			}
		})
	}
}

// These literals follow the public scenario contract, not the catalog resolver.
// They cover every public row and field separately from the legacy checksum.
// The 19 replacement declarations fix the approved 54-cell inventory: Authority
// changes permit disabled Recovery, all other SDK cases require enabled Recovery,
// and the four operator contexts use only disabled Recovery.
func expectedPublicScheduleRows(cell expectedScheduleCell) []scheduleProjection {
	cases := []struct {
		name         string
		roles        []string
		enabledOnly  bool
		disabledOnly bool
	}{
		{"plugin-contracts", []string{"authority", "apply", "reader", "consumer", "cleanup"}, true, false},
		{"prepare-complete-loss", []string{"authority", "apply", "reader", "consumer", "cleanup"}, false, false},
		{"inspection-receipts", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"manifest", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"materialization", []string{"authority", "apply", "reader", "recipient-consumer", "cleanup"}, true, false},
		{"capacity-gc", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"output-standalone", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"output-combined", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"generated-manual-lifecycle", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"generated-auto-rotation", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"credential-discovery", []string{"authority", "apply", "reader", "consumer", "cleanup"}, false, false},
		{"standard-discovery", []string{"authority", "apply", "reader", "consumer", "cleanup"}, false, false},
		{"empty-initialization", []string{"authority", "reader", "cleanup"}, false, false},
		{"required-public-denied", []string{"authority", "denied-public", "reader", "cleanup"}, false, false},
		{"normal-signing-denied", []string{"authority", "denied-normal-signing", "reader", "cleanup"}, false, false},
		{"authority-private-denied", []string{"authority", "denied-authority-private", "reader", "cleanup"}, false, false},
		{"recovery-signing-denied", []string{"authority", "denied-recovery-signing", "reader", "cleanup"}, true, false},
		{"recovery-private-denied", []string{"authority", "denied-recovery-private", "reader", "cleanup"}, true, false},
		{"portable-validation", []string{"authority", "apply", "reader", "consumer", "successor", "cleanup"}, false, false},
		{"fresh-secret-apply", []string{"authority", "apply", "reader", "consumer", "recovery", "cleanup"}, false, false},
		{"retained-input-access", []string{"authority", "apply", "reader", "consumer", "recipient-consumer", "excluded-consumer", "recovery", "cleanup"}, false, false},
		{"readonly-unknown-outcomes", []string{"authority", "apply", "reader", "consumer", "recovery", "cleanup"}, false, false},
		{"recipient-lifecycle", []string{"authority", "apply", "proposer", "reader", "consumer", "recipient-consumer", "excluded-consumer", "recovery", "cleanup"}, false, false},
		{"keys-replace-authority-signing-by-authority", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"keys-replace-authority-signing-by-recovery", []string{"authority", "apply", "reader", "cleanup", "successor"}, true, false},
		{"keys-replace-authority-encryption-by-authority", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"keys-replace-authority-encryption-by-recovery", []string{"authority", "apply", "reader", "cleanup", "successor"}, true, false},
		{"keys-replace-authority-both-by-authority", []string{"authority", "apply", "reader", "cleanup"}, false, false},
		{"keys-replace-authority-both-by-recovery", []string{"authority", "apply", "reader", "cleanup", "successor"}, true, false},
		{"keys-replace-recovery-signing-by-authority", []string{"authority", "apply", "reader", "cleanup"}, true, false},
		{"keys-replace-recovery-signing-by-recovery", []string{"authority", "apply", "reader", "cleanup", "successor"}, true, false},
		{"keys-replace-recovery-encryption-by-authority", []string{"authority", "apply", "reader", "cleanup"}, true, false},
		{"keys-replace-recovery-encryption-by-recovery", []string{"authority", "apply", "reader", "cleanup", "successor"}, true, false},
		{"keys-replace-recovery-both-by-authority", []string{"authority", "apply", "reader", "cleanup"}, true, false},
		{"keys-replace-recovery-both-by-recovery", []string{"authority", "apply", "reader", "cleanup", "successor"}, true, false},
		{"keys-replace-recipient", []string{"authority", "apply", "reader", "cleanup", "reader-successor"}, true, false},
		{"keys-replace-required-public-denied", []string{"authority", "apply", "reader", "cleanup", "denied-public"}, true, false},
		{"keys-replace-normal-signing-denied", []string{"authority", "apply", "reader", "cleanup", "denied-normal-signing"}, true, false},
		{"keys-replace-authority-private-denied", []string{"authority", "apply", "reader", "cleanup", "denied-authority-private"}, true, false},
		{"keys-replace-recovery-signing-denied", []string{"authority", "apply", "reader", "cleanup", "successor", "denied-recovery-signing"}, true, false},
		{"keys-replace-recovery-private-denied", []string{"authority", "apply", "reader", "cleanup", "denied-recovery-private"}, true, false},
		{"keys-replace-operator-both", []string{"authority", "apply", "reader", "consumer", "cleanup"}, false, true},
	}
	var rows []scheduleProjection
	for _, c := range cases {
		row := scheduleProjection{Name: "public-configuration." + c.name, Fixture: Shape{Members: 1, SmallValueCount: 1, SmallValueBytes: 1, RawValueBytes: 1, ValueSeed: "member_index_modulo_256"}}
		switch {
		case cell.mode != "live" || cell.provider != "aws" && cell.provider != "gcp":
			row.Status = "unsupported"
		case c.enabledOnly && cell.recovery == "disabled" || c.disabledOnly && cell.recovery == "enabled":
			row.Status = "excluded"
		default:
			row.Status = "scheduled"
			for _, role := range c.roles {
				if cell.recovery == "disabled" && (role == "successor" || role == "recovery") {
					continue
				}
				row.Roles = append(row.Roles, role)
			}
			row.Writer = []Step{{Name: "setup", Role: "authority", Expected: "selector-only-source-and-exact-roles-ready"}, {Name: "transition", Role: "authority", Expected: "joined-public-configuration-actions-exact"}, {Name: "verification", Role: "authority", Expected: "independent-public-private-and-source-facts-exact"}}
			row.AfterRole = "reader"
			row.AfterExpected = "pair-only-independent-public-observation-exact"
			row.AfterModes = []string{cell.recovery}
			row.Measurements = []bool{true, true, true, true}
		}
		rows = append(rows, row)
	}
	return rows
}
