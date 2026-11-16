package records

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicGeneratedEvidenceRequiresExactQualifiedCaptureAndJoin(t *testing.T) {
	runID, account, target := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	create, retire := strings.Repeat("d", 64), strings.Repeat("e", 64)
	scenario := "public-configuration.generated-manual-lifecycle/generated_manual_lifecycle"
	evidence := PublicConfigurationGeneratorEvidence{Account: account, Resources: []GeneratorFixtureResource{{ID: target, CreateAttempt: create, Disposition: "retired", DeleteAttempts: []string{retire}}}, WriterJoined: GeneratorFixtureJoined{SchemaVersion: 1, RunID: runID, Scenario: scenario, Joined: true}, OriginalLedgerSHA256: strings.Repeat("f", 64), OriginalJoinedSHA256: strings.Repeat("1", 64)}
	entry := nativeprocess.Event{Kind: "generator-entry", GeneratorAccount: account, GeneratorAttempt: create, GeneratorAction: 1}
	result := entry
	result.Kind, result.GeneratorTarget, result.GeneratorQualified = "generator-return", target, true
	deletion := entry
	deletion.GeneratorAttempt, deletion.GeneratorAction, deletion.GeneratorTarget = retire, 2, target
	deleted := deletion
	deleted.Kind, deleted.GeneratorQualified = "generator-return", true
	original := []nativeprocess.Event{entry, result, deletion, deleted}
	for _, condition := range []string{"exact", "account", "attempt", "target", "unqualified", "refused", "missing-entry", "missing-return", "duplicate", "join-missing", "join-other-scenario", "ledger-hash", "join-hash", "owned", "extra-resource", "fixture-exact", "fixture-account", "fixture-attempt", "fixture-target", "fixture-run", "fixture-scenario", "fixture-source-hash", "fixture-native-overlap", "fixture-no-create", "fixture-mixed"} {
		t.Run(condition, func(t *testing.T) {
			selected := evidence
			selected.Resources = slices.Clone(evidence.Resources)
			events := slices.Clone(original)
			if strings.HasPrefix(condition, "fixture-") {
				selected.FixtureCleanup = &PublicGeneratorFixtureCleanup{SchemaVersion: 1, RunID: runID, Scenario: scenario, Account: account, AcknowledgedDeletes: []PublicGeneratorFixtureDelete{{Attempt: retire, Target: target}}}
				selected.OriginalFixtureCleanupSHA256 = strings.Repeat("6", 64)
				events = events[:2:2]
			}
			switch condition {
			case "account":
				events[1].GeneratorAccount = strings.Repeat("2", 32)
			case "attempt":
				events[1].GeneratorAttempt = strings.Repeat("2", 64)
			case "target":
				events[1].GeneratorTarget = strings.Repeat("2", 32)
			case "unqualified":
				events[1].GeneratorQualified = false
			case "refused":
				events[1].Kind = "generator-refused"
			case "missing-entry":
				events = events[1:]
			case "missing-return":
				events = append(events[:1:1], events[2:]...)
			case "duplicate":
				events = append(events, original...)
			case "join-missing":
				selected.WriterJoined.Joined = false
			case "join-other-scenario":
				selected.WriterJoined.Scenario += "-other"
			case "ledger-hash":
				selected.OriginalLedgerSHA256 = ""
			case "join-hash":
				selected.OriginalJoinedSHA256 = ""
			case "owned":
				selected.Resources[0].Disposition = "owned"
			case "extra-resource":
				selected.Resources = append(selected.Resources, GeneratorFixtureResource{ID: strings.Repeat("3", 32), CreateAttempt: strings.Repeat("4", 64), Disposition: "retired", DeleteAttempts: []string{strings.Repeat("5", 64)}})
			case "fixture-account":
				selected.FixtureCleanup.Account = strings.Repeat("7", 32)
			case "fixture-attempt":
				selected.FixtureCleanup.AcknowledgedDeletes[0].Attempt = strings.Repeat("7", 64)
			case "fixture-target":
				selected.FixtureCleanup.AcknowledgedDeletes[0].Target = strings.Repeat("7", 32)
			case "fixture-run":
				selected.FixtureCleanup.RunID = strings.Repeat("7", 32)
			case "fixture-scenario":
				selected.FixtureCleanup.Scenario += "-other"
			case "fixture-source-hash":
				selected.OriginalFixtureCleanupSHA256 = ""
			case "fixture-native-overlap":
				events = append(events, original[2:]...)
			case "fixture-no-create":
				events = nil
			case "fixture-mixed":
				secondTarget, secondCreate, secondDelete := strings.Repeat("3", 32), strings.Repeat("4", 64), strings.Repeat("5", 64)
				selected.Resources = append(selected.Resources, GeneratorFixtureResource{ID: secondTarget, CreateAttempt: secondCreate, Disposition: "retired", DeleteAttempts: []string{secondDelete}})
				for _, event := range original {
					if event.GeneratorAction == 1 {
						event.GeneratorAttempt = secondCreate
						if event.Kind == "generator-return" {
							event.GeneratorTarget = secondTarget
						}
					} else {
						event.GeneratorAttempt, event.GeneratorTarget = secondDelete, secondTarget
					}
					events = append(events, event)
				}
			}
			err := selected.Validate(runID, scenario)
			if err == nil {
				err = selected.ValidateCaptures([]nativeprocess.Capture{{Events: events}})
			}
			if (err == nil) != (condition == "exact" || condition == "fixture-exact" || condition == "fixture-mixed") {
				t.Fatal("generator evidence omitted an exact source/capture/join obligation", condition, err)
			}
		})
	}
	fixture := PublicGeneratorFixtureCleanup{SchemaVersion: 1, RunID: runID, Scenario: scenario, Account: account, AcknowledgedDeletes: []PublicGeneratorFixtureDelete{{Attempt: retire, Target: target}}}
	body, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"exact", "limit", "duplicate-field", "folded-field", "foreign-field", "duplicate-attempt", "duplicate-target", "over-limit"} {
		t.Run("receipt/"+damage, func(t *testing.T) {
			selected := slices.Clone(body)
			switch damage {
			case "duplicate-field":
				selected = []byte(strings.Replace(string(body), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1))
			case "folded-field":
				selected = []byte(strings.Replace(string(body), `"account"`, `"ACCOUNT"`, 1))
			case "foreign-field":
				selected = append(selected[:len(selected)-1:len(selected)-1], []byte(`,"raw_response":"forbidden"}`)...)
			case "duplicate-attempt", "duplicate-target", "limit", "over-limit":
				copy := fixture
				copy.AcknowledgedDeletes = slices.Clone(fixture.AcknowledgedDeletes)
				row := PublicGeneratorFixtureDelete{Attempt: strings.Repeat("7", 64), Target: strings.Repeat("8", 32)}
				if damage == "duplicate-attempt" {
					row.Attempt = retire
				}
				if damage == "duplicate-target" {
					row.Target = target
				}
				copy.AcknowledgedDeletes = append(copy.AcknowledgedDeletes, row)
				if damage == "limit" || damage == "over-limit" {
					count := 6
					if damage == "over-limit" {
						count++
					}
					copy.AcknowledgedDeletes = nil
					for index := 1; index <= count; index++ {
						copy.AcknowledgedDeletes = append(copy.AcknowledgedDeletes, PublicGeneratorFixtureDelete{Attempt: fmt.Sprintf("%064x", index), Target: fmt.Sprintf("%032x", index)})
					}
				}
				selected, err = json.Marshal(copy)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := ReadPublicGeneratorFixtureCleanupBytes(selected, runID, scenario, account)
			if (err == nil) != (damage == "exact" || damage == "limit") {
				t.Fatal("fixture receipt admission differs", damage, err)
			}
		})
	}
	t.Run("receipt-append-byte-limit", func(t *testing.T) {
		directory, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil || os.Chmod(directory, 0700) != nil {
			t.Fatal("private receipt directory unavailable", err)
		}
		path := filepath.Join(directory, PublicGeneratorFixtureCleanupName)
		// The fixed JSON envelope is 16,172 bytes after one row and 16,295
		// after two; a third row would be 16,418, beyond the 16 KiB bound.
		scenario := strings.Repeat("x", 15900)
		for index := 1; index <= 2; index++ {
			if RecordPublicGeneratorFixtureCleanup(path, runID, scenario, account, fmt.Sprintf("%064x", index), fmt.Sprintf("%032x", index)) != nil {
				t.Fatal("bounded receipt append refused")
			}
		}
		before, err := os.ReadFile(path)
		if err != nil || len(before) != 16295 {
			t.Fatal("receipt derivation differs", len(before), err)
		}
		if RecordPublicGeneratorFixtureCleanup(path, runID, scenario, account, fmt.Sprintf("%064x", 3), fmt.Sprintf("%032x", 3)) == nil {
			t.Fatal("oversize receipt append accepted")
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("refused append changed original receipt", err)
		}
	})
	// The same optional projection remains inside the existing bounded snapshot.
	snapshot, binding := publicEvidenceFixture()
	snapshot.Scenario, binding.Scenario = scenario, scenario
	snapshot.Generator = &evidence
	if snapshot.Validate(binding) != nil {
		t.Fatal("bounded generated projection did not fit existing public snapshot")
	}
	snapshot.Generator = nil
	if snapshot.Validate(binding) == nil {
		t.Fatal("generated case omitted generator ownership evidence")
	}
}
