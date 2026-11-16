package records

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

const outputAWSProfile = "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3"
const outputGCPProfile = "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3"
const outputGitHubProfile = "ENKV/OUTPUT/GITHUB-REPOSITORY/v3"

func outputFixtureID(number int) string { return fmt.Sprintf("%064x", number) }

func outputInventorySetup(t *testing.T, profile string) (string, OutputFixtureScope) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	scope := OutputFixtureScope{RunID: strings.Repeat("a", 32), Scenario: "publication.value-policy-delete/plain1_secret1_value_policy_delete", DomainID: outputFixtureID(1), WriterID: "publication-writer"}
	path := filepath.Join(directory, "output-inventory.json")
	if err = NewOutputFixtureInventory(path, scope, []OutputFixtureRow{{ProfileID: profile, PlannedSlot: "exact/plain", ExclusiveNamespaceDigest: outputFixtureID(2)}}); err != nil {
		t.Fatal(err)
	}
	if outputCloudProfile(profile) {
		if SetOutputFixtureActors(path, scope, OutputFixtureActors{ProfileID: profile, Writer: "writer", ReaderA: "consumer-a", ReaderB: "consumer-b"}) != nil {
			t.Fatal("durable actor set refused")
		}
	}
	return path, scope
}

func outputInventoryUpdate(t *testing.T, path string, scope OutputFixtureScope, change func(*OutputFixtureInventory) error) {
	t.Helper()
	if err := updateOutputFixtureInventory(path, scope, change); err != nil {
		t.Fatal(err)
	}
}

func outputInventoryRead(t *testing.T, path string, scope OutputFixtureScope) OutputFixtureInventory {
	t.Helper()
	inventory, err := ReadOutputFixtureInventory(path, scope)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func outputRecordAction(t *testing.T, path string, scope OutputFixtureScope, attempt int, action uint8, outcome, instance string) {
	t.Helper()
	if err := BeginOutputFixtureAction(path, scope, 0, outputFixtureID(attempt), action); err != nil {
		t.Fatal(err)
	}
	if err := RecordOutputFixtureAction(path, scope, 0, outputFixtureID(attempt), outcome, instance); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestOutputFixtureInventoryLifecycle(t *testing.T) {
	t.Run("persist_before_send", func(t *testing.T) {
		path, scope := outputInventorySetup(t, outputAWSProfile)
		original := outputInventoryRead(t, path, scope)
		sends := 0
		if err := updateOutputFixtureInventory(path, scope, func(inventory *OutputFixtureInventory) error {
			return inventory.beginAction(0, outputFixtureID(3), contract.PublicationCreateEmpty)
		}); err == nil {
			persisted := outputInventoryRead(t, path, scope)
			if len(persisted.Rows[0].Attempts) != 1 || persisted.Rows[0].Attempts[0].Outcome != "pending" || persisted.Rows[0].OwnedInstance != "" {
				t.Fatal("send boundary lacks durable possible-create receipt")
			}
			sends++
		} else {
			t.Fatal(err)
		}
		if sends != 1 || len(original.Rows[0].Attempts) != 0 {
			t.Fatal("save aliased earlier private snapshot")
		}
	})
	t.Run("complete_lifecycle", func(t *testing.T) {
		path, scope := outputInventorySetup(t, outputAWSProfile)
		// Fixed expected actions are independent of the inventory's successor.
		actions := []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue, contract.PublicationWriteValue, contract.PublicationDeleteOwned}
		for index, action := range actions {
			instance := ""
			if index == 0 {
				instance = "exact-qualified-arn"
			}
			outputRecordAction(t, path, scope, index+3, action, "acknowledged", instance)
		}
		inventory := outputInventoryRead(t, path, scope)
		row, err := inventory.Row(0, outputAWSProfile, "exact/plain")
		if err != nil || row.BirthAttemptID != outputFixtureID(3) || row.OwnedInstance != "exact-qualified-arn" || len(row.Attempts) != len(actions) {
			t.Fatal("delete lost exact qualified birth or receipts", err)
		}
		for index, action := range actions {
			if row.Attempts[index] != (OutputFixtureAttempt{AttemptID: outputFixtureID(index + 3), Action: action, Outcome: "acknowledged"}) {
				t.Fatalf("action %d receipt differs", index)
			}
		}
		joined := filepath.Join(filepath.Dir(path), "writer-joined.json")
		if err = WriteOutputFixtureJoined(joined, scope); err != nil {
			t.Fatal(err)
		}
		if err = BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(20), joined); err != nil {
			t.Fatal(err)
		}
		if got := outputInventoryRead(t, path, scope).Rows[0].Cleanup; got == nil || got.Outcome != "pending" {
			t.Fatal("fixture cleanup entered without pending receipt")
		}
		outputInventoryUpdate(t, path, scope, func(inventory *OutputFixtureInventory) error {
			return inventory.recordCleanup(0, outputFixtureID(20), "scheduled")
		})
		inventory = outputInventoryRead(t, path, scope)
		if inventory.Rows[0].Cleanup.Outcome != "scheduled" || inventory.Rows[0].OwnedInstance != "exact-qualified-arn" || inventory.Rows[0].BirthAttemptID != outputFixtureID(3) {
			t.Fatal("scheduled ACK became erasure or removed birth")
		}
		if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(21), joined) == nil {
			t.Fatal("second cleanup attempt admitted")
		}
	})
	t.Run("unknowns_survive_cleanup", func(t *testing.T) {
		path, scope := outputInventorySetup(t, outputGCPProfile)
		outputRecordAction(t, path, scope, 3, contract.PublicationCreateEmpty, "unknown", "")
		outputRecordAction(t, path, scope, 4, contract.PublicationDeleteReservedSlot, "unknown", "")
		joined := filepath.Join(filepath.Dir(path), "writer-joined.json")
		if WriteOutputFixtureJoined(joined, scope) != nil || BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(5), joined) != nil {
			t.Fatal("joined exact uncertain-create cleanup refused")
		}
		outputInventoryUpdate(t, path, scope, func(inventory *OutputFixtureInventory) error {
			return inventory.recordCleanup(0, outputFixtureID(5), "absent")
		})
		inventory := outputInventoryRead(t, path, scope)
		expected := []OutputFixtureAttempt{{AttemptID: outputFixtureID(3), Action: contract.PublicationCreateEmpty, Outcome: "unknown"}, {AttemptID: outputFixtureID(4), Action: contract.PublicationDeleteReservedSlot, Outcome: "unknown"}}
		if !reflect.DeepEqual(inventory.Rows[0].Attempts, expected) || inventory.Rows[0].OwnedInstance != "" || inventory.Rows[0].BirthAttemptID != "" || inventory.Rows[0].Cleanup.Outcome != "absent" {
			t.Fatal("absence erased unknowns or claimed Product ownership")
		}
	})
	t.Run("joined_pending_stays_possible", func(t *testing.T) {
		path, scope := outputInventorySetup(t, outputGitHubProfile)
		outputInventoryUpdate(t, path, scope, func(inventory *OutputFixtureInventory) error {
			return inventory.beginAction(0, outputFixtureID(3), contract.PublicationCreateWithValue)
		})
		joined := filepath.Join(filepath.Dir(path), "writer-joined.json")
		if WriteOutputFixtureJoined(joined, scope) != nil || BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) != nil {
			t.Fatal("possible pending create not retained for cleanup")
		}
		outputInventoryUpdate(t, path, scope, func(inventory *OutputFixtureInventory) error {
			return inventory.recordCleanup(0, outputFixtureID(4), "unknown")
		})
		row := outputInventoryRead(t, path, scope).Rows[0]
		if row.Attempts[0].Outcome != "pending" || row.OwnedInstance != "" || row.Cleanup.Outcome != "unknown" {
			t.Fatal("joined writer converted possible effect to ACK")
		}
	})
}

// full_only: false
func TestOutputFixtureInventoryPersistenceFailurePreventsSend(t *testing.T) {
	path, scope := outputInventorySetup(t, outputGitHubProfile)
	directory := filepath.Dir(path)
	retained := directory + "-retained"
	// A real filesystem failure occurs after input read and intent validation,
	// before the synced save. No injected persistence or transport hook is used.
	t.Cleanup(func() {
		if err := os.Remove(directory); err != nil {
			t.Error("remove filesystem failure fixture", err)
		}
		if err := os.Rename(retained, directory); err != nil {
			t.Error("restore retained inventory directory", err)
		}
	})
	sends := 0
	err := updateOutputFixtureInventory(path, scope, func(inventory *OutputFixtureInventory) error {
		if err := inventory.beginAction(0, outputFixtureID(3), contract.PublicationCreateWithValue); err != nil {
			return err
		}
		if err := os.Rename(directory, retained); err != nil {
			return err
		}
		return os.WriteFile(directory, []byte("blocks directory creation"), 0o600)
	})
	if err == nil {
		sends++
	}
	if err == nil || sends != 0 {
		t.Fatal("provider entry survived failed durable intent")
	}
	old := outputInventoryRead(t, filepath.Join(retained, filepath.Base(path)), scope)
	if len(old.Rows[0].Attempts) != 0 {
		t.Fatal("failed save changed retained prior evidence")
	}
}

// full_only: false
func TestOutputFixtureInventoryRejectsInvalidMutationsWithoutLosingEvidence(t *testing.T) {
	path, scope := outputInventorySetup(t, outputAWSProfile)
	outputRecordAction(t, path, scope, 3, contract.PublicationCreateEmpty, "acknowledged", "exact-birth")
	outputRecordAction(t, path, scope, 4, contract.PublicationWriteValue, "unknown", "")
	before := outputInventoryRead(t, path, scope)
	cases := map[string]func(*OutputFixtureInventory) error{
		"duplicate_attempt": func(i *OutputFixtureInventory) error {
			return i.beginAction(0, outputFixtureID(3), contract.PublicationWriteValue)
		},
		"zero_attempt": func(i *OutputFixtureInventory) error {
			return i.beginAction(0, outputFixtureID(0), contract.PublicationWriteValue)
		},
		"invalid_action": func(i *OutputFixtureInventory) error { return i.beginAction(0, outputFixtureID(5), 0) },
		"wrong_row": func(i *OutputFixtureInventory) error {
			return i.beginAction(1, outputFixtureID(5), contract.PublicationWriteValue)
		},
		"reserved_delete_with_birth": func(i *OutputFixtureInventory) error {
			return i.beginAction(0, outputFixtureID(5), contract.PublicationDeleteReservedSlot)
		},
		"second_create": func(i *OutputFixtureInventory) error {
			return i.beginAction(0, outputFixtureID(5), contract.PublicationCreateEmpty)
		},
		"rewrite_unknown": func(i *OutputFixtureInventory) error {
			return i.recordAction(0, outputFixtureID(4), "acknowledged", "")
		},
		"duplicate_actors": func(i *OutputFixtureInventory) error { return i.setActors(i.Actors[0]) },
		"gh_actor_fiction": func(i *OutputFixtureInventory) error {
			return i.setActors(OutputFixtureActors{ProfileID: outputGitHubProfile, Writer: "w", ReaderA: "a", ReaderB: "b"})
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := before.clone()
			if candidate.change(change) == nil || !reflect.DeepEqual(candidate, before) {
				t.Fatal("invalid in-memory mutation changed earlier evidence")
			}
			if updateOutputFixtureInventory(path, scope, change) == nil || !reflect.DeepEqual(outputInventoryRead(t, path, scope), before) {
				t.Fatal("invalid saved mutation changed earlier evidence")
			}
		})
	}
}

// full_only: false
func TestOutputFixtureInventoryRequiresExactPendingResult(t *testing.T) {
	for _, outcome := range []string{"acknowledged", "no_effect", "not_sent", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			path, scope := outputInventorySetup(t, outputGitHubProfile)
			outputInventoryUpdate(t, path, scope, func(i *OutputFixtureInventory) error {
				return i.beginAction(0, outputFixtureID(3), contract.PublicationCreateWithValue)
			})
			before := outputInventoryRead(t, path, scope)
			for name, change := range map[string]func(*OutputFixtureInventory) error{
				"second_pending": func(i *OutputFixtureInventory) error {
					return i.beginAction(0, outputFixtureID(4), contract.PublicationCreateWithValue)
				},
				"wrong_attempt":   func(i *OutputFixtureInventory) error { return i.recordAction(0, outputFixtureID(4), outcome, "") },
				"invalid_outcome": func(i *OutputFixtureInventory) error { return i.recordAction(0, outputFixtureID(3), "erased", "") },
				"unqualified_ack_or_lookup": func(i *OutputFixtureInventory) error {
					instance := "metadata-lookup-instance"
					if outcome == "acknowledged" {
						instance = ""
					}
					return i.recordAction(0, outputFixtureID(3), outcome, instance)
				},
			} {
				t.Run(name, func(t *testing.T) {
					if updateOutputFixtureInventory(path, scope, change) == nil || !reflect.DeepEqual(outputInventoryRead(t, path, scope), before) {
						t.Fatal("uncorrelated result accepted or pending evidence lost")
					}
				})
			}
			instance := ""
			if outcome == "acknowledged" {
				instance = "exact-qualified-birth"
			}
			outputInventoryUpdate(t, path, scope, func(i *OutputFixtureInventory) error { return i.recordAction(0, outputFixtureID(3), outcome, instance) })
			row := outputInventoryRead(t, path, scope).Rows[0]
			if row.Attempts[0].Outcome != outcome || (row.BirthAttemptID != "") != (outcome == "acknowledged") {
				t.Fatal("closed result lost or ownership assigned without ACK")
			}
		})
	}
}

// full_only: false
func TestOutputFixtureInventoryBoundsAndPrivateScope(t *testing.T) {
	path, scope := outputInventorySetup(t, outputGitHubProfile)
	before := outputInventoryRead(t, path, scope)
	if NewOutputFixtureInventory(path, scope, before.Rows) == nil || !reflect.DeepEqual(outputInventoryRead(t, path, scope), before) {
		t.Fatal("New overwrote original inventory")
	}
	for name, change := range map[string]func(*OutputFixtureScope){
		"run":      func(s *OutputFixtureScope) { s.RunID = strings.Repeat("b", 32) },
		"scenario": func(s *OutputFixtureScope) { s.Scenario = "different.scenario" },
		"domain":   func(s *OutputFixtureScope) { s.DomainID = outputFixtureID(99) },
		"writer":   func(s *OutputFixtureScope) { s.WriterID = "different-writer" },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := scope
			change(&wrong)
			if _, err := ReadOutputFixtureInventory(path, wrong); err == nil {
				t.Fatal("scope mismatch accepted")
			}
		})
	}
	if _, err := before.Row(0, outputAWSProfile, "exact/plain"); err == nil {
		t.Fatal("wrong profile row reference accepted")
	}
	if _, err := before.Row(0, outputGitHubProfile, "other/plain"); err == nil {
		t.Fatal("wrong slot row reference accepted")
	}
	if _, err := before.Row(1, outputGitHubProfile, "exact/plain"); err == nil {
		t.Fatal("out-of-range failure reference accepted")
	}
	row, err := before.Row(0, outputGitHubProfile, "exact/plain")
	if err != nil {
		t.Fatal(err)
	}
	row.Attempts = append(row.Attempts, OutputFixtureAttempt{})
	if len(before.Rows[0].Attempts) != 0 {
		t.Fatal("returned row aliases private inventory")
	}
	outputRecordAction(t, path, scope, 3, contract.PublicationCreateWithValue, "acknowledged", "exact-birth")
	for n := 1; n < MaximumOutputFixtureAttempts; n++ {
		outputRecordAction(t, path, scope, n+3, contract.PublicationWriteValue, "acknowledged", "")
	}
	if updateOutputFixtureInventory(path, scope, func(i *OutputFixtureInventory) error {
		return i.beginAction(0, outputFixtureID(20), contract.PublicationWriteValue)
	}) == nil {
		t.Fatal("unbounded lifecycle history accepted")
	}
	if err = os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadOutputFixtureInventory(path, scope); err == nil {
		t.Fatal("public-readable inventory accepted")
	}
	if err = os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadOutputFixtureInventory(path, scope); err == nil {
		t.Fatal("public-readable parent accepted")
	}
	if err = os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestOutputFixtureInventoryFixedRowAndActorBounds(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if os.Chmod(directory, 0o700) != nil {
		t.Fatal("private directory")
	}
	scope := OutputFixtureScope{RunID: strings.Repeat("a", 32), Scenario: "publication.value-policy-delete/plain1_secret1_value_policy_delete", DomainID: outputFixtureID(1), WriterID: "writer"}
	profiles := []string{outputAWSProfile, outputGCPProfile, outputGitHubProfile, "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3"}
	var rows []OutputFixtureRow
	for _, profile := range profiles {
		for _, slot := range []string{"plain", "secret"} {
			rows = append(rows, OutputFixtureRow{ProfileID: profile, PlannedSlot: slot, ExclusiveNamespaceDigest: outputFixtureID(2)})
		}
	}
	path := filepath.Join(directory, "ten.json")
	if NewOutputFixtureInventory(path, scope, rows) != nil {
		t.Fatal("exact ten-row bound refused")
	}
	rows[0].PlannedSlot = "changed-input"
	if outputInventoryRead(t, path, scope).Rows[0].PlannedSlot != "plain" {
		t.Fatal("borrowed rows not copied")
	}
	for name, damage := range map[string]func([]OutputFixtureRow) []OutputFixtureRow{
		"eleven": func(r []OutputFixtureRow) []OutputFixtureRow {
			return append(r, OutputFixtureRow{ProfileID: outputAWSProfile, PlannedSlot: "third", ExclusiveNamespaceDigest: outputFixtureID(2)})
		},
		"duplicate_slot": func(r []OutputFixtureRow) []OutputFixtureRow { r[0] = r[1]; return r },
		"three_per_profile": func(r []OutputFixtureRow) []OutputFixtureRow {
			r[2].ProfileID = outputAWSProfile
			r[2].PlannedSlot = "third"
			return r
		},
		"unknown_profile": func(r []OutputFixtureRow) []OutputFixtureRow { r[0].ProfileID = "test-output"; return r },
		"empty_slot":      func(r []OutputFixtureRow) []OutputFixtureRow { r[0].PlannedSlot = ""; return r },
		"large_slot":      func(r []OutputFixtureRow) []OutputFixtureRow { r[0].PlannedSlot = strings.Repeat("s", 1025); return r },
		"zero_namespace": func(r []OutputFixtureRow) []OutputFixtureRow {
			r[0].ExclusiveNamespaceDigest = outputFixtureID(0)
			return r
		},
		"initial_birth": func(r []OutputFixtureRow) []OutputFixtureRow { r[0].OwnedInstance = "adopted"; return r },
	} {
		t.Run(name, func(t *testing.T) {
			if NewOutputFixtureInventory(filepath.Join(directory, name+".json"), scope, damage(append([]OutputFixtureRow(nil), rows...))) == nil {
				t.Fatal("invalid fixed inventory admitted")
			}
		})
	}
	inventory := outputInventoryRead(t, path, scope)
	if inventory.beginAction(0, outputFixtureID(3), contract.PublicationCreateEmpty) == nil {
		t.Fatal("cloud action before actual actor principals admitted")
	}
	for name, actors := range map[string]OutputFixtureActors{
		"missing":        {ProfileID: outputAWSProfile, Writer: "writer", ReaderA: "a"},
		"writer_alias":   {ProfileID: outputAWSProfile, Writer: "a", ReaderA: "a", ReaderB: "b"},
		"consumer_alias": {ProfileID: outputAWSProfile, Writer: "w", ReaderA: "a", ReaderB: "a"},
		"gh_fiction":     {ProfileID: outputGitHubProfile, Writer: "w", ReaderA: "a", ReaderB: "b"},
		"large":          {ProfileID: outputAWSProfile, Writer: strings.Repeat("w", 1025), ReaderA: "a", ReaderB: "b"},
	} {
		t.Run(name, func(t *testing.T) {
			if inventory.setActors(actors) == nil || len(inventory.Actors) != 0 {
				t.Fatal("invalid cloud principal set admitted or partially retained")
			}
		})
	}
	if inventory.setActors(OutputFixtureActors{ProfileID: outputAWSProfile, Writer: "w", ReaderA: "a", ReaderB: "b"}) != nil || inventory.beginAction(0, outputFixtureID(3), contract.PublicationCreateEmpty) != nil {
		t.Fatal("exact validated actor set refused")
	}
	if inventory.beginAction(1, outputFixtureID(3), contract.PublicationCreateEmpty) == nil {
		t.Fatal("cross-row duplicate attempt admitted")
	}
}

// full_only: false
func TestOutputFixtureCleanupRequiresJoinAndSingleExactResult(t *testing.T) {
	for _, profile := range []string{outputAWSProfile, outputGCPProfile, outputGitHubProfile} {
		t.Run(profile, func(t *testing.T) {
			path, scope := outputInventorySetup(t, profile)
			action := contract.PublicationCreateWithValue
			if outputCloudProfile(profile) {
				action = contract.PublicationCreateEmpty
			}
			outputRecordAction(t, path, scope, 3, action, "unknown", "")
			joined := filepath.Join(filepath.Dir(path), "writer-joined.json")
			if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) == nil {
				t.Fatal("missing join admitted cleanup")
			}
			wrong := scope
			wrong.WriterID = "other-writer"
			if WriteOutputFixtureJoined(joined, wrong) != nil {
				t.Fatal("join marker setup")
			}
			if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) == nil {
				t.Fatal("wrong writer join admitted cleanup")
			}
			if os.Remove(joined) != nil || WriteOutputFixtureJoined(joined, scope) != nil {
				t.Fatal("matching join setup")
			}
			if WriteOutputFixtureJoined(joined, wrong) == nil {
				t.Fatal("later join overwrote original evidence")
			}
			if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(3), joined) == nil {
				t.Fatal("Product attempt reused for fixture cleanup")
			}
			if BeginOutputFixtureCleanup(path, scope, 1, outputFixtureID(4), joined) == nil {
				t.Fatal("wrong cleanup row admitted")
			}
			if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) != nil {
				t.Fatal("first matching joined cleanup refused")
			}
			before := outputInventoryRead(t, path, scope)
			for name, change := range map[string]func(*OutputFixtureInventory) error{
				"wrong_attempt":  func(i *OutputFixtureInventory) error { return i.recordCleanup(0, outputFixtureID(5), "unknown") },
				"wrong_row":      func(i *OutputFixtureInventory) error { return i.recordCleanup(1, outputFixtureID(4), "unknown") },
				"invalid_result": func(i *OutputFixtureInventory) error { return i.recordCleanup(0, outputFixtureID(4), "erased") },
				"new_product_action": func(i *OutputFixtureInventory) error {
					return i.beginAction(0, outputFixtureID(5), contract.PublicationDeleteReservedSlot)
				},
			} {
				t.Run(name, func(t *testing.T) {
					if updateOutputFixtureInventory(path, scope, change) == nil || !reflect.DeepEqual(outputInventoryRead(t, path, scope), before) {
						t.Fatal("cleanup pending evidence lost or invalid result accepted")
					}
				})
			}
			if profile != outputAWSProfile && updateOutputFixtureInventory(path, scope, func(i *OutputFixtureInventory) error { return i.recordCleanup(0, outputFixtureID(4), "scheduled") }) == nil {
				t.Fatal("non-AWS scheduled ACK accepted")
			}
			outputInventoryUpdate(t, path, scope, func(i *OutputFixtureInventory) error { return i.recordCleanup(0, outputFixtureID(4), "unknown") })
			if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(5), joined) == nil || updateOutputFixtureInventory(path, scope, func(i *OutputFixtureInventory) error { return i.recordCleanup(0, outputFixtureID(4), "acknowledged") }) == nil {
				t.Fatal("unknown cleanup retried or overwritten")
			}
		})
	}
}

// full_only: false
func TestOutputFixtureInventoryReadRejectsMalformedState(t *testing.T) {
	path, scope := outputInventorySetup(t, outputGitHubProfile)
	outputRecordAction(t, path, scope, 3, contract.PublicationCreateWithValue, "acknowledged", "qualified-birth")
	original := outputInventoryRead(t, path, scope)
	for name, damage := range map[string]func(*OutputFixtureInventory){
		"schema":                func(i *OutputFixtureInventory) { i.SchemaVersion = 2 },
		"missing_birth_attempt": func(i *OutputFixtureInventory) { i.Rows[0].BirthAttemptID = "" },
		"wrong_birth_attempt":   func(i *OutputFixtureInventory) { i.Rows[0].BirthAttemptID = outputFixtureID(4) },
		"missing_instance":      func(i *OutputFixtureInventory) { i.Rows[0].OwnedInstance = "" },
		"unknown_create_owned":  func(i *OutputFixtureInventory) { i.Rows[0].Attempts[0].Outcome = "unknown" },
		"invalid_outcome":       func(i *OutputFixtureInventory) { i.Rows[0].Attempts[0].Outcome = "erased" },
		"nil_history":           func(i *OutputFixtureInventory) { i.Rows[0].Attempts = nil },
		"nil_actors":            func(i *OutputFixtureInventory) { i.Actors = nil },
		"wrong_action":          func(i *OutputFixtureInventory) { i.Rows[0].Attempts[0].Action = contract.PublicationWriteValue },
		"forged_cleanup": func(i *OutputFixtureInventory) {
			i.Rows[0].Cleanup = &OutputFixtureCleanup{AttemptID: outputFixtureID(3), Outcome: "acknowledged"}
		},
		"unselected_actors": func(i *OutputFixtureInventory) {
			i.Actors = []OutputFixtureActors{{ProfileID: outputAWSProfile, Writer: "w", ReaderA: "a", ReaderB: "b"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			damaged := original.clone()
			damage(&damaged)
			malformed := filepath.Join(filepath.Dir(path), name+".json")
			if WriteJSON(malformed, damaged, 0o600) != nil {
				t.Fatal("malformed-state setup")
			}
			if _, err := ReadOutputFixtureInventory(malformed, scope); err == nil {
				t.Fatal("malformed private state accepted")
			}
		})
	}
	for name, body := range map[string][]byte{"overflow": []byte(strings.Repeat(" ", MaximumOutputFixtureInventoryBytes+1)), "unknown_field": []byte(`{"schema_version":1,"private_path":"must-refuse"}`)} {
		t.Run(name, func(t *testing.T) {
			malformed := filepath.Join(filepath.Dir(path), name+".json")
			if os.WriteFile(malformed, body, 0o600) != nil {
				t.Fatal("malformed wire setup")
			}
			if _, err := ReadOutputFixtureInventory(malformed, scope); err == nil {
				t.Fatal("unbounded or unknown-field state accepted")
			}
		})
	}
	for _, action := range []uint8{contract.PublicationWriteValue, contract.PublicationUpdatePolicy, contract.PublicationDeleteOwned, contract.PublicationDeleteReservedSlot} {
		emptyPath, emptyScope := outputInventorySetup(t, outputGitHubProfile)
		if updateOutputFixtureInventory(emptyPath, emptyScope, func(i *OutputFixtureInventory) error { return i.beginAction(0, outputFixtureID(3), action) }) == nil {
			t.Fatalf("action %d acquired a nonexistent birth/possible create", action)
		}
	}
}

// full_only: false
func TestOutputFixtureCleanupClosedOutcomesAndExactJoinScope(t *testing.T) {
	for _, outcome := range []string{"absent", "acknowledged", "scheduled", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			path, scope := outputInventorySetup(t, outputAWSProfile)
			outputRecordAction(t, path, scope, 3, contract.PublicationCreateEmpty, "unknown", "")
			joined := filepath.Join(filepath.Dir(path), "writer-joined.json")
			for name, damage := range map[string]func(*OutputFixtureJoined){
				"not_joined": func(j *OutputFixtureJoined) { j.Joined = false },
				"schema":     func(j *OutputFixtureJoined) { j.SchemaVersion = 2 },
				"run":        func(j *OutputFixtureJoined) { j.Scope.RunID = strings.Repeat("b", 32) },
				"scenario":   func(j *OutputFixtureJoined) { j.Scope.Scenario = "different.scenario" },
				"domain":     func(j *OutputFixtureJoined) { j.Scope.DomainID = outputFixtureID(99) },
				"writer":     func(j *OutputFixtureJoined) { j.Scope.WriterID = "different-writer" },
			} {
				t.Run(name, func(t *testing.T) {
					marker := OutputFixtureJoined{SchemaVersion: 1, Scope: scope, Joined: true}
					damage(&marker)
					if WriteJSON(joined, marker, 0o600) != nil {
						t.Fatal("join setup")
					}
					if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) == nil || outputInventoryRead(t, path, scope).Rows[0].Cleanup != nil {
						t.Fatal("mismatched join created cleanup permission")
					}
				})
			}
			if os.Remove(joined) != nil || WriteOutputFixtureJoined(joined, scope) != nil || BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) != nil {
				t.Fatal("exact positive joined pending cleanup")
			}
			outputInventoryUpdate(t, path, scope, func(i *OutputFixtureInventory) error { return i.recordCleanup(0, outputFixtureID(4), outcome) })
			row := outputInventoryRead(t, path, scope).Rows[0]
			if row.Cleanup.Outcome != outcome || row.Attempts[0].Outcome != "unknown" || row.OwnedInstance != "" {
				t.Fatal("cleanup outcome lost uncertain create warning or acquired birth")
			}
		})
	}
	t.Run("no_effect_create_has_no_cleanup_target", func(t *testing.T) {
		for _, outcome := range []string{"no_effect", "not_sent"} {
			path, scope := outputInventorySetup(t, outputGitHubProfile)
			outputRecordAction(t, path, scope, 3, contract.PublicationCreateWithValue, outcome, "")
			joined := filepath.Join(filepath.Dir(path), "writer-joined.json")
			if WriteOutputFixtureJoined(joined, scope) != nil {
				t.Fatal("join setup")
			}
			if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) == nil {
				t.Fatal("known no-effect create granted a cleanup target")
			}
		}
	})
}

// full_only: false
func TestOutputFixtureInventorySafeCleanupFailureReferencesExactPrivateRow(t *testing.T) {
	path, scope := outputInventorySetup(t, outputAWSProfile)
	outputRecordAction(t, path, scope, 3, contract.PublicationCreateEmpty, "acknowledged", "PRIVATE_QUALIFIED_BIRTH")
	inventory := outputInventoryRead(t, path, scope)
	index := uint32(0)
	row, err := inventory.Row(index, outputAWSProfile, "exact/plain")
	if err != nil {
		t.Fatal(err)
	}
	// This diagnostic references the exact retained private row. It does not
	// expose the row or authorize cleanup. Generic facts have a larger bound;
	// callers must separately obtain this inventory's exact index correlation.
	fact := HarnessFailure{Operation: "output_cleanup", Stage: "persistence", Cause: "persistence_failed", Effect: "no_send", TargetKind: "output_inventory", TargetIndex: &index}
	if !fact.Validate() {
		t.Fatal("closed output cleanup fact refused")
	}
	body, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{row.ProfileID, row.PlannedSlot, row.ExclusiveNamespaceDigest, row.OwnedInstance, row.BirthAttemptID, scope.RunID, scope.DomainID, inventory.Actors[0].Writer, inventory.Actors[0].ReaderA, inventory.Actors[0].ReaderB, path} {
		if strings.Contains(string(body), private) {
			t.Fatal("private inventory value exposed in safe public fact")
		}
	}
	for name, damage := range map[string]func(*HarnessFailure){
		"object_operation":                func(f *HarnessFailure) { f.Operation = "object_cleanup" },
		"generator_operation":             func(f *HarnessFailure) { f.Operation = "generator_cleanup" },
		"unsupported_inventory_operation": func(f *HarnessFailure) { f.Operation = "output_inventory" },
		"store_kind":                      func(f *HarnessFailure) { f.TargetKind = "inventory" },
		"generator_kind":                  func(f *HarnessFailure) { f.TargetKind = "generator_ledger" },
		"missing_index":                   func(f *HarnessFailure) { f.TargetIndex = nil },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := fact
			damage(&invalid)
			if invalid.Validate() {
				t.Fatal("mismatched cleanup operation or private row kind accepted")
			}
		})
	}
	if _, err = inventory.Row(10, outputAWSProfile, "exact/plain"); err == nil {
		t.Fatal("generic diagnostic bound widened inventory row lookup")
	}
}

// full_only: false
func TestOutputFixtureInventoryRejectsUnjoinedCleanupMutation(t *testing.T) {
	path, scope := outputInventorySetup(t, outputGitHubProfile)
	outputRecordAction(t, path, scope, 3, contract.PublicationCreateWithValue, "unknown", "")
	before := outputInventoryRead(t, path, scope)
	// Cleanup has a separate durable operation. Its mutation requires a
	// positive matching writer join, including after an unknown create.
	joined := filepath.Join(filepath.Dir(path), "missing-writer-join.json")
	if BeginOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), joined) == nil || !reflect.DeepEqual(outputInventoryRead(t, path, scope), before) {
		t.Fatal("durable cleanup mutation acquired permission without matching writer join")
	}
	if RecordOutputFixtureCleanup(path, scope, 0, outputFixtureID(4), "acknowledged") == nil || !reflect.DeepEqual(outputInventoryRead(t, path, scope), before) {
		t.Fatal("cleanup result created missing cleanup attempt or erased unknown create")
	}
}

// full_only: false
func TestOutputFixtureInventoryEncodedBoundPreservesPriorRecord(t *testing.T) {
	path, scope := outputInventorySetup(t, outputGitHubProfile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Fixed valid text can expand in JSON. Ten rows, one ACK each and exactly
	// three actors per cloud profile remain within the schema's field bounds.
	// Their escaped representation exceeds the private record's byte bound.
	expanded := OutputFixtureInventory{SchemaVersion: 1, Scope: scope, Rows: []OutputFixtureRow{}, Actors: []OutputFixtureActors{}}
	profiles := []string{outputAWSProfile, outputGCPProfile, outputGitHubProfile, "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3", "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3"}
	for _, profile := range profiles {
		if outputCloudProfile(profile) {
			expanded.Actors = append(expanded.Actors, OutputFixtureActors{ProfileID: profile, Writer: strings.Repeat("\x01", 1023) + "w", ReaderA: strings.Repeat("\x01", 1023) + "a", ReaderB: strings.Repeat("\x01", 1023) + "b"})
		}
		for _, suffix := range []string{"p", "s"} {
			attempt := outputFixtureID(len(expanded.Rows) + 3)
			action := contract.PublicationCreateWithValue
			if outputCloudProfile(profile) {
				action = contract.PublicationCreateEmpty
			}
			expanded.Rows = append(expanded.Rows, OutputFixtureRow{ProfileID: profile, PlannedSlot: strings.Repeat("\x01", 1023) + suffix, ExclusiveNamespaceDigest: outputFixtureID(2), BirthAttemptID: attempt, OwnedInstance: strings.Repeat("\x01", 1023) + suffix, Attempts: []OutputFixtureAttempt{{AttemptID: attempt, Action: action, Outcome: "acknowledged"}}})
		}
	}
	body, err := json.Marshal(expanded)
	if err != nil || len(body)+1 <= MaximumOutputFixtureInventoryBytes || expanded.validate(scope) != nil {
		t.Fatal("encoded-size regression fixture does not cross valid-state byte boundary", err)
	}
	// Exercise the shared private save path used by each concrete durable
	// operation. No filesystem/transport injection knob is introduced.
	err = updateOutputFixtureInventory(path, scope, func(i *OutputFixtureInventory) error { *i = expanded; return nil })
	after, readErr := os.ReadFile(path)
	if err == nil || readErr != nil || string(before) != string(after) {
		t.Fatalf("oversized save: refused=%v read_failed=%v prior_bytes=%d later_bytes=%d limit=%d", err != nil, readErr != nil, len(before), len(after), MaximumOutputFixtureInventoryBytes)
	}
}
