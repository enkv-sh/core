package records

import (
	"encoding/json"
	"errors"
	"os"

	"enkv.sh/core/testsupport/nativeprocess"
)

const PublicGeneratorFixtureCleanupName = "generator-cleanup-receipts.json"
const MaximumPublicGeneratorFixtureCleanupBytes = 16 << 10

type PublicGeneratorFixtureDelete struct {
	Attempt string `json:"attempt"`
	Target  string `json:"target"`
}

// PublicGeneratorFixtureCleanup records the fixture's exact acknowledged
// deletions. It is evidence only and grants no cleanup or retry authority.
type PublicGeneratorFixtureCleanup struct {
	SchemaVersion       int                            `json:"schema_version"`
	RunID               string                         `json:"run_id"`
	Scenario            string                         `json:"scenario"`
	Account             string                         `json:"account"`
	AcknowledgedDeletes []PublicGeneratorFixtureDelete `json:"acknowledged_deletes"`
}

func (v PublicGeneratorFixtureCleanup) Validate(runID, scenario, account string) error {
	if !ValidRunID(runID) || scenario == "" || !generatorID.MatchString(account) ||
		v.SchemaVersion != 1 || v.RunID != runID || v.Scenario != scenario || v.Account != account ||
		len(v.AcknowledgedDeletes) == 0 || len(v.AcknowledgedDeletes) > 6 {
		return errRecord
	}
	attempts, targets := map[string]bool{}, map[string]bool{}
	for _, row := range v.AcknowledgedDeletes {
		if !generatorAttempt.MatchString(row.Attempt) || !generatorID.MatchString(row.Target) || attempts[row.Attempt] || targets[row.Target] {
			return errRecord
		}
		attempts[row.Attempt], targets[row.Target] = true, true
	}
	return nil
}

func ReadPublicGeneratorFixtureCleanupBytes(body []byte, runID, scenario, account string) (PublicGeneratorFixtureCleanup, error) {
	var value PublicGeneratorFixtureCleanup
	if publicEvidenceJSON(body, MaximumPublicGeneratorFixtureCleanupBytes, &value) != nil || value.Validate(runID, scenario, account) != nil {
		return PublicGeneratorFixtureCleanup{}, errRecord
	}
	return value, nil
}

// RecordPublicGeneratorFixtureCleanup is called only after the exact provider
// acknowledgement and durable retirement in the original fixture ledger.
func RecordPublicGeneratorFixtureCleanup(path, runID, scenario, account, attempt, target string) error {
	value := PublicGeneratorFixtureCleanup{SchemaVersion: 1, RunID: runID, Scenario: scenario, Account: account}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errRecord
		}
		body, err := ReadJSONBytes(path, MaximumPublicGeneratorFixtureCleanupBytes)
		if err != nil {
			return errRecord
		}
		value, err = ReadPublicGeneratorFixtureCleanupBytes(body, runID, scenario, account)
		if err != nil {
			return errRecord
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return errRecord
	}
	value.AcknowledgedDeletes = append(value.AcknowledgedDeletes, PublicGeneratorFixtureDelete{Attempt: attempt, Target: target})
	if value.Validate(runID, scenario, account) != nil {
		return errRecord
	}
	body, err := json.Marshal(value)
	if err != nil || len(body)+1 > MaximumPublicGeneratorFixtureCleanupBytes {
		return errRecord
	}
	if statErr != nil {
		return WriteJSONExclusive(path, value, MaximumPublicGeneratorFixtureCleanupBytes)
	}
	return WriteJSON(path, value, 0600)
}

// This immutable evidence projection is derived from the existing private
// fixture ledger only after every request has a qualified terminal result.
// It is never read as cleanup authority or used to update that ledger.
type PublicConfigurationGeneratorEvidence struct {
	Account                      string                         `json:"account"`
	Resources                    []GeneratorFixtureResource     `json:"resources"`
	WriterJoined                 GeneratorFixtureJoined         `json:"writer_joined"`
	OriginalLedgerSHA256         string                         `json:"original_ledger_sha256"`
	OriginalJoinedSHA256         string                         `json:"original_joined_sha256"`
	FixtureCleanup               *PublicGeneratorFixtureCleanup `json:"fixture_cleanup,omitempty"`
	OriginalFixtureCleanupSHA256 string                         `json:"original_fixture_cleanup_sha256,omitempty"`
}

func (v PublicConfigurationGeneratorEvidence) Validate(runID, scenario string) error {
	refused := errors.New("public generator evidence refused")
	if !generatorID.MatchString(v.Account) || len(v.Resources) == 0 || len(v.Resources) > 6 || !validHex(v.OriginalLedgerSHA256, 32) || !validHex(v.OriginalJoinedSHA256, 32) ||
		v.WriterJoined.SchemaVersion != 1 || v.WriterJoined.RunID != runID || v.WriterJoined.Scenario != scenario || !v.WriterJoined.Joined {
		return refused
	}
	ledger := GeneratorFixtureLedger{SchemaVersion: 1, RunID: runID, Provider: "cloudflare", Account: v.Account, PendingCreates: []string{}, Resources: v.Resources}
	if validateGeneratorFixtureLedger(ledger, runID, v.Account) != nil || !ledger.Clean() {
		return refused
	}
	deletes := 0
	for _, r := range v.Resources {
		if len(r.DeleteAttempts) == 0 {
			return refused
		}
		deletes += len(r.DeleteAttempts)
	}
	if deletes > 22 {
		return refused
	}
	if v.FixtureCleanup == nil {
		if v.OriginalFixtureCleanupSHA256 != "" {
			return refused
		}
	} else {
		if !validHex(v.OriginalFixtureCleanupSHA256, 32) || v.FixtureCleanup.Validate(runID, scenario, v.Account) != nil {
			return refused
		}
		for _, deletion := range v.FixtureCleanup.AcknowledgedDeletes {
			found := false
			for _, r := range v.Resources {
				for _, attempt := range r.DeleteAttempts {
					if r.ID == deletion.Target && attempt == deletion.Attempt {
						found = true
					}
				}
			}
			if !found {
				return refused
			}
		}
	}
	return nil
}

// ValidateCaptures joins the exact source-qualified attempts and provider IDs.
// A normal process exit alone contributes no remote completion evidence.
func (v PublicConfigurationGeneratorEvidence) ValidateCaptures(captures []nativeprocess.Capture) error {
	refused := errors.New("public generator capture join refused")
	if v.Validate(v.WriterJoined.RunID, v.WriterJoined.Scenario) != nil {
		return refused
	}
	type expected struct {
		action uint8
		target string
	}
	attempts := map[string]expected{}
	fixtureDeletes := map[string]string{}
	if v.FixtureCleanup != nil {
		for _, row := range v.FixtureCleanup.AcknowledgedDeletes {
			fixtureDeletes[row.Attempt] = row.Target
		}
	}
	for _, r := range v.Resources {
		attempts[r.CreateAttempt] = expected{action: 1, target: r.ID}
		for _, attempt := range r.DeleteAttempts {
			if fixtureDeletes[attempt] != r.ID {
				attempts[attempt] = expected{action: 2, target: r.ID}
			}
		}
	}
	entered, returned := map[string]bool{}, map[string]bool{}
	for _, capture := range captures {
		for _, event := range capture.Events {
			switch event.Kind {
			case "generator-entry", "generator-return":
				want, ok := attempts[event.GeneratorAttempt]
				if !ok || event.GeneratorAccount != v.Account || event.GeneratorAction != want.action {
					return refused
				}
				if event.Kind == "generator-entry" {
					if entered[event.GeneratorAttempt] || returned[event.GeneratorAttempt] || want.action == 1 && event.GeneratorTarget != "" || want.action == 2 && event.GeneratorTarget != want.target {
						return refused
					}
					entered[event.GeneratorAttempt] = true
				} else {
					if !entered[event.GeneratorAttempt] || returned[event.GeneratorAttempt] || !event.GeneratorQualified || event.GeneratorTarget != want.target {
						return refused
					}
					returned[event.GeneratorAttempt] = true
				}
			case "generator-refused":
				return refused
			}
		}
	}
	if len(entered) != len(attempts) || len(returned) != len(attempts) {
		return refused
	}
	return nil
}
