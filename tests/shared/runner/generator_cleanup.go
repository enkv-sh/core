package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	records "enkv.sh/core/internal/testrecords"
)

// The ledger is private runner cleanup state. Core never reads it, so a known
// fixture ID cannot become Product ownership, selection or no-effect evidence.
func createGeneratorFixtureLedger(state, runID string, generator generatorReference) (string, error) {
	refused := errors.New("generator fixture cleanup ledger refused")
	if !records.ValidRunID(runID) || !cloudflareAccount.MatchString(generator.Account) {
		return "", refused
	}
	path, err := records.SafePath(state, "generator-cleanup.json")
	if err != nil {
		return "", refused
	}
	if err := records.NewGeneratorFixtureLedger(path, runID, generator.Account); err != nil {
		return "", refused
	}
	return path, nil
}

func readGeneratorFixtureLedger(path, runID string) (records.GeneratorFixtureLedger, error) {
	refused := errors.New("generator fixture cleanup ledger refused")
	var fields map[string]json.RawMessage
	if !records.ValidRunID(runID) || records.ReadJSON(path, &fields) != nil {
		return records.GeneratorFixtureLedger{}, refused
	}
	var account string
	if json.Unmarshal(fields["account"], &account) != nil {
		return records.GeneratorFixtureLedger{}, refused
	}
	ledger, err := records.ReadGeneratorFixtureLedger(path, runID, account)
	if err != nil {
		return records.GeneratorFixtureLedger{}, refused
	}
	return ledger, nil
}

func recordGeneratorFixtureResource(path, runID, id string) error {
	ledger, err := readGeneratorFixtureLedger(path, runID)
	if err != nil {
		return errors.New("generator fixture cleanup ledger refused")
	}
	return records.UpdateGeneratorFixtureLedger(path, runID, ledger.Account, func(current *records.GeneratorFixtureLedger) error {
		attempt := fmt.Sprintf("%x", sha256.Sum256([]byte("test-create:"+id)))
		if err := current.BeginCreate(attempt); err != nil {
			return err
		}
		return current.RecordCreate(attempt, id)
	})
}

func retireGeneratorFixtureResource(path, runID, id string) error {
	ledger, err := readGeneratorFixtureLedger(path, runID)
	if err != nil {
		return err
	}
	return records.UpdateGeneratorFixtureLedger(path, runID, ledger.Account, func(current *records.GeneratorFixtureLedger) error {
		attempt := fmt.Sprintf("%x", sha256.Sum256([]byte("test-delete:"+id)))
		if err := current.BeginDelete(attempt, id); err != nil {
			return err
		}
		return current.RecordDelete(attempt, id)
	})
}

func generatorFixtureCleanupTargets(path, runID string) ([]string, error) {
	ledger, err := readGeneratorFixtureLedger(path, runID)
	if err != nil {
		return nil, err
	}
	if len(ledger.PendingCreates) != 0 {
		return nil, errors.New("generator fixture cleanup has an unknown create")
	}
	return ledger.CleanupTargets(), nil
}
