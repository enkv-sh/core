package records

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

const MaximumOutputFixtureInventoryBytes = 128 << 10
const MaximumOutputFixtureAttempts = 8

var errOutputInventory = errors.New("output fixture inventory refused")

type OutputFixtureScope struct {
	RunID    string `json:"run_id"`
	Scenario string `json:"scenario"`
	DomainID string `json:"domain_id"`
	WriterID string `json:"writer_id"`
}

type OutputFixtureAttempt struct {
	AttemptID string `json:"attempt_id"`
	Action    uint8  `json:"action"`
	Outcome   string `json:"outcome"`
}

type OutputFixtureCleanup struct {
	AttemptID string `json:"attempt_id"`
	Outcome   string `json:"outcome"`
}

type OutputFixtureRow struct {
	ProfileID                string                 `json:"profile_id"`
	PlannedSlot              string                 `json:"planned_slot"`
	ExclusiveNamespaceDigest string                 `json:"exclusive_namespace_digest"`
	BirthAttemptID           string                 `json:"birth_attempt_id,omitempty"`
	OwnedInstance            string                 `json:"owned_instance,omitempty"`
	Attempts                 []OutputFixtureAttempt `json:"attempts"`
	Cleanup                  *OutputFixtureCleanup  `json:"cleanup,omitempty"`
}

// OutputFixtureActors are the actual cloud principals, not Product roles.
// GitHub fixtures do not acquire a fictional cloud principal row.
type OutputFixtureActors struct {
	ProfileID string `json:"profile_id"`
	Writer    string `json:"writer"`
	ReaderA   string `json:"reader_a"`
	ReaderB   string `json:"reader_b"`
}

// OutputFixtureInventory is private, bounded test cleanup state. It grants
// neither Product ownership nor permission to send, retry or replay an action.
// An exact qualified create ACK is the only source of its retained birth.
type OutputFixtureInventory struct {
	SchemaVersion int                   `json:"schema_version"`
	Scope         OutputFixtureScope    `json:"scope"`
	Rows          []OutputFixtureRow    `json:"rows"`
	Actors        []OutputFixtureActors `json:"actors"`
}

type OutputFixtureJoined struct {
	SchemaVersion int                `json:"schema_version"`
	Scope         OutputFixtureScope `json:"scope"`
	Joined        bool               `json:"joined"`
}

func validOutputScope(scope OutputFixtureScope) bool {
	return ValidRunID(scope.RunID) && validOutputText(scope.Scenario, 256) && validOutputDigest(scope.DomainID) && labelPattern.MatchString(scope.WriterID)
}

func validOutputDigest(value string) bool {
	return generatorAttempt.MatchString(value) && value != strings.Repeat("0", 64)
}

func validOutputText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func outputCloudProfile(profile string) bool {
	return profile == "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3" || profile == "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3"
}

func validOutputProfile(profile string) bool {
	return outputCloudProfile(profile) || profile == "ENKV/OUTPUT/GITHUB-REPOSITORY/v3" ||
		profile == "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3" || profile == "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3"
}

func privateOutputRecord(path string) bool {
	if safeAbsolute(path) != nil {
		return false
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600
}

// NewOutputFixtureInventory never replaces an earlier run's evidence.
func NewOutputFixtureInventory(path string, scope OutputFixtureScope, rows []OutputFixtureRow) error {
	inventory := OutputFixtureInventory{SchemaVersion: 1, Scope: scope, Rows: slices.Clone(rows), Actors: []OutputFixtureActors{}}
	for i := range inventory.Rows {
		row := &inventory.Rows[i]
		if row.BirthAttemptID != "" || row.OwnedInstance != "" || len(row.Attempts) != 0 || row.Cleanup != nil {
			return errOutputInventory
		}
		row.Attempts = []OutputFixtureAttempt{}
	}
	if inventory.validate(scope) != nil {
		return errOutputInventory
	}
	if WriteJSONExclusive(path, inventory, MaximumOutputFixtureInventoryBytes) != nil {
		return errOutputInventory
	}
	return nil
}

func ReadOutputFixtureInventory(path string, scope OutputFixtureScope) (OutputFixtureInventory, error) {
	var inventory OutputFixtureInventory
	if !privateOutputRecord(path) || ReadJSONLimit(path, &inventory, MaximumOutputFixtureInventoryBytes) != nil || inventory.validate(scope) != nil {
		return OutputFixtureInventory{}, errOutputInventory
	}
	return inventory, nil
}

// The concrete durable operations save their intent/result before returning.
// Callers must await success before the associated provider action can enter.
// One writer owns each inventory; this is not a concurrent transaction API.
func SetOutputFixtureActors(path string, scope OutputFixtureScope, actors OutputFixtureActors) error {
	return updateOutputFixtureInventory(path, scope, func(inventory *OutputFixtureInventory) error { return inventory.setActors(actors) })
}

func BeginOutputFixtureAction(path string, scope OutputFixtureScope, index uint32, attempt string, action uint8) error {
	return updateOutputFixtureInventory(path, scope, func(inventory *OutputFixtureInventory) error { return inventory.beginAction(index, attempt, action) })
}

func RecordOutputFixtureAction(path string, scope OutputFixtureScope, index uint32, attempt, outcome, qualifiedInstance string) error {
	return updateOutputFixtureInventory(path, scope, func(inventory *OutputFixtureInventory) error {
		return inventory.recordAction(index, attempt, outcome, qualifiedInstance)
	})
}

func RecordOutputFixtureCleanup(path string, scope OutputFixtureScope, index uint32, attempt, outcome string) error {
	return updateOutputFixtureInventory(path, scope, func(inventory *OutputFixtureInventory) error { return inventory.recordCleanup(index, attempt, outcome) })
}

func updateOutputFixtureInventory(path string, scope OutputFixtureScope, change func(*OutputFixtureInventory) error) error {
	inventory, err := ReadOutputFixtureInventory(path, scope)
	if err != nil || change(&inventory) != nil || writeOutputFixtureInventory(path, inventory) != nil {
		return errOutputInventory
	}
	return nil
}

// Shared record IO has a larger limit. Check this fixture's complete encoded
// bound before replacing any earlier readable evidence.
func writeOutputFixtureInventory(path string, inventory OutputFixtureInventory) error {
	body, err := json.Marshal(inventory)
	if err != nil || len(body)+1 > MaximumOutputFixtureInventoryBytes || inventory.validate(inventory.Scope) != nil || WriteJSON(path, inventory, 0o600) != nil {
		return errOutputInventory
	}
	return nil
}

func (inventory OutputFixtureInventory) clone() OutputFixtureInventory {
	inventory.Rows = slices.Clone(inventory.Rows)
	inventory.Actors = slices.Clone(inventory.Actors)
	for i := range inventory.Rows {
		inventory.Rows[i].Attempts = slices.Clone(inventory.Rows[i].Attempts)
		if cleanup := inventory.Rows[i].Cleanup; cleanup != nil {
			copied := *cleanup
			inventory.Rows[i].Cleanup = &copied
		}
	}
	return inventory
}

func (inventory *OutputFixtureInventory) change(fn func(*OutputFixtureInventory) error) error {
	if inventory == nil || inventory.validate(inventory.Scope) != nil {
		return errOutputInventory
	}
	candidate := inventory.clone()
	if fn(&candidate) != nil || candidate.validate(inventory.Scope) != nil {
		return errOutputInventory
	}
	*inventory = candidate
	return nil
}

// Row returns an owned snapshot only for an exact fixed row correlation.
// Its index can be used in public safe failure facts; provider IDs stay private.
func (inventory OutputFixtureInventory) Row(index uint32, profile, slot string) (OutputFixtureRow, error) {
	if inventory.validate(inventory.Scope) != nil || uint64(index) >= uint64(len(inventory.Rows)) || inventory.Rows[index].ProfileID != profile || inventory.Rows[index].PlannedSlot != slot {
		return OutputFixtureRow{}, errOutputInventory
	}
	return inventory.clone().Rows[index], nil
}

func (inventory *OutputFixtureInventory) setActors(actors OutputFixtureActors) error {
	return inventory.change(func(candidate *OutputFixtureInventory) error {
		if slices.ContainsFunc(candidate.Actors, func(existing OutputFixtureActors) bool { return existing.ProfileID == actors.ProfileID }) {
			return errOutputInventory
		}
		candidate.Actors = append(candidate.Actors, actors)
		return nil
	})
}

func (inventory *OutputFixtureInventory) beginAction(index uint32, attempt string, action uint8) error {
	return inventory.change(func(candidate *OutputFixtureInventory) error {
		if uint64(index) >= uint64(len(candidate.Rows)) {
			return errOutputInventory
		}
		row := &candidate.Rows[index]
		if row.Cleanup != nil {
			return errOutputInventory
		}
		row.Attempts = append(row.Attempts, OutputFixtureAttempt{AttemptID: attempt, Action: action, Outcome: "pending"})
		return nil
	})
}

// recordAction accepts an already qualified result from the caller. A metadata
// lookup or an uncertain create must never supply qualifiedInstance.
func (inventory *OutputFixtureInventory) recordAction(index uint32, attempt, outcome, qualifiedInstance string) error {
	return inventory.change(func(candidate *OutputFixtureInventory) error {
		if uint64(index) >= uint64(len(candidate.Rows)) || outcome == "pending" {
			return errOutputInventory
		}
		row := &candidate.Rows[index]
		for i := range row.Attempts {
			result := &row.Attempts[i]
			if result.AttemptID != attempt {
				continue
			}
			if result.Outcome != "pending" {
				return errOutputInventory
			}
			create := result.Action == contract.PublicationCreateEmpty || result.Action == contract.PublicationCreateWithValue
			if create && outcome == "acknowledged" {
				if !validOutputText(qualifiedInstance, 1024) {
					return errOutputInventory
				}
				row.OwnedInstance, row.BirthAttemptID = qualifiedInstance, attempt
			} else if qualifiedInstance != "" {
				return errOutputInventory
			}
			result.Outcome = outcome
			return nil
		}
		return errOutputInventory
	})
}

// WriteOutputFixtureJoined is called only after a positive supervised writer
// group join. The exact writer and run scope are required by fixture cleanup.
func WriteOutputFixtureJoined(path string, scope OutputFixtureScope) error {
	if !validOutputScope(scope) || WriteJSONExclusive(path, OutputFixtureJoined{SchemaVersion: 1, Scope: scope, Joined: true}, MaximumOutputFixtureInventoryBytes) != nil {
		return errOutputInventory
	}
	return nil
}

func ReadOutputFixtureJoined(path string, scope OutputFixtureScope) error {
	var joined OutputFixtureJoined
	if !validOutputScope(scope) || !privateOutputRecord(path) || ReadJSONLimit(path, &joined, MaximumOutputFixtureInventoryBytes) != nil || joined.SchemaVersion != 1 || joined.Scope != scope || !joined.Joined {
		return errOutputInventory
	}
	return nil
}

// BeginOutputFixtureCleanup durably reserves the row's one fixture cleanup
// attempt, after the matching writer has stopped. It cannot authorize a retry.
func BeginOutputFixtureCleanup(path string, scope OutputFixtureScope, index uint32, attempt, joinedPath string) error {
	if ReadOutputFixtureJoined(joinedPath, scope) != nil {
		return errOutputInventory
	}
	inventory, err := ReadOutputFixtureInventory(path, scope)
	if err != nil {
		return errOutputInventory
	}
	if inventory.change(func(candidate *OutputFixtureInventory) error {
		if uint64(index) >= uint64(len(candidate.Rows)) || candidate.Rows[index].Cleanup != nil {
			return errOutputInventory
		}
		candidate.Rows[index].Cleanup = &OutputFixtureCleanup{AttemptID: attempt, Outcome: "pending"}
		return nil
	}) != nil || writeOutputFixtureInventory(path, inventory) != nil {
		return errOutputInventory
	}
	return nil
}

func (inventory *OutputFixtureInventory) recordCleanup(index uint32, attempt, outcome string) error {
	return inventory.change(func(candidate *OutputFixtureInventory) error {
		if uint64(index) >= uint64(len(candidate.Rows)) || outcome == "pending" {
			return errOutputInventory
		}
		cleanup := candidate.Rows[index].Cleanup
		if cleanup == nil || cleanup.AttemptID != attempt || cleanup.Outcome != "pending" {
			return errOutputInventory
		}
		cleanup.Outcome = outcome
		return nil
	})
}

func (inventory OutputFixtureInventory) validate(scope OutputFixtureScope) error {
	if !validOutputScope(scope) || inventory.SchemaVersion != 1 || inventory.Scope != scope || len(inventory.Rows) < 1 || len(inventory.Rows) > 10 || inventory.Actors == nil {
		return errOutputInventory
	}
	profiles := make(map[string]int)
	slots := make(map[string]bool)
	actors := make(map[string]bool)
	attempts := make(map[string]bool)
	for _, actor := range inventory.Actors {
		if !outputCloudProfile(actor.ProfileID) || actors[actor.ProfileID] || !validOutputText(actor.Writer, 1024) || !validOutputText(actor.ReaderA, 1024) || !validOutputText(actor.ReaderB, 1024) || actor.Writer == actor.ReaderA || actor.Writer == actor.ReaderB || actor.ReaderA == actor.ReaderB {
			return errOutputInventory
		}
		actors[actor.ProfileID] = true
	}
	for _, row := range inventory.Rows {
		key := row.ProfileID + "\x00" + row.PlannedSlot
		profiles[row.ProfileID]++
		if !validOutputProfile(row.ProfileID) || profiles[row.ProfileID] > 2 || !validOutputText(row.PlannedSlot, 1024) || !validOutputDigest(row.ExclusiveNamespaceDigest) || slots[key] || row.Attempts == nil || len(row.Attempts) > MaximumOutputFixtureAttempts || outputCloudProfile(row.ProfileID) && len(row.Attempts) > 0 && !actors[row.ProfileID] {
			return errOutputInventory
		}
		slots[key] = true
		birth, possibleCreate, pending := "", false, false
		for _, attempt := range row.Attempts {
			if !validOutputDigest(attempt.AttemptID) || attempts[attempt.AttemptID] || pending {
				return errOutputInventory
			}
			attempts[attempt.AttemptID] = true
			if attempt.Action == contract.PublicationUpdatePolicy && row.ProfileID != "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3" {
				return errOutputInventory
			}
			switch attempt.Outcome {
			case "pending", "acknowledged", "no_effect", "not_sent", "unknown":
			default:
				return errOutputInventory
			}
			switch attempt.Action {
			case contract.PublicationCreateEmpty, contract.PublicationCreateWithValue:
				if birth != "" || possibleCreate {
					return errOutputInventory
				}
				if attempt.Outcome == "acknowledged" {
					birth = attempt.AttemptID
				}
				possibleCreate = attempt.Outcome == "pending" || attempt.Outcome == "unknown" || attempt.Outcome == "acknowledged"
			case contract.PublicationWriteValue, contract.PublicationUpdatePolicy, contract.PublicationDeleteOwned:
				if birth == "" {
					return errOutputInventory
				}
			case contract.PublicationDeleteReservedSlot:
				if birth != "" || !possibleCreate {
					return errOutputInventory
				}
			default:
				return errOutputInventory
			}
			pending = attempt.Outcome == "pending"
		}
		if birth != row.BirthAttemptID || birth == "" && row.OwnedInstance != "" || birth != "" && !validOutputText(row.OwnedInstance, 1024) {
			return errOutputInventory
		}
		if cleanup := row.Cleanup; cleanup != nil {
			if !possibleCreate || !validOutputDigest(cleanup.AttemptID) || attempts[cleanup.AttemptID] {
				return errOutputInventory
			}
			attempts[cleanup.AttemptID] = true
			switch cleanup.Outcome {
			case "pending", "absent", "acknowledged", "unknown":
			case "scheduled":
				if row.ProfileID != "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3" {
					return errOutputInventory
				}
			default:
				return errOutputInventory
			}
		}
	}
	for profile := range actors {
		if profiles[profile] == 0 {
			return errOutputInventory
		}
	}
	return nil
}
