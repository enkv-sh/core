package records

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"syscall"
	"time"
)

var generatorID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var generatorAttempt = regexp.MustCompile(`^[0-9a-f]{64}$`)

type GeneratorFixtureResource struct {
	ID             string   `json:"id"`
	CreateAttempt  string   `json:"create_attempt"`
	Disposition    string   `json:"disposition"`
	DeleteAttempts []string `json:"delete_attempts,omitempty"`
}

// GeneratorFixtureLedger is private test cleanup state. A token ID here is a
// cleanup target only; it is never an enkv ownership or result assertion.
type GeneratorFixtureLedger struct {
	SchemaVersion  int                        `json:"schema_version"`
	RunID          string                     `json:"run_id"`
	Provider       string                     `json:"provider"`
	Account        string                     `json:"account"`
	PendingCreates []string                   `json:"pending_creates"`
	Resources      []GeneratorFixtureResource `json:"resources"`
}

// GeneratorFixtureJoined is written only after the supervised writer process
// group has stopped. Cleanup must not infer quiescence from a ledger ID.
type GeneratorFixtureJoined struct {
	SchemaVersion int    `json:"schema_version"`
	RunID         string `json:"run_id"`
	Scenario      string `json:"scenario"`
	Joined        bool   `json:"joined"`
}

func WriteGeneratorFixtureJoined(path, runID, scenario string) error {
	if !ValidRunID(runID) || scenario == "" {
		return errors.New("generator fixture join refused")
	}
	return WriteJSON(path, GeneratorFixtureJoined{SchemaVersion: 1, RunID: runID, Scenario: scenario, Joined: true}, 0400)
}

func ReadGeneratorFixtureJoined(path, runID, scenario string) error {
	var joined GeneratorFixtureJoined
	if !ValidRunID(runID) || scenario == "" || ReadJSON(path, &joined) != nil ||
		joined.SchemaVersion != 1 || joined.RunID != runID || joined.Scenario != scenario || !joined.Joined {
		return errors.New("generator fixture join unavailable")
	}
	return nil
}

func NewGeneratorFixtureLedger(path, runID, account string) error {
	if !ValidRunID(runID) || !generatorID.MatchString(account) {
		return errors.New("generator fixture ledger refused")
	}
	return generatorFixtureLedgerTransaction(path, func() error {
		return WriteJSONExclusive(path, GeneratorFixtureLedger{SchemaVersion: 1, RunID: runID, Provider: "cloudflare", Account: account,
			PendingCreates: []string{}, Resources: []GeneratorFixtureResource{}}, MaximumJSONBytes)
	})
}

func ReadGeneratorFixtureLedger(path, runID, account string) (GeneratorFixtureLedger, error) {
	refused := errors.New("generator fixture ledger refused")
	var ledger GeneratorFixtureLedger
	if !ValidRunID(runID) || !generatorID.MatchString(account) || ReadJSON(path, &ledger) != nil ||
		validateGeneratorFixtureLedger(ledger, runID, account) != nil {
		return GeneratorFixtureLedger{}, refused
	}
	return ledger, nil
}

func validateGeneratorFixtureLedger(ledger GeneratorFixtureLedger, runID, account string) error {
	refused := errors.New("generator fixture ledger refused")
	if !ValidRunID(runID) || !generatorID.MatchString(account) ||
		ledger.SchemaVersion != 1 || ledger.RunID != runID || ledger.Provider != "cloudflare" || ledger.Account != account ||
		ledger.PendingCreates == nil || ledger.Resources == nil {
		return refused
	}
	seenAttempts := make(map[string]bool)
	for _, attempt := range ledger.PendingCreates {
		if !generatorAttempt.MatchString(attempt) || seenAttempts[attempt] {
			return refused
		}
		seenAttempts[attempt] = true
	}
	seenResources := make(map[string]bool)
	for _, resource := range ledger.Resources {
		if !generatorID.MatchString(resource.ID) || seenResources[resource.ID] || resource.Disposition != "owned" && resource.Disposition != "retired" {
			return refused
		}
		seenResources[resource.ID] = true
		if !generatorAttempt.MatchString(resource.CreateAttempt) || seenAttempts[resource.CreateAttempt] {
			return refused
		}
		seenAttempts[resource.CreateAttempt] = true
		for _, attempt := range resource.DeleteAttempts {
			if !generatorAttempt.MatchString(attempt) || seenAttempts[attempt] {
				return refused
			}
			seenAttempts[attempt] = true
		}
	}
	return nil
}

func UpdateGeneratorFixtureLedger(path, runID, account string, change func(*GeneratorFixtureLedger) error) error {
	if change == nil {
		return errors.New("generator fixture ledger refused")
	}
	return generatorFixtureLedgerTransaction(path, func() error {
		ledger, err := ReadGeneratorFixtureLedger(path, runID, account)
		if err != nil || change(&ledger) != nil || validateGeneratorFixtureLedger(ledger, runID, account) != nil {
			return errors.New("generator fixture ledger refused")
		}
		return WriteJSON(path, ledger, 0600)
	})
}

func (ledger *GeneratorFixtureLedger) BeginCreate(attempt string) error {
	if !generatorAttempt.MatchString(attempt) || slices.Contains(ledger.PendingCreates, attempt) {
		return errors.New("generator fixture create refused")
	}
	for _, resource := range ledger.Resources {
		if resource.CreateAttempt == attempt || slices.Contains(resource.DeleteAttempts, attempt) {
			return errors.New("generator fixture create refused")
		}
	}
	ledger.PendingCreates = append(ledger.PendingCreates, attempt)
	return nil
}

func (ledger *GeneratorFixtureLedger) RecordCreate(attempt, id string) error {
	index := slices.Index(ledger.PendingCreates, attempt)
	if index < 0 || !generatorID.MatchString(id) || slices.ContainsFunc(ledger.Resources, func(resource GeneratorFixtureResource) bool { return resource.ID == id }) {
		return errors.New("generator fixture create result refused")
	}
	ledger.PendingCreates = slices.Delete(ledger.PendingCreates, index, index+1)
	ledger.Resources = append(ledger.Resources, GeneratorFixtureResource{ID: id, CreateAttempt: attempt, Disposition: "owned"})
	return nil
}

func (ledger *GeneratorFixtureLedger) BeginDelete(attempt, id string) error {
	if !generatorAttempt.MatchString(attempt) || !generatorID.MatchString(id) || slices.Contains(ledger.PendingCreates, attempt) {
		return errors.New("generator fixture delete refused")
	}
	for _, resource := range ledger.Resources {
		if resource.CreateAttempt == attempt || slices.Contains(resource.DeleteAttempts, attempt) {
			return errors.New("generator fixture delete refused")
		}
	}
	for i := range ledger.Resources {
		resource := &ledger.Resources[i]
		if resource.ID == id && resource.Disposition == "owned" {
			resource.DeleteAttempts = append(resource.DeleteAttempts, attempt)
			return nil
		}
	}
	return errors.New("generator fixture delete refused")
}

func (ledger *GeneratorFixtureLedger) RecordDelete(attempt, id string) error {
	for i := range ledger.Resources {
		resource := &ledger.Resources[i]
		if resource.ID == id && resource.Disposition == "owned" && slices.Contains(resource.DeleteAttempts, attempt) {
			resource.Disposition = "retired"
			return nil
		}
	}
	return errors.New("generator fixture delete result refused")
}

func (ledger GeneratorFixtureLedger) CleanupTargets() []string {
	var targets []string
	for _, resource := range ledger.Resources {
		if resource.Disposition == "owned" {
			targets = append(targets, resource.ID)
		}
	}
	return targets
}

func (ledger GeneratorFixtureLedger) Clean() bool {
	return len(ledger.PendingCreates) == 0 && len(ledger.CleanupTargets()) == 0
}

// All ledger writers hold the same stable sibling lock from the initial read
// through the synced file replacement and directory sync. The lock is bounded;
// contention is a refusal and never an entered-effect or success assertion.
func generatorFixtureLedgerTransaction(path string, change func() error) (result error) {
	refused := errors.New("generator fixture ledger transaction refused")
	if safeAbsolute(path) != nil {
		return refused
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return refused
	}
	defer func() {
		if lock.Close() != nil {
			result = errors.Join(result, refused)
		}
	}()
	info, err := lock.Stat()
	stat, owned := infoSysGeneratorLock(info)
	if err != nil || !owned || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return refused
	}
	deadline := time.Now().Add(time.Second)
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN || !time.Now().Before(deadline) {
			return refused
		}
		time.Sleep(5 * time.Millisecond)
	}
	defer func() {
		if syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) != nil {
			result = errors.Join(result, refused)
		}
	}()
	current, err := os.Lstat(path + ".lock")
	if err != nil || !current.Mode().IsRegular() || !SameLocalFile(info, current) || safeAbsolute(path) != nil {
		return refused
	}
	return change()
}
func infoSysGeneratorLock(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
