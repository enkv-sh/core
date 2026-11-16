package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

// full_only: false
func TestConfigurationRecoveryEvidenceRejectsIncompleteProof(t *testing.T) {
	setup, driver, terminal := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	source := records.Source{Revision: strings.Repeat("d", 40)}
	cell := catalog.RecoveryProcessCell{Provider: "aws", Recovery: "disabled"}
	value := configurationRecoveryEvidence{Provider: "aws", RecoveryMode: "disabled", Source: source, RaceOptions: raceOptions, LossBarrier: true,
		Checks: installedarchive.RecoveryReport{ChildStarted: true, ChildJoined: true, ChildTerminalsSHA256: terminal, Result: installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}, Opened: 5, RemoteEffectsZero: true, OracleEpochSeparate: true, Counts: installedarchive.RecoveryCounts{Reads: 12, PublicLookups: 1, NormalLookups: 1, AuthorityDecrypts: 5}}}
	for _, phase := range []string{"resource-owner", "setup", "writer", "reconstruction-parent", "restricted-child"} {
		binary := driver
		if phase == "setup" || phase == "writer" {
			binary = setup
		}
		value.Phases = append(value.Phases, records.ProcessCompletion{Phase: phase, Helper: recoveryPhaseHelper("aws", phase), BinarySHA256: binary, TerminalsSHA256: terminal, Started: true, Joined: true, Outcome: "passed"})
	}
	if !validateConfigurationRecovery(value, cell, "complete", source, setup, driver, true) {
		t.Fatal("complete evidence refused")
	}
	private := configurationRecoveryProcessEvidence{Provider: "aws", LossBarrier: true, Report: value.Checks}
	private.Report.ChildTerminalsSHA256 = ""
	for _, phase := range value.Phases[:4] {
		private.Phases = append(private.Phases, configurationRecoveryPhase{Phase: phase.Phase, Process: processResult{Status: phase.Outcome, Started: phase.Started, Joined: phase.Joined}})
	}
	if !validateConfigurationRecoverySemantics(configurationRecoveryOutcome(private), cell, "complete") {
		t.Fatal("current semantic completion required stored proof identities")
	}
	for _, row := range []struct {
		name   string
		change func(*configurationRecoveryEvidence)
	}{
		{"provider", func(v *configurationRecoveryEvidence) { v.Provider = "gcp" }},
		{"mode", func(v *configurationRecoveryEvidence) { v.RecoveryMode = "enabled" }},
		{"source", func(v *configurationRecoveryEvidence) { v.Source.Revision = strings.Repeat("e", 40) }},
		{"race", func(v *configurationRecoveryEvidence) { v.RaceOptions = "" }},
		{"loss", func(v *configurationRecoveryEvidence) { v.LossBarrier = false }},
		{"phase-order", func(v *configurationRecoveryEvidence) { v.Phases[1], v.Phases[2] = v.Phases[2], v.Phases[1] }},
		{"missing-phase", func(v *configurationRecoveryEvidence) { v.Phases = v.Phases[:4] }},
		{"wrong-binary", func(v *configurationRecoveryEvidence) { v.Phases[4].BinarySHA256 = setup }},
		{"child-join", func(v *configurationRecoveryEvidence) { v.Checks.ChildJoined = false }},
		{"child-terminal", func(v *configurationRecoveryEvidence) { v.Checks.ChildTerminalsSHA256 = setup }},
		{"wrong-result", func(v *configurationRecoveryEvidence) { v.Checks.Result.Outcome = 7 }},
		{"extra-decrypt", func(v *configurationRecoveryEvidence) { v.Checks.Counts.AuthorityDecrypts = 6 }},
		{"wrong-lookup-total", func(v *configurationRecoveryEvidence) { v.Checks.Counts.PublicLookups = 2 }},
		{"partial-content", func(v *configurationRecoveryEvidence) { v.Checks.Opened = 4 }},
		{"refused-content", func(v *configurationRecoveryEvidence) { v.Checks.Refused = true }},
		{"remote-effect", func(v *configurationRecoveryEvidence) { v.Checks.RemoteEffectsZero = false }},
		{"oracle-epoch", func(v *configurationRecoveryEvidence) { v.Checks.OracleEpochSeparate = false }},
		{"unexpected-mutation-join", func(v *configurationRecoveryEvidence) { v.Checks.MutationJoined = true }},
		{"unexpected-mutation-counter", func(v *configurationRecoveryEvidence) { v.Checks.MutationCounts.Delete = 1 }},
		{"external-effect", func(v *configurationRecoveryEvidence) { v.Checks.ExternalMutations = 1 }},
		{"missing-public", func(v *configurationRecoveryEvidence) {
			v.Checks.Counts.PublicLookups = 0
			v.Checks.Counts.NormalLookups = 0
		}},
		{"missing-secret", func(v *configurationRecoveryEvidence) { v.Checks.Counts.AuthorityDecrypts = 4 }},
		{"unused-recovery", func(v *configurationRecoveryEvidence) { v.Checks.Counts.RecoveryMetadata = 1 }},
		{"unknown", func(v *configurationRecoveryEvidence) { v.Checks.Counts.Unknown = 1 }},
		{"other-decrypt", func(v *configurationRecoveryEvidence) { v.Checks.Counts.OtherDecrypts = 1 }},
		{"write", func(v *configurationRecoveryEvidence) { v.Checks.Counts.StoreWrites = 1 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var damaged configurationRecoveryEvidence
			if err = json.Unmarshal(body, &damaged); err != nil {
				t.Fatal(err)
			}
			row.change(&damaged)
			if validateConfigurationRecovery(damaged, cell, "complete", source, setup, driver, true) {
				t.Fatal("incomplete evidence accepted")
			}
			proofOnly := row.name == "source" || row.name == "race" || row.name == "wrong-binary" || row.name == "child-terminal"
			if validateConfigurationRecoverySemantics(damaged, cell, "complete") != proofOnly {
				t.Fatal("current semantic validation changed a Product assertion or required proof identity")
			}
		})
	}
	refused := value
	refused.Checks.Refused = true
	refused.Checks.Result = installedarchive.RecoveryResult{Outcome: 6, Reason: 17}
	refused.Checks.Opened = 0
	refused.Checks.Counts.AuthorityDecrypts = 5
	if !validateConfigurationRecovery(refused, cell, "later-secret-denied", source, setup, driver, true) {
		t.Fatal("late complete refusal rejected")
	}
	refused.Checks.Opened = 1
	if validateConfigurationRecovery(refused, cell, "later-secret-denied", source, setup, driver, true) {
		t.Fatal("partial refused projection accepted")
	}
}

// full_only: false
func TestLiveConfigurationRecoveryFallbackEvidence(t *testing.T) {
	source := records.Source{Revision: strings.Repeat("d", 40)}
	driver, terminal := strings.Repeat("b", 64), strings.Repeat("c", 64)
	value := configurationRecoveryEvidence{Provider: "aws", RecoveryMode: "enabled", Source: source, RaceOptions: raceOptions, LossBarrier: true,
		Checks: installedarchive.RecoveryReport{ChildStarted: true, ChildJoined: true, ChildTerminalsSHA256: terminal, Result: installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}, Opened: 3, RemoteEffectsZero: true, OracleEpochSeparate: true, SnapshotReadsBefore: 11, SnapshotReadsAfter: 11, ReservedRequests: 46, ReservedBytes: 1000,
			Counts:    installedarchive.RecoveryCounts{Reads: 17, PublicLookups: 1, RecoveryLookups: 1, RecoveryMetadata: 1, AuthorityDecrypts: 3},
			Attempted: installedarchive.RecoveryCounts{Reads: 17, PublicLookups: 2, NormalLookups: 1, RecoveryLookups: 1, RecoveryMetadata: 1, AuthorityDecrypts: 3},
			Injected:  installedarchive.RecoveryCounts{PublicLookups: 1, NormalLookups: 1}, OracleCounts: installedarchive.RecoveryCounts{AuthorityDecrypts: 3}}}
	for _, phase := range []string{"reconstruction-parent", "restricted-child"} {
		value.Phases = append(value.Phases, records.ProcessCompletion{Phase: phase, Helper: recoveryPhaseHelper("aws", phase), BinarySHA256: driver, TerminalsSHA256: terminal, Started: true, Joined: true, Outcome: "passed"})
	}
	allowance := installedarchive.RecoveryInput{Provider: "aws", Requests: 4096, BodyBytes: 1 << 30}
	proofless := value
	proofless.Source, proofless.RaceOptions = records.Source{}, ""
	proofless.Phases = append([]records.ProcessCompletion(nil), value.Phases...)
	for index := range proofless.Phases {
		proofless.Phases[index].BinarySHA256, proofless.Phases[index].TerminalsSHA256 = "", ""
	}
	proofless.Checks.ChildTerminalsSHA256 = ""
	if !validateLiveConfigurationRecoverySemantics(proofless, "enabled", "adequate-anchor-fallback", allowance) {
		t.Fatal("live semantic completion required qualification identities")
	}
	if !validateLiveConfigurationRecovery(value, "enabled", "adequate-anchor-fallback", source, driver, allowance, true) {
		t.Fatal("qualified fallback with separately injected normal refusal rejected")
	}
	for _, row := range []struct {
		name   string
		change func(*configurationRecoveryEvidence)
	}{
		{"wrong-anchor", func(v *configurationRecoveryEvidence) {
			v.Checks.Injected = installedarchive.RecoveryCounts{PublicLookups: 1, RecoveryLookups: 1}
		}},
		{"other-operation", func(v *configurationRecoveryEvidence) {
			v.Checks.Injected = installedarchive.RecoveryCounts{AuthorityDecrypts: 1}
		}},
		{"missing-attempt", func(v *configurationRecoveryEvidence) { v.Checks.Attempted.NormalLookups = 0 }},
		{"false-physical-send", func(v *configurationRecoveryEvidence) {
			v.Checks.Counts.NormalLookups = 1
			v.Checks.Counts.PublicLookups = 2
		}},
		{"other-condition", func(v *configurationRecoveryEvidence) { v.Checks.Injected = installedarchive.RecoveryCounts{} }},
		{"missing-recovery", func(v *configurationRecoveryEvidence) { v.Checks.Counts.RecoveryLookups = 0 }},
		{"missing-metadata", func(v *configurationRecoveryEvidence) { v.Checks.Counts.RecoveryMetadata = 0 }},
		{"overflow-budget", func(v *configurationRecoveryEvidence) { v.Checks.ReservedRequests = 4097 }},
		{"partial-private", func(v *configurationRecoveryEvidence) { v.Checks.Opened = 2 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			damaged := value
			row.change(&damaged)
			if validateLiveConfigurationRecoverySemantics(damaged, "enabled", "adequate-anchor-fallback", allowance) {
				t.Fatal("current live semantic validation lost a Product assertion")
			}
			if validateLiveConfigurationRecovery(damaged, "enabled", "adequate-anchor-fallback", source, driver, allowance, true) {
				t.Fatal("incomplete fallback proof accepted")
			}
		})
	}
	if validateLiveConfigurationRecovery(value, "enabled", "complete", source, driver, allowance, true) {
		t.Fatal("injection admitted for unrelated condition")
	}

}

// full_only: false
func TestLiveConfigurationRecoveryProviderDenialEvidence(t *testing.T) {
	source := records.Source{Revision: strings.Repeat("d", 40)}
	driver, terminal := strings.Repeat("b", 64), strings.Repeat("c", 64)
	value := configurationRecoveryEvidence{Provider: "aws", RecoveryMode: "disabled", Source: source, RaceOptions: raceOptions, LossBarrier: true,
		Checks: installedarchive.RecoveryReport{ProviderDenial: true, ChildStarted: true, ChildJoined: true, ChildTerminalsSHA256: terminal, Result: installedarchive.RecoveryResult{Outcome: 6, Reason: 17}, Refused: true, RemoteEffectsZero: true, OracleEpochSeparate: true, SnapshotReadsBefore: 11, SnapshotReadsAfter: 11, ReservedRequests: 40, ReservedBytes: 1000,
			Counts: installedarchive.RecoveryCounts{Reads: 17, PublicLookups: 1, NormalLookups: 1, AuthorityDecrypts: 1}, Attempted: installedarchive.RecoveryCounts{Reads: 17, PublicLookups: 1, NormalLookups: 1, AuthorityDecrypts: 1}}}
	for _, phase := range []string{"reconstruction-parent", "restricted-child"} {
		value.Phases = append(value.Phases, records.ProcessCompletion{Phase: phase, Helper: recoveryPhaseHelper("aws", phase), BinarySHA256: driver, TerminalsSHA256: terminal, Started: true, Joined: true, Outcome: "passed"})
	}
	allowance := installedarchive.RecoveryInput{Provider: "aws", Requests: 4096, BodyBytes: 1 << 30}
	if !validateLiveConfigurationRecovery(value, "disabled", "required-authority-denied", source, driver, allowance, true) {
		t.Fatal("actual provider denial confused with injected request")
	}
	for _, condition := range []string{"complete", "adequate-anchor-fallback", "later-secret-denied"} {
		if validateLiveConfigurationRecovery(value, "disabled", condition, source, driver, allowance, true) {
			t.Fatal("provider denial accepted for unrelated condition")
		}
	}
	value.Checks.Injected.AuthorityDecrypts = 1
	if validateLiveConfigurationRecovery(value, "disabled", "required-authority-denied", source, driver, allowance, true) {
		t.Fatal("injected request relabelled as provider denial")
	}
}

// full_only: false
func TestLiveRecoveryLossRemovesEverySavedConfigurationDirectory(t *testing.T) {
	state := t.TempDir()
	for _, name := range []string{"workers", "parent-oracle", "saved-client", "basis-cache", "generator-config"} {
		if err := os.Mkdir(filepath.Join(state, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(state, name, "basis.json"), []byte("private fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"inventory.json", "inventory.lock", "recovery-parent.json", "generator-cleanup.json", "generator-writer-joined.json", "input.json", "facts.json", "generator-saved-settings.json"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := retireLiveRecoveryConfiguration(state); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"saved-client", "basis-cache", "generator-config", "input.json", "facts.json", "generator-saved-settings.json"} {
		if _, err := os.Lstat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Fatal("saved configuration survived", name)
		}
	}
	for _, name := range []string{"workers", "parent-oracle", "inventory.json", "inventory.lock", "recovery-parent.json", "generator-cleanup.json", "generator-writer-joined.json"} {
		if _, err := os.Lstat(filepath.Join(state, name)); err != nil {
			t.Fatal("owned evidence or cleanup state missing", name)
		}
	}
}

// full_only: false
func TestLiveRecoveryLossRefusesSubstitutedRetentionOwners(t *testing.T) {
	for _, name := range []string{"workers", "parent-oracle", "inventory.json", "generator-cleanup.json"} {
		t.Run(name, func(t *testing.T) {
			state := t.TempDir()
			outside := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(state, name)); err != nil {
				t.Fatal(err)
			}
			saved := filepath.Join(state, "input.json")
			if err := os.WriteFile(saved, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if retireLiveRecoveryConfiguration(state) == nil {
				t.Fatal("substituted retained owner accepted")
			}
			if _, err := os.Lstat(saved); err != nil {
				t.Fatal("loss began before complete retention validation")
			}
		})
	}
}
