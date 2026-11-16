package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type configurationRecoveryEvidence struct {
	Race         *bool                           `json:"race,omitempty"`
	Provider     string                          `json:"provider"`
	RecoveryMode string                          `json:"recovery_mode"`
	Source       records.Source                  `json:"source"`
	RaceOptions  string                          `json:"race_options"`
	LossBarrier  bool                            `json:"loss_barrier"`
	Phases       []records.ProcessCompletion     `json:"phases"`
	Checks       installedarchive.RecoveryReport `json:"checks"`
}

func recoveryPhaseHelper(provider, phase string) string {
	switch phase {
	case "resource-owner":
		return "TestConfigurationRecoveryResourceOwner"
	case "setup", "writer":
		return "TestConfigurationRecoveryFixtureProcess"
	case "reconstruction-parent", "restricted-child":
		if provider == "aws" {
			return "TestRestrictedAWSReconstructionFromConsoleInputs"
		}
		if provider == "gcp" {
			return "TestRestrictedGCPReconstructionFromConsoleInputs"
		}
	}
	return ""
}

func configurationRecoveryOutcome(private configurationRecoveryProcessEvidence) configurationRecoveryEvidence {
	value := configurationRecoveryEvidence{Provider: private.Provider, RecoveryMode: "disabled", LossBarrier: private.LossBarrier, Checks: private.Report}
	if private.Recovery {
		value.RecoveryMode = "enabled"
	}
	for _, phase := range private.Phases {
		value.Phases = append(value.Phases, records.ProcessCompletion{Phase: phase.Phase, Helper: recoveryPhaseHelper(private.Provider, phase.Phase), Started: phase.Process.Started, Joined: phase.Process.Joined, Outcome: phase.Process.Status})
	}
	if len(private.Phases) != 0 && private.Phases[len(private.Phases)-1].Phase == "reconstruction-parent" && (private.Report.ChildStarted || private.Report.ChildJoined) {
		outcome := "unknown"
		if private.Report.ChildStarted && private.Report.ChildJoined && private.Phases[len(private.Phases)-1].Process.Status == "passed" {
			outcome = "passed"
		}
		value.Phases = append(value.Phases, records.ProcessCompletion{Phase: "restricted-child", Helper: recoveryPhaseHelper(private.Provider, "restricted-child"), Started: private.Report.ChildStarted, Joined: private.Report.ChildJoined, Outcome: outcome})
	}
	return value
}

func publicConfigurationRecovery(private configurationRecoveryProcessEvidence, source records.Source, race bool) (configurationRecoveryEvidence, error) {
	value := configurationRecoveryOutcome(private)
	value.Source, value.Race, value.RaceOptions = source, raceSetting(race), acceptedRaceOptions(race)
	for index, phase := range private.Phases {
		digest, err := assemblyFileSHA256(phase.Terminals)
		if err != nil {
			return value, errors.New("recovery terminal identity unavailable")
		}
		value.Phases[index].BinarySHA256, value.Phases[index].TerminalsSHA256 = phase.BinarySHA256, digest
	}
	if len(value.Phases) > len(private.Phases) {
		child := &value.Phases[len(private.Phases)]
		child.BinarySHA256 = private.Phases[len(private.Phases)-1].BinarySHA256
		child.TerminalsSHA256 = private.Report.ChildTerminalsSHA256
	}
	return value, nil
}

func expectedRecoveryRefusal(condition string) (installedarchive.RecoveryResult, bool) {
	switch condition {
	case "prior-domain-pin", "copied-location", "wrong-domain-pin":
		return installedarchive.RecoveryResult{Outcome: 5, Reason: 2}, true
	case "wrong-anchor", "recovery-proof-two-normal":
		return installedarchive.RecoveryResult{Outcome: 5, Reason: 4}, true
	case "recovery-only-inadequate", "recovery-proof-normal-only":
		return installedarchive.RecoveryResult{Outcome: 6, Reason: 12}, true
	case "required-public-denied":
		return installedarchive.RecoveryResult{Outcome: 6, Reason: 12}, true
	case "required-authority-denied", "recovery-key-only", "later-secret-denied", "wrong-kek-pin":
		return installedarchive.RecoveryResult{Outcome: 6, Reason: 17}, true
	case "wrong-owner":
		return installedarchive.RecoveryResult{Outcome: 6, Reason: 8}, true
	case "selected-object-disappears":
		return installedarchive.RecoveryResult{Outcome: 6, Reason: 7}, true
	case "wrong-locator":
		return installedarchive.RecoveryResult{Outcome: 7, Reason: 7}, true
	default:
		return installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}, false
	}
}

func validateConfigurationRecovery(value configurationRecoveryEvidence, cell catalog.RecoveryProcessCell, condition string, source records.Source, setup, driver string, race bool) bool {
	if !sameSource(value.Source, source) || !raceObservationMatches(value.Race, value.RaceOptions, race) || !validateConfigurationRecoverySemantics(value, cell, condition) {
		return false
	}
	for index, phase := range []string{"resource-owner", "setup", "writer", "reconstruction-parent", "restricted-child"} {
		binary := driver
		if index == 1 || index == 2 {
			binary = setup
		}
		if value.Phases[index].Validate(phase, recoveryPhaseHelper(value.Provider, phase), binary) != nil {
			return false
		}
	}
	return value.Phases[4].TerminalsSHA256 == value.Checks.ChildTerminalsSHA256
}

func validateConfigurationRecoverySemantics(value configurationRecoveryEvidence, cell catalog.RecoveryProcessCell, condition string) bool {
	if value.Provider != cell.Provider || value.RecoveryMode != cell.Recovery || !value.LossBarrier || len(value.Phases) != 5 || !value.Checks.ChildStarted || !value.Checks.ChildJoined || !value.Checks.RemoteEffectsZero || !value.Checks.OracleEpochSeparate || value.Checks.MutationJoined || value.Checks.MutationCounts != (installedarchive.RecoveryCounts{}) {
		return false
	}
	for index, name := range []string{"resource-owner", "setup", "writer", "reconstruction-parent", "restricted-child"} {
		phase := value.Phases[index]
		if phase.Phase != name || phase.Helper != recoveryPhaseHelper(value.Provider, name) || !phase.Started || !phase.Joined || phase.Outcome != "passed" {
			return false
		}
	}
	expected, refused := expectedRecoveryRefusal(condition)
	if value.Checks.Refused != refused || value.Checks.Result != expected {
		return false
	}
	opened := installedarchive.RecoverySecretCount(condition)
	if refused {
		opened = 0
	}
	if value.Checks.Opened != opened {
		return false
	}
	mutations := uint8(0)
	if condition == "selected-object-disappears" {
		mutations = 1
	}
	if value.Checks.ExternalMutations != mutations {
		return false
	}
	counts := value.Checks.Counts
	if counts.Reads > 4096 || counts.PublicLookups > 2 || counts.NormalLookups > 1 || counts.RecoveryLookups > 1 || counts.RecoveryMetadata > 1 || counts.AuthorityDecrypts > 512 || counts.PublicLookups != counts.NormalLookups+counts.RecoveryLookups {
		return false
	}
	if value.RecoveryMode == "disabled" && (counts.RecoveryLookups != 0 || counts.RecoveryMetadata != 0) {
		return false
	}

	wantNormal, wantRecovery, wantDecrypts := uint64(0), uint64(0), uint64(0)
	if !refused {
		wantNormal, wantDecrypts = 1, uint64(opened)
		history, replaced := installedarchive.ReplacementFor(condition)
		if condition == "recovery-proof-recovery-only" || condition == "recovery-proof-both" || replaced && len(history.Steps) > 0 && history.Steps[len(history.Steps)-1].Approval == 2 && history.Steps[len(history.Steps)-1].Mask&1 == 0 {
			wantNormal, wantRecovery = 0, 1
		}
		if condition == "adequate-anchor-fallback" {
			wantRecovery = 1
		}
		if counts.Reads == 0 {
			return false
		}
	} else {
		switch condition {
		case "required-public-denied", "wrong-kek-pin", "selected-object-disappears":
			wantNormal = 1
		case "required-authority-denied", "recovery-key-only":
			wantNormal, wantDecrypts = 1, 1
		case "later-secret-denied":
			wantNormal, wantDecrypts = 1, 5
		}
	}
	if counts.NormalLookups != wantNormal || counts.RecoveryLookups != wantRecovery || counts.PublicLookups != wantNormal+wantRecovery || counts.RecoveryMetadata != wantRecovery || counts.AuthorityDecrypts != wantDecrypts {
		return false
	}

	counts.Reads, counts.PublicLookups, counts.NormalLookups, counts.RecoveryLookups, counts.RecoveryMetadata, counts.AuthorityDecrypts = 0, 0, 0, 0, 0, 0
	return counts == (installedarchive.RecoveryCounts{})
}

func (s *runState) executeConfigurationRecovery(parent context.Context, state string, result *scenarioResult, completion *scenarioCompletion) error {
	row, known := recordedReconstruction(result.Scenario)
	if !known || s.recoverySetup == nil || s.record.Resolved == nil {
		return errors.New("recovery process assembly unavailable")
	}
	completion.entered, completion.started, completion.joined = true, time.Now(), true
	ctx, cancel := context.WithTimeout(parent, defaultWorkDuration)
	defer cancel()

	result.Cleanup = noCleanup()
	cells := recordedReconstructionCells(result.Scenario, s.record.Resolved.RecoveryMode)
	if len(cells) == 0 {
		return errors.New("recovery process cells unavailable")
	}
	for index, cell := range cells {
		driver, known := s.recoveryArtifacts[cell.Provider]
		if !known {
			return errors.New("ordinary recovery artifact unavailable")
		}
		directory := filepath.Join(state, fmt.Sprintf("recovery-%d", index))
		if err := os.Mkdir(directory, 0700); err != nil {
			return errors.New("private recovery case directory unavailable")
		}
		private, processErr := runConfigurationRecoveryProcessesOwned(s.preparation, ctx, s.root, directory, *s.recoverySetup, driver, cell.Recovery == "enabled", row.Condition, "")
		for _, phase := range private.Phases {
			completion.joined = completion.joined && phase.Process.Joined
		}
		semanticComplete := validateConfigurationRecoverySemantics(configurationRecoveryOutcome(private), cell, row.Condition)
		public, publicErr := publicConfigurationRecovery(private, s.record.Source, s.record.BuildClosure.Race)
		result.Reconstruction = append(result.Reconstruction, public)
		if saveErr := records.WriteJSON(filepath.Join(directory, "process-evidence.json"), private, 0600); saveErr != nil {
			return errors.Join(errors.New("private recovery process evidence unavailable"), processErr, publicErr, saveErr)
		}
		if processErr != nil || publicErr != nil || !semanticComplete {
			failure := errors.Join(errors.New("complete-loss process verification failed"), processErr)
			if containedCheckFailure(ctx, processErr) {
				failure = &localCheckFailure{cause: failure}
			}
			return errors.Join(failure, publicErr)
		}
	}
	completion.completed = true
	return nil
}

func reconstructionScenarioComplete(result scenarioResult, parent runRecord) bool {
	row, known := recordedReconstruction(result.Scenario)
	if parent.Suite == "live" {
		return liveReconstructionScenarioComplete(result, parent)
	}
	if !known || parent.Suite != "hermetic" || parent.Resolved == nil || parent.BuildClosure == nil || !reconstructionScenarioSemantics(result, parent.Resolved.RecoveryMode) {
		return false
	}
	cells := recordedReconstructionCells(result.Scenario, parent.Resolved.RecoveryMode)
	if len(cells) == 0 || len(result.Reconstruction) != len(cells) {
		return false
	}
	for index, cell := range cells {
		binary := ""
		for _, artifact := range parent.BuildClosure.ReconstructionArtifacts {
			if artifact.Provider == cell.Provider {
				if binary != "" || !artifact.NoCoreOverlay || !raceObservationMatches(artifact.Race, artifact.RaceOptions, parent.BuildClosure.Race) || !sameSource(artifact.Source, parent.Source) || len(artifact.ResolvedModules) == 0 || len(artifact.CompiledImports) == 0 {
					return false
				}
				binary = artifact.BinarySHA256
			}
		}
		if !validateConfigurationRecovery(result.Reconstruction[index], cell, row.Condition, parent.Source, parent.BuildClosure.BinarySHA256, binary, parent.BuildClosure.Race) {
			return false
		}
	}
	return true
}

func reconstructionScenarioSemantics(result scenarioResult, mode string) bool {
	row, known := recordedReconstruction(result.Scenario)
	if !known || result.Writer != nil || len(result.Children)+len(result.PostExit) != 0 || result.Rerun != nil || result.FirstFailure != nil || result.Cleanup.Outcome != "not_applicable" || result.CleanupWorker != nil {
		return false
	}
	cells := recordedReconstructionCells(result.Scenario, mode)
	if len(cells) == 0 || len(result.Reconstruction) != len(cells) {
		return false
	}
	for index, cell := range cells {
		if !validateConfigurationRecoverySemantics(result.Reconstruction[index], cell, row.Condition) {
			return false
		}
	}
	return true
}

func liveRecoverySecretCount(condition string) int {
	switch condition {
	case "zero-secret-genesis":
		return 0
	case "generated-retiring", "generated-uncertain":
		return 1
	case "mixed-generated", "generated-repeated-later", "later-secret-denied":
		return 5
	default:
		return 3
	}
}

func validateLiveConfigurationRecovery(v configurationRecoveryEvidence, mode, condition string, source records.Source, driver string, allowance installedarchive.RecoveryInput, race bool) bool {
	if !sameSource(v.Source, source) || !raceObservationMatches(v.Race, v.RaceOptions, race) || !validateLiveConfigurationRecoverySemantics(v, mode, condition, allowance) {
		return false
	}
	for index, phase := range []string{"reconstruction-parent", "restricted-child"} {
		if v.Phases[index].Validate(phase, recoveryPhaseHelper(v.Provider, phase), driver) != nil {
			return false
		}
	}
	return v.Checks.ChildTerminalsSHA256 == v.Phases[1].TerminalsSHA256
}

func validateLiveConfigurationRecoverySemantics(v configurationRecoveryEvidence, mode, condition string, allowance installedarchive.RecoveryInput) bool {
	if v.Provider != allowance.Provider || v.RecoveryMode != mode || !v.LossBarrier || len(v.Phases) != 2 {
		return false
	}
	for index, name := range []string{"reconstruction-parent", "restricted-child"} {
		phase := v.Phases[index]
		if phase.Phase != name || phase.Helper != recoveryPhaseHelper(v.Provider, name) || !phase.Started || !phase.Joined || phase.Outcome != "passed" {
			return false
		}
	}
	c := v.Checks
	expected, refused := expectedRecoveryRefusal(condition)
	if c.Result != expected || c.Refused != refused || !c.ChildStarted || !c.ChildJoined || !c.RemoteEffectsZero || !c.OracleEpochSeparate || c.SnapshotReadsBefore == 0 || c.SnapshotReadsBefore != c.SnapshotReadsAfter || c.ReservedRequests == 0 || c.ReservedRequests > allowance.Requests || c.ReservedBytes > allowance.BodyBytes {
		return false
	}
	if condition == "selected-object-disappears" {
		counts := c.MutationCounts
		counts.Delete, counts.Authentication = 0, 0
		if c.ExternalMutations != 1 || !c.MutationJoined || c.MutationCounts.Delete != 1 || c.MutationCounts.Authentication > 4096 || counts != (installedarchive.RecoveryCounts{}) {
			return false
		}
	} else if c.ExternalMutations != 0 || c.MutationJoined || c.MutationCounts != (installedarchive.RecoveryCounts{}) {
		return false
	}
	opened := liveRecoverySecretCount(condition)
	if refused {
		opened = 0
	}
	if c.Opened != opened {
		return false
	}
	permitted := func(counts installedarchive.RecoveryCounts, oracle bool) bool {
		if counts.Reads > 4096 || counts.Authentication > 4096 || counts.AuthorityDecrypts > 512 || counts.PublicLookups > 2 || counts.NormalLookups > 1 || counts.RecoveryLookups > 1 || counts.RecoveryMetadata > 1 || counts.PublicLookups != counts.NormalLookups+counts.RecoveryLookups {
			return false
		}
		if oracle && (counts.Reads != 0 || counts.PublicLookups != 0 || counts.RecoveryMetadata != 0) {
			return false
		}
		counts.Reads, counts.Authentication, counts.PublicLookups, counts.NormalLookups, counts.RecoveryLookups, counts.RecoveryMetadata, counts.AuthorityDecrypts = 0, 0, 0, 0, 0, 0, 0
		return counts == (installedarchive.RecoveryCounts{})
	}
	if !permitted(c.Counts, false) || !permitted(c.Attempted, false) || !permitted(c.RefusedRequests, false) || !permitted(c.Injected, false) || !permitted(c.OracleCounts, true) {
		return false
	}
	sum := installedarchive.RecoveryCounts{Reads: c.Counts.Reads + c.RefusedRequests.Reads + c.Injected.Reads, Authentication: c.Counts.Authentication + c.RefusedRequests.Authentication + c.Injected.Authentication, AuthorityDecrypts: c.Counts.AuthorityDecrypts + c.RefusedRequests.AuthorityDecrypts + c.Injected.AuthorityDecrypts, PublicLookups: c.Counts.PublicLookups + c.RefusedRequests.PublicLookups + c.Injected.PublicLookups, NormalLookups: c.Counts.NormalLookups + c.RefusedRequests.NormalLookups + c.Injected.NormalLookups, RecoveryLookups: c.Counts.RecoveryLookups + c.RefusedRequests.RecoveryLookups + c.Injected.RecoveryLookups, RecoveryMetadata: c.Counts.RecoveryMetadata + c.RefusedRequests.RecoveryMetadata + c.Injected.RecoveryMetadata}
	if sum != c.Attempted || c.RefusedRequests != (installedarchive.RecoveryCounts{}) || !refused && c.OracleCounts.AuthorityDecrypts != uint64(opened) || refused && c.OracleCounts != (installedarchive.RecoveryCounts{}) {
		return false
	}
	normal, recoveryLookups, decrypts := uint64(0), uint64(0), uint64(0)
	if !refused {
		normal, decrypts = 1, uint64(opened)
		history, replaced := installedarchive.ReplacementFor(condition)
		if condition == "recovery-proof-recovery-only" || condition == "recovery-proof-both" || replaced && len(history.Steps) > 0 && history.Steps[len(history.Steps)-1].Approval == 2 && history.Steps[len(history.Steps)-1].Mask&1 == 0 {
			normal, recoveryLookups = 0, 1
		}
		if condition == "adequate-anchor-fallback" {
			recoveryLookups = 1
		}
		if c.Counts.Reads == 0 {
			return false
		}
	} else {
		switch condition {
		case "required-public-denied", "wrong-kek-pin", "selected-object-disappears":
			normal = 1
		case "required-authority-denied", "recovery-key-only":
			normal, decrypts = 1, 1
		case "later-secret-denied":
			normal, decrypts = 1, 5
		}
	}
	injected := installedarchive.RecoveryCounts{}
	switch condition {
	case "adequate-anchor-fallback", "required-public-denied":
		injected.PublicLookups, injected.NormalLookups = 1, 1
	case "required-authority-denied", "recovery-key-only", "later-secret-denied":
		injected.AuthorityDecrypts = 1
	}
	if c.ProviderDenial {
		switch condition {
		case "required-public-denied", "required-authority-denied", "recovery-key-only":
			injected = installedarchive.RecoveryCounts{}
		default:
			return false
		}
	}
	if c.Injected != injected || c.Attempted.NormalLookups != normal || c.Attempted.RecoveryLookups != recoveryLookups || c.Attempted.PublicLookups != normal+recoveryLookups || c.Attempted.RecoveryMetadata != recoveryLookups || c.Attempted.AuthorityDecrypts != decrypts {
		return false
	}
	return true
}

func liveReconstructionScenarioComplete(result scenarioResult, parent runRecord) bool {
	row, known := recordedReconstruction(result.Scenario)
	if !known || parent.Resolved == nil || parent.BuildClosure == nil || result.Writer == nil || result.Rerun != nil || result.FirstFailure != nil || len(result.PostExit) != 0 || len(result.Reconstruction) != 1 || !cleanupPassed(result.Cleanup) || result.CleanupWorker == nil || result.CleanupRetryBlocker != "" {
		return false
	}
	execution, known := recordedExecution(result.Scenario, "live")
	participants, err := parent.Resolved.scenarioParticipants(result.Scenario)
	if !known || err != nil || len(result.Children) != len(execution.ExpandedFreshBefore()) {
		return false
	}
	for index, child := range result.Children {
		expected := execution.ExpandedFreshBefore()[index]
		step := expected.Step
		if child.Role != "fresh_before" || child.RecoveryMode != parent.Resolved.RecoveryMode || !completeWorkerPhases(child.Role, child.Actor, child.Phases, result.Scenario, "live", participants, nil, child.RecoveryMode, &step) {
			return false
		}
	}
	seen := map[string]bool{}
	for _, worker := range scenarioWorkers(result) {
		if seen[worker.Worker] || !telemetryLabel.MatchString(worker.Worker) || !raceObservationMatches(worker.Race, worker.RaceOptions, parent.BuildClosure.Race) || worker.Failure != nil || worker.Outcome != "passed" || worker.Process != "passed" || !worker.Joined || worker.Assertions == nil || !worker.Assertions.PermitsSuccess() || worker.Assertions.Validate() != nil {
			return false
		}
		seen[worker.Worker] = true
		if worker.Role != "fresh_before" && !completeWorkerPhases(worker.Role, worker.Actor, worker.Phases, result.Scenario, "live", participants, &result.Cleanup, worker.RecoveryMode, nil) {
			return false
		}
	}
	driver := ""
	for _, artifact := range parent.BuildClosure.ReconstructionArtifacts {
		if artifact.Provider == parent.Provider {
			if driver != "" || !artifact.NoCoreOverlay || !raceObservationMatches(artifact.Race, artifact.RaceOptions, parent.BuildClosure.Race) || !sameSource(artifact.Source, parent.Source) || len(artifact.ResolvedModules) == 0 || len(artifact.CompiledImports) == 0 {
				return false
			}
			driver = artifact.BinarySHA256
		}
	}
	return validateLiveConfigurationRecovery(result.Reconstruction[0], parent.Resolved.RecoveryMode, row.Condition, parent.Source, driver, installedarchive.RecoveryInput{Provider: parent.Provider, Requests: 4096, BodyBytes: maximumBudgetBodyBytes}, parent.BuildClosure.Race)
}
