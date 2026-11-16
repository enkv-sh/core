package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	records "enkv.sh/core/internal/testrecords"
)

// scenarioCompletion belongs to one executeScenario call. Detailed worker,
// assertion and cleanup evidence remains in the scenario's existing records.
type scenarioCompletion struct {
	entered, completed, joined bool
	started                    time.Time
	failure                    *records.Failure
	oracleDirectory            string
	participants               *scenarioParticipants
}

type scenarioParticipants struct {
	state               string
	input, cleanupInput workerInput
	writer              records.Invocation
	writerProcess       processResult
}

// completeScenario is the only terminal scenario outcome writer. Workload and
// positive join facts are captured before cleanup and private disposal run.
func (s *runState) completeScenario(ctx context.Context, binary string, allowance limits, result *scenarioResult, completion *scenarioCompletion, workloadErr error) error {
	correct := completion.entered && completion.completed && completion.joined && completion.failure == nil && workloadErr == nil
	failure := completion.failure
	if completion.entered {
		result.WorkloadElapsed = time.Since(completion.started)
	}
	if !correct {
		if workloadErr == nil {
			workloadErr = errors.New("scenario workload completion unavailable")
		}
		if failure == nil {
			failure = &records.Failure{Class: "scenario_setup_failed", Stage: "setup"}
			if completion.entered {
				failure = &records.Failure{Class: "scenario_failed", Stage: "execution"}
			}
		}
	}
	// Existing cleanup admission and its saved retry receipts consume these
	// immutable workload facts before terminal cleanup has settled.
	result.CorrectnessPassed, result.Failure = correct, failure
	finalizationErr := s.finishScenarioParticipants(ctx, binary, allowance, result, completion)
	var retentionErr error
	if correct && finalizationErr == nil && result.Scenario == records.StockPluginScenario {
		retentionErr = s.retainStockPluginEvidence(result, completion.participants)
		if retentionErr != nil {
			s.exportFilesError = errors.Join(s.exportFilesError, retentionErr)
			s.record.ExportFilesStatus = "incomplete"
			result.Failure = &records.Failure{Class: "public_configuration_evidence_unavailable", Stage: "evidence"}
		} else if s.exportFilesError == nil {
			s.record.ExportFilesStatus = "complete"
		}
	}
	if correct && finalizationErr == nil && publicConfigurationEvidenceRequired(s.record, *result) {
		retentionErr = s.retainPublicConfigurationEvidence(result, completion.participants)
		if retentionErr != nil {
			s.exportFilesError = errors.Join(s.exportFilesError, retentionErr)
			s.record.ExportFilesStatus = "incomplete"
			result.Failure = &records.Failure{Class: "public_configuration_evidence_unavailable", Stage: "evidence"}
		} else if s.exportFilesError == nil {
			s.record.ExportFilesStatus = "complete"
		}
	}
	var disposalErr error
	if completion.oracleDirectory != "" {
		disposalErr = disposePrivateOracle(completion.oracleDirectory)
	}
	if correct && disposalErr != nil {
		result.Failure = &records.Failure{Class: "private_oracle_cleanup_failed", Stage: "cleanup"}
	}
	err := errors.Join(workloadErr, finalizationErr, retentionErr, disposalErr)
	result.Outcome = "failed"
	if correct && err == nil {
		result.Outcome = "passed"
	}
	return err
}

// Keep the existing durable join markers, route retirement, cleanup admission
// and finite retry order. Admission failures cannot erase actual join facts.
func (s *runState) finishScenarioParticipants(ctx context.Context, binary string, allowance limits, result *scenarioResult, completion *scenarioCompletion) (err error) {
	participants := completion.participants
	if participants == nil {
		return nil
	}
	state, input, cleanupInput, inv := participants.state, participants.input, participants.cleanupInput, participants.writer
	joined := completion.joined
	if input.Outputs != nil {
		if markerErr := writePublicationJoined(input.Outputs, inv, participants.writerProcess, joined); markerErr != nil {
			joined = false
			err = errors.Join(err, markerErr)
		} else if removeErr := removePublicationRoutes(input.Outputs); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
	}
	if s.record.Suite == "live" && input.Generator != nil && joined {
		marker, markerErr := records.SafePath(state, "generator-writer-joined.json")
		if markerErr == nil {
			markerErr = records.WriteGeneratorFixtureJoined(marker, input.RunID, input.Scenarios[0])
		}
		if markerErr != nil {
			joined = false
			err = errors.Join(err, errors.New("generator process groups join proof unavailable"))
		}
	}
	if s.record.Suite == "live" {
		cleanupStarted := time.Now()
		if joined {
			cleanupPath := filepath.Join(state, "cleanup-input.json")
			var prepareErr error
			if input.Outputs == nil {
				prepareErr = records.WriteJSON(cleanupPath, cleanupInput, 0400)
			} else {
				var retained workerInput
				if records.ReadJSON(cleanupPath, &retained) != nil || !reflect.DeepEqual(retained, cleanupInput) {
					prepareErr = errPublicationInput
				}
			}
			var cleanupInv records.Invocation
			if prepareErr == nil {
				cleanupInv, prepareErr = makeInvocation(records.Invocation{
					Scenario: result.Scenario, FailureSources: s.failureSources,
					TelemetrySettings: s.telemetrySettings,
					RunID:             s.record.RunID,
					Worker:            inv.Worker + "-cleanup",
					Role:              "cleanup",
					Input:             cleanupPath,
					StateDir:          inv.StateDir,
					OutputDir:         filepath.Join(inv.StateDir, "workers", "cleanup"),
				}, s.record.Suite)
			}
			if prepareErr != nil {
				result.Cleanup = unresolvedCleanup()
				result.CleanupRetryBlocker = "evidence_unavailable"
			} else {
				finish, release := finalizationContext(ctx)
				result.CleanupWorker, result.Cleanup = s.executeCleanup(finish, binary, cleanupInv, result.Scenario, allowance)
				release()
				if !scenarioCleanupPassed(*result) {
					err = errors.Join(err, s.retryLiveCleanup(ctx, binary, cleanupInv, input, allowance, cleanupStarted, joined, result))
				}
			}
		} else {
			result.Cleanup = unresolvedCleanup()
			result.Cleanup.Failure = &records.Failure{Class: "worker_group_not_joined", Stage: "cleanup"}
			result.CleanupRetryBlocker = "worker_unjoined"
		}
		result.CleanupElapsed = time.Since(cleanupStarted)
		if !scenarioCleanupPassed(*result) {
			err = errors.Join(err, errors.New("cleanup unresolved"))
		}
	}
	return err
}

func disposePrivateOracle(path string) error {
	var err error
	if removeErr := os.RemoveAll(path); removeErr != nil {
		err = errors.Join(err, errors.New("private oracle cleanup failed"))
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		err = errors.Join(err, errors.New("private oracle survived cleanup"))
	}
	return err
}
