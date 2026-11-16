package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	records "enkv.sh/core/internal/testrecords"
)

type currentDirectory struct {
	path     string
	identity os.FileInfo
}

func newCurrentDirectory(prefix string) (*currentDirectory, error) {
	parent, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return nil, err
	}
	path, err := os.MkdirTemp(parent, prefix)
	if err != nil {
		return nil, err
	}
	identity, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	return &currentDirectory{path: path, identity: identity}, nil
}

func (owned currentDirectory) createRun(id string) (string, error) {
	if !records.ValidRunID(id) {
		return "", errors.New("current run identity refused")
	}
	if err := owned.verify(); err != nil {
		return "", err
	}
	parent := filepath.Join(owned.path, "runs")
	if err := os.Mkdir(parent, 0700); err != nil {
		return "", err
	}
	directory := filepath.Join(parent, id)
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}
	return directory, nil
}

func (owned currentDirectory) verify() error {
	current, err := os.Lstat(owned.path)
	if err != nil || owned.identity == nil || !current.IsDir() || current.Mode().Perm() != 0700 || !records.SameLocalFile(owned.identity, current) {
		return errors.New("current directory ownership changed; files retained")
	}
	return nil
}

func (owned currentDirectory) remove(joined bool) error {
	if !joined {
		return errors.New("current files retained for an unjoined consumer")
	}
	if err := owned.verify(); err != nil {
		return err
	}
	return removeSupervisorInvocationStage(context.Background(), owned.path, owned.identity, true)
}

// Only the creator can remove this private directory. Exact recovery borrows
// original state and cannot obtain this in-memory ownership from a saved file.
type privateDirectory struct {
	current                    *currentDirectory
	root, suite, id, run, path string
	identity                   os.FileInfo
	runIdentity                os.FileInfo
}

func createPrivateDirectory(root, suite, id, run string) (privateDirectory, error) {
	refused := errors.New("private directory ownership refused")
	if suite != "hermetic" && suite != "live" || !records.ValidRunID(id) {
		return privateDirectory{}, refused
	}
	if root != "" {
		owner, err := records.SafePath(root, filepath.Join("tests", suite, "runs"))
		if err != nil {
			return privateDirectory{}, refused
		}
		relative, err := filepath.Rel(owner, run)
		parsed, parseErr := records.ParseRunRelative(relative)
		path, pathErr := records.SafePath(owner, relative)
		if err != nil || parseErr != nil || parsed != id || pathErr != nil || path != run {
			return privateDirectory{}, refused
		}
	}
	path, err := records.SafePath(run, "private")
	if err != nil || os.Mkdir(path, 0700) != nil {
		return privateDirectory{}, refused
	}
	identity, err := os.Lstat(path)
	if err != nil || !identity.IsDir() {
		return privateDirectory{}, refused
	}
	runIdentity, err := os.Lstat(run)
	if err != nil || !runIdentity.IsDir() {
		return privateDirectory{}, refused
	}
	return privateDirectory{root: root, suite: suite, id: id, run: run, path: path, identity: identity, runIdentity: runIdentity}, nil
}

func (owned privateDirectory) verify() error {
	refused := errors.New("private files retained: owned directory could not be safely removed")
	if owned.identity == nil || owned.runIdentity == nil || owned.path != filepath.Join(owned.run, "private") || owned.suite != "hermetic" && owned.suite != "live" || !records.ValidRunID(owned.id) {
		return refused
	}
	if owned.root != "" {
		owner, err := records.SafePath(owned.root, filepath.Join("tests", owned.suite, "runs"))
		if err != nil {
			return refused
		}
		relative, err := filepath.Rel(owner, owned.run)
		parsed, parseErr := records.ParseRunRelative(relative)
		path, pathErr := records.SafePath(owner, relative)
		if err != nil || parseErr != nil || parsed != owned.id || pathErr != nil || path != owned.run {
			return refused
		}
	}
	path, err := records.SafePath(owned.run, "private")
	if err != nil || path != owned.path {
		return refused
	}
	currentRun, err := os.Lstat(owned.run)
	if err != nil || !currentRun.IsDir() || !records.SameLocalFile(owned.runIdentity, currentRun) {
		return refused
	}
	current, err := os.Lstat(path)
	if err != nil || !current.IsDir() || !records.SameLocalFile(owned.identity, current) {
		return refused
	}
	return nil
}

func (owned privateDirectory) remove() error {
	if err := owned.verify(); err != nil {
		return err
	}
	if err := safeCurrentFiles(owned.path); err != nil {
		return err
	}
	if err := owned.verify(); err != nil {
		return err
	}
	if owned.current != nil {
		return owned.current.remove(true)
	}
	return os.RemoveAll(owned.path)
}

func safeCurrentFiles(path string) error {
	return filepath.WalkDir(path, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("private files retained: owned directory could not be safely removed")
		}
		return nil
	})
}

func (owned privateDirectory) protectedFixtureContext(ctx context.Context) (context.Context, error) {
	if err := owned.verify(); err != nil {
		return ctx, err
	}
	directory := filepath.Join(owned.path, "protected-fixtures")
	if err := os.Mkdir(directory, 0700); err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, protectedFixtureContextKey{}, directory), nil
}

func (s *runState) finishCurrentRun(output io.Writer, executionErr error) (finalization error) {
	defer func() {
		if finalization != nil {
			s.record.Outcome = "failed"
			s.fail("run_failed", "execution")
			if s.recovery != nil {
				finalization = errors.Join(finalization, s.save())
			}
		}
	}()
	if s.record.Suite == "hermetic" && executionErr != nil {
		finalization = writeAssemblyDiagnosticBody(output, executionErr)
	}
	finalization = errors.Join(finalization, s.verifyPublicConfigurationEvidence(), s.save())
	if s.current != nil {
		return errors.Join(finalization, s.current.remove(runProcessesJoined(s.record) && toolCommandsJoined(errors.Join(executionErr, finalization))))
	}
	if s.recovery != nil && finalization == nil && executionErr == nil && s.record.Outcome == "passed" && s.record.RecoveryRunID == "" && s.record.ContinuationRootRunID == "" {
		finalization = s.recovery.complete(s.record)
	}
	return finalization
}

func runProcessesJoined(value runRecord) bool {
	for _, scenario := range value.Scenarios {
		for _, reconstruction := range scenario.Reconstruction {
			for _, phase := range reconstruction.Phases {
				if phase.Started && !phase.Joined {
					return false
				}
			}
		}
		for _, worker := range scenarioWorkers(scenario) {
			if worker.Started && !worker.Joined {
				return false
			}
		}
		for _, attempt := range scenario.CleanupAttempts {
			if attempt.Worker != nil && attempt.Worker.Started && !attempt.Worker.Joined {
				return false
			}
		}
	}
	return true
}
