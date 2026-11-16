package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	records "enkv.sh/core/internal/testrecords"
)

func superviseInvocation(binding supervisorSourceBinding, root string, args []string) (retErr error) {
	if len(args) != 0 && args[0] == "plan" {
		return previewWorkflow(args, os.Stdout)
	}
	invocationDirectory, err := os.Getwd()
	if err != nil {
		return err
	}
	native, err := currentSupervisorNativeTarget()
	if err != nil {
		return err
	}
	if err := binding.validate(root, native); err != nil {
		return err
	}
	if err := verifyModuleInventory(root); err != nil {
		return err
	}
	cleanedArgs, enableRace, raceArgumentErr := parseRaceArguments(args)
	if raceArgumentErr == nil {
		args = cleanedArgs
	}
	acceptedRace, racePolicyErr := resolveInvocationRace(root, args, enableRace)
	inputs, preflightErr := preflightSupervisorExecution(root, args)
	preflightErr = errors.Join(raceArgumentErr, racePolicyErr, preflightErr)
	if preflightErr != nil {
		return preflightErr
	}
	policy := executionForClass(inputs.Policy, false)
	life := newInvocationLifetime(context.Background())
	defer life.close()
	signals, runnerSignals := make(chan os.Signal, 8), make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	signalQuit, signalDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(signalDone)
		for {
			select {
			case received := <-signals:
				life.interrupt()
				select {
				case runnerSignals <- received:
				case <-signalQuit:
					return
				}
			case <-signalQuit:
				return
			}
		}
	}()
	defer func() { close(signalQuit); <-signalDone }()
	locks, err := defaultResourceLocks()
	if err != nil {
		return err
	}
	machine, err := locks.acquireMachine(life.work, false)
	if err != nil {
		return err
	}
	var live *resourceLease
	var preparation, execution *toolDirectoryPhase
	var guard *invocationMemoryGuard
	var stage string
	var stageInfo os.FileInfo
	joined := true
	ctx := withResourceLocks(withExecutionCapacity(life.work, policy), locks)
	var guardQuit, guardDone chan struct{}
	var hardStopped bool
	var hardStopErr error
	// The monitor is joined before these shared result fields are consumed.
	startGuardMonitor := func() {
		guardQuit, guardDone = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(guardDone)
			select {
			case <-guard.failure():
				life.hardStop()
			case <-life.hard.Done():
			case <-guardQuit:
				return
			}
			hardStopped, hardStopErr = guard.stopDescendants()
		}()
	}
	defer func() {
		finish, finishRelease := finalizationContext(ctx)
		defer finishRelease()
		var settlement error
		if guard != nil && life.hard.Err() != nil {
			<-guardDone
			joined = joined && hardStopped
			settlement = errors.Join(settlement, hardStopErr)
		}
		if guard != nil && life.hard.Err() == nil {
			stopped, err := guard.stopDescendants()
			joined = joined && stopped
			settlement = errors.Join(settlement, err)
		}
		if !joined {
			settlement = errors.Join(settlement, errors.New("supervisor invocation has an unjoined command"))
		}
		releasePhase := func(phase *toolDirectoryPhase) {
			if phase == nil {
				return
			}
			if !phase.released {
				settlement = errors.Join(settlement, phase.Release(finish, joined))
			}
			if joined {
				settlement = errors.Join(settlement, phase.ReleaseAfterSettlement(finish))
			}
		}
		releasePhase(preparation)
		releasePhase(execution)
		if guard != nil && life.hard.Err() == nil {
			stopped, err := guard.stopDescendants()
			joined = joined && stopped
			settlement = errors.Join(settlement, err)
		}
		if stage != "" && settlement == nil {
			settlement = errors.Join(settlement, removeSupervisorInvocationStage(finish, stage, stageInfo, joined))
		}
		retErr = errors.Join(retErr, settlement)
		var lateErr error
		if guard != nil {
			sample, err := guard.stop()
			lateErr = errors.Join(lateErr, err)
			if err != nil {
				life.hardStop()
			}
			close(guardQuit)
			<-guardDone
			if life.hard.Err() != nil {
				stopped, stopErr := guard.stopDescendants()
				joined = joined && stopped
				lateErr = errors.Join(lateErr, hardStopErr, stopErr, life.hard.Err())
			} else if sample.count != 1 {
				joined = false
				lateErr = errors.Join(lateErr, errors.New("invocation ended with an observed descendant"))
			}
		}
		// A failed/unknown invocation never claims quiescence from descriptor close.
		// Kernel release on owner death has the same limit as an abrupt crash.
		if joined {
			lateErr = errors.Join(lateErr, live.Close(), machine.Close())
		}
		retErr = errors.Join(retErr, lateErr)

	}()
	guard, _, err = startInvocationMemoryGuard(uint64(policy.Resolved.MemoryLimitMiB) << 20)
	if err != nil {
		life.hardStop()
		return fmt.Errorf("resource_limit: %w", err)
	}
	startGuardMonitor()
	ctx, preparation, err = prepareToolDirectoryPhase(ctx, locks, root)
	if err != nil {
		return err
	}
	home, homeErr := os.UserHomeDir()
	stageParent, err := supervisorInvocationStageParent(root, os.TempDir(), home)
	if err != nil {
		if homeErr != nil {
			return errors.New("supervisor temporary directory parent unavailable")
		}
		return err
	}
	stage, err = os.MkdirTemp(stageParent, "invoke.")
	if err != nil {
		return err
	}
	stageInfo, err = os.Lstat(stage)
	if err != nil {
		return err
	}
	temporary, goTemporary := filepath.Join(stage, "tmp"), filepath.Join(stage, "go-tmp")
	for _, path := range []string{temporary, goTemporary} {
		if err := os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	env := environment(goEnvironment(), map[string]string{"TMPDIR": temporary, "GOTMPDIR": goTemporary, "GOFLAGS": buildGoFlags + " -p=" + strconv.Itoa(policy.Resolved.Parallel)})
	runnerContext := withExecutionCapacity(life.hard, policy)
	run := func(command *exec.Cmd, phase string, runner bool) error {
		command.Dir, command.Env = root, env
		command.Stdin, command.Stderr = os.Stdin, os.Stderr
		var result processResult
		if runner {
			command.Dir = invocationDirectory
			result = superviseNativeProcess(runnerContext, command, runnerSignals)
		} else {
			preparation, cancel := preparationCommandContext(ctx)
			result = superviseProcess(preparation, command)
			cancel()
		}
		joined = joined && result.Joined

		if result.Status != "passed" {
			return fmt.Errorf("%s: %s: %w", phase, result.Status, result.Cause)
		}
		return nil
	}
	bootstrapSource := filepath.Join(stage, "bootstrap.go")
	body := binding.bytes["tests/scripts/bootstrap.go"]
	if len(body) == 0 {
		return errors.New("supervisor bootstrap source absent")
	}
	if err := os.WriteFile(bootstrapSource, body, 0600); err != nil {
		return err
	}
	bootstrap := filepath.Join(stage, "bootstrap")
	compiler := exec.Command("go", "build", "-mod=readonly", "-o", bootstrap, bootstrapSource)
	compiler.Stdout = os.Stdout
	if err := run(compiler, "bootstrap compiler", false); err != nil {
		return err
	}
	output := new(limitedOutput)
	prepare := exec.Command(bootstrap, root)
	prepare.Stdout = output
	if err := run(prepare, "runner compiler", false); err != nil {
		return err
	}
	if output.overflow {
		return errors.New("bootstrap output exceeds its bound")
	}
	binary := strings.TrimSuffix(output.String(), "\n")
	if binary == "" || strings.ContainsAny(binary, "\r\n") || filepath.Dir(filepath.Dir(binary)) != temporary || filepath.Base(binary) != "runner" || !strings.HasPrefix(filepath.Base(filepath.Dir(binary)), "enkv-test-") {
		return errors.New("bootstrap runner path refused")
	}
	relative, err := filepath.Rel(stage, binary)
	if err != nil {
		return err
	}
	if _, err := records.SafePath(stage, relative); err != nil {
		return err
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return errors.New("bootstrap runner artifact refused")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	channel, ends, err := newRootChannels()
	if err != nil {
		return err
	}
	admissionCtx, stopAdmission := context.WithCancel(life.work)
	defer stopAdmission()
	type channelResult struct {
		terminal rootTerminal
		err      error
	}
	completed := make(chan channelResult, 1)
	go func() {
		currentBig, currentLive := false, false
		terminal, err := serveRootChannel(life.hard, channel, func(_ context.Context, request rootAdmission) (executionPolicy, error) {
			expected := executionForClass(inputs.Policy, request.Big)
			if !sameExecutionPolicy(request.Execution, expected) {
				return executionPolicy{}, errors.New("prepared execution policy differs from accepted inputs")
			}
			if err := admissionCtx.Err(); err != nil {
				return executionPolicy{}, err
			}
			for _, phase := range []*toolDirectoryPhase{preparation, execution} {
				if phase != nil {
					if err := phase.Release(admissionCtx, true); err != nil {
						return executionPolicy{}, err
					}
				}
			}
			preparation, execution = nil, nil
			if request.Big != currentBig || request.Live != currentLive {
				if err := machine.Close(); err != nil {
					return executionPolicy{}, err
				}
				machine = nil
				if request.Live != currentLive {
					if err := live.Close(); err != nil {
						return executionPolicy{}, err
					}
					live = nil
					if request.Live {
						live, err = locks.acquireLive(admissionCtx)
						if err != nil {
							return executionPolicy{}, err
						}
					}
				}
				machine, err = locks.acquireMachine(admissionCtx, request.Big)
				if err != nil {
					return executionPolicy{}, err
				}
			}
			if err := guard.setLimit(uint64(expected.Resolved.MemoryLimitMiB) << 20); err != nil {
				return executionPolicy{}, err
			}
			if err := life.admitCleanup(request.CleanupSeconds); err != nil {
				return executionPolicy{}, err
			}
			policy = expected
			currentBig, currentLive = request.Big, request.Live
			phaseCtx := withResourceLocks(withExecutionCapacity(admissionCtx, policy), locks)
			_, execution, err = prepareToolDirectoryPhase(phaseCtx, locks, root)
			if err != nil {
				return executionPolicy{}, err
			}
			return policy, nil
		})
		if err != nil {
			life.hardStop()
		}
		completed <- channelResult{terminal, err}
	}()
	runnerArgs := []string{"--root", root, "--bootstrap-dir", filepath.Dir(binary), "--invocation-stage", stage, "--accepted-race", strconv.FormatBool(acceptedRace)}
	runnerArgs = append(append(runnerArgs, "--"), args...)
	runner := exec.Command(binary, runnerArgs...)
	runner.Stdout, runner.ExtraFiles = os.Stdout, ends
	// Native supervision owns every transferred ExtraFiles entry from here.
	runErr := run(runner, "test runner", true)
	stopAdmission()
	result := <-completed
	joined = joined && result.terminal.Joined
	if result.err == nil && !result.terminal.Success {
		result.err = errors.New("runner terminal result failed")
	}
	ctx = withExecutionCapacity(ctx, policy)
	return errors.Join(runErr, result.err)
}

// Current descendants inherit this stage's temporary directories. Its parent
// must also admit protected Product artifacts; a private child below a writable
// ancestor does not meet that contract.
func supervisorInvocationStageParent(root, temporary, home string) (string, error) {
	refused := errors.New("supervisor temporary directory parent refused")
	validate := func(candidate string) (string, error) {
		if !filepath.IsAbs(candidate) {
			return "", refused
		}
		parent, err := filepath.EvalSymlinks(candidate)
		if err != nil || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
			return "", refused
		}
		relative, err := filepath.Rel(root, parent)
		if err != nil || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return "", refused
		}
		if _, err := records.SafePath(parent, "."); err != nil {
			return "", refused
		}
		for path := parent; ; path = filepath.Dir(path) {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
				return "", refused
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 && uint64(stat.Uid) != uint64(os.Geteuid()) {
				return "", refused
			}
			if path == filepath.Dir(path) {
				break
			}
		}
		return parent, nil
	}
	for _, candidate := range []string{temporary, home} {
		if parent, err := validate(candidate); err == nil {
			return parent, nil
		}
	}
	return "", refused
}

func removeSupervisorInvocationStage(ctx context.Context, stage string, original os.FileInfo, joined bool) (resultErr error) {
	changed := errors.New("supervisor invocation stage changed")
	if !joined {
		return errors.New("supervisor invocation stage has an unjoined consumer")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if original == nil || !original.IsDir() || original.Mode().Perm() != 0700 {
		return changed
	}
	current, err := os.Lstat(stage)
	if err != nil || !current.IsDir() || current.Mode().Perm() != 0700 || !records.SameLocalFile(original, current) {
		return errors.Join(changed, err)
	}
	parent, err := os.OpenRoot(filepath.Dir(stage))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.Close()) }()
	name := filepath.Base(stage)
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	held, err := root.Stat(".")
	if err != nil || !held.IsDir() || held.Mode().Perm() != 0700 || !records.SameLocalFile(original, held) {
		return errors.Join(changed, err)
	}
	current, err = parent.Lstat(name)
	if err != nil || !current.IsDir() || current.Mode().Perm() != 0700 || !records.SameLocalFile(original, current) {
		return errors.Join(changed, err)
	}
	if err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if err := errors.Join(walkErr, ctx.Err()); err != nil {
			return err
		}
		if path == "." || !entry.IsDir() {
			return nil
		}
		expected, err := entry.Info()
		if err != nil {
			return err
		}
		directory, err := root.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		opened, statErr := directory.Stat()
		if statErr != nil || !opened.IsDir() || !records.SameLocalFile(expected, opened) {
			return errors.Join(changed, statErr, directory.Close())
		}
		return errors.Join(directory.Chmod(0700), directory.Close())
	}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err = parent.Lstat(name)
	if err != nil || !current.IsDir() || current.Mode().Perm() != 0700 || !records.SameLocalFile(original, current) {
		return errors.Join(changed, err)
	}
	return parent.RemoveAll(name)
}
