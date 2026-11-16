package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func main() { os.Exit(runMain()) }

type rootAdmitterContextKey struct{}

func admitPreparedExecution(ctx context.Context, request rootAdmission) (context.Context, error) {
	request.Execution = executionForClass(request.Execution, request.Big)
	if admit, ok := ctx.Value(rootAdmitterContextKey{}).(rootAdmitter); ok {
		next, err := admit(ctx, request)
		return context.WithValue(next, workAdmissionContextKey{}, request), err
	}
	policy, err := executionWithinContext(ctx, request.Execution)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(withExecutionCapacity(ctx, policy), workAdmissionContextKey{}, request), nil
}

type workAdmissionContextKey struct{}

func admitTestExecution(ctx context.Context, exclusive bool) (context.Context, error) {
	request, present := ctx.Value(workAdmissionContextKey{}).(rootAdmission)
	if !present {
		return ctx, nil
	}
	assigned := executionCapacityFromContext(ctx).Parallel
	request.Big = exclusive
	next, err := admitPreparedExecution(ctx, request)
	return withExecutionParallel(next, assigned), err
}

func runMain() (status int) {
	channel, err := inheritedRootChannel()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	joined := true
	var phase *toolDirectoryPhase
	var bootstrapDirectory string
	life := newInvocationLifetime(context.Background())
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	quit, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-signals:
				life.interrupt()
			case <-quit:
				return
			}
		}
	}()
	ctx := withExecutionCapacity(life.work, defaultExecutionPolicy())
	defer func() {
		finish, release := finalizationContext(ctx)
		var finishErr error
		if phase != nil && !phase.released {
			finishErr = phase.Release(finish, joined)
			joined = joined && finishErr == nil
			phase = nil
		}
		if bootstrapDirectory != "" && joined {
			finishErr = errors.Join(finishErr, cleanupBootstrap(bootstrapDirectory))
		}
		if finishErr != nil {
			status = 1
			fmt.Fprintln(os.Stderr, "runner finalization failed")
		}
		release()
		signal.Stop(signals)
		close(quit)
		<-done
		life.close()
		success := status == 0
		if err := channel.write(rootMessage{Operation: "terminal", Success: &success, Joined: &joined}); err != nil {
			status = 1
			fmt.Fprintln(os.Stderr, "runner terminal publication failed")
		}
		if err := channel.close(); err != nil {
			status = 1
			fmt.Fprintln(os.Stderr, "runner channel close failed")
		}
	}()
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "")
	bootstrap := flags.String("bootstrap-dir", "", "")
	stage := flags.String("invocation-stage", "", "")
	acceptedRace := flags.String("accepted-race", "", "")
	if flags.Parse(os.Args[1:]) != nil || *root == "" || *bootstrap == "" || *stage == "" {
		fmt.Fprintln(os.Stderr, "invalid launcher arguments")
		return 2
	}
	physical, err := filepath.EvalSymlinks(*root)
	if err != nil || physical != *root {
		fmt.Fprintln(os.Stderr, "runner repository spelling refused")
		return 1
	}
	stagePath, err := filepath.EvalSymlinks(*stage)
	if err != nil || stagePath != *stage {
		fmt.Fprintln(os.Stderr, "runner stage refused")
		return 1
	}
	info, err := os.Lstat(stagePath)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		fmt.Fprintln(os.Stderr, "runner stage refused")
		return 1
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || filepath.Dir(*bootstrap) != filepath.Join(stagePath, "tmp") || !strings.HasPrefix(filepath.Base(*bootstrap), "enkv-test-") {
		fmt.Fprintln(os.Stderr, "runner stage owner refused")
		return 1
	}
	if _, err := records.SafePath(stagePath, filepath.Join("tmp", filepath.Base(*bootstrap), "runner")); err != nil {
		fmt.Fprintln(os.Stderr, "runner artifact owner refused")
		return 1
	}
	bootstrapDirectory = *bootstrap
	if *acceptedRace != "true" && *acceptedRace != "false" {
		fmt.Fprintln(os.Stderr, "accepted race policy unavailable")
		return 1
	}
	ctx = withRacePolicy(ctx, *acceptedRace == "true")
	ctx, phase, err = withBorrowedToolDirectoryPhase(ctx, *root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	admitted := false
	var current rootAdmission
	var phaseMu sync.Mutex
	admit := rootAdmitter(func(preparedCtx context.Context, request rootAdmission) (context.Context, error) {
		phaseMu.Lock()
		defer phaseMu.Unlock()
		if phase == nil {
			return preparedCtx, errors.New("root tool phase unavailable")
		}
		if admitted && current.Big == request.Big && current.Live == request.Live && current.CleanupSeconds == request.CleanupSeconds && sameExecutionPolicy(current.Execution, request.Execution) {
			return withExecutionCapacity(preparedCtx, current.Execution), nil
		}
		finish, release := finalizationContext(preparedCtx)
		phaseErr := phase.Release(finish, true)
		release()
		if phaseErr != nil {
			joined = false
			return preparedCtx, phaseErr
		}
		policy, err := channel.admit(preparedCtx, request)
		if err != nil {
			return preparedCtx, err
		}
		if !sameExecutionPolicy(policy, request.Execution) {
			return preparedCtx, errors.New("root admitted execution differs")
		}
		if err := life.admitCleanup(request.CleanupSeconds); err != nil {
			return preparedCtx, err
		}
		admitted = true
		current = request
		next := withExecutionCapacity(preparedCtx, policy)
		if err := phase.reopenBorrowed(); err != nil {
			joined = false
			return next, err
		}
		return next, nil
	})
	ctx = context.WithValue(ctx, rootAdmitterContextKey{}, admit)
	ctx, err = withPreparationBootstrap(ctx, *root, filepath.Join(*bootstrap, "overlay.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := runCommand(ctx, *root, filepath.Join(*bootstrap, "overlay.json"), flags.Args(), os.Stdout); err != nil {
		joined = joined && toolCommandsJoined(err) && sourceCommandsJoined(err)
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runCommand(ctx context.Context, root, toolOverlay string, args []string, output io.Writer) (retErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New(testCommandUsage)
	}
	if args[0] == "plan" {
		return previewWorkflow(args, output)
	}
	workflowObservationFinished := false
	if args[0] == "run" || args[0] == "unit" || args[0] == "runner-tests" || args[0] == "check" || args[0] == "dev" || args[0] == "fuzz" || args[0] == "cleanup" || args[0] == "lint" {
		source, ownsObservation, err := sourceObservation(ctx, root)
		if err != nil {
			return err
		}
		ctx = context.WithValue(ctx, sourceObservationContextKey{}, source)
		if ownsObservation {
			defer func() {
				if workflowObservationFinished {
					return
				}
				_, err := finishSourceObservation(ctx, root, source, output)
				retErr = errors.Join(retErr, err)
			}()
		}
	}
	args, enableRace, raceErr := parseRaceArguments(args)
	if raceErr != nil {
		return raceErr
	}
	if _, present := ctx.Value(racePolicyContextKey{}).(bool); !present {
		raced, err := resolveInvocationRace(root, args, enableRace)
		if err != nil {
			return err
		}
		ctx = withRacePolicy(ctx, raced)
	} else if enableRace && !raceEnabled(ctx) {
		return errors.New("race option differs from accepted invocation policy")
	}
	execution := executionRequest{}
	if args[0] != "plan" && args[0] != "run" && args[0] != "cleanup" {
		var err error
		args, execution, err = parseExecutionPositionals(args)
		if err != nil {
			return err
		}
	}
	policy, err := resolveExecution(executionRequest{}, execution)
	if err != nil {
		return err
	}
	policy, err = executionWithinContext(ctx, policy)
	if err != nil {
		return err
	}
	ctx = withExecutionCapacity(ctx, policy)
	if args[0] == "cleanup" {
		request, err := parseCleanupRequest(args)
		if err != nil {
			return err
		}
		request.race = raceEnabled(ctx)
		request.execution, err = executionWithinContext(ctx, request.execution)
		if err != nil {
			return err
		}
		ctx = withExecutionCapacity(ctx, request.execution)

		prepared, err := prepareCleanup(ctx, root, toolOverlay, request, output)
		var result suiteExecution
		if prepared != nil {
			defer func() {
				if retErr != nil {
					retErr = errors.Join(retErr, prepared.retainPreparation(&result, output))
				}
				finish, release := finalizationContext(ctx)
				defer release()
				retErr = errors.Join(retErr, prepared.close(finish))
				if retErr != nil {
					retErr = errors.Join(retErr, prepared.retainPreparation(&result, output))
				}
			}()
		}
		if err != nil {
			return err
		}
		ctx, err = admitPreparedExecution(ctx, prepared.admission())
		if err != nil {
			return err
		}
		if err := prepared.retainPreparation(&result, output); err != nil {
			return err
		}
		if err := prepared.verifyOwned(result.preparation, ctx, root); err != nil {
			return err
		}
		result, err = runPreparedCleanupResult(ctx, root, toolOverlay, prepared, output, result)
		outcome := "failed"
		if err == nil && result.Record != nil {
			outcome = result.Record.Outcome
		}
		return errors.Join(err, writeCurrentTestResult(output, "", "cleanup", outcome, workflowStepExecution{Suite: result.Record}))
	}
	if args[0] == "run" {
		preparationOutput := output
		parsed, err := parsePlanRunArguments(args)
		if err != nil {
			return err
		}

		if parsed.workflowPresent {
			request, err := workflowRequestFromArguments(parsed)
			if err != nil {
				return err
			}
			plan, err := resolveWorkflow(ctx, root, request)
			if err != nil {
				if request.Test != "" || request.Package != "" {
					return safeCheckFailure("preparation", "none", err)
				}
				return err
			}
			plan.Execution, err = executionWithinContext(ctx, plan.Execution)
			if err != nil {
				return err
			}
			ctx = withExecutionCapacity(ctx, plan.Execution)
			prepared, prepareErr := prepareWorkflow(ctx, root, toolOverlay, plan, preparationOutput)
			result, err := executeCommandWorkflow(ctx, root, toolOverlay, prepared, prepareErr, output)
			workflowObservationFinished = result.FinishedAt != nil
			return err
		}
		request, err := savedRequestFromArguments(parsed)
		if err != nil {
			return err
		}
		request.Resolved.Race = raceEnabled(ctx)
		request.execution, err = executionWithinContext(ctx, request.execution)
		if err != nil {
			return err
		}
		ctx = withExecutionCapacity(ctx, request.execution)
		prepared, err := prepareSuite(nil, ctx, root, toolOverlay, request, preparationOutput)
		var result suiteExecution
		if prepared != nil {
			defer func() {
				if retErr != nil {
					retErr = errors.Join(retErr, prepared.retainPreparation(&result, output))
				}
				finish, release := finalizationContext(ctx)
				defer release()
				retErr = errors.Join(retErr, prepared.close(finish))
				if retErr != nil {
					retErr = errors.Join(retErr, prepared.retainPreparation(&result, output))
				}
			}()
		}
		if err != nil {
			return err
		}
		ctx, err = admitPreparedExecution(ctx, prepared.admission())
		if err != nil {
			return err
		}
		if err := prepared.retainPreparation(&result, preparationOutput); err != nil {
			return err
		}
		if err := prepared.verifyOwned(result.preparation, ctx, root); err != nil {
			return err
		}
		result, err = runPreparedSuiteResult(ctx, root, toolOverlay, prepared, output, result)
		outcome := "failed"
		if err == nil && result.Record != nil {
			outcome = result.Record.Outcome
		}
		return errors.Join(err, writeCurrentTestResult(output, "", "run", outcome, workflowStepExecution{Suite: result.Record}))
	}
	if len(args) != 0 && args[0] == "unit" {
		packages := args[1:]
		if len(packages) == 0 {
			packages = nil
		}
		selection, err := resolveUnitPackages(packages)
		if err != nil {
			return err
		}
		if err := validateUnitPackages(ctx, root, selection); err != nil {
			var failure *toolFailure
			if errors.As(err, &failure) {
				return errors.Join(err, writeAssemblyDiagnosticBody(output, err))
			}
			return err
		}
		prepared, prepareErr := prepareWorkflow(ctx, root, toolOverlay, workflowPlan{Race: raceEnabled(ctx), Execution: policy, SchemaVersion: 1, Name: "unit", Profile: "full", Steps: []resolvedWorkflowStep{{ID: "unit", Kind: "unit", Selected: true, Packages: selection}}}, output)
		result, err := executeCommandWorkflow(ctx, root, toolOverlay, prepared, prepareErr, output)
		workflowObservationFinished = result.FinishedAt != nil
		if prepareErr != nil && prepared == nil {
			err = errors.Join(err, writeAssemblyDiagnosticBody(output, err))
		}
		return err
	}
	if len(args) == 1 && args[0] == "runner-tests" {
		prepared, prepareErr := prepareWorkflow(ctx, root, toolOverlay, workflowPlan{Race: raceEnabled(ctx), Execution: policy, SchemaVersion: 1, Name: "runner-tests", Profile: "full", Steps: []resolvedWorkflowStep{{ID: "runner", Kind: "runner-tests", Selected: true}}}, output)
		result, err := executeCommandWorkflow(ctx, root, toolOverlay, prepared, prepareErr, output)
		workflowObservationFinished = result.FinishedAt != nil
		if prepareErr != nil && prepared == nil {
			err = errors.Join(err, writeAssemblyDiagnosticBody(output, err))
		}
		return err
	}
	if len(args) == 1 && (args[0] == "check" || args[0] == "dev") {
		prepared, prepareErr := prepareLocalWorkflow(ctx, root, toolOverlay, args[0], execution, output)
		result, err := executeCommandWorkflow(ctx, root, toolOverlay, prepared, prepareErr, output)
		workflowObservationFinished = result.FinishedAt != nil
		return err
	}
	if len(args) != 0 && args[0] == "fuzz" {
		targets := args[1:]
		if len(targets) == 0 {
			targets = nil
		}
		ctx, err = withPreparationBootstrap(ctx, root, toolOverlay)
		if err != nil {
			return err
		}
		prepared, err := prepareFuzz(nil, ctx, root, targets, policy, output)
		if prepared != nil {
			defer func() {
				finish, release := finalizationContext(ctx)
				defer release()
				retErr = errors.Join(retErr, prepared.close(finish))
			}()
		}
		if err != nil {
			return err
		}
		ctx, err = admitPreparedExecution(ctx, prepared.admission())
		if err != nil {
			return err
		}
		if err := prepared.verify(ctx, root); err != nil {
			return err
		}
		results, err := runPreparedFuzz(ctx, root, prepared, output)
		outcome := "passed"
		if err != nil {
			outcome = "failed"
		}
		return errors.Join(err, writeCurrentTestResult(output, "", "fuzz", outcome, workflowStepExecution{Fuzz: results}))
	}
	if len(args) == 1 && (args[0] == "fmt" || args[0] == "fmt-check" || args[0] == "lint" || args[0] == "list") {
		ctx, err = admitPreparedExecution(ctx, rootAdmission{Execution: policy})
		if err != nil {
			return err
		}
	}
	if len(args) == 1 && (args[0] == "fmt" || args[0] == "fmt-check") {
		return runFormatting(ctx, root, args[0] == "fmt", output)
	}
	if len(args) == 1 && args[0] == "lint" {
		_, err := runLint(ctx, root, toolOverlay, output)
		return err
	}
	if len(args) == 1 && args[0] == "list" {
		for _, definition := range catalog.Definitions() {
			parameters := "fixed fixture"

			if _, err := fmt.Fprintf(output, "%s\t%s\t%s\tfixture members %d, value bytes %d; modes=%s; roles=%s\n", definition.Name, definition.Description, parameters, definition.Fixture.Members, definition.Fixture.RawValueBytes, strings.Join(definition.Modes, ","), strings.Join(definition.Roles, ",")); err != nil {
				return errors.New("scenario list output failed")
			}
		}
		return nil
	}
	return errors.New(testCommandUsage)
}

func executeCommandWorkflow(ctx context.Context, root, bootstrap string, prepared *preparedWorkflow, prepareErr error, output io.Writer) (result workflowResult, retErr error) {
	if prepared != nil {
		defer func() {
			retErr = errors.Join(retErr, prepared.retainWorkflowPreparation(&result, nil, output))
			finish, release := finalizationContext(ctx)
			defer release()
			retErr = errors.Join(retErr, prepared.close(finish))
		}()
	}
	if prepareErr != nil && (prepared == nil || prepared.planIdentity == "" || prepared.class.Live || !containedCheckFailure(ctx, prepareErr)) {
		if prepared != nil && !prepared.class.Live {
			return result, errors.Join(prepareErr, writeAssemblyDiagnosticBody(output, prepareErr))
		}
		return result, prepareErr
	}
	defer func() { retErr = errors.Join(prepareErr, retErr) }()
	ctx, err := admitPreparedExecution(ctx, prepared.admission())
	if err != nil {
		return result, err
	}
	if err := prepared.verifyResult(ctx, root, &result, output); err != nil {
		return result, err
	}
	return runPreparedWorkflowResult(ctx, root, bootstrap, prepared, output, result)
}

func cleanupBootstrap(directory string) error {
	actual, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	temporary, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil || filepath.Dir(executable) != actual || filepath.Base(executable) != "runner" || filepath.Dir(actual) != temporary || !strings.HasPrefix(filepath.Base(actual), "enkv-test-") {
		return errors.New("launcher cleanup path refused")
	}
	for _, name := range []string{"overlay.json", "runner.mod", "runner.sum", "runner"} {
		if err := os.Remove(filepath.Join(actual, name)); err != nil {
			return err
		}
	}
	return os.Remove(actual)
}
