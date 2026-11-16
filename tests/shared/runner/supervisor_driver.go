//go:build enkv_supervisor

package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	records "enkv.sh/core/internal/testrecords"
)

const setupFinalizationSettledFailureStatus = 3

//go:embed setup-inputs
var supervisorSetupInputs embed.FS

func main() {
	args := os.Args[1:]
	var err error
	if len(args) != 0 && args[0] == "invoke" {
		err = invokeInstalledSupervisor(args[1:])
	} else {
		err = finalizeSupervisorSetup(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		var settled *setupFinalizationFailure
		if errors.As(err, &settled) {
			os.Exit(setupFinalizationSettledFailureStatus)
		}
		os.Exit(1)
	}
}

func invokeInstalledSupervisor(args []string) error {
	if len(args) < 3 || args[0] != "--root" || args[2] != "--" {
		return errors.New("supervisor invocation arguments refused")
	}
	native, err := currentSupervisorNativeTarget()
	if err != nil {
		return err
	}
	inputs, err := fs.Sub(supervisorSetupInputs, "setup-inputs")
	if err != nil {
		return err
	}
	binding, err := bindSupervisorSources(inputs, native)
	if err != nil {
		return err
	}
	return superviseInvocation(binding, args[1], args[3:])
}

type setupFinalizationFailure struct{ cause error }

func (failure *setupFinalizationFailure) Error() string {
	return "setup failed after settlement verified: " + failure.cause.Error()
}
func (failure *setupFinalizationFailure) Unwrap() error { return failure.cause }

func finalizeSupervisorSetup(args []string) (retErr error) {
	processesSettled := false
	defer func() {
		if retErr != nil && processesSettled {
			retErr = &setupFinalizationFailure{cause: retErr}
		}
	}()
	if len(args) == 0 || args[0] != "finalize-setup" {
		return errors.New("supervisor setup-finalization command required")
	}
	flags := flag.NewFlagSet("finalize-setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rootPath := flags.String("root", "", "")
	stagePath := flags.String("stage", "", "")
	ownerPID := flags.Int("owner-pid", 0, "")
	compilerGroup := flags.Int("compiler-group", 0, "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("setup-finalization arguments refused")
	}
	owner, err := verifySetupProcesses(*ownerPID, *compilerGroup)
	if err != nil {
		return err
	}
	processesSettled = true
	root, err := filepath.EvalSymlinks(*rootPath)
	if err != nil || root != *rootPath {
		return errors.New("setup repository spelling refused")
	}
	stage, err := filepath.EvalSymlinks(*stagePath)
	if err != nil || stage != *stagePath || filepath.Dir(stage) != filepath.Join(root, "tests/.supervisor") || !strings.HasPrefix(filepath.Base(stage), "setup.") {
		return errors.New("setup staging ownership refused")
	}
	directory, err := os.Lstat(stage)
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 {
		return errors.New("setup staging directory refused")
	}
	executable, err := os.Executable()
	if err != nil || executable != filepath.Join(stage, "supervisor-candidate") {
		return errors.New("setup candidate identity refused")
	}
	native, err := currentSupervisorNativeTarget()
	if err != nil {
		return err
	}
	inputs, err := fs.Sub(supervisorSetupInputs, "setup-inputs")
	if err != nil {
		return err
	}
	binding, err := bindSupervisorSources(inputs, native)
	if err != nil {
		return err
	}
	currentOwner, err := verifySetupProcesses(*ownerPID, *compilerGroup)
	if err != nil || currentOwner.identity != owner.identity || currentOwner.group != owner.group {
		return errors.Join(errors.New("setup parent identity changed"), err)
	}
	destination := filepath.Join(root, "tests/.supervisor/supervisor")
	if err := publishSupervisorArtifact(binding, root, executable, destination, native); err != nil {
		return err
	}
	current, err := os.Lstat(stage)
	if err != nil || !records.SameLocalFile(directory, current) {
		return errors.New("setup staging identity changed")
	}
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	return nil
}

func verifySetupProcesses(ownerPID, compilerGroup int) (processIdentityInfo, error) {
	if ownerPID <= 0 || ownerPID != os.Getppid() || compilerGroup <= 0 || compilerGroup == os.Getpid() {
		return processIdentityInfo{}, errors.New("setup process ownership refused")
	}
	owner, err := nativeProcessIdentity(ownerPID)
	if err != nil || owner.identity.start == 0 || owner.group <= 0 || owner.group == compilerGroup || os.Getppid() != ownerPID {
		return processIdentityInfo{}, errors.Join(errors.New("setup parent identity refused"), err)
	}
	if !errors.Is(syscall.Kill(-compilerGroup, 0), syscall.ESRCH) {
		return processIdentityInfo{}, errors.New("setup compiler remains present or uncertain")
	}
	children, err := nativeProcessChildren(ownerPID)
	if err != nil || len(children) != 1 || children[0] != os.Getpid() {
		return processIdentityInfo{}, errors.Join(errors.New("setup parent finalizer census differs"), err)
	}
	return owner, nil
}
