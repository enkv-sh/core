package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"

	records "enkv.sh/core/internal/testrecords"
)

const rawSourceAlgorithm = "enkv-raw-git-tree-v1"

func sourceGitCommand(ctx context.Context, root string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-c", "core.fsmonitor=false"}, args...)...)
	command.Dir = root
	// The invocation root owns repository selection. Inherited Git settings
	// must not redirect observations to another repository.
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
			"GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS":
			continue
		}
		if strings.HasPrefix(name, "GIT_CONFIG_KEY_") || strings.HasPrefix(name, "GIT_CONFIG_VALUE_") {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "GIT_OPTIONAL_LOCKS=0")
	stdout, stderr := new(limitedOutput), new(limitedOutput)
	command.Stdout, command.Stderr = stdout, stderr
	ctx, cancel := preparationCommandContext(ctx)
	defer cancel()
	result := superviseProcess(ctx, command)
	if !result.Joined || result.Status != "passed" {
		return nil, &sourceCommandFailure{operation: args[0], process: result}
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("source command output exceeds its bound")
	}
	return slices.Clone(stdout.Bytes()), nil
}

type sourceCommandFailure struct {
	operation string
	process   processResult
}

func (*sourceCommandFailure) Error() string { return "source command failed" }

func sourceCommandsJoined(cause error) bool {
	if failure, ok := cause.(*sourceCommandFailure); ok && !failure.process.Joined {
		return false
	}
	switch wrapped := cause.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			if !sourceCommandsJoined(child) {
				return false
			}
		}
	case interface{ Unwrap() error }:
		return sourceCommandsJoined(wrapped.Unwrap())
	}
	return true
}

func rawSourceRelativePath(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsRune(value, 0) && !path.IsAbs(value) && path.Clean(value) == value && !strings.HasPrefix(value, "../")
}

func rawSourceValid(source records.Source) bool {
	if source.Algorithm != rawSourceAlgorithm || source.Dirty || source.DirtyDiffSHA256 != nil || source.PublicSourcesSHA256 != "" ||
		!rawSourceObjectID(source.Revision) || !rawSourceObjectID(source.Tree) ||
		!rawSourceObjectID(source.PublicRevision) || !rawSourceObjectID(source.PublicTree) ||
		len(source.Revision) != len(source.Tree) || len(source.PublicRevision) != len(source.PublicTree) ||
		!rawSourceRelativePath(source.PublicRepository) || strings.Contains(source.PublicRepository, "/") || len(source.PublicPaths) == 0 {
		return false
	}
	for i, directory := range source.PublicPaths {
		if !rawSourceRelativePath(directory) || (i != 0 && source.PublicPaths[i-1] >= directory) {
			return false
		}
	}
	return true
}

func rawSourceObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, digit := range value {
		if !(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f') {
			return false
		}
	}
	return true
}

func sameRawSource(first, second records.Source) bool {
	return rawSourceValid(first) && rawSourceValid(second) &&
		first.Revision == second.Revision && first.Tree == second.Tree &&
		first.PublicRepository == second.PublicRepository && first.PublicRevision == second.PublicRevision &&
		first.PublicTree == second.PublicTree && slices.Equal(first.PublicPaths, second.PublicPaths)
}
