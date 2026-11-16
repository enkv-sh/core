package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type preparedTestEventConverter struct {
	binary      string
	sha256      string
	preparation *checkCommandFacts
}

// Go can compile an absent builtin tool on demand. Keep that work in
// preparation, then retain the executable independently of Go's build cache.
func prepareTestEventConverter(ctx context.Context, root, directory string) (preparedTestEventConverter, checkCommandFacts, error) {
	var facts checkCommandFacts
	value, built, err := invocationArtifactValue(ctx, root, directory, "test2json", "cmd/test2json", func(build string) (preparedTestEventConverter, error) {
		value, current, err := constructTestEventConverter(ctx, root, build)
		facts = current
		return value, err
	})
	if !built {
		value.preparation = nil
	}
	return value, facts, err
}

func constructTestEventConverter(ctx context.Context, root, directory string) (preparedTestEventConverter, checkCommandFacts, error) {
	binary := filepath.Join(directory, "test2json")
	_, facts, err := runGoRecorded(ctx, root, "core", "build", "-mod=readonly", "-buildvcs=false", "-o", binary, "cmd/test2json")
	facts.Phase = "preparation"
	facts.Scope = "test2json"
	if err != nil {
		return preparedTestEventConverter{}, facts, err
	}
	digest, err := assemblyFileSHA256(binary)
	if err != nil {
		return preparedTestEventConverter{}, facts, err
	}
	converter := preparedTestEventConverter{binary: binary, sha256: digest, preparation: &facts}
	return converter, facts, converter.verify()
}

func (converter preparedTestEventConverter) verify() error {
	if !filepath.IsAbs(converter.binary) || !hexString(converter.sha256, sha256HexLength) {
		return errors.New("prepared test event converter identity missing")
	}
	info, err := os.Lstat(converter.binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.Join(err, errors.New("prepared test event converter unavailable"))
	}
	digest, err := assemblyFileSHA256(converter.binary)
	if err != nil || digest != converter.sha256 {
		return errors.Join(err, errors.New("prepared test event converter changed"))
	}
	return nil
}

func superviseTestEventConversion(work context.Context, command *exec.Cmd) processResult {
	tail, releaseTail := finalizationContext(work)
	conversion, cancel := context.WithCancelCause(tail)
	workDone := make(chan struct{})
	stopWork := context.AfterFunc(work, func() {
		defer close(workDone)
		timer := time.NewTimer(processGroupSettlementTimeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			cancel(context.DeadlineExceeded)
		case <-conversion.Done():
		}
	})
	defer func() {
		cancel(context.Canceled)
		if !stopWork() {
			<-workDone
		}
		releaseTail()
	}()
	process := superviseProcess(conversion, command)
	if process.Status == "interrupted" && errors.Is(context.Cause(conversion), context.DeadlineExceeded) {
		process.Status = "timed_out"
		process.Cause = errors.Join(process.Cause, context.DeadlineExceeded)
	}
	return process
}
