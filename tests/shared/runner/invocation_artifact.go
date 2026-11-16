package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

type invocationArtifactsKey struct{}
type artifactDiagnosticsKey struct{}

type sharedArtifactFailure struct{ cause error }

func (failure *sharedArtifactFailure) Error() string { return failure.cause.Error() }
func (failure *sharedArtifactFailure) Unwrap() error { return failure.cause }

type invocationArtifact struct {
	ready chan struct{}
	value any
	err   error
}

type invocationArtifacts struct {
	bootstraps  map[string]preparationBootstrap
	environment []string
	goBinary    string
	mu          sync.Mutex
	current     *currentDirectory
	artifacts   map[string]*invocationArtifact
	compilers   map[string]*invocationArtifact
	active      int
	changed     chan struct{}
	closing     bool
	closed      bool
	joined      bool
}

func withInvocationArtifacts(ctx context.Context) (context.Context, *invocationArtifacts) {
	if owner := invocationArtifactsFrom(ctx); owner != nil {
		return ctx, nil
	}
	binary, _ := exec.LookPath("go")
	owner := &invocationArtifacts{bootstraps: map[string]preparationBootstrap{}, environment: goEnvironment(), goBinary: binary, artifacts: map[string]*invocationArtifact{}, compilers: map[string]*invocationArtifact{}, changed: make(chan struct{}), joined: true}
	return context.WithValue(ctx, invocationArtifactsKey{}, owner), owner
}

func invocationArtifactsFrom(ctx context.Context) *invocationArtifacts {
	owner, _ := ctx.Value(invocationArtifactsKey{}).(*invocationArtifacts)
	return owner
}

func useInvocationArtifacts(ctx, prepared context.Context) context.Context {
	if owner := invocationArtifactsFrom(prepared); owner != nil {
		return context.WithValue(ctx, invocationArtifactsKey{}, owner)
	}
	return ctx
}

func (owner *invocationArtifacts) borrow() (func(bool), error) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closing || owner.closed || !owner.joined {
		return nil, errors.New("invocation artifacts are closed")
	}
	owner.active++
	var once sync.Once
	return func(joined bool) {
		once.Do(func() {
			owner.mu.Lock()
			defer owner.mu.Unlock()
			owner.joined = owner.joined && joined
			owner.active--
			close(owner.changed)
			owner.changed = make(chan struct{})
		})
	}, nil
}

func (owner *invocationArtifacts) close(ctx context.Context, joined bool) error {
	if owner == nil {
		return nil
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return nil
	}
	owner.closing = true
	owner.joined = owner.joined && joined
	for owner.active != 0 {
		changed := owner.changed
		owner.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			owner.mu.Lock()
			return errors.New("invocation artifacts retained for active consumers")
		}
		owner.mu.Lock()
	}
	if !owner.joined {
		return errors.New("invocation artifacts retained for an unjoined consumer")
	}
	if owner.current != nil {
		finish, release := finalizationContext(ctx)
		defer release()
		if err := removeSupervisorInvocationStage(finish, owner.current.path, owner.current.identity, true); err != nil {
			return err
		}
	}
	owner.closed = true
	return nil
}

func borrowInvocationArtifacts(ctx context.Context) (func(bool), error) {
	if owner := invocationArtifactsFrom(ctx); owner != nil {
		return owner.borrow()
	}
	return func(bool) {}, nil
}

func invocationCompiler(ctx context.Context, owner *invocationArtifacts, root string) (any, error) {
	owner.mu.Lock()
	if entry := owner.compilers[root]; entry != nil {
		owner.mu.Unlock()
		select {
		case <-entry.ready:
			return entry.value, entry.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	entry := &invocationArtifact{ready: make(chan struct{})}
	owner.compilers[root] = entry
	owner.mu.Unlock()
	command := goEnvironmentCommand(runGoEnvironment)
	if diagnostics, ok := ctx.Value(artifactDiagnosticsKey{}).(*checkDiagnostics); ok && diagnostics != nil {
		command = diagnostics.runGoEnvironment
	}
	value, err := testBuildEnvironment(command, ctx, root)
	owner.mu.Lock()
	entry.value, entry.err = value, err
	close(entry.ready)
	owner.mu.Unlock()
	return value, err
}

func invocationArtifactValue[T any](ctx context.Context, root, directory, family string, recipe any, construct func(string) (T, error)) (T, bool, error) {
	var zero T
	owner := invocationArtifactsFrom(ctx)
	if owner == nil {
		value, err := construct(directory)
		return value, true, err
	}
	release, err := owner.borrow()
	if err != nil {
		return zero, false, err
	}
	joined := true
	defer func() { release(joined) }()
	compiler, err := invocationCompiler(ctx, owner, root)
	if err != nil {
		joined = toolCommandsJoined(err)
		return zero, false, err
	}
	body, err := json.Marshal(struct {
		Root, Family string
		Compiler     any
		Race         bool
		Recipe       any
	}{root, family, compiler, raceEnabled(ctx), recipe})
	if err != nil {
		return zero, false, err
	}
	key := digestBytes(body)
	owner.mu.Lock()
	if entry := owner.artifacts[key]; entry != nil {
		owner.mu.Unlock()
		select {
		case <-entry.ready:
			if entry.err != nil {
				return zero, false, &sharedArtifactFailure{cause: entry.err}
			}
			value, ok := entry.value.(T)
			if !ok {
				return zero, false, errors.New("invocation artifact type differs")
			}
			return value, false, nil
		case <-ctx.Done():
			return zero, false, ctx.Err()
		}
	}
	entry := &invocationArtifact{ready: make(chan struct{})}
	owner.artifacts[key] = entry
	if owner.current == nil {
		owner.current, err = newCurrentDirectory("enkv-invocation-artifacts-")
	}
	if err == nil {
		directory = filepath.Join(owner.current.path, family+"-"+key)
		err = os.Mkdir(directory, 0700)
	}
	owner.mu.Unlock()
	var value T
	if err == nil {
		value, err = construct(directory)
	}
	joined = toolCommandsJoined(err)
	owner.mu.Lock()
	entry.value, entry.err = value, err
	close(entry.ready)
	owner.mu.Unlock()
	return value, true, err
}

func linkInvocationFile(source, target string) error {
	if source == target {
		return nil
	}
	if err := os.Link(source, target); err != nil {
		original, first := os.Stat(source)
		linked, second := os.Stat(target)
		if first == nil && second == nil && os.SameFile(original, linked) {
			return nil
		}
		return fmt.Errorf("link invocation artifact: %w", err)
	}
	return nil
}

func invocationGoEnvironment(ctx context.Context) []string {
	if owner := invocationArtifactsFrom(ctx); owner != nil {
		return append([]string(nil), owner.environment...)
	}
	return goEnvironment()
}

func invocationGoBinary(ctx context.Context) string {
	if owner := invocationArtifactsFrom(ctx); owner != nil && owner.goBinary != "" {
		return owner.goBinary
	}
	return "go"
}

func linkInvocationDirectory(source, target string) error {
	if source == target {
		return nil
	}
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, cause error) error {
		if cause != nil {
			return cause
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if entry.IsDir() {
			if err := os.Mkdir(destination, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("invocation artifact contains a nonregular file")
		}
		return linkInvocationFile(path, destination)
	})
}
