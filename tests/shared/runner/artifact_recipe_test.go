package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestPublicHelpersShareConstructionAcrossOutputSelections(t *testing.T) {
	root := workflowExecutionFixture(t)
	writeLocalGoFixture(t, root, "core/fixture.go", "package core\n")
	ctx, owner := withInvocationArtifacts(withRacePolicy(workflowTestContext(t, root), false))
	defer func() {
		if err := owner.close(ctx, true); err != nil {
			t.Error(err)
		}
	}()
	// This fixture has no public helper source. Its real constructor failure is
	// retained once, independently of validated installation selections.
	first := testOutputClosure(t, "ENKV/OUTPUT/GITHUB-REPOSITORY/v3", false)
	second := testOutputClosure(t, "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3", false)
	_, firstErr := buildPublicConfigurationArtifact(ctx, root, t.TempDir(), []*outputArtifactClosure{first})
	if firstErr == nil {
		t.Fatal("missing helper source did not fail construction")
	}
	_, nextErr := buildPublicConfigurationArtifact(ctx, root, t.TempDir(), []*outputArtifactClosure{second})
	if !errors.Is(nextErr, firstErr) || len(owner.artifacts) != 1 {
		t.Fatal("output selection repeated identical public helper construction", nextErr, len(owner.artifacts))
	}
	first.Metadata = nil
	_, invalidErr := buildPublicConfigurationArtifact(ctx, root, t.TempDir(), []*outputArtifactClosure{first})
	if invalidErr == nil || errors.Is(invalidErr, firstErr) || len(owner.artifacts) != 1 {
		t.Fatal("cached helper bypassed installation argument validation", invalidErr)
	}
}

// full_only: false
func TestStockAuthorKeepsCapturedConstructionAcrossDescriptorEdits(t *testing.T) {
	root := workflowExecutionFixture(t)
	writeLocalGoFixture(t, root, "core/fixture.go", "package core\n")
	ctx, cancel := context.WithTimeout(withRacePolicy(workflowTestContext(t, root), false), 30*time.Second)
	defer cancel()
	ctx, owner := withInvocationArtifacts(ctx)
	defer func() {
		if err := owner.close(ctx, true); err != nil {
			t.Error(err)
		}
	}()
	directory := t.TempDir()
	source, otherSource := filepath.Join(directory, "author"), filepath.Join(directory, "other-author")
	command, _ := outputCommand("ENKV/OUTPUT/GITHUB-REPOSITORY/v3")
	descriptor, _, err := readOutputDescriptor(ctx, maintainedCloudflareRoot(t), command)
	if err != nil {
		t.Fatal(err)
	}
	body, err := artifact.EncodeDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	for _, author := range []string{source, otherSource} {
		if err := os.MkdirAll(filepath.Join(author, "cmd/plugin"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(author, "cmd/plugin/plugin.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	journal, tool := filepath.Join(directory, "calls"), filepath.Join(directory, "author-tool")
	script := "#!/bin/sh\nprintf 'constructed\\n' >> " + shellQuote(journal) + "\nexit 21\n"
	if err := os.WriteFile(tool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	capturedWorkspace := filepath.Join(directory, "captured.work")
	_, firstErr := buildStockAuthor(ctx, root, tool, source, "./cmd/plugin", filepath.Join(directory, "aws-output"), filepath.Join(directory, "aws.work"), capturedWorkspace, invocationGoEnvironment(ctx))
	var failure *toolFailure
	if !errors.As(firstErr, &failure) || failure.operation != "stock CLI preparation" || !failure.process.Started || !failure.process.Joined {
		t.Fatal("real author failure did not join", firstErr)
	}
	if err := os.WriteFile(filepath.Join(source, "cmd/plugin/plugin.json"), []byte("invalid descriptor after completed construction"), 0600); err != nil {
		t.Fatal(err)
	}
	_, nextErr := buildStockAuthor(ctx, root, tool, source, "./cmd/plugin", filepath.Join(directory, "gcp-output"), filepath.Join(directory, "gcp.work"), capturedWorkspace, invocationGoEnvironment(ctx))
	if !errors.Is(nextErr, firstErr) {
		t.Fatal("descriptor edit or provider workspace invalidated captured author construction", nextErr)
	}
	_, distinctErr := buildStockAuthor(ctx, root, tool, otherSource, "./cmd/plugin", filepath.Join(directory, "other-output"), filepath.Join(directory, "other.work"), capturedWorkspace, invocationGoEnvironment(ctx))
	if distinctErr == nil || errors.Is(distinctErr, firstErr) {
		t.Fatal("distinct actual source owner reused another build", distinctErr)
	}
	calls, err := os.ReadFile(journal)
	if err != nil || strings.Count(string(calls), "constructed\n") != 2 {
		t.Fatal("author construction count differs", string(calls), err)
	}
}
