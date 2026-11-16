package nativeprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeTemporaryRootSeparatorsPreserveConfigurationWorkflow(t *testing.T) {
	// Keep build and fixture preparation independent of the command environment.
	t.Setenv("TMPDIR", t.TempDir())
	cli, helper := workflowExecutables(t)
	f := nativeSequenceSetupRecovery(t, cli, "aws", false)
	s := f.server
	root := t.TempDir()
	environment := []string{"TMPDIR=" + root + "/"}
	run := func(binary, phase string, policy observer.Policy, input []byte, args ...string) workflowChild {
		t.Helper()
		child := workflowRunDeclaredEnvironment(t, s, binary, phase, policy, input, environment, []string{"TMPDIR"}, args...)
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatal("joined command retained temporary files", err)
		}
		return child
	}
	compare := func(path string) {
		t.Helper()
		child := run(cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", path, "--trusted-format", "json", "--json")
		if workflowResult(t, child, "success").Payload.Verdict != "match" {
			t.Fatal("ordinary source capture did not match selected configuration")
		}
		workflowGETOnly(t, child)
	}

	// This installed CLI command is the first regression boundary.
	compare(f.source)
	value := []byte("changed secret with ordinary temporary-root spelling\x00\xff")
	t.Cleanup(func() { clear(value) })
	set := run(cli, "set-change", observer.Policy{NoKMS: true}, value, "set", "--source", f.source, "--source-format", "json", "--name", "binary", "--json")
	workflowResult(t, set, "success")
	if len(set.capture.Events) != 1 {
		t.Fatal("local editing opened provider capabilities")
	}
	workflowResult(t, run(cli, "apply", observer.Policy{}, nil, "apply", "--source", f.source, "--source-format", "json", "--json"), "success")
	compare(f.source)
	pair := workflowReadPair(t, f.source)
	_, selected := workflowHead(t, s)
	objects := s.objectCount()
	sum := sha256.Sum256(value)
	policy := observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}}

	output := nativeMergePair(t, pair)
	separate := run(helper, "authority", policy, nil, "--source", f.source, "--source-format", "json", "--reconstruct-output", output)
	if separate.code != 0 {
		var refusal struct{ PreparationStage uint8 }
		decoded := json.Unmarshal(separate.out, &refusal) == nil
		t.Fatalf("separate reconstruction output refused: exit=%d preparation_decoded=%t preparation_stage=%d %s", separate.code, decoded, refusal.PreparationStage, separate.summary)
	}
	workflowPlaintext(t, separate, "plaintext")
	workflowUnchanged(t, f.source, pair)
	compare(output)
	consumed := run(helper, "authority", policy, nil, "--source", output, "--source-format", "json")
	if consumed.code != 0 {
		t.Fatal("separate output changed expected plaintext", consumed.summary)
	}
	workflowPlaintext(t, consumed, "plaintext")

	recovered := filepath.Join(t.TempDir(), "recovered.json")
	prepared := run(cli, "authority", policy, nil, "prepare", "--source", recovered, "--source-format", "json", "--name", "restored", "--provider", "aws", "--bucket", "fixture-bucket", "--region", "us-east-1", "--prefix", s.prefix, "--normal-signing-key", s.selector(1), "--json")
	result := nativePrepareResult(t, prepared, "reconstruction")
	recoveredPair := workflowReadNamedPair(t, recovered, "restored")
	if result.Recovery.Status != "complete" || result.Delivery.Outcome != "recorded" || result.Delivery.CleanupFailed || result.Delivery.RecoverySource != "" || result.Delivery.EditablePath != recovered || result.Delivery.GeneratedPath != filepath.Join(filepath.Dir(recovered), recoveredPair.reference) {
		t.Fatal("reconstruction changed complete delivery or encrypted source bytes")
	}
	compare(recovered)
	consumed = run(helper, "authority", policy, nil, "--source", recovered, "--source-format", "json")
	if consumed.code != 0 {
		t.Fatal("reconstructed source changed expected plaintext", consumed.summary)
	}
	workflowPlaintext(t, consumed, "plaintext")
	workflowUnchanged(t, f.source, pair)
	_, after := workflowHead(t, s)
	if !reflect.DeepEqual(selected, after) || s.objectCount() != objects {
		t.Fatal("local output, reconstruction or next source use changed selected state")
	}
	s.clean(t)
}
