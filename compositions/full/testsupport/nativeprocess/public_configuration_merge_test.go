package nativeprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"enkv.sh/core/contract"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeGitMergePreservesIndependentSecretEdits(t *testing.T) {
	cli, helper := workflowExecutables(t)
	f := nativeSequenceSetup(t, cli, "aws")
	s := f.server
	second := []byte("independent second secret\x00\xff")
	set := workflowRun(t, s, cli, "set-change", observer.Policy{NoKMS: true}, second, "set", "--source", f.source, "--source-format", "json", "--name", "second", "--json")
	workflowResult(t, set, "success")
	if len(set.capture.Events) != 1 {
		t.Fatal("local set opened provider capabilities")
	}
	workflowResult(t, workflowRun(t, s, cli, "change", observer.Policy{}, nil, "apply", "--source", f.source, "--source-format", "json", "--json"), "success")
	base := workflowReadPair(t, f.source)
	leftPath := nativeMergePair(t, base)
	rightPath := nativeMergePair(t, base)
	leftValue := []byte("changed first secret on left\x00\xff")
	rightValue := []byte("changed second secret on right\xff\x00")
	for _, edit := range []struct {
		path, name string
		value      []byte
	}{{leftPath, "binary", leftValue}, {rightPath, "second", rightValue}} {
		child := workflowRun(t, s, cli, "set-change", observer.Policy{NoKMS: true}, edit.value, "set", "--source", edit.path, "--source-format", "json", "--name", edit.name, "--json")
		workflowResult(t, child, "success")
		if len(child.capture.Events) != 1 {
			t.Fatal("branch set opened provider capabilities")
		}
	}
	left, right := workflowReadPair(t, leftPath), workflowReadPair(t, rightPath)
	if !bytes.Equal(base.editable, left.editable) || !bytes.Equal(base.editable, right.editable) || left.reference != base.reference || right.reference != base.reference {
		t.Fatal("secret edits changed stable manifest or path")
	}
	merged, conflict := nativeGitMergeFile(t, left.generated, base.generated, right.generated)
	if conflict {
		t.Fatal("disjoint existing encrypted records did not merge")
	}
	expected := nativeMergeSealed(t, base.generated)
	expected["binary"] = nativeMergeSealed(t, left.generated)["binary"]
	expected["second"] = nativeMergeSealed(t, right.generated)["second"]
	nativeMergeExactRecords(t, merged, expected)
	joined := base
	joined.generated = merged
	path := nativeMergePair(t, joined)
	restore := workflowReadOnlyPair(t, path, joined)
	applied := workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	workflowReceipt(t, workflowResult(t, applied, "success").Receipt, contract.OperationApplyDeclaration)
	workflowOneHeadAttempt(t, applied, true, 200)
	workflowUnchanged(t, path, joined)
	compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", path, "--trusted-format", "json", "--json")
	if workflowResult(t, compared, "success").Payload.Verdict != "match" {
		t.Fatal("merged current pair did not compare")
	}
	workflowGETOnly(t, compared)
	expectedHashes := map[string]string{}
	for name, value := range map[string][]byte{"binary": leftValue, "second": rightValue} {
		sum := sha256.Sum256(value)
		expectedHashes[name] = hex.EncodeToString(sum[:])
	}
	child := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: expectedHashes}, nil, "--source", path, "--source-format", "json")
	if child.code != 0 {
		t.Fatal("merged secrets failed fresh-process reconstruction", child.summary)
	}
	count := 0
	for _, event := range child.capture.Events {
		if event.Kind == "plaintext" {
			if event.Count != 1 || !event.Matched {
				t.Fatal("merged selected plaintext differed")
			}
			count++
		}
	}
	if count != 2 {
		t.Fatal("reconstruction did not verify both selected secrets")
	}
	workflowUnchanged(t, path, joined)
	restore()
	s.clean(t)
}

func nativeMergePair(t *testing.T, pair workflowPair) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "configuration.json")
	if os.Mkdir(filepath.Join(dir, ".enkv"), 0700) != nil || os.WriteFile(path, pair.editable, 0600) != nil || os.WriteFile(filepath.Join(dir, pair.reference), pair.generated, 0600) != nil {
		t.Fatal("portable merge pair unavailable")
	}
	return path
}

// Git's ordinary three-way file merger uses these exact branch images without
// changing any repository index or creating commits.
func nativeGitMergeFile(t *testing.T, left, base, right []byte) ([]byte, bool) {
	t.Helper()
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "left"), filepath.Join(dir, "base"), filepath.Join(dir, "right")}
	for i, body := range [][]byte{left, base, right} {
		if err := os.WriteFile(paths[i], body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "git", "merge-file", "--stdout", "--diff3", paths[0], paths[1], paths[2])
	command.Dir = dir
	output, err := command.Output()
	if ctx.Err() != nil {
		t.Fatal("Git merge did not join before deadline")
	}
	if err == nil {
		return output, false
	}
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() == 1 {
		return output, true
	}
	t.Fatal("Git merge failed", err)
	return nil, false
}

func nativeMergeSealed(t *testing.T, body []byte) map[string][]byte {
	t.Helper()
	var generated struct {
		Secrets map[string]struct{ Sealed []byte }
	}
	if json.Unmarshal(body, &generated) != nil {
		t.Fatal("merged satellite is not JSON")
	}
	rows := make(map[string][]byte, len(generated.Secrets))
	for name, row := range generated.Secrets {
		if len(row.Sealed) == 0 {
			t.Fatal("complete encrypted record absent")
		}
		rows[name] = row.Sealed
	}
	return rows
}

func nativeMergeExactRecords(t *testing.T, body []byte, expected map[string][]byte) {
	t.Helper()
	rows := nativeMergeSealed(t, body)
	if len(rows) != len(expected) {
		t.Fatal("merge omitted or added an encrypted record")
	}
	for name, want := range expected {
		if !bytes.Equal(rows[name], want) {
			t.Fatal("merge changed a selected complete encrypted record")
		}
	}
}

// full_only: false
func TestPublicNativeGitInsertionConflictRequiresCompleteRecords(t *testing.T) {
	cli, helper := workflowExecutables(t)
	f := nativeSequenceSetup(t, cli, "aws")
	s := f.server
	base := f.pair
	leftPath, rightPath := nativeMergePair(t, base), nativeMergePair(t, base)
	values := map[string][]byte{"left-new": []byte("left addition\x00\xff"), "right-new": []byte("right addition\xff\x00")}
	for _, edit := range []struct{ path, name string }{{leftPath, "left-new"}, {rightPath, "right-new"}} {
		child := workflowRun(t, s, cli, "set-change", observer.Policy{NoKMS: true}, values[edit.name], "set", "--source", edit.path, "--source-format", "json", "--name", edit.name, "--json")
		workflowResult(t, child, "success")
		if len(child.capture.Events) != 1 {
			t.Fatal("local addition opened provider capabilities")
		}
	}
	left, right := workflowReadPair(t, leftPath), workflowReadPair(t, rightPath)
	conflicted, conflict := nativeGitMergeFile(t, left.generated, base.generated, right.generated)
	if !conflict || !bytes.Contains(conflicted, []byte("<<<<<<<")) {
		t.Fatal("same insertion point did not exercise Git conflict markers")
	}
	marked := left
	marked.generated = conflicted
	markedPath := nativeMergePair(t, marked)
	refused := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "apply", "--source", markedPath, "--source-format", "json", "--json")
	var refusal struct {
		Schema  string
		State   string `json:"state_result"`
		Receipt string `json:"receipt_hex"`
	}
	if refused.code != 2 || json.Unmarshal(refused.out, &refusal) != nil || refusal.Schema != "ProductResult/v1" || refusal.State != "refused" || refusal.Receipt != "" || len(refused.capture.Events) != 1 {
		t.Fatal("conflict markers reached provider or mutation admission")
	}
	// This is an explicit manual choice of both complete new records. No source
	// value is read again and neither encrypted record is altered or retargeted.
	selected := base
	for _, document := range []struct {
		base, left, right []byte
		container         string
		out               *[]byte
	}{{base.editable, left.editable, right.editable, "entries", &selected.editable}, {base.generated, left.generated, right.generated, "secrets", &selected.generated}} {
		var original, leftDocument, rightDocument map[string]json.RawMessage
		if json.Unmarshal(document.base, &original) != nil || json.Unmarshal(document.left, &leftDocument) != nil || json.Unmarshal(document.right, &rightDocument) != nil {
			t.Fatal("manual source image invalid")
		}
		var kept, leftRows, rightRows map[string]json.RawMessage
		if json.Unmarshal(original[document.container], &kept) != nil || json.Unmarshal(leftDocument[document.container], &leftRows) != nil || json.Unmarshal(rightDocument[document.container], &rightRows) != nil {
			t.Fatal("manual container invalid")
		}
		kept["left-new"], kept["right-new"] = leftRows["left-new"], rightRows["right-new"]
		rows, err := json.Marshal(kept)
		if err != nil {
			t.Fatal(err)
		}
		original[document.container] = rows
		body, err := json.MarshalIndent(original, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		*document.out = append(body, '\n')
	}
	expected := nativeMergeSealed(t, base.generated)
	expected["left-new"] = nativeMergeSealed(t, left.generated)["left-new"]
	expected["right-new"] = nativeMergeSealed(t, right.generated)["right-new"]
	nativeMergeExactRecords(t, selected.generated, expected)
	path := nativeMergePair(t, selected)
	restore := workflowReadOnlyPair(t, path, selected)
	applied := workflowRun(t, s, cli, "apply", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	workflowReceipt(t, workflowResult(t, applied, "success").Receipt, contract.OperationApplyDeclaration)
	workflowOneHeadAttempt(t, applied, true, 200)
	compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", path, "--trusted-format", "json", "--json")
	if workflowResult(t, compared, "success").Payload.Verdict != "match" {
		t.Fatal("manually selected pair did not compare")
	}
	workflowGETOnly(t, compared)
	values["binary"] = f.value
	hashes := map[string]string{}
	for name, value := range values {
		sum := sha256.Sum256(value)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	child := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: hashes}, nil, "--source", path, "--source-format", "json")
	if child.code != 0 {
		t.Fatal("manual merged secrets failed fresh-process reconstruction", child.summary)
	}
	count := 0
	for _, event := range child.capture.Events {
		if event.Kind == "plaintext" {
			if event.Count != 1 || !event.Matched {
				t.Fatal("manual selection changed plaintext")
			}
			count++
		}
	}
	if count != 3 {
		t.Fatal("manual merge lost a selected secret")
	}
	workflowUnchanged(t, path, selected)
	restore()
	s.clean(t)
}
