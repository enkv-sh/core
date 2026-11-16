package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

type boundedCommandOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedCommandOutput) Len() int       { return b.buffer.Len() }
func (b *boundedCommandOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedCommandOutput) String() string { return b.buffer.String() }

// full_only: false
func TestBoundedCommandOutputDrainsPipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	written := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(bytes.Repeat([]byte("x"), 8192))
		written <- errors.Join(writeErr, writer.Close())
	}()
	capture := boundedCommandOutput{limit: 4096}
	n, copyErr := io.Copy(&capture, reader)
	writeErr := <-written
	closeErr := reader.Close()
	if copyErr != nil || writeErr != nil || closeErr != nil || n != 8192 || capture.Len() != 4096 || !capture.overflow {
		t.Fatalf("pipe copy bypassed bounded capture: bytes=%d copy=%v write=%v close=%v retained=%d overflow=%t", n, copyErr, writeErr, closeErr, capture.Len(), capture.overflow)
	}
}

func (b *boundedCommandOutput) Write(body []byte) (int, error) {
	n := len(body)
	remaining := b.limit - b.Len()
	if remaining < 0 {
		remaining = 0
	}
	if n > remaining {
		body = body[:remaining]
		b.overflow = true
	}
	_, err := b.buffer.Write(body)
	return n, err
}

func decisionFixtureDirectory(t *testing.T) string {
	t.Helper()
	parent := os.Getenv("ENKV_TEST_PROTECTED_FIXTURES")
	if parent == "" {
		t.Fatal("protected fixtures require the test runner's managed private directory")
	}
	dir, err := os.MkdirTemp(parent, "decision-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("protected fixture cleanup", err)
		}
	})
	return dir
}

type commandWriterFunc func([]byte) (int, error)

func (w commandWriterFunc) Write(b []byte) (int, error) { return w(b) }

// full_only: false
func TestRetiredRestoreSignerUsesClosedUnknownDispatch(t *testing.T) {
	var output, diagnostic bytes.Buffer
	if code := run([]string{"restore-signer", "--connection", "private-path-must-not-echo", "--json"}, &output, &diagnostic); code != 2 {
		t.Fatal("retired restoration still dispatches", code)
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(output.Bytes(), &result) != nil || len(result) != 15 || diagnostic.String() != "unsupported command\n" || bytes.Contains(output.Bytes(), []byte("private-path-must-not-echo")) || bytes.Contains(diagnostic.Bytes(), []byte("private-path-must-not-echo")) {
		t.Fatal("retired dispatch lost canonical unknown shape")
	}
	if _, ok := result["operation_kind"]; ok {
		t.Fatal("retired route retained recognized operation")
	}
	if !bytes.HasPrefix(output.Bytes(), []byte("{\n  \"schema\": \"ProductResult/v1\",\n")) || !bytes.HasSuffix(output.Bytes(), []byte("\n}\n")) {
		t.Fatal("ordinary dispatch failure is not readable JSON", output.String())
	}
	if string(result["request_identity"]) != `"none"` || string(result["replay_identity"]) != `"none"` || string(result["state_result"]) != `"refused"` || string(result["operation_payload"]) != `"none"` || string(result["evidence_ceiling"]) != `"unavailable"` {
		t.Fatal("retired route fabricated authority or evidence")
	}
}

// full_only: false
func TestUnknownDispatchHumanShowsSupportedNextAction(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"unknown-command", "--private-option", "private-argument-body"}, &out, &diagnostic); code != 2 || diagnostic.String() != "unsupported command\n" {
		t.Fatal("unknown command did not refuse", code, diagnostic.String())
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("Command: refused\n")) || !bytes.Contains(out.Bytes(), []byte("enkv --help")) || bytes.Contains(out.Bytes(), []byte("ProductResult/v1")) || bytes.Contains(out.Bytes(), []byte("private-argument-body")) {
		t.Fatal("unknown command lost its safe next action", out.String())
	}
}
