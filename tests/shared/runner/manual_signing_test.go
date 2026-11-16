package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestManualReleaseSigningKeepsPrivateKeyOutsideOutput(t *testing.T) {
	_, docs := distributionRoots(t)
	realSigner := releaseSigner(t, docs)
	digest := sha256.Sum256([]byte(releaseChecksum))
	expectedDigest := hex.EncodeToString(digest[:])
	for _, condition := range []string{"complete", "interrupted", "signing-failure", "verification-failure"} {
		t.Run(condition, func(t *testing.T) {
			root := t.TempDir()
			privateDirectory, outputDirectory := filepath.Join(root, "key source"), filepath.Join(root, "public output")
			for _, directory := range []string{privateDirectory, outputDirectory} {
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
			}
			privateKey := filepath.Join(privateDirectory, "private key.pem")
			publicKey := filepath.Join(privateDirectory, "public key.pem")
			input, output := filepath.Join(root, "input.record"), filepath.Join(outputDirectory, "signature")
			wrapper := filepath.Join(root, "controlled signer")
			for path, body := range map[string]string{privateKey: releasePrivatePEM, publicKey: releasePublicPEM, input: releaseChecksum, wrapper: manualSigningFixture} {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(wrapper, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			command := exec.Command("sh", filepath.Join(docs, "distribution/sign-release.sh"), wrapper, "cli-checksums", input,
				expectedDigest, privateKey, publicKey, output)
			command.Dir = root
			command.Env = environment(os.Environ(), map[string]string{
				"MANUAL_SIGNER_FIXTURE_DIRECTORY": root, "MANUAL_SIGNER_FIXTURE_MODE": condition, "MANUAL_SIGNER_FIXTURE_REAL": realSigner,
			})
			diagnostic := new(limitedOutput)
			command.Stdout, command.Stderr = diagnostic, diagnostic
			done := make(chan processResult, 1)
			go func() { done <- superviseProcess(ctx, command) }()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case result := <-done:
						if !result.Started || !result.Joined {
							t.Error("manual signing fixture did not settle")
						}
					case <-time.After(10 * time.Second):
						t.Error("manual signing fixture did not join after cancellation")
					}
				}
			})
			deadline := time.Now().Add(15 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
					break
				} else if !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				select {
				case result := <-done:
					joined = true
					t.Fatalf("manual signing exited before signer admission: status=%s started=%v joined=%v", result.Status, result.Started, result.Joined)
				default:
				}
				if !time.Now().Before(deadline) {
					t.Fatal("manual signer did not reach controlled admission")
				}
				time.Sleep(10 * time.Millisecond)
			}
			manualSigningNoPrivateCopies(t, outputDirectory)
			if condition == "interrupted" {
				cancel()
			} else if err := os.WriteFile(filepath.Join(root, "continue"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			var result processResult
			select {
			case result = <-done:
				joined = true
			case <-time.After(15 * time.Second):
				t.Fatal("manual signing did not settle after controlled admission")
			}
			if !result.Started || !result.Joined || diagnostic.overflow {
				t.Fatal("manual signing lost its bounded joined result")
			}
			wantCalls := 1
			switch condition {
			case "complete":
				wantCalls = 3
				body, err := os.ReadFile(output)
				if result.Status != "passed" || err != nil || hex.EncodeToString(body) != releaseSignature {
					t.Fatal("manual signing did not preserve the independently verified signature", result.Status, err)
				}
			case "interrupted":
				if result.Status != "interrupted" || !errors.Is(result.Cause, context.Canceled) {
					t.Fatal("manual signing interruption lost cancellation or positive settlement", result.Status)
				}
			case "signing-failure", "verification-failure":
				if condition == "verification-failure" {
					wantCalls = 2
				}
				if result.Status != "process_failed" || !strings.Contains(diagnostic.String(), condition) {
					t.Fatal("manual signing hid the selected signer failure", result.Status)
				}
			}
			if condition != "complete" {
				if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed manual signing produced a final signature", err)
				}
			}
			calls, err := filepath.Glob(filepath.Join(root, "call-*.json"))
			if err != nil || len(calls) != wantCalls {
				t.Fatal("manual signing changed its exact signer invocation count", err, len(calls))
			}
			for _, path := range calls {
				body, err := os.ReadFile(path)
				var call struct {
					Verify bool   `json:"verify"`
					Key    string `json:"key"`
				}
				if err != nil || json.Unmarshal(body, &call) != nil {
					t.Fatal("cannot inspect controlled signer admission", err)
				}
				if !call.Verify && call.Key != privateKey {
					t.Error("signing did not receive the exact original private-key pathname")
				}
				if call.Verify && (filepath.Base(call.Key) != "public.pem" || filepath.Dir(filepath.Dir(call.Key)) != outputDirectory) {
					t.Error("verification lost its admitted public-key snapshot")
				}
			}
			manualSigningNoPrivateCopies(t, outputDirectory)
		})
	}
}

func manualSigningNoPrivateCopies(t *testing.T, root string) {
	t.Helper()
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(body, []byte(releasePrivatePEM)) {
			t.Error("private key bytes were copied below signature output", entry.Name())
		}
		return nil
	}); err != nil {
		t.Fatal("cannot inspect owned signing files", err)
	}
}

const manualSigningFixture = `#!/usr/bin/env python3
import json, os, pathlib, sys, time
root = pathlib.Path(os.environ["MANUAL_SIGNER_FIXTURE_DIRECTORY"])
mode = os.environ["MANUAL_SIGNER_FIXTURE_MODE"]
args = sys.argv[1:]
verify = "-verify" in args
calls = len(list(root.glob("call-*.json")))
(root / ("call-%d.json" % calls)).write_text(json.dumps({"verify": verify, "key": args[args.index("-key") + 1]}))
if calls == 0:
    (root / "ready").touch()
    deadline = time.monotonic() + 20
    while not (root / "continue").exists():
        if time.monotonic() >= deadline:
            sys.exit("signer fixture admission deadline")
        time.sleep(0.01)
if mode == "signing-failure" or mode == "verification-failure" and verify:
    sys.stderr.write(mode + "\n")
    sys.exit(23)
os.execv(os.environ["MANUAL_SIGNER_FIXTURE_REAL"], [os.environ["MANUAL_SIGNER_FIXTURE_REAL"], *args])
`
