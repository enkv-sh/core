package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const releaseChecksum = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  enkv.tar.gz\n"

// OpenSSL 3.5.9 pkeyutl -sign -rawin, RFC 8032 section 7.1 seed,
// and the SHA-256("abc") checksum literal above. Shared with the public codec's independent vector.
const releaseSignature = "29cc54b459bae27bd5958e6b587d4157c2f189eab4b02093e0c75ac133908add36f6503ee13d3e83b307ff504777edb6016f58d1150e704a75fd2d066345d00c"

// RFC 8032 section 7.1 test 1 seed/public bytes, wrapped in the RFC 8410
// PKCS8 DER prefix 302e020100300506032b657004220420 and SPKI DER prefix
// 302a300506032b6570032100, then base64-encoded. The alternate SPKI uses
// RFC 8032 section 7.1 test 2 public bytes. Only the public signer opens PKCS8.
const releasePrivatePEM = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\n-----END PRIVATE KEY-----\n"
const releasePublicPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n"
const releaseOtherPublicPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=\n-----END PUBLIC KEY-----\n"

func releaseSigner(t *testing.T, docs string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "enkv-artifact-sign")
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	runModuleModeCommand(t, ctx, filepath.Join(docs, "sdk/artifact"), map[string]string{
		"GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off",
	}, "build", "-mod=readonly", "-p=1", "-trimpath", "-o", binary, "./cmd/enkv-artifact-sign")
	return binary
}

func releaseRun(t *testing.T, directory string, env map[string]string, args ...string) (bool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	command := exec.Command(args[0], args[1:]...)
	command.Dir, command.Env = directory, environment(os.Environ(), env)
	output := new(limitedOutput)
	command.Stdout, command.Stderr = output, output
	result := superviseProcess(ctx, command)
	if !result.Started || !result.Joined || output.overflow || ctx.Err() != nil || result.Status != "passed" && result.Status != "process_failed" {
		t.Fatalf("release command did not settle: %+v %s", result, output.String())
	}
	if result.Status != "passed" {
		t.Logf("release command refused input: %s", output.String())
	}
	return result.Status == "passed", output.String()
}

func releasePEM(t *testing.T, directory string) {
	t.Helper()
	rawSourceWrite(t, directory, "private.pem", releasePrivatePEM)
	rawSourceWrite(t, directory, "public.pem", releasePublicPEM)
}

// full_only: false
func TestReleaseSigningTemplates(t *testing.T) {
	_, docs := distributionRoots(t)
	signer := releaseSigner(t, docs)
	for _, condition := range []string{"manual", "wrong-digest", "wrong-key", "wrong-purpose", "malformed", "record-limit", "private-key-limit", "public-key-limit", "missing-input", "existing-file", "existing-symlink", "existing-directory"} {
		t.Run(condition, func(t *testing.T) {
			dir := t.TempDir()
			releasePEM(t, dir)
			body, purpose := releaseChecksum, "cli-checksums"
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
			switch condition {
			case "wrong-digest":
				digest = strings.Repeat("0", 64)
			case "wrong-key":
				rawSourceWrite(t, dir, "public.pem", releaseOtherPublicPEM)
			case "wrong-purpose":
				purpose = "plugin-index"
			case "malformed":
				body = strings.TrimSuffix(body, "\n")
				digest = fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
			case "record-limit":
				body = strings.Repeat("x", 1048577)
				digest = fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
			case "private-key-limit":
				rawSourceWrite(t, dir, "private.pem", strings.Repeat("x", 16385))
			case "public-key-limit":
				rawSourceWrite(t, dir, "public.pem", strings.Repeat("x", 16385))
			}
			rawSourceWrite(t, dir, "input.record", body)
			if condition == "missing-input" {
				if err := os.Remove(filepath.Join(dir, "input.record")); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(dir, "signature")
			switch condition {
			case "existing-file":
				rawSourceWrite(t, dir, "signature", "preserved")
			case "existing-symlink":
				rawSourceWrite(t, dir, "target", "preserved")
				if err := os.Symlink("target", output); err != nil {
					t.Fatal(err)
				}
			case "existing-directory":
				if err := os.Mkdir(output, 0700); err != nil {
					t.Fatal(err)
				}
				rawSourceWrite(t, output, "child", "preserved")
			}
			args := []string{"sh", filepath.Join(docs, "distribution/sign-release.sh"), signer, purpose, filepath.Join(dir, "input.record"), digest, filepath.Join(dir, "private.pem"), filepath.Join(dir, "public.pem"), output}
			env := map[string]string{}
			success, detail := releaseRun(t, dir, env, args...)
			want := condition == "manual"
			if success != want {
				t.Fatalf("success=%v want %v", success, want)
			}
			if want {
				actual, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(actual) != releaseSignature {
					t.Fatalf("signature differs from independent OpenSSL fixture: %x", actual)
				}
			} else {
				var reason string
				switch condition {
				case "wrong-digest":
					reason = "qualified input SHA-256 mismatch"
				case "wrong-key":
					reason = "artifact signature refused"
				case "wrong-purpose", "malformed":
					reason = "selected purpose or record"
				case "record-limit", "public-key-limit":
					reason = "signing input exceeds byte limit"
				case "private-key-limit":
					reason = "read key:"
				case "missing-input":
					reason = "FileNotFoundError:"
				case "existing-file", "existing-symlink", "existing-directory":
					reason = "create signature:"
				default:
					t.Fatal("missing signing refusal assertion", condition)
				}
				if !strings.Contains(detail, reason) {
					t.Fatalf("signing did not reach intended refusal %q: %s", reason, detail)
				}
				switch condition {
				case "existing-file", "existing-symlink":
					actual, err := os.ReadFile(output)
					if err != nil || string(actual) != "preserved" {
						t.Fatal("existing output changed", err)
					}
					if condition == "existing-symlink" {
						info, err := os.Lstat(output)
						if err != nil || info.Mode()&os.ModeSymlink == 0 {
							t.Fatal("existing symlink replaced", err)
						}
					}
				case "existing-directory":
					actual, err := os.ReadFile(filepath.Join(output, "child"))
					if err != nil || string(actual) != "preserved" {
						t.Fatal("existing directory changed", err)
					}
				default:
					if _, err := os.Lstat(output); !os.IsNotExist(err) {
						t.Fatal("failed signing created output", err)
					}
				}
			}
			for _, pattern := range []string{".enkv-sign.*", "release-key.*"} {
				matches, err := filepath.Glob(filepath.Join(dir, pattern))
				if err != nil || len(matches) != 0 {
					t.Fatal("temporary key directory remains", matches, err)
				}
			}
		})
	}

}

// full_only: false
func TestReleasePublicationTemplate(t *testing.T) {
	core, extensions := distributionRoots(t)
	for _, test := range []struct{ root, script string }{
		{core, "distribution/test_release_workflow.py"},
		{extensions, "distribution/test_release.py"},
	} {
		if ok, detail := releaseRun(t, test.root, nil, "python3", test.script); !ok {
			t.Fatalf("%s: %s", test.script, detail)
		}
	}
	for _, root := range []string{core, extensions} {
		body, err := os.ReadFile(filepath.Join(root, ".github/workflows/release.yml"))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		for _, required := range []string{"workflow_dispatch:", "permissions: {}", "persist-credentials: false", "environment: release-signing", "environment: release-draft", "github.ref == 'refs/heads/main'", "github.repository == 'enkv-sh/" + strings.TrimPrefix(filepath.Base(root), "enkv-") + "'", "github.ref_protected", "SOURCE_COMMIT: ${{ github.sha }}", "cancel-in-progress: false", "stage-release.py"} {
			if !strings.Contains(text, required) {
				t.Fatalf("release workflow missing %q", required)
			}
		}
		for _, forbidden := range []string{"pull_request:", "push:", "--clobber", "draft: false", "REPLACE_", "inputs.source_commit", "vars.RELEASE_", "    inputs:"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("unsafe release workflow %q", forbidden)
			}
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "uses: actions/") {
				_, pin, ok := strings.Cut(line, "@")
				if !ok || len(pin) != 40 {
					t.Fatalf("action is not pinned: %s", line)
				}
			}
		}
	}
}
