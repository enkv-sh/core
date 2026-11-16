package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cliDiagnosticWriter struct {
	body                    bytes.Buffer
	limit, calls, attempted int
	failure                 error
}

// full_only: false
func TestCLITextDeliveryPreservesFailure(t *testing.T) {
	failure := errors.New("controlled output failure")
	for _, tc := range []struct {
		name, text    string
		failure, want error
	}{
		{"writer-error", "result\n", failure, failure},
		{"short-write", "result\n", nil, io.ErrShortWrite},
		{"empty", "", failure, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := &cliDiagnosticWriter{limit: 3, failure: tc.failure}
			if err := writeText(output, tc.text); !errors.Is(err, tc.want) {
				t.Fatalf("delivery error=%v want=%v", err, tc.want)
			}
			if tc.text == "" {
				if output.calls != 0 {
					t.Fatal("empty text used the output stream")
				}
			} else if output.body.String() != "res" || output.attempted != len(tc.text) {
				t.Fatal("delivery prefix or attempted bytes differ", output.body.String(), output.attempted)
			}
		})
	}
}

func (w *cliDiagnosticWriter) Write(body []byte) (int, error) {
	w.calls++
	w.attempted += len(body)
	if w.limit < 0 {
		return w.body.Write(body)
	}
	n, err := w.body.Write(body[:min(len(body), max(0, w.limit-w.body.Len()))])
	if err != nil {
		return n, err
	}
	return n, w.failure
}

// full_only: false
func TestCLIDiagnosticDeliveryControlsExitStatus(t *testing.T) {
	checksums := filepath.Join(t.TempDir(), "checksums.txt")
	for _, tc := range []struct {
		name       string
		args       []string
		diagnostic string
		code       int
		usage      bool
	}{
		{"help", []string{"-help"}, "Usage of enkv-cli-package:\n", 0, true},
		{"parse-error", []string{"-unknown"}, "flag provided but not defined: -unknown\n", 2, true},
		{"checksums-no-archive", []string{"-checksums", checksums}, "checksums requires only archive paths\n", 2, false},
		{"positional", []string{"unexpected"}, "unexpected positional arguments\n", 2, false},
		{"absent-package-config", nil, "directory, output and semantic version are required\n", 1, false},
	} {
		for _, mode := range []string{"healthy", "error-after-prefix", "nil-error-short"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				const prefix = 7
				stderr := &cliDiagnosticWriter{limit: -1}
				wantCode := tc.code
				if mode != "healthy" {
					stderr.limit = prefix
					wantCode = 1
					if mode == "error-after-prefix" {
						stderr.failure = errors.New("controlled diagnostic delivery failure")
					}
				}
				var stdout bytes.Buffer
				code := run(t.Context(), tc.args, &stdout, stderr)
				if code != wantCode || stdout.Len() != 0 {
					t.Fatalf("diagnostic outcome: code=%d want=%d stdout=%q", code, wantCode, stdout.String())
				}
				if stderr.calls == 0 {
					t.Fatal("required diagnostic was not attempted")
				}
				if mode == "healthy" {
					got := stderr.body.String()
					if !strings.HasPrefix(got, tc.diagnostic) || tc.usage && !strings.Contains(got, "write a new checksum file for positional archive paths") || !tc.usage && got != tc.diagnostic {
						t.Fatalf("healthy diagnostic differs: %q", got)
					}
				} else if got := stderr.body.String(); got != tc.diagnostic[:prefix] || stderr.attempted <= prefix {
					t.Fatalf("failed diagnostic did not deliver a strict prefix: body=%q attempted=%d", got, stderr.attempted)
				}
				if _, err := os.Lstat(checksums); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("diagnostic refusal published checksum output", err)
				}
			})
		}
	}
}
