package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"enkv.sh/sdk/artifact"
)

func stockArchiveFixture(t *testing.T, condition string) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	names := []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "enkv"}
	if condition == "notice" {
		names = []string{"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "enkv"}
	}
	switch condition {
	case "missing":
		names = names[1:]
	case "extra":
		names = append(names, "extra")
	case "duplicate":
		names = append(names, "enkv")
	case "order":
		names[0], names[1] = names[1], names[0]
	}
	incomplete := false
	for i, name := range names {
		body := []byte("fixed " + name)
		mode := int64(0644)
		if name == "enkv" {
			mode = 0755
		}
		header := &tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if i == 0 {
			switch condition {
			case "path":
				header.Name = "../LICENSE"
			case "symlink":
				header.Typeflag = tar.TypeSymlink
				header.Size = 0
				header.Linkname = "elsewhere"
				body = nil
			case "directory":
				header.Typeflag = tar.TypeDir
				header.Size = 0
				body = nil
			case "gnu":
				header.Format = tar.FormatGNU
			case "pax":
				header.Format = tar.FormatPAX
				header.PAXRecords = map[string]string{"comment": "extra"}
			case "mode":
				header.Mode = 0600
			case "owner":
				header.Uid = 1
			case "time":
				header.ModTime = time.Unix(1, 0)
			case "body-short":
				header.Size++
				incomplete = true
			case "expanded-bound":
				header.Size = artifact.MaxArchiveBytes
				body = nil
				incomplete = true
			case "member-bound":
				header.Size = artifact.MaxArchiveBytes + 1
				body = nil
				incomplete = true
			}
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal("fixture header failed", condition, err)
		}
		if _, err := archive.Write(body); err != nil {
			t.Fatal("fixture body failed", condition, err)
		}
		if incomplete {
			break
		}
	}
	if !incomplete {
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if condition == "expanded-trailing" {
		if _, err := compressed.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	body := slices.Clone(output.Bytes())
	switch condition {
	case "gzip-crc":
		body[len(body)-8] ^= 1
	case "truncated":
		body = body[:len(body)-5]
	case "concatenated":
		body = append(body, body...)
	case "compressed-trailing":
		body = append(body, 1)
	}
	return body
}

// full_only: false
func TestStockCLIArchiveUsesClosedStreamingLayout(t *testing.T) {
	for _, condition := range []string{"complete", "notice"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "archive.tar.gz")
			body := stockArchiveFixture(t, condition)
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			install := filepath.Join(directory, "installed")
			if err := os.Mkdir(install, 0700); err != nil {
				t.Fatal(err)
			}
			observed, err := extractStockCLIArchive(t.Context(), path, install)
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 3
			if condition == "notice" {
				wantCount = 4
			}
			if len(observed.members) != wantCount || observed.archive.Length != uint64(len(body)) || observed.archive.SHA256 != artifact.Digest(sha256.Sum256(body)) {
				t.Fatal("archive identity or whole member set differs")
			}
			for name, member := range observed.members {
				want := []byte("fixed " + name)
				if member.Length != uint64(len(want)) || member.SHA256 != artifact.Digest(sha256.Sum256(want)) {
					t.Fatal("member differs", name)
				}
				actual, err := os.ReadFile(filepath.Join(install, name))
				if err != nil || !bytes.Equal(actual, want) {
					t.Fatal("extraction differs", name, err)
				}
			}
		})
	}
	for _, condition := range []string{"missing", "extra", "duplicate", "order", "path", "symlink", "directory", "gnu", "pax", "mode", "owner", "time", "body-short", "expanded-bound", "member-bound", "gzip-crc", "truncated", "concatenated", "compressed-trailing", "expanded-trailing"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "archive.tar.gz")
			if err := os.WriteFile(path, stockArchiveFixture(t, condition), 0600); err != nil {
				t.Fatal(err)
			}
			install := filepath.Join(directory, "installed")
			if err := os.Mkdir(install, 0700); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"missing": "member set or tar length refused", "extra": "member refused", "duplicate": "attributes refused", "order": "member set or tar length refused", "path": "member refused",
				"symlink": "attributes refused", "directory": "attributes refused", "gnu": "attributes refused", "pax": "attributes refused", "mode": "attributes refused", "owner": "attributes refused", "time": "attributes refused",
				"body-short": "member incomplete", "expanded-bound": "expanded archive exceeds bound", "member-bound": "attributes refused", "gzip-crc": "expanded trailing bytes", "truncated": "expanded trailing bytes", "concatenated": "compressed trailing bytes", "compressed-trailing": "compressed trailing bytes", "expanded-trailing": "expanded trailing bytes",
			}[condition]
			if _, err := extractStockCLIArchive(t.Context(), path, install); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal("invalid archive did not reach its exact refusal", condition, want, err)
			}
		})
	}
}

// full_only: false
func TestStockCLIArchiveRefusesCancelledOversizedAndNonemptyInputs(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "archive.tar.gz")
	if err := os.WriteFile(path, stockArchiveFixture(t, "complete"), 0600); err != nil {
		t.Fatal(err)
	}
	install := filepath.Join(directory, "installed")
	if err := os.Mkdir(install, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := extractStockCLIArchive(ctx, path, install); err == nil {
		t.Fatal("cancelled extraction passed")
	}
	if err := os.WriteFile(filepath.Join(install, "foreign"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := extractStockCLIArchive(t.Context(), path, install); err == nil {
		t.Fatal("nonempty extraction passed")
	}
	if err := os.Remove(filepath.Join(install, "foreign")); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, artifact.MaxArchiveBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := extractStockCLIArchive(t.Context(), path, install); err == nil {
		t.Fatal("oversized compressed input passed")
	}
	if entries, err := os.ReadDir(install); err != nil || len(entries) != 0 {
		t.Fatal("early refusal created output", err)
	}
}

type stockCLIProductionFixture struct {
	ctx          context.Context
	prepared     preparedStockCLI
	construction stockCLIConstruction
	binding      preparationBinding
	directory    string
}

func prepareStockCLIProductionFixture(t *testing.T, ctx context.Context) stockCLIProductionFixture {
	t.Helper()
	t.Setenv("GOFLAGS", "")
	root := maintainedCloudflareRoot(t)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"plugin-public.pem": cliArchivePluginPublicPEM, "cli-public.pem": cliArchiveCLIPublicPEM} {
		rawSourceWrite(t, directory, name, body)
	}
	ctx, owner := withInvocationArtifacts(ctx)
	joined := true
	var prepared preparedStockCLI
	t.Cleanup(func() {
		tail, finish := finalizationContext(ctx)
		defer finish()
		if err := owner.close(tail, joined); err != nil {
			t.Error("stock CLI invocation owner did not close after joined construction", err)
		}
		if owner != nil && joined && prepared.executable != "" {
			if _, err := os.Stat(prepared.executable); !os.IsNotExist(err) {
				t.Error("stock CLI invocation retained its disposed executable", err)
			}
		}
	})
	binding, err := prepareBindingOwned(nil, ctx, root, true)
	joined = toolCommandsJoined(err) && sourceCommandsJoined(err)
	if err != nil {
		t.Fatal(err)
	}
	construction := stockCLIConstruction{version: "1.2.3", cliKey: stockCLIKeyInput{path: filepath.Join(directory, "cli-public.pem"), expected: artifact.DigestLength{SHA256: artifact.Digest(sha256.Sum256([]byte(cliArchiveCLIPublicPEM))), Length: uint64(len(cliArchiveCLIPublicPEM))}}, pluginKeys: []stockCLIKeyInput{{path: filepath.Join(directory, "plugin-public.pem"), expected: artifact.DigestLength{SHA256: artifact.Digest(sha256.Sum256([]byte(cliArchivePluginPublicPEM))), Length: uint64(len(cliArchivePluginPublicPEM))}}}}
	prepared, err = prepareStockCLI(ctx, root, filepath.Join(directory, "production"), construction, binding)
	joined = joined && toolCommandsJoined(err)
	if prepared.diagnostics.Len() != 0 {
		t.Logf("stock CLI preparation diagnostics: %s", prepared.diagnostics.String())
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.verify(ctx); err != nil {
		t.Fatal(err)
	}
	if prepared.packaging.Status != "passed" || !prepared.packaging.Started || !prepared.packaging.Joined || !prepared.build.Started || !prepared.build.Joined || len(prepared.members) != 3 {
		t.Fatal("actual production/source/legal construction incomplete")
	}
	// The main owner has no NOTICE source today. A future owner change must
	// update this independently expected current member set.
	if _, present := prepared.members["NOTICE"]; present {
		t.Fatal("production archive invented main NOTICE")
	}
	return stockCLIProductionFixture{ctx: ctx, prepared: prepared, construction: construction, binding: binding, directory: directory}
}

// full_only: false
func TestStockCLIProductionConstructionAndRevalidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 8*time.Minute)
	defer cancel()
	fixture := prepareStockCLIProductionFixture(t, ctx)
	prepared := fixture.prepared
	directory := fixture.directory
	info, err := buildinfo.ReadFile(prepared.executable)
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"compiler", "native", "provider-only", "tag", "compiled-module", "main-version"} {
		t.Run(damage, func(t *testing.T) {
			changed := *info
			changed.Settings = slices.Clone(info.Settings)
			changed.Deps = slices.Clone(info.Deps)
			switch damage {
			case "compiler":
				changed.GoVersion = "go1.27.0"
			case "native":
				for i := range changed.Settings {
					if changed.Settings[i].Key == "GOARCH" {
						changed.Settings[i].Value = "other"
					}
				}
			case "provider-only":
				for i, m := range changed.Deps {
					if m.Path == "enkv.sh/compositions/gcp" {
						changed.Deps = append(changed.Deps[:i], changed.Deps[i+1:]...)
						break
					}
				}
			case "tag":
				changed.Settings = append(changed.Settings, debug.BuildSetting{Key: "-tags", Value: "enkv_aws"})
			case "compiled-module":
				changed.Deps = append(changed.Deps, &debug.Module{Path: "example.invalid/extra", Version: "v1.0.0"})
			case "main-version":
				changed.Main.Version = "v1.0.0"
			}
			if err := checkStockCLIBuild(&changed, prepared.selected); err == nil {
				t.Fatal("bad actual stock build facts accepted", damage)
			}
		})
	}
	if err := (preparedStockCLI{}).verify(ctx); err == nil {
		t.Fatal("missing production constructor proof accepted")
	}
	for _, damage := range []string{"missing-join", "failed-producer", "archive-bytes", "executable-bytes"} {
		t.Run(damage, func(t *testing.T) {
			changed := prepared
			switch damage {
			case "missing-join":
				changed.packaging.Joined = false
			case "failed-producer":
				changed.packaging.Status = "process_failed"
			case "archive-bytes", "executable-bytes":
				name := "archive"
				mode := os.FileMode(0444)
				if damage == "executable-bytes" {
					name = "executable"
					mode = 0555
				}
				path := filepath.Join(directory, "changed-"+name)
				if err := os.WriteFile(path, []byte("different immutable subject"), mode); err != nil {
					t.Fatal(err)
				}
				if damage == "archive-bytes" {
					changed.archive = path
				} else {
					changed.executable = path
				}
			}
			want := map[string]string{"missing-join": "production construction missing", "failed-producer": "production construction missing", "archive-bytes": "admitted archive changed", "executable-bytes": "admitted executable changed"}[damage]
			if err := changed.verify(ctx); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal("changed construction did not reach its exact refusal", damage, want, err)
			}
		})
	}
	// All damage below is local test data after positively joined construction.
	// Restore the original inode/mode, then require a healthy verification before
	// selecting the next independent refusal control.
	if err := prepared.verify(ctx); err != nil {
		t.Fatal("mode control began from invalid subject", err)
	}
	mode := prepared.executableFile.Mode().Perm()
	if err := os.Chmod(prepared.executable, 0444); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(prepared.executable, mode); err != nil {
			t.Error(err)
		}
	}()
	if err := prepared.verify(ctx); err == nil || !strings.Contains(err.Error(), "admitted executable changed") {
		t.Fatal("changed executable mode was not reached", err)
	}
	if err := os.Chmod(prepared.executable, mode); err != nil {
		t.Fatal(err)
	}
	if err := prepared.verify(ctx); err != nil {
		t.Fatal("mode control did not restore healthy subject", err)
	}
}

// full_only: false
func TestStockCLIProductionConstructionReproducesIndependentBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 8*time.Minute)
	defer cancel()
	fixture := prepareStockCLIProductionFixture(t, ctx)
	prepared := fixture.prepared
	reusedDirectory := filepath.Join(fixture.directory, "production-reused")
	reused, err := prepareStockCLI(fixture.ctx, prepared.root, reusedDirectory, fixture.construction, fixture.binding)
	if err != nil || reused.archive != prepared.archive || reused.executable != prepared.executable || reused.archiveIdentity != prepared.archiveIdentity || reused.executableIdentity != prepared.executableIdentity {
		t.Fatal("compatible invocation borrow did not reuse its actual stock CLI build", err)
	}
	if _, err := os.Stat(reusedDirectory); !os.IsNotExist(err) {
		t.Fatal("compatible borrow created a separate construction directory", err)
	}
	// A separate invocation constructs an independent subject. Its expected
	// bytes are compared with the first actual production construction.
	second := prepareStockCLIProductionFixture(t, ctx).prepared
	if second.archiveIdentity != prepared.archiveIdentity || second.executableIdentity != prepared.executableIdentity || second.archive == prepared.archive || second.executable == prepared.executable {
		t.Fatal("same production owner did not reproduce immutable bytes at independent paths")
	}
}

// full_only: false
func TestStockCLIProductionKeepsBuildAfterWorkspaceEdits(t *testing.T) {
	ctx, cancel := context.WithTimeout(cacheOnlyGoContext(t.Context()), 8*time.Minute)
	defer cancel()
	fixture := prepareStockCLIProductionFixture(t, ctx)
	prepared := fixture.prepared
	workspaceInfo, err := os.Stat(prepared.workspace)
	if err != nil || workspaceInfo.Mode().Perm() != 0400 {
		t.Fatal("captured construction workspace mode differs", err)
	}
	for _, row := range []struct {
		name, path string
		absentSum  bool
	}{
		{"go.work", prepared.workspace, false},
		{"go.work.sum", prepared.workspace + ".sum", false},
		{"sum-absent-verifier-subject", prepared.workspace + ".sum", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := row.path
			if err := prepared.verify(ctx); err != nil {
				t.Fatal("input control began from invalid subject", err)
			}
			_, err := os.Lstat(path)
			absent := errors.Is(err, os.ErrNotExist)
			if err != nil && !absent {
				t.Fatal(err)
			}
			backup := path + ".original"
			if !absent {
				if err := os.Rename(path, backup); err != nil {
					t.Fatal(err)
				}
			}
			restored := false
			restore := func() {
				if restored {
					return
				}
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if !absent {
					if err := os.Rename(backup, path); err != nil {
						t.Fatal(err)
					}
				}
				restored = true
			}
			defer restore()
			subject := prepared
			if row.absentSum {
				// This narrow verifier subject models the optional sum being
				// absent. Archive/executable bytes and joined construction facts
				// come from the real existing-sum construction above.
				_, absentErr := os.Lstat(path)
				if !errors.Is(absentErr, os.ErrNotExist) {
					t.Fatal("optional-sum verifier subject did not start absent", absentErr)
				}
				if err := subject.verify(ctx); err != nil {
					t.Fatal("absent-sum verifier subject was invalid before appearance", err)
				}
			}
			if err := os.WriteFile(path, []byte("changed\n"), 0400); err != nil {
				t.Fatal(err)
			}
			if err := subject.verify(ctx); err != nil {
				t.Fatal("workspace edit invalidated completed archive/executable construction", path, err)
			}
			reused, err := prepareStockCLI(fixture.ctx, prepared.root, filepath.Join(fixture.directory, row.name+"-borrow"), fixture.construction, fixture.binding)
			if err != nil || reused.archive != prepared.archive || reused.executable != prepared.executable || reused.archiveIdentity != prepared.archiveIdentity || reused.executableIdentity != prepared.executableIdentity {
				t.Fatal("workspace edit rebuilt or changed the invocation artifact", err)
			}
			if err := reused.verify(ctx); err != nil {
				t.Fatal("borrowed build lost actual archive/executable integrity", err)
			}
			restore()
			if err := prepared.verify(ctx); err != nil {
				t.Fatal("input control did not restore healthy subject", err)
			}
		})
	}
}

// full_only: false
func TestStockCLIConstructionRequiresFiniteJoinedProcesses(t *testing.T) {
	if _, _, result, err := stockCLIProcess(context.Background(), "/bin/sh", t.TempDir(), []string{"PATH=/usr/bin:/bin"}, "-c", "exit 0"); err != nil || !result.Started || !result.Joined || result.Status != "passed" {
		t.Fatal("preparation command did not receive its own finite dispatch allowance", result, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, diagnostic := range []string{"", "arbitrary compiler diagnostic\nsecond diagnostic line\n"} {
		name := "quiet-success"
		if diagnostic != "" {
			name = "success-with-diagnostics"
		}
		t.Run(name, func(t *testing.T) {
			body, captured, result, err := stockCLIProcess(ctx, "/bin/sh", t.TempDir(), []string{"PATH=/usr/bin:/bin"}, "-c", "printf '%s' 'selected source bytes'; printf '%s' \"$1\" >&2", "stock-cli-output", diagnostic)
			if err != nil || !result.Started || !result.Joined || result.Status != "passed" {
				t.Fatal("successful producer diagnostics became a process failure", result, err)
			}
			if string(body) != "selected source bytes" {
				t.Fatal("producer stdout changed or included diagnostics", string(body))
			}
			if string(captured) != diagnostic {
				t.Fatal("successful producer diagnostic bytes changed", string(captured))
			}
		})
	}
	t.Run("failed-with-diagnostics", func(t *testing.T) {
		_, _, result, err := stockCLIProcess(ctx, "/bin/sh", t.TempDir(), []string{"PATH=/usr/bin:/bin"}, "-c", "printf '%s' 'producer refusal' >&2; exit 7")
		var failure *toolFailure
		if !errors.As(err, &failure) || !result.Started || !result.Joined || result.Status != "process_failed" {
			t.Fatal("failed producer process did not retain positive join", result, err)
		}
		if string(failure.stderr) != "producer refusal" || len(failure.stdout) != 0 || failure.overflow {
			t.Fatal("failed producer diagnostic bytes changed")
		}
	})
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream+"-overflow", func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "output")
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if err := errors.Join(file.Truncate(maximumToolOutputBytes+1), file.Close()); err != nil {
				t.Fatal(err)
			}
			command := "exec /bin/cat \"$1\""
			if stream == "stderr" {
				command += " >&2"
			}
			_, _, result, err := stockCLIProcess(ctx, "/bin/sh", directory, []string{"PATH=/usr/bin:/bin"}, "-c", command, "stock-cli-output", path)
			var failure *toolFailure
			if !errors.As(err, &failure) || !failure.overflow || !result.Started || !result.Joined || result.Status != "passed" {
				t.Fatal("exit-zero producer output overflow did not refuse with positive join", result)
			}
			stdout, stderr := len(failure.stdout), len(failure.stderr)
			if stream == "stdout" && (stdout != maximumToolOutputBytes || stderr != 0) || stream == "stderr" && (stderr != maximumToolOutputBytes || stdout != 0) {
				t.Fatal("producer output overflow did not retain the exact stream bound", stdout, stderr)
			}
		})
	}
}

// full_only: false
func TestStockCLIKeySnapshotsAreBoundedAndFreezeActualBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(directory, "key.pem")
	body := []byte(cliArchivePluginPublicPEM)
	if err := os.WriteFile(key, body, 0600); err != nil {
		t.Fatal(err)
	}
	input := stockCLIKeyInput{path: key, expected: artifact.DigestLength{SHA256: artifact.Digest(sha256.Sum256(body)), Length: uint64(len(body))}}
	owned := filepath.Join(directory, "owned.pem")
	original, err := snapshotStockCLIKey(ctx, input, owned)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.verify(ctx); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(owned)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("snapshot differs from same opened bytes", err)
	}
	info, err := os.Stat(owned)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("snapshot not immutable", err)
	}
	if err := os.Rename(key, key+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := original.verify(ctx); err == nil {
		t.Fatal("equal-byte original key replacement accepted")
	}
	for _, condition := range []string{"fifo", "too-large", "wrong-identity", "not-public-key"} {
		t.Run(condition, func(t *testing.T) {
			path := filepath.Join(directory, condition)
			candidate := input
			candidate.path = path
			switch condition {
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "too-large":
				if err := os.WriteFile(path, make([]byte, 4097), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-identity":
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				candidate.expected.Length--
			case "not-public-key":
				bad := []byte("not a public key")
				if err := os.WriteFile(path, bad, 0600); err != nil {
					t.Fatal(err)
				}
				candidate.expected = artifact.DigestLength{SHA256: artifact.Digest(sha256.Sum256(bad)), Length: uint64(len(bad))}
			}
			output := filepath.Join(directory, condition+"-copy")
			_, err := snapshotStockCLIKey(ctx, candidate, output)
			if condition == "fifo" || condition == "too-large" {
				if !errors.Is(err, errPublicConfigurationEvidence) {
					t.Fatal("key did not reach bounded opened-file refusal", condition, err)
				}
			} else {
				want := map[string]string{"wrong-identity": "public key identity differs", "not-public-key": "public key refused"}[condition]
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatal("key did not reach its exact refusal", condition, want, err)
				}
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("invalid key created an owned input", err)
			}
		})
	}
}

// full_only: false
func TestStockCLIEnvironmentUsesAdmittedParallelCapacity(t *testing.T) {
	for _, parent := range []string{"", "-trimpath -p=1", "-trimpath -p=4", "-race -tags=untrusted"} {
		t.Run(fmt.Sprintf("parent-%q", parent), func(t *testing.T) {
			t.Setenv("GOFLAGS", parent)
			for _, parallel := range []int{1, 3} {
				env, err := stockCLIEnvironment(withExecutionParallel(t.Context(), parallel))
				if err != nil {
					t.Fatal(err)
				}
				want := fmt.Sprintf("GOMAXPROCS=%d", parallel)
				count, flags, goenv := 0, 0, 0
				for _, entry := range env {
					if strings.HasPrefix(entry, "GOMAXPROCS=") {
						count++
						if entry != want {
							t.Fatal("stock construction received a different parallel capacity")
						}
					}
					if strings.HasPrefix(entry, "GOFLAGS=") {
						flags++
						if entry != "GOFLAGS=" {
							t.Fatal("parent compiler flags reached stock construction")
						}
					}
					if strings.HasPrefix(entry, "GOENV=") {
						goenv++
						if entry != "GOENV=off" {
							t.Fatal("stock construction inherited Go environment configuration")
						}
					}
				}
				if count != 1 || flags != 1 || goenv != 1 {
					t.Fatal("stock environment lost its admitted capacity or sealed compiler inputs", parallel, count, flags, goenv)
				}
			}
		})
	}
	for key, value := range map[string]string{"GOEXPERIMENT": "untrusted", "GOOS": "not-a-platform"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("GOFLAGS", "")
			t.Setenv(key, value)
			if _, err := stockCLIEnvironment(withExecutionParallel(t.Context(), 1)); err == nil {
				t.Fatal("custom compiler or cross-build input was accepted", key)
			}
		})
	}
}
