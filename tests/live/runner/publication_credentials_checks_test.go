package core

import (
	"bytes"
	records "enkv.sh/core/internal/testrecords"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	protocol "enkv.sh/sdk/protocols/output"
	"golang.org/x/sys/unix"
)

func liveOutputCredentialTestDirectory(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func liveOutputCredentialTestFile(t *testing.T, body []byte) string {
	t.Helper()
	path := filepath.Join(liveOutputCredentialTestDirectory(t), "source")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// full_only: false
func TestLiveOutputCredentialCaptureOwnsImmutablePrivateSnapshot(t *testing.T) {
	body := []byte("synthetic-loader-source\n")
	source := liveOutputCredentialTestFile(t, body)
	captured, err := captureLiveOutputCredentialFile(source, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := captured.Close(); err != nil {
			t.Error(err)
		}
	})
	original, err := os.Stat(source)
	if err != nil || captured.Path == source || !records.SameLocalFile(original, captured.Identity) {
		t.Fatal("original identity was not retained", err)
	}
	snapshot, err := os.Lstat(captured.Path)
	if err != nil || snapshot.Mode().Perm() != 0600 || !liveOutputCredentialOwned(snapshot) || records.SameLocalFile(snapshot, original) {
		t.Fatal("snapshot ownership differs", err)
	}
	directory, err := os.Lstat(filepath.Dir(captured.Path))
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 || !liveOutputCredentialOwned(directory) {
		t.Fatal("snapshot directory ownership differs", err)
	}
	alias := filepath.Join(filepath.Dir(source), "alias")
	if err := os.Link(source, alias); err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(alias)
	if err != nil || !records.SameLocalFile(captured.Identity, aliasInfo) {
		t.Fatal("alias comparison lost original inode", err)
	}
	other, err := captureLiveOutputCredentialFile(alias, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if other.Path == captured.Path || !records.SameLocalFile(other.Identity, captured.Identity) {
		t.Fatal("captures share custody or lose alias identity")
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement-source"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(captured.Path)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("loader snapshot changed with source", err)
	}
	privatePath := captured.Path
	if err := captured.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{privatePath, filepath.Dir(privatePath)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("owned snapshot remained after close", err)
		}
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != "replacement-source" {
		t.Fatal("close changed original", err)
	}
	if err := captured.Close(); err != nil {
		t.Fatal("close is not idempotent", err)
	}
}

// full_only: false
func TestLiveOutputCredentialCaptureRefusesUnownedUnsafeOrUnboundedSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		size    int
		maximum int64
		valid   bool
	}{
		{"one", 1, 1, true}, {"exact-source-limit", 64 << 10, 64 << 10, true}, {"source-limit-overflow", 64<<10 + 1, 64 << 10, false}, {"caller-limit-overflow", 2, 1, false}, {"empty", 0, 1, false}, {"zero-limit", 1, 0, false}, {"negative-limit", 1, -1, false}, {"unsupported-limit", 1, 64<<10 + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := liveOutputCredentialTestFile(t, bytes.Repeat([]byte{'x'}, tc.size))
			captured, err := captureLiveOutputCredentialFile(path, tc.maximum)
			if (err == nil) != tc.valid || (captured != nil) != tc.valid {
				t.Fatal("capture bound differs", tc.size, tc.maximum, err)
			}
			if captured != nil {
				got, err := os.ReadFile(captured.Path)
				if err != nil || len(got) != tc.size {
					t.Fatal("captured bytes differ", err)
				}
				if err := captured.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	for _, name := range []string{"public-file", "symlink", "ancestor-symlink", "directory", "fifo", "relative", "unclean", "missing"} {
		t.Run(name, func(t *testing.T) {
			source := liveOutputCredentialTestFile(t, []byte("synthetic"))
			path := source
			switch name {
			case "public-file":
				if err := os.Chmod(source, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				path = source + "-link"
				if err := os.Symlink(source, path); err != nil {
					t.Fatal(err)
				}
			case "ancestor-symlink":
				link := filepath.Join(liveOutputCredentialTestDirectory(t), "link")
				if err := os.Symlink(filepath.Dir(source), link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "source")
			case "directory":
				path = filepath.Dir(source)
			case "fifo":
				path = source + "-fifo"
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "relative":
				path = "source"
			case "unclean":
				path = filepath.Dir(source) + "/./source"
			case "missing":
				path = source + "-missing"
			}
			if captured, err := captureLiveOutputCredentialFile(path, 64<<10); err == nil || captured != nil {
				t.Fatal("unsafe source admitted", name)
			}
		})
	}
}

type liveOutputCredentialForeignOwner struct{ os.FileInfo }

func (info liveOutputCredentialForeignOwner) Sys() any {
	stat := *info.FileInfo.Sys().(*syscall.Stat_t)
	stat.Uid ^= 1
	return &stat
}

// full_only: false
func TestLiveOutputCredentialCaptureRejectsChangedIdentityAndMetadata(t *testing.T) {
	path := liveOutputCredentialTestFile(t, []byte("before"))
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	var first unix.Stat_t
	if unix.Lstat(path, &first) != nil {
		t.Fatal("source metadata unavailable")
	}
	if !liveOutputCredentialStable(before, before, before) || liveOutputCredentialOwned(liveOutputCredentialForeignOwner{before}) || liveOutputCredentialStable(before, liveOutputCredentialForeignOwner{before}, before) {
		t.Fatal("owner validation differs")
	}
	differentPath := liveOutputCredentialTestFile(t, []byte("before"))
	different, err := os.Lstat(differentPath)
	if err != nil || liveOutputCredentialStable(before, before, different) {
		t.Fatal("replaced path identity admitted", err)
	}
	if err := os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Now(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	var last unix.Stat_t
	if err != nil || unix.Lstat(path, &last) != nil || liveOutputCredentialMetadataStable(first, last, last) {
		t.Fatal("same-size mutation with restored mtime admitted", err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	mode, err := os.Lstat(path)
	if err != nil || liveOutputCredentialStable(after, mode, mode) {
		t.Fatal("source mode change admitted", err)
	}
	if err := os.WriteFile(differentPath, []byte("longer-source"), 0600); err != nil {
		t.Fatal(err)
	}
	larger, err := os.Lstat(differentPath)
	if err != nil || liveOutputCredentialStable(different, larger, larger) {
		t.Fatal("source size change admitted", err)
	}
}

// full_only: false
func TestLiveOutputCredentialCloseReportsFailureAndPreservesOtherFiles(t *testing.T) {
	source := liveOutputCredentialTestFile(t, []byte("synthetic"))
	captured, err := captureLiveOutputCredentialFile(source, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(captured.Path)
	extra := filepath.Join(directory, "other-file")
	if err := os.WriteFile(extra, []byte("unowned"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(extra); err != nil {
			t.Error(err)
		}
		if err := os.Remove(directory); err != nil {
			t.Error(err)
		}
	})
	if captured.Close() == nil {
		t.Fatal("nonempty owned directory cleanup failure lost")
	}
	if got, err := os.ReadFile(extra); err != nil || string(got) != "unowned" {
		t.Fatal("close removed an unowned file", err)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != "synthetic" {
		t.Fatal("close changed original source", err)
	}
}

// full_only: false
func TestLiveOutputCredentialCloseRefusesReplacedSnapshotOrDirectory(t *testing.T) {
	for _, name := range []string{"snapshot", "directory"} {
		t.Run(name, func(t *testing.T) {
			source := liveOutputCredentialTestFile(t, []byte("synthetic"))
			captured, err := captureLiveOutputCredentialFile(source, 64<<10)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Dir(captured.Path)
			if name == "snapshot" {
				moved := captured.Path + "-moved"
				if err := os.Rename(captured.Path, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(captured.Path, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					for _, path := range []string{moved, captured.Path, directory} {
						if err := os.Remove(path); err != nil {
							t.Error(err)
						}
					}
				})
			} else {
				moved := directory + "-moved"
				if err := os.Rename(directory, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(directory, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(captured.Path, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					for _, path := range []string{filepath.Join(moved, "credential"), moved, captured.Path, directory} {
						if err := os.Remove(path); err != nil {
							t.Error(err)
						}
					}
				})
			}
			if captured.Close() == nil {
				t.Fatal("replacement cleanup failure lost")
			}
			if got, err := os.ReadFile(captured.Path); err != nil || string(got) != "replacement" {
				t.Fatal("close removed a replacement", err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatal("close removed source", err)
			}
		})
	}
}

// full_only: false
func TestLiveOutputCredentialRouteWritesOnceWithExactBoundsAndPrivateOwner(t *testing.T) {
	for _, size := range []int{1, protocol.MaximumCredentialBytes - 36} {
		t.Run(map[int]string{1: "one", protocol.MaximumCredentialBytes - 36: "exact-route-limit"}[size], func(t *testing.T) {
			path := filepath.Join(liveOutputCredentialTestDirectory(t), "route")
			route := liveOutputCredentialRoute{Path: path, ID: protocol.ID{1}}
			body := bytes.Repeat([]byte{'x'}, size)
			if err := writeLiveOutputCredentialRoute(route, body); err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != 0600 || !liveOutputCredentialOwned(info) {
				t.Fatal("route is not private", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("route bytes differ", err)
			}
			if writeLiveOutputCredentialRoute(route, []byte("replacement")) == nil {
				t.Fatal("active route rewritten")
			}
			got, err = os.ReadFile(path)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatal("refused rewrite changed route", err)
			}
		})
	}
	for _, name := range []string{"empty", "overflow", "zero-route", "relative", "unclean", "public-parent", "symlink-parent", "symlink-file", "existing-file"} {
		t.Run(name, func(t *testing.T) {
			dir := liveOutputCredentialTestDirectory(t)
			route := liveOutputCredentialRoute{Path: filepath.Join(dir, "route"), ID: protocol.ID{1}}
			body := []byte("synthetic")
			var preserved string
			switch name {
			case "empty":
				body = nil
			case "overflow":
				body = make([]byte, protocol.MaximumCredentialBytes-35)
			case "zero-route":
				route.ID = protocol.ID{}
			case "relative":
				route.Path = "route"
			case "unclean":
				route.Path = dir + "/./route"
			case "public-parent":
				if err := os.Chmod(dir, 0750); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				link := filepath.Join(liveOutputCredentialTestDirectory(t), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				route.Path = filepath.Join(link, "route")
			case "symlink-file":
				preserved = liveOutputCredentialTestFile(t, []byte("original"))
				if err := os.Symlink(preserved, route.Path); err != nil {
					t.Fatal(err)
				}
			case "existing-file":
				preserved = route.Path
				if err := os.WriteFile(preserved, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if writeLiveOutputCredentialRoute(route, body) == nil {
				t.Fatal("unsafe route admitted", name)
			}
			if preserved != "" {
				if got, err := os.ReadFile(preserved); err != nil || string(got) != "original" {
					t.Fatal("refusal changed preexisting file", err)
				}
			} else if _, err := os.Lstat(filepath.Join(dir, "route")); !os.IsNotExist(err) {
				t.Fatal("refusal created route", err)
			}
		})
	}
}
