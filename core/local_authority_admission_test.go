package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func protectedFixtureDirectory(t testing.TB) string {
	t.Helper()
	parent := os.Getenv("ENKV_TEST_PROTECTED_FIXTURES")
	if parent == "" {
		t.Fatal("protected fixtures require the test runner's managed private directory")
	}
	fd, _, err := localProtectedParent(filepath.Join(parent, "fixture"))
	if err != nil {
		t.Fatal("protected fixture parent refused", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(parent, "fixture-")
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

func localAdmissionPath(t *testing.T, name string, body []byte) string {
	t.Helper()
	dir := protectedFixtureDirectory(t)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// full_only: false
func TestLocalProtectedReadRejectsModesAndLinks(t *testing.T) {
	path := localAdmissionPath(t, "mapping", []byte("exact protected bytes"))
	if body, err := readLocalProtected(path, 64); err != nil || string(body) != "exact protected bytes" {
		t.Fatal("stable protected file", err)
	}
	if _, err := readLocalProtected(path, 5); err == nil {
		t.Fatal("oversize file admitted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalProtected(path, 64); err == nil {
		t.Fatal("group or other access admitted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalProtected(link, 64); err == nil {
		t.Fatal("final symlink admitted")
	}
	parent := filepath.Join(filepath.Dir(path), "linked-parent")
	if err := os.Symlink(filepath.Dir(path), parent); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalProtected(filepath.Join(parent, "mapping"), 64); err == nil {
		t.Fatal("parent symlink admitted")
	}
	for _, mode := range []os.FileMode{0720, 0702, os.ModeSticky | 0777} {
		if err := os.Chmod(filepath.Dir(path), mode); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalProtected(path, 64); err == nil {
			t.Errorf("writable ancestor admitted: %v", mode)
		}
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestLocalProtectedBasisLimitIncludesLegalEnvelopeAndRejectsExcess(t *testing.T) {
	if localBasisLimit < localGenesisBasisLimit || localBasisLimit < localNextBasisLimit {
		t.Fatal("protected basis bound omits a legal envelope")
	}
	body := bytes.Repeat([]byte{'x'}, localBasisLimit)
	path := localAdmissionPath(t, "basis", body)
	if read, err := readLocalProtected(path, localBasisLimit); err != nil || len(read) != len(body) {
		t.Fatal("at-bound protected basis read", err)
	}
	if err := os.WriteFile(path, append(body, 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalProtected(path, localBasisLimit); err == nil {
		t.Fatal("over-bound protected basis read admitted")
	}
}

// full_only: false
func TestLocalProtectedReadOwnsExactFileBacking(t *testing.T) {
	for _, size := range []int{1, 64 << 10, localBasisLimit} {
		path := localAdmissionPath(t, "basis", bytes.Repeat([]byte{'x'}, size))
		body, err := readLocalProtected(path, int64(size))
		if err != nil || len(body) != size || cap(body) != size {
			t.Fatal("protected reader retained excess file backing", size, len(body), cap(body), err)
		}
	}
}

// full_only: false
func TestLocalProtectedAcquisitionRetriesOnlyInterruptedOpenWithinLifetime(t *testing.T) {
	path := localAdmissionPath(t, "decision", []byte("public decision"))
	for _, mode := range []string{"interrupted", "other-error", "canceled-before", "canceled-interrupt", "canceled-after-open"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls, opened := 0, -1
			if mode == "canceled-before" {
				cancel()
			}
			fd, err := openLocalProtected(ctx, unix.AT_FDCWD, path, 0, func(dir int, got string, flags int, permission uint32) (int, error) {
				calls++
				required := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_NOFOLLOW | unix.O_CLOEXEC
				if dir != unix.AT_FDCWD || got != path || flags != required || permission != 0 {
					t.Error("decision acquisition lost exact descriptor policy")
				}
				if mode == "interrupted" && calls < 3 {
					return -1, unix.EINTR
				}
				if mode == "other-error" {
					return -1, unix.EACCES
				}
				if mode == "canceled-interrupt" {
					cancel()
					return -1, unix.EINTR
				}
				fd, err := unix.Openat(dir, got, flags, permission)
				if err == nil {
					opened = fd
					if mode == "canceled-after-open" {
						cancel()
					}
				}
				return fd, err
			})
			if mode == "interrupted" {
				if err != nil || fd < 0 || calls != 3 {
					t.Fatal("interrupted acquisition did not recover", err, calls)
				}
				if err := unix.Close(fd); err != nil {
					t.Fatal(err)
				}
			} else {
				expectedCalls := 1
				if mode == "canceled-before" {
					expectedCalls = 0
				}
				expected := error(context.Canceled)
				if mode == "other-error" {
					expected = unix.EACCES
				}
				if fd >= 0 || !errors.Is(err, expected) || calls != expectedCalls {
					t.Fatal("acquisition changed failure/cancellation", err, calls)
				}
			}
			if opened >= 0 {
				if _, err := unix.FcntlInt(uintptr(opened), unix.F_GETFD, 0); err != unix.EBADF {
					t.Fatal("owned decision descriptor was not closed", err)
				}
			}
			if strings.HasPrefix(mode, "canceled") {
				if body, err := ReadLocalProtectedFile(ctx, path, 64); err == nil || body != nil {
					t.Fatal("canceled decision read was accepted")
				}
			}
		})
	}
}

// full_only: false
func TestLocalProtectedCaptureRejectsMutationAndCancellation(t *testing.T) {
	want := []byte("exact protected decision")
	for _, mode := range []string{"stable", "replacement", "same-size-rewrite", "canceled-after-read"} {
		t.Run(mode, func(t *testing.T) {
			path := localAdmissionPath(t, "decision", want)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			got, err := readLocalProtectedFile(ctx, path, 64, func(reader io.Reader, body []byte) (int, error) {
				calls++
				n, err := io.ReadFull(reader, body)
				if err != nil {
					return n, err
				}
				switch mode {
				case "replacement":
					replacement := path + "-next"
					if err := os.WriteFile(replacement, want, 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "same-size-rewrite":
					if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(want)), 0600); err != nil {
						t.Fatal(err)
					}
				case "canceled-after-read":
					cancel()
				}
				return n, nil
			})
			if calls != 1 {
				t.Fatal("capture did not reach the read boundary", calls)
			}
			if mode == "stable" {
				if err != nil || !bytes.Equal(got, want) || len(got) != cap(got) {
					t.Fatal("stable capture lost exact owned bytes", err)
				}
				got[0] ^= 1
				reread, err := ReadLocalProtectedFile(t.Context(), path, 64)
				if err != nil || !bytes.Equal(reread, want) {
					t.Fatal("owned bytes changed the protected file", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("changed capture returned decision bytes", err)
			}
		})
	}
}
