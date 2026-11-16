//go:build darwin || linux

package awsprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type scriptedCredentialFile struct {
	reader   io.Reader
	stats    []os.FileInfo
	statCall int
	readErr  error
	closeErr error
	closed   bool
}

func (f *scriptedCredentialFile) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return f.reader.Read(p)
}

func (f *scriptedCredentialFile) Stat() (os.FileInfo, error) {
	if f.statCall >= len(f.stats) {
		return nil, errors.New("unexpected stat")
	}
	info := f.stats[f.statCall]
	f.statCall++
	return info, nil
}

func (f *scriptedCredentialFile) Close() error {
	f.closed = true
	return f.closeErr
}

type countedReader struct {
	reader io.Reader
	n      int
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.n += n
	return n, err
}

// full_only: false
func TestCredentialFileUsesOneNonblockingCloseOnExecDescriptor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	original := []byte("original")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openCredentialFile(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	fd := int(f.Fd())
	fdFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatal("credential descriptor is not close-on-exec")
	}
	statusFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || statusFlags&unix.O_NONBLOCK == 0 {
		t.Fatal("credential descriptor is not nonblocking")
	}
	if err := os.Rename(path, filepath.Join(dir, "opened")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	b, ok := captureOpenedCredentialFile(f, credentialLimit)
	if !ok || !bytes.Equal(b, original) {
		t.Fatal("capture reopened a replaced pathname")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("credential descriptor remained open")
	}
}

// full_only: false
func TestCredentialFileRejectsChangeReadAndCloseErrors(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join(dir, "before")
	afterPath := filepath.Join(dir, "after")
	if err := os.WriteFile(beforePath, []byte("1234"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(afterPath, []byte("5678"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(beforePath)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(afterPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, file := range map[string]*scriptedCredentialFile{
		"metadata-change": {reader: strings.NewReader("1234"), stats: []os.FileInfo{before, after}},
		"read-error":      {reader: strings.NewReader(""), stats: []os.FileInfo{before}, readErr: errors.New("read failed")},
		"close-error":     {reader: strings.NewReader("1234"), stats: []os.FileInfo{before, before}, closeErr: errors.New("close failed")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := captureOpenedCredentialFile(file, credentialLimit); ok || !file.closed {
				t.Fatal("credential capture accepted an incomplete descriptor result")
			}
		})
	}

	limitPath := filepath.Join(dir, "limit")
	if err := os.WriteFile(limitPath, make([]byte, credentialLimit), 0600); err != nil {
		t.Fatal(err)
	}
	grownPath := filepath.Join(dir, "grown")
	if err := os.WriteFile(grownPath, make([]byte, credentialLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	limitInfo, _ := os.Stat(limitPath)
	grownInfo, _ := os.Stat(grownPath)
	reader := &countedReader{reader: strings.NewReader(strings.Repeat("x", credentialLimit+32))}
	file := &scriptedCredentialFile{reader: reader, stats: []os.FileInfo{limitInfo, grownInfo}}
	if _, ok := captureOpenedCredentialFile(file, credentialLimit); ok || reader.n != credentialLimit+1 || !file.closed {
		t.Fatal("growing credential input was not bounded and refused")
	}
}

// full_only: false
func TestSharedCredentialsFIFOWithNoWriterRefusesPromptly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := LoadSharedCredentialsFile(context.Background(), path, "chosen", time.Time{}); err != ErrCredentials {
		t.Fatal("FIFO credential input accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("FIFO credential input did not refuse promptly")
	}
}

type retainedCredentialReader struct {
	reader  io.Reader
	buffers [][]byte
}

func (r *retainedCredentialReader) Read(p []byte) (int, error) {
	r.buffers = append(r.buffers, p[:cap(p)])
	return r.reader.Read(p)
}

// full_only: false
func TestCredentialCaptureDisposesEveryOwnedReadBuffer(t *testing.T) {
	for _, size := range []int{1, 1024, credentialLimit} {
		for _, fail := range []bool{false, true} {
			name := fmt.Sprintf("bytes-%d-close-failure-%t", size, fail)
			t.Run(name, func(t *testing.T) {
				value := bytes.Repeat([]byte("x"), size)
				path := filepath.Join(t.TempDir(), "credential")
				if err := os.WriteFile(path, value, 0600); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				reader := &retainedCredentialReader{reader: bytes.NewReader(value)}
				file := &scriptedCredentialFile{reader: reader, stats: []os.FileInfo{info, info}}
				if fail {
					file.closeErr = errors.New("close failed")
				}
				captured, ok := captureOpenedCredentialFile(file, credentialLimit)
				if ok == fail || !file.closed {
					t.Fatal("capture outcome or close ownership differs")
				}
				if !fail && !bytes.Equal(captured, value) {
					t.Fatal("capture changed exact credential bytes")
				}
				if captured != nil {
					clear(captured[:cap(captured)])
				}
				for _, buffer := range reader.buffers {
					for _, b := range buffer {
						if b != 0 {
							t.Fatal("an application-owned read buffer survived disposal")
						}
					}
				}
				t.Logf("descriptor_closed=true buffers_disposed=true exact_contents=%t", !fail)
			})
		}
	}
}

// full_only: false
func TestCredentialTerminalRefusalRetainsNoControllingTerminal(t *testing.T) {
	if path := os.Getenv("ENKV_TEST_CREDENTIAL_TERMINAL"); path != "" {
		if fd, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err == nil {
			if closeErr := unix.Close(fd); closeErr != nil {
				t.Error("close unexpected controlling terminal", closeErr)
			}
			t.Fatal("fresh session unexpectedly has a controlling terminal")
		}
		if _, ok := captureCredentialFile(context.Background(), path, credentialLimit); ok {
			t.Fatal("terminal accepted as credential")
		}
		if fd, err := unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_NONBLOCK, 0); err == nil {
			if closeErr := unix.Close(fd); closeErr != nil {
				t.Error("close unexpected controlling terminal", closeErr)
			}
			t.Fatal("refused credential acquired a controlling terminal")
		}
		t.Log("credential_refused=true controlling_terminal_absent=true")
		return
	}
	master, path := credentialTestTerminal(t)
	defer func() {
		if err := master.Close(); err != nil {
			t.Error("close terminal master", err)
		}
	}()
	child := exec.Command(os.Args[0], "-test.run=^TestCredentialTerminalRefusalRetainsNoControllingTerminal$", "-test.v")
	child.Env = append(os.Environ(), "ENKV_TEST_CREDENTIAL_TERMINAL="+path)
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	output, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("fresh session credential refusal failed: %v\n%s", err, output)
	}
	t.Logf("fresh_session_joined=true\n%s", output)
}

// full_only: false
func TestCredentialOpenRetriesOnlyInterruptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"interrupted-success", "repeated-interrupted-cancel", "other-error"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			file, err := openCredentialFileWith(ctx, path, func(path string, flags int, mode uint32) (int, error) {
				calls++
				required := unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_NOFOLLOW | unix.O_CLOEXEC
				if flags&required != required {
					t.Error("native acquisition omitted safe flags")
				}
				switch name {
				case "other-error":
					return -1, unix.EACCES
				case "repeated-interrupted-cancel":
					if calls == 3 {
						cancel()
					}
					return -1, unix.EINTR
				}
				if calls == 1 {
					return -1, unix.EINTR
				}
				return unix.Open(path, flags, mode)
			})
			switch name {
			case "interrupted-success":
				if err != nil || file == nil || calls != 2 {
					t.Fatal("interruption did not preserve successful acquisition", calls, err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "repeated-interrupted-cancel":
				if !errors.Is(err, context.Canceled) || file != nil || calls != 3 {
					t.Fatal("interruption ignored cancellation", calls, err)
				}
			case "other-error":
				if !errors.Is(err, unix.EACCES) || file != nil || calls != 1 {
					t.Fatal("non-interruption was repeated or lost", calls, err)
				}
			}
			t.Logf("acquisition_calls=%d successful_descriptor_joined=%t", calls, file != nil)
		})
	}
}
