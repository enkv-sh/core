package configuration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
)

// full_only: false
func TestEditEmissionCoalescesFragments(t *testing.T) {
	// These bytes and their digest are independent of configuration serialization.
	want := bytes.Repeat([]byte("x"), 2*WindowBytes+17)
	digest := sha256.Sum256(want)
	for _, width := range []int{1, 7, WindowBytes - 1, WindowBytes, WindowBytes + 1} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			s := &EditSession{io: nativeEditIO()}
			calls := 0
			s.io.write = func(f *os.File, p []byte) (int, error) {
				calls++
				return f.Write(p)
			}
			image, err := s.emit(t.Context(), t.TempDir(), "candidate-*", int64(len(want)), func(w io.Writer) error {
				for offset := 0; offset < len(want); offset += width {
					if _, err := w.Write(want[offset:min(offset+width, len(want))]); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := image.Close(); err != nil {
					t.Error(err)
				}
			})
			body, err := io.ReadAll(io.NewSectionReader(image, 0, image.Size()))
			if err != nil || !bytes.Equal(body, want) || image.Size() != int64(len(want)) || image.digest != digest {
				t.Fatal("emission changed bytes, size or digest", err)
			}
			if calls > (len(want)+WindowBytes-1)/WindowBytes {
				t.Fatalf("physical writes follow fragments: got %d, want at most 3", calls)
			}
		})
	}
}

// full_only: false
func TestEditEmissionDiscardsFailedOutput(t *testing.T) {
	fault := errors.New("candidate write fault")
	for _, width := range []int{17, WindowBytes + 1} {
		for _, condition := range []string{"cause", "short", "zero", "negative", "excess", "partial-cause", "complete-cause", "cancel-write", "cancel-emitter", "cancel-return", "emitter", "panic", "bound"} {
			t.Run(fmt.Sprintf("%d/%s", width, condition), func(t *testing.T) {
				s := &EditSession{io: nativeEditIO()}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				dir := t.TempDir()
				calls := 0
				s.io.write = func(f *os.File, p []byte) (int, error) {
					calls++
					switch condition {
					case "cause":
						return 0, fault
					case "short":
						return len(p) - 1, nil
					case "zero":
						return 0, nil
					case "negative":
						return -1, fault
					case "excess":
						return len(p) + 1, fault
					case "partial-cause":
						return len(p) - 1, fault
					case "complete-cause":
						return len(p), fault
					case "cancel-write":
						cancel()
					}
					return f.Write(p)
				}
				var image *Image
				var err error
				var panicked any
				func() {
					defer func() { panicked = recover() }()
					image, err = s.emit(ctx, dir, "candidate-*", int64(width), func(w io.Writer) error {
						_, _ = w.Write(bytes.Repeat([]byte("x"), width))
						switch condition {
						case "cancel-emitter":
							cancel()
							_, _ = w.Write(nil)
						case "cancel-return":
							cancel()
						case "emitter":
							return fault
						case "panic":
							panic(fault)
						case "bound":
							_, _ = w.Write([]byte("y"))
							_, _ = w.Write(nil)
						default:
							_, _ = w.Write(nil)
						}
						return nil
					})
				}()
				if condition == "panic" {
					if panicked != fault {
						t.Fatal("emitter panic did not propagate")
					}
				} else {
					if panicked != nil || image != nil || !errors.Is(err, ErrEdit) && !errors.Is(err, ErrEditBounds) {
						t.Fatal("failed emission returned usable image or panicked", err)
					}
					var cause error
					switch condition {
					case "cause", "negative", "excess", "partial-cause", "complete-cause", "emitter":
						cause = fault
					case "short", "zero":
						cause = io.ErrShortWrite
					case "cancel-write", "cancel-emitter", "cancel-return":
						cause = context.Canceled
					case "bound":
						cause = ErrEditBounds
					}
					if !errors.Is(err, cause) || condition == "partial-cause" && !errors.Is(err, io.ErrShortWrite) {
						t.Fatal("emission failure lost cause", err)
					}
				}
				if calls > 1 {
					t.Fatal("failed physical write repeated")
				}
				if width < WindowBytes && (condition == "cancel-emitter" || condition == "cancel-return" || condition == "emitter" || condition == "panic" || condition == "bound") && calls != 0 {
					t.Fatal("failed emitter flushed private bytes")
				}
				files, readErr := os.ReadDir(dir)
				if readErr != nil || len(files) != 0 {
					t.Fatal("failed emission retained private files", readErr)
				}
			})
		}
	}
}
