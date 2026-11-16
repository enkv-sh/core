package configuration

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recaptureContext struct {
	context.Context
	temporary, path, initial, current       string
	discovery, owned                        string
	parsers                                 int
	change, cancelAfter, changed, cancelled bool
	cancel                                  context.CancelFunc
	problem                                 error
}

func (c *recaptureContext) Done() <-chan struct{} {
	c.cancelAfterOwnedCapture()
	c.parsers++
	if c.parsers <= 2 && c.problem == nil {
		entries, err := os.ReadDir(c.temporary)
		if err != nil || len(entries) != 1 {
			c.problem = errors.Join(errors.New("parser did not start with one frozen editable image"), err)
		} else {
			path := filepath.Join(c.temporary, entries[0].Name())
			info, statErr := entries[0].Info()
			body, readErr := os.ReadFile(path)
			want := c.initial
			if c.parsers == 2 {
				want = c.current
			}
			if statErr != nil || readErr != nil || !info.Mode().IsRegular() || string(body) != want {
				c.problem = errors.Join(errors.New("parser image differs from the expected frozen observation"), statErr, readErr)
			} else if c.parsers == 1 {
				c.discovery = path
				if c.change {
					c.problem = os.WriteFile(c.path, []byte(c.current), 0600)
					c.changed = c.problem == nil
				}
			} else {
				c.owned = path
			}
		}
	}
	return c.Context.Done()
}

func (c *recaptureContext) Err() error {
	c.cancelAfterOwnedCapture()
	err := c.Context.Err()
	if c.problem == nil {
		return err
	}
	return errors.Join(err, c.problem)
}

func (c *recaptureContext) cancelAfterOwnedCapture() {
	if c.cancelAfter && c.parsers >= 2 && c.owned != "" && !c.cancelled && c.problem == nil {
		entries, err := os.ReadDir(c.temporary)
		if err != nil {
			c.problem = err
		} else if len(entries) == 0 {
			if _, err := os.Lstat(c.owned); !errors.Is(err, os.ErrNotExist) {
				c.problem = errors.Join(errors.New("owned capture did not unlink its editable image"), err)
			} else {
				c.cancel()
				c.cancelled = true
			}
		}
	}
}

// full_only: false
func TestCaptureDiscoveryRequiresRecapturedNamesAndCurrentContext(t *testing.T) {
	for _, caller := range []string{"read-capture", "begin-edit"} {
		for _, condition := range []string{"domain-name", "generated-reference", "unrelated-field", "cancel-after-owned-capture", "domain-name-change-and-cancel"} {
			t.Run(caller+"/"+condition, func(t *testing.T) {
				directory, temporary := t.TempDir(), t.TempDir()
				if err := os.Chmod(temporary, 0700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("TMPDIR", temporary)
				path := filepath.Join(directory, "configuration.json")
				generated := filepath.Join(directory, ".enkv", "prod.generated.json")
				if err := os.Mkdir(filepath.Dir(generated), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(generated, []byte(sourceGeneratedJSON), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(sourceSetupJSON), 0600); err != nil {
					t.Fatal(err)
				}
				current := sourceSetupJSON
				switch condition {
				case "domain-name", "domain-name-change-and-cancel":
					current = strings.Replace(current, `"name":"prod"`, `"name":"other"`, 1)
				case "generated-reference":
					current = strings.TrimSuffix(current, "}") + `,"generated":".enkv/prod.generated.json"}`
				case "unrelated-field":
					current = strings.Replace(current, `"display_name":""`, `"display_name":"changed"`, 1)
				}
				base, cancel := context.WithCancel(t.Context())
				defer cancel()
				cancelAfter := condition == "cancel-after-owned-capture" || condition == "domain-name-change-and-cancel"
				ctx := &recaptureContext{Context: base, temporary: temporary, path: path, initial: sourceSetupJSON, current: current, change: condition != "cancel-after-owned-capture", cancelAfter: cancelAfter, cancel: cancel}
				var pair *Pair
				var session *EditSession
				var err error
				wantError := ErrCapture
				if caller == "read-capture" {
					pair, err = capturePair(ctx, path, JSON)
					if pair != nil {
						t.Cleanup(func() { closeSourceOwner(t, pair) })
					}
				} else {
					wantError = ErrEdit
					session, err = beginEditForName(ctx, path, JSON, "")
					if session != nil {
						t.Cleanup(func() { closeSourceOwner(t, session) })
						pair = session.Pair()
					}
				}
				if ctx.problem != nil || ctx.parsers < 2 || ctx.discovery == "" || ctx.owned == "" || ctx.changed != ctx.change || ctx.cancelled != ctx.cancelAfter {
					t.Fatalf("capture boundary was not established: parsers=%d changed=%t cancelled=%t problem=%v", ctx.parsers, ctx.changed, ctx.cancelled, ctx.problem)
				}
				if condition == "unrelated-field" {
					if err != nil || pair == nil || pair.Editable.Digest() != sha256.Sum256([]byte(current)) {
						t.Fatal("same-name recapture did not return its current image", err)
					}
					model, parseErr := Parse(t.Context(), pair)
					if parseErr != nil || model == nil || model.DomainName != "prod" || model.Generated != "" || model.Authority.DisplayName != "changed" {
						t.Fatal("same-name recapture reused discovery meaning", parseErr)
					}
				} else if pair != nil || session != nil || !errors.Is(err, wantError) || errors.Is(err, context.Canceled) != ctx.cancelAfter {
					t.Fatal("changed discovery or canceled capture returned an owner or lost its refusal", err)
				}
				if ctx.cancelAfter {
					var diagnostic *Diagnostic
					if !errors.As(err, &diagnostic) || diagnostic.Reason != "cancelled" || diagnostic.Offset != 0 || diagnostic.Line != 1 || diagnostic.Column != 1 || diagnostic.Generated || errors.Is(err, ErrSourceInvalid) {
						t.Fatal("post-capture cancellation lost its first-byte diagnostic or priority", err)
					}
				}
				if session != nil {
					closeSourceOwner(t, session)
				} else if pair != nil {
					closeSourceOwner(t, pair)
				}
				entries, readErr := os.ReadDir(temporary)
				if readErr != nil || len(entries) != 0 {
					t.Fatal("capture retained temporary images", entries, readErr)
				}
				if readSource(t, path) != current || readSource(t, generated) != sourceGeneratedJSON {
					t.Fatal("capture changed the controlled source bytes")
				}
				probe, probeErr := openPathLocks([]string{path, generated}, false, true)
				if probeErr != nil {
					t.Fatal("capture retained a path lock", probeErr)
				}
				if err := probe.close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
