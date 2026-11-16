package crypto

import (
	"bytes"
	"context"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestMaterializationCustodyCancellationJoinsPrivateWork(t *testing.T) {
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a.ExpiresAt, _ = ctx.Deadline()
		started, release := make(chan struct{}), make(chan struct{})
		route.started, route.release = started, release
		c, err := NewMaterializationCustody(ctx, route, a, target)
		if err != nil {
			t.Fatal(err)
		}
		released := false
		defer func() {
			if !released {
				close(release)
			}
			c.Close()
		}()
		result := make(chan contract.MaterializationCompletion, 1)
		go func() { result <- c.Materialize(ctx) }()
		<-started
		backing := c.raw[:cap(c.raw)]
		if !bytes.HasPrefix(backing, []byte("plain")) {
			t.Fatal("raw owner missing before private join")
		}
		cancel()
		closed := make(chan struct{})
		go func() { c.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close returned before private join")
		case <-result:
			t.Fatal("Materialize returned before private join")
		default:
		}
		if !bytes.HasPrefix(backing, []byte("plain")) || c.route == nil || c.admission.Entries == nil {
			t.Fatal("cancellation released a pending private owner")
		}
		close(release)
		released = true
		out := <-result
		<-closed
		if out.StateResult != contract.MaterializationUnavailable || out.Facts.Failure.Reason != contract.MaterializationCanceled || out.Validate() != nil ||
			c.raw != nil || c.route != nil || c.target != nil || c.admission.Entries != nil || !bytes.Equal(backing, make([]byte, len(backing))) || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
			t.Fatal("private cancellation did not join and clear", out)
		}
		if _, err := os.Stat(a.Target.Path); !os.IsNotExist(err) {
			t.Fatal("canceled private work created a candidate", err)
		}
	})
}

// full_only: false
func TestMaterializationCustodyCancellationJoinsNativeWork(t *testing.T) {
	t.Run("write", func(t *testing.T) { testMaterializationCustodyNativeJoin(t, false) })
	t.Run("cleanup", func(t *testing.T) { testMaterializationCustodyNativeJoin(t, true) })
}

func testMaterializationCustodyNativeJoin(t *testing.T, cleanup bool) {
	t.Helper()
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a.ExpiresAt, _ = ctx.Deadline()
		started, release := make(chan struct{}), make(chan struct{})
		write := target.io.write
		first := true
		target.io.write = func(file *os.File, raw []byte) (int, error) {
			if cleanup {
				cancel()
				return 0, ctx.Err()
			}
			if first {
				first = false
				close(started)
				<-release
			}
			return write(file, raw)
		}
		if cleanup {
			remove := target.io.remove
			target.io.remove = func(path string) error {
				close(started)
				<-release
				return remove(path)
			}
		}
		c, err := NewMaterializationCustody(ctx, route, a, target)
		if err != nil {
			t.Fatal(err)
		}
		released := false
		defer func() {
			if !released {
				close(release)
			}
			c.Close()
		}()
		result := make(chan contract.MaterializationCompletion, 1)
		go func() { result <- c.Materialize(ctx) }()
		<-started
		backing := c.raw[:cap(c.raw)]
		if !bytes.Contains(backing, []byte("supplied\nvalue")) || route.privateCalls != 2 {
			t.Fatal("native write preceded complete private authentication")
		}
		cancel()
		closed := make(chan struct{})
		go func() { c.Close(); close(closed) }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close returned before native write joined")
		case <-result:
			t.Fatal("Materialize returned before native write joined")
		default:
		}
		if !bytes.Contains(backing, []byte("supplied\nvalue")) || c.route == nil {
			t.Fatal("pending native write lost its borrowed raw backing")
		}
		close(release)
		released = true
		out := <-result
		<-closed
		disclosure := contract.MaterializationDisclosureOccurred
		if cleanup {
			disclosure = contract.MaterializationDisclosureUnknown
		}
		if out.StateResult != contract.MaterializationUnavailable || out.Facts.Failure.Reason != contract.MaterializationCanceled || out.Validate() != nil ||
			out.Facts.Replacement != contract.MaterializationNotReplaced || out.Facts.Cleanup != contract.MaterializationCandidateRemoved || out.Facts.Disclosure != disclosure ||
			c.raw != nil || c.route != nil || c.target != nil || !bytes.Equal(backing, make([]byte, len(backing))) {
			t.Fatal("native cancellation did not preserve facts and clear", out)
		}
		if _, err := os.Stat(a.Target.Path); !os.IsNotExist(err) {
			t.Fatal("canceled native write replaced destination", err)
		}
	})
}

// full_only: false
func TestMaterializationCustodyExpiryAndClosePreventLaterUse(t *testing.T) {
	ctx := planningContext(t)
	a, route, target := materializationFixture(t, ctx)
	for _, condition := range []string{"expiry", "close"} {
		t.Run(condition, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				a.ExpiresAt, _ = ctx.Deadline()
				c, err := NewMaterializationCustody(ctx, route, a, target)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(c.Close)
				reason := contract.MaterializationCanceled
				if condition == "expiry" {
					time.Sleep(2 * time.Second)
					synctest.Wait()
					reason = contract.MaterializationDeadlineExceeded
				} else {
					c.Close()
				}
				out := c.Materialize(ctx)
				if out.StateResult != contract.MaterializationUnavailable || out.Facts.Failure.Reason != reason || out.Validate() != nil || route.privateCalls != 0 || c.route != nil || c.admission.Entries != nil {
					t.Fatal("expired/closed custody retained access", out)
				}
			})
		})
	}
}
