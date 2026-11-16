//go:build darwin || linux

package plugininstallation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestSelectionFactsAgreeWithPublicationAfterLockCompletionFailure(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "previous")
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "replacement")
	catalog.publish(t, one)
	catalog.publish(t, two)
	resolve(t, c, request(scope, "private-renderer", "1.0.0", Prepare))
	path := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	lockPath := path + ".lock"
	interleaved := false
	r := request(scope, "private-renderer", "2.0.0", Prepare)
	r.CheckSource = func(context.Context) error {
		if interleaved {
			return nil
		}
		probe, err := os.OpenFile(lockPath, os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		lockErr := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if lockErr == nil {
			return errors.Join(syscall.Flock(int(probe.Fd()), syscall.LOCK_UN), probe.Close())
		}
		closeErr := probe.Close()
		if closeErr != nil {
			return closeErr
		}
		if !errors.Is(lockErr, syscall.EWOULDBLOCK) && !errors.Is(lockErr, syscall.EAGAIN) {
			return lockErr
		}
		if err := os.Rename(lockPath, lockPath+".original"); err != nil {
			return err
		}
		if err := os.WriteFile(lockPath, nil, 0600); err != nil {
			return err
		}
		interleaved = true
		return nil
	}
	session, rows, err := c.Resolve(t.Context(), r)
	if err == nil || session != nil || !interleaved || len(rows) != 1 {
		t.Fatalf("completion failure was not exercised %#v %v", rows, err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	record, decodeErr := artifact.DecodeSelectionRecord(body)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	row := rows[0]
	switch record.Selections[0].Artifact {
	case two.identity:
		if !row.Changed || row.Status != "verified" || row.Version != "2.0.0" || row.Artifact == nil || *row.Artifact != two.identity || row.Previous == nil || row.Previous.Artifact != one.identity {
			t.Fatalf("visible publication lost its facts %#v", row)
		}
	case one.identity:
		if row.Changed || row.Status == "verified" || row.Previous == nil || row.Previous.Artifact != one.identity {
			t.Fatalf("prepublication refusal lost previous facts %#v", row)
		}
	default:
		t.Fatal("unexpected selected artifact")
	}
}
