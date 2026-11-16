package plugininstallation

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestCommittedSelectionFactsSurviveLaterSourceReadinessFailure(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	one := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "old")
	catalog.publish(t, one)
	resolve(t, c, request(scope, "private-renderer", "", Prepare))
	two := makeFixture(t, "private-renderer", "manifest-generator", "2.0.0", "new")
	catalog.publish(t, two)
	selectionPath := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	r := request(scope, "private-renderer", "2.0.0", Prepare)
	r.CheckSource = func(ctx context.Context) error {
		body, err := os.ReadFile(selectionPath)
		if err != nil {
			return err
		}
		record, err := artifact.DecodeSelectionRecord(body)
		if err != nil {
			return err
		}
		if record.Selections[0].Version == "2.0.0" {
			return ErrSourceChanged
		}
		return nil
	}
	session, rows, err := c.Resolve(t.Context(), r)
	if !errors.Is(err, ErrSourceChanged) || session != nil || len(rows) != 1 {
		t.Fatalf("readiness outcome %#v %v", rows, err)
	}
	row := rows[0]
	if !row.Changed || row.Status != "verified" || row.Version != "2.0.0" || row.Artifact == nil || *row.Artifact != two.identity || row.Previous == nil || row.Previous.Artifact != one.identity {
		t.Fatalf("committed facts lost %#v", row)
	}
	body, err := os.ReadFile(selectionPath)
	if err != nil {
		t.Fatal(err)
	}
	record, err := artifact.DecodeSelectionRecord(body)
	if err != nil || record.Selections[0].Artifact != two.identity {
		t.Fatal("committed identity differs", err)
	}
}

// full_only: false
func TestSelectionCommitRefusesReplacedStagedFile(t *testing.T) {
	catalog := newCatalog(t)
	c := catalog.coordinator(t)
	scope := tempDirectory(t)
	path := filepath.Join(c.store, "applications", artifact.Hash([]byte(scope)).String()+".json")
	body := []byte(`{"schema":"enkv/plugin-selection/v1","directory":` + fmtQuote(scope) + `,"selections":[]}`)
	changed := false
	check := func(context.Context) error {
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".stage-") {
				staged := filepath.Join(filepath.Dir(path), entry.Name(), "record")
				if err := os.Remove(staged); err != nil {
					return err
				}
				if err := os.WriteFile(staged, []byte("foreign staged record"), 0600); err != nil {
					return err
				}
				changed = true
			}
		}
		return nil
	}
	if err := c.commitSelection(t.Context(), path, scope, nil, body, check); err == nil {
		t.Fatal("replaced staged file committed")
	}
	if !changed {
		t.Fatal("interleaving did not replace staged file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign staged bytes reached selection", err)
	}
}

type interleavingContext struct {
	context.Context
	once   sync.Once
	action func()
}

func (c *interleavingContext) Err() error { c.once.Do(c.action); return c.Context.Err() }

// full_only: false
func TestRestoreMissingDoesNotWriteReplacementDirectory(t *testing.T) {
	parent := tempDirectory(t)
	s, err := makeStage(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.finish(); err != nil {
			t.Error(err)
		}
	}()
	for _, name := range []string{"a", "b"} {
		if err := s.writeBytes(t.Context(), name, []byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "a"), []byte("a"), 0400); err != nil {
		t.Fatal(err)
	}
	ctx := &interleavingContext{Context: t.Context(), action: func() {
		if err := os.Rename(target, target+"-old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
	}}
	if err := restoreMissing(ctx, s, "target"); err == nil {
		t.Error("replaced directory was accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("replacement directory was modified: %v", entries)
	}
}

// full_only: false
func TestConcurrentSelectionsPublishOneExactPredecessor(t *testing.T) {
	catalog := newCatalog(t)
	f := makeFixture(t, "private-renderer", "manifest-generator", "1.0.0", "race")
	catalog.publish(t, f)
	assembly := catalog.assembly()
	originalCheck := assembly.Check
	var wait sync.WaitGroup
	wait.Add(2)
	type invocationKey struct{}
	var first, second sync.Once
	assembly.Check = func(ctx context.Context, m artifact.Metadata, b []byte) error {
		which, _ := ctx.Value(invocationKey{}).(int)
		barrier := func() { wait.Done(); wait.Wait() }
		switch which {
		case 1:
			first.Do(barrier)
		case 2:
			second.Do(barrier)
		}
		return originalCheck(ctx, m, b)
	}
	c, err := newCoordinator(tempDirectory(t), assembly)
	if err != nil {
		t.Fatal(err)
	}
	scope := tempDirectory(t)
	outcomes := make(chan error, 2)
	for j := 1; j <= 2; j++ {
		go func(id int) {
			_, _, err := c.Resolve(context.WithValue(t.Context(), invocationKey{}, id), request(scope, "private-renderer", "", Prepare))
			outcomes <- err
		}(j)
	}
	passed, stale := 0, 0
	for range 2 {
		err := <-outcomes
		switch {
		case err == nil:
			passed++
		case errors.Is(err, ErrSourceChanged):
			stale++
		default:
			t.Fatal("unexpected concurrent outcome", err)
		}
	}
	if passed != 1 || stale != 1 {
		t.Fatalf("outcomes passed=%d stale=%d", passed, stale)
	}
	selected, _ := resolve(t, c, request(scope, "private-renderer", "", Ordinary))
	if selected.Identity() != f.identity {
		t.Fatal("selected identity differs")
	}
	actual, err := os.ReadFile(selected.Executable())
	if err != nil || !bytes.Equal(actual, f.members["plugin"]) {
		t.Fatal("immutable bytes differ", err)
	}
}
