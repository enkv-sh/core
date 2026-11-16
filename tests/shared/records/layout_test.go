package records

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// full_only: false
func TestRunRelativeUsesLocalStartAndRetainedTimestamp(t *testing.T) {
	originalLocal := time.Local
	t.Cleanup(func() { time.Local = originalLocal })
	for _, test := range []struct {
		name   string
		id     string
		start  time.Time
		offset int
		want   string
	}{
		{"east rollover", testRunID, time.Date(2026, 9, 7, 17, 11, 1, 0, time.UTC), 10 * 3600, "2026-09-08/03-11-01+1000-" + testRunID},
		{"west rollover", testRunID, time.Date(2026, 9, 8, 2, 11, 1, 0, time.UTC), -(5*3600 + 30*60), "2026-09-07/20-41-01-0530-" + testRunID},
		{"quarter hour", testRunID, time.Date(2026, 9, 8, 2, 11, 1, 0, time.UTC), 5*3600 + 45*60, "2026-09-08/07-56-01+0545-" + testRunID},
		{"timestamp fallback", "20260907T171101Z-retained", time.Time{}, 10 * 3600, "2026-09-08/03-11-01+1000-20260907T171101Z-retained"},
		{"record overrides timestamp", "20260907T171101Z-retained", time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC), 0, "2026-09-09/00-00-00+0000-20260907T171101Z-retained"},
		{"unknown", testRunID, time.Time{}, 0, "undated/" + testRunID},
		{"legacy", "legacy-baseline", time.Time{}, 0, "undated/legacy-baseline"},
		{"invalid retained timestamp", "20260230T171101Z-retained", time.Time{}, 0, "undated/20260230T171101Z-retained"},
		{"year zero", testRunID, time.Date(0, 9, 8, 1, 2, 3, 0, time.UTC), 0, "undated/" + testRunID},
		{"large year", testRunID, time.Date(10000, 9, 8, 1, 2, 3, 0, time.UTC), 0, "undated/" + testRunID},
		{"large source year rolls back", testRunID, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), -3600, "undated/" + testRunID},
		{"local year rolls forward", testRunID, time.Date(9999, 12, 31, 23, 30, 0, 0, time.UTC), 3600, "undated/" + testRunID},
		{"offset seconds", testRunID, time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC), 1, "undated/" + testRunID},
		{"offset outside numeric range", testRunID, time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC), 24 * 3600, "undated/" + testRunID},
	} {
		t.Run(test.name, func(t *testing.T) {
			time.Local = time.FixedZone("test-local", test.offset)
			got, err := RunRelative(test.id, test.start)
			if err != nil || got != filepath.FromSlash(test.want) {
				t.Fatalf("RunRelative = %q, %v; want %q", got, err, test.want)
			}
			if parsed, err := ParseRunRelative(got); err != nil || parsed != test.id {
				t.Fatalf("generated layout did not preserve identity: %q, %v", parsed, err)
			}
		})
	}
	if _, err := RunRelative("../"+testRunID, time.Now()); err == nil {
		t.Fatal("invalid identity admitted")
	}
}

// full_only: false
func TestParseRunRelativeRequiresExactLayout(t *testing.T) {
	for _, relative := range []string{
		testRunID, "legacy-baseline", "20260907T171101Z-retained",
		"undated/" + testRunID,
		"2026-09-08/03-11-01+1000-" + testRunID,
		"2026-09-07/20-41-01-0530-" + testRunID,
		"2024-02-29/23-59-59+0000-" + testRunID,
	} {
		if _, err := ParseRunRelative(filepath.FromSlash(relative)); err != nil {
			t.Fatalf("valid layout refused: %q: %v", relative, err)
		}
	}
	for _, relative := range []string{
		"", ".", "/" + testRunID, "../" + testRunID,
		"undated//" + testRunID, "undated/./" + testRunID, `undated\` + testRunID,
		"undated/" + testRunID + "/private", "unknown/" + testRunID,
		"2026-02-29/03-11-01+1000-" + testRunID,
		"2026-09-31/03-11-01+1000-" + testRunID,
		"2026-9-08/03-11-01+1000-" + testRunID,
		"0000-09-08/03-11-01+1000-" + testRunID,
		"2026-09-08/24-11-01+1000-" + testRunID,
		"2026-09-08/03-60-01+1000-" + testRunID,
		"2026-09-08/03-11-60+1000-" + testRunID,
		"2026-09-08/03-11-01+2400-" + testRunID,
		"2026-09-08/03-11-01-2400-" + testRunID,
		"2026-09-08/03-11-01+0060-" + testRunID,
		"2026-09-08/03-11-01-0000-" + testRunID,
		"2026-09-08/03-11-01+10:00-" + testRunID,
		"2026-09-08/3-11-01+1000-" + testRunID,
		"2026-09-08/03-11-01+1000-../" + testRunID,
		"2026-09-08/03-11-01+1000-invalid",
		"2026-09-08/" + testRunID,
	} {
		if _, err := ParseRunRelative(filepath.FromSlash(relative)); err == nil {
			t.Fatalf("invalid layout admitted: %q", relative)
		}
	}
}

// full_only: false
func TestResolveRunRecognizesLayoutsWithoutEnteringPrivateTrees(t *testing.T) {
	for _, relative := range []string{testRunID, "undated/" + testRunID, "2026-09-08/03-11-01+1000-" + testRunID} {
		t.Run(relative, func(t *testing.T) {
			root := filepath.Join(canonicalTemp(t), "runs")
			want := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(want, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, ".DS_Store"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(canonicalTemp(t), filepath.Join(want, "private")); err != nil {
				t.Fatal(err)
			}
			if got, err := ResolveRun(root, testRunID); err != nil || got != want {
				t.Fatalf("ResolveRun = %q, %v; want %q", got, err, want)
			}
			if _, err := ResolveRun(root, oldRunID); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing identity did not return os.ErrNotExist: %v", err)
			}
		})
	}
}

// full_only: false
func TestResolveRunRefusesDuplicateAndMalformedMatchingPaths(t *testing.T) {
	for name, relatives := range map[string][]string{
		"flat and dated":       {testRunID, "2026-09-08/03-11-01+1000-" + testRunID},
		"two dates":            {"2026-09-08/03-11-01+1000-" + testRunID, "2026-09-09/03-11-01+1000-" + testRunID},
		"undated and dated":    {"undated/" + testRunID, "2026-09-08/03-11-01+1000-" + testRunID},
		"invalid calendar":     {"2026-02-30/03-11-01+1000-" + testRunID},
		"invalid clock":        {"2026-09-08/25-11-01+1000-" + testRunID},
		"invalid offset":       {"2026-09-08/03-11-01+2400-" + testRunID},
		"date without time":    {"2026-09-08/" + testRunID},
		"undated with time":    {"undated/03-11-01+1000-" + testRunID},
		"time without date":    {"03-11-01+1000-" + testRunID},
		"valid plus malformed": {testRunID, "2026-09-08/25-11-01+1000-" + testRunID},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(canonicalTemp(t), "reports")
			for _, relative := range relatives {
				if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(relative)), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ResolveRun(root, testRunID); err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ambiguous or malformed identity was not refused: %v", err)
			}
		})
	}
}

// full_only: false
func TestResolveRunRefusesSymlinksAndNonDirectories(t *testing.T) {
	for _, relative := range []string{testRunID, "undated", "2026-09-08", "undated/" + testRunID, "2026-09-08/03-11-01+1000-" + testRunID} {
		t.Run(relative, func(t *testing.T) {
			root := filepath.Join(canonicalTemp(t), "runs")
			path := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(canonicalTemp(t), path); err != nil {
				t.Fatal(err)
			}
			if _, err := ResolveRun(root, testRunID); err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("symlink admitted: %v", err)
			}
		})
	}
	root := canonicalTemp(t)
	if err := os.WriteFile(filepath.Join(root, testRunID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveRun(root, testRunID); err == nil {
		t.Fatal("regular file admitted as run directory")
	}
	alias := filepath.Join(canonicalTemp(t), "runs")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveRun(alias, testRunID); err == nil {
		t.Fatal("symlink root admitted")
	}
	if _, err := ResolveRun(filepath.Join(root, "missing"), testRunID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing root did not return os.ErrNotExist: %v", err)
	}
}
