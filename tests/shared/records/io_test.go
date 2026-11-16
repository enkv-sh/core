package records

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// full_only: false
func TestReadJSONLimitEnforcesCallerBound(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "input.json")
	body := []byte(`{"ok":true}`)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{-1, 0, int64(len(body) - 1), int64(len(body)), int64(len(body) + 1), MaximumJSONBytes + 1} {
		var value struct {
			OK bool `json:"ok"`
		}
		err := ReadJSONLimit(path, &value, limit)
		wantValid := limit >= int64(len(body)) && limit <= MaximumJSONBytes
		if (err == nil) != wantValid || err == nil && !value.OK {
			t.Fatalf("limit %d: valid = %t, want %t", limit, err == nil, wantValid)
		}
	}
}

type localIdentityFileInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info localIdentityFileInfo) Sys() any { return &info.stat }

// full_only: false
func TestLocalFileComparisonDoesNotUseMountNumbers(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("native file identity unavailable")
	}
	changed := localIdentityFileInfo{FileInfo: info, stat: *stat}
	changed.stat.Dev++
	if !SameLocalFile(info, changed) {
		t.Fatal("mount renumbering changed the same local file identity")
	}
	changed.stat.Ino++
	if SameLocalFile(info, changed) {
		t.Fatal("different inode accepted as the same file")
	}
	changed.stat.Ino--
	changed.stat.Uid++
	if SameLocalFile(info, changed) || SameLocalFile(nil, info) || SameLocalFile(info, nil) {
		t.Fatal("unavailable or different owner accepted as the same file")
	}
}
