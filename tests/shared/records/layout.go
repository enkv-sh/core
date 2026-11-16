package records

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const runDateFormat = "2006-01-02"
const runTimeFormat = "15-04-05-0700"

// RunRelative preserves the run identity under its local start date and time.
// Retained timestamp identities supply the start when no record does. Runs with
// no representable start remain explicitly undated.
func RunRelative(id string, startedAt time.Time) (string, error) {
	if !ValidRunID(id) {
		return "", errRecord
	}
	if startedAt.IsZero() && len(id) > 17 && id[8] == 'T' && id[15:17] == "Z-" {
		startedAt, _ = time.Parse("20060102T150405Z", id[:16])
	}
	if !startedAt.IsZero() && startedAt.Year() >= 1 && startedAt.Year() <= 9999 {
		local := startedAt.In(time.Local)
		_, offset := local.Zone()
		if local.Year() >= 1 && local.Year() <= 9999 && offset > -24*60*60 && offset < 24*60*60 && offset%60 == 0 {
			return filepath.Join(local.Format(runDateFormat), local.Format(runTimeFormat)+"-"+id), nil
		}
	}
	return filepath.Join("undated", id), nil
}

// ParseRunRelative accepts the current layout and retained flat identities.
// Calendar fields, numeric offsets, separators, and spelling must be exact.
func ParseRunRelative(relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.Contains(relative, `\`) {
		return "", errRecord
	}
	if ValidRunID(relative) {
		return relative, nil
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) != 2 {
		return "", errRecord
	}
	if parts[0] == "undated" && ValidRunID(parts[1]) {
		return parts[1], nil
	}
	if !validRunDate(parts[0]) || len(parts[1]) < 15 || parts[1][13] != '-' || !ValidRunID(parts[1][14:]) {
		return "", errRecord
	}
	stamp := parts[0] + "/" + parts[1][:13]
	value, err := time.Parse(runDateFormat+"/"+runTimeFormat, stamp)
	if err != nil || value.Format(runDateFormat+"/"+runTimeFormat) != stamp {
		return "", errRecord
	}
	_, offset := value.Zone()
	if offset <= -24*60*60 || offset >= 24*60*60 {
		return "", errRecord
	}
	return parts[1][14:], nil
}

// ResolveRun locates one existing identity without entering any run's contents.
// A duplicate, malformed matching layout, or symlink refuses the lookup.
func ResolveRun(root, id string) (string, error) {
	if !ValidRunID(id) || safeAbsolute(root) != nil {
		return "", errRecord
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	var found string
	match := func(relative string) error {
		parsed, err := ParseRunRelative(relative)
		if err != nil || parsed != id || found != "" {
			return errRecord
		}
		path, err := SafePath(root, relative)
		if err != nil || !directory(path) {
			return errRecord
		}
		found = path
		return nil
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == id {
			if err := match(name); err != nil {
				return "", err
			}
			continue
		}
		if name != "undated" && !runDateShape(name) {
			if strings.HasSuffix(name, "-"+id) {
				return "", errRecord
			}
			continue
		}
		container, err := SafePath(root, name)
		if err != nil || !directory(container) {
			return "", errRecord
		}
		children, err := os.ReadDir(container)
		if err != nil {
			return "", err
		}
		for _, child := range children {
			if child.Name() != id && !strings.HasSuffix(child.Name(), "-"+id) {
				continue
			}
			if err := match(filepath.Join(name, child.Name())); err != nil {
				return "", err
			}
		}
	}
	if found == "" {
		return "", os.ErrNotExist
	}
	return found, nil
}

func runDateShape(value string) bool {
	if len(value) != 10 || value[4] != '-' || value[7] != '-' {
		return false
	}
	for index, digit := range value {
		if index != 4 && index != 7 && (digit < '0' || digit > '9') {
			return false
		}
	}
	return true
}

func validRunDate(value string) bool {
	if !runDateShape(value) {
		return false
	}
	date, err := time.Parse(runDateFormat, value)
	return err == nil && date.Year() >= 1 && date.Format(runDateFormat) == value
}
