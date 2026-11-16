package main

import (
	"errors"
	"strings"
	"time"
)

func ordinaryProcessTimeout(flags []string, maximum time.Duration) (time.Duration, error) {
	timeout := maximum
	for _, flag := range flags {
		if value, ok := strings.CutPrefix(flag, "-timeout="); ok {
			parsed, err := time.ParseDuration(value)
			if err != nil {
				return 0, err
			}
			timeout = parsed
		}
	}
	if timeout <= 0 || timeout > maximum {
		return 0, errors.New("ordinary process timeout is outside its bound")
	}
	return timeout, nil
}

func ordinaryExclusiveProcess(pkg, name string) bool {
	if pkg != modulePrefix+"core/internal/testmain" {
		return false
	}
	switch name {
	case "TestSupervisorRegisteredCancellationReleasesAdmission", "TestSupervisorInstalledInvocationBoundaries":
		return true
	default:
		return false
	}
}

// Zero disables only the cumulative suite deadline; process limits remain finite.
const unitGroupAllowance time.Duration = 0
const runnerGroupAllowance time.Duration = 0
const unitProcessTimeoutLimit = 10 * time.Minute
const unitFullOnlyProcessTimeoutLimit = 30 * time.Minute
const runnerProcessTimeoutLimit = 15 * time.Minute
const maximumOrdinaryProcesses = 8192

type ordinaryProcessGroup struct {
	tests    []string
	big      bool
	fullOnly bool
}

func ordinaryProcessMaximum(unit bool, group ordinaryProcessGroup) time.Duration {
	if !unit {
		return runnerProcessTimeoutLimit
	}
	if group.fullOnly {
		return unitFullOnlyProcessTimeoutLimit
	}
	return unitProcessTimeoutLimit
}

func ordinaryRootTimeouts(artifact preparedOrdinaryArtifact, group ordinaryProcessGroup, helpers map[string]string) (map[string]time.Duration, time.Duration, error) {
	limit, err := ordinaryProcessTimeout(artifact.TestFlags, ordinaryProcessMaximum(artifact.unit, group))
	if err != nil {
		return nil, 0, err
	}
	base := runnerProcessTimeoutLimit
	if artifact.unit {
		base = unitProcessTimeoutLimit
	}
	full := map[string]bool{}
	for _, row := range artifact.Classifications {
		if row.FullOnly != nil {
			full[row.Name] = *row.FullOnly
		}
	}
	closures, err := ordinaryHelperGroups(artifact.Package, artifact.Tests, helpers)
	if err != nil {
		return nil, 0, err
	}
	allowances := make(map[string]time.Duration, len(artifact.Tests))
	idle := time.Minute
	for _, closure := range closures {
		allowance := base
		for _, name := range closure {
			if artifact.unit && full[name] {
				allowance = unitFullOnlyProcessTimeoutLimit
			}
		}
		allowance = min(allowance, limit)
		for _, name := range closure {
			allowances[name] = allowance
		}
		idle = max(idle, allowance)
	}
	if len(allowances) == 0 {
		idle = max(idle, limit)
	}
	return allowances, idle, nil
}

func ordinaryHelperGroup(pkg string, names []string, seed string, helpers map[string]string) map[string]bool {
	selected := make(map[string]bool, len(names))
	for _, name := range names {
		selected[name] = true
	}
	group := map[string]bool{seed: true}
	for changed := true; changed; {
		changed = false
		for helper, proof := range helpers {
			helperPackage, helperName, ok := strings.Cut(helper, "\x00")
			proofName, _, _ := strings.Cut(proof, "/")
			if !ok || helperPackage != pkg || !selected[helperName] || !selected[proofName] {
				continue
			}
			if group[helperName] != group[proofName] {
				group[helperName], group[proofName], changed = true, true, true
			}
		}
	}
	return group
}

func ordinaryHelperGroups(pkg string, names []string, helpers map[string]string) ([][]string, error) {
	if len(names) == 0 {
		return [][]string{nil}, nil
	}
	remaining := make(map[string]bool, len(names))
	for _, name := range names {
		if !validOrdinaryName(name) || strings.Contains(name, "/") || remaining[name] {
			return nil, errors.New("ordinary process selection is invalid")
		}
		remaining[name] = true
	}
	linked := map[string]bool{}
	for helper, proof := range helpers {
		owner, name, ok := strings.Cut(helper, "\x00")
		proofName, _, _ := strings.Cut(proof, "/")
		if !ok || owner != pkg || !remaining[name] {
			continue
		}
		if !remaining[proofName] {
			return nil, errors.New("ordinary helper lacks its selected proving parent")
		}
		linked[name], linked[proofName] = true, true
	}
	var groups [][]string
	for _, seed := range names {
		if !remaining[seed] {
			continue
		}
		group := []string{seed}
		if linked[seed] {
			connected := ordinaryHelperGroup(pkg, names, seed, helpers)
			group = nil
			for _, name := range names {
				if remaining[name] && connected[name] {
					group = append(group, name)
					delete(remaining, name)
				}
			}
		} else {
			delete(remaining, seed)
		}
		groups = append(groups, group)
		if len(groups) > maximumOrdinaryProcesses {
			return nil, errors.New("ordinary process selection exceeds its bound")
		}
	}
	return groups, nil
}

func ordinaryProcessGroups(artifact ordinaryArtifact, helpers map[string]string) ([]ordinaryProcessGroup, error) {
	if len(artifact.Tests) == 0 {
		return []ordinaryProcessGroup{{}}, nil
	}
	fullOnly := make(map[string]bool, len(artifact.Classifications))
	exclusive := make(map[string]bool, len(artifact.Classifications))
	seen := map[string]bool{}
	for _, row := range artifact.Classifications {
		if seen[row.Name] {
			return nil, errors.New("ordinary process classification is repeated")
		}
		seen[row.Name] = true
		if row.Unavailable {
			if row.FullOnly != nil || row.Exclusive {
				return nil, errors.New("unavailable test classification is inconsistent")
			}
			continue
		}
		if row.FullOnly == nil {
			return nil, errors.New("ordinary process classification is missing")
		}
		fullOnly[row.Name] = *row.FullOnly
		exclusive[row.Name] = row.Exclusive
	}
	groups, err := ordinaryHelperGroups(artifact.Package, artifact.Tests, helpers)
	if err != nil {
		return nil, err
	}
	var normal ordinaryProcessGroup
	var big []ordinaryProcessGroup
	for _, names := range groups {
		group := ordinaryProcessGroup{tests: names}
		for _, name := range names {
			full, found := fullOnly[name]
			if !found {
				return nil, errors.New("ordinary process selection lacks classification")
			}
			group.fullOnly = group.fullOnly || full
			group.big = group.big || exclusive[name] || ordinaryExclusiveProcess(artifact.Package, name)
		}
		if group.big {
			big = append(big, group)
		} else {
			normal.tests = append(normal.tests, group.tests...)
			normal.fullOnly = normal.fullOnly || group.fullOnly
		}
	}
	if len(normal.tests) != 0 {
		return append([]ordinaryProcessGroup{normal}, big...), nil
	}
	return big, nil
}
