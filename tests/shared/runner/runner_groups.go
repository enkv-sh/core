package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

type runnerGroup struct {
	Name             string            `json:"name"`
	Packages         []ordinaryPackage `json:"packages"`
	EstimatedSeconds float64           `json:"estimated_seconds"`
}

type runnerGroupEvidence struct {
	runnerGroup
	Outcome        string  `json:"outcome"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
}

// Estimates affect placement only. Discovery and the event parser own coverage.
func runnerTestGroups(want map[string][]string, estimates map[string]float64, parallel int) ([]runnerGroup, error) {
	if err := validateRunnerTestInventory(want); err != nil {
		return nil, err
	}
	return ordinaryTestGroups(want, ordinaryRunnerHelperProofs, estimates, parallel)
}

func validateRunnerTestInventory(want map[string][]string) error {
	if _, err := newTestEventState(want, maximumOrdinaryTests, validOrdinaryName, nil); err != nil {
		return err
	}
	for pkg, names := range want {
		for key, proof := range ordinaryRunnerHelperProofs {
			owner, helper, _ := strings.Cut(key, "\x00")
			if owner != pkg {
				continue
			}
			parent, _, _ := strings.Cut(proof, "/")
			if !slices.Contains(names, helper) || !slices.Contains(names, parent) {
				return fmt.Errorf("runner inventory lacks helper %s or proof parent %s in %s", helper, parent, pkg)
			}
		}
	}
	return nil
}

func ordinaryTestGroups(want map[string][]string, helpers map[string]string, estimates map[string]float64, parallel int) ([]runnerGroup, error) {
	if parallel < 1 || parallel > maximumExecutionParallel {
		return nil, errors.New("ordinary placement has an invalid parallel allowance")
	}
	var clusters []ordinaryPackage
	var items []normalPlacementItem
	packages := make([]string, 0, len(want))
	for pkg := range want {
		packages = append(packages, pkg)
	}
	slices.Sort(packages)
	for _, pkg := range packages {
		names := slices.Clone(want[pkg])
		slices.Sort(names)
		bundles, err := ordinaryHelperGroups(pkg, names, helpers)
		if err != nil {
			return nil, err
		}
		for _, bundle := range bundles {
			item := normalPlacementItem{key: pkg + "\x00" + strings.Join(bundle, "\x00")}
			for _, name := range bundle {
				weight := testEstimate(estimates, pkg+"\x00"+name)
				item.estimatedSeconds += weight
			}
			if len(bundle) == 0 {
				item.estimatedSeconds = 1
			}
			clusters = append(clusters, ordinaryPackage{Name: pkg, Tests: bundle})
			items = append(items, item)
		}
	}
	placements := normalPlacement(items, parallel)
	groups := make([]runnerGroup, len(placements))
	for index, placement := range placements {
		group := &groups[index]
		group.Name = fmt.Sprintf("balanced-%d", index+1)
		for _, item := range placement {
			cluster := clusters[item]
			position := slices.IndexFunc(group.Packages, func(pkg ordinaryPackage) bool { return pkg.Name == cluster.Name })
			if position < 0 {
				position = len(group.Packages)
				group.Packages = append(group.Packages, ordinaryPackage{Name: cluster.Name})
			}
			group.Packages[position].Tests = append(group.Packages[position].Tests, cluster.Tests...)
			group.EstimatedSeconds += items[item].estimatedSeconds
		}
		slices.SortFunc(group.Packages, func(left, right ordinaryPackage) int { return strings.Compare(left.Name, right.Name) })
		for index := range group.Packages {
			slices.Sort(group.Packages[index].Tests)
		}
	}
	return groups, nil
}

func runnerGroupSelection(names []string) string {
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return "^(" + strings.Join(quoted, "|") + ")$"
}

// One coordinator owns progress and folds private worker evidence after joining.
func runRunnerGroups(parent context.Context, groups []runnerGroup, output io.Writer, evidence *ordinaryStepEvidence,
	run func(context.Context, runnerGroup) (ordinaryStepEvidence, error)) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if evidence.Diagnostics == nil {
		evidence.Diagnostics = &checkDiagnostics{Preparation: "passed"}
	}
	admission := *evidence.Diagnostics
	admission.Commands = slices.Clone(evidence.Diagnostics.Commands)
	type result struct {
		index    int
		evidence ordinaryStepEvidence
		elapsed  float64
		err      error
	}
	parallel := min(executionCapacityFromContext(ctx).Parallel, len(groups))
	results := make(chan result, parallel)
	completed := make([]*result, len(groups))
	next, active := 0, 0
	var executionErrors, diagnosticErrors []error
	for next < len(groups) || active != 0 {
		for next < len(groups) && active < parallel && ctx.Err() == nil {
			group := groups[next]
			if _, writeErr := fmt.Fprintf(output, "runner: starting group %s (estimated %.0fs)\n", group.Name, group.EstimatedSeconds); writeErr != nil {
				executionErrors = append(executionErrors, errors.New("verification output failed"))
				cancel()
				break
			}
			go func(index int) {
				start := time.Now()
				local, runErr := run(withExecutionParallel(ctx, 1), groups[index])
				if runErr != nil && !containedCheckFailure(ctx, runErr) {
					cancel()
				}
				results <- result{index, local, time.Since(start).Seconds(), runErr}
			}(next)
			next++
			active++
		}
		if active == 0 {
			break
		}
		item := <-results
		active--
		completed[item.index] = &item
		if item.evidence.Diagnostics != nil {
			for _, command := range item.evidence.Diagnostics.Commands {
				command.Scope = groups[item.index].Name + "/" + command.Scope
				if err := admission.append(command); err != nil {
					diagnosticErrors = append(diagnosticErrors, err)
					cancel()
					break
				}
			}
		}
	}
	for index, group := range groups {
		fact := runnerGroupEvidence{runnerGroup: group, Outcome: "not_run"}
		if item := completed[index]; item != nil {
			fact.Outcome, fact.ElapsedSeconds = "passed", item.elapsed
			if item.err != nil {
				fact.Outcome = "failed"
				executionErrors = append(executionErrors, item.err)
			}
			evidence.Tests = append(evidence.Tests, item.evidence.Tests...)
			if item.evidence.EventTimeSource != "" {
				evidence.EventTimeSource = item.evidence.EventTimeSource
			}
			if item.evidence.Diagnostics != nil {
				if item.evidence.Diagnostics.Preparation != "passed" {
					evidence.Diagnostics.Preparation = "failed"
				}
				for _, command := range item.evidence.Diagnostics.Commands {
					command.Scope = group.Name + "/" + command.Scope
					if err := evidence.Diagnostics.append(command); err != nil {
						diagnosticErrors = append(diagnosticErrors, err)
					}
				}
			}
		}
		evidence.RunnerGroups = append(evidence.RunnerGroups, fact)
	}
	executionErrors = append(executionErrors, ctx.Err())
	// Keep command failures ahead of diagnostic-capacity errors in bounded output.
	return errors.Join(append(executionErrors, diagnosticErrors...)...)
}
