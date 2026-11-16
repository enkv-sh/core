package main

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

type literalTestGroup struct {
	Tests     []string
	Roots     []string
	Selection string
}

// Go matches each slash-delimited -run expression independently. Child paths
// with different parents need separate processes to avoid selecting a cross
// product of unrequested children. Complete roots share one expression.
func literalTestGroups(tests []string) ([]literalTestGroup, error) {
	if err := validateRequestedTests(tests); err != nil {
		return nil, err
	}
	var groups []literalTestGroup
	parents := map[string]int{}
	for _, path := range tests {
		parent := ""
		if index := strings.LastIndex(path, "/"); index >= 0 {
			parent = path[:index]
		}
		index, found := parents[parent]
		if !found {
			index = len(groups)
			parents[parent] = index
			groups = append(groups, literalTestGroup{})
		}
		group := &groups[index]
		group.Tests = append(group.Tests, path)
	}
	for _, groupIndex := range parents {
		group := &groups[groupIndex]
		group.Roots = requestedTestRoots(group.Tests)
		parts := make([]string, len(group.Tests))
		parent := ""
		for index, path := range group.Tests {
			leaf := path
			if slash := strings.LastIndex(path, "/"); slash >= 0 {
				parent, leaf = path[:slash], path[slash+1:]
			}
			parts[index] = regexp.QuoteMeta(leaf)
		}
		group.Selection = "^(" + strings.Join(parts, "|") + ")$"
		if len(parts) == 1 {
			group.Selection = "^" + parts[0] + "$"
		}
		if parent != "" {
			group.Selection = literalTestSelection(parent) + "/" + group.Selection
		}
		if len(group.Selection) > maximumToolOutputBytes {
			return nil, errors.New("literal test selection exceeds its bound")
		}
	}
	return groups, nil
}

func requestedTestContains(request, name string) bool {
	return name == request || strings.HasPrefix(name, request+"/") || strings.HasPrefix(request, name+"/")
}

func requestedTestRoots(tests []string) []string {
	var roots []string
	for _, path := range tests {
		root, _, _ := strings.Cut(path, "/")
		if !slices.Contains(roots, root) {
			roots = append(roots, root)
		}
	}
	return roots
}

func validRequestedTestNames(requests, names []string) bool {
	groups, err := literalTestGroups(requests)
	if err != nil || len(groups) == 0 {
		return false
	}
	expected := map[string]int{}
	required := map[string]bool{}
	for _, group := range groups {
		ancestors := map[string]bool{}
		for _, request := range group.Tests {
			root, _, _ := strings.Cut(request, "/")
			required[root], required[request] = true, true
			segments := strings.Split(request, "/")
			for index := range segments {
				ancestors[strings.Join(segments[:index+1], "/")] = true
			}
		}
		for name := range ancestors {
			expected[name]++
		}
	}
	observed := map[string]int{}
	for _, name := range names {
		limit := expected[name]
		if limit == 0 {
			for _, request := range requests {
				if strings.HasPrefix(name, request+"/") {
					limit = 1
					break
				}
			}
		}
		observed[name]++
		if limit == 0 || observed[name] > limit {
			return false
		}
	}
	for name, count := range expected {
		if required[name] && observed[name] != count {
			return false
		}
	}
	return true
}
