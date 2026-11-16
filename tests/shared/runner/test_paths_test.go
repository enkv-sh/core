package main

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// full_only: false
func TestLiteralTestGroupsKeepRootsTogetherAndPreventChildCrossProducts(t *testing.T) {
	requests := []string{"TestFirst", "TestSecond", "TestParent/first[1]", "TestParent/second+2", "TestOther/third", "TestParent/deep/last"}
	groups, err := literalTestGroups(requests)
	if err != nil || len(groups) != 4 || !reflect.DeepEqual(groups[0].Roots, []string{"TestFirst", "TestSecond"}) || !reflect.DeepEqual(groups[1].Tests, requests[2:4]) {
		t.Fatal("literal package partitions differ", groups, err)
	}
	matches := func(selection, path string) bool {
		patterns, names := strings.Split(selection, "/"), strings.Split(path, "/")
		if len(patterns) != len(names) {
			return false
		}
		for index, pattern := range patterns {
			matched, err := regexp.MatchString(pattern, names[index])
			if err != nil || !matched {
				return false
			}
		}
		return true
	}
	for _, request := range requests {
		count := 0
		for _, group := range groups {
			if matches(group.Selection, request) {
				count++
			}
		}
		if count != 1 {
			t.Fatal("request does not have one exact process owner", request, count)
		}
	}
	for _, unrequested := range []string{"TestParent/third", "TestOther/first[1]", "TestOther/second+2", "TestParent/first1", "TestParent/second22", "TestParent/deep/third"} {
		for _, group := range groups {
			if matches(group.Selection, unrequested) {
				t.Fatal("selection adds an unrequested child", unrequested, group)
			}
		}
	}
}

// full_only: false
func TestRequestedTestNamesRequireEachPartitionAndExactLeaf(t *testing.T) {
	requests := []string{"TestParent/left/one", "TestParent/right/two"}
	complete := []string{"TestParent", "TestParent/left", "TestParent/left/one", "TestParent", "TestParent/right", "TestParent/right/two"}
	if !validRequestedTestNames(requests, complete) {
		t.Fatal("separate child partitions lost their actual repeated parent terminals")
	}
	for index := range complete {
		if complete[index] == "TestParent/left" || complete[index] == "TestParent/right" {
			continue
		}
		missing := append(append([]string{}, complete[:index]...), complete[index+1:]...)
		if validRequestedTestNames(requests, missing) {
			t.Fatal("missing partition root or exact leaf accepted", complete[index])
		}
	}
	for _, extra := range []string{"TestParent", "TestParent/left/one", "TestParent/left/two", "TestOther"} {
		if validRequestedTestNames(requests, append(append([]string{}, complete...), extra)) {
			t.Fatal("extra terminal accepted", extra)
		}
	}
	if !validRequestedTestNames([]string{"TestParent/left", "TestParent/right"}, []string{"TestParent", "TestParent/left", "TestParent/right"}) {
		t.Fatal("siblings sharing a process required duplicate parent terminals")
	}
}

// full_only: false
func TestRequestedTestNamesAcceptSlashWithinOneSubtestName(t *testing.T) {
	if !validRequestedTestNames([]string{"TestParent/deep/path"}, []string{"TestParent", "TestParent/deep/path"}) {
		t.Fatal("one slash-bearing t.Run name required an intermediate terminal")
	}
}

// full_only: false
func TestRequestedTestNamesAllowDifferentNativeAncestorShapes(t *testing.T) {
	requests := []string{"TestParent/x/one", "TestParent/x/two/z"}
	if !validRequestedTestNames(requests, []string{"TestParent", "TestParent/x", "TestParent/x/one", "TestParent", "TestParent/x/two/z"}) {
		t.Fatal("a slash-bearing sibling required an intermediate terminal emitted only by the other process")
	}
}
