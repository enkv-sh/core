package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"
)

// full_only: false
func TestRequestedTestPathsRejectDuplicatesAndOverlaps(t *testing.T) {
	for _, tests := range [][]string{nil, {}, {"TestFirst", "TestSecond"}, {"TestParent/child[1]", "TestParent/child+2"}, {"TestParent/first", "TestOther/second"}} {
		if err := validateRequestedTests(tests); err != nil {
			t.Fatalf("literal selection %q refused: %v", tests, err)
		}
	}
	for _, tests := range [][]string{{"TestParent", "TestParent"}, {"TestParent", "TestParent/child"}, {"TestParent/child", "TestParent"}, {"TestParent/"}, {"TestParent//child"}, {""}, {"TestParent/with space"}} {
		if err := validateRequestedTests(tests); err == nil {
			t.Fatalf("invalid or overlapping selection %q accepted", tests)
		}
	}
}

// full_only: false
func TestWorkflowPreviewReportsRequestedWorkAndUnresolvedBuildFacts(t *testing.T) {
	path := t.TempDir() + "/workflow.json"
	saveSelection(t, path, workflowFile{SchemaVersion: 1, Name: "preview", Profile: "dev", Steps: []workflowStep{
		{ID: "first", Kind: "runner-tests"},
		{ID: "component", Kind: "component-tests", Profile: "dev", Tests: singleTestRequest("TestParent/child[1]")},
	}})
	var body bytes.Buffer
	if err := previewWorkflow([]string{"plan", "--workflow", path, "--step", "component", "--race", "--parallel=2"}, &body); err != nil {
		t.Fatal(err)
	}
	var preview workflowPreview
	if err := json.Unmarshal(body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Kind != "selection_preview" || preview.Name != "preview" || preview.Profile != "dev" || !preview.Race || preview.Execution.Resolved.Parallel != 2 ||
		len(preview.Steps) != 2 || preview.Steps[0].Selected || !preview.Steps[1].Selected || preview.Steps[1].Tests[0] != "TestParent/child[1]" || len(preview.Unresolved) != 4 {
		t.Fatalf("preview changed requested work or claimed compiled facts: %s", body.String())
	}
	request := workflowRequest{Path: path, SelectedStep: "component", Race: true}
	file, _, err := readWorkflowConfiguration(request)
	if err != nil || !reflect.DeepEqual(file.Steps[1], preview.Steps[1].workflowStep) {
		t.Fatal("preview changed shared configuration", err)
	}
}

// full_only: false
func TestWorkflowPreviewRejectsAmbiguousAndInvalidRequests(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":1,"name":"preview","steps":[{"id":"runner","kind":"runner-tests","test":"TestOld"}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"runner","kind":"runner-tests","test":"TestOld","tests":["TestNew"]}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"runner","kind":"runner-tests","tests":["TestParent","TestParent/child"]}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"runner","kind":"runner-tests","tests":["TestParent/child","TestParent"]}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"runner","kind":"runner-tests","tests":["TestSame","TestSame"]}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"runner","kind":"runner-tests","tests":[""]}]}`,
		`{"schema_version":1,"name":"preview","execution":{"parallel":0},"steps":[{"id":"runner","kind":"runner-tests"}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"lint","kind":"lint","tests":["TestWrongKind"]}]}`,
		`{"schema_version":1,"name":"preview","steps":[{"id":"unit","kind":"unit","package":"../outside","tests":["TestOutside"]}]}`,
	} {
		path := t.TempDir() + "/workflow.json"
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := previewWorkflow([]string{"plan", "--workflow", path}, &output); err == nil || output.Len() != 0 {
			t.Fatalf("invalid configuration produced a preview: %s; error=%v", body, err)
		}
	}
	for _, args := range [][]string{
		{"plan", "--workflow", "absent.json", "--step", ""},
		{"plan", "--workflow", "absent.json", "--test", "TestNoStep"},
		{"plan", "--workflow", "absent.json", "--step", "runner", "--test", ""},
		{"plan", "--workflow", "absent.json", "--parallel=0"},
		{"plan", "--suite", "", "--environment", "environment.json"},
	} {
		if err := previewWorkflow(args, io.Discard); err == nil {
			t.Fatal("invalid preview arguments accepted", args)
		}
	}
}
