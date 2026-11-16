package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

type testEventResult struct {
	Package, Name, Outcome string
	StartedAt, FinishedAt  *time.Time
	ElapsedSeconds         *float64
	Relation               *retainedSecretMaterialRelation
}

const retainedSecretMaterialMarker = "enkv-retained-secret-material"
const retainedSecretMaterialOwner = "TestSuppliedPlainMutationOpensSourcesOnlyDuringComparison"

// This is one reviewed relation, not an extensible assertion vocabulary.
type retainedSecretMaterialRelation struct {
	Name          string `json:"name"`
	ExpectedCount uint32 `json:"expected_count"`
	ActualCount   uint32 `json:"actual_count"`
}

var errTestResultBound = errors.New("test results exceed their bound")

type testCompletionFailure struct{ cause error }

func (failure *testCompletionFailure) Error() string { return failure.cause.Error() }
func (failure *testCompletionFailure) Unwrap() error { return failure.cause }

type testEventState struct {
	want              map[string][]string
	states            map[string]map[string]string
	packageStates     map[string]string
	positions         map[string]int
	results           []testEventResult // run order, including incomplete tests
	maximum           int
	validName         func(string) bool
	pendingRoots      int
	unobservedOutcome string
	emptySelected     map[string]bool
}

func newTestEventState(want map[string][]string, maximum int, validName func(string) bool, testless map[string]bool) (*testEventState, error) {
	if len(want) == 0 {
		return nil, errors.New("test package inventory is empty")
	}
	s := &testEventState{want: want, states: make(map[string]map[string]string), packageStates: make(map[string]string), positions: make(map[string]int), maximum: maximum, validName: validName}
	total := 0
	for pkg, names := range want {
		if pkg == "" || len(names) == 0 && !testless[pkg] {
			return nil, fmt.Errorf("required package %s has no discovered tests", pkg)
		}
		s.states[pkg] = make(map[string]string)
		for _, name := range names {
			if !validName(name) || strings.Contains(name, "/") || s.states[pkg][name] != "" {
				return nil, fmt.Errorf("package %s has invalid inventory", pkg)
			}
			s.states[pkg][name] = "expected"
			total++
			if total > maximum {
				return nil, errors.New("test inventory exceeds its bound")
			}
		}
	}
	s.pendingRoots = total
	return s, nil
}

func decodeTestEvent(line []byte) (ordinaryEvent, error) {
	var event ordinaryEvent
	if err := json.Unmarshal(line, &event); err != nil || event.Action == "" {
		return event, errors.New("test event is invalid")
	}
	if event.Action == "build-output" {
		// Go 1.27 interleaves BuildEvents with TestEvents. ImportPath is a
		// build identity, not Package; a nil-package printer explicitly emits
		// an empty ImportPath. Build output cannot establish test lifecycle.
		var build struct {
			ImportPath *string
			Action     string
			Output     *string
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&build); err != nil || build.ImportPath == nil || build.Output == nil || *build.Output == "" {
			return event, errors.New("build output event is invalid")
		}
		return event, nil
	}
	if event.Action == "build-fail" {
		return event, errors.New("go build failed")
	}
	if event.Package == "" || event.ImportPath != "" || event.Elapsed != nil && (*event.Elapsed < 0 || math.IsNaN(*event.Elapsed) || math.IsInf(*event.Elapsed, 0)) {
		return event, errors.New("test event is invalid")
	}
	return event, nil
}

func (s *testEventState) accept(event ordinaryEvent) error {
	if event.Action == "build-output" {
		return nil
	}
	pkg := event.Package
	if _, known := s.states[pkg]; !known {
		return fmt.Errorf("package %s was not selected", pkg)
	}
	state := s.packageStates[pkg]
	if event.Action == "start" {
		if state != "" || event.Test != "" {
			return fmt.Errorf("package %s has duplicate or invalid start", pkg)
		}
		s.packageStates[pkg] = "started"
		return nil
	}
	if state != "started" {
		return fmt.Errorf("package %s has an event outside execution", pkg)
	}
	if event.Action == "output" && strings.Contains(event.Output, retainedSecretMaterialMarker) {
		if err := s.acceptRetainedSecretMaterial(event); err != nil {
			return err
		}
	}
	if event.Test == "" {
		switch event.Action {
		case "output":
			return nil
		case "pass":
			if len(s.want[pkg]) == 0 && !s.emptySelected[pkg] {
				return fmt.Errorf("testless package %s passed without a skip", pkg)
			}
			s.packageStates[pkg] = "passed"
		case "skip":
			if len(s.want[pkg]) != 0 || s.emptySelected[pkg] {
				return fmt.Errorf("required package %s skipped", pkg)
			}
			s.packageStates[pkg] = "testless"
		case "fail":
			s.packageStates[pkg] = "failed"
		default:
			return fmt.Errorf("package %s has invalid action %s", pkg, event.Action)
		}
		return nil
	}
	if !s.validName(event.Test) {
		return fmt.Errorf("package %s has invalid test name", pkg)
	}
	top, _, subtest := strings.Cut(event.Test, "/")
	if s.states[pkg][top] == "" {
		return fmt.Errorf("package %s ran unlisted test %s", pkg, event.Test)
	}
	current := s.states[pkg][event.Test]
	key := pkg + "\x00" + event.Test
	switch event.Action {
	case "run":
		if current != "" && current != "expected" {
			return fmt.Errorf("test %s has duplicate run", event.Test)
		}
		// A slash-bearing name need not emit events for each path prefix.
		if subtest && s.states[pkg][top] != "running" {
			return fmt.Errorf("subtest %s lacks running top-level test", event.Test)
		}
		if !subtest {
			s.pendingRoots--
		}
		if len(s.results)+s.pendingRoots >= s.maximum {
			return errTestResultBound
		}
		s.states[pkg][event.Test] = "running"
		s.positions[key] = len(s.results)
		s.results = append(s.results, testEventResult{Package: pkg, Name: event.Test, Outcome: "incomplete", StartedAt: event.Time})
	case "pause", "cont", "output", "attr", "artifacts":
		if current != "running" {
			return fmt.Errorf("test %s has action without run", event.Test)
		}
	case "pass", "fail", "skip":
		if current != "running" {
			return fmt.Errorf("test %s lacks one terminal", event.Test)
		}
		s.states[pkg][event.Test] = event.Action
		result := &s.results[s.positions[key]]
		result.Outcome, result.FinishedAt, result.ElapsedSeconds = event.Action, event.Time, event.Elapsed
	default:
		return fmt.Errorf("test %s has invalid action %s", event.Test, event.Action)
	}
	return nil
}

func (s *testEventState) complete() error {
	for _, result := range s.results {
		if result.Relation != nil && result.Outcome == "pass" && result.Relation.ExpectedCount != result.Relation.ActualCount {
			return errors.New("retained secret material relation contradicts a passing terminal")
		}
	}
	for pkg, outcomes := range s.states {
		for name, outcome := range outcomes {
			if outcome == "pass" || outcome == "skip" {
				continue
			}
			if s.packageStates[pkg] == "passed" || s.packageStates[pkg] == "testless" {
				return fmt.Errorf("test %s contradicts a passing package terminal", name)
			}
			ancestor := name
			for strings.Contains(ancestor, "/") {
				ancestor = ancestor[:strings.LastIndexByte(ancestor, '/')]
				if outcomes[ancestor] == "pass" {
					return fmt.Errorf("test %s contradicts a passing parent terminal", name)
				}
			}
		}
	}
	for pkg, names := range s.want {
		if s.packageStates[pkg] == "failed" {
			return &testCompletionFailure{cause: fmt.Errorf("package %s failed", pkg)}
		}
		terminal := "passed"
		if len(names) == 0 && !s.emptySelected[pkg] {
			terminal = "testless"
		}
		if s.packageStates[pkg] != terminal {
			return &testCompletionFailure{cause: fmt.Errorf("package %s lacks its terminal", pkg)}
		}
		for name, outcome := range s.states[pkg] {
			if outcome != "pass" && outcome != "skip" {
				return &testCompletionFailure{cause: fmt.Errorf("test %s is incomplete or failed", name)}
			}
		}
	}
	return nil
}

func (s *testEventState) acceptRetainedSecretMaterial(event ordinaryEvent) error {
	refused := errors.New("retained secret material relation evidence refused")
	if event.Package != componentPackage ||
		(event.Test != retainedSecretMaterialOwner+"/false" && event.Test != retainedSecretMaterialOwner+"/true") ||
		s.states[event.Package][event.Test] != "running" {
		return refused
	}
	result := &s.results[s.positions[event.Package+"\x00"+event.Test]]
	for _, line := range strings.Split(event.Output, "\n") {
		prefix, marker, found := strings.Cut(line, retainedSecretMaterialMarker)
		if !found {
			continue
		}
		if result.Relation != nil {
			return refused
		}
		prefix = strings.TrimSpace(prefix)
		if prefix != "" {
			// Normal t.Log output adds source:line: before the message. It is
			// discarded; only the event envelope identifies the reviewed owner.
			if !strings.HasSuffix(prefix, ":") {
				return refused
			}
			location := strings.TrimSuffix(prefix, ":")
			separator := strings.LastIndex(location, ":")
			if separator <= 0 || separator == len(location)-1 {
				return refused
			}
			number := location[separator+1:]
			for _, digit := range number {
				if digit < '0' || digit > '9' {
					return refused
				}
			}
		}
		if !strings.HasPrefix(marker, " expected=") {
			return refused
		}
		fields := strings.Fields(marker)
		if len(fields) != 2 || (fields[0] != "expected=0" && fields[0] != "expected=1") || (fields[1] != "actual=0" && fields[1] != "actual=1") {
			return refused
		}
		result.Relation = &retainedSecretMaterialRelation{Name: "retained_secret_material", ExpectedCount: uint32(fields[0][len(fields[0])-1] - '0'), ActualCount: uint32(fields[1][len(fields[1])-1] - '0')}
	}
	return nil
}

func retainedSecretMaterialDescription(pkg, test string, relation *retainedSecretMaterialRelation) string {
	if relation == nil || pkg != componentPackage || relation.Name != "retained_secret_material" || relation.ExpectedCount > 1 || relation.ActualCount > 1 ||
		(test != retainedSecretMaterialOwner+"/false" && test != retainedSecretMaterialOwner+"/true") {
		return "unavailable"
	}
	return fmt.Sprintf("retained_secret_material expected_count=%d actual_count=%d", relation.ExpectedCount, relation.ActualCount)
}

// Consume converter output as it arrives. Retain bounded test rows, not another
// copy of JSON-escaped output. The binary's two raw captures keep their existing
// independent bounds and remain the private diagnostic source.
type testEventStream struct {
	state              *testEventState
	partial            []byte
	err                error
	overflow           bool
	privateErrorOutput *limitedOutput
}

func (s *testEventStream) Write(body []byte) (int, error) {
	n := len(body)
	for len(body) != 0 && s.err == nil {
		line, rest, complete := bytes.Cut(body, []byte{'\n'})
		if len(s.partial)+len(line) > maximumToolOutputBytes {
			s.err = errors.New("test event line exceeds its bound")
			s.overflow = true
			break
		}
		s.partial = append(s.partial, line...)
		if !complete {
			break
		}
		if len(s.partial) != 0 {
			var event ordinaryEvent
			event, s.err = decodeTestEvent(s.partial)
			if s.err == nil {
				s.err = s.state.accept(event)
				s.overflow = errors.Is(s.err, errTestResultBound)
				if s.err == nil && s.privateErrorOutput != nil {
					s.privateErrorOutput.capturePrivateComponentError(event)
				}
			}
		}
		s.partial = s.partial[:0]
		body = rest
	}
	return n, nil
}

func (s *testEventStream) complete() error {
	if s.err != nil {
		s.state.unobservedOutcome = "incomplete"
		return s.err
	}
	if len(s.partial) != 0 {
		s.state.unobservedOutcome = "incomplete"
		return errors.New("test event stream is truncated")
	}
	return s.state.complete()
}

// Parsing and success proof are different facts. Failed test/package terminals
// can form a valid stream, while missing inventory or helper proof still fails.
func (s *testEventStream) status() string {
	if s.overflow {
		return "overflow"
	}
	if s.err != nil {
		return "malformed"
	}
	if len(s.partial) != 0 {
		return "truncated"
	}
	if len(s.state.packageStates) == 0 {
		return "unavailable"
	}
	for _, outcome := range s.state.packageStates {
		if outcome == "started" {
			return "incomplete"
		}
	}
	for _, result := range s.state.results {
		if result.Outcome == "incomplete" {
			return "incomplete"
		}
	}
	return "valid"
}

func (s *testEventState) componentTests() []componentTest {
	observed := s.executionResults()
	results := make([]componentTest, 0, len(observed))
	for _, result := range observed {
		outcome := result.Outcome
		switch outcome {
		case "pass":
			outcome = "passed"
		case "fail":
			outcome = "failed"
		case "skip":
			outcome = "skipped"
		}
		elapsedObserved := result.ElapsedSeconds != nil
		test := componentTest{Name: result.Name, Outcome: outcome, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt, ElapsedObserved: &elapsedObserved, Relation: result.Relation}
		if result.ElapsedSeconds != nil {
			test.ElapsedSeconds = *result.ElapsedSeconds
		}
		results = append(results, test)
	}
	return results
}

func (s *testEventState) ordinaryTests() []ordinaryTest {
	observed := s.executionResults()
	results := make([]ordinaryTest, 0, len(observed))
	for _, result := range observed {
		results = append(results, ordinaryTest{Package: result.Package, Name: result.Name, Outcome: result.Outcome,
			StartedAt: result.StartedAt, FinishedAt: result.FinishedAt, ElapsedSeconds: result.ElapsedSeconds, Relation: result.Relation})
	}
	return results
}

func (s *testEventState) executionResults() []testEventResult {
	results := append([]testEventResult(nil), s.results...)
	packages := make([]string, 0, len(s.want))
	for pkg := range s.want {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)
	for _, pkg := range packages {
		for _, name := range s.want[pkg] {
			if s.states[pkg][name] == "expected" {
				outcome := s.unobservedOutcome
				if outcome == "" {
					outcome = "not_run"
				}
				results = append(results, testEventResult{Package: pkg, Name: name, Outcome: outcome})
			}
		}
	}
	return results
}
