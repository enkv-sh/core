package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const retainedMaterialTest = "TestSuppliedPlainMutationOpensSourcesOnlyDuringComparison"

func retainedRelationEvents(pkg, owner string, outputs []string, terminal string) []byte {
	top, _, _ := strings.Cut(owner, "/")
	events := []ordinaryEvent{{Action: "start", Package: pkg}, {Action: "run", Package: pkg, Test: top}}
	if owner != top {
		events = append(events, ordinaryEvent{Action: "run", Package: pkg, Test: owner})
	}
	for _, output := range outputs {
		events = append(events, ordinaryEvent{Action: "output", Package: pkg, Test: owner, Output: output})
	}
	if terminal != "" {
		if owner != top {
			events = append(events, ordinaryEvent{Action: terminal, Package: pkg, Test: owner})
		}
		events = append(events, ordinaryEvent{Action: terminal, Package: pkg, Test: top})
		packageTerminal := terminal
		if terminal == "skip" {
			packageTerminal = "pass"
		}
		events = append(events, ordinaryEvent{Action: packageTerminal, Package: pkg})
	}
	return ordinaryEvents(events...)
}

func retainedRelationRows(t *testing.T, body []byte, pkg, owner, consumer string, chunk int) ([]map[string]any, error) {
	t.Helper()
	top, _, _ := strings.Cut(owner, "/")
	var rows any
	var resultErr error
	if consumer == "ordinary" {
		rows, resultErr = validateOrdinaryEvents(body, map[string][]string{pkg: {top}}, nil)
	} else {
		state, err := newTestEventState(map[string][]string{pkg: {top}}, maximumComponentTests, validComponentName, nil)
		if err != nil {
			t.Fatal(err)
		}
		stream := &testEventStream{state: state}
		for len(body) != 0 {
			n := min(chunk, len(body))
			_, _ = stream.Write(body[:n])
			body = body[n:]
		}
		resultErr = stream.complete()
		rows = state.componentTests()
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"SYNTHETIC_RELATION_PREFIX", "/private/controlled-lifecycle.go", "enkv-retained-secret-material"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Error("raw relation output reached public rows", private)
		}
	}
	var saved []map[string]any
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	return saved, resultErr
}

// full_only: false
func TestRetainedSecretMaterialRelationEvidencePreservesOwnedCounts(t *testing.T) {
	for _, consumer := range []string{"ordinary", "component"} {
		for _, mode := range []string{"false", "true"} {
			for _, spec := range []struct {
				name, marker, terminal, tail string
				expected, actual             float64
				wantError                    bool
			}{
				{"matching-pass", "enkv-retained-secret-material expected=1 actual=1", "pass", "", 1, 1, false},
				{"mismatching-failure", "enkv-retained-secret-material expected=1 actual=0", "fail", "", 1, 0, true},
				{"reversed-mismatch", "enkv-retained-secret-material expected=0 actual=1", "fail", "", 0, 1, true},
				{"mismatching-claimed-pass", "enkv-retained-secret-material expected=1 actual=0", "pass", "", 1, 0, true},
				{"matching-incomplete", "enkv-retained-secret-material expected=1 actual=1", "", "", 1, 1, true},
				{"prefix-before-malformed", "enkv-retained-secret-material expected=1 actual=1", "", "not-json\n", 1, 1, true},
				{"prefix-before-truncated", "enkv-retained-secret-material expected=1 actual=1", "", `{"Action":"pass"`, 1, 1, true},
			} {
				t.Run(consumer+"/"+mode+"/"+spec.name, func(t *testing.T) {
					owner := retainedMaterialTest + "/" + mode
					output := "    /private/controlled-lifecycle.go/SYNTHETIC_RELATION_PREFIX:1: " + spec.marker + "\n"
					body := append(retainedRelationEvents(componentPackage, owner, []string{output}, spec.terminal), spec.tail...)
					chunks := []int{len(body)}
					if consumer == "component" {
						chunks = []int{1, 7, len(body)}
					}
					for _, chunk := range chunks {
						rows, err := retainedRelationRows(t, body, componentPackage, owner, consumer, chunk)
						if (err != nil) != spec.wantError {
							t.Error("relation changed execution qualification", chunk, err)
						}
						found := false
						for _, row := range rows {
							if row["name"] != owner {
								if _, present := row["relation"]; present {
									t.Error("relation escaped its event owner", row)
								}
								continue
							}
							found = true
							fact, ok := row["relation"].(map[string]any)
							if !ok || len(fact) != 3 || fact["name"] != "retained_secret_material" || fact["expected_count"] != spec.expected || fact["actual_count"] != spec.actual {
								t.Error("owned bounded relation counts were lost", chunk, row)
							}
							if spec.name == "mismatching-claimed-pass" {
								want := "pass"
								if consumer == "component" {
									want = "passed"
								}
								if row["outcome"] != want {
									t.Error("relation mismatch fabricated a failed test terminal", row)
								}
							}
						}
						if !found {
							t.Error("relation lost its observed child", chunk)
						}
					}
				})
			}
		}
	}
}

// full_only: false
func TestRetainedSecretMaterialRelationRejectsUnownedOrMalformedFacts(t *testing.T) {
	valid := "enkv-retained-secret-material expected=1 actual=1\n"
	for _, consumer := range []string{"ordinary", "component"} {
		for _, spec := range []struct {
			name, pkg, owner string
			outputs          []string
		}{
			{"wrong-package", "example.org/unowned", retainedMaterialTest + "/false", []string{valid}},
			{"wrong-root", componentPackage, "TestOther/false", []string{valid}},
			{"parent-only", componentPackage, retainedMaterialTest, []string{valid}},
			{"wrong-mode", componentPackage, retainedMaterialTest + "/other", []string{valid}},
			{"unknown-key", componentPackage, retainedMaterialTest + "/false", []string{"enkv-retained-secret-material expected=1 unknown=1\n"}},
			{"negative", componentPackage, retainedMaterialTest + "/false", []string{"enkv-retained-secret-material expected=1 actual=-1\n"}},
			{"oversized", componentPackage, retainedMaterialTest + "/false", []string{"enkv-retained-secret-material expected=1 actual=2\n"}},
			{"expected-oversized", componentPackage, retainedMaterialTest + "/false", []string{"enkv-retained-secret-material expected=2 actual=1\n"}},
			{"duplicate", componentPackage, retainedMaterialTest + "/false", []string{valid, valid}},
			{"trailing-text", componentPackage, retainedMaterialTest + "/false", []string{strings.TrimSuffix(valid, "\n") + " SYNTHETIC_RELATION_PREFIX\n"}},
		} {
			t.Run(consumer+"/"+spec.name, func(t *testing.T) {
				body := retainedRelationEvents(spec.pkg, spec.owner, spec.outputs, "pass")
				rows, err := retainedRelationRows(t, body, spec.pkg, spec.owner, consumer, len(body))
				if err == nil {
					t.Error("unowned or malformed relation facts qualified the stream")
				}
				if err != nil && strings.Contains(err.Error(), "SYNTHETIC_RELATION_PREFIX") {
					t.Error("relation rejection echoed raw text")
				}
				for _, row := range rows {
					fact, present := row["relation"].(map[string]any)
					wantPresent := spec.name == "duplicate" && row["name"] == spec.owner
					if present != wantPresent || present && (fact["name"] != "retained_secret_material" || fact["expected_count"] != float64(1) || fact["actual_count"] != float64(1)) {
						t.Error("invalid marker changed retained relation ownership or erased the first observation", row)
					}
				}
			})
		}
	}
}

// full_only: false
func TestRetainedSecretMaterialRelationDoesNotCompleteMissingChild(t *testing.T) {
	owner := retainedMaterialTest + "/false"
	body := retainedRelationEvents(componentPackage, owner, []string{"enkv-retained-secret-material expected=1 actual=1\n"}, "pass")
	focus := ordinaryFocus{Package: componentPackage, Tests: singleTestRequest(owner + "/unobserved")}
	rows, err := validateOrdinaryFocusedEvents(body, map[string][]string{componentPackage: {retainedMaterialTest}}, nil, focus)
	if err == nil {
		t.Fatal("matching relation granted a missing child completion")
	}
	if len(rows) != 2 {
		t.Error("matching relation erased observed owner rows")
	}
}

// full_only: false
func TestRetainedSecretMaterialRelationOutputRequiresStartedChild(t *testing.T) {
	owner := retainedMaterialTest + "/false"
	for _, consumer := range []string{"ordinary", "component"} {
		for _, condition := range []string{"package-output", "before-child"} {
			t.Run(consumer+"/"+condition, func(t *testing.T) {
				outputOwner := ""
				if condition == "before-child" {
					outputOwner = owner
				}
				body := ordinaryEvents(
					ordinaryEvent{Action: "start", Package: componentPackage},
					ordinaryEvent{Action: "run", Package: componentPackage, Test: retainedMaterialTest},
					ordinaryEvent{Action: "output", Package: componentPackage, Test: outputOwner, Output: "enkv-retained-secret-material expected=1 actual=1\n"},
					ordinaryEvent{Action: "run", Package: componentPackage, Test: owner},
					ordinaryEvent{Action: "pass", Package: componentPackage, Test: owner},
					ordinaryEvent{Action: "pass", Package: componentPackage, Test: retainedMaterialTest},
					ordinaryEvent{Action: "pass", Package: componentPackage},
				)
				rows, err := retainedRelationRows(t, body, componentPackage, owner, consumer, len(body))
				if err == nil {
					t.Error("relation output without a started child qualified")
				}
				for _, row := range rows {
					if _, present := row["relation"]; present {
						t.Error("relation was assigned without its observed child", row)
					}
				}
			})
		}
	}
}
