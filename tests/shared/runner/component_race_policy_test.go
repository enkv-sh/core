package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestComponentRacePolicyUsesCompiledSourceAndFocus(t *testing.T) {
	// These empty roots satisfy the component assembly's fixed inventory rules.
	// They do not establish the Product memory claims carried by the real roots.
	scaffold := []string{
		"TestOutputConfigurationMaximumPolicyTransitionMemory",
		"TestOutputConfigurationMaximumRoutingTransitionMemory",
		"TestOutputConfigurationMaximumEqualSourceConversionMemory",
		"TestOutputConfigurationMaximumPreparationPreCanceledMemory",
		"TestOutputConfigurationMaximumLastConfigurationReadCanceledMemory",
		"TestOutputConfigurationMaximumLastLargeReadbackUnavailableMemory",
		"TestOutputConfigurationMaximumSigningRefusedMemory",
		"TestOutputConfigurationMaximumSelectionPreCanceledMemory",
		"TestOutputConfigurationMaximumSelectionUnknownWithEffectMemory",
		"TestOutputConfigurationMaximumSelectionUnknownWithoutEffectMemory",
		"TestOrdinaryOutputMemoryNativeArtifact",
		"TestOutputConfigurationGeneratedMaximumTransitionMemory",
		"TestGeneratedMaximumSelectedSetFitsAccessReplacementOverlap",
	}
	const request = "TestPolicyParent/punct[a]+b.c"
	for _, race := range []bool{false, true} {
		t.Run(fmt.Sprintf("race=%t", race), func(t *testing.T) {
			root, bootstrap, build := overlayFixture(t)
			var common strings.Builder
			common.WriteString(`package core
import ("os"; "testing")
// full_only: false
func TestPolicyParent(t *testing.T) {
 options := ""
 if compiledRace { options = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000" }
 if os.Getenv("GORACE") != options { t.Fatal("compiled mode and runtime race options differ") }
 path := os.Getenv("ENKV_COMPONENT_RACE_WITNESS")
 if err := os.WriteFile(path, []byte(compiledMode+"\nsetup\n"), 0600); err != nil { t.Fatal(err) }
 t.Run("punct[a]+b.c", func(t *testing.T) {
  file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
  if err != nil { t.Fatal(err) }
  _, writeErr := file.WriteString(t.Name()+"\n")
  closeErr := file.Close()
  if writeErr != nil || closeErr != nil { t.Fatal(writeErr, closeErr) }
 })
 t.Run("punctaabxc", func(t *testing.T) { t.Fatal("literal focus selected another child") })
 file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
 if err != nil { t.Fatal(err) }
 _, writeErr := file.WriteString("suffix\n")
 closeErr := file.Close()
 if writeErr != nil || closeErr != nil { t.Fatal(writeErr, closeErr) }
}
`)
			for _, name := range scaffold {
				fmt.Fprintf(&common, "// full_only: true\nfunc %s(t *testing.T) {}\n", name)
			}
			writeLocalGoFixture(t, root, "tests/hermetic/component_test.go", common.String())
			writeLocalGoFixture(t, root, "tests/hermetic/race_test.go", `//go:build race

package core
import "testing"
const compiledRace = true
const compiledMode = "race"
// full_only: true
func TestSourcePolicy(t *testing.T) {}
// full_only: false
func TestRaceOnly(t *testing.T) {}
`)
			writeLocalGoFixture(t, root, "tests/hermetic/plain_test.go", `//go:build !race

package core
import "testing"
const compiledRace = false
const compiledMode = "plain"
// full_only: false
func TestSourcePolicy(t *testing.T) {}
// full_only: false
func TestPlainOnly(t *testing.T) {}
`)
			overlay, err := buildOverlay(root, "hermetic", "memory", bootstrap, build)
			if err != nil {
				t.Fatal(err)
			}
			flags := []string{"-mod=readonly", "-overlay=" + overlay}
			ctx, cancel := context.WithTimeout(withRacePolicy(t.Context(), race), 2*time.Minute)
			defer cancel()
			binary := filepath.Join(build, "component-policy.test")
			args := append([]string{"test"}, compilerBuildFlags(flags, race)...)
			if _, err := runGo(ctx, root, "core", append(args, "-c", "-o", binary, ".")...); err != nil {
				t.Fatal(err)
			}
			observed, err := binaryRace(binary)
			if err != nil || observed != race {
				t.Fatal("compiled race mode differs", observed, err)
			}
			active, mode := "TestPlainOnly", "plain"
			if race {
				active, mode = "TestRaceOnly", "race"
			}
			wantInventory := append(slices.Clone(scaffold), "TestPolicyParent", "TestSourcePolicy", active)
			slices.Sort(wantInventory)
			wantClassifications := map[string]bool{"TestPolicyParent": false, "TestSourcePolicy": race, active: false}
			for _, name := range scaffold {
				wantClassifications[name] = true
			}
			t.Setenv("GORACE", "exitcode=0 halt_on_error=1 atexit_sleep_ms=0")
			for _, profile := range []string{"dev", "full"} {
				t.Run(profile, func(t *testing.T) {
					witness := filepath.Join(t.TempDir(), "observation")
					env := environment(os.Environ(), map[string]string{"ENKV_COMPONENT_RACE_WITNESS": witness})
					process, checks, _, _ := executeFixtureProfileComponentChecks(t, nil, ctx, root, binary, testEventConverterFixture(t, root), flags, env, profile, singleTestRequest(request), 1, nil, nil)
					if process.Status != "passed" || !process.Joined || !completeFocusedComponentEvidence(checks) {
						t.Fatalf("component execution lacks complete focused results: process=%+v cause=%v checks=%+v", process, process.Cause, checks)
					}
					inventory := slices.Clone(checks.Inventory)
					slices.Sort(inventory)
					if !slices.Equal(inventory, wantInventory) {
						t.Fatal("compiled source inventory differs", inventory, wantInventory)
					}
					classifications := map[string]bool{}
					for _, row := range checks.Classifications {
						if row.FullOnly == nil {
							t.Fatal("active source classification is missing", row.Name)
						}
						classifications[row.Name] = *row.FullOnly
					}
					if !reflect.DeepEqual(classifications, wantClassifications) || len(checks.Classifications) != len(wantClassifications) {
						t.Fatal("classification did not use the active compiled source", classifications, wantClassifications)
					}
					var wantOmitted []string
					if profile == "dev" {
						wantOmitted = slices.Clone(scaffold)
						if race {
							wantOmitted = append(wantOmitted, "TestSourcePolicy")
						}
					}
					omitted := slices.Clone(checks.NotSelected)
					slices.Sort(omitted)
					slices.Sort(wantOmitted)
					if !slices.Equal(omitted, wantOmitted) || checks.Profile != profile || checks.Race != race || checks.RaceOptions != acceptedRaceOptions(race) || checks.Selection != "^TestPolicyParent$/^punct\\[a\\]\\+b\\.c$" {
						t.Fatal("focus changed profile, omissions, literal selection or race policy", checks)
					}
					if len(checks.Tests) != 2 || checks.Tests[0].Name != "TestPolicyParent" || checks.Tests[1].Name != request || checks.Tests[0].Outcome != "passed" || checks.Tests[1].Outcome != "passed" {
						t.Fatal("focus did not retain the exact ancestor and child terminals", checks.Tests)
					}
					body, err := os.ReadFile(witness)
					if err != nil || string(body) != mode+"\nsetup\n"+request+"\nsuffix\n" {
						t.Fatal("compiled witness omitted parent or literal child work", string(body), err)
					}
					if len(checks.Diagnostics.Commands) != 4 {
						t.Fatal("component command inventory differs", checks.Diagnostics.Commands)
					}
					phases := map[string]int{}
					for index, command := range checks.Diagnostics.Commands {
						phases[command.Phase+"/"+command.Scope]++
						wantPreparation := command.Phase == "preparation" && command.Scope == "test2json"
						if (command.ModulePreparation != nil) != wantPreparation {
							t.Fatal("component module prerequisite inventory differs", index, command)
						}
						if preparation := command.ModulePreparation; preparation != nil && (preparation.Process != "passed" || !preparation.Started || !preparation.Joined) {
							t.Fatal("component module prerequisite did not complete and join", index, preparation)
						}
						if !command.Started || !command.Joined || command.Process != "passed" {
							t.Fatal("component command did not complete and join", command)
						}
					}
					for _, key := range []string{"preparation/inventory", "preparation/test2json", "test/selected-1", "conversion/selected-1"} {
						if phases[key] != 1 {
							t.Fatal("component capture, converter or execution facts were omitted or repeated", phases)
						}
					}
					_, _, _, _, focusErr := resolveComponentGroups(checks.Inventory, checks.Classifications, profile, singleTestRequest("TestSourcePolicy"), 4, componentEstimates)
					if (focusErr != nil) != (profile == "dev" && race) {
						t.Fatal("focus bypassed the active source classification", focusErr)
					}

				})
			}
			for _, mismatch := range []string{"assembly-policy", "invocation"} {
				t.Run(mismatch+"-mismatch", func(t *testing.T) {
					owner := assembly{Binary: binary, Closure: assemblyClosure{Race: observed}}
					invocation := ctx
					if mismatch == "assembly-policy" {
						owner.Closure.Race = !observed
					} else {
						invocation = withRacePolicy(ctx, !observed)
					}
					owner.Closure.RaceOptions = acceptedRaceOptions(owner.Closure.Race)
					if owner.Closure.Race {
						owner.Closure.RaceExitSleepMillis = 1000
					}
					process, checks, _, _ := executeFixtureProfileComponentChecks(t, nil, invocation, root, binary, testEventConverterFixture(t, root), flags, os.Environ(), "dev", singleTestRequest(request), 1, nil, &owner)
					if process.Status != "process_failed" || !process.Joined || process.Cause == nil || !strings.Contains(process.Cause.Error(), "component race policy differs from assembly") || len(checks.Inventory) != 0 || len(checks.Tests) != 0 {
						t.Fatalf("mismatched owner reached component execution: process=%+v cause=%v checks=%+v", process, process.Cause, checks)
					}
				})
			}
		})
	}
}
