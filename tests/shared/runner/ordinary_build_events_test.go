package main

import (
	"strings"
	"testing"
)

// full_only: false
func TestOrdinaryChecksKeepTestsDistinctFromGoBuildEvents(t *testing.T) {
	const pkg = "example.org/ordinary"
	const build = "{\"ImportPath\":\"example.org/ordinary [example.org/ordinary.test]\",\"Action\":\"build-output\",\"Output\":\"compiler diagnostic\\n\"}\n"
	execution := ordinaryEvents(
		ordinaryEvent{Action: "start", Package: pkg},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "pass", Package: pkg},
	)
	body := append([]byte(build), execution...)
	outcomes, err := validateOrdinaryEvents(body, map[string][]string{pkg: {"TestAlpha"}}, nil)
	if err != nil || len(outcomes) != 1 || outcomes[0].Name != "TestAlpha" || outcomes[0].Outcome != "pass" {
		t.Fatal("valid independent build output prevented exact test results", outcomes, err)
	}
	inventory := []byte(build + "{\"Action\":\"start\",\"Package\":\"example.org/ordinary\"}\n" +
		"{\"Action\":\"output\",\"Package\":\"example.org/ordinary\",\"Output\":\"TestAlpha\\n\"}\n" +
		"{\"Action\":\"pass\",\"Package\":\"example.org/ordinary\"}\n")
	events, err := ordinaryEventsFrom(inventory)
	if err != nil || len(events) != 3 || events[1].Output != "TestAlpha\n" {
		t.Fatal("build output was not separated from exact test inventory", events, err)
	}
	const global = "{\"ImportPath\":\"\",\"Action\":\"build-output\",\"Output\":\"global compiler diagnostic\\n\"}\n"
	if outcomes, err := validateOrdinaryEvents(append([]byte(global), execution...), map[string][]string{pkg: {"TestAlpha"}}, nil); err != nil || len(outcomes) != 1 || outcomes[0].Outcome != "pass" {
		t.Fatal("explicit global build identity prevented exact test results", outcomes, err)
	}
	for _, invalid := range []string{
		"{\"ImportPath\":\"example.org/ordinary\",\"Action\":\"build-fail\"}\n",
		"{\"Action\":\"build-output\",\"Output\":\"missing identity\\n\"}\n",
		"{\"ImportPath\":\"example.org/ordinary\",\"Action\":\"unknown-build-action\"}\n",
		"{\"ImportPath\":null,\"Action\":\"build-output\",\"Output\":\"null identity\\n\"}\n",
		"{\"ImportPath\":\"example.org/ordinary\",\"Action\":\"build-output\",\"Package\":\"\",\"Output\":\"empty package still mixes schemas\\n\"}\n",
		"{\"ImportPath\":\"example.org/ordinary\",\"Action\":\"build-output\",\"Elapsed\":null,\"Output\":\"test time field still mixes schemas\\n\"}\n",
		"{\"ImportPath\":\"example.org/ordinary\",\"Action\":\"build-output\",\"Package\":\"example.org/ordinary\",\"Test\":\"TestAlpha\",\"Output\":\"mixed schema\\n\"}\n",
	} {
		if _, err := validateOrdinaryEvents(append([]byte(invalid), execution...), map[string][]string{pkg: {"TestAlpha"}}, nil); err == nil {
			t.Fatal("failed or malformed build event was accepted", invalid)
		}
	}
	failed := ordinaryEvents(
		ordinaryEvent{Action: "start", Package: pkg},
		ordinaryEvent{Action: "run", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "output", Package: pkg, Test: "TestAlpha", Output: "exact failed assertion\n"},
		ordinaryEvent{Action: "fail", Package: pkg, Test: "TestAlpha"},
		ordinaryEvent{Action: "fail", Package: pkg},
	)
	private := prioritizeFailedGoTestOutput(append([]byte(build), failed...))
	if !strings.Contains(string(private), "exact failed assertion") || !strings.Contains(string(private), "compiler diagnostic") || strings.Contains(string(private), "Non-event stdout excluded") {
		t.Fatal("valid build output damaged bounded private failed-test diagnostics")
	}
	if _, err := validateOrdinaryEvents(append([]byte(global), failed...), map[string][]string{pkg: {"TestAlpha"}}, nil); err == nil {
		t.Fatal("global build output masked an actual failed test")
	}
	if _, err := validateOrdinaryEvents([]byte(build), map[string][]string{pkg: {"TestAlpha"}}, nil); err == nil {
		t.Fatal("build output established an unexecuted test")
	}
}
