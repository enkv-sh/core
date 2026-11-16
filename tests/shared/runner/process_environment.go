package main

import (
	"os"
	"strings"
)

const raceOptions = "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000"

const buildGoFlags = "-trimpath"

// Analysis must retain physical paths used by CGo //line directives.
const analysisGoFlags = "-trimpath=false"

func goEnvironment() []string {
	return environment(os.Environ(), map[string]string{"GOWORK": "off", "GOTOOLCHAIN": "local", "GOFLAGS": buildGoFlags, "GORACE": ""})
}

func raceEnvironment(base []string, enabled bool) []string {
	return environment(base, map[string]string{"GORACE": acceptedRaceOptions(enabled)})
}

func environment(base []string, overrides map[string]string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[key]; !replaced {
			result = append(result, item)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}
