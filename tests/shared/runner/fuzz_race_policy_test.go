package main

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// full_only: false
func TestFuzzBuilderCompilesAcceptedRacePolicy(t *testing.T) {
	for _, race := range []bool{false, true} {
		t.Run(fmt.Sprintf("race_%t", race), func(t *testing.T) {
			root, _, build := overlayFixture(t)
			writeLocalGoFixture(t, root, "crypto/go.mod", "module "+modulePrefix+"crypto\n\ngo 1.27.0\n\nrequire enkv.sh/telemetry v0.0.0\n")
			writeLocalGoFixture(t, root, "telemetry/go.mod", "module enkv.sh/telemetry\n\ngo 1.27.0\n")
			writeLocalGoFixture(t, root, "telemetry/telemetry.go", "package telemetry\nfunc Value() int {return 1}\n")
			writeLocalGoFixture(t, root, "crypto/internal/custody/fuzz_test.go", `package custody
import ("testing"; "enkv.sh/telemetry")
// full_only: false
func FuzzCustodyOpen(f *testing.F) {
 f.Add([]byte{byte(telemetry.Value())})
 f.Fuzz(func(t *testing.T, value []byte) {})
}
`)
			ctx, artifactOwner := withInvocationArtifacts(withRacePolicy(t.Context(), race))
			defer func() {
				if err := artifactOwner.close(ctx, true); err != nil {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			artifact, err := prepareFuzzArtifact(ctx, root, build, fuzzSpecifications[2], nil)
			if err != nil {
				t.Fatal("instrumented compile-only artifact", err)
			}
			binary := artifact.executable.binary
			writeLocalGoFixture(t, root, "crypto/internal/custody/fuzz_test.go", "invalid source after completed instrumented construction")
			again, err := prepareFuzzArtifact(ctx, root, build, fuzzSpecifications[2], nil)
			if err != nil || again.executable.binary != binary {
				t.Fatal("source edit rebuilt fuzz executable", err)
			}
			if _, err := os.Stat(binary); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(binary, "package.test") || artifact.closure.BinarySHA256 == "" || artifact.seedDigests["FuzzCustodyOpen"] == "" || !slices.Contains(artifact.closure.CompiledImports, "enkv.sh/telemetry") {
				t.Fatal("actual fuzz artifact lacks build/corpus identity")
			}
			info, err := buildinfo.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			raceFlags := 0
			for _, setting := range info.Settings {
				if setting.Key != "-race" {
					continue
				}
				if setting.Value != "true" {
					t.Fatalf("unsupported race metadata: %+v", setting)
				}
				raceFlags++
			}
			wantRaceFlags := 0
			if race {
				wantRaceFlags = 1
			}
			if raceFlags != wantRaceFlags {
				t.Fatalf("actual compiled fuzz mode differs: race=%t metadata flags=%d", race, raceFlags)
			}
		})
	}
}
