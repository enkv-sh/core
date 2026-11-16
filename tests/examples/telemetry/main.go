package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"

	"enkv.sh/compositions/observability"
	"enkv.sh/core"
	"enkv.sh/telemetry"
)

func main() {
	configuration := flag.String("telemetry-config", "", "selected JSON telemetry configuration")
	logLevel := flag.String("log-level", "", "console and export log level")
	flag.Parse()
	settings, err := observability.Load(*configuration, observability.EnvironmentOptions(*logLevel))
	if err != nil {
		fmt.Fprintln(os.Stderr, "telemetry configuration refused")
		os.Exit(2)
	}
	var invocationBytes [16]byte
	if _, err := rand.Read(invocationBytes[:]); err != nil {
		fmt.Fprintln(os.Stderr, "invocation identity unavailable")
		os.Exit(2)
	}
	runtime, err := observability.Start(settings, observability.SetupOptions{BaseDirectory: "."})
	if err != nil {
		fmt.Fprintln(os.Stderr, "telemetry setup refused")
		os.Exit(2)
	}
	invocationID := hex.EncodeToString(invocationBytes[:])
	ctx := runtime.Context(context.Background())
	invocation := telemetry.StartWithDetails(ctx, telemetry.ProviderApplication, telemetry.OpApplicationInvocation,
		(telemetry.DiagnosticDetails{}).WithInvocationID(invocationID))
	// A zero admission demonstrates a bounded refusal without fixtures or cloud access.
	_, result := core.Open(telemetry.CallContext(ctx, invocation), core.OpenContext{}, nil)
	if result.Outcome == core.AdmissionRefused {
		invocation.Finish(telemetry.ResultSuccess)
	} else {
		invocation.Finish(telemetry.ResultFailure)
	}
	fmt.Printf("invocation ID: %s\n", invocationID)
	fmt.Printf("operation outcome: %d\n", result.Outcome)
	if runtime.Close(context.Background()) != nil {
		fmt.Fprintln(os.Stderr, "telemetry delivery incomplete")
	}
	statuses := runtime.DeliveryStatuses()
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status := statuses[name]
		fmt.Fprintf(os.Stderr, "telemetry %s accepted=%d written=%d dropped=%d failed=%d incomplete=%t\n",
			name, status.Accepted, status.Written, status.Dropped, status.Failed, status.Incomplete)
	}
}
