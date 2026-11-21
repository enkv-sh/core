package compositionfull_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core/contract"
)

func ExamplePrepareConfiguration() {
	prepare := func(ctx context.Context, out io.Writer) (int, error) {
		result, operationErr := compositionfull.PrepareConfiguration(ctx, compositionfull.PrepareRequest{
			Source: "/absolute/configuration.yaml", Format: configuration.YAML,
		})
		body, renderErr := compositionfull.RenderPrepareJSON(result)
		var writeErr error
		if renderErr == nil {
			var n int
			n, writeErr = out.Write(body)
			if writeErr == nil && n != len(body) {
				writeErr = io.ErrShortWrite
			}
		}
		presentationErr := errors.Join(renderErr, writeErr)
		return compositionfull.PrepareExitCode(result, presentationErr), errors.Join(operationErr, presentationErr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	code, err := prepare(ctx, os.Stdout)
	fmt.Printf("exit=%d failure=%t\n", code, err != nil)
}

func ExampleDisplayConfigurationFiles() {
	display := func(ctx context.Context, output *os.File) (int, error) {
		var requestID contract.ID
		if _, err := rand.Read(requestID[:]); err != nil {
			return 2, err
		}
		if requestID.IsZero() {
			return 2, errors.New("request correlation unavailable")
		}
		factory, err := compositionfull.NewPlanningDisplayFile(output, true)
		if err != nil {
			return 2, err
		}
		result := compositionfull.DisplayConfigurationFiles(ctx, requestID,
			"/absolute/trusted.yaml", configuration.YAML,
			"/absolute/candidate.yaml", configuration.YAML,
			[]string{"API_TOKEN"}, factory)
		code := compositionfull.PlanningExitCode(result)
		if result.DisplayDelivery != contract.PlanningDeliveryComplete {
			return code, errors.New("display incomplete")
		}
		body, renderErr := compositionfull.RenderPlanningCommandJSON(result)
		if renderErr != nil {
			if code != 3 {
				code = 2
			}
			return code, renderErr
		}
		if err := result.WriteDisplayResult(ctx, output, body); err != nil {
			if code != 3 {
				code = 2
			}
			return code, err
		}
		return code, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	code, err := display(ctx, os.Stdout)
	fmt.Printf("exit=%d failure=%t\n", code, err != nil)
}
