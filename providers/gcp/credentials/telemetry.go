package credentials

import (
	"context"
	"net/http"

	"enkv.sh/telemetry"
)

type authenticationKey struct{}

// StartAuthenticationTelemetry counts a nested managed-token capture only once.
func StartAuthenticationTelemetry(ctx context.Context) (context.Context, *telemetry.Call) {
	if ctx != nil && ctx.Value(authenticationKey{}) == true {
		return ctx, nil
	}
	call := telemetry.Start(ctx, telemetry.ProviderGCP, telemetry.OpAuthentication)
	if call == nil {
		return ctx, nil
	}
	call.Checkpoint(telemetry.DiagnosticProviderCall, telemetry.DiagnosticReasonNone)
	return context.WithValue(call.Context(), authenticationKey{}, true), call
}

func finishCredentialTelemetry(call *telemetry.Call, ok bool) {
	result := telemetry.ResultFailure
	if ok {
		result = telemetry.ResultSuccess
	}
	call.Finish(result)
}

type httpTelemetry struct {
	attempt           *telemetry.HTTPAttempt
	request, response *telemetry.BodyObservation
	status            int
}

func startHTTPTelemetry(r *http.Request) *httpTelemetry {
	_, ok := r.Context().Value(authenticationKey{}).(bool)
	if !ok {
		return nil
	}
	attempt := telemetry.StartHTTP(r.Context(), telemetry.ProviderGCP, telemetry.OpAuthentication)
	if attempt == nil {
		return nil
	}
	observation := &httpTelemetry{attempt: attempt}
	if r.Body != nil && r.Body != http.NoBody {
		length := r.ContentLength
		if length == 0 {
			length = -1
		}
		observation.request = telemetry.TrackBody(r.Body, length)
		r.Body = observation.request
	}
	return observation
}

func (observation *httpTelemetry) observeResponse(resp *http.Response) {
	if observation == nil || resp == nil {
		return
	}
	observation.status = resp.StatusCode
	if resp.Body != nil {
		observation.response = telemetry.TrackBody(resp.Body, resp.ContentLength)
		resp.Body = observation.response
	}
}

func (observation *httpTelemetry) finish(failed bool) {
	if observation == nil {
		return
	}
	observation.attempt.ObserveRequest(observation.request.Snapshot())
	if observation.response != nil {
		observation.attempt.ObserveResponse(observation.response.Snapshot())
	}
	observation.attempt.Finish(observation.status, failed)
}
