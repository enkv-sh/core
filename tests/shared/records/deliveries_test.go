package records

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"enkv.sh/compositions/observability"
)

func completeDeliveryFixture(accepted, written, dropped, failed uint64, incomplete bool) DeliveryStatus {
	return DeliveryStatus{Accepted: &accepted, Written: &written, Dropped: &dropped, Failed: &failed, Incomplete: &incomplete}
}

// full_only: false
func TestInspectDeliveryStatusesAdmitsOnlySelectedRoutes(t *testing.T) {
	console := completeDeliveryFixture(2, 2, 0, 0, false)
	fileLogs := completeDeliveryFixture(7, 4, 2, 1, true)
	httpLogs := completeDeliveryFixture(11, 8, 1, 2, false)
	fileMetrics := completeDeliveryFixture(13, 10, 3, 0, false)
	httpMetrics := completeDeliveryFixture(17, 15, 0, 2, true)
	fileTraces := completeDeliveryFixture(19, 19, 0, 0, false)
	httpTraces := completeDeliveryFixture(23, 20, 2, 1, false)
	claims := map[string]DeliveryStatus{
		"logs.console":                       console,
		"logs.private-file-route":            fileLogs,
		"logs.private-http-route":            httpLogs,
		"metrics.private-file-route":         fileMetrics,
		"metrics.private-http-route":         httpMetrics,
		"traces.private-file-route":          fileTraces,
		"traces.private-http-route":          httpTraces,
		"PRIVATE-UNSELECTED-SECRET-SENTINEL": completeDeliveryFixture(999, 999, 0, 0, false),
	}
	for _, test := range []struct {
		name, configuration string
		want                map[string]DeliveryStatus
	}{
		{"nil_default", "", map[string]DeliveryStatus{"logs.console": console}},
		{"console_default", `{"schema_version":1}`, map[string]DeliveryStatus{"logs.console": console}},
		{"file", `{"schema_version":1,"logs":{"exporters":["private-file-route"]},"metrics":{"exporters":["private-file-route"]},"traces":{"exporters":["private-file-route"]},"exporters":{"private-file-route":{"type":"otlp_file","directory":"private-directory-sentinel"}}}`, map[string]DeliveryStatus{"logs.file": fileLogs, "metrics.file": fileMetrics, "traces.file": fileTraces}},
		{"http", `{"schema_version":1,"logs":{"exporters":["private-http-route"]},"metrics":{"exporters":["private-http-route"]},"traces":{"exporters":["private-http-route"]},"exporters":{"private-http-route":{"type":"otlp_http","endpoint":"https://127.0.0.1:4318","api_key_env":"PRIVATE_API_KEY_SENTINEL"}}}`, map[string]DeliveryStatus{"logs.http": httpLogs, "metrics.http": httpMetrics, "traces.http": httpTraces}},
		{"both_with_console", `{"schema_version":1,"logs":{"exporters":["console","private-http-route","private-file-route"]},"metrics":{"exporters":["private-http-route","private-file-route"]},"traces":{"exporters":["private-http-route","private-file-route"]},"exporters":{"private-file-route":{"type":"otlp_file","directory":"private-directory-sentinel"},"private-http-route":{"type":"otlp_http","endpoint":"https://127.0.0.1:4318","api_key_env":"PRIVATE_API_KEY_SENTINEL"}}}`, map[string]DeliveryStatus{"logs.console": console, "logs.file": fileLogs, "logs.http": httpLogs, "metrics.file": fileMetrics, "metrics.http": httpMetrics, "traces.file": fileTraces, "traces.http": httpTraces}},
		{"logs_off", `{"schema_version":1,"logs":{"level":"off","exporters":["console","private-file-route"]},"metrics":{"exporters":["private-file-route"]},"traces":{"exporters":["private-file-route"]},"exporters":{"private-file-route":{"type":"otlp_file","directory":"private-directory-sentinel"}}}`, map[string]DeliveryStatus{"metrics.file": fileMetrics, "traces.file": fileTraces}},
		{"explicit_noop", `{"schema_version":1,"logs":{"exporters":[]}}`, map[string]DeliveryStatus{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inv := Invocation{}
			if test.configuration != "" {
				settings, err := observability.Decode([]byte(test.configuration), observability.Options{})
				if err != nil {
					t.Fatal(err)
				}
				inv.TelemetrySettings = &settings
			}
			before, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			got := InspectDeliveryStatuses(inv, claims)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("public delivery routes or counters differ: got %#v, want %#v", got, test.want)
			}
			missing := InspectDeliveryStatuses(inv, nil)
			wantMissing := make(map[string]DeliveryStatus, len(test.want))
			for route := range test.want {
				wantMissing[route] = DeliveryStatus{}
			}
			if !reflect.DeepEqual(missing, wantMissing) {
				t.Errorf("missing selected delivery claims differ: got %#v, want %#v", missing, wantMissing)
			}
			for _, status := range missing {
				if !status.EvidenceIncomplete() {
					t.Error("unknown selected delivery evidence became complete")
				}
			}
			for _, status := range got {
				*status.Accepted, *status.Written, *status.Dropped, *status.Failed = 101, 102, 103, 104
				*status.Incomplete = !*status.Incomplete
			}
			after, err := json.Marshal(claims)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("public delivery projection retained aliases to private claim fields", err)
			}
		})
	}
}
