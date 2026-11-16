package records

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"

	"enkv.sh/compositions/observability"
)

const maximumDiagnosticLineBytes = 256 << 10

const maximumLogFileBytes = 4 << 20

// InspectLogs admits only the selected OTLP JSONL log file. Worker-provided
// counts are advisory; the file shape and ownership are checked separately.
func InspectLogs(inv Invocation, claim Diagnostics) (out Diagnostics) {
	settings := inv.TelemetrySettings
	if settings == nil {
		defaults, err := observability.Resolve(observability.Config{}, observability.Options{})
		if err != nil {
			return Diagnostics{Enabled: true, Status: "incomplete", FailureClass: "configuration_invalid"}
		}
		settings = &defaults
	}
	enabled := settings.LogLevel != observability.Off && (settings.Console || len(settings.LogExporters) != 0)
	if !enabled {
		return Diagnostics{Status: "disabled"}
	}
	out = Diagnostics{Enabled: true, Status: "incomplete", FailureClass: "worker_terminated"}
	if !claim.Enabled || claim.Status != "complete" && claim.Status != "incomplete" {
		return out
	}
	out = claim
	out.Source = ""
	if claim.Source == "" {
		return out
	}
	expected := ""
	for _, name := range settings.LogExporters {
		exporter := settings.ActiveExporters[name]
		if exporter.Type == "otlp_file" {
			expected = path.Join(exporter.Directory, "logs.jsonl")
		}
	}
	if expected == "" || claim.Source != expected {
		out.Status, out.FailureClass = "incomplete", "source_refused"
		return out
	}
	filePath, err := SafePath(inv.OutputDir, expected)
	if err != nil {
		out.Status, out.FailureClass = "incomplete", "path_unavailable"
		return out
	}
	file, err := os.Open(filePath)
	if err != nil {
		out.Status, out.FailureClass = "incomplete", "source_unavailable"
		return out
	}
	defer func() {
		if err := file.Close(); err != nil {
			out.Source = ""
			out.Status, out.FailureClass = "incomplete", "source_unavailable"
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maximumLogFileBytes {
		out.Status, out.FailureClass = "incomplete", "source_refused"
		return out
	}
	reader := bufio.NewReader(io.LimitReader(file, maximumLogFileBytes+1))
	lines := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) != 0 {
			if readErr != nil || len(line) > maximumDiagnosticLineBytes {
				out.Status, out.FailureClass = "incomplete", "truncated"
				return out
			}
			var top struct {
				ResourceLogs []json.RawMessage `json:"resourceLogs"`
			}
			if json.Unmarshal(bytes.TrimSuffix(line, []byte{'\n'}), &top) != nil || len(top.ResourceLogs) == 0 {
				out.Status, out.FailureClass = "incomplete", "format_refused"
				return out
			}
			lines++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.Status, out.FailureClass = "incomplete", "source_unavailable"
			return out
		}
	}
	if lines == 0 {
		out.Status, out.FailureClass = "incomplete", "source_unavailable"
		return out
	}
	out.Source = expected
	return out
}
