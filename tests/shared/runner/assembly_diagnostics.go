package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	assemblyDiagnosticName        = "assembly.log"
	assemblyDiagnosticOutputLimit = 256 << 10
	assemblyDiagnosticCauseLimit  = 64 << 10
	assemblyDiagnosticFileLimit   = 1 << 20
)

type assemblyDiagnosticSink interface {
	io.Writer
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

func (s *runState) retainAssemblyFailure(cause error) error {
	return retainCheckFailure(s.directory, assemblyDiagnosticName, "assembly", cause)
}

func writeAssemblyDiagnostic(file assemblyDiagnosticSink, cause error) error {
	writeErr := file.Chmod(0600)
	if writeErr == nil {
		writeErr = writeAssemblyDiagnosticBody(file, cause)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

func writeAssemblyDiagnosticBody(writer io.Writer, cause error) error {
	bounded := &checkDiagnosticWriter{writer: writer, remaining: assemblyDiagnosticFileLimit - 64}
	remaining := 128
	err := writeCheckCauses(bounded, cause, 0, &remaining)
	if bounded.truncated {
		_, markerErr := io.WriteString(writer, "\nAdditional diagnostic content truncated: true\n")
		err = errors.Join(err, markerErr)
	}
	return err
}

type checkDiagnosticWriter struct {
	writer    io.Writer
	remaining int
	truncated bool
}

func (w *checkDiagnosticWriter) Write(body []byte) (int, error) {
	n := len(body)
	if len(body) > w.remaining {
		body = body[:w.remaining]
		w.truncated = true
	}
	written, err := w.writer.Write(body)
	w.remaining -= written
	if err != nil {
		return written, err
	}
	if written != len(body) {
		return written, io.ErrShortWrite
	}
	return n, nil
}

func writeCheckCauses(writer io.Writer, cause error, depth int, remaining *int) error {
	if depth >= 32 || *remaining <= 0 {
		_, err := io.WriteString(writer, "Additional cause branches truncated: true\n")
		return err
	}
	*remaining--
	if failure, ok := cause.(*checkFailure); ok {
		return writeCheckCauses(writer, failure.cause, depth+1, remaining)
	}
	if failure, ok := cause.(*localCheckFailure); ok {
		return writeCheckCauses(writer, failure.cause, depth+1, remaining)
	}
	if joined, ok := cause.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if err := writeCheckCauses(writer, child, depth+1, remaining); err != nil {
				return err
			}
		}
		return nil
	}
	if failure, ok := cause.(*toolFailure); ok {
		if _, err := fmt.Fprintf(writer, "Operation: %s\nProcess: %s\nStarted: %t\nJoined: %t\nOutput bound exceeded: %t\n",
			failure.operation, failure.process.Status, failure.process.Started, failure.process.Joined, failure.overflow); err != nil {
			return err
		}
		if err := writeAssemblyCause(writer, "Command cause", failure.process.Cause); err != nil {
			return err
		}
		if err := writeAssemblyCause(writer, "Cleanup cause", failure.cleanup); err != nil {
			return err
		}
		if !failure.process.Joined {
			_, err := io.WriteString(writer, "Captured output unavailable: process group did not settle\n")
			return err
		}
		stdout := failure.stdout
		if failure.operation == "go test" {
			stdout = prioritizeFailedGoTestOutput(stdout)
		}
		if err := writeAssemblyOutput(writer, "Stdout", stdout, failure.overflow); err != nil {
			return err
		}
		return writeAssemblyOutput(writer, "Stderr", failure.stderr, failure.overflow)
	}
	if wrapped, ok := cause.(interface{ Unwrap() error }); ok && wrapped.Unwrap() != nil {
		if err := writeAssemblyCause(writer, "Wrapper context", cause); err != nil {
			return err
		}
		return writeCheckCauses(writer, wrapped.Unwrap(), depth+1, remaining)
	}
	return writeAssemblyCause(writer, "Assembly cause", cause)
}

func writeAssemblyCause(writer io.Writer, name string, cause error) error {
	value := "<nil>"
	if cause != nil {
		value = cause.Error()
	}
	truncated := len(value) > assemblyDiagnosticCauseLimit
	if truncated {
		value = value[:assemblyDiagnosticCauseLimit]
	}
	_, err := fmt.Fprintf(writer, "%s (truncated: %t): %s\n", name, truncated, value)
	return err
}

func writeAssemblyOutput(writer io.Writer, name string, body []byte, upstreamTruncated bool) error {
	truncated := upstreamTruncated || len(body) > assemblyDiagnosticOutputLimit
	if len(body) > assemblyDiagnosticOutputLimit {
		body = body[:assemblyDiagnosticOutputLimit]
	}
	if _, err := fmt.Fprintf(writer, "\n%s (truncated: %t):\n", name, truncated); err != nil {
		return err
	}
	_, err := writer.Write(body)
	return err
}

// Failed assertions must not lose their diagnostic space to earlier passing tests.
// This changes private output order only; raw non-JSON diagnostics keep their prefix.
func prioritizeFailedGoTestOutput(body []byte) []byte {
	failed := make(map[string]bool)
	invalid := false
	for line := range bytes.SplitSeq(body, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		event, err := decodeTestEvent(line)
		if err != nil {
			invalid = true
			continue
		}
		if event.Action == "fail" && event.Test != "" {
			failed[event.Package+"\x00"+event.Test] = true
			if len(failed) > maximumOrdinaryTests {
				return body
			}
		}
	}
	if len(failed) == 0 {
		return body
	}
	const heading = "Failed Go test output (bounded tail):\n"
	const rawHeading = "\nRaw stdout prefix:\n"
	const tailMarker = "\nFailed test output tail truncated: true\n"
	const invalidMarker = "Non-event stdout excluded from failed-test selection: true\n"
	limit := assemblyDiagnosticOutputLimit - len(heading) - len(rawHeading) - len(tailMarker)
	if invalid {
		limit -= len(invalidMarker)
	}
	var tail []byte
	truncated := false
	for line := range bytes.SplitSeq(body, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		event, err := decodeTestEvent(line)
		if err != nil || event.Action != "output" || !failed[event.Package+"\x00"+event.Test] {
			continue
		}
		for _, part := range []string{"[" + event.Package + " " + event.Test + "] ", event.Output} {
			if len(part) >= limit {
				tail = append(tail[:0], part[len(part)-limit:]...)
				truncated = true
				continue
			}
			if excess := len(tail) + len(part) - limit; excess > 0 {
				copy(tail, tail[excess:])
				tail = tail[:len(tail)-excess]
				truncated = true
			}
			tail = append(tail, part...)
		}
	}
	if len(tail) == 0 {
		return body
	}
	result := append([]byte(heading), tail...)
	if invalid {
		result = append(result, invalidMarker...)
	}
	if truncated {
		result = append(result, tailMarker...)
	}
	result = append(result, rawHeading...)
	remaining := assemblyDiagnosticOutputLimit - len(result)
	result = append(result, body[:min(len(body), remaining)]...)
	// Preserve the generic writer's signal whenever the raw prefix was truncated.
	if len(body) > remaining {
		result = append(result, '\n')
	}
	return result
}
