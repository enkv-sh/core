package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func rootChannelFixture(t *testing.T) (*rootChannel, *rootChannel) {
	t.Helper()
	native, ends, err := newRootChannels()
	if err != nil {
		t.Fatal(err)
	}
	runner := makeRootChannel(ends[0], ends[1])
	t.Cleanup(func() {
		if err := errors.Join(native.close(), runner.close()); err != nil {
			t.Error(err)
		}
	})
	return native, runner
}

// full_only: false
func TestRootChannelSupportsRepeatedResourcePhases(t *testing.T) {
	native, runner := rootChannelFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	type outcome struct {
		terminal rootTerminal
		requests []rootAdmission
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		var requests []rootAdmission
		terminal, err := serveRootChannel(ctx, native, func(_ context.Context, request rootAdmission) (executionPolicy, error) {
			requests = append(requests, request)
			return request.Execution, nil
		})
		done <- outcome{terminal, requests, err}
	}()
	returned := false
	defer func() {
		cancel()
		if !returned {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("resource phase channel did not join")
			}
		}
	}()
	for _, big := range []bool{false, true, false} {
		request := rootAdmission{Big: big, Execution: executionForClass(defaultExecutionPolicy(), big)}
		policy, err := runner.admit(ctx, request)
		if err != nil || !sameExecutionPolicy(policy, request.Execution) {
			t.Fatal("resource phase was not admitted", big, err)
		}
	}
	success, joined := true, true
	if err := runner.write(rootMessage{Operation: "terminal", Success: &success, Joined: &joined}); err != nil {
		t.Fatal(err)
	}
	if err := runner.close(); err != nil {
		t.Fatal(err)
	}
	got := <-done
	returned = true
	if got.err != nil || !got.terminal.Admitted || !got.terminal.Success || !got.terminal.Joined || len(got.requests) != 3 {
		t.Fatal("resource phases lost their terminal result", got)
	}
	for index, request := range got.requests {
		if request.Big != (index == 1) {
			t.Fatal("resource phase order changed", got.requests)
		}
	}
}

// full_only: false
func TestRootChannelRequiresOneAdmissionAndTerminal(t *testing.T) {
	for _, mode := range []string{"passed", "preparation_failed", "admission_refused", "success_before_ready", "missing_terminal_after_phase", "missing_terminal", "trailing", "unjoined"} {
		t.Run(mode, func(t *testing.T) {
			native, runner := rootChannelFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			type outcome struct {
				terminal rootTerminal
				err      error
			}
			done := make(chan outcome, 1)
			admissions := 0
			go func() {
				terminal, err := serveRootChannel(ctx, native, func(_ context.Context, r rootAdmission) (executionPolicy, error) {
					admissions++
					if mode == "admission_refused" {
						return executionPolicy{}, errors.New("fixture refusal")
					}
					return r.Execution, nil
				})
				done <- outcome{terminal, err}
			}()
			success, joined := true, true
			if mode == "preparation_failed" || mode == "unjoined" {
				success = false
			}
			if mode == "unjoined" {
				joined = false
			}
			request := rootAdmission{Execution: defaultExecutionPolicy()}
			if mode != "preparation_failed" && mode != "success_before_ready" {
				_, err := runner.admit(ctx, request)
				if (err != nil) != (mode == "admission_refused") {
					t.Fatal("admission outcome differs", err)
				}
			}
			switch mode {
			case "missing_terminal_after_phase":
				if _, err := runner.admit(ctx, request); err != nil {
					t.Fatal(err)
				}
			case "admission_refused", "missing_terminal":
			default:
				if err := runner.write(rootMessage{Operation: "terminal", Success: &success, Joined: &joined}); err != nil {
					t.Fatal(err)
				}
				if mode == "trailing" {
					if err := runner.write(rootMessage{Operation: "refused"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := runner.close(); err != nil {
				t.Fatal(err)
			}
			got := <-done
			valid := mode == "passed" || mode == "preparation_failed" || mode == "unjoined"
			if (got.err == nil) != valid || ctx.Err() != nil {
				t.Fatal("terminal protocol differs", got, ctx.Err())
			}
			wantAdmissions := 1
			if mode == "preparation_failed" || mode == "success_before_ready" {
				wantAdmissions = 0
			}
			if mode == "missing_terminal_after_phase" {
				wantAdmissions = 2
			}
			if admissions != wantAdmissions {
				t.Fatal("admission count differs", admissions)
			}
			if valid && (got.terminal.Success != success || got.terminal.Joined != joined) {
				t.Fatal("terminal facts differ", got.terminal)
			}
		})
	}
}

// full_only: false
func TestRootChannelRejectsNoncanonicalAndUnboundedFrames(t *testing.T) {
	valid := `{"operation":"phase","admission":{"big":false,"live":false,"execution":{"requested":{},"resolved":{"parallel":4,"memory_limit_mib":8192}},"cleanup_seconds":0}}`
	if _, err := decodeRootMessage([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		strings.Replace(valid, `"operation":"phase"`, `"operation":"ready"`, 1),
		`{"operation":"terminal","success":true,"joined":false}`,
		`{"operation":"terminal","success":false}`,
		`{"operation":"terminal","success":null,"joined":true}`,
		`{"operation":"terminal","success":false,"success":true,"joined":true}`,
		`{"Operation":"refused"}`,
		`{"operation":"refused","extra":false}`,
		strings.Replace(valid, `"live":false,`, "", 1),
		strings.Replace(valid, `"cleanup_seconds":0`, `"cleanup_seconds":1`, 1),
		strings.Replace(valid, `"requested":{}`, `"requested":null`, 1),
		strings.Replace(valid, `"parallel":4`, `"lanes":4`, 1),
		valid + `{}`,
	} {
		if body == valid {
			t.Fatal("invalid frame fixture did not change input")
		}
		if _, err := decodeRootMessage([]byte(body)); err == nil {
			t.Fatal("invalid frame accepted", body)
		}
	}
	for _, body := range []string{strings.Repeat("x", rootMessageLimit) + "\n", `{"operation":"refused"}`} {
		native, runner := rootChannelFixture(t)
		done := make(chan error, 1)
		go func() { _, err := runner.writeFile.Write([]byte(body)); done <- err; _ = runner.close() }()
		if _, err := native.read(); err == nil || err == io.EOF {
			t.Fatal("unbounded or incomplete frame accepted", err)
		}
		_ = native.close()
		<-done
	}
	// Both explicit false fields are required and remain distinct from omission.
	no, yes := false, true
	body, err := json.Marshal(rootMessage{Operation: "terminal", Success: &no, Joined: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRootMessage(body); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestRootChannelCancellationJoinsBlockedReadAndAdmission(t *testing.T) {
	t.Run("inherited runner waiting for admission", func(t *testing.T) {
		var reply, request [2]int
		if err := syscall.Pipe(reply[:]); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Pipe(request[:]); err != nil {
			t.Fatal(errors.Join(err, syscall.Close(reply[0]), syscall.Close(reply[1])))
		}
		native := makeRootChannel(os.NewFile(uintptr(request[0]), "test-request"), os.NewFile(uintptr(reply[1]), "test-reply"))
		runner, err := inheritedRootChannel(reply[0], request[1])
		if err != nil {
			t.Fatal(errors.Join(err, native.close()))
		}
		t.Cleanup(func() {
			if err := errors.Join(native.close(), runner.close()); err != nil {
				t.Error(err)
			}
		})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := runner.admit(ctx, rootAdmission{Execution: defaultExecutionPolicy()})
			done <- err
		}()
		if msg, err := native.read(); err != nil || msg.Operation != "phase" {
			t.Fatal("runner did not request admission", err)
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled inherited admission passed")
			}
		case <-time.After(3 * time.Second):
			// Release the peer before joining even if the regression returns.
			_ = native.close()
			<-done
			t.Fatal("canceled inherited admission did not join")
		}
	})
	for _, mode := range []string{"read", "admission"} {
		t.Run(mode, func(t *testing.T) {
			native, runner := rootChannelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			entered := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				_, err := serveRootChannel(ctx, native, func(ctx context.Context, _ rootAdmission) (executionPolicy, error) {
					close(entered)
					<-ctx.Done()
					return executionPolicy{}, ctx.Err()
				})
				done <- err
			}()
			if mode == "admission" {
				request := rootAdmission{Execution: defaultExecutionPolicy()}
				if err := runner.write(rootMessage{Operation: "phase", Admission: &request}); err != nil {
					t.Fatal(err)
				}
				<-entered
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancellation passed")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled channel did not join")
			}
		})
	}
}
