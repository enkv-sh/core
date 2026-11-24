//go:build darwin || linux

package nativeprocess

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	observer "enkv.sh/core/testsupport/nativeprocess"
)

type nativePlanCostEvent struct {
	Kind            string `json:"kind"`
	PID             int    `json:"pid,omitempty"`
	Bytes           int64  `json:"bytes,omitempty"`
	Nanoseconds     int64  `json:"nanoseconds,omitempty"`
	Complete        bool   `json:"complete"`
	AllocatedBytes  uint64 `json:"allocated_bytes,omitempty"`
	Allocations     uint64 `json:"allocations,omitempty"`
	DeadlineExpired bool   `json:"deadline_expired,omitempty"`
}

type nativePlanMeasuredFacts struct {
	Started, Joined, Pending, Copies, SourceChecks   int
	StagedBytes, SourceNanoseconds, ChildNanoseconds int64
	EventOffset, EventBytes                          int64
	Plans                                            []nativePlanCostEvent
}

func nativePlanCostEvidence(t *testing.T) (string, func(string, any) error) {
	t.Helper()
	directory := os.Getenv("ENKV_PERFORMANCE_EVIDENCE_DIRECTORY")
	retained := directory != ""
	if !retained {
		directory = t.TempDir()
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal("private performance evidence directory permissions", err)
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !filepath.IsAbs(directory) || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("performance evidence requires an absolute private directory", err)
	}
	file, err := os.OpenFile(filepath.Join(directory, "native-plan-capacity.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("performance evidence file", err)
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("performance evidence file is not private", errors.Join(err, file.Close()))
	}
	written := 0
	appendRecord := func(kind string, value any) error {
		body, err := json.Marshal(struct {
			Kind string `json:"kind"`
			Data any    `json:"data"`
		}{kind, value})
		if err != nil {
			return err
		}
		body = append(body, '\n')
		if len(body) > (1<<20)-written {
			return errors.New("performance evidence exceeds its bound")
		}
		n, writeErr := file.Write(body)
		written += n
		if n != len(body) && writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return errors.Join(writeErr, file.Sync())
	}
	if err := appendRecord("capture_ready", map[string]any{"schema_version": 1, "test": t.Name(), "retained": retained,
		"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version()}); err != nil {
		t.Fatal("performance evidence header", errors.Join(err, file.Close()))
	}
	t.Cleanup(func() {
		footerErr := appendRecord("capture_complete", map[string]bool{"failed": t.Failed()})
		if err := errors.Join(footerErr, file.Close()); err != nil {
			t.Error("performance evidence completion", err)
		}
	})
	return directory, appendRecord
}

func nativePlanCostCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &usage); err != nil {
		t.Fatal("native plan process CPU measurement", err)
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second +
		time.Duration(int64(usage.Utime.Usec)+int64(usage.Stime.Usec))*time.Microsecond
}

func nativePlanCostExecutable(t *testing.T, binaries nativeOutputExecutables, ledger string) string {
	t.Helper()
	root, private := nativeRepository(t), filepath.Dir(binaries.cli)
	overlay := filepath.Join(private, "overlay", "overlay.json")
	manifest := filepath.Join(private, "overlay", "sources.json")
	var mapping struct{ Replace map[string]string }
	var sources []observer.Source
	nativeGeneratedReadJSON(t, overlay, &mapping)
	nativeGeneratedReadJSON(t, manifest, &sources)
	add := func(relative, anchor, replacement, suffix string) {
		t.Helper()
		target := nativeGeneratedSourcePath(root, relative)
		original, err := os.ReadFile(target)
		selected := original
		if previous, ok := mapping.Replace[target]; ok {
			selected, err = os.ReadFile(previous)
		}
		if err != nil || strings.Count(string(selected), anchor) != 1 {
			t.Fatal("native plan observation anchor differs", relative)
		}
		body := []byte(strings.Replace(string(selected), anchor, replacement, 1) + suffix)
		path := filepath.Join(private, "overlay", "plan_"+strings.ReplaceAll(relative, "/", "_"))
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		mapping.Replace[target] = path
		found := false
		for i := range sources {
			if sources[i].Target == target {
				sources[i].Replacement, sources[i].ReplacementSHA256 = path, workflowDigest(body)
				found = true
			}
		}
		if !found {
			sources = append(sources, observer.Source{Target: target, OriginalSHA256: workflowDigest(original), Replacement: path, ReplacementSHA256: workflowDigest(body)})
		}
	}
	path := strconv.Quote(ledger)
	hostRecord := `
func nativePlanCostRecord(kind string, pid int, size int64, complete bool) (resultErr error) {
 file, err := os.OpenFile(` + path + `, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
 if err != nil { return err }
 defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
 _, err = fmt.Fprintf(file, "{\"kind\":%q,\"pid\":%d,\"bytes\":%d,\"nanoseconds\":%d,\"complete\":%t}\n", kind, pid, size, time.Now().UnixNano(), complete)
 return err
}
`
	add("compositions/outputhost/host.go", "package outputhost", "package outputhost", hostRecord)
	add("compositions/internal/nativeprocess/process_unix.go", "import (", "import (\n \"fmt\"\n \"time\"", hostRecord)
	wait := "func (child *Child) Wait() error {"
	add("compositions/internal/nativeprocess/process_unix.go", wait, `func (child *Child) Wait() (resultErr error) {
 defer func() {
  resultErr = errors.Join(resultErr, nativePlanCostRecord("wait", child.Process.Pid, 0, child.ProcessState != nil))
 }()`, "")
	started := "child = &Child{Process: process}"
	add("compositions/internal/nativeprocess/process_unix.go", started, started+`
  resultErr = errors.Join(resultErr, nativePlanCostRecord("start", process.Pid, 0, true))`, "")
	copy := "written, copyErr := io.Copy(io.MultiWriter(copyFile, hash), io.LimitReader(artifactFileReader{ctx, source.file}, int64(length)+1))"
	add("compositions/outputhost/files.go", copy, copy+`
 if recordErr := nativePlanCostRecord("copy", 0, written, copyErr == nil); recordErr != nil {
  return stage, nil, recordErr
 }`, "")
	add("compositions/configuration/source_unchanged.go", "import (", "import (\n \"fmt\"\n \"time\"", "")
	check := "func (p *Pair) CheckUnchanged(ctx context.Context) (resultErr error) {"
	add("compositions/configuration/source_unchanged.go", check, check+`
 started := time.Now()
 defer func() { resultErr = errors.Join(resultErr, nativePlanSourceCostRecord(time.Since(started), resultErr == nil)) }()`, `
func nativePlanSourceCostRecord(elapsed time.Duration, complete bool) (resultErr error) {
 file, err := os.OpenFile(`+path+`, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
 if err != nil { return err }
 defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
 _, err = fmt.Fprintf(file, "{\"kind\":\"source-check\",\"nanoseconds\":%d,\"complete\":%t}\n", elapsed.Nanoseconds(), complete)
 return err
}
`)
	add("compositions/full/cmd/enkv/plan.go", "import (", "import (\n \"encoding/json\"\n \"runtime\"", "")
	plan := "func runPlanContext(ctx context.Context, args []string, out, diagnostic io.Writer) (code int) {"
	add("compositions/full/cmd/enkv/plan.go", plan, `func runPlanContext(ctx context.Context, args []string, out, diagnostic io.Writer) (code int) {
 finishCost := nativePlanCommandCost(ctx)
 defer func() {
  if err := finishCost(); err != nil { code = commandDiagnosticExit(diagnostic, "plan measurement failed", 2) }
 }()`, `
func nativePlanCommandCost(ctx context.Context) func() error {
 var before runtime.MemStats
 runtime.ReadMemStats(&before)
 started := time.Now()
 return func() error {
  var after runtime.MemStats
  runtime.ReadMemStats(&after)
  file, err := os.OpenFile(`+path+`, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
  if err != nil { return err }
  facts := struct {
   Kind string `+"`json:\"kind\"`"+`
   Nanoseconds int64 `+"`json:\"nanoseconds\"`"+`
   Complete bool `+"`json:\"complete\"`"+`
   AllocatedBytes uint64 `+"`json:\"allocated_bytes\"`"+`
   Allocations uint64 `+"`json:\"allocations\"`"+`
   DeadlineExpired bool `+"`json:\"deadline_expired\"`"+`
  }{"plan", time.Since(started).Nanoseconds(), true, after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs, ctx.Err() != nil}
  return errors.Join(json.NewEncoder(file).Encode(facts), file.Close())
 }
}
`)
	slices.SortFunc(sources, func(a, b observer.Source) int { return strings.Compare(a.Target, b.Target) })
	nativeGeneratedWriteJSON(t, overlay, mapping)
	nativeGeneratedWriteJSON(t, manifest, sources)
	cli := filepath.Join(private, "enkv-plan-cost")
	args := nativeGoArguments("build", "-mod=readonly", "-tags=netgo", "-trimpath", "-buildvcs=false", "-overlay="+overlay, "-ldflags="+nativePluginLinkerFlags(), "-o", cli, "./cmd/enkv")
	nativeGeneratedGo(t, root, "compositions/full", args...)
	nativeRequireRaceMode(t, cli)
	t.Logf("native plan observation overlay=%s source_manifest=%s", overlay, manifest)
	return cli
}

func nativePlanCostFacts(t *testing.T, path string, offset int64) (facts nativePlanMeasuredFacts) {
	t.Helper()
	facts.EventOffset = offset
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Error("native plan cost facts unavailable", err)
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error("native plan cost facts close", err)
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || offset < 0 || offset > info.Size() {
		t.Error("native plan cost facts range invalid", err)
		return
	}
	facts.EventBytes = info.Size() - offset
	if err := file.Sync(); err != nil {
		t.Error("native plan cost facts sync", err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(io.NewSectionReader(file, offset, facts.EventBytes), (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		t.Error("native plan cost facts unavailable or oversized", err)
		return
	}
	active := map[int]int64{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		var event nativePlanCostEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Error("native plan cost fact invalid", err)
			break
		}
		switch event.Kind {
		case "start":
			if event.PID <= 0 || active[event.PID] != 0 || !event.Complete || event.Nanoseconds <= 0 {
				t.Error("native plan child start has no unique process")
			}
			active[event.PID] = event.Nanoseconds
			facts.Started++
		case "wait":
			if active[event.PID] == 0 || !event.Complete || event.Nanoseconds < active[event.PID] {
				t.Error("native plan child Wait lacks positive process settlement")
			}
			facts.ChildNanoseconds += event.Nanoseconds - active[event.PID]
			delete(active, event.PID)
			facts.Joined++
		case "copy":
			if event.Bytes < 0 {
				t.Error("negative staged-byte observation")
			}
			facts.Copies++
			facts.StagedBytes += event.Bytes
		case "source-check":
			facts.SourceChecks++
			facts.SourceNanoseconds += event.Nanoseconds
		case "plan":
			facts.Plans = append(facts.Plans, event)
		default:
			t.Error("unknown native plan cost fact")
		}
	}
	facts.Pending = len(active)
	return
}

// full_only: true
func TestPublicNativePlanMaximumOutputCost(t *testing.T) {
	directory, capture := nativePlanCostEvidence(t)
	output := newNativePublicationServer(t)
	binaries := buildNativeOutputExecutables(t, output.server.URL)
	ledger := filepath.Join(directory, "native-plan-events.jsonl")
	file, err := os.OpenFile(ledger, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("native plan event ledger", err)
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("native plan event ledger is not private", errors.Join(statErr, file.Close()))
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		t.Fatal("native plan event ledger creation", err)
	}
	cli := nativePlanCostExecutable(t, binaries, ledger)
	var pluginBytes uint64
	for _, facts := range binaries.artifacts {
		if facts.Descriptor.Name == "aws-secrets-manager" {
			pluginBytes = facts.ArtifactLength
		}
	}
	if pluginBytes == 0 {
		t.Fatal("selected output executable length absent")
	}
	for sample := 1; sample <= 2; sample++ {
		t.Run(fmt.Sprintf("sample-%d", sample), func(t *testing.T) {
			s := newWorkflowServer(t, "aws", false)
			s.childLimit, s.requestLimit = 2, 2*workflowChildRequestLimit
			s.childTimeout = 330 * time.Second
			source := filepath.Join(t.TempDir(), "configuration.json")
			if err := os.WriteFile(source, workflowSetup(t, s, false), 0600); err != nil {
				t.Fatal(err)
			}
			initialized := workflowRunEnvironment(t, s, cli, "init", observer.Policy{}, nil, binaries.Environment(t, source), "init", "--source", source, "--source-format", "json", "--json")
			workflowResult(t, initialized, "success")
			pair := workflowReadPair(t, source)
			candidate := nativeMergePair(t, pair)
			entries := map[string]any{}
			destinations := map[string]any{}
			for i := 0; i < 64; i++ {
				name := fmt.Sprintf("destination-%02d", i)
				destinations[name] = map[string]any{"plugin": "aws-secrets-manager", "settings": map[string]any{"account": fmt.Sprintf("%012d", 123456789000+i), "region": "us-east-1"}}
			}
			routes := map[string]any{}
			for i := 0; i < 128; i++ {
				name := fmt.Sprintf("VALUE_%03d", i)
				entries[name] = map[string]any{"confidentiality": "plain", "recipients": []string{}, "source": map[string]any{"kind": "supplied", "value": "public plan cost input"}}
				selected := make([]string, 8)
				for j := range selected {
					selected[j] = fmt.Sprintf("destination-%02d", i/16*8+j)
				}
				routes[name] = selected
			}
			nativePublicationSource(t, candidate, func(value map[string]any) {
				value["entries"] = entries
				value["outputs"] = map[string]any{"destinations": destinations, "routing": map[string]any{"entries": routes}}
			})
			candidatePair := workflowReadPair(t, candidate)
			before, _ := workflowHead(t, s)
			objects, effects := s.objectCount(), output.effectCount()
			ledgerInfo, err := os.Stat(ledger)
			if err != nil {
				t.Fatal("native plan event ledger offset", err)
			}
			offset := ledgerInfo.Size()
			if err := os.WriteFile(binaries.ledger, nil, 0600); err != nil {
				t.Fatal(err)
			}
			cpu, started := nativePlanCostCPU(t), time.Now()
			var child workflowChild
			var wall, usedCPU time.Duration
			returned := false
			t.Cleanup(func() {
				if !returned {
					wall, usedCPU = time.Since(started), nativePlanCostCPU(t)-cpu
				}
				cost := struct {
					Sample                                       int
					WallNanoseconds, CPUNanoseconds, EventOffset int64
					Returned                                     bool
				}{sample, wall.Nanoseconds(), usedCPU.Nanoseconds(), offset, returned}
				if err := capture("native_plan_sample", cost); err != nil {
					t.Error("performance plan cost capture", err)
				}
				facts := nativePlanCostFacts(t, ledger, offset)
				_, passive, dispatches := nativeOutputLedger(t, binaries)
				measurement := struct {
					Sample, Entries, Bindings, Targets, Passive, Dispatches int
					WallNanoseconds, CPUNanoseconds                         int64
					PluginBytes                                             uint64
					ProductDeadlineSeconds, OuterJoinHorizonSeconds         int
					Returned                                                bool
					Facts                                                   nativePlanMeasuredFacts
				}{Sample: sample, Entries: 128, Bindings: 64, Targets: 1024, Passive: passive, Dispatches: dispatches,
					WallNanoseconds: wall.Nanoseconds(), CPUNanoseconds: usedCPU.Nanoseconds(), PluginBytes: pluginBytes,
					ProductDeadlineSeconds: 300, OuterJoinHorizonSeconds: 330, Returned: returned, Facts: facts}
				body, err := json.Marshal(measurement)
				if err != nil {
					t.Error(err)
				} else {
					t.Logf("native_plan_measurement=%s", body)
				}
				if err := capture("native_plan_measurement", measurement); err != nil {
					t.Error("performance plan sample capture", err)
				}
				if facts.Started != facts.Joined || facts.Pending != 0 || dispatches != 0 {
					t.Error("native plan did not join every started passive child or entered private dispatch", facts.Started, facts.Joined, facts.Pending, dispatches)
				}
				if returned && child.code == 1 && (passive != 1088 || facts.Started != 1088 || len(facts.Plans) != 1 || facts.Plans[0].DeadlineExpired) {
					t.Error("complete maximum plan changed its fixed semantic calls or lifetime", passive, facts.Started, facts.Plans)
				}
			})
			child = workflowRunEnvironment(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, binaries.Environment(t, source), "plan", "--trusted", source, "--trusted-format", "json", "--candidate", candidate, "--candidate-format", "json", "--json")
			wall, usedCPU = time.Since(started), nativePlanCostCPU(t)-cpu
			returned = true
			var result workflowOutput
			decoded := json.Unmarshal(child.out, &result) == nil
			var publicFacts nativePlanningOutput
			changesDecoded := json.Unmarshal(child.out, &publicFacts) == nil
			completeChanges := changesDecoded && len(publicFacts.Payload.Changes) == 128*8+64*3+1024*12+128*2
			fields := map[string][]string{
				"entry":          {"class", "input_encoding", "memberships", "name", "output_encoding", "plain_value", "presence", "source"},
				"output_binding": {"destination", "presence", "targets"},
				"output_target":  {"capabilities", "canonical_target", "consumer_locator", "consumer_policy", "create_value_bounds", "locator_requires_creation", "payload_encoding", "presence", "service_contract", "target_contract", "target_data", "write_value_bounds"},
				"routing_rule":   {"destinations", "presence"},
			}
			seen := make(map[string]bool, len(publicFacts.Payload.Changes))
			counts := make(map[string]int)
			for _, change := range publicFacts.Payload.Changes {
				kind := change.Subject.Kind
				if len(change.Path) != 1 || !slices.Contains(fields[kind], change.Path[0].Field) || change.Action != "added" || change.Before.State != "absent" || len(change.Before.Value) != 0 || change.After.State != "present" || len(change.After.Value) == 0 {
					completeChanges = false
					continue
				}
				name, destination := change.Subject.Name, change.Subject.Destination
				switch kind {
				case "entry":
					if entries[name] == nil || destination != "" {
						completeChanges = false
					}
				case "output_binding":
					if destinations[destination] == nil || name != "" {
						completeChanges = false
					}
				case "output_target":
					selected, ok := routes[name].([]string)
					if !ok || !slices.Contains(selected, destination) {
						completeChanges = false
					}
				case "routing_rule":
					if change.Subject.Entry.Kind != "entry" || entries[change.Subject.Entry.Name] == nil {
						completeChanges = false
					}
				}
				key := kind + "/" + destination + "/" + name + "/" + change.Subject.Entry.Name + "/" + change.Path[0].Field
				if seen[key] {
					completeChanges = false
				}
				seen[key] = true
				counts[kind]++
				if kind == "entry" && change.Path[0].Field == "plain_value" {
					var value struct {
						Base64 string
						Length int `json:"byte_length"`
					}
					if change.After.Type != "bytes" || json.Unmarshal(change.After.Value, &value) != nil || value.Base64 != "cHVibGljIHBsYW4gY29zdCBpbnB1dA==" || value.Length != 22 {
						completeChanges = false
					}
				}
				if kind == "routing_rule" && change.Path[0].Field == "destinations" {
					var value []string
					if change.After.Type != "text-set" || json.Unmarshal(change.After.Value, &value) != nil || !reflect.DeepEqual(value, routes[change.Subject.Entry.Name]) {
						completeChanges = false
					}
				}
			}
			completeChanges = completeChanges && counts["entry"] == 128*8 && counts["output_binding"] == 64*3 && counts["output_target"] == 1024*12 && counts["routing_rule"] == 128*2
			if !completeChanges {
				t.Error("maximum plan lost complete owned fields", len(publicFacts.Payload.Changes), counts)
			}

			semantic := struct {
				Sample, ExitCode, DiagnosticBytes                                    int
				JSONDecoded, SchemaValid, StateSuccess, VerdictMismatch              bool
				DiagnosticsComplete, DiagnosticDeliveryIncomplete, ResultWriteFailed bool
			}{Sample: sample, ExitCode: child.code, DiagnosticBytes: len(child.diagnostic),
				JSONDecoded: decoded, SchemaValid: result.Schema == "ProductResult/v1",
				StateSuccess: result.State == "success", VerdictMismatch: result.Payload.Verdict == "mismatch",
				DiagnosticsComplete:          result.Payload.DiagnosticsComplete,
				DiagnosticDeliveryIncomplete: bytes.Contains(child.diagnostic, []byte("diagnostic delivery incomplete; retain the result on stdout\n")),
				ResultWriteFailed:            bytes.Contains(child.diagnostic, []byte("plan output failed\n"))}
			if err := capture("native_plan_result", semantic); err != nil {
				t.Error("performance plan result capture", err)
			}
			if child.code != 1 || len(child.diagnostic) != 0 || !decoded || !semantic.SchemaValid || !semantic.StateSuccess || !semantic.VerdictMismatch || !semantic.DiagnosticsComplete {
				t.Error("maximum plan did not complete the exact public mismatch", child.code)
			}
			workflowGETOnly(t, child)
			workflowUnchanged(t, source, pair)
			workflowUnchanged(t, candidate, candidatePair)
			after, _ := workflowHead(t, s)
			if !reflect.DeepEqual(before, after) || s.objectCount() != objects || output.effectCount() != effects {
				t.Error("maximum plan changed stored state or provider effects")
			}
			t.Logf("native_plan_tuple=%s/%s go=%s", runtime.GOOS, runtime.GOARCH, runtime.Version())
		})
	}
}
