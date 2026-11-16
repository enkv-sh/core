package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestRecordedExecutionPreservesHistoricalBytes(t *testing.T) {
	// These literals follow the historical struct field order. Their SHA256
	// values were derived with Python hashlib over each literal plus newline.
	for _, test := range []struct {
		name, body, hash string
	}{
		{"default", `{"requested":{},"resolved":{"lanes":4,"memory_limit_mib":24576}}`, "63dcf401a1efd913c9d324cbd48f4d2e12f9b30dadb7fe3ebb36f1ecbd66f40c"},
		{"explicit", `{"requested":{"lanes":2,"memory_limit_mib":512},"resolved":{"lanes":2,"memory_limit_mib":512}}`, "3f7f58c916272ade2758f0d6a0a65e6fd5bf3641aa4617e7fc8091aec567a042"},
		{"lanes-only", `{"requested":{"lanes":2},"resolved":{"lanes":2,"memory_limit_mib":24576}}`, "387a9d34977c90575a7a4813267d159fb6213c82e9765d49b9a6e4942a29ec34"},
		{"memory-only", `{"requested":{"memory_limit_mib":1024},"resolved":{"lanes":4,"memory_limit_mib":1024}}`, "6cca4beb41a3e96f83ef2e6f8669eccbea847219c7b3fbe01111890db8a31739"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(test.body + "\n")
			path := filepath.Join(t.TempDir(), "run.json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			var direct, canonical recordedExecutionPolicy
			if err := records.ReadJSON(path, &direct); err != nil {
				t.Fatal("direct recovery reader refused historical policy", err)
			}
			if err := decodeCleanupRecord(body, &canonical); err != nil {
				t.Fatal("canonical recovery reader refused historical policy", err)
			}
			if !reflect.DeepEqual(direct, canonical) {
				t.Fatal("recovery readers produced different policy facts")
			}
			for _, value := range []recordedExecutionPolicy{direct, canonical.clone()} {
				encoded, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				encoded = append(encoded, '\n')
				if !bytes.Equal(encoded, body) {
					t.Fatalf("historical bytes changed: got %s want %s", encoded, body)
				}
				sum := sha256.Sum256(encoded)
				if got := hex.EncodeToString(sum[:]); got != test.hash {
					t.Fatalf("historical hash changed: got %s want %s", got, test.hash)
				}
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(retained, body) {
				t.Fatal("read changed historical file bytes", err)
			}
		})
	}
}

// full_only: false
func TestRecordedExecutionConstructsCurrentPolicyAndOwnsRequestedValues(t *testing.T) {
	parallel, memory := 2, 1024
	current := executionPolicy{
		Requested: executionRequest{Parallel: &parallel, MemoryLimitMiB: &memory},
		Resolved:  executionCapacity{Parallel: 2, MemoryLimitMiB: 1024},
	}
	value := recordExecutionPolicy(current)
	parallel, memory = 4, 8192
	clone := value.clone()
	*clone.Requested.Parallel, *clone.Requested.MemoryLimitMiB = 1, 512
	const want = `{"requested":{"parallel":2,"memory_limit_mib":1024},"resolved":{"parallel":2,"memory_limit_mib":1024}}`
	body, err := json.Marshal(value)
	if err != nil || string(body) != want {
		t.Fatalf("new record policy differs: got %s want %s err=%v", body, want, err)
	}
	var decoded recordedExecutionPolicy
	if err := decodeCleanupRecord(append(body, '\n'), &decoded); err != nil {
		t.Fatal("new record did not round trip", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatal("new record lost current policy facts")
	}
	const empty = `{"requested":{},"resolved":{"parallel":4,"memory_limit_mib":8192}}`
	body, err = json.Marshal(recordExecutionPolicy(executionPolicy{Resolved: executionCapacity{Parallel: 4, MemoryLimitMiB: 8192}}))
	if err != nil || string(body) != empty {
		t.Fatalf("omitted current request differs: got %s want %s err=%v", body, empty, err)
	}
}

// full_only: false
func TestRecordedExecutionRejectsAmbiguousFields(t *testing.T) {
	for _, body := range []string{
		`null`,
		`{"requested":null,"resolved":{"lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":null}`,
		`{"requested":{"lanes":null},"resolved":{"lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{"parallel":null},"resolved":{"parallel":4,"memory_limit_mib":8192}}`,
		`{"requested":{"memory_limit_mib":null},"resolved":{"lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"lanes":null,"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"parallel":null,"memory_limit_mib":8192}}`,
		`{"requested":{},"resolved":{"lanes":4,"memory_limit_mib":null}}`,
		`{"requested":{},"requested":{},"resolved":{"lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"lanes":4,"lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{"parallel":2,"parallel":2},"resolved":{"parallel":2,"memory_limit_mib":8192}}`,
		`{"requested":{},"resolved":{"lanes":4,"memory_limit_mib":8192,"memory_limit_mib":8192}}`,
		`{"requested":{},"resolved":{"lanes":4,"parallel":4,"memory_limit_mib":8192}}`,
		`{"requested":{"lanes":2,"parallel":2},"resolved":{"parallel":2,"memory_limit_mib":8192}}`,
		`{"requested":{"parallel":2},"resolved":{"lanes":2,"memory_limit_mib":8192}}`,
		`{"requested":{"lanes":2},"resolved":{"parallel":2,"memory_limit_mib":8192}}`,
		`{"requested":{},"resolved":{"lanes":4,"memory_limit_mib":24576},"extra":true}`,
		`{"requested":{"extra":1},"resolved":{"lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"parallel":4,"memory_limit_mib":8192,"extra":1}}`,
		`{"requested":{},"resolved":{"Lanes":4,"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"lanes":"4","memory_limit_mib":24576}}`,
		`{"requested":{},"resolved":{"parallel":1.5,"memory_limit_mib":8192}}`,
	} {
		t.Run(body, func(t *testing.T) {
			var value recordedExecutionPolicy
			if err := json.Unmarshal([]byte(body), &value); err == nil {
				t.Fatal("ambiguous or malformed recorded policy was accepted")
			}
		})
	}
}

// These complete record literals were written from the historical field
// declarations, independently of a record writer. Hashes use Python hashlib
// over each literal plus newline. They exercise decoding, not recovery admission.
const historicalRunExecutionJSON = `{"supervisor":{"invocation_id":"historical","source_binding":"historical-source","path":"historical-supervisor.json"},"execution":{"requested":{},"resolved":{"lanes":4,"memory_limit_mib":24576}},"profile":"dev","coverage_scope":"","scenario_coverage":false,"schema_version":2,"run_id":"11111111111111111111111111111111","native":{"goos":"darwin","goarch":"arm64"},"suite":"live","provider":"gcp","target":"historical","started_at":"2026-10-15T00:00:00Z","finished_at":"2026-10-15T00:00:01Z","outcome":"failed","source":{"revision":"1111111111111111111111111111111111111111","dirty":false,"dirty_diff_sha256":null},"toolchain":"go1.27.0","schedule":{"recovery_mode":"disabled","selected_scenarios":[],"repetitions":1,"entries":[],"full_coverage":false},"full_coverage":false,"scenarios":[],"correctness":{"passed":false,"evidence_complete":false},"cleanup":{"outcome":"unresolved","remaining_owned_objects":null,"unknown_effects":null},"telemetry":{"enabled":false,"status":"disabled"},"diagnostics":{"enabled":false,"status":"disabled","accepted":0,"written":0,"dropped_contention":0,"dropped_full":0,"dropped_closed":0,"dropped_writer":0,"rejected":0}}`

const historicalWorkflowExecutionJSON = `{"execution":{"requested":{"lanes":2,"memory_limit_mib":512},"resolved":{"lanes":2,"memory_limit_mib":512}},"profile":"dev","schema_version":1,"run_id":"22222222222222222222222222222222","name":"historical","source":{"revision":"1111111111111111111111111111111111111111","dirty":false,"dirty_diff_sha256":null},"native":{"goos":"darwin","goarch":"arm64"},"started_at":"2026-10-15T00:00:00Z","finished_at":"2026-10-15T00:00:01Z","outcome":"failed","steps":[]}`

// full_only: false
func TestRecordedExecutionKeepsHistoricalRunAndWorkflowReaders(t *testing.T) {
	for _, test := range []struct {
		name, body, hash string
		newValue         func() any
	}{
		{"run", historicalRunExecutionJSON, "e0b16056e1fe6dd5437f99ed585124766e7dd46c40ad1292457209401ec13550", func() any { return new(runRecord) }},
		{"workflow", historicalWorkflowExecutionJSON, "59d3531e0b57f68d86aa1bf6fe8e5a0a3afaeef7dfeb28e0539d33423a10cb9f", func() any { return new(workflowResult) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := []byte(test.body + "\n")
			path := filepath.Join(t.TempDir(), test.name+".json")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			direct, canonical := test.newValue(), test.newValue()
			if err := records.ReadJSON(path, direct); err != nil {
				t.Fatal("direct record reader refused historical policy", err)
			}
			if err := decodeCleanupRecord(body, canonical); err != nil {
				t.Fatal("canonical record reader refused historical policy", err)
			}
			if !reflect.DeepEqual(direct, canonical) {
				t.Fatal("record readers produced different historical facts")
			}
			encoded, err := json.Marshal(canonical)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, '\n')
			sum := sha256.Sum256(encoded)
			if !bytes.Equal(encoded, body) || hex.EncodeToString(sum[:]) != test.hash {
				t.Fatalf("historical record bytes or hash changed: got %s", encoded)
			}
			retained, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(retained, body) {
				t.Fatal("record read changed historical bytes", err)
			}
		})
	}
}

// full_only: false
func TestNewRunStateRecordsAssignedCurrentCapacity(t *testing.T) {
	parallel, memory := 4, 24576
	for _, test := range []struct {
		name   string
		policy executionPolicy
		want   string
	}{
		{"default", executionPolicy{}, `{"requested":{},"resolved":{"parallel":4,"memory_limit_mib":8192}}`},
		{"big", executionPolicy{Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 24576}}, `{"requested":{},"resolved":{"parallel":2,"memory_limit_mib":24576}}`},
		{"assigned", executionPolicy{Requested: executionRequest{Parallel: &parallel, MemoryLimitMiB: &memory}, Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 1024}}, `{"requested":{"parallel":4,"memory_limit_mib":24576},"resolved":{"parallel":2,"memory_limit_mib":1024}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, err := newRunState(t.TempDir(), runRequest{Suite: "hermetic", execution: test.policy}, records.Source{}, "controlled toolchain")
			if err != nil {
				t.Fatal("assigned current capacity was refused", err)
			}
			t.Cleanup(func() {
				if err := state.current.remove(true); err != nil {
					t.Error(err)
				}
			})
			body, err := json.Marshal(state.record.Execution)
			if err != nil || string(body) != test.want {
				t.Fatalf("new run replaced assigned capacity: got %s want %s err=%v", body, test.want, err)
			}
		})
	}
	requestedParallel, requestedMemory := 1, 512
	for _, policy := range []executionPolicy{
		{Requested: executionRequest{Parallel: &requestedParallel}, Resolved: executionCapacity{Parallel: 2, MemoryLimitMiB: 512}},
		{Requested: executionRequest{MemoryLimitMiB: &requestedMemory}, Resolved: executionCapacity{Parallel: 1, MemoryLimitMiB: 1024}},
	} {
		state, err := newRunState(t.TempDir(), runRequest{Suite: "hermetic", execution: policy}, records.Source{}, "controlled toolchain")
		if state != nil {
			if cleanupErr := state.current.remove(true); cleanupErr != nil {
				t.Error(cleanupErr)
			}
		}
		if err == nil {
			t.Error("assigned capacity exceeded an explicit invocation request")
		}
	}
}
