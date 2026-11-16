package nativeprocess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicNativeConfigurationCommitUnknownDisposesObservation(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	cli, helper := workflowExecutables(t)
	for _, operation := range []string{"materialize-retained", "reconstruct-output"} {
		t.Run(operation, func(t *testing.T) {
			f := nativeSequenceSetup(t, cli, "aws")
			s := f.server
			_, before := workflowHead(t, s)
			objects := s.objectCount()
			target := f.source
			args := []string{"--source", f.source, "--source-format", "json"}
			if operation == "materialize-retained" {
				args = append(args, "--materialize-retained")
			} else {
				target = nativeMergePair(t, f.pair)
				args = append(args, "--reconstruct-output", target)
				restore := workflowReadOnlyPair(t, f.source, f.pair)
				defer restore()
			}
			sum := sha256.Sum256(f.value)
			child := workflowRun(t, s, helper, "authority", observer.Policy{ExpectedSHA256: map[string]string{"binary": hex.EncodeToString(sum[:])}, SuccessorKEK: s.selector(7), Fault: "local-edit-unknown", FaultOrdinal: 1}, nil, args...)
			var result struct{ PreparationStage uint8 }
			if child.code != 2 || json.Unmarshal(child.out, &result) != nil || result.PreparationStage == 0 {
				t.Fatal("real interrupted local Commit did not return preparation refusal", child.summary)
			}
			workflowPlaintext(t, child, "plaintext")
			faults, unknowns, disposed := 0, 0, 0
			for _, event := range child.capture.Events {
				switch event.Kind {
				case "local-edit-fault":
					faults++
				case "local-edit-unknown":
					unknowns++
				case "local-edit-disposed":
					disposed++
					if !event.Matched || event.Count != 4 {
						t.Error("observation disposal did not close owned handles and preserve durable images")
					}
				}
				if event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
					t.Fatal("local output interruption attempted a domain mutation")
				}
			}
			if faults != 1 || unknowns != 1 {
				t.Fatal("real generated-installed interruption did not return exactly one UnknownEdit")
			}
			if disposed != 1 {
				t.Error("Commit UnknownEdit observation was not disposed before helper return")
			}
			records, err := filepath.Glob(filepath.Join(filepath.Dir(target), ".enkv-transactions", "*.json"))
			if err != nil || len(records) != 1 {
				t.Fatal("interrupted edit did not retain exactly one durable recovery record", err)
			}
			markers, err := os.ReadDir(filepath.Join(filepath.Dir(target), ".enkv-pending"))
			if err != nil || len(markers) == 0 {
				t.Fatal("interrupted edit lost its source recovery marker", err)
			}
			if operation == "reconstruct-output" {
				workflowUnchanged(t, f.source, f.pair)
			}
			recovered := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "recover", "--source", target, "--source-format", "json", "--json")
			var delivery struct {
				Schema  string
				Outcome string
				Local   struct{ Outcome string } `json:"local_delivery"`
			}
			if recovered.code != 0 || json.Unmarshal(recovered.out, &delivery) != nil || delivery.Schema != "LocalEditResult/v1" || delivery.Outcome != "edited" || delivery.Local.Outcome != "recorded" {
				t.Fatal("saved local candidate could not recover after observation disposal", recovered.summary)
			}
			for _, event := range recovered.capture.Events {
				if event.Kind != "footer" {
					t.Fatal("local recovery acquired a provider capability")
				}
			}
			compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", target, "--trusted-format", "json", "--json")
			if workflowResult(t, compared, "success").Payload.Verdict != "match" {
				t.Fatal("recovered exact candidate does not describe the selected state")
			}
			workflowGETOnly(t, compared)
			_, after := workflowHead(t, s)
			if !reflect.DeepEqual(before, after) || s.objectCount() != objects {
				t.Fatal("local interruption and recovery changed the selected domain")
			}
			if operation == "reconstruct-output" {
				workflowUnchanged(t, f.source, f.pair)
			}
			s.clean(t)
		})
	}
}
