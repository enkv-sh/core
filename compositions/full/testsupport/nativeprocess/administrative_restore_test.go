package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestAdministrativeAuthorityReplacementUsesInstalledAWSGCPCLI(t *testing.T) {
	cli, _ := workflowExecutables(t)
	for _, family := range []string{"aws", "gcp"} {
		for _, enabled := range []bool{false, true} {
			faults := []string{""}
			if enabled {
				faults = append(faults, "lose-head-reply", "lose-head-reply-and-observation")
			}
			for _, fault := range faults {
				t.Run(fmt.Sprintf("%s/recovery-%t/%s", family, enabled, fault), func(t *testing.T) {
					s := newWorkflowServer(t, family, enabled)
					source := filepath.Join(t.TempDir(), "configuration.json")
					if err := os.WriteFile(source, workflowSetup(t, s, enabled), 0600); err != nil {
						t.Fatal(err)
					}
					workflowResult(t, workflowRun(t, s, cli, "init", observer.Policy{}, nil, "init", "--source", source, "--source-format", "json", "--json"), "success")
					pair := workflowReadPair(t, source)
					d := pair.descriptor
					before, beforeObject := workflowHead(t, s)
					beforeRoot := workflowRoot(t, s, before)
					objects := s.objectCount()
					dir := administrativeReplacementDirectory(t)
					output := filepath.Join(dir, "successor.json")
					args := []string{"keys", "replace", "--source", source, "--source-format", "json", "--target", "authority", "--authorizer", "recovery", "--signing", s.selector(6), "--out", output, "--json"}
					child := workflowRun(t, s, cli, "successor", observer.Policy{Fault: fault, FaultOrdinal: 1}, nil, args...)
					type replyRecord struct {
						Schema        string
						OperationKind string `json:"operation_kind"`
						OperationID   string `json:"operation_id"`
						DomainID      string `json:"domain_id"`
						State         string `json:"state_result"`
						Payload       string `json:"operation_payload"`
						Receipt       string `json:"receipt_hex"`
						Replay        string `json:"replay_identity"`
						Observed      string `json:"observed_revision_id"`
						Snapshot      string `json:"observed_snapshot_id"`
						Query         *struct {
							Observation *struct {
								Domain   string `json:"domain_id"`
								Revision string `json:"head_revision_id"`
								Snapshot string `json:"snapshot_id"`
							} `json:"observation"`
						} `json:"query"`
					}
					var reply replyRecord
					decodeErr := json.Unmarshal(child.out, &reply)
					if decodeErr != nil || reply.Schema != "ProductResult/v1" || reply.OperationKind != "keys-replace-authority" || reply.Receipt != "" {
						t.Fatalf("replacement lost its closed receipt-free Authority result: exit=%d decoded=%t schema=%t kind=%t receipt_empty=%t", child.code, decodeErr == nil, reply.Schema == "ProductResult/v1", reply.OperationKind == "keys-replace-authority", reply.Receipt == "")
					}
					if !administrativeReplacementDiagnostics(child.diagnostic, family, enabled, fault) {
						t.Fatalf("replacement diagnostic output has unexpected console content: exit=%d bytes=%d warn_markers=%d error_markers=%d", child.code, len(child.diagnostic), bytes.Count(child.diagnostic, []byte(" WARN (13) ")), bytes.Count(child.diagnostic, []byte(" ERROR (17) ")))
					}
					workflowUnchanged(t, source, pair)
					if !enabled {
						nativeReplacementNoConstruction(t, child)
						_, afterObject := workflowHead(t, s)
						if child.code != 2 || reply.State != "refused" || reply.Payload != "none" || s.objectCount() != objects || !reflect.DeepEqual(beforeObject, afterObject) {
							t.Fatal("disabled Recovery changed selected state or lost typed refusal", reply.State)
						}
						for _, event := range child.capture.Events {
							if event.Kind == "http-start" && event.Operation != "head-read" && event.Operation != "store-read" {
								t.Fatal("disabled Recovery reached public successor or private construction effects")
							}
						}
						if _, err := os.Lstat(output); !os.IsNotExist(err) {
							t.Fatal("disabled Recovery delivered an output", err)
						}
						return
					}
					state := "success"
					if fault == "lose-head-reply-and-observation" {
						state = "commit-outcome-unknown"
					}
					if reply.State != state || state == "success" && child.code != 0 || state != "success" && child.code == 0 || reply.DomainID != hex.EncodeToString(d.DomainID[:]) || len(reply.OperationID) != 64 {
						t.Fatal("replacement lost actual selection disposition", child.code, reply.State)
					}
					if fault != "" {
						// The local observer hides the provider-validated acknowledgment;
						// the second fault also blocks later HEAD reads. This does not
						// establish physical cloud response loss.
						workflowOneHeadAttempt(t, child, true, 200)
						if fault == "lose-head-reply" {
							workflowPostWriteHeadObservation(t, child)
						}
					}
					after, afterObject := workflowHead(t, s)
					counts := s.snapshot("successor")
					if counts.headUpdates != 1 || counts.headCreates != 0 || counts.conditions != 0 || counts.calls["Sign/normal"] != 0 || counts.calls["Sign/recovery-signing"] == 0 || counts.calls["Sign/successor"] == 0 || counts.calls["Decrypt/authority"] != 0 || counts.calls["Decrypt/recovery-private"] != 0 {
						t.Fatal("signing-only replacement constructed another private route or repeated selection", counts)
					}
					seen := map[string]int{}
					for _, event := range child.capture.Events {
						if event.Kind != "http-start" {
							continue
						}
						switch event.Operation {
						case "head-read", "store-read", "store-write", "head-write", "kms-public", "kms-sign":
						default:
							t.Fatal("signing-only replacement attempted another provider operation")
						}
						if event.Operation == "kms-sign" {
							if event.Role != "recovery-signing" && event.Role != "successor" {
								t.Fatal("lost Normal private signing route was used")
							}
							if event.Sent {
								seen[event.Role]++
							}
						}
					}
					if seen["recovery-signing"] == 0 || seen["successor"] == 0 || after.AuthKind != stateformat.SuccessionAuth || after.Succession == nil || reply.OperationID != hex.EncodeToString(after.Succession.Subject.OperationID[:]) || after.Succession.Subject.ApprovalRole != contract.RecoverySigningRole || after.Succession.Subject.ChangeMask != contract.SuccessionChangeNormalSigner || after.Core.PreviousRevision != before.Core.Revision || after.Core.PreviousDigest != contract.ID(sha256.Sum256(beforeObject.body)) || after.Core.PreviousToken != (contract.Token{Family: d.Provider, Value: beforeObject.etag}) {
						t.Fatal("replacement lost exact predecessor or current Recovery authorization")
					}
					editable, generated, reference, basis := workflowSuccessorPair(t, output)
					control, err := contract.DecodeControlCore(basis.Control)
					if err != nil || !bytes.Equal(basis.Selection, afterObject.body) || control.NormalSigning.KeySelector != s.selector(6) || !bytes.Equal(control.NormalSigning.SPKI, s.keys[s.selector(6)].der) || control.NormalSigning.BindingID.IsZero() || control.NormalSigning.BindingID == d.NormalSigning.BindingID || control.NormalSigning.Binding.Epoch != d.NormalSigning.Binding.Epoch+1 {
						t.Fatal("output lacks exact selected successor proof", err)
					}
					expected := beforeRoot.CurrentAccess.Core.CurrentControl
					expected.NormalSigning = control.NormalSigning
					expected.AccessGeneration++
					afterRoot := workflowRoot(t, s, after)
					if !reflect.DeepEqual(control.CurrentControl, expected) || !reflect.DeepEqual(afterRoot.CurrentAccess.Core.CurrentControl, expected) || !reflect.DeepEqual(afterRoot.ValueEntryPages, beforeRoot.ValueEntryPages) || !reflect.DeepEqual(afterRoot.Recipients, beforeRoot.Recipients) || !reflect.DeepEqual(afterRoot.Names, beforeRoot.Names) || afterRoot.ValueEntryCount != 0 || afterRoot.SecretCount != 0 || afterRoot.WarningBits != beforeRoot.WarningBits || len(basis.Enrollment) != len(d.Recipients) {
						t.Fatal("replacement changed state outside selected Normal signing binding")
					}
					for i, row := range d.Recipients {
						if basis.Enrollment[i].ID != hex.EncodeToString(row.RecipientID[:]) || basis.Enrollment[i].Status != "current" || basis.Enrollment[i].DisplayName != row.DisplayName {
							t.Fatal("output changed complete independent enrollment")
						}
					}
					outputImage := workflowSuccessorImage(t, dir)
					objects = s.objectCount()
					observedChild := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, args...)
					workflowResult(t, observedChild, "success")
					var observed replyRecord
					if json.Unmarshal(observedChild.out, &observed) != nil || observed.OperationKind != "keys-replace-observe" || observed.Payload != "InspectionPayload/v1" || observed.Receipt != "" || observed.Replay != "none" || observed.OperationID == reply.OperationID || len(observed.OperationID) != 64 || observed.Observed != hex.EncodeToString(after.Core.Revision[:]) || observed.Snapshot != hex.EncodeToString(after.Core.Root.Object[:]) || observed.Query == nil || observed.Query.Observation == nil || observed.Query.Observation.Domain != reply.DomainID || observed.Query.Observation.Revision != observed.Observed || observed.Query.Observation.Snapshot != observed.Snapshot {
						t.Fatal("existing output borrowed mutation replay or fabricated a receipt")
					}
					workflowGETOnly(t, observedChild)
					_, rechecked := workflowHead(t, s)
					if !reflect.DeepEqual(outputImage, workflowSuccessorImage(t, dir)) || !reflect.DeepEqual(rechecked, afterObject) || s.objectCount() != objects || s.snapshot("successor").headUpdates != 1 {
						t.Fatal("existing-output observation changed pair or selected state")
					}
					workflowUnchanged(t, source, pair)
					// A separate Reader machine receives only the pair, without the old
					// source, proposal, credentials or process-local installation state.
					portable := t.TempDir()
					portableSource := filepath.Join(portable, "configuration.json")
					if os.Mkdir(filepath.Join(portable, ".enkv"), 0700) != nil || os.WriteFile(portableSource, editable, 0400) != nil || os.WriteFile(filepath.Join(portable, reference), generated, 0400) != nil {
						t.Fatal("successor pair transfer failed")
					}
					portableImage := workflowSuccessorImage(t, portable)
					if len(portableImage) != 3 {
						t.Fatal("cold Reader transfer includes more than the pair")
					}
					compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", portableSource, "--trusted-format", "json", "--json")
					comparison := workflowResult(t, compared, "success")
					workflowGETOnly(t, compared)
					if comparison.Payload.Schema != "ComparisonPayload/v1" || comparison.Payload.Verdict != "match" || !comparison.Payload.DiagnosticsComplete || len(comparison.Payload.Scope) != 12 || comparison.Observation.Revision != hex.EncodeToString(after.Core.Revision[:]) {
						t.Fatal("cold pair-only Reader did not authenticate full selected projection")
					}
					_, coldHead := workflowHead(t, s)
					if !reflect.DeepEqual(portableImage, workflowSuccessorImage(t, portable)) || !reflect.DeepEqual(coldHead, afterObject) || s.objectCount() != objects {
						t.Fatal("cold Reader changed local or selected state")
					}
				})
			}
		}
	}
}

func administrativeReplacementDirectory(t *testing.T) string {
	t.Helper()
	parent := os.Getenv("ENKV_TEST_PROTECTED_FIXTURES")
	if parent == "" || !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		t.Fatal("replacement requires runner protected directory")
	}
	dir, err := os.MkdirTemp(parent, "native-replacement-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("protected replacement cleanup failed", err)
		}
	})
	return dir
}

// Default command setup has no trace SDK or caller diagnostic details. Permit
// only complete formatter records for this fixture's refusal or lost response.
func administrativeReplacementDiagnostics(body []byte, family string, enabled bool, fault string) bool {
	if family != "aws" && family != "gcp" || !enabled && fault != "" || fault != "" && fault != "lose-head-reply" && fault != "lose-head-reply-and-observation" {
		return false
	}
	if enabled && fault == "" {
		return len(body) == 0
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return false
	}
	type consoleResult struct {
		severity, component, operation, result, reason string
		level                                          int
		pathKind, path, errorStatus                    string
	}
	rows := []consoleResult{{severity: "WARN", level: 13, component: "application", operation: "application.invocation", result: "admission_refused", reason: "admission_refused"}}
	if enabled {
		rows = []consoleResult{
			{severity: "WARN", level: 13, component: family, operation: "store.compare_and_swap", result: "write_unknown", reason: "uncertain", pathKind: "state_head", path: "HEAD", errorStatus: "unavailable"},
			{severity: "WARN", level: 13, component: "core", operation: "core.store.compare_and_swap", result: "write_unknown", reason: "uncertain"},
		}
		if fault == "lose-head-reply-and-observation" {
			rows = append(rows,
				consoleResult{severity: "ERROR", level: 17, component: family, operation: "store.read", result: "read_unavailable", reason: "evidence_unavailable", pathKind: "state_head", path: "HEAD", errorStatus: "unavailable"},
				consoleResult{severity: "ERROR", level: 17, component: "core", operation: "core.store.read", result: "read_unavailable", reason: "evidence_unavailable"},
				consoleResult{severity: "WARN", level: 13, component: "core", operation: "core.replace_authority_keys", result: "unresolved_commit", reason: "read_unavailable"},
				consoleResult{severity: "WARN", level: 13, component: "application", operation: "application.invocation", result: "unresolved_commit", reason: "uncertain"},
			)
		}
	}
	allowed := make(map[string]bool, len(rows))
	for _, row := range rows {
		tail := fmt.Sprintf(`%s (%d) component=%q operation=%q event="return" result=%q reason=%q trace_id="" span_id="" trace_sampled=false invocation_id="" worker_id="" member="" key_id="" command_id="" attempt_id="" path_kind=%q path=%q config_field="" error_status=%q error=""`, row.severity, row.level, row.component, row.operation, row.result, row.reason, row.pathKind, row.path, row.errorStatus)
		allowed[tail] = true
	}
	lines := strings.Split(string(body), "\n")
	for _, line := range lines[:len(lines)-1] {
		stamp, tail, ok := strings.Cut(line, " ")
		if !ok || !allowed[tail] || !strings.HasSuffix(stamp, "Z") {
			return false
		}
		parsed, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || parsed.IsZero() || parsed.Format(time.RFC3339Nano) != stamp {
			return false
		}
	}
	return true
}
