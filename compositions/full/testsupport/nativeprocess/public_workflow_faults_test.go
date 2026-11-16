package nativeprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	stateformat "enkv.sh/core/format"
	observer "enkv.sh/core/testsupport/nativeprocess"
)

func workflowFaults(t *testing.T, s *workflowServer, cli, path string, pair workflowPair, head stateformat.Head, object workflowObject, recovery bool) {
	t.Helper()
	// The negative source is an isolated two-file image; the running domain and
	// successful source remain available for the independent effect cases.
	badDirectory := t.TempDir()
	badPath := filepath.Join(badDirectory, "configuration.json")
	var badEditable map[string]json.RawMessage
	if json.Unmarshal(pair.editable, &badEditable) != nil {
		t.Fatal("source refusal fixture unavailable")
	}
	badEditable["schema"] = json.RawMessage(`"enkv/configuration/unsupported"`)
	badBody, err := json.Marshal(badEditable)
	if err != nil || os.Mkdir(filepath.Join(badDirectory, ".enkv"), 0700) != nil || os.WriteFile(badPath, badBody, 0600) != nil || os.WriteFile(filepath.Join(badDirectory, pair.reference), pair.generated, 0600) != nil {
		t.Fatal("source refusal image unavailable")
	}
	badPair := workflowReadPair(t, badPath)
	restoreBad := workflowReadOnlyPair(t, badPath, badPair)
	beforeBadObjects := s.objectCount()
	bad := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "apply", "--source", badPath, "--source-format", "json", "--json")
	var badResult struct {
		Schema  string
		State   string `json:"state_result"`
		Receipt string `json:"receipt_hex"`
		Payload any
	}
	if bad.code != 2 || json.Unmarshal(bad.out, &badResult) != nil || badResult.Schema != "ProductResult/v1" || badResult.State != "refused" || badResult.Receipt != "" || badResult.Payload != nil || s.objectCount() != beforeBadObjects {
		t.Fatal("invalid source did not refuse without effect evidence")
	}
	for _, event := range bad.capture.Events {
		if event.Kind != "footer" {
			t.Fatal("source refusal opened credentials, transport, or private material")
		}
	}
	workflowUnchanged(t, badPath, badPair)
	restoreBad()
	unchanged := func(before workflowPair) {
		t.Helper()
		after := workflowReadPair(t, path)
		if contract.Hash(after.editable) != contract.Hash(before.editable) || contract.Hash(after.generated) != contract.Hash(before.generated) {
			t.Fatal("remote operation changed exact source pair hashes")
		}
		workflowUnchanged(t, path, before)
	}
	unchangedHead := func(before workflowObject) {
		t.Helper()
		_, after := workflowHead(t, s)
		if after.etag != before.etag || !bytes.Equal(after.body, before.body) {
			t.Fatal("read or refused conditional update changed selected HEAD")
		}
	}
	restore := workflowReadOnlyPair(t, path, pair)
	compared := workflowRun(t, s, cli, "reader", observer.Policy{NoKMS: true}, nil, "plan", "--trusted", path, "--trusted-format", "json", "--json")
	comparison := workflowResult(t, compared, "success")
	workflowGETOnly(t, compared)
	if comparison.Payload.Verdict != "match" || comparison.Observation.Revision != hex.EncodeToString(head.Core.Revision[:]) {
		t.Fatal("read-only pair comparison did not observe exact current HEAD")
	}
	unchanged(pair)
	unchangedHead(object)
	beforeNoop, objects := s.snapshot("noop"), s.objectCount()
	noop := workflowRun(t, s, cli, "noop", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	noopResult := workflowResult(t, noop, "no-op")
	workflowNoRecovery(t, noop)
	var noopPayload struct{ Payload json.RawMessage }
	if json.Unmarshal(noop.out, &noopPayload) != nil || string(noopPayload.Payload) != "null" || noopResult.Receipt != "" {
		t.Fatal("read-only apply no-op fabricated transition evidence")
	}
	for _, event := range noop.capture.Events {
		if event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
			t.Fatal("read-only apply no-op attempted a write or signature")
		}
	}
	afterNoop := s.snapshot("noop")
	if afterNoop.creates != beforeNoop.creates || afterNoop.headCreates != beforeNoop.headCreates || afterNoop.headUpdates != beforeNoop.headUpdates || afterNoop.conditions != beforeNoop.conditions || afterNoop.calls["Sign/normal"] != beforeNoop.calls["Sign/normal"] || s.objectCount() != objects {
		t.Fatal("read-only apply no-op changed remote objects")
	}
	unchanged(pair)
	unchangedHead(object)
	restore()

	beforeEntry := workflowEntry(t, s, workflowRoot(t, s, head))
	lostPlain := []byte("independent value for the controlled lost HEAD reply\x00\xff")
	defer clear(lostPlain)
	lostPair := workflowPrepare(t, s, cli, path, "set-change", pair, lostPlain)
	restore = workflowReadOnlyPair(t, path, lostPair)
	beforeLost := s.snapshot("apply")
	lost := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "lose-head-reply", FaultOrdinal: 1}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	lostResult := workflowResult(t, lost, "success")
	lostReceipt := workflowReceipt(t, lostResult.Receipt, contract.OperationApplyDeclaration)
	workflowNoRecovery(t, lost)
	workflowOneHeadAttempt(t, lost, true, 200)
	workflowPostWriteHeadObservation(t, lost)
	unchanged(lostPair)
	selected, selectedObject := workflowHead(t, s)
	root := workflowRoot(t, s, selected)
	entry := workflowEntry(t, s, root)
	if selected.Core.Form != stateformat.SuccessorHead || selected.Core.PreviousRevision != head.Core.Revision || selected.Core.PreviousDigest != contract.Hash(object.body) || selected.Core.PreviousToken != (contract.Token{Family: pair.descriptor.Provider, Value: object.etag}) || selected.Core.Revision == head.Core.Revision || selectedObject.etag == object.etag || lostReceipt.RequestedRevisionID != selected.Core.Revision || lostReceipt.ObservedRevisionID != selected.Core.Revision || lostReceipt.PredecessorRevisionID != head.Core.Revision || lostReceipt.DomainID != pair.descriptor.DomainID || root.ValueEntryCount != 1 || root.SecretCount != 1 || entry.Incarnation != beforeEntry.Incarnation || entry.ValueState == beforeEntry.ValueState {
		t.Fatal("lost reply did not leave the exact requested successor actually selected")
	}
	afterLost := s.snapshot("apply")
	if afterLost.headUpdates-beforeLost.headUpdates != 1 || afterLost.headCreates != beforeLost.headCreates || afterLost.conditions != beforeLost.conditions || afterLost.calls["Sign/normal"]-beforeLost.calls["Sign/normal"] != 1 {
		t.Fatal("lost reply retried the conditional mutation or signing")
	}
	workflowRecoveryWraps(t, s, root, recovery)
	restore()

	contentionPlain := []byte("distinct proposal for controlled HEAD contention\xff\x00")
	defer clear(contentionPlain)
	contentionPair := workflowPrepare(t, s, cli, path, "set-change", lostPair, contentionPlain)
	restore = workflowReadOnlyPair(t, path, contentionPair)
	beforeContention := s.snapshot("apply")
	contended := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "head-contention", FaultOrdinal: 1}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	contentionResult := workflowFaultResult(t, contended, "contention", false)
	workflowNoRecovery(t, contended)
	workflowOneHeadAttempt(t, contended, false, 412)
	if contentionResult.Requested == hex.EncodeToString(lostReceipt.RequestedRevisionID[:]) || contentionResult.Payload.Predecessor != hex.EncodeToString(selected.Core.Revision[:]) {
		t.Fatal("contention restarted the lost-reply operation or used another predecessor")
	}
	unchanged(contentionPair)
	unchangedHead(selectedObject)
	afterContention := s.snapshot("apply")
	if afterContention.headUpdates != beforeContention.headUpdates || afterContention.headCreates != beforeContention.headCreates || afterContention.conditions != beforeContention.conditions || afterContention.calls["Sign/normal"]-beforeContention.calls["Sign/normal"] != 1 {
		t.Fatal("controlled contention reached Store HEAD or repeated signing")
	}
	restore()

	// A separate invocation loses both its real conditional reply and every
	// subsequent exact HEAD observation. Independent server inspection below
	// does not turn that invocation's unknown result into a success.
	unknownPlain := []byte("independent exact unknown proposal\x00\xff")
	defer clear(unknownPlain)
	unknownPair := workflowPrepare(t, s, cli, path, "set-change", contentionPair, unknownPlain)
	restore = workflowReadOnlyPair(t, path, unknownPair)
	beforeUnknown := s.snapshot("apply")
	unknown := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "lose-head-reply-and-observation", FaultOrdinal: 1}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	unknownResult := workflowFaultResult(t, unknown, "commit-outcome-unknown", true)
	workflowNoRecovery(t, unknown)
	workflowOneHeadAttempt(t, unknown, true, 200)
	writeReturned, refusedReads := false, 0
	for _, event := range unknown.capture.Events {
		if event.Kind == "http-return" && event.Operation == "head-write" {
			writeReturned = true
		}
		if writeReturned && event.Operation == "head-read" {
			if event.Sent || event.Status != 0 {
				t.Fatal("unknown invocation recovered an exact HEAD observation")
			}
			if event.Kind == "http-return" {
				refusedReads++
			}
		}
	}
	if refusedReads == 0 {
		t.Fatal("unknown result did not attempt and join refused HEAD observation")
	}
	unchanged(unknownPair)
	unknownHead, unknownObject := workflowHead(t, s)
	if unknownResult.Requested != hex.EncodeToString(unknownHead.Core.Revision[:]) || unknownResult.Payload.Predecessor != hex.EncodeToString(selected.Core.Revision[:]) || unknownHead.Core.PreviousDigest != contract.Hash(selectedObject.body) || unknownHead.Core.PreviousToken != (contract.Token{Family: pair.descriptor.Provider, Value: selectedObject.etag}) || unknownObject.etag == selectedObject.etag {
		t.Fatal("independent unknown observation did not select the exact requested successor")
	}
	afterUnknown := s.snapshot("apply")
	if afterUnknown.headUpdates-beforeUnknown.headUpdates != 1 || afterUnknown.headCreates != beforeUnknown.headCreates || afterUnknown.conditions != beforeUnknown.conditions || afterUnknown.calls["Sign/normal"]-beforeUnknown.calls["Sign/normal"] != 1 {
		t.Fatal("unknown invocation restarted its conditional operation or signing")
	}
	restore()

	cancelPlain := []byte("distinct proposal canceled before private reply\xff\x00")
	defer clear(cancelPlain)
	cancelPair := workflowPrepare(t, s, cli, path, "set-change", unknownPair, cancelPlain)
	restore = workflowReadOnlyPair(t, path, cancelPair)
	beforeInvalid, invalidObjects := s.snapshot("invalid-private"), s.objectCount()
	invalid := workflowRun(t, s, cli, "invalid-private", observer.Policy{}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	var invalidResult struct {
		Schema    string
		State     string `json:"state_result"`
		Receipt   string `json:"receipt_hex"`
		Uncertain bool   `json:"commit_may_have_occurred"`
	}
	if invalid.code != 2 || json.Unmarshal(invalid.out, &invalidResult) != nil || invalidResult.Schema != "ProductResult/v1" || invalidResult.State != "positive-defect" || invalidResult.Receipt != "" || invalidResult.Uncertain {
		t.Fatal("wrong private current packet did not return authenticated validation failure without commit evidence")
	}
	workflowNoRecovery(t, invalid)
	for _, event := range invalid.capture.Events {
		if event.Kind == "plaintext" || event.Kind == "recovery-plaintext" || event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
			t.Fatal("private packet validation failure released plaintext or attempted a write/signature")
		}
	}
	afterInvalid := s.snapshot("invalid-private")
	if afterInvalid.calls["Decrypt/authority"]-beforeInvalid.calls["Decrypt/authority"] != 1 || afterInvalid.calls["Sign/normal"] != 0 || afterInvalid.creates != 0 || afterInvalid.headUpdates != 0 || afterInvalid.headCreates != 0 || afterInvalid.conditions != 0 || s.objectCount() != invalidObjects {
		t.Fatal("private packet validation failure repeated access or changed remote objects")
	}
	unchanged(cancelPair)
	unchangedHead(unknownObject)
	beforeCancel, cancelObjects := s.snapshot("apply"), s.objectCount()
	canceled := workflowRun(t, s, cli, "apply", observer.Policy{Fault: "cancel-private-return", FaultOrdinal: 1}, nil, "apply", "--source", path, "--source-format", "json", "--json")
	var canceledResult struct {
		Schema    string
		State     string `json:"state_result"`
		Receipt   string `json:"receipt_hex"`
		Uncertain bool   `json:"commit_may_have_occurred"`
	}
	if canceled.code != 2 || json.Unmarshal(canceled.out, &canceledResult) != nil || canceledResult.Schema != "ProductResult/v1" || canceledResult.State != "refused" || canceledResult.Receipt != "" || canceledResult.Uncertain {
		t.Fatal("canceled existing Apply context did not return a normal refusal without commit evidence")
	}
	workflowNoRecovery(t, canceled)
	uses, signaled, joined := canceled.cancellationState()
	if uses != 1 || !signaled || !joined {
		t.Fatal("cancellation did not join its exact private-return barrier")
	}
	for _, event := range canceled.capture.Events {
		if event.Kind == "plaintext" || event.Kind == "recovery-plaintext" || event.Kind == "http-start" && (event.Operation == "head-write" || event.Operation == "store-write" || event.Operation == "kms-sign") {
			t.Fatal("canceled private return released plaintext or attempted a write/signature")
		}
	}
	afterCancel := s.snapshot("apply")
	if afterCancel.calls["Decrypt/authority"]-beforeCancel.calls["Decrypt/authority"] != 1 || afterCancel.calls["Sign/normal"] != beforeCancel.calls["Sign/normal"] || afterCancel.creates != beforeCancel.creates || afterCancel.headUpdates != beforeCancel.headUpdates || afterCancel.headCreates != beforeCancel.headCreates || afterCancel.conditions != beforeCancel.conditions || s.objectCount() != cancelObjects {
		t.Fatal("canceled private return repeated private access or changed remote objects")
	}
	unchanged(cancelPair)
	unchangedHead(unknownObject)
	restore()
}

func workflowReadOnlyPair(t *testing.T, path string, pair workflowPair) func() {
	t.Helper()
	directory := filepath.Dir(path)
	dependencyDirectory := filepath.Join(directory, ".enkv")
	paths := []string{directory, dependencyDirectory, path, filepath.Join(directory, pair.reference)}
	modes := make([]os.FileMode, len(paths))
	for i, name := range paths {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		modes[i] = info.Mode().Perm()
	}
	listing := func(name string) []string {
		t.Helper()
		entries, err := os.ReadDir(name)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		return names
	}
	beforeDirectory, beforeDependencies := listing(directory), listing(dependencyDirectory)
	restored := false
	restore := func() {
		t.Helper()
		if restored {
			return
		}
		restored = true
		for i, name := range paths {
			if err := os.Chmod(name, modes[i]); err != nil {
				t.Error("read-only fixture mode restore failed", err)
			}
		}
		if !slices.Equal(beforeDirectory, listing(directory)) || !slices.Equal(beforeDependencies, listing(dependencyDirectory)) {
			t.Error("read-only operation changed source directory entries")
		}
		workflowUnchanged(t, path, pair)
	}
	t.Cleanup(restore)
	for i, name := range paths {
		mode := os.FileMode(0400)
		if i < 2 {
			mode = 0500
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal("read-only fixture mode setup failed", err)
		}
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("read-only fixture mode did not take effect")
		}
	}
	return restore
}

type workflowFaultOutput struct {
	Schema    string
	Operation string `json:"operation_kind"`
	State     string `json:"state_result"`
	Requested string `json:"requested_revision_id"`
	Receipt   string `json:"receipt_hex"`
	Uncertain bool   `json:"commit_may_have_occurred"`
	Delivery  *struct {
		Path          string `json:"path"`
		Status        string `json:"status"`
		Failed        bool   `json:"failed"`
		CleanupFailed bool   `json:"cleanup_failed"`
		Pins          *struct {
			EditableDigest  string `json:"editable_digest"`
			GeneratedDigest string `json:"generated_digest"`
			EditableLength  uint64 `json:"editable_length"`
			GeneratedLength uint64 `json:"generated_length"`
			HasGenerated    bool   `json:"has_generated"`
		} `json:"pair_pins"`
	} `json:"delivery"`
	SourceUsability string `json:"source_usability"`
	Payload         struct {
		Schema      string
		Predecessor string `json:"predecessor_revision_id"`
		Requested   string `json:"requested_revision_id"`
	}
}

func workflowFaultResult(t *testing.T, child workflowChild, state string, uncertain bool) workflowFaultOutput {
	t.Helper()
	return workflowMutationFaultResult(t, child, "apply-declaration", state, uncertain)
}

func workflowMutationFaultResult(t *testing.T, child workflowChild, operation, state string, uncertain bool) workflowFaultOutput {
	t.Helper()
	var result workflowFaultOutput
	if child.code != 3 || json.Unmarshal(child.out, &result) != nil || result.Schema != "ProductResult/v1" || result.Operation != operation || result.State != state || result.Uncertain != uncertain || result.Receipt != "" || result.Payload.Schema != "TransitionPayload/v1" || result.Payload.Requested != result.Requested || result.Payload.Predecessor == "" || result.Requested == "" {
		t.Fatalf("controlled HEAD fault lost exact uncertain/contention result (state=%s, exit=%d)", state, child.code)
	}
	if operation == "envelope-rekey" || operation == "retire-recipient-identity" {
		delivery := result.Delivery
		if delivery == nil || delivery.Status != "delivered" || delivery.Failed || delivery.CleanupFailed || !filepath.IsAbs(delivery.Path) || delivery.Pins == nil || !delivery.Pins.HasGenerated || result.SourceUsability != "unchecked" {
			t.Fatal("maintenance fault lost separate delivery or claimed unverified source usability")
		}
		pair := workflowReadPair(t, delivery.Path)
		editable, generated := sha256.Sum256(pair.editable), sha256.Sum256(pair.generated)
		if delivery.Pins.EditableDigest != hex.EncodeToString(editable[:]) || delivery.Pins.GeneratedDigest != hex.EncodeToString(generated[:]) || delivery.Pins.EditableLength != uint64(len(pair.editable)) || delivery.Pins.GeneratedLength != uint64(len(pair.generated)) {
			t.Fatal("maintenance fault delivery pins differ from the independently reopened pair")
		}
	}
	return result
}

func workflowOneHeadAttempt(t *testing.T, child workflowChild, sent bool, status int) {
	t.Helper()
	starts, returns := 0, 0
	for _, event := range child.capture.Events {
		if event.Operation != "head-write" {
			continue
		}
		switch event.Kind {
		case "http-start":
			starts++
			if event.Sent != sent {
				t.Fatal("controlled HEAD dispatch differs")
			}
		case "http-return":
			returns++
			if event.Sent != sent || event.Status != status {
				t.Fatal("controlled HEAD completion differs")
			}
		}
	}
	if starts != 1 || returns != 1 {
		t.Fatal("controlled HEAD mutation did not have exactly one joined attempt")
	}
}

func workflowPostWriteHeadObservation(t *testing.T, child workflowChild) {
	t.Helper()
	writeReturned, observed := false, false
	for _, event := range child.capture.Events {
		if event.Kind == "http-return" && event.Operation == "head-write" {
			writeReturned = true
		}
		if writeReturned && event.Kind == "http-return" && event.Operation == "head-read" && event.Sent && event.Status == 200 {
			observed = true
		}
	}
	if !observed {
		t.Fatal("lost reply success lacked a joined post-write HEAD observation")
	}
}
