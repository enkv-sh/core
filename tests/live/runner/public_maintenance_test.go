package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// Maintenance borrows the source files and uses its native coordination paths.
// Keep those paths writable while protecting the pair and checking its inventory.
func publicMaintenanceSourceProtected(t testing.TB, source string, run func() publicChildResult) publicChildResult {
	t.Helper()
	image := publicSourceImage(t, source)
	modes := map[string]os.FileMode{}
	defer func() {
		for path, mode := range modes {
			if err := os.Chmod(path, mode); err != nil {
				t.Error("maintenance source mode restore failed", err)
			}
		}
	}()
	for path := range image.Files {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal("maintenance source mode unavailable", err)
		}
		modes[path] = info.Mode().Perm()
		if err := os.Chmod(path, 0400); err != nil {
			t.Fatal("maintenance source protection failed", err)
		}
	}
	result := run()
	publicImageUnchanged(t, image)
	for path := range modes {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0400 {
			t.Fatal("maintenance source file protection changed")
		}
	}
	return result
}

type publicMaintenanceResult struct {
	Delivery struct {
		Status        string `json:"status"`
		Failed        bool   `json:"failed"`
		CleanupFailed bool   `json:"cleanup_failed"`
		Pins          struct {
			EditableDigest  string `json:"editable_digest"`
			GeneratedDigest string `json:"generated_digest"`
			EditableLength  uint64 `json:"editable_length"`
			GeneratedLength uint64 `json:"generated_length"`
		} `json:"pair_pins"`
	} `json:"delivery"`
	Usability   string `json:"source_usability"`
	Observation *struct {
		Schema                 string `json:"schema"`
		Operation              uint16 `json:"original_operation_kind"`
		OperationID            string `json:"original_operation_id"`
		RequestIdentity        string `json:"original_request_identity"`
		Receipt                string `json:"receipt_hex"`
		CandidateCurrent       bool   `json:"candidate_current"`
		SourceUsable           bool   `json:"source_usable"`
		SourceUsabilityChecked bool   `json:"source_usability_checked"`
	} `json:"maintenance_observation"`
}

func publicMaintenancePins(t testing.TB, child publicChildResult, output, status string) publicMaintenanceResult {
	t.Helper()
	var result publicMaintenanceResult
	if json.Unmarshal(child.Body, &result) != nil || result.Delivery.Status != status || result.Delivery.Failed || result.Delivery.CleanupFailed || result.Usability != "confirmed" {
		t.Fatal("maintenance lacks separate confirmed delivery and source usability")
	}
	document := publicSourceDocument(t, output)
	ref, ok := document["generated"].(string)
	if !ok || ref == "" {
		t.Fatal("maintenance generated pair member unavailable")
	}
	image := publicSourceImage(t, output)
	editable := image.Files[output]
	generated := image.Files[filepath.Join(filepath.Dir(output), filepath.FromSlash(ref))]
	ed, gd := sha256.Sum256(editable), sha256.Sum256(generated)
	if result.Delivery.Pins.EditableDigest != hex.EncodeToString(ed[:]) || result.Delivery.Pins.GeneratedDigest != hex.EncodeToString(gd[:]) || result.Delivery.Pins.EditableLength != uint64(len(editable)) || result.Delivery.Pins.GeneratedLength != uint64(len(generated)) || len(editable) == 0 || len(generated) == 0 {
		t.Fatal("maintenance delivery pins differ from independently reopened complete pair")
	}
	return result
}

func publicMaintenanceDelivered(t testing.TB, child publicChildResult, source, output string) {
	t.Helper()
	if source == output || filepath.Dir(source) == filepath.Dir(output) {
		t.Fatal("maintenance successor is not independently named")
	}
	result := publicMaintenancePins(t, child, output, "delivered")
	if result.Observation != nil {
		t.Fatal("fresh maintenance mutation was reported as observation")
	}
	before, after := publicSourceDocument(t, source), publicSourceDocument(t, output)
	var args struct {
		Operation string `json:"operation_kind"`
	}
	if json.Unmarshal(child.Body, &args) != nil {
		t.Fatal("maintenance operation unavailable")
	}
	removed := ""
	if args.Operation == "retire-recipient-identity" {
		oldRecipients, nextRecipients := before["recipients"].(map[string]any), after["recipients"].(map[string]any)
		for reference := range oldRecipients {
			if _, present := nextRecipients[reference]; !present {
				if removed != "" {
					t.Fatal("retirement removed more than one live recipient declaration")
				}
				removed = reference
			}
		}
		if removed == "" {
			t.Fatal("retirement did not remove its live recipient declaration")
		}
		delete(oldRecipients, removed)
		for _, raw := range before["entries"].(map[string]any) {
			entry := raw.(map[string]any)
			members := entry["recipients"].([]any)
			entry["recipients"] = slices.DeleteFunc(members, func(member any) bool { return member == removed })
		}
	} else if args.Operation != "envelope-rekey" {
		t.Fatal("unexpected maintenance operation")
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("maintenance successor changed unrelated pending declarations")
	}
	type generatedFacts struct {
		Secrets    map[string]json.RawMessage `json:"secrets"`
		Recipients map[string]json.RawMessage `json:"recipients"`
	}
	readGenerated := func(path string) generatedFacts {
		doc := publicSourceDocument(t, path)
		body, err := os.ReadFile(filepath.Join(filepath.Dir(path), filepath.FromSlash(doc["generated"].(string))))
		var generated generatedFacts
		if err != nil || json.Unmarshal(body, &generated) != nil {
			t.Fatal("maintenance generated records unavailable")
		}
		return generated
	}
	oldGenerated, nextGenerated := readGenerated(source), readGenerated(output)
	if len(oldGenerated.Secrets) != 1 || len(nextGenerated.Secrets) != 1 {
		t.Fatal("maintenance changed complete supplied input coverage")
	}
	for name, original := range oldGenerated.Secrets {
		// Material maintenance preserves supplied input and its original context.
		if !bytes.Equal(original, nextGenerated.Secrets[name]) {
			t.Fatal("maintenance changed original supplied input record")
		}
	}
	if removed != "" {
		if _, present := oldGenerated.Recipients[removed]; !present {
			t.Fatal("retirement source generated recipient unavailable")
		}
		delete(oldGenerated.Recipients, removed)
	}
	if !reflect.DeepEqual(oldGenerated.Recipients, nextGenerated.Recipients) {
		t.Fatal("maintenance changed unrelated generated recipient records")
	}
}

func publicObserveMaintenance(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source, output string, selected publicChildResult, kind uint16, args []string) {
	t.Helper()
	original := publicProduct(t, selected, publicLifecycleOperation(kind))
	identity, admitted := publicAdmittedRequestIdentity(original)
	if !admitted {
		t.Fatal("maintenance original request identity unavailable")
	}
	image := publicSourceImage(t, output)
	observed := publicMaintenanceSourceProtected(t, source, func() publicChildResult {
		// The two-entry fixture bounds the complete selected closure to 512 KiB.
		// Observation has no immutable or conditional-write reservation.
		return publicCLIReserved(t, ctx, inv, input, budget, "reader", false, nativeprocess.Policy{NoKMS: true}, budgetReservation{Requests: 64, BodyBytes: 4 << 20}, nil, args...)
	})
	defer clear(observed.Body)
	product := publicProduct(t, observed, "mutation-receipt")
	result := publicMaintenancePins(t, observed, output, "existing")
	fact := result.Observation
	if observed.Code != 0 || product.State != "success" || product.CommitUnknown || fact == nil || fact.Schema != "MaintenanceObservation/v1" || fact.Operation != kind || fact.OperationID != original.OperationID || fact.RequestIdentity != identity || fact.Receipt != original.Receipt || !fact.CandidateCurrent || !fact.SourceUsable || !fact.SourceUsabilityChecked {
		t.Fatal("existing maintenance output lost original receipt or current source usability")
	}
	publicAssertGETOnly(t, observed.Capture)
	for _, event := range observed.Capture.Events {
		if event.Kind == "construction" && (event.Operation == "signer" || event.Operation == "key-access") {
			t.Fatal("maintenance observation constructed private mutation capability")
		}
	}
	publicImageUnchanged(t, image)
}

func publicMaintenanceRefused(t testing.TB, child publicChildResult, output string) {
	t.Helper()
	product := publicProduct(t, child, "retire-recipient-identity")
	var result publicMaintenanceResult
	if json.Unmarshal(child.Body, &result) != nil || child.Code == 0 || product.State != "refused" || product.CommitUnknown || product.Receipt != "" || !product.payloadNull || result.Delivery.Status != "unproved" || result.Usability != "unchecked" {
		t.Fatal("stale pending membership grant did not refuse before successor delivery")
	}
	publicAssertGETOnly(t, child.Capture)
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("refused maintenance delivered an output")
	}
}

// HTTP evidence establishes private comparison before provider mutation. The
// installed-owner tests separately check read-owner Close before custody.
func publicMaintenancePrivateBeforeMutation(t testing.TB, capture nativeprocess.Capture) {
	t.Helper()
	opens := 0
	for _, event := range capture.Events {
		if event.Kind == "http-return" && event.Operation == "kms-decrypt" && event.Role == "authority" && event.Sent && event.Status == 200 {
			opens++
		}
		if event.Kind == "http-start" && (event.Operation == "kms-sign" || event.Operation == "store-write" || event.Operation == "head-write") {
			if opens < 2 {
				t.Fatal("maintenance reached provider mutation before proposed/current private checks")
			}
			return
		}
	}
	t.Fatal("maintenance lacks provider mutation evidence")
}
