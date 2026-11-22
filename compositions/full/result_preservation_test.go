package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestResultDeliveryHasSeparateFiniteLifetime(t *testing.T) {
	execution, stopExecution := context.WithCancel(t.Context())
	stopExecution()
	started := time.Now()
	delivery, stopDelivery := ResultDeliveryContext(execution)
	deadline, finite := delivery.Deadline()
	if !finite || deadline.Before(started) || deadline.After(time.Now().Add(5*time.Minute)) || delivery.Err() != nil || !errors.Is(execution.Err(), context.Canceled) {
		t.Fatal("result delivery did not separate its finite lifetime from execution")
	}
	stopDelivery()
	if !errors.Is(delivery.Err(), context.Canceled) {
		t.Error("delivery owner cannot stop output")
	}
}

func maximumMutationDiagnostic() contract.Diagnostic {
	return contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, Name: strings.Repeat("\x00", 256), DestinationID: strings.Repeat("\x00", 256)},
		Path: []contract.DiagnosticField{contract.FieldLocatorRequiresCreation}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable,
		SourceLocation: &contract.SourceLocation{SourceID: strings.Repeat("a", 64), Line: math.MaxUint64, Column: math.MaxUint64}}
}

// full_only: false
func TestMutationDiagnosticCountAndExactEncodedAccount(t *testing.T) {
	row, valid := readerDiagnostic(maximumMutationDiagnostic())
	body, err := json.Marshal(row)
	if !valid || err != nil || len(body) != 3415 {
		t.Fatal("independent maximum diagnostic account", len(body), valid, err)
	}
	r := suppliedApplyResultFixture(t)
	r.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}
	r.Payload, r.Receipt = nil, nil
	baseJSON, err := RenderApplyJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	baseHuman, err := RenderApplyHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Diagnostics = make([]contract.Diagnostic, 3081)
	for i := range r.Diagnostics {
		r.Diagnostics[i] = maximumMutationDiagnostic()
	}
	machine, err := RenderApplyJSON(r)
	if err != nil || len(machine)-len(baseJSON) != 10524695 {
		t.Error("complete JSON diagnostic account", len(machine)-len(baseJSON), err)
	}
	human, err := RenderApplyHuman(r)
	if err != nil || len(human)-len(baseHuman) != 10561668 {
		t.Error("complete human diagnostic account", len(human)-len(baseHuman), err)
	}
	generated, err := RenderGeneratedMutationJSON(r, contract.OperationApplyDeclaration)
	if err != nil || !bytes.Equal(generated, machine) {
		t.Error("generated-free family lost complete diagnostic envelope", err)
	}
	r.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "refused", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectNoChange, EvidenceCeiling: contract.ReceiptEvidenceCanonical}
	for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
		if _, err := render(r, contract.OperationApplyDeclaration); err != nil {
			t.Error("complete generated diagnostic account refused", err)
		}
	}
	r.Diagnostics = append(r.Diagnostics, maximumMutationDiagnostic())
	for _, render := range []func(core.PublicApplyResult, uint16) ([]byte, error){RenderGeneratedMutationJSON, RenderGeneratedMutationHuman} {
		if body, err := render(r, contract.OperationApplyDeclaration); err == nil || body != nil {
			t.Error("one-over generated diagnostic count accepted")
		}
	}
	r.Generated = nil
	for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
		if body, err := render(r); err == nil || body != nil {
			t.Error("one-over transition diagnostic count accepted")
		}
	}
}

// full_only: false
func TestMutationDiagnosticsRetainSelectionAndReceipt(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Diagnostics = []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedObjectUnavailable},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonExpired},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable},
	}
	r.Diagnostics = append(r.Diagnostics, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonImmutableConflict})
	before := r.Result
	for name, render := range map[string]func(core.PublicApplyResult) ([]byte, error){"json": RenderApplyJSON, "human": RenderApplyHuman} {
		t.Run(name, func(t *testing.T) {
			body, err := render(r)
			if err != nil {
				t.Fatal("preparation, interruption and pair cleanup diagnostics hid a selected result", err)
			}
			for _, reason := range []string{"selected-object-unavailable", "expired", "evidence-unavailable", "immutable-conflict"} {
				if !bytes.Contains(body, []byte(reason)) {
					t.Error("missing diagnostic", reason)
				}
			}
			if !bytes.Contains(body, []byte(readerID(r.OperationID))) || !bytes.Contains(body, []byte(readerID(r.Payload.RequestedRevisionID))) || r.Result != before {
				t.Error("rendering changed selection correlation")
			}
		})
	}
	body, err := RenderApplyJSON(r)
	if err == nil {
		var got struct {
			Diagnostics []readerDiagnosticRecord `json:"diagnostics"`
			Receipt     string                   `json:"receipt_hex"`
		}
		if json.Unmarshal(body, &got) != nil || len(got.Diagnostics) != len(r.Diagnostics) || got.Receipt == "" {
			t.Error("complete diagnostic sequence or retained receipt missing")
		}
	}
	t.Run("generated-unknown", func(t *testing.T) {
		generated := r
		generated.Receipt = nil
		generated.Result.Outcome, generated.Result.CommitMayHaveOccurred = core.UnresolvedCommit, true
		fact := generatedRendererEffect()
		generated.Generated = &core.GeneratedInvocationResult{OperationKind: contract.OperationApplyDeclaration, StateResult: "commit-outcome-unknown", CanonicalOutcome: contract.ReceiptCanonicalNotSelected, EffectSummary: contract.ReceiptEffectUnknown, EvidenceCeiling: contract.ReceiptEvidenceProviderFacts, SummaryCountsAvailable: true, EffectsAvailable: true, Effects: []core.GeneratedEffectFact{fact}, RelatedWorkAvailable: true, UnknownCount: 1}
		generated.Generated.SummaryCounts[contract.ReceiptEffectCount], generated.Generated.SummaryCounts[contract.ReceiptSummaryUnknownCount] = 1, 1
		for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
			body, err := render(generated)
			if err != nil || !bytes.Contains(body, []byte(readerID(fact.Record.AttemptID))) || !bytes.Contains(body, []byte("commit-outcome-unknown")) || !bytes.Contains(body, []byte("expired")) || !bytes.Contains(body, []byte("evidence-unavailable")) {
				t.Error("diagnostic sequence lost unknown effects or operation facts", err)
			}
		}
	})
}

// full_only: false
func TestGeneratedMutationFallbackUsesCompleteEnvelopeBudget(t *testing.T) {
	r := suppliedApplyResultFixture(t)
	r.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}
	r.Payload, r.Receipt = nil, nil
	for range 2 {
		r.Diagnostics = append(r.Diagnostics, contract.Diagnostic{
			Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, Name: strings.Repeat("\x00", 256), DestinationID: strings.Repeat("\x00", 256)},
			Path:    []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable,
		})
	}
	want, err := RenderApplyJSON(r)
	if err != nil || len(want) <= 4096 {
		t.Fatal("fixture must have valid rows in a complete envelope larger than one row", len(want), err)
	}
	got, err := RenderGeneratedMutationJSON(r, contract.OperationApplyDeclaration)
	if err != nil || !bytes.Equal(got, want) {
		t.Error("generated-free result was limited as one row", len(got), err)
	}
}

// full_only: false
func TestPublicationPairCleanupIsSeparateFromProviderAndSelection(t *testing.T) {
	for _, disposition := range []uint8{contract.PublicationOutcomeAcknowledged, contract.PublicationOutcomeUnknown, contract.PublicationOutcomeQualifiedNoEffect} {
		r := publicPublicationResultFixture(contract.PublicationWriteValue, disposition)
		source := configurationSetPair(t, "aws", configuration.JSON, nil)
		pair, err := configuration.Capture(t.Context(), source.path, configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		fileField := reflect.ValueOf(pair.Editable).Elem().FieldByName("file")
		if fileField.IsNil() {
			t.Fatal("captured snapshot handle absent")
		}
		file := (*os.File)(fileField.UnsafePointer())
		if err := file.Close(); err != nil {
			t.Fatal("controlled snapshot close", err)
		}
		if err := pair.Close(); !errors.Is(err, os.ErrClosed) {
			t.Fatal("captured pair Close failure not established", err)
		}
		before, err := RenderPublicationJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		field := reflect.ValueOf(&r).Elem().FieldByName("CleanupFailed")
		if !field.IsValid() || !field.CanSet() || field.Kind() != reflect.Bool {
			t.Fatal("publication result has no separate pair cleanup fact")
		}
		field.SetBool(true)
		body, err := RenderPublicationJSON(r)
		if err != nil {
			t.Fatal("local cleanup hid provider evidence", err)
		}
		var old, got map[string]json.RawMessage
		if json.Unmarshal(before, &old) != nil || json.Unmarshal(body, &got) != nil {
			t.Fatal("invalid public result")
		}
		if !bytes.Equal(got["payload"], old["payload"]) || !bytes.Equal(got["reason_code"], old["reason_code"]) || string(got["cleanup_failed"]) != "true" {
			t.Error("cleanup changed provider or Core facts")
		}
		wantExit := 2
		if disposition == contract.PublicationOutcomeUnknown {
			wantExit = 3
		}
		if PublicationExitCode(r) != wantExit {
			t.Error("cleanup/effect precedence", PublicationExitCode(r))
		}
		human, err := RenderPublicationHuman(r)
		if err != nil || !bytes.Contains(human, []byte("Warning: source cleanup failed.\n")) {
			t.Error("human cleanup fact missing", err)
		}
	}
	refused := core.PublicPublicationResult{RequestID: contract.ID{1}, Result: core.Result{Outcome: core.AdmissionRefused, Reason: core.InvalidIntent}, CleanupFailed: true}
	for _, test := range []struct {
		render func(core.PublicPublicationResult) ([]byte, error)
		fact   string
	}{{RenderPublicationJSON, `"cleanup_failed": true`}, {RenderPublicationHuman, "Warning: source cleanup failed."}} {
		if body, err := test.render(refused); err != nil || !bytes.Contains(body, []byte(test.fact)) {
			t.Error("local pair cleanup hid a pre-admission refusal", err)
		}
	}
	if PublicationExitCode(refused) != 2 {
		t.Error("local cleanup changed refusal exit")
	}
	r := publicPublicationResultFixture(contract.PublicationWriteValue, contract.PublicationOutcomeAcknowledged)
	r.Result = core.Result{Outcome: core.AdmissionRefused, Reason: core.CustodyUnavailable}
	r.CleanupFailed, r.ExecutableCleanupFailed = true, true
	combined := core.PublicApplyPublicationResult{Apply: suppliedApplyResultFixture(t), Publication: core.ApplyPublicationStage{Stage: "evaluated", Result: &r}}
	var machine, human bytes.Buffer
	if err := WriteApplyPublicationJSON(&machine, combined); err != nil || bytes.Count(machine.Bytes(), []byte(`"cleanup_failed": true`)) != 1 || bytes.Count(machine.Bytes(), []byte(`"executable_cleanup_failed": true`)) != 1 {
		t.Error("combined JSON lost an independent cleanup fact", err)
	}
	if err := WriteApplyPublicationHuman(&human, combined); err != nil || !bytes.Contains(human.Bytes(), []byte("Warning: executable cleanup failed.\nWarning: source cleanup failed.\n")) {
		t.Error("combined human output lost an independent cleanup fact", err)
	}
}

// full_only: false
func TestGeneratedFileCloseCoalescesAndPreservesSelectedResult(t *testing.T) {
	original := suppliedApplyResultFixture(t)
	original.AddCleanupDiagnostic()
	beforeResult := original.Result
	beforeReceipt := bytes.Clone(original.Receipt)
	source := configurationSetPair(t, "aws", configuration.JSON, nil)
	got := configurationGeneratedMutationFile(t.Context(), original.RequestID, source.path, configuration.JSON, func(pair *configuration.Pair) ConfigurationApplyResult {
		field := reflect.ValueOf(pair.Editable).Elem().FieldByName("file")
		if field.IsNil() {
			t.Fatal("captured snapshot handle absent")
		}
		if err := (*os.File)(field.UnsafePointer()).Close(); err != nil {
			t.Fatal("controlled snapshot close", err)
		}
		return ConfigurationApplyResult{PublicApplyResult: original}
	})
	if got.Result != beforeResult || !bytes.Equal(got.Receipt, beforeReceipt) || len(got.Diagnostics) != 1 {
		t.Fatal("File cleanup changed selected result or duplicated its diagnostic")
	}
	for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman} {
		body, err := render(got.PublicApplyResult)
		if err != nil || !bytes.Contains(body, []byte("evidence-unavailable")) {
			t.Error("File cleanup hid complete result", err)
		}
	}
}
