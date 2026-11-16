package core

import (
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// Field-inventory cases retain their independently listed subjects and fields.
// Value-bearing cases separately assert complete typed sides and ownership.
func publicComparisonFactsMatch(t *testing.T, got contract.ComparisonPayload, expected []contract.Diagnostic) bool {
	t.Helper()
	var failures []contract.Diagnostic
	type changeKey struct {
		subject contract.DiagnosticSubject
		path    []contract.DiagnosticField
		action  contract.ComparisonChangeAction
	}
	var changes []changeKey
	for _, row := range expected {
		if row.Outcome == contract.DiagnosticUnable {
			failures = append(failures, row)
			continue
		}
		action := contract.ComparisonChanged
		switch row.Reason {
		case contract.ReasonObservedEntryAbsent, contract.ReasonObservedSettingAbsent:
			action = contract.ComparisonAdded
		case contract.ReasonExpectedEntryAbsent, contract.ReasonExpectedSettingAbsent:
			action = contract.ComparisonRemoved
		}
		changes = append(changes, changeKey{row.Subject, row.Path, action})
	}
	// Expected field lists are independent literals. Reuse only the existing
	// ordering owner, as the field-inventory cases did before partitioning.
	slices.SortFunc(changes, func(a, b changeKey) int {
		return comparePublicDiagnostics(contract.Diagnostic{Subject: a.subject, Path: a.path}, contract.Diagnostic{Subject: b.subject, Path: b.path})
	})
	if len(got.Diagnostics) != len(failures) || !slices.EqualFunc(got.Diagnostics, failures, func(a, b contract.Diagnostic) bool { return reflect.DeepEqual(a, b) }) {
		return false
	}
	if len(got.Changes) != len(changes) {
		return false
	}
	for at, want := range changes {
		change := got.Changes[at]
		if change.Subject != want.subject || !slices.Equal(change.Path, want.path) || change.Action != want.action {
			return false
		}
		if change.Before.State == contract.ComparisonPresent && change.Before.Value == nil || change.After.State == contract.ComparisonPresent && change.After.Value == nil {
			return false
		}
		switch want.action {
		case contract.ComparisonAdded:
			if change.Before.State != contract.ComparisonAbsent || change.Before.Value != nil || change.After.State != contract.ComparisonPresent {
				return false
			}
		case contract.ComparisonRemoved:
			if change.Before.State != contract.ComparisonPresent || change.After.State != contract.ComparisonAbsent || change.After.Value != nil {
				return false
			}
		case contract.ComparisonChanged:
			if change.Before.State != contract.ComparisonPresent || change.After.State != contract.ComparisonPresent {
				return false
			}
		}
	}
	return true
}

func appendExpectedPublicFields(rows []contract.Diagnostic, subject contract.DiagnosticSubject, reason contract.DiagnosticReason, fields ...contract.DiagnosticField) []contract.Diagnostic {
	for _, field := range fields {
		rows = append(rows, contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticDifference, Reason: reason})
	}
	return rows
}

func appendExpectedGeneratedFields(rows []contract.Diagnostic, subject contract.DiagnosticSubject) []contract.Diagnostic {
	for _, field := range []contract.DiagnosticField{contract.FieldEpoch, contract.FieldConfigContract, contract.FieldResourceContract, contract.FieldLifecycle, contract.FieldContentIntent, contract.FieldRetirement, contract.FieldCompletion} {
		rows = append(rows, contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{contract.FieldGenerated, field}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonObservedSettingAbsent})
	}
	return rows
}
