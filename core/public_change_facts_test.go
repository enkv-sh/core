package core

import (
	"context"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// Fixed byte triples and empty values below are semantic expectations. No
// production comparison, result encoder or result value derives them.

// full_only: false
func TestPublicChangeFactsPartitionIndependentFailures(t *testing.T) {
	before := publicConfigurationFixture(t)
	entry := publicFixtureEntry(before, "a/\n雪")
	entry.Class = publicPresent(contract.Plain)
	entry.PlainValue = publicPresent([]byte{0, 10, 65})
	before.Entries = publicPresent([]contract.PublicEntry{entry})
	after := ownPublicConfiguration(before)
	after.Entries.Value[0].PlainValue = publicPresent([]byte{0, 10, 66})
	after.Recipients.Value[1].DisplayName = publicPresent("")
	after.Store.Region = contract.PublicField[string]{State: contract.PublicUnavailable}
	v := NewPublicConfigurationValidator(nil)
	desired, actual := v.Validate(t.Context(), after), v.Validate(t.Context(), before)
	got := comparePublicConfigurations(t.Context(), desired, actual)
	wantFailures := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldRegion}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}
	wantChanges := []contract.ComparisonChange{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Action: contract.ComparisonChanged,
			Before: presentChangeSide(contract.ComparisonBytes{0, 10, 65}), After: presentChangeSide(contract.ComparisonBytes{0, 10, 66})},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: contract.ID{3}}, Path: []contract.DiagnosticField{contract.FieldDisplayName}, Action: contract.ComparisonChanged,
			Before: presentChangeSide(contract.ComparisonText("unassigned")), After: presentChangeSide(contract.ComparisonText(""))},
	}
	if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, wantFailures) {
		t.Errorf("verified changes were duplicated as diagnostics or an independent failure was lost: verdict=%s diagnostics=%+v", got.Verdict, got.Diagnostics)
	}
	if !reflect.DeepEqual(got.Changes, wantChanges) {
		t.Errorf("independent verified changes differ: got=%+v want=%+v", got.Changes, wantChanges)
	}
	// The result outlives both normalized comparison owners, not only the
	// original caller input that validation already copied.
	clear(desired.Configuration.Entries.Value[0].PlainValue.Value)
	clear(actual.Configuration.Entries.Value[0].PlainValue.Value)
	desired.Configuration.Recipients.Value[1].DisplayName.Value = "replaced proposal label"
	actual.Configuration.Recipients.Value[1].DisplayName.Value = "replaced observed label"
	if !reflect.DeepEqual(got.Changes, wantChanges) {
		t.Error("change values borrow normalized comparison owners")
	}
}

// full_only: false
func TestPublicChangeFactsCompleteDifferenceHasNoFailureDiagnostics(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		before := publicConfigurationFixture(t)
		before.Recipients.Value[1].DisplayName = publicPresent("")
		after := ownPublicConfiguration(before)
		after.Recipients.Value[1].DisplayName = publicPresent("owner/\n雪")
		want := []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: contract.ID{3}}, Path: []contract.DiagnosticField{contract.FieldDisplayName}, Action: contract.ComparisonChanged,
			Before: presentChangeSide(contract.ComparisonText("")), After: presentChangeSide(contract.ComparisonText("owner/\n雪"))}}
		assertCompletePublicChanges(t, after, before, want)
	})
	t.Run("present-empty-bytes", func(t *testing.T) {
		before := plainChangeConfiguration(t)
		after := ownPublicConfiguration(before)
		after.Entries.Value[0].PlainValue = publicPresent([]byte{})
		want := []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Action: contract.ComparisonChanged,
			Before: presentChangeSide(contract.ComparisonBytes{0, 10, 65}), After: presentChangeSide(contract.ComparisonBytes{})}}
		assertCompletePublicChanges(t, after, before, want)
	})
	for _, removed := range []bool{false, true} {
		name := "absent-to-empty-route"
		if removed {
			name = "empty-route-to-absent"
		}
		t.Run(name, func(t *testing.T) {
			before := publicConfigurationFixture(t)
			before.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(before, "")})
			after := ownPublicConfiguration(before)
			// An omitted domain default normalizes to empty. An entry override
			// retains the required distinction between absence and empty.
			key := contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: ""}
			after.Routing = publicPresent([]contract.PublicRoutingRule{{Key: key, Destinations: publicPresent([]string{})}})
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: key}
			absent := contract.ComparisonSide{State: contract.ComparisonAbsent}
			want := []contract.ComparisonChange{
				{Subject: subject, Path: []contract.DiagnosticField{contract.FieldDestinations}, Action: contract.ComparisonAdded, Before: absent, After: presentChangeSide(contract.ComparisonTextSet{})},
				{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPresence}, Action: contract.ComparisonAdded, Before: absent, After: presentChangeSide(contract.ComparisonBoolean(true))},
			}
			if removed {
				before, after = after, before
				for at := range want {
					want[at].Action = contract.ComparisonRemoved
					want[at].Before, want[at].After = want[at].After, want[at].Before
				}
			}
			assertCompletePublicChanges(t, after, before, want)
		})
	}
	t.Run("complete-memberships-and-shared-labels", func(t *testing.T) {
		before := plainChangeConfiguration(t)
		recipient := before.Recipients.Value[1]
		recipient.RecipientID, recipient.DisplayName = contract.ID{4}, publicPresent("")
		before.Recipients.Value = append(before.Recipients.Value, recipient)
		before.Entries.Value[0].Memberships = publicPresent([]contract.ID{{2}, {3}})
		second := before.Entries.Value[0]
		second.Name = "second"
		second.PlainValue = publicPresent([]byte{0, 10, 65})
		second.Memberships = publicPresent([]contract.ID{{2}, {3}})
		before.Entries.Value = append(before.Entries.Value, second)
		after := ownPublicConfiguration(before)
		for at := range after.Entries.Value {
			after.Entries.Value[at].Memberships = publicPresent([]contract.ID{{2}, {4}})
		}
		want := []contract.ComparisonChange{
			{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, Path: []contract.DiagnosticField{contract.FieldMemberships}, Action: contract.ComparisonChanged,
				Before: presentChangeSide(contract.ComparisonIDSet{{ID: contract.ID{2}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{3}, Change: contract.ComparisonMemberRemoved}}),
				After:  presentChangeSide(contract.ComparisonIDSet{{ID: contract.ID{2}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{4}, Change: contract.ComparisonMemberAdded}})},
			{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "second"}, Path: []contract.DiagnosticField{contract.FieldMemberships}, Action: contract.ComparisonChanged,
				Before: presentChangeSide(contract.ComparisonIDSet{{ID: contract.ID{2}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{3}, Change: contract.ComparisonMemberRemoved}}),
				After:  presentChangeSide(contract.ComparisonIDSet{{ID: contract.ID{2}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{4}, Change: contract.ComparisonMemberAdded}})},
		}
		v := NewPublicConfigurationValidator(nil)
		desired, actual := v.Validate(t.Context(), after), v.Validate(t.Context(), before)
		got := comparePublicConfigurations(t.Context(), desired, actual)
		assertPublicChangePayload(t, got, want)
		wantLabels := []contract.ComparisonRecipientLabel{
			{RecipientID: contract.ID{2}, DisplayName: changeLabel("authority")},
			{RecipientID: contract.ID{3}, DisplayName: changeLabel("unassigned")},
			{RecipientID: contract.ID{4}, DisplayName: changeLabel("")},
		}
		if !reflect.DeepEqual(got.BeforeRecipients, wantLabels) || !reflect.DeepEqual(got.AfterRecipients, wantLabels) {
			t.Errorf("shared labels lost exact IDs, available empty labels or absent source names: before=%+v after=%+v", got.BeforeRecipients, got.AfterRecipients)
		}
		for at := range desired.Configuration.Entries.Value {
			clear(desired.Configuration.Entries.Value[at].Memberships.Value)
			clear(actual.Configuration.Entries.Value[at].Memberships.Value)
		}
		for at := range desired.Configuration.Recipients.Value {
			desired.Configuration.Recipients.Value[at].DisplayName.Value = "replaced proposal label"
			actual.Configuration.Recipients.Value[at].DisplayName.Value = "replaced observed label"
		}
		if !reflect.DeepEqual(got.Changes, want) || !reflect.DeepEqual(got.BeforeRecipients, wantLabels) || !reflect.DeepEqual(got.AfterRecipients, wantLabels) {
			t.Error("membership or shared label facts borrow normalized comparison owners")
		}
	})
	t.Run("late-shared-proof-clears-values", func(t *testing.T) {
		observation := &contract.ComparisonObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{2}, SnapshotID: contract.ID{3}}
		out := PublicComparisonResult{ComparisonPayload: newComparisonPayload(contract.ScopeComplete), StateResult: contract.ReaderSuccess}
		out.Verdict, out.Observation = contract.ComparisonMismatch, observation
		out.Changes = []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Action: contract.ComparisonChanged,
			Before: presentChangeSide(contract.ComparisonBytes{0, 10, 65}), After: presentChangeSide(contract.ComparisonBytes{0, 10, 66})}}
		out.BeforeRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{2}, DisplayName: changeLabel("authority")}}
		out.AfterRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{2}, DisplayName: changeLabel("authority")}}
		out.finishComparisonFailure(readerFailure{Result: failure(IntegrityFailure, InvalidProof), diagnostic: contract.ReasonProofInvalid})
		want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonProofInvalid}}
		if out.Verdict != contract.ComparisonUnable || out.StateResult != contract.ReaderPositiveDefect || !out.DiagnosticsComplete || out.Observation != observation || !reflect.DeepEqual(out.Diagnostics, want) {
			t.Error("shared proof failure lost its fixed observation or exact failure")
		}
		if len(out.Changes) != 0 || len(out.BeforeRecipients) != 0 || len(out.AfterRecipients) != 0 {
			t.Error("shared proof failure retained dependent values or labels")
		}
		for _, scope := range out.CheckedScope {
			if scope.Status != contract.ScopeUnchecked {
				t.Error("shared proof failure retained checked scope", scope)
			}
		}
	})
}

func presentChangeSide(value contract.ComparisonValue) contract.ComparisonSide {
	return contract.ComparisonSide{State: contract.ComparisonPresent, Value: value}
}

func changeLabel(value string) *string { return &value }

func plainChangeConfiguration(t *testing.T) contract.PublicConfiguration {
	t.Helper()
	input := publicConfigurationFixture(t)
	entry := publicFixtureEntry(input, "a/\n雪")
	entry.Class = publicPresent(contract.Plain)
	entry.PlainValue = publicPresent([]byte{0, 10, 65})
	input.Entries = publicPresent([]contract.PublicEntry{entry})
	return input
}

func assertCompletePublicChanges(t *testing.T, after, before contract.PublicConfiguration, want []contract.ComparisonChange) {
	t.Helper()
	v := NewPublicConfigurationValidator(nil)
	desired, actual := v.Validate(context.Background(), after), v.Validate(context.Background(), before)
	got := comparePublicConfigurations(context.Background(), desired, actual)
	assertPublicChangePayload(t, got, want)
}

func assertPublicChangePayload(t *testing.T, got contract.ComparisonPayload, want []contract.ComparisonChange) {
	t.Helper()
	if got.Verdict != contract.ComparisonMismatch || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 {
		t.Errorf("a complete public change was encoded as a failure diagnostic: verdict=%s diagnostics=%+v", got.Verdict, got.Diagnostics)
	}
	if !reflect.DeepEqual(got.Changes, want) {
		t.Errorf("complete public changes differ: got=%+v want=%+v", got.Changes, want)
	}
}
