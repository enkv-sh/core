package core

import (
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicChangePlainValuesUseApplicationBytes(t *testing.T) {
	for _, fixture := range []struct {
		name                                string
		beforeEncoding, afterEncoding       uint8
		beforeRetained, afterRetained       string
		beforeApplication, afterApplication string
	}{
		{"raw-to-base64-same", 1, 2, "ABC", "QUJD", "ABC", "ABC"},
		{"raw-spelling-to-base64", 1, 2, "QUJD", "QUJD", "QUJD", "ABC"},
		{"base64-to-raw-same", 2, 1, "QUJD", "ABC", "ABC", "ABC"},
		{"base64-to-raw-spelling", 2, 1, "QUJD", "QUJD", "ABC", "QUJD"},
		{"raw-to-base64-changed", 1, 2, "ABC", "QUJE", "ABC", "ABD"},
		{"base64-to-raw-changed", 2, 1, "QUJD", "ABD", "ABC", "ABD"},
		{"raw-changed", 1, 1, "ABC", "ABD", "ABC", "ABD"},
		{"base64-changed", 2, 2, "QUJD", "QUJE", "ABC", "ABD"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			before := publicConfigurationFixture(t)
			entry := publicFixtureEntry(before, "plain")
			entry.Class = publicPresent(contract.Plain)
			entry.InputEncoding = publicPresent(fixture.beforeEncoding)
			entry.PlainValue = publicPresent([]byte(fixture.beforeRetained))
			before.Entries = publicPresent([]contract.PublicEntry{entry})
			after := ownPublicConfiguration(before)
			after.Entries.Value[0].InputEncoding = publicPresent(fixture.afterEncoding)
			after.Entries.Value[0].PlainValue = publicPresent([]byte(fixture.afterRetained))
			v := NewPublicConfigurationValidator(nil)
			got := comparePublicConfigurations(t.Context(), v.Validate(t.Context(), after), v.Validate(t.Context(), before))
			subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "plain"}
			var want []contract.ComparisonChange
			if fixture.beforeEncoding != fixture.afterEncoding {
				want = append(want, contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{contract.FieldInputEncoding}, Action: contract.ComparisonChanged, Before: presentChangeSide(contract.ComparisonUint(fixture.beforeEncoding)), After: presentChangeSide(contract.ComparisonUint(fixture.afterEncoding))})
			}
			// These fixed spellings independently encode ABC and ABD. Neither
			// expected application value comes from the production decoder.
			if fixture.beforeApplication != fixture.afterApplication {
				want = append(want, contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Action: contract.ComparisonChanged, Before: presentChangeSide(contract.ComparisonBytes(fixture.beforeApplication)), After: presentChangeSide(contract.ComparisonBytes(fixture.afterApplication))})
			}
			if got.Verdict != contract.ComparisonMismatch || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || !reflect.DeepEqual(got.Changes, want) {
				t.Fatalf("application meaning or representation difference lost: %+v, want %+v", got, want)
			}
			if string(before.Entries.Value[0].PlainValue.Value) != fixture.beforeRetained || string(after.Entries.Value[0].PlainValue.Value) != fixture.afterRetained {
				t.Fatal("comparison replaced retained source representation")
			}
		})
	}
	for _, encoding := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		for _, actualSide := range []bool{false, true} {
			for _, unavailable := range []bool{false, true} {
				name := fmt.Sprintf("encoding-%d/observed-%t/unavailable-%t", encoding, actualSide, unavailable)
				t.Run(name, func(t *testing.T) {
					before := publicConfigurationFixture(t)
					entry := publicFixtureEntry(before, "plain")
					entry.Class = publicPresent(contract.Plain)
					entry.InputEncoding = publicPresent(encoding)
					entry.PlainValue = publicPresent([]byte("ABC"))
					if encoding == contract.InputEncodingBase64 {
						entry.PlainValue = publicPresent([]byte("QUJD"))
					}
					before.Entries = publicPresent([]contract.PublicEntry{entry})
					// The explicit empty default keeps this case about the input
					// representation dependency when other facts are incomplete.
					before.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string{})}})
					after := ownPublicConfiguration(before)
					after.Store.Prefix = publicPresent("known-change")
					after.Entries.Value[0].PlainValue = publicPresent([]byte("ABD"))
					if encoding == contract.InputEncodingBase64 {
						after.Entries.Value[0].PlainValue = publicPresent([]byte("QUJE"))
					}
					target := &after.Entries.Value[0]
					if actualSide {
						target = &before.Entries.Value[0]
					}
					target.InputEncoding = publicPresent(uint8(99))
					reason := contract.ReasonInvalidInput
					if unavailable {
						target.InputEncoding = contract.PublicField[uint8]{State: contract.PublicUnavailable}
						reason = contract.ReasonPublicFactUnavailable
					}
					v := NewPublicConfigurationValidator(nil)
					got := comparePublicConfigurations(t.Context(), v.Validate(t.Context(), after), v.Validate(t.Context(), before))
					subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "plain"}
					failures := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{contract.FieldInputEncoding}, Outcome: contract.DiagnosticUnable, Reason: reason}}
					failures = append(failures, contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput})
					changes := []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPrefix}, Action: contract.ComparisonChanged, Before: presentChangeSide(contract.ComparisonText("team/prod")), After: presentChangeSide(contract.ComparisonText("known-change"))}}
					if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, failures) || !reflect.DeepEqual(got.Changes, changes) {
						t.Fatalf("unavailable representation produced a dependent value or lost independent truth: %+v", got)
					}
				})
			}
		}
	}

}
