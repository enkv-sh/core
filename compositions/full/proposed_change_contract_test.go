package compositionfull

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func proposedSide(value contract.ComparisonValue) contract.ComparisonSide {
	return contract.ComparisonSide{State: contract.ComparisonPresent, Value: value}
}
func proposedRecord(subject contract.DiagnosticSubject, field contract.DiagnosticField, before, after contract.ComparisonValue) contract.ComparisonChange {
	return contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{field}, Action: contract.ComparisonChanged, Before: proposedSide(before), After: proposedSide(after)}
}
func proposedResult(changes ...contract.ComparisonChange) ConfigurationComparisonResult {
	return ConfigurationComparisonResult{PublicComparisonResult: core.PublicComparisonResult{Context: core.ReaderOperationContext{Operation: contract.ReaderCompareOperation}, StateResult: contract.ReaderSuccess, ComparisonPayload: contract.ComparisonPayload{Verdict: contract.ComparisonMismatch, Changes: changes, DiagnosticsComplete: true, EvidenceLimit: contract.ComparisonEvidenceLimit, Observation: &contract.ComparisonObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{2}, SnapshotID: contract.ID{3}}}}, InstallationRequirements: InstallationRequirementComparison{Complete: true, Differences: []InstallationRequirementDifference{}}}
}

// full_only: false
func TestProposedChangeHumanGroupsSubjectsAndKeepsWholeMembership(t *testing.T) {
	r := proposedResult(
		proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "item"}, contract.FieldInputEncoding, contract.ComparisonUint(1), contract.ComparisonUint(2)),
		proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "item"}, contract.FieldMemberships,
			contract.ComparisonIDSet{{ID: contract.ID{1}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{2}, Change: contract.ComparisonMemberRemoved}},
			contract.ComparisonIDSet{{ID: contract.ID{1}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{3}, Change: contract.ComparisonMemberAdded}}),
	)
	body, err := RenderComparisonHuman(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(body, []byte(`Entry "item"`)) != 1 || !bytes.Contains(body, []byte("  input_encoding (changed)")) || !bytes.Contains(body, []byte("  memberships (changed)")) {
		t.Fatal("field changes were not grouped by their exact subject", string(body))
	}
	for _, want := range []string{"01" + strings.Repeat("00", 31) + " (unchanged)", "02" + strings.Repeat("00", 31) + " (removed)", "03" + strings.Repeat("00", 31) + " (added)"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatal("human membership omitted a complete member or disposition", want)
		}
	}
}

// full_only: false
func TestProposedChangeResultClosedValueArms(t *testing.T) {
	id := func(b byte) contract.ComparisonID { return contract.ComparisonID(contract.ID{b}) }
	destination := func(settings string) contract.ComparisonDestination {
		owned := make([]byte, len(settings))
		copy(owned, settings)
		return contract.ComparisonDestination{ConfigContractID: "config", ServiceContractID: "service", CanonicalSettings: owned, Capabilities: contract.OutputCapabilityWriteValue}
	}
	if contract.OutputCapabilityWriteValue != 4 {
		t.Fatal("independent capability literal changed")
	}
	for _, fixture := range []struct {
		name          string
		change        contract.ComparisonChange
		before, after string
	}{
		{"boolean", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRecovery}, contract.FieldEnabled, contract.ComparisonBoolean(false), contract.ComparisonBoolean(true)), `false`, `true`},
		{"uint", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, contract.FieldInputEncoding, contract.ComparisonUint(1), contract.ComparisonUint(2)), `"1"`, `"2"`},
		{"text", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectStore}, contract.FieldPrefix, contract.ComparisonText("before/\n雪"), contract.ComparisonText("")), `"before/\n雪"`, `""`},
		{"bytes", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, contract.FieldPlainValue, contract.ComparisonBytes{0, 10, 65}, contract.ComparisonBytes{0, 10, 66}), `{"base64":"AApB","byte_length":3}`, `{"base64":"AApC","byte_length":3}`},
		{"id", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectDomain}, contract.FieldDomainID, id(1), id(2)), `"01` + strings.Repeat("00", 31) + `"`, `"02` + strings.Repeat("00", 31) + `"`},
		{"id-set", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, contract.FieldMemberships, contract.ComparisonIDSet{{ID: contract.ID{1}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{2}, Change: contract.ComparisonMemberRemoved}}, contract.ComparisonIDSet{{ID: contract.ID{1}, Change: contract.ComparisonMemberUnchanged}, {ID: contract.ID{3}, Change: contract.ComparisonMemberAdded}}), `[{"id":"01` + strings.Repeat("00", 31) + `","change":"unchanged"},{"id":"02` + strings.Repeat("00", 31) + `","change":"removed"}]`, `[{"id":"01` + strings.Repeat("00", 31) + `","change":"unchanged"},{"id":"03` + strings.Repeat("00", 31) + `","change":"added"}]`},
		{"text-set", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}}, contract.FieldDestinations, contract.ComparisonTextSet{"a"}, contract.ComparisonTextSet{}), `["a"]`, `[]`},
		{"groups", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldGroups, contract.ComparisonGroups{{"a", "b"}}, contract.ComparisonGroups{{"a"}, {"b"}}), `[["a","b"]]`, `[["a"],["b"]]`},
		{"destination", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "out"}, contract.FieldDestination, destination("null"), destination("[]")), `{"config_contract":"config","service_contract":"service","settings":{"base64":"bnVsbA==","byte_length":4},"policy":{"contract":"","data":{"base64":"","byte_length":0}},"capabilities":"4"}`, `{"config_contract":"config","service_contract":"service","settings":{"base64":"W10=","byte_length":2},"policy":{"contract":"","data":{"base64":"","byte_length":0}},"capabilities":"4"}`},
		{"policy", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "out", Name: ""}, contract.FieldConsumerPolicy, contract.ComparisonPolicy{ContractID: "policy", Data: []byte{0}}, contract.ComparisonPolicy{ContractID: "policy", Data: []byte{255}}), `{"contract":"policy","data":{"base64":"AA==","byte_length":1}}`, `{"contract":"policy","data":{"base64":"/w==","byte_length":1}}`},
		{"bounds", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "out", Name: ""}, contract.FieldWriteValueBounds, contract.ComparisonBounds{Minimum: 0, Maximum: 10}, contract.ComparisonBounds{Minimum: 1, Maximum: 20}), `{"minimum":"0","maximum":"10"}`, `{"minimum":"1","maximum":"20"}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body, err := RenderComparisonJSON(proposedResult(fixture.change))
			if err != nil || len(body) != cap(body) || !bytes.HasPrefix(body, []byte("{\n  ")) || !bytes.HasSuffix(body, []byte("\n")) {
				t.Fatal("closed readable value refused", err)
			}
			var got struct {
				Payload struct {
					Changes []struct {
						Before, After struct{ Value json.RawMessage }
					}
				}
			}
			if json.Unmarshal(body, &got) != nil || len(got.Payload.Changes) != 1 {
				t.Fatal("complete closed change missing")
			}
			for _, side := range []struct {
				got  json.RawMessage
				want string
			}{{got.Payload.Changes[0].Before.Value, fixture.before}, {got.Payload.Changes[0].After.Value, fixture.after}} {
				var actual, expected interface{}
				if json.Unmarshal(side.got, &actual) != nil || json.Unmarshal([]byte(side.want), &expected) != nil || !reflect.DeepEqual(actual, expected) {
					t.Fatalf("independent value differs: got=%s want=%s", side.got, side.want)
				}
			}
		})
	}
}

// full_only: false
func TestProposedChangeResultRejectsUnprovedOrOpenSides(t *testing.T) {
	for _, damage := range []string{"unknown-field", "wrong-type", "reserved-null", "absent-value", "present-no-value", "wrong-action", "equal-values", "unknown-member-change", "wrong-member-classification", "duplicate-field", "no-observation", "missing-recipient-id"} {
		t.Run(damage, func(t *testing.T) {
			change := proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, contract.FieldPlainValue, contract.ComparisonBytes{0}, contract.ComparisonBytes{1})
			r := proposedResult(change)
			switch damage {
			case "unknown-field":
				r.Changes[0].Path[0] = "ciphertext"
			case "wrong-type":
				r.Changes[0].After.Value = contract.ComparisonText("private envelope sentinel")
			case "reserved-null":
				r.Changes[0].After.Value = contract.ComparisonNull{}
			case "absent-value":
				r.Changes[0].Action = contract.ComparisonAdded
				r.Changes[0].Before.State = contract.ComparisonAbsent
			case "present-no-value":
				r.Changes[0].After.Value = nil
			case "wrong-action":
				r.Changes[0].Action = "performed"
			case "equal-values":
				r.Changes[0].After.Value = contract.ComparisonBytes{0}
			case "unknown-member-change", "wrong-member-classification":
				r.Changes[0].Path[0] = contract.FieldMemberships
				r.Changes[0].Before.Value = contract.ComparisonIDSet{{ID: contract.ID{1}, Change: contract.ComparisonMemberRemoved}}
				r.Changes[0].After.Value = contract.ComparisonIDSet{{ID: contract.ID{2}, Change: contract.ComparisonMemberAdded}}
				if damage == "unknown-member-change" {
					r.Changes[0].After.Value.(contract.ComparisonIDSet)[0].Change = "secret-changed"
				} else {
					r.Changes[0].After.Value.(contract.ComparisonIDSet)[0].Change = contract.ComparisonMemberUnchanged
				}
			case "duplicate-field":
				r.Changes = append(r.Changes, r.Changes[0])
			case "no-observation":
				r.Observation = nil
			case "missing-recipient-id":
				r.Changes[0] = proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRecipient}, contract.FieldDisplayName, contract.ComparisonText("a"), contract.ComparisonText("b"))
			}
			for _, render := range []func(ConfigurationComparisonResult) ([]byte, error){RenderComparisonJSON, RenderComparisonHuman} {
				if body, err := render(r); err != ErrReaderResult || body != nil {
					t.Fatal("unproved/open side escaped", err)
				}
			}
		})
	}
}

// full_only: false
func TestProposedChangeHumanPreviewsIncludeChangedRegion(t *testing.T) {
	before := strings.Repeat("雪", 300) + "BEFORE" + strings.Repeat("y", 1000)
	after := strings.Repeat("雪", 300) + "AFTER!" + strings.Repeat("y", 1000)
	owned := func(s string) contract.ComparisonBytes {
		body := make(contract.ComparisonBytes, len(s))
		copy(body, s)
		return body
	}
	r := proposedResult(proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, contract.FieldPlainValue, owned(before), owned(after)))
	body, err := RenderComparisonHuman(r)
	if err != nil || !utf8.Valid(body) || !bytes.HasPrefix(body, []byte("Plan: success\nPublic configuration: proposed changes follow.\n")) || !bytes.Contains(body, []byte("BEFORE")) || !bytes.Contains(body, []byte("AFTER!")) || !bytes.Contains(body, []byte("of 1906")) || len(body) > 6000 || !bytes.Contains(body, []byte(`a/\n雪`)) {
		t.Fatal("bounded changed-region preview lost facts", err, string(body))
	}
	jsonBody, err := RenderComparisonJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Payload struct {
			Changes []struct {
				Before, After struct {
					Value struct {
						Base64 string
						Length int `json:"byte_length"`
					}
				}
			}
		}
	}
	if json.Unmarshal(jsonBody, &decoded) != nil || len(decoded.Payload.Changes) != 1 || decoded.Payload.Changes[0].Before.Value.Length != len(before) || decoded.Payload.Changes[0].After.Value.Length != len(after) {
		t.Fatal("JSON previewed a complete value")
	}
	r.Changes[0].Before.Value, r.Changes[0].After.Value = contract.ComparisonBytes{0, 255}, contract.ComparisonBytes{1, 254, 0}
	body, err = RenderComparisonHuman(r)
	if err != nil || !bytes.Contains(body, []byte("2 bytes")) || !bytes.Contains(body, []byte("3 bytes")) || bytes.Contains(body, []byte("AP8=")) {
		t.Fatal("binary human view lost lengths or copied payload", err)
	}
	for _, fixture := range []struct {
		name   string
		change contract.ComparisonChange
		labels bool
		long   bool
	}{
		{"controls-subject-and-value", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "out", Name: "name\x7f\u0085雪"}, contract.FieldConsumerLocator, contract.ComparisonText("before\x7f\u0085雪"), contract.ComparisonText("after\x7f\u0085雪")), false, false},
		{"controls-recipient-labels", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: contract.ID{4}}, contract.FieldDisplayName, contract.ComparisonText("before\x7f\u0085雪"), contract.ComparisonText("after\x7f\u0085雪")), true, false},
		{"controls-routing-subject-and-set", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "name\x7f\u0085雪"}}, contract.FieldDestinations, contract.ComparisonTextSet{"before\x7f\u0085雪"}, contract.ComparisonTextSet{"after\x7f\u0085雪"}), false, false},
		{"controls-groups", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldGroups, contract.ComparisonGroups{{"before\x7f\u0085雪"}}, contract.ComparisonGroups{{"after\x7f\u0085雪"}}), false, false},
		{"controls-bounded-preview", proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: contract.ID{4}}, contract.FieldDisplayName, contract.ComparisonText(strings.Repeat("雪", 60)+"BEFORE\x7f\u0085"+strings.Repeat("y", 40)), contract.ComparisonText(strings.Repeat("雪", 60)+"AFTER!\x7f\u0085"+strings.Repeat("y", 40))), false, true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			r := proposedResult(fixture.change)
			if fixture.labels {
				beforeName, afterName := "local-before\x7f\u0085雪", "local-after\x7f\u0085雪"
				beforeDisplay, afterDisplay := "before\x7f\u0085雪", "after\x7f\u0085雪"
				r.BeforeRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{4}, Name: &beforeName, DisplayName: &beforeDisplay}}
				r.AfterRecipients = []contract.ComparisonRecipientLabel{{RecipientID: contract.ID{4}, Name: &afterName, DisplayName: &afterDisplay}}
			}
			private := configurationPlanningResult(r)
			private.PrivateComplete = true
			for _, render := range []func() ([]byte, error){func() ([]byte, error) { return RenderComparisonHuman(r) }, func() ([]byte, error) { return RenderPlanningHuman(private) }} {
				body, err := render()
				if err != nil || len(body) != cap(body) || !utf8.Valid(body) || len(body) > 6000 || bytes.Contains(body, []byte{'\x7f'}) || bytes.Contains(body, []byte("\u0085")) || !bytes.Contains(body, []byte(`\x7f\u0085`)) {
					t.Fatal("human controls were literal or bounded UTF-8 quoting changed", err, string(body))
				}
				if fixture.labels {
					for _, fragment := range []string{`name "local-before\x7f\u0085雪"`, `name "local-after\x7f\u0085雪"`, `display_name "before\x7f\u0085雪"`, `display_name "after\x7f\u0085雪"`} {
						if !bytes.Contains(body, []byte(fragment)) {
							t.Fatal("shared human label was omitted or changed", fragment)
						}
					}
				}
				if fixture.long && (!bytes.Contains(body, []byte("preview bytes ")) || !bytes.Contains(body, []byte("of 229")) || !bytes.Contains(body, []byte("BEFORE")) || !bytes.Contains(body, []byte("AFTER!"))) {
					t.Fatal("bounded text preview lost controls or the changed region")
				}
			}
			for _, render := range []func() ([]byte, error){func() ([]byte, error) { return RenderComparisonJSON(r) }, func() ([]byte, error) { return RenderPlanningJSON(private) }} {
				body, err := render()
				var decoded struct {
					Payload struct {
						Changes []struct {
							Subject struct {
								Name  string
								Entry struct{ Name string }
							}
							Before, After struct{ Value json.RawMessage }
						}
						Labels struct {
							Before, After []struct {
								Name        *string
								DisplayName *string `json:"display_name"`
							}
						} `json:"recipient_labels"`
					}
				}
				if err != nil || json.Unmarshal(body, &decoded) != nil || len(decoded.Payload.Changes) != 1 || decoded.Payload.Changes[0].Subject.Name != fixture.change.Subject.Name || decoded.Payload.Changes[0].Subject.Entry.Name != fixture.change.Subject.RoutingKey.EntryName {
					t.Fatal("JSON lost the exact control-bearing subject", err)
				}
				for _, pair := range []struct {
					got  json.RawMessage
					want contract.ComparisonValue
				}{{decoded.Payload.Changes[0].Before.Value, fixture.change.Before.Value}, {decoded.Payload.Changes[0].After.Value, fixture.change.After.Value}} {
					wantJSON, err := json.Marshal(pair.want)
					var gotValue, wantValue interface{}
					if err != nil || json.Unmarshal(pair.got, &gotValue) != nil || json.Unmarshal(wantJSON, &wantValue) != nil || !reflect.DeepEqual(gotValue, wantValue) {
						t.Fatal("JSON did not preserve the complete control-bearing value")
					}
				}
				if fixture.labels {
					for _, pair := range []struct {
						got []struct {
							Name        *string
							DisplayName *string `json:"display_name"`
						}
						want []contract.ComparisonRecipientLabel
					}{{decoded.Payload.Labels.Before, r.BeforeRecipients}, {decoded.Payload.Labels.After, r.AfterRecipients}} {
						if len(pair.got) != 1 || !reflect.DeepEqual(pair.got[0].Name, pair.want[0].Name) || !reflect.DeepEqual(pair.got[0].DisplayName, pair.want[0].DisplayName) {
							t.Fatal("JSON did not preserve complete shared control-bearing labels")
						}
					}
				}
			}
		})
	}

}

// full_only: false
func TestProposedChangeResultMaximumMembershipFacts(t *testing.T) {
	changes := make([]contract.ComparisonChange, 512)
	for at := range changes {
		before, after := make(contract.ComparisonIDSet, 8), make(contract.ComparisonIDSet, 8)
		before[0], after[0] = contract.ComparisonMember{ID: contract.ID{1}, Change: contract.ComparisonMemberUnchanged}, contract.ComparisonMember{ID: contract.ID{1}, Change: contract.ComparisonMemberUnchanged}
		for member := 1; member < 8; member++ {
			before[member] = contract.ComparisonMember{ID: contract.ID{byte(member + 1)}, Change: contract.ComparisonMemberRemoved}
			after[member] = contract.ComparisonMember{ID: contract.ID{byte(member + 8)}, Change: contract.ComparisonMemberAdded}
		}
		changes[at] = proposedRecord(contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: fmt.Sprintf("entry-%03d", at)}, contract.FieldMemberships, before, after)
	}
	r := proposedResult(changes...)
	body, err := RenderComparisonJSON(r)
	if err != nil || len(body) != cap(body) {
		t.Fatal("joint 4096-member side refused", err)
	}
	var got struct {
		Payload struct {
			Changes []struct {
				Before, After struct{ Value []struct{ ID, Change string } }
			}
		}
	}
	if json.Unmarshal(body, &got) != nil || len(got.Payload.Changes) != 512 {
		t.Fatal("membership field set incomplete")
	}
	for _, change := range got.Payload.Changes {
		if len(change.Before.Value) != 8 || len(change.After.Value) != 8 {
			t.Fatal("complete membership sides lost")
		}
		for at := 0; at < 8; at++ {
			beforeID, afterID := byte(at+1), byte(at+8)
			beforeChange, afterChange := "removed", "added"
			if at == 0 {
				beforeID, afterID = 1, 1
				beforeChange, afterChange = "unchanged", "unchanged"
			}
			if change.Before.Value[at].ID != fmt.Sprintf("%02x", beforeID)+strings.Repeat("00", 31) || change.After.Value[at].ID != fmt.Sprintf("%02x", afterID)+strings.Repeat("00", 31) || change.Before.Value[at].Change != beforeChange || change.After.Value[at].Change != afterChange {
				t.Fatal("exact full membership or classification lost")
			}
		}
	}
	r.Changes[0].After.Value = append(make(contract.ComparisonIDSet, 0, 9), r.Changes[0].After.Value.(contract.ComparisonIDSet)...)
	r.Changes[0].After.Value = append(r.Changes[0].After.Value.(contract.ComparisonIDSet), contract.ComparisonMember{ID: contract.ID{16}, Change: contract.ComparisonMemberAdded})
	if body, err := RenderComparisonJSON(r); err != ErrReaderResult || body != nil {
		t.Fatal("one-over joint membership side escaped", err)
	}
}
