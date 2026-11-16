package core

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicInspectionReceiptCaptureRequiresJoinedGETOnly(t *testing.T) {
	valid := []nativeprocess.Event{
		{Kind: "source-kind", SourceKind: "aws-assume-role", Count: 1, Matched: true},
		{Kind: "http-start", Operation: "head-read", Sequence: 1, Sent: true, ObjectKeySHA256: strings.Repeat("1", 64)},
		{Kind: "http-return", Operation: "head-read", Sequence: 1, Sent: true, Status: 200, ObjectKeySHA256: strings.Repeat("1", 64)},
		{Kind: "footer"},
	}
	for _, name := range []string{"valid", "no-footer", "unjoined", "unmatched-return", "unsent", "no-success", "failed-child", "source-mismatch", "write", "list", "kms-public", "kms-sign", "kms-decrypt", "constructor", "generator", "plaintext"} {
		t.Run(name, func(t *testing.T) {
			events := append([]nativeprocess.Event(nil), valid...)
			switch name {
			case "no-footer":
				events = events[:3]
			case "unjoined":
				events = append(events[:2], events[3])
			case "unmatched-return":
				events[2].Sequence = 2
			case "unsent":
				events[1].Sent, events[2].Sent = false, false
			case "no-success":
				events[2].Status = 403
			case "failed-child":
				events[3].Code = 2
			case "source-mismatch":
				events[0].Matched = false
			case "write", "list", "kms-public", "kms-sign", "kms-decrypt":
				operation := name
				if name == "write" {
					operation = "head-write"
				}
				if name == "list" {
					operation = "store-list"
				}
				events[1].Operation, events[2].Operation = operation, operation
			case "constructor":
				events = append([]nativeprocess.Event{{Kind: "construction", Count: 1, Operation: "key-access", Role: "authority"}}, events...)
			case "generator":
				events = append([]nativeprocess.Event{{Kind: "generator-entry"}}, events...)
			case "plaintext":
				events = append([]nativeprocess.Event{{Kind: "plaintext", Count: 1, Matched: true, EntrySHA256: strings.Repeat("a", 64)}}, events...)
			}
			var body bytes.Buffer
			for _, event := range events {
				if err := json.NewEncoder(&body).Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			capture, err := nativeprocess.InspectCapture(body.Bytes())
			got := err == nil && publicInspectionReadCapture(capture)
			if got != (name == "valid") {
				t.Fatal("inspection accepted an incomplete join or a capability outside object GET")
			}
		})
	}
}

// full_only: false
func TestPublicInspectionReceiptPayloadRequiresCompleteFacts(t *testing.T) {
	const domain = "1111111111111111111111111111111111111111111111111111111111111111"
	const current = "2222222222222222222222222222222222222222222222222222222222222222"
	const historic = "3333333333333333333333333333333333333333333333333333333333333333"
	for _, form := range []struct{ operation, schema, payload string }{
		{"inspect", "InspectionPayload/v1", `{"schema":"InspectionPayload/v1","form":"domain","observation":{"head_revision_id":"` + current + `"},"entries":[{"name":"local-plain"},{"name":"secret"}],"recipients":["authority","consumer"],"domain_warning_bits":0}`},
		{"inspect-recipient", "InspectionPayload/v1", `{"schema":"InspectionPayload/v1","form":"recipient","observation":{"head_revision_id":"` + current + `"},"recipient_id":"consumer","entries":[{"name":"secret","raw_length":15}]}`},
		{"receipt-list", "ReceiptPayload/v1", `{"schema":"ReceiptPayload/v1","form":"list","observation":{"head_revision_id":"` + current + `"},"receipts":[{"operation_id":"apply","observed_revision_id":"` + current + `"},{"operation_id":"init","observed_revision_id":"` + historic + `"}]}`},
		{"receipt-detail", "ReceiptPayload/v1", `{"schema":"ReceiptPayload/v1","form":"detail","observation":{"head_revision_id":"` + current + `"},"current_domain_warning_bits":0,"receipt":{"observed_revision_id":"` + historic + `","state_result":1,"warning_bits":18446744073709551615,"evidence_ceiling":5},"encoded_receipt":"AQID","authenticity":"authenticated-retained","retention":"retained"}`},
	} {
		t.Run(form.operation, func(t *testing.T) {
			// This literal envelope is independent of the matcher. Each payload is
			// intentionally small: these tests establish assertion semantics only.
			body := `{"schema":"ProductResult/v1","operation_kind":"` + form.operation + `","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","request_id":"` + domain + `","operation_id":"` + current + `","request_identity":"` + historic + `","replay_identity":"none","domain_id":"` + domain + `","failure_reason":"","result":{"outcome":"observed_current","reason":"none","observed_revision":"` + current + `","commit_may_have_occurred":false},"evidence_ceiling":"canonical","effects":[],"outputs":[],"duties":[],"hazards":[],"capsule_policy":"none","operation_payload":"` + form.schema + `","payload":` + form.payload + `}`
			check := func(child publicChildResult) bool {
				return publicInspectionPayloadMatches(child, form.operation, form.schema, domain, current, json.RawMessage(form.payload))
			}
			if !check(publicChildResult{Body: []byte(body)}) {
				t.Fatal("complete independent expected facts refused")
			}
			for name, tc := range map[string]struct {
				child publicChildResult
				want  string
			}{
				"exit":           {publicChildResult{Code: 1, Body: []byte(body)}, "exit"},
				"diagnostic":     {publicChildResult{DiagnosticBytes: 1, Body: []byte(body)}, "exit"},
				"malformed":      {publicChildResult{Body: []byte("{")}, "envelope"},
				"envelope":       {publicChildResult{Body: []byte(strings.Replace(body, `"state_result":"success"`, `"state_result":"unavailable"`, 1))}, "envelope"},
				"outer-schema":   {publicChildResult{Body: []byte(strings.Replace(body, `"operation_payload":"`+form.schema+`"`, `"operation_payload":"different"`, 1))}, "schema"},
				"payload-schema": {publicChildResult{Body: []byte(strings.Replace(body, `"schema":"`+form.schema+`"`, `"schema":"different"`, 1))}, "schema"},
				"payload":        {publicChildResult{Body: []byte(strings.Replace(body, `"form":`, `"wrong_form":`, 1))}, "payload"},
			} {
				t.Run("failure-class/"+name, func(t *testing.T) {
					if got := publicInspectionPayloadFailure(tc.child, form.operation, form.schema, domain, current, json.RawMessage(form.payload)); got != tc.want {
						t.Fatalf("failure class: got %q, want %q", got, tc.want)
					}
				})
			}
			if got := publicInspectionFailure(publicChildResult{Body: []byte(body)}, form.operation, form.schema, domain, current, json.RawMessage(form.payload)); got != "capture" {
				t.Fatal("missing capture did not retain its failure class")
			}
			for name, mutate := range map[string]func(string) string{
				"current-observation": func(s string) string {
					return strings.Replace(s, `"head_revision_id":"`+current+`"`, `"head_revision_id":"`+historic+`"`, 1)
				},
				"form": func(s string) string { return strings.Replace(s, `"form":`, `"other_form":`, 1) },
				"effect": func(s string) string {
					return strings.Replace(s, `"effect_summary":"not-applicable"`, `"effect_summary":"complete"`, 1)
				},
				"unknown-field": func(s string) string {
					return strings.Replace(s, `"payload":{`, `"payload":{"output":{"leak":true},`, 1)
				},
				"missing-field": func(s string) string { return strings.Replace(s, `"observation":`, `"lost_observation":`, 1) },
				"commit-ambiguity": func(s string) string {
					return strings.Replace(s, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true`, 1)
				},
				"truncated": func(s string) string { return s[:len(s)-1] },
			} {
				t.Run(name, func(t *testing.T) {
					if check(publicChildResult{Body: []byte(mutate(body))}) {
						t.Fatal("changed or incomplete query facts accepted")
					}
				})
			}
			for name, changed := range map[string]string{
				"entry-scope":         strings.Replace(body, `"name":"secret"`, `"name":"local-plain"`, 1),
				"receipt-bytes":       strings.Replace(body, `"encoded_receipt":"AQID"`, `"encoded_receipt":"AQIE"`, 1),
				"historical-revision": strings.Replace(body, `"observed_revision_id":"`+historic+`"`, `"observed_revision_id":"`+current+`"`, 1),
				"historical-warning":  strings.Replace(body, `"warning_bits":18446744073709551615`, `"warning_bits":18446744073709551614`, 1),
				"historical-state":    strings.Replace(body, `"state_result":1`, `"state_result":4`, 1),
				"evidence":            strings.Replace(body, `"evidence_ceiling":5`, `"evidence_ceiling":4`, 1),
				"retained-order":      strings.Replace(body, `"receipts":[{"operation_id":"apply","observed_revision_id":"`+current+`"},{"operation_id":"init","observed_revision_id":"`+historic+`"}]`, `"receipts":[{"operation_id":"init","observed_revision_id":"`+historic+`"},{"operation_id":"apply","observed_revision_id":"`+current+`"}]`, 1),
			} {
				if changed == body {
					continue
				}
				t.Run(name, func(t *testing.T) {
					if check(publicChildResult{Body: []byte(changed)}) {
						t.Fatal("changed scoped metadata or original retained facts accepted")
					}
				})
			}
			if check(publicChildResult{Code: 2, Body: []byte(body)}) || check(publicChildResult{DiagnosticBytes: 1, Body: []byte(body)}) {
				t.Fatal("incomplete delivery accepted")
			}
		})
	}
}
