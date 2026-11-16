package core

import (
	"testing"

	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicInitializationDenialRequiresExactCapability(t *testing.T) {
	for _, row := range []struct{ role, operation, eventRole string }{
		{"public", "kms-public", "normal"},
		{"normal", "kms-sign", "normal"},
		{"authority", "kms-decrypt", "authority"},
		{"recovery-signing", "kms-sign", "recovery-signing"},
		{"recovery-private", "kms-decrypt", "recovery-private"},
	} {
		t.Run(row.role, func(t *testing.T) {
			for _, condition := range []string{"exact", "wrong_operation", "wrong_role", "unsent", "untyped", "missing_return", "missing_events", "head_attempt"} {
				if row.role == "public" && condition == "wrong_role" {
					continue // Required public lookup applies to every selected key.
				}
				t.Run(condition, func(t *testing.T) {
					capture := nativeprocess.Capture{Events: []nativeprocess.Event{
						{Kind: "http-start", Operation: row.operation, Role: row.eventRole, Sequence: 1, Sent: true},
						{Kind: "http-return", Operation: row.operation, Role: row.eventRole, Sequence: 1, Sent: true, Status: 403, PermissionDenied: true},
					}}
					switch condition {
					case "wrong_operation":
						operation := "kms-public"
						if row.role == "public" {
							operation = "kms-sign"
						}
						capture.Events[0].Operation, capture.Events[1].Operation = operation, operation
					case "wrong_role":
						capture.Events[0].Role, capture.Events[1].Role = "unselected", "unselected"
					case "unsent":
						capture.Events[0].Sent, capture.Events[1].Sent = false, false
					case "untyped":
						capture.Events[1].PermissionDenied = false
					case "missing_return":
						capture.Events = capture.Events[:1]
					case "missing_events":
						capture.Events = nil
					case "head_attempt":
						capture.Events = append(capture.Events, nativeprocess.Event{Kind: "http-start", Operation: "head-write", Sequence: 2})
					}
					if err := publicDenied(capture, row.role); (err == nil) != (condition == "exact") {
						t.Fatal("public initialization accepted a different capability or lost the exact IAM denial", err)
					}
				})
			}
		})
	}
}
