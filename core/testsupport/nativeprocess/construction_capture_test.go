package nativeprocess

import (
	"encoding/json"
	"reflect"
	"testing"
)

// full_only: false
func TestNativeReplacementConstructionCaptureIsClosed(t *testing.T) {
	valid := Event{Kind: "construction", Count: 1, Operation: "key-access", Role: "successor-private"}
	for _, damage := range []string{"", "purpose", "role", "sequence", "sent", "count", "hash", "code"} {
		t.Run(damage, func(t *testing.T) {
			row := valid
			switch damage {
			case "purpose":
				row.Operation = "raw-selector"
			case "role":
				row.Role = "unbounded-role"
			case "sequence":
				row.Sequence = 1
			case "sent":
				row.Sent = true
			case "count":
				row.Count = 2
			case "hash":
				row.ObjectKeySHA256 = "discarded"
			case "code":
				row.Code = 1
			}
			encoded, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, '\n')
			encoded = append(encoded, []byte("{\"kind\":\"footer\"}\n")...)
			got, err := inspectCaptureImage(encoded, true)
			if (err == nil) != (damage == "") {
				t.Fatal("constructor capture accepted an open shape", damage)
			}
			if damage == "" && (len(got.Events) != 2 || !reflect.DeepEqual(got.Events[0], valid)) {
				t.Fatal("valid constructor event lost exact labels")
			}
		})
	}
}
