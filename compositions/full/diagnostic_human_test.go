package compositionfull

import (
	"bytes"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestStaleSealedBindingDiagnosticRetainsSubjectAndCorrection(t *testing.T) {
	r, err := NewApplyRefusal(configuration.YAML)
	if err != nil {
		t.Fatal(err)
	}
	r.PreAdmission.Stage = "apply"
	r.Diagnostics = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "entry\nname"}, Path: []contract.DiagnosticField{contract.FieldSource}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonStaleSealedInputBinding}}
	result := ConfigurationApplyResult{PublicApplyResult: r}
	human, err := result.RenderHuman()
	if err != nil || !bytes.Contains(human, []byte(`entry "entry\nname"`)) || !bytes.Contains(human, []byte("use set to prepare a fresh supplied input for this entry before apply")) {
		t.Fatalf("binding diagnostic lost safe subject/correction: %v %s", err, human)
	}
	body, err := result.RenderJSON()
	if err != nil || !bytes.Contains(body, []byte(`"reason": "stale-sealed-input-binding"`)) || !bytes.Contains(body, []byte(`"name": "entry\nname"`)) {
		t.Fatalf("structured binding fact changed: %v %s", err, body)
	}
	for _, damage := range []string{"subject", "field", "outcome", "location"} {
		t.Run(damage, func(t *testing.T) {
			row := r.Diagnostics[0]
			row.Path = append([]contract.DiagnosticField(nil), row.Path...)
			switch damage {
			case "subject":
				row.Subject = contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
			case "field":
				row.Path[0] = contract.FieldPresence
			case "outcome":
				row.Outcome = contract.DiagnosticDifference
			case "location":
				row.SourceLocation = &contract.SourceLocation{SourceID: "source", Line: 1, Column: 1}
			}
			copy := result
			copy.Diagnostics = []contract.Diagnostic{row}
			if body, err := copy.RenderHuman(); err == nil || body != nil {
				t.Fatal("invalid binding diagnosis reached human output")
			}
			if body, err := copy.RenderJSON(); err == nil || body != nil {
				t.Fatal("invalid binding diagnosis reached JSON output")
			}
		})
	}
	result.Diagnostics[0].Subject.Name = strings.Repeat("\x01", contract.CryptoMaxName)
	if body, err := result.RenderHuman(); err != nil || len(body) >= 4096 {
		t.Fatal("maximum escaped entry diagnosis exceeded existing row account", err)
	}
}
