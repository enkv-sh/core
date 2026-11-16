package compositionfull

import (
	"fmt"
	"strings"

	"enkv.sh/core/contract"
)

func writeDiagnosticHuman(w generatedFactWriter, d contract.Diagnostic) {
	w.text("Issue " + strings.ReplaceAll(string(d.Subject.Kind), "_", " "))
	s := d.Subject
	if s.Kind == contract.SubjectEntry || s.Kind == contract.SubjectOutputTarget {
		w.text(fmt.Sprintf(" %q", s.Name))
	}
	if s.DestinationID != "" {
		w.text(fmt.Sprintf(" destination %q", s.DestinationID))
	}
	if !s.RecipientID.IsZero() {
		w.text(" recipient " + readerID(s.RecipientID))
	}
	if s.Kind == contract.SubjectRoutingRule {
		switch s.RoutingKey.EntrySelector {
		case contract.PublicNamedEntry:
			w.text(fmt.Sprintf(" entry %q", s.RoutingKey.EntryName))
		case contract.PublicDefaultRoute:
			w.text(" default route")
		}
	}
	if len(d.Path) != 0 {
		w.text("; field ")
		for i, field := range d.Path {
			if i != 0 {
				w.text(".")
			}
			w.text(string(field))
		}
	}
	w.text(": " + string(d.Outcome) + "; " + string(d.Reason))
	if d.SourceLocation != nil {
		w.text(fmt.Sprintf("; source %q location %d:%d", d.SourceLocation.SourceID, d.SourceLocation.Line, d.SourceLocation.Column))
	}
	if d.Reason == contract.ReasonStaleSealedInputBinding {
		w.text("; use set to prepare a fresh supplied input for this entry before apply")
	}
	w.text("\n")
}

func writeReaderDiagnosticHuman(w generatedFactWriter, d readerDiagnosticRecord) {
	kind := d.Subject["kind"].(contract.DiagnosticSubjectKind)
	w.text("Issue " + strings.ReplaceAll(string(kind), "_", " "))
	if name, ok := d.Subject["name"].(string); ok {
		w.text(fmt.Sprintf(" %q", name))
	}
	if destination, ok := d.Subject["destination_id"].(string); ok {
		w.text(fmt.Sprintf(" destination %q", destination))
	}
	if recipient, ok := d.Subject["recipient_id"].(string); ok {
		w.text(" recipient " + recipient)
	}
	if entry, ok := d.Subject["entry"].(map[string]any); ok {
		if entry["kind"] == "entry" {
			w.text(fmt.Sprintf(" entry %q", entry["name"]))
		} else {
			w.text(" default route")
		}
	}
	if len(d.Path) != 0 {
		w.text("; field ")
		for i, field := range d.Path {
			if i != 0 {
				w.text(".")
			}
			w.text(string(field.Field))
		}
	}
	w.text(": " + string(d.Outcome) + "; " + string(d.Reason))
	if d.Source != nil {
		w.text(fmt.Sprintf("; source %q location %d:%d", d.Source.SourceID, d.Source.Line, d.Source.Column))
	}
	if d.Reason == contract.ReasonStaleSealedInputBinding {
		w.text("; use set to prepare a fresh supplied input for this entry before apply")
	}
	w.text("\n")
}
