package compositionfull

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// ConfigurationSourceFailure describes one source admission failure. It carries
// safe field categories and syntax reasons, never source text or user keys.
type ConfigurationSourceFailure struct {
	SourceID  string `json:"source_id"`
	Path      string `json:"path,omitempty"`
	Field     string `json:"field,omitempty"`
	Reason    string `json:"reason"`
	Line      uint64 `json:"line,omitempty"`
	Column    uint64 `json:"column,omitempty"`
	Precision string `json:"precision,omitempty"`
}

const configurationSourceFailureJSONBytes = 26634

func configurationSourceFailureHuman(f *ConfigurationSourceFailure) string {
	if f == nil {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Input %s: %s", f.SourceID, f.Reason)
	if f.Path != "" {
		fmt.Fprintf(&out, "; file %q", f.Path)
	}
	if f.Field != "" {
		fmt.Fprintf(&out, "; field %s", f.Field)
	}
	if f.Line != 0 {
		fmt.Fprintf(&out, "; %s location %d:%d", f.Precision, f.Line, f.Column)
	}
	out.WriteByte('\n')
	return out.String()
}

func validConfigurationAdmissionSourceFailure(f *ConfigurationSourceFailure, admission *core.PreAdmissionRequestIdentity, identity contract.ID, result core.Result) bool {
	if f == nil {
		return true
	}
	if !validConfigurationSourceFailure(f) || f.SourceID != "source" && f.SourceID != "source.generated" || admission == nil || !identity.IsZero() {
		return false
	}
	if !validSourceAdmissionStage(admission.Stage) {
		return false
	}
	return validUnadmittedSourceResult(result)
}

func validSourceAdmissionStage(stage string) bool {
	switch stage {
	case "capture", "parse", "declaration", "public-basis":
		return true
	default:
		return false
	}
}

func configurationSourceFailure(source string, err error) *ConfigurationSourceFailure {
	var d *configuration.Diagnostic
	if !errors.As(err, &d) {
		return nil
	}
	if d.Generated {
		source += ".generated"
	}
	f := &ConfigurationSourceFailure{SourceID: source, Field: d.Field, Reason: d.Reason, Line: d.Line, Column: d.Column}
	if f.Reason == "restore-exact-generated-file" && !errors.Is(err, configuration.ErrSourceImageMissing) {
		f.Reason = "missing-required-field"
	}
	var captured interface{ CapturedSourcePath() string }
	if errors.As(err, &captured) {
		f.Path = strings.Clone(captured.CapturedSourcePath())
	}
	if d.Line != 0 && d.Column != 0 {
		f.Precision = "exact"
		if d.Context {
			f.Precision = "context"
		}
	}
	return f
}
func validConfigurationSourceFailure(f *ConfigurationSourceFailure) bool {
	if f == nil {
		return true
	}
	switch f.SourceID {
	case "trusted", "candidate", "source", "trusted.generated", "candidate.generated", "source.generated":
	default:
		return false
	}
	if !configuration.DiagnosticFieldValid(f.Field) || !configuration.DiagnosticReasonValid(f.Reason) {
		return false
	}
	if f.Path != "" && (!utf8.ValidString(f.Path) || len(f.Path) > 4096 || !filepath.IsAbs(f.Path) || filepath.Dir(f.Path) == f.Path || filepath.Clean(f.Path) != f.Path || strings.ContainsRune(f.Path, 0)) {
		return false
	}
	if f.Line == 0 || f.Column == 0 {
		return f.Line == 0 && f.Column == 0 && f.Precision == ""
	}
	return f.Precision == "exact" || f.Precision == "context"
}
func (w *readerResultWriter) sourceFailure(f *ConfigurationSourceFailure, human bool) {
	if f == nil {
		return
	}
	if human {
		w.literal(configurationSourceFailureHuman(f))
		return
	} else {
		w.literal(`,"source_failure":`)
	}
	w.json(f, configurationSourceFailureJSONBytes)
}

func validSourceFailureDiagnostics(f *ConfigurationSourceFailure, diagnostics []contract.Diagnostic) bool {
	if f == nil {
		return true
	}
	if len(diagnostics) < 1 || len(diagnostics) > 2 {
		return false
	}
	for _, d := range diagnostics {
		if d.Outcome != contract.DiagnosticUnable || d.Subject.Kind != contract.SubjectConfiguration && d.Subject.Kind != contract.SubjectObservation {
			return false
		}
	}
	return true
}

func validSourceFailureComparison(p contract.ComparisonPayload) bool {
	return p.Observation == nil && len(p.Changes) == 0 && len(p.BeforeRecipients) == 0 && len(p.AfterRecipients) == 0 && len(p.GeneratedEntries) == 0 && (p.Publication == nil || len(p.Publication.Entries) == 0)
}

func validUnadmittedSourceResult(result core.Result) bool {
	return (result.Outcome == core.AdmissionRefused || result.Outcome == core.EvidenceUnavailable) && !result.CommitMayHaveOccurred && result.Evidence == core.NoEvidence && result.RequestedRevision.IsZero() && result.ObservedRevision.IsZero() && result.ObservedSnapshotID.IsZero()
}

func validSourceFailureReaderState(result core.Result, state contract.ReaderStateResult) bool {
	if !validUnadmittedSourceResult(result) {
		return false
	}
	if result.Outcome == core.AdmissionRefused {
		return state == contract.ReaderRefused || state == contract.ReaderProfileBlocked
	}
	return state == contract.ReaderUnavailable
}
