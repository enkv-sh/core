package compositionfull

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/sdk/artifact"
)

var ErrPrepareResult = errors.New("prepare result rendering refused")

// PrepareResult retains immutable local operation facts, independently of native
// handles, error causes and presentation. It grants no replay or mutation right.
type PrepareResult struct{ facts prepareResultFacts }

// SetupRequired reports completed source/recovery work with only known plugin
// selection or compatibility work remaining. Unavailable evidence and local
// delivery or cleanup failures are separate outcomes.
func (r *PrepareResult) SetupRequired() bool {
	if !r.valid() || r.facts.Outcome != "incomplete" || r.facts.Delivery.CleanupFailed || r.facts.Dependencies.Assessment != "complete" || !r.facts.Dependencies.MinimumAdministrativeReady || r.facts.Dependencies.AllDeclaredReady || r.facts.Dependencies.SettingsFailure != nil || len(r.facts.MissingInputs) != 0 {
		return false
	}
	if r.facts.Branch != "existing" && (r.facts.Recovery.Status != "complete" || r.facts.Delivery.Outcome != "recorded") {
		return false
	}
	missing := false
	for _, row := range r.facts.Dependencies.Requirements {
		switch row.Status {
		case "verified":
		case "missing", "incompatible":
			missing = true
		default:
			return false
		}
	}
	for _, row := range r.facts.Dependencies.Installations {
		switch row.Status {
		case "verified":
		case "missing", "incompatible":
			missing = true
		default:
			return false
		}
	}
	for _, diagnostic := range r.facts.Diagnostics {
		if diagnostic.Subject != "dependencies" || diagnostic.Reason != "dependency-missing" && diagnostic.Reason != "dependency-invalid" {
			return false
		}
	}
	return missing
}

type prepareRecoveryFacts struct {
	Status string `json:"status"`
	Domain string `json:"domain,omitempty"`
	Head   string `json:"head,omitempty"`
}
type prepareReadbackFacts struct {
	EditableDigest  string `json:"editable_digest"`
	GeneratedDigest string `json:"generated_digest"`
}
type prepareDeliveryFacts struct {
	Outcome        string                `json:"outcome"`
	EditablePath   string                `json:"editable_path,omitempty"`
	GeneratedPath  string                `json:"generated_path,omitempty"`
	Readback       *prepareReadbackFacts `json:"readback,omitempty"`
	RecoverySource string                `json:"recovery_source,omitempty"`
	CleanupFailed  bool                  `json:"cleanup_failed"`
}
type prepareDiagnostic struct {
	Reason  string `json:"reason"`
	Subject string `json:"subject"`
}
type prepareResultFacts struct {
	SourceFailure *ConfigurationSourceFailure
	MissingInputs []string
	RequestID     string
	Branch        string
	Recovery      prepareRecoveryFacts
	Delivery      prepareDeliveryFacts
	Dependencies  PrepareDependencyAssessment
	Outcome       string
	Diagnostics   []prepareDiagnostic
}

// NewPrepareRefusal supplies fresh correlation for recognized CLI input or
// application-setup refusal before source classification.
func NewPrepareRefusal() (*PrepareResult, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil || nonce == ([32]byte{}) {
		return nil, errors.Join(ErrPrepareResult, err)
	}
	return &PrepareResult{facts: prepareResultFacts{RequestID: hex.EncodeToString(nonce[:]), Branch: "unclassified",
		Recovery: prepareRecoveryFacts{Status: "not-attempted"}, Delivery: prepareDeliveryFacts{Outcome: "not-recorded"},
		Dependencies: PrepareDependencyAssessment{Assessment: "not-attempted", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}},
		Outcome:      "refused", Diagnostics: []prepareDiagnostic{{Reason: "invalid-request", Subject: "request"}}}}, nil
}

func prepareHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func validPrepareDiagnostic(d prepareDiagnostic) bool {
	switch d.Subject {
	case "request", "source", "generated", "recovery", "delivery", "dependencies", "presentation":
	default:
		return false
	}
	switch d.Reason {
	case "invalid-request", "source-invalid", "source-unavailable", "pending-edit", "target-occupied", "unsafe-path", "trust-invalid", "state-unavailable", "state-invalid", "secret-unverifiable", "contention", "cancelled", "delivery-failed", "delivery-unknown", "cleanup-failed", "dependency-missing", "dependency-invalid", "dependency-unavailable", "source-changed", "presentation-failed":
		return true
	}
	return false
}

func validPrepareRequirement(row PrepareDependencyRequirement) bool {
	if row.Role != "generator" && row.Role != "output" && row.Role != "manifest-generator" || row.Plugin != nil && !artifact.ValidPluginID(*row.Plugin) || len(row.Contract) > 256 || !utf8.ValidString(row.Contract) || row.Artifact != nil && !prepareHex(*row.Artifact) || len(row.Subjects) == 0 || len(row.Subjects) != cap(row.Subjects) {
		return false
	}
	maximum := uint16(512)
	switch row.Role {
	case "output":
		maximum = 64
	case "manifest-generator":
		maximum = 1
	}
	for i, subject := range row.Subjects {
		if subject >= maximum || i > 0 && row.Subjects[i-1] >= subject {
			return false
		}
	}
	if row.Status == "not-attempted" {
		return row.Plugin != nil && row.Artifact == nil && (row.Reason == "settings-invalid" || row.Reason == "settings-unavailable")
	}
	if row.ProtocolVersion == 0 {
		return false
	}
	if row.Plugin == nil {
		return row.Artifact == nil && row.Status == "missing" && row.Reason == "selection-required"
	}

	switch row.Status {
	case "verified":
		return row.Artifact != nil && row.Reason == "none" && row.Contract != ""
	case "missing":
		return row.Reason == "not-installed"
	case "tampered":
		return row.Reason == "identity-mismatch"
	case "incompatible":
		return row.Reason == "identity-mismatch" || row.Reason == "platform-mismatch" || row.Reason == "version-mismatch" || row.Reason == "unsupported-protocol"
	case "unavailable":
		return row.Reason == "unavailable"
	}
	return false
}

func prepareRequirementLess(a, b PrepareDependencyRequirement) bool {
	if a.Role != b.Role {
		return a.Role < b.Role
	}
	if a.Contract != b.Contract {
		return a.Contract < b.Contract
	}
	if prepareDependencyPlugin(a) != prepareDependencyPlugin(b) {
		return prepareDependencyPlugin(a) < prepareDependencyPlugin(b)
	}
	if a.ProtocolVersion != b.ProtocolVersion {
		return a.ProtocolVersion < b.ProtocolVersion
	}
	if prepareDependencyArtifact(a) != prepareDependencyArtifact(b) {
		return prepareDependencyArtifact(a) < prepareDependencyArtifact(b)
	}
	if a.Status != b.Status {
		return a.Status < b.Status
	}
	return a.Reason < b.Reason
}

func (r *PrepareResult) valid() bool {
	if r == nil {
		return false
	}
	f := &r.facts
	if !prepareHex(f.RequestID) || f.RequestID == strings.Repeat("0", 64) || len(f.Diagnostics) > 64 || f.Diagnostics == nil || len(f.MissingInputs) > 512 {
		return false
	}
	for i, name := range f.MissingInputs {
		if len(name) > 256 || !utf8.ValidString(name) || i > 0 && f.MissingInputs[i-1] >= name {
			return false
		}
	}
	if len(f.MissingInputs) != 0 && (f.SourceFailure != nil || f.Outcome == "complete" || f.Dependencies.AllDeclaredReady || f.Branch != "existing" && (f.Branch != "reconstruction" || f.Recovery.Status != "complete")) {
		return false
	}
	for _, d := range f.Diagnostics {
		if !validPrepareDiagnostic(d) {
			return false
		}
	}
	switch f.Outcome {
	case "complete", "refused", "incomplete", "unknown":
	default:
		return false
	}
	switch f.Recovery.Status {
	case "complete":
		if !prepareHex(f.Recovery.Domain) || !prepareHex(f.Recovery.Head) {
			return false
		}
	case "not-attempted", "refused", "failed":
		if f.Recovery.Domain != "" || f.Recovery.Head != "" {
			return false
		}
	default:
		return false
	}
	d := &f.Delivery
	for _, path := range []string{d.EditablePath, d.GeneratedPath, d.RecoverySource} {
		if !localResultPath(path) {
			return false
		}
	}
	switch d.Outcome {
	case "recorded":
		if d.EditablePath == "" || d.GeneratedPath == "" || d.Readback == nil {
			return false
		}
	case "not-recorded":
		if d.Readback != nil || d.RecoverySource != "" {
			return false
		}
	case "pending", "unknown":
	default:
		return false
	}
	if d.Readback != nil && (!prepareHex(d.Readback.EditableDigest) || !prepareHex(d.Readback.GeneratedDigest) || d.EditablePath == "" || d.GeneratedPath == "") {
		return false
	}
	p := &f.Dependencies
	if f.SourceFailure != nil {
		if !validConfigurationSourceFailure(f.SourceFailure) || f.SourceFailure.SourceID != "source" && f.SourceFailure.SourceID != "source.generated" || f.Outcome != "refused" && f.Outcome != "incomplete" || d.Outcome != "not-recorded" || p.Assessment != "not-attempted" || (f.Branch != "unclassified" || f.Recovery.Status != "not-attempted") && (f.Branch != "reconstruction" || f.Recovery.Status != "complete") || len(f.Diagnostics) < 1 || len(f.Diagnostics) > 2 {
			return false
		}
		sourceCount := 0
		for _, diagnostic := range f.Diagnostics {
			if (diagnostic.Subject == "source" || diagnostic.Subject == "generated") && (diagnostic.Reason == "source-invalid" || diagnostic.Reason == "source-unavailable" || diagnostic.Reason == "cancelled") {
				sourceCount++
			} else if diagnostic.Subject != "delivery" || diagnostic.Reason != "cleanup-failed" {
				return false
			}
		}
		if sourceCount != 1 {
			return false
		}
	}
	if p.SettingsFailure != nil && (!p.SettingsFailure.Valid() || p.Assessment != "incomplete" || p.AllDeclaredReady) {
		return false
	}
	if p.Requirements == nil || len(p.Requirements)+len(f.MissingInputs) > MaxPrepareDependencyRequirements || p.Installations == nil || len(p.Installations) > 64 {
		return false
	}
	switch p.Assessment {
	case "not-attempted":
		if len(p.Requirements) != 0 || len(p.Installations) != 0 || p.SettingsFailure != nil || p.MinimumAdministrativeReady || p.AllDeclaredReady {
			return false
		}
	case "incomplete":
		if p.AllDeclaredReady {
			return false
		}
	case "complete":
	default:
		return false
	}
	subjects, generators, outputs, renderers := 0, 0, 0, 0
	var seen [3][512]bool
	for i, row := range p.Requirements {
		if !validPrepareRequirement(row) {
			return false
		}
		subjects += len(row.Subjects)
		if subjects+len(f.MissingInputs) > MaxPrepareDependencyRequirements {
			return false
		}
		roleIndex := 0
		switch row.Role {
		case "output":
			roleIndex = 1
		case "manifest-generator":
			roleIndex = 2
		}
		for _, subject := range row.Subjects {
			if seen[roleIndex][subject] {
				return false
			}
			seen[roleIndex][subject] = true
		}
		switch row.Role {
		case "generator":
			generators += len(row.Subjects)
			if generators+len(f.MissingInputs) > 512 {
				return false
			}
		case "output":
			outputs += len(row.Subjects)
			if outputs > 64 {
				return false
			}
		default:
			renderers += len(row.Subjects)
			if renderers > 1 {
				return false
			}
		}
		if row.Status == "not-attempted" {
			if p.SettingsFailure == nil {
				return false
			}
			reason := "settings-invalid"
			if p.SettingsFailure.Reason == "settings-unavailable" {
				reason = "settings-unavailable"
			}
			if row.Reason != reason {
				return false
			}
		}
		if i > 0 && !prepareRequirementLess(p.Requirements[i-1], row) || p.AllDeclaredReady && row.Status != "verified" {
			return false
		}
	}
	for i, row := range p.Installations {
		if !validPrepareInstallation(row) || i > 0 && p.Installations[i-1].Name >= row.Name || p.AllDeclaredReady && row.Status != "verified" {
			return false
		}
	}
	if p.AllDeclaredReady && (!p.MinimumAdministrativeReady || p.Assessment != "complete") {
		return false
	}
	switch f.Branch {
	case "unclassified":
		if f.Recovery.Status != "not-attempted" || d.Outcome != "not-recorded" || p.Assessment != "not-attempted" || f.Outcome == "complete" {
			return false
		}
	case "existing":
		if f.Recovery.Status != "not-attempted" || d.Outcome != "not-recorded" {
			return false
		}
	case "reconstruction":
		if f.Recovery.Status != "complete" && (d.Outcome != "not-recorded" || p.Assessment != "not-attempted") {
			return false
		}
		if f.Recovery.Status == "not-attempted" && f.Outcome != "refused" && f.Outcome != "incomplete" {
			return false
		}
		if p.Assessment != "not-attempted" && d.Outcome != "recorded" {
			return false
		}
	default:
		return false
	}
	if f.Outcome == "refused" && d.Outcome != "not-recorded" {
		return false
	}
	if f.Outcome == "complete" && (len(f.Diagnostics) != 0 || !p.AllDeclaredReady || d.CleanupFailed || f.Branch == "reconstruction" && (f.Recovery.Status != "complete" || d.Outcome != "recorded" || d.RecoverySource != "")) {
		return false
	}
	for _, diag := range f.Diagnostics {
		if diag.Reason == "source-changed" && (f.Outcome != "incomplete" || p.MinimumAdministrativeReady || p.AllDeclaredReady) {
			return false
		}
	}
	return true
}

func validPrepareInstallation(row plugininstallation.Installation) bool {
	if !artifact.ValidPluginID(row.Name) || row.Role != "" && row.Role != "generator" && row.Role != "output" && row.Role != "manifest-generator" || row.Version != "" && !artifact.ValidVersion(row.Version) || row.Artifact != nil && row.Artifact.IsZero() || !preparePlatform(row.Platform) || row.Source != "local" && row.Source != "official" {
		return false
	}
	switch row.Status {
	case "verified":
		if row.Role == "" || row.Version == "" || row.Artifact == nil || row.Reason != "none" {
			return false
		}
	case "missing":
		if row.Reason != "not-installed" {
			return false
		}
	case "tampered":
		if row.Reason != "identity-mismatch" && row.Reason != "signature-invalid" && row.Reason != "record-invalid" {
			return false
		}
	case "incompatible":
		if row.Reason != "identity-mismatch" && row.Reason != "platform-mismatch" && row.Reason != "version-mismatch" && row.Reason != "unsupported-protocol" {
			return false
		}
	case "unavailable":
		if row.Reason != "unavailable" && row.Reason != "build-incomplete" {
			return false
		}
	default:
		return false
	}
	same := false
	if previous := row.Previous; previous != nil {
		if !artifact.ValidVersion(previous.Version) || previous.Artifact.IsZero() || !preparePlatform(previous.Platform) || previous.Source != "local" && previous.Source != "official" {
			return false
		}
		same = previous.Version == row.Version && row.Artifact != nil && previous.Artifact == *row.Artifact && previous.Platform == row.Platform && previous.Source == row.Source
	}
	if row.Changed {
		return row.Status == "verified" && !same
	}
	return row.Status != "verified" || row.Previous == nil || same
}

func preparePlatform(value string) bool { return value == "darwin/arm64" || value == "linux/amd64" }

// RenderPrepareJSON counts and writes directly into one caller-owned result.
func RenderPrepareJSON(r *PrepareResult) ([]byte, error) {
	if !r.valid() {
		return nil, ErrPrepareResult
	}
	f := &r.facts
	body, err := renderReaderResultJSONBound(1572864, 1572864, func(w *readerResultWriter) {
		w.literal(`{"schema":"enkv/prepare-result/v2","operation":"prepare","request_id":`)
		w.json(f.RequestID, 66)
		w.literal(`,"branch":`)
		w.json(f.Branch, 32)
		if f.SourceFailure != nil {
			w.literal(`,"source_failure":`)
			w.json(f.SourceFailure, configurationSourceFailureJSONBytes)
		}
		w.literal(`,"recovery":`)
		w.json(f.Recovery, 256)
		w.literal(`,"local_delivery":`)
		deliveryStart := w.formattedAt
		w.json(f.Delivery, 74752)
		deliveryBytes := w.formattedAt - deliveryStart
		pathBytes := 0
		for _, path := range []string{f.Delivery.EditablePath, f.Delivery.GeneratedPath, f.Delivery.RecoverySource} {
			encoded, err := json.Marshal(path)
			if err != nil {
				w.failed = true
				return
			}
			pathBytes += len(encoded) - 2
		}
		if pathBytes > 73728 {
			w.failed = true
			return
		}
		w.literal(`,"dependencies":{"assessment":`)
		w.json(f.Dependencies.Assessment, 32)
		w.literal(`,"minimum_administrative_ready":`)
		w.json(f.Dependencies.MinimumAdministrativeReady, 5)
		w.literal(`,"all_declared_ready":`)
		w.json(f.Dependencies.AllDeclaredReady, 5)
		w.literal(`,"requirements":[`)
		semanticStart := w.formattedAt
		for i, row := range f.Dependencies.Requirements {
			if i != 0 {
				w.literal(",")
			}
			w.json(row, len(row.Subjects)*2304)
		}
		semanticBytes := w.formattedAt - semanticStart
		if semanticBytes > MaxPrepareDependencyRequirements*2304+MaxPrepareDependencyRequirements-1 {
			w.failed = true
			return
		}
		installationStart := w.formattedAt
		w.literal(`],"installations":[`)
		for i, row := range f.Dependencies.Installations {
			if i != 0 {
				w.literal(",")
			}
			w.json(row, 1280)
		}
		w.literal("]")
		installationBytes := w.formattedAt - installationStart
		if installationBytes > 64*1280+64 {
			w.failed = true
			return
		}
		w.literal(`,"settings_failure":`)
		settingsStart := w.formattedAt
		w.json(f.Dependencies.SettingsFailure, 26624)
		settingsBytes := w.formattedAt - settingsStart
		w.literal(`},"missing_inputs":[`)
		missingStart := w.formattedAt
		for i, name := range f.MissingInputs {
			if i != 0 {
				w.literal(",")
			}
			w.json(struct {
				Name       string `json:"name"`
				Reason     string `json:"reason"`
				NextAction string `json:"next_action"`
			}{name, "supplied-input-missing", "set"}, 2304)
		}
		semanticBytes += w.formattedAt - missingStart
		if semanticBytes > MaxPrepareDependencyRequirements*2304+MaxPrepareDependencyRequirements-1 {
			w.failed = true
			return
		}
		w.literal(`],"outcome":`)
		w.json(f.Outcome, 32)
		w.literal(`,"diagnostics":[`)
		for i, diagnostic := range f.Diagnostics {
			if i != 0 {
				w.literal(",")
			}
			w.json(diagnostic, 128)
		}
		w.literal("]}")
		if w.formattedAt+1-semanticBytes-pathBytes-installationBytes-settingsBytes > 32768 || deliveryBytes > 74752 {
			w.failed = true
		}
	})
	if err != nil {
		return nil, ErrPrepareResult
	}
	return body, nil
}

// RenderPrepareHuman presents the owned phase facts without granting a retry or
// treating recovered local files as remote operation readiness.
func RenderPrepareHuman(r *PrepareResult) ([]byte, error) {
	if !r.valid() {
		return nil, ErrPrepareResult
	}
	f := &r.facts
	var out strings.Builder
	fmt.Fprintf(&out, "Prepare: %s\n", f.Outcome)
	if f.Branch == "reconstruction" && f.Recovery.Status == "complete" {
		out.WriteString("Configuration restoration: complete.\n")
	} else if f.Branch == "existing" {
		out.WriteString("Existing configuration selected.\n")
		if f.Outcome == "complete" || r.SetupRequired() {
			out.WriteString("Configuration files were not changed.\n")
		}
	} else {
		fmt.Fprintf(&out, "Source branch: %s\nRecovery: %s\n", f.Branch, f.Recovery.Status)
	}
	if f.Recovery.Domain != "" {
		fmt.Fprintf(&out, "Domain: %s\nRecovered HEAD: %s\n", f.Recovery.Domain, f.Recovery.Head)
	}
	if f.Branch != "existing" || f.Delivery.Outcome != "not-recorded" {
		fmt.Fprintf(&out, "Local files: %s\n", f.Delivery.Outcome)
	}
	for _, field := range []struct{ label, value string }{{"Editable file", f.Delivery.EditablePath}, {"Generated file", f.Delivery.GeneratedPath}, {"Recovery source", f.Delivery.RecoverySource}} {
		if field.value != "" && (f.Branch != "existing" || f.Delivery.CleanupFailed || field.label == "Recovery source") {
			fmt.Fprintf(&out, "%s: %q\n", field.label, field.value)
		}
	}
	if f.Delivery.CleanupFailed {
		out.WriteString("Warning: local cleanup failed; retain the reported files.\n")
	}
	out.WriteString(configurationSourceFailureHuman(f.SourceFailure))
	p := &f.Dependencies
	fmt.Fprintf(&out, "Plugin check: %s\n", p.Assessment)
	if p.Assessment != "not-attempted" {
		administrative, dependencies := "not established", "not ready"
		if p.MinimumAdministrativeReady {
			administrative = "ready"
		}
		if p.AllDeclaredReady {
			dependencies = "ready"
		} else if r.SetupRequired() {
			dependencies = "setup required"
		} else if p.Assessment != "complete" {
			dependencies = "assessment incomplete"
		}
		fmt.Fprintf(&out, "Administrative support: %s\nPlugin dependencies: %s\n", administrative, dependencies)
	}
	for _, name := range f.MissingInputs {
		fmt.Fprintf(&out, "Missing supplied input %q: supplied-input-missing; next action: set\n", name)
	}
	if len(f.MissingInputs) != 0 {
		out.WriteString("Local file delivery preserves these declarations. It does not supply the missing inputs.\nSet each listed input before plan, apply, read or materialize.\n")
	}
	for _, row := range p.Requirements {
		if row.Status == "verified" {
			continue
		}
		fmt.Fprintf(&out, "Required %s", row.Role)
		if row.Plugin != nil {
			fmt.Fprintf(&out, " %q", *row.Plugin)
		}
		if row.Contract != "" {
			fmt.Fprintf(&out, " for %q", row.Contract)
		}
		fmt.Fprintf(&out, ": %s; %s\n", row.Status, row.Reason)
		for _, subject := range row.Subjects {
			label := map[string]string{"generator": "Entry declaration", "output": "Destination declaration", "manifest-generator": "Requested renderer"}[row.Role]
			if row.Role == "manifest-generator" {
				fmt.Fprintf(&out, "  %s %d\n", label, int(subject)+1)
			} else {
				fmt.Fprintf(&out, "  %s %d (source order)\n", label, int(subject)+1)
			}
		}
		switch row.Reason {
		case "selection-required":
			out.WriteString("  Select a compatible local plugin for these declarations.\n")
		case "not-installed":
			out.WriteString("  Install the selected plugin before this dependency is ready.\n")
		}
	}
	for _, row := range p.Installations {
		if row.Status != "verified" || row.Changed {
			fmt.Fprintf(&out, "Plugin %q: %s; %s; selection changed: %t\n", row.Name, row.Status, row.Reason, row.Changed)
		}
	}
	if failure := p.SettingsFailure; failure != nil {
		fmt.Fprintf(&out, "Plugin settings %s: %s\n", failure.Object, failure.Reason)
		if failure.Path != nil {
			fmt.Fprintf(&out, "Settings file: %q\n", *failure.Path)
		}
		if failure.Location != nil {
			fmt.Fprintf(&out, "Settings %s location: %d:%d\n", failure.Location.Precision, failure.Location.Line, failure.Location.Column)
		}
		fmt.Fprintf(&out, "Next action: %s\n", failure.Action)
	}
	for _, diagnostic := range f.Diagnostics {
		fmt.Fprintf(&out, "Issue %s: %s\n", diagnostic.Subject, diagnostic.Reason)
	}
	if f.Delivery.RecoverySource != "" {
		out.WriteString("Next action: run recover with the reported recovery source and its original source format.\n")
	} else if r.SetupRequired() {
		if f.Delivery.EditablePath != "" {
			fmt.Fprintf(&out, "Next action: resolve the listed plugin requirements, then run prepare with source %q and its original source format.\n", f.Delivery.EditablePath)
		} else {
			out.WriteString("Next action: resolve the listed plugin requirements, then run prepare on the same source pair.\n")
		}
	}
	// The dedicated readable account also bounds this subset of its strings and
	// rows. No installation provenance or settings error cause is reproduced.
	if out.Len() > 1572864 {
		return nil, ErrPrepareResult
	}
	return []byte(out.String()), nil
}

// PrepareExitCode preserves unavailable or unresolved operation facts even when
// a later result writer fails. Presentation does not modify the result.
func PrepareExitCode(r *PrepareResult, presentationErr error) int {
	if !r.valid() {
		return 2
	}
	f := &r.facts
	if f.Dependencies.SettingsFailure != nil && f.Dependencies.SettingsFailure.Reason == "settings-unavailable" {
		return 3
	}
	if f.Outcome == "unknown" || f.Delivery.Outcome == "pending" || f.Delivery.Outcome == "unknown" || f.Delivery.RecoverySource != "" {
		return 3
	}
	for _, d := range f.Diagnostics {
		switch d.Reason {
		case "pending-edit", "contention", "source-unavailable", "state-unavailable", "dependency-unavailable":
			return 3
		}
	}
	for _, row := range f.Dependencies.Requirements {
		if row.Status == "unavailable" {
			return 3
		}
	}
	for _, row := range f.Dependencies.Installations {
		if row.Status == "unavailable" {
			return 3
		}
	}
	if presentationErr == nil && f.Outcome == "complete" {
		return 0
	}
	return 2
}
