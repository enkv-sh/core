// Package plugininstallation coordinates trusted local plugin installation.
// It has no plugin execution or provider-effect operation.
package plugininstallation

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/sdk/artifact"
)

// Installation failure sentinels support errors.Is. ErrIncompatible alone is
// a protocol selection result; a joined cleanup or integrity failure must not
// become permission to consider an older release.
var (
	ErrInstallation  = errors.New("plugin installation incomplete")
	ErrIncompatible  = errors.New("plugin family protocol unsupported")
	ErrMissing       = errors.New("plugin installation missing")
	ErrInvalid       = errors.New("plugin installation record invalid")
	ErrIdentity      = errors.New("plugin installation identity differs")
	ErrSourceChanged = errors.New("plugin installation source changed")
	ErrSignature     = errors.New("plugin installation signature invalid")
)

// SettingsFailure records one shared settings-stage refusal before selection.
// Its closed fields exclude file contents, plugin provenance and raw errors.
type SettingsFailure struct {
	Stage    string                     `json:"stage"`
	Object   string                     `json:"object"`
	Path     *string                    `json:"path"`
	Reason   string                     `json:"reason"`
	Location *artifact.SettingsLocation `json:"location"`
	Action   string                     `json:"action"`
	cause    error
}

func (e *SettingsFailure) Error() string { return "plugin settings failed" }
func (e *SettingsFailure) Unwrap() error { return e.cause }

// Valid checks the safe public settings-failure shape independently of its cause.
func (e *SettingsFailure) Valid() bool {
	if e == nil || e.Stage != "settings" || e.Object != "plugins.json" {
		return false
	}
	if e.Path != nil && (len(*e.Path) == 0 || len(*e.Path) > 4096 || !utf8.ValidString(*e.Path) || strings.ContainsRune(*e.Path, 0)) {
		return false
	}
	if e.Reason == "settings-unavailable" {
		return e.Action == "check-settings-access" && e.Location == nil
	}
	if e.Path == nil || e.Action != "correct-settings" {
		return false
	}
	switch e.Reason {
	case "invalid-json", "duplicate-key", "unknown-field", "duplicate-application", "duplicate-plugin", "invalid-value", "limit-exceeded":
	default:
		return false
	}
	if l := e.Location; l != nil {
		return l.Byte <= artifact.MaxRecordBytes && l.Line >= 1 && l.Line <= artifact.MaxRecordBytes+1 && l.Column >= 1 && l.Column <= artifact.MaxRecordBytes+1 && (l.Precision == "exact" || l.Precision == "context")
	}
	return true
}

func settingsFailure(path, reason string, location *artifact.SettingsLocation, cause error) *SettingsFailure {
	failure := &SettingsFailure{Stage: "settings", Object: "plugins.json", Reason: reason, Location: location, Action: "correct-settings", cause: cause}
	if len(path) > 0 && len(path) <= 4096 && utf8.ValidString(path) && !strings.ContainsRune(path, 0) {
		failure.Path = &path
	}
	if reason == "settings-unavailable" {
		failure.Action = "check-settings-access"
	}
	return failure
}

// Mode controls acquisition and selection updates. Ordinary is the zero value.
type Mode uint8

const (
	// Ordinary uses a current local build or the existing exact official selection.
	Ordinary Mode = iota
	// Prepare acquires missing official support and selects when no usable pin exists.
	Prepare
	// Upgrade also considers newer compatible stable releases for unversioned requirements.
	Upgrade
)

// Requirement names one plugin and an optional exact official version.
// Local application overrides take precedence over the version requirement.
type Requirement struct{ Name, Version string }

// Check is supplied by the trusted composition, never by project input. It
// checks the host's supported family protocol. Only ErrIncompatible
// permits considering an older release after authenticated byte verification.
type Check func(context.Context, artifact.Metadata, []byte) error

// Candidate coordinates remain useful after byte verification fails. They are
// distinct from Installed and cannot supply execution or readiness authority.
type candidateFailure struct {
	selection artifact.Selection
	cause     error
}

func (e *candidateFailure) Error() string { return ErrInstallation.Error() }
func (e *candidateFailure) Unwrap() error { return e.cause }

type protocolMismatch struct{ cause error }

func (e *protocolMismatch) Error() string { return ErrIncompatible.Error() }
func (e *protocolMismatch) Unwrap() error { return e.cause }

func onlyIncompatible(err error) bool {
	if err == ErrIncompatible {
		return true
	}
	if _, joined := err.(interface{ Unwrap() []error }); joined {
		return false
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyIncompatible(wrapped.Unwrap())
	}
	return false
}

func candidateMaySkip(err error) bool {
	if candidate, ok := err.(*candidateFailure); ok {
		err = candidate.cause
	}
	_, ok := err.(*protocolMismatch)
	return ok
}

type recordCompletionFailure struct{ cause error }

func (e *recordCompletionFailure) Error() string { return ErrInstallation.Error() }
func (e *recordCompletionFailure) Unwrap() error { return e.cause }

func recordWasPublished(err error) bool {
	var completion *recordCompletionFailure
	return errors.As(err, &completion)
}

func candidateFacts(row Installation, err error) Installation {
	var candidate *candidateFailure
	if !errors.As(err, &candidate) {
		return row
	}
	row.Version = candidate.selection.Version
	row.Artifact = nil
	if !candidate.selection.Artifact.IsZero() {
		row.Artifact = digestPointer(candidate.selection.Artifact)
	}
	return row
}

// Assembly binds the distribution and protocol trust at application assembly.
// None of these fields is an editable configuration setting.
type Assembly struct {
	Origin        string
	RedirectHosts []string
	PluginKeys    []ed25519.PublicKey
	TLSRoots      *x509.CertPool
	Check         Check
}

// Coordinator captures trusted packages and application selections without
// executing plugins. Construct it with New; the zero value is not usable.
type Coordinator struct {
	configDirectory string
	store           string
	origin          string
	hosts           map[string]bool
	keys            []ed25519.PublicKey
	client          *http.Client
	check           Check
}

// Installed retains the exact captured expectation for one invocation. Its
// executable is still subject to the lower family's independent launch checks.
type Installed struct {
	path       string
	metadata   []byte
	dependency []byte
	identity   artifact.Digest
	proof      *artifact.Digest
	source     string
}

// Executable returns the captured executable path, which the family host
// must independently authenticate before launch. The receiver must be nonnil.
func (i *Installed) Executable() string { return i.path }

// Identity returns the packaging identity, not just the executable hash.
func (i *Installed) Identity() artifact.Digest { return i.identity }

// Source reports local or official installation provenance, not effect authority.
func (i *Installed) Source() string { return i.source }

// Metadata decodes an independent copy of the captured metadata.
func (i *Installed) Metadata() (artifact.Metadata, error) { return artifact.DecodeMetadata(i.metadata) }

// DependencyBytes returns an independent copy of the complete dependency bytes.
func (i *Installed) DependencyBytes() []byte { return slices.Clone(i.dependency) }

// Previous reports the verified selection that preceded an installation decision.
// It does not provide an executable or permission to replay an operation.
type Previous struct {
	Version  string          `json:"version"`
	Artifact artifact.Digest `json:"artifact"`
	Platform string          `json:"platform"`
	Source   string          `json:"source"`
}

// Installation is one bounded outcome row, including failed selection facts.
// Changed reports a published selection change even if later completion failed;
// callers must also check Resolve's error. Public fields alone grant no readiness.
type Installation struct {
	Name             string           `json:"name"`
	Role             string           `json:"role"`
	Version          string           `json:"version"`
	Artifact         *artifact.Digest `json:"artifact"`
	Platform         string           `json:"platform"`
	Source           string           `json:"source"`
	Status           string           `json:"status"`
	Reason           string           `json:"reason"`
	Previous         *Previous        `json:"previous"`
	Changed          bool             `json:"changed"`
	executableSHA256 artifact.Digest
	descriptor       artifact.Descriptor
}

// ExecutableSHA256 reports completed byte verification independently of an
// invocation session. Failed rows and caller-constructed rows supply no fact.
func (r Installation) ExecutableSHA256() (artifact.Digest, bool) {
	if !artifact.ValidPluginID(r.Name) || r.descriptor.Name != r.Name || r.descriptor.Role != r.Role || r.descriptor.Version != r.Version || r.Status != "verified" || r.Reason != "none" || !artifact.ValidVersion(r.Version) || r.Artifact == nil || r.Artifact.IsZero() || r.Platform != "darwin/arm64" && r.Platform != "linux/amd64" || r.Source != "local" && r.Source != "official" || r.executableSHA256.IsZero() {
		return artifact.Digest{}, false
	}
	return r.executableSHA256, true
}

// WireContract reports the supported family protocol declaration after completed
// installation verification. It supplies no invocation readiness.
func (r Installation) WireContract() (artifact.Contract, bool) {
	if _, verified := r.ExecutableSHA256(); !verified {
		return artifact.Contract{}, false
	}
	return r.descriptor.Wire, true
}

// ConfigContractID reports an effect family's verified configuration contract
// independently of an invocation session. It supplies no operation permission.
func (r Installation) ConfigContractID() (string, bool) {
	if _, verified := r.ExecutableSHA256(); !verified {
		return "", false
	}
	switch r.Role {
	case "generator":
		if r.descriptor.Generator != nil && !r.descriptor.Generator.ConfigContractID.IsZero() {
			return r.descriptor.Generator.ConfigContractID.String(), true
		}
	case "output":
		if r.descriptor.Output != nil && r.descriptor.Output.ConfigContractID != "" {
			return r.descriptor.Output.ConfigContractID, true
		}
	}
	return "", false
}

// Session holds immutable captured installations from one Resolve. Prepare and
// Upgrade may return verified partial captures alongside a nonnil error after
// stable-source and live-context checks. Check that error and every Lookup;
// partial captures are evidence, never all-dependencies readiness. Ordinary
// returns no session on error. Its zero value has no installations; it owns no
// running child or private input.
type Session struct{ installed map[string]*Installed }

// Lookup returns the shared immutable capture for name. A nil session or
// missing name returns false; callers must not treat a missing capture as ready.
func (s *Session) Lookup(name string) (*Installed, bool) {
	if s == nil {
		return nil, false
	}
	i, ok := s.installed[name]
	return i, ok
}

// Request contains safe requirements and an explicit trusted application scope.
// CheckSource must recheck the exact source-pair pins captured by the caller.
// A callable composition without a file pair supplies its own scope check.
type Request struct {
	Directory    string
	Requirements []Requirement
	Mode         Mode
	CheckSource  func(context.Context) error
}

func validRequirements(rows []Requirement) bool {
	if len(rows) > 64 {
		return false
	}
	for j, r := range rows {
		if !artifact.ValidPluginID(r.Name) || r.Version != "" && !artifact.ValidVersion(r.Version) || j > 0 && rows[j-1].Name >= r.Name {
			return false
		}
	}
	return true
}

func canonicalDirectory(path string) (string, error) {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, 0) {
		return "", ErrInvalid
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func failureRow(row Installation, err error) Installation {
	row.Changed = false
	switch {
	case errors.Is(err, ErrMissing):
		row.Status, row.Reason = "missing", "not-installed"
	case errors.Is(err, ErrSignature), errors.Is(err, artifact.ErrSignature):
		row.Status, row.Reason = "tampered", "signature-invalid"
	case candidateMaySkip(err) || onlyIncompatible(err):
		row.Status, row.Reason = "incompatible", "unsupported-protocol"
	case errors.Is(err, ErrIdentity):
		row.Status, row.Reason = "tampered", "identity-mismatch"
	case errors.Is(err, ErrInvalid), errors.Is(err, artifact.ErrRecord):
		row.Status, row.Reason = "tampered", "record-invalid"
	default:
		row.Status, row.Reason = "unavailable", "unavailable"
	}
	return row
}
