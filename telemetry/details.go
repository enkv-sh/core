package telemetry

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

const (
	maximumReviewedPathLength = 1024
	diagnosticDigestLength    = 32
	maximumInvocationIDLength = 64
	maximumWorkerIDLength     = 96
	maximumEntryNameLength    = 256
	maximumHTTPStatus         = 599
)

// DiagnosticDetails contains only fields whose source owner has reviewed their
// meaning. It has no message, raw error, credential, or plaintext field.
// A caller builds details before StartWithDetails admits any record.
type DiagnosticDetails struct {
	entryName    string
	keyID        string
	commandID    string
	attemptID    string
	invocationID string
	workerID     string
	pathKind     string
	path         string
	configField  string
	errorClass   DiagnosticReason
	httpStatus   int
	errorText    string
	invalid      bool
}

// WithReviewedPath copies a path after its source owner has removed private
// segments, such as credential filenames and plaintext-derived names.
func (details DiagnosticDetails) WithReviewedPath(path string) DiagnosticDetails {
	if !validPublicText(path, maximumReviewedPathLength) {
		details.invalid = true
	} else {
		details.path = strings.Clone(path)
	}
	return details
}

func (details DiagnosticDetails) WithEntryName(name string) DiagnosticDetails {
	if !validPublicName(name) {
		details.invalid = true
	} else {
		details.entryName = strings.Clone(name)
	}
	return details
}

func (details DiagnosticDetails) WithKeyID(id string) DiagnosticDetails {
	if !validDiagnosticDigest(id) {
		details.invalid = true
	} else {
		details.keyID = strings.Clone(strings.ToLower(id))
	}
	return details
}

// WithCommandID accepts a non-secret digest that identifies one command.
func (details DiagnosticDetails) WithCommandID(id string) DiagnosticDetails {
	if !validDiagnosticDigest(id) {
		details.invalid = true
	} else {
		details.commandID = strings.Clone(strings.ToLower(id))
	}
	return details
}

// WithAttemptID accepts a non-secret generated-attempt identity.
func (details DiagnosticDetails) WithAttemptID(id string) DiagnosticDetails {
	if !validDiagnosticDigest(id) {
		details.invalid = true
	} else {
		details.attemptID = strings.Clone(strings.ToLower(id))
	}
	return details
}

func (details DiagnosticDetails) WithInvocationID(id string) DiagnosticDetails {
	if !validDiagnosticIdentity(id, maximumInvocationIDLength) {
		details.invalid = true
	} else {
		details.invocationID = strings.Clone(id)
	}
	return details
}

func (details DiagnosticDetails) WithWorkerID(id string) DiagnosticDetails {
	if !validDiagnosticIdentity(id, maximumWorkerIDLength) {
		details.invalid = true
	} else {
		details.workerID = strings.Clone(id)
	}
	return details
}

func validDiagnosticDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == diagnosticDigestLength
}

func validDiagnosticIdentity(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// PathKind names a reviewed logical Product path, never a credential or host
// filesystem path. Its small vocabulary prevents arbitrary path capture.
func (details DiagnosticDetails) WithPathKind(kind string) DiagnosticDetails {
	switch kind {
	case "state_head", "state_object", "trust_key", "generator_artifact":
		details.pathKind = kind
	default:
		details.invalid = true
	}
	return details
}

// ConfigField names a public configuration key. Values are never recorded.
func (details DiagnosticDetails) WithConfigField(field string) DiagnosticDetails {
	switch field {
	case "provider", "region", "domain", "recovery_mode", "generator":
		details.configField = field
	default:
		details.invalid = true
	}
	return details
}

// WithErrorFacts projects a typed disposition and numeric HTTP status. It has
// no error object or free-form text argument, so raw provider errors cannot
// enter the capture buffer through this path.
func (details DiagnosticDetails) WithErrorFacts(class DiagnosticReason, status int) DiagnosticDetails {
	if !validDiagnosticReason(class) || class == "" || status < 0 || status > maximumHTTPStatus {
		details.invalid = true
	} else {
		details.errorClass, details.httpStatus = class, status
	}
	return details
}

// WithReviewedErrorText copies text projected by the source owner from a known
// error type. Do not pass error.Error() or transport response bodies here.
func (details DiagnosticDetails) WithReviewedErrorText(text string) DiagnosticDetails {
	if !validPublicText(text, MaximumErrorBytes) {
		details.invalid = true
	} else {
		details.errorText = strings.Clone(text)
	}
	return details
}

func validPublicName(name string) bool {
	return validPublicText(name, maximumEntryNameLength)
}

func validPublicText(name string, limit int) bool {
	if name == "" || len(name) > limit || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

func validDetails(details DiagnosticDetails) bool {
	if details.invalid || details.entryName != "" && !validPublicName(details.entryName) {
		return false
	}
	for _, id := range []string{details.keyID, details.commandID, details.attemptID} {
		if id != "" && (!validDiagnosticDigest(id) || id != strings.ToLower(id)) {
			return false
		}
	}
	if details.invocationID != "" && !validDiagnosticIdentity(details.invocationID, maximumInvocationIDLength) || details.workerID != "" && !validDiagnosticIdentity(details.workerID, maximumWorkerIDLength) {
		return false
	}
	if details.pathKind != "" {
		if (DiagnosticDetails{}).WithPathKind(details.pathKind).invalid {
			return false
		}
	}
	if details.path != "" && !validPublicText(details.path, maximumReviewedPathLength) {
		return false
	}
	if details.configField != "" {
		if (DiagnosticDetails{}).WithConfigField(details.configField).invalid {
			return false
		}
	}
	if details.errorText != "" && !validPublicText(details.errorText, MaximumErrorBytes) {
		return false
	}
	if details.errorClass == "" {
		return details.httpStatus == 0 && details.errorText == ""
	}
	return validDiagnosticReason(details.errorClass) && details.httpStatus >= 0 && details.httpStatus <= maximumHTTPStatus
}

func errorDetail(details DiagnosticDetails) string {
	return details.errorText
}

func errorDetailStatus(details DiagnosticDetails) string {
	if details.errorClass == "" {
		return ""
	}
	if details.errorText == "" {
		return "unavailable"
	}
	return "reviewed"
}
