// Package configuration reads the bounded portable configuration pair. Parsing
// supplies public facts; it grants no authenticated identity or operation power.
package configuration

import (
	"fmt"
	"strings"

	"enkv.sh/core/contract"
)

type Format uint8

const (
	JSON Format = iota + 1
	YAML
)
const (
	MaxPairBytes int64 = contract.MaxConfigurationPairLength
	WindowBytes        = 64 << 10
	MaxDepth           = 16
	MaxSpans           = 8192
)

type Span struct {
	Offset, Length int64
	Line, Column   uint64
	Kind           uint16
	// Entry spans also retain the context of their packed value location.
	Flow, ValueFlow            bool
	Index                      uint32
	SourceOffset, SourceLength int64
	ValueOffset, ValueLength   uint32
}
type Diagnostic struct {
	Field        string
	Context      bool // Position identifies enclosing context when true.
	Generated    bool // Positions belong to the generated JSON image when true.
	Offset       int64
	Line, Column uint64
	Reason       string
	cause        error
}

func (d *Diagnostic) Unwrap() error { return d.cause }

func (d *Diagnostic) Error() string {
	if d.Line == 0 || d.Column == 0 {
		return fmt.Sprintf("configuration %s: %s", d.Field, d.Reason)
	}
	if d.Context {
		return fmt.Sprintf("configuration %s context at %d:%d: %s", d.Field, d.Line, d.Column, d.Reason)
	}
	return fmt.Sprintf("configuration %s at %d:%d: %s", d.Field, d.Line, d.Column, d.Reason)
}

type Binding struct {
	ID, Incarnation contract.ID
	Serial          uint64
	Protection      uint8
}
type Key struct {
	GeneratedSpan uint32
	Selector      string
	PublicKey     []byte
	Binding       Binding
}
type Role struct {
	SigningSpan, EncryptionSpan                      uint32
	ID                                               contract.ID
	DisplayName, SigningSelector, EncryptionSelector string
	Signing, Encryption                              Key
}
type Recipient struct {
	SelectorSpan                     uint32
	IDSpan                           uint32 // MaxSpans when source id is absent.
	EditableSpan, GeneratedSpan      uint32
	Reference, DisplayName, Selector string
	ID                               contract.ID
	Encryption                       Key
	Creation                         *Creation
}
type Creation struct{ Snapshot, Nonce contract.ID }
type Pin struct{ Incarnation, Material contract.ID }
type Entry struct {
	EntrySpan, SecretSpan         uint32
	Name                          string
	Secret                        bool
	PlainBase64                   bool
	InputEncoding, OutputEncoding uint8
	ContentLength                 uint32
	Recipients                    []string
	Plain                         []byte
	Generated                     *Generator
	Sealed                        []byte
	Retained                      *Pin
}

// Settings retains the ordinary source arm. Intent holds canonical meaning;
// when Settings is nil, the nested view is backed by one exact saved record.
type Generator struct {
	Plugin                             string
	Settings, Intent                   []byte
	canonicalSettings, canonicalRecord []byte
	Epoch                              uint64
	Retirement                         string
}

// Binding carries source-ready targets with no durable entry incarnations.
// Ordinary settings leave targets to the operation's routed interpretation.
type OutputBinding struct {
	DestinationID, Plugin              string
	Settings                           []byte
	canonicalSettings, canonicalRecord []byte
	settingsEdited                     bool
	SourceIndex                        uint16
	Binding                            contract.NormalOutputBinding
}

// CanonicalSettingsEdited reports whether the source view differs from the saved record.
func (b *OutputBinding) CanonicalSettingsEdited() bool { return b.settingsEdited }

type Route struct {
	Default      bool
	EntryName    string
	Destinations []string
}
type Enrollment struct {
	ID          contract.ID
	Status      uint8
	DisplayName string
}
type Basis struct {
	Descriptor, Control, Selection                []byte
	Enrollment                                    []Enrollment
	SigningAnchor, StoreConfiguration, HEAD, Root []byte
	RecipientPages                                [][]byte
}
type Observation struct{ StoreConfiguration, Head []byte }

// PluginRequirement is a source-local release preference. An empty Version is
// unpinned and does not select an installed executable.
type PluginRequirement struct{ Name, Version string }

type Model struct {
	layoutRoot, layoutEntries, layoutEntry, layoutSource         layoutSize
	RootSpan, GeneratedSpan                                      uint32
	DomainNameSpan                                               uint32
	EntriesSpan, SecretsSpan                                     uint32
	SelectedSecretSpan                                           uint32
	SelectedSecretPresent                                        bool
	SecretRowsCount                                              uint32
	SelectedConfidentialityOffset, SelectedConfidentialityLength uint32
	discardPayloads                                              bool
	preparation                                                  bool
	selected                                                     *string
	selectedRecipient, selectedReference                         *string
	parsedPair                                                   *Pair
	RecipientsSpan, GeneratedRecipientsSpan                      uint32
	Public                                                       contract.PublicConfiguration
	FileID, DomainID                                             contract.ID
	Provider                                                     contract.Family
	Store                                                        contract.StoreLocation
	Authority                                                    Role
	RecoveryEnabled                                              bool
	Recovery                                                     Role
	Recipients                                                   []Recipient
	GeneratedRecipients                                          []Recipient
	GeneratedRootSpan, BasisSpan, ReplacementSpan                uint32
	Replacement                                                  *ReplacementMetadata
	MaintenanceSpan                                              uint32
	Maintenance                                                  *MaintenanceMetadata
	maintenance                                                  bool
	maintenanceRemovals                                          []maintenanceRemoval
	Routes                                                       []Route
	Outputs                                                      []OutputBinding
	Plugins                                                      []PluginRequirement
	Entries                                                      []Entry
	// MissingInputs is complete only after successful preparation parsing or
	// reconstruction joining. Its ordered names borrow the declared entry names.
	MissingInputs []string
	Basis         Basis
	Observation   *Observation
	Generated     string
	DomainName    string
	Spans         []Span
	Resolved      bool
}

func present[T any](v T) contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicPresent, Value: v}
}

const (
	SpanRoot uint16 = iota + 1
	SpanDomain
	SpanRole
	SpanKey
	SpanRecipient
	SpanEntry
	SpanSecret
	SpanDestination
	SpanRoute
	SpanGroup
	SpanGeneratedReference
	SpanEntries
	SpanSecrets
	SpanRecipients
	SpanRecipientReference
	SpanCanonicalGenerator
)

// TakePublic transfers the public input and releases source-only owners.
func (m *Model) TakePublic() (contract.PublicConfiguration, Basis) {
	p, b := m.Public, m.Basis
	*m = Model{}
	return p, b
}

func (b *Basis) clear() {
	for _, body := range [][]byte{b.Descriptor, b.Control, b.Selection, b.SigningAnchor, b.StoreConfiguration, b.HEAD, b.Root} {
		clear(body)
	}
	for _, page := range b.RecipientPages {
		clear(page)
	}
	clear(b.Enrollment)
	*b = Basis{}
}

// DiagnosticFieldValid admits only bounded schema categories. User-defined
// names are represented by item at the parser boundary.
func DiagnosticFieldValid(field string) bool {
	if len(field) > 512 {
		return false
	}
	if field == "" {
		return true
	}
	parts := strings.Split(field, ".")
	if len(parts) > MaxDepth {
		return false
	}
	for _, part := range parts {
		if part == "" || safeField(part) != part {
			return false
		}
	}
	return true
}

// DiagnosticReasonValid closes safe source-failure reasons for public results.
func DiagnosticReasonValid(reason string) bool {
	switch reason {
	case "changed-generated-path", "domain-name-reference-mismatch", "invalid-generated-path", "missing-prepared-recipient", "missing-prepared-secret", "additional-document", "aggregate-limit", "array-required", "base64-limit-or-padding", "binding-name-mismatch", "block-value-separation", "boolean-required", "cancelled", "collection-limit", "colon-separation", "complex-key", "depth-limit", "directive-forbidden", "duplicate-enrollment-id", "duplicate-group-member", "duplicate-key", "duplicate-or-empty-destination", "duplicate-or-empty-reference", "duplicate-recipient-id", "empty-basis", "empty-destination", "empty-group", "empty-reference", "empty-route", "empty-scalar", "expired", "flow-indicator-in-plain-scalar", "generated-limit", "generator-declaration-limit", "group-member-limit", "integer-range", "integer-required", "invalid-base64", "invalid-basis", "invalid-binding-serial", "invalid-block-header", "invalid-candidate", "invalid-canonical-binding", "invalid-canonical-intent", "invalid-confidentiality", "invalid-context", "invalid-control", "invalid-domain-name", "invalid-encoding", "invalid-enrollment-status", "invalid-escape", "invalid-generated-reference", "invalid-generator-input", "invalid-id", "invalid-indentation", "invalid-input-representation", "invalid-key-selector", "invalid-maintenance", "invalid-observation", "invalid-output-encoding", "invalid-output-input", "invalid-output-reference", "invalid-owner", "invalid-plugin", "invalid-plugin-version", "invalid-protection", "invalid-public-key", "invalid-replacement", "invalid-scalar", "invalid-sealed-input", "invalid-selected-name", "invalid-selected-reference", "invalid-sequence", "invalid-settings-value", "invalid-source", "invalid-store", "invalid-surrogate", "invalid-unicode", "invalid-unicode-escape", "merge-forbidden", "missing-plugin", "missing-required-field", "missing-secret-input", "object-required", "output-configuration-limit", "output-declaration-limit", "output-target-limit", "pair-size-limit", "prepare-selected-key", "raw-value-limit", "read-failed", "recovery-mode-mismatch", "restore-exact-generated-file", "routing-byte-limit", "routing-count-limit", "scalar-limit", "sealed-context-mismatch", "sealed-input-limit", "settings-limit", "span-limit", "store-mismatch", "string-required", "tab-indentation", "trailing-comma", "trailing-content", "undeclared-generated-file", "unescaped-control", "unexpected-end", "unexpected-token", "unknown-field", "unresolved-reference", "unsupported-format", "unsupported-provider", "unsupported-scalar", "unsupported-schema":
		return true
	}
	return false
}
