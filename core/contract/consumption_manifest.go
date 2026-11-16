package contract

import (
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
)

const (
	// MaxManifestResultJSONBytes is the complete compact issuance account.
	// Native readable codecs apply their separate layout bound.
	MaxManifestResultJSONBytes                  = 2162688
	ReasonTargetAbsent         DiagnosticReason = "target-absent"
	ReasonEntryAbsent          DiagnosticReason = "entry-absent"
	ReasonDuplicateEntry       DiagnosticReason = "duplicate-entry"
	ReasonTargetNotAuthorized  DiagnosticReason = "target-not-authorized"
	ReasonLocatorUnusable      DiagnosticReason = "locator-unusable"
)

// ManifestRendererSelection names one exact installed build. These public facts
// do not authenticate that build or grant permission to execute it.
type ManifestRendererSelection struct {
	Name                 string `json:"name"`
	Version              string `json:"version"`
	ProtocolID           ID     `json:"protocol_id"`
	DescriptorID         ID     `json:"descriptor_id"`
	ExecutorID           ID     `json:"executor_id"`
	ArtifactContractID   ID     `json:"artifact_contract_id"`
	DependencyManifestID ID     `json:"dependency_manifest_id"`
	ArtifactID           ID     `json:"artifact_id"`
	ArtifactSHA256       ID     `json:"artifact_sha256"`
	ArtifactLength       uint64 `json:"artifact_length"`
}

// ManifestRequestScope records canonical renderer, settings and selection facts
// for request correlation. Its mutable fields have the enclosing request owner;
// the struct itself neither authenticates a build nor grants Reader authority.
type ManifestRequestScope struct {
	Renderer         ManifestRendererSelection `json:"renderer"`
	FormatContractID string                    `json:"format_contract_id"`
	ConfigContractID string                    `json:"config_contract_id"`
	Settings         []byte                    `json:"settings"`
	Selection        manifest.Selection        `json:"selection"`
	ServiceFilter    *string                   `json:"service_filter"`
}

// ManifestRequest carries canonical bytes returned by the selected build's settings
// validation. Composition retains that exact build for rendering. Exact-names
// requires a nonnil vector; a nonnil empty selection is valid.
type ManifestRequest struct {
	Renderer          ManifestRendererSelection
	FormatContractID  string
	ConfigContractID  string
	Settings          []byte
	TargetMode        manifest.TargetMode
	EntryMode         manifest.EntryMode
	ServiceFilter     *string
	TargetRecipientID ID
	EntryNames        []string
}

// ManifestRequestError reports a closed common request failure reason. Use
// errors.As to inspect Reason; it carries no plugin-supplied diagnostic text.
type ManifestRequestError struct{ Reason DiagnosticReason }

func (e ManifestRequestError) Error() string { return "manifest request refused: " + string(e.Reason) }

// OwnManifestRequest checks common syntax and bounds before copying and orders
// exact UTF-8 names. It does not verify plugin semantics, authenticate the build
// or target, or issue Reader permission. Returned mutable fields are independent
// copies. Refusals return ManifestRequestError; a zero request is invalid.
func OwnManifestRequest(request ManifestRequest) (ManifestRequest, error) {
	fail := func(reason DiagnosticReason) (ManifestRequest, error) {
		return ManifestRequest{}, ManifestRequestError{Reason: reason}
	}
	if reason := manifestRendererSelectionReason(request.Renderer); reason != "" {
		return fail(reason)
	}
	for _, value := range []string{request.FormatContractID, request.ConfigContractID} {
		if reason := manifestSemanticReason(value); reason != "" {
			return fail(reason)
		}
	}
	switch manifest.ValidateSettings(request.Settings) {
	case "":
	case manifest.LimitExceeded:
		return fail(ReasonLimitExceeded)
	case manifest.InvalidUTF8:
		return fail(ReasonInvalidUTF8)
	default:
		return fail(ReasonInvalidInput)
	}
	switch request.TargetMode {
	case manifest.CurrentAuthority:
		request.TargetMode = manifest.CurrentAuthority
		if !request.TargetRecipientID.IsZero() {
			return fail(ReasonInvalidInput)
		}
	case manifest.ExactRecipient:
		request.TargetMode = manifest.ExactRecipient
		if request.TargetRecipientID.IsZero() {
			return fail(ReasonMissingRequiredField)
		}
	case "":
		return fail(ReasonMissingRequiredField)
	default:
		return fail(ReasonInvalidInput)
	}
	switch request.EntryMode {
	case manifest.AllAuthorized:
		request.EntryMode = manifest.AllAuthorized
		if request.EntryNames != nil {
			return fail(ReasonInvalidInput)
		}
	case manifest.ExactNames:
		request.EntryMode = manifest.ExactNames
		if request.EntryNames == nil {
			return fail(ReasonMissingRequiredField)
		}
	case "":
		return fail(ReasonMissingRequiredField)
	default:
		return fail(ReasonInvalidInput)
	}
	if request.ServiceFilter != nil {
		if reason := manifestSemanticReason(*request.ServiceFilter); reason != "" {
			return fail(reason)
		}
	}
	if len(request.EntryNames) > CryptoMaxValueEntries {
		return fail(ReasonLimitExceeded)
	}
	for _, name := range request.EntryNames {
		if len(name) > CryptoMaxName {
			return fail(ReasonLimitExceeded)
		}
		if !utf8.ValidString(name) {
			return fail(ReasonInvalidUTF8)
		}
	}
	owned := request
	owned.Renderer.Name = strings.Clone(request.Renderer.Name)
	owned.Renderer.Version = strings.Clone(request.Renderer.Version)
	owned.FormatContractID = strings.Clone(request.FormatContractID)
	owned.ConfigContractID = strings.Clone(request.ConfigContractID)
	owned.Settings = make([]byte, len(request.Settings))
	copy(owned.Settings, request.Settings)
	if request.ServiceFilter != nil {
		filter := strings.Clone(*request.ServiceFilter)
		owned.ServiceFilter = &filter
	}
	if request.EntryNames != nil {
		owned.EntryNames = make([]string, len(request.EntryNames))
	}
	for i, name := range request.EntryNames {
		owned.EntryNames[i] = strings.Clone(name)
	}
	slices.Sort(owned.EntryNames)
	for i := 1; i < len(owned.EntryNames); i++ {
		if owned.EntryNames[i-1] == owned.EntryNames[i] {
			return fail(ReasonDuplicateEntry)
		}
	}
	return owned, nil
}

func manifestSemanticReason(value string) DiagnosticReason {
	if len(value) > manifest.MaxContractBytes {
		return ReasonLimitExceeded
	}
	if !utf8.ValidString(value) {
		return ReasonInvalidUTF8
	}
	if value == "" {
		return ReasonMissingRequiredField
	}
	return ""
}

func manifestRendererSelectionReason(renderer ManifestRendererSelection) DiagnosticReason {
	if len(renderer.Name) > 255 || len(renderer.Version) > 128 || renderer.ArtifactLength > artifact.MaxExecutableBytes {
		return ReasonLimitExceeded
	}
	if renderer.Name == "" || renderer.Version == "" || renderer.ArtifactLength == 0 {
		return ReasonMissingRequiredField
	}
	if !artifact.ValidPluginID(renderer.Name) || !artifact.ValidVersion(renderer.Version) {
		return ReasonInvalidInput
	}
	for _, id := range [...]ID{renderer.ProtocolID, renderer.DescriptorID, renderer.ExecutorID, renderer.ArtifactContractID,
		renderer.DependencyManifestID, renderer.ArtifactID, renderer.ArtifactSHA256} {
		if id.IsZero() {
			return ReasonMissingRequiredField
		}
	}
	return ""
}

// ManifestPayload reports input-selection facts and completion of one exact
// in-memory artifact. It grants no format-validity, semantic-correspondence,
// independent-verification, output-delivery or existence claim.
type ManifestPayload struct {
	Renderer          ManifestRendererSelection
	FormatContractID  string
	ConfigContractID  string
	Settings          []byte
	Selection         manifest.Selection
	ServiceFilter     *string
	IncludedEntries   []manifest.EntryIdentity
	ExcludedEntries   []manifest.ExcludedEntry
	Observation       manifest.Observation
	TargetRecipientID ID
	ArtifactLength    uint64
	ArtifactDigest    ID
	EvidenceLimit     string
}
