package records

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
)

const StockRetirementProofPurpose = "stock-plugin-retirement-proof"
const StockPluginScenario = "public-configuration.plugin-contracts/plugin_contracts"
const StockPluginEvidenceVersion uint16 = 1
const MaximumStockPluginEvidenceBytes = 256 << 10
const MaximumStockPluginDiagnosticBytes = 256 << 10
const MaximumStockPluginCommands = 64
const MaximumStockPluginVerifications = 32

// StockPluginFixture identifies one reusable test bucket. Each run receives
// separate authority over its own prefix, never over the whole bucket.
type StockPluginFixture struct {
	Schema        uint16 `json:"schema"`
	Purpose       string `json:"purpose"`
	FixtureID     string `json:"fixture_id"`
	Provider      string `json:"provider"`
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	Account       string `json:"account,omitempty"`
	Project       string `json:"project,omitempty"`
	ProjectNumber string `json:"project_number,omitempty"`
}

var stockFixtureLabel = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func (v StockPluginFixture) Validate() error {
	if v.Schema != 1 || !validHex(v.FixtureID, 16) ||
		!stockFixtureLabel.MatchString(v.Bucket) || !strings.HasSuffix(v.Bucket, "-pa-"+v.FixtureID) ||
		v.Region == "" || len(v.Region) > 64 || strings.ContainsAny(v.Region, "/\\\x00 \t\n") {
		return errRecord
	}
	switch v.Purpose {
	case StockRetirementProofPurpose:
		if v.Provider != "aws" || v.Bucket != "enkv-"+v.Account+"-pa-"+v.FixtureID {
			return errRecord
		}
	case "stock-plugin-acceptance":
	default:
		return errRecord
	}
	switch v.Provider {
	case "aws":
		if len(v.Account) != 12 || strings.Trim(v.Account, "0123456789") != "" || v.Project != "" || v.ProjectNumber != "" {
			return errRecord
		}
	case "gcp":
		if v.Account != "" || !stockFixtureLabel.MatchString(v.Project) || len(v.ProjectNumber) < 6 || len(v.ProjectNumber) > 20 || strings.Trim(v.ProjectNumber, "0123456789") != "" {
			return errRecord
		}
	default:
		return errRecord
	}
	return nil
}

// The AWS stock scenario owns the real Cloudflare retirement qualification.
// Existing grants still identify their original fixture during recovery.
func (v StockPluginFixture) ValidateNewStockRun() error {
	if err := v.Validate(); err != nil {
		return err
	}
	if v.Provider == "aws" && v.Purpose != StockRetirementProofPurpose {
		return errRecord
	}
	return nil
}

// The private grant binds the configured fixture to one original run prefix.
// PreflightEmpty describes that prefix, not the rest of the bucket.
type StockPluginGrant struct {
	Schema         uint16             `json:"schema"`
	Fixture        StockPluginFixture `json:"fixture"`
	RunID          string             `json:"run_id"`
	Scenario       string             `json:"scenario"`
	Prefix         string             `json:"prefix"`
	LimitsSHA256   string             `json:"limits_sha256"`
	PreflightEmpty bool               `json:"preflight_empty"`
	BucketIdentity string             `json:"bucket_identity"`
}

// ObservedEmpty qualifies the final prefix listing. It does not fence a
// request that can arrive after that observation.
type StockPluginPrefixCleanup struct {
	Schema         uint16 `json:"schema"`
	RunID          string `json:"run_id"`
	FixtureID      string `json:"fixture_id"`
	Prefix         string `json:"prefix"`
	BucketIdentity string `json:"bucket_identity"`
	Started        bool   `json:"started"`
	Completed      bool   `json:"completed"`
	ObservedEmpty  bool   `json:"observed_empty"`
}

func (v StockPluginPrefixCleanup) Validate(grant StockPluginGrant) error {
	if grant.Validate() != nil || v.Schema != 1 || v.RunID != grant.RunID || v.FixtureID != grant.Fixture.FixtureID ||
		v.Prefix != grant.Prefix || v.BucketIdentity != grant.BucketIdentity || !v.Started || !v.Completed || !v.ObservedEmpty {
		return errRecord
	}
	return nil
}

func (v StockPluginGrant) Validate() error {
	if v.Schema != 1 || v.Fixture.Validate() != nil || !ValidRunID(v.RunID) || v.Scenario != StockPluginScenario ||
		!strings.HasPrefix(v.Prefix, "enkv-test/"+v.RunID+"/") || filepath.Clean(v.Prefix) != v.Prefix ||
		strings.Contains(v.Prefix, `\`) || !validHex(v.LimitsSHA256, 32) || !v.PreflightEmpty || v.BucketIdentity == "" || len(v.BucketIdentity) > 256 || strings.ContainsRune(v.BucketIdentity, 0) {
		return errRecord
	}
	return nil
}

type StockPluginFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Length uint64 `json:"length"`
}

func (v StockPluginFile) valid(maximum uint64) bool {
	return filepath.IsAbs(v.Path) && filepath.Clean(v.Path) == v.Path && !strings.ContainsRune(v.Path, 0) && validHex(v.SHA256, 32) && v.Length > 0 && v.Length <= maximum
}

type StockPluginBuild struct {
	Directory string            `json:"directory"`
	Metadata  artifact.Metadata `json:"metadata"`
}

func (v StockPluginBuild) valid(role, name, platform string) bool {
	_, err := artifact.EncodeMetadata(v.Metadata)
	return err == nil && filepath.IsAbs(v.Directory) && filepath.Clean(v.Directory) == v.Directory &&
		v.Metadata.Name == name && v.Metadata.Role == role && v.Metadata.Platform == platform && v.Metadata.Toolchain == "go1.27.3"
}

type StockPluginArtifact struct {
	Schema     uint16             `json:"schema"`
	CLI        StockPluginFile    `json:"cli"`
	Archive    StockPluginFile    `json:"archive"`
	Platform   string             `json:"platform"`
	Toolchain  string             `json:"toolchain"`
	Source     Source             `json:"source"`
	GeneratorA StockPluginBuild   `json:"generator_a"`
	GeneratorB StockPluginBuild   `json:"generator_b"`
	Outputs    []StockPluginBuild `json:"outputs"`
	Renderer   StockPluginBuild   `json:"renderer"`
}

func StockPluginOutputNames(provider string) []string {
	if provider == "aws" {
		return []string{"aws-secrets-manager", "github-actions-repository", "github-actions-organization", "github-actions-environment"}
	}
	if provider == "gcp" {
		return []string{"gcp-secret-manager"}
	}
	return nil
}

func (v StockPluginArtifact) Validate(provider string) error {
	if v.Schema != 1 || !v.CLI.valid(artifact.MaxExecutableBytes) || !v.Archive.valid(artifact.MaxArchiveBytes) ||
		(v.Platform != "darwin/arm64" && v.Platform != "linux/amd64") || v.Toolchain != "go1.27.3" ||
		!v.GeneratorA.valid("generator", "cloudflare-account-token", v.Platform) || !v.GeneratorB.valid("generator", "cloudflare-account-token", v.Platform) ||
		!v.Renderer.valid("manifest-generator", "workshop-ini", v.Platform) {
		return errRecord
	}
	a, errA := v.GeneratorA.Metadata.GeneratorFacts()
	b, errB := v.GeneratorB.Metadata.GeneratorFacts()
	if errA != nil || errB != nil || a.ExecutorID == b.ExecutorID || a.DescriptorID == b.DescriptorID ||
		v.GeneratorA.Metadata.Executable == v.GeneratorB.Metadata.Executable ||
		a.Descriptor.Generator.ConfigContractID != b.Descriptor.Generator.ConfigContractID ||
		bytes.Equal(a.Descriptor.Generator.CredentialRoute, b.Descriptor.Generator.CredentialRoute) {
		return errRecord
	}
	for _, facts := range []artifact.GeneratorFacts{a, b} {
		route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
		if err != nil || route.Mode != credentialroute.ModeEnvironment || len(route.Names) != 1 {
			return errRecord
		}
	}
	want := StockPluginOutputNames(provider)
	if len(want) == 0 || len(v.Outputs) != len(want) {
		return errRecord
	}
	for i, name := range want {
		if !v.Outputs[i].valid("output", name, v.Platform) {
			return errRecord
		}
	}
	return nil
}

type StockPluginAcceptanceInput struct {
	CloudflareAccount         string              `json:"cloudflare_account"`
	CloudflarePermissionGroup string              `json:"cloudflare_permission_group"`
	Fixture                   StockPluginFixture  `json:"fixture"`
	Artifact                  StockPluginArtifact `json:"artifact"`
}

type StockPluginCommand struct {
	Ordinal          uint32 `json:"ordinal"`
	Worker           string `json:"worker"`
	Nonce            string `json:"nonce"`
	Role             string `json:"role"`
	Actor            string `json:"actor"`
	Phase            string `json:"phase"`
	Started          bool   `json:"started"`
	Joined           bool   `json:"joined"`
	ExitCode         int    `json:"exit_code"`
	ResultSHA256     string `json:"result_sha256"`
	DiagnosticSHA256 string `json:"diagnostic_sha256,omitempty"`
	DiagnosticBytes  uint32 `json:"diagnostic_bytes,omitempty"`
	DiagnosticStatus string `json:"diagnostic_status,omitempty"`
}

type StockPluginGeneration struct {
	Phase             string `json:"phase"`
	Epoch             uint64 `json:"epoch"`
	GenerationID      string `json:"generation_id"`
	ResourceID        string `json:"resource_id"`
	ResourceDigest    string `json:"resource_digest"`
	OriginOperationID string `json:"origin_operation_id"`
	OriginAttemptID   string `json:"origin_attempt_id"`
}

type StockPluginCreate struct {
	Phase              string `json:"phase"`
	OperationID        string `json:"operation_id"`
	AttemptID          string `json:"attempt_id"`
	GenerationID       string `json:"generation_id"`
	ResourceID         string `json:"resource_id"`
	ResourceDigest     string `json:"resource_digest"`
	DescriptorID       string `json:"descriptor_id"`
	ExecutorID         string `json:"executor_id"`
	CredentialRouteID  string `json:"credential_route_id"`
	ConfigContractID   string `json:"config_contract_id"`
	ResourceContractID string `json:"resource_contract_id"`
	ResultContractID   string `json:"result_contract_id"`
}

type StockPluginDuty struct {
	Phase               string `json:"phase"`
	DutyID              string `json:"duty_id"`
	ResourceID          string `json:"resource_id"`
	DescriptorID        string `json:"descriptor_id"`
	ExecutorID          string `json:"executor_id"`
	CredentialRouteID   string `json:"credential_route_id"`
	ResultContractID    string `json:"result_contract_id"`
	OriginalOperationID string `json:"original_operation_id"`
	OriginalAttemptID   string `json:"original_attempt_id"`
}

type StockPluginRetirement struct {
	CloseDigest                    string `json:"close_digest,omitempty"`
	ResultDigest                   string `json:"result_digest,omitempty"`
	ResultLength                   uint32 `json:"result_length,omitempty"`
	Phase                          string `json:"phase"`
	DutyID                         string `json:"duty_id"`
	DeletionAcknowledgedCount      uint32 `json:"deletion_acknowledged_count"`
	InvalidationConfirmedCount     uint32 `json:"invalidation_confirmed_count"`
	UnknownCount                   uint32 `json:"unknown_count"`
	InvalidationNotConfirmed       bool   `json:"invalidation_not_confirmed"`
	EffectInvalidationNotConfirmed bool   `json:"effect_invalidation_not_confirmed"`
}

type StockPluginOutput struct {
	Instance         string                 `json:"instance"`
	Coordinate       PublicOutputCoordinate `json:"coordinate"`
	Published        bool                   `json:"published"`
	ValueEqual       bool                   `json:"value_equal"`
	MetadataVerified bool                   `json:"metadata_verified"`
	Deletion         string                 `json:"deletion"`
}

// StockPluginEvidence retains only public identities and closed observations.
// Original worker invocation/result hashes are bound by the coordinator.
type StockPluginEvidence struct {
	ServiceVerifications uint32                  `json:"service_verifications"`
	Schema               uint16                  `json:"schema"`
	RunID                string                  `json:"run_id"`
	Scenario             string                  `json:"scenario"`
	Provider             string                  `json:"provider"`
	Prefix               string                  `json:"prefix"`
	FixtureID            string                  `json:"fixture_id"`
	CLISHA256            string                  `json:"cli_sha256"`
	Commands             []StockPluginCommand    `json:"commands"`
	Assertions           []string                `json:"assertions"`
	Generations          []StockPluginGeneration `json:"generations"`
	Creates              []StockPluginCreate     `json:"creates"`
	Duties               []StockPluginDuty       `json:"duties"`
	Retirements          []StockPluginRetirement `json:"retirements"`
	Outputs              []StockPluginOutput     `json:"outputs"`
	ProviderTokenIDs     []string                `json:"provider_token_ids,omitempty"`
}

type StockPluginEvidenceRef struct {
	SchemaVersion uint16 `json:"schema_version"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Bytes         uint64 `json:"bytes"`
}

func StockPluginAssertions(provider string) []string {
	v := []string{"a0-created", "a1-pending-a", "b-same-epoch-reused", "missing-a-refused", "exact-a-retired", "b2-created", "b-retired-a1", "outputs-published", "cloud-output-values-equal", "manifest-complete", "reconstruction-canonical", "final-generation-retired", "post-exit-reader", "store-prefix-observed-empty"}
	if provider == "aws" {
		v = append(v, "github-metadata-checked")
	}
	slices.Sort(v)
	return v
}

func validateStockPluginAssertions(actual, required []string) error {
	assertions := slices.Clone(actual)
	slices.Sort(assertions)
	if !slices.Equal(assertions, required) {
		return errRecord
	}
	return nil
}

func stockPluginBeforeCleanupAssertions(provider string) []string {
	return slices.DeleteFunc(StockPluginAssertions(provider), func(value string) bool { return value == "store-prefix-observed-empty" })
}

// ValidateBeforeCleanup establishes the complete known provider work before
// cleaning its Store prefix. No final absence observation has been recorded.
func (v StockPluginEvidence) ValidateBeforeCleanup(input StockPluginAcceptanceInput) error {
	if err := v.validateFacts(input); err != nil {
		return err
	}
	return validateStockPluginAssertions(v.Assertions, stockPluginBeforeCleanupAssertions(v.Provider))
}

func (v StockPluginEvidence) ValidateComplete(input StockPluginAcceptanceInput) error {
	if err := v.validateFacts(input); err != nil {
		return err
	}
	return validateStockPluginAssertions(v.Assertions, StockPluginAssertions(v.Provider))
}

func (v StockPluginEvidence) validateFacts(input StockPluginAcceptanceInput) error {
	if input.Fixture.Validate() != nil || input.Artifact.Validate(input.Fixture.Provider) != nil || v.Schema != 1 || !ValidRunID(v.RunID) || v.Scenario != StockPluginScenario ||
		v.Provider != input.Fixture.Provider || v.FixtureID != input.Fixture.FixtureID || v.CLISHA256 != input.Artifact.CLI.SHA256 ||
		!strings.HasPrefix(v.Prefix, "enkv-test/"+v.RunID+"/") || filepath.Clean(v.Prefix) != v.Prefix || strings.Contains(v.Prefix, `\`) ||
		len(v.Commands) < 15 || len(v.Commands) > MaximumStockPluginCommands || len(v.Generations) != 3 || len(v.Creates) != 3 || len(v.Duties) != 3 || len(v.Retirements) != 3 || len(v.ProviderTokenIDs) != 3 || v.ServiceVerifications < 3 || v.ServiceVerifications > MaximumStockPluginVerifications {
		return errRecord
	}
	for i, command := range v.Commands {
		if command.Ordinal != uint32(i) || !command.Started || !command.Joined || command.Worker == "" || command.Nonce == "" ||
			!slices.Contains([]string{"authority", "apply", "reader", "consumer", "cleanup"}, command.Role) || command.Actor == "" ||
			command.ExitCode < 0 || command.ExitCode > 3 || !validHex(command.ResultSHA256, 32) ||
			!slices.Contains([]string{"init", "set-secret", "plan", "generated-list", "materialize", "manifest", "prepare", "publish", "output-delete", "remove-generated", "a0-created", "a1-pending-a", "b-same-epoch-reused", "missing-a-refused", "exact-a-retired", "b2-created", "b-retired-a1", "final-generation-retired", "post-exit-reader"}, command.Phase) {
			return errRecord
		}
		if command.DiagnosticSHA256 != "" || command.DiagnosticBytes != 0 || command.DiagnosticStatus != "" {
			if !validHex(command.DiagnosticSHA256, 32) || command.DiagnosticBytes == 0 || command.DiagnosticBytes > MaximumStockPluginDiagnosticBytes || command.DiagnosticStatus != "observed" {
				return errRecord
			}
		}
	}
	resources, generations, attempts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, generation := range v.Generations {
		if generation.Epoch != uint64(i) || generation.Phase != []string{"a0-created", "a1-pending-a", "b2-created"}[i] || resources[generation.ResourceID] || generations[generation.GenerationID] || attempts[generation.OriginAttemptID] {
			return errRecord
		}
		resources[generation.ResourceID], generations[generation.GenerationID], attempts[generation.OriginAttemptID] = true, true, true
		for _, id := range []string{generation.GenerationID, generation.ResourceID, generation.ResourceDigest, generation.OriginOperationID, generation.OriginAttemptID} {
			if !validHex(id, 32) {
				return errRecord
			}
		}
	}
	a, _ := input.Artifact.GeneratorA.Metadata.GeneratorFacts()
	b, _ := input.Artifact.GeneratorB.Metadata.GeneratorFacts()
	for i, create := range v.Creates {
		facts := a
		if i == 2 {
			facts = b
		}
		route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
		routeID, identityErr := credentialroute.Identity(route)
		generation := v.Generations[i]
		if err != nil || identityErr != nil || create.Phase != generation.Phase || create.GenerationID != generation.GenerationID || create.ResourceID != generation.ResourceID || create.ResourceDigest != generation.ResourceDigest ||
			create.OperationID != generation.OriginOperationID || create.AttemptID != generation.OriginAttemptID || create.DescriptorID != facts.DescriptorID.String() || create.ExecutorID != facts.ExecutorID.String() ||
			create.CredentialRouteID != artifact.Digest(routeID).String() || create.ConfigContractID != facts.Descriptor.Generator.ConfigContractID.String() || !validHex(create.ResourceContractID, 32) || !validHex(create.ResultContractID, 32) {
			return errRecord
		}
	}
	for i, duty := range v.Duties {
		facts := b
		if i == 0 {
			facts = a
		}
		route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
		routeID, identityErr := credentialroute.Identity(route)
		if err != nil || identityErr != nil || duty.Phase != []string{"a1-pending-a", "b2-created", "final-generation-retired"}[i] || duty.ResourceID != v.Generations[i].ResourceID || duty.DescriptorID != facts.DescriptorID.String() || duty.ExecutorID != facts.ExecutorID.String() || duty.CredentialRouteID != artifact.Digest(routeID).String() ||
			duty.OriginalOperationID != v.Generations[i].OriginOperationID || duty.OriginalAttemptID != v.Generations[i].OriginAttemptID || !validHex(duty.DutyID, 32) || !validHex(duty.ResultContractID, 32) {
			return errRecord
		}
	}

	for i, retirement := range v.Retirements {
		if input.Fixture.Purpose == StockRetirementProofPurpose {
			if !publicOutputID(retirement.CloseDigest) || !publicOutputID(retirement.ResultDigest) || retirement.ResultLength == 0 || retirement.ResultLength > uint32(contract.GeneratedResultRecordMaxLength) {
				return errRecord
			}
		} else if retirement.CloseDigest != "" || retirement.ResultDigest != "" || retirement.ResultLength != 0 {
			return errRecord
		}

		if retirement.Phase != []string{"exact-a-retired", "b-retired-a1", "final-generation-retired"}[i] || retirement.DutyID != v.Duties[i].DutyID || retirement.DeletionAcknowledgedCount != 1 || retirement.InvalidationConfirmedCount != 0 || retirement.UnknownCount != 0 || !retirement.InvalidationNotConfirmed || !retirement.EffectInvalidationNotConfirmed {
			return errRecord
		}
	}
	wantOutputs := 2 * len(StockPluginOutputNames(v.Provider))
	if len(v.Outputs) != wantOutputs {
		return errRecord
	}
	seen := map[PublicOutputCoordinate]bool{}
	counts := map[string]int{}
	wantScopes := map[string]bool{}
	for _, name := range StockPluginOutputNames(v.Provider) {
		wantScopes[strings.Replace(name, "github-actions-", "github-", 1)] = true
	}
	for _, row := range v.Outputs {
		scope := publicOutputCoordinateScope(row.Coordinate)
		if !row.Published || seen[row.Coordinate] || !wantScopes[scope] || !publicOutputID(row.Coordinate.CoordinateID) || !publicOutputID(row.Coordinate.BindingID) || len(row.Instance) > 512 {
			return errRecord
		}
		seen[row.Coordinate] = true
		counts[scope]++
		cloud := strings.HasPrefix(row.Coordinate.ServiceContractID, "ENKV/OUTPUT/")
		if cloud && (!row.ValueEqual || row.Instance == "") || !cloud && !row.MetadataVerified ||
			row.Deletion != "absent" && row.Deletion != "scheduled" && row.Deletion != "acknowledged" ||
			row.Deletion == "scheduled" && (v.Provider != "aws" || !strings.Contains(row.Coordinate.ServiceContractID, "AWS-SECRETS-MANAGER")) {
			return errRecord
		}
	}
	for scope := range wantScopes {
		if counts[scope] != 2 {
			return errRecord
		}
	}
	seenTokens := map[string]bool{}
	for _, id := range v.ProviderTokenIDs {
		if !validHex(id, 16) || seenTokens[id] {
			return errRecord
		}
		seenTokens[id] = true
	}
	return nil
}

func ReadStockPluginEvidence(path string) (StockPluginEvidence, error) {
	body, err := ReadJSONBytes(path, MaximumStockPluginEvidenceBytes)
	var value StockPluginEvidence
	if err != nil || publicEvidenceJSON(body, MaximumStockPluginEvidenceBytes, &value) != nil {
		return StockPluginEvidence{}, errRecord
	}
	// Historical records omit all three fields. Explicitly present values must
	// remain distinguishable from that absence before a later write can omit
	// zero values. Failed diagnostic writes remain readable but incomplete.
	var wire struct {
		Commands []map[string]json.RawMessage `json:"commands"`
	}
	if json.Unmarshal(body, &wire) != nil || len(wire.Commands) != len(value.Commands) {
		return StockPluginEvidence{}, errRecord
	}
	for i, fields := range wire.Commands {
		_, hasDigest := fields["diagnostic_sha256"]
		_, hasBytes := fields["diagnostic_bytes"]
		_, hasStatus := fields["diagnostic_status"]
		if !hasDigest && !hasBytes && !hasStatus {
			continue
		}
		command := value.Commands[i]
		if command.DiagnosticStatus == "write-failed" {
			if !hasStatus || hasDigest || hasBytes {
				return StockPluginEvidence{}, errRecord
			}
			continue
		}
		if !hasDigest || !hasBytes || !hasStatus || !validHex(command.DiagnosticSHA256, 32) || command.DiagnosticBytes == 0 || command.DiagnosticBytes > MaximumStockPluginDiagnosticBytes || !slices.Contains([]string{"observed", "partial", "unavailable"}, command.DiagnosticStatus) {
			return StockPluginEvidence{}, errRecord
		}
	}
	return value, nil
}

func WriteStockPluginEvidence(path string, value StockPluginEvidence) error {
	body, err := json.Marshal(value)
	if err != nil || len(body)+1 > MaximumStockPluginEvidenceBytes {
		return errRecord
	}
	return WriteJSON(path, value, 0600)
}
