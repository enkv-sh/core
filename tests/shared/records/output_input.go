package records

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

var errOutputInput = errors.New("output fixture input refused")

// MaximumOutputFixtureAWSNamePrefix leaves room for 32 Domain characters and
// the two-character role suffix within a Core entry name.
const MaximumOutputFixtureAWSNamePrefix = contract.CryptoMaxName - 32 - 2

// OutputFixtureInput contains private references, never credential or value
// bytes. Parent is an in-memory source; child inputs use one role projection.
type OutputFixtureInput struct {
	SchemaVersion int                    `json:"schema_version"`
	Scope         OutputFixtureScope     `json:"scope"`
	InventoryPath string                 `json:"inventory_path"`
	JoinedPath    string                 `json:"joined_path"`
	Profiles      []OutputFixtureProfile `json:"profiles"`
}
type OutputFixtureProfile struct {
	Scope     string                `json:"scope"`
	Namespace string                `json:"namespace"`
	ProfileID string                `json:"profile_id"`
	Cloud     *OutputFixtureCloud   `json:"cloud,omitempty"`
	GitHub    *OutputFixtureGitHub  `json:"github,omitempty"`
	Native    *OutputFixtureNative  `json:"native,omitempty"`
	Writer    *OutputFixtureActor   `json:"writer,omitempty"`
	Cleaner   *OutputFixtureActor   `json:"cleaner,omitempty"`
	ConsumerA *OutputFixtureActor   `json:"consumer_a,omitempty"`
	ConsumerB *OutputFixtureActor   `json:"consumer_b,omitempty"`
	Targets   []OutputFixtureTarget `json:"targets"`
}
type OutputFixtureActor struct {
	CredentialsFile string `json:"credentials_file"`
	Profile         string `json:"profile,omitempty"`
	ServiceAccount  string `json:"service_account,omitempty"`
	Principal       string `json:"principal,omitempty"`
}
type OutputFixtureCloud struct {
	Provider         string `json:"provider"`
	Region           string `json:"region,omitempty"`
	Account          string `json:"account,omitempty"`
	Project          string `json:"project,omitempty"`
	ProjectNumber    string `json:"project_number,omitempty"`
	SecretNamePrefix string `json:"secret_name_prefix"`
}
type OutputFixtureGitHub struct {
	Owner                 string   `json:"owner"`
	Repository            string   `json:"repository,omitempty"`
	Environment           string   `json:"environment,omitempty"`
	SecretNamePrefix      string   `json:"secret_name_prefix"`
	SelectedRepositoryIDs []uint64 `json:"selected_repository_ids,omitempty"`
}
type OutputFixtureNative struct {
	ArtifactPath              string `json:"artifact_path"`
	ArtifactSHA256            string `json:"artifact_sha256"`
	ArtifactLength            uint64 `json:"artifact_length"`
	CredentialPath            string `json:"credential_path"`
	CredentialRouteID         string `json:"credential_route_id"`
	DescriptorID              string `json:"descriptor_id"`
	ConfigContractID          string `json:"config_contract_id"`
	CredentialRouteContractID string `json:"credential_route_contract_id"`
}
type OutputFixtureTarget struct {
	Index                    uint32 `json:"index"`
	PlannedSlot              string `json:"planned_slot"`
	ConsumerLocator          string `json:"consumer_locator"`
	ExclusiveNamespaceDigest string `json:"exclusive_namespace_digest"`
}

// Validate is pure. Invocation/file owners check private directories, symlink
// components, exact installed artifacts and credential captures separately.
// The rerun mode does not grant the caller a Store retry entitlement.
func (input *OutputFixtureInput) Validate(expected OutputFixtureScope, role string) error {
	return input.validate(expected, role, role == "cleanup")
}

// ValidateRecorded checks a retained projection. It supplies no permission to
// execute its writer, child or cleanup actions.
func (input *OutputFixtureInput) ValidateRecorded(expected OutputFixtureScope, role string) error {
	return input.validate(expected, role, true)
}

func (input *OutputFixtureInput) validate(expected OutputFixtureScope, role string, historical bool) error {
	switch role {
	case "fresh_before", "fresh_after", "rerun":
		if input == nil {
			return nil
		}
		return errOutputInput
	case "parent", "writer", "cleanup":
	default:
		return errOutputInput
	}
	if input == nil || input.SchemaVersion != 2 || !validOutputScope(expected) || input.Scope != expected ||
		len(input.Profiles) < 1 || len(input.Profiles) > 5 || !outputInputPath(input.InventoryPath) || !outputInputPath(input.JoinedPath) ||
		input.InventoryPath == input.JoinedPath || filepath.Dir(input.InventoryPath) != filepath.Dir(input.JoinedPath) {
		return errOutputInput
	}
	selected, known := catalog.LivePublication(input.Scope.Scenario)
	if !known && historical {
		selected, known = catalog.HistoricalLivePublication(input.Scope.Scenario)
	}
	if !known {
		return errOutputInput
	}
	paths := map[string]bool{input.InventoryPath: true, input.JoinedPath: true}
	profiles, scopes, indices := make(map[string]bool), make(map[string]bool), make(map[uint32]bool)
	descriptors := make(map[string]bool)
	provider := "aws"
	clouds := 0
	rows := make([]OutputFixtureRow, 2*len(input.Profiles))
	for _, profile := range input.Profiles {
		if !validOutputProfile(profile.ProfileID) || profile.ProfileID != "ENKV/OUTPUT/"+strings.ToUpper(profile.Scope)+"/v3" ||
			profile.Namespace != selected.Namespace || profiles[profile.ProfileID] || scopes[profile.Scope] || len(profile.Targets) != 2 {
			return errOutputInput
		}
		profiles[profile.ProfileID], scopes[profile.Scope] = true, true
		if outputCloudProfile(profile.ProfileID) {
			clouds++
			if profile.Scope == "gcp-secret-manager" {
				provider = "gcp"
			}
		}
		slots, ok := outputInputSlots(profile, input.Scope.DomainID)
		if !ok {
			return errOutputInput
		}
		if profile.Targets[0].ExclusiveNamespaceDigest != profile.Targets[1].ExclusiveNamespaceDigest {
			return errOutputInput
		}
		for i, target := range profile.Targets {
			consumer := slots[i]
			if profile.Scope == "aws-secrets-manager" {
				consumer += "?stage=AWSCURRENT"
			}
			if profile.Scope == "gcp-secret-manager" {
				consumer += "/versions/latest"
			}
			if uint64(target.Index) >= uint64(len(rows)) || indices[target.Index] || target.PlannedSlot != slots[i] || target.ConsumerLocator != consumer || !validOutputText(consumer, 1024) || !validOutputDigest(target.ExclusiveNamespaceDigest) {
				return errOutputInput
			}
			indices[target.Index] = true
			rows[target.Index] = OutputFixtureRow{ProfileID: profile.ProfileID, PlannedSlot: target.PlannedSlot, ExclusiveNamespaceDigest: target.ExclusiveNamespaceDigest, Attempts: []OutputFixtureAttempt{}}
		}
		writer := role == "parent" || role == "writer"
		cleaner := role == "parent" || role == "cleanup"
		if (profile.Writer != nil) != writer || (profile.Cleaner != nil) != cleaner ||
			(profile.Native != nil) != writer || (profile.ConsumerA != nil) != (writer && profile.Cloud != nil) || (profile.ConsumerB != nil) != (writer && profile.Cloud != nil) {
			return errOutputInput
		}
		actors := []*OutputFixtureActor{profile.Writer, profile.Cleaner, profile.ConsumerA, profile.ConsumerB}
		for index, actor := range actors {
			if actor == nil {
				continue
			}
			if !outputInputActor(actor, profile, index >= 2) || !outputInputReservePath(paths, actor.CredentialsFile) {
				return errOutputInput
			}
		}
		if profile.ConsumerA != nil && profile.ConsumerA.Principal == profile.ConsumerB.Principal {
			return errOutputInput
		}
		if profile.Cloud != nil && profile.Cloud.Provider == "gcp" {
			emails := make(map[string]bool)
			for _, actor := range actors {
				if actor != nil {
					if emails[actor.ServiceAccount] {
						return errOutputInput
					}
					emails[actor.ServiceAccount] = true
				}
			}
		}
		if native := profile.Native; native != nil {
			if !validOutputDigest(native.ArtifactSHA256) || native.ArtifactLength == 0 || native.ArtifactLength > 128<<20 ||
				!validOutputDigest(native.CredentialRouteID) || !validOutputDigest(native.DescriptorID) || !validOutputDigest(native.CredentialRouteContractID) || !validOutputText(native.ConfigContractID, 256) || descriptors[native.DescriptorID] ||
				!outputInputReservePath(paths, native.ArtifactPath) || !outputInputReservePath(paths, native.CredentialPath) || filepath.Dir(native.CredentialPath) != filepath.Dir(input.InventoryPath) {
				return errOutputInput
			}
			descriptors[native.DescriptorID] = true
		}
	}
	if clouds > 1 {
		return errOutputInput
	}
	expectedScopes := selected.OutputScopes(provider)
	if len(expectedScopes) != len(scopes) {
		return errOutputInput
	}
	for _, scope := range expectedScopes {
		if !scopes[scope] {
			return errOutputInput
		}
	}
	inventory := OutputFixtureInventory{SchemaVersion: 1, Scope: input.Scope, Rows: rows, Actors: []OutputFixtureActors{}}
	if inventory.validate(expected) != nil {
		return errOutputInput
	}
	body, err := json.Marshal(input)
	if err != nil || len(body)+1 > MaximumJSONBytes {
		return errOutputInput
	}
	return nil
}

func outputInputPath(path string) bool {
	return validOutputText(path, 4096) && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.Contains(path, `\`)
}
func outputInputReservePath(paths map[string]bool, path string) bool {
	if !outputInputPath(path) || paths[path] {
		return false
	}
	paths[path] = true
	return true
}
func outputInputName(value string, maximum int, initial, rest string) bool {
	if len(value) == 0 || len(value) > maximum || !strings.ContainsRune(initial, rune(value[0])) {
		return false
	}
	for i := 1; i < len(value); i++ {
		if !strings.ContainsRune(rest, rune(value[i])) {
			return false
		}
	}
	return true
}

// Prefix forms are those of the validated environment input: GCP keeps its
// full parent path. Plain/secret positions fix the two Domain-derived names.
func outputInputSlots(profile OutputFixtureProfile, domain string) ([2]string, bool) {
	var result [2]string
	const lower = "abcdefghijklmnopqrstuvwxyz0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
	const labels = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
	prefix, base := "", ""
	if cloud := profile.Cloud; cloud != nil {
		if profile.GitHub != nil {
			return result, false
		}
		switch profile.Scope {
		case "aws-secrets-manager":
			if cloud.Provider != "aws" || !outputInputName(cloud.Region, 255, labels, labels) || len(cloud.Account) != 12 || !outputInputName(cloud.Account, 12, "0123456789", "0123456789") || cloud.Project != "" || cloud.ProjectNumber != "" ||
				!outputInputName(cloud.SecretNamePrefix, MaximumOutputFixtureAWSNamePrefix, labels, labels) || !strings.HasSuffix(cloud.SecretNamePrefix, "-output-"+profile.Namespace+"-") {
				return result, false
			}
			prefix = cloud.SecretNamePrefix
			base = "arn:aws:secretsmanager:" + cloud.Region + ":" + cloud.Account + ":secret:"
		case "gcp-secret-manager":
			number, err := strconv.ParseInt(cloud.ProjectNumber, 10, 64)
			parent := "projects/" + cloud.ProjectNumber + "/secrets/"
			if cloud.Provider != "gcp" || cloud.Region != "" || cloud.Account != "" || err != nil || number <= 0 || strconv.FormatInt(number, 10) != cloud.ProjectNumber ||
				!outputInputName(cloud.Project, 30, lower[:26], lower+"-") || !strings.ContainsRune(lower, rune(cloud.Project[len(cloud.Project)-1])) ||
				!strings.HasPrefix(cloud.SecretNamePrefix, parent) {
				return result, false
			}
			name := strings.TrimPrefix(cloud.SecretNamePrefix, parent)
			if !outputInputName(name, 221, labels, labels) || strings.Contains(name, ".") || !strings.HasSuffix(name, "-output-"+profile.Namespace+"-") {
				return result, false
			}
			prefix = cloud.SecretNamePrefix
		default:
			return result, false
		}
	} else if github := profile.GitHub; github != nil {
		if !outputInputName(github.Owner, 39, lower, lower+"-") || strings.HasSuffix(github.Owner, "-") || !outputInputName(github.SecretNamePrefix, 66, upper, upper+"0123456789") || strings.HasPrefix(github.SecretNamePrefix, "GITHUB_") {
			return result, false
		}
		switch profile.Scope {
		case "github-organization":
			if github.Repository != "" || github.Environment != "" || len(github.SelectedRepositoryIDs) != 2 || github.SelectedRepositoryIDs[0] == 0 || github.SelectedRepositoryIDs[0] >= github.SelectedRepositoryIDs[1] {
				return result, false
			}
			base = "orgs/" + github.Owner + "/actions/secrets/"
		case "github-repository", "github-environment":
			if !outputInputName(github.Repository, 100, lower, lower+"._-") || !strings.ContainsRune(lower, rune(github.Repository[len(github.Repository)-1])) || strings.HasSuffix(github.Repository, ".git") || len(github.SelectedRepositoryIDs) != 0 {
				return result, false
			}
			base = "repos/" + github.Owner + "/" + github.Repository + "/actions/secrets/"
			if profile.Scope == "github-environment" {
				if !outputInputName(github.Environment, 255, lower, lower+"._-") || !strings.ContainsRune(lower, rune(github.Environment[len(github.Environment)-1])) {
					return result, false
				}
				base = "repos/" + github.Owner + "/" + github.Repository + "/environments/" + github.Environment + "/secrets/"
			} else if github.Environment != "" {
				return result, false
			}
		default:
			return result, false
		}
		prefix = github.SecretNamePrefix
	} else {
		return result, false
	}
	suffix := strings.ToUpper(domain[:32])
	result[0], result[1] = base+prefix+suffix+"_P", base+prefix+suffix+"_S"
	return result, true
}

func outputInputActor(actor *OutputFixtureActor, profile OutputFixtureProfile, consumer bool) bool {
	if profile.GitHub != nil {
		return actor.Profile == "" && actor.ServiceAccount == "" && actor.Principal == ""
	}
	if !consumer && actor.Principal != "" {
		return false
	}
	const labels = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
	if profile.Cloud.Provider == "aws" {
		if !outputInputName(actor.Profile, 255, labels, labels) || actor.ServiceAccount != "" {
			return false
		}
		if consumer {
			prefix := "arn:aws:iam::" + profile.Cloud.Account + ":user/"
			return strings.HasPrefix(actor.Principal, prefix) && outputInputName(strings.TrimPrefix(actor.Principal, prefix), 255, labels, labels)
		}
		return true
	}
	if actor.Profile != "" || !validOutputText(actor.ServiceAccount, 255) || !strings.HasSuffix(actor.ServiceAccount, "@"+profile.Cloud.Project+".iam.gserviceaccount.com") || strings.HasPrefix(actor.ServiceAccount, "@") {
		return false
	}
	return !consumer || actor.Principal == "serviceAccount:"+actor.ServiceAccount
}

func (input *OutputFixtureInput) Clone() *OutputFixtureInput {
	if input == nil {
		return nil
	}
	copy := *input
	copy.Profiles = slices.Clone(input.Profiles)
	for i := range copy.Profiles {
		profile := &copy.Profiles[i]
		profile.Targets = slices.Clone(profile.Targets)
		if profile.Cloud != nil {
			value := *profile.Cloud
			profile.Cloud = &value
		}
		if profile.GitHub != nil {
			value := *profile.GitHub
			value.SelectedRepositoryIDs = slices.Clone(value.SelectedRepositoryIDs)
			profile.GitHub = &value
		}
		if profile.Native != nil {
			value := *profile.Native
			profile.Native = &value
		}
		for _, actor := range []**OutputFixtureActor{&profile.Writer, &profile.Cleaner, &profile.ConsumerA, &profile.ConsumerB} {
			if *actor != nil {
				value := **actor
				*actor = &value
			}
		}
	}
	return &copy
}
func (input *OutputFixtureInput) WriterProjection() (*OutputFixtureInput, error) {
	if input == nil || input.Validate(input.Scope, "parent") != nil {
		return nil, errOutputInput
	}
	copy := input.Clone()
	for i := range copy.Profiles {
		copy.Profiles[i].Cleaner = nil
	}
	if copy.Validate(input.Scope, "writer") != nil {
		return nil, errOutputInput
	}
	return copy, nil
}
func (input *OutputFixtureInput) CleanerProjection() (*OutputFixtureInput, error) {
	if input == nil || input.Validate(input.Scope, "parent") != nil {
		return nil, errOutputInput
	}
	copy := input.Clone()
	for i := range copy.Profiles {
		profile := &copy.Profiles[i]
		profile.Writer, profile.ConsumerA, profile.ConsumerB, profile.Native = nil, nil, nil, nil
	}
	if copy.Validate(input.Scope, "cleanup") != nil {
		return nil, errOutputInput
	}
	return copy, nil
}
