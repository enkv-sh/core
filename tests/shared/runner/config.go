package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	records "enkv.sh/core/internal/testrecords"
)

const maximumProviderResourceIDLength = 2048

const maximumPublicKeyPEMBytes = 4096

type liveSettings map[string]string

var publicResourceFields = []string{"bucket", "key_id", "public_key_pem", "recovery_mode", "authority_kek_id", "authority_kek_public_key_pem", "reader_kek_id", "reader_kek_public_key_pem", "recovery_key_id", "recovery_public_key_pem", "recovery_kek_id", "recovery_kek_public_key_pem",
	"normal_successor_key_id", "normal_successor_public_key_pem", "normal_successor_2_key_id", "normal_successor_2_public_key_pem", "reader_successor_kek_id", "reader_successor_kek_public_key_pem", "authority_successor_1_kek_id", "authority_successor_1_kek_public_key_pem", "authority_successor_2_kek_id", "authority_successor_2_kek_public_key_pem", "recovery_successor_key_id", "recovery_successor_public_key_pem", "recovery_successor_1_kek_id", "recovery_successor_1_kek_public_key_pem", "recovery_successor_2_kek_id", "recovery_successor_2_kek_public_key_pem"}

// Older suites do not require this bundle. When supplied, every public key for
// the selected recovery mode is required; individual successor fields are not optional.
func hasReplacementSettings(settings liveSettings) bool {
	for key := range settings {
		if slices.Contains(publicResourceFields, key) && strings.Contains(key, "successor") {
			return true
		}
	}
	return false
}

// The bool marks routes that are present only when recovery is enabled.
var replacementRoles = map[string]bool{
	"normal-signer-0": false, "normal-signer-1": false, "normal-signer-2": false,
	"authority-decrypter-0": false, "authority-decrypter-1": false, "authority-decrypter-2": false,
	"reader-successor": false, "replacement-store": false,
	"recovery-signer-0": true, "recovery-signer-1": true,
	"recovery-decrypter-0": true, "recovery-decrypter-1": true, "recovery-decrypter-2": true,
}

var resourceLabel = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,255}$`)
var gcpOwner = regexp.MustCompile(`^[0-9]{6,20}$`)
var awsOwner = regexp.MustCompile(`^[0-9]{12}$`)
var cloudflareAccount = regexp.MustCompile(`^[0-9a-f]{32}$`)

type generatorConfiguration struct {
	SchemaVersion int                `json:"schema_version"`
	Provider      string             `json:"provider"`
	Generator     generatorReference `json:"generator"`
}

func readGeneratorConfiguration(path string) (generatorReference, error) {
	var input generatorConfiguration
	if readSelectionFile(path, &input) != nil || input.SchemaVersion != 1 || input.Provider != "cloudflare" {
		return generatorReference{}, errors.New("Cloudflare generator configuration refused")
	}
	return input.Generator, nil
}

func loadGeneratorConfiguration(path string, public ...bool) (generatorReference, error) {
	input, err := readGeneratorConfiguration(path)
	if err != nil {
		return generatorReference{}, err
	}
	return validateGeneratorFields(input, filepath.Dir(path))
}

func loadStockGeneratorConfiguration(path string) (generatorReference, error) {
	input, err := readGeneratorConfiguration(path)
	if err != nil {
		return generatorReference{}, err
	}
	return validateStockGenerator(input)
}

func validateGeneratorFields(input generatorReference, configurationDirectory string) (generatorReference, error) {
	refused := errors.New("Cloudflare generator configuration refused")
	if !cloudflareAccount.MatchString(input.Account) || !cloudflareAccount.MatchString(input.PermissionGroup) || input.CredentialsFile != "" || input.Artifact == "" {
		return generatorReference{}, refused
	}
	if !filepath.IsAbs(input.Artifact) {
		input.Artifact = filepath.Join(configurationDirectory, input.Artifact)
	}
	input.Artifact = filepath.Clean(input.Artifact)
	return input, nil
}

func validateGenerator(input generatorReference) (generatorReference, error) {
	input, err := validateGeneratorFields(input, "")
	if err != nil {
		return generatorReference{}, err
	}
	artifact, err := filepath.EvalSymlinks(input.Artifact)
	if err != nil {
		return generatorReference{}, errors.New("Cloudflare artifact unavailable")
	}
	artifactInfo, err := os.Stat(artifact)
	if err != nil || !artifactInfo.Mode().IsRegular() || artifactInfo.Mode().Perm()&0111 == 0 || artifactInfo.Mode().Perm()&0022 != 0 {
		return generatorReference{}, errors.New("Cloudflare artifact unavailable")
	}
	input.Artifact = artifact
	return input, nil
}

func validateSettings(input liveSettings, provider, configurationDirectory string) (liveSettings, error) {
	settings, err := validateSettingsFields(input, provider, configurationDirectory)
	if err != nil {
		return nil, err
	}
	credential, err := filepath.EvalSymlinks(settings["credentials_file"])
	if err != nil {
		return nil, errors.New("credential file unavailable")
	}
	info, err := os.Stat(credential)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("credential file unavailable")
	}
	settings["credentials_file"] = credential
	return settings, nil
}

// Output routes are fixture inputs only. Resolve their local references, but
// do not open credentials or add these actors to the State worker routes.
func validateOutputTargets(input map[string]outputTargetReference, provider string, resource liveSettings,
	paths map[string]bool, configurationDirectory string) (map[string]outputTargetReference, error) {
	refused := errors.New("output target location or credential route refused")
	if len(input) != 2 || provider != "aws" && provider != "gcp" {
		return nil, refused
	}
	result := make(map[string]outputTargetReference, 2)
	for _, name := range []string{"positive", "ambiguity"} {
		target, found := input[name]
		if !found || len(target.Consumers) != 2 || target.SecretNamePrefix == "" {
			return nil, refused
		}
		prefix := target.SecretNamePrefix
		if provider == "aws" {
			if target.Region != resource["region"] || target.Account != resource["account"] ||
				!awsOwner.MatchString(target.Account) || target.Project != "" || target.ProjectNumber != "" ||
				target.Version != "" || target.VersionStage != "AWSCURRENT" ||
				len(prefix) > records.MaximumOutputFixtureAWSNamePrefix || !resourceLabel.MatchString(prefix) || !strings.HasSuffix(prefix, "-output-"+name+"-") {
				return nil, refused
			}
		} else {
			base := "projects/" + target.ProjectNumber + "/secrets/"
			if target.Project != resource["project"] || target.ProjectNumber != resource["project_number"] ||
				!gcpOwner.MatchString(target.ProjectNumber) || target.Region != "" || target.Account != "" ||
				target.VersionStage != "" || target.Version != "latest" || !strings.HasPrefix(prefix, base) ||
				!resourceLabel.MatchString(strings.TrimPrefix(prefix, base)) || !strings.HasSuffix(prefix, "-output-"+name+"-") {
				return nil, refused
			}
		}
		writer, ok := validateOutputActor(target.Writer, provider, target.Project, target.Account, "", configurationDirectory, paths)
		if !ok {
			return nil, refused
		}
		target.Writer = writer
		cleaner, ok := validateOutputActor(target.Cleaner, provider, target.Project, target.Account, "", configurationDirectory, paths)
		if !ok {
			return nil, refused
		}
		target.Cleaner = cleaner
		consumers := make(map[string]outputActorReference, 2)
		for _, role := range []string{"consumer_a", "consumer_b"} {
			actor, found := target.Consumers[role]
			if !found {
				return nil, refused
			}
			actor, ok = validateOutputActor(actor, provider, target.Project, target.Account, role, configurationDirectory, paths)
			if !ok {
				return nil, refused
			}
			consumers[role] = actor
		}
		target.Consumers = consumers
		result[name] = target
	}
	if strings.HasPrefix(result["positive"].SecretNamePrefix, result["ambiguity"].SecretNamePrefix) ||
		strings.HasPrefix(result["ambiguity"].SecretNamePrefix, result["positive"].SecretNamePrefix) {
		return nil, refused
	}
	return result, nil
}

func validateOutputActor(input outputActorReference, provider, project, account, role, directory string,
	paths map[string]bool) (outputActorReference, bool) {
	if input.CredentialsFile == "" || role == "" && input.Principal != "" {
		return outputActorReference{}, false
	}
	if provider == "aws" {
		if !resourceLabel.MatchString(input.Profile) || input.ServiceAccount != "" {
			return outputActorReference{}, false
		}
		if role != "" {
			prefix := "arn:aws:iam::" + account + ":user/"
			if !strings.HasPrefix(input.Principal, prefix) || !resourceLabel.MatchString(strings.TrimPrefix(input.Principal, prefix)) {
				return outputActorReference{}, false
			}
		}
	} else {
		if input.Profile != "" || !strings.HasSuffix(input.ServiceAccount, "@"+project+".iam.gserviceaccount.com") ||
			input.ServiceAccount == "@"+project+".iam.gserviceaccount.com" {
			return outputActorReference{}, false
		}
		if role != "" && input.Principal != "serviceAccount:"+input.ServiceAccount {
			return outputActorReference{}, false
		}
	}
	if !filepath.IsAbs(input.CredentialsFile) {
		input.CredentialsFile = filepath.Join(directory, input.CredentialsFile)
	}
	input.CredentialsFile = filepath.Clean(input.CredentialsFile)
	if paths[input.CredentialsFile] {
		return outputActorReference{}, false
	}
	paths[input.CredentialsFile] = true
	return input, true
}

// Planning validates the configuration without opening credential references.
func validateSettingsFields(input liveSettings, provider, configurationDirectory string) (liveSettings, error) {
	if provider != "gcp" && provider != "aws" {
		return nil, errors.New("unknown provider configuration")
	}
	settings := make(liveSettings, len(input))
	for key, value := range input {
		settings[key] = value
	}
	fields := []string{"provider", "region", "bucket", "key_id", "public_key_pem", "credentials_file", "recovery_mode", "authority_kek_id", "authority_kek_public_key_pem", "reader_kek_id", "reader_kek_public_key_pem"}
	switch settings["recovery_mode"] {
	case "disabled":
	case "enabled":
		fields = append(fields, "recovery_key_id", "recovery_public_key_pem", "recovery_kek_id", "recovery_kek_public_key_pem")
	default:
		return nil, errors.New("explicit enabled or disabled recovery mode required")
	}
	if hasReplacementSettings(settings) {
		for _, field := range publicResourceFields {
			if strings.HasPrefix(field, "normal_successor_2_") && settings["normal_successor_2_key_id"] == "" && settings["normal_successor_2_public_key_pem"] == "" {
				continue
			}
			if strings.Contains(field, "successor") && (settings["recovery_mode"] == "enabled" || !strings.HasPrefix(field, "recovery_")) {
				fields = append(fields, field)
			}
		}
	}
	if settings["normal_successor_2_key_id"] != "" && (settings["normal_successor_2_key_id"] == settings["normal_successor_key_id"] || settings["normal_successor_2_key_id"] == settings["key_id"] || settings["normal_successor_2_public_key_pem"] == settings["normal_successor_public_key_pem"] || settings["normal_successor_2_public_key_pem"] == settings["public_key_pem"]) {
		return nil, errors.New("independent second normal signer refused")
	}
	if provider == "gcp" {
		fields = append(fields, "project", "project_number")
	} else {
		fields = append(fields, "account", "profile")
	}
	for _, field := range fields {
		if settings[field] == "" {
			return nil, errors.New("configuration fields refused")
		}
	}
	for field, value := range settings {
		if value == "" || !slices.Contains(fields, field) && field != "credential_expires" {
			return nil, errors.New("configuration fields refused")
		}
	}
	if settings["provider"] != provider {
		return nil, errors.New("configuration provider differs")
	}
	for _, field := range []string{"region", "bucket", "project", "profile"} {
		if value, present := settings[field]; present && !resourceLabel.MatchString(value) {
			return nil, errors.New("resource label refused")
		}
	}
	if provider == "gcp" && !gcpOwner.MatchString(settings["project_number"]) || provider == "aws" && !awsOwner.MatchString(settings["account"]) {
		return nil, errors.New("resource owner refused")
	}
	for _, key := range publicResourceFields {
		if value, present := settings[key]; present && strings.HasSuffix(key, "_id") && (len(value) > maximumProviderResourceIDLength || strings.ContainsFunc(value, unicode.IsSpace)) {
			return nil, errors.New("key identity refused")
		}
	}
	for _, key := range publicResourceFields {
		if value, present := settings[key]; present && strings.HasSuffix(key, "_pem") && (!strings.HasPrefix(value, "-----BEGIN PUBLIC KEY-----\n") || len(value) > maximumPublicKeyPEMBytes) {
			return nil, errors.New("public basis refused")
		}
	}
	if value, present := settings["credential_expires"]; present {
		expires, err := time.Parse(time.RFC3339, value)
		if err != nil || !expires.After(time.Now()) {
			return nil, errors.New("credential expiration refused")
		}
	}
	credential := settings["credentials_file"]
	if !filepath.IsAbs(credential) {
		credential = filepath.Join(configurationDirectory, credential)
	}
	settings["credentials_file"] = filepath.Clean(credential)
	return settings, nil
}

func resourceIdentity(settings liveSettings) liveSettings {
	identity := make(liveSettings)
	for key, value := range settings {
		if key != "credentials_file" && key != "profile" && key != "credential_expires" {
			identity[key] = value
		}
	}
	return identity
}

func sameResources(first, second liveSettings) bool {
	a, b := resourceIdentity(first), resourceIdentity(second)
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func readEvidence(path string, value any) error {
	var body json.RawMessage
	if records.ReadJSON(path, &body) != nil || json.Unmarshal(body, value) != nil {
		return errors.New("evidence unavailable")
	}
	return nil
}

func validateGeneratorRoute(input generatorReference, _ bool) (generatorReference, error) {
	return validateGenerator(input)
}
