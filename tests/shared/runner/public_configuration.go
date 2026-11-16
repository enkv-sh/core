package main

import (
	"errors"
	"maps"
	"path/filepath"
	"strings"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

// Public cases have selector-only resources. They do not make credentials or
// pasted public keys mandatory for any existing injected-control environment.
func validatePublicConfigurationEnvironment(environment *environmentFile) error {
	refused := errors.New("public configuration environment refused")
	if environment.Mode != "live" || len(environment.OutputTargets) != 0 || environment.GitHubOutputTargets != nil {
		return refused
	}
	if environment.PublicOutputs != nil && !environment.PublicOutputs.Valid() {
		return refused
	}
	if environment.PluginAcceptance != nil {
		if err := validateStockPluginEnvironment(environment); err != nil {
			return err
		}
	}
	if environment.Generator != nil && environment.PluginAcceptance == nil {
		generator, err := validateGeneratorFields(*environment.Generator, "")
		if err != nil {
			return refused
		}
		environment.Generator = &generator
	}
	fields := map[string]bool{"region": true, "bucket": true, "account": true, "project": true, "project_number": true, "recovery_mode": true, "key_id": true, "authority_kek_id": true, "reader_kek_id": true, "recovery_key_id": true, "recovery_kek_id": true, "quota_project": true, "normal_successor_key_id": true, "recovery_successor_key_id": true, "authority_successor_1_kek_id": true, "recovery_successor_1_kek_id": true, "reader_successor_kek_id": true}
	for key := range environment.Resource.Settings {
		if !fields[key] {
			return refused
		}
	}
	s := environment.Resource.Settings
	if !resourceLabel.MatchString(s["region"]) || !resourceLabel.MatchString(s["bucket"]) || s["recovery_mode"] != "enabled" && s["recovery_mode"] != "disabled" {
		return refused
	}
	family := contract.AWS
	if environment.Provider == "aws" {
		if !awsOwner.MatchString(s["account"]) || s["project"] != "" || s["project_number"] != "" {
			return refused
		}
	} else if environment.Provider == "gcp" {
		family = contract.GCP
		if !gcpOwner.MatchString(s["project_number"]) || s["project"] == "" || s["account"] != "" {
			return refused
		}
	} else {
		return refused
	}
	selectors := []struct {
		field   string
		signing bool
	}{{"key_id", true}, {"authority_kek_id", false}, {"reader_kek_id", false}}
	for _, candidate := range []struct {
		field   string
		signing bool
	}{
		{"normal_successor_key_id", true}, {"recovery_successor_key_id", true}, {"authority_successor_1_kek_id", false}, {"recovery_successor_1_kek_id", false}, {"reader_successor_kek_id", false},
	} {
		if s[candidate.field] != "" {
			selectors = append(selectors, candidate)
		}
	}
	if s["recovery_mode"] == "enabled" {
		selectors = append(selectors, struct {
			field   string
			signing bool
		}{"recovery_key_id", true}, struct {
			field   string
			signing bool
		}{"recovery_kek_id", false})
	} else if s["recovery_key_id"] != "" || s["recovery_kek_id"] != "" || s["recovery_successor_key_id"] != "" || s["recovery_successor_1_kek_id"] != "" {
		return refused
	}
	seen := map[string]bool{}
	for _, selector := range selectors {
		value := s[selector.field]
		if !contract.PublicKeySelectorValid(family, value, selector.signing) || seen[value] {
			return refused
		}
		seen[value] = true
		if family == contract.AWS {
			parsed, _ := contract.ParseAWSKeySelector(value, selector.signing)
			if parsed.Region != s["region"] || parsed.Account != s["account"] {
				return refused
			}
		} else {
			parsed, _ := contract.ParseGCPKeySelector(value, selector.signing)
			if parsed.Region != s["region"] || parsed.Project != s["project"] && parsed.Project != s["project_number"] {
				return refused
			}
		}
	}
	for role, name := range environment.RoleBindings {
		if !telemetryLabel.MatchString(role) || !telemetryLabel.MatchString(name) {
			return refused
		}
	}
	for name := range environment.Participants {
		if !telemetryLabel.MatchString(name) {
			return refused
		}
	}
	return nil
}

func (environment environmentFile) publicConfigurationSettings(name string) (liveSettings, error) {
	participant, ok := environment.Participants[name]
	sdk := participant.Access.SDK
	if !ok || sdk == nil || participant.Access.CredentialsFile != "" || participant.Access.Profile != "" || participant.Access.CredentialExpires != "" || sdk.Validate(environment.Provider) != nil {
		return nil, errors.New("required standard SDK participant unavailable")
	}
	settings := maps.Clone(environment.Resource.Settings)
	settings["provider"] = environment.Provider
	settings["sdk_mode"], settings["sdk_home"], settings["sdk_profile"] = sdk.Mode, sdk.Home, sdk.Profile
	settings["sdk_credentials_file"], settings["sdk_quota_project"] = sdk.CredentialsFile, sdk.QuotaProject
	if (sdk.Mode == "gcp-service-account-adc" || sdk.Mode == "gcp-impersonated-adc") && (sdk.QuotaProject == "" || sdk.QuotaProject != settings["quota_project"]) {
		return nil, errors.New("selected ADC quota project differs from resource context")
	}
	return settings, nil
}
func loadPublicConfigurationSettings(request runRequest) (map[string]liveSettings, *actorIdentityEvidence, error) {
	if request.environment == nil || request.Resolved == nil || !request.environment.PublicConfiguration {
		return nil, nil, errors.New("public configuration selection unavailable")
	}
	actors := map[string]liveSettings{}
	for _, entry := range request.Schedule.Entries {
		if !catalog.HasFixtureCapability(entry.Scenario, catalog.FixturePublicConfiguration) {
			return nil, nil, errors.New("public and injected scenarios cannot share one context")
		}
	}
	// Selection has resolved every required role before any login is opened.
	for role, participant := range request.Resolved.RoleBindings {
		if role == "successor" && request.environment.Resource.Settings["normal_successor_key_id"] == "" {
			return nil, nil, errors.New("public successor selector required")
		}
		settings, err := request.environment.publicConfigurationSettings(participant)
		if err != nil {
			return nil, nil, err
		}
		actors[role] = settings
	}
	return actors, nil, nil
}
func standardContext(settings liveSettings) nativeprocess.StandardContext {
	return nativeprocess.StandardContext{Mode: settings["sdk_mode"], Home: settings["sdk_home"], Profile: settings["sdk_profile"], CredentialsFile: settings["sdk_credentials_file"], QuotaProject: settings["sdk_quota_project"]}
}
func publicConfigurationSettingsValid(settings liveSettings, provider string) bool {
	return settings["provider"] == provider && standardContext(settings).Validate(provider) == nil && filepath.IsAbs(settings["sdk_home"]) && !strings.ContainsRune(settings["sdk_home"], 0)
}

type publicConfigurationInput struct {
	Stock    *records.StockPluginAcceptanceInput `json:"stock,omitempty"`
	Artifact publicConfigurationArtifact         `json:"artifact"`
	Actors   map[string]liveSettings             `json:"actors"`
	Outputs  *records.PublicOutputScopes         `json:"outputs,omitempty"`
}
