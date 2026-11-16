package main

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"

	records "enkv.sh/core/internal/testrecords"

	catalog "enkv.sh/core/internal/testcatalog"
)

func publicOutputCaseCompleted(directory string, entry catalog.Entry, input workerInput) (bool, catalog.Entry, error) {
	row, known := catalog.PublicConfiguration(entry.Scenario)
	if !known || !row.Output {
		return false, entry, nil
	}
	body, _, err := publicCleanupRecord(filepath.Join(directory, "run.json"))
	if os.IsNotExist(err) {
		return false, entry, nil
	}
	var parent runRecord
	if err != nil || decodeCleanupRecord(body, &parent) != nil || parent.RunID != input.RunID || parent.Provider != input.Settings["provider"] {
		return false, entry, errPublicConfigurationEvidence
	}
	var selected *scenarioResult
	for i := range parent.Scenarios {
		candidate := &parent.Scenarios[i]
		if candidate.Sequence != entry.Sequence {
			continue
		}
		if selected != nil || candidate.Scenario != entry.Scenario || candidate.Members != entry.Members {
			return false, entry, errPublicConfigurationEvidence
		}
		selected = candidate
	}
	if selected == nil {
		return false, entry, nil
	}
	entry = selected.Entry
	if selected.Outcome != "passed" {
		return false, entry, nil
	}
	name, nameErr := recordedCaseDirectory(selected.Entry)
	if nameErr != nil || input.Prefix != "enkv-test/"+parent.RunID+"/"+name || !selected.CorrectnessPassed ||
		!scenarioCleanupPassed(*selected) || input.PublicConfiguration == nil || parent.BuildClosure == nil ||
		!reflect.DeepEqual(input.PublicConfiguration.Artifact.closure(), parent.BuildClosure.PublicConfiguration) ||
		readPublicConfigurationEvidence(directory, parent, *selected) != nil {
		return false, entry, errPublicConfigurationEvidence
	}
	matched := false
	for _, ref := range parent.CaseReceipts {
		if ref.Sequence != selected.Sequence {
			continue
		}
		leaf, err := validateCaseReceipt(directory, parent, ref, selected.Entry)
		if matched || err != nil || !reflect.DeepEqual(leaf, *selected) {
			return false, entry, errPublicConfigurationEvidence
		}
		matched = true
	}
	if !matched {
		return false, entry, errPublicConfigurationEvidence
	}
	return true, entry, nil
}

// SDK locations belong to individual actors. Resource comparison must retain
// every selector while allowing the selected actors to have different logins.
func publicCleanupResources(settings liveSettings) liveSettings {
	resource := maps.Clone(settings)
	for _, key := range []string{"provider", "sdk_mode", "sdk_home", "sdk_profile", "sdk_credentials_file", "sdk_quota_project"} {
		delete(resource, key)
	}
	return resource
}

func publicCleanupInputValid(input workerInput, provider string) bool {
	if input.PublicConfiguration == nil || len(input.Scenarios) != 1 || input.RecoveryMode != input.Settings["recovery_mode"] ||
		!maps.Equal(input.Settings, input.PublicConfiguration.Actors["authority"]) {
		return false
	}
	resolved := resolvedRequest{Mode: "live", RecoveryMode: input.RecoveryMode, RoleBindings: input.Participants}
	participants, err := resolved.scenarioParticipants(input.Scenarios[0])
	if err != nil || !maps.Equal(participants, input.Participants) || len(input.PublicConfiguration.Actors) != len(participants) {
		return false
	}
	resource := publicCleanupResources(input.Settings)
	environment := environmentFile{Mode: "live", Provider: provider, PublicConfiguration: true}
	environment.Resource.Settings = resource
	stock := input.PublicConfiguration.Stock
	if input.Scenarios[0] == records.StockPluginScenario {
		if stock == nil || !reflect.DeepEqual(input.PublicConfiguration.Artifact, publicConfigurationArtifact{}) || stock.Artifact.Validate(provider) != nil {
			return false
		}
		environment.PluginAcceptance = &stock.Fixture
		environment.Generator = &generatorReference{Account: stock.CloudflareAccount, PermissionGroup: stock.CloudflarePermissionGroup}
		environment.PublicOutputs = input.PublicConfiguration.Outputs
		environment.RoleBindings = maps.Clone(input.Participants)
		environment.Participants = map[string]participantReference{}
		for role, name := range input.Participants {
			context := standardContext(input.PublicConfiguration.Actors[role])
			environment.Participants[name] = participantReference{Access: accessReference{SDK: &context}}
		}
	} else if stock != nil {
		return false
	}
	if validatePublicConfigurationEnvironment(&environment) != nil {
		return false
	}
	row, ok := catalog.PublicConfiguration(input.Scenarios[0])
	if !input.PublicConfiguration.Outputs.ValidForScopes(row.OutputScopes(provider)) {
		return false
	}
	if !ok && !catalog.HasFixtureCapability(input.Scenarios[0], catalog.FixturePublicConfiguration) {
		return false
	}
	for role := range participants {
		actor := input.PublicConfiguration.Actors[role]
		if !publicConfigurationSettingsValid(actor, provider) || !maps.Equal(publicCleanupResources(actor), resource) ||
			(actor["sdk_mode"] == "gcp-service-account-adc" || actor["sdk_mode"] == "gcp-impersonated-adc") && (actor["sdk_quota_project"] == "" || actor["sdk_quota_project"] != actor["quota_project"]) {
			return false
		}
		context := standardContext(actor)
		if row.UsesOperatorSDKContext() && (!context.OperatorDiscovery(provider) || context != standardContext(input.Settings)) ||
			row.Condition == "standard-discovery" && !context.StandardDiscovery(provider) {
			return false
		}
	}
	return true
}
