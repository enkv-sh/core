package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

const maximumActorsFileBytes = 64 << 10

type actorIdentityEvidence struct {
	Source             string `json:"source"`
	DistinctIdentities bool   `json:"distinct_identities"`
	DistinctOrigins    bool   `json:"distinct_origins"`
}

func loadRunSettings(request runRequest) (map[string]liveSettings, *actorIdentityEvidence, error) {
	if request.environment == nil || request.Resolved == nil {
		return nil, nil, errors.New("resolved environment required")
	}
	if request.environment.PublicConfiguration {
		return loadPublicConfigurationSettings(request)
	}
	loaded := map[string]liveSettings{}
	for _, name := range request.Resolved.Participants {
		settings, err := request.environment.settingsFor(name)
		if err != nil {
			return nil, nil, err
		}
		settings, err = validateSettings(settings, request.Provider, "")
		if err != nil {
			return nil, nil, err
		}
		loaded[name] = settings
	}
	actors := make(map[string]liveSettings, len(request.Resolved.RoleBindings))
	for role, participant := range request.Resolved.RoleBindings {
		settings := loaded[participant]
		if settings == nil {
			return nil, nil, errors.New("resolved actor settings unavailable")
		}
		actors[role] = settings
		if recovery, replacement := replacementRoles[role]; replacement && (!hasReplacementSettings(settings) || recovery && settings["recovery_mode"] != "enabled") {
			return nil, nil, errors.New("replacement actor requires its public bundle and recovery mode")
		}
	}
	// First-flow routes are separate selected credentials. This proves route
	// separation; it does not claim to identify the cloud principal in an AWS file.
	for _, role := range []string{"reader", "recovery", "denied-reader"} {
		settings := actors[role]
		if settings == nil {
			continue
		}
		for _, other := range []string{"authority", "reader", "recovery", "denied-reader"} {
			if other != role && actors[other] != nil && settings["credentials_file"] == actors[other]["credentials_file"] && settings["profile"] == actors[other]["profile"] {
				return nil, nil, errors.New("first-flow actors require separate credential routes")
			}
		}
	}
	for role := range replacementRoles {
		settings := actors[role]
		if settings == nil {
			continue
		}
		for other, route := range actors {
			if other != role && settings["credentials_file"] == route["credentials_file"] && settings["profile"] == route["profile"] {
				return nil, nil, errors.New("replacement actors require separate credential routes")
			}
		}
	}
	authority := actors["authority"]
	var identities *actorIdentityEvidence
	checked := map[string]bool{}
	for _, entry := range request.Schedule.Entries {
		definition, definitionKnown := catalog.DefinitionFor(entry.Scenario)
		execution, known := catalog.ExecutionFor(entry.Scenario, request.Suite)
		if !definitionKnown || !known {
			return nil, nil, errors.New("scenario execution facts unavailable")
		}
		if !definition.DistinctParticipants {
			continue
		}
		if len(execution.FreshAfter) == 0 || execution.FreshAfter[0].Role == "" || actors[execution.FreshAfter[0].Role] == nil {
			return nil, nil, errors.New("distinct actor execution facts unavailable")
		}
		role := execution.FreshAfter[0].Role
		if checked[role] {
			continue
		}
		if request.Provider != "gcp" {
			return nil, nil, errors.New("distinct credential evidence requires GCP")
		}
		evidence, err := verifyGCPActorIdentities(authority["credentials_file"], actors[role]["credentials_file"])
		if err != nil {
			return nil, nil, err
		}
		if identities == nil {
			identities = evidence
		} else {
			identities.DistinctOrigins = identities.DistinctOrigins && evidence.DistinctOrigins
		}
		checked[role] = true
	}
	if observer, denied := actors["observer"], actors["denied-observer"]; observer != nil && denied != nil {
		evidence, err := verifyGCPActorIdentities(observer["credentials_file"], denied["credentials_file"])
		if err != nil {
			return nil, nil, err
		}
		if identities == nil {
			identities = evidence
		} else {
			identities.DistinctOrigins = identities.DistinctOrigins && evidence.DistinctOrigins
		}
	}
	return actors, identities, nil
}

type serviceAccountIdentity struct {
	Type        string `json:"type"`
	Project     string `json:"project_id"`
	ClientEmail string `json:"client_email"`
	ClientID    string `json:"client_id"`
}

var serviceAccountEmail = regexp.MustCompile(`^[a-z0-9-]+@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com$`)
var serviceAccountID = regexp.MustCompile(`^[0-9]{6,32}$`)

func readGCPActorIdentity(path string) (serviceAccountIdentity, error) {
	refused := errors.New("actor credential identity unavailable")
	var body json.RawMessage
	if records.ReadJSONLimit(path, &body, maximumActorsFileBytes) != nil || uniqueJSONKeys(json.NewDecoder(bytes.NewReader(body))) != nil {
		return serviceAccountIdentity{}, refused
	}
	var identity serviceAccountIdentity
	if json.Unmarshal(body, &identity) != nil || identity.Type != "service_account" || !serviceAccountID.MatchString(identity.ClientID) {
		return serviceAccountIdentity{}, refused
	}
	match := serviceAccountEmail.FindStringSubmatch(identity.ClientEmail)
	if len(match) != 2 || match[1] != identity.Project {
		return serviceAccountIdentity{}, refused
	}
	return identity, nil
}

func verifyGCPActorIdentities(writerPath, readerPath string) (*actorIdentityEvidence, error) {
	writer, err := readGCPActorIdentity(writerPath)
	if err != nil {
		return nil, err
	}
	reader, err := readGCPActorIdentity(readerPath)
	if err != nil {
		return nil, err
	}
	if writer.ClientEmail == reader.ClientEmail || writer.ClientID == reader.ClientID {
		return nil, errors.New("scenario requires distinct credential identities")
	}
	return &actorIdentityEvidence{Source: "service-account-files", DistinctIdentities: true, DistinctOrigins: writer.Project != reader.Project}, nil
}
