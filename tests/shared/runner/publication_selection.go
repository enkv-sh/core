package main

import (
	"errors"
	"slices"
	"strings"

	catalog "enkv.sh/core/internal/testcatalog"
	artifactpkg "enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
)

type resolvedOutputScope struct {
	Scope     string `json:"scope"`
	Namespace string `json:"namespace"`
	ProfileID string `json:"profile_id"`
}

// A selected profile has one fixture namespace and writer route for the whole
// assembly. The alternate namespace therefore needs a separate saved run.
type selectedOutputProfile struct {
	resolvedOutputScope
	Cloud  *outputTargetReference
	GitHub *githubOutputTargetReference
}

func selectPublicationOutputs(schedule catalog.Schedule, environment environmentFile) ([]selectedOutputProfile, error) {
	refused := errors.New("selected publication scope or namespace unavailable")
	selected := make(map[string]selectedOutputProfile)
	for _, entry := range schedule.Entries {
		if public, ok := catalog.PublicConfiguration(entry.Scenario); ok && public.Output {
			scopes := public.OutputScopes(environment.Provider)
			if environment.Mode != "live" || len(scopes) == 0 || !environment.PublicOutputs.ValidForScopes(scopes) {
				return nil, refused
			}
			for _, scope := range scopes {
				profile := "ENKV/OUTPUT/" + strings.ToUpper(scope) + "/v3"
				item := selectedOutputProfile{resolvedOutputScope: resolvedOutputScope{Scope: scope, Namespace: "public", ProfileID: profile}}
				if scope == "aws-secrets-manager" || scope == "gcp-secret-manager" {
					s := environment.Resource.Settings
					item.Cloud = &outputTargetReference{Region: s["region"], Account: s["account"], Project: s["project"], ProjectNumber: s["project_number"]}
				} else {
					g := environment.PublicOutputs.Repository
					if scope == "github-organization" {
						g = environment.PublicOutputs.Organization
					} else if scope == "github-environment" {
						g = environment.PublicOutputs.Environment
					}
					item.GitHub = &githubOutputTargetReference{Owner: g.Owner, Repository: g.Repository, Environment: g.Environment, SelectedRepositoryIDs: slices.Clone(g.Repositories)}
				}
				if old, found := selected[profile]; found && old.Namespace != item.Namespace {
					return nil, refused
				}
				selected[profile] = item
			}
			continue
		}
		row, publication := catalog.LivePublication(entry.Scenario)
		if !publication {
			continue
		}
		if environment.Mode != "live" {
			return nil, refused
		}
		scopes := row.OutputScopes(environment.Provider)
		if len(scopes) == 0 {
			return nil, refused
		}
		for _, scope := range scopes {
			profile := "ENKV/OUTPUT/" + strings.ToUpper(scope) + "/v3"
			if _, valid := outputCommand(profile); !valid {
				return nil, refused
			}
			if earlier, exists := selected[profile]; exists {
				if earlier.Namespace != row.Namespace {
					return nil, refused
				}
				continue
			}
			item := selectedOutputProfile{resolvedOutputScope: resolvedOutputScope{Scope: scope, Namespace: row.Namespace, ProfileID: profile}}
			if scope == "aws-secrets-manager" || scope == "gcp-secret-manager" {
				cloud, present := environment.OutputTargets[row.Namespace]
				if !present {
					return nil, refused
				}
				cloud.Consumers = make(map[string]outputActorReference, len(cloud.Consumers))
				for name, actor := range environment.OutputTargets[row.Namespace].Consumers {
					cloud.Consumers[name] = actor
				}
				item.Cloud = &cloud
			} else {
				if environment.GitHubOutputTargets == nil {
					return nil, refused
				}
				var target *githubOutputTargetReference
				switch scope {
				case "github-repository":
					target = environment.GitHubOutputTargets.Repository
				case "github-organization":
					target = environment.GitHubOutputTargets.Organization
				case "github-environment":
					target = environment.GitHubOutputTargets.Environment
				}
				if target == nil {
					return nil, refused
				}
				copy := *target
				copy.SelectedRepositoryIDs = slices.Clone(target.SelectedRepositoryIDs)
				item.GitHub = &copy
			}
			selected[profile] = item
		}
	}
	var result []selectedOutputProfile
	for _, command := range outputProductionCommands {
		if item, present := selected[command.label]; present {
			result = append(result, item)
		}
	}
	return result, nil
}

func publicationAssemblyBindings(runID string, profiles []selectedOutputProfile) ([]outputProfileBinding, error) {
	if len(profiles) == 0 {
		return nil, nil
	}
	if len(runID) != 32 {
		return nil, errors.New("publication assembly run identity unavailable")
	}
	return selectedPublicationBindings(profiles)
}

func selectedPublicationBindings(profiles []selectedOutputProfile) ([]outputProfileBinding, error) {
	if len(profiles) == 0 {
		return nil, nil
	}
	bindings := make([]outputProfileBinding, 0, len(profiles))
	for _, profile := range profiles {
		binding, err := productionOutputBinding(profile.ProfileID)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return validateOutputBindings(bindings)
}

// These qualification identities were derived from canonical plugin.json JSON
// with Python json/struct/hashlib. Route IDs hash the decoded public route bytes.
func productionOutputBinding(label string) (outputProfileBinding, error) {
	var descriptor, route, config, routeContract string
	switch label {
	case "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v3":
		descriptor, route, config, routeContract = "e94b164f79a21c5db3aa780ece37c940a915ee76bcc01e86f67fd8c103195fa3", "6a9e5b236a8b4fcd66b1149679e1d77cf791bda023676896859e2db8e0f83f90", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/CONFIG/v1", "693c9548d6df16ead6cae7ad84b1363fa256413fc10bfe311090830ff18dc667"
	case "ENKV/OUTPUT/GCP-SECRET-MANAGER/v3":
		descriptor, route, config, routeContract = "9f01ecfc93cd90f623d10f43c2a100ad6fd39bc8da5371dbcce8f730bf42a298", "ed850a0133c5d22de7353375d02bc81bbe2ed8622fc77e24ef216bdc4fe89ba9", "ENKV/OUTPUT/GCP-SECRET-MANAGER/CONFIG/v1", "7dd29e638afb06b3e5abff57d595af37fd9a176451c1a4b55782db70e06f5a88"
	case "ENKV/OUTPUT/GITHUB-REPOSITORY/v3":
		descriptor, route, config, routeContract = "103e434e30443a4e27517865a1d3e0d0dcb3eb3a3fb0716cf12e1e72e8bee3b3", "87cfb42eb2de2607a1074fb863fdecbc2ee89d15da619b67fbedb274445695af", "github-actions/repository-config/v1", "095a90c4259f7ccf9c246c4b7d26fb40332049545082795aa400bbe2a8681d36"
	case "ENKV/OUTPUT/GITHUB-ORGANIZATION/v3":
		descriptor, route, config, routeContract = "ebee4cc723c6781e9bea27253c778aeb667993e27bf6f3c92d494fdd5ba8f550", "87cfb42eb2de2607a1074fb863fdecbc2ee89d15da619b67fbedb274445695af", "github-actions/organization-config/v1", "095a90c4259f7ccf9c246c4b7d26fb40332049545082795aa400bbe2a8681d36"
	case "ENKV/OUTPUT/GITHUB-ENVIRONMENT/v3":
		descriptor, route, config, routeContract = "dd1a29a13017d5a1cb2636f896c5ea282074d5d7e83584db99e86a596c7eeceb", "87cfb42eb2de2607a1074fb863fdecbc2ee89d15da619b67fbedb274445695af", "github-actions/environment-config/v1", "095a90c4259f7ccf9c246c4b7d26fb40332049545082795aa400bbe2a8681d36"
	default:
		return outputProfileBinding{}, errors.New("output qualification case refused")
	}
	descriptorID, err := artifactpkg.ParseDigest(descriptor)
	if err != nil {
		return outputProfileBinding{}, err
	}
	routeID, err := artifactpkg.ParseDigest(route)
	if err != nil {
		return outputProfileBinding{}, err
	}
	return outputProfileBinding{StoredProfileID: label, DescriptorID: protocol.ID(descriptorID), CredentialRouteID: protocol.ID(routeID), ConfigContractID: config, CredentialRouteContractID: routeContract}, nil
}
