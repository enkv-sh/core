package main

import (
	"errors"
	"path/filepath"
	"strings"
)

type githubOutputActorReference struct {
	CredentialsFile string `json:"credentials_file"`
}

type githubOutputTargetReference struct {
	Owner                 string                     `json:"owner"`
	Repository            string                     `json:"repository,omitempty"`
	Environment           string                     `json:"environment,omitempty"`
	SecretNamePrefix      string                     `json:"secret_name_prefix"`
	Writer                githubOutputActorReference `json:"writer"`
	Cleaner               githubOutputActorReference `json:"cleaner"`
	SelectedRepositoryIDs []uint64                   `json:"selected_repository_ids,omitempty"`
}

type githubOutputReference struct {
	Repository   *githubOutputTargetReference `json:"repository,omitempty"`
	Organization *githubOutputTargetReference `json:"organization,omitempty"`
	Environment  *githubOutputTargetReference `json:"environment,omitempty"`
}

func validateOutputConfiguration(environment *environmentFile, directory string) error {
	if environment.OutputTargets == nil && environment.GitHubOutputTargets == nil {
		return nil
	}
	if environment.Mode != "live" {
		return errors.New("output targets require a live fixture")
	}
	paths := make(map[string]bool)
	reserve := func(path string) {
		if path != "" {
			if !filepath.IsAbs(path) {
				path = filepath.Join(directory, path)
			}
			paths[filepath.Clean(path)] = true
		}
	}
	for _, participant := range environment.Participants {
		reserve(participant.Access.CredentialsFile)
	}
	if environment.Generator != nil {
		reserve(environment.Generator.CredentialsFile)
	}
	var primary map[string]outputTargetReference
	var github *githubOutputReference
	var err error
	if environment.OutputTargets != nil {
		primary, err = validateOutputTargets(environment.OutputTargets, environment.Provider, environment.Resource.Settings, paths, directory)
		if err != nil {
			return err
		}
	}
	if environment.GitHubOutputTargets != nil {
		input := *environment.GitHubOutputTargets
		if input.Repository == nil && input.Organization == nil && input.Environment == nil {
			return errors.New("GitHub output scope refused")
		}
		for _, scope := range []struct {
			name   string
			target **githubOutputTargetReference
		}{
			{"repository", &input.Repository}, {"organization", &input.Organization}, {"environment", &input.Environment},
		} {
			if *scope.target == nil {
				continue
			}
			validated, err := validateGitHubOutputTarget(**scope.target, scope.name, directory, paths)
			if err != nil {
				return err
			}
			*scope.target = &validated
		}
		github = &input
	}
	environment.OutputTargets, environment.GitHubOutputTargets = primary, github
	return nil
}

func validateGitHubOutputTarget(input githubOutputTargetReference, scope, directory string, paths map[string]bool) (githubOutputTargetReference, error) {
	refused := errors.New("GitHub output scope or credential route refused")
	const lower = "abcdefghijklmnopqrstuvwxyz0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
	if !githubOutputName(input.Owner, 39, lower, lower+"-") || strings.HasSuffix(input.Owner, "-") ||
		!githubOutputName(input.SecretNamePrefix, 66, upper, upper+"0123456789") || strings.HasPrefix(input.SecretNamePrefix, "GITHUB_") {
		return githubOutputTargetReference{}, refused
	}
	if scope == "organization" {
		if input.Repository != "" || input.Environment != "" || len(input.SelectedRepositoryIDs) != 2 ||
			input.SelectedRepositoryIDs[0] == 0 || input.SelectedRepositoryIDs[0] >= input.SelectedRepositoryIDs[1] {
			return githubOutputTargetReference{}, refused
		}
	} else {
		if !githubOutputName(input.Repository, 100, lower, lower+"._-") ||
			!strings.ContainsRune(lower, rune(input.Repository[len(input.Repository)-1])) || strings.HasSuffix(input.Repository, ".git") || input.SelectedRepositoryIDs != nil {
			return githubOutputTargetReference{}, refused
		}
		if scope == "environment" {
			if !githubOutputName(input.Environment, 255, lower, lower+"._-") || !strings.ContainsRune(lower, rune(input.Environment[len(input.Environment)-1])) {
				return githubOutputTargetReference{}, refused
			}
		} else if input.Environment != "" {
			return githubOutputTargetReference{}, refused
		}
	}
	for _, actor := range []*githubOutputActorReference{&input.Writer, &input.Cleaner} {
		if actor.CredentialsFile == "" {
			return githubOutputTargetReference{}, refused
		}
		if !filepath.IsAbs(actor.CredentialsFile) {
			actor.CredentialsFile = filepath.Join(directory, actor.CredentialsFile)
		}
		actor.CredentialsFile = filepath.Clean(actor.CredentialsFile)
		if paths[actor.CredentialsFile] {
			return githubOutputTargetReference{}, refused
		}
		paths[actor.CredentialsFile] = true
	}
	return input, nil
}

// These public spellings follow plugins/github-output/internal/github/profile.go
// at the pinned assembly source. The fixture reserves 34 suffix bytes per name.
func githubOutputName(value string, maximum int, first, rest string) bool {
	if len(value) == 0 || len(value) > maximum || !strings.ContainsRune(first, rune(value[0])) {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune(rest, character) {
			return false
		}
	}
	return true
}
