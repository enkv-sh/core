package core

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

func livePublicationInput(inv records.Invocation, input liveRunInput) error {
	selected, publication := catalog.LivePublication(inv.Scenario)
	role := inv.Role
	if role == "cleanup" && (input.CleanupRetry != nil || input.CleanupGrant != nil) {
		// loadLiveInput validates the existing exact Store grant first.
		role = "rerun"
	}
	if !publication || role == "fresh_before" || role == "fresh_after" || role == "rerun" {
		if input.Outputs != nil {
			return errLivePublication
		}
		return nil
	}
	if input.Outputs == nil || input.ConfigurationRecovery != nil || role != "writer" && role != "cleanup" {
		return errLivePublication
	}
	scope := input.Outputs.Scope
	scope.RunID, scope.Scenario = input.RunID, inv.Scenario
	if role == "writer" {
		scope.WriterID = inv.Worker
	}
	if input.Outputs.Validate(scope, role) != nil || input.Outputs.InventoryPath != filepath.Join(inv.StateDir, "output-inventory.json") || input.Outputs.JoinedPath != filepath.Join(inv.StateDir, "output-joined.json") {
		return errLivePublication
	}
	scopes := selected.OutputScopes(input.Settings.Provider)
	if len(scopes) != len(input.Outputs.Profiles) {
		return errLivePublication
	}
	for _, scope := range scopes {
		present := false
		for _, profile := range input.Outputs.Profiles {
			present = present || profile.Scope == scope
		}
		if !present {
			return errLivePublication
		}
	}
	inventory, err := records.ReadOutputFixtureInventory(input.Outputs.InventoryPath, scope)
	if err != nil || len(inventory.Rows) != 2*len(input.Outputs.Profiles) || role == "writer" && len(inventory.Actors) != 0 {
		return errLivePublication
	}
	for _, profile := range input.Outputs.Profiles {
		for _, target := range profile.Targets {
			row, err := inventory.Row(target.Index, profile.ProfileID, target.PlannedSlot)
			if err != nil || row.ExclusiveNamespaceDigest != target.ExclusiveNamespaceDigest || role == "writer" && (len(row.Attempts) != 0 || row.Cleanup != nil) {
				return errLivePublication
			}
		}
	}
	if role == "cleanup" && records.ReadOutputFixtureJoined(input.Outputs.JoinedPath, scope) != nil {
		return errLivePublication
	}
	return nil
}

type livePublicationProfile struct {
	input  records.OutputFixtureProfile
	config custody.PublicationConfig
	cloud  liveCloudOutput
	github *liveGitHubOutput
}

type livePublicationRuntime struct {
	input           *records.OutputFixtureInput
	profiles        []livePublicationProfile
	recorder        *livePublicationRecorder
	private         publicationPrivate
	deadline        time.Time
	prepareOnce     sync.Once
	prepareErr      error
	bindEnvironment func(string, string)
	checks          atomic.Uint64
	preparations    atomic.Uint64
}

func livePublicationArtifact(profile records.OutputFixtureProfile) (custody.PublicationConfig, error) {
	if profile.Native == nil {
		return custody.PublicationConfig{}, errLivePublication
	}
	native := profile.Native
	config, err := installedPublicationFixtureConfig(native.ArtifactPath)
	if err != nil {
		return custody.PublicationConfig{}, errLivePublication
	}
	selected := config.Artifact
	if hex.EncodeToString(selected.DescriptorID[:]) != native.DescriptorID || selected.ConfigContractID != native.ConfigContractID || hex.EncodeToString(selected.SHA256[:]) != native.ArtifactSHA256 || selected.Length != native.ArtifactLength ||
		hex.EncodeToString(selected.CredentialRouteID[:]) != native.CredentialRouteID || selected.CredentialRouteContractID != native.CredentialRouteContractID {
		return custody.PublicationConfig{}, errLivePublication
	}
	if err := config.Validate(native.ConfigContractID); err != nil {
		return custody.PublicationConfig{}, errLivePublication
	}
	return config, nil
}

func newLivePublicationRuntime(ctx context.Context, input *records.OutputFixtureInput, budget *runBudget, keys *custody.Fixture, deadline time.Time) (*livePublicationRuntime, error) {
	if input == nil || input.Validate(input.Scope, "writer") != nil || budget == nil || keys == nil || !time.Now().Before(deadline) {
		return nil, errLivePublication
	}
	r := &livePublicationRuntime{input: input.Clone(), deadline: deadline, recorder: &livePublicationRecorder{scope: input.Scope, inventoryPath: input.InventoryPath, budget: budget}}
	for _, profile := range r.input.Profiles {
		config, err := livePublicationArtifact(profile)
		if err != nil {
			return nil, err
		}
		selected := livePublicationProfile{input: profile, config: config}
		writer := liveOutputActor(*profile.Writer)
		if cloud := profile.Cloud; cloud != nil {
			a, b := liveOutputActor(*profile.ConsumerA), liveOutputActor(*profile.ConsumerB)
			selected.cloud, err = newLiveCloudOutput(liveCloudOutputSpec{Location: liveOutputLocation{Provider: cloud.Provider, Region: cloud.Region, Account: cloud.Account, ProjectNumber: cloud.ProjectNumber, SecretNamePrefix: cloud.SecretNamePrefix}, Writer: &writer, ConsumerA: &a, ConsumerB: &b, Budget: budget})
		} else {
			github := profile.GitHub
			selected.github, err = newLiveGitHubOutput(liveGitHubOutputSpec{Scope: profile.Scope, Owner: github.Owner, Repository: github.Repository, Environment: github.Environment, SecretNamePrefix: github.SecretNamePrefix, Writer: &writer, Budget: budget})
		}
		if err != nil || keys.InstallPublication(ctx, config, "publication-"+profile.Scope, config.Artifact.ConfigContractID) != nil {
			return nil, errLivePublication
		}
		r.profiles = append(r.profiles, selected)
	}
	base := publicationCustodyPrivate(keys)
	r.private = base
	r.private.Check = func(ctx context.Context, input publicationActionCheckInput) (publicationActionCheckFacts, error) {
		r.checks.Add(1)
		return base.Check(ctx, input)
	}
	r.private.NewOwner = func(ctx context.Context, input publicationOwnerInput) (publicationPrivateOwner, error) {
		index, ok := r.targetIndex(input.Target)
		if !ok || hex.EncodeToString(input.Projection.DomainID[:]) != r.input.Scope.DomainID {
			return nil, errLivePublication
		}
		if err := r.prepare(ctx); err != nil {
			return nil, err
		}
		for _, profile := range r.profiles {
			selected := false
			for _, target := range profile.input.Targets {
				selected = selected || target.Index == index
			}
			if !selected {
				continue
			}
			var bindErr error
			if profile.cloud != nil {
				bindErr = profile.cloud.BindWriterEnvironment(r.bindEnvironment)
			} else {
				bindErr = profile.github.BindWriterEnvironment(r.bindEnvironment)
			}
			if bindErr != nil {
				return nil, bindErr
			}
		}
		owner, err := base.NewOwner(ctx, input)
		if err != nil {
			return nil, err
		}
		return r.recorder.observe(owner, input, index), nil
	}
	return r, nil
}

func (r *livePublicationRuntime) targetIndex(target contract.OutputTarget) (uint32, bool) {
	for _, profile := range r.profiles {
		if livePublicationProvider(profile.input.Scope) != target.ServiceContractID {
			continue
		}
		for _, row := range profile.input.Targets {
			if row.PlannedSlot == target.CanonicalTarget {
				return row.Index, true
			}
		}
	}
	return 0, false
}

// All selected credentials and actual cloud actors are qualified before the
// first private owner exists. A failed preparation never reopens its sources.
func (r *livePublicationRuntime) prepare(ctx context.Context) error {
	r.prepareOnce.Do(func() {
		r.preparations.Add(1)
		for _, profile := range r.profiles {
			if profile.cloud != nil {
				facts, err := profile.cloud.PrepareWriter(ctx, liveOutputCredentialRoute{Path: profile.input.Native.CredentialPath, ID: profile.config.Artifact.CredentialRouteID}, r.deadline)
				if err != nil {
					r.prepareErr = err
					break
				}
				actors := records.OutputFixtureActors{ProfileID: profile.input.ProfileID, Writer: facts.Principal, ReaderA: profile.input.ConsumerA.Principal, ReaderB: profile.input.ConsumerB.Principal}
				if err := records.SetOutputFixtureActors(r.input.InventoryPath, r.input.Scope, actors); err != nil {
					r.prepareErr = errLivePublication
					break
				}
			} else if err := profile.github.PrepareWriter(ctx, liveOutputCredentialRoute{Path: profile.input.Native.CredentialPath, ID: profile.config.Artifact.CredentialRouteID}, r.deadline); err != nil {
				r.prepareErr = err
				break
			}
		}
		r.recorder.fail(r.prepareErr)
	})
	return r.prepareErr
}
