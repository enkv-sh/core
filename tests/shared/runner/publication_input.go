package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

var errPublicationInput = errors.New("private publication input unavailable or inconsistent")

func publicationActor(value outputActorReference) *records.OutputFixtureActor {
	return &records.OutputFixtureActor{CredentialsFile: value.CredentialsFile, Profile: value.Profile, ServiceAccount: value.ServiceAccount, Principal: value.Principal}
}

// Allocation reserves names under the separately required exclusive fixture
// namespace. Neither these rows nor their digest establish Product ownership.
func preparePublicationInput(state, runID, writerID, scenario string, selected []selectedOutputProfile, build string, closure assemblyClosure) (*records.OutputFixtureInput, error) {
	row, ok := catalog.LivePublication(scenario)
	if !ok {
		return nil, errPublicationInput
	}
	var domain [32]byte
	if _, err := rand.Read(domain[:]); err != nil || domain == [32]byte{} {
		return nil, errPublicationInput
	}
	input := &records.OutputFixtureInput{SchemaVersion: 2, Scope: records.OutputFixtureScope{RunID: runID, Scenario: scenario, DomainID: hex.EncodeToString(domain[:]), WriterID: writerID}, InventoryPath: filepath.Join(state, "output-inventory.json"), JoinedPath: filepath.Join(state, "output-joined.json")}
	provider := closure.Provider
	for _, scope := range row.OutputScopes(provider) {
		var chosen *selectedOutputProfile
		for i := range selected {
			if selected[i].Scope == scope && selected[i].Namespace == row.Namespace {
				if chosen != nil {
					return nil, errPublicationInput
				}
				chosen = &selected[i]
			}
		}
		if chosen == nil {
			return nil, errPublicationInput
		}
		p := records.OutputFixtureProfile{Scope: scope, Namespace: chosen.Namespace, ProfileID: chosen.ProfileID}
		if c := chosen.Cloud; c != nil {
			p.Cloud = &records.OutputFixtureCloud{Provider: provider, Region: c.Region, Account: c.Account, Project: c.Project, ProjectNumber: c.ProjectNumber, SecretNamePrefix: c.SecretNamePrefix}
			p.Writer, p.Cleaner = publicationActor(c.Writer), publicationActor(c.Cleaner)
			a, aok := c.Consumers["consumer_a"]
			b, bok := c.Consumers["consumer_b"]
			if !aok || !bok {
				return nil, errPublicationInput
			}
			p.ConsumerA, p.ConsumerB = publicationActor(a), publicationActor(b)
		}
		if g := chosen.GitHub; g != nil {
			p.GitHub = &records.OutputFixtureGitHub{Owner: g.Owner, Repository: g.Repository, Environment: g.Environment, SecretNamePrefix: g.SecretNamePrefix, SelectedRepositoryIDs: slices.Clone(g.SelectedRepositoryIDs)}
			p.Writer = &records.OutputFixtureActor{CredentialsFile: g.Writer.CredentialsFile}
			p.Cleaner = &records.OutputFixtureActor{CredentialsFile: g.Cleaner.CredentialsFile}
		}
		var native *outputArtifactClosure
		for _, artifact := range closure.OutputArtifacts {
			if artifact == nil {
				return nil, errPublicationInput
			}
			binding, err := outputBinding(artifact.Artifact)
			if err != nil {
				return nil, errPublicationInput
			}
			if binding.StoredProfileID == p.ProfileID {
				if native != nil {
					return nil, errPublicationInput
				}
				native = artifact
			}
		}
		if native == nil {
			return nil, errPublicationInput
		}
		command, _ := outputCommand(p.ProfileID)
		p.Native = &records.OutputFixtureNative{ArtifactPath: filepath.Join(build, command.command), ArtifactSHA256: hex.EncodeToString(native.Artifact.SHA256[:]), ArtifactLength: native.Artifact.Length, CredentialPath: filepath.Join(state, "output-credential-"+scope), CredentialRouteID: hex.EncodeToString(native.Artifact.CredentialRouteID[:]), DescriptorID: hex.EncodeToString(native.Artifact.DescriptorID[:]), ConfigContractID: native.Artifact.ConfigContractID, CredentialRouteContractID: native.Artifact.CredentialRouteContractID}
		slots, locators, err := publicationCoordinates(p, input.Scope.DomainID)
		if err != nil {
			return nil, err
		}
		for i := range slots {
			p.Targets = append(p.Targets, records.OutputFixtureTarget{Index: uint32(2*len(input.Profiles) + i), PlannedSlot: slots[i], ConsumerLocator: locators[i]})
		}
		digest, err := publicationNamespaceDigest(input.Scope.DomainID, p)
		if err != nil {
			return nil, err
		}
		for i := range p.Targets {
			p.Targets[i].ExclusiveNamespaceDigest = digest
		}
		input.Profiles = append(input.Profiles, p)
	}
	if input.Validate(input.Scope, "parent") != nil || validatePublicationNative(input, runID, closure, build) != nil {
		return nil, errPublicationInput
	}
	if _, err := os.Lstat(input.JoinedPath); !os.IsNotExist(err) {
		return nil, errPublicationInput
	}
	rows := publicationInventoryRows(input)
	if records.NewOutputFixtureInventory(input.InventoryPath, input.Scope, rows) != nil {
		return nil, errPublicationInput
	}
	return input, nil
}

func publicationCoordinates(p records.OutputFixtureProfile, domain string) ([2]string, [2]string, error) {
	var slots, locators [2]string
	if len(domain) != 64 {
		return slots, locators, errPublicationInput
	}
	prefix, base := "", ""
	switch p.Scope {
	case "aws-secrets-manager":
		if p.Cloud == nil {
			return slots, locators, errPublicationInput
		}
		prefix = p.Cloud.SecretNamePrefix
		base = "arn:aws:secretsmanager:" + p.Cloud.Region + ":" + p.Cloud.Account + ":secret:"
	case "gcp-secret-manager":
		if p.Cloud == nil {
			return slots, locators, errPublicationInput
		}
		prefix = p.Cloud.SecretNamePrefix
	case "github-repository", "github-organization", "github-environment":
		if p.GitHub == nil {
			return slots, locators, errPublicationInput
		}
		g := p.GitHub
		prefix = g.SecretNamePrefix
		base = "repos/" + g.Owner + "/" + g.Repository + "/actions/secrets/"
		if p.Scope == "github-organization" {
			base = "orgs/" + g.Owner + "/actions/secrets/"
		}
		if p.Scope == "github-environment" {
			base = "repos/" + g.Owner + "/" + g.Repository + "/environments/" + g.Environment + "/secrets/"
		}
	default:
		return slots, locators, errPublicationInput
	}
	for i, suffix := range []string{"_P", "_S"} {
		slots[i] = base + prefix + strings.ToUpper(domain[:32]) + suffix
		locators[i] = slots[i]
		if p.Scope == "aws-secrets-manager" {
			locators[i] += "?stage=AWSCURRENT"
		}
		if p.Scope == "gcp-secret-manager" {
			locators[i] += "/versions/latest"
		}
	}
	return slots, locators, nil
}

func publicationNamespaceDigest(domain string, p records.OutputFixtureProfile) (string, error) {
	public := struct {
		Cloud  *records.OutputFixtureCloud
		GitHub *records.OutputFixtureGitHub
	}{p.Cloud, p.GitHub}
	location, err := json.Marshal(public)
	if err != nil || len(p.Targets) != 2 {
		return "", errPublicationInput
	}
	body := []byte("ENKV/TEST/OUTPUT-NAMESPACE/v1\x00")
	for _, field := range []string{domain, p.ProfileID, p.Namespace, string(location), p.Targets[0].PlannedSlot, p.Targets[1].PlannedSlot} {
		body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
		body = append(body, field...)
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func publicationInventoryRows(input *records.OutputFixtureInput) []records.OutputFixtureRow {
	rows := make([]records.OutputFixtureRow, 2*len(input.Profiles))
	for _, p := range input.Profiles {
		for _, target := range p.Targets {
			rows[target.Index] = records.OutputFixtureRow{ProfileID: p.ProfileID, PlannedSlot: target.PlannedSlot, ExclusiveNamespaceDigest: target.ExclusiveNamespaceDigest, Attempts: []records.OutputFixtureAttempt{}}
		}
	}
	return rows
}

// The caller has already verified the complete assembly against current source
// and bytes. This checks that a case references exactly those bound rows.
func validatePublicationNative(input *records.OutputFixtureInput, runID string, closure assemblyClosure, build string) error {
	selected := make([]selectedOutputProfile, 0, len(input.Profiles))
	for _, p := range input.Profiles {
		s := selectedOutputProfile{resolvedOutputScope: resolvedOutputScope{Scope: p.Scope, Namespace: p.Namespace, ProfileID: p.ProfileID}}
		if c := p.Cloud; c != nil {
			s.Cloud = &outputTargetReference{Region: c.Region, Account: c.Account, Project: c.Project, ProjectNumber: c.ProjectNumber, SecretNamePrefix: c.SecretNamePrefix, Consumers: map[string]outputActorReference{"consumer_a": {Principal: p.ConsumerA.Principal}, "consumer_b": {Principal: p.ConsumerB.Principal}}}
			if c.Provider == "aws" {
				s.Cloud.VersionStage = "AWSCURRENT"
			} else {
				s.Cloud.Version = "latest"
			}
		}
		if g := p.GitHub; g != nil {
			s.GitHub = &githubOutputTargetReference{Owner: g.Owner, Repository: g.Repository, Environment: g.Environment, SecretNamePrefix: g.SecretNamePrefix, SelectedRepositoryIDs: slices.Clone(g.SelectedRepositoryIDs)}
		}
		selected = append(selected, s)
	}
	bindings, err := publicationAssemblyBindings(runID, selected)
	if err != nil {
		return errPublicationInput
	}
	for _, p := range input.Profiles {
		var found bool
		for _, artifact := range closure.OutputArtifacts {
			if artifact == nil {
				return errPublicationInput
			}
			binding, err := outputBinding(artifact.Artifact)
			if err != nil {
				return errPublicationInput
			}
			if binding.StoredProfileID != p.ProfileID {
				continue
			}
			if found {
				return errPublicationInput
			}
			found = true
			expected := false
			for _, candidate := range bindings {
				if candidate == binding {
					expected = true
				}
			}
			n := p.Native
			command, _ := outputCommand(p.ProfileID)
			if !expected || n == nil || n.ArtifactPath != filepath.Join(build, command.command) || n.ArtifactSHA256 != hex.EncodeToString(artifact.Artifact.SHA256[:]) || n.ArtifactLength != artifact.Artifact.Length || n.CredentialRouteID != hex.EncodeToString(binding.CredentialRouteID[:]) || n.DescriptorID != hex.EncodeToString(binding.DescriptorID[:]) || n.ConfigContractID != binding.ConfigContractID || n.CredentialRouteContractID != binding.CredentialRouteContractID {
				return errPublicationInput
			}
		}
		if !found {
			return errPublicationInput
		}
	}
	return nil
}

func publicationEvidenceDigest(writer, cleaner *records.OutputFixtureInput) (string, error) {
	body, err := json.Marshal(struct{ Writer, Cleaner *records.OutputFixtureInput }{writer, cleaner})
	if err != nil {
		return "", errPublicationInput
	}
	return digestBytes(body), nil
}

// validateRecordedPublicationInventory reads retained ownership and join facts.
// Callers that perform new worker actions must also admit the current input.
func validateRecordedPublicationInventory(input *records.OutputFixtureInput, joined bool) error {
	if input == nil {
		return errPublicationInput
	}
	role := "parent"
	if len(input.Profiles) > 0 {
		if input.Profiles[0].Writer == nil {
			role = "cleanup"
		} else if input.Profiles[0].Cleaner == nil {
			role = "writer"
		}
	}
	if input.ValidateRecorded(input.Scope, role) != nil {
		return errPublicationInput
	}
	inventory, err := records.ReadOutputFixtureInventory(input.InventoryPath, input.Scope)
	if err != nil {
		return errPublicationInput
	}
	rows := publicationInventoryRows(input)
	if len(rows) != len(inventory.Rows) {
		return errPublicationInput
	}
	for i, row := range rows {
		got := inventory.Rows[i]
		scope := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(row.ProfileID, "ENKV/OUTPUT/"), "/v3"))
		if row.ProfileID != got.ProfileID || row.PlannedSlot != got.PlannedSlot || row.ExclusiveNamespaceDigest != got.ExclusiveNamespaceDigest || !publicationOwnedInstance(scope, got.PlannedSlot, got.OwnedInstance) {
			return errPublicationInput
		}
	}
	for _, profile := range input.Profiles {
		if profile.Cloud == nil {
			continue
		}
		entered := false
		for _, target := range profile.Targets {
			if len(inventory.Rows[target.Index].Attempts) != 0 {
				entered = true
			}
		}
		found := false
		for _, actor := range inventory.Actors {
			if actor.ProfileID != profile.ProfileID {
				continue
			}
			found = true
			if profile.ConsumerA != nil && (actor.ReaderA != profile.ConsumerA.Principal || actor.ReaderB != profile.ConsumerB.Principal) {
				return errPublicationInput
			}
			if profile.Cloud.Provider == "aws" {
				prefix := "arn:aws:iam::" + profile.Cloud.Account + ":user/"
				if !strings.HasPrefix(actor.Writer, prefix) || actor.Writer == prefix {
					return errPublicationInput
				}
			} else if profile.Writer != nil && actor.Writer != "serviceAccount:"+profile.Writer.ServiceAccount {
				return errPublicationInput
			}
		}
		if entered && !found {
			return errPublicationInput
		}
	}
	if joined && records.ReadOutputFixtureJoined(input.JoinedPath, input.Scope) != nil {
		return errPublicationInput
	}
	return nil
}

func writePublicationJoined(input *records.OutputFixtureInput, inv records.Invocation, process processResult, groupJoined bool) error {
	if input == nil || input.Validate(input.Scope, "writer") != nil || inv.Role != "writer" || inv.Worker != input.Scope.WriterID || inv.RunID != input.Scope.RunID || inv.Scenario != input.Scope.Scenario || inv.StateDir != filepath.Dir(input.InventoryPath) || !process.Started || !process.Joined || !groupJoined || validateRecordedPublicationInventory(input, false) != nil {
		return errPublicationInput
	}
	return records.WriteOutputFixtureJoined(input.JoinedPath, input.Scope)
}

func removePublicationRoutes(input *records.OutputFixtureInput) error {
	if input == nil || input.Validate(input.Scope, "writer") != nil || validateRecordedPublicationInventory(input, true) != nil {
		return errPublicationInput
	}
	for _, p := range input.Profiles {
		if p.Native == nil {
			return errPublicationInput
		}
		if err := os.Remove(p.Native.CredentialPath); err != nil && !os.IsNotExist(err) {
			return errPublicationInput
		}
	}
	return nil
}

func validateRetainedPublication(state string, parent runRecord, result scenarioResult) error {
	_, publication := recordedPublication(result.Scenario)
	if !publication {
		if result.OutputsSHA256 != "" {
			return errPublicationInput
		}
		return nil
	}
	if !hexString(result.OutputsSHA256, sha256HexLength) || result.Writer == nil || parent.BuildClosure == nil {
		return errPublicationInput
	}
	var writer, cleaner workerInput
	if records.ReadJSON(filepath.Join(state, "input.json"), &writer) != nil || records.ReadJSON(filepath.Join(state, "cleanup-input.json"), &cleaner) != nil || writer.Outputs == nil || cleaner.Outputs == nil {
		return errPublicationInput
	}
	w, c := writer.Outputs, cleaner.Outputs
	if w.Scope.RunID != parent.RunID || w.Scope.Scenario != result.Scenario || w.Scope.WriterID != result.Writer.Worker || w.ValidateRecorded(w.Scope, "writer") != nil || c.ValidateRecorded(w.Scope, "cleanup") != nil || writer.RunID != parent.RunID || cleaner.RunID != parent.RunID || !reflect.DeepEqual(writer.authorityOnly(), cleaner.authorityOnly()) || w.InventoryPath != filepath.Join(state, "output-inventory.json") || w.JoinedPath != filepath.Join(state, "output-joined.json") {
		return errPublicationInput
	}
	wc, cc := w.Clone(), c.Clone()
	for i := range wc.Profiles {
		wc.Profiles[i].Writer, wc.Profiles[i].ConsumerA, wc.Profiles[i].ConsumerB, wc.Profiles[i].Native = nil, nil, nil, nil
		cc.Profiles[i].Cleaner = nil
	}
	if !reflect.DeepEqual(wc, cc) {
		return errPublicationInput
	}
	digest, err := publicationEvidenceDigest(w, c)
	if err != nil || digest != result.OutputsSHA256 || validatePublicationNative(w, parent.RunID, *parent.BuildClosure, filepath.Join(filepath.Dir(state), "build")) != nil || validateRecordedPublicationInventory(w, true) != nil {
		return errPublicationInput
	}
	for _, p := range w.Profiles {
		digest, err := publicationNamespaceDigest(w.Scope.DomainID, p)
		if err != nil || digest != p.Targets[0].ExclusiveNamespaceDigest {
			return errPublicationInput
		}
	}
	return nil
}

func samePublicationBindings(selected, retained []outputProfileBinding) bool {
	if len(selected) != len(retained) {
		return false
	}
	for i := range selected {
		if selected[i] != retained[i] {
			return false
		}
	}
	return true
}

type publicationResidue struct {
	Remaining, Unknown, Scheduled int64
	FirstUnresolved               *uint32
}

func publicationResidueState(input *records.OutputFixtureInput) (publicationResidue, error) {
	var result publicationResidue
	if input == nil || validateRecordedPublicationInventory(input, true) != nil {
		return result, errPublicationInput
	}
	inventory, err := records.ReadOutputFixtureInventory(input.InventoryPath, input.Scope)
	if err != nil {
		return result, errPublicationInput
	}
	for _, p := range input.Profiles {
		for _, target := range p.Targets {
			row, err := inventory.Row(target.Index, p.ProfileID, target.PlannedSlot)
			if err != nil || !publicationOwnedInstance(p.Scope, row.PlannedSlot, row.OwnedInstance) {
				return publicationResidue{}, errPublicationInput
			}
			state, err := inventory.CleanupState(target.Index)
			if err != nil {
				return publicationResidue{}, errPublicationInput
			}
			if state.Remaining {
				result.Remaining++
			}
			if state.Unknown {
				result.Unknown++
			}
			if state.Scheduled {
				result.Scheduled++
			}
			if (state.Unknown || state.Remaining && !state.Scheduled) && result.FirstUnresolved == nil {
				index := target.Index
				result.FirstUnresolved = &index
			}
		}
	}
	return result, nil
}

func publicationOwnedInstance(scope, slot, owned string) bool {
	if owned == "" {
		return true
	}
	if scope != "aws-secrets-manager" {
		return owned == slot
	}
	suffix := strings.TrimPrefix(owned, slot+"-")
	if suffix == owned || len(suffix) != 6 {
		return false
	}
	for _, c := range suffix {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", c) {
			return false
		}
	}
	return true
}

// Aggregate counts alone never justify scheduled residue. These facts are set
// only after the private input, exact rows, qualified birth and join are read.
func scenarioCleanupPassed(result scenarioResult) bool {
	if cleanupPassed(result.Cleanup) {
		return result.OutputScheduled == 0
	}
	value := result.Cleanup
	if result.OutputScheduled == 0 || result.OutputScheduled > 10 || !hexString(result.OutputsSHA256, sha256HexLength) || value.Outcome != "passed" || value.Failure != nil || value.HarnessFailure != nil || value.RemainingOwnedObjects == nil || *value.RemainingOwnedObjects != int64(result.OutputScheduled) || value.UnknownEffects == nil || *value.UnknownEffects != 0 {
		return false
	}
	if result.Scenario == records.StockPluginScenario {
		return result.OutputScheduled == 2
	}
	row, ok := recordedPublication(result.Scenario)
	if !ok {
		return false
	}
	return slices.Contains(row.OutputScopes("aws"), "aws-secrets-manager")
}

func runCleanupPassed(value runRecord) bool {
	var scheduled int64
	for _, item := range value.Scenarios {
		scheduled += int64(item.OutputScheduled)
	}
	if scheduled == 0 {
		return cleanupPassed(value.Cleanup)
	}
	for _, item := range value.Scenarios {
		if !scenarioCleanupPassed(item) {
			return false
		}
	}
	c := value.Cleanup
	return scheduled > 0 && c.Outcome == "passed" && c.Failure == nil && c.HarnessFailure == nil && c.RemainingOwnedObjects != nil && *c.RemainingOwnedObjects == scheduled && c.UnknownEffects != nil && *c.UnknownEffects == 0
}

func publicationScenarioState(directory string, result scenarioResult) (string, error) {
	name, err := recordedCaseDirectory(result.Entry)
	if err != nil {
		return "", errPublicationInput
	}
	return filepath.Join(directory, "private", name), nil
}

func validatePublicationRunEvidence(root, directory string, value runRecord) error {
	for _, result := range value.Scenarios {
		if result.Scenario == records.StockPluginScenario {
			if result.Outcome == "passed" || result.StockPluginEvidence != nil {
				if readStockPluginEvidence(directory, value, result) != nil {
					return errPublicationInput
				}
			}
			continue
		}
		_, publication := recordedPublication(result.Scenario)
		if !publication {
			if result.OutputScheduled != 0 || result.OutputsSHA256 != "" {
				return errPublicationInput
			}
			continue
		}
		parent, owner := value, directory
		originalResult := result
		if value.RecoveryRunID != "" {
			var err error
			owner, err = runPath(root, "live", "runs", value.RecoveryRunID)
			if err != nil || records.ReadJSON(filepath.Join(owner, "run.json"), &parent) != nil || parent.RunID != value.RecoveryRunID || !sameSource(value.Source, parent.Source) {
				return errPublicationInput
			}
			found := false
			for _, candidate := range parent.Scenarios {
				if candidate.Entry == result.Entry {
					originalResult = candidate
					found = true
					break
				}
			}
			if !found || result.OutputsSHA256 != originalResult.OutputsSHA256 {
				return errPublicationInput
			}
		}
		state, err := publicationScenarioState(owner, originalResult)
		if err != nil || validateRetainedPublication(state, parent, originalResult) != nil {
			return errPublicationInput
		}
		var input workerInput
		if records.ReadJSON(filepath.Join(state, "input.json"), &input) != nil {
			return errPublicationInput
		}
		residue, err := publicationResidueState(input.Outputs)
		if err != nil || residue.Scheduled != int64(result.OutputScheduled) {
			return errPublicationInput
		}
		if scenarioCleanupPassed(result) && (residue.Unknown != 0 || residue.Remaining != residue.Scheduled) {
			return errPublicationInput
		}
	}
	return nil
}

func preservePublicationResidue(cleanup records.Cleanup, residue publicationResidue) records.Cleanup {
	value := cleanup
	if value.RemainingOwnedObjects == nil || value.UnknownEffects == nil || *value.RemainingOwnedObjects < 0 || *value.UnknownEffects < 0 || *value.RemainingOwnedObjects > maximumCleanupCount-residue.Remaining || *value.UnknownEffects > maximumCleanupCount-residue.Unknown {
		return unresolvedCleanup()
	}
	remaining, unknown := *value.RemainingOwnedObjects+residue.Remaining, *value.UnknownEffects+residue.Unknown
	value.RemainingOwnedObjects, value.UnknownEffects = &remaining, &unknown
	if residue.Unknown != 0 || residue.Remaining != residue.Scheduled {
		value.Outcome = "unresolved"
		value.Failure = &records.Failure{Class: "cleanup_unresolved", Stage: "cleanup"}
		// Preserve an eligible Store failure while it is still unresolved. A Store
		// success cannot replace independent output uncertainty with success.
		if cleanupPassed(cleanup) && residue.FirstUnresolved != nil {
			index := *residue.FirstUnresolved
			value.HarnessFailure = &records.HarnessFailure{Operation: "output_cleanup", Stage: "response_intake", Cause: "evidence_unavailable", Effect: "unknown", TargetKind: "output_inventory", TargetIndex: &index}
		}
	}
	return value
}
