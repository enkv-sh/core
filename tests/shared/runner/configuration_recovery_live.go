package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/installedarchive"
)

func recoveryPublicResource(settings liveSettings, selector, public string) (installedarchive.SigningResource, error) {
	block, tail := pem.Decode([]byte(settings[public]))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(strings.TrimSpace(string(tail))) != 0 {
		return installedarchive.SigningResource{}, errors.New("recovery public resource refused")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return installedarchive.SigningResource{}, errors.New("recovery public resource refused")
	}
	key := settings[selector]
	parts := strings.Split(key, ":")
	if settings["provider"] == "gcp" {
		parts = strings.Split(key, "/")
	}
	if settings["provider"] == "aws" && len(parts) != 6 || settings["provider"] == "gcp" && len(parts) != 10 || key == "" {
		return installedarchive.SigningResource{}, errors.New("recovery immutable resource refused")
	}
	return installedarchive.SigningResource{Selector: key, Region: parts[3], PublicKey: append([]byte(nil), block.Bytes...)}, nil
}

func (s *runState) prepareLiveConfigurationRecovery(state string, input workerInput, allowance limits) (*installedarchive.LiveRecoveryParentInput, *installedarchive.RecoveryWriterInput, error) {
	row, known := catalog.ConfigurationRecovery(input.Scenarios[0])
	if !known || input.Limits == nil || input.Settings["provider"] != s.record.Provider {
		return nil, nil, errors.New("live recovery preparation refused")
	}
	settings := input.Settings
	resources := installedarchive.RecoveryResources{RecoveryEnabled: input.RecoveryMode == "enabled"}
	family := contract.AWS
	if settings["provider"] == "gcp" {
		family = contract.GCP
	}
	resources.Location = contract.StoreLocation{Provider: family, Region: settings["region"], Bucket: settings["bucket"], PrefixBeforeHEAD: input.Prefix, ExpectedOwner: settings["account"]}
	if family == contract.GCP {
		resources.Location.ExpectedOwner = ""
	}
	var err error
	resources.InitialNormal, err = recoveryPublicResource(settings, "key_id", "public_key_pem")
	if err != nil {
		return nil, nil, err
	}
	resources.Normal = resources.InitialNormal
	if resources.RecoveryEnabled {
		resources.InitialRecovery, err = recoveryPublicResource(settings, "recovery_key_id", "recovery_public_key_pem")
		if err != nil {
			return nil, nil, err
		}
		resources.Recovery = resources.InitialRecovery
	}
	normalIndex, recoveryIndex, authorityIndex := 0, 0, 0
	if history, ok := installedarchive.ReplacementFor(row.Condition); ok {
		for _, step := range history.Steps {
			if step.Mask&1 != 0 {
				normalIndex++
			}
			if step.Mask&4 != 0 && step.Operation != 2 {
				recoveryIndex++
			}
			if step.Mask&2 != 0 {
				authorityIndex++
			}
		}
	}
	for _, pair := range [][2]string{{"normal_successor_key_id", "normal_successor_public_key_pem"}, {"normal_successor_2_key_id", "normal_successor_2_public_key_pem"}} {
		if settings[pair[0]] != "" {
			next, err := recoveryPublicResource(settings, pair[0], pair[1])
			if err != nil {
				return nil, nil, err
			}
			resources.NormalSuccessors = append(resources.NormalSuccessors, next)
		}
	}
	if settings["recovery_successor_key_id"] != "" {
		next, err := recoveryPublicResource(settings, "recovery_successor_key_id", "recovery_successor_public_key_pem")
		if err != nil {
			return nil, nil, err
		}
		resources.RecoverySuccessors = append(resources.RecoverySuccessors, next)
	}
	if normalIndex > len(resources.NormalSuccessors) || recoveryIndex > len(resources.RecoverySuccessors) {
		return nil, nil, errors.New("independent current signing resource unavailable")
	}
	if normalIndex > 0 {
		resources.Normal = resources.NormalSuccessors[normalIndex-1]
	}
	if recoveryIndex > 0 {
		resources.Recovery = resources.RecoverySuccessors[recoveryIndex-1]
	}
	authorityFields := [][2]string{{"authority_kek_id", "authority_kek_public_key_pem"}, {"authority_successor_1_kek_id", "authority_successor_1_kek_public_key_pem"}, {"authority_successor_2_kek_id", "authority_successor_2_kek_public_key_pem"}}
	if authorityIndex >= len(authorityFields) {
		return nil, nil, errors.New("independent current private resource unavailable")
	}
	authority, err := recoveryPublicResource(settings, authorityFields[authorityIndex][0], authorityFields[authorityIndex][1])
	if err != nil {
		return nil, nil, err
	}
	// All resources and public keys above precede random-domain allocation.
	if _, err := rand.Read(resources.Domain[:]); err != nil || resources.Domain.IsZero() {
		return nil, nil, errors.New("recovery Domain allocation refused")
	}
	locations := installedarchive.RecoveryLocations{}
	if row.Condition == "new-domain-no-pin" || row.Condition == "prior-domain-pin" {
		if _, err := rand.Read(resources.PriorDomain[:]); err != nil || resources.PriorDomain.IsZero() || resources.Domain == resources.PriorDomain {
			return nil, nil, errors.New("recovery prior Domain allocation refused")
		}
		locations.PriorDomain = resources.PriorDomain
	}
	if row.Condition == "copied-location" {
		locations.CopiedPrefix = resources.Location.PrefixBeforeHEAD + "/copied"
	}

	oracle := filepath.Join(state, "parent-oracle")

	owner := &installedarchive.LiveRecoveryParentInput{Fixture: filepath.Join(state, "recovery-parent.json"), Condition: row.Condition, Report: filepath.Join(state, "recovery-report.json"), ChildTerminals: filepath.Join(state, "restricted-child.txt"), Resources: resources, Locations: locations, AuthoritySelector: authority.Selector, AuthorityPublicKey: authority.PublicKey}
	console := installedarchive.RecoveryInput{Provider: settings["provider"], Owner: resources.Location.ExpectedOwner, ReadRoute: "new-recovery-read", SignRoute: "new-recovery-public", PrivateRoute: "new-recovery-private", TimeoutMillis: 10000, Requests: min(allowance.Requests, 4096), BodyBytes: allowance.BodyBytes, ResponseBytes: 8 << 20}
	source := func(role string) (installedarchive.LiveCredentialFile, error) {
		actor := s.actorSettings[role]
		if actor["credentials_file"] == "" {
			return installedarchive.LiveCredentialFile{}, errors.New("independent recovery credential route unavailable")
		}
		expires := time.Time{}
		if actor["credential_expires"] != "" {
			var err error
			expires, err = time.Parse(time.RFC3339, actor["credential_expires"])
			if err != nil {
				return installedarchive.LiveCredentialFile{}, errors.New("recovery credential expiry refused")
			}
		}
		return installedarchive.LiveCredentialFile{Path: actor["credentials_file"], Profile: actor["profile"], Expires: expires}, nil
	}
	for _, route := range []struct {
		role        string
		destination *installedarchive.LiveCredentialFile
	}{
		{"replacement-store", &owner.Credentials.Read}, {fmt.Sprintf("normal-signer-%d", normalIndex), &owner.Credentials.Normal}, {fmt.Sprintf("authority-decrypter-%d", authorityIndex), &owner.Credentials.Private},
	} {
		value, err := source(route.role)
		if err != nil {
			return nil, nil, err
		}
		*route.destination = value
	}
	if resources.RecoveryEnabled {
		owner.Credentials.Recovery, err = source(fmt.Sprintf("recovery-signer-%d", recoveryIndex))
		if err != nil {
			return nil, nil, err
		}
	}
	switch row.Condition {
	case "required-public-denied", "required-authority-denied", "recovery-key-only":
		role := "denied-observer"
		if row.Condition == "required-authority-denied" {
			role = "denied-reader"
		}
		if row.Condition == "recovery-key-only" {
			role = "recovery-decrypter-0"
		}
		denied, err := source(role)
		if err != nil {
			return nil, nil, err
		}
		owner.ProviderDenial = true
		if row.Condition == "required-public-denied" {
			owner.Credentials.Normal = denied
		} else {
			owner.Credentials.Private = denied
		}
	}
	if resources.RecoveryEnabled && row.Condition == "wrong-anchor" {
		owner.Credentials.Normal = owner.Credentials.Recovery
	}
	if row.Condition == "recovery-proof-two-normal" {
		owner.Credentials.Recovery = owner.Credentials.Normal
	}
	if family == contract.GCP {
		console.ServiceAccountFile = owner.Credentials.Read.Path
		console.NormalServiceAccountFile = owner.Credentials.Normal.Path
		console.PrivateServiceAccountFile = owner.Credentials.Private.Path
		console.RecoveryServiceAccountFile = owner.Credentials.Recovery.Path
	}
	if !resources.RecoveryEnabled && (row.Condition == "wrong-anchor" || row.Condition == "recovery-only-inadequate") {
		if len(resources.NormalSuccessors) == 0 {
			return nil, nil, errors.New("independent inadequate signer unavailable")
		}
		resources.Recovery = resources.NormalSuccessors[0]
		owner.Resources = resources
		other, err := source("normal-signer-1")
		if err != nil {
			return nil, nil, err
		}
		if row.Condition == "wrong-anchor" {
			owner.Credentials.Normal = other
			if family == contract.GCP {
				console.NormalServiceAccountFile = other.Path
			}
		} else {
			owner.Credentials.Recovery = other
			if family == contract.GCP {
				console.RecoveryServiceAccountFile = other.Path
			}
		}
	}
	if err := os.Mkdir(oracle, 0700); err != nil {
		return nil, nil, errors.New("private capture owner unavailable")
	}
	owner.Input = console
	return owner, &installedarchive.RecoveryWriterInput{Domain: resources.Domain, OracleDirectory: oracle, Locations: locations}, nil
}

func (s *runState) executeLiveConfigurationRecovery(ctx context.Context, state string, input workerInput, owner installedarchive.LiveRecoveryParentInput, deadline time.Time, result *scenarioResult, joined *bool, localControl ...bool) error {
	if len(localControl) > 1 {
		return errors.New("parent control selection refused")
	}
	driver, known := s.recoveryArtifacts[s.record.Provider]
	if !known {
		return errors.New("ordinary live recovery artifact unavailable")
	}
	if err := retireLiveRecoveryConfiguration(state); err != nil {
		return err
	}
	remaining := owner.Input
	if result.BudgetReserved == nil || result.BudgetReserved.Requests >= input.Limits.Requests || result.BudgetReserved.BodyBytes >= input.Limits.BodyBytes {
		return errors.New("live recovery cumulative allowance unavailable")
	}
	remaining.Requests = min(remaining.Requests, input.Limits.Requests-result.BudgetReserved.Requests)
	remaining.BodyBytes = min(remaining.BodyBytes, input.Limits.BodyBytes-result.BudgetReserved.BodyBytes)
	owner.Input = remaining
	parentInput := filepath.Join(state, "ordinary-parent-input.json")
	if err := records.WriteJSON(parentInput, owner, 0600); err != nil {
		return errors.New("private live recovery input unavailable")
	}
	name := recoveryPhaseHelper(s.record.Provider, "reconstruction-parent")
	processCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	controlKey := "ENKV_RECOVERY_LIVE_PARENT_INPUT"
	if len(localControl) == 1 && localControl[0] {
		controlKey = "ENKV_RECOVERY_LIVE_PARENT_CONTROL"
	}
	phase, processErr := runConfigurationRecoveryPhase(processCtx, state, driver.Path, driver.SHA256, "reconstruction-parent", name, environment(os.Environ(), map[string]string{controlKey: parentInput}))
	*joined = *joined && phase.Process.Joined
	var report installedarchive.RecoveryReport
	readErr := records.ReadJSON(owner.Report, &report)
	reservation := &records.BudgetReservation{Requests: remaining.Requests, BodyBytes: remaining.BodyBytes}
	if processErr == nil && readErr == nil {
		reservation.Requests, reservation.BodyBytes = report.ReservedRequests, report.ReservedBytes
	}
	var err error
	result.BudgetReserved, err = addReservations(result.BudgetReserved, reservation)
	if err != nil {
		return errors.New("recovery cumulative reservation unavailable")
	}
	private := configurationRecoveryProcessEvidence{Provider: s.record.Provider, Recovery: input.RecoveryMode == "enabled", LossBarrier: true, Report: report, Phases: []configurationRecoveryPhase{phase}}
	semanticComplete := validateLiveConfigurationRecoverySemantics(configurationRecoveryOutcome(private), input.RecoveryMode, owner.Condition, remaining)
	public, publicErr := publicConfigurationRecovery(private, s.record.Source, s.record.BuildClosure.Race)
	result.Reconstruction = append(result.Reconstruction, public)
	if processErr != nil || readErr != nil || publicErr != nil || !semanticComplete || !validateLiveConfigurationRecovery(public, input.RecoveryMode, owner.Condition, s.record.Source, driver.SHA256, remaining, s.record.BuildClosure.Race) {
		return errors.New("ordinary live recovery verification incomplete")
	}
	return nil
}

func retireLiveRecoveryConfiguration(state string) error {
	entries, err := os.ReadDir(state)
	if err != nil {
		return errors.New("loss inventory unavailable")
	}
	retained := map[string]bool{"workers": true, "parent-oracle": true, "inventory.json": false, "inventory.lock": false, "recovery-parent.json": false, "generator-cleanup.json": false, "generator-writer-joined.json": false}
	for _, entry := range entries {
		directory, keep := retained[entry.Name()]
		if !keep {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || !directory && !info.Mode().IsRegular() || directory && info.Mode().Perm() != 0700 {
			return errors.New("loss retained owner refused")
		}
	}
	for _, entry := range entries {
		if _, keep := retained[entry.Name()]; keep {
			continue
		}
		if err := os.RemoveAll(filepath.Join(state, entry.Name())); err != nil {
			return errors.New("local configuration retirement failed")
		}
	}
	return nil
}
