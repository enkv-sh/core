package compositionfull

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/compositions/generatorhost"
	"enkv.sh/compositions/outputhost"
	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact"
	generatorprotocol "enkv.sh/sdk/protocols/generator"
	outputprotocol "enkv.sh/sdk/protocols/output"
)

// MaxPrepareDependencyRequirements bounds declared effect requirements plus
// the common administrative requirement allowance.
const MaxPrepareDependencyRequirements = contract.CryptoMaxValueEntries + contract.MaxOutputBindings + 1

// ErrPrepareSourceCheck marks failure to establish the captured source pair.
// Callers can check it with errors.Is; readiness facts must not survive it.
var ErrPrepareSourceCheck = errors.New("prepare source check incomplete")

// PrepareDependencyRequirement describes one exact declared binary requirement.
// Artifact is the admitted SHA-256 in lowercase hexadecimal, or nil when the
// installed metadata cannot resolve that requirement. It contains no path or
// credential coordinate.
type PrepareDependencyRequirement struct {
	Role            string   `json:"role"`
	Plugin          *string  `json:"plugin"`
	Contract        string   `json:"contract"`
	ProtocolVersion uint32   `json:"protocol_version"`
	Artifact        *string  `json:"artifact"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason"`
	Subjects        []uint16 `json:"subjects"`
}

// PrepareDependencyAssessment keeps administrative support separate from effect
// artifacts. Readiness supplies no credential, permission or execution right.
type PrepareDependencyAssessment struct {
	Assessment                 string                              `json:"assessment"`
	MinimumAdministrativeReady bool                                `json:"minimum_administrative_ready"`
	AllDeclaredReady           bool                                `json:"all_declared_ready"`
	Requirements               []PrepareDependencyRequirement      `json:"requirements"`
	Installations              []plugininstallation.Installation   `json:"installations"`
	SettingsFailure            *plugininstallation.SettingsFailure `json:"settings_failure"`
}

func prepareDependencies(ctx context.Context, pair *configuration.Pair, model *configuration.Model, upgrade bool) (PrepareDependencyAssessment, error) {
	result := PrepareDependencyAssessment{Assessment: "incomplete", Requirements: []PrepareDependencyRequirement{}, Installations: []plugininstallation.Installation{}}
	if ctx == nil || pair == nil || model == nil {
		return result, ErrCell
	}
	if err := ctx.Err(); err != nil {
		return result, errors.Join(err, context.Cause(ctx))
	}
	checks, err := configurationDependencyChecks(model)
	if err != nil {
		return result, err
	}
	result.Requirements = make([]PrepareDependencyRequirement, 0, len(checks))
	requirements, err := configurationPluginRequirements(model)
	if err != nil {
		return result, err
	}
	mode := plugininstallation.Prepare
	if upgrade {
		mode = plugininstallation.Upgrade
	}
	var rows []plugininstallation.Installation
	var captureErr error
	var plugins *configurationInstalledPlugins
	if len(requirements) != 0 {
		plugins, rows, captureErr = configurationCapturePlugins(ctx, pair, requirements, mode)
	} else if err := pair.CheckUnchanged(ctx); err != nil {
		captureErr = errors.Join(plugininstallation.ErrSourceChanged, err)
	}
	result.MinimumAdministrativeReady = configurationMinimumAdministrativeReady(model)
	if len(rows) == 0 && errors.Is(captureErr, plugininstallation.ErrSourceChanged) {
		result.MinimumAdministrativeReady = false
		return result, errors.Join(ErrPrepareSourceCheck, captureErr)
	}
	var shared *plugininstallation.SettingsFailure
	if errors.As(captureErr, &shared) {
		owned := *shared
		if shared.Path != nil {
			path := *shared.Path
			owned.Path = &path
		}
		if shared.Location != nil {
			location := *shared.Location
			owned.Location = &location
		}
		result.SettingsFailure = &owned
	}
	result.Installations = append(result.Installations, rows...)
	byName := make(map[string]plugininstallation.Installation, len(rows))
	allReady := len(rows) == len(requirements)
	for _, row := range rows {
		byName[row.Name] = row
		allReady = allReady && row.Status == "verified"
	}
	canonical, canonicalErr := configurationCanonicalDependencyChecks(ctx, pair, model, plugins, byName)
	captureErr = errors.Join(captureErr, canonicalErr)
	for _, check := range checks {
		row := check
		installation, found := byName[prepareDependencyPlugin(check)]
		if row.Reason == "none" {
			if !found {
				if result.SettingsFailure != nil {
					row.Status, row.Reason = "not-attempted", "settings-invalid"
					if result.SettingsFailure.Reason == "settings-unavailable" {
						row.Reason = "settings-unavailable"
					}
				} else {
					row.Status, row.Reason = "unavailable", "unavailable"
				}
			} else {
				row.Status, row.Reason = installation.Status, installation.Reason
				switch row.Reason {
				case "build-incomplete":
					row.Status, row.Reason = "unavailable", "unavailable"
				case "signature-invalid", "record-invalid":
					row.Status, row.Reason = "tampered", "identity-mismatch"
				}
				if row.Status == "verified" {
					wire, verified := installation.WireContract()
					switch {
					case !verified:
						row.Status, row.Reason = "unavailable", "unavailable"
					case installation.Role != row.Role:
						row.Status, row.Reason = "incompatible", "unsupported-protocol"
					case wire.Version != row.ProtocolVersion:
						row.Status, row.Reason = "incompatible", "version-mismatch"
					default:
						digest, _ := installation.ExecutableSHA256()
						text := digest.String()
						row.Artifact = &text
					}
				}
			}
		}
		if row.Status == "verified" && row.Contract == "" {
			contractID, verified := installation.ConfigContractID()
			if !verified {
				row.Status, row.Reason, row.Artifact = "unavailable", "unavailable", nil
			} else {
				row.Contract = strings.Clone(contractID)
			}
		}
		if row.Status == "verified" {
			accepted := canonical[prepareCanonicalDependency{role: row.Role, name: prepareDependencyPlugin(check), semantic: row.Contract}]
			if accepted.refused {
				row.Status, row.Reason = "incompatible", "identity-mismatch"
			} else if accepted.unavailable {
				row.Status, row.Reason = "unavailable", "unavailable"
			}
		}
		allReady = allReady && row.Status == "verified"
		result.Requirements = append(result.Requirements, row)
	}
	slices.SortFunc(result.Requirements, func(a, b PrepareDependencyRequirement) int {
		if prepareRequirementLess(a, b) {
			return -1
		}
		if prepareRequirementLess(b, a) {
			return 1
		}
		return 0
	})
	result.Requirements = compactPrepareRequirements(result.Requirements)
	if len(rows) == len(requirements) && result.SettingsFailure == nil {
		result.Assessment = "complete"
	}
	result.AllDeclaredReady = allReady && captureErr == nil && result.MinimumAdministrativeReady
	if err := pair.CheckUnchanged(ctx); err != nil {
		result.MinimumAdministrativeReady, result.AllDeclaredReady = false, false
		if ctx.Err() != nil {
			return result, errors.Join(captureErr, ctx.Err(), context.Cause(ctx), err)
		}
		return result, errors.Join(ErrPrepareSourceCheck, captureErr, err)
	}
	if errors.Is(captureErr, plugininstallation.ErrSourceChanged) {
		result.MinimumAdministrativeReady, result.AllDeclaredReady = false, false
		return result, errors.Join(ErrPrepareSourceCheck, captureErr)
	}
	if ctx.Err() != nil || errors.Is(captureErr, context.Canceled) || errors.Is(captureErr, context.DeadlineExceeded) {
		result.MinimumAdministrativeReady, result.AllDeclaredReady = false, false
		return result, errors.Join(ctx.Err(), context.Cause(ctx), captureErr)
	}
	return result, captureErr
}

type prepareCanonicalDependency struct{ role, name, semantic string }
type prepareCanonicalAcceptance struct{ refused, unavailable bool }

func configurationCanonicalDependencyChecks(ctx context.Context, pair *configuration.Pair, model *configuration.Model, plugins *configurationInstalledPlugins,
	installations map[string]plugininstallation.Installation) (map[prepareCanonicalDependency]prepareCanonicalAcceptance, error) {
	results := make(map[prepareCanonicalDependency]prepareCanonicalAcceptance)
	generators := make(map[string]*generatorhost.PublicValidator)
	outputs := make(map[string]*outputhost.PublicValidator)
	var resultErr error
	checkSource := func() error {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, context.Cause(ctx))
		}
		if err := pair.CheckUnchanged(ctx); err != nil {
			return errors.Join(plugininstallation.ErrSourceChanged, err)
		}
		return nil
	}
	assess := func(key prepareCanonicalDependency, version uint32, validate func(*plugininstallation.Installed) error) {
		installation, found := installations[key.name]
		wire, verified := installation.WireContract()
		if !found || installation.Status != "verified" || installation.Role != key.role || !verified || wire.Version != version {
			return
		}
		facts := results[key]
		if errors.Is(resultErr, plugininstallation.ErrSourceChanged) || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded) {
			facts.unavailable = true
			results[key] = facts
			return
		}
		err := checkSource()
		if err == nil {
			selected, ok := plugins.lookup(key.name)
			if !ok {
				err = plugininstallation.ErrInstallation
			} else {
				err = validate(selected)
			}
		}
		err = errors.Join(err, checkSource())
		if err != nil {
			if (errors.Is(err, generatorhost.ErrPassiveRefused) || errors.Is(err, outputhost.ErrPassiveRefused) || errors.Is(err, contract.ErrRecord)) && !configurationPluginUnavailable(err) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, plugininstallation.ErrSourceChanged) {
				facts.refused = true
			} else {
				facts.unavailable = true
				resultErr = errors.Join(resultErr, err)
			}
		}
		results[key] = facts
	}
	for _, entry := range model.Entries {
		g := entry.Generated
		if g == nil || g.Plugin == "" || g.Settings != nil {
			continue
		}
		intent, err := generatorprotocol.DecodeIntent(g.Intent)
		if err != nil {
			return results, errors.Join(resultErr, err)
		}
		key := prepareCanonicalDependency{role: "generator", name: g.Plugin, semantic: hex.EncodeToString(intent.ConfigContractID[:])}
		assess(key, uint32(generatorprotocol.Version), func(selected *plugininstallation.Installed) error {
			validator := generators[g.Plugin]
			if validator == nil {
				metadata, err := selected.Metadata()
				if err != nil {
					return err
				}
				installed, err := generatorhost.NewInstallation(metadata, selected.DependencyBytes())
				if err != nil {
					return err
				}
				validator, err = generatorhost.NewPublicValidator(ctx, selected.Executable(), installed)
				if err != nil {
					return err
				}
				generators[g.Plugin] = validator
			}
			return configurationNormalizeGenerator(ctx, validator, generatorprotocol.ID{}, g)
		})
	}
	routes, err := model.OutputTargetEncodings()
	if err != nil {
		return results, errors.Join(resultErr, err)
	}
	for _, binding := range model.Outputs {
		if binding.Plugin == "" || binding.Settings != nil {
			continue
		}
		key := prepareCanonicalDependency{role: "output", name: binding.Plugin, semantic: binding.Binding.Destination.ConfigContractID}
		assess(key, uint32(outputprotocol.Version), func(*plugininstallation.Installed) error {
			validator := outputs[binding.Plugin]
			if validator == nil {
				path, installed, err := configurationOutputArtifact(plugins, binding.Plugin)
				if err != nil {
					return err
				}
				validator, err = outputhost.NewPublicValidator(ctx, path, installed)
				if err != nil {
					return err
				}
				outputs[binding.Plugin] = validator
			}
			deadline, err := configurationPassiveDeadline(ctx)
			if err != nil {
				return err
			}
			if _, err := validator.ValidateCanonical(ctx, outputprotocol.CanonicalRequest{Schema: 1, DeadlineUnixMillis: deadline, Destination: configurationProtocolDestination(binding.Binding.Destination)}); err != nil {
				return err
			}
			at := slices.IndexFunc(model.Public.OutputBindings.Value, func(row contract.PublicOutputBinding) bool { return row.DestinationID == binding.DestinationID })
			if at < 0 {
				return contract.ErrRecord
			}
			offered := model.Public.OutputBindings.Value[at].Targets
			encodings := routes[binding.DestinationID]
			names := slices.Sorted(maps.Keys(encodings))
			if offered.State == contract.PublicPresent && len(offered.Value) != len(names) {
				return contract.ErrRecord
			}
			for i, name := range names {
				if err := checkSource(); err != nil {
					return err
				}
				target, err := configurationInterpretOutput(ctx, validator, binding.Binding.Destination, name, encodings[name])
				if err != nil {
					return err
				}
				if offered.State == contract.PublicPresent && (offered.Value[i].EntryName != name || !target.Equal(configurationCanonicalTarget(offered.Value[i]))) {
					return contract.ErrRecord
				}
			}
			return nil
		})
	}
	return results, resultErr
}

func configurationDependencyChecks(model *configuration.Model) ([]PrepareDependencyRequirement, error) {
	if model == nil || len(model.Entries) > contract.CryptoMaxValueEntries || len(model.Outputs) > contract.MaxOutputBindings {
		return nil, ErrCell
	}
	checks := make([]PrepareDependencyRequirement, 0, len(model.Entries)+len(model.Outputs))
	add := func(role, name, semantic string, version uint32, subject uint16) error {
		row := PrepareDependencyRequirement{Role: role, Contract: strings.Clone(semantic), ProtocolVersion: version, Reason: "none", Subjects: []uint16{subject}}
		if name == "" {
			row.Status, row.Reason = "missing", "selection-required"
		} else {
			if !artifact.ValidPluginID(name) {
				return ErrCell
			}
			owned := strings.Clone(name)
			row.Plugin = &owned
		}
		checks = append(checks, row)
		return nil
	}
	for _, entry := range model.Entries {
		if entry.Generated == nil {
			continue
		}
		g := entry.Generated
		semantic := ""
		if g.Settings == nil {
			intent, err := generatorprotocol.DecodeIntent(g.Intent)
			if err != nil {
				return nil, err
			}
			semantic = hex.EncodeToString(intent.ConfigContractID[:])
		}
		if int(entry.EntrySpan) >= len(model.Spans) || model.Spans[entry.EntrySpan].Kind != configuration.SpanEntry || model.Spans[entry.EntrySpan].Index >= contract.CryptoMaxValueEntries {
			return nil, ErrCell
		}
		if err := add("generator", g.Plugin, semantic, uint32(generatorprotocol.Version), uint16(model.Spans[entry.EntrySpan].Index)); err != nil {
			return nil, err
		}
	}
	for _, binding := range model.Outputs {
		semantic := ""
		if binding.Settings == nil {
			semantic = binding.Binding.Destination.ConfigContractID
		}
		if binding.SourceIndex >= contract.MaxOutputBindings {
			return nil, ErrCell
		}
		if err := add("output", binding.Plugin, semantic, uint32(outputprotocol.Version), binding.SourceIndex); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(checks, func(a, b PrepareDependencyRequirement) int {
		if prepareRequirementLess(a, b) {
			return -1
		}
		if prepareRequirementLess(b, a) {
			return 1
		}
		return 0
	})
	return compactPrepareRequirements(checks), nil
}

func compactPrepareRequirements(rows []PrepareDependencyRequirement) []PrepareDependencyRequirement {
	total := 0
	for _, row := range rows {
		total += len(row.Subjects)
	}
	subjects := make([]uint16, total)
	used, at, groupStart := 0, 0, 0
	for _, row := range rows {
		if used == 0 || prepareRequirementLess(rows[used-1], row) || prepareRequirementLess(row, rows[used-1]) {
			if used != 0 {
				slices.Sort(rows[used-1].Subjects)
			}
			groupStart = at
			copy(subjects[at:], row.Subjects)
			at += len(row.Subjects)
			row.Subjects = subjects[groupStart:at:at]
			rows[used] = row
			used++
		} else {
			copy(subjects[at:], row.Subjects)
			at += len(row.Subjects)
			rows[used-1].Subjects = subjects[groupStart:at:at]
		}
	}
	if used != 0 {
		slices.Sort(rows[used-1].Subjects)
	}
	clear(rows[used:])
	return rows[:used:used]
}

func prepareDependencyArtifact(row PrepareDependencyRequirement) string {
	if row.Artifact == nil {
		return ""
	}
	return *row.Artifact
}

func prepareDependencyPlugin(row PrepareDependencyRequirement) string {
	if row.Plugin == nil {
		return ""
	}
	return *row.Plugin
}

func configurationMinimumAdministrativeReady(model *configuration.Model) bool {
	basis, descriptor, err := configurationPublicBasis(model)
	if err != nil {
		return false
	}
	control, err := basis.ControlCore(model.DomainID, descriptor)
	if err != nil || !contract.PublicKeySelectorValid(model.Provider, control.NormalSigning.KeySelector, true) {
		return false
	}
	if control.Recovery != nil && !contract.PublicKeySelectorValid(model.Provider, control.Recovery.Signing.KeySelector, true) {
		return false
	}
	manifest := CompatibilityManifest()
	store, trust, verifier := false, false, false
	for _, row := range manifest.Constructions {
		if row.Family != model.Provider {
			continue
		}
		store = store || row.Kind == contract.StoreComponentKind
		trust = trust || row.Kind == contract.TrustComponentKind
	}
	for _, row := range manifest.Verifiers {
		if row.Family != model.Provider || row.Parse == nil {
			continue
		}
		if _, err := row.Parse(control.NormalSigning.SPKI); err == nil {
			verifier = true
		}
	}
	return store && trust && verifier
}
