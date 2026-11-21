package compositionfull

import (
	"os"
	"slices"
	"strconv"
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/sdk/artifact"
)

// ConfigurationComparisonResult keeps local source preferences outside Core's
// authenticated domain comparison.
type ConfigurationComparisonResult struct {
	core.PublicComparisonResult
	SourceFailure            *ConfigurationSourceFailure
	InstallationRequirements InstallationRequirementComparison
}

type ConfigurationPlanningResult struct {
	core.PlanningResult
	displayFile              os.FileInfo
	SourceFailure            *ConfigurationSourceFailure
	InstallationRequirements InstallationRequirementComparison
}

type InstallationRequirement struct {
	Version string `json:"version,omitempty"`
}

type InstallationRequirementDifference struct {
	Name      string                   `json:"name"`
	Trusted   *InstallationRequirement `json:"trusted"`
	Candidate *InstallationRequirement `json:"candidate"`
}

type InstallationRequirementComparison struct {
	Complete    bool                                `json:"complete"`
	Differences []InstallationRequirementDifference `json:"differences"`
}

const (
	configurationSelectionLimit             = 64
	configurationRequirementDifferenceLimit = 2 * configurationSelectionLimit
	configurationRequirementRowLimit        = 1024
	configurationRequirementResultAllowance = configurationRequirementDifferenceLimit*configurationRequirementRowLimit + 8 + 128
)

func configurationPluginRequirement(model *configuration.Model, name string) plugininstallation.Requirement {
	row := plugininstallation.Requirement{Name: strings.Clone(name)}
	if model != nil {
		for _, requirement := range model.Plugins {
			if requirement.Name == name {
				row.Version = strings.Clone(requirement.Version)
				break
			}
		}
	}
	return row
}

func configurationPluginRequirements(model *configuration.Model) ([]plugininstallation.Requirement, error) {
	if model == nil || len(model.Plugins) > configurationSelectionLimit {
		return nil, ErrCell
	}
	names := map[string]bool{}
	add := func(name string) error {
		if name == "" {
			return nil
		}
		if !artifact.ValidPluginID(name) {
			return ErrCell
		}
		names[name] = true
		if len(names) > configurationSelectionLimit {
			return ErrCell
		}
		return nil
	}
	for _, entry := range model.Entries {
		if entry.Generated != nil {
			if err := add(entry.Generated.Plugin); err != nil {
				return nil, err
			}
		}
	}
	for _, binding := range model.Outputs {
		if err := add(binding.Plugin); err != nil {
			return nil, err
		}
	}
	explicit := map[string]bool{}
	for _, row := range model.Plugins {
		if !artifact.ValidPluginID(row.Name) || explicit[row.Name] || row.Version != "" && !artifact.ValidVersion(row.Version) {
			return nil, ErrCell
		}
		if err := add(row.Name); err != nil {
			return nil, err
		}
		explicit[row.Name] = true
	}
	rows := make([]plugininstallation.Requirement, 0, len(names))
	for name := range names {
		rows = append(rows, configurationPluginRequirement(model, name))
	}
	slices.SortFunc(rows, func(a, b plugininstallation.Requirement) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func compareConfigurationRequirements(trusted, candidate *configuration.Model) InstallationRequirementComparison {
	out := InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}
	before, err := configurationPluginRequirements(trusted)
	if err != nil {
		return out
	}
	after, err := configurationPluginRequirements(candidate)
	if err != nil {
		return out
	}
	for i, j := 0, 0; i < len(before) || j < len(after); {
		var row InstallationRequirementDifference
		switch {
		case j == len(after) || i < len(before) && before[i].Name < after[j].Name:
			row.Name, row.Trusted = before[i].Name, &InstallationRequirement{Version: before[i].Version}
			i++
		case i == len(before) || after[j].Name < before[i].Name:
			row.Name, row.Candidate = after[j].Name, &InstallationRequirement{Version: after[j].Version}
			j++
		default:
			if before[i].Version != after[j].Version {
				row = InstallationRequirementDifference{Name: before[i].Name, Trusted: &InstallationRequirement{Version: before[i].Version}, Candidate: &InstallationRequirement{Version: after[j].Version}}
			}
			i++
			j++
		}
		if row.Name != "" {
			out.Differences = append(out.Differences, row)
		}
	}
	out.Complete = true
	return out
}

func validInstallationRequirementComparison(value InstallationRequirementComparison) bool {
	if value.Differences == nil || len(value.Differences) > configurationRequirementDifferenceLimit || !value.Complete && len(value.Differences) != 0 {
		return false
	}
	for i, row := range value.Differences {
		if !artifact.ValidPluginID(row.Name) || i > 0 && value.Differences[i-1].Name >= row.Name || row.Trusted == nil && row.Candidate == nil {
			return false
		}
		for _, side := range []*InstallationRequirement{row.Trusted, row.Candidate} {
			if side != nil && side.Version != "" && !artifact.ValidVersion(side.Version) {
				return false
			}
		}
		if row.Trusted != nil && row.Candidate != nil && row.Trusted.Version == row.Candidate.Version {
			return false
		}
	}
	return true
}

func renderInstallationRequirementComparison(w *readerResultWriter, value InstallationRequirementComparison, human bool) {
	if human {
		status := "incomplete"
		if value.Complete {
			status = "complete"
		}
		w.literal("Local plugin selection comparison: " + status + "; " + strconv.Itoa(len(value.Differences)) + " differences.\n")
		for _, row := range value.Differences {
			w.literal("  Plugin ")
			w.comparisonHumanString(row.Name)
			for _, side := range []struct {
				label string
				value *InstallationRequirement
			}{{"trusted", row.Trusted}, {"candidate", row.Candidate}} {
				w.literal("; " + side.label + " ")
				if side.value == nil {
					w.literal("absent")
				} else if side.value.Version == "" {
					w.literal("selected without a version pin")
				} else {
					w.comparisonHumanString(side.value.Version)
				}
			}
			w.literal("\n")
		}
		return
	}
	w.literal(`,"installation_requirements":`)
	w.literal(`{"complete":`)
	if value.Complete {
		w.literal("true")
	} else {
		w.literal("false")
	}
	w.literal(`,"differences":[`)
	for i, row := range value.Differences {
		if i != 0 {
			w.literal(",")
		}
		w.json(row, configurationRequirementRowLimit)
	}
	w.literal("]}")
}
