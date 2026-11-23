package main

import (
	"errors"
	"slices"

	records "enkv.sh/core/internal/testrecords"
)

const dailyRetirementSuite = "daily-retirement-browser-login"

func validateDailyRetirementSelection(suites, scenarios []string, environment environmentFile) error {
	daily := environment.PluginAcceptance != nil && environment.PluginAcceptance.DailyRolePrefix != ""
	selected := slices.Contains(suites, dailyRetirementSuite)
	if !daily && !selected {
		return nil
	}
	if !daily || !selected || len(suites) != 1 ||
		!slices.Equal(scenarios, []string{records.StockPluginScenario}) || environment.Mode != "live" ||
		environment.Provider != "aws" || environment.PluginAcceptance.Validate() != nil {
		return errors.New("daily browser login requires its exclusive retirement suite and AWS fixture")
	}
	return nil
}
