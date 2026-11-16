package core

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

// full_only: false
func TestInstalledConfigurationOwnershipRefusesNestedNames(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	control := f.engine(t, f.selected, nil, nil)
	base := control.installation
	for _, axis := range []string{"groups"} {
		t.Run("apply/"+axis, func(t *testing.T) {
			input := base
			input.PublicConfiguration = base.PublicConfiguration
			name := strings.Repeat("n", 257)
			if axis == "groups" {
				input.PublicConfiguration.Groups = publicPresent([][]string{{name, name}})
			}
			engine, err := NewInstalledApply(input)
			if engine != nil {
				engine.Close()
			}
			if !errors.Is(err, contract.ErrRecordCapacity) || engine != nil {
				t.Fatal("installed apply acquired invalid nested names", err)
			}
		})
	}
	f, delivered, _ := maintenanceObserverFixture(t, ctx, false)
	for _, axis := range []string{"groups"} {
		t.Run("observation/"+axis, func(t *testing.T) {
			input := maintenanceObserverInput(f, delivered, &replacementObservationSource{store: f.env.Store})
			name := strings.Repeat("n", 257)
			if axis == "groups" {
				input.Configuration.Groups = publicPresent([][]string{{name, name}})
			}
			observer, err := NewInstalledMaintenanceObserver(input)
			if observer != nil {
				if closeErr := observer.Close(); closeErr != nil {
					t.Error("observer cleanup", closeErr)
				}
			}
			if !errors.Is(err, contract.ErrRecordCapacity) || observer != nil {
				t.Fatal("installed observer acquired invalid nested names", err)
			}
		})
	}
}

func runConfigurationRecoveryScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	t.Helper()
	if _, known := catalog.ConfigurationRecovery(name); !known || env.ConfigurationRecovery == nil {
		t.Fatal("complete-loss process owner unavailable")
	}
	env.ConfigurationRecovery(t, ctx, env, name)
}
