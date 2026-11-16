package core

import (
	"fmt"
	"net/http"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestCloudflareTaggedRetirementAcknowledgementClosesAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, mode := range []uint8{contract.GeneratedRetirementManual, contract.GeneratedRetirementAuto} {
			t.Run(fmt.Sprintf("recovery=%t/mode=%d", recovery, mode), func(t *testing.T) {
				runCloudflareTaggedRetirement(t, cloudflareRetirementResponse{mode: mode}, recovery)
			})
		}
	}
}

// full_only: false
func TestCloudflareTaggedLateOriginalDeleteAuthenticatesAndClosesWithoutDispatch(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			runCloudflareTaggedRetirement(t, cloudflareRetirementResponse{earlyEOF: true, reason: 8, previous: 2, late: true}, recovery)
		})
	}
}

// full_only: false
func TestCloudflareTaggedRepeatedRetirementResiduePreservesEveryOriginalAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, parked := range []bool{false, true} {
			t.Run(fmt.Sprintf("recovery=%t/parked=%t", recovery, parked), func(t *testing.T) {
				runCloudflareTaggedRetirement(t, cloudflareRetirementResponse{earlyEOF: true, reason: 8, previous: 2, park: parked}, recovery)
			})
		}
	}
}

// full_only: false
func TestCloudflareTaggedRetirementUnknownParksAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for name, response := range map[string]cloudflareRetirementResponse{
			"malformed":            {body: `{"success":`, reason: 5, park: true},
			"rejected":             {status: http.StatusTooManyRequests, body: `{"success":false,"errors":[{"code":9109}],"messages":[],"result":null}`, reason: 7, park: true},
			"early EOF":            {earlyEOF: true, reason: 8, park: true},
			"conflicting identity": {body: `{"success":true,"errors":[],"messages":[],"result":{"id":"99999999999999999999999999999999"}}`, reason: 10, park: true},
		} {
			t.Run(fmt.Sprintf("%s/recovery=%t", name, recovery), func(t *testing.T) {
				runCloudflareTaggedRetirement(t, response, recovery)
			})
		}
	}
}

// full_only: false
func TestCloudflareTaggedRetirementTimeoutParksAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			runCloudflareTaggedRetirement(t, cloudflareRetirementResponse{timeout: true, reason: 9, park: true}, recovery)
		})
	}
}

// full_only: false
func TestCloudflareTaggedActiveRetirementResidueClosesAndReopens(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for name, response := range map[string]cloudflareRetirementResponse{
			"malformed":            {body: `{"success":`, reason: 5},
			"rejected":             {status: http.StatusTooManyRequests, body: `{"success":false,"errors":[{"code":9109}],"messages":[],"result":null}`, reason: 7},
			"early EOF":            {earlyEOF: true, reason: 8},
			"conflicting identity": {body: `{"success":true,"errors":[],"messages":[],"result":{"id":"99999999999999999999999999999999"}}`, reason: 10},
		} {
			t.Run(fmt.Sprintf("%s/recovery=%t", name, recovery), func(t *testing.T) {
				runCloudflareTaggedRetirement(t, response, recovery)
			})
		}
	}
}

// full_only: false
func TestCloudflareTaggedDeletingHazardCleanupClosesAndRetainsUnknownInbox(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			runCloudflareTaggedRetirement(t, cloudflareRetirementResponse{earlyEOF: true, reason: 8, cleanupResidue: true}, recovery)
		})
	}
}

func runCloudflareTaggedRetirement(t *testing.T, response cloudflareRetirementResponse, recovery bool) {
	env, _ := genesisEnvironment(t, contract.GCP, recovery)
	freshCurrent := env.FreshCurrent
	env = syntheticAuthorityScenarioEnvironment(t, env)
	env.FreshCurrent = freshCurrent
	runCloudflareTaggedRetirementScenario(t, t.Context(), env, response)
}

// full_only: false
func TestCloudflareTaggedOrdinaryCleanupClosesSource0AndSource2(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, sourceMode := range []uint8{0, 2} {
			t.Run(fmt.Sprintf("recovery=%t/source=%d", recovery, sourceMode), func(t *testing.T) {
				runCloudflareTaggedCleanup(t, cloudflareCleanupScenario{sourceMode: sourceMode, replaceCurrent: sourceMode == 2}, recovery)
			})
		}
	}
}

// full_only: false
func TestCloudflareTaggedOrdinaryCleanupRepeatedAmbiguityCloses(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			runCloudflareTaggedCleanup(t, cloudflareCleanupScenario{sourceMode: 2, ambiguitiesPerOwner: 2}, recovery)
		})
	}
}

func runCloudflareTaggedCleanup(t *testing.T, scenario cloudflareCleanupScenario, recovery bool) {
	env, _ := genesisEnvironment(t, contract.GCP, recovery)
	freshCurrent := env.FreshCurrent
	env = syntheticAuthorityScenarioEnvironment(t, env)
	env.FreshCurrent = freshCurrent
	runCloudflareTaggedCleanupScenario(t, t.Context(), env, scenario)
}
