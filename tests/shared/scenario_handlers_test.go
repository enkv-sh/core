package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

type scenarioHandler func(testing.TB, context.Context, fixtureEnvironment, string)

type scenarioHandlerRegistration struct {
	family catalog.ScenarioFamily
	names  []string
}

var declaredScenarioHandlers = []scenarioHandlerRegistration{
	{family: catalog.FamilyState, names: []string{
		"state.identical-input-keeps-current-state/members_32",
		"state.single-value-update-preserves-other-values/members_1",
		"state.single-value-update-preserves-other-values/members_2",
		"state.single-value-update-preserves-other-values/members_3",
		"state.single-value-update-preserves-other-values/members_4",
		"state.single-value-update-preserves-other-values/members_5",
		"state.single-value-update-preserves-other-values/members_6",
		"state.single-value-update-preserves-other-values/members_7",
		"state.single-value-update-preserves-other-values/members_8",
		"state.single-value-update-preserves-other-values/members_9",
		"state.single-value-update-preserves-other-values/members_10",
		"state.single-value-update-preserves-other-values/members_11",
		"state.single-value-update-preserves-other-values/members_12",
		"state.single-value-update-preserves-other-values/members_13",
		"state.single-value-update-preserves-other-values/members_14",
		"state.single-value-update-preserves-other-values/members_15",
		"state.single-value-update-preserves-other-values/members_16",
		"state.single-value-update-preserves-other-values/members_17",
		"state.single-value-update-preserves-other-values/members_18",
		"state.single-value-update-preserves-other-values/members_19",
		"state.single-value-update-preserves-other-values/members_20",
		"state.single-value-update-preserves-other-values/members_21",
		"state.single-value-update-preserves-other-values/members_22",
		"state.single-value-update-preserves-other-values/members_23",
		"state.single-value-update-preserves-other-values/members_24",
		"state.single-value-update-preserves-other-values/members_25",
		"state.single-value-update-preserves-other-values/members_26",
		"state.single-value-update-preserves-other-values/members_27",
		"state.single-value-update-preserves-other-values/members_28",
		"state.single-value-update-preserves-other-values/members_29",
		"state.single-value-update-preserves-other-values/members_30",
		"state.single-value-update-preserves-other-values/members_31",
		"state.single-value-update-preserves-other-values/members_32",
		"state.single-value-update-preserves-other-values/members_33",
		"state.single-value-update-preserves-other-values/members_34",
		"state.single-value-update-preserves-other-values/members_35",
		"state.single-value-update-preserves-other-values/members_36",
		"state.single-value-update-preserves-other-values/members_37",
		"state.single-value-update-preserves-other-values/members_38",
		"state.single-value-update-preserves-other-values/members_39",
		"state.single-value-update-preserves-other-values/members_40",
		"state.single-value-update-preserves-other-values/members_41",
		"state.single-value-update-preserves-other-values/members_42",
		"state.single-value-update-preserves-other-values/members_43",
		"state.single-value-update-preserves-other-values/members_44",
		"state.single-value-update-preserves-other-values/members_45",
		"state.single-value-update-preserves-other-values/members_46",
		"state.single-value-update-preserves-other-values/members_47",
		"state.single-value-update-preserves-other-values/members_48",
		"state.single-value-update-preserves-other-values/members_49",
		"state.single-value-update-preserves-other-values/members_50",
		"state.single-value-update-preserves-other-values/members_51",
		"state.single-value-update-preserves-other-values/members_52",
		"state.single-value-update-preserves-other-values/members_53",
		"state.single-value-update-preserves-other-values/members_54",
		"state.single-value-update-preserves-other-values/members_55",
		"state.single-value-update-preserves-other-values/members_56",
		"state.single-value-update-preserves-other-values/members_57",
		"state.single-value-update-preserves-other-values/members_58",
		"state.single-value-update-preserves-other-values/members_59",
		"state.single-value-update-preserves-other-values/members_60",
		"state.single-value-update-preserves-other-values/members_61",
		"state.single-value-update-preserves-other-values/members_62",
		"state.single-value-update-preserves-other-values/members_63",
		"state.single-value-update-preserves-other-values/members_64",
		"state.transient-before-send-rerun/one_value_before_send",
		"state.same-page-updates-preserve-other-pages/members_32_same_page",
		"state.cross-page-updates-preserve-other-values/members_32_cross_page",
		"selection.concurrent-writers-select-one-complete-state/members_32_two_writers",
		"storage.equal-immutable-objects-allow-selection/members_32_equal_objects",
		"storage.conflicting-immutable-object-refuses-selection/members_32_conflict",
		"state.historical-bytes-get-new-identities/members_32_three_generations",
		"evidence.missing-selected-child-prevents-open/members_32_missing_page",
		"evidence.corrupt-selected-child-prevents-open/members_32_corrupt_page",
		"selection.prepared-candidate-keeps-current-state/members_32_prepared_only",
		"selection.selected-candidate-survives-fresh-open/members_32_selected",
		"storage.lost-create-reply-recovers-from-readback/members_32_lost_create_reply",
		"selection.lost-head-reply-recovers-from-observation/members_32_lost_head_reply",
		"capacity.compact-state-preserves-complete-update/members_64_compact",
		"capacity.fragmented-state-preserves-complete-update/members_64_fragmented",
		"capacity.maximum-member-count-preserves-complete-update/members_512_mixed_sizes",
		"capacity.maximum-size-state-refuses-growth-and-allows-update/members_512_value_16kib",
		"lifecycle.empty-state-preserves-domain-and-readd/empty_add17_remove_readd",
		"lifecycle.mixed-membership-preserves-retained-records/members_32_mixed_changes",
		"capacity.maximum-disjoint-replacement-reuses-successor-slots/members_512_names_256bytes_values_128x64kib",
	}},
	{family: catalog.FamilyFirstSelection, names: []string{
		"genesis.empty-domain-reopens/empty_genesis",
		"secret.empty-domain-first-selection-survives-restart/genesis_first_shared_secret",
		"secret.authority-only-survives-restart/plain_neighbor_authority_secret",
		"secret.shared-reader-survives-restart/plain_neighbor_shared_secret",
		"secret.provider-refuses-reader/plain_neighbor_denied_reader",
	}},
	{family: catalog.FamilySuppliedLifecycle, names: []string{"secret.complete-supplied-lifecycle-preserves-material/plain17_secret2_full_lifecycle"}},
	{family: catalog.FamilySuppliedSharing, names: []string{"secret.complete-supplied-sharing-preserves-current-access/plain1_secret1_grant_exclude"}},
	{family: catalog.FamilySuppliedAtomic, names: []string{"secret.competing-supplied-candidates-preserve-atomic-outcomes/plain2_secret2_competing_and_lost_reply"}},
	{family: catalog.FamilyReaderReplacement, names: []string{"access.reader-replacement-preserves-current-material/plain1_shared_secret_reader_successor"}},
	{family: catalog.FamilyState, names: []string{
		"access.observer-sees-selected-state/members_32_observer",
		"access.distinct-observer-sees-selected-state/members_32_distinct_observer",
		"access.provider-refuses-observer/members_32_denied_observer",
	}},
	{family: catalog.FamilyAuthorityReplacement, names: []string{
		"access.normal-signer-k2-zero-material/plain1_no_current_secret",
		"access.normal-signer-k2-current-material/plain1_secret1_exact_successor",
		"access.normal-signer-k3-zero-material/plain1_no_current_secret",
		"access.normal-signer-k3-current-material/plain1_secret1_exact_successor",
		"access.normal-kek-k2-zero-material/plain1_no_current_secret",
		"access.normal-kek-k2-current-material/plain1_secret1_exact_successor",
		"access.normal-kek-k3-zero-material/plain1_no_current_secret",
		"access.normal-kek-k3-current-material/plain1_secret1_exact_successor",
		"access.normal-combined-k2-zero-material/plain1_no_current_secret",
		"access.normal-combined-k2-current-material/plain1_secret1_exact_successor",
		"access.normal-combined-k3-zero-material/plain1_no_current_secret",
		"access.normal-combined-k3-current-material/plain1_secret1_exact_successor",
		"access.recovery-signer-k2-zero-material/plain1_no_current_secret",
		"access.recovery-signer-k2-current-material/plain1_secret1_exact_successor",
		"access.recovery-signer-k3-zero-material/plain1_no_current_secret",
		"access.recovery-signer-k3-current-material/plain1_secret1_exact_successor",
		"access.recovery-kek-k2-zero-material/plain1_no_current_secret",
		"access.recovery-kek-k2-current-material/plain1_secret1_exact_successor",
		"access.recovery-kek-k3-zero-material/plain1_no_current_secret",
		"access.recovery-kek-k3-current-material/plain1_secret1_exact_successor",
		"access.recovery-combined-k2-zero-material/plain1_no_current_secret",
		"access.recovery-combined-k2-current-material/plain1_secret1_exact_successor",
		"access.recovery-combined-k3-zero-material/plain1_no_current_secret",
		"access.recovery-combined-k3-current-material/plain1_secret1_exact_successor",
		"access.reciprocal-authority-zero-material/plain1_no_current_secret",
		"access.reciprocal-authority-current-material/plain1_secret1_exact_successor",
	}},
	{family: catalog.FamilyGeneratedHistory, names: []string{
		"accepted.source-mode0-late-result/source0_late_result",
		"accepted.source-mode1-late-result/source1_late_result",
		"accepted.source-mode2-late-result/source2_late_result",
		"accepted.same-value-reader-union/source2_late_result_reader_union",
		"accepted.source-mode0-reciprocal-loss/source0_four_replacements_late_result",
		"accepted.source-mode1-reciprocal-loss/source1_four_replacements_late_result",
		"accepted.source-mode2-reciprocal-loss/source2_four_replacements_late_result",
	}},
	{family: catalog.FamilyCombinedHistory, names: []string{"history.secret-lifecycle-and-recovery/plain1_secret1_reader_and_authority_history"}},
	{family: catalog.FamilyGeneratedApply, names: []string{"generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2"}},
	{family: catalog.FamilyGeneratedRetirement, names: []string{
		"generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack",
		"generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack",
		"generated.active-retirement-residue/one_current_one_retiring_manual_active_unknown",
		"generated.parked-retirement-residue/one_current_one_retiring_manual_parked_unknown",
		"generated.conflicting-retirement-stays-open/one_current_one_retiring_manual_conflict",
	}},
	{family: catalog.FamilyGeneratedCleanup, names: []string{
		"generated.cleanup-source0-closes/failed_two_create_source0_ack",
		"generated.cleanup-source2-closes/failed_two_create_source2_current_replacement",
		"generated.cleanup-repeated-ambiguity-closes/failed_two_create_source2_two_unknown_then_ack",
		"generated.cleanup-detached-hazard-closes/failed_two_create_detached_hazard",
		"generated.cleanup-deleting-hazard-closes/one_current_one_retiring_manual_eof_then_cleanup_ack",
	}},
	{family: catalog.FamilyAuthorityOperator, names: catalog.AuthorityOperatorLiveNames()},
	{family: catalog.FamilyConfigurationRecovery, names: catalog.ConfigurationRecoveryNames()},
	{family: catalog.FamilyPublication, names: append(catalog.PublicationNames(), catalog.LivePublicationNames()...)},
}

func runStateScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	t.Helper()
	handlers, err := scenarioHandlerIndex(declaredScenarioHandlers)
	if err != nil {
		t.Fatal(err)
	}
	handler, known := handlers[name]
	if !known {
		t.Fatal("unknown scenario")
	}
	handler(t, ctx, env, name)
}

func scenarioHandlerIndex(registrations []scenarioHandlerRegistration) (map[string]scenarioHandler, error) {
	var declared []string
	for _, name := range catalog.Names() {
		definition, known := catalog.DefinitionFor(name)
		if !known || len(definition.Modes) == 0 {
			return nil, fmt.Errorf("unknown scenario declaration: %s", name)
		}
		execution, known := catalog.ExecutionFor(name, definition.Modes[0])
		if !known {
			return nil, fmt.Errorf("scenario execution unavailable: %s", name)
		}
		if execution.Family != catalog.FamilyPublicConfiguration {
			declared = append(declared, name)
		}
	}
	if len(registrations) == 0 {
		return nil, errors.New("scenario handler registry is empty")
	}
	handlers := make(map[string]scenarioHandler, len(declared))
	position := 0
	for _, registration := range registrations {
		handler := scenarioHandlerForFamily(registration.family)
		if handler == nil || len(registration.names) == 0 {
			return nil, errors.New("scenario handler registration is incomplete")
		}
		for _, name := range registration.names {
			if position >= len(declared) || declared[position] != name {
				return nil, fmt.Errorf("scenario handler order differs at %d: %q", position, name)
			}
			if _, duplicate := handlers[name]; duplicate {
				return nil, fmt.Errorf("duplicate scenario handler: %s", name)
			}
			definition, known := catalog.DefinitionFor(name)
			if !known || len(definition.Modes) == 0 {
				return nil, fmt.Errorf("unknown scenario handler: %s", name)
			}
			execution, known := catalog.ExecutionFor(name, definition.Modes[0])
			if !known || execution.Family != registration.family {
				return nil, fmt.Errorf("scenario handler family differs: %s", name)
			}
			handlers[name] = handler
			position++
		}
	}
	if position != len(declared) {
		return nil, fmt.Errorf("scenario handlers cover %d of %d declarations", position, len(declared))
	}
	return handlers, nil
}

func scenarioHandlerForFamily(family catalog.ScenarioFamily) scenarioHandler {
	switch family {
	case catalog.FamilyState:
		return runOrdinaryStateScenario
	case catalog.FamilyFirstSelection:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
			runFirstFlowScenario(t, ctx, env, name)
		}
	case catalog.FamilySuppliedLifecycle:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, _ string) {
			runSuppliedLifecycleScenario(t, ctx, env)
		}
	case catalog.FamilySuppliedSharing:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, _ string) {
			runSuppliedSharingScenario(t, ctx, env)
		}
	case catalog.FamilySuppliedAtomic:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, _ string) {
			runSuppliedAtomicScenario(t, ctx, env)
		}
	case catalog.FamilyReaderReplacement:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, _ string) {
			runReaderReplacementScenario(t, ctx, env)
		}
	case catalog.FamilyAuthorityReplacement:
		return runDeclaredAuthorityScenario
	case catalog.FamilyGeneratedHistory:
		return runDeclaredGeneratedHistoryScenario
	case catalog.FamilyCombinedHistory:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, _ string) {
			runGeneratedCombinedLifecycleRecoveryScenario(t, ctx, env)
		}
	case catalog.FamilyGeneratedApply:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, _ string) {
			runGeneratedWholeSetScenario(t, ctx, env, true, false, 0, nil)
		}
	case catalog.FamilyGeneratedRetirement:
		return runDeclaredGeneratedRetirementScenario
	case catalog.FamilyGeneratedCleanup:
		return runDeclaredGeneratedCleanupScenario
	case catalog.FamilyConfigurationRecovery:
		return runConfigurationRecoveryScenario
	case catalog.FamilyPublication:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
			if _, live := catalog.LivePublication(name); live {
				if env.LivePublication == nil {
					t.Fatal("named publication fixture unavailable")
				}
				env.LivePublication(t, ctx, env, name)
				return
			}
			runPublicationScenario(t, ctx, env, name)
		}
	case catalog.FamilyAuthorityOperator:
		return func(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
			if env.AuthorityOperator == nil {
				t.Fatal("production Authority operator fixture unavailable")
			}
			env.AuthorityOperator(t, ctx, env, name)
		}
	}
	return nil
}

func runDeclaredAuthorityScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	replacement, known := catalog.AuthorityReplacement(name)
	if !known {
		t.Fatal("authority replacement declaration unavailable")
	}
	runAuthorityScenario(t, ctx, env, replacement)
}

func runDeclaredGeneratedHistoryScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	history, known := catalog.GeneratedHistory(name)
	if !known {
		t.Fatal("generated history declaration unavailable")
	}
	runGeneratedHistoryScenario(t, ctx, env, history)
}

func runDeclaredGeneratedRetirementScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	if env.GeneratedProcess != nil {
		if name != "generated.retirement-acknowledgement-closes/one_current_one_retiring_manual_ack" && name != "generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack" {
			t.Fatal("live generated process does not cover this retirement scenario")
		}
		runLiveGeneratedRetirementScenario(t, ctx, env, name == "generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack")
		return
	}
	response := cloudflareRetirementResponse{}
	switch name {
	case "generated.auto-retirement-acknowledgement-closes/one_current_one_retiring_auto_ack":
		response.mode = contract.GeneratedRetirementAuto
	case "generated.active-retirement-residue/one_current_one_retiring_manual_active_unknown":
		response = cloudflareRetirementResponse{body: `{"success":`, reason: 5}
	case "generated.parked-retirement-residue/one_current_one_retiring_manual_parked_unknown":
		response = cloudflareRetirementResponse{status: 429, body: `{"success":false,"errors":[{"code":9109}],"messages":[],"result":null}`, reason: 7, park: true}
	case "generated.conflicting-retirement-stays-open/one_current_one_retiring_manual_conflict":
		response = cloudflareRetirementResponse{body: `{"success":true,"errors":[],"messages":[],"result":{"id":"99999999999999999999999999999999"}}`, reason: 10, park: true}
	}
	runCloudflareTaggedRetirementScenario(t, ctx, env, response)
}

func runDeclaredGeneratedCleanupScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, name string) {
	if name == "generated.cleanup-deleting-hazard-closes/one_current_one_retiring_manual_eof_then_cleanup_ack" {
		runCloudflareTaggedRetirementScenario(t, ctx, env, cloudflareRetirementResponse{earlyEOF: true, reason: 8, cleanupResidue: true})
		return
	}
	scenario := cloudflareCleanupScenario{}
	switch name {
	case "generated.cleanup-source2-closes/failed_two_create_source2_current_replacement":
		scenario.sourceMode, scenario.replaceCurrent = 2, true
	case "generated.cleanup-repeated-ambiguity-closes/failed_two_create_source2_two_unknown_then_ack":
		scenario.sourceMode, scenario.ambiguitiesPerOwner = 2, 2
	case "generated.cleanup-detached-hazard-closes/failed_two_create_detached_hazard":
		scenario.detachHazard = true
	}
	runCloudflareTaggedCleanupScenario(t, ctx, env, scenario)
}

func cloneScenarioHandlerRegistrations(registrations []scenarioHandlerRegistration) []scenarioHandlerRegistration {
	cloned := make([]scenarioHandlerRegistration, len(registrations))
	for index, registration := range registrations {
		cloned[index] = scenarioHandlerRegistration{family: registration.family, names: append([]string(nil), registration.names...)}
	}
	return cloned
}

// full_only: false
func TestScenarioHandlersExactlyMatchCatalog(t *testing.T) {
	handlers, err := scenarioHandlerIndex(declaredScenarioHandlers)
	if err != nil {
		t.Fatal("scenario handlers do not match their catalog ownership", err)
	}
	shared := 0
	for _, name := range catalog.Names() {
		if _, public := catalog.PublicConfiguration(name); public {
			if handlers[name] != nil {
				t.Fatal("public CLI scenario has a shared fixture handler", name)
			}
			t.Run(name, func(t *testing.T) {
				env := fixtureEnvironment{Phase: func(string) { panic("fixture phase entered") }}
				defer func() {
					if got := recover(); got != scenarioFixtureRefusal("unknown scenario") {
						t.Fatalf("public scenario fixture refusal = %v, want unknown scenario", got)
					}
				}()
				runStateScenario(scenarioFixtureRefusalTB{TB: t}, t.Context(), env, name)
			})
			continue
		}
		shared++
		if handlers[name] == nil {
			t.Fatal("shared scenario has no fixture handler", name)
		}
	}
	if len(handlers) != shared {
		t.Fatal("scenario handlers do not exactly match shared catalog", len(handlers), shared)
	}

	for _, damage := range []string{"missing", "unknown", "duplicate", "reordered", "wrong-family"} {
		t.Run(damage, func(t *testing.T) {
			registrations := cloneScenarioHandlerRegistrations(declaredScenarioHandlers)
			switch damage {
			case "missing":
				registrations[len(registrations)-1].names = registrations[len(registrations)-1].names[:len(registrations[len(registrations)-1].names)-1]
			case "unknown":
				registrations[0].names[0] = "unknown"
			case "duplicate":
				registrations[0].names[1] = registrations[0].names[0]
			case "reordered":
				registrations[0].names[0], registrations[0].names[1] = registrations[0].names[1], registrations[0].names[0]
			case "wrong-family":
				registrations[0].family = catalog.FamilyFirstSelection
			}
			if _, err := scenarioHandlerIndex(registrations); err == nil {
				t.Fatal("damaged scenario handler registry passed")
			}
		})
	}
}

// A refused declaration must stop before the first fixture phase. Capturing only
// Fatal keeps this control in-process without constructing a Product fixture.
type scenarioFixtureRefusalTB struct{ testing.TB }

type scenarioFixtureRefusal string

func (t scenarioFixtureRefusalTB) Fatal(args ...any) {
	panic(scenarioFixtureRefusal(fmt.Sprint(args...)))
}

// full_only: false
func TestScenarioFixtureParametersBelongToNamedScenario(t *testing.T) {
	for _, members := range []int{1, 2, 16, 32, 64} {
		t.Run(fmt.Sprintf("point/members_%d", members), func(t *testing.T) {
			env := memoryScenarioEnvironment(t)
			fresh := env.FreshCurrent
			reopened := 0
			env.FreshCurrent = func(tb testing.TB, admission OpenContext, selected *StateSession) {
				inputs := selected.currentEntryInputs()
				if len(inputs) != members {
					tb.Fatalf("point fixture has %d members, want %d", len(inputs), members)
				}
				for index, input := range inputs {
					want := []byte{byte(index)}
					if index == 0 {
						want = append(want, 99)
					}
					if input.Name != fmt.Sprintf("member-%03d", index) || !bytes.Equal(input.InputBytes, want) {
						tb.Fatal("point fixture differs from independently defined names and values")
					}
				}
				fresh(tb, admission, selected)
				reopened++
			}
			runStateScenario(t, t.Context(), env, fmt.Sprintf("state.single-value-update-preserves-other-values/members_%d", members))
			if reopened != 1 {
				t.Fatal("point fixture was not checked in a joined fresh process")
			}
		})
	}
	for _, name := range []string{
		"access.observer-sees-selected-state/members_32_observer",
		"access.distinct-observer-sees-selected-state/members_32_distinct_observer",
		"access.provider-refuses-observer/members_32_denied_observer",
	} {
		for _, members := range []int{1, 64} {
			t.Run(fmt.Sprintf("%s/members_%d", strings.SplitN(name, "/", 2)[0], members), func(t *testing.T) {
				const entered = "fixture phase entered"
				env := fixtureEnvironment{
					Store:  &memoryStore{},
					Trust:  &fixtureTrust{},
					Put:    func(context.Context, string, []byte) error { t.Fatal("unexpected fixture write"); return nil },
					Delete: func(context.Context, string) error { t.Fatal("unexpected fixture delete"); return nil },
					Phase:  func(string) { panic(entered) },
				}
				defer func() {
					got := recover()
					want := scenarioFixtureRefusal("unknown scenario")
					if got != want {
						t.Fatalf("named scenario fixture refusal = %v, want %v", got, want)
					}
				}()
				runStateScenario(scenarioFixtureRefusalTB{TB: t}, t.Context(), env, fmt.Sprintf("%s/members_%d", strings.SplitN(name, "/", 2)[0], members))
			})
		}
	}
}
