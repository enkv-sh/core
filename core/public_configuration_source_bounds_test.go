package core

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicConfigurationNestedNamesRefuseBeforeOwnership(t *testing.T) {
	for _, axis := range []string{"groups"} {
		for _, name := range []string{strings.Repeat("n", 257), strings.Repeat("é", 129), string([]byte{0xff})} {
			t.Run(axis+"/"+strconv.Itoa(len(name)), func(t *testing.T) {
				input := publicConfigurationFixture(t)
				if axis == "groups" {
					input.Groups = publicPresent([][]string{{name, name}})
				}
				// Both occurrences share their input backing; each clone would
				// acquire another complete name at the ownership boundary.
				if publicConfigurationBounded(input) {
					t.Error("nested name reached the shared ownership admission")
				}
				if digest, err := PlanningInputDigest(input, nil); !errors.Is(err, contract.ErrRecordCapacity) || !digest.IsZero() {
					t.Error("planning digest captured invalid nested name", err)
				}
				planner := &InstalledPlanning{reader: &ReaderEngine{expectedDomain: contract.Hash([]byte("nested name admission domain"))}}
				planned := planner.Plan(context.Background(), contract.Hash([]byte("nested name admission request")), input, nil, contract.PlanningOptions{Purpose: contract.PlanningEquality})
				if len(planned.Diagnostics) != 1 || planned.Diagnostics[0].Reason != contract.ReasonLimitExceeded {
					t.Error("planning invocation reached captured-source identity checks", planned.Diagnostics)
				}
				calls, generators := 0, 0
				validator := publicFixtureValidator(t, &calls, &generators)
				got := validator.Validate(context.Background(), input)
				if got.Valid || got.Complete || calls != 0 || generators != 0 || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) {
					t.Fatal("validator captured invalid nested name or reached an interpreter", got.Diagnostics)
				}
				subject, field := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldGroups
				reason := contract.ReasonLimitExceeded
				if !utf8.ValidString(name) {
					reason = contract.ReasonInvalidUTF8
				}
				want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticUnable, Reason: reason}}
				if !reflect.DeepEqual(got.Diagnostics, want) {
					t.Fatal("nested name diagnostic changed reason or field", got.Diagnostics)
				}
			})
		}
	}
}

// full_only: false
func TestPublicConfigurationNestedNameCountsAndMaximumBytes(t *testing.T) {
	input := publicConfigurationFixture(t)
	maximum := strings.Repeat("é", 128)
	group := make([]string, 512)
	for i := range group {
		group[i] = maximum
	}
	input.Groups = publicPresent([][]string{group})
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("a"), publicFixtureBinding("b")})
	// This checks capacity before relation validation. Duplicate names do not
	// become valid group semantics through this admission.
	if !publicConfigurationBounded(input) {
		t.Fatal("bounded maximum nested occurrences refused")
	}
	for _, axis := range []string{"group-count", "group-members"} {
		t.Run(axis, func(t *testing.T) {
			offered := input
			offered.OutputBindings.Value = append([]contract.PublicOutputBinding(nil), input.OutputBindings.Value...)
			switch axis {
			case "group-count":
				offered.Groups = publicPresent(make([][]string, 513))
			case "group-members":
				offered.Groups = publicPresent([][]string{append(append([]string(nil), group...), maximum)})
			}
			if publicConfigurationBounded(offered) {
				t.Fatal("excess nested occurrences reached ownership")
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationSourceOuterAxesPrecedeTraversal(t *testing.T) {
	for _, axis := range []string{"groups", "destination-policy"} {
		t.Run(axis, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("e", "slot"))})
			publicFixtureRouteTargets(&input)
			calls, generators := 0, 0
			validator := publicFixtureValidator(t, &calls, &generators)
			publicFixtureInstallSources(validator, input.OutputBindings.Value...)
			switch axis {
			case "groups":
				input.Groups = publicPresent(make([][]string, contract.CryptoMaxValueEntries+1))
			case "destination-policy":
				input.OutputBindings.Value[0].Destination.Value.Policy.Data = make([]byte, 524547)
			}
			got := validator.Validate(context.Background(), input)
			want := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonLimitExceeded}
			if got.Valid || got.Complete || calls != 0 || generators != 0 || !reflect.DeepEqual(got.Diagnostics, []contract.Diagnostic{want}) || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) {
				t.Fatalf("%s reached capture or interpreter: %+v", axis, got.Diagnostics)
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationOwnsDerivedTargetPolicy(t *testing.T) {
	input := publicConfigurationFixture(t)
	group := []string{"e", "e1", "e2", "e3", "e4", "e5", "e6"}
	entries := make([]contract.PublicEntry, len(group))
	for i, name := range group {
		entries[i] = publicFixtureEntry(input, name)
	}
	input.Entries = publicPresent(entries)
	input.Groups = publicPresent([][]string{group})
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("e", "slot"))})
	input.OutputBindings.Value[0].Destination.Value.Policy.Data = []byte{3, 7, 11, 13, 17, 19, 23}
	publicFixtureRouteTargets(&input)
	calls, generators := 0, 0
	validator := publicFixtureValidator(t, &calls, &generators)
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	derive := validator.interpret
	borrowed := []byte{3, 7, 11, 13, 17, 19, 23}
	validator.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		target, err := derive(ctx, id, destination, name, encoding)
		target.Policy.Data = borrowed
		return target, err
	}
	input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
	first := validator.Validate(context.Background(), input)
	second := validator.Validate(context.Background(), input)
	if !first.Valid || !first.Complete || !second.Valid || !second.Complete || calls != 2 {
		t.Fatal("derived controls", first.Diagnostics, second.Diagnostics, calls)
	}
	borrowed[0] = 99
	for _, got := range []PublicConfigurationValidation{first, second} {
		policy := got.Configuration.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value
		if !reflect.DeepEqual(policy.Data, []byte{3, 7, 11, 13, 17, 19, 23}) {
			t.Fatal("borrowed interpreter policy", policy.Data)
		}
		_ = publicCapacityBacking(t, got.Configuration, true)
		publicCapacityDetached(t, reflect.ValueOf(input.Groups.Value), reflect.ValueOf(got.Configuration.Groups.Value))
		if !reflect.DeepEqual(got.Configuration.Groups.Value, [][]string{{"e", "e1", "e2", "e3", "e4", "e5", "e6"}}) {
			t.Fatal("captured group changed")
		}
	}
	first.Configuration.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data[0] = 111
	if second.Configuration.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data[0] != 3 {
		t.Fatal("results share policy backing")
	}
	group[0], first.Configuration.Groups.Value[0][1] = "caller mutation", "first result mutation"
	if first.Configuration.Groups.Value[0][0] != "e" || !reflect.DeepEqual(second.Configuration.Groups.Value, [][]string{{"e", "e1", "e2", "e3", "e4", "e5", "e6"}}) {
		t.Fatal("groups share backing")
	}
}

// full_only: false
func TestPublicConfigurationCanonicalizesAbsentDestinationPolicy(t *testing.T) {
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
	target := publicFixtureTarget("e", "slot")
	target.ConsumerPolicy = publicPresent(contract.OutputPolicy{})
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", target)})
	input.OutputBindings.Value[0].Destination.Value.Policy = contract.OutputPolicy{Data: []byte{}}
	publicFixtureRouteTargets(&input)
	calls, generators := 0, 0
	validator := publicFixtureValidator(t, &calls, &generators)
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
	got := validator.Validate(context.Background(), input)
	if !got.Valid || !got.Complete {
		t.Fatal("empty absent policy refused", got.Diagnostics)
	}
	binding := got.Configuration.OutputBindings.Value[0]
	if !reflect.DeepEqual(binding.Destination.Value.Policy, contract.OutputPolicy{}) || !reflect.DeepEqual(binding.Targets.Value[0].ConsumerPolicy.Value, contract.OutputPolicy{}) {
		t.Fatal("absent policy retained empty backing")
	}
}

// full_only: false
func TestPublicConfigurationDerivedTargetsRespectDeclarationBound(t *testing.T) {
	input := publicConfigurationFixture(t)
	policy := contract.OutputPolicy{ContractID: "test-policy", Data: make([]byte, 524546)}
	entries := make([]contract.PublicEntry, 512)
	targets := make([]contract.PublicOutputTarget, 512)
	for i := range entries {
		name := "e" + strconv.Itoa(1000 + i)[1:]
		entries[i] = publicFixtureEntry(input, name)
		targets[i] = publicFixtureTarget(name, name)
		targets[i].ConsumerPolicy = publicPresent(policy)
	}
	input.Entries = publicPresent(entries)
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", targets...)})
	input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string{"d"})}})
	calls, generators, derived := 0, 0, 0
	validator := publicFixtureValidator(t, &calls, &generators)
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	derive := validator.interpret
	validator.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		derived++
		return derive(ctx, id, destination, name, encoding)
	}
	input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
	// Declaration6; binding ID5+incarnation32; destination17+contracts43+
	// settings15+policy(10+11+524546); target count2. Target75 includes
	// incarnation32, five blob headers20, three tags3, bounds16, policy blob4;
	// then service22+
	// target21+target4+locator11+data6+same policy. The63rd target crosses32MiB.
	const policyLength = 10 + 11 + 524546
	const sourceDeclaration = 6 + 5 + 32 + 17 + 43 + 15 + policyLength + 2
	const targetLength = 75 + 22 + 21 + 4 + 11 + 6 + policyLength
	const firstOver = (33554432-sourceDeclaration)/targetLength + 1
	if firstOver != 63 {
		t.Fatal("independent field algebra changed", firstOver)
	}
	got := validator.Validate(context.Background(), input)
	want := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonLimitExceeded}
	if got.Valid || got.Complete || !reflect.DeepEqual(got.Diagnostics, []contract.Diagnostic{want}) || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) || derived != firstOver || calls != firstOver {
		t.Fatalf("derived%d want%d callbacks%d diagnostics%+v", derived, firstOver, calls, got.Diagnostics)
	}
}
