package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
)

// The passive fixture table fixes coordinates before validation. Source rows
// omit targets, so both public and private callers must derive the same union.
func outputNormalizationFixture(t *testing.T, names ...string) (contract.PublicConfiguration, *PublicConfigurationValidator, *int) {
	t.Helper()
	input := publicConfigurationFixture(t)
	authority, recipient := input.Recipients.Value[0].RecipientID, input.Recipients.Value[1].RecipientID
	slices.Sort(names)
	for _, name := range names {
		entry := publicFixtureEntry(input, name)
		entry.Memberships = publicPresent([]contract.ID{authority, recipient})
		input.Entries.Value = append(input.Entries.Value, entry)
	}
	for _, destination := range []string{"a", "b", "c"} {
		targets := make([]contract.PublicOutputTarget, len(names))
		for i, name := range names {
			targets[i] = publicFixtureTarget(name, destination+"/"+name)
			targets[i].ConsumerPolicy = publicPresent(contract.OutputPolicy{})
		}
		binding := publicFixtureBinding(destination, targets...)
		binding.Destination.Value.Policy = contract.OutputPolicy{}
		input.OutputBindings.Value = append(input.OutputBindings.Value, binding)
	}
	calls, generators := 0, 0
	validator := publicFixtureValidator(t, &calls, &generators)
	publicFixtureInstallSources(validator, input.OutputBindings.Value...)
	interpret := validator.interpret
	derived := new(int)
	validator.interpret = func(ctx context.Context, id string, d contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		*derived++
		return interpret(ctx, id, d, name, encoding)
	}
	for i := range input.OutputBindings.Value {
		input.OutputBindings.Value[i].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
	}
	return input, validator, derived
}

func outputNormalizationRoute(kind contract.PublicEntrySelector, name string, destinations ...string) contract.PublicRoutingRule {
	return contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: kind, EntryName: name}, Destinations: publicPresent(destinations)}
}

// These adapters retain the original source input. The generated variant uses
// the real declaration codec and entry adapter used by generated admission.
func outputNormalizationApply(t *testing.T, input contract.PublicConfiguration, generated bool) ([]ApplyEntryInput, []contract.ID, *outputApplyInput) {
	t.Helper()
	entries := make([]ApplyEntryInput, len(input.Entries.Value))
	recipients := make([]contract.ID, len(input.Recipients.Value))
	for i, row := range input.Entries.Value {
		inputEncoding, outputEncoding := uint8(contract.InputEncodingRaw), uint8(contract.OutputEncodingRaw)
		if row.InputEncoding.State == contract.PublicPresent {
			inputEncoding = row.InputEncoding.Value
		}
		if row.OutputEncoding.State == contract.PublicPresent {
			outputEncoding = row.OutputEncoding.Value
		}
		entries[i] = ApplyEntryInput{Name: row.Name, Recipients: row.Memberships.Value, InputEncoding: inputEncoding, OutputEncoding: outputEncoding}
	}
	for i, row := range input.Recipients.Value {
		recipients[i] = row.RecipientID
	}
	if generated {
		declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: input.Store.DomainID.Value, OperationID: contract.ID{99}}
		for _, entry := range entries {
			declaration.Entries = append(declaration.Entries, contract.GeneratorDeclarationEntry{InputEncoding: entry.InputEncoding, OutputEncoding: entry.OutputEncoding, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain, Name: entry.Name, Recipients: entry.Recipients, Payload: []byte("original")})
		}
		body, err := contract.EncodeGeneratorDeclaration(declaration)
		if err != nil {
			t.Fatal(err)
		}
		view, err := contract.InspectGeneratorDeclaration(body)
		if err != nil {
			t.Fatal(err)
		}
		entries, err = generatedDeclarationOutputEntries(view)
		if err != nil {
			t.Fatal(err)
		}
	}
	output := &outputApplyInput{groups: input.Groups.Value}
	for _, binding := range input.OutputBindings.Value {
		output.bindings = append(output.bindings, outputApplyBinding{destinationID: binding.DestinationID, destination: binding.Destination.Value})
	}
	for _, route := range input.Routing.Value {
		output.routes = append(output.routes, outputApplyRoute{defaultRoute: route.Key.EntrySelector == contract.PublicDefaultRoute, entryName: route.Key.EntryName, destinations: route.Destinations.Value})
	}
	return entries, recipients, output
}

func outputNormalizationInterpreter(validator *PublicConfigurationValidator) PublicOutputInterpreter {
	return validator.interpret
}

func outputNormalizationStored(t *testing.T, input contract.PublicConfiguration, output *outputApplyInput) (contract.OutputConfiguration, []byte) {
	t.Helper()
	entries := make(map[string]contract.ID)
	bindings := make(map[string]contract.ID)
	for i, row := range input.Entries.Value {
		entries[row.Name] = contract.ID{byte(10 + i)}
	}
	for i, row := range input.OutputBindings.Value {
		bindings[row.DestinationID] = contract.ID{byte(20 + i)}
	}
	stored, body, err := outputApplyConfiguration(input.Store.DomainID.Value, output, entries, bindings)
	if err != nil {
		t.Fatal("normalized stored configuration", err)
	}
	return stored, body
}

// full_only: false
func TestOutputNormalizationRawOmissionAndExplicitRawStoreIdentically(t *testing.T) {
	var wantPublic contract.PublicConfiguration
	var wantStored []byte
	for _, explicit := range []bool{false, true} {
		input, validator, derived := outputNormalizationFixture(t, "alpha")
		input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicNamedEntry, "alpha", "a")})
		if explicit {
			input.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingRaw)
		}
		public := validator.Validate(t.Context(), input)
		if !public.Valid || !public.Complete || len(public.Diagnostics) != 0 || *derived != 1 {
			t.Fatal("public raw normalization", explicit, public.Diagnostics, *derived)
		}
		if explicit && !reflect.DeepEqual(public.Configuration, wantPublic) {
			t.Fatal("explicit raw changed public meaning")
		}
		wantPublic = public.Configuration
		for _, generated := range []bool{false, true} {
			entries, recipients, source := outputNormalizationApply(t, input, generated)
			normalized, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, outputNormalizationInterpreter(validator))
			if err != nil {
				t.Fatal("raw apply normalization", explicit, generated, err)
			}
			stored, body := outputNormalizationStored(t, input, normalized)
			if len(stored.Bindings[0].Targets) != 1 || stored.Bindings[0].Targets[0].PayloadEncoding != contract.OutputEncodingRaw {
				t.Fatal("raw override entered stored rows")
			}
			if wantStored != nil && !bytes.Equal(body, wantStored) {
				t.Fatal("ordinary/generated omission/raw stored bytes differ")
			}
			wantStored = body
		}
	}
}

// full_only: false
func TestOutputNormalizationOmittedDefaultEqualsEmptyDefault(t *testing.T) {
	var wantPublic contract.PublicConfiguration
	var wantStored []byte
	var wantRoutes []outputApplyRoute
	for _, explicit := range []bool{false, true} {
		input, validator, _ := outputNormalizationFixture(t, "alpha")
		input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicNamedEntry, "alpha", "a")})
		if explicit {
			input.Routing.Value = append([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "")}, input.Routing.Value...)
		}
		got := validator.Validate(t.Context(), input)
		if !got.Valid || !got.Complete || len(got.Diagnostics) != 0 {
			t.Fatal("valid optional default refused", got.Diagnostics)
		}
		entries, recipients, source := outputNormalizationApply(t, input, false)
		normalized, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, outputNormalizationInterpreter(validator))
		if err != nil {
			t.Fatal(err)
		}
		if explicit && !reflect.DeepEqual(normalized.routes, wantRoutes) {
			t.Fatal("omitted default differs from explicit empty default private meaning")
		}
		wantRoutes = normalized.routes
		_, stored := outputNormalizationStored(t, input, normalized)
		if explicit && (!reflect.DeepEqual(got.Configuration, wantPublic) || !bytes.Equal(stored, wantStored)) {
			t.Fatal("omitted default differs from explicit empty default")
		}
		wantPublic, wantStored = got.Configuration, stored
	}
}

// full_only: false
func TestOutputNormalizationRefusesUnknownAndUnroutedEncodings(t *testing.T) {
	for _, condition := range []string{"unknown-input", "unknown-output", "zero-input", "zero-output"} {
		t.Run(condition, func(t *testing.T) {
			input, validator, _ := outputNormalizationFixture(t, "alpha", "beta")
			input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicNamedEntry, "alpha", "a")})
			field := &input.Entries.Value[1].OutputEncoding
			if condition == "unknown-input" || condition == "zero-input" {
				field = &input.Entries.Value[1].InputEncoding
			}
			encoding := uint8(99)
			if condition == "zero-input" || condition == "zero-output" {
				encoding = 0
			}
			*field = publicPresent(encoding)
			public := validator.Validate(t.Context(), input)
			if public.Valid || public.Complete || len(public.Diagnostics) == 0 {
				t.Fatal("invalid unrouted entry encoding admitted", condition)
			}
			for _, generated := range []bool{false, true} {
				privateInput := input
				if generated {
					// Decode valid declared input, then damage only the private
					// normalizer boundary; the declaration codec refuses bad tags.
					privateInput.Entries.Value = slices.Clone(input.Entries.Value)
					privateInput.Entries.Value[1].InputEncoding = publicPresent(contract.InputEncodingRaw)
					privateInput.Entries.Value[1].OutputEncoding = publicPresent(contract.OutputEncodingRaw)
				}
				entries, recipients, source := outputNormalizationApply(t, privateInput, generated)
				if condition == "unknown-input" || condition == "zero-input" {
					entries[1].InputEncoding = encoding
				} else {
					entries[1].OutputEncoding = encoding
				}
				normalized, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, outputNormalizationInterpreter(validator))
				if err == nil || normalized != nil {
					t.Fatal("invalid apply encoding admitted", condition, generated)
				}
			}
		})
	}
}

// full_only: false
func TestOutputNormalizationDerivesSharedPairsOnceAndReplacesWholeRouteLists(t *testing.T) {
	input, validator, derived := outputNormalizationFixture(t, "alpha", "beta", "delta", "gamma")
	authority := input.Authority.RecipientID.Value
	other := input.Recipients.Value[1]
	other.RecipientID = contract.ID{4}
	other.DisplayName = publicPresent("current nonmember")
	input.Recipients.Value = append(input.Recipients.Value, other)
	input.Entries.Value[1].Memberships = publicPresent([]contract.ID{authority})
	input.Routing = publicPresent([]contract.PublicRoutingRule{
		outputNormalizationRoute(contract.PublicDefaultRoute, "", "a", "b"),
		outputNormalizationRoute(contract.PublicNamedEntry, "alpha", "c"),
		outputNormalizationRoute(contract.PublicNamedEntry, "beta"),
		outputNormalizationRoute(contract.PublicNamedEntry, "gamma", "a", "b"),
	})
	for _, phase := range []struct {
		name     string
		defaults []string
		expected map[string][]string
		calls    int
	}{
		{"initial-default", []string{"a", "b"}, map[string][]string{"a": {"delta", "gamma"}, "b": {"delta", "gamma"}, "c": {"alpha"}}, 5},
		{"changed-default", []string{"c"}, map[string][]string{"a": {"gamma"}, "b": {"gamma"}, "c": {"alpha", "delta"}}, 4},
	} {
		t.Run(phase.name, func(t *testing.T) {
			input.Routing.Value[0].Destinations.Value = phase.defaults
			*derived = 0
			public := validator.Validate(t.Context(), input)
			if !public.Valid || !public.Complete || len(public.Diagnostics) != 0 || *derived != phase.calls {
				t.Fatal("shared public route union", public.Diagnostics, *derived)
			}
			for _, binding := range public.Configuration.OutputBindings.Value {
				var names []string
				for _, target := range binding.Targets.Value {
					names = append(names, target.EntryName)
				}
				if !slices.Equal(names, phase.expected[binding.DestinationID]) {
					t.Fatal("public complete-list route union", binding.DestinationID, names)
				}
			}
			for _, generated := range []bool{false, true} {
				entries, recipients, source := outputNormalizationApply(t, input, generated)
				*derived = 0
				normalized, err := normalizeOutputApply(t.Context(), entries, recipients, authority, source, outputNormalizationInterpreter(validator))
				if err != nil || *derived != phase.calls {
					t.Fatal("apply shared-pair count", generated, err, *derived)
				}
				for _, binding := range normalized.bindings {
					var names []string
					for _, target := range binding.targets {
						names = append(names, target.entryName)
					}
					if !slices.Equal(names, phase.expected[binding.destinationID]) {
						t.Fatal("apply complete-list route union", generated, binding.destinationID, names)
					}
				}
				stored, _ := outputNormalizationStored(t, input, normalized)
				if !slices.Equal(stored.DefaultDestinations, phase.defaults) || len(stored.Routes) != 3 || stored.Routes[1].EntryIncarnationID != (contract.ID{11}) || len(stored.Routes[1].Destinations) != 0 || !slices.Equal(stored.Routes[2].Destinations, []string{"a", "b"}) {
					t.Fatal("stored declaration lost inherited, empty or equal-to-default replacement")
				}
			}
		})
	}
}

// full_only: false
func TestOutputNormalizationGroupsAreExplicitDisjointAndCrossDestination(t *testing.T) {
	for _, condition := range []string{"independent", "cross-destination", "disjoint", "overlapping", "duplicate-member", "unknown-member", "empty-group"} {
		t.Run(condition, func(t *testing.T) {
			input, validator, _ := outputNormalizationFixture(t, "alpha", "beta", "delta", "gamma")
			input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicNamedEntry, "alpha", "a"), outputNormalizationRoute(contract.PublicNamedEntry, "beta", "b"), outputNormalizationRoute(contract.PublicNamedEntry, "delta", "b"), outputNormalizationRoute(contract.PublicNamedEntry, "gamma", "a")})
			var expected [][]string
			switch condition {
			case "cross-destination":
				input.Groups = publicPresent([][]string{{"beta", "alpha"}})
				expected = [][]string{{"alpha", "beta"}}
			case "disjoint":
				input.Groups = publicPresent([][]string{{"gamma", "delta"}, {"beta", "alpha"}})
				expected = [][]string{{"alpha", "beta"}, {"delta", "gamma"}}
			case "overlapping":
				input.Groups = publicPresent([][]string{{"alpha", "beta"}, {"beta", "gamma"}})
			case "duplicate-member":
				input.Groups = publicPresent([][]string{{"alpha", "alpha"}})
			case "unknown-member":
				input.Groups = publicPresent([][]string{{"alpha", "missing"}})
			case "empty-group":
				input.Groups = publicPresent([][]string{{}})
			}
			valid := condition == "independent" || condition == "cross-destination" || condition == "disjoint"
			public := validator.Validate(t.Context(), input)
			if public.Valid != valid || public.Complete != valid {
				t.Fatal("public explicit group admission", condition, public.Diagnostics)
			}
			if valid && (!slices.EqualFunc(public.Configuration.Groups.Value, expected, slices.Equal[[]string, string]) || len(public.Configuration.OutputBindings.Value[0].Targets.Value) != 2 || len(public.Configuration.OutputBindings.Value[1].Targets.Value) != 2 || len(public.Configuration.OutputBindings.Value[2].Targets.Value) != 0) {
				t.Fatal("public grouping changed independent pairs", condition)
			}
			for _, generated := range []bool{false, true} {
				entries, recipients, source := outputNormalizationApply(t, input, generated)
				normalized, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, outputNormalizationInterpreter(validator))
				if !valid {
					if err == nil || normalized != nil {
						t.Fatal("invalid private group admitted", condition, generated)
					}
					continue
				}
				if err != nil || !slices.EqualFunc(normalized.groups, expected, slices.Equal[[]string, string]) {
					t.Fatal("private group meaning", condition, generated, err)
				}
				stored, _ := outputNormalizationStored(t, input, normalized)
				if len(stored.Groups) != len(expected) || len(stored.Bindings[0].Targets) != 2 || len(stored.Bindings[1].Targets) != 2 {
					t.Fatal("stored groups changed independent coordinates", condition, generated)
				}
			}
		})
	}
}

// full_only: false
func TestOutputNormalizationAggregatePolicyBytesPrecedeOwnership(t *testing.T) {
	for _, family := range []string{"targets", "destinations"} {
		t.Run(family, func(t *testing.T) {
			input, subjects := publicAdmissionAggregatePolicyFixture(t, family)
			entries, recipients, source := outputNormalizationApply(t, input, false)
			// This source adapter normally omits targets. Retain offered target
			// assertions here to exercise the other retained private input family.
			for i, binding := range input.OutputBindings.Value {
				for _, target := range binding.Targets.Value {
					source.bindings[i].targets = append(source.bindings[i].targets, outputApplyTarget{entryName: target.EntryName, target: publicTargetValue(target)})
				}
			}
			// The cheap boundary must refuse from row and subject lengths alone.
			// This assertion detects the formerly late bound even though the
			// final byte-account bool returns false on both implementations.
			if outputApplyInputAxes(source) {
				t.Error("aggregate policy byte floor passed cheap admission")
			}
			callbacks := 0
			interpret := func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
				callbacks++
				return contract.OutputTarget{}, contract.ErrRecord
			}
			for _, owned := range []bool{false, true} {
				ctx := &publicAdmissionCancellationContext{Context: context.Background(), ceiling: 1}
				var normalized *outputApplyInput
				var err error
				if owned {
					normalized, err = normalizeOwnedOutputApply(ctx, entries, recipients, input.Authority.RecipientID.Value, source, interpret, false)
				} else {
					normalized, err = normalizeOutputApply(ctx, entries, recipients, input.Authority.RecipientID.Value, source, interpret)
				}
				if normalized != nil || err != contract.ErrRecordCapacity || callbacks != 0 || ctx.calls != 0 {
					t.Errorf("private admission owned=%t: result=%v err=%v callbacks=%d visits=%d", owned, normalized != nil, err, callbacks, ctx.calls)
				}
			}
			publicAdmissionAggregatePolicyUnchanged(t, input, subjects)
			for i, binding := range source.bindings {
				if binding.destinationID != input.OutputBindings.Value[i].DestinationID || len(binding.targets) != len(input.OutputBindings.Value[i].Targets.Value) {
					t.Fatal("private refusal changed borrowed source rows")
				}
				for _, target := range binding.targets {
					if target.entryName != "e" || target.target.CanonicalTarget != "slot" || len(target.target.Policy.Data) != len(subjects) || &target.target.Policy.Data[0] != &subjects[0] {
						t.Fatal("private refusal changed borrowed target policy")
					}
				}
			}
		})
	}
}

// full_only: false
func TestOutputNormalizationCanonicalTargetsNeedNoInterpreter(t *testing.T) {
	input, validator, derived := outputNormalizationFixture(t, "alpha", "beta")
	input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a")})
	first := validator.Validate(t.Context(), input)
	if !first.Valid || !first.Complete || *derived != 2 {
		t.Fatal("ordinary target derivation", first.Diagnostics, *derived)
	}
	canonical := NewPublicConfigurationValidator(nil).Validate(t.Context(), first.Configuration)
	if !canonical.Valid || !canonical.Complete || !reflect.DeepEqual(canonical.Configuration, first.Configuration) {
		t.Fatal("canonical public facts required an interpreter", canonical.Diagnostics)
	}
	entries, recipients, _ := outputNormalizationApply(t, canonical.Configuration, false)
	source := publicOutputApplyInput(canonical.Configuration)
	got, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, nil)
	if err != nil || got == nil || len(got.bindings[0].targets) != 2 {
		t.Fatal("canonical private facts required an interpreter", err)
	}
	wrong := ownOutputApplyInput(source)
	wrong.bindings[0].targets = wrong.bindings[0].targets[:1]
	calls := 0
	interpret := func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
		calls++
		return contract.OutputTarget{}, contract.ErrRecord
	}
	if got, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, wrong, interpret); err == nil || got != nil || calls != 0 {
		t.Fatal("incomplete canonical target vector was repaired", err, calls)
	}
}

// full_only: false
func TestOutputNormalizationRetainsExistingTargetsAndDerivesOnlyMissingNames(t *testing.T) {
	input, validator, _ := outputNormalizationFixture(t, "alpha", "beta")
	input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a")})
	canonical := validator.Validate(t.Context(), input)
	if !canonical.Valid || !canonical.Complete {
		t.Fatal("canonical fixture", canonical.Diagnostics)
	}
	entries, recipients, _ := outputNormalizationApply(t, canonical.Configuration, false)
	source := publicOutputApplyInput(canonical.Configuration)
	source.bindings[0].targetsComplete = false
	source.bindings[0].targets = source.bindings[0].targets[:1]
	retained := ownOutputTarget(source.bindings[0].targets[0].target)
	calls := []string{}
	interpret := func(ctx context.Context, destinationID string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		calls = append(calls, name)
		return validator.interpret(ctx, destinationID, destination, name, encoding)
	}
	got, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, interpret)
	if err != nil || got == nil || !slices.Equal(calls, []string{"beta"}) || !got.bindings[0].targets[0].target.Equal(retained) || !got.bindings[0].targetsComplete {
		t.Fatal("retained targets drifted or were reinterpreted", err, calls)
	}
	if got, err := normalizeOutputApply(t.Context(), entries, recipients, input.Authority.RecipientID.Value, source, nil); !errors.Is(err, ErrPublicOutputUnavailable) || got != nil {
		t.Fatal("missing interpretation silently completed a new target", err)
	}
	for _, oldEncoding := range []uint8{contract.OutputEncodingRaw, contract.OutputEncodingBase64} {
		t.Run("present-target-encoding-"+strconv.Itoa(int(oldEncoding)), func(t *testing.T) {
			input, validator, derived := outputNormalizationFixture(t, "alpha", "beta")
			input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a")})
			input.Entries.Value[0].OutputEncoding = publicPresent(oldEncoding)
			original := validator.Validate(t.Context(), input)
			if !original.Valid || !original.Complete || *derived != 2 {
				t.Fatal("complete target baseline", original.Diagnostics, *derived)
			}
			changed := original.Configuration
			changed.Entries.Value = slices.Clone(changed.Entries.Value)
			nextEncoding := uint8(contract.OutputEncodingBase64)
			if oldEncoding == contract.OutputEncodingBase64 {
				nextEncoding = contract.OutputEncodingRaw
			}
			changed.Entries.Value[0].OutputEncoding = publicPresent(nextEncoding)
			beforeAlpha := publicTargetValue(changed.OutputBindings.Value[0].Targets.Value[0])
			beforeBeta := publicTargetValue(changed.OutputBindings.Value[0].Targets.Value[1])
			returned := validator.Validate(t.Context(), changed)
			if !returned.Valid || !returned.Complete || len(returned.Diagnostics) != 0 || *derived != 3 {
				t.Fatal("entry-owned encoding edit was not derived once", returned.Diagnostics, *derived)
			}
			expectedAlpha := beforeAlpha
			expectedAlpha.PayloadEncoding = nextEncoding
			actual := returned.Configuration.OutputBindings.Value[0].Targets.Value
			if len(actual) != 2 || !publicTargetValue(actual[0]).Equal(expectedAlpha) || !publicTargetValue(actual[1]).Equal(beforeBeta) {
				t.Error("public normalization returned stale targets after the owning entry tag changed")
			}
			if changed.OutputBindings.Value[0].Targets.Value[0].PayloadEncoding.Value != oldEncoding {
				t.Error("normalization changed the offered target assertion")
			}
		})
	}

}

// full_only: false
func TestOutputNormalizationDerivedCollisionsMatchCanonicalDiagnostics(t *testing.T) {
	input, validator, derived := outputNormalizationFixture(t, "alpha", "beta", "gamma")
	input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a", "b", "c")})
	input.OutputBindings.Value[2].Destination.Value.ServiceContractID = "other-output/service/v1"
	interpret := validator.interpret
	validator.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
		target, err := interpret(ctx, id, destination, name, encoding)
		target.ServiceContractID = destination.ServiceContractID
		switch id + "/" + name {
		case "a/alpha", "a/beta", "b/alpha", "c/alpha":
			target.CanonicalTarget = "shared-first"
		case "a/gamma", "b/beta":
			target.CanonicalTarget = "shared-second"
		}
		if id == "b" {
			target.TargetContractID = "other-output/target/v1"
		}
		return target, err
	}
	want := []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "a", Name: "beta"}, Path: []contract.DiagnosticField{contract.FieldCanonicalTarget}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "b", Name: "alpha"}, Path: []contract.DiagnosticField{contract.FieldCanonicalTarget}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "b", Name: "beta"}, Path: []contract.DiagnosticField{contract.FieldCanonicalTarget}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey},
	}
	for _, canonical := range []bool{false, true} {
		t.Run(map[bool]string{false: "derived", true: "canonical"}[canonical], func(t *testing.T) {
			candidate := ownPublicConfiguration(input)
			if canonical {
				for i := range candidate.OutputBindings.Value {
					binding := &candidate.OutputBindings.Value[i]
					binding.Targets = publicPresent([]contract.PublicOutputTarget{})
					for _, name := range []string{"alpha", "beta", "gamma"} {
						target, err := validator.interpret(t.Context(), binding.DestinationID, binding.Destination.Value, name, contract.OutputEncodingRaw)
						if err != nil {
							t.Fatal(err)
						}
						binding.Targets.Value = append(binding.Targets.Value, publicOutputTarget(name, target))
					}
				}
			}
			*derived = 0
			got := validator.Validate(t.Context(), candidate)
			if got.Valid || got.Complete || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, want) {
				t.Fatalf("collision diagnostics: got %+v want %+v", got.Diagnostics, want)
			}
			wantCalls := 9
			if canonical {
				wantCalls = 0
			}
			if *derived != wantCalls {
				t.Errorf("interpretations: got %d want %d", *derived, wantCalls)
			}
			for _, generated := range []bool{false, true} {
				entries, recipients, source := outputNormalizationApply(t, candidate, generated)
				if canonical {
					source = publicOutputApplyInput(candidate)
				}
				normalized, err := normalizeOutputApply(t.Context(), entries, recipients, candidate.Authority.RecipientID.Value, source, validator.interpret)
				if normalized != nil || !errors.Is(err, contract.ErrRecord) {
					t.Fatalf("collision admitted: generated=%t result=%v err=%v", generated, normalized != nil, err)
				}
			}
		})
	}
}

// full_only: false
func TestOutputNormalizationKeepsCollisionsBeforeLaterFailure(t *testing.T) {
	for _, condition := range []string{"typed-interpretation", "unavailable", "capacity", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			input, validator, derived := outputNormalizationFixture(t, "alpha", "beta", "gamma")
			input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a")})
			interpret := validator.interpret
			failure := errors.New("test interpretation refusal")
			reason := contract.ReasonInvalidInput
			lateSubject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "a", Name: "gamma"}
			lateField := contract.FieldTargetData
			switch condition {
			case "unavailable":
				failure, reason = ErrPublicOutputUnavailable, contract.ReasonPublicFactUnavailable
			case "capacity":
				failure, reason = contract.ErrRecordCapacity, contract.ReasonLimitExceeded
			case "cancelled":
				failure, reason = context.Canceled, contract.ReasonCancelled
				lateSubject, lateField = contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence
			}
			for _, public := range []bool{true, false} {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				validator.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
					target, err := interpret(ctx, id, destination, name, encoding)
					if name != "gamma" {
						target.CanonicalTarget = "shared"
						return target, err
					}
					if condition == "cancelled" {
						cancel()
						return target, err
					}
					return contract.OutputTarget{}, errors.Join(failure, PublicOutputError{Field: lateField})
				}
				*derived = 0
				if public {
					got := validator.Validate(ctx, input)
					want := []contract.Diagnostic{
						{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "a", Name: "beta"}, Path: []contract.DiagnosticField{contract.FieldCanonicalTarget}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey},
						{Subject: lateSubject, Path: []contract.DiagnosticField{lateField}, Outcome: contract.DiagnosticUnable, Reason: reason},
					}
					if condition == "cancelled" {
						want[0], want[1] = want[1], want[0]
					}
					if got.Valid || got.Complete || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, want) {
						t.Errorf("public collision and later failure: got %+v want %+v", got.Diagnostics, want)
					}
				} else {
					entries, recipients, source := outputNormalizationApply(t, input, false)
					normalized, err := normalizeOutputApply(ctx, entries, recipients, input.Authority.RecipientID.Value, source, validator.interpret)
					if normalized != nil || !errors.Is(err, failure) {
						t.Errorf("private collision hid later failure: result=%v err=%v", normalized != nil, err)
					}
					var interpretation publicOutputInterpretationError
					if condition != "cancelled" && (!errors.As(err, &interpretation) || interpretation.destinationID != "a" || interpretation.entryName != "gamma" || !errors.Is(err, PublicOutputError{Field: lateField})) {
						t.Errorf("private typed interpretation attribution lost: %v", err)
					}
				}
				if *derived != 3 {
					t.Errorf("later failure was not visited: got %d interpretations want 3", *derived)
				}
			}
		})
	}
}

// full_only: false
func TestOutputNormalizationReportsBoundedCollisionSet(t *testing.T) {
	names := make([]string, contract.MaxOutputTargetsPerBinding)
	for i := range names {
		names[i] = "e" + strconv.Itoa(1000+i)
	}
	for _, overCapacity := range []bool{false, true} {
		t.Run(map[bool]string{false: "maximum-targets", true: "later-target-capacity"}[overCapacity], func(t *testing.T) {
			input, validator, derived := outputNormalizationFixture(t, names...)
			destinations := []string{"a", "b"}
			if overCapacity {
				destinations = append(destinations, "c")
			}
			input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", destinations...)})
			interpret := validator.interpret
			validator.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
				target, err := interpret(ctx, id, destination, name, encoding)
				target.CanonicalTarget = "shared"
				return target, err
			}
			var want []contract.Diagnostic
			if overCapacity {
				want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonLimitExceeded})
			}
			for _, destination := range []string{"a", "b"} {
				for i, name := range names {
					if destination == "a" && i == 0 {
						continue
					}
					want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: destination, Name: name}, Path: []contract.DiagnosticField{contract.FieldCanonicalTarget}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey})
				}
			}
			got := validator.Validate(t.Context(), input)
			if got.Valid || got.Complete || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, want) || *derived != contract.MaxOutputTargets {
				t.Fatalf("bounded collision collection: diagnostics=%d want=%d exact=%t interpretations=%d want=%d", len(got.Diagnostics), len(want), reflect.DeepEqual(got.Diagnostics, want), *derived, contract.MaxOutputTargets)
			}
			if overCapacity && !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) {
				t.Fatal("late target capacity returned partial configuration")
			}
		})
	}
}

// full_only: false
func TestOutputInterpretationUnavailableKeepsContextPriority(t *testing.T) {
	for _, condition := range []struct {
		name             string
		caller, returned error
		unavailable      bool
		reason           contract.DiagnosticReason
	}{
		{"cancelled", context.Canceled, context.Canceled, true, contract.ReasonCancelled},
		{"expired", context.DeadlineExceeded, context.DeadlineExceeded, true, contract.ReasonExpired},
		{"returned-cancelled", nil, context.Canceled, false, contract.ReasonCancelled},
		{"returned-expired", nil, context.DeadlineExceeded, false, contract.ReasonExpired},
		{"unavailable-returned-cancelled", nil, context.Canceled, true, contract.ReasonCancelled},
		{"unavailable-returned-expired", nil, context.DeadlineExceeded, true, contract.ReasonExpired},
		{"caller-cancelled-returned-expired", context.Canceled, context.DeadlineExceeded, true, contract.ReasonCancelled},
		{"caller-expired-returned-cancelled", context.DeadlineExceeded, context.Canceled, true, contract.ReasonExpired},
	} {
		t.Run(condition.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				input, validator, _ := outputNormalizationFixture(t, "alpha")
				input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a")})
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				validator.interpret = func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
					switch condition.caller {
					case context.DeadlineExceeded:
						time.Sleep(2 * time.Second)
					case context.Canceled:
						cancel()
					}
					failure := condition.returned
					if condition.unavailable {
						failure = errors.Join(ErrPublicOutputUnavailable, failure)
					}
					return contract.OutputTarget{}, failure
				}
				got := validator.Validate(ctx, input)
				var want []contract.Diagnostic
				if condition.caller != nil {
					want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: condition.reason})
				}
				want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "a"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: condition.reason})
				if got.Valid || got.Complete || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, want) {
					t.Errorf("unavailable interpretation lost context priority: got %+v want %+v", got.Diagnostics, want)
				}
			})
		})
	}
}

// full_only: false
func TestProposedOutputRoutesRequireIndependentInterpretation(t *testing.T) {
	input, plugin, calls := outputNormalizationFixture(t, "alpha", "beta")
	input.Routing = publicPresent([]contract.PublicRoutingRule{outputNormalizationRoute(contract.PublicDefaultRoute, "", "a")})
	baseline := plugin.Validate(t.Context(), input)
	if !baseline.Valid || !baseline.Complete || *calls != 2 {
		t.Fatal("fixture target derivation", baseline.Diagnostics)
	}
	if baseline.CheckedRouteValidator() != nil {
		t.Fatal("structural validation supplied proposed route authority")
	}
	for _, mode := range []string{"exact", "missing-plugin", "target", "locator", "target-data"} {
		t.Run(mode, func(t *testing.T) {
			proposed := ownPublicConfiguration(baseline.Configuration)
			row := &proposed.OutputBindings.Value[0].Targets.Value[0]
			validator := plugin
			switch mode {
			case "missing-plugin":
				validator = NewPublicConfigurationValidator(nil)
			case "target":
				row.CanonicalTarget.Value = "other/slot"
			case "locator":
				row.ConsumerLocator.Value = "other/locator"
			case "target-data":
				row.TargetData.Value = []byte("different")
			}
			before := *calls
			result := validator.ValidateProposed(t.Context(), proposed)
			switch mode {
			case "exact":
				if !result.Valid || !result.Complete || *calls-before != 2 {
					t.Error("exact proposed routes need two independent interpretations", result.Diagnostics, *calls-before)
				}
				captured := result.CheckedRouteValidator()
				if captured == nil {
					t.Fatal("missing checked routes")
				}
				same := captured.ValidateProposed(t.Context(), result.Configuration)
				if !same.Valid || !same.Complete || *calls-before != 2 {
					t.Fatal("exact handoff changed or repeated interpretation", same.Diagnostics)
				}
				for _, edit := range []string{"address", "settings", "entry-encoding", "route"} {
					changed := ownPublicConfiguration(result.Configuration)
					switch edit {
					case "address":
						changed.OutputBindings.Value[0].Targets.Value[0].CanonicalTarget.Value = "other/slot"
					case "settings":
						changed.OutputBindings.Value[0].Destination.Value.CanonicalSettings = []byte(`{"changed":true}`)
					case "entry-encoding":
						changed.Entries.Value[0].OutputEncoding.Value = contract.OutputEncodingBase64
					case "route":
						changed.Routing.Value[0].Destinations.Value = nil
					}
					got := captured.ValidateProposed(t.Context(), changed)
					if got.Valid && got.Complete || got.CheckedRouteValidator() != nil {
						t.Fatal("modified source inherited verified route", edit)
					}
				}
			case "missing-plugin":
				if result.Complete || *calls != before {
					t.Error("unavailable route interpretation", result.Diagnostics)
				}
			default:
				if result.Valid || *calls == before {
					t.Error("offered route disagrees with its interpretation", result.Diagnostics)
				}
			}
		})
	}
}
