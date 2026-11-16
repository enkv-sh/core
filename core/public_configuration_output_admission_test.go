package core

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicConfigurationAcceptsPluginOwnedTargetData(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("single"), []byte("private-shape"), {0, 255}} {
		t.Run(strconv.Itoa(len(data)), func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
			target := publicFixtureTarget("e", "slot")
			target.TargetData = publicPresent(data)
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", target)})
			publicFixtureRouteTargets(&input)
			got := NewPublicConfigurationValidator(nil).Validate(context.Background(), input)
			if !got.Valid || !got.Complete || !slices.Equal(got.Configuration.OutputBindings.Value[0].Targets.Value[0].TargetData.Value, data) {
				t.Fatal("canonical plugin target data refused or changed", got.Diagnostics)
			}
		})
	}
}

type publicAdmissionCancellationContext struct {
	context.Context
	calls   int
	ceiling int
	cause   error
}

func (c *publicAdmissionCancellationContext) Err() error {
	c.calls++
	ceiling := c.ceiling
	if ceiling == 0 {
		ceiling = 3
	}
	if c.calls >= ceiling {
		if c.cause != nil {
			return c.cause
		}
		return context.Canceled
	}
	return nil
}

// full_only: false
func TestPublicConfigurationAdmissionTraversalBoundsAndCancellation(t *testing.T) {
	t.Run("aggregate-before-policy-payloads", func(t *testing.T) {
		input := publicConfigurationFixture(t)
		input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
		// 64 admitted outer rows and 17 rows each exceed the independent 1,024
		// target axis. Every binding borrows the same nested policy backing.
		// Its oversized payload must not be copied before that count refusal.
		payload := make([]byte, 524547)
		targets := make([]contract.PublicOutputTarget, 17)
		for i := range targets {
			targets[i] = publicFixtureTarget("e", "slot")
			targets[i].ConsumerPolicy = publicPresent(contract.OutputPolicy{ContractID: "controlled-policy", Data: payload})
		}
		bindings := make([]contract.PublicOutputBinding, contract.MaxOutputBindings)
		for i := range bindings {
			bindings[i] = contract.PublicOutputBinding{DestinationID: string(rune('a' + i)), Targets: publicPresent(targets)}
		}
		input.OutputBindings = publicPresent(bindings)
		calls, generators := 0, 0
		validator := publicFixtureValidator(t, &calls, &generators)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		got := validator.Validate(context.Background(), input)
		runtime.ReadMemStats(&after)
		want := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonLimitExceeded}
		if got.Valid || got.Complete || calls != 0 || generators != 0 || !reflect.DeepEqual(got.Diagnostics, []contract.Diagnostic{want}) || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) {
			t.Fatalf("aggregate refusal visited nested policy payloads or interpretation: %+v", got.Diagnostics)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated >= 512<<10 {
			t.Fatalf("aggregate refusal allocated %d bytes before admission", allocated)
		}
		if len(targets[0].ConsumerPolicy.Value.Data) != 524547 {
			t.Fatal("aggregate refusal changed borrowed policy backing")
		}
	})
	for _, condition := range []struct {
		name    string
		cause   error
		ceiling int
		reason  contract.DiagnosticReason
	}{
		{"cancel-before-traversal", context.Canceled, 1, contract.ReasonCancelled},
		{"expire-before-traversal", context.DeadlineExceeded, 1, contract.ReasonExpired},
		{"cancel-during-admitted-traversal", context.Canceled, 3, contract.ReasonCancelled},
		{"expire-during-admitted-traversal", context.DeadlineExceeded, 3, contract.ReasonExpired},
	} {
		t.Run(condition.name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("e", "slot"))})
			publicFixtureRouteTargets(&input)
			calls, generators := 0, 0
			validator := publicFixtureValidator(t, &calls, &generators)
			publicFixtureInstallSources(validator, input.OutputBindings.Value...)
			control := validator.Validate(context.Background(), input)
			if !control.Valid || !control.Complete || calls != 0 {
				t.Fatalf("admitted control failed: %+v", control.Diagnostics)
			}
			calls = 0
			ctx := &publicAdmissionCancellationContext{Context: context.Background(), ceiling: condition.ceiling, cause: condition.cause}
			got := validator.Validate(ctx, input)
			if got.Valid || got.Complete || calls != 0 || generators != 0 {
				t.Fatalf("ended admission entered interpreter: calls=%d diagnostics=%+v", calls, got.Diagnostics)
			}
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: condition.reason}}
			if !reflect.DeepEqual(got.Diagnostics, want) {
				t.Errorf("admission context reason differs: got %+v want %+v", got.Diagnostics, want)
			}
		})
	}
}

func slicesContainCancelledDiagnostic(rows []contract.Diagnostic) bool {
	for _, row := range rows {
		if row.Reason == contract.ReasonCancelled {
			return true
		}
	}
	return false
}

// full_only: false
func TestPublicConfigurationSharedRoutesRequireEffectiveTargets(t *testing.T) {
	for _, condition := range []string{"member", "nonmember", "missing-default-target", "overridden-default"} {
		t.Run(condition, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			entry := publicFixtureEntry(input, "e")
			other := input.Recipients.Value[1].RecipientID
			if condition != "nonmember" {
				entry.Memberships.Value = append(entry.Memberships.Value, other)
			}
			input.Entries = publicPresent([]contract.PublicEntry{entry, publicFixtureEntry(input, "peer")})
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{
				publicFixtureBinding("a", publicFixtureTarget("peer", "peer-slot")),
				publicFixtureBinding("b", publicFixtureTarget("e", "entry-slot")),
			})
			input.Routing = publicPresent([]contract.PublicRoutingRule{
				{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "peer"}, Destinations: publicPresent([]string{"a"})},
			})
			if condition != "missing-default-target" {
				input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "e"}, Destinations: publicPresent([]string{"b"})})
			}
			if condition == "missing-default-target" || condition == "overridden-default" {
				input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string{"a"})})
			}
			calls, generators := 0, 0
			validator := publicFixtureValidator(t, &calls, &generators)
			publicFixtureInstallSources(validator, input.OutputBindings.Value...)
			got := validator.Validate(context.Background(), input)
			wantValid := condition != "missing-default-target"
			if got.Valid != wantValid || got.Complete != wantValid {
				t.Fatalf("route %s valid=%v complete=%v diagnostics=%+v", condition, got.Valid, got.Complete, got.Diagnostics)
			}
			if condition == "nonmember" && slices.Contains(got.Configuration.Entries.Value[0].Memberships.Value, other) {
				t.Fatal("shared routing granted membership")
			}
		})
	}
}

// full_only: false
func TestPublicConfigurationCancellationOwnsDormantTargets(t *testing.T) {
	for _, state := range []contract.PublicFieldState{contract.PublicMissing, contract.PublicUnavailable} {
		t.Run(strconv.Itoa(int(state)), func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
			location := &contract.SourceLocation{SourceID: strings.Repeat("s", 65), Line: 1, Column: 1}
			dormant := []contract.PublicOutputTarget{publicFixtureTarget("e", "dormant-slot")}
			dormant[0].TargetData.SourceLocation = location
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("a", publicFixtureTarget("e", "active-slot")), publicFixtureBinding("z", publicFixtureTarget("e", "dormant-slot"))})
			input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "e"}, Destinations: publicPresent([]string{"a"})}})
			// Cancellation after capture must still clear dormant mutable backing.
			ctx := &publicAdmissionCancellationContext{Context: context.Background(), ceiling: 9}
			calls, generators := 0, 0
			v := publicFixtureValidator(t, &calls, &generators)
			publicFixtureInstallSources(v, input.OutputBindings.Value...)

			input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
			input.OutputBindings.Value[1].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: state, Value: dormant}
			got := v.Validate(ctx, input)
			if got.Valid || got.Complete || calls != 0 || !slicesContainCancelledDiagnostic(got.Diagnostics) || len(got.Configuration.OutputBindings.Value) != 2 {
				t.Fatalf("cancellation not observed after capture: %+v", got.Diagnostics)
			}
			if dormant[0].TargetData.SourceLocation != location || location.SourceID != strings.Repeat("s", 65) || dormant[0].CanonicalTarget.Value != "dormant-slot" {
				t.Fatal("cancellation changed dormant backing")
			}
			for _, binding := range got.Configuration.OutputBindings.Value {
				if binding.DestinationID == "z" && len(binding.Targets.Value) != 0 {
					t.Fatal("canceled result retained dormant target backing")
				}
			}
		})
	}
}

// Each opaque occurrence is charged even when all rows borrow one payload.
func publicAdmissionAggregatePolicyFixture(t *testing.T, family string) (contract.PublicConfiguration, []byte) {
	t.Helper()
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
	data := make([]byte, 524546)
	for i := range data {
		data[i] = byte(i)
	}
	policy := contract.OutputPolicy{ContractID: "test-policy", Data: data}
	if family == "bindings" {
		input.OutputBindings.Value = make([]contract.PublicOutputBinding, 64)
		for i := range input.OutputBindings.Value {
			target := publicFixtureTarget("e", "slot"+strconv.Itoa(i))
			target.ConsumerPolicy = publicPresent(policy)
			input.OutputBindings.Value[i] = publicFixtureBinding(strconv.Itoa(i), target)
		}
	} else {
		targets := make([]contract.PublicOutputTarget, 64)
		for i := range targets {
			targets[i] = publicFixtureTarget("e", "slot")
			targets[i].ConsumerPolicy = publicPresent(policy)
		}
		input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", targets...)})
	}
	return input, data
}
func publicAdmissionAggregatePolicyUnchanged(t *testing.T, input contract.PublicConfiguration, data []byte) {
	t.Helper()
	for _, binding := range input.OutputBindings.Value {
		for _, target := range binding.Targets.Value {
			if len(target.ConsumerPolicy.Value.Data) != 524546 || &target.ConsumerPolicy.Value.Data[0] != &data[0] {
				t.Fatal("refusal changed borrowed opaque policy")
			}
		}
	}
	for i, b := range data {
		if b != byte(i) {
			t.Fatal("refusal changed policy bytes", i)
		}
	}
}

// full_only: false
func TestPublicConfigurationAggregatePolicyBytesPrecedeCapture(t *testing.T) {
	for _, family := range []string{"bindings", "targets"} {
		t.Run(family, func(t *testing.T) {
			input, data := publicAdmissionAggregatePolicyFixture(t, family)
			calls, generators := 0, 0
			validator := publicFixtureValidator(t, &calls, &generators)
			ctx := &publicAdmissionCancellationContext{Context: context.Background(), ceiling: 100}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			got := validator.Validate(ctx, input)
			runtime.ReadMemStats(&after)
			want := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonLimitExceeded}
			if got.Valid || got.Complete || calls != 0 || generators != 0 || !reflect.DeepEqual(got.Diagnostics, []contract.Diagnostic{want}) || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) || ctx.calls >= ctx.ceiling || after.TotalAlloc-before.TotalAlloc >= 512<<10 {
				t.Fatalf("aggregate reached capture or interpretation: %+v", got.Diagnostics)
			}
			publicAdmissionAggregatePolicyUnchanged(t, input, data)
		})
	}
}

// full_only: false
func TestPublicConfigurationPolicyBytesPrecedeCapture(t *testing.T) {
	input := publicConfigurationFixture(t)
	binding := publicFixtureBinding("d")
	payload := make([]byte, 524547)
	binding.Destination.Value.Policy.Data = payload
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{binding})
	calls, generators := 0, 0
	v := publicFixtureValidator(t, &calls, &generators)
	got := v.Validate(context.Background(), input)
	if got.Valid || got.Complete || calls != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != contract.ReasonLimitExceeded || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) || len(input.OutputBindings.Value[0].Destination.Value.Policy.Data) != len(payload) {
		t.Fatal("oversized opaque policy reached capture", got.Diagnostics)
	}
}

// full_only: false
func TestPublicOutputPolicyBoundedLengthExactBytes(t *testing.T) {
	policy := contract.OutputPolicy{ContractID: "test-policy", Data: make([]byte, 524546)}
	length, ok := publicOutputPolicyBoundedLength(policy)
	if !ok || length != 524567 {
		t.Fatalf("opaque policy frame=%d bounded=%t want524567", length, ok)
	}
	policy.Data = append(policy.Data, 0)
	if _, ok := publicOutputPolicyBoundedLength(policy); ok {
		t.Fatal("524547-byte payload passed bound")
	}
}

// full_only: false
func TestPublicConfigurationSharedPolicyOccurrencesRespectDeclaration(t *testing.T) {
	input, data := publicAdmissionAggregatePolicyFixture(t, "targets")
	calls, generators := 0, 0
	v := publicFixtureValidator(t, &calls, &generators)
	got := v.Validate(context.Background(), input)
	want := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonLimitExceeded}
	if got.Valid || got.Complete || calls != 0 || generators != 0 || !reflect.DeepEqual(got.Diagnostics, []contract.Diagnostic{want}) || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) {
		t.Fatal("shared policy occurrences escaped aggregate", got.Diagnostics)
	}
	publicAdmissionAggregatePolicyUnchanged(t, input, data)
}

func assertPublicSliceOwnership[T comparable](t *testing.T, name string, input, returned []T, changed T) {
	t.Helper()
	if len(returned) == 0 {
		return
	}
	original := input[0]
	input[0] = changed
	if returned[0] == changed {
		t.Errorf("%s: caller mutation changed returned backing", name)
	}
	input[0] = original
	returned[0] = changed
	if input[0] != original {
		t.Errorf("%s: returned mutation changed caller backing", name)
	}
	returned[0] = original
}

// full_only: false
func TestPublicConfigurationCancellationOwnsMutableFields(t *testing.T) {
	for _, phase := range []string{"pre-cancel", "callback", "input-limit"} {
		for _, state := range []contract.PublicFieldState{contract.PublicPresent, contract.PublicMissing, contract.PublicUnavailable, contract.PublicInvalid} {
			t.Run(phase+"/"+strconv.Itoa(int(state)), func(t *testing.T) {
				input := publicConfigurationFixture(t)
				publicRecoveryFixture(t, &input)
				generated := publicFixtureEntry(input, "zz-generated")
				generated.Source = publicPresent(contract.Generated)
				generated.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
				generated.Generated.ContentIntent.State = state
				plain := publicFixtureEntry(input, "z-plain")
				plain.Class = publicPresent(contract.Plain)
				plain.PlainValue = contract.PublicField[[]byte]{State: state, Value: []byte{4}}
				plain.Memberships.State = state
				input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "a-gate"), plain, generated})
				location := &contract.SourceLocation{SourceID: "input", Line: 1, Column: 1}
				input.Entries.Value[1].PlainValue.SourceLocation = location
				target := publicFixtureTarget("a-gate", "slot")
				input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", target)})
				publicFixtureRouteTargets(&input)
				input.Groups = publicPresent([][]string{{"z-plain"}})
				policyInput := input.OutputBindings.Value[0].Destination.Value.Policy.Data
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				outputs, generators := 0, 0
				v := publicFixtureValidator(t, &outputs, &generators)
				publicFixtureInstallSources(v, input.OutputBindings.Value...)
				derive := v.interpret
				v.interpret = func(ctx context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
					target, err := derive(ctx, id, destination, name, encoding)
					cancel()
					return target, err
				}
				input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
				switch phase {
				case "pre-cancel":
					cancel()
				case "input-limit":
					input.Store.Region.Value = strings.Repeat("r", 65)
				}
				got := v.Validate(ctx, input)
				if got.Valid || got.Complete || !got.DiagnosticsComplete {
					t.Fatalf("early status: %+v", got)
				}
				if phase != "callback" {
					if outputs != 0 || !reflect.DeepEqual(got.Configuration, contract.PublicConfiguration{}) {
						t.Fatal("early refusal retained input or interpreted")
					}
					return
				}
				if len(got.Configuration.Entries.Value) != 3 || (state == contract.PublicPresent && (outputs != 1 || !slicesContainCancelledDiagnostic(got.Diagnostics))) || (state != contract.PublicPresent && (outputs != 0 || slicesContainCancelledDiagnostic(got.Diagnostics))) {
					t.Fatalf("callback not reached once: %+v", got.Diagnostics)
				}
				owned := got.Configuration
				assertPublicSliceOwnership(t, "opaque destination policy", policyInput, owned.OutputBindings.Value[0].Destination.Value.Policy.Data, byte(99))
				assertPublicSliceOwnership(t, "plain bytes", plain.PlainValue.Value, owned.Entries.Value[1].PlainValue.Value, byte(99))
				assertPublicSliceOwnership(t, "ContentIntent", generated.Generated.ContentIntent.Value, owned.Entries.Value[2].Generated.ContentIntent.Value, byte(99))
				assertPublicSliceOwnership(t, "memberships", plain.Memberships.Value, owned.Entries.Value[1].Memberships.Value, contract.ID{99})
				assertPublicSliceOwnership(t, "recipient key", input.Recipients.Value[0].Encryption.PublicKey.Value, owned.Recipients.Value[0].Encryption.PublicKey.Value, byte(99))
				assertPublicSliceOwnership(t, "Authority key", input.Authority.Signing.PublicKey.Value, owned.Authority.Signing.PublicKey.Value, byte(99))
				assertPublicSliceOwnership(t, "Recovery signing key", input.Recovery.Signing.PublicKey.Value, owned.Recovery.Signing.PublicKey.Value, byte(99))
				assertPublicSliceOwnership(t, "Recovery encryption key", input.Recovery.Encryption.PublicKey.Value, owned.Recovery.Encryption.PublicKey.Value, byte(99))
				assertPublicSliceOwnership(t, "route destinations", input.Routing.Value[0].Destinations.Value, owned.Routing.Value[0].Destinations.Value, "changed")
				assertPublicSliceOwnership(t, "groups", input.Groups.Value[0], owned.Groups.Value[0], "changed")
				assertPublicSliceOwnership(t, "canonical destination", input.OutputBindings.Value[0].Destination.Value.CanonicalSettings, owned.OutputBindings.Value[0].Destination.Value.CanonicalSettings, byte(99))
				if owned.Entries.Value[2].Generated == generated.Generated || owned.Recovery.Signing == input.Recovery.Signing || owned.Recovery.Encryption == input.Recovery.Encryption {
					t.Error("returned settings borrow pointers")
				}
				if returned := owned.Entries.Value[1].PlainValue.SourceLocation; returned != nil {
					location.Line = 9
					if returned.Line != 1 {
						t.Error("caller changed returned source location")
					}
					returned.Column = 9
					if location.Column != 1 {
						t.Error("returned source location changed caller")
					}
				}
			})
		}
	}
}

// full_only: false
func TestPublicConfigurationEncodingValidationDoesNotDependOnTargets(t *testing.T) {
	for _, targetState := range []contract.PublicFieldState{contract.PublicMissing, contract.PublicUnavailable} {
		for _, condition := range []string{"raw", "base64", "invalid-input", "invalid-output", "zero-input", "zero-output"} {
			t.Run(strconv.Itoa(int(targetState))+"/"+condition, func(t *testing.T) {
				input := publicConfigurationFixture(t)
				input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "a"), publicFixtureEntry(input, "b")})
				binding := publicFixtureBinding("d", publicFixtureTarget("a", "slot-a"), publicFixtureTarget("b", "slot-b"))
				input.OutputBindings = publicPresent([]contract.PublicOutputBinding{binding})
				publicFixtureRouteTargets(&input)
				input.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: targetState}
				input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
				input.Entries.Value[0].InputEncoding = publicPresent(contract.InputEncodingRaw)
				input.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingRaw)
				var invalidField contract.DiagnosticField
				switch condition {
				case "base64":
					input.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingBase64)
				case "invalid-input":
					input.Entries.Value[0].InputEncoding = publicPresent(uint8(99))
					invalidField = contract.FieldInputEncoding
				case "invalid-output":
					input.Entries.Value[0].OutputEncoding = publicPresent(uint8(99))
					invalidField = contract.FieldOutputEncoding
				case "zero-input":
					input.Entries.Value[0].InputEncoding = publicPresent(uint8(0))
					invalidField = contract.FieldInputEncoding
				case "zero-output":
					input.Entries.Value[0].OutputEncoding = publicPresent(uint8(0))
					invalidField = contract.FieldOutputEncoding
				}
				outputs, generators := 0, 0
				v := publicFixtureValidator(t, &outputs, &generators)
				publicFixtureInstallSources(v, binding)
				got := v.Validate(context.Background(), input)
				if got.Complete {
					t.Fatal("unavailable fact became complete")
				}
				var encodingDiagnostics, targetDiagnostics []contract.Diagnostic
				for _, d := range got.Diagnostics {
					if len(d.Path) != 1 {
						continue
					}
					if d.Subject.Kind == contract.SubjectEntry && (d.Path[0] == contract.FieldInputEncoding || d.Path[0] == contract.FieldOutputEncoding) {
						encodingDiagnostics = append(encodingDiagnostics, d)
					}
					if d.Subject.Kind == contract.SubjectOutputBinding && d.Path[0] == contract.FieldTargets {
						targetDiagnostics = append(targetDiagnostics, d)
					}
				}
				var wantTargets []contract.Diagnostic
				if targetState == contract.PublicMissing {
					wantTargets = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonMissingRequiredField}}
				}
				if !reflect.DeepEqual(targetDiagnostics, wantTargets) {
					t.Fatalf("target state diagnostics: %+v, want %+v", targetDiagnostics, wantTargets)
				}
				if invalidField != "" {
					want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a"}, Path: []contract.DiagnosticField{invalidField}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput}}
					if got.Valid || !reflect.DeepEqual(encodingDiagnostics, want) {
						t.Fatalf("encoding failure missing: %+v", got.Diagnostics)
					}
					return
				}
				if len(encodingDiagnostics) != 0 || got.Valid != (targetState == contract.PublicUnavailable) || got.Configuration.Entries.Value[0].OutputEncoding != input.Entries.Value[0].OutputEncoding {
					t.Fatalf("independent entry encoding: %+v", got.Diagnostics)
				}
			})
		}
	}
}

// full_only: false
func TestPublicConfigurationNonpresentBindingsKeepCallerEncodings(t *testing.T) {
	for _, state := range []contract.PublicFieldState{contract.PublicMissing, contract.PublicUnavailable, contract.PublicInvalid} {
		for _, declaration := range []string{"omitted", "raw"} {
			t.Run(strconv.Itoa(int(state))+"/"+declaration, func(t *testing.T) {
				input := publicConfigurationFixture(t)
				input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "a"), publicFixtureEntry(input, "b")})
				binding := publicFixtureBinding("d")
				var wantEncoding contract.PublicField[uint8]
				if declaration == "raw" {
					input.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingRaw)
					wantEncoding = input.Entries.Value[0].OutputEncoding
				}
				input.OutputBindings = contract.PublicField[[]contract.PublicOutputBinding]{State: state, Value: []contract.PublicOutputBinding{binding}}
				v := NewPublicConfigurationValidator(nil)
				got := v.Validate(context.Background(), input)
				reason := contract.ReasonInvalidFieldCombination
				if state == contract.PublicInvalid {
					reason = contract.ReasonInvalidInput
				}
				want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}
				if got.Valid || got.Complete || got.Configuration.OutputBindings.Value != nil || !reflect.DeepEqual(got.Diagnostics, want) {
					t.Fatalf("nonpresent binding refusal: %+v", got)
				}
				if !reflect.DeepEqual(input.Entries.Value[0].OutputEncoding, wantEncoding) {
					t.Fatalf("invalid return changed caller encoding: %+v, want %+v", input.Entries.Value[0].OutputEncoding, wantEncoding)
				}
			})
		}
	}
}

// full_only: false
func TestPublicConfigurationRejectsInvalidRoutingSelectors(t *testing.T) {
	for _, key := range []contract.PublicRoutingKey{
		{},
		{EntrySelector: contract.PublicEntrySelector(255)},
		{EntrySelector: contract.PublicDefaultRoute, EntryName: "entry"},
	} {
		t.Run(fmt.Sprintf("%d/%s", key.EntrySelector, key.EntryName), func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: key, Destinations: publicPresent([]string{})}})
			calls, generators := 0, 0
			v := publicFixtureValidator(t, &calls, &generators)
			got := v.Validate(context.Background(), input)
			if got.Valid || got.Complete || calls != 0 || generators != 0 || !slices.ContainsFunc(got.Diagnostics, func(row contract.Diagnostic) bool {
				return row.Reason == contract.ReasonInvalidInput && row.Subject.Kind == contract.SubjectRoutingRule
			}) {
				t.Fatal("invalid routing selector reached public facts", got.Diagnostics, calls, generators)
			}
		})
	}
}
