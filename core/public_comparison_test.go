package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicComparisonLateFailureClearsCompletedVerdict(t *testing.T) {
	for _, verdict := range []contract.ComparisonVerdict{contract.ComparisonMatch, contract.ComparisonMismatch} {
		for _, failed := range []readerFailure{readerSelectionFailure(failure(EvidenceUnavailable, ReadUnavailable)), readerSelectionFailure(failure(IntegrityFailure, InvalidRelation))} {
			t.Run(string(verdict)+"/"+string(failed.diagnostic), func(t *testing.T) {
				observation := &contract.ComparisonObservation{DomainID: contract.ID{1}, HeadRevisionID: contract.ID{2}, SnapshotID: contract.ID{3}}
				out := PublicComparisonResult{ComparisonPayload: newComparisonPayload(contract.ScopeUnchecked)}
				out.Verdict, out.Observation = verdict, observation
				out.finishComparisonFailure(failed)
				if out.Verdict != contract.ComparisonUnable || out.Observation != observation || out.Result != failed.Result || out.StateResult == contract.ReaderSuccess {
					t.Fatal("required late failure retained a completed verdict or lost its observation/failure", out)
				}
				want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: failed.diagnostic}}
				if !reflect.DeepEqual(out.Diagnostics, want) || !out.DiagnosticsComplete {
					t.Fatal("late failure lost its complete safe diagnostic", out.Diagnostics)
				}
			})
		}
	}
}

// full_only: false
func TestPublicComparisonKeepsAllIndependentFields(t *testing.T) {
	input := publicConfigurationFixture(t)
	input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "a/\nα")})
	input.Entries.Value[0].Class = publicPresent(contract.Plain)
	input.Entries.Value[0].PlainValue = publicPresent([]byte{0, '\n'})
	observed := ownPublicConfiguration(input)
	input.Entries.Value[0].PlainValue = publicPresent([]byte{1, '\n'})
	input.Recipients.Value[1].DisplayName = publicPresent("changed")
	input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
	input.Recipients.Value[0].Encryption.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
	v := NewPublicConfigurationValidator(nil)
	desired := v.Validate(context.Background(), input)
	actual := v.Validate(context.Background(), observed)
	got := comparePublicConfigurations(context.Background(), desired, actual)
	want := []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, Path: []contract.DiagnosticField{contract.FieldSigningPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\nα"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonBytesDiffer},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, Path: []contract.DiagnosticField{contract.FieldEncryptionPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[1].RecipientID}, Path: []contract.DiagnosticField{contract.FieldDisplayName}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
	}
	if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
		t.Fatalf("comparison=%+v", got)
	}
}

// full_only: false
func TestPublicComparisonInvalidSubjectHasPresenceOnly(t *testing.T) {
	w := publicConfigurationFixture(t)
	a := ownPublicConfiguration(w)
	key := contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}
	w.Routing = publicPresent([]contract.PublicRoutingRule{{Key: key, Destinations: publicPresent([]string{"different"})}})
	a.Routing = publicPresent([]contract.PublicRoutingRule{{Key: key, Destinations: publicPresent([]string{"observed"})}})
	d := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: key}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonUnresolvedReference}
	got := comparePublicConfigurations(context.Background(), PublicConfigurationValidation{Configuration: w, Diagnostics: []contract.Diagnostic{d}, DiagnosticsComplete: true}, PublicConfigurationValidation{Configuration: a, DiagnosticsComplete: true})
	if got.Verdict != contract.ComparisonUnable || !reflect.DeepEqual(got.Diagnostics, []contract.Diagnostic{d}) {
		t.Fatalf("invalid subject gained unverified field difference: %+v", got.Diagnostics)
	}
}

// full_only: false
func TestPublicComparisonSourceFaultsKeepIndependentDifference(t *testing.T) {
	w := publicConfigurationFixture(t)
	entry := publicFixtureEntry(w, "plain")
	entry.Class = publicPresent(contract.Plain)
	entry.PlainValue = publicPresent([]byte{0, '\n'})
	w.Entries = publicPresent([]contract.PublicEntry{entry})
	w.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("plain", "slot"))})
	publicFixtureRouteTargets(&w)
	a := ownPublicConfiguration(w)
	w.Entries.Value[0].PlainValue = publicPresent([]byte{1, '\n'})
	w.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
	w.Recipients.Value[0].Encryption.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
	w.OutputBindings.Value[0].Targets.Value[0].TargetContractID = publicPresent("")
	outputCalls, generatorCalls := 0, 0
	v := publicFixtureValidator(t, &outputCalls, &generatorCalls)
	publicFixtureInstallSources(v, a.OutputBindings.Value...)
	got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
	want := []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, Path: []contract.DiagnosticField{contract.FieldSigningPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "plain"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonBytesDiffer},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "d", Name: "plain"}, Path: []contract.DiagnosticField{contract.FieldTargetContract}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonInvalidInput},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: w.Recipients.Value[0].RecipientID}, Path: []contract.DiagnosticField{contract.FieldEncryptionPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
	}
	if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
		t.Fatalf("simultaneous faults=%+v", got)
	}
	for _, scope := range got.CheckedScope {
		expected := contract.ScopeComplete
		switch scope.Family {
		case contract.ScopeAuthorityRecovery, contract.ScopeRecipients, contract.ScopeEncryption, contract.ScopeOutputs, contract.ScopeCompatibilityProfiles:
			expected = contract.ScopePartial
		}
		if scope.Status != expected {
			t.Fatalf("scope=%+v expected=%s", scope, expected)
		}
	}
	if comparisonState(got.Diagnostics, true) != contract.ReaderRefused {
		t.Fatal("unavailability hid invalid canonical target")
	}
}

// full_only: false
func TestPublicComparisonFaultMergeAndUncheckedSections(t *testing.T) {
	v := NewPublicConfigurationValidator(nil)
	input := publicConfigurationFixture(t)
	for _, name := range []string{"entry-set", "registry", "output-set", "routing-set", "duplicate-name", "same-fault", "different-faults"} {
		t.Run(name, func(t *testing.T) {
			w, a := ownPublicConfiguration(input), ownPublicConfiguration(input)
			families := []contract.ComparisonFieldFamily{}
			switch name {
			case "entry-set":
				w.Entries = contract.PublicField[[]contract.PublicEntry]{State: contract.PublicUnavailable}
				families = []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeGenerated}
			case "registry":
				w.Recipients = contract.PublicField[[]contract.PublicRecipient]{State: contract.PublicUnavailable}
				families = []contract.ComparisonFieldFamily{contract.ScopeRecipients, contract.ScopeEncryption}
			case "output-set":
				w.OutputBindings = contract.PublicField[[]contract.PublicOutputBinding]{State: contract.PublicUnavailable}
				families = []contract.ComparisonFieldFamily{contract.ScopeOutputs}
			case "routing-set":
				w.Routing = contract.PublicField[[]contract.PublicRoutingRule]{State: contract.PublicUnavailable}
				families = []contract.ComparisonFieldFamily{contract.ScopeRouting}
			case "duplicate-name":
				w.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(w, ""), publicFixtureEntry(w, "")})
				families = []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeGenerated}
			case "same-fault":
				w.Store.Region = contract.PublicField[string]{State: contract.PublicUnavailable}
				a.Store.Region = w.Store.Region
			case "different-faults":
				w.Store.Region = contract.PublicField[string]{State: contract.PublicUnavailable}
				a.Store.Region = contract.PublicField[string]{}
			}
			got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
			if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete {
				t.Fatal(got)
			}
			if name == "same-fault" && len(got.Diagnostics) != 1 || name == "different-faults" && len(got.Diagnostics) != 2 {
				t.Fatal("fault merge lost or duplicated reasons", got.Diagnostics)
			}
			for _, scope := range got.CheckedScope {
				if slices.Contains(families, scope.Family) && scope.Status != contract.ScopeUnchecked {
					t.Fatal("section remains checked", scope)
				}
			}
		})
	}
}

// full_only: false
func TestPublicComparisonMissingPrerequisitesMarkDependentScope(t *testing.T) {
	base := publicConfigurationFixture(t)
	plain := publicFixtureEntry(base, "plain")
	plain.Class = publicPresent(contract.Plain)
	plain.PlainValue = publicPresent([]byte{0})
	generated := publicFixtureEntry(base, "generated")
	generated.Source = publicPresent(contract.Generated)
	generated.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
	base.Entries = publicPresent([]contract.PublicEntry{generated, plain})
	publicRecoveryFixture(t, &base)
	for _, field := range []contract.DiagnosticField{contract.FieldClass, contract.FieldSource, contract.FieldEnabled} {
		for _, state := range []contract.PublicFieldState{contract.PublicMissing, contract.PublicUnavailable} {
			for _, side := range []string{"desired", "observed"} {
				t.Run(string(field)+"/"+strconv.Itoa(int(state))+"/"+side, func(t *testing.T) {
					w, a := ownPublicConfiguration(base), ownPublicConfiguration(base)
					w.Store.Prefix = publicPresent("independent-difference")
					faulty := &w
					if side == "observed" {
						faulty = &a
					}
					subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry}
					partial := []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopeSecretSettings}
					switch field {
					case contract.FieldClass:
						subject.Name = "plain"
						w.Entries.Value[1].PlainValue = publicPresent([]byte{9})
						faulty.Entries.Value[1].Class = contract.PublicField[uint8]{State: state}
						partial = append(partial, contract.ScopePlainValues)
					case contract.FieldSource:
						subject.Name = "generated"
						w.Entries.Value[0].Generated.Epoch = publicPresent(uint64(1))
						faulty.Entries.Value[0].Source = contract.PublicField[uint8]{State: state}
						partial = append(partial, contract.ScopeGenerated, contract.ScopeCompatibilityProfiles)
					case contract.FieldEnabled:
						subject = contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
						w.Recovery.Encryption.ProtectionClass = publicPresent(contract.HardwareProtection)
						faulty.Recovery.Enabled = contract.PublicField[bool]{State: state}
						partial = []contract.ComparisonFieldFamily{contract.ScopeAuthorityRecovery, contract.ScopeEncryption, contract.ScopeCompatibilityProfiles}
					}
					outputCalls, generatorCalls := 0, 0
					v := publicFixtureValidator(t, &outputCalls, &generatorCalls)
					got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
					reason := contract.ReasonMissingRequiredField
					if state == contract.PublicUnavailable {
						reason = contract.ReasonPublicFactUnavailable
					}
					want := []contract.Diagnostic{
						{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticUnable, Reason: reason},
						{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPrefix}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
					}
					if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
						t.Fatalf("prerequisite fault lost exact independent diagnostics: verdict=%s complete=%t diagnostics=%+v", got.Verdict, got.DiagnosticsComplete, got.Diagnostics)
					}
					families := []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeRecipients, contract.ScopeEncryption, contract.ScopeGenerated, contract.ScopeOutputs, contract.ScopeRouting, contract.ScopeDomainStore, contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles}
					wantScope := make([]contract.ComparisonScope, len(families))
					for i, family := range families {
						status := contract.ScopeComplete
						if slices.Contains(partial, family) {
							status = contract.ScopePartial
						}
						wantScope[i] = contract.ComparisonScope{Family: family, Status: status}
					}
					if !reflect.DeepEqual(got.CheckedScope, wantScope) {
						t.Fatalf("dependent comparison scope=%+v want=%+v", got.CheckedScope, wantScope)
					}
				})
			}
		}
	}
}

// full_only: false
func TestPublicComparisonUnavailableCollectionsMarkProfileScope(t *testing.T) {
	base := publicConfigurationFixture(t)
	base.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(base, "entry")})
	base.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("entry", "slot"))})
	publicFixtureRouteTargets(&base)
	for _, section := range []string{"entries", "recipients", "outputs", "targets"} {
		for _, side := range []string{"desired", "observed"} {
			t.Run(section+"/"+side, func(t *testing.T) {
				w, a := ownPublicConfiguration(base), ownPublicConfiguration(base)
				w.Store.Prefix = publicPresent("independent-difference")
				faulty := &w
				if side == "observed" {
					faulty = &a
				}
				subject := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
				field := contract.FieldPresence
				var unchecked []contract.ComparisonFieldFamily
				switch section {
				case "entries":
					faulty.Entries = contract.PublicField[[]contract.PublicEntry]{State: contract.PublicUnavailable}
					unchecked = []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeGenerated}
				case "recipients":
					faulty.Recipients = contract.PublicField[[]contract.PublicRecipient]{State: contract.PublicUnavailable}
					subject.Kind = contract.SubjectRecipient
					unchecked = []contract.ComparisonFieldFamily{contract.ScopeRecipients, contract.ScopeEncryption}
				case "outputs":
					faulty.OutputBindings = contract.PublicField[[]contract.PublicOutputBinding]{State: contract.PublicUnavailable}
					subject.Kind = contract.SubjectOutputBinding
					unchecked = []contract.ComparisonFieldFamily{contract.ScopeOutputs}
				case "targets":
					faulty.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
					subject = contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}
					field = contract.FieldTargets
				}
				v := NewPublicConfigurationValidator(nil)
				got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
				want := []contract.Diagnostic{
					{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable},
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPrefix}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
				}
				if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
					t.Fatalf("collection fault lost exact independent diagnostics: verdict=%s complete=%t diagnostics=%+v", got.Verdict, got.DiagnosticsComplete, got.Diagnostics)
				}
				families := []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeRecipients, contract.ScopeEncryption, contract.ScopeGenerated, contract.ScopeOutputs, contract.ScopeRouting, contract.ScopeDomainStore, contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles}
				wantScope := make([]contract.ComparisonScope, len(families))
				for i, family := range families {
					status := contract.ScopeComplete
					if slices.Contains(unchecked, family) {
						status = contract.ScopeUnchecked
					} else if family == contract.ScopeCompatibilityProfiles || section == "targets" && family == contract.ScopeOutputs {
						status = contract.ScopePartial
					}
					wantScope[i] = contract.ComparisonScope{Family: family, Status: status}
				}
				if !reflect.DeepEqual(got.CheckedScope, wantScope) {
					t.Fatalf("collection comparison scope=%+v want=%+v", got.CheckedScope, wantScope)
				}
			})
		}
	}
}

// full_only: false
func TestPublicComparisonAbsentSettingsMarkProfileScope(t *testing.T) {
	base := publicConfigurationFixture(t)
	entry := publicFixtureEntry(base, "generated")
	entry.Source = publicPresent(contract.Generated)
	entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
	base.Entries = publicPresent([]contract.PublicEntry{entry})
	publicRecoveryFixture(t, &base)
	for _, owner := range []string{"generated", "signing", "encryption"} {
		for _, absent := range []string{"settings", "field"} {
			for _, side := range []string{"desired", "observed"} {
				t.Run(owner+"/"+absent+"/"+side, func(t *testing.T) {
					w, a := ownPublicConfiguration(base), ownPublicConfiguration(base)
					w.Store.Prefix = publicPresent("independent-difference")
					faulty := &w
					if side == "observed" {
						faulty = &a
					}
					subject := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
					field := contract.FieldSigningPublicKey
					partial := []contract.ComparisonFieldFamily{contract.ScopeAuthorityRecovery}
					switch owner {
					case "generated":
						subject = contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "generated"}
						field = contract.FieldContentIntent
						partial = []contract.ComparisonFieldFamily{contract.ScopeGenerated}
						if absent == "settings" {
							faulty.Entries.Value[0].Generated = nil
						} else {
							faulty.Entries.Value[0].Generated.ContentIntent = contract.PublicField[[]byte]{}
						}
					case "signing":
						if absent == "settings" {
							faulty.Recovery.Signing = nil
						} else {
							faulty.Recovery.Signing.PublicKey = contract.PublicField[[]byte]{}
						}
					case "encryption":
						field = contract.FieldEncryptionPublicKey
						partial = append(partial, contract.ScopeEncryption)
						if absent == "settings" {
							faulty.Recovery.Encryption = nil
						} else {
							faulty.Recovery.Encryption.PublicKey = contract.PublicField[[]byte]{}
						}
					}
					if absent == "settings" && owner != "generated" {
						partial = append(partial, contract.ScopeCompatibilityProfiles)
					}
					path := []contract.DiagnosticField{field}
					if owner == "generated" {
						path = []contract.DiagnosticField{contract.FieldGenerated, field}
					}
					outputCalls, generatorCalls := 0, 0
					v := publicFixtureValidator(t, &outputCalls, &generatorCalls)
					got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
					want := []contract.Diagnostic{
						{Subject: subject, Path: path, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonMissingRequiredField},
						{Subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, Path: []contract.DiagnosticField{contract.FieldPrefix}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
					}
					if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
						t.Fatalf("absent settings lost exact independent diagnostics: verdict=%s complete=%t diagnostics=%+v", got.Verdict, got.DiagnosticsComplete, got.Diagnostics)
					}
					families := []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeRecipients, contract.ScopeEncryption, contract.ScopeGenerated, contract.ScopeOutputs, contract.ScopeRouting, contract.ScopeDomainStore, contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles}
					wantScope := make([]contract.ComparisonScope, len(families))
					for i, family := range families {
						status := contract.ScopeComplete
						if slices.Contains(partial, family) {
							status = contract.ScopePartial
						}
						wantScope[i] = contract.ComparisonScope{Family: family, Status: status}
					}
					if !reflect.DeepEqual(got.CheckedScope, wantScope) {
						t.Fatalf("absent settings comparison scope=%+v want=%+v", got.CheckedScope, wantScope)
					}
				})
			}
		}
	}
}

// full_only: false
func TestPublicComparisonPresenceUnionAndSemanticEmptySets(t *testing.T) {
	v := NewPublicConfigurationValidator(nil)
	w := publicConfigurationFixture(t)
	a := ownPublicConfiguration(w)
	w.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(w, "")})
	a.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(a, "/\nα")})
	w.Recipients.Value = w.Recipients.Value[:1]
	got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
	want := []contract.Diagnostic{
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonObservedEntryAbsent},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "/\nα"}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonExpectedEntryAbsent},
		{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: a.Recipients.Value[1].RecipientID}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonExpectedSettingAbsent},
	}
	want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, contract.ReasonObservedEntryAbsent, contract.FieldName, contract.FieldClass, contract.FieldSource, contract.FieldInputEncoding, contract.FieldOutputEncoding, contract.FieldMemberships)
	want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "/\nα"}, contract.ReasonExpectedEntryAbsent, contract.FieldName, contract.FieldClass, contract.FieldSource, contract.FieldInputEncoding, contract.FieldOutputEncoding, contract.FieldMemberships)
	want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: a.Recipients.Value[1].RecipientID}, contract.ReasonExpectedSettingAbsent, contract.FieldDisplayName, contract.FieldEncryptionProvider, contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint, contract.FieldWrapProfile, contract.FieldProtectionClass)
	if got.Verdict != contract.ComparisonMismatch || !publicComparisonFactsMatch(t, got, want) {
		t.Fatal(got)
	}
	for _, scope := range got.CheckedScope {
		if scope.Status != contract.ScopeComplete {
			t.Fatal(scope)
		}
	}
	w = publicConfigurationFixture(t)
	a = ownPublicConfiguration(w)
	a.Groups.Value = nil
	w.Groups.Value = [][]string{}
	got = comparePublicConfigurations(context.Background(), v.Validate(context.Background(), w), v.Validate(context.Background(), a))
	if got.Verdict != contract.ComparisonMatch {
		t.Fatal("semantic empty collection became difference", got)
	}
}

// full_only: false
func TestPublicComparisonRequestMeaningAndOwnedValidation(t *testing.T) {
	// Independent literals: Python hashlib.sha256(struct.pack('>Q', n) + b'x'*n).
	for _, tc := range []struct {
		n      int
		digest string
	}{
		{0, "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"},
		{4095, "e742a7727d56a10f4a053c4a2919e7d5bab9d43cae7cc51697c26ed2c9d5c4ac"},
		{4096, "b58b9363072bfb947dc30eda689f27702a9a104912f1f6d86525ff49aed13986"},
		{4097, "d2929e46b4b2f5eef6ab3022802471647ac98fba31d1d1b20fd9042f4e13400b"},
		{8193, "02355063dbeadd530e88f39ee452267ede9c77a3372361490c7ffac19ce1cffe"},
	} {
		t.Run(strconv.Itoa(tc.n), func(t *testing.T) {
			h := sha256.New()
			hashPublicSemantic(h, reflect.ValueOf(strings.Repeat("x", tc.n)))
			if hex.EncodeToString(h.Sum(nil)) != tc.digest {
				t.Fatal("framed string digest differs")
			}
		})
	}
	v := NewPublicConfigurationValidator(nil)
	input := publicConfigurationFixture(t)
	owned := ownPublicConfiguration(input)
	key := owned.Authority.Signing.PublicKey.Value
	got := v.validateOwned(context.Background(), owned, false)
	if !got.Valid || !got.Complete || len(got.Diagnostics) != 0 || unsafe.SliceData(got.Configuration.Authority.Signing.PublicKey.Value) != unsafe.SliceData(key) {
		t.Fatal("exclusive validation cloned or changed meaning")
	}
	nonce := contract.Hash([]byte("request nonce"))
	first := publicComparisonRequestDigest(nonce, got)
	input.Store.Region.SourceLocation = &contract.SourceLocation{SourceID: "source", Line: 1, Column: 1}
	second := publicComparisonRequestDigest(nonce, v.Validate(context.Background(), input))
	if first != second {
		t.Fatal("source presentation changed semantic identity")
	}
	input.Store.Prefix.Value = "different"
	if first == publicComparisonRequestDigest(nonce, v.Validate(context.Background(), input)) || first == publicComparisonRequestDigest(contract.Hash([]byte("other nonce")), got) {
		t.Fatal("request failed to bind semantic input or caller nonce")
	}
}

// full_only: false
func TestPublicComparisonDiagnosticBackingBound(t *testing.T) {
	// Entry and generated slots include structural allowances. Only 128
	// entries per side can carry generated settings. Targets have eleven
	// fields plus presence; preliminary route rows may still be invalid.
	const fields = 2*(512*6+128*8) + 2*256*8 + 2*64*4 + 2*1024*12 + 2*59918 + 66
	const count = 160060
	if fields != 157278 || fields > count || count != contract.MaxPublicDiagnostics || unsafe.Sizeof(contract.Diagnostic{}) != 200 || unsafe.Sizeof(contract.SourceLocation{}) != 32 || unsafe.Sizeof(contract.DiagnosticField("")) != 16 {
		t.Fatal("diagnostic inventory/layout changed")
	}
	const names = 2*(512*6+128*8)*256 + 2*1024*12*512 + 2*59918*256 + 2*64*4*256
	const peak = 3*count*200 + names + count*32 + count*96 + 65536
	const budget = count*1024 + 65536
	if names != 45489152 || peak != 162078368 || budget != 163966976 || peak > budget {
		t.Fatal("diagnostic owners exceed shared backing account")
	}
}

// full_only: true
// Proves the whole diagnostic count ceiling; small field construction is covered
// by TestPublicComparisonKeepsAllIndependentFields.
func TestPublicComparisonDiagnosticCapacityPreventsCompleteVerdict(t *testing.T) {
	p := newComparisonPayload(contract.ScopeComplete)
	p.Verdict = contract.ComparisonMatch
	p.Diagnostics = make([]contract.Diagnostic, contract.MaxPublicDiagnostics)
	appendComparisonDiagnostic(&p, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonProofInvalid})
	if p.DiagnosticsComplete || p.Verdict != contract.ComparisonUnable || len(p.Diagnostics) != contract.MaxPublicDiagnostics || p.Diagnostics[len(p.Diagnostics)-1].Reason != contract.ReasonDiagnosticsIncomplete {
		t.Fatal("diagnostic overflow escaped as complete", p.Verdict)
	}
}

// full_only: false
func TestPublicComparisonFieldInventory(t *testing.T) {
	input := publicConfigurationFixture(t)
	encryption := input.Recipients.Value[0].Encryption
	signing := input.Authority.Signing
	subjects := []struct {
		name    string
		subject contract.DiagnosticSubject
		field   contract.DiagnosticField
		reason  contract.DiagnosticReason
		run     func(*publicComparisonBuilder)
	}{
		{name: "encryption-EncryptionProvider", subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, field: contract.FieldEncryptionProvider, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := encryption, encryption
			w.Provider.Value = contract.AWS
			b.compareEncryption(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, w, a)
		}},
		{name: "encryption-EncryptionSelector", subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, field: contract.FieldEncryptionSelector, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := encryption, encryption
			w.Selector.Value = "other"
			b.compareEncryption(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, w, a)
		}},
		{name: "encryption-EncryptionPublicKey", subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, field: contract.FieldEncryptionPublicKey, reason: contract.ReasonBytesDiffer, run: func(b *publicComparisonBuilder) {
			w, a := encryption, encryption
			w.PublicKey.Value = []byte{7}
			b.compareEncryption(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, w, a)
		}},
		{name: "encryption-EncryptionFingerprint", subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, field: contract.FieldEncryptionFingerprint, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := encryption, encryption
			w.Fingerprint.Value[0] ^= 1
			b.compareEncryption(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, w, a)
		}},
		{name: "encryption-WrapProfile", subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, field: contract.FieldWrapProfile, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := encryption, encryption
			w.WrapProfile.Value++
			b.compareEncryption(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, w, a)
		}},
		{name: "encryption-ProtectionClass", subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, field: contract.FieldProtectionClass, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := encryption, encryption
			w.ProtectionClass.Value = contract.HardwareProtection
			b.compareEncryption(contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: input.Recipients.Value[0].RecipientID}, w, a)
		}},
		{name: "signing-SigningProvider", subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, field: contract.FieldSigningProvider, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := signing, signing
			w.Provider.Value = contract.AWS
			b.compareSigning(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, w, a)
		}},
		{name: "signing-SigningSelector", subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, field: contract.FieldSigningSelector, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := signing, signing
			w.Selector.Value = "other"
			b.compareSigning(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, w, a)
		}},
		{name: "signing-SigningPublicKey", subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, field: contract.FieldSigningPublicKey, reason: contract.ReasonBytesDiffer, run: func(b *publicComparisonBuilder) {
			w, a := signing, signing
			w.PublicKey.Value = []byte{7}
			b.compareSigning(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, w, a)
		}},
		{name: "signing-SigningFingerprint", subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, field: contract.FieldSigningFingerprint, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := signing, signing
			w.Fingerprint.Value[0] ^= 1
			b.compareSigning(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, w, a)
		}},
		{name: "signing-SigningRole", subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, field: contract.FieldSigningRole, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := signing, signing
			w.Role.Value = contract.RecoverySigningRole
			b.compareSigning(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, w, a)
		}},
		{name: "signing-SigningProfile", subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, field: contract.FieldSigningProfile, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := signing, signing
			w.Profile.Value++
			b.compareSigning(contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, w, a)
		}},
		{name: "store-Region", subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, field: contract.FieldRegion, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.Region.Value = "other"
			b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
		}},
		{name: "store-Bucket", subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, field: contract.FieldBucket, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.Bucket.Value = "other"
			b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
		}},
		{name: "store-Prefix", subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, field: contract.FieldPrefix, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.Prefix.Value = "other"
			b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
		}},
		{name: "store-ExpectedOwner", subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, field: contract.FieldExpectedOwner, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.ExpectedOwner.Value = "other"
			b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
		}},
		{name: "store-Provider", subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, field: contract.FieldProvider, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.Provider.Value = contract.AWS
			b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
		}},
		{name: "store-ConstructionProfile", subject: contract.DiagnosticSubject{Kind: contract.SubjectStore}, field: contract.FieldConstructionProfile, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.ConstructionProfile.Value++
			b.compareStoreFields(contract.DiagnosticSubject{Kind: contract.SubjectStore}, w, a)
		}},

		{name: "domain", subject: contract.DiagnosticSubject{Kind: contract.SubjectDomain}, field: contract.FieldDomainID, reason: contract.ReasonFieldDiffers, run: func(b *publicComparisonBuilder) {
			w, a := input.Store, input.Store
			w.DomainID.Value[0] ^= 1
			b.compareStore(w, a)
		}},
	}
	for _, row := range subjects {
		t.Run(row.name, func(t *testing.T) {
			b := publicComparisonBuilder{payload: newComparisonPayload(contract.ScopeComplete), unavailable: map[publicDiagnosticFieldKey]bool{}}
			row.run(&b)
			b.finish(context.Background())
			want := []contract.Diagnostic{{Subject: row.subject, Path: []contract.DiagnosticField{row.field}, Outcome: contract.DiagnosticDifference, Reason: row.reason}}
			if b.payload.Verdict != contract.ComparisonMismatch || !publicComparisonFactsMatch(t, b.payload, want) {
				t.Fatalf("field inventory=%+v want=%+v", b.payload.Diagnostics, want)
			}
		})
	}
	for _, field := range []contract.DiagnosticField{contract.FieldServiceContract, contract.FieldTargetContract, contract.FieldCanonicalTarget, contract.FieldConsumerLocator, contract.FieldTargetData, contract.FieldPayloadEncoding, contract.FieldLocatorRequiresCreation, contract.FieldCapabilities, contract.FieldCreateValueBounds, contract.FieldWriteValueBounds, contract.FieldConsumerPolicy} {
		t.Run("output-"+string(field), func(t *testing.T) {
			a := publicFixtureTarget("entry", "slot")
			w := a
			reason := contract.ReasonFieldDiffers
			switch field {
			case contract.FieldServiceContract:
				w.ServiceContractID.Value = "other"
			case contract.FieldTargetContract:
				w.TargetContractID.Value = "other"
			case contract.FieldCanonicalTarget:
				w.CanonicalTarget.Value = "other"
			case contract.FieldConsumerLocator:
				w.ConsumerLocator.Value = "other"
			case contract.FieldTargetData:
				w.TargetData.Value = []byte("other")
				reason = contract.ReasonBytesDiffer
			case contract.FieldPayloadEncoding:
				w.PayloadEncoding.Value = contract.OutputEncodingBase64
			case contract.FieldLocatorRequiresCreation:
				w.LocatorRequiresCreation.Value = true
			case contract.FieldCapabilities:
				w.Capabilities.Value = contract.OutputCapabilityWriteValue
			case contract.FieldCreateValueBounds:
				w.CreateValueBounds.Value = contract.OutputPayloadBounds{Minimum: 1, Maximum: 1}
			case contract.FieldWriteValueBounds:
				w.WriteValueBounds.Value.Maximum--
			case contract.FieldConsumerPolicy:
				w.ConsumerPolicy.Value.ContractID = "other"
			}
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "destination", Name: "entry"}
			b := publicComparisonBuilder{payload: newComparisonPayload(contract.ScopeComplete), unavailable: map[publicDiagnosticFieldKey]bool{}}
			b.compareOutputTarget(subject, w, a)
			b.finish(context.Background())
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticDifference, Reason: reason}}
			if !publicComparisonFactsMatch(t, b.payload, want) {
				t.Fatalf("output field=%+v", b.payload.Diagnostics)
			}
		})
	}

}

// full_only: false
func TestPublicComparisonGeneratedFieldsResolveCanonicalMeaning(t *testing.T) {
	entry := publicFixtureEntry(publicConfigurationFixture(t), "generated")
	entry.Source = publicPresent(contract.Generated)
	entry.Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
	for _, field := range []contract.DiagnosticField{contract.FieldEpoch, contract.FieldResourceContract, contract.FieldConfigContract, contract.FieldLifecycle, contract.FieldContentIntent, contract.FieldRetirement, contract.FieldCompletion} {
		t.Run(string(field), func(t *testing.T) {
			original := entry
			g := *entry.Generated
			w := entry
			w.Generated = &g
			reason := contract.ReasonFieldDiffers
			switch field {
			case contract.FieldEpoch:
				w.Generated.Epoch.Value++
			case contract.FieldResourceContract:
				w.Generated.ResourceContractID.Value[0] ^= 1
			case contract.FieldConfigContract:
				w.Generated.ConfigContractID.Value[0] ^= 1
			case contract.FieldLifecycle:
				w.Generated.LifecycleMode.Value = contract.GeneratorLifecycleNone
			case contract.FieldContentIntent:
				w.Generated.ContentIntent.Value = []byte{8}
				reason = contract.ReasonBytesDiffer
			case contract.FieldRetirement:
				w.Generated.Retirement.Value = contract.GeneratedRetirementAuto
			case contract.FieldCompletion:
				w.Generated.Completion.Value = contract.GeneratedCompletionConfirmed
			}
			b := publicComparisonBuilder{payload: newComparisonPayload(contract.ScopeComplete), unavailable: map[publicDiagnosticFieldKey]bool{}}
			b.compareEntry(w, original)
			b.finish(context.Background())
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: entry.Name}, Path: []contract.DiagnosticField{contract.FieldGenerated, field}, Outcome: contract.DiagnosticDifference, Reason: reason}}
			if !publicComparisonFactsMatch(t, b.payload, want) {
				t.Fatal(b.payload.Diagnostics)
			}
		})
	}
	t.Run("canonical-copy", func(t *testing.T) {
		w := entry
		g := *entry.Generated
		w.Generated = &g
		w.Generated.ContentIntent.Value = append([]byte{}, entry.Generated.ContentIntent.Value...)
		b := publicComparisonBuilder{payload: newComparisonPayload(contract.ScopeComplete), unavailable: map[publicDiagnosticFieldKey]bool{}}
		b.compareEntry(w, entry)
		b.finish(context.Background())
		if b.payload.Verdict != contract.ComparisonMatch {
			t.Fatal("equal canonical meaning changed with backing", b.payload.Diagnostics)
		}
	})
}

// full_only: false
func TestPublicComparisonEntryRegistryAndControlFields(t *testing.T) {
	for _, name := range []string{"class", "source", "memberships", "display", "authority", "recovery"} {
		t.Run(name, func(t *testing.T) {
			w := publicConfigurationFixture(t)
			entry := publicFixtureEntry(w, "e")
			w.Entries = publicPresent([]contract.PublicEntry{entry})
			a := ownPublicConfiguration(w)
			subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "e"}
			field := contract.FieldClass
			reason := contract.ReasonFieldDiffers
			switch name {
			case "class":
				w.Entries.Value[0].Class = publicPresent(contract.Plain)
				w.Entries.Value[0].PlainValue = publicPresent([]byte{})
			case "source":
				w.Entries.Value[0].Source = publicPresent(contract.Generated)
				w.Entries.Value[0].Generated = publicFixtureGenerated(t, contract.GeneratorLifecycleManaged)
				w.Entries.Value[0].Generated.Epoch.Value = 1
				field = contract.FieldSource
			case "memberships":
				w.Entries.Value[0].Memberships.Value = append(w.Entries.Value[0].Memberships.Value, w.Recipients.Value[1].RecipientID)
				field = contract.FieldMemberships
				reason = contract.ReasonSetDiffers
			case "display":
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: w.Recipients.Value[1].RecipientID}
				w.Recipients.Value[1].DisplayName.Value = "changed"
				field = contract.FieldDisplayName
			case "authority":
				w.Entries = publicPresent([]contract.PublicEntry{})
				a.Entries = publicPresent([]contract.PublicEntry{})
				w.Authority.RecipientID.Value = w.Recipients.Value[1].RecipientID
				subject = contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
				field = contract.FieldRecipientID
			case "recovery":
				publicRecoveryFixture(t, &w)
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
				field = contract.FieldEnabled
			}
			calls, generators := 0, 0
			v := publicFixtureValidator(t, &calls, &generators)
			desired, observed := v.Validate(context.Background(), w), v.Validate(context.Background(), a)
			if !desired.Complete || !desired.Valid || !observed.Complete || !observed.Valid {
				t.Fatalf("invalid proving inputs: desired=%+v observed=%+v", desired.Diagnostics, observed.Diagnostics)
			}
			got := comparePublicConfigurations(context.Background(), desired, observed)
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticDifference, Reason: reason}}
			switch name {
			case "class":
				want = appendExpectedPublicFields(want, subject, contract.ReasonObservedSettingAbsent, contract.FieldPlainValue)
			case "source":
				want = appendExpectedGeneratedFields(want, subject)
			case "recovery":
				want = appendExpectedPublicFields(want, subject, contract.ReasonObservedSettingAbsent, contract.FieldSigningProvider, contract.FieldSigningSelector, contract.FieldSigningPublicKey, contract.FieldSigningFingerprint, contract.FieldSigningRole, contract.FieldSigningProfile, contract.FieldEncryptionProvider, contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint, contract.FieldWrapProfile, contract.FieldProtectionClass)
			}
			if got.Verdict != contract.ComparisonMismatch || !publicComparisonFactsMatch(t, got, want) {
				t.Fatal(got.Diagnostics)
			}
		})
	}
}

// full_only: false
func TestPublicComparisonOutputTargetAndRoutingKeySets(t *testing.T) {
	for _, name := range []string{"binding", "target-set", "default-vs-empty-name", "policy-exact-bytes"} {
		t.Run(name, func(t *testing.T) {
			w := publicConfigurationFixture(t)
			w.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(w, "")})
			binding := publicFixtureBinding("d", publicFixtureTarget("", "slot"), publicFixtureTarget("other", "other-slot"))
			w.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("", "slot"))})
			named := contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry}
			defaultRoute := contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}
			w.Routing = publicPresent([]contract.PublicRoutingRule{{Key: named, Destinations: publicPresent([]string{"d"})}})
			a := ownPublicConfiguration(w)
			var want []contract.Diagnostic
			switch name {
			case "binding":
				w.OutputBindings.Value = nil
				w.Routing.Value = nil
				a.Routing.Value = nil
				a.OutputBindings.Value[0].Targets = publicPresent([]contract.PublicOutputTarget{})
				want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonExpectedSettingAbsent}}
			case "target-set":
				w.Entries.Value = append(w.Entries.Value, publicFixtureEntry(w, "other"))
				a.Entries.Value = append(a.Entries.Value, publicFixtureEntry(a, "other"))
				w.OutputBindings.Value[0].Targets.Value = append(w.OutputBindings.Value[0].Targets.Value, publicFixtureTarget("other", "other-slot"))
				other := named
				other.EntryName = "other"
				w.Routing.Value = append(w.Routing.Value, contract.PublicRoutingRule{Key: other, Destinations: publicPresent([]string{"d"})})
				want = []contract.Diagnostic{
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}, Path: []contract.DiagnosticField{contract.FieldTargets}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonSetDiffers},
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "d", Name: "other"}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonObservedSettingAbsent},
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: other}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonObservedSettingAbsent},
				}
			case "default-vs-empty-name":
				a.Routing.Value[0].Key = defaultRoute
				want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: named}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonObservedSettingAbsent}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: defaultRoute}, Path: []contract.DiagnosticField{contract.FieldDestinations}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonSetDiffers}}
			case "policy-exact-bytes":
				w.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value.Data = []byte{7, 3}
				w.OutputBindings.Value[0].Destination.Value.Policy.Data = []byte{7, 3}
				want = []contract.Diagnostic{
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}, Path: []contract.DiagnosticField{contract.FieldDestination}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "d", Name: ""}, Path: []contract.DiagnosticField{contract.FieldConsumerPolicy}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
				}
			}
			switch name {
			case "binding":
				want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}, contract.ReasonExpectedSettingAbsent, contract.FieldDestination, contract.FieldTargets)
			case "target-set":
				want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "d", Name: "other"}, contract.ReasonObservedSettingAbsent, contract.FieldServiceContract, contract.FieldTargetContract, contract.FieldCanonicalTarget, contract.FieldConsumerLocator, contract.FieldTargetData, contract.FieldPayloadEncoding, contract.FieldLocatorRequiresCreation, contract.FieldCapabilities, contract.FieldCreateValueBounds, contract.FieldWriteValueBounds, contract.FieldConsumerPolicy)
				want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "other"}}, contract.ReasonObservedSettingAbsent, contract.FieldDestinations)
			case "default-vs-empty-name":
				want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: named}, contract.ReasonObservedSettingAbsent, contract.FieldDestinations)
			}
			calls, generators := 0, 0
			v := publicFixtureValidator(t, &calls, &generators)
			publicFixtureInstallSources(v, binding)
			desired, observed := v.Validate(context.Background(), w), v.Validate(context.Background(), a)
			if !desired.Complete || !observed.Complete {
				t.Fatalf("invalid fixture desired=%+v actual=%+v", desired.Diagnostics, observed.Diagnostics)
			}
			got := comparePublicConfigurations(context.Background(), desired, observed)
			if !publicComparisonFactsMatch(t, got, want) || got.Verdict != contract.ComparisonMismatch {
				t.Fatal(got.Diagnostics)
			}
		})
	}
}

// full_only: false
func TestPublicComparisonOutputSourceFields(t *testing.T) {
	for _, name := range []string{"destination-policy", "encoding", "groups", "explicit-raw"} {
		t.Run(name, func(t *testing.T) {
			w := publicConfigurationFixture(t)
			w.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(w, "")})
			source := publicFixtureBinding("d", publicFixtureTarget("", "slot"))
			w.OutputBindings = publicPresent([]contract.PublicOutputBinding{source})
			publicFixtureRouteTargets(&w)
			w.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
			a := ownPublicConfiguration(w)
			var want []contract.Diagnostic
			binding := contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "d"}
			target := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "d", Name: ""}
			switch name {
			case "destination-policy":
				w.OutputBindings.Value[0].Destination.Value.Policy.ContractID = "other-policy"
				want = []contract.Diagnostic{
					{Subject: binding, Path: []contract.DiagnosticField{contract.FieldDestination}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
					{Subject: target, Path: []contract.DiagnosticField{contract.FieldConsumerPolicy}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
				}
			case "encoding":
				w.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingBase64)
				want = []contract.Diagnostic{
					{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, Path: []contract.DiagnosticField{contract.FieldOutputEncoding}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
					{Subject: target, Path: []contract.DiagnosticField{contract.FieldPayloadEncoding}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers},
				}
			case "groups":
				w.Groups = publicPresent([][]string{{""}})
				want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldGroups}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonSetDiffers}}
			case "explicit-raw":
				w.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingRaw)
			}
			calls, generators := 0, 0
			v := publicFixtureValidator(t, &calls, &generators)
			publicFixtureInstallSources(v, source)
			desired, observed := v.Validate(context.Background(), w), v.Validate(context.Background(), a)
			if !desired.Complete || !observed.Complete {
				t.Fatalf("invalid source comparison desired=%+v observed=%+v", desired.Diagnostics, observed.Diagnostics)
			}
			got := comparePublicConfigurations(context.Background(), desired, observed)
			verdict := contract.ComparisonMismatch
			if name == "explicit-raw" {
				verdict = contract.ComparisonMatch
			}
			if got.Verdict != verdict || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
				t.Fatalf("source comparison=%+v want=%+v", got.Diagnostics, want)
			}
		})
	}
}

// full_only: false
func TestPublicComparisonUnavailableFactKeepsCanonicalEncodings(t *testing.T) {
	for _, condition := range []string{"permuted", "explicit-raw", "independent-difference"} {
		t.Run(condition, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "a"), publicFixtureEntry(input, "b")})
			for i := range input.Entries.Value {
				input.Entries.Value[i].Class = publicPresent(contract.Plain)
				input.Entries.Value[i].PlainValue = publicPresent([]byte{byte(i)})
			}
			input.OutputBindings = publicPresent([]contract.PublicOutputBinding{publicFixtureBinding("d", publicFixtureTarget("a", "slot-a"), publicFixtureTarget("b", "slot-b"))})
			publicFixtureRouteTargets(&input)
			if condition == "permuted" {
				for i := range input.Entries.Value {
					input.Entries.Value[i].OutputEncoding = publicPresent(contract.OutputEncodingBase64)
				}
				for i := range input.OutputBindings.Value[0].Targets.Value {
					input.OutputBindings.Value[0].Targets.Value[i].PayloadEncoding.Value = contract.OutputEncodingBase64
				}
			}
			observed := ownPublicConfiguration(input)
			if condition == "permuted" {
				slices.Reverse(input.Entries.Value)
			} else {
				input.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingRaw)
			}
			input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, Path: []contract.DiagnosticField{contract.FieldSigningPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}
			if condition == "independent-difference" {
				input.Entries.Value[1].PlainValue.Value[0] = 9
				want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "b"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonBytesDiffer})
			}
			outputs, generators := 0, 0
			v := publicFixtureValidator(t, &outputs, &generators)
			publicFixtureInstallSources(v, input.OutputBindings.Value...)
			got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), input), v.Validate(context.Background(), observed))
			if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
				t.Fatalf("independent comparison: %+v, want %+v", got.Diagnostics, want)
			}
		})
	}
}

// full_only: false
func TestPublicComparisonUnavailableFactKeepsDefaultGroups(t *testing.T) {
	for _, observedNonempty := range []bool{false, true} {
		name := "empty"
		if observedNonempty {
			name = "nonempty"
		}
		t.Run(name, func(t *testing.T) {
			input := publicConfigurationFixture(t)
			input.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(input, "e")})
			input.Groups = contract.PublicField[[][]string]{}
			observed := ownPublicConfiguration(input)
			observed.Groups = publicPresent([][]string{})
			if observedNonempty {
				observed.Groups.Value = [][]string{{"e"}}
			}
			input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
			v := NewPublicConfigurationValidator(nil)
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, Path: []contract.DiagnosticField{contract.FieldSigningPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}
			if observedNonempty {
				want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldGroups}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonSetDiffers})
			}
			got := comparePublicConfigurations(context.Background(), v.Validate(context.Background(), input), v.Validate(context.Background(), observed))
			if got.Verdict != contract.ComparisonUnable || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got, want) {
				t.Fatalf("default groups comparison: %+v, want %+v", got.Diagnostics, want)
			}
		})
	}
}

// full_only: false
func TestPublicComparisonRequestV4IndependentEmptyProjection(t *testing.T) {
	// Python hashlib.sha256 over the v4 prefix and nonce(01+31*00), then:
	// five empty PublicField vectors(80 bytes); Store 368; Authority 624;
	// Recovery 18; scope vector 448. PublicField state/numerics and lengths are
	// uint64be, ID arrays are length 32 then 32 uint64be bytes, nil pointers 00.
	// Scope rows are the 12 declared families in order, each with "unchecked".
	// The complete preimage is 1,604 bytes. Source locations are excluded.
	// Generated semantic identity is carried by the canonical entry settings.
	want, err := hex.DecodeString("fade6b01b0898a66a49751b4b185240e05b628156f86248ead89ad71dc9dad7f")
	if err != nil {
		t.Fatal(err)
	}
	got := publicComparisonRequestDigest(contract.ID{1}, PublicConfigurationValidation{})
	if !bytes.Equal(got[:], want) {
		t.Fatalf("independent v4 request digest=%x", got)
	}
}
