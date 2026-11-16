package core

import (
	"bytes"
	"context"
	"encoding/json"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func comparisonGenesisInput(t *testing.T, env fixtureEnvironment, s *StateSession) contract.PublicConfiguration {
	t.Helper()
	p := func(v string) contract.PublicField[string] {
		return contract.PublicField[string]{State: contract.PublicPresent, Value: v}
	}
	c := env.Store.(contract.StoreConfigurationSource).StoreConfiguration()
	signing := s.root.CurrentAccess.Core.NormalSigning
	input := contract.PublicConfiguration{
		Entries:        contract.PublicField[[]contract.PublicEntry]{State: contract.PublicPresent},
		Recipients:     contract.PublicField[[]contract.PublicRecipient]{State: contract.PublicPresent},
		OutputBindings: contract.PublicField[[]contract.PublicOutputBinding]{State: contract.PublicPresent},
		Routing:        contract.PublicField[[]contract.PublicRoutingRule]{State: contract.PublicPresent},
		Store:          contract.PublicStoreSettings{DomainID: contract.PublicField[contract.ID]{State: contract.PublicPresent, Value: env.Domain}, Provider: contract.PublicField[contract.Family]{State: contract.PublicPresent, Value: c.Provider}, ConstructionProfile: contract.PublicField[uint16]{State: contract.PublicPresent, Value: c.ConstructionProfile}, Region: p(c.Region), Bucket: p(c.Bucket), Prefix: p(c.PrefixBeforeHEAD), ExpectedOwner: p(c.ExpectedOwner)},
		Authority:      contract.PublicAuthoritySettings{RecipientID: contract.PublicField[contract.ID]{State: contract.PublicPresent, Value: s.root.CurrentAccess.Core.AuthorityRecipientID}, Signing: contract.PublicSigningSettings{Provider: contract.PublicField[contract.Family]{State: contract.PublicPresent, Value: signing.Provider}, Selector: p(signing.KeySelector), PublicKey: contract.PublicField[[]byte]{State: contract.PublicPresent, Value: signing.SPKI}, Fingerprint: contract.PublicField[contract.ID]{State: contract.PublicPresent, Value: signing.Fingerprint}, Role: contract.PublicField[uint8]{State: contract.PublicPresent, Value: signing.Role}, Profile: contract.PublicField[uint16]{State: contract.PublicPresent, Value: signing.SigningProfile}}},
		Recovery:       contract.PublicRecoverySettings{Enabled: contract.PublicField[bool]{State: contract.PublicPresent, Value: false}},
	}
	for _, page := range s.recipients {
		if page == nil {
			continue
		}
		for _, r := range page.Slots {
			if r == nil {
				continue
			}
			b := r.CurrentBinding
			input.Recipients.Value = append(input.Recipients.Value, contract.PublicRecipient{RecipientID: r.RecipientID, DisplayName: p(r.DisplayName), Encryption: contract.PublicEncryptionSettings{Provider: contract.PublicField[contract.Family]{State: contract.PublicPresent, Value: b.Provider}, Selector: p(b.KeySelector), PublicKey: contract.PublicField[[]byte]{State: contract.PublicPresent, Value: b.SPKI}, Fingerprint: contract.PublicField[contract.ID]{State: contract.PublicPresent, Value: b.Fingerprint}, WrapProfile: contract.PublicField[uint16]{State: contract.PublicPresent, Value: b.WrapProfile}, ProtectionClass: contract.PublicField[uint8]{State: contract.PublicPresent, Value: b.ProtectionClass}}})
		}
	}
	return input
}

// full_only: false
func TestReaderComparisonAuthenticatesCompleteEmptyConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	e, _, _ := readerEngineFixture(t, env, f.session)
	input := comparisonGenesisInput(t, env, f.session)
	request := contract.Hash([]byte("caller comparison request"))
	got := e.Compare(ctx, request, input)
	if got.Verdict != contract.ComparisonMatch || got.Result.Outcome != ObservedCurrent || got.Observation == nil || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || got.Context.RequestID != request {
		t.Fatalf("comparison=%+v", got)
	}
	for _, scope := range got.CheckedScope {
		if scope.Status != contract.ScopeComplete {
			t.Fatalf("incomplete scope=%+v", scope)
		}
	}
}

func comparisonCurrentInput(t *testing.T, env fixtureEnvironment, s *StateSession) contract.PublicConfiguration {
	t.Helper()
	input := comparisonGenesisInput(t, env, s)
	for _, name := range s.root.Names {
		entry := s.valueEntry(name.Slot)
		row := contract.PublicEntry{Name: name.Name, Class: publicPresent(entry.ConfidentialityClass), Source: publicPresent(entry.ValueSource), InputEncoding: publicPresent(entry.InputEncoding), OutputEncoding: publicPresent(entry.OutputEncoding), Memberships: publicPresent(entry.Recipients)}
		if entry.ConfidentialityClass == contract.Plain {
			row.PlainValue = publicPresent(entry.ValueBytes)
		}
		input.Entries.Value = append(input.Entries.Value, row)
	}
	if r := s.root.CurrentAccess.Core.Recovery; r != nil {
		signing := contract.PublicSigningSettings{Provider: publicPresent(r.Signing.Provider), Selector: publicPresent(r.Signing.KeySelector), PublicKey: publicPresent(r.Signing.SPKI), Fingerprint: publicPresent(r.Signing.Fingerprint), Role: publicPresent(r.Signing.Role), Profile: publicPresent(r.Signing.SigningProfile)}
		encryption := contract.PublicEncryptionSettings{Provider: publicPresent(r.KMS.Provider), Selector: publicPresent(r.KMS.KeySelector), PublicKey: publicPresent(r.KMS.SPKI), Fingerprint: publicPresent(r.KMS.Fingerprint), WrapProfile: publicPresent(r.KMS.WrapProfile), ProtectionClass: publicPresent(r.KMS.ProtectionClass)}
		input.Recovery = contract.PublicRecoverySettings{Enabled: publicPresent(true), Signing: &signing, Encryption: &encryption}
	}
	return input
}

// full_only: false
func TestReaderComparisonPublicMeaningIgnoresChangedSecretValues(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", family, recovery), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				env, keys := genesisEnvironment(t, family, recovery)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, []int{2}, false)
				entries := append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "first source", custody.StandardValue))
				run.suppliedSelection(f, entries)
				input := comparisonCurrentInput(t, env, f.session)
				firstBytes := bytes.Clone(f.session.valueEntry(namedSlot(t, f.session, "secret")).ValueBytes)
				request := contract.Hash([]byte("public settings request"))
				e, _, _ := readerEngineFixture(t, env, f.session)
				public, private := keys.Calls()
				store := env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				first := e.Compare(ctx, request, input)
				if first.Verdict != contract.ComparisonMatch || first.Observation == nil || first.Context.OperationID.IsZero() {
					t.Fatal(first)
				}
				if p, k := keys.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
					t.Fatal("Reader reached private/effect route")
				}
				e.Close()
				entries = f.session.currentEntryInputs()
				for i := range entries {
					if entries[i].Name == "secret" {
						entries[i] = suppliedSecret(t, env, "secret", "different secret source", custody.AlternateStandardValue)
					}
				}
				run.suppliedSelection(f, entries)
				if bytes.Equal(firstBytes, f.session.valueEntry(namedSlot(t, f.session, "secret")).ValueBytes) {
					t.Fatal("secret fixture did not change encoded secret")
				}
				e, _, _ = readerEngineFixture(t, env, f.session)
				public, private = keys.Calls()
				creates, cas = store.creates, store.cas
				second := e.Compare(ctx, request, input)
				if second.Verdict != contract.ComparisonMatch || second.Observation == nil || second.Observation.SnapshotID == first.Observation.SnapshotID || second.Context.OperationID == first.Context.OperationID {
					t.Fatal("value/revision changed public equality or fresh context", second)
				}
				if p, k := keys.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
					t.Fatal("Reader reached private/effect route")
				}
			})
		}
	}
}

type comparisonReadGate struct {
	PublicSelectedReader
	key           string
	reads, failAt int
	kind          string
	cancel        context.CancelFunc
}

func (r *comparisonReadGate) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	read := r.PublicSelectedReader.Read(ctx, key, limit)
	if key != r.key {
		return read
	}
	r.reads++
	if r.failAt == 0 || r.reads != r.failAt {
		return read
	}
	switch r.kind {
	case "missing":
		return contract.ReadResult{Status: contract.ReadMissing}
	case "corrupt":
		read.Body = bytes.Clone(read.Body)
		read.Body[len(read.Body)-1] ^= 1
	case "cancelled":
		r.cancel()
	}
	return read
}

// full_only: false
func TestReaderComparisonLateOutputFailureDiscardsDifferences(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newNamedEnvironmentFixture(t, ctx, env, []int{2}, false, []string{"/\nα"})
	input := comparisonCurrentInput(t, env, f.session)
	e, _, source := readerEngineFixture(t, env, f.session)
	refs := capacityConfigurationSelectedRefs(t, f.session)
	key := readerFixtureKey(t, source.descriptor.Prefix, refs[len(refs)-1])
	baseline := &comparisonReadGate{PublicSelectedReader: source, key: key}
	e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return baseline, Result{}
	}
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	public, private := env.Custody.Calls()
	creates, cas, signs := store.creates, store.cas, trust.signs
	match := e.Compare(ctx, contract.Hash([]byte("output baseline")), input)
	if match.Verdict != contract.ComparisonMatch || match.Observation == nil || baseline.reads < 3 {
		t.Fatal("complete output baseline", match, baseline.reads)
	}
	if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs || source.closes != 1 || e.activeDone != nil {
		t.Fatal("output baseline made effects or retained reader ownership")
	}
	for _, kind := range []string{"missing", "corrupt", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), time.Minute)
			defer stop()
			e, _, source := readerEngineFixture(t, env, f.session)
			gate := &comparisonReadGate{PublicSelectedReader: source, key: key, failAt: baseline.reads, kind: kind, cancel: stop}
			e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return gate, Result{}
			}
			desired := comparisonCurrentInput(t, env, f.session)
			desired.Entries.Value[0].PlainValue = publicPresent([]byte{9})
			desired.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
			got := e.Compare(ctx, contract.Hash([]byte("late output failure")), desired)
			reason := contract.ReasonSelectedObjectUnavailable
			if kind == "corrupt" {
				reason = contract.ReasonSelectedObjectInvalid
			}
			if kind == "cancelled" {
				reason = contract.ReasonCancelled
			}
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, Path: []contract.DiagnosticField{contract.FieldSigningPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}
			if got.Verdict != contract.ComparisonUnable || got.Observation == nil || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got.ComparisonPayload, want) || gate.reads != baseline.reads {
				t.Fatalf("late %s failure=%+v reads=%d", kind, got, gate.reads)
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas || trust.signs != signs || source.closes != 1 || e.activeDone != nil {
				t.Fatal("late output failure made effects or retained reader ownership")
			}
			for _, scope := range got.CheckedScope {
				if scope.Status != contract.ScopeUnchecked {
					t.Fatal("late shared defect left checked fields", scope)
				}
			}
		})
	}
}

// full_only: false
func TestReaderComparisonDesiredPublicSettingsDifferFromTrust(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	for _, kind := range []string{"domain", "bucket", "signing-selector", "unassigned", "wrong-basis", "missing-evidence", "zero-request"} {
		t.Run(kind, func(t *testing.T) {
			e, candidate, source := readerEngineFixture(t, env, f.session)
			input := comparisonCurrentInput(t, env, f.session)
			request := contract.Hash([]byte("desired vs independent trust"))
			subject := contract.DiagnosticSubject{Kind: contract.SubjectDomain}
			field := contract.FieldDomainID
			reason := contract.ReasonFieldDiffers
			verdict := contract.ComparisonMismatch
			switch kind {
			case "domain":
				input.Store.DomainID.Value[0] ^= 1
			case "bucket":
				input.Store.Bucket.Value = "other-valid-bucket"
				subject = contract.DiagnosticSubject{Kind: contract.SubjectStore}
				field = contract.FieldBucket
			case "signing-selector":
				input.Authority.Signing.Selector.Value = strings.TrimSuffix(input.Authority.Signing.Selector.Value, "1") + "2"
				subject = contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
				field = contract.FieldSigningSelector
			case "unassigned":
				var id contract.ID
				for i, row := range input.Recipients.Value {
					if row.RecipientID != input.Authority.RecipientID.Value {
						id = row.RecipientID
						input.Recipients.Value = slices.Delete(input.Recipients.Value, i, i+1)
						break
					}
				}
				subject = contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: id}
				field = contract.FieldPresence
				reason = contract.ReasonExpectedSettingAbsent
			case "wrong-basis":
				e.expectedDomain[0] ^= 1
				subject = contract.DiagnosticSubject{Kind: contract.SubjectObservation}
				field = contract.FieldPresence
				reason = contract.ReasonDomainBasisInvalid
				verdict = contract.ComparisonUnable
			case "missing-evidence":
				candidate.root = contract.ReadResult{Status: contract.ReadMissing}
				input.Authority.Signing.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
				verdict = contract.ComparisonUnable
			case "zero-request":
				request = contract.ID{}
				subject = contract.DiagnosticSubject{Kind: contract.SubjectObservation}
				field = contract.FieldPresence
				reason = contract.ReasonInvalidInput
				verdict = contract.ComparisonUnable
			}
			got := e.Compare(ctx, request, input)
			want := []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: contract.DiagnosticDifference, Reason: reason}}
			if verdict == contract.ComparisonUnable {
				want[0].Outcome = contract.DiagnosticUnable
			}
			if kind == "missing-evidence" {
				want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectAuthority}, Path: []contract.DiagnosticField{contract.FieldSigningPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonSelectedObjectUnavailable}}
			}
			if kind == "unassigned" {
				want = appendExpectedPublicFields(want, subject, contract.ReasonExpectedSettingAbsent, contract.FieldDisplayName, contract.FieldEncryptionProvider, contract.FieldEncryptionSelector, contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint, contract.FieldWrapProfile, contract.FieldProtectionClass)
			}
			if got.Verdict != verdict || !publicComparisonFactsMatch(t, got.ComparisonPayload, want) || !got.DiagnosticsComplete {
				t.Fatal(kind, got)
			}
			if verdict == contract.ComparisonMismatch && (got.Observation == nil || got.Result.Outcome != ObservedCurrent) {
				t.Fatal("desired difference became authentication fault", got)
			}
			if (kind == "wrong-basis" || kind == "zero-request") && (got.Observation != nil || source.reads != 0 || len(candidate.calls) != 0) {
				t.Fatal("invalid admission reached Store", got)
			}
		})
	}
}

func comparisonOutputInterpreter(ctx context.Context, _ string, d contract.OutputDestination, _ string, encoding uint8) (contract.OutputTarget, error) {
	if err := ctx.Err(); err != nil {
		return contract.OutputTarget{}, err
	}
	var settings map[string]string
	if d.ServiceContractID != "aws" || d.ConfigContractID != "aws" || json.Unmarshal(d.CanonicalSettings, &settings) != nil || len(settings) != 1 || settings["consumer"] == "" {
		return contract.OutputTarget{}, contract.ErrRecord
	}
	return outputFixtureTarget(d.ServiceContractID, "slot", settings["consumer"], encoding, d.Capabilities, d.Policy), nil
}

func comparisonOutputFixture(t *testing.T) (context.Context, context.CancelFunc, fixtureEnvironment, *StateSession, contract.PublicConfiguration, *PublicConfigurationValidator) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newNamedEnvironmentFixture(t, ctx, env, []int{2}, false, []string{"/\nα"})
	target := outputConfigurationTarget("/\nα", "slot")
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "destination", destination: contract.OutputDestination{ConfigContractID: "aws", ServiceContractID: "aws", CanonicalSettings: hermeticDestinationSettings([][2]string{{"consumer", "slot?stage=AWSCURRENT"}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}, targets: []outputApplyTarget{target}}}, routes: []outputApplyRoute{{entryName: "/\nα", destinations: []string{"destination"}}}}
	s := selectAdmittedOutputConfiguration(t, ctx, f.session, env, keys, f.session.currentEntryInputs(), output)
	input := comparisonCurrentInput(t, env, s)
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{{DestinationID: "destination", Destination: publicPresent(output.bindings[0].destination), Targets: publicPresent([]contract.PublicOutputTarget{hermeticPublicOutputTarget("/\nα", target.target)})}})
	input.Routing = publicPresent([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "/\nα"}, Destinations: publicPresent([]string{"destination"})}})
	v := NewPublicConfigurationValidator(comparisonOutputInterpreter)
	return ctx, cancel, env, s, input, v
}

// full_only: false
func TestReaderComparisonProjectsCompleteOutputAndRouting(t *testing.T) {
	ctx, cancel, env, s, input, validator := comparisonOutputFixture(t)
	defer cancel()
	for _, kind := range []string{"equal", "locator", "policy", "routing", "changed-contract", "without-interpreter"} {
		t.Run(kind, func(t *testing.T) {
			e, _, _ := readerEngineFixture(t, env, s)
			e.validator = validator
			desired := ownPublicConfiguration(input)
			verdict := contract.ComparisonMismatch
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "destination", Name: "/\nα"}
			field := contract.FieldConsumerLocator
			reason := contract.ReasonFieldDiffers
			switch kind {
			case "equal":
				verdict = contract.ComparisonMatch
			case "locator":
				desired.OutputBindings.Value[0].Destination.Value.CanonicalSettings = []byte(`{"consumer":"other?stage=AWSCURRENT"}`)
				desired.OutputBindings.Value[0].Targets.Value[0].ConsumerLocator.Value = "other?stage=AWSCURRENT"
			case "policy":
				desired.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value = hermeticNumberPolicy("aws", []uint64{7})
				desired.OutputBindings.Value[0].Destination.Value.Policy = desired.OutputBindings.Value[0].Targets.Value[0].ConsumerPolicy.Value
				field = contract.FieldConsumerPolicy
			case "routing":
				desired.Routing.Value[0].Key.EntrySelector = contract.PublicDefaultRoute
				desired.Routing.Value[0].Key.EntryName = ""
			case "changed-contract":
				desired.OutputBindings.Value[0].Destination.Value.ConfigContractID = "other-contract"
				field = contract.FieldDestination
				subject = contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "destination"}
			case "without-interpreter":
				e.validator = NewPublicConfigurationValidator(nil)
				verdict = contract.ComparisonMatch

			}
			public, private := env.Custody.Calls()
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			got := e.Compare(ctx, contract.Hash([]byte("output projection request")), desired)
			var want []contract.Diagnostic
			if kind != "equal" && kind != "without-interpreter" {
				outcome := contract.DiagnosticDifference
				if verdict == contract.ComparisonUnable {
					outcome = contract.DiagnosticUnable
				}
				want = []contract.Diagnostic{{Subject: subject, Path: []contract.DiagnosticField{field}, Outcome: outcome, Reason: reason}}
			}
			if kind == "locator" || kind == "policy" {
				want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "destination"}, Path: []contract.DiagnosticField{contract.FieldDestination}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers})
			}

			slices.SortFunc(want, comparePublicDiagnostics)
			if kind == "routing" {
				key := input.Routing.Value[0].Key
				defaultRoute := key
				defaultRoute.EntrySelector = contract.PublicDefaultRoute
				defaultRoute.EntryName = ""
				want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: key}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonExpectedSettingAbsent}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: defaultRoute}, Path: []contract.DiagnosticField{contract.FieldDestinations}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonSetDiffers}}
			}
			if kind == "routing" {
				want = appendExpectedPublicFields(want, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: input.Routing.Value[0].Key}, contract.ReasonExpectedSettingAbsent, contract.FieldDestinations)
			}
			if got.Verdict != verdict || !got.DiagnosticsComplete || got.Observation == nil || !publicComparisonFactsMatch(t, got.ComparisonPayload, want) {
				t.Fatal(kind, got)
			}
			if p, k := env.Custody.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
				t.Fatal("public output interpretation reached private/effect route")
			}
		})
	}
	t.Run("observed-collections-exact-backing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		env, keys := genesisEnvironment(t, contract.GCP, false)
		names := []string{"alpha", "beta", "gamma"}
		f := newNamedEnvironmentFixture(t, ctx, env, []int{1, 1, 1}, false, names)
		output := &outputApplyInput{groups: [][]string{{"alpha"}, {"beta"}, {"gamma"}}}
		for _, destination := range []string{"active", "unused-a", "unused-b"} {
			row := outputApplyBinding{destinationID: destination, destination: contract.OutputDestination{ConfigContractID: "aws", ServiceContractID: "aws", CanonicalSettings: hermeticDestinationSettings([][2]string{{"a", destination}, {"b", "two"}, {"c", "three"}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}}
			if destination == "active" {
				for _, name := range names {
					target := outputConfigurationTarget(name, "active-"+name)
					target.target.PayloadEncoding = contract.OutputEncodingBase64
					row.targets = append(row.targets, target)
					output.routes = append(output.routes, outputApplyRoute{entryName: name, destinations: []string{"active"}})
				}
			}
			output.bindings = append(output.bindings, row)
		}
		selected := selectAdmittedOutputConfiguration(t, ctx, f.session, env, keys, f.session.currentEntryInputs(), output)
		defer readerCapacityNoEffects(t, env)()
		want := comparisonCurrentInput(t, env, selected)
		want.Groups = publicPresent([][]string{{"alpha"}, {"beta"}, {"gamma"}})
		want.OutputBindings = publicPresent(make([]contract.PublicOutputBinding, 3))
		want.Routing = publicPresent(make([]contract.PublicRoutingRule, len(names)+1))
		for i, row := range output.bindings {
			binding := contract.PublicOutputBinding{DestinationID: row.destinationID, Destination: publicPresent(row.destination), Targets: publicPresent([]contract.PublicOutputTarget{})}
			if i == 0 {
				for _, name := range names {
					target := outputConfigurationTarget(name, "active-"+name).target
					target.PayloadEncoding = contract.OutputEncodingBase64
					binding.Targets.Value = append(binding.Targets.Value, hermeticPublicOutputTarget(name, target))
				}
			}
			want.OutputBindings.Value[i] = binding
		}
		for i, name := range names {
			want.Routing.Value[i] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: name}, Destinations: publicPresent([]string{"active"})}
		}
		want.Routing.Value[len(names)] = contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent([]string(nil))}
		e, _, source := readerEngineFixture(t, env, selected)
		validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
		e.validator = validator
		owned := validator.Validate(ctx, want)
		inv := readerInvocationFixture(t, e, ctx)
		observation, failure := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
		if failure.Outcome != 0 || !owned.Valid || !owned.Complete {
			t.Fatal("small simultaneous ownership admission", failure, owned.Diagnostics)
		}
		actual, failure := e.projectPublicConfiguration(ctx, observation)
		if failure.Outcome != 0 || !actual.Valid || !actual.Complete || len(actual.Diagnostics) != 0 || !reflect.DeepEqual(actual.Configuration, want) {
			t.Fatal("observed complete public configuration changed", failure, actual.Diagnostics, actual.Configuration)
		}
		for owner, configuration := range map[string]contract.PublicConfiguration{"desired": owned.Configuration, "observed": actual.Configuration} {
			if len(configuration.Entries.Value) != 3 || cap(configuration.Entries.Value) != 3 {
				t.Error(owner, "entry backing", len(configuration.Entries.Value), cap(configuration.Entries.Value))
			}
			for _, entry := range configuration.Entries.Value {
				if entry.OutputEncoding.State != contract.PublicPresent || entry.OutputEncoding.Value != contract.OutputEncodingBase64 {
					t.Error(owner, "committed entry output encoding", entry.Name, entry.OutputEncoding)
				}
			}
			if len(configuration.OutputBindings.Value) != 3 || cap(configuration.OutputBindings.Value) != 3 {
				t.Error(owner, "declared binding backing", len(configuration.OutputBindings.Value), cap(configuration.OutputBindings.Value))
			}
			if len(configuration.Groups.Value) != 3 || cap(configuration.Groups.Value) != 3 {
				t.Error(owner, "group backing", len(configuration.Groups.Value), cap(configuration.Groups.Value))
			}
			for _, binding := range configuration.OutputBindings.Value {
				if len(binding.Destination.Value.CanonicalSettings) != cap(binding.Destination.Value.CanonicalSettings) {
					t.Error(owner, binding.DestinationID, "settings backing", len(binding.Destination.Value.CanonicalSettings), cap(binding.Destination.Value.CanonicalSettings))
				}
				if binding.DestinationID == "active" && cap(binding.Targets.Value) != 3 {
					t.Error(owner, "active target backing", cap(binding.Targets.Value))
				}
			}
		}
		readerCapacityOwnedBacking(t, reflect.ValueOf(owned.Configuration))
		readerCapacityOwnedBacking(t, reflect.ValueOf(actual.Configuration))
		if &owned.Configuration.OutputBindings.Value[0].Destination.Value.CanonicalSettings[0] == &actual.Configuration.OutputBindings.Value[0].Destination.Value.CanonicalSettings[0] || &actual.Configuration.OutputBindings.Value[0].Destination.Value.CanonicalSettings[0] == &output.bindings[0].destination.CanonicalSettings[0] {
			t.Error("desired/observed/source settings owners overlap")
		}
		inv.Close()
		if source.closes != 1 || e.activeDone != nil || inv.selection.complete || inv.admission.issued || inv.source != nil || !reflect.DeepEqual(inv.admission.basis, readerPublicBasis{}) {
			t.Fatal("small ownership invocation did not release selected state and basis")
		}
	})

}

func comparisonGeneratedFixture(t *testing.T) (context.Context, context.CancelFunc, fixtureEnvironment, *StateSession, contract.PublicConfiguration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	env, _ := genesisEnvironment(t, contract.GCP, false)
	env.Context = ctx
	f := newNamedEnvironmentFixture(t, ctx, env, []int{2}, false, []string{"plain"})
	intent := generatedFixtureCanonicalIntent(t, generatedWriterIntent("generated", 1, 64), defaultGeneratedFixtureProfile())
	initial := generatedWriterPlanInput(t, f.session, fixtureID(env.Domain, "comparison generated initial writer"), []string{"generated"}, func(string) []byte { return intent }, 0, nil)
	s := selectGeneratedWriterBatch(t, env, f.session, initial, "comparison generated initial writer", custody.StandardValue)
	s = generatedLifecycleReopen(t, ctx, s, env.Store)
	plan := generatedWriterPlanInput(t, s, fixtureID(env.Domain, "comparison generated writer"), []string{"generated"}, func(string) []byte { return intent }, 1,
		generatedWriterRetiringEntries(s, []string{"generated"}))
	s = selectGeneratedWriterBatch(t, env, s, plan, "comparison generated writer", custody.StandardValue)
	s = closeGeneratedWriterRetirement(t, env, s, "generated", fixtureID(env.Domain, "comparison generated retirement"))
	input := comparisonCurrentInput(t, env, s)
	profile := defaultGeneratedFixtureProfile()
	generated := s.valueEntry(namedSlot(t, s, "generated"))
	for i := range input.Entries.Value {
		if input.Entries.Value[i].Name == "generated" {
			input.Entries.Value[i].Generated = &contract.PublicGeneratedSettings{Epoch: publicPresent(uint64(1)), ConfigContractID: publicPresent(profile.ConfigContractID), ResourceContractID: publicPresent(profile.ResourceContractID), LifecycleMode: publicPresent(profile.LifecycleMode), ContentIntent: publicPresent(intent), Retirement: publicPresent(contract.GeneratedRetirementManual), Completion: publicPresent(generated.Generated.CompletionClass)}
		}
	}
	return ctx, cancel, env, s, input
}

// full_only: false
func TestReaderComparisonGeneratedIntentAndLateEvidence(t *testing.T) {
	ctx, cancel, env, s, input := comparisonGeneratedFixture(t)
	defer cancel()
	validator := NewPublicConfigurationValidator(nil)
	e, _, source := readerEngineFixture(t, env, s)
	e.validator = validator
	content, err := newGeneratedContent(s)
	if err != nil {
		t.Fatal(err)
	}
	generated := s.valueEntry(namedSlot(t, s, "generated"))
	intent, ok := content.locations[generatedContentKey{contract.GeneratorContentIntent, generated.Generated.IntentDigest}]
	locations := content.fragmentLocations[intent.BlobID]
	if !ok || len(locations) != 1 {
		t.Fatal("fixture intent must occupy one known fragment")
	}
	location := locations[0]
	var ref contract.Ref
	for _, r := range s.root.RequiredSupport {
		if r.Index == location.SupportPageIndex {
			ref = r
			break
		}
	}
	if ref.Object.IsZero() {
		t.Fatal("missing generated support fixture")
	}
	key := readerFixtureKey(t, source.descriptor.Prefix, ref)
	baseline := &comparisonReadGate{PublicSelectedReader: source, key: key}
	e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return baseline, Result{}
	}
	public, private := env.Custody.Calls()
	match := e.Compare(ctx, contract.Hash([]byte("generated public baseline")), input)
	if match.Verdict != contract.ComparisonMatch || match.Observation == nil || baseline.reads < 2 {
		t.Fatal("generated intent projection or independent profile alias failed", match, baseline.reads)
	}
	if p, k := env.Custody.Calls(); p != public || k != private {
		t.Fatal("generated Reader reached private custody")
	}
	for _, kind := range []string{"epoch", "intent", "without-interpreter", "missing", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			e, _, source := readerEngineFixture(t, env, s)
			e.validator = validator
			desired := ownPublicConfiguration(input)
			subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "generated"}
			field := contract.FieldEpoch
			reason := contract.ReasonFieldDiffers
			outcome := contract.DiagnosticDifference
			verdict := contract.ComparisonMismatch
			for i := range desired.Entries.Value {
				if desired.Entries.Value[i].Name == "generated" {
					switch kind {
					case "epoch":
						desired.Entries.Value[i].Generated.Epoch.Value++
					case "intent":
						desired.Entries.Value[i].Generated.ContentIntent.Value = generatedFixtureCanonicalIntent(t, []byte(`{"value":"changed"}`), defaultGeneratedFixtureProfile())
						field = contract.FieldContentIntent
						reason = contract.ReasonBytesDiffer
					}
				}
			}
			if kind == "without-interpreter" {
				e.validator = NewPublicConfigurationValidator(nil)
				verdict = contract.ComparisonMatch
			}

			if kind == "missing" || kind == "corrupt" {
				gate := &comparisonReadGate{PublicSelectedReader: source, key: key, failAt: baseline.reads, kind: kind}
				e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return gate, Result{}
				}
				for i := range desired.Entries.Value {
					if desired.Entries.Value[i].Name == "plain" {
						desired.Entries.Value[i].PlainValue = publicPresent([]byte{9})
					}
				}
				subject = contract.DiagnosticSubject{Kind: contract.SubjectObservation}
				field = contract.FieldPresence
				reason = contract.ReasonSelectedObjectUnavailable
				if kind == "corrupt" {
					reason = contract.ReasonSelectedObjectInvalid
				}
				outcome = contract.DiagnosticUnable
				verdict = contract.ComparisonUnable
			}
			public, private := env.Custody.Calls()
			got := e.Compare(ctx, contract.Hash([]byte("generated public case")), desired)
			path := []contract.DiagnosticField{contract.FieldGenerated, field}
			if subject.Kind == contract.SubjectObservation {
				path = []contract.DiagnosticField{field}
			}
			want := []contract.Diagnostic{{Subject: subject, Path: path, Outcome: outcome, Reason: reason}}
			if kind == "without-interpreter" {
				want = nil
			}
			diagnosticsEqual := publicComparisonFactsMatch(t, got.ComparisonPayload, want)
			if got.Verdict != verdict || !got.DiagnosticsComplete || got.Observation == nil || !diagnosticsEqual {
				t.Fatal(kind, got)
			}
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("generated comparison reached private custody")
			}
			if kind == "missing" || kind == "corrupt" {
				for _, scope := range got.CheckedScope {
					if scope.Status != contract.ScopeUnchecked {
						t.Fatal("late generated failure left checked settings", scope)
					}
				}
			}
		})
	}
}

// full_only: false
func TestReaderComparisonIgnoresPendingGenerationProgress(t *testing.T) {
	a := newGeneratedResultFixture(t, contract.GeneratedRetirementManual, false)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	if a.f.session.root.Generated.ActiveOwner.IsZero() {
		t.Fatal("fixture has no pending generation")
	}
	input := comparisonCurrentInput(t, a.env, a.f.session)
	e, _, _ := readerEngineFixture(t, a.env, a.f.session)
	public, private := a.env.Custody.Calls()
	got := e.Compare(ctx, contract.Hash([]byte("current settings during pending generation")), input)
	if got.Verdict != contract.ComparisonMatch || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || got.Observation == nil {
		t.Fatal("pending runtime progress became equality field", got)
	}
	if p, k := a.env.Custody.Calls(); p != public || k != private {
		t.Fatal("pending public comparison reached private custody")
	}
}

// full_only: false
func TestReaderComparisonGenericFieldDifferencesKeepIndependentDifference(t *testing.T) {
	for _, kind := range []string{"output-locator", "generated-intent"} {
		t.Run(kind, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			var env fixtureEnvironment
			var selected *StateSession
			var desired contract.PublicConfiguration
			var validator *PublicConfigurationValidator
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: "destination", Name: "/\nα"}
			path := []contract.DiagnosticField{contract.FieldConsumerLocator}
			reason := contract.ReasonFieldDiffers
			plainName := "/\nα"
			if kind == "output-locator" {
				ctx, cancel, env, selected, desired, validator = comparisonOutputFixture(t)
				desired.OutputBindings.Value[0].Destination.Value.CanonicalSettings = []byte(`{"consumer":"accepted/current"}`)
				desired.OutputBindings.Value[0].Targets.Value[0].ConsumerLocator.Value = "accepted/current"
			} else {
				ctx, cancel, env, selected, desired = comparisonGeneratedFixture(t)
				validator = NewPublicConfigurationValidator(nil)
				for i := range desired.Entries.Value {
					if desired.Entries.Value[i].Name == "generated" {
						desired.Entries.Value[i].Generated.ContentIntent = publicPresent(generatedFixtureCanonicalIntent(t, []byte(`{"value":"changed"}`), defaultGeneratedFixtureProfile()))
					}
				}
				subject = contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "generated"}
				path = []contract.DiagnosticField{contract.FieldGenerated, contract.FieldContentIntent}
				reason = contract.ReasonBytesDiffer
				plainName = "plain"
			}
			defer cancel()
			for i := range desired.Entries.Value {
				if desired.Entries.Value[i].Name == plainName {
					desired.Entries.Value[i].PlainValue = publicPresent([]byte{9})
				}
			}
			check := validator.Validate(ctx, desired)
			if !check.Valid || !check.Complete {
				t.Fatal("desired generic input invalid", check.Diagnostics)
			}
			e, _, _ := readerEngineFixture(t, env, selected)
			e.validator = validator
			public, private := env.Custody.Calls()
			got := e.Compare(ctx, contract.Hash([]byte("independent generic field differences")), desired)
			want := []contract.Diagnostic{{Subject: subject, Path: path, Outcome: contract.DiagnosticDifference, Reason: reason}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: plainName}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonBytesDiffer}}
			if kind == "output-locator" {
				want = append(want, contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: "destination"}, Path: []contract.DiagnosticField{contract.FieldDestination}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers})
			}
			slices.SortFunc(want, comparePublicDiagnostics)
			if got.Verdict != contract.ComparisonMismatch || got.StateResult != contract.ReaderSuccess || got.Observation == nil || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got.ComparisonPayload, want) {
				t.Fatal("generic comparison lost an independent difference", got)
			}
			for _, scope := range got.CheckedScope {
				if scope.Status != contract.ScopeComplete {
					t.Fatal("generic comparison left incomplete scope", scope)
				}
			}
			if p, k := env.Custody.Calls(); p != public || k != private {
				t.Fatal("public differences reached private custody")
			}
		})
	}
}

// full_only: false
func TestReaderComparisonWithoutInterpreterKeepsCanonicalGroups(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	names := []string{"alpha", "beta", "gamma"}
	f := newNamedEnvironmentFixture(t, ctx, env, []int{1, 1, 1}, false, names)
	output := &outputApplyInput{groups: [][]string{{"alpha"}, {"beta"}, {"gamma"}}}
	binding := outputApplyBinding{destinationID: "d", destination: contract.OutputDestination{ConfigContractID: "aws", ServiceContractID: "aws", CanonicalSettings: hermeticDestinationSettings([][2]string{{"fixture", "d"}}), Policy: contract.OutputPolicy{}, Capabilities: (contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot)}}
	for _, name := range names {
		binding.targets = append(binding.targets, outputConfigurationTarget(name, "slot-"+name))
		output.routes = append(output.routes, outputApplyRoute{entryName: name, destinations: []string{"d"}})
	}
	output.bindings = []outputApplyBinding{binding}
	selected := selectAdmittedOutputConfiguration(t, ctx, f.session, env, keys, f.session.currentEntryInputs(), output)
	defer readerCapacityNoEffects(t, env)()
	input := comparisonCurrentInput(t, env, selected)
	input.Groups = publicPresent([][]string{{"gamma"}, {"alpha"}, {"beta"}})
	row := contract.PublicOutputBinding{DestinationID: "d", Destination: publicPresent(output.bindings[0].destination), Targets: publicPresent([]contract.PublicOutputTarget{})}
	input.Routing = publicPresent([]contract.PublicRoutingRule{})
	for _, name := range names {
		row.Targets.Value = append(row.Targets.Value, hermeticPublicOutputTarget(name, outputConfigurationTarget(name, "slot-"+name).target))
		input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: name}, Destinations: publicPresent([]string{"d"})})
	}
	input.OutputBindings = publicPresent([]contract.PublicOutputBinding{row})
	for _, condition := range []string{"healthy", "unavailable", "independent-difference"} {
		t.Run(condition, func(t *testing.T) {
			e, _, _ := readerEngineFixture(t, env, selected)
			interpret := selected.admission.outputInterpreter
			if condition != "healthy" {
				interpret = nil
			}
			e.validator = NewPublicConfigurationValidator(interpret)

			desired := ownPublicConfiguration(input)
			if condition == "independent-difference" {
				desired.Entries.Value[0].PlainValue.Value[0] = 99
			}
			var want []contract.Diagnostic
			verdict := contract.ComparisonMatch
			if condition == "independent-difference" {
				verdict = contract.ComparisonMismatch
				want = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "alpha"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonBytesDiffer}}
			}

			got := e.Compare(ctx, contract.Hash([]byte("canonical groups "+condition)), desired)
			if got.Verdict != verdict || !got.DiagnosticsComplete || got.Observation == nil || !publicComparisonFactsMatch(t, got.ComparisonPayload, want) {
				t.Fatalf("group projection: %+v, want %+v", got, want)
			}
		})
	}
}
