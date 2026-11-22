package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func installedOutputValidator(t testing.TB, selected *StateSession) *PublicConfigurationValidator {
	t.Helper()
	return NewPublicConfigurationValidator(selected.admission.outputInterpreter)
}

func installedOutputSecretFixture(t testing.TB, ctx context.Context, shared bool) installedApplyTestFixture {
	t.Helper()
	f := newInstalledApplyTestFixture(t, ctx, contract.AWS, false)
	members := []contract.ID{f.selected.admission.recipient}
	if shared {
		members = append(members, fixtureID(f.env.Domain, "reader"))
		slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	}
	input := []ApplyEntryInput{sharingSecretNamed(t, f.env, "secret", "installed output secret", members)}
	engine := f.engine(t, f.selected, input, nil)
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "installed output secret setup"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent {
		t.Fatal("installed output secret setup", result.Result)
	}
	f.selected = f.open(t, ctx)
	return f
}

func installedOutputSelect(t testing.TB, ctx context.Context, f installedApplyTestFixture, output *outputApplyInput) installedApplyTestFixture {
	t.Helper()
	input := installedApplyCurrentInput(f.selected)
	for at := range input {
		if input[at].ValueSource == contract.Generated {
			input[at].InputBytes = f.selected.valueEntry(f.selected.root.Names[at].Slot).ValueBytes
		}
	}
	f.selected = selectAdmittedOutputConfiguration(t, ctx, f.selected, f.env, f.keys, input, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	return f
}

func installedOutputConfiguration(t testing.TB, ctx context.Context, selected *StateSession) contract.OutputConfiguration {
	t.Helper()
	configuration, result := selected.currentOutputConfigurationForApply(ctx)
	if result.Outcome != 0 {
		t.Fatal("complete installed output configuration", result)
	}
	return configuration
}

// full_only: false
func TestInstalledLifecyclePreservesUnchangedOutputConfiguration(t *testing.T) {
	for _, operation := range []string{"noop", "metadata", "creation", "rekey", "exclude", "retire"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := installedOutputSecretFixture(t, ctx, true)
			target := outputConfigurationTarget("secret", "app-secret")
			target.target.PayloadEncoding = contract.OutputEncodingBase64
			f = installedOutputSelect(t, ctx, f, &outputApplyInput{
				bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}},
				routes:   []outputApplyRoute{{entryName: "secret", destinations: []string{"app"}}},
				groups:   [][]string{{"secret"}},
			})
			selected := f.selected
			beforeOutput := installedOutputConfiguration(t, ctx, selected)
			beforeWork := installedApplyStableWork(t, ctx, selected)
			beforeEntry := ownScenarioValueEntry(*selected.valueEntry(selected.root.Names[0].Slot))
			beforeRegistry := selected.registry()
			validator := installedOutputValidator(t, selected)
			reader := fixtureID(f.env.Domain, "reader")
			store := requireAdmittedMemoryStore(t, f.env.Store)
			creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
			var result PublicApplyResult
			kind := uint16(contract.OperationApplyDeclaration)
			var stages []contract.CryptoKind
			wantRegistry := beforeRegistry
			switch operation {
			case "noop", "metadata", "creation", "exclude":
				desired := currentApplyRecipients(selected.registry())
				switch operation {
				case "metadata":
					desired[0].Recipient.DisplayName = "output configuration metadata"
				case "creation":
					desired = installedApplyPreparedRecipient(t, selected, "output configuration enrollment")
				}
				wantRegistry = make([]contract.RecipientRecord, len(desired))
				for at, row := range desired {
					wantRegistry[at] = row.Recipient
				}
				input := installedApplyCurrentInput(selected)
				if operation == "exclude" {
					input[0].Recipients = []contract.ID{selected.admission.recipient}
				}
				engine := f.engineWithValidator(t, selected, input, desired, validator, func(stage contract.CryptoKind) { stages = append(stages, stage) })
				result = engine.Apply(ctx, fixtureID(f.env.Domain, "installed output "+operation), input)
				engine.Close()
			case "rekey":
				kind = contract.OperationEnvelopeRekey
				installation := installedSecretAccessTestInstallation(t, f, selected, validator, nil, nil)
				engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, Name: "secret", AdmitCustody: installation.AdmitCustody})
				if err != nil {
					t.Fatal(err)
				}
				result = engine.Rekey(ctx, fixtureID(f.env.Domain, "installed output rekey"))
				engine.Close()
			case "retire":
				kind = contract.OperationRetireRecipientIdentity
				wantRegistry = slices.DeleteFunc(slices.Clone(beforeRegistry), func(row contract.RecipientRecord) bool { return row.RecipientID == reader })
				installation := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, reader), nil, validator)
				engine, err := NewInstalledRecipientRetirement(installation)
				if err != nil {
					t.Fatal(err)
				}
				result = engine.Retire(ctx, fixtureID(f.env.Domain, "installed output retirement"))
				engine.Close()
			}
			if operation == "noop" {
				if result.Result.Outcome != Unchanged || result.Payload != nil || len(result.Receipt) != 0 || store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || !slices.Equal(stages, []contract.CryptoKind{contract.CryptoCompare, contract.CryptoDiscard}) {
					t.Fatal("installed exact output no-op did not validate without selection", result.Result, stages)
				}
			} else {
				if result.Result.Outcome != ObservedCurrent || result.Payload == nil || store.cas != cas+1 {
					t.Fatal("installed lifecycle refused unchanged passive output or selected more than once", result.Result, store.cas-cas)
				}
				receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
				wantEffect := uint16(contract.ReceiptEffectNotApplicable)
				if kind == contract.OperationApplyDeclaration {
					wantEffect = contract.ReceiptEffectNoChange
				}
				if err != nil || receipt.EffectSummary != wantEffect || receipt.OperationKind != kind || receipt.StateResult != contract.ReceiptStateSuccess || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || len(result.Payload.LiveDutyIDs)+len(result.Payload.LiveHazardIDs) != 0 {
					t.Fatal("installed lifecycle granted effect or output work", err)
				}
			}
			fresh := f.open(t, ctx)
			if fresh.root.OutputConfiguration != selected.root.OutputConfiguration || !reflect.DeepEqual(installedOutputConfiguration(t, ctx, fresh), beforeOutput) || !reflect.DeepEqual(installedApplyStableWork(t, ctx, fresh), beforeWork) {
				t.Fatal("installed lifecycle changed complete output state or retained work")
			}
			_, after := lifecycleEntry(t, fresh, "secret")
			if operation == "noop" || operation == "metadata" || operation == "creation" {
				if !reflect.DeepEqual(*after, beforeEntry) || !reflect.DeepEqual(fresh.accessRecords(), selected.accessRecords()) {
					t.Fatal("registry-only apply changed current material or access")
				}
			} else if after.ValueState == beforeEntry.ValueState || bytes.Equal(after.ValueBytes, beforeEntry.ValueBytes) || after.Incarnation != beforeEntry.Incarnation {
				t.Fatal("standalone lifecycle did not refresh exactly current protection")
			}
			wantMembers := beforeEntry.Recipients
			if operation == "exclude" || operation == "retire" {
				wantMembers = []contract.ID{fresh.admission.recipient}
			}
			if !slices.Equal(after.Recipients, wantMembers) || !reflect.DeepEqual(fresh.registry(), wantRegistry) {
				t.Fatal("installed lifecycle changed the wrong membership or registry set")
			}
			if check := f.keys.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, "secret"), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
				t.Fatal("cold installed lifecycle changed secret plaintext", check)
			}
		})
	}
}

// full_only: false
func TestInstalledOutputMetadataPreservesUnresolvedPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, prior, coordinate, marker := signedPublicationSelectionFixture(t, format.OutputReserveAuth, false)
	selected := prior.session
	f := installedApplyTestFixture{env: env, keys: env.Custody, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	name := selected.root.Names[0].Name
	target := outputConfigurationTarget(name, coordinate.CanonicalTarget)
	target.target.ServiceContractID = coordinate.ServiceContractID
	target.target.ConsumerLocator, target.target.TargetContractID = coordinate.DeletionConsumerLocator, coordinate.DeletionTargetContractID
	target.target.TargetData = slices.Clone(coordinate.DeletionTargetData)
	target.target.LocatorRequiresCreation = coordinate.LocatorRequiresCreation
	if target.target.LocatorRequiresCreation {
		target.target.ConsumerLocator = ""
	}
	f = installedOutputSelect(t, ctx, f, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}})
	selected = f.selected
	before := installedOutputConfiguration(t, ctx, selected)
	work := installedApplyStableWork(t, ctx, selected)
	if !slices.ContainsFunc(work, func(row contract.SupportRecordDigest) bool {
		return row.Kind() == contract.PublicationMarkerSupportKind && row.RecordID() == marker.AttemptID
	}) {
		t.Fatal("fixture lacks the exact selected unresolved publication")
	}
	desired := currentApplyRecipients(selected.registry())
	desired[0].Recipient.DisplayName = "metadata with unresolved publication"
	input := installedApplyCurrentInput(selected)
	private := 0
	engine := f.engineWithValidator(t, selected, input, desired, installedOutputValidator(t, selected), func(contract.CryptoKind) { private++ })
	store := requireAdmittedMemoryStore(t, f.env.Store)
	cas := store.cas
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "preserve unresolved publication"), input)
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || store.cas != cas+1 || private != 0 {
		t.Fatal("plain metadata with retained publication did not select without private work", result.Result, private)
	}
	fresh := f.open(t, ctx)
	if !reflect.DeepEqual(installedOutputConfiguration(t, ctx, fresh), before) || !reflect.DeepEqual(installedApplyStableWork(t, ctx, fresh), work) || fresh.root.OutputConfiguration != selected.root.OutputConfiguration || fresh.root.WarningBits != selected.root.WarningBits {
		t.Fatal("installed metadata changed output, original marker, coordinate history or warnings")
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.EffectSummary != contract.ReceiptEffectNoChange || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 {
		t.Fatal("metadata gained an output send or cleanup result", err)
	}
}

// full_only: false
func TestInstalledRetirementBindsSharedOutputBeforeCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := installedOutputSecretFixture(t, ctx, true)
	reader := fixtureID(f.env.Domain, "reader")
	encoded := outputConfigurationTarget("secret", "reader-secret")
	encoded.target.PayloadEncoding = contract.OutputEncodingBase64
	stable := outputConfigurationTarget("secret", "stable-secret")
	stable.target.PayloadEncoding = contract.OutputEncodingBase64
	f = installedOutputSelect(t, ctx, f, &outputApplyInput{
		bindings: []outputApplyBinding{{destinationID: "reader", targets: []outputApplyTarget{encoded}}, {destinationID: "stable", targets: []outputApplyTarget{stable}}},
		routes:   []outputApplyRoute{{entryName: "secret", destinations: []string{"reader", "stable"}}},
		groups:   [][]string{{"secret"}},
	})
	selected := f.selected
	before := installedOutputConfiguration(t, ctx, selected)
	if len(before.Bindings) != 2 || selected.valueEntry(selected.root.Names[0].Slot).OutputEncoding != contract.OutputEncodingBase64 || len(before.Routes) != 1 {
		t.Fatal("shared route and encoding fixture differs")
	}
	store := requireAdmittedMemoryStore(t, f.env.Store)
	cas := store.cas
	_, private := f.keys.Calls()
	installation := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, reader), nil, installedOutputValidator(t, selected))
	admit := installation.AdmitCustody
	called := 0
	installation.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, registry []contract.RecipientRecord, slot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warnings uint8, deadline time.Time) (*InstalledApplyCustody, error) {
		called++
		if witness == nil || witness.Output == nil || len(witness.Handoffs) != 0 || !reflect.DeepEqual(witness.Output.Before, before) || witness.Output.BeforeDescriptor != selected.root.OutputConfiguration {
			t.Fatal("shared output was not bound before custody")
		}
		bindings := []contract.NormalOutputBinding{
			{DestinationID: "reader", Destination: before.Bindings[0].Destination, Targets: []contract.NormalOutputTarget{{Name: "secret", Target: encoded.target}}},
			{DestinationID: "stable", Destination: before.Bindings[1].Destination, Targets: []contract.NormalOutputTarget{{Name: "secret", Target: stable.target}}},
		}
		routes := []contract.NormalOutputRoute{{Name: "secret", Destinations: []string{"reader", "stable"}}, {Default: true, Destinations: nil}}
		if !reflect.DeepEqual(witness.Output.Bindings, bindings) || !reflect.DeepEqual(witness.Output.Routes, routes) || !reflect.DeepEqual(witness.Output.Groups, [][]string{{"secret"}}) {
			t.Fatal("pre-custody witness changed the complete shared output")
		}
		return admit(ctx, q, control, registry, slot, plain, support, witness, revision, windows, warnings, deadline)
	}
	engine, err := NewInstalledRecipientRetirement(installation)
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Retire(ctx, fixtureID(f.env.Domain, "shared output retirement"))
	engine.Close()
	_, privateAfter := f.keys.Calls()
	if result.Result.Outcome != ObservedCurrent || called != 1 || store.cas != cas+1 || privateAfter-private != 2 {
		t.Fatal("shared output retirement did not select after exact custody", result.Result, called, privateAfter-private)
	}
	fresh := f.open(t, ctx)
	wantRegistry := slices.DeleteFunc(slices.Clone(selected.registry()), func(row contract.RecipientRecord) bool { return row.RecipientID == reader })
	if !reflect.DeepEqual(installedOutputConfiguration(t, ctx, fresh), before) || !reflect.DeepEqual(fresh.registry(), wantRegistry) {
		t.Fatal("recipient retirement changed shared routes, targets, encoding or groups")
	}
	incarnation := before.Routes[0].EntryIncarnationID
	var subjects []contract.ChangedSubjectIdentity
	for _, row := range []struct {
		kind, change       uint8
		primary, secondary contract.ID
	}{
		{contract.ChangedSubjectRecipient, contract.ChangedSubjectRemoved, reader, contract.ID{}},
		{contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, incarnation, contract.ID{}},
		{contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, incarnation, reader},
	} {
		id, err := contract.ChangedSubjectIdentityID(f.env.Domain, row.kind, row.primary, row.secondary)
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, contract.ChangedSubjectIdentity{Kind: row.kind, Change: row.change, Identity: id})
	}
	expectedSubjects, err := contract.ChangedSubjectDescriptor(subjects)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.ChangedSubjects != expectedSubjects || result.Payload == nil || result.Payload.ChangedSubjects.Count != expectedSubjects.Count || result.Payload.ChangedSubjects.IdentityRootDigest != expectedSubjects.Digest {
		t.Fatal("retirement receipt changed subjects beyond recipient access", err)
	}
}

// full_only: false
func TestInstalledRetirementPreservesDefaultAgainstProposedRegistry(t *testing.T) {
	for _, condition := range []string{"unassigned", "secret-member", "exclusion-keeps-default"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := installedOutputSecretFixture(t, ctx, condition != "unassigned")
			reader := fixtureID(f.env.Domain, "reader")
			target := outputConfigurationTarget("secret", "default-secret")
			f = installedOutputSelect(t, ctx, f, &outputApplyInput{
				bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}},
				routes: []outputApplyRoute{{entryName: "secret", destinations: []string{"app"}},
					{defaultRoute: true, destinations: []string{"app"}}},
			})
			selected := f.selected
			before := installedOutputConfiguration(t, ctx, selected)
			beforeEntry := ownScenarioValueEntry(*selected.valueEntry(selected.root.Names[0].Slot))
			wantRegistry := slices.DeleteFunc(slices.Clone(selected.registry()), func(row contract.RecipientRecord) bool { return row.RecipientID == reader })
			want := before
			want.Routes = slices.Clone(before.Routes)
			store := requireAdmittedMemoryStore(t, f.env.Store)
			cas := store.cas
			_, private := f.keys.Calls()
			var result PublicApplyResult
			called := 0
			if condition == "exclusion-keeps-default" {
				input := installedApplyCurrentInput(selected)
				input[0].Recipients = []contract.ID{selected.admission.recipient}
				engine := f.engineWithValidator(t, selected, input, currentApplyRecipients(selected.registry()), installedOutputValidator(t, selected), func(stage contract.CryptoKind) {
					if stage == contract.CryptoCompare {
						called++
					}
				})
				result = engine.Apply(ctx, fixtureID(f.env.Domain, "keep enrolled default"), input)
				engine.Close()
				want = before
				wantRegistry = selected.registry()
			} else {
				installation := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, reader), nil, installedOutputValidator(t, selected))
				admit := installation.AdmitCustody
				installation.AdmitCustody = func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, registry []contract.RecipientRecord, slot uint16, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, windows contract.MutationReceiptWindows, warnings uint8, deadline time.Time) (*InstalledApplyCustody, error) {
					called++
					if witness == nil || witness.Output == nil || len(witness.Handoffs) != 0 || !reflect.DeepEqual(witness.Output.Before, before) || !reflect.DeepEqual(witness.Output.Routes, []contract.NormalOutputRoute{{Name: "secret", Destinations: []string{"app"}}, {Default: true, Destinations: []string{"app"}}}) || len(witness.Output.Bindings) != 1 || len(witness.Output.Bindings[0].Targets) != 1 || !reflect.DeepEqual(witness.Output.Bindings[0].Targets[0].Target, target.target) {
						t.Fatal("retirement did not preserve the exact default before custody")
					}
					return admit(ctx, q, control, registry, slot, plain, support, witness, revision, windows, warnings, deadline)
				}
				engine, err := NewInstalledRecipientRetirement(installation)
				if err != nil {
					t.Fatal(err)
				}
				result = engine.Retire(ctx, fixtureID(f.env.Domain, "retire recipient with shared default"))
				engine.Close()
			}
			_, privateAfter := f.keys.Calls()
			wantPrivate := 2
			if condition == "unassigned" {
				wantPrivate = 0
			}
			if result.Result.Outcome != ObservedCurrent || called != 1 || store.cas != cas+1 || privateAfter-private != wantPrivate {
				t.Fatal("default lifecycle did not select with exact private scope", result.Result, called, privateAfter-private)
			}
			fresh := f.open(t, ctx)
			if !reflect.DeepEqual(installedOutputConfiguration(t, ctx, fresh), want) || !reflect.DeepEqual(fresh.registry(), wantRegistry) {
				t.Fatal("recipient lifecycle changed the shared default or intended registry")
			}
			_, current := lifecycleEntry(t, fresh, "secret")
			if condition == "unassigned" {
				if !reflect.DeepEqual(*current, beforeEntry) || !reflect.DeepEqual(fresh.accessRecords(), selected.accessRecords()) {
					t.Fatal("unassigned retirement changed unrelated secret material or access")
				}
			} else if current.ValueState == beforeEntry.ValueState || current.Incarnation != beforeEntry.Incarnation || !slices.Equal(current.Recipients, []contract.ID{fresh.admission.recipient}) {
				t.Fatal("membership removal did not refresh exactly the affected current secret")
			}
			receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
			wantKind, wantEffect := uint16(contract.OperationRetireRecipientIdentity), uint16(contract.ReceiptEffectNotApplicable)
			if condition == "exclusion-keeps-default" {
				wantKind, wantEffect = contract.OperationApplyDeclaration, contract.ReceiptEffectNoChange
			}
			if err != nil || receipt.OperationKind != wantKind || receipt.EffectSummary != wantEffect || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 {
				t.Fatal("default change gained output or generator effect permission", err)
			}
		})
	}
}

// full_only: false
func TestInstalledOutputAdmissionRefusesChangedIntentAndMissingProfilesBeforeCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := installedOutputSecretFixture(t, ctx, true)
	f = installedOutputSelect(t, ctx, f, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "strict-secret")}}}})
	selected := f.selected
	validator := installedOutputValidator(t, selected)
	input := installedApplyCurrentInput(selected)
	desired := currentApplyRecipients(selected.registry())
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
	for _, condition := range []string{"route-removal", "encoding-change", "unrouted-encoding", "missing-profile", "wrong-profile-version"} {
		t.Run(condition, func(t *testing.T) {
			proposal := ownPublicConfiguration(configuration)
			installed := validator
			switch condition {
			case "route-removal":
				proposal.Routing.Value = nil
			case "encoding-change":
				proposal.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingBase64)
			case "unrouted-encoding":
				proposal.Routing.Value = nil
				proposal.Entries.Value[0].OutputEncoding = publicPresent(contract.OutputEncodingBase64)
			case "missing-profile":
				proposal.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
				installed = NewPublicConfigurationValidator(nil)
			case "wrong-profile-version":
				proposal.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
				installed = NewPublicConfigurationValidator(func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error) {
					return contract.OutputTarget{}, contract.ErrRecord
				})
			}
			called := 0
			engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), DesiredRecipients: desired, PublicConfiguration: proposal, ConfigurationValidator: installed, CloseInstalled: func() {},
				AdmitCustody: func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error) {
					called++
					return nil, contract.ErrRecord
				}})
			if err != nil {
				t.Fatal(err)
			}
			store := requireAdmittedMemoryStore(t, f.env.Store)
			creates, cas, signs := store.creates, store.cas, f.env.Trust.(*fixtureTrust).signs
			public, private := f.keys.Calls()
			result := engine.Apply(ctx, fixtureID(f.env.Domain, "strict output "+condition), input)
			engine.Close()
			publicAfter, privateAfter := f.keys.Calls()
			if result.Result.Outcome != AdmissionRefused || called != 0 || store.creates != creates || store.cas != cas || f.env.Trust.(*fixtureTrust).signs != signs || publicAfter != public || privateAfter != private || result.Payload != nil || len(result.Receipt) != 0 || result.Result.CommitMayHaveOccurred {
				t.Fatal("invalid explicit output intent or absent installation crossed custody or mutation", result.Result, called)
			}
		})
	}
}

// full_only: false
func TestInstalledRetirementPreservesOutputSlicesAndRetainedWork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	retained := newRetainedReaderFixture(t, true, 2)
	selected := retained.selected
	f := installedApplyTestFixture{env: retained.env, keys: retained.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	reader := fixtureID(f.env.Domain, "reader")
	desired := installedApplyPreparedRecipient(t, selected, "reader-successor")
	var successor contract.ID
	for _, row := range desired {
		if selected.recipientRecord(row.Recipient.RecipientID) == nil {
			if !successor.IsZero() {
				t.Fatal("output slice fixture prepared more than one recipient")
			}
			successor = row.Recipient.RecipientID
		}
	}
	if successor.IsZero() {
		t.Fatal("output slice fixture did not prepare its successor recipient")
	}
	input := installedApplyCurrentInput(selected)
	for at := range input {
		if input[at].Name == "shared" {
			input[at].Recipients = append(slices.Clone(input[at].Recipients), successor)
			slices.SortFunc(input[at].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		}
	}
	grant := f.engineWithValidator(t, selected, input, desired, installedOutputValidator(t, selected), nil)
	granted := grant.Apply(ctx, fixtureID(f.env.Domain, "output slice boundary reader grant"), input)
	grant.Close()
	if granted.Result.Outcome != ObservedCurrent {
		t.Fatal("output slice boundary reader grant", granted.Result)
	}
	f.selected = f.open(t, ctx)
	if row := f.selected.recipientRecord(successor); row == nil || row.Status != contract.CurrentRecipient || row.CurrentBinding == nil {
		t.Fatal("output slice successor was not enrolled before routing")
	}
	// Two opaque policies cross one output slice; removing the target leaves one.
	policy := contract.OutputPolicy{ContractID: strings.Repeat("p", 256), Data: bytes.Repeat([]byte{7}, 524000)}
	target := outputConfigurationTarget("shared", strings.Repeat("s", 1024))
	target.target.ConsumerLocator = strings.Repeat("l", 1024)
	target.target.Policy = policy
	f = installedOutputSelect(t, ctx, f, &outputApplyInput{
		bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}},
		routes:   []outputApplyRoute{{entryName: "shared", destinations: []string{"app"}}},
		groups:   [][]string{{"shared"}},
	})
	selected = f.selected
	beforeOutput := installedOutputConfiguration(t, ctx, selected)
	if selected.root.OutputConfiguration.SliceCount != 2 || len(beforeOutput.Bindings) != 1 || len(beforeOutput.Bindings[0].Targets) != 1 || len(beforeOutput.Routes) != 1 {
		t.Fatal("fixture did not cross exactly the two-slice output boundary")
	}
	wantOutput := beforeOutput

	beforeCoordinate := selectedOutputCoordinate(t, selected, target.target.CanonicalTarget)
	wantCoordinate := beforeCoordinate

	stableWork := func(state *StateSession) []contract.SupportRecordDigest {
		facts := installedApplyStableWork(t, ctx, state)
		return slices.DeleteFunc(facts, func(row contract.SupportRecordDigest) bool {
			return row.Kind() == contract.OutputConfigurationSliceSupportKind || row.Kind() == contract.PublicationCoordinateSupportKind
		})
	}
	beforeWork := stableWork(selected)
	beforeClosure := selected.root.Generated
	beforeAccess := selected.accessRecords()
	beforeEntries := make(map[string]contract.ValueEntry)
	for _, named := range selected.root.Names {
		beforeEntries[named.Name] = ownScenarioValueEntry(*selected.valueEntry(named.Slot))
	}
	beforeReceipts, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	opaque := 0
	for _, page := range selected.support {
		for _, row := range page.Records {
			if row.Kind == contract.GeneratedFragmentSupportKind && row.Body == nil {
				opaque++
			}
		}
	}
	if opaque == 0 || len(selected.fragmentFacts) == 0 || len(retained.owners) != 2 {
		t.Fatal("fixture lacks authenticated opaque fragments and actual retained owners")
	}
	installation := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, successor), nil, installedOutputValidator(t, selected))
	engine, err := NewInstalledRecipientRetirement(installation)
	if err != nil {
		t.Fatal(err)
	}
	store := requireAdmittedMemoryStore(t, f.env.Store)
	cas := store.cas
	_, private := f.keys.Calls()
	result := engine.Retire(ctx, fixtureID(f.env.Domain, "shared output slice retirement"))
	engine.Close()
	_, privateAfter := f.keys.Calls()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || store.cas != cas+1 || privateAfter-private != 2 {
		t.Fatal("installed slice retention did not select once with only target custody", result.Result, privateAfter-private)
	}
	fresh := f.open(t, ctx)
	if fresh.root.OutputConfiguration.SliceCount != 2 || !reflect.DeepEqual(installedOutputConfiguration(t, ctx, fresh), wantOutput) || !reflect.DeepEqual(selectedOutputCoordinate(t, fresh, target.target.CanonicalTarget), wantCoordinate) || !slices.Equal(stableWork(fresh), beforeWork) {
		t.Fatal("slice retention changed unrelated authenticated records or lost exact output/coordinate meaning")
	}
	afterReceipts, err := fresh.receiptWindows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, result.OperationID)
	afterClosure := fresh.root.Generated
	beforeClosure.Fragments, afterClosure.Fragments = nil, nil
	beforeClosure.SuccessWindow, afterClosure.SuccessWindow = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	beforeClosure.ReceiptOrder, afterClosure.ReceiptOrder = contract.GeneratorDescriptor{}, contract.GeneratorDescriptor{}
	wantRegistry := slices.DeleteFunc(slices.Clone(selected.registry()), func(row contract.RecipientRecord) bool { return row.RecipientID == successor })
	if !reflect.DeepEqual(beforeClosure, afterClosure) || !reflect.DeepEqual(fresh.registry(), wantRegistry) || fresh.root.WarningBits != selected.root.WarningBits || !slices.Equal(fresh.generatedSliceLocations, selected.generatedSliceLocations) {
		t.Fatal("slice retention changed generated/retained owners, source locations, registry or warnings")
	}
	fragments, err := fresh.selectedFragmentFactsByRecord()
	if err != nil || len(fresh.fragmentFacts) != len(fresh.root.Generated.Fragments) || len(fragments) != len(fresh.root.Generated.Fragments)+int(fresh.root.OutputConfiguration.SliceCount) {
		t.Fatal("slice retention left incomplete fragment facts", err)
	}
	expectedKinds := make(map[contract.ID]contract.SupportRecordKind, len(fragments))
	for _, location := range fresh.root.Generated.Fragments {
		id, err := contract.GeneratorFragmentID(location.BlobID, location.FragmentIndex)
		fact, present := fresh.fragmentFacts[location]
		if err != nil || !present || expectedKinds[id] != 0 || fact.ref.Index != location.SupportPageIndex || fact.logical != uint16(location.RowSlot) || fragments[id] != fact {
			t.Fatal("generated fragment directory differs from exact selected locations and facts", err)
		}
		expectedKinds[id] = contract.GeneratedFragmentSupportKind
	}
	for index := uint16(0); index < fresh.root.OutputConfiguration.SliceCount; index++ {
		id, err := contract.OutputConfigurationSliceID(fresh.root.Domain, fresh.root.OutputConfiguration.ConfigurationDigest, index)
		fact, present := fragments[id]
		if err != nil || !present || expectedKinds[id] != 0 || fact.blob != fresh.root.OutputConfiguration.ConfigurationDigest {
			t.Fatal("output slice census differs from the complete selected descriptor", err)
		}
		expectedKinds[id] = contract.OutputConfigurationSliceSupportKind
	}
	for id, fact := range fragments {
		kind, expected := expectedKinds[id]
		position := slices.Index(fresh.root.RequiredSupport, fact.ref)
		if !expected || fact.row.RecordID() != id || fact.row.Kind() != kind || position < 0 {
			t.Fatal("fragment union contains an unexpected identity, kind or physical reference")
		}
		page := fresh.supportFacts[position]
		logical := int(fact.logical)
		if page.ref != fact.ref || logical >= len(page.rows) || logical >= len(page.ordinals) || page.rows[logical] != fact.row || page.ordinals[logical] != fact.physical {
			t.Fatal("fragment union does not match its exact authenticated physical row")
		}
		delete(expectedKinds, id)
	}
	if len(expectedKinds) != 0 {
		t.Fatal("fragment union omitted a generated directory row or output slice")
	}
	for location, fact := range selected.fragmentFacts {
		if slices.Contains(fresh.root.RequiredSupport, fact.ref) {
			if current, present := fresh.fragmentFacts[location]; !present || current != fact {
				t.Fatal("unchanged fragment page lost its exact physical reference, index or ordinal")
			}
		}
	}
	for _, named := range fresh.root.Names {
		current, before := fresh.valueEntry(named.Slot), beforeEntries[named.Name]
		if named.Name != "shared" {
			if !reflect.DeepEqual(*current, before) {
				t.Fatal("slice retention changed unrelated current value")
			}
		} else if current.Incarnation != before.Incarnation || current.ValueState == before.ValueState || bytes.Equal(current.ValueBytes, before.ValueBytes) || !slices.Equal(current.Recipients, []contract.ID{fresh.admission.recipient}) {
			t.Fatal("slice retention did not refresh exactly the excluded current secret")
		}
	}
	if len(fresh.accessRecords()) != len(beforeAccess) {
		t.Fatal("slice retention changed the material access inventory")
	}
	for _, before := range beforeAccess {
		if before.MaterialKind == contract.ValueMaterialKind && before.MaterialID == beforeEntries["shared"].ValueState {
			if _, present := fresh.materialAccess(before.MaterialKind, before.MaterialID); present {
				t.Fatal("unowned replaced current material remained selected")
			}
			continue
		}
		current, present := fresh.materialAccess(before.MaterialKind, before.MaterialID)
		if !present || !reflect.DeepEqual(current, before) {
			t.Fatal("slice retention changed unrelated current or retained access")
		}
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationRetireRecipientIdentity || receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 2 || receipt.WarningBits&contract.ReceiptWarningPossibleLive == 0 {
		t.Fatal("slice retention changed operation receipt or gained effect permission", err)
	}
	wantSuccesses := append(slices.Clone(beforeReceipts.Successes), receipt)
	if len(wantSuccesses) > contract.MutationReceiptWindowLimit {
		wantSuccesses = wantSuccesses[len(wantSuccesses)-contract.MutationReceiptWindowLimit:]
	}
	if err != nil || afterReceipts.DomainID != beforeReceipts.DomainID || !slices.Equal(afterReceipts.Successes, wantSuccesses) || !slices.Equal(afterReceipts.Failures, beforeReceipts.Failures) {
		t.Fatal("slice retention did not append exactly one receipt and preserve both windows", err)
	}
	var owners []contract.ID
	for owner := range retained.owners {
		owners = append(owners, owner)
		selection, outcome := fresh.generatedConsumerSelection(ctx, contract.GeneratedHazardSupportKind, owner, retained.value.ValueState, reader)
		if outcome.Outcome != ObservedCurrent {
			t.Fatal("cold slice retention lost the retained reader selection", outcome)
		}
		if check := f.keys.ConsumeGenerated(ctx, selection, custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("cold slice retention lost retained plaintext access", check)
		}
	}
	slices.SortFunc(owners, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	if !slices.Equal(result.Payload.LiveHazardIDs, owners) || len(result.Payload.LiveDutyIDs) != 0 {
		t.Fatal("slice retention returned the wrong live owner set")
	}
	if check := f.keys.Consume(ctx, sessionConsumerSelection(t, fresh, fresh.admission.recipient, "shared"), custody.StandardValue); check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
		t.Fatal("cold slice retention changed current plaintext", check)
	}
}
