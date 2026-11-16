package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func hermeticDestinationSettings(rows [][2]string) []byte {
	values := make(map[string]string, len(rows))
	for _, row := range rows {
		values[row[0]] = row[1]
	}
	body, err := json.Marshal(values)
	if err != nil {
		panic(err)
	}
	return body
}
func hermeticNumberPolicy(contractID string, subjects []uint64) contract.OutputPolicy {
	var values []string
	for _, subject := range subjects {
		values = append(values, fmt.Sprint(subject))
	}
	return contract.OutputPolicy{ContractID: contractID, Data: []byte(strings.Join(values, ","))}
}
func hermeticTextPolicy(contractID string, subjects []string) contract.OutputPolicy {
	body, err := json.Marshal(subjects)
	if err != nil {
		panic(err)
	}
	return contract.OutputPolicy{ContractID: contractID, Data: body}
}
func hermeticOutputEncoding(value string) uint8 {
	switch value {
	case "raw":
		return contract.OutputEncodingRaw
	case "base64":
		return contract.OutputEncodingBase64
	default:
		panic("invalid fixture encoding")
	}
}
func hermeticRetargetOutput(target *contract.OutputTarget, physical, locator string) {
	target.CanonicalTarget, target.ConsumerLocator = physical, locator
	target.TargetData = []byte("target:" + physical)
}
func hermeticNativeOutputTarget(physical, locator string, encoding uint8, policy contract.OutputPolicy) contract.OutputTarget {
	target := outputFixtureTarget("test-output/service/v1", physical, locator, encoding, 255, policy)
	target.TargetContractID = "test-output/target/v1"
	return target
}
func hermeticPublicOutputTarget(name string, target contract.OutputTarget) contract.PublicOutputTarget {
	return contract.PublicOutputTarget{EntryName: name, ServiceContractID: publicPresent(target.ServiceContractID),
		CanonicalTarget: publicPresent(target.CanonicalTarget), ConsumerLocator: publicPresent(target.ConsumerLocator),
		TargetContractID: publicPresent(target.TargetContractID), TargetData: publicPresent(bytes.Clone(target.TargetData)),
		PayloadEncoding: publicPresent(target.PayloadEncoding), LocatorRequiresCreation: publicPresent(target.LocatorRequiresCreation),
		Capabilities: publicPresent(target.Capabilities), CreateValueBounds: publicPresent(target.CreateValueBounds), WriteValueBounds: publicPresent(target.WriteValueBounds),
		ConsumerPolicy: publicPresent(target.Policy)}
}

func publicOutputApplyProposal(configuration *contract.PublicConfiguration, output *outputApplyInput) {
	configuration.OutputBindings = observedPublicField([]contract.PublicOutputBinding(nil))
	for _, binding := range output.bindings {
		configuration.OutputBindings.Value = append(configuration.OutputBindings.Value, contract.PublicOutputBinding{
			DestinationID: binding.destinationID, Destination: observedPublicField(binding.destination),
			Targets: contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable},
		})
	}
	configuration.Routing = observedPublicField([]contract.PublicRoutingRule(nil))
	for _, route := range output.routes {
		key := contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: route.entryName}
		if route.defaultRoute {
			key.EntrySelector = contract.PublicDefaultRoute
		}
		configuration.Routing.Value = append(configuration.Routing.Value, contract.PublicRoutingRule{Key: key, Destinations: observedPublicField(slices.Clone(route.destinations))})
	}
	configuration.Groups = observedPublicField(output.groups)
}

func publicOutputApplyExpectedBinding(domain, operation contract.ID, destination string) contract.ID {
	// The specification frames the destination with a four-byte big-endian length.
	material := append([]byte("ENKV/OUTPUT/APPLY-BINDING/v1\x00"), domain[:]...)
	material = append(material, operation[:]...)
	material = binary.BigEndian.AppendUint32(material, uint32(len(destination)))
	material = append(material, destination...)
	return contract.ID(sha256.Sum256(material))
}

func publicOutputApplyAssertNoPublication(t testing.TB, selected *StateSession) {
	t.Helper()
	relation, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil || len(relation.markers) != 0 {
		t.Fatal("plain apply admitted publication work", err)
	}
	for _, coordinate := range relation.coordinates {
		if coordinate.OwnerState != contract.PublicationOwnerNone || !coordinate.OwnedBirthAttemptID.IsZero() || coordinate.LastAdmissionOrdinal != 0 || coordinate.PossibleRemoteObject != 0 || coordinate.LateEffectRisk != 0 {
			t.Fatal("plain apply acquired output effect or birth evidence")
		}
	}
}

// Re-offer the edited fixture proposal through the public constructor. Keeping
// this caller-owned copy tests the ownership boundary; the engine is free to
// normalize the separate proposal it owns.
func publicOutputApplyReinstall(t testing.TB, previous *InstalledApply) (*InstalledApply, contract.PublicConfiguration) {
	t.Helper()
	installation := previous.installation
	source := installation.PublicConfiguration
	previous.Close()
	engine, err := NewInstalledApply(installation)
	if err != nil {
		t.Fatal("public output proposal construction", err)
	}
	t.Cleanup(engine.Close)
	return engine, source
}

func publicOutputApplyAssertConfiguration(t testing.TB, got, want contract.OutputConfiguration) {
	t.Helper()
	if got.Schema != want.Schema || got.DomainID != want.DomainID || len(got.Bindings) != len(want.Bindings) || len(got.Routes) != len(want.Routes) || len(got.Groups) != len(want.Groups) {
		t.Fatal("cold selection changed the exact output declaration sets")
	}
	actual, err := contract.EncodeOutputConfiguration(got)
	if err != nil {
		t.Fatal("cold output configuration encoding", err)
	}
	expected, err := contract.EncodeOutputConfiguration(want)
	if err != nil {
		t.Fatal("independent expected output configuration encoding", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("cold selection differs from the complete requested output rows")
	}
}

// full_only: false
func TestPublicOutputApplySelectsCompleteDeclaration(t *testing.T) {
	for _, condition := range []string{"output-only", "value-and-output-removal", "recipient-enrollment-and-route"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("before"), Recipients: []contract.ID{f.selected.admission.recipient}}}
			seed := f.engine(t, f.selected, input, nil)
			if result := seed.Apply(ctx, fixtureID(f.env.Domain, "public output seed"), input); result.Result.Outcome != ObservedCurrent {
				t.Fatal("plain seed", result.Result)
			}
			seed.Close()
			f.selected = f.open(t, ctx)
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("plain", "public-plain")}}}}
			f = installedOutputSelect(t, ctx, f, output)
			selected := f.selected
			beforeOutput := installedOutputConfiguration(t, ctx, selected)
			beforeEntry := ownScenarioValueEntry(*selected.valueEntry(entrySlot(t, selected, "plain")))
			input = installedApplyCurrentInput(selected)
			desired := currentApplyRecipients(selected.registry())
			if condition == "recipient-enrollment-and-route" {
				desired = installedApplyPreparedRecipient(t, selected, "public output enrolled recipient")
				for _, row := range desired {
					if row.Creation != nil {
						routedRecipient := row.Recipient.RecipientID
						input[0].Recipients = append(slices.Clone(input[0].Recipients), routedRecipient)
						slices.SortFunc(input[0].Recipients, compareGeneratedIDs)
					}
				}
			}
			if condition == "value-and-output-removal" {
				input[0].InputBytes = []byte("after")
			}
			if condition != "value-and-output-removal" {
				input[0].OutputEncoding = contract.OutputEncodingBase64
			}
			engine := f.engineWithValidator(t, selected, input, desired, installedOutputValidator(t, selected), nil)
			proposal := &engine.installation.PublicConfiguration
			want := beforeOutput
			wantCount := uint32(2)
			if condition != "value-and-output-removal" {
				proposal.Groups = observedPublicField([][]string{{"plain"}})
				proposal.Entries.Value[0].OutputEncoding = observedPublicField(contract.OutputEncodingBase64)
				proposal.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
				proposal.Routing = observedPublicField([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: observedPublicField([]string{"app"})}})
				want.Bindings = slices.Clone(beforeOutput.Bindings)
				want.Bindings[0].Targets = slices.Clone(beforeOutput.Bindings[0].Targets)
				want.Bindings[0].Targets[0].PayloadEncoding = contract.OutputEncodingBase64
				want.Groups = [][]contract.ID{{beforeEntry.Incarnation}}
				want.DefaultDestinations = []string{"app"}
				want.Routes = nil
				if condition == "recipient-enrollment-and-route" {
					wantCount = 4
				}
			} else {
				publicOutputApplyProposal(proposal, &outputApplyInput{})
				want = contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain}
				wantCount = 2
			}
			engine, source := publicOutputApplyReinstall(t, engine)
			proposalBefore := ownPublicConfiguration(source)
			inputBefore := bytes.Clone(input[0].InputBytes)
			store := requireAdmittedMemoryStore(t, f.env.Store)
			cas := store.cas
			result := engine.Apply(ctx, fixtureID(f.env.Domain, "public output "+condition), input)
			engine.Close()
			if result.Result.Outcome != ObservedCurrent || result.Payload == nil || store.cas != cas+1 {
				t.Fatal("complete output declaration was refused or not selected once", result.Result)
			}
			cold := f.open(t, ctx)
			publicOutputApplyAssertConfiguration(t, installedOutputConfiguration(t, ctx, cold), want)
			after := cold.valueEntry(entrySlot(t, cold, "plain"))
			if after.Incarnation != beforeEntry.Incarnation {
				t.Fatal("apply changed the retained entry incarnation")
			}
			if after.InputEncoding != input[0].InputEncoding || after.OutputEncoding != input[0].OutputEncoding {
				t.Fatal("apply lost the requested entry encodings")
			}
			if condition == "output-only" && (after.ValueState != beforeEntry.ValueState || after.OriginSnapshot != beforeEntry.OriginSnapshot || after.OriginTransition != beforeEntry.OriginTransition || after.ContentLength != beforeEntry.ContentLength || after.RetainedLength != beforeEntry.RetainedLength) {
				t.Fatal("output-only apply changed immutable value metadata")
			}
			if !bytes.Equal(after.ValueBytes, inputBefore) {
				t.Fatal("apply lost the requested value bytes")
			}
			if !slices.Equal(after.Recipients, input[0].Recipients) {
				t.Fatal("apply lost the requested recipient membership")
			}
			if !reflect.DeepEqual(proposalBefore, source) {
				t.Fatal("apply changed the caller-owned public proposal")
			}
			if !bytes.Equal(input[0].InputBytes, inputBefore) {
				t.Fatal("apply changed borrowed input bytes")
			}
			receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
			if err != nil || receipt.ChangedSubjects.Count != wantCount || result.Payload.ChangedSubjects.Count != wantCount || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 {
				t.Fatal("apply receipt omitted output changes or claimed publication", err, receipt.ChangedSubjects.Count)
			}
			if condition == "output-only" {
				// Target encoding, routes and groups update the same retained binding.
				// The complete vector adds the retained entry, with no membership row.
				var rows [][]byte
				for _, subject := range []struct {
					kind byte
					id   contract.ID
				}{{1, beforeEntry.Incarnation}, {5, beforeOutput.Bindings[0].IncarnationID}} {
					preimage := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), f.env.Domain[:]...)
					preimage = append(preimage, subject.kind)
					preimage = append(preimage, subject.id[:]...)
					preimage = append(preimage, make([]byte, 32)...)
					digest := sha256.Sum256(preimage)
					rows = append(rows, append([]byte{subject.kind, 3}, digest[:]...))
				}
				slices.SortFunc(rows, bytes.Compare)
				vector := binary.BigEndian.AppendUint32(nil, 2)
				for _, row := range rows {
					vector = append(binary.BigEndian.AppendUint32(vector, 34), row...)
				}
				preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/changed-subjects\x00"), uint32(len(vector)))
				wantSubjects := contract.GeneratorDescriptor{Count: 2, Length: 80, Digest: sha256.Sum256(append(preimage, vector...))}
				if receipt.ChangedSubjects != wantSubjects || result.Payload.ChangedSubjects != (ChangedSubjectCommitment{Count: 2, IdentityRootDigest: wantSubjects.Digest}) {
					t.Fatal("routed encoding edit omitted or added changed subjects", receipt.ChangedSubjects, wantSubjects)
				}
				retained, raw, found, err := cold.retainedMutationReceipt(result.OperationID)
				if err != nil || !found || retained != receipt || !bytes.Equal(raw, result.Receipt) {
					t.Fatal("retained routed encoding receipt differs from the returned receipt", err)
				}
			}
			publicOutputApplyAssertNoPublication(t, cold)
		})
	}
	t.Run("encoding-only-without-destinations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		process, effects := configurationRecoveryLocalGeneratedProcess(t)
		f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
		f.env.GeneratedProcess = process
		authority := f.selected.admission.recipient
		implementation := process.Implementation
		metadata := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged,
			RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged,
			ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), Intent: bytes.Clone(process.Intent)}
		input := []ApplyEntryInput{
			{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{authority}, Generated: metadata,
				InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
			{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("retained plain bytes"),
				InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
			suppliedSecret(t, f.env, "secret", "output encoding source", custody.StandardValue, authority),
			{Name: "untouched", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("unchanged sibling"),
				InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
		}
		seed := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedTestCallbacks(t, f, process))
		if result := seed.Apply(ctx, fixtureID(f.env.Domain, "encoding receipt seed"), input); result.Result.Outcome != ObservedCurrent {
			t.Fatal("encoding receipt seed", result.Result)
		}
		seed.Close()
		selected := f.open(t, ctx)
		creates, deletes := effects()
		for _, encoding := range []uint8{contract.OutputEncodingBase64, contract.OutputEncodingRaw} {
			input = installedApplyCurrentInput(selected)
			var rows [][]byte
			for at := range input {
				if input[at].Name == "untouched" {
					continue
				}
				input[at].OutputEncoding = encoding
				before := selected.valueEntry(entrySlot(t, selected, input[at].Name))
				identities := []struct {
					kind byte
					id   contract.ID
				}{{1, before.Incarnation}}
				if before.ValueSource == contract.Generated {
					identities = append(identities, struct {
						kind byte
						id   contract.ID
					}{4, before.Generated.GenerationID})
				}
				// Identity framing and the four updated rows are derived independently
				// from the Product changed-subject contract, without its encoder.
				for _, identity := range identities {
					preimage := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), f.env.Domain[:]...)
					preimage = append(preimage, identity.kind)
					preimage = append(preimage, identity.id[:]...)
					preimage = append(preimage, make([]byte, 32)...)
					digest := sha256.Sum256(preimage)
					rows = append(rows, append([]byte{identity.kind, 3}, digest[:]...))
				}
			}
			slices.SortFunc(rows, bytes.Compare)
			vector := binary.BigEndian.AppendUint32(nil, 4)
			for _, row := range rows {
				vector = append(binary.BigEndian.AppendUint32(vector, 34), row...)
			}
			preimage := binary.BigEndian.AppendUint32([]byte("ENKV/GENERATOR/v1/changed-subjects\x00"), uint32(len(vector)))
			want := contract.GeneratorDescriptor{Count: 4, Length: 156, Digest: sha256.Sum256(append(preimage, vector...))}
			var privateStages []contract.CryptoKind
			engine := f.engine(t, selected, input, func(kind contract.CryptoKind) { privateStages = append(privateStages, kind) })
			result := engine.Apply(ctx, fixtureID(f.env.Domain, fmt.Sprintf("encoding receipt %d", encoding)), input)
			engine.Close()
			if result.Result.Outcome != ObservedCurrent || result.Payload == nil {
				t.Fatal("encoding-only apply was not selected", result.Result, "private stages", privateStages)
			}
			cold := f.open(t, ctx)
			for _, named := range selected.root.Names {
				before := selected.valueEntry(named.Slot)
				after := cold.valueEntry(entrySlot(t, cold, named.Name))
				wantEntry := ownScenarioValueEntry(*before)
				if named.Name != "untouched" {
					wantEntry.OutputEncoding = encoding
				}
				if !reflect.DeepEqual(*after, wantEntry) {
					t.Fatal("encoding-only apply changed retained value or membership", named.Name)
				}
				if before.ConfidentialityClass == contract.Secret {
					oldCore, oldErr := contract.ValueCoreForEntry(f.env.Domain, contract.CompatibilityID(), *before)
					newCore, newErr := contract.ValueCoreForEntry(f.env.Domain, contract.CompatibilityID(), *after)
					if oldErr != nil || newErr != nil || !reflect.DeepEqual(oldCore, newCore) {
						t.Fatal("encoding-only apply changed immutable ValueCore", oldErr, newErr)
					}
				}
			}
			afterCreates, afterDeletes := effects()
			if afterCreates != creates || afterDeletes != deletes {
				t.Fatal("encoding-only apply regenerated or retired a value", afterCreates, afterDeletes)
			}
			if configuration := installedOutputConfiguration(t, ctx, cold); len(configuration.Bindings) != 0 || len(configuration.Routes) != 0 || len(configuration.DefaultDestinations) != 0 || len(configuration.Groups) != 0 {
				t.Fatal("encoding-only apply acquired output destinations")
			}
			receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
			if err != nil || receipt.ChangedSubjects != want || result.Payload.ChangedSubjects != (ChangedSubjectCommitment{Count: want.Count, IdentityRootDigest: want.Digest}) {
				t.Fatal("returned encoding-only receipt omitted or added changed subjects", err, receipt.ChangedSubjects, want)
			}
			retained, raw, found, err := cold.retainedMutationReceipt(result.OperationID)
			if err != nil || !found || retained != receipt || retained.ChangedSubjects != want || !bytes.Equal(raw, result.Receipt) {
				t.Fatal("selected encoding-only receipt differs from the returned receipt", err)
			}
			publicOutputApplyAssertNoPublication(t, cold)
			selected = cold
		}
	})

}

// full_only: false
func TestPublicOutputApplyCapacityUsesSuccessorMembership(t *testing.T) {
	for _, condition := range []string{"membership-removal", "new-entry"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			authority, reader := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
			members := []contract.ID{authority, reader}
			slices.SortFunc(members, compareGeneratedIDs)
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("retained value"), Recipients: members}}
			seed := f.engine(t, f.selected, input, nil)
			if result := seed.Apply(ctx, fixtureID(f.env.Domain, "prospective output seed"), input); result.Result.Outcome != ObservedCurrent {
				t.Fatal("prospective membership seed", result.Result)
			}
			seed.Close()
			f.selected = f.open(t, ctx)
			plain := outputConfigurationTarget("plain", "prospective-plain")
			f = installedOutputSelect(t, ctx, f, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{plain}}}})
			before := installedOutputConfiguration(t, ctx, f.selected)
			oldEntry := ownScenarioValueEntry(*f.selected.valueEntry(entrySlot(t, f.selected, "plain")))
			input = installedApplyCurrentInput(f.selected)
			targetName, target := "plain", plain.target
			if condition == "membership-removal" {
				input[0].Recipients = []contract.ID{authority}
			} else {
				added := outputConfigurationTarget("plain-added", "prospective-added")
				// Install one passive table that can derive both the authenticated
				// predecessor and the new declaration. No output is selected here.
				installOutputFixtureSource(t, f.selected, &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{plain, added}}}})
				input = append(input, ApplyEntryInput{Name: "plain-added", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("new value"), Recipients: []contract.ID{authority}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
				targetName, target = "plain-added", added.target
			}
			engine := f.engineWithValidator(t, f.selected, input, currentApplyRecipients(f.selected.registry()), installedOutputValidator(t, f.selected), nil)
			proposal := &engine.installation.PublicConfiguration
			proposal.Groups = observedPublicField([][]string{{targetName}})
			proposal.OutputBindings.Value[0].Targets = contract.PublicField[[]contract.PublicOutputTarget]{State: contract.PublicUnavailable}
			proposal.Routing = observedPublicField([]contract.PublicRoutingRule{{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: targetName}, Destinations: observedPublicField([]string{"app"})}})
			engine, source := publicOutputApplyReinstall(t, engine)
			sourceBefore := ownPublicConfiguration(source)
			store := requireAdmittedMemoryStore(t, f.env.Store)
			cas := store.cas
			result := engine.Apply(ctx, fixtureID(f.env.Domain, "prospective output "+condition), input)
			engine.Close()
			if result.Result.Outcome != ObservedCurrent || result.Payload == nil || store.cas != cas+1 {
				t.Fatal("successor membership was not admitted with its exact output", result.Result)
			}
			cold := f.open(t, ctx)
			for _, desired := range input {
				entry := cold.valueEntry(entrySlot(t, cold, desired.Name))
				if !bytes.Equal(entry.ValueBytes, desired.InputBytes) || !slices.Equal(entry.Recipients, desired.Recipients) {
					t.Fatal("successor value or membership differs", desired.Name)
				}
			}
			if cold.valueEntry(entrySlot(t, cold, "plain")).Incarnation != oldEntry.Incarnation || !reflect.DeepEqual(source, sourceBefore) {
				t.Fatal("capacity admission changed retained identity or caller proposal")
			}
			selectedEntry := cold.valueEntry(entrySlot(t, cold, targetName))
			target.EntryIncarnationID = selectedEntry.Incarnation
			want := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain,
				Bindings: []contract.OutputBinding{{DestinationID: "app", IncarnationID: before.Bindings[0].IncarnationID, Destination: before.Bindings[0].Destination, Targets: []contract.OutputTarget{target}}},
				Routes:   []contract.OutputRoute{{EntryIncarnationID: selectedEntry.Incarnation, Destinations: []string{"app"}}}, Groups: [][]contract.ID{{selectedEntry.Incarnation}}}
			publicOutputApplyAssertConfiguration(t, installedOutputConfiguration(t, ctx, cold), want)
			receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
			if err != nil || receipt.ChangedSubjects.Count != 3 || result.Payload.ChangedSubjects.Count != 3 || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 {
				t.Fatal("successor membership/output receipt differs", err, receipt.ChangedSubjects.Count)
			}
			publicOutputApplyAssertNoPublication(t, cold)
		})
	}
}

// full_only: false
func TestPublicGeneratedOutputApplySelectsCompleteDeclaration(t *testing.T) {
	for _, condition := range []string{"generated-and-output", "zero-create", "failed-final"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := configurationRecoveryLocalGeneratedProcess(t)
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			f.env.GeneratedProcess = process
			implementation := process.Implementation
			meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: meta}, {InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("whole sibling")}}
			if condition == "zero-create" {
				seed := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedTestCallbacks(t, f, process))
				if result := seed.Apply(ctx, fixtureID(f.env.Domain, "zero-create output seed"), input); result.Result.Outcome != ObservedCurrent {
					t.Fatal("generated seed", result.Result)
				}
				seed.Close()
				f.selected = f.open(t, ctx)
			}
			output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("generated", "public-generated"), outputConfigurationTarget("plain", "public-sibling")}}}, groups: [][]string{{"generated", "plain"}}}
			installOutputFixtureSource(t, f.selected, output)
			f.admitted = OpenContext{admission: &f.selected.admission}
			callbacks := installedGeneratedTestCallbacks(t, f, process)
			if condition == "failed-final" {
				callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
					return nil, contract.ErrRecord
				}
			}
			engine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
			engine, source := publicOutputApplyReinstall(t, engine)
			proposal := ownPublicConfiguration(source)
			result := engine.Apply(ctx, fixtureID(f.env.Domain, "public generated output "+condition), input)
			engine.Close()
			cold := f.open(t, ctx)
			creates, deletes := effects()
			if condition == "failed-final" {
				if creates != 1 || deletes != 0 || cold.root.ValueEntryCount != 0 || len(installedOutputConfiguration(t, ctx, cold).Bindings) != 0 || cold.root.Generated.ActiveOwner.IsZero() {
					t.Fatal("failed generated parent selected requested value/output or failed before the intended Final boundary", result.Result, creates, deletes)
				}
				return
			}
			if result.Result.Outcome != ObservedCurrent || result.Payload == nil || creates != 1 || deletes != 0 || cold.root.ValueEntryCount != 2 {
				t.Fatal("complete generated/output declaration was not selected", result.Result, creates, deletes)
			}
			want := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain, Groups: [][]contract.ID{{}}, Bindings: []contract.OutputBinding{{DestinationID: "app", IncarnationID: publicOutputApplyExpectedBinding(f.env.Domain, result.OperationID, "app"), Destination: output.bindings[0].destination}}}
			for _, named := range output.bindings[0].targets {
				entry := cold.valueEntry(entrySlot(t, cold, named.entryName))
				target := named.target
				target.EntryIncarnationID = entry.Incarnation
				want.Bindings[0].Targets = append(want.Bindings[0].Targets, target)
				want.Groups[0] = append(want.Groups[0], entry.Incarnation)
				want.Routes = append(want.Routes, contract.OutputRoute{EntryIncarnationID: entry.Incarnation, Destinations: []string{"app"}})
			}
			slices.SortFunc(want.Bindings[0].Targets, func(a, b contract.OutputTarget) int {
				return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
			})
			slices.SortFunc(want.Groups[0], compareGeneratedIDs)
			slices.SortFunc(want.Routes, func(a, b contract.OutputRoute) int {
				return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
			})
			publicOutputApplyAssertConfiguration(t, installedOutputConfiguration(t, ctx, cold), want)
			if !bytes.Equal(input[1].InputBytes, []byte("whole sibling")) || input[0].InputBytes != nil {
				t.Fatal("generated apply changed borrowed entry inputs")
			}
			if !bytes.Equal(meta.Intent, process.Intent) {
				t.Fatal("generated apply changed the borrowed generator intent")
			}
			if !reflect.DeepEqual(proposal, source) {
				t.Fatal("generated apply changed the caller-owned public proposal")
			}
			publicOutputApplyAssertNoPublication(t, cold)
		})
	}
}

func publicGeneratedOutputEngine(t testing.TB, ctx context.Context, f installedApplyTestFixture, input []ApplyEntryInput, output *outputApplyInput, callbacks *GeneratedApplyInstallation) *InstalledApply {
	t.Helper()
	engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), callbacks)
	engine.installation.ConfigurationValidator = NewPublicConfigurationValidator(f.selected.admission.outputInterpreter)
	publicOutputApplyProposal(&engine.installation.PublicConfiguration, output)
	return engine
}

// full_only: false
func TestPublicGeneratedOutputContinuationKeepsAcceptedDeclaration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	implementation := process.Implementation
	meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: meta}, {InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("accepted sibling")}}
	target := outputConfigurationTarget("generated", "accepted-generated")
	target.target.PayloadEncoding = contract.OutputEncodingBase64
	input[0].OutputEncoding = contract.OutputEncodingBase64
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target, outputConfigurationTarget("plain", "accepted-plain")}}}, groups: [][]string{{"generated", "plain"}}}
	installOutputFixtureSource(t, f.selected, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	engine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
	stopped := engine.Apply(ctx, fixtureID(f.env.Domain, "accepted output stop"), input)
	engine.Close()
	cold := f.open(t, ctx)
	creates, deletes := effects()
	if creates != 1 || deletes != 0 || stopped.OperationID.IsZero() || cold.root.Generated.ActiveOwner != stopped.OperationID || cold.root.ValueEntryCount != 0 || len(installedOutputConfiguration(t, ctx, cold).Bindings) != 0 {
		t.Fatal("generated stop did not retain only pending complete intent", stopped.Result, creates, deletes)
	}
	work, err := cold.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	graph := work.bundles[0]
	image, err := work.readSelectedSlice(ctx, contract.GeneratorContentOutputConfiguration, stopped.OperationID, contract.MaxOutputConfigurationBytes)
	if err != nil || graph.Request.Schema != contract.GeneratorApplyRequestCoreSchema {
		t.Fatal("accepted output image missing", err)
	}
	accepted, _, err := contract.InspectOutputConfiguration(f.env.Domain, image)
	if err != nil || len(accepted.Bindings) != 1 || accepted.Bindings[0].IncarnationID != publicOutputApplyExpectedBinding(f.env.Domain, stopped.OperationID, "app") {
		t.Fatal("retained output has wrong binding", err)
	}
	input[1].InputBytes[0], meta.Intent[0] = 'X', 'X'
	f.selected = cold
	edited := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "edited", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{cold.admission.recipient}, InputBytes: []byte("unrelated local proposal")}}
	resumed := publicGeneratedOutputEngine(t, ctx, f, edited, &outputApplyInput{}, installedGeneratedTestCallbacks(t, f, process))
	result := resumed.Continue(ctx, fixtureID(f.env.Domain, "accepted output continuation"), stopped.OperationID)
	resumed.Close()
	after := f.open(t, ctx)
	creates, deletes = effects()
	if result.Result.Outcome != ObservedCurrent || result.RequestIdentity != stopped.RequestIdentity || creates != 1 || deletes != 0 || !after.root.Generated.ActiveOwner.IsZero() || after.root.ValueEntryCount != 2 {
		t.Fatal("continuation did not select the accepted complete set without another create", result.Result, creates, deletes)
	}
	want := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: f.env.Domain, Groups: [][]contract.ID{{}}, Bindings: []contract.OutputBinding{{DestinationID: "app", IncarnationID: publicOutputApplyExpectedBinding(f.env.Domain, stopped.OperationID, "app"), Destination: output.bindings[0].destination}}}
	for _, named := range output.bindings[0].targets {
		entry := after.valueEntry(entrySlot(t, after, named.entryName))
		target := named.target
		target.EntryIncarnationID = entry.Incarnation
		want.Bindings[0].Targets = append(want.Bindings[0].Targets, target)
		want.Groups[0] = append(want.Groups[0], entry.Incarnation)
		want.Routes = append(want.Routes, contract.OutputRoute{EntryIncarnationID: entry.Incarnation, Destinations: []string{"app"}})
	}
	slices.SortFunc(want.Bindings[0].Targets, func(a, b contract.OutputTarget) int {
		return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
	})
	slices.SortFunc(want.Groups[0], compareGeneratedIDs)
	slices.SortFunc(want.Routes, func(a, b contract.OutputRoute) int {
		return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:])
	})
	if after.valueEntry(entrySlot(t, after, "generated")).OutputEncoding != contract.OutputEncodingBase64 || !reflect.DeepEqual(installedOutputConfiguration(t, ctx, after), want) || !reflect.DeepEqual(accepted, want) || !bytes.Equal(after.valueEntry(entrySlot(t, after, "plain")).ValueBytes, []byte("accepted sibling")) {
		t.Fatal("continuation adopted local values or lost exact accepted output")
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.ChangedSubjects.Count != 6 || receipt.OutputSummary != contract.ReceiptOutputNotApplicable {
		t.Fatal("generated receipt omitted output binding", err)
	}
	publicOutputApplyAssertNoPublication(t, after)
}

// full_only: false
func TestPublicGeneratedOutputDamageRefusesContinuationAndAllowsEnding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	implementation := process.Implementation
	meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: meta}}
	policy := contract.OutputPolicy{ContractID: "fixture-readers", Data: []byte(`{}`)}
	for i := 0; i < 250; i++ {
		policy.Data = append(policy.Data, []byte(fmt.Sprintf("%03d-", i)+strings.Repeat("s", 2044))...)
	}
	output := &outputApplyInput{}
	for _, name := range []string{"a", "b"} {
		target := outputConfigurationTarget("generated", "later-fragment-"+name)
		target.target.Policy = policy
		output.bindings = append(output.bindings, outputApplyBinding{destinationID: name, targets: []outputApplyTarget{target}})
	}
	installOutputFixtureSource(t, f.selected, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	engine := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
	stopped := engine.Apply(ctx, fixtureID(f.env.Domain, "later output fragment stop"), input)
	engine.Close()
	cold := f.open(t, ctx)
	work, err := cold.selectedGeneratedWork(ctx)
	if err != nil || work.parent == nil {
		t.Fatal("pending output fixture unavailable", err, stopped.Result)
	}
	location, present := work.content.locations[generatedContentKey{kind: contract.GeneratorContentOutputConfiguration, id: stopped.OperationID}]
	if !present || location.Length <= contract.GeneratedFragmentMaxPayload {
		t.Fatal("fixture does not reach a later output fragment")
	}
	var later format.FragmentLocation
	found := false
	for _, fragment := range cold.root.Generated.Fragments {
		if fragment.BlobID == location.BlobID && fragment.FragmentIndex == 1 {
			later, found = fragment, true
			break
		}
	}
	if !found {
		t.Fatal("actual second output fragment is not selected")
	}
	f.selected = cold
	resumed := publicGeneratedOutputEngine(t, ctx, f, input, &outputApplyInput{}, installedGeneratedTestCallbacks(t, f, process))
	store := requireAdmittedMemoryStore(t, f.env.Store)
	ref := cold.root.RequiredSupport[later.SupportPageIndex]
	key, err := format.Key(store.desc.Prefix, ref)
	if err != nil {
		t.Fatal(err)
	}
	object := store.objects[key]
	object.Body = bytes.Clone(object.Body)
	object.Body[len(object.Body)-1] ^= 1
	store.objects[key] = object
	beforeHead := bytes.Clone(store.objects[store.desc.HeadKey].Body)
	cas, creates := store.cas, store.creates
	signs := f.env.Trust.(*fixtureTrust).signs
	beforeCreates, beforeDeletes := effects()
	result := resumed.Continue(ctx, fixtureID(f.env.Domain, "damaged later output fragment continuation"), stopped.OperationID)
	resumed.Close()
	afterCreates, afterDeletes := effects()
	if result.Result.Outcome != IntegrityFailure || result.Result.CommitMayHaveOccurred || len(result.Receipt) != 0 || store.cas != cas || store.creates != creates || f.env.Trust.(*fixtureTrust).signs != signs || beforeCreates != 1 || beforeDeletes != 0 || afterCreates != beforeCreates || afterDeletes != beforeDeletes || !bytes.Equal(beforeHead, store.objects[store.desc.HeadKey].Body) {
		t.Fatal("damaged later output fragment crossed authentication or repeated effects", result.Result)
	}
	admin, observed := openAdministrative(ctx, OpenContext{admission: &cold.admission}, store)
	if admin == nil || observed.Outcome != ObservedCurrent {
		t.Fatal("optional desired image blocked administrative observation", observed)
	}
	candidate, prepared := prepareTestEndSelectedWork(t, admin, ctx, stopped.OperationID, f.env.Trust)
	if candidate == nil || prepared.Outcome != ObservedCurrent {
		t.Fatal("exact ending required damaged pending output bytes", prepared)
	}
	ended, selected := admin.selectCandidate(ctx, candidate)
	if ended == nil || selected.Outcome != ObservedCurrent {
		t.Fatal("exact pending owner ending failed", selected)
	}
	closed := generatedLifecycleReopen(t, ctx, ended, f.env.Store)
	remaining, err := closed.selectedGeneratedWork(ctx)
	if err != nil || remaining.parent != nil || !closed.root.Generated.ActiveOwner.IsZero() || closed.root.ValueEntryCount != 0 || len(installedOutputConfiguration(t, ctx, closed).Bindings) != 0 || closed.root.WarningBits&cold.root.WarningBits != cold.root.WarningBits {
		t.Fatal("ending selected pending outputs or lost preserved facts", err)
	}
	if _, present := remaining.content.locations[generatedContentKey{kind: contract.GeneratorContentOutputConfiguration, id: stopped.OperationID}]; present {
		t.Fatal("ended owner retained unclaimed desired output content")
	}
	afterCreates, afterDeletes = effects()
	if afterCreates != beforeCreates || afterDeletes != beforeDeletes {
		t.Fatal("administrative ending repeated provider effects")
	}
}

// full_only: false
func TestPublicOutputRemovalRetainsUnknownTargetAndReadditionUsesFreshBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, prior, coordinate, marker := signedPublicationSelectionFixture(t, format.OutputReserveAuth, false)
	selected := prior.session
	f := installedApplyTestFixture{env: env, keys: env.Custody, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
	name := selected.root.Names[0].Name
	target := outputConfigurationTarget(name, coordinate.CanonicalTarget)
	target.target.ServiceContractID = coordinate.ServiceContractID
	target.target.ConsumerLocator, target.target.TargetContractID = coordinate.DeletionConsumerLocator, coordinate.DeletionTargetContractID
	target.target.TargetData, target.target.PayloadEncoding = bytes.Clone(coordinate.DeletionTargetData), coordinate.DeletionPayloadEncoding
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target}}}}
	f = installedOutputSelect(t, ctx, f, output)
	selected = f.selected
	beforeConfiguration := installedOutputConfiguration(t, ctx, selected)
	before, err := selectedPublicationRelation(selected.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	if _, present := before.markers[marker.AttemptID]; !present {
		t.Fatal("fixture lost its exact unknown Attempt")
	}
	oldCoordinate := before.coordinates[coordinate.CoordinateID]
	input := installedApplyCurrentInput(selected)
	engine := f.engineWithValidator(t, selected, input, currentApplyRecipients(selected.registry()), installedOutputValidator(t, selected), nil)
	publicOutputApplyProposal(&engine.installation.PublicConfiguration, &outputApplyInput{})
	removed := engine.Apply(ctx, fixtureID(env.Domain, "public remove unknown output"), input)
	engine.Close()
	if removed.Result.Outcome != ObservedCurrent || removed.Payload == nil || removed.Payload.ChangedSubjects.Count != 1 {
		t.Fatal("binding removal was refused or lost its receipt subject", removed.Result)
	}
	cold := f.open(t, ctx)
	retired, err := selectedPublicationRelation(cold.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	wantRetired := oldCoordinate
	wantRetired.BindingState, wantRetired.ActiveBindingIncarnationID = contract.PublicationBindingRetired, contract.ID{}
	if len(installedOutputConfiguration(t, ctx, cold).Bindings) != 0 || !reflect.DeepEqual(retired.coordinates[coordinate.CoordinateID], wantRetired) || !reflect.DeepEqual(retired.markers, before.markers) || removed.WarningBits != selected.root.WarningBits {
		t.Fatal("removal changed exact target, birth, blockers or warnings")
	}
	f.selected = cold
	input = installedApplyCurrentInput(cold)
	readd := f.engineWithValidator(t, cold, input, currentApplyRecipients(cold.registry()), installedOutputValidator(t, cold), nil)
	publicOutputApplyProposal(&readd.installation.PublicConfiguration, output)
	added := readd.Apply(ctx, fixtureID(env.Domain, "public readd unknown output"), input)
	readd.Close()
	if added.Result.Outcome != ObservedCurrent || added.Payload == nil || added.Payload.ChangedSubjects.Count != 1 {
		t.Fatal("binding re-addition lost complete admission", added.Result)
	}
	after := f.open(t, ctx)
	configuration := installedOutputConfiguration(t, ctx, after)
	if len(configuration.Bindings) != 1 || configuration.Bindings[0].IncarnationID == beforeConfiguration.Bindings[0].IncarnationID || configuration.Bindings[0].IncarnationID != publicOutputApplyExpectedBinding(env.Domain, added.OperationID, "app") {
		t.Fatal("re-addition reused an old binding incarnation")
	}
	relation, err := selectedPublicationRelation(after.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	wantActive := oldCoordinate
	wantActive.BindingState, wantActive.ActiveBindingIncarnationID = contract.PublicationBindingActive, configuration.Bindings[0].IncarnationID
	if !reflect.DeepEqual(relation.coordinates[coordinate.CoordinateID], wantActive) || !reflect.DeepEqual(relation.markers, before.markers) || added.WarningBits != selected.root.WarningBits {
		t.Fatal("fresh binding cleared old target, birth, blockers or warnings")
	}
}

// full_only: false
func TestPublicGeneratedRetirementRiskFromApplyUsesFreshResidueIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := installedGeneratedRetirementProcess(t, "unknown")
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}
	input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: meta}}
	initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
	first := initial.Apply(ctx, testID("public residue initial apply"), input)
	initial.Close()
	if first.Result.Outcome != ObservedCurrent {
		t.Fatal("initial public generation failed", first.Result)
	}
	before := f.open(t, ctx)
	_, original := observeCurrentValueEntry(t, before, "generated")
	meta.Epoch, meta.RetirementMode = 1, contract.GeneratedRetirementAuto
	rotation := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), installedGeneratedRetirementCallbacks(t, f, process))
	parked := rotation.Apply(ctx, testID("public residue automatic rotation"), input)
	rotation.Close()
	if parked.Result.Outcome != ObservedCurrent || parked.Generated == nil || parked.Generated.StateResult != "retirement-pending" {
		t.Fatal("automatic retirement ambiguity did not park", parked.Result)
	}
	cold := f.open(t, ctx)
	_, current := observeCurrentValueEntry(t, cold, "generated")
	work := mustSelectedGeneratedWork(t, cold)
	var attempt contract.ID
	for id, row := range work.attempts {
		if row.record.OperationID == parked.OperationID && row.expected.Template.Action == contract.GeneratorActionDelete {
			attempt = id
		}
	}
	graph, err := work.retainedGraph(parked.OperationID)
	if err != nil || graph.Request.Schema != contract.GeneratorApplyRequestCoreSchema || graph.Request.OutputConfiguration.ConfigurationDigest.IsZero() || attempt.IsZero() || current.Generated.RetiringDutyPresent != 1 {
		t.Fatal("retained ambiguity is not from a complete public apply", err)
	}
	graphBefore := graph
	creates, deletes := effects()
	if creates != 2 || len(deletes) != 1 || original.Generated.ResourceDigest != hermeticCloudflareResourceDigest(deletes[0]) {
		t.Fatal("fixture changed its exact retired target", creates, deletes)
	}
	f.keys.SetDenied(cold.admission.recipient, true)
	public, private := f.keys.Calls()
	acceptor := installedGeneratedRetirementEngine(t, ctx, f, cold, nil)
	accepted := acceptor.AcceptGeneratedRetirementRisk(ctx, testID("public apply exact retirement risk"), GeneratedRetirementRiskRequest{DutyID: current.Generated.RetiringDutyID, AttemptID: attempt})
	acceptor.Close()
	if accepted.Result.Outcome != ObservedCurrent || accepted.Generated == nil || accepted.Generated.StateResult != "possible-live-residue-accepted" || accepted.Generated.EffectSummary != contract.ReceiptEffectNotApplicable || len(accepted.Generated.Effects) != 0 || len(accepted.Generated.RelatedHazardIDs) != 1 || !accepted.Generated.Warnings.PossibleLiveResidue || len(accepted.Receipt) == 0 {
		t.Fatal("public apply retirement ambiguity could not create its separate residue identity", accepted.Result)
	}
	after := f.open(t, ctx)
	retained := mustSelectedGeneratedWork(t, after)
	actualGraph, err := retained.retainedGraph(parked.OperationID)
	if err != nil || !reflect.DeepEqual(actualGraph, graphBefore) {
		t.Fatal("risk acceptance changed the original apply graph or output declaration", err)
	}
	expectedCurrent := current
	expectedCurrent.Generated.RetiringDutyPresent, expectedCurrent.Generated.RetiringDutyID = 0, contract.ID{}
	_, actualCurrent := observeCurrentValueEntry(t, after, "generated")
	if !reflect.DeepEqual(actualCurrent, expectedCurrent) || after.root.Generated.Retiring != 0 || after.root.Generated.Hazards != 1 {
		t.Fatal("risk acceptance changed canonical generation or lost the retained hazard")
	}
	receipt, err := contract.InspectCompactMutationReceipt(accepted.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationAcceptGeneratedRetirementResidue || receipt.OperationID != accepted.OperationID || receipt.EffectSummary != contract.ReceiptEffectNotApplicable || receipt.OutputSummary != contract.ReceiptOutputNotApplicable || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 1 {
		t.Fatal("residue receipt changed its operation or evidence axes", err)
	}
	raw, observed := after.MutationReceipt(ctx, accepted.OperationID)
	if observed.Outcome != ObservedCurrent || !bytes.Equal(raw, accepted.Receipt) {
		t.Fatal("cold receipt lost exact risk evidence", observed)
	}
	if p, q := f.keys.Calls(); p != public || q != private {
		t.Fatal("effect-free risk acceptance used private KMS")
	}
	if c, d := effects(); c != creates || !reflect.DeepEqual(d, deletes) {
		t.Fatal("risk acceptance repeated a provider request", c, d)
	}
}

// full_only: false
func TestPublicGeneratedRetainedV3AutomaticSelectionPreservesCurrentOutputs(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	implementation := process.Implementation
	input := []ApplyEntryInput{
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent), ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), LifecycleMode: contract.GeneratorLifecycleManaged}},
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("retained v3 sibling")},
	}
	target := outputConfigurationTarget("generated", "retained-v3-generated")
	target.target.PayloadEncoding = contract.OutputEncodingBase64
	input[0].OutputEncoding = contract.OutputEncodingBase64
	output := &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{target, outputConfigurationTarget("plain", "retained-v3-plain")}}}, groups: [][]string{{"generated", "plain"}}}
	installOutputFixtureSource(t, f.selected, output)
	f.admitted = OpenContext{admission: &f.selected.admission}
	callbacks := installedGeneratedRetirementCallbacks(t, f, process)
	initial := publicGeneratedOutputEngine(t, ctx, f, input, output, callbacks)
	first := initial.Apply(ctx, fixtureID(f.env.Domain, "retained v3 initial"), input)
	initial.Close()
	if !applyPublicationComplete(first) {
		t.Fatal("initial complete output selection failed", first.Result)
	}
	f.selected = f.open(t, ctx)
	before := ownScenarioValueEntry(*f.selected.valueEntry(entrySlot(t, f.selected, "generated")))
	beforeOutput := installedOutputConfiguration(t, ctx, f.selected)
	if len(beforeOutput.Bindings) != 1 || len(beforeOutput.Groups) != 1 || len(beforeOutput.Routes) == 0 {
		t.Fatal("fixture lacks complete nonempty selected output intent")
	}
	input[0].Generated.Epoch, input[0].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
	engine := publicGeneratedOutputEngine(t, ctx, f, input, &outputApplyInput{}, callbacks)
	defer engine.Close()
	i := engine.installation
	plan, err := f.selected.installedGeneratedPlan(ctx, i, input, nil, deadline)
	if err != nil {
		t.Fatal("rotation construction", err)
	}
	// Construct accepted historical meaning before admission. Fresh public apply
	// still emits v4; this fixture gives v3 no desired output descriptor or image.
	historical := plan.input
	historical.graph.Request.Schema = contract.GeneratorPublicRequestCoreSchema
	historical.graph.Request.OutputConfiguration = contract.OutputConfigurationDescriptor{}
	historical.outputConfiguration = nil
	historical.graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(historical.graph.Request)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(historical.graph.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal("historical public v3 complete join", err)
	}
	historical.graph.Edges = slices.Clone(historical.graph.Edges)
	for at := range historical.graph.Edges {
		if historical.graph.Edges[at].Guard >= contract.GeneratorGuardQualifiedSuccess {
			historical.graph.Edges[at].DestinationTemplateID = join
		}
	}
	historical.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(historical.graph.Header, historical.graph.ValueEntryPlans, historical.graph.Lineages, historical.graph.Edges)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contract.EncodeGeneratorPlanBundle(historical.graph); err != nil {
		t.Fatal("complete historical public v3 graph", err)
	}
	plan, err = f.selected.generatedPlanRequest(ctx, historical)
	if err != nil {
		t.Fatal("historical public v3 plan admission", err)
	}
	operation := plan.input.graph.Request.OperationID
	session, proposal, err := f.selected.installedGeneratedSession(ctx, plan.input.graph, plan.input.declaration, plan.input.registryImage, nil)
	if err != nil {
		t.Fatal("historical public v3 installed session", err)
	}
	owner, err := i.Generated.AdmitReservation(ctx, plan.request, currentControlOf(f.selected), contract.GeneratedReservationInput{Session: session, Plan: proposal, Phase: plan.phase}, deadline)
	if err != nil || !validInstalledGeneratedCustody(owner) {
		t.Fatal("historical public v3 reservation custody", err)
	}
	t.Cleanup(owner.Close)
	prior, result := f.selected.PrepareGeneratedPlan(ctx, &admittedGeneratedPlan{session: f.selected, plan: plan, crypto: owner.Crypto, instance: owner.Crypto.InstanceID(), deadline: deadline})
	if prior == nil || len(prior.reservation.originalAttempts) != 1 {
		t.Fatal("historical public v3 reservation preparation", result)
	}
	candidateInput, err := f.selected.installedGeneratedCandidate(ctx, prior.reservation, nil)
	if err != nil || owner.BindCandidate(ctx, candidateInput) != contract.CryptoSuccess {
		t.Fatal("historical public v3 reservation candidate", err)
	}
	if candidate, result := f.selected.ClaimGeneratedPreparation(ctx, prior.reservation.candidate, i.Trust); candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("historical public v3 reservation claim", result)
	}
	owner.Close()
	producer, producerOwner, result := f.selected.installedGeneratedPrepareProducer(ctx, i, prior, prior.reservation.originalAttempts[0], true, deadline)
	if producerOwner != nil {
		t.Cleanup(producerOwner.Close)
	}
	if producer == nil || producerOwner == nil {
		t.Fatal("historical public v3 original producer", result)
	}
	candidate, result := f.selected.ClaimGeneratedOriginalSet(ctx, []*generatedPreparation{producer}, i.Trust)
	if candidate == nil {
		t.Fatal("historical public v3 original-set claim", result)
	}
	if !candidate.bindFirstSend(producer, func(callctx context.Context, authority contract.ID) contract.CryptoResultCode {
		returned := producerOwner.InvokeProducer(callctx, producer.producerLocator, authority)
		body, code := returned.Record, returned.Code
		if code == contract.CryptoSuccess && len(body) != 0 {
			if persisted := prior.reservation.state.persistGeneratedResult(callctx, generatedResultWrite{attempt: producer.attempt, body: body}); persisted.Outcome != 0 {
				return contract.CryptoCustodyUnavailable
			}
		}
		return code
	}) {
		t.Fatal("historical public v3 first-send binding")
	}
	if selected, result := f.selected.selectObserved(ctx, candidate); selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("historical public v3 original selection", result)
	}
	producerOwner.Close()
	f.selected = f.open(t, ctx)
	work := mustSelectedGeneratedWork(t, f.selected)
	graph, err := work.retainedGraph(operation)
	_, hasOutputImage := work.content.locations[generatedContentKey{contract.GeneratorContentOutputConfiguration, operation}]
	if err != nil || graph.Request.Schema != contract.GeneratorPublicRequestCoreSchema || graph.Request.OutputConfiguration != (contract.OutputConfigurationDescriptor{}) || hasOutputImage || work.parent == nil || work.parent.OperationID != operation {
		t.Fatal("fixture did not select exact accepted public v3 work", err, hasOutputImage)
	}
	var anchor contract.GeneratedPhaseRecord
	finalBinds, deleteAdmissions := 0, 0
	callbacks = installedGeneratedRetirementCallbacks(t, f, process)
	admitFinal := callbacks.AdmitFinal
	callbacks.AdmitFinal = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedFinalInput, until time.Time) (*InstalledGeneratedCustody, error) {
		owner, err := admitFinal(callctx, q, control, in, until)
		if err != nil || owner == nil {
			return owner, err
		}
		bind := owner.BindCandidate
		owner.BindCandidate = func(bindctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
			if candidate.Subject.Purpose == contract.GeneratorAuthorityFinal {
				finalBinds++
				var generation contract.ID
				for _, row := range candidate.Entries {
					if row.Entry.Name == "generated" {
						generation = row.Entry.Generated.GenerationID
					}
				}
				var subjects []contract.ChangedSubjectIdentity
				for _, change := range []struct {
					kind, change uint8
					primary      contract.ID
				}{
					{contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, before.Incarnation},
					{contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, before.Generated.GenerationID},
					{contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, generation},
				} {
					material := append([]byte("ENKV/CRYPTO/v2/changed-subject-identity-v1\x00"), f.env.Domain[:]...)
					material = append(material, change.kind)
					material = append(material, change.primary[:]...)
					material = append(material, make([]byte, 32)...)
					subjects = append(subjects, contract.ChangedSubjectIdentity{Kind: change.kind, Change: change.change, Identity: contract.ID(sha256.Sum256(material))})
				}
				expected, subjectErr := contract.ChangedSubjectDescriptor(subjects)
				if subjectErr != nil || generation.IsZero() {
					t.Fatal("independent public v3 changed subjects", subjectErr)
				}
				for _, row := range candidate.SupportRecords {
					if row.Kind == contract.GeneratedPhaseSupportKind && row.RecordID == operation {
						anchor, err = contract.InspectGeneratedPhaseRecord(row.Body)
						if err != nil || anchor.SelectionPhaseID.IsZero() || anchor.ChangedSubjects != expected {
							t.Fatal("public v3 first Final changed its independent selection anchor", err)
						}
					}
				}
			}
			code := bind(bindctx, candidate)
			if code != contract.CryptoSuccess {
				t.Fatal("public v3 exact installed candidate refused", candidate.Subject.Purpose, code)
			}
			return code
		}
		return owner, nil
	}
	admitProducer := callbacks.AdmitProducer
	callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, until time.Time) (*InstalledGeneratedProducerCustody, error) {
		if in.Expected.Template.Action == contract.GeneratorActionDelete {
			deleteAdmissions++
			if anchor.SelectionPhaseID.IsZero() || in.Session.SelectionPhase == nil || in.Session.SelectionPhase.SelectionPhaseID != anchor.SelectionPhaseID || in.Session.SelectionPhase.ChangedSubjects != anchor.ChangedSubjects || in.Session.SelectionPhase.ChangedAccess != anchor.ChangedAccess {
				t.Fatal("public v3 automatic DELETE lost its frozen selection commitment")
			}
			publicOutputApplyAssertConfiguration(t, in.Session.Output.Before, beforeOutput)
		}
		return admitProducer(callctx, q, control, in, implementation, until)
	}
	// The source now proposes removal. Continue must preserve v3's accepted
	// current-output meaning and must not apply this later local proposal.
	continued := publicGeneratedOutputEngine(t, ctx, f, input, &outputApplyInput{}, callbacks)
	resultOfContinue := continued.Continue(ctx, fixtureID(f.env.Domain, "retained v3 continuation"), operation)
	continued.Close()
	creates, deletes := effects()
	if finalBinds != 1 || deleteAdmissions != 1 || !applyPublicationComplete(resultOfContinue) || resultOfContinue.Generated == nil || resultOfContinue.Generated.StateResult != "success" || !resultOfContinue.Generated.HasObservedCanonicalSelection(resultOfContinue.DomainID, operation, resultOfContinue.RequestIdentity) || creates != 2 || len(deletes) != 1 || before.Generated.ResourceDigest != hermeticCloudflareResourceDigest(deletes[0]) {
		t.Fatal("public v3 continuation did not close its exact automatic work", resultOfContinue.Result, finalBinds, deleteAdmissions, creates, deletes)
	}
	cold := f.open(t, ctx)
	publicOutputApplyAssertConfiguration(t, installedOutputConfiguration(t, ctx, cold), beforeOutput)
	after := cold.valueEntry(entrySlot(t, cold, "generated"))
	if after.Incarnation != before.Incarnation || after.Generated.GenerationID == before.Generated.GenerationID || after.Generated.RetiringDutyPresent != 0 || !cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.Retiring != 0 {
		t.Fatal("public v3 continuation lost its successor or retained completed retirement")
	}
	receipt, err := contract.InspectCompactMutationReceipt(resultOfContinue.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.OperationID != operation || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.StateResult != contract.ReceiptStateSuccess || receipt.ChangedSubjects != anchor.ChangedSubjects || receipt.SummaryCounts[contract.ReceiptChangedAccessCount] != anchor.ChangedAccess.Count || receipt.SummaryCounts[contract.ReceiptEffectCount] != 2 || receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 2 {
		t.Fatal("public v3 final receipt changed the frozen original facts", err)
	}
	publicOutputApplyAssertNoPublication(t, cold)
}
