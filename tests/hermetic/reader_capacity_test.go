package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
)

func readerCapacityValidator(t *testing.T, selected *StateSession) *PublicConfigurationValidator {
	t.Helper()
	return NewPublicConfigurationValidator(selected.admission.outputInterpreter)
}

// Desired intent bytes use independent schema 1 framing and JSON settings.
// Each complete intent is 393216 bytes; projection and Compare do not supply it.
func readerCapacityInput(t *testing.T, env fixtureEnvironment, selected *StateSession, configuration contract.OutputConfiguration) contract.PublicConfiguration {
	t.Helper()
	input := comparisonCurrentInput(t, env, selected)
	names := make(map[contract.ID]string, len(input.Entries.Value))
	for i := range input.Entries.Value {
		row := &input.Entries.Value[i]
		entry := selected.valueEntry(namedSlot(t, selected, row.Name))
		names[entry.Incarnation] = row.Name
		if entry.ValueSource == contract.Generated {
			g := entry.Generated
			intent := capacityIntentBytes(t, row.Name)
			row.Generated = &contract.PublicGeneratedSettings{Epoch: publicPresent(g.Epoch), ConfigContractID: publicPresent(g.ConfigContractID), ResourceContractID: publicPresent(g.ResourceContractID), LifecycleMode: publicPresent(g.LifecycleMode), ContentIntent: publicPresent(intent), Retirement: publicPresent(g.RetirementMode), Completion: publicPresent(g.CompletionClass)}
		}
	}
	input.OutputBindings.Value = make([]contract.PublicOutputBinding, len(configuration.Bindings))
	for i, b := range configuration.Bindings {
		binding := &input.OutputBindings.Value[i]
		binding.DestinationID = b.DestinationID
		binding.Destination = publicPresent(b.Destination)
		binding.Targets = publicPresent(make([]contract.PublicOutputTarget, len(b.Targets)))
		for j, target := range b.Targets {
			binding.Targets.Value[j] = hermeticPublicOutputTarget(names[target.EntryIncarnationID], target)
		}
	}
	input.Groups = publicPresent(make([][]string, len(configuration.Groups)))
	for i, group := range configuration.Groups {
		for _, id := range group {
			input.Groups.Value[i] = append(input.Groups.Value[i], names[id])
		}
	}
	input.Routing.Value = make([]contract.PublicRoutingRule, 0, len(configuration.Routes)+1)
	for _, route := range configuration.Routes {
		key := contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: names[route.EntryIncarnationID]}
		input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: key, Destinations: publicPresent(route.Destinations)})
	}
	input.Routing.Value = append(input.Routing.Value, contract.PublicRoutingRule{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: publicPresent(configuration.DefaultDestinations)})
	return input
}

func readerCapacityNoEffects(t *testing.T, env fixtureEnvironment) func() {
	t.Helper()
	store := env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	public, private := env.Custody.Calls()
	signers := []*testtrust.Signer{env.Trust.(*fixtureTrust).Signer}
	if env.Recovery != nil {
		signers = append(signers, env.Recovery.(*testtrust.Signer))
	}
	calls := make([][2]int, len(signers))
	for i, signer := range signers {
		calls[i] = [2]int{signer.Calls(), signer.QualificationCalls()}
	}
	return func() {
		t.Helper()
		if p, q := env.Custody.Calls(); p != public || q != private || store.creates != creates || store.cas != cas {
			t.Fatal("Reader used custody or changed Store", p-public, q-private, store.creates-creates, store.cas-cas)
		}
		for i, signer := range signers {
			if [2]int{signer.Calls(), signer.QualificationCalls()} != calls[i] {
				t.Fatal("Reader signed or fetched a public key")
			}
		}
	}
}

func readerCapacityScope(t *testing.T, got []contract.ComparisonScope, status contract.ComparisonScopeStatus) {
	t.Helper()
	families := []contract.ComparisonFieldFamily{contract.ScopeEntries, contract.ScopePlainValues, contract.ScopeSecretSettings, contract.ScopeMemberships, contract.ScopeRecipients, contract.ScopeEncryption, contract.ScopeGenerated, contract.ScopeOutputs, contract.ScopeRouting, contract.ScopeDomainStore, contract.ScopeAuthorityRecovery, contract.ScopeCompatibilityProfiles}
	want := make([]contract.ComparisonScope, len(families))
	for i, family := range families {
		want[i] = contract.ComparisonScope{Family: family, Status: status}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("wrong complete scope vector", got, want)
	}
}

func readerCapacityComparison(t *testing.T, got PublicComparisonResult, selected *StateSession, request contract.ID, diagnostics []contract.Diagnostic) {
	t.Helper()
	want := contract.ComparisonMatch
	if len(diagnostics) != 0 {
		want = contract.ComparisonMismatch
	}
	observation := contract.ComparisonObservation{DomainID: selected.root.Domain, HeadRevisionID: selected.head.Core.Revision, SnapshotID: selected.root.Snapshot}
	if got.StateResult != contract.ReaderSuccess || got.Verdict != want || !got.DiagnosticsComplete || !publicComparisonFactsMatch(t, got.ComparisonPayload, diagnostics) || got.Observation == nil || *got.Observation != observation || got.Result.Evidence != AuthenticatedClosure || got.Result.ObservedRevision != observation.HeadRevisionID || got.Result.ObservedSnapshotID != observation.SnapshotID || got.EvidenceLimit != contract.ComparisonEvidenceLimit || got.Context.RequestID != request || got.Context.Operation != contract.ReaderCompareOperation || got.Context.OperationID.IsZero() {
		t.Fatalf("wrong authenticated comparison state=%s verdict=%s complete=%t diagnostics=%d want=%d observation=%t evidence=%v", got.StateResult, got.Verdict, got.DiagnosticsComplete, len(got.Diagnostics), len(diagnostics), got.Observation != nil, got.Result.Evidence)
	}
	readerCapacityScope(t, got.CheckedScope, contract.ScopeComplete)
}

// full_only: true
// Covers jointly admitted stored maxima and retained history, with one seed.
func TestReaderJointMaximumAuthenticatedOperations(t *testing.T) {
	env, f, _ := configuredSuccessionMemoryFixture(t, true)
	selected := f.session
	configuration := capacityOutputConfiguration(t, selected, true)
	input := readerCapacityInput(t, env, selected, configuration)
	defer readerCapacityNoEffects(t, env)()
	entries, generated, memberships, recipients, raw, intents, targets, routes := 0, 0, 0, 0, uint64(0), 0, 0, 0
	for _, named := range selected.root.Names {
		entry := selected.valueEntry(named.Slot)
		entries++
		memberships += len(entry.Recipients)
		payload, err := contract.InspectCanonicalPayload(entry.ValueBytes)
		if err != nil || entry.ConfidentialityClass != contract.Secret {
			t.Fatal("maximum selected secret", err)
		}
		raw += uint64(payload.ContentLength)
		if entry.ValueSource == contract.Generated {
			generated++
		}
	}
	for _, row := range input.Entries.Value {
		if row.Generated != nil {
			intents += len(row.Generated.ContentIntent.Value)
		}
	}
	for _, row := range input.Recipients.Value {
		recipients++
		if len(row.DisplayName.Value) != 256 || len(row.Encryption.Selector.Value) != contract.MaxKeySelector {
			t.Fatal("maximum metadata row not present")
		}
	}
	encodedTargets, sourceSettings, groupMembers := 0, 0, 0
	for _, binding := range configuration.Bindings {
		targets += len(binding.Targets)
		for _, target := range binding.Targets {
			if target.PayloadEncoding == contract.OutputEncodingBase64 {
				encodedTargets++
			}
		}
		var settings map[string]string
		if err := json.Unmarshal(binding.Destination.CanonicalSettings, &settings); err != nil {
			t.Fatal(err)
		}
		sourceSettings += len(settings)
	}
	for _, group := range configuration.Groups {
		groupMembers += len(group)
	}
	for _, route := range configuration.Routes {
		routes += len(route.Destinations)
	}
	declaration, routing := capacityConfigurationLengths(t, configuration)
	if encodedTargets != 1024 || sourceSettings != 192 || len(configuration.Groups) != 512 || groupMembers != 512 || entries != 512 || generated != 128 || memberships != 4096 || recipients != 256 || raw != 8<<20 || intents != 48<<20 || targets != 1024 || len(configuration.Routes) != 512 || len(configuration.DefaultDestinations) != 8 || routes != 1024 || declaration != 32<<20 || declaration+4+routing != 33839305 || routing != 284869 || selected.root.Generated.SuccessWindow.Count != 256 || selected.root.Generated.FailureWindow.Count != 256 {
		t.Fatal("independent joint dimensions", encodedTargets, sourceSettings, groupMembers, entries, generated, memberships, recipients, raw, intents, targets, routes, declaration, routing)
	}
	successionReceiptSupportRef(t, selected, 512)
	t.Logf("Reader joint owners: entries=%d generated=%d memberships=%d recipients=%d raw=%d intents=%d output=%d targets=%d route-members=%d receipts=512 generated-windows=256+256", entries, generated, memberships, recipients, raw, intents, declaration+4+routing, targets, routes)

	t.Run("complete-comparison", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		e, candidate, source := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		request := contract.Hash([]byte("joint maximum comparison"))
		readerCapacityComparison(t, e.Compare(ctx, request, input), selected, request, nil)
		if source.closes != 1 || !slices.Equal(candidate.calls, []string{"HEAD", "root"}) || e.activeDone != nil {
			t.Fatal("maximum comparison did not settle its exact read invocation")
		}
	})
	t.Run("complete-differences", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		e, _, _ := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		desired := input
		desired.Recipients.Value = slices.Clone(input.Recipients.Value)
		for i := range desired.Recipients.Value {
			desired.Recipients.Value[i].DisplayName = publicPresent("different maximum metadata")
		}
		want := make([]contract.Diagnostic, len(desired.Recipients.Value))
		wantChanges := make([]contract.ComparisonChange, len(desired.Recipients.Value))
		for i, row := range desired.Recipients.Value {
			subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: row.RecipientID}
			want[i] = contract.Diagnostic{Subject: subject, Path: []contract.DiagnosticField{contract.FieldDisplayName}, Outcome: contract.DiagnosticDifference, Reason: contract.ReasonFieldDiffers}
			wantChanges[i] = contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{contract.FieldDisplayName}, Action: contract.ComparisonChanged,
				Before: contract.ComparisonSide{State: contract.ComparisonPresent, Value: contract.ComparisonText(input.Recipients.Value[i].DisplayName.Value)},
				After:  contract.ComparisonSide{State: contract.ComparisonPresent, Value: contract.ComparisonText(row.DisplayName.Value)}}
		}
		slices.SortFunc(want, func(a, b contract.Diagnostic) int {
			return bytes.Compare(a.Subject.RecipientID[:], b.Subject.RecipientID[:])
		})
		slices.SortFunc(wantChanges, comparePublicChanges)
		request := contract.Hash([]byte("joint maximum complete differences"))
		got := e.Compare(ctx, request, desired)
		readerCapacityComparison(t, got, selected, request, want)
		if !reflect.DeepEqual(got.Changes, wantChanges) {
			t.Fatalf("complete display-name changes differ: changes=%d want=%d", len(got.Changes), len(wantChanges))
		}
	})
	t.Run("owned-public-changes-after-release", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		e, _, source := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		desired := input
		desired.Entries.Value = slices.Clone(input.Entries.Value)
		desired.OutputBindings.Value = slices.Clone(input.OutputBindings.Value)
		want := make([]contract.ComparisonChange, 0, 1984)
		present := func(value contract.ComparisonValue) contract.ComparisonSide {
			return contract.ComparisonSide{State: contract.ComparisonPresent, Value: value}
		}
		changed := func(subject contract.DiagnosticSubject, field contract.DiagnosticField, before, after contract.ComparisonValue) {
			want = append(want, contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{field}, Action: contract.ComparisonChanged, Before: present(before), After: present(after)})
		}
		plain, generatedBytes, plainBytes := 0, 0, 0
		for at := range desired.Entries.Value {
			row := &desired.Entries.Value[at]
			subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: row.Name}
			if row.Generated != nil {
				g := *row.Generated
				before := row.Generated.ContentIntent.Value
				g.ContentIntent.Value = slices.Clone(before)
				// The independently framed settings end with JSON padding Zs.
				// Replacing one such byte keeps the complete canonical intent size.
				if before[len(before)-3] != 'Z' {
					t.Fatal("maximum intent padding differs")
				}
				g.ContentIntent.Value[len(before)-3] = 'Y'
				row.Generated = &g
				generatedBytes += len(before)
				want = append(want, contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{contract.FieldGenerated, contract.FieldContentIntent}, Action: contract.ComparisonChanged,
					Before: present(contract.ComparisonBytes(before)), After: present(contract.ComparisonBytes(g.ContentIntent.Value))})
				continue
			}
			if row.Class.Value != contract.Secret || row.Source.Value != contract.Supplied || row.InputEncoding.Value != contract.InputEncodingRaw {
				t.Fatal("maximum supplied conversion prerequisites differ")
			}
			row.Class = publicPresent(contract.Plain)
			size := 0
			if plain < 128 {
				size = 65536
			}
			body := bytes.Repeat([]byte{0x6d}, size)
			row.PlainValue = publicPresent(body)
			plain++
			plainBytes += len(body)
			changed(subject, contract.FieldClass, contract.ComparisonUint(contract.Secret), contract.ComparisonUint(contract.Plain))
			want = append(want, contract.ComparisonChange{Subject: subject, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Action: contract.ComparisonAdded, Before: contract.ComparisonSide{State: contract.ComparisonAbsent}, After: present(contract.ComparisonBytes(body))})
		}
		policyBytes := 0
		for at := range desired.OutputBindings.Value {
			binding := &desired.OutputBindings.Value[at]
			before := binding.Destination.Value
			policy := before.Policy
			policy.Data = slices.Clone(policy.Data)
			padding := bytes.IndexByte(policy.Data, 'x')
			if padding < 0 {
				t.Fatal("maximum policy padding differs")
			}
			policy.Data[padding] = 'y'
			binding.Destination.Value.Policy = policy
			policyBytes += len(policy.Data)
			changed(contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: binding.DestinationID}, contract.FieldDestination, contract.ComparisonDestination(before), contract.ComparisonDestination(binding.Destination.Value))
			binding.Targets.Value = slices.Clone(binding.Targets.Value)
			for index := range binding.Targets.Value {
				target := &binding.Targets.Value[index]
				old := target.ConsumerPolicy.Value
				target.ConsumerPolicy.Value = policy
				policyBytes += len(policy.Data)
				changed(contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: binding.DestinationID, Name: target.EntryName}, contract.FieldConsumerPolicy, contract.ComparisonPolicy(old), contract.ComparisonPolicy(policy))
			}
		}
		if plain != 384 || generatedBytes != 48<<20 || plainBytes != 8<<20 || len(want) != 1984 || policyBytes == 0 || policyBytes >= 32<<20 {
			t.Fatal("independent changed public dimensions differ", plain, generatedBytes, plainBytes, len(want), policyBytes)
		}
		// Reuse only descriptor slices: policies alias the already constructed
		// proposal bodies. The independent format account checks every target's
		// full policy against its destination before measuring the new image.
		proposedOutput := configuration
		proposedOutput.Bindings = slices.Clone(configuration.Bindings)
		for at := range proposedOutput.Bindings {
			binding := &proposedOutput.Bindings[at]
			proposed := desired.OutputBindings.Value[at]
			if binding.DestinationID != proposed.DestinationID {
				t.Fatal("output fixture binding order changed")
			}
			binding.Destination = proposed.Destination.Value
			binding.Targets = slices.Clone(binding.Targets)
			for index := range binding.Targets {
				binding.Targets[index].Policy = proposed.Targets.Value[index].ConsumerPolicy.Value
			}
		}
		beforeDeclaration, beforeRouting := capacityConfigurationLengths(t, configuration)
		afterDeclaration, afterRouting := capacityConfigurationLengths(t, proposedOutput)
		if beforeDeclaration != 33554432 || afterDeclaration != 33554432 || beforeRouting != 284869 || afterRouting != 284869 || afterDeclaration+4+afterRouting != 33839305 {
			t.Fatal("changed policy image does not preserve exact complete output dimensions", beforeDeclaration, afterDeclaration, beforeRouting, afterRouting)
		}
		slices.SortFunc(want, comparePublicChanges)
		request := contract.Hash([]byte("joint maximum owned public changes"))
		got := e.Compare(ctx, request, desired)
		observation := contract.ComparisonObservation{DomainID: selected.root.Domain, HeadRevisionID: selected.head.Core.Revision, SnapshotID: selected.root.Snapshot}
		if got.StateResult != contract.ReaderSuccess || got.Verdict != contract.ComparisonMismatch || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || !reflect.DeepEqual(got.Changes, want) || got.Observation == nil || *got.Observation != observation || got.Result.Evidence != AuthenticatedClosure || source.closes != 1 || e.activeDone != nil {
			t.Fatalf("maximum owned public changes lost authenticated facts: state=%s verdict=%s changes=%d diagnostics=%d closed=%d", got.StateResult, got.Verdict, len(got.Changes), len(got.Diagnostics), source.closes)
		}
		readerCapacityScope(t, got.CheckedScope, contract.ScopeComplete)
		backing := readerCapacityOwnedBacking(t, reflect.ValueOf(got.Changes)) + readerCapacityOwnedBacking(t, reflect.ValueOf(got.BeforeRecipients)) + readerCapacityOwnedBacking(t, reflect.ValueOf(got.AfterRecipients))
		const valueAccount = 2 * (contract.MaxPublicConfigurationBytes + contract.MaxPublicTypedConfigurationBytes)
		const rowAccount = contract.MaxPublicDiagnostics * 200
		if backing <= uint64(2*generatedBytes+2*policyBytes+plainBytes) || backing > uint64(valueAccount+rowAccount+contract.MaxPublicSourceLocationBytes) {
			t.Fatal("owned changed-interface backing outside its independent account", backing)
		}
		// This digest is only the ownership check after exact semantic equality.
		// The encoder retains at most one bounded field record, not the vector.
		factDigest := func() [32]byte {
			h := sha256.New()
			encoder := json.NewEncoder(h)
			for _, change := range got.Changes {
				if err := encoder.Encode(change); err != nil {
					t.Fatal("owned record cannot be encoded", err)
				}
			}
			var digest [32]byte
			copy(digest[:], h.Sum(nil))
			return digest
		}
		digest := factDigest()
		for _, entry := range desired.Entries.Value {
			if entry.Generated != nil {
				clear(entry.Generated.ContentIntent.Value)
			} else {
				clear(entry.PlainValue.Value)
			}
		}
		for _, binding := range desired.OutputBindings.Value {
			clear(binding.Destination.Value.Policy.Data)
		}
		desired, proposedOutput, want, e = contract.PublicConfiguration{}, contract.OutputConfiguration{}, nil, nil
		runtime.GC()
		if factDigest() != digest || readerCapacityOwnedBacking(t, reflect.ValueOf(got.Changes))+readerCapacityOwnedBacking(t, reflect.ValueOf(got.BeforeRecipients))+readerCapacityOwnedBacking(t, reflect.ValueOf(got.AfterRecipients)) != backing {
			t.Fatal("completed comparison borrows cleared caller or closed invocation owners")
		}
		t.Logf("authenticated changes=%d; intents per side=%d; changed opaque policy bytes per side=%d; proposed plain bytes=%d; counted result backing=%d; declarations before=%d after=%d; selected Store remains the fixture owner; this selected source has no plain before-side and does not saturate V or J", len(got.Changes), generatedBytes, policyBytes, plainBytes, backing, beforeDeclaration, afterDeclaration)
	})
	t.Run("core-owned-overlap", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		e, _, _ := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		owned := e.validator.Validate(ctx, input)
		inv := readerInvocationFixture(t, e, ctx)
		observed, failure := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
		if failure.Outcome != 0 || !owned.Valid || !owned.Complete {
			t.Fatalf("maximum ownership admission failure=%+v valid=%t complete=%t diagnostics=%d", failure, owned.Valid, owned.Complete, len(owned.Diagnostics))
		}
		actual, failure := e.projectPublicConfiguration(ctx, observed)
		if failure.Outcome != 0 || !actual.Valid || !actual.Complete {
			t.Fatal("maximum projection backing", failure, actual.Valid, actual.Complete)
		}
		generatedRows := 0
		for _, entry := range actual.Configuration.Entries.Value {
			if entry.Generated != nil {
				generatedRows++
			}
		}
		if generatedRows != 128 {
			t.Fatal("maximum generated declarations incomplete", generatedRows)
		}

		// This counts Core-created exact-capacity collections and string content.
		// Repeated string occurrences are conservatively charged separately.
		// It makes no claim about hidden preexisting caller allocation extents,
		// runtime maps, object headers, allocator rounding, heap or RSS.
		backing := readerCapacityOwnedBacking(t, reflect.ValueOf(owned.Configuration)) + readerCapacityOwnedBacking(t, reflect.ValueOf(actual.Configuration))
		const projectionAccounts = uint64(2 * (contract.MaxPublicConfigurationBytes + contract.MaxPublicTypedConfigurationBytes + contract.MaxPublicSourceLocationBytes))
		if backing > projectionAccounts {
			t.Fatal("counted projection owners exceed two admitted accounts", backing)
		}
		for _, entry := range actual.Configuration.Entries.Value {
			if entry.Generated != nil {
				assertCapacityIntentBytes(t, entry.Name, entry.Generated.ContentIntent.Value)
				for _, original := range input.Entries.Value {
					if original.Name != entry.Name {
						continue
					}
					for _, desired := range owned.Configuration.Entries.Value {
						if desired.Name != entry.Name {
							continue
						}
						a, b, c := original.Generated.ContentIntent.Value, desired.Generated.ContentIntent.Value, entry.Generated.ContentIntent.Value
						if cap(a) != len(a) || &a[0] == &b[0] || &b[0] == &c[0] || &a[0] == &c[0] {
							t.Fatal("original/desired/observed intent owners overlap", entry.Name)
						}
					}
				}
			}
		}
		// Reuse the existing address-range union for actual selected byte owners.
		// This temporary view adds no copy and supplies no operational admission.
		view := &StateSession{root: observed.image.root, pages: observed.image.pages, recipients: observed.image.recipients, support: observed.image.support, access: observed.image.access, cache: observed.image.cache, head: observed.basis.anchor.head, body: observed.basis.anchor.headBody}
		buffers := retainedByteBuffers(view, nil, nil, nil)
		buffers.add(observed.basis.anchor.rootBody)
		buffers.add(observed.basis.anchor.configBody)
		buffers.addControlCore(inv.admission.basis.control)
		buffers.addBasis(inv.admission.basis.current)
		selectedBytes := buffers.capacity()
		const selectedByteAccount = uint64(512<<20 + 64<<10)
		if selectedBytes == 0 || selectedBytes > selectedByteAccount {
			t.Fatal("selected known byte-owner account", selectedBytes)
		}
		// Every original intent allocation was constructed above as one exact
		// bytes.Repeat owner. Other caller views are not claimed as full owners.
		knownOriginalIntents := uint64(intents)
		// These are the counted owners in this test, not the full Reader or
		// native process account. Each projection and the selected-byte union
		// keep their independent ceilings above.
		const countedAccounts = projectionAccounts + selectedByteAccount + 48<<20
		if countedAccounts != 1082702096 || backing+selectedBytes+knownOriginalIntents > countedAccounts {
			t.Fatal("simultaneous counted owners exceed their accounts", backing, selectedBytes, knownOriginalIntents)
		}
		t.Logf("simultaneous Core projections backing/content upper bound=%d; selected byte-owner union=%d; known original intent owners=%d; selected encoded children=%d", backing, selectedBytes, knownOriginalIntents, observed.image.root.ChildEncodedBytes)
		runtime.KeepAlive(owned)
		runtime.KeepAlive(actual)
		runtime.KeepAlive(observed)
		runtime.KeepAlive(view)
		inv.Close()
		if inv.selection.complete || inv.admission.issued || inv.source != nil || !reflect.DeepEqual(inv.admission.basis, readerPublicBasis{}) || e.activeDone != nil {
			t.Fatal("maximum invocation retained selection or public basis after Close")
		}
	})
	t.Run("complete-all-entry-partition", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		e, _, source := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		names := make([]string, len(selected.root.Names))
		for i, named := range selected.root.Names {
			names[i] = named.Name
		}
		got := e.Manifest(ctx, contract.ID{7}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: selected.admission.recipient, EntryNames: names}))
		if got.StateResult != contract.ReaderSuccess || got.Payload == nil || got.Observation == nil || len(got.Payload.IncludedEntries) != 128 || len(got.Payload.ExcludedEntries) != 384 || source.closes != 1 || e.activeDone != nil {
			t.Fatal("maximum complete partition", got.StateResult, got.FailureReason)
		}
		for _, row := range got.Payload.IncludedEntries {
			entry := selected.valueEntry(namedSlot(t, selected, row.Name))
			if entry.ValueSource != contract.Generated || row.EntryIncarnationID != manifestsdk.ID(entry.Incarnation) {
				t.Fatal("maximum routed included identity", row.Name)
			}
		}
		for _, row := range got.Payload.ExcludedEntries {
			entry := selected.valueEntry(namedSlot(t, selected, row.Name))
			if entry.ValueSource == contract.Generated || row.EntryIncarnationID != manifestsdk.ID(entry.Incarnation) || row.Reason != manifestsdk.NoOutput {
				t.Fatal("maximum unrouted exclusion identity", row.Name)
			}
		}
	})
	readerCapacityLateComparison(t, env, selected, input)
	readerCapacityManifestCases(t, env, selected, configuration, true)
}

func readerCapacityOwnedBacking(t *testing.T, value reflect.Value) uint64 {
	t.Helper()
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return 0
		}
		return uint64(value.Elem().Type().Size()) + readerCapacityOwnedBacking(t, value.Elem())
	case reflect.String:
		return uint64(value.Len())
	case reflect.Pointer:
		if value.IsNil() {
			return 0
		}
		return uint64(value.Type().Elem().Size()) + readerCapacityOwnedBacking(t, value.Elem())
	case reflect.Slice:
		if value.Len() != value.Cap() {
			t.Fatal("Core collection has excess capacity", value.Type(), value.Len(), value.Cap())
		}
		total := uint64(value.Cap()) * uint64(value.Type().Elem().Size())
		for i := 0; i < value.Len(); i++ {
			total += readerCapacityOwnedBacking(t, value.Index(i))
		}
		return total
	case reflect.Struct:
		var total uint64
		for i := 0; i < value.NumField(); i++ {
			total += readerCapacityOwnedBacking(t, value.Field(i))
		}
		return total
	}
	return 0
}

func readerCapacityLateComparison(t *testing.T, env fixtureEnvironment, selected *StateSession, input contract.PublicConfiguration) {
	t.Helper()
	refs := capacityConfigurationSupportRefs(t, selected)
	key := readerFixtureKey(t, env.Store.Descriptor().Prefix, refs[len(refs)-1])
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	e, _, source := readerEngineFixture(t, env, selected)
	e.validator = readerCapacityValidator(t, selected)
	baseline := &comparisonReadGate{PublicSelectedReader: source, key: key}
	e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return baseline, Result{}
	}
	if got := e.Compare(ctx, contract.ID{1}, input); got.Verdict != contract.ComparisonMatch || baseline.reads < 3 {
		t.Fatalf("late maximum reread baseline state=%s verdict=%s diagnostics=%d reads=%d", got.StateResult, got.Verdict, len(got.Diagnostics), baseline.reads)
	}
	for _, kind := range []string{"missing", "cancelled"} {
		t.Run("late-maximum-"+kind, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 10*time.Minute)
			defer stop()
			e, _, source := readerEngineFixture(t, env, selected)
			e.validator = readerCapacityValidator(t, selected)
			gate := &comparisonReadGate{PublicSelectedReader: source, key: key, failAt: baseline.reads, kind: kind, cancel: stop}
			e.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return gate, Result{}
			}
			desired := input
			desired.Recipients.Value = slices.Clone(input.Recipients.Value)
			desired.Recipients.Value[0].DisplayName = publicPresent("provisional difference")
			got := e.Compare(ctx, contract.ID{2}, desired)
			reason, state := contract.ReasonSelectedObjectUnavailable, contract.ReaderUnavailable
			if kind == "cancelled" {
				reason, state = contract.ReasonCancelled, contract.ReaderRefused
			}
			want := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: reason}}
			if got.Verdict != contract.ComparisonUnable || got.StateResult != state || got.Observation == nil || !got.DiagnosticsComplete || !reflect.DeepEqual(got.Diagnostics, want) || gate.reads != baseline.reads || source.closes != 1 || e.activeDone != nil {
				t.Fatalf("late maximum failure state=%s verdict=%s complete=%t diagnostics=%d observation=%t reads=%d want=%d closes=%d active=%t", got.StateResult, got.Verdict, got.DiagnosticsComplete, len(got.Diagnostics), got.Observation != nil, gate.reads, baseline.reads, source.closes, e.activeDone != nil)
			}
			readerCapacityScope(t, got.CheckedScope, contract.ScopeUnchecked)
		})
	}
}

type readerCapacityJSONManifest struct {
	Schema      string `json:"schema"`
	Format      string `json:"format_contract_id"`
	Config      string `json:"config_contract_id"`
	Observation struct {
		Domain   string `json:"domain_id"`
		HEAD     string `json:"head_revision_id"`
		Snapshot string `json:"snapshot_id"`
	} `json:"observation"`
	Target  string `json:"target_recipient_id"`
	Entries []struct {
		Name        string `json:"name"`
		Incarnation string `json:"entry_incarnation_id"`
		Content     struct {
			Kind         string `json:"kind"`
			Plain        string `json:"value_base64"`
			Destinations []struct {
				Destination    string `json:"destination_id"`
				Binding        string `json:"binding_incarnation_id"`
				Incarnation    string `json:"entry_incarnation_id"`
				Service        string `json:"service_contract_id"`
				Locator        string `json:"consumer_locator"`
				TargetContract string `json:"target_contract_id"`
				Target         string `json:"canonical_target"`
				TargetData     string `json:"target_data_base64"`
				Encoding       string `json:"payload_encoding"`
				Policy         *struct {
					Contract string `json:"contract_id"`
					Data     string `json:"data_base64"`
					Digest   string `json:"digest"`
				} `json:"consumer_policy"`
			} `json:"destinations"`
		} `json:"content"`
	} `json:"entries"`
	Evidence string `json:"evidence_limit"`
}

func readerCapacityManifest(t *testing.T, got PublicManifestResult, selected *StateSession, target contract.ID) readerCapacityJSONManifest {
	t.Helper()
	want := manifestsdk.Observation{DomainID: manifestsdk.ID(selected.root.Domain), HEADRevisionID: manifestsdk.ID(selected.head.Core.Revision), SnapshotID: manifestsdk.ID(selected.root.Snapshot)}
	if got.StateResult != contract.ReaderSuccess || got.FailureReason != "" || got.Payload == nil || got.Artifact == nil || got.Observation == nil || *got.Observation != want || got.Payload.Observation != want || got.Payload.TargetRecipientID != target || got.TargetRecipientID != target || got.Payload.ArtifactLength != uint64(len(got.Artifact)) || cap(got.Artifact) != len(got.Artifact) || got.Payload.ArtifactDigest != contract.ID(sha256.Sum256(got.Artifact)) || got.Payload.EvidenceLimit != manifestsdk.EvidenceLimit || uint64(len(got.Artifact)) > manifestsdk.MaxArtifactBytes || got.Context.Operation != contract.ReaderManifestOperation || got.Result.Evidence != AuthenticatedClosure {
		t.Fatalf("maximum manifest completion state=%s reason=%s artifact=%d/%d payload=%t observation=%t evidence=%v", got.StateResult, got.FailureReason, len(got.Artifact), cap(got.Artifact), got.Payload != nil, got.Observation != nil, got.Result.Evidence)
	}
	var doc readerCapacityJSONManifest
	if err := json.Unmarshal(got.Artifact, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != genericjson.Schema || doc.Format != genericjson.FormatContractID || doc.Config != genericjson.ConfigContractID || doc.Evidence != manifestsdk.EvidenceLimit || doc.Target != hex.EncodeToString(target[:]) || doc.Observation.Domain != hex.EncodeToString(want.DomainID[:]) || doc.Observation.HEAD != hex.EncodeToString(want.HEADRevisionID[:]) || doc.Observation.Snapshot != hex.EncodeToString(want.SnapshotID[:]) {
		t.Fatal("manifest envelope changed")
	}
	return doc
}

func readerCapacityManifestCases(t *testing.T, env fixtureEnvironment, selected *StateSession, configuration contract.OutputConfiguration, generatedOnly bool) {
	t.Helper()
	target := selected.admission.recipient
	names := []string{}
	for _, named := range selected.root.Names {
		if !generatedOnly || selected.valueEntry(named.Slot).ValueSource == contract.Generated {
			names = append(names, named.Name)
		}
	}
	var count int
	t.Run("complete-requested-destinations", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
		defer cancel()
		e, _, source := readerEngineFixture(t, env, selected)
		e.validator = readerCapacityValidator(t, selected)
		request := hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: slices.Clone(names)})
		got := e.Manifest(ctx, contract.ID{3}, request)
		doc := readerCapacityManifest(t, got, selected, target)
		if len(doc.Entries) != len(names) || !slices.Equal(manifestIncludedNamesForTest(got.Payload), names) || source.closes != 1 || e.activeDone != nil {
			t.Fatal("manifest omitted requested entries")
		}
		var locatorRequests []manifestLocatorRequest
		for i, row := range doc.Entries {
			entry := selected.valueEntry(namedSlot(t, selected, names[i]))
			destinations := configuration.DefaultDestinations
			// Fixtures declare exact entry replacements. This expected vector is
			// taken from signed inputs, not the Reader's routing implementation.
			for _, route := range configuration.Routes {
				if route.EntryIncarnationID == entry.Incarnation {
					destinations = route.Destinations
				}
			}
			if row.Name != names[i] || row.Incarnation != hex.EncodeToString(entry.Incarnation[:]) || row.Content.Kind != "secret" || row.Content.Plain != "" || len(row.Content.Destinations) != len(destinations) {
				t.Fatal("manifest changed exact entry mapping", row.Name)
			}
			for j, d := range row.Content.Destinations {
				var binding contract.OutputBinding
				var output contract.OutputTarget
				for _, b := range configuration.Bindings {
					if b.DestinationID == destinations[j] {
						binding = b
						for _, candidate := range b.Targets {
							if candidate.EntryIncarnationID == entry.Incarnation {
								output = candidate
							}
						}
					}
				}
				encoding := "raw"
				if output.PayloadEncoding == contract.OutputEncodingBase64 {
					encoding = "base64"
				}
				wantPolicyDigest := independentManifestPolicyDigest(env.Domain, output.Policy.ContractID, output.Policy.Data)
				if d.Destination != destinations[j] || d.Binding != hex.EncodeToString(binding.IncarnationID[:]) || d.Incarnation != row.Incarnation || d.Service != output.ServiceContractID || d.Locator != output.ConsumerLocator || d.TargetContract != output.TargetContractID || d.Target != output.CanonicalTarget || d.TargetData != base64.StdEncoding.EncodeToString(output.TargetData) || d.Encoding != encoding || d.Policy == nil || d.Policy.Contract != output.Policy.ContractID || d.Policy.Data != base64.StdEncoding.EncodeToString(output.Policy.Data) || d.Policy.Digest != hex.EncodeToString(wantPolicyDigest[:]) {
					t.Fatal("manifest omitted or changed destination facts", row.Name, j)
				}

				locatorRequests = append(locatorRequests, manifestLocatorRequest{binding: binding.IncarnationID, destination: binding.DestinationID, target: output})
				count++
			}
		}
		if !generatedOnly && count != 1024 {
			t.Fatal("complete vector is not 128*8", count)
		}
		if len(locatorRequests) == 0 {
			t.Fatal("maximum locator vector absent")
		}
		locatorRequests[len(locatorRequests)-1].target.ConsumerLocator = ""
		locators, failed := manifestConsumerLocators(ctx, publicSelection{}, locatorRequests)
		if locators != nil || failed.diagnostic != contract.ReasonLocatorUnusable {
			t.Fatal("last unusable required locator exposed partial maximum vector", failed)
		}
		t.Logf("actual requested manifest entries=%d destinations=%d artifact-len=cap=%d", len(names), count, len(got.Artifact))
	})
	for _, fault := range []string{"renderer-failure", "cancelled-after-render", "late-deadline"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
			defer cancel()
			deadline := &manifestChangedDeadlineContext{Context: ctx}
			engine, _, source := readerEngineFixture(t, env, selected)
			seen := 0
			var supplied []byte
			engine.prepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
				return func(c context.Context, view manifestsdk.View) manifestsdk.Result {
					for i := 0; i < view.EntryCount(); i++ {
						entry, ok := view.Entry(i)
						if !ok {
							t.Fatal("missing maximum entry")
						}
						seen += entry.DestinationCount()
					}
					result := genericjson.Render(c, view)
					if result.Failure != "" {
						t.Fatal("maximum renderer failed before fault", result.Failure)
					}
					supplied = result.Artifact
					switch fault {
					case "renderer-failure":
						result.Failure = manifestsdk.InvalidResult
					case "cancelled-after-render":
						cancel()
					case "late-deadline":
						deadline.changed = true
					}
					return result
				}, ""
			}
			got := engine.Manifest(deadline, contract.ID{4}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: names}))
			reason := contract.ReasonInvalidInput
			if fault == "cancelled-after-render" {
				reason = contract.ReasonCancelled
			}
			if fault == "late-deadline" {
				reason = contract.ReasonExpired
			}
			if len(supplied) == 0 || bytes.Count(supplied, []byte{0}) != len(supplied) {
				t.Fatal("refused maximum artifact backing was not cleared")
			}
			if seen != count || got.FailureReason != reason || got.StateResult != contract.ReaderRefused || got.Artifact != nil || got.Payload != nil || got.Observation == nil || source.closes != 1 || engine.activeDone != nil {
				t.Fatalf("maximum partial output escaped fault=%s seen=%d want=%d state=%s reason=%s closes=%d", fault, seen, count, got.StateResult, got.FailureReason, source.closes)
			}
		})
	}

}

// full_only: true
// Exercises the independent all-PLAIN 8 MiB axis through authenticated issuance.
func TestReaderManifestMaximumPlainBase64(t *testing.T) {
	env, run, f, _, _ := successionMemoryRegistryFixture(t, true)
	recipients := capacityRecipients(t, f.session, 8)
	input := make([]ApplyEntryInput, 512)
	names := make([]string, 512)
	for i := range input {
		names[i] = "n" + strings.Repeat("界", 84) + fmt.Sprintf("%03d", i)
		input[i] = ApplyEntryInput{Name: names[i], Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: bytes.Repeat([]byte{byte(i)}, 16<<10), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	run.suppliedSelection(f, input)
	selected := f.session
	if selected.root.ValueEntryCount != 512 || selected.root.MembershipCount != 4096 || selected.root.RawBytes != 8<<20 {
		t.Fatal("plain joint counts")
	}
	defer readerCapacityNoEffects(t, env)()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	e, _, source := readerEngineFixture(t, env, selected)
	got := e.Manifest(ctx, contract.ID{5}, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: selected.admission.recipient, EntryNames: slices.Clone(names)}))
	doc := readerCapacityManifest(t, got, selected, selected.admission.recipient)
	if len(doc.Entries) != 512 || source.closes != 1 {
		t.Fatal("plain selection incomplete")
	}
	encoded, decoded := 0, 0
	for i, row := range doc.Entries {
		want := input[i]
		entry := selected.valueEntry(namedSlot(t, selected, want.Name))
		if row.Name != want.Name || row.Incarnation != hex.EncodeToString(entry.Incarnation[:]) || row.Content.Kind != "plain" || row.Content.Destinations != nil || len(row.Content.Plain) != 4*((len(want.InputBytes)+2)/3) {
			t.Fatal("plain name/base64 dimensions", i)
		}
		body, err := base64.StdEncoding.Strict().DecodeString(row.Content.Plain)
		if err != nil || !bytes.Equal(body, want.InputBytes) {
			t.Fatal("plain application bytes changed", i, err)
		}
		encoded += len(row.Content.Plain)
		decoded += len(body)
	}
	if decoded != 8<<20 || encoded != 512*21848 || encoded <= 4*((8<<20+2)/3) {
		t.Fatal("per-entry padding was not charged", encoded, decoded)
	}
	t.Logf("plain actual raw=%d separate base64=%d JSON-len=cap=%d", decoded, encoded, len(got.Artifact))
	before := sha256.Sum256(got.Artifact)
	e.Close()
	for i := range names {
		names[i] = "caller changed"
	}
	if sha256.Sum256(got.Artifact) != before || got.Payload.IncludedEntries[511].Name != input[511].Name {
		t.Fatal("completed maximum artifact did not transfer ownership")
	}
}

// full_only: true
// Every requested secret resolves all eight destinations.
func TestReaderManifestMaximumRequestedDestinations(t *testing.T) {
	env, run, f, _, _ := successionMemoryRegistryFixture(t, false)
	entries := make([]ApplyEntryInput, 128)
	members := []contract.ID{f.session.admission.recipient}
	for i := range entries {
		entries[i] = sharingSecretNamed(t, env, fmt.Sprintf("secret-%03d", i), fmt.Sprintf("reader destination source %03d", i), members)
	}
	run.suppliedSelection(f, entries)
	configuration := contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: env.Domain}
	byIncarnation := slices.Clone(f.session.root.Names)
	slices.SortFunc(byIncarnation, func(a, b format.NameEntry) int {
		left, right := f.session.valueEntry(a.Slot).Incarnation, f.session.valueEntry(b.Slot).Incarnation
		return bytes.Compare(left[:], right[:])
	})
	for b := 0; b < 8; b++ {
		binding := contract.OutputBinding{DestinationID: fmt.Sprintf("destination-%02d", b), IncarnationID: fixtureID(env.Domain, fmt.Sprintf("reader complete binding %d", b)), Destination: contract.OutputDestination{ConfigContractID: "fixture/capacity-config/v1", ServiceContractID: "test-capacity", CanonicalSettings: []byte(`{"a":"fixture-a","b":"fixture-b","c":"fixture-c"}`), Capabilities: contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot, Policy: contract.OutputPolicy{ContractID: "test-capacity-members", Data: []byte(`["consumer"]`)}}}

		for i, named := range byIncarnation {
			slot := fmt.Sprintf("capacity/reader-b%02d/e%03d", b, i)
			target := outputFixtureTarget("test-capacity", slot, slot+"/current", contract.OutputEncodingRaw, 63, binding.Destination.Policy)
			target.EntryIncarnationID = f.session.valueEntry(named.Slot).Incarnation
			binding.Targets = append(binding.Targets, target)
		}
		configuration.Bindings = append(configuration.Bindings, binding)
	}
	for _, named := range byIncarnation {
		route := contract.OutputRoute{EntryIncarnationID: f.session.valueEntry(named.Slot).Incarnation}
		for _, binding := range configuration.Bindings {
			route.Destinations = append(route.Destinations, binding.DestinationID)
		}
		configuration.Routes = append(configuration.Routes, route)
	}
	store, selected := signedCapacityConfigurationImage(t, env, f.session, f.session, "reader complete 1024 destinations", false, configuration)
	env.Store = store
	if selected.root.SecretCount != 128 || selected.root.MembershipCount != 128 || len(configuration.Routes) != 128 || len(selected.adminIndex.PublicationOrder) != 1024 {
		t.Fatal("complete destination fixture is not jointly admitted", selected.root.OutputConfiguration)
	}
	defer readerCapacityNoEffects(t, env)()
	readerCapacityManifestCases(t, env, selected, configuration, false)
}
