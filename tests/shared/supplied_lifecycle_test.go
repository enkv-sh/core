package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func suppliedSecret(t testing.TB, env fixtureEnvironment, name, seal string, choice uint8, selected ...contract.ID) ApplyEntryInput {
	t.Helper()
	core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain, FileIdentity: fixtureID(env.Domain, "source-file"), SourceID: fixtureID(env.Domain, seal), DataKeyID: fixtureID(env.Domain, seal+" key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: name}
	recipients := []contract.ID{fixtureID(env.Domain, "recipient")}
	if len(selected) != 0 {
		recipients = slices.Clone(selected)
	}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	sealed, code := env.Custody.SealInput(env.operationContext(), core, recipients, choice)
	if code != contract.CryptoSuccess {
		t.Fatal("supplied source sealing", code)
	}
	return ApplyEntryInput{Name: name, Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: sealed, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
}

func (r *scenarioRun) suppliedPreparation(f *environmentFixture, input []ApplyEntryInput) *Candidate {
	r.t.Helper()
	secret := f.session.root.SecretCount != 0 || slices.ContainsFunc(input, func(value ApplyEntryInput) bool { return value.ConfidentialityClass == format.Secret })
	parent := admitSuppliedComparison(r.t, f.session, r.env.Custody, input)
	sourceCount := 0
	for _, value := range input {
		if value.ConfidentialityClass == format.Secret {
			sourceCount++
		}
	}
	if r.env.ReserveCustody != nil && secret && !r.env.ReserveCustody("compare", int(f.session.root.SecretCount)+sourceCount) {
		r.t.Fatal("comparison custody budget exhausted")
	}
	comparison, result := f.session.Compare(r.ctx, input, parent)
	if comparison == nil {
		r.t.Fatal("supplied comparison", result)
	}
	preparedCount := 0
	for i, value := range comparison.desiredEntries {
		if value.ConfidentialityClass == format.Secret && slices.Contains(comparison.changed, comparison.slots[i]) {
			preparedCount++
		}
	}
	if r.env.ReserveCustody != nil && secret && preparedCount > 0 && !r.env.ReserveCustody("prepare", preparedCount) {
		r.t.Fatal("preparation custody budget exhausted")
	}
	permit := admit(r.t, f.session, comparison)
	candidate, result := f.session.Prepare(r.ctx, comparison, permit, r.env.Trust)
	if candidate == nil {
		r.t.Fatal("supplied preparation", result)
	}
	if secret {
		r.env.Custody.RetireApply()
	}
	return candidate
}

func (r *scenarioRun) suppliedSelection(f *environmentFixture, input []ApplyEntryInput) *StateSession {
	r.t.Helper()
	creates, cas, signs := r.spy.StoreCreate, r.spy.StoreCAS, r.spy.TrustSign
	candidate := r.suppliedPreparation(f, input)
	if result := f.session.Select(r.ctx, candidate); result.Outcome != ObservedCurrent {
		r.t.Fatal("supplied selection", result)
	}
	if r.spy.StoreCreate == creates || r.spy.StoreCAS != cas+1 || r.spy.TrustSign != signs+1 {
		r.t.Fatal("complete supplied change did not select exactly once")
	}
	selected, result := Open(r.ctx, f.admission, r.env.Store)
	if selected == nil || result.Outcome != ObservedCurrent || int(selected.root.ValueEntryCount) != len(input) {
		r.t.Fatal("incomplete supplied selection", result)
	}
	f.session = selected
	return selected
}

func lifecycleEntry(t testing.TB, session *StateSession, name string) (uint16, *format.ValueEntry) {
	t.Helper()
	for _, entry := range session.root.Names {
		if entry.Name == name {
			return entry.Slot, session.valueEntry(entry.Slot)
		}
	}
	t.Fatal("lifecycle member is absent")
	return 0, nil
}

func assertFreshSecretValue(t testing.TB, before, after *format.ValueEntry, sameIncarnation bool) {
	t.Helper()
	if (before.Incarnation == after.Incarnation) != sameIncarnation || before.ValueState == after.ValueState || before.OriginSnapshot == after.OriginSnapshot || before.OriginTransition == after.OriginTransition || bytes.Equal(before.ValueBytes, after.ValueBytes) {
		t.Fatal("secret lifecycle retained material that must change")
	}
	oldPayload, err := contract.InspectCanonicalPayload(before.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	newPayload, err := contract.InspectCanonicalPayload(after.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	if oldPayload.DataKeyID == newPayload.DataKeyID || oldPayload.CommitmentKeyID == newPayload.CommitmentKeyID || oldPayload.SemanticCommitment == newPayload.SemanticCommitment || oldPayload.PackageCheck == newPayload.PackageCheck || bytes.Equal(oldPayload.Ciphertext, newPayload.Ciphertext) {
		t.Fatal("secret lifecycle reused protected value material")
	}
}

func runSuppliedLifecycleScenario(t testing.TB, ctx context.Context, env fixtureEnvironment) {
	t.Helper()
	if env.Custody == nil {
		t.Fatal("supplied lifecycle has no private fixture")
	}
	run := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	run.phase("setup", func() {
		sizes := make([]int, 17)
		for i := range sizes {
			sizes[i] = 1
		}
		f = newEnvironmentFixture(t, ctx, run.env, sizes, false)
	})
	var input []ApplyEntryInput
	var first, retained *format.ValueEntry
	var firstSlot, retainedSlot uint16
	var historical ApplyEntryInput
	run.phase("transition", func() {
		input = f.session.currentEntryInputs()
		historical = suppliedSecret(t, env, "secret", "first seal", custody.StandardValue)
		input = append(input, historical, suppliedSecret(t, env, "zz-retained", "retained seal", custody.EmptyValue))
		run.suppliedSelection(f, input)
		firstSlot, first = lifecycleEntry(t, f.session, "secret")
		retainedSlot, retained = lifecycleEntry(t, f.session, "zz-retained")
		if firstSlot/format.PageSlots != retainedSlot/format.PageSlots {
			t.Fatal("retention fixture members are on different pages")
		}
	})
	run.phase("transition", func() {
		input[17] = suppliedSecret(t, env, "secret", "randomized equal seal", custody.StandardValue)
		input[18] = suppliedSecret(t, env, "zz-retained", "randomized empty seal", custody.EmptyValue)
		if bytes.Equal(input[17].InputBytes, historical.InputBytes) {
			t.Fatal("equal source seal was not randomized")
		}
		parent := admitSuppliedComparison(t, f.session, env.Custody, input)
		calls, private := env.Custody.Calls()
		before := bytes.Clone(f.session.body)
		entropy := bytes.NewReader(bytes.Repeat([]byte{0x7a}, 32))
		f.session.admission.entropy = entropy
		if env.ReserveCustody != nil && !env.ReserveCustody("compare", 4) {
			t.Fatal("comparison custody budget exhausted")
		}
		reads, transportReads := run.spy.StoreRead, run.spy.StoreTransportRead
		comparison, result := f.session.Compare(ctx, input, parent)
		if comparison != nil || result.Outcome != Unchanged || run.spy.StoreRead-reads != 2*uint64(f.session.root.OutputConfiguration.SliceCount)+run.spy.StoreTransportRead-transportReads || run.spy.StoreCreate+run.spy.StoreCAS+run.spy.TrustSign != 0 || f.session.prepared || !bytes.Equal(f.session.body, before) || entropy.Len() != 32 {
			t.Fatal("equal supplied values changed canonical state", result)
		}
		f.session.admission.entropy = nil
		if publicAfter, privateAfter := env.Custody.Calls(); publicAfter != calls || privateAfter != private+4 {
			t.Fatal("equality did not perform only required private validation")
		}
		env.Custody.RetireApply()
	})
	var changed *format.ValueEntry
	run.phase("transition", func() {
		before := f.session
		input[17] = suppliedSecret(t, env, "secret", "changed seal", custody.EmptyValue)
		input[16].InputBytes = []byte("changed plain")
		input = append(input[1:], suppliedSecret(t, env, "new-secret", "added seal", custody.StandardValue))
		run.suppliedSelection(f, input)
		_, changed = lifecycleEntry(t, f.session, "secret")
		assertFreshSecretValue(t, first, changed, true)
		gotSlot, gotRetained := lifecycleEntry(t, f.session, "zz-retained")
		_, _, oldAccess, ok := before.selectedValue(retainedSlot)
		if !ok {
			t.Fatal("retained access missing before change")
		}
		_, _, newAccess, ok := f.session.selectedValue(gotSlot)
		if !ok || gotSlot != retainedSlot || !reflect.DeepEqual(retained, gotRetained) || !reflect.DeepEqual(oldAccess, newAccess) {
			t.Fatal("mixed change replaced an unchanged neighbor or its access")
		}
		newSlot, _ := lifecycleEntry(t, f.session, "new-secret")
		if newSlot != 0 || f.session.root.SecretCount != 3 {
			t.Fatal("mixed replacement lost successor-free slot allocation or secret count")
		}
	})
	run.phase("transition", func() {
		before := f.session
		index := slices.IndexFunc(input, func(value ApplyEntryInput) bool { return value.Name == "secret" })
		input[index] = historical
		run.suppliedSelection(f, input)
		restoredSlot, restored := lifecycleEntry(t, f.session, "secret")
		assertFreshSecretValue(t, changed, restored, true)
		assertFreshSecretValue(t, first, restored, true)
		_, _, oldAccess, oldPresent := before.selectedValue(firstSlot)
		_, _, newAccess, newPresent := f.session.selectedValue(restoredSlot)
		oldRows, newRows := before.accessRecords(), f.session.accessRecords()
		if *before.root.ValueEntryPages[0] != *f.session.root.ValueEntryPages[0] || f.session.root.SecretCount != 3 ||
			restoredSlot != firstSlot || !oldPresent || !newPresent || oldAccess.MaterialID == newAccess.MaterialID ||
			len(oldRows) != 3 || len(newRows) != len(oldRows) {
			t.Fatal("secret update replaced another page or lost untouched secret counts")
		}
		// Access rows share a byte-packed physical page. Updating one material
		// may repack that page, while every other complete row must be retained.
		for _, row := range oldRows {
			if row.MaterialKind == oldAccess.MaterialKind && row.MaterialID == oldAccess.MaterialID {
				if slices.ContainsFunc(newRows, func(candidate contract.AccessRecord) bool {
					return candidate.MaterialKind == row.MaterialKind && candidate.MaterialID == row.MaterialID
				}) {
					t.Fatal("restored secret retained its replaced access material")
				}
				continue
			}
			if !slices.ContainsFunc(newRows, func(candidate contract.AccessRecord) bool { return reflect.DeepEqual(candidate, row) }) {
				t.Fatal("restored secret changed an untouched complete access row")
			}
		}
	})
	run.phase("transition", func() {
		run.suppliedSelection(f, nil)
		if f.session.root.ValueEntryCount != 0 || f.session.root.RawBytes != 0 || f.session.root.SecretCount != 0 || f.session.root.AccessRecordCount != 0 || len(f.session.root.CurrentAccess.Core.AccessPageRefs) != 0 {
			t.Fatal("last removal retained current material")
		}
	})
	run.phase("transition", func() {
		run.suppliedSelection(f, []ApplyEntryInput{historical})
		_, readded := lifecycleEntry(t, f.session, "secret")
		assertFreshSecretValue(t, first, readded, false)
	})
	var expected stateImage
	run.phase("verification", func() {
		selection := sessionConsumerSelection(t, f.session, f.session.admission.recipient, "secret")
		if env.ReserveCustody != nil && !env.ReserveCustody("consume", 1) {
			t.Fatal("consumer custody budget exhausted")
		}
		check := env.Custody.Consume(ctx, selection, custody.StandardValue)
		if firstFlowConsumerOutcome(check, selection, false) != "success" {
			t.Fatal("historical-source re-addition cannot be consumed")
		}
		expected = sessionStateImage(t, f.session)
	})
	run.phase("reopen", func() {
		assertStateImage(t, f.session, expected)
		if env.FreshCurrent != nil {
			env.FreshCurrent(t, f.admission, f.session)
		} else if env.FreshOpen != nil {
			env.FreshOpen(t, expected)
		} else {
			t.Fatal("supplied lifecycle requires fresh-process verification")
		}
	})
}

// full_only: false
func TestCompleteSuppliedLifecyclePreservesEqualMaterial(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			runSuppliedLifecycleScenario(t, context.Background(), env)
		})
	}
}

// full_only: false
func TestSuppliedPlainMutationOpensSourcesOnlyDuringComparison(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, recovery)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
			input := append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "plain-only seal", custody.StandardValue))
			run.suppliedSelection(f, input)
			before := f.session
			secretSlot, _ := lifecycleEntry(t, before, "secret")
			beforeCore, beforePayload, beforeAccess, ok := before.selectedValue(secretSlot)
			if !ok {
				t.Fatal("plain-only fixture has no current secret")
			}
			changed := false
			for i := range input {
				if input[i].ConfidentialityClass == format.Plain {
					input[i].ValueSource = format.Supplied
					input[i].InputBytes = []byte("plain-only mutation")
					changed = true
					break
				}
			}
			if !changed {
				t.Fatal("plain-only fixture has no plain value")
			}
			parent := admitSuppliedComparison(t, before, keys, input)
			defer keys.RetireApply()
			public, private := keys.Calls()
			comparison, result := before.Compare(ctx, input, parent)
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("plain-only comparison", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private+2 {
				t.Fatal("plain-only comparison did not open the current and proposed secret sources", gotPublic-public, gotPrivate-private)
			}
			permit := admit(t, before, comparison)
			public, private = keys.Calls()
			candidate, result := before.Prepare(ctx, comparison, permit, run.env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("plain-only preparation", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("plain-only preparation used a private key", gotPublic-public, gotPrivate-private)
			}
			if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("plain-only selection", result)
			}
			selected, result := Open(ctx, f.admission, run.env.Store)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("plain-only selected state", result)
			}
			afterSlot, _ := lifecycleEntry(t, selected, "secret")
			afterCore, afterPayload, afterAccess, ok := selected.selectedValue(afterSlot)
			actualRetainedSecretCount := uint32(0)
			if ok && afterSlot == secretSlot && reflect.DeepEqual(afterCore, beforeCore) && reflect.DeepEqual(afterPayload, beforePayload) && reflect.DeepEqual(afterAccess, beforeAccess) {
				actualRetainedSecretCount = 1
			}
			expectedRetainedSecretCount := uint32(1)
			t.Logf("enkv-retained-secret-material expected=%d actual=%d", expectedRetainedSecretCount, actualRetainedSecretCount)
			if actualRetainedSecretCount != expectedRetainedSecretCount {
				t.Fatal("plain-only mutation changed current secret material")
			}
		})
	}
}

// full_only: false
func TestRetainedSuppliedInputRefusesWholeRequest(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	input := append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "input seal", custody.StandardValue))
	run.suppliedSelection(f, input)
	conversion := suppliedSecret(t, env, input[0].Name, "conversion seal", custody.StandardValue)
	for _, name := range []string{"duplicate", "missing-authority", "duplicate-recipient", "unsupported-source", "unsupported-encoding", "later-malformed-source", "secret-to-plain", "plain-to-secret", "missing-private-parent"} {
		t.Run(name, func(t *testing.T) {
			proposed := slices.Clone(input)
			want := refused(InvalidIntent)
			var configurationReads uint64
			parent := admitSuppliedComparison(t, f.session, keys, proposed)
			defer keys.RetireApply()
			switch name {
			case "duplicate":
				proposed = append(proposed, proposed[1])
			case "missing-authority":
				proposed[1].Recipients = []contract.ID{fixtureID(env.Domain, "reader")}
			case "duplicate-recipient":
				proposed[1].Recipients = []contract.ID{f.session.admission.recipient, f.session.admission.recipient}
			case "unsupported-source":
				proposed[1].ValueSource = contract.Generated
			case "unsupported-encoding":
				proposed[1].ConfidentialityClass = 255
			case "later-malformed-source":
				proposed = append(proposed, ApplyEntryInput{Name: "zz-invalid", Recipients: input[1].Recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: []byte{1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			case "secret-to-plain":
				proposed[1].ConfidentialityClass, proposed[1].InputBytes = format.Plain, nil
			case "plain-to-secret":
				proposed[0] = conversion
			case "missing-private-parent":
				parent = nil
				want = refused(AdmissionInvalid)
				configurationReads = 2 * uint64(f.session.root.OutputConfiguration.SliceCount)
			}
			public, private := keys.Calls()
			wantEffects := run.spy.scenarioEffects
			wantEffects.StoreRead += configurationReads
			comparison, result := f.session.Compare(ctx, proposed, parent)
			if comparison != nil || result != want || parent != nil && parent.used || run.spy.scenarioEffects != wantEffects {
				t.Fatal("invalid complete supplied request crossed admission", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("invalid complete input entered private custody")
			}
		})
	}
}

// full_only: true
func TestDisjointSuppliedReplacementAtJointBounds(t *testing.T) {
	for _, allSecret := range []bool{false, true} {
		t.Run(fmt.Sprint(allSecret), func(t *testing.T) {
			testDisjointSuppliedReplacement(t, allSecret)
		})
	}
}

func testDisjointSuppliedReplacement(t *testing.T, allSecret bool) {
	t.Helper()
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	for generation := range 2 {
		names := maximumLifecycleNames(fmt.Sprintf("generation-%d", generation))
		input := make([]ApplyEntryInput, 512)
		for i, name := range names {
			input[i] = ApplyEntryInput{Name: name, Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			if i >= 384 {
				input[i].InputBytes = bytes.Repeat([]byte{byte(generation)}, contract.CryptoMaxRawValue)
			}
			if allSecret {
				choice := custody.EmptyValue
				if i >= 384 {
					choice = custody.MaximumValue
				}
				input[i] = suppliedSecret(t, env, name, fmt.Sprintf("maximum seal %d/%d", generation, i), choice)
			}
		}
		secretCount := uint32(512)
		if !allSecret {
			input[511] = suppliedSecret(t, env, names[511], fmt.Sprintf("maximum seal %d", generation), custody.MaximumValue)
			secretCount = 1
		}
		run.suppliedSelection(f, input)
		if f.session.root.ValueEntryCount != 512 || f.session.root.SecretCount != secretCount || f.session.root.RawBytes != contract.CryptoMaxRawSet {
			t.Fatal("joint supplied bounds were not retained")
		}
		if generation == 1 && (f.session.head.Subject.Normal.Union.Count != 1024 || f.session.head.Subject.Grant.Grants.Count != 512 || f.session.head.Subject.Exclusion.Exclusions.Count != 512) {
			t.Fatal("disjoint replacement did not bind the complete comparison union")
		}
		for i, entry := range f.session.root.Names {
			if entry.Name != names[i] || entry.Slot != uint16(i) {
				t.Fatal("disjoint replacement did not reuse successor-free slots")
			}
		}
	}
}

// full_only: true
func TestSuppliedSingleUpdateRetainsMaximumSecretSet(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	names := maximumLifecycleNames("retained")
	input := make([]ApplyEntryInput, 512)
	for i, name := range names {
		choice := custody.EmptyValue
		if i >= 384 {
			choice = custody.MaximumValue
		}
		input[i] = suppliedSecret(t, env, name, fmt.Sprintf("retained seal %d", i), choice)
	}
	run.suppliedSelection(f, input)
	before := f.session
	if before.root.RawBytes != contract.CryptoMaxRawSet {
		t.Fatal("retained secret fixture did not reach the raw-byte bound")
	}
	input[511] = suppliedSecret(t, env, names[511], "single changed seal", custody.EmptyValue)
	run.suppliedSelection(f, input)
	if f.session.root.ValueEntryCount != 512 || f.session.root.SecretCount != 512 || f.session.root.RawBytes != contract.CryptoMaxRawSet-contract.CryptoMaxRawValue {
		t.Fatal("single update changed complete-set accounting")
	}
	for i, name := range names {
		oldSlot, oldEntry := lifecycleEntry(t, before, name)
		newSlot, newEntry := lifecycleEntry(t, f.session, name)
		if i == 511 {
			assertFreshSecretValue(t, oldEntry, newEntry, true)
			continue
		}
		_, _, oldAccess, oldOK := before.selectedValue(oldSlot)
		_, _, newAccess, newOK := f.session.selectedValue(newSlot)
		if !oldOK || !newOK || oldSlot != newSlot || !reflect.DeepEqual(oldEntry, newEntry) || !reflect.DeepEqual(oldAccess, newAccess) {
			t.Fatal("single update replaced retained secret material", name)
		}
	}
}
