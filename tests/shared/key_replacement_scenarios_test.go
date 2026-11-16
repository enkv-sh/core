package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func admitReaderReplacement(t testing.TB, s *StateSession, keys *custody.Fixture, recipient contract.ID, successor contract.KMSBinding) *AdmittedRecipientReplacement {
	t.Helper()
	intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: s.admission.domain, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, RecipientID: recipient}, Before: *s.recipientRecord(recipient).CurrentBinding, Successor: successor}
	p, ok := s.planRecipientReplacement(t.Context(), intent)
	if !ok {
		t.Fatal("recipient replacement plan refused")
	}
	deadline := time.Now().Add(time.Minute)
	c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), PredecessorHEADDigest: contract.Hash(s.body), CurrentAccessRoot: s.root.CurrentAccess.AccessRoot}
	if _, err := rand.Read(c.AdmissionID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(c.SessionID[:]); err != nil {
		t.Fatal(err)
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], root)
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	q, request, rows, err := s.replacementRequest(t.Context(), intent, p, c)
	if err != nil {
		t.Fatal("recipient replacement public request refused")
	}
	control := contract.ControlCore{CurrentControl: s.root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *s.authority().CurrentBinding}
	if err := keys.AdmitAccess(q, intent, request, control, rows, deadline); err != nil {
		t.Fatal("recipient replacement private admission", err)
	}
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	return &AdmittedRecipientReplacement{session: s, intent: intent, plan: p, context: q.Context, requestDigest: contract.Hash(body), requestLength: len(body), crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), deadline: deadline}
}

func runReaderReplacementScenario(t testing.TB, ctx context.Context, env fixtureEnvironment) (contract.ConsumerSelection, contract.ConsumerSelection) {
	t.Helper()
	run := newScenarioRun(t, ctx, env)
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	var f *environmentFixture
	run.phase("setup", func() { f = newEnvironmentFixture(t, ctx, run.env, []int{1}, false) })
	run.phase("transition", func() {
		input := f.session.currentEntryInputs()
		input[0].Recipients = shared
		input = append(input, sharingSecret(t, env, "replacement current", shared))
		run.suppliedSelection(f, input)
	})
	var before, after contract.ConsumerSelection
	run.phase("transition", func() {
		before, after = replaceReaderInSelected(t, ctx, run, f)
	})
	run.phase("verification", func() {
		selection := sessionConsumerSelection(t, f.session, reader, "secret")
		check := env.readerSuccessorConsume(selection, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
			t.Fatal("successor reader did not consume through its own route", check)
		}
	})
	want := sessionStateImage(t, f.session)
	run.verify(f.admission, want)
	return before, after
}

func replaceReaderInSelected(t testing.TB, ctx context.Context, run *scenarioRun, f *environmentFixture) (contract.ConsumerSelection, contract.ConsumerSelection) {
	t.Helper()
	return replaceReaderInSelectedForName(t, ctx, run, f, "secret")
}

func replaceReaderInSelectedForName(t testing.TB, ctx context.Context, run *scenarioRun, f *environmentFixture, name string) (contract.ConsumerSelection, contract.ConsumerSelection) {
	t.Helper()
	env := run.env
	authority, reader := f.session.admission.recipient, fixtureID(env.Domain, "reader")
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	before := f.session
	const discardedName = "discarded reader predecessor"
	for _, entry := range before.root.Names {
		if entry.Name == discardedName {
			t.Fatal("discarded reader input must target an absent name")
		}
	}
	stale := sharingSecretNamed(t, env, discardedName, "discarded reader predecessor", shared)
	successor := env.ReaderSuccessor
	if successor.BindingID.IsZero() {
		successor = env.Custody.RecipientSuccessor(t, reader)
	}
	env.Custody.LoseRecipientPredecessor(reader)
	permit := admitReaderReplacement(t, before, env.Custody, reader, successor)
	if env.ReserveCustody != nil && !env.ReserveCustody("prepare", int(before.root.SecretCount)+1) {
		t.Fatal("replacement custody budget exhausted")
	}
	candidate, result := before.PrepareRecipientReplacement(ctx, permit, run.env.Trust)
	if candidate == nil {
		t.Fatal("reader replacement preparation", result)
	}
	if result = before.Select(ctx, candidate); result.Outcome != ObservedCurrent {
		t.Fatal("reader replacement selection", result)
	}
	env.Custody.RetireAccess()
	if err := env.Custody.ActivateRecipientSuccessor(reader); err != nil {
		t.Fatal(err)
	}
	selected, result := Open(ctx, f.admission, run.env.Store)
	if selected == nil {
		t.Fatal("reader replacement reopen", result)
	}
	f.session = selected
	if selected.recipientRecord(reader).RecipientID != reader || selected.recipientRecord(reader).CurrentBinding.BindingID != successor.BindingID || selected.root.CurrentAccess.Core.AccessGeneration != before.root.CurrentAccess.Core.AccessGeneration+1 {
		t.Fatal("reader replacement lost stable identity or exact generation")
	}
	for _, entry := range before.root.Names {
		a, err := contract.EncodeValueEntry(*before.valueEntry(entry.Slot))
		if err != nil {
			t.Fatal(err)
		}
		b, err := contract.EncodeValueEntry(*selected.valueEntry(entry.Slot))
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("reader replacement changed immutable member bytes")
		}
	}
	for i, ref := range before.root.ValueEntryPages {
		if ref == nil {
			if selected.root.ValueEntryPages[i] != nil {
				t.Fatal("reader replacement added member page")
			}
			continue
		}
		if selected.root.ValueEntryPages[i] == nil || *ref != *selected.root.ValueEntryPages[i] {
			t.Fatal("reader replacement rewrote member pages")
		}
	}
	effects := observeScenarioEffects(run.spy)
	public, private := env.Custody.Calls()
	comparison, result := selected.compareEntryInputs([]ApplyEntryInput{stale})
	if comparison != nil || result != refused(InvalidIntent) || observeScenarioEffects(run.spy) != effects {
		t.Fatal("absent entry source under the prior reader binding was not refused without effects", result)
	}
	if gotPublic, gotPrivate := env.Custody.Calls(); gotPublic != public || gotPrivate != private {
		t.Fatal("absent entry source under the prior reader binding entered private custody")
	}
	return sessionConsumerSelection(t, before, authority, name), sessionConsumerSelection(t, selected, reader, name)
}

// full_only: false
func TestReaderReplacementPreservesCurrentMaterial(t *testing.T) {
	for _, family := range []contract.Family{contract.GCP, contract.AWS} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", family, recovery), func(t *testing.T) {
				env, keys := genesisEnvironment(t, family, recovery)
				reader := fixtureID(env.Domain, "reader")
				env.ReaderSuccessor = keys.RecipientSuccessor(t, reader)
				env.FreshCurrent = func(t testing.TB, admitted OpenContext, selected *StateSession) {
					store := env.Store.(*memoryStore)
					input := selectedProcessFacts(t, admitted, selected)
					input.Objects = store.objects
					input.Consumer = &successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: reader, Binding: env.ReaderSuccessor}, Name: "secret", Value: custody.StandardValue}
					checkFreshProcessInput(t, input)
				}
				before, after := runReaderReplacementScenario(t, context.Background(), env)
				if !keys.MaterialPreserved(before, after) {
					t.Fatal("private replacement oracle found changed D/C material")
				}
			})
		}
	}
}

// full_only: false
func TestUnusedReaderReplacementDoesNotOpenPrivateMaterial(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	reader := fixtureID(env.Domain, "reader")
	successor := keys.RecipientSuccessor(t, reader)
	keys.LoseRecipientPredecessor(reader)
	permit := admitReaderReplacement(t, f.session, keys, reader, successor)
	_, private := keys.Calls()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, invalid := range []context.Context{nil, cancelled} {
		if candidate, result := f.session.PrepareRecipientReplacement(invalid, permit, env.Trust); candidate != nil || result != refused(AdmissionInvalid) || permit.used {
			t.Fatal("invalid original context consumed reader replacement", result)
		}
	}
	if _, after := keys.Calls(); after != private {
		t.Fatal("invalid reader replacement reached Crypto")
	}
	candidate, result := f.session.PrepareRecipientReplacement(context.Background(), permit, env.Trust)
	if candidate == nil {
		t.Fatal(result)
	}
	if _, after := keys.Calls(); after != private {
		t.Fatal("empty replacement coverage opened private material")
	}
	if result = f.session.Select(context.Background(), candidate); result.Outcome != ObservedCurrent {
		t.Fatal(result)
	}
	keys.RetireAccess()
	selected, result := Open(context.Background(), f.admission, env.Store)
	if selected == nil {
		t.Fatal(result)
	}
	env.FreshOpen(t, sessionStateImage(t, selected))
}

// full_only: false
func TestReaderReplacementRefusesUnadmittedBindingAndPredecessor(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	reader := fixtureID(env.Domain, "reader")
	successor := keys.RecipientSuccessor(t, reader)
	permit := admitReaderReplacement(t, f.session, keys, reader, successor)
	defer keys.RetireAccess()
	for _, name := range []string{"provider", "selector", "spki", "serial", "before", "predecessor", "authority"} {
		t.Run(name, func(t *testing.T) {
			bad := *permit
			switch name {
			case "provider":
				bad.intent.Successor.Provider = contract.AWS
			case "selector":
				bad.intent.Successor.KeySelector += "-other"
			case "spki":
				bad.intent.Successor.SPKI = bytes.Clone(bad.intent.Successor.SPKI)
				bad.intent.Successor.SPKI[len(bad.intent.Successor.SPKI)-1] ^= 1
			case "serial":
				bad.intent.Successor.BindingSerial++
			case "before":
				bad.intent.Before.BindingID = testID("another predecessor binding")
			case "predecessor":
				bad.context.PredecessorHEADDigest = testID("another predecessor")
			case "authority":
				bad.intent.RecipientID = f.session.admission.recipient
			}
			candidate, result := f.session.PrepareRecipientReplacement(context.Background(), &bad, env.Trust)
			if candidate != nil || result.Outcome != AdmissionRefused {
				t.Fatal("unadmitted replacement succeeded", result)
			}
		})
	}
}

// full_only: false
func TestReaderReplacementQualificationUsesMatchProvider(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		expected := uint32(2)
		if family == contract.GCP {
			expected = 3
		}
		for _, count := range []uint32{0, 1, expected, expected + 1} {
			t.Run(fmt.Sprintf("%d/%d", family, count), func(t *testing.T) {
				env, keys := genesisEnvironment(t, family, false)
				f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
				reader := fixtureID(env.Domain, "reader")
				permit := admitReaderReplacement(t, f.session, keys, reader, keys.RecipientSuccessor(t, reader))
				defer keys.RetireAccess()
				keys.SetQualificationUses(count)
				candidate, result := f.session.PrepareRecipientReplacement(context.Background(), permit, env.Trust)
				if (candidate != nil) != (count == expected) {
					t.Fatal("provider public-read count was not enforced", count, result)
				}
			})
		}
	}
}

// full_only: false
func TestReaderReplacementStaleAccessRootRefusesBeforeCustody(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	reader := fixtureID(env.Domain, "reader")
	permit := admitReaderReplacement(t, f.session, keys, reader, keys.RecipientSuccessor(t, reader))
	defer keys.RetireAccess()
	f.session.root.CurrentAccess.Core.AccessGeneration = math.MaxUint64
	var err error
	f.session.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(f.session.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	public, private := keys.Calls()
	candidate, result := f.session.PrepareRecipientReplacement(context.Background(), permit, env.Trust)
	afterPublic, afterPrivate := keys.Calls()
	if candidate != nil || result.Outcome != AdmissionRefused || afterPublic != public || afterPrivate != private {
		t.Fatal("access root changed after permit admission reached custody", result)
	}
}
