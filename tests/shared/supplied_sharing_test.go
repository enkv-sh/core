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

func sharingSecret(t testing.TB, env fixtureEnvironment, seal string, recipients []contract.ID) ApplyEntryInput {
	t.Helper()
	return sharingSecretNamed(t, env, "secret", seal, recipients)
}

func sharingSecretNamed(t testing.TB, env fixtureEnvironment, name, seal string, recipients []contract.ID) ApplyEntryInput {
	t.Helper()
	core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain, FileIdentity: fixtureID(env.Domain, "source-file"), SourceID: fixtureID(env.Domain, seal), DataKeyID: fixtureID(env.Domain, seal+" key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: name}
	sealed, code := env.Custody.SealInput(env.operationContext(), core, recipients, custody.StandardValue)
	if code != contract.CryptoSuccess {
		t.Fatal("sharing source sealing", code)
	}
	return ApplyEntryInput{Name: core.Name, Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: sealed, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
}

func assertRetainedValue(t testing.TB, before, after *format.ValueEntry) {
	t.Helper()
	if before.Incarnation != after.Incarnation || before.ValueState != after.ValueState || before.OriginSnapshot != after.OriginSnapshot || before.OriginTransition != after.OriginTransition || !bytes.Equal(before.ValueBytes, after.ValueBytes) {
		t.Fatal("membership-only change replaced the value or its identity")
	}
}

func (r *scenarioRun) refuseSharingAuthority(f *environmentFixture, input []ApplyEntryInput, grant bool) {
	r.t.Helper()
	parent := admitSuppliedComparison(r.t, f.session, r.env.Custody, input)
	if grant {
		invalid := append(slices.Clone(input), ApplyEntryInput{Name: "zz-invalid", Recipients: []contract.ID{f.session.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: []byte{1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		public, private := r.env.Custody.Calls()
		before := r.spy.scenarioEffects
		comparison, result := f.session.Compare(r.ctx, invalid, parent)
		if comparison != nil || result != refused(InvalidIntent) || parent.used || r.spy.scenarioEffects != before {
			r.t.Fatal("later invalid source escaped whole-input preflight", result)
		}
		if gotPublic, gotPrivate := r.env.Custody.Calls(); gotPublic != public || gotPrivate != private {
			r.t.Fatal("later invalid source entered private custody")
		}
	}
	if r.env.ReserveCustody != nil && !r.env.ReserveCustody("compare", 2) {
		r.t.Fatal("comparison custody budget exhausted")
	}
	comparison, result := f.session.Compare(r.ctx, input, parent)
	if comparison == nil {
		r.t.Fatal("sharing authority comparison", result)
	}
	if r.env.ReserveCustody != nil && !r.env.ReserveCustody("prepare", 1) {
		r.t.Fatal("preparation custody budget exhausted")
	}
	permit := admit(r.t, f.session, comparison)
	if grant {
		permit.authority.grant.Rows[len(permit.authority.grant.Rows)-1].EntryDigest[0] ^= 1
	} else {
		permit.authority.exclusion.Rows[len(permit.authority.exclusion.Rows)-1].Path[0] ^= 1
	}
	before := r.spy.scenarioEffects
	public, private := r.env.Custody.Calls()
	predecessor := contract.Hash(f.session.body)
	candidate, result := f.session.Prepare(r.ctx, comparison, permit, r.env.Trust)
	if candidate != nil || result != refused(AdmissionInvalid) || permit.used || f.session.prepared || r.spy.scenarioEffects != before {
		r.t.Fatal("wrong exact sharing authority crossed selection", result)
	}
	if gotPublic, gotPrivate := r.env.Custody.Calls(); gotPublic != public || gotPrivate != private {
		r.t.Fatal("wrong sharing authority performed private work")
	}
	r.env.Custody.RetireApply()
	opened, result := Open(r.ctx, f.admission, r.env.Store)
	if opened == nil || result.Outcome != ObservedCurrent || contract.Hash(opened.body) != predecessor {
		r.t.Fatal("refused sharing authority changed the selected predecessor", result)
	}
	f.session = opened
}

func runSuppliedSharingScenario(t testing.TB, ctx context.Context, env fixtureEnvironment) {
	t.Helper()
	if env.Custody == nil {
		t.Fatal("supplied sharing has no private fixture")
	}
	run := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	authority, reader := fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run.phase("setup", func() {
		f = newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
		// Initial key qualification precedes this plain-only call count.
		plainBefore := f.session.valueEntry(0)
		public, private := env.Custody.Calls()
		for _, recipients := range [][]contract.ID{shared, {authority}} {
			plain := f.session.currentEntryInputs()
			plain[0].Recipients = recipients
			run.suppliedSelection(f, plain)
			assertRetainedValue(t, plainBefore, f.session.valueEntry(0))
		}
		if gotPublic, gotPrivate := env.Custody.Calls(); gotPublic != public || gotPrivate != private {
			t.Fatal("plain sharing used private custody")
		}
	})
	var input []ApplyEntryInput
	var initial, granted *StateSession
	var captured contract.ConsumerSelection
	run.phase("transition", func() {
		input = append(f.session.currentEntryInputs(), sharingSecret(t, env, "sharing initial", []contract.ID{authority}))
		initial = run.suppliedSelection(f, input)
	})
	run.phase("transition", func() {
		input[0].Recipients = shared
		input[1] = sharingSecret(t, env, "sharing grant", shared)
		run.refuseSharingAuthority(f, input, true)
		granted = run.suppliedSelection(f, input)
		for _, entry := range initial.root.Names {
			assertRetainedValue(t, initial.valueEntry(entry.Slot), granted.valueEntry(entry.Slot))
		}
		before := sessionConsumerSelection(t, initial, authority, "secret")
		captured = sessionConsumerSelection(t, granted, reader, "secret")
		if before.Core != captured.Core || !reflect.DeepEqual(before.Payload, captured.Payload) || before.Access.MaterialID != captured.Access.MaterialID || before.Access.MaterialContextDigest != captured.Access.MaterialContextDigest || before.Access.PackageCheck != captured.Access.PackageCheck || len(captured.Access.Wraps) != len(before.Access.Wraps)+1 {
			t.Fatal("grant changed current protected material")
		}
		for _, wrap := range before.Access.Wraps {
			i := slices.IndexFunc(captured.Access.Wraps, func(row contract.WrapRow) bool {
				return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID
			})
			if i < 0 || !reflect.DeepEqual(wrap, captured.Access.Wraps[i]) {
				t.Fatal("grant replaced an existing ordinary or recovery wrap")
			}
		}
	})
	run.phase("verification", func() {
		if env.ReserveCustody != nil && !env.ReserveCustody("consume", 1) {
			t.Fatal("consumer custody budget exhausted")
		}
		if check := env.readerConsume(captured, custody.StandardValue); firstFlowConsumerOutcome(check, captured, false) != "success" {
			t.Fatal("granted reader cannot consume through its own private route")
		}
	})
	run.phase("transition", func() {
		input[0].Recipients = []contract.ID{authority}
		original := bytes.Clone(input[1].InputBytes)
		input[1].Recipients = []contract.ID{authority}
		run.refuseSharingAuthority(f, input, false)
		run.suppliedSelection(f, input)
		assertRetainedValue(t, granted.valueEntry(0), f.session.valueEntry(0))
		_, before := lifecycleEntry(t, granted, "secret")
		_, after := lifecycleEntry(t, f.session, "secret")
		assertFreshSecretValue(t, before, after, true)
		current := sessionConsumerSelection(t, f.session, authority, "secret")
		if len(current.Access.Wraps)+1 != len(captured.Access.Wraps) || !slices.Equal(after.Recipients, []contract.ID{authority}) || !reflect.DeepEqual(initial.root.CurrentAccess.Core.Recovery, f.session.root.CurrentAccess.Core.Recovery) {
			t.Fatal("exclusion lost remaining access or recovery coverage")
		}
		for _, wrap := range current.Access.Wraps {
			i := slices.IndexFunc(captured.Access.Wraps, func(row contract.WrapRow) bool {
				return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID
			})
			if i < 0 || bytes.Equal(wrap.RSACiphertext, captured.Access.Wraps[i].RSACiphertext) {
				t.Fatal("exclusion reused an old key package")
			}
		}
		parent := admitSuppliedComparison(t, f.session, env.Custody, input)
		if env.ReserveCustody != nil && !env.ReserveCustody("compare", 2) {
			t.Fatal("comparison custody budget exhausted")
		}
		creates, cas, signs := run.spy.StoreCreate, run.spy.StoreCAS, run.spy.TrustSign
		beforeHead := bytes.Clone(f.session.body)
		comparison, result := f.session.Compare(ctx, input, parent)
		if comparison != nil || result.Outcome != Unchanged || run.spy.StoreCreate != creates || run.spy.StoreCAS != cas || run.spy.TrustSign != signs || !bytes.Equal(f.session.body, beforeHead) || !bytes.Equal(input[1].InputBytes, original) {
			t.Fatal("original source repeat failed checked no-op or source preservation", result)
		}
		env.Custody.RetireApply()
	})
	var expected stateImage
	run.phase("verification", func() {
		current := sessionConsumerSelection(t, f.session, authority, "secret")
		if selection, result := f.session.admitConsumerSelection(ctx, []string{input[0].Name, "secret"}, reader); selection != nil || result != refused(AdmissionInvalid) {
			t.Fatal("excluded reader passed complete Core selection admission", result)
		}
		denied := current
		denied.Binding = captured.Binding
		public, private := env.Custody.Calls()
		check := env.readerConsume(denied, custody.StandardValue)
		if check.Code != contract.CryptoInvalidAdmission || check.Delivery != 0 || check.SinkCalls != 0 || len(check.KeyUses) != 0 {
			t.Fatal("excluded reader passed current consumer admission")
		}
		if gotPublic, gotPrivate := env.Custody.Calls(); gotPublic != public || gotPrivate != private {
			t.Fatal("excluded current consumer used private custody")
		}
		if env.ReserveCustody != nil && !env.ReserveCustody("consume", 1) {
			t.Fatal("consumer custody budget exhausted")
		}
		if check := env.readerConsume(captured, custody.StandardValue); firstFlowConsumerOutcome(check, captured, false) != "success" {
			t.Fatal("exclusion claimed historical revocation")
		}
	})
	run.phase("verification", func() {
		current := sessionConsumerSelection(t, f.session, authority, "secret")
		if env.ReserveCustody != nil && !env.ReserveCustody("consume", 1) {
			t.Fatal("consumer custody budget exhausted")
		}
		if check := env.Custody.Consume(ctx, current, custody.StandardValue); firstFlowConsumerOutcome(check, current, false) != "success" {
			t.Fatal("exclusion denied remaining authority")
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
			t.Fatal("supplied sharing requires a fresh reader")
		}
	})
}

// full_only: false
func TestCompleteSuppliedSharingPreservesCurrentAccess(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			runSuppliedSharingScenario(t, context.Background(), env)
		})
	}
}
