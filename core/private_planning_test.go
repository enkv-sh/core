package core

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

func planningUnitInput(name string) contract.PlanningInput {
	return contract.PlanningInput{Name: name, Form: contract.PlanningRetained, Retained: contract.RetainedSecretInput{
		Incarnation: contract.Hash([]byte("incarnation/" + name)), Material: contract.Hash([]byte("material/" + name))}}
}

// full_only: false
func TestPlanningRequiresCompleteSuppliedInputs(t *testing.T) {
	public := publicConfigurationFixture(t)
	public.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(public, "a"), publicFixtureEntry(public, "b")})
	v := NewPublicConfigurationValidator(nil)
	validated := v.Validate(context.Background(), public)
	if !validated.Valid || !validated.Complete {
		t.Fatal("public fixture incomplete", validated.Diagnostics)
	}
	complete := []contract.PlanningInput{planningUnitInput("a"), planningUnitInput("b")}
	if !planningInputScopeMatches(validated.Configuration, complete) {
		t.Fatal("complete required scope refused")
	}
	for _, inputs := range [][]contract.PlanningInput{nil, complete[:1], {complete[0], planningUnitInput("missing")}, {complete[0], complete[1], planningUnitInput("extra")}} {
		if planningInputScopeMatches(validated.Configuration, inputs) {
			t.Fatal("incomplete or extra scope admitted", inputs)
		}
	}
	public.Entries.Value[1].Class = publicPresent(contract.Plain)
	public.Entries.Value[1].PlainValue = publicPresent([]byte("public"))
	validated = v.Validate(context.Background(), public)
	if !validated.Valid || !planningInputScopeMatches(validated.Configuration, complete[:1]) || planningInputScopeMatches(validated.Configuration, complete) {
		t.Fatal("plain entry became a private source target", validated.Diagnostics)
	}
}

// full_only: false
func TestPlanningSourceDigestBindsPublicAndExactInputs(t *testing.T) {
	public := publicConfigurationFixture(t)
	public.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(public, "a"), publicFixtureEntry(public, "b")})
	inputs := []contract.PlanningInput{planningUnitInput("a"), planningUnitInput("b")}
	want, err := PlanningInputDigest(public, inputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*contract.PublicConfiguration, []contract.PlanningInput){
		func(p *contract.PublicConfiguration, _ []contract.PlanningInput) {
			p.Recipients.Value[0].DisplayName.Value = "changed"
		},
		func(_ *contract.PublicConfiguration, rows []contract.PlanningInput) {
			rows[0].Retained.Material[0] ^= 1
		},
		func(_ *contract.PublicConfiguration, rows []contract.PlanningInput) {
			rows[0].Retained.Incarnation[0] ^= 1
		},
	} {
		p, rows := ownPublicConfiguration(public), slices.Clone(inputs)
		change(&p, rows)
		got, err := PlanningInputDigest(p, rows)
		if err != nil || got == want {
			t.Fatal("changed source content reused captured digest", err)
		}
	}
	ordered := []contract.PlanningInput{inputs[1], inputs[0]}
	got, err := PlanningInputDigest(public, ordered)
	if err != nil || got != want || ordered[0].Name != "b" {
		t.Fatal("input ordering changes meaning or mutates caller", err)
	}
	owned, err := ownPlanningInputs(inputs)
	if err != nil {
		t.Fatal(err)
	}
	inputs[0].Retained.Material[0] ^= 1
	if owned[0].Retained == inputs[0].Retained {
		t.Fatal("source owner borrowed mutable pins")
	}
	t.Run("equivalent-public-ownership", func(t *testing.T) {
		public := publicConfigurationFixture(t)
		public.Entries = publicPresent([]contract.PublicEntry{publicFixtureEntry(public, "a"), publicFixtureEntry(public, "b")})
		for i := range public.Entries.Value {
			public.Entries.Value[i].Memberships = publicPresent([]contract.ID{public.Recipients.Value[0].RecipientID, public.Recipients.Value[1].RecipientID})
		}
		inputs := []contract.PlanningInput{planningUnitInput("a"), planningUnitInput("b")}
		want, err := PlanningInputDigest(public, inputs)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*contract.PublicConfiguration){
			func(p *contract.PublicConfiguration) { p.Groups = contract.PublicField[[][]string]{} },
			func(p *contract.PublicConfiguration) { slices.Reverse(p.Entries.Value) },
			func(p *contract.PublicConfiguration) { slices.Reverse(p.Recipients.Value) },
			func(p *contract.PublicConfiguration) { slices.Reverse(p.Entries.Value[0].Memberships.Value) },
		} {
			p := ownPublicConfiguration(public)
			change(&p)
			got, err := PlanningInputDigest(p, inputs)
			if err != nil || got != want {
				t.Fatal("equivalent owned public meaning changed source binding", err)
			}
		}
	})
}

// full_only: false
func TestPlanningPrivateResultRequiresExactWholeSet(t *testing.T) {
	current := &contract.ConsumerSelection{}
	targets := []contract.PlanningTarget{
		{Input: planningUnitInput("a"), CurrentPresent: true, Current: current},
		{Input: contract.PlanningInput{Name: "b", Form: contract.PlanningSealed}},
	}
	good := contract.PlanningCheckResult{Complete: true, Code: contract.CryptoSuccess, Rows: []contract.PlanningRelation{
		{Name: "a", Form: contract.PlanningRetained, Relation: contract.PlanningEqual, Code: contract.CryptoSuccess},
		{Name: "b", Form: contract.PlanningSealed, Relation: contract.PlanningNew, Code: contract.CryptoSuccess},
	}}
	if !planningCheckMatches(targets, good) {
		t.Fatal("valid whole result refused")
	}
	for _, change := range []func(*contract.PlanningCheckResult){
		func(r *contract.PlanningCheckResult) { r.Rows = r.Rows[:1] },
		func(r *contract.PlanningCheckResult) { r.Rows[0].Name = "other" },
		func(r *contract.PlanningCheckResult) { r.Rows[0].Form = contract.PlanningSealed },
		func(r *contract.PlanningCheckResult) { r.Rows[0].Relation = contract.PlanningChanged },
		func(r *contract.PlanningCheckResult) { r.Rows[1].Relation = contract.PlanningEqual },
		func(r *contract.PlanningCheckResult) { r.Complete = false },
		func(r *contract.PlanningCheckResult) { r.Code = contract.CryptoCancelled },
	} {
		bad := good
		bad.Rows = slices.Clone(good.Rows)
		change(&bad)
		if planningCheckMatches(targets, bad) {
			t.Fatal("invalid whole result admitted", bad)
		}
	}
	for _, prefix := range []int{0, 1, 2} {
		partial := good
		partial.Complete, partial.Code = false, contract.CryptoCancelled
		partial.Rows = slices.Clone(good.Rows)
		for i := prefix; i < len(partial.Rows); i++ {
			partial.Rows[i].Relation, partial.Rows[i].Code = contract.PlanningUnchecked, 0
		}
		if !planningCheckMatches(targets, partial) {
			t.Fatal("operation cancellation fabricated a source defect", prefix, partial)
		}
	}
}

// full_only: false
func TestPlanningPrivateFailurePrecedence(t *testing.T) {
	for _, item := range []struct {
		code  contract.CryptoResultCode
		state contract.ReaderStateResult
	}{
		{contract.CryptoInvalidAdmission, contract.ReaderRefused}, {contract.CryptoSourceAuthenticationFailed, contract.ReaderRefused},
		{contract.CryptoCancelled, contract.ReaderRefused}, {contract.CryptoExpired, contract.ReaderRefused},
		{contract.CryptoStoredAuthenticationFailed, contract.ReaderPositiveDefect}, {contract.CryptoCustodyUnavailable, contract.ReaderUnavailable},
		{contract.CryptoPrivateRouteUnavailable, contract.ReaderUnavailable}, {contract.CryptoResponseUnknown, contract.ReaderUnavailable},
	} {
		r := newPlanningResult(contract.Hash([]byte("request")), contract.Hash([]byte("domain")))
		r.Verdict = contract.ComparisonMismatch
		difference := contract.ComparisonChange{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "public"}, Path: []contract.DiagnosticField{contract.FieldPresence}, Action: contract.ComparisonAdded,
			Before: contract.ComparisonSide{State: contract.ComparisonAbsent}, After: contract.ComparisonSide{State: contract.ComparisonPresent, Value: contract.ComparisonBoolean(true)}}
		r.Changes = []contract.ComparisonChange{difference}
		r.fail(planningCryptoFailure(item.code))
		if r.StateResult != item.state || r.Verdict != contract.ComparisonUnable || r.PrivateComplete || !slices.ContainsFunc(r.Changes, func(change contract.ComparisonChange) bool { return reflect.DeepEqual(change, difference) }) {
			t.Fatal("private failure lost precedence or independent public facts", item, r)
		}
	}
}

// full_only: false
func TestPlanningDisplayFactsRequireValidCompletion(t *testing.T) {
	valid := contract.PlanningDisplayResult{SelectedRecords: 2, CompletedRecords: 2, Delivery: contract.PlanningDeliveryComplete, Code: contract.CryptoSuccess}
	if !planningDisplayMatches(2, valid) {
		t.Fatal("valid completion refused")
	}
	for _, damage := range []func(*contract.PlanningDisplayResult){
		func(r *contract.PlanningDisplayResult) { r.SelectedRecords = 3 }, func(r *contract.PlanningDisplayResult) { r.CompletedRecords = 3 }, func(r *contract.PlanningDisplayResult) { r.CompletedRecords = 1 }, func(r *contract.PlanningDisplayResult) { r.Delivery = "invalid" }, func(r *contract.PlanningDisplayResult) { r.Code = 0 }, func(r *contract.PlanningDisplayResult) { r.OutputFailed = true },
	} {
		r := valid
		damage(&r)
		if planningDisplayMatches(2, r) {
			t.Fatal("malformed safe display facts admitted")
		}
	}
	for _, r := range []contract.PlanningDisplayResult{
		{SelectedRecords: 2, Delivery: contract.PlanningDeliveryNone, Code: contract.CryptoInvalidAdmission},
		{SelectedRecords: 2, CompletedRecords: 1, Delivery: contract.PlanningDeliveryIncomplete, Code: contract.CryptoCustodyUnavailable},
		{SelectedRecords: 2, CompletedRecords: 2, Delivery: contract.PlanningDeliveryIncomplete, Code: contract.CryptoResponseUnknown, OutputFailed: true},
	} {
		if !planningDisplayMatches(2, r) {
			t.Fatal("honest interrupted delivery refused", r)
		}
	}
	out := newPlanningResult(contract.Hash([]byte("request")), contract.Hash([]byte("domain")))
	out.PrivateComplete = true
	out.DisplayDelivery = contract.PlanningDeliveryIncomplete
	out.fail(readerRefusal(contract.ReasonInvalidInput))
	if !out.PrivateComplete || out.Verdict != contract.ComparisonUnable || out.DisplayDelivery != contract.PlanningDeliveryIncomplete {
		t.Fatal("sink failure erased completed private checks")
	}
}
