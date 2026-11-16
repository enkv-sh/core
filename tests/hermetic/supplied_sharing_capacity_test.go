package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestSuppliedSharingJointRecipientBoundsBeforeCustody(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	authority := fixtureID(env.Domain, "recipient")
	recipients := []contract.ID{authority}
	for i := 1; i < 256; i++ {
		recipients = append(recipients, fixtureID(env.Domain, fmt.Sprintf("bounded recipient %d", i)))
	}
	keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "bounded custody"), true, recipients)
	env.Custody, env.Bindings, env.Crypto, env.AdmitInit, env.RetireInit = keys, keys.Bindings(), keys.Crypto(), keys.AdmitInit, keys.RetireInit
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input := make([]ApplyEntryInput, 64)
	for i := range input {
		set := []contract.ID{authority}
		for j := range 63 {
			set = append(set, recipients[1+(i*63+j)%255])
		}
		slices.SortFunc(set, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		input[i] = ApplyEntryInput{Name: fmt.Sprintf("member-%03d", i), Recipients: set, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	run.suppliedSelection(f, input)
	if f.session.root.RecipientCount != 256 || f.session.root.ValueEntryCount != 64 || f.session.root.MembershipCount != 4096 {
		t.Fatal("joint recipient and relation maxima did not select")
	}
	public, private := keys.Calls()
	before := run.spy.scenarioEffects
	for _, name := range []string{"member-65", "relations-4097", "unregistered-257"} {
		t.Run(name, func(t *testing.T) {
			proposed := slices.Clone(input)
			want := refused(InvalidIntent)
			switch name {
			case "member-65":
				proposed[0].Recipients = append(slices.Clone(proposed[0].Recipients), recipients[64])
				slices.SortFunc(proposed[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			case "relations-4097":
				proposed = append(proposed, ApplyEntryInput{Name: "zz-extra", Recipients: []contract.ID{authority}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
				want = refused(CapacityExceeded)
			case "unregistered-257":
				proposed = []ApplyEntryInput{{Name: "unknown", Recipients: []contract.ID{authority, fixtureID(env.Domain, "recipient 257")}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain}}
				slices.SortFunc(proposed[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			}
			comparison, result := f.session.Compare(ctx, proposed, nil)
			if comparison != nil || result != want || run.spy.scenarioEffects != before {
				t.Fatal("excess membership crossed public preflight", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("excess membership entered private custody")
			}
		})
	}
	rows, _, err := buildEntryIntent(env.Domain, input)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"member-65", "relations-4097", "recipients-257"} {
		t.Run("allocation-"+name, func(t *testing.T) {
			proposed := slices.Clone(rows)
			switch name {
			case "member-65":
				proposed[0].Recipients = append(slices.Clone(proposed[0].Recipients), recipients[64])
				slices.SortFunc(proposed[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			case "relations-4097":
				row := rows[0]
				row.Name, row.Recipients = "zz-extra", []contract.ID{authority}
				proposed = append(proposed, row)
			case "recipients-257":
				proposed = proposed[:5]
				proposed[4].Recipients = []contract.ID{authority, fixtureID(env.Domain, "recipient 257")}
				slices.SortFunc(proposed[4].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				// Four full groups cover authority and the first 252 ordinary IDs.
				proposed[4].Recipients = append(proposed[4].Recipients, recipients[253:]...)
				slices.SortFunc(proposed[4].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			}
			allocs := testing.AllocsPerRun(5, func() {
				body, err := contract.EncodeCryptoIntent(env.Domain, proposed)
				if err == nil || body != nil {
					t.Fatal("excess intent encoded")
				}
			})
			if allocs != 0 {
				t.Fatal("excess intent allocated by rejected counts", allocs)
			}
		})
	}
	basis, ok := f.session.admission.domainBasis()
	if !ok {
		t.Fatal("selected registry missing")
	}
	basis.Recipients = append(basis.Recipients, basis.Recipients[0])
	if allocs := testing.AllocsPerRun(5, func() {
		body, err := contract.EncodeGenesisRecipientsCore(env.Domain, basis.Recipients)
		if body != nil || err != contract.ErrRecordCapacity {
			t.Fatal("registry recipient 257 was admitted", err)
		}
	}); allocs != 0 {
		t.Fatal("oversized registry allocated before recipient bound", allocs)
	}
}
