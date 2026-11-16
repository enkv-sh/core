package core

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestMixedSharingRequiresExactSeparateAuthority(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	authority := f.session.admission.recipient
	shared := []contract.ID{authority, fixtureID(env.Domain, "reader")}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input := f.session.currentEntryInputs()
	input[0].Recipients = shared
	input = append(input, sharingSecret(t, env, "mixed sharing initial", []contract.ID{authority}))
	run.suppliedSelection(f, input)
	before := f.session
	input[0].Recipients = []contract.ID{authority}
	input[1] = sharingSecret(t, env, "mixed sharing grant", shared)
	parent := admitSuppliedComparison(t, f.session, keys, input)
	defer keys.RetireApply()
	comparison, result := f.session.Compare(ctx, input, parent)
	if comparison == nil {
		t.Fatal(result)
	}
	permit := admit(t, f.session, comparison)
	if len(permit.plan.values) != 0 || len(comparison.preparedRows) != 1 || len(permit.authority.grant.Rows) != 1 || len(permit.authority.exclusion.Rows) != 1 {
		t.Fatal("mixed membership did not separate fresh values and exact authority")
	}
	for _, name := range []string{"missing-normal", "missing-grant", "missing-exclusion", "empty-grant", "empty-exclusion", "excess-grant", "excess-exclusion", "grant-member", "grant-recipient", "grant-incarnation", "grant-slot", "grant-name", "exclusion-member", "exclusion-recipient", "exclusion-path", "exclusion-name", "exclusion-slot", "exclusion-incarnation", "normal-state", "normal-union", "normal-intent", "normal-count", "grant-predecessor", "exclusion-predecessor", "grant-candidate", "exclusion-candidate", "grant-access", "exclusion-access", "grant-token", "exclusion-token", "grant-identity", "exclusion-identity"} {
		t.Run(name, func(t *testing.T) {
			bad := *permit
			normal, grant, exclusion := *permit.authority.normal, *permit.authority.grant, *permit.authority.exclusion
			grant.Rows, exclusion.Rows = slices.Clone(grant.Rows), slices.Clone(exclusion.Rows)
			grant.Rows[0].Recipients = slices.Clone(grant.Rows[0].Recipients)
			exclusion.Rows[0].Recipients = slices.Clone(exclusion.Rows[0].Recipients)
			bad.authority = lifecycleAuthority{normal: &normal, grant: &grant, exclusion: &exclusion}
			wrong := testID("wrong sharing authority")
			switch name {
			case "missing-normal":
				bad.authority.normal = nil
			case "missing-grant":
				bad.authority.grant = nil
			case "missing-exclusion":
				bad.authority.exclusion = nil
			case "empty-grant":
				grant.Rows = nil
			case "empty-exclusion":
				exclusion.Rows = nil
			case "excess-grant":
				grant.Rows = append(grant.Rows, grant.Rows[0])
			case "excess-exclusion":
				exclusion.Rows = append(exclusion.Rows, exclusion.Rows[0])
			case "grant-member":
				grant.Rows[0].EntryDigest = wrong
			case "grant-recipient":
				grant.Rows[0].Recipients[0] = wrong
			case "grant-incarnation":
				grant.Rows[0].Incarnation = wrong
			case "grant-slot":
				grant.Rows[0].Slot++
			case "grant-name":
				grant.Rows[0].Name = "other"
			case "exclusion-member":
				exclusion.Rows[0].EntryDigest = wrong
			case "exclusion-recipient":
				exclusion.Rows[0].Recipients[0] = wrong
			case "exclusion-path":
				exclusion.Rows[0].Path = wrong
			case "exclusion-name":
				exclusion.Rows[0].Name = "other"
			case "exclusion-slot":
				exclusion.Rows[0].Slot++
			case "exclusion-incarnation":
				exclusion.Rows[0].Incarnation = wrong
			case "normal-state":
				normal.Section.PublicState.Digest = wrong
			case "normal-union":
				normal.Section.Union.Digest = wrong
			case "normal-intent":
				normal.Section.Intent.Digest = wrong
			case "normal-count":
				normal.Section.Changed++
			case "grant-predecessor":
				grant.Context.PreviousDigest = wrong
			case "exclusion-predecessor":
				exclusion.Context.PreviousDigest = wrong
			case "grant-candidate":
				grant.Context.Snapshot = wrong
			case "exclusion-candidate":
				exclusion.Context.Snapshot = wrong
			case "grant-access":
				grant.Context.AfterAccessRoot = wrong
			case "exclusion-access":
				exclusion.Context.BeforeAccessRoot = wrong
			case "grant-token":
				grant.Context.PreviousToken.Value = "987654321"
			case "exclusion-token":
				exclusion.Context.PreviousToken.Value = "987654321"
			case "grant-identity":
				grant.Context.IdentityPlan.Digest = wrong
			case "exclusion-identity":
				exclusion.Context.IdentityPlan.Digest = wrong
			}
			beforeCalls := run.spy.scenarioEffects
			public, private := keys.Calls()
			candidate, result := f.session.Prepare(ctx, comparison, &bad, env.Trust)
			if candidate != nil || result != refused(AdmissionInvalid) || bad.used || f.session.prepared || beforeCalls != run.spy.scenarioEffects {
				t.Fatal("wrong membership authority crossed complete admission", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("wrong authority used private custody")
			}
		})
	}
	candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust)
	if candidate == nil || f.session.Select(ctx, candidate).Outcome != ObservedCurrent {
		t.Fatal("exact mixed authority refused", result)
	}
	selected, result := Open(ctx, f.admission, env.Store)
	if selected == nil || selected.head.Subject.Grant.Grants.Count != 1 || selected.head.Subject.Exclusion.Exclusions.Count != 1 || selected.head.Subject.Normal.Changed != 2 {
		t.Fatal("mixed grant and exclusion did not select completely", result)
	}
	for _, entry := range before.root.Names {
		assertRetainedValue(t, before.valueEntry(entry.Slot), selected.valueEntry(entry.Slot))
	}
}

// full_only: false
func TestOldSuppliedDeclarationRequiresNewGrantAuthority(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	authority := f.session.admission.recipient
	shared := []contract.ID{authority, fixtureID(env.Domain, "reader")}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	historical := f.session.currentEntryInputs()
	historical[0].Recipients = shared
	historical = append(historical, sharingSecret(t, env, "old shared declaration", shared))
	run.suppliedSelection(f, historical)
	excluded := slices.Clone(historical)
	excluded[0].Recipients = []contract.ID{authority}
	excluded[1] = sharingSecret(t, env, "excluded declaration", []contract.ID{authority})
	run.suppliedSelection(f, excluded)
	parent := admitSuppliedComparison(t, f.session, keys, historical)
	defer keys.RetireApply()
	comparison, result := f.session.Compare(ctx, historical, parent)
	if comparison == nil {
		t.Fatal(result)
	}
	permit := admit(t, f.session, comparison)
	if len(permit.authority.grant.Rows) != 2 || len(permit.plan.values) != 0 {
		t.Fatal("old declaration did not request new complete grant authority")
	}
	permit.authority.grant.Rows = nil
	before := run.spy.scenarioEffects
	if candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust); candidate != nil || result != refused(AdmissionInvalid) || run.spy.scenarioEffects != before {
		t.Fatal("old declaration regranted access without current grant authority", result)
	}
	opened, result := Open(ctx, f.admission, env.Store)
	if opened == nil || opened.root.Snapshot != f.session.root.Snapshot || opened.valueEntry(0).ConfidentialityClass != format.Plain || len(opened.valueEntry(0).Recipients) != 1 || len(opened.valueEntry(1).Recipients) != 1 {
		t.Fatal("refused old declaration changed current membership", result)
	}
}

// full_only: false
func TestPlainSharingRetainsValueWithoutPrivateCustody(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	authority := f.session.admission.recipient
	shared := []contract.ID{authority, fixtureID(env.Domain, "reader")}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	before := f.session.valueEntry(0)
	public, private := keys.Calls()
	for _, recipients := range [][]contract.ID{shared, {authority}} {
		input := f.session.currentEntryInputs()
		input[0].Recipients = recipients
		run.suppliedSelection(f, input)
		assertRetainedValue(t, before, f.session.valueEntry(0))
	}
	if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
		t.Fatal("plain membership used private custody")
	}
}

// full_only: false
func TestGrantRejectsChangedPreparedMaterialBeforeSelection(t *testing.T) {
	for _, name := range []string{"missing-row", "changed-value", "changed-origin", "changed-payload", "missing-authority-wrap", "missing-recovery-wrap", "changed-retained-wrap", "missing-granted-wrap"} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, nil, false)
			authority, reader := f.session.admission.recipient, fixtureID(env.Domain, "reader")
			run.suppliedSelection(f, []ApplyEntryInput{sharingSecret(t, env, "prepared initial", []contract.ID{authority})})
			shared := []contract.ID{authority, reader}
			slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			input := []ApplyEntryInput{sharingSecret(t, env, "prepared grant", shared)}
			parent := admitSuppliedComparison(t, f.session, keys, input)
			defer keys.RetireApply()
			changed := &changedCryptoReply{inner: parent.crypto, kind: contract.CryptoPrepare, change: func(reply contract.CryptoResponse) contract.CryptoResponse {
				prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
				if err != nil || len(prepared.Rows) != 1 {
					t.Fatal("prepared fixture", err)
				}
				row := &prepared.Rows[0]
				entry, err := contract.DecodeValueEntry(row.EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				access, err := contract.DecodeAccessRecord(row.AccessRecord)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "missing-row":
					prepared.Rows = nil
				case "changed-value":
					entry.ValueState = testID("changed value")
				case "changed-origin":
					entry.OriginSnapshot = testID("changed origin")
				case "changed-payload":
					entry.ValueBytes[len(entry.ValueBytes)-1] ^= 1
				case "missing-authority-wrap":
					access.Wraps = slices.DeleteFunc(access.Wraps, func(wrap contract.WrapRow) bool { return wrap.SubjectKind == 1 && wrap.SubjectID == authority })
				case "missing-recovery-wrap":
					access.Wraps = slices.DeleteFunc(access.Wraps, func(wrap contract.WrapRow) bool { return wrap.SubjectKind == 2 })
				case "missing-granted-wrap":
					access.Wraps = slices.DeleteFunc(access.Wraps, func(wrap contract.WrapRow) bool { return wrap.SubjectKind == 1 && wrap.SubjectID == reader })
				case "changed-retained-wrap":
					i := slices.IndexFunc(access.Wraps, func(wrap contract.WrapRow) bool { return wrap.SubjectKind == 1 && wrap.SubjectID == authority })
					access.Wraps[i].RSACiphertext[0] ^= 1
				}
				row.EntryBytes, err = contract.EncodeValueEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				row.AccessRecord, err = contract.EncodeAccessRecord(access)
				if err != nil {
					t.Fatal(err)
				}
				reply.Body, err = contract.EncodeCryptoPrepareResult(prepared)
				if err != nil {
					t.Fatal(err)
				}
				return reply
			}}
			parent.crypto = changed
			comparison, result := f.session.Compare(ctx, input, parent)
			if comparison == nil {
				t.Fatal(result)
			}
			plan, err := planTransition(t.Context(), comparison)
			if err != nil {
				t.Fatal("grant plan refused")
			}
			before := run.spy.scenarioEffects
			result = f.session.prepareCompared(ctx, comparison, plan)
			if result.Outcome == 0 {
				authority, err := f.session.lifecycleAuthority(t.Context(), comparison, plan)
				if err == nil {
					permit := &AdmittedParentTransition{session: f.session, comparison: comparison, predecessorDigest: contract.Hash(f.session.body), predecessorRevision: f.session.head.Core.Revision, predecessorToken: f.session.token, plan: plan, authority: authority}
					candidate, res := f.session.Prepare(ctx, comparison, permit, env.Trust)
					result = res
					if candidate != nil {
						t.Fatal("changed grant produced a candidate")
					}
				} else {
					result = refused(AdmissionInvalid)
				}
			}
			if result.Outcome != AdmissionRefused || changed.calls != 1 || run.spy.scenarioEffects != before {
				t.Fatal("changed grant crossed selection boundary", result)
			}
		})
	}
}
