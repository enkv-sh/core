package crypto

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

type retirementTestFixture struct {
	f      applyTestFixture
	slot   uint16
	plain  []contract.ValueEntry
	before []contract.MembershipRow
}

func retirementFixture(t *testing.T, base applyTestFixture, census string) retirementTestFixture {
	t.Helper()
	v := retirementTestFixture{f: cloneApplyFixture(t, base), slot: 43}
	f := &v.f
	i := slices.IndexFunc(f.current, func(row contract.RecipientRecord) bool { return row.RecipientID != f.control.AuthorityRecipientID })
	if i < 0 {
		t.Fatal("retirement fixture lacks ordinary recipient")
	}
	retired := f.current[i]
	row, err := contract.NewRecipientRetirementRow(v.slot, retired)
	if err != nil {
		t.Fatal(err)
	}
	f.q.Retirement = &row
	f.q.Recipients = slices.DeleteFunc(f.q.Recipients, func(row contract.ApplyRecipientInput) bool { return row.Recipient.RecipientID == retired.RecipientID })
	if census == "empty" || census == "plain-only" {
		f.q.Current, f.q.Intent = nil, nil
	}
	for at := range f.q.Current {
		entry, err := contract.DecodeValueEntry(f.q.Current[at].EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		affected := census == "secrets" || census == "mixed" && at == 0
		if !affected {
			entry.Recipients = slices.DeleteFunc(entry.Recipients, func(id contract.ID) bool { return id == retired.RecipientID })
			access, err := contract.DecodeAccessRecord(f.q.Current[at].AccessRecord)
			if err != nil {
				t.Fatal(err)
			}
			access.Wraps = slices.DeleteFunc(access.Wraps, func(w contract.WrapRow) bool {
				return w.SubjectKind == contract.OrdinaryWrapSubject && w.SubjectID == retired.RecipientID
			})
			f.q.Current[at].AccessRecord, err = contract.EncodeAccessRecord(access)
			if err != nil {
				t.Fatal(err)
			}
			// A private open of this unrelated row would fail authentication.
			entry.ValueBytes[len(entry.ValueBytes)-1] ^= 1
		}
		f.q.Current[at].EntryBytes, err = contract.EncodeValueEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		f.q.Intent[at].Recipients = slices.DeleteFunc(slices.Clone(entry.Recipients), func(id contract.ID) bool { return id == retired.RecipientID })
		f.q.Intent[at].PayloadDigest = contract.Hash(entry.ValueBytes)
	}
	if census == "plain-only" || census == "plain-with-secrets" || census == "mixed" {
		for at, name := range []string{"plain-affected", "plain-untouched"} {
			entry := contract.ValueEntry{Name: name, Incarnation: consumerID(name + " incarnation"), ValueState: consumerID(name + " material"), OriginSnapshot: consumerID(name + " origin snapshot"), OriginTransition: consumerID(name + " origin transition"), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.control.AuthorityRecipientID}, ValueBytes: []byte("unchanged public value"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("unchanged public value"))), RetainedLength: uint32(len([]byte("unchanged public value")))}
			if at == 0 {
				entry.Recipients = append(entry.Recipients, retired.RecipientID)
				slices.SortFunc(entry.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			}
			slot := uint16(at + 2)
			digest, err := contract.PublicValueEntryDigest(f.q.Context.DomainID, slot, entry)
			if err != nil {
				t.Fatal(err)
			}
			v.plain = append(v.plain, entry)
			v.before = append(v.before, contract.MembershipRow{Name: name, Slot: slot, Incarnation: entry.Incarnation, EntryDigest: digest, Recipients: slices.Clone(entry.Recipients)})
			input, err := contract.PlainInputDigest(entry.ValueBytes)
			if err != nil {
				t.Fatal(err)
			}
			f.q.Intent = append(f.q.Intent, contract.CryptoIntentRow{Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, ContentLength: uint32(len(entry.ValueBytes)), PayloadLength: uint32(len(entry.ValueBytes)), PayloadDigest: input, Recipients: slices.DeleteFunc(slices.Clone(entry.Recipients), func(id contract.ID) bool { return id == retired.RecipientID }), InputEncoding: contract.InputEncodingRaw, RetainedLength: uint32(len(entry.ValueBytes)), OutputEncoding: contract.OutputEncodingRaw})
		}
	}
	refreshRetirementIntent(t, f)
	return v
}

func refreshRetirementIntent(t *testing.T, f *applyTestFixture) {
	t.Helper()
	var err error
	f.q.Context.IntentDescriptor, err = contract.RecipientRetirementIntentDescriptor(f.q.Context.DomainID, f.q.Intent, f.q.Recipients, *f.q.Retirement)
	if err != nil {
		t.Fatal(err)
	}
}

func retirementOwner(t *testing.T, v *retirementTestFixture) (*Runtime, *ApplyCustody) {
	t.Helper()
	f := &v.f
	ctx, cancel := context.WithDeadline(t.Context(), f.deadline)
	t.Cleanup(cancel)
	f.ctx = ctx
	w := secretAccessWitness(t, f)
	r := newConsumerRuntime(t, f.route)
	owner, err := NewRecipientRetirementCustody(r, f.q, f.control, f.current, v.slot, f.route.CredentialRoute(), v.before, f.support, w, consumerID("retirement predecessor revision"), contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}, 0, f.deadline)
	if err != nil {
		t.Fatal("recipient retirement custody", err)
	}
	t.Cleanup(owner.Close)
	return r, owner
}

func retirementCompare(t *testing.T, r *Runtime, f applyTestFixture) contract.CryptoCompareResult {
	t.Helper()
	body, err := contract.EncodeCryptoCompareRequest(f.q)
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, f.ctx, contract.CryptoCompare, body)
	var expected []contract.CryptoComparisonRow
	for _, row := range f.q.Current {
		entry, err := contract.DecodeValueEntry(row.EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(entry.Recipients, f.q.Retirement.RecipientID) {
			continue
		}
		digest, err := contract.PublicValueEntryDigest(f.q.Context.DomainID, row.Slot, entry)
		if err != nil {
			t.Fatal(err)
		}
		at := slices.IndexFunc(f.q.Intent, func(intent contract.CryptoIntentRow) bool { return intent.Name == entry.Name })
		expected = append(expected, contract.CryptoComparisonRow{Name: entry.Name, BeforePresent: true, AfterPresent: true, Relation: contract.CryptoEqual, BeforePublicEntryDigest: digest, SourceDigest: contract.Hash(entry.ValueBytes), AfterRawLength: f.q.Intent[at].ContentLength})
	}
	var uses []contract.KeyUseRow
	if len(expected) != 0 {
		uses = []contract.KeyUseRow{independentKeyUseRow(f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)], contract.KeyUseMaterialOpen, contract.KeyUseCompleted, uint32(len(expected)))}
	}
	if reply.ResultCode != contract.CryptoSuccess || !slices.Equal(reply.KeyUseRows, uses) {
		t.Fatal("retirement compared the wrong private census", reply.ResultCode, reply.KeyUseRows, uses)
	}
	got, err := contract.DecodeCryptoCompareResult(reply.Body)
	if err != nil || len(got.Rows) != len(expected) {
		t.Fatal("retirement comparison omitted or added census rows", err)
	}
	for i, row := range got.Rows {
		path := row.ExclusionPathDigest
		row.ExclusionPathDigest = contract.ID{}
		if path.IsZero() || row != expected[i] {
			t.Fatal("retirement comparison lost exact current identity or truthful equality", row, expected[i])
		}
	}
	return got
}

func retirementPlan(t *testing.T, f applyTestFixture) contract.IdentityPlan {
	t.Helper()
	plan := contract.IdentityPlan{Operation: consumerID("retirement operation"), Transition: consumerID("retirement transition"), Snapshot: consumerID("retirement snapshot"), Revision: consumerID("retirement revision"), Pages: []contract.IdentityPage{{Kind: contract.RecipientKind, Index: 0, Object: consumerID("retirement recipient page")}}}
	for _, row := range f.q.Current {
		entry, err := contract.DecodeValueEntry(row.EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(entry.Recipients, f.q.Retirement.RecipientID) {
			plan.Rows = append(plan.Rows, contract.IdentityRow{Name: entry.Name, Slot: row.Slot, Incarnation: entry.Incarnation, ValueState: consumerID("retirement fresh " + entry.Name), OriginSnapshot: plan.Snapshot, OriginTransition: plan.Transition})
		}
	}
	if len(plan.Rows) != 0 {
		plan.Pages = append(plan.Pages, contract.IdentityPage{Kind: contract.AccessKind, Index: 0, Object: consumerID("retirement access page")})
	}
	slices.SortFunc(plan.Pages, func(a, b contract.IdentityPage) int { return int(a.Kind) - int(b.Kind) })
	return plan
}

func retirementPrepare(t *testing.T, r *Runtime, f applyTestFixture, comparison contract.CryptoCompareResult, plan contract.IdentityPlan) contract.CryptoPrepareResult {
	t.Helper()
	identity, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: f.q.Context, IdentityPlan: identity})
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, f.ctx, contract.CryptoPrepare, body)
	var expected []contract.KeyUseRow
	if len(plan.Rows) != 0 {
		expected = append(expected, independentKeyUseRow(f.q.Bindings[applyBindingIndex(f.q.Bindings, f.control.AuthorityRecipientID)], contract.KeyUseMaterialOpen, contract.KeyUseCompleted, uint32(len(plan.Rows))))
		for _, binding := range f.q.Bindings {
			if binding.SubjectID != f.q.Retirement.RecipientID {
				expected = append(expected, independentKeyUseRow(binding, contract.KeyUseMaterialWrap, contract.KeyUseCompleted, uint32(len(plan.Rows))))
			}
		}
	}
	if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != len(expected) {
		t.Fatal("retirement preparation key-use facts differ", reply.ResultCode, reply.KeyUseRows)
	}
	for _, row := range expected {
		if !slices.Contains(reply.KeyUseRows, row) {
			t.Fatal("retirement preparation omitted exact Authority or public wrap use", row)
		}
	}
	prepared, err := contract.DecodeCryptoPrepareResult(reply.Body)
	if err != nil || len(prepared.Rows) != len(plan.Rows) {
		t.Fatal("retirement prepared the wrong current subset", err)
	}
	return prepared
}

func retirementFreeze(t *testing.T, v retirementTestFixture, a *applyAdmission, comparison contract.CryptoCompareResult, plan contract.IdentityPlan, prepared contract.CryptoPrepareResult) contract.CryptoFreezeRequest {
	t.Helper()
	f := v.f
	var plain []contract.PublicStateRow
	var exclusions []contract.ExclusionRow
	for i, before := range v.before {
		after := v.plain[i]
		after.Recipients = slices.DeleteFunc(slices.Clone(after.Recipients), func(id contract.ID) bool { return id == f.q.Retirement.RecipientID })
		digest, err := contract.PublicValueEntryDigest(f.q.Context.DomainID, before.Slot, after)
		if err != nil {
			t.Fatal(err)
		}
		plain = append(plain, contract.PublicStateRow{Name: before.Name, Slot: before.Slot, EntryDigest: digest})
		if !slices.Contains(before.Recipients, f.q.Retirement.RecipientID) {
			continue
		}
		removed := []contract.ID{f.q.Retirement.RecipientID}
		path, err := contract.PlainExclusionDigest(contract.PlainExclusionPath{Domain: f.q.Context.DomainID, Name: before.Name, Slot: before.Slot, Incarnation: before.Incarnation, EntryDigest: before.EntryDigest, RemovedRecipients: removed})
		if err != nil {
			t.Fatal(err)
		}
		exclusions = append(exclusions, contract.ExclusionRow{MembershipRow: contract.MembershipRow{Name: before.Name, Slot: before.Slot, Incarnation: before.Incarnation, EntryDigest: before.EntryDigest, Recipients: removed}, Path: path})
	}
	for _, row := range comparison.Rows {
		at := slices.IndexFunc(f.q.Current, func(current contract.CryptoCurrentSecret) bool {
			entry, err := contract.InspectValueEntry(current.EntryBytes)
			return err == nil && string(entry.Name) == row.Name
		})
		entry, err := contract.DecodeValueEntry(f.q.Current[at].EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		exclusions = append(exclusions, contract.ExclusionRow{MembershipRow: contract.MembershipRow{Name: row.Name, Slot: f.q.Current[at].Slot, Incarnation: entry.Incarnation, EntryDigest: row.BeforePublicEntryDigest, Recipients: []contract.ID{f.q.Retirement.RecipientID}}, Path: row.ExclusionPathDigest})
	}
	slices.SortFunc(exclusions, func(a, b contract.ExclusionRow) int { return strings.Compare(a.Name, b.Name) })
	return accessMutationFreeze(t, f, a, comparison, plan, prepared, plain, exclusions)
}

// full_only: false
func TestRecipientRetirementCensusControlsPrivateWork(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, census := range []string{"empty", "unassigned", "plain-only", "plain-with-secrets", "mixed", "secrets"} {
		t.Run(census, func(t *testing.T) {
			v := retirementFixture(t, base, census)
			r, owner := retirementOwner(t, &v)
			comparison := retirementCompare(t, r, v.f)
			plan := retirementPlan(t, v.f)
			prepared := retirementPrepare(t, r, v.f, comparison, plan)
			for i, row := range prepared.Rows {
				entry, err := contract.DecodeValueEntry(row.EntryBytes)
				if err != nil || entry.Incarnation != plan.Rows[i].Incarnation || entry.ValueState != plan.Rows[i].ValueState || entry.OriginSnapshot != plan.Snapshot || entry.OriginTransition != plan.Transition || slices.Contains(entry.Recipients, v.f.q.Retirement.RecipientID) {
					t.Fatal("retirement refreshed wrong identity or kept retired membership", err)
				}
			}
			freeze := retirementFreeze(t, v, r.apply, comparison, plan, prepared)
			row := receiptHistoryRow(v.f.q.Context.DomainID, "retirement selected", true)
			row.OperationKind, row.EffectSummary = contract.OperationRetireRecipientIdentity, contract.ReceiptEffectNotApplicable
			row.OperationID, row.PredecessorRevisionID = plan.Operation, owner.predecessorRevision
			row.RequestedRevisionID, row.ObservedRevisionID, row.ChangedSubjects = plan.Revision, plan.Revision, retirementExpectedSubjects(t, v, plan)
			receipt, freeze := retirementReceiptAdmission(t, v, owner, comparison, freeze, row, nil)
			if err := owner.BindReceipt(v.f.ctx, receipt); err != nil {
				t.Fatal("bind census receipt", err)
			}
			body, err := contract.EncodeCryptoFreezeRequest(freeze)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, v.f.ctx, contract.CryptoFreeze, body)
			if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 0 || v.f.route.privateCalls != 2*len(comparison.Rows) {
				t.Fatal("retirement failed or opened material outside its exact census", reply.ResultCode, v.f.route.privateCalls)
			}
		})
	}
}

// full_only: false
func TestRecipientRetirementAdmissionPinsPhysicalSlotAndOldRecord(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"slot", "parent-slot", "id", "digest", "length", "current-display", "current-binding", "missing-binding", "authority", "ordinary-factory", "secret-factory"} {
		t.Run(damage, func(t *testing.T) {
			v := retirementFixture(t, base, "mixed")
			f := &v.f
			w := secretAccessWitness(t, f)
			old := slices.IndexFunc(f.current, func(row contract.RecipientRecord) bool { return row.RecipientID == f.q.Retirement.RecipientID })
			switch damage {
			case "slot":
				f.q.Retirement.Slot++
			case "parent-slot":
				v.slot = uint16(old)
			case "id":
				f.q.Retirement.RecipientID = consumerID("absent retired recipient")
			case "digest":
				f.q.Retirement.BeforeRecordDigest[0] ^= 1
			case "length":
				f.q.Retirement.BeforeRecordLength++
			case "current-display":
				f.current[old].DisplayName += " changed"
			case "current-binding":
				f.current[old].CurrentBinding.BindingSerial++
			case "missing-binding":
				f.q.Bindings = slices.DeleteFunc(f.q.Bindings, func(row contract.BindingTableRow) bool { return row.SubjectID == f.q.Retirement.RecipientID })
			case "authority":
				at := slices.IndexFunc(f.current, func(row contract.RecipientRecord) bool { return row.RecipientID == f.control.AuthorityRecipientID })
				row, err := contract.NewRecipientRetirementRow(v.slot, f.current[at])
				if err != nil {
					t.Fatal(err)
				}
				f.q.Retirement = &row
			}
			refreshRetirementIntent(t, f)
			f.route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
				t.Fatal("retirement used a private key before exact old-row admission")
				return PrivateResult{}
			}
			r := newConsumerRuntime(t, f.route)
			before := contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}
			var owner *ApplyCustody
			var err error
			switch damage {
			case "ordinary-factory":
				owner, err = NewApplyCustody(r, f.q, f.control, f.current, nil, f.route.CredentialRoute(), consumerID("file"), v.before, f.support, w, consumerID("revision"), before, 0, f.deadline)
			case "secret-factory":
				owner, err = NewEnvelopeRekeyCustody(r, f.q, f.control, f.current, f.route.CredentialRoute(), v.before, f.support, w, consumerID("revision"), before, 0, f.deadline)
			default:
				owner, err = NewRecipientRetirementCustody(r, f.q, f.control, f.current, v.slot, f.route.CredentialRoute(), v.before, f.support, w, consumerID("revision"), before, 0, f.deadline)
			}
			if err != ErrAdmission || owner != nil || r.apply != nil || f.route.privateCalls != 0 {
				t.Fatal("invalid retirement target, physical slot or binding was admitted", err)
			}
		})
	}
}

// full_only: false
func TestRecipientRetirementAdmissionRequiresCompleteCensus(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"secret-membership", "plain-membership", "unrelated-membership", "secret-input", "missing-intent", "display", "proof", "secret-access"} {
		t.Run(damage, func(t *testing.T) {
			v := retirementFixture(t, base, "mixed")
			f := &v.f
			w := secretAccessWitness(t, f)
			retired := f.q.Retirement.RecipientID
			switch damage {
			case "secret-membership", "plain-membership", "unrelated-membership":
				at := 0
				switch damage {
				case "plain-membership":
					at = 2
				case "unrelated-membership":
					at = 1
				}
				f.q.Intent[at].Recipients = append(f.q.Intent[at].Recipients, retired)
				slices.SortFunc(f.q.Intent[at].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			case "secret-input":
				f.q.Intent[1].PayloadDigest[0] ^= 1
			case "missing-intent":
				f.q.Intent = f.q.Intent[:len(f.q.Intent)-1]
			case "display":
				f.q.Recipients[0].Recipient.DisplayName += " changed"
			case "proof":
				f.q.Recipients[0].Creation = &contract.RecipientCreationProof{Snapshot: consumerID("proof snapshot"), Nonce: consumerID("proof nonce")}
			case "secret-access":
				f.q.SecretAccess = &contract.CryptoSecretAccessIntent{OperationKind: contract.OperationEnvelopeRekey}
			}
			if damage != "proof" {
				refreshRetirementIntent(t, f)
			}
			r := newConsumerRuntime(t, f.route)
			owner, err := NewRecipientRetirementCustody(r, f.q, f.control, f.current, v.slot, f.route.CredentialRoute(), v.before, f.support, w, consumerID("revision"), contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}, 0, f.deadline)
			if err != ErrAdmission || owner != nil || r.apply != nil || f.route.privateCalls != 0 {
				t.Fatal("retirement omitted census rows or changed unrelated input", err)
			}
		})
	}
}

// full_only: false
func TestRecipientRetirementScopeIsOwnedAtPrivateBoundary(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"owned", "exchange", "private-open"} {
		t.Run(damage, func(t *testing.T) {
			v := retirementFixture(t, base, "mixed")
			r, _ := retirementOwner(t, &v)
			if damage == "private-open" {
				current, ok := r.apply.current(r.apply.request.Current[1])
				if !ok {
					t.Fatal("unrelated current row is invalid")
				}
				reply := contract.CryptoResponse{Kind: contract.CryptoCompare}
				keys, code := r.apply.openCurrent(v.f.ctx, v.f.route, current, &reply)
				if code != contract.CryptoInvalidAdmission || keys != nil || len(reply.KeyUseRows) != 0 || v.f.route.privateCalls != 0 {
					t.Fatal("retirement private consuming boundary accepted unrelated material", code)
				}
				return
			}
			original := *r.apply.request.Retirement
			v.f.q.Retirement.BeforeRecordDigest[0] ^= 1
			if *r.apply.request.Retirement != original {
				t.Fatal("caller mutation changed admitted retirement row")
			}
			if damage == "owned" {
				v.f.q.Retirement = &original
				retirementCompare(t, r, v.f)
				return
			}
			refreshRetirementIntent(t, &v.f)
			body, err := contract.EncodeCryptoCompareRequest(v.f.q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, v.f.ctx, contract.CryptoCompare, body)
			if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.KeyUseRows) != 0 || v.f.route.privateCalls != 0 {
				t.Fatal("Compare substituted a different typed retirement row", reply.ResultCode)
			}
		})
	}
}

// full_only: false
func TestRecipientRetirementPreparationRequiresExactlyAffectedSecrets(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"missing", "unrelated-secret", "plain", "old-material", "old-incarnation"} {
		t.Run(damage, func(t *testing.T) {
			v := retirementFixture(t, base, "mixed")
			r, _ := retirementOwner(t, &v)
			comparison := retirementCompare(t, r, v.f)
			plan := retirementPlan(t, v.f)
			switch damage {
			case "missing":
				plan.Rows = nil
			case "unrelated-secret":
				entry, err := contract.DecodeValueEntry(v.f.q.Current[1].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				plan.Rows = append(plan.Rows, contract.IdentityRow{Name: entry.Name, Slot: v.f.q.Current[1].Slot, Incarnation: entry.Incarnation, ValueState: consumerID("unrelated replacement"), OriginSnapshot: plan.Snapshot, OriginTransition: plan.Transition})
			case "plain":
				row := v.before[0]
				plan.Rows = append(plan.Rows, contract.IdentityRow{Name: row.Name, Slot: row.Slot, Incarnation: row.Incarnation, ValueState: consumerID("plain replacement"), OriginSnapshot: plan.Snapshot, OriginTransition: plan.Transition})
			case "old-material":
				entry, err := contract.DecodeValueEntry(v.f.q.Current[0].EntryBytes)
				if err != nil {
					t.Fatal(err)
				}
				plan.Rows[0].ValueState = entry.ValueState
			case "old-incarnation":
				plan.Rows[0].Incarnation = consumerID("unrelated old incarnation")
			}
			identity, err := contract.EncodeIdentityPlan(plan)
			if err != nil {
				t.Fatal("retirement plan mutation is not structurally valid", err)
			}
			body, err := contract.EncodeCryptoPrepareRequest(contract.CryptoPrepareRequest{OperationRef: comparison.OperationRef, Context: v.f.q.Context, IdentityPlan: identity})
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, v.f.ctx, contract.CryptoPrepare, body)
			if reply.ResultCode != contract.CryptoInvalidInput || len(reply.KeyUseRows) != 0 || v.f.route.privateCalls != 1 {
				t.Fatal("invalid retirement refresh set reached private preparation", reply.ResultCode)
			}
		})
	}
}

// full_only: false
func TestRecipientRetirementFreezePinsCensusAndUntouchedState(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, damage := range []string{"unrelated-secret", "unrelated-plain", "unchanged-affected-plain", "registry", "missing-exclusion", "context"} {
		t.Run(damage, func(t *testing.T) {
			v := retirementFixture(t, base, "mixed")
			r, owner := retirementOwner(t, &v)
			comparison := retirementCompare(t, r, v.f)
			plan := retirementPlan(t, v.f)
			prepared := retirementPrepare(t, r, v.f, comparison, plan)
			q := retirementFreeze(t, v, r.apply, comparison, plan, prepared)
			view, err := contract.InspectPublicState(q.CandidatePublicState, v.f.q.Context.DomainID)
			if err != nil {
				t.Fatal(err)
			}
			public, err := view.Own()
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "unrelated-secret":
				public.Rows[1].EntryDigest[0] ^= 1
			case "unrelated-plain":
				public.Rows[3].EntryDigest[0] ^= 1
			case "unchanged-affected-plain":
				public.Rows[2].EntryDigest = v.before[0].EntryDigest
			case "registry":
				q.Recipients = cloneApplyRecipients(t, v.f.current)
			case "missing-exclusion":
				rows, err := contract.DecodeExclusions(q.Exclusions, v.f.q.Context.DomainID)
				if err != nil {
					t.Fatal(err)
				}
				q.Exclusions, err = contract.EncodeExclusions(v.f.q.Context.DomainID, rows[:1])
				if err != nil {
					t.Fatal(err)
				}
			case "context":
				q.Context.IntentDescriptor.Digest[0] ^= 1
			}
			q.CandidatePublicState, err = contract.EncodePublicState(public)
			if err != nil {
				t.Fatal(err)
			}
			row := receiptHistoryRow(v.f.q.Context.DomainID, "retirement selected", true)
			row.OperationKind, row.EffectSummary = contract.OperationRetireRecipientIdentity, contract.ReceiptEffectNotApplicable
			row.OperationID, row.PredecessorRevisionID = plan.Operation, owner.predecessorRevision
			row.RequestedRevisionID, row.ObservedRevisionID, row.ChangedSubjects = plan.Revision, plan.Revision, retirementExpectedSubjects(t, v, plan)
			receipt, q := retirementReceiptAdmission(t, v, owner, comparison, q, row, nil)
			if err := owner.BindReceipt(v.f.ctx, receipt); err != nil {
				t.Fatal("exact receipt for candidate under test", err)
			}
			body, err := contract.EncodeCryptoFreezeRequest(q)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, v.f.ctx, contract.CryptoFreeze, body)
			if reply.ResultCode == contract.CryptoSuccess || len(reply.KeyUseRows) != 0 || v.f.route.privateCalls != 2 {
				t.Fatal("retirement freeze admitted incomplete census or unrelated state", reply.ResultCode)
			}
		})
	}
}

func retirementExpectedSubjects(t *testing.T, v retirementTestFixture, plan contract.IdentityPlan) contract.GeneratorDescriptor {
	t.Helper()
	f := v.f
	retired := f.q.Retirement.RecipientID
	var rows []contract.ChangedSubjectIdentity
	add := func(kind, change uint8, primary, secondary contract.ID) {
		t.Helper()
		id, err := contract.ChangedSubjectIdentityID(f.q.Context.DomainID, kind, primary, secondary)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.ChangedSubjectIdentity{Kind: kind, Change: change, Identity: id})
	}
	add(contract.ChangedSubjectRecipient, contract.ChangedSubjectRemoved, retired, contract.ID{})
	var members []contract.MembershipRow
	members = append(members, v.before...)
	for _, row := range f.q.Current {
		entry, err := contract.DecodeValueEntry(row.EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, contract.MembershipRow{Incarnation: entry.Incarnation, Recipients: entry.Recipients})
		if entry.ValueSource == contract.Generated && slices.Contains(entry.Recipients, retired) {
			at := slices.IndexFunc(plan.Rows, func(row contract.IdentityRow) bool { return row.Name == entry.Name })
			if at < 0 {
				t.Fatal("generated retirement target has no fresh identity row")
			}
			add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectRemoved, entry.Generated.GenerationID, contract.ID{})
			add(contract.ChangedSubjectGeneratedValue, contract.ChangedSubjectAdded, plan.Rows[at].ValueState, contract.ID{})
		}
	}
	for _, row := range members {
		if slices.Contains(row.Recipients, retired) {
			add(contract.ChangedSubjectValueEntry, contract.ChangedSubjectUpdated, row.Incarnation, contract.ID{})
			add(contract.ChangedSubjectMembership, contract.ChangedSubjectRemoved, row.Incarnation, retired)
		}
	}
	descriptor, err := contract.ChangedSubjectDescriptor(rows)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func retirementReceiptAdmission(t *testing.T, v retirementTestFixture, owner *ApplyCustody, comparison contract.CryptoCompareResult, freeze contract.CryptoFreezeRequest, row contract.CompactMutationReceipt, retained []contract.SupportRecord) (contract.CryptoApplyReceiptAdmission, contract.CryptoFreezeRequest) {
	t.Helper()
	after, err := contract.AppendMutationReceipt(owner.before, row)
	if err != nil {
		t.Fatal(err)
	}
	records, err := after.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	records = append(records, installedReceiptIndexRecord(t, after))
	records = append(records, retained...)
	slices.SortFunc(records, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	support, err := contract.RequiredSupportDescriptor(v.f.q.Context.DomainID, records)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectPublicState(freeze.CandidatePublicState, v.f.q.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	public.RequiredSupport = support
	freeze.CandidatePublicState, err = contract.EncodePublicState(public)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := contract.PublicStateDescriptor(public)
	if err != nil {
		t.Fatal(err)
	}
	var duties, hazards []contract.SupportRecord
	for _, row := range retained {
		switch row.Kind {
		case contract.GeneratedDutySupportKind:
			duties = append(duties, row)
		case contract.GeneratedHazardSupportKind:
			hazards = append(hazards, row)
		}
	}
	liveDuties, err := contract.MutationResultRecordDescriptor(contract.MutationResultDuties, v.f.q.Context.DomainID, duties)
	if err != nil {
		t.Fatal(err)
	}
	liveHazards, err := contract.MutationResultRecordDescriptor(contract.MutationResultHazards, v.f.q.Context.DomainID, hazards)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.CryptoApplyReceiptAdmission{OperationKind: row.OperationKind, ChangedSubjects: row.ChangedSubjects, LiveDuties: liveDuties, LiveHazards: liveHazards, Context: v.f.q.Context, OperationRef: comparison.OperationRef, IdentityPlanDescriptor: freeze.IdentityPlanDescriptor,
		Delta: contract.MutationReceiptDelta{DomainID: v.f.q.Context.DomainID, OperationKind: row.OperationKind, AddedCount: 1, Before: owner.before, After: after}, AfterSupport: support, CandidatePublicState: candidate}
	return q, freeze
}

// full_only: false
func TestRecipientRetirementReceiptBindsCompleteSubjects(t *testing.T) {
	base := exactRetainedFixture(t)
	for _, census := range []string{"empty", "plain-with-secrets", "mixed"} {
		for _, damage := range []string{"exact", "kind", "subjects", "effects"} {
			t.Run(fmt.Sprintf("%s/%s", census, damage), func(t *testing.T) {
				v := retirementFixture(t, base, census)
				r, owner := retirementOwner(t, &v)
				comparison := retirementCompare(t, r, v.f)
				plan := retirementPlan(t, v.f)
				prepared := retirementPrepare(t, r, v.f, comparison, plan)
				freeze := retirementFreeze(t, v, r.apply, comparison, plan, prepared)
				row := receiptHistoryRow(v.f.q.Context.DomainID, "retirement selected", true)
				row.OperationKind, row.EffectSummary = contract.OperationRetireRecipientIdentity, contract.ReceiptEffectNotApplicable
				row.OperationID, row.PredecessorRevisionID = plan.Operation, owner.predecessorRevision
				row.RequestedRevisionID, row.ObservedRevisionID, row.ChangedSubjects = plan.Revision, plan.Revision, retirementExpectedSubjects(t, v, plan)
				switch damage {
				case "kind":
					row.OperationKind = contract.OperationApplyDeclaration
				case "subjects":
					row.ChangedSubjects.Digest[0] ^= 1
				case "effects":
					row.EffectSummary = contract.ReceiptEffectNoChange
				}
				q, freeze := retirementReceiptAdmission(t, v, owner, comparison, freeze, row, nil)
				if err := owner.BindReceipt(v.f.ctx, q); (err == nil) != (damage == "exact") {
					t.Fatal("retirement receipt did not pin kind, removed identity and complete census subjects", damage, err)
				}
				if damage != "exact" {
					return
				}
				body, err := contract.EncodeCryptoFreezeRequest(freeze)
				if err != nil {
					t.Fatal(err)
				}
				if reply := applyCall(r, v.f.ctx, contract.CryptoFreeze, body); reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 0 {
					t.Fatal("exact retirement receipt did not bind frozen candidate", reply.ResultCode)
				}
			})
		}
	}
}

// full_only: false
func TestRecipientRetirementGeneratedRefreshPreservesResourceAndReplacesSubjects(t *testing.T) {
	v := retirementFixture(t, exactRetainedFixture(t), "mixed")
	before := generatedRefreshFixture(t, &v.f)
	refreshRetirementIntent(t, &v.f)
	a := &applyAdmission{request: v.f.q, control: v.f.control, operationKind: contract.OperationRetireRecipientIdentity, registryChanged: recipientRetirementAdmission(v.f.q, v.f.current, v.slot, v.f.control), authorityIndex: applyBindingIndex(v.f.q.Bindings, v.f.control.AuthorityRecipientID), routeID: v.f.route.CredentialRoute(), plainBefore: v.before, supportTransition: &contract.GeneratedSupportTransition{}}
	if !a.registryChanged {
		t.Fatal("generated retirement registry removal was not admitted")
	}
	if !a.recipientRetirementCensus() {
		t.Fatal("generated retirement census refused exact current material")
	}
	// Complete generated support admission is exercised by installed Core
	// tests. This check starts at the private comparison/refresh mechanism.
	reply := contract.CryptoResponse{Kind: contract.CryptoCompare}
	if code := a.compare(t.Context(), v.f.route, &reply); code != contract.CryptoSuccess || len(a.comparison) != 1 || a.comparison[0].Relation != contract.CryptoEqual || a.comparison[0].ExclusionPathDigest.IsZero() {
		t.Fatal("generated retirement comparison lost equality or exact reader loss", code)
	}
	plan := retirementPlan(t, v.f)
	identity, err := contract.EncodeIdentityPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	reply = contract.CryptoResponse{Kind: contract.CryptoPrepare}
	if code := a.prepare(t.Context(), v.f.route, contract.CryptoPrepareRequest{IdentityPlan: identity}, &reply); code != contract.CryptoSuccess || len(a.prepared) != 1 {
		t.Fatal("generated retirement did not refresh its exact affected secret", code)
	}
	after, err := contract.DecodeValueEntry(a.prepared[0].EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	expected := before.Generated
	expected.GenerationID = plan.Rows[0].ValueState
	if after.Generated != expected || after.ValueSource != contract.Generated || after.Incarnation != before.Incarnation || after.ValueState != expected.GenerationID || slices.Contains(after.Recipients, v.f.q.Retirement.RecipientID) || v.f.route.privateCalls != 2 {
		t.Fatal("generated retirement changed resource/evidence or unrelated private work")
	}
	want := retirementExpectedSubjects(t, v, plan)
	got, err := a.recipientRetirementSubjects()
	if err != nil || got != want {
		t.Fatal("generated retirement subjects did not replace exact old/new generation identities", err)
	}
}

// full_only: false
func TestRecipientRetirementPreservesInheritedWorkAndReceiptFacts(t *testing.T) {
	base := exactRetainedFixture(t)
	duty, _ := generatedCanonicalFixture(t, uint8(contract.GeneratedDutySupportKind))
	hazard, _ := generatedCanonicalFixture(t, uint8(contract.GeneratedHazardSupportKind))
	for _, damage := range []string{"exact", "same-count-duty", "same-count-hazard", "lost-possible-live"} {
		t.Run(damage, func(t *testing.T) {
			v := retirementFixture(t, base, "empty")
			f := &v.f
			ctx, cancel := context.WithDeadline(t.Context(), f.deadline)
			t.Cleanup(cancel)
			f.ctx = ctx
			w := secretAccessWitness(t, f)
			retained := []contract.SupportRecord{duty.Owner, hazard.Owner}
			w.Records = slices.Clone(retained)
			for _, row := range retained {
				fact, err := contract.InspectSupportRecordDigest(f.q.Context.DomainID, row)
				if err != nil {
					t.Fatal(err)
				}
				w.RecordFacts = append(w.RecordFacts, fact)
			}
			var err error
			f.support, err = contract.RequiredSupportDescriptor(f.q.Context.DomainID, retained)
			if err != nil {
				t.Fatal(err)
			}
			w.BeforeSupport = f.support
			r := newConsumerRuntime(t, f.route)
			owner, err := NewRecipientRetirementCustody(r, f.q, f.control, f.current, v.slot, f.route.CredentialRoute(), nil, f.support, w, consumerID("retirement predecessor revision"), contract.MutationReceiptWindows{DomainID: f.q.Context.DomainID}, 0, f.deadline)
			if err != nil {
				t.Fatal("retirement inherited work custody", err)
			}
			t.Cleanup(owner.Close)
			comparison := retirementCompare(t, r, *f)
			plan := retirementPlan(t, *f)
			prepared := retirementPrepare(t, r, *f, comparison, plan)
			freeze := retirementFreeze(t, v, r.apply, comparison, plan, prepared)
			after, err := r.apply.supportTransition.SupportAfter(plan, f.q.Intent)
			if err != nil || len(after.Records) != len(retained) {
				t.Fatal("retirement changed inherited support closure", err)
			}
			for i, row := range after.Records {
				if row.Kind != retained[i].Kind || row.RecordID != retained[i].RecordID || !bytes.Equal(row.Body, retained[i].Body) {
					t.Fatal("retirement changed original inherited support bytes")
				}
			}
			row := receiptHistoryRow(f.q.Context.DomainID, "retirement inherited work", true)
			row.OperationKind, row.EffectSummary = contract.OperationRetireRecipientIdentity, contract.ReceiptEffectNotApplicable
			row.OperationID, row.PredecessorRevisionID = plan.Operation, owner.predecessorRevision
			row.RequestedRevisionID, row.ObservedRevisionID, row.ChangedSubjects = plan.Revision, plan.Revision, retirementExpectedSubjects(t, v, plan)
			row.SummaryCounts[contract.ReceiptDutyCount], row.SummaryCounts[contract.ReceiptHazardCount] = 1, 1
			row.WarningBits = contract.ReceiptWarningPossibleLive
			q, freeze := retirementReceiptAdmission(t, v, owner, comparison, freeze, row, retained)
			switch damage {
			case "same-count-duty":
				q.LiveDuties.Digest[0] ^= 1
			case "same-count-hazard":
				q.LiveHazards.Digest[0] ^= 1
			case "lost-possible-live":
				q.Delta.After.Successes[0].WarningBits = 0
			}
			if err := owner.BindReceipt(f.ctx, q); (err == nil) != (damage == "exact") {
				t.Fatal("retirement inherited work receipt lost exact Success facts", damage, err)
			}
			if damage != "exact" {
				return
			}
			body, err := contract.EncodeCryptoFreezeRequest(freeze)
			if err != nil {
				t.Fatal(err)
			}
			if reply := applyCall(r, f.ctx, contract.CryptoFreeze, body); reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 0 || f.route.privateCalls != 0 {
				t.Fatal("retirement inherited work changed freeze or used private material", reply.ResultCode)
			}
		})
	}
}
