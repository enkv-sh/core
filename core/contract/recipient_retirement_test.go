package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"
)

func recipientRetirementFixture(t testing.TB) (ID, []CryptoIntentRow, []ApplyRecipientInput, RecipientRetirementRow) {
	t.Helper()
	domain, values, recipients := completeApplyFixture(t)
	row, err := NewRecipientRetirementRow(34, recipients[0].Recipient)
	if err != nil {
		t.Fatal(err)
	}
	recipients[0].Recipient.RecipientID = completeApplyID(20)
	recipients[0].Creation = nil
	values[0].Recipients = []ID{completeApplyID(20)}
	return domain, values, recipients, row
}

// full_only: false
func TestRecipientRetirementProjectionIndependentCanonicalBytes(t *testing.T) {
	domain, _, _, row := recipientRetirementFixture(t)
	// Python struct big-endian fields and direct RSA SPKI DER independently
	// give the old record length577 and SHA-256 below. Slot34 is page4/row2.
	if row.BeforeRecordLength != 577 || hex.EncodeToString(row.BeforeRecordDigest[:]) != "80b96dc22598b35fb15385243d4a4265fe9fb65813be3adc4fc39d5accb0f48f" {
		t.Fatal("retirement does not hash the exact old canonical record", row)
	}
	want, err := hex.DecodeString("454e4b562f43525950544f2f76322f7265746972656d656e74732d7636000101010101010101010101010101010101010101010101010101010101010101000000010022020202020202020202020202020202020202020202020202020202020202020280b96dc22598b35fb15385243d4a4265fe9fb65813be3adc4fc39d5accb0f48f00000241")
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeRetirements(domain, []RecipientRetirementRow{row})
	if err != nil || len(body) != 136 || !bytes.Equal(body, want) {
		t.Fatal("retirement projection differs from independent literal", err)
	}
	descriptor, err := RetirementDescriptor(domain, []RecipientRetirementRow{row})
	if err != nil || descriptor.Count != 1 || descriptor.Length != 136 || hex.EncodeToString(descriptor.Digest[:]) != "c58acc58d119dc2c3b0a279431005f2a1ebcb3476b28417a00ac434186de9051" {
		t.Fatal("retirement projection descriptor differs", descriptor, err)
	}
	inspected, err := InspectRetirements(body, domain)
	if err != nil || inspected != descriptor {
		t.Fatal("retirement scanner and producer disagree", err)
	}
	prefixed := []byte{1, 2}
	appended, err := AppendRetirements(prefixed, domain, []RecipientRetirementRow{row})
	if err != nil || !bytes.Equal(appended[2:], want) {
		t.Fatal("retirement append differs", err)
	}
	parsed, n, err := ParseRetirements(append(bytes.Clone(body), 7), domain)
	if err != nil || n != 136 || parsed != descriptor {
		t.Fatal("retirement parser does not consume exactly one projection", err)
	}
	if _, err := InspectRetirements(append(bytes.Clone(body), 7), domain); err == nil {
		t.Fatal("retirement inspector accepts trailing input")
	}
	empty, err := EncodeRetirements(domain, nil)
	if err != nil || len(empty) != 66 {
		t.Fatal("empty retirement encoding changed", err)
	}
	d, err := RetirementDescriptor(domain, nil)
	if err != nil || d.Count != 0 || d.Length != 66 || hex.EncodeToString(d.Digest[:]) != "602fec1741994a171a4cbbb9e7ceda66af33ff6b223c671b94943d01bcb0881b" || d.Digest != Hash(empty) {
		t.Fatal("empty retirement descriptor changed", err)
	}
}

// full_only: false
func TestLifecycleRecipientRetirementAllowsEmptyAndPlainCensus(t *testing.T) {
	for _, condition := range []string{"empty image", "unassigned", "plain memberships", "secret memberships"} {
		s := lifecycleFixture()
		s.OperationKind = OperationRetireRecipientIdentity
		s.Exclusion.Retirements.Count, s.Exclusion.Retirements.Length = 1, 136
		s.Normal.Intent.Length = 1002
		s.Normal.Changed, s.IdentityPlan.Length = 0, 197
		switch condition {
		case "empty image":
			s.BeforeValueEntryCount, s.AfterValueEntryCount = 0, 0
			s.BeforeRawBytes, s.AfterRawBytes = 0, 0
			s.BeforeMembershipCount, s.AfterMembershipCount = 0, 0
			s.Normal.Intent.Length, s.Normal.PublicState.Length = 851, 143
			s.Normal.Union.Count, s.Normal.Union.Length = 0, 70
		case "plain memberships", "secret memberships":
			s.BeforeMembershipCount = 2
			s.Normal.Union.Length = 308
			s.Normal.Changed = 1
			s.Exclusion.Exclusions.Count, s.Exclusion.Exclusions.Length = 1, 201
			if condition == "secret memberships" {
				s.BeforeSecretCount, s.AfterSecretCount = 1, 1
				s.IdentityPlan.Length = 331
			}
		}
		for _, sameAccess := range []bool{false, true} {
			if sameAccess {
				s.AfterAccessRoot = s.BeforeAccessRoot
			}
			body, err := LifecycleBytes(s)
			if err != nil {
				t.Fatal("retirement scalar family refused", condition, sameAccess, err)
			}
			got, err := InspectLifecycleSubject(body)
			if err != nil || got != s {
				t.Fatal("retirement subject round trip differs", err)
			}
		}
		for _, damage := range []string{"empty retirement", "two retirements", "short retirement", "ordinary intent", "grants", "membership delta", "changed count", "raw bytes", "entry count", "secret count", "wrong family"} {
			t.Run(condition+"/"+damage, func(t *testing.T) {
				bad := s
				switch damage {
				case "empty retirement":
					bad.Exclusion.Retirements.Count, bad.Exclusion.Retirements.Length = 0, 66
				case "two retirements":
					bad.Exclusion.Retirements.Count, bad.Exclusion.Retirements.Length = 2, 206
				case "short retirement":
					bad.Exclusion.Retirements.Length--
				case "ordinary intent":
					bad.Normal.Intent.Length -= 120
				case "grants":
					bad.Grant.Grants.Count = 1
				case "membership delta":
					bad.BeforeMembershipCount++
				case "changed count":
					bad.Normal.Changed++
				case "raw bytes":
					bad.BeforeRawBytes++
				case "entry count":
					bad.BeforeValueEntryCount++
				case "secret count":
					bad.BeforeSecretCount++
				case "wrong family":
					bad.OperationKind = OperationApplyDeclaration
				}
				if _, err := LifecycleBytes(bad); err != ErrSubject {
					t.Fatal("invalid retirement family admitted", err)
				}
			})
		}
	}
}

// full_only: false
func TestRecipientRetirementRejectsInvalidRowsAndProjections(t *testing.T) {
	domain, _, _, row := recipientRetirementFixture(t)
	for _, condition := range []string{"slot", "recipient", "digest", "short record", "long record", "two rows", "domain"} {
		t.Run(condition, func(t *testing.T) {
			d, changed := domain, row
			switch condition {
			case "slot":
				changed.Slot = CryptoMaxRecipients
			case "recipient":
				changed.RecipientID = ID{}
			case "digest":
				changed.BeforeRecordDigest = ID{}
			case "short record":
				changed.BeforeRecordLength = 575
			case "long record":
				changed.BeforeRecordLength = 1856
			case "domain":
				d = ID{}
			}
			rows := []RecipientRetirementRow{changed}
			if condition == "two rows" {
				rows = append(rows, changed)
			}
			if _, err := RetirementDescriptor(d, rows); err == nil {
				t.Fatal("invalid retirement descriptor accepted")
			}
			if _, err := EncodeRetirements(d, rows); err == nil {
				t.Fatal("invalid retirement encoding accepted")
			}
			w := cryptoWriter{}
			writeRetirements(&w, d, rows)
			if _, err := InspectRetirements(w.b, domain); err == nil {
				t.Fatal("retirement scanner accepted invalid row")
			}
		})
	}
	for _, condition := range []string{"retired", "no binding", "bad binding", "slot"} {
		t.Run("factory/"+condition, func(t *testing.T) {
			_, _, records := completeApplyFixture(t)
			r, slot := records[0].Recipient, uint16(34)
			switch condition {
			case "retired":
				r.Status, r.CurrentBinding = RetiredRecipient, nil
			case "no binding":
				r.CurrentBinding = nil
			case "bad binding":
				r.CurrentBinding.Fingerprint[0] ^= 1
			case "slot":
				slot = CryptoMaxRecipients
			}
			if _, err := NewRecipientRetirementRow(slot, r); err == nil {
				t.Fatal("factory accepted invalid predecessor record")
			}
		})
	}
	for _, length := range []uint32{576, 1855} {
		valid := row
		valid.Slot, valid.BeforeRecordLength = 255, length
		body, err := EncodeRetirements(domain, []RecipientRetirementRow{valid})
		if err != nil {
			t.Fatal("valid fixed retirement bound refused", err)
		}
		if _, err := InspectRetirements(body, domain); err != nil {
			t.Fatal("fixed retirement bound scanner disagrees", err)
		}
	}
}

// full_only: false
func TestRecipientRetirementFactoryBindsExactRecordAndPhysicalSlot(t *testing.T) {
	_, _, records := completeApplyFixture(t)
	record := records[0].Recipient
	base, err := NewRecipientRetirementRow(34, record)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"display", "selector", "binding", "public key"} {
		t.Run(field, func(t *testing.T) {
			_, _, records := completeApplyFixture(t)
			changed := records[0].Recipient
			switch field {
			case "display":
				changed.DisplayName = "other"
			case "selector":
				changed.CurrentBinding.KeySelector = "other"
			case "binding":
				changed.CurrentBinding.BindingSerial++
			case "public key":
				key := successionTestKMS(t, 2)
				changed.CurrentBinding.SPKI, changed.CurrentBinding.Fingerprint = key.SPKI, key.Fingerprint
			}
			row, err := NewRecipientRetirementRow(34, changed)
			if err != nil || row.BeforeRecordDigest == base.BeforeRecordDigest {
				t.Fatal("retirement factory omitted old record field", err)
			}
		})
	}
	moved, err := NewRecipientRetirementRow(0, record)
	if err != nil || moved.Slot == base.Slot || moved.BeforeRecordDigest != base.BeforeRecordDigest || moved.BeforeRecordLength != base.BeforeRecordLength {
		t.Fatal("physical slot was confused with exact encoded record", err)
	}
	first, err := RetirementDescriptor(completeApplyID(1), []RecipientRetirementRow{base})
	if err != nil {
		t.Fatal(err)
	}
	second, err := RetirementDescriptor(completeApplyID(1), []RecipientRetirementRow{moved})
	if err != nil || first == second {
		t.Fatal("physical predecessor slot omitted from signed projection", err)
	}
}

// full_only: false
func TestRecipientRetirementIntentIndependentCommitmentAndBounds(t *testing.T) {
	for _, empty := range []bool{false, true} {
		domain, values, recipients, row := recipientRetirementFixture(t)
		wantLength, wantHash := uint64(1004), "c22de42f63b42d78894b6cae5dd41635ece986e7cd0d1a011badf8ea0bfa48cb"
		if empty {
			values = nil
			wantLength, wantHash = 852, "1703982628159c79a8fc5d1ea1ae703cae4c2c232af282510c2bfa42be31e46d"
		}
		// Direct Python framing gives complete lengths884/732 and adds exactly
		// the literal46-byte retirement prefix, u32 and independently fixed70-byte row.
		d, err := RecipientRetirementIntentDescriptor(domain, values, recipients, row)
		if err != nil || d.Length != wantLength || d.Count != uint32(len(values)) || hex.EncodeToString(d.Digest[:]) != wantHash {
			t.Fatal("retirement intent differs from independent frame", empty, d, err)
		}
		value, registry, err := completeApplyIntentLengths(domain, values, recipients)
		if err != nil {
			t.Fatal(err)
		}
		w := cryptoWriter{}
		writeRecipientRetirementIntent(&w, domain, values, recipients, row, value, registry)
		if !bytes.HasPrefix(w.b, []byte("ENKV/CRYPTO/v2/recipient-retirement-intent-v1\x00")) || Hash(w.b) != d.Digest || len(w.b) != int(wantLength) {
			t.Fatal("retirement writer omitted fixed prefix or row")
		}
		r := cryptoReader{b: w.b}
		complete, access, retired := readCompareIntent(&r, domain)
		if r.end() != nil || complete.descriptor != d || access.present || retired.own() == nil || *retired.own() != row {
			t.Fatal("retirement scanner and writer disagree", r.err)
		}
	}
	if RecipientRetirementRowLength != 70 || retirementLength != 66 || len(recipientRetirementIntentPrefix) != 46 || recipientRetirementIntentExtraLength != 120 || recipientRetirementIntentLimit != 814866 || 31570798+120 != 31570918 || CryptoRequestLimit < 31570918 {
		t.Fatal("retirement independent bound arithmetic changed")
	}
	_, maximum := completeApplyIntentDescriptorBounds(0)
	d := DescriptorVector{Digest: completeApplyID(1), Length: maximum + 120}
	if cryptoLifecycleIntentDescriptorError(completeApplyID(1), d) != nil || completeApplyIntentDescriptorError(completeApplyID(1), d) == nil {
		t.Fatal("zero-entry retirement did not retain separate ordinary component bound")
	}
	d.Length++
	if cryptoLifecycleIntentDescriptorError(completeApplyID(1), d) == nil {
		t.Fatal("zero-entry retirement acquired secret-access capacity")
	}
}

// full_only: false
func TestRecipientRetirementIntentCommitsEveryField(t *testing.T) {
	domain, values, recipients, row := recipientRetirementFixture(t)
	base, err := RecipientRetirementIntentDescriptor(domain, values, recipients, row)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"slot", "recipient", "digest", "record length", "value", "registry", "domain"} {
		t.Run(field, func(t *testing.T) {
			domain, values, recipients, row := recipientRetirementFixture(t)
			switch field {
			case "slot":
				row.Slot++
			case "recipient":
				row.RecipientID[0]++
			case "digest":
				row.BeforeRecordDigest[0]++
			case "record length":
				row.BeforeRecordLength++
			case "value":
				values[0].PayloadDigest[0]++
			case "registry":
				recipients[0].Recipient.DisplayName = "other"
			case "domain":
				domain[0]++
			}
			d, err := RecipientRetirementIntentDescriptor(domain, values, recipients, row)
			if err != nil || d == base {
				t.Fatal("retirement field omitted from commitment", err)
			}
		})
	}
}

func recipientRetirementCompare(t *testing.T, secret bool) CryptoCompareRequest {
	t.Helper()
	q := completeApplyCompare(t)
	q.Recipients[0].Creation = nil
	row, err := NewRecipientRetirementRow(34, q.Recipients[0].Recipient)
	if err != nil {
		t.Fatal(err)
	}
	if secret {
		q = cryptoRetainedCompareFixture(t)
	} else {
		q.Intent = nil
	}
	q.Retirement = &row
	q.Context.IntentDescriptor, err = RecipientRetirementIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, row)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// full_only: false
func TestRecipientRetirementCompareOwnAndClosedDispatch(t *testing.T) {
	for _, secret := range []bool{false, true} {
		q := recipientRetirementCompare(t, secret)
		body, err := EncodeCryptoCompareRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectCryptoCompareRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || owned.Retirement == nil || *owned.Retirement != *q.Retirement || len(owned.Intent) != len(q.Intent) || len(q.Intent) != 0 && !reflect.DeepEqual(owned.Intent, q.Intent) || owned.SecretAccess != nil {
			t.Fatal("retirement Compare ownership lost fields", err)
		}
		want := bytes.Clone(body)
		clear(body)
		encoded, err := EncodeCryptoCompareRequest(owned)
		if err != nil || !bytes.Equal(encoded, want) {
			t.Fatal("retirement Own retained borrowed storage", err)
		}
		decoded, err := DecodeCryptoCompareRequest(encoded)
		if err != nil || !reflect.DeepEqual(decoded, owned) {
			t.Fatal("retirement scanner/Own agreement failed", err)
		}
		view, err = InspectCryptoCompareRequest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		encoded[cryptoContextBlobLength] ^= 1
		if _, err := view.Own(); err == nil {
			t.Fatal("retirement Own did not rescan changed input")
		}
		q.SecretAccess = &CryptoSecretAccessIntent{}
		if _, err := EncodeCryptoCompareRequest(q); err == nil {
			t.Fatal("two operation intent forms accepted")
		}
		q.SecretAccess = nil
		q.SealedInputs = []CryptoSealedInput{{Name: "pending"}}
		if _, err := EncodeCryptoCompareRequest(q); err == nil {
			t.Fatal("retirement accepted sealed pending declaration")
		}
	}
}

// full_only: false
func TestRecipientRetirementCompareScannerRejectsMalformedIntent(t *testing.T) {
	q := recipientRetirementCompare(t, false)
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	start, end := cryptoContextBlobLength, cryptoContextBlobLength+int(q.Context.IntentDescriptor.Length)
	target := end - 70
	for _, condition := range []string{"prefix", "nested length", "nested prefix", "slot", "recipient", "digest", "short record", "long record", "truncated", "trailing"} {
		t.Run(condition, func(t *testing.T) {
			bad := bytes.Clone(body)
			switch condition {
			case "prefix":
				bad[start] ^= 1
			case "nested length":
				binary.BigEndian.PutUint32(bad[start+46:], uint32(completeApplyIntentLimit+1))
			case "nested prefix":
				bad[start+50] ^= 1
			case "slot":
				binary.BigEndian.PutUint16(bad[target:], CryptoMaxRecipients)
			case "recipient":
				clear(bad[target+2 : target+34])
			case "digest":
				clear(bad[target+34 : target+66])
			case "short record":
				binary.BigEndian.PutUint32(bad[target+66:], 575)
			case "long record":
				binary.BigEndian.PutUint32(bad[target+66:], 1856)
			case "truncated":
				bad = bad[:end-1]
			case "trailing":
				bad = append(bad, 0)
			}
			if condition != "truncated" && condition != "trailing" {
				context := q.Context
				context.IntentDescriptor.Digest = Hash(bad[start:end])
				encoded, err := EncodeApplyContext(context)
				if err != nil {
					t.Fatal(err)
				}
				copy(bad[4:4+len(encoded)], encoded)
			}
			if _, err := InspectCryptoCompareRequest(bad); err == nil {
				t.Fatal("retirement scanner accepted malformed target")
			}
			if _, err := DecodeCryptoCompareRequest(bad); err == nil {
				t.Fatal("retirement decoder accepted malformed target")
			}
		})
	}
	q.Recipients[0].Creation = &RecipientCreationProof{Snapshot: completeApplyID(30), Nonce: completeApplyID(31)}
	if _, err := RecipientRetirementIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, *q.Retirement); err == nil {
		t.Fatal("retirement descriptor accepted creation proof")
	}
	value, registry, err := completeApplyIntentLengths(q.Context.DomainID, q.Intent, q.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	w := cryptoWriter{}
	writeRecipientRetirementIntent(&w, q.Context.DomainID, q.Intent, q.Recipients, *q.Retirement, value, registry)
	r := cryptoReader{b: w.b}
	readCompareIntent(&r, q.Context.DomainID)
	if r.end() == nil {
		t.Fatal("retirement borrowed scanner accepted creation proof")
	}
}
