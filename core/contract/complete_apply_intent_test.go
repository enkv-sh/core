package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func completeApplyID(n byte) ID { return ID(bytes.Repeat([]byte{n}, 32)) }

func completeApplyFixture(t testing.TB) (ID, []CryptoIntentRow, []ApplyRecipientInput) {
	t.Helper()
	binding := successionTestKMS(t, 1)
	binding.BindingID, binding.BindingIncarnationID, binding.KeySelector = completeApplyID(3), completeApplyID(4), "k"
	return completeApplyID(1), []CryptoIntentRow{{Name: "a", Recipients: []ID{completeApplyID(2)}, ValueSource: Supplied, ConfidentialityClass: Plain,
		ContentLength: 1, InputEncoding: InputEncodingRaw, RetainedLength: 1, OutputEncoding: OutputEncodingRaw, PayloadDigest: completeApplyID(9), PayloadLength: 1}}, []ApplyRecipientInput{{
		Recipient: RecipientRecord{RecipientID: completeApplyID(2), Status: CurrentRecipient, DisplayName: "x", CurrentBinding: &binding},
		Creation:  &RecipientCreationProof{Snapshot: completeApplyID(5), Nonce: completeApplyID(6)},
	}}
}

func completeApplyCompare(t testing.TB) CryptoCompareRequest {
	t.Helper()
	domain, values, recipients := completeApplyFixture(t)
	descriptor, err := CompleteApplyIntentDescriptor(domain, values, recipients)
	if err != nil {
		t.Fatal(err)
	}
	root, err := AppendRef(nil, Ref{Kind: RootKind, Format: CanonicalSchema, Domain: domain, Object: completeApplyID(20), Digest: completeApplyID(21), Length: 100}, CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	context := ApplyContext{OperationClass: CryptoOrdinaryLifecycle, AdmissionID: completeApplyID(10), SessionID: completeApplyID(11), DomainID: domain,
		CompatibilityID: CompatibilityID(), Expiry: 1, PredecessorHEADDigest: completeApplyID(12), OriginalConditionDigest: completeApplyID(13),
		IntentDescriptor: descriptor, CurrentAccessRoot: completeApplyID(14)}
	copy(context.PredecessorRootRef[:], root)
	return CryptoCompareRequest{Context: context, Intent: values, Recipients: recipients}
}

// full_only: false
func TestCompleteApplyIntentIndependentCanonicalBytes(t *testing.T) {
	domain, values, recipients := completeApplyFixture(t)
	// Independently concatenate the specified fields with Python struct big-endian
	// integers. RSA SPKI is DER for modulus 2^3071+12347 and exponent 65537.
	// The value body is 222 bytes; registry body 646; complete body 948.
	wantHex := "454e4b562f43525950544f2f76322f636f6d706c6574652d6170706c792d696e74656e742d7631000101010101010101010101010101010101010101010101010101010101010101000000de454e4b562f43525950544f2f76322f737570706c6965642d696e74656e742d7638000101010101010101010101010101010101010101010101010101010101010101000000010000000161000102020202020202020202020202020202020202020202020202020202020202020101000000010100000001010909090909090909090909090909090909090909090909090909090909090909000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002860000000102020202020202020202020202020202020202020202020202020202020202020100000001780000021703030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404000000000000000102000202000000016b308201a2300d06092a864886f70d01010105000382018f003082018a028201810080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303b0203010001e1bf5e38cc6043f66906582d7a9cb4777945e600e62ac6de29875ba048b91b330105050505050505050505050505050505050505050505050505050505050505050606060606060606060606060606060606060606060606060606060606060606"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := CompleteApplyIntentDescriptor(domain, values, recipients)
	if err != nil || descriptor.Length != 948 || descriptor.Count != 1 || hex.EncodeToString(descriptor.Digest[:]) != "8b28a045bea386a0695209992685157d0b6ce781854f453902771cd6a95e5fe8" {
		t.Fatal("complete descriptor differs from independent literal", descriptor, err)
	}
	q := completeApplyCompare(t)
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil || len(body) < cryptoContextBlobLength+len(want) || !bytes.Equal(body[cryptoContextBlobLength:cryptoContextBlobLength+len(want)], want) {
		t.Fatal("comparison does not carry the exact complete intent", err)
	}
	valueOnly, err := CryptoIntentDescriptor(domain, values)
	if err != nil || valueOnly.Count != descriptor.Count || valueOnly == descriptor {
		t.Fatal("complete apply and value subprojection collapsed", err)
	}
}

// full_only: false
func TestCompleteApplyIntentCommitsEveryRegistryField(t *testing.T) {
	domain, values, recipients := completeApplyFixture(t)
	baseline, err := CompleteApplyIntentDescriptor(domain, values, recipients)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"domain", "recipient", "display", "binding", "incarnation", "serial", "provider", "profile", "protection", "selector", "public key", "fingerprint", "proof presence", "snapshot", "nonce"} {
		t.Run(field, func(t *testing.T) {
			d, v, rows := completeApplyFixture(t)
			row, binding := &rows[0], rows[0].Recipient.CurrentBinding
			switch field {
			case "domain":
				d[0] ^= 1
			case "recipient":
				row.Recipient.RecipientID[0] ^= 1
			case "display":
				row.Recipient.DisplayName = "changed"
			case "binding":
				binding.BindingID[0] ^= 1
			case "incarnation":
				binding.BindingIncarnationID[0] ^= 1
			case "serial":
				binding.BindingSerial++
			case "provider":
				binding.Provider = AWS
			case "profile":
				binding.WrapProfile++
			case "protection":
				binding.ProtectionClass = HardwareProtection
			case "selector":
				binding.KeySelector = "other"
			case "public key":
				replacement := successionTestKMS(t, 2)
				binding.SPKI, binding.Fingerprint = replacement.SPKI, replacement.Fingerprint
			case "fingerprint":
				binding.Fingerprint[0] ^= 1
			case "proof presence":
				row.Creation = nil
			case "snapshot":
				row.Creation.Snapshot[0] ^= 1
			case "nonce":
				row.Creation.Nonce[0] ^= 1
			}
			changed, err := CompleteApplyIntentDescriptor(d, v, rows)
			if err == nil && changed == baseline {
				t.Fatal("registry field omitted from complete commitment")
			}
		})
	}
}

// full_only: false
func TestCompleteApplyIntentRejectsInvalidRegistry(t *testing.T) {
	for _, condition := range []string{"empty", "retired", "missing binding", "zero snapshot", "zero nonce", "duplicate", "reverse", "row count", "name bound", "key bound"} {
		t.Run(condition, func(t *testing.T) {
			domain, values, rows := completeApplyFixture(t)
			switch condition {
			case "empty":
				rows = nil
			case "retired":
				rows[0].Recipient.Status, rows[0].Recipient.CurrentBinding = RetiredRecipient, nil
			case "missing binding":
				rows[0].Recipient.CurrentBinding = nil
			case "zero snapshot":
				rows[0].Creation.Snapshot = ID{}
			case "zero nonce":
				rows[0].Creation.Nonce = ID{}
			case "duplicate":
				rows = append(rows, rows[0])
			case "reverse":
				other := rows[0]
				other.Recipient.RecipientID = completeApplyID(1)
				rows = append(rows, other)
			case "row count":
				rows = make([]ApplyRecipientInput, 257)
			case "name bound":
				rows[0].Recipient.DisplayName = strings.Repeat("x", 257)
			case "key bound":
				rows[0].Recipient.CurrentBinding.KeySelector = strings.Repeat("k", 1025)
			}
			if _, err := CompleteApplyIntentDescriptor(domain, values, rows); err == nil {
				t.Fatal("invalid complete registry accepted")
			}
		})
	}
}

// full_only: false
func TestCompleteApplyCompareOwnRetainsRegistry(t *testing.T) {
	q := completeApplyCompare(t)
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectCryptoCompareRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil || !reflect.DeepEqual(owned.Recipients, q.Recipients) {
		t.Fatal("complete registry lost during Own", err)
	}
	clear(body)
	if !reflect.DeepEqual(owned.Recipients, q.Recipients) {
		t.Fatal("owned registry borrows input")
	}
	encoded, err := EncodeCryptoCompareRequest(owned)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCryptoCompareRequest(encoded)
	if err != nil || !reflect.DeepEqual(decoded.Recipients, q.Recipients) {
		t.Fatal("registry scanner and decoder disagree", err)
	}
}

// full_only: false
func TestCompleteApplyCompareScannerRejectsMalformedRegistry(t *testing.T) {
	q := completeApplyCompare(t)
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	const registryAt = 80 + 222
	start := cryptoContextBlobLength
	if len(body) < start+948 || string(body[start:start+40]) != "ENKV/CRYPTO/v2/complete-apply-intent-v1\x00" {
		t.Fatal("complete framing absent")
	}
	for _, condition := range []string{"count", "status", "proof tag", "snapshot", "nonce", "registry length", "trailing"} {
		t.Run(condition, func(t *testing.T) {
			bad := bytes.Clone(body)
			switch condition {
			case "count":
				binary.BigEndian.PutUint32(bad[start+registryAt:], 257)
			case "status":
				bad[start+registryAt+4+32] = RetiredRecipient
			case "proof tag":
				bad[start+registryAt+4+577] = 2
			case "snapshot":
				clear(bad[start+registryAt+4+578 : start+registryAt+4+610])
			case "nonce":
				clear(bad[start+registryAt+4+610 : start+registryAt+4+642])
			case "registry length":
				binary.BigEndian.PutUint32(bad[start+registryAt-4:], 8<<20+1)
			case "trailing":
				bad = append(bad, 0)
			}
			if condition != "registry length" && condition != "trailing" {
				changed := q.Context
				changed.IntentDescriptor.Digest = Hash(bad[start : start+948])
				context, err := EncodeApplyContext(changed)
				if err != nil {
					t.Fatal(err)
				}
				copy(bad[4:4+len(context)], context)
			}
			if _, err := InspectCryptoCompareRequest(bad); err == nil {
				t.Fatal("malformed registry accepted")
			}
			if _, err := DecodeCryptoCompareRequest(bad); err == nil {
				t.Fatal("decoder accepted malformed registry")
			}
		})
	}
	view, err := InspectCryptoCompareRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	body[start+registryAt+4+577] = 2
	if _, err := view.Own(); err == nil {
		t.Fatal("Own retained damaged registry after inspection")
	}
	for _, condition := range []string{"duplicate", "reverse"} {
		t.Run(condition, func(t *testing.T) {
			candidate := completeApplyCompare(t)
			second := candidate.Recipients[0]
			second.Recipient.RecipientID = completeApplyID(7)
			candidate.Recipients = append(candidate.Recipients, second)
			candidate.Context.IntentDescriptor, err = CompleteApplyIntentDescriptor(candidate.Context.DomainID, candidate.Intent, candidate.Recipients)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := EncodeCryptoCompareRequest(candidate)
			if err != nil {
				t.Fatal(err)
			}
			id := completeApplyID(2)
			if condition == "reverse" {
				id = completeApplyID(1)
			}
			copy(bad[start+registryAt+4+642:], id[:])
			length := int(candidate.Context.IntentDescriptor.Length)
			candidate.Context.IntentDescriptor.Digest = Hash(bad[start : start+length])
			context, err := EncodeApplyContext(candidate.Context)
			if err != nil {
				t.Fatal(err)
			}
			copy(bad[4:4+len(context)], context)
			if _, err := InspectCryptoCompareRequest(bad); err == nil {
				t.Fatal("noncanonical registry order accepted with matching commitment")
			}
		})
	}
}

// full_only: false
func TestCompleteApplyIntentRegistryCapacity(t *testing.T) {
	if completeApplyIntentLimit != 814746 || CryptoRequestLimit != 31573219 || CryptoRequestLimit > CryptoFrameLimit {
		t.Fatal("complete intent or directional request bound differs")
	}
	domain, values, source := completeApplyFixture(t)
	rows := make([]ApplyRecipientInput, 256)
	for i := range rows {
		rows[i] = source[0]
		rows[i].Recipient.RecipientID = ID{}
		binary.BigEndian.PutUint16(rows[i].Recipient.RecipientID[30:], uint16(i+1))
		rows[i].Recipient.DisplayName = strings.Repeat("x", 256)
		binding := *source[0].Recipient.CurrentBinding
		binding.KeySelector = strings.Repeat("k", 1024)
		rows[i].Recipient.CurrentBinding = &binding
	}
	d, err := CompleteApplyIntentDescriptor(domain, values, rows)
	if err != nil || d.Length != 80+222+4+256*(1855+65) || d.Count != 1 {
		t.Fatal("complete registry capacity differs", d, err)
	}
	q := completeApplyCompare(t)
	q.Recipients, q.Context.IntentDescriptor = rows, d
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	view, err := InspectCryptoCompareRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil || len(owned.Recipients) != 256 {
		t.Fatal("maximum registry scanner/Own disagree", err)
	}
	if _, err := CompleteApplyIntentDescriptor(domain, values, append(rows, rows[0])); err == nil {
		t.Fatal("257 recipients accepted")
	}
	for _, count := range []int{0, 1, 512} {
		values := make([]CryptoIntentRow, count)
		for i := range values {
			values[i] = CryptoIntentRow{Name: fmt.Sprintf("v%03d", i), Recipients: []ID{rows[0].Recipient.RecipientID}, ValueSource: Supplied, ConfidentialityClass: Plain, InputEncoding: InputEncodingRaw, RetainedLength: 0, OutputEncoding: OutputEncodingRaw}
		}
		d, err := CompleteApplyIntentDescriptor(domain, values, rows[:1])
		if err != nil || d.Count != uint32(count) {
			t.Fatal("registry count replaced value count", count, d, err)
		}
	}
}

// full_only: false
func TestCompleteApplyFreezeRetainsCandidateRegistry(t *testing.T) {
	compared := completeApplyCompare(t)
	plan := IdentityPlan{Operation: completeApplyID(30), Transition: completeApplyID(31), Snapshot: completeApplyID(32), Revision: completeApplyID(33),
		Pages: []IdentityPage{{Kind: RecipientKind, Object: completeApplyID(34)}}}
	identity, err := IdentityPlanDescriptor(plan)
	if err != nil {
		t.Fatal(err)
	}
	support, err := EmptyRequiredSupportDescriptor(compared.Context.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	public, err := EncodePublicState(PublicState{Domain: compared.Context.DomainID, AccessRoot: completeApplyID(35), RequiredSupport: support,
		Rows: []PublicStateRow{{Name: "a", Slot: 0, EntryDigest: completeApplyID(36)}}})
	if err != nil {
		t.Fatal(err)
	}
	exclusions, err := EncodeExclusions(compared.Context.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := CryptoPreparedRowsDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	q := CryptoFreezeRequest{OperationRef: completeApplyID(40), Context: compared.Context, IdentityPlanDescriptor: identity,
		CanonicalRowsDescriptor: prepared, CandidatePublicState: public, Exclusions: exclusions, Recipients: []RecipientRecord{compared.Recipients[0].Recipient}}
	body, err := EncodeCryptoFreezeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := DecodeCryptoFreezeRequest(body)
	if err != nil || !reflect.DeepEqual(owned.Recipients, q.Recipients) {
		t.Fatal("freeze omitted candidate registry", err)
	}
	clear(body)
	if !reflect.DeepEqual(owned.Recipients, q.Recipients) {
		t.Fatal("freeze registry borrows input")
	}
	q.Recipients = nil
	if _, err := EncodeCryptoFreezeRequest(q); err == nil {
		t.Fatal("freeze accepted missing complete registry")
	}
}

// full_only: false
func TestLifecycleRegistryOnlyCompleteIntent(t *testing.T) {
	s := lifecycleFixture()
	s.OperationKind, s.Normal.Changed = OperationApplyDeclaration, 0
	s.IdentityPlan.Length = 197
	// The unchanged value projection is 221 bytes. Complete framing is 80;
	// a nonempty minimal registry projection is 581 bytes, independently bounded.
	s.Normal.Intent.Length = 221 + 80 + 581
	for _, sameAccess := range []bool{false, true} {
		if sameAccess {
			s.AfterAccessRoot = s.BeforeAccessRoot
		}
		body, err := LifecycleBytes(s)
		if err != nil || len(body) != 715 {
			t.Fatal("registry-only lifecycle refused", sameAccess, err)
		}
		decoded, err := InspectLifecycleSubject(body)
		if err != nil || decoded != s {
			t.Fatal("operation kind lost", err)
		}
	}
}

// full_only: false
func TestLifecycleUsesExplicitOperationKind(t *testing.T) {
	s := lifecycleFixture()
	s.OperationKind = OperationApplyDeclaration
	s.Normal.Intent.Length += 80 + 581
	body, err := LifecycleBytes(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 715 || binary.BigEndian.Uint16(body[len(lifecyclePrefix):]) != OperationApplyDeclaration {
		t.Fatal("explicit operation kind absent")
	}
	for _, kind := range []uint16{0, OperationRotateRecipientKeyBinding, OperationInitializeDomain, 65535} {
		bad := s
		bad.OperationKind = kind
		if _, err := LifecycleBytes(bad); err == nil {
			t.Fatal("wrong operation kind accepted", kind)
		}
	}
	s.Normal.Changed, s.IdentityPlan.Length, s.OperationKind = 0, 197, OperationRotateRecipientKeyBinding
	s.Normal.Intent.Length = uint64(recipientReplacementIntentMinLength)
	if _, err := LifecycleBytes(s); err != nil {
		t.Fatal("explicit replacement law refused", err)
	}
	s.OperationKind = OperationApplyDeclaration
	s.Normal.Intent.Length = 215
	if _, err := LifecycleBytes(s); err == nil {
		t.Fatal("value-only intent interpreted as complete apply")
	}
}
