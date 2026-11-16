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

func secretAccessFixture(t testing.TB, kind uint16) (ID, []CryptoIntentRow, []ApplyRecipientInput, CryptoSecretAccessIntent) {
	t.Helper()
	domain, values, recipients := completeApplyFixture(t)
	values[0].ConfidentialityClass, values[0].PayloadLength = Secret, CanonicalPayloadOverhead+1
	values[0].Retained = RetainedSecretInput{Incarnation: completeApplyID(7), Material: completeApplyID(8)}
	recipients[0].Creation = nil
	intent := CryptoSecretAccessIntent{OperationKind: kind, Target: SecretAccessTarget{Slot: 258, Name: "a", Incarnation: completeApplyID(7), Material: completeApplyID(8), BeforePublicEntryDigest: completeApplyID(10)}}
	if kind == OperationRemoveSecretValueEntryAccess {
		intent.RemovedRecipients = []ID{completeApplyID(11), completeApplyID(12)}
	}
	return domain, values, recipients, intent
}

func secretAccessCompare(t *testing.T, kind uint16) CryptoCompareRequest {
	t.Helper()
	q := cryptoRetainedCompareFixture(t)
	q.SealedInputs = []CryptoSealedInput{}
	entry, err := DecodeValueEntry(q.Current[0].EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PublicValueEntryDigest(q.Context.DomainID, q.Current[0].Slot, entry)
	if err != nil {
		t.Fatal(err)
	}
	q.SecretAccess = &CryptoSecretAccessIntent{OperationKind: kind, Target: SecretAccessTarget{Slot: q.Current[0].Slot, Name: entry.Name, Incarnation: entry.Incarnation, Material: entry.ValueState, BeforePublicEntryDigest: digest}}
	if kind == OperationRemoveSecretValueEntryAccess {
		q.SecretAccess.RemovedRecipients = []ID{completeApplyID(100), completeApplyID(101)}
	}
	q.Context.IntentDescriptor, err = SecretAccessIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, *q.SecretAccess)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// full_only: false
func TestSecretAccessIntentIndependentCanonicalBytes(t *testing.T) {
	// Python struct big-endian fields, SHA-256 and direct RSA SPKI DER construction
	// independently give a 222-byte value body, 582-byte registry and 884-byte
	// complete body. The outer re-key body is 1032 bytes; exclusion is 1098.
	wantHex := "454e4b562f43525950544f2f76322f7365637265742d6163636573732d696e74656e742d763100000b00000374454e4b562f43525950544f2f76322f636f6d706c6574652d6170706c792d696e74656e742d7631000101010101010101010101010101010101010101010101010101010101010101000000de454e4b562f43525950544f2f76322f737570706c6965642d696e74656e742d7638000101010101010101010101010101010101010101010101010101010101010101000000010000000161000102020202020202020202020202020202020202020202020202020202020202020102000000010100000001010909090909090909090909090909090909090909090909090909090909090909000000d80107070707070707070707070707070707070707070707070707070707070707070808080808080808080808080808080808080808080808080808080808080808000002460000000102020202020202020202020202020202020202020202020202020202020202020100000001780000021703030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404000000000000000102000202000000016b308201a2300d06092a864886f70d01010105000382018f003082018a028201810080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000303b0203010001e1bf5e38cc6043f66906582d7a9cb4777945e600e62ac6de29875ba048b91b330001020000000161070707070707070707070707070707070707070707070707070707070707070708080808080808080808080808080808080808080808080808080808080808080a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
	rekey, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []uint16{OperationEnvelopeRekey, OperationRemoveSecretValueEntryAccess} {
		domain, values, recipients, intent := secretAccessFixture(t, kind)
		want := bytes.Clone(rekey)
		wantHash := "a8ad092dc2e3b156240ebf868695a9c66893d39d16e9d7d24f616d3a5ba948cb"
		if kind == OperationRemoveSecretValueEntryAccess {
			want[40] = 8
			want = append(want, 0, 2)
			want = append(want, bytes.Repeat([]byte{11}, 32)...)
			want = append(want, bytes.Repeat([]byte{12}, 32)...)
			wantHash = "a1458c3f3d825fd630bb24e7f589bae106fc8b22d82dc0f48c7b0c1c451b9f41"
		}
		d, err := SecretAccessIntentDescriptor(domain, values, recipients, intent)
		if err != nil || d.Count != 1 || d.Length != uint64(len(want)) || hex.EncodeToString(d.Digest[:]) != wantHash {
			t.Fatal("typed descriptor differs from independent literal", kind, d, err)
		}
		value, registry, err := completeApplyIntentLengths(domain, values, recipients)
		if err != nil {
			t.Fatal(err)
		}
		w := cryptoWriter{}
		writeSecretAccessIntent(&w, domain, values, recipients, intent, value, registry)
		if !bytes.Equal(w.b, want) {
			t.Fatal("typed canonical bytes differ", kind)
		}
		reader := cryptoReader{b: want}
		complete, access, _ := readCompareIntent(&reader, domain)
		if reader.end() != nil || complete.descriptor != d || !reflect.DeepEqual(access.own(), &intent) {
			t.Fatal("independent typed literal did not scan", kind, reader.err)
		}
	}
}

// full_only: false
func TestSecretAccessIntentCommitsExactOperationAndTarget(t *testing.T) {
	domain, values, recipients, intent := secretAccessFixture(t, OperationRemoveSecretValueEntryAccess)
	base, err := SecretAccessIntentDescriptor(domain, values, recipients, intent)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"kind", "slot", "name", "incarnation", "material", "public row", "removed", "value", "registry", "domain"} {
		t.Run(field, func(t *testing.T) {
			domain, values, recipients, intent := secretAccessFixture(t, OperationRemoveSecretValueEntryAccess)
			switch field {
			case "kind":
				intent.OperationKind, intent.RemovedRecipients = OperationEnvelopeRekey, nil
			case "slot":
				intent.Target.Slot++
			case "name":
				intent.Target.Name = "b"
			case "incarnation":
				intent.Target.Incarnation[0]++
			case "material":
				intent.Target.Material[0]++
			case "public row":
				intent.Target.BeforePublicEntryDigest[0]++
			case "removed":
				intent.RemovedRecipients[1][0]++
			case "value":
				values[0].PayloadDigest[0]++
			case "registry":
				recipients[0].Recipient.DisplayName = "other"
			case "domain":
				domain[0]++
			}
			got, err := SecretAccessIntentDescriptor(domain, values, recipients, intent)
			if err != nil || got == base {
				t.Fatal("valid field change did not change commitment", got, err)
			}
		})
	}
}

// full_only: false
func TestSecretAccessIntentRejectsInvalidShapes(t *testing.T) {
	for _, condition := range []string{"ordinary kind", "retirement kind", "unknown kind", "empty values", "slot", "name bytes", "name utf8", "incarnation", "material", "public row", "empty removed", "zero removed", "duplicate removed", "reverse removed", "removed capacity", "rekey removed", "creation proof"} {
		t.Run(condition, func(t *testing.T) {
			domain, values, recipients, intent := secretAccessFixture(t, OperationRemoveSecretValueEntryAccess)
			switch condition {
			case "ordinary kind":
				intent.OperationKind = OperationApplyDeclaration
			case "retirement kind":
				intent.OperationKind = OperationRetireRecipientIdentity
			case "unknown kind":
				intent.OperationKind = 65535
			case "empty values":
				values = nil
			case "slot":
				intent.Target.Slot = CryptoMaxValueEntries
			case "name bytes":
				intent.Target.Name = strings.Repeat("a", CryptoMaxName+1)
			case "name utf8":
				intent.Target.Name = "\xff"
			case "incarnation":
				intent.Target.Incarnation = ID{}
			case "material":
				intent.Target.Material = ID{}
			case "public row":
				intent.Target.BeforePublicEntryDigest = ID{}
			case "empty removed":
				intent.RemovedRecipients = nil
			case "zero removed":
				intent.RemovedRecipients[0] = ID{}
			case "duplicate removed":
				intent.RemovedRecipients[1] = intent.RemovedRecipients[0]
			case "reverse removed":
				intent.RemovedRecipients[0], intent.RemovedRecipients[1] = intent.RemovedRecipients[1], intent.RemovedRecipients[0]
			case "removed capacity":
				intent.RemovedRecipients = make([]ID, 64)
				for i := range intent.RemovedRecipients {
					intent.RemovedRecipients[i] = completeApplyID(byte(i + 1))
				}
			case "rekey removed":
				intent.OperationKind = OperationEnvelopeRekey
			case "creation proof":
				recipients[0].Creation = &RecipientCreationProof{Snapshot: completeApplyID(20), Nonce: completeApplyID(21)}
			}
			if _, err := SecretAccessIntentDescriptor(domain, values, recipients, intent); err == nil {
				t.Fatal("invalid typed intent admitted")
			}
			if condition != "rekey removed" {
				value, registry, err := completeApplyIntentLengths(domain, values, recipients)
				if err != nil {
					t.Fatal("invalid fixture embedded complete body", err)
				}
				w := cryptoWriter{}
				writeSecretAccessIntent(&w, domain, values, recipients, intent, value, registry)
				r := cryptoReader{b: w.b}
				readCompareIntent(&r, domain)
				if r.end() == nil {
					t.Fatal("borrowed scanner admitted invalid typed shape")
				}
			}
		})
	}
}

// full_only: false
func TestSecretAccessCompareOwnRetainsExactIntent(t *testing.T) {
	for _, kind := range []uint16{OperationRemoveSecretValueEntryAccess, OperationEnvelopeRekey} {
		q := secretAccessCompare(t, kind)
		body, err := EncodeCryptoCompareRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectCryptoCompareRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := view.Own()
		if err != nil || !reflect.DeepEqual(owned, q) {
			t.Fatal("typed compare ownership differs", kind, err)
		}
		want := bytes.Clone(body)
		clear(body)
		encoded, err := EncodeCryptoCompareRequest(owned)
		if err != nil || !bytes.Equal(encoded, want) {
			t.Fatal("typed compare retained borrowed storage", kind, err)
		}
		decoded, err := DecodeCryptoCompareRequest(encoded)
		if err != nil || !reflect.DeepEqual(decoded, q) {
			t.Fatal("typed compare scanner and Own disagree", kind, err)
		}
		view, err = InspectCryptoCompareRequest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		encoded[cryptoContextBlobLength] ^= 1
		if _, err := view.Own(); err == nil {
			t.Fatal("Own did not rescan changed typed input")
		}
	}
}

// full_only: false
func TestSecretAccessCompareScannerRejectsMalformedIntent(t *testing.T) {
	q := secretAccessCompare(t, OperationRemoveSecretValueEntryAccess)
	body, err := EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	start := cryptoContextBlobLength
	completeLength := int(binary.BigEndian.Uint32(body[start+41:]))
	target := start + 45 + completeLength
	nameLength := len(q.SecretAccess.Target.Name)
	ids, removed := target+6+nameLength, target+6+nameLength+96
	for _, condition := range []string{"prefix", "kind", "nested prefix", "nested capacity", "slot", "name bytes", "name utf8", "incarnation", "material", "public row", "empty removed", "removed capacity", "zero removed", "duplicate removed", "reverse removed", "truncated", "trailing"} {
		t.Run(condition, func(t *testing.T) {
			bad := bytes.Clone(body)
			switch condition {
			case "prefix":
				bad[start] ^= 1
			case "kind":
				binary.BigEndian.PutUint16(bad[start+39:], OperationRetireRecipientIdentity)
			case "nested prefix":
				bad[start+45] ^= 1
			case "nested capacity":
				binary.BigEndian.PutUint32(bad[start+41:], uint32(completeApplyIntentLimit+1))
			case "slot":
				binary.BigEndian.PutUint16(bad[target:], CryptoMaxValueEntries)
			case "name bytes":
				binary.BigEndian.PutUint32(bad[target+2:], CryptoMaxName+1)
			case "name utf8":
				bad[target+6] = 255
			case "incarnation":
				clear(bad[ids : ids+32])
			case "material":
				clear(bad[ids+32 : ids+64])
			case "public row":
				clear(bad[ids+64 : ids+96])
			case "empty removed":
				binary.BigEndian.PutUint16(bad[removed:], 0)
			case "removed capacity":
				binary.BigEndian.PutUint16(bad[removed:], 64)
			case "zero removed":
				clear(bad[removed+2 : removed+34])
			case "duplicate removed":
				copy(bad[removed+34:removed+66], bad[removed+2:removed+34])
			case "reverse removed":
				copy(bad[removed+2:removed+34], bytes.Repeat([]byte{255}, 32))
			case "truncated":
				bad = bad[:start+int(q.Context.IntentDescriptor.Length)-1]
			case "trailing":
				bad = append(bad, 0)
			}
			if condition != "truncated" && condition != "trailing" {
				context := q.Context
				context.IntentDescriptor.Digest = Hash(bad[start : start+int(context.IntentDescriptor.Length)])
				encoded, err := EncodeApplyContext(context)
				if err != nil {
					t.Fatal(err)
				}
				copy(bad[4:4+len(encoded)], encoded)
			}
			if _, err := InspectCryptoCompareRequest(bad); err == nil {
				t.Fatal("scanner admitted malformed typed intent")
			}
			if _, err := DecodeCryptoCompareRequest(bad); err == nil {
				t.Fatal("decoder admitted malformed typed intent")
			}
		})
	}
	q.SealedInputs = []CryptoSealedInput{{Name: "source"}}
	if _, err := EncodeCryptoCompareRequest(q); err == nil {
		t.Fatal("standalone compare accepted a pending sealed source")
	}
}

// full_only: false
func TestSecretAccessIntentBounds(t *testing.T) {
	if secretAccessIntentFixedLength != 147 || secretExclusionIntentExtraLimit != 2421 || secretRekeyIntentExtraLimit != 403 || secretAccessIntentLimit != 817167 || CryptoRequestLimit != 31573219 {
		t.Fatal("typed intent or request bound differs from independent arithmetic")
	}
	domain, values, recipients, intent := secretAccessFixture(t, OperationRemoveSecretValueEntryAccess)
	intent.Target.Slot, intent.Target.Name = CryptoMaxValueEntries-1, strings.Repeat("a", CryptoMaxName)
	intent.RemovedRecipients = make([]ID, 63)
	for i := range intent.RemovedRecipients {
		intent.RemovedRecipients[i] = completeApplyID(byte(i + 1))
	}
	base, err := CompleteApplyIntentDescriptor(domain, values, recipients)
	if err != nil {
		t.Fatal(err)
	}
	d, err := SecretAccessIntentDescriptor(domain, values, recipients, intent)
	if err != nil || d.Length != base.Length+2421 || d.Count != base.Count {
		t.Fatal("maximum target or removed-set bound refused", d, err)
	}
	value, registry, err := completeApplyIntentLengths(domain, values, recipients)
	if err != nil {
		t.Fatal(err)
	}
	w := cryptoWriter{}
	writeSecretAccessIntent(&w, domain, values, recipients, intent, value, registry)
	r := cryptoReader{b: w.b}
	complete, access, _ := readCompareIntent(&r, domain)
	if r.end() != nil || complete.descriptor != d || !reflect.DeepEqual(access.own(), &intent) {
		t.Fatal("maximum target and removed-set scanner/Own disagree", r.err)
	}
	intent.Target.Name = ""
	intent.OperationKind, intent.RemovedRecipients = OperationEnvelopeRekey, nil
	d, err = SecretAccessIntentDescriptor(domain, values, recipients, intent)
	if err != nil || d.Length != base.Length+147 {
		t.Fatal("empty target name refused", d, err)
	}
	_, maximum := completeApplyIntentDescriptorBounds(CryptoMaxValueEntries)
	d = DescriptorVector{Count: CryptoMaxValueEntries, Length: maximum + 2421, Digest: completeApplyID(1)}
	if cryptoLifecycleIntentDescriptorError(domain, d) != nil || completeApplyIntentDescriptorError(domain, d) == nil {
		t.Fatal("typed context bound enlarged the ordinary intent component")
	}
	d.Length++
	if cryptoLifecycleIntentDescriptorError(domain, d) == nil {
		t.Fatal("oversized typed context admitted")
	}
	_, maximum = completeApplyIntentDescriptorBounds(0)
	d.Count, d.Length = 0, maximum+uint64(recipientRetirementIntentExtraLength)+1
	if cryptoLifecycleIntentDescriptorError(domain, d) == nil {
		t.Fatal("zero-entry context exceeded retirement capacity")
	}
}

// full_only: false
func TestLifecycleSecretAccessRequiresExactClosedFamily(t *testing.T) {
	for _, kind := range []uint16{OperationRemoveSecretValueEntryAccess, OperationEnvelopeRekey} {
		s := lifecycleFixture()
		s.OperationKind = kind
		s.BeforeSecretCount, s.AfterSecretCount = 1, 1
		// The complete minimum is 882 bytes for one entry, one membership and
		// no name bytes. Re-key adds 147; one removed recipient adds 34 more.
		s.Normal.Intent.Length = 1029
		if kind == OperationRemoveSecretValueEntryAccess {
			s.BeforeMembershipCount = 2
			s.Normal.Union.Length = 308
			s.Exclusion.Exclusions.Count, s.Exclusion.Exclusions.Length = 1, 201
			s.Normal.Intent.Length = 1063
		}
		body, err := LifecycleBytes(s)
		if err != nil {
			t.Fatal("closed standalone lifecycle refused", kind, err)
		}
		decoded, err := InspectLifecycleSubject(body)
		if err != nil || decoded != s {
			t.Fatal("standalone lifecycle kind lost", kind, err)
		}
		for _, condition := range []string{"no secret", "changed entries", "changed raw", "changed access", "no target change", "two target changes", "grant", "wrong exclusions", "wrong memberships", "ordinary length"} {
			t.Run(fmt.Sprintf("%d/%s", kind, condition), func(t *testing.T) {
				bad := s
				switch condition {
				case "no secret":
					bad.BeforeSecretCount, bad.AfterSecretCount = 0, 0
				case "changed entries":
					bad.AfterValueEntryCount = 0
				case "changed raw":
					bad.AfterRawBytes++
				case "changed access":
					bad.AfterAccessRoot = bad.BeforeAccessRoot
				case "no target change":
					bad.Normal.Changed = 0
				case "two target changes":
					bad.Normal.Changed = 2
				case "grant":
					bad.Grant.Grants.Count = 1
				case "wrong exclusions":
					bad.Exclusion.Exclusions.Count = 1 - s.Exclusion.Exclusions.Count
				case "wrong memberships":
					if kind == OperationRemoveSecretValueEntryAccess {
						bad.BeforeMembershipCount = bad.AfterMembershipCount
					} else {
						bad.BeforeMembershipCount++
					}
				case "ordinary length":
					bad.Normal.Intent.Length = 882
				}
				if _, err := LifecycleBytes(bad); err != ErrSubject {
					t.Fatal("invalid standalone lifecycle admitted", kind, err)
				}
			})
		}
	}
}
