package contract

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func generatedCryptoVerificationFixture(t testing.TB) CryptoGeneratedCompareRequest {
	t.Helper()
	prior := generatedCryptoCompareFixture(t, 4)
	a := generatedRecordAttempt()
	a.State, a.Stage = GeneratedEffectClosedWithResidue, GeneratedStageTerminal
	q := CryptoGeneratedCompareRequest{Context: prior.Context, Purpose: 5, Original: a,
		PlanGraph: prior.PlanGraph, UsePlanDigest: prior.UsePlanDigest, MaterialID: prior.MaterialID,
		OriginalOwnerKind: 11, OriginalOwnerID: generatedRecordID(28), Target: generatedRecordDescriptor(29),
		OriginalResult: GeneratorResultReference{Schema: 1, ResultID: a.ResultID, ResultBodyDigest: generatedRecordID(27), ResultLength: 1024}}
	var err error
	q.Context.IntentDescriptor, err = CryptoGeneratedAdmissionDescriptor(q)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// full_only: false
func TestCryptoGeneratedOriginalVerificationIndependentTailAndClosedFields(t *testing.T) {
	q := generatedCryptoVerificationFixture(t)
	if q.Context.IntentDescriptor != (DescriptorVector{Digest: generatedCryptoHexID(t, "d5874523da4214eaa00feffaab8663a1f208cb4fec07718ec23427302775805e"), Length: 1057, Count: 1}) {
		t.Fatal("independent verification admission differs")
	}
	b, err := EncodeCryptoGeneratedCompareRequest(q)
	// Independent Python big-endian concatenation: B(Context382) then kind-9 row797,
	// Attempt body760 (IDs1..18 with predecessor0, lifecycle2/state9/stage5/retry0/class1/failure0,
	// descriptors19..22 length4/count0); graph13 length300/count1, use6,
	// material7, owner-kind11/Owner28, Target29 length4/count0, ref(1,10,27,1024).
	if err != nil || len(b) != 1443 || Hash(b[386:]) != generatedCryptoHexID(t, "95222014fe59d2e5dd99cd59c1c140e1736912e7fafa457d948ace03cc7343c8") {
		t.Fatal("independent original Compare tail differs", len(b), err)
	}
	// The current Attempt has one exact body length. Both
	// support framing and the admission descriptor bind that exact length.
	t.Run("exact_attempt_framing", func(t *testing.T) {
		fresh := q
		fresh.Original.Schema = GeneratedAttemptRecordSchema
		fresh.Original.LifecycleMode = GeneratorLifecycleManaged
		fresh.Context.IntentDescriptor, err = CryptoGeneratedAdmissionDescriptor(fresh)
		if err != nil || fresh.Context.IntentDescriptor.Length != 1057 {
			t.Fatal("generic admission length differs", err)
		}
		encoded, err := EncodeCryptoGeneratedCompareRequest(fresh)
		if err != nil || len(encoded) != 1443 || binary.BigEndian.Uint32(encoded[387:391]) != 797 || binary.BigEndian.Uint32(encoded[424:428]) != 760 {
			t.Fatal("generic support framing differs", err)
		}
		got, err := InspectCryptoGeneratedCompareRequest(encoded)
		if err != nil || got != fresh {
			t.Fatal("generic original Compare traversal differs", err)
		}
	})
	for n := 0; n < len(b); n++ {
		if _, err := InspectCryptoGeneratedCompareRequest(b[:n]); err == nil {
			t.Fatal("original Compare truncation accepted", n)
		}
	}
	if got, err := InspectCryptoGeneratedCompareRequest(b); err != nil || got != q {
		t.Fatal("original Compare traversal differs", err)
	}
	for _, damage := range []func(*CryptoGeneratedCompareRequest){
		func(v *CryptoGeneratedCompareRequest) { v.Parent = generatedRecordParent() },
		func(v *CryptoGeneratedCompareRequest) { v.ParentPlan = generatedCryptoCompareFixture(t, 1).ParentPlan },
		func(v *CryptoGeneratedCompareRequest) { v.AcceptedSources = generatedRecordDescriptor(30) },
		func(v *CryptoGeneratedCompareRequest) { v.IntendedEntryPlans = generatedRecordDescriptor(30) },
		func(v *CryptoGeneratedCompareRequest) { v.Original.Stage = GeneratedStageRetainedResult },
		func(v *CryptoGeneratedCompareRequest) { v.OriginalResult.ResultID = generatedRecordID(30) },
		func(v *CryptoGeneratedCompareRequest) { v.OriginalOwnerID = ID{} },
		func(v *CryptoGeneratedCompareRequest) { v.OriginalOwnerKind = 0 },
		func(v *CryptoGeneratedCompareRequest) { v.OriginalOwnerKind = 9 },
		func(v *CryptoGeneratedCompareRequest) { v.Context.IntentDescriptor.Length = 894 },
	} {
		bad := q
		damage(&bad)
		if _, err := EncodeCryptoGeneratedCompareRequest(bad); err == nil {
			t.Fatal("changed original verification facts accepted")
		}
	}
	bad := bytes.Clone(b)
	bad[391] = 2 // actual Attempt cannot be traversed as a typed parent.
	if _, err := InspectCryptoGeneratedCompareRequest(bad); err == nil {
		t.Fatal("original typed-row substitution accepted")
	}
}

// full_only: false
func TestCryptoGeneratedOriginalVerificationAcceptsFiniteOwnerWire(t *testing.T) {
	// This scalar framing is independent of the production compare encoder.
	// The established numeric fixture keeps IDs1..18 (predecessor0), schema3,
	// state9/stage5/retry0/class1 and descriptors19..22 length4/count0.
	id := func(n byte) []byte { return bytes.Repeat([]byte{n}, 32) }
	descriptor := func(n byte, length uint64, count uint32) []byte {
		body := id(n)
		body = binary.BigEndian.AppendUint64(body, length)
		return binary.BigEndian.AppendUint32(body, count)
	}
	attempt := binary.BigEndian.AppendUint16(nil, 3)
	for _, n := range []byte{1, 2, 3, 4, 5, 0, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18} {
		attempt = append(attempt, id(n)...)
	}
	attempt = append(attempt, 2, 9, 5, 0, 1, 0)
	for n := byte(19); n <= 22; n++ {
		attempt = append(attempt, descriptor(n, 4, 0)...)
	}
	row := append([]byte{9}, id(4)...)
	row = binary.BigEndian.AppendUint32(row, uint32(len(attempt)))
	row = append(row, attempt...)
	for _, tc := range []struct {
		kind            byte
		tail, admission string
	}{
		{10, "e7af155ba64ab054715c27eec04dcc6f74ba08a80baa7c57ecbcc9a5372ed078", "b480cf06c59f00db11f9827e73558c725467703e6d4c699487bbca5b1f8c2873"},
		{11, "95222014fe59d2e5dd99cd59c1c140e1736912e7fafa457d948ace03cc7343c8", "d5874523da4214eaa00feffaab8663a1f208cb4fec07718ec23427302775805e"},
	} {
		tail := binary.BigEndian.AppendUint32([]byte{5}, uint32(len(row)))
		tail = append(tail, row...)
		tail = append(tail, descriptor(13, 300, 1)...)
		tail = append(tail, id(6)...)
		tail = append(tail, id(7)...)
		tail = append(tail, tc.kind)
		tail = append(tail, id(28)...)
		tail = append(tail, descriptor(29, 4, 0)...)
		tail = binary.BigEndian.AppendUint16(tail, 1)
		tail = append(tail, id(10)...)
		tail = append(tail, id(27)...)
		tail = binary.BigEndian.AppendUint32(tail, 1024)
		if len(tail) != 1057 || Hash(tail) != generatedCryptoHexID(t, tc.tail) {
			t.Fatal("independent owner wire setup differs", tc.kind)
		}
		q := generatedCryptoVerificationFixture(t)
		c := q.Context
		body := binary.BigEndian.AppendUint32(nil, 382)
		body = append(body, byte(c.OperationClass))
		for _, value := range []ID{c.AdmissionID, c.SessionID, c.DomainID, c.CompatibilityID} {
			body = append(body, value[:]...)
		}
		body = binary.BigEndian.AppendUint64(body, c.Expiry)
		body = append(body, c.PredecessorHEADDigest[:]...)
		body = append(body, c.PredecessorRootRef[:]...)
		body = append(body, c.OriginalConditionDigest[:]...)
		admission := generatedCryptoHexID(t, tc.admission)
		body = append(body, admission[:]...)
		body = binary.BigEndian.AppendUint64(body, 1057)
		body = binary.BigEndian.AppendUint32(body, 1)
		body = append(body, c.CurrentAccessRoot[:]...)
		body = append(body, tail...)
		decoded, err := InspectCryptoGeneratedCompareRequest(body)
		if err != nil || decoded.Original != q.Original || decoded.OriginalResult != q.OriginalResult || decoded.Target != q.Target {
			t.Fatal("finite original owner wire refused", tc.kind, err)
		}
		encoded, err := EncodeCryptoGeneratedCompareRequest(decoded)
		if err != nil || !bytes.Equal(encoded, body) {
			t.Fatal("finite original owner wire changed", tc.kind, err)
		}
	}
}
