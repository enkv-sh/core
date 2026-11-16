package contract

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func successorKEKProbeVector() (SuccessorKEKProbeCore, []byte) {
	id := successionTestID
	// The current shared context admits the ordinary class-2 descriptor range.
	// This is a byte-level probe fixture, not evidence of succession execution.
	c := ApplyContext{OperationClass: CryptoAccessReplacementClass, AdmissionID: id(1), SessionID: id(2), DomainID: id(5), CompatibilityID: id(6), Expiry: 1, PredecessorHEADDigest: id(7), OriginalConditionDigest: id(8), IntentDescriptor: DescriptorVector{Digest: id(9), Length: 430, Count: 1}, CurrentAccessRoot: id(10)}
	ref := []byte{3, 0, 11}
	ref = successionExpectedIDs(ref, id(5), id(11), id(12))
	ref = binary.BigEndian.AppendUint32(ref, 100)
	ref = append(ref, 0, 0)
	copy(c.PredecessorRootRef[:], ref)
	v := SuccessorKEKProbeCore{Schema: CanonicalSchema, Profile: 2, ProbeID: id(13), Context: c, SubjectKind: 1, SubjectID: id(14), SuccessorBindingDigest: id(15)}
	context := []byte{2}
	context = successionExpectedIDs(context, id(1), id(2), id(5), id(6))
	context = binary.BigEndian.AppendUint64(context, 1)
	context = successionExpectedIDs(context, id(7))
	context = append(context, ref...)
	context = successionExpectedIDs(context, id(8), id(9))
	context = binary.BigEndian.AppendUint64(context, 430)
	context = binary.BigEndian.AppendUint32(context, 1)
	context = successionExpectedIDs(context, id(10))
	b := successionExpectedIDs([]byte{0, 11, 0, 2}, id(13))
	b = successionExpectedBlob(b, context)
	b = append(b, 1)
	b = successionExpectedIDs(b, id(14), id(15))
	return v, b
}

// full_only: false
func TestSuccessorKEKProbeIndependentBytesAndContext(t *testing.T) {
	v, want := successorKEKProbeVector()
	got, err := EncodeSuccessorKEKProbeCore(v)
	if err != nil || len(got) != 487 || !bytes.Equal(got, want) {
		t.Fatal("KEK probe differs from independent bytes", err)
	}
	d, err := SuccessorKEKProbeMaterialContextDigest(v)
	material := successionExpectedBlob([]byte("ENKV/CRYPTO/v2/material\x00"), want)
	if err != nil || d != Hash(material) {
		t.Fatal("KEK material digest differs")
	}
	for name, change := range map[string]func(*SuccessorKEKProbeCore){
		"schema": func(v *SuccessorKEKProbeCore) { v.Schema = 1 }, "profile": func(v *SuccessorKEKProbeCore) { v.Profile = 1 },
		"signer subject": func(v *SuccessorKEKProbeCore) { v.SubjectKind = 3 }, "missing probe": func(v *SuccessorKEKProbeCore) { v.ProbeID = ID{} },
		"missing subject": func(v *SuccessorKEKProbeCore) { v.SubjectID = ID{} }, "missing binding": func(v *SuccessorKEKProbeCore) { v.SuccessorBindingDigest = ID{} },
		"wrong class": func(v *SuccessorKEKProbeCore) { v.Context.OperationClass = CryptoOrdinaryLifecycle }, "missing admission": func(v *SuccessorKEKProbeCore) { v.Context.AdmissionID = ID{} },
		"invalid root": func(v *SuccessorKEKProbeCore) { v.Context.PredecessorRootRef[0] = 1 }, "missing request": func(v *SuccessorKEKProbeCore) { v.Context.IntentDescriptor.Digest = ID{} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if _, err := SuccessorKEKProbeMaterialContextDigest(bad); err == nil {
				t.Fatal("invalid KEK probe admitted")
			}
		})
	}
}

// full_only: false
func TestSuccessionRequestDescriptorBounds(t *testing.T) {
	for _, pair := range []struct {
		count   uint32
		minimum int
	}{{1, successionSingleRequestMinimum}, {2, successionPairRequestMinimum}} {
		v := DescriptorVector{Digest: successionTestID(1), Length: uint64(pair.minimum), Count: pair.count}
		if err := successionRequestDescriptorError(v); err != nil {
			t.Fatal("lower bound refused", err)
		}
		v.Length--
		if err := successionRequestDescriptorError(v); err == nil {
			t.Fatal("short descriptor admitted")
		}
		v.Length = uint64(SuccessionRequestCoreMaxLength)
		if err := successionRequestDescriptorError(v); err != nil {
			t.Fatal("upper bound refused", err)
		}
		v.Length++
		if err := successionRequestDescriptorError(v); err == nil {
			t.Fatal("excess descriptor admitted")
		}
	}
	for _, count := range []uint32{0, 3, 256} {
		if err := successionRequestDescriptorError(DescriptorVector{Digest: successionTestID(1), Length: 10000, Count: count}); err == nil {
			t.Fatal("invalid count admitted")
		}
	}
}
