package contract

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// full_only: false
func TestCryptoAccessClaimCurrentLayout(t *testing.T) {
	probe, _ := successorKEKProbeVector()
	id := successionTestID
	ref := successionExpectedIDs([]byte{3, 0, 11}, id(5), id(11), id(12))
	ref = binary.BigEndian.AppendUint32(ref, 100)
	ref = append(ref, 0, 0)
	copy(probe.Context.PredecessorRootRef[:], ref)
	v := CryptoAccessClaimRequest{CryptoAccessFreezeRequest: CryptoAccessFreezeRequest{
		OperationRef: id(20), Context: probe.Context,
		IdentityPlanDescriptor:         DescriptorVector{Digest: id(21), Length: 162},
		ExpectedCoverageDescriptor:     DescriptorVector{Digest: id(22), Length: 178},
		AfterAccessRowsDescriptor:      DescriptorVector{Digest: id(23), Length: 7},
		CandidatePublicStateDescriptor: DescriptorVector{Digest: id(24), Length: 143},
		CandidateAccessRoot:            id(25),
		UnchangedMaterialDescriptor:    DescriptorVector{Digest: id(26), Length: 144},
		FinalTranscriptDigest:          id(27),
	}, FactDigest: id(28)}
	// Build the current context without an encoder or production size constant.
	// Four IDs remain before expiry; no caller or access-grant ID is present.
	c := successionExpectedIDs([]byte{2}, id(1), id(2), id(5), id(6))
	c = binary.BigEndian.AppendUint64(c, 1)
	c = successionExpectedIDs(c, id(7))
	c = append(c, ref...)
	c = successionExpectedIDs(c, id(8), id(9))
	c = binary.BigEndian.AppendUint64(c, 430)
	c = binary.BigEndian.AppendUint32(c, 1)
	c = successionExpectedIDs(c, id(10))
	want := successionExpectedBlob(successionExpectedIDs(nil, id(20)), c)
	appendDescriptor := func(d DescriptorVector) {
		want = successionExpectedIDs(want, d.Digest)
		want = binary.BigEndian.AppendUint64(want, d.Length)
		want = binary.BigEndian.AppendUint32(want, d.Count)
	}
	appendDescriptor(v.IdentityPlanDescriptor)
	appendDescriptor(v.ExpectedCoverageDescriptor)
	appendDescriptor(v.AfterAccessRowsDescriptor)
	appendDescriptor(v.CandidatePublicStateDescriptor)
	want = successionExpectedIDs(want, id(25))
	appendDescriptor(v.UnchangedMaterialDescriptor)
	want = successionExpectedIDs(want, id(27), id(28))
	// Freeze: 32 + (4+382) + 5*44 + 2*32 =702. Claim adds32.
	if len(c) != 382 || len(want) != 734 {
		t.Fatal("independent access claim field count", len(c), len(want))
	}
	got, err := EncodeCryptoAccessClaimRequest(v)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("current access claim differs from independent fields", err)
	}
	decoded, err := DecodeCryptoAccessClaimRequest(want)
	if err != nil || decoded != v {
		t.Fatal("current access claim round trip", err)
	}
	for n := range want {
		if _, err := DecodeCryptoAccessClaimRequest(want[:n]); err == nil {
			t.Fatal("truncated claim accepted", n)
		}
	}
	for _, malformed := range [][]byte{append(bytes.Clone(want), 0), append(bytes.Clone(want), make([]byte, 64)...)} {
		if _, err := DecodeCryptoAccessClaimRequest(malformed); err == nil {
			t.Fatal("trailing or obsolete-width claim accepted", len(malformed))
		}
	}
}
