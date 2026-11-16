package format

import (
	"bytes"
	"encoding/binary"
	"testing"

	"enkv.sh/core/contract"
)

func endWorkHeadFixture(t *testing.T) Head {
	t.Helper()
	h := headFixture(t)
	coreBytes, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	conditionalBytes, err := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family,
		Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody,
		Condition: conditionFixture(h.Core.PreviousToken), HeadCore: contract.Hash(coreBytes), HeadCoreLength: uint32(len(coreBytes))})
	if err != nil {
		t.Fatal(err)
	}
	d := func(b byte) contract.GeneratorDescriptor {
		return contract.GeneratorDescriptor{Digest: fid(b), Length: 42, Count: 1}
	}
	h.AuthKind = AdministrativeAuth
	h.Subject = contract.LifecycleSubject{}
	h.EndWork = &contract.EndWorkSubject{Schema: contract.CanonicalSchema, DomainID: h.Core.Domain,
		OperationID: fid(40), AdmissionID: fid(42),
		PredecessorRevisionID: h.Core.PreviousRevision, PredecessorFullHEADDigest: h.Core.PreviousDigest,
		PredecessorToken: h.Core.PreviousToken, TargetGroupID: fid(44), TargetOwnerID: fid(45), TargetID: fid(46),
		TargetKind: 2, DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing,
		DependentGroups: d(47), RemovedSupport: d(48),
		PreservedCurrent: contract.DigestLength{Digest: fid(49), Length: 1000},
		BeforeAccessRoot: fid(51), AfterAccessRoot: fid(52),
		BeforeAccessIncarnationID: fid(53), AfterAccessIncarnationID: fid(53),
		BeforeAccessGeneration: 1, AfterAccessGeneration: 2,
		BeforeChildCount: 10, AfterChildCount: 9, BeforeChildBytes: 10000, AfterChildBytes: 9000,
		ReceiptDeltaDigest: fid(50), HeadCoreDigest: contract.Hash(coreBytes), HeadCoreLength: uint32(len(coreBytes)),
		ConditionalPlanDigest: contract.Hash(conditionalBytes)}
	h.EndWork.RequestCoreDigest, err = contract.EndWorkRequestCoreDigest(*h.EndWork)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// full_only: false
func TestEndWorkHeadClosedRoundTripAndExactPredecessor(t *testing.T) {
	h := endWorkHeadFixture(t)
	b, err := EncodeHead(h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeHead(b)
	if err != nil || got.AuthKind != AdministrativeAuth || got.EndWork == nil || *got.EndWork != *h.EndWork ||
		!bytes.Equal(got.K1, h.K1) || !bytes.Equal(got.AuthorizationSignature, h.AuthorizationSignature) {
		t.Fatalf("decoded=%#v err=%v", got, err)
	}
	for name, change := range map[string]func(*Head){
		"old digest": func(h *Head) { h.EndWork.PredecessorFullHEADDigest = fid(97) },
		"old token":  func(h *Head) { h.EndWork.PredecessorToken.Value = `"different"` },
		"root kind":  func(h *Head) { h.AuthKind = LifecycleAuth },
	} {
		t.Run(name, func(t *testing.T) {
			bad := h
			copy := *h.EndWork
			bad.EndWork = &copy
			change(&bad)
			if _, err := EncodeHead(bad); err == nil {
				t.Fatal("changed administrative HEAD encoded")
			}
		})
	}
}

// full_only: false
func TestEndWorkHeadValidatesOptionalRecoveryProofFraming(t *testing.T) {
	for _, present := range []bool{false, true} {
		h := endWorkHeadFixture(t)
		if present {
			h.K3 = bytes.Clone(h.K1)
		}
		encoded, err := EncodeHead(h)
		if err != nil {
			t.Fatal("valid optional recovery proof refused", present, err)
		}
		decoded, err := DecodeHead(encoded)
		if err != nil || !bytes.Equal(decoded.K3, h.K3) {
			t.Fatal("optional recovery proof changed", present, err)
		}
	}
	for name, proof := range map[string][]byte{
		"one-byte":      {1},
		"malformed-der": {0x30, 1, 0},
		"oversized":     bytes.Repeat([]byte{1}, contract.MaxSignature+1),
	} {
		t.Run(name, func(t *testing.T) {
			h := endWorkHeadFixture(t)
			h.K3 = proof
			if _, err := EncodeHead(h); err == nil {
				t.Error("malformed optional recovery proof encoded")
			}
			h.K3 = nil
			encoded, err := EncodeHead(h)
			if err != nil {
				t.Fatal(err)
			}
			// HEAD starts with its seven-byte prefix, B(core), B(K1), B(K3).
			offset := 7
			for range 2 {
				offset += 4 + int(binary.BigEndian.Uint32(encoded[offset:]))
			}
			end := offset + 4 + int(binary.BigEndian.Uint32(encoded[offset:]))
			damaged := append(bytes.Clone(encoded[:offset]), binary.BigEndian.AppendUint32(nil, uint32(len(proof)))...)
			damaged = append(damaged, proof...)
			damaged = append(damaged, encoded[end:]...)
			if _, err := DecodeHead(damaged); err == nil {
				t.Error("stored malformed optional recovery proof accepted")
			}
		})
	}
}
