package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
)

func outputHeadFixture(t *testing.T, closeResult bool) Head {
	t.Helper()
	h := headFixture(t)
	h.Subject = contract.LifecycleSubject{}
	core, err := EncodeHeadCore(h.Core)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.MatchHeadCondition(h.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := EncodeConditionalPlan(ConditionalPlan{Family: h.Core.PreviousToken.Family,
		Store: h.Core.Store, Coordinate: h.Core.Coordinate, NonBody: h.Core.NonBody,
		Condition: condition, HeadCore: contract.Hash(core), HeadCoreLength: uint32(len(core))})
	if err != nil {
		t.Fatal(err)
	}
	if closeResult {
		h.AuthKind = OutputCloseAuth
		h.OutputClose = &contract.OutputCloseSubject{Schema: 4, Action: contract.PublicationWriteValue,
			DomainID: h.Core.Domain, OperationID: fid(30), AttemptID: fid(31),
			ReservationAdmissionDigest: fid(34),
			PredecessorRevisionID:      h.Core.PreviousRevision, PredecessorFullHEADDigest: h.Core.PreviousDigest,
			PredecessorToken: h.Core.PreviousToken, CurrentAccessRoot: fid(35), ConfigurationDigest: fid(36),
			CoordinateID: fid(37), BindingIncarnationID: fid(38), EntryIncarnationID: fid(39),
			TargetRowDigest: fid(40), OwnedBirthAttemptID: fid(41), ActionProjectionCommitment: fid(42),
			EntryClass: contract.PublicationMayHaveEnteredEntry, ResultClass: contract.PublicationRequestAcknowledged,
			ResultEvidenceDigest: fid(43), HeadCoreDigest: contract.Hash(core), HeadCoreLength: uint32(len(core)),
			ConditionalPlanDigest: contract.Hash(plan)}
		return h
	}
	h.AuthKind = OutputReserveAuth
	h.OutputReserve = &contract.OutputReserveSubject{Schema: 5, PublicationIncarnationID: fid(47), AdmissionOrdinal: 1, Action: contract.PublicationWriteValue,
		DomainID: h.Core.Domain, OperationID: fid(30), AttemptID: fid(31),
		PredecessorRevisionID:     h.Core.PreviousRevision,
		PredecessorFullHEADDigest: h.Core.PreviousDigest, PredecessorToken: h.Core.PreviousToken,
		CurrentAccessRoot: fid(35), ConfigurationDigest: fid(36), CoordinateID: fid(37),
		BindingIncarnationID: fid(38), EntryIncarnationID: fid(39), TargetRowDigest: fid(40),
		BirthTargetRowDigest: fid(46),
		OwnedBirthAttemptID:  fid(41), ValueBasisDigest: fid(42), PolicyDigest: fid(43),
		RequestContractDigest: fid(44), DispatchContextDigest: fid(45),
		HeadCoreDigest: contract.Hash(core), HeadCoreLength: uint32(len(core)),
		ConditionalPlanDigest: contract.Hash(plan)}
	return h
}

// full_only: false
func TestOutputHeadsClosedRoundTripAndExactPredecessor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close bool
	}{{"reserve", false}, {"close", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := outputHeadFixture(t, tc.close)
			body, err := EncodeHead(h)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeHead(body)
			if err != nil || decoded.AuthKind != h.AuthKind || decoded.Core != h.Core ||
				!bytes.Equal(decoded.K1, h.K1) || !bytes.Equal(decoded.AuthorizationSignature, h.AuthorizationSignature) {
				t.Fatal("typed output HEAD did not round-trip", err)
			}
			if tc.close {
				if decoded.OutputClose == nil || *decoded.OutputClose != *h.OutputClose || decoded.OutputReserve != nil {
					t.Fatal("close subject or type changed")
				}
			} else if decoded.OutputReserve == nil || *decoded.OutputReserve != *h.OutputReserve || decoded.OutputClose != nil {
				t.Fatal("reserve subject or type changed")
			}
			for name, change := range map[string]func(*Head){
				"wrong predecessor revision": func(h *Head) { h.Core.PreviousRevision = fid(99) },
				"wrong predecessor digest":   func(h *Head) { h.Core.PreviousDigest = fid(98) },
				"wrong predecessor token":    func(h *Head) { h.Core.PreviousToken.Value = `"different"` },
				"wrong root":                 func(h *Head) { h.Core.Root.Digest = fid(97) },
				"wrong conditional plan": func(h *Head) {
					if h.OutputReserve != nil {
						h.OutputReserve.ConditionalPlanDigest = fid(96)
					} else {
						h.OutputClose.ConditionalPlanDigest = fid(96)
					}
				},
				"malformed recovery basis": func(h *Head) { h.K3 = []byte{1} },
				"foreign subject":          func(h *Head) { h.Subject = headFixture(t).Subject },
				"wrong kind":               func(h *Head) { h.AuthKind = GenesisAuth },
			} {
				t.Run(name, func(t *testing.T) {
					bad := h
					if h.OutputReserve != nil {
						reserve := *h.OutputReserve
						bad.OutputReserve = &reserve
					}
					if h.OutputClose != nil {
						close := *h.OutputClose
						bad.OutputClose = &close
					}
					change(&bad)
					if _, err := EncodeHead(bad); err == nil {
						t.Fatal("altered output HEAD encoded")
					}
				})
			}
		})
	}
}

// full_only: false
func TestOutputHeadsRejectMixedSubjectVariants(t *testing.T) {
	h := outputHeadFixture(t, false)
	other := outputHeadFixture(t, true)
	h.OutputClose = other.OutputClose
	if _, err := EncodeHead(h); err == nil {
		t.Fatal("reserve HEAD admitted a close subject")
	}
	h = headFixture(t)
	h.OutputReserve = outputHeadFixture(t, false).OutputReserve
	if _, err := EncodeHead(h); err == nil {
		t.Fatal("legacy HEAD admitted an output subject")
	}
}

// full_only: false
func TestOutputHeadsRetainRecoveryBasisFraming(t *testing.T) {
	for _, closeResult := range []bool{false, true} {
		for _, basis := range []string{"absent", "present", "malformed"} {
			t.Run(fmt.Sprintf("%t/%s", closeResult, basis), func(t *testing.T) {
				head := outputHeadFixture(t, closeResult)
				if basis != "absent" {
					head.K3 = bytes.Clone(head.K1)
				}
				if basis == "malformed" {
					head.K3 = []byte{0x30, 1, 0}
				}
				body, err := EncodeHead(head)
				if basis == "malformed" {
					if err == nil {
						t.Fatal("malformed recovery basis proof encoded")
					}
					return
				}
				decoded, err := DecodeHead(body)
				if err != nil || !bytes.Equal(decoded.K3, head.K3) || decoded.AuthKind != head.AuthKind {
					t.Fatal("output HEAD lost exact optional recovery basis", err)
				}
				encoded, err := EncodeHead(decoded)
				if err != nil || !bytes.Equal(encoded, body) {
					t.Fatal("optional recovery basis framing changed", err)
				}
				if basis == "present" {
					// HEAD starts with B(core), B(K1), B(K3). Damage only K3's DER tag.
					offset := 7
					offset += 4 + int(binary.BigEndian.Uint32(body[offset:]))
					offset += 4 + int(binary.BigEndian.Uint32(body[offset:]))
					damaged := bytes.Clone(body)
					damaged[offset+4] = 0x31
					if _, err := DecodeHead(damaged); err == nil {
						t.Fatal("stored malformed recovery basis accepted")
					}
				}
			})
		}
	}
}
