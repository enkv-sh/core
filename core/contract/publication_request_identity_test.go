package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"testing"
)

func publicationRequestIdentityTarget() PublicationRequestTarget {
	return PublicationRequestTarget{CoordinateID: publicationTestID(3), BindingIncarnationID: publicationTestID(4),
		EntryIncarnationID: publicationTestID(5), TargetRowDigest: publicationTestID(6),
		ValueBasisDigest: publicationTestID(8), PolicyDigest: publicationTestID(9),
		ServiceContractID: "profile", TargetContractID: "3", ProtocolID: publicationTestID(12),
		ConfigContractDigest: publicationTestID(13), ArtifactContractID: publicationTestID(14),
		ExecutorID: publicationTestID(15), CredentialRouteID: publicationTestID(16)}
}

// full_only: false
func TestPublicationRequestTargetsDescriptorHasIndependentCanonicalPreimage(t *testing.T) {
	row := publicationRequestIdentityTarget()
	row.BlockerIDs = []ID{publicationTestID(20), publicationTestID(21)}
	before := append([]ID(nil), row.BlockerIDs...)
	got, err := PublicationRequestTargetsDescriptor(publicationTestID(1), []PublicationRequestTarget{row})
	if err != nil {
		t.Fatal(err)
	}
	// Construct the documented framing independently: raw prefix/domain,
	// BE16 row count, six IDs, BE32 UTF-8 blobs, five IDs, BE16 blockers,
	// raw blocker IDs and one zero action-count byte. No production codec
	// or descriptor constructor contributes expected bytes.
	want := append([]byte("ENKV/PUBLICATION/REQUEST-TARGETS/v3\x00"), bytes.Repeat([]byte{1}, 32)...)
	want = append(want, 0, 1)
	for _, n := range []byte{3, 4, 5, 6, 8, 9} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, 0, 0, 0, 7)
	want = append(want, "profile"...)
	want = append(want, 0, 0, 0, 1, '3')
	for _, n := range []byte{12, 13, 14, 15, 16} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, 0, 2)
	for _, n := range []byte{20, 21} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, 0)
	if got != (DescriptorVector{Digest: sha256.Sum256(want), Length: uint64(len(want)), Count: 1}) {
		t.Fatal("request target descriptor changed its exact framing", got)
	}
	if !reflect.DeepEqual(row.BlockerIDs, before) {
		t.Fatal("descriptor construction changed borrowed blockers")
	}
}

// full_only: false
func TestPublicationRequestIdentityBindsEveryAdmittedObservationField(t *testing.T) {
	row := publicationRequestIdentityTarget()
	targets, err := PublicationRequestTargetsDescriptor(publicationTestID(1), []PublicationRequestTarget{row})
	if err != nil {
		t.Fatal(err)
	}
	observation := PublicationRequestObservation{DomainID: publicationTestID(1), OperationID: publicationTestID(30),
		HEADRevisionID: publicationTestID(31), HEADDigest: publicationTestID(32), TokenDigest: publicationTestID(33),
		Snapshot:        Ref{Kind: RootKind, Format: CanonicalSchema, Domain: publicationTestID(1), Object: publicationTestID(34), Length: 99, Digest: publicationTestID(35)},
		SelectionDigest: publicationTestID(32), ActingRecipientID: publicationTestID(11), Targets: targets, Nonce: publicationTestID(36)}
	got, err := PublicationRequestIdentity(observation)
	if err != nil {
		t.Fatal(err)
	}
	// Root Ref framing is kind/u16 format/domain/object/digest/u32 length/
	// u16 index. This fixed independent preimage also checks descriptor framing.
	want := []byte("ENKV/PUBLICATION/REQUEST/v3\x00")
	want = append(want, 0, 2)
	for _, n := range []byte{1, 30, 31, 32, 33} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, byte(RootKind), 0, byte(CanonicalSchema))
	for _, n := range []byte{1, 34, 35} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, 0, 0, 0, 99, 0, 0)
	for _, n := range []byte{32, 11} {
		want = append(want, bytes.Repeat([]byte{n}, 32)...)
	}
	want = append(want, targets.Digest[:]...)
	want = binary.BigEndian.AppendUint64(want, targets.Length)
	want = binary.BigEndian.AppendUint32(want, targets.Count)
	want = append(want, bytes.Repeat([]byte{36}, 32)...)
	if got != sha256.Sum256(want) {
		t.Fatal("publication request identity differs from independent canonical bytes")
	}
	for name, mutate := range map[string]func(*PublicationRequestObservation){
		"operation": func(v *PublicationRequestObservation) { v.OperationID = publicationTestID(90) },
		"revision":  func(v *PublicationRequestObservation) { v.HEADRevisionID = publicationTestID(90) },
		"head": func(v *PublicationRequestObservation) {
			v.HEADDigest, v.SelectionDigest = publicationTestID(90), publicationTestID(90)
		},
		"token":    func(v *PublicationRequestObservation) { v.TokenDigest = publicationTestID(90) },
		"snapshot": func(v *PublicationRequestObservation) { v.Snapshot.Object = publicationTestID(90) },
		"acting":   func(v *PublicationRequestObservation) { v.ActingRecipientID = publicationTestID(90) },
		"targets":  func(v *PublicationRequestObservation) { v.Targets.Digest = publicationTestID(90) },
		"nonce":    func(v *PublicationRequestObservation) { v.Nonce = publicationTestID(90) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := observation
			mutate(&changed)
			other, err := PublicationRequestIdentity(changed)
			if err != nil || other == got {
				t.Fatal("admitted observation field was not bound", err)
			}
		})
	}
}

// full_only: false
func TestPublicationRequestTargetsRejectAmbiguousCoordinatesAndBlockers(t *testing.T) {
	base := publicationRequestIdentityTarget()
	for name, rows := range map[string][]PublicationRequestTarget{
		"duplicate-coordinate": {base, base},
		"zero-coordinate":      {func() PublicationRequestTarget { r := base; r.CoordinateID = ID{}; return r }()},
		"duplicate-blocker": {func() PublicationRequestTarget {
			r := base
			r.BlockerIDs = []ID{publicationTestID(20), publicationTestID(20)}
			return r
		}()},
		"unordered-blockers": {func() PublicationRequestTarget {
			r := base
			r.BlockerIDs = []ID{publicationTestID(21), publicationTestID(20)}
			return r
		}()},
		"zero-blocker": {func() PublicationRequestTarget { r := base; r.BlockerIDs = []ID{{}}; return r }()},
		"service-contract-overflow": {func() PublicationRequestTarget {
			r := base
			r.ServiceContractID = string(bytes.Repeat([]byte{'p'}, 257))
			return r
		}()},
		"target-contract-overflow": {func() PublicationRequestTarget {
			r := base
			r.TargetContractID = string(bytes.Repeat([]byte{'3'}, 257))
			return r
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PublicationRequestTargetsDescriptor(publicationTestID(1), rows); err == nil {
				t.Fatal("ambiguous request targets accepted")
			}
		})
	}
	if _, err := PublicationRequestIdentity(PublicationRequestObservation{}); err == nil {
		t.Fatal("unadmitted zero observation acquired a request identity")
	}
}

// full_only: false
func TestPublicationRequestTargetsCompleteMaximum(t *testing.T) {
	protocol := publicationContractVectorID(t, "c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2")
	domain, config := publicationTestID(1), publicationTestID(2)
	service, target := string(bytes.Repeat([]byte{'s'}, 256)), string(bytes.Repeat([]byte{'t'}, 256))
	request, err := PublicationRequestContractDigest(protocol, config, service, target, PublicationCreateEmpty)
	if err != nil {
		t.Fatal(err)
	}
	numbered := func(namespace byte, n int) ID {
		var id ID
		id[0] = namespace
		binary.BigEndian.PutUint32(id[28:], uint32(n+1))
		return id
	}
	rows := make([]PublicationRequestTarget, 1024)
	for i := range rows {
		row := PublicationRequestTarget{CoordinateID: numbered(1, i), BindingIncarnationID: publicationTestID(3), EntryIncarnationID: publicationTestID(4), TargetRowDigest: publicationTestID(5), ServiceContractID: service, TargetContractID: target, ProtocolID: protocol, ConfigContractDigest: config, ArtifactContractID: publicationTestID(6), ExecutorID: publicationTestID(7), CredentialRouteID: publicationTestID(8), BlockerIDs: []ID{numbered(2, 2*i), numbered(2, 2*i+1)}}
		projection := PublicationProjection{Schema: 4, DomainID: domain, ConfigurationDigest: publicationTestID(9), CoordinateID: row.CoordinateID, BindingIncarnationID: row.BindingIncarnationID, EntryIncarnationID: row.EntryIncarnationID, TargetRowDigest: row.TargetRowDigest, Action: PublicationCreateEmpty, RequestContractDigest: request, ActingRecipientID: publicationTestID(10)}
		row.Actions = []PublicationRequestAction{{Projection: projection, AttemptID: numbered(3, i)}}
		rows[i] = row
	}
	descriptor, err := PublicationRequestTargetsDescriptor(domain, rows)
	// Header70; row has11 IDs352+two blobs520+blocker count2+action count1=875.
	// Each action is blob32(419)+Attempt32=455; every blocker contributes32.
	const maximum = 70 + 1024*875 + 1024*455 + 2048*32
	if err != nil || descriptor.Length != maximum {
		t.Fatal("complete target descriptor maximum", descriptor, err)
	}
	rows[0].ServiceContractID += "s"
	if _, err := PublicationRequestTargetsDescriptor(domain, rows); err == nil {
		t.Fatal("semantic row identity max+1 accepted")
	}
}
