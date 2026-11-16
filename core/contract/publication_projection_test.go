package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func publicationTestProjection() PublicationProjection {
	return PublicationProjection{Schema: 4, DomainID: publicationTestID(1), ConfigurationDigest: publicationTestID(2),
		CoordinateID: publicationTestID(3), BindingIncarnationID: publicationTestID(4),
		EntryIncarnationID: publicationTestID(5), TargetRowDigest: publicationTestID(6),
		Action: PublicationWriteValue, OwnedBirthAttemptID: publicationTestID(7),
		ValueBasisDigest: publicationTestID(8), PolicyDigest: publicationTestID(9),
		RequestContractDigest: publicationTestID(10), ActingRecipientID: publicationTestID(11)}
}

// full_only: false
func TestPublicationCoordinateV3Hash(t *testing.T) {
	domain := publicationTestID(1)
	input := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), domain[:]...)
	input = binary.BigEndian.AppendUint32(input, 1)
	input = append(input, 'p')
	input = binary.BigEndian.AppendUint32(input, 1)
	input = append(input, 't')
	want := sha256.Sum256(input)
	got, err := PublicationCoordinateID(domain, "p", "t")
	if err != nil || got != want {
		t.Fatalf("coordinate=%x want=%x err=%v", got, want, err)
	}
}

// full_only: false
func TestPublicationProjectionChangedPolicyKeepsCoordinate(t *testing.T) {
	p := publicationTestProjection()
	p.Action = PublicationUpdatePolicy
	p.ValueBasisDigest = ID{}
	first, err := PublicationProjectionCommitment(p)
	if err != nil {
		t.Fatal(err)
	}
	p.PolicyDigest = publicationTestID(12)
	second, err := PublicationProjectionCommitment(p)
	if err != nil || first == second {
		t.Fatal("policy change did not change action projection")
	}
	domain := publicationTestID(1)
	coordinate, err := PublicationCoordinateID(domain, "github-actions", "orgs/owner/actions/secrets/KEY")
	if err != nil {
		t.Fatal(err)
	}
	if same, err := PublicationCoordinateID(domain, "github-actions", "orgs/owner/actions/secrets/KEY"); err != nil || same != coordinate {
		t.Fatal("policy changed physical coordinate")
	}
}

// full_only: false
func TestPublicationProjectionV3ExactBytesAndDigest(t *testing.T) {
	p := publicationTestProjection()
	body, err := EncodePublicationProjection(p)
	if err != nil {
		t.Fatal(err)
	}
	var want []byte
	put := func(b byte) { want = append(want, bytes.Repeat([]byte{b}, 32)...) }
	want = append(want, 0, 4)
	for _, b := range []byte{1, 2, 3, 4, 5, 6} {
		put(b)
	}
	want = append(want, 3)
	for _, b := range []byte{7, 0, 0, 8, 9, 10, 11} {
		put(b)
	}
	if len(want) != 419 || !bytes.Equal(body, want) {
		t.Fatalf("body=%x want=%x", body, want)
	}
	input := append([]byte("ENKV/PUBLICATION/PROJECTION/v4\x00"), want...)
	if digest, err := PublicationProjectionCommitment(p); err != nil || digest != sha256.Sum256(input) {
		t.Fatalf("digest=%x err=%v", digest, err)
	}
	if decoded, err := InspectPublicationProjection(want); err != nil || decoded != p {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := InspectPublicationProjection(append(bytes.Clone(want), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}

	// Independent Python struct.pack/hashlib literals retain the original target
	// digest while reserved-slot deletion has zero birth, value and policy fields.
	protocol := publicationContractVectorID(t, "c0432dd35c122a5bf0b44a58234ef9aef0a2cbeb48acd2169f4bc027f322dcf2")
	config := publicationContractVectorID(t, "73a7d313254227a07dcc88482fba1ca4080c8c3772a4df4d8245a588e8654812")
	request, err := PublicationRequestContractDigest(protocol, config, "private-service", "private-target", PublicationDeleteReservedSlot)
	if wantRequest := publicationContractVectorID(t, "4dd8a372a43246e7307bd117a98ee79b6b3f708cb7f5956ec25c00aa811b88ed"); err != nil || request != wantRequest {
		t.Fatalf("reserved-slot request=%x want=%x err=%v", request, wantRequest, err)
	}
	p = PublicationProjection{Schema: 4, DomainID: publicationTestID(1), ConfigurationDigest: publicationTestID(2),
		CoordinateID:         publicationContractVectorID(t, "fb7eee5640f93d03a157aa1e445e51015937c57eacf03caa490ac885038ae66a"),
		BindingIncarnationID: publicationTestID(4), EntryIncarnationID: publicationTestID(5),
		TargetRowDigest: publicationContractVectorID(t, "0a4ac9740e8f4ac9e4c5f31e92fd86628414ad7f9e4e91a4f515bf2a1180a99a"),
		Action:          PublicationDeleteReservedSlot, UncertainCreateAttemptID: publicationTestID(31),
		ExclusiveNamespaceDigest: publicationTestID(32), RequestContractDigest: request, ActingRecipientID: publicationTestID(11)}
	want, err = hex.DecodeString(
		"0004" +
			"0101010101010101010101010101010101010101010101010101010101010101" +
			"0202020202020202020202020202020202020202020202020202020202020202" +
			"fb7eee5640f93d03a157aa1e445e51015937c57eacf03caa490ac885038ae66a" +
			"0404040404040404040404040404040404040404040404040404040404040404" +
			"0505050505050505050505050505050505050505050505050505050505050505" +
			"0a4ac9740e8f4ac9e4c5f31e92fd86628414ad7f9e4e91a4f515bf2a1180a99a" +
			"06" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f" +
			"2020202020202020202020202020202020202020202020202020202020202020" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"4dd8a372a43246e7307bd117a98ee79b6b3f708cb7f5956ec25c00aa811b88ed" +
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	if err != nil || len(want) != 419 {
		t.Fatal("invalid independent reserved-slot projection literal", err)
	}
	body, err = EncodePublicationProjection(p)
	if err != nil || !bytes.Equal(body, want) {
		t.Fatalf("reserved-slot body=%x want=%x err=%v", body, want, err)
	}
	wantCommitment := publicationContractVectorID(t, "02e89d701d18187802d5e19aa0d7a7929c50708df37a0a0aa00f6727baa445fc")
	if digest, err := PublicationProjectionCommitment(p); err != nil || digest != wantCommitment {
		t.Fatalf("reserved-slot commitment=%x want=%x err=%v", digest, wantCommitment, err)
	}
	if decoded, err := InspectPublicationProjection(want); err != nil || decoded != p {
		t.Fatalf("reserved-slot decoded=%#v err=%v", decoded, err)
	}
	artifact := publicationContractVectorID(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	wantResponse := publicationContractVectorID(t, "72a4d0099d5f65e501c5b1a7f86785ddaac2b87aa8ea92f3b2ac6486fd8a2f87")
	if response, err := PublicationResponseContractDigest(request, artifact); err != nil || response != wantResponse {
		t.Fatalf("reserved-slot response=%x want=%x err=%v", response, wantResponse, err)
	}
}

// full_only: false
func TestEveryPublicationProjectionFieldChangesCommitment(t *testing.T) {
	base := publicationTestProjection()
	want, err := PublicationProjectionCommitment(base)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*PublicationProjection){
		"domain":        func(v *PublicationProjection) { v.DomainID = publicationTestID(20) },
		"configuration": func(v *PublicationProjection) { v.ConfigurationDigest = publicationTestID(21) },
		"coordinate":    func(v *PublicationProjection) { v.CoordinateID = publicationTestID(22) },
		"binding":       func(v *PublicationProjection) { v.BindingIncarnationID = publicationTestID(23) },
		"entry":         func(v *PublicationProjection) { v.EntryIncarnationID = publicationTestID(24) },
		"target":        func(v *PublicationProjection) { v.TargetRowDigest = publicationTestID(25) },
		"birth":         func(v *PublicationProjection) { v.OwnedBirthAttemptID = publicationTestID(26) },
		"value":         func(v *PublicationProjection) { v.ValueBasisDigest = publicationTestID(27) },
		"policy":        func(v *PublicationProjection) { v.PolicyDigest = publicationTestID(28) },
		"request":       func(v *PublicationProjection) { v.RequestContractDigest = publicationTestID(29) },
		"recipient":     func(v *PublicationProjection) { v.ActingRecipientID = publicationTestID(30) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			next := base
			change(&next)
			got, err := PublicationProjectionCommitment(next)
			if err != nil || got == want {
				t.Fatalf("digest=%x err=%v", got, err)
			}
		})
	}
}

// full_only: false
func TestPublicationProjectionActionZeroPredicates(t *testing.T) {
	base := publicationTestProjection()
	cases := []PublicationProjection{
		func() PublicationProjection {
			v := base
			v.Action = PublicationCreateEmpty
			v.OwnedBirthAttemptID = ID{}
			v.ValueBasisDigest = ID{}
			return v
		}(),
		func() PublicationProjection {
			v := base
			v.Action = PublicationCreateWithValue
			v.OwnedBirthAttemptID = ID{}
			return v
		}(),
		base,
		func() PublicationProjection {
			v := base
			v.Action = PublicationUpdatePolicy
			v.ValueBasisDigest = ID{}
			return v
		}(),
		func() PublicationProjection {
			v := base
			v.Action = PublicationDeleteOwned
			v.ValueBasisDigest = ID{}
			v.PolicyDigest = ID{}
			return v
		}(),
		func() PublicationProjection {
			v := base
			v.Action = PublicationDeleteReservedSlot
			v.OwnedBirthAttemptID = ID{}
			v.ValueBasisDigest = ID{}
			v.PolicyDigest = ID{}
			v.UncertainCreateAttemptID = publicationTestID(31)
			v.ExclusiveNamespaceDigest = publicationTestID(32)
			return v
		}(),
	}
	for _, v := range cases {
		if _, err := EncodePublicationProjection(v); err != nil {
			t.Fatalf("action %d: %v", v.Action, err)
		}
	}
	for _, action := range []uint8{0, 7, 255} {
		bad := base
		bad.Action = action
		if _, err := EncodePublicationProjection(bad); err == nil {
			t.Fatalf("unknown action %d encoded", action)
		}
		body, err := EncodePublicationProjection(base)
		if err != nil {
			t.Fatal(err)
		}
		body[194] = action
		if _, err := InspectPublicationProjection(body); err == nil {
			t.Fatalf("unknown action %d inspected", action)
		}
	}
	bad := cases[5]
	bad.ExclusiveNamespaceDigest = ID{}
	if _, err := EncodePublicationProjection(bad); err == nil {
		t.Fatal("unproved reserved-slot delete accepted")
	}
	bad = cases[4]
	bad.PolicyDigest = publicationTestID(33)
	if _, err := EncodePublicationProjection(bad); err == nil {
		t.Fatal("delete with policy digest accepted")
	}
}

// full_only: false
func TestPublicationValueBasisAndOwnedInstanceIndependentDigests(t *testing.T) {
	domain, binding := publicationTestID(1), publicationTestID(2)
	target := outputTestTarget(3, "slot", outputTestPolicy())
	value := PublicationValueBasis{EntryIncarnationID: target.EntryIncarnationID, ValueStateID: publicationTestID(4),
		ContentLength: 18, InputEncoding: InputEncodingRaw, RetainedLength: 18, ConfidentialityClass: Secret, SemanticCommitment: publicationTestID(5)}
	basis, err := PublicationValueBasisDigest(domain, "destination", binding, target, value)
	if err != nil {
		t.Fatal(err)
	}
	var input []byte
	putID := func(id ID) { input = append(input, id[:]...) }
	putB := func(s string) {
		input = binary.BigEndian.AppendUint32(input, uint32(len(s)))
		input = append(input, s...)
	}
	input = append(input, []byte("ENKV/PUBLICATION/VALUE-BASIS/v4\x00")...)
	putID(domain)
	putB("destination")
	putID(binding)
	putID(target.EntryIncarnationID)
	putID(value.ValueStateID)
	input = binary.BigEndian.AppendUint32(input, value.ContentLength)
	input = append(input, value.InputEncoding)
	input = binary.BigEndian.AppendUint32(input, value.RetainedLength)
	input = append(input, Secret)
	putID(value.SemanticCommitment)
	for _, s := range []string{target.ServiceContractID, target.CanonicalTarget, target.TargetContractID} {
		putB(s)
	}
	input = append(input, target.PayloadEncoding)
	if want := sha256.Sum256(input); basis != want {
		t.Fatalf("basis=%x want=%x", basis, want)
	}
	coordinate, err := PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
	if err != nil {
		t.Fatal(err)
	}
	row, err := PublicationTargetRowDigest(domain, "destination", binding, target)
	if err != nil {
		t.Fatal(err)
	}
	birth := publicationTestID(6)
	owner, err := PublicationOwnedInstanceDigest(domain, coordinate, binding, target.EntryIncarnationID, row, birth, "instance")
	if err != nil {
		t.Fatal(err)
	}
	input = append([]byte("ENKV/PUBLICATION/OWNED-INSTANCE/v2\x00"), domain[:]...)
	for _, id := range []ID{coordinate, binding, target.EntryIncarnationID, row, birth} {
		putID(id)
	}
	putB("instance")
	if want := sha256.Sum256(input); owner != want {
		t.Fatalf("owner=%x want=%x", owner, want)
	}
	selected, err := PublicationSelectedValueDigest(domain, basis, birth, owner)
	if err != nil {
		t.Fatal(err)
	}
	input = append([]byte("ENKV/PUBLICATION/SELECTED-VALUE/v2\x00"), domain[:]...)
	for _, id := range []ID{basis, birth, owner} {
		putID(id)
	}
	if want := sha256.Sum256(input); selected != want {
		t.Fatalf("selected=%x want=%x", selected, want)
	}
	value.SemanticCommitment = publicationTestID(7)
	if changed, err := PublicationValueBasisDigest(domain, "destination", binding, target, value); err != nil || changed == basis {
		t.Fatal("changed selected value inherited basis")
	}
	target.Policy = OutputPolicy{ContractID: "class", Data: []byte{7}}
	if same, err := PublicationValueBasisDigest(domain, "destination", binding, target, PublicationValueBasis{EntryIncarnationID: target.EntryIncarnationID, ValueStateID: publicationTestID(4), ContentLength: 18, InputEncoding: InputEncodingRaw, RetainedLength: 18, ConfidentialityClass: Secret, SemanticCommitment: publicationTestID(5)}); err != nil || same != basis {
		t.Fatal("policy altered value equality")
	}
}

// full_only: false
func TestPublicationValueBasisExcludesPassivePolicyAndCapabilityFacts(t *testing.T) {
	domain, binding := publicationTestID(1), publicationTestID(2)
	target := outputTestTarget(3, "physical", outputTestPolicy())
	value := PublicationValueBasis{EntryIncarnationID: target.EntryIncarnationID, ValueStateID: publicationTestID(4), ContentLength: 1, InputEncoding: InputEncodingRaw, RetainedLength: 1, ConfidentialityClass: Plain, SemanticCommitment: publicationTestID(5)}
	basis, err := PublicationValueBasisDigest(domain, "destination", binding, target, value)
	if err != nil {
		t.Fatal(err)
	}
	row, err := PublicationTargetRowDigest(domain, "destination", binding, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*OutputTarget){func(v *OutputTarget) { v.Policy = OutputPolicy{ContractID: "other", Data: []byte{0, 255}} }, func(v *OutputTarget) { v.Capabilities = OutputCapabilityCreateEmpty }, func(v *OutputTarget) { v.CreateValueBounds = OutputPayloadBounds{Minimum: 1, Maximum: 7} }, func(v *OutputTarget) { v.WriteValueBounds = OutputPayloadBounds{Maximum: 9} }, func(v *OutputTarget) { v.TargetData = []byte("changed interpretation") }, func(v *OutputTarget) { v.ConsumerLocator = "other-reference" }} {
		changed := target
		change(&changed)
		got, err := PublicationValueBasisDigest(domain, "destination", binding, changed, value)
		if err != nil || got != basis {
			t.Fatal("passive facts forced value write", err)
		}
		digest, err := PublicationTargetRowDigest(domain, "destination", binding, changed)
		if err != nil || digest == row {
			t.Fatal("target row lost passive facts", err)
		}
	}
	for _, change := range []func(*OutputTarget){func(v *OutputTarget) { v.ServiceContractID = "other-service" }, func(v *OutputTarget) { v.TargetContractID = "other-target" }, func(v *OutputTarget) { v.CanonicalTarget = "other-physical" }, func(v *OutputTarget) { v.PayloadEncoding = OutputEncodingBase64 }} {
		changed := target
		change(&changed)
		got, err := PublicationValueBasisDigest(domain, "destination", binding, changed, value)
		if err != nil || got == basis {
			t.Fatal("value basis lost payload meaning", err)
		}
	}
}
