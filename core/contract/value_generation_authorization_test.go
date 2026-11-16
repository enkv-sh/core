package contract

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// The literal lists the schema, purpose and authority mask, then repeated-byte
// IDs 1..24, eight descriptors (IDs 25..32, lengths 257*n, counts n), and
// u32(2), u32(3), u32(426), u32(160), all in big-endian order. The fixed hashes
// were computed with Node's SHA-256 over the displayed bytes and exact domain
// labels, without calling a product encoder.
const generatorAuthorityRecordHex = "00020207" +
	"0101010101010101010101010101010101010101010101010101010101010101" +
	"0202020202020202020202020202020202020202020202020202020202020202" +
	"0303030303030303030303030303030303030303030303030303030303030303" +
	"0404040404040404040404040404040404040404040404040404040404040404" +
	"0505050505050505050505050505050505050505050505050505050505050505" +
	"0606060606060606060606060606060606060606060606060606060606060606" +
	"0707070707070707070707070707070707070707070707070707070707070707" +
	"0808080808080808080808080808080808080808080808080808080808080808" +
	"0909090909090909090909090909090909090909090909090909090909090909" +
	"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a" +
	"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" +
	"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" +
	"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d" +
	"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e" +
	"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" +
	"1010101010101010101010101010101010101010101010101010101010101010" +
	"1111111111111111111111111111111111111111111111111111111111111111" +
	"1212121212121212121212121212121212121212121212121212121212121212" +
	"1313131313131313131313131313131313131313131313131313131313131313" +
	"1414141414141414141414141414141414141414141414141414141414141414" +
	"1515151515151515151515151515151515151515151515151515151515151515" +
	"1616161616161616161616161616161616161616161616161616161616161616" +
	"1717171717171717171717171717171717171717171717171717171717171717" +
	"1818181818181818181818181818181818181818181818181818181818181818" +
	"1919191919191919191919191919191919191919191919191919191919191919000000000000010100000001" +
	"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a000000000000020200000002" +
	"1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b000000000000030300000003" +
	"1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c000000000000040400000004" +
	"1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d000000000000050500000005" +
	"1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e000000000000060600000006" +
	"1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f000000000000070700000007" +
	"2020202020202020202020202020202020202020202020202020202020202020000000000000080800000008" +
	"0000000200000003000001aa000000a0"

func generatorAuthorityFixture() GeneratorAuthoritySubject {
	id := generatedRecordID
	descriptor := func(n byte) GeneratorDescriptor {
		return GeneratorDescriptor{Digest: id(24 + n), Length: uint64(n) * 257, Count: uint32(n)}
	}
	return GeneratorAuthoritySubject{
		Schema: GeneratorAuthoritySubjectSchema, Purpose: GeneratorAuthorityRecord, RequiredAuthoritySet: 7,
		DomainID: id(1), OperationID: id(2), RequestIdentityDigest: id(3), PlanGraphID: id(4), UsePlanDigest: id(5), PhaseID: id(6),
		PreviousHEADDigest: id(7), PreviousRevisionID: id(8), ConditionDigest: id(9), BeforeRootDigest: id(10), AfterRootDigest: id(11),
		BeforeAccessDigest: id(12), AfterAccessDigest: id(13), OwnerID: id(14), LineageID: id(15), AttemptID: id(16), PredecessorAttemptID: id(17),
		ResultID: id(18), ResultDigest: id(19), DescriptorID: id(20), ConfigContractID: id(21), ResultContractID: id(22), HeadCoreDigest: id(23), ConditionalPlanDigest: id(24),
		Intent: descriptor(1), IdentityPlan: descriptor(2), ValueEntryUnion: descriptor(3), MembershipChanges: descriptor(4),
		BeforeWork: descriptor(5), AfterWork: descriptor(6), ResultVector: descriptor(7), CapacityReservation: descriptor(8),
		BeforePhase: 2, AfterPhase: 3, HeadCoreLength: 426, ConditionalLength: 160,
	}
}

func generatorAuthorityOperation(v *GeneratorAuthoritySubject) {
	v.LineageID, v.AttemptID, v.PredecessorAttemptID = ID{}, ID{}, ID{}
	v.ResultID, v.ResultDigest, v.DescriptorID, v.ConfigContractID, v.ResultContractID = ID{}, ID{}, ID{}, ID{}, ID{}
}

// full_only: false
func TestGeneratorAuthorityIndependentBytes(t *testing.T) {
	want, err := hex.DecodeString(generatorAuthorityRecordHex)
	if err != nil || len(want) != 1140 {
		t.Fatal("invalid independent literal", len(want), err)
	}
	v := generatorAuthorityFixture()
	got, err := EncodeGeneratorAuthoritySubject(v)
	if err != nil || len(got) != GeneratorAuthoritySubjectLength || !bytes.Equal(got, want) {
		t.Fatal("authority subject differs from independent literal", err)
	}
	decoded, err := DecodeGeneratorAuthoritySubject(want)
	if err != nil || decoded != v {
		t.Fatal("authority subject decode differs", err)
	}
	signing, err := GeneratorAuthoritySigningBytes(v)
	wantSigning := append([]byte("ENKV/GENERATOR-AUTH/v2/record\x00\x00\x00\x04\x74"), want...)
	if err != nil || !bytes.Equal(signing, wantSigning) {
		t.Fatal("authority signing preimage differs", err)
	}
	digest, err := GeneratorAuthorityDigest(v)
	if err != nil || hex.EncodeToString(digest[:]) != "666867b43a6b2992d007618bc011c830398872768d95cff721648f30fb7ef54f" || digest != Hash(signing) {
		t.Fatal("authority signing digest differs", err)
	}
}

// full_only: false
func TestGeneratorSigningUsesExactSubjectAndNormalRole(t *testing.T) {
	v := generatorAuthorityFixture()
	request, err := NewGeneratorRequest(v)
	if err != nil || !request.Valid() || request.Purpose() != GeneratorPurpose {
		t.Fatal("closed generator signing request", err)
	}
	digest := request.Digest()
	if hex.EncodeToString(digest[:]) != "666867b43a6b2992d007618bc011c830398872768d95cff721648f30fb7ef54f" {
		t.Fatal("signer input differs from independent subject digest")
	}
	if !SigningPurposeAllowed(NormalSigningRole, GeneratorPurpose) || SigningPurposeAllowed(RecoverySigningRole, GeneratorPurpose) {
		t.Fatal("generator permission crossed signing roles")
	}
	v.RequiredAuthoritySet = 0
	if _, err := NewGeneratorRequest(v); err == nil {
		t.Fatal("subject without normal authority accepted")
	}
}

// full_only: false
func TestGeneratorAuthorityPurposeSeparation(t *testing.T) {
	// Each hash uses the literal above with its numeric purpose changed. Final
	// clears IDs 15..22; reservations clear ID 19 and delete reservations also
	// clear ID 17. The prefix uses the exact name below, followed by NUL+B(body).
	for _, tc := range []struct {
		purpose      GeneratorAuthorityPurpose
		name, digest string
	}{
		{GeneratorAuthorityReservation, "reservation", "82522510ca8533818c06f613d4fb78005fb012a560f8cb9a3cea919eda79f4e1"},
		{GeneratorAuthorityRecord, "record", "666867b43a6b2992d007618bc011c830398872768d95cff721648f30fb7ef54f"},
		{GeneratorAuthorityNoEffectBranch, "no-effect-branch", "3dc192d0d96a888c3e7afc0fa9f56d35e48f7460ad527bb8283ea1cf97b4881b"},
		{GeneratorAuthorityResidue, "residue", "c164a6b403bbfa98228ee8b0a1ade8080fb89434fb09b984df7d579a962d574c"},
		{GeneratorAuthorityFinal, "final", "d44957228671cda7ebed0945d70d5eaf7f62bdccf1907bef3258bf49e627b6d7"},
		{GeneratorAuthorityFinalPreparation, "final-preparation", "7a26d1e8e59c96281fa1e6d4c3f9a6a2148adf21fead53f60d4312c34bf0ace7"},
		{GeneratorAuthorityRetireReserve, "retire-reserve", "84c4956dc01133462315894c98523c942f130c9fc6ace24428db7c62b81fc853"},
		{GeneratorAuthorityRetireClose, "retire-close", "85d09e1b5e380fe0bbd76061b152b4e3764ed20b5d43889985fcbcb27cf1123a"},
		{GeneratorAuthorityCleanupReserve, "cleanup-reserve", "fc9fe5b606d6f55645fc87e924a02ec10e520e4daddfdcc9c99359ee794e243d"},
		{GeneratorAuthorityCleanupClose, "cleanup-close", "040e9d994637c25332214754648494d3ff7e03aa3c9c77781acc12c3c2abd12f"},
		{GeneratorAuthorityReflection, "reflection", "2d0536d22dc183e48831bf90555994789683ff0861101c5eea1c24f6b1beea52"},
		{GeneratorAuthorityInboxRelease, "inbox-release", "b372f3ef03914cec41d1204de6d7aa7c93af326e4e6c982e33e3a9bc464a329d"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := generatorAuthorityFixture()
			v.Purpose = tc.purpose
			switch tc.purpose {
			case GeneratorAuthorityReservation:
				v.ResultDigest = ID{}
			case GeneratorAuthorityFinal, GeneratorAuthorityFinalPreparation:
				generatorAuthorityOperation(&v)
			case GeneratorAuthorityRetireReserve, GeneratorAuthorityCleanupReserve:
				v.ResultDigest, v.PredecessorAttemptID = ID{}, ID{}
			}
			if tc.purpose.Name() != tc.name {
				t.Fatal("purpose name differs")
			}
			got, err := GeneratorAuthorityDigest(v)
			if err != nil || hex.EncodeToString(got[:]) != tc.digest {
				t.Fatalf("purpose digest = %x, %v", got, err)
			}
			wire, err := EncodeGeneratorAuthoritySubject(v)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeGeneratorAuthoritySubject(wire)
			if err != nil || decoded != v {
				t.Fatal("purpose round trip differs", err)
			}
		})
	}
	for _, purpose := range []GeneratorAuthorityPurpose{0, 14, 255} {
		if purpose.Name() != "" {
			t.Fatal("unknown purpose has a signing label")
		}
	}
}

// full_only: false
func TestGeneratorAuthorityRefusesDamageAndCapacity(t *testing.T) {
	wire, err := hex.DecodeString(generatorAuthorityRecordHex)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(wire); n++ {
		if _, err := DecodeGeneratorAuthoritySubject(wire[:n]); err == nil {
			t.Fatalf("truncation %d accepted", n)
		}
	}
	if _, err := DecodeGeneratorAuthoritySubject(append(bytes.Clone(wire), 0)); !errors.Is(err, ErrRecordCapacity) {
		t.Fatal("excess subject did not refuse capacity", err)
	}
	for _, offset := range []int{1, 2, 3} {
		bad := bytes.Clone(wire)
		bad[offset] = 255
		if _, err := DecodeGeneratorAuthoritySubject(bad); err == nil {
			t.Fatalf("unknown tag at %d accepted", offset)
		}
	}
	for i := 0; i < 24; i++ {
		if i == 16 {
			continue
		} // Branch zero has no predecessor Attempt.
		bad := bytes.Clone(wire)
		clear(bad[4+i*32 : 4+(i+1)*32])
		if _, err := DecodeGeneratorAuthoritySubject(bad); err == nil {
			t.Fatalf("missing record identity %d accepted", i)
		}
	}
	for i := 0; i < 8; i++ {
		bad := bytes.Clone(wire)
		clear(bad[772+i*44 : 772+i*44+32])
		if _, err := DecodeGeneratorAuthoritySubject(bad); err == nil {
			t.Fatalf("missing descriptor %d accepted", i)
		}
		bad = bytes.Clone(wire)
		clear(bad[772+i*44+32 : 772+i*44+40])
		if _, err := DecodeGeneratorAuthoritySubject(bad); err == nil {
			t.Fatalf("invalid descriptor length %d accepted", i)
		}
	}
	for name, change := range map[string]func(*GeneratorAuthoritySubject){
		"schema":                  func(v *GeneratorAuthoritySubject) { v.Schema = 5 },
		"purpose":                 func(v *GeneratorAuthoritySubject) { v.Purpose = 14 },
		"no normal authority":     func(v *GeneratorAuthoritySubject) { v.RequiredAuthoritySet = 6 },
		"unknown authority":       func(v *GeneratorAuthoritySubject) { v.RequiredAuthoritySet = 9 },
		"initial record":          func(v *GeneratorAuthoritySubject) { v.BeforePhase, v.AfterPhase = 0, 1 },
		"same phase":              func(v *GeneratorAuthoritySubject) { v.AfterPhase = v.BeforePhase },
		"skipped phase":           func(v *GeneratorAuthoritySubject) { v.AfterPhase += 1 },
		"phase overflow":          func(v *GeneratorAuthoritySubject) { v.BeforePhase, v.AfterPhase = ^uint32(0), 0 },
		"short head":              func(v *GeneratorAuthoritySubject) { v.HeadCoreLength, v.ConditionalLength = 418, 152 },
		"long head":               func(v *GeneratorAuthoritySubject) { v.HeadCoreLength, v.ConditionalLength = 675, 409 },
		"unequal conditional":     func(v *GeneratorAuthoritySubject) { v.ConditionalLength = 159 },
		"long conditional":        func(v *GeneratorAuthoritySubject) { v.ConditionalLength = 410 },
		"empty descriptor length": func(v *GeneratorAuthoritySubject) { v.Intent.Count = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			v := generatorAuthorityFixture()
			change(&v)
			if _, err := EncodeGeneratorAuthoritySubject(v); err == nil {
				t.Fatal("invalid subject encoded")
			}
			if _, err := GeneratorAuthoritySigningBytes(v); err == nil {
				t.Fatal("invalid subject received signing bytes")
			}
			if _, err := GeneratorAuthorityDigest(v); err == nil {
				t.Fatal("invalid subject received signing digest")
			}
		})
	}
	for _, mask := range []uint8{1, 3, 5, 7} {
		for _, lengths := range [][2]uint32{{419, 153}, {419, 154}, {674, 408}, {674, 409}} {
			v := generatorAuthorityFixture()
			v.RequiredAuthoritySet = mask
			v.HeadCoreLength, v.ConditionalLength = lengths[0], lengths[1]
			if _, err := EncodeGeneratorAuthoritySubject(v); err != nil {
				t.Fatal("valid structural boundary refused", mask, lengths, err)
			}
		}
	}
}

// full_only: false
func TestGeneratorAuthorityPurposeSpecificFields(t *testing.T) {
	for _, purpose := range []GeneratorAuthorityPurpose{GeneratorAuthorityReservation, GeneratorAuthorityFinal} {
		v := generatorAuthorityFixture()
		v.Purpose = purpose
		generatorAuthorityOperation(&v)
		if _, err := EncodeGeneratorAuthoritySubject(v); err != nil {
			t.Fatal("operation subject refused", err)
		}
		for i := 0; i < 8; i++ {
			bad := v
			fields := []*ID{&bad.LineageID, &bad.AttemptID, &bad.PredecessorAttemptID, &bad.ResultID, &bad.ResultDigest, &bad.DescriptorID, &bad.ConfigContractID, &bad.ResultContractID}
			*fields[i] = generatedRecordID(40)
			if _, err := EncodeGeneratorAuthoritySubject(bad); err == nil {
				t.Fatal("partial operation tuple accepted", purpose, i)
			}
		}
		v.BeforePhase, v.AfterPhase = 0, 1
		_, err := EncodeGeneratorAuthoritySubject(v)
		if (err == nil) != (purpose == GeneratorAuthorityReservation) {
			t.Fatal("initial authority purpose differs", purpose, err)
		}
	}
	for _, purpose := range []GeneratorAuthorityPurpose{GeneratorAuthorityRecord, GeneratorAuthorityNoEffectBranch, GeneratorAuthorityRetireClose, GeneratorAuthorityCleanupClose, GeneratorAuthorityReflection, GeneratorAuthorityInboxRelease} {
		v := generatorAuthorityFixture()
		v.Purpose = purpose
		v.PredecessorAttemptID = ID{}
		if _, err := EncodeGeneratorAuthoritySubject(v); err != nil {
			t.Fatal("original branch subject refused", purpose, err)
		}
		v.ResultDigest = ID{}
		// Inbox release binds a frozen original object, not an assertion that
		// this object still exists. Handoff and no-consumer checks belong to Core.
		if _, err := EncodeGeneratorAuthoritySubject(v); err == nil {
			t.Fatal("result-bound purpose omitted frozen digest", purpose)
		}
	}
	v := generatorAuthorityFixture()
	v.Purpose = GeneratorAuthorityResidue
	v.ResultDigest = ID{}
	v.PredecessorAttemptID = ID{}
	if _, err := EncodeGeneratorAuthoritySubject(v); err != nil {
		t.Fatal("uncertain residue required terminal evidence", err)
	}
	for _, purpose := range []GeneratorAuthorityPurpose{GeneratorAuthorityReservation, GeneratorAuthorityRetireReserve, GeneratorAuthorityCleanupReserve} {
		v := generatorAuthorityFixture()
		v.Purpose = purpose
		if _, err := EncodeGeneratorAuthoritySubject(v); err == nil {
			t.Fatal("reservation accepted result evidence", purpose)
		}
		v.ResultDigest = ID{}
		_, err := EncodeGeneratorAuthoritySubject(v)
		if (err == nil) != (purpose == GeneratorAuthorityReservation) {
			t.Fatal("delete reservation predecessor rule differs", purpose, err)
		}
		v.PredecessorAttemptID = ID{}
		if _, err := EncodeGeneratorAuthoritySubject(v); err != nil {
			t.Fatal("planned reservation refused", purpose, err)
		}
		v.ResultID = ID{}
		if _, err := EncodeGeneratorAuthoritySubject(v); err == nil {
			t.Fatal("reservation omitted planned result", purpose)
		}
	}
	v = generatorAuthorityFixture()
	v.Purpose = GeneratorAuthorityFinal
	if _, err := EncodeGeneratorAuthoritySubject(v); err == nil {
		t.Fatal("final selected one Attempt instead of the complete set")
	}
}

// full_only: false
func TestGeneratorPhaseIndependentIdentities(t *testing.T) {
	v := GeneratorPhaseIdentity{RequestIdentityDigest: generatedRecordID(1), ObservedHEADDigest: generatedRecordID(2), ConditionDigest: generatedRecordID(3),
		TransitionKind: GeneratorAuthorityRecord, BeforePhase: 2, AfterPhase: 3, Evidence: GeneratorDescriptor{Digest: generatedRecordID(25), Length: 257, Count: 1}}
	// phase body = three repeated-byte IDs 1,2,3; 02; 00000002;
	// 00000003; ID 25; 0000000000000101; 00000001. D wraps its 149 bytes.
	phase, err := GeneratorPhaseID(v)
	if err != nil || hex.EncodeToString(phase[:]) != "aaf09909bb7bc96116f821a94a7689f826d425b0c56cf504502dae8edaed1ab8" {
		t.Fatalf("phase = %x, %v", phase, err)
	}
	// Independent preparation vector replaces only the phase body's purpose
	// byte 02 with 0c; its other 148 bytes and domain label are unchanged.
	prepared := v
	prepared.TransitionKind = GeneratorAuthorityPurpose(12)
	preparedPhase, err := GeneratorPhaseID(prepared)
	if GeneratorAuthorityFinalPreparation != 12 || prepared.TransitionKind.Name() != "final-preparation" ||
		err != nil || hex.EncodeToString(preparedPhase[:]) != "f7d082e89d434920792d51407f7085a9428962eba68850a5a4b5dcfa7d66cacc" || preparedPhase == phase {
		t.Fatalf("literal purpose12 phase = %x, %v", preparedPhase, err)
	}
	for _, tc := range []struct {
		name, want string
		derive     func(ID) (ID, error)
		source     ID
	}{
		{"initial-phase", "72ef2601409cb1f38348211448c2c24c05e7889a0c5299c6718b5de78be0a478", GeneratorInitialPhaseID, generatedRecordID(1)},
		{"initial-snapshot", "a2c51f4e4f08890642838880703e199bc315388aad0a23cb550718c4114d5281", GeneratorInitialSnapshotID, generatedRecordID(1)},
		{"initial-transition", "954f8bd7869b66ff656783dd25b442cea42c31b54a5323f60662ec3c06b6645e", GeneratorInitialTransitionID, generatedRecordID(1)},
		{"initial-revision", "ec84150902922a8eaf621c0dd06b69bdb492cc372b5163261be9cb162978b2a2", GeneratorInitialRevisionID, generatedRecordID(1)},
		{"delete-reservation-request", "c921863e746a740f92437f10ad3dfcb5cf08e7b932b2166e7243832c9ea5dc38", GeneratorDeleteReservationRequestID, generatedRecordID(1)},
		{"phase-snapshot", "3fc48cf27e677a63848ec9d8efdd7d8009f461534607a877b13cf1829df2bb27", GeneratorPhaseSnapshotID, phase},
		{"phase-transition", "70c053509b004d87bba8857af0ce48d81ef4524c3862a4f5c0b94f7a3cac6b41", GeneratorPhaseTransitionID, phase},
		{"phase-revision", "1daf9e73173f95329a0ef25604e68bafec11f478745e5e5ec1fea6b92adb26b3", GeneratorPhaseRevisionID, phase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each D body is exactly the 32-byte source, without other request,
			// graph, material, future-result, access or HEAD fields.
			got, err := tc.derive(tc.source)
			if err != nil || hex.EncodeToString(got[:]) != tc.want {
				t.Fatalf("identity = %x, %v", got, err)
			}
			if _, err := tc.derive(ID{}); err == nil {
				t.Fatal("missing source identity accepted")
			}
		})
	}
	for _, tc := range []struct {
		name, want string
		derive     func(ID, Kind, uint16) (ID, error)
		source     ID
	}{
		{"initial-page", "1b8b43f72a242a03775d01e3c029297bb2221f08474b37f62586f38ab42df72d", GeneratorInitialPageID, generatedRecordID(1)},
		{"phase-page", "a1dfc20e38d935d106444ae709ada3a888c54b81484870d25d458f12687dd208", GeneratorPhasePageID, phase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Page D appends 08 00 ff to the source, for a 35-byte body.
			got, err := tc.derive(tc.source, RequiredSupportKind, 255)
			if err != nil || hex.EncodeToString(got[:]) != tc.want {
				t.Fatalf("page identity = %x, %v", got, err)
			}
			for _, coordinate := range []struct {
				kind  Kind
				index uint16
			}{{ValueEntryPageKind, 31}, {RecipientKind, 31}, {AccessKind, 255}, {RequiredSupportKind, 255}, {AdministrativeIndexKind, 255}} {
				if _, err := tc.derive(tc.source, coordinate.kind, coordinate.index); err != nil {
					t.Fatal("maximum page index refused", err)
				}
				if _, err := tc.derive(tc.source, coordinate.kind, coordinate.index+1); err == nil {
					t.Fatal("excess page index accepted")
				}
			}
			for _, kind := range []Kind{0, RootKind, HeadKind, 10} {
				if _, err := tc.derive(tc.source, kind, 0); err == nil {
					t.Fatal("non-page kind accepted", kind)
				}
			}
			if _, err := tc.derive(ID{}, ValueEntryPageKind, 0); err == nil {
				t.Fatal("missing page source accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratorPhaseRefusesInitialCycleAndBindsEvidence(t *testing.T) {
	v := GeneratorPhaseIdentity{RequestIdentityDigest: generatedRecordID(1), ObservedHEADDigest: generatedRecordID(2), ConditionDigest: generatedRecordID(3),
		TransitionKind: GeneratorAuthorityRecord, BeforePhase: 2, AfterPhase: 3, Evidence: GeneratorDescriptor{Digest: generatedRecordID(25), Length: 257, Count: 1}}
	base, err := GeneratorPhaseID(v)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*GeneratorPhaseIdentity){
		"request":         func(v *GeneratorPhaseIdentity) { v.RequestIdentityDigest = ID{} },
		"head":            func(v *GeneratorPhaseIdentity) { v.ObservedHEADDigest = ID{} },
		"condition":       func(v *GeneratorPhaseIdentity) { v.ConditionDigest = ID{} },
		"purpose":         func(v *GeneratorPhaseIdentity) { v.TransitionKind = 0 },
		"unknown purpose": func(v *GeneratorPhaseIdentity) { v.TransitionKind = 14 },
		"initial cycle": func(v *GeneratorPhaseIdentity) {
			v.TransitionKind = GeneratorAuthorityReservation
			v.BeforePhase, v.AfterPhase = 0, 1
		},
		"unchanged phase": func(v *GeneratorPhaseIdentity) { v.AfterPhase = 2 },
		"skipped phase":   func(v *GeneratorPhaseIdentity) { v.AfterPhase = 4 },
		"overflow":        func(v *GeneratorPhaseIdentity) { v.BeforePhase, v.AfterPhase = ^uint32(0), 0 },
		"evidence":        func(v *GeneratorPhaseIdentity) { v.Evidence.Digest = ID{} },
		"length":          func(v *GeneratorPhaseIdentity) { v.Evidence.Length = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if _, err := GeneratorPhaseID(bad); err == nil {
				t.Fatal("invalid phase identity accepted")
			}
		})
	}
	for _, change := range []func(*GeneratorPhaseIdentity){
		func(v *GeneratorPhaseIdentity) { v.RequestIdentityDigest = generatedRecordID(90) },
		func(v *GeneratorPhaseIdentity) { v.ObservedHEADDigest = generatedRecordID(90) },
		func(v *GeneratorPhaseIdentity) { v.ConditionDigest = generatedRecordID(90) },
		func(v *GeneratorPhaseIdentity) { v.TransitionKind = GeneratorAuthorityResidue },
		func(v *GeneratorPhaseIdentity) { v.BeforePhase, v.AfterPhase = 3, 4 },
		func(v *GeneratorPhaseIdentity) { v.Evidence.Digest = generatedRecordID(90) },
		func(v *GeneratorPhaseIdentity) { v.Evidence.Length++ },
		func(v *GeneratorPhaseIdentity) { v.Evidence.Count++ },
	} {
		changed := v
		change(&changed)
		got, err := GeneratorPhaseID(changed)
		if err != nil || got == base {
			t.Fatal("phase identity omitted a bound field", err)
		}
	}
}
