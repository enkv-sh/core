package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestLifecycleProjection(t *testing.T) {
	// The fixed preimages, lengths and hashes below were calculated separately
	// with Node Buffer big-endian integers and node:crypto SHA-256. The bytes
	// follow the projection field tables without calling the Go implementation.
	id := func(value byte) contract.ID {
		var result contract.ID
		for i := range result {
			result[i] = value
		}
		return result
	}
	t.Run("plain representation admission", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			encoding uint8
			body     []byte
			content  uint32
			err      error
		}{
			{"literal raw", contract.InputEncodingRaw, []byte("QUJD"), 4, nil},
			{"padded Base64", contract.InputEncodingBase64, []byte("QUJD"), 3, nil},
			{"noncanonical bits", contract.InputEncodingBase64, []byte("Zh=="), 0, contract.ErrRecord},
			{"whitespace", contract.InputEncodingBase64, []byte("QUJD\n"), 0, contract.ErrRecord},
			{"raw one over", contract.InputEncodingRaw, bytes.Repeat([]byte{'x'}, 65537), 0, contract.ErrRecordCapacity},
		} {
			t.Run(test.name, func(t *testing.T) {
				input := []ApplyEntryInput{{Name: "plain", Recipients: []contract.ID{id(2)}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
					InputEncoding: test.encoding, OutputEncoding: contract.OutputEncodingRaw, InputBytes: test.body}}
				rows, descriptor, err := buildEntryIntent(id(1), input)
				if test.err != nil {
					if !errors.Is(err, test.err) || rows != nil || descriptor != (contract.DescriptorVector{}) {
						t.Fatal("invalid plain representation lost its admission error", err)
					}
					if digest, length := entryInputCommitment(id(1), input); !digest.IsZero() || length != 0 {
						t.Fatal("invalid plain representation acquired a commitment")
					}
					return
				}
				if err != nil || len(rows) != 1 || rows[0].ContentLength != test.content || rows[0].RetainedLength != 4 || rows[0].InputEncoding != test.encoding || descriptor.Count != 1 {
					t.Fatal("valid plain representation changed its logical or retained length", err)
				}
			})
		}
	})
	literalID := func(value string) contract.ID {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 {
			t.Fatalf("invalid literal digest: %q", value)
		}
		return contract.ID(b)
	}
	empty := &format.ValueEntry{Name: "", Incarnation: id(5), ValueState: id(6), OriginSnapshot: id(7), OriginTransition: id(8), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	old := &format.ValueEntry{Name: "a", Incarnation: id(9), ValueState: id(10), OriginSnapshot: id(11), OriginTransition: id(12), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, ValueBytes: []byte{0, 127, 128, 255}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte{0, 127, 128, 255})), RetainedLength: uint32(len([]byte{0, 127, 128, 255}))}
	added := &format.ValueEntry{Name: "é/β", Incarnation: id(36), ValueState: id(35), OriginSnapshot: id(32), OriginTransition: id(31), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, ValueBytes: []byte{0, 255, 85}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte{0, 255, 85})), RetainedLength: uint32(len([]byte{0, 255, 85}))}
	recipientRef := format.Ref{Kind: format.RecipientKind, Format: contract.CanonicalSchema, Domain: id(1), Object: id(13), Digest: id(14), Length: 0x0123, Index: 31}
	pageRef := format.Ref{Kind: format.ValueEntryPageKind, Format: contract.CanonicalSchema, Domain: id(1), Object: id(17), Digest: id(18), Length: 0x020304, Index: 16}
	rootRef := format.Ref{Kind: format.RootKind, Format: contract.CanonicalSchema, Domain: id(1), Object: id(19), Digest: id(20), Length: 0x010506}
	s := &StateSession{
		admission:  openAdmission{domain: id(1), recipient: id(2)},
		head:       format.Head{Core: format.HeadCore{Revision: id(21), Root: rootRef}},
		body:       []byte("selected HEAD\x00\xff"),
		token:      contract.Token{Family: contract.AWS, Value: `"etag-0123456789"`},
		root:       format.Root{Domain: id(1), Snapshot: rootRef.Object, ValueEntryCount: 2, Names: []format.NameEntry{{Name: "", Slot: 17}, {Name: "a", Slot: 258}}, Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()},
		adminIndex: format.AdministrativeIndex{Domain: id(1), Object: id(39), SliceSnapshot: rootRef.Object},
		recipients: [contract.MaxRecipientPages]*format.RecipientPage{0: {Slots: [format.RecipientSlots]*format.Recipient{0: {RecipientID: id(2), CurrentBinding: &contract.KMSBinding{BindingID: id(3), Fingerprint: id(4), BindingSerial: 0x0102030405060708}}}}},
	}
	s.root.Recipients[31] = &recipientRef
	s.root.ValueEntryPages[16] = &pageRef
	s.pages[1] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{1: empty}}
	s.pages[16] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{2: old}}
	oldRow := membershipRow{Name: "a", Slot: 258, Incarnation: id(9), Recipients: []contract.ID{id(2)}, EntryDigest: literalID("7aefa641edf73f1470ac5bce3d07ae78d6131d6de4c4c880ef43c36c32c608ea")}
	addedRow := membershipRow{Name: "é/β", Slot: 0, Incarnation: id(36), Recipients: []contract.ID{id(2)}, EntryDigest: literalID("d9497731b6d1fb0c16cdf62ae84cc06a8c5673a3b2b3a2d8a61f6826c16b47f2")}
	removedRow := exclusionRow{MembershipRow: oldRow, Path: literalID("4ee5e671c9fd5ff6af6f07c6e4e63fa14dbedcbd9c3552a1e15d349f0b657a4d")}

	// Name order differs from slot order. The retained empty-name entry has no
	// new value identity, and the update retains its old incarnation.
	c := &Comparison{
		session: s,
		desiredEntries: []ApplyEntryInput{
			{Name: "", Recipients: []contract.ID{id(2)}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
			{Name: "a", Recipients: []contract.ID{id(2)}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw},
			{Name: "é/β", Recipients: []contract.ID{id(2)}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte{0, 255, 85}},
		},
		slots: []uint16{17, 258, 0}, changed: []uint16{258, 0}, added: []uint16{0},
	}
	c.touched[0], c.touched[16] = true, true
	var entropyBytes []byte
	for _, value := range []byte{30, 31, 32, 33, 36, 34, 35, 38, 37} {
		identity := id(value)
		entropyBytes = append(entropyBytes, identity[:]...)
	}
	entropy := bytes.NewReader(entropyBytes)
	s.admission.entropy = entropy
	p, err := planTransition(t.Context(), c)
	if err != nil || entropy.Len() != 0 {
		t.Fatalf("identity allocation: error=%v remaining entropy=%d", err, entropy.Len())
	}
	h := format.HeadCore{
		Domain: id(1), Store: id(22), Trust: id(23), Coordinate: id(24), NonBody: id(25), Interpretation: id(26),
		Epoch: 0x0102030405060708, PreviousRevision: id(21), PreviousDigest: literalID("35035835dba5dc13885bc811f0c43ed0f6a222b43f4ff6147e3c88e720695f23"), PreviousToken: s.token,
	}
	subject := contract.LifecycleSubject{

		Normal:       contract.NormalSection{Intent: contract.DigestLength{Digest: id(29), Length: 0x010203}},
		IdentityPlan: contract.DigestLength{Digest: literalID("1fff4d96b420c4850c1d6449a2c3dc464443daabdb9dcf64f6fa5b45a95ed722"), Length: 506},
	}

	// The representative digest-only APIs retain complete independently
	// calculated preimages as well as their expected digest and length.
	for _, v := range []struct {
		name, preimage, digest string
		length                 int
		got                    contract.ID
	}{
		{"public-member", "454e4b562f43525950544f2f76322f7075626c69632d6d656d6265722d76360001010101010101010101010101010101010101010101010101010101010101010102000000016109090909090909090909090909090909090909090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0101010000000400000004010001020202020202020202020202020202020202020202020202020202020202020200000004007f80ff00000000", "7aefa641edf73f1470ac5bce3d07ae78d6131d6de4c4c880ef43c36c32c608ea", 257, publicEntryDigest(id(1), 258, old)},
		{"plain-path", "454e4b562f43525950544f2f76322f706c61696e2d6578636c7573696f6e2d76360001010101010101010101010101010101010101010101010101010101010101010000000161010209090909090909090909090909090909090909090909090909090909090909097aefa641edf73f1470ac5bce3d07ae78d6131d6de4c4c880ef43c36c32c608ea00010202020202020202020202020202020202020202020202020202020202020202", "4ee5e671c9fd5ff6af6f07c6e4e63fa14dbedcbd9c3552a1e15d349f0b657a4d", 171, s.plainPath(oldRow)},
		{"request", "454e4b562f524551554553542f763300010101010101010101010101010101010101010101010101010101010101010116161616161616161616161616161616161616161616161616161616161616161717171717171717171717171717171717171717171717171717171717171717181818181818181818181818181818181818181818181818181818181818181819191919191919191919191919191919191919191919191919191919191919191a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a0102030405060708151515151515151515151515151515151515151515151515151515151515151535035835dba5dc13885bc811f0c43ed0f6a222b43f4ff6147e3c88e720695f23010000001122657461672d30313233343536373839221d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d00000000000102031fff4d96b420c4850c1d6449a2c3dc464443daabdb9dcf64f6fa5b45a95ed72200000000000001fa", "4e77d5aaf6ae071469189739e65052a0e363ec69b89a3640d89eca2f293b9ccc", 382, requestCommitment(h, subject)},
	} {
		t.Run(v.name, func(t *testing.T) {
			body, err := hex.DecodeString(v.preimage)
			if err != nil || len(body) != v.length || sha256.Sum256(body) != literalID(v.digest) {
				t.Fatal("invalid independent vector")
			}
			if v.got != literalID(v.digest) {
				t.Fatalf("digest=%x want=%s", v.got, v.digest)
			}
		})
	}
	emptyState := *s
	emptyState.root.ValueEntryCount, emptyState.root.Names = 0, nil
	for _, v := range []struct {
		name, digest string
		length       uint64
		got          contract.DigestLength
	}{
		{"public-state", "b5c69aee8ba91589307ce82341075b391791d5135fb51e588eafd3656615ef1a", 220, s.publicState()},
		{"public-state-empty", "68bed0bf720fc40da87b6cd4635a8fed8031e392796522ff9660be6d3ac61359", 143, emptyState.publicState()},
		{"identity-plan", "1fff4d96b420c4850c1d6449a2c3dc464443daabdb9dcf64f6fa5b45a95ed722", 506, identityCommitment(c, p)},
		{"identity-plan-empty", "f5ba1b2b1102e08682cd38671cc2e1e907d956b1b9079778dffcf11efb4a1bdd", 162, identityCommitment(c, transitionPlan{operation: id(30), transition: id(31), snapshot: id(32), revision: id(33)})},
	} {
		t.Run(v.name, func(t *testing.T) {
			if v.got.Length != v.length || v.got.Digest != literalID(v.digest) {
				t.Fatalf("projection=%+v want length=%d digest=%s", v.got, v.length, v.digest)
			}
		})
	}
	for _, v := range []struct {
		name, digest string
		length       uint64
		count        uint32
		got          contract.DescriptorVector
	}{
		{"grants", "6e10a868c5ab0093f1f2a7049e1ee92312694139c161cbd219c83c1ff08ff32d", 170, 1, grantCommitment(id(1), []membershipRow{addedRow})},
		{"grants-empty", "db5014d70b6382585412d710e48de1f984f91bd37f8f50358c15e9338f79dda6", 61, 0, grantCommitment(id(1), nil)},
		{"exclusions", "96fa4cf24b19d567b32ca249ad039367f841bb162b9b8178eb5c52f956db71c4", 202, 1, exclusionCommitment(id(1), []exclusionRow{removedRow})},
		{"exclusions-empty", "18f56688d06ba5946bf1408ef587002c10c8f001c16604a8a0e110903a03ba90", 65, 0, exclusionCommitment(id(1), nil)},
		{"retirements", "602fec1741994a171a4cbbb9e7ceda66af33ff6b223c671b94943d01bcb0881b", 66, 0, retirementCommitment(id(1))},
	} {
		t.Run(v.name, func(t *testing.T) {
			if v.got.Length != v.length || v.got.Count != v.count || v.got.Digest != literalID(v.digest) {
				t.Fatalf("projection=%+v want length=%d digest=%s", v.got, v.length, v.digest)
			}
		})
	}
	for _, v := range []struct {
		name, digest string
		got          contract.ID
	}{
		{"public-member-empty", "bf73f37a7bbcd6c9bdc2605fc152fe0d1f8cb46c54c4632e504ac3d56bcdc891", publicEntryDigest(id(1), 17, empty)},
		{"public-member-added", "d9497731b6d1fb0c16cdf62ae84cc06a8c5673a3b2b3a2d8a61f6826c16b47f2", publicEntryDigest(id(1), 0, added)},
	} {
		if v.got != literalID(v.digest) {
			t.Fatalf("%s digest=%x want=%s", v.name, v.got, v.digest)
		}
	}
}

// full_only: false
func TestLifecycleUnionProjectionMixedMembership(t *testing.T) {
	id := func(n byte) contract.ID {
		var value contract.ID
		for i := range value {
			value[i] = n
		}
		return value
	}
	gone := &format.ValueEntry{Name: "gone", Incarnation: id(3), ValueState: id(4), OriginSnapshot: id(5), OriginTransition: id(6), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, ValueBytes: []byte{0, 255}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte{0, 255})), RetainedLength: uint32(len([]byte{0, 255}))}
	kept := &format.ValueEntry{Name: "kept", Incarnation: id(7), ValueState: id(8), OriginSnapshot: id(9), OriginTransition: id(10), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: 0, RetainedLength: 0}
	old := &format.ValueEntry{Name: "updated", Incarnation: id(11), ValueState: id(12), OriginSnapshot: id(13), OriginTransition: id(14), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, ValueBytes: []byte("old"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte("old"))), RetainedLength: uint32(len([]byte("old")))}
	added := &format.ValueEntry{Name: "added", Incarnation: id(15), ValueState: id(16), OriginSnapshot: id(17), OriginTransition: id(18), Recipients: []contract.ID{id(2)}, ValueSource: 1, ConfidentialityClass: 1, ValueBytes: []byte{42}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ContentLength: uint32(len([]byte{42})), RetainedLength: uint32(len([]byte{42}))}
	updated := *old
	updated.ValueState, updated.OriginSnapshot, updated.OriginTransition, updated.ValueBytes = id(19), id(17), id(18), []byte("new")
	before := &StateSession{admission: openAdmission{domain: id(1)}, root: format.Root{ValueEntryCount: 3, RawBytes: 5}}
	before.root.Names = []format.NameEntry{{Name: "gone", Slot: 0}, {Name: "kept", Slot: 17}, {Name: "updated", Slot: 258}}
	before.pages[0] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{0: gone}}
	before.pages[1] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{1: kept}}
	before.pages[16] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{2: old}}
	before.root.ValueEntryPages[0] = &format.Ref{Kind: format.ValueEntryPageKind, Format: contract.CanonicalSchema, Domain: id(1), Object: id(30), Digest: id(31), Length: 200}
	after := &StateSession{admission: before.admission, root: format.Root{ValueEntryCount: 3, RawBytes: 4}}
	after.root.Names = []format.NameEntry{{Name: "added", Slot: 0}, {Name: "kept", Slot: 17}, {Name: "updated", Slot: 258}}
	after.pages[0] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{0: added}}
	after.pages[1] = before.pages[1]
	after.pages[16] = &format.ValueEntryPage{Slots: [format.PageSlots]*format.ValueEntry{2: &updated}}
	union, grants, exclusions, changed := before.lifecycleVectors(after)
	// Independent Node Buffer/node:crypto vector covers both absent-side
	// markers, unchanged and updated retained entries, and a reused free slot.
	if union.Length != 714 || union.Count != 4 || changed != 3 || hex.EncodeToString(union.Digest[:]) != "9a97ed8a63932795abcacd0b0cdd4414f76816b8dcf73d99932c996ad4475013" {
		t.Fatalf("mixed union: %+v changed=%d", union, changed)
	}
	if len(grants) != 1 || grants[0].Name != "added" || len(exclusions) != 1 || exclusions[0].Name != "gone" {
		t.Fatalf("mixed vector membership: grants=%+v exclusions=%+v", grants, exclusions)
	}
}
