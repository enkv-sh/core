package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedRootExtensionFixedBytes(t *testing.T) {
	w := writer{}
	v := EmptyGeneratedClosure()
	if err := writeGeneratedClosure(&w, v); err != nil {
		t.Fatal(err)
	}
	if len(w.b) != 363 || fmt.Sprintf("%x", sha256.Sum256(w.b)) != "797de9337b20ef795155eddc33ce0e8a18d3407d13b48dda7c92ee7a10903486" {
		t.Fatalf("empty extension length %d", len(w.b))
	}
	// The first97 bytes are absent owner, two zero IDs and eight zero counters.
	if !bytes.Equal(w.b[:97], make([]byte, 97)) {
		t.Fatal("empty extension fields")
	}
	r := reader{b: w.b}
	got := readGeneratedClosure(&r)
	if !r.end() || got.ActiveOwner != (ID{}) || got.GeneratedCurrent != 0 || got.Graphs != v.Graphs || got.LiveOwners != v.LiveOwners || got.SuccessWindow != v.SuccessWindow || got.FailureWindow != v.FailureWindow || got.ReceiptOrder != v.ReceiptOrder || got.Slices != v.Slices {
		t.Fatal("extension field mismatch")
	}
	for n := range w.b {
		r := reader{b: w.b[:n]}
		readGeneratedClosure(&r)
		if r.end() {
			t.Fatalf("accepted extension truncation %d", n)
		}
	}
}

// full_only: false
func TestGeneratedRootJointEncodedCapacity(t *testing.T) {
	// These are root-format inputs, not authenticated child images. Full
	// selected-state validation must separately reconcile their contents.
	p := rootFixture(t)
	id := func(n uint32) ID {
		var v ID
		binary.BigEndian.PutUint32(v[28:], n)
		return v
	}
	ref := func(kind Kind, index uint16, length uint32) Ref {
		return Ref{Kind: kind, Format: Version, Domain: p.Domain, Object: id(uint32(kind)*1000 + uint32(index) + 1),
			Digest: fid(90), Length: length, Index: index}
	}
	p.ValueEntryPages, p.Recipients, p.Names = [contract.MaxValueEntryPages]*Ref{}, [contract.MaxRecipientPages]*Ref{}, nil
	var recipients []Ref
	// Recipient rows carry ID/status, display B(256) and KMS B(1558).
	const recipientPageLength = 74 + 8*(41+256+1558)
	for i := range p.ValueEntryPages {
		m := ref(ValueEntryPageKind, uint16(i), MaxValueEntryPage)
		r := ref(RecipientKind, uint16(i), recipientPageLength)
		p.ValueEntryPages[i], p.Recipients[i] = &m, &r
		recipients = append(recipients, r)
	}
	for i := 0; i < 512; i++ {
		p.Names = append(p.Names, NameEntry{Name: fmt.Sprintf("%03d", i) + strings.Repeat("n", 253), Slot: uint16(i)})
	}
	c := &p.CurrentAccess.Core
	c.NormalSigning.KeySelector = strings.Repeat("s", 1024)
	signing := c.NormalSigning
	signing.Role, signing.BindingID = contract.RecoverySigningRole, fid(91)
	registry := recipientFixture(t)
	kms := *registry.Slots[2].CurrentBinding
	kms.KeySelector = strings.Repeat("k", 1024)
	c.Recovery = &contract.RecoveryBindings{RoleID: fid(92), Signing: signing, KMS: kms}
	var err error
	c.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: p.Domain, Refs: recipients})
	if err != nil {
		t.Fatal(err)
	}
	// Two access pages each hold 256 records with eight ordinary wraps and
	// one recovery wrap. The descriptor adds its 66-byte domain/header and
	// four bytes per row; the page itself has no per-row length word.
	const accessPayload = 256 * (102 + 9*489)
	c.AccessPageRefs = []Ref{ref(AccessKind, 0, 75+accessPayload), ref(AccessKind, 1, 75+accessPayload)}
	c.AccessRecordsDescriptor = contract.DescriptorVector{Digest: fid(93), Length: 66 + 4*512 + 2*accessPayload, Count: 512}
	p.CurrentAccess.AccessRoot, err = contract.AccessRoot(*c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 188; i++ {
		p.RequiredSupport = append(p.RequiredSupport, ref(contract.RequiredSupportKind, uint16(i+1), 323))
		for slot := 0; slot < 2; slot++ {
			p.Generated.Fragments = append(p.Generated.Fragments, FragmentLocation{BlobID: id(uint32(2*i + slot + 1)),
				SupportPageIndex: uint16(i + 1), RowSlot: uint8(slot)})
		}
	}
	p.Generated.ActiveOwner, p.Generated.ActivePhase, p.Generated.ActiveGraph = fid(94), fid(95), fid(96)
	p.AdministrativeIndexShards = []Ref{}
	p.Generated.GeneratedCurrent = 128
	p.ValueEntryCount, p.SecretCount, p.RawBytes = 512, 512, 8<<20
	p.MembershipCount, p.SecretOrdinaryWrapCount, p.RecipientCount = 4096, 4096, 256
	p.AccessRecordCount, p.RequiredSupportRecordCount, p.ChildCount = 512, 377, 256
	p.ChildEncodedBytes = contract.MaxValueEntryPages*MaxValueEntryPage + contract.MaxRecipientPages*recipientPageLength + 2*(75+accessPayload) + 188*323 + uint64(p.AdministrativeIndex.Length) + uint64(p.RequiredSupport[0].Length)
	body, err := EncodeRoot(p)
	if err != nil {
		t.Fatal("joint root-format bounds refused", err)
	}
	// Independent wire sum: 256 references, 512 maximum names, two 1,416
	// byte signing bindings (91-byte P-256 SPKI), a 1,526-byte KEK binding,
	// 128 bytes of incarnation identity, the three-byte administrative shard
	// count/warning fields, and 376 directory rows. The conservative bound also charges impossible
	// simultaneous maxima: 256-byte signing SPKIs and 512 directory rows.
	const inherited = 7 + 3*32 + 64 + 256*105 + (4 + 364 + 1416 + (32 + 8 + 1416 + 1526) + 32) + 128 + 3 + 2 + 4 + 512*(4+256+2) + 48
	const extension = 33 + 32 + 32 + 32 + 6*44 + 2 + 376*37 + 46
	// Root appends ActiveGC (32 bytes) and the GCPlans descriptor (44 bytes).
	const gcRelation = 32 + 44
	const expected = inherited + extension + gcRelation
	const conservative = expected + 2*(256-91) + (512-376)*37
	if len(body) != expected || len(body) > conservative || len(body) > MaxRoot {
		t.Fatal("joint encoded root changed its independent size", len(body))
	}
	decoded, err := DecodeRoot(body)
	if err != nil || !reflect.DeepEqual(decoded, p) {
		t.Fatal("joint root-format round trip", err)
	}
	for name, change := range map[string]func(*Root){
		"one extra child": func(v *Root) {
			v.RequiredSupport = append(v.RequiredSupport, ref(contract.RequiredSupportKind, 189, 323))
			v.RequiredSupportRecordCount++
			v.ChildCount++
			v.ChildEncodedBytes += 323
		},
		"one extra generated member": func(v *Root) { v.Generated.GeneratedCurrent++ },
		"one extra name byte": func(v *Root) {
			v.Names = append([]NameEntry(nil), v.Names...)
			v.Names[511].Name += "n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			change(&bad)
			if _, err := EncodeRoot(bad); err == nil {
				t.Fatal("one excess root dimension accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedFragmentDirectoryEncodedLimit(t *testing.T) {
	v := EmptyGeneratedClosure()
	v.ActiveOwner, v.ActivePhase, v.ActiveGraph = fid(1), fid(2), fid(3)
	for i := 0; i < 512; i++ {
		v.Fragments = append(v.Fragments, FragmentLocation{BlobID: fid(4), FragmentIndex: uint16(i),
			SupportPageIndex: uint16(i / 2), RowSlot: uint8(i % 2)})
	}
	w := writer{}
	if err := writeGeneratedClosure(&w, v); err != nil || len(w.b) != 33+32+32+32+6*44+2+512*37 {
		t.Fatal("maximum directory encoding", len(w.b), err)
	}
	r := reader{b: w.b}
	if got := readGeneratedClosure(&r); !r.end() || !reflect.DeepEqual(got, v) {
		t.Fatal("maximum directory decoding")
	}
	v.Fragments = append(v.Fragments, FragmentLocation{BlobID: fid(5)})
	if err := writeGeneratedClosure(&writer{}, v); err == nil {
		t.Fatal("513 directory rows encoded")
	}
	bad := append(bytes.Clone(w.b), make([]byte, 37)...)
	binary.BigEndian.PutUint16(bad[393:395], 513)
	r = reader{b: bad}
	readGeneratedClosure(&r)
	if r.end() {
		t.Fatal("513 directory rows decoded")
	}
}

// full_only: false
func TestGeneratedFragmentDirectoryRequiresExactSelectedRows(t *testing.T) {
	const payloadLimit = contract.GeneratedFragmentMaxPayload
	body := bytes.Repeat([]byte{9}, payloadLimit+1)
	whole := contract.Hash(body)
	fragments := make([]contract.SupportRecordView, 2)
	for i := range fragments {
		payload := body[i*payloadLimit : min((i+1)*payloadLimit, len(body))]
		fragment := contract.GeneratedFragment{Schema: 1, BlobID: fid(1), Index: uint16(i), Count: 2, TotalLength: uint64(len(body)), WholeDigest: whole, Offset: uint32(i * payloadLimit), Payload: payload}
		b, err := contract.EncodeGeneratedFragment(fragment)
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(fragment.BlobID, fragment.Index)
		if err != nil {
			t.Fatal(err)
		}
		fragments[i] = contract.SupportRecordView{Kind: 3, RecordID: id, Body: b}
	}
	page := RequiredSupportPageView{Domain: fid(2), Object: fid(3), Index: 7, Records: fragments}
	directory := []FragmentLocation{{BlobID: fid(1), FragmentIndex: 0, SupportPageIndex: 7, RowSlot: 0}, {BlobID: fid(1), FragmentIndex: 1, SupportPageIndex: 7, RowSlot: 1}}
	if err := ValidateFragmentDirectory(directory, []RequiredSupportPageView{page}); err != nil {
		t.Fatal(err)
	}
	for name, damage := range map[string]func([]FragmentLocation) []FragmentLocation{
		"missing":           func(v []FragmentLocation) []FragmentLocation { return v[:1] },
		"duplicate":         func(v []FragmentLocation) []FragmentLocation { v[1] = v[0]; return v },
		"wrong slot":        func(v []FragmentLocation) []FragmentLocation { v[1].RowSlot = 0; return v },
		"outside selection": func(v []FragmentLocation) []FragmentLocation { v[1].SupportPageIndex = 8; return v },
		"wrong index":       func(v []FragmentLocation) []FragmentLocation { v[1].FragmentIndex = 2; return v },
	} {
		t.Run(name, func(t *testing.T) {
			v := append([]FragmentLocation(nil), directory...)
			if ValidateFragmentDirectory(damage(v), []RequiredSupportPageView{page}) == nil {
				t.Fatal("accepted invalid directory")
			}
		})
	}
	changed := append([]contract.SupportRecordView(nil), fragments...)
	b := bytes.Clone(changed[1].Body)
	b[len(b)-1]++
	changed[1].Body = b
	page.Records = changed
	if ValidateFragmentDirectory(directory, []RequiredSupportPageView{page}) == nil {
		t.Fatal("accepted unequal whole blob")
	}
}

// full_only: false
func TestGeneratedRootReceiptOrderDescriptorIsMandatory(t *testing.T) {
	v := EmptyGeneratedClosure()
	for name, change := range map[string]func(*GeneratedClosure){
		"absent":       func(v *GeneratedClosure) { v.ReceiptOrder = contract.GeneratorDescriptor{} },
		"empty digest": func(v *GeneratedClosure) { v.ReceiptOrder.Digest = fid(99) },
		"length":       func(v *GeneratedClosure) { v.ReceiptOrder.Length++ },
		"count relation": func(v *GeneratedClosure) {
			v.ReceiptOrder = contract.GeneratorDescriptor{Digest: fid(99), Length: 40, Count: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := v
			change(&bad)
			if _, err := EncodeGeneratedClosure(bad); err == nil {
				t.Fatal("accepted missing or invalid receipt-order descriptor")
			}
		})
	}
}

// full_only: false
func TestRootRejectsPreviousSchemaAndMissingReceiptOrder(t *testing.T) {
	root := rootFixture(t)
	body, err := EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	// Empty generated closure is 1+2*32+8*4+6*44+2 = 363 bytes.
	// Root appends 32+44 = 76 GC bytes. ReceiptOrder follows the
	// 97 scalar bytes and four 44-byte descriptors in the generated closure.
	order := len(body) - 76 - 363 + 97 + 4*44
	withoutOrder := append(bytes.Clone(body[:order]), body[order+44:]...)
	schema8MissingOrder := bytes.Clone(withoutOrder)
	schema8MissingOrder[6] = 8
	schema8CurrentLength := bytes.Clone(body)
	schema8CurrentLength[6] = 8
	schema9CurrentLength := bytes.Clone(body)
	schema9CurrentLength[6] = 9
	// The schema-8 mutations are corruption controls, not historical archives.
	for name, bad := range map[string][]byte{"schema8/current-length": schema8CurrentLength, "schema8/missing-receipt-order": schema8MissingOrder, "schema10/missing-receipt-order": withoutOrder, "schema9/current-length": schema9CurrentLength} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRoot(bad); err == nil {
				t.Fatal("accepted obsolete or incomplete root")
			}
		})
	}
}
