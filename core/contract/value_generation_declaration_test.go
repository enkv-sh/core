package contract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func generatorDeclarationFixture(t testing.TB) GeneratorDeclaration {
	t.Helper()
	id := generatedRecordID
	payload, err := EncodeGeneratorDeclaredGeneration(GeneratorDeclaredGeneration{
		Schema:             GeneratorDeclaredGenerationSchema,
		LifecycleMode:      GeneratorLifecycleManaged,
		Epoch:              7,
		RetirementMode:     1,
		ConfigContractID:   id(6),
		ResourceContractID: id(9),
		CompletionClass:    1,
		Intent:             generatorIntentFixture(t, id(6), id(9), GeneratorLifecycleManaged, []byte("{}")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(2), Entries: []GeneratorDeclarationEntry{
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationPlain, Recipients: []ID{id(3)}},
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGenerated, Name: "token", Recipients: []ID{id(3), id(4)}, Payload: payload},
	}}
}

// full_only: false
func TestGeneratorDeclarationIndependentWireAndProjections(t *testing.T) {
	v := generatorDeclarationFixture(t)
	b, err := EncodeGeneratorDeclaration(v)
	// Independent Node Buffer big-endian concatenation and SHA-256: schema1,
	// repeated-byte domain1/operation2, two entries. Entry1 is kind1, empty
	// name/value, recipient3. Entry2 is kind4, name "token", recipients3/4;
	// schema4, epoch7, manual1, config6/resource9, managed2/class1, then
	// B(intent schema1, config6, managed2, resource9, B("{}")).
	// D adds ENKV/GENERATOR/v1/<label>+NUL+B(preimage), never a Go encoder.
	if err != nil || len(b) != 363 || Hash(b) != generatedCryptoHexID(t, "fbe8578a22a991ee9b6151707c160f5c75e8e4a1bccd2694b945de19710bdb59") {
		t.Fatal("declaration bytes differ", len(b), err)
	}
	d, err := GeneratorDeclarationDescriptor(v)
	if err != nil || d.Length != 371 || d.Count != 1 || d.Digest != generatedCryptoHexID(t, "38865e4661ac9dbc82399485eb1f9faf432c60dbb25c676e8a837b738399e25c") {
		t.Fatal("declaration descriptor differs", d, err)
	}
	view, err := InspectGeneratorDeclaration(b)
	if err != nil || view.EntryCount() != 2 || view.DomainID != v.DomainID || view.OperationID != v.OperationID {
		t.Fatal("declaration traversal", err)
	}
	got, err := view.Descriptor()
	if err != nil || got != d {
		t.Fatal("borrowed declaration commitment", err)
	}
	entry, offset, err := view.Entry(1)
	if err != nil || offset != 125 || string(entry.Name) != "token" || entry.Kind != GeneratorDeclarationGenerated || len(entry.RecipientIDs) != 64 {
		t.Fatal("entry location", offset, err)
	}
	for _, i := range []int{-1, 2} {
		if _, _, err := view.Entry(i); err == nil {
			t.Fatal("out-of-range entry")
		}
	}
	membership, err := GeneratorIntendedMembershipDescriptor(v.Entries[1].Recipients)
	if err != nil || membership.Length != 76 || membership.Count != 2 || membership.Digest != generatedCryptoHexID(t, "591b07526196c7aa182f6fae8c3d912575a9160d76ac0d1356feaa2278e21ecc") {
		t.Fatal("membership descriptor", err)
	}
	id, err := GeneratorDeclarationEntryID(v.DomainID, v.OperationID, "token")
	if err != nil || id != generatedCryptoHexID(t, "6497000e980626f882a9d5fc070aa8293aae9d6047de00f213ec8bea4829b5b6") {
		t.Fatal("entry identity", err)
	}
	intent, err := GeneratorIntentDigest(generatorIntentFixture(t, generatedRecordID(6), generatedRecordID(9), GeneratorLifecycleManaged, []byte("{}")))
	if err != nil || intent != generatedCryptoHexID(t, "baed83394dc997bf5b1e252e7c1e8efca8750b80304d2f304e60a209548a0810") {
		t.Fatal("intent identity", err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	for n := range b {
		if _, err := InspectGeneratorDeclaration(b[:n]); err == nil {
			t.Fatal("accepted truncation", n)
		}
	}
	if _, err := InspectGeneratorDeclaration(append(bytes.Clone(b), 0)); err == nil {
		t.Fatal("accepted suffix")
	}
	clear(b)
	again, err := EncodeGeneratorDeclaration(owned)
	if err != nil || Hash(again) != generatedCryptoHexID(t, "fbe8578a22a991ee9b6151707c160f5c75e8e4a1bccd2694b945de19710bdb59") {
		t.Fatal("owned declaration retained borrowed input", err)
	}
}

// full_only: false
func TestGeneratorDeclarationClosedFieldsAndJointLimits(t *testing.T) {
	for name, edit := range map[string]func(*GeneratorDeclaration){
		"schema":               func(v *GeneratorDeclaration) { v.Schema++ },
		"domain":               func(v *GeneratorDeclaration) { v.DomainID = ID{} },
		"operation":            func(v *GeneratorDeclaration) { v.OperationID = ID{} },
		"unknown entry":        func(v *GeneratorDeclaration) { v.Entries[0].Kind = 6 },
		"entry schema":         func(v *GeneratorDeclaration) { v.Entries[0].Schema++ },
		"reordered":            func(v *GeneratorDeclaration) { slices.Reverse(v.Entries) },
		"duplicate name":       func(v *GeneratorDeclaration) { v.Entries[1].Name = "" },
		"invalid UTF8":         func(v *GeneratorDeclaration) { v.Entries[0].Name = "\xff" },
		"name length":          func(v *GeneratorDeclaration) { v.Entries[0].Name = strings.Repeat("a", 257) },
		"no recipient":         func(v *GeneratorDeclaration) { v.Entries[0].Recipients = nil },
		"zero recipient":       func(v *GeneratorDeclaration) { v.Entries[0].Recipients = []ID{{}} },
		"duplicate recipient":  func(v *GeneratorDeclaration) { v.Entries[1].Recipients[1] = v.Entries[1].Recipients[0] },
		"reordered recipients": func(v *GeneratorDeclaration) { slices.Reverse(v.Entries[1].Recipients) },
		"plain length":         func(v *GeneratorDeclaration) { v.Entries[0].Payload = make([]byte, CryptoMaxRawValue+1) },
		"source body":          func(v *GeneratorDeclaration) { v.Entries[0].Kind = GeneratorDeclarationSealed },
		"canonical body":       func(v *GeneratorDeclaration) { v.Entries[0].Kind = GeneratorDeclarationRetained },
		"generated suffix":     func(v *GeneratorDeclaration) { v.Entries[1].Payload = append(v.Entries[1].Payload, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			v := generatorDeclarationFixture(t)
			edit(&v)
			if _, err := EncodeGeneratorDeclaration(v); err == nil {
				t.Fatal("invalid declaration accepted")
			}
		})
	}
	for _, count := range []int{512, 513} {
		v := generatorDeclarationFixture(t)
		v.Entries = make([]GeneratorDeclarationEntry, count)
		for i := range v.Entries {
			v.Entries[i] = GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationPlain, Name: fmt.Sprintf("%03d", i), Recipients: []ID{generatedRecordID(3)}, Payload: make([]byte, 16384)}
		}
		_, err := EncodeGeneratorDeclaration(v)
		if (err == nil) != (count == 512) {
			t.Fatal("member/raw joint bound", count, err)
		}
		if count == 512 {
			v.Entries[0].Payload = append(v.Entries[0].Payload, 0)
			if _, err := EncodeGeneratorDeclaration(v); err == nil {
				t.Fatal("accepted raw byte 8388609")
			}
		}
	}
	v := generatorDeclarationFixture(t)
	generated := v.Entries[1]
	v.Entries = make([]GeneratorDeclarationEntry, 129)
	for i := range v.Entries {
		v.Entries[i] = generated
		v.Entries[i].Name = fmt.Sprintf("%03d", i)
	}
	if _, err := EncodeGeneratorDeclaration(v); err == nil {
		t.Fatal("generated entry 129 accepted")
	}
	v.Entries = v.Entries[:128]
	if _, err := EncodeGeneratorDeclaration(v); err != nil {
		t.Fatal("generated maximum", err)
	}
	if _, err := InspectGeneratorDeclaration(make([]byte, GeneratorDeclarationMaxLength+1)); err != ErrRecordCapacity {
		t.Fatal("outer bound", err)
	}
	b, err := EncodeGeneratorDeclaration(generatorDeclarationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(b[66:70], ^uint32(0))
	if _, err := InspectGeneratorDeclaration(b); err == nil {
		t.Fatal("unbounded count accepted")
	}
}

// full_only: false
func TestGeneratorDeclarationSourceVariantsKeepTheirOriginalMeaning(t *testing.T) {
	id := generatedRecordID
	m := generatedValueEntryFixture(t)
	m.ValueSource, m.Generated = Supplied, GeneratedEntryMetadata{}
	canonical, err := EncodeRetainedCanonicalRecord(RetainedCanonicalRecord{OriginalSlot: 3, Entry: m})
	if err != nil {
		t.Fatal(err)
	}
	source := SealedInputEnvelope{Core: SealedInputCore{SealedInputCoreFields: SealedInputCoreFields{Schema: SealedInputSchema, Profile: 2, CompatibilityID: id(4), DomainID: id(1),
		FileIdentity: id(5), SourceID: id(6), CryptoSupportID: id(9), DataKeyID: id(10), DataKeyEpoch: 1, InputEncoding: InputEncodingRaw, RetainedLength: 0}, Name: m.Name},
		Ciphertext: make([]byte, 16), AuthorityWrap: accessStructuralRow(t, 0, 1, 0).BeforeAccessRecord.Wraps[0]}
	sealed, err := EncodeSealedInputEnvelope(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []GeneratorDeclarationEntry{
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationSealed, Name: m.Name, Recipients: m.Recipients, Payload: sealed},
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationRetained, Name: m.Name, Recipients: m.Recipients, Payload: canonical},
	} {
		v := GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(2), Entries: []GeneratorDeclarationEntry{row}}
		b, err := EncodeGeneratorDeclaration(v)
		if err != nil {
			t.Fatal("closed encrypted source", row.Kind, err)
		}
		view, err := InspectGeneratorDeclaration(b)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := view.Entry(0)
		if err != nil || got.ValueSource() != Supplied || got.ConfidentialityClass() != Secret || !bytes.Equal(got.Payload, row.Payload) {
			t.Fatal("source payload or kind changed", err)
		}
		v.Entries[0].Name = "another"
		if _, err := EncodeGeneratorDeclaration(v); err == nil {
			t.Fatal("different source name accepted")
		}
		v.Entries[0] = row
		v.Entries[0].Payload = append(bytes.Clone(row.Payload), 0)
		if _, err := EncodeGeneratorDeclaration(v); err == nil {
			t.Fatal("source suffix accepted")
		}
	}
	v := GeneratorDeclaration{Schema: 1, DomainID: id(11), OperationID: id(2), Entries: []GeneratorDeclarationEntry{
		{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationSealed, Name: m.Name, Recipients: m.Recipients, Payload: sealed},
	}}
	if _, err := EncodeGeneratorDeclaration(v); err == nil {
		t.Fatal("cross-domain source accepted")
	}
	m.ValueSource, m.Generated = Generated, generatedRecordEntryMetadata()
	canonical, err = EncodeRetainedCanonicalRecord(RetainedCanonicalRecord{OriginalSlot: 3, Entry: m})
	if err != nil {
		t.Fatal(err)
	}
	v.DomainID, v.Entries[0].Kind, v.Entries[0].Payload = id(1), GeneratorDeclarationRetained, canonical
	if _, err := EncodeGeneratorDeclaration(v); err == nil {
		t.Fatal("generated member relabelled as supplied input")
	}
}

// full_only: false
func TestGeneratorDeclarationExactEncodedLimit(t *testing.T) {
	id := generatedRecordID
	v := GeneratorDeclaration{Schema: 1, DomainID: id(1), OperationID: id(2), Entries: make([]GeneratorDeclarationEntry, 86)}
	for i := range v.Entries {
		length := GeneratorIntentMaxLength
		if i == 85 {
			// Body70 + 86*(B4+entry15+name256+recipient32+generation81)
			// + 85*intent393216 + finalIntent97626 = 32 MiB - framing8.
			length = 97626
		}
		payload, err := EncodeGeneratorDeclaredGeneration(GeneratorDeclaredGeneration{
			Schema:             GeneratorDeclaredGenerationSchema,
			LifecycleMode:      GeneratorLifecycleManaged,
			RetirementMode:     1,
			ConfigContractID:   id(4),
			ResourceContractID: id(5),
			CompletionClass:    1,
			Intent:             generatorIntentLengthFixture(t, id(4), id(5), GeneratorLifecycleManaged, length),
		})
		if err != nil {
			t.Fatal(err)
		}
		v.Entries[i] = GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationGenerated, Name: fmt.Sprintf("%03d", i) + strings.Repeat("n", 253), Recipients: []ID{id(6)}, Payload: payload}
	}
	b, err := EncodeGeneratorDeclaration(v)
	if err != nil || len(b) != 32<<20-8 {
		t.Fatal("exact declaration limit", len(b), err)
	}
	if _, err := InspectGeneratorDeclaration(b); err != nil {
		t.Fatal(err)
	}
	last, err := InspectGeneratorDeclaredGeneration(v.Entries[85].Payload)
	if err != nil {
		t.Fatal(err)
	}
	last.Intent = generatorIntentLengthFixture(t, id(4), id(5), GeneratorLifecycleManaged, len(last.Intent)+1)
	v.Entries[85].Payload, err = EncodeGeneratorDeclaredGeneration(last)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeGeneratorDeclaration(v); err != ErrRecordCapacity {
		t.Fatal("one encoded byte over declaration", err)
	}
	for count, recipientsPerEntry := range map[int]int{257: 1, 65: 64} {
		v.Entries = make([]GeneratorDeclarationEntry, count)
		for i := range v.Entries {
			recipients := make([]ID, recipientsPerEntry)
			for j := range recipients {
				value := j + 1
				if recipientsPerEntry == 1 {
					value = i + 1
				}
				binary.BigEndian.PutUint32(recipients[j][28:], uint32(value))
			}
			v.Entries[i] = GeneratorDeclarationEntry{InputEncoding: InputEncodingRaw, OutputEncoding: OutputEncodingRaw, Schema: GeneratorDeclarationEntrySchema, Kind: GeneratorDeclarationPlain, Name: fmt.Sprintf("%03d", i), Recipients: recipients}
		}
		if _, err := EncodeGeneratorDeclaration(v); err == nil {
			t.Fatal("joint recipient/membership excess accepted", count, recipientsPerEntry)
		}
	}
}

// full_only: false
func TestGeneratorDeclarationCheckedEntrySpans(t *testing.T) {
	if got := []uint8{GeneratorContentIntent, GeneratorContentDeclaration, GeneratorContentGraph, GeneratorContentSource, GeneratorContentConfiguration}; !slices.Equal(got, []uint8{1, 2, 3, 4, 5}) {
		t.Fatal("content kind assignments changed", got)
	}
	if got := []GeneratorDeclarationKind{GeneratorDeclarationPlain, GeneratorDeclarationSealed, GeneratorDeclarationRetained, GeneratorDeclarationGenerated, GeneratorDeclarationGeneratedReference}; !slices.Equal(got, []GeneratorDeclarationKind{1, 2, 3, 4, 5}) {
		t.Fatal("declaration kind assignments changed", got)
	}
	t.Run("independent committed vector", func(t *testing.T) {
		body, err := EncodeGeneratorDeclaration(generatorDeclarationFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectGeneratorDeclaration(body)
		if err != nil {
			t.Fatal(err)
		}
		// The independent wire vector above has header70 and B(entry) prefix4;
		// each entry has fixed15 + name + recipient IDs + complete payload.
		for index, want := range []struct{ offset, length, payload uint32 }{{74, 47, 121}, {125, 238, 209}} {
			row, offset, err := view.Entry(index)
			if err != nil || offset != want.offset {
				t.Fatal("entry offset", index, offset, err)
			}
			length, payload, err := view.EntrySpan(index)
			if err != nil || length != want.length || payload != want.payload || !bytes.Equal(body[payload:offset+length], row.Payload) {
				t.Fatal("exact checked span", index, length, payload, err)
			}
			for _, borrowed := range [][]byte{row.Name, row.RecipientIDs, row.Payload} {
				if cap(borrowed) != len(borrowed) {
					t.Fatal("borrowed field includes bytes outside its span", index)
				}
			}
			if len(row.Payload) != 0 && &row.Payload[0] != &body[payload] {
				t.Fatal("span accessor copied the payload", index)
			}
		}
		for _, index := range []int{-1, 2} {
			if length, payload, err := view.EntrySpan(index); err == nil || length != 0 || payload != 0 {
				t.Fatal("invalid index exposed span", index)
			}
		}
		// The second payload's length frame is at literal205. Indexed access
		// must recheck framing rather than return its previously checked span.
		binary.BigEndian.PutUint32(body[205:209], 113)
		if length, payload, err := view.EntrySpan(1); err == nil || length != 0 || payload != 0 {
			t.Fatal("changed payload framing exposed cached span")
		}
		if _, _, err := view.Entry(1); err == nil {
			t.Fatal("Entry and EntrySpan disagreed on changed framing")
		}
	})
	t.Run("hand-framed variable fields", func(t *testing.T) {
		// Independent big-endian wire assembly: header70, then 51-byte and
		// 84-byte plain entries, each with its four-byte outer length frame.
		// Row1: name x, recipient3, payload abc. Row2: name xyz, recipients3/4,
		// payload de. The literal positions are not supplied by an encoder.
		body := make([]byte, 213)
		binary.BigEndian.PutUint16(body[0:2], 1)
		copy(body[2:34], bytes.Repeat([]byte{1}, 32))
		copy(body[34:66], bytes.Repeat([]byte{2}, 32))
		binary.BigEndian.PutUint32(body[66:70], 2)
		binary.BigEndian.PutUint32(body[70:74], 51)
		binary.BigEndian.PutUint16(body[74:76], 4)
		body[76], body[77], body[78] = 1, 1, 1
		binary.BigEndian.PutUint32(body[79:83], 1)
		body[83] = 'x'
		binary.BigEndian.PutUint16(body[84:86], 1)
		copy(body[86:118], bytes.Repeat([]byte{3}, 32))
		binary.BigEndian.PutUint32(body[118:122], 3)
		copy(body[122:125], "abc")
		binary.BigEndian.PutUint32(body[125:129], 84)
		binary.BigEndian.PutUint16(body[129:131], 4)
		body[131], body[132], body[133] = 1, 1, 1
		binary.BigEndian.PutUint32(body[134:138], 3)
		copy(body[138:141], "xyz")
		binary.BigEndian.PutUint16(body[141:143], 2)
		copy(body[143:175], bytes.Repeat([]byte{3}, 32))
		copy(body[175:207], bytes.Repeat([]byte{4}, 32))
		binary.BigEndian.PutUint32(body[207:211], 2)
		copy(body[211:213], "de")
		view, err := InspectGeneratorDeclaration(body)
		if err != nil {
			t.Fatal("hand-framed declaration", err)
		}
		for index, want := range []struct {
			length, payload uint32
			value           string
		}{{51, 122, "abc"}, {84, 211, "de"}} {
			length, payload, err := view.EntrySpan(index)
			row, _, rowErr := view.Entry(index)
			if err != nil || rowErr != nil || length != want.length || payload != want.payload || string(row.Payload) != want.value {
				t.Fatal("variable fields changed exact span", index, length, payload, err, rowErr)
			}
		}
	})
}
