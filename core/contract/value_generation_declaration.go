package contract

import (
	"bytes"
	"unicode/utf8"

	protocol "enkv.sh/sdk/protocols/generator"
)

const (
	GeneratorDeclarationMaxFramedLength        = 32 << 20
	GeneratorDeclarationMaxLength              = GeneratorDeclarationMaxFramedLength - 8
	GeneratorDeclarationEntryMaxLength         = 395652
	GeneratorIntentMaxLength                   = protocol.MaximumIntentLength
	generatorDeclaredGenerationFixedLength     = 81
	GeneratorDeclaredGenerationReferenceLength = 148
	generatorDeclarationHeaderLength           = 70
)

type GeneratorDeclarationKind uint8

const (
	GeneratorDeclarationPlain              GeneratorDeclarationKind = 1
	GeneratorDeclarationSealed             GeneratorDeclarationKind = 2
	GeneratorDeclarationRetained           GeneratorDeclarationKind = 3
	GeneratorDeclarationGenerated          GeneratorDeclarationKind = 4
	GeneratorDeclarationGeneratedReference GeneratorDeclarationKind = 5
)

type GeneratorDeclaredGeneration struct {
	Schema                               uint16
	Epoch                                uint64
	RetirementMode                       uint8
	ConfigContractID, ResourceContractID ID
	LifecycleMode                        GeneratorLifecycleMode
	CompletionClass                      uint8
	Intent                               []byte
}

type GeneratorDeclarationEntry struct {
	Schema                        uint16
	Kind                          GeneratorDeclarationKind
	InputEncoding, OutputEncoding uint8
	Name                          string
	Recipients                    []ID
	Payload                       []byte
}

type GeneratorDeclarationEntryView struct {
	Schema                        uint16
	Kind                          GeneratorDeclarationKind
	InputEncoding, OutputEncoding uint8
	Name, RecipientIDs, Payload   []byte
}

func (v GeneratorDeclarationEntryView) ValueSource() uint8 {
	if v.Kind == GeneratorDeclarationGenerated || v.Kind == GeneratorDeclarationGeneratedReference {
		return Generated
	}
	return Supplied
}

func (v GeneratorDeclarationEntryView) ConfidentialityClass() uint8 {
	if v.Kind == GeneratorDeclarationPlain {
		return Plain
	}
	return Secret
}

func generatorDeclarationPayload(schema uint16, kind GeneratorDeclarationKind, input uint8, name, payload []byte) (raw uint32, domain ID, err error) {
	switch kind {
	case GeneratorDeclarationPlain:
		content, err := InputContentLength(input, payload)
		return content, ID{}, err
	case GeneratorDeclarationSealed:
		s, err := InspectSealedInputEnvelope(payload)
		if err != nil || s.Core.InputEncoding != input || !bytes.Equal(s.Core.Name, name) {
			return 0, ID{}, ErrRecord
		}
		return s.Core.ContentLength, s.Core.DomainID, nil
	case GeneratorDeclarationRetained:
		m, err := InspectRetainedCanonicalRecord(payload)
		if err != nil || m.Entry.InputEncoding != input || m.Entry.ValueSource != Supplied || m.Entry.ConfidentialityClass != Secret || !bytes.Equal(m.Entry.Name, name) {
			return 0, ID{}, ErrRecord
		}
		p, err := InspectCanonicalPayload(m.Entry.ValueBytes)
		return p.ContentLength, ID{}, err
	case GeneratorDeclarationGenerated:
		_, err := InspectGeneratorDeclaredGenerationForEntry(schema, payload)
		return 0, ID{}, err
	case GeneratorDeclarationGeneratedReference:
		_, err := InspectGeneratorDeclaredGenerationReferenceForEntry(schema, payload)
		return 0, ID{}, err
	default:
		return 0, ID{}, ErrRecord
	}
}

func GeneratorDeclarationEntryLength(v GeneratorDeclarationEntry) (int, error) {
	if len(v.Name) > CryptoMaxName || len(v.Payload) > 7+generatorDeclaredGenerationFixedLength+GeneratorIntentMaxLength {
		return 0, ErrRecordCapacity
	}
	if (v.InputEncoding != InputEncodingRaw && v.InputEncoding != InputEncodingBase64) || (v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64) || v.Schema != GeneratorDeclarationEntrySchema || !utf8.ValidString(v.Name) {
		return 0, ErrRecord
	}
	n, err := recipientIDsLength(v.Recipients)
	if err != nil {
		return 0, err
	}
	if _, _, err := generatorDeclarationPayload(v.Schema, v.Kind, v.InputEncoding, []byte(v.Name), v.Payload); err != nil {
		return 0, err
	}
	return 2 + 1 + 2 + 4 + len(v.Name) + n + 4 + len(v.Payload), nil
}

func writeGeneratorDeclarationEntry(w *cryptoWriter, v GeneratorDeclarationEntry) {
	w.u16(v.Schema)
	w.u8(uint8(v.Kind))
	w.u8(v.InputEncoding)
	w.u8(v.OutputEncoding)
	w.blob([]byte(v.Name))
	writeRecipientIDs(w, v.Recipients)
	w.blob(v.Payload)
}

func EncodeGeneratorDeclarationEntry(v GeneratorDeclarationEntry) ([]byte, error) {
	n, err := GeneratorDeclarationEntryLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratorDeclarationEntry(&w, v)
	return w.b, nil
}

func InspectGeneratorDeclarationEntry(b []byte) (GeneratorDeclarationEntryView, error) {
	row, _, err := inspectGeneratorDeclarationEntry(b)
	return row, err
}

func inspectGeneratorDeclarationEntry(b []byte) (GeneratorDeclarationEntryView, int, error) {
	if len(b) > GeneratorDeclarationEntryMaxLength {
		return GeneratorDeclarationEntryView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := GeneratorDeclarationEntryView{Schema: r.u16(), Kind: GeneratorDeclarationKind(r.u8()), InputEncoding: r.u8(), OutputEncoding: r.u8(), Name: r.name(), RecipientIDs: readRecipientIDs(&r), Payload: r.blob(7 + generatorDeclaredGenerationFixedLength + GeneratorIntentMaxLength)}
	if err := r.end(); err != nil {
		return GeneratorDeclarationEntryView{}, 0, err
	}
	if (v.InputEncoding != InputEncodingRaw && v.InputEncoding != InputEncodingBase64) || (v.OutputEncoding != OutputEncodingRaw && v.OutputEncoding != OutputEncodingBase64) || v.Schema != GeneratorDeclarationEntrySchema {
		return GeneratorDeclarationEntryView{}, 0, ErrRecord
	}
	if _, _, err := generatorDeclarationPayload(v.Schema, v.Kind, v.InputEncoding, v.Name, v.Payload); err != nil {
		return GeneratorDeclarationEntryView{}, 0, err
	}
	return v, r.i - len(v.Payload), nil
}

type GeneratorDeclaration struct {
	Schema                uint16
	DomainID, OperationID ID
	Entries               []GeneratorDeclarationEntry
}

type generatorDeclarationSpan struct{ offset, length int }

// GeneratorDeclarationView borrows all entry bytes. The small position index
// is allocated only after the complete count and row boundaries pass.
type GeneratorDeclarationView struct {
	DomainID, OperationID ID
	body                  []byte
	entries               []generatorDeclarationSpan
}

func generatorDeclarationTotals(domain ID, schema uint16, kind GeneratorDeclarationKind, input uint8, name, payload []byte, recipients []ID, totals *cryptoIntentTotals, generated *int) error {
	raw, sourceDomain, err := generatorDeclarationPayload(schema, kind, input, name, payload)
	if err != nil || !sourceDomain.IsZero() && sourceDomain != domain {
		return ErrRecord
	}
	if kind == GeneratorDeclarationGenerated || kind == GeneratorDeclarationGeneratedReference {
		*generated++
		if *generated > GeneratedCurrentEntryLimit {
			return ErrRecordCapacity
		}
	}
	if err := totals.addRow(raw, len(recipients)); err != nil {
		return err
	}
	for _, id := range recipients {
		if err := totals.addRecipient(id); err != nil {
			return err
		}
	}
	return nil
}

func GeneratorDeclarationLength(v GeneratorDeclaration) (int, error) {
	if len(v.Entries) > CryptoMaxValueEntries {
		return 0, ErrRecordCapacity
	}
	if v.Schema != GeneratorRecordSchema || !publicIDsValid(v.DomainID, v.OperationID) {
		return 0, ErrRecord
	}
	n, generated := generatorDeclarationHeaderLength, 0
	var totals cryptoIntentTotals
	for i, row := range v.Entries {
		length, err := GeneratorDeclarationEntryLength(row)
		if err != nil {
			return 0, err
		}
		if i > 0 && v.Entries[i-1].Name >= row.Name {
			return 0, ErrRecord
		}
		if n > GeneratorDeclarationMaxLength-4-length {
			return 0, ErrRecordCapacity
		}
		n += 4 + length
		if err := generatorDeclarationTotals(v.DomainID, row.Schema, row.Kind, row.InputEncoding, []byte(row.Name), row.Payload, row.Recipients, &totals, &generated); err != nil {
			return 0, err
		}
	}
	return n, nil
}

func writeGeneratorDeclaration(w *cryptoWriter, v GeneratorDeclaration) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.u32(uint32(len(v.Entries)))
	for _, row := range v.Entries {
		w.u32(uint32(15 + len(row.Name) + 32*len(row.Recipients) + len(row.Payload)))
		writeGeneratorDeclarationEntry(w, row)
	}
}

func EncodeGeneratorDeclaration(v GeneratorDeclaration) ([]byte, error) {
	n, err := GeneratorDeclarationLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratorDeclaration(&w, v)
	return w.b, nil
}

func InspectGeneratorDeclaration(b []byte) (GeneratorDeclarationView, error) {
	if len(b) > GeneratorDeclarationMaxLength {
		return GeneratorDeclarationView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if r.u16() != GeneratorRecordSchema {
		return GeneratorDeclarationView{}, ErrRecord
	}
	v := GeneratorDeclarationView{DomainID: r.requiredID(), OperationID: r.requiredID(), body: b}
	count := r.count(CryptoMaxValueEntries, 4+45)
	if r.err != nil {
		return GeneratorDeclarationView{}, r.failure()
	}
	var spans [CryptoMaxValueEntries]generatorDeclarationSpan
	var ids [CryptoMaxValueEntryRecipients]ID
	var totals cryptoIntentTotals
	generated := 0
	var previous []byte
	for i := 0; i < count; i++ {
		body := r.blob(GeneratorDeclarationEntryMaxLength)
		if r.err != nil {
			return GeneratorDeclarationView{}, r.failure()
		}
		row, err := InspectGeneratorDeclarationEntry(body)
		if err != nil || !cryptoNamesValid(previous, row.Name, i == 0) {
			return GeneratorDeclarationView{}, ErrRecord
		}
		previous = row.Name
		recipients := ids[:len(row.RecipientIDs)/32]
		for j := range recipients {
			recipients[j] = ID(row.RecipientIDs[j*32 : (j+1)*32])
		}
		if err := generatorDeclarationTotals(v.DomainID, row.Schema, row.Kind, row.InputEncoding, row.Name, row.Payload, recipients, &totals, &generated); err != nil {
			return GeneratorDeclarationView{}, err
		}
		spans[i] = generatorDeclarationSpan{r.i - len(body), len(body)}
	}
	if err := r.end(); err != nil {
		return GeneratorDeclarationView{}, err
	}
	v.entries = append([]generatorDeclarationSpan(nil), spans[:count]...)
	return v, nil
}

func (v GeneratorDeclarationView) EntryCount() int { return len(v.entries) }

func (v GeneratorDeclarationView) Entry(index int) (GeneratorDeclarationEntryView, uint32, error) {
	row, span, _, err := v.inspectEntry(index)
	return row, uint32(span.offset), err
}

// EntrySpan reinspects the borrowed entry and returns its encoded length and
// the payload's absolute offset within the declaration. The body must remain
// unchanged while the view and these positions are used.
func (v GeneratorDeclarationView) EntrySpan(index int) (entryLength, payloadOffset uint32, err error) {
	_, span, payloadStart, err := v.inspectEntry(index)
	if err != nil {
		return 0, 0, err
	}
	return uint32(span.length), uint32(payloadStart), nil
}

func (v GeneratorDeclarationView) inspectEntry(index int) (GeneratorDeclarationEntryView, generatorDeclarationSpan, int, error) {
	if index < 0 || index >= len(v.entries) {
		return GeneratorDeclarationEntryView{}, generatorDeclarationSpan{}, 0, ErrRecord
	}
	span := v.entries[index]
	if span.offset < generatorDeclarationHeaderLength || span.offset > len(v.body) || span.length < 0 || span.length > len(v.body)-span.offset {
		return GeneratorDeclarationEntryView{}, generatorDeclarationSpan{}, 0, ErrRecord
	}
	row, payloadStart, err := inspectGeneratorDeclarationEntry(v.body[span.offset : span.offset+span.length : span.offset+span.length])
	return row, span, span.offset + payloadStart, err
}

func (v GeneratorDeclarationView) Own() (GeneratorDeclaration, error) {
	checked, err := InspectGeneratorDeclaration(v.body)
	if err != nil || checked.DomainID != v.DomainID || checked.OperationID != v.OperationID {
		return GeneratorDeclaration{}, ErrRecord
	}
	out := GeneratorDeclaration{Schema: GeneratorRecordSchema, DomainID: v.DomainID, OperationID: v.OperationID, Entries: make([]GeneratorDeclarationEntry, checked.EntryCount())}
	for i := range out.Entries {
		row, _, err := checked.Entry(i)
		if err != nil {
			return GeneratorDeclaration{}, err
		}
		entry := GeneratorDeclarationEntry{Schema: row.Schema, Kind: row.Kind, InputEncoding: row.InputEncoding, OutputEncoding: row.OutputEncoding, Name: string(row.Name), Payload: ownedBytes(row.Payload), Recipients: make([]ID, len(row.RecipientIDs)/32)}
		for j := range entry.Recipients {
			entry.Recipients[j] = ID(row.RecipientIDs[j*32 : (j+1)*32])
		}
		out.Entries[i] = entry
	}
	return out, nil
}

func GeneratorDeclarationDescriptor(v GeneratorDeclaration) (GeneratorDescriptor, error) {
	n, err := GeneratorDeclarationLength(v)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	w := generatorVectorHashWriter("declaration", n+8, 1)
	w.u32(uint32(n))
	writeGeneratorDeclaration(&w, v)
	return generatorVectorResult(&w, n+8, 1), nil
}

func (v GeneratorDeclarationView) Descriptor() (GeneratorDescriptor, error) {
	checked, err := InspectGeneratorDeclaration(v.body)
	if err != nil || checked.DomainID != v.DomainID || checked.OperationID != v.OperationID {
		return GeneratorDescriptor{}, ErrRecord
	}
	n := len(v.body) + 8
	w := generatorVectorHashWriter("declaration", n, 1)
	w.blob(v.body)
	return generatorVectorResult(&w, n, 1), nil
}

func GeneratorIntendedMembershipDescriptor(recipients []ID) (GeneratorDescriptor, error) {
	if _, err := recipientIDsLength(recipients); err != nil {
		return GeneratorDescriptor{}, err
	}
	n := 4 + (4+len(ID{}))*len(recipients)
	w := generatorVectorHashWriter("intended-membership", n, len(recipients))
	for _, id := range recipients {
		w.blob(id[:])
	}
	return generatorVectorResult(&w, n, len(recipients)), nil
}

func GeneratorDeclarationEntryID(domain, operation ID, name string) (ID, error) {
	if len(name) > CryptoMaxName {
		return ID{}, ErrRecordCapacity
	}
	if !publicIDsValid(domain, operation) || !utf8.ValidString(name) {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 68+len(name))}
	w.id(domain)
	w.id(operation)
	w.blob([]byte(name))
	return generatorDigest("declaration-entry", w.b), nil
}

func GeneratorIntentDigest(b []byte) (ID, error) {
	if len(b) > GeneratorIntentMaxLength {
		return ID{}, ErrRecordCapacity
	}
	if _, err := InspectGeneratorIntent(b); err != nil {
		return ID{}, ErrRecord
	}
	digest, err := protocol.IntentDigest(b)
	if err != nil {
		return ID{}, ErrRecord
	}
	return ID(digest), nil
}
