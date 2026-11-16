package contract

import (
	"bytes"
	"unicode/utf8"
)

const (
	ValueEntryFixedLength       = 154
	Supplied              uint8 = 1
	Generated             uint8 = 2
	Plain                 uint8 = 1
	Secret                uint8 = 2
)

type ValueEntry struct {
	Name                                                      string
	Incarnation, ValueState, OriginSnapshot, OriginTransition ID
	ValueSource, ConfidentialityClass                         uint8
	InputEncoding, OutputEncoding                             uint8
	ContentLength, RetainedLength                             uint32
	Recipients                                                []ID
	ValueBytes                                                []byte
	Generated                                                 GeneratedEntryMetadata
}

// ValueEntryView borrows Name, RecipientIDs and ValueBytes. RecipientIDs contains
// ordered 32-byte rows. Keep the input unchanged until inspection ends or Own
// copies the retained fields. Structural validation grants no authority.
type ValueEntryView struct {
	Name                                                      []byte
	Incarnation, ValueState, OriginSnapshot, OriginTransition ID
	ValueSource, ConfidentialityClass                         uint8
	InputEncoding, OutputEncoding                             uint8
	ContentLength, RetainedLength                             uint32
	RecipientIDs                                              []byte
	ValueBytes                                                []byte
	Generated                                                 GeneratedEntryMetadata
}

func (v ValueEntryView) RecipientCount() int {
	return len(v.RecipientIDs) / 32
}

func (v ValueEntryView) RecipientID(index int) (ID, bool) {
	if index < 0 || index >= v.RecipientCount() {
		return ID{}, false
	}
	return ID(v.RecipientIDs[index*32 : (index+1)*32]), true
}

func (v ValueEntryView) own() ValueEntry {
	out := ValueEntry{Name: string(v.Name), Incarnation: v.Incarnation, ValueState: v.ValueState,
		OriginSnapshot: v.OriginSnapshot, OriginTransition: v.OriginTransition,
		ValueSource: v.ValueSource, ConfidentialityClass: v.ConfidentialityClass, InputEncoding: v.InputEncoding, OutputEncoding: v.OutputEncoding, ContentLength: v.ContentLength, RetainedLength: v.RetainedLength, ValueBytes: ownedBytes(v.ValueBytes), Generated: v.Generated}
	if count := v.RecipientCount(); count != 0 {
		out.Recipients = make([]ID, count)
		for i := range out.Recipients {
			out.Recipients[i] = ID(v.RecipientIDs[i*32 : (i+1)*32])
		}
	}
	return out
}

func (v ValueEntryView) Own() (ValueEntry, error) {
	if len(v.Name) > CryptoMaxName || len(v.ValueBytes) > canonicalPayloadMaxLength {
		return ValueEntry{}, ErrRecordCapacity
	}
	if !utf8.Valid(v.Name) || !ValidatePublicEntryTags(v.ValueSource, v.ConfidentialityClass) ||
		!publicIDsValid(v.Incarnation, v.ValueState, v.OriginSnapshot, v.OriginTransition) {
		return ValueEntry{}, ErrRecord
	}
	if err := recipientIDSpanError(v.RecipientIDs); err != nil {
		return ValueEntry{}, err
	}
	if _, err := valueEntryGeneratedMetadataLength(v.ValueSource, v.ValueState, v.Generated); err != nil {
		return ValueEntry{}, err
	}
	if err := valueEntryRepresentation(v.InputEncoding, v.OutputEncoding, v.ContentLength, v.RetainedLength, v.ConfidentialityClass, v.ValueBytes); err != nil {
		return ValueEntry{}, err
	}

	return v.own(), nil
}

func ValidatePublicEntryTags(valueSource, confidentialityClass uint8) bool {
	return valueSource == Supplied && (confidentialityClass == Plain || confidentialityClass == Secret) || valueSource == Generated && confidentialityClass == Secret
}

func valueEntryGeneratedMetadataLength(valueSource uint8, valueState ID, generated GeneratedEntryMetadata) (int, error) {
	if valueSource == Supplied {
		if generated != (GeneratedEntryMetadata{}) {
			return 0, ErrRecord
		}
		return 0, nil
	}
	if valueSource != Generated || generated.GenerationID != valueState {
		return 0, ErrRecord
	}
	return GeneratedEntryMetadataLength(generated)
}

func recipientIDsLength(ids []ID) (int, error) {
	if len(ids) > CryptoMaxValueEntryRecipients {
		return 0, ErrRecordCapacity
	}
	if len(ids) == 0 {
		return 0, ErrRecord
	}
	for i, id := range ids {
		if id.IsZero() || i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
			return 0, ErrRecord
		}
	}
	return 2 + 32*len(ids), nil
}

func writeRecipientIDs(w *cryptoWriter, ids []ID) {
	w.u16(uint16(len(ids)))
	for _, id := range ids {
		w.id(id)
	}
}

func recipientIDSpanError(ids []byte) error {
	if len(ids) > 32*CryptoMaxValueEntryRecipients {
		return ErrRecordCapacity
	}
	if len(ids) == 0 || len(ids)%32 != 0 {
		return ErrRecord
	}
	for i := 0; i < len(ids); i += 32 {
		id := ids[i : i+32]
		if ID(id).IsZero() || i > 0 && bytes.Compare(ids[i-32:i], id) >= 0 {
			return ErrRecord
		}
	}
	return nil
}

func readRecipientIDs(r *cryptoReader) []byte {
	count := r.u16()
	if r.err != nil {
		return nil
	}
	if count > CryptoMaxValueEntryRecipients {
		r.err = ErrRecordCapacity
		return nil
	}
	if count == 0 {
		r.err = ErrRecord
		return nil
	}
	ids := r.take(32 * int(count))
	if r.err != nil {
		return nil
	}
	if r.err = recipientIDSpanError(ids); r.err != nil {
		return nil
	}
	return ids
}

func ValueEntryLength(m ValueEntry) (int, error) {
	if len(m.Name) > CryptoMaxName || len(m.ValueBytes) > canonicalPayloadMaxLength {
		return 0, ErrRecordCapacity
	}
	recipientsLength, err := recipientIDsLength(m.Recipients)
	if err != nil {
		return 0, err
	}
	if !utf8.ValidString(m.Name) || !ValidatePublicEntryTags(m.ValueSource, m.ConfidentialityClass) ||
		!publicIDsValid(m.Incarnation, m.ValueState, m.OriginSnapshot, m.OriginTransition) {
		return 0, ErrRecord
	}
	generatedLength, err := valueEntryGeneratedMetadataLength(m.ValueSource, m.ValueState, m.Generated)
	if err != nil {
		return 0, err
	}
	if err := valueEntryRepresentation(m.InputEncoding, m.OutputEncoding, m.ContentLength, m.RetainedLength, m.ConfidentialityClass, m.ValueBytes); err != nil {
		return 0, err
	}

	// ValueEntryFixedLength already includes the recipient count.
	return ValueEntryFixedLength - 2 + len(m.Name) + recipientsLength + len(m.ValueBytes) + generatedLength, nil
}

func writeValueEntry(w *cryptoWriter, m ValueEntry) {
	w.blob([]byte(m.Name))
	w.id(m.Incarnation)
	w.id(m.ValueState)
	w.id(m.OriginSnapshot)
	w.id(m.OriginTransition)
	w.u8(m.ValueSource)
	w.u8(m.ConfidentialityClass)
	w.u8(m.InputEncoding)
	w.u32(m.ContentLength)
	w.u32(m.RetainedLength)
	w.u8(m.OutputEncoding)
	writeRecipientIDs(w, m.Recipients)
	w.blob(m.ValueBytes)
	if m.ValueSource == Supplied {
		w.u32(0)
	} else {
		n, _ := GeneratedEntryMetadataLength(m.Generated)
		w.u32(uint32(n))
		writeGeneratedEntryMetadata(w, m.Generated)
	}
}

func readValueEntry(r *cryptoReader) ValueEntryView {
	v := ValueEntryView{Name: r.name(), Incarnation: r.requiredID(), ValueState: r.requiredID(),
		OriginSnapshot: r.requiredID(), OriginTransition: r.requiredID(), ValueSource: r.u8(), ConfidentialityClass: r.u8(), InputEncoding: r.u8(), ContentLength: r.u32(), RetainedLength: r.u32(), OutputEncoding: r.u8()}
	v.RecipientIDs = readRecipientIDs(r)
	if r.err != nil {
		return v
	}
	if !ValidatePublicEntryTags(v.ValueSource, v.ConfidentialityClass) {
		r.err = ErrRecord
		return v
	}
	limit := CryptoMaxRetainedValue
	if v.ConfidentialityClass == Secret {
		limit = canonicalPayloadMaxLength
	}
	v.ValueBytes = r.blob(limit)
	if r.err != nil {
		return v
	}
	r.err = valueEntryRepresentation(v.InputEncoding, v.OutputEncoding, v.ContentLength, v.RetainedLength, v.ConfidentialityClass, v.ValueBytes)
	if r.err != nil {
		return v
	}

	generated := r.blob(GeneratedEntryMetadataMaxLength)
	if r.err != nil {
		return v
	}
	if v.ValueSource == Supplied {
		if len(generated) != 0 {
			r.err = ErrRecord
			return v
		}
	} else {
		v.Generated, r.err = InspectGeneratedEntryMetadata(generated)
	}
	if r.err == nil {
		_, r.err = valueEntryGeneratedMetadataLength(v.ValueSource, v.ValueState, v.Generated)
	}
	return v
}

func AppendValueEntry(dst []byte, m ValueEntry) ([]byte, error) {
	if _, err := ValueEntryLength(m); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeValueEntry(&w, m)
	return w.b, nil
}

func EncodeValueEntry(m ValueEntry) ([]byte, error) {
	n, err := ValueEntryLength(m)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeValueEntry(&w, m)
	return w.b, nil
}

func ParseValueEntry(b []byte) (ValueEntryView, int, error) {
	r := newRecordReader(b)
	v := readValueEntry(&r)
	if r.err != nil {
		return ValueEntryView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectValueEntry(b []byte) (ValueEntryView, error) {
	if len(b) > CryptoMaxValueEntryLength {
		return ValueEntryView{}, ErrRecordCapacity
	}
	v, n, err := ParseValueEntry(b)
	if err != nil {
		return ValueEntryView{}, err
	}
	if n != len(b) {
		return ValueEntryView{}, ErrRecord
	}
	return v, nil
}

func DecodeValueEntry(b []byte) (ValueEntry, error) {
	v, err := InspectValueEntry(b)
	if err != nil {
		return ValueEntry{}, err
	}
	return v.own(), nil
}

func valueEntryRepresentation(input, output uint8, content, retained uint32, class uint8, body []byte) error {
	if err := InputLengths(input, content, retained); err != nil {
		return err
	}
	if output != OutputEncodingRaw && output != OutputEncodingBase64 {
		return ErrRecord
	}
	if class == Plain {
		actual, err := InputContentLength(input, body)
		if err != nil {
			return err
		}
		if actual != content || uint32(len(body)) != retained {
			return ErrRecord
		}
		return nil
	}
	payload, err := InspectCanonicalPayload(body)
	if err != nil {
		return err
	}
	if payload.InputEncoding != input || payload.ContentLength != content || payload.RetainedLength != retained {
		return ErrRecord
	}
	return nil
}
