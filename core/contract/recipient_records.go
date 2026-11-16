package contract

import (
	"unicode/utf8"
)

const (
	recipientRecordFixedLength       = 32 + 1 + 4 + 4
	RecipientRecordMaxLength         = recipientRecordFixedLength + CryptoMaxName + KMSBindingMaxLength
	CurrentRecipient           uint8 = 1
	RetiredRecipient           uint8 = 2
)

type RecipientRecord struct {
	RecipientID ID
	Status      uint8
	DisplayName string

	CurrentBinding *KMSBinding
}

// RecipientRecordView borrows display and nested public key bytes. Keep the
// complete input unchanged until inspection finishes or Own copies it.
type RecipientRecordView struct {
	RecipientID ID
	Status      uint8
	DisplayName []byte

	CurrentBinding KMSBindingView
}

func (v RecipientRecordView) own() RecipientRecord {
	out := RecipientRecord{RecipientID: v.RecipientID, Status: v.Status, DisplayName: string(v.DisplayName)}

	if v.Status == CurrentRecipient && !v.CurrentBinding.BindingID.IsZero() {
		binding := v.CurrentBinding.own()
		out.CurrentBinding = &binding
	}
	return out
}

func (v RecipientRecordView) Own() (RecipientRecord, error) {
	if len(v.DisplayName) > CryptoMaxName {
		return RecipientRecord{}, ErrRecordCapacity
	}
	if v.RecipientID.IsZero() || !utf8.Valid(v.DisplayName) {
		return RecipientRecord{}, ErrRecord
	}

	b := v.CurrentBinding
	switch v.Status {
	case CurrentRecipient:
		if err := kmsBindingViewShapeError(b); err != nil {
			return RecipientRecord{}, err
		}
		if err := ValidatePublicEncryptionKey(b.SPKI, b.Fingerprint); err != nil {
			return RecipientRecord{}, err
		}
	case RetiredRecipient:
		if !b.BindingID.IsZero() || b.BindingSerial != 0 || b.Provider != 0 || b.WrapProfile != 0 ||
			b.ProtectionClass != 0 || len(b.KeySelector) != 0 || len(b.SPKI) != 0 || !b.Fingerprint.IsZero() {
			return RecipientRecord{}, ErrRecord
		}
	default:
		return RecipientRecord{}, ErrRecord
	}
	return v.own(), nil
}

func RecipientRecordLength(v RecipientRecord) (int, error) {
	return recipientRecordLength(v, false)
}

func recipientRecordLength(v RecipientRecord, omitCurrentBinding bool) (int, error) {
	if len(v.DisplayName) > CryptoMaxName {
		return 0, ErrRecordCapacity
	}
	if v.RecipientID.IsZero() || !utf8.ValidString(v.DisplayName) {
		return 0, ErrRecord
	}
	switch v.Status {
	case CurrentRecipient:
		if (v.CurrentBinding == nil) != omitCurrentBinding {
			return 0, ErrRecord
		}
	case RetiredRecipient:
		if v.CurrentBinding != nil {
			return 0, ErrRecord
		}
	default:
		return 0, ErrRecord
	}

	if v.CurrentBinding != nil {
		if _, err := KMSBindingLength(*v.CurrentBinding); err != nil {
			return 0, err
		}
	}
	return recipientRecordEncodedLength(v), nil
}

func recipientRecordEncodedLength(v RecipientRecord) int {
	n := recipientRecordFixedLength + len(v.DisplayName)
	if v.CurrentBinding != nil {
		n += kmsBindingLength(len(v.CurrentBinding.KeySelector))
	}
	return n
}

func writeRecipientRecord(w *cryptoWriter, v RecipientRecord) {
	w.id(v.RecipientID)
	w.u8(v.Status)
	w.blob([]byte(v.DisplayName))

	if v.CurrentBinding == nil {
		w.u32(0)
		return
	}
	w.u32(uint32(kmsBindingLength(len(v.CurrentBinding.KeySelector))))
	writeKMSBinding(w, *v.CurrentBinding)
}

func readRecipientRecord(r *cryptoReader) RecipientRecordView {
	return readRecipientRecordWithOmission(r, ID{})
}

func readRecipientRecordWithOmission(r *cryptoReader, omittedRecipient ID) RecipientRecordView {
	v := RecipientRecordView{RecipientID: r.requiredID(), Status: r.u8(), DisplayName: r.name()}
	binding := r.blob(KMSBindingMaxLength)
	if r.err != nil {
		return v
	}
	switch v.Status {
	case CurrentRecipient:
		if v.RecipientID == omittedRecipient {
			if len(binding) != 0 {
				r.err = ErrRecord
			}
			break
		}
		nested := newRecordReader(binding)
		v.CurrentBinding = readKMSBinding(&nested)
		if err := nested.end(); err != nil {
			r.err = err
			return v
		}
	case RetiredRecipient:
		if len(binding) != 0 {
			r.err = ErrRecord
			return v
		}
	default:
		r.err = ErrRecord
		return v
	}

	return v
}

func AppendRecipientRecord(dst []byte, v RecipientRecord) ([]byte, error) {
	if _, err := RecipientRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeRecipientRecord(&w, v)
	return w.b, nil
}

func EncodeRecipientRecord(v RecipientRecord) ([]byte, error) {
	n, err := RecipientRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeRecipientRecord(&w, v)
	return w.b, nil
}

func ParseRecipientRecord(b []byte) (RecipientRecordView, int, error) {
	r := newRecordReader(b)
	v := readRecipientRecord(&r)
	if r.err != nil {
		return RecipientRecordView{}, 0, r.failure()
	}
	if v.Status == CurrentRecipient {
		if err := ValidatePublicEncryptionKey(v.CurrentBinding.SPKI, v.CurrentBinding.Fingerprint); err != nil {
			return RecipientRecordView{}, 0, err
		}
	}
	return v, r.i, nil
}

func InspectRecipientRecord(b []byte) (RecipientRecordView, error) {
	if len(b) > RecipientRecordMaxLength {
		return RecipientRecordView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readRecipientRecord(&r)
	if err := r.end(); err != nil {
		return RecipientRecordView{}, err
	}
	if v.Status == CurrentRecipient {
		if err := ValidatePublicEncryptionKey(v.CurrentBinding.SPKI, v.CurrentBinding.Fingerprint); err != nil {
			return RecipientRecordView{}, err
		}
	}
	return v, nil
}

func DecodeRecipientRecord(b []byte) (RecipientRecord, error) {
	v, err := InspectRecipientRecord(b)
	if err != nil {
		return RecipientRecord{}, err
	}
	return v.own(), nil
}
