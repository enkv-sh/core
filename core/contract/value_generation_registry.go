package contract

import "bytes"

const GeneratedRecipientRegistrySchema uint16 = 1
const GeneratedRecipientRegistryMaxLength = MaxPublicRegistryBytes - 8

type GeneratedRecipientRegistryImage struct {
	Schema                                               uint16
	DomainID, OperationID, OriginalPredecessorSnapshotID ID
	Recipients                                           []ApplyRecipientInput
	InitiallyAbsent                                      []ID
}

func GeneratedRecipientRegistryImageLength(v GeneratedRecipientRegistryImage) (int, error) {
	if v.Schema != GeneratedRecipientRegistrySchema || !publicIDsValid(v.DomainID, v.OperationID, v.OriginalPredecessorSnapshotID) || len(v.InitiallyAbsent) > len(v.Recipients) {
		return 0, ErrRecord
	}
	n, err := applyRecipientsLength(v.Recipients)
	if err != nil {
		return 0, err
	}
	for i, id := range v.InitiallyAbsent {
		if id.IsZero() || i > 0 && bytes.Compare(v.InitiallyAbsent[i-1][:], id[:]) >= 0 {
			return 0, ErrRecord
		}
		found := false
		for _, row := range v.Recipients {
			if row.Recipient.RecipientID == id {
				found = true
				break
			}
		}
		if !found {
			return 0, ErrRecord
		}
	}
	n += 2 + 3*len(ID{}) + 4 + len(v.InitiallyAbsent)*len(ID{})
	if n > GeneratedRecipientRegistryMaxLength {
		return 0, ErrRecordCapacity
	}
	return n, nil
}

func writeGeneratedRecipientRegistry(w *cryptoWriter, v GeneratedRecipientRegistryImage) {
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.OriginalPredecessorSnapshotID)
	writeApplyRecipients(w, v.Recipients)
	w.u32(uint32(len(v.InitiallyAbsent)))
	for _, id := range v.InitiallyAbsent {
		w.id(id)
	}
}

func EncodeGeneratedRecipientRegistryImage(v GeneratedRecipientRegistryImage) ([]byte, error) {
	n, err := GeneratedRecipientRegistryImageLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGeneratedRecipientRegistry(&w, v)
	return w.b, nil
}

func DecodeGeneratedRecipientRegistryImage(body []byte) (GeneratedRecipientRegistryImage, error) {
	var out GeneratedRecipientRegistryImage
	if len(body) > GeneratedRecipientRegistryMaxLength {
		return out, ErrRecordCapacity
	}
	r := newRecordReader(body)
	out.Schema = r.u16()
	out.DomainID = r.requiredID()
	out.OperationID = r.requiredID()
	out.OriginalPredecessorSnapshotID = r.requiredID()
	rows := readApplyRecipientProjection(&r, true)
	n := r.count(CryptoMaxRecipients, len(ID{}))
	var absent [CryptoMaxRecipients]ID
	for i := 0; i < n && r.err == nil; i++ {
		absent[i] = r.requiredID()
		if i > 0 && bytes.Compare(absent[i-1][:], absent[i][:]) >= 0 {
			r.err = ErrRecord
		}
	}
	if err := r.end(); err != nil {
		return GeneratedRecipientRegistryImage{}, err
	}
	if err := rows.keysError(); err != nil {
		return GeneratedRecipientRegistryImage{}, err
	}
	out.Recipients = rows.own()
	out.InitiallyAbsent = append([]ID(nil), absent[:n]...)
	if _, err := GeneratedRecipientRegistryImageLength(out); err != nil {
		return GeneratedRecipientRegistryImage{}, err
	}
	return out, nil
}

func GeneratedRecipientRegistryDescriptor(body []byte) (GeneratorDescriptor, error) {
	if _, err := DecodeGeneratedRecipientRegistryImage(body); err != nil {
		return GeneratorDescriptor{}, err
	}
	n := 8 + len(body)
	w := generatorVectorHashWriter("recipient-registry-image", n, 1)
	w.blob(body)
	return generatorVectorResult(&w, n, 1), nil
}
