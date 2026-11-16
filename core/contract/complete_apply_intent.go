package contract

import "bytes"

const (
	completeApplyIntentPrefix   = cryptoPurposePrefix + "complete-apply-intent-v1\x00"
	completeApplyIntentFraming  = len(completeApplyIntentPrefix) + 32 + 2*4
	applyRecipientRecordMinimum = recipientRecordFixedLength + kmsBindingFixedLength + 1
	applyRegistryRecordLimit    = min(MaxPublicRegistryBytes, CryptoMaxRecipients*RecipientRecordMaxLength)
	applyRegistryMinimum        = 4 + applyRecipientRecordMinimum + 1
	applyRegistryLimit          = 4 + applyRegistryRecordLimit + CryptoMaxRecipients*(1+2*32)
	currentApplyRegistryLimit   = 4 + applyRegistryRecordLimit
	completeApplyIntentLimit    = completeApplyIntentFraming + cryptoIntentLimit + applyRegistryLimit
)

type RecipientCreationProof struct {
	Snapshot, Nonce ID
}

type ApplyRecipientInput struct {
	Recipient RecipientRecord
	Creation  *RecipientCreationProof
}

func applyRecipientRecordLength(row RecipientRecord) (int, error) {
	if row.Status != CurrentRecipient {
		return 0, ErrCryptoMessage
	}
	return RecipientRecordLength(row)
}

func applyRecipientsLength(rows []ApplyRecipientInput) (int, error) {
	if len(rows) > CryptoMaxRecipients {
		return 0, ErrCryptoCapacity
	}
	if len(rows) == 0 {
		return 0, ErrCryptoMessage
	}
	n, records := 4, 0
	for i, row := range rows {
		length, err := applyRecipientRecordLength(row.Recipient)
		if err != nil {
			return 0, err
		}
		if i > 0 && bytes.Compare(rows[i-1].Recipient.RecipientID[:], row.Recipient.RecipientID[:]) >= 0 {
			return 0, ErrCryptoMessage
		}
		records += length
		if records > MaxPublicRegistryBytes {
			return 0, ErrCryptoCapacity
		}
		n += length + 1
		if row.Creation != nil {
			if row.Creation.Snapshot.IsZero() || row.Creation.Nonce.IsZero() {
				return 0, ErrCryptoMessage
			}
			n += 64
		}
	}
	return n, nil
}

func currentApplyRecipientsLength(rows []RecipientRecord) (int, error) {
	if len(rows) > CryptoMaxRecipients {
		return 0, ErrCryptoCapacity
	}
	if len(rows) == 0 {
		return 0, ErrCryptoMessage
	}
	n := 4
	for i, row := range rows {
		length, err := applyRecipientRecordLength(row)
		if err != nil {
			return 0, err
		}
		if i > 0 && bytes.Compare(rows[i-1].RecipientID[:], row.RecipientID[:]) >= 0 {
			return 0, ErrCryptoMessage
		}
		n += length
		if n-4 > MaxPublicRegistryBytes {
			return 0, ErrCryptoCapacity
		}
	}
	return n, nil
}

func writeApplyRecipients(w *cryptoWriter, rows []ApplyRecipientInput) {
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		writeRecipientRecord(w, row.Recipient)
		if row.Creation == nil {
			w.u8(0)
			continue
		}
		w.u8(1)
		w.id(row.Creation.Snapshot)
		w.id(row.Creation.Nonce)
	}
}

func writeCurrentApplyRecipients(w *cryptoWriter, rows []RecipientRecord) {
	w.u32(uint32(len(rows)))
	for _, row := range rows {
		writeRecipientRecord(w, row)
	}
}

type applyRecipientRowView struct {
	recipient RecipientRecordView
	creation  RecipientCreationProof
	present   bool
}

type applyRecipientProjectionView struct {
	rows      []byte
	count     int
	withProof bool
}

func readApplyRecipientRow(r *cryptoReader, withProof bool) applyRecipientRowView {
	row := applyRecipientRowView{recipient: readRecipientRecord(r)}
	if r.err == nil && row.recipient.Status != CurrentRecipient {
		r.err = ErrCryptoMessage
	}
	if withProof {
		tag := r.u8()
		if r.err == nil && tag > 1 {
			r.err = ErrCryptoMessage
		}
		row.present = tag == 1
		if row.present {
			row.creation = RecipientCreationProof{Snapshot: r.requiredID(), Nonce: r.requiredID()}
		}
	}
	return row
}

// The complete fixed-scratch scan precedes retained slice, string, binding and
// proof allocation. Public-key parsing follows structural validation and is
// bounded by one fixed 422-byte key at a time.
func readApplyRecipientProjection(r *cryptoReader, withProof bool) applyRecipientProjectionView {
	minimum := applyRecipientRecordMinimum
	if withProof {
		minimum++
	}
	v := applyRecipientProjectionView{count: r.count(CryptoMaxRecipients, minimum), withProof: withProof}
	if r.err == nil && v.count == 0 {
		r.err = ErrCryptoMessage
	}
	start, records := r.i, 0
	var previous ID
	for i := 0; i < v.count && r.err == nil; i++ {
		before := r.i
		row := readApplyRecipientRow(r, withProof)
		length := r.i - before
		if withProof {
			length--
			if row.present {
				length -= 64
			}
		}
		records += length
		if r.err == nil && records > MaxPublicRegistryBytes {
			r.err = ErrCryptoCapacity
		}
		if r.err == nil && i > 0 && bytes.Compare(previous[:], row.recipient.RecipientID[:]) >= 0 {
			r.err = ErrCryptoMessage
		}
		previous = row.recipient.RecipientID
	}
	v.rows = r.b[start:r.i:r.i]
	return v
}

func (v applyRecipientProjectionView) keysError() error {
	r := cryptoReader{b: v.rows}
	for i := 0; i < v.count; i++ {
		row := readApplyRecipientRow(&r, v.withProof)
		if r.err != nil {
			return r.failure()
		}
		if err := ValidatePublicEncryptionKey(row.recipient.CurrentBinding.SPKI, row.recipient.CurrentBinding.Fingerprint); err != nil {
			return err
		}
	}
	return r.end()
}

func (v applyRecipientProjectionView) own() []ApplyRecipientInput {
	rows := make([]ApplyRecipientInput, v.count)
	r := cryptoReader{b: v.rows}
	for i := range rows {
		row := readApplyRecipientRow(&r, v.withProof)
		rows[i].Recipient = row.recipient.own()
		if row.present {
			proof := row.creation
			rows[i].Creation = &proof
		}
	}
	return rows
}

func (v applyRecipientProjectionView) ownCurrent() []RecipientRecord {
	rows := make([]RecipientRecord, v.count)
	r := cryptoReader{b: v.rows}
	for i := range rows {
		rows[i] = readApplyRecipientRow(&r, false).recipient.own()
	}
	return rows
}

func completeApplyIntentLengths(domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput) (value, registry int, err error) {
	value, err = cryptoIntentSize(domain, values)
	if err != nil {
		return 0, 0, err
	}
	registry, err = applyRecipientsLength(recipients)
	return value, registry, err
}

func writeCompleteApplyIntent(w *cryptoWriter, domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput, value, registry int) {
	w.raw([]byte(completeApplyIntentPrefix))
	w.id(domain)
	w.u32(uint32(value))
	cryptoWriteIntent(w, domain, values)
	w.u32(uint32(registry))
	writeApplyRecipients(w, recipients)
}

func CompleteApplyIntentDescriptor(domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput) (DescriptorVector, error) {
	value, registry, err := completeApplyIntentLengths(domain, values, recipients)
	if err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeCompleteApplyIntent(&w, domain, values, recipients, value, registry)
	return w.result(len(values)), nil
}

type completeApplyIntentView struct {
	values     CryptoIntentView
	recipients applyRecipientProjectionView
	descriptor DescriptorVector
}

func readCompleteApplyIntent(r *cryptoReader, domain ID) completeApplyIntentView {
	var v completeApplyIntentView
	start := r.i
	if !bytes.Equal(r.take(len(completeApplyIntentPrefix)), []byte(completeApplyIntentPrefix)) || r.requiredID() != domain {
		if r.err == nil {
			r.err = ErrCryptoMessage
		}
		return v
	}
	body := r.blob(cryptoIntentLimit)
	if r.err != nil {
		return v
	}
	var err error
	v.values, err = InspectCryptoIntent(body, domain)
	if err != nil {
		r.err = err
		return v
	}
	registry := r.blob(applyRegistryLimit)
	if r.err != nil {
		return v
	}
	nested := cryptoReader{b: registry}
	v.recipients = readApplyRecipientProjection(&nested, true)
	if err := nested.end(); err != nil {
		r.err = err
		return v
	}
	v.descriptor = DescriptorVector{Digest: Hash(r.b[start:r.i]), Length: uint64(r.i - start), Count: v.values.Descriptor.Count}
	return v
}
