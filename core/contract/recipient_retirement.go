package contract

const RecipientRetirementRowLength = 2 + 2*32 + 4

type RecipientRetirementRow struct {
	Slot               uint16
	RecipientID        ID
	BeforeRecordDigest ID
	BeforeRecordLength uint32
}

func recipientRetirementRowError(row RecipientRetirementRow) error {
	if row.Slot >= CryptoMaxRecipients || !publicIDsValid(row.RecipientID, row.BeforeRecordDigest) ||
		row.BeforeRecordLength < uint32(applyRecipientRecordMinimum) || row.BeforeRecordLength > uint32(RecipientRecordMaxLength) {
		return ErrRecord
	}
	return nil
}

func NewRecipientRetirementRow(slot uint16, record RecipientRecord) (RecipientRetirementRow, error) {
	length, err := RecipientRecordLength(record)
	if err != nil {
		return RecipientRetirementRow{}, err
	}
	if record.Status != CurrentRecipient || slot >= CryptoMaxRecipients {
		return RecipientRetirementRow{}, ErrRecord
	}
	w := cryptoHashWriter("")
	writeRecipientRecord(&w, record)
	row := RecipientRetirementRow{Slot: slot, RecipientID: record.RecipientID, BeforeRecordDigest: w.result(0).Digest, BeforeRecordLength: uint32(length)}
	return row, recipientRetirementRowError(row)
}

func writeRecipientRetirementRow(w *cryptoWriter, row RecipientRetirementRow) {
	w.u16(row.Slot)
	w.id(row.RecipientID)
	w.id(row.BeforeRecordDigest)
	w.u32(row.BeforeRecordLength)
}

func readRecipientRetirementRow(r *cryptoReader) RecipientRetirementRow {
	row := RecipientRetirementRow{Slot: r.u16(), RecipientID: r.requiredID(), BeforeRecordDigest: r.requiredID(), BeforeRecordLength: r.u32()}
	if r.err == nil {
		r.err = recipientRetirementRowError(row)
	}
	return row
}

func retirementRowsError(domain ID, rows []RecipientRetirementRow) error {
	if len(rows) > 1 {
		return ErrRecordCapacity
	}
	if domain.IsZero() {
		return ErrRecord
	}
	if len(rows) != 0 {
		return recipientRetirementRowError(rows[0])
	}
	return nil
}

func writeRetirements(w *cryptoWriter, domain ID, rows []RecipientRetirementRow) {
	writeProjectionStart(w, cryptoRetirementPrefix, domain, len(rows))
	for _, row := range rows {
		writeRecipientRetirementRow(w, row)
	}
}
