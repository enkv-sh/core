package contract

import "bytes"

const (
	recipientRetirementIntentPrefix      = cryptoPurposePrefix + "recipient-retirement-intent-v1\x00"
	recipientRetirementIntentExtraLength = len(recipientRetirementIntentPrefix) + 4 + RecipientRetirementRowLength
	recipientRetirementIntentLimit       = completeApplyIntentLimit + recipientRetirementIntentExtraLength
)

func RecipientRetirementIntentDescriptor(domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput, row RecipientRetirementRow) (DescriptorVector, error) {
	value, registry, err := completeApplyIntentLengths(domain, values, recipients)
	if err != nil {
		return DescriptorVector{}, err
	}
	if err := recipientRetirementRowError(row); err != nil {
		return DescriptorVector{}, err
	}
	if err := standaloneRecipientsError(recipients); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeRecipientRetirementIntent(&w, domain, values, recipients, row, value, registry)
	return w.result(len(values)), nil
}

func writeRecipientRetirementIntent(w *cryptoWriter, domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput, row RecipientRetirementRow, value, registry int) {
	w.raw([]byte(recipientRetirementIntentPrefix))
	w.u32(uint32(completeApplyIntentFraming + value + registry))
	writeCompleteApplyIntent(w, domain, values, recipients, value, registry)
	writeRecipientRetirementRow(w, row)
}

type recipientRetirementIntentView struct {
	present bool
	row     RecipientRetirementRow
}

func (v recipientRetirementIntentView) own() *RecipientRetirementRow {
	if !v.present {
		return nil
	}
	row := v.row
	return &row
}

func readCompareIntent(r *cryptoReader, domain ID) (completeApplyIntentView, secretAccessIntentView, recipientRetirementIntentView) {
	var retirement recipientRetirementIntentView
	if r.err != nil || !bytes.HasPrefix(r.b[r.i:], []byte(recipientRetirementIntentPrefix)) {
		complete, access := readSecretAccessOrApplyIntent(r, domain)
		return complete, access, retirement
	}
	start := r.i
	r.take(len(recipientRetirementIntentPrefix))
	body := r.blob(completeApplyIntentLimit)
	if r.err != nil {
		return completeApplyIntentView{}, secretAccessIntentView{}, retirement
	}
	nested := r.child(body)
	complete := readCompleteApplyIntent(&nested, domain)
	if err := nested.end(); err != nil {
		r.err = err
		return complete, secretAccessIntentView{}, retirement
	}
	if err := standaloneRecipientProjectionError(complete.recipients); err != nil {
		r.err = err
		return complete, secretAccessIntentView{}, retirement
	}
	retirement.present, retirement.row = true, readRecipientRetirementRow(r)
	if r.err == nil {
		complete.descriptor = DescriptorVector{Digest: Hash(r.b[start:r.i]), Length: uint64(r.i - start), Count: complete.values.Descriptor.Count}
	}
	return complete, secretAccessIntentView{}, retirement
}
