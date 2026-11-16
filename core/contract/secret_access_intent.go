package contract

import (
	"bytes"
	"unicode/utf8"
)

const (
	secretAccessIntentPrefix        = cryptoPurposePrefix + "secret-access-intent-v1\x00"
	secretAccessIntentFixedLength   = len(secretAccessIntentPrefix) + 2 + 4 + 2 + 4 + 3*32
	secretExclusionIntentExtraLimit = secretAccessIntentFixedLength + CryptoMaxName + 2 + 32*(CryptoMaxValueEntryRecipients-1)
	secretRekeyIntentExtraLimit     = secretAccessIntentFixedLength + CryptoMaxName
	secretAccessIntentLimit         = completeApplyIntentLimit + secretExclusionIntentExtraLimit
)

type SecretAccessTarget struct {
	Slot                                           uint16
	Name                                           string
	Incarnation, Material, BeforePublicEntryDigest ID
}

type CryptoSecretAccessIntent struct {
	OperationKind     uint16
	Target            SecretAccessTarget
	RemovedRecipients []ID
}

func secretAccessTargetError(slot uint16, name []byte, incarnation, material, before ID) error {
	if len(name) > CryptoMaxName {
		return ErrCryptoCapacity
	}
	if slot >= CryptoMaxValueEntries || !utf8.Valid(name) || !publicIDsValid(incarnation, material, before) {
		return ErrCryptoMessage
	}
	return nil
}

func secretAccessIntentLength(v CryptoSecretAccessIntent) (int, error) {
	if err := secretAccessTargetError(v.Target.Slot, []byte(v.Target.Name), v.Target.Incarnation, v.Target.Material, v.Target.BeforePublicEntryDigest); err != nil {
		return 0, err
	}
	n := secretAccessIntentFixedLength + len(v.Target.Name)
	switch v.OperationKind {
	case OperationRemoveSecretValueEntryAccess:
		if len(v.RemovedRecipients) >= CryptoMaxValueEntryRecipients {
			return 0, ErrCryptoCapacity
		}
		length, err := recipientIDsLength(v.RemovedRecipients)
		if err != nil {
			return 0, err
		}
		n += length
	case OperationEnvelopeRekey:
		if len(v.RemovedRecipients) != 0 {
			return 0, ErrCryptoMessage
		}
	default:
		return 0, ErrCryptoMessage
	}
	return n, nil
}

func standaloneRecipientsError(rows []ApplyRecipientInput) error {
	for _, row := range rows {
		if row.Creation != nil {
			return ErrCryptoMessage
		}
	}
	return nil
}

func SecretAccessIntentDescriptor(domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput, intent CryptoSecretAccessIntent) (DescriptorVector, error) {
	value, registry, err := completeApplyIntentLengths(domain, values, recipients)
	if err != nil {
		return DescriptorVector{}, err
	}
	if len(values) == 0 {
		return DescriptorVector{}, ErrCryptoMessage
	}
	if _, err := secretAccessIntentLength(intent); err != nil {
		return DescriptorVector{}, err
	}
	if err := standaloneRecipientsError(recipients); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeSecretAccessIntent(&w, domain, values, recipients, intent, value, registry)
	return w.result(len(values)), nil
}

func writeSecretAccessIntent(w *cryptoWriter, domain ID, values []CryptoIntentRow, recipients []ApplyRecipientInput, intent CryptoSecretAccessIntent, value, registry int) {
	w.raw([]byte(secretAccessIntentPrefix))
	w.u16(intent.OperationKind)
	w.u32(uint32(completeApplyIntentFraming + value + registry))
	writeCompleteApplyIntent(w, domain, values, recipients, value, registry)
	w.u16(intent.Target.Slot)
	w.blob([]byte(intent.Target.Name))
	w.id(intent.Target.Incarnation)
	w.id(intent.Target.Material)
	w.id(intent.Target.BeforePublicEntryDigest)
	if intent.OperationKind == OperationRemoveSecretValueEntryAccess {
		writeRecipientIDs(w, intent.RemovedRecipients)
	}
}

type secretAccessIntentView struct {
	present                       bool
	kind                          uint16
	slot                          uint16
	name, removed                 []byte
	incarnation, material, before ID
}

func (v secretAccessIntentView) own() *CryptoSecretAccessIntent {
	if !v.present {
		return nil
	}
	out := &CryptoSecretAccessIntent{OperationKind: v.kind, Target: SecretAccessTarget{Slot: v.slot, Name: string(v.name), Incarnation: v.incarnation, Material: v.material, BeforePublicEntryDigest: v.before}}
	if len(v.removed) != 0 {
		out.RemovedRecipients = make([]ID, len(v.removed)/32)
		for i := range out.RemovedRecipients {
			out.RemovedRecipients[i] = ID(v.removed[32*i : 32*(i+1)])
		}
	}
	return out
}

func readSecretAccessOrApplyIntent(r *cryptoReader, domain ID) (completeApplyIntentView, secretAccessIntentView) {
	var access secretAccessIntentView
	if r.err != nil {
		return completeApplyIntentView{}, access
	}
	if bytes.HasPrefix(r.b[r.i:], []byte(completeApplyIntentPrefix)) {
		return readCompleteApplyIntent(r, domain), access
	}
	start := r.i
	if !bytes.Equal(r.take(len(secretAccessIntentPrefix)), []byte(secretAccessIntentPrefix)) {
		if r.err == nil {
			r.err = ErrCryptoMessage
		}
		return completeApplyIntentView{}, access
	}
	access.present, access.kind = true, r.u16()
	if r.err == nil && access.kind != OperationRemoveSecretValueEntryAccess && access.kind != OperationEnvelopeRekey {
		r.err = ErrCryptoMessage
	}
	body := r.blob(completeApplyIntentLimit)
	if r.err != nil {
		return completeApplyIntentView{}, access
	}
	nested := cryptoReader{b: body}
	complete := readCompleteApplyIntent(&nested, domain)
	if err := nested.end(); err != nil {
		r.err = err
		return complete, access
	}
	if complete.values.Descriptor.Count == 0 {
		r.err = ErrCryptoMessage
		return complete, access
	}
	if err := standaloneRecipientProjectionError(complete.recipients); err != nil {
		r.err = err
		return complete, access
	}
	access.slot, access.name = r.u16(), r.name()
	access.incarnation, access.material, access.before = r.requiredID(), r.requiredID(), r.requiredID()
	if r.err == nil {
		r.err = secretAccessTargetError(access.slot, access.name, access.incarnation, access.material, access.before)
	}
	if access.kind == OperationRemoveSecretValueEntryAccess {
		access.removed = readRecipientIDs(r)
		if r.err == nil && len(access.removed) >= CryptoMaxValueEntryRecipients*32 {
			r.err = ErrCryptoCapacity
		}
	}
	if r.err == nil {
		complete.descriptor = DescriptorVector{Digest: Hash(r.b[start:r.i]), Length: uint64(r.i - start), Count: complete.values.Descriptor.Count}
	}
	return complete, access
}

func standaloneRecipientProjectionError(v applyRecipientProjectionView) error {
	rows := cryptoReader{b: v.rows}
	for i := 0; i < v.count; i++ {
		if readApplyRecipientRow(&rows, true).present {
			return ErrCryptoMessage
		}
	}
	return rows.end()
}
