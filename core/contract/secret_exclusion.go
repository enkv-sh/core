package contract

type SecretExclusionPath struct {
	Core               ValueCore
	EntryDigest        ID
	SemanticCommitment ID
	RemovedRecipients  []ID
	ActingRecipient    ID
	BeforeAccessRoot   ID
}

func writeSecretExclusion(w *cryptoWriter, v SecretExclusionPath) {
	w.raw([]byte(cryptoPurposePrefix + "secret-exclusion-v6\x00"))
	writeValueCoreBlob(w, v.Core)
	w.id(v.EntryDigest)
	w.id(v.SemanticCommitment)
	writeRecipientIDs(w, v.RemovedRecipients)
	w.id(v.ActingRecipient)
	w.id(v.BeforeAccessRoot)
}

// SecretExclusionDigest binds public path facts. Custody must authenticate the
// predecessor privately before returning this digest as exclusion evidence.
func SecretExclusionDigest(v SecretExclusionPath) (ID, error) {
	if _, err := ValueCoreLength(v.Core); err != nil {
		return ID{}, err
	}
	if _, err := recipientIDsLength(v.RemovedRecipients); err != nil {
		return ID{}, err
	}
	if v.ActingRecipient.IsZero() {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("")
	writeSecretExclusion(&w, v)
	return w.result(0).Digest, nil
}
