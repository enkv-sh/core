package contract

// GeneratorPhaseValueID fixes the value identity for one supplied entry in a
// generated final phase. Generated values use DeriveGeneratedValueIdentity;
// this derivation is only for supplied values prepared in the same atomic set.
func GeneratorPhaseValueID(phase ID, slot uint16) (ID, error) {
	if phase.IsZero() || slot >= CryptoMaxValueEntries {
		return ID{}, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 34)}
	w.id(phase)
	w.u16(slot)
	return generatorDigest("phase-value", w.b), nil
}
