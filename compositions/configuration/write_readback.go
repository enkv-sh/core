package configuration

// Digests returns the exact bytes confirmed by this delivery's native readback.
// It is an observation at delivery, not a later path-currentness or Core fact.
func (d *PairDelivery) Digests() (editable, generated [32]byte, err error) {
	if d == nil || d.editable == "" || d.editableDigest == ([32]byte{}) {
		return editable, generated, ErrEdit
	}
	if (d.generated == "") != (d.generatedDigest == ([32]byte{})) {
		return editable, generated, ErrEdit
	}
	return d.editableDigest, d.generatedDigest, nil
}
