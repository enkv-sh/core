package contract

// RecipientCreationID derives an additional recipient from its fixed original
// selected predecessor and the nonce saved by explicit preparation.
func RecipientCreationID(domain, snapshot, nonce ID) (ID, error) {
	if domain.IsZero() || snapshot.IsZero() || nonce.IsZero() {
		return ID{}, ErrRecord
	}
	const prefix = "ENKV/recipient-creation/v1\x00"
	var preimage [len(prefix) + 3*len(ID{})]byte
	copy(preimage[:], prefix)
	copy(preimage[len(prefix):], domain[:])
	copy(preimage[len(prefix)+len(ID{}):], snapshot[:])
	copy(preimage[len(prefix)+2*len(ID{}):], nonce[:])
	id := Hash(preimage[:])
	if id.IsZero() {
		return ID{}, ErrRecord
	}
	return id, nil
}

// RecipientInitialBindingIDs fixes the two initial binding identities before
// confidential input can be prepared for an additional recipient.
func RecipientInitialBindingIDs(domain, recipient ID) (binding, incarnation ID, err error) {
	if domain.IsZero() || recipient.IsZero() {
		return ID{}, ID{}, ErrRecord
	}
	const bindingPrefix = "ENKV/recipient-initial-binding/v1\x00"
	const incarnationPrefix = "ENKV/recipient-initial-incarnation/v1\x00"
	var bindingPreimage [len(bindingPrefix) + 2*len(ID{})]byte
	copy(bindingPreimage[:], bindingPrefix)
	copy(bindingPreimage[len(bindingPrefix):], domain[:])
	copy(bindingPreimage[len(bindingPrefix)+len(ID{}):], recipient[:])
	var incarnationPreimage [len(incarnationPrefix) + 2*len(ID{})]byte
	copy(incarnationPreimage[:], incarnationPrefix)
	copy(incarnationPreimage[len(incarnationPrefix):], domain[:])
	copy(incarnationPreimage[len(incarnationPrefix)+len(ID{}):], recipient[:])
	binding, incarnation = Hash(bindingPreimage[:]), Hash(incarnationPreimage[:])
	if binding.IsZero() || incarnation.IsZero() || binding == incarnation {
		return ID{}, ID{}, ErrRecord
	}
	return binding, incarnation, nil
}
