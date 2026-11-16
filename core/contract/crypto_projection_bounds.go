package contract

// Sorted UTF-8 names have one empty string and 128 one-byte strings.
func cryptoMinimumNameBytes(count uint32) uint64 {
	if count <= 1 {
		return 0
	}
	if count <= 129 {
		return uint64(count) - 1
	}
	return 2*uint64(count) - 130
}

func cryptoIntentDescriptorError(domain ID, d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	n := uint64(d.Count)
	minimum := uint64(intentBaseLength) + (intentRowFixedLength+32)*n + cryptoMinimumNameBytes(d.Count)
	maximum := uint64(intentBaseLength) + (intentRowFixedLength+CryptoMaxName)*n + 32*min(CryptoMaxValueEntryRecipients*n, uint64(CryptoMaxMemberships))
	if d.Length > maximum {
		return ErrCryptoCapacity
	}
	if domain.IsZero() || d.Length < minimum {
		return ErrCryptoMessage
	}
	if d.Count == 0 {
		header := cryptoIntentHeader(domain, 0)
		if d.Digest != Hash(header[:]) {
			return ErrCryptoMessage
		}
	}
	return nil
}

func completeApplyIntentDescriptorBounds(count uint32) (minimum, maximum uint64) {
	n := uint64(count)
	valueMinimum := uint64(intentBaseLength) + (intentRowFixedLength+32)*n + cryptoMinimumNameBytes(count)
	valueMaximum := uint64(intentBaseLength) + (intentRowFixedLength+CryptoMaxName)*n + 32*min(CryptoMaxValueEntryRecipients*n, uint64(CryptoMaxMemberships))
	return uint64(completeApplyIntentFraming+applyRegistryMinimum) + valueMinimum, uint64(completeApplyIntentFraming+applyRegistryLimit) + valueMaximum
}

func completeApplyIntentDescriptorError(domain ID, d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	minimum, maximum := completeApplyIntentDescriptorBounds(d.Count)
	if d.Length > maximum {
		return ErrCryptoCapacity
	}
	if domain.IsZero() || d.Digest.IsZero() || d.Length < minimum {
		return ErrCryptoMessage
	}
	return nil
}

// Context is retained through all ordinary lifecycle stages. Compare's explicit
// purpose and the private parent fix which closed intent owns this commitment.
func cryptoLifecycleIntentDescriptorError(domain ID, d DescriptorVector) error {
	if d.Count > CryptoMaxValueEntries {
		return ErrCryptoCapacity
	}
	minimum, maximum := completeApplyIntentDescriptorBounds(d.Count)
	if d.Count != 0 {
		maximum += uint64(secretExclusionIntentExtraLimit)
	} else {
		maximum += uint64(recipientRetirementIntentExtraLength)
	}
	if d.Length > maximum {
		return ErrCryptoCapacity
	}
	if domain.IsZero() || d.Digest.IsZero() || d.Length < minimum {
		return ErrCryptoMessage
	}
	return nil
}
