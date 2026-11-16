package contract

// The ordinary projections have their own framing, including nonempty
// preimages for zero-row projections. Preserve that descriptor as one typed
// generated row; do not reinterpret its count as the outer vector count.
func generatorAuthorityProjection(label string, inner DescriptorVector) GeneratorDescriptor {
	const length = 4 + 4 + descriptorSize
	w := generatorVectorHashWriter(label, length, 1)
	w.u32(descriptorSize)
	w.descriptor(inner)
	return generatorVectorResult(&w, length, 1)
}

func GeneratorAuthorityIdentityDescriptor(plan IdentityPlan) (GeneratorDescriptor, error) {
	d, err := IdentityPlanDescriptor(plan)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	return generatorAuthorityProjection("authority-identity-plan", d), nil
}

// GeneratorAuthorityValueEntriesDescriptor binds the complete actual before/after
// union, including unchanged entries. Every present side has an actual digest.
func GeneratorAuthorityValueEntriesDescriptor(domain ID, rows []UnionRow) (GeneratorDescriptor, error) {
	d, err := UnionDescriptor(domain, rows)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	for _, row := range rows {
		if row.BeforePresent && row.Before.EntryDigest.IsZero() || row.AfterPresent && row.After.EntryDigest.IsZero() {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	return generatorAuthorityProjection("authority-member-changes", d), nil
}

// GeneratorAuthorityMembershipDescriptor binds an intended membership union.
// Before entries are authenticated values; all after-entry digests are zero
// because their future ciphertext is not part of membership planning.
func GeneratorAuthorityMembershipDescriptor(domain ID, rows []UnionRow) (GeneratorDescriptor, error) {
	d, err := UnionDescriptor(domain, rows)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	for _, row := range rows {
		if row.BeforePresent && row.Before.EntryDigest.IsZero() || row.AfterPresent && !row.After.EntryDigest.IsZero() {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	return generatorAuthorityProjection("authority-membership-plan", d), nil
}

// GeneratorAuthorityWorkDescriptor receives the authenticated live-work set.
// Core excludes receipt rows and the separately owned receipt-index blob.
func GeneratorAuthorityWorkDescriptor(domain ID, rows []SupportRecord) (GeneratorDescriptor, error) {
	d, err := RequiredSupportDescriptor(domain, rows)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	for _, row := range rows {
		if row.Kind == MutationReceiptSupportKind {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	return generatorAuthorityProjection("authority-work", d), nil
}

// GeneratorAuthorityWorkDescriptorFromDigests uses rows that a complete
// selected-page scan already inspected and bound to exact page references.
func GeneratorAuthorityWorkDescriptorFromDigests(domain ID, rows []SupportRecordDigest) (GeneratorDescriptor, error) {
	d, err := RequiredSupportDescriptorFromDigests(domain, rows)
	if err != nil {
		return GeneratorDescriptor{}, err
	}
	for _, row := range rows {
		if row.Kind() == MutationReceiptSupportKind {
			return GeneratorDescriptor{}, ErrRecord
		}
	}
	return generatorAuthorityProjection("authority-work", d), nil
}
