package contract

import "bytes"

const LifecycleSubjectLength = 715
const (
	digestLengthSize = 32 + 8
	descriptorSize   = digestLengthSize + 4
	lifecyclePrefix  = "ENKV/K2-LIFECYCLE/v8\x00"
	normalPrefix     = "ENKV/K2-NORMAL/v8\x00"
	grantPrefix      = "ENKV/K2-GRANT/v8\x00"
	exclusionPrefix  = "ENKV/K2-EXCLUSION/v8\x00"
)

type DigestLength struct {
	Digest ID
	Length uint64
}

type DescriptorVector struct {
	Digest ID
	Length uint64
	Count  uint32
}

type NormalSection struct {
	Intent, PublicState DigestLength
	Union               DescriptorVector
	Changed             uint32
}

type GrantSection struct{ Grants DescriptorVector }

type ExclusionSection struct {
	Exclusions, Retirements DescriptorVector
}

type LifecycleSubject struct {
	OperationKind                               uint16
	Operation, Request                          ID
	Recipient, KeyBinding, Fingerprint          ID
	BindingVersion                              uint64
	IdentityPlan                                DigestLength
	HeadCore                                    ID
	HeadCoreLength                              uint32
	ConditionalPlan                             ID
	BeforeValueEntryCount, AfterValueEntryCount uint32
	BeforeSecretCount, AfterSecretCount         uint16
	BeforeRawBytes, AfterRawBytes               uint64
	BeforeAccessRoot, AfterAccessRoot           ID
	BeforeMembershipCount, AfterMembershipCount uint32
	Normal                                      NormalSection
	Grant                                       GrantSection
	Exclusion                                   ExclusionSection
}

func writeLifecycleSubject(w *cryptoWriter, s LifecycleSubject) {
	w.raw([]byte(lifecyclePrefix))
	w.u16(s.OperationKind)
	for _, id := range []ID{s.Operation, s.Request, s.Recipient, s.KeyBinding, s.Fingerprint} {
		w.id(id)
	}
	w.u64(s.BindingVersion)
	w.digestLength(s.IdentityPlan)
	w.id(s.HeadCore)
	w.u32(s.HeadCoreLength)
	w.id(s.ConditionalPlan)
	w.u32(s.BeforeValueEntryCount)
	w.u16(s.BeforeSecretCount)
	w.u32(s.AfterValueEntryCount)
	w.u16(s.AfterSecretCount)
	w.u64(s.BeforeRawBytes)
	w.u64(s.AfterRawBytes)
	w.id(s.BeforeAccessRoot)
	w.id(s.AfterAccessRoot)
	w.u32(s.BeforeMembershipCount)
	w.u32(s.AfterMembershipCount)
	w.raw([]byte(normalPrefix))
	w.digestLength(s.Normal.Intent)
	w.digestLength(s.Normal.PublicState)
	w.descriptor(s.Normal.Union)
	w.u32(s.Normal.Changed)
	w.raw([]byte(grantPrefix))
	w.descriptor(s.Grant.Grants)
	w.raw([]byte(exclusionPrefix))
	w.descriptor(s.Exclusion.Exclusions)
	w.descriptor(s.Exclusion.Retirements)
}

// LifecycleBytes validates necessary signed scalar laws. Admission, signatures
// and exact selected-state relations remain checks of their owning components.
func LifecycleBytes(s LifecycleSubject) ([]byte, error) {
	if !lifecycleValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, LifecycleSubjectLength)}
	writeLifecycleSubject(&w, s)
	return w.b, nil
}

func AppendLifecycleSubject(dst []byte, s LifecycleSubject) ([]byte, error) {
	if !lifecycleValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: dst}
	writeLifecycleSubject(&w, s)
	return w.b, nil
}

func ParseLifecycleSubject(b []byte) (LifecycleSubject, int, error) {
	if len(b) < LifecycleSubjectLength {
		return LifecycleSubject{}, 0, ErrSubject
	}
	r := cryptoReader{b: b[:LifecycleSubjectLength]}
	prefix := func(want string) {
		if !bytes.Equal(r.take(len(want)), []byte(want)) {
			r.err = ErrSubject
		}
	}
	prefix(lifecyclePrefix)
	s := LifecycleSubject{OperationKind: r.u16(), Operation: r.requiredID(), Request: r.requiredID(),
		Recipient: r.requiredID(), KeyBinding: r.requiredID(), Fingerprint: r.requiredID(), BindingVersion: r.u64(),
		IdentityPlan: r.digestLength(), HeadCore: r.requiredID(), HeadCoreLength: r.u32(), ConditionalPlan: r.requiredID(),
		BeforeValueEntryCount: r.u32(), BeforeSecretCount: r.u16(), AfterValueEntryCount: r.u32(), AfterSecretCount: r.u16(), BeforeRawBytes: r.u64(), AfterRawBytes: r.u64(),
		BeforeAccessRoot: r.id(), AfterAccessRoot: r.id(), BeforeMembershipCount: r.u32(), AfterMembershipCount: r.u32()}
	prefix(normalPrefix)
	s.Normal = NormalSection{Intent: r.digestLength(), PublicState: r.digestLength(), Union: r.descriptor(), Changed: r.u32()}
	prefix(grantPrefix)
	s.Grant = GrantSection{Grants: r.descriptor()}
	prefix(exclusionPrefix)
	s.Exclusion = ExclusionSection{Exclusions: r.descriptor(), Retirements: r.descriptor()}
	if r.end() != nil || !lifecycleValid(s) {
		return LifecycleSubject{}, 0, ErrSubject
	}
	return s, r.i, nil
}

func InspectLifecycleSubject(b []byte) (LifecycleSubject, error) {
	if len(b) != LifecycleSubjectLength {
		return LifecycleSubject{}, ErrSubject
	}
	s, _, err := ParseLifecycleSubject(b)
	return s, err
}

func DecodeLifecycleSubject(b []byte) (LifecycleSubject, error) {
	return InspectLifecycleSubject(b)
}

func NewLifecycleRequest(s LifecycleSubject) (SignRequest, error) {
	if !lifecycleValid(s) {
		return SignRequest{}, ErrSubject
	}
	w := cryptoHashWriter("")
	writeLifecycleSubject(&w, s)
	return SignRequest{LifecyclePurpose, w.result(0).Digest}, nil
}

func lifecycleSideValid(entries uint32, secrets uint16, raw uint64, memberships uint32) bool {
	n, m := uint64(entries), uint64(memberships)
	return n <= CryptoMaxValueEntries && uint64(secrets) <= n && raw <= min(uint64(CryptoMaxRawSet), CryptoMaxRawValue*n) &&
		m >= n && m <= min(uint64(CryptoMaxMemberships), CryptoMaxValueEntryRecipients*n)
}

// A entry-row count does not reveal its number of changed recipient relations.
// Encoded length and bounded name bytes restrict that unknown relation count.
func lifecycleRelationRange(length, base, rowWidth, rows, relations, minNames, maxNames uint64) (uint64, uint64, bool) {
	fixed := base + rowWidth*rows
	if minNames > maxNames || length < fixed || length-fixed < minNames {
		return 0, 0, false
	}
	remaining := length - fixed
	low := rows
	if remaining > maxNames {
		low = max(low, (remaining-maxNames+31)/32)
	}
	high := min(CryptoMaxValueEntryRecipients*rows, relations, (remaining-minNames)/32)
	return low, high, low <= high
}

func lifecycleValid(s LifecycleSubject) bool {
	return !s.HeadCore.IsZero() && !s.ConditionalPlan.IsZero() && lifecycleFieldsValid(s)
}

func lifecycleFieldsValid(s LifecycleSubject) bool {
	switch s.OperationKind {
	case OperationApplyDeclaration, OperationRemoveSecretValueEntryAccess, OperationRotateRecipientKeyBinding, OperationRetireRecipientIdentity, OperationEnvelopeRekey:
	default:
		return false
	}

	if !publicIDsValid(s.Operation, s.Request, s.Recipient, s.KeyBinding, s.Fingerprint,
		s.IdentityPlan.Digest, s.Normal.Intent.Digest, s.Normal.PublicState.Digest,
		s.Normal.Union.Digest, s.Grant.Grants.Digest, s.Exclusion.Exclusions.Digest, s.Exclusion.Retirements.Digest) ||
		s.BindingVersion == 0 || s.HeadCoreLength < SuccessorHeadCoreMinLength || s.HeadCoreLength > SuccessorHeadCoreMaxLength ||
		!lifecycleSideValid(s.BeforeValueEntryCount, s.BeforeSecretCount, s.BeforeRawBytes, s.BeforeMembershipCount) ||
		!lifecycleSideValid(s.AfterValueEntryCount, s.AfterSecretCount, s.AfterRawBytes, s.AfterMembershipCount) {
		return false
	}
	before, after := uint64(s.BeforeValueEntryCount), uint64(s.AfterValueEntryCount)
	beforeMemberships, afterMemberships := uint64(s.BeforeMembershipCount), uint64(s.AfterMembershipCount)
	union, changed := uint64(s.Normal.Union.Count), uint64(s.Normal.Changed)
	grants, exclusions := uint64(s.Grant.Grants.Count), uint64(s.Exclusion.Exclusions.Count)
	if union < max(before, after) || union > before+after || changed > union || grants > after || exclusions > before ||
		s.Normal.Union.Length > uint64(cryptoUnionLimit) || s.Grant.Grants.Length > uint64(cryptoGrantLimit) || s.Exclusion.Exclusions.Length > uint64(cryptoExclusionLimit) {
		return false
	}
	if s.OperationKind == OperationRetireRecipientIdentity {
		if s.Exclusion.Retirements.Count != 1 || s.Exclusion.Retirements.Length != uint64(retirementLength+RecipientRetirementRowLength) ||
			before != after || union != before || s.BeforeSecretCount != s.AfterSecretCount || s.BeforeRawBytes != s.AfterRawBytes || grants != 0 ||
			beforeMemberships < afterMemberships || beforeMemberships-afterMemberships != exclusions || changed != exclusions || s.BeforeAccessRoot.IsZero() || s.AfterAccessRoot.IsZero() {
			return false
		}
	} else if s.Exclusion.Retirements.Count != 0 || s.Exclusion.Retirements.Length != uint64(retirementLength) {
		return false
	}
	if s.OperationKind == OperationRemoveSecretValueEntryAccess || s.OperationKind == OperationEnvelopeRekey {
		if before != after || union != before || changed != 1 || s.BeforeSecretCount == 0 || s.BeforeSecretCount != s.AfterSecretCount || s.BeforeRawBytes != s.AfterRawBytes || grants != 0 || s.BeforeAccessRoot.IsZero() || s.AfterAccessRoot.IsZero() || s.BeforeAccessRoot == s.AfterAccessRoot {
			return false
		}
		if s.OperationKind == OperationRemoveSecretValueEntryAccess {
			if exclusions != 1 || beforeMemberships <= afterMemberships || beforeMemberships-afterMemberships >= CryptoMaxValueEntryRecipients {
				return false
			}
		} else if exclusions != 0 || beforeMemberships != afterMemberships {
			return false
		}
	}
	addedNames, removedNames := union-before, union-after
	if changed < addedNames+removedNames || grants < addedNames || exclusions < removedNames ||
		!boundedLength(s.IdentityPlan.Length, uint64(identityBaseLength)+identityRowFixedLength*addedNames, uint64(cryptoIdentityLimit)) {
		return false
	}
	if s.IdentityPlan.Length < uint64(identityBaseLength+identityRowFixedLength) &&
		(s.IdentityPlan.Length-uint64(identityBaseLength))%identityPageLength != 0 {
		return false
	}
	publicBase := uint64(publicStateBaseLength) + publicStateRowFixedLength*after
	if !boundedLength(s.Normal.PublicState.Length, publicBase, publicBase+CryptoMaxName*after) {
		return false
	}
	afterNameBytes := s.Normal.PublicState.Length - publicBase
	unionBase := uint64(unionBaseLength) + unionRowFixedLength*union + membershipSideLength*(before+after) + 32*(beforeMemberships+afterMemberships)
	if !boundedLength(s.Normal.Union.Length, unionBase+afterNameBytes, unionBase+afterNameBytes+CryptoMaxName*removedNames) {
		return false
	}
	if changed == 0 {
		if before != after || union != before || s.BeforeSecretCount != s.AfterSecretCount || s.BeforeRawBytes != s.AfterRawBytes || beforeMemberships != afterMemberships ||
			grants != 0 || exclusions != 0 || s.Grant.Grants.Length != uint64(grantBaseLength) || s.Exclusion.Exclusions.Length != uint64(exclusionBaseLength) ||
			s.BeforeAccessRoot.IsZero() ||
			!boundedLength(s.IdentityPlan.Length, uint64(identityBaseLength+identityPageLength), uint64(identityBaseLength+identityPageLength*MaxChildPages)) ||
			(s.IdentityPlan.Length-uint64(identityBaseLength))%identityPageLength != 0 {
			return false
		}
		if s.OperationKind == OperationRotateRecipientKeyBinding {
			return s.BeforeAccessRoot != s.AfterAccessRoot && boundedLength(s.Normal.Intent.Length, uint64(recipientReplacementIntentMinLength), uint64(recipientReplacementIntentMaxLength))
		}
		return lifecycleIntentLengthValid(s.OperationKind, s.Normal.Intent.Length, after, afterNameBytes, afterMemberships)
	}
	if s.OperationKind == OperationRotateRecipientKeyBinding || !lifecycleIntentLengthValid(s.OperationKind, s.Normal.Intent.Length, after, afterNameBytes, afterMemberships) ||
		changed < max(grants+removedNames, exclusions+addedNames) {
		return false
	}
	grantNameMinimum := uint64(0)
	if afterNameBytes > CryptoMaxName*(after-grants) {
		grantNameMinimum = afterNameBytes - CryptoMaxName*(after-grants)
	}
	grantLow, grantHigh, ok := lifecycleRelationRange(s.Grant.Grants.Length, uint64(grantBaseLength), membershipRowFixedLength, grants,
		afterMemberships-(after-grants), grantNameMinimum, min(afterNameBytes, CryptoMaxName*grants))
	if !ok {
		return false
	}
	removedNameBytes := s.Normal.Union.Length - unionBase - afterNameBytes
	exclusionNameMinimum := removedNameBytes
	if afterNameBytes > CryptoMaxName*(after-(exclusions-removedNames)) {
		exclusionNameMinimum += afterNameBytes - CryptoMaxName*(after-(exclusions-removedNames))
	}
	exclusionNameMaximum := removedNameBytes + min(afterNameBytes, CryptoMaxName*(exclusions-removedNames))
	exclusionLow, exclusionHigh, ok := lifecycleRelationRange(s.Exclusion.Exclusions.Length, uint64(exclusionBaseLength), exclusionRowFixedLength, exclusions,
		beforeMemberships-(before-exclusions), exclusionNameMinimum, exclusionNameMaximum)
	if !ok {
		return false
	}
	// All totals have been bounded to small nonnegative values before signed
	// subtraction. There must be one feasible added/removed relation difference.
	delta := int64(afterMemberships) - int64(beforeMemberships)
	if max(int64(grantLow), int64(exclusionLow)+delta) > min(int64(grantHigh), int64(exclusionHigh)+delta) {
		return false
	}
	// Shared grant/exclusion names cancel. Only names outside their intersection
	// can contribute to the difference in their encoded name-byte totals.
	grantRemainder := s.Grant.Grants.Length - uint64(grantBaseLength) - membershipRowFixedLength*grants
	exclusionRemainder := s.Exclusion.Exclusions.Length - uint64(exclusionBaseLength) - exclusionRowFixedLength*exclusions
	nameDifference := int64(grantRemainder) - int64(exclusionRemainder) - 32*delta + int64(removedNameBytes)
	minimumDifference := -int64(CryptoMaxName * min(exclusions-removedNames, changed-grants-removedNames))
	maximumDifference := int64(CryptoMaxName * min(grants, changed-exclusions))
	return minimumDifference <= nameDifference && nameDifference <= maximumDifference
}

func boundedLength(n, minimum, maximum uint64) bool { return minimum <= n && n <= maximum }

// LifecycleAuthorizationPlan has only the final HeadCore and conditional
// digest holes. The shared writer preserves every other lifecycle field.
type LifecycleAuthorizationPlan LifecycleSubject

func EncodeLifecycleAuthorizationPlan(v LifecycleAuthorizationPlan) ([]byte, error) {
	s := LifecycleSubject(v)
	if !s.HeadCore.IsZero() || !s.ConditionalPlan.IsZero() || !lifecycleFieldsValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, LifecycleSubjectLength)}
	writeLifecycleSubject(&w, s)
	return w.b, nil
}

func lifecycleCompleteIntentLengthValid(length, entries, names, memberships uint64) bool {
	value := uint64(intentBaseLength) + intentRowFixedLength*entries + names + 32*memberships
	return boundedLength(length, value+uint64(completeApplyIntentFraming+applyRegistryMinimum), value+uint64(completeApplyIntentFraming+applyRegistryLimit))
}

func lifecycleIntentLengthValid(kind uint16, length, entries, names, memberships uint64) bool {
	if kind == OperationRetireRecipientIdentity {
		return length >= uint64(recipientRetirementIntentExtraLength) && lifecycleCompleteIntentLengthValid(length-uint64(recipientRetirementIntentExtraLength), entries, names, memberships)
	}
	if kind != OperationRemoveSecretValueEntryAccess && kind != OperationEnvelopeRekey {
		return lifecycleCompleteIntentLengthValid(length, entries, names, memberships)
	}
	if entries == 0 {
		return false
	}
	minimumName := uint64(0)
	if names > CryptoMaxName*(entries-1) {
		minimumName = names - CryptoMaxName*(entries-1)
	}
	minimumExtra, maximumExtra := uint64(secretAccessIntentFixedLength)+minimumName, uint64(secretAccessIntentFixedLength)+min(names, uint64(CryptoMaxName))
	if kind == OperationRemoveSecretValueEntryAccess {
		minimumExtra += 2 + 32
		maximumExtra += 2 + 32*(CryptoMaxValueEntryRecipients-1)
	}
	value := uint64(intentBaseLength) + intentRowFixedLength*entries + names + 32*memberships
	return boundedLength(length, value+uint64(completeApplyIntentFraming+applyRegistryMinimum)+minimumExtra, value+uint64(completeApplyIntentFraming+applyRegistryLimit)+maximumExtra)
}
