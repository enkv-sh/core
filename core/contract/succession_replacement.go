package contract

import "bytes"

const (
	SuccessionReplaceAuthority     = 1
	SuccessionReplaceRecoveryBasis = 3
)

const (
	SuccessionChangeNormalSigner   = 1
	SuccessionChangeAuthorityKEK   = 2
	SuccessionChangeRecoverySigner = 4
	SuccessionChangeRecoveryKEK    = 8
)

const (
	SuccessionChangeAuthorityMask = SuccessionChangeNormalSigner | SuccessionChangeAuthorityKEK
	SuccessionChangeRecoveryMask  = SuccessionChangeRecoverySigner | SuccessionChangeRecoveryKEK
	SuccessionChangeMask          = SuccessionChangeAuthorityMask | SuccessionChangeRecoveryMask
)

const (
	successionReplacementPrefix            = cryptoPurposePrefix + "succession-replacement-plan-v1\x00"
	successionReplacementFixedLength       = len(successionReplacementPrefix) + 2 + 32 + 1 + 1 + 2
	SuccessionReplacementPlanCoreMaxLength = successionReplacementFixedLength + 2*9 + 2*PublicSigningBindingMaxLength + 2*KMSBindingMaxLength
)

type SuccessionReplacementPlanFields struct {
	Schema                    uint16
	DomainID                  ID
	OperationKind, ChangeMask uint8
}

type SuccessionReplacementRow struct {
	TargetRole                  uint8
	BeforeSigning, AfterSigning PublicSigningBinding
	BeforeKMS, AfterKMS         KMSBinding
}

// SuccessionReplacementPlanCore is a typed hash projection. The containing
// request checks its complete before/after bindings against current control.
type SuccessionReplacementPlanCore struct {
	SuccessionReplacementPlanFields
	Rows []SuccessionReplacementRow
}

func successionRoles(operation, mask uint8) (roles [2]uint8, count int, err error) {
	var allowed uint8
	switch operation {
	case SuccessionReplaceAuthority:
		allowed = SuccessionChangeAuthorityMask
	case SuccessionReplaceRecoveryBasis:
		allowed = SuccessionChangeRecoveryMask
	default:
		return roles, 0, ErrRecord
	}
	if mask == 0 || mask & ^allowed != 0 {
		return roles, 0, ErrRecord
	}
	for role := uint8(SuccessorNormalSigner); role <= SuccessorRecoveryKEK; role++ {
		if mask&(1<<(role-1)) != 0 {
			roles[count] = role
			count++
		}
	}
	return roles, count, nil
}

func successionSigningEmpty(v PublicSigningBinding) bool {
	return v.Schema == 0 && v.Role == 0 && v.Provider == 0 && v.SigningProfile == 0 && v.BindingID.IsZero() &&
		v.KeySelector == "" && len(v.SPKI) == 0 && v.Fingerprint.IsZero() && v.Binding == (BindingSubject{})
}
func successionKMSEmpty(v KMSBinding) bool {
	return v.BindingID.IsZero() && v.BindingIncarnationID.IsZero() && v.BindingSerial == 0 && v.Provider == 0 && v.WrapProfile == 0 && v.ProtectionClass == 0 &&
		v.KeySelector == "" && len(v.SPKI) == 0 && v.Fingerprint.IsZero()
}
func successionSigningEqual(a, b PublicSigningBinding) bool {
	return a.Schema == b.Schema && a.Role == b.Role && a.Provider == b.Provider && a.SigningProfile == b.SigningProfile &&
		a.BindingID == b.BindingID && a.KeySelector == b.KeySelector && bytes.Equal(a.SPKI, b.SPKI) && a.Fingerprint == b.Fingerprint && a.Binding == b.Binding
}
func successionKMSEqual(a, b KMSBinding) bool {
	return a.BindingID == b.BindingID && a.BindingIncarnationID == b.BindingIncarnationID && a.BindingSerial == b.BindingSerial && a.Provider == b.Provider &&
		a.WrapProfile == b.WrapProfile && a.ProtectionClass == b.ProtectionClass && a.KeySelector == b.KeySelector &&
		bytes.Equal(a.SPKI, b.SPKI) && a.Fingerprint == b.Fingerprint
}

func SuccessionReplacementPlanCoreLength(v SuccessionReplacementPlanCore) (int, error) {
	if len(v.Rows) > 2 {
		return 0, ErrRecordCapacity
	}
	roles, count, err := successionRoles(v.OperationKind, v.ChangeMask)
	if err != nil || v.Schema != CanonicalSchema || v.DomainID.IsZero() || len(v.Rows) != count {
		return 0, ErrRecord
	}
	n := successionReplacementFixedLength
	for i, row := range v.Rows {
		if row.TargetRole != roles[i] {
			return 0, ErrRecord
		}
		var before, after int
		if row.TargetRole == SuccessorNormalSigner || row.TargetRole == SuccessorRecoverySigner {
			role := NormalSigningRole
			if row.TargetRole == SuccessorRecoverySigner {
				role = RecoverySigningRole
			}
			if !successionKMSEmpty(row.BeforeKMS) || !successionKMSEmpty(row.AfterKMS) || row.BeforeSigning.Role != role || row.AfterSigning.Role != role ||
				row.BeforeSigning.Binding.Domain != v.DomainID || row.AfterSigning.Binding.Domain != v.DomainID ||
				row.BeforeSigning.Provider != row.AfterSigning.Provider {
				return 0, ErrRecord
			}
			before, err = PublicSigningBindingLength(row.BeforeSigning)
			if err != nil {
				return 0, err
			}
			after, err = PublicSigningBindingLength(row.AfterSigning)
		} else {
			if !successionSigningEmpty(row.BeforeSigning) || !successionSigningEmpty(row.AfterSigning) || row.BeforeKMS.Provider != row.AfterKMS.Provider {
				return 0, ErrRecord
			}
			before, err = KMSBindingLength(row.BeforeKMS)
			if err != nil {
				return 0, err
			}
			after, err = KMSBindingLength(row.AfterKMS)
		}
		if err != nil {
			return 0, err
		}
		n += 9 + before + after
	}
	return n, nil
}

func writeSuccessionReplacementPlanCore(w *cryptoWriter, v SuccessionReplacementPlanCore) {
	w.raw([]byte(successionReplacementPrefix))
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.u8(v.OperationKind)
	w.u8(v.ChangeMask)
	w.u16(uint16(len(v.Rows)))
	for _, row := range v.Rows {
		w.u8(row.TargetRole)
		if row.TargetRole == SuccessorNormalSigner || row.TargetRole == SuccessorRecoverySigner {
			writePublicSigningBindingBlob(w, row.BeforeSigning)
			writePublicSigningBindingBlob(w, row.AfterSigning)
		} else {
			writeKMSBindingBlob(w, row.BeforeKMS)
			writeKMSBindingBlob(w, row.AfterKMS)
		}
	}
}

func EncodeSuccessionReplacementPlanCore(v SuccessionReplacementPlanCore) ([]byte, error) {
	n, err := SuccessionReplacementPlanCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSuccessionReplacementPlanCore(&w, v)
	return w.b, nil
}
func SuccessionReplacementPlanDescriptor(v SuccessionReplacementPlanCore) (DescriptorVector, error) {
	if _, err := SuccessionReplacementPlanCoreLength(v); err != nil {
		return DescriptorVector{}, err
	}
	w := cryptoHashWriter("")
	writeSuccessionReplacementPlanCore(&w, v)
	return w.result(len(v.Rows)), nil
}
