package contract

import "bytes"

const (
	successorEvidenceMaxRows         = 2
	SuccessorEvidenceVectorMaxLength = 1 + successorEvidenceMaxRows*(2+32+32+2+MaxSignature)
	successorEvidencePrefix          = cryptoPurposePrefix + "successor-evidence-v1\x00"
	successorEvidencePlanPrefix      = cryptoPurposePrefix + "successor-evidence-plan-v1\x00"
)

type SuccessorSignerFields struct {
	ProbeAttemptID, SigningBindingDigest ID
}

type SuccessorTrustEvidence struct {
	SuccessorSignerFields
	Signature []byte
}

// SuccessorEvidenceRow carries structural public evidence. Its relation to the
// exact requested successor and the admitted operation remains with the caller.
type SuccessorEvidenceRow struct {
	TargetRole, EvidenceKind uint8
	Trust                    SuccessorTrustEvidence
	KEK                      QualifiedSuccessorRow
}

// SuccessorEvidencePlanRow excludes the randomized Trust signature from request
// identity. Qualified KEK fields remain complete.
type SuccessorEvidencePlanRow struct {
	TargetRole, EvidenceKind uint8
	Trust                    SuccessorSignerFields
	KEK                      QualifiedSuccessorRow
}

func (v SuccessorEvidenceRow) plan() SuccessorEvidencePlanRow {
	return SuccessorEvidencePlanRow{TargetRole: v.TargetRole, EvidenceKind: v.EvidenceKind, Trust: v.Trust.SuccessorSignerFields, KEK: v.KEK}
}

func successorEvidenceTagsValid(role, kind uint8) bool {
	switch role {
	case SuccessorNormalSigner, SuccessorRecoverySigner:
		return kind == SuccessorSignerEvidence
	case SuccessorAuthorityKEK, SuccessorRecoveryKEK:
		return kind == SuccessorKEKEvidence
	default:
		return false
	}
}

func successorEvidenceRowLength(v SuccessorEvidencePlanRow, signature []byte, actual bool) (int, error) {
	if !successorEvidenceTagsValid(v.TargetRole, v.EvidenceKind) {
		return 0, ErrRecord
	}
	switch v.EvidenceKind {
	case SuccessorSignerEvidence:
		if !publicIDsValid(v.Trust.ProbeAttemptID, v.Trust.SigningBindingDigest) || v.KEK != (QualifiedSuccessorRow{}) {
			return 0, ErrRecord
		}
		if !actual {
			return 2 + 32 + 32, nil
		}
		if len(signature) > MaxSignature {
			return 0, ErrRecordCapacity
		}
		if !P256SignatureEncodingValid(signature) {
			return 0, ErrRecord
		}
		return 2 + 32 + 32 + 2 + len(signature), nil
	case SuccessorKEKEvidence:
		subjectKind := OrdinaryWrapSubject
		if v.TargetRole == SuccessorRecoveryKEK {
			subjectKind = RecoveryWrapSubject
		}
		if v.Trust != (SuccessorSignerFields{}) || signature != nil || v.KEK.SubjectKind != subjectKind || v.KEK.PublicBindingDigest.IsZero() {
			return 0, ErrRecord
		}
		n, err := QualifiedSuccessorRowLength(v.KEK)
		if err != nil {
			return 0, err
		}
		return 2 + n, nil
	default:
		return 0, ErrRecord
	}
}

func SuccessorEvidenceVectorLength(rows []SuccessorEvidenceRow) (int, error) {
	if len(rows) > successorEvidenceMaxRows {
		return 0, ErrRecordCapacity
	}
	n := 1
	var previous uint8
	for _, row := range rows {
		if row.TargetRole <= previous {
			return 0, ErrRecord
		}
		length, err := successorEvidenceRowLength(row.plan(), row.Trust.Signature, true)
		if err != nil {
			return 0, err
		}
		n += length
		previous = row.TargetRole
	}
	return n, nil
}

func SuccessorEvidencePlanCoreLength(rows []SuccessorEvidencePlanRow) (int, error) {
	if len(rows) > successorEvidenceMaxRows {
		return 0, ErrRecordCapacity
	}
	n := len(successorEvidencePlanPrefix) + 1
	var previous uint8
	for _, row := range rows {
		if row.TargetRole <= previous {
			return 0, ErrRecord
		}
		length, err := successorEvidenceRowLength(row, nil, false)
		if err != nil {
			return 0, err
		}
		n += length
		previous = row.TargetRole
	}
	return n, nil
}

func writeSuccessorEvidenceRow(w *cryptoWriter, row SuccessorEvidencePlanRow, signature []byte, actual bool) {
	w.u8(row.TargetRole)
	w.u8(row.EvidenceKind)
	if row.EvidenceKind == SuccessorSignerEvidence {
		w.id(row.Trust.ProbeAttemptID)
		w.id(row.Trust.SigningBindingDigest)
		if actual {
			w.u16(uint16(len(signature)))
			w.raw(signature)
		}
	} else {
		writeQualifiedSuccessorRow(w, row.KEK)
	}
}

func writeSuccessorEvidenceVector(w *cryptoWriter, rows []SuccessorEvidenceRow) {
	w.u8(uint8(len(rows)))
	for _, row := range rows {
		writeSuccessorEvidenceRow(w, row.plan(), row.Trust.Signature, true)
	}
}

func writeSuccessorEvidenceCore(w *cryptoWriter, rows []SuccessorEvidenceRow, vectorLength int) {
	w.raw([]byte(successorEvidencePrefix))
	w.u32(uint32(vectorLength))
	writeSuccessorEvidenceVector(w, rows)
}

func writeSuccessorEvidencePlanCore(w *cryptoWriter, rows []SuccessorEvidencePlanRow) {
	w.raw([]byte(successorEvidencePlanPrefix))
	w.u8(uint8(len(rows)))
	for _, row := range rows {
		writeSuccessorEvidenceRow(w, row, nil, false)
	}
}

func EncodeSuccessorEvidenceVector(rows []SuccessorEvidenceRow) ([]byte, error) {
	n, err := SuccessorEvidenceVectorLength(rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSuccessorEvidenceVector(&w, rows)
	return w.b, nil
}

func EncodeSuccessorEvidencePlanCore(rows []SuccessorEvidencePlanRow) ([]byte, error) {
	n, err := SuccessorEvidencePlanCoreLength(rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeSuccessorEvidencePlanCore(&w, rows)
	return w.b, nil
}

func SuccessorEvidenceDigest(rows []SuccessorEvidenceRow) (ID, error) {
	n, err := SuccessorEvidenceVectorLength(rows)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeSuccessorEvidenceCore(&w, rows, n)
	return w.result(0).Digest, nil
}

func EvidencePlanDigest(rows []SuccessorEvidencePlanRow) (ID, error) {
	if _, err := SuccessorEvidencePlanCoreLength(rows); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeSuccessorEvidencePlanCore(&w, rows)
	return w.result(0).Digest, nil
}

// PlanSuccessorEvidence validates the complete actual evidence before removing
// only the signature length and bytes from each Trust row.
func PlanSuccessorEvidence(rows []SuccessorEvidenceRow) ([]SuccessorEvidencePlanRow, error) {
	if _, err := SuccessorEvidenceVectorLength(rows); err != nil {
		return nil, err
	}
	plan := make([]SuccessorEvidencePlanRow, len(rows))
	for i, row := range rows {
		plan[i] = row.plan()
	}
	return plan, nil
}

// DecodeSuccessorEvidenceVector returns owned signatures from the stored HEAD.
func DecodeSuccessorEvidenceVector(b []byte) ([]SuccessorEvidenceRow, error) {
	if len(b) > SuccessorEvidenceVectorMaxLength {
		return nil, ErrRecordCapacity
	}
	r := newRecordReader(b)
	count := r.u8()
	if count > successorEvidenceMaxRows {
		return nil, ErrRecordCapacity
	}
	rows := make([]SuccessorEvidenceRow, 0, count)
	for i := uint8(0); i < count && r.err == nil; i++ {
		row := SuccessorEvidenceRow{TargetRole: r.u8(), EvidenceKind: r.u8()}
		if !successorEvidenceTagsValid(row.TargetRole, row.EvidenceKind) {
			return nil, ErrRecord
		}
		if row.EvidenceKind == SuccessorSignerEvidence {
			row.Trust.SuccessorSignerFields = SuccessorSignerFields{ProbeAttemptID: r.requiredID(), SigningBindingDigest: r.requiredID()}
			n := r.u16()
			if n > MaxSignature {
				return nil, ErrRecordCapacity
			}
			row.Trust.Signature = bytes.Clone(r.take(int(n)))
		} else {
			row.KEK = readQualifiedSuccessorRow(&r)
		}
		rows = append(rows, row)
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	if _, err := SuccessorEvidenceVectorLength(rows); err != nil {
		return nil, err
	}
	return rows, nil
}
