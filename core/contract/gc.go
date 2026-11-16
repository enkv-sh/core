package contract

import (
	"bytes"
	"encoding/binary"
	"slices"
	"unicode/utf8"
)

const (
	GCPlanSchema          uint16 = 1
	GCTargetLimit                = 256
	GCTransmissionLimit          = 3
	GCProviderCursorLimit        = 4096
	GCPlanMaxLength              = 105413
	GCProgressMaxLength          = 8854
	GCSubjectMaxLength           = 762
	gcPlanPrefix                 = "ENKV/GC-PLAN/v1\x00"
	gcTargetsPrefix              = "ENKV/GC-TARGETS/v1\x00"
	gcOwnersPrefix               = "ENKV/GC-OWNERS/v1\x00"
	gcSubjectPrefix              = "ENKV/K2-GC/v1\x00"
)

type GCDescriptor struct {
	Digest ID
	Length uint64
	Count  uint32
}

func appendGCDescriptor(b []byte, d GCDescriptor) []byte {
	b = append(b, d.Digest[:]...)
	b = binary.BigEndian.AppendUint64(b, d.Length)
	return binary.BigEndian.AppendUint32(b, d.Count)
}
func readGCDescriptor(r *cryptoReader) GCDescriptor {
	return GCDescriptor{Digest: r.id(), Length: r.u64(), Count: r.u32()}
}
func AppendGCDescriptor(b []byte, d GCDescriptor) ([]byte, error) {
	if d.Digest.IsZero() {
		return nil, ErrRecord
	}
	return appendGCDescriptor(b, d), nil
}
func DecodeGCDescriptor(b []byte) (GCDescriptor, error) {
	if len(b) != 44 {
		return GCDescriptor{}, ErrRecord
	}
	r := newRecordReader(b)
	v := readGCDescriptor(&r)
	if r.end() != nil || v.Digest.IsZero() {
		return GCDescriptor{}, ErrRecord
	}
	return v, nil
}
func EmptyGCOwnersDescriptor() GCDescriptor {
	b := append([]byte(gcOwnersPrefix), 0, 0, 0, 0)
	return GCDescriptor{Hash(b), uint64(len(b)), 0}
}
func (d GCDescriptor) ValidOwners() bool {
	if d.Count == 0 {
		return d == EmptyGCOwnersDescriptor()
	}
	return !d.Digest.IsZero() && d.Count <= 65535 && d.Length >= 22+uint64(d.Count)*(4+32+184) && d.Length <= uint64(MaxChildPages)*MaxRequiredSupportPageLength
}
func (d GCDescriptor) ValidTargets() bool {
	if d.Count == 0 {
		return d == GCTargetsEmptyDescriptor()
	}
	return !d.Digest.IsZero() && d.Count <= GCTargetLimit && d.Length >= 21+uint64(d.Count)*78 && d.Length <= 21+uint64(d.Count)*333
}
func GCTargetsEmptyDescriptor() GCDescriptor {
	b := append([]byte(gcTargetsPrefix), 0, 0)
	return GCDescriptor{Hash(b), uint64(len(b)), 0}
}

type GCTarget struct {
	Object StoreObjectIdentity
	Length uint32
	Digest ID
	Token  Token
}

func (v GCTarget) Valid() bool {
	return StoreObjectLimit(v.Object) != 0 && v.Length > 0 && v.Length <= StoreObjectLimit(v.Object) && !v.Digest.IsZero() && v.Token.Valid()
}
func appendGCTarget(w *cryptoWriter, v GCTarget) {
	w.u8(uint8(v.Object.Namespace))
	w.u8(uint8(v.Object.Kind))
	w.u16(v.Object.Index)
	w.id(v.Object.ObjectID)
	w.u32(v.Length)
	w.id(v.Digest)
	writeToken(w, v.Token)
}
func readGCTarget(r *cryptoReader) GCTarget {
	v := GCTarget{Object: StoreObjectIdentity{Namespace: StoreObjectNamespace(r.u8()), Kind: Kind(r.u8()), Index: r.u16(), ObjectID: r.id()}, Length: r.u32(), Digest: r.id()}
	t := readToken(r)
	if r.err == nil {
		v.Token = Token{Family: t.Family, Value: string(t.Value)}
	}
	if !v.Valid() {
		r.err = ErrRecord
	}
	return v
}
func EncodeGCTarget(v GCTarget) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{}
	appendGCTarget(&w, v)
	return w.b, nil
}
func gcTargetsValid(rows []GCTarget) bool {
	if len(rows) > GCTargetLimit {
		return false
	}
	var previous string
	for i, v := range rows {
		key, e := StoreObjectKey("p", ID{1}, v.Object)
		if e != nil || !v.Valid() || i > 0 && previous >= key {
			return false
		}
		previous = key
	}
	return true
}
func GCTargetsDescriptor(rows []GCTarget) (GCDescriptor, error) {
	if !gcTargetsValid(rows) {
		return GCDescriptor{}, ErrRecord
	}
	w := cryptoWriter{b: []byte(gcTargetsPrefix)}
	w.u16(uint16(len(rows)))
	for _, v := range rows {
		appendGCTarget(&w, v)
	}
	return GCDescriptor{Hash(w.b), uint64(len(w.b)), uint32(len(rows))}, nil
}

type GCCandidateClass uint8

const (
	GCCandidateProtected GCCandidateClass = iota + 1
	GCCandidateEligible
	GCCandidateAlreadyPending
	GCCandidateAbsent
	GCCandidateChanged
	GCCandidateUnverifiable
)

type GCCandidateReason uint8

const (
	GCReasonNone GCCandidateReason = iota
	GCReasonForeign
	GCReasonUnknownKind
	GCReasonMalformed
	GCReasonCondition
	GCReasonUnavailable
)

type GCCandidate struct {
	KeyDigest      ID
	Classification GCCandidateClass
	TargetIndex    uint16
	Reason         GCCandidateReason
	ListedLength   uint64
}
type GCPlan struct {
	DomainID, OperationID, RequestNonce                        ID
	StoreDescriptorDigest, PublicBasisDigest, SourcePinsDigest ID
	HeadRevisionID, FullHEADDigest, SnapshotID, RootDigest     ID
	MarkDigest, EnumerationDigest, TargetsDigest               ID
	PredecessorToken                                           Token
	InputProviderCursor, NextProviderCursor                    string
	Targets                                                    []GCTarget
	Candidates                                                 []GCCandidate
}

func (v GCPlan) Valid() bool {
	if !publicIDsValid(v.DomainID, v.OperationID, v.RequestNonce, v.StoreDescriptorDigest, v.PublicBasisDigest, v.SourcePinsDigest, v.HeadRevisionID, v.FullHEADDigest, v.SnapshotID, v.RootDigest, v.MarkDigest, v.EnumerationDigest, v.TargetsDigest) || !v.PredecessorToken.Valid() || len(v.InputProviderCursor) > GCProviderCursorLimit || len(v.NextProviderCursor) > GCProviderCursorLimit || !utf8.ValidString(v.InputProviderCursor) || !utf8.ValidString(v.NextProviderCursor) || len(v.Candidates) > GCTargetLimit {
		return false
	}
	d, e := GCTargetsDescriptor(v.Targets)
	if e != nil || d.Digest != v.TargetsDigest {
		return false
	}
	var seen [GCTargetLimit]bool
	for _, c := range v.Candidates {
		if c.Classification < GCCandidateProtected || c.Classification > GCCandidateUnverifiable || c.Reason > GCReasonUnavailable {
			return false
		}
		if c.Classification == GCCandidateEligible {
			if int(c.TargetIndex) >= len(v.Targets) || seen[c.TargetIndex] || c.KeyDigest.IsZero() || c.Reason != GCReasonNone {
				return false
			}
			seen[c.TargetIndex] = true
		} else if c.TargetIndex != 65535 {
			return false
		}
		if c.Classification != GCCandidateUnverifiable && c.KeyDigest.IsZero() {
			return false
		}
	}
	for i := range v.Targets {
		if !seen[i] || v.Targets[i].Token.Family != v.PredecessorToken.Family {
			return false
		}
	}
	return true
}
func EncodeGCPlan(v GCPlan) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: []byte(gcPlanPrefix)}
	w.u16(GCPlanSchema)
	w.u16(CanonicalSchema)
	for _, id := range []ID{v.DomainID, v.OperationID, v.RequestNonce, v.StoreDescriptorDigest, v.PublicBasisDigest, v.SourcePinsDigest, v.HeadRevisionID, v.FullHEADDigest, v.SnapshotID, v.RootDigest, v.MarkDigest, v.EnumerationDigest, v.TargetsDigest} {
		w.id(id)
	}
	writeToken(&w, v.PredecessorToken)
	w.u16(uint16(len(v.Targets)))
	w.u16(uint16(len(v.Candidates)))
	w.blob([]byte(v.InputProviderCursor))
	w.blob([]byte(v.NextProviderCursor))
	for _, r := range v.Targets {
		appendGCTarget(&w, r)
	}
	for _, r := range v.Candidates {
		w.id(r.KeyDigest)
		w.u8(uint8(r.Classification))
		w.u16(r.TargetIndex)
		w.u8(uint8(r.Reason))
		w.u64(r.ListedLength)
	}
	if len(w.b) > GCPlanMaxLength {
		return nil, ErrRecordCapacity
	}
	return w.b, nil
}
func DecodeGCPlan(b []byte) (GCPlan, error) {
	if len(b) > GCPlanMaxLength {
		return GCPlan{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(gcPlanPrefix)), []byte(gcPlanPrefix)) || r.u16() != GCPlanSchema || r.u16() != CanonicalSchema {
		return GCPlan{}, ErrRecord
	}
	v := GCPlan{DomainID: r.id(), OperationID: r.id(), RequestNonce: r.id(), StoreDescriptorDigest: r.id(), PublicBasisDigest: r.id(), SourcePinsDigest: r.id(), HeadRevisionID: r.id(), FullHEADDigest: r.id(), SnapshotID: r.id(), RootDigest: r.id(), MarkDigest: r.id(), EnumerationDigest: r.id(), TargetsDigest: r.id()}
	t := readToken(&r)
	v.PredecessorToken = Token{Family: t.Family, Value: string(t.Value)}
	n, c := int(r.u16()), int(r.u16())
	v.InputProviderCursor = string(r.blob(GCProviderCursorLimit))
	v.NextProviderCursor = string(r.blob(GCProviderCursorLimit))
	if r.err != nil || n > GCTargetLimit || c > GCTargetLimit || n > (len(b)-r.i)/78 {
		return GCPlan{}, ErrRecord
	}
	v.Targets = make([]GCTarget, n)
	for i := range v.Targets {
		v.Targets[i] = readGCTarget(&r)
	}
	if r.err != nil || c > (len(b)-r.i)/44 {
		return GCPlan{}, ErrRecord
	}
	v.Candidates = make([]GCCandidate, c)
	for i := range v.Candidates {
		v.Candidates[i] = GCCandidate{KeyDigest: r.id(), Classification: GCCandidateClass(r.u8()), TargetIndex: r.u16(), Reason: GCCandidateReason(r.u8()), ListedLength: r.u64()}
	}
	if r.end() != nil || !v.Valid() {
		return GCPlan{}, ErrRecord
	}
	return v, nil
}
func GCPlanDigest(v GCPlan) (ID, error) {
	b, e := EncodeGCPlan(v)
	if e != nil {
		return ID{}, e
	}
	return Hash(b), nil
}
func GCPlanRequestIdentity(v GCPlan) (ID, error) {
	digest, err := GCPlanDigest(v)
	if err != nil {
		return ID{}, err
	}
	return Hash(append([]byte("ENKV/GC-REQUEST/v1\x00"), digest[:]...)), nil
}
func GCPlanEncodedLength(v GCPlan) (uint32, error) { b, e := EncodeGCPlan(v); return uint32(len(b)), e }

type GCTargetDisposition uint8

const (
	GCTargetPending GCTargetDisposition = iota + 1
	GCTargetUnknown
	GCTargetAbsent
	GCTargetChanged
	GCTargetTerminalFailure
	GCTargetRetryableNotSent
)

type GCTargetProgress struct {
	Consumed       uint8
	Disposition    GCTargetDisposition
	EvidenceDigest ID
}
type GCProgress struct {
	PlanDigest                         ID
	TargetsDescriptor                  GCDescriptor
	RequestIdentity, ObservationDigest ID
	RemainingCount                     uint16
	Ordinal                            uint32
	Targets                            []GCTargetProgress
}

func (v GCProgress) Valid() bool {
	if !publicIDsValid(v.PlanDigest, v.RequestIdentity, v.ObservationDigest) || !v.TargetsDescriptor.ValidTargets() || len(v.Targets) == 0 || len(v.Targets) > GCTargetLimit || uint32(len(v.Targets)) != v.TargetsDescriptor.Count || v.Ordinal == 0 {
		return false
	}
	remaining := 0
	for _, r := range v.Targets {
		if r.Consumed > GCTransmissionLimit || r.Disposition < GCTargetPending || r.Disposition > GCTargetRetryableNotSent || (r.Disposition == GCTargetAbsent || r.Disposition == GCTargetRetryableNotSent) == r.EvidenceDigest.IsZero() || r.Disposition == GCTargetRetryableNotSent && (r.Consumed == 0 || r.Consumed >= GCTransmissionLimit) {
			return false
		}
		if r.Disposition != GCTargetAbsent {
			remaining++
		}
	}
	return int(v.RemainingCount) == remaining
}
func (v GCProgress) Own() GCProgress { v.Targets = slices.Clone(v.Targets); return v }
func EncodeGCProgress(v GCProgress) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{}
	w.u16(GCPlanSchema)
	w.id(v.PlanDigest)
	w.raw(appendGCDescriptor(nil, v.TargetsDescriptor))
	w.id(v.RequestIdentity)
	w.id(v.ObservationDigest)
	w.u16(uint16(len(v.Targets)))
	w.u16(v.RemainingCount)
	w.u32(v.Ordinal)
	for _, r := range v.Targets {
		w.u8(r.Consumed)
		w.u8(uint8(r.Disposition))
		w.id(r.EvidenceDigest)
	}
	return w.b, nil
}
func DecodeGCProgress(b []byte) (GCProgress, error) {
	v, n, e := ParseGCProgress(b)
	if e != nil || n != len(b) {
		return GCProgress{}, ErrRecord
	}
	return v, nil
}
func ParseGCProgress(b []byte) (GCProgress, int, error) {
	if len(b) < 150 {
		return GCProgress{}, 0, ErrRecord
	}
	r := newRecordReader(b)
	if r.u16() != GCPlanSchema {
		return GCProgress{}, 0, ErrRecord
	}
	v := GCProgress{PlanDigest: r.id(), TargetsDescriptor: readGCDescriptor(&r), RequestIdentity: r.id(), ObservationDigest: r.id()}
	n := int(r.u16())
	v.RemainingCount = r.u16()
	v.Ordinal = r.u32()
	if r.err != nil || n == 0 || n > GCTargetLimit || n > (len(b)-r.i)/34 {
		return GCProgress{}, 0, ErrRecord
	}
	v.Targets = make([]GCTargetProgress, n)
	for i := range v.Targets {
		v.Targets[i] = GCTargetProgress{Consumed: r.u8(), Disposition: GCTargetDisposition(r.u8()), EvidenceDigest: r.id()}
	}
	if r.err != nil || !v.Valid() {
		return GCProgress{}, 0, ErrRecord
	}
	return v, r.i, nil
}
func GCProgressDigest(v GCProgress) (ID, error) {
	b, e := EncodeGCProgress(v)
	if e != nil {
		return ID{}, e
	}
	return Hash(b), nil
}
func GCProgressEqual(a, b GCProgress) bool {
	return a.PlanDigest == b.PlanDigest && a.TargetsDescriptor == b.TargetsDescriptor && a.RequestIdentity == b.RequestIdentity && a.ObservationDigest == b.ObservationDigest && a.RemainingCount == b.RemainingCount && a.Ordinal == b.Ordinal && slices.Equal(a.Targets, b.Targets)
}

type GCOwner struct {
	OperationID ID
	Progress    GCProgress
}

func GCOwnersDescriptor(rows []GCOwner) (GCDescriptor, error) {
	if len(rows) > 65535 {
		return GCDescriptor{}, ErrRecordCapacity
	}
	w := cryptoWriter{b: []byte(gcOwnersPrefix)}
	w.u32(uint32(len(rows)))
	for i, v := range rows {
		if v.OperationID.IsZero() || i > 0 && bytes.Compare(rows[i-1].OperationID[:], v.OperationID[:]) >= 0 {
			return GCDescriptor{}, ErrRecord
		}
		b, e := EncodeGCProgress(v.Progress)
		if e != nil {
			return GCDescriptor{}, e
		}
		w.u32(uint32(32 + len(b)))
		w.id(v.OperationID)
		w.raw(b)
	}
	d := GCDescriptor{Hash(w.b), uint64(len(w.b)), uint32(len(rows))}
	if !d.ValidOwners() {
		return GCDescriptor{}, ErrRecordCapacity
	}
	return d, nil
}

type GCPhase uint8

const (
	GCSelect GCPhase = iota + 1
	GCReacquire
	GCReserve
	GCRecordProgress
	GCClose
)

type GCSubject struct {
	DomainID, OperationID, AdmissionID, RequestIdentity   ID
	Phase                                                 GCPhase
	PredecessorRevisionID, PredecessorFullHEADDigest      ID
	PredecessorToken                                      Token
	BeforeOwners, AfterOwners                             GCDescriptor
	PlanDigest, BeforeProgressDigest, AfterProgressDigest ID
	PreservedCurrentDigest                                ID
	PreservedCurrentLength                                uint64
	HeadCoreDigest                                        ID
	HeadCoreLength                                        uint32
	ConditionalPlanDigest                                 ID
}

func (v GCSubject) Valid() bool {
	if !publicIDsValid(v.DomainID, v.OperationID, v.AdmissionID, v.RequestIdentity, v.PredecessorRevisionID, v.PredecessorFullHEADDigest, v.PlanDigest, v.PreservedCurrentDigest, v.HeadCoreDigest, v.ConditionalPlanDigest) || v.Phase < GCSelect || v.Phase > GCClose || !v.PredecessorToken.Valid() || !v.BeforeOwners.ValidOwners() || !v.AfterOwners.ValidOwners() || v.PreservedCurrentLength == 0 || v.HeadCoreLength < SuccessorHeadCoreMinLength || v.HeadCoreLength > SuccessorHeadCoreMaxLength {
		return false
	}
	if (v.Phase == GCSelect) != v.BeforeProgressDigest.IsZero() || v.Phase != GCClose && v.AfterProgressDigest.IsZero() {
		return false
	}
	if v.Phase != GCSelect && v.BeforeOwners.Count == 0 {
		return false
	}
	switch v.Phase {
	case GCSelect:
		return v.AfterOwners.Count == v.BeforeOwners.Count+1
	case GCReacquire:
		return v.BeforeOwners.Count == v.AfterOwners.Count && v.BeforeProgressDigest == v.AfterProgressDigest
	case GCReserve, GCRecordProgress:
		return v.BeforeOwners.Count == v.AfterOwners.Count && v.BeforeProgressDigest != v.AfterProgressDigest
	case GCClose:
		if v.AfterProgressDigest.IsZero() {
			return v.BeforeOwners.Count == v.AfterOwners.Count+1
		}
		return v.BeforeOwners.Count == v.AfterOwners.Count && v.BeforeProgressDigest == v.AfterProgressDigest
	}
	return false
}
func EncodeGCSubject(v GCSubject) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: []byte(gcSubjectPrefix)}
	w.u16(CanonicalSchema)
	for _, id := range []ID{v.DomainID, v.OperationID, v.AdmissionID, v.RequestIdentity} {
		w.id(id)
	}
	w.u8(uint8(v.Phase))
	w.id(v.PredecessorRevisionID)
	w.id(v.PredecessorFullHEADDigest)
	writeToken(&w, v.PredecessorToken)
	w.raw(appendGCDescriptor(nil, v.BeforeOwners))
	w.raw(appendGCDescriptor(nil, v.AfterOwners))
	for _, id := range []ID{v.PlanDigest, v.BeforeProgressDigest, v.AfterProgressDigest, v.PreservedCurrentDigest} {
		w.id(id)
	}
	w.u64(v.PreservedCurrentLength)
	w.id(v.HeadCoreDigest)
	w.u32(v.HeadCoreLength)
	w.id(v.ConditionalPlanDigest)
	return w.b, nil
}
func DecodeGCSubject(b []byte) (GCSubject, error) {
	if len(b) > GCSubjectMaxLength {
		return GCSubject{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(gcSubjectPrefix)), []byte(gcSubjectPrefix)) || r.u16() != CanonicalSchema {
		return GCSubject{}, ErrRecord
	}
	v := GCSubject{DomainID: r.id(), OperationID: r.id(), AdmissionID: r.id(), RequestIdentity: r.id(), Phase: GCPhase(r.u8()), PredecessorRevisionID: r.id(), PredecessorFullHEADDigest: r.id()}
	t := readToken(&r)
	v.PredecessorToken = Token{Family: t.Family, Value: string(t.Value)}
	v.BeforeOwners = readGCDescriptor(&r)
	v.AfterOwners = readGCDescriptor(&r)
	v.PlanDigest = r.id()
	v.BeforeProgressDigest = r.id()
	v.AfterProgressDigest = r.id()
	v.PreservedCurrentDigest = r.id()
	v.PreservedCurrentLength = r.u64()
	v.HeadCoreDigest = r.id()
	v.HeadCoreLength = r.u32()
	v.ConditionalPlanDigest = r.id()
	if r.end() != nil || !v.Valid() {
		return GCSubject{}, ErrRecord
	}
	return v, nil
}
func NewGCRequest(v GCSubject) (SignRequest, error) {
	b, e := EncodeGCSubject(v)
	if e != nil {
		return SignRequest{}, e
	}
	return SignRequest{purpose: GCPurpose, digest: Hash(b)}, nil
}

func GCPlanObservationDigest(v GCPlan) (ID, error) {
	if !v.Valid() {
		return ID{}, ErrRecord
	}
	b := []byte("ENKV/GC-OBSERVATION/v1\x00")
	for _, id := range []ID{v.DomainID, v.HeadRevisionID, v.FullHEADDigest, v.SnapshotID, v.RootDigest, v.MarkDigest, v.EnumerationDigest} {
		b = append(b, id[:]...)
	}
	return Hash(b), nil
}

func (v GCProgress) EvidenceSummary() uint16 {
	var bits uint16
	for _, row := range v.Targets {
		switch row.Disposition {
		case GCTargetAbsent:
			bits |= AdministrativeEvidenceConfirmed
		case GCTargetUnknown:
			bits |= AdministrativeEvidenceQualifiedUnknown
		case GCTargetChanged:
			bits |= AdministrativeEvidenceContradiction
		case GCTargetTerminalFailure:
			bits |= AdministrativeEvidenceTerminalFailure
		default:
			bits |= AdministrativeEvidenceMissing
		}
	}
	return bits
}
func (v GCProgress) EffectEntryCeiling() uint8 {
	for _, row := range v.Targets {
		if row.Consumed != 0 {
			return 1
		}
	}
	return 0
}
