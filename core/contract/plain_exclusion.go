package contract

import (
	"bytes"
	"unicode/utf8"
)

const (
	plainExclusionPrefix = cryptoPurposePrefix + "plain-exclusion-v6\x00"
	plainExclusionLimit  = len(plainExclusionPrefix) + 32 + membershipRowFixedLength + CryptoMaxName + 32*CryptoMaxValueEntryRecipients
)

type PlainExclusionPath struct {
	Domain                   ID
	Name                     string
	Slot                     uint16
	Incarnation, EntryDigest ID
	RemovedRecipients        []ID
}

type PlainExclusionPathView struct {
	Domain                   ID
	Name                     []byte
	Slot                     uint16
	Incarnation, EntryDigest ID
	RemovedRecipients        []byte
}

func (v PlainExclusionPath) row() MembershipRow {
	return MembershipRow{Name: v.Name, Slot: v.Slot, Incarnation: v.Incarnation, EntryDigest: v.EntryDigest, Recipients: v.RemovedRecipients}
}

func plainExclusionSize(v PlainExclusionPath) (int, error) {
	if len(v.Name) > CryptoMaxName {
		return 0, ErrRecordCapacity
	}
	if v.Domain.IsZero() || !utf8.ValidString(v.Name) {
		return 0, ErrRecord
	}
	n, err := membershipSideSize(v.row().Side())
	return len(plainExclusionPrefix) + 32 + 4 + len(v.Name) + n, err
}

func writePlainExclusion(w *cryptoWriter, v PlainExclusionPath) {
	w.raw([]byte(plainExclusionPrefix))
	w.id(v.Domain)
	writeMembershipRow(w, v.row())
}

func EncodePlainExclusionPath(v PlainExclusionPath) ([]byte, error) {
	n, err := plainExclusionSize(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writePlainExclusion(&w, v)
	return w.b, nil
}

func AppendPlainExclusionPath(dst []byte, v PlainExclusionPath) ([]byte, error) {
	if _, err := plainExclusionSize(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writePlainExclusion(&w, v)
	return w.b, nil
}

func PlainExclusionDigest(v PlainExclusionPath) (ID, error) {
	if _, err := plainExclusionSize(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writePlainExclusion(&w, v)
	return w.result(1).Digest, nil
}

func ParsePlainExclusionPath(b []byte) (PlainExclusionPathView, int, error) {
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(plainExclusionPrefix)), []byte(plainExclusionPrefix)) {
		return PlainExclusionPathView{}, 0, ErrRecord
	}
	domain := r.requiredID()
	name, side := readMembershipRow(&r)
	if r.err != nil {
		return PlainExclusionPathView{}, 0, r.failure()
	}
	return PlainExclusionPathView{Domain: domain, Name: name, Slot: side.Slot, Incarnation: side.Incarnation, EntryDigest: side.EntryDigest, RemovedRecipients: side.Recipients}, r.i, nil
}

func InspectPlainExclusionPath(b []byte) (PlainExclusionPathView, error) {
	if len(b) > plainExclusionLimit {
		return PlainExclusionPathView{}, ErrRecordCapacity
	}
	v, n, err := ParsePlainExclusionPath(b)
	if err != nil {
		return PlainExclusionPathView{}, err
	}
	if n != len(b) {
		return PlainExclusionPathView{}, ErrRecord
	}
	return v, nil
}

func (v PlainExclusionPathView) Own() (PlainExclusionPath, error) {
	if len(v.Name) > CryptoMaxName {
		return PlainExclusionPath{}, ErrRecordCapacity
	}
	if v.Domain.IsZero() || !utf8.Valid(v.Name) {
		return PlainExclusionPath{}, ErrRecord
	}
	side, err := (MembershipSideView{Slot: v.Slot, Incarnation: v.Incarnation, EntryDigest: v.EntryDigest, Recipients: v.RemovedRecipients}).Own()
	if err != nil {
		return PlainExclusionPath{}, err
	}
	return PlainExclusionPath{Domain: v.Domain, Name: string(v.Name), Slot: side.Slot, Incarnation: side.Incarnation, EntryDigest: side.EntryDigest, RemovedRecipients: side.Recipients}, nil
}

func DecodePlainExclusionPath(b []byte) (PlainExclusionPath, error) {
	v, err := InspectPlainExclusionPath(b)
	if err != nil {
		return PlainExclusionPath{}, err
	}
	return v.Own()
}
