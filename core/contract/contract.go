// Package contract defines bounded records and the proof, provider and custody
// interfaces shared by their owners. Inspection views borrow unchanged input
// for their documented scope; Own revalidates and copies retained fields.
// These boundaries assign neither state meaning nor Product outcomes.
package contract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
)

const MaxStorePrefixLength = 512

type ID [32]byte

func Hash(b []byte) ID     { return sha256.Sum256(b) }
func (id ID) IsZero() bool { return id == ID{} }

type Family uint8

const (
	AWS Family = 1
	GCP Family = 2
)

func (f Family) Valid() bool { return f == AWS || f == GCP }

// Descriptor binds an independently admitted, exact provider construction.
// NonBody binds all required request fields other than the condition and body.
type Descriptor struct {
	Family                        Family
	Identity, Coordinate, NonBody ID
	Prefix, HeadKey               string
}

func (d Descriptor) Valid() bool {
	return d.Family.Valid() && !d.Identity.IsZero() && !d.Coordinate.IsZero() && !d.NonBody.IsZero() && len(d.Prefix) > 0 && len(d.Prefix) <= MaxStorePrefixLength && d.HeadKey == d.Prefix+"/HEAD"
}

type ReadStatus uint8

const (
	ReadOK ReadStatus = iota + 1
	ReadMissing
	ReadUnavailable
	ReadInvalid
)

type WriteStatus uint8

const (
	WriteAcknowledged WriteStatus = iota + 1
	WritePrecondition
	WriteConflict
	WriteUnknown
	WriteRefused
)

type Reason uint8

const (
	ReasonNone Reason = iota
	ReasonAccess
	ReasonTransport
	ReasonMalformed
	ReasonCondition
	ReasonConstruction
	ReasonLimit
	ReasonProof
)

type ReadResult struct {
	Status ReadStatus
	Body   []byte
	Token  Token
	Reason Reason
}
type WriteResult struct {
	Status WriteStatus
	Reason Reason
	// NotSent is true only when the adapter proved that the physical request
	// never entered its provider transport.
	NotSent bool
}
type Store interface {
	Descriptor() Descriptor
	Read(context.Context, string, uint32) ReadResult
	Create(context.Context, string, []byte) WriteResult
	CreateHead(context.Context, HeadCreateRequest) WriteResult
	CompareAndSwap(context.Context, string, Token, []byte) WriteResult
}

// StoreConfigurationSource exposes only the durable construction facts used
// at genesis. Local credential routing remains outside this selected record.
type StoreConfigurationSource interface {
	StoreConfiguration() StoreConfiguration
}

// ConditionalDeleteStore supplies exact conditional deletion of admitted immutable
// objects. Its caller owns temporary-release or selected-GC policy and eligibility.
// Implementations apply the provider's conditional predicate
// to the token observed by the caller. A match establishes only that provider's
// representation or version relation, not a unique physical incarnation or
// permanent erasure.
type ConditionalDeleteStore interface {
	DeleteIfToken(context.Context, string, Token) WriteResult
}

type Purpose uint8

const (
	BindingPurpose              Purpose = 1
	LifecyclePurpose            Purpose = 3
	K2SuccessionPurpose         Purpose = 4
	K3SuccessionPurpose         Purpose = 5
	SuccessorSignerProbePurpose Purpose = 7
	K3BasisPurpose              Purpose = 8
	GenesisPurpose              Purpose = 10
	K3InitChallengePurpose      Purpose = 11
	GeneratorPurpose            Purpose = 12
	EndWorkPurpose              Purpose = 13
	SelectionAcceptancePurpose  Purpose = 14
	OutputReservePurpose        Purpose = 15
	OutputClosePurpose          Purpose = 16
	GCPurpose                   Purpose = 17
)
const MaxSignature = 72
const MaxPublicKey = 256

// A successor HeadCore contains 418 fixed bytes and a nonempty token value.
const (
	SuccessorHeadCoreMinLength = 418 + 1
	SuccessorHeadCoreMaxLength = 418 + maxTokenValue
)

// SignRequest has no arbitrary-message or arbitrary-digest constructor.
// Typed constructors fix the subject schema and its signing purpose.
type SignRequest struct {
	purpose Purpose
	digest  ID
}

func (s SignRequest) Purpose() Purpose { return s.purpose }
func (s SignRequest) Digest() ID       { return s.digest }
func (s SignRequest) Valid() bool {
	switch s.purpose {
	case BindingPurpose, LifecyclePurpose, K2SuccessionPurpose, K3SuccessionPurpose, SuccessorSignerProbePurpose, K3BasisPurpose, GenesisPurpose, K3InitChallengePurpose, GeneratorPurpose, EndWorkPurpose, SelectionAcceptancePurpose, OutputReservePurpose, OutputClosePurpose, GCPurpose:
		return !s.digest.IsZero()
	default:
		return false
	}
}

type SignResult struct {
	Signature []byte
	Reason    Reason
}
type Trust interface {
	Identity() ID
	Family() Family
	Sign(context.Context, SignRequest) SignResult
}

type BindingSubject struct {
	Domain, Coordinate, Store, Trust, PublicKey, Interpretation ID
	ControlIncarnationID                                        ID
	Epoch                                                       uint64
}

var ErrSubject = errors.New("invalid closed authority subject")

const (
	BindingSubjectLength = 251
	bindingSubjectPrefix = "ENKV/K1-BINDING/v2\x00"
)

func bindingSubjectValid(s BindingSubject) bool {
	return publicIDsValid(s.Domain, s.Coordinate, s.Store, s.Trust, s.PublicKey, s.Interpretation, s.ControlIncarnationID) && s.Epoch != 0
}

func writeBindingSubject(w *cryptoWriter, s BindingSubject) {
	w.raw([]byte(bindingSubjectPrefix))
	for _, id := range []ID{s.Domain, s.Coordinate, s.Store, s.Trust, s.PublicKey, s.Interpretation} {
		w.id(id)
	}
	w.id(s.ControlIncarnationID)
	w.u64(s.Epoch)
}

func readBindingSubject(r *cryptoReader) BindingSubject {
	if !bytes.Equal(r.take(len(bindingSubjectPrefix)), []byte(bindingSubjectPrefix)) {
		r.err = ErrSubject
		return BindingSubject{}
	}
	s := BindingSubject{Domain: r.requiredID(), Coordinate: r.requiredID(), Store: r.requiredID(),
		Trust: r.requiredID(), PublicKey: r.requiredID(), Interpretation: r.requiredID(), ControlIncarnationID: r.requiredID(), Epoch: r.u64()}
	if r.err != nil || !bindingSubjectValid(s) {
		r.err = ErrSubject
	}
	return s
}

func BindingBytes(s BindingSubject) ([]byte, error) {
	if !bindingSubjectValid(s) {
		return nil, ErrSubject
	}
	w := cryptoWriter{b: make([]byte, 0, BindingSubjectLength)}
	writeBindingSubject(&w, s)
	return w.b, nil
}

// ParseBindingSubject reads one fixed-size K1 subject from an enclosing record.
// The returned fields are values and retain no input buffer.
func ParseBindingSubject(b []byte) (BindingSubject, int, error) {
	if len(b) < BindingSubjectLength {
		return BindingSubject{}, 0, ErrSubject
	}
	r := cryptoReader{b: b}
	s := readBindingSubject(&r)
	if r.err != nil {
		return BindingSubject{}, 0, ErrSubject
	}
	return s, r.i, nil
}

func InspectBindingSubject(b []byte) (BindingSubject, error) {
	if len(b) != BindingSubjectLength {
		return BindingSubject{}, ErrSubject
	}
	s, _, err := ParseBindingSubject(b)
	return s, err
}

func DecodeBindingSubject(b []byte) (BindingSubject, error) {
	return InspectBindingSubject(b)
}

func NewBindingRequest(s BindingSubject) (SignRequest, error) {
	b, err := BindingBytes(s)
	if err != nil {
		return SignRequest{}, err
	}
	return SignRequest{BindingPurpose, Hash(b)}, nil
}
