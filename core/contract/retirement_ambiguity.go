package contract

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

// The key has one statement type and one retirement. The reservation commits
// to it in its fresh caller nonce. Only Crypto has the private signing method.
type RetirementReturnProof interface {
	Commitment() ID
	Close()
}

const retirementAmbiguitySchema uint16 = 1
const retirementPublicKeyLength = 65
const RetirementAmbiguityMaxLength = 2 + 5*32 + 4 + retirementPublicKeyLength + 4 + GeneratorSafeFactsEnvelopeLength + 4 + MaxSignature

func RetirementReturnCommitment(public []byte) (ID, error) {
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), public); err != nil {
		return ID{}, ErrRecord
	}
	return generatorDigest("retirement-return-key", public), nil
}

// RetirementAmbiguityRecord contains the original public Unknown facts. A wire
// inspection alone does not authenticate their origin.
type RetirementAmbiguityRecord struct {
	Domain, Operation, Attempt, Inbox, Graph ID
	PublicKey, Facts, Signature              []byte
}

func (v RetirementAmbiguityRecord) statement() ([]byte, error) {
	facts, err := InspectGeneratorSafeFacts(v.Facts)
	if err != nil || len(v.Facts) > GeneratorSafeFactsEnvelopeLength || facts.LifecycleMode != GeneratorLifecycleManaged || facts.Action != GeneratorActionDelete || facts.Disposition != GeneratorDispositionUnknown ||
		!publicIDsValid(v.Domain, v.Operation, v.Attempt, v.Inbox, v.Graph) || len(v.PublicKey) != retirementPublicKeyLength {
		return nil, ErrRecord
	}
	var w cryptoWriter
	w.u16(retirementAmbiguitySchema)
	w.id(v.Domain)
	w.id(v.Operation)
	w.id(v.Attempt)
	w.id(v.Inbox)
	w.id(v.Graph)
	w.blob(v.PublicKey)
	w.blob(v.Facts)
	return w.b, nil
}

func (v RetirementAmbiguityRecord) Digest() (ID, error) {
	body, err := v.statement()
	if err != nil {
		return ID{}, err
	}
	return generatorDigest("retirement-return", body), nil
}

func EncodeRetirementAmbiguity(v RetirementAmbiguityRecord) ([]byte, error) {
	body, err := v.statement()
	if err != nil || !P256SignatureEncodingValid(v.Signature) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: body}
	w.blob(v.Signature)
	return w.b, nil
}

// InspectRetirementAmbiguity borrows the input until the caller finishes
// validation. GC only uses the physical identity of an unmarked object.
func InspectRetirementAmbiguity(body []byte) (RetirementAmbiguityRecord, error) {
	if len(body) > RetirementAmbiguityMaxLength {
		return RetirementAmbiguityRecord{}, ErrRecordCapacity
	}
	r := cryptoReader{b: body}
	schema := r.u16()
	v := RetirementAmbiguityRecord{Domain: r.requiredID(), Operation: r.requiredID(), Attempt: r.requiredID(), Inbox: r.requiredID(), Graph: r.requiredID(), PublicKey: r.blob(retirementPublicKeyLength), Facts: r.blob(GeneratorSafeFactsEnvelopeLength), Signature: r.blob(MaxSignature)}
	if err := r.end(); err != nil || schema != retirementAmbiguitySchema || !P256SignatureEncodingValid(v.Signature) {
		return RetirementAmbiguityRecord{}, ErrRecord
	}
	if _, err := v.statement(); err != nil {
		return RetirementAmbiguityRecord{}, err
	}
	return v, nil
}

func (v RetirementAmbiguityRecord) Verify(commitment, domain, operation, attempt, inbox, graph ID) bool {
	if v.Domain != domain || v.Operation != operation || v.Attempt != attempt || v.Inbox != inbox || v.Graph != graph {
		return false
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), v.PublicKey)
	if err != nil || generatorDigest("retirement-return-key", v.PublicKey) != commitment || !P256SignatureEncodingValid(v.Signature) {
		return false
	}
	digest, err := v.Digest()
	return err == nil && ecdsa.VerifyASN1(key, digest[:], v.Signature)
}
