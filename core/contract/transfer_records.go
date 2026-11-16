package contract

import "bytes"

const (
	operationMaterialCoreWireLength  = 204
	operationMaterialRecordLength    = operationMaterialCoreWireLength + 32
	transferSchema                   = 2
	sourceTransferUse                = 1
	resultTransferUse                = 2
	sourceTransferPacketKind         = 5
	resultTransferPacketKind         = 6
	SourceTransferPacketLength       = 68
	ResultTransferPacketLength       = 100
	sourceTransferCoreWireLength     = 297
	resultTransferCoreWireLength     = 329
	transferEnvelopePrefix           = "ENKV/TRANSFER/v2\x00"
	transferPacketDigestPrefix       = cryptoPurposePrefix + "transfer-packet\x00"
	transferCiphertextMaxLength      = ResultTransferPacketLength + canonicalCiphertextTagSize
	sourceTransferEnvelopeWireLength = len(transferEnvelopePrefix) + sourceTransferCoreWireLength + 12 + SourceTransferPacketLength + canonicalCiphertextTagSize
	transferEnvelopeMaxLength        = len(transferEnvelopePrefix) + resultTransferCoreWireLength + 12 + transferCiphertextMaxLength
)

// OperationMaterialCore fixes the public seed context. It excludes the seed,
// its confirmation check, and mutable key access protection.
type OperationMaterialCore struct {
	Schema              uint16
	Profile             uint16
	CompatibilityID     ID
	CryptoSupportID     ID
	DomainID            ID
	OperationID         ID
	OperationMaterialID ID
	UsePlanDigest       ID
	SeedEpoch           uint64
}

func operationMaterialCoreValid(v OperationMaterialCore) bool {
	return v.Schema == storedMaterialSchema && v.Profile == MaterialCryptoProfile && v.SeedEpoch != 0 &&
		publicIDsValid(v.CompatibilityID, v.CryptoSupportID, v.DomainID, v.OperationID, v.OperationMaterialID)
}

func OperationMaterialCoreLength(v OperationMaterialCore) (int, error) {
	if !operationMaterialCoreValid(v) {
		return 0, ErrRecord
	}
	return operationMaterialCoreWireLength, nil
}

func writeOperationMaterialCore(w *cryptoWriter, v OperationMaterialCore) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.CompatibilityID)
	w.id(v.CryptoSupportID)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.OperationMaterialID)
	w.id(v.UsePlanDigest)
	w.u64(v.SeedEpoch)
}

func readOperationMaterialCore(r *cryptoReader) OperationMaterialCore {
	v := OperationMaterialCore{Schema: r.u16(), Profile: r.u16(), CompatibilityID: r.requiredID(),
		CryptoSupportID: r.requiredID(), DomainID: r.requiredID(), OperationID: r.requiredID(),
		OperationMaterialID: r.requiredID(), UsePlanDigest: r.id(), SeedEpoch: r.u64()}
	if r.err == nil && !operationMaterialCoreValid(v) {
		r.err = ErrRecord
	}
	return v
}

func AppendOperationMaterialCore(dst []byte, v OperationMaterialCore) ([]byte, error) {
	if _, err := OperationMaterialCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeOperationMaterialCore(&w, v)
	return w.b, nil
}

func EncodeOperationMaterialCore(v OperationMaterialCore) ([]byte, error) {
	n, err := OperationMaterialCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeOperationMaterialCore(&w, v)
	return w.b, nil
}

func ParseOperationMaterialCore(b []byte) (OperationMaterialCore, int, error) {
	r := newRecordReader(b)
	v := readOperationMaterialCore(&r)
	if r.err != nil {
		return OperationMaterialCore{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectOperationMaterialCore(b []byte) (OperationMaterialCore, error) {
	if len(b) > operationMaterialCoreWireLength {
		return OperationMaterialCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readOperationMaterialCore(&r)
	if err := r.end(); err != nil {
		return OperationMaterialCore{}, err
	}
	return v, nil
}

func DecodeOperationMaterialCore(b []byte) (OperationMaterialCore, error) {
	return InspectOperationMaterialCore(b)
}

func OperationMaterialContextDigest(v OperationMaterialCore) (ID, error) {
	n, err := OperationMaterialCoreLength(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(valueMaterialDigestPrefix)
	w.u32(uint32(n))
	writeOperationMaterialCore(&w, v)
	return w.result(0).Digest, nil
}

// OperationImmutableBodyDigest binds the complete public seed context and
// opaque check. It does not establish possession or validity of the seed.
func OperationImmutableBodyDigest(v OperationMaterialCore, seedCheck ID) (ID, error) {
	n, err := OperationMaterialCoreLength(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(immutableMaterialBodyPrefix)
	w.u16(uint16(OperationSeedMaterialKind))
	w.u32(uint32(n))
	writeOperationMaterialCore(&w, v)
	w.id(seedCheck)
	return w.result(0).Digest, nil
}

// OperationMaterialRecord adds the opaque immutable seed check to its public
// context. Structural decoding does not authenticate the check or grant access.
type OperationMaterialRecord struct {
	Core      OperationMaterialCore
	SeedCheck ID
}

func OperationMaterialRecordLength(v OperationMaterialRecord) (int, error) {
	if _, err := OperationMaterialCoreLength(v.Core); err != nil {
		return 0, err
	}
	return operationMaterialRecordLength, nil
}

func writeOperationMaterialRecord(w *cryptoWriter, v OperationMaterialRecord) {
	writeOperationMaterialCore(w, v.Core)
	w.id(v.SeedCheck)
}

func readOperationMaterialRecord(r *cryptoReader) OperationMaterialRecord {
	return OperationMaterialRecord{Core: readOperationMaterialCore(r), SeedCheck: r.id()}
}

func AppendOperationMaterialRecord(dst []byte, v OperationMaterialRecord) ([]byte, error) {
	if _, err := OperationMaterialRecordLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeOperationMaterialRecord(&w, v)
	return w.b, nil
}

func EncodeOperationMaterialRecord(v OperationMaterialRecord) ([]byte, error) {
	n, err := OperationMaterialRecordLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeOperationMaterialRecord(&w, v)
	return w.b, nil
}

func ParseOperationMaterialRecord(b []byte) (OperationMaterialRecord, int, error) {
	r := newRecordReader(b)
	v := readOperationMaterialRecord(&r)
	if r.err != nil {
		return OperationMaterialRecord{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectOperationMaterialRecord(b []byte) (OperationMaterialRecord, error) {
	if len(b) > operationMaterialRecordLength {
		return OperationMaterialRecord{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readOperationMaterialRecord(&r)
	if err := r.end(); err != nil {
		return OperationMaterialRecord{}, err
	}
	return v, nil
}

func DecodeOperationMaterialRecord(b []byte) (OperationMaterialRecord, error) {
	return InspectOperationMaterialRecord(b)
}

// TransferCore binds one closed source or result packet to its immutable
// operation context. It excludes current key routes and access protection.
type TransferCore struct {
	Schema                uint16
	Profile               uint16
	CompatibilityID       ID
	CryptoSupportID       ID
	DomainID              ID
	OperationID           ID
	OperationMaterialID   ID
	UsePlanDigest         ID
	EnvelopeID            ID
	UseKind               uint8
	PacketKind            uint16
	PacketLength          uint16
	SourceID              ID
	SealedInputCoreDigest ID
	AttemptID             ID
	ResultID              ID
	ResultCoreDigest      ID
}

func transferCoreHeaderLength(v TransferCore) (int, error) {
	if v.Schema != transferSchema || v.Profile != MaterialCryptoProfile ||
		!publicIDsValid(v.CompatibilityID, v.CryptoSupportID, v.DomainID, v.OperationID, v.OperationMaterialID, v.EnvelopeID) {
		return 0, ErrRecord
	}
	switch v.UseKind {
	case sourceTransferUse:
		if v.PacketKind == sourceTransferPacketKind && v.PacketLength == SourceTransferPacketLength {
			return sourceTransferCoreWireLength, nil
		}
	case resultTransferUse:
		if v.PacketKind == resultTransferPacketKind && v.PacketLength == ResultTransferPacketLength {
			return resultTransferCoreWireLength, nil
		}
	}
	return 0, ErrRecord
}

func TransferCoreLength(v TransferCore) (int, error) {
	n, err := transferCoreHeaderLength(v)
	if err != nil {
		return 0, err
	}
	if v.UseKind == sourceTransferUse {
		if v.SourceID.IsZero() || !v.AttemptID.IsZero() || !v.ResultID.IsZero() || !v.ResultCoreDigest.IsZero() {
			return 0, ErrRecord
		}
	} else if v.AttemptID.IsZero() || v.ResultID.IsZero() || !v.SourceID.IsZero() || !v.SealedInputCoreDigest.IsZero() {
		return 0, ErrRecord
	}
	return n, nil
}

func writeTransferCore(w *cryptoWriter, v TransferCore) {
	w.u16(v.Schema)
	w.u16(v.Profile)
	w.id(v.CompatibilityID)
	w.id(v.CryptoSupportID)
	w.id(v.DomainID)
	w.id(v.OperationID)
	w.id(v.OperationMaterialID)
	w.id(v.UsePlanDigest)
	w.id(v.EnvelopeID)
	w.u8(v.UseKind)
	w.u16(v.PacketKind)
	w.u16(v.PacketLength)
	if v.UseKind == sourceTransferUse {
		w.id(v.SourceID)
		w.id(v.SealedInputCoreDigest)
		return
	}
	w.id(v.AttemptID)
	w.id(v.ResultID)
	w.id(v.ResultCoreDigest)
}

func readTransferCore(r *cryptoReader) TransferCore {
	v := TransferCore{Schema: r.u16(), Profile: r.u16(), CompatibilityID: r.requiredID(),
		CryptoSupportID: r.requiredID(), DomainID: r.requiredID(), OperationID: r.requiredID(),
		OperationMaterialID: r.requiredID(), UsePlanDigest: r.id(), EnvelopeID: r.requiredID(),
		UseKind: r.u8(), PacketKind: r.u16(), PacketLength: r.u16()}
	if r.err != nil {
		return v
	}
	if _, err := transferCoreHeaderLength(v); err != nil {
		r.err = err
		return v
	}
	if v.UseKind == sourceTransferUse {
		v.SourceID = r.requiredID()
		v.SealedInputCoreDigest = r.id()
		return v
	}
	v.AttemptID = r.requiredID()
	v.ResultID = r.requiredID()
	v.ResultCoreDigest = r.id()
	return v
}

func AppendTransferCore(dst []byte, v TransferCore) ([]byte, error) {
	if _, err := TransferCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeTransferCore(&w, v)
	return w.b, nil
}

func EncodeTransferCore(v TransferCore) ([]byte, error) {
	n, err := TransferCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeTransferCore(&w, v)
	return w.b, nil
}

func ParseTransferCore(b []byte) (TransferCore, int, error) {
	r := newRecordReader(b)
	v := readTransferCore(&r)
	if r.err != nil {
		return TransferCore{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectTransferCore(b []byte) (TransferCore, error) {
	if len(b) > resultTransferCoreWireLength {
		return TransferCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readTransferCore(&r)
	if err := r.end(); err != nil {
		return TransferCore{}, err
	}
	return v, nil
}

func DecodeTransferCore(b []byte) (TransferCore, error) {
	return InspectTransferCore(b)
}

func TransferPacketContextDigest(v TransferCore) (ID, error) {
	n, err := TransferCoreLength(v)
	if err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(transferPacketDigestPrefix)
	w.u32(uint32(n))
	writeTransferCore(&w, v)
	return w.result(0).Digest, nil
}

// TransferEnvelope carries public encrypted packet bytes. Structural decoding
// does not authenticate its context or open its private packet.
type TransferEnvelope struct {
	Core       TransferCore
	Nonce      [12]byte
	Ciphertext []byte
}

// TransferEnvelopeView borrows Ciphertext. Keep the input unchanged until
// inspection ends or Own copies the validated view.
type TransferEnvelopeView TransferEnvelope

func (v TransferEnvelopeView) Own() (TransferEnvelope, error) {
	out := TransferEnvelope(v)
	if _, err := TransferEnvelopeLength(out); err != nil {
		return TransferEnvelope{}, err
	}
	out.Ciphertext = ownedBytes(out.Ciphertext)
	return out, nil
}

func TransferEnvelopeLength(v TransferEnvelope) (int, error) {
	if len(v.Ciphertext) > transferCiphertextMaxLength {
		return 0, ErrRecordCapacity
	}
	n, err := TransferCoreLength(v.Core)
	if err != nil {
		return 0, err
	}
	if len(v.Ciphertext) != int(v.Core.PacketLength)+canonicalCiphertextTagSize {
		return 0, ErrRecord
	}
	return len(transferEnvelopePrefix) + n + len(v.Nonce) + len(v.Ciphertext), nil
}

func writeTransferEnvelope(w *cryptoWriter, v TransferEnvelope) {
	w.raw([]byte(transferEnvelopePrefix))
	writeTransferCore(w, v.Core)
	w.raw(v.Nonce[:])
	w.raw(v.Ciphertext)
}

func readTransferEnvelope(r *cryptoReader) TransferEnvelopeView {
	if !bytes.Equal(r.take(len(transferEnvelopePrefix)), []byte(transferEnvelopePrefix)) {
		if r.err == nil {
			r.err = ErrRecord
		}
		return TransferEnvelopeView{}
	}
	v := TransferEnvelopeView{Core: readTransferCore(r)}
	if r.err != nil {
		return v
	}
	copy(v.Nonce[:], r.take(len(v.Nonce)))
	v.Ciphertext = r.take(int(v.Core.PacketLength) + canonicalCiphertextTagSize)
	return v
}

func AppendTransferEnvelope(dst []byte, v TransferEnvelope) ([]byte, error) {
	if _, err := TransferEnvelopeLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeTransferEnvelope(&w, v)
	return w.b, nil
}

func EncodeTransferEnvelope(v TransferEnvelope) ([]byte, error) {
	n, err := TransferEnvelopeLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeTransferEnvelope(&w, v)
	return w.b, nil
}

func ParseTransferEnvelope(b []byte) (TransferEnvelopeView, int, error) {
	r := newRecordReader(b)
	v := readTransferEnvelope(&r)
	if r.err != nil {
		return TransferEnvelopeView{}, 0, r.failure()
	}
	return v, r.i, nil
}

func InspectTransferEnvelope(b []byte) (TransferEnvelopeView, error) {
	if len(b) > transferEnvelopeMaxLength {
		return TransferEnvelopeView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readTransferEnvelope(&r)
	if err := r.end(); err != nil {
		return TransferEnvelopeView{}, err
	}
	return v, nil
}

func DecodeTransferEnvelope(b []byte) (TransferEnvelope, error) {
	v, err := InspectTransferEnvelope(b)
	if err != nil {
		return TransferEnvelope{}, err
	}
	return v.Own()
}
