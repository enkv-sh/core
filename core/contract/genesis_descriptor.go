package contract

import "bytes"

const (
	GenesisDescriptorLimit    = 4 << 20
	GenesisRecipientsLimit    = len(genesisRecipientsPrefix) + 2 + 32 + 2 + CryptoMaxRecipients*(2+4+RecipientRecordMaxLength)
	GenesisRequestCoreLength  = 209
	GenesisArtifactFactLength = 76
	genesisDescriptorPrefix   = cryptoPurposePrefix + "genesis-descriptor-v1\x00"
	genesisRecipientsPrefix   = cryptoPurposePrefix + "genesis-recipients-v1\x00"
	genesisRequestPrefix      = cryptoPurposePrefix + "genesis-request-v2\x00"
)

type GenesisDescriptorCore struct {
	InitID, DomainID, DescriptorArtifactID, ManifestArtifactID                                      ID
	Provider                                                                                        Family
	StoreID, CoordinateID, NonBodyID, TrustID                                                       ID
	InterpretationID, TrustInterpretationID, CompatibilityID, CryptoSupportID, AuthorityRecipientID ID
	NormalSigning                                                                                   PublicSigningBinding
	Recovery                                                                                        *RecoveryBindings
	Recipients                                                                                      []RecipientRecord
}

func (v GenesisDescriptorCore) CurrentControl() CurrentControl {
	return CurrentControl{CurrentControlFields: CurrentControlFields{Schema: CanonicalSchema, Profile: MaterialCryptoProfile, DomainID: v.DomainID, Provider: v.Provider, StoreID: v.StoreID, CoordinateID: v.CoordinateID, NonBodyID: v.NonBodyID, TrustInterpretationID: v.TrustInterpretationID, CompatibilityID: v.CompatibilityID, CryptoSupportID: v.CryptoSupportID, AuthorityRecipientID: v.AuthorityRecipientID, AccessIncarnationID: DeriveAccessIncarnationID(v.DomainID, v.NormalSigning.Binding.ControlIncarnationID), AccessGeneration: 1}, NormalSigning: v.NormalSigning, Recovery: v.Recovery}
}
func (v GenesisDescriptorCore) RecoveryMode() uint8 {
	if v.Recovery != nil {
		return 1
	}
	return 0
}
func genesisRecipientsLength(domain ID, rows []RecipientRecord) (int, error) {
	if len(rows) > CryptoMaxRecipients {
		return 0, ErrRecordCapacity
	}
	if domain.IsZero() || len(rows) == 0 {
		return 0, ErrRecord
	}
	n := len(genesisRecipientsPrefix) + 2 + 32 + 2
	identities := make(map[ID]bool, 2*len(rows))
	for i, row := range rows {
		size, err := RecipientRecordLength(row)
		if err != nil {
			return 0, err
		}
		if row.Status != CurrentRecipient || row.CurrentBinding == nil || row.CurrentBinding.BindingSerial != 1 ||
			identities[row.RecipientID] || identities[row.CurrentBinding.BindingID] || row.RecipientID == row.CurrentBinding.BindingID ||
			i > 0 && bytes.Compare(rows[i-1].RecipientID[:], row.RecipientID[:]) >= 0 {
			return 0, ErrRecord
		}
		identities[row.RecipientID] = true
		identities[row.CurrentBinding.BindingID] = true
		n += 2 + 4 + size
	}
	return n, nil
}
func writeGenesisRecipients(w *cryptoWriter, domain ID, rows []RecipientRecord) {
	w.raw([]byte(genesisRecipientsPrefix))
	w.u16(CanonicalSchema)
	w.id(domain)
	w.u16(uint16(len(rows)))
	for i, row := range rows {
		w.u16(uint16(i))
		w.u32(uint32(recipientRecordEncodedLength(row)))
		writeRecipientRecord(w, row)
	}
}
func EncodeGenesisRecipientsCore(domain ID, rows []RecipientRecord) ([]byte, error) {
	n, err := genesisRecipientsLength(domain, rows)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGenesisRecipients(&w, domain, rows)
	return w.b, nil
}

type genesisRecipientsView struct {
	domain ID
	rows   []byte
	count  int
}

func inspectGenesisRecipients(b []byte) (genesisRecipientsView, error) {
	if len(b) > GenesisRecipientsLimit {
		return genesisRecipientsView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisRecipientsPrefix)), []byte(genesisRecipientsPrefix)) || r.u16() != CanonicalSchema {
		return genesisRecipientsView{}, ErrRecord
	}
	v := genesisRecipientsView{domain: r.requiredID(), count: int(r.u16())}
	if v.count < 1 || v.count > CryptoMaxRecipients {
		return genesisRecipientsView{}, ErrRecordCapacity
	}
	start := r.i
	var previous ID
	var identities [2 * CryptoMaxRecipients]ID
	identityCount := 0
	for i := 0; i < v.count; i++ {
		if r.u16() != uint16(i) {
			return genesisRecipientsView{}, ErrRecord
		}
		body := r.blob(RecipientRecordMaxLength)
		if r.err != nil {
			return genesisRecipientsView{}, r.failure()
		}
		nested := newRecordReader(body)
		row := readRecipientRecord(&nested)
		if err := nested.end(); err != nil {
			return genesisRecipientsView{}, err
		}
		if row.Status != CurrentRecipient || row.CurrentBinding.BindingSerial != 1 || i > 0 && bytes.Compare(previous[:], row.RecipientID[:]) >= 0 {
			return genesisRecipientsView{}, ErrRecord
		}
		previous = row.RecipientID
		for _, id := range []ID{row.RecipientID, row.CurrentBinding.BindingID} {
			for j := 0; j < identityCount; j++ {
				if identities[j] == id {
					return genesisRecipientsView{}, ErrRecord
				}
			}
			if row.RecipientID == row.CurrentBinding.BindingID {
				return genesisRecipientsView{}, ErrRecord
			}
			identities[identityCount] = id
			identityCount++
		}
	}
	if err := r.end(); err != nil {
		return genesisRecipientsView{}, err
	}
	v.rows = b[start:r.i:r.i]
	// Validate public keys only after all structure and suffix bounds pass.
	rows := newRecordReader(v.rows)
	for i := 0; i < v.count; i++ {
		rows.u16()
		body := rows.blob(RecipientRecordMaxLength)
		if _, err := InspectRecipientRecord(body); err != nil {
			return genesisRecipientsView{}, err
		}
	}
	return v, nil
}
func (v genesisRecipientsView) own() []RecipientRecord {
	rows := make([]RecipientRecord, v.count)
	r := newRecordReader(v.rows)
	for i := range rows {
		r.u16()
		body := r.blob(RecipientRecordMaxLength)
		nested := newRecordReader(body)
		rows[i] = readRecipientRecord(&nested).own()
	}
	return rows
}
func DecodeGenesisRecipientsCore(b []byte) (ID, []RecipientRecord, error) {
	v, err := inspectGenesisRecipients(b)
	if err != nil {
		return ID{}, nil, err
	}
	return v.domain, v.own(), nil
}
func (v GenesisDescriptorCore) BindingTable() ([]BindingTableRow, error) {
	if _, err := GenesisDescriptorCoreLength(v); err != nil {
		return nil, err
	}
	rows := make([]BindingTableRow, 0, len(v.Recipients)+int(v.RecoveryMode()))
	for _, row := range v.Recipients {
		binding := *row.CurrentBinding
		binding.SPKI = ownedBytes(binding.SPKI)
		rows = append(rows, BindingTableRow{SubjectKind: OrdinaryWrapSubject, SubjectID: row.RecipientID, Binding: binding})
	}
	if v.Recovery != nil {
		binding := v.Recovery.KMS
		binding.SPKI = ownedBytes(binding.SPKI)
		rows = append(rows, BindingTableRow{SubjectKind: RecoveryWrapSubject, SubjectID: v.Recovery.RoleID, Binding: binding})
	}
	return rows, nil
}
func GenesisDescriptorCoreLength(v GenesisDescriptorCore) (int, error) {
	if !publicIDsValid(v.InitID, v.DomainID, v.DescriptorArtifactID, v.ManifestArtifactID, v.TrustID, v.InterpretationID) || v.DescriptorArtifactID == v.ManifestArtifactID {
		return 0, ErrRecord
	}
	control := currentControlInputOf(v.CurrentControl())
	if err := control.shapeError(); err != nil {
		return 0, err
	}
	if err := control.keysError(); err != nil {
		return 0, err
	}
	if v.NormalSigning.Binding.Trust != v.TrustID || v.NormalSigning.Binding.Interpretation != v.InterpretationID || v.NormalSigning.Binding.Epoch != 1 {
		return 0, ErrRecord
	}
	n, err := genesisRecipientsLength(v.DomainID, v.Recipients)
	if err != nil {
		return 0, err
	}
	var authority *KMSBinding
	for _, row := range v.Recipients {
		if row.CurrentBinding.Provider != v.Provider {
			return 0, ErrRecord
		}
		if row.RecipientID == v.AuthorityRecipientID {
			authority = row.CurrentBinding
		}
	}
	if authority == nil {
		return 0, ErrRecord
	}
	pair := ControlCore{CurrentControl: v.CurrentControl(), AuthorityKMSBinding: *authority}
	if !successionControlPairValid(pair) {
		return 0, ErrRecord
	}
	if v.Recovery != nil {
		r := v.Recovery
		if r.Signing.Binding.Epoch != 1 || r.KMS.BindingSerial != 1 {
			return 0, ErrRecord
		}
		for _, row := range v.Recipients {
			if row.RecipientID == r.RoleID || row.CurrentBinding.BindingID == r.KMS.BindingID {
				return 0, ErrRecord
			}
		}
	}
	// Prefix/schema/profile/durability, thirteen IDs, provider, two blobs, mode.
	return len(genesisDescriptorPrefix) + 6 + 13*32 + 1 + 4 + control.normal.length() + 1 + control.recoveryLength() + 4 + n, nil
}
func writeGenesisDescriptor(w *cryptoWriter, v GenesisDescriptorCore, recipientLength int) {
	w.raw([]byte(genesisDescriptorPrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	w.u16(1)
	for _, id := range []ID{v.InitID, v.DomainID, v.DescriptorArtifactID, v.ManifestArtifactID} {
		w.id(id)
	}
	w.u8(uint8(v.Provider))
	for _, id := range []ID{v.StoreID, v.CoordinateID, v.NonBodyID, v.TrustID, v.InterpretationID, v.TrustInterpretationID, v.CompatibilityID, v.CryptoSupportID, v.AuthorityRecipientID} {
		w.id(id)
	}
	writePublicSigningBindingBlob(w, v.NormalSigning)
	writeRecoveryBindings(w, currentControlInputOf(v.CurrentControl()))
	w.u32(uint32(recipientLength))
	writeGenesisRecipients(w, v.DomainID, v.Recipients)
}
func EncodeGenesisDescriptorCore(v GenesisDescriptorCore) ([]byte, error) {
	n, err := GenesisDescriptorCoreLength(v)
	if err != nil {
		return nil, err
	}
	recipientLength, err := genesisRecipientsLength(v.DomainID, v.Recipients)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeGenesisDescriptor(&w, v, recipientLength)
	return w.b, nil
}
func DecodeGenesisDescriptorCore(b []byte) (GenesisDescriptorCore, error) {
	if len(b) > GenesisDescriptorLimit {
		return GenesisDescriptorCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisDescriptorPrefix)), []byte(genesisDescriptorPrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile || r.u16() != 1 {
		return GenesisDescriptorCore{}, ErrRecord
	}
	v := GenesisDescriptorCore{InitID: r.requiredID(), DomainID: r.requiredID(), DescriptorArtifactID: r.requiredID(), ManifestArtifactID: r.requiredID(), Provider: Family(r.u8()), StoreID: r.requiredID(), CoordinateID: r.requiredID(), NonBodyID: r.requiredID(), TrustID: r.requiredID(), InterpretationID: r.requiredID(), TrustInterpretationID: r.requiredID(), CompatibilityID: r.requiredID(), CryptoSupportID: r.requiredID(), AuthorityRecipientID: r.requiredID()}
	normal := readPublicSigningBindingBlob(&r)
	recovery := readRecoveryBindings(&r)
	recipientBytes := r.blob(GenesisRecipientsLimit)
	if err := r.end(); err != nil {
		return GenesisDescriptorCore{}, err
	}
	recipients, err := inspectGenesisRecipients(recipientBytes)
	if err != nil {
		return GenesisDescriptorCore{}, err
	}
	if recipients.domain != v.DomainID {
		return GenesisDescriptorCore{}, ErrRecord
	}
	if v.NormalSigning, err = normal.Own(); err != nil {
		return GenesisDescriptorCore{}, err
	}
	if recovery != nil {
		signing, err := recovery.Signing.Own()
		if err != nil {
			return GenesisDescriptorCore{}, err
		}
		kms, err := recovery.KMS.Own()
		if err != nil {
			return GenesisDescriptorCore{}, err
		}
		v.Recovery = &RecoveryBindings{RoleID: recovery.RoleID, Signing: signing, KMS: kms}
	}
	v.Recipients = recipients.own()
	if _, err := GenesisDescriptorCoreLength(v); err != nil {
		return GenesisDescriptorCore{}, err
	}
	return v, nil
}

type GenesisRequestCore struct {
	InitID, DomainID, DescriptorDigest, GenesisIdentityPlanDigest, SetupDigest ID
	Expiry                                                                     uint64
	RecoveryMode, InitOwnerDecision, RecoveryLossAcknowledgement               uint8
}

func (v GenesisRequestCore) valid() bool {
	return publicIDsValid(v.InitID, v.DomainID, v.DescriptorDigest, v.GenesisIdentityPlanDigest, v.SetupDigest) && v.Expiry > 0 && v.Expiry <= 1<<63-1 && v.RecoveryMode <= 1 && v.InitOwnerDecision == 1 && v.RecoveryLossAcknowledgement == 1-v.RecoveryMode
}
func writeGenesisRequestCore(w *cryptoWriter, v GenesisRequestCore) {
	w.raw([]byte(genesisRequestPrefix))
	w.u16(CanonicalSchema)
	w.u16(GenesisProfile)
	for _, id := range []ID{v.InitID, v.DomainID, v.DescriptorDigest, v.GenesisIdentityPlanDigest, v.SetupDigest} {
		w.id(id)
	}
	w.u64(v.Expiry)
	w.u8(v.RecoveryMode)
	w.u8(v.InitOwnerDecision)
	w.u8(v.RecoveryLossAcknowledgement)
}
func EncodeGenesisRequestCore(v GenesisRequestCore) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GenesisRequestCoreLength)}
	writeGenesisRequestCore(&w, v)
	return w.b, nil
}
func DecodeGenesisRequestCore(b []byte) (GenesisRequestCore, error) {
	if len(b) > GenesisRequestCoreLength {
		return GenesisRequestCore{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	if !bytes.Equal(r.take(len(genesisRequestPrefix)), []byte(genesisRequestPrefix)) || r.u16() != CanonicalSchema || r.u16() != GenesisProfile {
		return GenesisRequestCore{}, ErrRecord
	}
	v := GenesisRequestCore{InitID: r.requiredID(), DomainID: r.requiredID(), DescriptorDigest: r.requiredID(), GenesisIdentityPlanDigest: r.requiredID(), SetupDigest: r.requiredID(), Expiry: r.u64(), RecoveryMode: r.u8(), InitOwnerDecision: r.u8(), RecoveryLossAcknowledgement: r.u8()}
	if err := r.end(); err != nil {
		return GenesisRequestCore{}, err
	}
	if !v.valid() {
		return GenesisRequestCore{}, ErrRecord
	}
	return v, nil
}

// These public facts record checks completed by the private artifact owner.
// Parsing one cannot grant artifact durability or parent admission.
type GenesisArtifactFact struct {
	Kind                   uint8
	ArtifactID, BodyDigest ID
	BodyLength             uint64
	DurabilityProfile      uint16
	Outcome                uint8
}

func (v GenesisArtifactFact) valid() bool {
	return (v.Kind == 1 || v.Kind == 2 || v.Kind == 3) && publicIDsValid(v.ArtifactID, v.BodyDigest) && v.BodyLength > 0 && v.BodyLength <= GenesisDescriptorLimit && v.DurabilityProfile == 1 && v.Outcome == 1 && (v.Kind != 2 || v.BodyLength <= 32<<10) && (v.Kind != 3 || v.BodyLength <= MaxStoreConfigurationLength && v.ArtifactID == v.BodyDigest)
}
func writeGenesisArtifactFact(w *cryptoWriter, v GenesisArtifactFact) {
	w.u8(v.Kind)
	w.id(v.ArtifactID)
	w.id(v.BodyDigest)
	w.u64(v.BodyLength)
	w.u16(v.DurabilityProfile)
	w.u8(v.Outcome)
}
func readGenesisArtifactFact(r *cryptoReader) GenesisArtifactFact {
	v := GenesisArtifactFact{Kind: r.u8(), ArtifactID: r.requiredID(), BodyDigest: r.requiredID(), BodyLength: r.u64(), DurabilityProfile: r.u16(), Outcome: r.u8()}
	if r.err == nil && !v.valid() {
		r.err = ErrRecord
	}
	return v
}
func EncodeGenesisArtifactFact(v GenesisArtifactFact) ([]byte, error) {
	if !v.valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, GenesisArtifactFactLength)}
	writeGenesisArtifactFact(&w, v)
	return w.b, nil
}
func DecodeGenesisArtifactFact(b []byte) (GenesisArtifactFact, error) {
	if len(b) > GenesisArtifactFactLength {
		return GenesisArtifactFact{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readGenesisArtifactFact(&r)
	if err := r.end(); err != nil {
		return GenesisArtifactFact{}, err
	}
	return v, nil
}
