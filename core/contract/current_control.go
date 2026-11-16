package contract

import "bytes"

const (
	controlCorePrefix      = cryptoPurposePrefix + "succession-control-v2\x00"
	controlCoreFixedLength = 347
	controlCoreMaxLength   = 6697
	// ControlCoreMaxLength bounds an encoded current-control basis.
	ControlCoreMaxLength      = controlCoreMaxLength
	recoveryBindingsMaxLength = 32 + 8 + PublicSigningBindingMaxLength + KMSBindingMaxLength
)

type CurrentControlFields struct {
	Schema, Profile                                         uint16
	DomainID                                                ID
	Provider                                                Family
	StoreID, CoordinateID, NonBodyID, TrustInterpretationID ID
	CompatibilityID, CryptoSupportID, AuthorityRecipientID  ID
	AccessIncarnationID                                     ID
	AccessGeneration                                        uint64
}

type RecoveryBindings struct {
	RoleID  ID
	Signing PublicSigningBinding
	KMS     KMSBinding
}

type CurrentControl struct {
	CurrentControlFields
	NormalSigning PublicSigningBinding
	Recovery      *RecoveryBindings
}

type RecoveryBindingsView struct {
	RoleID  ID
	Signing PublicSigningBindingView
	KMS     KMSBindingView
}

// CurrentControlView borrows selectors and public keys from unchanged input.
// Recovery is nil exactly when the encoded recovery mode is disabled.
type CurrentControlView struct {
	CurrentControlFields
	NormalSigning PublicSigningBindingView
	Recovery      *RecoveryBindingsView
}

// ControlCore adds the authority KEK resolved from its ordinary registry row.
// Structural validation does not establish that selected-registry relation.
type ControlCore struct {
	CurrentControl
	AuthorityKMSBinding KMSBinding
}

type ControlCoreView struct {
	CurrentControlView
	AuthorityKMSBinding KMSBindingView
}

// These adapters retain either an owned selector or a borrowed selector span.
// Both forms use the same binding writer, with no intermediate key or image copy.
type signingBindingInput struct {
	value    PublicSigningBinding
	selector []byte
}

func signingViewInput(v PublicSigningBindingView) signingBindingInput {
	return signingBindingInput{value: v.fields(), selector: v.KeySelector}
}
func (v signingBindingInput) length() int {
	n := len(v.value.KeySelector)
	if v.selector != nil {
		n = len(v.selector)
	}
	return publicSigningBindingLength(n, len(v.value.SPKI))
}
func (v signingBindingInput) shapeError() error {
	x := v.value
	if v.selector != nil {
		return signingBindingShapeError(x.Schema, x.Role, x.Provider, x.SigningProfile, x.BindingID, x.Fingerprint, x.Binding, v.selector, len(x.SPKI))
	}
	_, err := publicSigningBindingShapeLength(x)
	return err
}
func (v signingBindingInput) keyError() error {
	return ValidatePublicSigningKey(v.value.SPKI, v.value.Fingerprint)
}
func (v signingBindingInput) writeBlob(w *cryptoWriter) {
	w.u32(uint32(v.length()))
	if v.selector != nil {
		writePublicSigningBindingFields(w, v.value, v.selector)
	} else {
		writePublicSigningBinding(w, v.value)
	}
}
func (v signingBindingInput) own() PublicSigningBinding {
	x := v.value
	if v.selector != nil {
		x.KeySelector = string(v.selector)
	}
	x.SPKI = ownedBytes(x.SPKI)
	return x
}

type kmsBindingInput struct {
	value    KMSBinding
	selector []byte
}

func kmsViewInput(v KMSBindingView) kmsBindingInput {
	return kmsBindingInput{value: v.fields(), selector: v.KeySelector}
}
func (v kmsBindingInput) length() int {
	n := len(v.value.KeySelector)
	if v.selector != nil {
		n = len(v.selector)
	}
	return kmsBindingLength(n)
}
func (v kmsBindingInput) shapeError() error {
	x := v.value
	if v.selector != nil {
		return kmsBindingViewShapeError(KMSBindingView{BindingID: x.BindingID, BindingIncarnationID: x.BindingIncarnationID,
			BindingSerial: x.BindingSerial, Provider: x.Provider,
			WrapProfile: x.WrapProfile, ProtectionClass: x.ProtectionClass, KeySelector: v.selector, SPKI: x.SPKI, Fingerprint: x.Fingerprint})
	}
	_, err := kmsBindingShapeLength(x)
	return err
}
func (v kmsBindingInput) keyError() error {
	return ValidatePublicEncryptionKey(v.value.SPKI, v.value.Fingerprint)
}
func (v kmsBindingInput) writeBlob(w *cryptoWriter) {
	w.u32(uint32(v.length()))
	if v.selector != nil {
		writeKMSBindingFields(w, v.value, v.selector)
	} else {
		writeKMSBinding(w, v.value)
	}
}
func (v kmsBindingInput) own() KMSBinding {
	x := v.value
	if v.selector != nil {
		x.KeySelector = string(v.selector)
	}
	x.SPKI = ownedBytes(x.SPKI)
	return x
}

type currentControlInput struct {
	fields                  CurrentControlFields
	normal, recoverySigning signingBindingInput
	recoveryKMS             kmsBindingInput
	recoveryRole            ID
	recovery                bool
}

func currentControlInputOf(v CurrentControl) currentControlInput {
	x := currentControlInput{fields: v.CurrentControlFields, normal: signingBindingInput{value: v.NormalSigning}}
	if v.Recovery != nil {
		x.recovery, x.recoveryRole = true, v.Recovery.RoleID
		x.recoverySigning, x.recoveryKMS = signingBindingInput{value: v.Recovery.Signing}, kmsBindingInput{value: v.Recovery.KMS}
	}
	return x
}
func (v CurrentControlView) input() currentControlInput {
	x := currentControlInput{fields: v.CurrentControlFields, normal: signingViewInput(v.NormalSigning)}
	if v.Recovery != nil {
		x.recovery, x.recoveryRole = true, v.Recovery.RoleID
		x.recoverySigning, x.recoveryKMS = signingViewInput(v.Recovery.Signing), kmsViewInput(v.Recovery.KMS)
	}
	return x
}
func (v currentControlInput) recoveryLength() int {
	if !v.recovery {
		return 0
	}
	return 40 + v.recoverySigning.length() + v.recoveryKMS.length()
}
func (v currentControlInput) signerMatches(s PublicSigningBinding, role uint8) bool {
	return s.Role == role && s.Provider == v.fields.Provider && s.Binding.Domain == v.fields.DomainID &&
		s.Binding.Store == v.fields.StoreID && s.Binding.Coordinate == v.fields.CoordinateID
}
func (v currentControlInput) shapeError() error {
	f := v.fields
	if f.Schema != CanonicalSchema || f.Profile != MaterialCryptoProfile || !f.Provider.Valid() || f.AccessGeneration == 0 ||
		!publicIDsValid(f.DomainID, f.StoreID, f.CoordinateID, f.NonBodyID, f.TrustInterpretationID, f.CompatibilityID, f.CryptoSupportID, f.AuthorityRecipientID, f.AccessIncarnationID) {
		return ErrRecord
	}
	if err := v.normal.shapeError(); err != nil {
		return err
	}
	if !v.signerMatches(v.normal.value, NormalSigningRole) {
		return ErrRecord
	}
	if v.recovery {
		if v.recoveryRole.IsZero() {
			return ErrRecord
		}
		if err := v.recoverySigning.shapeError(); err != nil {
			return err
		}
		if err := v.recoveryKMS.shapeError(); err != nil {
			return err
		}
		if !v.signerMatches(v.recoverySigning.value, RecoverySigningRole) || v.recoveryKMS.value.Provider != f.Provider ||
			v.normal.value.Binding.Interpretation != v.recoverySigning.value.Binding.Interpretation {
			return ErrRecord
		}
	}
	return nil
}
func (v currentControlInput) keysError() error {
	if err := v.normal.keyError(); err != nil {
		return err
	}
	if v.recovery {
		if err := v.recoverySigning.keyError(); err != nil {
			return err
		}
		return v.recoveryKMS.keyError()
	}
	return nil
}
func (v currentControlInput) own() CurrentControl {
	out := CurrentControl{CurrentControlFields: v.fields, NormalSigning: v.normal.own()}
	if v.recovery {
		out.Recovery = &RecoveryBindings{RoleID: v.recoveryRole, Signing: v.recoverySigning.own(), KMS: v.recoveryKMS.own()}
	}
	return out
}

func writeRecoveryBindings(w *cryptoWriter, v currentControlInput) {
	if !v.recovery {
		w.u8(0)
		return
	}
	w.u8(1)
	w.id(v.recoveryRole)
	v.recoverySigning.writeBlob(w)
	v.recoveryKMS.writeBlob(w)
}
func readRecoveryBindings(r *cryptoReader) *RecoveryBindingsView {
	mode := r.u8()
	if r.err != nil || mode == 0 {
		return nil
	}
	if mode != 1 {
		r.err = ErrRecord
		return nil
	}
	v := RecoveryBindingsView{RoleID: r.requiredID(), Signing: readPublicSigningBindingBlob(r), KMS: readKMSBindingBlob(r)}
	if r.err != nil {
		return nil
	}
	return &v
}

func controlCoreShapeLength(control currentControlInput, authority kmsBindingInput) (int, error) {
	if err := control.shapeError(); err != nil {
		return 0, err
	}
	if err := authority.shapeError(); err != nil {
		return 0, err
	}
	if authority.value.Provider != control.fields.Provider {
		return 0, ErrRecord
	}
	return controlCoreFixedLength + control.normal.length() + authority.length() + control.recoveryLength(), nil
}
func controlCoreKeysError(control currentControlInput, authority kmsBindingInput) error {
	if err := control.keysError(); err != nil {
		return err
	}
	return authority.keyError()
}
func ControlCoreLength(v ControlCore) (int, error) {
	c, k := currentControlInputOf(v.CurrentControl), kmsBindingInput{value: v.AuthorityKMSBinding}
	n, err := controlCoreShapeLength(c, k)
	if err != nil {
		return 0, err
	}
	if err := controlCoreKeysError(c, k); err != nil {
		return 0, err
	}
	return n, nil
}
func writeControlCore(w *cryptoWriter, c currentControlInput, authority kmsBindingInput) {
	f := c.fields
	w.raw([]byte(controlCorePrefix))
	w.u16(f.Schema)
	w.u16(f.Profile)
	w.id(f.DomainID)
	w.u8(uint8(f.Provider))
	for _, id := range []ID{f.StoreID, f.CoordinateID, f.NonBodyID, f.TrustInterpretationID, f.CompatibilityID, f.CryptoSupportID, f.AuthorityRecipientID} {
		w.id(id)
	}
	w.id(f.AccessIncarnationID)
	w.u64(f.AccessGeneration)
	c.normal.writeBlob(w)
	authority.writeBlob(w)
	writeRecoveryBindings(w, c)
}
func readControlCore(r *cryptoReader) ControlCoreView {
	if !bytes.Equal(r.take(len(controlCorePrefix)), []byte(controlCorePrefix)) {
		r.err = ErrRecord
	}
	v := ControlCoreView{CurrentControlView: CurrentControlView{CurrentControlFields: CurrentControlFields{
		Schema: r.u16(), Profile: r.u16(), DomainID: r.requiredID(), Provider: Family(r.u8()), StoreID: r.requiredID(),
		CoordinateID: r.requiredID(), NonBodyID: r.requiredID(), TrustInterpretationID: r.requiredID(), CompatibilityID: r.requiredID(),
		CryptoSupportID: r.requiredID(), AuthorityRecipientID: r.requiredID(), AccessIncarnationID: r.requiredID(), AccessGeneration: r.u64()}}}
	v.NormalSigning = readPublicSigningBindingBlob(r)
	v.AuthorityKMSBinding = readKMSBindingBlob(r)
	v.Recovery = readRecoveryBindings(r)
	if r.err == nil {
		_, r.err = controlCoreShapeLength(v.input(), kmsViewInput(v.AuthorityKMSBinding))
	}
	return v
}
func AppendControlCore(dst []byte, v ControlCore) ([]byte, error) {
	if _, err := ControlCoreLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeControlCore(&w, currentControlInputOf(v.CurrentControl), kmsBindingInput{value: v.AuthorityKMSBinding})
	return w.b, nil
}
func EncodeControlCore(v ControlCore) ([]byte, error) {
	n, err := ControlCoreLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeControlCore(&w, currentControlInputOf(v.CurrentControl), kmsBindingInput{value: v.AuthorityKMSBinding})
	return w.b, nil
}
func parseControlCore(b []byte, complete bool) (ControlCoreView, int, error) {
	if complete && len(b) > controlCoreMaxLength {
		return ControlCoreView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), controlCoreMaxLength)])
	v := readControlCore(&r)
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return ControlCoreView{}, 0, r.failure()
	}
	if err := controlCoreKeysError(v.input(), kmsViewInput(v.AuthorityKMSBinding)); err != nil {
		return ControlCoreView{}, 0, err
	}
	return v, r.i, nil
}
func ParseControlCore(b []byte) (ControlCoreView, int, error) { return parseControlCore(b, false) }
func InspectControlCore(b []byte) (ControlCoreView, error) {
	v, _, err := parseControlCore(b, true)
	return v, err
}
func (v ControlCoreView) Own() (ControlCore, error) {
	c, k := v.input(), kmsViewInput(v.AuthorityKMSBinding)
	if _, err := controlCoreShapeLength(c, k); err != nil {
		return ControlCore{}, err
	}
	if err := controlCoreKeysError(c, k); err != nil {
		return ControlCore{}, err
	}
	return ControlCore{CurrentControl: c.own(), AuthorityKMSBinding: k.own()}, nil
}
func DecodeControlCore(b []byte) (ControlCore, error) {
	v, err := InspectControlCore(b)
	if err != nil {
		return ControlCore{}, err
	}
	return ControlCore{CurrentControl: v.input().own(), AuthorityKMSBinding: kmsViewInput(v.AuthorityKMSBinding).own()}, nil
}
func ControlCoreDigest(v ControlCore) (ID, error) {
	if _, err := ControlCoreLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter("")
	writeControlCore(&w, currentControlInputOf(v.CurrentControl), kmsBindingInput{value: v.AuthorityKMSBinding})
	return w.result(0).Digest, nil
}
