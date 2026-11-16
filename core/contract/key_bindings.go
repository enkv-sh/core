package contract

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"strconv"
	"strings"
)

const (
	MaxKeySelector                         = 1024
	KMSPublicKeyLength                     = 422
	kmsBindingFixedLength                  = 32 + 32 + 8 + 1 + 2 + 1 + 4 + KMSPublicKeyLength + 32
	KMSBindingMaxLength                    = kmsBindingFixedLength + MaxKeySelector
	publicSigningBindingFixedLength        = 2 + 1 + 1 + 2 + 32 + 4 + 4 + 32 + 4 + BindingSubjectLength
	PublicSigningBindingMaxLength          = publicSigningBindingFixedLength + MaxKeySelector + MaxPublicKey
	PublicSigningBindingSchema      uint16 = CanonicalSchema
	RSAOAEPWrapProfile              uint16 = 2
	P256SigningProfile              uint16 = 1
	HardwareProtection              uint8  = 1
	SoftwareProtection              uint8  = 2
	NormalSigningRole               uint8  = 1
	RecoverySigningRole             uint8  = 2
	publicBindingDigestPrefix              = cryptoPurposePrefix + "binding\x00"
)

// KMSBinding describes one public encryption-key generation. A structurally
// valid binding still needs provider resource admission and state authentication.
type KMSBinding struct {
	BindingID            ID
	BindingIncarnationID ID
	BindingSerial        uint64
	Provider             Family
	WrapProfile          uint16
	ProtectionClass      uint8
	KeySelector          string
	SPKI                 []byte
	Fingerprint          ID
}

// IndependentKMSBindings checks the authority/recovery separation relation.
// Provider permission and state remain provider checks. This relation validates
// the selector syntax needed to prove that the parents are separate.
func IndependentKMSBindings(a, b KMSBinding) bool {
	if !a.Provider.Valid() || a.Provider != b.Provider || a.Fingerprint.IsZero() || b.Fingerprint.IsZero() || a.Fingerprint == b.Fingerprint || a.KeySelector == b.KeySelector {
		return false
	}
	switch a.Provider {
	case GCP:
		ap, aok := parseGCPKMSSelector(a.KeySelector)
		bp, bok := parseGCPKMSSelector(b.KeySelector)
		if !aok || !bok {
			return false
		}
		if ap.location != bp.location || ap.keyRing != bp.keyRing || ap.cryptoKey != bp.cryptoKey {
			return true
		}
		return ap.projectKind == bp.projectKind && ap.project != bp.project
	case AWS:
		_, ak, aok := strings.Cut(a.KeySelector, ":key/")
		_, bk, bok := strings.Cut(b.KeySelector, ":key/")
		return aok && bok && ak != "" && bk != "" && (!strings.HasPrefix(ak, "mrk-") || ak != bk)
	}
	return false
}

type gcpKMSParent struct {
	project, location, keyRing, cryptoKey string
	projectKind                           uint8
}

const (
	gcpProjectID uint8 = iota + 1
	gcpProjectNumber
)

func parseGCPKMSSelector(selector string) (gcpKMSParent, bool) {
	if len(selector) == 0 || len(selector) > MaxKeySelector {
		return gcpKMSParent{}, false
	}
	parts := strings.Split(selector, "/")
	if len(parts) != 10 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" || parts[8] != "cryptoKeyVersions" ||
		!validGCPLocation(parts[3]) || !validGCPKeyID(parts[5]) || !validGCPKeyID(parts[7]) || !canonicalPositiveInt64(parts[9]) {
		return gcpKMSParent{}, false
	}
	kind := gcpProjectKind(parts[1])
	if kind == 0 {
		return gcpKMSParent{}, false
	}
	return gcpKMSParent{project: parts[1], location: parts[3], keyRing: parts[5], cryptoKey: parts[7], projectKind: kind}, true
}

func gcpProjectKind(project string) uint8 {
	if canonicalPositiveInt64(project) {
		return gcpProjectNumber
	}
	if len(project) < 6 || len(project) > 30 || project[0] < 'a' || project[0] > 'z' || !asciiLowerOrDigit(project[len(project)-1]) {
		return 0
	}
	for i := 1; i < len(project)-1; i++ {
		if !asciiLowerOrDigit(project[i]) && project[i] != '-' {
			return 0
		}
	}
	return gcpProjectID
}

func validGCPLocation(location string) bool {
	if len(location) == 0 || location[0] < 'a' || location[0] > 'z' || !asciiLowerOrDigit(location[len(location)-1]) {
		return false
	}
	for i := 1; i < len(location)-1; i++ {
		if !asciiLowerOrDigit(location[i]) && location[i] != '-' {
			return false
		}
	}
	return true
}

func validGCPKeyID(id string) bool {
	if len(id) == 0 || len(id) > 63 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !asciiLowerOrDigit(id[i]) && (id[i] < 'A' || id[i] > 'Z') && id[i] != '_' && id[i] != '-' {
			return false
		}
	}
	return true
}

func asciiLowerOrDigit(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func canonicalPositiveInt64(value string) bool {
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == value
}

// KMSBindingView borrows KeySelector and SPKI. Keep its input unchanged until
// inspection finishes or Own creates a retained value.
type KMSBindingView struct {
	BindingID            ID
	BindingIncarnationID ID
	BindingSerial        uint64
	Provider             Family
	WrapProfile          uint16
	ProtectionClass      uint8
	KeySelector          []byte
	SPKI                 []byte
	Fingerprint          ID
}

func (v KMSBindingView) own() KMSBinding {
	out := v.fields()
	out.KeySelector, out.SPKI = string(v.KeySelector), ownedBytes(v.SPKI)
	return out
}

func (v KMSBindingView) fields() KMSBinding {
	return KMSBinding{BindingID: v.BindingID, BindingIncarnationID: v.BindingIncarnationID, BindingSerial: v.BindingSerial, Provider: v.Provider,
		WrapProfile: v.WrapProfile, ProtectionClass: v.ProtectionClass, SPKI: v.SPKI, Fingerprint: v.Fingerprint}
}

func (v KMSBindingView) Own() (KMSBinding, error) {
	if err := kmsBindingViewShapeError(v); err != nil {
		return KMSBinding{}, err
	}
	if err := ValidatePublicEncryptionKey(v.SPKI, v.Fingerprint); err != nil {
		return KMSBinding{}, err
	}
	return v.own(), nil
}

// The two selector representations share validation without a temporary copy.
// Exact provider resource grammar remains with the provider admission owner.
func keySelectorError[S ~string | ~[]byte](selector S) error {
	if len(selector) > MaxKeySelector {
		return ErrRecordCapacity
	}
	if len(selector) == 0 {
		return ErrRecord
	}
	for i := 0; i < len(selector); i++ {
		if selector[i] > 127 {
			return ErrRecord
		}
	}
	return nil
}

func kmsBindingFieldsValid(id, incarnation ID, serial uint64, provider Family, profile uint16, protection uint8) bool {
	return !id.IsZero() && !incarnation.IsZero() && serial != 0 && provider.Valid() && profile == RSAOAEPWrapProfile &&
		(protection == HardwareProtection || protection == SoftwareProtection)
}

func ValidatePublicEncryptionKey(spki []byte, fingerprint ID) error {
	if len(spki) > KMSPublicKeyLength {
		return ErrRecordCapacity
	}
	if Hash(spki) != fingerprint {
		return ErrRecord
	}
	return ValidateEncryptionPublicKey(spki)
}

func ValidateEncryptionPublicKey(spki []byte) error {
	if len(spki) > KMSPublicKeyLength {
		return ErrRecordCapacity
	}
	if len(spki) != KMSPublicKeyLength {
		return ErrRecord
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return ErrRecord
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N == nil || key.N.Sign() <= 0 || key.N.BitLen() != 3072 || key.N.Bit(0) != 1 || key.E != 65537 {
		return ErrRecord
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonical, spki) {
		return ErrRecord
	}
	return nil
}

func kmsBindingLength(selectorLength int) int {
	return kmsBindingFixedLength + selectorLength
}

func kmsBindingShapeLength(v KMSBinding) (int, error) {
	if len(v.KeySelector) > MaxKeySelector || len(v.SPKI) > KMSPublicKeyLength {
		return 0, ErrRecordCapacity
	}
	if !kmsBindingFieldsValid(v.BindingID, v.BindingIncarnationID, v.BindingSerial, v.Provider, v.WrapProfile, v.ProtectionClass) ||
		len(v.SPKI) != KMSPublicKeyLength || v.Fingerprint.IsZero() {
		return 0, ErrRecord
	}
	if err := keySelectorError(v.KeySelector); err != nil {
		return 0, err
	}
	return kmsBindingLength(len(v.KeySelector)), nil
}

func KMSBindingLength(v KMSBinding) (int, error) {
	n, err := kmsBindingShapeLength(v)
	if err != nil {
		return 0, err
	}
	if err := ValidatePublicEncryptionKey(v.SPKI, v.Fingerprint); err != nil {
		return 0, err
	}
	return n, nil
}

func writeKMSBinding(w *cryptoWriter, v KMSBinding) {
	writeKMSBindingFields(w, v, v.KeySelector)
}

func writeKMSBindingFields[S ~string | ~[]byte](w *cryptoWriter, v KMSBinding, selector S) {
	w.id(v.BindingID)
	w.id(v.BindingIncarnationID)
	w.u64(v.BindingSerial)
	w.u8(uint8(v.Provider))
	w.u16(v.WrapProfile)
	w.u8(v.ProtectionClass)
	w.blob([]byte(selector))
	w.raw(v.SPKI)
	w.id(v.Fingerprint)
}

// Key parsing is deferred until the complete enclosing structure has passed.
func readKMSBinding(r *cryptoReader) KMSBindingView {
	v := KMSBindingView{BindingID: r.requiredID(), BindingIncarnationID: r.requiredID(), BindingSerial: r.u64(), Provider: Family(r.u8()),
		WrapProfile: r.u16(), ProtectionClass: r.u8(), KeySelector: r.blob(MaxKeySelector),
		SPKI: r.take(KMSPublicKeyLength), Fingerprint: r.requiredID()}
	if r.err != nil {
		return v
	}
	if !kmsBindingFieldsValid(v.BindingID, v.BindingIncarnationID, v.BindingSerial, v.Provider, v.WrapProfile, v.ProtectionClass) {
		r.err = ErrRecord
		return v
	}
	r.err = keySelectorError(v.KeySelector)
	return v
}

func writeKMSBindingBlob(w *cryptoWriter, v KMSBinding) {
	w.u32(uint32(kmsBindingLength(len(v.KeySelector))))
	writeKMSBinding(w, v)
}

func readKMSBindingBlob(r *cryptoReader) KMSBindingView {
	b := r.blob(KMSBindingMaxLength)
	if r.err != nil {
		return KMSBindingView{}
	}
	nested := r.child(b)
	v := readKMSBinding(&nested)
	if err := nested.end(); err != nil {
		r.err = err
		return KMSBindingView{}
	}
	v.KeySelector = v.KeySelector[:len(v.KeySelector):len(v.KeySelector)]
	v.SPKI = v.SPKI[:len(v.SPKI):len(v.SPKI)]
	return v
}

func kmsBindingViewShapeError(v KMSBindingView) error {
	if len(v.KeySelector) > MaxKeySelector || len(v.SPKI) > KMSPublicKeyLength {
		return ErrRecordCapacity
	}
	if !kmsBindingFieldsValid(v.BindingID, v.BindingIncarnationID, v.BindingSerial, v.Provider, v.WrapProfile, v.ProtectionClass) ||
		len(v.SPKI) != KMSPublicKeyLength || v.Fingerprint.IsZero() {
		return ErrRecord
	}
	return keySelectorError(v.KeySelector)
}

func AppendKMSBinding(dst []byte, v KMSBinding) ([]byte, error) {
	if _, err := KMSBindingLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeKMSBinding(&w, v)
	return w.b, nil
}

func EncodeKMSBinding(v KMSBinding) ([]byte, error) {
	n, err := KMSBindingLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeKMSBinding(&w, v)
	return w.b, nil
}

func ParseKMSBinding(b []byte) (KMSBindingView, int, error) {
	r := newRecordReader(b)
	v := readKMSBinding(&r)
	if r.err != nil {
		return KMSBindingView{}, 0, r.failure()
	}
	if err := ValidatePublicEncryptionKey(v.SPKI, v.Fingerprint); err != nil {
		return KMSBindingView{}, 0, err
	}
	return v, r.i, nil
}

func InspectKMSBinding(b []byte) (KMSBindingView, error) {
	if len(b) > KMSBindingMaxLength {
		return KMSBindingView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readKMSBinding(&r)
	if err := r.end(); err != nil {
		return KMSBindingView{}, err
	}
	if err := ValidatePublicEncryptionKey(v.SPKI, v.Fingerprint); err != nil {
		return KMSBindingView{}, err
	}
	return v, nil
}

func DecodeKMSBinding(b []byte) (KMSBinding, error) {
	v, err := InspectKMSBinding(b)
	if err != nil {
		return KMSBinding{}, err
	}
	return v.own(), nil
}

func PublicBindingDigest(v KMSBinding) (ID, error) {
	if _, err := KMSBindingLength(v); err != nil {
		return ID{}, err
	}
	w := cryptoHashWriter(publicBindingDigestPrefix)
	writeKMSBindingBlob(&w, v)
	return w.result(0).Digest, nil
}

type PublicSigningBinding struct {
	Schema         uint16
	Role           uint8
	Provider       Family
	SigningProfile uint16
	BindingID      ID
	KeySelector    string
	SPKI           []byte
	Fingerprint    ID
	Binding        BindingSubject
}

// PublicSigningBindingView borrows KeySelector and SPKI. Binding contains only
// fixed value fields; structural success does not establish current trust.
type PublicSigningBindingView struct {
	Schema         uint16
	Role           uint8
	Provider       Family
	SigningProfile uint16
	BindingID      ID
	KeySelector    []byte
	SPKI           []byte
	Fingerprint    ID
	Binding        BindingSubject
}

func (v PublicSigningBindingView) own() PublicSigningBinding {
	out := v.fields()
	out.KeySelector, out.SPKI = string(v.KeySelector), ownedBytes(v.SPKI)
	return out
}

func (v PublicSigningBindingView) fields() PublicSigningBinding {
	return PublicSigningBinding{Schema: v.Schema, Role: v.Role, Provider: v.Provider, SigningProfile: v.SigningProfile,
		BindingID: v.BindingID, SPKI: v.SPKI, Fingerprint: v.Fingerprint, Binding: v.Binding}
}

func (v PublicSigningBindingView) Own() (PublicSigningBinding, error) {
	if err := publicSigningBindingViewShapeError(v); err != nil {
		return PublicSigningBinding{}, err
	}
	if err := ValidatePublicSigningKey(v.SPKI, v.Fingerprint); err != nil {
		return PublicSigningBinding{}, err
	}
	return v.own(), nil
}

func signingBindingFieldsValid(schema uint16, role uint8, provider Family, profile uint16, id, fingerprint ID, binding BindingSubject) bool {
	return schema == PublicSigningBindingSchema && (role == NormalSigningRole || role == RecoverySigningRole) &&
		provider.Valid() && profile == P256SigningProfile && !id.IsZero() && !fingerprint.IsZero() &&
		bindingSubjectValid(binding) && binding.PublicKey == fingerprint
}

func signingBindingShapeError[S ~string | ~[]byte](schema uint16, role uint8, provider Family, profile uint16, id, fingerprint ID, binding BindingSubject, selector S, spkiLength int) error {
	if len(selector) > MaxKeySelector || spkiLength > MaxPublicKey {
		return ErrRecordCapacity
	}
	if spkiLength == 0 || !signingBindingFieldsValid(schema, role, provider, profile, id, fingerprint, binding) {
		return ErrRecord
	}
	return keySelectorError(selector)
}

func publicSigningBindingViewShapeError(v PublicSigningBindingView) error {
	return signingBindingShapeError(v.Schema, v.Role, v.Provider, v.SigningProfile, v.BindingID, v.Fingerprint, v.Binding, v.KeySelector, len(v.SPKI))
}

func ValidatePublicSigningKey(spki []byte, fingerprint ID) error {
	if len(spki) > MaxPublicKey {
		return ErrRecordCapacity
	}
	if Hash(spki) != fingerprint {
		return ErrRecord
	}
	return ValidateSigningPublicKey(spki)
}

func ValidateSigningPublicKey(spki []byte) error {
	_, err := ParseSigningPublicKey(spki)
	return err
}

// ParseSigningPublicKey returns a canonical P-256 verifier. The returned key
// does not borrow spki.
func ParseSigningPublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) > MaxPublicKey {
		return nil, ErrRecordCapacity
	}
	if len(spki) == 0 {
		return nil, ErrRecord
	}
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, ErrRecord
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrRecord
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || !bytes.Equal(canonical, spki) {
		return nil, ErrRecord
	}
	return key, nil
}

func publicSigningBindingShapeLength(v PublicSigningBinding) (int, error) {
	if err := signingBindingShapeError(v.Schema, v.Role, v.Provider, v.SigningProfile, v.BindingID, v.Fingerprint, v.Binding, v.KeySelector, len(v.SPKI)); err != nil {
		return 0, err
	}
	return publicSigningBindingLength(len(v.KeySelector), len(v.SPKI)), nil
}

func publicSigningBindingLength(selectorLength, spkiLength int) int {
	return publicSigningBindingFixedLength + selectorLength + spkiLength
}

func PublicSigningBindingLength(v PublicSigningBinding) (int, error) {
	n, err := publicSigningBindingShapeLength(v)
	if err != nil {
		return 0, err
	}
	if err := ValidatePublicSigningKey(v.SPKI, v.Fingerprint); err != nil {
		return 0, err
	}
	return n, nil
}

func writePublicSigningBinding(w *cryptoWriter, v PublicSigningBinding) {
	writePublicSigningBindingFields(w, v, v.KeySelector)
}

func writePublicSigningBindingFields[S ~string | ~[]byte](w *cryptoWriter, v PublicSigningBinding, selector S) {
	w.u16(v.Schema)
	w.u8(v.Role)
	w.u8(uint8(v.Provider))
	w.u16(v.SigningProfile)
	w.id(v.BindingID)
	w.blob([]byte(selector))
	w.blob(v.SPKI)
	w.id(v.Fingerprint)
	w.u32(BindingSubjectLength)
	writeBindingSubject(w, v.Binding)
}

func readPublicSigningBinding(r *cryptoReader) PublicSigningBindingView {
	v := PublicSigningBindingView{Schema: r.u16(), Role: r.u8(), Provider: Family(r.u8()), SigningProfile: r.u16(),
		BindingID: r.requiredID(), KeySelector: r.blob(MaxKeySelector), SPKI: r.blob(MaxPublicKey), Fingerprint: r.requiredID()}
	subject := r.blob(BindingSubjectLength)
	if r.err != nil {
		return v
	}
	var err error
	v.Binding, err = DecodeBindingSubject(subject)
	if err != nil || !signingBindingFieldsValid(v.Schema, v.Role, v.Provider, v.SigningProfile, v.BindingID, v.Fingerprint, v.Binding) {
		r.err = ErrRecord
		return v
	}
	r.err = keySelectorError(v.KeySelector)
	return v
}

func writePublicSigningBindingBlob(w *cryptoWriter, v PublicSigningBinding) {
	w.u32(uint32(publicSigningBindingLength(len(v.KeySelector), len(v.SPKI))))
	writePublicSigningBinding(w, v)
}

func readPublicSigningBindingBlob(r *cryptoReader) PublicSigningBindingView {
	b := r.blob(PublicSigningBindingMaxLength)
	if r.err != nil {
		return PublicSigningBindingView{}
	}
	nested := r.child(b)
	v := readPublicSigningBinding(&nested)
	if err := nested.end(); err != nil {
		r.err = err
		return PublicSigningBindingView{}
	}
	return v
}

func AppendPublicSigningBinding(dst []byte, v PublicSigningBinding) ([]byte, error) {
	if _, err := PublicSigningBindingLength(v); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writePublicSigningBinding(&w, v)
	return w.b, nil
}

func EncodePublicSigningBinding(v PublicSigningBinding) ([]byte, error) {
	n, err := PublicSigningBindingLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writePublicSigningBinding(&w, v)
	return w.b, nil
}

func ParsePublicSigningBinding(b []byte) (PublicSigningBindingView, int, error) {
	r := newRecordReader(b)
	v := readPublicSigningBinding(&r)
	if r.err != nil {
		return PublicSigningBindingView{}, 0, r.failure()
	}
	if err := ValidatePublicSigningKey(v.SPKI, v.Fingerprint); err != nil {
		return PublicSigningBindingView{}, 0, err
	}
	return v, r.i, nil
}

func InspectPublicSigningBinding(b []byte) (PublicSigningBindingView, error) {
	if len(b) > PublicSigningBindingMaxLength {
		return PublicSigningBindingView{}, ErrRecordCapacity
	}
	r := newRecordReader(b)
	v := readPublicSigningBinding(&r)
	if err := r.end(); err != nil {
		return PublicSigningBindingView{}, err
	}
	if err := ValidatePublicSigningKey(v.SPKI, v.Fingerprint); err != nil {
		return PublicSigningBindingView{}, err
	}
	return v, nil
}

func DecodePublicSigningBinding(b []byte) (PublicSigningBinding, error) {
	v, err := InspectPublicSigningBinding(b)
	if err != nil {
		return PublicSigningBinding{}, err
	}
	return v.own(), nil
}
