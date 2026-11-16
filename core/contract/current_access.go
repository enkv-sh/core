package contract

const (
	currentAccessPrefix           = cryptoPurposePrefix + "current-access\x00"
	accessRecordsPrefix           = cryptoPurposePrefix + "access-records\x00"
	accessRecordsFixedLength      = len(accessRecordsPrefix) + 32 + 4
	currentAccessCoreFixedLength  = 396
	currentAccessCoreMaxLength    = currentAccessCoreFixedLength + PublicSigningBindingMaxLength + recoveryBindingsMaxLength + MaxChildPages*RefLength
	currentAccessSectionMaxLength = 4 + currentAccessCoreMaxLength + 32
	AccessPageHeaderLength        = 75
)

type CurrentAccessCore struct {
	CurrentControl
	RecipientRefsDescriptor DescriptorVector
	AccessPageRefs          []Ref
	AccessRecordsDescriptor DescriptorVector
}

// CurrentAccessCoreView borrows key and complete Ref spans from unchanged input.
// It supplies public structure, not current binding or child authentication.
type CurrentAccessCoreView struct {
	CurrentControlView
	RecipientRefsDescriptor DescriptorVector
	AccessPageRefs          []byte
	AccessRecordsDescriptor DescriptorVector
}

type CurrentAccessSection struct {
	Core       CurrentAccessCore
	AccessRoot ID
}

type CurrentAccessSectionView struct {
	Core       CurrentAccessCoreView
	AccessRoot ID
}

func (v CurrentAccessCoreView) AccessPageCount() int { return len(v.AccessPageRefs) / RefLength }
func (v CurrentAccessCoreView) AccessPage(index int) (Ref, bool) {
	return pageRefAt(v.AccessPageRefs, index)
}

type currentAccessInput struct {
	control             currentControlInput
	recipients, records DescriptorVector
	refs                pageRefs
}

func currentAccessInputOf(v CurrentAccessCore) currentAccessInput {
	return currentAccessInput{control: currentControlInputOf(v.CurrentControl), recipients: v.RecipientRefsDescriptor,
		records: v.AccessRecordsDescriptor, refs: pageRefs{values: v.AccessPageRefs}}
}
func (v CurrentAccessCoreView) input() currentAccessInput {
	return currentAccessInput{control: v.CurrentControlView.input(), recipients: v.RecipientRefsDescriptor,
		records: v.AccessRecordsDescriptor, refs: pageRefs{span: v.AccessPageRefs}}
}

func emptyAccessRecordsDescriptor(domain ID) DescriptorVector {
	w := cryptoHashWriter(accessRecordsPrefix)
	w.id(domain)
	w.u32(0)
	return w.result(0)
}

func (v currentAccessInput) descriptorError() error {
	pages, n := uint64(v.refs.count()), uint64(v.records.Count)
	if n == 0 {
		if pages != 0 || v.records.Length != uint64(accessRecordsFixedLength) {
			return ErrRecord
		}
		if v.records != emptyAccessRecordsDescriptor(v.control.fields.DomainID) {
			return ErrRecord
		}
		return nil
	}
	if pages == 0 || pages > n {
		return ErrRecord
	}
	base := uint64(accessRecordsFixedLength) + (4+AccessRecordFixedLength)*n
	if v.records.Length < base {
		return ErrRecord
	}
	wrapBytes := v.records.Length - base
	if wrapBytes%WrapRowWireLength != 0 {
		return ErrRecord
	}
	mode := uint64(0)
	if v.control.recovery {
		mode = 1
	}
	wraps := wrapBytes / WrapRowWireLength
	if wraps < (1+mode)*n || wraps > (ordinaryValueWrapLimit+mode)*n {
		return ErrRecord
	}
	minimumRecord := uint64(AccessRecordFixedLength) + WrapRowWireLength*(1+mode)
	maximumRecord := uint64(AccessRecordFixedLength) + WrapRowWireLength*(ordinaryValueWrapLimit+mode)
	var payloadSum, minimumCount, maximumCount, residueSum uint64
	err := v.refs.walk(func(_ int, row Ref) error {
		if row.Length <= AccessPageHeaderLength {
			return ErrRecord
		}
		payload := uint64(row.Length - AccessPageHeaderLength)
		// 102*c + 489*w = payload fixes c modulo 163. Keep whole
		// record counts per page; an aggregate byte range alone is insufficient.
		if payload%3 != 0 {
			return ErrRecord
		}
		lower := max(uint64(1), (payload+maximumRecord-1)/maximumRecord)
		upper := min(uint64(AccessPageRecordLimit), payload/minimumRecord)
		residue := (24 * (payload / 3)) % 163
		lower += (residue + 163 - lower%163) % 163
		step := (upper%163 + 163 - residue) % 163
		if step > upper {
			return ErrRecord
		}
		upper -= step
		if lower > upper {
			return ErrRecord
		}
		payloadSum += payload
		minimumCount += lower
		maximumCount += upper
		residueSum += residue
		return nil
	})
	if err != nil {
		return err
	}
	if v.records.Length != uint64(accessRecordsFixedLength)+4*n+payloadSum || n < minimumCount || n > maximumCount || n%163 != residueSum%163 {
		return ErrRecord
	}
	return nil
}

func (v currentAccessInput) shapeLength() (int, error) {
	if len(v.refs.values) > MaxChildPages || len(v.refs.span) > MaxChildPages*RefLength || v.recipients.Count > MaxRecipientPages {
		return 0, ErrRecordCapacity
	}
	if v.recipients.Count == 0 || v.recipients.Length != uint64(recipientRefsFixedLength)+RefLength*uint64(v.recipients.Count) {
		return 0, ErrRecord
	}
	if uint64(v.recipients.Count)+uint64(v.refs.count()) > MaxChildPages {
		return 0, ErrRecordCapacity
	}
	if err := v.control.shapeError(); err != nil {
		return 0, err
	}
	if err := v.refs.shapeError(AccessKind, v.control.fields.DomainID, MaxChildPages); err != nil {
		return 0, err
	}
	if err := v.descriptorError(); err != nil {
		return 0, err
	}
	return currentAccessCoreFixedLength + v.control.normal.length() + v.control.recoveryLength() + RefLength*v.refs.count(), nil
}
func (v currentAccessInput) length() (int, error) {
	n, err := v.shapeLength()
	if err != nil {
		return 0, err
	}
	if err := v.control.keysError(); err != nil {
		return 0, err
	}
	return n, nil
}
func (v currentAccessInput) own() (CurrentAccessCore, error) {
	refs, err := v.refs.own()
	if err != nil {
		return CurrentAccessCore{}, err
	}
	return CurrentAccessCore{CurrentControl: v.control.own(), RecipientRefsDescriptor: v.recipients,
		AccessPageRefs: refs, AccessRecordsDescriptor: v.records}, nil
}

func writeCurrentAccessCore(w *cryptoWriter, v currentAccessInput) error {
	f := v.control.fields
	w.u16(f.Schema)
	w.u16(f.Profile)
	w.id(f.CryptoSupportID)
	w.id(f.CompatibilityID)
	w.id(f.DomainID)
	w.u8(uint8(f.Provider))
	for _, id := range []ID{f.StoreID, f.CoordinateID, f.NonBodyID, f.TrustInterpretationID, f.AuthorityRecipientID} {
		w.id(id)
	}
	w.id(f.AccessIncarnationID)
	w.u64(f.AccessGeneration)
	v.control.normal.writeBlob(w)
	writeRecoveryBindings(w, v.control)
	w.descriptor(v.recipients)
	w.u16(uint16(v.refs.count()))
	if err := v.refs.write(w); err != nil {
		return err
	}
	w.descriptor(v.records)
	return nil
}
func readCurrentAccessCore(r *cryptoReader) CurrentAccessCoreView {
	v := CurrentAccessCoreView{CurrentControlView: CurrentControlView{CurrentControlFields: CurrentControlFields{
		Schema: r.u16(), Profile: r.u16(), CryptoSupportID: r.requiredID(), CompatibilityID: r.requiredID(), DomainID: r.requiredID(),
		Provider: Family(r.u8()), StoreID: r.requiredID(), CoordinateID: r.requiredID(), NonBodyID: r.requiredID(),
		TrustInterpretationID: r.requiredID(), AuthorityRecipientID: r.requiredID(), AccessIncarnationID: r.requiredID(), AccessGeneration: r.u64()}}}
	v.NormalSigning = readPublicSigningBindingBlob(r)
	v.Recovery = readRecoveryBindings(r)
	v.RecipientRefsDescriptor = r.descriptor()
	n := int(r.u16())
	if r.err != nil {
		return v
	}
	if n > MaxChildPages {
		r.err = ErrRecordCapacity
		return v
	}
	v.AccessPageRefs = r.take(n * RefLength)
	v.AccessRecordsDescriptor = r.descriptor()
	if r.err == nil {
		_, r.err = v.input().shapeLength()
	}
	return v
}
func readCurrentAccessCoreBlob(r *cryptoReader) CurrentAccessCoreView {
	b := r.blob(currentAccessCoreMaxLength)
	if r.err != nil {
		return CurrentAccessCoreView{}
	}
	nested := r.child(b)
	v := readCurrentAccessCore(&nested)
	if err := nested.end(); err != nil {
		r.err = err
		return CurrentAccessCoreView{}
	}
	return v
}

func CurrentAccessCoreLength(v CurrentAccessCore) (int, error) {
	return currentAccessInputOf(v).length()
}
func AppendCurrentAccessCore(dst []byte, v CurrentAccessCore) ([]byte, error) {
	x := currentAccessInputOf(v)
	if _, err := x.length(); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	if err := writeCurrentAccessCore(&w, x); err != nil {
		return nil, err
	}
	return w.b, nil
}
func EncodeCurrentAccessCore(v CurrentAccessCore) ([]byte, error) {
	x := currentAccessInputOf(v)
	n, err := x.length()
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	if err := writeCurrentAccessCore(&w, x); err != nil {
		return nil, err
	}
	return w.b, nil
}
func parseCurrentAccessCore(b []byte, complete bool) (CurrentAccessCoreView, int, error) {
	if complete && len(b) > currentAccessCoreMaxLength {
		return CurrentAccessCoreView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), currentAccessCoreMaxLength)])
	v := readCurrentAccessCore(&r)
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return CurrentAccessCoreView{}, 0, r.failure()
	}
	if err := v.CurrentControlView.input().keysError(); err != nil {
		return CurrentAccessCoreView{}, 0, err
	}
	return v, r.i, nil
}
func ParseCurrentAccessCore(b []byte) (CurrentAccessCoreView, int, error) {
	return parseCurrentAccessCore(b, false)
}
func InspectCurrentAccessCore(b []byte) (CurrentAccessCoreView, error) {
	v, _, err := parseCurrentAccessCore(b, true)
	return v, err
}
func (v CurrentAccessCoreView) Own() (CurrentAccessCore, error) {
	x := v.input()
	if _, err := x.length(); err != nil {
		return CurrentAccessCore{}, err
	}
	return x.own()
}
func DecodeCurrentAccessCore(b []byte) (CurrentAccessCore, error) {
	v, err := InspectCurrentAccessCore(b)
	if err != nil {
		return CurrentAccessCore{}, err
	}
	return v.input().own()
}

func writeAccessRootPreimage(w *cryptoWriter, v currentAccessInput, coreLength int) error {
	w.raw([]byte(currentAccessPrefix))
	w.u32(uint32(coreLength))
	return writeCurrentAccessCore(w, v)
}
func accessRoot(v currentAccessInput, coreLength int) (ID, error) {
	w := cryptoHashWriter("")
	if err := writeAccessRootPreimage(&w, v, coreLength); err != nil {
		return ID{}, err
	}
	return w.result(0).Digest, nil
}
func AccessRoot(v CurrentAccessCore) (ID, error) {
	x := currentAccessInputOf(v)
	n, err := x.length()
	if err != nil {
		return ID{}, err
	}
	return accessRoot(x, n)
}

func currentAccessSectionLength(v currentAccessInput, root ID) (int, error) {
	n, err := v.shapeLength()
	if err != nil {
		return 0, err
	}
	digest, err := accessRoot(v, n)
	if err != nil {
		return 0, err
	}
	if digest != root {
		return 0, ErrRecord
	}
	if err := v.control.keysError(); err != nil {
		return 0, err
	}
	return 4 + n + 32, nil
}
func CurrentAccessSectionLength(v CurrentAccessSection) (int, error) {
	return currentAccessSectionLength(currentAccessInputOf(v.Core), v.AccessRoot)
}
func writeCurrentAccessSection(w *cryptoWriter, v currentAccessInput, root ID, coreLength int) error {
	w.u32(uint32(coreLength))
	if err := writeCurrentAccessCore(w, v); err != nil {
		return err
	}
	w.id(root)
	return nil
}
func AppendCurrentAccessSection(dst []byte, v CurrentAccessSection) ([]byte, error) {
	n, err := CurrentAccessSectionLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	if err := writeCurrentAccessSection(&w, currentAccessInputOf(v.Core), v.AccessRoot, n-36); err != nil {
		return nil, err
	}
	return w.b, nil
}
func EncodeCurrentAccessSection(v CurrentAccessSection) ([]byte, error) {
	n, err := CurrentAccessSectionLength(v)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	if err := writeCurrentAccessSection(&w, currentAccessInputOf(v.Core), v.AccessRoot, n-36); err != nil {
		return nil, err
	}
	return w.b, nil
}
func parseCurrentAccessSection(b []byte, complete bool) (CurrentAccessSectionView, int, error) {
	if complete && len(b) > currentAccessSectionMaxLength {
		return CurrentAccessSectionView{}, 0, ErrRecordCapacity
	}
	r := newRecordReader(b[:min(len(b), currentAccessSectionMaxLength)])
	v := CurrentAccessSectionView{Core: readCurrentAccessCoreBlob(&r), AccessRoot: r.id()}
	if complete {
		r.err = r.end()
	}
	if r.err != nil {
		return CurrentAccessSectionView{}, 0, r.failure()
	}
	if _, err := currentAccessSectionLength(v.Core.input(), v.AccessRoot); err != nil {
		return CurrentAccessSectionView{}, 0, err
	}
	return v, r.i, nil
}
func ParseCurrentAccessSection(b []byte) (CurrentAccessSectionView, int, error) {
	return parseCurrentAccessSection(b, false)
}
func InspectCurrentAccessSection(b []byte) (CurrentAccessSectionView, error) {
	v, _, err := parseCurrentAccessSection(b, true)
	return v, err
}
func (v CurrentAccessSectionView) Own() (CurrentAccessSection, error) {
	x := v.Core.input()
	if _, err := currentAccessSectionLength(x, v.AccessRoot); err != nil {
		return CurrentAccessSection{}, err
	}
	core, err := x.own()
	if err != nil {
		return CurrentAccessSection{}, err
	}
	return CurrentAccessSection{Core: core, AccessRoot: v.AccessRoot}, nil
}
func DecodeCurrentAccessSection(b []byte) (CurrentAccessSection, error) {
	v, err := InspectCurrentAccessSection(b)
	if err != nil {
		return CurrentAccessSection{}, err
	}
	core, err := v.Core.input().own()
	if err != nil {
		return CurrentAccessSection{}, err
	}
	return CurrentAccessSection{Core: core, AccessRoot: v.AccessRoot}, nil
}
