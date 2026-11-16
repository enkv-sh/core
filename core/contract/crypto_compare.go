package contract

import "bytes"

const (
	cryptoCurrentRowFixedLength     = 2 + 4 + ValueEntryFixedLength + 32 + CanonicalPayloadOverhead + 4 + AccessRecordFixedLength + WrapRowWireLength
	cryptoSealedInputRowFixedLength = 4 + 4 + SealedInputEnvelopeFixedLength
)

type cryptoCurrentRowView struct {
	slot               uint16
	entryBytes, access []byte
}

type cryptoSealedInputRowView struct{ name, envelopeBytes []byte }

func cryptoReadCurrentRow(r *cryptoReader) cryptoCurrentRowView {
	return cryptoCurrentRowView{slot: r.u16(), entryBytes: r.blob(CryptoMaxValueEntryLength), access: r.blob(accessRecordMaxLength)}
}

func cryptoWriteCurrentRow(w *cryptoWriter, row CryptoCurrentSecret) {
	w.u16(row.Slot)
	w.blob(row.EntryBytes)
	w.blob(row.AccessRecord)
}

func cryptoReadSealedInputRow(r *cryptoReader) cryptoSealedInputRowView {
	return cryptoSealedInputRowView{name: r.name(), envelopeBytes: r.blob(CryptoMaxSealedInputLength)}
}

func cryptoWriteSealedInputRow(w *cryptoWriter, row CryptoSealedInput) {
	w.blob([]byte(row.Name))
	w.blob(row.EnvelopeBytes)
}

type cryptoCurrentTotals struct {
	previous       []byte
	slots          [CryptoMaxValueEntries]bool
	entries        cryptoIntentTotals
	ordinaryWraps  int
	wrapRecipients cryptoRecipientSet
}

func (s *cryptoCurrentTotals) add(row cryptoCurrentRowView, first bool) error {
	facts, err := cryptoValueEntryFacts(row.entryBytes)
	if err != nil {
		return err
	}
	if !cryptoNamesValid(s.previous, facts.name, first) || row.slot >= CryptoMaxValueEntries || s.slots[row.slot] {
		return ErrCryptoMessage
	}
	access, err := InspectAccessRecord(row.access)
	if err != nil {
		return err
	}
	if access.MaterialKind != ValueMaterialKind {
		return ErrCryptoMessage
	}
	if err := s.entries.addRow(facts.raw, len(facts.recipients)/32); err != nil {
		return err
	}
	if err := s.entries.addValueSource(facts.valueSource); err != nil {
		return err
	}
	for i := 0; i < len(facts.recipients); i += 32 {
		if err := s.entries.addRecipient(ID(facts.recipients[i : i+32])); err != nil {
			return err
		}
	}
	for i := 0; i < access.WrapCount(); i++ {
		wrap, ok := access.Wrap(i)
		if !ok {
			return ErrCryptoMessage
		}
		if wrap.SubjectKind == OrdinaryWrapSubject {
			s.ordinaryWraps++
			if s.ordinaryWraps > CryptoMaxMemberships {
				return ErrCryptoCapacity
			}
			if err := s.wrapRecipients.addRecipient(wrap.SubjectID); err != nil {
				return err
			}
		}
	}
	s.slots[row.slot] = true
	s.previous = facts.name
	return nil
}

func cryptoCompareSealedInputFields(c ApplyContext, source cryptoSealedInputRowView, name []byte, row CryptoIntentRow) error {
	v, err := InspectSealedInputEnvelope(source.envelopeBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(source.name, name) || !bytes.Equal(source.name, v.Core.Name) ||
		v.Core.ContentLength != row.ContentLength || v.Core.InputEncoding != row.InputEncoding || v.Core.RetainedLength != row.RetainedLength || len(source.envelopeBytes) != int(row.PayloadLength) ||
		v.Core.DomainID != c.DomainID || v.Core.CompatibilityID != c.CompatibilityID {
		return ErrCryptoMessage
	}
	// Binding-set agreement needs the owner's exact admitted current bindings.
	return nil
}

func cryptoCompareRetainedInputFields(name []byte, row CryptoIntentRow, current cryptoCurrentRowView) error {
	entry, err := InspectValueEntry(current.entryBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(entry.Name, name) || entry.ValueSource != Supplied || entry.ConfidentialityClass != Secret ||
		entry.Incarnation != row.Retained.Incarnation || entry.ValueState != row.Retained.Material ||
		len(entry.ValueBytes) != int(row.PayloadLength) {
		return ErrCryptoMessage
	}
	payload, err := InspectCanonicalPayload(entry.ValueBytes)
	if err != nil {
		return err
	}
	if payload.ContentLength != row.ContentLength || payload.InputEncoding != row.InputEncoding || payload.RetainedLength != row.RetainedLength || Hash(entry.ValueBytes) != row.PayloadDigest {
		return ErrCryptoMessage
	}
	return nil
}

type cryptoCompareLayout struct {
	context                                     ApplyContext
	intent, current, sealedInputs               []byte
	intentCount, currentCount, sealedInputCount int
	bindings                                    BindingTableView
	recipients                                  applyRecipientProjectionView
	completeIntent                              DescriptorVector
	secretAccess                                secretAccessIntentView
	retirement                                  recipientRetirementIntentView
}

func cryptoReadCompare(r *cryptoReader) cryptoCompareLayout {
	var l cryptoCompareLayout
	l.context = r.context()
	if r.err == nil && l.context.OperationClass != CryptoOrdinaryLifecycle {
		r.err = ErrCryptoMessage
	}
	complete, access, retirement := readCompareIntent(r, l.context.DomainID)
	l.secretAccess, l.retirement = access, retirement
	l.intent, l.intentCount = complete.values.Rows, int(complete.values.Descriptor.Count)
	l.recipients, l.completeIntent = complete.recipients, complete.descriptor
	if r.err != nil {
		return l
	}
	l.currentCount = r.count(CryptoMaxValueEntries, cryptoCurrentRowFixedLength)
	start := r.i
	var current cryptoCurrentTotals
	for i := 0; i < l.currentCount && r.err == nil; i++ {
		row := cryptoReadCurrentRow(r)
		if r.err == nil {
			r.err = current.add(row, i == 0)
		}
	}
	l.current = r.b[start:r.i:r.i]
	l.sealedInputCount = r.count(CryptoMaxValueEntries, cryptoSealedInputRowFixedLength)
	if r.err == nil && (l.secretAccess.present || l.retirement.present) && l.sealedInputCount != 0 {
		r.err = ErrCryptoMessage
	}
	start = r.i
	intent := cryptoReader{b: l.intent}
	var previous []byte
	for i := 0; i < l.sealedInputCount && r.err == nil; i++ {
		source := cryptoReadSealedInputRow(r)
		if r.err != nil {
			break
		}
		if !cryptoNamesValid(previous, source.name, i == 0) {
			r.err = ErrCryptoMessage
			break
		}
		previous = source.name
		var row cryptoIntentRowView
		for (row.fields.ConfidentialityClass != Secret || row.fields.ValueSource != Supplied || row.fields.Retained != (RetainedSecretInput{})) && intent.err == nil {
			row = cryptoReadIntentRow(&intent)
		}
		if intent.err != nil {
			r.err = intent.err
			break
		}
		r.err = cryptoCompareSealedInputFields(l.context, source, row.name, row.fields)
	}
	l.sealedInputs = r.b[start:r.i:r.i]
	for intent.i < len(intent.b) && r.err == nil {
		row := cryptoReadIntentRow(&intent)
		if intent.err != nil {
			r.err = intent.err
		} else if row.fields.ConfidentialityClass == Secret && row.fields.ValueSource == Supplied && row.fields.Retained == (RetainedSecretInput{}) {
			r.err = ErrCryptoMessage
		}
	}
	table := r.blob(BindingTableMaxLength)
	if r.err != nil {
		return l
	}
	nested := cryptoReader{b: table}
	l.bindings = readBindingTable(&nested)
	r.err = nested.end()
	return l
}

func (l cryptoCompareLayout) commitmentsError() error {
	if l.completeIntent != l.context.IntentDescriptor {
		return ErrCryptoMessage
	}
	intent, sources, currents := cryptoReader{b: l.intent}, cryptoReader{b: l.sealedInputs}, cryptoReader{b: l.current}
	for i := 0; i < l.intentCount; i++ {
		row := cryptoReadIntentRow(&intent)
		if intent.err != nil {
			return intent.failure()
		}
		if row.fields.Retained != (RetainedSecretInput{}) {
			found := false
			for currents.i < len(currents.b) {
				current := cryptoReadCurrentRow(&currents)
				entry, err := InspectValueEntry(current.entryBytes)
				if currents.err != nil || err != nil {
					return ErrCryptoMessage
				}
				order := bytes.Compare(entry.Name, row.name)
				if order < 0 {
					continue
				}
				if order > 0 {
					return ErrCryptoMessage
				}
				if err := cryptoCompareRetainedInputFields(row.name, row.fields, current); err != nil {
					return err
				}
				found = true
				break
			}
			if !found {
				return ErrCryptoMessage
			}
		}
		if row.fields.ConfidentialityClass == Secret && row.fields.ValueSource == Supplied && row.fields.Retained == (RetainedSecretInput{}) {
			source := cryptoReadSealedInputRow(&sources)
			if sources.err != nil {
				return sources.failure()
			}
			if cryptoSealedInputDigest(source.envelopeBytes) != row.fields.PayloadDigest {
				return ErrCryptoMessage
			}
		}
	}
	if err := sources.end(); err != nil {
		return err
	}
	if err := l.recipients.keysError(); err != nil {
		return err
	}
	return l.bindings.keysError()
}

func cryptoScanCompare(b []byte) (cryptoCompareLayout, error) {
	if len(b) > CryptoRequestLimit-cryptoRequestHeader {
		return cryptoCompareLayout{}, ErrCryptoCapacity
	}
	r := cryptoReader{b: b}
	l := cryptoReadCompare(&r)
	if err := r.end(); err != nil {
		return cryptoCompareLayout{}, err
	}
	if err := l.commitmentsError(); err != nil {
		return cryptoCompareLayout{}, err
	}
	return l, nil
}

func cryptoCompareLengths(q CryptoCompareRequest) (body, table int, err error) {
	if q.Context.OperationClass != CryptoOrdinaryLifecycle {
		return 0, 0, ErrCryptoMessage
	}
	if err := cryptoContextError(q.Context); err != nil {
		return 0, 0, err
	}
	if len(q.Current) > CryptoMaxValueEntries || len(q.SealedInputs) > CryptoMaxValueEntries {
		return 0, 0, ErrCryptoCapacity
	}
	table, err = bindingTableShapeLength(q.Bindings)
	if err != nil {
		return 0, 0, err
	}
	var d DescriptorVector
	if q.SecretAccess != nil && q.Retirement != nil {
		return 0, 0, ErrCryptoMessage
	}
	if q.Retirement != nil {
		if len(q.SealedInputs) != 0 {
			return 0, 0, ErrCryptoMessage
		}
		d, err = RecipientRetirementIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, *q.Retirement)
	} else if q.SecretAccess == nil {
		d, err = CompleteApplyIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients)
	} else {
		if len(q.SealedInputs) != 0 {
			return 0, 0, ErrCryptoMessage
		}
		d, err = SecretAccessIntentDescriptor(q.Context.DomainID, q.Intent, q.Recipients, *q.SecretAccess)
	}
	if err != nil {
		return 0, 0, err
	}
	if d != q.Context.IntentDescriptor {
		return 0, 0, ErrCryptoMessage
	}
	body = cryptoContextBlobLength + int(d.Length) + 3*4 + table
	if body > CryptoRequestLimit-cryptoRequestHeader {
		return 0, 0, ErrCryptoCapacity
	}
	var current cryptoCurrentTotals
	for i, row := range q.Current {
		if err := current.add(cryptoCurrentRowView{row.Slot, row.EntryBytes, row.AccessRecord}, i == 0); err != nil {
			return 0, 0, err
		}
		body += 2 + 4 + len(row.EntryBytes) + 4 + len(row.AccessRecord)
		if body > CryptoRequestLimit-cryptoRequestHeader {
			return 0, 0, ErrCryptoCapacity
		}
	}
	currentIndex := 0
	for _, row := range q.Intent {
		if row.Retained == (RetainedSecretInput{}) {
			continue
		}
		found := false
		for currentIndex < len(q.Current) {
			current := q.Current[currentIndex]
			currentIndex++
			entry, err := InspectValueEntry(current.EntryBytes)
			if err != nil {
				return 0, 0, err
			}
			order := bytes.Compare(entry.Name, []byte(row.Name))
			if order < 0 {
				continue
			}
			if order > 0 {
				return 0, 0, ErrCryptoMessage
			}
			if err := cryptoCompareRetainedInputFields([]byte(row.Name), row, cryptoCurrentRowView{current.Slot, current.EntryBytes, current.AccessRecord}); err != nil {
				return 0, 0, err
			}
			found = true
			break
		}
		if !found {
			return 0, 0, ErrCryptoMessage
		}
	}
	j := 0
	for i, source := range q.SealedInputs {
		if len(source.Name) > CryptoMaxName {
			return 0, 0, ErrCryptoCapacity
		}
		if !cryptoNamesValid(nil, []byte(source.Name), true) || i > 0 && q.SealedInputs[i-1].Name >= source.Name {
			return 0, 0, ErrCryptoMessage
		}
		for j < len(q.Intent) && (q.Intent[j].ConfidentialityClass != Secret || q.Intent[j].ValueSource != Supplied || q.Intent[j].Retained != (RetainedSecretInput{})) {
			j++
		}
		if j == len(q.Intent) {
			return 0, 0, ErrCryptoMessage
		}
		row := q.Intent[j]
		j++
		if err := cryptoCompareSealedInputFields(q.Context, cryptoSealedInputRowView{[]byte(source.Name), source.EnvelopeBytes}, []byte(row.Name), row); err != nil {
			return 0, 0, err
		}
		if cryptoSealedInputDigest(source.EnvelopeBytes) != row.PayloadDigest {
			return 0, 0, ErrCryptoMessage
		}
		body += 8 + len(source.Name) + len(source.EnvelopeBytes)
		if body > CryptoRequestLimit-cryptoRequestHeader {
			return 0, 0, ErrCryptoCapacity
		}
	}
	for ; j < len(q.Intent); j++ {
		if q.Intent[j].ConfidentialityClass == Secret && q.Intent[j].ValueSource == Supplied && q.Intent[j].Retained == (RetainedSecretInput{}) {
			return 0, 0, ErrCryptoMessage
		}
	}
	if err := bindingTableKeysError(q.Bindings); err != nil {
		return 0, 0, err
	}
	return body, table, nil
}

func cryptoWriteCompare(w *cryptoWriter, q CryptoCompareRequest, tableLength int) {
	w.context(q.Context)
	value, registry := intentBaseLength, 4
	for _, row := range q.Intent {
		value += intentRowFixedLength + len(row.Name) + 32*len(row.Recipients)
	}
	for _, row := range q.Recipients {
		registry += recipientRecordEncodedLength(row.Recipient) + 1
		if row.Creation != nil {
			registry += 64
		}
	}
	if q.Retirement != nil {
		writeRecipientRetirementIntent(w, q.Context.DomainID, q.Intent, q.Recipients, *q.Retirement, value, registry)
	} else if q.SecretAccess == nil {
		writeCompleteApplyIntent(w, q.Context.DomainID, q.Intent, q.Recipients, value, registry)
	} else {
		writeSecretAccessIntent(w, q.Context.DomainID, q.Intent, q.Recipients, *q.SecretAccess, value, registry)
	}
	w.u32(uint32(len(q.Current)))
	for _, row := range q.Current {
		cryptoWriteCurrentRow(w, row)
	}
	w.u32(uint32(len(q.SealedInputs)))
	for _, row := range q.SealedInputs {
		cryptoWriteSealedInputRow(w, row)
	}
	w.u32(uint32(tableLength))
	writeBindingTable(w, q.Bindings)
}

func AppendCryptoCompareRequest(dst []byte, q CryptoCompareRequest) ([]byte, error) {
	_, tableLength, err := cryptoCompareLengths(q)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	cryptoWriteCompare(&w, q, tableLength)
	return w.b, nil
}

func EncodeCryptoCompareRequest(q CryptoCompareRequest) ([]byte, error) {
	size, tableLength, err := cryptoCompareLengths(q)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, size)}
	cryptoWriteCompare(&w, q, tableLength)
	return w.b, nil
}

// CryptoCompareRequestView borrows one complete body. Keep its input unchanged
// until inspection ends or Own has copied the retained records and bindings.
type CryptoCompareRequestView struct {
	body   []byte
	layout cryptoCompareLayout
}

func (v CryptoCompareRequestView) Context() ApplyContext      { return v.layout.context }
func (v CryptoCompareRequestView) IntentCount() int           { return v.layout.intentCount }
func (v CryptoCompareRequestView) CurrentCount() int          { return v.layout.currentCount }
func (v CryptoCompareRequestView) SealedInputCount() int      { return v.layout.sealedInputCount }
func (v CryptoCompareRequestView) Bindings() BindingTableView { return v.layout.bindings }

func ParseCryptoCompareRequest(b []byte) (CryptoCompareRequestView, int, error) {
	limit := min(len(b), CryptoRequestLimit-cryptoRequestHeader)
	r := cryptoReader{b: b[:limit:limit]}
	l := cryptoReadCompare(&r)
	if r.err != nil {
		return CryptoCompareRequestView{}, 0, r.failure()
	}
	if err := l.commitmentsError(); err != nil {
		return CryptoCompareRequestView{}, 0, err
	}
	return CryptoCompareRequestView{body: b[:r.i:r.i], layout: l}, r.i, nil
}

func InspectCryptoCompareRequest(b []byte) (CryptoCompareRequestView, error) {
	l, err := cryptoScanCompare(b)
	if err != nil {
		return CryptoCompareRequestView{}, err
	}
	return CryptoCompareRequestView{body: b[:len(b):len(b)], layout: l}, nil
}

func (l cryptoCompareLayout) own() CryptoCompareRequest {
	q := CryptoCompareRequest{Context: l.context, Intent: cryptoOwnIntentRows(l.intent, l.intentCount), Recipients: l.recipients.own(), SecretAccess: l.secretAccess.own(), Retirement: l.retirement.own(),
		Current: make([]CryptoCurrentSecret, l.currentCount), SealedInputs: make([]CryptoSealedInput, l.sealedInputCount), Bindings: l.bindings.own()}
	r := cryptoReader{b: l.current}
	for i := range q.Current {
		row := cryptoReadCurrentRow(&r)
		q.Current[i] = CryptoCurrentSecret{Slot: row.slot, EntryBytes: ownedBytes(row.entryBytes), AccessRecord: ownedBytes(row.access)}
	}
	r = cryptoReader{b: l.sealedInputs}
	for i := range q.SealedInputs {
		row := cryptoReadSealedInputRow(&r)
		q.SealedInputs[i] = CryptoSealedInput{Name: string(row.name), EnvelopeBytes: ownedBytes(row.envelopeBytes)}
	}
	return q
}

func (v CryptoCompareRequestView) Own() (CryptoCompareRequest, error) {
	l, err := cryptoScanCompare(v.body)
	if err != nil {
		return CryptoCompareRequest{}, err
	}
	return l.own(), nil
}

func DecodeCryptoCompareRequest(b []byte) (CryptoCompareRequest, error) {
	l, err := cryptoScanCompare(b)
	if err != nil {
		return CryptoCompareRequest{}, err
	}
	return l.own(), nil
}
