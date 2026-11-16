package contract

// PreservedStateProjection traverses each complete current and retained record once. Its
// omissions are the exact authority/recovery KEK fields named by the closed
// change mask. Core normalizes snapshot-owned location carriers before this
// walk. The enclosing succession checks before/after control and locations.
type PreservedStateProjection struct {
	w                                       cryptoWriter
	domain, authority, recoveryRole         ID
	mask                                    uint8
	expectedEntryCount, recipients, access  uint32
	entryCount, recipientCount, accessCount uint32
	workSupport, workSupportCount           uint32
	lastEntrySlot, lastRecipient            uint16
	lastMaterialKind                        MaterialKind
	lastMaterial                            ID
	lastSupportKind                         SupportRecordKind
	lastSupport                             ID
	authoritySeen                           bool
	failed                                  bool
	rawBytes                                uint64
	recordBytes                             uint64
}

func NewPreservedStateProjection(control ControlCore, mask uint8, entries, recipients, access, workSupport uint32) (*PreservedStateProjection, error) {
	if mask == 0 || mask & ^uint8(SuccessionChangeMask) != 0 || entries > CryptoMaxValueEntries || recipients == 0 || recipients > CryptoMaxRecipients || access > AccessMaterialLimit || workSupport > requiredSupportMaxRecords || control.Recovery == nil && mask&SuccessionChangeRecoveryMask != 0 {
		return nil, ErrRecord
	}
	if _, err := ControlCoreLength(control); err != nil {
		return nil, err
	}
	p := &PreservedStateProjection{w: cryptoHashWriter(cryptoPurposePrefix + "succession-preserved-state-v2\x00"), domain: control.DomainID, authority: control.AuthorityRecipientID, mask: mask, expectedEntryCount: entries, recipients: recipients, access: access, workSupport: workSupport}
	if control.Recovery != nil {
		p.recoveryRole = control.Recovery.RoleID
	}
	w := &p.w
	w.u16(CanonicalSchema)
	w.id(control.DomainID)
	w.u8(mask)
	w.id(control.CryptoSupportID)
	w.id(control.CompatibilityID)
	w.u8(uint8(control.Provider))
	for _, id := range []ID{control.StoreID, control.CoordinateID, control.NonBodyID, control.TrustInterpretationID, control.AuthorityRecipientID} {
		w.id(id)
	}
	if control.Recovery == nil {
		w.u8(0)
	} else {
		w.u8(1)
		w.id(control.Recovery.RoleID)
	}
	w.u16(uint16(entries))
	if entries == 0 {
		w.u16(uint16(recipients))
	}
	return p, nil
}

func (p *PreservedStateProjection) charge(n int) error {
	if n < 0 || p.recordBytes+uint64(n) > uint64(MaxChildPages)*MaxValueEntryPageLength {
		p.failed = true
		return ErrRecordCapacity
	}
	p.recordBytes += uint64(n)
	return nil
}

func (p *PreservedStateProjection) refuse() error {
	if p != nil {
		p.failed = true
	}
	return ErrRecord
}

func (p *PreservedStateProjection) AddValueEntry(slot uint16, row ValueEntry) error {
	if p == nil || p.failed || p.entryCount >= p.expectedEntryCount || slot >= CryptoMaxValueEntries || p.entryCount > 0 && slot <= p.lastEntrySlot {
		return p.refuse()
	}
	n, err := ValueEntryLength(row)
	if err != nil {
		p.failed = true
		return err
	}
	if err := p.charge(n); err != nil {
		return err
	}
	raw := uint64(row.ContentLength)
	if row.ConfidentialityClass == Secret {
		payload, err := InspectCanonicalPayload(row.ValueBytes)
		if err != nil {
			p.failed = true
			return err
		}
		raw = uint64(payload.ContentLength)
	}
	if p.rawBytes+raw > CryptoMaxRawSet {
		p.failed = true
		return ErrRecordCapacity
	}
	p.rawBytes += raw
	p.w.u16(slot)
	p.w.u32(uint32(n))
	writeValueEntry(&p.w, row)
	p.entryCount++
	p.lastEntrySlot = slot
	if p.entryCount == p.expectedEntryCount {
		p.w.u16(uint16(p.recipients))
	}
	return nil
}

func (p *PreservedStateProjection) AddRecipient(slot uint16, row RecipientRecord) error {
	if p == nil || p.failed || p.entryCount != p.expectedEntryCount || p.recipientCount >= p.recipients || slot >= CryptoMaxRecipients || p.recipientCount > 0 && slot <= p.lastRecipient {
		return p.refuse()
	}
	n, err := RecipientRecordLength(row)
	if err != nil {
		p.failed = true
		return err
	}
	if err := p.charge(n); err != nil {
		return err
	}
	if row.RecipientID == p.authority {
		if p.authoritySeen {
			return p.refuse()
		}
		p.authoritySeen = true
		if p.mask&SuccessionChangeAuthorityKEK != 0 {
			row.CurrentBinding = nil
		}
	}
	p.w.u16(slot)
	p.w.u32(uint32(recipientRecordEncodedLength(row)))
	writeRecipientRecord(&p.w, row)
	p.recipientCount++
	p.lastRecipient = slot
	if p.recipientCount == p.recipients {
		if !p.authoritySeen {
			return p.refuse()
		}
		p.w.u32(p.access)
		if p.access == 0 {
			p.w.u32(p.workSupport)
		}
	}
	return nil
}

func (p *PreservedStateProjection) AddAccess(row AccessRecord) error {
	if p == nil || p.failed || p.recipientCount != p.recipients || p.accessCount >= p.access || !replacementMaterialKind(row.MaterialKind) || p.accessCount > 0 && !materialBefore(p.lastMaterialKind, p.lastMaterial, row.MaterialKind, row.MaterialID) {
		return p.refuse()
	}
	length, err := AccessRecordLength(row)
	if err != nil {
		p.failed = true
		return err
	}
	if err := p.charge(length); err != nil {
		return err
	}
	// The retained/current reader union can span the complete registry. These
	// public row views borrow ciphertext and retain no second state image.
	var kept [valueAccessWrapLimit]WrapRow
	n := 0
	for _, wrap := range row.Wraps {
		if p.mask&SuccessionChangeAuthorityKEK != 0 && wrap.SubjectKind == OrdinaryWrapSubject && wrap.SubjectID == p.authority {
			continue
		}
		if p.mask&SuccessionChangeRecoveryKEK != 0 && wrap.SubjectKind == RecoveryWrapSubject && !p.recoveryRole.IsZero() && wrap.SubjectID == p.recoveryRole {
			continue
		}
		kept[n] = wrap
		n++
	}
	row.Wraps = kept[:n]
	writeAccessRecordBlob(&p.w, row)
	p.accessCount++
	p.lastMaterialKind = row.MaterialKind
	p.lastMaterial = row.MaterialID
	if p.accessCount == p.access {
		p.w.u32(p.workSupport)
	}
	return nil
}

func (p *PreservedStateProjection) AddWorkSupport(row SupportRecord) error {
	if p == nil || p.failed || p.recipientCount != p.recipients || p.accessCount != p.access || p.workSupportCount >= p.workSupport || row.Kind == MutationReceiptSupportKind || p.workSupportCount > 0 && !supportRecordBefore(p.lastSupportKind, p.lastSupport, row.Kind, row.RecordID) {
		return p.refuse()
	}
	domain, err := inspectSupportBody(row)
	if err != nil {
		p.failed = true
		return err
	}
	if !domain.IsZero() && domain != p.domain {
		return p.refuse()
	}
	if err := p.charge(SupportRecordOverhead + len(row.Body)); err != nil {
		return err
	}
	writeSupportRecord(&p.w, row.Kind, row.RecordID, len(row.Body), func(w *cryptoWriter) { w.raw(row.Body) })
	p.workSupportCount++
	p.lastSupportKind, p.lastSupport = row.Kind, row.RecordID
	return nil
}

func (p *PreservedStateProjection) Digest() (DigestLength, error) {
	if p == nil || p.failed || p.entryCount != p.expectedEntryCount || p.recipientCount != p.recipients || p.accessCount != p.access || p.workSupportCount != p.workSupport || !p.authoritySeen {
		return DigestLength{}, ErrRecord
	}
	v := p.w.result(0)
	return DigestLength{Digest: v.Digest, Length: v.Length}, nil
}
