package contract

import (
	"bytes"
	"crypto/sha256"
	"slices"

	protocol "enkv.sh/sdk/protocols/generator"
)

// GeneratedSupportTransition contains private predecessor facts. Its structural
// checks do not authenticate a root or grant lifecycle or effect authority.
// Only the existing private parent may install it in an opaque admission.
type GeneratedSupportTransition struct {
	Schema                                     uint16
	DomainID, BeforeSnapshot, BeforeRootDigest ID
	// The authenticated administrative Slice owner can outlive BeforeSnapshot.
	BeforeSliceSnapshot ID
	BeforeSupport       DescriptorVector
	Records             []SupportRecord
	RecordFacts         []SupportRecordDigest
	BeforeAccess        CurrentAccessCore
	AccessRecords       []AccessRecord
	CurrentGenerated    []GeneratedSupportCurrent
	Handoffs            []GeneratedSupportHandoff
	Readers             []GeneratedSupportReaders
	Groups              [GeneratorCapacityGroupCount]GeneratorCapacityGroup
	Output              *NormalOutputTransition
}

type GeneratedSupportCurrent struct {
	Slot           uint16
	EntryBytes     []byte
	EvidenceRecord uint32
	CarrierRecord  uint32
	Intent         GeneratorSliceLocation
	Target         GeneratorTarget
	Proof          GeneratedSupportCurrentProof
}

type GeneratedSupportHandoff struct {
	Current                                     uint16
	Implementation                              GeneratorImplementation
	CompatibilityRequest, CompatibilityResponse []byte
	Support                                     []GeneratorSupportBinding
}

type GeneratedSupportReaders struct {
	Access            uint32
	Current, Retained []ID
	Bindings          []RecipientBindingReference
	Recovery          *RecipientBindingReference
	Consumers         []GeneratorConsumer
}

// GeneratedSupportRows keeps each inspected row fact in the same position as
// its support record. Only an authenticated predecessor fragment may have an
// absent Body; its exact digest and length remain present in Facts.
type GeneratedSupportRows struct {
	Records []SupportRecord
	Facts   []SupportRecordDigest
}

func GeneratedResultContractID(row GeneratorImplementation, action, completion uint8, maxValue, maxFacts uint32, inputEncoding uint8) (ID, error) {
	return GeneratedResultContractForReader(row, action, completion, maxValue, maxFacts, inputEncoding, GeneratorResultReaderFor(action, completion, inputEncoding))
}

// GeneratedResultContractForReader also qualifies retained work against its original reader.
func GeneratedResultContractForReader(row GeneratorImplementation, action, completion uint8, maxValue, maxFacts uint32, inputEncoding uint8, reader ID) (ID, error) {
	if reader != GeneratorResultReaderID() && reader != GeneratorResultReaderFor(action, completion, inputEncoding) {
		return ID{}, ErrRecord
	}
	if (inputEncoding != InputEncodingRaw && inputEncoding != InputEncodingBase64) || action == GeneratorActionDelete && inputEncoding != InputEncodingRaw || row.Validate() != nil || action < GeneratorActionCreate || action > GeneratorActionDelete || maxValue > CryptoMaxRawValue || maxFacts == 0 || maxFacts > GeneratorSafeFactsEnvelopeLength || action == GeneratorActionDelete && (maxValue != 0 || !generatedCompletionValid(completion)) || action == GeneratorActionCreate && (maxValue == 0 || completion != 0 && !generatedCompletionValid(completion)) {
		return ID{}, ErrRecord
	}
	var w cryptoWriter
	w.id(row.DescriptorID)
	w.id(row.ProtocolID)
	w.id(reader)
	w.u8(action)
	w.u8(completion)
	w.u32(maxValue)
	w.u32(maxFacts)
	w.u8(inputEncoding)
	return generatorDigest("result-contract-v4", w.b), nil
}

func generatedReaderIDsValid(ids []ID) bool {
	if len(ids) > CryptoMaxRecipients {
		return false
	}
	for i, id := range ids {
		if id.IsZero() || i > 0 && bytes.Compare(ids[i-1][:], id[:]) >= 0 {
			return false
		}
	}
	return true
}

// Inspect checks all contributor bounds before any owned byte image is made.
func (v *GeneratedSupportTransition) Inspect() error {
	if v == nil || v.Schema != 1 || !publicIDsValid(v.DomainID, v.BeforeSnapshot, v.BeforeSliceSnapshot, v.BeforeRootDigest) || len(v.CurrentGenerated) > GeneratedCurrentEntryLimit || len(v.Handoffs) > GeneratedHandoffLimit || len(v.Readers) != len(v.AccessRecords) {
		return ErrRecord
	}
	if len(v.Records) != len(v.RecordFacts) {
		return ErrRecord
	}
	if v.Output != nil {
		if v.Output.Before.DomainID != v.DomainID || v.Output.Inspect(GeneratedSupportRows{v.Records, v.RecordFacts}) != nil {
			return ErrRecord
		}
	}
	for i, row := range v.Records {
		fact := v.RecordFacts[i]
		if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
			return ErrRecord
		}
		if row.Body == nil {
			if row.Kind != GeneratedFragmentSupportKind && row.Kind != OutputConfigurationSliceSupportKind {
				return ErrRecord
			}
			continue
		}
		inspected, err := InspectSupportRecordDigest(v.DomainID, row)
		if err != nil || inspected != fact {
			return ErrRecord
		}
	}
	d, err := RequiredSupportDescriptorFromDigests(v.DomainID, v.RecordFacts)
	if err != nil || d != v.BeforeSupport {
		return ErrRecord
	}
	a, err := AccessRecordsDescriptor(v.DomainID, v.AccessRecords)
	if err != nil || a != v.BeforeAccess.AccessRecordsDescriptor {
		return ErrRecord
	}
	if _, err := AccessRoot(v.BeforeAccess); err != nil {
		return err
	}
	var charge uint64
	for _, fact := range v.RecordFacts {
		charge += uint64(SupportRecordOverhead) + uint64(fact.BodyLength())
	}
	for _, row := range v.AccessRecords {
		n, err := AccessRecordLength(row)
		if err != nil {
			return err
		}
		charge += uint64(n)
	}
	if charge > MaxChildPages*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength) {
		return ErrRecordCapacity
	}
	var previous []byte
	for i, row := range v.CurrentGenerated {
		m, err := InspectValueEntry(row.EntryBytes)
		if err != nil || m.ValueSource != Generated || m.ConfidentialityClass != Secret || row.Slot >= CryptoMaxValueEntries || !cryptoNamesValid(previous, m.Name, i == 0) || row.Intent.Length > GeneratorIntentMaxLength || int(row.EvidenceRecord) >= len(v.Records) || int(row.CarrierRecord) >= len(v.Records) {
			return ErrRecord
		}
		previous = m.Name
		if err := v.currentSupport(m.Generated); err != nil {
			return err
		}
		if !row.Proof.matches(v.DomainID, v.BeforeSliceSnapshot, v.BeforeRootDigest, row,
			v.Records[row.EvidenceRecord], v.Records[row.CarrierRecord]) {
			return ErrRecord
		}
	}
	last := -1
	for _, h := range v.Handoffs {
		if int(h.Current) <= last || int(h.Current) >= len(v.CurrentGenerated) {
			return ErrRecord
		}
		last = int(h.Current)
		m, _ := InspectValueEntry(v.CurrentGenerated[h.Current].EntryBytes)
		r := h.Implementation
		if r.Validate() != nil || m.Generated.LifecycleMode != GeneratorLifecycleManaged || m.Generated.RetiringDutyPresent != 0 {
			return ErrRecord
		}
		request, err := protocol.DecodeRetirementCompatibilityRequest(h.CompatibilityRequest)
		if err != nil {
			return ErrRecord
		}
		response, err := protocol.DecodeValidationResponse(h.CompatibilityResponse)
		if err != nil || !response.Accepted || response.InputDigest != request.InputDigest || request.CompletionClass != m.Generated.CompletionClass {
			return ErrRecord
		}
		intent, err := GeneratorIntentDigest(request.Intent)
		if err != nil || intent != m.Generated.IntentDigest {
			return ErrRecord
		}
		evidence, err := InspectGeneratedCreateEvidence(v.Records[v.CurrentGenerated[h.Current].EvidenceRecord].Body)
		if err != nil {
			return ErrRecord
		}
		original, err := InspectGeneratorSafeFacts(evidence.SafeFacts)
		if err != nil {
			return ErrRecord
		}
		native, err := EncodeNativeGeneratorSafeFacts(original.GeneratorSafeFacts)
		if err != nil || !bytes.Equal(native, request.OriginalFacts) {
			return ErrRecord
		}
		routeFound := false
		for _, binding := range h.Support {
			body, err := EncodeGeneratorSupportBinding(binding)
			if err != nil {
				return err
			}
			charge += uint64(SupportRecordOverhead + GeneratorCarrierFixedLength + len(body))
			if charge > MaxChildPages*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength) {
				return ErrRecordCapacity
			}
			if binding.Role == 7 {
				if routeFound || binding.ImplementationID != r.ExecutorID || binding.PublicBindingDigest != r.CredentialRouteID || !bytes.Equal(binding.Binding, r.CredentialRoute) {
					return ErrRecord
				}
				routeFound = true
			}
		}
		if !routeFound {
			return ErrRecord
		}
		if charge > MaxChildPages*(MaxRequiredSupportPageLength-RequiredSupportPageHeaderLength) {
			return ErrRecordCapacity
		}
	}
	for i, readers := range v.Readers {
		if readers.Access != uint32(i) || !generatedReaderIDsValid(readers.Current) || !generatedReaderIDsValid(readers.Retained) || len(readers.Consumers) > len(v.Records) {
			return ErrRecord
		}
		row := v.AccessRecords[i]
		ids := slices.Concat(readers.Current, readers.Retained)
		slices.SortFunc(ids, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
		ids = slices.Compact(ids)
		if len(ids) > CryptoMaxRecipients || len(readers.Bindings) != len(ids) || len(row.Wraps) != len(ids)+int(boolU8(readers.Recovery != nil)) {
			return ErrRecord
		}
		for j, id := range ids {
			w := row.Wraps[j]
			if w.SubjectKind != OrdinaryWrapSubject || w.SubjectID != id || readers.Bindings[j].RecipientID != id || readers.Bindings[j].PublicBindingDigest != w.PublicBindingDigest {
				return ErrRecord
			}
		}
		if readers.Recovery != nil {
			w := row.Wraps[len(ids)]
			if w.SubjectKind != RecoveryWrapSubject || w.SubjectID != readers.Recovery.RecipientID || w.PublicBindingDigest != readers.Recovery.PublicBindingDigest {
				return ErrRecord
			}
		}
		for _, c := range readers.Consumers {
			if _, err := EncodeGeneratorConsumer(c); err != nil || c.MaterialID != row.MaterialID {
				return ErrRecord
			}
		}
		if row.MaterialKind == ValueMaterialKind && (len(readers.Retained) != 0 || len(readers.Consumers) != 0) {
			if len(readers.Consumers) == 0 {
				return ErrRecord
			}
			sources := make(map[ID]bool)
			var retained []ID
			for _, consumer := range readers.Consumers {
				k := slices.IndexFunc(v.Records, func(r SupportRecord) bool {
					return r.Kind == RetainedCanonicalSupportKind && r.RecordID == consumer.SubjectID
				})
				if k < 0 {
					return ErrRecord
				}
				canonical, err := DecodeRetainedCanonicalRecord(v.Records[k].Body)
				if err != nil || canonical.Entry.ValueState != row.MaterialID {
					return ErrRecord
				}
				sources[consumer.SubjectID] = true
				retained = append(retained, canonical.Entry.Recipients...)
			}
			slices.SortFunc(retained, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
			if !slices.Equal(slices.Compact(retained), readers.Retained) {
				return ErrRecord
			}
			var actual []GeneratorConsumer
			for _, r := range v.Records {
				if r.Kind != GeneratorVectorSupportKind {
					continue
				}
				carrier, err := InspectGeneratorVectorCarrier(r.Body)
				if err != nil {
					return err
				}
				if carrier.VectorKind != GeneratorVectorConsumers {
					continue
				}
				consumer, err := InspectGeneratorConsumer(carrier.Row)
				if err != nil {
					return err
				}
				if consumer.SubjectKind == GeneratorConsumerRetainedCanonicalValue && consumer.MaterialID == row.MaterialID {
					if consumer.OwnerID != carrier.OwnerID || !sources[consumer.SubjectID] || consumer.Purpose != GeneratorConsumerUseRetainedCanonical || consumer.ContextDigest != row.MaterialContextDigest {
						return ErrRecord
					}
					actual = append(actual, consumer)
				}
			}
			if len(actual) != len(readers.Consumers) {
				return ErrRecord
			}
			for _, consumer := range readers.Consumers {
				j := slices.Index(actual, consumer)
				if j < 0 {
					return ErrRecord
				}
				actual = slices.Delete(actual, j, j+1)
			}
		}
	}
	return nil
}

// A detached Duty keeps the original operation's exact support vector. Check
// carrier identity and all ordinal/digest joins before that vector is reused.
func (v *GeneratedSupportTransition) currentSupport(entryMetadata GeneratedEntryMetadata) error {
	descriptor := entryMetadata.RequiredSupport
	if !GeneratorVectorShapeValid(GeneratorVectorSupport, descriptor) || uint64(descriptor.Count) > uint64(len(v.Records)) {
		return ErrRecord
	}
	if descriptor.Count == 0 {
		return nil
	}
	var carriers []GeneratorVectorCarrier
	for _, row := range v.Records {
		if row.Kind != GeneratorVectorSupportKind {
			continue
		}
		carrier, err := InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return err
		}
		if carrier.OwnerKind != GeneratedParentSupportKind || carrier.OwnerID != entryMetadata.OriginOperationID || carrier.VectorKind != GeneratorVectorSupport || carrier.Vector != descriptor {
			continue
		}
		id, err := GeneratorVectorCarrierID(carrier)
		if err != nil || id != row.RecordID || carrier.DomainID != v.DomainID {
			return ErrRecord
		}
		carriers = append(carriers, carrier)
	}
	if uint64(len(carriers)) != uint64(descriptor.Count) {
		return ErrRecord
	}
	slices.SortFunc(carriers, func(a, b GeneratorVectorCarrier) int { return int(a.Ordinal) - int(b.Ordinal) })
	rows := make([][]byte, len(carriers))
	for i, carrier := range carriers {
		if carrier.Ordinal != uint32(i) {
			return ErrRecord
		}
		rows[i] = carrier.Row
	}
	actual, err := GeneratorVectorDescriptor(GeneratorVectorSupport, rows)
	if err != nil || actual != descriptor {
		return ErrRecord
	}
	return nil
}

// InspectGeneratedImmutableSlice borrows immutable selected backing. A crossing
// uses one serial, explicitly bounded scratch image; it grants no authority.
func InspectGeneratedImmutableSlice(domain, snapshot ID, records []SupportRecord, location GeneratorSliceLocation, limit uint32) ([]byte, error) {
	if domain.IsZero() || snapshot.IsZero() || !location.valid() || location.Length > limit {
		return nil, ErrRecord
	}
	v, err := inspectGeneratedImmutableSlice(domain, snapshot, records, location)
	if err != nil {
		return nil, err
	}
	return v.span(0, location.Length)
}

type generatedImmutableSlice struct {
	location  GeneratorSliceLocation
	fragments []GeneratedFragmentView
	scratch   []byte
}

func inspectGeneratedImmutableSlice(domain, snapshot ID, records []SupportRecord, location GeneratorSliceLocation) (*generatedImmutableSlice, error) {
	if domain.IsZero() || snapshot.IsZero() || !location.valid() {
		return nil, ErrRecord
	}
	found := false
	var fragments []GeneratedFragmentView
	for _, row := range records {
		if row.Kind == GeneratorVectorSupportKind {
			c, err := InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return nil, err
			}
			if c.VectorKind == GeneratorVectorSlices {
				l, err := InspectGeneratorSliceLocation(c.Row)
				if err != nil {
					return nil, err
				}
				if l == location {
					id, err := GeneratorVectorCarrierID(c)
					if err != nil || id != row.RecordID || c.DomainID != domain || c.OwnerKind != GeneratorSnapshotOwner || c.OwnerID != snapshot || found {
						return nil, ErrRecord
					}
					found = true
				}
			}
		}
		if row.Kind == GeneratedFragmentSupportKind {
			f, err := InspectGeneratedFragment(row.Body)
			if err != nil {
				return nil, err
			}
			if f.BlobID == location.BlobID {
				id, err := GeneratorFragmentID(f.BlobID, f.Index)
				if err != nil || id != row.RecordID {
					return nil, ErrRecord
				}
				fragments = append(fragments, f)
			}
		}
	}
	if !found {
		return nil, ErrRecord
	}
	slices.SortFunc(fragments, func(a, b GeneratedFragmentView) int {
		if a.Offset < b.Offset {
			return -1
		}
		if a.Offset > b.Offset {
			return 1
		}
		return 0
	})
	if len(fragments) == 0 || len(fragments) != int(fragments[0].Count) {
		return nil, ErrRecord
	}
	whole := sha256.New()
	var length uint64
	for i, f := range fragments {
		first := fragments[0]
		if int(f.Index) != i || f.Count != first.Count || f.TotalLength != first.TotalLength || f.WholeDigest != first.WholeDigest || uint64(f.Offset) != length {
			return nil, ErrRecord
		}
		whole.Write(f.Payload)
		length += uint64(len(f.Payload))
	}
	if length != fragments[0].TotalLength || !bytes.Equal(whole.Sum(nil), fragments[0].WholeDigest[:]) || location.Offset+uint64(location.Length) > length {
		return nil, ErrRecord
	}
	end := location.Offset + uint64(location.Length)
	sliceHash := sha256.New()
	next := location.Offset
	for _, f := range fragments {
		start, stop := uint64(f.Offset), uint64(f.Offset)+uint64(len(f.Payload))
		if start < end && stop > location.Offset {
			lo, hi := max(start, location.Offset), min(stop, end)
			if lo != next {
				return nil, ErrRecord
			}
			sliceHash.Write(f.Payload[lo-start : hi-start])
			next = hi
		}
	}
	if next != end || !bytes.Equal(sliceHash.Sum(nil), location.Digest[:]) {
		return nil, ErrRecord
	}
	return &generatedImmutableSlice{location: location, fragments: fragments}, nil
}

func (v *generatedImmutableSlice) span(offset, length uint32) ([]byte, error) {
	if uint64(offset)+uint64(length) > uint64(v.location.Length) {
		return nil, ErrRecord
	}
	begin := v.location.Offset + uint64(offset)
	end := begin + uint64(length)
	for _, f := range v.fragments {
		start, stop := uint64(f.Offset), uint64(f.Offset)+uint64(len(f.Payload))
		if start <= begin && end <= stop {
			return f.Payload[begin-start : end-start : end-start], nil
		}
	}
	if cap(v.scratch) < int(length) {
		v.scratch = make([]byte, length)
	}
	body := v.scratch[:0]
	next := begin
	for _, f := range v.fragments {
		start, stop := uint64(f.Offset), uint64(f.Offset)+uint64(len(f.Payload))
		if start < end && stop > begin {
			lo, hi := max(start, begin), min(stop, end)
			if lo != next {
				return nil, ErrRecord
			}
			body = append(body, f.Payload[lo-start:hi-start]...)
			next = hi
		}
	}
	if next != end {
		return nil, ErrRecord
	}
	return body, nil
}

func boolU8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// CopyMetadata copies metadata around already immutable, private-parent-owned selected
// backing. It does not duplicate the selected child image. The private parent
// retains that backing for the operation lifetime; disposal must not clear it.
// This method checks structure only and cannot authenticate caller backing.
func (v *GeneratedSupportTransition) CopyMetadata() (*GeneratedSupportTransition, error) {
	if err := v.Inspect(); err != nil {
		return nil, err
	}
	out := *v
	if v.Output != nil {
		var err error
		out.Output, err = v.Output.Own()
		if err != nil {
			return nil, err
		}
	}
	out.Records = slices.Clone(v.Records)
	out.RecordFacts = slices.Clone(v.RecordFacts)
	out.AccessRecords = slices.Clone(v.AccessRecords)
	for i := range out.AccessRecords {
		out.AccessRecords[i].Wraps = slices.Clone(out.AccessRecords[i].Wraps)
	}
	body, err := EncodeCurrentAccessCore(v.BeforeAccess)
	if err != nil {
		return nil, err
	}
	out.BeforeAccess, err = DecodeCurrentAccessCore(body)
	if err != nil {
		return nil, err
	}
	out.CurrentGenerated = slices.Clone(v.CurrentGenerated)
	for i := range out.CurrentGenerated {
		out.CurrentGenerated[i].EntryBytes = slices.Clone(out.CurrentGenerated[i].EntryBytes)
	}
	out.Handoffs = slices.Clone(v.Handoffs)
	for i := range out.Handoffs {
		h := &out.Handoffs[i]
		h.Implementation.CredentialRoute = slices.Clone(h.Implementation.CredentialRoute)
		h.CompatibilityRequest = slices.Clone(h.CompatibilityRequest)
		h.CompatibilityResponse = slices.Clone(h.CompatibilityResponse)
		h.Support = slices.Clone(h.Support)
		for j := range h.Support {
			h.Support[j].Binding = slices.Clone(h.Support[j].Binding)
		}
	}
	out.Readers = slices.Clone(v.Readers)
	for i := range out.Readers {
		r := &out.Readers[i]
		r.Current = slices.Clone(r.Current)
		r.Retained = slices.Clone(r.Retained)
		r.Bindings = slices.Clone(r.Bindings)
		r.Consumers = slices.Clone(r.Consumers)
		if r.Recovery != nil {
			c := *r.Recovery
			r.Recovery = &c
		}
	}
	return &out, nil
}

func (v *GeneratedSupportTransition) IntentError(intent []CryptoIntentRow) error {
	if err := v.Inspect(); err != nil {
		return err
	}
	if v.Output != nil {
		actual, err := CryptoIntentDescriptor(v.DomainID, intent)
		expected, expectedErr := CryptoIntentDescriptor(v.DomainID, v.Output.Intent)
		if err != nil || expectedErr != nil || actual != expected {
			return ErrRecord
		}
	}
	var handoffs []uint16
	for i, selected := range v.CurrentGenerated {
		m, _ := InspectValueEntry(selected.EntryBytes)
		j := slices.IndexFunc(intent, func(row CryptoIntentRow) bool { return bytes.Equal([]byte(row.Name), m.Name) })
		if j < 0 || intent[j].ValueSource == Supplied {
			if m.Generated.SemanticLifecycleMode() != GeneratorLifecycleNone {
				handoffs = append(handoffs, uint16(i))
			}
			continue
		}
		row := intent[j]
		if row.ConfidentialityClass != Secret || row.PayloadDigest != Hash(m.ValueBytes) || row.PayloadLength != uint32(len(m.ValueBytes)) || row.ContentLength != m.ContentLength || row.InputEncoding != m.InputEncoding || row.RetainedLength != m.RetainedLength {
			return ErrRecord
		}
	}
	if len(handoffs) != len(v.Handoffs) {
		return ErrRecord
	}
	for i, index := range handoffs {
		if v.Handoffs[i].Current != index {
			return ErrRecord
		}
	}
	for _, row := range intent {
		if row.ValueSource == Generated && !slices.ContainsFunc(v.CurrentGenerated, func(c GeneratedSupportCurrent) bool {
			m, _ := InspectValueEntry(c.EntryBytes)
			return bytes.Equal(m.Name, []byte(row.Name))
		}) {
			return ErrRecord
		}
	}
	return nil
}

// SupportAfter is the only permitted normal support transformation.
func (v *GeneratedSupportTransition) SupportAfter(plan IdentityPlan, intent []CryptoIntentRow) (GeneratedSupportRows, error) {
	retained, err := v.LocalEvidenceAfter(intent)
	if err != nil {
		return GeneratedSupportRows{}, err
	}
	descriptor, err := CryptoIntentDescriptor(v.DomainID, intent)
	if err != nil {
		return GeneratedSupportRows{}, err
	}
	capacity, err := GeneratedNormalCapacityDescriptor(GeneratedNormalCapacity{Schema: 1, BeforeRootDigest: v.BeforeRootDigest, TransitionID: plan.Transition, Intent: descriptor, Groups: v.Groups})
	if err != nil {
		return GeneratedSupportRows{}, err
	}
	rows, facts := retained.Records, retained.Facts
	for i, row := range rows {
		if row.Kind != GeneratorVectorSupportKind {
			continue
		}
		c, err := InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		if c.VectorKind != GeneratorVectorSlices {
			continue
		}
		if c.OwnerKind != GeneratorSnapshotOwner || c.OwnerID != v.BeforeSliceSnapshot || c.DomainID != v.DomainID {
			return GeneratedSupportRows{}, ErrRecord
		}
		c.OwnerID = plan.Snapshot
		rows[i].Body, err = EncodeGeneratorVectorCarrier(c)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		rows[i].RecordID, err = GeneratorVectorCarrierID(c)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		facts[i], err = InspectSupportRecordDigest(v.DomainID, rows[i])
		if err != nil {
			return GeneratedSupportRows{}, err
		}
	}
	for _, h := range v.Handoffs {
		old := v.CurrentGenerated[h.Current]
		m, _ := InspectValueEntry(old.EntryBytes)
		id, err := GeneratorDutyID(v.DomainID, m.Generated.OriginOperationID, m.Generated.OriginAttemptID, GeneratedDutyRetirement)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		body, err := EncodeGeneratorTarget(old.Target)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		targets, err := GeneratorVectorDescriptor(GeneratorVectorTargets, [][]byte{body})
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		carrier := GeneratorVectorCarrier{Schema: 1, DomainID: v.DomainID, OwnerKind: GeneratedDutySupportKind, OwnerID: id, VectorKind: GeneratorVectorTargets, Vector: targets, Row: body}
		carrierBody, err := EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		carrierID, err := GeneratorVectorCarrierID(carrier)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		result, err := GeneratedResultContractID(h.Implementation, 2, m.Generated.CompletionClass, 0, GeneratorSafeFactsEnvelopeLength, InputEncodingRaw)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		supportRows := make([][]byte, len(h.Support))
		for i, binding := range h.Support {
			supportRows[i], err = EncodeGeneratorSupportBinding(binding)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
		}
		slices.SortFunc(supportRows, func(a, b []byte) int { return generatorVectorRowCompare(GeneratorVectorSupport, a, b) })
		support, err := GeneratorVectorDescriptor(GeneratorVectorSupport, supportRows)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		for i, body := range supportRows {
			carrier := GeneratorVectorCarrier{Schema: 1, DomainID: v.DomainID, OwnerKind: GeneratedParentSupportKind, OwnerID: m.Generated.OriginOperationID, VectorKind: GeneratorVectorSupport, Vector: support, Ordinal: uint32(i), Row: body}
			encoded, err := EncodeGeneratorVectorCarrier(carrier)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			recordID, err := GeneratorVectorCarrierID(carrier)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			row := SupportRecord{Kind: GeneratorVectorSupportKind, RecordID: recordID, Body: encoded}
			fact, err := InspectSupportRecordDigest(v.DomainID, row)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			existing := slices.IndexFunc(rows, func(existing SupportRecord) bool {
				return existing.Kind == row.Kind && existing.RecordID == row.RecordID
			})
			if existing >= 0 {
				if !bytes.Equal(rows[existing].Body, row.Body) || facts[existing] != fact {
					return GeneratedSupportRows{}, ErrRecord
				}
				continue
			}
			rows = append(rows, row)
			facts = append(facts, fact)
		}
		empty := EmptyGeneratorVector
		duty := GeneratedDutyRecord{Schema: GeneratedDutyRecordSchema, LifecycleMode: GeneratorLifecycleManaged, DomainID: v.DomainID, DutyID: id, OwnerID: id, OriginalOperationID: m.Generated.OriginOperationID, OriginalAttemptID: m.Generated.OriginAttemptID, ResourceID: m.Generated.ResourceIncarnationID,
			DescriptorID: h.Implementation.DescriptorID, ConfigContractID: m.Generated.ConfigContractID, ExecutorID: h.Implementation.ExecutorID, CredentialRouteID: h.Implementation.CredentialRouteID, ResourceContractID: m.Generated.ResourceContractID,
			ResultContractID: result, Kind: GeneratedDutyRetirement, CompletionClass: m.Generated.CompletionClass, Step: 1, Status: GeneratedEffectNotStarted, CapacityReservation: capacity, Target: targets,
			Progress: empty(GeneratorVectorProgress), History: empty(GeneratorVectorHistory), Support: support, Consumers: empty(GeneratorVectorConsumers)}
		body, err = EncodeGeneratedDutyRecord(duty)
		if err != nil {
			return GeneratedSupportRows{}, err
		}
		added := [2]SupportRecord{{Kind: GeneratedDutySupportKind, RecordID: id, Body: body},
			{Kind: GeneratorVectorSupportKind, RecordID: carrierID, Body: carrierBody}}
		for _, row := range added {
			fact, err := InspectSupportRecordDigest(v.DomainID, row)
			if err != nil {
				return GeneratedSupportRows{}, err
			}
			rows = append(rows, row)
			facts = append(facts, fact)
		}
	}
	type pair struct {
		row  SupportRecord
		fact SupportRecordDigest
	}
	ordered := make([]pair, len(rows))
	for i := range rows {
		ordered[i] = pair{row: rows[i], fact: facts[i]}
	}
	slices.SortFunc(ordered, func(a, b pair) int {
		if a.row.Kind != b.row.Kind {
			return int(a.row.Kind) - int(b.row.Kind)
		}
		return bytes.Compare(a.row.RecordID[:], b.row.RecordID[:])
	})
	for i, row := range ordered {
		rows[i], facts[i] = row.row, row.fact
	}
	if _, err := RequiredSupportDescriptorFromDigests(v.DomainID, facts); err != nil {
		return GeneratedSupportRows{}, err
	}
	out := GeneratedSupportRows{Records: rows, Facts: facts}
	if v.Output != nil {
		return v.Output.SupportAfter(plan, out)
	}
	return out, nil
}

// CurrentError checks the public current-only projection against the separately
// pinned complete selected rows. SourceGenerated must also match the complete
// selected entry, slot and original evidence table, not just its value binding.
func (v *GeneratedSupportTransition) CurrentError(current []CryptoCurrentSecret) error {
	if err := v.Inspect(); err != nil {
		return err
	}
	seen := make([]bool, len(v.CurrentGenerated))
	seenAccess := make([]bool, len(v.AccessRecords))
	for _, row := range current {
		m, err := InspectValueEntry(row.EntryBytes)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(v.AccessRecords, func(a AccessRecord) bool { return a.MaterialKind == ValueMaterialKind && a.MaterialID == m.ValueState })
		if i < 0 {
			return ErrRecord
		}
		if seenAccess[i] || len(v.Readers[i].Current) != m.RecipientCount() {
			return ErrRecord
		}
		seenAccess[i] = true
		for j, id := range v.Readers[i].Current {
			selected, _ := m.RecipientID(j)
			if id != selected {
				return ErrRecord
			}
		}
		full := v.AccessRecords[i]
		full.Wraps = slices.Clone(full.Wraps)
		full.Wraps = slices.DeleteFunc(full.Wraps, func(w WrapRow) bool {
			if w.SubjectKind != OrdinaryWrapSubject {
				return false
			}
			for j := 0; j < m.RecipientCount(); j++ {
				id, _ := m.RecipientID(j)
				if id == w.SubjectID {
					return false
				}
			}
			return true
		})
		body, err := EncodeAccessRecord(full)
		if err != nil || !bytes.Equal(body, row.AccessRecord) {
			return ErrRecord
		}
		if m.ValueSource == Generated {
			j := slices.IndexFunc(v.CurrentGenerated, func(c GeneratedSupportCurrent) bool { return c.Slot == row.Slot })
			if j < 0 || seen[j] || !bytes.Equal(row.EntryBytes, v.CurrentGenerated[j].EntryBytes) {
				return ErrRecord
			}
			seen[j] = true
		}
	}
	for _, ok := range seen {
		if !ok {
			return ErrRecord
		}
	}
	for i, ok := range seenAccess {
		if !ok && len(v.Readers[i].Current) != 0 {
			return ErrRecord
		}
	}
	return nil
}

func generatedSameWrap(a, b WrapRow) bool {
	return a.SubjectKind == b.SubjectKind && a.SubjectID == b.SubjectID && a.BindingID == b.BindingID && a.BindingSerial == b.BindingSerial && a.PublicBindingDigest == b.PublicBindingDigest && bytes.Equal(a.RSACiphertext, b.RSACiphertext)
}

// AccessAfter merges bounded current projections with only the pinned real
// retained reader subsets. Ciphertext and unchanged wraps are never regenerated.
func (v *GeneratedSupportTransition) AccessAfter(intent []CryptoIntentRow, current []CryptoCurrentSecret, prepared []CryptoPreparedSecret) ([]AccessRecord, error) {
	if err := v.IntentError(intent); err != nil {
		return nil, err
	}
	if err := v.CurrentError(current); err != nil {
		return nil, err
	}
	var out []AccessRecord
	for i, old := range v.AccessRecords {
		readers := v.Readers[i]
		if old.MaterialKind != OperationSeedMaterialKind && len(readers.Retained) == 0 {
			continue
		}
		row := old
		row.Wraps = slices.Clone(old.Wraps)
		row.Wraps = slices.DeleteFunc(row.Wraps, func(w WrapRow) bool {
			return w.SubjectKind == OrdinaryWrapSubject && !slices.Contains(readers.Retained, w.SubjectID)
		})
		out = append(out, row)
	}
	for _, intended := range intent {
		if intended.ConfidentialityClass != Secret {
			continue
		}
		var body []byte
		if i := slices.IndexFunc(prepared, func(p CryptoPreparedSecret) bool { return p.Name == intended.Name }); i >= 0 {
			body = prepared[i].AccessRecord
		} else {
			i := slices.IndexFunc(current, func(c CryptoCurrentSecret) bool {
				m, err := InspectValueEntry(c.EntryBytes)
				return err == nil && bytes.Equal(m.Name, []byte(intended.Name))
			})
			if i < 0 {
				return nil, ErrRecord
			}
			body = current[i].AccessRecord
		}
		row, err := DecodeAccessRecord(body)
		if err != nil {
			return nil, err
		}
		if len(row.Wraps) != len(intended.Recipients)+int(boolU8(v.BeforeAccess.Recovery != nil)) {
			return nil, ErrRecord
		}
		for j, id := range intended.Recipients {
			if row.Wraps[j].SubjectKind != OrdinaryWrapSubject || row.Wraps[j].SubjectID != id {
				return nil, ErrRecord
			}
		}
		if v.BeforeAccess.Recovery != nil {
			wrap := row.Wraps[len(intended.Recipients)]
			if wrap.SubjectKind != RecoveryWrapSubject || wrap.SubjectID != v.BeforeAccess.Recovery.RoleID {
				return nil, ErrRecord
			}
		}
		if i := slices.IndexFunc(out, func(a AccessRecord) bool { return a.MaterialKind == row.MaterialKind && a.MaterialID == row.MaterialID }); i >= 0 {
			old := out[i]
			if old.MaterialContextDigest != row.MaterialContextDigest || old.PackageCheck != row.PackageCheck {
				return nil, ErrRecord
			}
			for _, wrap := range old.Wraps {
				j := slices.IndexFunc(row.Wraps, func(w WrapRow) bool { return w.SubjectKind == wrap.SubjectKind && w.SubjectID == wrap.SubjectID })
				if j >= 0 {
					if !generatedSameWrap(wrap, row.Wraps[j]) {
						return nil, ErrRecord
					}
				} else {
					row.Wraps = append(row.Wraps, wrap)
				}
			}
			slices.SortFunc(row.Wraps, func(a, b WrapRow) int {
				if a.SubjectKind != b.SubjectKind {
					return int(a.SubjectKind) - int(b.SubjectKind)
				}
				return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
			})
			out[i] = row
		} else {
			out = append(out, row)
		}
	}
	slices.SortFunc(out, func(a, b AccessRecord) int {
		if a.MaterialKind != b.MaterialKind {
			return int(a.MaterialKind) - int(b.MaterialKind)
		}
		return bytes.Compare(a.MaterialID[:], b.MaterialID[:])
	})
	if _, err := AccessRecordsDescriptor(v.DomainID, out); err != nil {
		return nil, err
	}
	return out, nil
}

type GeneratedNormalAccessPage struct {
	Ref     Ref
	Records []AccessRecord
}

// AccessCoreAfter uses the existing global order and greedy whole-row page
// rule. Hashing streams rows and creates no independent page-sized image.
func (v *GeneratedSupportTransition) AccessCoreAfter(rows []AccessRecord, plan IdentityPlan) (CurrentAccessCore, []GeneratedNormalAccessPage, error) {
	d, err := AccessRecordsDescriptor(v.DomainID, rows)
	if err != nil {
		return CurrentAccessCore{}, nil, err
	}
	core := v.BeforeAccess
	if d == core.AccessRecordsDescriptor {
		for _, p := range plan.Pages {
			if p.Kind == AccessKind {
				return CurrentAccessCore{}, nil, ErrRecord
			}
		}
		return core, nil, nil
	}
	core.AccessPageRefs = nil
	core.AccessRecordsDescriptor = d
	pages := make([]GeneratedNormalAccessPage, 0)
	start, length := 0, AccessPageHeaderLength
	flush := func(end int) error {
		if start == end {
			return nil
		}
		index := uint16(len(pages))
		if int(index) >= MaxChildPages {
			return ErrRecordCapacity
		}
		i := slices.IndexFunc(plan.Pages, func(p IdentityPage) bool { return p.Kind == AccessKind && p.Index == index })
		if i < 0 {
			return ErrRecord
		}
		id := plan.Pages[i].Object
		w := cryptoHashWriter("")
		w.raw([]byte{'E', 'N', 'K', 'V', byte(AccessKind), byte(CanonicalSchema >> 8), byte(CanonicalSchema)})
		w.id(v.DomainID)
		w.id(id)
		w.u16(index)
		w.u16(uint16(end - start))
		for _, row := range rows[start:end] {
			writeAccessRecord(&w, row)
		}
		result := w.result(end - start)
		ref := Ref{Kind: AccessKind, Format: CanonicalSchema, Domain: v.DomainID, Object: id, Index: index, Length: uint32(result.Length), Digest: result.Digest}
		pages = append(pages, GeneratedNormalAccessPage{Ref: ref, Records: rows[start:end]})
		core.AccessPageRefs = append(core.AccessPageRefs, ref)
		start, length = end, AccessPageHeaderLength
		return nil
	}
	for i, row := range rows {
		n, err := AccessRecordLength(row)
		if err != nil {
			return CurrentAccessCore{}, nil, err
		}
		if length+n > MaxAccessPageLength || i-start == AccessPageRecordLimit {
			if err := flush(i); err != nil {
				return CurrentAccessCore{}, nil, err
			}
		}
		length += n
	}
	if err := flush(len(rows)); err != nil {
		return CurrentAccessCore{}, nil, err
	}
	n := 0
	for _, p := range plan.Pages {
		if p.Kind == AccessKind {
			n++
		}
	}
	if n != len(pages) {
		return CurrentAccessCore{}, nil, ErrRecord
	}
	if err := AdvanceAccessGeneration(&core, plan.Transition); err != nil {
		return CurrentAccessCore{}, nil, err
	}
	if _, err := AccessRoot(core); err != nil {
		return CurrentAccessCore{}, nil, err
	}
	return core, pages, nil
}
