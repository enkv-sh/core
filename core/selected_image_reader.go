package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type selectedScanMode uint8

const (
	selectedComplete selectedScanMode = iota + 1
	selectedAdministrativePartial
)

func readCompleteSelectedImage(ctx context.Context, reader selectedObjectReader, root format.Root, retainObjects bool) (selectedImage, Result) {
	return scanSelectedImage(ctx, reader, root, retainObjects, selectedComplete, nil)
}
func scanSelectedImage(ctx context.Context, reader selectedObjectReader, root format.Root, retainObjects bool, mode selectedScanMode, previous *selectedImage) (selectedImage, Result) {
	if ctx == nil || root.Domain != reader.domain || (mode != selectedComplete && mode != selectedAdministrativePartial) {
		return selectedImage{}, refused(AdmissionInvalid)
	}
	administrative := mode == selectedAdministrativePartial
	currentOnly := selectedCurrentOnlyRoot(root)
	if currentOnly && root.AccessRecordCount != root.SecretCount {
		return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
	}
	image := selectedImage{root: root, cache: make(map[format.Ref][]byte), accessFacts: make(map[format.Ref]*format.AccessPage), fragmentFacts: make(map[format.FragmentLocation]selectedFragmentFact), publicationFacts: make(map[generatedRecordKey]selectedPublicationRecord)}
	var actualEntryCount, actualMemberships, actualSecrets uint32
	var actualRaw uint64
	for i, ref := range root.ValueEntryPages {
		if ref == nil {
			continue
		}
		var p *format.ValueEntryPage
		var prior *format.Ref
		if previous != nil {
			p = previous.pages[i]
			prior = previous.root.ValueEntryPages[i]
		}
		// Authenticated typed pages own their payloads and remain immutable.
		// Reuse only the complete selected Ref; changed pages must decode and Own.
		if p == nil || prior == nil || *prior != *ref {
			b, res := reader.readOwned(ctx, *ref)
			if res.Outcome != 0 {
				return selectedImage{}, res
			}
			decoded, err := format.DecodeValueEntryPage(b)
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidReference)
			}
			p = &decoded
		}
		if ref.Domain != reader.domain || p.Domain != reader.domain || p.Object != ref.Object || p.Index != uint16(i) {
			return selectedImage{}, failure(IntegrityFailure, InvalidReference)
		}
		for _, m := range p.Slots {
			if m == nil {
				continue
			}
			actualEntryCount++
			actualMemberships += uint32(len(m.Recipients))
			if m.ConfidentialityClass == format.Secret {
				payload, err := contract.InspectCanonicalPayload(m.ValueBytes)
				if err != nil {
					return selectedImage{}, failure(IntegrityFailure, InvalidFormat)
				}
				actualRaw += uint64(payload.ContentLength)
				actualSecrets++
			} else {
				actualRaw += uint64(m.ContentLength)
			}
		}
		if actualEntryCount > root.ValueEntryCount || actualMemberships > root.MembershipCount || actualSecrets > root.SecretCount || actualRaw > root.RawBytes {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		image.pages[i] = p
	}
	var currentIntents, currentEvidence, seenCurrentSlices map[contract.ID]bool
	if currentOnly {
		currentIntents = make(map[contract.ID]bool)
		currentEvidence = make(map[contract.ID]bool)
		seenCurrentSlices = make(map[contract.ID]bool)
		var generated uint32
		for _, page := range image.pages {
			if page != nil {
				for _, entry := range page.Slots {
					if entry != nil && entry.ValueSource == contract.Generated {
						generated++
						currentIntents[entry.Generated.IntentDigest] = true
						currentEvidence[entry.Generated.CreateResultID] = true
					}
				}
			}
		}
		if generated != root.Generated.GeneratedCurrent || root.Generated.Slices.Count != uint32(len(currentIntents)) {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
	}
	for i, ref := range root.Recipients {
		if ref == nil {
			continue
		}
		b, res := reader.readOwned(ctx, *ref)
		if res.Outcome != 0 {
			return selectedImage{}, res
		}
		p, err := format.DecodeRecipientPage(b)
		if err != nil || p.Domain != reader.domain || p.Object != ref.Object || p.Index != uint16(i) {
			return selectedImage{}, failure(IntegrityFailure, InvalidReference)
		}
		image.recipients[i] = &p
		if retainObjects {
			image.cache[*ref] = b
		}
	}
	var actualAccessRecords, actualOrdinaryWraps, actualRecoveryWraps uint32
	for _, ref := range root.CurrentAccess.Core.AccessPageRefs {
		page := reader.accessFacts[ref]
		if page == nil {
			body, _, result := reader.readBorrowed(ctx, ref)
			if result.Outcome != 0 {
				return selectedImage{}, result
			}
			decoded, err := format.DecodeAccessPage(body)
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidReference)
			}
			page = &decoded
		}
		if ref.Kind != contract.AccessKind || ref.Domain != reader.domain || page.Domain != reader.domain || page.Object != ref.Object || page.Index != ref.Index || int(ref.Index) >= len(image.access) {
			return selectedImage{}, failure(IntegrityFailure, InvalidReference)
		}
		actualAccessRecords += uint32(len(page.Records))
		if actualAccessRecords > root.AccessRecordCount {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		if currentOnly {
			for _, record := range page.Records {
				for _, wrap := range record.Wraps {
					if wrap.SubjectKind == contract.RecoveryWrapSubject {
						actualRecoveryWraps++
					} else {
						actualOrdinaryWraps++
					}
				}
			}
			var recoveryWraps uint32
			if root.CurrentAccess.Core.Recovery != nil {
				recoveryWraps = root.SecretCount
			}
			if actualOrdinaryWraps > root.SecretOrdinaryWrapCount || actualRecoveryWraps > recoveryWraps {
				return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
			}
		}
		image.access[ref.Index] = page
		image.accessFacts[ref] = page
	}
	indexRefs := make([]format.Ref, 0, 1+len(root.AdministrativeIndexShards))
	indexRefs = append(indexRefs, root.AdministrativeIndex)
	indexRefs = append(indexRefs, root.AdministrativeIndexShards...)
	var index format.AdministrativeIndex
	var err error
	if reader.replacementRead && reader.cachedAdministrativeIndexFacts.exact(indexRefs) {
		index = reader.cachedAdministrativeIndexFacts.index
		image.administrativeIndexFacts = reader.cachedAdministrativeIndexFacts
	} else if reader.replacementRead && previous != nil && previous.administrativeIndexFacts.exact(indexRefs) {
		index = previous.administrativeIndexFacts.index
		image.administrativeIndexFacts = previous.administrativeIndexFacts
	} else if reader.replacementRead {
		index, err = format.DecodeAdministrativeIndexSource(indexRefs, func(ref format.Ref) ([]byte, error) {
			body, _, result := reader.readBorrowed(ctx, ref)
			if result.Outcome != 0 {
				return nil, selectedReadFailure(result)
			}
			return body, nil
		})
	} else {
		indexPages := make([]format.AdministrativeIndexPage, len(indexRefs))
		for i, ref := range indexRefs {
			body, result := reader.readOwned(ctx, ref)
			if result.Outcome != 0 {
				return selectedImage{}, result
			}
			indexPages[i] = format.AdministrativeIndexPage{Ref: ref, Body: body}
			if !reader.replacementRead {
				image.cache[ref] = body
			}
		}
		index, err = format.DecodeAdministrativeIndexPages(indexPages)
	}
	if result, ok := selectedReadResult(err); ok {
		return selectedImage{}, result
	}
	if err != nil || index.Domain != reader.domain || index.Object != root.AdministrativeIndex.Object || len(index.Pages) != len(root.RequiredSupport) {
		return selectedImage{}, failure(IntegrityFailure, InvalidReference)
	}
	for i, page := range index.Pages {
		if page.Ref != root.RequiredSupport[i] {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
	}
	{
		var currentSupport bool
		for _, page := range image.pages {
			if page != nil {
				for _, entry := range page.Slots {
					if entry != nil && entry.ValueSource == contract.Generated && entry.Generated.RequiredSupport.Count != 0 {
						currentSupport = true
					}
				}
			}
		}
		if !selectedIndexOwnerBounds(root, index, !administrative, currentSupport, currentEvidence) {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
	}
	image.adminIndex = index
	if reader.replacementRead && image.administrativeIndexFacts == nil {
		image.administrativeIndexFacts = &selectedAdministrativeIndexFacts{refs: slices.Clone(indexRefs), index: index}
	}
	var receiptFragment contract.ID
	if reader.replacementRead && administrative {
		blob, err := selectedReceiptIndexID(reader.domain, root)
		if err != nil {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		if !blob.IsZero() {
			receiptFragment, err = contract.GeneratorFragmentID(blob, 0)
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
			}
		}
	}
	for i, ref := range root.RequiredSupport {
		if ref.Kind != contract.RequiredSupportKind {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		mandatory := slices.ContainsFunc(index.Pages[i].Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory })
		if administrative && !mandatory && !index.Pages[i].ReadRequired {
			image.support = append(image.support, format.RequiredSupportPageView{Domain: reader.domain, Object: ref.Object, Index: ref.Index})
			image.supportFacts = append(image.supportFacts, selectedSupportPageFacts{ref: ref})
			continue
		}
		if reader.replacementRead && previous != nil {
			page, facts, reused, err := reuseSelectedSupportPage(previous, index.Pages[i])
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
			}
			if reused {
				for _, row := range page.Records {
					if publicationSupportKind(row.Kind) {
						fact, err := previous.publicationRecord(contract.SupportRecord(row))
						if err != nil {
							return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
						}
						image.publicationFacts[generatedRecordKey{row.Kind, row.RecordID}] = fact
					}
				}
				image.support = append(image.support, page)
				image.supportFacts = append(image.supportFacts, facts)
				if body, present := previous.cache[ref]; present {
					image.cache[ref] = body
				}
				releaseSelectedPublicationPageBodies(&image, len(image.support)-1)
				continue
			}
		}

		b, owned, res := reader.readBorrowed(ctx, ref)
		if res.Outcome != 0 {
			return selectedImage{}, res
		}
		page, err := format.InspectRequiredSupportPage(b)
		if err != nil || page.Domain != reader.domain || page.Object != ref.Object || page.Index != ref.Index {
			return selectedImage{}, failure(IntegrityFailure, InvalidReference)
		}
		var hasOpaque, hasFragment bool
		for _, row := range page.Records {
			hasFragment = hasFragment || row.Kind == contract.GeneratedFragmentSupportKind
			hasOpaque = hasOpaque || opaqueSupportKind(row.Kind)
		}
		cachePage := !hasOpaque && !reader.replacementRead
		if (cachePage || !reader.replacementRead && administrative && hasFragment) && !owned {
			b = bytes.Clone(b)
			page, err = format.InspectRequiredSupportPage(b)
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidReference)
			}
		}
		physical := page.Records
		readRequired := false
		for _, row := range physical {
			if row.Kind != contract.GeneratorVectorSupportKind {
				continue
			}
			carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidFormat)
			}
			if carrier.VectorKind == contract.GeneratorVectorSlices {
				readRequired = true
			}
		}
		if readRequired != index.Pages[i].ReadRequired {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		if readRequired {
			for _, row := range physical {
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if row.Kind != contract.GeneratorVectorSupportKind || err != nil || carrier.VectorKind != contract.GeneratorVectorSlices {
					return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
				}
			}
		}
		page.Records = nil
		facts := selectedSupportPageFacts{ref: ref}
		summary := 0
		for _, span := range index.Pages[i].Spans {
			end := uint32(span.First) + uint32(span.Count)
			if end > uint32(len(physical)) {
				return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
			}
			if !readRequired {
				for ordinal := uint32(span.First); ordinal < end; ordinal++ {
					row := physical[ordinal]
					if summary >= len(index.Pages[i].Rows) || !index.Pages[i].Rows[summary].MatchesRecord(contract.SupportRecord(row)) {
						return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
					}
					summary++
				}
			}
			for ordinal := uint32(span.First); ordinal < end; ordinal++ {
				row := physical[ordinal]
				if currentOnly && row.Kind == contract.GeneratorVectorSupportKind {
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil {
						return selectedImage{}, failure(IntegrityFailure, InvalidFormat)
					}
					if carrier.VectorKind == contract.GeneratorVectorSlices {
						location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
						if err != nil || location.ContentKind != contract.GeneratorContentIntent || !currentIntents[location.ContentID] || seenCurrentSlices[location.ContentID] {
							return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
						}
						seenCurrentSlices[location.ContentID] = true
					}
				}
				fact, err := contract.InspectSupportRecordDigest(reader.domain, contract.SupportRecord(row))
				if err != nil {
					return selectedImage{}, failure(IntegrityFailure, InvalidFormat)
				}
				if reader.replacementRead && publicationSupportKind(row.Kind) {
					key := generatedRecordKey{row.Kind, row.RecordID}
					if _, duplicate := image.publicationFacts[key]; duplicate {
						return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
					}
					decoded, err := inspectSelectedPublicationRecord(reader.domain, contract.SupportRecord(row))
					if err != nil {
						return selectedImage{}, failure(IntegrityFailure, InvalidFormat)
					}
					image.publicationFacts[key] = decoded
				}
				logical := len(page.Records)
				facts.rows = append(facts.rows, fact)
				facts.ordinals = append(facts.ordinals, uint16(ordinal))
				if row.Kind == contract.GeneratedFragmentSupportKind {
					fragment, err := contract.InspectGeneratedFragment(row.Body)
					if err != nil || logical > 1 {
						return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
					}
					if reader.replacementRead && administrative && row.RecordID == receiptFragment {
						if fragment.TotalLength > contract.MutationReceiptIndexesMaxLength {
							return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
						}
						indexes, err := contract.InspectMutationReceiptIndexes(fragment.Payload)
						if err != nil {
							return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
						}
						successes, failures, order, err := indexes.Descriptors()
						if err != nil || successes != root.Generated.SuccessWindow || failures != root.Generated.FailureWindow || order != root.Generated.ReceiptOrder ||
							fragment.WholeDigest != contract.Hash(fragment.Payload) {
							return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
						}
					}
					location := format.FragmentLocation{BlobID: fragment.BlobID, FragmentIndex: fragment.Index,
						SupportPageIndex: ref.Index, RowSlot: uint8(logical)}
					if _, duplicate := image.fragmentFacts[location]; duplicate {
						return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
					}
					image.fragmentFacts[location] = selectedFragmentFact{ref: ref, row: fact, physical: uint16(ordinal), logical: uint8(logical),
						blob: fragment.BlobID, index: fragment.Index, count: fragment.Count, total: fragment.TotalLength,
						whole: fragment.WholeDigest, offset: fragment.Offset, payloadLength: uint32(len(fragment.Payload))}
				}
				page.Records = append(page.Records, row)
			}
		}
		if !readRequired && summary != len(index.Pages[i].Rows) {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		for j := range page.Records {
			row := &page.Records[j]
			releaseFragment := row.Kind == contract.GeneratedFragmentSupportKind && (!administrative || reader.replacementRead && row.RecordID != receiptFragment)
			if row.Kind == contract.OutputConfigurationSliceSupportKind || releaseFragment || reader.replacementRead && publicationSupportKind(row.Kind) {
				row.Body = nil
			} else if reader.replacementRead || hasOpaque && row.Kind != contract.GeneratedFragmentSupportKind {
				// A private replacement owns selected rows only. Omitted physical
				// rows and opaque payloads must not survive through a small peer.
				row.Body = bytes.Clone(row.Body)
			}
		}
		image.support = append(image.support, page)
		image.supportFacts = append(image.supportFacts, facts)
		if cachePage {
			image.cache[ref] = b
		}
		if reader.replacementRead {
			releaseSelectedPublicationPageBodies(&image, len(image.support)-1)
		}
	}
	streamReader := reader
	streamReader.cache = image.cache
	{
		reads := uint64(root.OutputConfiguration.SliceCount)
		var err error
		if !administrative {
			reads, err = selectedObservationExtraReads(&image, mode)
		}
		if err != nil {
			return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
		}
		if reads != 0 && !extendObservedReadStage(ctx, reads) {
			limited := failure(EvidenceUnavailable, ReadUnavailable)
			limited.StoreReason = contract.ReasonLimit
			return selectedImage{}, limited
		}
		if administrative {
			if result := validateSelectedOutputConfiguration(ctx, &image, streamReader, nil); result.Outcome != 0 {
				return selectedImage{}, result
			}
		} else {
			proof, result, err := validateSelectedPublicationConfigurationWithReader(ctx, &image, streamReader)
			if result.Outcome != 0 {
				return selectedImage{}, result
			}
			if err != nil {
				return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
			}
			image.publicationProof = proof
		}
		if !administrative {
			if result := verifySelectedGeneratedSlices(ctx, &image, streamReader); result.Outcome != 0 {
				return selectedImage{}, result
			}
		}
	}
	if !administrativeSelectedKeysUnique(index, image.support) {
		return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
	}

	body, err := format.EncodeRoot(root)
	if err != nil {
		return selectedImage{}, failure(IntegrityFailure, InvalidRelation)
	}
	image.generatedSlicesRoot = contract.Hash(body)
	return image, Result{}
}
