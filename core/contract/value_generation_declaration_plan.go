package contract

import (
	"bytes"
	"cmp"
	"slices"
)

type GeneratorDeclarationSlice struct {
	Logical GeneratorLogicalSlice
	Offset  uint32
}

// Slices reconstructs embedded content and offsets from the closed declaration.
// References have no embedded bytes. Physical BlobID/base offsets are assigned
// separately and never enter a plan.
func (v GeneratorDeclarationView) Slices() ([]GeneratorDeclarationSlice, error) {
	checked, err := InspectGeneratorDeclaration(v.body)
	if err != nil || checked.DomainID != v.DomainID || checked.OperationID != v.OperationID {
		return nil, ErrRecord
	}
	rows := make([]GeneratorDeclarationSlice, 0, 1+2*checked.EntryCount())
	add := func(kind uint8, id ID, offset uint32, body []byte) {
		rows = append(rows, GeneratorDeclarationSlice{Logical: GeneratorLogicalSlice{Schema: 1, ContentKind: kind, ContentID: id,
			Length: uint32(len(body)), Digest: Hash(body)}, Offset: offset})
	}
	add(GeneratorContentDeclaration, v.OperationID, 0, v.body)
	for i := 0; i < checked.EntryCount(); i++ {
		row, offset, err := checked.Entry(i)
		if err != nil {
			return nil, err
		}
		_, payloadOffset, err := checked.EntrySpan(i)
		if err != nil {
			return nil, err
		}
		if row.Kind == GeneratorDeclarationGeneratedReference {
			continue
		}
		if row.Kind == GeneratorDeclarationGenerated {
			g, err := InspectGeneratorDeclaredGenerationForEntry(row.Schema, row.Payload)
			if err != nil {
				return nil, err
			}
			id, err := GeneratorIntentDigest(g.Intent)
			if err != nil {
				return nil, err
			}
			add(GeneratorContentIntent, id, payloadOffset+generatorDeclaredIntentOffset(g), g.Intent)
			continue
		}
		id, err := GeneratorDeclarationEntryID(v.DomainID, v.OperationID, string(row.Name))
		if err != nil {
			return nil, err
		}
		span := checked.entries[i]
		add(GeneratorContentSource, id, offset, v.body[span.offset:span.offset+span.length])
		if row.Kind == GeneratorDeclarationSealed {
			source, err := InspectSealedInputEnvelope(row.Payload)
			if err != nil {
				return nil, err
			}
			add(GeneratorContentSource, source.Core.SourceID, payloadOffset, row.Payload)
		}
	}
	slices.SortFunc(rows, func(a, b GeneratorDeclarationSlice) int {
		if order := cmp.Compare(a.Logical.ContentKind, b.Logical.ContentKind); order != 0 {
			return order
		}
		return bytes.Compare(a.Logical.ContentID[:], b.Logical.ContentID[:])
	})
	n := 0
	for _, row := range rows {
		if n > 0 && rows[n-1].Logical.ContentKind == row.Logical.ContentKind && rows[n-1].Logical.ContentID == row.Logical.ContentID {
			if rows[n-1].Logical != row.Logical {
				return nil, ErrRecord
			}
			continue
		}
		rows[n] = row
		n++
	}
	return rows[:n], nil
}

// LogicalSlices returns complete declared logical content, including references
// whose bytes must come from authenticated selected support.
func (v GeneratorDeclarationView) LogicalSlices() ([]GeneratorLogicalSlice, error) {
	physical, err := v.Slices()
	if err != nil {
		return nil, err
	}
	rows := make([]GeneratorLogicalSlice, 0, len(physical)+v.EntryCount())
	for _, row := range physical {
		rows = append(rows, row.Logical)
	}
	for i := 0; i < v.EntryCount(); i++ {
		entry, _, err := v.Entry(i)
		if err != nil {
			return nil, err
		}
		if entry.Kind != GeneratorDeclarationGeneratedReference {
			continue
		}
		g, err := InspectGeneratorDeclaredGenerationReferenceForEntry(entry.Schema, entry.Payload)
		if err != nil {
			return nil, err
		}
		rows = append(rows, g.Intent)
	}
	slices.SortFunc(rows, func(a, b GeneratorLogicalSlice) int {
		if order := cmp.Compare(a.ContentKind, b.ContentKind); order != 0 {
			return order
		}
		return bytes.Compare(a.ContentID[:], b.ContentID[:])
	})
	n := 0
	for _, row := range rows {
		if n > 0 && rows[n-1].ContentKind == row.ContentKind && rows[n-1].ContentID == row.ContentID {
			if rows[n-1] != row {
				return nil, ErrRecord
			}
			continue
		}
		rows[n] = row
		n++
	}
	return rows[:n], nil
}

func GeneratorAcceptedSourceConsumer(operation, material ID, source GeneratorSourceUse) (GeneratorConsumer, error) {
	v := GeneratorConsumer{Schema: 1, OwnerID: operation, MaterialID: material, ContextDigest: source.SealedInputCoreDigest, SubjectKind: GeneratorConsumerAcceptedSource, SubjectID: source.SourceID, Purpose: GeneratorConsumerPrepareAcceptedSource}
	if !v.valid() {
		return GeneratorConsumer{}, ErrRecord
	}
	return v, nil
}

func GeneratorResultUseDigest(v GeneratorResultUse) (ID, error) {
	body, err := EncodeGeneratorResultUse(v)
	if err != nil {
		return ID{}, err
	}
	return generatorDigest("result-use", body), nil
}

// ValidateGeneratorDeclarationGraph checks public correspondence only. Private
// admission still supplies the authenticated selected canonical sources,
// recipient bindings and normalizer/profile; Crypto authenticates secrets.
func ValidateGeneratorDeclarationGraph(v GeneratorDeclarationView, bundle GeneratorPlanBundle) error {
	d, err := v.Descriptor()
	if err != nil {
		return err
	}
	if _, err := GeneratorPlanBundleLength(bundle); err != nil {
		return err
	}
	if v.DomainID != bundle.Header.DomainID || v.OperationID != bundle.Header.OperationID || bundle.Request.Declaration != d || len(bundle.ValueEntryPlans) != v.EntryCount() {
		return ErrRecord
	}
	locations, err := v.LogicalSlices()
	if err != nil {
		return err
	}
	logical := make(map[[33]byte]GeneratorLogicalSlice, len(locations))
	key := func(kind uint8, id ID) (k [33]byte) { k[0] = kind; copy(k[1:], id[:]); return }
	for _, row := range locations {
		logical[key(row.ContentKind, row.ContentID)] = row
	}
	sliceDescriptor := func(kind uint8, id ID) (GeneratorDescriptor, error) {
		row, ok := logical[key(kind, id)]
		if !ok {
			return GeneratorDescriptor{}, ErrRecord
		}
		return GeneratorLogicalSlicesDescriptor([]GeneratorLogicalSlice{row})
	}
	var recipients [CryptoMaxValueEntryRecipients]ID
	expectedSources := make([]GeneratorSourceUse, 0, len(bundle.SourceUses))
	for i, plan := range bundle.ValueEntryPlans {
		entry, _, err := v.Entry(i)
		if err != nil {
			return err
		}
		if entry.Schema != GeneratorDeclarationEntrySchema || string(entry.Name) != plan.Name || entry.ValueSource() != plan.ValueSource || entry.ConfidentialityClass() != plan.ConfidentialityClass || entry.InputEncoding != plan.InputEncoding || entry.OutputEncoding != plan.OutputEncoding {
			return ErrRecord
		}
		ids := recipients[:len(entry.RecipientIDs)/32]
		for j := range ids {
			ids[j] = ID(entry.RecipientIDs[j*32 : (j+1)*32])
		}
		membership, err := GeneratorIntendedMembershipDescriptor(ids)
		if err != nil || membership != plan.IntendedMembership {
			return ErrRecord
		}
		if entry.Kind == GeneratorDeclarationGenerated {
			g, err := InspectGeneratorDeclaredGenerationForEntry(entry.Schema, entry.Payload)
			if err != nil {
				return err
			}
			intent, err := GeneratorIntentDigest(g.Intent)
			if err != nil || plan.Epoch != g.Epoch || plan.LifecycleMode != g.LifecycleMode || plan.RetirementMode != g.RetirementMode || plan.IntentDigest != intent {
				return ErrRecord
			}
			if plan.ChangeMask&GeneratorValueChangeContent == 0 {
				d, err := sliceDescriptor(GeneratorContentIntent, intent)
				if err != nil || plan.SourceSlice != d {
					return ErrRecord
				}
			} else {
				for _, lineage := range bundle.Lineages {
					if lineage.Purpose != GeneratorLineageCreate || lineage.LineageID != plan.LineageID {
						continue
					}
					for _, template := range lineage.Templates[:lineage.TemplateCount] {
						if template.ConfigContractID != g.ConfigContractID || template.ResourceContractID != g.ResourceContractID || template.LifecycleMode != g.LifecycleMode || template.CompletionClass != g.CompletionClass {
							return ErrRecord
						}
					}
				}
			}
			continue
		}
		if entry.Kind == GeneratorDeclarationGeneratedReference {
			g, err := InspectGeneratorDeclaredGenerationReferenceForEntry(entry.Schema, entry.Payload)
			if err != nil {
				return err
			}
			d, err := sliceDescriptor(GeneratorContentIntent, g.Intent.ContentID)
			if err != nil || plan.ChangeMask&GeneratorValueChangeContent != 0 || plan.Epoch != g.Epoch || plan.LifecycleMode != g.LifecycleMode || plan.RetirementMode != g.RetirementMode ||
				plan.IntentDigest != g.Intent.ContentID || plan.SourceSlice != d {
				return ErrRecord
			}
			continue
		}
		entryID, err := GeneratorDeclarationEntryID(v.DomainID, v.OperationID, plan.Name)
		if err != nil {
			return err
		}
		d, err := sliceDescriptor(GeneratorContentSource, entryID)
		if err != nil || plan.SourceSlice != d {
			return ErrRecord
		}
		if entry.Kind == GeneratorDeclarationSealed {
			source, err := InspectSealedInputEnvelope(entry.Payload)
			if err != nil {
				return err
			}
			core, err := source.Core.Own()
			if err != nil {
				return err
			}
			coreDigest, err := SealedInputCoreDigest(core)
			if err != nil {
				return err
			}
			d, err := sliceDescriptor(GeneratorContentSource, core.SourceID)
			if err != nil {
				return err
			}
			use := GeneratorSourceUse{Schema: 1, SourceID: core.SourceID, SealedInputCoreDigest: coreDigest, EnvelopeDigest: Hash(entry.Payload), SourceSlice: d, Purpose: GeneratorUseAcceptedSource}
			consumer, err := GeneratorAcceptedSourceConsumer(v.OperationID, bundle.Header.MaterialID, use)
			if err != nil {
				return err
			}
			body, err := EncodeGeneratorConsumer(consumer)
			if err != nil {
				return err
			}
			use.Consumers, err = GeneratorVectorDescriptor(GeneratorVectorConsumers, [][]byte{body})
			if err != nil {
				return err
			}
			expectedSources = append(expectedSources, use)
		}
	}
	slices.SortFunc(expectedSources, func(a, b GeneratorSourceUse) int { return bytes.Compare(a.SourceID[:], b.SourceID[:]) })
	if !slices.Equal(expectedSources, bundle.SourceUses) {
		return ErrRecord
	}
	return nil
}
