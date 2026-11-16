package core

import "enkv.sh/core/contract"

func (b *generatedSelectionBuilder) resolveActiveSources() error {
	if b == nil || b.facts == nil {
		return contract.ErrRecord
	}
	g := b.facts
	if g.parent == nil || g.phase != nil && !g.phase.SelectionPhaseID.IsZero() {
		return nil
	}
	bundle := g.bundles[0]
	if len(bundle.SourceUses) == 0 {
		return nil
	}
	material, err := b.operationMaterial(bundle)
	if err != nil {
		return err
	}
	body, err := b.content.read(contract.GeneratorContentConfiguration, material.Core.OperationMaterialID, 1<<20)
	if err != nil {
		return err
	}
	protected, err := contract.InspectGeneratedSourceProtections(material, body)
	if err != nil || protected.Count() != len(bundle.SourceUses) {
		return contract.ErrRecord
	}
	key := materialIdentity{contract.OperationSeedMaterialKind, material.Core.OperationMaterialID}
	for i, use := range bundle.SourceUses {
		protection, err := protected.Row(i)
		if err != nil || protection.SourceID != use.SourceID || protection.OriginalSourceCoreDigest != use.SealedInputCoreDigest ||
			protection.OriginalEnvelopeDigest != use.EnvelopeDigest {
			return contract.ErrRecord
		}
		body, err := b.content.readLogical(contract.GeneratorContentSource, use.SourceID, use.SourceSlice, contract.GeneratorDeclarationEntryMaxLength)
		if err != nil {
			return err
		}
		if contract.Hash(body) != use.EnvelopeDigest {
			return contract.ErrRecord
		}
		envelope, err := contract.InspectSealedInputEnvelope(body)
		if err != nil || envelope.Core.DomainID != material.Core.DomainID || envelope.Core.SourceID != use.SourceID ||
			envelope.Core.CompatibilityID != material.Core.CompatibilityID || envelope.Core.CryptoSupportID != material.Core.CryptoSupportID {
			return contract.ErrRecord
		}
		core, err := envelope.Core.Own()
		if err != nil {
			return err
		}
		digest, err := contract.SealedInputCoreDigest(core)
		if err != nil || digest != use.SealedInputCoreDigest {
			return contract.ErrRecord
		}
		rows, err := b.vectors.resolve(contract.GeneratedParentSupportKind, bundle.Header.OperationID, contract.GeneratorVectorConsumers, use.Consumers)
		if err != nil || len(rows) != 1 {
			return contract.ErrRecord
		}
		consumer, err := contract.InspectGeneratorConsumer(rows[0])
		if err != nil {
			return err
		}
		want, err := contract.GeneratorAcceptedSourceConsumer(bundle.Header.OperationID, material.Core.OperationMaterialID, use)
		if err != nil || consumer != want {
			return contract.ErrRecord
		}
		g.consumers[key] = append(g.consumers[key], consumer)
	}
	g.sources[material.Core.OperationMaterialID] = bundle.SourceUses
	g.protected[material.Core.OperationMaterialID] = body
	return nil
}
