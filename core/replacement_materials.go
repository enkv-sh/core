package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
)

func compareMaterial(aKind uint16, a contract.ID, bKind uint16, b contract.ID) int {
	if aKind != bKind {
		return int(aKind) - int(bKind)
	}
	return bytes.Compare(a[:], b[:])
}

func (s *StateSession) replacementMaterialRows(ctx context.Context, source, target uint16, successor contract.BindingTableRow) ([]contract.CompactRow, error) {
	generated, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return nil, err
	}
	if len(generated.materials) != int(s.root.AccessRecordCount) {
		return nil, contract.ErrRecord
	}
	emptyConsumers, err := contract.CurrentValueConsumerDigest(s.admission.domain)
	if err != nil {
		return nil, err
	}
	consumerDigest := func(kind uint16, id contract.ID) (contract.ID, error) {
		consumers := generated.consumers[materialIdentity{kind, id}]
		if len(consumers) == 0 {
			return emptyConsumers, nil
		}
		rows := make([][]byte, len(consumers))
		for i, consumer := range consumers {
			var err error
			rows[i], err = contract.EncodeGeneratorConsumer(consumer)
			if err != nil {
				return contract.ID{}, err
			}
		}
		slices.SortFunc(rows, bytes.Compare)
		descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, rows)
		return descriptor.Digest, err
	}
	rows := make([]contract.CompactRow, 0, s.root.AccessRecordCount)
	seen := make(map[materialIdentity]bool, s.root.AccessRecordCount)
	appendRow := func(value contract.ValueCore, seed contract.OperationMaterialCore, immutable contract.ID, access contract.AccessRecord) error {
		key := materialIdentity{access.MaterialKind, access.MaterialID}
		if seen[key] {
			return nil
		}
		seen[key] = true
		if !slices.ContainsFunc(access.Wraps, func(w contract.WrapRow) bool {
			return w.SubjectKind == successor.SubjectKind && w.SubjectID == successor.SubjectID
		}) {
			return nil
		}
		before, err := contract.AccessRecordDigest(access)
		if err != nil {
			return err
		}
		consumers, err := consumerDigest(access.MaterialKind, access.MaterialID)
		if err != nil {
			return err
		}
		rows = append(rows, contract.CompactRow{Coverage: contract.CoverageRow{MaterialKind: access.MaterialKind, MaterialID: access.MaterialID,
			MaterialContextDigest: access.MaterialContextDigest, ImmutableBodyDigest: immutable, BeforeAccessDigest: before,
			RequiredConsumerDigest: consumers, SourceBindingIndex: source, TargetBindingIndices: []uint16{target}},
			ValueCore: value, OperationMaterialCore: seed, BeforeAccessRecord: access})
		return nil
	}
	for _, entry := range s.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry == nil || valueEntry.ConfidentialityClass != contract.Secret {
			continue
		}
		core, payload, access, ok := s.selectedValue(entry.Slot)
		if !ok {
			return nil, contract.ErrRecord
		}
		immutable, err := contract.ValueImmutableBodyDigest(core, payload)
		if err != nil {
			return nil, err
		}
		if err := appendRow(core, contract.OperationMaterialCore{}, immutable, access); err != nil {
			return nil, err
		}
	}
	for _, retained := range generated.canonical {
		immutable, err := contract.ValueImmutableBodyDigest(retained.core, retained.payload)
		if err != nil {
			return nil, err
		}
		if err := appendRow(retained.core, contract.OperationMaterialCore{}, immutable, retained.access); err != nil {
			return nil, err
		}
	}
	for key := range generated.materials {
		if key.kind != contract.OperationSeedMaterialKind {
			continue
		}
		row, ok := generated.records[generatedRecordKey{contract.OperationMaterialSupportKind, key.id}]
		if !ok {
			return nil, contract.ErrRecord
		}
		material, err := contract.InspectOperationMaterialRecord(row.Body)
		if err != nil {
			return nil, err
		}
		if material.Core.OperationMaterialID != key.id {
			return nil, contract.ErrRecord
		}
		access, ok := s.materialAccess(key.kind, key.id)
		if !ok {
			return nil, contract.ErrRecord
		}
		immutable, err := contract.OperationImmutableBodyDigest(material.Core, material.SeedCheck)
		if err != nil {
			return nil, err
		}
		if err := appendRow(contract.ValueCore{}, material.Core, immutable, access); err != nil {
			return nil, err
		}
	}
	if len(seen) != int(s.root.AccessRecordCount) {
		return nil, contract.ErrRecord
	}
	slices.SortFunc(rows, func(a, b contract.CompactRow) int {
		return compareMaterial(a.Coverage.MaterialKind, a.Coverage.MaterialID, b.Coverage.MaterialKind, b.Coverage.MaterialID)
	})
	return rows, nil
}
