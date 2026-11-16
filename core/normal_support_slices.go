package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

// normalReceiptSlices is scoped to one privately derived normal successor.
// It contains public coordinates only, never an input, support body or parent.
type normalReceiptSlices struct {
	beforeRevision, beforeRoot   contract.ID
	domain, snapshot, transition contract.ID
	descriptor                   contract.GeneratorDescriptor
	locations                    []contract.GeneratorSliceLocation
}

// normalSupportSlices reads the complete exact directory carried by a normal
// support transform. Other vector families do not contribute directory rows.
func normalSupportSlices(domain, snapshot contract.ID, rows []contract.SupportRecord) (contract.GeneratorDescriptor, []contract.GeneratorSliceLocation, error) {
	if domain.IsZero() || snapshot.IsZero() {
		return contract.GeneratorDescriptor{}, nil, contract.ErrRecord
	}
	declared := contract.EmptyGeneratorVector(contract.GeneratorVectorSlices)
	var bodies [][]byte
	for _, row := range rows {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return contract.GeneratorDescriptor{}, nil, err
		}
		if carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil || id != row.RecordID || carrier.DomainID != domain || carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.OwnerID != snapshot || len(bodies) != 0 && carrier.Vector != declared {
			return contract.GeneratorDescriptor{}, nil, contract.ErrRecord
		}
		declared = carrier.Vector
		bodies = append(bodies, carrier.Row)
	}
	slices.SortFunc(bodies, func(a, b []byte) int { return bytes.Compare(a[2:35], b[2:35]) })
	descriptor, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, bodies)
	if err != nil || descriptor != declared {
		return contract.GeneratorDescriptor{}, nil, contract.ErrRecord
	}
	locations := make([]contract.GeneratorSliceLocation, len(bodies))
	for i, body := range bodies {
		locations[i], err = contract.InspectGeneratorSliceLocation(body)
		if err != nil {
			return contract.GeneratorDescriptor{}, nil, err
		}
	}
	return descriptor, locations, nil
}

func (s *StateSession) bindNormalReceiptSlicePlan(c *Comparison, next *StateSession, p transitionPlan) error {
	if s == nil || c == nil || c.session != s || next == nil || next.normalReceiptSlices != nil ||
		next.root.Domain != s.root.Domain || next.root.Snapshot != p.snapshot || next.root.Transition != p.transition || p.snapshot.IsZero() || p.transition.IsZero() {
		return contract.ErrRecord
	}
	if c.support == nil && !c.outputChanged {
		return nil
	}
	if !normalSupportPredecessorMatches(c) {
		return contract.ErrRecord
	}
	after, err := generatedNormalSupportRows(c, p)
	if err != nil {
		return err
	}
	descriptor, locations, err := normalSupportSlices(s.root.Domain, normalSupportSliceOwner(c, p), after.Records)
	if err != nil {
		return err
	}
	if descriptor == s.root.Generated.Slices && slices.Equal(locations, s.generatedSliceLocations) {
		return nil
	}
	beforeRoot, ok := s.generatedSelectionRoot()
	if !ok || s.generatedSlicesRoot != beforeRoot {
		return contract.ErrRecord
	}
	if !generatedSlicesSurvive(s.generatedSliceLocations, locations) {
		return contract.ErrRecord
	}
	next.normalReceiptSlices = &normalReceiptSlices{beforeRevision: s.head.Core.Revision, beforeRoot: s.head.Core.Root.Digest,
		domain: next.root.Domain, snapshot: p.snapshot, transition: p.transition, descriptor: descriptor, locations: locations}
	return nil
}

func generatedSlicesSurvive(before, after []contract.GeneratorSliceLocation) bool {
	for _, location := range after {
		for len(before) != 0 && before[0] != location {
			before = before[1:]
		}
		if len(before) == 0 {
			return false
		}
		before = before[1:]
	}
	return true
}

// A support witness rebinds Snapshot carriers. An output-only transform keeps
// the predecessor carriers until the receipt encoder performs that rebind.
func normalSupportSliceOwner(c *Comparison, p transitionPlan) contract.ID {
	if c.support != nil {
		return p.snapshot
	}
	return c.session.adminIndex.SliceSnapshot
}
