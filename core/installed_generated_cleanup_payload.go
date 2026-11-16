package core

import (
	"slices"
	"strings"
	"unsafe"

	"enkv.sh/core/contract"
)

type GeneratedCleanupBasisKind uint8

const (
	GeneratedCleanupNoWork GeneratedCleanupBasisKind = iota + 1
	GeneratedCleanupReflection
	GeneratedCleanupOwnedTarget
)

type GeneratedCleanupBasis struct {
	Kind                                   GeneratedCleanupBasisKind
	PlanGraphID                            contract.ID
	SourceKind                             contract.SupportRecordKind
	SourceID, OriginalOwnerID              contract.ID
	OriginalOperationID, OriginalAttemptID contract.ID
	OriginalResult                         *contract.GeneratorResultReference
	Target                                 *contract.GeneratorTarget
}

type GeneratedCleanupWorkBasis struct {
	HeadRevisionID contract.ID
	Snapshot       contract.Ref
}

type GeneratedCleanupSiblingCommitment struct {
	Count      uint32
	RootDigest contract.ID
}

// RemainingInboxIDs names only selected PendingInboxRelease mappings. These
// observation-scoped identities do not enumerate unfinished originals or Store
// garbage, and do not establish currentness after a competing or unknown CAS.
type GeneratedCleanupPayload struct {
	Schema                                                  uint16
	Basis                                                   GeneratedCleanupBasis
	PredecessorRevisionID                                   contract.ID
	RemainingWorkBasis                                      GeneratedCleanupWorkBasis
	SiblingResults                                          GeneratedCleanupSiblingCommitment
	RemainingDutyIDs, RemainingHazardIDs, RemainingInboxIDs []contract.ID
}

func ownedGeneratedCleanupBasis(basis GeneratedCleanupBasis) GeneratedCleanupBasis {
	if basis.Target != nil {
		target := *basis.Target
		target.Name = strings.Clone(target.Name)
		basis.Target = &target
	}
	if basis.OriginalResult != nil {
		result := *basis.OriginalResult
		basis.OriginalResult = &result
	}
	return basis
}

func captureGeneratedCleanupPayload(s *StateSession, work *generatedSelection, basis GeneratedCleanupBasis, predecessor contract.ID) (*GeneratedCleanupPayload, error) {
	if s == nil || work == nil || work.image == nil || work.image.root.Snapshot != s.root.Snapshot || work.image.root.Domain != s.root.Domain {
		return nil, contract.ErrRecord
	}
	counts := [3]int{}
	for key := range work.records {
		switch key.kind {
		case contract.GeneratedDutySupportKind:
			counts[0]++
		case contract.GeneratedHazardSupportKind:
			counts[1]++
		case contract.PendingInboxReleaseSupportKind:
			counts[2]++
		}
	}
	if uint64(counts[0])+uint64(counts[1])+uint64(counts[2]) > GeneratedResultWorkLimit {
		return nil, contract.ErrRecordCapacity
	}
	out := &GeneratedCleanupPayload{Schema: 1, Basis: ownedGeneratedCleanupBasis(basis), PredecessorRevisionID: predecessor,
		RemainingWorkBasis: GeneratedCleanupWorkBasis{HeadRevisionID: s.head.Core.Revision, Snapshot: s.head.Core.Root},
		RemainingDutyIDs:   make([]contract.ID, counts[0]), RemainingHazardIDs: make([]contract.ID, counts[1]), RemainingInboxIDs: make([]contract.ID, counts[2])}
	positions := [3]int{}
	for key := range work.records {
		switch key.kind {
		case contract.GeneratedDutySupportKind:
			out.RemainingDutyIDs[positions[0]] = key.id
			positions[0]++
		case contract.GeneratedHazardSupportKind:
			out.RemainingHazardIDs[positions[1]] = key.id
			positions[1]++
		case contract.PendingInboxReleaseSupportKind:
			out.RemainingInboxIDs[positions[2]] = key.id
			positions[2]++
		}
	}
	slices.SortFunc(out.RemainingDutyIDs, compareGeneratedIDs)
	slices.SortFunc(out.RemainingHazardIDs, compareGeneratedIDs)
	slices.SortFunc(out.RemainingInboxIDs, compareGeneratedIDs)
	return out, nil
}

// Charge each independently owned allocation once. Both candidate and observed
// variants can coexist; sharing is an optimization, never a required bound.
func generatedCleanupPayloadBackingBytes(payloads ...*GeneratedCleanupPayload) (uint64, error) {
	var total uint64
	seen := make(map[*GeneratedCleanupPayload]bool)
	ids := make(map[*contract.ID]uint64)
	targets := make(map[*contract.GeneratorTarget]bool)
	results := make(map[*contract.GeneratorResultReference]bool)
	names := make(map[*byte]bool)
	for _, p := range payloads {
		if p == nil || seen[p] {
			continue
		}
		seen[p] = true
		total += uint64(unsafe.Sizeof(*p))
		var count uint64
		for _, rows := range [][]contract.ID{p.RemainingDutyIDs, p.RemainingHazardIDs, p.RemainingInboxIDs} {
			count += uint64(cap(rows))
			if len(rows) > 0 {
				pointer, size := unsafe.SliceData(rows), uint64(cap(rows))*32
				if size > ids[pointer] {
					total += size - ids[pointer]
					ids[pointer] = size
				}
			}
		}
		if count > GeneratedResultWorkLimit {
			return 0, contract.ErrRecordCapacity
		}
		if target := p.Basis.Target; target != nil && !targets[target] {
			targets[target] = true
			total += uint64(unsafe.Sizeof(*target))
			if len(target.Name) > 0 && !names[unsafe.StringData(target.Name)] {
				names[unsafe.StringData(target.Name)] = true
				total += uint64(len(target.Name))
			}
		}
		if result := p.Basis.OriginalResult; result != nil && !results[result] {
			results[result] = true
			total += uint64(unsafe.Sizeof(*result))
		}
	}
	return total, nil
}
