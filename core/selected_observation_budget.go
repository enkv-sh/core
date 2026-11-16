package core

import (
	"enkv.sh/core/contract"
)

// selectedObservationExtraReads bounds exact-ref rereads after the selected
// child scan. Each logical content read can touch every selected fragment row,
// including two rows that share one physical page. The count comes only from
// the just-authenticated Root and selected support rows, never from the
// requested candidate: a competing HEAD can select a different valid image.
func selectedObservationExtraReads(s *selectedImage, mode selectedScanMode) (uint64, error) {
	if s == nil || len(s.support) != len(s.root.RequiredSupport) || len(s.supportFacts) != len(s.support) ||
		len(s.root.Generated.Fragments) != len(s.fragmentFacts) {
		return 0, contract.ErrRecord
	}
	var parents, attempts, duties, hazards, history, owners uint64
	for i, page := range s.support {
		facts := s.supportFacts[i]
		if facts.ref != s.root.RequiredSupport[i] || page.Index != facts.ref.Index ||
			len(page.Records) != len(facts.rows) || len(page.Records) != len(facts.ordinals) {
			return 0, contract.ErrRecord
		}
		for j, row := range page.Records {
			if row.Kind != facts.rows[j].Kind() || row.RecordID != facts.rows[j].RecordID() {
				return 0, contract.ErrRecord
			}
			switch row.Kind {
			case contract.GeneratedParentSupportKind:
				parents++
				owners++
			case contract.GeneratedAttemptSupportKind:
				attempts++
				owners++
			case contract.GeneratedDutySupportKind:
				duties++
				owners++
			case contract.GeneratedHazardSupportKind:
				hazards++
				owners++
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					return 0, err
				}
				if carrier.VectorKind == contract.GeneratorVectorHistory {
					history++
				}
			case contract.GeneratedFragmentSupportKind, contract.OutputConfigurationSliceSupportKind:
			default:
				owners++
			}
		}
	}
	fragments := uint64(len(s.root.Generated.Fragments))
	slices := uint64(s.root.Generated.Slices.Count)
	// A selected Slice carrier cannot authorize itself. An active Parent can
	// claim at most one Declaration with 512 entries (one Intent and one
	// Source per entry), its Graph, and one Configuration. Every detached
	// Graph/Intent claim has a selected typed owner or a History item; three
	// locations per such owner is conservative. Current generated entries
	// can each claim one Intent. Complete content validation still checks
	// every exact key and byte digest after this read-free orphan preflight.
	if slices > 1027*parents+uint64(s.root.Generated.GeneratedCurrent)+3*(owners+history) {
		return 0, contract.ErrRecord
	}
	// Relation coverage reads each current generated intent, each distinct
	// selected graph, and retained attempt/duty/hazard evidence. Per active
	// Parent, the bounds are two Declaration reads, one Configuration read,
	// 128 create Lineages and 512 SourceUses. A History carrier is one row of
	// a bounded vector, charged for its repeated hazard/cleanup traversals.
	// Graphs <= Slices; ValueEntryCount also covers invalid pre-relation rows.
	relations := uint64(s.root.ValueEntryCount) + slices +
		(3+contract.GeneratorMaxCreateLineages+contract.CryptoMaxValueEntries)*parents +
		2*(attempts+duties+hazards) + 4*history
	// Whole-blob validation reads each fragment once. Each selected Slice and
	// each relation/proof logical read can intersect at most all fragments.
	// The signed-family proof adds at most three logical reads after relation
	// reuse; the receipt-index blob adds at most one more full-fragment pass.
	return fragments*(slices+relations+5) + uint64(s.root.OutputConfiguration.SliceCount), nil
}
