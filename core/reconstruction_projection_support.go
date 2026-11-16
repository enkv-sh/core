package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// projectionSupportFactsBound checks the selected physical ordinal sequence
// against the signed administrative spans before an exact page read lends
// those rows to the projection owner. Obsolete physical rows are not emitted.
func projectionSupportFactsBound(root format.Root, index format.AdministrativeIndex,
	facts []selectedSupportPageFacts) bool {
	if len(facts) != len(root.RequiredSupport) || len(index.Pages) != len(facts) {
		return false
	}
	var total uint64
	for i, selected := range facts {
		page := index.Pages[i]
		if selected.ref != root.RequiredSupport[i] || !projectionSupportPageFactsBound(page, selected) {
			return false
		}
		total += uint64(len(selected.rows))
	}
	return total == uint64(root.RequiredSupportRecordCount)
}

func projectionSupportPageFactsBound(page format.AdministrativePage, selected selectedSupportPageFacts) bool {
	if page.Ref != selected.ref || len(selected.rows) == 0 || len(selected.rows) != len(selected.ordinals) ||
		!page.ReadRequired && len(page.Rows) != len(selected.rows) ||
		page.ReadRequired && len(page.Rows) != 0 {
		return false
	}
	logical := 0
	for _, span := range page.Spans {
		for ordinal := uint32(span.First); ordinal < uint32(span.First)+uint32(span.Count); ordinal++ {
			if logical >= len(selected.rows) || selected.ordinals[logical] != uint16(ordinal) {
				return false
			}
			fact := selected.rows[logical]
			if page.ReadRequired {
				if fact.Kind() != contract.GeneratorVectorSupportKind {
					return false
				}
			} else {
				row := page.Rows[logical]
				if row.Kind != uint8(fact.Kind()) || row.RecordID != fact.RecordID() ||
					row.BodyLength != fact.BodyLength() {
					return false
				}
			}
			logical++
		}
	}
	return logical == len(selected.rows)
}

// emitReconstructionSupportRows emits every selected support record body and
// its kind, ID, reference and physical ordinal. The consumer must not mutate
// borrowed bytes or retain them without making its own bounded copy. The
// helper authenticates a complete physical page before any callback and reads
// it only once; no omitted physical row becomes selected or empty state.
func emitReconstructionSupportRows(ctx context.Context, selected *publicSelection,
	consumer reconstructionProjectionConsumer, progress reconstructionProjectionProgress) (reconstructionProjectionProgress, Result) {
	if selected == nil || !selected.complete || consumer == nil || selected.basis.reader.source == nil ||
		selected.image.root.Domain != selected.basis.reader.domain ||
		!projectionSupportFactsBound(selected.image.root, selected.image.adminIndex, selected.image.supportFacts) {
		return progress, refused(AdmissionInvalid)
	}
	anchor := selected.basis.anchor
	if !reconstructionInvocationCurrent(ctx, anchor) {
		return progress, failure(EvidenceUnavailable, ReadUnavailable)
	}
	maxBytes := selected.image.root.ChildEncodedBytes +
		uint64(len(anchor.configBody)+len(anchor.headBody)+len(anchor.rootBody))
	read := func(ctx context.Context, ref format.Ref) ([]byte, Result) {
		body, _, result := selected.basis.reader.readBorrowed(ctx, ref)
		return body, result
	}
	for _, facts := range selected.image.supportFacts {
		var callbackResult Result
		result, err := withAuthenticatedSupportRows(ctx, read, selected.image.root.Domain, facts,
			func(_ uint16, physical uint16, row contract.SupportRecordView) error {
				callbackResult = acceptReconstructionPart(ctx, anchor, consumer, &progress, maxBytes,
					reconstructionProjectionPart{kind: reconstructionSupportRowPart, ref: facts.ref,
						physicalOrdinal: physical, supportKind: row.Kind, recordID: row.RecordID, body: row.Body})
				if callbackResult != (Result{}) {
					return contract.ErrRecord
				}
				return nil
			})
		if callbackResult != (Result{}) {
			return progress, callbackResult
		}
		if result != (Result{}) {
			return progress, result
		}
		if err != nil {
			return progress, failure(IntegrityFailure, InvalidRelation)
		}
	}
	return progress, Result{}
}
