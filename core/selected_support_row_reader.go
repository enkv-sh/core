package core

import (
	"context"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedRefBorrow returns one exact selected object for synchronous use.
// The body may borrow Store backing. It is read-only and must not be retained
// or used after the consumer call.
type selectedRefBorrow func(context.Context, format.Ref) ([]byte, Result)

// withAuthenticatedSupportRows checks every selected row against one immutable
// page Ref before lending any row. Physical rows omitted from facts are never
// passed to the caller. The caller first binds facts to its signed Root and
// administrative spans; this helper grants no Store write or admission reach.
func withAuthenticatedSupportRows(ctx context.Context, read selectedRefBorrow, domain contract.ID,
	facts selectedSupportPageFacts, consume func(uint16, uint16, contract.SupportRecordView) error) (Result, error) {
	if ctx == nil || ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	if facts.plannedReceipt != nil || read == nil || consume == nil || domain.IsZero() || !facts.ref.ValidFor(format.Version) ||
		facts.ref.Kind != contract.RequiredSupportKind || facts.ref.Domain != domain ||
		len(facts.rows) == 0 || len(facts.rows) != len(facts.ordinals) {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	body, result := read(ctx, facts.ref)
	if result.Outcome != 0 {
		return result, nil
	}
	if result != (Result{}) {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	if ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	if uint64(len(body)) != uint64(facts.ref.Length) || contract.Hash(body) != facts.ref.Digest {
		return failure(IntegrityFailure, InvalidReference), nil
	}
	page, err := format.InspectRequiredSupportPage(body)
	if err != nil || page.Domain != domain || page.Object != facts.ref.Object || page.Index != facts.ref.Index {
		return failure(IntegrityFailure, InvalidReference), nil
	}
	for logical, physical := range facts.ordinals {
		if int(physical) >= len(page.Records) || logical > 0 && physical <= facts.ordinals[logical-1] {
			return failure(IntegrityFailure, InvalidRelation), nil
		}
		actual, err := contract.InspectSupportRecordDigest(domain, contract.SupportRecord(page.Records[physical]))
		if err != nil || actual != facts.rows[logical] {
			return failure(IntegrityFailure, InvalidRelation), nil
		}
	}
	for logical, physical := range facts.ordinals {
		if ctx.Err() != nil {
			return failure(EvidenceUnavailable, ReadUnavailable), nil
		}
		if err := consume(uint16(logical), physical, page.Records[physical]); err != nil {
			return Result{}, err
		}
	}
	if ctx.Err() != nil {
		return failure(EvidenceUnavailable, ReadUnavailable), nil
	}
	return Result{}, nil
}

// withAuthenticatedSupportRow lends one checked logical row from a selected
// page. It shares the whole-page validation so another damaged selected row
// cannot be ignored by a caller that reads only this row.
func withAuthenticatedSupportRow(ctx context.Context, read selectedRefBorrow, domain contract.ID,
	facts selectedSupportPageFacts, logical uint16, consume func(contract.SupportRecordView) error) (Result, error) {
	if int(logical) >= len(facts.rows) || consume == nil {
		return failure(IntegrityFailure, InvalidRelation), nil
	}
	return withAuthenticatedSupportRows(ctx, read, domain, facts,
		func(slot uint16, _ uint16, row contract.SupportRecordView) error {
			if slot == logical {
				return consume(row)
			}
			return nil
		})
}
