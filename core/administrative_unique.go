package core

import (
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The partial reader cannot inspect optional bodies. Their authenticated row
// summaries must therefore establish the same global key uniqueness that the
// complete generated reader checks from physical selected records.
func administrativeSelectedKeysUnique(index format.AdministrativeIndex, support []format.RequiredSupportPageView) bool {
	if !index.Valid() || len(index.Pages) != len(support) {
		return false
	}
	seen := make(map[generatedRecordKey]bool)
	for i, page := range index.Pages {
		var rows []format.AdministrativeRowSummary
		if page.ReadRequired {
			for _, row := range support[i].Records {
				rows = append(rows, format.AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
			}
		} else {
			rows = page.Rows
		}
		for _, row := range rows {
			key := generatedRecordKey{kind: contract.SupportRecordKind(row.Kind), id: row.RecordID}
			if seen[key] {
				return false
			}
			seen[key] = true
		}
	}
	return true
}
