package format

import (
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestAdministrativeIndexReadRequiredAndUnreadableRowSummary(t *testing.T) {
	domain := fid(1)
	ref := Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: domain,
		Object: fid(2), Digest: fid(3), Length: contract.RequiredSupportPageHeaderLength + contract.SupportRecordMinLength}
	index := AdministrativeIndex{Domain: domain, Object: fid(4), SliceSnapshot: fid(5), Pages: []AdministrativePage{{
		Ref: ref, Spans: []AdministrativeSpan{{First: 0, Count: 1, Mandatory: true}},
		Rows: []AdministrativeRowSummary{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fid(6), BodyLength: 87}},
	}}}
	body, err := EncodeAdministrativeIndex(index)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAdministrativeIndex(body)
	if err != nil || decoded.Domain != index.Domain || decoded.Object != index.Object ||
		decoded.SliceSnapshot != index.SliceSnapshot || len(decoded.Pages) != 1 ||
		len(decoded.Pages[0].Rows) != 1 || decoded.Pages[0].Rows[0] != index.Pages[0].Rows[0] {
		t.Fatal("row summaries lost", err)
	}
	index.Pages[0].ReadRequired = true
	index.Pages[0].Rows = nil
	if _, err := EncodeAdministrativeIndex(index); err != nil {
		t.Fatal("read-required page refused", err)
	}
	index.Pages[0].Rows = []AdministrativeRowSummary{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fid(6), BodyLength: 87}}
	if _, err := EncodeAdministrativeIndex(index); err == nil {
		t.Fatal("read-required page accepted redundant row summaries")
	}
}
