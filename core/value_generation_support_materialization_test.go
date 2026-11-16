package core

import (
	"bytes"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedMaterializerFragment(t testing.TB, blob contract.ID, payload []byte) contract.SupportRecord {
	t.Helper()
	fragment := contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1, TotalLength: uint64(len(payload)),
		WholeDigest: contract.Hash(payload), Payload: payload}
	body, err := contract.EncodeGeneratedFragment(fragment)
	if err != nil {
		t.Fatal(err)
	}
	id, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	return contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body}
}

// full_only: false
func TestMaterializeGeneratedRequiredSupportMatchesIndependentPageConstruction(t *testing.T) {
	domain := generatedVectorID(70)
	rows := [][]contract.SupportRecord{
		{generatedMaterializerFragment(t, generatedVectorID(71), []byte("first fragment"))},
		{generatedMaterializerFragment(t, generatedVectorID(72), []byte("second fragment"))},
	}
	pageIDs := []contract.ID{generatedVectorID(73), generatedVectorID(74)}

	got, err := materializeGeneratedRequiredSupport(domain, rows, pageIDs)
	if err != nil {
		t.Fatal(err)
	}
	if got.recordCount != 2 || len(got.objects) != 2 || len(got.references) != 2 || len(got.views) != 2 || len(got.identityPages) != 2 {
		t.Fatalf("wrong materialized counts: %+v", got)
	}
	for i := range rows {
		page := format.RequiredSupportPage{Domain: domain, Object: pageIDs[i], Index: uint16(i), Records: rows[i]}
		body, err := format.EncodeRequiredSupportPage(page)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := format.Reference(contract.RequiredSupportKind, domain, pageIDs[i], uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		identity := contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: uint16(i), Object: pageIDs[i]}
		if !bytes.Equal(got.objects[i].body, body) || got.objects[i].ref != ref || got.references[i] != ref || got.identityPages[i] != identity {
			t.Fatalf("page %d differs from independent construction", i)
		}
		if got.views[i].Domain != domain || got.views[i].Object != pageIDs[i] || got.views[i].Index != uint16(i) ||
			len(got.views[i].Records) != 1 || got.views[i].Records[0].Kind != rows[i][0].Kind ||
			got.views[i].Records[0].RecordID != rows[i][0].RecordID || !bytes.Equal(got.views[i].Records[0].Body, rows[i][0].Body) {
			t.Fatalf("page %d view differs from independent construction", i)
		}
	}
	wantDirectory := []format.FragmentLocation{
		{BlobID: generatedVectorID(71), SupportPageIndex: 0, RowSlot: 0},
		{BlobID: generatedVectorID(72), SupportPageIndex: 1, RowSlot: 0},
	}
	if !reflect.DeepEqual(got.fragments, wantDirectory) {
		t.Fatalf("wrong fragment directory: got %+v want %+v", got.fragments, wantDirectory)
	}
	offset := bytes.Index(got.objects[0].body, got.views[0].Records[0].Body)
	if offset < 0 {
		t.Fatal("borrowed view body is absent from its encoded object")
	}
	before := got.views[0].Records[0].Body[0]
	got.objects[0].body[offset] ^= 0xff
	if got.views[0].Records[0].Body[0] == before {
		t.Fatal("view does not borrow its encoded object's backing")
	}
}

// full_only: false
func TestMaterializeGeneratedRequiredSupportRefusesMalformedInputWithoutPartialConstruction(t *testing.T) {
	domain := generatedVectorID(80)
	valid := generatedMaterializerFragment(t, generatedVectorID(81), []byte("fragment"))
	invalid := valid
	invalid.Body = []byte{0}
	oversized := valid
	oversized.Body = make([]byte, contract.GeneratedFragmentMaxLength+1)
	tooMany := make([][]contract.SupportRecord, contract.MaxChildPages+1)
	tooManyIDs := make([]contract.ID, len(tooMany))
	for i := range tooMany {
		tooMany[i] = []contract.SupportRecord{valid}
		tooManyIDs[i] = contract.ID{1, byte(i), byte(i >> 8)}
	}
	for name, tc := range map[string]struct {
		rows [][]contract.SupportRecord
		ids  []contract.ID
	}{
		"count mismatch": {[][]contract.SupportRecord{{valid}}, nil},
		"zero id":        {[][]contract.SupportRecord{{valid}}, []contract.ID{{}}},
		"duplicate id":   {[][]contract.SupportRecord{{valid}, {valid}}, []contract.ID{generatedVectorID(82), generatedVectorID(82)}},
		"invalid row":    {[][]contract.SupportRecord{{valid}, {invalid}}, []contract.ID{generatedVectorID(83), generatedVectorID(84)}},
		"oversized row":  {[][]contract.SupportRecord{{valid}, {oversized}}, []contract.ID{generatedVectorID(85), generatedVectorID(86)}},
		"too many pages": {tooMany, tooManyIDs},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := materializeGeneratedRequiredSupport(domain, tc.rows, tc.ids)
			if err == nil {
				t.Fatal("accepted malformed materialization")
			}
			if !reflect.DeepEqual(got, generatedRequiredSupportMaterialization{}) {
				t.Fatalf("returned usable partial construction: %+v", got)
			}
		})
	}

	got, err := materializeGeneratedRequiredSupport(domain, nil, nil)
	if err != nil || !reflect.DeepEqual(got, generatedRequiredSupportMaterialization{}) {
		t.Fatal("empty support is not the empty construction", got, err)
	}
}
