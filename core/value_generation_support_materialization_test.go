package core

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// full_only: false
func TestMaximumGeneratedSupportGroupsReopen(t *testing.T) {
	// A 65,536-byte value uses 87,384 bytes of padded Base64. The four
	// result fields contribute 452, 4,096, 215+87,384, and 474 bytes.
	const logical, retained = 65_536, 87_384
	entry := *generatedSelectedEntryState(t).pages[0].Slots[0]
	entry.Name = strings.Repeat("n", 256)
	entry.Recipients = nil
	for i := byte(1); i <= 64; i++ {
		entry.Recipients = append(entry.Recipients, generatedVectorID(i))
	}
	entry.Generated.RetiringDutyPresent, entry.Generated.RetiringDutyID = 1, generatedVectorID(91)
	entry.InputEncoding, entry.ContentLength, entry.RetainedLength = contract.InputEncodingBase64, logical, retained
	payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.InputEncoding, payload.ContentLength, payload.RetainedLength = entry.InputEncoding, logical, retained
	payload.Ciphertext = bytes.Repeat([]byte{90}, retained+16)
	entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{Entry: entry})
	// Entry framing 154, name 256, 64 membership IDs, payload 87,599,
	// current metadata with a retiring Duty 422, retained header 8.
	if err != nil || len(canonical)+37 != 90_524 {
		t.Fatal("maximum retained row", len(canonical), err)
	}
	_, reservation := observationReservationFixture(t, "generated")
	work := mustSelectedGeneratedWork(t, reservation.state)
	attempt := work.attempts[work.phase.FrontierAttemptID]
	base, err := contract.DecodeGeneratedResultRecord(generatedPublicResultFixture(t, attempt, contract.GeneratorDispositionCompleteCreate))
	if err != nil {
		t.Fatal(err)
	}
	base.SafeFacts.ProviderFacts = bytes.Repeat([]byte{3}, 4096-115-len(base.SafeFacts.Target)-len(base.SafeFacts.ResourceData))
	base.Core.SafeFactsDigest, err = contract.GeneratorSafeFactsDigest(base.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	base.Payload.InputEncoding, base.Payload.ContentLength, base.Payload.RetainedLength = entry.InputEncoding, logical, retained
	base.Payload.Ciphertext = payload.Ciphertext
	domain := base.Core.DomainID
	makeResult := func(number byte) contract.SupportRecord {
		t.Helper()
		result := base
		core := &result.Core
		core.AttemptID = generatedVectorID(number)
		core.TransmissionID, err = contract.GeneratorTransmissionID(core.AttemptID, contract.GeneratorActionCreate)
		if err != nil {
			t.Fatal(err)
		}
		core.ResultID, err = contract.GeneratorResultID(domain, core.OperationID, core.AttemptID, core.TransmissionID, contract.GeneratorActionCreate)
		if err != nil {
			t.Fatal(err)
		}
		result.Payload.DataKeyID, result.Payload.CommitmentKeyID, err = contract.GeneratorResultKeyIDs(core.ResultID)
		if err != nil {
			t.Fatal(err)
		}
		result.Transfer.Core.AttemptID, result.Transfer.Core.ResultID = core.AttemptID, core.ResultID
		result.Transfer.Core.ResultCoreDigest, err = contract.GeneratedResultCoreDigest(*core)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratedResultRecord(result)
		if err != nil || len(body)+37 != 92_674 {
			t.Fatal("maximum result row", len(body), err)
		}
		return contract.SupportRecord{Kind: contract.GeneratedResultSupportKind, RecordID: core.ResultID, Body: body}
	}
	canonicalRow := contract.SupportRecord{Kind: contract.RetainedCanonicalSupportKind, RecordID: entry.ValueState, Body: canonical}
	// The packer permits the two old-value record kinds under one owner.
	evidenceCore := base.Core
	evidenceCore.ResultID = entry.ValueState
	resultCore, err := contract.EncodeGeneratedResultCore(evidenceCore)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := contract.EncodeGeneratorSafeFacts(base.SafeFacts)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := contract.EncodeGeneratedCreateEvidence(contract.GeneratedCreateEvidence{
		Schema: contract.GeneratedCreateEvidenceSchema, LifecycleMode: base.SafeFacts.LifecycleMode,
		OriginalResultID: evidenceCore.ResultID, CredentialRouteID: attempt.expected.Template.CredentialRouteID,
		Intent:     contract.GeneratorDescriptor{Digest: generatedVectorID(30), Length: 73, Count: 1},
		ResultCore: resultCore, SafeFacts: facts, CompletionClass: contract.GeneratedCompletionAcknowledged,
	})
	if err != nil || len(evidence)+37 != 4705 {
		t.Fatal("maximum evidence row", len(evidence), err)
	}
	evidenceRow := contract.SupportRecord{Kind: contract.GeneratedCreateEvidenceSupportKind, RecordID: evidenceCore.ResultID, Body: evidence}
	results := make([]format.RequiredSupportGroup, 23)
	for i := range results {
		row := makeResult(byte(i + 1))
		results[i] = format.RequiredSupportGroup{Class: format.ResultSupport, Owner: row.RecordID, Records: []contract.SupportRecord{row}}
	}
	// 22 maximum groups fit on one page. Moving one group to the mandatory
	// partition requires a second page, even when their total is unchanged.
	for _, tc := range []struct{ count, mandatory, pages int }{{22, 0, 1}, {23, 0, 2}, {22, 1, 2}} {
		population := make(continuationPopulation)
		for i, group := range results[:tc.count] {
			population[continuationGroupKey{group.Class, group.Owner, i < tc.mandatory}] = continuationGroupCharge{count: 1, framed: 92_674}
		}
		groups, rows, err := continuationGroupTotals(population, continuationGrowth{})
		want := contract.GeneratorCapacityGroup{MaxCount: uint64(tc.count), MaxFramedBytes: uint64(tc.count) * 92_674, MaxPages: uint32(tc.pages)}
		if err != nil || rows != uint64(tc.count) || groups[contract.GeneratorCapacityCreateResults] != want {
			t.Fatalf("reservation for %d results (%d mandatory): got %+v, rows %d, error %v, want %+v", tc.count, tc.mandatory, groups[contract.GeneratorCapacityCreateResults], rows, err, want)
		}
	}
	excess := results[0]
	excessRow := excess.Records[0]
	excessRow.Body = append(bytes.Clone(excessRow.Body), 0)
	excess.Records = []contract.SupportRecord{excessRow}
	if _, err := format.PackRequiredSupportRows(domain, []format.RequiredSupportGroup{excess}, 0); err == nil {
		t.Fatal("accepted a result one byte above the complete record limit")
	}
	// The same two valid rows fit individually below. Their combined width
	// exceeds the group limit before the page itself would become full.
	overfull := results[0]
	overfull.Records = []contract.SupportRecord{results[0].Records[0], results[1].Records[0]}
	if _, err := format.PackRequiredSupportRows(domain, []format.RequiredSupportGroup{overfull}, 0); err == nil {
		t.Fatal("accepted two maximum rows in one result group")
	}
	for _, c := range []struct {
		name   string
		groups []format.RequiredSupportGroup
		widths []int
	}{
		{"old", []format.RequiredSupportGroup{{Class: format.OldValueSupport, Owner: entry.ValueState, Records: []contract.SupportRecord{canonicalRow, evidenceRow}}}, []int{75 + 90_524 + 4705}},
		{"candidate", []format.RequiredSupportGroup{{Class: format.CandidateValueSupport, Owner: entry.ValueState, Records: []contract.SupportRecord{canonicalRow}}}, []int{75 + 90_524}},
		{"results", results, []int{75 + 22*92_674, 75 + 92_674}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rows, err := format.PackRequiredSupportRows(domain, c.groups, uint32(256-len(c.widths)))
			if err != nil || len(rows) != len(c.widths) {
				t.Fatal("cannot pack supported rows in reserved pages", len(rows), err)
			}
			if _, err := format.PackRequiredSupportRows(domain, c.groups, uint32(257-len(c.widths))); err == nil {
				t.Fatal("packing exceeded the reserved child limit")
			}
			want := make(map[generatedRecordKey][]byte)
			for _, group := range c.groups {
				for _, row := range group.Records {
					want[generatedRecordKey{row.Kind, row.RecordID}] = row.Body
				}
			}
			for i, page := range rows {
				body, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: domain, Object: generatedVectorID(byte(i + 10)), Index: uint16(i), Records: page})
				if err != nil || len(body) != c.widths[i] {
					t.Fatal("encoded page size", len(body), err)
				}
				path := filepath.Join(t.TempDir(), "page")
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
				stored, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				view, err := format.InspectRequiredSupportPage(stored)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range view.Records {
					key := generatedRecordKey{row.Kind, row.RecordID}
					if !bytes.Equal(want[key], row.Body) {
						t.Fatal("reopened row differs", row.RecordID)
					}
					delete(want, key)
				}
			}
			if len(want) != 0 {
				t.Fatal("missing persisted rows", len(want))
			}
		})
	}
}
