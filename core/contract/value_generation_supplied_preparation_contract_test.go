package contract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
)

func generatedSuppliedCryptoFixture(t testing.TB) CryptoGeneratedSuppliedRequest {
	t.Helper()
	context := generatedCryptoCompareFixture(t, 3).Context
	plan, err := EncodeIdentityPlan(IdentityPlan{Operation: generatedRecordID(2), Transition: generatedRecordID(30),
		Snapshot: generatedRecordID(31), Revision: generatedRecordID(32), Rows: []IdentityRow{{Name: "plain", Slot: 2,
			Incarnation: generatedRecordID(33), ValueState: generatedRecordID(34), OriginSnapshot: generatedRecordID(31),
			OriginTransition: generatedRecordID(30)}}})
	if err != nil {
		t.Fatal(err)
	}
	return CryptoGeneratedSuppliedRequest{OperationRef: generatedRecordID(27), Context: context,
		PhaseID: generatedRecordID(28), Final: 1, IdentityPlan: plan}
}

func generatedSuppliedSourceFixture(t testing.TB, request CryptoGeneratedSuppliedRequest, name string) CryptoSealedInput {
	t.Helper()
	sealed, err := EncodeSealedInputEnvelope(SealedInputEnvelope{Core: SealedInputCore{SealedInputCoreFields: SealedInputCoreFields{Schema: SealedInputSchema, Profile: 2,
		CompatibilityID: request.Context.CompatibilityID, DomainID: request.Context.DomainID, FileIdentity: generatedRecordID(98),
		SourceID:        generatedRecordID(99),
		CryptoSupportID: generatedRecordID(102), DataKeyID: generatedRecordID(103), DataKeyEpoch: 1, InputEncoding: InputEncodingRaw, RetainedLength: 0}, Name: name},
		Ciphertext: make([]byte, 16), AuthorityWrap: accessStructuralRow(t, 0, 1, 0).BeforeAccessRecord.Wraps[0]})
	if err != nil {
		t.Fatal(err)
	}
	return CryptoSealedInput{Name: name, EnvelopeBytes: sealed}
}

func generatedSuppliedPreparedFixture(t *testing.T, request CryptoGeneratedSuppliedRequest, row IdentityRow) CryptoPreparedSecret {
	t.Helper()
	entry, _, _ := generatedEntryEvidenceFixture(t, 0)
	entry.Name, entry.Incarnation, entry.ValueState = row.Name, row.Incarnation, row.ValueState
	entry.OriginSnapshot, entry.OriginTransition = row.OriginSnapshot, row.OriginTransition
	entry.ValueSource, entry.Generated = Supplied, GeneratedEntryMetadata{}
	entryBytes, err := EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	core, err := ValueCoreForEntry(request.Context.DomainID, request.Context.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	material, err := ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := DecodeCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	accessBody, err := EncodeAccessRecord(AccessRecord{Schema: CanonicalSchema, MaterialKind: ValueMaterialKind, MaterialID: entry.ValueState,
		MaterialContextDigest: material, PackageCheck: payload.PackageCheck,
		Wraps: []WrapRow{{SubjectKind: 1, SubjectID: entry.Recipients[0], BindingID: generatedRecordID(91), BindingSerial: 1,
			PublicBindingDigest: generatedRecordID(92), RSACiphertext: bytes.Repeat([]byte{1}, 384)}}})
	if err != nil {
		t.Fatal(err)
	}
	return CryptoPreparedSecret{Name: row.Name, Slot: row.Slot, EntryBytes: entryBytes, AccessRecord: accessBody}
}

func generatedSuppliedMaximumPreparedFixture(t *testing.T, request CryptoGeneratedSuppliedRequest, row IdentityRow) CryptoPreparedSecret {
	t.Helper()
	prepared := generatedSuppliedPreparedFixture(t, request, row)
	entry, err := DecodeValueEntry(prepared.EntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := DecodeCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.ContentLength, payload.RetainedLength = CryptoMaxRawValue, CryptoMaxRawValue
	entry.ContentLength, entry.RetainedLength = payload.ContentLength, payload.RetainedLength
	payload.Ciphertext = make([]byte, CryptoMaxRawValue+canonicalCiphertextTagSize)
	entry.ValueBytes, err = EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	prepared.EntryBytes, err = EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	access, err := DecodeAccessRecord(prepared.AccessRecord)
	if err != nil {
		t.Fatal(err)
	}
	core, err := ValueCoreForEntry(request.Context.DomainID, request.Context.CompatibilityID, entry)
	if err != nil {
		t.Fatal(err)
	}
	access.MaterialContextDigest, err = ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	prepared.AccessRecord, err = EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func generatedSuppliedIdentityRows(count int) []IdentityRow {
	rows := make([]IdentityRow, count)
	for i := range rows {
		rows[i] = IdentityRow{Name: fmt.Sprintf("member-%03d", i), Slot: uint16(i), Incarnation: generatedRecordID(33),
			ValueState: generatedRecordID(34), OriginSnapshot: generatedRecordID(31), OriginTransition: generatedRecordID(30)}
	}
	return rows
}

func generatedSuppliedIdentityBody(t testing.TB, rows []IdentityRow) []byte {
	t.Helper()
	body, err := EncodeIdentityPlan(IdentityPlan{Operation: generatedRecordID(2), Transition: generatedRecordID(30),
		Snapshot: generatedRecordID(31), Revision: generatedRecordID(32), Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestCryptoGeneratedSuppliedRequestIsTypedOwnedAndClosed(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	request.SealedInputs = []CryptoSealedInput{generatedSuppliedSourceFixture(t, request, "plain")}
	body, err := EncodeCryptoGeneratedSuppliedRequest(request)
	// Independent Python writes OpRef27+B(Context382), variant6, Phase28,
	// index0/final1, B(identity301), count1, B("plain")+B(source824).
	// The source uses schema4/profile2 and literal IDs23,1,98,99,102,103;
	// the context's RootRef uses canonical schema11.
	if err != nil || len(body) != 1602 || Hash(body) != generatedCryptoHexID(t, "2b38ded1af7efbad6c9d9a216701c2ec76bdc1da92d79567ee5ed9d912aefff0") {
		t.Fatal("single supplied request vector", len(body), Hash(body), err)
	}
	view, err := InspectCryptoGeneratedSuppliedRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := view.Own()
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	if owned.OperationRef != request.OperationRef || owned.Context != request.Context || owned.PhaseID != request.PhaseID ||
		!bytes.Equal(owned.IdentityPlan, request.IdentityPlan) || len(owned.SealedInputs) != 1 || owned.SealedInputs[0].Name != request.SealedInputs[0].Name ||
		!bytes.Equal(owned.SealedInputs[0].EnvelopeBytes, request.SealedInputs[0].EnvelopeBytes) {
		t.Fatal("supplied request retained or changed borrowed fields")
	}
	response, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: request.Final})
	if err != nil || len(response) != 10 || Hash(response) != generatedCryptoHexID(t, "ef67ca1bc3efe22bbfbd3717ee6c0bfc870b5fd9cf38172a48c1bbb0ad8933cc") {
		t.Fatal("empty supplied response vector", len(response), Hash(response), err)
	}
	result, err := InspectCryptoGeneratedSuppliedResult(response)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := result.Own()
	if err != nil || len(rows) != 0 {
		t.Fatal("empty supplied response differs", err)
	}
	for name, mutate := range map[string]func(*CryptoGeneratedSuppliedRequest){
		"phase":        func(v *CryptoGeneratedSuppliedRequest) { v.PhaseID = ID{} },
		"batch index":  func(v *CryptoGeneratedSuppliedRequest) { v.BatchIndex = CryptoMaxValueEntries },
		"final marker": func(v *CryptoGeneratedSuppliedRequest) { v.Final = 2 },
		"identity": func(v *CryptoGeneratedSuppliedRequest) {
			v.IdentityPlan = bytes.Clone(v.IdentityPlan[:len(v.IdentityPlan)-1])
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			mutate(&bad)
			if _, err := EncodeCryptoGeneratedSuppliedRequest(bad); err == nil {
				t.Fatal("invalid supplied request accepted")
			}
		})
	}
}

// full_only: false
func TestCryptoGeneratedSuppliedRequestOwnRevalidatesCurrentView(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	request.SealedInputs = []CryptoSealedInput{generatedSuppliedSourceFixture(t, request, "plain")}
	for name, mutate := range map[string]func(*CryptoGeneratedSuppliedRequestView){
		"operation": func(v *CryptoGeneratedSuppliedRequestView) { v.OperationRef = ID{} },
		"context":   func(v *CryptoGeneratedSuppliedRequestView) { v.Context.OperationClass = CryptoOrdinaryLifecycle },
		"phase":     func(v *CryptoGeneratedSuppliedRequestView) { v.PhaseID = ID{} },
		"batch":     func(v *CryptoGeneratedSuppliedRequestView) { v.BatchIndex = CryptoMaxValueEntries },
		"final":     func(v *CryptoGeneratedSuppliedRequestView) { v.Final = 2 },
		"identity field": func(v *CryptoGeneratedSuppliedRequestView) {
			v.IdentityPlan = v.IdentityPlan[:len(v.IdentityPlan)-1]
		},
		"identity backing": func(v *CryptoGeneratedSuppliedRequestView) { v.IdentityPlan[0] ^= 0xff },
		"source framing": func(v *CryptoGeneratedSuppliedRequestView) {
			binary.BigEndian.PutUint32(v.sealedInputs, CryptoMaxName+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			body, err := EncodeCryptoGeneratedSuppliedRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			view, err := InspectCryptoGeneratedSuppliedRequest(body)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&view)
			owned, err := view.Own()
			if err == nil {
				t.Fatal("changed supplied request view retained")
			}
			if owned.OperationRef != (ID{}) || owned.Context != (ApplyContext{}) || owned.PhaseID != (ID{}) ||
				owned.IdentityPlan != nil || owned.SealedInputs != nil {
				t.Fatal("rejected ownership returned partial output")
			}
		})
	}
}

// full_only: false
func TestCryptoGeneratedSuppliedValidationAllocatesLessThanRetention(t *testing.T) {
	requestBody, err := EncodeCryptoGeneratedSuppliedRequest(generatedSuppliedCryptoFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1})
	if err != nil {
		t.Fatal(err)
	}
	q := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(93),
		CustodyInstanceID: generatedRecordID(94), Body: requestBody}
	p := CryptoResponse{Schema: q.Schema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID,
		ResultCode: CryptoSuccess, Body: responseBody}
	validationAllocs := testing.AllocsPerRun(20, func() {
		if err := ValidateCryptoExchange(q, p); err != nil {
			t.Fatal(err)
		}
	})
	requestView, err := InspectCryptoGeneratedSuppliedRequest(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	resultView, err := InspectCryptoGeneratedSuppliedResult(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	retentionAllocs := testing.AllocsPerRun(20, func() {
		if _, err := requestView.Own(); err != nil {
			t.Fatal(err)
		}
		if _, err := resultView.Own(); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("borrowed metadata validation: %.0f allocations; explicit retention: %.0f allocations", validationAllocs, retentionAllocs)
	if validationAllocs >= retentionAllocs {
		t.Fatalf("metadata validation allocations %v, retained ownership allocations %v", validationAllocs, retentionAllocs)
	}
}

// full_only: false
func TestCryptoGeneratedSuppliedResponseMayPrepareRetainedIdentity(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	identity, err := DecodeIdentityPlan(request.IdentityPlan)
	if err != nil || len(identity.Rows) != 1 {
		t.Fatal("retained supplied identity", err)
	}
	row := identity.Rows[0]
	prepared := generatedSuppliedPreparedFixture(t, request, row)
	requestBody, err := EncodeCryptoGeneratedSuppliedRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: request.Final, Rows: []CryptoPreparedSecret{prepared}})
	if err != nil {
		t.Fatal(err)
	}
	q := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(93),
		CustodyInstanceID: generatedRecordID(94), Body: requestBody}
	p := CryptoResponse{Schema: q.Schema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID,
		ResultCode: CryptoSuccess, Body: responseBody}
	if err := ValidateCryptoExchange(q, p); err != nil {
		t.Fatal("retained supplied response relation", err)
	}
	for _, metadata := range []CryptoGeneratedSuppliedResult{{BatchIndex: 1, Final: request.Final, Rows: []CryptoPreparedSecret{prepared}},
		{BatchIndex: request.BatchIndex, Final: 0, Rows: []CryptoPreparedSecret{prepared}}} {
		p.Body, err = EncodeCryptoGeneratedSuppliedResult(metadata)
		if err != nil || ValidateCryptoExchange(q, p) != ErrCryptoMessage {
			t.Fatal("changed supplied batch reply metadata", err)
		}
	}
	p.Body = responseBody
	missingSourceIdentity := identity
	missingSourceIdentity.Rows = append(missingSourceIdentity.Rows, IdentityRow{Name: "sealed", Slot: 3,
		Incarnation: generatedRecordID(96), ValueState: generatedRecordID(97), OriginSnapshot: generatedRecordID(31),
		OriginTransition: generatedRecordID(30)})
	missingSourceRequest := request
	missingSourceRequest.IdentityPlan, err = EncodeIdentityPlan(missingSourceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	missingSourceRequest.SealedInputs = []CryptoSealedInput{generatedSuppliedSourceFixture(t, request, "sealed")}
	missingSourceBody, err := EncodeCryptoGeneratedSuppliedRequest(missingSourceRequest)
	if err != nil {
		t.Fatal(err)
	}
	missingSourceQuery := q
	missingSourceQuery.Body = missingSourceBody
	missingSourceResponse := p
	missingSourceResponse.RequestID = missingSourceQuery.RequestID
	if err := ValidateCryptoExchange(missingSourceQuery, missingSourceResponse); err == nil {
		t.Fatal("supplied response omitted one exact sealed source row")
	}
	identity.Rows[0].ValueState = generatedRecordID(95)
	request.IdentityPlan, err = EncodeIdentityPlan(identity)
	if err != nil {
		t.Fatal(err)
	}
	q.Body, err = EncodeCryptoGeneratedSuppliedRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCryptoExchange(q, p); err == nil {
		t.Fatal("retained supplied response escaped its exact identity")
	}
}

// full_only: false
func TestCryptoGeneratedSuppliedFramingOrderCountAndAggregateRefusal(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	identity := generatedSuppliedIdentityRows(2)
	request.IdentityPlan = generatedSuppliedIdentityBody(t, identity)
	request.SealedInputs = []CryptoSealedInput{
		generatedSuppliedSourceFixture(t, request, identity[0].Name),
		generatedSuppliedSourceFixture(t, request, identity[1].Name),
	}
	body, err := EncodeCryptoGeneratedSuppliedRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	for n := range body {
		if _, err := InspectCryptoGeneratedSuppliedRequest(body[:n]); err == nil {
			t.Fatal("truncated supplied request accepted", n)
		}
	}
	if _, err := InspectCryptoGeneratedSuppliedRequest(append(bytes.Clone(body), 0)); err != ErrCryptoMessage {
		t.Fatal("trailing supplied request bytes", err)
	}
	countOffset := cryptoGeneratedOperationContextLength + 1 + 32 + 4 + 1 + 4 + len(request.IdentityPlan)
	for name, count := range map[string]uint32{"short": 1, "long": 3} {
		t.Run("request count "+name, func(t *testing.T) {
			bad := bytes.Clone(body)
			binary.BigEndian.PutUint32(bad[countOffset:], count)
			if _, err := InspectCryptoGeneratedSuppliedRequest(bad); err != ErrCryptoMessage {
				t.Fatal("wrong supplied source count", err)
			}
		})
	}
	for name, change := range map[string]func(*CryptoGeneratedSuppliedRequest){
		"duplicate": func(v *CryptoGeneratedSuppliedRequest) { v.SealedInputs[1] = v.SealedInputs[0] },
		"misordered": func(v *CryptoGeneratedSuppliedRequest) {
			v.SealedInputs[0], v.SealedInputs[1] = v.SealedInputs[1], v.SealedInputs[0]
		},
		"mismatched name": func(v *CryptoGeneratedSuppliedRequest) { v.SealedInputs[0].Name = "different" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := request
			bad.SealedInputs = append([]CryptoSealedInput(nil), request.SealedInputs...)
			change(&bad)
			if _, err := EncodeCryptoGeneratedSuppliedRequest(bad); err != ErrCryptoMessage {
				t.Fatal("invalid supplied source order or identity", err)
			}
		})
	}

	prepared := []CryptoPreparedSecret{
		generatedSuppliedPreparedFixture(t, request, identity[0]),
		generatedSuppliedPreparedFixture(t, request, identity[1]),
	}
	response, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: request.Final, Rows: prepared})
	if err != nil {
		t.Fatal(err)
	}
	for n := range response {
		if _, err := InspectCryptoGeneratedSuppliedResult(response[:n]); err == nil {
			t.Fatal("truncated supplied response accepted", n)
		}
	}
	if _, err := InspectCryptoGeneratedSuppliedResult(append(bytes.Clone(response), 0)); err != ErrCryptoMessage {
		t.Fatal("trailing supplied response bytes", err)
	}
	for name, count := range map[string]uint32{"short": 1, "long": 3} {
		t.Run("response count "+name, func(t *testing.T) {
			bad := bytes.Clone(response)
			binary.BigEndian.PutUint32(bad[6:], count)
			if _, err := InspectCryptoGeneratedSuppliedResult(bad); err != ErrCryptoMessage {
				t.Fatal("wrong prepared row count", err)
			}
		})
	}
	for name, rows := range map[string][]CryptoPreparedSecret{
		"duplicate":  {prepared[0], prepared[0]},
		"misordered": {prepared[1], prepared[0]},
	} {
		t.Run("response "+name, func(t *testing.T) {
			if _, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Rows: rows}); err != ErrCryptoMessage {
				t.Fatal("invalid prepared order", err)
			}
		})
	}
	overflow := make([]byte, 1+cryptoPreparedRowsLimit+1)
	overflow[0] = byte(CryptoGeneratedPrepareSupplied)
	if _, err := InspectCryptoGeneratedSuppliedResult(overflow); err != ErrCryptoCapacity {
		t.Fatal("prepared aggregate overflow", err)
	}
}

// full_only: false
func TestCryptoGeneratedSuppliedMaximumBoundaryAndMixedIdentity(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	identity := generatedSuppliedIdentityRows(CryptoMaxValueEntries)
	request.IdentityPlan = generatedSuppliedIdentityBody(t, identity)
	request.SealedInputs = make([]CryptoSealedInput, len(identity))
	prepared := make([]CryptoPreparedSecret, len(identity))
	for i := range identity {
		request.SealedInputs[i] = generatedSuppliedSourceFixture(t, request, identity[i].Name)
		prepared[i] = generatedSuppliedPreparedFixture(t, request, identity[i])
	}
	requestBody, err := EncodeCryptoGeneratedSuppliedRequest(request)
	if err != nil {
		t.Fatal("maximum supplied request", err)
	}
	responseBody, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: request.Final, Rows: prepared})
	if err != nil {
		t.Fatal("maximum supplied response", err)
	}
	q := CryptoRequest{Schema: CryptoSchema, Kind: CryptoPrepare, RequestID: generatedRecordID(93),
		CustodyInstanceID: generatedRecordID(94), Body: requestBody}
	p := CryptoResponse{Schema: q.Schema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID,
		ResultCode: CryptoSuccess, Body: responseBody}
	// Independent Python writes all 512 member-NNN names/slots. Request:
	// OpRef+B(Context382)+46+identity73890+512*847 = 508018 bytes.
	// Response: variant6/index0/final1+count512+512*1029 = 526858 bytes.
	// Each supplied ValueCore uses schema11 and the independently derived
	// original member DataKeyID/CommitmentKeyID; the response access rows
	// contain SHA256(L("material")+B(ValueCore)). The payload remains from
	// the generated fixture when its entry is changed to supplied. Its keys
	// now derive through canonical intent-v3 and member-binding-v3: configR6,
	// resourceR9, target "account/target", resource bytes00ff02, lifecycle2,
	// completion1. The member-value preimage is slot||R31||result||binding.
	// These count vectors retain the smaller-batch worst-value checks.
	if len(requestBody) != 508018 || Hash(requestBody) != generatedCryptoHexID(t, "e3f57648100d3a3ce2ac50bd33cd68897c9b0a2c2fef1294999daff06f34c25f") ||
		len(responseBody) != 526858 || Hash(responseBody) != generatedCryptoHexID(t, "9c4a86e5fa28604a9f21fc314418c41e61a7c2a3c5ecac8197c801317e1f5686") {
		t.Fatal("maximum supplied vectors changed", len(requestBody), Hash(requestBody), len(responseBody), Hash(responseBody))
	}
	if err := ValidateCryptoExchange(q, p); err != nil {
		t.Fatal("maximum supplied exchange", err)
	}

	extraName := fmt.Sprintf("member-%03d", CryptoMaxValueEntries)
	extraIdentity := append(append([]IdentityRow(nil), identity...), IdentityRow{Name: extraName, Slot: CryptoMaxValueEntries,
		Incarnation: generatedRecordID(33), ValueState: generatedRecordID(34), OriginSnapshot: generatedRecordID(31), OriginTransition: generatedRecordID(30)})
	for _, row := range identity {
		if row.Name == extraIdentity[len(extraIdentity)-1].Name {
			t.Fatalf("extra identity row %d duplicates maximum fixture name %q", len(extraIdentity), row.Name)
		}
	}
	if _, err := EncodeIdentityPlan(IdentityPlan{Operation: generatedRecordID(2), Transition: generatedRecordID(30),
		Snapshot: generatedRecordID(31), Revision: generatedRecordID(32), Rows: extraIdentity}); err != ErrRecordCapacity {
		t.Fatal("identity row count", len(extraIdentity), err)
	}
	extraSources := append(append([]CryptoSealedInput(nil), request.SealedInputs...), generatedSuppliedSourceFixture(t, request, extraName))
	tooManySources := request
	tooManySources.SealedInputs = extraSources
	if _, err := EncodeCryptoGeneratedSuppliedRequest(tooManySources); err != ErrCryptoCapacity {
		t.Fatal("supplied source count", len(extraSources), err)
	}
	extraPrepared := append(append([]CryptoPreparedSecret(nil), prepared...), generatedSuppliedPreparedFixture(t, request, extraIdentity[len(extraIdentity)-1]))
	if _, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Rows: extraPrepared}); err != ErrCryptoCapacity {
		t.Fatal("prepared row count", len(extraPrepared), err)
	}

	_, _, generatedResults := generatedCryptoValueEntryBatchFixture(t, 1)
	generatedResult := generatedResults[0]
	mixedRows := []IdentityRow{
		{Name: generatedResult.Entry.Name, Slot: generatedResult.Slot, Incarnation: generatedResult.Entry.Incarnation,
			ValueState: generatedResult.Entry.ValueState, OriginSnapshot: generatedResult.Entry.OriginSnapshot,
			OriginTransition: generatedResult.Entry.OriginTransition},
		{Name: "supplied", Slot: 1, Incarnation: generatedRecordID(43), ValueState: generatedRecordID(44), OriginSnapshot: generatedRecordID(31), OriginTransition: generatedRecordID(30)},
	}
	mixed := generatedSuppliedCryptoFixture(t)
	mixed.IdentityPlan = generatedSuppliedIdentityBody(t, mixedRows)
	mixed.SealedInputs = []CryptoSealedInput{generatedSuppliedSourceFixture(t, mixed, "supplied")}
	mixedRequest, err := EncodeCryptoGeneratedSuppliedRequest(mixed)
	if err != nil {
		t.Fatal(err)
	}
	mixedResponse, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: mixed.Final, Rows: []CryptoPreparedSecret{
		generatedSuppliedPreparedFixture(t, mixed, mixedRows[1]),
	}})
	if err != nil {
		t.Fatal(err)
	}
	q.Body, p.Body = mixedRequest, mixedResponse
	if err := ValidateCryptoExchange(q, p); err != nil {
		t.Fatal("mixed generated and supplied identity", err)
	}
	generatedEntryBytes, err := EncodeValueEntry(generatedResult.Entry)
	if err != nil {
		t.Fatal(err)
	}
	generatedAccess, err := EncodeAccessRecord(generatedResult.Access)
	if err != nil {
		t.Fatal(err)
	}
	wrongSet, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Rows: []CryptoPreparedSecret{
		{Name: generatedResult.Entry.Name, Slot: generatedResult.Slot, EntryBytes: generatedEntryBytes, AccessRecord: generatedAccess},
		generatedSuppliedPreparedFixture(t, mixed, mixedRows[1]),
	}})
	if err != nil {
		t.Fatal(err)
	}
	p.Body = wrongSet
	if err := ValidateCryptoExchange(q, p); err != ErrCryptoMessage {
		t.Fatal("generated member accepted in supplied final preparation", err)
	}
}

// full_only: false
func TestCryptoGeneratedSuppliedPreflightCoversCompleteOuterResponse(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	bound := func(count int) error {
		t.Helper()
		request.IdentityPlan = generatedSuppliedIdentityBody(t, generatedSuppliedIdentityRows(count))
		body, err := EncodeCryptoGeneratedSuppliedRequest(request)
		if err != nil {
			return err
		}
		view, err := InspectCryptoGeneratedSuppliedRequest(body)
		if err != nil {
			return err
		}
		_, err = CryptoGeneratedSuppliedResultBound(view)
		return err
	}
	frontier := 0
	for n := 1; n <= 65; n++ {
		if err := bound(n); err == nil {
			frontier = n
		} else if err != ErrCryptoCapacity {
			t.Fatal("preflight error", n, err)
		}
	}
	if frontier != 15 || bound(frontier) != nil || bound(frontier+1) != ErrCryptoCapacity {
		t.Fatal("outer response frontier", frontier)
	}
	identity := generatedSuppliedIdentityRows(65)
	prepared := make([]CryptoPreparedSecret, len(identity))
	for i, row := range identity {
		prepared[i] = generatedSuppliedMaximumPreparedFixture(t, request, row)
	}
	inner, err := EncodeCryptoPrepareResult(CryptoPrepareResult{Rows: prepared})
	if err != nil || len(inner) <= CryptoGeneratedResponseLimit {
		t.Fatal("large admitted inner prepared rows", len(inner), err)
	}
	if _, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1, Rows: prepared}); err != ErrCryptoCapacity {
		t.Fatal("oversized supplied outer body", err)
	}
}

// full_only: false
func TestGeneratedSuppliedPreflightIncludesAggregateWrapLimit(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	identities := generatedSuppliedIdentityRows(17)
	rows := make([]CryptoPreparedSecret, len(identities))
	var readerIDs []ID
	for i := 0; i < 256; i++ {
		readerIDs = append(readerIDs, Hash([]byte(fmt.Sprintf("batch reader %d", i))))
	}
	slices.SortFunc(readerIDs, func(a, b ID) int { return bytes.Compare(a[:], b[:]) })
	for i, identity := range identities {
		row := generatedSuppliedPreparedFixture(t, request, identity)
		entry, err := DecodeValueEntry(row.EntryBytes)
		if err != nil {
			t.Fatal(err)
		}
		entry.Recipients = []ID{readerIDs[0]}
		row.EntryBytes, err = EncodeValueEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		access, err := DecodeAccessRecord(row.AccessRecord)
		if err != nil {
			t.Fatal(err)
		}
		template := access.Wraps[0]
		access.Wraps = nil
		for _, id := range readerIDs {
			wrap := template
			wrap.SubjectID = id
			access.Wraps = append(access.Wraps, wrap)
		}
		row.AccessRecord, err = EncodeAccessRecord(access)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = row
	}
	for _, count := range []int{15, 16, 17} {
		request.IdentityPlan = generatedSuppliedIdentityBody(t, identities[:count])
		body, err := EncodeCryptoGeneratedSuppliedRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectCryptoGeneratedSuppliedRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		bound, preflight := CryptoGeneratedSuppliedResultBound(view)
		resultBody, encoded := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Final: 1, Rows: rows[:count]})
		if count == 15 {
			if preflight != nil || bound+855371 != 4103811 || encoded != nil {
				t.Fatal("complete worst-case response did not fit", bound, preflight, encoded)
			}
		} else if preflight != ErrCryptoCapacity {
			t.Fatal("worst-case outer response did not split before private work", count, preflight)
		}
		if count == 16 {
			if encoded != nil || len(resultBody) != 2011594 {
				t.Fatal("4096-wrap response must remain available", len(resultBody), encoded)
			}
		} else if count == 17 && encoded != ErrCryptoCapacity {
			t.Fatal("4352-wrap response exceeded the aggregate wrap limit", encoded)
		}
	}
}
