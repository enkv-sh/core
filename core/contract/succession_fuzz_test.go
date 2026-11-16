package contract

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These seeds extend the maintained FuzzFirstFlowRecords campaign. Exact leaf
// bytes come from the independent unit vectors; batch sizes reuse the recorded
// access-bounds equation. Other encoders construct structural corpus inputs,
// not independent expectations or evidence of private qualification.
func addCurrentKeyFuzzSeeds(f *testing.F, bindings []BindingTableRow) {
	f.Helper()
	add := func(b []byte, err error) {
		f.Helper()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	_, subject := successionSubjectVector()
	f.Add(subject)
	evidence, wire, plan := successorEvidenceVector()
	f.Add(wire)
	f.Add(plan) // A proof-free plan cannot enter the stored evidence decoder.
	f.Add([]byte{0})
	evidence[0].TargetRole, evidence[1].TargetRole = 3, 4
	evidence[1].KEK.SubjectKind = 2
	add(EncodeSuccessorEvidenceVector(evidence))
	probe, probeWire := successorKEKProbeVector()
	encodedProbe, err := EncodeSuccessorKEKProbeCore(probe)
	if err != nil || !bytes.Equal(encodedProbe, probeWire) {
		f.Fatal("probe seed differs from independent bytes", err)
	}
	// Probe cores have no wire decoder. Fuzz the shared context decoder, then
	// pass its result through both typed probe writers below.
	add(EncodeApplyContext(probe.Context))
	receipt := mutationReceiptFixture()
	receiptBody, err := EncodeCompactMutationReceipt(receipt)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(receiptBody)
	add(AppendSupportRecord(nil, SupportRecord{Kind: MutationReceiptSupportKind, RecordID: receipt.OperationID, Body: receiptBody}))
	for _, count := range []int{0, 1, 256} {
		indexes := MutationReceiptIndexes{Successes: make([]ID, count), Failures: make([]ID, count)}
		for i := range indexes.Successes {
			binary.BigEndian.PutUint32(indexes.Successes[i][28:], uint32(i+1))
			binary.BigEndian.PutUint32(indexes.Failures[i][28:], uint32(i+257))
		}
		indexes.Order = append(append([]ID{}, indexes.Successes...), indexes.Failures...)
		body, err := EncodeMutationReceiptIndexes(indexes)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(body)
		f.Add(append(bytes.Clone(body), 0))
		f.Add(body[:len(body)-1])
	}

	q := CryptoAccessReplaceRequest{Context: probe.Context, BindingTable: bindings,
		Replacements: []ReplacementRow{{SubjectKind: bindings[0].SubjectKind, SubjectID: bindings[0].SubjectID, BeforeBindingDigest: successionTestID(20)}}}
	planDescriptor, err := AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		f.Fatal(err)
	}
	identity, err := IdentityPlanDescriptor(IdentityPlan{Operation: successionTestID(21), Transition: successionTestID(22), Snapshot: successionTestID(23), Revision: successionTestID(24)})
	if err != nil {
		f.Fatal(err)
	}
	support, err := EmptyRequiredSupportDescriptor(q.Context.DomainID)
	if err != nil {
		f.Fatal(err)
	}
	public, err := PublicStateDescriptor(PublicState{Domain: q.Context.DomainID, AccessRoot: q.Context.CurrentAccessRoot, RequiredSupport: support})
	if err != nil {
		f.Fatal(err)
	}
	for _, count := range []int{0, 1} {
		projection, err := NewAccessProjection(AccessProjectionMetadata{DomainID: q.Context.DomainID, BeforeAccessRoot: q.Context.CurrentAccessRoot, RequestCoreDigest: q.Context.IntentDescriptor.Digest}, planDescriptor, uint32(count))
		if err != nil {
			f.Fatal(err)
		}
		rows := make([]CompactRow, count)
		outputs := make([]AccessOutputRow, count)
		for i := range rows {
			rows[i] = accessStructuralRow(f, i, 2, 0)
			outputs[i] = AccessOutputRow{MaterialKind: 1, MaterialID: rows[i].Coverage.MaterialID, BeforeAccessDigest: rows[i].Coverage.BeforeAccessDigest, AfterAccessRecord: rows[i].BeforeAccessRecord}
			if err := projection.Add(rows[i], outputs[i]); err != nil {
				f.Fatal(err)
			}
		}
		coverage, after, unchanged, err := projection.Descriptors()
		if err != nil {
			f.Fatal(err)
		}
		q.ExpectedCoverageDescriptor = coverage
		add(EncodeCryptoAccessReplaceRequest(q))
		prepare := CryptoAccessPrepareRequest{OperationRef: successionTestID(25), Context: q.Context, Final: 1, Rows: rows}
		add(EncodeCryptoAccessPrepareRequest(prepare))
		inputBatch, err := AccessInputBatchDescriptor(rows)
		if err != nil {
			f.Fatal(err)
		}
		outputBatch, err := AccessOutputBatchDescriptor(outputs)
		if err != nil {
			f.Fatal(err)
		}
		result := CryptoAccessPrepareResult{Final: 1, Rows: outputs, InputBatchDescriptor: inputBatch, OutputBatchDescriptor: outputBatch}
		if err := ValidateAccessBatchResult(prepare, result); err != nil {
			f.Fatal(err)
		}
		add(EncodeCryptoAccessPrepareResult(result))
		freeze := CryptoAccessFreezeRequest{OperationRef: prepare.OperationRef, Context: q.Context, IdentityPlanDescriptor: identity, ExpectedCoverageDescriptor: coverage, AfterAccessRowsDescriptor: after, CandidatePublicStateDescriptor: public, CandidateAccessRoot: q.Context.CurrentAccessRoot, UnchangedMaterialDescriptor: unchanged, FinalTranscriptDigest: successionTestID(26)}
		add(EncodeCryptoAccessFreezeRequest(freeze))
		add(EncodeCryptoAccessClaimRequest(CryptoAccessClaimRequest{CryptoAccessFreezeRequest: freeze, FactDigest: successionTestID(27)}))
	}
	evidence, _, _ = successorEvidenceVector()
	add(EncodeCryptoAccessReplaceResult(CryptoAccessReplaceResult{OperationRef: successionTestID(25), Qualified: []CryptoQualifiedSuccessor{{Qualification: evidence[1].KEK}}}))
	add(EncodeCryptoAccessReplaceResult(CryptoAccessReplaceResult{OperationRef: successionTestID(25)}))
	rows := make([]CompactRow, 65)
	for i := range rows {
		wraps, name := 65, 0
		if i == 64 {
			wraps, name = 48, 176
		}
		rows[i] = accessStructuralRow(f, i, wraps, name)
	}
	if n, err := AccessInputBatchLength(rows); err != nil || n != 2<<20 {
		f.Fatal("exact 2 MiB batch seed differs", n, err)
	}
	add(EncodeCryptoAccessPrepareRequest(CryptoAccessPrepareRequest{OperationRef: successionTestID(25), Context: q.Context, Rows: rows}))
}

func fuzzSupportRecord(t *testing.T, b []byte) {
	t.Helper()
	v, n, err := ParseSupportRecord(b)
	if err != nil {
		return
	}
	// This API parses a prefix and deliberately borrows its body.
	if n <= 0 || n > len(b) {
		t.Fatal("support parser consumed outside input")
	}
	got, err := AppendSupportRecord(nil, SupportRecord(v))
	if err != nil || !bytes.Equal(got, b[:n]) {
		t.Fatal("support parser accepted noncanonical prefix", err)
	}
}

func fuzzSuccessorKEKProbe(t *testing.T, b []byte) {
	t.Helper()
	context, err := DecodeApplyContext(b)
	if err != nil {
		return
	}
	probe, _ := successorKEKProbeVector()
	probe.Context = context
	for _, kind := range []uint8{1, 2} {
		probe.SubjectKind = kind
		wire, encoding := EncodeSuccessorKEKProbeCore(probe)
		digest, hashing := SuccessorKEKProbeMaterialContextDigest(probe)
		if (encoding == nil) != (hashing == nil) {
			t.Fatal("probe writer and material digest disagree")
		}
		if encoding == nil {
			want := successionExpectedBlob([]byte("ENKV/CRYPTO/v2/material\x00"), wire)
			if len(wire) != 487 || digest != Hash(want) {
				t.Fatal("probe material framing differs")
			}
		}
	}
}
