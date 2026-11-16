package contract

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"slices"
	"testing"
)

func applySupportPlanFixture(t testing.TB) (ID, []SupportRecord, []SupportRecordDigest, CompactMutationReceiptPlan) {
	t.Helper()
	old := mutationReceiptFixture()
	oldBody, err := EncodeCompactMutationReceipt(old)
	if err != nil {
		t.Fatal(err)
	}
	plan := CompactMutationReceiptPlan(old)
	plan.OperationKind, plan.OperationID, plan.RequestIdentityDigest = OperationApplyDeclaration, generatedRecordID(42), ID{}
	planned, err := AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil {
		t.Fatal(err)
	}
	blob := generatedRecordID(80)
	fragment, err := EncodeGeneratedFragment(GeneratedFragment{Schema: 1, BlobID: blob, Count: 1, TotalLength: 1, WholeDigest: Hash([]byte{5}), Payload: []byte{5}})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	configurationBytes, err := EncodeOutputConfiguration(OutputConfiguration{Schema: OutputConfigurationSchema, DomainID: old.DomainID})
	if err != nil {
		t.Fatal(err)
	}
	configuration := Hash(configurationBytes)
	output, err := EncodeOutputConfigurationSlice(OutputConfigurationSlice{Schema: OutputConfigurationSchema, DomainID: old.DomainID, ConfigurationDigest: configuration, SliceCount: 1, TotalLength: uint32(len(configurationBytes)), SliceBytes: configurationBytes})
	if err != nil {
		t.Fatal(err)
	}
	outputID, err := OutputConfigurationSliceID(old.DomainID, configuration, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows := []SupportRecord{{GeneratedFragmentSupportKind, fragmentID, fragment}, {MutationReceiptSupportKind, old.OperationID, oldBody}, {MutationReceiptSupportKind, plan.OperationID, planned}, {OutputConfigurationSliceSupportKind, outputID, output}}
	facts := make([]SupportRecordDigest, len(rows))
	for i, row := range rows {
		if i != 2 {
			facts[i], err = InspectSupportRecordDigest(old.DomainID, row)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return old.DomainID, rows, facts, plan
}

// full_only: false
func TestApplyReceiptSupportPlanPermitsOnlyOneNamedHole(t *testing.T) {
	domain, rows, facts, plan := applySupportPlanFixture(t)
	beforeRows, beforeFacts := slices.Clone(rows), slices.Clone(facts)
	for i := range beforeRows {
		beforeRows[i].Body = bytes.Clone(rows[i].Body)
	}
	got, err := RequiredSupportReceiptPlanDescriptor(domain, rows, facts, plan)
	if err != nil {
		t.Fatal("complete inspected support plus one named hole refused", err)
	}
	// The descriptor frame is specified directly, without the new projector.
	want := append([]byte("ENKV/CRYPTO/v2/required-support-v2\x00"), domain[:]...)
	want = binary.BigEndian.AppendUint32(want, 4)
	for _, row := range rows {
		want = append(want, row.Kind)
		want = append(want, row.RecordID[:]...)
		digest := Hash(row.Body)
		want = append(want, digest[:]...)
		want = binary.BigEndian.AppendUint32(want, uint32(len(row.Body)))
	}
	if got != (DescriptorVector{Hash(want), uint64(len(want)), 4}) || !reflect.DeepEqual(rows, beforeRows) || !slices.Equal(facts, beforeFacts) {
		t.Fatal("plan descriptor changed a support fact or frame")
	}
	if _, err := InspectCompactMutationReceipt(rows[2].Body); err == nil {
		t.Fatal("receipt plan entered the stored receipt decoder")
	}
	if _, err := RequiredSupportDescriptor(domain, rows); err == nil {
		t.Fatal("receipt plan entered ordinary selected support")
	}
	// Only the two large, already-inspected body owners may be absent here.
	rows[0].Body, rows[3].Body = nil, nil
	streamed, err := RequiredSupportReceiptPlanDescriptor(domain, rows, facts, plan)
	if err != nil || streamed != got {
		t.Fatal("releasing inspected stream bodies changed the plan descriptor", err)
	}
}

// full_only: false
func TestApplyReceiptSupportPlanRejectsSubstitutionAndMutation(t *testing.T) {
	for name, change := range map[string]func(*ID, *[]SupportRecord, *[]SupportRecordDigest, *CompactMutationReceiptPlan){
		"domain": func(d *ID, _ *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			*d = generatedRecordID(99)
		},
		"fact-count": func(_ *ID, _ *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			*f = (*f)[:3]
		},
		"missing-hole": func(_ *ID, r *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			*r = append((*r)[:2], (*r)[3:]...)
			*f = append((*f)[:2], (*f)[3:]...)
		},
		"duplicate-hole": func(_ *ID, r *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			*r = append(*r, (*r)[2])
			*f = append(*f, SupportRecordDigest{})
		},
		"wrong-hole-kind": func(_ *ID, r *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[2].Kind = GeneratedFragmentSupportKind
		},
		"wrong-hole-operation": func(_ *ID, r *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[2].RecordID = generatedRecordID(99)
		},
		"filled-plan": func(_ *ID, _ *[]SupportRecord, _ *[]SupportRecordDigest, p *CompactMutationReceiptPlan) {
			p.RequestIdentityDigest = generatedRecordID(99)
		},
		"filled-hole-fact": func(_ *ID, _ *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*f)[2] = (*f)[1]
		},
		"changed-hole-body": func(_ *ID, r *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[2].Body[200] ^= 1
		},
		"changed-plan-result": func(_ *ID, _ *[]SupportRecord, _ *[]SupportRecordDigest, p *CompactMutationReceiptPlan) {
			p.CompleteResult.Digest = generatedRecordID(99)
		},
		"fact-order": func(_ *ID, _ *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*f)[0], (*f)[1] = (*f)[1], (*f)[0]
		},
		"uninspected-stream": func(_ *ID, r *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[0].Body = nil
			(*f)[0] = SupportRecordDigest{}
		},
		"wrong-domain-fact": func(_ *ID, _ *[]SupportRecord, f *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*f)[0].domain = generatedRecordID(99)
		},
		"released-receipt": func(_ *ID, r *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[1].Body = nil
		},
		"changed-retained-receipt": func(_ *ID, r *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[1].Body[200] ^= 1
		},
		"changed-stream-body": func(_ *ID, r *[]SupportRecord, _ *[]SupportRecordDigest, _ *CompactMutationReceiptPlan) {
			(*r)[0].Body[len((*r)[0].Body)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			domain, rows, facts, plan := applySupportPlanFixture(t)
			for i := range rows {
				rows[i].Body = bytes.Clone(rows[i].Body)
			}
			change(&domain, &rows, &facts, &plan)
			if _, err := RequiredSupportReceiptPlanDescriptor(domain, rows, facts, plan); err == nil {
				t.Fatal("substituted or mutated support accepted")
			}
		})
	}
}
