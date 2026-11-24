package core

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func generatedPreparationSourceFixture(t testing.TB, s *StateSession, retained bool) contract.GeneratorDeclarationEntry {
	t.Helper()
	if retained {
		observationCurrentSecret(t, s, []contract.ID{s.admission.recipient}, generatedVectorID(201))
		generatedSealSelectedFixture(t, s)
		current := s.valueEntry(0)
		body, err := contract.EncodeRetainedCanonicalRecord(contract.RetainedCanonicalRecord{OriginalSlot: 0, Entry: *current})
		if err != nil {
			t.Fatal(err)
		}
		return contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationRetained,
			Name: current.Name, Recipients: []contract.ID{s.admission.recipient}, Payload: body}
	}
	source := generatedSealedSource(t, "source")
	envelope, err := contract.DecodeSealedInputEnvelope(source.Payload)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.PublicBindingDigest(*s.authority().CurrentBinding)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Core.CryptoSupportID = s.root.CurrentAccess.Core.CryptoSupportID
	envelope.Core.IntendedRecipientBindingSetDigest, err = contract.IntendedRecipientBindingSetDigest(s.root.Domain,
		s.admission.recipient, []contract.RecipientBindingReference{{RecipientID: s.admission.recipient, PublicBindingDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	source.Payload, err = contract.EncodeSealedInputEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// full_only: false
func TestGeneratedPreparationStreamsExactContentAndSourceCharges(t *testing.T) {
	for _, retained := range []bool{false, true} {
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("retained=%t/end=%d", retained, delta), func(t *testing.T) {
				s, _ := observationTestSession(t)
				source := generatedPreparationSourceFixture(t, s, retained)
				// Independent schema: header70; each B(entry) has prefix4;
				// entry has fixed15 + name + 32 bytes per recipient + payload.
				// Generated payloads have fixed81, intent framing71,
				// two JSON quotes and 340000 settings bytes.
				// The physical part is 1 MiB minus its 256-byte envelope allowance.
				const cut = 1048320
				const generatedPrefix = 70 + 3*(4+15+3+32+81+71+2+340000)
				const paddingOverhead = 4 + 15 + 3 + 32
				sourceLength := 15 + len(source.Name) + 32 + len(source.Payload)
				paddingLength := cut + delta - generatedPrefix - paddingOverhead - 4 - sourceLength
				if paddingLength < 0 || paddingLength > 65536 {
					t.Fatal("independent padding outside plain-value bounds", paddingLength)
				}
				padding := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
					Name: "a09", Recipients: []contract.ID{s.admission.recipient}, Payload: bytes.Repeat([]byte{'p'}, paddingLength)}
				tail := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
					Name: "zz", Recipients: []contract.ID{s.admission.recipient}, Payload: []byte("tail")}
				input := generatedPlanInputForGenerationsIntent(t, s, generatedVectorID(10), []string{"a00", "a01", "a02"},
					bytes.Repeat([]byte{'i'}, 340000), defaultGeneratedFixtureProfile(), padding, source, tail)
				plan, err := s.generatedPlanRequest(t.Context(), input)
				if err != nil {
					t.Fatal("source-bound plan admission", err)
				}
				graph, err := contract.EncodeGeneratorPlanBundle(input.graph)
				if err != nil {
					t.Fatal(err)
				}
				if len(input.declaration) != cut+delta+4+15+2+32+4 || len(graph) >= cut {
					t.Fatal("independent complete-body framing", len(input.declaration), len(graph))
				}
				// Successful part replies supply the independently expected open counts.
				// The real exchange boundary rejects them if Core charges another part.
				wantOpens := []uint32{1, 0, 0}
				if delta > 0 {
					wantOpens = []uint32{0, 1, 0}
				}
				bindings, err := s.currentBindings()
				if err != nil || len(bindings) != 1 {
					t.Fatal("authority-only fixture", err)
				}
				binding := bindings[0]
				digest, err := contract.PublicBindingDigest(binding.Binding)
				if err != nil {
					t.Fatal(err)
				}
				open := contract.KeyUseRow{BindingID: binding.Binding.BindingID, PublicBindingDigest: digest,
					SubjectKind: binding.SubjectKind, SubjectID: binding.SubjectID, Provider: binding.Binding.Provider,
					Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}
				operation := generatedVectorID(110)
				custody := &observationExchangeCustody{instance: generatedVectorID(105)}
				partIndex := 0
				var actualKinds []uint8
				custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
					if len(custody.calls) == 1 {
						want, err := contract.EncodeCryptoGeneratedCompareRequest(plan.request)
						if err != nil || q.Kind != contract.CryptoCompare || !bytes.Equal(q.Body, want) {
							t.Fatal("complete Compare request differs", err)
						}
						body, err := contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: operation})
						if err != nil {
							t.Fatal(err)
						}
						return observationReply(q, contract.CryptoSuccess, nil, body)
					}
					if partIndex < 3 {
						part, err := contract.InspectCryptoGeneratedPlanPartRequest(q.Body)
						if err != nil || q.Kind != contract.CryptoPrepare {
							t.Fatal("expected complete plan part", partIndex, err)
						}
						kind, index, count, blob := uint8(2), partIndex, 2, input.declaration
						if partIndex == 2 {
							kind, index, count, blob = 3, 0, 1, graph
						}
						start, end := index*cut, min((index+1)*cut, len(blob))
						if part.OperationRef != operation || part.Context != plan.request.Context || part.BlobKind != kind ||
							part.Index != uint16(index) || part.Count != uint16(count) || part.Total != uint64(len(blob)) ||
							part.WholeDigest != contract.Hash(blob) || part.Offset != uint32(start) || !bytes.Equal(part.Payload, blob[start:end]) {
							t.Fatal("kind and complete body cross-paired or changed", partIndex)
						}
						var rows []contract.KeyUseRow
						if wantOpens[partIndex] != 0 {
							rows = []contract.KeyUseRow{open}
						}
						actualKinds = append(actualKinds, part.BlobKind)
						partIndex++
						return observationReply(q, contract.CryptoSuccess, rows, []byte{1})
					}
					finish, err := contract.InspectCryptoGeneratedFinishPlanRequest(q.Body)
					if err != nil || q.Kind != contract.CryptoPrepare || finish.OperationRef != operation ||
						finish.Context != plan.request.Context || finish.Declaration != plan.request.ParentPlan.Declaration ||
						finish.Graph != plan.request.PlanGraph || finish.SourceUses != plan.request.AcceptedSources {
						t.Fatal("finish did not follow the exact complete content", err)
					}
					return observationReply(q, contract.CryptoCustodyUnavailable, nil, nil)
				}
				permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: custody, instance: custody.instance,
					deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
				prepared, result := s.prepareGeneratedPlan(t.Context(), permit)
				if prepared != nil || result != custodyFailure(contract.CryptoCustodyUnavailable) || !permit.used || len(custody.calls) != 5 ||
					!slices.Equal(actualKinds, []uint8{2, 2, 3}) {
					t.Fatal("exact content or source charge was refused before finish", result, actualKinds)
				}
			})
		}
	}
}
