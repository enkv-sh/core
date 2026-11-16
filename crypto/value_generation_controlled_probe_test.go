package crypto

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// full_only: false
func TestGeneratedControlledProbeReturnsBoundedIdentityFacts(t *testing.T) {
	f := generatedSelectDeleteProducer(t, generatedDeleteProducerFixture(t, false), contract.GeneratedDutyRetirement)
	f.producer.Phase = &contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest,
		ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
		TransitionKind: contract.GeneratorAuthorityRetireReserve, BeforePhase: 1, AfterPhase: 2,
		Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)}
	for _, tc := range []struct {
		name        string
		status      byte
		length      int
		zero        int
		mismatch    int
		disposition uint8
	}{
		{"missing response", 2, 0, 0, 0, contract.GeneratorDispositionUnknown},
		{"short response", 2, 96, 0, 0, contract.GeneratorDispositionUnknown},
		{"trailing response", 2, 98, 0, 0, contract.GeneratorDispositionUnknown},
		{"invalid status", 0, 97, 0, 0, contract.GeneratorDispositionUnknown},
		{"missing resource", 2, 97, 1, 0, contract.GeneratorDispositionUnknown},
		{"missing token", 2, 97, 2, 0, contract.GeneratorDispositionUnknown},
		{"missing scope", 2, 97, 3, 0, contract.GeneratorDispositionUnknown},
		{"all identities missing", 2, 97, 4, 0, contract.GeneratorDispositionUnknown},
		{"inactive exact target", 2, 97, 0, 0, contract.GeneratorDispositionScopedUnusability},
		{"usable exact target", 1, 97, 0, 0, contract.GeneratorDispositionContinuedUsability},
		{"different resource", 2, 97, 0, 1, contract.GeneratorDispositionConflictingBinding},
		{"different token", 2, 97, 0, 2, contract.GeneratorDispositionConflictingBinding},
		{"different scope", 2, 97, 0, 3, contract.GeneratorDispositionConflictingBinding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.producerRuntime(t)
			t.Cleanup(r.retireGenerated)
			op, _ := generatedAdoptionCompare(t, r, f)
			locator := generatedProducerPrepare(t, r, f, op)
			a := r.generated
			p := a.purpose.producer.producer
			// Start at the return/seal boundary after private preparation. The
			// selected-predecessor and native-admission tests own admission.
			p.expected.Template.CompletionClass = contract.GeneratedCompletionConfirmed
			var err error
			p.expected.Template.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(p.expected.Template)
			if err != nil {
				t.Fatal(err)
			}
			ackResult, ackDigest := consumerID("preceding sealed ACK result"), consumerID("preceding sealed ACK body")
			progress, err := contract.EncodeGeneratorProgress(contract.GeneratorProgress{Schema: 1,
				AttemptID: consumerID("preceding ACK attempt"), ResultID: ackResult,
				Evidence:      contract.GeneratorDescriptor{Digest: ackDigest, Length: contract.GeneratedResultCoreLength, Count: 1},
				RequiredSteps: 2, CompletedSteps: 1, CompletionClass: contract.GeneratedCompletionConfirmed})
			if err != nil {
				t.Fatal(err)
			}
			x := p.expected.Template
			scope := contract.GeneratorControlledRetirementScope(x.DescriptorID, x.ConfigContractID, x.ResultContractID)
			p.expected.RequestDigest = contract.GeneratorControlledRetirementProbeDigest(p.expected.Plan.DomainID,
				x.ResourceIncarnationID, p.expected.TargetResourceDigest, scope, ackResult, ackDigest)
			p.preparation.RequestDigest = p.expected.RequestDigest
			p.progress, p.returnValue, p.claimed = [][]byte{progress}, nil, true
			authority := consumerID("claimed controlled probe authority")
			a.candidate = &generatedCandidateFacts{authorityDigest: authority}
			expected, material, seed := p.expected, a.material, bytes.Clone(a.seed)
			defer clear(seed)
			if err := expected.Validate(material); err != nil {
				t.Fatal("probe result context", err)
			}
			observed := [3]contract.ID{x.ResourceIncarnationID, expected.TargetResourceDigest, scope}
			if tc.zero == 4 {
				observed = [3]contract.ID{}
			} else if tc.zero != 0 {
				observed[tc.zero-1] = contract.ID{}
			}
			if tc.mismatch != 0 {
				observed[tc.mismatch-1] = consumerID("different observed identity")
			}
			response := make([]byte, 98)
			response[0] = tc.status
			for i, id := range observed {
				copy(response[1+32*i:1+32*(i+1)], id[:])
			}
			calls := 0
			p.probe = func(_ context.Context, command contract.GeneratedProducerCommand) []byte {
				calls++
				if command.Action != contract.GeneratorActionDelete || command.ResourceDigest != expected.TargetResourceDigest || command.RequestDigest != expected.RequestDigest {
					t.Error("probe changed its original target or preceding ACK transcript")
				}
				return response[:tc.length]
			}
			out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
			if out.code != contract.CryptoSuccess || calls != 1 || out.Facts.Disposition != tc.disposition {
				t.Fatalf("probe return code=%v calls=%d disposition=%d, want %d", out.code, calls, out.Facts.Disposition, tc.disposition)
			}
			factsBody, err := contract.EncodeGeneratorSafeFacts(out.Facts)
			if err != nil {
				t.Fatal("returned facts cannot be encoded", err)
			}
			if _, err := contract.InspectGeneratorSafeFacts(factsBody); err != nil {
				t.Fatal("returned facts cannot be decoded", err)
			}
			if tc.disposition == contract.GeneratorDispositionUnknown {
				want := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Disposition: contract.GeneratorDispositionUnknown,
					Action: contract.GeneratorActionDelete, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID,
					Reason: contract.GeneratorReasonRejected, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest}
				original, err := contract.InspectGeneratorSafeFacts(f.producer.Producer.OriginalFacts)
				if err != nil {
					t.Fatal(err)
				}
				want.Target, want.ResourceData = original.Target, original.ResourceData
				wantBody, err := contract.EncodeGeneratorSafeFacts(want)
				if err != nil {
					t.Fatal("expected unknown observation", err)
				}
				if !bytes.Equal(factsBody, wantBody) || len(out.Record) != 0 {
					t.Fatal("malformed observation became evidence or a result inbox")
				}
				return
			}
			if out.Facts.Schema != contract.GeneratorSafeFactsSchema || generatedFixtureResourceDigest(t, out.Facts) != expected.TargetResourceDigest || out.Facts.ScopeID != scope ||
				out.Facts.PrecedingResultID != ackResult || out.Facts.PrecedingResultBodyDigest != ackDigest ||
				out.Facts.ObservedResourceID != observed[0] || out.Facts.ObservedResourceDigest != observed[1] || out.Facts.ObservedScopeID != observed[2] {
				t.Fatal("qualified observation lost its exact target, predecessor or observed identities")
			}
			record, err := contract.DecodeGeneratedResultRecord(out.Record)
			if err != nil || !reflect.DeepEqual(record.SafeFacts, out.Facts) || contract.ValidateGeneratedResult(expected, material, record) != nil {
				t.Fatal("private result did not retain the qualified observation", err)
			}
			plain, err := custody.OpenGeneratedResult(expected, material, seed, record)
			if err != nil || len(plain) != 0 {
				t.Fatal("qualified observation has invalid result custody", err)
			}
			clear(plain)
		})
	}
}
