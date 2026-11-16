package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

type generatedFinalBatchFault struct {
	t        *testing.T
	inner    contract.Crypto
	stage    string
	fault    string
	supplied []uint32
	final    []uint8
	entries  []uint32
	changed  bool
}

func (f *generatedFinalBatchFault) InstanceID() contract.ID { return f.inner.InstanceID() }

func (f *generatedFinalBatchFault) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	reply := f.inner.Exchange(ctx, request)
	if request.Kind != contract.CryptoPrepare {
		return reply
	}
	if batch, err := contract.InspectCryptoGeneratedSuppliedRequest(request.Body); err == nil {
		actual, err := contract.InspectCryptoGeneratedSuppliedResult(reply.Body)
		if reply.ResultCode != contract.CryptoSuccess || err != nil || actual.BatchIndex != batch.BatchIndex || actual.Final != batch.Final || actual.Descriptor.Count == 0 {
			f.t.Fatal("real supplied batch did not succeed", batch.BatchIndex, reply.ResultCode, err)
		}
		f.supplied = append(f.supplied, batch.BatchIndex)
		f.final = append(f.final, batch.Final)
		if f.stage == "supplied" && batch.BatchIndex > 0 && batch.Final == 1 {
			f.change(&reply)
		}
		return reply
	}
	if batch, err := contract.InspectCryptoGeneratedValueEntriesRequest(request.Body); err == nil {
		actual, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
		if reply.ResultCode != contract.CryptoSuccess || err != nil || actual.BatchIndex != batch.BatchIndex || actual.Final != batch.Final || actual.RowCount() != 1 {
			f.t.Fatal("real generated entry batch did not succeed", batch.BatchIndex, reply.ResultCode, err)
		}
		f.entries = append(f.entries, batch.BatchIndex)
		if f.stage == "entries" && batch.BatchIndex == 0 {
			f.change(&reply)
		}
		return reply
	}
	f.t.Fatal("Final sent another preparation variant")
	return reply
}

func (f *generatedFinalBatchFault) change(reply *contract.CryptoResponse) {
	if f.changed {
		f.t.Fatal("Final repeated the faulted batch")
	}
	f.changed = true
	switch f.fault {
	case "cancelled":
		reply.ResultCode, reply.Body = contract.CryptoCancelled, nil
	case "unknown":
		reply.ResultCode, reply.Body = contract.CryptoResponseUnknown, nil
	case "wrong-index":
		reply.Body = bytes.Clone(reply.Body)
		binary.BigEndian.PutUint32(reply.Body[1:5], 0)
	case "wrong-final":
		reply.Body = bytes.Clone(reply.Body)
		reply.Body[5] ^= 1
	default:
		f.t.Fatal("unknown Final batch fault", f.fault)
	}
}

type generatedFinalFailureFixture struct {
	env         fixtureEnvironment
	admission   OpenContext
	predecessor *StateSession
	plan        *generatedFinalPlan
	attempt     contract.ID
	result      []byte
	effects     int
}

func newGeneratedFinalFailureFixture(t *testing.T) *generatedFinalFailureFixture {
	t.Helper()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	var sources []contract.GeneratorDeclarationEntry
	for i := 0; i < 65; i++ {
		name := fmt.Sprintf("large-%03d", i)
		secret := suppliedSecret(t, env, name, name+" final failure source", custody.MaximumValue)
		sources = append(sources, contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed,
			Name: secret.Name, Recipients: secret.Recipients, Payload: secret.InputBytes})
	}
	input := generatedPlanInputForGenerations(t, f.session, generatedVectorID(10), []string{"alpha"}, defaultGeneratedFixtureProfile(), sources...)
	reservation, _ := preparePrivateGeneratedReservation(t, env, f.session, input, nil)
	producer, expected := preparePrivateGeneratedProducer(t, env, f.session, reservation, nil)
	fixture := &generatedFinalFailureFixture{env: env, admission: f.admission, attempt: expected.Template.AttemptID}
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		fixture.effects++
		var code contract.CryptoResultCode
		fixture.result, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("original producer handoff")
	}
	selected, res := f.session.selectCandidate(ctx, producer.reservation.candidate)
	if selected == nil || res.Outcome != ObservedCurrent || fixture.effects != 1 || len(fixture.result) == 0 {
		t.Fatal("original producer selection", res)
	}
	keys.RetireGenerated()
	recordPlan := generatedRecordPlanForResult(t, selected, fixture.attempt, fixture.result, t.Name()+" record")
	record := preparePrivateGeneratedRecord(t, env, selected, recordPlan)
	recorded, res := selected.selectCandidate(ctx, record.reservation.candidate)
	if recorded == nil || res.Outcome != ObservedCurrent {
		t.Fatal("durable generated result", res)
	}
	cold, res := Open(ctx, f.admission, env.Store)
	if cold == nil || res.Outcome != ObservedCurrent || cold.head.Core != recorded.head.Core {
		t.Fatal("cold generated result", res)
	}
	fixture.predecessor = cold
	admitted := generatedPlanInputFixture(t, cold).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" failed final admission"), testID(t.Name()+" failed final session")
	var err error
	fixture.plan, err = cold.generatedFinalRequest(t.Context(), admitted)
	if err != nil || fixture.plan == nil || !fixture.plan.selecting || len(fixture.plan.supplied.Rows) != 65 || len(fixture.plan.entryPlans) != 1 {
		t.Fatal("multi-batch Final request", err)
	}
	return fixture
}

func (f *generatedFinalFailureFixture) assertRefusalAndRetry(t *testing.T, stage, fault string, want Result) {
	t.Helper()
	ctx := context.Background()
	before := sessionStateImage(t, f.predecessor)
	support, err := f.predecessor.preservedWorkSupportRecords(t.Context())
	if err != nil {
		t.Fatal("predecessor work support", err)
	}
	store := f.env.Store.(*memoryStore)
	trust := f.env.Trust.(*fixtureTrust)
	permit := admitPrivateGeneratedFinal(t, f.env, f.predecessor, f.plan)
	changed := &generatedFinalBatchFault{t: t, inner: permit.crypto, stage: stage, fault: fault}
	permit.crypto = changed
	creates, cas, signs, effects := store.creates, store.cas, trust.signs, f.effects
	prepared, result := f.predecessor.PrepareGeneratedFinal(ctx, permit)
	if prepared != nil || result != want || !permit.used || !changed.changed {
		t.Fatal("later Final failure did not consume its permit", result, permit.used, changed.changed)
	}
	if len(changed.supplied) < 2 || changed.supplied[0] != 0 || changed.supplied[1] != 1 ||
		changed.final[0] != 0 || changed.final[len(changed.final)-1] != 1 ||
		stage == "supplied" && len(changed.entries) != 0 || stage == "entries" && (len(changed.entries) != 1 || changed.entries[0] != 0) {
		t.Fatal("Final failure missed its real batch boundary", changed.supplied, changed.entries)
	}
	if again, reused := f.predecessor.PrepareGeneratedFinal(ctx, permit); again != nil || reused != refused(AdmissionInvalid) {
		t.Fatal("failed Final permit was reusable", reused)
	}
	if store.creates != creates || store.cas != cas || trust.signs != signs || f.effects != effects {
		t.Fatal("failed Final reached a durable or producer effect", store.creates-creates, store.cas-cas, trust.signs-signs, f.effects-effects)
	}
	cold, observed := Open(ctx, f.admission, f.env.Store)
	if cold == nil || observed.Outcome != ObservedCurrent || cold.head.Core != f.predecessor.head.Core {
		t.Fatal("failed Final changed the authenticated predecessor", observed)
	}
	assertStateImage(t, cold, before)
	retained, err := cold.preservedWorkSupportRecords(t.Context())
	if err != nil || !reflect.DeepEqual(retained, support) {
		t.Fatal("failed Final changed accepted work support", err)
	}
	work, err := cold.selectedGeneratedWork(context.Background())
	if err != nil || !bytes.Equal(work.attempts[f.attempt].result, f.result) || f.effects != effects {
		t.Fatal("failed Final changed the accepted result", err)
	}
	admitted := generatedPlanInputFixture(t, cold).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" fresh final admission"), testID(t.Name()+" fresh final session")
	freshPlan, err := cold.generatedFinalRequest(t.Context(), admitted)
	if err != nil {
		t.Fatal("fresh Final request", err)
	}
	cold, fresh := preparePrivateGeneratedFinal(t, f.env, cold, freshPlan)
	selected, observed := cold.selectCandidate(ctx, fresh.reservation.candidate)
	if selected == nil || observed.Outcome != ObservedCurrent || selected.root.ValueEntryCount != 66 ||
		selected.root.Generated.GeneratedCurrent != 1 || f.effects != effects {
		t.Fatal("fresh Final did not reuse the durable result", observed, f.effects-effects)
	}
}

// full_only: false
func TestGeneratedFinalLaterSuppliedFailurePreservesDurableResults(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fault string
		want  Result
	}{
		{"cancelled", "cancelled", refused(AdmissionInvalid)},
		{"unknown", "unknown", failure(EvidenceUnavailable, CustodyUnavailable)},
		{"wrong-batch-index", "wrong-index", refused(AdmissionInvalid)},
		{"wrong-final-marker", "wrong-final", refused(AdmissionInvalid)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newGeneratedFinalFailureFixture(t)
			fixture.assertRefusalAndRetry(t, "supplied", tc.fault, tc.want)
		})
	}
}

// full_only: false
func TestGeneratedFinalLaterEntryFailurePreservesDurableResults(t *testing.T) {
	fixture := newGeneratedFinalFailureFixture(t)
	fixture.assertRefusalAndRetry(t, "entries", "wrong-final", refused(AdmissionInvalid))
}
