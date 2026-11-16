package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
	wire "enkv.sh/sdk/protocols/generator"
	"enkv.sh/telemetry"
)

func generatedProducerFixture(t *testing.T, recovery bool) (generatedRuntimeFixture, contract.CryptoGeneratedFinishPlanResult, generatedCandidate) {
	t.Helper()
	return generatedProducerPlanFixture(t, generatedRuntimeEffectFixture(t, recovery))
}

func generatedProducerPlanFixture(t *testing.T, f generatedRuntimeFixture) (generatedRuntimeFixture, contract.CryptoGeneratedFinishPlanResult, generatedCandidate) {
	t.Helper()
	r := f.reservationRuntime(t)
	op := generatedCompare(t, r, f)
	generatedPlanParts(t, r, f, op)
	prepared := generatedFinishPlan(t, r, f, op)
	c := generatedPlanCandidate(t, f, prepared)
	r.retireGenerated()
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	x := g.Lineages[0].Templates[0]
	use := g.ResultUses[slices.IndexFunc(g.ResultUses, func(v contract.GeneratorResultUse) bool { return v.ResultID == x.ResultID })]
	encoding := uint8(contract.InputEncodingRaw)
	if x.Action == contract.GeneratorActionCreate {
		owner := slices.IndexFunc(g.ValueEntryPlans, func(entry contract.GeneratorValueEntryPlan) bool { return entry.LineageID == x.LineageID })
		if owner < 0 {
			t.Fatal("producer fixture lacks its owning create entry")
		}
		encoding = g.ValueEntryPlans[owner].InputEncoding
	}
	expected := contract.GeneratorResultExpectation{InputEncoding: encoding, Plan: g.UsePlan, Template: x, Use: use, RequestDigest: consumerID("HTTP request")}
	f.compare.Parent = contract.GeneratedParentRecord(f.compare.ParentPlan)
	f.compare.Parent.RequestIdentityDigest = c.Subject.RequestIdentityDigest
	f.compare.ParentPlan, f.compare.Purpose = contract.GeneratedParentPlan{}, 4
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f.producer = generatedProducerPreparationAdmissionInput{
		Session: f.reservation.Session, Plan: f.reservation.Plan, Phase: f.reservation.Phase, Target: f.reservation.Target,
		Material: prepared.Material, SeedAccess: prepared.SeedAccess, SourceProtections: nil,
		ControlledPredecessor: f.reservation.ControlledPredecessor,
	}
	preparation := contract.GeneratedProducerPreparation{Schema: contract.GeneratedProducerPreparationSchema, LifecycleMode: x.SemanticLifecycleMode(), DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
		RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest, PlanGraphID: g.UsePlan.PlanGraphID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TransmissionID: x.TransmissionID, ResultID: x.ResultID,
		ResultContractID: x.ResultContractID, DescriptorID: x.DescriptorID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		Action: x.Action, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest, ResourceContractID: x.ResourceContractID}
	useDigest, err := contract.GeneratorResultUseDigest(use)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]byte
	for _, purpose := range []uint8{3, 4} {
		row, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: x.DutyID,
			MaterialID: g.Header.MaterialID, ContextDigest: useDigest, SubjectKind: 3, SubjectID: x.ResultID, Purpose: purpose})
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	consumers, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, rows)
	if err != nil {
		t.Fatal(err)
	}
	duty := contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, DomainID: g.Header.DomainID, DutyID: x.DutyID,
		OriginalOperationID: g.Header.OperationID, OriginalAttemptID: x.AttemptID, OwnerID: x.DutyID,
		ResourceID: x.ResourceIncarnationID, DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID,
		CredentialRouteID: x.CredentialRouteID, ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID,
		Kind: contract.GeneratedDutyCreate, CompletionClass: x.CompletionClass, Step: 1, Status: contract.GeneratedEffectTransmitted,
		CapacityReservation: f.compare.Parent.Capacity,
		Target:              contract.EmptyGeneratorVector(contract.GeneratorVectorTargets), Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress),
		History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory), Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), Consumers: consumers}
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal(err)
	}
	attempt := contract.GeneratedAttemptRecord{Schema: contract.GeneratedAttemptRecordSchema, DomainID: g.Header.DomainID, OperationID: g.Header.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: template, PredecessorAttemptID: x.PredecessorAttemptID,
		OwnerID: x.DutyID, ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID, RequestDigest: expected.RequestDigest,
		State: contract.GeneratedEffectTransmitted, Stage: contract.GeneratedStageRetainedResult, CompletionClass: x.CompletionClass,
		Facts: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts), Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress),
		Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)}
	intent := generatedFixtureIntent(x.ConfigContractID, x.ResourceContractID, x.LifecycleMode, `{"name":"token"}`)
	duty.LifecycleMode, attempt.LifecycleMode = x.LifecycleMode, x.LifecycleMode
	if x.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
		duty.Target, duty.Progress, attempt.Progress = contract.EmptyGeneratorVector(contract.GeneratorVectorTargets), contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), contract.EmptyGeneratorVector(contract.GeneratorVectorProgress)
		intent = generatedFixtureIntent(x.ConfigContractID, contract.ID{}, contract.GeneratorLifecycleNone, `{}`)
	}
	f.producer.Producer = generatedProducerAdmissionInput{Expected: expected, Preparation: preparation, Intent: intent,
		Duty: duty, Attempt: attempt, Consumers: rows, Return: func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
			secret := []byte("provider-secret")
			if x.SemanticLifecycleMode() == contract.GeneratorLifecycleNone {
				secret = []byte("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
			}
			return generatedProducerReturn{Facts: generatedProducerFacts(expected), Secret: secret}
		}}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	dutyBody, err := contract.EncodeGeneratedDutyRecord(duty)
	if err != nil {
		t.Fatal(err)
	}
	c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: 9, RecordID: x.AttemptID, Body: attemptBody}, contract.SupportRecord{Kind: 10, RecordID: x.DutyID, Body: dutyBody})
	for i, row := range rows {
		carrier := contract.GeneratorVectorCarrier{Schema: 1, DomainID: g.Header.DomainID, OwnerKind: 10, OwnerID: x.DutyID,
			VectorKind: contract.GeneratorVectorConsumers, Ordinal: uint32(i), Vector: consumers, Row: row}
		id, err := contract.GeneratorVectorCarrierID(carrier)
		if err != nil {
			t.Fatal(err)
		}
		body, err := contract.EncodeGeneratorVectorCarrier(carrier)
		if err != nil {
			t.Fatal(err)
		}
		c.SupportRecords = append(c.SupportRecords, contract.SupportRecord{Kind: 14, RecordID: id, Body: body})
	}
	slices.SortFunc(c.SupportRecords, func(a, b contract.SupportRecord) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	c.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(g.Header.DomainID, c.SupportRecords)
	if err != nil {
		t.Fatal(err)
	}
	return f, prepared, c
}

func generatedProducerFacts(expected contract.GeneratorResultExpectation) contract.GeneratorSafeFacts {
	x := expected.Template
	facts := contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: x.Action, LifecycleMode: x.LifecycleMode, ResourceContractID: x.ResourceContractID,
		Disposition: contract.GeneratorDispositionCompleteCreate, RequestDigest: expected.RequestDigest, IntentDigest: x.IntentDigest}
	if x.LifecycleMode == contract.GeneratorLifecycleManaged {
		resource := consumerID("provider resource")
		facts.Target = []byte("private-service/target")
		facts.ResourceData = bytes.Clone(resource[:])
		facts.ProviderFacts = []byte{0, 255}
	}
	return facts
}

func generatedProducerPrepare(t *testing.T, r *Runtime, f generatedRuntimeFixture, op contract.ID) contract.ID {
	t.Helper()
	p := f.producer.Producer
	body, err := contract.EncodeCryptoGeneratedProducerRequest(contract.CryptoGeneratedProducerRequest{OperationRef: op, Context: f.compare.Context,
		Template: p.Expected.Template, Material: f.producer.Material, SeedAccess: f.producer.SeedAccess, Preparation: p.Preparation,
		Intent: contract.GeneratorDescriptor{Digest: p.Expected.Template.IntentDigest, Length: uint64(len(p.Intent)), Count: 1}})
	if err != nil {
		t.Fatal(err)
	}
	reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
	if reply.ResultCode != contract.CryptoSuccess || len(reply.KeyUseRows) != 0 {
		t.Fatal("prepare producer", reply.ResultCode)
	}
	result, err := contract.InspectCryptoGeneratedProducerResult(reply.Body)
	if err != nil {
		t.Fatal(err)
	}
	return result.ProducerLocatorID
}

func generatedProducerClaim(t *testing.T, r *Runtime, f generatedRuntimeFixture, c generatedCandidate, op contract.ID, uses []contract.KeyUseRow) contract.ID {
	t.Helper()
	if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoSuccess {
		t.Fatal("bind producer", code)
	}
	q := generatedCandidateRequest(t, f, op, c, nil, uses)
	if reply := generatedFreeze(t, r, q); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("freeze producer", reply.ResultCode)
	}
	body, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal(err)
	}
	if reply := applyCall(r, context.Background(), contract.CryptoClaim, body); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("claim producer", reply.ResultCode)
	}
	digest, err := contract.GeneratorAuthorityDigest(c.Subject)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

type generatedAdmissionLauncher struct {
	implementation contract.GeneratorImplementation
	starts         int
}

func (l *generatedAdmissionLauncher) Implementation() contract.GeneratorImplementation {
	return l.implementation
}

func (l *generatedAdmissionLauncher) Start(_ context.Context, _ wire.Command, writer *os.File) (generatorhost.Run, error) {
	l.starts++
	return nil, errors.Join(ErrAdmission, writer.Close())
}

// full_only: false
func TestGeneratedProducerRefusesLauncherResultContractMismatchBeforeEntry(t *testing.T) {
	route, routeID := generatedFixtureRoute(t)
	implementation := contract.GeneratorImplementation{Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind,
		DescriptorID: consumerID("descriptor"), ProtocolID: contract.ID(wire.ProtocolID()), ExecutorID: consumerID("executor"), ArtifactContractID: consumerID("artifact contract"),
		ConfigContractID: consumerID("configuration contract"), DependencyManifestID: consumerID("dependencies"), ArtifactSHA256: consumerID("artifact"),
		CredentialRouteID: routeID, CredentialRoute: route, ArtifactLength: 1, Module: "fixture", Command: "fixture/cmd/plugin", Version: "0.0.0", GoVersion: runtime.Version(), NativeTuple: runtime.GOOS + "/" + runtime.GOARCH}
	resultContract, err := contract.GeneratedResultContractID(implementation, contract.GeneratorActionCreate, contract.GeneratedCompletionAcknowledged, 65536, 4096, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal("baseline implementation", err)
	}
	for _, name := range []string{"matching", "descriptor changed", "protocol changed", "input class differs from graph"} {
		t.Run(name, func(t *testing.T) {
			selectedContract := resultContract
			if name == "input class differs from graph" {
				var err error
				selectedContract, err = contract.GeneratedResultContractID(implementation, contract.GeneratorActionCreate, contract.GeneratedCompletionAcknowledged, 65536, 4096, contract.InputEncodingBase64)
				if err != nil {
					t.Fatal("classified implementation contract", err)
				}
			}
			f, _, candidate := generatedProducerPlanFixture(t, generatedRuntimeEffectFixture(t, false, selectedContract))
			if name == "input class differs from graph" {
				f.producer.Producer.Expected.InputEncoding = contract.InputEncodingBase64
			}
			launcher := &generatedAdmissionLauncher{implementation: implementation}
			switch name {
			case "descriptor changed":
				launcher.implementation.DescriptorID = consumerID("other descriptor")
			case "protocol changed":
				launcher.implementation.ProtocolID = consumerID("other protocol")
			}
			f.producer.Producer.Return, f.producer.Producer.Process = nil, launcher
			r := newConsumerRuntime(t, f.base.route)
			admissionErr := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline)
			matching := name == "matching"
			if matching && admissionErr != nil {
				t.Fatal("matching launcher refused", admissionErr)
			}
			if !matching && !errors.Is(admissionErr, ErrAdmission) {
				t.Error("launcher with a different result contract was admitted", admissionErr)
			}
			if admissionErr == nil {
				op, uses := generatedAdoptionCompare(t, r, f)
				locator := generatedProducerPrepare(t, r, f, op)
				authority := generatedProducerClaim(t, r, f, candidate, op, uses)
				out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
				if len(out.Record) != 0 || out.code == contract.CryptoSuccess {
					t.Error("refused launcher returned successful effect evidence", out.code)
				}
			}
			wantStarts := 0
			if matching {
				wantStarts = 1
			}
			if launcher.starts != wantStarts {
				t.Errorf("launcher starts = %d, want %d", launcher.starts, wantStarts)
			}
		})
	}
}

// full_only: false
func TestGeneratedProducerDoesNotRetainWholeDeclaration(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(*testing.T) generatedRuntimeFixture
	}{
		{"generated", func(t *testing.T) generatedRuntimeFixture { return generatedRuntimeEffectFixture(t, false) }},
		{"retained-canonical", func(t *testing.T) generatedRuntimeFixture {
			f := generatedCanonicalPlanFixtureFrom(t, generatedRuntimeEffectFixture(t, false))
			selected := &f.reservation.Plan.Canonical[0]
			owner := consumerID("retained producer owner")
			context, err := contract.ValueMaterialContextDigest(selected.Selection.Core)
			if err != nil {
				t.Fatal(err)
			}
			body, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: owner,
				MaterialID: selected.Selection.Core.ValueStateID, ContextDigest: context,
				SubjectKind: contract.GeneratorConsumerRetainedCanonicalValue,
				SubjectID:   selected.Selection.Core.ValueStateID, Purpose: contract.GeneratorConsumerUseRetainedCanonical})
			if err != nil {
				t.Fatal(err)
			}
			selected.Consumers = [][]byte{body}
			consumers, err := contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, selected.Consumers)
			if err != nil {
				t.Fatal(err)
			}
			selected.Owner = contract.SupportRecord{Kind: contract.GeneratedDutySupportKind, RecordID: owner}
			selected.Owner.Body, err = contract.EncodeGeneratedDutyRecord(contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, LifecycleMode: contract.GeneratorLifecycleManaged,
				DomainID: selected.Selection.DomainID, DutyID: owner, OriginalOperationID: consumerID("retained producer original operation"),
				OriginalAttemptID: consumerID("retained producer original attempt"), OwnerID: owner,
				ResourceID: consumerID("retained producer resource"), DescriptorID: consumerID("retained producer profile"),
				ConfigContractID: consumerID("retained producer assumption"), ExecutorID: consumerID("retained producer executor"),
				CredentialRouteID: consumerID("retained producer route"), ResourceContractID: consumerID("retained producer permission"),
				ResultContractID: consumerID("retained producer result"), Kind: contract.GeneratedDutyRetirement,
				CompletionClass: 1, Step: 1, Status: contract.GeneratedEffectTransmitted,
				CapacityReservation: contract.GeneratorDescriptor{Digest: consumerID("retained producer capacity"), Length: 8, Count: 1},
				Target:              contract.EmptyGeneratorVector(contract.GeneratorVectorTargets),
				Progress:            contract.EmptyGeneratorVector(contract.GeneratorVectorProgress), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory),
				Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), Consumers: consumers})
			if err != nil {
				t.Fatal(err)
			}
			return f
		}},
		{"sealed-source", func(t *testing.T) generatedRuntimeFixture { return generatedSealedPlanFixture(t, false) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, prepared, candidate := generatedProducerPlanFixture(t, test.build(t))
			if len(prepared.SourceProtections) != 0 {
				var err error
				f.producer.SourceProtections, err = contract.EncodeGeneratedSourceProtections(prepared.Material, prepared.SourceProtections)
				if err != nil {
					t.Fatal(err)
				}
			}
			r := f.producerRuntime(t)
			plan := &r.generated.purpose.producer.plan
			if len(plan.declaration) != 0 || cap(plan.declaration) != 0 {
				t.Fatalf("producer admission retained %d declaration bytes", cap(plan.declaration))
			}
			for _, canonical := range plan.canonicals {
				if len(canonical.buffer) != 0 || cap(canonical.buffer) != 0 {
					t.Fatalf("producer canonical pinned %d declaration bytes", cap(canonical.buffer))
				}
			}
			original := bytes.Clone(f.producer.Plan.Declaration)
			for i := range f.producer.Plan.Declaration {
				f.producer.Plan.Declaration[i] ^= 0xff
			}
			op, uses := generatedAdoptionCompare(t, r, f)
			locator := generatedProducerPrepare(t, r, f, op)
			if test.name == "generated" {
				authority := generatedProducerClaim(t, r, f, candidate, op, uses)
				if out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); out.code != contract.CryptoSuccess {
					t.Fatal("producer after caller mutation", out.code)
				}
			}
			r.retireGenerated()
			copy(f.producer.Plan.Declaration, original)
			r = f.producerRuntime(t)
			r.retireGenerated()
			if !bytes.Equal(f.producer.Plan.Declaration, original) {
				t.Fatal("retiring producer changed caller declaration")
			}
		})
	}
}

// full_only: false
func TestGeneratedProducerSealsOneOriginalReturn(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		recorder := telemetry.NewRecorder()
		ctx := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
		f, prepared, c := generatedProducerPlanFixture(t, generatedRuntimeOutputFixtureFrom(t, generatedRuntimeEffectFixture(t, recovery), false))
		secret := []byte("provider-secret")
		calls := 0
		f.producer.Producer.Return = func(_ context.Context, command contract.GeneratedProducerCommand, intent []byte) generatedProducerReturn {
			calls++
			if command.GeneratedProducerPreparation != f.producer.Producer.Preparation || !bytes.Equal(intent, f.producer.Producer.Intent) {
				t.Error("changed producer inputs")
			}
			return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: secret}
		}
		r := f.producerRuntime(t)
		a, witness := generatedOutputOwner(t, r, f.producer.Session.Output, f.producer.Session.BeforePublic)
		op, uses := generatedAdoptionCompare(t, r, f)
		locator := generatedProducerPrepare(t, r, f, op)
		authority, err := contract.GeneratorAuthorityDigest(c.Subject)
		if err != nil {
			t.Fatal(err)
		}
		if out := r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, locator, authority); out.code != contract.CryptoInvalidAdmission || calls != 0 {
			t.Fatal("entry before claim", out.code, calls)
		}
		authority = generatedProducerClaim(t, r, f, c, op, uses)
		generatedOutputReleased(t, r, a, f.producer.Session.Output, witness)
		out := r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, locator, authority)
		if out.code != contract.CryptoSuccess || calls != 1 || len(out.Record) == 0 || !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("original return", out.code, calls)
		}
		seed := generatedTestSeed(t, f, prepared)
		record, err := contract.DecodeGeneratedResultRecord(out.Record)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := custody.OpenGeneratedResult(f.producer.Producer.Expected, prepared.Material, seed, record)
		if err != nil || string(plain) != "provider-secret" {
			t.Fatal("original ciphertext", err)
		}
		clear(seed)
		clear(plain)
		if out := r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, locator, authority); out.code != contract.CryptoAlreadyUsed || calls != 1 {
			t.Fatal("duplicate entry", out.code, calls)
		}
		r.retireGenerated()
		generatedOutputReleased(t, r, a, f.producer.Session.Output, witness)
		records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32))
		starts := map[telemetry.Operation]int{}
		returns := map[telemetry.Operation]int{}
		var entryCall, settlementCall uint64
		for _, record := range records {
			if err := record.Validate(); err != nil {
				t.Fatal(err)
			}
			switch record.Event {
			case telemetry.DiagnosticStart:
				starts[record.Operation]++
				if record.Operation == telemetry.OpCryptoGeneratedProducerEntry && starts[record.Operation] == 2 {
					entryCall = record.Call
				}
				if record.Operation == telemetry.OpCryptoGeneratedReturnSettle {
					settlementCall = record.Call
					if record.ParentCall != entryCall || record.AttemptID != hex.EncodeToString(f.producer.Producer.Preparation.AttemptID[:]) {
						t.Fatal("private return settlement lost caller parent")
					}
				}
				if record.Operation == telemetry.OpCryptoGeneratedResultSeal && (record.ParentCall != settlementCall || record.AttemptID != hex.EncodeToString(f.producer.Producer.Preparation.AttemptID[:])) {
					t.Fatal("result seal lost return owner parent")
				}
			case telemetry.DiagnosticReturn:
				returns[record.Operation]++
			}
		}
		for operation, want := range map[telemetry.Operation]int{telemetry.OpCryptoGeneratedProducerEntry: 3, telemetry.OpCryptoGeneratedReturnSettle: 1, telemetry.OpCryptoGeneratedResultSeal: 1} {
			if starts[operation] != want || returns[operation] != want {
				t.Fatalf("%s starts=%d returns=%d want=%d", operation, starts[operation], returns[operation], want)
			}
		}
		encoded, err := json.Marshal(records)
		if err != nil || bytes.Contains(encoded, []byte("provider-secret")) {
			t.Fatal("private producer result reached telemetry")
		}
	}
}

// full_only: false
func TestGeneratedProducerCancellationJoinsOriginalReturn(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(strconv.FormatBool(recovery), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, prepared, c := generatedProducerPlanFixture(t, generatedRuntimeOutputFixtureFrom(t, generatedRuntimeEffectFixture(t, recovery), false))
				entered, release := make(chan struct{}), make(chan struct{})
				finishReturn := sync.OnceFunc(func() { close(release) })
				defer finishReturn()
				secret := []byte("late-original-secret")
				calls := 0
				f.producer.Producer.Return = func(ctx context.Context, _ contract.GeneratedProducerCommand, _ []byte) generatedProducerReturn {
					calls++
					close(entered)
					<-release
					if ctx.Err() != nil {
						t.Error("entered return owner inherited session cancellation", ctx.Err())
					}
					return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: secret}
				}
				r := f.producerRuntime(t)
				a, witness := generatedOutputOwner(t, r, f.producer.Session.Output, f.producer.Session.BeforePublic)
				op, uses := generatedAdoptionCompare(t, r, f)
				locator := generatedProducerPrepare(t, r, f, op)
				authority := generatedProducerClaim(t, r, f, c, op, uses)
				generatedOutputReleased(t, r, a, f.producer.Session.Output, witness)
				r.mu.Lock()
				ownedSeed := a.seed
				producer := a.purpose.producer.producer
				ownedIntent := producer.intent[:cap(producer.intent)]
				progressBacking := bytes.Repeat([]byte{0x5a}, 31)
				producer.progress = [][]byte{progressBacking[:19]}
				r.mu.Unlock()
				recorder := telemetry.NewRecorder()
				base := telemetry.WithCapability(context.Background(), telemetry.NewCapability(nil, recorder))
				ctx, cancel := context.WithCancel(base)
				defer cancel()
				result := make(chan generatedProducerOutput, 1)
				go func() { result <- r.invokeGeneratedProducer(ctx, f.compare.Context.AdmissionID, locator, authority) }()
				<-entered
				generatedOutputReleased(t, r, a, f.producer.Session.Output, witness)
				r.mu.Lock()
				owner := a.purpose.producer.returnOwner
				sessionSeed := a.seed
				r.mu.Unlock()
				if owner == nil || len(owner.seed) == 0 || len(owner.intent) == 0 || len(owner.progress) != 1 || len(sessionSeed) != 0 ||
					len(producer.intent) != 0 || len(producer.progress) != 0 {
					t.Fatal("entry did not transfer all return buffers to the return owner")
				}
				select {
				case <-owner.done:
					t.Fatal("return owner disposed before its return joined")
				default:
				}
				public, private := f.base.route.publicCalls, f.base.route.privateCalls
				cancel()
				<-a.ctx.Done()
				closed := make(chan struct{})
				go func() { r.Close(); close(closed) }()
				synctest.Wait()
				select {
				case <-closed:
					t.Fatal("Close did not join the entered return")
				default:
				}
				if bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) || bytes.Equal(ownedIntent, make([]byte, len(ownedIntent))) ||
					bytes.Equal(progressBacking, make([]byte, len(progressBacking))) {
					t.Error("ordinary session disposal cleared active return-owner buffers")
				}
				if out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); out.code == contract.CryptoSuccess || calls != 1 || len(out.Record) != 0 {
					t.Error("closing runtime restored effect entry", out.code)
				}
				finishReturn()
				out := <-result
				<-closed
				generatedOutputReleased(t, r, a, f.producer.Session.Output, witness)
				if out.code != contract.CryptoSuccess || len(out.Record) == 0 || !bytes.Equal(secret, make([]byte, len(secret))) ||
					!bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) || !bytes.Equal(ownedIntent, make([]byte, len(ownedIntent))) ||
					!bytes.Equal(progressBacking, make([]byte, len(progressBacking))) || len(owner.seed) != 0 || len(owner.intent) != 0 || len(owner.progress) != 0 {
					t.Fatal("return-only disposal", out.code)
				}
				select {
				case <-owner.done:
				default:
					t.Fatal("Close completed before the return owner joined")
				}
				if again := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); again.code == contract.CryptoSuccess || calls != 1 || len(again.Record) != 0 {
					t.Fatal("closed runtime regenerated a result", again.code)
				}
				if f.base.route.publicCalls != public || f.base.route.privateCalls != private {
					t.Fatal("original return reopened a retired key route")
				}
				record, err := contract.DecodeGeneratedResultRecord(out.Record)
				if err != nil {
					t.Fatal(err)
				}
				seed := generatedTestSeed(t, f, prepared)
				defer clear(seed)
				plain, err := custody.OpenGeneratedResult(f.producer.Producer.Expected, prepared.Material, seed, record)
				defer clear(plain)
				if err != nil || string(plain) != "late-original-secret" {
					t.Fatal("late original result", err)
				}
				var settled bool
				for _, event := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 32)) {
					if event.Operation == telemetry.OpCryptoGeneratedReturnSettle && event.Event == telemetry.DiagnosticReturn && event.Result == telemetry.ResultSuccess {
						settled = true
					}
				}
				if !settled {
					t.Fatal("late return owner lost invocation telemetry after caller cancellation")
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedProducerReturnAfterCommandDeadlineIsExpired(t *testing.T) {
	for _, parent := range []time.Duration{12 * time.Second, 5 * time.Minute} {
		t.Run(parent.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, _, candidate := generatedProducerFixture(t, false)
				f.base.deadline = time.Now().Add(parent)
				f.compare.Context.Expiry = uint64(f.base.deadline.UnixNano())
				var err error
				f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
				if err != nil {
					t.Fatal(err)
				}
				secret := append([]byte("late-provider-secret"), bytes.Repeat([]byte{0x5a}, 17)...)
				var want contract.GeneratedProducerCommand
				f.producer.Producer.Return = func(ctx context.Context, command contract.GeneratedProducerCommand, _ []byte) generatedProducerReturn {
					deadline, ok := ctx.Deadline()
					if !reflect.DeepEqual(command, want) || !ok || !deadline.Equal(time.UnixMilli(int64(want.DeadlineUnixMillis))) {
						t.Error("late return did not receive the exact fixed issued command")
					}
					<-ctx.Done()
					if !time.Now().Equal(deadline) {
						t.Error("return context expired at a different deadline")
					}
					return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: secret[:len("late-provider-secret")]}
				}
				r := f.producerRuntime(t)
				op, uses := generatedAdoptionCompare(t, r, f)
				locator := generatedProducerPrepare(t, r, f, op)
				authority := generatedProducerClaim(t, r, f, candidate, op, uses)
				deadline := uint64(f.base.deadline.UnixMilli())
				maximum := uint64(time.Now().UnixMilli()) + 90_000
				if deadline > maximum {
					deadline = maximum
				}
				want = contract.GeneratedProducerCommand{GeneratedProducerPreparation: f.producer.Producer.Preparation, DeadlineUnixMillis: deadline, Intent: f.producer.Producer.Intent, OriginalFacts: f.producer.Producer.OriginalFacts}
				out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
				if out.code != contract.CryptoExpired || out.stage != generatedFailureReturn || out.category != generatedFailureExpired || out.effect != generatedEffectUnknown ||
					len(out.Record) != 0 || !bytes.Equal(secret, make([]byte, len(secret))) || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
					t.Fatal("late producer return was accepted or retained", out.code, len(out.Record))
				}
				r.retireGenerated()
			})
		})
	}
}

// full_only: false
func TestGeneratedProducerNoNewEntryAfterExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _, c := generatedProducerFixture(t, false)
		calls := 0
		f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
			calls++
			return generatedProducerReturn{}
		}
		r := f.producerRuntime(t)
		op, uses := generatedAdoptionCompare(t, r, f)
		locator := generatedProducerPrepare(t, r, f, op)
		authority := generatedProducerClaim(t, r, f, c, op, uses)
		r.mu.Lock()
		a := r.generated
		ownedSeed := a.seed
		r.mu.Unlock()
		time.Sleep(time.Until(f.base.deadline))
		synctest.Wait()
		<-a.done
		out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
		if out.code == contract.CryptoSuccess || calls != 0 || !bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) {
			t.Fatal("expired producer entered", out.code, calls)
		}
	})

	t.Run("unrepresentable remaining millisecond", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, _, candidate := generatedProducerFixture(t, false)
			f.base.deadline = time.Now().Truncate(time.Millisecond).Add(12*time.Second + 500*time.Microsecond)
			f.compare.Context.Expiry = uint64(f.base.deadline.UnixNano())
			var err error
			f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
				calls++
				return generatedProducerReturn{}
			}
			r := f.producerRuntime(t)
			op, uses := generatedAdoptionCompare(t, r, f)
			locator := generatedProducerPrepare(t, r, f, op)
			authority := generatedProducerClaim(t, r, f, candidate, op, uses)
			a := r.generated
			state := a.purpose.producer
			producer := state.producer
			ownedSeed := a.seed
			time.Sleep(time.Until(f.base.deadline.Add(-250 * time.Microsecond)))
			if !time.Now().Before(f.base.deadline) {
				t.Fatal("parent expired before the rounding boundary")
			}
			out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
			r.mu.Lock()
			owner := state.returnOwner
			r.mu.Unlock()
			if out.code != contract.CryptoExpired || out.stage != generatedFailureDeadline || out.category != generatedFailureExpired || out.effect != generatedEffectNoSend ||
				calls != 0 || len(out.Record) != 0 || !producer.entryUsed || owner != nil {
				t.Fatal("unrepresentable child deadline entered an effect", out.code, calls)
			}
			r.retireGenerated()
			if !bytes.Equal(ownedSeed, make([]byte, len(ownedSeed))) {
				t.Fatal("refused entry did not join seed disposal")
			}
		})
	})
}

// full_only: false
func TestGeneratedProducerUnknownHasNoResultRecord(t *testing.T) {
	f, _, c := generatedProducerFixture(t, false)
	secret := []byte("unqualified-return")
	f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
		facts := generatedProducerFacts(f.producer.Producer.Expected)
		facts.Disposition, facts.Reason = contract.GeneratorDispositionUnknown, contract.GeneratorReasonMalformed
		facts.Target, facts.ResourceData, facts.ProviderFacts = nil, nil, nil
		return generatedProducerReturn{Facts: facts, Secret: secret}
	}
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, c, op, uses)
	out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
	if out.code != contract.CryptoSuccess || out.Facts.Disposition != contract.GeneratorDispositionUnknown || len(out.Record) != 0 || !bytes.Equal(secret, make([]byte, len(secret))) ||
		out.stage != "" || out.category != "" || out.effect != generatedEffectUnknown {
		t.Fatal("unknown fabricated result", out.code, out.Facts.Disposition)
	}
}

// full_only: false
func TestGeneratedProducerMissingAdmissionHasClosedNoSend(t *testing.T) {
	r := &Runtime{}
	id := sha256.Sum256([]byte("missing admission"))
	out := r.invokeGeneratedProducer(context.Background(), id, contract.ID{}, contract.ID{})
	if out.code != contract.CryptoInvalidAdmission || out.stage != generatedFailureEntry || out.category != generatedFailureInvalid ||
		out.effect != generatedEffectNoSend || len(out.Record) != 0 || !reflect.DeepEqual(out.Facts, contract.GeneratorSafeFacts{}) {
		t.Fatal("missing admission gained a process or qualified facts")
	}
}

// full_only: false
func TestGeneratedProducerUnknownRespectsAdmittedFactsBound(t *testing.T) {
	f := generatedRuntimeEffectFixture(t, false)
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	for i := range g.ResultUses {
		g.ResultUses[i].MaxFacts = 1
	}
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	f.graph, err = contract.EncodeGeneratorPlanBundle(g)
	if err != nil {
		t.Fatal(err)
	}
	f.reservation.Session.Graph = f.graph
	f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.ParentPlan.Graph, f.compare.ParentPlan.UsePlanDigest = f.compare.PlanGraph, f.compare.UsePlanDigest
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f, _, candidate := generatedProducerPlanFixture(t, f)
	secret := []byte("unqualified-return")
	f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
		facts := generatedProducerFacts(f.producer.Producer.Expected)
		facts.Disposition, facts.Reason = contract.GeneratorDispositionUnknown, contract.GeneratorReasonMalformed
		facts.Target, facts.ResourceData, facts.ProviderFacts = nil, nil, nil
		return generatedProducerReturn{Facts: facts, Secret: secret}
	}
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, candidate, op, uses)
	out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
	if out.code != contract.CryptoCustodyUnavailable || len(out.Record) != 0 || out.Facts.Disposition != 0 || !bytes.Equal(secret, make([]byte, len(secret))) ||
		out.stage != generatedFailureFacts || out.category != generatedFailureInvalid || out.effect != generatedEffectUnknown {
		t.Fatal("unknown exceeded admitted facts bound", out.code, out.Facts.Disposition)
	}
}

// full_only: false
func TestGeneratedProducerCreateRequiresReservationPhase(t *testing.T) {
	f, _, _ := generatedProducerFixture(t, false)
	for _, purpose := range []contract.GeneratorAuthorityPurpose{contract.GeneratorAuthorityReservation, contract.GeneratorAuthorityRetireReserve, contract.GeneratorAuthorityCleanupReserve} {
		f.producer.Phase = &contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest,
			ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
			TransitionKind: purpose, BeforePhase: 1, AfterPhase: 2, Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)}
		r := newConsumerRuntime(t, f.base.route)
		err := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline)
		if (err == nil) != (purpose == contract.GeneratorAuthorityReservation) {
			t.Fatalf("create admitted phase %v: %v", purpose, err)
		}
		r.retireGenerated()
	}
}

// full_only: false
func TestGeneratedSuccessorProducerBindsReservationEvidenceAndSubject(t *testing.T) {
	f, _, candidate := generatedProducerFixture(t, false)
	original := f.producer.Producer.Expected.Template
	f.producer.Producer.Return = func(context.Context, contract.GeneratedProducerCommand, []byte) generatedProducerReturn {
		return generatedProducerReturn{Facts: contract.GeneratorSafeFacts{Schema: contract.GeneratorSafeFactsSchema, Action: contract.GeneratorActionCreate, LifecycleMode: original.LifecycleMode, ResourceContractID: original.ResourceContractID,
			Disposition: contract.GeneratorDispositionConfirmedNoEffect, RequestDigest: f.producer.Producer.Expected.RequestDigest, IntentDigest: original.IntentDigest}}
	}
	r := f.producerRuntime(t)
	op, uses := generatedAdoptionCompare(t, r, f)
	locator := generatedProducerPrepare(t, r, f, op)
	authority := generatedProducerClaim(t, r, f, candidate, op, uses)
	packet := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
	if packet.code != contract.CryptoSuccess || len(packet.Record) == 0 {
		t.Fatal("qualified predecessor result", packet.code)
	}
	graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	x := graph.Lineages[0].Templates[1]
	attempt := f.producer.Producer.Attempt
	attempt.State, attempt.Stage = contract.GeneratedEffectConfirmedNoEffect, contract.GeneratedStageTerminal
	body, err := contract.EncodeGeneratedAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	for i := range candidate.SupportRecords {
		if candidate.SupportRecords[i].Kind == contract.GeneratedAttemptSupportKind && candidate.SupportRecords[i].RecordID == attempt.AttemptID {
			candidate.SupportRecords[i].Body = body
		}
	}
	candidate.SupportRecords = append(candidate.SupportRecords, contract.SupportRecord{Kind: contract.GeneratedResultSupportKind,
		RecordID: original.ResultID, Body: packet.Record})
	candidate.Subject.Purpose = contract.GeneratorAuthorityReservation
	candidate.Subject.LineageID, candidate.Subject.AttemptID = x.LineageID, x.AttemptID
	candidate.Subject.PredecessorAttemptID, candidate.Subject.ResultID = x.PredecessorAttemptID, x.ResultID
	candidate.Subject.DescriptorID, candidate.Subject.ConfigContractID, candidate.Subject.ResultContractID = x.DescriptorID, x.ConfigContractID, x.ResultContractID
	candidate.Subject.ResultDigest = contract.ID{}
	templateBody, err := contract.EncodeGeneratorAttemptTemplate(x)
	if err != nil {
		t.Fatal(err)
	}
	phase := contract.GeneratorPhaseIdentity{TransitionKind: contract.GeneratorAuthorityReservation,
		Evidence: contract.GeneratorDescriptor{Digest: contract.Hash(templateBody), Length: uint64(len(templateBody)), Count: 1}}
	state := &generatedProducerPreparationState{phase: &phase, producer: &generatedProducer{
		expected: contract.GeneratorResultExpectation{InputEncoding: contract.InputEncodingRaw, Template: x}, attempt: contract.GeneratedAttemptRecord{RequestDigest: attempt.RequestDigest}}}
	admission := &generatedAdmission{graph: graph, purpose: generatedPurposeState{producer: state}}
	if !admission.candidateSuccessorReservationProducer(candidate) {
		t.Fatal("exact successor reservation did not match Crypto candidate")
	}
	badEvidence := phase
	badEvidence.Evidence.Digest = consumerID("changed successor evidence")
	state.phase = &badEvidence
	if admission.candidateSuccessorReservationProducer(candidate) {
		t.Fatal("changed reservation evidence matched")
	}
	state.phase = &phase
	for _, field := range []struct {
		name   string
		change func(*contract.GeneratorAuthoritySubject)
	}{
		{"predecessor", func(s *contract.GeneratorAuthoritySubject) { s.PredecessorAttemptID = consumerID("other predecessor") }},
		{"result", func(s *contract.GeneratorAuthoritySubject) { s.ResultID = consumerID("other result") }},
	} {
		t.Run(field.name, func(t *testing.T) {
			changed := candidate
			field.change(&changed.Subject)
			if admission.candidateSuccessorReservationProducer(changed) {
				t.Fatal("changed successor subject matched")
			}
		})
	}
}

func generatedDeleteProducerFixture(t *testing.T, recovery bool) generatedRuntimeFixture {
	t.Helper()
	f, _, _ := generatedProducerFixture(t, recovery)
	return f
}

func generatedSelectDeleteProducer(t *testing.T, f generatedRuntimeFixture, kind uint8) generatedRuntimeFixture {
	t.Helper()
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	original := g.Lineages[0]
	create := original.Templates[0]
	originalFacts := generatedProducerFacts(f.producer.Producer.Expected)
	originalFactsBody, err := contract.EncodeGeneratorSafeFacts(originalFacts)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest, err := contract.GeneratorResourceDigest(originalFacts)
	if err != nil {
		t.Fatal(err)
	}
	operation := consumerID("fresh delete operation " + strconv.Itoa(int(kind)))
	g.Request.OperationID, g.Request.CallerNonce = operation, consumerID("fresh delete nonce "+strconv.Itoa(int(kind)))
	g.Request.OperationKind = contract.OperationRetireGeneratedGeneration
	if kind == contract.GeneratedDutyUnselectedCleanup {
		g.Request.OperationKind = contract.OperationCleanOwnedFailureResidue
	}
	declaration := contract.GeneratorDeclaration{Schema: 1, DomainID: g.Header.DomainID, OperationID: operation}
	f.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	g.Request.Declaration, err = contract.GeneratorDeclarationDescriptor(declaration)
	if err != nil {
		t.Fatal(err)
	}
	g.Header.OperationID = operation
	g.Header.MaterialID, err = contract.GeneratorMaterialID(g.Header.DomainID, operation)
	if err != nil {
		t.Fatal(err)
	}
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	if err != nil {
		t.Fatal(err)
	}
	lineage := contract.GeneratorLineageTemplate{Schema: contract.GeneratorLineageTemplateSchema, DomainID: g.Header.DomainID, OperationID: operation,
		Purpose: contract.GeneratorLineagePurpose(kind), ResourceIncarnationID: create.ResourceIncarnationID, Name: original.Name,
		EntryIncarnationID: original.EntryIncarnationID, Epoch: original.Epoch, IntentDigest: original.IntentDigest, TemplateCount: 1}
	lineage.LineageID, err = contract.GeneratorObligationLineageID(lineage.DomainID, lineage.OperationID, lineage.ResourceIncarnationID, lineage.Purpose)
	if err != nil {
		t.Fatal(err)
	}
	x := &lineage.Templates[0]
	*x = create
	x.Action, x.Branch, x.NoEffectBudget, x.ResidueBudget, x.PredecessorAttemptID = 2, 0, 0, 0, contract.ID{}
	x.ResourceDigest = originalDigest
	x.LineageID, x.TargetKind, x.TargetSourceID = lineage.LineageID, 2, lineage.ResourceIncarnationID
	if kind == contract.GeneratedDutyUnselectedCleanup {
		x.TargetKind, x.TargetSourceID = 3, create.ResultID
	} else {
		x.DutyID, err = contract.GeneratorDutyID(lineage.DomainID, original.OperationID, create.AttemptID, 2)
		if err != nil {
			t.Fatal(err)
		}
	}
	x.ResultContractID = consumerID("delete result contract")
	x.AttemptID, err = contract.GeneratorAttemptID(x.LineageID, 0)
	if err != nil {
		t.Fatal(err)
	}
	x.PlannedValueSlotID, err = contract.GeneratorValueSlotID(lineage.DomainID, lineage.OperationID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.HazardID, err = contract.GeneratorHazardID(lineage.DomainID, x.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	x.TransmissionID, err = contract.GeneratorTransmissionID(x.AttemptID, 2)
	if err != nil {
		t.Fatal(err)
	}
	x.ResultID, err = contract.GeneratorResultID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.TransmissionID, 2)
	if err != nil {
		t.Fatal(err)
	}
	x.InboxID, err = contract.GeneratorInboxID(lineage.DomainID, lineage.OperationID, x.AttemptID, x.ResultID)
	if err != nil {
		t.Fatal(err)
	}
	x.RequestPlanDigest, err = contract.GeneratorRequestPlanDigest(*x)
	if err != nil {
		t.Fatal(err)
	}
	g.Lineages, g.ValueEntryPlans, g.Edges, g.ResultUses, g.SourceUses = []contract.GeneratorLineageTemplate{lineage}, nil, nil, nil, nil
	template, err := contract.GeneratorTemplateID(*x)
	if err != nil {
		t.Fatal(err)
	}
	join, err := contract.GeneratorCompleteJoinID(g.Header.RequestCoreDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []uint8{3, 4} {
		g.Edges = append(g.Edges, contract.GeneratorEdge{Schema: 1, SourceTemplateID: template, DestinationTemplateID: join,
			Guard: guard, ResultSlotID: x.ResultID, RequiredAuthoritySet: x.RequiredAuthoritySet})
	}
	g.ResultUses = append(g.ResultUses, contract.GeneratorResultUse{Schema: 1, AttemptID: x.AttemptID, ResultID: x.ResultID,
		InboxID: x.InboxID, ExecutorID: x.ExecutorID, ResultContractID: x.ResultContractID, PlannedValueSlotID: x.PlannedValueSlotID,
		MaterialID: g.Header.MaterialID, Purpose: 1, MaxFacts: 4096})
	g.Header.ValueEntryPlanCount, g.Header.LineageCount, g.Header.TemplateCount = 0, 0, 1
	g.UsePlan.OperationID, g.UsePlan.MaterialID = operation, g.Header.MaterialID
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	g.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(g.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	f.graph, err = contract.EncodeGeneratorPlanBundle(g)
	if err != nil || contract.ValidateGeneratorEffectGraph(g) != nil {
		t.Fatal("retirement graph fixture", err)
	}
	f.reservation.Session.Graph, f.reservation.Plan.Declaration = f.graph, f.declaration
	f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.IntendedEntryPlans, err = contract.GeneratorValueEntryPlansDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.MaterialID = g.Header.MaterialID
	f.compare.ParentPlan, f.compare.Parent, f.compare.Purpose = contract.GeneratedParentPlan(f.compare.Parent), contract.GeneratedParentRecord{}, 1
	parent := &f.compare.ParentPlan
	parent.OperationID, parent.MaterialID, parent.RequestCoreDigest = operation, g.Header.MaterialID, g.Header.RequestCoreDigest
	parent.RequestIdentityDigest = contract.ID{}
	parent.Declaration, parent.IntendedEntryPlans = g.Request.Declaration, f.compare.IntendedEntryPlans
	parent.ValueEntryPlanCount, parent.LineageCount, parent.TemplateCount = 0, 0, 1
	parent.Graph, parent.PlanGraphID, parent.UsePlanDigest = f.compare.PlanGraph, g.UsePlan.PlanGraphID, f.compare.UsePlanDigest
	target := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, Name: original.Name, IncarnationID: original.EntryIncarnationID, Epoch: original.Epoch,
		ResourceID: create.ResourceIncarnationID, LifecycleMode: create.LifecycleMode, ResourceDigest: originalDigest,
		ConfigContractID: create.ConfigContractID, ResourceContractID: create.ResourceContractID, OriginalOperationID: original.OperationID,
		OriginalAttemptID: create.AttemptID, ResultContractID: create.ResultContractID, CompletionClass: create.CompletionClass}
	f.reservation.Target = &target
	f.reservation.Phase = &contract.GeneratorPhaseIdentity{RequestIdentityDigest: consumerID("fresh delete request"),
		ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
		TransitionKind: contract.GeneratorAuthorityRetireReserve, BeforePhase: 1, AfterPhase: 2,
		Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)}
	if kind == contract.GeneratedDutyUnselectedCleanup {
		f.reservation.Phase.TransitionKind = contract.GeneratorAuthorityCleanupReserve
	}
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	f, _, _ = generatedProducerPlanFixture(t, f)
	use := g.ResultUses[0]
	p := f.producer.Producer
	p.Expected.Template, p.Expected.Use, p.Expected.TargetResourceDigest = *x, use, originalDigest
	p.OriginalFacts = originalFactsBody
	c := &p.Preparation
	c.LineageID, c.AttemptID, c.TransmissionID, c.ResultID = x.LineageID, x.AttemptID, x.TransmissionID, x.ResultID
	c.ResultContractID, c.IntentDigest, c.Action, c.ResourceDigest = x.ResultContractID, x.IntentDigest, x.Action, p.Expected.TargetResourceDigest
	d := &p.Duty
	d.Kind, d.Status, d.DutyID, d.OwnerID, d.ResourceID = kind, contract.GeneratedEffectSucceeded, x.DutyID, x.DutyID, x.ResourceIncarnationID
	d.OriginalOperationID, d.OriginalAttemptID = original.OperationID, create.AttemptID
	d.ResultContractID = x.ResultContractID
	if kind == contract.GeneratedDutyRetirement {
		d.Status = contract.GeneratedEffectTransmitted
	} else {
		d.ResultContractID = create.ResultContractID
	}
	targetBody, err := contract.EncodeGeneratorTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	d.Target, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorTargets, [][]byte{targetBody})
	if err != nil {
		t.Fatal(err)
	}
	v := &p.Attempt
	v.LineageID, v.AttemptID, v.PredecessorAttemptID = x.LineageID, x.AttemptID, x.PredecessorAttemptID
	v.OwnerID, v.ResourceID, v.TransmissionID, v.ResultID, v.InboxID = d.DutyID, x.ResourceIncarnationID, x.TransmissionID, x.ResultID, x.InboxID
	v.ResultContractID = x.ResultContractID
	v.TemplateDigest, err = contract.GeneratorTemplateID(*x)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := contract.GeneratorResultUseDigest(use)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := contract.EncodeGeneratorConsumer(contract.GeneratorConsumer{Schema: 1, OwnerID: d.DutyID, MaterialID: g.Header.MaterialID,
		ContextDigest: contextDigest, SubjectKind: 3, SubjectID: x.ResultID, Purpose: 4})
	if err != nil {
		t.Fatal(err)
	}
	p.Consumers = [][]byte{consumer}
	d.Consumers, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, p.Consumers)
	if err != nil {
		t.Fatal(err)
	}
	f.producer.Producer = p
	return f
}

// full_only: false
func TestGeneratedProducerDeleteRequiresItsExactObligationPhase(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		base := generatedDeleteProducerFixture(t, recovery)
		for _, kind := range []uint8{contract.GeneratedDutyRetirement, contract.GeneratedDutyUnselectedCleanup} {
			f := generatedSelectDeleteProducer(t, base, kind)
			for _, purpose := range []contract.GeneratorAuthorityPurpose{contract.GeneratorAuthorityReservation, contract.GeneratorAuthorityRetireReserve, contract.GeneratorAuthorityCleanupReserve} {
				f.producer.Phase = &contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest,
					ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
					TransitionKind: purpose, BeforePhase: 1, AfterPhase: 2, Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)}
				want := kind == contract.GeneratedDutyRetirement && purpose == contract.GeneratorAuthorityRetireReserve ||
					kind == contract.GeneratedDutyUnselectedCleanup && purpose == contract.GeneratorAuthorityCleanupReserve
				r := newConsumerRuntime(t, f.base.route)
				err := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline)
				if (err == nil) != want {
					t.Fatal("delete obligation phase", recovery, kind, purpose, err)
				}
				if want {
					op, _ := generatedAdoptionCompare(t, r, f)
					generatedProducerPrepare(t, r, f, op)
					if r.generated.purpose.producer.producer.entryUsed || r.generated.purpose.producer.producer.claimed || f.producer.Producer.Duty.OriginalAttemptID == f.producer.Producer.Attempt.AttemptID {
						t.Fatal("delete preparation changed original create provenance or entered producer")
					}
				}
				r.retireGenerated()
			}
			for _, name := range []string{"initial entry", "create duty", "changed result contract", "changed executor", "changed completion class",
				"missing target", "changed target resource digest", "changed target resource contract", "changed target resource", "changed target config contract",
				"changed target lifecycle", "changed target original operation", "changed target original attempt", "changed target original contract",
				"changed target completion class", "changed target name", "changed target incarnation", "changed target epoch", "changed duty original operation",
				"changed duty original attempt", "same-operation create origin", "missing duty target"} {
				changed := f
				p := f.producer.Producer
				target := *f.producer.Target
				changed.producer.Target = &target
				purpose := contract.GeneratorAuthorityRetireReserve
				if kind == contract.GeneratedDutyUnselectedCleanup {
					purpose = contract.GeneratorAuthorityCleanupReserve
				}
				changed.producer.Phase = &contract.GeneratorPhaseIdentity{RequestIdentityDigest: f.compare.Parent.RequestIdentityDigest,
					ObservedHEADDigest: f.compare.Context.PredecessorHEADDigest, ConditionDigest: f.compare.Context.OriginalConditionDigest,
					TransitionKind: purpose, BeforePhase: 1, AfterPhase: 2, Evidence: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts)}
				switch name {
				case "initial entry":
					changed.producer.Phase = nil
				case "create duty":
					p.Duty.Kind = contract.GeneratedDutyCreate
				case "changed result contract":
					p.Duty.ResultContractID = consumerID("replacement result contract")
				case "changed executor":
					p.Duty.ExecutorID = consumerID("replacement executor")
				case "changed completion class":
					p.Duty.CompletionClass = 2
				case "missing target":
					changed.producer.Target = nil
				case "changed target resource digest":
					target.ResourceDigest = consumerID("replacement resource digest")
				case "changed target resource contract":
					target.ResourceContractID = consumerID("replacement resource contract")
				case "changed target resource":
					target.ResourceID = consumerID("replacement resource")
				case "changed target config contract":
					target.ConfigContractID = consumerID("replacement config")
				case "changed target lifecycle":
					target.LifecycleMode = contract.GeneratorLifecycleNone
				case "changed target original operation":
					target.OriginalOperationID = consumerID("replacement original operation")
				case "changed target original attempt":
					target.OriginalAttemptID = consumerID("replacement original attempt")
				case "changed target original contract":
					target.ResultContractID = consumerID("replacement original contract")
				case "changed target completion class":
					target.CompletionClass = 2
				case "changed target name":
					target.Name = "replacement"
				case "changed target incarnation":
					target.IncarnationID = consumerID("replacement incarnation")
				case "changed target epoch":
					target.Epoch++
				case "changed duty original operation":
					p.Duty.OriginalOperationID = consumerID("replacement original operation")
				case "changed duty original attempt":
					p.Duty.OriginalAttemptID = consumerID("replacement original attempt")
				case "same-operation create origin":
					p.Duty.OriginalOperationID, target.OriginalOperationID = p.Preparation.OperationID, p.Preparation.OperationID
				case "missing duty target":
					p.Duty.Target = contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)
				}
				changed.producer.Producer = p
				r := newConsumerRuntime(t, f.base.route)
				if err := r.admitGeneratedProducer(changed.compare, changed.producer, changed.base.deadline); err == nil || r.slot != nil {
					t.Fatal("changed delete obligation admitted", kind, name, err)
				}
			}
		}
	}
}

// full_only: false
func TestGeneratedProducerChecksPrivateInitialContextAndObligation(t *testing.T) {
	f, _, _ := generatedProducerFixture(t, false)
	for _, nonce := range []string{"admission", "session"} {
		t.Run("fresh initial "+nonce, func(t *testing.T) {
			current := f
			if nonce == "admission" {
				current.compare.Context.AdmissionID = consumerID("fresh admission")
			} else {
				current.compare.Context.SessionID = consumerID("fresh session")
			}
			parent := current.compare.Parent
			// A new private invocation may use fresh nonces with the same
			// canonical producer parent. Its later requests must use the
			// exact context that this invocation installed.
			control := current.producerRuntime(t)
			op, _ := generatedAdoptionCompare(t, control, current)
			generatedProducerPrepare(t, control, current, op)
			if control.generated.request.Parent != parent {
				t.Fatal("fresh private context changed the canonical parent")
			}
			control.retireGenerated()

			r := current.producerRuntime(t)
			op, _ = generatedAdoptionCompare(t, r, current)
			producer := current.producer.Producer
			request := contract.CryptoGeneratedProducerRequest{OperationRef: op, Context: f.compare.Context,
				Template: producer.Expected.Template, Material: current.producer.Material, SeedAccess: current.producer.SeedAccess,
				Preparation: producer.Preparation, Intent: contract.GeneratorDescriptor{Digest: producer.Expected.Template.IntentDigest, Length: uint64(len(producer.Intent)), Count: 1}}
			body, err := contract.EncodeCryptoGeneratedProducerRequest(request)
			if err != nil {
				t.Fatal("invalid independent context substitution", err)
			}
			public, private := f.base.route.publicCalls, f.base.route.privateCalls
			if reply := applyCall(r, context.Background(), contract.CryptoPrepare, body); reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("different invocation context reached producer preparation", reply.ResultCode)
			}
			if f.base.route.publicCalls != public || f.base.route.privateCalls != private {
				t.Fatal("different invocation context started private key work")
			}
			if reply := applyCall(r, context.Background(), contract.CryptoPrepare, body); reply.ResultCode != contract.CryptoAlreadyUsed {
				t.Fatal("refused private context left a reusable producer admission", reply.ResultCode)
			}
			r.retireGenerated()
		})
	}
	for _, name := range []string{"different preparation", "old producer tag"} {
		t.Run(name, func(t *testing.T) {
			r := f.producerRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			producer := f.producer.Producer
			preparation := producer.Preparation
			if name == "different preparation" {
				preparation.RequestIdentityDigest = consumerID("different prepared request identity")
			}
			body, err := contract.EncodeCryptoGeneratedProducerRequest(contract.CryptoGeneratedProducerRequest{OperationRef: op, Context: f.compare.Context,
				Template: producer.Expected.Template, Material: f.producer.Material, SeedAccess: f.producer.SeedAccess, Preparation: preparation,
				Intent: contract.GeneratorDescriptor{Digest: producer.Expected.Template.IntentDigest, Length: uint64(len(producer.Intent)), Count: 1}})
			if err != nil {
				t.Fatal(err)
			}
			if name == "old producer tag" {
				body[32+4+contract.CryptoApplyContextLength] = 3
			}
			public, private := f.base.route.publicCalls, f.base.route.privateCalls
			state := r.generated.purpose.producer
			want := contract.CryptoInvalidAdmission
			if name == "old producer tag" {
				want = contract.CryptoInvalidInput
			}
			if reply := applyCall(r, context.Background(), contract.CryptoPrepare, body); reply.ResultCode != want || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("different preparation or old tag reached producer preparation", reply.ResultCode)
			}
			r.mu.Lock()
			owner := state.returnOwner
			r.mu.Unlock()
			r.retireGenerated()
			if f.base.route.publicCalls != public || f.base.route.privateCalls != private || owner != nil {
				t.Fatal("refused preparation started private work or issued a return owner")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*generatedRuntimeFixture)
	}{
		{"changed intent", func(f *generatedRuntimeFixture) { f.producer.Producer.Intent = []byte(`{"name":"different"}`) }},
		{"changed attempt", func(f *generatedRuntimeFixture) {
			f.producer.Producer.Attempt.RequestDigest = consumerID("other request")
		}},
		{"changed duty", func(f *generatedRuntimeFixture) { f.producer.Producer.Duty.ResourceID = consumerID("other resource") }},
		{"missing late-result consumer", func(f *generatedRuntimeFixture) {
			f.producer.Producer.Consumers = f.producer.Producer.Consumers[:1]
			var err error
			f.producer.Producer.Duty.Consumers, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorConsumers, f.producer.Producer.Consumers)
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := f
			p := f.producer.Producer
			changed.producer.Producer = p
			tc.change(&changed)
			if _, err := contract.EncodeCryptoGeneratedCompareRequest(changed.compare); err != nil {
				t.Fatal("invalid public fixture", err)
			}
			r := newConsumerRuntime(t, f.base.route)
			if err := r.admitGeneratedProducer(changed.compare, changed.producer, changed.base.deadline); err == nil || r.slot != nil {
				t.Fatal("unbound producer admitted", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedProducerDeadlineCapsWholeChildCommand(t *testing.T) {
	for _, test := range []struct {
		name         string
		parent       time.Duration
		prepareDelay time.Duration
	}{
		{"short parent", 12 * time.Second, 0},
		{"five minute parent", 5 * time.Minute, 0},
		{"delayed preparation", 5 * time.Minute, 91 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, _, candidate := generatedProducerFixture(t, false)
				f.base.deadline = time.Now().Add(test.parent)
				f.compare.Context.Expiry = uint64(f.base.deadline.UnixNano())
				var err error
				f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				var issued, want contract.GeneratedProducerCommand
				var owner *generatedProducerReturnOwner
				var r *Runtime
				f.producer.Producer.Return = func(ctx context.Context, command contract.GeneratedProducerCommand, intent []byte) generatedProducerReturn {
					calls++
					issued = command
					issued.Intent, issued.OriginalFacts = bytes.Clone(command.Intent), bytes.Clone(command.OriginalFacts)
					if !reflect.DeepEqual(command, want) || !bytes.Equal(intent, f.producer.Producer.Intent) {
						t.Error("entry changed the exact prepared identity or issued deadline")
					}
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(time.UnixMilli(int64(want.DeadlineUnixMillis))) {
						t.Error("return context did not use the issued deadline")
					}
					r.mu.Lock()
					owner = r.generated.purpose.producer.returnOwner
					r.mu.Unlock()
					time.Sleep(time.Second)
					later, still := ctx.Deadline()
					if !still || !later.Equal(deadline) || !reflect.DeepEqual(owner.command, command) {
						t.Error("issued command or return deadline was renewed")
					}
					return generatedProducerReturn{Facts: generatedProducerFacts(f.producer.Producer.Expected), Secret: []byte("provider-secret")}
				}
				r = f.producerRuntime(t)
				op, uses := generatedAdoptionCompare(t, r, f)
				time.Sleep(test.prepareDelay)
				locator := generatedProducerPrepare(t, r, f, op)
				authority := generatedProducerClaim(t, r, f, candidate, op, uses)
				if calls != 0 || r.generated.purpose.producer.returnOwner != nil {
					t.Fatal("preparation or Claim issued an effect owner")
				}
				deadline := uint64(f.base.deadline.UnixMilli())
				maximum := uint64(time.Now().UnixMilli()) + 90_000
				if deadline > maximum {
					deadline = maximum
				}
				want = contract.GeneratedProducerCommand{GeneratedProducerPreparation: f.producer.Producer.Preparation, DeadlineUnixMillis: deadline, Intent: f.producer.Producer.Intent, OriginalFacts: f.producer.Producer.OriginalFacts}
				out := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority)
				released := want
				released.Intent, released.OriginalFacts = nil, nil
				if out.code != contract.CryptoSuccess || calls != 1 || !reflect.DeepEqual(issued, want) || owner == nil || !reflect.DeepEqual(owner.command, released) || len(out.Record) == 0 {
					t.Fatal("entry did not issue one fixed bounded command", out.code, calls)
				}
				if again := r.invokeGeneratedProducer(context.Background(), f.compare.Context.AdmissionID, locator, authority); again.code != contract.CryptoAlreadyUsed || calls != 1 || !reflect.DeepEqual(owner.command, released) {
					t.Fatal("duplicate entry issued or renewed a command", again.code, calls)
				}
				r.retireGenerated()
			})
		})
	}
}

// full_only: false
func TestGeneratedProducerCandidatePinsAttemptDutyAndConsumerRows(t *testing.T) {
	for _, kind := range []uint8{9, 10, 14} {
		f, _, c := generatedProducerFixture(t, false)
		r := f.producerRuntime(t)
		op, _ := generatedAdoptionCompare(t, r, f)
		generatedProducerPrepare(t, r, f, op)
		index := slices.IndexFunc(c.SupportRecords, func(row contract.SupportRecord) bool { return row.Kind == kind })
		c.SupportRecords = slices.Delete(c.SupportRecords, index, index+1)
		var err error
		c.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(c.PublicState.Domain, c.SupportRecords)
		if err != nil {
			t.Fatal(err)
		}
		if code := r.bindGeneratedCandidate(context.Background(), f.compare.Context.AdmissionID, c); code != contract.CryptoInvalidAdmission {
			t.Fatal("missing producer support admitted", kind, code)
		}
	}
}

// full_only: false
func TestGeneratedContinuationUsesFreshPrivateAdmission(t *testing.T) {
	f, _, result := generatedAdoptionFixture(t, false)
	parent := f.compare.Parent
	f.compare.Context.AdmissionID = consumerID("fresh admission")
	f.compare.Context.SessionID = consumerID("fresh session")
	r := f.adoptionRuntime(t)
	op, _ := generatedAdoptionCompare(t, r, f)
	if reply := applyCall(r, context.Background(), contract.CryptoPrepare, generatedAdoptBody(t, f, op, result)); reply.ResultCode != contract.CryptoSuccess {
		t.Fatal("original result did not accept current admission", reply.ResultCode)
	}
	if r.generated.request.Parent != parent {
		t.Fatal("continuation rewrote original parent")
	}
}

// full_only: false
func TestGeneratedProcessResultCodeClassifiesCommandDeadlineBeforeSessionCancellation(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := processResultCode(cancelled, time.Now().Add(-time.Second)); got != contract.CryptoExpired {
		t.Fatal("elapsed command deadline lost to its cancelled session", got)
	}
	if got := processResultCode(cancelled, time.Now().Add(time.Minute)); got != contract.CryptoCancelled {
		t.Fatal("caller cancellation became a command expiry", got)
	}
	if got := processResultCode(context.Background(), time.Now().Add(time.Minute)); got != contract.CryptoCustodyUnavailable {
		t.Fatal("ordinary process failure changed class", got)
	}
}

// full_only: false
func TestGeneratedProducerOriginalFactsAdmissionAndOwnership(t *testing.T) {
	t.Run("create has no original facts", func(t *testing.T) {
		f, _, _ := generatedProducerFixture(t, false)
		f.producer.Producer.OriginalFacts = []byte{1}
		r := newConsumerRuntime(t, f.base.route)
		if err := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline); !errors.Is(err, ErrAdmission) {
			t.Fatal("create admitted an original resource", err)
		}
	})
	for _, name := range []string{"exact", "missing", "oversized", "action", "intent", "resource contract", "resource bytes"} {
		t.Run(name, func(t *testing.T) {
			f := generatedSelectDeleteProducer(t, generatedDeleteProducerFixture(t, false), contract.GeneratedDutyRetirement)
			p := &f.producer.Producer
			original := bytes.Clone(p.OriginalFacts)
			switch name {
			case "missing":
				p.OriginalFacts = nil
			case "oversized":
				p.OriginalFacts = make([]byte, contract.GeneratorSafeFactsEnvelopeLength+1)
			case "action", "intent", "resource contract", "resource bytes":
				facts, err := contract.DecodeGeneratorSafeFacts(p.OriginalFacts)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "action":
					facts.Action, facts.Disposition = contract.GeneratorActionDelete, contract.GeneratorDispositionRetirementAcknowledged
				case "intent":
					facts.IntentDigest[0] ^= 1
				case "resource contract":
					facts.ResourceContractID[0] ^= 1
				case "resource bytes":
					facts.ResourceData[0] ^= 1
				}
				p.OriginalFacts, err = contract.EncodeGeneratorSafeFacts(facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			r := newConsumerRuntime(t, f.base.route)
			err := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline)
			if name != "exact" {
				if !errors.Is(err, ErrAdmission) {
					t.Fatal("changed original facts admitted", err)
				}
				return
			}
			if err != nil {
				t.Fatal("exact original facts refused", err)
			}
			clear(p.OriginalFacts)
			if !bytes.Equal(r.generated.purpose.producer.producer.originalFacts, original) {
				t.Fatal("producer retained caller-owned original facts")
			}
		})
	}
}

// full_only: false
func TestGeneratedProducerReturnRequiresOwningInputClass(t *testing.T) {
	for _, changed := range []bool{false, true} {
		f, _, _ := generatedProducerFixture(t, false)
		if changed {
			f.producer.Producer.Expected.InputEncoding = contract.InputEncodingBase64
		}
		calls := 0
		original := f.producer.Producer.Return
		f.producer.Producer.Return = func(ctx context.Context, command contract.GeneratedProducerCommand, seed []byte) generatedProducerReturn {
			calls++
			return original(ctx, command, seed)
		}
		r := newConsumerRuntime(t, f.base.route)
		err := r.admitGeneratedProducer(f.compare, f.producer, f.base.deadline)
		if changed {
			if !errors.Is(err, ErrAdmission) || r.slot != nil {
				t.Fatal("Return admitted a class outside its owning graph", err)
			}
		} else {
			if err != nil {
				t.Fatal("matching Return admission refused", err)
			}
			r.retireGenerated()
		}
		if calls != 0 {
			t.Fatal("Return entered before private admission")
		}
	}
}
