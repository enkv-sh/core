package core

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type observationExchangeCustody struct {
	instance contract.ID
	calls    []contract.CryptoRequest
	reply    func(contract.CryptoRequest) contract.CryptoResponse
}

func (c *observationExchangeCustody) InstanceID() contract.ID { return c.instance }
func (c *observationExchangeCustody) Exchange(_ context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	c.calls = append(c.calls, q)
	return c.reply(q)
}

func observationReply(q contract.CryptoRequest, code contract.CryptoResultCode, rows []contract.KeyUseRow, body []byte) contract.CryptoResponse {
	return contract.CryptoResponse{Schema: q.Schema, Kind: q.Kind, RequestID: q.RequestID, CustodyInstanceID: q.CustodyInstanceID, ResultCode: code, KeyUseRows: rows, Body: body}
}

// full_only: false
func TestCheckedExchangeFailureSurvivesGeneratedPreparation(t *testing.T) {
	s, _ := observationTestSession(t)
	input := generatedPlanInputFixture(t, s)
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	custody := &observationExchangeCustody{instance: generatedVectorID(105)}
	custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
		return observationReply(q, contract.CryptoCustodyUnavailable, nil, nil)
	}
	permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
	if !attachOperationObservation(&permit.observation, s, plan.request.Context, true) {
		t.Fatal("private generated observation admission refused")
	}
	prepared, result := s.prepareGeneratedPlan(t.Context(), permit)
	if prepared != nil || result != custodyFailure(contract.CryptoCustodyUnavailable) || len(custody.calls) != 1 {
		t.Fatal("controlled failure changed", result)
	}
	facts, status := permit.observation.read()
	if len(facts) != 1 || status.Accepted != 1 {
		t.Fatal("checked unsuccessful exchange was discarded", status)
	}
	fact := facts[0].Exchange
	c := plan.request.Context
	wantSource := observationSource{Stage: observationExchange, DomainID: c.DomainID, AdmissionID: c.AdmissionID, SessionID: c.SessionID,
		OperationID: generatedVectorID(10)}
	if fact == nil || fact.Source != wantSource {
		t.Fatal("generated failure source correlation changed", fact)
	}
	q := custody.calls[0]
	if fact == nil || fact.RequestID != q.RequestID || fact.Kind != q.Kind || fact.CustodyInstanceID != q.CustodyInstanceID || fact.ResultCode != contract.CryptoCustodyUnavailable || !reflect.DeepEqual(fact.Rows, []contract.KeyUseRow(nil)) {
		t.Fatal("exact unsuccessful exchange changed", fact)
	}
}

func observationExchangeFixture(t testing.TB, enabled bool) (*generatedPreparation, *observationExchangeCustody, []byte, contract.KeyUseRow) {
	t.Helper()
	s, _ := observationTestSession(t)
	plan, err := s.generatedPlanRequest(t.Context(), generatedPlanInputFixture(t, s))
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoGeneratedCompareRequest(plan.request)
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := s.currentBindings()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.PublicBindingDigest(bindings[0].Binding)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.KeyUseRow{BindingID: bindings[0].Binding.BindingID, PublicBindingDigest: digest, SubjectKind: bindings[0].SubjectKind,
		SubjectID: bindings[0].SubjectID, Provider: bindings[0].Binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}
	custody := &observationExchangeCustody{instance: generatedVectorID(105)}
	permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
	if !attachOperationObservation(&permit.observation, s, plan.request.Context, enabled) {
		t.Fatal("private observation admission refused")
	}
	op := &cryptoOperation{observation: permit.observation, source: generatedExchangeSource(plan.request), context: plan.request.Context,
		adapter: custody, instance: custody.instance, deadline: permit.deadline, authority: s.admission.recipient, bindings: bindings, sourceCount: 1}
	return &generatedPreparation{operation: op}, custody, body, row
}

// full_only: false
func TestCryptoExchangeObservationCheckedBoundary(t *testing.T) {
	t.Run("mixed unsuccessful outcomes", func(t *testing.T) {
		for _, code := range []contract.CryptoResultCode{contract.CryptoCustodyUnavailable, contract.CryptoResponseUnknown, contract.CryptoPrivateRouteUnavailable} {
			t.Run(fmt.Sprint(code), func(t *testing.T) {
				p, custody, body, row := observationExchangeFixture(t, true)
				p.operation.sourceCount = 10
				rows := make([]contract.KeyUseRow, 4)
				for i, outcome := range []uint8{contract.KeyUseCompleted, contract.KeyUseDenied, contract.KeyUseFailed, contract.KeyUseUnknown} {
					rows[i] = row
					rows[i].Outcome = outcome
					rows[i].Count = uint32(i + 1)
				}
				custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse { return observationReply(q, code, rows, nil) }
				reply, result := p.exchange(t.Context(), contract.CryptoCompare, body)
				if result != custodyFailure(code) || !reflect.DeepEqual(reply.KeyUseRows, rows) || len(p.keyUses) != 0 || !p.operation.terminal {
					t.Fatal("failed exchange entered the success aggregate", result)
				}
				facts, status := p.operation.observation.read()
				if len(facts) != 1 || status.Accepted != 1 || !reflect.DeepEqual(facts[0].Exchange.Rows, rows) || facts[0].Exchange.ResultCode != code {
					t.Fatal("mixed checked facts lost", status)
				}
				expected := p.operation.observation.sourceFor(p.operation.source)
				if facts[0].Exchange.Source != expected || facts[0].Exchange.Source.Stage != observationExchange || !expected.AttemptID.IsZero() || !expected.PhaseID.IsZero() {
					t.Fatal("unavailable source identities invented")
				}
			})
		}
	})
	t.Run("rejects unchecked replies", func(t *testing.T) {
		for _, name := range []string{"request", "kind", "instance", "instance after reply", "expired before", "expired after", "cancelled before", "cancelled after", "binding", "digest", "subject", "provider", "purpose", "count", "too many opens", "incomplete success", "malformed body", "failure body", "nil context", "terminal", "adapter absent", "instance before", "request body", "schema", "invalid result", "invalid outcome"} {
			t.Run(name, func(t *testing.T) {
				p, custody, body, row := observationExchangeFixture(t, true)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				replyBody, err := contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(110)})
				if err != nil {
					t.Fatal(err)
				}
				code := contract.CryptoSuccess
				rows := []contract.KeyUseRow{row}
				switch name {
				case "nil context":
					ctx = nil
				case "terminal":
					p.operation.terminal = true
				case "adapter absent":
					p.operation.adapter = nil
				case "instance before":
					custody.instance = generatedVectorID(112)
				case "request body":
					body = []byte{1}
				case "invalid result":
					code = 0
				case "invalid outcome":
					rows[0].Outcome = 0
				case "expired before":
					p.operation.deadline = time.Unix(0, 1)
				case "cancelled before":
					cancel()
				case "binding":
					rows[0].BindingID = generatedVectorID(112)
				case "digest":
					rows[0].PublicBindingDigest = generatedVectorID(112)
				case "subject":
					rows[0].SubjectID = generatedVectorID(112)
				case "provider":
					rows[0].Provider = contract.GCP
				case "purpose":
					rows[0].Purpose = contract.KeyUseMaterialWrap
				case "count":
					rows[0].Count = 0
				case "too many opens":
					rows[0].Count = 2
				case "incomplete success":
					rows = nil
				case "malformed body":
					replyBody = []byte{1}
				case "failure body":
					code = contract.CryptoCustodyUnavailable
				}
				custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
					reply := observationReply(q, code, rows, replyBody)
					switch name {
					case "schema":
						reply.Schema = 0
					case "request":
						reply.RequestID = generatedVectorID(112)
					case "kind":
						reply.Kind = contract.CryptoPrepare
					case "instance":
						reply.CustodyInstanceID = generatedVectorID(112)
					case "instance after reply":
						custody.instance = generatedVectorID(112)
					case "expired after":
						p.operation.deadline = time.Unix(0, 1)
					case "cancelled after":
						cancel()
					}
					return reply
				}
				if _, result := p.exchange(ctx, contract.CryptoCompare, body); result != refused(AdmissionInvalid) {
					t.Fatal("unchecked reply accepted", result)
				}
				facts, status := p.operation.observation.read()
				if len(facts) != 0 || status.Accepted != 0 || status.Rejected != 0 || len(p.keyUses) != 0 {
					t.Fatal("unchecked reply disclosed trusted facts", status)
				}
				expectedCalls := 1
				if name == "expired before" || name == "cancelled before" || name == "nil context" || name == "terminal" || name == "adapter absent" || name == "instance before" {
					expectedCalls = 0
				}
				if len(custody.calls) != expectedCalls {
					t.Fatal("observation added Crypto work")
				}
			})
		}
	})
}

func observationFreezeFixture(t testing.TB, p *generatedPreparation) contract.CryptoGeneratedFreezeRequest {
	t.Helper()
	c := p.operation.context
	support, err := contract.RequiredSupportDescriptor(c.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	access, err := contract.AccessRecordsDescriptor(c.DomainID, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, err := contract.PublicStateDescriptor(contract.PublicState{Domain: c.DomainID, AccessRoot: c.CurrentAccessRoot, RequiredSupport: support})
	if err != nil {
		t.Fatal(err)
	}
	results, err := contract.GeneratorResultReferencesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := contract.CryptoGeneratedKeyUseDescriptor(p.keyUses)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoGeneratedFreezeRequest{OperationRef: generatedVectorID(110), Context: c, PhaseID: generatedVectorID(113), RequestIdentityDigest: generatedVectorID(114),
		CandidatePublicStateDescriptor: public, CandidateAccess: access, CandidateSupport: support, HeadCoreDigest: generatedVectorID(115), ConditionDigest: c.OriginalConditionDigest, ActualResults: results, KeyUses: uses}
}

// full_only: false
func TestCryptoExchangeObservationPreservesAggregateAndTerminalPhases(t *testing.T) {
	var expectedAggregate []contract.KeyUseRow
	var expectedFreeze []byte
	for _, mode := range []string{"accepting", "disabled", "absent", "full", "busy"} {
		t.Run(mode, func(t *testing.T) {
			p, custody, body, row := observationExchangeFixture(t, mode != "disabled" && mode != "absent")
			if mode == "absent" {
				p.operation.observation = nil
			}
			if mode == "full" {
				p.operation.observation.collector.storedBytes = observationRetainedLimit()
			}
			if mode == "busy" {
				p.operation.observation.collector.mu.Lock()
			}
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				rows := []contract.KeyUseRow{row}
				var responseBody []byte
				var err error
				switch q.Kind {
				case contract.CryptoCompare:
					responseBody, err = contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(110)})
				case contract.CryptoFreeze:
					rows = []contract.KeyUseRow{}
					responseBody, err = contract.EncodeCryptoFreezeResult(contract.CryptoFreezeResult{FactDigest: generatedVectorID(116)})
				default:
					rows = []contract.KeyUseRow{}
				}
				if err != nil {
					t.Fatal(err)
				}
				return observationReply(q, contract.CryptoSuccess, rows, responseBody)
			}
			for range 2 {
				if _, result := p.exchange(t.Context(), contract.CryptoCompare, body); result.Outcome != 0 {
					t.Fatal(result)
				}
			}
			want := row
			want.Count = 2
			if !reflect.DeepEqual(p.keyUses, []contract.KeyUseRow{want}) {
				t.Fatal("aggregate changed", p.keyUses)
			}
			frozen := observationFreezeFixture(t, p)
			freezeBody, err := contract.EncodeCryptoGeneratedFreezeRequest(frozen)
			if err != nil {
				t.Fatal(err)
			}
			if _, result := p.exchange(t.Context(), contract.CryptoFreeze, freezeBody); result.Outcome != 0 {
				t.Fatal(result)
			}
			claimBody, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(frozen))
			if err != nil {
				t.Fatal(err)
			}
			if _, result := p.exchange(t.Context(), contract.CryptoClaim, claimBody); result.Outcome != 0 {
				t.Fatal(result)
			}
			discardOp := *p.operation
			discardOp.terminal = false
			discardBody, err := contract.EncodeCryptoGeneratedDiscardRequest(contract.CryptoGeneratedDiscardRequest{OperationRef: frozen.OperationRef, Context: frozen.Context})
			if err != nil {
				t.Fatal(err)
			}
			if _, result := discardOp.exchange(t.Context(), contract.CryptoDiscard, discardBody); result.Outcome != 0 {
				t.Fatal(result)
			}
			if mode == "busy" {
				p.operation.observation.collector.mu.Unlock()
			}
			if len(custody.calls) != 5 || !p.operation.terminal || !discardOp.terminal {
				t.Fatal("observer changed exchanges or terminal ownership")
			}
			// Expiry changes between fixtures. Compare the complete Freeze bytes with
			// just that source field held equal, alongside the exact aggregate rows.
			// Hold only the admitted expiry equal across observer modes.
			if mode == "accepting" {
				expectedAggregate = slices.Clone(p.keyUses)
				expectedFreeze = freezeBody
			} else {
				base, err := contract.InspectCryptoGeneratedFreezeRequest(expectedFreeze)
				if err != nil {
					t.Fatal(err)
				}
				frozen.Context.Expiry = base.Context.Expiry
				current, err := contract.EncodeCryptoGeneratedFreezeRequest(frozen)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(current, expectedFreeze) || !reflect.DeepEqual(p.keyUses, expectedAggregate) {
					t.Fatal("observer changed Freeze commitment bytes")
				}
			}
			facts, status := p.operation.observation.read()
			switch mode {
			case "accepting":
				if len(facts) != 5 || status.Accepted != 5 {
					t.Fatal("checked terminal records lost", status)
				}
				if facts[0].Exchange.RequestID == facts[1].Exchange.RequestID || !reflect.DeepEqual(facts[0].Exchange.Rows, facts[1].Exchange.Rows) {
					t.Fatal("equal aggregate exchanges lost their distinction")
				}
				for i, kind := range []contract.CryptoKind{contract.CryptoFreeze, contract.CryptoClaim, contract.CryptoDiscard} {
					fact := facts[i+2].Exchange
					if fact.Kind != kind || fact.Rows == nil || len(fact.Rows) != 0 || fact.ResultCode != contract.CryptoSuccess {
						t.Fatal("zero-use phase inferred private work")
					}
				}
			case "disabled", "absent":
				if len(facts) != 0 || status != (observationStatus{}) {
					t.Fatal("disabled observer retained facts")
				}
			case "full":
				if len(facts) != 0 || status.DroppedFull != 5 {
					t.Fatal("full collector changed offer accounting", status)
				}
			case "busy":
				if len(facts) != 0 || status.DroppedContention != 5 {
					t.Fatal("busy collector changed offer accounting", status)
				}
			}
		})
	}
}

func observationProtectFixture(t testing.TB, s *StateSession) {
	t.Helper()
	s.admission.composition = generatedVectorID(97)
	s.admission.expires = time.Now().Add(time.Hour)
	s.admission.store.HeadKey = s.admission.store.Prefix + "/HEAD"
	s.store.(*generatedFixtureSupportStore).descriptor = s.admission.store
	if !s.admission.valid(s.store) {
		t.Fatal("protected fixture admission refused")
	}
}

func observationComparisonPermit(t testing.TB, s *StateSession, custody *observationExchangeCustody) ([]ApplyEntryInput, *AdmittedParentComparison, contract.KeyUseRow) {
	t.Helper()
	binding := s.authority().CurrentBinding
	digest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	set, err := contract.IntendedRecipientBindingSetDigest(s.admission.domain, s.admission.recipient, []contract.RecipientBindingReference{{RecipientID: s.admission.recipient, PublicBindingDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := contract.EncodeSealedInputEnvelope(contract.SealedInputEnvelope{Core: contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{
		Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), DomainID: s.admission.domain, FileIdentity: generatedVectorID(120), SourceID: generatedVectorID(121),
		CryptoSupportID: contract.CryptoSupportID(), DataKeyID: generatedVectorID(122), DataKeyEpoch: 1, IntendedRecipientBindingSetDigest: set, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "secret"},
		Ciphertext: make([]byte, 16), AuthorityWrap: contract.WrapRow{SubjectKind: 1, SubjectID: s.admission.recipient, BindingID: binding.BindingID, BindingSerial: binding.BindingSerial, PublicBindingDigest: digest, RSACiphertext: make([]byte, 384)}})
	if err != nil {
		t.Fatal(err)
	}
	input := []ApplyEntryInput{{Name: "secret", ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: sealed, Recipients: []contract.ID{s.admission.recipient}}}
	compared, result := s.compareEntryInputs(input)
	if compared == nil {
		t.Fatal(result)
	}
	c := generatedContinuationContext(t, s, 123, 124)
	c.OperationClass = contract.CryptoOrdinaryLifecycle
	c.IntentDescriptor = contract.DescriptorVector{Digest: compared.desired, Length: compared.desiredLength, Count: uint32(len(compared.desiredEntries))}
	q, ok := s.comparisonRequest(compared, c)
	if !ok {
		t.Fatal("private comparison request refused")
	}
	body, err := contract.EncodeCryptoCompareRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	permit := &AdmittedParentComparison{session: s, crypto: custody, instance: custody.instance, context: c, requestDigest: contract.Hash(body), requestLength: len(body), deadline: time.Unix(0, int64(c.Expiry))}
	if !attachOperationObservation(&permit.observation, s, c, true) {
		t.Fatal("comparison observation admission refused")
	}
	return input, permit, contract.KeyUseRow{BindingID: binding.BindingID, PublicBindingDigest: digest, SubjectKind: 1, SubjectID: s.admission.recipient, Provider: binding.Provider, Purpose: contract.KeyUseMaterialOpen, Outcome: contract.KeyUseCompleted, Count: 1}
}

// full_only: false
func TestCheckedExchangeSurvivesComparisonBodyRejection(t *testing.T) {
	for _, name := range []string{"checked semantic mismatch", "structurally malformed", "plain no Crypto"} {
		t.Run(name, func(t *testing.T) {
			s, _ := observationTestSession(t)
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			input, permit, row := observationComparisonPermit(t, s, custody)
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				rows := []contract.CryptoComparisonRow{{Name: "different-entry", AfterPresent: true, Relation: contract.CryptoAdded, SourceDigest: generatedVectorID(127)}}
				descriptor, err := contract.CryptoComparisonDescriptor(rows)
				if err != nil {
					t.Fatal(err)
				}
				body, err := contract.EncodeCryptoCompareResult(contract.CryptoCompareResult{OperationRef: generatedVectorID(128), ComparisonDigest: descriptor.Digest, Rows: rows})
				if err != nil {
					t.Fatal(err)
				}
				if name == "structurally malformed" {
					body = []byte{1}
				}
				reply := observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{row}, body)
				if name == "checked semantic mismatch" && contract.ValidateCryptoExchange(q, reply) != nil {
					t.Fatal("semantic mismatch fixture is not a checked exchange")
				}
				return reply
			}
			if name == "plain no Crypto" {
				input[0].ConfidentialityClass = contract.Plain
				input[0].InputBytes = []byte("plain")
			}
			activePermit := permit
			if name == "plain no Crypto" {
				activePermit = nil
			}
			compared, result := s.compare(t.Context(), input, activePermit)
			if name == "plain no Crypto" {
				if compared == nil || result.Outcome != ObservedCurrent || len(custody.calls) != 0 {
					t.Fatal("plain comparison added Crypto work", result)
				}
			} else if compared != nil || result != refused(AdmissionInvalid) || len(custody.calls) != 1 {
				t.Fatal("invalid comparison result accepted", result)
			}
			facts, status := permit.observation.read()
			expected := 0
			if name == "checked semantic mismatch" {
				expected = 1
			}
			if len(facts) != expected || status.Accepted != uint64(expected) {
				t.Fatal("checked exchange lost or unchecked body disclosed", status)
			}
			if expected == 1 {
				if facts[0].Change != nil || facts[0].Exchange.Source.OperationID != (contract.ID{}) || facts[0].Exchange.Source.AttemptID != (contract.ID{}) || !reflect.DeepEqual(facts[0].Exchange.Rows, []contract.KeyUseRow{row}) {
					t.Fatal("exchange made a body claim or invented correlation")
				}
			}
		})
	}
}

type observationGenesisStore struct {
	*generatedFixtureSupportStore
	configuration contract.StoreConfiguration
}

func (s *observationGenesisStore) Create(context.Context, string, []byte) contract.WriteResult {
	return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
}
func (s *observationGenesisStore) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}
func (s *observationGenesisStore) Read(context.Context, string, uint32) contract.ReadResult {
	return contract.ReadResult{Status: contract.ReadMissing}
}

func observationGenesisFixture(t testing.TB) (*initAdmission, *observationGenesisStore, *testtrust.Signer, *observationExchangeCustody) {
	t.Helper()
	s := generatedEmptyPredecessorForFamily(t, contract.GCP)
	observationProtectFixture(t, s)
	configuration := contract.StoreConfiguration{Provider: contract.GCP, ConstructionProfile: 2, DomainID: s.admission.domain, Region: "us-central1", Bucket: "fixture-bucket", PrefixBeforeHEAD: "fixture"}
	storeID, err := contract.StoreConfigurationID(configuration)
	if err != nil {
		t.Fatal(err)
	}
	d, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
	if err != nil {
		t.Fatal(err)
	}
	d.StoreID, d.NormalSigning.Binding.Store = storeID, storeID
	s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		t.Fatal(err)
	}
	s.admission.store.Identity = storeID
	store := &observationGenesisStore{generatedFixtureSupportStore: s.store.(*generatedFixtureSupportStore), configuration: configuration}
	store.descriptor = s.admission.store
	prepared, err := planGenesis(s.admission)
	if err != nil {
		t.Fatal(err)
	}
	d = prepared.descriptor
	bindings, err := d.BindingTable()
	if err != nil {
		t.Fatal(err)
	}
	custody := &observationExchangeCustody{instance: generatedVectorID(105)}
	deadline := time.Now().Add(time.Minute)
	a := &initAdmission{open: OpenContext{admission: &s.admission}, prepared: prepared,
		descriptor: artifactReceipt{fact: contract.GenesisArtifactFact{Kind: 1, ArtifactID: d.DescriptorArtifactID, BodyDigest: contract.Hash(prepared.descriptorBytes), BodyLength: uint64(len(prepared.descriptorBytes)), DurabilityProfile: 1, Outcome: 1}},
		manifest:   artifactReceipt{fact: contract.GenesisArtifactFact{Kind: 2, ArtifactID: d.ManifestArtifactID, BodyDigest: contract.Hash(prepared.manifestBytes), BodyLength: uint64(len(prepared.manifestBytes)), DurabilityProfile: 1, Outcome: 1}},
		requestID:  generatedVectorID(100), custodyID: custody.instance, custody: custody, deadline: deadline}
	a.qualification = contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: 1, AdmissionID: generatedVectorID(102), SessionID: generatedVectorID(103), DomainID: s.admission.domain,
		CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), InitID: d.InitID, DescriptorDigest: contract.Hash(prepared.descriptorBytes), GenesisPlanDigest: contract.Hash(prepared.planBytes), RequestDescriptor: contract.DescriptorVector{Count: 1, Length: uint64(len(prepared.requestBytes)), Digest: contract.Hash(prepared.requestBytes)}}, Bindings: bindings, Probes: slices.Clone(prepared.plan.Probes)}
	if !attachInitObservation(a, store, custody, true) {
		t.Fatal("genesis observation admission refused")
	}
	return a, store, testtrust.New(t, contract.GCP, d.TrustID), custody
}

// full_only: false
func TestGenesisCheckedExchangeObservation(t *testing.T) {
	for _, name := range []string{"successful qualification then Store failure", "mixed unsuccessful qualification", "wrong request", "invalid row", "malformed body", "cancelled reply", "expired reply", "disabled expired reply"} {
		t.Run(name, func(t *testing.T) {
			a, store, trust, custody := observationGenesisFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var expectedRows []contract.KeyUseRow
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				qualification := a.qualification
				field := qualification.Probes[0]
				public := contract.QualifiedBindingFields{SubjectKind: field.SubjectKind, SubjectID: field.SubjectID, BindingID: field.BindingID, PublicBindingDigest: field.PublicBindingDigest, Provider: contract.GCP, Qualified: 1}
				rows := []contract.KeyUseRow{{BindingID: field.BindingID, PublicBindingDigest: field.PublicBindingDigest, SubjectKind: field.SubjectKind, SubjectID: field.SubjectID, Provider: contract.GCP, Purpose: contract.KeyUsePublicKeyRead, Outcome: contract.KeyUseCompleted, Count: 3},
					{BindingID: field.BindingID, PublicBindingDigest: field.PublicBindingDigest, SubjectKind: field.SubjectKind, SubjectID: field.SubjectID, Provider: contract.GCP, Purpose: contract.KeyUsePrivateRoleProbe, Outcome: contract.KeyUseCompleted, Count: 1}}
				result := contract.GenesisQualifiedKeysCore{InitID: qualification.Context.InitID, DescriptorDigest: qualification.Context.DescriptorDigest, RequestCoreDigest: qualification.Context.RequestDescriptor.Digest, GenesisPlanDigest: qualification.Context.GenesisPlanDigest,
					Public: []contract.QualifiedBindingFields{public}, Private: []contract.QualifiedSuccessorRow{{ProbeID: field.ProbeID, QualifiedBindingFields: public}}}
				body, err := contract.EncodeCryptoQualifyInitKeysResult(result)
				if err != nil {
					t.Fatal(err)
				}
				code := contract.CryptoSuccess
				if name != "successful qualification then Store failure" && name != "malformed body" {
					code = contract.CryptoCustodyUnavailable
					body = nil
				}
				if name == "mixed unsuccessful qualification" {
					rows = make([]contract.KeyUseRow, 4)
					for i, outcome := range []uint8{contract.KeyUseCompleted, contract.KeyUseDenied, contract.KeyUseFailed, contract.KeyUseUnknown} {
						rows[i] = contract.KeyUseRow{BindingID: field.BindingID, PublicBindingDigest: field.PublicBindingDigest, SubjectKind: field.SubjectKind, SubjectID: field.SubjectID, Provider: contract.GCP, Purpose: contract.KeyUsePublicKeyRead, Outcome: outcome, Count: uint32(i + 1)}
					}
				}
				if name == "invalid row" {
					rows[0].PublicBindingDigest = generatedVectorID(129)
				}
				if name == "malformed body" {
					body = []byte{1}
				}
				reply := observationReply(q, code, rows, body)
				if name == "wrong request" {
					reply.RequestID = generatedVectorID(129)
				}
				if name == "cancelled reply" {
					cancel()
				}
				if name == "expired reply" || name == "disabled expired reply" {
					a.deadline = time.Unix(0, 1)
				}
				expectedRows = slices.Clone(rows)
				return reply
			}
			if name == "disabled expired reply" {
				a.observation.collector = nil
			}
			selected, result := initialize(ctx, InitContext{admission: a}, store, trust, nil, custody)
			if selected != nil || result.Outcome == 0 || len(custody.calls) != 1 {
				t.Fatal("qualification fixture did not reach its controlled terminal", result)
			}
			if strings.Contains(name, "reply") || name == "mixed unsuccessful qualification" {
				if result != failure(EvidenceUnavailable, SigningUnavailable) {
					t.Fatal("observation changed unsuccessful init result", result)
				}
			}
			facts, status := a.observation.read()
			expected := 0
			if name == "successful qualification then Store failure" || name == "mixed unsuccessful qualification" {
				expected = 1
			}
			if len(facts) != expected || status.Accepted != uint64(expected) {
				t.Fatal("genesis checked fact boundary changed", status)
			}
			if expected == 1 {
				fact := facts[0].Exchange
				source := fact.Source
				c := a.qualification.Context
				if fact.RequestID != a.requestID || fact.Kind != contract.CryptoQualifyInitKeys || fact.CustodyInstanceID != a.custodyID || !reflect.DeepEqual(fact.Rows, expectedRows) || source.InitID != c.InitID || source.DomainID != c.DomainID || source.AdmissionID != c.AdmissionID || source.SessionID != c.SessionID || !source.OperationID.IsZero() || !source.AttemptID.IsZero() {
					t.Fatal("genesis facts lost their exact Init context", fact)
				}
			}
		})
	}
}

func observationFailingCustody() *observationExchangeCustody {
	custody := &observationExchangeCustody{instance: generatedVectorID(105)}
	custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
		return observationReply(q, contract.CryptoCustodyUnavailable, nil, nil)
	}
	return custody
}

func observationCheckConstructor(t testing.TB, owner *operationObservation, custody *observationExchangeCustody, result Result, want observationSource, expectedChanges ...int) {
	t.Helper()
	if result != custodyFailure(contract.CryptoCustodyUnavailable) || len(custody.calls) != 1 {
		t.Fatal("constructor did not reach the checked failure", result, len(custody.calls))
	}
	facts, status := owner.read()
	changeCount := 0
	if len(expectedChanges) != 0 {
		changeCount = expectedChanges[0]
	}
	for i := 0; i < changeCount && i < len(facts); i++ {
		if facts[i].Change == nil {
			t.Fatal("expected change stage missing")
		}
	}
	if len(facts) != 1+changeCount || status.Accepted != uint64(1+changeCount) || facts[changeCount].Exchange == nil {
		t.Fatal("constructor lost its enclosing observer", status)
	}
	fact, q := facts[changeCount].Exchange, custody.calls[0]
	if fact.Source != owner.sourceFor(want) || fact.RequestID != q.RequestID || fact.Kind != q.Kind || fact.CustodyInstanceID != q.CustodyInstanceID || fact.ResultCode != contract.CryptoCustodyUnavailable || len(fact.Rows) != 0 {
		t.Fatal("constructor lost source correlation", fact.Source, want)
	}
}

func observationReservationFixture(t testing.TB, names ...string) (*StateSession, *generatedReservation) {
	t.Helper()
	before := generatedEmptyPredecessorForFamily(t, contract.GCP)
	observationProtectFixture(t, before)
	reservation, err := before.deriveGeneratedReservation(context.Background(), generatedReservationInputForGenerations(t, before, generatedVectorID(10), names))
	if err != nil {
		t.Fatal(err)
	}
	observationProtectFixture(t, reservation.state)
	return before, reservation
}

// observationInitialProducerFixture retains the real initial-plan owner and
// its exchange facts before the later producer admission. A Record or restart
// cannot stand in for this uninterrupted initial boundary.
func observationInitialProducerFixture(t testing.TB, enabled bool, names ...string) (*StateSession, *generatedPreparation) {
	t.Helper()
	s, _ := observationTestSession(t)
	return observationInitialProducerForSession(t, s, enabled, names...)
}

func observationInitialProducerForSession(t testing.TB, s *StateSession, enabled bool, names ...string) (*StateSession, *generatedPreparation) {
	t.Helper()
	input := generatedPlanInputForGenerations(t, s, generatedVectorID(10), names, defaultGeneratedFixtureProfile())
	plan, err := s.generatedPlanRequest(t.Context(), input)
	if err != nil {
		t.Fatal("initial observed producer plan", err)
	}
	finished := generatedReservationInputForGenerations(t, s, generatedVectorID(10), names).finished
	custody := &observationExchangeCustody{instance: generatedVectorID(106)}
	prepares := 0
	custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
		var body []byte
		var err error
		var rows []contract.KeyUseRow
		if q.Kind == contract.CryptoCompare {
			body, err = contract.EncodeCryptoGeneratedCompareResult(contract.CryptoGeneratedCompareResult{OperationRef: generatedVectorID(128)})
		} else {
			prepares++
			if prepares <= 2 {
				body, err = contract.EncodeCryptoGeneratedPartResult(contract.CryptoGeneratedPartResult{})
			} else {
				body, err = contract.EncodeCryptoGeneratedFinishPlanResult(finished)
			}
			if prepares == 3 {
				rows = []contract.KeyUseRow{observationSelectionKeyUse(t, s, contract.KeyUseMaterialWrap)}
			}
		}
		if err != nil {
			t.Fatal("observed initial producer reply", err)
		}
		return observationReply(q, contract.CryptoSuccess, rows, body)
	}
	permit := &admittedGeneratedPlan{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
	if enabled && !attachOperationObservation(&permit.observation, s, plan.request.Context, true) {
		t.Fatal("initial producer enclosing owner")
	}
	prior, result := s.prepareGeneratedPlan(t.Context(), permit)
	if prior == nil || result != s.observed(ObservedCurrent) || prepares != 3 || len(custody.calls) != 4 {
		t.Fatal("initial producer enclosing preparation", result, prepares, len(custody.calls))
	}
	if enabled {
		facts, _ := permit.observation.read()
		if len(facts) != 4 {
			t.Fatal("initial enclosing exchange facts missing")
		}
	}
	prior.claimed = true
	authority, err := contract.GeneratorAuthorityDigest(*prior.reservation.candidate.head.Generator)
	if err != nil {
		t.Fatal("initial producer authority", err)
	}
	prior.reservation.candidate.generated = &generatedCandidateFacts{reservation: prior.reservation, authority: authority, claimed: true}
	prior.reservation.candidate.producer = prior
	return s, prior
}

func observationNextBinding(t testing.TB, before contract.KMSBinding) contract.KMSBinding {
	t.Helper()
	successor := before
	successor.BindingID = generatedVectorID(180)
	successor.BindingSerial++
	successor.KeySelector = "projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/successor/cryptoKeyVersions/1"
	public := &rsa.PublicKey{N: new(big.Int).SetBytes(bytes.Repeat([]byte{253}, 384)), E: 65537}
	var err error
	successor.SPKI, err = x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	successor.Fingerprint = contract.Hash(successor.SPKI)
	if _, err := contract.KMSBindingLength(successor); err != nil {
		t.Fatal(err)
	}
	return successor
}

// full_only: false
func TestCryptoExchangeObservationConstructorOwners(t *testing.T) {
	t.Run("generated record original and current roles", func(t *testing.T) {
		_, reservation := observationReservationFixture(t, "generated")
		s := reservation.state
		g := mustSelectedGeneratedWork(t, s)
		a := g.attempts[g.phase.FrontierAttemptID]

		admitted := generatedContinuationContext(t, s, 130, 131)
		plan, err := s.generatedRecordRequest(context.Background(), a.record.AttemptID, generatedPublicResultFixture(t, a, 1), admitted)
		if err != nil {
			t.Fatal(err)
		}
		custody := observationFailingCustody()
		permit := &admittedGeneratedRecord{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, plan.request.Context, true) {
			t.Fatal("record observer admission refused")
		}
		prepared, result := s.prepareGeneratedRecord(t.Context(), permit)
		if prepared != nil {
			t.Fatal("failed record returned preparation")
		}
		phase, err := contract.GeneratorPhaseID(plan.phase)
		if err != nil {
			t.Fatal(err)
		}
		want := observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), PhaseID: phase, AttemptID: a.record.AttemptID}
		observationCheckConstructor(t, permit.observation, custody, result, want)
		facts, _ := permit.observation.read()
		if facts[0].Exchange.Source.AdmissionID != admitted.AdmissionID || facts[0].Exchange.Source.SessionID != admitted.SessionID {
			t.Fatal("current executor replaced original requester")
		}
	})
	t.Run("generated final", func(t *testing.T) {
		_, reservation := observationReservationFixture(t, "generated")
		s := reservation.state
		g := mustSelectedGeneratedWork(t, s)
		a := g.attempts[g.phase.FrontierAttemptID]
		record, err := s.generatedRecordRequest(context.Background(), a.record.AttemptID, generatedPublicResultFixture(t, a, 1), generatedContinuationContext(t, s, 130, 131))
		if err != nil {
			t.Fatal(err)
		}
		recorded, err := s.deriveGeneratedRecord(context.Background(), record)
		if err != nil {
			t.Fatal(err)
		}
		s = recorded.state
		observationProtectFixture(t, s)
		plan, err := s.generatedFinalRequest(t.Context(), generatedContinuationContext(t, s, 132, 133))
		if err != nil {
			t.Fatal(err)
		}
		custody := observationFailingCustody()
		permit := &admittedGeneratedFinal{session: s, plan: plan, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(plan.request.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, plan.request.Context, true) {
			t.Fatal("final observer admission refused")
		}
		prepared, result := s.prepareGeneratedFinal(t.Context(), permit)
		if prepared != nil {
			t.Fatal("failed final returned preparation")
		}
		phase, err := contract.GeneratorPhaseID(plan.phase)
		if err != nil {
			t.Fatal(err)
		}
		observationCheckConstructor(t, permit.observation, custody, result, observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), PhaseID: phase})
	})
	t.Run("generated producer", func(t *testing.T) {
		s, prior := observationInitialProducerFixture(t, false, "alpha", "omega")
		reserved := prior.reservation
		admitted := prior.operation.context
		admitted.AdmissionID, admitted.SessionID, admitted.IntentDescriptor = generatedVectorID(132), generatedVectorID(133), contract.DescriptorVector{}
		q, preparation, err := s.generatedProducerRequest(context.Background(), prior, admitted)
		if err != nil {
			t.Fatal(err)
		}
		custody := observationFailingCustody()
		permit := &admittedGeneratedProducer{session: s, prior: prior, request: q, preparation: preparation, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, q.Context, true) {
			t.Fatal("producer observer admission refused")
		}
		prepared, result := s.prepareGeneratedProducer(t.Context(), permit)
		if prepared != nil {
			t.Fatal("failed producer returned preparation")
		}
		after := mustSelectedGeneratedWork(t, reserved.state)
		observationCheckConstructor(t, permit.observation, custody, result, observationSource{Stage: observationExchange, OperationID: generatedVectorID(10), PhaseID: after.phase.PhaseID, AttemptID: preparation.AttemptID})
	})
	t.Run("generated original verification", func(t *testing.T) {
		s, original, _ := generatedCreateHazardState(t, 0, 0)
		generatedLifecycleFixtureForFamily(t, s, contract.GCP)
		observationProtectFixture(t, s)
		g := mustSelectedGeneratedWork(t, s)
		a := g.attempts[original.record.AttemptID]
		graph, err := g.retainedGraph(a.record.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if graph.Request.OperationID != a.record.OperationID {
			t.Fatal("retained request lost original operation")
		}
		admitted := generatedContinuationContext(t, s, 130, 131)
		custody := observationFailingCustody()
		key, _, err := s.generatedResultCoordinate(t.Context(), a.record.AttemptID)
		if err != nil {
			t.Fatal("original inbox coordinate", err)
		}
		s.store.(*generatedFixtureSupportStore).objects[key] = generatedPublicResultFixture(t, a, 1)
		permit, err := s.admitGeneratedReflection(t.Context(), a.record.ResultID, generatedPublicResultFixture(t, a, 1), admitted, custody)
		if err != nil {
			t.Fatal(err)
		}
		if !attachOperationObservation(&permit.observation, s, permit.verification.Context, true) {
			t.Fatal("lifecycle observer admission refused")
		}
		reserved, err := s.deriveGeneratedReflection(t.Context(), permit.plan)
		if err != nil {
			t.Fatal(err)
		}
		candidate, result := s.prepareGeneratedLifecycle(t.Context(), permit, testtrust.New(t, contract.GCP, s.admission.trust))
		if candidate != nil {
			t.Fatal("failed lifecycle returned candidate")
		}
		observationCheckConstructor(t, permit.observation, custody, result, observationSource{Stage: observationExchange, OperationID: permit.plan.identity.operation, ParentID: a.record.OperationID, AttemptID: a.record.AttemptID, PhaseID: reserved.candidate.head.Generator.PhaseID})
		facts, _ := permit.observation.read()
		if facts[0].Exchange.Source.AdmissionID != admitted.AdmissionID || facts[0].Exchange.Source.SessionID != admitted.SessionID {
			t.Fatal("original verification lost current executor")
		}
	})
	t.Run("recipient replacement", func(t *testing.T) {
		s := generatedEmptyPredecessorForFamily(t, contract.GCP)
		binding := generatedPublicBinding(t, 181)
		recipient := contract.RecipientRecord{RecipientID: generatedVectorID(12), Status: contract.CurrentRecipient, CurrentBinding: &binding}
		s.recipients[0].Slots[1] = &recipient
		d, err := contract.DecodeGenesisDescriptorCore(s.admission.descriptor)
		if err != nil {
			t.Fatal(err)
		}
		d.Recipients = append(d.Recipients, recipient)
		s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(d)
		if err != nil {
			t.Fatal(err)
		}
		generatedSealSelectedFixture(t, s)
		generatedVerifySelectedFixtureSlices(t, s)
		observationProtectFixture(t, s)
		intent := contract.RecipientReplacementIntent{RecipientReplacementIntentFields: contract.RecipientReplacementIntentFields{Schema: contract.CanonicalSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: s.admission.domain, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, RecipientID: recipient.RecipientID}, Before: binding, Successor: observationNextBinding(t, binding)}
		plan := transitionPlan{operation: generatedVectorID(182), snapshot: generatedVectorID(183), transition: generatedVectorID(184), revision: generatedVectorID(185)}
		plan.recipientPages[0] = generatedVectorID(186)
		receiptPages, err := s.mutationReceiptPageIndexes(t.Context())
		if err != nil || len(receiptPages) != 2 {
			t.Fatal("receipt support plan", receiptPages, err)
		}
		for i, index := range receiptPages {
			plan.supportPages[index] = generatedVectorID(byte(188 + i))
		}
		c := generatedContinuationContext(t, s, 130, 131)
		c.OperationClass = contract.CryptoAccessReplacementClass
		q, _, _, err := s.replacementRequest(t.Context(), intent, plan, c)
		if err != nil {
			t.Fatal("recipient replacement fixture request refused")
		}
		body, err := contract.EncodeCryptoAccessReplaceRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		custody := observationFailingCustody()
		permit := &AdmittedRecipientReplacement{session: s, intent: intent, plan: plan, context: q.Context, requestDigest: contract.Hash(body), requestLength: len(body), crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, q.Context, true) {
			t.Fatal("recipient observer admission refused")
		}
		candidate, result := s.prepareRecipientReplacement(t.Context(), permit, testtrust.New(t, contract.GCP, s.admission.trust), nil)
		if candidate != nil {
			t.Fatal("failed replacement returned candidate")
		}
		observationCheckConstructor(t, permit.observation, custody, result, observationSource{Stage: observationExchange, OperationID: generatedVectorID(182)})
	})
	t.Run("succession", func(t *testing.T) {
		s := generatedEmptyPredecessorForFamily(t, contract.GCP)
		observationProtectFixture(t, s)
		before := currentControlOf(s)
		after := before
		after.AccessGeneration++
		after.AuthorityKMSBinding = observationNextBinding(t, before.AuthorityKMSBinding)
		plan := transitionPlan{operation: generatedVectorID(182), snapshot: generatedVectorID(183), transition: generatedVectorID(184), revision: generatedVectorID(185)}
		plan.recipientPages[0] = generatedVectorID(186)
		c := generatedContinuationContext(t, s, 130, 131)
		c.OperationClass = contract.CryptoAccessReplacementClass
		request := contract.SuccessionRequestCore{SuccessionRequestFields: contract.SuccessionRequestFields{Schema: contract.CanonicalSchema, OperationKind: contract.SuccessionReplaceAuthority, ApprovalRole: contract.NormalSigningRole, ChangeMask: contract.SuccessionChangeAuthorityKEK, MaterialSourceRole: contract.SuccessionMaterialAuthority,
			DomainID: s.admission.domain, StoreID: s.admission.store.Identity, CoordinateID: s.admission.store.Coordinate, NonBodyID: s.admission.store.NonBody, TrustInterpretationID: contract.TrustInterpretationID(), CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AdmissionID: c.AdmissionID, OperationID: plan.operation, PredecessorHeadRevisionID: s.head.Core.Revision, PredecessorFullHEADDigest: contract.Hash(s.body), BeforeAccessRoot: s.root.CurrentAccess.AccessRoot},
			Token: s.token, BeforeControl: before, ProposedAfterControl: after, ReplacementPlan: successionRolePlan(before, after, contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK), IdentityPlan: identityPlan(&Comparison{session: s}, plan)}
		descriptor, err := contract.SuccessionRequestDescriptor(request)
		if err != nil {
			t.Fatal(err)
		}
		source := contract.BindingTableRow{SubjectKind: 1, SubjectID: s.admission.recipient, Binding: before.AuthorityKMSBinding}
		q, _, err := s.successionAccessRequest(t.Context(), request, plan, c, source)
		if err != nil {
			t.Fatal("succession fixture request refused")
		}
		digest, err := contract.PublicBindingDigest(after.AuthorityKMSBinding)
		if err != nil {
			t.Fatal(err)
		}
		probe := contract.SuccessorKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, ProbeID: generatedVectorID(187), Context: q.Context, SubjectKind: 1, SubjectID: s.admission.recipient, SuccessorBindingDigest: digest}
		custody := observationFailingCustody()
		permit := &AdmittedSuccession{session: s, request: request, plan: plan, descriptor: descriptor, context: q.Context, source: source, probe: probe, crypto: custody, instance: custody.instance, deadline: time.Unix(0, int64(q.Context.Expiry))}
		if !attachOperationObservation(&permit.observation, s, q.Context, true) {
			t.Fatal("succession observer admission refused")
		}
		candidate, result := s.prepareSuccession(t.Context(), permit, SuccessionSigners{Authorizer: testtrust.New(t, contract.GCP, s.admission.trust)}, nil)
		if candidate != nil {
			t.Fatal("failed succession returned candidate")
		}
		observationCheckConstructor(t, permit.observation, custody, result, observationSource{Stage: observationExchange, OperationID: generatedVectorID(182)}, 1)
		facts, _ := permit.observation.read()
		controlCheckAuthorityKEKDetail(t, permit, facts[0].Change)
	})
}

// full_only: false
func TestOrdinaryCheckedExchangeGainsOnlyAdmittedPlanIdentity(t *testing.T) {
	s, _ := observationTestSession(t)
	custody := &observationExchangeCustody{instance: generatedVectorID(105)}
	input, permit, row := observationComparisonPermit(t, s, custody)
	comparison, result := s.compareEntryInputs(input)
	if comparison == nil {
		t.Fatal(result)
	}
	rows := []contract.CryptoComparisonRow{{Name: "secret", AfterPresent: true, Relation: contract.CryptoAdded, SourceDigest: comparison.intent[0].PayloadDigest, AfterRawLength: comparison.intent[0].ContentLength}}
	descriptor, err := contract.CryptoComparisonDescriptor(rows)
	if err != nil {
		t.Fatal(err)
	}
	comparedBody, err := contract.EncodeCryptoCompareResult(contract.CryptoCompareResult{OperationRef: generatedVectorID(128), Rows: rows, ComparisonDigest: descriptor.Digest})
	if err != nil {
		t.Fatal(err)
	}
	custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
		if q.Kind == contract.CryptoCompare {
			return observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{row}, comparedBody)
		}
		return observationReply(q, contract.CryptoCustodyUnavailable, nil, nil)
	}
	comparison, result = s.compare(t.Context(), input, permit)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("checked comparison refused", result)
	}
	plan, err := planTransition(t.Context(), comparison)
	if err != nil {
		t.Fatal("admitted ordinary plan refused")
	}
	if result := s.prepareCompared(t.Context(), comparison, plan); result != custodyFailure(contract.CryptoCustodyUnavailable) {
		t.Fatal("controlled preparation failure changed", result)
	}
	facts, status := permit.observation.read()
	if len(facts) != 3 || status.Accepted != 3 || facts[1].Change == nil || len(facts[1].Change.Entries) != 1 || !facts[1].Change.Entries[0].AfterPresent || facts[1].Change.Entries[0].BeforePresent || facts[1].Change.HasChangedSubjects {
		t.Fatal("checked comparison detail missing", status)
	}
	facts = []observationFact{facts[0], facts[2]}
	if len(facts) != 2 || len(custody.calls) != 2 || facts[0].Exchange.Kind != contract.CryptoCompare || facts[1].Exchange.Kind != contract.CryptoPrepare ||
		!facts[0].Exchange.Source.OperationID.IsZero() || facts[1].Exchange.Source.OperationID != plan.operation || !facts[0].Exchange.Source.AttemptID.IsZero() || !facts[1].Exchange.Source.AttemptID.IsZero() ||
		!reflect.DeepEqual(facts[0].Exchange.Rows, []contract.KeyUseRow{row}) || len(facts[1].Exchange.Rows) != 0 {
		t.Fatal("checked plan rewrote earlier facts or lost admitted identity", status)
	}
}
