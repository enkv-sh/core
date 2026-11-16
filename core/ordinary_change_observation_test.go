package core

import (
	"bytes"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func observationOrdinaryPreparedBody(t testing.TB, c *Comparison, plan transitionPlan, invalid bool) []byte {
	t.Helper()
	entry := *c.session.valueEntry(0)
	entry.Recipients = slices.Clone(c.desiredEntries[0].Recipients)
	entry.ValueState, entry.OriginSnapshot, entry.OriginTransition = plan.values[0], plan.snapshot, plan.transition
	if invalid {
		entry.OriginTransition = generatedVectorID(250)
	}
	payload, err := contract.DecodeCanonicalPayload(entry.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.DataKeyID, payload.CommitmentKeyID, payload.PackageCheck = generatedVectorID(251), generatedVectorID(252), generatedVectorID(253)
	payload.Ciphertext = bytes.Repeat([]byte{254}, len(payload.Ciphertext))
	entry.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	entryBody, err := contract.EncodeValueEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	core, err := contract.ValueCoreForEntry(c.session.root.Domain, contract.CompatibilityID(), entry)
	if err != nil {
		t.Fatal(err)
	}
	material, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	access := c.session.access[0].Records[0]
	access.MaterialID, access.MaterialContextDigest, access.PackageCheck = entry.ValueState, material, payload.PackageCheck
	access.Wraps = slices.Clone(access.Wraps[:1])
	access.Wraps[0].RSACiphertext = bytes.Repeat([]byte{255}, 384)
	accessBody, err := contract.EncodeAccessRecord(access)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.EncodeCryptoPrepareResult(contract.CryptoPrepareResult{Rows: []contract.CryptoPreparedSecret{{Name: entry.Name, Slot: 0, EntryBytes: entryBody, AccessRecord: accessBody}}})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// full_only: false
func TestOrdinaryCandidateObservationSeparatesEqualContentAndMaterialReplacement(t *testing.T) {
	for _, condition := range []string{"freeze failure", "malformed preparation", "wrong prepared identity"} {
		t.Run(condition, func(t *testing.T) {
			s := generatedEmptyPredecessorForFamily(t, contract.GCP)
			observationCurrentSecret(t, s, []contract.ID{s.admission.recipient, generatedVectorID(200)}, generatedVectorID(201))
			basis, ok := s.admission.domainBasis()
			if !ok {
				t.Fatal("selected fixture public basis unavailable")
			}
			basis.Recipients = append(basis.Recipients, *s.recipients[0].Slots[1])
			var err error
			s.admission.descriptor, err = contract.EncodeGenesisDescriptorCore(basis)
			if err != nil {
				t.Fatal("selected fixture reader enrollment", err)
			}
			generatedSealSelectedFixture(t, s)
			observationProtectFixture(t, s)
			if _, relationErr := s.validateRelationsMode(t.Context(), false); relationErr != nil {
				t.Fatal("selected fixture relations invalid")
			}
			custody := &observationExchangeCustody{instance: generatedVectorID(105)}
			input, owner, key := observationComparisonPermit(t, s, custody)
			unchecked, result := s.compareEntryInputs(input)
			if unchecked == nil {
				t.Fatal(result)
			}
			comparisonBody := observationComparedBody(t, unchecked, contract.CryptoEqual, true)
			var preparedBody []byte
			freezeCalls := 0
			custody.reply = func(q contract.CryptoRequest) contract.CryptoResponse {
				switch q.Kind {
				case contract.CryptoCompare:
					opened := key
					opened.Count = 2
					return observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{opened}, comparisonBody)
				case contract.CryptoPrepare:
					wrapped := key
					wrapped.Purpose = contract.KeyUseMaterialWrap
					return observationReply(q, contract.CryptoSuccess, []contract.KeyUseRow{wrapped, key}, preparedBody)
				case contract.CryptoFreeze:
					freezeCalls++
					facts, _ := owner.observation.read()
					if len(facts) != 4 || facts[3].Change == nil || facts[3].Change.Source.Stage != observationCandidate {
						t.Fatal("candidate material fact missing before Freeze")
					}
					return observationReply(q, contract.CryptoCustodyUnavailable, nil, nil)
				default:
					t.Fatal("unexpected custody exchange", q.Kind)
					return contract.CryptoResponse{}
				}
			}
			comparison, result := s.compare(t.Context(), input, owner)
			if comparison == nil || result.Outcome != ObservedCurrent || !comparison.needsFreshValue(0) {
				t.Fatal("checked equal exclusion did not require fresh material", result)
			}
			plan, err := planTransition(t.Context(), comparison)
			if err != nil {
				t.Fatal("ordinary plan refused")
			}
			preparedBody = observationOrdinaryPreparedBody(t, comparison, plan, condition == "wrong prepared identity")
			if condition == "malformed preparation" {
				preparedBody = []byte{1}
			}
			result = s.prepareCompared(t.Context(), comparison, plan)
			if condition != "freeze failure" {
				facts, status := owner.observation.read()
				if result != refused(AdmissionInvalid) || status.Rejected != 0 || freezeCalls != 0 || len(custody.calls) != 2 || custody.calls[1].Kind != contract.CryptoPrepare {
					t.Fatal("rejected preparation crossed the candidate boundary", result, status)
				}
				if condition == "malformed preparation" {
					if len(facts) != 2 || status.Accepted != 2 || facts[0].Exchange == nil || facts[0].Exchange.Kind != contract.CryptoCompare || facts[1].Change == nil || facts[1].Change.Source.Stage != observationComparison {
						t.Fatal("rejected exchange supplied preparation or candidate facts", status)
					}
				} else if len(facts) != 3 || status.Accepted != 3 || facts[2].Exchange == nil || facts[2].Exchange.Kind != contract.CryptoPrepare || facts[2].Exchange.ResultCode != contract.CryptoSuccess {
					t.Fatal("semantic rejection lost checked exchange or supplied candidate facts", status)
				}
				return
			}
			if result != (Result{}) {
				t.Fatal("checked preparation refused", result)
			}
			next, err := s.deriveSuccessor(t.Context(), comparison, plan)
			if err != nil {
				t.Fatal("validated successor refused")
			}
			authority, err := s.authorityFrom(next, comparison, plan)
			if err != nil {
				t.Fatal(err)
			}
			permit := &AdmittedParentTransition{session: s, comparison: comparison, predecessorDigest: contract.Hash(s.body), predecessorRevision: s.head.Core.Revision, predecessorToken: s.token, plan: plan, authority: authority}
			candidate, result := s.prepare(t.Context(), comparison, permit, testtrust.New(t, contract.GCP, s.admission.trust))
			if candidate != nil || result != custodyFailure(contract.CryptoCustodyUnavailable) || freezeCalls != 1 {
				t.Fatal("controlled Freeze failure changed", result, freezeCalls)
			}
			facts, status := owner.observation.read()
			if len(facts) != 5 || status.Accepted != 5 || status.Rejected != 0 || facts[1].Change == nil || facts[3].Change == nil {
				t.Fatal("checked comparison or candidate detail lost", status)
			}
			checked, detail := facts[1].Change, facts[3].Change
			wantEntry := observationEntry{BeforePresent: true, AfterPresent: true, BeforeIncarnationID: generatedVectorID(201), AfterIncarnationID: generatedVectorID(201), BeforeSource: contract.Supplied, AfterSource: contract.Supplied, BeforeConfidentiality: contract.Secret, AfterConfidentiality: contract.Secret, Fields: observationFieldMembership | observationFieldEncodedMaterial}
			wantNames := []observationName{{EntryIncarnationID: generatedVectorID(201), Name: "secret", Side: observationBefore}, {EntryIncarnationID: generatedVectorID(201), Name: "secret", Side: observationAfter}}
			wantMemberships := []observationMembership{{EntryIncarnationID: generatedVectorID(201), RecipientID: generatedVectorID(200), Change: contract.ChangedSubjectRemoved}}
			if len(checked.Entries) != 1 || checked.Entries[0].Relation != observationEqual || checked.Entries[0].Fields != 0 || !reflect.DeepEqual(checked.Memberships, wantMemberships) || !reflect.DeepEqual(detail.Entries, []observationEntry{wantEntry}) || !reflect.DeepEqual(detail.Names, wantNames) {
				t.Fatal("content relation, membership and material replacement were conflated", checked, detail)
			}
			if detail.Source != owner.observation.sourceFor(observationSource{Stage: observationCandidate, OperationID: plan.operation}) || detail.Candidate != (observationCandidateIdentity{RevisionID: plan.revision, SnapshotID: plan.snapshot, PredecessorRevisionID: s.head.Core.Revision, PredecessorDigest: contract.Hash(s.body)}) || detail.Result != (Result{}) || detail.HasChangedSubjects || detail.Descriptor != (contract.GeneratorDescriptor{}) || len(detail.Subjects) != 0 || len(detail.Memberships) != 0 {
				t.Fatal("ordinary candidate overstated its stage or commitment", detail)
			}
		})
	}
}

// full_only: false
func TestOrdinaryCandidateObservationRetainedMaterialHasNoReplacementFlag(t *testing.T) {
	before, _ := observationTestSession(t)
	observationCurrentSecret(t, before, []contract.ID{before.admission.recipient}, generatedVectorID(201))
	entry := *before.valueEntry(0)
	entry.Recipients = []contract.ID{before.admission.recipient, generatedVectorID(200)}
	after := *before
	observationInstallEntries(&after, []contract.ValueEntry{entry})
	detail := ordinaryCandidateObservation(before, &after)
	if len(detail.Entries) != 1 || detail.Entries[0].Fields != observationFieldMembership || detail.Entries[0].Relation != observationRelationUnavailable || detail.HasChangedSubjects || len(detail.Subjects) != 0 {
		t.Fatal("retained encrypted material claimed replacement or checked relation", detail)
	}
}
