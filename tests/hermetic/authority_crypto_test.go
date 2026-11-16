package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func authorityCryptoRequest(t *testing.T, s *StateSession, role, materialSourceRole uint8, successor contract.KMSBinding) (contract.SuccessionRequestCore, contract.ApplyContext) {
	t.Helper()
	before := contract.ControlCore{CurrentControl: s.root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *s.authority().CurrentBinding}
	after := before
	after.AccessGeneration++
	operation, mask := uint8(1), uint8(2)
	row := contract.SuccessionReplacementRow{TargetRole: role, BeforeKMS: before.AuthorityKMSBinding, AfterKMS: successor}
	if role == contract.SuccessorRecoveryKEK {
		operation, mask = 3, 8
		copy := *before.Recovery
		after.Recovery = &copy
		row.BeforeKMS = before.Recovery.KMS
		after.Recovery.KMS = successor
	} else {
		after.AuthorityKMSBinding = successor
	}
	var invocation contract.ID
	if _, err := rand.Read(invocation[:]); err != nil {
		t.Fatal(err)
	}
	id := func(name string) contract.ID { return fixtureID(invocation, name) }
	request := contract.SuccessionRequestCore{SuccessionRequestFields: contract.SuccessionRequestFields{Schema: contract.CanonicalSchema, OperationKind: operation, ApprovalRole: 1, ChangeMask: mask, MaterialSourceRole: materialSourceRole,
		DomainID: s.admission.domain, StoreID: before.StoreID, CoordinateID: before.CoordinateID, NonBodyID: before.NonBodyID, TrustInterpretationID: before.TrustInterpretationID,
		CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(),
		AdmissionID: id("succession admission"), OperationID: id("succession operation"), PredecessorHeadRevisionID: s.head.Core.Revision,
		PredecessorFullHEADDigest: contract.Hash(s.body), BeforeAccessRoot: s.root.CurrentAccess.AccessRoot}, Token: s.token, BeforeControl: before, ProposedAfterControl: after,
		ReplacementPlan: contract.SuccessionReplacementPlanCore{SuccessionReplacementPlanFields: contract.SuccessionReplacementPlanFields{Schema: contract.CanonicalSchema, DomainID: s.admission.domain, OperationKind: operation, ChangeMask: mask}, Rows: []contract.SuccessionReplacementRow{row}},
		IdentityPlan:    contract.IdentityPlan{Operation: id("succession operation"), Transition: id("succession transition"), Snapshot: id("succession snapshot"), Revision: id("succession revision")}}
	d, err := contract.SuccessionRequestDescriptor(request)
	if err != nil {
		t.Fatal(err)
	}
	c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, AdmissionID: request.AdmissionID, SessionID: id("succession session"), DomainID: request.DomainID, CompatibilityID: request.CompatibilityID,
		Expiry: uint64(time.Now().Add(time.Minute).UnixNano()), PredecessorHEADDigest: request.PredecessorFullHEADDigest, IntentDescriptor: d, CurrentAccessRoot: request.BeforeAccessRoot}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], root)
	c.OriginalConditionDigest, err = contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	return request, c
}

// full_only: false
func TestAuthorityCryptoAcceptsExactSuccessionContext(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	successor := keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
	_, c := authorityCryptoRequest(t, f.session, contract.SuccessorAuthorityKEK, contract.SuccessionMaterialAuthority, successor)
	if _, err := contract.EncodeApplyContext(c); err != nil {
		t.Fatal("typed succession request context refused", err)
	}
}

// full_only: false
func TestAuthorityCryptoSignerOnlyProjectionDoesNotBegin(t *testing.T) {
	id := func(name string) contract.ID { return testID(name) }
	plan := contract.AccessReplacementPlanCore{DomainID: id("domain"), RequestCoreDigest: id("request"), BeforeAccessRoot: id("access")}
	d, err := contract.AccessReplacementPlanDescriptor(plan)
	if err != nil {
		t.Fatal("canonical signer-only plan refused", err)
	}
	p, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: plan.DomainID, BeforeAccessRoot: plan.BeforeAccessRoot, RequestCoreDigest: plan.RequestCoreDigest}, d, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p.Descriptors(); err != nil {
		t.Fatal(err)
	}
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	successor := keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
	_, c := authorityCryptoRequest(t, f.session, contract.SuccessorAuthorityKEK, contract.SuccessionMaterialAuthority, successor)
	if _, err := contract.EncodeCryptoAccessReplaceRequest(contract.CryptoAccessReplaceRequest{Context: c}); err == nil {
		t.Fatal("empty signer-only plan started Crypto")
	}
}

// full_only: false
func TestAuthorityCryptoQualifiedResultExactBytesAndOwnership(t *testing.T) {
	id := func(value byte) contract.ID { return contract.ID(bytes.Repeat([]byte{value}, 32)) }
	rows := []contract.CryptoQualifiedSuccessor{
		{BindingIndex: 2, Qualification: contract.QualifiedSuccessorRow{ProbeID: id(2), QualifiedBindingFields: contract.QualifiedBindingFields{SubjectKind: 1, SubjectID: id(3), BindingID: id(4), PublicBindingDigest: id(5), Provider: contract.GCP, Qualified: 1}}},
		{BindingIndex: 9, Qualification: contract.QualifiedSuccessorRow{ProbeID: id(6), QualifiedBindingFields: contract.QualifiedBindingFields{SubjectKind: 2, SubjectID: id(7), BindingID: id(8), PublicBindingDigest: id(9), Provider: contract.GCP, Qualified: 1}}},
	}
	for count := 0; count <= 2; count++ {
		result := contract.CryptoAccessReplaceResult{OperationRef: id(1), Qualified: rows[:count]}
		body, err := contract.EncodeCryptoAccessReplaceResult(result)
		if err != nil {
			t.Fatal(err)
		}
		// Independent traversal of the specified u32 count, u16 index and fixed
		// 131-byte public qualification. No production row encoder builds want.
		want := bytes.Repeat([]byte{1}, 32)
		want = binary.BigEndian.AppendUint32(want, uint32(count))
		for _, row := range rows[:count] {
			want = binary.BigEndian.AppendUint16(want, row.BindingIndex)
			want = append(want, row.Qualification.ProbeID[:]...)
			want = append(want, row.Qualification.SubjectKind)
			for _, id := range []contract.ID{row.Qualification.SubjectID, row.Qualification.BindingID, row.Qualification.PublicBindingDigest} {
				want = append(want, id[:]...)
			}
			want = append(want, byte(row.Qualification.Provider), 1)
		}
		if len(body) != 36+133*count || !bytes.Equal(body, want) {
			t.Fatal("qualified result differs from independent bytes")
		}
		decoded, err := contract.DecodeCryptoAccessReplaceResult(body)
		if err != nil {
			t.Fatal(err)
		}
		clear(body)
		owned, err := contract.EncodeCryptoAccessReplaceResult(decoded)
		if err != nil || !bytes.Equal(owned, want) {
			t.Fatal("qualified result borrowed input", err)
		}
	}
	for _, bad := range []contract.CryptoAccessReplaceResult{
		{OperationRef: id(1), Qualified: []contract.CryptoQualifiedSuccessor{rows[1], rows[0]}},
		{OperationRef: id(1), Qualified: []contract.CryptoQualifiedSuccessor{rows[0], rows[0]}},
		{OperationRef: id(1), Qualified: append(slices.Clone(rows), rows[0])},
	} {
		if _, err := contract.EncodeCryptoAccessReplaceResult(bad); err == nil {
			t.Fatal("unordered, duplicate or excess qualification accepted")
		}
	}
	body, err := contract.EncodeCryptoAccessReplaceResult(contract.CryptoAccessReplaceResult{OperationRef: id(1), Qualified: rows[:1]})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{body[:len(body)-1], append(bytes.Clone(body), 0)} {
		if _, err := contract.DecodeCryptoAccessReplaceResult(bad); err == nil {
			t.Fatal("non-exact qualification body accepted")
		}
	}
}

func authorityCryptoPlan(t *testing.T, s *StateSession, keys *custody.Fixture, role uint8, source contract.BindingTableRow, successor contract.KMSBinding) (contract.SuccessionRequestCore, contract.CryptoAccessReplaceRequest, contract.SuccessorKEKProbeCore, []contract.CompactRow) {
	t.Helper()
	request, c := authorityCryptoRequest(t, s, role, source.SubjectKind, successor)
	target := contract.BindingTableRow{SubjectKind: 1, SubjectID: request.BeforeControl.AuthorityRecipientID, Binding: successor}
	before := request.BeforeControl.AuthorityKMSBinding
	if role == contract.SuccessorRecoveryKEK {
		target.SubjectKind, target.SubjectID = 2, request.BeforeControl.Recovery.RoleID
		before = request.BeforeControl.Recovery.KMS
	}
	table := append(keys.Bindings(), target)
	orderBindings(table)
	sourceIndex, successorIndex := -1, -1
	for i, binding := range table {
		if binding.Binding.BindingID == source.Binding.BindingID {
			sourceIndex = i
		}
		if binding.Binding.BindingID == successor.BindingID {
			successorIndex = i
		}
	}
	if sourceIndex < 0 || successorIndex < 0 {
		t.Fatal("test source or successor is missing")
	}
	beforeDigest, err := contract.PublicBindingDigest(before)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.CryptoAccessReplaceRequest{Context: c, BindingTable: table, Replacements: []contract.ReplacementRow{{SubjectKind: target.SubjectKind, SubjectID: target.SubjectID, BeforeBindingDigest: beforeDigest, SuccessorBindingIndex: uint16(successorIndex)}}}
	var rows []contract.CompactRow
	consumer, err := contract.CurrentValueConsumerDigest(s.admission.domain)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range s.root.Names {
		if s.valueEntry(name.Slot).ConfidentialityClass != format.Secret {
			continue
		}
		core, payload, access, ok := s.selectedValue(name.Slot)
		if !ok {
			t.Fatal("selected test material refused")
		}
		immutable, err := contract.ValueImmutableBodyDigest(core, payload)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := contract.AccessRecordDigest(access)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, contract.CompactRow{Coverage: contract.CoverageRow{MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: access.MaterialContextDigest, ImmutableBodyDigest: immutable, BeforeAccessDigest: digest, RequiredConsumerDigest: consumer, SourceBindingIndex: uint16(sourceIndex), TargetBindingIndices: []uint16{uint16(successorIndex)}}, ValueCore: core, BeforeAccessRecord: access})
	}
	slices.SortFunc(rows, func(a, b contract.CompactRow) int {
		return bytes.Compare(a.Coverage.MaterialID[:], b.Coverage.MaterialID[:])
	})
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: c.DomainID, BeforeAccessRoot: c.CurrentAccessRoot, RequestCoreDigest: c.IntentDescriptor.Digest}, plan, uint32(len(rows)))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if err := projection.Add(row, contract.AccessOutputRow{MaterialKind: 1, MaterialID: row.Coverage.MaterialID, BeforeAccessDigest: row.Coverage.BeforeAccessDigest, AfterAccessRecord: row.BeforeAccessRecord}); err != nil {
			t.Fatal(err)
		}
	}
	q.ExpectedCoverageDescriptor, _, _, err = projection.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contract.PublicBindingDigest(successor)
	if err != nil {
		t.Fatal(err)
	}
	probe := contract.SuccessorKEKProbeCore{Schema: contract.CanonicalSchema, Profile: 2, ProbeID: fixtureID(c.AdmissionID, "probe"), Context: c, SubjectKind: target.SubjectKind, SubjectID: target.SubjectID, SuccessorBindingDigest: digest}
	return request, q, probe, rows
}

func authorityCryptoExchange(t *testing.T, adapter contract.Crypto, kind contract.CryptoKind, body []byte) contract.CryptoResponse {
	t.Helper()
	var id contract.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: kind, RequestID: id, CustodyInstanceID: adapter.InstanceID(), Body: body}
	p := adapter.Exchange(context.Background(), q)
	if err := contract.ValidateCryptoExchange(q, p); err != nil {
		t.Fatal("invalid Crypto exchange", err)
	}
	return p
}

// full_only: false
func TestAuthorityCryptoPrivateProbeAndExactSurvivingSource(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, targetRole := range []uint8{contract.SuccessorAuthorityKEK, contract.SuccessorRecoveryKEK} {
			for _, sourceKind := range []uint8{1, 2} {
				for _, material := range []bool{false, true} {
					t.Run(fmt.Sprintf("%d/target%d/source%d/material%t", family, targetRole, sourceKind, material), func(t *testing.T) {
						env, keys := genesisEnvironment(t, family, true)
						run := newScenarioRun(t, context.Background(), env)
						f := newEnvironmentFixture(t, context.Background(), run.env, []int{1}, false)
						if material {
							run.suppliedSelection(f, append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "authority recovery source", custody.StandardValue)))
						}
						var source contract.BindingTableRow
						for _, row := range keys.Bindings() {
							if row.SubjectKind == sourceKind && (sourceKind == 2 || row.SubjectID == f.session.admission.recipient) {
								source = row
							}
						}
						successor := keys.KEKSuccessor(t, targetRole)
						request, q, probe, rows := authorityCryptoPlan(t, f.session, keys, targetRole, source, successor)
						if source.SubjectID != probe.SubjectID {
							keys.LoseRecipientPredecessor(probe.SubjectID)
						}
						if err := keys.AdmitSuccessionAccess(q, request, request.BeforeControl, source, probe, rows, time.Unix(0, int64(q.Context.Expiry))); err != nil {
							t.Fatal("succession private admission refused", err)
						}
						defer keys.RetireAccess()
						_, private := keys.Calls()
						body, err := contract.EncodeCryptoAccessReplaceRequest(q)
						if err != nil {
							t.Fatal(err)
						}
						begin := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoAccessReplace, body)
						if begin.ResultCode != contract.CryptoSuccess {
							t.Fatal("private successor probe failed", begin.ResultCode)
						}
						started, err := contract.DecodeCryptoAccessReplaceResult(begin.Body)
						if err != nil || len(started.Qualified) != 1 || started.Qualified[0].BindingIndex != q.Replacements[0].SuccessorBindingIndex || started.Qualified[0].Qualification.ProbeID != probe.ProbeID || started.Qualified[0].Qualification.PublicBindingDigest != probe.SuccessorBindingDigest {
							t.Fatal("exact qualified successor missing", err)
						}
						if _, after := keys.Calls(); after != private+1 {
							t.Fatal("successor probe did not make exactly one private call")
						}
						prepare := contract.CryptoAccessPrepareRequest{OperationRef: started.OperationRef, Context: q.Context, Final: 1, Rows: rows}
						body, err = contract.EncodeCryptoAccessPrepareRequest(prepare)
						if err != nil {
							t.Fatal(err)
						}
						prepared := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoPrepare, body)
						if prepared.ResultCode != contract.CryptoSuccess {
							t.Fatal("surviving source refused", prepared.ResultCode)
						}
						out, err := contract.DecodeCryptoAccessPrepareResult(prepared.Body)
						if err != nil {
							t.Fatal(err)
						}
						if _, after := keys.Calls(); after != private+1+len(rows) {
							t.Fatal("replacement opened material more than once")
						}
						if material {
							before := sessionConsumerSelection(t, f.session, f.session.admission.recipient, "secret")
							before.Binding = source
							after := before
							after.Binding = q.BindingTable[q.Replacements[0].SuccessorBindingIndex]
							after.Access = out.Rows[0].AfterAccessRecord
							if !keys.MaterialPreserved(before, after) {
								t.Fatal("private oracle found changed D/C")
							}
						}
						frozen := authorityCryptoFreeze(t, f.session, request, q, started.OperationRef, rows, out, keys.Crypto().InstanceID())
						body, err = contract.EncodeCryptoAccessFreezeRequest(frozen)
						if err != nil {
							t.Fatal(err)
						}
						freeze := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoFreeze, body)
						if freeze.ResultCode != contract.CryptoSuccess {
							t.Fatal("succession Freeze refused", freeze.ResultCode)
						}
						fact, err := contract.DecodeCryptoFreezeResult(freeze.Body)
						if err != nil {
							t.Fatal(err)
						}
						want, err := contract.CryptoAccessFactDigest(keys.Crypto().InstanceID(), frozen)
						if err != nil || fact.FactDigest != want {
							t.Fatal("succession fact differs", err)
						}
						body, err = contract.EncodeCryptoAccessClaimRequest(contract.CryptoAccessClaimRequest{CryptoAccessFreezeRequest: frozen, FactDigest: want})
						if err != nil {
							t.Fatal(err)
						}
						if claim := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoClaim, body); claim.ResultCode != contract.CryptoSuccess {
							t.Fatal("succession Claim refused", claim.ResultCode)
						}
						if repeat := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoClaim, body); repeat.ResultCode != contract.CryptoAlreadyUsed {
							t.Fatal("succession Claim repeated", repeat.ResultCode)
						}
					})
				}
			}
		}
	}
}

func authorityCryptoFreeze(t *testing.T, s *StateSession, request contract.SuccessionRequestCore, q contract.CryptoAccessReplaceRequest, operation contract.ID, rows []contract.CompactRow, result contract.CryptoAccessPrepareResult, instance contract.ID) contract.CryptoAccessFreezeRequest {
	t.Helper()
	plan, err := contract.AccessReplacementPlanDescriptor(q.Plan())
	if err != nil {
		t.Fatal(err)
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: q.Context.DomainID, BeforeAccessRoot: q.Context.CurrentAccessRoot, RequestCoreDigest: q.Context.IntentDescriptor.Digest}, plan, uint32(len(rows)))
	if err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		before, after := row.BeforeAccessRecord, result.Rows[i].AfterAccessRecord
		for n, wrap := range before.Wraps {
			if wrap.SubjectKind == q.Replacements[0].SubjectKind && wrap.SubjectID == q.Replacements[0].SubjectID {
				continue
			}
			a, err := contract.EncodeWrapRow(wrap)
			if err != nil {
				t.Fatal(err)
			}
			b, err := contract.EncodeWrapRow(after.Wraps[n])
			if err != nil || !bytes.Equal(a, b) {
				t.Fatal("unaffected wrap bytes changed", err)
			}
		}
		if err := projection.Add(row, result.Rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	coverage, after, unchanged, err := projection.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contract.IdentityPlanDescriptor(request.IdentityPlan)
	if err != nil {
		t.Fatal(err)
	}
	public, err := s.publicProjection()
	if err != nil {
		t.Fatal(err)
	}
	publicDescriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := contract.AccessTranscriptStartDigest(instance, operation, q.Context, plan, coverage)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err = contract.AccessTranscriptStepDigest(transcript, 0, 1, result.InputBatchDescriptor, result.OutputBatchDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	return contract.CryptoAccessFreezeRequest{OperationRef: operation, Context: q.Context, IdentityPlanDescriptor: identity, ExpectedCoverageDescriptor: coverage, AfterAccessRowsDescriptor: after, CandidatePublicStateDescriptor: publicDescriptor, CandidateAccessRoot: fixtureID(q.Context.AdmissionID, "candidate access"), UnchangedMaterialDescriptor: unchanged, FinalTranscriptDigest: transcript}
}

// full_only: false
func TestAuthorityReplacementCoversCurrentRetainedValueAndSeed(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("replace-recovery-%t", recovery), func(t *testing.T) {
			a := newGeneratedResultFixture(t, 2, true)
			env := syntheticAuthorityScenarioEnvironment(t, a.env)
			run := newScenarioRun(t, t.Context(), env)
			before := a.f.session
			work, err := before.selectedGeneratedWork(t.Context())
			if err != nil || work.parent == nil || len(work.canonical) != 1 {
				t.Fatal("fixture lacks retained canonical and seed", err)
			}
			entry := before.valueEntry(before.root.Names[0].Slot)
			if entry == nil || len(work.consumers[materialIdentity{contract.ValueMaterialKind, entry.ValueState}]) == 0 || len(work.consumers[materialIdentity{contract.OperationSeedMaterialKind, work.parent.MaterialID}]) == 0 {
				t.Fatal("fixture lacks current value with retained consumers and owned seed")
			}
			operation, mask, approval := uint8(1), uint8(2), uint8(contract.RecoverySigningRole)
			if recovery {
				operation, mask, approval = 3, 8, contract.NormalSigningRole
			}
			selectGeneratedAccessReplacement(t, t.Context(), run, a.f, operation, mask, approval)
			// A separate custody owner can open every material only through the
			// first successor while replacing the other key.
			run.env = syntheticFreshAuthorityReplacementEnvironment(t, run.env)
			operation, mask, approval = 3, 8, contract.NormalSigningRole
			if recovery {
				operation, mask, approval = 1, 2, contract.RecoverySigningRole
			}
			selectGeneratedAccessReplacement(t, t.Context(), run, a.f, operation, mask, approval)
			store := requireAdmittedMemoryStore(t, a.env.Store)
			selected := selectFreshGeneratedRecord(t, store, a.f.session, a.expected.Template.AttemptID, a.result)
			after, err := selected.selectedGeneratedWork(t.Context())
			if err != nil || !bytes.Equal(after.attempts[a.expected.Template.AttemptID].result, a.result) || a.calls != 1 {
				t.Fatal("cold successor could not authenticate the original result through preserved seed", err)
			}
			checkFreshGeneratedProcess(t, store, selected)
		})
	}
}
