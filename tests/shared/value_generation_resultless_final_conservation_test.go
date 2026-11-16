package core

import (
	"slices"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGeneratedResultlessFinalPreservesEnteredFrontier(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, true)
	before := newEnvironmentFixture(t, t.Context(), env, nil, false).session
	prior, _ := preparePrivateGeneratedReservation(t, env, before,
		generatedPlanInputForGenerations(t, before, generatedVectorID(230), []string{"resultless"}, defaultGeneratedFixtureProfile()), nil)
	entered, original := generatedRetainedClosureEnterWithoutPacket(t, env, before, prior)
	fenced := selectGeneratedResiduePlan(t, t.Context(), env, entered, original.Template.AttemptID)
	prior = preparePrivateGeneratedSuccessorReservation(t, env, fenced)
	entered, frontier := generatedRetainedClosureEnterWithoutPacket(t, env, fenced, prior)
	fenced = selectGeneratedResiduePlan(t, t.Context(), env, entered, frontier.Template.AttemptID)
	admitted := generatedPlanInputFixture(t, fenced).context
	admitted.AdmissionID, admitted.SessionID = testID(t.Name()+" admission"), testID(t.Name()+" session")
	plan, err := fenced.generatedFinalRequest(t.Context(), admitted)
	if err != nil || plan.selecting || len(plan.results) != 0 {
		t.Fatal("exhausted actual resultless path did not admit nonselecting Final", err)
	}
	permit := admitPrivateGeneratedFinal(t, env, fenced, plan)
	prepared, result := fenced.PrepareGeneratedFinal(t.Context(), permit)
	if prepared == nil || result.Outcome != ObservedCurrent {
		t.Fatal("actual resultless Final preparation", result)
	}
	work := mustSelectedGeneratedWork(t, prepared.reservation.state)
	if len(work.attempts) != 2 || work.attempts[original.Template.AttemptID].record.State != contract.GeneratedEffectClosedWithResidue ||
		work.attempts[frontier.Template.AttemptID].record.State != contract.GeneratedEffectClosedWithResidue {
		t.Fatal("actual Final did not contain both independently entered Attempts")
	}
	candidate := generatedPrivateCandidate(t, prepared)
	candidate.SupportRecords = slices.DeleteFunc(slices.Clone(candidate.SupportRecords), func(row contract.SupportRecord) bool {
		if row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == frontier.Template.AttemptID ||
			row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == frontier.Template.HazardID {
			return true
		}
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		return carrier.OwnerKind == contract.GeneratedAttemptSupportKind && carrier.OwnerID == frontier.Template.AttemptID ||
			carrier.OwnerKind == contract.GeneratedHazardSupportKind && carrier.OwnerID == frontier.Template.HazardID
	})
	candidate.PublicState.RequiredSupport, err = contract.RequiredSupportDescriptor(env.Domain, candidate.SupportRecords)
	if err != nil {
		t.Fatal("well-formed omitted frontier support", err)
	}
	q := contract.CryptoGeneratedFreezeRequest{OperationRef: prepared.operation.operationRef, Context: prepared.operation.context,
		PhaseID: candidate.Subject.PhaseID, RequestIdentityDigest: candidate.Subject.RequestIdentityDigest,
		HeadCoreDigest: candidate.Subject.HeadCoreDigest, ConditionDigest: candidate.Subject.ConditionDigest}
	q.CandidatePublicStateDescriptor, err = contract.PublicStateDescriptor(candidate.PublicState)
	if err != nil {
		t.Fatal(err)
	}
	q.CandidateSupport = candidate.PublicState.RequiredSupport
	q.CandidateAccess, err = contract.AccessRecordsDescriptor(env.Domain, candidate.AccessRecords)
	if err != nil {
		t.Fatal(err)
	}
	q.ActualResults, err = contract.GeneratorResultReferencesDescriptor(prepared.results)
	if err != nil {
		t.Fatal(err)
	}
	q.KeyUses, err = contract.CryptoGeneratedKeyUseDescriptor(prepared.keyUses)
	if err != nil {
		t.Fatal(err)
	}
	freezeBody, err := contract.EncodeCryptoGeneratedFreezeRequest(q)
	if err != nil {
		t.Fatal("well-formed omitted frontier Freeze", err)
	}
	claimBody, err := contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(q))
	if err != nil {
		t.Fatal("well-formed omitted frontier Claim", err)
	}
	store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
	creates, cas, signs := store.creates, store.cas, trust.signs
	code := keys.BindGeneratedCandidate(t.Context(), plan.request.Context.AdmissionID, candidate)
	crypto := keys.Crypto()
	freezeRequest := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoFreeze,
		RequestID: testID(t.Name() + " Freeze"), CustodyInstanceID: crypto.InstanceID(), Body: freezeBody}
	freeze := crypto.Exchange(t.Context(), freezeRequest)
	if err := contract.ValidateCryptoExchange(freezeRequest, freeze); err != nil {
		t.Fatal("Freeze exchange framing", err)
	}
	claimRequest := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoClaim,
		RequestID: testID(t.Name() + " Claim"), CustodyInstanceID: crypto.InstanceID(), Body: claimBody}
	claim := crypto.Exchange(t.Context(), claimRequest)
	if err := contract.ValidateCryptoExchange(claimRequest, claim); err != nil {
		t.Fatal("Claim exchange framing", err)
	}
	if code != contract.CryptoInvalidAdmission || freeze.ResultCode != contract.CryptoAlreadyUsed || claim.ResultCode != contract.CryptoAlreadyUsed {
		t.Fatal("resultless Final omitted a selected entered frontier", code, "Freeze", freeze.ResultCode, "Claim", claim.ResultCode)
	}
	if len(freeze.Body) != 0 || len(freeze.KeyUseRows) != 0 || len(claim.Body) != 0 || len(claim.KeyUseRows) != 0 ||
		store.creates != creates || store.cas != cas || trust.signs != signs {
		t.Fatal("refused resultless Final retained private rights or reached a write")
	}
	keys.RetireGenerated()
}
