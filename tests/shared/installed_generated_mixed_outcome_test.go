package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func installedGeneratedMixedProcess(t testing.TB) (*generatedProcessFixture, func() int32) {
	t.Helper()
	var creates atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Error("mixed create sent an unexpected operation")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if creates.Add(1) != 1 {
			if _, err := w.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{}}`)); err != nil {
				t.Error("mixed create ambiguity response failed")
			}
			return
		}
		if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"00000000000000000000000000000001","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount); err != nil {
			t.Error("mixed create success response failed")
		}
	}))
	t.Cleanup(server.Close)
	origin := server.URL + "/client/v4"
	artifact, implementation := buildHermeticCloudflareGenerator(t, origin)
	intent, request := hermeticCloudflareIntent()
	return &generatedProcessFixture{Artifact: artifact, Implementation: implementation, Intent: intent,
		RequestDigest: hermeticCloudflareHTTPRequestDigest(request), Configure: func(tb testing.TB, artifact string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(tb, artifact, origin, implementation, expected)
		}}, creates.Load
}

// full_only: false
func TestInstalledGeneratedMixedCreateOutcomesPreserveCompletePredecessor(t *testing.T) {
	for _, tc := range []struct {
		name              string
		custodyFailure    bool
		cleanupDiagnostic bool
	}{
		{name: "unknown-exhaustion"},
		{name: "custody-unavailable-restart", custodyFailure: true},
		{name: "multiple-cleanup-with-unknown", cleanupDiagnostic: true},
		{name: "cleanup-before-later-custody-failure", custodyFailure: true, cleanupDiagnostic: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, creates := installedGeneratedMixedProcess(t)
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, tc.custodyFailure)
			f.env.GeneratedProcess = process
			authority := []contract.ID{f.selected.admission.recipient}
			priorInput := []ApplyEntryInput{
				suppliedSecret(t, f.env, "secret", "mixed failed membership predecessor", custody.StandardValue, authority...),
				{Name: "plain", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: authority, InputBytes: []byte("prior supplied value")},
				{Name: "prior-only", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: authority, InputBytes: []byte("prior entry that the proposal removes")},
			}
			initial := f.engine(t, f.selected, priorInput, nil)
			if got := initial.Apply(ctx, testID("mixed create predecessor"), priorInput); got.Result.Outcome != ObservedCurrent {
				t.Fatal("mixed create predecessor was not selected", got.Result)
			}
			initial.Close()
			prior := f.open(t, ctx)
			oldSecret := sessionConsumerSelection(t, prior, authority[0], "secret")
			grant := []contract.ID{authority[0], fixtureID(f.env.Domain, "reader")}
			slices.SortFunc(grant, compareGeneratedIDs)
			assertPrior := func(selected *StateSession) {
				t.Helper()
				if selected.root.ValueEntryCount != 3 || selected.root.SecretCount != 1 || selected.root.MembershipCount != 3 ||
					selected.root.Generated.GeneratedCurrent != 0 || !reflect.DeepEqual(selected.root.Names, prior.root.Names) ||
					!reflect.DeepEqual(selected.registry(), prior.registry()) {
					t.Fatal("mixed create partially selected its proposed complete set")
				}
				if access, ok := observeMaterialAccess(selected, contract.ValueMaterialKind, oldSecret.Entry.ValueState); !ok || !reflect.DeepEqual(access, oldSecret.Access) {
					t.Fatal("failed membership grant changed exact predecessor access")
				}
				if selection, result := selected.admitConsumerSelection(ctx, []string{"secret"}, fixtureID(f.env.Domain, "reader")); selection != nil || result.Outcome != AdmissionRefused {
					t.Fatal("failed membership grant gave the proposed reader current access")
				}
				for _, named := range prior.root.Names {
					if !reflect.DeepEqual(selected.valueEntry(named.Slot), prior.valueEntry(named.Slot)) {
						t.Fatal("mixed create changed an exact predecessor entry", named.Name)
					}
				}
			}
			declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
				ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
				CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			input := []ApplyEntryInput{
				{Name: "alpha", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: authority, Generated: &declaration},
				{Name: "omega", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: authority, Generated: &declaration},
				{Name: "plain", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: authority, InputBytes: []byte("proposed replacement supplied value")},
				{Name: "secret", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, Recipients: grant, Retained: &contract.RetainedSecretInput{Incarnation: oldSecret.Entry.Incarnation, Material: oldSecret.Entry.ValueState}},
			}
			type attemptObservation struct {
				name     string
				template contract.GeneratorAttemptTemplate
				calls    atomic.Int32
				joined   atomic.Int32
			}
			var attempts []*attemptObservation
			alphaReady, omegaReturned, releaseAlpha := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseAlpha) }) }
			callbacks := installedGeneratedTestCallbacks(t, f, process)
			admit := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				graph, err := contract.DecodeGeneratorPlanBundle(in.Session.Graph)
				if err != nil {
					return nil, err
				}
				name := ""
				for _, lineage := range graph.Lineages {
					if lineage.LineageID == in.Expected.Template.LineageID {
						name = lineage.Name
					}
				}
				for _, previous := range attempts {
					if previous.template.AttemptID == in.Expected.Template.AttemptID {
						t.Error("continuation prepared an already entered original")
						return nil, contract.ErrRecord
					}
				}
				owner, err := admit(ctx, q, control, in, implementation, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				observed := &attemptObservation{name: name, template: in.Expected.Template}
				attempts = append(attempts, observed)
				invoke, closeOwner := owner.InvokeProducer, owner.Close
				owner.Close = func() {
					if observed.joined.Load() != observed.calls.Load() {
						t.Error("installed apply closed custody before its entered child joined")
					}
					closeOwner()
				}
				owner.InvokeProducer = func(ctx context.Context, locator, transmission contract.ID) contract.GeneratedProducerResult {
					observed.calls.Add(1)
					defer observed.joined.Add(1)
					if name == "omega" && observed.template.Branch == contract.GeneratorBranchInitial {
						select {
						case <-alphaReady:
						case <-ctx.Done():
							return contract.GeneratedProducerResult{Code: contract.CryptoCustodyUnavailable}
						}
					}
					returned := invoke(ctx, locator, transmission)
					body, facts, code := returned.Record, returned.Facts, returned.Code
					// Controlled typed facts test Core aggregation only. Native host
					// qualification is covered by the independent removal fixtures.
					if tc.cleanupDiagnostic {
						returned.ExecutableCleanupFailed = true
					}
					switch name {
					case "alpha":
						if code != contract.CryptoSuccess || len(body) == 0 || facts.Disposition != contract.GeneratorDispositionCompleteCreate {
							t.Error("successful original did not return its qualified result")
						}
						close(alphaReady)
						select {
						case <-releaseAlpha:
						case <-ctx.Done():
						}
					case "omega":
						if code != contract.CryptoSuccess || len(body) != 0 || facts.Disposition != contract.GeneratorDispositionUnknown {
							t.Error("ambiguous create did not return qualified bodyless unknown facts")
						}
						if observed.template.Branch == contract.GeneratorBranchInitial {
							close(omegaReturned)
							if tc.custodyFailure {
								returned.Record, returned.Code = nil, contract.CryptoCustodyUnavailable
								return returned
							}
						}
					default:
						t.Error("mixed create admitted an unexpected lineage")
					}
					return returned
				}
				return owner, nil
			}
			if tc.custodyFailure {
				callbacks.AdmitAdoption = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error) {
					return nil, contract.ErrRecord
				}
			}
			engine := installedGeneratedTestEngine(t, ctx, f, prior, input, currentApplyRecipients(prior.registry()), callbacks)
			returned, joined := make(chan PublicApplyResult, 1), make(chan struct{})
			go func() {
				defer close(joined)
				returned <- engine.Apply(ctx, testID("mixed original create outcomes"), input)
			}()
			defer func() { release(); cancel(); <-joined }()
			select {
			case <-omegaReturned:
			case <-ctx.Done():
				t.Fatal("both original producers did not enter and finish native work")
			}
			select {
			case <-returned:
				t.Fatal("installed apply returned while its successful child was still held")
			case <-time.After(50 * time.Millisecond):
			}
			release()
			var got PublicApplyResult
			select {
			case got = <-returned:
			case <-ctx.Done():
				t.Fatal("mixed create did not return after both children joined")
			}
			<-joined
			engine.Close()
			assertCleanup := func(result PublicApplyResult, invoked bool) {
				t.Helper()
				count := 0
				for _, diagnostic := range result.Diagnostics {
					if generatorCleanupDiagnostic(diagnostic) {
						count++
					}
				}
				want := 0
				if tc.cleanupDiagnostic && invoked {
					want = 1
				}
				if count != want {
					t.Fatal("joined original cleanup aggregation differs", count, want)
				}
			}
			assertCleanup(got, true)
			if tc.custodyFailure {
				stopped := f.open(t, ctx)
				assertPrior(stopped)
				if got.Result.Outcome != ObservedCurrent || got.Result.Reason != CustodyUnavailable || got.OperationID.IsZero() ||
					got.RequestIdentity.IsZero() || got.Generated == nil || len(got.Generated.Effects) != 2 || len(got.Receipt) != 0 || got.Payload != nil ||
					stopped.root.Generated.ActiveOwner != got.OperationID || creates() != 2 {
					t.Fatal("non-success producer return lost the selected original set or custody reason", got.Result)
				}
				work := mustSelectedGeneratedWork(t, stopped)
				for _, observed := range attempts {
					original, present := work.attempts[observed.template.AttemptID]
					if !present || original.record.State != contract.GeneratedEffectTransmitted || observed.calls.Load() != 1 || observed.joined.Load() != 1 {
						t.Fatal("non-success return lost an exact joined original")
					}
					body, found, result := stopped.ReadGeneratedResult(ctx, observed.template.AttemptID)
					if result.Outcome != 0 || found != (observed.name == "alpha") || (found && len(body) == 0) {
						t.Fatal("non-success return lost its successful sibling's durable original")
					}
				}
				resumedCallbacks := installedGeneratedTestCallbacks(t, f, process)
				resumedCallbacks.AdmitProducer = callbacks.AdmitProducer
				resumed := installedGeneratedTestEngine(t, ctx, f, stopped, input, currentApplyRecipients(stopped.registry()), resumedCallbacks)
				continued := resumed.Continue(ctx, testID("mixed original exact continuation"), got.OperationID)
				resumed.Close()
				if continued.OperationID != got.OperationID || continued.RequestIdentity != got.RequestIdentity {
					t.Fatal("cold continuation replaced the accepted parent or request")
				}
				assertCleanup(continued, false)
				got = continued
			}
			closed := f.open(t, ctx)
			assertPrior(closed)
			if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.StateResult != "effect-unknown" ||
				got.Generated.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || got.Generated.EffectSummary != contract.ReceiptEffectUnknown ||
				!got.Generated.EffectsAvailable || !got.Generated.RelatedWorkAvailable || !got.Generated.SummaryCountsAvailable ||
				len(got.Generated.Effects) != 2 || len(got.Generated.Duties) != 1 || len(got.Generated.Hazards) != 1 || got.Generated.UnknownCount != 1 ||
				!got.Generated.Warnings.PossibleLiveResidue || got.Payload == nil || len(got.Receipt) == 0 || creates() != 2 || len(attempts) != 2 ||
				!closed.root.Generated.ActiveOwner.IsZero() || !closed.root.Generated.ActivePhase.IsZero() || !closed.root.Generated.ActiveGraph.IsZero() {
				t.Fatal("mixed create did not close with the complete failed aggregate", got.Result, creates())
			}
			counts := got.Generated.SummaryCounts
			if counts[contract.ReceiptEffectCount] != 2 || counts[contract.ReceiptSummarySuccessCount] != 1 || counts[contract.ReceiptSummaryUnknownCount] != 1 ||
				counts[contract.ReceiptPreservedResidueCount] != 0 || counts[contract.ReceiptDutyCount] != 1 || counts[contract.ReceiptHazardCount] != 1 {
				t.Fatal("mixed create summary omitted an entered sibling")
			}
			work := mustSelectedGeneratedWork(t, closed)
			if work.parent != nil || len(work.attempts) != 2 || closed.root.Generated.Duties != 1 || closed.root.Generated.Hazards != 1 {
				t.Fatal("cold closure lost exact failed aggregate support")
			}
			var dutyIDs, hazardIDs []contract.ID
			for _, observed := range attempts {
				x := observed.template
				if observed.calls.Load() != 1 || observed.joined.Load() != 1 {
					t.Fatal("an entered producer was repeated or did not join")
				}
				at := slices.IndexFunc(got.Generated.Effects, func(row GeneratedEffectFact) bool { return row.Record.AttemptID == x.AttemptID })
				actual, present := work.attempts[x.AttemptID]
				if at < 0 || !present || got.Generated.Effects[at].Record != actual.record || actual.record.OperationID != got.OperationID ||
					got.Generated.Effects[at].Name != observed.name || actual.record.ResourceID != x.ResourceIncarnationID {
					t.Fatal("public result and cold state disagree on an exact entered create")
				}
				if observed.name == "alpha" {
					duty := got.Generated.Duties[0]
					if x.Branch != contract.GeneratorBranchInitial || actual.record.State != contract.GeneratedEffectSucceeded ||
						duty.Record.DutyID != x.DutyID || duty.Record.Kind != contract.GeneratedDutyUnselectedCleanup ||
						duty.Record.Status != contract.GeneratedEffectSucceeded || duty.Record.OriginalAttemptID != x.AttemptID ||
						duty.Target == nil || duty.Target.Name != "alpha" || duty.Target.OriginalOperationID != got.OperationID ||
						duty.Target.OriginalAttemptID != x.AttemptID || duty.Target.ResourceID != x.ResourceIncarnationID ||
						duty.Target.ResourceContractID != hermeticCloudflareResourceContractID() || duty.Target.ResourceDigest != hermeticCloudflareResourceDigest("00000000000000000000000000000001") {
						t.Fatal("successful unselected create lost its exact cleanup obligation")
					}
					body := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, x.DutyID}].Body
					coldDuty, err := contract.InspectGeneratedDutyRecord(body)
					if err != nil || coldDuty != duty.Record {
						t.Fatal("public cleanup Duty differs from cold selected support", err)
					}
					dutyIDs = append(dutyIDs, x.DutyID)
					continue
				}
				if observed.name != "omega" || x.Branch != contract.GeneratorBranchInitial ||
					actual.record.State != contract.GeneratedEffectClosedWithResidue || got.Generated.Effects[at].HazardID != x.HazardID {
					t.Fatal("unknown lineage exceeded or lost its admitted residue path")
				}
				hazardAt := slices.IndexFunc(got.Generated.Hazards, func(row GeneratedHazardFact) bool { return row.Record.HazardID == x.HazardID })
				if hazardAt < 0 {
					t.Fatal("public aggregate omitted an unknown sibling Hazard")
				}
				hazard := got.Generated.Hazards[hazardAt]
				coldHazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, x.HazardID}].Body)
				if err != nil || coldHazard != hazard.Record || hazard.Record.OriginalAttemptID != x.AttemptID ||
					hazard.Record.OriginalOperationID != got.OperationID || hazard.Record.ResourceID != x.ResourceIncarnationID ||
					hazard.Record.Exposure != contract.GeneratedExposurePossibleLive || hazard.Record.Fenced != 1 ||
					hazard.Target != nil || !hazard.Warnings.PossibleLiveResidue {
					t.Fatal("unknown sibling lost its exact possible-live owner", err)
				}
				hazardIDs = append(hazardIDs, x.HazardID)
			}
			slices.SortFunc(dutyIDs, compareGeneratedIDs)
			slices.SortFunc(hazardIDs, compareGeneratedIDs)
			if !slices.Equal(got.Generated.RelatedDutyIDs, dutyIDs) || !slices.Equal(got.Generated.RelatedHazardIDs, hazardIDs) ||
				!slices.Equal(got.Payload.LiveDutyIDs, dutyIDs) || !slices.Equal(got.Payload.LiveHazardIDs, hazardIDs) {
				t.Fatal("aggregate identity vectors omit exact retained cleanup or unknown work")
			}
			receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
			if err != nil || receipt.OperationID != got.OperationID || receipt.RequestIdentityDigest != got.RequestIdentity ||
				receipt.OperationKind != contract.OperationApplyDeclaration || receipt.StateResult != contract.ReceiptStateEffectUnknown ||
				receipt.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || receipt.SummaryCounts != counts || receipt.UnknownCount != 1 {
				t.Fatal("failed aggregate receipt differs from the complete public result", err)
			}
			observer := installedGeneratedTestEngine(t, ctx, f, closed, input, currentApplyRecipients(closed.registry()), nil)
			observed := observer.Continue(ctx, testID("mixed failed aggregate receipt observation"), got.OperationID)
			observer.Close()
			if observed.Result.Outcome != ObservedCurrent || observed.Generated == nil || !observed.Generated.ReceiptObservation ||
				!bytes.Equal(observed.Receipt, got.Receipt) || creates() != 2 {
				t.Fatal("terminal continuation repeated a create or changed its retained receipt")
			}
			if check := f.keys.Consume(ctx, sessionConsumerSelection(t, closed, authority[0], "secret"), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched {
				t.Fatal("failed mixed create lost the original supplied value", check)
			}
			nextInput := installedApplyCurrentInput(closed)
			nextInput = append(nextInput, ApplyEntryInput{Name: "next", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: authority, InputBytes: []byte("permitted after failed Final"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			next := f.engine(t, closed, nextInput, nil)
			progress := next.Apply(ctx, testID("mutation after failed mixed create"), nextInput)
			next.Close()
			if progress.Result.Outcome != ObservedCurrent || len(progress.Receipt) == 0 || creates() != 2 {
				t.Fatal("failed Final kept the domain blocked or repeated a create", progress.Result)
			}
		})
	}
}
