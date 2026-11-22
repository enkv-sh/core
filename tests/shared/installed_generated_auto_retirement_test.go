package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledGeneratedAutomaticUnknownParksAndAdvances(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    int
		rejected bool
	}{
		{"deletes-1", 1, false}, {"deletes-2", 2, false}, {"one host rejection", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count := tc.count
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "unknown")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, count == 2)
			f.env.GeneratedProcess = process
			input := make([]ApplyEntryInput, count)
			for at := range input {
				input[at] = ApplyEntryInput{Name: fmt.Sprintf("generated-%d", at), ValueSource: contract.Generated,
					ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient},
					Generated: &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
						ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
						CompletionClass: contract.GeneratedCompletionAcknowledged,
						Intent:          bytes.Clone(process.Intent)}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			}
			initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			first := initial.Apply(ctx, testID(fmt.Sprintf("automatic unknown initial %d", count)), input)
			initial.Close()
			if first.Result.Outcome != ObservedCurrent {
				t.Fatal("initial generations were not selected", first.Result)
			}
			before := f.open(t, ctx)
			beforeReceipts, err := before.receiptWindows(ctx)
			if err != nil {
				t.Fatal("automatic unknown predecessor receipt order", err)
			}
			old := make(map[string]contract.ValueEntry, count)
			var expectedDeletes []string
			for at := range input {
				_, entry := observeCurrentValueEntry(t, before, input[at].Name)
				old[input[at].Name] = entry
				expectedDeletes = append(expectedDeletes, generatedEntryProviderToken(t, before, entry))
				input[at].Generated.Epoch, input[at].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
			}
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			var rejected contract.ID
			if tc.rejected {
				admit := callbacks.AdmitProducer
				callbacks.AdmitProducer = func(c context.Context, q contract.CryptoGeneratedCompareRequest, ctrl contract.ControlCore, in contract.GeneratedProducerInput, impl contract.GeneratorImplementation, until time.Time) (*InstalledGeneratedProducerCustody, error) {
					owner, err := admit(c, q, ctrl, in, impl, until)
					if err != nil || in.Expected.Template.Action != contract.GeneratorActionDelete || !rejected.IsZero() {
						return owner, err
					}
					invoke := owner.InvokeProducer
					owner.InvokeProducer = func(c context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
						actual := invoke(c, locator, authority)
						if actual.Code != contract.CryptoSuccess || actual.Facts.Disposition != contract.GeneratorDispositionUnknown {
							t.Fatal("missing automatic DELETE return")
						}
						rejected = in.Expected.Template.AttemptID
						actual.Facts.ResourceData = []byte("different public resource")
						body, err := contract.EncodeRejectedRetirement(actual.Facts)
						if err != nil {
							t.Fatal(err)
						}
						return contract.GeneratedProducerResult{Code: contract.CryptoCustodyUnavailable, RejectedRetirement: body}
					}
					return owner, nil
				}
			}
			engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
			result := engine.Apply(ctx, testID(fmt.Sprintf("automatic unknown rotation %d", count)), input)
			engine.Close()
			creates, deletes := effects()
			slices.Sort(expectedDeletes)
			slices.Sort(deletes)
			if result.Result.Outcome != ObservedCurrent || result.Generated == nil || result.Generated.StateResult != "retirement-pending" ||
				result.Generated.CanonicalOutcome != contract.ReceiptCanonicalSelected || len(result.Receipt) == 0 || creates != 2*count || !slices.Equal(deletes, expectedDeletes) {
				t.Fatalf("automatic ambiguity did not park and advance: outcome=%d generated=%t receipt=%t creates=%d deletes=%d", result.Result.Outcome, result.Generated != nil, len(result.Receipt) != 0, creates, len(deletes))
			}
			closed := f.open(t, ctx)
			afterReceipts, err := closed.receiptWindows(ctx)
			if err != nil || len(afterReceipts.Successes) != len(beforeReceipts.Successes)+1 || !slices.Equal(afterReceipts.Failures, beforeReceipts.Failures) || afterReceipts.Successes[len(afterReceipts.Successes)-1].OperationID != result.OperationID {
				t.Fatal("automatic unknown rotation did not append only its parent receipt", err)
			}
			assertSuccessReceiptOrder(t, beforeReceipts, afterReceipts, result.OperationID)
			if !closed.root.Generated.ActiveOwner.IsZero() || len(result.Generated.Effects) != 2*count || len(result.Generated.Duties) != count || len(result.Generated.Hazards) != 0 || result.Generated.UnknownCount != uint32(count) || result.Generated.AcknowledgedCount != 0 {
				t.Fatal("automatic ambiguity lost its terminal parent or exact retained work")
			}
			work := mustSelectedGeneratedWork(t, closed)
			var expectedDutyIDs []contract.ID
			for _, row := range work.records {
				if row.Kind != contract.GeneratedDutySupportKind {
					continue
				}
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil || duty.Kind != contract.GeneratedDutyRetirement {
					t.Fatal("selected automatic work is not an exact retirement Duty", err)
				}
				target, err := work.retirementTarget(ctx, duty)
				prior, present := old[target.Name]
				if err != nil || !present || target.ResourceID != prior.Generated.ResourceIncarnationID || target.ResourceDigest != prior.Generated.ResourceDigest ||
					duty.OriginalOperationID != prior.Generated.OriginOperationID || duty.OriginalAttemptID != prior.Generated.OriginAttemptID {
					t.Fatal("selected pending Duty changed its displaced generation", err)
				}
				expectedDutyIDs = append(expectedDutyIDs, duty.DutyID)
			}
			slices.SortFunc(expectedDutyIDs, compareGeneratedIDs)
			if len(expectedDutyIDs) != count || !slices.Equal(result.Generated.RelatedDutyIDs, expectedDutyIDs) {
				t.Fatal("automatic ambiguity changed the complete ordered selected Duties")
			}
			for at, id := range expectedDutyIDs {
				if result.Generated.Duties[at].Record.DutyID != id {
					t.Fatal("automatic ambiguity Duty facts differ from the selected ordered set")
				}
			}
			unknown := 0
			for _, effect := range result.Generated.Effects {
				if effect.Action != contract.GeneratorActionDelete {
					continue
				}
				prior := old[effect.Name]
				if effect.Record.OperationID != result.OperationID || effect.Record.State != contract.GeneratedEffectUnknown || effect.Target == nil || effect.Target.ResourceDigest != prior.Generated.ResourceDigest || effect.Target.ResourceID != prior.Generated.ResourceIncarnationID || effect.DutyID.IsZero() {
					t.Fatal("parked automatic delete lost its exact old target")
				}
				unknown++
			}
			if tc.rejected {
				receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
				if err != nil || rejected.IsZero() || receipt.EvidenceCeiling != contract.ReceiptEvidenceProviderFacts || receipt.UnknownCount != uint32(count) {
					t.Fatal("mixed automatic receipt lost qualified provider evidence", err)
				}
				if !slices.ContainsFunc(result.Generated.Effects, func(f GeneratedEffectFact) bool {
					return f.Record.AttemptID == rejected && f.Reason == GeneratedReasonRetirementResourceMismatch && f.EvidenceCeiling == contract.ReceiptEvidenceCanonical
				}) {
					t.Fatal("missing exact rejected automatic attempt")
				}
			}
			if unknown != count {
				t.Fatal("automatic ambiguity omitted a requested delete")
			}
			for name, prior := range old {
				_, current := observeCurrentValueEntry(t, closed, name)
				if current.Generated.Epoch != 1 || current.Generated.GenerationID == prior.Generated.GenerationID || current.Generated.RetiringDutyPresent != 1 {
					t.Fatal("parking changed the selected successor or released its old duty")
				}
			}
			cold := installedGeneratedRetirementEngine(t, ctx, f, closed, nil)
			observed := cold.Continue(ctx, testID("automatic unknown terminal observation"), result.OperationID)
			cold.Close()
			if observed.Result.Outcome != ObservedCurrent || observed.Generated == nil || !observed.Generated.ReceiptObservation || !bytes.Equal(observed.Receipt, result.Receipt) {
				t.Fatal("cold continuation replaced the terminal automatic result")
			}
			assertGeneratedReceiptOrder(t, ctx, f.open(t, ctx), afterReceipts.Order)
			laterCreates, laterDeletes := effects()
			slices.Sort(laterDeletes)
			if laterCreates != creates || !slices.Equal(laterDeletes, deletes) {
				t.Fatal("terminal automatic continuation sent another effect")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedRotationRetiresWithinOriginalApply(t *testing.T) {
	for _, tc := range []struct {
		name     string
		modes    []uint8
		recovery bool
		stop     string
	}{
		{name: "manual", modes: []uint8{contract.GeneratedRetirementManual}},
		{name: "auto", modes: []uint8{contract.GeneratedRetirementAuto}, recovery: true},
		{name: "two_auto", modes: []uint8{contract.GeneratedRetirementAuto, contract.GeneratedRetirementAuto}},
		{name: "restart_after_first_auto_close", modes: []uint8{contract.GeneratedRetirementAuto, contract.GeneratedRetirementAuto}, stop: "second_producer"},
		{name: "mixed", modes: []uint8{contract.GeneratedRetirementAuto, contract.GeneratedRetirementManual}},
		{name: "restart_before_delete_reservation", modes: []uint8{contract.GeneratedRetirementAuto}, stop: "producer"},
		{name: "restart_after_result_conflict", modes: []uint8{contract.GeneratedRetirementAuto}, recovery: true, stop: "store"},
		{name: "restart_after_delete_transmission", modes: []uint8{contract.GeneratedRetirementAuto}, recovery: true, stop: "adoption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, tc.recovery)
			f.env.GeneratedProcess = process
			input := []ApplyEntryInput{{Name: "healthy", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw,
				Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("unchanged supplied sibling")}}
			for at := range tc.modes {
				meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
					CompletionClass: contract.GeneratedCompletionAcknowledged,
					Intent:          bytes.Clone(process.Intent)}
				input = append(input, ApplyEntryInput{Name: fmt.Sprintf("generated-%d", at), ValueSource: contract.Generated,
					ConfidentialityClass: contract.Secret, Recipients: []contract.ID{f.selected.admission.recipient}, Generated: meta, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			}
			first := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			initial := first.Apply(ctx, testID(tc.name+" initial generations"), input)
			first.Close()
			if initial.Result.Outcome != ObservedCurrent {
				t.Fatal("initial generations were not selected", initial.Result)
			}
			before := f.open(t, ctx)
			windows, err := before.receiptWindows(ctx)
			if err != nil {
				t.Fatal("initial receipt windows", err)
			}
			old := make(map[string]contract.ValueEntry, len(tc.modes))
			var expectedDeletes []string
			var expectedDuties []contract.ID
			for at, mode := range tc.modes {
				row := &input[at+1]
				_, prior := observeCurrentValueEntry(t, before, row.Name)
				old[row.Name] = prior
				row.Generated.Epoch, row.Generated.RetirementMode = 1, mode
				if mode == contract.GeneratedRetirementAuto {
					expectedDeletes = append(expectedDeletes, generatedEntryProviderToken(t, before, prior))
				} else {
					duty, err := contract.GeneratorDutyID(before.root.Domain, prior.Generated.OriginOperationID, prior.Generated.OriginAttemptID, 2)
					if err != nil {
						t.Fatal("exact manual retirement identity", err)
					}
					expectedDuties = append(expectedDuties, duty)
				}
			}
			slices.Sort(expectedDeletes)
			slices.SortFunc(expectedDuties, compareGeneratedIDs)
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			admitFinal := callbacks.AdmitFinal
			callbacks.AdmitFinal = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				if tc.name == "two_auto" || tc.name == "restart_after_first_auto_close" {
					if len(in.Results) != 2 || len(in.ResultBodies) != 2 {
						t.Fatal("paired result-order fixture requires its two exact Creates")
					}
					// Carrier order is independent of graph order. Keep each
					// qualified reference with its original sealed result body.
					in.Results, in.ResultBodies = slices.Clone(in.Results), slices.Clone(in.ResultBodies)
					descending := tc.name == "restart_after_first_auto_close"
					order := bytes.Compare(in.Results[0].Reference.ResultID[:], in.Results[1].Reference.ResultID[:])
					if !descending && order > 0 || descending && order < 0 {
						in.Results[0], in.Results[1] = in.Results[1], in.Results[0]
						in.ResultBodies[0], in.ResultBodies[1] = in.ResultBodies[1], in.ResultBodies[0]
					}
					t.Log("automatic Final paired carrier order", "descending", descending)
				}
				owner, err := admitFinal(ctx, q, control, in, deadline)
				prepared := in.Preparation != nil
				t.Log("automatic Final admission", "preparation", prepared, "entries", len(in.EntryAdmissions), "results", len(in.Results), "owner present", owner != nil, "error present", err != nil)
				if owner != nil {
					if owner.Crypto != nil {
						owner.Crypto = &automaticFinalDiagnosticCrypto{Crypto: owner.Crypto, t: t, prepared: prepared}
					}
					if owner.BindCandidate != nil {
						bind := owner.BindCandidate
						owner.BindCandidate = func(ctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
							code := bind(ctx, candidate)
							t.Log("automatic Final binding", "preparation", prepared, "code", code)
							return code
						}
					}
				}
				return owner, err
			}
			producer := callbacks.AdmitProducer
			var operation contract.ID
			deleteAdmissions := 0
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				if in.Expected.Template.Action == contract.GeneratorActionDelete {
					deleteAdmissions++
					operation = in.Expected.Plan.OperationID
					selected := f.open(t, ctx)
					assertGeneratedReceiptOrder(t, ctx, selected, windows.Order)
					work := mustSelectedGeneratedWork(t, selected)
					if work.parent == nil || work.parent.OperationID != operation || selected.root.Generated.ActiveOwner != operation || work.bundles[0].Request.OperationKind != contract.OperationApplyDeclaration {
						t.Fatal("automatic delete left the original apply Parent")
					}
					if _, _, found, err := selected.retainedMutationReceipt(operation); err != nil || found {
						t.Fatal("automatic delete followed an early terminal apply receipt", found, err)
					}
					for name, prior := range old {
						_, current := observeCurrentValueEntry(t, selected, name)
						if current.Generated.Epoch != 1 || current.Generated.GenerationID == prior.Generated.GenerationID || current.Generated.OriginOperationID != operation || in.Target != nil && name == in.Target.Name && current.Generated.RetiringDutyPresent != 1 {
							t.Fatal("automatic delete preceded whole-set successor selection", name)
						}
					}
					if in.Target == nil || in.Target.ResourceDigest != old[in.Target.Name].Generated.ResourceDigest {
						t.Fatal("automatic delete did not name its exact displaced resource")
					}
					if tc.stop == "producer" || tc.stop == "second_producer" && deleteAdmissions == 2 {
						return nil, contract.ErrRecord
					}
				}
				return producer(ctx, q, control, in, implementation, deadline)
			}
			adoption := callbacks.AdmitAdoption
			callbacks.AdmitAdoption = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				if tc.stop == "adoption" && in.Result.Expected.Template.Action == contract.GeneratorActionDelete {
					return nil, contract.ErrRecord
				}
				return adoption(ctx, q, control, in, deadline)
			}
			var checkConflict func(PublicApplyResult)
			if tc.stop == "store" {
				checkConflict = conflictInstalledDeleteReadback(t, &f, callbacks)
			}
			engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
			got := engine.Apply(ctx, testID(tc.name+" requested rotation"), input)
			engine.Close()
			if checkConflict != nil {
				checkConflict(got)
			}
			for _, row := range f.open(t, ctx).supportRecords() {
				if row.Kind != contract.GeneratedDutySupportKind {
					continue
				}
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil || duty.Kind == contract.GeneratedDutyRetirement && (duty.Schema != contract.GeneratedDutyRecordSchema || duty.LifecycleMode != contract.GeneratorLifecycleManaged) {
					t.Fatal("new CF retirement did not use the current stored Duty schema", err)
				}
			}
			if tc.stop != "" {
				wantAdmissions := 1
				if tc.stop == "second_producer" {
					wantAdmissions = 2
				}
				if deleteAdmissions != wantAdmissions || operation.IsZero() || got.OperationID != operation || len(got.Receipt) != 0 {
					diagnoseInstalledGeneratedAutomaticClose(t, ctx, f.open(t, ctx))
					t.Fatal("interrupted auto retirement did not retain the original nonterminal apply", deleteAdmissions, got.Result)
				}
				cold := f.open(t, ctx)
				assertGeneratedReceiptOrder(t, ctx, cold, windows.Order)
				if cold.root.Generated.ActiveOwner != operation {
					t.Fatal("cold open lost the selected apply Parent")
				}
				creates, deletes := effects()
				expectedEntered := 0
				if tc.stop == "adoption" || tc.stop == "store" {
					expectedEntered = 1
					work := mustSelectedGeneratedWork(t, cold)
					attempt, present := work.attempts[work.phase.FrontierAttemptID]
					if !present || attempt.record.State != contract.GeneratedEffectTransmitted || attempt.expected.Template.Action != contract.GeneratorActionDelete {
						t.Fatal("interrupted delete lost its transmitted reservation")
					}
				}
				if tc.stop == "second_producer" {
					expectedEntered = 1
					work := mustSelectedGeneratedWork(t, cold)
					scope, err := generatedAutomaticInvocationScope(ctx, cold, work)
					if err != nil {
						t.Fatal(err)
					}
					facts, err := generatedInvocationFacts(ctx, work, scope, scope.Effects, scope.Duties, scope.Hazards)
					if err != nil {
						t.Fatal("cold after first auto close facts", err)
					}
					for _, effect := range facts.Effects {
						if effect.Action == contract.GeneratorActionDelete {
							want := old[effect.Name]
							if effect.Target == nil || effect.Target.ResourceDigest != want.Generated.ResourceDigest || effect.Target.ResourceID != want.Generated.ResourceIncarnationID || effect.Target.IncarnationID != want.Incarnation || effect.Target.LifecycleMode != want.Generated.LifecycleMode || effect.Target.ConfigContractID != want.Generated.ConfigContractID || effect.Target.ResourceContractID != want.Generated.ResourceContractID {
								t.Fatal("cold completed delete lost exact target")
							}
						}
					}
				}
				if creates != 2*len(tc.modes) || len(deletes) != expectedEntered {
					t.Fatal("cold reconstruction changed entered effects", creates, deletes)
				}
				resumeCallbacks := installedGeneratedRetirementCallbacks(t, f, process)
				resumeProducer := resumeCallbacks.AdmitProducer
				resumeCallbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, c contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
					if in.Expected.Template.Action == contract.GeneratorActionDelete {
						deleteAdmissions++
					}
					return resumeProducer(ctx, q, c, in, implementation, deadline)
				}
				if tc.stop == "adoption" {
					resumeCallbacks.AdmitProducer = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedProducerInput, contract.GeneratorImplementation, time.Time) (*InstalledGeneratedProducerCustody, error) {
						t.Fatal("cold continuation restored an already transmitted first send")
						return nil, contract.ErrRecord
					}
				}
				resumed := installedGeneratedRetirementEngine(t, ctx, f, cold, resumeCallbacks)
				completed := resumed.Continue(ctx, testID(tc.name+" exact apply continuation"), operation)
				resumed.Close()
				if completed.OperationID != operation || completed.RequestIdentity != got.RequestIdentity {
					t.Fatal("continuation replaced the accepted apply identity")
				}
				got = completed
			}
			creates, deletes := effects()
			slices.Sort(deletes)
			if got.Result.Outcome != ObservedCurrent || creates != 2*len(tc.modes) || !slices.Equal(deletes, expectedDeletes) || deleteAdmissions != len(expectedDeletes)+boolInt(tc.stop == "producer" || tc.stop == "second_producer") {
				diagnoseInstalledGeneratedAutomaticClose(t, ctx, f.open(t, ctx))
				t.Fatal("rotation did not execute only its requested automatic retirements", got.Result, creates, deletes, deleteAdmissions)
			}
			closed := f.open(t, ctx)
			if !closed.root.Generated.ActiveOwner.IsZero() || got.Generated == nil || !got.Generated.EffectsAvailable || !got.Generated.RelatedWorkAvailable ||
				!slices.Equal(got.Generated.RelatedDutyIDs, expectedDuties) || len(got.Generated.Effects) != len(tc.modes)+len(expectedDeletes) {
				diagnoseInstalledGeneratedAutomaticClose(t, ctx, f.open(t, ctx))
				t.Fatal("terminal apply lost its complete create/delete vector or manual obligations")
			}
			type expectedEffect struct {
				name   string
				action uint8
			}
			var requestedNames []string
			requestedModes := make(map[string]uint8, len(tc.modes))
			for at, mode := range tc.modes {
				name := fmt.Sprintf("generated-%d", at)
				requestedNames = append(requestedNames, name)
				requestedModes[name] = mode
			}
			slices.Sort(requestedNames)
			var expectedEffects []expectedEffect
			for _, name := range requestedNames {
				expectedEffects = append(expectedEffects, expectedEffect{name, contract.GeneratorActionCreate})
				if requestedModes[name] == contract.GeneratedRetirementAuto {
					expectedEffects = append(expectedEffects, expectedEffect{name, contract.GeneratorActionDelete})
				}
			}
			for at, effect := range got.Generated.Effects {
				want := expectedEffects[at]
				if effect.Action == contract.GeneratorActionDelete {
					want := old[effect.Name]
					if effect.Target == nil || effect.Target.Name != want.Name || effect.Target.ResourceDigest != want.Generated.ResourceDigest || effect.Target.ResourceID != want.Generated.ResourceIncarnationID || effect.Target.IncarnationID != want.Incarnation || effect.Target.LifecycleMode != want.Generated.LifecycleMode || effect.Target.ConfigContractID != want.Generated.ConfigContractID || effect.Target.ResourceContractID != want.Generated.ResourceContractID {
						t.Fatal("terminal delete lost exact displaced target", at)
					}
				}
				if effect.Name != want.name || effect.Action != want.action || effect.Record.OperationID != got.OperationID || effect.Record.State != contract.GeneratedEffectSucceeded {
					t.Fatal("terminal effects changed original apply identity or graph order", at)
				}
			}
			if got.Payload == nil || !slices.Equal(got.Payload.LiveDutyIDs, expectedDuties) || len(got.Payload.LiveHazardIDs) != 0 {
				t.Fatal("terminal payload lost complete domain live work")
			}
			for name, prior := range old {
				_, current := observeCurrentValueEntry(t, closed, name)
				if current.Generated.Epoch != 1 || current.Generated.GenerationID == prior.Generated.GenerationID || current.Generated.OriginOperationID != got.OperationID {
					t.Fatal("retirement changed its selected successor", name)
				}
			}
			_, healthy := observeCurrentValueEntry(t, closed, "healthy")
			if !bytes.Equal(healthy.ValueBytes, input[0].InputBytes) {
				t.Fatal("retirement changed the supplied sibling")
			}
			receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
			if err != nil || receipt.OperationID != got.OperationID || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.SummaryCounts[contract.ReceiptEffectCount] != uint32(len(tc.modes)+len(expectedDeletes)) || receipt.SummaryCounts[contract.ReceiptDutyCount] != uint32(len(expectedDuties)) || receipt.AcknowledgedCount != uint32(len(expectedDeletes)) {
				t.Fatal("one original apply receipt did not commit the complete terminal result", err, receipt)
			}
			if len(expectedDeletes) != 0 && (!got.Generated.Warnings.InvalidationNotConfirmed || receipt.WarningBits&contract.ReceiptWarningInvalidationNotConfirmed == 0) {
				t.Fatal("automatic retirement lost its acknowledgement ceiling")
			}
			afterWindows, err := closed.receiptWindows(ctx)
			if err != nil || len(afterWindows.Successes) != len(windows.Successes)+1 || len(afterWindows.Failures) != len(windows.Failures) || !reflect.DeepEqual(afterWindows.Successes[:len(windows.Successes)], windows.Successes) {
				t.Fatal("enclosed retirement added a separate receipt or replaced prior receipts", err)
			}
			assertSuccessReceiptOrder(t, windows, afterWindows, got.OperationID)
			observer := installedGeneratedRetirementEngine(t, ctx, f, closed, nil)
			observed := observer.Continue(ctx, testID(tc.name+" terminal apply observation"), got.OperationID)
			observer.Close()
			if observed.Generated == nil || !observed.Generated.ReceiptObservation || !bytes.Equal(observed.Receipt, got.Receipt) {
				t.Fatal("terminal observation changed the original apply receipt")
			}
			assertGeneratedReceiptOrder(t, ctx, f.open(t, ctx), afterWindows.Order)
			_, observedDeletes := effects()
			slices.Sort(observedDeletes)
			if !slices.Equal(observedDeletes, expectedDeletes) {
				t.Fatal("terminal observation sent another delete")
			}
		})
	}
}

// Diagnose only the stopped selected state. Derivation and capture do not sign,
// select, invoke a provider, or retry the failed operation.
func diagnoseInstalledGeneratedAutomaticClose(t *testing.T, ctx context.Context, state *StateSession) {
	t.Helper()
	work, err := state.selectedGeneratedWork(ctx)
	if err != nil {
		t.Log("automatic close selected work:", err)
		return
	}
	if !generatedSelectionAnchored(work) {
		diagnoseInstalledGeneratedBeforeAutomaticSelection(t, ctx, state, work)
		return
	}
	scope, err := generatedAutomaticInvocationScope(ctx, state, work)
	if err != nil {
		t.Log("automatic close observed scope:", err)
		return
	}
	facts, err := generatedInvocationFacts(ctx, work, scope, scope.Effects, scope.Duties, scope.Hazards)
	if err != nil {
		t.Log("automatic close observed facts:", err)
		return
	}
	admitted, err := installedGeneratedContext(state, time.Now().Add(time.Minute))
	if err != nil {
		t.Log("automatic close context:", err)
		return
	}
	plan, err := state.generatedAutomaticClosePlan(ctx, admitted)
	if err != nil {
		t.Log("automatic close plan:", err)
		return
	}
	proposal, err := state.deriveGeneratedLifecycle(ctx, plan, nil)
	if err != nil {
		t.Log("automatic close candidate derivation:", err)
		return
	}
	selected, err := proposal.state.selectedGeneratedWork(ctx)
	if err != nil {
		t.Log("automatic close candidate selected work:", err)
		return
	}
	_, _, terminal, err := proposal.state.retainedMutationReceipt(scope.OperationID)
	if err != nil {
		t.Log("automatic close candidate receipt:", err)
		return
	}
	var checkpoint generatedSelectionCheckpoint
	checkpoint.rememberObserved(state, PublicApplyResult{OperationID: scope.OperationID, Generated: &facts})
	if terminal {
		_, err = captureGeneratedFinalInvocationResult(ctx, state, work, &generatedFinalPlan{}, proposal, &checkpoint)
	} else {
		selectedScope, scopeErr := generatedCurrentResultScope(ctx, proposal.state, selected)
		if scopeErr != nil {
			t.Log("automatic close candidate scope:", scopeErr)
			return
		}
		if _, factsErr := generatedInvocationFacts(ctx, selected, selectedScope, selectedScope.Effects, selectedScope.Duties, selectedScope.Hazards); factsErr != nil {
			t.Log("automatic close candidate facts:", factsErr)
			return
		}
		_, err = captureGeneratedSelectionStep(ctx, state, work, proposal, &checkpoint)
	}
	t.Log("automatic close candidate capture:", err)
}

func diagnoseInstalledGeneratedBeforeAutomaticSelection(t *testing.T, ctx context.Context, state *StateSession, work *generatedSelection) {
	t.Helper()
	t.Logf("automatic selection stopped before anchor: parent=%t phase=%t", work.parent != nil, work.phase != nil)
	if work.parent == nil || work.phase == nil {
		return
	}
	t.Logf("automatic selection retained stage=%d phase=%d preparation=%t", work.phase.Stage, work.phase.Phase, work.preparation != nil)
	if work.phase.Stage != contract.GeneratedStageTerminal {
		return
	}
	admitted, err := installedGeneratedContext(state, time.Now().Add(time.Minute))
	if err != nil {
		t.Log("automatic selection context:", err)
		return
	}
	plan, err := state.generatedFinalRequest(ctx, admitted)
	if err != nil {
		t.Log("automatic selection final request:", err)
		return
	}
	defer plan.clearOwnedInputs()
	if _, err := state.installedGeneratedFinalInput(ctx, work, plan); err != nil {
		t.Log("automatic selection final input:", err)
		return
	}
	if plan.materialization == nil {
		t.Log("automatic selection has no retained final materialization")
		return
	}
	prepared, err := state.generatedFinalPreparationImage(ctx, work)
	if err != nil {
		t.Log("automatic selection retained materialization:", err)
		return
	}
	defer prepared.Clear()
	proposal, err := state.deriveGeneratedFinal(ctx, plan, prepared.Generated, prepared.Supplied)
	if err != nil {
		t.Log("automatic selection candidate derivation:", err)
		return
	}
	if _, err := state.installedGeneratedCandidate(ctx, proposal, plan); err != nil {
		t.Log("automatic selection candidate input:", err)
		return
	}
	var checkpoint generatedSelectionCheckpoint
	_, err = captureGeneratedSelectionStep(ctx, state, work, proposal, &checkpoint)
	t.Log("automatic selection candidate capture:", err)
}

// This delegate observes only the original private call's closed stage/code.
// It neither repeats an exchange nor retains its request or response bodies.
type automaticFinalDiagnosticCrypto struct {
	contract.Crypto
	t        testing.TB
	prepared bool
}

func (c *automaticFinalDiagnosticCrypto) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	response := c.Crypto.Exchange(ctx, q)
	c.t.Log("automatic Final exchange", "preparation", c.prepared, "kind", q.Kind, "code", response.ResultCode)
	return response
}
