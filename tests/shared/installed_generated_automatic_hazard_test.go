package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledGeneratedAutomaticTerminalPreservesEarlierCreateHazard(t *testing.T) {
	for _, mode := range []string{"acknowledged", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "create-hazard-"+mode)
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
				Recipients: []contract.ID{f.selected.admission.recipient},
				Generated: &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
					LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
					ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
					CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}}}
			initial := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			first := initial.Apply(ctx, testID("hazard automatic initial "+mode), input)
			initial.Close()
			if first.Result.Outcome != ObservedCurrent {
				t.Fatal("initial generation was not selected", first.Result)
			}
			before := f.open(t, ctx)
			_, old := observeCurrentValueEntry(t, before, "generated")
			oldToken := generatedEntryProviderToken(t, before, old)
			windows, err := before.receiptWindows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			input[0].Generated.Epoch, input[0].Generated.RetirementMode = 1, contract.GeneratedRetirementAuto
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			producer := callbacks.AdmitProducer
			var original generatedAttempt
			var hazard contract.GeneratedHazardRecord
			var graph contract.GeneratorPlanBundle
			var preserved []contract.SupportRecord
			var current contract.ConsumerSelection
			var seed contract.AccessRecord
			var deleteAttempt contract.ID
			deleteAdmissions := 0
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				if in.Expected.Template.Action == contract.GeneratorActionDelete {
					deleteAdmissions++
					deleteAttempt = in.Expected.Template.AttemptID
					selected := f.open(t, ctx)
					work := mustSelectedGeneratedWork(t, selected)
					if !generatedSelectionAnchored(work) || selected.root.Generated.Hazards != 1 {
						t.Fatal("automatic delete did not follow selected successor and one earlier Hazard")
					}
					for _, row := range work.records {
						if row.Kind == contract.GeneratedHazardSupportKind {
							hazard, err = contract.InspectGeneratedHazardRecord(row.Body)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					original = work.attempts[hazard.OriginalAttemptID]
					if hazard.Exposure != contract.GeneratedExposurePossibleLive || hazard.Fenced != 1 || original.record.State != contract.GeneratedEffectClosedWithResidue || len(original.result) != 0 {
						t.Fatalf("earlier CREATE must retain possible-live uncertainty: exposure=%d fenced=%d state=%d result_present=%t", hazard.Exposure, hazard.Fenced, original.record.State, len(original.result) != 0)
					}
					graph, err = work.retainedGraph(hazard.OriginalOperationID)
					if err != nil {
						t.Fatal(err)
					}
					for _, row := range selected.supportRecords() {
						keep := row.Kind == contract.GeneratedHazardSupportKind && row.RecordID == hazard.HazardID ||
							row.Kind == contract.GeneratedAttemptSupportKind && row.RecordID == original.record.AttemptID ||
							row.Kind == contract.GeneratedResultSupportKind && row.RecordID == original.record.ResultID ||
							row.Kind == contract.OperationMaterialSupportKind && row.RecordID == work.parent.MaterialID
						if row.Kind == contract.GeneratorVectorSupportKind {
							vector, e := contract.InspectGeneratorVectorCarrier(row.Body)
							if e != nil {
								t.Fatal(e)
							}
							keep = vector.OwnerID == original.record.AttemptID || vector.OwnerID == hazard.HazardID ||
								vector.OwnerID == work.parent.OperationID && vector.VectorKind == contract.GeneratorVectorSupport
						}
						if keep {
							preserved = append(preserved, row)
						}
					}
					seed = *generatedFixtureMaterialAccess(t, selected, contract.OperationSeedMaterialKind, work.parent.MaterialID)
					current = sessionConsumerSelection(t, selected, selected.admission.recipient, "generated")
				}
				return producer(ctx, q, control, in, implementation, deadline)
			}
			engine := installedGeneratedTestEngine(t, ctx, f, before, input, currentApplyRecipients(before.registry()), callbacks)
			got := engine.Apply(ctx, testID("hazard automatic rotation "+mode), input)
			engine.Close()
			creates, deletes := effects()
			if deleteAdmissions != 1 || creates != 3 || !slices.Equal(deletes, []string{oldToken}) {
				t.Fatal("rotation did not enter exactly initial CREATE, uncertain CREATE, successor CREATE and old DELETE", creates, len(deletes), deleteAdmissions)
			}
			if got.Result.Outcome != ObservedCurrent || len(got.Receipt) == 0 {
				diagnoseInstalledGeneratedAutomaticClose(t, ctx, f.open(t, ctx))
				t.Fatal("last automatic transition did not validate and close with the earlier CREATE Hazard", got.Result)
			}
			wantDuties, wantUnknown, wantAcknowledged := 0, uint32(1), uint32(1)
			wantState, wantReceiptState := "success", uint16(contract.ReceiptStateSuccess)
			if mode == "unknown" {
				wantDuties, wantUnknown, wantAcknowledged = 1, 2, 0
				wantState, wantReceiptState = "retirement-pending", contract.ReceiptStateRetirementPending
			}
			if got.Generated == nil || got.Generated.StateResult != wantState || got.Generated.CanonicalOutcome != contract.ReceiptCanonicalSelected ||
				len(got.Generated.Effects) != 3 || len(got.Generated.Duties) != wantDuties || len(got.Generated.Hazards) != 1 ||
				got.Generated.UnknownCount != wantUnknown || got.Generated.AcknowledgedCount != wantAcknowledged || !got.Generated.Warnings.PossibleLiveResidue ||
				!slices.Equal(got.Generated.RelatedHazardIDs, []contract.ID{hazard.HazardID}) {
				t.Fatal("terminal result changed entered effects, uncertainty or surviving obligations")
			}
			for at, effect := range got.Generated.Effects {
				wantAction, wantEffectState := uint8(contract.GeneratorActionCreate), uint8(contract.GeneratedEffectSucceeded)
				if at == 0 {
					wantEffectState = contract.GeneratedEffectClosedWithResidue
					if effect.Record != original.record || effect.Record.ResultID != original.expected.Template.ResultID {
						t.Fatal("terminal effects replaced the uncertain original CREATE")
					}
				}
				if at == 2 {
					wantAction = contract.GeneratorActionDelete
					if mode == "unknown" {
						wantEffectState = contract.GeneratedEffectUnknown
					}
					if effect.Target == nil || effect.Target.ResourceID != old.Generated.ResourceIncarnationID || effect.Target.ResourceDigest != old.Generated.ResourceDigest {
						t.Fatal("terminal DELETE changed its displaced-resource target")
					}
				}
				if effect.Name != "generated" || effect.Action != wantAction || effect.Record.State != wantEffectState || effect.Record.OperationID != got.OperationID {
					t.Fatal("terminal effects changed exact graph order, original operation or outcome", at)
				}
			}
			receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
			if err != nil || receipt.OperationID != got.OperationID || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.StateResult != wantReceiptState ||
				receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected || receipt.SummaryCounts[contract.ReceiptEffectCount] != 3 ||
				receipt.SummaryCounts[contract.ReceiptDutyCount] != uint32(wantDuties) || receipt.SummaryCounts[contract.ReceiptHazardCount] != 1 ||
				receipt.UnknownCount != wantUnknown || receipt.AcknowledgedCount != wantAcknowledged || receipt.WarningBits&contract.ReceiptWarningPossibleLive == 0 {
				t.Fatal("terminal receipt lost the exact parent outcome", err)
			}
			closed := f.open(t, ctx)
			if !closed.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("terminal automatic transition retained the active parent")
			}
			work := mustSelectedGeneratedWork(t, closed)
			wantAttempts := []contract.ID{original.record.AttemptID}
			if mode == "unknown" {
				wantAttempts = append(wantAttempts, deleteAttempt)
			}
			if len(work.attempts) != len(wantAttempts) {
				t.Fatal("terminal pruning retained ended CREATE work or lost a surviving owner", len(work.attempts))
			}
			for _, id := range wantAttempts {
				if _, present := work.attempts[id]; !present {
					t.Fatal("terminal pruning omitted a surviving owner's Attempt")
				}
			}
			for _, want := range preserved {
				if actual, ok := work.records[generatedRecordKey{want.Kind, want.RecordID}]; !ok || !bytes.Equal(actual.Body, want.Body) {
					t.Fatal("terminal pruning changed a live Hazard dependency", want.Kind)
				}
			}
			retainedGraph, err := work.retainedGraph(hazard.OriginalOperationID)
			if err != nil || !reflect.DeepEqual(retainedGraph, graph) {
				t.Fatal("terminal pruning changed the original immutable graph", err)
			}
			if !reflect.DeepEqual(work.attempts[original.record.AttemptID], original) {
				t.Fatal("terminal pruning changed the exact original Attempt, result expectation or material")
			}
			if !reflect.DeepEqual(*generatedFixtureMaterialAccess(t, closed, contract.OperationSeedMaterialKind, seed.MaterialID), seed) {
				t.Fatal("terminal pruning changed original seed access or readers")
			}
			currentAfter := sessionConsumerSelection(t, closed, closed.admission.recipient, "generated")
			if !reflect.DeepEqual(currentAfter.Access, current.Access) {
				t.Fatal("terminal pruning changed current value access")
			}
			wantCurrent := current.Entry
			if mode == "acknowledged" {
				wantCurrent.Generated.RetiringDutyPresent = 0
				wantCurrent.Generated.RetiringDutyID = contract.ID{}
			}
			if !reflect.DeepEqual(currentAfter.Entry, wantCurrent) {
				t.Fatal("terminal transition changed current value beyond its exact retirement-pointer update")
			}
			captureDir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(captureDir, 0700); err != nil {
				t.Fatal("private current-value oracle directory", err)
			}
			capturePath := filepath.Join(captureDir, "current-value")
			if read := f.keys.CaptureSelected(ctx, currentAfter, capturePath); read.Code != contract.CryptoSuccess || read.Delivery != 1 || !read.ValueMatched || read.SinkCalls != 1 {
				t.Fatalf("current successor cannot be consumed: code=%d delivery=%d matched=%t sink_calls=%d", read.Code, read.Delivery, read.ValueMatched, read.SinkCalls)
			}
			plain, err := os.ReadFile(capturePath)
			if err != nil || !bytes.Equal(plain, []byte(hermeticCloudflareSecret)) {
				t.Fatal("current successor bytes changed", err)
			}
			clear(plain)
			afterWindows, err := closed.receiptWindows(ctx)
			if err != nil {
				t.Fatal(err)
			}
			assertSuccessReceiptOrder(t, windows, afterWindows, got.OperationID)
			cold := installedGeneratedRetirementEngine(t, ctx, f, closed, nil)
			observed := cold.Continue(ctx, testID("hazard automatic cold "+mode), got.OperationID)
			cold.Close()
			if observed.Result.Outcome != ObservedCurrent || observed.Generated == nil || !observed.Generated.ReceiptObservation || !bytes.Equal(observed.Receipt, got.Receipt) {
				t.Fatal("cold continuation did not return the exact terminal receipt")
			}
			input = append(input, ApplyEntryInput{Name: "later", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				Recipients: []contract.ID{closed.admission.recipient}, InputBytes: []byte("permitted later mutation"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			later := f.open(t, ctx)
			next := installedGeneratedTestEngine(t, ctx, f, later, input, currentApplyRecipients(later.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			changed := next.Apply(ctx, testID("hazard automatic subsequent "+mode), input)
			next.Close()
			if changed.Result.Outcome != ObservedCurrent || len(changed.Receipt) == 0 || !f.open(t, ctx).root.Generated.ActiveOwner.IsZero() {
				t.Fatal("surviving Hazard blocked a subsequent permitted mutation", changed.Result)
			}
			laterCreates, laterDeletes := effects()
			if laterCreates != creates || !slices.Equal(laterDeletes, deletes) {
				t.Fatal("cold continuation or later mutation resent an entered effect")
			}
		})
	}
}
