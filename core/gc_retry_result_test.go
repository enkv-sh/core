package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCRetryableWitnessSurvivesObservationOnlyContinue(t *testing.T) {
	for _, observation := range []string{"changed", "unavailable"} {
		t.Run(observation, func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			store.onDelete = func(string, contract.Token) *contract.WriteResult {
				return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport, NotSent: true}
			}
			engine, _ := gcExecutionEngine(t, state, store, input)
			first := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("retry-witness-first"), EncodedPlan: encoded})
			if first.Payload == nil || !first.Payload.Closed || first.Payload.Targets[0].Selected.Disposition != contract.GCTargetRetryableNotSent {
				t.Fatal("real joined NotSent witness was not selected", first.Result, first.Payload)
			}
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
			before := first.Payload.Targets[0].Selected
			ordinal := first.Payload.ProgressOrdinal
			deletes := len(store.deletes)
			phaseOffset := len(store.phases)
			key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
			store.onRead = func(actual string) *contract.ReadResult {
				if actual != key {
					return nil
				}
				if observation == "unavailable" {
					return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				}
				return &contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(store.objects[key]), Token: contract.Token{Family: contract.GCP, Value: "999"}}
			}
			resume, _ := gcExecutionEngine(t, state, store, input)
			out := resume.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("retry-witness-observation-only"), OperationID: plan.OperationID})
			if out.Payload == nil || !out.Payload.Closed || out.Payload.Targets[0].Selected != before || out.Payload.ProgressOrdinal != ordinal {
				t.Fatal("observation-only continuation discarded selected retry witness", observation, out.Result, out.Payload, before, ordinal)
			}
			if len(store.deletes) != deletes || !reflect.DeepEqual(store.phases[phaseOffset:], []contract.GCPhase{contract.GCReacquire, contract.GCClose}) {
				t.Fatal("observation-only continuation reserved or changed durable progress", store.phases[phaseOffset:], store.deletes)
			}
		})
	}
}

// full_only: false
func TestGCTerminalFailureSurvivesObservationOnlyContinue(t *testing.T) {
	for _, observation := range []string{"matching", "changed", "unavailable", "absent"} {
		t.Run(observation, func(t *testing.T) {
			state, store, input, plan, encoded := gcExecutionFixture(t)
			ctx := gcReadContext(t)
			refusal := contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess}
			store.onDelete = func(string, contract.Token) *contract.WriteResult { return &refusal }
			engine, _ := gcExecutionEngine(t, state, store, input)
			first := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("terminal-failure-first"), EncodedPlan: encoded})
			terminal := contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetTerminalFailure}
			if first.Payload == nil || !first.Payload.Closed || first.Payload.Active || len(first.Payload.Targets) != 1 {
				t.Fatal("refused delete did not close with retained work", first)
			}
			row := first.Payload.Targets[0]
			if row.Selected != terminal || !row.PermissionOwned || !row.DeleteAttempted || row.DeleteResult != refusal || row.Observed != contract.GCTargetPending || row.ObservationReason != contract.ReasonNone || !row.ObservedEvidence.IsZero() {
				t.Fatal("qualified refusal did not select the exact terminal failure", row)
			}
			if first.Payload.ProgressOrdinal != 3 || first.Payload.RemainingCount != 1 || first.StateResult != "gc-partial-garbage" || first.SummaryCounts != ([4]uint32{0, 1, 0, 0}) || first.EffectSummary != contract.ReceiptEffectFailed {
				t.Fatal("terminal failure lost its progress or summary", first)
			}
			if err := first.Validate(); err != nil {
				t.Fatal("initial terminal failure result is invalid", err)
			}
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
			key := gcObjectTestKey(t, store.Descriptor(), state.root.Domain, plan.Targets[0].Object)
			if !reflect.DeepEqual(store.phases, []contract.GCPhase{contract.GCSelect, contract.GCReserve, contract.GCRecordProgress, contract.GCClose}) || !reflect.DeepEqual(store.deletes, []gcDeleteCall{{key, plan.Targets[0].Token}}) {
				t.Fatal("initial refusal changed the exact dispatch inventory", store.phases, store.deletes)
			}
			phaseOffset := len(store.phases)
			store.onRead = func(actual string) *contract.ReadResult {
				if actual != key {
					return nil
				}
				switch observation {
				case "changed":
					return &contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(store.objects[key]), Token: contract.Token{Family: contract.GCP, Value: "999"}}
				case "unavailable":
					return &contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				case "absent":
					return &contract.ReadResult{Status: contract.ReadMissing}
				}
				return nil
			}
			resume, _ := gcExecutionEngine(t, state, store, input)
			out := resume.Continue(ctx, GCContinueRequest{RequestNonce: gcTestID("terminal-failure-observation-only"), OperationID: plan.OperationID})
			if out.Payload == nil || !out.Payload.Closed || out.Payload.Active || len(out.Payload.Targets) != 1 {
				t.Fatal("observation-only continuation did not close", out)
			}
			row = out.Payload.Targets[0]
			if row.Object != plan.Targets[0].Object || row.Length != plan.Targets[0].Length || row.Digest != plan.Targets[0].Digest || out.OperationID != first.OperationID || out.RequestIdentity != first.RequestIdentity || out.Payload.PlanDigest != first.Payload.PlanDigest || out.Payload.RequestIdentity != first.Payload.RequestIdentity || out.Payload.TargetsDescriptor != first.Payload.TargetsDescriptor || out.Payload.MarkDigest != first.Payload.MarkDigest || out.Payload.EnumerationDigest != first.Payload.EnumerationDigest {
				t.Error("continuation changed the original target or plan commitments", first.Payload, out.Payload)
			}
			if row.PermissionOwned || row.DeleteAttempted || row.DeleteResult != (contract.WriteResult{}) || len(store.deletes) != 1 {
				t.Error("observation-only continuation acquired or dispatched another permission", row, store.deletes)
			}
			wantObserved, wantReason := contract.GCTargetPending, contract.ReasonNone
			wantSelected, wantOrdinal, wantRemaining := terminal, uint32(3), uint16(1)
			wantPhases := []contract.GCPhase{contract.GCReacquire, contract.GCClose}
			wantToken, wantState, wantEffect, wantCounts := "failed-terminal", "gc-partial-garbage", uint16(contract.ReceiptEffectFailed), [4]uint32{0, 1, 0, 0}
			switch observation {
			case "changed":
				wantObserved, wantReason = contract.GCTargetChanged, contract.ReasonCondition
			case "unavailable":
				wantObserved, wantReason = contract.GCTargetUnknown, contract.ReasonAccess
			case "absent":
				wantObserved = contract.GCTargetAbsent
				// Derive the expected preimage from original fixture facts without
				// calling the production descriptor, target or evidence encoders.
				descriptor := store.Descriptor()
				profileImage := append([]byte("ENKV/store-descriptor/v1\x00"), byte(descriptor.Family))
				profileImage = binary.LittleEndian.AppendUint32(profileImage, uint32(len(descriptor.Prefix)))
				profileImage = append(profileImage, descriptor.Prefix...)
				profileImage = binary.LittleEndian.AppendUint32(profileImage, uint32(len(descriptor.HeadKey)))
				profileImage = append(profileImage, descriptor.HeadKey...)
				profileImage = append(profileImage, descriptor.Identity[:]...)
				profileImage = append(profileImage, descriptor.Coordinate[:]...)
				profileImage = append(profileImage, descriptor.NonBody[:]...)
				profileDigest := sha256.Sum256(profileImage)
				target := plan.Targets[0]
				image := append([]byte("ENKV/GC-ABSENCE/v1\x00"), profileDigest[:]...)
				image = append(image, plan.DomainID[:]...)
				image = append(image, plan.OperationID[:]...)
				image = binary.BigEndian.AppendUint32(image, 3)
				image = append(image, byte(target.Object.Namespace), byte(target.Object.Kind))
				image = binary.BigEndian.AppendUint16(image, target.Object.Index)
				image = append(image, target.Object.ObjectID[:]...)
				image = binary.BigEndian.AppendUint32(image, target.Length)
				image = append(image, target.Digest[:]...)
				image = append(image, byte(target.Token.Family))
				image = binary.BigEndian.AppendUint32(image, uint32(len(target.Token.Value)))
				image = append(image, target.Token.Value...)
				image = append(image, 2, 0) // Qualified ReadMissing and ReasonNone.
				absence := contract.ID(sha256.Sum256(image))
				if row.ObservedEvidence != absence {
					t.Error("absence evidence changed the original target, token or selected ordinal", row.ObservedEvidence, absence)
				}
				wantSelected = contract.GCTargetProgress{Consumed: 1, Disposition: contract.GCTargetAbsent, EvidenceDigest: absence}
				wantOrdinal, wantRemaining = 4, 0
				wantPhases = []contract.GCPhase{contract.GCReacquire, contract.GCRecordProgress, contract.GCClose}
				wantToken, wantState, wantEffect, wantCounts = "succeeded", "success", contract.ReceiptEffectComplete, [4]uint32{1, 0, 0, 0}
			}
			if row.Observed != wantObserved || row.ObservationReason != wantReason || row.ObservedEvidence.IsZero() != (observation != "absent") {
				t.Error("continuation lost the separate exact observation", row, wantObserved, wantReason)
			}
			if row.Selected != wantSelected || out.Payload.ProgressOrdinal != wantOrdinal || out.Payload.RemainingCount != wantRemaining || !reflect.DeepEqual(store.phases[phaseOffset:], wantPhases) {
				t.Error("observation-only continuation rewrote retained progress", row.Selected, out.Payload.ProgressOrdinal, out.Payload.RemainingCount, store.phases[phaseOffset:])
			}
			if token, err := GCTargetEffectToken(row); err != nil || token != wantToken {
				t.Error("continuation lost the selected effect evidence", token, err)
			}
			if out.StateResult != wantState || out.EffectSummary != wantEffect || out.SummaryCounts != wantCounts || out.Payload.SiblingResults.Count != 1 || out.Payload.SiblingResults.RootDigest.IsZero() {
				t.Error("continuation lost the exact summary or sibling commitment", out)
			}
			if err := out.Validate(); err != nil {
				t.Error("continuation result or sibling commitment is invalid", err)
			}
			current := gcOpenRuntime(t, ctx, input, store)
			if !current.root.ActiveGC.IsZero() {
				t.Error("continuation left the active slot occupied")
			}
			selectedPlan, progress, err := current.selectedGCPlan(plan.OperationID)
			if observation == "absent" {
				if err == nil {
					t.Error("qualified absence retained the completed obligation")
				}
			} else if err != nil || !reflect.DeepEqual(selectedPlan, plan) || progress.Ordinal != 3 || progress.RemainingCount != 1 || !reflect.DeepEqual(progress.Targets, []contract.GCTargetProgress{terminal}) {
				t.Error("durable continuation changed the original plan or terminal progress", err, selectedPlan, progress)
			}
		})
	}
}

// full_only: false
func TestGCReserveContentionRetainsRequestedRevision(t *testing.T) {
	state, store, input, _, encoded := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	var attempted contract.ID
	store.onCAS = func(phase contract.GCPhase, body []byte) *contract.WriteResult {
		if phase != contract.GCReserve {
			return nil
		}
		head, err := format.DecodeHead(body)
		if err != nil {
			t.Fatal(err)
		}
		attempted = head.Core.Revision
		return &contract.WriteResult{Status: contract.WritePrecondition, Reason: contract.ReasonCondition}
	}
	engine, _ := gcExecutionEngine(t, state, store, input)
	out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("reserve-requested-revision"), EncodedPlan: encoded})
	if attempted.IsZero() || out.Payload == nil || len(out.Payload.Failures) != 1 || out.Payload.Failures[0].Phase != contract.GCReserve || out.Payload.Failures[0].Result.RequestedRevision != attempted || out.Result.RequestedRevision != attempted {
		t.Fatal("reserve contention lost attempted candidate correlation", attempted, out.Result, out.Payload)
	}
	if len(store.deletes) != 0 {
		t.Fatal("contended reserve dispatched deletion")
	}
}

// full_only: false
func TestGCMalformedWriteTuplesRemainRenderableAndCannotGrantEffects(t *testing.T) {
	for _, boundary := range []string{"cas", "delete"} {
		for _, tuple := range []contract.WriteResult{{Status: contract.WritePrecondition, Reason: contract.ReasonTransport}, {Status: contract.WriteConflict, Reason: contract.ReasonCondition, NotSent: true}, {Status: contract.WriteAcknowledged, Reason: contract.ReasonTransport}, {Status: 255, Reason: 255}} {
			t.Run(fmt.Sprintf("%s/status-%d/reason-%d/not-sent-%t", boundary, tuple.Status, tuple.Reason, tuple.NotSent), func(t *testing.T) {
				state, store, input, _, encoded := gcExecutionFixture(t)
				ctx := gcReadContext(t)
				if boundary == "cas" {
					store.onCAS = func(phase contract.GCPhase, _ []byte) *contract.WriteResult {
						if phase == contract.GCReserve {
							return &tuple
						}
						return nil
					}
				} else {
					store.onDelete = func(string, contract.Token) *contract.WriteResult { return &tuple }
				}
				engine, _ := gcExecutionEngine(t, state, store, input)
				out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: gcTestID("malformed-write-tuple"), EncodedPlan: encoded})
				want := contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonMalformed}
				if out.Payload == nil {
					t.Fatal("malformed result lost admitted facts", out.Result)
				}
				if boundary == "cas" {
					if len(out.Payload.Failures) != 1 || out.Payload.Failures[0].Write != want || len(store.deletes) != 0 || len(store.phases) != 2 {
						t.Fatal("malformed CAS tuple granted effects or lost safe malformation", tuple, out.Result, out.Payload, store.phases)
					}
				} else if out.Payload.Targets[0].DeleteResult != want || len(store.deletes) != 1 || out.Payload.Targets[0].Selected.Disposition == contract.GCTargetRetryableNotSent {
					t.Fatal("malformed delete tuple became success or retry authority", tuple, out.Result, out.Payload)
				}
				if err := out.Validate(); err != nil {
					t.Fatal("possibly effectful malformed result cannot be rendered", err, out)
				}
			})
		}
	}
}
