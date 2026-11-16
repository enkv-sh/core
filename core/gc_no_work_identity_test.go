package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"sync/atomic"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGCEmptyApplyBindsFreshObservationAndPreservesPlan(t *testing.T) {
	state, store, input, _, _ := gcExecutionFixture(t)
	ctx := gcReadContext(t)
	var lists, closes atomic.Int32
	root := contract.StoreObjectIdentity{Namespace: contract.StorePageObject, Kind: contract.RootKind, ObjectID: state.root.Snapshot}
	page := contract.ListPageResult{Status: contract.ListPageOK, Keys: []string{gcObjectTestKey(t, store.Descriptor(), state.root.Domain, root), store.Descriptor().Prefix + "/unknown"}, NextCursor: "next-page"}
	input.Construct = func(context.Context, contract.StoreConfiguration) (PublicCapacityReader, Result) {
		return &gcExecutionRead{store: store, page: page, lists: &lists, closes: &closes}, Result{}
	}
	reader, err := NewInstalledCapacityReader(input)
	if err != nil {
		t.Fatal(err)
	}
	preview := reader.PlanGC(ctx, GCPreviewRequest{RequestNonce: gcTestID("empty-observation-preview"), OperationID: gcTestID("empty-observation-operation")})
	reader.Close()
	if preview.Payload == nil || len(preview.Payload.Plan.Targets) != 0 || len(preview.Payload.Plan.Candidates) != 2 || preview.Payload.Plan.NextProviderCursor != page.NextCursor {
		t.Fatal("empty preview lost the bounded page basis", preview.Result)
	}
	plan := preview.Payload.Plan
	encoded := bytes.Clone(preview.Payload.EncodedPlan)
	planDigest := sha256.Sum256(encoded)
	planRequest := sha256.Sum256(append([]byte("ENKV/GC-REQUEST/v1\x00"), planDigest[:]...))
	objects := make(map[string][]byte, len(store.objects))
	for key, body := range store.objects {
		objects[key] = bytes.Clone(body)
	}
	headGeneration := store.headGeneration
	var results [2]PublicGCResult
	for i, nonce := range []contract.ID{gcTestID("empty-observation-first"), gcTestID("empty-observation-second")} {
		engine, factories := gcExecutionEngine(t, state, store, input)
		out := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: nonce, EncodedPlan: encoded})
		if err := engine.Close(); err != nil {
			t.Fatal("empty engine close", err)
		}
		if out.Payload == nil {
			t.Fatal("empty apply lost plan payload", out)
		}
		p := out.Payload
		if out.StateResult != "no-op" || out.Result.Outcome != Unchanged || out.Result.Evidence != AuthenticatedClosure || out.Result.CommitMayHaveOccurred || out.EffectSummary != contract.ReceiptEffectNoChange || out.OutputSummary != contract.ReceiptOutputNotApplicable || out.EvidenceCeiling != contract.ReceiptEvidenceCanonical || out.SummaryCounts != [4]uint32{} {
			t.Error("empty current observation changed its result relation", out)
		}
		if out.RequestID != nonce || out.OperationID != plan.OperationID || out.DomainID != plan.DomainID || p.PlanDigest != planDigest || p.RequestIdentity != planRequest || p.MarkDigest != plan.MarkDigest || p.EnumerationDigest != plan.EnumerationDigest || !reflect.DeepEqual(p.Candidates, plan.Candidates) || p.TargetsDescriptor.Count != 0 || len(p.Targets) != 0 || p.RemainingCount != 0 || p.ProgressOrdinal != 0 || p.Active || p.Closed || p.SelectionUncertain || len(p.Failures) != 0 {
			t.Error("fresh empty observation changed the immutable plan or acquired work", out)
		}
		if *factories != 0 || len(store.phases) != 0 || len(store.deletes) != 0 || store.headGeneration != headGeneration || !reflect.DeepEqual(store.objects, objects) || !bytes.Equal(encoded, preview.Payload.EncodedPlan) {
			t.Error("empty observation constructed private resources or changed bytes", *factories, store.phases, store.deletes)
		}
		if err := out.Validate(); err != nil || p.SiblingResults.Count != 0 || p.SiblingResults.RootDigest.IsZero() {
			t.Error("empty sibling result is invalid", err, p.SiblingResults)
		}
		preimage := gcEmptyObservationPreimage(plan, state.head.Core.Root, planRequest, nonce)
		if len(preimage) != 403 || out.RequestIdentity != sha256.Sum256(preimage) {
			t.Errorf("empty observation differs from independent canonical preimage: got %x, want %x, length %d", out.RequestIdentity, sha256.Sum256(preimage), len(preimage))
		}
		results[i] = out
	}
	if lists.Load() != 1 || closes.Load() != 3 {
		t.Error("fresh apply repeated LIST or did not close its public reader", lists.Load(), closes.Load())
	}
	if results[0].RequestIdentity == results[1].RequestIdentity || results[0].RequestIdentity == planRequest || results[1].RequestIdentity == planRequest {
		t.Error("fresh empty observations reused the immutable preview request identity")
	}
	if results[0].Payload.SiblingResults.RootDigest == results[1].Payload.SiblingResults.RootDigest {
		t.Error("sibling results omitted the fresh observation identity and nonce")
	}
	for _, field := range []string{"nonce", "head revision", "snapshot", "root digest"} {
		t.Run("reject changed "+field, func(t *testing.T) {
			changed := results[0]
			payload := *changed.Payload
			changed.Payload = &payload
			switch field {
			case "nonce":
				changed.RequestID = gcTestID("unobserved-nonce")
			case "head revision":
				changed.Result.ObservedRevision = gcTestID("unobserved-head")
				payload.Observation.HeadRevisionID = changed.Result.ObservedRevision
			case "snapshot":
				changed.Result.ObservedSnapshotID = gcTestID("unobserved-snapshot")
				payload.Observation.SnapshotID = changed.Result.ObservedSnapshotID
			case "root digest":
				payload.Observation.RootDigest = gcTestID("unobserved-root")
			}
			if err := RefreshGCResult(&changed); err == nil {
				t.Error("changing observation facts retained a valid no-work identity")
			}
		})
	}
}

// This direct concatenation follows the fixed NoWorkObservationIdentity/v1
// fields. It uses the immutable plan request commitment as RequestCoreDigest
// and the complete empty targets descriptor as the empty-work basis.
func gcEmptyObservationPreimage(plan contract.GCPlan, snapshot contract.Ref, request, nonce contract.ID) []byte {
	condition := []byte("ENKV/CRYPTO-CONDITION/v1\x00")
	condition = append(condition, byte(plan.PredecessorToken.Family))
	condition = binary.BigEndian.AppendUint32(condition, uint32(len(plan.PredecessorToken.Value)))
	condition = append(condition, plan.PredecessorToken.Value...)
	token := sha256.Sum256(condition)
	emptyTargets := sha256.Sum256([]byte("ENKV/GC-TARGETS/v1\x00\x00\x00"))
	body := []byte("ENKV/NO-WORK-OBSERVATION/v1\x00")
	body = binary.BigEndian.AppendUint16(body, 40)
	for _, id := range []contract.ID{plan.OperationID, plan.DomainID, request, plan.HeadRevisionID, plan.FullHEADDigest, token} {
		body = append(body, id[:]...)
	}
	body = append(body, byte(snapshot.Kind))
	body = binary.BigEndian.AppendUint16(body, snapshot.Format)
	for _, id := range []contract.ID{snapshot.Domain, snapshot.Object, snapshot.Digest} {
		body = append(body, id[:]...)
	}
	body = binary.BigEndian.AppendUint32(body, snapshot.Length)
	body = binary.BigEndian.AppendUint16(body, snapshot.Index)
	body = append(body, emptyTargets[:]...)
	body = binary.BigEndian.AppendUint64(body, 21)
	body = binary.BigEndian.AppendUint32(body, 0)
	return append(body, nonce[:]...)
}

// full_only: false
func TestGCNoWorkWitnessRejectsIncompleteOrReboundFacts(t *testing.T) {
	for _, field := range []string{"missing", "full HEAD missing", "full HEAD changed", "token missing", "token changed", "root length missing", "root length changed", "root kind", "root format", "root domain", "root object", "root digest", "root index", "nonempty extra"} {
		t.Run(field, func(t *testing.T) {
			out := gcEmptyResultLiteral(t)
			switch field {
			case "missing":
				out.Payload.NoWork = nil
			case "full HEAD missing":
				out.Payload.NoWork.FullHEADDigest = contract.ID{}
			case "full HEAD changed":
				out.Payload.NoWork.FullHEADDigest = contract.ID{90}
			case "token missing":
				out.Payload.NoWork.TokenDigest = contract.ID{}
			case "token changed":
				out.Payload.NoWork.TokenDigest = contract.ID{90}
			case "root length missing":
				out.Payload.NoWork.Snapshot.Length = 0
			case "root length changed":
				out.Payload.NoWork.Snapshot.Length++
			case "root kind":
				out.Payload.NoWork.Snapshot.Kind = contract.RecipientKind
			case "root format":
				out.Payload.NoWork.Snapshot.Format++
			case "root domain":
				out.Payload.NoWork.Snapshot.Domain = contract.ID{90}
			case "root object":
				out.Payload.NoWork.Snapshot.Object = contract.ID{90}
			case "root digest":
				out.Payload.NoWork.Snapshot.Digest = contract.ID{90}
			case "root index":
				out.Payload.NoWork.Snapshot.Index = 1
			case "nonempty extra":
				witness := out.Payload.NoWork
				out = gcSiblingLiteral(t, false)
				if err := RefreshGCResult(&out); err != nil {
					t.Fatal("valid nonempty control", err)
				}
				out.Payload.NoWork = witness
			}
			if err := out.Validate(); err == nil {
				t.Error("incomplete or changed witness passed public validation")
			}
			if err := RefreshGCResult(&out); err == nil {
				t.Error("refresh admitted an incomplete or changed witness")
			}
		})
	}
}
