package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestGCActiveSelectionDoesNotRevokeLoadedPublicationSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, input, private := publicationEngineFixture(t)
	store := newGCInterleavingStore(f.store)
	orphan := *f.session.recipients[0]
	orphan.Object = fixtureID(f.session.root.Domain, "publication GC orphan recipient")
	body, err := format.EncodeRecipientPage(orphan)
	if err != nil {
		t.Fatal(err)
	}
	ref := format.Ref{Kind: contract.RecipientKind, Format: contract.CanonicalSchema, Domain: orphan.Domain, Object: orphan.Object, Index: orphan.Index, Length: uint32(len(body)), Digest: contract.Hash(body)}
	key := mustKey(t, f.store.desc.Prefix, ref)
	if created := store.Create(ctx, key, body); created.Status != contract.WriteAcknowledged {
		t.Fatal("publication GC orphan creation", created)
	}
	plan := publicationEnginePlan(t, f, input, private)
	var occupied *StateSession
	var operation contract.ID
	entered, returned := 0, 0
	private.onSend = func() {
		entered++
		current := gcInterleavingCurrent(t, ctx, f.admission, store)
		if len(private.owners) != 1 || private.owners[0].armed != 1 || private.owners[0].sent != 1 || private.owners[0].retired != 0 {
			t.Fatal("GC did not enter after the original loaded publication send")
		}
		selected, err := selectedPublicationRelation(current.selectedImage())
		if err != nil || selected.markers[private.owners[0].dispatch.AttemptID].State != contract.PublicationMayHaveEntered {
			t.Fatal("loaded publication lacked its exact selected send marker", err)
		}
		preview, encoded := gcInterleavingPreview(t, ctx, current, store, []string{key}, "loaded publication")
		if len(preview.Targets) != 1 {
			t.Fatal("publication GC did not retain its exact orphan target")
		}
		operation = preview.OperationID
		store.delete = func(context.Context, string, contract.Token) *contract.WriteResult {
			// The transmitted delete remains unknown. Refuse subsequent GC
			// selection writes to leave the canonical slot occupied.
			f.store.casMode = "refused"
			return &contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
		}
		engine := gcInterleavingEngine(t, current, store, []string{key}, f.trust)
		cleaned := engine.ApplyPlan(ctx, GCApplyPlanRequest{RequestNonce: fixtureID(f.session.root.Domain, "loaded publication GC apply"), EncodedPlan: encoded})
		if err := engine.Close(); err != nil {
			t.Fatal("publication GC invocation did not join", err)
		}
		f.store.casMode = ""
		if cleaned.Validate() != nil || cleaned.Payload == nil || cleaned.Payload.Closed || !cleaned.Payload.Active || len(store.deleteCalls) != 1 {
			t.Fatal("publication GC cut did not retain the active unresolved owner", cleaned.Result)
		}
		occupied = gcInterleavingCurrent(t, ctx, f.admission, store)
		_, progress, err := occupied.selectedGCPlan(operation)
		if err != nil || occupied.root.ActiveGC != operation || progress.Targets[0].Consumed != 1 || !reflect.DeepEqual(occupied.pages, current.pages) || !bytes.Equal(occupied.valueEntry(0).ValueBytes, current.valueEntry(0).ValueBytes) {
			t.Fatal("GC occupation lost application bytes or its consumed allowance", err)
		}
		returned++
	}
	t.Cleanup(func() {
		t.Logf("publication GC joins: entered=%d returned=%d owners=%d deletes=%d", entered, returned, len(private.owners), len(store.deleteCalls))
	})
	got := plan.execute(ctx, private.callbacks(), publicationEngineCurrent(f))
	if len(private.owners) != 1 {
		t.Fatal("publication allocated another owner after GC")
	}
	owner := private.owners[0]
	row := got.output.Entries[0].Actions[0]
	if entered != 1 || returned != 1 || occupied == nil || owner.sent != 1 || owner.retired != 1 || row.Disposition != contract.PublicationOutcomeUnknown {
		t.Fatal("GC occupation revoked loaded send or permitted a later close", got.state, row)
	}
	selected := publicationEngineReopen(t, f)
	if f.session.root.ActiveGC != operation || f.session.head.Core.Revision != occupied.head.Core.Revision || selected.markers[row.AttemptID].State != contract.PublicationMayHaveEntered || selected.markers[row.AttemptID].Projection != owner.input.Projection {
		t.Fatal("publication close changed the active GC predecessor or original marker")
	}
	creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
	target := plan.targets[0]
	reservation, preparation, result := plan.reserveCandidate(ctx, f.session, target, target.actions[0], private.callbacks())
	if reservation != nil || preparation != nil || result != refused(AdmissionInvalid) || len(private.owners) != 1 || owner.sent != 1 || owner.retired != 1 ||
		f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs {
		t.Fatal("active GC admitted a later publication reservation or another send", result)
	}
}
