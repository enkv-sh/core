package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

// full_only: false
func TestGCAdministrativeEndingPreservesInstalledCurrentCreationProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, selected, current, effects := installedGeneratedRetirementFixture(t, ctx, "acknowledged")
	store := newGCInterleavingStore(requireAdmittedMemoryStore(t, f.env.Store))
	source := retainedReaderColdOpen(t, selected, store)
	obsolete := f.selected.head.Core.Root
	plan, _ := gcInterleavingPreview(t, ctx, source, store, []string{mustKey(t, store.desc.Prefix, obsolete)}, "preserve current creation proof")
	if len(plan.Targets) != 1 || plan.Targets[0].Object.ObjectID != obsolete.Object {
		t.Fatal("GC plan did not select the previous root")
	}
	active := gcSelectPlanAndReopen(t, ctx, source, store, f.env.Trust, plan)
	proof := generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, current.Generated.CreateResultID}
	indexed, err := active.priorAdministrativeRows()
	if err != nil {
		t.Fatal(err)
	}
	row, ok := indexed[proof]
	if !ok || !active.priorAdministrativeOwnership(row).mandatory {
		t.Fatal("current creation proof lost mandatory ownership")
	}
	proofBody := bytes.Clone(mustSelectedGeneratedWork(t, active).records[proof].Body)
	if len(proofBody) == 0 {
		t.Fatal("missing original creation proof")
	}
	ref := active.root.RequiredSupport[row.page]
	store.readHook = retainedReaderFault("missing", mustKey(t, store.desc.Prefix, ref))
	admission := OpenContext{admission: &active.admission}
	if opened, got := openAdministrative(ctx, admission, store); opened != nil || got != (Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}) {
		t.Fatal("administrative read with unavailable current creation proof", got)
	}
	store.readHook = nil
	partial, result := openAdministrative(ctx, admission, store)
	if partial == nil || result.Outcome != ObservedCurrent {
		t.Fatal("open for administrative ending", result)
	}
	ended := retainedReaderEndWork(t, partial, plan.OperationID, f.env.Trust)
	cold := retainedReaderColdOpen(t, ended, store)
	_, after := observeCurrentValueEntry(t, cold, "generated")
	creates, deletes := effects()
	if !reflect.DeepEqual(current, after) || !bytes.Equal(proofBody, mustSelectedGeneratedWork(t, cold).records[proof].Body) ||
		!cold.root.ActiveGC.IsZero() || cold.root.GCPlans.Count != 0 || cold.root.Generated.Duties != active.root.Generated.Duties ||
		creates != 2 || len(deletes) != 0 || len(store.deleteCalls) != 0 {
		t.Fatal("ending GC changed the current value, creation proof, retirement work or effect count")
	}
}
