package compositionfull

import (
	"bytes"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestAdministrativeCoreResultRetainsGeneratedReasons(t *testing.T) {
	for _, tc := range []struct {
		reason core.Reason
		want   string
	}{{core.StaleGeneratedEpoch, "stale_generated_epoch"}, {core.GeneratedIntentConflict, "generated_intent_conflict"}} {
		got, ok := administrativeCoreResult(core.Result{Outcome: core.AdmissionRefused, Reason: tc.reason})
		if !ok || got.Outcome != "admission_refused" || got.Reason != tc.want {
			t.Errorf("valid Core reason lost: got=%+v ok=%t want=%s", got, ok, tc.want)
		}
	}
}

// full_only: false
func TestGCApplyHumanExplainsCompletionAndPhaseFailures(t *testing.T) {
	r := gcResultEncodingFixture(t, 1)
	var out bytes.Buffer
	if err := WriteGCApplyJSON(t.Context(), &out, r); err != nil {
		t.Fatal("fixture refused by complete result renderer", err)
	}
	out.Reset()
	if err := WriteGCApplyHuman(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"gc-apply: success\n", "Deletion: 1 succeeded, 0 failed, 0 pending, 0 unknown.\n", "Phase select: unresolved_commit / write_uncertain (store: transport); commit may have occurred.\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing operator fact %q in %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), `"schema"`) {
		t.Fatal("human result contains a structured record dump")
	}
}

// full_only: false
func TestAdministrativeHumanListsEveryTargetAndEndingLimits(t *testing.T) {
	r := administrativeListResult(2)
	var out bytes.Buffer
	if err := WriteAdministrativeJSON(t.Context(), &out, r); err != nil {
		t.Fatal("fixture refused by complete result renderer", err)
	}
	out.Reset()
	if err := WriteAdministrativeHuman(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"abandon-list: success\n", "Target 0100000000000000000000000000000000000000000000000000000000000064 (generated-duty)", "Target 0100000000000000000000000000000000000000000000000000000000000065 (generated-duty)", "Evidence: missing.\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing requested administrative fact %q in %s", want, out.String())
		}
	}
	partial := administrativeListResult(0)
	partial.Operation.Operation, partial.Operation.Query.Operation = core.AdministrativePlan, core.AdministrativePlan
	partial.Operation.Query.TargetGroupID = contract.ID{1}
	partial.Operation.Query.ArtifactPath = "/private/abandon-plan.json"
	partial.Operation.List = nil
	partial.Operation.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.ReadUnavailable}
	partial.Operation.StateResult = "unavailable"
	partial.Delivery.PlanCreated, partial.Delivery.PlanFailed = true, true
	out.Reset()
	if err := WriteAdministrativeJSON(t.Context(), &out, partial); err != nil {
		t.Fatal("partial delivery fixture refused by complete result renderer", err)
	}
	out.Reset()
	if err := WriteAdministrativeHuman(t.Context(), &out, partial); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Plan file: \"/private/abandon-plan.json\".\n", "Plan creation completed.\n", "Plan synchronization is not established.\n", "Plan readback is not established.\n", "Plan delivery failed.\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("partial delivery fact omitted: %q in %s", want, out.String())
		}
	}
	out.Reset()
	if err := WriteAdministrativeHuman(t.Context(), &out, administrativeEndedResult(t)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Selected rights ended. Original completion and physical cleanup are not established.\n") {
		t.Fatal("known ending hides its completion and cleanup limits", out.String())
	}
}

// full_only: false
func TestMaterializationHumanExplainsDeliveryAndPrivateResidue(t *testing.T) {
	r := materializationRenderingCleanupResult(t)
	var out bytes.Buffer
	if err := WriteMaterializationJSON(t.Context(), &out, r); err != nil {
		t.Fatal("fixture refused by complete result renderer", err)
	}
	out.Reset()
	if err := WriteMaterializationHuman(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"materialize: unavailable\n", "Materialize file: \"/private/application.env\"\n", "Replacement: not-replaced; installed verification=not-observed; completion=incomplete.\n", "Failure: staging / io-failure.\n", "Candidate cleanup: failed.\n", "Cleanup failure: cleanup / cleanup-failure.\n", "Private residue: \"/private/.enkv-materialize-owned-candidate\".\n", "Plaintext disk disclosure: occurred.\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing materialization fact %q in %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), `"schema"`) {
		t.Fatal("human result contains a structured record dump")
	}
}
