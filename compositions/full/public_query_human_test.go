package compositionfull

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicQueryHumanViewsLeadWithOutcomeAndRetainRequestedFacts(t *testing.T) {
	t.Run("receipt-detail", func(t *testing.T) {
		r := publicQueryRendererDetail(t)
		var out bytes.Buffer
		if err := WriteReceiptDetailHuman(t.Context(), &out, r); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Receipt detail: success\n", "Authenticity: \"authenticated-retained\"", "Retention: \"retained\"", "Operation id: \"" + readerID(contract.ID{11}) + "\""} {
			if !strings.Contains(out.String(), want) {
				t.Fatal("requested receipt fact missing", want, out.String())
			}
		}
		if strings.Contains(out.String(), "Encoded receipt:") {
			t.Fatal("encoded receipt backing in human output")
		}
		assertQueryHumanHasNoEnvelope(t, out.String())
	})
	t.Run("capacity-refusal", func(t *testing.T) {
		r, err := NewCapacityInspectionRefusal(configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := WriteCapacityInspectionHuman(t.Context(), &out, r); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(out.String(), "Capacity inspection: refused\n") || !strings.Contains(out.String(), "Reason: "+string(r.FailureReason)) || !strings.Contains(out.String(), "No query data is available.") {
			t.Fatal("refusal did not identify outcome and unavailable data", out.String())
		}
		assertQueryHumanHasNoEnvelope(t, out.String())
	})
	t.Run("gc-plan-refusal", func(t *testing.T) {
		r, err := NewGCPlanRefusal(configuration.JSON)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := WriteGCPlanHuman(t.Context(), &out, r); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"GC plan: refused\n", "Plan file created: false", "Plan file synced: false", "Plan file read back: false", "No remote objects were deleted."} {
			if !strings.Contains(out.String(), want) {
				t.Fatal("plan delivery/effect fact missing", want, out.String())
			}
		}
		assertQueryHumanHasNoEnvelope(t, out.String())
	})
}

// full_only: true
func TestPublicInspectionHumanRetainsMaximumMetadataAndMemberships(t *testing.T) {
	r := publicQueryRendererDomain(t)
	maximumInspectionMetadata(t, r.View)
	var out bytes.Buffer
	if err := WriteInspectionHuman(t.Context(), &out, r); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.HasPrefix(text, "Domain inspection: success\n") || !strings.Contains(text, "Entries: 512 rows") || !strings.Contains(text, "Recipients: 256 rows") {
		t.Fatal("maximum query counts missing")
	}
	for i := range 512 {
		name := fmt.Sprintf("%04d", i) + strings.Repeat("\x00", 252)
		if !strings.Contains(text, "Entry "+fmt.Sprintf("%q", name)+":") {
			t.Fatal("entry was omitted or truncated", i)
		}
	}
	if got := strings.Count(text, "  Recipients:"); got != 512 {
		t.Fatal("membership row sets missing", got)
	}
	if got := strings.Count(text, "; display name "); got != 256 {
		t.Fatal("Recipient rows missing", got)
	}
	// Every membership value is retained, including the first entry's 64 members.
	if !strings.Contains(text, "  Recipients: 64\n") || strings.Count(text, "; value state:") != 512 {
		t.Fatal("complete memberships or entry identity facts missing")
	}
	if got := strings.Count(text, "  Recipient: "); got != 4096 {
		t.Fatal("membership identities were omitted or duplicated", got)
	}
	assertQueryHumanHasNoEnvelope(t, text)
}

// full_only: false
func TestPublicInspectionHumanPreservesCleanupIdentityAndNoInventedAction(t *testing.T) {
	r := publicQueryRendererDomain(t)
	id := contract.ID{1}
	cleanup, effect := generatedRendererRelease(contract.PendingInboxReleaseRecord{Schema: 1, DomainID: id, InboxID: contract.ID{2}, OriginalResultID: contract.ID{3}, SelectedHandoffDigest: id, HandoffRevisionID: id, CapacityReservation: contract.GeneratorDescriptor{Digest: id, Length: 4}, ObjectLength: uint32(contract.GeneratedResultRecordMaxLength), State: contract.GeneratedReleasePending})
	r.View.Generated.PendingReleases = []core.GeneratedPendingResultCleanup{cleanup}
	r.View.Generated.Effects = []core.GeneratedEffectFact{effect}
	model := &configuration.Model{Provider: contract.AWS, DomainID: r.DomainID, Resolved: true}
	model.Store.Region, model.Store.Bucket, model.Store.PrefixBeforeHEAD, model.Store.ExpectedOwner = "us-east-1", "cleanup-result-bucket", "cleanup-results", "123456789012"
	location := newResultStoreLocation(model, r.DomainID, r.Result)
	if location == nil {
		t.Fatal("authenticated Store fixture refused")
	}
	result := ConfigurationInspectionResult{PublicDomainInspectionResult: r, storeLocation: location}
	var out bytes.Buffer
	if err := result.WriteHuman(t.Context(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), "Configured Store:") != 1 || !strings.Contains(out.String(), `bucket "cleanup-result-bucket"; prefix "cleanup-results"`) {
		t.Fatal("cleanup location missing or repeated", out.String())
	}
	for _, want := range []string{"Pending Store result cleanup: pending", "Inbox: " + readerID(cleanup.InboxID), "Original operation: " + readerID(cleanup.OriginalOperationID), "Original attempt: " + readerID(cleanup.OriginalAttemptID), "This does not confirm Store result cleanup.", "No supported generated-work action is available."} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("cleanup fact missing", want, out.String())
		}
	}
	assertQueryHumanHasNoEnvelope(t, out.String())
	result.View.Generated.NextActions = []core.GeneratedNextAction{{Command: "generated accept-retirement-risk", DutyID: contract.ID{7}, AttemptID: contract.ID{8}}}
	out.Reset()
	if err := result.WriteHuman(t.Context(), &out); err != nil {
		t.Fatal(err)
	}
	want := "Supported next action: generated accept-retirement-risk; duty " + readerID(contract.ID{7}) + "; attempt " + readerID(contract.ID{8})
	if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "No supported generated-work action is available.") || strings.Count(out.String(), "Configured Store:") != 1 {
		t.Fatal("typed action identities lost or replaced", out.String())
	}
}

func assertQueryHumanHasNoEnvelope(t *testing.T, text string) {
	t.Helper()
	for _, absent := range []string{"ProductResult/v1", "InspectionPayload/v1", "ReceiptPayload/v1", "CapacityPayload/v1", "CleanupPayload/v1", "operation_payload", "replay_identity", "capsule_policy", "\nresult: "} {
		if strings.Contains(text, absent) {
			t.Fatal("human result contains an internal wrapper", absent)
		}
	}
	if !strings.HasSuffix(text, "\n") || strings.HasSuffix(text, "\n\n") {
		t.Fatal("human result must end with one LF")
	}
}
