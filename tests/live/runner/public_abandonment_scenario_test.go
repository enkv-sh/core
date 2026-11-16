package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

const publicOperatorAbandonmentScenario = "operator.abandon-selected-work-through-cli/one_generated_group_stale_plan_apply_history_receipt"
const publicOperatorReplacementScenario = "operator.replace-authority-then-abandon-through-cli/recovery_signing_replacement_then_stale_plan_apply_history"
const publicOperatorDisabledScenario = "operator.disabled-recovery-refuses-authority-replacement-through-cli/disabled_recovery_preserves_selected_work"

type operatorCLIResult struct {
	Outcome               string `json:"outcome"`
	Reason                string `json:"reason"`
	StoreReason           string `json:"store_reason,omitempty"`
	ObservedRevision      string `json:"observed_revision,omitempty"`
	RequestedRevision     string `json:"requested_revision,omitempty"`
	CommitMayHaveOccurred bool   `json:"commit_may_have_occurred"`
}
type operatorDescriptor struct {
	Digest string `json:"digest"`
	Length uint64 `json:"length"`
	Count  uint32 `json:"count"`
}
type operatorDigestLength struct {
	Digest string `json:"digest"`
	Length uint64 `json:"length"`
}
type operatorPreview struct {
	Identity                string               `json:"identity"`
	PredecessorRevision     string               `json:"predecessor_revision"`
	TargetGroupID           string               `json:"target_group_id"`
	EndedGroupIDs           []string             `json:"ended_group_ids"`
	TargetOwnerID           string               `json:"target_owner_id"`
	TargetID                string               `json:"target_id"`
	TargetKind              uint8                `json:"target_kind"`
	DutyKind                uint8                `json:"duty_kind"`
	SelectedEvidenceSummary uint16               `json:"selected_evidence_summary"`
	DependentGroups         operatorDescriptor   `json:"dependent_groups"`
	RemovedSupport          operatorDescriptor   `json:"removed_support"`
	PreservedCurrent        operatorDigestLength `json:"preserved_current"`
	BeforeWarningBits       uint8                `json:"before_warning_bits"`
	WarningBits             uint8                `json:"warning_bits"`
	BeforeChildCount        uint16               `json:"before_child_count"`
	AfterChildCount         uint16               `json:"after_child_count"`
	BeforeChildBytes        uint64               `json:"before_child_bytes"`
	AfterChildBytes         uint64               `json:"after_child_bytes"`
}
type operatorRisk struct {
	OriginalEvidence      []string `json:"original_evidence"`
	Warnings              []string `json:"warnings"`
	WarningChanges        uint8    `json:"warning_changes"`
	OriginalCompletion    string   `json:"original_completion"`
	PhysicalCleanup       string   `json:"physical_cleanup"`
	PreservedCurrentState string   `json:"preserved_current_state"`
	FutureCleanupHistory  string   `json:"future_cleanup_history"`
	LateEffects           string   `json:"late_effects"`
}
type operatorGroup struct {
	GroupID           string   `json:"group_id"`
	Kind              string   `json:"kind"`
	OwnerID           string   `json:"owner_id"`
	TargetID          string   `json:"target_id"`
	OwnerKind         uint8    `json:"owner_kind"`
	DutyKind          uint8    `json:"duty_kind"`
	Evidence          uint16   `json:"selected_evidence_summary"`
	EvidenceFacts     []string `json:"original_evidence_facts"`
	ChargedPages      uint16   `json:"charged_pages"`
	ChargedBytes      uint64   `json:"charged_bytes"`
	Blocks            bool     `json:"blocks_changed_mutation"`
	Parent            string   `json:"required_parent_group_id,omitempty"`
	Selectable        bool     `json:"selectable"`
	OriginalOperation string   `json:"original_operation_id,omitempty"`
	Warnings          []string `json:"warnings"`
	Related           []string `json:"related_group_ids"`
}
type operatorReceipt struct {
	Schema            string   `json:"schema"`
	OperationID       string   `json:"operation_id"`
	Kind              uint16   `json:"operation_kind"`
	StoredState       string   `json:"stored_state_result"`
	Group             string   `json:"group_id"`
	Target            string   `json:"target_id"`
	TargetKind        uint8    `json:"target_kind"`
	Disposition       string   `json:"disposition_id"`
	Evidence          []string `json:"original_evidence_facts"`
	Warnings          []string `json:"historical_warning_summary"`
	WarningChanges    uint8    `json:"warning_changes"`
	Pages             int16    `json:"page_delta"`
	Bytes             int64    `json:"byte_delta"`
	Raw               string   `json:"receipt_hex"`
	Authenticity      string   `json:"authenticity"`
	EvidenceCeiling   string   `json:"evidence_ceiling"`
	Retention         string   `json:"retention"`
	OriginalOperation string   `json:"original_operation_id,omitempty"`
}
type operatorListPayload struct {
	Schema       string            `json:"schema"`
	View         string            `json:"view"`
	Revision     string            `json:"revision"`
	Snapshot     string            `json:"snapshot"`
	Warnings     []string          `json:"current_warning_summary"`
	Targets      []operatorGroup   `json:"targets"`
	Abandonments []operatorReceipt `json:"abandonments"`
}
type operatorArtifact struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Length uint64 `json:"length"`
}
type operatorPlanPayload struct {
	Schema       string           `json:"schema"`
	View         string           `json:"view"`
	Preview      operatorPreview  `json:"preview"`
	Risk         operatorRisk     `json:"risk"`
	ArtifactPath string           `json:"artifact_path"`
	Artifact     operatorArtifact `json:"artifact"`
}
type operatorEndPayload struct {
	Schema             string          `json:"schema"`
	Preview            operatorPreview `json:"preview"`
	Risk               operatorRisk    `json:"risk"`
	OriginalCompletion string          `json:"original_completion"`
	PhysicalCleanup    string          `json:"physical_cleanup"`
	SelectedRights     string          `json:"selected_rights"`
	ExclusiveCapacity  string          `json:"exclusive_capacity"`
	SharedSupport      string          `json:"shared_support"`
	Receipt            operatorReceipt `json:"receipt"`
}
type operatorDelivery struct {
	PlanCreated   bool `json:"plan_created"`
	PlanSynced    bool `json:"plan_synced"`
	PlanReadback  bool `json:"plan_readback"`
	PlanFailed    bool `json:"plan_failed"`
	CleanupFailed bool `json:"cleanup_failed"`
}
type operatorAbandonmentReply struct {
	Schema        string            `json:"schema"`
	Operation     string            `json:"operation_kind"`
	State         string            `json:"state_result"`
	Effect        string            `json:"effect_summary"`
	Output        string            `json:"output_summary"`
	OperationID   string            `json:"operation_id"`
	RequestID     string            `json:"request_id"`
	Domain        string            `json:"domain_id"`
	Identity      json.RawMessage   `json:"request_identity"`
	Result        operatorCLIResult `json:"result"`
	Evidence      string            `json:"evidence_ceiling"`
	Replay        string            `json:"replay_identity"`
	CommitUnknown bool              `json:"commit_may_have_occurred"`
	Warnings      []string          `json:"warning_summary"`
	Delivery      operatorDelivery  `json:"delivery"`
	Effects       []struct{}        `json:"effects"`
	Outputs       []struct{}        `json:"outputs"`
	Duties        []struct{}        `json:"duties"`
	Hazards       []struct{}        `json:"hazards"`
	Capsule       string            `json:"capsule_policy"`
	PayloadKind   string            `json:"operation_payload"`
	Payload       json.RawMessage   `json:"payload"`
}

func operatorStrictJSON(body []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return contract.ErrRecord
	}
	return nil
}
func operatorAbandonmentResult(body []byte) (operatorAbandonmentReply, error) {
	var r operatorAbandonmentReply
	if len(body) > operatorCLICaptureLimit || operatorStrictJSON(body, &r) != nil || r.Schema != "ProductResult/v1" || r.Result.Outcome == "" || r.Result.Reason == "" || r.Effect != "not-applicable" || r.Output != "not-applicable" || r.Capsule != "none" || len(r.Effects)+len(r.Outputs)+len(r.Duties)+len(r.Hazards) != 0 || r.CommitUnknown != r.Result.CommitMayHaveOccurred {
		return r, contract.ErrRecord
	}
	switch r.Operation {
	case "abandon-list", "abandon-plan", "abandon-apply", "abandon-receipt":
	default:
		return r, contract.ErrRecord
	}
	return r, nil
}

type operatorQuerySource struct {
	FileID          string `json:"file_id"`
	Format          uint8  `json:"format"`
	EditableDigest  string `json:"editable_digest"`
	GeneratedDigest string `json:"generated_digest"`
	EditableLength  uint64 `json:"editable_length"`
	GeneratedLength uint64 `json:"generated_length"`
	HasGenerated    bool   `json:"has_generated"`
}
type operatorQueryObservation struct {
	Domain   string `json:"domain_id"`
	Revision string `json:"head_revision_id"`
	Snapshot string `json:"snapshot_id"`
}
type operatorQuery struct {
	Schema             string                    `json:"schema"`
	Operation          string                    `json:"operation_kind"`
	SemanticOperation  uint16                    `json:"semantic_operation"`
	ExpectedDomain     string                    `json:"expected_domain_id"`
	Store              string                    `json:"store_id"`
	Coordinate         string                    `json:"coordinate_id"`
	NonBody            string                    `json:"non_body_id"`
	Basis              string                    `json:"public_basis_digest"`
	StoreDescriptor    string                    `json:"store_descriptor_digest"`
	Source             operatorQuerySource       `json:"source"`
	Observation        *operatorQueryObservation `json:"observation"`
	Nonce              string                    `json:"request_nonce"`
	RequestedOperation string                    `json:"requested_operation_id,omitempty"`
	RequiredKind       uint16                    `json:"required_stored_kind,omitempty"`
	Target             string                    `json:"target_group_id,omitempty"`
	Plan               string                    `json:"plan_identity,omitempty"`
	ArtifactPath       string                    `json:"artifact_path,omitempty"`
	Artifact           *operatorArtifact         `json:"artifact,omitempty"`
	Digest             string                    `json:"digest"`
}

func operatorCheckQuery(t testing.TB, r operatorAbandonmentReply, selected *StateSession, target, path, requested string) operatorQuery {
	t.Helper()
	var q operatorQuery
	if operatorStrictJSON(r.Identity, &q) != nil {
		t.Fatal("native query omitted its closed typed identity")
	}
	semantic := uint16(15)
	if r.Operation == "abandon-receipt" {
		semantic = 16
	}
	d := selected.store.Descriptor()
	if q.Schema != "QueryRequestIdentity/v1" || q.Operation != r.Operation || q.SemanticOperation != semantic || q.ExpectedDomain != operatorIDText(selected.root.Domain) || q.Store != operatorIDText(d.Identity) || q.Coordinate != operatorIDText(d.Coordinate) || q.NonBody != operatorIDText(d.NonBody) || q.Basis == "" || q.StoreDescriptor == "" || q.Source.FileID == "" || q.Source.Format != 1 || q.Source.EditableDigest == "" || q.Source.EditableLength == 0 || !q.Source.HasGenerated || q.Source.GeneratedDigest == "" || q.Source.GeneratedLength == 0 || q.Observation == nil || q.Observation.Domain != operatorIDText(selected.root.Domain) || q.Observation.Revision != operatorIDText(selected.head.Core.Revision) || q.Observation.Snapshot != operatorIDText(selected.root.Snapshot) || q.Nonce != r.RequestID || q.Digest == "" || q.Target != target || q.ArtifactPath != path || q.RequestedOperation != requested {
		t.Fatal("native query lost source, selection, observation or nonce binding")
	}
	if r.Operation == "abandon-plan" {
		if q.Plan == "" || q.Artifact == nil || q.Artifact.Path != path || q.Artifact.Digest == "" || q.Artifact.Length == 0 {
			t.Fatal("native plan query lost delivered artifact commitment")
		}
	} else if q.Plan != "" || q.Artifact != nil {
		t.Fatal("nonplan query borrowed plan commitment")
	}
	if r.Operation == "abandon-receipt" {
		if q.RequiredKind != 43 {
			t.Fatal("receipt query omitted required stored kind")
		}
	} else if q.RequiredKind != 0 {
		t.Fatal("other query borrowed receipt kind")
	}
	return q
}
func operatorObserved(r operatorAbandonmentReply) bool {
	return r.Result.Outcome == "observed_current" && r.Result.Reason == "none" && r.Result.StoreReason == "" && !r.Result.CommitMayHaveOccurred
}
func operatorPayload[T any](t testing.TB, r operatorAbandonmentReply, kind string) T {
	t.Helper()
	var p T
	if r.PayloadKind != kind || operatorStrictJSON(r.Payload, &p) != nil {
		t.Fatal("native command lost closed typed payload", r.Operation, r.PayloadKind)
	}
	return p
}
func publicOperatorSourceBasis(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source string, domain contract.ID, store contract.Descriptor) PublicBasis {
	t.Helper()
	facts := publicParsedSourceFacts(t, ctx, inv, input, budget, source)
	if facts.DomainID != domain {
		t.Fatal("native source independent basis unavailable")
	}
	basis := publicParsedSourceBasis(facts)
	owned, err := basis.own()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owned.ControlCore(domain, store); err != nil {
		t.Fatal("native source basis does not qualify configured domain/store", err)
	}
	return owned
}
func operatorAuthenticatedRead(t testing.TB, ctx context.Context, selected *StateSession, store contract.Store) *StateSession {
	return publicOperatorOpen(t, ctx, selected.root.Domain, selected.admission.publicBasis(), store)
}
func operatorEndFixture(t testing.TB, ctx context.Context, selected *StateSession, store contract.Store, trust contract.Trust) EndWorkPreview {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	reader := &installedAdministrativeTestReader{store: store}
	input := installedAdministrativeReadInput(selected, reader)
	planner, err := NewInstalledAdministrativeReader(input, AdministrativePlan)
	if err != nil {
		t.Fatal(err)
	}
	planned := planner.Plan(ctx, contract.Hash([]byte("operator fixture plan")), AdministrativePlanRequest{TargetGroupID: selected.adminIndex.Groups[0].GroupID, ArtifactPath: "/fixture/plan.json"})
	if err := planner.Close(); err != nil {
		t.Fatal(err)
	}
	if planned.Result.Outcome != ObservedCurrent || planned.Plan == nil {
		t.Fatal("installed fixture planning refused", planned.Result)
	}
	authority, err := NewInstalledAdministrativeAuthority(AdministrativeAuthorityInstallation{ExpectedDomain: input.ExpectedDomain, ExpectedStore: input.ExpectedStore, PublicBasis: input.PublicBasis, CompositionID: input.CompositionID, SourcePins: input.SourcePins, Store: store, Trust: trust, CheckSource: input.CheckSource, CloseInstalled: func() error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	ended := authority.Apply(ctx, contract.Hash([]byte("operator fixture apply")), planned.Plan.Preview)
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	if ended.Result.Outcome != ObservedCurrent || ended.End == nil {
		t.Fatal("installed fixture ending refused", ended.Result)
	}
	return planned.Plan.Preview
}
func operatorAdvanceCurrent(run *scenarioRun, current *StateSession, trust contract.Trust, name string) *StateSession {
	run.t.Helper()
	before := sessionStateImage(run.t, current)
	beforeRows, err := operatorAdvanceSupportRows(current)
	if err != nil {
		run.t.Fatal("ordinary predecessor support ownership unavailable")
	}
	old := observeSelectedState(run.t, current)
	wanted := append(current.currentEntryInputs(), ApplyEntryInput{Name: name, Recipients: []contract.ID{current.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte(name), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	continuation := *run
	if observed, ok := trust.(scenarioTrust); !ok || observed.spy != run.spy {
		trust = scenarioTrust{Trust: trust, spy: run.spy}
	}
	continuation.env.Trust = trust
	candidate := continuation.suppliedCandidate(current, wanted)
	next, result := current.selectCandidate(run.ctx, candidate)
	if next == nil || result.Outcome != ObservedCurrent || next.head.Core.Revision == current.head.Core.Revision || next.root.ChildCount > 32 || next.root.ChildEncodedBytes > 32<<20 || len(next.adminIndex.Groups) != len(current.adminIndex.Groups) {
		run.t.Fatal("ordinary transition did not advance exact predecessor while preserving work", result)
	}
	for _, row := range old.Root.Names {
		if !reflect.DeepEqual(next.valueEntry(row.Slot), current.valueEntry(row.Slot)) {
			run.t.Fatal("ordinary predecessor advance changed a current value")
		}
	}
	afterRows, err := operatorAdvanceSupportRows(next)
	if err != nil {
		run.t.Fatal("ordinary successor support ownership unavailable")
	}
	expected, err := operatorAdvanceExpectedGroups(before.AdministrativeIndex.Groups, beforeRows, afterRows,
		before.Root.Domain, before.AdministrativeIndex.SliceSnapshot, next.root.Snapshot)
	if err != nil {
		run.t.Fatal("ordinary predecessor advance changed retained support")
	}
	if !reflect.DeepEqual(expected, next.adminIndex.Groups) {
		for i, group := range expected {
			want, got := reflect.ValueOf(group), reflect.ValueOf(next.adminIndex.Groups[i])
			for field := 0; field < want.NumField(); field++ {
				if !reflect.DeepEqual(want.Field(field).Interface(), got.Field(field).Interface()) {
					run.t.Logf("administrative group %d changed field %s", i, want.Type().Field(field).Name)
				}
			}
		}
		run.t.Fatal("ordinary predecessor advance changed exact administrative groups")
	}
	return next
}

func publicAbandonmentCLI(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, selected *StateSession, afterCount uint16, afterBytes uint64, source, command string, args ...string) (operatorAbandonmentReply, publicChildResult) {
	t.Helper()
	reservation, ok := operatorCLIReservation(selected, command, afterCount, afterBytes)
	if !ok {
		t.Fatal("native abandonment reservation refused")
	}
	role := "reader"
	if command == "apply" || command == "stale-apply" {
		role = "authority"
		if currentControlOf(selected).NormalSigning.KeySelector == input.Settings.NormalSuccessorKeyID {
			role = "successor"
		}
	}
	subcommand := command
	if subcommand == "stale-apply" {
		subcommand = "apply"
	}
	argv := append([]string{"abandon", subcommand, "--source", source, "--source-format", "json", "--json"}, args...)
	result := publicCLIReserved(t, ctx, inv, input, budget, role, false, nativeprocess.Policy{NoKMS: command != "apply"}, reservation, nil, argv...)
	reply, err := operatorAbandonmentResult(result.Body)
	if err != nil || reply.Operation != "abandon-"+subcommand {
		clear(result.Body)
		t.Fatal("native abandonment did not return its exact recognized result", err, result.Code)
	}
	if err := publicOperatorCapture(result.Capture, command, currentControlOf(selected).NormalSigning.KeySelector == input.Settings.NormalSuccessorKeyID); err != nil {
		clear(result.Body)
		t.Fatal(err)
	}
	return reply, result
}
func operatorCheckPlan(t testing.TB, r operatorAbandonmentReply, selected *StateSession, group format.AdministrativeGroup, path string) operatorPlanPayload {
	t.Helper()
	p := operatorPayload[operatorPlanPayload](t, r, "InspectionPayload/v1")
	q := operatorCheckQuery(t, r, selected, operatorIDText(group.GroupID), path, "")
	if !operatorObserved(r) || r.State != "success" || r.Evidence != "canonical" || r.Replay != "none" || p.Schema != "InspectionPayload/v1" || p.View != "administrative-plan" || p.Preview.TargetGroupID != operatorIDText(group.GroupID) || !slices.Equal(p.Preview.EndedGroupIDs, []string{operatorIDText(group.GroupID)}) || p.Preview.TargetOwnerID != operatorIDText(group.OwnerID) || p.Preview.TargetID != operatorIDText(group.TargetID) || p.Preview.TargetKind != group.OwnerKind || p.Preview.DutyKind != group.DutyKind || p.Preview.PredecessorRevision != operatorIDText(selected.head.Core.Revision) || p.Preview.SelectedEvidenceSummary != group.SelectedEvidenceSummary || p.Preview.BeforeChildCount != uint16(selected.root.ChildCount) || p.Preview.BeforeChildBytes != selected.root.ChildEncodedBytes || p.Preview.AfterChildCount == 0 || p.Preview.AfterChildCount > 32 || p.Preview.AfterChildBytes == 0 || p.Preview.AfterChildBytes > 32<<20 || q.Plan != p.Preview.Identity || q.Artifact == nil || *q.Artifact != p.Artifact || p.Preview.DependentGroups.Count != 1 || p.Preview.RemovedSupport.Count == 0 || p.Preview.PreservedCurrent.Length == 0 || p.Risk.OriginalCompletion != "not-established" || p.Risk.PhysicalCleanup != "not-established" || p.Risk.PreservedCurrentState != "selected values and access remain; ended work rights and exclusive support would be removed" || p.Risk.FutureCleanupHistory != "exact ended-work history and future adoption rights would be discarded" || p.Risk.LateEffects != "old processes can still send; remote effects are not cancelled or isolated" || !slices.Equal(p.Risk.OriginalEvidence, operatorEvidence(group.SelectedEvidenceSummary)) || !slices.Equal(r.Warnings, operatorExpectedWarnings(selected.root.WarningBits)) || p.Preview.BeforeWarningBits != selected.root.WarningBits || p.Risk.WarningChanges != p.Preview.WarningBits&^p.Preview.BeforeWarningBits || !slices.Equal(p.Risk.Warnings, operatorHistoricalWarnings(p.Preview.WarningBits, group.SelectedEvidenceSummary)) || !r.Delivery.PlanCreated || !r.Delivery.PlanSynced || !r.Delivery.PlanReadback || r.Delivery.PlanFailed || r.Delivery.CleanupFailed {
		t.Fatal("native plan omitted complete exact disposition or delivery")
	}
	body, err := os.ReadFile(path)
	digest := sha256.Sum256(body)
	if err != nil || p.ArtifactPath != path || p.Artifact.Path != path || p.Artifact.Length != uint64(len(body)) || p.Artifact.Digest != hex.EncodeToString(digest[:]) {
		t.Fatal("native plan artifact commitment differs from protected delivery", err)
	}
	return p
}

type operatorAuthorityReply struct {
	Schema        string                    `json:"schema"`
	Operation     string                    `json:"operation_kind"`
	State         string                    `json:"state_result"`
	Effect        string                    `json:"effect_summary"`
	Output        string                    `json:"output_summary"`
	Request       string                    `json:"request_id"`
	OperationID   string                    `json:"operation_id"`
	Identity      json.RawMessage           `json:"request_identity"`
	Replay        string                    `json:"replay_identity"`
	Domain        string                    `json:"domain_id"`
	Requested     string                    `json:"requested_revision_id"`
	Observed      string                    `json:"observed_revision_id"`
	Snapshot      string                    `json:"observed_snapshot_id"`
	Evidence      string                    `json:"evidence_ceiling"`
	Unknown       bool                      `json:"commit_may_have_occurred"`
	WarningBits   uint8                     `json:"current_warning_bits"`
	Warnings      []string                  `json:"warning_summary"`
	Result        operatorCLIResult         `json:"result"`
	PayloadKind   string                    `json:"operation_payload"`
	Payload       json.RawMessage           `json:"payload"`
	Effects       []struct{}                `json:"effects"`
	Outputs       []struct{}                `json:"outputs"`
	Duties        []struct{}                `json:"duties"`
	Hazards       []struct{}                `json:"hazards"`
	Capsule       string                    `json:"capsule_policy"`
	StoredReceipt json.RawMessage           `json:"stored_receipt"`
	Query         json.RawMessage           `json:"query"`
	NoWork        json.RawMessage           `json:"no_work_observation"`
	Diagnostics   []json.RawMessage         `json:"diagnostics"`
	Delivery      publicReplacementDelivery `json:"delivery"`
}

func publicOperatorReplace(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, selected *StateSession, source string, disabled bool) (*StateSession, contract.Trust, string) {
	t.Helper()
	before := publicOperatorFreeze(t, ctx, selected)
	original := publicSourceImage(t, source)
	out := filepath.Join(inv.StateDir, "authority-successor.json")
	selector := input.Settings.NormalSuccessorKeyID
	if disabled && selector == "" {
		selector = before.Control.NormalSigning.KeySelector
	}
	if selector == "" {
		t.Fatal("configured successor selector unavailable")
	}
	reservation, ok := operatorCLIReservation(selected, "keys-replace", 32, 32<<20)
	if !ok {
		t.Fatal("finite native replacement reservation unavailable")
	}
	role := "successor"
	if disabled {
		role = "authority"
	}
	result := publicCLIReserved(t, ctx, inv, input, budget, role, false, nativeprocess.Policy{NoKMS: disabled}, reservation, nil, "keys", "replace", "--source", source, "--source-format", "json", "--target", "authority", "--authorizer", "recovery", "--signing", selector, "--out", out, "--json")
	var reply operatorAuthorityReply
	if operatorStrictJSON(result.Body, &reply) != nil || reply.Schema != "ProductResult/v1" || reply.Operation != "keys-replace-authority" || reply.Unknown || reply.Result.CommitMayHaveOccurred {
		clear(result.Body)
		t.Fatal("native Authority replacement lost exact operation result", result.Code)
	}
	clear(result.Body)
	publicImageUnchanged(t, original)
	if disabled {
		if result.Code != 2 || reply.State != "refused" || reply.Result.Outcome != "admission_refused" || reply.PayloadKind != "none" || len(reply.StoredReceipt) != 0 || len(reply.NoWork) != 0 || reply.Delivery.Status != "not-attempted" {
			t.Fatal("disabled Recovery borrowed replacement authority")
		}
		for _, event := range result.Capture.Events {
			if event.Kind == "construction" || event.Kind == "http-start" && event.Sent {
				t.Fatal("disabled Recovery attempted capability construction or provider work")
			}
		}
		if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("disabled Recovery published successor", err)
		}
		current := operatorAuthenticatedRead(t, ctx, selected, selected.store)
		assertStateImage(t, current, before.Image)
		if !bytes.Equal(current.body, before.HEAD) || current.token != before.Token {
			t.Fatal("disabled Recovery refusal changed selected HEAD")
		}
		windows, err := current.receiptWindows(ctx)
		if err != nil || !publicOperatorReceiptWindowsEqual(windows, before.Windows) {
			t.Fatal("disabled Recovery refusal changed complete receipt windows", err)
		}
		return current, nil, source
	}
	if result.Code != 0 || reply.State != "success" || reply.PayloadKind != "TransitionPayload/v1" || reply.Evidence != "canonical" || reply.Domain != operatorIDText(selected.root.Domain) || reply.OperationID == "" || reply.Requested == "" || reply.Requested != reply.Observed || reply.Snapshot == "" || len(reply.StoredReceipt) != 0 || len(reply.NoWork) != 0 || reply.Delivery.Path != out || reply.Delivery.Status != "delivered" || reply.Delivery.Failed || reply.Delivery.CleanupFailed {
		t.Fatal("native Authority replacement did not deliver and select exact successor")
	}
	if !publicReplacementDeliveryMatches(reply.Delivery, out, publicSourceImage(t, out)) {
		t.Fatal("native Authority replacement delivery differs from the exact pair readback")
	}
	if err := publicOperatorCapture(result.Capture, "keys-replace", false); err != nil {
		t.Fatal(err)
	}
	if !budget.reserve(8, 8*operationBodyAllowance, "", 0) {
		t.Fatal("independent successor public qualification reservation unavailable")
	}
	expectedPublic, expectedTrust, err := resolvePublicOperatorSuccessor(ctx, input, inv.StateDir)
	if err != nil || bytes.Equal(expectedPublic, before.Control.NormalSigning.SPKI) {
		t.Fatal("independent successor resource owner did not supply a distinct signer", err)
	}
	basis := publicOperatorSourceBasis(t, ctx, inv, input, budget, out, selected.root.Domain, selected.store.Descriptor())
	current := publicOperatorOpen(t, ctx, selected.root.Domain, basis, selected.store)
	next := currentControlOf(current).NormalSigning
	if next.KeySelector != input.Settings.NormalSuccessorKeyID || !bytes.Equal(next.SPKI, expectedPublic) || next.Fingerprint != contract.Hash(expectedPublic) || next.Binding.PublicKey != next.Fingerprint || next.Binding.Trust != expectedTrust || next.BindingID.IsZero() || next.BindingID == before.Control.NormalSigning.BindingID || next.Binding.Epoch != before.Control.NormalSigning.Binding.Epoch+1 || operatorIDText(current.head.Core.Revision) != reply.Observed || operatorIDText(current.root.Snapshot) != reply.Snapshot {
		t.Fatal("selected signer differs from independently qualified resource or delivered source")
	}
	publicOperatorCheckRestore(t, ctx, before, current, next)
	client, err := openPublicOperatorClient(t, ctx, input, "successor", inv.StateDir, current.root.Domain, &next)
	if err != nil {
		t.Fatal("current successor signer context unavailable", err)
	}
	return current, budgetTrust{Trust: client.Trust, budget: budget}, out
}

func runPublicAuthorityOperatorScenario(t testing.TB, ctx context.Context, env fixtureEnvironment, initial *StateSession, name string, inv records.Invocation, input liveRunInput, budget *runBudget, source string) (*StateSession, string) {
	t.Helper()
	replacement := name == publicOperatorReplacementScenario
	disabled := name == publicOperatorDisabledScenario
	if name != publicOperatorAbandonmentScenario && !replacement && !disabled || !publicAuthorityOperator(input) || env.Composition != contract.Hash([]byte("enkv/composition/full/v1")) {
		t.Fatal("native operator scenario construction refused")
	}
	run := newScenarioRun(t, ctx, env)
	env = run.env
	selected := initial
	if selected == nil || selected.root.ChildCount > 32 || selected.root.ChildEncodedBytes > 32<<20 || len(selected.adminIndex.Groups) != 1 {
		t.Fatal("operator scenario requires one bounded selected generated group")
	}
	originalSource := publicSourceImage(t, source)
	group := selected.adminIndex.Groups[0]
	initialBefore := publicOperatorFreeze(t, ctx, selected)
	activeTrust := env.Trust
	var after, current *StateSession
	var finalPlan operatorPlanPayload
	var ended operatorAbandonmentReply
	var endedPayload operatorEndPayload
	var endBefore publicOperatorBefore
	var mutationIdentity contract.ID
	run.phase("transition", func() {
		if replacement || disabled {
			var nextTrust contract.Trust
			selected, nextTrust, source = publicOperatorReplace(t, ctx, inv, input, budget, selected, source, disabled)
			if disabled {
				after = selected
				return
			}
			activeTrust = nextTrust
			control := currentControlOf(selected)
			run.env.Trust = activeTrust
			run.env.SigningSelector = control.NormalSigning.KeySelector
			run.env.PublicKey = bytes.Clone(control.NormalSigning.SPKI)
		}
		listed, result := publicAbandonmentCLI(t, ctx, inv, input, budget, selected, 0, 0, source, "list")
		defer clear(result.Body)
		list := operatorPayload[operatorListPayload](t, listed, "InspectionPayload/v1")
		operatorCheckQuery(t, listed, selected, "", "", "")
		if result.Code != 0 || !operatorObserved(listed) || listed.State != "success" || listed.Replay != "none" || listed.Evidence != "canonical" || list.View != "administrative-list" || list.Revision != operatorIDText(selected.head.Core.Revision) || list.Snapshot != operatorIDText(selected.root.Snapshot) || len(list.Targets) != 1 || len(list.Abandonments) != 0 {
			t.Fatal("native list changed current targets or invented abandonment history")
		}
		target := list.Targets[0]
		if target.GroupID != operatorIDText(group.GroupID) || target.OwnerID != operatorIDText(group.OwnerID) || target.TargetID != operatorIDText(group.TargetID) || target.Kind != "generated-duty" || group.OwnerKind != 2 || target.Blocks != (group.OwnerID == selected.root.Generated.ActiveOwner) || target.Parent != "" || target.OwnerKind != group.OwnerKind || target.DutyKind != group.DutyKind || target.Evidence != group.SelectedEvidenceSummary || target.ChargedPages != group.ChargedPages || target.ChargedBytes != group.ChargedBytes || !target.Selectable || !slices.Equal(target.EvidenceFacts, operatorEvidence(group.SelectedEvidenceSummary)) || len(target.Related) != len(group.RelatedGroupIndexes) {
			t.Fatal("native list lost exact owner, parent or evidence")
		}
		for i, index := range group.RelatedGroupIndexes {
			if int(index) >= len(selected.adminIndex.Groups) || target.Related[i] != operatorIDText(selected.adminIndex.Groups[index].GroupID) {
				t.Fatal("native list changed same-table dependency")
			}
		}
		oldPath := filepath.Join(inv.StateDir, "abandon-before-progress.json")
		old, planned := publicAbandonmentCLI(t, ctx, inv, input, budget, selected, 0, 0, source, "plan", "--target", target.GroupID, "--out", oldPath)
		defer clear(planned.Body)
		if planned.Code != 0 {
			t.Fatal("initial native plan refused")
		}
		oldPlan := operatorCheckPlan(t, old, selected, group, oldPath)
		oldArtifact, err := os.ReadFile(oldPath)
		if err != nil {
			t.Fatal(err)
		}
		selected = operatorAdvanceCurrent(run, selected, activeTrust, "ordinary-between-plan-and-apply")
		beforeStale := publicOperatorFreeze(t, ctx, selected)
		stale, refused := publicAbandonmentCLI(t, ctx, inv, input, budget, selected, 0, 0, source, "stale-apply", "--plan", oldPath)
		defer clear(refused.Body)
		if refused.Code != 2 || stale.State != "refused" || stale.Result.Outcome != "admission_refused" || stale.Result.Reason != "stale_precondition" || stale.Result.CommitMayHaveOccurred || stale.PayloadKind != "none" || string(stale.Payload) != "null" {
			t.Fatal("stale native plan was rebased or gained mutation authority")
		}
		selected = operatorAuthenticatedRead(t, ctx, selected, env.Store)
		if !bytes.Equal(selected.body, beforeStale.HEAD) || selected.token != beforeStale.Token {
			t.Fatal("stale apply changed selected HEAD")
		}
		assertStateImage(t, selected, beforeStale.Image)
		if got, err := os.ReadFile(oldPath); err != nil || !bytes.Equal(got, oldArtifact) {
			t.Fatal("stale apply replaced reviewed artifact", err)
		}
		newPath := filepath.Join(inv.StateDir, "abandon-current.json")
		fresh, planned := publicAbandonmentCLI(t, ctx, inv, input, budget, selected, 0, 0, source, "plan", "--target", target.GroupID, "--out", newPath)
		defer clear(planned.Body)
		if planned.Code != 0 {
			t.Fatal("fresh native replan refused")
		}
		finalPlan = operatorCheckPlan(t, fresh, selected, group, newPath)
		if finalPlan.Preview.Identity == oldPlan.Preview.Identity || finalPlan.Preview.PredecessorRevision == oldPlan.Preview.PredecessorRevision {
			t.Fatal("fresh reviewed plan reused stale predecessor or disposition")
		}
		endBefore = publicOperatorFreeze(t, ctx, selected)
		var applied publicChildResult
		ended, applied = publicAbandonmentCLI(t, ctx, inv, input, budget, selected, finalPlan.Preview.AfterChildCount, finalPlan.Preview.AfterChildBytes, source, "apply", "--plan", newPath)
		defer clear(applied.Body)
		endedPayload = operatorPayload[operatorEndPayload](t, ended, "EndSelectedWorkPayload/v1")
		if applied.Code != 0 || !operatorObserved(ended) || ended.State != "work-ended" || ended.Evidence != "canonical" || !reflect.DeepEqual(endedPayload.Preview, finalPlan.Preview) || !reflect.DeepEqual(endedPayload.Risk, finalPlan.Risk) || endedPayload.OriginalCompletion != "not-established" || endedPayload.PhysicalCleanup != "not-established" || endedPayload.SelectedRights != "ended" || endedPayload.ExclusiveCapacity != "released-as-receipted" || endedPayload.SharedSupport != "retained" || !slices.Equal(ended.Warnings, operatorExpectedWarnings(finalPlan.Preview.WarningBits)) {
			t.Fatal("native apply lost exact disposition or claimed remote completion")
		}
		var identity string
		if json.Unmarshal(ended.Identity, &identity) != nil || identity == "" || ended.Replay != identity {
			t.Fatal("native ending lost actual mutation identity")
		}
		var valid bool
		mutationIdentity, valid = operatorParseID(identity)
		if !valid {
			t.Fatal("native ending lost exact request identity")
		}
		after = operatorAuthenticatedRead(t, ctx, selected, env.Store)
		if after.head.EndWork == nil || ended.OperationID != operatorIDText(after.head.EndWork.OperationID) || after.head.EndWork.TargetGroupID != group.GroupID || after.root.ChildCount != uint32(finalPlan.Preview.AfterChildCount) || after.root.ChildEncodedBytes != finalPlan.Preview.AfterChildBytes {
			t.Fatal("native apply did not select exact prepared successor")
		}
		publicOperatorCheckEnd(t, ctx, endBefore, after, group)
	})
	run.phase("verification", func() {
		if disabled {
			assertStateImage(t, after, initialBefore.Image)
			return
		}
		windows, err := after.receiptWindows(ctx)
		if err != nil || len(windows.Successes) == 0 {
			t.Fatal("complete selected receipt windows unavailable", err)
		}
		row := windows.Successes[len(windows.Successes)-1]
		raw, err := hex.DecodeString(endedPayload.Receipt.Raw)
		decoded, inspectErr := contract.InspectCompactMutationReceipt(raw)
		if err != nil || inspectErr != nil || decoded != row || row.OperationKind != contract.OperationEndSelectedWork || row.AdministrativeGroupID != group.GroupID || row.OperationID != after.head.EndWork.OperationID || endedPayload.Receipt.OperationID != operatorIDText(row.OperationID) || endedPayload.Receipt.Group != operatorIDText(group.GroupID) || endedPayload.Receipt.StoredState != "work-ended" || row.AdministrativeOriginalEvidence != group.SelectedEvidenceSummary {
			t.Fatal("native apply changed exact original receipt", err, inspectErr)
		}
	})
	run.phase("reopen", func() {
		current = operatorReopenCurrent(run, after, activeTrust, disabled)
		listed, result := publicAbandonmentCLI(t, ctx, inv, input, budget, current, 0, 0, source, "list")
		defer clear(result.Body)
		list := operatorPayload[operatorListPayload](t, listed, "InspectionPayload/v1")
		operatorCheckQuery(t, listed, current, "", "", "")
		if result.Code != 0 || !operatorObserved(listed) || list.Revision != operatorIDText(current.head.Core.Revision) || list.Snapshot != operatorIDText(current.root.Snapshot) || listed.Replay != "none" {
			t.Fatal("cold native list lost current authenticated observation")
		}
		if disabled {
			if len(list.Targets) != 1 || list.Targets[0].GroupID != operatorIDText(group.GroupID) || len(list.Abandonments) != 0 {
				t.Fatal("disabled Recovery lost exact current work")
			}
			return
		}
		if current.head.Core.Revision == after.head.Core.Revision || len(list.Targets) != 0 || len(list.Abandonments) != 1 {
			t.Fatal("later native list failed retained result discovery after ordinary progress")
		}
		discovered := list.Abandonments[0]
		if discovered.Group != operatorIDText(group.GroupID) || discovered.OperationID != ended.OperationID || discovered.Raw != endedPayload.Receipt.Raw || discovered.StoredState != "work-ended" {
			t.Fatal("later list confused target and abandonment identities")
		}
		queried, result := publicAbandonmentCLI(t, ctx, inv, input, budget, current, 0, 0, source, "receipt", "--operation", discovered.OperationID)
		defer clear(result.Body)
		receipt := operatorPayload[operatorReceipt](t, queried, "ReceiptPayload/v1")
		operatorCheckQuery(t, queried, current, "", "", discovered.OperationID)
		if result.Code != 0 || !operatorObserved(queried) || queried.State != "success" || queried.Replay != "none" || receipt.OperationID != discovered.OperationID || receipt.Group != discovered.Group || receipt.Raw != discovered.Raw || receipt.StoredState != "work-ended" || !reflect.DeepEqual(receipt, discovered) || queried.OperationID == receipt.OperationID {
			t.Fatal("fresh receipt read changed stored state or borrowed original mutation identity")
		}
		windows, err := current.receiptWindows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range windows.Successes {
			if operatorIDText(row.OperationID) == discovered.OperationID {
				found = true
				if row.AdministrativeGroupID != group.GroupID || row.RequestIdentityDigest != mutationIdentity {
					t.Fatal("later canonical receipt lost exact original identity")
				}
			}
		}
		if !found {
			t.Fatal("later canonical windows lost discoverable abandonment")
		}
	})
	publicImageUnchanged(t, originalSource)
	return current, source
}

func operatorExpectedWarnings(bits uint8) []string {
	out := []string{}
	for _, row := range []struct {
		bit  uint8
		text string
	}{{1, "An old generated effect may still be live."}, {2, "An old destructive request may act after this exit."}, {4, "An old publication may replace a newer value."}, {8, "Original completion and remote cleanup remain unproved; exact discarded evidence cannot be recovered from this exit."}, {16, "Immutable store garbage may remain after this exit."}} {
		if bits&row.bit != 0 {
			out = append(out, row.text)
		}
	}
	return out
}

func operatorEvidence(bits uint16) []string {
	out := []string{}
	for _, row := range []struct {
		bit  uint16
		text string
	}{{1, "missing"}, {2, "qualified-unknown"}, {4, "terminal-failure"}, {8, "deletion-acknowledged"}, {16, "contradiction"}, {32, "invalidation-confirmed"}, {64, "possible-live"}, {128, "release-pending"}, {256, "release-unknown"}, {512, "release-unobserved"}} {
		if bits&row.bit != 0 {
			out = append(out, row.text)
		}
	}
	return out
}
func operatorHistoricalWarnings(bits uint8, evidence uint16) []string {
	out := operatorExpectedWarnings(bits)
	if evidence&64 != 0 {
		out = append(out, "The old effect can still be live; a successful frontier does not close it. No qualified cleanup path is established by this administrative view.")
	}
	if evidence&8 != 0 {
		out = append(out, "Deletion was acknowledged; invalidation is not confirmed for every original effect.")
	}
	return out
}

func publicOperatorCapture(capture nativeprocess.Capture, command string, successor bool) error {
	read := command == "list" || command == "plan" || command == "receipt" || command == "stale-apply"
	if !read && command != "apply" && command != "keys-replace" {
		return errors.New("unknown native operation")
	}
	normalSigns, successorSigns, recoverySigns, heads, reads := 0, 0, 0, 0, 0
	constructions := map[string]int{}
	for _, event := range capture.Events {
		if event.Kind == "construction" {
			key := event.Operation + "/" + event.Role
			if command != "keys-replace" || event.Count != 1 || key != "signing-metadata/successor" && key != "signer/recovery-signing" && key != "signer/successor" {
				return errors.New("native operation constructed an unused capability")
			}
			constructions[key]++
			if constructions[key] != 1 {
				return errors.New("native operation repeated a capability constructor")
			}
			continue
		}
		if event.Kind != "http-start" {
			continue
		}
		if read && event.Operation != "head-read" && event.Operation != "store-read" {
			return errors.New("administrative read attempted a non-GET capability")
		}
		switch event.Operation {
		case "head-read", "store-read":
			if event.Sent {
				reads++
			}
		case "store-write":
		case "kms-public":
			if command != "keys-replace" {
				return errors.New("administrative apply looked up another public resource")
			}
		case "head-write":
			if event.Sent {
				heads++
			}
		case "kms-sign":
			if command == "keys-replace" && event.Role == "recovery-signing" {
				if event.Sent {
					recoverySigns++
				}
			} else if event.Role == "successor" && (command == "keys-replace" || successor) {
				if event.Sent {
					successorSigns++
				}
			} else if command == "apply" && !successor && event.Role == "normal" {
				if event.Sent {
					normalSigns++
				}
			} else {
				return errors.New("native mutation used another private signer")
			}
		default:
			return errors.New("native mutation attempted decryption, LIST or another effect")
		}
	}
	if command == "keys-replace" && (len(constructions) != 3 || constructions["signing-metadata/successor"] != 1 || constructions["signer/recovery-signing"] != 1 || constructions["signer/successor"] != 1) {
		return errors.New("signing-only replacement lost exact constructors")
	}
	if reads == 0 {
		return errors.New("native operation had no actual authenticated GET")
	}
	if read {
		return nil
	}
	if heads != 1 || command == "keys-replace" && (recoverySigns < 1 || recoverySigns > 3 || successorSigns < 3 || successorSigns > 9 || normalSigns != 0) || command == "apply" && (recoverySigns != 0 || successor && (successorSigns != 1 || normalSigns != 0) || !successor && (normalSigns != 1 || successorSigns != 0)) {
		return errors.New("native mutation lost its exact signer or one physical HEAD selection")
	}
	return nil
}

// full_only: false
func TestPublicOperatorCaptureRequiresExactCommandCapabilities(t *testing.T) {
	start := func(op, role string) nativeprocess.Event {
		return nativeprocess.Event{Kind: "http-start", Operation: op, Role: role, Sent: true}
	}
	for _, command := range []string{"list", "plan", "receipt", "stale-apply"} {
		t.Run(command, func(t *testing.T) {
			good := nativeprocess.Capture{Events: []nativeprocess.Event{start("head-read", ""), start("store-read", "")}}
			if publicOperatorCapture(good, command, false) != nil {
				t.Fatal("GET-only operation refused")
			}
			for _, op := range []string{"kms-public", "kms-sign", "kms-decrypt", "store-list", "store-write", "head-write"} {
				bad := nativeprocess.Capture{Events: append(slices.Clone(good.Events), start(op, "normal"))}
				if publicOperatorCapture(bad, command, false) == nil {
					t.Fatal("GET-only operation accepted another capability", op)
				}
			}
			bad := nativeprocess.Capture{Events: append(slices.Clone(good.Events), nativeprocess.Event{Kind: "construction", Operation: "key-access", Role: "authority", Count: 1})}
			if publicOperatorCapture(bad, command, false) == nil {
				t.Fatal("GET-only operation constructed unused private capability")
			}
			if publicOperatorCapture(nativeprocess.Capture{}, command, false) == nil {
				t.Fatal("GET-only proof accepted no actual read")
			}
		})
	}
	for _, row := range []struct {
		name, command string
		successor     bool
		signs         []string
	}{{"current-apply", "apply", false, []string{"normal"}}, {"successor-apply", "apply", true, []string{"successor"}}, {"recovery-replacement", "keys-replace", false, []string{"recovery-signing", "successor", "successor", "successor"}}} {
		t.Run(row.name, func(t *testing.T) {
			good := nativeprocess.Capture{Events: []nativeprocess.Event{start("head-read", ""), start("store-read", ""), start("store-write", ""), start("head-write", "")}}
			for _, role := range row.signs {
				good.Events = append(good.Events, start("kms-sign", role))
			}
			if row.command == "keys-replace" {
				for _, key := range []struct{ purpose, role string }{{"signing-metadata", "successor"}, {"signer", "recovery-signing"}, {"signer", "successor"}} {
					good.Events = append(good.Events, nativeprocess.Event{Kind: "construction", Operation: key.purpose, Role: key.role, Count: 1})
				}
			}
			if publicOperatorCapture(good, row.command, row.successor) != nil {
				t.Fatal("exact native capabilities refused")
			}
			for _, event := range []nativeprocess.Event{start("kms-decrypt", "authority"), start("kms-decrypt", "recovery-private"), start("store-list", ""), start("kms-sign", "ordinary"), start("head-write", "")} {
				bad := nativeprocess.Capture{Events: append(slices.Clone(good.Events), event)}
				if publicOperatorCapture(bad, row.command, row.successor) == nil {
					t.Fatal("native operation accepted another capability or second physical CAS")
				}
			}
			if row.successor || row.command == "keys-replace" {
				bad := nativeprocess.Capture{Events: append(slices.Clone(good.Events), start("kms-sign", "normal"))}
				if publicOperatorCapture(bad, row.command, row.successor) == nil {
					t.Fatal("successor command used old Normal signer")
				}
			}
			for _, purpose := range []string{"key-access", "public-qualifier", "encryption-metadata"} {
				bad := nativeprocess.Capture{Events: append(slices.Clone(good.Events), nativeprocess.Event{Kind: "construction", Operation: purpose, Role: "successor", Count: 1})}
				if publicOperatorCapture(bad, row.command, row.successor) == nil {
					t.Fatal("signing-only operation constructed unused purpose", purpose)
				}
			}
			if row.command == "keys-replace" {
				for _, role := range []string{"recovery-signing", "successor"} {
					bad := nativeprocess.Capture{Events: slices.DeleteFunc(slices.Clone(good.Events), func(e nativeprocess.Event) bool {
						return e.Kind == "construction" && e.Operation == "signer" && e.Role == role
					})}
					if publicOperatorCapture(bad, row.command, row.successor) == nil {
						t.Fatal("signing-only operation lost required constructor", role)
					}
				}
			}
			for _, missing := range []string{"head-write", "kms-sign"} {
				bad := nativeprocess.Capture{Events: slices.DeleteFunc(slices.Clone(good.Events), func(e nativeprocess.Event) bool { return e.Operation == missing })}
				if publicOperatorCapture(bad, row.command, row.successor) == nil {
					t.Fatal("native command lost required selection or signing capability")
				}
			}
		})
	}
}

// full_only: false
func TestPublicOperatorResultPreservesStoreReasonAndWarnings(t *testing.T) {
	body := []byte(`{"schema":"ProductResult/v1","operation_kind":"abandon-list","state_result":"unavailable","effect_summary":"not-applicable","output_summary":"not-applicable","request_identity":null,"operation_id":"read-operation","request_id":"read-nonce","domain_id":"domain","result":{"outcome":"evidence_unavailable","reason":"read_unavailable","store_reason":"access","observed_revision":"retained-observation","requested_revision":"exact-request","commit_may_have_occurred":false},"evidence_ceiling":"unavailable","replay_identity":"none","commit_may_have_occurred":false,"warning_summary":["first retained warning","second retained warning"],"delivery":{"plan_created":false,"plan_synced":false,"plan_readback":false,"plan_failed":false,"cleanup_failed":false},"effects":[],"outputs":[],"duties":[],"hazards":[],"capsule_policy":"none","operation_payload":"none","payload":null}`)
	reply, err := operatorAbandonmentResult(body)
	if err != nil || reply.Result.StoreReason != "access" || reply.Result.ObservedRevision != "retained-observation" || reply.Result.RequestedRevision != "exact-request" || !slices.Equal(reply.Warnings, []string{"first retained warning", "second retained warning"}) || operatorObserved(reply) {
		t.Fatal("native result lost exact provider cause, observation or warnings", err)
	}
	reply.Result.Outcome, reply.Result.Reason = "observed_current", "none"
	if operatorObserved(reply) {
		t.Fatal("provider failure was promoted to successful observation")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		t.Fatal("test input")
	}
	object["retired_alias"] = json.RawMessage(`true`)
	damaged, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operatorAbandonmentResult(damaged); err == nil {
		t.Fatal("native result decoder accepted retired field")
	}
}
