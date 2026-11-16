package compositionfull

import (
	"encoding/json"
	"strconv"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

const applyResultDiagnosticBytes = uint64(core.MaxApplyResultDiagnostics) * 3428

// Let S=GeneratedResultSupportBytes, A=floor(S/797), W=floor(S/692),
// P=floor(S/270)+2*floor(S/1045). The 32*S term pays distinct charges:
// 6144*(A+W) complete fact/target rows; 512*P progress; 512*A original release
// fields; 512*(2*W+2) next-action rows; 67*W related IDs; 67*W all remaining
// cleanup IDs; 67*(2*65535) terminal sibling IDs; 1024*W hazard warnings.
// These total 12,495,575,736 < 32*S = 17,179,254,784. Human row labels/captions
// add at most 2048*(A+W), and full human release records add 1024*A; their
// disjoint total is 16,153,676,472, still below 32*S. Dormant template/current
// rows use the separate 8192-row term. The added 512*A below pays the five cleanup
// origin/status fields; source and one owned Store location have separate
// 2048/1024 reserves. Header, receipts, preparation and diagnostics are separate.
const generatedResultOutputLimit = uint64(65536+8192*(contract.GeneratorMaxTemplates+contract.GeneratedCurrentEntryLimit)+2*contract.CompactMutationReceiptLength) + 32*core.GeneratedResultSupportBytes + applyPreparationFieldBytes + applyResultDiagnosticBytes + 512*core.GeneratedResultAttemptLimit + 2048 + 1024
const generatedResultRowLimit = 4096

type generatedResultWriter struct {
	body                          []byte
	size                          uint64
	err                           error
	layout                        *resultJSONLayout
	formattedSize, formattedLimit uint64
}

func (w *generatedResultWriter) raw(b []byte) {
	if w.err != nil {
		return
	}
	if uint64(len(b)) > generatedResultOutputLimit-w.size {
		w.err = errApplyResult
		return
	}
	w.size += uint64(len(b))
	if w.layout != nil {
		if err := w.layout.write(string(b), w.formattedText); err != nil {
			w.err = errApplyResult
		}
		return
	}
	if w.body != nil {
		if len(b) > cap(w.body)-len(w.body) {
			w.err = errApplyResult
			return
		}
		w.body = append(w.body, b...)
	}
}

func (w *generatedResultWriter) formattedText(s string) {
	if w.err != nil {
		return
	}
	if uint64(len(s)) > w.formattedLimit-w.formattedSize {
		w.err = errApplyResult
		return
	}
	w.formattedSize += uint64(len(s))
	if w.body != nil {
		if len(s) > cap(w.body)-len(w.body) {
			w.err = errApplyResult
			return
		}
		w.body = append(w.body, s...)
	}
}

func (w *generatedResultWriter) finishJSON() {
	if w.err == nil && w.layout != nil {
		if err := w.layout.finish(w.formattedText); err != nil {
			w.err = errApplyResult
		}
	}
}
func (w *generatedResultWriter) text(s string) { w.raw([]byte(s)) }
func (w *generatedResultWriter) value(v any) {
	if w.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > generatedResultRowLimit {
		w.err = errApplyResult
		return
	}
	w.raw(b)
}

func renderGeneratedResult(emit func(*generatedResultWriter)) ([]byte, error) {
	count := &generatedResultWriter{}
	emit(count)
	if count.err != nil || count.size > uint64(int(^uint(0)>>1)) {
		return nil, errApplyResult
	}
	out := &generatedResultWriter{body: make([]byte, 0, int(count.size))}
	emit(out)
	if out.err != nil || out.size != count.size || len(out.body) != cap(out.body) {
		return nil, errApplyResult
	}
	return out.body, nil
}

func renderReadableGeneratedResult(emit func(*generatedResultWriter)) ([]byte, error) {
	layout := resultJSONLayout{compactLimit: generatedResultOutputLimit}
	count := &generatedResultWriter{layout: &layout, formattedLimit: 67 * generatedResultOutputLimit}
	emit(count)
	count.finishJSON()
	if count.err != nil || count.formattedSize > uint64(int(^uint(0)>>1)) {
		return nil, errApplyResult
	}
	layout = resultJSONLayout{compactLimit: generatedResultOutputLimit}
	out := &generatedResultWriter{body: make([]byte, 0, int(count.formattedSize)), layout: &layout, formattedLimit: count.formattedSize}
	emit(out)
	out.finishJSON()
	if out.err != nil || out.size != count.size || out.formattedSize != count.formattedSize || len(out.body) != cap(out.body) {
		clear(out.body)
		return nil, errApplyResult
	}
	return out.body, nil
}

type generatedResultDocument struct {
	w            *generatedResultWriter
	human, first bool
}

func newGeneratedResultDocument(w *generatedResultWriter, human bool) *generatedResultDocument {
	if !human {
		w.text("{")
	}
	return &generatedResultDocument{w: w, human: human, first: true}
}
func (d *generatedResultDocument) key(name string) {
	if d.human {
		d.w.text(name + ": ")
		return
	}
	if !d.first {
		d.w.text(",")
	}
	d.first = false
	d.w.value(name)
	d.w.text(":")
}
func (d *generatedResultDocument) endField() {
	if d.human {
		d.w.text("\n")
	}
}
func (d *generatedResultDocument) field(name string, value any) {
	d.key(name)
	d.w.value(value)
	d.endField()
}
func (d *generatedResultDocument) array(name string, count int, emit func(int)) {
	d.key(name)
	d.w.text("[")
	for i := 0; i < count; i++ {
		if i != 0 {
			d.w.text(",")
		}
		emit(i)
		if d.w.err != nil {
			break
		}
	}
	d.w.text("]")
	d.endField()
}
func (d *generatedResultDocument) finish() {
	if !d.human {
		d.w.text("}")
	}
}

func generatedID(id contract.ID) any {
	if id.IsZero() {
		return nil
	}
	return readerID(id)
}
func generatedDescriptor(v *contract.GeneratorDescriptor) any {
	if v == nil {
		return nil
	}
	return struct {
		Count  uint32 `json:"count"`
		Length uint64 `json:"length"`
		Digest string `json:"digest"`
	}{v.Count, v.Length, readerID(v.Digest)}
}
func generatedEffectSummary(v uint16) string {
	values := [...]string{"not-applicable", "effect-no-change", "effect-complete", "effect-pending", "effect-partial", "effect-unknown", "effect-mixed-terminal", "effect-failed"}
	if int(v) >= len(values) {
		return ""
	}
	return values[v]
}
func generatedEvidence(v uint16) string {
	values := [...]string{"unavailable", "canonical", "provider-facts", "deletion-acknowledged", "invalidation-confirmed", "mixed-completion"}
	if int(v) >= len(values) {
		return ""
	}
	return values[v]
}
func generatedCompletion(v uint8) string {
	switch v {
	case contract.GeneratedCompletionAcknowledged:
		return "deletion-acknowledged"
	case contract.GeneratedCompletionConfirmed:
		return "invalidation-confirmed"
	}
	return ""
}
func generatedLifecycleCompletion(mode contract.GeneratorLifecycleMode, completion uint8) any {
	if mode == contract.GeneratorLifecycleNone {
		return nil
	}
	return generatedCompletion(completion)
}
func generatedEffectState(v uint8) string {
	values := [...]string{"", "not-started", "prepared", "transmitted", "succeeded", "confirmed-no-effect", "failed-terminal", "unknown", "possible-live", "closed-with-residue"}
	if int(v) >= len(values) {
		return ""
	}
	return values[v]
}
func generatedWarnings(v core.GeneratedResultWarnings) any {
	return struct {
		PossibleLive             bool `json:"possible_live_residue"`
		LateEffect               bool `json:"late_effect"`
		InvalidationNotConfirmed bool `json:"invalidation_not_confirmed"`
	}{v.PossibleLiveResidue, v.LateEffect, v.InvalidationNotConfirmed}
}
func generatedLifecycle(mode contract.GeneratorLifecycleMode) any {
	switch mode {
	case contract.GeneratorLifecycleNone:
		return "none"
	case contract.GeneratorLifecycleManaged:
		return "managed"
	}
	return nil
}

func generatedCurrentGeneration(p core.GeneratedCurrentGeneration) map[string]any {
	return map[string]any{"name": p.Name, "entry_incarnation_id": readerID(p.EntryIncarnationID), "generation_id": readerID(p.GenerationID), "epoch": p.Epoch, "origin_operation_id": readerID(p.OriginOperationID), "origin_attempt_id": readerID(p.OriginAttemptID), "resource_incarnation_id": readerID(p.ResourceID), "config_contract_id": readerID(p.ConfigContractID), "resource_contract_id": generatedID(p.ResourceContractID), "resource_digest": generatedID(p.ResourceDigest), "lifecycle_mode": generatedLifecycle(p.LifecycleMode), "completion_class": generatedLifecycleCompletion(p.LifecycleMode, p.CompletionClass), "retirement_policy": generatedPlanningPolicy(p.RetirementMode), "retiring_duty_id": generatedID(p.RetiringDutyID)}
}

func generatedTarget(v *contract.GeneratorTarget) any {
	if v == nil {
		return nil
	}
	return map[string]any{"name": v.Name, "entry_incarnation_id": readerID(v.IncarnationID), "epoch": v.Epoch, "resource_incarnation_id": readerID(v.ResourceID), "config_contract_id": readerID(v.ConfigContractID), "resource_contract_id": generatedID(v.ResourceContractID), "resource_digest": generatedID(v.ResourceDigest), "lifecycle_mode": generatedLifecycle(v.LifecycleMode), "original_operation_id": readerID(v.OriginalOperationID), "original_attempt_id": readerID(v.OriginalAttemptID), "result_contract_id": readerID(v.ResultContractID), "completion_class": generatedLifecycleCompletion(v.LifecycleMode, v.CompletionClass)}
}

type generatedFactWriter interface {
	text(string)
	value(any)
}

func writeGeneratedProgress(w generatedFactWriter, rows []contract.GeneratorProgress) {
	w.text("[")
	for i, p := range rows {
		if i != 0 {
			w.text(",")
		}
		w.value(map[string]any{"attempt_id": readerID(p.AttemptID), "result_id": readerID(p.ResultID), "required_steps": p.RequiredSteps, "completed_steps": p.CompletedSteps, "completion_class": generatedCompletion(p.CompletionClass), "evidence": generatedDescriptor(&p.Evidence)})
	}
	w.text("]")
}
func writeGeneratedEffect(w generatedFactWriter, v core.GeneratedEffectFact) {
	w.text(`{"facts":`)
	w.value(generatedEffectFacts(v))
	w.text(`,"target":`)
	w.value(generatedTarget(v.Target))
	w.text(`,"progress":`)
	writeGeneratedProgress(w, v.Progress)
	w.text("}")
}
func writeGeneratedDuty(w generatedFactWriter, v core.GeneratedDutyFact) {
	w.text(`{"facts":`)
	w.value(generatedDutyFacts(v))
	w.text(`,"target":`)
	w.value(generatedTarget(v.Target))
	w.text(`,"progress":`)
	writeGeneratedProgress(w, v.Progress)
	w.text("}")
}
func writeGeneratedHazard(w generatedFactWriter, v core.GeneratedHazardFact) {
	w.text(`{"facts":`)
	w.value(generatedHazardFacts(v))
	w.text(`,"target":`)
	w.value(generatedTarget(v.Target))
	w.text("}")
}
func writeGeneratedIDs(d *generatedResultDocument, name string, ids []contract.ID) {
	d.array(name, len(ids), func(i int) { d.w.value(readerID(ids[i])) })
}
func writeGeneratedCounts(d *generatedResultDocument, counts [contract.ReceiptSummaryCount]uint32) {
	names := [...]string{"effects", "outputs", "duties", "hazards", "changed_access", "succeeded", "failed", "neutral", "pending", "unknown", "preserved_residue", "no_effect_predecessors"}
	d.key("summary_counts")
	d.w.text("{")
	for i, n := range counts {
		if i != 0 {
			d.w.text(",")
		}
		d.w.value(names[i])
		d.w.text(":" + strconv.FormatUint(uint64(n), 10))
	}
	d.w.text("}")
	d.endField()
}

func writeGeneratedHazardWarnings(w generatedFactWriter, hazards []core.GeneratedHazardFact, required []bool) {
	for at, v := range hazards {
		if v.Record.Exposure != contract.GeneratedExposurePossibleLive && (required == nil || !required[at]) {
			continue
		}
		w.text("Warning: The old effect can still be live. A succeeded frontier does not close this hazard.\n")
		w.text("Hazard ID: " + readerID(v.Record.HazardID) + "; Attempt ID: " + readerID(v.Record.OriginalAttemptID) +
			"; resource incarnation ID: " + readerID(v.Record.ResourceID) + "; evidence ceiling: " + generatedEvidence(v.EvidenceCeiling) + ".\n")
		w.text("Descriptor ID: " + readerID(v.Record.DescriptorID) + "; credential route ID: " + readerID(v.Record.CredentialRouteID) + ".\n")
		if v.Target != nil {
			w.text("Resource contract ID: " + readerID(v.Target.ResourceContractID) + "; resource digest: " + readerID(v.Target.ResourceDigest) + ".\n")
		}
		if v.CleanupImplementationQualified {
			w.text("generated cleanup can use the currently qualified cleanup implementation. Current eligibility still applies.\n")
		} else {
			w.text("No qualified cleanup path is available.\n")
		}
	}
}

func writeGeneratedCleanup(w *generatedResultWriter, p *core.GeneratedCleanupPayload) {
	d := newGeneratedResultDocument(w, false)
	d.field("schema", "CleanupPayload/v2")
	d.field("predecessor_revision_id", generatedID(p.PredecessorRevisionID))
	d.key("basis")
	basis := newGeneratedResultDocument(w, false)
	b := p.Basis
	basis.field("kind", b.Kind)
	basis.field("plan_graph_id", generatedID(b.PlanGraphID))
	basis.field("source_kind", b.SourceKind)
	basis.field("source_id", generatedID(b.SourceID))
	basis.field("original_owner_id", generatedID(b.OriginalOwnerID))
	basis.field("original_operation_id", generatedID(b.OriginalOperationID))
	basis.field("original_attempt_id", generatedID(b.OriginalAttemptID))
	if r := b.OriginalResult; r != nil {
		basis.field("original_result", map[string]any{"schema": r.Schema, "result_id": readerID(r.ResultID), "body_digest": readerID(r.ResultBodyDigest), "length": r.ResultLength})
	} else {
		basis.field("original_result", nil)
	}
	basis.field("target", generatedTarget(b.Target))
	basis.finish()
	ref := p.RemainingWorkBasis.Snapshot
	d.field("remaining_work_basis", map[string]any{"head_revision_id": readerID(p.RemainingWorkBasis.HeadRevisionID), "snapshot": map[string]any{"kind": ref.Kind, "domain_id": readerID(ref.Domain), "object_id": readerID(ref.Object), "digest": readerID(ref.Digest), "format": ref.Format, "length": ref.Length, "index": ref.Index}})
	d.field("sibling_results", map[string]any{"count": p.SiblingResults.Count, "root_digest": readerID(p.SiblingResults.RootDigest)})
	writeGeneratedIDs(d, "remaining_duty_ids", p.RemainingDutyIDs)
	writeGeneratedIDs(d, "remaining_hazard_ids", p.RemainingHazardIDs)
	writeGeneratedIDs(d, "remaining_inbox_ids", p.RemainingInboxIDs)
	d.finish()
}

func generatedEffectFacts(v core.GeneratedEffectFact) map[string]any {
	r := v.Record
	return map[string]any{"operation_id": readerID(r.OperationID), "lineage_id": readerID(r.LineageID), "attempt_id": readerID(r.AttemptID), "predecessor_attempt_id": generatedID(r.PredecessorAttemptID), "action": map[uint8]string{contract.GeneratorActionCreate: "create", contract.GeneratorActionDelete: "delete"}[v.Action], "name": v.Name, "entry_incarnation_id": readerID(v.EntryIncarnationID), "epoch": v.Epoch, "planned_value_slot_id": readerID(v.PlannedValueSlotID), "planned_resource_incarnation_id": readerID(r.ResourceID), "resource_digest": generatedID(v.ResourceDigest), "generation_id": generatedID(v.GenerationID), "duty_id": generatedID(v.DutyID), "hazard_id": generatedID(v.HazardID), "transmission_id": readerID(r.TransmissionID), "result_id": readerID(r.ResultID), "descriptor_id": readerID(r.DescriptorID), "config_contract_id": readerID(r.ConfigContractID), "resource_contract_id": generatedID(r.ResourceContractID), "executor_id": readerID(r.ExecutorID), "credential_route_id": generatedID(r.CredentialRouteID), "result_contract_id": readerID(r.ResultContractID), "lifecycle_mode": generatedLifecycle(r.LifecycleMode), "state": generatedEffectState(r.State), "stage": r.Stage, "retry_consumed": r.RetryUsed == 1, "completion_class": generatedLifecycleCompletion(r.LifecycleMode, r.CompletionClass), "reason": v.Reason, "evidence_ceiling": generatedEvidence(v.EvidenceCeiling), "summary_class": v.SummaryClass, "warnings": generatedWarnings(v.Warnings)}
}

func generatedDutyFacts(v core.GeneratedDutyFact) map[string]any {
	r := v.Record
	return map[string]any{"duty_id": readerID(r.DutyID), "original_operation_id": readerID(r.OriginalOperationID), "original_attempt_id": readerID(r.OriginalAttemptID), "owner_id": readerID(r.OwnerID), "resource_incarnation_id": readerID(r.ResourceID), "descriptor_id": readerID(r.DescriptorID), "config_contract_id": readerID(r.ConfigContractID), "resource_contract_id": generatedID(r.ResourceContractID), "executor_id": readerID(r.ExecutorID), "credential_route_id": generatedID(r.CredentialRouteID), "result_contract_id": readerID(r.ResultContractID), "lifecycle_mode": generatedLifecycle(r.LifecycleMode), "kind": map[uint8]string{contract.GeneratedDutyCreate: "create", contract.GeneratedDutyRetirement: "retirement", contract.GeneratedDutyUnselectedCleanup: "unselected-generated-cleanup"}[r.Kind], "status": generatedEffectState(r.Status), "step": r.Step, "completion_class": generatedLifecycleCompletion(r.LifecycleMode, r.CompletionClass), "generation_id": generatedID(v.GenerationID), "retirement_policy": generatedPlanningPolicy(v.RetirementMode), "evidence_ceiling": generatedEvidence(v.EvidenceCeiling), "warnings": generatedWarnings(v.Warnings)}
}

func generatedHazardFacts(v core.GeneratedHazardFact) map[string]any {
	r := v.Record
	return map[string]any{"hazard_id": readerID(r.HazardID), "original_operation_id": readerID(r.OriginalOperationID), "original_attempt_id": readerID(r.OriginalAttemptID), "owner_id": readerID(r.OwnerID), "resource_incarnation_id": readerID(r.ResourceID), "descriptor_id": readerID(r.DescriptorID), "config_contract_id": readerID(r.ConfigContractID), "resource_contract_id": generatedID(r.ResourceContractID), "executor_id": readerID(r.ExecutorID), "credential_route_id": readerID(r.CredentialRouteID), "result_contract_id": readerID(r.ResultContractID), "lifecycle_mode": generatedLifecycle(contract.GeneratorLifecycleManaged), "exposure": map[uint8]string{contract.GeneratedExposurePossibleLive: "possible-live", contract.GeneratedExposureLateEffect: "late-effect"}[r.Exposure], "fenced": r.Fenced == 1, "eligibility": r.Eligibility, "cleanup_result_contract_id": generatedID(v.CleanupResultContractID), "cleanup_implementation_qualified": v.CleanupImplementationQualified, "completion_class": generatedCompletion(r.CompletionClass), "generation_id": generatedID(v.GenerationID), "retirement_policy": generatedPlanningPolicy(v.RetirementMode), "evidence_ceiling": generatedEvidence(v.EvidenceCeiling), "warnings": generatedWarnings(v.Warnings)}
}
