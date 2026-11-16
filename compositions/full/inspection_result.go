package compositionfull

import (
	"context"
	"io"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func WriteInspectionJSON(ctx context.Context, out io.Writer, r core.PublicDomainInspectionResult) error {
	return writeInspection(ctx, out, r, false, nil)
}
func WriteInspectionHuman(ctx context.Context, out io.Writer, r core.PublicDomainInspectionResult) error {
	return writeInspection(ctx, out, r, true, nil)
}
func WriteRecipientInspectionJSON(ctx context.Context, out io.Writer, r core.PublicRecipientInspectionResult) error {
	return writeRecipientInspection(ctx, out, r, false, nil)
}
func WriteRecipientInspectionHuman(ctx context.Context, out io.Writer, r core.PublicRecipientInspectionResult) error {
	return writeRecipientInspection(ctx, out, r, true, nil)
}

func validateInspection(r core.PublicDomainInspectionResult) error {
	if err := r.ValidateMetadataWorkOutput(); err != nil {
		return err
	}
	if v := r.View; v != nil {
		g := v.Generated
		borrowed := core.GeneratedListView{DomainID: v.Observation.DomainID, RevisionID: v.Observation.HeadRevisionID, SnapshotID: v.Observation.SnapshotID, CurrentGenerations: g.CurrentGenerations, ActiveOperation: v.ActiveOperation, Effects: g.Effects, Duties: g.Duties, Hazards: g.Hazards, PendingReleases: g.PendingReleases, NextActions: g.NextActions, DomainWarningBits: v.DomainWarningBits, Warnings: v.Warnings.Generated, PossibleGarbage: v.Warnings.PossibleStoreGarbage}
		return validateGeneratedList(core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: r.RequestID, ExpectedDomain: r.DomainID}, Result: r.Result, StateResult: contract.ReaderSuccess, View: &borrowed})
	}
	return nil
}

func writeInspection(ctx context.Context, out io.Writer, r core.PublicDomainInspectionResult, human bool, sourceFailure *ConfigurationSourceFailure, locations ...*resultStoreLocation) error {
	if err := validateInspection(r); err != nil {
		return ErrPublicQueryResult
	}
	var location *resultStoreLocation
	if len(locations) != 0 {
		location = locations[0]
	}
	if !location.valid(r.DomainID, r.Result) || location != nil && r.View == nil {
		return ErrPublicQueryResult
	}
	var emit func(*queryObject)
	kind := "none"
	if v := r.View; v != nil {
		kind = contract.InspectionPayloadSchema
		emit = func(q *queryObject) {
			if q.human {
				inspectionDomainHuman(q, v)
				return
			}
			q.field("schema", kind)
			q.field("form", "domain")
			q.object("observation", func(o *queryObject) { queryObservation(o, v.Observation) })
			q.array("entries", len(v.Entries), func(i int) { o := q.begin(); inspectionEntryFields(o, v.Entries[i]); o.end() })
			q.array("recipients", len(v.Recipients), func(i int) {
				p := v.Recipients[i]
				o := q.begin()
				o.id("recipient_id", p.RecipientID)
				o.field("status", p.Status)
				o.field("display_name", p.DisplayName)
				o.id("binding_id", p.BindingID)
				o.field("binding_serial", p.BindingSerial)
				o.id("binding_fingerprint", p.BindingFingerprint)
				o.end()
			})
			if p := v.ActiveOperation; p != nil {
				q.object("active_operation", func(o *queryObject) {
					o.id("operation_id", p.OperationID)
					o.field("operation_kind", p.OperationKind)
					o.id("phase_id", p.PhaseID)
					o.field("phase", p.Phase)
					o.field("stage", p.Stage)
					o.id("frontier_attempt_id", p.FrontierAttemptID)
				})
			} else {
				q.field("active_operation", nil)
			}
			q.object("generated", func(o *queryObject) { inspectionGenerated(o, v.Generated) })
			q.object("work", func(o *queryObject) { inspectionWork(o, v.Work) })
			q.object("output", func(o *queryObject) { inspectionOutput(o, v.Output) })
			q.field("domain_warning_bits", v.DomainWarningBits)
			q.object("warnings", func(o *queryObject) {
				o.object("domain", func(d *queryObject) { queryDomainWarnings(d, v.Warnings.Domain) })
				o.field("generated", generatedWarnings(v.Warnings.Generated))
				o.object("output", func(d *queryObject) { inspectionOutputWarnings(d, v.Warnings.Output) })
				o.field("possible_store_garbage", v.Warnings.PossibleStoreGarbage)
			})
		}
	}
	return writePublicQuery(ctx, out, r.PublicQueryResult, human, kind, emit, nil, sourceFailure, location)
}

func writeRecipientInspection(ctx context.Context, out io.Writer, r core.PublicRecipientInspectionResult, human bool, sourceFailure *ConfigurationSourceFailure) error {
	if err := r.Validate(); err != nil {
		return ErrPublicQueryResult
	}
	var emit func(*queryObject)
	kind := "none"
	if v := r.View; v != nil {
		kind = contract.InspectionPayloadSchema
		emit = func(q *queryObject) {
			q.field("schema", kind)
			q.field("form", "recipient")
			if q.human {
				inspectionObservationHuman(q.w, v.Observation)
			} else {
				q.object("observation", func(o *queryObject) { queryObservation(o, v.Observation) })
			}
			q.id("recipient_id", v.RecipientID)
			q.array("entries", len(v.Entries), func(i int) { p := v.Entries[i]; o := q.begin(); recipientInspectionEntryFields(o, p); o.end() })
		}
	}
	return writePublicQuery(ctx, out, r.PublicQueryResult, human, kind, emit, nil, sourceFailure)
}

func recipientInspectionEntryFields(o *queryObject, p core.RecipientInspectionEntry) {
	o.field("name", p.Name)
	o.id("incarnation_id", p.IncarnationID)
	o.id("value_state_id", p.ValueStateID)
	if o.human {
		o.field("value_source", inspectionSourceHuman(p.ValueSource))
	} else {
		o.field("value_source", p.ValueSource)
	}
	o.field("confidential", p.Confidential)
	if !o.human {
		o.field("raw_length", p.RawLength)
	}
	if p.ValueSource == contract.Generated {
		o.id("generation_id", p.GenerationID)
		o.field("epoch", p.Epoch)
	}
}
func inspectionEntryFields(o *queryObject, p core.InspectionEntry) {
	o.field("slot", p.Slot)
	recipientInspectionEntryFields(o, core.RecipientInspectionEntry{Name: p.Name, IncarnationID: p.IncarnationID, ValueStateID: p.ValueStateID, ValueSource: p.ValueSource, Confidential: p.Confidential, RawLength: p.RawLength, GenerationID: p.GenerationID, Epoch: p.Epoch})
	queryIDs(o, "recipient_ids", p.RecipientIDs)
	if p.ValueSource == contract.Generated {
		if p.RetirementMode == 0 {
			o.field("retirement_mode", nil)
		} else {
			o.field("retirement_mode", p.RetirementMode)
		}
	}
}

func inspectionGenerated(o *queryObject, v core.InspectionGeneratedWork) {
	o.array("current_generations", len(v.CurrentGenerations), func(i int) {
		o.value(generatedCurrentGeneration(v.CurrentGenerations[i]))
	})
	o.array("effects", len(v.Effects), func(i int) {
		p := v.Effects[i]
		writeGeneratedEffect(o.w, p)
	})
	o.array("duties", len(v.Duties), func(i int) {
		p := v.Duties[i]
		writeGeneratedDuty(o.w, p)
	})
	o.array("hazards", len(v.Hazards), func(i int) {
		p := v.Hazards[i]
		writeGeneratedHazard(o.w, p)
	})
	o.array("pending_releases", len(v.PendingReleases), func(i int) {
		p := v.PendingReleases[i]
		q := o.begin()
		q.field("schema", p.Schema)
		q.id("domain_id", p.DomainID)
		q.id("inbox_id", p.InboxID)
		q.id("original_result_id", p.OriginalResultID)
		q.id("selected_handoff_digest", p.SelectedHandoffDigest)
		q.id("handoff_revision_id", p.HandoffRevisionID)
		queryDescriptor(q, "capacity_reservation", p.CapacityReservation)
		q.field("object_length", p.ObjectLength)
		q.field("state", p.State)
		q.id("original_operation_id", p.OriginalOperationID)
		q.id("original_attempt_id", p.OriginalAttemptID)
		q.field("action", map[uint8]string{contract.GeneratorActionCreate: "create", contract.GeneratorActionDelete: "delete"}[p.Action])
		q.field("effect_state", generatedEffectState(p.EffectState))
		var completion any
		if p.CompletionClass != 0 {
			completion = generatedCompletion(p.CompletionClass)
		}
		q.field("completion_class", completion)
		q.end()
	})
	o.array("next_actions", len(v.NextActions), func(i int) {
		p := v.NextActions[i]
		q := o.begin()
		q.field("command", p.Command)
		q.field("operation_id", generatedID(p.OperationID))
		q.field("duty_id", generatedID(p.DutyID))
		q.field("attempt_id", generatedID(p.AttemptID))
		q.end()
	})
}

func inspectionWork(o *queryObject, v core.InspectionWork) {
	o.array("groups", len(v.Groups), func(i int) {
		p := v.Groups[i]
		s := v.GroupSelections[i]
		q := o.begin()
		q.id("group_id", p.GroupID)
		q.id("owner_id", p.OwnerID)
		q.id("target_id", p.TargetID)
		q.field("owner_kind", p.OwnerKind)
		q.field("duty_kind", p.DutyKind)
		q.field("effect_entry_ceiling", p.EffectEntryCeiling)
		q.field("selected_evidence_summary", p.SelectedEvidenceSummary)
		q.field("destructive_effect", p.DestructiveEffect != 0)
		q.field("uncertain_create_proof", p.UncertainCreateProof != 0)
		queryDescriptor(q, "affected", p.Affected)
		queryDescriptor(q, "dependencies", p.Dependencies)
		queryDescriptor(q, "disposable", p.Disposable)
		q.field("charged_pages", p.ChargedPages)
		q.field("charged_bytes", p.ChargedBytes)
		queryIndexes(q, "related_group_indexes", p.RelatedGroupIndexes)
		q.id("publication_incarnation_id", p.PublicationIncarnationID)
		q.field("admission_ordinal", p.AdmissionOrdinal)
		if p.GC != nil {
			v, err := publicGCProgress(p.GC)
			if err != nil {
				o.w.err = err
				return
			}
			q.field("gc", v)
		}
		q.field("selectable", s.Selectable)
		q.field("required_parent_index", s.RequiredParentIndex)
		q.end()
	})
	o.array("pages", len(v.Pages), func(i int) {
		p := v.Pages[i]
		q := o.begin()
		q.object("ref", func(r *queryObject) { inspectionRef(r, p.Ref) })
		q.field("read_required", p.ReadRequired)
		q.array("spans", len(p.Spans), func(i int) {
			s := p.Spans[i]
			r := q.begin()
			r.field("first", s.First)
			r.field("count", s.Count)
			r.field("mandatory", s.Mandatory)
			queryIndexes(r, "group_indexes", s.GroupIndexes)
			r.end()
		})
		q.array("rows", len(p.Rows), func(i int) {
			s := p.Rows[i]
			r := q.begin()
			r.field("kind", s.Kind)
			r.id("record_id", s.RecordID)
			r.field("body_length", s.BodyLength)
			if !s.MaterialID.IsZero() {
				r.id("material_id", s.MaterialID)
			}
			r.end()
		})
		q.end()
	})
	o.array("publication_order", len(v.PublicationOrder), func(i int) {
		p := v.PublicationOrder[i]
		q := o.begin()
		q.id("coordinate_id", p.CoordinateID)
		queryIDs(q, "incarnations", p.Incarnations)
		q.end()
	})
}
func inspectionRef(q *queryObject, v format.Ref) {
	q.field("kind", v.Kind)
	q.id("domain_id", v.Domain)
	q.id("object_id", v.Object)
	q.id("digest", v.Digest)
	q.field("format", v.Format)
	q.field("length", v.Length)
	q.field("index", v.Index)
}
