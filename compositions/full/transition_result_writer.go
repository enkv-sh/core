package compositionfull

func transitionResultFields(q *queryObject, v transitionResultRecord) {
	if v.SourceFailure != nil {
		q.field("source_failure", v.SourceFailure)
	}
	q.field("schema", v.Schema)
	q.field("operation_kind", v.Operation)
	q.field("state_result", v.State)
	q.field("effect_summary", v.Effect)
	q.field("output_summary", v.Output)
	q.field("request_id", v.Request)
	if v.OperationID != "" {
		q.field("operation_id", v.OperationID)
	}
	if v.RequestIdentity != nil {
		q.field("request_identity", v.RequestIdentity)
	}
	q.field("replay_identity", v.ReplayIdentity)
	if v.Domain != "" {
		q.field("domain_id", v.Domain)
	}
	if v.Requested != "" {
		q.field("requested_revision_id", v.Requested)
	}
	if v.Observed != "" {
		q.field("observed_revision_id", v.Observed)
	}
	q.field("commit_may_have_occurred", v.CommitMayHaveOccurred)
	q.field("evidence_ceiling", v.Evidence)
	q.field("warning_summary", v.Warnings)
	if v.Preparation != nil {
		q.field("preparation", v.Preparation)
	}
	if v.Payload == nil {
		q.field("payload", nil)
	} else {
		q.object("payload", func(o *queryObject) { transitionPayloadFields(o, v.Payload) })
	}
	q.array("diagnostics", len(v.Diagnostics), func(i int) { q.w.value(v.Diagnostics[i]) })
	if v.Receipt != "" {
		q.field("receipt_hex", v.Receipt)
	}
	if p := v.RetirementBlockers; p != nil {
		q.object("recipient_retirement_blockers", func(o *queryObject) {
			o.field("total", p.Total)
			o.array("rows", len(p.Rows), func(i int) { o.w.value(p.Rows[i]) })
		})
	}
}

func renderTransitionResultJSON(v transitionResultRecord) ([]byte, error) {
	// The generated family account includes all 3081 diagnostic rows, both
	// 65535-ID terminal sibling sets, retirement blockers, preparation and one
	// source singleton. These closed records have at most five structural levels.
	return renderReadableResultJSON(generatedResultOutputLimit, errApplyResult, func(w *resultStreamWriter) { q := queryBegin(w); transitionResultFields(q, v); q.end() })
}

func transitionPayloadFields(o *queryObject, p *applyTransitionRecord) {
	o.field("schema", p.Schema)
	o.field("predecessor_revision_id", p.Predecessor)
	o.field("requested_revision_id", p.Requested)
	if p.Observed != "" {
		o.field("observed_revision_id", p.Observed)
	}
	o.field("changed_subject_commitment", p.ChangedSubjects)
	o.array("live_duty_ids", len(p.Duties), func(i int) { o.w.value(p.Duties[i]) })
	o.array("live_hazard_ids", len(p.Hazards), func(i int) { o.w.value(p.Hazards[i]) })
}
