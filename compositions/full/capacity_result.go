package compositionfull

import (
	"context"
	"io"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func WriteCapacityInspectionJSON(ctx context.Context, out io.Writer, result core.PublicCapacityInspectionResult) error {
	return writeCapacityInspection(ctx, out, result, false, nil)
}
func WriteCapacityInspectionHuman(ctx context.Context, out io.Writer, result core.PublicCapacityInspectionResult) error {
	return writeCapacityInspection(ctx, out, result, true, nil)
}

func writeCapacityInspection(ctx context.Context, out io.Writer, result core.PublicCapacityInspectionResult, human bool, sourceFailure *ConfigurationSourceFailure) error {
	if result.Validate() != nil {
		return ErrPublicQueryResult
	}
	var emit func(*queryObject)
	kind := "none"
	if v := result.View; v != nil {
		kind = "CapacityPayload/v1"
		emit = func(q *queryObject) {
			q.field("schema", kind)
			q.object("observation", func(o *queryObject) { queryObservation(o, v.Observation) })
			q.array("counts", len(v.Counts), func(i int) {
				c := v.Counts[i]
				o := q.begin()
				o.field("name", c.Name)
				o.field("used", c.Used)
				o.field("limit", c.Limit)
				o.field("margin", c.Margin)
				o.end()
			})
			q.object("selected", func(o *queryObject) {
				s := v.Selected
				o.field("secret_values", s.SecretValues)
				o.field("access_records", s.AccessRecords)
				o.field("support_records", s.SupportRecords)
				o.field("generated_attempts", s.GeneratedAttempts)
				o.field("generated_duties", s.GeneratedDuties)
				o.field("generated_hazards", s.GeneratedHazards)
				o.field("generated_materials", s.GeneratedMaterials)
				o.field("pending_inbox_releases", s.PendingInboxReleases)
				o.field("generated_graphs", s.GeneratedGraphs)
				o.field("administrative_groups", s.AdministrativeGroups)
				o.field("gc_obligations", s.GCObligations)
				o.field("output_bindings", s.OutputBindings)
				o.field("publication_coordinates", s.PublicationCoordinates)
				o.field("publication_markers", s.PublicationMarkers)
			})
			q.object("encoded", func(o *queryObject) {
				e := v.Encoded
				o.field("head_bytes", e.HEADBytes)
				o.field("root_bytes", e.RootBytes)
				o.field("child_bytes", e.ChildBytes)
				o.field("configuration_bytes", e.ConfigurationBytes)
				o.field("value_entry_bytes", e.ValueEntryBytes)
				o.field("recipient_bytes", e.RecipientBytes)
				o.field("access_bytes", e.AccessBytes)
				o.field("support_bytes", e.SupportBytes)
				o.field("administrative_index_bytes", e.AdministrativeIndexBytes)
				o.array("objects", len(e.Objects), func(i int) {
					p := e.Objects[i]
					a := o.begin()
					queryStoreObject(a, contract.StoreObjectIdentity{Namespace: p.Namespace, Kind: p.Kind, Index: p.Index, ObjectID: p.ObjectID})
					a.field("encoded_bytes", p.EncodedBytes)
					a.field("limit", p.Limit)
					a.field("margin", p.Margin)
					a.end()
				})
			})
			q.object("continuation", func(o *queryObject) {
				c := v.Continuation
				o.id("root_digest", c.RootDigest)
				queryDescriptor(o, "graphs", c.Graphs)
				queryGCDescriptor(o, "gc_plans", c.GCPlans)
				o.field("administrative_group_count_qualification", c.AdministrativeGroupCountQualification)
				o.field("administrative_exit_qualification", c.AdministrativeExitQualification)
				o.object("remaining", func(a *queryObject) { queryCapacityBound(a, c.Remaining) })
				o.object("first_exit", func(a *queryObject) { queryCapacityBound(a, c.FirstExit) })
			})
			q.array("gc_obligations", len(v.GCObligations), func(i int) {
				p := v.GCObligations[i]
				o := q.begin()
				o.id("operation_id", p.OperationID)
				o.field("active", p.Active)
				o.id("plan_digest", p.PlanDigest)
				o.id("progress_digest", p.ProgressDigest)
				queryGCDescriptor(o, "targets", p.Targets)
				o.field("remaining_count", p.RemainingCount)
				o.field("progress_ordinal", p.ProgressOrdinal)
				o.field("consumed_allowances", p.ConsumedAllowances)
				o.end()
			})
			q.object("garbage", func(o *queryObject) { queryGCCandidatePage(o, v.Garbage) })
		}
	}
	return writePublicQuery(ctx, out, result.PublicQueryResult, human, kind, emit, nil, sourceFailure)
}

func queryCapacityBound(o *queryObject, b core.CapacityContinuationBound) {
	o.field("scope", b.Scope)
	o.field("status", b.Status)
	o.id("basis_digest", b.BasisDigest)
	o.field("child_pages", b.ChildPages)
	o.field("child_encoded_bytes", b.ChildEncodedBytes)
	o.field("root_bytes", b.RootBytes)
	o.field("administrative_index_bytes", b.AdministrativeIndexBytes)
	o.field("administrative_index_shards", b.AdministrativeIndexShards)
	o.field("child_page_limit", b.ChildPageLimit)
	o.field("root_byte_limit", b.RootByteLimit)
	o.field("administrative_page_byte_limit", b.AdministrativePageByteLimit)
	o.array("groups", len(b.Groups), func(i int) {
		g := b.Groups[i]
		q := o.begin()
		q.field("group", i)
		q.field("max_count", g.MaxCount)
		q.field("max_framed_bytes", g.MaxFramedBytes)
		q.field("max_pages", g.MaxPages)
		q.end()
	})
}

func queryGCDescriptor(o *queryObject, name string, d contract.GCDescriptor) {
	o.object(name, func(q *queryObject) { q.id("digest", d.Digest); q.field("length", d.Length); q.field("count", d.Count) })
}
func queryStoreObject(o *queryObject, v contract.StoreObjectIdentity) {
	o.field("namespace", v.Namespace)
	o.field("kind", v.Kind)
	o.field("index", v.Index)
	o.id("object_id", v.ObjectID)
}
func queryGCTarget(o *queryObject, v contract.GCTarget) {
	queryStoreObject(o, v.Object)
	o.field("length", v.Length)
	o.id("digest", v.Digest)
	// Provider conditions are in the protected canonical artifact. Rendering
	// uses only typed object identity and byte commitments, never raw tokens.
}
func queryGCCandidate(o *queryObject, c contract.GCCandidate) {
	o.id("key_digest", c.KeyDigest)
	o.field("classification", gcCandidateClass(c.Classification))
	o.field("reason", c.Reason)
	o.field("target_index", c.TargetIndex)
	o.field("listed_length", c.ListedLength)
}
func queryGCCandidatePage(o *queryObject, p core.GCCandidatePage) {
	o.id("mark_digest", p.MarkDigest)
	o.id("enumeration_digest", p.EnumerationDigest)
	o.field("protected_object_count", p.ProtectedObjectCount)
	queryGCDescriptor(o, "targets", p.Targets)
	o.field("next_cursor", p.NextCursor)
	o.field("observation_limit", p.ObservationLimit)
	o.array("candidates", len(p.Candidates), func(i int) {
		q := o.begin()
		queryGCCandidate(q, p.Candidates[i])
		q.end()
	})
	o.array("eligible_targets", len(p.EligibleTargets), func(i int) { q := o.begin(); queryGCTarget(q, p.EligibleTargets[i]); q.end() })
}
func gcCandidateClass(c contract.GCCandidateClass) string {
	switch c {
	case contract.GCCandidateProtected:
		return "protected"
	case contract.GCCandidateEligible:
		return "eligible"
	case contract.GCCandidateAlreadyPending:
		return "already-pending"
	case contract.GCCandidateAbsent:
		return "absent"
	case contract.GCCandidateChanged:
		return "changed"
	case contract.GCCandidateUnverifiable:
		return "unverifiable"
	}
	return ""
}
