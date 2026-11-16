package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

func (q CapacityInspectionQueryIdentity) Validate() error {
	digest, ok := gcQueryDigest(q.PublicQueryBasis, q.Cursor, contract.ID{}, q.MarkDigest, q.EnumerationDigest)
	if !ok || q.Operation != InspectCapacityOperation || digest != q.Digest {
		return contract.ErrRecord
	}
	return nil
}

func (q GCPreviewQueryIdentity) Validate() error {
	digest, ok := gcQueryDigest(q.PublicQueryBasis, q.Cursor, q.ProposedOperationID, q.MarkDigest, q.EnumerationDigest)
	if !ok || q.Operation != GCPlanOperation || digest != q.Digest {
		return contract.ErrRecord
	}
	return nil
}

func validateGCQueryBinding(out PublicQueryResult, q PublicQueryBasis, digest contract.ID) error {
	if err := validatePublicQueryResult(out); err != nil {
		return err
	}
	if out.Operation != q.Operation || out.RequestID != q.RequestNonce || out.DomainID != q.ExpectedDomain || out.RequestIdentity != digest || out.OperationID != publicQueryOperationID(digest) {
		return contract.ErrRecord
	}
	if out.StateResult == PublicQuerySuccess && (q.Observation == nil || q.Observation.HeadRevisionID != out.Result.ObservedRevision || q.Observation.SnapshotID != out.Result.ObservedSnapshotID) {
		return contract.ErrRecord
	}
	return nil
}

func validateGCCandidatePage(page GCCandidatePage, q PublicQueryBasis, mark, enumeration contract.ID) error {
	if page.MarkDigest.IsZero() || page.MarkDigest != mark || page.EnumerationDigest.IsZero() || page.EnumerationDigest != enumeration ||
		page.ProtectedObjectCount < 3 || page.ObservationLimit != "one-page-no-snapshot" || len(page.Candidates) > contract.GCTargetLimit || len(page.EligibleTargets) > contract.GCTargetLimit {
		return contract.ErrRecord
	}
	fields, err := decodeGCCursorFields(page.NextCursor)
	if err != nil || page.NextCursor != "" && (fields.domain != q.ExpectedDomain || fields.store != q.StoreDescriptorDigest) {
		return contract.ErrRecord
	}
	targets, err := contract.GCTargetsDescriptor(page.EligibleTargets)
	if err != nil || targets != page.Targets {
		return contract.ErrRecord
	}
	seen := make([]bool, len(page.EligibleTargets))
	for _, candidate := range page.Candidates {
		if candidate.Classification < contract.GCCandidateProtected || candidate.Classification > contract.GCCandidateUnverifiable || candidate.Reason > contract.GCReasonUnavailable {
			return contract.ErrRecord
		}
		if candidate.Classification == contract.GCCandidateEligible {
			if int(candidate.TargetIndex) >= len(seen) || seen[candidate.TargetIndex] || candidate.KeyDigest.IsZero() || candidate.Reason != contract.GCReasonNone {
				return contract.ErrRecord
			}
			seen[candidate.TargetIndex] = true
		} else if candidate.TargetIndex != 65535 {
			return contract.ErrRecord
		}
		if candidate.Classification != contract.GCCandidateUnverifiable && candidate.KeyDigest.IsZero() {
			return contract.ErrRecord
		}
	}
	for _, present := range seen {
		if !present {
			return contract.ErrRecord
		}
	}
	return nil
}

func (r PublicCapacityInspectionResult) Validate() error {
	if r.Operation != InspectCapacityOperation {
		return contract.ErrRecord
	}
	if r.Query == nil {
		if r.View != nil {
			return contract.ErrRecord
		}
		return validateUnboundPublicQuery(r.PublicQueryResult)
	}
	if err := r.Query.Validate(); err != nil {
		return err
	}
	if err := validateGCQueryBinding(r.PublicQueryResult, r.Query.PublicQueryBasis, r.Query.Digest); err != nil {
		return err
	}
	if r.StateResult != PublicQuerySuccess {
		if r.View != nil {
			return contract.ErrRecord
		}
		return nil
	}
	if r.View == nil || r.Query.Observation == nil || r.View.Observation != *r.Query.Observation || r.View.Continuation.RootDigest != r.View.Observation.RootDigest || len(r.View.Encoded.Objects) > contract.MaxChildPages+3 {
		return contract.ErrRecord
	}
	if err := validateGCCandidatePage(r.View.Garbage, r.Query.PublicQueryBasis, r.Query.MarkDigest, r.Query.EnumerationDigest); err != nil {
		return err
	}
	seen := make(map[string]bool, len(r.View.Counts))
	limits := map[string]uint64{
		"current-value-entries": contract.CryptoMaxValueEntries, "current-generated-value-entries": contract.GeneratedCurrentEntryLimit,
		"current-raw-value-bytes": contract.CryptoMaxRawSet, "current-recipients": contract.CryptoMaxRecipients,
		"current-memberships": contract.CryptoMaxMemberships, "selected-child-pages": contract.MaxChildPages,
		"retained-success-receipts": contract.MutationReceiptWindowLimit, "retained-failure-receipts": contract.MutationReceiptWindowLimit,
		"common-receipt-order": 2 * contract.MutationReceiptWindowLimit, "administrative-groups-format": 65535,
	}
	used := make(map[string]uint64, len(limits))
	for _, row := range r.View.Counts {
		limit, known := limits[row.Name]
		if !known || seen[row.Name] || row.Limit != limit || row.Used > row.Limit || row.Margin != row.Limit-row.Used {
			return contract.ErrRecord
		}
		seen[row.Name] = true
		used[row.Name] = row.Used
	}
	if len(seen) != 10 {
		return contract.ErrRecord
	}
	var heads, roots, helpers, children, childBytes uint64
	var values, recipients, access, support, index uint64
	physical := make(map[contract.StoreObjectIdentity]bool, len(r.View.Encoded.Objects))
	for _, object := range r.View.Encoded.Objects {
		if object.ObjectID.IsZero() || object.EncodedBytes == 0 || object.EncodedBytes > object.Limit || object.Margin != object.Limit-object.EncodedBytes {
			return contract.ErrRecord
		}
		identity := contract.StoreObjectIdentity{Namespace: object.Namespace, Kind: object.Kind, Index: object.Index, ObjectID: object.ObjectID}
		if physical[identity] {
			return contract.ErrRecord
		}
		physical[identity] = true
		switch {
		case object.Namespace == 0 && object.Kind == contract.HeadKind:
			heads++
			if object.Index != 0 || object.ObjectID != r.View.Observation.HeadRevisionID || object.EncodedBytes != r.View.Encoded.HEADBytes || object.Limit != contract.MaxHeadLength {
				return contract.ErrRecord
			}
		case object.Namespace == contract.StorePageObject && object.Kind == contract.RootKind:
			roots++
			if object.Index != 0 || object.ObjectID != r.View.Observation.SnapshotID || object.EncodedBytes != r.View.Encoded.RootBytes || object.Limit != contract.MaxRootLength {
				return contract.ErrRecord
			}
		case object.Namespace == contract.StoreConfigurationObject:
			helpers++
			if object.Kind != 0 || object.Index != 0 || object.ObjectID != r.Query.StoreID || object.EncodedBytes != r.View.Encoded.ConfigurationBytes || object.Limit != contract.MaxStoreConfigurationLength {
				return contract.ErrRecord
			}
		case object.Namespace == contract.StorePageObject:
			if uint64(contract.StoreObjectLimit(identity)) != object.Limit {
				return contract.ErrRecord
			}
			children++
			childBytes += object.EncodedBytes
			switch object.Kind {
			case contract.ValueEntryPageKind:
				values += object.EncodedBytes
			case contract.RecipientKind:
				recipients += object.EncodedBytes
			case contract.AccessKind:
				access += object.EncodedBytes
			case contract.RequiredSupportKind:
				support += object.EncodedBytes
			case contract.AdministrativeIndexKind:
				index += object.EncodedBytes
			default:
				return contract.ErrRecord
			}
		default:
			return contract.ErrRecord
		}
	}
	if heads != 1 || roots != 1 || helpers != 1 || children != used["selected-child-pages"] || childBytes != r.View.Encoded.ChildBytes ||
		values != r.View.Encoded.ValueEntryBytes || recipients != r.View.Encoded.RecipientBytes || access != r.View.Encoded.AccessBytes || support != r.View.Encoded.SupportBytes || index != r.View.Encoded.AdministrativeIndexBytes {
		return contract.ErrRecord
	}
	if r.View.Selected.AdministrativeGroups != used["administrative-groups-format"] || r.View.Selected.GCObligations != uint64(len(r.View.GCObligations)) ||
		r.View.Selected.GCObligations != uint64(r.View.Continuation.GCPlans.Count) || r.View.Selected.GeneratedGraphs != uint64(r.View.Continuation.Graphs.Count) ||
		r.View.Continuation.Remaining.Scope != "remaining-selected-continuations" || r.View.Continuation.FirstExit.Scope != "sufficient-first-administrative-exit" ||
		r.View.Continuation.AdministrativeGroupCountQualification != "format-limit-is-not-proved-usable-admission-capacity" || r.View.Continuation.AdministrativeExitQualification != "no-general-first-or-all-exit-capacity-guarantee" {
		return contract.ErrRecord
	}
	for _, bound := range []CapacityContinuationBound{r.View.Continuation.Remaining, r.View.Continuation.FirstExit} {
		if bound.BasisDigest.IsZero() || bound.Status != "sufficient" && bound.Status != "sufficient-bound-not-established" && bound.Status != "not-applicable" ||
			bound.Scope != "remaining-selected-continuations" && bound.Scope != "sufficient-first-administrative-exit" || bound.ChildPageLimit == 0 || bound.RootByteLimit != contract.MaxRootLength || bound.AdministrativePageByteLimit != contract.MaxRequiredSupportPageLength {
			return contract.ErrRecord
		}
		if bound.Status == "sufficient" && (bound.ChildPages > bound.ChildPageLimit || bound.RootBytes > bound.RootByteLimit) {
			return contract.ErrRecord
		}
	}
	active := 0
	for i, obligation := range r.View.GCObligations {
		if obligation.OperationID.IsZero() || obligation.PlanDigest.IsZero() || obligation.ProgressDigest.IsZero() || !obligation.Targets.ValidTargets() || obligation.Targets.Count == 0 || uint32(obligation.RemainingCount) > obligation.Targets.Count || obligation.ProgressOrdinal == 0 || obligation.ConsumedAllowances > uint64(obligation.Targets.Count)*contract.GCTransmissionLimit {
			return contract.ErrRecord
		}
		if i > 0 && bytes.Compare(r.View.GCObligations[i-1].OperationID[:], obligation.OperationID[:]) >= 0 {
			return contract.ErrRecord
		}
		if obligation.Active {
			active++
		}
	}
	if active > 1 {
		return contract.ErrRecord
	}
	return nil
}

func (r PublicGCPreviewResult) Validate() error {
	if r.Operation != GCPlanOperation {
		return contract.ErrRecord
	}
	if r.Query == nil {
		if r.Payload != nil {
			return contract.ErrRecord
		}
		return validateUnboundPublicQuery(r.PublicQueryResult)
	}
	if err := r.Query.Validate(); err != nil {
		return err
	}
	if err := validateGCQueryBinding(r.PublicQueryResult, r.Query.PublicQueryBasis, r.Query.Digest); err != nil {
		return err
	}
	if r.StateResult != PublicQuerySuccess {
		if r.Payload != nil {
			return contract.ErrRecord
		}
		return nil
	}
	if r.Payload == nil || r.Query.Observation == nil || r.Payload.Observation != *r.Query.Observation {
		return contract.ErrRecord
	}
	p := r.Payload
	encoded, err := contract.EncodeGCPlan(p.Plan)
	if err != nil || !bytes.Equal(encoded, p.EncodedPlan) || p.PlanDigest != contract.Hash(encoded) {
		return contract.ErrRecord
	}
	identity, err := contract.GCPlanRequestIdentity(p.Plan)
	if err != nil || identity != p.RequestIdentity || p.Plan.DomainID != r.DomainID || p.Plan.OperationID != r.Query.ProposedOperationID || p.Plan.RequestNonce != r.RequestID ||
		p.Plan.StoreDescriptorDigest != r.Query.StoreDescriptorDigest || p.Plan.PublicBasisDigest != r.Query.PublicBasisDigest || p.Plan.MarkDigest != r.Query.MarkDigest || p.Plan.EnumerationDigest != r.Query.EnumerationDigest ||
		p.Plan.HeadRevisionID != p.Observation.HeadRevisionID || p.Plan.RootDigest != p.Observation.RootDigest || p.Plan.SnapshotID != p.Observation.SnapshotID {
		return contract.ErrRecord
	}
	pins, err := gcSourcePinsDigest(r.Query.SourcePins)
	if err != nil || pins != p.Plan.SourcePinsDigest {
		return contract.ErrRecord
	}
	input, err := decodeGCCursorFields(r.Query.Cursor)
	if err != nil || input.provider != p.Plan.InputProviderCursor {
		return contract.ErrRecord
	}
	next, err := decodeGCCursorFields(p.Garbage.NextCursor)
	if err != nil || next.provider != p.Plan.NextProviderCursor || !slices.Equal(p.Plan.Targets, p.Garbage.EligibleTargets) || !slices.Equal(p.Plan.Candidates, p.Garbage.Candidates) {
		return contract.ErrRecord
	}
	return validateGCCandidatePage(p.Garbage, r.Query.PublicQueryBasis, r.Query.MarkDigest, r.Query.EnumerationDigest)
}
