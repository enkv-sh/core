package crypto

import (
	"bytes"
	"crypto/sha256"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedRecipientsEqual(left, right []contract.RecipientRecord) bool {
	return slices.EqualFunc(left, right, sameApplyRecipient)
}

func generatedReceiptWindowsEqual(left, right contract.MutationReceiptWindows) bool {
	return left.DomainID == right.DomainID && slices.Equal(left.Successes, right.Successes) && slices.Equal(left.Failures, right.Failures) && slices.Equal(left.Order, right.Order)
}

func (a *generatedAdmission) candidateRegistryMatches(c generatedCandidate, head format.HeadCore) bool {
	if a.registry == nil {
		if c.Registry != nil {
			return false
		}
		if c.UnchangedRegistry == nil {
			return a.candidateGrantsMatch(c, head, nil)
		}
		if a.graph.Request.Schema != contract.GeneratorRequestCoreSchema || a.purpose.final == nil ||
			a.purpose.final.nonselecting || c.Subject.Purpose != contract.GeneratorAuthorityFinal || head.GrantDigest.IsZero() {
			return false
		}
		beforeRef, err := contract.DecodeRef(a.request.Context.PredecessorRootRef[:], contract.CanonicalSchema)
		if err != nil || format.CheckReference(beforeRef, c.UnchangedRegistry.Before) != nil || format.CheckReference(head.Root, c.UnchangedRegistry.After) != nil {
			return false
		}
		before, err := format.DecodeRoot(c.UnchangedRegistry.Before)
		if err != nil || before.CurrentAccess.AccessRoot != a.request.Context.CurrentAccessRoot {
			return false
		}
		after, err := format.DecodeRoot(c.UnchangedRegistry.After)
		if err != nil || after.Domain != before.Domain || after.Domain != c.PublicState.Domain ||
			after.CurrentAccess.AccessRoot != c.PublicState.AccessRoot || after.RecipientCount != before.RecipientCount ||
			after.CurrentAccess.Core.RecipientRefsDescriptor != before.CurrentAccess.Core.RecipientRefsDescriptor {
			return false
		}
		return a.candidateGrantsMatch(c, head, &after)
	}
	if c.UnchangedRegistry != nil {
		return false
	}
	v := c.Registry
	if v == nil || !bytes.Equal(v.Image, a.registry.image) {
		return false
	}
	root, err := format.DecodeRoot(v.Root)
	if err != nil || format.CheckReference(head.Root, v.Root) != nil || !a.candidateGrantsMatch(c, head, &root) || root.Domain != c.PublicState.Domain || root.Snapshot != head.Root.Object || root.RecipientCount != uint16(len(v.Recipients)) {
		return false
	}
	rootCore, err := contract.EncodeCurrentAccessCore(root.CurrentAccess.Core)
	if err != nil {
		return false
	}
	core, err := contract.EncodeCurrentAccessCore(c.CurrentAccess)
	if err != nil || !bytes.Equal(rootCore, core) || root.CurrentAccess.AccessRoot != c.PublicState.AccessRoot {
		return false
	}
	var refs []contract.Ref
	for _, ref := range root.Recipients {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	if !slices.Equal(refs, v.RecipientRefs) || !generatedRecipientPagesMatch(root.Domain, v.Recipients, refs) {
		return false
	}
	descriptor, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: root.Domain, Refs: refs})
	if err != nil || descriptor != c.CurrentAccess.RecipientRefsDescriptor {
		return false
	}
	terminal := a.purpose.final != nil && c.Subject.Purpose == contract.GeneratorAuthorityFinal
	closing := terminal && !a.firstAutomaticSelection(c)
	if !generatedRegistrySliceMatches(c.SupportRecords, root.Domain, root.Snapshot, a.graph.Header.OperationID, a.registry.image, !closing) {
		return false
	}
	if a.graph.Request.Schema == contract.GeneratorApplyRequestCoreSchema {
		configuration, err := a.purpose.output.ConfigurationAfter(a.graph.Header.OperationID, a.graph.ValueEntryPlans)
		if err != nil {
			return false
		}
		image, err := contract.EncodeOutputConfiguration(configuration)
		if err != nil {
			return false
		}
		if !generatedCandidateContentMatches(c.SupportRecords, root.Domain, root.Snapshot, contract.GeneratorContentOutputConfiguration, a.graph.Header.OperationID,
			contract.DigestLength{Digest: contract.Hash(image), Length: uint64(len(image))}, image, !closing) {
			return false
		}
	}
	selecting := terminal && !a.purpose.final.nonselecting
	want := a.registry.current
	if selecting {
		want = a.registry.desired
	}
	if !generatedRecipientsEqual(want, v.Recipients) {
		return false
	}
	if selecting && a.registry.changed {
		plan := v.IdentityPlan
		if plan.Operation != a.graph.Header.OperationID || plan.Snapshot != root.Snapshot || plan.Transition != root.Transition || plan.Revision != head.Revision {
			return false
		}
		_, actual, err := format.ApplyRecipientPages(root.Domain, v.Recipients, plan)
		if err != nil || !slices.Equal(actual, refs) {
			return false
		}
	} else if !slices.Equal(a.registry.refs, refs) || slices.ContainsFunc(v.IdentityPlan.Pages, func(page contract.IdentityPage) bool { return page.Kind == contract.RecipientKind }) {
		return false
	}
	if root.Generated.ActiveOwner != c.ActiveOwner || root.Generated.ActivePhase != c.ActivePhase || root.Generated.ActiveGraph != c.ActiveGraph {
		return false
	}
	if closing {
		return a.candidateRegistryReceiptMatches(c, root, selecting)
	}
	if v.ReceiptDelta != nil {
		return false
	}
	return generatedCandidateReceiptsMatch(c.SupportRecords, a.registry.before, root)
}

func generatedRegistrySliceMatches(support []contract.SupportRecord, domain, snapshot, operation contract.ID, image []byte, active bool) bool {
	return generatedCandidateContentMatches(support, domain, snapshot, contract.GeneratorContentRecipientRegistry, operation,
		contract.DigestLength{Digest: contract.Hash(image), Length: uint64(len(image))}, image, active)
}

func generatedCandidateContentMatches(support []contract.SupportRecord, domain, snapshot contract.ID, kind uint8, content contract.ID, expected contract.DigestLength, image []byte, active bool) bool {
	found := 0
	for _, row := range support {
		if row.Kind != contract.GeneratorVectorSupportKind {
			continue
		}
		carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			return false
		}
		if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.OwnerID != snapshot || carrier.VectorKind != contract.GeneratorVectorSlices {
			continue
		}
		location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
		if err != nil {
			return false
		}
		if location.ContentKind != kind {
			continue
		}
		if location.ContentID != content {
			if kind == contract.GeneratorContentRecipientRegistry || kind == contract.GeneratorContentOutputConfiguration {
				return false
			}
			continue
		}
		if !active || carrier.DomainID != domain || uint64(location.Length) != expected.Length || location.Digest != expected.Digest {
			return false
		}
		found++
		if expected.Length == 0 || expected.Length > uint64(contract.MaxChildPages*2)*contract.GeneratedFragmentMaxPayload {
			return false
		}
		hash := sha256.New()
		consumed := 0
		for uint64(consumed) < expected.Length {
			offset := uint64(location.Offset) + uint64(consumed)
			if offset >= uint64(contract.MaxChildPages*2)*contract.GeneratedFragmentMaxPayload {
				return false
			}
			index := uint16(offset / contract.GeneratedFragmentMaxPayload)
			id, err := contract.GeneratorFragmentID(location.BlobID, index)
			if err != nil {
				return false
			}
			at := slices.IndexFunc(support, func(row contract.SupportRecord) bool {
				return row.Kind == contract.GeneratedFragmentSupportKind && row.RecordID == id
			})
			if at < 0 {
				return false
			}
			fragment, err := contract.InspectGeneratedFragment(support[at].Body)
			if err != nil || fragment.BlobID != location.BlobID || fragment.Index != index || location.Offset+uint64(location.Length) > fragment.TotalLength {
				return false
			}
			start := int(offset % contract.GeneratedFragmentMaxPayload)
			if start >= len(fragment.Payload) {
				return false
			}
			n := min(int(expected.Length)-consumed, len(fragment.Payload)-start)
			if len(image) != 0 && (uint64(len(image)) != expected.Length || !bytes.Equal(fragment.Payload[start:start+n], image[consumed:consumed+n])) {
				return false
			}
			_, _ = hash.Write(fragment.Payload[start : start+n])
			consumed += n
		}
		var digest contract.ID
		copy(digest[:], hash.Sum(nil))
		if digest != expected.Digest {
			return false
		}
	}
	return active && found == 1 || !active && found == 0
}

func generatedCandidateReceiptsMatch(support []contract.SupportRecord, windows contract.MutationReceiptWindows, root format.Root) bool {
	indexes, err := windows.Indexes()
	if err != nil {
		return false
	}
	successes, failures, order, err := indexes.Descriptors()
	if err != nil || root.Generated.SuccessWindow != successes || root.Generated.FailureWindow != failures || root.Generated.ReceiptOrder != order {
		return false
	}
	want, err := windows.SupportRecords()
	if err != nil {
		return false
	}
	at := 0
	for _, row := range support {
		if row.Kind != contract.MutationReceiptSupportKind {
			continue
		}
		if at >= len(want) || row.RecordID != want[at].RecordID || !bytes.Equal(row.Body, want[at].Body) {
			return false
		}
		at++
	}
	return at == len(want)
}

func (a *generatedAdmission) candidateRegistryReceiptMatches(c generatedCandidate, root format.Root, selecting bool) bool {
	input := c.Registry.ReceiptDelta
	if input == nil || !generatedReceiptWindowsEqual(input.Plan.Before, a.registry.before) {
		return false
	}
	plan := input.Plan
	if _, err := contract.MutationReceiptDeltaPlanDigest(plan); err != nil {
		return false
	}
	row := contract.CompactMutationReceipt(plan.NewReceipt)
	if plan.DomainID != a.graph.Header.DomainID || plan.OperationKind != a.graph.Request.OperationKind || plan.AddedCount != 1 ||
		row.DomainID != plan.DomainID || row.OperationKind != plan.OperationKind || row.OperationID != a.graph.Header.OperationID ||
		row.PredecessorRevisionID != a.graph.Request.PredecessorRevisionID || row.RequestedRevisionID != c.Registry.IdentityPlan.Revision ||
		!row.RequestIdentityDigest.IsZero() || row.OutputSummary != contract.ReceiptOutputNotApplicable {
		return false
	}
	head, err := format.DecodeHeadCore(c.HeadCore)
	if err != nil || row.RequestedRevisionID != head.Revision {
		return false
	}
	observed := head.PreviousRevision
	canonical := uint8(contract.ReceiptCanonicalNotSelected)
	if selecting {
		observed = head.Revision
		canonical = contract.ReceiptCanonicalSelected
	}
	if row.ObservedRevisionID != observed || row.CanonicalOutcome != canonical {
		return false
	}
	changed, err := contract.ChangedSubjectDescriptor(input.ChangedSubjects)
	if err != nil || changed != row.ChangedSubjects {
		return false
	}
	var expected, actual []contract.ChangedSubjectIdentity
	if selecting {
		for _, next := range a.registry.desired {
			at := slices.IndexFunc(a.registry.current, func(old contract.RecipientRecord) bool { return old.RecipientID == next.RecipientID })
			if at >= 0 && sameApplyRecipient(a.registry.current[at], next) {
				continue
			}
			kind := uint8(contract.ChangedSubjectUpdated)
			if at < 0 {
				kind = contract.ChangedSubjectAdded
			}
			identity, err := contract.ChangedSubjectIdentityID(root.Domain, contract.ChangedSubjectRecipient, next.RecipientID, contract.ID{})
			if err != nil {
				return false
			}
			expected = append(expected, contract.ChangedSubjectIdentity{Kind: contract.ChangedSubjectRecipient, Change: kind, Identity: identity})
		}
	}
	for _, subject := range input.ChangedSubjects {
		if subject.Kind == contract.ChangedSubjectRecipient {
			actual = append(actual, subject)
		}
	}
	want, err := contract.ChangedSubjectDescriptor(expected)
	if err != nil {
		return false
	}
	got, err := contract.ChangedSubjectDescriptor(actual)
	if err != nil || got != want {
		return false
	}
	row.RequestIdentityDigest = a.request.Parent.RequestIdentityDigest
	after, err := contract.AppendMutationReceipt(a.registry.before, row)
	if err != nil || !generatedReceiptWindowsEqual(after, input.After) {
		return false
	}
	return generatedCandidateReceiptsMatch(c.SupportRecords, after, root)
}
