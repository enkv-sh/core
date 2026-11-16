package core

import (
	"bytes"
	stdcontext "context"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func checkEndWorkIndexReserveAgainstActual(t *testing.T, before, after *StateSession, groupID contract.ID) (uint64, int64) {
	t.Helper()
	work, _, err := before.administrativeWorkClosure(groupID)
	if err != nil {
		t.Fatal(err)
	}
	work, err = before.administrativeWorkWithoutOldReceipts(work)
	if err != nil {
		t.Fatal(err)
	}
	projected, _, err := before.administrativeGeneratedProjection(work)
	if err != nil {
		t.Fatal(err)
	}
	oldLength, err := format.AdministrativeIndexEncodedLength(before.adminIndex)
	if err != nil {
		t.Fatal(err)
	}
	oldShards, err := format.AdministrativeIndexShardCount(oldLength)
	if err != nil {
		t.Fatal(err)
	}
	boundLength, err := format.AdministrativeIndexEncodedLength(work)
	if err != nil {
		t.Fatal(err)
	}
	boundLength += 19211 // Two page envelopes/spans and 513 fixed row summaries.
	if projected.Slices != before.root.Generated.Slices {
		for _, page := range work.Pages {
			if !page.ReadRequired {
				continue
			}
			for _, span := range page.Spans {
				boundLength += uint64(span.Count-1) * uint64(7+2*len(span.GroupIndexes))
			}
		}
	}
	actualLength, err := format.AdministrativeIndexEncodedLength(after.adminIndex)
	if err != nil || actualLength > boundLength {
		t.Fatalf("actual exit index exceeded encoded bound: %d > %d: %v", actualLength, boundLength, err)
	}
	boundShards, err := format.AdministrativeIndexShardCount(boundLength)
	if err != nil {
		t.Fatal(err)
	}
	droppedSupport := len(before.adminIndex.Pages) - len(work.Pages)
	droppedAccess := len(before.root.CurrentAccess.Core.AccessPageRefs) - len(after.root.CurrentAccess.Core.AccessPageRefs)
	boundChildren := int64(before.root.ChildCount) + 2 - int64(droppedSupport) - int64(droppedAccess) + int64(boundShards) - int64(oldShards)
	if boundChildren > contract.MaxChildPages || int64(after.root.ChildCount) > boundChildren {
		t.Fatalf("actual exit pages exceeded reserved upper bound: %d > %d", after.root.ChildCount, boundChildren)
	}
	return boundLength, boundChildren
}

func controlEndWorkFixture(t *testing.T, currentShape string) (*StateSession, contract.ID, endWorkIDs, *StateSession) {
	t.Helper()
	s, _, _ := generatedDetachedRetirementState(t, currentShape, 0)
	// The compact identity includes the complete typed current intent.
	compactBlob := contract.ID{
		0xad, 0x1c, 0xca, 0xe6, 0x1c, 0xfb, 0xcc, 0xdf,
		0x41, 0xad, 0x11, 0xef, 0x76, 0x47, 0xe2, 0x6a,
		0x20, 0xda, 0xe2, 0xc5, 0xce, 0x0d, 0x80, 0xbb,
		0xe7, 0xfd, 0x44, 0x11, 0xad, 0x95, 0x7e, 0x7a,
	}
	for i := range s.support {
		for j, row := range s.support[i].Records {
			switch row.Kind {
			case contract.GeneratedFragmentSupportKind:
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				fragment.BlobID = compactBlob
				s.support[i].Records[j].Body, err = contract.EncodeGeneratedFragment(contract.GeneratedFragment(fragment))
				if err != nil {
					t.Fatal(err)
				}
				s.support[i].Records[j].RecordID, err = contract.GeneratorFragmentID(compactBlob, fragment.Index)
				if err != nil {
					t.Fatal(err)
				}
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.VectorKind != contract.GeneratorVectorSlices {
					continue
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					t.Fatal(err)
				}
				location.BlobID = compactBlob
				carrier.Row, err = contract.EncodeGeneratorSliceLocation(location)
				if err != nil {
					t.Fatal(err)
				}
				s.root.Generated.Slices, err = contract.GeneratorVectorDescriptor(contract.GeneratorVectorSlices, [][]byte{carrier.Row})
				if err != nil {
					t.Fatal(err)
				}
				carrier.Vector = s.root.Generated.Slices
				s.support[i].Records[j].RecordID, err = contract.GeneratorVectorCarrierID(carrier)
				if err != nil {
					t.Fatal(err)
				}
				s.support[i].Records[j].Body, err = contract.EncodeGeneratorVectorCarrier(carrier)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	s.root.Generated.Fragments[0].BlobID = compactBlob
	generatedRefreshSupport(t, s)
	if _, err := s.selectedGeneratedWork(stdcontext.Background()); err != nil {
		t.Fatal("compact detached retirement fixture", err)
	}
	basis := generatedEmptyPredecessor(t)
	s.admission, s.body, s.token, s.head = basis.admission, basis.body, basis.token, basis.head
	s.root.CurrentAccess, s.root.Recipients = basis.root.CurrentAccess, basis.root.Recipients
	s.root.OutputConfiguration = basis.root.OutputConfiguration
	s.root.Transition = basis.root.Transition
	s.root.RecipientCount, s.recipients = basis.root.RecipientCount, basis.recipients
	current := s.pages[0].Slots[0]
	current.Recipients = []contract.ID{s.admission.recipient}
	payload, err := contract.DecodeCanonicalPayload(current.ValueBytes)
	if err != nil {
		t.Fatal(err)
	}
	payload.CryptoSupportID = s.root.CurrentAccess.Core.CryptoSupportID
	current.ValueBytes, err = contract.EncodeCanonicalPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	valueBody, err := format.EncodeValueEntryPage(*s.pages[0])
	if err != nil {
		t.Fatal(err)
	}
	valueRef, err := format.Reference(format.ValueEntryPageKind, s.root.Domain, s.pages[0].Object, 0, valueBody)
	if err != nil {
		t.Fatal(err)
	}
	s.root.ValueEntryPages[0] = &valueRef
	s.root.SecretCount, s.root.RawBytes = 1, uint64(payload.ContentLength)
	s.root.MembershipCount, s.root.SecretOrdinaryWrapCount = 1, 1
	core, err := contract.ValueCoreForEntry(s.root.Domain, s.root.CurrentAccess.Core.CompatibilityID, *current)
	if err != nil {
		t.Fatal(err)
	}
	context, err := contract.ValueMaterialContextDigest(core)
	if err != nil {
		t.Fatal(err)
	}
	binding := s.recipients[0].Slots[0].CurrentBinding
	bindingDigest, err := contract.PublicBindingDigest(*binding)
	if err != nil {
		t.Fatal(err)
	}
	s.access[0] = &format.AccessPage{Domain: s.root.Domain, Object: generatedVectorID(199), Records: []contract.AccessRecord{{
		Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind, MaterialID: current.ValueState,
		MaterialContextDigest: context, PackageCheck: payload.PackageCheck,
		Wraps: []contract.WrapRow{{SubjectKind: 1, SubjectID: s.admission.recipient, BindingID: binding.BindingID,
			BindingSerial: binding.BindingSerial, PublicBindingDigest: bindingDigest, RSACiphertext: bytes.Repeat([]byte{68}, 384)}},
	}}}
	accessBody, err := format.EncodeAccessPage(*s.access[0])
	if err != nil {
		t.Fatal(err)
	}
	accessRef, err := format.Reference(format.AccessKind, s.root.Domain, s.access[0].Object, 0, accessBody)
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.Core.AccessPageRefs = []format.Ref{accessRef}
	s.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(s.root.Domain, s.access[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	s.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(s.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	s.root.AccessRecordCount = 1
	generatedRefreshSupport(t, s)
	s.recountChildren()
	var duty contract.ID
	for _, group := range s.adminIndex.Groups {
		if group.OwnerKind == format.AdministrativeGeneratedDuty {
			duty = group.GroupID
		}
	}
	if duty.IsZero() {
		t.Fatal("selected duty is absent")
	}
	ids := endWorkIDs{operation: generatedVectorID(180), transition: generatedVectorID(181),
		snapshot: generatedVectorID(182), revision: generatedVectorID(183),
		receipts: generatedVectorID(184), receiptIndex: generatedVectorID(185)}
	for _, invocation := range []contract.ID{{}, s.root.Snapshot} {
		bad := *s
		bad.admission.endWorkInvocation = invocation
		if allocated, err := bad.freshEndWorkIDs(); allocated != (endWorkIDs{}) || err == nil {
			t.Fatal("EndWork allocated identities for absent or reused invocation identity")
		}
		if invocation.IsZero() {
			if candidate, next, err := bad.deriveEndWorkCandidate(t.Context(), duty, ids); candidate != nil || next != nil || err == nil {
				t.Fatal("EndWork candidate accepted absent invocation identity")
			}
		}
	}
	s.admission.endWorkInvocation = generatedVectorID(196)
	if _, err := format.EncodeRoot(s.root); err != nil {
		t.Fatal("EndWork fixture Root", err)
	}
	if _, err := s.supportDescriptor(); err != nil {
		t.Fatal("EndWork fixture support descriptor", err)
	}
	if len(s.fragmentFacts) != len(s.root.Generated.Fragments) {
		t.Fatal("EndWork fixture fragment fact count")
	}
	for _, location := range s.root.Generated.Fragments {
		result, err := s.withSelectedFragment(t.Context(), location, func([]byte) error { return nil })
		if result.Outcome != 0 || err != nil {
			t.Fatal("EndWork fixture fragment fact", result, err)
		}
	}
	return s, duty, ids, basis
}

// full_only: false
func TestEndWorkCandidateBindsExactRetainedImageAndReceiptUnit(t *testing.T) {
	s, duty, ids, basis := controlEndWorkFixture(t, "generated")
	cancelled, cancel := stdcontext.WithCancelCause(t.Context())
	cancel(errors.New("private retained intent cancellation cause"))
	for _, test := range []struct {
		name        string
		ctx         stdcontext.Context
		readFailure bool
		recordError bool
		want        Result
		message     string
	}{
		{
			name: "cancelled retained intent read", ctx: cancelled, readFailure: true,
			want:    Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable},
			message: "end selected work: read retained current intents: selected object read failed",
		},
		{
			name: "invalid retained intent context", ctx: nil, recordError: true,
			message: "end selected work: read retained current intents: " + contract.ErrRecord.Error(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, next, err := s.deriveEndWorkCandidate(test.ctx, duty, ids)
			var read *selectedReadError
			got, typed := selectedReadResult(err)
			if candidate != nil || next != nil || err == nil || errors.Is(err, contract.ErrRecord) != test.recordError ||
				errors.As(err, &read) != test.readFailure || typed != test.readFailure || got != test.want || read != nil && read.result != test.want {
				t.Fatalf("retained intent context changed its exact failure: result=%+v typed=%t error=%v", got, typed, err)
			}
			if err.Error() != test.message {
				t.Fatal("retained intent context lost fixed operation context", err)
			}
		})
	}
	candidate, next, err := s.deriveEndWorkCandidate(t.Context(), duty, ids)
	if err != nil {
		t.Fatal(err)
	}
	checkEndWorkIndexReserveAgainstActual(t, s, next, duty)
	if candidate.head.AuthKind != format.AdministrativeAuth || candidate.head.EndWork == nil ||
		next.root.Snapshot != ids.snapshot || next.root.Transition != ids.transition ||
		next.head.Core.Revision != ids.revision || !next.validEndWorkSelection() ||
		next.root.WarningBits&WarningDiscardedExactEvidence == 0 {
		t.Fatal("end-work candidate lost exact successor or receipt")
	}
	if next.root.Generated.Slices != s.root.Generated.Slices {
		t.Fatal("Duty fixture changed the complete Slice descriptor")
	}
	if next.adminIndex.SliceSnapshot != s.adminIndex.SliceSnapshot {
		t.Fatal("unchanged Slice descriptor acquired a new owner snapshot")
	}
	for _, page := range s.adminIndex.Pages {
		if page.ReadRequired && !slices.Contains(next.root.RequiredSupport, page.Ref) {
			t.Fatal("unchanged Slice page was rewritten", page.Ref.Index)
		}
	}
	for i, ref := range next.root.RequiredSupport {
		if len(next.support[i].Records) != 0 {
			continue
		}
		found := false
		for _, object := range candidate.objects {
			if object.ref != ref {
				continue
			}
			found = true
			if err := format.CheckReference(object.ref, object.body); err != nil {
				t.Fatal("selected support reference", err)
			}
			next.support[i], err = format.InspectRequiredSupportPage(object.body)
			if err != nil {
				t.Fatal("materialize selected support page", err)
			}
			break
		}
		if !found && !slices.Contains(s.root.RequiredSupport, ref) {
			t.Fatal("new selected support page is absent")
		}
	}
	priorStore := next.store.(*generatedFixtureSupportStore)
	selectedStore := &generatedFixtureSupportStore{t: t, descriptor: priorStore.descriptor, objects: make(map[string][]byte)}
	for key, body := range priorStore.objects {
		selectedStore.objects[key] = bytes.Clone(body)
	}
	for _, object := range candidate.objects {
		if err := format.CheckReference(object.ref, object.body); err != nil {
			t.Fatal("EndWork selected fixture object", err)
		}
		key, err := format.Key(selectedStore.descriptor.Prefix, object.ref)
		if err != nil {
			t.Fatal("EndWork selected fixture object key", err)
		}
		selectedStore.objects[key] = bytes.Clone(object.body)
	}
	next.store = selectedStore
	image := next.selectedImage()
	if result := verifySelectedGeneratedSlices(t.Context(), image, next.selectedObjectReader()); result.Outcome != 0 {
		t.Fatal("EndWork selected fixture slices", result)
	}
	selectedRoot, err := format.EncodeRoot(next.root)
	if err != nil {
		t.Fatal("EndWork selected fixture Root", err)
	}
	next.generatedSliceLocations, next.generatedSlicesRoot = image.generatedSliceLocations, contract.Hash(selectedRoot)
	// A later ordinary writer must consume the retained older Slice owner and
	// bind its carriers to the new ordinary snapshot.
	ordinary := *next
	plan := transitionPlan{snapshot: generatedVectorID(210)}
	ordinary.root.Snapshot = plan.snapshot
	for _, page := range next.adminIndex.Pages {
		if page.ReadRequired {
			plan.supportPages[page.Ref.Index] = contract.Hash(append([]byte("ordinary-after-end-work"), byte(page.Ref.Index)))
		}
	}
	images, err := next.rebindGeneratedSnapshot(t.Context(), &ordinary, plan)
	if err != nil || len(images) == 0 || ordinary.adminIndex.SliceSnapshot != plan.snapshot {
		t.Fatal("ordinary successor could not rebind the retained older Slice owner", err)
	}
	for i, indexed := range ordinary.adminIndex.Pages {
		if !indexed.ReadRequired {
			continue
		}
		for _, row := range ordinary.support[i].Records {
			if _, match, err := snapshotSliceRecord(contract.SupportRecord(row), next.root.Domain, plan.snapshot); err != nil || !match {
				t.Fatal("ordinary successor retained an old Slice carrier", err)
			}
		}
	}
	_, receipt, _ := receiptStateFixture(t)
	receipt.DomainID, receipt.OperationID, receipt.RequestIdentityDigest = next.root.Domain, generatedVectorID(231), contract.ID{}
	windows, err := next.receiptWindows(t.Context())
	if err != nil {
		t.Fatal("retained Slice predecessor receipts", err)
	}
	delta := contract.MutationReceiptDeltaPlan{DomainID: next.root.Domain, OperationKind: receipt.OperationKind,
		AddedCount: 1, Before: windows, NewReceipt: contract.CompactMutationReceiptPlan(receipt)}
	receiptPlan := transitionPlan{snapshot: generatedVectorID(232)}
	indexes, err := next.mutationReceiptPageIndexes(t.Context())
	if err != nil {
		t.Fatal("ordinary receipt page layout after exit", err)
	}
	for _, index := range indexes {
		receiptPlan.supportPages[index] = contract.Hash(append([]byte("receipt-after-end-work"), byte(index)))
	}
	storage, err := next.encodeMutationReceiptSupport(t.Context(), receiptPlan, delta, generatedVectorID(233))
	if err != nil {
		t.Fatal("ordinary receipt successor could not rebind old Slice owner", err)
	}
	receipted := *next
	receipted.root.Snapshot = receiptPlan.snapshot
	storage.install(&receipted)
	if receipted.adminIndex.SliceSnapshot != receiptPlan.snapshot {
		t.Fatal("ordinary receipt successor kept an old Slice owner")
	}
	for _, page := range receipted.support {
		if !slices.ContainsFunc(next.adminIndex.Pages, func(indexed format.AdministrativePage) bool {
			return indexed.ReadRequired && indexed.Ref.Index == page.Index
		}) {
			continue
		}
		for _, row := range page.Records {
			if _, match, err := snapshotSliceRecord(contract.SupportRecord(row), next.root.Domain, receiptPlan.snapshot); err != nil || !match {
				t.Fatal("ordinary receipt successor kept an old Slice carrier", err)
			}
		}
	}
	for _, group := range next.adminIndex.Groups {
		if group.GroupID == duty {
			t.Fatal("ended duty is still selected")
		}
	}
	active := generatedReservationState(t)
	active.admission, active.body, active.token, active.head = basis.admission, basis.body, basis.token, basis.head
	active.root.CurrentAccess, active.root.Recipients = basis.root.CurrentAccess, basis.root.Recipients
	active.root.OutputConfiguration, active.root.Transition = basis.root.OutputConfiguration, basis.root.Transition
	active.root.RecipientCount, active.recipients = basis.root.RecipientCount, basis.recipients
	activeAccessBody, err := format.EncodeAccessPage(*active.access[0])
	if err != nil {
		t.Fatal(err)
	}
	activeAccessRef, err := format.Reference(format.AccessKind, active.root.Domain, active.access[0].Object, 0, activeAccessBody)
	if err != nil {
		t.Fatal(err)
	}
	active.root.CurrentAccess.Core.AccessPageRefs = []format.Ref{activeAccessRef}
	active.root.CurrentAccess.Core.AccessRecordsDescriptor, err = contract.AccessRecordsDescriptor(active.root.Domain, active.access[0].Records)
	if err != nil {
		t.Fatal(err)
	}
	active.root.CurrentAccess.AccessRoot, err = contract.AccessRoot(active.root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	active.root.AccessRecordCount = 1
	generatedRefreshSupport(t, active)
	active.recountChildren()
	parent := active.root.Generated.ActiveOwner
	parentIDs := endWorkIDs{operation: generatedVectorID(190), transition: generatedVectorID(191),
		snapshot: generatedVectorID(192), revision: generatedVectorID(193),
		receipts: generatedVectorID(194), receiptIndex: generatedVectorID(195)}
	active.admission.endWorkInvocation = generatedVectorID(197)
	for _, group := range active.adminIndex.Groups {
		if group.OwnerKind != format.AdministrativeGeneratedDuty {
			continue
		}
		if candidate, next, err := active.deriveEndWorkCandidate(t.Context(), group.GroupID, parentIDs); candidate != nil || next != nil || err == nil {
			t.Fatal("active duty acquired an independent exit")
		}
	}
	parentCandidate, parentNext, err := active.deriveEndWorkCandidate(t.Context(), parent, parentIDs)
	if err != nil {
		t.Fatal("parent candidate", err)
	}
	checkEndWorkIndexReserveAgainstActual(t, active, parentNext, parent)
	if !parentNext.validEndWorkSelection() || len(parentNext.adminIndex.Groups) != 0 ||
		!parentNext.root.Generated.ActiveOwner.IsZero() ||
		parentCandidate.head.EndWork.DependentGroups.Count != 2 {
		t.Fatal("parent closure did not end its complete selected dependent scope")
	}
	_, ended, err := active.administrativeWorkClosure(parent)
	if err != nil || len(ended) != 2 {
		t.Fatal("parent has no exact two-group closure", err)
	}
	preview, ok := previewFromCandidate(parentCandidate)
	if !ok || !slices.Equal(preview.EndedGroupIDs, []contract.ID{ended[0].GroupID, ended[1].GroupID}) {
		t.Fatal("preview omitted the complete ordered ended-group scope", ok, preview.EndedGroupIDs)
	}
}
