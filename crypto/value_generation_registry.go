package crypto

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The image fixes accepted intent; current rows independently fix usable keys.
type generatedRegistryAdmission struct {
	image            []byte
	current, desired []contract.RecipientRecord
	refs             []contract.Ref
	before           contract.MutationReceiptWindows
	public           map[contract.ID]PublicKeyQualifier
	changed          bool
}

func generatedRegistryBindings(control contract.ControlCore, rows []contract.RecipientRecord) []contract.BindingTableRow {
	bindings := make([]contract.BindingTableRow, 0, len(rows)+1)
	for _, row := range rows {
		bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: row.RecipientID, Binding: *row.CurrentBinding})
	}
	if control.Recovery != nil {
		bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS})
	}
	return bindings
}

func ownGeneratedRecipients(rows []contract.RecipientRecord) ([]contract.RecipientRecord, error) {
	owned := make([]contract.RecipientRecord, len(rows))
	for i, row := range rows {
		body, err := contract.EncodeRecipientRecord(row)
		if err != nil {
			return nil, ErrAdmission
		}
		owned[i], err = contract.DecodeRecipientRecord(body)
		if err != nil {
			return nil, ErrAdmission
		}
	}
	return owned, nil
}

func generatedRecipientPagesMatch(domain contract.ID, rows []contract.RecipientRecord, refs []contract.Ref) bool {
	if len(refs) != (len(rows)+format.RecipientSlots-1)/format.RecipientSlots {
		return false
	}
	for i, ref := range refs {
		page := format.RecipientPage{Domain: domain, Object: ref.Object, Index: uint16(i)}
		for j := 0; j < format.RecipientSlots && i*format.RecipientSlots+j < len(rows); j++ {
			page.Slots[j] = &rows[i*format.RecipientSlots+j]
		}
		body, err := format.EncodeRecipientPage(page)
		if err != nil {
			return false
		}
		actual, err := format.Reference(format.RecipientKind, domain, ref.Object, uint16(i), body)
		if err != nil || actual != ref {
			return false
		}
	}
	return true
}

func installedGeneratedSession(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedSessionInput, image []byte) (generatedSessionAdmissionInput, error) {
	graph, err := contract.DecodeGeneratorPlanBundle(input.Graph)
	if err != nil {
		return generatedSessionAdmissionInput{}, ErrAdmission
	}
	return installedGeneratedSessionWithGraph(q, control, construction, input, image, graph, false)
}

func (r *Runtime) generatedInstalledSession(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedSessionInput, plan contract.GeneratedPlanInput, selectsEntries bool) (generatedSessionAdmissionInput, error) {
	validated, _, err := r.validateGeneratedPlan(input.Graph, plan.Declaration, false)
	if err != nil {
		return generatedSessionAdmissionInput{}, err
	}
	return installedGeneratedSessionWithGraph(q, control, construction, input, plan.RegistryImage, validated.graph, selectsEntries)
}

func installedGeneratedSessionWithGraph(q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, construction GeneratedCustodyConstruction, input contract.GeneratedSessionInput, image []byte, graph contract.GeneratorPlanBundle, selectsEntries bool) (generatedSessionAdmissionInput, error) {
	out := generatedSessionAdmissionInput{Control: control, RouteID: construction.RouteID, Graph: input.Graph, BeforePublic: input.BeforePublic, Output: input.Output}
	selectedPhase, phaseErr := generatedSelectedPhase(q, input)
	if phaseErr != nil {
		return out, phaseErr
	}
	out.SelectionPhase, out.BeforeAccess, out.BeforeAccessRecords = selectedPhase, input.BeforeAccess, input.BeforeAccessRecords
	if !validApplyCurrentRecipients(input.CurrentRecipients, control) || !generatedRecipientPagesMatch(control.DomainID, input.CurrentRecipients, input.CurrentRecipientRefs) {
		return out, ErrAdmission
	}
	current, err := ownGeneratedRecipients(input.CurrentRecipients)
	if err != nil {
		return out, err
	}
	out.Bindings = generatedRegistryBindings(control, current)
	if q.Purpose == contract.CryptoGeneratedOriginalVerificationPurpose {
		if len(image) != 0 {
			return out, ErrAdmission
		}
		return out, nil
	}
	if graph.Request.Schema == contract.GeneratorRequestCoreSchema {
		if q.Purpose == contract.CryptoGeneratedReservationPurpose || q.Purpose == contract.CryptoGeneratedProducerPreparationPurpose || len(image) != 0 || len(construction.Public) != 0 {
			return out, ErrAdmission
		}
		return out, nil
	}
	if graph.Request.Schema != contract.GeneratorPublicRequestCoreSchema && graph.Request.Schema != contract.GeneratorApplyRequestCoreSchema {
		return out, ErrAdmission
	}
	descriptor, err := contract.GeneratedRecipientRegistryDescriptor(image)
	if err != nil || descriptor != graph.Request.Registry {
		return out, ErrAdmission
	}
	accepted, err := contract.DecodeGeneratedRecipientRegistryImage(image)
	if err != nil || accepted.DomainID != control.DomainID || accepted.OperationID != graph.Header.OperationID || !validApplyCurrentRecipients(current, control) {
		return out, ErrAdmission
	}
	root, err := contract.DecodeRef(q.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		return out, ErrAdmission
	}
	fresh := q.Purpose == contract.CryptoGeneratedReservationPurpose && graph.Request.OperationKind == contract.OperationApplyDeclaration && selectedPhase == nil
	if fresh && root.Object != accepted.OriginalPredecessorSnapshotID {
		return out, ErrAdmission
	}
	var absent []contract.ID
	for i := range accepted.Recipients {
		row := &accepted.Recipients[i]
		at := slices.IndexFunc(current, func(current contract.RecipientRecord) bool { return current.RecipientID == row.Recipient.RecipientID })
		pending := slices.Contains(accepted.InitiallyAbsent, row.Recipient.RecipientID)
		if selectedPhase != nil {
			pending = false
			row.Creation = nil
		}
		if at < 0 {
			absent = append(absent, row.Recipient.RecipientID)
		}
		if pending != (at < 0) {
			return out, ErrAdmission
		}
		if at >= 0 {
			if fresh && !sameApplyBinding(*row.Recipient.CurrentBinding, *current[at].CurrentBinding) {
				return out, ErrAdmission
			}
			row.Recipient.CurrentBinding = current[at].CurrentBinding
		}
	}
	if selectedPhase == nil && !slices.Equal(absent, accepted.InitiallyAbsent) || selectedPhase != nil && len(absent) != 0 {
		return out, ErrAdmission
	}
	desired := make([]contract.RecipientRecord, len(accepted.Recipients))
	for i, row := range accepted.Recipients {
		desired[i] = row.Recipient
	}
	out.Bindings = generatedRegistryBindings(control, desired)
	for i, row := range out.Bindings {
		for _, other := range out.Bindings[:i] {
			if row.Binding.BindingID == other.Binding.BindingID || row.Binding.BindingIncarnationID == other.Binding.BindingIncarnationID {
				return out, ErrAdmission
			}
		}
	}
	request := contract.CryptoCompareRequest{Context: q.Context, Bindings: out.Bindings, Recipients: accepted.Recipients}
	changed, pending, ok := applyRecipientChangesAtSnapshot(request, current, control, accepted.OriginalPredecessorSnapshotID)
	if !ok || !controlBindingsValid(control, out.Bindings) || input.BeforeReceipts.DomainID != control.DomainID {
		return out, ErrAdmission
	}
	if _, err := input.BeforeReceipts.Descriptors(); err != nil {
		return out, ErrAdmission
	}
	if input.Output == nil {
		return out, ErrAdmission
	}
	receipts, err := input.BeforeReceipts.SupportRecords()
	if err != nil {
		return out, ErrAdmission
	}
	count := 0
	for _, fact := range input.Output.Rows.Facts {
		if fact.Kind() == contract.MutationReceiptSupportKind {
			count++
		}
	}
	if count != len(receipts) {
		return out, ErrAdmission
	}
	for _, row := range receipts {
		fact, err := contract.InspectSupportRecordDigest(control.DomainID, row)
		if err != nil || !slices.Contains(input.Output.Rows.Facts, fact) {
			return out, ErrAdmission
		}
	}
	var public map[contract.ID]PublicKeyQualifier
	if q.Purpose.QualifiesPendingRecipients(selectsEntries) {
		public, ok = pendingRecipientRoutes(pending, construction.Public, control.Provider)
		if !ok {
			return out, ErrAdmission
		}
	}
	before := input.BeforeReceipts
	before.Successes, before.Failures, before.Order = slices.Clone(before.Successes), slices.Clone(before.Failures), slices.Clone(before.Order)
	out.Registry = &generatedRegistryAdmission{image: bytes.Clone(image), current: current, desired: desired, refs: slices.Clone(input.CurrentRecipientRefs), before: before, public: public, changed: changed}
	return out, nil
}

func (a *generatedAdmission) qualifyGeneratedRecipients(ctx context.Context, out *contract.CryptoResponse) contract.CryptoResultCode {
	if a.registry == nil {
		return contract.CryptoSuccess
	}
	for _, row := range a.registry.desired {
		route := a.registry.public[row.RecipientID]
		if route == nil {
			continue
		}
		if ctx.Err() != nil {
			return contract.CryptoCancelled
		}
		binding := a.bindings[applyBindingIndex(a.bindings, row.RecipientID)]
		result := route.Qualify(ctx, binding.Binding)
		expected := contract.PublicKeyQualificationUseCount(binding.Binding.Provider)
		if expected == 0 || !appendKeyUses(out, binding, contract.KeyUsePublicKeyRead, result.Uses, uint64(expected)) {
			return contract.CryptoResponseUnknown
		}
		if ctx.Err() != nil {
			return contract.CryptoCancelled
		}
		if result.Status != KeyOK {
			return keyResultCode(result.Status)
		}
		if result.Uses != (KeyUses{Completed: expected}) {
			return contract.CryptoResponseUnknown
		}
	}
	return contract.CryptoSuccess
}
