package crypto

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func generatedInstalledRegistryFixture(t *testing.T) (generatedRuntimeFixture, contract.GeneratedReservationInput, GeneratedCustodyConstruction, *applyRecipientQualifier) {
	t.Helper()
	f := generatedRuntimePlanFixture(t, false)
	root, err := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	image := contract.GeneratedRecipientRegistryImage{Schema: 1, DomainID: f.base.control.DomainID, OperationID: f.compare.ParentPlan.OperationID, OriginalPredecessorSnapshotID: root.Object, Recipients: slices.Clone(f.base.q.Recipients)}
	nonce := consumerID("pending recipient nonce")
	id, err := contract.RecipientCreationID(image.DomainID, root.Object, nonce)
	if err != nil {
		t.Fatal(err)
	}
	binding := *f.base.current[0].CurrentBinding
	binding.BindingID, binding.BindingIncarnationID, err = contract.RecipientInitialBindingIDs(image.DomainID, id)
	if err != nil {
		t.Fatal(err)
	}
	binding.BindingSerial = 1
	image.Recipients = append(image.Recipients, contract.ApplyRecipientInput{Recipient: contract.RecipientRecord{RecipientID: id, Status: contract.CurrentRecipient, DisplayName: "pending display", CurrentBinding: &binding}, Creation: &contract.RecipientCreationProof{Snapshot: root.Object, Nonce: nonce}})
	slices.SortFunc(image.Recipients, func(a, b contract.ApplyRecipientInput) int {
		return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
	})
	image.InitiallyAbsent = []contract.ID{id}
	body, err := contract.EncodeGeneratedRecipientRegistryImage(image)
	if err != nil {
		t.Fatal(err)
	}
	input := contract.GeneratedReservationInput{Session: contract.GeneratedSessionInput{BeforePublic: f.reservation.Session.BeforePublic, Output: f.reservation.Session.Output, CurrentRecipients: f.base.current, BeforeReceipts: contract.MutationReceiptWindows{DomainID: image.DomainID}}, Plan: contract.GeneratedPlanInput{Declaration: f.declaration, RegistryImage: body}}
	page := format.RecipientPage{Domain: image.DomainID, Object: consumerID("current registry page")}
	for i := range f.base.current {
		page.Slots[i] = &f.base.current[i]
	}
	pageBody, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.RecipientKind, page.Domain, page.Object, 0, pageBody)
	if err != nil {
		t.Fatal(err)
	}
	input.Session.CurrentRecipientRefs = []contract.Ref{ref}
	qualifier := &applyRecipientQualifier{binding: binding, result: KeyResult{Status: KeyOK, Uses: KeyUses{Completed: contract.PublicKeyQualificationUseCount(binding.Provider)}}}
	construction := GeneratedCustodyConstruction{RouteID: f.base.route.CredentialRoute(), FileIdentity: consumerID("source file"), Public: map[contract.ID]PublicKeyQualifier{id: qualifier}}
	refreshGeneratedRegistryFixture(t, &f, &input)
	return f, input, construction, qualifier
}

func refreshGeneratedRegistryFixture(t *testing.T, f *generatedRuntimeFixture, input *contract.GeneratedReservationInput) {
	t.Helper()
	g, err := contract.DecodeGeneratorPlanBundle(f.graph)
	if err != nil {
		t.Fatal(err)
	}
	g.Request.Schema = contract.GeneratorPublicRequestCoreSchema
	g.Request.RecoveryPolicyID = contract.GeneratorRecoveryPolicyID()
	g.Header.RecoveryPolicyID = g.Request.RecoveryPolicyID
	g.Request.Registry, err = contract.GeneratedRecipientRegistryDescriptor(input.Plan.RegistryImage)
	if err != nil {
		t.Fatal(err)
	}
	g.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(g.Request)
	if err != nil {
		t.Fatal(err)
	}
	g.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(g.Header, g.ValueEntryPlans, g.Lineages, g.Edges)
	if err != nil {
		t.Fatal(err)
	}
	f.graph, err = contract.EncodeGeneratorPlanBundle(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(g)
	if err != nil {
		t.Fatal(err)
	}
	f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(g.UsePlan)
	if err != nil {
		t.Fatal(err)
	}
	p := &f.compare.ParentPlan
	p.Registry, p.RequestCoreDigest, p.PlanGraphID, p.UsePlanDigest, p.Graph = g.Request.Registry, g.Header.RequestCoreDigest, g.UsePlan.PlanGraphID, f.compare.UsePlanDigest, f.compare.PlanGraph
	p.RecoveryPolicyID = g.Request.RecoveryPolicyID
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal(err)
	}
	input.Session.Graph = f.graph
}

// full_only: false
func TestInstalledGeneratedReservationOwnsRegistryAndQualifiesPendingKey(t *testing.T) {
	f, input, construction, qualifier := generatedInstalledRegistryFixture(t)
	r := newConsumerRuntime(t, f.base.route)
	owner, err := NewGeneratedReservationCustody(r, f.compare, f.base.control, construction, input, f.base.deadline)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	clear(input.Plan.RegistryImage)
	input.Session.CurrentRecipients[0].DisplayName = "later local edit"
	if out := installedGeneratedTestCompare(t, owner, f); out.ResultCode != contract.CryptoSuccess {
		t.Fatal("owned registry comparison", out.ResultCode)
	}
	if qualifier.calls != 1 {
		t.Fatal("pending key qualification calls", qualifier.calls)
	}
}

// full_only: false
func TestInstalledGeneratedReservationRefusesInvalidOriginalRegistryFacts(t *testing.T) {
	for _, name := range []string{"wrong original snapshot", "missing absent identity", "changed first binding", "missing public qualification", "missing image", "wrong recovery policy"} {
		t.Run(name, func(t *testing.T) {
			f, input, construction, qualifier := generatedInstalledRegistryFixture(t)
			image, err := contract.DecodeGeneratedRecipientRegistryImage(input.Plan.RegistryImage)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "wrong original snapshot":
				image.OriginalPredecessorSnapshotID = consumerID("other original snapshot")
			case "missing absent identity":
				image.InitiallyAbsent = nil
			case "changed first binding":
				for i := range image.Recipients {
					if image.Recipients[i].Recipient.RecipientID == image.InitiallyAbsent[0] {
						image.Recipients[i].Recipient.CurrentBinding.BindingID = consumerID("other first binding")
					}
				}
			case "missing public qualification":
				construction.Public = nil
			}
			input.Plan.RegistryImage, err = contract.EncodeGeneratedRecipientRegistryImage(image)
			if err != nil {
				t.Fatal(err)
			}
			refreshGeneratedRegistryFixture(t, &f, &input)
			if name == "wrong recovery policy" {
				f.compare.ParentPlan.RecoveryPolicyID = consumerID("unadmitted recovery policy")
				f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare); err != nil {
					t.Fatal("policy mismatch must reach custody with a valid request", err)
				}
			}
			if name == "missing image" {
				input.Plan.RegistryImage = nil
			}
			r := newConsumerRuntime(t, f.base.route)
			owner, err := NewGeneratedReservationCustody(r, f.compare, f.base.control, construction, input, f.base.deadline)
			if owner != nil || !errors.Is(err, ErrAdmission) {
				if owner != nil {
					owner.Close()
				}
				t.Fatal("invalid original registry admitted", err)
			}
			if qualifier.calls != 0 {
				t.Fatal("refused registry entered qualification", qualifier.calls)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedContinuationUsesCurrentExistingBindingAndOriginalPendingProof(t *testing.T) {
	f, input, construction, _ := generatedInstalledRegistryFixture(t)
	current, err := ownGeneratedRecipients(input.Session.CurrentRecipients)
	if err != nil {
		t.Fatal(err)
	}
	at := slices.IndexFunc(current, func(row contract.RecipientRecord) bool { return row.RecipientID != f.base.control.AuthorityRecipientID })
	if at < 0 {
		t.Fatal("missing existing ordinary recipient")
	}
	current[at].CurrentBinding.BindingID = consumerID("replacement existing binding")
	current[at].CurrentBinding.BindingIncarnationID = consumerID("replacement existing binding incarnation")
	current[at].CurrentBinding.BindingSerial++
	page := format.RecipientPage{Domain: f.base.control.DomainID, Object: consumerID("replacement registry page")}
	for i := range current {
		page.Slots[i] = &current[i]
	}
	body, err := format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(format.RecipientKind, page.Domain, page.Object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	input.Session.CurrentRecipients = current
	input.Session.CurrentRecipientRefs = []contract.Ref{ref}
	f.compare.Purpose = contract.CryptoGeneratedProducerPreparationPurpose
	t.Run("older policy cannot enter a producer", func(t *testing.T) {
		legacy := generatedRuntimePlanFixture(t, false)
		public := input.Session
		public.Graph = legacy.graph
		routes := construction
		routes.Public = nil
		q := f.compare
		q.Purpose = contract.CryptoGeneratedAdoptionPurpose
		if _, err := installedGeneratedSession(q, f.base.control, routes, public, nil); err != nil {
			t.Fatal("evidence-only session refused", err)
		}
		q.Purpose = contract.CryptoGeneratedProducerPreparationPurpose
		if _, err := installedGeneratedSession(q, f.base.control, routes, public, nil); !errors.Is(err, ErrAdmission) {
			t.Fatal("older policy authorized a producer", err)
		}
	})

	root, err := contract.DecodeRef(f.compare.Context.PredecessorRootRef[:], contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	root.Object = consumerID("later selected snapshot")
	encoded, err := contract.AppendRef(nil, root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(f.compare.Context.PredecessorRootRef[:], encoded)
	session, err := installedGeneratedSession(f.compare, f.base.control, construction, input.Session, input.Plan.RegistryImage)
	if err != nil {
		t.Fatal("accepted original registry did not survive current replacement", err)
	}
	index := applyBindingIndex(session.Bindings, current[at].RecipientID)
	if index < 0 || !sameApplyBinding(session.Bindings[index].Binding, *current[at].CurrentBinding) {
		t.Fatal("accepted image restored old binding")
	}
	image, err := contract.DecodeGeneratedRecipientRegistryImage(input.Plan.RegistryImage)
	if err != nil {
		t.Fatal(err)
	}
	input.Session.CurrentRecipients = append(current, session.Registry.desired[slices.IndexFunc(session.Registry.desired, func(row contract.RecipientRecord) bool { return row.RecipientID == image.InitiallyAbsent[0] })])
	slices.SortFunc(input.Session.CurrentRecipients, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	page = format.RecipientPage{Domain: page.Domain, Object: consumerID("claimed pending registry page")}
	for i := range input.Session.CurrentRecipients {
		page.Slots[i] = &input.Session.CurrentRecipients[i]
	}
	body, err = format.EncodeRecipientPage(page)
	if err != nil {
		t.Fatal(err)
	}
	ref, err = format.Reference(format.RecipientKind, page.Domain, page.Object, 0, body)
	if err != nil {
		t.Fatal(err)
	}
	input.Session.CurrentRecipientRefs = []contract.Ref{ref}
	if _, err := installedGeneratedSession(f.compare, f.base.control, construction, input.Session, input.Plan.RegistryImage); !errors.Is(err, ErrAdmission) {
		t.Fatal("accepted pending recipient was reclassified as current", err)
	}
}

// full_only: false
func TestGeneratedCandidateReceiptsBindCommonOrder(t *testing.T) {
	domain := consumerID("ordered generated receipts")
	success := receiptHistoryRow(domain, "generated prior success", true)
	failure := receiptHistoryRow(domain, "generated prior failure", false)
	windows := contract.MutationReceiptWindows{DomainID: domain,
		Successes: []contract.CompactMutationReceipt{success}, Failures: []contract.CompactMutationReceipt{failure},
		Order: []contract.ID{success.OperationID, failure.OperationID}}
	descriptors, err := windows.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	root := format.Root{Domain: domain, Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()}
	root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder = descriptors.Successes, descriptors.Failures, descriptors.Order
	rows, err := windows.SupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	if !generatedCandidateReceiptsMatch(rows, windows, root) {
		t.Fatal("exact ordered receipt candidate refused")
	}
	alternate := windows
	alternate.Order = []contract.ID{failure.OperationID, success.OperationID}
	alternateDescriptors, err := alternate.Descriptors()
	if err != nil {
		t.Fatal("alternate interleave", err)
	}
	if alternateDescriptors.Successes != descriptors.Successes || alternateDescriptors.Failures != descriptors.Failures {
		t.Fatal("interleave changed class windows")
	}
	if generatedReceiptWindowsEqual(windows, alternate) {
		t.Fatal("different common orders compared equal")
	}
	root.Generated.ReceiptOrder = alternateDescriptors.Order
	if generatedCandidateReceiptsMatch(rows, windows, root) {
		t.Fatal("order-only candidate substitution admitted")
	}
	if !generatedCandidateReceiptsMatch(rows, alternate, root) {
		t.Fatal("alternate ordered receipt candidate refused")
	}
}

// full_only: false
func TestGeneratedRecordingValidatesRegistryWithoutPendingRoutes(t *testing.T) {
	for _, damage := range []string{"none", "registry image", "current page", "authority binding", "first binding proof"} {
		t.Run(damage, func(t *testing.T) {
			f, in, construction, _ := generatedInstalledRegistryFixture(t)
			construction.Public = nil
			control := f.base.control
			switch damage {
			case "registry image":
				in.Plan.RegistryImage = nil
			case "current page":
				in.Session.CurrentRecipientRefs[0].Object = consumerID("changed current page")
			case "authority binding":
				control.AuthorityKMSBinding.BindingID = consumerID("unselected authority binding")
			case "first binding proof":
				image, err := contract.DecodeGeneratedRecipientRegistryImage(in.Plan.RegistryImage)
				if err != nil {
					t.Fatal(err)
				}
				for i := range image.Recipients {
					if proof := image.Recipients[i].Creation; proof != nil {
						proof.Nonce = consumerID("different creation nonce")
					}
				}
				in.Plan.RegistryImage, err = contract.EncodeGeneratedRecipientRegistryImage(image)
				if err != nil {
					t.Fatal(err)
				}
				refreshGeneratedRegistryFixture(t, &f, &in)
			}
			f.compare.Purpose = contract.CryptoGeneratedAdoptionPurpose
			session, err := installedGeneratedSession(f.compare, control, construction, in.Session, in.Plan.RegistryImage)
			if damage == "none" {
				if err != nil || session.Registry == nil || len(session.Registry.public) != 0 ||
					len(session.Registry.desired) != len(session.Registry.current)+1 || !session.Registry.changed {
					t.Fatal("recording lost proposed registry facts or required a key route", err)
				}
			} else if !errors.Is(err, ErrAdmission) {
				t.Fatal("recording accepted damaged registry facts", err)
			}
		})
	}
}
