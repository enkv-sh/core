package format

import (
	"bytes"
	"testing"

	"enkv.sh/core/contract"
)

// This is a public codec fixture. It creates no store, admission or ready domain.
func genesisPlanFixture(t testing.TB) GenesisPlanCore {
	t.Helper()
	root := rootFixture(t)
	root.ValueEntryPages, root.Names = [contract.MaxValueEntryPages]*Ref{}, nil
	root.ValueEntryCount, root.RawBytes, root.MembershipCount, root.ChildCount = 0, 0, 0, 4
	ref := *root.Recipients[4]
	ref.Index = 0
	root.Recipients = [contract.MaxRecipientPages]*Ref{0: &ref}
	genesisFixtureSupport(t, &root)
	root.ChildEncodedBytes += uint64(ref.Length)
	var err error
	root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: root.Domain, Refs: []Ref{ref}})
	if err != nil {
		t.Fatal(err)
	}
	root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	rootBody, err := EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	rootRef, err := Reference(RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	control := root.CurrentAccess.Core
	head := HeadCore{Form: GenesisHead, Domain: root.Domain, Revision: fid(20), Root: rootRef, Store: control.StoreID, Trust: control.NormalSigning.Binding.Trust, Coordinate: control.CoordinateID, NonBody: control.NonBodyID, Interpretation: control.NormalSigning.Binding.Interpretation, Epoch: 1}
	headBody, err := EncodeHeadCore(head)
	if err != nil {
		t.Fatal(err)
	}
	return GenesisPlanCore{DescriptorDigest: fid(21), Root: root, HeadCore: head,
		IdentityPlan:    contract.IdentityPlan{Operation: fid(22), Snapshot: root.Snapshot, Transition: root.Transition, Revision: head.Revision, Pages: []contract.IdentityPage{{Kind: RecipientKind, Index: 0, Object: ref.Object}, {Kind: contract.RequiredSupportKind, Index: root.RequiredSupport[0].Index, Object: root.RequiredSupport[0].Object}, {Kind: contract.RequiredSupportKind, Index: 1, Object: root.RequiredSupport[1].Object}, {Kind: contract.AdministrativeIndexKind, Index: 0, Object: root.AdministrativeIndex.Object}}},
		ConditionalPlan: ConditionalPlan{Family: control.Provider, Store: head.Store, Coordinate: head.Coordinate, NonBody: head.NonBody, Condition: contract.AbsentHeadCondition(), HeadCore: contract.Hash(headBody), HeadCoreLength: uint32(len(headBody))},
		Probes:          []contract.InitProbePlanRow{{ProbeID: fid(23), SubjectKind: 1, SubjectID: control.AuthorityRecipientID, BindingID: fid(9), PublicBindingDigest: fid(24)}},
	}
}

// full_only: false
func TestGenesisPlanMaximumRecipientPagesRoundTrip(t *testing.T) {
	plan := genesisPlanFixture(t)
	first := *plan.Root.Recipients[0]
	plan.Root.RecipientCount = contract.CryptoMaxRecipients
	plan.Root.ChildCount = contract.MaxRecipientPages + 3 // Two mandatory support pages and administrative index.
	plan.Root.ChildEncodedBytes = uint64(plan.Root.AdministrativeIndex.Length) + uint64(plan.Root.RequiredSupport[0].Length) + uint64(plan.Root.RequiredSupport[1].Length)
	plan.IdentityPlan.Pages = nil
	var refs []Ref
	for i := range plan.Root.Recipients {
		ref := first
		ref.Index = uint16(i)
		ref.Object = fid(byte(100 + i))
		plan.Root.Recipients[i] = &ref
		refs = append(refs, ref)
		plan.IdentityPlan.Pages = append(plan.IdentityPlan.Pages, contract.IdentityPage{Kind: RecipientKind, Index: uint16(i), Object: ref.Object})
		plan.Root.ChildEncodedBytes += uint64(ref.Length)
	}
	plan.IdentityPlan.Pages = append(plan.IdentityPlan.Pages, contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: plan.Root.RequiredSupport[0].Index, Object: plan.Root.RequiredSupport[0].Object},
		contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: 1, Object: plan.Root.RequiredSupport[1].Object},
		contract.IdentityPage{Kind: contract.AdministrativeIndexKind, Object: plan.Root.AdministrativeIndex.Object})
	var err error
	plan.Root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: plan.Root.Domain, Refs: refs})
	if err != nil {
		t.Fatal(err)
	}
	plan.Root.CurrentAccess.AccessRoot, err = contract.AccessRoot(plan.Root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	root, err := EncodeRoot(plan.Root)
	if err != nil {
		t.Fatal(err)
	}
	plan.HeadCore.Root, err = Reference(RootKind, plan.Root.Domain, plan.Root.Snapshot, 0, root)
	if err != nil {
		t.Fatal(err)
	}
	head, err := EncodeHeadCore(plan.HeadCore)
	if err != nil {
		t.Fatal(err)
	}
	plan.ConditionalPlan.HeadCore = contract.Hash(head)
	plan.ConditionalPlan.HeadCoreLength = uint32(len(head))
	identity, err := contract.EncodeIdentityPlan(plan.IdentityPlan)
	if err != nil || len(identity) != 1387 {
		t.Fatal("maximum Genesis identity length", len(identity), err)
	}
	body, err := EncodeGenesisPlanCore(plan)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGenesisPlanCore(body)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeGenesisPlanCore(decoded)
	if err != nil || !bytes.Equal(body, encoded) {
		t.Fatal("maximum Genesis plan changed on readback", err)
	}
}

// full_only: false
func TestGenesisPlanRejectsMismatchedRootIdentity(t *testing.T) {
	for _, field := range []string{"valid", "object", "domain"} {
		t.Run(field, func(t *testing.T) {
			plan := genesisPlanFixture(t)
			body, err := EncodeGenesisPlanCore(plan)
			if err != nil {
				t.Fatal(err)
			}
			switch field {
			case "object":
				plan.HeadCore.Root.Object = fid(25)
			case "domain":
				plan.HeadCore.Domain, plan.HeadCore.Root.Domain = fid(25), fid(25)
			}
			head, err := EncodeHeadCore(plan.HeadCore)
			if err != nil {
				t.Fatal(err)
			}
			plan.ConditionalPlan.HeadCore = contract.Hash(head)
			conditional, err := EncodeConditionalPlan(plan.ConditionalPlan)
			if err != nil {
				t.Fatal(err)
			}
			// Replace only the two complete nested records. Keep both nested
			// hashes valid so refusal must come from the root identity relation.
			r := reader{b: body, off: len(genesisPlanPrefix) + 4 + 32}
			r.blob(GenesisPlanLimit)
			r.blob(GenesisPlanLimit)
			copy(r.blob(GenesisPlanLimit), head)
			copy(r.blob(GenesisPlanLimit), conditional)
			if r.bad {
				t.Fatal("fixture framing")
			}
			decoded, err := DecodeGenesisPlanCore(body)
			if field != "valid" {
				if err == nil {
					t.Fatal("genesis plan admitted a mismatched root identity")
				}
				if _, err := EncodeGenesisPlanCore(plan); err == nil {
					t.Fatal("genesis plan encoded a mismatched root identity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			reencoded, err := EncodeGenesisPlanCore(decoded)
			if err != nil || !bytes.Equal(body, reencoded) {
				t.Fatal("valid genesis plan did not retain canonical bytes")
			}
		})
	}
}

func genesisFixtureSupport(t testing.TB, root *Root) {
	t.Helper()
	receipt, err := contract.GenesisReceiptFields(root.Domain, fid(22), fid(20))
	if err != nil {
		t.Fatal(err)
	}
	empty := contract.EmptyMutationResultDescriptors()
	receipt.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{
		Receipt: contract.CompactMutationReceiptPlan(receipt), RequestCoreDigest: fid(254),
		ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil {
		t.Fatal(err)
	}
	receipt.RequestIdentityDigest = fid(254)
	receiptBody, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	indexes := contract.MutationReceiptIndexes{Successes: []contract.ID{fid(22)}, Order: []contract.ID{fid(22)}}
	root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: contract.GeneratorRecordSchema,
		BlobID: blob, Count: 1, TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	output, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: root.Domain})
	if err != nil {
		t.Fatal(err)
	}
	_, outputSlices, err := contract.SplitOutputConfiguration(root.Domain, output)
	if err != nil {
		t.Fatal(err)
	}
	outputSlice, err := contract.EncodeOutputConfigurationSlice(outputSlices[0])
	if err != nil {
		t.Fatal(err)
	}
	outputID, err := contract.OutputConfigurationSliceID(root.Domain, root.OutputConfiguration.ConfigurationDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows := [][]contract.SupportRecord{{{Kind: contract.MutationReceiptSupportKind, RecordID: fid(22), Body: receiptBody},
		{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: outputID, Body: outputSlice}},
		{{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: fragment}}}
	root.RequiredSupport = nil
	root.RequiredSupportRecordCount = 3
	root.ChildEncodedBytes = 0
	index := AdministrativeIndex{Domain: root.Domain, Object: fid(213), SliceSnapshot: root.Snapshot}
	for i, records := range rows {
		object := fid(byte(211 + i))
		body, err := EncodeRequiredSupportPage(RequiredSupportPage{Domain: root.Domain, Object: object, Index: uint16(i), Records: records})
		if err != nil {
			t.Fatal(err)
		}
		ref, err := Reference(contract.RequiredSupportKind, root.Domain, object, uint16(i), body)
		if err != nil {
			t.Fatal(err)
		}
		root.RequiredSupport = append(root.RequiredSupport, ref)
		root.ChildEncodedBytes += uint64(len(body))
		page := AdministrativePage{Ref: ref, Spans: []AdministrativeSpan{{Count: uint16(len(records)), Mandatory: true}}}
		for _, row := range records {
			page.Rows = append(page.Rows, AdministrativeRowSummary{Kind: row.Kind, RecordID: row.RecordID, BodyLength: uint32(len(row.Body))})
		}
		index.Pages = append(index.Pages, page)
	}
	pages, err := EncodeAdministrativeIndexPages(index)
	if err != nil || len(pages) != 1 {
		t.Fatal("genesis fixture index", err)
	}
	root.AdministrativeIndex = pages[0].Ref
	root.ChildEncodedBytes += uint64(len(pages[0].Body))
	root.Generated.Fragments = []FragmentLocation{{BlobID: blob, SupportPageIndex: 1}}
}
