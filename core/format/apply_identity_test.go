package format

import (
	"encoding/json"
	"os"
	"testing"

	"enkv.sh/core/contract"
)

// Independent Python field framing and SHA-256 reproduce the earlier literals
// before deriving canonical schema 11, common receipt order and the schema 5
// empty output image under the v5 configuration/slice commitment domains.
// The derivation recipe and its inherited-leaf limits are recorded in
// tests/shared/testdata/README.md.
func suppliedApplyIdentityFixture(t testing.TB) SuppliedApplyIdentityPlan {
	t.Helper()
	body, err := os.ReadFile("../../tests/shared/testdata/stored-closure-v11.json")
	if err != nil || contract.Hash(body) != successionLiteralID(t, "d619ec197d4924c5c1adb2dc98147b3ca9acf741d02a00ea8ba1ece9dcc0b4fc") {
		t.Fatal("independent source vector changed", err)
	}
	var vectors storedClosureVectors
	if json.Unmarshal(body, &vectors) != nil || len(vectors.Cases) != 2 || vectors.Cases[0].RecoveryMode != 0 {
		t.Fatal("independent source vector unavailable")
	}
	root, err := DecodeRoot(vectors.Cases[0].FirstSecret.Root.bytes(t))
	if err != nil {
		t.Fatal(err)
	}
	receipt := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: contract.OperationApplyDeclaration, StateResult: 1, EvidenceCeiling: 1,
		DomainID: fid(1), OperationID: fid(20), PredecessorRevisionID: fid(2), RequestedRevisionID: fid(34), ObservedRevisionID: fid(34), CanonicalOutcome: 1,
		ChangedSubjects: contract.GeneratorDescriptor{Digest: fid(91), Length: 42, Count: 1}, CompleteResult: contract.GeneratorDescriptor{Digest: fid(92), Length: 655, Count: 1}}
	receipt.SummaryCounts[contract.ReceiptChangedAccessCount] = 1
	receiptBody, err := contract.AppendCompactMutationReceiptPlan(nil, receipt)
	if err != nil {
		t.Fatal(err)
	}
	page, err := EncodeRequiredSupportReceiptPlan(RequiredSupportPage{Domain: fid(1), Object: fid(106), Index: 1, Records: []contract.SupportRecord{{Kind: contract.MutationReceiptSupportKind, RecordID: fid(20), Body: receiptBody}}}, receipt)
	if err != nil {
		t.Fatal(err)
	}
	root.RequiredSupport = append(root.RequiredSupport, Ref{Kind: contract.RequiredSupportKind, Format: 11, Domain: fid(1), Object: fid(106), Digest: contract.Hash(page), Length: uint32(len(page)), Index: 1})
	root.RequiredSupportRecordCount++
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(page))
	rootBody, err := EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	identity := contract.IdentityPlan{Operation: fid(20), Transition: fid(33), Snapshot: fid(30), Revision: fid(34),
		Rows:  []contract.IdentityRow{{Name: "sample", Slot: 0, Incarnation: fid(35), ValueState: fid(36), OriginSnapshot: fid(30), OriginTransition: fid(33)}},
		Pages: []contract.IdentityPage{{Kind: ValueEntryPageKind, Object: fid(31)}, {Kind: AccessKind, Object: fid(32)}, {Kind: contract.RequiredSupportKind, Index: 1, Object: fid(106)}}}
	identityBody, err := contract.EncodeIdentityPlan(identity)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.RequestCore{RequestCoreFields: contract.RequestCoreFields{Domain: fid(1), Store: fid(71), Trust: fid(75), Coordinate: fid(72), NonBody: fid(73), Interpretation: fid(76), Epoch: 1,
		PreviousRevision: fid(2), PreviousDigest: fid(3), Intent: contract.DigestLength{Digest: fid(24), Length: 888}, IdentityPlan: contract.DigestLength{Digest: contract.Hash(identityBody), Length: uint64(len(identityBody))}}, PreviousToken: contract.Token{Family: contract.AWS, Value: `"etag"`}}
	requestBody, err := contract.EncodeRequestCore(request)
	if err != nil {
		t.Fatal(err)
	}
	head := HeadPlan{Form: SuccessorHead, Domain: fid(1), Revision: fid(34), PreviousRevision: fid(2), PreviousDigest: fid(3), PreviousToken: request.PreviousToken,
		Root: Ref{Kind: RootKind, Format: 11, Domain: fid(1), Object: fid(30), Length: uint32(len(rootBody))}, Store: fid(71), Trust: fid(75), Coordinate: fid(72), NonBody: fid(73), Interpretation: fid(76), Epoch: 1}
	headBody, err := EncodeHeadPlan(head)
	if err != nil {
		t.Fatal(err)
	}
	output, err := InspectRequiredSupportPage(vectors.OutputConfigurationPage.bytes(t))
	if err != nil || len(output.Records) != 1 {
		t.Fatal(err)
	}
	outputRow := contract.SupportRecord(output.Records[0])
	outputFact, err := contract.InspectSupportRecordDigest(fid(1), outputRow)
	if err != nil {
		t.Fatal(err)
	}
	support, err := contract.RequiredSupportReceiptPlanDescriptor(fid(1), []contract.SupportRecord{{Kind: contract.MutationReceiptSupportKind, RecordID: fid(20), Body: receiptBody}, outputRow}, []contract.SupportRecordDigest{{}, outputFact}, receipt)
	if err != nil {
		t.Fatal(err)
	}
	public := contract.PublicState{Domain: fid(1), AccessRoot: root.CurrentAccess.AccessRoot, RequiredSupport: support, Rows: []contract.PublicStateRow{{Name: "sample", Slot: 0, EntryDigest: fid(90)}}}
	publicDescriptor, err := contract.PublicStateDescriptor(public)
	if err != nil {
		t.Fatal(err)
	}
	authorization := contract.LifecycleAuthorizationPlan{OperationKind: contract.OperationApplyDeclaration, Operation: fid(20), Request: contract.Hash(requestBody), Recipient: fid(7), KeyBinding: fid(9), Fingerprint: storedVectorID(t, vectors.Keys.AuthorityKEK.SHA256), BindingVersion: 1,
		IdentityPlan: request.IdentityPlan, HeadCoreLength: uint32(len(headBody)), BeforeValueEntryCount: 1, AfterValueEntryCount: 1, BeforeSecretCount: 1, AfterSecretCount: 1, BeforeRawBytes: 4, AfterRawBytes: 4,
		BeforeAccessRoot: root.CurrentAccess.AccessRoot, AfterAccessRoot: root.CurrentAccess.AccessRoot, BeforeMembershipCount: 1, AfterMembershipCount: 1,
		Normal: contract.NormalSection{Intent: request.Intent, PublicState: contract.DigestLength{Digest: publicDescriptor.Digest, Length: publicDescriptor.Length}, Union: contract.DescriptorVector{Digest: fid(25), Length: 282, Count: 1}, Changed: 1},
		Grant:  contract.GrantSection{Grants: contract.DescriptorVector{Digest: fid(26), Length: 61}}, Exclusion: contract.ExclusionSection{Exclusions: contract.DescriptorVector{Digest: fid(27), Length: 65}, Retirements: contract.DescriptorVector{Digest: fid(28), Length: 66}}}
	return SuppliedApplyIdentityPlan{Request: request, Identity: identity, Snapshot: root, Head: head,
		Conditional:   ConditionalRequestPlan{Family: contract.AWS, Store: fid(71), Coordinate: fid(72), NonBody: fid(73), Condition: conditionFixture(request.PreviousToken), HeadCoreLength: uint32(len(headBody))},
		Authorization: authorization, PublicState: public, Receipt: contract.MutationReceiptDeltaPlan{DomainID: fid(1), OperationKind: contract.OperationApplyDeclaration, AddedCount: 1, Before: contract.MutationReceiptWindows{DomainID: fid(1)}, NewReceipt: receipt}}
}

// full_only: false
func TestSuppliedApplyIdentityMatchesIndependentLiteralAndNamedHoles(t *testing.T) {
	p := suppliedApplyIdentityFixture(t)
	got, err := DeriveSuppliedApplyIdentity(p)
	if err != nil || got != successionLiteralID(t, "d955c17ab078dcdf43ced3ce0bfaa2e710df17bb3496662f7d25018dc94b4e30") {
		t.Fatal("supplied request identity differs from independent fixed frame", err)
	}
	type component struct {
		name   string
		body   []byte
		length int
		digest string
	}
	var parts []component
	appendPart := func(name string, body []byte, err error, length int, digest string) {
		t.Helper()
		if err != nil {
			t.Fatal(name, err)
		}
		parts = append(parts, component{name, body, length, digest})
	}
	b, e := contract.EncodeRequestCore(p.Request)
	appendPart("request", b, e, 371, "727e36f336c6395b5d8eaa2c1aa2ef102d077275a3cdc6d03286de41120e47af")
	b, e = contract.EncodeIdentityPlan(p.Identity)
	appendPart("identity", b, e, 407, "8c9963fe99d8a30da746d33cc6dfe07438c3fdda54ebf2c6e263c403036f6570")
	b, e = EncodeRoot(p.Snapshot)
	appendPart("root", b, e, 2282, "1efda9ccf6bda21385f28e44ed3ff89cc661d9fccc7c5d5ca4284cdf5f665a10")
	b, e = EncodeHeadPlan(p.Head)
	appendPart("head", b, e, 424, "89d2830125611120dbdfbea9b82e8b2c117e93978763e7df5a018a8fdde26724")
	b, e = EncodeConditionalRequestPlan(p.Conditional)
	appendPart("condition", b, e, 158, "98f1aaa43aa8b95fe5cf56d88c1834b6fed8c257d97bd7498175c8c94e210fb8")
	b, e = contract.EncodeLifecycleAuthorizationPlan(p.Authorization)
	appendPart("authorization", b, e, 715, "c364f8c784c2fa965fddb2993975df19abafd6bbeb35852a605558ddd16f96fc")
	b, e = contract.AppendCompactMutationReceiptPlan(nil, p.Receipt.NewReceipt)
	appendPart("receipt", b, e, 471, "5267b12357261e0495193eb427fc2869f6b463849d9acf0f88f646bf1aec18bd")
	b, e = contract.EncodePublicState(p.PublicState)
	appendPart("public", b, e, 187, "7b2952b9a5da971ac8c25501fdf9ddf94ceb5dbb8b5948626d662d2889eb88e3")
	for _, part := range parts {
		if len(part.body) != part.length || contract.Hash(part.body) != successionLiteralID(t, part.digest) {
			t.Fatal("independent component literal differs", part.name)
		}
	}
	delta, err := contract.MutationReceiptDeltaPlanDigest(p.Receipt)
	if err != nil || delta != successionLiteralID(t, "789ed75b02ff050adac26137622d9339b9169803ad45b2a91dc498bbccd25a3a") {
		t.Fatal("independent receipt delta differs", err)
	}
	if _, err := EncodeHeadCore(HeadCore(p.Head)); err == nil {
		t.Fatal("stored HEAD accepted its root digest hole")
	}
	if _, err := DecodeHeadCore(parts[3].body); err == nil {
		t.Fatal("stored HEAD decoder accepted the plan")
	}
	if _, err := EncodeConditionalPlan(ConditionalPlan(p.Conditional)); err == nil {
		t.Fatal("executable condition accepted its HEAD hole")
	}
	if _, err := DecodeConditionalPlan(parts[4].body); err == nil {
		t.Fatal("stored condition decoder accepted the plan")
	}
	if _, err := contract.LifecycleBytes(contract.LifecycleSubject(p.Authorization)); err == nil {
		t.Fatal("actual lifecycle accepted its digest holes")
	}
	if _, err := contract.InspectCompactMutationReceipt(parts[6].body); err == nil {
		t.Fatal("stored receipt accepted its request hole")
	}
}

// full_only: false
func TestSuppliedApplyIdentityRejectsCrossPartSubstitution(t *testing.T) {
	for name, change := range map[string]func(*SuppliedApplyIdentityPlan){
		"request-domain":          func(p *SuppliedApplyIdentityPlan) { p.Request.Domain = fid(200) },
		"request-identity-digest": func(p *SuppliedApplyIdentityPlan) { p.Request.IdentityPlan.Digest = fid(200) },
		"request-identity-length": func(p *SuppliedApplyIdentityPlan) { p.Request.IdentityPlan.Length++ },
		"request-intent":          func(p *SuppliedApplyIdentityPlan) { p.Request.Intent.Digest = fid(200) },
		"snapshot-id":             func(p *SuppliedApplyIdentityPlan) { p.Snapshot.Snapshot = fid(200) },
		"snapshot-transition":     func(p *SuppliedApplyIdentityPlan) { p.Snapshot.Transition = fid(200) },
		"head-root-object":        func(p *SuppliedApplyIdentityPlan) { p.Head.Root.Object = fid(200) },
		"head-root-length":        func(p *SuppliedApplyIdentityPlan) { p.Head.Root.Length++ },
		"head-root-hole-filled":   func(p *SuppliedApplyIdentityPlan) { p.Head.Root.Digest = fid(200) },
		"head-domain":             func(p *SuppliedApplyIdentityPlan) { p.Head.Domain = fid(200) },
		"head-revision":           func(p *SuppliedApplyIdentityPlan) { p.Head.Revision = fid(200) },
		"head-previous-revision":  func(p *SuppliedApplyIdentityPlan) { p.Head.PreviousRevision = fid(200) },
		"head-previous-digest":    func(p *SuppliedApplyIdentityPlan) { p.Head.PreviousDigest = fid(200) },
		"head-previous-token":     func(p *SuppliedApplyIdentityPlan) { p.Head.PreviousToken.Value = `"other"` },
		"head-store":              func(p *SuppliedApplyIdentityPlan) { p.Head.Store = fid(200) },
		"head-trust":              func(p *SuppliedApplyIdentityPlan) { p.Head.Trust = fid(200) },
		"head-coordinate":         func(p *SuppliedApplyIdentityPlan) { p.Head.Coordinate = fid(200) },
		"head-non-body":           func(p *SuppliedApplyIdentityPlan) { p.Head.NonBody = fid(200) },
		"head-interpretation":     func(p *SuppliedApplyIdentityPlan) { p.Head.Interpretation = fid(200) },
		"head-epoch":              func(p *SuppliedApplyIdentityPlan) { p.Head.Epoch++ },
		"condition-family":        func(p *SuppliedApplyIdentityPlan) { p.Conditional.Family = contract.GCP },
		"condition-store":         func(p *SuppliedApplyIdentityPlan) { p.Conditional.Store = fid(200) },
		"condition-coordinate":    func(p *SuppliedApplyIdentityPlan) { p.Conditional.Coordinate = fid(200) },
		"condition-non-body":      func(p *SuppliedApplyIdentityPlan) { p.Conditional.NonBody = fid(200) },
		"condition-token": func(p *SuppliedApplyIdentityPlan) {
			p.Conditional.Condition = conditionFixture(contract.Token{Family: contract.AWS, Value: `"other"`})
		},
		"condition-absent":        func(p *SuppliedApplyIdentityPlan) { p.Conditional.Condition = contract.AbsentHeadCondition() },
		"condition-length":        func(p *SuppliedApplyIdentityPlan) { p.Conditional.HeadCoreLength++ },
		"condition-hole-filled":   func(p *SuppliedApplyIdentityPlan) { p.Conditional.HeadCore = fid(200) },
		"authorization-request":   func(p *SuppliedApplyIdentityPlan) { p.Authorization.Request = fid(200) },
		"authorization-operation": func(p *SuppliedApplyIdentityPlan) { p.Authorization.Operation = fid(200) },
		"authorization-kind": func(p *SuppliedApplyIdentityPlan) {
			p.Authorization.OperationKind = contract.OperationRotateRecipientKeyBinding
		},
		"authorization-identity":              func(p *SuppliedApplyIdentityPlan) { p.Authorization.IdentityPlan.Digest = fid(200) },
		"authorization-intent":                func(p *SuppliedApplyIdentityPlan) { p.Authorization.Normal.Intent.Digest = fid(200) },
		"authorization-public":                func(p *SuppliedApplyIdentityPlan) { p.Authorization.Normal.PublicState.Digest = fid(200) },
		"authorization-access":                func(p *SuppliedApplyIdentityPlan) { p.Authorization.AfterAccessRoot = fid(200) },
		"authorization-head-length":           func(p *SuppliedApplyIdentityPlan) { p.Authorization.HeadCoreLength++ },
		"authorization-head-hole-filled":      func(p *SuppliedApplyIdentityPlan) { p.Authorization.HeadCore = fid(200) },
		"authorization-condition-hole-filled": func(p *SuppliedApplyIdentityPlan) { p.Authorization.ConditionalPlan = fid(200) },
		"public-domain":                       func(p *SuppliedApplyIdentityPlan) { p.PublicState.Domain = fid(200) },
		"public-access":                       func(p *SuppliedApplyIdentityPlan) { p.PublicState.AccessRoot = fid(200) },
		"public-name":                         func(p *SuppliedApplyIdentityPlan) { p.PublicState.Rows[0].Name = "another" },
		"public-slot":                         func(p *SuppliedApplyIdentityPlan) { p.PublicState.Rows[0].Slot++ },
		"public-row-count":                    func(p *SuppliedApplyIdentityPlan) { p.PublicState.Rows = nil },
		"page-object":                         func(p *SuppliedApplyIdentityPlan) { p.Identity.Pages[0].Object = fid(200) },
		"receipt-added-count":                 func(p *SuppliedApplyIdentityPlan) { p.Receipt.AddedCount = 0 },
		"receipt-operation-kind":              func(p *SuppliedApplyIdentityPlan) { p.Receipt.OperationKind = contract.OperationRotateValueEntryValue },
		"receipt-domain":                      func(p *SuppliedApplyIdentityPlan) { p.Receipt.DomainID = fid(200) },
		"receipt-operation":                   func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.OperationID = fid(200) },
		"receipt-predecessor":                 func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.PredecessorRevisionID = fid(200) },
		"receipt-requested-revision":          func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.RequestedRevisionID = fid(200) },
		"receipt-observed-revision":           func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.ObservedRevisionID = fid(200) },
		"receipt-hole-filled":                 func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.RequestIdentityDigest = fid(200) },
	} {
		t.Run(name, func(t *testing.T) {
			p := suppliedApplyIdentityFixture(t)
			change(&p)
			if _, err := DeriveSuppliedApplyIdentity(p); err == nil {
				t.Fatal("cross-part substitution or an unnamed hole accepted")
			}
		})
	}
}

// full_only: false
func TestSuppliedApplyIdentityBindsEveryOpaquePlanCommitment(t *testing.T) {
	for name, change := range map[string]func(*SuppliedApplyIdentityPlan){
		"complete-result":     func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.CompleteResult.Digest = fid(200) },
		"changed-subjects":    func(p *SuppliedApplyIdentityPlan) { p.Receipt.NewReceipt.ChangedSubjects.Digest = fid(200) },
		"union":               func(p *SuppliedApplyIdentityPlan) { p.Authorization.Normal.Union.Digest = fid(200) },
		"grants":              func(p *SuppliedApplyIdentityPlan) { p.Authorization.Grant.Grants.Digest = fid(200) },
		"exclusions":          func(p *SuppliedApplyIdentityPlan) { p.Authorization.Exclusion.Exclusions.Digest = fid(200) },
		"retirements":         func(p *SuppliedApplyIdentityPlan) { p.Authorization.Exclusion.Retirements.Digest = fid(200) },
		"before-access":       func(p *SuppliedApplyIdentityPlan) { p.Authorization.BeforeAccessRoot = fid(200) },
		"authorizing-binding": func(p *SuppliedApplyIdentityPlan) { p.Authorization.KeyBinding = fid(200) },
	} {
		t.Run(name, func(t *testing.T) {
			p := suppliedApplyIdentityFixture(t)
			before, err := DeriveSuppliedApplyIdentity(p)
			if err != nil {
				t.Fatal(err)
			}
			change(&p)
			after, err := DeriveSuppliedApplyIdentity(p)
			if err != nil || after == before {
				t.Fatal("opaque plan commitment was omitted from identity", err)
			}
		})
	}
}
