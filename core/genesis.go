package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"reflect"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// InitContext is issued only by the enclosing initialization admission owner.
// Parsed public records cannot install durability or private custody facts.
type InitContext struct{ admission *initAdmission }
type artifactReceipt struct{ fact contract.GenesisArtifactFact }
type initAdmission struct {
	observation          *operationObservation
	open                 OpenContext
	prepared             *genesisPreparation
	descriptor, manifest artifactReceipt
	qualification        contract.CryptoQualifyInitKeysRequest
	requestID, custodyID contract.ID
	custody              contract.Crypto
	deadline             time.Time
	used                 bool
}
type genesisPreparation struct {
	descriptor                                              contract.GenesisDescriptorCore
	plan                                                    format.GenesisPlanCore
	request                                                 contract.GenesisRequestCore
	manifest                                                contract.GenesisBootstrapManifestCore
	descriptorBytes, planBytes, requestBytes, manifestBytes []byte
	objects                                                 []objectImage
}

func matchedCondition(t contract.Token) contract.HeadCondition {
	v, err := contract.MatchHeadCondition(t)
	if err != nil {
		return contract.HeadCondition{}
	}
	return v
}

func planGenesis(a openAdmission) (*genesisPreparation, error) {
	return planGenesisScope(a, contract.Hash(a.descriptor), uint64(a.expires.UnixNano()))
}

func planGenesisScope(a openAdmission, setup contract.ID, expiry uint64) (*genesisPreparation, error) {
	d, ok := a.domainBasis()
	if !ok {
		return nil, contract.ErrSubject
	}
	used := map[contract.ID]bool{}
	for _, id := range []contract.ID{d.InitID, d.DomainID, d.DescriptorArtifactID, d.ManifestArtifactID, d.StoreID, d.TrustID, d.AuthorityRecipientID} {
		used[id] = true
	}
	for _, r := range d.Recipients {
		used[r.RecipientID] = true
		used[r.CurrentBinding.BindingID] = true
	}
	if d.Recovery != nil {
		used[d.Recovery.RoleID] = true
		used[d.Recovery.KMS.BindingID] = true
	}
	entropy := a.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	next := func() (contract.ID, error) {
		var id contract.ID
		if _, err := io.ReadFull(entropy, id[:]); err != nil {
			return id, err
		}
		if id.IsZero() || used[id] {
			return contract.ID{}, contract.ErrSubject
		}
		used[id] = true
		return id, nil
	}
	identity := contract.IdentityPlan{Operation: d.InitID}
	for _, id := range []*contract.ID{&identity.Transition, &identity.Snapshot, &identity.Revision} {
		v, err := next()
		if err != nil {
			return nil, err
		}
		*id = v
	}
	for i := 0; i < (len(d.Recipients)+7)/8; i++ {
		id, err := next()
		if err != nil {
			return nil, err
		}
		identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: format.RecipientKind, Index: uint16(i), Object: id})
	}
	indexID, err := next()
	if err != nil {
		return nil, err
	}
	supportID, err := next()
	if err != nil {
		return nil, err
	}
	identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: 0, Object: supportID})
	fragmentPageID, err := next()
	if err != nil {
		return nil, err
	}
	identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: contract.RequiredSupportKind, Index: 1, Object: fragmentPageID})
	identity.Pages = append(identity.Pages, contract.IdentityPage{Kind: contract.AdministrativeIndexKind, Index: 0, Object: indexID})
	bindings, err := d.BindingTable()
	if err != nil {
		return nil, err
	}
	probes := make([]contract.InitProbePlanRow, 0, 1+int(d.RecoveryMode()))
	for _, b := range bindings {
		if b.SubjectKind == contract.OrdinaryWrapSubject && b.SubjectID != d.AuthorityRecipientID {
			continue
		}
		id, err := next()
		if err != nil {
			return nil, err
		}
		digest, err := contract.PublicBindingDigest(b.Binding)
		if err != nil {
			return nil, err
		}
		probes = append(probes, contract.InitProbePlanRow{ProbeID: id, SubjectKind: b.SubjectKind, SubjectID: b.SubjectID, BindingID: b.Binding.BindingID, PublicBindingDigest: digest})
	}
	var challenge contract.ID
	if d.Recovery != nil {
		challenge, err = next()
		if err != nil {
			return nil, err
		}
	}
	return reconstructGenesis(a, d, identity, probes, challenge, setup, expiry)
}

// Reconstruction is deterministic and has no Store, signing or private-key
// effects. Reopen uses the stored plan only for its allocated public identities.
func reconstructGenesis(a openAdmission, d contract.GenesisDescriptorCore, identity contract.IdentityPlan, probes []contract.InitProbePlanRow, challenge contract.ID, setup contract.ID, expiry uint64) (*genesisPreparation, error) {
	descriptor, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil || !bytes.Equal(descriptor, a.descriptor) {
		return nil, contract.ErrSubject
	}
	return reconstructGenesisPlan(d, identity, probes, challenge, setup, expiry)
}

// reconstructGenesisPlan derives the public selected plan from explicit fixed
// inputs. Ordinary admission separately compares its independent descriptor;
// complete reconstruction compares the resulting bytes to signed closure facts.
func reconstructGenesisPlan(d contract.GenesisDescriptorCore, identity contract.IdentityPlan, probes []contract.InitProbePlanRow, challenge contract.ID, setup contract.ID, expiry uint64) (*genesisPreparation, error) {
	descriptor, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		return nil, err
	}
	recipientPages := (len(d.Recipients) + 7) / 8
	if identity.Operation != d.InitID || len(identity.Pages) != recipientPages+3 || len(identity.Rows) != 0 {
		return nil, contract.ErrSubject
	}
	p := &genesisPreparation{descriptor: d, descriptorBytes: descriptor}
	root := format.Root{Domain: d.DomainID, Snapshot: identity.Snapshot, Transition: identity.Transition, RecipientCount: uint16(len(d.Recipients)), Generated: format.EmptyGeneratedClosure(), GCPlans: contract.EmptyGCOwnersDescriptor()}
	var refs []contract.Ref
	for i, row := range identity.Pages[:recipientPages] {
		if row.Kind != format.RecipientKind || row.Index != uint16(i) {
			return nil, contract.ErrSubject
		}
		page := format.RecipientPage{Domain: d.DomainID, Object: row.Object, Index: row.Index}
		for j := 0; j < format.RecipientSlots && i*format.RecipientSlots+j < len(d.Recipients); j++ {
			v := d.Recipients[i*format.RecipientSlots+j]
			page.Slots[j] = &v
		}
		body, err := format.EncodeRecipientPage(page)
		if err != nil {
			return nil, err
		}
		ref, err := format.Reference(format.RecipientKind, d.DomainID, page.Object, page.Index, body)
		if err != nil {
			return nil, err
		}
		root.Recipients[i] = &ref
		refs = append(refs, ref)
		root.ChildCount++
		root.ChildEncodedBytes += uint64(len(body))
		p.objects = append(p.objects, objectImage{ref: ref, body: body})
	}
	indexPage := identity.Pages[recipientPages+2]
	if indexPage.Kind != contract.AdministrativeIndexKind || indexPage.Index != 0 {
		return nil, contract.ErrSubject
	}
	supportIdentity := identity.Pages[recipientPages]
	fragmentIdentity := identity.Pages[recipientPages+1]
	if fragmentIdentity.Kind != contract.RequiredSupportKind || fragmentIdentity.Index != 1 {
		return nil, contract.ErrSubject
	}
	if supportIdentity.Kind != contract.RequiredSupportKind || supportIdentity.Index != 0 {
		return nil, contract.ErrSubject
	}
	identityBytes, err := contract.EncodeGenesisIdentityPlanCore(contract.GenesisIdentityPlanCore{DomainID: d.DomainID,
		DescriptorDigest: contract.Hash(descriptor), IdentityPlan: identity, RecoveryMode: d.RecoveryMode(),
		K3ChallengeID: challenge, Probes: probes})
	if err != nil {
		return nil, err
	}
	p.request = contract.GenesisRequestCore{InitID: d.InitID, DomainID: d.DomainID, DescriptorDigest: contract.Hash(descriptor),
		GenesisIdentityPlanDigest: contract.Hash(identityBytes), SetupDigest: setup, Expiry: expiry,
		RecoveryMode: d.RecoveryMode(), InitOwnerDecision: 1, RecoveryLossAcknowledgement: 1 - d.RecoveryMode()}
	p.requestBytes, err = contract.EncodeGenesisRequestCore(p.request)
	if err != nil {
		return nil, err
	}
	receipt, err := genesisReceipt(p.request, identity.Revision)
	if err != nil {
		return nil, err
	}
	receiptBody, err := contract.EncodeCompactMutationReceipt(receipt)
	if err != nil {
		return nil, err
	}
	windows, err := contract.AppendMutationReceipt(contract.MutationReceiptWindows{DomainID: d.DomainID}, receipt)
	if err != nil {
		return nil, err
	}
	indexes, err := windows.Indexes()
	if err != nil {
		return nil, err
	}
	root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		return nil, err
	}
	receiptIndex, blob, err := endWorkReceiptIndexRow(d.DomainID, indexes)
	if err != nil {
		return nil, err
	}
	outputImage, err := contract.EncodeOutputConfiguration(contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: d.DomainID})
	if err != nil {
		return nil, err
	}
	outputDescriptor, outputSlices, err := contract.SplitOutputConfiguration(d.DomainID, outputImage)
	if err != nil || len(outputSlices) != 1 {
		return nil, contract.ErrRecord
	}
	sliceBody, err := contract.EncodeOutputConfigurationSlice(outputSlices[0])
	if err != nil {
		return nil, err
	}
	sliceID, err := contract.OutputConfigurationSliceID(d.DomainID, outputDescriptor.ConfigurationDigest, 0)
	if err != nil {
		return nil, err
	}
	rows := []contract.SupportRecord{{Kind: contract.OutputConfigurationSliceSupportKind, RecordID: sliceID, Body: sliceBody},
		{Kind: contract.MutationReceiptSupportKind, RecordID: d.InitID, Body: receiptBody}}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind < b.Kind {
			return -1
		}
		if a.Kind > b.Kind {
			return 1
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	root.Generated.Fragments = []format.FragmentLocation{{BlobID: blob, SupportPageIndex: 1}}
	fragmentBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: d.DomainID,
		Object: fragmentIdentity.Object, Index: 1, Records: []contract.SupportRecord{receiptIndex}})
	if err != nil {
		return nil, err
	}
	fragmentRef, err := format.Reference(contract.RequiredSupportKind, d.DomainID, fragmentIdentity.Object, 1, fragmentBody)
	if err != nil {
		return nil, err
	}
	supportBody, err := format.EncodeRequiredSupportPage(format.RequiredSupportPage{Domain: d.DomainID, Object: supportIdentity.Object,
		Index: 0, Records: rows})
	if err != nil {
		return nil, err
	}
	supportRef, err := format.Reference(contract.RequiredSupportKind, d.DomainID, supportIdentity.Object, 0, supportBody)
	if err != nil {
		return nil, err
	}
	index := format.AdministrativeIndex{Domain: d.DomainID, Object: indexPage.Object, SliceSnapshot: root.Snapshot,
		Pages: []format.AdministrativePage{endWorkIndexPage(supportRef, rows), endWorkIndexPage(fragmentRef, []contract.SupportRecord{receiptIndex})}}
	indexPages, err := format.EncodeAdministrativeIndexPages(index)
	if err != nil || len(indexPages) != 1 || indexPages[0].Ref.Object != indexPage.Object {
		return nil, contract.ErrRecord
	}
	root.AdministrativeIndex = indexPages[0].Ref
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(indexPages[0].Body))
	p.objects = append(p.objects, objectImage{ref: root.AdministrativeIndex, body: indexPages[0].Body})
	root.OutputConfiguration = outputDescriptor
	root.RequiredSupport = []contract.Ref{supportRef, fragmentRef}
	root.RequiredSupportRecordCount = uint32(len(rows) + 1)
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(supportBody))
	p.objects = append(p.objects, objectImage{ref: supportRef, body: supportBody}, objectImage{ref: fragmentRef, body: fragmentBody})
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(fragmentBody))
	recipients, err := contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: d.DomainID, Refs: refs})
	if err != nil {
		return nil, err
	}
	records, err := contract.AccessRecordsDescriptor(d.DomainID, nil)
	if err != nil {
		return nil, err
	}
	root.CurrentAccess.Core = contract.CurrentAccessCore{CurrentControl: d.CurrentControl(), RecipientRefsDescriptor: recipients, AccessRecordsDescriptor: records}
	root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		return nil, err
	}
	rootBytes, err := format.EncodeRoot(root)
	if err != nil {
		return nil, err
	}
	rootRef, err := format.Reference(format.RootKind, d.DomainID, root.Snapshot, 0, rootBytes)
	if err != nil {
		return nil, err
	}
	p.objects = append(p.objects, objectImage{ref: rootRef, body: rootBytes})
	head := format.HeadCore{Form: format.GenesisHead, Domain: d.DomainID, Revision: identity.Revision, Root: rootRef, Store: d.StoreID, Trust: d.TrustID, Coordinate: d.CoordinateID, NonBody: d.NonBodyID, Interpretation: d.InterpretationID, Epoch: 1}
	headBytes, err := format.EncodeHeadCore(head)
	if err != nil {
		return nil, err
	}
	conditional := format.ConditionalPlan{Family: d.Provider, Store: d.StoreID, Coordinate: d.CoordinateID, NonBody: d.NonBodyID, Condition: contract.AbsentHeadCondition(), HeadCore: contract.Hash(headBytes), HeadCoreLength: uint32(len(headBytes))}
	p.plan = format.GenesisPlanCore{DescriptorDigest: contract.Hash(descriptor), IdentityPlan: identity, Root: root, HeadCore: head, ConditionalPlan: conditional, RecoveryMode: d.RecoveryMode(), K3ChallengeID: challenge, Probes: slices.Clone(probes)}
	p.planBytes, err = format.EncodeGenesisPlanCore(p.plan)
	if err != nil {
		return nil, err
	}
	p.manifest, err = genesisManifest(d, p.request, p.plan, p.objects)
	if err != nil {
		return nil, err
	}
	p.manifestBytes, err = contract.EncodeGenesisBootstrapManifestCore(p.manifest)
	if err != nil {
		return nil, err
	}
	return p, nil
}
func genesisChallenge(d contract.GenesisDescriptorCore, q contract.GenesisRequestCore, p format.GenesisPlanCore) (contract.GenesisK3ChallengeCore, error) {
	if d.Recovery == nil {
		return contract.GenesisK3ChallengeCore{}, contract.ErrSubject
	}
	signing, err := contract.SigningBindingDigest(d.Recovery.Signing)
	if err != nil {
		return contract.GenesisK3ChallengeCore{}, err
	}
	kms, err := contract.PublicBindingDigest(d.Recovery.KMS)
	if err != nil {
		return contract.GenesisK3ChallengeCore{}, err
	}
	request, err := contract.EncodeGenesisRequestCore(q)
	if err != nil {
		return contract.GenesisK3ChallengeCore{}, err
	}
	return contract.GenesisK3ChallengeCore{InitID: d.InitID, DomainID: d.DomainID, DescriptorDigest: q.DescriptorDigest, RequestCoreDigest: contract.Hash(request), GenesisPlanDigest: genesisPlanDigest(p), StoreID: d.StoreID, CoordinateID: d.CoordinateID, RecoveryRoleID: d.Recovery.RoleID, K3SigningBindingDigest: signing, RecoveryKMSBindingDigest: kms, K3ChallengeID: p.K3ChallengeID}, nil
}
func genesisManifest(d contract.GenesisDescriptorCore, q contract.GenesisRequestCore, p format.GenesisPlanCore, objects []objectImage) (contract.GenesisBootstrapManifestCore, error) {
	request, err := contract.EncodeGenesisRequestCore(q)
	if err != nil {
		return contract.GenesisBootstrapManifestCore{}, err
	}
	normal, err := contract.NewBindingRequest(d.NormalSigning.Binding)
	if err != nil {
		return contract.GenesisBootstrapManifestCore{}, err
	}
	signing, err := contract.SigningBindingDigest(d.NormalSigning)
	if err != nil {
		return contract.GenesisBootstrapManifestCore{}, err
	}
	m := contract.GenesisBootstrapManifestCore{DescriptorDigest: q.DescriptorDigest, RequestCoreDigest: contract.Hash(request), GenesisPlanDigest: genesisPlanDigest(p), NormalBindingSubjectDigest: normal.Digest(), RecoveryMode: d.RecoveryMode(), Signers: []contract.GenesisSignerPlanRow{{TargetRole: 1, SigningBindingDigest: signing}}, Probes: slices.Clone(p.Probes), HeadCoreDigest: p.ConditionalPlan.HeadCore, HeadCoreLength: p.ConditionalPlan.HeadCoreLength, ConditionalPlanDigest: p.ConditionalPlanDigest()}
	if d.Recovery != nil {
		basis, err := contract.NewK3BasisRequest(d.Recovery.Signing)
		if err != nil {
			return m, err
		}
		m.K3BasisSubjectDigest = basis.Digest()
		challenge, err := genesisChallenge(d, q, p)
		if err != nil {
			return m, err
		}
		body, err := contract.EncodeGenesisK3ChallengeCore(challenge)
		if err != nil {
			return m, err
		}
		m.K3InitChallengeCoreDigest = contract.Hash(body)
		signing, err = contract.SigningBindingDigest(d.Recovery.Signing)
		if err != nil {
			return m, err
		}
		m.Signers = append(m.Signers, contract.GenesisSignerPlanRow{TargetRole: 3, SigningBindingDigest: signing})
	}
	bindings, err := d.BindingTable()
	if err != nil {
		return m, err
	}
	for _, b := range bindings {
		digest, err := contract.PublicBindingDigest(b.Binding)
		if err != nil {
			return m, err
		}
		m.PublicBindings = append(m.PublicBindings, contract.GenesisPublicBindingRow{SubjectKind: b.SubjectKind, SubjectID: b.SubjectID, BindingID: b.Binding.BindingID, PublicBindingDigest: digest})
	}
	for _, o := range objects {
		m.Immutable = append(m.Immutable, o.ref)
	}
	return m, nil
}
func (a *initAdmission) valid(store contract.Store, crypto contract.Crypto) bool {
	if a == nil || a.used || a.open.admission == nil || !a.open.admission.valid(store) || a.prepared == nil || crypto == nil ||
		a.custody == nil || !reflect.TypeOf(crypto).Comparable() || crypto != a.custody || a.custodyID.IsZero() ||
		a.custodyID != a.custody.InstanceID() || a.requestID.IsZero() || !time.Now().Before(a.deadline) || a.deadline.After(a.open.admission.expires) {
		return false
	}
	p := a.prepared
	q := a.qualification
	c := q.Context
	if c.DomainID != p.descriptor.DomainID || c.CompatibilityID != contract.CompatibilityID() || c.InitID != p.descriptor.InitID || c.Expiry != uint64(a.deadline.UnixNano()) || c.Expiry > p.request.Expiry || c.DescriptorDigest != contract.Hash(p.descriptorBytes) || c.GenesisPlanDigest != contract.Hash(p.planBytes) || c.RequestDescriptor != (contract.DescriptorVector{Digest: contract.Hash(p.requestBytes), Length: uint64(len(p.requestBytes)), Count: 1}) {
		return false
	}
	if _, err := contract.EncodeCryptoQualifyInitKeysRequest(q); err != nil {
		return false
	}
	expected, err := p.descriptor.BindingTable()
	if err != nil {
		return false
	}
	left, err := contract.EncodeBindingTable(expected)
	if err != nil {
		return false
	}
	right, err := contract.EncodeBindingTable(q.Bindings)
	if err != nil || !bytes.Equal(left, right) || !slices.Equal(q.Probes, p.plan.Probes) {
		return false
	}
	return artifactMatches(a.descriptor.fact, 1, p.descriptor.DescriptorArtifactID, p.descriptorBytes) && artifactMatches(a.manifest.fact, 2, p.descriptor.ManifestArtifactID, p.manifestBytes)
}
func artifactMatches(f contract.GenesisArtifactFact, kind uint8, id contract.ID, body []byte) bool {
	return f.Kind == kind && f.ArtifactID == id && f.BodyDigest == contract.Hash(body) && f.BodyLength == uint64(len(body)) && f.DurabilityProfile == 1 && f.Outcome == 1
}

// Initialize executes InternalEmptyGenesis/v1. A zero context refuses before
// any external call. Only authenticated selected bytes establish its outcome.
func initialize(ctx context.Context, admitted InitContext, store contract.Store, normal, recovery contract.QualifyingTrust, crypto contract.Crypto) (*StateSession, Result) {
	if ctx == nil || ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	a := admitted.admission
	if !a.valid(store, crypto) {
		return nil, refused(AdmissionInvalid)
	}
	var cancel context.CancelFunc
	ctx, cancel = context.WithDeadline(ctx, a.deadline)
	defer cancel()
	p := a.prepared
	d := p.descriptor
	if normal == nil || normal.Identity() != d.TrustID || normal.Family() != d.Provider || (d.Recovery == nil) != (recovery == nil) || recovery != nil && (recovery.Identity() != d.Recovery.Signing.Binding.Trust || recovery.Family() != d.Provider) {
		return nil, refused(ConstructionMismatch)
	}
	rebuilt, err := reconstructGenesis(*a.open.admission, d, p.plan.IdentityPlan, p.plan.Probes, p.plan.K3ChallengeID, p.request.SetupDigest, p.request.Expiry)
	if err != nil || !bytes.Equal(rebuilt.planBytes, p.planBytes) || !bytes.Equal(rebuilt.requestBytes, p.requestBytes) || !bytes.Equal(rebuilt.manifestBytes, p.manifestBytes) {
		return nil, refused(AdmissionInvalid)
	}
	a.used = true
	key, ok := publicKey(a.open.admission.publicKey)
	if !ok {
		return nil, refused(InvalidProof)
	}
	s := &StateSession{admission: *a.open.admission, store: store, key: key, cache: map[format.Ref][]byte{}}
	initial := s.storeRead(ctx, s.admission.store.HeadKey, contract.MaxHeadLength)
	if initial.Status == contract.ReadOK {
		selected, res := s.readCurrent(ctx)
		if selected != nil && sameGenesisPreparation(selected, p) {
			return selected, res
		}
		if selected != nil {
			return nil, failure(Contention, DifferentSelection)
		}
		if res.Outcome == IntegrityFailure {
			return nil, refused(res.Reason)
		}
		return nil, res
	}
	if initial.Status != contract.ReadMissing {
		if initial.Status == contract.ReadInvalid {
			return nil, refused(InvalidFormat)
		}
		return nil, unavailableStoreRead(initial)
	}
	source, ok := store.(contract.StoreConfigurationSource)
	if !ok {
		return nil, refused(ConstructionMismatch)
	}
	configuration := source.StoreConfiguration()
	configurationBytes, err := contract.EncodeStoreConfiguration(configuration)
	if err != nil {
		return nil, refused(ConstructionMismatch)
	}
	configurationID := contract.Hash(configurationBytes)
	if configuration.DomainID != d.DomainID || configuration.Provider != d.Provider || configurationID != d.StoreID ||
		configurationID != s.admission.store.Identity {
		return nil, refused(ConstructionMismatch)
	}
	configurationKey, err := contract.StoreConfigurationKey(configuration)
	if err != nil {
		return nil, refused(ConstructionMismatch)
	}
	active := func() bool { return ctx.Err() == nil && time.Now().Before(a.deadline) && s.admission.valid(store) }
	closure := contract.GenesisBootstrapClosureCore{DescriptorDigest: p.manifest.DescriptorDigest, RequestCoreDigest: p.manifest.RequestCoreDigest, GenesisPlanDigest: p.manifest.GenesisPlanDigest, ManifestDigest: contract.Hash(p.manifestBytes), DescriptorReadbackFact: a.descriptor.fact, ManifestReadbackFact: a.manifest.fact, ConfigurationReadbackFact: contract.GenesisArtifactFact{Kind: 3, ArtifactID: configurationID, BodyDigest: configurationID, BodyLength: uint64(len(configurationBytes)), DurabilityProfile: 1, Outcome: 1}, InitialHeadObservation: 1, NormalBindingSubjectDigest: p.manifest.NormalBindingSubjectDigest, RecoveryMode: d.RecoveryMode(), K3BasisSubjectDigest: p.manifest.K3BasisSubjectDigest, K3InitChallengeCoreDigest: p.manifest.K3InitChallengeCoreDigest}
	var signingFailure Result
	qualify := func(t contract.QualifyingTrust, b contract.PublicSigningBinding, target uint8) bool {
		if !active() {
			signingFailure = refused(AdmissionInvalid)
			return false
		}
		q := t.QualifySigningBinding(ctx, b)
		if ctx.Err() != nil || q.Qualified == 0 && (q.Reason == contract.ReasonAccess || q.Reason == contract.ReasonTransport || q.Reason == contract.ReasonLimit) {
			signingFailure = failure(EvidenceUnavailable, SigningUnavailable)
			return false
		}
		digest, err := contract.SigningBindingDigest(b)
		if err != nil || q.Qualified != 1 || q.Reason != contract.ReasonNone || q.TargetRole != target || q.SigningBindingDigest != digest || q.Provider != d.Provider {
			signingFailure = failure(IntegrityFailure, InvalidProof)
			return false
		}
		closure.Signers = append(closure.Signers, q)
		return true
	}
	if !qualify(normal, d.NormalSigning, 1) {
		return nil, signingFailure
	}
	if recovery != nil && !qualify(recovery, d.Recovery.Signing, 3) {
		return nil, signingFailure
	}
	sign := func(t contract.Trust, q contract.SignRequest, public []byte) ([]byte, bool) {
		if !active() {
			signingFailure = refused(AdmissionInvalid)
			return nil, false
		}
		key, ok := publicKey(public)
		if !ok {
			signingFailure = failure(IntegrityFailure, InvalidProof)
			return nil, false
		}
		result := s.trustSign(ctx, t, q)
		if result.Reason == contract.ReasonProof || result.Reason == contract.ReasonMalformed || result.Reason == contract.ReasonNone && !verify(key, q, result.Signature) {
			signingFailure = failure(IntegrityFailure, InvalidProof)
			return nil, false
		}
		if result.Reason != contract.ReasonNone {
			signingFailure = failure(EvidenceUnavailable, SigningUnavailable)
			return nil, false
		}
		return bytes.Clone(result.Signature), true
	}
	head := format.Head{Core: p.plan.HeadCore, AuthKind: format.GenesisAuth}
	k1, err := contract.NewBindingRequest(d.NormalSigning.Binding)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	head.K1, ok = sign(normal, k1, d.NormalSigning.SPKI)
	if !ok {
		return nil, signingFailure
	}
	var challengeProof []byte
	if recovery != nil {
		q, err := contract.NewK3BasisRequest(d.Recovery.Signing)
		if err != nil {
			return nil, refused(InvalidProof)
		}
		head.K3, ok = sign(recovery, q, d.Recovery.Signing.SPKI)
		if !ok {
			return nil, signingFailure
		}
		challenge, err := genesisChallenge(d, p.request, p.plan)
		if err != nil {
			return nil, refused(InvalidProof)
		}
		q, err = contract.NewK3InitChallengeRequest(challenge)
		if err != nil {
			return nil, refused(InvalidProof)
		}
		challengeProof, ok = sign(recovery, q, d.Recovery.Signing.SPKI)
		if !ok {
			return nil, signingFailure
		}
	}
	if !active() {
		return nil, refused(AdmissionInvalid)
	}
	body, err := contract.EncodeCryptoQualifyInitKeysRequest(a.qualification)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoQualifyInitKeys, RequestID: a.requestID, CustodyInstanceID: a.custodyID, Body: body}
	reply := a.custody.Exchange(ctx, q)
	if a.custody.InstanceID() != a.custodyID {
		return nil, refused(AdmissionInvalid)
	}
	if err := contract.ValidateCryptoExchange(q, reply); err != nil {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	if err := contract.ValidateInitKeyUseRows(a.qualification, reply.KeyUseRows); err != nil {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	if a.observation.enabled() && active() {
		c := a.qualification.Context
		a.observation.offerExchange(ctx, exchangeObservation{Source: observationSource{Stage: observationExchange,
			DomainID: c.DomainID, AdmissionID: c.AdmissionID, SessionID: c.SessionID, InitID: c.InitID},
			RequestID: q.RequestID, Kind: q.Kind, CustodyInstanceID: q.CustodyInstanceID, ResultCode: reply.ResultCode, Rows: reply.KeyUseRows})
	}
	if reply.ResultCode != contract.CryptoSuccess {
		return nil, failure(EvidenceUnavailable, SigningUnavailable)
	}
	closure.QualifiedKeys, err = contract.DecodeCryptoQualifyInitKeysResult(reply.Body)
	if err != nil || !active() {
		return nil, refused(AdmissionInvalid)
	}
	if res := s.persistImmutable(ctx, configurationKey, configurationBytes, uint32(len(configurationBytes))); res.Outcome != 0 {
		return nil, res
	}
	for _, object := range p.objects {
		if !active() {
			return nil, refused(AdmissionInvalid)
		}
		key, err := format.Key(s.admission.store.Prefix, object.ref)
		if err != nil {
			return nil, refused(InvalidReference)
		}
		if res := s.persistImmutable(ctx, key, object.body, object.ref.Length); res.Outcome != 0 {
			return nil, res
		}
		closure.Immutable = append(closure.Immutable, contract.GenesisImmutableObservation{Ref: object.ref, ReadbackObservation: 1})
	}
	closureBytes, err := contract.EncodeGenesisBootstrapClosureCore(closure)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	subject := contract.GenesisSubject{InitID: d.InitID, DomainID: d.DomainID, DescriptorDigest: p.manifest.DescriptorDigest, RequestCoreDigest: p.manifest.RequestCoreDigest, GenesisPlanDigest: p.manifest.GenesisPlanDigest, ManifestDigest: contract.Hash(p.manifestBytes), BootstrapClosureDigest: contract.Hash(closureBytes), HeadCoreDigest: p.manifest.HeadCoreDigest, ConditionalPlanDigest: p.manifest.ConditionalPlanDigest, HeadCoreLength: p.manifest.HeadCoreLength, RecoveryMode: d.RecoveryMode()}
	k2, err := contract.NewGenesisRequest(subject)
	if err != nil {
		return nil, refused(InvalidProof)
	}
	head.AuthorizationSignature, ok = sign(normal, k2, d.NormalSigning.SPKI)
	if !ok {
		return nil, signingFailure
	}
	head.Genesis = &format.GenesisProof{Subject: subject, Request: p.request, Plan: p.plan, Closure: closure, K3Challenge: challengeProof}
	headBytes, err := format.EncodeHead(head)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	request, err := contract.NewHeadCreateRequest(s.admission.store, headBytes)
	if err != nil || !active() {
		return nil, refused(AdmissionInvalid)
	}
	episode := &storeEpisode{}
	writeContext := context.WithValue(ctx, storeEpisodeKey{}, episode)
	possibleCommit := false
	hadTransport := false
	for send := 0; send < 3; send++ {
		if !episode.active(writeContext) || !active() {
			return nil, genesisWriteStopped(head.Core.Revision, possibleCommit, contract.ReasonLimit)
		}
		episode.writes++
		callCtx, cancel := episode.callContext(writeContext)
		written := s.storeCreateHead(callCtx, request)
		cancel()
		if written.Status == contract.WritePrecondition && !possibleCommit {
			return nil, failure(Contention, StalePrecondition)
		}
		if written.Status == contract.WriteRefused && !possibleCommit {
			return nil, refusedStoreWrite(written)
		}
		if written.Status == contract.WriteUnknown && !written.NotSent || written.Status == contract.WriteConflict {
			possibleCommit = true
		}
		if written.Status == contract.WriteUnknown && written.Reason == contract.ReasonTransport {
			hadTransport = true
			episode.startFailure(writeContext, s.admission.expires)
		}
		if !episode.beginStage(headObservationLimit()) {
			return nil, genesisWriteStopped(head.Core.Revision, possibleCommit, contract.ReasonLimit)
		}
		callCtx, cancel = episode.callContext(writeContext)
		selected, res := s.readCurrent(callCtx)
		cancel()
		res.RequestedRevision = head.Core.Revision
		if selected != nil && sameGenesisHead(selected.head, head) {
			return selected, res
		}
		if written.Status == contract.WriteUnknown && written.Reason == contract.ReasonTransport && res.Outcome == RootLossUnsupported && res.Reason == MissingSelectedObject && send < 2 {
			if waitForStoreRetry(writeContext, episode.deadline, storeRetryWait[send]) {
				continue
			}
			res.StoreReason = contract.ReasonLimit
		}
		if written.Status == contract.WriteUnknown && written.NotSent && !possibleCommit {
			if selected != nil {
				res.Outcome, res.Reason = Contention, DifferentSelection
			} else if res.Outcome == RootLossUnsupported && res.Reason == MissingSelectedObject {
				res = failure(EvidenceUnavailable, WriteUncertain)
				res.StoreReason = contract.ReasonTransport
			}
			res.RequestedRevision = head.Core.Revision
			return nil, res
		}
		if hadTransport && res.StoreReason == contract.ReasonNone && res.Outcome != IntegrityFailure && res.Outcome != AdmissionRefused {
			res.StoreReason = contract.ReasonTransport
		}
		res.Outcome = UnresolvedCommit
		res.CommitMayHaveOccurred = true
		if res.Reason == NoReason {
			res.Reason = WriteUncertain
		}
		return nil, res
	}
	return nil, genesisWriteStopped(head.Core.Revision, possibleCommit, contract.ReasonTransport)
}

func genesisWriteStopped(revision contract.ID, possibleCommit bool, reason contract.Reason) Result {
	if !possibleCommit {
		result := failure(EvidenceUnavailable, WriteUncertain)
		result.RequestedRevision = revision
		result.StoreReason = reason
		return result
	}
	result := failure(UnresolvedCommit, WriteUncertain)
	result.RequestedRevision = revision
	result.CommitMayHaveOccurred = true
	result.StoreReason = reason
	return result
}
func sameGenesisPreparation(s *StateSession, p *genesisPreparation) bool {
	if s == nil {
		return false
	}
	return selectedGenesisPreparation(s.head, p)
}

func selectedGenesisPreparation(head format.Head, p *genesisPreparation) bool {
	if p == nil || head.Genesis == nil || head.Core != p.plan.HeadCore {
		return false
	}
	g := head.Genesis
	plan, err := format.EncodeGenesisPlanCore(g.Plan)
	if err != nil {
		return false
	}
	request, err := contract.EncodeGenesisRequestCore(g.Request)
	return err == nil && bytes.Equal(plan, p.planBytes) && bytes.Equal(request, p.requestBytes) && g.Subject.ManifestDigest == contract.Hash(p.manifestBytes)
}
func sameGenesisHead(a, b format.Head) bool {
	if a.Genesis == nil || b.Genesis == nil || a.Core != b.Core || a.Genesis.Subject != b.Genesis.Subject {
		return false
	}
	x, err := contract.EncodeGenesisBootstrapClosureCore(a.Genesis.Closure)
	if err != nil {
		return false
	}
	y, err := contract.EncodeGenesisBootstrapClosureCore(b.Genesis.Closure)
	return err == nil && bytes.Equal(x, y)
}
func (s *StateSession) validGenesisSelection(d contract.GenesisDescriptorCore) bool {
	if s == nil || s.store == nil {
		return false
	}
	source, ok := s.store.(contract.StoreConfigurationSource)
	if !ok {
		return false
	}
	selected, ok := selectedGenesisClosure(s.head, &selectedImage{root: s.root, recipients: s.recipients}, source.StoreConfiguration())
	if !ok {
		return false
	}
	independent, err := contract.EncodeGenesisDescriptorCore(d)
	if err != nil {
		return false
	}
	selectedBytes, err := contract.EncodeGenesisDescriptorCore(selected)
	return err == nil && (s.admission.observation != nil || bytes.Equal(independent, s.admission.descriptor)) && bytes.Equal(selectedBytes, independent)
}
