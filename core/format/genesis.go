package format

import (
	"bytes"

	"enkv.sh/core/contract"
)

const GenesisPlanLimit = 12 << 10
const genesisPlanPrefix = "ENKV/CRYPTO/v2/genesis-plan-v2\x00"

func genesisPlanFieldsValid(p GenesisPlanCore) bool {
	if p.HeadCore.Root.Object != p.Root.Snapshot || p.HeadCore.Root.Domain != p.Root.Domain {
		return false
	}
	if p.DescriptorDigest.IsZero() || p.HeadCore.Form != GenesisHead || p.HeadCore.Epoch != 1 || p.Root.ValueEntryCount != 0 || p.Root.SecretCount != 0 || p.Root.RawBytes != 0 || p.Root.MembershipCount != 0 || p.Root.SecretOrdinaryWrapCount != 0 || p.Root.AccessRecordCount != 0 || p.Root.RequiredSupportRecordCount != 3 || len(p.Root.Names) != 0 || len(p.Root.RequiredSupport) != 2 || len(p.Root.CurrentAccess.Core.AccessPageRefs) != 0 || p.Root.CurrentAccess.Core.AccessGeneration != 1 || p.RecoveryMode > 1 || (p.RecoveryMode == 0) != p.K3ChallengeID.IsZero() || len(p.Probes) != 1+int(p.RecoveryMode) {
		return false
	}
	if !p.Root.ActiveGC.IsZero() || p.Root.GCPlans != contract.EmptyGCOwnersDescriptor() || !p.Root.Generated.ActiveOwner.IsZero() || !p.Root.Generated.ActivePhase.IsZero() || !p.Root.Generated.ActiveGraph.IsZero() ||
		p.Root.Generated.GeneratedCurrent != 0 || p.Root.Generated.Retiring != 0 || p.Root.Generated.Attempts != 0 ||
		p.Root.Generated.Duties != 0 || p.Root.Generated.Hazards != 0 || p.Root.Generated.Results != 0 ||
		p.Root.Generated.Materials != 0 || p.Root.Generated.PendingReleases != 0 || p.Root.Generated.Graphs.Count != 0 ||
		p.Root.Generated.LiveOwners.Count != 0 || p.Root.Generated.Slices.Count != 0 ||
		p.Root.Generated.SuccessWindow.Count != 1 || p.Root.Generated.FailureWindow.Count != 0 ||
		len(p.Root.Generated.Fragments) != 1 || p.Root.Generated.Fragments[0].FragmentIndex != 0 ||
		p.Root.Generated.Fragments[0].SupportPageIndex != 1 || p.Root.Generated.Fragments[0].RowSlot != 0 {
		return false
	}
	if (p.Root.CurrentAccess.Core.Recovery == nil) != (p.RecoveryMode == 0) || p.IdentityPlan.Operation.IsZero() || p.IdentityPlan.Snapshot != p.Root.Snapshot || p.IdentityPlan.Transition != p.Root.Transition || p.IdentityPlan.Revision != p.HeadCore.Revision || len(p.IdentityPlan.Rows) != 0 || len(p.IdentityPlan.Pages) != int(p.Root.ChildCount) {
		return false
	}
	recipientPages := int((p.Root.RecipientCount + RecipientSlots - 1) / RecipientSlots)
	if len(p.IdentityPlan.Pages) != recipientPages+3 {
		return false
	}
	for i, page := range p.IdentityPlan.Pages[:recipientPages] {
		if page.Kind != RecipientKind || page.Index != uint16(i) || i >= contract.MaxRecipientPages || p.Root.Recipients[i] == nil || p.Root.Recipients[i].Object != page.Object {
			return false
		}
	}
	indexPage := p.IdentityPlan.Pages[recipientPages+2]
	if indexPage.Kind != contract.AdministrativeIndexKind || indexPage.Index != 0 || indexPage.Object != p.Root.AdministrativeIndex.Object || p.Root.WarningBits != 0 {
		return false
	}
	supportPage := p.IdentityPlan.Pages[recipientPages]
	fragmentPage := p.IdentityPlan.Pages[recipientPages+1]
	if fragmentPage.Kind != contract.RequiredSupportKind || fragmentPage.Index != 1 || fragmentPage.Object != p.Root.RequiredSupport[1].Object {
		return false
	}
	if supportPage.Kind != contract.RequiredSupportKind || supportPage.Index != 0 || supportPage.Object != p.Root.RequiredSupport[0].Object {
		return false
	}
	for _, ref := range p.Root.ValueEntryPages {
		if ref != nil {
			return false
		}
	}
	if p.ConditionalPlan.Family != p.Root.CurrentAccess.Core.Provider || !p.ConditionalPlan.Condition.IsAbsent() || p.ConditionalPlan.Store != p.HeadCore.Store || p.ConditionalPlan.Coordinate != p.HeadCore.Coordinate || p.ConditionalPlan.NonBody != p.HeadCore.NonBody {
		return false
	}
	for i, probe := range p.Probes {
		if probe.SubjectKind != uint8(i+1) || probe.ProbeID.IsZero() {
			return false
		}
		if i == 0 && probe.SubjectID != p.Root.CurrentAccess.Core.AuthorityRecipientID {
			return false
		}
		if i == 1 && (probe.SubjectID != p.Root.CurrentAccess.Core.Recovery.RoleID || probe.BindingID != p.Root.CurrentAccess.Core.Recovery.KMS.BindingID) {
			return false
		}
	}
	return true
}
func EncodeGenesisPlanCore(p GenesisPlanCore) ([]byte, error) {
	if !genesisPlanFieldsValid(p) {
		return nil, ErrFormat
	}
	identity, err := contract.EncodeIdentityPlan(p.IdentityPlan)
	if err != nil {
		return nil, ErrFormat
	}
	root, err := EncodeRoot(p.Root)
	if err != nil {
		return nil, err
	}
	head, err := EncodeHeadCore(p.HeadCore)
	if err != nil {
		return nil, err
	}
	plan, err := EncodeConditionalPlan(p.ConditionalPlan)
	if err != nil {
		return nil, err
	}
	if p.HeadCore.Root.Digest != contract.Hash(root) || p.HeadCore.Root.Length != uint32(len(root)) || p.ConditionalPlan.HeadCore != contract.Hash(head) || p.ConditionalPlan.HeadCoreLength != uint32(len(head)) {
		return nil, ErrFormat
	}
	w := writer{b: []byte(genesisPlanPrefix)}
	w.u16(Version)
	w.u16(contract.GenesisProfile)
	w.id(p.DescriptorDigest)
	w.blob(identity)
	w.blob(root)
	w.blob(head)
	w.blob(plan)
	w.u8(p.RecoveryMode)
	if p.RecoveryMode == 1 {
		w.id(p.K3ChallengeID)
	}
	w.u8(uint8(len(p.Probes)))
	for _, probe := range p.Probes {
		w.b, err = contract.AppendInitProbePlanRow(w.b, probe)
		if err != nil {
			return nil, ErrFormat
		}
	}
	if len(w.b) > GenesisPlanLimit {
		return nil, ErrFormat
	}
	return w.result()
}
func DecodeGenesisPlanCore(b []byte) (GenesisPlanCore, error) {
	if len(b) > GenesisPlanLimit {
		return GenesisPlanCore{}, ErrFormat
	}
	r := reader{b: b}
	if !bytes.Equal(r.take(len(genesisPlanPrefix)), []byte(genesisPlanPrefix)) || r.u16() != Version || r.u16() != contract.GenesisProfile {
		return GenesisPlanCore{}, ErrFormat
	}
	p := GenesisPlanCore{DescriptorDigest: r.id()}
	// The complete plan bounds each frame; its decoder checks the frame's
	// own limit. Genesis includes the mandatory administrative index page.
	identity := r.blob(GenesisPlanLimit)
	root := r.blob(GenesisPlanLimit)
	head := r.blob(GenesisPlanLimit)
	plan := r.blob(GenesisPlanLimit)
	p.RecoveryMode = r.u8()
	if p.RecoveryMode == 1 {
		p.K3ChallengeID = r.id()
	} else if p.RecoveryMode != 0 {
		return GenesisPlanCore{}, ErrFormat
	}
	count := int(r.u8())
	if count < 1 || count > 2 || r.bad {
		return GenesisPlanCore{}, ErrFormat
	}
	var probes [2]contract.InitProbePlanRow
	for i := 0; i < count; i++ {
		v, n, err := contract.ParseInitProbePlanRow(r.b[r.off:])
		if err != nil {
			return GenesisPlanCore{}, ErrFormat
		}
		r.off += n
		probes[i] = v
	}
	if !r.end() {
		return GenesisPlanCore{}, ErrFormat
	}
	var err error
	p.IdentityPlan, err = contract.DecodeIdentityPlan(identity)
	if err != nil {
		return GenesisPlanCore{}, ErrFormat
	}
	p.Root, err = DecodeRoot(root)
	if err != nil {
		return GenesisPlanCore{}, err
	}
	p.HeadCore, err = DecodeHeadCore(head)
	if err != nil {
		return GenesisPlanCore{}, err
	}
	p.ConditionalPlan, err = DecodeConditionalPlan(plan)
	if err != nil {
		return GenesisPlanCore{}, err
	}
	p.Probes = append([]contract.InitProbePlanRow(nil), probes[:count]...)
	if !genesisPlanFieldsValid(p) || p.HeadCore.Root.Digest != contract.Hash(root) || p.HeadCore.Root.Length != uint32(len(root)) || p.ConditionalPlan.HeadCore != contract.Hash(head) || p.ConditionalPlan.HeadCoreLength != uint32(len(head)) {
		return GenesisPlanCore{}, ErrFormat
	}
	return p, nil
}
func genesisHeadRelations(p Head, core, plan, request, closure []byte) bool {
	g := p.Genesis
	s := g.Subject
	q := g.Request
	c := g.Closure
	return p.Core.Form == GenesisHead && p.AuthKind == GenesisAuth && s.HeadCoreDigest == contract.Hash(core) && s.HeadCoreLength == uint32(len(core)) && s.InitID == q.InitID && q.InitID == g.Plan.IdentityPlan.Operation && s.DomainID == q.DomainID && s.DomainID == p.Core.Domain && s.DescriptorDigest == q.DescriptorDigest && s.DescriptorDigest == g.Plan.DescriptorDigest && s.RequestCoreDigest == contract.Hash(request) && s.GenesisPlanDigest == contract.Hash(plan) && s.BootstrapClosureDigest == contract.Hash(closure) && s.ManifestDigest == c.ManifestDigest && s.DescriptorDigest == c.DescriptorDigest && s.RequestCoreDigest == c.RequestCoreDigest && s.GenesisPlanDigest == c.GenesisPlanDigest && genesisRequestIdentityMatches(q, g.Plan) && q.RecoveryMode == s.RecoveryMode && c.RecoveryMode == s.RecoveryMode && g.Plan.RecoveryMode == s.RecoveryMode && g.Plan.HeadCore == p.Core && s.ConditionalPlanDigest == g.Plan.ConditionalPlanDigest()
}
func (p GenesisPlanCore) ConditionalPlanDigest() ID {
	b, err := EncodeConditionalPlan(p.ConditionalPlan)
	if err != nil {
		return ID{}
	}
	return contract.Hash(b)
}
func EncodeHead(p Head) ([]byte, error) {
	core, err := EncodeHeadCore(p.Core)
	if err != nil || !signatureValid(p.K1) || !signatureValid(p.AuthorizationSignature) ||
		!grantBodyMatches(p.Core, p.GrantWraps) || len(p.GrantWraps) != 0 && !grantHeadAllowed(p) {
		return nil, ErrFormat
	}
	if p.AuthKind != GCAuth && p.GC != nil {
		return nil, ErrFormat
	}
	if p.AuthKind != OutputReserveAuth && p.OutputReserve != nil || p.AuthKind != OutputCloseAuth && p.OutputClose != nil {
		return nil, ErrFormat
	}
	w := start(byte(HeadKind))
	if p.AuthKind != GeneratorAuth && p.Generator != nil {
		return nil, ErrFormat
	}
	if p.AuthKind != AdministrativeAuth && p.EndWork != nil {
		return nil, ErrFormat
	}
	w.blob(core)
	w.blob(p.K1)
	w.blob(p.K3)
	w.u8(p.AuthKind)
	switch p.AuthKind {
	case LifecycleAuth:
		if p.Core.Form != SuccessorHead || p.Genesis != nil || p.Succession != nil || (len(p.K3) > 0 && !signatureValid(p.K3)) {
			return nil, ErrFormat
		}
		subject, err := contract.LifecycleBytes(p.Subject)
		if err != nil || p.Subject.HeadCore != contract.Hash(core) || p.Subject.HeadCoreLength != uint32(len(core)) {
			return nil, ErrFormat
		}
		condition, err := contract.MatchHeadCondition(p.Core.PreviousToken)
		if err != nil {
			return nil, ErrFormat
		}
		plan, err := EncodeConditionalPlan(ConditionalPlan{Family: p.Core.PreviousToken.Family, Store: p.Core.Store, Coordinate: p.Core.Coordinate, NonBody: p.Core.NonBody, Condition: condition, HeadCore: p.Subject.HeadCore, HeadCoreLength: p.Subject.HeadCoreLength})
		if err != nil || p.Subject.ConditionalPlan != contract.Hash(plan) {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(p.AuthorizationSignature)
	case SuccessionAuth:
		if !successionHeadRelations(p, core) {
			return nil, ErrFormat
		}
		subject, err := contract.EncodeSuccessionSubject(p.Succession.Subject)
		if err != nil {
			return nil, ErrFormat
		}
		authorizer, err := contract.EncodePublicSigningBinding(p.Succession.Authorizer)
		if err != nil {
			return nil, ErrFormat
		}
		evidence, err := contract.EncodeSuccessorEvidenceVector(p.Succession.Evidence)
		if err != nil {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(authorizer)
		w.blob(evidence)
		w.blob(p.AuthorizationSignature)
		w.u8(uint8(len(p.Succession.Acceptances)))
		for _, acceptance := range p.Succession.Acceptances {
			w.u8(acceptance.Role)
			w.id(acceptance.BindingDigest)
			w.u64(acceptance.Epoch)
			w.blob(acceptance.Signature)
		}
	case GeneratorAuth:
		if !generatorHeadRelations(p, core) {
			return nil, ErrFormat
		}
		subject, err := contract.EncodeGeneratorAuthoritySubject(*p.Generator)
		if err != nil {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(p.AuthorizationSignature)
	case AdministrativeAuth:
		if !endWorkHeadRelations(p, core) {
			return nil, ErrFormat
		}
		subject, err := contract.EncodeEndWorkSubject(*p.EndWork)
		if err != nil {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(p.AuthorizationSignature)
	case GCAuth:
		if !gcHeadRelations(p, core) {
			return nil, ErrFormat
		}
		subject, err := contract.EncodeGCSubject(*p.GC)
		if err != nil {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(p.AuthorizationSignature)
	case OutputReserveAuth, OutputCloseAuth:
		if !outputHeadRelations(p, core) {
			return nil, ErrFormat
		}
		var subject []byte
		if p.AuthKind == OutputReserveAuth {
			subject, err = contract.EncodeOutputReserveSubject(*p.OutputReserve)
		} else {
			subject, err = contract.EncodeOutputCloseSubject(*p.OutputClose)
		}
		if err != nil {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(p.AuthorizationSignature)
	case GenesisAuth:
		if p.Core.Form != GenesisHead || p.Genesis == nil || p.Succession != nil || p.Subject != (contract.LifecycleSubject{}) {
			return nil, ErrFormat
		}
		g := p.Genesis
		subject, err := contract.EncodeGenesisSubject(g.Subject)
		if err != nil {
			return nil, ErrFormat
		}
		request, err := contract.EncodeGenesisRequestCore(g.Request)
		if err != nil {
			return nil, ErrFormat
		}
		plan, err := EncodeGenesisPlanCore(g.Plan)
		if err != nil {
			return nil, ErrFormat
		}
		closure, err := contract.EncodeGenesisBootstrapClosureCore(g.Closure)
		if err != nil {
			return nil, ErrFormat
		}
		if !genesisHeadRelations(p, core, plan, request, closure) {
			return nil, ErrFormat
		}
		if g.Subject.RecoveryMode == 0 {
			if len(p.K3) != 0 || len(g.K3Challenge) != 0 {
				return nil, ErrFormat
			}
		} else if !signatureValid(p.K3) || !signatureValid(g.K3Challenge) {
			return nil, ErrFormat
		}
		w.blob(subject)
		w.blob(request)
		w.blob(plan)
		w.blob(closure)
		w.blob(g.K3Challenge)
		w.blob(p.AuthorizationSignature)
	default:
		return nil, ErrFormat
	}
	if len(w.b) > contract.MaxHeadLength-len(p.GrantWraps) {
		return nil, ErrFormat
	}
	w.b = append(w.b, p.GrantWraps...)
	return w.result()
}
func DecodeHead(b []byte) (Head, error) {
	r := begin(b, byte(HeadKind), contract.MaxHeadLength)
	coreBytes := r.blob(contract.GrantHeadCoreMaxLength)
	k1 := r.blob(contract.MaxSignature)
	k3 := r.blob(contract.MaxSignature)
	kind := r.u8()
	if r.bad {
		return Head{}, ErrFormat
	}
	p := Head{AuthKind: kind}
	var subject, request, plan, closure, challenge, authorizer, evidence, authorizationSignature []byte
	switch kind {
	case LifecycleAuth:
		subject = r.blob(contract.LifecycleSubjectLength)
		authorizationSignature = r.blob(contract.MaxSignature)
	case SuccessionAuth:
		subject = r.blob(uint32(contract.SuccessionSubjectWireLength))
		authorizer = r.blob(contract.PublicSigningBindingMaxLength)
		evidence = r.blob(contract.SuccessorEvidenceVectorMaxLength)
		authorizationSignature = r.blob(contract.MaxSignature)
		count := r.u8()
		if count > 2 {
			return Head{}, ErrFormat
		}
		p.Succession = &SuccessionProof{}
		if count != 0 {
			p.Succession.Acceptances = make([]SelectionAcceptanceProof, count)
		}
		for i := range p.Succession.Acceptances {
			row := &p.Succession.Acceptances[i]
			row.Role = r.u8()
			row.BindingDigest = r.id()
			row.Epoch = r.u64()
			row.Signature = bytes.Clone(r.blob(contract.MaxSignature))
		}
	case GeneratorAuth:
		subject = r.blob(contract.GeneratorAuthoritySubjectLength)
		authorizationSignature = r.blob(contract.MaxSignature)
	case AdministrativeAuth:
		subject = r.blob(contract.EndWorkSubjectMaxLength)
		authorizationSignature = r.blob(contract.MaxSignature)
	case GCAuth:
		subject = r.blob(contract.GCSubjectMaxLength)
		authorizationSignature = r.blob(contract.MaxSignature)
	case OutputReserveAuth:
		subject = r.blob(contract.OutputReserveSubjectMaxLength)
		authorizationSignature = r.blob(contract.MaxSignature)
	case OutputCloseAuth:
		subject = r.blob(contract.OutputCloseSubjectMaxLength)
		authorizationSignature = r.blob(contract.MaxSignature)
	case GenesisAuth:
		subject = r.blob(contract.GenesisSubjectLength)
		request = r.blob(contract.GenesisRequestCoreLength)
		plan = r.blob(GenesisPlanLimit)
		closure = r.blob(contract.GenesisBootstrapLimit)
		challenge = r.blob(contract.MaxSignature)
		authorizationSignature = r.blob(contract.MaxSignature)
	default:
		return Head{}, ErrFormat
	}
	var grants []byte
	if kind == LifecycleAuth || kind == GeneratorAuth {
		grants = r.take(r.remaining())
	}
	if !r.end() || !signatureValid(k1) || !signatureValid(authorizationSignature) {
		return Head{}, ErrFormat
	}
	var err error
	p.Core, err = DecodeHeadCore(coreBytes)
	if err != nil {
		return Head{}, err
	}
	if !grantBodyMatches(p.Core, grants) {
		return Head{}, ErrFormat
	}
	if len(grants) != 0 {
		p.GrantWraps = bytes.Clone(grants)
	}
	p.K1 = bytes.Clone(k1)
	p.K3 = bytes.Clone(k3)
	p.AuthorizationSignature = bytes.Clone(authorizationSignature)
	if kind == GCAuth {
		q, err := contract.DecodeGCSubject(subject)
		if err != nil {
			return Head{}, ErrFormat
		}
		p.GC = &q
		if !gcHeadRelations(p, coreBytes) {
			return Head{}, ErrFormat
		}
		return p, nil
	}
	if kind == OutputReserveAuth || kind == OutputCloseAuth {
		if kind == OutputReserveAuth {
			v, err := contract.DecodeOutputReserveSubject(subject)
			if err != nil {
				return Head{}, ErrFormat
			}
			p.OutputReserve = &v
		} else {
			v, err := contract.DecodeOutputCloseSubject(subject)
			if err != nil {
				return Head{}, ErrFormat
			}
			p.OutputClose = &v
		}
		if !outputHeadRelations(p, coreBytes) {
			return Head{}, ErrFormat
		}
		return p, nil
	}
	if kind == AdministrativeAuth {
		s, err := contract.DecodeEndWorkSubject(subject)
		if err != nil {
			return Head{}, ErrFormat
		}
		p.EndWork = &s
		if !endWorkHeadRelations(p, coreBytes) {
			return Head{}, ErrFormat
		}
		return p, nil
	}
	if kind == GeneratorAuth {
		s, err := contract.DecodeGeneratorAuthoritySubject(subject)
		if err != nil {
			return Head{}, ErrFormat
		}
		p.Generator = &s
		if !generatorHeadRelations(p, coreBytes) || len(grants) != 0 && !grantHeadAllowed(p) {
			return Head{}, ErrFormat
		}
		return p, nil
	}
	if kind == SuccessionAuth {
		s := p.Succession
		s.Subject, err = contract.DecodeSuccessionSubject(subject)
		if err != nil {
			return Head{}, ErrFormat
		}
		s.Authorizer, err = contract.DecodePublicSigningBinding(authorizer)
		if err != nil {
			return Head{}, ErrFormat
		}
		s.Evidence, err = contract.DecodeSuccessorEvidenceVector(evidence)
		if err != nil || !successionHeadRelations(p, coreBytes) {
			return Head{}, ErrFormat
		}
		return p, nil
	}
	if kind == LifecycleAuth {
		if p.Core.Form != SuccessorHead || (len(k3) > 0 && !signatureValid(k3)) {
			return Head{}, ErrFormat
		}
		p.Subject, err = contract.DecodeLifecycleSubject(subject)
		if err != nil {
			return Head{}, ErrFormat
		}
		if p.Subject.HeadCore != contract.Hash(coreBytes) || p.Subject.HeadCoreLength != uint32(len(coreBytes)) ||
			len(grants) != 0 && !grantHeadAllowed(p) {
			return Head{}, ErrFormat
		}
		condition, err := contract.MatchHeadCondition(p.Core.PreviousToken)
		if err != nil {
			return Head{}, ErrFormat
		}
		plan, err := EncodeConditionalPlan(ConditionalPlan{Family: p.Core.PreviousToken.Family, Store: p.Core.Store, Coordinate: p.Core.Coordinate, NonBody: p.Core.NonBody, Condition: condition, HeadCore: p.Subject.HeadCore, HeadCoreLength: p.Subject.HeadCoreLength})
		if err != nil || p.Subject.ConditionalPlan != contract.Hash(plan) {
			return Head{}, ErrFormat
		}
		return p, nil
	}
	g := &GenesisProof{}
	p.Genesis = g
	g.Subject, err = contract.DecodeGenesisSubject(subject)
	if err != nil {
		return Head{}, ErrFormat
	}
	g.Request, err = contract.DecodeGenesisRequestCore(request)
	if err != nil {
		return Head{}, ErrFormat
	}
	g.Plan, err = DecodeGenesisPlanCore(plan)
	if err != nil {
		return Head{}, ErrFormat
	}
	g.Closure, err = contract.DecodeGenesisBootstrapClosureCore(closure)
	if err != nil {
		return Head{}, ErrFormat
	}
	if !genesisHeadRelations(p, coreBytes, plan, request, closure) {
		return Head{}, ErrFormat
	}
	if g.Subject.RecoveryMode == 0 {
		if len(k3) != 0 || len(challenge) != 0 {
			return Head{}, ErrFormat
		}
	} else if !signatureValid(k3) || !signatureValid(challenge) {
		return Head{}, ErrFormat
	}
	g.K3Challenge = bytes.Clone(challenge)
	return p, nil
}

func genesisRequestIdentityMatches(q contract.GenesisRequestCore, p GenesisPlanCore) bool {
	body, err := contract.EncodeGenesisIdentityPlanCore(contract.GenesisIdentityPlanCore{DomainID: p.Root.Domain,
		DescriptorDigest: p.DescriptorDigest, IdentityPlan: p.IdentityPlan, RecoveryMode: p.RecoveryMode,
		K3ChallengeID: p.K3ChallengeID, Probes: p.Probes})
	return err == nil && q.GenesisIdentityPlanDigest == contract.Hash(body)
}
