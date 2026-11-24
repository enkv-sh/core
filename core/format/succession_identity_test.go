package format

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"enkv.sh/core/contract"
)

func successionRotatedSigningKey(t testing.TB, scalar byte) []byte {
	t.Helper()
	var literal string
	switch scalar {
	case 3:
		literal = "3059301306072a8648ce3d020106082a8648ce3d030107034200045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"
	case 4:
		literal = "3059301306072a8648ce3d020106082a8648ce3d03010703420004e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6"
	default:
		t.Fatal("unknown public successor key")
	}
	spki, err := hex.DecodeString(literal)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func successionRotatedKMSKey(t testing.TB, offset int64) []byte {
	t.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(offset))
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func successionIdentityFixture(t testing.TB) SuccessionIdentityPlan {
	t.Helper()
	root := rootFixture(t)
	root.ValueEntryPages, root.Names = [contract.MaxValueEntryPages]*Ref{}, nil
	root.ValueEntryCount, root.RawBytes, root.MembershipCount, root.ChildCount = 0, 0, 0, 3
	root.ChildEncodedBytes = uint64(root.Recipients[4].Length) + uint64(root.AdministrativeIndex.Length) + uint64(root.RequiredSupport[0].Length)
	b := contract.ControlCore{CurrentControl: root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *recipientFixture(t).Slots[2].CurrentBinding}
	a := b
	a.AccessGeneration++
	a.NormalSigning.BindingID = fid(85)
	a.NormalSigning.Binding.Epoch++
	a.NormalSigning.SPKI = successionRotatedSigningKey(t, 3)
	a.NormalSigning.Fingerprint = contract.Hash(a.NormalSigning.SPKI)
	a.NormalSigning.Binding.PublicKey = a.NormalSigning.Fingerprint
	a.NormalSigning.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000005"
	q := contract.SuccessionRequestCore{SuccessionRequestFields: contract.SuccessionRequestFields{Schema: contract.CanonicalSchema, OperationKind: 1, ApprovalRole: 1, ChangeMask: 1,
		DomainID: b.DomainID, StoreID: b.StoreID, CoordinateID: b.CoordinateID, NonBodyID: b.NonBodyID, TrustInterpretationID: b.TrustInterpretationID, CompatibilityID: b.CompatibilityID, CryptoSupportID: b.CryptoSupportID,
		AdmissionID: fid(92), OperationID: fid(93), PredecessorHeadRevisionID: fid(94), PredecessorFullHEADDigest: fid(95), BeforeAccessRoot: root.CurrentAccess.AccessRoot},
		Token: contract.Token{Family: contract.AWS, Value: `"etag"`}, BeforeControl: b, ProposedAfterControl: a,
		IdentityPlan:    contract.IdentityPlan{Operation: fid(93), Transition: fid(88), Snapshot: fid(87), Revision: fid(89)},
		ReplacementPlan: contract.SuccessionReplacementPlanCore{SuccessionReplacementPlanFields: contract.SuccessionReplacementPlanFields{Schema: contract.CanonicalSchema, DomainID: b.DomainID, OperationKind: 1, ChangeMask: 1}, Rows: []contract.SuccessionReplacementRow{{TargetRole: 1, BeforeSigning: b.NormalSigning, AfterSigning: a.NormalSigning}}}}
	return successionIdentityForRequest(t, q, root, fid(98))
}

func successionIdentityForRequest(t testing.TB, q contract.SuccessionRequestCore, root Root, receipt ID) SuccessionIdentityPlan {
	t.Helper()
	a, b := q.ProposedAfterControl, q.BeforeControl
	root.Snapshot, root.Transition = q.IdentityPlan.Snapshot, q.IdentityPlan.Transition
	root.CurrentAccess.Core.CurrentControl = a.CurrentControl
	var err error
	root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatal("access root:", err)
	}
	raw, err := EncodeRoot(root)
	if err != nil {
		t.Fatal("snapshot:", err)
	}
	head := HeadCore{Form: 1, Domain: q.DomainID, Revision: q.IdentityPlan.Revision, PreviousRevision: q.PredecessorHeadRevisionID, PreviousDigest: q.PredecessorFullHEADDigest, PreviousToken: q.Token,
		Root: Ref{Kind: RootKind, Format: Version, Domain: q.DomainID, Object: root.Snapshot, Length: uint32(len(raw))}, Store: q.StoreID, Trust: a.NormalSigning.Binding.Trust, Coordinate: q.CoordinateID, NonBody: q.NonBodyID, Interpretation: a.NormalSigning.Binding.Interpretation, Epoch: a.NormalSigning.Binding.Epoch}
	headerLength := uint32(len(successionHeadCoreBytes(head)))
	request, err := contract.SuccessionRequestDescriptor(q)
	if err != nil {
		t.Fatal("request:", err)
	}
	access := contract.AccessReplacementPlanCore{DomainID: q.DomainID, RequestCoreDigest: request.Digest, BeforeAccessRoot: q.BeforeAccessRoot}
	var evidence []contract.SuccessorEvidencePlanRow
	for i, row := range q.ReplacementPlan.Rows {
		proof := contract.SuccessorEvidencePlanRow{TargetRole: row.TargetRole}
		if row.TargetRole == 1 || row.TargetRole == 3 {
			digest, err := contract.SigningBindingDigest(row.AfterSigning)
			if err != nil {
				t.Fatal(err)
			}
			proof.EvidenceKind, proof.Trust = 1, contract.SuccessorSignerFields{ProbeAttemptID: fid(96 + byte(i)), SigningBindingDigest: digest}
		} else {
			kind, subject := uint8(1), b.AuthorityRecipientID
			if row.TargetRole == 4 {
				kind, subject = 2, b.Recovery.RoleID
			}
			beforeDigest, err := contract.PublicBindingDigest(row.BeforeKMS)
			if err != nil {
				t.Fatal(err)
			}
			afterDigest, err := contract.PublicBindingDigest(row.AfterKMS)
			if err != nil {
				t.Fatal(err)
			}
			access.BindingTable = []contract.BindingTableRow{{SubjectKind: kind, SubjectID: subject, Binding: row.AfterKMS}}
			access.Replacements = []contract.ReplacementRow{{SubjectKind: kind, SubjectID: subject, BeforeBindingDigest: beforeDigest}}
			proof.EvidenceKind = 2
			proof.KEK = contract.QualifiedSuccessorRow{ProbeID: fid(96 + byte(i)), QualifiedBindingFields: contract.QualifiedBindingFields{SubjectKind: kind, SubjectID: subject, BindingID: row.AfterKMS.BindingID, PublicBindingDigest: afterDigest, Provider: q.Token.Family, Qualified: 1}}
		}
		evidence = append(evidence, proof)
	}
	accessDescriptor, err := contract.AccessReplacementPlanDescriptor(access)
	if err != nil {
		t.Fatal("access plan:", err)
	}
	projection, err := contract.NewAccessProjection(contract.AccessProjectionMetadata{DomainID: q.DomainID, RequestCoreDigest: request.Digest, BeforeAccessRoot: q.BeforeAccessRoot}, accessDescriptor, 0)
	if err != nil {
		t.Fatal("projection:", err)
	}
	coverage, after, unchanged, err := projection.Descriptors()
	if err != nil {
		t.Fatal("access descriptors:", err)
	}
	identity, err := contract.EncodeIdentityPlan(q.IdentityPlan)
	if err != nil {
		t.Fatal(err)
	}
	before, err := contract.EncodeControlCore(b)
	if err != nil {
		t.Fatal(err)
	}
	afterControl, err := contract.EncodeControlCore(a)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := contract.SuccessionReplacementPlanDescriptor(q.ReplacementPlan)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDigest, err := contract.EvidencePlanDigest(evidence)
	if err != nil {
		t.Fatal(err)
	}
	subject := contract.SuccessionSubject{Schema: contract.CanonicalSchema, OperationKind: q.OperationKind, ApprovalRole: q.ApprovalRole, MaterialSourceRole: q.MaterialSourceRole, OperationID: q.OperationID, AdmissionID: q.AdmissionID, RequestCoreDigest: request.Digest, IdentityPlanDigest: contract.Hash(identity), BeforeControlDigest: contract.Hash(before), AfterControlDigest: contract.Hash(afterControl), BeforeAccessRoot: q.BeforeAccessRoot, AfterAccessRoot: root.CurrentAccess.AccessRoot, PreservedStateDigest: fid(97), CoverageDigest: coverage.Digest, ReplacementPlanDigest: replacement.Digest, SuccessorEvidenceDigest: evidenceDigest, ReceiptDeltaDigest: receipt, IdentityPlanLength: uint32(len(identity)), HeadCoreLength: headerLength, ReplacementCount: uint16(len(evidence)), SuccessorEvidenceCount: uint8(len(evidence)), ChangeMask: q.ChangeMask}
	if q.OperationKind != 1 {
		subject.ReceiptDeltaCount = 1
	}
	authorizer := b.NormalSigning
	if q.ApprovalRole == 2 {
		authorizer = b.Recovery.Signing
	}
	return SuccessionIdentityPlan{Request: q, Snapshot: root, Head: HeadPlan(head), Conditional: ConditionalRequestPlan(ConditionalPlan{Family: q.Token.Family, Store: q.StoreID, Coordinate: q.CoordinateID, NonBody: q.NonBodyID, Condition: conditionFixture(q.Token), HeadCoreLength: headerLength}), Authorization: contract.SuccessionAuthorizationPlan{Subject: contract.SuccessionAuthorizationSubject(subject), Authorizer: authorizer}, Evidence: evidence, AccessPlan: access, Coverage: coverage, AfterAccess: after, Unchanged: unchanged}
}

// full_only: false
func TestSuccessionIdentityDerivesTypedCandidate(t *testing.T) {
	p := successionIdentityFixture(t)
	got, err := DeriveSuccessionIdentity(p)
	if err != nil || got.RequestIdentityDigest.IsZero() {
		t.Fatal("valid typed succession identity refused", err)
	}
	// Independent Python framing, SHA-256 and manual public-key DER derive
	// these fixed schema-11 fields. The empty output uses schema 5 and the v5
	// configuration/slice commitment domains. The root adds the 76-byte GC relation;
	// the succession request/subject field layouts and purpose labels stay fixed.
	// The recorded derivation and its inherited-leaf limits are described in
	// tests/shared/testdata/README.md.
	// Entry=L(entry)||B(request); Binding=L(binding)||B(identity)||B(head)||B(condition).
	// Graph=L(graph)||DV(entry,1)||B(snapshot)||DV(binding,1)||B(authorization)||
	// B(evidence-plan)||coverageDV||unchangedDV||outputDV. The identity appends
	// request, entry, binding and graph hashes, then the assigned revision.
	for _, row := range []struct {
		name   string
		got    contract.DescriptorVector
		length uint64
		digest string
	}{
		{"entry", got.PhaseEntry, 4667, "9c1a92c396898dc4bede661d026a0aec0c386e6c71f37fad9e547cbf2b107ac0"},
		{"binding", got.TransitionBinding, 804, "7829fb41200d6d063326000fb6d36ab1bde362f44d65af78c314315f8b5b720b"},
		{"graph", got.Graph, 3399, "b6e4debc37445eb88457c7833eb2c226137a4a80fb9cb14f41daca83a405fe33"},
	} {
		if row.got.Digest != successionLiteralID(t, row.digest) || row.got.Length != row.length || row.got.Count != 1 {
			t.Fatalf("%s differs from fixed descriptor: %+v", row.name, row.got)
		}
	}
	if got.RequestIdentityDigest != successionLiteralID(t, "bee9435ac0ee97b26821ef352c7b8db82dc9f8e2ed4ba7edac4ffe3910c0589b") {
		t.Fatal("request identity differs from fixed literal")
	}
}

func successionLiteralID(t testing.TB, literal string) ID {
	t.Helper()
	b, err := hex.DecodeString(literal)
	if err != nil || len(b) != 32 {
		t.Fatal("invalid expected digest", err)
	}
	return ID(b)
}

// full_only: false
func TestSuccessionIdentityRefusesInconsistentTypedParts(t *testing.T) {
	for name, change := range map[string]func(*SuccessionIdentityPlan){
		"request domain":          func(p *SuccessionIdentityPlan) { p.Request.DomainID = fid(200) },
		"request material source": func(p *SuccessionIdentityPlan) { p.Request.MaterialSourceRole = contract.SuccessionMaterialAuthority },
		"authorization material source": func(p *SuccessionIdentityPlan) {
			p.Authorization.Subject.MaterialSourceRole = contract.SuccessionMaterialAuthority
		},
		"authorization final identity hole": func(p *SuccessionIdentityPlan) { p.Authorization.Subject.RequestIdentityDigest = fid(201) },
		"request fresh admission":           func(p *SuccessionIdentityPlan) { p.Request.AdmissionID = fid(200) },
		"request operation":                 func(p *SuccessionIdentityPlan) { p.Request.OperationID = fid(200) },
		"snapshot identity":                 func(p *SuccessionIdentityPlan) { p.Snapshot.Snapshot = fid(200) },
		"snapshot transition":               func(p *SuccessionIdentityPlan) { p.Snapshot.Transition = fid(200) },
		"snapshot control":                  func(p *SuccessionIdentityPlan) { p.Snapshot.CurrentAccess.Core.AccessGeneration++ },
		"head root length":                  func(p *SuccessionIdentityPlan) { p.Head.Root.Length++ },
		"head root object":                  func(p *SuccessionIdentityPlan) { p.Head.Root.Object = fid(200) },
		"head root hole":                    func(p *SuccessionIdentityPlan) { p.Head.Root.Digest = fid(200) },
		"head revision":                     func(p *SuccessionIdentityPlan) { p.Head.Revision = fid(200) },
		"head previous revision":            func(p *SuccessionIdentityPlan) { p.Head.PreviousRevision = fid(200) },
		"head previous digest":              func(p *SuccessionIdentityPlan) { p.Head.PreviousDigest = fid(200) },
		"head token":                        func(p *SuccessionIdentityPlan) { p.Head.PreviousToken.Value = `"other"` },
		"head store":                        func(p *SuccessionIdentityPlan) { p.Head.Store = fid(200) },
		"head trust":                        func(p *SuccessionIdentityPlan) { p.Head.Trust = fid(200) },
		"head epoch":                        func(p *SuccessionIdentityPlan) { p.Head.Epoch++ },
		"conditional store":                 func(p *SuccessionIdentityPlan) { p.Conditional.Store = fid(200) },
		"conditional length":                func(p *SuccessionIdentityPlan) { p.Conditional.HeadCoreLength++ },
		"conditional token": func(p *SuccessionIdentityPlan) {
			p.Conditional.Condition = conditionFixture(contract.Token{Family: contract.AWS, Value: `"other"`})
		},
		"conditional hole": func(p *SuccessionIdentityPlan) { p.Conditional.HeadCore = fid(200) },
		"authorizer substitution": func(p *SuccessionIdentityPlan) {
			p.Authorization.Authorizer = p.Request.ProposedAfterControl.NormalSigning
		},
		"authorizer epoch":              func(p *SuccessionIdentityPlan) { p.Authorization.Authorizer.Binding.Epoch++ },
		"authorization fresh admission": func(p *SuccessionIdentityPlan) { p.Authorization.Subject.AdmissionID = fid(200) },
		"authorization request":         func(p *SuccessionIdentityPlan) { p.Authorization.Subject.RequestCoreDigest = fid(200) },
		"authorization identity":        func(p *SuccessionIdentityPlan) { p.Authorization.Subject.IdentityPlanDigest = fid(200) },
		"authorization identity length": func(p *SuccessionIdentityPlan) { p.Authorization.Subject.IdentityPlanLength += 35 },
		"authorization before control":  func(p *SuccessionIdentityPlan) { p.Authorization.Subject.BeforeControlDigest = fid(200) },
		"authorization after control":   func(p *SuccessionIdentityPlan) { p.Authorization.Subject.AfterControlDigest = fid(200) },
		"authorization before access":   func(p *SuccessionIdentityPlan) { p.Authorization.Subject.BeforeAccessRoot = fid(200) },
		"authorization after access":    func(p *SuccessionIdentityPlan) { p.Authorization.Subject.AfterAccessRoot = fid(200) },
		"authorization replacement":     func(p *SuccessionIdentityPlan) { p.Authorization.Subject.ReplacementPlanDigest = fid(200) },
		"authorization evidence":        func(p *SuccessionIdentityPlan) { p.Authorization.Subject.SuccessorEvidenceDigest = fid(200) },
		"authorization head hole":       func(p *SuccessionIdentityPlan) { p.Authorization.Subject.HeadCoreDigest = fid(200) },
		"authorization condition hole":  func(p *SuccessionIdentityPlan) { p.Authorization.Subject.ConditionalPlanDigest = fid(200) },
		"access plan request":           func(p *SuccessionIdentityPlan) { p.AccessPlan.RequestCoreDigest = fid(200) },
		"access plan domain":            func(p *SuccessionIdentityPlan) { p.AccessPlan.DomainID = fid(200) },
		"access plan predecessor":       func(p *SuccessionIdentityPlan) { p.AccessPlan.BeforeAccessRoot = fid(200) },
		"empty coverage length":         func(p *SuccessionIdentityPlan) { p.Coverage.Length++ },
		"empty coverage digest": func(p *SuccessionIdentityPlan) {
			p.Coverage.Digest = fid(200)
			p.Authorization.Subject.CoverageDigest = p.Coverage.Digest
		},
		"empty unchanged digest":       func(p *SuccessionIdentityPlan) { p.Unchanged.Digest = fid(200) },
		"empty output digest":          func(p *SuccessionIdentityPlan) { p.AfterAccess.Digest = fid(200) },
		"output count":                 func(p *SuccessionIdentityPlan) { p.AfterAccess.Count = 1 },
		"unchanged count":              func(p *SuccessionIdentityPlan) { p.Unchanged.Count = 1 },
		"signer only private material": func(p *SuccessionIdentityPlan) { p.Coverage.Count = 1 },
		"missing evidence":             func(p *SuccessionIdentityPlan) { p.Evidence = nil },
		"unrequested page": func(p *SuccessionIdentityPlan) {
			p.Request.IdentityPlan.Pages = []contract.IdentityPage{{Kind: ValueEntryPageKind, Index: 0, Object: fid(200)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := successionIdentityFixture(t)
			change(&p)
			if _, err := DeriveSuccessionIdentity(p); err == nil {
				t.Fatal("inconsistent plan accepted")
			}
		})
	}
	p := successionIdentityFixture(t)
	p.Evidence[0].Trust.SigningBindingDigest = fid(200)
	digest, err := contract.EvidencePlanDigest(p.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Subject.SuccessorEvidenceDigest = digest
	if _, err := DeriveSuccessionIdentity(p); err == nil {
		t.Fatal("self-consistent evidence digest admitted a different successor")
	}
}

// full_only: false
func TestSuccessionIdentityBindsPreservedAndReceiptMeaning(t *testing.T) {
	p := successionIdentityFixture(t)
	first, err := DeriveSuccessionIdentity(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SuccessionIdentityPlan){
		func(p *SuccessionIdentityPlan) { p.Authorization.Subject.PreservedStateDigest = fid(200) },
		func(p *SuccessionIdentityPlan) { p.Authorization.Subject.ReceiptDeltaDigest = fid(200) },
		func(p *SuccessionIdentityPlan) {
			p.Evidence[0].Trust.ProbeAttemptID = fid(200)
			digest, err := contract.EvidencePlanDigest(p.Evidence)
			if err != nil {
				t.Fatal(err)
			}
			p.Authorization.Subject.SuccessorEvidenceDigest = digest
		},
	} {
		p := successionIdentityFixture(t)
		change(&p)
		next, err := DeriveSuccessionIdentity(p)
		if err != nil || next.RequestIdentityDigest == first.RequestIdentityDigest || next.Graph == first.Graph || next.PhaseEntry != first.PhaseEntry || next.TransitionBinding != first.TransitionBinding {
			t.Fatal("prepared meaning did not enter only the graph and identity", err)
		}
	}
}

func successionRecoveryIdentityFixture(t testing.TB, operation, mask, approval uint8) SuccessionIdentityPlan {
	t.Helper()
	p := successionIdentityFixture(t)
	q := p.Request
	b := q.BeforeControl
	recovery := b.NormalSigning
	recovery.Role, recovery.BindingID, recovery.Binding.Trust = 2, fid(101), fid(102)
	// Public P-256 base point doubled, encoded as DER SPKI.
	spki, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
	if err != nil {
		t.Fatal(err)
	}
	recovery.SPKI, recovery.Fingerprint, recovery.Binding.PublicKey = spki, contract.Hash(spki), contract.Hash(spki)
	recovery.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000003"
	kms := b.AuthorityKMSBinding
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	n.Add(n, big.NewInt(12347))
	spki, err = x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	kms.BindingID, kms.SPKI, kms.Fingerprint = fid(103), spki, contract.Hash(spki)
	kms.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000004"
	b.Recovery = &contract.RecoveryBindings{RoleID: fid(104), Signing: recovery, KMS: kms}
	a := b
	a.AccessGeneration++
	next := *b.Recovery
	a.Recovery = &next
	if mask&1 != 0 {
		a.NormalSigning.BindingID = fid(85)
		a.NormalSigning.Binding.Epoch++
		a.NormalSigning.SPKI = successionRotatedSigningKey(t, 3)
		a.NormalSigning.Fingerprint = contract.Hash(a.NormalSigning.SPKI)
		a.NormalSigning.Binding.PublicKey = a.NormalSigning.Fingerprint
		a.NormalSigning.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000005"
	}
	if mask&2 != 0 {
		a.AuthorityKMSBinding.BindingID = fid(110)
		a.AuthorityKMSBinding.BindingSerial++
		a.AuthorityKMSBinding.SPKI = successionRotatedKMSKey(t, 12351)
		a.AuthorityKMSBinding.Fingerprint = contract.Hash(a.AuthorityKMSBinding.SPKI)
		a.AuthorityKMSBinding.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000006"
	}
	if mask&4 != 0 {
		a.Recovery.Signing.BindingID = fid(105)
		a.Recovery.Signing.Binding.Epoch++
		a.Recovery.Signing.SPKI = successionRotatedSigningKey(t, 4)
		a.Recovery.Signing.Fingerprint = contract.Hash(a.Recovery.Signing.SPKI)
		a.Recovery.Signing.Binding.PublicKey = a.Recovery.Signing.Fingerprint
		a.Recovery.Signing.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000007"
	}
	if mask&8 != 0 {
		a.Recovery.KMS.BindingID = fid(107)
		a.Recovery.KMS.BindingSerial++
		a.Recovery.KMS.SPKI = successionRotatedKMSKey(t, 12353)
		a.Recovery.KMS.Fingerprint = contract.Hash(a.Recovery.KMS.SPKI)
		a.Recovery.KMS.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000008"
	}
	q.BeforeControl, q.ProposedAfterControl = b, a
	q.OperationKind, q.ChangeMask, q.ApprovalRole = operation, mask, approval
	if mask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 {
		q.MaterialSourceRole = contract.SuccessionMaterialAuthority
	}
	beforeAccess := p.Snapshot.CurrentAccess.Core
	beforeAccess.CurrentControl = b.CurrentControl
	q.BeforeAccessRoot, err = contract.AccessRoot(beforeAccess)
	if err != nil {
		t.Fatal(err)
	}
	q.ReplacementPlan = contract.SuccessionReplacementPlanCore{SuccessionReplacementPlanFields: contract.SuccessionReplacementPlanFields{Schema: contract.CanonicalSchema, DomainID: q.DomainID, OperationKind: operation, ChangeMask: mask}}
	if mask&1 != 0 {
		q.ReplacementPlan.Rows = append(q.ReplacementPlan.Rows, contract.SuccessionReplacementRow{TargetRole: 1, BeforeSigning: b.NormalSigning, AfterSigning: a.NormalSigning})
	}
	if mask&2 != 0 {
		q.ReplacementPlan.Rows = append(q.ReplacementPlan.Rows, contract.SuccessionReplacementRow{TargetRole: 2, BeforeKMS: b.AuthorityKMSBinding, AfterKMS: a.AuthorityKMSBinding})
	}
	if mask&4 != 0 {
		q.ReplacementPlan.Rows = append(q.ReplacementPlan.Rows, contract.SuccessionReplacementRow{TargetRole: 3, BeforeSigning: b.Recovery.Signing, AfterSigning: a.Recovery.Signing})
	}
	if mask&8 != 0 {
		q.ReplacementPlan.Rows = append(q.ReplacementPlan.Rows, contract.SuccessionReplacementRow{TargetRole: 4, BeforeKMS: b.Recovery.KMS, AfterKMS: a.Recovery.KMS})
	}
	if operation == 1 {
		root := p.Snapshot
		if mask&2 != 0 {
			page := recipientFixture(t)
			page.Object, page.Slots[2].CurrentBinding = fid(111), &a.AuthorityKMSBinding
			body, err := EncodeRecipientPage(page)
			if err != nil {
				t.Fatal(err)
			}
			ref, err := Reference(RecipientKind, page.Domain, page.Object, page.Index, body)
			if err != nil {
				t.Fatal(err)
			}
			root.Recipients[4], root.ChildEncodedBytes = &ref, uint64(len(body))+uint64(root.AdministrativeIndex.Length)+uint64(root.RequiredSupport[0].Length)
			root.CurrentAccess.Core.RecipientRefsDescriptor, err = contract.RecipientRefsDescriptor(contract.RecipientRefsProjection{DomainID: q.DomainID, Refs: []Ref{ref}})
			if err != nil {
				t.Fatal(err)
			}
			q.IdentityPlan.Pages = []contract.IdentityPage{{Kind: RecipientKind, Index: 4, Object: page.Object}}
		}
		return successionIdentityForRequest(t, q, root, fid(98))
	}
	q.IdentityPlan.Pages = []contract.IdentityPage{{Kind: contract.RequiredSupportKind, Index: 1, Object: fid(106)}, {Kind: contract.RequiredSupportKind, Index: 2, Object: fid(107)}}
	request, err := contract.SuccessionRequestDescriptor(q)
	if err != nil {
		t.Fatal(err)
	}
	publicOperation := uint16(contract.OperationReplaceRecoveryKeysAndRoot)
	newReceipt := contract.CompactMutationReceiptPlan{Schema: contract.MutationReceiptSchema, OperationKind: publicOperation, DomainID: q.DomainID, OperationID: q.OperationID,
		PredecessorRevisionID: q.PredecessorHeadRevisionID, RequestedRevisionID: q.IdentityPlan.Revision, ObservedRevisionID: q.IdentityPlan.Revision, StateResult: 1, EvidenceCeiling: 1,
		CanonicalOutcome: 1, ChangedSubjects: contract.GeneratorDescriptor{Digest: fid(108), Length: 80, Count: 2}}
	empty := contract.EmptyMutationResultDescriptors()
	newReceipt.CompleteResult, err = contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: newReceipt,
		RequestCoreDigest: request.Digest, ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
	if err != nil {
		t.Fatal(err)
	}
	receiptPlan := contract.MutationReceiptDeltaPlan{DomainID: q.DomainID, OperationKind: publicOperation, AddedCount: 1,
		Before: contract.MutationReceiptWindows{DomainID: q.DomainID}, NewReceipt: newReceipt}
	rows, err := receiptPlan.AfterSupportRecords()
	if err != nil {
		t.Fatal(err)
	}
	page, err := EncodeRequiredSupportReceiptPlan(RequiredSupportPage{Domain: q.DomainID, Object: fid(106), Index: 1, Records: rows}, newReceipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := contract.MutationReceiptDeltaPlanDigest(receiptPlan)
	if err != nil {
		t.Fatal(err)
	}
	root := p.Snapshot
	root.RequiredSupport = append(root.RequiredSupport, Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: q.DomainID, Object: fid(106), Digest: contract.Hash(page), Length: uint32(len(page)), Index: 1})
	root.RequiredSupportRecordCount++
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(page))
	indexes, err := receiptPlan.AfterIndexes()
	if err != nil {
		t.Fatal(err)
	}
	root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder, err = indexes.Descriptors()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := contract.MutationReceiptIndexBlobID(q.DomainID, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
	if err != nil {
		t.Fatal(err)
	}
	indexBody, err := contract.EncodeMutationReceiptIndexes(indexes)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, Count: 1, TotalLength: uint64(len(indexBody)), WholeDigest: contract.Hash(indexBody), Payload: indexBody})
	if err != nil {
		t.Fatal(err)
	}
	fragmentID, err := contract.GeneratorFragmentID(blob, 0)
	if err != nil {
		t.Fatal(err)
	}
	indexPage, err := EncodeRequiredSupportPage(RequiredSupportPage{Domain: q.DomainID, Object: fid(107), Index: 2, Records: []contract.SupportRecord{{Kind: 3, RecordID: fragmentID, Body: fragment}}})
	if err != nil {
		t.Fatal(err)
	}
	root.RequiredSupport = append(root.RequiredSupport, Ref{Kind: contract.RequiredSupportKind, Format: Version, Domain: q.DomainID, Object: fid(107), Digest: contract.Hash(indexPage), Length: uint32(len(indexPage)), Index: 2})
	root.RequiredSupportRecordCount++
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(indexPage))
	root.Generated.Fragments = []FragmentLocation{{BlobID: blob, SupportPageIndex: 2}}
	return successionIdentityForRequest(t, q, root, receipt)
}

// full_only: false
func TestSuccessionIdentityNormalKEKAndCombinedPlans(t *testing.T) {
	for _, mask := range []uint8{1, 2, 3} {
		for _, approval := range []uint8{1, 2} {
			p := successionRecoveryIdentityFixture(t, 1, mask, approval)
			if _, err := DeriveSuccessionIdentity(p); err != nil {
				t.Fatalf("normal mask %d approval %d refused: %v", mask, approval, err)
			}
		}
	}
}

// full_only: false
func TestSuccessionRecoveryIdentityUsesTypedReceiptPlan(t *testing.T) {
	for _, choice := range [][2]uint8{{3, 4}, {3, 8}, {3, 12}} {
		for _, approval := range []uint8{1, 2} {
			t.Run(fmt.Sprintf("operation%d-mask%d-approval%d", choice[0], choice[1], approval), func(t *testing.T) {
				p := successionRecoveryIdentityFixture(t, choice[0], choice[1], approval)
				got, err := DeriveSuccessionIdentity(p)
				if err != nil {
					t.Fatal(err)
				}
				// The mutation branch has only these four exact fields; graph
				// framing is independently pinned by the normal fixture above.
				want := successionIDs([]byte("ENKV/CRYPTO/v2/mutation-request-identity-v1\x00"), p.Authorization.Subject.RequestCoreDigest)
				want = binary.BigEndian.AppendUint32(want, 0)
				want = successionIDs(want, p.Request.IdentityPlan.Revision, got.Graph.Digest)
				if got.RequestIdentityDigest != contract.Hash(want) {
					t.Fatal("recovery identity omitted a field or used wrong purpose")
				}
				if got.Graph.Length >= 512<<10 {
					t.Fatal("graph exceeded fixed bound")
				}
				p.Snapshot.RequiredSupport[0].Digest = ID{}
				if _, err := DeriveSuccessionIdentity(p); err == nil {
					t.Fatal("root used a zero receipt-page digest")
				}
			})
		}
	}
	p := successionRecoveryIdentityFixture(t, 3, 4, 1)
	p.Request.IdentityPlan.Pages = nil
	if _, err := DeriveSuccessionIdentity(p); err == nil {
		t.Fatal("recovery did not assign its new support page")
	}
	p = successionRecoveryIdentityFixture(t, 3, 8, 1)
	p.Evidence[0].KEK.BindingID = fid(200)
	digest, err := contract.EvidencePlanDigest(p.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	p.Authorization.Subject.SuccessorEvidenceDigest = digest
	if _, err := DeriveSuccessionIdentity(p); err == nil {
		t.Fatal("matching evidence hash admitted wrong successor KEK")
	}
	p = successionRecoveryIdentityFixture(t, 3, 8, 1)
	p.AccessPlan.Replacements[0].BeforeBindingDigest = fid(200)
	if _, err := DeriveSuccessionIdentity(p); err == nil {
		t.Fatal("access plan changed a different predecessor KEK")
	}
}

// full_only: false
func TestSuccessionAccessDescriptorScalarBounds(t *testing.T) {
	// These are the graph's scalar checks only. A complete nonempty closure and
	// actual record-derived digests are admitted by Core before graph assembly.
	for _, count := range []uint32{1, 512, 514} {
		p := successionRecoveryIdentityFixture(t, 3, 8, 1)
		p.Snapshot.SecretCount = min(count, 512)
		p.Snapshot.SecretOrdinaryWrapCount = p.Snapshot.SecretCount
		p.Snapshot.AccessRecordCount = count
		wraps := 2 * uint64(count)
		if count == 514 {
			// 512 current values, one 64-reader retained value and one seed,
			// each with its dedicated recovery wrapper.
			wraps += 63
		}
		p.Snapshot.CurrentAccess.Core.AccessPageRefs = []contract.Ref{{Length: uint32(75 + 102*uint64(count) + 489*wraps)}}
		p.Coverage = contract.DescriptorVector{Digest: fid(201), Length: 178 + 168*uint64(count), Count: count}
		p.Unchanged = contract.DescriptorVector{Digest: fid(202), Length: 144 + 162*uint64(count), Count: count}
		p.AfterAccess = contract.DescriptorVector{Digest: fid(203), Length: 181 + 172*uint64(count) + 489*wraps, Count: count}
		request := p.Authorization.Subject.RequestCoreDigest
		if !p.accessMatches(request) {
			t.Fatal("valid full-coverage scalar descriptor refused")
		}
		for _, change := range []func(*SuccessionIdentityPlan){
			func(p *SuccessionIdentityPlan) { p.Coverage.Length++ }, func(p *SuccessionIdentityPlan) { p.Unchanged.Length++ }, func(p *SuccessionIdentityPlan) { p.AfterAccess.Length++ },
			func(p *SuccessionIdentityPlan) { p.Coverage.Count++ }, func(p *SuccessionIdentityPlan) { p.Unchanged.Count++ }, func(p *SuccessionIdentityPlan) { p.AfterAccess.Count++ },
			func(p *SuccessionIdentityPlan) { p.AfterAccess.Digest = ID{} }, func(p *SuccessionIdentityPlan) { p.Snapshot.AccessRecordCount++ },
			func(p *SuccessionIdentityPlan) {
				p.Snapshot.CurrentAccess.Core.AccessPageRefs = []contract.Ref{{Length: 74}}
			},
		} {
			bad := p
			change(&bad)
			if bad.accessMatches(request) {
				t.Fatal("inconsistent access descriptor scalar admitted")
			}
		}
	}
}
