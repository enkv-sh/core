package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type candidateQualifierProbe struct {
	calls             int
	reason            contract.Reason
	wrongDigest       bool
	wrongTarget       bool
	wrongFamily       bool
	cancel            context.CancelFunc
	mutateSPKI        bool
	qualifiedOnReason bool
}

func qualifiedCandidateForTest(ctx context.Context, h format.Head, root format.Root, normal, recovery candidateSigningQualifier) (qualifiedCandidateAnchor, bool) {
	anchor, result := qualifyCandidateSelection(ctx, h, root, normal, recovery)
	return anchor, result.Outcome == 0
}

type unguardedCandidateProbe struct{ read *candidateReadProbe }

func (p unguardedCandidateProbe) CandidateLocation() contract.StoreLocation {
	return p.read.CandidateLocation()
}
func (p unguardedCandidateProbe) ReadHEAD(ctx context.Context) contract.ReadResult {
	return p.read.ReadHEAD(ctx)
}
func (p unguardedCandidateProbe) ReadConfiguration(ctx context.Context, domain, store contract.ID) contract.ReadResult {
	return p.read.ReadConfiguration(ctx, domain, store)
}
func (p unguardedCandidateProbe) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	return p.read.ReadRoot(ctx, ref)
}

func candidateProbeForSelected(t *testing.T, env fixtureEnvironment, selected *StateSession) *candidateReadProbe {
	t.Helper()
	configuration := env.Store.(contract.StoreConfigurationSource).StoreConfiguration()
	configBody, err := contract.EncodeStoreConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	rootBody, err := format.EncodeRoot(selected.root)
	if err != nil {
		t.Fatal(err)
	}
	ok := func(body []byte) contract.ReadResult {
		return contract.ReadResult{Status: contract.ReadOK, Body: bytes.Clone(body), Token: selected.token}
	}
	return &candidateReadProbe{
		head: ok(selected.body), configuration: ok(configBody), root: ok(rootBody),
		location: contract.StoreLocation{Provider: configuration.Provider, Region: configuration.Region,
			Bucket: configuration.Bucket, PrefixBeforeHEAD: configuration.PrefixBeforeHEAD,
			ExpectedOwner: configuration.ExpectedOwner},
	}
}

// full_only: false
func TestAnchoredPublicCandidateBindsOneLocationAndSelection(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	probe := candidateProbeForSelected(t, env, f.session)
	qualifier := &candidateQualifierProbe{}
	anchored, result := anchorPublicCandidate(ctx, probe, env.Domain, qualifier, nil)
	if result.Outcome != 0 || anchored.headToken != f.session.token || anchored.root.Snapshot != f.session.root.Snapshot ||
		anchored.configuration.DomainID != env.Domain || anchored.anchor.role != contract.NormalSigningRole ||
		!slices.Equal(probe.calls, []string{"HEAD", "configuration", "root"}) || qualifier.calls != 1 {
		t.Fatal("public candidate was not anchored to its fixed GETs", result, probe.calls, qualifier.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.configuration = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
	qualifier = &candidateQualifierProbe{}
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, qualifier, nil); result.Outcome != EvidenceUnavailable ||
		result.StoreReason != contract.ReasonAccess || qualifier.calls != 0 || !slices.Equal(probe.calls, []string{"HEAD", "configuration"}) {
		t.Fatal("reconstruction continued without its required helper", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.location.Bucket = "other-valid-bucket"
	qualifier = &candidateQualifierProbe{}
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, qualifier, nil); result.Outcome != IntegrityFailure ||
		result.Reason != ConstructionMismatch || !slices.Equal(probe.calls, []string{"HEAD", "configuration"}) || qualifier.calls != 0 {
		t.Fatal("copied helper became valid at another physical location", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	if _, result := anchorPublicCandidate(ctx, probe, contract.Hash([]byte("another domain")), &candidateQualifierProbe{}, nil); result.Outcome != IntegrityFailure ||
		result.Reason != ConstructionMismatch || !slices.Equal(probe.calls, []string{"HEAD"}) {
		t.Fatal("wrong independent DomainID reached helper or signer", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.root.Body[0] ^= 1
	qualifier = &candidateQualifierProbe{}
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, qualifier, nil); result.Outcome != IntegrityFailure ||
		qualifier.calls != 0 || !slices.Equal(probe.calls, []string{"HEAD", "configuration", "root"}) {
		t.Fatal("altered root reached signing lookup", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.configuration.Token = contract.Token{Family: contract.AWS, Value: `"foreign"`}
	qualifier = &candidateQualifierProbe{}
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, qualifier, nil); result.Outcome != IntegrityFailure ||
		result.Reason != ConstructionMismatch || qualifier.calls != 0 ||
		!slices.Equal(probe.calls, []string{"HEAD", "configuration"}) {
		t.Fatal("foreign provider helper token reached the selected root", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.head = contract.ReadResult{Status: contract.ReadMissing}
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, &candidateQualifierProbe{}, nil); result.Outcome != RootLossUnsupported ||
		result.Reason != MissingSelectedObject || !slices.Equal(probe.calls, []string{"HEAD"}) {
		t.Fatal("missing HEAD continued candidate reads", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	qualifier = &candidateQualifierProbe{reason: contract.ReasonAccess}
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, qualifier, nil); result.Outcome != EvidenceUnavailable ||
		result.Reason != SigningUnavailable || qualifier.calls != 1 {
		t.Fatal("public lookup denial lost its unavailable outcome", result)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, nil, nil); result.Outcome != AdmissionRefused || len(probe.calls) != 0 {
		t.Fatal("candidate with no supplied signing resource reached Store", result, probe.calls)
	}
	disabled, _ := genesisEnvironment(t, contract.GCP, false)
	disabledRun := newScenarioRun(t, ctx, disabled)
	disabledFixture := newEnvironmentFixture(t, ctx, disabledRun.env, []int{1}, false)
	probe = candidateProbeForSelected(t, disabled, disabledFixture.session)
	recovery := &candidateQualifierProbe{}
	if _, result := anchorPublicCandidate(ctx, probe, disabled.Domain, nil, recovery); result.Outcome != EvidenceUnavailable || result.Reason != SigningUnavailable ||
		recovery.calls != 0 || !slices.Equal(probe.calls, []string{"HEAD", "configuration", "root"}) {
		t.Fatal("disabled recovery called a K3 resource or skipped public candidate bounds", result, probe.calls)
	}
}

// full_only: false
func TestAnchoredAWSCandidateRequiresSameGuardedHEAD(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.AWS, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	probe := candidateProbeForSelected(t, env, f.session)
	probe.location.ExpectedOwner = "" // No owner was supplied for the first public GET.
	anchored, result := anchorPublicCandidate(ctx, probe, env.Domain, &candidateQualifierProbe{}, nil)
	if result.Outcome != 0 || anchored.configuration.ExpectedOwner == "" ||
		probe.guardedOwner != anchored.configuration.ExpectedOwner ||
		!slices.Equal(probe.calls, []string{"HEAD", "configuration", "root", "guarded HEAD"}) {
		t.Fatal("AWS owner was not applied to the identical selected HEAD", result, probe.calls, probe.guardedOwner)
	}
	for _, tc := range []struct {
		name    string
		edit    func(*candidateReadProbe)
		outcome Outcome
		reason  Reason
	}{
		{"body changed", func(p *candidateReadProbe) {
			p.guardedSet = true
			p.guarded = p.head
			p.guarded.Body = bytes.Clone(p.head.Body)
			p.guarded.Body[0] ^= 1
		}, Contention, DifferentSelection},
		{"token changed", func(p *candidateReadProbe) {
			p.guardedSet = true
			p.guarded = p.head
			p.guarded.Token.Value = `"another"`
		}, Contention, DifferentSelection},
		{"owner denied", func(p *candidateReadProbe) {
			p.guardedSet = true
			p.guarded = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
		}, EvidenceUnavailable, ReadUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := candidateProbeForSelected(t, env, f.session)
			p.location.ExpectedOwner = ""
			tc.edit(p)
			if _, result := anchorPublicCandidate(ctx, p, env.Domain, &candidateQualifierProbe{}, nil); result.Outcome != tc.outcome ||
				result.Reason != tc.reason || len(p.calls) != 4 || p.calls[3] != "guarded HEAD" {
				t.Fatal("changed or denied guarded HEAD used an unguarded fallback", result, p.calls)
			}
		})
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.location.ExpectedOwner = "999999999999"
	if _, result := anchorPublicCandidate(ctx, probe, env.Domain, &candidateQualifierProbe{}, nil); result.Outcome != IntegrityFailure ||
		result.Reason != ConstructionMismatch || !slices.Equal(probe.calls, []string{"HEAD", "configuration"}) {
		t.Fatal("wrong supplied owner reached an unguarded helper continuation", result, probe.calls)
	}
	probe = candidateProbeForSelected(t, env, f.session)
	probe.location.ExpectedOwner = ""
	if _, result := anchorPublicCandidate(ctx, unguardedCandidateProbe{probe}, env.Domain, &candidateQualifierProbe{}, nil); result.Outcome != AdmissionRefused ||
		!slices.Equal(probe.calls, []string{"HEAD", "configuration", "root"}) {
		t.Fatal("AWS candidate lacking a guarded reread source was admitted", result, probe.calls)
	}
}

func (p *candidateQualifierProbe) QualifySigningBinding(_ context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	p.calls++
	if p.cancel != nil {
		p.cancel()
	}
	if p.reason != contract.ReasonNone && !p.qualifiedOnReason {
		return contract.SigningQualificationResult{Reason: p.reason}
	}
	digest, err := contract.SigningBindingDigest(binding)
	if err != nil {
		return contract.SigningQualificationResult{Reason: contract.ReasonProof}
	}
	if p.mutateSPKI {
		binding.SPKI[0] ^= 1
	}
	if p.wrongDigest {
		digest[0] ^= 1
	}
	target := contract.NormalSignerTarget
	if binding.Role == contract.RecoverySigningRole {
		target = contract.RecoverySignerTarget
	}
	if p.wrongTarget {
		target ^= 1
	}
	provider := binding.Provider
	if p.wrongFamily {
		if provider == contract.GCP {
			provider = contract.AWS
		} else {
			provider = contract.GCP
		}
	}
	return contract.SigningQualificationResult{TargetRole: target, SigningBindingDigest: digest,
		Provider: provider, Qualified: 1, Reason: p.reason}
}

// full_only: false
func TestCandidateCurrentSignerSignatureBindsSelectedRoot(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	check := func(label string) {
		t.Helper()
		selected := f.session
		control, ok := selectedControlFrom(selected.root, &selected.recipients, selected.root.CurrentAccess.Core.AuthorityRecipientID)
		if !ok {
			t.Fatal(label, "selected authority control missing")
		}
		var genesis *contract.GenesisDescriptorCore
		if selected.head.AuthKind == format.GenesisAuth {
			d, valid := selected.admission.domainBasis()
			if !valid {
				t.Fatal(label, "validated genesis descriptor missing")
			}
			genesis = &d
		}
		if !selectedHeadProofs(selected.head, control, genesis) {
			t.Fatal(label, "selected complete HEAD proof refused")
		}
		binding, ok := candidateSelectionSignature(selected.head, selected.root, contract.NormalSigningRole)
		if !ok || !signingBindingEqual(binding, selected.root.CurrentAccess.Core.NormalSigning) {
			t.Fatal(label, "selected normal signer lost its complete signature")
		}
		if _, ok := candidateSelectionSignature(selected.head, selected.root, contract.RecoverySigningRole); ok {
			t.Fatal(label, "recovery basis signature became a complete selection signature")
		}
		if _, ok := candidateSelectionSignature(selected.head, selected.root, 0); ok {
			t.Fatal(label, "unknown signing role became an anchor")
		}
		damaged := selected.head
		damaged.AuthorizationSignature = bytes.Clone(damaged.AuthorizationSignature)
		damaged.AuthorizationSignature[0] ^= 1
		if _, ok := candidateSelectionSignature(damaged, selected.root, contract.NormalSigningRole); ok {
			t.Fatal(label, "damaged complete signature accepted")
		}
		if selectedHeadProofs(damaged, control, genesis) {
			t.Fatal(label, "damaged complete signature passed intrinsic HEAD proof")
		}
		damaged = selected.head
		damaged.K1 = bytes.Clone(damaged.K1)
		damaged.K1[0] ^= 1
		if _, ok := candidateSelectionSignature(damaged, selected.root, contract.NormalSigningRole); ok {
			t.Fatal(label, "damaged current binding signature accepted")
		}
		if selectedHeadProofs(damaged, control, genesis) {
			t.Fatal(label, "damaged current binding passed intrinsic HEAD proof")
		}
		if genesis != nil {
			missing := selected.head
			g := *missing.Genesis
			g.K3Challenge = bytes.Clone(g.K3Challenge)
			g.K3Challenge[0] ^= 1
			missing.Genesis = &g
			if _, ok := candidateSelectionSignature(missing, selected.root, contract.NormalSigningRole); !ok {
				t.Fatal("K3 challenge change did not isolate the later genesis proof")
			}
			if selectedHeadProofs(missing, control, genesis) {
				t.Fatal("damaged genesis K3 initialization challenge passed")
			}
			if selectedHeadProofs(selected.head, control, nil) {
				t.Fatal("genesis proof passed without validated descriptor")
			}
		}
		unknown := selected.head
		unknown.AuthKind = 255
		if selectedHeadProofs(unknown, control, genesis) {
			t.Fatal("unknown HEAD proof family accepted")
		}
		damaged = selected.head
		damaged.Core.Root.Digest[0] ^= 1
		if _, ok := candidateSelectionSignature(damaged, selected.root, contract.NormalSigningRole); ok {
			t.Fatal(label, "uncommitted root accepted")
		}
		alteredRoot := selected.root
		alteredRoot.CurrentAccess.AccessRoot[0] ^= 1
		if _, ok := candidateSelectionSignature(selected.head, alteredRoot, contract.NormalSigningRole); ok {
			t.Fatal(label, "damaged access root accepted")
		}
	}
	check("genesis")
	normal, recovery := &candidateQualifierProbe{}, &candidateQualifierProbe{}
	if anchor, ok := qualifiedCandidateForTest(ctx, f.session.head, f.session.root, normal, recovery); !ok ||
		anchor.role != contract.NormalSigningRole || normal.calls != 1 || recovery.calls != 0 {
		t.Fatal("genesis did not stop after adequate independent normal key", normal.calls, recovery.calls)
	}
	beforeSPKI := bytes.Clone(f.session.root.CurrentAccess.Core.NormalSigning.SPKI)
	mutating := &candidateQualifierProbe{mutateSPKI: true}
	if anchor, ok := qualifiedCandidateForTest(ctx, f.session.head, f.session.root, mutating, nil); !ok ||
		!bytes.Equal(anchor.binding.SPKI, beforeSPKI) ||
		!bytes.Equal(f.session.root.CurrentAccess.Core.NormalSigning.SPKI, beforeSPKI) {
		t.Fatal("public lookup changed the authenticated signing binding")
	}
	for _, tc := range []struct {
		name  string
		probe candidateQualifierProbe
	}{
		{"wrong target", candidateQualifierProbe{wrongTarget: true}},
		{"wrong provider", candidateQualifierProbe{wrongFamily: true}},
		{"qualified with refusal", candidateQualifierProbe{reason: contract.ReasonProof, qualifiedOnReason: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := qualifiedCandidateForTest(ctx, f.session.head, f.session.root, &tc.probe, nil); ok || tc.probe.calls != 1 {
				t.Fatal("mismatched public qualification became an independent anchor")
			}
		})
	}
	recipients := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run.suppliedSelection(f, append(f.session.currentEntryInputs(), sharingSecretNamed(t, env, "anchor secret", "anchor source", recipients)))
	check("ordinary")
}

// full_only: false
func TestCandidateGeneratedAndAdministrativeProofKinds(t *testing.T) {
	ctx := context.Background()
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	if selected.head.AuthKind != format.GeneratorAuth {
		t.Fatal("generated fixture is not selected under its generator proof")
	}
	check := func(label string, s *StateSession) {
		t.Helper()
		control, ok := selectedControlFrom(s.root, &s.recipients, s.root.CurrentAccess.Core.AuthorityRecipientID)
		if !ok || !selectedHeadProofs(s.head, control, nil) {
			t.Fatal(label, "selected complete HEAD proof refused")
		}
		if _, ok := candidateSelectionSignature(s.head, s.root, contract.NormalSigningRole); !ok {
			t.Fatal(label, "complete normal selection proof refused")
		}
		if _, ok := candidateSelectionSignature(s.head, s.root, contract.RecoverySigningRole); ok {
			t.Fatal(label, "K3 basis became a complete selection signature")
		}
		bad := s.head
		bad.AuthorizationSignature = bytes.Clone(bad.AuthorizationSignature)
		bad.AuthorizationSignature[0] ^= 1
		if _, ok := candidateSelectionSignature(bad, s.root, contract.NormalSigningRole); ok {
			t.Fatal(label, "damaged selected proof accepted")
		}
		if selectedHeadProofs(bad, control, nil) {
			t.Fatal(label, "damaged selected proof passed intrinsic HEAD proof")
		}
		probe := &candidateQualifierProbe{}
		if anchor, ok := qualifiedCandidateForTest(ctx, s.head, s.root, probe, nil); !ok ||
			anchor.role != contract.NormalSigningRole || probe.calls != 1 {
			t.Fatal(label, "independent normal signing anchor refused")
		}
		public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, s), env.Domain,
			&candidateQualifierProbe{}, nil)
		if result.Outcome != 0 {
			t.Fatal(label, "public candidate refused", result)
		}
		source := &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(),
			configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
		basis, result := bindPublicReadBasis(ctx, public, source)
		if result.Outcome != 0 {
			t.Fatal(label, "normal read basis refused", result)
		}
		complete, result := completePublicSelection(ctx, basis, nil)
		if result.Outcome != 0 || complete.image.root.Snapshot != s.root.Snapshot || complete.authorityID != s.admission.recipient {
			t.Fatal(label, "complete read-only proof refused", result)
		}
	}
	check("generator", selected)
	admin, result := openAdministrative(ctx, OpenContext{admission: &selected.admission}, env.Store)
	if admin == nil || result.Outcome != ObservedCurrent || len(admin.adminIndex.Groups) == 0 {
		t.Fatal("administrative predecessor", result)
	}
	candidate, result := prepareTestEndSelectedWork(t, admin, ctx, admin.adminIndex.Groups[0].GroupID, env.Trust)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("administrative candidate", result)
	}
	ended, result := admin.selectCandidate(ctx, candidate)
	if ended == nil || result.Outcome != ObservedCurrent || ended.head.AuthKind != format.AdministrativeAuth {
		t.Fatal("administrative selection", result)
	}
	check("administrative", ended)
}

// full_only: false
func TestCandidateChangedRecoverySignerUsesAcceptance(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, f.session, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, contract.NormalSigningRole)
	permit := admitAuthorityReplacement(t, f.session, actors.Keys, actors.After, contract.SuccessionReplaceRecoveryBasis, contract.NormalSigningRole, contract.SuccessionChangeRecoverySigner, actors.Source)
	candidate, result := f.session.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("changed recovery signer preparation", result)
	}
	_ = deliverSuccessionBasis(t, candidate)
	selected, result := f.session.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent || len(selected.head.Succession.Acceptances) != 1 ||
		selected.head.Succession.Acceptances[0].Role != contract.RecoverySigningRole {
		t.Fatal("changed recovery signer selection", result)
	}
	for _, role := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		if _, ok := candidateSelectionSignature(selected.head, selected.root, role); !ok {
			t.Fatal("current normal authorizer or changed recovery acceptance lost its selected signature", role)
		}
	}
	recovery := &candidateQualifierProbe{}
	if anchor, ok := qualifiedCandidateForTest(ctx, selected.head, selected.root, nil, recovery); !ok ||
		anchor.role != contract.RecoverySigningRole || recovery.calls != 1 {
		t.Fatal("recovery-only independent selector did not use changed-signer acceptance")
	}
	public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, selected), env.Domain,
		nil, &candidateQualifierProbe{})
	if result.Outcome != 0 || public.anchor.role != contract.RecoverySigningRole {
		t.Fatal("changed recovery signer did not anchor complete selection", result)
	}
	source := &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(),
		configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	basis, result := bindPublicReadBasis(ctx, public, source)
	if result.Outcome != 0 {
		t.Fatal("changed recovery signer read basis", result)
	}
	complete, result := completePublicSelection(ctx, basis, nil)
	if result.Outcome != 0 || complete.image.root.Snapshot != selected.root.Snapshot || complete.authorityID != selected.admission.recipient {
		t.Fatal("changed recovery acceptance did not complete read-only relations", result)
	}
	bad := selected.head
	proof := *bad.Succession
	proof.Acceptances = slices.Clone(proof.Acceptances)
	proof.Acceptances[0].Signature = bytes.Clone(proof.Acceptances[0].Signature)
	proof.Acceptances[0].Signature[0] ^= 1
	bad.Succession = &proof
	if _, ok := candidateSelectionSignature(bad, selected.root, contract.RecoverySigningRole); ok {
		t.Fatal("damaged recovery acceptance authenticated the changed signer")
	}
}

// full_only: false
func TestCandidateChangedSignerNeedsAcceptanceOrCurrentAuthorizer(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, f.session, 1, 1, contract.RecoverySigningRole)
	permit := admitAuthorityReplacement(t, f.session, actors.Keys, actors.After, 1, contract.RecoverySigningRole, 1, actors.Source)
	candidate, result := f.session.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("changed signer preparation", result)
	}
	_ = deliverSuccessionBasis(t, candidate)
	selected, result := f.session.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("changed signer selection", result)
	}
	if _, ok := candidateSelectionSignature(selected.head, selected.root, contract.NormalSigningRole); !ok {
		t.Fatal("current changed normal signer lost complete-selection acceptance")
	}
	if _, ok := candidateSelectionSignature(selected.head, selected.root, contract.RecoverySigningRole); !ok {
		t.Fatal("unchanged recovery authorizer lost its complete-selection signature")
	}
	normal, recovery := &candidateQualifierProbe{}, &candidateQualifierProbe{}
	if anchor, ok := qualifiedCandidateForTest(ctx, selected.head, selected.root, normal, recovery); !ok ||
		anchor.role != contract.NormalSigningRole || normal.calls != 1 || recovery.calls != 0 {
		t.Fatal("changed normal acceptance did not stop before unused recovery lookup", normal.calls, recovery.calls)
	}
	normal, recovery = &candidateQualifierProbe{reason: contract.ReasonAccess}, &candidateQualifierProbe{}
	if anchor, ok := qualifiedCandidateForTest(ctx, selected.head, selected.root, normal, recovery); !ok ||
		anchor.role != contract.RecoverySigningRole || normal.calls != 1 || recovery.calls != 1 {
		t.Fatal("unavailable normal key prevented applicable recovery anchor", normal.calls, recovery.calls)
	}
	normal = &candidateQualifierProbe{wrongDigest: true}
	if _, ok := qualifiedCandidateForTest(ctx, selected.head, selected.root, normal, nil); ok || normal.calls != 1 {
		t.Fatal("unbound provider qualification accepted")
	}
	ctxCanceled, cancel := context.WithCancel(ctx)
	normal, recovery = &candidateQualifierProbe{cancel: cancel}, &candidateQualifierProbe{}
	if _, ok := qualifiedCandidateForTest(ctxCanceled, selected.head, selected.root, normal, recovery); ok ||
		normal.calls != 1 || recovery.calls != 0 {
		t.Fatal("canceled public lookup reached another key", normal.calls, recovery.calls)
	}
	withoutAcceptance := selected.head
	proof := *withoutAcceptance.Succession
	proof.Acceptances = nil
	withoutAcceptance.Succession = &proof
	if _, ok := candidateSelectionSignature(withoutAcceptance, selected.root, contract.NormalSigningRole); ok {
		t.Fatal("K1 became a full selection signature without acceptance")
	}
	if _, ok := candidateSelectionSignature(withoutAcceptance, selected.root, contract.RecoverySigningRole); ok {
		t.Fatal("invalid changed-signer HEAD passed under unchanged authorizer")
	}
	wrongAcceptance := selected.head
	proof = *wrongAcceptance.Succession
	proof.Acceptances = slices.Clone(proof.Acceptances)
	proof.Acceptances[0].Signature = bytes.Clone(proof.Acceptances[0].Signature)
	proof.Acceptances[0].Signature[0] ^= 1
	wrongAcceptance.Succession = &proof
	if _, ok := candidateSelectionSignature(wrongAcceptance, selected.root, contract.NormalSigningRole); ok {
		t.Fatal("damaged final-selection acceptance passed")
	}
}

// full_only: false
func TestCandidateRecoveryOnlyAnchorUsesOnlyApplicableK3(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	recipients := []contract.ID{f.session.admission.recipient, fixtureID(env.Domain, "reader")}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run.suppliedSelection(f, append(f.session.currentEntryInputs(), sharingSecretNamed(t, env, "K3 anchor secret", "K3 anchor source", recipients)))
	env = syntheticAuthorityScenarioEnvironment(t, env)
	actors := env.ReplacementActors(t, ctx, f.session, 3, 8, contract.RecoverySigningRole)
	permit := admitAuthorityReplacement(t, f.session, actors.Keys, actors.After, 3, contract.RecoverySigningRole, 8, actors.Source)
	candidate, result := f.session.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("recovery-authorized replacement preparation", result)
	}
	_ = deliverSuccessionBasis(t, candidate)
	selected, result := f.session.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("recovery-authorized replacement selection", result)
	}
	normal, recovery := &candidateQualifierProbe{}, &candidateQualifierProbe{}
	if anchor, ok := qualifiedCandidateForTest(ctx, selected.head, selected.root, normal, recovery); !ok ||
		anchor.role != contract.RecoverySigningRole || normal.calls != 0 || recovery.calls != 1 {
		t.Fatal("K3-only selection used an inapplicable normal key", normal.calls, recovery.calls)
	}

	disabled, _ := genesisEnvironment(t, contract.GCP, false)
	disabledFixture := newEnvironmentFixture(t, ctx, disabled, []int{1}, false)
	recovery = &candidateQualifierProbe{}
	if _, ok := qualifiedCandidateForTest(ctx, disabledFixture.session.head, disabledFixture.session.root, nil, recovery); ok || recovery.calls != 0 {
		t.Fatal("disabled recovery reached a K3 lookup")
	}
}

// full_only: false
func TestReconstructionPreservesCurrentPublicationProofFamilies(t *testing.T) {
	for _, kind := range []uint8{format.LifecycleAuth, format.OutputReserveAuth, format.OutputCloseAuth} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			env, f, coordinate, marker := signedPublicationSelectionFixture(t, kind, true)
			ctx := t.Context()
			public, result := anchorPublicCandidate(ctx, candidateProbeForSelected(t, env, f.session), env.Domain, &candidateQualifierProbe{}, nil)
			if result.Outcome != 0 {
				t.Fatal("publication public anchor", result)
			}
			store := env.Store.(*memoryStore)
			basis, result := bindPublicReadBasis(ctx, public, &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: store.StoreConfiguration()})
			if result.Outcome != 0 {
				t.Fatal("publication read basis", result)
			}
			selected, result := completePublicSelection(ctx, basis, nil)
			if result.Outcome != 0 {
				t.Fatal("publication complete closure", result)
			}
			relation, err := selectedPublicationRelation(&selected.image)
			if err != nil {
				t.Fatal(err)
			}
			gotCoordinate, present := relation.coordinates[coordinate.CoordinateID]
			gotMarker, found := relation.markers[marker.AttemptID]
			wantCoordinate, _ := contract.EncodePublicationCoordinate(coordinate)
			actualCoordinate, _ := contract.EncodePublicationCoordinate(gotCoordinate)
			wantMarker, _ := contract.EncodePublicationMarker(marker)
			actualMarker, _ := contract.EncodePublicationMarker(gotMarker)
			if !present || !found || !bytes.Equal(wantCoordinate, actualCoordinate) || !bytes.Equal(wantMarker, actualMarker) {
				t.Fatal("publication selected observations changed")
			}
		})
	}
}
