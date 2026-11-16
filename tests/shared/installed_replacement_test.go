package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

type installedReplacementEngine interface {
	Replace(context.Context, contract.ID) PublicReplacementResult
	Close()
}
type installedReplacementFixture struct {
	env                                                                                     fixtureEnvironment
	fixture                                                                                 *environmentFixture
	keys                                                                                    *custody.Fixture
	installation                                                                            ReplacementInstallation
	goal                                                                                    RoleReplacementGoal
	target                                                                                  ReplacementTarget
	recipient                                                                               contract.ID
	public                                                                                  ReplacementPublicGoal
	successor                                                                               *testtrust.Signer
	publicCalls, signerFactories, custodyFactories, delivered, closedSigners, closedCustody int
	changed                                                                                 bool
	output                                                                                  ReplacementSuccessor
	publish                                                                                 func(context.Context, ReplacementSuccessor) (ReplacementReadback, error)
}

func newInstalledReplacementFixture(t *testing.T, family contract.Family, target ReplacementTarget, mask, approval uint8, material ReplacementMaterialSource, equalRecipient ...bool) *installedReplacementFixture {
	t.Helper()
	ctx := context.Background()
	env, keys := genesisEnvironment(t, family, true)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	reader := fixtureID(env.Domain, "reader")
	recipients := []contract.ID{f.session.admission.recipient, reader}
	slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	run.suppliedSelection(f, []ApplyEntryInput{sharingSecret(t, env, "installed replacement shared material", recipients)})
	h := &installedReplacementFixture{env: env, fixture: f, keys: keys, target: target, recipient: reader, goal: RoleReplacementGoal{ApprovalRole: approval, MaterialSource: material}, public: ReplacementPublicGoal{Provider: family}}
	before := currentControlOf(f.session)
	if mask&(contract.SuccessionChangeNormalSigner|contract.SuccessionChangeRecoverySigner) != 0 {
		var binding contract.PublicSigningBinding
		if target == ReplacementTargetRecovery {
			h.successor, binding = env.Recovery.(*testtrust.Signer).Successor(t, before.Recovery.Signing)
		} else {
			h.successor, binding = env.Trust.(*fixtureTrust).Successor(t, before.NormalSigning)
		}
		h.public.Signing = &ReplacementSigningKey{Selector: binding.KeySelector, SPKI: binding.SPKI, Fingerprint: binding.Fingerprint, Trust: binding.Binding.Trust, Profile: binding.SigningProfile}
		h.goal.SigningSelector = binding.KeySelector
	}
	if mask&(contract.SuccessionChangeAuthorityKEK|contract.SuccessionChangeRecoveryKEK) != 0 || target == ReplacementTargetRecipient {
		var binding contract.KMSBinding
		switch target {
		case ReplacementTargetRecipient:
			if len(equalRecipient) > 0 && equalRecipient[0] {
				binding = *f.session.recipientRecord(reader).CurrentBinding
			} else {
				binding = keys.RecipientSuccessor(t, reader)
			}
		case ReplacementTargetAuthority:
			binding = keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
		default:
			binding = keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
		}
		h.public.Encryption = &ReplacementEncryptionKey{Selector: binding.KeySelector, SPKI: binding.SPKI, Fingerprint: binding.Fingerprint, Profile: binding.WrapProfile, ProtectionClass: binding.ProtectionClass}
		h.goal.EncryptionSelector = binding.KeySelector
	}
	i := ReplacementInstallation{ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), ExpectedControl: before, PublicBasis: f.admission.admission.publicBasis(),
		Store: env.Store, CompositionID: f.session.admission.composition, FileIdentity: fixtureID(env.Domain, "installed replacement source file"), CloseInstalled: func() {}}
	// Complete local generated facts include an unselected pending row and a
	// duplicate reference to the target. Only the nominated first row may change.
	current := *f.session.recipientRecord(reader).CurrentBinding
	i.CapturedRecipients = []ReplacementRecipientFact{{RecipientID: reader, Encryption: current}, {RecipientID: reader, Encryption: current}, {RecipientID: fixtureID(env.Domain, "pending local recipient"), Encryption: current}}
	i.SourceUnchanged = func(context.Context) error {
		if h.changed {
			return errors.New("fixture source changed")
		}
		return nil
	}
	i.ResolvePublicGoal = func(_ context.Context, request ReplacementPublicRequest) (ReplacementPublicGoal, error) {
		h.publicCalls++
		if request.Provider != family || request.SigningSelector != h.goal.SigningSelector || request.EncryptionSelector != h.goal.EncryptionSelector {
			t.Fatal("public resolver changed goal")
		}
		return h.public, nil
	}
	i.ConstructSigners = func(_ context.Context, authorizer contract.PublicSigningBinding, successor *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
		h.signerFactories++
		expected := before.NormalSigning
		trust := env.Trust
		if approval == contract.RecoverySigningRole {
			expected = before.Recovery.Signing
			trust = env.Recovery
		}
		if !signingBindingEqual(expected, authorizer) {
			t.Fatal("private authorizer route changed")
		}
		signers := SuccessionSigners{Authorizer: trust}
		if successor != nil {
			if h.successor == nil || successor.KeySelector != h.public.Signing.Selector || !bytes.Equal(successor.SPKI, h.public.Signing.SPKI) {
				t.Fatal("successor signer changed")
			}
			if target == ReplacementTargetRecovery {
				signers.RecoverySuccessor = h.successor
			} else {
				signers.NormalSuccessor = h.successor
			}
		}
		return signers, func() { h.closedSigners++ }, nil
	}
	if target == ReplacementTargetRecipient {
		i.AdmitRecipientCustody = func(_ context.Context, q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, before contract.ControlCore, rows []contract.CompactRow, deadline time.Time) (*InstalledReplacementCustody, error) {
			h.custodyFactories++
			owner, err := keys.AdmitInstalledRecipientReplacement(q, intent, request, before, rows, deadline)
			if err != nil {
				return nil, err
			}
			return &InstalledReplacementCustody{Crypto: owner, Close: func() { owner.Close(); h.closedCustody++ }}, nil
		}
	} else if h.goal.EncryptionSelector != "" {
		i.AdmitSuccessionCustody = func(_ context.Context, q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, before contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, deadline time.Time) (*InstalledReplacementCustody, error) {
			h.custodyFactories++
			expected := before.AuthorityRecipientID
			if material == ReplacementMaterialRecovery {
				expected = before.Recovery.RoleID
			}
			if source.SubjectID != expected {
				t.Fatal("fixed surviving material route changed")
			}
			for _, row := range rows {
				if q.BindingTable[row.Coverage.SourceBindingIndex].SubjectID != expected {
					t.Fatal("coverage changed surviving source")
				}
			}
			owner, err := keys.AdmitInstalledSuccessionReplacement(q, request, before, source, probe, rows, deadline)
			if err != nil {
				return nil, err
			}
			return &InstalledReplacementCustody{Crypto: owner, Close: func() { owner.Close(); h.closedCustody++ }}, nil
		}
	}
	i.PublishSuccessor = func(ctx context.Context, out ReplacementSuccessor) (ReplacementReadback, error) {
		h.delivered++
		h.output = out
		if h.publish != nil {
			return h.publish(ctx, out)
		}
		control, err := out.Basis.ControlCore(env.Domain, env.Store.Descriptor())
		if err != nil {
			return ReplacementReadback{}, err
		}
		return ReplacementReadback{FileIdentity: i.FileIdentity, Control: control, Basis: out.Basis, Recipients: out.Recipients, Correlation: out.Correlation}, nil
	}
	h.installation = i
	return h
}
func (h *installedReplacementFixture) engine(t *testing.T) installedReplacementEngine {
	t.Helper()
	var e installedReplacementEngine
	var err error
	switch h.target {
	case ReplacementTargetAuthority:
		e, err = NewInstalledAuthorityReplacement(AuthorityReplacementInstallation{ReplacementInstallation: h.installation, Goal: h.goal})
	case ReplacementTargetRecovery:
		e, err = NewInstalledRecoveryReplacement(RecoveryReplacementInstallation{ReplacementInstallation: h.installation, Goal: h.goal})
	case ReplacementTargetRecipient:
		e, err = NewInstalledRecipientReplacement(RecipientReplacementInstallation{ReplacementInstallation: h.installation, RecipientID: h.recipient, RecipientRow: 0, EncryptionSelector: h.goal.EncryptionSelector})
	}
	if err != nil {
		t.Fatal("installed replacement construction", err)
	}
	t.Cleanup(e.Close)
	return e
}

// full_only: false
func TestInstalledReplacementMatrixUsesOnlyFixedCapabilities(t *testing.T) {
	cases := []struct {
		name           string
		target         ReplacementTarget
		mask, approval uint8
		material       ReplacementMaterialSource
	}{
		{"authority signer normal", ReplacementTargetAuthority, 1, 1, 0},
		{"authority signer recovery", ReplacementTargetAuthority, 1, 2, 0},
		{"authority encryption authority source", ReplacementTargetAuthority, 2, 1, ReplacementMaterialAuthority},
		{"authority encryption recovery source", ReplacementTargetAuthority, 2, 2, ReplacementMaterialRecovery},
		{"authority both independent approval source", ReplacementTargetAuthority, 3, 2, ReplacementMaterialAuthority},
		{"recovery signer normal", ReplacementTargetRecovery, 4, 1, 0},
		{"recovery signer recovery", ReplacementTargetRecovery, 4, 2, 0},
		{"recovery encryption authority source", ReplacementTargetRecovery, 8, 1, ReplacementMaterialAuthority},
		{"recovery encryption recovery source", ReplacementTargetRecovery, 8, 2, ReplacementMaterialRecovery},
		{"recovery both independent approval source", ReplacementTargetRecovery, 12, 1, ReplacementMaterialRecovery},
		{"recipient public only", ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority},
	}
	for _, family := range []contract.Family{contract.GCP, contract.AWS} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("family%d/%s", family, tc.name), func(t *testing.T) {
				h := newInstalledReplacementFixture(t, family, tc.target, tc.mask, tc.approval, tc.material)
				engine := h.engine(t)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				beforeCAS := h.env.Store.(*memoryStore).cas
				out := engine.Replace(ctx, testID("installed matrix request"))
				if out.Result.Outcome != ObservedCurrent || out.OperationID.IsZero() || out.RequestIdentity.IsZero() || out.DomainID != h.env.Domain || out.Payload == nil || out.NoWorkObservation != nil || h.delivered != 1 || h.publicCalls != 1 || h.signerFactories != 1 || h.closedSigners != 1 {
					t.Fatal("installed replacement did not produce exact selected result", out.Result, out.OperationID, out.RequestIdentity, h.delivered, h.publicCalls, h.signerFactories, h.closedSigners)
				}
				needsCustody := tc.mask&10 != 0 || tc.target == ReplacementTargetRecipient
				expectedCustody := 0
				if needsCustody {
					expectedCustody = 1
				}
				if h.custodyFactories != expectedCustody || h.closedCustody != expectedCustody || h.env.Store.(*memoryStore).cas != beforeCAS+1 {
					t.Fatal("replacement used unexpected custody or selection count")
				}
				if tc.target == ReplacementTargetAuthority {
					if len(out.Receipt) != 0 {
						t.Fatal("Authority succession invented retained receipt")
					}
				} else {
					receipt, err := contract.InspectCompactMutationReceipt(out.Receipt)
					kind := uint16(9)
					if tc.target == ReplacementTargetRecovery {
						kind = 36
					}
					if err != nil || receipt.OperationKind != kind || receipt.OperationID != out.OperationID || receipt.RequestIdentityDigest != out.RequestIdentity {
						t.Fatal("installed result receipt correlation", err)
					}
				}
				if !kmsBindingEqual(h.output.Recipients[1].Encryption, h.installation.CapturedRecipients[1].Encryption) || !kmsBindingEqual(h.output.Recipients[2].Encryption, h.installation.CapturedRecipients[2].Encryption) {
					t.Fatal("replacement changed duplicate or pending untargeted local facts")
				}
				admission, result := admitPublicNormal(ctx, h.env.Domain, h.env.Store.Descriptor(), h.output.Basis, h.env.Store, h.installation.CompositionID, nil)
				if result.Outcome != ObservedCurrent {
					t.Fatal("delivered basis could not admit cold reader", result)
				}
				selected, result := Open(ctx, admission, h.env.Store)
				if selected == nil || result.Outcome != ObservedCurrent || selected.head.Core.Revision != out.Result.RequestedRevision {
					t.Fatal("installed candidate not cold selected", result)
				}
				for _, name := range h.fixture.session.root.Names {
					before, _ := contract.EncodeValueEntry(*h.fixture.session.valueEntry(name.Slot))
					after, _ := contract.EncodeValueEntry(*selected.valueEntry(name.Slot))
					if !bytes.Equal(before, after) {
						t.Fatal("replacement changed immutable application entry")
					}
				}
				if again := engine.Replace(ctx, testID("reused installed parent")); again.Result.Outcome != AdmissionRefused {
					t.Fatal("one-use parent reused")
				}
			})
		}
	}
}

// full_only: false
func TestInstalledAuthorityReplacementNoWorkHasOnlyObservationIdentity(t *testing.T) {
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 0, 1, 0)
	before := currentControlOf(h.fixture.session)
	h.goal.SigningSelector = before.NormalSigning.KeySelector
	h.public.Signing = &ReplacementSigningKey{Selector: before.NormalSigning.KeySelector, SPKI: before.NormalSigning.SPKI, Fingerprint: before.NormalSigning.Fingerprint, Trust: before.NormalSigning.Binding.Trust, Profile: before.NormalSigning.SigningProfile}
	engine := h.engine(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	store := h.env.Store.(*memoryStore)
	beforeCAS := store.cas
	beforeSigns := h.env.Trust.(*fixtureTrust).Calls()
	out := engine.Replace(ctx, testID("authority current binding observation"))
	if out.Result.Outcome != Unchanged || out.NoWorkObservation == nil || out.OperationID.IsZero() || out.RequestIdentity.IsZero() || out.NoWorkObservation.OperationID != out.OperationID || out.NoWorkObservation.RequestIdentity != out.RequestIdentity || out.NoWorkObservation.RequestCoreDigest.IsZero() || out.Payload != nil || len(out.Receipt) != 0 || h.publicCalls != 1 || h.signerFactories != 0 || h.custodyFactories != 0 || h.delivered != 0 || store.cas != beforeCAS || h.env.Trust.(*fixtureTrust).Calls() != beforeSigns {
		t.Fatal("current binding observation allocated mutation work or omitted exact identity", out.Result, out.NoWorkObservation)
	}
}

// full_only: false
func TestInstalledAuthorityReplacementRecoversSignerWithoutLostRoute(t *testing.T) {
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 1, 2, 0)
	normal := h.env.Trust.(*fixtureTrust).Signer
	normal.SetUnavailable(true)
	before := normal.Calls()
	engine := h.engine(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	out := engine.Replace(ctx, testID("recovery signer replacement"))
	if out.Result.Outcome != ObservedCurrent || normal.Calls() != before || h.custodyFactories != 0 || h.signerFactories != 1 {
		t.Fatal("Recovery-only signer replacement touched lost Normal or KEK route", out.Result)
	}
}

// full_only: false
func TestInstalledReplacementRequiresExactDeliveredCandidateBeforeSelection(t *testing.T) {
	for _, condition := range []string{"callback failure", "candidate mismatch", "target mismatch", "recipient rows mismatch", "basis mismatch", "source changed", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h.publish = func(_ context.Context, out ReplacementSuccessor) (ReplacementReadback, error) {
				control, err := out.Basis.ControlCore(h.env.Domain, h.env.Store.Descriptor())
				if err != nil {
					return ReplacementReadback{}, err
				}
				read := ReplacementReadback{FileIdentity: h.installation.FileIdentity, Control: control, Basis: out.Basis, Recipients: out.Recipients, Correlation: out.Correlation}
				switch condition {
				case "callback failure":
					return ReplacementReadback{}, errors.New("fixture interrupted delivery")
				case "candidate mismatch":
					read.Correlation.SignedCandidate = bytes.Clone(read.Correlation.SignedCandidate)
					read.Correlation.SignedCandidate[len(read.Correlation.SignedCandidate)-1] ^= 1
				case "target mismatch":
					read.Correlation.Target = ReplacementTargetRecovery
				case "recipient rows mismatch":
					read.Recipients = append(slices.Clone(read.Recipients), read.Recipients[0])
				case "basis mismatch":
					read.Basis.Descriptor = bytes.Clone(read.Basis.Descriptor)
					if len(read.Basis.Descriptor) > 0 {
						read.Basis.Descriptor[0] ^= 1
					} else {
						read.Basis.Control = nil
					}
				case "source changed":
					h.changed = true
				case "cancelled":
					cancel()
				}
				return read, nil
			}
			engine := h.engine(t)
			before := h.env.Store.(*memoryStore).cas
			out := engine.Replace(ctx, testID("interrupted replacement delivery"))
			if out.Result.Outcome == ObservedCurrent || h.delivered != 1 || h.env.Store.(*memoryStore).cas != before {
				t.Fatal("unqualified output reached selection", out.Result, h.delivered)
			}
		})
	}
}

// full_only: false
func TestInstalledAuthorityReplacementPreservesEqualDeclaredRoleBindings(t *testing.T) {
	for _, equalSigning := range []bool{false, true} {
		t.Run(fmt.Sprintf("equal-signing-%t", equalSigning), func(t *testing.T) {
			mask := uint8(1)
			material := ReplacementMaterialAuthority
			if equalSigning {
				mask = 2
			}
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, mask, 1, material)
			before := currentControlOf(h.fixture.session)
			if equalSigning {
				h.goal.SigningSelector = before.NormalSigning.KeySelector
				h.public.Signing = &ReplacementSigningKey{Selector: before.NormalSigning.KeySelector, SPKI: before.NormalSigning.SPKI, Fingerprint: before.NormalSigning.Fingerprint, Trust: before.NormalSigning.Binding.Trust, Profile: before.NormalSigning.SigningProfile}
			} else {
				key := before.AuthorityKMSBinding
				h.goal.EncryptionSelector = key.KeySelector
				h.public.Encryption = &ReplacementEncryptionKey{Selector: key.KeySelector, SPKI: key.SPKI, Fingerprint: key.Fingerprint, Profile: key.WrapProfile, ProtectionClass: key.ProtectionClass}
				h.installation.AdmitSuccessionCustody = func(context.Context, contract.CryptoAccessReplaceRequest, contract.SuccessionRequestCore, contract.ControlCore, contract.BindingTableRow, contract.SuccessorKEKProbeCore, []contract.CompactRow, time.Time) (*InstalledReplacementCustody, error) {
					t.Fatal("equal declared KEK constructed custody")
					return nil, contract.ErrRecord
				}
			}
			engine := h.engine(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			out := engine.Replace(ctx, testID("partial current Authority role"))
			if out.Result.Outcome != ObservedCurrent {
				t.Fatal("partially equal Authority goal refused", out.Result)
			}
			if equalSigning {
				if !signingBindingEqual(h.output.Control.NormalSigning, before.NormalSigning) {
					t.Fatal("equal signing role acquired fresh IDs")
				}
			} else if !kmsBindingEqual(h.output.Control.AuthorityKMSBinding, before.AuthorityKMSBinding) {
				t.Fatal("equal KEK role acquired fresh IDs")
			}
		})
	}
}

// full_only: false
func TestInstalledRecoveryReplacementRequiresChangedMaterialForEveryDeclaredRole(t *testing.T) {
	for _, signing := range []bool{false, true} {
		t.Run(fmt.Sprintf("signing-%t", signing), func(t *testing.T) {
			mask := uint8(8)
			material := ReplacementMaterialAuthority
			if signing {
				mask = 4
				material = 0
			}
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecovery, mask, 1, material)
			before := currentControlOf(h.fixture.session).Recovery
			if signing {
				h.goal.SigningSelector = before.Signing.KeySelector
				h.public.Signing = &ReplacementSigningKey{Selector: before.Signing.KeySelector, SPKI: before.Signing.SPKI, Fingerprint: before.Signing.Fingerprint, Trust: before.Signing.Binding.Trust, Profile: before.Signing.SigningProfile}
			} else {
				key := before.KMS
				h.goal.EncryptionSelector = key.KeySelector
				h.public.Encryption = &ReplacementEncryptionKey{Selector: key.KeySelector, SPKI: key.SPKI, Fingerprint: key.Fingerprint, Profile: key.WrapProfile, ProtectionClass: key.ProtectionClass}
			}
			engine := h.engine(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			beforeCAS := h.env.Store.(*memoryStore).cas
			out := engine.Replace(ctx, testID("unchanged Recovery role refused"))
			if out.Result.Outcome != AdmissionRefused || !out.OperationID.IsZero() || !out.RequestIdentity.IsZero() || out.NoWorkObservation != nil || h.publicCalls != 1 || h.signerFactories != 0 || h.custodyFactories != 0 || h.delivered != 0 || h.env.Store.(*memoryStore).cas != beforeCAS {
				t.Fatal("unchanged Recovery role gained work or no-op identity", out.Result)
			}
		})
	}
}

// full_only: false
func TestInstalledRecipientReplacementRejectsFalseCapturedMappingsBeforeEffects(t *testing.T) {
	for _, name := range []string{"authority-target", "different-current-binding", "row-id-mismatch", "pending-unselected-recipient"} {
		t.Run(name, func(t *testing.T) {
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, contract.NormalSigningRole, ReplacementMaterialAuthority)
			sourceChecks := 0
			checkSource := h.installation.SourceUnchanged
			h.installation.SourceUnchanged = func(ctx context.Context) error {
				sourceChecks++
				return checkSource(ctx)
			}
			s := h.fixture.session
			recipient, row := h.recipient, uint16(0)
			switch name {
			case "authority-target":
				recipient = s.admission.recipient
				h.installation.CapturedRecipients[0] = ReplacementRecipientFact{RecipientID: recipient, Encryption: currentControlOf(s).AuthorityKMSBinding}
			case "different-current-binding":
				h.installation.CapturedRecipients[0].Encryption.BindingID = fixtureID(h.env.Domain, "different captured Recipient binding")
				if kmsBindingEqual(h.installation.CapturedRecipients[0].Encryption, *s.recipientRecord(recipient).CurrentBinding) {
					t.Fatal("fixture did not change the captured binding")
				}
			case "row-id-mismatch":
				row = 2
				if h.installation.CapturedRecipients[row].RecipientID == recipient {
					t.Fatal("fixture row still identifies the nominated Recipient")
				}
			case "pending-unselected-recipient":
				row = 2
				recipient = h.installation.CapturedRecipients[row].RecipientID
				if s.recipientRecord(recipient) != nil {
					t.Fatal("fixture pending Recipient is already selected")
				}
			}
			for _, fact := range h.installation.CapturedRecipients {
				body, err := contract.EncodeKMSBinding(fact.Encryption)
				if err != nil {
					t.Fatal("fixture captured binding is not canonical")
				}
				if _, err := contract.DecodeKMSBinding(body); err != nil {
					t.Fatal("fixture captured binding cannot be independently parsed")
				}
			}
			snapshot := func(value any) []byte {
				t.Helper()
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal("fixture snapshot failed")
				}
				return body
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			windows, err := s.receiptWindows(ctx)
			if err != nil {
				t.Fatal("fixture receipt windows unavailable")
			}
			beforeWindows := snapshot(windows)
			beforeState := sessionStateImage(t, s)
			beforeSource := snapshot(h.installation.CapturedRecipients)
			store := h.env.Store.(*memoryStore)
			beforeObjects := snapshot(store.objects)
			beforeHEAD := store.objects[store.desc.HeadKey]
			beforeHEAD.Body = bytes.Clone(beforeHEAD.Body)
			reads, creates, cas, generation := store.reads, store.creates, store.cas, store.generation
			public, private := h.keys.Calls()
			normalSigns := h.env.Trust.(*fixtureTrust).Calls()
			recoverySigns := h.env.Recovery.(*testtrust.Signer).Calls()
			engine, err := NewInstalledRecipientReplacement(RecipientReplacementInstallation{ReplacementInstallation: h.installation, RecipientID: recipient, RecipientRow: row, EncryptionSelector: h.goal.EncryptionSelector})
			if name == "row-id-mismatch" {
				if engine != nil || !errors.Is(err, contract.ErrRecord) || store.reads != reads || sourceChecks != 0 {
					t.Fatalf("row/ID mismatch did not refuse locally: reads=%d source-checks=%d", store.reads-reads, sourceChecks)
				}
			} else {
				if err != nil || engine == nil {
					t.Fatal("canonical false mapping did not reach installed selected-state admission")
				}
				t.Cleanup(engine.Close)
				request := testID("false captured Recipient mapping")
				out := engine.Replace(ctx, request)
				if out.Result != refused(AdmissionInvalid) || out.RequestID != request || out.DomainID != h.env.Domain || !out.OperationID.IsZero() || !out.RequestIdentity.IsZero() || out.Payload != nil || len(out.Receipt) != 0 || out.NoWorkObservation != nil || store.reads <= reads {
					t.Fatalf("false selected mapping returned evidence or missed public authentication: outcome=%d reason=%d evidence=%d reads=%d", out.Result.Outcome, out.Result.Reason, out.Result.Evidence, store.reads-reads)
				}
			}
			if h.publicCalls != 0 || h.signerFactories != 0 || h.custodyFactories != 0 || h.delivered != 0 || h.closedSigners != 0 || h.closedCustody != 0 {
				t.Fatalf("false mapping reached a replacement capability: public=%d signer=%d custody=%d delivered=%d", h.publicCalls, h.signerFactories, h.custodyFactories, h.delivered)
			}
			cold, result := Open(ctx, h.fixture.admission, h.env.Store)
			if cold == nil || result.Outcome != ObservedCurrent {
				t.Fatalf("false mapping changed selected readability: outcome=%d reason=%d", result.Outcome, result.Reason)
			}
			assertStateImage(t, s, beforeState)
			assertStateImage(t, cold, beforeState)
			afterWindows, err := cold.receiptWindows(ctx)
			if err != nil || !bytes.Equal(snapshot(afterWindows), beforeWindows) || !bytes.Equal(snapshot(h.installation.CapturedRecipients), beforeSource) || !bytes.Equal(snapshot(store.objects), beforeObjects) {
				t.Fatal("false mapping changed source facts, selected objects or complete receipt windows")
			}
			afterHEAD := store.objects[store.desc.HeadKey]
			p, k := h.keys.Calls()
			if afterHEAD.Token != beforeHEAD.Token || !bytes.Equal(afterHEAD.Body, beforeHEAD.Body) || store.creates != creates || store.cas != cas || store.generation != generation || p != public || k != private || h.env.Trust.(*fixtureTrust).Calls() != normalSigns || h.env.Recovery.(*testtrust.Signer).Calls() != recoverySigns {
				t.Fatalf("false mapping changed HEAD or used private/write effects: creates=%d cas=%d public=%d private=%d", store.creates-creates, store.cas-cas, p-public, k-private)
			}
		})
	}
}

// full_only: false
func TestInstalledRecipientReplacementAllowsEqualKeyWithFreshBinding(t *testing.T) {
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority, true)
	before := *h.fixture.session.recipientRecord(h.recipient).CurrentBinding
	engine := h.engine(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	public, private := h.keys.Calls()
	out := engine.Replace(ctx, testID("same public Recipient key fresh binding"))
	after := h.output.Recipients[0].Encryption
	p, k := h.keys.Calls()
	if out.Result.Outcome != ObservedCurrent || after.BindingID == before.BindingID || !contract.IncarnationCounterStep(before.BindingIncarnationID, before.BindingSerial, after.BindingIncarnationID, after.BindingSerial) || after.KeySelector != before.KeySelector || !bytes.Equal(after.SPKI, before.SPKI) || p != public+1 || k != private+1 {
		t.Fatal("equal Recipient key did not get fresh binding through Authority only", out.Result, p-public, k-private)
	}
}

type replacementQualifyingHook struct {
	contract.QualifyingTrust
	hook func(context.Context)
}

func (q replacementQualifyingHook) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	q.hook(ctx)
	return q.QualifyingTrust.QualifySigningBinding(ctx, binding)
}

// full_only: false
func TestInstalledReplacementPinsIndependentSourceAndGoal(t *testing.T) {
	for _, condition := range []string{"domain", "store", "control", "during public resolution", "during signer qualification", "fresh identity collision"} {
		t.Run(condition, func(t *testing.T) {
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 1, 1, 0)
			switch condition {
			case "domain":
				h.installation.ExpectedDomain = testID("other independent domain")
			case "store":
				h.installation.ExpectedStore.Identity = testID("other independent store")
			case "control":
				h.installation.ExpectedControl.NormalSigning.SPKI = bytes.Clone(h.installation.ExpectedControl.NormalSigning.SPKI)
				h.installation.ExpectedControl.NormalSigning.SPKI[0] ^= 1
			case "during public resolution":
				original := h.installation.ResolvePublicGoal
				h.installation.ResolvePublicGoal = func(ctx context.Context, q ReplacementPublicRequest) (ReplacementPublicGoal, error) {
					goal, err := original(ctx, q)
					h.changed = true
					return goal, err
				}
			case "during signer qualification":
				original := h.installation.ConstructSigners
				h.installation.ConstructSigners = func(ctx context.Context, a contract.PublicSigningBinding, b *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
					signers, close, err := original(ctx, a, b)
					signers.NormalSuccessor = replacementQualifyingHook{QualifyingTrust: signers.NormalSuccessor, hook: func(context.Context) { h.changed = true }}
					return signers, close, err
				}
			}
			beforeCAS := h.env.Store.(*memoryStore).cas
			beforeSigns := h.env.Trust.(*fixtureTrust).Calls()
			engine, err := NewInstalledAuthorityReplacement(AuthorityReplacementInstallation{ReplacementInstallation: h.installation, Goal: h.goal})
			if condition == "domain" || condition == "store" || condition == "control" {
				if err == nil {
					engine.Close()
					t.Fatal("mixed independent source admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			if condition == "fresh identity collision" {
				collision := h.fixture.session.head.Core.Revision
				engine.owner.entropy = bytes.NewReader(collision[:])
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			out := engine.Replace(ctx, testID("pinned replacement refusal"))
			if out.Result.Outcome == ObservedCurrent || h.env.Store.(*memoryStore).cas != beforeCAS || h.env.Trust.(*fixtureTrust).Calls() != beforeSigns || h.delivered != 0 {
				t.Fatal("changed source or reused identity reached authority/selection", out.Result)
			}
			if condition == "during public resolution" && h.signerFactories != 0 {
				t.Fatal("source mutation reached private construction")
			}
		})
	}
}

// full_only: false
func TestInstalledReplacementSendsOneCASAndObservesUnknownOutcome(t *testing.T) {
	for _, mode := range []string{"lost-after", "delayed"} {
		t.Run(mode, func(t *testing.T) {
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority)
			store := h.env.Store.(*memoryStore)
			store.casMode = mode
			before := store.cas
			engine := h.engine(t)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			out := engine.Replace(ctx, testID("one physical replacement CAS"))
			if store.cas != before+1 || h.delivered != 1 {
				t.Fatal("unknown selection repeated a physical send", store.cas-before, h.delivered)
			}
			if mode == "lost-after" {
				if out.Result.Outcome != ObservedCurrent || len(out.Receipt) != contract.CompactMutationReceiptLength {
					t.Fatal("exact authentic selected candidate not recovered", out.Result)
				}
			} else {
				if out.Result.Outcome != UnresolvedCommit || !out.Result.CommitMayHaveOccurred || len(out.Receipt) != 0 || out.Payload == nil || store.late == nil {
					t.Fatal("unknown predecessor observation lost possible effect", out.Result)
				}
				if err := store.late(); err != nil {
					t.Fatal(err)
				}
				admitted, result := admitPublicNormal(ctx, h.env.Domain, store.Descriptor(), h.output.Basis, store, h.installation.CompositionID, nil)
				if result.Outcome != ObservedCurrent {
					t.Fatal(result)
				}
				selected, result := Open(ctx, admitted, store)
				if selected == nil || result.Outcome != ObservedCurrent || selected.head.Subject.Operation != out.OperationID || store.cas != before+1 {
					t.Fatal("late exact candidate could not be authentically observed without resend", result)
				}
			}
		})
	}
}

// full_only: false
func TestInstalledReplacementCloseCancelsAndJoinsOwnedInvocation(t *testing.T) {
	h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 1, 1, 0)
	entered := make(chan struct{})
	original := h.installation.ConstructSigners
	h.installation.ConstructSigners = func(ctx context.Context, a contract.PublicSigningBinding, b *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
		signers, closeSigners, err := original(ctx, a, b)
		signers.NormalSuccessor = replacementQualifyingHook{QualifyingTrust: signers.NormalSuccessor, hook: func(ctx context.Context) { close(entered); <-ctx.Done() }}
		return signers, closeSigners, err
	}
	engine := h.engine(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	done := make(chan PublicReplacementResult, 1)
	go func() { done <- engine.Replace(ctx, testID("cancelled owned replacement")) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement qualification did not enter")
	}
	engine.Close()
	select {
	case out := <-done:
		if out.Result.Outcome == ObservedCurrent || h.closedSigners != 1 || h.delivered != 0 {
			t.Fatal("closed replacement retained active work", out.Result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not join owned invocation")
	}
	engine.Close()
}

// full_only: false
func TestInstalledReplacementValidatesSignerFactoriesBeforeCustody(t *testing.T) {
	for _, target := range []ReplacementTarget{ReplacementTargetAuthority, ReplacementTargetRecipient} {
		for _, damage := range []string{"nil authorizer", "wrong authorizer identity", "wrong authorizer family", "unused successor", "nil successor", "wrong successor identity", "wrong successor family"} {
			if target == ReplacementTargetRecipient && (damage == "nil successor" || damage == "wrong successor identity" || damage == "wrong successor family") {
				continue
			}
			t.Run(fmt.Sprintf("target%d/%s", target, damage), func(t *testing.T) {
				mask := uint8(3)
				if target == ReplacementTargetRecipient {
					mask = 0
				}
				h := newInstalledReplacementFixture(t, contract.GCP, target, mask, 1, ReplacementMaterialAuthority)
				original := h.installation.ConstructSigners
				h.installation.ConstructSigners = func(ctx context.Context, a contract.PublicSigningBinding, b *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
					signers, close, err := original(ctx, a, b)
					wrong := testtrust.New(t, contract.GCP, testID("wrong signer factory identity"))
					switch damage {
					case "nil authorizer":
						signers.Authorizer = nil
					case "wrong authorizer identity":
						signers.Authorizer = wrong
					case "wrong authorizer family":
						signers.Authorizer = testtrust.New(t, contract.AWS, a.Binding.Trust)
					case "unused successor":
						signers.RecoverySuccessor = h.env.Recovery.(*testtrust.Signer)
					case "nil successor":
						signers.NormalSuccessor = nil
					case "wrong successor identity":
						signers.NormalSuccessor = wrong
					case "wrong successor family":
						signers.NormalSuccessor = testtrust.New(t, contract.AWS, b.Binding.Trust)
					}
					return signers, close, err
				}
				engine := h.engine(t)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				public, private := h.keys.Calls()
				beforeCAS := h.env.Store.(*memoryStore).cas
				out := engine.Replace(ctx, testID("invalid signer factory before custody"))
				p, k := h.keys.Calls()
				if out.Result.Outcome != AdmissionRefused || h.signerFactories != 1 || h.closedSigners != 1 || h.custodyFactories != 0 || h.delivered != 0 || p != public || k != private || h.env.Store.(*memoryStore).cas != beforeCAS {
					t.Fatal("invalid signer factory reached private custody", out.Result, h.custodyFactories, p-public, k-private)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledRecipientReplacementRechecksAfterSignerConstruction(t *testing.T) {
	for _, damage := range []string{"source pins changed", "context cancelled"} {
		t.Run(damage, func(t *testing.T) {
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetRecipient, 0, 1, ReplacementMaterialAuthority)
			original := h.installation.ConstructSigners
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			h.installation.ConstructSigners = func(ctx context.Context, a contract.PublicSigningBinding, b *contract.PublicSigningBinding) (SuccessionSigners, func(), error) {
				signers, close, err := original(ctx, a, b)
				if damage == "source pins changed" {
					h.changed = true
				} else {
					cancel()
				}
				return signers, close, err
			}
			engine := h.engine(t)
			public, private := h.keys.Calls()
			store := h.env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			out := engine.Replace(ctx, testID("recipient pre-custody source guard"))
			p, k := h.keys.Calls()
			if out.Result.Outcome != AdmissionRefused || h.signerFactories != 1 || h.closedSigners != 1 || h.custodyFactories != 0 || h.delivered != 0 || p != public || k != private || store.creates != creates || store.cas != cas {
				t.Fatal("changed signer-construction boundary reached custody or writes", out.Result, h.custodyFactories, p-public, k-private)
			}
		})
	}
}
