package core

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

func genesisEnvironment(t testing.TB, family contract.Family, recovery bool, recipientCount ...int) (fixtureEnvironment, *custody.Fixture) {
	t.Helper()
	if len(recipientCount) > 1 || len(recipientCount) == 1 && (recipientCount[0] < 2 || recipientCount[0] > contract.CryptoMaxRecipients) {
		t.Fatal("invalid genesis fixture recipient count")
	}
	env := memoryScenarioEnvironment(t)
	store := env.Store.(*memoryStore)
	store.configure(t, family, env.Domain)
	normal := &fixtureTrust{Signer: testtrust.New(t, family, testID("trust"))}
	env.Trust = normal
	env.PublicKey = normal.PublicKey()
	env.SigningSelector = normal.KeySelector()
	recipients := []contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")}
	if len(recipientCount) == 1 {
		for i := 2; i < recipientCount[0]; i++ {
			recipients = append(recipients, fixtureID(env.Domain, fmt.Sprintf("reader-%03d", i)))
		}
	}
	keys := custody.New(t, family, fixtureID(env.Domain, "custody"), recovery, recipients)
	env.Bindings = keys.Bindings()
	env.Crypto = keys.Crypto()
	env.AdmitInit = keys.AdmitInit
	env.RetireInit = keys.RetireInit
	env.Custody = keys
	if recovery {
		r := testtrust.NewRecovery(t, family, testID("recovery-trust"))
		env.Recovery = r
		env.RecoveryPublicKey = r.PublicKey()
		env.RecoverySelector = r.KeySelector()
	}
	env.FreshOpen = func(t testing.TB, want stateImage) {
		checkFreshProcess(t, &fixture{store: store, trust: normal, admission: fixtureAdmission(env)}, want)
	}
	env.FreshCurrent = func(t testing.TB, _ OpenContext, selected *StateSession) {
		checkFreshGeneratedProcess(t, store, selected)
	}
	return env, keys
}

// full_only: false
func TestCoreOriginalContextRefusesBeforeAdmissionAndEffects(t *testing.T) {
	for _, mode := range []string{"off", "metrics", "recorder"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/recovery=%t", mode, recovery), func(t *testing.T) {
				valid := context.Background()
				if mode == "metrics" {
					valid, _, _ = coreTelemetryReader(t)
				}
				if mode == "recorder" {
					valid = telemetry.WithCapability(valid, telemetry.NewCapability(nil, telemetry.NewRecorder()))
				}
				cancelled, cancel := context.WithCancel(valid)
				cancel()
				invalid := []context.Context{nil, cancelled}
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				admitted := fixtureAdmission(env)
				init, _ := fixtureInitAdmission(t, env, admitted)
				store := env.Store.(*memoryStore)
				reads, creates, cas := store.reads, store.creates, store.cas
				public, private := keys.Calls()
				for _, ctx := range invalid {
					if selected, result := Initialize(ctx, init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto); selected != nil || result != refused(AdmissionInvalid) || init.admission.used {
						t.Fatal("invalid original context consumed initialization", result)
					}
				}
				gotPublic, gotPrivate := keys.Calls()
				if store.reads != reads || store.creates != creates || store.cas != cas || gotPublic != public || gotPrivate != private {
					t.Fatal("invalid initialization reached Store or Crypto")
				}
				s, result := Initialize(valid, init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
				if s == nil || result.Outcome != ObservedCurrent {
					t.Fatal("valid initialization after context refusal", result)
				}
				keys.RetireInit()
				reads = store.reads
				for _, ctx := range invalid {
					if opened, result := Open(ctx, admitted, env.Store); opened != nil || result != refused(AdmissionInvalid) {
						t.Fatal("invalid original context reached Open", result)
					}
				}
				if store.reads != reads {
					t.Fatal("invalid Open read Store")
				}
				s, result = Open(valid, admitted, env.Store)
				if s == nil || result.Outcome != ObservedCurrent {
					t.Fatal("valid Open after context refusal", result)
				}
				desiredEntries := []ApplyEntryInput{{Name: "alpha", Recipients: []contract.ID{admitted.admission.recipient}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte("x")}}
				for _, ctx := range invalid {
					if comparison, result := s.Compare(ctx, desiredEntries, nil); comparison != nil || result != refused(AdmissionInvalid) {
						t.Fatal("invalid original context reached Compare", result)
					}
				}
				comparison, result := s.Compare(valid, desiredEntries, admitSuppliedComparison(t, s, nil, desiredEntries))
				if comparison == nil || result.Outcome != ObservedCurrent {
					t.Fatal("valid Compare after context refusal", result)
				}
				permit := admit(t, s, comparison)
				for _, ctx := range invalid {
					if candidate, result := s.Prepare(ctx, comparison, permit, env.Trust); candidate != nil || result != refused(AdmissionInvalid) || permit.used || s.prepared {
						t.Fatal("invalid original context consumed preparation", result)
					}
				}
				candidate, result := s.Prepare(valid, comparison, permit, env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("valid Prepare after context refusal", result)
				}
				reads = store.reads
				public, private = keys.Calls()
				for _, ctx := range invalid {
					if prepared, outcome := s.PrepareRecipientReplacement(ctx, nil, env.Trust); prepared != nil || outcome != refused(AdmissionInvalid) {
						t.Fatal("invalid original context reached reader replacement", outcome)
					}
					if prepared, outcome := s.PrepareSuccession(ctx, nil, SuccessionSigners{}); prepared != nil || outcome != refused(AdmissionInvalid) {
						t.Fatal("invalid original context reached succession", outcome)
					}
					if body, outcome := s.MutationReceipt(ctx, testID("context receipt")); body != nil || outcome != refused(AdmissionInvalid) {
						t.Fatal("invalid original context reached receipt", outcome)
					}
				}
				gotPublic, gotPrivate = keys.Calls()
				if store.reads != reads || gotPublic != public || gotPrivate != private {
					t.Fatal("invalid original context reached Store or Crypto")
				}
				cas = store.cas
				for _, ctx := range invalid {
					if result := s.Select(ctx, candidate); result != refused(AdmissionInvalid) || candidate.used {
						t.Fatal("invalid original context consumed selection", result)
					}
				}
				if store.cas != cas || s.Select(valid, candidate).Outcome != ObservedCurrent {
					t.Fatal("invalid Select changed Store or blocked valid selection")
				}
			})
		}
	}
}

type genesisQualificationTrust struct {
	contract.QualifyingTrust
	alter func(contract.SigningQualificationResult) contract.SigningQualificationResult
}

type genesisCryptoProxy struct {
	contract.Crypto
	id                  contract.ID
	changeAfterExchange bool
	calls               int
}

func (p *genesisCryptoProxy) InstanceID() contract.ID { return p.id }

func (p *genesisCryptoProxy) Exchange(ctx context.Context, request contract.CryptoRequest) contract.CryptoResponse {
	p.calls++
	reply := p.Crypto.Exchange(ctx, request)
	if p.changeAfterExchange {
		p.id = testID("genesis crypto changed identity")
	}
	return reply
}

// full_only: false
func TestInternalGenesisUsesOnlyAdmittedCryptoCapability(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, recovery)
			init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
			store := env.Store.(*memoryStore)
			other := custody.New(t, contract.GCP, testID("different honest init runtime"), recovery,
				[]contract.ID{fixtureID(env.Domain, "recipient"), fixtureID(env.Domain, "reader")})
			spoof := &genesisCryptoProxy{Crypto: env.Crypto, id: env.Crypto.InstanceID()}
			for _, adapter := range []contract.Crypto{other.Crypto(), spoof} {
				if selected, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, adapter); selected != nil || result != refused(AdmissionInvalid) || init.admission.used {
					t.Fatal("nonadmitted Crypto capability reached genesis", result)
				}
			}
			if spoof.calls != 0 || store.reads != 0 || store.creates != 0 || store.cas != 0 {
				t.Fatal("substitute Crypto reached dependencies")
			}
			if selected, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto); selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("retained admitted Crypto could not initialize", result)
			}
			keys.RetireInit()
		})
		t.Run(fmt.Sprintf("changed-after-exchange/recovery=%t", recovery), func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, recovery)
			proxy := &genesisCryptoProxy{Crypto: env.Crypto, id: env.Crypto.InstanceID(), changeAfterExchange: true}
			env.Crypto = proxy
			init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
			store := env.Store.(*memoryStore)
			selected, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, proxy)
			if selected != nil || result != refused(AdmissionInvalid) || proxy.calls != 1 || store.creates != 0 || store.cas != 0 {
				t.Fatal("changed Crypto identity reached genesis selection", result)
			}
			keys.RetireInit()
		})
	}
}

func (t genesisQualificationTrust) QualifySigningBinding(ctx context.Context, binding contract.PublicSigningBinding) contract.SigningQualificationResult {
	return t.alter(t.QualifyingTrust.QualifySigningBinding(ctx, binding))
}

// full_only: false
func TestInternalGenesisSigningQualificationOutcomes(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, role := range []string{"normal", "recovery"} {
			for _, tc := range []struct {
				name  string
				alter func(contract.SigningQualificationResult) contract.SigningQualificationResult
				want  Result
			}{
				{"access", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: contract.ReasonAccess}
				}, failure(EvidenceUnavailable, SigningUnavailable)},
				{"transport", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: contract.ReasonTransport}
				}, failure(EvidenceUnavailable, SigningUnavailable)},
				{"limit", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: contract.ReasonLimit}
				}, failure(EvidenceUnavailable, SigningUnavailable)},
				{"proof", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: contract.ReasonProof}
				}, failure(IntegrityFailure, InvalidProof)},
				{"malformed", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: contract.ReasonMalformed}
				}, failure(IntegrityFailure, InvalidProof)},
				{"construction", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: contract.ReasonConstruction}
				}, failure(IntegrityFailure, InvalidProof)},
				{"missing-reason", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{}
				}, failure(IntegrityFailure, InvalidProof)},
				{"unknown-reason", func(contract.SigningQualificationResult) contract.SigningQualificationResult {
					return contract.SigningQualificationResult{Reason: 255}
				}, failure(IntegrityFailure, InvalidProof)},
				{"invalid-qualified", func(q contract.SigningQualificationResult) contract.SigningQualificationResult {
					q.Qualified = 2
					q.Reason = contract.ReasonAccess
					return q
				}, failure(IntegrityFailure, InvalidProof)},
				{"success-with-error", func(q contract.SigningQualificationResult) contract.SigningQualificationResult {
					q.Reason = contract.ReasonAccess
					return q
				}, failure(IntegrityFailure, InvalidProof)},
				{"wrong-target", func(q contract.SigningQualificationResult) contract.SigningQualificationResult {
					q.TargetRole = 2
					return q
				}, failure(IntegrityFailure, InvalidProof)},
				{"wrong-digest", func(q contract.SigningQualificationResult) contract.SigningQualificationResult {
					q.SigningBindingDigest[0] ^= 1
					return q
				}, failure(IntegrityFailure, InvalidProof)},
				{"wrong-provider", func(q contract.SigningQualificationResult) contract.SigningQualificationResult {
					q.Provider = 3
					return q
				}, failure(IntegrityFailure, InvalidProof)},
			} {
				t.Run(fmt.Sprintf("%d/%s/%s", family, role, tc.name), func(t *testing.T) {
					env, keys := genesisEnvironment(t, family, role == "recovery")
					init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
					normal, recovery := env.Trust.(contract.QualifyingTrust), env.Recovery
					if role == "normal" {
						normal = genesisQualificationTrust{QualifyingTrust: normal, alter: tc.alter}
					} else {
						recovery = genesisQualificationTrust{QualifyingTrust: recovery, alter: tc.alter}
					}
					s, result := Initialize(context.Background(), init, env.Store, normal, recovery, env.Crypto)
					public, private := keys.Calls()
					store := env.Store.(*memoryStore)
					if s != nil || result != tc.want || public != 0 || private != 0 || store.creates != 0 || store.cas != 0 || env.Trust.(*fixtureTrust).signs != 0 {
						t.Fatalf("signing qualification result=%+v want=%+v; custody=%d/%d creates=%d CAS=%d", result, tc.want, public, private, store.creates, store.cas)
					}
				})
			}
		}
	}
}

// full_only: false
func TestInternalEmptyGenesisAndPublicReopen(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprint(family)+map[bool]string{false: "/disabled", true: "/enabled"}[recovery], func(t *testing.T) {
				ctx, reader, _ := coreTelemetryReader(t)
				env, keys := genesisEnvironment(t, family, recovery)
				admitted := fixtureAdmission(env)
				init, p := fixtureInitAdmission(t, env, admitted)
				s, res := Initialize(ctx, init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
				if s == nil || res.Outcome != ObservedCurrent || s.head.AuthKind != format.GenesisAuth || s.head.Core.Form != format.GenesisHead || s.root.ValueEntryCount != 0 || s.root.RecipientCount != 2 || !sameGenesisPreparation(s, p) {
					t.Fatalf("genesis: %+v", res)
				}
				data := coreTelemetrySnapshot(t, reader)
				if coreMetricSum(data, "enkv.operation.calls", "core.initialize", "") != 1 || coreMetricSum(data, "enkv.operation.results", "core.initialize", "observed_current") != 1 {
					t.Fatal("successful initialization telemetry missing")
				}
				pub, private := keys.Calls()
				if pub != 2+boolInt(recovery) || private != 1+boolInt(recovery) {
					t.Fatalf("qualification calls: public=%d private=%d", pub, private)
				}
				normal := env.Trust.(*fixtureTrust)
				normal.SetUnavailable(true)
				if env.Recovery != nil {
					env.Recovery.(*testtrust.Signer).SetUnavailable(true)
				}
				keys.SetUnavailable(true)
				beforeSign := normal.signs
				store := env.Store.(*memoryStore)
				beforeCreate, beforeCAS := store.creates, store.cas
				reopened, res := Open(ctx, admitted, env.Store)
				if reopened == nil || res.Outcome != ObservedCurrent || reopened.head.Core != s.head.Core {
					t.Fatalf("public reopen: %+v", res)
				}
				afterPub, afterPrivate := keys.Calls()
				if afterPub != pub || afterPrivate != private || normal.signs != beforeSign || store.creates != beforeCreate || store.cas != beforeCAS {
					t.Fatal("public reopen used signing, private custody or writes")
				}
				if _, res := Initialize(ctx, init, env.Store, normal, env.Recovery, env.Crypto); res.Outcome != AdmissionRefused || res.Reason != AdmissionInvalid {
					t.Fatal("one-use init reused", res)
				}
			})
		}
	}
}

// full_only: false
func TestInternalEmptyGenesisLostRepliesAndNoModeChange(t *testing.T) {
	t.Run("lost-create-replies", func(t *testing.T) {
		env, _ := genesisEnvironment(t, contract.GCP, false)
		store := env.Store.(*memoryStore)
		store.createMode = "lost-after"
		admitted := fixtureAdmission(env)
		init, _ := fixtureInitAdmission(t, env, admitted)
		s, res := Initialize(context.Background(), init, store, env.Trust.(contract.QualifyingTrust), nil, env.Crypto)
		// Genesis writes the helper, recipient, configuration and receipt-index
		// pages, index, root and HEAD.
		const creates = 1 + 1 + 1 + 1 + 1 + 1 + 1
		if s == nil || res.Outcome != ObservedCurrent || store.cas != 0 || store.creates != creates {
			t.Fatalf("lost reply: %+v create=%d CAS=%d", res, store.creates, store.cas)
		}
	})
	t.Run("recovery-unavailable", func(t *testing.T) {
		env, keys := genesisEnvironment(t, contract.GCP, true)
		keys.SetDenied(keys.RecoveryID(), true)
		admitted := fixtureAdmission(env)
		init, _ := fixtureInitAdmission(t, env, admitted)
		s, res := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
		store := env.Store.(*memoryStore)
		if s != nil || res.Outcome != EvidenceUnavailable || store.creates != 0 || store.cas != 0 {
			t.Fatalf("failed recovery changed mode or selected: %+v", res)
		}
	})
}

// full_only: false
func TestInternalEmptyGenesisRefusesMissingDurability(t *testing.T) {
	env, _ := genesisEnvironment(t, contract.GCP, false)
	admitted := fixtureAdmission(env)
	init, _ := fixtureInitAdmission(t, env, admitted)
	init.admission.manifest = artifactReceipt{}
	store := env.Store.(*memoryStore)
	if s, res := Initialize(context.Background(), init, store, env.Trust.(contract.QualifyingTrust), nil, env.Crypto); s != nil || res.Outcome != AdmissionRefused || store.reads != 0 || store.creates != 0 {
		t.Fatal("public durability fields created admission", res)
	}
}

// full_only: false
func TestInternalGenesisThenPlainLifecycle(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprint(family)+map[bool]string{false: "/disabled", true: "/enabled"}[recovery], func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, family, recovery)
				sizes := make([]int, 33)
				for i := range sizes {
					sizes[i] = 1
				}
				f := newEnvironmentFixture(t, ctx, env, sizes, true)
				if f.session.root.ValueEntryCount != 33 || f.session.root.RawBytes != 33 || f.session.root.RecipientCount != 2 {
					t.Fatal("plain fixture totals differ")
				}
				occupied := make(map[uint16]bool, 33)
				for i := range sizes {
					occupied[uint16((i%32)*16+i/32)] = true
				}
				for _, name := range f.session.root.Names {
					if !occupied[name.Slot] {
						t.Fatal("plain fixture did not preserve the spread slot set")
					}
					delete(occupied, name.Slot)
				}
				if len(occupied) != 0 {
					t.Fatal("spread fixture omitted a slot")
				}
				public, private := keys.Calls()
				keys.SetUnavailable(true)
				before := observeSelectedState(t, f.session)
				input := before.entryInputs()
				input[0].InputBytes = append(input[0].InputBytes, 99)
				comparison, result := f.session.Compare(ctx, input, admitSuppliedComparison(t, f.session, nil, input))
				if comparison == nil {
					t.Fatal(result)
				}
				permit, inputs := admitTransition(t, f.session, comparison)
				want := expectedSuccessorImage(t, before, input, inputs)
				candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust)
				if candidate == nil {
					t.Fatal(result)
				}
				if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal(result)
				}
				env.Trust.(*fixtureTrust).SetUnavailable(true)
				if env.Recovery != nil {
					env.Recovery.(*testtrust.Signer).SetUnavailable(true)
				}
				current, result := Open(ctx, f.admission, env.Store)
				if current == nil {
					t.Fatal(result)
				}
				assertStateImage(t, current, want)
				if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
					t.Fatal("plain lifecycle or reopen used private custody")
				}
			})
		}
	}
}

// full_only: false
func TestInternalEmptyGenesisSingleRecipient(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", family, recovery), func(t *testing.T) {
				env, _ := genesisEnvironment(t, family, recovery)
				keys := custody.New(t, family, fixtureID(env.Domain, "custody"), recovery, []contract.ID{fixtureID(env.Domain, "recipient")})
				env.Bindings, env.Crypto, env.Custody = keys.Bindings(), keys.Crypto(), keys
				env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
				f := newEnvironmentFixture(t, context.Background(), env, nil, false)
				if f.session.root.RecipientCount != 1 || f.session.root.ValueEntryCount != 0 {
					t.Fatal("single-recipient empty domain differs")
				}
				keys.SetUnavailable(true)
				s, result := Open(context.Background(), f.admission, env.Store)
				if s == nil || result.Outcome != ObservedCurrent || s.root.RecipientCount != 1 {
					t.Fatal("single-recipient public reopen", result)
				}
			})
		}
	}
}

// full_only: false
func TestInternalGenesisQualificationUsesMatchProvider(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		expected := uint32(2)
		if family == contract.GCP {
			expected = 3
		}
		for _, recovery := range []bool{false, true} {
			for count := uint32(0); count <= expected+1; count++ {
				t.Run(fmt.Sprintf("%d/%t/%d", family, recovery, count), func(t *testing.T) {
					env, keys := genesisEnvironment(t, family, recovery)
					keys.SetQualificationUses(count)
					admitted := fixtureAdmission(env)
					init, _ := fixtureInitAdmission(t, env, admitted)
					s, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
					store := env.Store.(*memoryStore)
					if count == expected {
						if s == nil || result.Outcome != ObservedCurrent {
							t.Fatal("exact provider qualification facts were refused", result)
						}
						return
					}
					if s != nil || result.Outcome != EvidenceUnavailable || store.creates != 0 || store.cas != 0 {
						t.Fatal("inexact provider qualification facts reached dependent writes", result)
					}
				})
			}
		}
	}
}

// full_only: false
func TestInternalGenesisRejectsIncompleteSuccessfulKeyUseFactsBeforeWrites(t *testing.T) {
	cases := map[string]func(contract.CryptoResponse) contract.CryptoResponse{
		"missing-nonauthority-public": func(r contract.CryptoResponse) contract.CryptoResponse {
			var authorityBinding contract.ID
			for _, row := range r.KeyUseRows {
				if row.Purpose == contract.KeyUsePrivateRoleProbe && row.SubjectKind == 1 {
					authorityBinding = row.BindingID
				}
			}
			r.KeyUseRows = slices.DeleteFunc(r.KeyUseRows, func(row contract.KeyUseRow) bool {
				return row.Purpose == contract.KeyUsePublicKeyRead && row.SubjectKind == 1 && row.BindingID != authorityBinding
			})
			return r
		},
		"missing-authority-public": func(r contract.CryptoResponse) contract.CryptoResponse {
			removed := false
			r.KeyUseRows = slices.DeleteFunc(r.KeyUseRows, func(row contract.KeyUseRow) bool {
				if !removed && row.Purpose == contract.KeyUsePublicKeyRead && row.SubjectKind == 1 {
					removed = true
					return true
				}
				return false
			})
			return r
		},
		"missing-authority-probe": func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows = slices.DeleteFunc(r.KeyUseRows, func(row contract.KeyUseRow) bool {
				return row.Purpose == contract.KeyUsePrivateRoleProbe && row.SubjectKind == 1
			})
			return r
		},
		"missing-recovery-probe": func(r contract.CryptoResponse) contract.CryptoResponse {
			r.KeyUseRows = slices.DeleteFunc(r.KeyUseRows, func(row contract.KeyUseRow) bool {
				return row.Purpose == contract.KeyUsePrivateRoleProbe && row.SubjectKind == 2
			})
			return r
		},
		"excess-public": func(r contract.CryptoResponse) contract.CryptoResponse {
			for i := range r.KeyUseRows {
				if r.KeyUseRows[i].Purpose == contract.KeyUsePublicKeyRead {
					r.KeyUseRows[i].Count++
					break
				}
			}
			return r
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			changed := &changedCryptoReply{inner: env.Crypto, kind: contract.CryptoQualifyInitKeys, change: change}
			env.Crypto = changed
			admitted := fixtureAdmission(env)
			init, _ := fixtureInitAdmission(t, env, admitted)
			s, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, changed)
			store := env.Store.(*memoryStore)
			if s != nil || result != failure(IntegrityFailure, InvalidProof) || changed.calls != 1 || store.creates != 0 || store.cas != 0 {
				t.Fatal("incomplete successful qualification reached dependent writes", result)
			}
			public, private := keys.Calls()
			if public != 3 || private != 2 {
				t.Fatal("response damage changed custody execution", public, private)
			}
		})
	}
}

// full_only: false
func TestInternalEmptyGenesisAtRecipientCapacity(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", family, recovery), func(t *testing.T) {
				env, _ := genesisEnvironment(t, family, recovery)
				recipients := make([]contract.ID, 256)
				recipients[0] = fixtureID(env.Domain, "recipient")
				for i := 1; i < len(recipients); i++ {
					recipients[i] = fixtureID(env.Domain, fmt.Sprintf("reader-%03d", i))
				}
				keys := custody.New(t, family, fixtureID(env.Domain, "capacity-custody"), recovery, recipients)
				env.Bindings, env.Crypto, env.Custody = keys.Bindings(), keys.Crypto(), keys
				env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
				store := env.Store.(*memoryStore)
				normal := env.Trust.(*fixtureTrust)
				env.FreshOpen = func(t testing.TB, want stateImage) {
					checkFreshProcess(t, &fixture{store: store, trust: normal, admission: fixtureAdmission(env)}, want)
				}
				admitted := fixtureAdmission(env)
				init, _ := fixtureInitAdmission(t, env, admitted)
				s, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
				if s == nil || result.Outcome != ObservedCurrent || s.root.RecipientCount != 256 {
					t.Fatal("maximum-recipient genesis failed", result)
				}
				env.FreshOpen(t, sessionStateImage(t, s))
			})
		}
	}
}

// full_only: false
func TestNormalProspectiveConfigurationRequiresExactFacts(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	input := append(f.session.currentEntryInputs(), sharingSecret(t, env, "planning boundary", []contract.ID{f.session.admission.recipient}))
	parent := admitSuppliedComparison(t, f.session, keys, input)
	c, result := f.session.Compare(ctx, input, parent)
	if c == nil {
		t.Fatal("compare", result)
	}
	p, err := planTransition(t.Context(), c)
	if err != nil {
		t.Fatal("plan")
	}
	if result := f.session.prepareCompared(ctx, c, p); result.Outcome != 0 {
		t.Fatal("prepare", result)
	}
	next, err := f.session.deriveSuccessor(ctx, c, p)
	if err != nil {
		t.Fatal("derive", err)
	}
	_, selectedErr := next.selectedNormalSupportRows()
	_, projectionErr := next.prospectiveNormalPublicState(c, p)
	if projectionErr != nil {
		t.Fatal("prospective public projection refused", projectionErr)
	}
	if selectedErr == nil || next.selectedOutputComplete() || next.publicationProof != nil {
		t.Fatal("provisional support gained complete selected authority")
	}
	if _, err := next.normalCapacityUsage(ctx, c); err != nil {
		t.Fatal("healthy prospective capacity census refused")
	}
	for _, damage := range []string{"missing facts", "changed ref", "changed configuration"} {
		t.Run(damage, func(t *testing.T) {
			bad := *next
			switch damage {
			case "missing facts":
				bad.supportFacts = nil
			case "changed ref":
				bad.root.RequiredSupport = slices.Clone(next.root.RequiredSupport)
				bad.root.RequiredSupport[0].Digest[0] ^= 1
			case "changed configuration":
				bad.root.OutputConfiguration.ConfigurationDigest[0] ^= 1
			}
			if _, err := bad.prospectiveNormalPublicState(c, p); err == nil {
				t.Fatal("prospective projection admitted damaged source relation")
			}
			if _, err := bad.normalCapacityUsage(ctx, c); err == nil {
				t.Fatal("prospective capacity admitted damaged source relation")
			}
			if !f.session.selectedOutputComplete() {
				t.Fatal("refused planning changed predecessor proof")
			}
		})
	}
}

// full_only: false
func TestSuccessionPreservesBorrowedConfiguration(t *testing.T) {
	ctx := context.Background()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	s := f.session
	store := env.Store.(*memoryStore)
	want, err := s.preservedState(ctx, contract.SuccessionChangeNormalSigner, false)
	if err != nil {
		t.Fatal(err)
	}
	backed := *s
	backed.support = slices.Clone(s.support)
	for i, ref := range s.root.RequiredSupport {
		key, err := format.Key(s.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		read := store.Read(ctx, key, ref.Length)
		if read.Status != contract.ReadOK {
			t.Fatal("fixture page read", read.Status)
		}
		view, err := format.InspectRequiredSupportPage(read.Body)
		if err != nil {
			t.Fatal(err)
		}
		backed.support[i] = view
	}
	got, err := backed.preservedState(ctx, contract.SuccessionChangeNormalSigner, false)
	if err != nil || got != want {
		t.Fatal("borrowed configuration differs from exact body-backed projection", err)
	}
	for _, damage := range []string{"changed ref", "wrong ordinal", "changed read", "missing read", "unavailable read", "cancelled"} {
		t.Run(damage, func(t *testing.T) {
			bad := *s
			readContext := ctx
			switch damage {
			case "changed ref":
				bad.root.RequiredSupport = slices.Clone(s.root.RequiredSupport)
				bad.root.RequiredSupport[0].Digest[0] ^= 1
			case "wrong ordinal":
				bad.supportFacts = slices.Clone(s.supportFacts)
				page, logical := -1, -1
				for i, facts := range s.supportFacts {
					for j, row := range facts.rows {
						if row.Kind() == contract.OutputConfigurationSliceSupportKind {
							page, logical = i, j
							break
						}
					}
					if page >= 0 {
						break
					}
				}
				if page < 0 || logical >= len(s.supportFacts[page].ordinals) {
					t.Fatal("fixture lacks an output configuration ordinal")
				}
				bad.supportFacts[page].ordinals = slices.Clone(s.supportFacts[page].ordinals)
				bad.supportFacts[page].ordinals[logical]++
			case "changed read", "missing read", "unavailable read":
				store.readHook = func(_ string, read contract.ReadResult) contract.ReadResult {
					if damage == "missing read" {
						return contract.ReadResult{Status: contract.ReadMissing}
					}
					if damage == "unavailable read" {
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
					}
					read.Body = slices.Clone(read.Body)
					read.Body[len(read.Body)-1] ^= 1
					return read
				}
				t.Cleanup(func() { store.readHook = nil })
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				readContext = cancelled
			}
			if _, err := bad.preservedState(readContext, contract.SuccessionChangeNormalSigner, false); err == nil {
				t.Fatal("damaged borrowed configuration admitted")
			}
			for _, page := range s.support {
				for _, row := range page.Records {
					if row.Kind == contract.OutputConfigurationSliceSupportKind && row.Body != nil {
						t.Fatal("configuration body retained")
					}
				}
			}
			if !s.selectedOutputComplete() {
				t.Fatal("refusal changed predecessor proof")
			}
		})
	}
}

type cancelledQualificationTrust struct {
	contract.QualifyingTrust
	cancel context.CancelFunc
}

func (q cancelledQualificationTrust) QualifySigningBinding(ctx context.Context, b contract.PublicSigningBinding) contract.SigningQualificationResult {
	result := q.QualifyingTrust.QualifySigningBinding(ctx, b)
	q.cancel()
	return result
}

// full_only: false
func TestInternalGenesisSigningCancellationAfterQualifiedReply(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, role := range []string{"normal", "recovery"} {
			t.Run(fmt.Sprintf("%d/%s", family, role), func(t *testing.T) {
				env, keys := genesisEnvironment(t, family, role == "recovery")
				init, _ := fixtureInitAdmission(t, env, fixtureAdmission(env))
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				normal, recovery := env.Trust.(contract.QualifyingTrust), env.Recovery
				if role == "normal" {
					normal = cancelledQualificationTrust{QualifyingTrust: normal, cancel: cancel}
				} else {
					recovery = cancelledQualificationTrust{QualifyingTrust: recovery, cancel: cancel}
				}
				selected, result := Initialize(ctx, init, env.Store, normal, recovery, env.Crypto)
				store := env.Store.(*memoryStore)
				public, private := keys.Calls()
				if selected != nil || result != failure(EvidenceUnavailable, SigningUnavailable) || store.creates != 0 || store.cas != 0 || public != 0 || private != 0 {
					t.Fatalf("result=%+v effects=%d/%d keys=%d/%d", result, store.creates, store.cas, public, private)
				}
				keys.RetireInit()
			})
		}
	}
}
