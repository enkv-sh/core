package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func selectReaderSuccessionFixture(t *testing.T, ctx context.Context, env fixtureEnvironment, before *StateSession, operation, mask, approval uint8) (*StateSession, successionActors) {
	t.Helper()
	actors := env.ReplacementActors(t, ctx, before, operation, mask, approval)
	permit := admitAuthorityReplacement(t, before, actors.Keys, actors.After, operation, approval, mask, actors.Source)
	candidate, result := before.PrepareSuccession(ctx, permit, actors.Signers)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("Reader succession fixture preparation", result)
	}
	_ = deliverSuccessionBasis(t, candidate)
	selected, result := before.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent {
		t.Fatal("Reader succession fixture selection", result)
	}
	actors.Activate(t, selected)
	return selected, actors
}

// full_only: false
func TestReaderAuthenticatesIndependentSuccessorSigningBasis(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, tc := range []struct {
			name                      string
			recovery                  bool
			operation, mask, approval uint8
		}{
			{"normal recovery disabled", false, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole},
			{"normal normal authorizer", true, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole},
			{"normal recovery authorizer", true, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.RecoverySigningRole},
			{"recovery normal authorizer", true, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, contract.NormalSigningRole},
			{"recovery recovery authorizer", true, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, contract.RecoverySigningRole},
		} {
			t.Run(fmt.Sprintf("%d/%s", family, tc.name), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				env, keys := genesisEnvironment(t, family, tc.recovery)
				f := newEnvironmentFixture(t, ctx, env, nil, false)
				env = syntheticAuthorityScenarioEnvironment(t, env)
				selected, actors := selectReaderSuccessionFixture(t, ctx, env, f.session, tc.operation, tc.mask, tc.approval)
				signers := []*testtrust.Signer{env.Trust.(*fixtureTrust).Signer}
				if env.Recovery != nil {
					signers = append(signers, env.Recovery.(*testtrust.Signer))
				}
				if actors.Signers.NormalSuccessor != nil {
					signers = append(signers, actors.Signers.NormalSuccessor.(*testtrust.Signer))
				}
				if actors.Signers.RecoverySuccessor != nil {
					signers = append(signers, actors.Signers.RecoverySuccessor.(*testtrust.Signer))
				}
				calls := make([][2]int, len(signers))
				for i, signer := range signers {
					calls[i] = [2]int{signer.Calls(), signer.QualificationCalls()}
				}
				public, private := keys.Calls()
				store := env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				e, _, source := readerEngineFixture(t, env, selected)
				inv := readerInvocationFixture(t, e, ctx)
				observed, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
				if result.Outcome != 0 || !observed.complete || observed.image.root.Snapshot != selected.root.Snapshot ||
					observed.basis.anchor.head.Core.Revision != selected.head.Core.Revision {
					t.Fatal("independent successor basis did not authenticate its complete selection", result)
				}
				if len(selected.head.Succession.Acceptances) != 1 {
					t.Fatal("fixture lacks the exact successor acceptance")
				}
				if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private || store.creates != creates || store.cas != cas {
					t.Fatal("Reader reached private key use or Store writes")
				}
				for i, signer := range signers {
					if [2]int{signer.Calls(), signer.QualificationCalls()} != calls[i] {
						t.Fatal("Reader reached signing or key qualification")
					}
				}
				inv.Close()
				if source.closes != 1 {
					t.Fatal("successor read source was not closed once", source.closes)
				}
			})
		}
	}
}

// full_only: false
func TestReaderRejectsStaleBasisWrongAuthorizerAndControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	genesisBasis := readerTypedBasisFixture(t, f.session)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	selected, _ := selectReaderSuccessionFixture(t, ctx, env, f.session, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
	successorBasis := readerTypedBasisFixture(t, selected)
	later, _ := selectReaderSuccessionFixture(t, ctx, env, selected, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, contract.NormalSigningRole)
	for _, name := range []string{"stale genesis", "stale successor", "successor as authorizer", "wrong control"} {
		t.Run(name, func(t *testing.T) {
			selection := selected
			if name == "stale successor" {
				selection = later
			}
			basis := readerTypedBasisFixture(t, selection)
			switch name {
			case "stale genesis":
				basis = genesisBasis
			case "stale successor":
				basis = successorBasis
			default:
				if name == "successor as authorizer" {
					head, err := format.DecodeHead(basis.Selection)
					if err != nil {
						t.Fatal(err)
					}
					head.Succession.Authorizer = currentControlOf(selected).NormalSigning
					basis.Selection, err = format.EncodeHead(head)
					if err != nil {
						t.Fatal("wrong-authorizer fixture must remain structurally valid", err)
					}
				} else {
					control, err := contract.DecodeControlCore(basis.Control)
					if err != nil {
						t.Fatal(err)
					}
					control.AccessGeneration++
					basis.Control, err = contract.EncodeControlCore(control)
					if err != nil {
						t.Fatal(err)
					}
				}

			}
			e, candidate, source := readerEngineWithPublicBasisFixture(t, env, selection, basis)
			inv, result := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("replacement request")))
			if inv != nil {
				t.Cleanup(inv.Close)
			}
			if name != "stale genesis" && name != "stale successor" {
				if inv != nil || result.Outcome != AdmissionRefused || result.diagnostic != contract.ReasonTrustBasisInvalid || len(candidate.calls) != 0 || source.reads != 0 {
					t.Fatal("invalid independent successor proof reached Store", result, candidate.calls)
				}
				return
			}
			if result.Outcome != 0 || inv == nil {
				t.Fatal("valid stale public basis was not independently admitted", result)
			}
			defer inv.Close()
			observed, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
			if result.Outcome == 0 || observed.complete || source.reads != 0 {
				t.Fatal("current successor selected its own independent trust basis", result)
			}
		})
	}
}

// full_only: false
func TestReaderSavedSuccessorBasisPermitsLaterAccessAdvance(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	successor, _ := selectReaderSuccessionFixture(t, ctx, env, f.session, contract.SuccessionReplaceAuthority, contract.SuccessionChangeNormalSigner, contract.NormalSigningRole)
	basis := readerTypedBasisFixture(t, successor)
	reader := fixtureID(env.Domain, "reader")
	binding := keys.RecipientSuccessor(t, reader)
	permit := admitReaderReplacement(t, successor, keys, reader, binding)
	currentSigner := testtrust.NewCurrent(t, currentControlOf(successor).NormalSigning)
	candidate, result := successor.PrepareRecipientReplacement(ctx, permit, currentSigner)
	if candidate == nil || result.Outcome != ObservedCurrent {
		t.Fatal("ordinary access advance preparation", result)
	}
	later, result := successor.selectCandidate(ctx, candidate)
	if later == nil || result.Outcome != ObservedCurrent || later.head.AuthKind == format.SuccessionAuth ||
		later.root.CurrentAccess.Core.AccessGeneration != successor.root.CurrentAccess.Core.AccessGeneration+1 {
		t.Fatal("fixture did not advance access after the saved succession", result)
	}
	e, _, _ := readerEngineWithPublicBasisFixture(t, env, later, basis)
	inv := readerInvocationFixture(t, e, ctx)
	observed, readResult := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
	if readResult.Outcome != 0 || !observed.complete || observed.image.root.Snapshot != later.root.Snapshot ||
		observed.image.root.CurrentAccess.Core.AccessGeneration != later.root.CurrentAccess.Core.AccessGeneration ||
		observed.image.recipientRecord(reader).CurrentBinding.BindingID != binding.BindingID {
		t.Fatal("saved successor basis incorrectly pinned later access to the old HEAD", readResult)
	}
}

// full_only: false
func TestReaderFixedObservationAndUnreadSelectedObjectLifetime(t *testing.T) {
	for _, loaded := range []bool{true, false} {
		t.Run(fmt.Sprintf("bytes loaded=%t", loaded), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, _ := genesisEnvironment(t, contract.GCP, false)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
			e, candidate, source := readerEngineFixture(t, env, f.session)
			inv := readerInvocationFixture(t, e, ctx)
			observed, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil)
			if result.Outcome != 0 || !observed.complete {
				t.Fatal("fixed observation fixture", result)
			}
			var configuration contract.OutputConfiguration
			if loaded {
				var read Result
				configuration, read = selectedOutputConfigurationWithReader(ctx, observed.image.root, observed.image.supportFacts, observed.basis.reader, true, nil)
				if read.Outcome != 0 {
					t.Fatal("load exact selected output bytes", read)
				}
			}
			input := f.session.currentEntryInputs()
			input[0].InputBytes = []byte("later plain bytes")
			later := run.suppliedSelection(f, input)
			if later.head.Core.Revision == observed.basis.anchor.head.Core.Revision || later.root.Snapshot == observed.image.root.Snapshot {
				t.Fatal("fixture did not advance HEAD")
			}
			store := env.Store.(*memoryStore)
			creates, cas, reads := store.creates, store.cas, source.reads
			candidateReads := len(candidate.calls)
			headReads := 0
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == store.desc.HeadKey {
					headReads++
				}
				return read
			}
			defer func() { store.readHook = nil }()
			if loaded {
				if err := env.Delete(ctx, readerFixtureKey(t, store.desc.Prefix, observed.basis.anchor.head.Core.Root)); err != nil {
					t.Fatal(err)
				}
				if !observed.complete || !observed.image.selectedOutputComplete() || configuration.DomainID != env.Domain ||
					len(configuration.Bindings) != 0 || len(configuration.Routes) != 0 ||
					!bytes.Equal(observed.image.valueEntry(observed.image.root.Names[0].Slot).ValueBytes, []byte{0}) ||
					!reflect.DeepEqual(inv.selection.image.root, observed.image.root) || source.reads != reads {
					t.Fatal("later HEAD or GC changed completed observation")
				}
			} else {
				for _, page := range observed.image.supportFacts {
					for _, row := range page.rows {
						if row.Kind() == contract.OutputConfigurationSliceSupportKind {
							if err := env.Delete(ctx, readerFixtureKey(t, store.desc.Prefix, page.ref)); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
				_, read := selectedOutputConfigurationWithReader(ctx, observed.image.root, observed.image.supportFacts, observed.basis.reader, true, nil)
				if read.Outcome != EvidenceUnavailable || read.Reason != MissingSelectedObject || source.reads != reads+1 {
					t.Fatal("unread GC object became current output or triggered automatic retry", read, source.reads-reads)
				}
				if retried, refusal := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil); refusal.Outcome != AdmissionRefused || retried.complete || source.reads != reads+1 {
					t.Fatal("failed fixed observation reused its invocation", refusal)
				}
			}
			if headReads != 0 || len(candidate.calls) != candidateReads || store.creates != creates || store.cas != cas {
				t.Fatal("fixed observation reread HEAD or wrote state", headReads, candidate.calls)
			}
		})
	}
}

// full_only: false
func TestReaderCloseJoinsActiveFiniteInvocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	e, _, source := readerEngineFixture(t, env, f.session)
	if len(e.publicBasis.Descriptor)+len(e.publicBasis.Control)+len(e.publicBasis.Selection) == 0 {
		t.Fatal("Reader fixture lacks owned public basis")
	}
	installedClosed := make(chan struct{}, 2)
	e.closeInstalled = func() { installedClosed <- struct{}{} }
	inv := readerInvocationFixture(t, e, ctx)
	if _, result := inv.loadPublicSelection(ctx, contract.ReaderCompareOperation, inv.admission.request, nil); result.Outcome != 0 {
		t.Fatal("active Reader fixture", result)
	}
	joined := make(chan struct{})
	go func() { e.Close(); close(joined) }()
	deadline := time.After(5 * time.Second)
	for {
		e.mu.Lock()
		closing := e.closed
		e.mu.Unlock()
		if closing {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Reader Close did not close admission")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	select {
	case <-joined:
		t.Fatal("Reader Close returned before the active invocation closed")
	case <-installedClosed:
		t.Fatal("Reader released installation before the active source")
	default:
	}
	if next, result := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("later request"))); next != nil || result.Outcome != AdmissionRefused {
		if next != nil {
			t.Cleanup(next.Close)
		}
		t.Fatal("closing Reader admitted a later invocation", result)
	}
	inv.Close()
	select {
	case <-joined:
	case <-time.After(5 * time.Second):
		t.Fatal("Reader Close did not join invocation release")
	}
	if source.closes != 1 || inv.selection.complete || inv.admission.issued || inv.source != nil {
		t.Fatal("invocation close retained its source, selection or admission")
	}
	if !reflect.DeepEqual(e.publicBasis, PublicBasis{}) {
		t.Fatal("Reader close retained its public basis after the active invocation joined")
	}
	select {
	case <-installedClosed:
	default:
		t.Fatal("Reader did not close its installation after the join")
	}
	e.Close()
	select {
	case <-installedClosed:
		t.Fatal("Reader closed its installation more than once")
	default:
	}
}

// full_only: false
func TestReaderRefusesRetiredSuccessionKindWithValidSignature(t *testing.T) {
	for _, approval := range []uint8{contract.NormalSigningRole, contract.RecoverySigningRole} {
		t.Run(fmt.Sprintf("approval%d", approval), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, keys := genesisEnvironment(t, contract.GCP, true)
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			selected, _ := selectReaderSuccessionFixture(t, ctx, env, f.session, contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner, approval)
			basis := readerTypedBasisFixture(t, selected)
			head, err := format.DecodeHead(basis.Selection)
			if err != nil {
				t.Fatal(err)
			}
			subject, err := contract.EncodeSuccessionSubject(head.Succession.Subject)
			if err != nil {
				t.Fatal(err)
			}
			position := bytes.Index(basis.Selection, subject)
			if position < 0 || bytes.Count(basis.Selection, subject) != 1 {
				t.Fatal("selection lacks its one subject image")
			}
			authorizer := env.Trust.(*fixtureTrust).Signer
			if approval == contract.RecoverySigningRole {
				authorizer = env.Recovery.(*testtrust.Signer)
			}
			retiredSubject, signature := authorizer.RetiredSuccessionProof(t, head.Succession.Subject)
			public, err := x509.ParsePKIXPublicKey(head.Succession.Authorizer.SPKI)
			if err != nil || !bytes.Equal(authorizer.PublicKey(), head.Succession.Authorizer.SPKI) {
				t.Fatal("fixture signer differs from current authorizer")
			}
			digest := sha256.Sum256(retiredSubject)
			if !ecdsa.VerifyASN1(public.(*ecdsa.PublicKey), digest[:], signature) {
				t.Fatal("retired subject lacks a valid current-authorizer signature")
			}
			copy(basis.Selection[position:position+len(subject)], retiredSubject)
			oldSignature := head.AuthorizationSignature
			position = bytes.Index(basis.Selection, oldSignature)
			if position < 4 || bytes.Count(basis.Selection, oldSignature) != 1 || binary.BigEndian.Uint32(basis.Selection[position-4:position]) != uint32(len(oldSignature)) {
				t.Fatal("selection lacks its one framed authorization signature")
			}
			wire := binary.BigEndian.AppendUint32(bytes.Clone(basis.Selection[:position-4]), uint32(len(signature)))
			wire = append(wire, signature...)
			basis.Selection = append(wire, basis.Selection[position+len(oldSignature):]...)
			e, candidate, source := readerEngineWithPublicBasisFixture(t, env, selected, basis)
			publicCalls, privateCalls := keys.Calls()
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			inv, result := e.beginReaderInvocation(ctx, contract.ReaderCompareOperation, contract.Hash([]byte("retired succession proof")))
			if inv != nil {
				inv.Close()
			}
			if inv != nil || result.Outcome != AdmissionRefused || result.diagnostic != contract.ReasonTrustBasisInvalid || len(candidate.calls) != 0 || source.reads != 0 {
				t.Fatal("validly signed retired proof reached public Store admission", result)
			}
			if p, k := keys.Calls(); p != publicCalls || k != privateCalls || store.creates != creates || store.cas != cas {
				t.Fatal("retired proof reached private key use or Store writes")
			}
		})
	}
}
