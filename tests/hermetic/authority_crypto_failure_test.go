package core

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestReplacementFreezeClaimFailureConsumesSession(t *testing.T) {
	for _, operation := range []string{"reader", "authority"} {
		for _, fault := range []string{"freeze-fact", "freeze-unknown", "claim-framing", "claim-unknown"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				ctx := context.Background()
				env, keys := genesisEnvironment(t, contract.GCP, true)
				run := newScenarioRun(t, ctx, env)
				f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
				reader := fixtureID(env.Domain, "reader")
				recipients := []contract.ID{f.session.admission.recipient, reader}
				slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				run.suppliedSelection(f, append(f.session.currentEntryInputs(), sharingSecretNamed(t, env, "secret", "freeze claim source", recipients)))
				s := f.session
				adapter := &changedCryptoReply{inner: keys.Crypto(), kind: contract.CryptoFreeze}
				if fault == "claim-framing" || fault == "claim-unknown" {
					adapter.kind = contract.CryptoClaim
				}
				want := refused(AdmissionInvalid)
				if fault == "freeze-unknown" || fault == "claim-unknown" {
					want = failure(EvidenceUnavailable, CustodyUnavailable)
				}
				adapter.change = func(reply contract.CryptoResponse) contract.CryptoResponse {
					if reply.ResultCode != contract.CryptoSuccess {
						t.Fatal("fault did not reach a successful custody boundary", reply.ResultCode)
					}
					switch fault {
					case "freeze-fact":
						fact, err := contract.DecodeCryptoFreezeResult(reply.Body)
						if err != nil {
							t.Fatal(err)
						}
						fact.FactDigest[0] ^= 1
						reply.Body, err = contract.EncodeCryptoFreezeResult(fact)
						if err != nil {
							t.Fatal(err)
						}
					case "claim-framing":
						reply.Body = []byte{1}
					default:
						reply.ResultCode, reply.Body = contract.CryptoResponseUnknown, nil
					}
					return reply
				}
				var prepare func() (*Candidate, Result)
				var canAdmitFresh func() bool
				if operation == "reader" {
					permit := admitReaderReplacement(t, s, keys, reader, keys.RecipientSuccessor(t, reader))
					permit.crypto = adapter
					prepare = func() (*Candidate, Result) { return s.PrepareRecipientReplacement(ctx, permit, run.env.Trust) }
					canAdmitFresh = func() bool { _, ok := s.planRecipientReplacement(ctx, permit.intent); return ok }
				} else {
					after := currentControlOf(s)
					source := contract.BindingTableRow{SubjectKind: 2, SubjectID: after.Recovery.RoleID, Binding: after.Recovery.KMS}
					after.AuthorityKMSBinding = keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
					after.AccessGeneration++
					permit := admitAuthorityReplacement(t, s, keys, after, 1, 1, 2, source)
					permit.crypto = adapter
					prepare = func() (*Candidate, Result) {
						return s.PrepareSuccession(ctx, permit, SuccessionSigners{Authorizer: run.env.Trust})
					}
					canAdmitFresh = func() bool {
						_, _, ok := s.planSuccession(t.Context(), after, 1, 1, 2, testID("fresh failed-session admission"), contract.SuccessionMaterialRecovery)
						return ok
					}
				}
				defer keys.RetireAccess()
				creates, cas, signs := run.spy.StoreCreate, run.spy.StoreCAS, run.spy.TrustSign
				selected := bytes.Clone(s.body)
				candidate, result := prepare()
				if candidate != nil || result != want || adapter.calls != 1 || !s.prepared {
					t.Fatalf("failed terminal custody stage left usable session: result=%+v candidate=%t calls=%d prepared=%t", result, candidate != nil, adapter.calls, s.prepared)
				}
				public, private := keys.Calls()
				if candidate, _ := prepare(); candidate != nil || canAdmitFresh() {
					t.Fatal("failed session accepted an old or fresh replacement permit")
				}
				if p, k := keys.Calls(); p != public || k != private || adapter.calls != 1 {
					t.Fatal("failed session resumed custody")
				}
				if run.spy.StoreCreate != creates || run.spy.StoreCAS != cas || run.spy.TrustSign != signs {
					t.Fatal("failed custody stage reached persistence or final authorization")
				}
				opened, result := Open(ctx, f.admission, run.env.Store)
				if opened == nil || result.Outcome != ObservedCurrent || !bytes.Equal(opened.body, selected) {
					t.Fatal("failed custody stage changed selected HEAD", result)
				}
			})
		}
	}
}

// full_only: false
func TestAuthorityCryptoRefusesUnadmittedSourceControlAndProbe(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, context.Background(), env, []int{1}, false)
	control := f.session.root.CurrentAccess.Core
	source := contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
	request, q, probe, rows := authorityCryptoPlan(t, f.session, keys, contract.SuccessorAuthorityKEK, source, keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK))
	for _, name := range []string{"control", "invocation", "condition", "source-reader", "source-successor", "source-binding", "probe-context", "probe-id", "probe-subject", "probe-binding", "omitted-binding", "replacement-before", "replacement-target", "expired"} {
		t.Run(name, func(t *testing.T) {
			badRequest, badQ, badSource, badProbe, badBefore := request, q, source, probe, request.BeforeControl
			deadline := time.Unix(0, int64(q.Context.Expiry))
			switch name {
			case "control":
				badBefore.AccessGeneration++
			case "invocation":
				badRequest.AdmissionID = testID("unadmitted invocation")
			case "condition":
				badRequest.Token.Value += "-other"
			case "source-reader":
				for _, row := range keys.Bindings() {
					if row.SubjectID == fixtureID(env.Domain, "reader") {
						badSource = row
					}
				}
			case "source-successor":
				badSource = q.BindingTable[q.Replacements[0].SuccessorBindingIndex]
			case "source-binding":
				badSource.Binding.BindingSerial++
			case "probe-context":
				badProbe.Context.CurrentAccessRoot = testID("other access")
			case "probe-id":
				badProbe.ProbeID = contract.ID{}
			case "probe-subject":
				badProbe.SubjectKind = 2
			case "probe-binding":
				badProbe.SuccessorBindingDigest = testID("other successor")
			case "omitted-binding":
				badQ.BindingTable = slices.Clone(q.BindingTable[1:])
			case "replacement-before":
				badQ.Replacements = slices.Clone(q.Replacements)
				badQ.Replacements[0].BeforeBindingDigest = testID("other predecessor binding")
			case "replacement-target":
				badQ.Replacements = slices.Clone(q.Replacements)
				badQ.Replacements[0].SuccessorBindingIndex = uint16(len(q.BindingTable))
			case "expired":
				deadline = time.Now().Add(-time.Second)
			}
			public, private := keys.Calls()
			if err := keys.AdmitSuccessionAccess(badQ, badRequest, badBefore, badSource, badProbe, rows, deadline); err == nil {
				keys.RetireAccess()
				t.Fatal("unadmitted succession installed")
			}
			if afterPublic, afterPrivate := keys.Calls(); afterPublic != public || afterPrivate != private {
				t.Fatal("invalid admission used a key route")
			}
		})
	}
}

// full_only: false
func TestAuthorityCryptoFailedProbeOrSourceClosesOperation(t *testing.T) {
	for _, name := range []string{"successor-denied", "source-denied", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			run := newScenarioRun(t, context.Background(), env)
			f := newEnvironmentFixture(t, context.Background(), run.env, []int{1}, false)
			run.suppliedSelection(f, append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "surviving source", custody.StandardValue)))
			control := f.session.root.CurrentAccess.Core
			source := contract.BindingTableRow{SubjectKind: 2, SubjectID: control.Recovery.RoleID, Binding: control.Recovery.KMS}
			request, q, probe, rows := authorityCryptoPlan(t, f.session, keys, contract.SuccessorAuthorityKEK, source, keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK))
			keys.LoseRecipientPredecessor(probe.SubjectID)
			if err := keys.AdmitSuccessionAccess(q, request, request.BeforeControl, source, probe, rows, time.Unix(0, int64(q.Context.Expiry))); err != nil {
				t.Fatal(err)
			}
			defer keys.RetireAccess()
			body, err := contract.EncodeCryptoAccessReplaceRequest(q)
			if err != nil {
				t.Fatal(err)
			}
			if name == "successor-denied" {
				keys.SetDenied(probe.SubjectID, true)
			}
			public, private := keys.Calls()
			var begin contract.CryptoResponse
			if name == "cancelled" {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				begin = keys.Crypto().Exchange(ctx, contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoAccessReplace, RequestID: testID("cancelled message"), CustodyInstanceID: keys.Crypto().InstanceID(), Body: body})
				if afterPublic, afterPrivate := keys.Calls(); afterPublic != public || afterPrivate != private {
					t.Fatal("cancelled Begin called custody")
				}
			} else {
				begin = authorityCryptoExchange(t, keys.Crypto(), contract.CryptoAccessReplace, body)
			}
			if name != "source-denied" {
				if begin.ResultCode == contract.CryptoSuccess || len(begin.Body) != 0 {
					t.Fatal("failed private probe returned qualification")
				}
			} else {
				if begin.ResultCode != contract.CryptoSuccess {
					t.Fatal(begin.ResultCode)
				}
				started, err := contract.DecodeCryptoAccessReplaceResult(begin.Body)
				if err != nil {
					t.Fatal(err)
				}
				keys.SetDenied(source.SubjectID, true)
				body, err = contract.EncodeCryptoAccessPrepareRequest(contract.CryptoAccessPrepareRequest{OperationRef: started.OperationRef, Context: q.Context, Final: 1, Rows: rows})
				if err != nil {
					t.Fatal(err)
				}
				prepared := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoPrepare, body)
				if prepared.ResultCode == contract.CryptoSuccess || len(prepared.Body) != 0 {
					t.Fatal("failed surviving source returned material")
				}
			}
			public, private = keys.Calls()
			body, err = contract.EncodeCryptoAccessReplaceRequest(q)
			if err != nil {
				t.Fatal(err)
			}
			if repeat := authorityCryptoExchange(t, keys.Crypto(), contract.CryptoAccessReplace, body); repeat.ResultCode != contract.CryptoAlreadyUsed {
				t.Fatal("failed operation restarted", repeat.ResultCode)
			}
			if afterPublic, afterPrivate := keys.Calls(); afterPublic != public || afterPrivate != private {
				t.Fatal("failed operation called another route")
			}
		})
	}
}
