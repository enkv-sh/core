package core

import (
	"bytes"
	"context"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestReaderRotatedBasisKeepsExactUnavailableAndProofResults(t *testing.T) {
	for _, condition := range []struct {
		name                             string
		recovery, ordinary, badSignature bool
		mask                             uint8
	}{
		{"normal rotation without recovery", false, false, false, contract.SuccessionChangeNormalSigner},
		{"recovery rotation succession", true, false, false, contract.SuccessionChangeRecoverySigner},
		{"recovery rotation ordinary", true, true, false, contract.SuccessionChangeRecoverySigner},
		{"authority KEK rotation ordinary", true, true, false, contract.SuccessionChangeAuthorityKEK},
		{"bad rotated signature", false, false, true, contract.SuccessionChangeNormalSigner},
	} {
		t.Run(condition.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, keys := genesisEnvironment(t, contract.GCP, condition.recovery)
			f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
			oldBasis := readerTypedBasisFixture(t, f.session)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			operation := uint8(contract.SuccessionReplaceAuthority)
			if condition.mask == contract.SuccessionChangeRecoverySigner {
				operation = contract.SuccessionReplaceRecoveryBasis
			}
			selected, actors := selectReaderSuccessionFixture(t, ctx, env, f.session, operation, condition.mask, contract.NormalSigningRole)
			if condition.ordinary {
				actors.Keys.RetireAccess()
				reader := fixtureID(env.Domain, "reader")
				replacement := keys.RecipientSuccessor(t, reader)
				permit := admitReaderReplacement(t, selected, keys, reader, replacement)
				candidate, result := selected.PrepareRecipientReplacement(ctx, permit, env.Trust)
				if candidate == nil {
					t.Fatal("prepare ordinary post-rotation state", result)
				}
				selected, result = selected.selectCandidate(ctx, candidate)
				if selected == nil || result.Outcome != ObservedCurrent || selected.head.AuthKind != format.LifecycleAuth {
					t.Fatal("select ordinary post-rotation state", result)
				}
			}
			desired := comparisonCurrentInput(t, env, selected)
			want := failure(EvidenceUnavailable, SigningUnavailable)
			wantState, wantDiagnostic := contract.ReaderUnavailable, contract.ReasonEvidenceUnavailable
			if condition.badSignature {
				want = failure(IntegrityFailure, InvalidProof)
				wantState, wantDiagnostic = contract.ReaderPositiveDefect, contract.ReasonProofInvalid
			}
			for _, operation := range []string{contract.ReaderCompareOperation, contract.ReaderManifestOperation} {
				t.Run(operation, func(t *testing.T) {
					engine, candidate, source := readerEngineWithPublicBasisFixture(t, env, selected, oldBasis)
					if condition.badSignature {
						head, err := format.DecodeHead(candidate.head.Body)
						if err != nil {
							t.Fatal(err)
						}
						head.AuthorizationSignature = bytes.Clone(head.AuthorizationSignature)
						head.AuthorizationSignature[len(head.AuthorizationSignature)-1] ^= 1
						candidate.head.Body, err = format.EncodeHead(head)
						if err != nil {
							t.Fatal("bad signature must remain structurally valid", err)
						}
					}
					store := env.Store.(*memoryStore)
					creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).Calls()
					public, private := keys.Calls()
					request := contract.Hash([]byte("Reader rotated-basis request"))
					if operation == contract.ReaderCompareOperation {
						got := engine.Compare(ctx, request, desired)
						if got.Result != want || got.StateResult != wantState || got.Verdict != contract.ComparisonUnable || got.Observation != nil || len(got.Diagnostics) != 1 || got.Diagnostics[0].Reason != wantDiagnostic {
							t.Fatal("Reader comparison lost exact basis/proof result", got)
						}
					} else {
						got := engine.Manifest(ctx, request, hermeticManifestRequest(contract.ManifestRequest{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: selected.admission.recipient, EntryNames: []string{}}))
						if got.Result != want || got.StateResult != wantState || got.FailureReason != wantDiagnostic || got.Artifact != nil || got.Payload != nil || got.Observation != nil {
							t.Fatal("Reader manifest lost exact basis/proof result", got)
						}
					}
					gotPublic, gotPrivate := keys.Calls()
					if gotPublic != public || gotPrivate != private || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).Calls() != signs || condition.ordinary && source.reads == 0 || !condition.ordinary && source.reads != 0 {
						t.Fatal("Reader basis failure reached private effects or wrong read boundary", source.reads)
					}
				})
			}
		})
	}
}
