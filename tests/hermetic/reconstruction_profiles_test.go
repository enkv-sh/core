package core

import (
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestReconstructionRequiresInstalledProfilesBeforeSelectedWork(t *testing.T) {
	for _, profile := range []string{"matching", "compatibility", "crypto support", "interpretation"} {
		t.Run(profile, func(t *testing.T) {
			env, _ := genesisEnvironment(t, contract.GCP, false)
			run := newScenarioRun(t, t.Context(), env)
			f := newEnvironmentFixture(t, t.Context(), run.env, []int{1}, false)
			store := env.Store.(*memoryStore)
			selected := *f.session
			control := &selected.root.CurrentAccess.Core.CurrentControl
			switch profile {
			case "compatibility":
				control.CompatibilityID[0] ^= 1
			case "crypto support":
				control.CryptoSupportID[0] ^= 1
			case "interpretation":
				control.NormalSigning.Binding.Interpretation[0] ^= 1
				selected.head.Core.Interpretation = control.NormalSigning.Binding.Interpretation
				request, err := contract.NewBindingRequest(control.NormalSigning.Binding)
				if err != nil {
					t.Fatal("changed public binding", err)
				}
				signed := env.Trust.Sign(t.Context(), request)
				if signed.Reason != contract.ReasonNone {
					t.Fatal("changed binding signature", signed.Reason)
				}
				selected.head.K1 = signed.Signature
			}
			writer := &fixture{store: store, trust: env.Trust.(*fixtureTrust), admission: f.admission, session: &selected}
			storeContractRoot(t, writer, selected.root, selected.currentEntryInputs())
			headRead := store.objects[store.desc.HeadKey]
			var err error
			selected.head, err = format.DecodeHead(headRead.Body)
			if err != nil {
				t.Fatal("signed HEAD", err)
			}
			selected.body, selected.token = headRead.Body, headRead.Token
			selected.root, err = format.DecodeRoot(store.objects[mustKey(t, store.desc.Prefix, selected.head.Core.Root)].Body)
			if err != nil || selected.root.SecretCount != 0 {
				t.Fatal("signed plain-only root", err)
			}
			if _, valid := candidateSelectionSignature(selected.head, selected.root, contract.NormalSigningRole); !valid {
				t.Fatal("profile fixture lacks a coherent complete-selection signature")
			}
			qualifier := &candidateQualifierProbe{}
			constructs, verifies := 0, 0
			var reader *constructedReadProbe
			verifier := &reconstructionVerifyProbe{}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			engine, err := NewInstalledReconstruction(ReconstructionInstallation{
				Candidate: candidateProbeForSelected(t, env, &selected), Normal: qualifier,
				Construct: func(_ context.Context, configuration contract.StoreConfiguration) (PublicSelectedReader, Result) {
					constructs++
					reader = &constructedReadProbe{store: store, descriptor: store.Descriptor(), configuration: configuration}
					return reader, Result{}
				},
				Verify: func(_ context.Context, _ contract.ReconstructionVerificationPins, _ time.Time) (ReconstructionVerifier, error) {
					verifies++
					return verifier, nil
				}, CloseInstalled: func() {},
			})
			if err != nil {
				t.Fatal("fixed installation", err)
			}
			defer engine.Close()
			creates, cas := store.creates, store.cas
			projection, result := engine.Reconstruct(ctx)
			if projection != nil {
				defer projection.Close()
			}
			if store.creates != creates || store.cas != cas {
				t.Fatal("read-only reconstruction changed the selected store")
			}
			if profile == "matching" {
				if result.Outcome != ObservedCurrent || projection == nil || projection.PartCount() == 0 ||
					qualifier.calls != 1 || constructs != 1 || verifies != 1 || reader.closes != 1 ||
					verifier.calls != 0 || verifier.closes != 1 {
					t.Fatal("matching plain-only installed support did not return a complete projection", result, qualifier.calls, constructs, verifies)
				}
				return
			}
			if result != (Result{Outcome: AdmissionRefused, Reason: AdmissionInvalid}) || projection != nil ||
				qualifier.calls != 0 || constructs != 0 || verifies != 0 || verifier.calls != 0 || verifier.closes != 0 {
				t.Fatal("unsupported installed profile reached selected or private work", result, qualifier.calls, constructs, verifies)
			}
		})
	}
}
