package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

// full_only: false
func TestInternalEmptyGenesisRetainsInitializationReceipt(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprint(family)+fmt.Sprint(recovery), func(t *testing.T) {
				env, _ := genesisEnvironment(t, family, recovery)
				init, p := fixtureInitAdmission(t, env, fixtureAdmission(env))
				state, result := Initialize(context.Background(), init, env.Store, env.Trust.(contract.QualifyingTrust), env.Recovery, env.Crypto)
				if state == nil || result.Outcome != ObservedCurrent {
					t.Fatal("genesis did not select ready state", result)
				}
				windows, err := state.receiptWindows(context.Background())
				if err != nil || !slices.Equal(windows.Order, []contract.ID{p.descriptor.InitID}) {
					t.Fatal("genesis did not select exactly its initialization receipt order", err)
				}
				body, result := state.MutationReceipt(context.Background(), p.descriptor.InitID)
				if result.Outcome != ObservedCurrent {
					t.Fatal("initialization receipt unavailable", result)
				}
				receipt, err := contract.InspectCompactMutationReceipt(body)
				if err != nil || receipt.OperationKind != contract.OperationInitializeDomain || receipt.StateResult != contract.ReceiptStateSuccess ||
					receipt.DomainID != p.descriptor.DomainID || receipt.OperationID != p.descriptor.InitID ||
					!receipt.PredecessorRevisionID.IsZero() || receipt.RequestedRevisionID != state.head.Core.Revision ||
					receipt.RequestedRevisionID != receipt.ObservedRevisionID || receipt.EffectSummary != contract.ReceiptEffectNoChange ||
					receipt.ChangedSubjects.Count != 0 || receipt.ChangedSubjects.Length != 4 || receipt.WarningBits != 0 ||
					receipt.RequestIdentityDigest != contract.Hash(p.requestBytes) || state.root.RequiredSupportRecordCount != 3 ||
					len(state.root.RequiredSupport) != 2 || state.root.Generated.SuccessWindow.Count != 1 || state.root.Generated.FailureWindow.Count != 0 || state.root.Generated.ReceiptOrder.Count != 1 {
					t.Fatal("initialization receipt or mandatory support has wrong public facts", err)
				}
				for _, count := range receipt.SummaryCounts {
					if count != 0 {
						t.Fatal("empty genesis retained a nonempty result vector")
					}
				}
			})
		}
	}
}

func initializationAllocationForDescriptor(t testing.TB, d contract.GenesisDescriptorCore) *InitializationAllocation {
	t.Helper()
	fields := []contract.ID{d.InitID, d.DomainID, d.DescriptorArtifactID, d.ManifestArtifactID,
		d.NormalSigning.BindingID, d.NormalSigning.Binding.ControlIncarnationID, d.AuthorityRecipientID}
	var authority *contract.KMSBinding
	for _, r := range d.Recipients {
		if r.RecipientID == d.AuthorityRecipientID {
			authority = r.CurrentBinding
		}
	}
	if authority == nil {
		t.Fatal("missing fixture authority")
	}
	fields = append(fields, authority.BindingID, authority.BindingIncarnationID)
	for _, r := range d.Recipients {
		if r.RecipientID != d.AuthorityRecipientID {
			fields = append(fields, r.RecipientID, r.CurrentBinding.BindingID, r.CurrentBinding.BindingIncarnationID)
		}
	}
	if d.Recovery != nil {
		r := d.Recovery
		fields = append(fields, r.RoleID, r.Signing.BindingID, r.Signing.Binding.ControlIncarnationID, r.KMS.BindingID, r.KMS.BindingIncarnationID)
	}
	var entropy []byte
	for _, id := range fields {
		entropy = append(entropy, id[:]...)
	}
	allocation, err := allocateInitialization(bytes.NewReader(entropy), uint16(len(d.Recipients)-1), d.Recovery != nil)
	if err != nil || !initializationIDsMatch(allocation.Identities(), d) {
		t.Fatal("descriptor fixture did not pass production allocation", err)
	}
	return allocation
}

func publicInitializationInstallation(t testing.TB, env fixtureEnvironment, keys *custody.Fixture) (InitializationInstallation, map[uint8][]byte) {
	t.Helper()
	d, err := fixtureDescriptor(env)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[uint8][]byte{}
	store := env.Store.(*memoryStore)
	sink := func(kind uint8) InitializationArtifactSink {
		return func(_ context.Context, id contract.ID, body []byte) (contract.GenesisArtifactFact, error) {
			pub, private := keys.Calls()
			if pub != 0 || private != 0 || env.Trust.(*fixtureTrust).signs != 0 || store.creates != 0 || store.cas != 0 {
				t.Error("provider work preceded installed artifact delivery")
			}
			if kind == 2 && len(artifacts[1]) == 0 {
				t.Error("manifest preceded descriptor delivery")
			}
			artifacts[kind] = bytes.Clone(body)
			return contract.GenesisArtifactFact{Kind: kind, ArtifactID: id, BodyDigest: contract.Hash(body), BodyLength: uint64(len(body)), DurabilityProfile: 1, Outcome: 1}, nil
		}
	}
	return InitializationInstallation{Descriptor: d, Store: env.Store, Normal: env.Trust.(contract.QualifyingTrust), Recovery: env.Recovery,
		CompositionID: fixtureID(env.Domain, "public-init-composition"), SetupDigest: contract.Hash([]byte("original frozen setup")),
		PersistDescriptor: sink(1), PersistManifest: sink(2), CloseInstalled: func() {},
		AdmitCustody: func(ctx context.Context, q contract.CryptoQualifyInitKeysRequest) (contract.Crypto, func(), error) {
			if len(artifacts[1]) == 0 || len(artifacts[2]) == 0 {
				t.Error("private custody preceded artifacts")
			}
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("missing public initialization deadline")
			}
			owner, err := keys.NewInitializationCustody(q, deadline)
			if err != nil {
				return nil, nil, err
			}
			return owner, owner.Close, nil
		}}, artifacts
}

// full_only: false
func TestPublicInitializationAndSameInitObserverUseProductionAdmission(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprint(family)+fmt.Sprint(recovery), func(t *testing.T) {
				env, keys := genesisEnvironment(t, family, recovery)
				installation, artifacts := publicInitializationInstallation(t, env, keys)
				allocation := initializationAllocationForDescriptor(t, installation.Descriptor)
				for _, row := range installation.Descriptor.Recipients {
					if row.RecipientID != installation.Descriptor.AuthorityRecipientID {
						keys.SetDenied(row.RecipientID, true)
					}
				}
				engine, err := NewInstalledInitializer(allocation, installation)
				if err != nil {
					t.Fatal(err)
				}
				defer engine.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				points := make(chan telemetry.MetricPoint, 2048)
				recorder := telemetry.NewRecorder()
				capability := telemetry.NewCapability(points, recorder)
				ctx = telemetry.WithCapability(ctx, capability)
				assertTelemetry := func(want telemetry.Result, reason telemetry.DiagnosticReason, children bool) {
					t.Helper()
					status := recorder.Status()
					if status.DroppedContention != 0 || status.DroppedFull != 0 || status.DroppedClosed != 0 || status.Rejected != 0 || capability.LostMetrics() != 0 || capability.RejectedMetrics() != 0 {
						t.Fatal("public initialization telemetry evidence was lost")
					}
					records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 512))
					calls := make(map[uint64]bool)
					starts, returns, childStarts := 0, 0, 0
					for _, record := range records {
						if err := record.Validate(); err != nil {
							t.Fatal(err)
						}
						if record.Event == telemetry.DiagnosticStart {
							if record.ParentCall != 0 && !calls[record.ParentCall] {
								t.Fatal("initialization child lost its owning call")
							}
							calls[record.Call] = true
							if record.Operation == telemetry.OpCoreInitialize {
								starts++
								if record.ParentCall != 0 {
									t.Fatal("public initialization return owner was duplicated")
								}
							} else if record.ParentCall != 0 {
								childStarts++
							}
						}
						if record.Operation == telemetry.OpCoreInitialize && record.Event == telemetry.DiagnosticReturn {
							returns++
							severity := "INFO"
							if want == telemetry.ResultAdmissionRefused {
								severity = "WARN"
							}
							if record.Result != want || record.Reason != reason || record.SeverityText != severity {
								t.Fatal("public initialization telemetry changed result or reason")
							}
						}
					}
					if starts != 1 || returns != 1 || children && childStarts == 0 || !children && childStarts != 0 {
						t.Fatal("public initialization normal-return or parent linkage differs", starts, returns, childStarts)
					}
					body, err := json.Marshal(records)
					if err != nil || bytes.Contains(body, []byte(installation.Descriptor.NormalSigning.KeySelector)) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(installation.Descriptor.NormalSigning.SPKI))) {
						t.Fatal("initialization telemetry disclosed key material or selectors")
					}
					for _, recipient := range installation.Descriptor.Recipients {
						if recipient.CurrentBinding != nil && bytes.Contains(body, []byte(recipient.CurrentBinding.KeySelector)) {
							t.Fatal("initialization telemetry disclosed recipient key selector")
						}
					}
					metricCalls, metricResults, durations := int64(0), int64(0), 0
					for len(points) != 0 {
						point := <-points
						if point.Operation != telemetry.OpCoreInitialize {
							continue
						}
						switch point.Name {
						case telemetry.OperationCalls:
							metricCalls += point.IntValue
						case telemetry.OperationResults:
							metricResults += point.IntValue
							if point.Result != want {
								t.Fatal("public initialization metric changed result")
							}
						case telemetry.OperationDuration:
							durations++
						}
					}
					if metricCalls != 1 || metricResults != 1 || durations != 1 {
						t.Fatal("public initialization call/result/duration counts differ")
					}
				}
				got := engine.Initialize(ctx)
				assertTelemetry(telemetry.ResultObservedCurrent, telemetry.DiagnosticReasonNone, true)
				if got.StateResult != contract.InitializationSuccess || got.Result.Evidence != AuthenticatedClosure ||
					got.Payload == nil || got.PublicBasis == nil || len(got.Receipt) == 0 || got.EffectSummary != "effect-no-change" ||
					got.Payload.DomainID != env.Domain || got.Payload.InitID != allocation.Identities().InitID ||
					!bytes.Equal(got.PublicBasis.Descriptor, artifacts[1]) {
					t.Fatal("public initialization did not return exact ready result", got.Result, got.StateResult)
				}
				receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
				if err != nil || receipt.RequestIdentityDigest != got.RequestIdentity || receipt.StateResult != contract.ReceiptStateSuccess {
					t.Fatal("public result receipt mismatch", err)
				}
				admitted, admission := admitPublicNormal(t.Context(), env.Domain, env.Store.Descriptor(), *got.PublicBasis, env.Store, installation.CompositionID, nil)
				if admission.Outcome != ObservedCurrent {
					t.Fatal("public initialization receipt read admission", admission)
				}
				before, read := Open(t.Context(), admitted, env.Store)
				if before == nil || read.Outcome != ObservedCurrent {
					t.Fatal("public initialization receipt cold read", read)
				}
				beforeWindows, err := before.receiptWindows(t.Context())
				if err != nil || !slices.Equal(beforeWindows.Order, []contract.ID{allocation.Identities().InitID}) {
					t.Fatal("public initialization receipt order differs", err)
				}
				if reused := engine.Initialize(ctx); reused.StateResult != contract.InitializationRefused || reused.Payload != nil {
					t.Fatal("one-use initialization repeated")
				}
				assertTelemetry(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid, false)
				store := env.Store.(*memoryStore)
				pub, private := keys.Calls()
				beforeCreates, beforeCAS, beforeSigns := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
				keys.SetUnavailable(true)
				env.Trust.(*fixtureTrust).SetUnavailable(true)
				if env.Recovery != nil {
					env.Recovery.(*testtrust.Signer).SetUnavailable(true)
				}
				observer, err := NewInstalledInitializationObserver(InitializationObservationInstallation{Descriptor: artifacts[1], Manifest: artifacts[2], Store: env.Store, CompositionID: installation.CompositionID, CloseInstalled: func() {}})
				if err != nil {
					t.Fatal(err)
				}
				defer observer.Close()
				observed := observer.Initialize(ctx)
				assertTelemetry(telemetry.ResultObservedCurrent, telemetry.DiagnosticReasonNone, true)
				afterPub, afterPrivate := keys.Calls()
				if observed.StateResult != contract.InitializationExactResume || observed.Payload == nil || !bytes.Equal(observed.Receipt, got.Receipt) ||
					beforeCreates != store.creates || beforeCAS != store.cas || beforeSigns != env.Trust.(*fixtureTrust).signs || pub != afterPub || private != afterPrivate {
					t.Fatal("same-init observation changed receipt or used private/write reach", observed.Result, observed.StateResult)
				}
				after, read := Open(t.Context(), admitted, env.Store)
				if after == nil || read.Outcome != ObservedCurrent {
					t.Fatal("same-init observation receipt cold read", read)
				}
				afterWindows, err := after.receiptWindows(t.Context())
				if err != nil || !slices.Equal(afterWindows.Order, []contract.ID{allocation.Identities().InitID}) {
					t.Fatal("same-init observation changed exact initialization receipt order", err)
				}
			})
		}
	}
}

// full_only: false
func TestPublicInitializationArtifactRefusalsPrecedeProviderWork(t *testing.T) {
	for _, boundary := range []string{"descriptor", "manifest", "cancelled-descriptor", "unbounded-context"} {
		t.Run(boundary, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			i, artifacts := publicInitializationInstallation(t, env, keys)
			allocation := initializationAllocationForDescriptor(t, i.Descriptor)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if boundary == "unbounded-context" {
				ctx = context.Background()
			}
			var custodyCalls int
			originalCustody := i.AdmitCustody
			i.AdmitCustody = func(ctx context.Context, q contract.CryptoQualifyInitKeysRequest) (contract.Crypto, func(), error) {
				custodyCalls++
				return originalCustody(ctx, q)
			}
			original := i.PersistDescriptor
			i.PersistDescriptor = func(ctx context.Context, id contract.ID, body []byte) (contract.GenesisArtifactFact, error) {
				fact, err := original(ctx, id, body)
				if boundary == "descriptor" {
					fact.BodyDigest = contract.ID{}
				}
				if boundary == "cancelled-descriptor" {
					cancel()
				}
				return fact, err
			}
			manifest := i.PersistManifest
			i.PersistManifest = func(ctx context.Context, id contract.ID, body []byte) (contract.GenesisArtifactFact, error) {
				fact, err := manifest(ctx, id, body)
				if boundary == "manifest" {
					fact.ArtifactID = contract.ID{}
				}
				return fact, err
			}
			engine, err := NewInstalledInitializer(allocation, i)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			got := engine.Initialize(ctx)
			pub, private := keys.Calls()
			store := env.Store.(*memoryStore)
			if got.Payload != nil || got.PublicBasis != nil || len(got.Receipt) != 0 || got.StateResult == contract.InitializationSuccess ||
				pub != 0 || private != 0 || store.reads != 0 || store.creates != 0 || store.cas != 0 || custodyCalls != 0 {
				t.Fatal("artifact refusal reached provider or public success", got.Result)
			}
			if boundary == "unbounded-context" && len(artifacts) != 0 {
				t.Fatal("unbounded context reached artifact delivery")
			}
		})
	}
}

// full_only: false
func TestPublicInitializationRequiredCapabilityDenialsRetainMode(t *testing.T) {
	for _, denial := range []string{"normal-signing", "authority-private", "recovery-signing", "recovery-private", "public-metadata"} {
		t.Run(denial, func(t *testing.T) {
			env, keys := genesisEnvironment(t, contract.GCP, true)
			i, artifacts := publicInitializationInstallation(t, env, keys)
			allocation := initializationAllocationForDescriptor(t, i.Descriptor)
			switch denial {
			case "normal-signing":
				env.Trust.(*fixtureTrust).SetUnavailable(true)
			case "authority-private":
				keys.SetDenied(i.Descriptor.AuthorityRecipientID, true)
			case "recovery-signing":
				env.Recovery.(*testtrust.Signer).SetUnavailable(true)
			case "recovery-private":
				keys.SetDenied(i.Descriptor.Recovery.RoleID, true)
			case "public-metadata":
				keys.SetUnavailable(true)
			}
			engine, err := NewInstalledInitializer(allocation, i)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			got := engine.Initialize(ctx)
			store := env.Store.(*memoryStore)
			if got.StateResult != contract.InitializationUnavailable || got.Payload != nil || len(got.Receipt) != 0 ||
				store.creates != 0 || store.cas != 0 || len(artifacts[1]) == 0 || len(artifacts[2]) == 0 {
				t.Fatal("required capability denial changed mode or selected genesis", got.Result)
			}
			creates, cas := store.creates, store.cas
			pub, private := keys.Calls()
			signs := env.Trust.(*fixtureTrust).signs
			observer, err := NewInstalledInitializationObserver(InitializationObservationInstallation{Descriptor: artifacts[1], Manifest: artifacts[2], Store: env.Store, CompositionID: i.CompositionID, CloseInstalled: func() {}})
			if err != nil {
				t.Fatal(err)
			}
			defer observer.Close()
			observed := observer.Initialize(ctx)
			afterPub, afterPrivate := keys.Calls()
			if observed.StateResult != contract.InitializationUnavailable || observed.Payload != nil || len(observed.Receipt) != 0 ||
				creates != store.creates || cas != store.cas || pub != afterPub || private != afterPrivate || signs != env.Trust.(*fixtureTrust).signs {
				t.Fatal("absent-HEAD observation resumed pre-HEAD work", observed.Result)
			}
		})
	}
}

// full_only: false
func TestPublicInitializationObserverAuthenticatesManifestAndHistoricalExpiry(t *testing.T) {
	env, keys := genesisEnvironment(t, contract.GCP, false)
	i, artifacts := publicInitializationInstallation(t, env, keys)
	engine, err := NewInstalledInitializer(initializationAllocationForDescriptor(t, i.Descriptor), i)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ready := engine.Initialize(ctx)
	if ready.StateResult != contract.InitializationSuccess {
		t.Fatal("initialization did not become ready", ready.Result)
	}
	manifest, err := contract.DecodeGenesisBootstrapManifestCore(artifacts[2])
	if err != nil {
		t.Fatal(err)
	}
	manifest.RequestCoreDigest = contract.Hash([]byte("different original captured request"))
	changed, err := contract.EncodeGenesisBootstrapManifestCore(manifest)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := NewInstalledInitializationObserver(InitializationObservationInstallation{Descriptor: artifacts[1], Manifest: changed,
		Store: env.Store, CompositionID: i.CompositionID, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	observed := bad.Initialize(ctx)
	if observed.StateResult != contract.InitializationPositiveDefect || observed.Payload != nil || len(observed.Receipt) != 0 {
		t.Fatal("observer accepted a manifest for a different captured request", observed.Result)
	}
	<-ctx.Done()
	fresh, freshCancel := context.WithTimeout(context.Background(), time.Minute)
	defer freshCancel()
	keys.SetUnavailable(true)
	env.Trust.(*fixtureTrust).SetUnavailable(true)
	store := env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).signs
	pub, private := keys.Calls()
	good, err := NewInstalledInitializationObserver(InitializationObservationInstallation{Descriptor: artifacts[1], Manifest: artifacts[2],
		Store: env.Store, CompositionID: i.CompositionID, CloseInstalled: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	observed = good.Initialize(fresh)
	afterPub, afterPrivate := keys.Calls()
	if observed.StateResult != contract.InitializationExactResume || observed.Payload == nil || !bytes.Equal(observed.Receipt, ready.Receipt) ||
		creates != store.creates || cas != store.cas || signs != env.Trust.(*fixtureTrust).signs || pub != afterPub || private != afterPrivate {
		t.Fatal("historical initialization expiry blocked public observation or caused new effects", observed.Result)
	}
}
