package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	protocol "enkv.sh/sdk/protocols/generator"
)

// full_only: false
func TestInstalledParallelCreateReportsOneStoreFailureInPlanOrder(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(fmt.Sprintf("conflict-%t", conflict), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			first := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "unused")[0]
			second := first
			first.Name, second.Name = "alpha", "beta"
			input := []ApplyEntryInput{first, second}
			base := requireAdmittedMemoryStore(t, f.env.Store)
			store := &applyPreparationTestStore{Store: base, memory: base}
			f.env.Store = store
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			admit := callbacks.AdmitProducer
			var keys []string
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				key, err := format.GeneratedResultKey(base.desc.Prefix, f.env.Domain, in.Expected.Template.InboxID)
				if err != nil {
					return nil, err
				}
				keys = append(keys, key)
				return admit(ctx, q, control, in, row, deadline)
			}
			secondWrite := make(chan struct{})
			store.create = func(ctx context.Context, key string, body []byte) contract.WriteResult {
				if len(keys) == 2 {
					switch key {
					case keys[0]:
						select {
						case <-secondWrite:
						case <-ctx.Done():
							t.Error("second write did not join")
						}
						return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonLimit, NotSent: true}
					case keys[1]:
						close(secondWrite)
						if conflict {
							return contract.WriteResult{Status: contract.WritePrecondition}
						}
						return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
					}
				}
				return base.Create(ctx, key, body)
			}
			store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
				if conflict && len(keys) == 2 && key == keys[1] {
					return contract.ReadResult{Status: contract.ReadOK, Body: []byte("different")}
				}
				return base.Read(ctx, key, limit)
			}
			engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), callbacks)
			got := engine.Apply(ctx, testID("two result writes"), input)
			engine.Close()
			cold := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, cold)
			want := contract.ReasonLimitExceeded
			if conflict {
				want = contract.ReasonImmutableConflict
			}
			var reasons []contract.DiagnosticReason
			for _, d := range got.Diagnostics {
				if d.Subject.Kind == contract.SubjectStore {
					reasons = append(reasons, d.Reason)
				}
			}
			creates, deletes := effects()
			if len(reasons) != 1 || reasons[0] != want || len(keys) != 2 || len(work.attempts) != 2 || cold.root.Generated.ActiveOwner != got.OperationID ||
				got.Result.Outcome != ObservedCurrent || len(got.Receipt) != 0 || creates != 2 || len(deletes) != 0 {
				t.Fatal("parallel return lost the selection or Store summary", reasons, got.Result.Outcome, len(work.attempts), creates, len(deletes))
			}
			for _, a := range work.attempts {
				if a.record.State != contract.GeneratedEffectTransmitted || len(a.result) != 0 {
					t.Fatal("uncertain sibling acquired result evidence")
				}
			}
		})
	}
}

// full_only: false
func TestInstalledManagedCreateRecoversAcrossStoreLoss(t *testing.T) {
	for _, mode := range []string{"reservation-not-sent", "reservation-ack-lost", "result-ack-lost", "result-cancel-and-save", "result-not-saved", "result-conflict", "result-denied", "result-cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			applyctx, cancelApply := context.WithCancel(ctx)
			defer cancelApply()
			process, count := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			f.env.GeneratedProcess = process
			input := installedGeneratedRetirementEntries(process, f.selected.admission.recipient, 0, "proposed")
			input[0].InputEncoding = contract.InputEncodingBase64
			base := requireAdmittedMemoryStore(t, f.env.Store)
			proxy := &applyPreparationTestStore{Store: base, memory: base}
			f.env.Store = proxy
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			var original contract.GeneratorAttemptTemplate
			var inbox string
			admit := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				x := in.Expected.Template
				if x.Branch == contract.GeneratorBranchInitial {
					original = x
					var err error
					inbox, err = format.GeneratedResultKey(base.desc.Prefix, f.env.Domain, x.InboxID)
					if err != nil {
						t.Fatal(err)
					}
				}
				return admit(ctx, q, control, in, row, deadline)
			}
			// Only the selected original inbox loses its write reply. The test
			// retains a digest for comparison, never a packet for recovery.
			var attemptedDigest contract.ID
			denyRead, invalidRead, interruptWrite := false, false, true
			proxy.read = func(ctx context.Context, key string, max uint32) contract.ReadResult {
				if key == inbox && invalidRead {
					return contract.ReadResult{Status: contract.ReadOK, Body: []byte("damaged packet")}
				}
				if key == inbox && denyRead {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
				}
				return base.Read(ctx, key, max)
			}
			proxy.create = func(ctx context.Context, key string, body []byte) contract.WriteResult {
				if key != inbox || !interruptWrite {
					return base.Create(ctx, key, body)
				}
				attemptedDigest = sha256.Sum256(body)
				if mode == "result-conflict" {
					invalidRead = true
					return contract.WriteResult{Status: contract.WritePrecondition}
				}
				if mode == "result-denied" || mode == "result-cancelled" {
					if mode == "result-cancelled" {
						cancelApply()
					}
					denyRead = true
					return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonAccess, NotSent: true}
				}
				denyRead = true
				if mode == "result-cancel-and-save" {
					cancelApply()
					if ctx.Err() != nil {
						t.Error("caller cancellation ended the sealed managed CREATE write")
					}
				}
				if mode == "result-ack-lost" || mode == "result-cancel-and-save" {
					if result := base.Create(ctx, key, body); result.Status != contract.WriteAcknowledged {
						t.Error("fixture did not commit the original result", result.Status)
					}
				}
				return contract.WriteResult{Status: contract.WriteUnknown, Reason: contract.ReasonTransport}
			}
			reservationCAS := base.cas
			switch mode {
			case "reservation-not-sent":
				base.casMode = "lost-before"
			case "reservation-ack-lost":
				base.casMode = "lost-after"
				base.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
					if key == base.desc.HeadKey && base.cas > reservationCAS {
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
					}
					return result
				}
			}
			engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, currentApplyRecipients(f.selected.registry()), callbacks)
			start := engine.Apply(applyctx, testID(mode+" apply"), input)
			engine.Close()
			interruptWrite = false
			if mode == "result-conflict" || mode == "result-denied" || mode == "result-cancelled" {
				want := contract.ReasonImmutableConflict
				if mode == "result-cancelled" {
					want = contract.ReasonCancelled
				}
				if mode == "result-denied" {
					want = contract.ReasonEvidenceUnavailable
				}
				matches := 0
				for _, d := range start.Diagnostics {
					if d.Subject.Kind == contract.SubjectStore && d.Reason == want {
						matches++
					}
				}
				if matches != 1 || start.Result.Outcome != ObservedCurrent || start.Result.Reason == CustodyUnavailable {
					t.Fatal("selected reservation lost its Store stop", mode, matches, start.Result.Outcome, start.Result.Reason)
				}
				invalidRead, denyRead = false, true
			}
			base.casMode = ""
			base.readHook = nil
			cold := f.open(t, ctx)
			creates, deletes := count()
			if original.AttemptID.IsZero() || len(start.Receipt) != 0 || len(deletes) != 0 {
				t.Fatal("did not reach the original reservation boundary", start.Result, creates, len(deletes))
			}
			t.Logf("predecessor=%x reopened=%x active=%t creates=%d deletes=%d", f.selected.head.Core.Revision, cold.head.Core.Revision, !cold.root.Generated.ActiveOwner.IsZero(), creates, len(deletes))
			if mode == "reservation-not-sent" {
				if base.cas == reservationCAS || start.Result.Outcome != EvidenceUnavailable || start.Result.CommitMayHaveOccurred || creates != 0 || !attemptedDigest.IsZero() || cold.head.Core.Revision != f.selected.head.Core.Revision || !cold.root.Generated.ActiveOwner.IsZero() {
					t.Fatal("failed reservation admitted an effect or changed HEAD", start.Result, creates)
				}
				return
			}
			work := mustSelectedGeneratedWork(t, cold)
			a, ok := work.attempts[original.AttemptID]
			if !ok || len(work.attempts) != 1 || len(a.result) != 0 || work.parent == nil || work.parent.OperationID != start.OperationID ||
				cold.root.Generated.ActiveOwner != start.OperationID || a.record.State != contract.GeneratedEffectTransmitted || a.record.InboxID != original.InboxID {
				t.Fatal("reopen lost the transmitted original or its inbox", start.Result)
			}
			pauseFinal := false
			resume := func(s *StateSession, label string) PublicApplyResult {
				t.Helper()
				// Fresh installation, without the first producer's private result.
				callbacks := installedGeneratedRetirementCallbacks(t, f, process)
				if pauseFinal {
					callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
						return nil, contract.ErrRecord
					}
				}
				next := installedGeneratedTestEngine(t, ctx, f, s, input, currentApplyRecipients(s.registry()), callbacks)
				defer next.Close()
				return next.Continue(ctx, testID(mode+" "+label), start.OperationID)
			}
			if mode == "reservation-ack-lost" {
				if start.Result.Outcome != UnresolvedCommit || !start.Result.CommitMayHaveOccurred || creates != 0 || !attemptedDigest.IsZero() {
					t.Fatal("observing a committed reservation restored the initial send")
				}
				checkFreshGeneratedProcess(t, base, cold)
				done := resume(cold, "missing result before dispatch")
				after := f.open(t, ctx)
				creates, deletes = count()
				if done.Generated == nil || done.Generated.StateResult != "effect-unknown" || !done.Generated.Warnings.PossibleLiveResidue ||
					!after.root.Generated.ActiveOwner.IsZero() || after.root.Generated.Hazards != 1 || creates != 0 || len(deletes) != 0 {
					t.Fatal("restart after a lost reservation reply created a token or lost the warning", done.Result, creates, deletes)
				}
				checkFreshGeneratedProcess(t, base, after)
				return
			}
			if creates != 1 || attemptedDigest.IsZero() {
				t.Fatal("inbox outage missed the provider return", creates)
			}
			blocked := resume(cold, "read denied")
			again := f.open(t, ctx)
			creates, deletes = count()
			if blocked.Result.Outcome != EvidenceUnavailable || blocked.Result.StoreReason != contract.ReasonAccess || again.head.Core.Revision != cold.head.Core.Revision ||
				creates != 1 || len(deletes) != 0 || len(blocked.Receipt) != 0 {
				t.Fatal("unreadable inbox advanced recovery", blocked.Result, creates, deletes)
			}
			denyRead = false
			invalidRead = true
			bad := resume(again, "damaged result")
			invalidRead = false
			creates, deletes = count()
			if bad.Result.Outcome != IntegrityFailure || len(bad.Receipt) != 0 || f.open(t, ctx).head.Core.Revision != again.head.Core.Revision || creates != 1 || len(deletes) != 0 {
				t.Fatal("invalid result advanced recovery", bad.Result, creates, deletes)
			}
			read := base.Read(ctx, inbox, uint32(contract.GeneratedResultRecordMaxLength))
			saved := mode == "result-ack-lost" || mode == "result-cancel-and-save"
			if saved {
				if read.Status != contract.ReadOK || sha256.Sum256(read.Body) != attemptedDigest {
					t.Fatal("committed inbox lost its exact bytes")
				}
			} else {
				if read.Status != contract.ReadMissing {
					t.Fatal("original result persisted unexpectedly", read.Status)
				}
				base.casMode = "lost-before"
				interrupted := resume(again, "fence write unavailable")
				base.casMode = ""
				again = f.open(t, ctx)
				creates, deletes = count()
				if interrupted.Result.Outcome == ObservedCurrent || len(interrupted.Receipt) != 0 || again.head.Core.Revision != cold.head.Core.Revision ||
					again.root.Generated.ActiveOwner != start.OperationID || creates != 1 || len(deletes) != 0 {
					t.Fatal("failed fence write released the domain or sent a request", interrupted.Result, creates, deletes)
				}
			}
			checkFreshGeneratedProcess(t, base, again)
			if !saved {
				pauseFinal = true
				interrupted := resume(again, "after durable fence")
				pauseFinal = false
				again = f.open(t, ctx)
				creates, deletes = count()
				fenced := mustSelectedGeneratedWork(t, again).attempts[original.AttemptID]
				if len(interrupted.Receipt) != 0 || again.root.Generated.ActiveOwner != start.OperationID || again.root.Generated.Hazards != 1 ||
					fenced.record.State != contract.GeneratedEffectClosedWithResidue || creates != 1 || len(deletes) != 0 {
					t.Fatal("interruption before Final lost the original attempt or released the domain", interrupted.Result, creates, deletes)
				}
				checkFreshGeneratedProcess(t, base, again)
			}
			done := resume(again, "read restored")
			final := f.open(t, ctx)
			creates, deletes = count()
			if done.Result.Outcome != ObservedCurrent || len(done.Receipt) == 0 || done.Generated == nil ||
				!final.root.Generated.ActiveOwner.IsZero() || final.root.Generated.GeneratedCurrent != 0 ||
				final.root.Generated.Hazards != 1 || creates != 1 || len(deletes) != 0 {
				t.Fatal("recovery did not close the original operation after one CREATE", done.Result, final.root.Generated, creates, deletes)
			}
			checkFreshGeneratedProcess(t, base, final)
			selection, found, err := final.readGeneratedCleanup(ctx)
			if err != nil || found != saved {
				t.Fatal("cleanup eligibility disagrees with the stored evidence", found, err)
			}
			originalState := mustSelectedGeneratedWork(t, final).attempts[original.AttemptID]
			const token = "00000000000000000000000000000001"
			if saved {
				if selection.kind != generatedCleanupHazard || selection.target.ResourceDigest != hermeticCloudflareResourceDigest(token) ||
					selection.target.OriginalAttemptID != original.AttemptID || originalState.record.State != contract.GeneratedEffectFailedTerminal ||
					sha256.Sum256(originalState.result) != attemptedDigest {
					t.Fatal("recovery lost the original result or exact cleanup target")
				}
			} else if originalState.record.State != contract.GeneratedEffectClosedWithResidue || len(originalState.result) != 0 ||
				done.Generated.StateResult != "effect-unknown" || !done.Generated.Warnings.PossibleLiveResidue ||
				len(done.Generated.Hazards) != 1 || done.Generated.Hazards[0].Record.OriginalAttemptID != original.AttemptID ||
				done.Generated.Hazards[0].Record.Exposure != contract.GeneratedExposurePossibleLive || done.Generated.Hazards[0].Target != nil {
				t.Fatal("closing an unknown CREATE lost the warning or assigned a target")
			}
			for _, label := range []string{"first terminal observation", "second terminal observation"} {
				seen := resume(f.open(t, ctx), label)
				if seen.Generated == nil || !seen.Generated.ReceiptObservation || !bytes.Equal(seen.Receipt, done.Receipt) ||
					!saved && !seen.Generated.Warnings.PossibleLiveResidue {
					t.Fatal("terminal continuation changed the receipt or warnings", seen.Result)
				}
			}
			cleaner := installedGeneratedRetirementEngine(t, ctx, f, final, installedGeneratedRetirementCallbacks(t, f, process))
			cleaned := cleaner.CleanupGenerated(ctx, testID(mode+" cleanup"))
			cleaner.Close()
			creates, deletes = count()
			after := f.open(t, ctx)
			if saved {
				if cleaned.Generated == nil || cleaned.Generated.StateResult != "success" || creates != 1 || !slices.Equal(deletes, []string{token}) || after.root.Generated.Hazards != 0 {
					t.Fatal("cleanup missed the original known token", cleaned.Result, creates, deletes)
				}
				return
			}
			if cleaned.Result.Outcome != Unchanged || creates != 1 || len(deletes) != 0 || after.head.Core.Revision != final.head.Core.Revision {
				t.Fatal("cleanup acted without a known target", cleaned.Result, creates, deletes)
			}
			plain := []ApplyEntryInput{{Name: "healthy", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{after.admission.recipient},
				InputBytes: []byte("independent"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}}
			writer := installedGeneratedTestEngine(t, ctx, f, after, plain, currentApplyRecipients(after.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			changed := writer.Apply(ctx, testID(mode+" independent apply"), plain)
			writer.Close()
			after = f.open(t, ctx)
			creates, deletes = count()
			if changed.Result.Outcome != ObservedCurrent || after.head.Core.Revision == final.head.Core.Revision || after.root.Generated.Hazards != 1 ||
				creates != 1 || len(deletes) != 0 {
				t.Fatal("independent apply lost the warning or sent a request", changed.Result, creates, deletes)
			}
			writer = installedGeneratedTestEngine(t, ctx, f, after, input, currentApplyRecipients(after.registry()), installedGeneratedRetirementCallbacks(t, f, process))
			replacement := writer.Apply(ctx, testID(mode+" explicit replacement"), input)
			writer.Close()
			creates, deletes = count()
			if replacement.OperationID == start.OperationID || replacement.Result.Outcome != ObservedCurrent || creates != 2 || len(deletes) != 0 {
				t.Fatal("new apply did not independently authorize exactly one replacement", replacement.Result, creates, deletes)
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedApplySelectsCompleteGeneratedAndSuppliedSet(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	selected := f.selected
	authority := selected.admission.recipient
	implementation := process.Implementation
	intent := bytes.Clone(process.Intent)
	declaration := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: intent}
	input := []ApplyEntryInput{
		{Name: "generated", Recipients: []contract.ID{authority}, ValueSource: contract.Generated,
			ConfidentialityClass: contract.Secret, Generated: &declaration},
		{Name: "plain", Recipients: []contract.ID{authority}, ValueSource: contract.Supplied,
			ConfidentialityClass: contract.Plain, InputBytes: []byte("complete supplied sibling")},
	}
	validator := NewPublicConfigurationValidator(nil)
	desired := currentApplyRecipients(selected.registry())
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
	configuration.Entries.Value[0].Generated = installedGeneratedPublicSettings(&declaration)
	configurationBefore := ownPublicConfiguration(configuration)
	intentBefore, plainBefore := bytes.Clone(intent), bytes.Clone(input[1].InputBytes)
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(),
		PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired,
		GeneratorImplementations: []contract.GeneratorImplementation{implementation}, Generated: installedGeneratedTestCallbacks(t, f, process), PublicConfiguration: configuration,
		ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition,
		FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {},
		AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore,
			current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector,
			witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows,
			warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
			owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"),
				plain, support, witness, revision, before, warningBits, deadline)
			if err != nil {
				return nil, err
			}
			return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
		}})
	if err != nil {
		t.Fatal("installed generated apply construction", err)
	}
	defer engine.Close()
	result := engine.Apply(ctx, fixtureID(f.env.Domain, "installed generated whole-set request"), input)
	if !reflect.DeepEqual(configuration, configurationBefore) || !bytes.Equal(intent, intentBefore) ||
		!bytes.Equal(input[1].InputBytes, plainBefore) || input[0].InputBytes != nil || declaration.Epoch != 0 ||
		!slices.Equal(input[0].Recipients, []contract.ID{authority}) || !slices.Equal(input[1].Recipients, []contract.ID{authority}) {
		t.Error("installed apply changed its complete source inputs")
	}
	creates, deletes := effects()
	if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.RequestIdentity.IsZero() ||
		creates != 1 || deletes != 0 {
		t.Fatal("installed apply did not select the complete generated and supplied set with one create", result.Result, creates, deletes)
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.OperationID != result.OperationID ||
		receipt.RequestIdentityDigest != result.RequestIdentity || receipt.StateResult != contract.ReceiptStateSuccess ||
		receipt.EffectSummary != contract.ReceiptEffectComplete || receipt.SummaryCounts[contract.ReceiptEffectCount] != 1 ||
		receipt.SummaryCounts[contract.ReceiptSummarySuccessCount] != 1 || receipt.ChangedSubjects.Count != 5 {
		t.Fatal("installed generated receipt differs from the complete selection", err, receipt)
	}
	cold := f.open(t, ctx)
	if cold.root.ValueEntryCount != 2 || cold.root.SecretCount != 1 || cold.root.MembershipCount != 2 ||
		cold.root.Generated.GeneratedCurrent != 1 || !cold.root.Generated.ActiveOwner.IsZero() ||
		!reflect.DeepEqual(cold.registry(), selected.registry()) {
		t.Fatal("cold selection lost the complete value set or changed the registry")
	}
	generatedAt := slices.IndexFunc(cold.root.Names, func(row format.NameEntry) bool { return row.Name == "generated" })
	plainAt := slices.IndexFunc(cold.root.Names, func(row format.NameEntry) bool { return row.Name == "plain" })
	if generatedAt < 0 || plainAt < 0 {
		t.Fatal("cold selection omitted a requested sibling")
	}
	generated, supplied := cold.valueEntry(cold.root.Names[generatedAt].Slot), cold.valueEntry(cold.root.Names[plainAt].Slot)
	if generated.ValueSource != contract.Generated || generated.ConfidentialityClass != contract.Secret ||
		generated.Generated.Epoch != 0 || generated.Generated.LifecycleMode != contract.GeneratorLifecycleManaged ||
		generated.Generated.ConfigContractID != implementation.ConfigContractID || generated.Generated.ResourceContractID != hermeticCloudflareResourceContractID() ||
		generated.Generated.OriginOperationID != result.OperationID ||
		generated.Generated.ResourceDigest != hermeticCloudflareResourceDigest("00000000000000000000000000000001") ||
		!slices.Equal(generated.Recipients, []contract.ID{authority}) ||
		supplied.ValueSource != contract.Supplied || supplied.ConfidentialityClass != contract.Plain ||
		!bytes.Equal(supplied.ValueBytes, plainBefore) || !slices.Equal(supplied.Recipients, []contract.ID{authority}) {
		t.Fatal("cold generated origin or supplied sibling differs from the exact request")
	}
	beforeNoOp := bytes.Clone(cold.body)
	noFresh := installedGeneratedTestCallbacks(t, f, process)
	noFresh.CheckCreateReadiness = func(context.Context, string, contract.GeneratorImplementation, []byte) error {
		t.Fatal("same-epoch current value requested fresh CREATE readiness")
		return contract.ErrRecord
	}
	unchanged := installedGeneratedTestEngine(t, ctx, f, cold, input, currentApplyRecipients(cold.registry()), noFresh)
	noOp := unchanged.Apply(ctx, fixtureID(f.env.Domain, "unchanged generated value"), input)
	unchanged.Close()
	afterNoOp := f.open(t, ctx)
	creates, deletes = effects()
	if noOp.Result.Outcome != Unchanged || !bytes.Equal(afterNoOp.body, beforeNoOp) || creates != 1 || deletes != 0 {
		t.Fatal("same-epoch current value changed state or entered a new effect", noOp.Result, creates, deletes)
	}
}

func installedGeneratedTestCallbacks(t testing.TB, f installedApplyTestFixture, process *generatedProcessFixture) *GeneratedApplyInstallation {
	t.Helper()
	wrap := func(owner *custody.InstalledGeneratedOwner, err error) (*InstalledGeneratedCustody, error) {
		if err != nil {
			return nil, err
		}
		return &InstalledGeneratedCustody{Crypto: owner, BindCandidate: owner.BindCandidate, Close: owner.Close}, nil
	}
	return &GeneratedApplyInstallation{
		NewRetirementReturnProof: f.keys.NewRetirementReturnProof,
		CheckCreateReadiness: func(ctx context.Context, _ string, row contract.GeneratorImplementation, intent []byte) error {
			if !reflect.DeepEqual(row, process.Implementation) || !bytes.Equal(intent, process.Intent) {
				return contract.ErrRecord
			}
			metadata, err := os.ReadFile(process.Artifact + ".metadata.json")
			if err != nil {
				return err
			}
			dependency, err := os.ReadFile(process.Artifact + ".dependencies.bin")
			if err != nil {
				return err
			}
			return installedGeneratorCreateReadiness(ctx, custody.GeneratedProcessConfig{ArtifactPath: process.Artifact, Artifact: row, Metadata: metadata, Dependency: dependency}, intent)
		},
		CheckRetirementCompatibility: func(ctx context.Context, row contract.GeneratorImplementation, intent []byte, facts contract.GeneratorSafeFacts, completion uint8) ([]byte, []byte, error) {
			return hermeticCloudflareRetirementExchange(ctx, process.Artifact, row, intent, facts, completion)
		},
		ResolveImplementation: func(request GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			row := process.Implementation
			if request.ConfigContractID != row.ConfigContractID || request.LifecycleMode != contract.GeneratorLifecycleManaged || request.ResourceContractID != hermeticCloudflareResourceContractID() {
				return row, contract.ErrRecord
			}
			return row, nil
		},
		RequestDigest: func(ctx context.Context, row contract.GeneratorImplementation, action uint8, intent []byte, target *contract.GeneratorTarget) (contract.ID, error) {
			if ctx.Err() != nil || !reflect.DeepEqual(row, process.Implementation) || action != contract.GeneratorActionCreate || target != nil || !bytes.Equal(intent, process.Intent) {
				return contract.ID{}, contract.ErrRecord
			}
			return process.RequestDigest, nil
		},
		AdmitReservation: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedReservation(q, control, input, fixtureID(f.env.Domain, "source-file"), deadline)
			return wrap(owner, err)
		},
		AdmitProducer: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
			config := process.Configure(t, process.Artifact, input.Expected)
			owner, err := f.keys.NewInstalledGeneratedProducer(ctx, q, control, input, config, deadline)
			base, err := wrap(owner, err)
			if err != nil {
				return nil, err
			}
			return &InstalledGeneratedProducerCustody{InstalledGeneratedCustody: *base, InvokeProducer: owner.InvokeProducer}, nil
		},
		AdmitAdoption: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedAdoptionInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedAdoption(q, control, input, deadline)
			return wrap(owner, err)
		},
		AdmitFinal: func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedFinalInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
			owner, err := f.keys.NewInstalledGeneratedFinal(q, control, input, deadline)
			return wrap(owner, err)
		},
	}
}

func installedGeneratedPublicSettings(g *contract.GeneratorDeclaredGeneration) *contract.PublicGeneratedSettings {
	public := &contract.PublicGeneratedSettings{Epoch: observedPublicField(g.Epoch), ConfigContractID: observedPublicField(g.ConfigContractID), ResourceContractID: observedPublicField(g.ResourceContractID), LifecycleMode: observedPublicField(g.LifecycleMode), ContentIntent: observedPublicField(bytes.Clone(g.Intent))}
	if g.LifecycleMode == contract.GeneratorLifecycleManaged {
		public.Retirement = observedPublicField(g.RetirementMode)
		public.Completion = observedPublicField(g.CompletionClass)
	}
	return public
}

func installedGeneratedTestEngine(t testing.TB, ctx context.Context, f installedApplyTestFixture, selected *StateSession, input []ApplyEntryInput, desired []contract.ApplyRecipientInput, callbacks *GeneratedApplyInstallation) *InstalledApply {
	t.Helper()
	implementation := f.env.GeneratedProcess.Implementation
	validator := NewPublicConfigurationValidator(selected.admission.outputInterpreter)
	configuration := installedApplyTestConfiguration(t, ctx, selected, input, desired, validator)
	for at := range configuration.Entries.Value {
		row := &configuration.Entries.Value[at]
		source := slices.IndexFunc(input, func(entry ApplyEntryInput) bool { return entry.Name == row.Name })
		if source < 0 || input[source].Generated == nil {
			continue
		}
		g := input[source].Generated
		row.Generated = installedGeneratedPublicSettings(g)
	}
	engine, err := NewInstalledApply(ApplyInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis, ExpectedControl: currentControlOf(selected), DesiredRecipients: desired, GeneratorImplementations: []contract.GeneratorImplementation{implementation}, Generated: callbacks, PublicConfiguration: configuration, ConfigurationValidator: validator, Store: f.env.Store, Trust: f.env.Trust, CompositionID: f.composition, FileIdentity: fixtureID(f.env.Domain, "source-file"), CloseInstalled: func() {}, AdmitCustody: func(ctx context.Context, q contract.CryptoCompareRequest, control contract.ControlCore, current []contract.RecipientRecord, plain []contract.MembershipRow, support contract.DescriptorVector, witness *contract.GeneratedSupportTransition, revision contract.ID, before contract.MutationReceiptWindows, warningBits uint8, deadline time.Time) (*InstalledApplyCustody, error) {
		owner, err := f.keys.NewApplyCustody(q, control, current, fixtureID(f.env.Domain, "source-file"), plain, support, witness, revision, before, warningBits, deadline)
		if err != nil {
			return nil, err
		}
		return &InstalledApplyCustody{Crypto: owner, BindReceipt: owner.BindReceipt, Close: owner.Close}, nil
	}})
	if err != nil {
		t.Fatal("installed generated engine", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

// full_only: false
func TestInstalledGeneratedContinueInstallsAcceptedRegistryAfterRestart(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recovery), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := configurationRecoveryLocalGeneratedProcess(t)
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, recovery)
			f.env.GeneratedProcess = process
			desired := installedApplyPreparedRecipient(t, f.selected, "generated registry creation nonce")
			created := slices.IndexFunc(desired, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
			pending := desired[created].Recipient.RecipientID
			for at := range desired {
				if desired[at].Recipient.RecipientID == f.selected.admission.recipient {
					desired[at].Recipient.DisplayName = "accepted authority display"
				}
			}
			readers := []contract.ID{f.selected.admission.recipient, pending}
			slices.SortFunc(readers, compareGeneratedIDs)
			meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, Epoch: 0, RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			input := []ApplyEntryInput{{Name: "generated", Recipients: readers, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Generated: &meta}, {Name: "plain", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, InputBytes: []byte("accepted complete sibling")}}
			callbacks := installedGeneratedTestCallbacks(t, f, process)
			traceOwner := func(stage string, owner *InstalledGeneratedCustody, err error) {
				t.Log("registry restart admission", stage, "owner present", owner != nil, "error", err)
				if owner != nil && owner.BindCandidate != nil {
					bind := owner.BindCandidate
					owner.BindCandidate = func(ctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
						code := bind(ctx, candidate)
						t.Log("registry restart binding", stage, "code", code)
						return code
					}
				}
			}
			admitReservation := callbacks.AdmitReservation
			callbacks.AdmitReservation = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedReservationInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
				owner, err := admitReservation(ctx, q, control, in, deadline)
				traceOwner("reservation", owner, err)
				return owner, err
			}
			admitProducer := callbacks.AdmitProducer
			callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admitProducer(ctx, q, control, in, implementation, deadline)
				if owner == nil {
					traceOwner("producer", nil, err)
				} else {
					traceOwner("producer", &owner.InstalledGeneratedCustody, err)
				}
				return owner, err
			}
			callbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
				traceOwner("intentional Final stop", nil, contract.ErrRecord)
				return nil, contract.ErrRecord
			}
			engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, desired, callbacks)
			initialInstallation := engine.installation
			stopped := engine.Apply(ctx, fixtureID(f.env.Domain, "generated stop before final"), input)
			engine.Close()
			creates, deletes := effects()
			cold := f.open(t, ctx)
			if stopped.OperationID.IsZero() || cold.root.Generated.ActiveOwner != stopped.OperationID || creates != 1 || deletes != 0 || !reflect.DeepEqual(cold.registry(), f.selected.registry()) {
				t.Log("registry restart selected state", "operation present", !stopped.OperationID.IsZero(), "active owner present", !cold.root.Generated.ActiveOwner.IsZero(), "active phase present", !cold.root.Generated.ActivePhase.IsZero())
				if stopped.OperationID.IsZero() {
					deadline, _ := ctx.Deadline()
					plan, err := f.selected.installedGeneratedPlan(ctx, initialInstallation, input, nil, deadline)
					t.Log("registry restart side-effect-free plan validation", "plan present", plan != nil, "error", err)
				}
				t.Fatal("pre-Final stop changed registry or lost exact active operation", stopped.Result, creates, deletes)
			}
			if stopped.Generated == nil || stopped.Payload != nil || len(stopped.Receipt) != 0 {
				t.Fatal("nonterminal apply exposed an unproved terminal payload", stopped.Generated, stopped.Payload)
			}
			selected, err := cold.selectedGeneratedWork(ctx)
			if err != nil || selected.registry == nil || !slices.Equal(selected.registry.InitiallyAbsent, []contract.ID{pending}) {
				t.Fatal("cold accepted recipient image missing", err)
			}
			for _, row := range desired {
				if row.Recipient.RecipientID == pending && cold.recipientRecord(pending) != nil {
					t.Fatal("pending recipient became current before Final")
				}
			}
			// A fresh installed invocation has an edited local complete proposal. Exact
			// continuation must use the retained proposal, including its original proof.
			input[1].InputBytes[0] = 'X'
			meta.Intent[0] = 'X'
			edited := []ApplyEntryInput{{Name: "edited", Recipients: []contract.ID{cold.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("unrelated local proposal")}}
			resumed := installedGeneratedTestEngine(t, ctx, f, cold, edited, currentApplyRecipients(cold.registry()), installedGeneratedTestCallbacks(t, f, process))
			got := resumed.Continue(ctx, fixtureID(f.env.Domain, "generated exact restart"), stopped.OperationID)
			resumed.Close()
			creates, deletes = effects()
			after := f.open(t, ctx)
			expectedRegistry := make([]contract.RecipientRecord, len(desired))
			for at, row := range desired {
				expectedRegistry[at] = row.Recipient
			}
			if got.Result.Outcome != ObservedCurrent || got.Generated == nil || got.Generated.ReceiptObservation || got.RequestIdentity != stopped.RequestIdentity || creates != 1 || deletes != 0 || !after.root.Generated.ActiveOwner.IsZero() || !reflect.DeepEqual(after.registry(), expectedRegistry) {
				t.Fatal("exact restart did not atomically install accepted registry", got.Result, creates, deletes)
			}
			plainAt := slices.IndexFunc(after.root.Names, func(row format.NameEntry) bool { return row.Name == "plain" })
			if plainAt < 0 || !bytes.Equal(after.valueEntry(after.root.Names[plainAt].Slot).ValueBytes, []byte("accepted complete sibling")) {
				t.Fatal("restart reread the edited supplied source")
			}
			generatorAt := slices.IndexFunc(after.root.Names, func(row format.NameEntry) bool { return row.Name == "generated" })
			generated := after.valueEntry(after.root.Names[generatorAt].Slot)
			if !slices.Equal(generated.Recipients, readers) {
				t.Fatal("Final omitted accepted pending recipient membership")
			}
			selection := sessionConsumerSelection(t, after, after.admission.recipient, "generated")
			if len(selection.Access.Wraps) != len(readers)+boolInt(recovery) {
				t.Fatal("Final has inexact pending/Recovery wrap coverage")
			}
			receiptOnlyCallbacks := installedGeneratedTestCallbacks(t, f, process)
			receiptOnlyCallbacks.ResolveImplementation = func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
				t.Error("terminal receipt lookup resolved an old producer")
				return contract.GeneratorImplementation{}, contract.ErrRecord
			}
			receiptOnlyCallbacks.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
				t.Error("terminal receipt lookup entered private custody")
				return nil, contract.ErrRecord
			}
			observer := installedGeneratedTestEngine(t, ctx, f, after, edited, currentApplyRecipients(after.registry()), receiptOnlyCallbacks)
			observed := observer.Continue(ctx, fixtureID(f.env.Domain, "generated terminal observation"), stopped.OperationID)
			observer.Close()
			if observed.Result.Outcome != ObservedCurrent || observed.Generated == nil || !observed.Generated.ReceiptObservation || observed.Generated.EffectsAvailable || observed.Generated.RelatedWorkAvailable || observed.Generated.StateResult != got.Generated.StateResult || !bytes.Equal(observed.Receipt, got.Receipt) {
				t.Fatal("terminal receipt observation fabricated complete effect history or changed historical token")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedPlanRequiresFreshReadinessBeforeRequestBinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := configurationRecoveryLocalGeneratedProcess(t)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
		LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
		ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
		CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	input := []ApplyEntryInput{{Name: "generated", Recipients: []contract.ID{f.selected.admission.recipient},
		ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Generated: &meta}}
	requestCalls := 0
	installation := ApplyInstallation{DesiredRecipients: currentApplyRecipients(f.selected.registry()), Generated: &GeneratedApplyInstallation{
		ResolveImplementation: func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
			return process.Implementation, nil
		},
		RequestDigest: func(context.Context, contract.GeneratorImplementation, uint8, []byte, *contract.GeneratorTarget) (contract.ID, error) {
			requestCalls++
			return process.RequestDigest, nil
		},
	}}
	deadline, _ := ctx.Deadline()
	plan, err := f.selected.installedGeneratedPlan(ctx, installation, input, nil, deadline)
	creates, deletes := effects()
	if err == nil || plan != nil || requestCalls != 0 || creates != 0 || deletes != 0 {
		t.Fatal("fresh CREATE without readiness reached request binding", "plan", plan != nil, "error", err,
			"request calls", requestCalls, "creates", creates, "deletes", deletes)
	}
	refused := errors.Join(contract.ErrRecord, errors.New("selected generator cannot create"))
	installation.Generated.CheckCreateReadiness = func(context.Context, string, contract.GeneratorImplementation, []byte) error { return refused }
	if plan, err := f.selected.installedGeneratedPlan(ctx, installation, input, nil, deadline); !errors.Is(err, refused) || plan != nil || requestCalls != 0 {
		t.Fatal("fresh readiness refusal reached request binding or lost its cause", plan != nil, err, requestCalls)
	}
	f.env.GeneratedProcess = process
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	refusedCalls := 0
	callbacks.CheckCreateReadiness = func(context.Context, string, contract.GeneratorImplementation, []byte) error {
		refusedCalls++
		return refused
	}
	callbacks.RequestDigest = installation.Generated.RequestDigest
	engine := installedGeneratedTestEngine(t, ctx, f, f.selected, input, installation.DesiredRecipients, callbacks)
	refusal := engine.Apply(ctx, testID("refused fresh generator settings"), input)
	engine.Close()
	cold := f.open(t, ctx)
	creates, deletes = effects()
	if refusal.Result.Outcome != AdmissionRefused || refusal.Result.CommitMayHaveOccurred || !bytes.Equal(cold.body, f.selected.body) ||
		!cold.root.Generated.ActiveOwner.IsZero() || refusedCalls != 1 || requestCalls != 0 || creates != 0 || deletes != 0 {
		t.Fatalf("semantic refusal: outcome=%d commit=%t same_head=%t active_owner=%t readiness=%d requests=%d creates=%d deletes=%d", refusal.Result.Outcome, refusal.Result.CommitMayHaveOccurred, bytes.Equal(cold.body, f.selected.body), !cold.root.Generated.ActiveOwner.IsZero(), refusedCalls, requestCalls, creates, deletes)
	}
	readyCalls := 0
	installation.Generated.CheckCreateReadiness = func(ctx context.Context, name string, row contract.GeneratorImplementation, intent []byte) error {
		readyCalls++
		if ctx.Err() != nil || name != "generated" || !reflect.DeepEqual(row, process.Implementation) || !bytes.Equal(intent, process.Intent) {
			t.Fatal("fresh readiness did not receive the exact resolved current input")
		}
		return nil
	}
	if plan, err := f.selected.installedGeneratedPlan(ctx, installation, input, nil, deadline); err != nil || plan == nil || requestCalls != 1 || readyCalls != 1 {
		t.Fatal("accepted fresh readiness did not precede request binding", plan != nil, err, requestCalls, readyCalls)
	}
	creates, deletes = effects()
	if creates != 0 || deletes != 0 {
		t.Fatal("fresh planning entered provider effects", creates, deletes)
	}
}

// full_only: false
func TestInstalledMaximumGeneratedResultResumesAfterReopen(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	t.Setenv("ENKV_GENERATOR_TEST_TOKEN", "fixture-only")
	config := custody.BuildInstalledHostTestGenerator(t, installedLocalPublicRoot(t))
	resource := sha256.Sum256([]byte{22})
	settings := []byte(`{"maximum_result":true}`)
	intent, err := protocol.EncodeIntent(protocol.Intent{Schema: 1, LifecycleMode: protocol.LifecycleManaged, ConfigContractID: protocol.ID(config.Artifact.ConfigContractID), ResourceContractID: resource, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	process := &generatedProcessFixture{Artifact: config.ArtifactPath, Implementation: config.Artifact, Intent: intent, RequestDigest: contract.Hash(intent),
		Configure: func(testing.TB, string, contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return config
		}}
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	meta := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, ConfigContractID: config.Artifact.ConfigContractID, ResourceContractID: resource, Intent: intent}
	input := []ApplyEntryInput{{Name: "maximum", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Generated: meta, InputEncoding: contract.InputEncodingBase64, OutputEncoding: contract.OutputEncodingRaw}}
	callbacks := installedGeneratedTestCallbacks(t, f, process)
	callbacks.ResolveImplementation = func(q GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
		if q.ConfigContractID != config.Artifact.ConfigContractID || q.ResourceContractID != resource || q.LifecycleMode != contract.GeneratorLifecycleManaged {
			return contract.GeneratorImplementation{}, contract.ErrRecord
		}
		return config.Artifact, nil
	}
	callbacks.CheckCreateReadiness = func(ctx context.Context, _ string, row contract.GeneratorImplementation, actual []byte) error {
		if !reflect.DeepEqual(row, config.Artifact) || !bytes.Equal(actual, intent) {
			return contract.ErrRecord
		}
		err := installedGeneratorCreateReadiness(ctx, config, actual)
		if err != nil {
			t.Log("native create readiness", err)
		}
		return err
	}
	var creates int
	admit := callbacks.AdmitProducer
	callbacks.AdmitProducer = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, row contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
		producer, err := admit(ctx, q, control, in, row, deadline)
		if err != nil {
			t.Log("native producer admission", err)
		}
		if err != nil {
			return nil, err
		}
		invoke := producer.InvokeProducer
		producer.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
			creates++
			return invoke(ctx, locator, authority)
		}
		return producer, nil
	}
	run := func(s *StateSession, c GeneratedApplyInstallation) *InstalledApply {
		return installedGeneratedTestEngine(t, ctx, f, s, input, currentApplyRecipients(s.registry()), &c)
	}
	beforeAdoption := *callbacks
	beforeAdoption.AdmitAdoption = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedAdoptionInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	engine := run(f.selected, beforeAdoption)
	started := engine.Apply(ctx, testID("maximum create"), input)
	if started.OperationID.IsZero() {
		deadline, _ := ctx.Deadline()
		_, planErr := f.selected.installedGeneratedPlan(ctx, engine.installation, input, nil, deadline)
		t.Log("native maximum plan", planErr)
	}
	engine.Close()
	cold := f.open(t, ctx)
	if started.OperationID.IsZero() || cold.root.Generated.ActiveOwner != started.OperationID || creates != 1 {
		t.Fatal("result was not saved before adoption", started.Result, creates)
	}
	work := mustSelectedGeneratedWork(t, cold)
	attempt := work.phase.FrontierAttemptID
	inbox, found, read := cold.readGeneratedResult(ctx, attempt)
	if !found || len(inbox) != 92_637 {
		t.Fatal("cold result inbox", read, found, len(inbox))
	}
	beforeFinal := *callbacks
	beforeFinal.AdmitFinal = func(context.Context, contract.CryptoGeneratedCompareRequest, contract.ControlCore, contract.GeneratedFinalInput, time.Time) (*InstalledGeneratedCustody, error) {
		return nil, contract.ErrRecord
	}
	engine = run(cold, beforeFinal)
	recorded := engine.Continue(ctx, testID("maximum record"), started.OperationID)
	engine.Close()
	cold = f.open(t, ctx)
	selected := mustSelectedGeneratedWork(t, cold)
	a := selected.attempts[attempt]
	if cold.root.Generated.ActiveOwner != started.OperationID || !bytes.Equal(a.result, inbox) || creates != 1 {
		t.Fatal("reopened support did not contain the original result", recorded.Result, len(a.result), creates)
	}
	engine = run(cold, *callbacks)
	finished := engine.Continue(ctx, testID("maximum final"), started.OperationID)
	engine.Close()
	cold = f.open(t, ctx)
	if finished.Result.Outcome != ObservedCurrent || !cold.root.Generated.ActiveOwner.IsZero() || cold.root.Generated.GeneratedCurrent != 1 || creates != 1 {
		t.Fatal("maximum result did not finish exactly once", finished.Result, creates)
	}
	t.Logf("predecessor=%x selected=%x result_bytes=%d creates=%d", f.selected.head.Core.Revision, cold.head.Core.Revision, len(inbox), creates)
	_, entry := observeCurrentValueEntry(t, cold, "maximum")
	if entry.Generated.CreateResultID != a.record.ResultID || entry.ContentLength != 65_536 || entry.RetainedLength != 87_384 || entry.InputEncoding != contract.InputEncodingBase64 {
		t.Fatal("selected value differs from the original result", entry.ContentLength, entry.RetainedLength)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "maximum.private")
	capture := f.keys.CaptureSelected(ctx, sessionConsumerSelection(t, cold, cold.admission.recipient, "maximum"), path)
	if capture.Code != contract.CryptoSuccess || capture.Delivery != 1 || !capture.ValueMatched || capture.SinkCalls != 1 {
		t.Fatal("maximum selected secret delivery", capture.Code, capture.SinkCalls)
	}
	got, err := os.ReadFile(path)
	defer clear(got)
	if err != nil || !bytes.Equal(got, base64.StdEncoding.AppendEncode(nil, bytes.Repeat([]byte{0xfb}, 65_536))) {
		t.Fatal("maximum selected secret differs from the original retained bytes", len(got), err)
	}

}
