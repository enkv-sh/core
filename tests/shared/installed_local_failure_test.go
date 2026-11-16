package core

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

type installedLocalFailureObservedCrypto struct {
	contract.Crypto
	after func(contract.CryptoRequest, contract.CryptoResponse)
}

func (c installedLocalFailureObservedCrypto) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	out := c.Crypto.Exchange(ctx, q)
	c.after(q, out)
	return out
}

// full_only: false
func TestInstalledLocalGeneratorJoinedEntropyFailureHasNoRemoteOwner(t *testing.T) {
	root := installedLocalPublicRoot(t)
	unavailable := installedLocalAuthor{config: custody.BuildInstalledUnavailableLocalAuthor(t, root)}
	invalid := installedLocalAuthor{config: custody.BuildInstalledInvalidLocalAuthor(t, root)}
	cancelled := installedLocalAuthor{config: custody.BuildInstalledCancelledLocalAuthor(t, root)}
	for _, tc := range []struct {
		name, fault string
		author      installedLocalAuthor
		reason      uint8
	}{
		{"none", "none", unavailable, contract.GeneratorFailureUnavailable},
		{"cancel after failure claim", "cancel after failure claim", unavailable, contract.GeneratorFailureUnavailable},
		{"failure CAS lost-before", "failure CAS lost-before", unavailable, contract.GeneratorFailureUnavailable},
		{"failure CAS lost-after", "failure CAS lost-after", unavailable, contract.GeneratorFailureUnavailable},
		{"invalid callback", "none", invalid, contract.GeneratorFailureInvalid},
		{"cancelled callback", "none", cancelled, contract.GeneratorFailureCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			author, fault := tc.author, tc.fault
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			store := requireAdmittedMemoryStore(t, f.env.Store)
			trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
			if !ok {
				t.Fatal("actual admitted trust observer unavailable")
			}
			beforeEntries := make(map[uint16]contract.ID)
			for _, row := range f.selected.root.Names {
				digest, err := contract.PublicValueEntryDigest(f.env.Domain, row.Slot, *f.selected.valueEntry(row.Slot))
				if err != nil {
					t.Fatal(err)
				}
				beforeEntries[row.Slot] = digest
			}
			row := author.config.Artifact
			declared := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone,
				ConfigContractID: row.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
				Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declared}}
			admissions := 0
			engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions)
			callbacks := engine.installation.Generated
			admitProducer := callbacks.AdmitProducer
			var invocations, joined, sealed, prepare9, claims atomic.Int64
			var inbox string
			var terminalAttempt contract.ID
			var canceledCreates, canceledCAS, canceledSigns int
			baselineCAS := len(store.casBodies)
			var writes []generatedWriterWrite
			store.writerWrites = &writes
			defer func() { store.writerWrites = nil; store.readHook = nil; store.casMode = "" }()
			callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admitProducer(callctx, q, control, in, implementation, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				terminalAttempt = in.Attempt.AttemptID
				inbox, err = format.GeneratedResultKey(store.desc.Prefix, f.env.Domain, in.Expected.Template.InboxID)
				if err != nil {
					t.Fatal(err)
				}
				invoke, closeOwner := owner.InvokeProducer, owner.Close
				owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
					invocations.Add(1)
					returned := invoke(ctx, locator, authority)
					body := returned.Record
					if len(body) != 0 {
						sealed.Add(1)
					}
					return returned
				}
				owner.Close = sync.OnceFunc(func() { closeOwner(); joined.Add(1) })
				admitFailure := owner.AdmitLocalFailure
				if admitFailure == nil || owner.LocalFailureReason == nil {
					t.Fatal("actual local receiver has no bound failure admission")
				}
				owner.AdmitLocalFailure = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedLocalFailureInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
					if invocations.Load() != 1 || joined.Load() != 1 || input.Attempt.FailureReason != tc.reason {
						t.Fatal("failure admission preceded original join or lost actual SDK reason")
					}
					continued, err := admitFailure(ctx, q, control, input, deadline)
					if err != nil || continued == nil {
						return continued, err
					}
					continued.Crypto = installedLocalFailureObservedCrypto{Crypto: continued.Crypto, after: func(request contract.CryptoRequest, reply contract.CryptoResponse) {
						if request.Kind == contract.CryptoPrepare {
							prepared, err := contract.InspectCryptoGeneratedPrepareRequest(request)
							if err != nil || prepared.Variant != contract.CryptoGeneratedPrepareLocalFailure {
								t.Fatal("resultless local transition used ordinary adoption")
							}
							if reply.ResultCode == contract.CryptoSuccess {
								prepare9.Add(1)
							}
						}
						if request.Kind == contract.CryptoClaim && reply.ResultCode == contract.CryptoSuccess {
							claims.Add(1)
							if fault == "cancel after failure claim" {
								canceledCreates, canceledCAS, canceledSigns = store.creates, store.cas, trust.signs
								cancel()
							}
						}
					}}
					bind := continued.BindCandidate
					continued.BindCandidate = func(ctx context.Context, candidate contract.GeneratedCandidateInput) contract.CryptoResultCode {
						code := bind(ctx, candidate)
						if code == contract.CryptoSuccess && fault != "none" && fault != "cancel after failure claim" {
							store.casMode = fault[len("failure CAS "):]
							beforeCAS := store.cas
							store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
								if key == store.desc.HeadKey && store.cas > beforeCAS {
									return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
								}
								return result
							}
						}
						return code
					}
					return continued, nil
				}
				return owner, nil
			}
			got := engine.Apply(ctx, fixtureID(f.env.Domain, "joined actual local failure "+tc.name), input)
			engine.Close()
			if admissions != 1 || invocations.Load() != 1 || joined.Load() != 1 || sealed.Load() != 0 || prepare9.Load() != 1 || claims.Load() != 1 {
				t.Fatalf("actual local failure did not traverse one joined resultless transition: admissions=%d invocations=%d joined=%d sealed=%d prepare9=%d claims=%d outcome=%d reason=%d operation_present=%t", admissions, invocations.Load(), joined.Load(), sealed.Load(), prepare9.Load(), claims.Load(), got.Result.Outcome, got.Result.Reason, !got.OperationID.IsZero())
			}
			for _, write := range writes {
				if write.Key == inbox {
					t.Fatal("callback failure published a result inbox")
				}
			}
			if fault == "cancel after failure claim" && (store.creates != canceledCreates || store.cas != canceledCAS || trust.signs != canceledSigns) {
				t.Fatal("ended original context reached signing or persistence")
			}
			store.readHook, store.casMode = nil, ""
			readctx, readcancel := context.WithTimeout(t.Context(), time.Minute)
			defer readcancel()
			cold := f.open(t, readctx)
			if cold.root.Generated.GeneratedCurrent != 0 || cold.root.Generated.Retiring != 0 || cold.root.Generated.Hazards != 0 || len(cold.root.Names) != len(beforeEntries) {
				t.Fatal("local failure changed canonical values or created a remote owner")
			}
			for _, row := range cold.root.Names {
				digest, err := contract.PublicValueEntryDigest(f.env.Domain, row.Slot, *cold.valueEntry(row.Slot))
				if err != nil || digest != beforeEntries[row.Slot] {
					t.Fatal("nonselecting local failure changed a previous selected member", err)
				}
			}
			if fault == "none" {
				receipt, err := contract.InspectCompactMutationReceipt(got.Receipt)
				if err != nil || receipt.StateResult != contract.ReceiptStateEffectTerminalFailure || !cold.root.Generated.ActiveOwner.IsZero() {
					t.Fatal("joined local failure did not complete nonselecting Final", got.Result, err)
				}
			} else {
				work := mustSelectedGeneratedWork(t, cold)
				a, present := work.attempts[terminalAttempt]
				if !present || work.parent == nil || work.parent.OperationID != got.OperationID {
					t.Fatal("uncertain or canceled selection lost original active support")
				}
				wantState := uint8(contract.GeneratedEffectTransmitted)
				if fault == "failure CAS lost-after" {
					wantState = contract.GeneratedEffectFailedTerminal
				}
				if a.record.State != wantState || wantState == contract.GeneratedEffectFailedTerminal && a.record.FailureReason != tc.reason {
					t.Fatal("cold failure readback does not match actual selected CAS outcome")
				}
			}
			purpose13 := 0
			for _, raw := range store.casBodies[baselineCAS:] {
				head, err := format.DecodeHead(raw)
				if err != nil {
					t.Fatal(err)
				}
				if head.Generator != nil && head.Generator.Purpose == contract.GeneratorAuthorityFailedTerminal {
					purpose13++
				}
			}
			if fault == "cancel after failure claim" && purpose13 != 0 || fault != "cancel after failure claim" && purpose13 != 1 {
				t.Fatal("local failure attempted an unexpected number of purpose13 selections", purpose13)
			}
		})
	}
}

// full_only: false
func TestInstalledLocalGeneratorExportedResultPUTNeverBecomesCallbackFailure(t *testing.T) {
	author := buildInstalledLocalAuthor(t, false)
	for _, mode := range []string{"lost-before", "lost-after", "delayed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			store := requireAdmittedMemoryStore(t, f.env.Store)
			row := author.config.Artifact
			declared := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone,
				ConfigContractID: row.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
				Recipients: []contract.ID{f.selected.admission.recipient}, Generated: &declared}}
			admissions := 0
			engine := installedLocalEngine(t, ctx, f, f.selected, input, author, &admissions)
			callbacks := engine.installation.Generated
			admitProducer := callbacks.AdmitProducer
			var invokes, joins, sealed, failureAdmissions atomic.Int64
			var failureReason func() uint8
			var inbox, attemptKey string
			var attemptID contract.ID
			createsBeforePUT := -1
			callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admitProducer(callctx, q, control, in, implementation, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				attemptID = in.Attempt.AttemptID
				inbox, err = format.GeneratedResultKey(store.desc.Prefix, f.env.Domain, in.Expected.Template.InboxID)
				if err != nil {
					t.Fatal(err)
				}
				attemptKey = inbox
				failureReason = owner.LocalFailureReason
				invoke, closeOwner := owner.InvokeProducer, owner.Close
				owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
					invokes.Add(1)
					returned := invoke(ctx, locator, authority)
					body := returned.Record
					if returned.Code != contract.CryptoSuccess || len(body) == 0 {
						t.Error("actual public author did not export one successful sealed Result")
						return returned
					}
					sealed.Add(1)
					// This controlled per-call bit proves Core carry across the later
					// PUT refusal. Separate native fixtures prove host qualification.
					returned.ExecutableCleanupFailed = true
					createsBeforePUT = store.creates
					store.createMode = mode
					store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
						if key == attemptKey {
							return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
						}
						return result
					}
					return returned
				}
				owner.Close = sync.OnceFunc(func() { closeOwner(); joins.Add(1) })
				admitFailure := owner.AdmitLocalFailure
				if admitFailure != nil {
					owner.AdmitLocalFailure = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedLocalFailureInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
						failureAdmissions.Add(1)
						return admitFailure(ctx, q, control, in, deadline)
					}
				}
				return owner, nil
			}
			got := engine.Apply(ctx, fixtureID(f.env.Domain, "local successful result PUT "+mode), input)
			engine.Close()
			cleanupRows := 0
			for _, diagnostic := range got.Diagnostics {
				if generatorCleanupDiagnostic(diagnostic) {
					cleanupRows++
				}
			}
			if cleanupRows != 1 {
				t.Fatal("later result PUT refusal lost the invocation cleanup evidence", cleanupRows)
			}
			if admissions != 1 || invokes.Load() != 1 || joins.Load() != 1 || sealed.Load() != 1 || createsBeforePUT < 0 || store.creates-createsBeforePUT != 1 ||
				failureAdmissions.Load() != 0 || failureReason == nil || failureReason() != 0 {
				t.Fatal("successful export or uncertain PUT gained local-failure authority", admissions, invokes.Load(), joins.Load(), sealed.Load(), store.creates-createsBeforePUT, failureAdmissions.Load())
			}
			store.createMode, store.readHook = "", nil
			cold := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, cold)
			a, present := work.attempts[attemptID]
			if !present || work.parent == nil || work.parent.OperationID != got.OperationID || a.record.State != contract.GeneratedEffectTransmitted ||
				a.record.FailureReason != 0 || cold.root.Generated.Hazards != 0 || cold.root.Generated.GeneratedCurrent != 0 {
				t.Fatal("unknown original result PUT lost its exact active readback closure")
			}
			if mode == "delayed" {
				late := store.late
				store.late = nil
				if late == nil || late() != nil {
					t.Fatal("existing delayed immutable PUT did not publish its original bytes")
				}
			}
			continued := installedLocalEngine(t, ctx, f, cold, input, author, &admissions)
			resumed := continued.Continue(ctx, fixtureID(f.env.Domain, "read actual original local result "+mode), got.OperationID)
			continued.Close()
			after := f.open(t, ctx)
			if admissions != 1 || invokes.Load() != 1 || failureAdmissions.Load() != 0 || after.root.Generated.Hazards != 0 {
				t.Fatal("cold original-result readback repeated the callback or created local remote work")
			}
			if mode == "lost-before" {
				if after.root.Generated.ActiveOwner != got.OperationID || after.root.Generated.GeneratedCurrent != 0 {
					t.Fatal("missing result without receiver authority invented a terminal outcome", resumed.Result)
				}
			} else {
				if resumed.Result.Outcome != ObservedCurrent || !after.root.Generated.ActiveOwner.IsZero() || after.root.Generated.GeneratedCurrent != 1 {
					t.Fatal("exact original ciphertext was not ordinarily adopted", resumed.Result)
				}
				captureInstalledLocalValue(t, ctx, f, after, "local")
			}
			if inbox == "" {
				t.Fatal("fixture did not bind the actual result coordinate")
			}
		})
	}
}

// full_only: false
func TestInstalledLocalGeneratorMixedFinalPreservesActualCFClosure(t *testing.T) {
	// Spec 019: SHA256("ENKV/GENERATOR/v1/progress\x00" || 00000004 ||
	// 00000000), independently hashed from the framed empty u32 count.
	wantEmptyProgress := contract.GeneratorDescriptor{Digest: contract.ID{
		0x67, 0x9e, 0xbb, 0xa2, 0xdd, 0xf0, 0x04, 0xca,
		0xff, 0xac, 0x67, 0x1f, 0xc6, 0x1c, 0x5b, 0x38,
		0x38, 0x49, 0x5c, 0xdc, 0x81, 0xfd, 0x32, 0x9e,
		0xe9, 0x98, 0x22, 0x6f, 0x2d, 0x93, 0xe2, 0x05,
	}, Length: 4, Count: 0}
	failedAuthor := installedLocalAuthor{config: custody.BuildInstalledUnavailableLocalAuthor(t, installedLocalPublicRoot(t))}
	successAuthor := buildInstalledLocalAuthor(t, false)
	for _, scenario := range []string{"local failure first", "local failure last", "successful local discarded"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			var process *generatedProcessFixture
			var creates func() int
			if scenario == "successful local discarded" {
				p, count := installedGeneratedMixedProcess(t)
				process, creates = p, func() int { return int(count()) }
			} else {
				p, count := installedGeneratedRetirementProcess(t, "acknowledged")
				process, creates = p, func() int {
					n, deleted := count()
					if len(deleted) != 0 {
						t.Error("failed Final entered a remote DELETE")
					}
					return n
				}
			}
			f.env.GeneratedProcess = process
			remote := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged,
				RetirementMode: contract.GeneratedRetirementManual, ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
				CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			localName, remoteName := "alpha", "omega"
			if scenario == "local failure last" {
				localName, remoteName = remoteName, localName
			}
			prior := f.selected
			if scenario == "successful local discarded" {
				initialInput := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: remoteName, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{prior.admission.recipient}, Generated: remote}}
				initial := installedGeneratedTestEngine(t, ctx, f, prior, initialInput, currentApplyRecipients(prior.registry()), installedGeneratedRetirementCallbacks(t, f, process))
				if got := initial.Apply(ctx, fixtureID(f.env.Domain, "mixed failure prior actual CF"), initialInput); got.Result.Outcome != ObservedCurrent {
					t.Fatal("actual controlled CF predecessor did not select", got.Result)
				}
				initial.Close()
				prior = f.open(t, ctx)
				remote.Epoch = 1
			}
			before := make(map[uint16]contract.ID)
			for _, named := range prior.root.Names {
				digest, err := contract.PublicValueEntryDigest(f.env.Domain, named.Slot, *prior.valueEntry(named.Slot))
				if err != nil {
					t.Fatal(err)
				}
				before[named.Slot] = digest
			}
			author := failedAuthor
			if scenario == "successful local discarded" {
				author = successAuthor
			}
			row := author.config.Artifact
			local := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone,
				ConfigContractID: row.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
			input := []ApplyEntryInput{{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: localName, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{prior.admission.recipient}, Generated: local},
				{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: remoteName, ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{prior.admission.recipient}, Generated: remote}}
			admissions := 0
			engine := installedLocalEngine(t, ctx, f, prior, input, author, &admissions)
			callbacks := engine.installation.Generated
			admitProducer := callbacks.AdmitProducer
			var invoked, joined, localInvoked, remoteInvoked, localFailures atomic.Int64
			var localAttempt contract.GeneratedAttemptRecord
			var localCapacity contract.GeneratorDescriptor
			var material contract.ID
			var localReference contract.GeneratorResultReference
			baselineCreates := creates()
			callbacks.AdmitProducer = func(callctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, in contract.GeneratedProducerInput, implementation contract.GeneratorImplementation, deadline time.Time) (*InstalledGeneratedProducerCustody, error) {
				owner, err := admitProducer(callctx, q, control, in, implementation, deadline)
				if err != nil || owner == nil {
					return owner, err
				}
				isLocal := in.Expected.Template.SemanticLifecycleMode() == contract.GeneratorLifecycleNone
				if isLocal {
					localAttempt, localCapacity, material = in.Attempt, in.Duty.CapacityReservation, in.Custody.Material.Core.OperationMaterialID
				}
				if isLocal && owner.AdmitLocalFailure != nil {
					admitFailure := owner.AdmitLocalFailure
					owner.AdmitLocalFailure = func(ctx context.Context, q contract.CryptoGeneratedCompareRequest, control contract.ControlCore, input contract.GeneratedLocalFailureInput, deadline time.Time) (*InstalledGeneratedCustody, error) {
						localFailures.Add(1)
						phase := input.Session.SelectionPhase
						wantPriorResults := uint32(0)
						if scenario == "local failure last" {
							wantPriorResults = 1
						}
						if phase == nil || phase.AcceptedResults.Count != wantPriorResults || input.Attempt.FailureReason != contract.GeneratorFailureUnavailable {
							t.Fatal("mixed failure did not bind the exact original-order recording cursor")
						}
						return admitFailure(ctx, q, control, input, deadline)
					}
				}
				invoke, closeOwner := owner.InvokeProducer, owner.Close
				owner.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
					invoked.Add(1)
					if isLocal {
						localInvoked.Add(1)
					} else {
						remoteInvoked.Add(1)
					}
					returned := invoke(ctx, locator, authority)
					body := returned.Record
					if isLocal && len(body) != 0 {
						localReference = contract.GeneratorResultReference{Schema: 1, ResultID: in.Attempt.ResultID, ResultBodyDigest: contract.Hash(body), ResultLength: uint32(len(body))}
					}
					return returned
				}
				owner.Close = sync.OnceFunc(func() { closeOwner(); joined.Add(1) })
				return owner, nil
			}
			got := engine.Apply(ctx, fixtureID(f.env.Domain, "actual native local mixed "+scenario), input)
			engine.Close()
			cold := f.open(t, ctx)
			work := mustSelectedGeneratedWork(t, cold)
			if got.Result.Outcome != ObservedCurrent || got.Generated == nil || work.parent != nil || len(cold.root.Names) != len(before) || localInvoked.Load() != 1 || invoked.Load() != joined.Load() || admissions != int(invoked.Load()) || creates()-baselineCreates != int(remoteInvoked.Load()) {
				t.Fatal("actual mixed Final did not conserve the complete predecessor and joined originals", got.Result, admissions, invoked.Load(), joined.Load())
			}
			for _, named := range cold.root.Names {
				digest, err := contract.PublicValueEntryDigest(f.env.Domain, named.Slot, *cold.valueEntry(named.Slot))
				if err != nil || digest != before[named.Slot] {
					t.Fatal("mixed failure partially selected a proposed member", err)
				}
			}
			for _, row := range cold.supportRecords() {
				if row.Kind == contract.GeneratedDutySupportKind {
					duty, err := contract.InspectGeneratedDutyRecord(row.Body)
					if err != nil || duty.SemanticLifecycleMode() != contract.GeneratorLifecycleManaged || duty.Kind != contract.GeneratedDutyUnselectedCleanup {
						t.Fatal("mixed Final invented local remote cleanup", err)
					}
				}
			}
			if _, present := work.attempts[localAttempt.AttemptID]; present {
				t.Fatal("Final retained a dead local active Attempt")
			}
			if _, present := work.records[generatedRecordKey{contract.GeneratedResultSupportKind, localAttempt.ResultID}]; present {
				t.Fatal("Final retained the discarded local Result row")
			}
			if scenario == "successful local discarded" {
				if localFailures.Load() != 0 {
					t.Fatal("successful local export gained a failure transition")
				}
				released, present := work.releases[localAttempt.AttemptID]
				if !present || released.attempt.State != contract.GeneratedEffectSucceeded || released.attempt.Progress != wantEmptyProgress || released.attempt.Support != localAttempt.Support ||
					released.release.OriginalResultID != localReference.ResultID || released.release.SelectedHandoffDigest != localReference.ResultBodyDigest || released.release.ObjectLength != localReference.ResultLength ||
					released.release.CapacityReservation != localCapacity || released.release.HandoffRevisionID != cold.head.Core.Revision {
					t.Fatalf("discarded actual local success lost its exact same-Final inbox handoff: release_present=%t attempt_state=%d progress_match=%t support_match=%t result_id_match=%t handoff_digest_match=%t object_length_match=%t capacity_match=%t revision_match=%t", present, released.attempt.State,
						released.attempt.Progress == wantEmptyProgress, released.attempt.Support == localAttempt.Support,
						released.release.OriginalResultID == localReference.ResultID, released.release.SelectedHandoffDigest == localReference.ResultBodyDigest, released.release.ObjectLength == localReference.ResultLength,
						released.release.CapacityReservation == localCapacity, released.release.HandoffRevisionID == cold.head.Core.Revision)
				}
				if cold.root.Generated.Hazards == 0 {
					t.Fatal("controlled ambiguous CF siblings lost their actual cleanup closure")
				}
			} else {
				if localFailures.Load() != 1 || len(work.releases) != 0 || cold.root.Generated.Duties != 1 || len(work.attempts) != 1 {
					t.Fatal("local failure lost or added independent successful CF cleanup")
				}
				localFact := false
				for _, effect := range got.Generated.Effects {
					if effect.Record.AttemptID == localAttempt.AttemptID {
						localFact = effect.Record.State == contract.GeneratedEffectFailedTerminal && effect.Reason == contract.GeneratorFailureUnavailable && effect.Target == nil
					}
				}
				if !localFact {
					t.Fatal("mixed result lost the actual local failure reason")
				}
			}
			if _, present := cold.materialAccess(contract.OperationSeedMaterialKind, material); !present {
				t.Fatal("mixed Final dropped the seed still required by actual CF work")
			}
		})
	}
}
