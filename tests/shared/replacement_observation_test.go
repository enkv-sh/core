package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/telemetry"
)

type replacementObservationSource struct {
	store                contract.Store
	heads, reads, closes atomic.Int64
	hook                 func(context.Context, string) (contract.ReadResult, bool)
}

func (s *replacementObservationSource) Descriptor() contract.Descriptor { return s.store.Descriptor() }
func (s *replacementObservationSource) StoreConfiguration() contract.StoreConfiguration {
	if source, ok := s.store.(contract.StoreConfigurationSource); ok {
		return source.StoreConfiguration()
	}
	return contract.StoreConfiguration{}
}
func (s *replacementObservationSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.reads.Add(1)
	if key == s.Descriptor().HeadKey {
		s.heads.Add(1)
	}
	if s.hook != nil {
		if read, handled := s.hook(ctx, key); handled {
			return read
		}
	}
	return s.store.Read(ctx, key, limit)
}
func (s *replacementObservationSource) Close() { s.closes.Add(1) }

type replacementObservationFixture struct {
	env                         fixtureEnvironment
	keys                        *custody.Fixture
	before, current             *StateSession
	admission                   OpenContext
	candidate                   *Candidate
	installation                ReplacementObservationInstallation
	normal, recovery, successor *testtrust.Signer
	ordinarySigner              contract.Trust
	activate                    contract.ID
}

func replacementObservationPins(t *testing.T, label string) AdministrativeSourcePins {
	t.Helper()
	return AdministrativeSourcePins{FileID: contract.Hash([]byte("portable file")), Format: AdministrativeJSONFormat, EditableDigest: contract.Hash([]byte(label + " editable")), GeneratedDigest: contract.Hash([]byte(label + " generated")), EditableLength: 100, GeneratedLength: 200, HasGenerated: true}
}
func replacementObservationPrepare(t *testing.T, condition string) replacementObservationFixture {
	t.Helper()
	ctx := t.Context()
	env, keys := genesisEnvironment(t, contract.GCP, true)
	f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
	return replacementObservationPrepareSelected(t, condition, env, keys, f.session, f.admission)
}

func replacementObservationPrepareSelected(t *testing.T, condition string, env fixtureEnvironment, keys *custody.Fixture, before *StateSession, admission OpenContext) replacementObservationFixture {
	t.Helper()
	ctx := t.Context()
	body, err := contract.EncodeControlCore(currentControlOf(before))
	if err != nil {
		t.Fatal(err)
	}
	after, err := contract.DecodeControlCore(body)
	if err != nil {
		t.Fatal(err)
	}
	after.AccessGeneration++
	fixture := replacementObservationFixture{env: env, keys: keys, before: before, admission: admission, normal: env.Trust.(*fixtureTrust).Signer, recovery: env.Recovery.(*testtrust.Signer), ordinarySigner: env.Trust}
	input := ReplacementObservationInstallation{ExpectedDomain: env.Domain, ExpectedStore: env.Store.Descriptor(), SourceBasis: before.admission.publicBasis(), SourcePins: replacementObservationPins(t, "source"), OutputPins: replacementObservationPins(t, "output"), CompositionID: before.admission.composition, CheckSourceOutput: func(context.Context) error { return nil }}
	if condition == "recipient" {
		recipient := fixtureID(env.Domain, "reader")
		successor := keys.RecipientSuccessor(t, recipient)
		permit := admitReaderReplacement(t, before, keys, recipient, successor)
		fixture.candidate, _ = before.PrepareRecipientReplacement(ctx, permit, env.Trust)
		input.Correlation.Target, input.Correlation.RecipientID = ReplacementTargetRecipient, recipient
		input.RecipientBefore, input.RecipientAfter = permit.intent.Before, permit.intent.Successor
		input.Goal = RoleReplacementGoal{ApprovalRole: contract.NormalSigningRole, EncryptionSelector: successor.KeySelector, MaterialSource: ReplacementMaterialAuthority}
		input.SuccessorBasis = input.SourceBasis
		fixture.activate = recipient
	} else {
		operation, mask := uint8(contract.SuccessionReplaceAuthority), uint8(contract.SuccessionChangeNormalSigner)
		input.Correlation.Target = ReplacementTargetAuthority
		input.Goal.ApprovalRole = contract.NormalSigningRole
		signers := SuccessionSigners{Authorizer: env.Trust}
		var source contract.BindingTableRow
		switch condition {
		case "authority-signer":
			fixture.successor, after.NormalSigning = fixture.normal.Successor(t, after.NormalSigning)
			signers.NormalSuccessor = fixture.successor
			input.Goal.SigningSelector = after.NormalSigning.KeySelector
			fixture.ordinarySigner = fixture.successor
		case "authority-kek":
			mask = contract.SuccessionChangeAuthorityKEK
			source = contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
			after.AuthorityKMSBinding = keys.KEKSuccessor(t, contract.SuccessorAuthorityKEK)
			input.Goal.EncryptionSelector = after.AuthorityKMSBinding.KeySelector
			input.Goal.MaterialSource = ReplacementMaterialAuthority
			fixture.activate = after.AuthorityRecipientID
		case "recovery-signer":
			operation, mask = contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoverySigner
			input.Correlation.Target = ReplacementTargetRecovery
			fixture.successor, after.Recovery.Signing = fixture.recovery.Successor(t, after.Recovery.Signing)
			signers.RecoverySuccessor = fixture.successor
			input.Goal.SigningSelector = after.Recovery.Signing.KeySelector
		case "recovery-kek":
			operation, mask = contract.SuccessionReplaceRecoveryBasis, contract.SuccessionChangeRecoveryKEK
			input.Correlation.Target = ReplacementTargetRecovery
			source = contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: after.AuthorityRecipientID, Binding: after.AuthorityKMSBinding}
			after.Recovery.KMS = keys.KEKSuccessor(t, contract.SuccessorRecoveryKEK)
			input.Goal.EncryptionSelector = after.Recovery.KMS.KeySelector
			input.Goal.MaterialSource = ReplacementMaterialAuthority
			fixture.activate = after.Recovery.RoleID
		default:
			t.Fatal("unknown fixture condition")
		}
		permit := admitAuthorityReplacement(t, before, keys, after, operation, contract.NormalSigningRole, mask, source)
		var result Result
		fixture.candidate, result = before.PrepareSuccession(ctx, permit, signers)
		if fixture.candidate == nil {
			t.Fatal("real candidate preparation", result)
		}
		fixture.admission = deliverSuccessionBasis(t, fixture.candidate)
		input.SuccessorBasis = fixture.admission.admission.publicBasis()
	}
	if fixture.candidate == nil || fixture.candidate.requestIdentity.IsZero() {
		t.Fatal("prepared mutation lost its exact graph identity")
	}
	input.Correlation.RequestIdentity = fixture.candidate.requestIdentity
	input.Correlation.SignedCandidate = bytes.Clone(fixture.candidate.body)
	fixture.installation = input
	t.Cleanup(keys.RetireAccess)
	return fixture
}
func (f *replacementObservationFixture) selectCandidate(t *testing.T) {
	t.Helper()
	if result := f.before.Select(t.Context(), f.candidate); result.Outcome != ObservedCurrent {
		t.Fatal("real candidate selection", result)
	}
	if !f.activate.IsZero() {
		f.keys.RetireAccess()
		if err := f.keys.ActivateSuccessor(f.activate); err != nil {
			t.Fatal(err)
		}
	}
	var result Result
	f.current, result = Open(t.Context(), f.admission, f.env.Store)
	if f.current == nil {
		t.Fatal("cold selected state", result)
	}
}
func (f *replacementObservationFixture) ordinaryAdvance(t *testing.T) {
	t.Helper()
	input := f.current.currentEntryInputs()
	input[0].InputBytes = []byte("ordinary progress after replacement")
	comparison, result := f.current.Compare(t.Context(), input, admitSuppliedComparison(t, f.current, nil, input))
	if comparison == nil {
		t.Fatal("ordinary comparison", result)
	}
	candidate, result := f.current.Prepare(t.Context(), comparison, admit(t, f.current, comparison), f.ordinarySigner)
	if candidate == nil {
		t.Fatal("ordinary preparation", result)
	}
	if result = f.current.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
		t.Fatal("ordinary selection", result)
	}
	f.current, result = Open(t.Context(), f.admission, f.env.Store)
	if f.current == nil {
		t.Fatal("ordinary cold state", result)
	}
}
func (f *replacementObservationFixture) query(t *testing.T, label string) (PublicReplacementObservationResult, *replacementObservationSource) {
	t.Helper()
	source := &replacementObservationSource{store: f.env.Store}
	input := f.installation
	input.Source = source
	public, private := f.keys.Calls()
	normal, recovery := f.normal.Calls(), f.recovery.Calls()
	successor := 0
	if f.successor != nil {
		successor = f.successor.Calls()
	}
	store := f.env.Store.(*memoryStore)
	creates, cas := store.creates, store.cas
	parent, err := NewInstalledReplacementObserver(input)
	if err != nil {
		t.Fatal("public observer admission", err)
	}
	if source.reads.Load() != 0 {
		t.Fatal("observer constructor performed remote I/O")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	nonce := contract.Hash([]byte(label))
	result := parent.Observe(ctx, nonce)
	if result.Query == nil || !result.Query.Valid() || result.Query.OriginalRequestIdentity != f.candidate.requestIdentity || result.Query.CandidateDigest != contract.Hash(f.candidate.body) || result.RequestID != nonce || result.RequestIdentity != result.Query.Digest || source.heads.Load() != 1 || result.Result.CommitMayHaveOccurred {
		t.Fatal("closed fresh query or one HEAD capture changed", result.Result)
	}
	reads := source.reads.Load()
	again := parent.Observe(ctx, contract.Hash([]byte(label+" again")))
	if again.Result.Outcome != AdmissionRefused || source.reads.Load() != reads {
		t.Fatal("observer reused cached image or admitted second invocation")
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil || source.closes.Load() != 1 {
		t.Fatal("public source cleanup not idempotent", err)
	}
	gotPublic, gotPrivate := f.keys.Calls()
	if gotPublic != public || gotPrivate != private || f.normal.Calls() != normal || f.recovery.Calls() != recovery || f.successor != nil && f.successor.Calls() != successor || store.creates != creates || store.cas != cas {
		t.Fatal("read constructed or called private mutation capabilities")
	}
	return result, source
}

// full_only: false
func TestInstalledReplacementObservationsAuthenticatePreparedSelectedAndProgress(t *testing.T) {
	for _, condition := range []string{"authority-signer", "authority-kek", "recovery-signer", "recovery-kek", "recipient"} {
		t.Run(condition, func(t *testing.T) {
			f := replacementObservationPrepare(t, condition)
			prepared, _ := f.query(t, condition+" prepared")
			if prepared.StateResult != contract.ReaderUnavailable || prepared.Query.Observation == nil || prepared.Query.AuthenticatedBasisDigest != prepared.Query.SourceBasisDigest || prepared.Receipt != nil || prepared.Selection != nil && (prepared.Selection.CandidateSelected || prepared.Selection.SuccessorSourceUsable) {
				t.Fatal("prepared output gained selected or historical authority", prepared.Result)
			}
			if f.installation.Correlation.Target == ReplacementTargetAuthority && prepared.Selection == nil {
				t.Fatal("authenticated predecessor lost separate current-selection facts")
			}
			f.selectCandidate(t)
			selected, _ := f.query(t, condition+" selected")
			if selected.StateResult != contract.ReaderSuccess || selected.Query.Observation == nil {
				t.Fatal("selected replacement query failed", selected.Result)
			}
			var original []byte
			if selected.Target == ReplacementTargetAuthority {
				if selected.Selection == nil || !selected.Selection.CandidateSelected || !selected.Selection.SuccessorSourceUsable || selected.Receipt != nil {
					t.Fatal("Authority result merged usability/history/receipt")
				}
			} else {
				if selected.Receipt == nil || !selected.Receipt.CandidateSelected || selected.Receipt.Receipt.OperationKind != selected.UnderlyingOperation {
					t.Fatal("typed selected receipt missing")
				}
				for _, page := range f.current.support {
					for _, row := range page.Records {
						if row.Kind == contract.MutationReceiptSupportKind && row.RecordID == selected.Query.OriginalOperationID {
							original = bytes.Clone(row.Body)
						}
					}
				}
				if !bytes.Equal(original, selected.Receipt.ReceiptBytes) {
					t.Fatal("receipt is not original stored bytes")
				}
			}
			f.ordinaryAdvance(t)
			later, _ := f.query(t, condition+" progress")
			if later.StateResult != contract.ReaderSuccess || later.Query.Observation == nil || later.Query.Observation.Revision == selected.Query.Observation.Revision || later.Query.OriginalRequestIdentity != selected.Query.OriginalRequestIdentity || later.RequestIdentity == selected.RequestIdentity {
				t.Fatal("later progress changed query/historical relation", later.Result)
			}
			if later.Target == ReplacementTargetAuthority {
				if later.Selection == nil || later.Selection.CandidateSelected || !later.Selection.SuccessorSourceUsable || later.Selection.EvidenceLimit != "historical-attribution-unavailable" {
					t.Fatal("ordinary progress lost usability or invented historical attribution")
				}
			} else if later.Receipt == nil || later.Receipt.CandidateSelected || !bytes.Equal(later.Receipt.ReceiptBytes, original) {
				t.Fatal("later progress changed stored receipt/currentness separation")
			}
		})
	}
}

// full_only: false
func TestInstalledReplacementObservationRefusesChangedPinsAndJoinsClose(t *testing.T) {
	f := replacementObservationPrepare(t, "authority-signer")
	f.selectCandidate(t)
	input := f.installation
	source := &replacementObservationSource{store: f.env.Store}
	input.Source = source
	checks := 0
	sourceErr := errors.New("controlled changed pair")
	input.CheckSourceOutput = func(context.Context) error {
		checks++
		if checks == 2 {
			return sourceErr
		}
		return nil
	}
	parent, err := NewInstalledReplacementObserver(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	out := parent.Observe(ctx, contract.Hash([]byte("changed pins")))
	if out.StateResult != contract.ReaderRefused || out.Selection != nil || out.Receipt != nil || out.CurrentWarningBits != 0 || out.Query == nil || out.Query.Observation != nil || !out.Query.Valid() || out.RequestIdentity != out.Query.Digest || source.heads.Load() != 1 || source.reads.Load() <= 1 {
		t.Fatal("changed pins released semantic payload or query observation", out.Result)
	}
	if err := parent.Close(); !errors.Is(err, sourceErr) {
		t.Error("first Close lost retained source cause", err)
	}
	if err := parent.Close(); !errors.Is(err, sourceErr) {
		t.Error("second Close lost retained source cause", err)
	}
	if source.closes.Load() != 1 {
		t.Fatal("Close closed source twice")
	}
	entered := make(chan struct{})
	source = &replacementObservationSource{store: f.env.Store}
	source.hook = func(ctx context.Context, key string) (contract.ReadResult, bool) {
		if key != source.Descriptor().HeadKey {
			return contract.ReadResult{}, false
		}
		close(entered)
		<-ctx.Done()
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}, true
	}
	input = f.installation
	input.Source = source
	parent, err = NewInstalledReplacementObserver(input)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan PublicReplacementObservationResult, 1)
	go func() { done <- parent.Observe(ctx, contract.Hash([]byte("joined close"))) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- parent.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel and join public read")
	}
	select {
	case result := <-done:
		if result.StateResult == contract.ReaderSuccess || result.Selection != nil || result.Receipt != nil || source.closes.Load() != 1 {
			t.Fatal("closed invocation released successful payload")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("read did not return after Close")
	}
}

// full_only: false
func TestInstalledReplacementObservationMissingHEADRetainsRootLoss(t *testing.T) {
	f := replacementObservationPrepare(t, "recovery-signer")
	input := f.installation
	source := &replacementObservationSource{store: f.env.Store}
	input.Source = source
	source.hook = func(_ context.Context, key string) (contract.ReadResult, bool) {
		if key == source.Descriptor().HeadKey {
			return contract.ReadResult{Status: contract.ReadMissing}, true
		}
		return contract.ReadResult{}, false
	}
	parent, err := NewInstalledReplacementObserver(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	result := parent.Observe(ctx, contract.Hash([]byte("missing replacement HEAD")))
	if result.StateResult != ReplacementRootLossUnsupported || result.Selection != nil || result.Receipt != nil || source.heads.Load() != 1 || result.Query == nil || !result.Query.Valid() {
		t.Fatal("missing HEAD lost root-loss boundary", result.Result, result.StateResult)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
}

// full_only: false
func TestInstalledReplacementObservationRefusesChangedOriginalCorrelationBeforeIO(t *testing.T) {
	for _, condition := range []string{"authority-kek", "recovery-kek"} {
		t.Run(condition, func(t *testing.T) {
			f := replacementObservationPrepare(t, condition)
			for _, damage := range []string{"request-identity", "material-route", "signed-identity", "signed-route"} {
				t.Run(damage, func(t *testing.T) {
					input := f.installation
					source := &replacementObservationSource{store: f.env.Store}
					input.Source = source
					switch damage {
					case "request-identity":
						input.Correlation.RequestIdentity[0] ^= 0xff
					case "material-route":
						input.Goal.MaterialSource = ReplacementMaterialRecovery
					case "signed-identity", "signed-route":
						head, err := format.DecodeHead(input.Correlation.SignedCandidate)
						if err != nil {
							t.Fatal(err)
						}
						if damage == "signed-identity" {
							input.Correlation.RequestIdentity[0] ^= 0xff
							head.Succession.Subject.RequestIdentityDigest = input.Correlation.RequestIdentity
						} else {
							input.Goal.MaterialSource = ReplacementMaterialRecovery
							head.Succession.Subject.MaterialSourceRole = contract.SuccessionMaterialRecovery
						}
						body, err := format.EncodeHead(head)
						if err != nil {
							t.Fatal(err)
						}
						input.Correlation.SignedCandidate = body
						input.SuccessorBasis.Selection = bytes.Clone(body)
					}
					parent, err := NewInstalledReplacementObserver(input)
					if err == nil || parent != nil || source.reads.Load() != 0 || source.closes.Load() != 0 {
						t.Fatal("unmatched signed original facts admitted or reached provider", err)
					}
					// Constructor failure leaves the borrowed source with its caller.
					source.Close()
				})
			}
		})
	}
}

// full_only: false
func TestInstalledReplacementObservationTelemetryPreservesCloseCancellation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("telemetry=%t", enabled), func(t *testing.T) {
			f := replacementObservationPrepare(t, "authority-signer")
			f.selectCandidate(t)
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				if enabled {
					ctx = telemetry.WithCapability(ctx, telemetry.NewCapability(nil, telemetry.NewRecorder()))
				}
				entered, exited := make(chan struct{}), make(chan struct{})
				var readCancellation error
				source := &replacementObservationSource{store: f.env.Store}
				source.hook = func(ctx context.Context, _ string) (contract.ReadResult, bool) {
					close(entered)
					<-ctx.Done()
					readCancellation = ctx.Err()
					close(exited)
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}, true
				}
				input := f.installation
				input.Source = source
				parent, err := NewInstalledReplacementObserver(input)
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan PublicReplacementObservationResult, 1)
				go func() { result <- parent.Observe(ctx, testID("replacement observation cancellation")) }()
				<-entered
				if err := parent.Close(); err != nil {
					t.Error(err)
				}
				got := <-result
				select {
				case <-exited:
				default:
					t.Error("Close returned before its source joined")
				}
				if readCancellation != context.Canceled || ctx.Err() != nil || source.closes.Load() != 1 || got.StateResult == contract.ReaderSuccess || got.Selection != nil || got.Receipt != nil {
					t.Fatal("telemetry discarded the observer's Close cancellation", readCancellation, ctx.Err(), got.Result)
				}
			})
		})
	}
}

// full_only: false
func TestInstalledReplacementObservationKeepsPinnedSignatureDefect(t *testing.T) {
	for _, condition := range []string{"pinned-invalid-k1", "unfamiliar-successor"} {
		t.Run(condition, func(t *testing.T) {
			f := replacementObservationPrepare(t, "authority-signer")
			f.selectCandidate(t)
			var captured contract.ReadResult
			if condition == "pinned-invalid-k1" {
				head, err := format.DecodeHead(f.candidate.body)
				if err != nil {
					t.Fatal(err)
				}
				head.K1 = bytes.Clone(f.before.head.K1)
				body, err := format.EncodeHead(head)
				if err != nil || !successionProofValid(head) || !savedSuccessionSelected(f.installation.Correlation.SignedCandidate, head) {
					t.Fatal("signature damage lost the independently pinned succession", err)
				}
				captured = f.env.Store.Read(t.Context(), f.env.Store.Descriptor().HeadKey, contract.MaxHeadLength)
				captured.Body = body
			} else {
				environment := f.env
				environment.Trust = &fixtureTrust{Signer: f.successor}
				next := replacementObservationPrepareSelected(t, "authority-signer", environment, f.keys, f.current, f.admission)
				next.selectCandidate(t)
			}
			source := &replacementObservationSource{store: f.env.Store}
			if condition == "pinned-invalid-k1" {
				source.hook = func(_ context.Context, key string) (contract.ReadResult, bool) {
					return captured, key == source.Descriptor().HeadKey
				}
			}
			input := f.installation
			input.Source = source
			observer, err := NewInstalledReplacementObserver(input)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			out := observer.Observe(ctx, fixtureID(f.env.Domain, condition))
			if err := observer.Close(); err != nil {
				t.Fatal(err)
			}
			wantState, wantOutcome, wantReason := contract.ReaderPositiveDefect, IntegrityFailure, InvalidProof
			if condition == "unfamiliar-successor" {
				wantState, wantOutcome, wantReason = contract.ReaderUnavailable, EvidenceUnavailable, SigningUnavailable
			}
			if out.StateResult != wantState || out.Result.Outcome != wantOutcome || out.Result.Reason != wantReason || out.Selection != nil || out.Receipt != nil || source.heads.Load() != 1 || source.closes.Load() != 1 || out.Query == nil || !out.Query.Valid() {
				t.Fatal("replacement proof defect and unfamiliar basis were conflated", out.Result, out.StateResult)
			}
		})
	}
}
