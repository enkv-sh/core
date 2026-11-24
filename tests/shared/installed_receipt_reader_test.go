package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func installedReceiptInput(f installedApplyTestFixture, source *installedGeneratedReadSource) ReceiptReadInstallation {
	return ReceiptReadInstallation{Candidate: source, ExpectedDomain: f.env.Domain, ExpectedStore: source.Descriptor(), PublicBasis: f.basis,
		CompositionID: f.composition, SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil },
		Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return source, Result{}
		}, CloseInstalled: func() {}}
}

func installedReceiptFixture(t *testing.T, f installedApplyTestFixture) (*InstalledReceiptReader, *installedGeneratedReadSource) {
	t.Helper()
	source := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	reader, err := NewInstalledReceiptReader(installedReceiptInput(f, source))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if source.reads != 0 {
		t.Fatal("receipt construction performed GET")
	}
	return reader, source
}

func installedReceiptAppliedFixture(t *testing.T, ctx context.Context) installedApplyTestFixture {
	t.Helper()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("current")}}
	engine := f.engine(t, f.selected, input, nil)
	out := engine.Apply(ctx, testID("receipt current selected input"), input)
	engine.Close()
	if out.Result.Outcome != ObservedCurrent {
		t.Fatal("receipt fixture apply", out.Result)
	}
	f.selected = f.open(t, ctx)
	return f
}

// full_only: false
func TestInstalledReceiptReadsAllKindsInRecordedOrderWithOriginalBytesAndGETOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := installedReceiptAppliedFixture(t, ctx)
	base := fullSuccessReceiptRows(f.env.Domain, f.selected.admission)[0]
	kinds := []uint16{contract.OperationInitializeDomain, contract.OperationApplyDeclaration, contract.OperationRemoveSecretValueEntryAccess,
		contract.OperationRotateRecipientKeyBinding, contract.OperationRetireRecipientIdentity, contract.OperationEnvelopeRekey,
		contract.OperationRotateValueEntryValue, contract.OperationRebindStoreConstruction, contract.OperationConfigureCommercialAttachment,
		contract.OperationReplaceRecoveryKeysAndRoot, contract.OperationRetireGeneratedGeneration, contract.OperationAcceptGeneratedRetirementResidue, contract.OperationEndSelectedWork}
	windows := contract.MutationReceiptWindows{DomainID: f.env.Domain}
	var chronological []contract.CompactMutationReceipt
	for i, kind := range kinds {
		row := base
		row.OperationID = contract.ID{byte(i + 1), 91}
		row.OperationKind = kind
		if kind == contract.OperationInitializeDomain {
			row.PredecessorRevisionID = contract.ID{}
		}
		if kind == contract.OperationEndSelectedWork {
			row.StateResult = contract.ReceiptStateWorkEnded
			row.AdministrativeTargetKind = contract.AdministrativeGeneratedParent
			row.AdministrativeTargetID, row.AdministrativeGroupID, row.AdministrativeDisposition = contract.ID{81}, contract.ID{81}, contract.ID{82}
			row.AdministrativeOriginalEvidence = contract.AdministrativeEvidenceMissing
			row.WarningBits = uint64(WarningDiscardedExactEvidence)
			row.AdministrativeWarningChanges = WarningDiscardedExactEvidence
			row.ChangedSubjects.Length, row.ChangedSubjects.Count = 42, 1
		}
		windows.Successes = append(windows.Successes, row)
		windows.Order = append(windows.Order, row.OperationID)
		chronological = append(chronological, row)
		if i == 2 {
			failed := fullUnknownReceiptRows(f.env.Domain, f.selected.admission)[0]
			windows.Failures = append(windows.Failures, failed)
			windows.Order = append(windows.Order, failed.OperationID)
			chronological = append(chronological, failed)
		}
	}
	prior := *f.selected
	prior.root.WarningBits = WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningDiscardedExactEvidence
	history := &environmentFixture{admission: f.admitted, session: &prior}
	seedSignedReceiptWindows(t, f.env, history, mutationReceiptFixtureStorage(t, windows))
	f.selected = history.session
	wantBytes := make(map[contract.ID][]byte, len(chronological))
	for _, row := range chronological {
		body, err := contract.EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal(err)
		}
		wantBytes[row.OperationID] = body
	}
	reader, source := installedReceiptFixture(t, f)
	memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("missing mutation counters")
	}
	trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
	if !ok {
		t.Fatal("missing signing counters")
	}
	public, private := f.keys.Calls()
	creates, cas, signs := memory.creates, memory.cas, trust.signs
	listed := reader.List(ctx, ReceiptListRequest{testID("mixed receipt list")})
	if listed.StateResult != PublicQuerySuccess || listed.Payload == nil || len(listed.Payload.Receipts) != len(chronological) || listed.Query == nil || listed.Query.Observation == nil {
		t.Fatal("complete receipt list", listed)
	}
	if err := listed.Validate(); err != nil {
		t.Fatal("closed list validation", err)
	}
	wantObservation := PublicObservation{f.env.Domain, f.selected.head.Core.Revision, f.selected.root.Snapshot, f.selected.head.Core.Root.Digest}
	if listed.Payload.Observation != wantObservation || *listed.Query.Observation != wantObservation || listed.Payload.CurrentDomainWarningBits != 11 || listed.Payload.CurrentWarnings != (PublicDomainWarnings{OrphanGeneratedEffect: true, LateDestructiveEffect: true, DiscardedExactEvidence: true}) {
		t.Fatal("current observation/warnings changed", listed.Payload)
	}
	for i, row := range chronological {
		want := ReceiptSummary{row.OperationID, row.OperationKind, row.CanonicalOutcome, row.StateResult, row.ObservedRevisionID, row.RequestedRevisionID, row.WarningBits, row.EvidenceCeiling}
		if listed.Payload.Receipts[len(chronological)-1-i] != want {
			t.Fatal("common order or original summary changed", i)
		}
		detail := reader.Detail(ctx, ReceiptDetailRequest{testID("receipt detail " + string(rune(i+1))), row.OperationID})
		if detail.StateResult != PublicQuerySuccess || detail.Payload == nil || detail.Payload.Receipt != row || !bytes.Equal(detail.Payload.EncodedReceipt, wantBytes[row.OperationID]) || len(detail.Payload.EncodedReceipt) != 471 || detail.Payload.Observation != wantObservation || detail.Payload.Authenticity != "authenticated-retained" || detail.Payload.Retention != "retained" {
			t.Fatal("exact original receipt changed", i, detail)
		}
		if err := detail.Validate(); err != nil {
			t.Fatal("closed detail validation", err)
		}
		detail.Payload.EncodedReceipt[0] ^= 1
		if detail.Validate() == nil {
			t.Fatal("changed encoded detail passed validation")
		}
		detail.Payload.Receipt.WarningBits ^= 1
		again := reader.Detail(ctx, ReceiptDetailRequest{testID("fresh receipt detail " + string(rune(i+1))), row.OperationID})
		if again.Payload == nil || again.Payload.Receipt != row || !bytes.Equal(again.Payload.EncodedReceipt, wantBytes[row.OperationID]) {
			t.Fatal("caller owns no original receipt copy")
		}
	}
	listed.Payload.Receipts[0].WarningBits ^= 1
	again := reader.List(ctx, ReceiptListRequest{testID("fresh receipt list")})
	if again.Payload == nil || reflect.DeepEqual(again.Payload.Receipts, listed.Payload.Receipts) {
		t.Fatal("list rows borrowed mutable owner")
	}
	missing := reader.Detail(ctx, ReceiptDetailRequest{testID("missing receipt"), contract.ID{255}})
	if err := missing.Validate(); err != nil {
		t.Fatal("closed absent result validation", err)
	}
	if missing.StateResult != PublicQueryUnavailable || missing.Payload != nil || missing.Query == nil || missing.Query.Observation == nil {
		t.Fatal("absent exact receipt made a history claim", missing)
	}
	if p, q := f.keys.Calls(); p != public || q != private || memory.creates != creates || memory.cas != cas || trust.signs != signs {
		t.Fatal("receipt read used KMS/signing/mutation")
	}
	if source.closes != 2*len(chronological)+3 {
		t.Fatal("GET attempts did not close exactly", source.closes)
	}
}

// full_only: false
func TestInstalledReceiptEmptyRetentionAndFixedObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := installedReceiptAppliedFixture(t, ctx)
	history := &environmentFixture{admission: f.admitted, session: f.selected}
	seedSignedReceiptWindows(t, f.env, history, mutationReceiptStorage{generated: format.EmptyGeneratedClosure()})
	f.selected = history.session
	reader, source := installedReceiptFixture(t, f)
	rootKey, err := format.Key(source.Descriptor().Prefix, f.selected.root.AdministrativeIndex)
	if err != nil {
		t.Fatal(err)
	}
	memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("missing memory source")
	}
	headKey := source.Descriptor().HeadKey
	old := memory.objects[headKey]
	defer func() { memory.objects[headKey] = old }()
	changed := false
	source.afterRead = func(key string) {
		if key == rootKey && !changed {
			changed = true
			delete(memory.objects, headKey)
		}
	}
	out := reader.List(ctx, ReceiptListRequest{testID("empty receipt retention")})
	if !changed || out.StateResult != PublicQuerySuccess || out.Payload == nil || out.Payload.Receipts == nil || len(out.Payload.Receipts) != 0 || out.Payload.Observation.HeadRevisionID != f.selected.head.Core.Revision {
		t.Fatal("empty fixed observation refused", out)
	}
}

// full_only: false
func TestInstalledReceiptMandatoryLossSourceChangesAndCanceledReadersDiscloseNothing(t *testing.T) {
	for _, condition := range []string{"missing-receipt-page", "corrupt-index", "missing-administrative-index", "source-before", "source-after", "cancel-before", "cancel-final", "closed"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			source := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
			input := installedReceiptInput(f, source)
			checks := 0
			input.CheckSource = func(context.Context) error {
				checks++
				if condition == "source-before" || condition == "source-after" && checks == 2 {
					return errors.New("changed captured source")
				}
				if condition == "cancel-final" && checks == 2 {
					cancel()
				}
				return nil
			}
			reader, err := NewInstalledReceiptReader(input)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			want := PublicQueryUnavailable
			switch condition {
			case "missing-receipt-page":
				for i, page := range f.selected.support {
					if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool { return row.Kind == contract.MutationReceiptSupportKind }) {
						source.missingKey, err = format.Key(source.Descriptor().Prefix, f.selected.root.RequiredSupport[i])
						break
					}
				}
			case "corrupt-index":
				indexID, indexErr := f.selected.receiptIndexID()
				if indexErr != nil {
					t.Fatal(indexErr)
				}
				for _, location := range f.selected.root.Generated.Fragments {
					if location.BlobID != indexID {
						continue
					}
					for _, ref := range f.selected.root.RequiredSupport {
						if ref.Index == location.SupportPageIndex {
							source.corruptKey, err = format.Key(source.Descriptor().Prefix, ref)
						}
					}
				}
				if source.corruptKey == "" {
					t.Fatal("fixture omitted exact receipt index")
				}
				want = PublicQueryPositiveDefect
			case "missing-administrative-index":
				source.missingKey, err = format.Key(source.Descriptor().Prefix, f.selected.root.AdministrativeIndex)
			case "source-before", "source-after", "cancel-final":
				want = PublicQueryRefused
			case "cancel-before":
				cancel()
				want = PublicQueryRefused
			case "closed":
				reader.Close()
				want = PublicQueryRefused
			}
			if err != nil {
				t.Fatal(err)
			}
			out := reader.List(ctx, ReceiptListRequest{testID(condition)})
			if out.StateResult != want || out.Payload != nil {
				t.Fatal("unsafe incomplete list", out)
			}
			if (condition == "cancel-before" || condition == "closed" || condition == "source-before") && source.reads != 0 {
				t.Fatal("refused read performed GET")
			}
			if condition == "missing-receipt-page" || condition == "corrupt-index" || condition == "missing-administrative-index" {
				detail := reader.Detail(ctx, ReceiptDetailRequest{testID(condition + " detail"), contract.ID{255}})
				if detail.StateResult != want || detail.Payload != nil || detail.Query != nil && detail.Query.Observation != nil {
					t.Fatal("absent ID bypassed mandatory damage", detail)
				}
			}
		})
	}
}

// full_only: false
func TestInstalledReceiptReadToleratesUnrelatedDisposableBodyLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	f.selected = configurationRecoveryGenerated(t, ctx, f.env, f.selected, "generated-active")
	reader, source := installedReceiptFixture(t, f)
	var optional format.Ref
	for _, page := range f.selected.adminIndex.Pages {
		if !page.ReadRequired && !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			optional = page.Ref
			break
		}
	}
	if optional == (format.Ref{}) {
		t.Fatal("fixture has no unrelated disposable page")
	}
	var err error
	source.missingKey, err = format.Key(source.Descriptor().Prefix, optional)
	if err != nil {
		t.Fatal(err)
	}
	out := reader.List(ctx, ReceiptListRequest{testID("disposable receipt list")})
	if out.StateResult != PublicQuerySuccess || out.Payload == nil || len(out.Payload.Receipts) == 0 {
		t.Fatal("unrelated disposable loss blocked mandatory receipt read", out)
	}
	detail := reader.Detail(ctx, ReceiptDetailRequest{testID("disposable receipt detail"), out.Payload.Receipts[0].OperationID})
	if detail.StateResult != PublicQuerySuccess || detail.Payload == nil || len(detail.Payload.EncodedReceipt) != 471 {
		t.Fatal("unrelated disposable loss blocked exact receipt", detail)
	}
}

type receiptDeniedSource struct{ *installedGeneratedReadSource }

func (s receiptDeniedSource) Read(context.Context, string, uint32) contract.ReadResult {
	return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
}

// full_only: false
func TestInstalledReceiptReadRejectsWrongBasisAndDeniedConstructedGET(t *testing.T) {
	for _, condition := range []string{"wrong-domain", "wrong-store", "denied-get"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			source := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
			input := installedReceiptInput(f, source)
			want := PublicQueryRefused
			switch condition {
			case "wrong-domain":
				input.ExpectedDomain = contract.ID{254}
			case "wrong-store":
				input.ExpectedStore.Identity = contract.ID{254}
			case "denied-get":
				input.Construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return receiptDeniedSource{source}, Result{}
				}
				want = PublicQueryUnavailable
			}
			reader, err := NewInstalledReceiptReader(input)
			if err != nil {
				t.Fatal("local read input unexpectedly refused", err)
			}
			defer reader.Close()
			out := reader.List(ctx, ReceiptListRequest{testID(condition)})
			if out.StateResult != want || out.Payload != nil {
				t.Fatal("wrong public basis or denied GET disclosed receipts", out)
			}
			if condition == "denied-get" && out.Result.StoreReason != contract.ReasonAccess {
				t.Fatal("typed Store denial was discarded", out)
			}
		})
	}
}

type receiptSelectedChildCancellationSource struct {
	*installedGeneratedReadSource
	selectedKey string
	cancel      context.CancelFunc
	status      contract.ReadStatus
	triggered   bool
}

func (s *receiptSelectedChildCancellationSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if key == s.selectedKey {
		s.triggered = true
		s.cancel()
		return contract.ReadResult{Status: s.status, Reason: contract.ReasonLimit}
	}
	return s.installedGeneratedReadSource.Read(ctx, key, limit)
}

// full_only: false
func TestInstalledReceiptCancellationDuringMandatorySelectedGETIsCanceled(t *testing.T) {
	for _, operation := range []string{ReceiptListOperation, ReceiptDetailOperation} {
		for _, returned := range []struct {
			name   string
			status contract.ReadStatus
		}{{"unavailable", contract.ReadUnavailable}, {"invalid", contract.ReadInvalid}} {
			t.Run(operation+"/"+returned.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
				readCtx, stop := context.WithCancel(ctx)
				defer stop()
				base := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
				source := &receiptSelectedChildCancellationSource{installedGeneratedReadSource: base, cancel: stop, status: returned.status}
				var receiptID contract.ID
				for i, page := range f.selected.support {
					for _, row := range page.Records {
						if row.Kind != contract.MutationReceiptSupportKind {
							continue
						}
						var err error
						source.selectedKey, err = format.Key(base.Descriptor().Prefix, f.selected.root.RequiredSupport[i])
						if err != nil {
							t.Fatal(err)
						}
						receiptID = row.RecordID
						break
					}
				}
				if source.selectedKey == "" || receiptID.IsZero() {
					t.Fatal("fixture omitted mandatory retained receipt")
				}
				input := installedReceiptInput(f, base)
				input.Construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
					return source, Result{}
				}
				closed := 0
				input.CloseInstalled = func() { closed++ }
				reader, err := NewInstalledReceiptReader(input)
				if err != nil {
					t.Fatal(err)
				}
				var result PublicQueryResult
				var validation error
				var payload bool
				if operation == ReceiptListOperation {
					out := reader.List(readCtx, ReceiptListRequest{testID("mandatory GET canceled list " + returned.name)})
					result, validation, payload = out.PublicQueryResult, out.Validate(), out.Payload != nil
				} else {
					out := reader.Detail(readCtx, ReceiptDetailRequest{testID("mandatory GET canceled detail " + returned.name), receiptID})
					result, validation, payload = out.PublicQueryResult, out.Validate(), out.Payload != nil
				}
				reader.reader.mu.Lock()
				joined := reader.reader.activeDone == nil
				reader.reader.mu.Unlock()
				if !source.triggered || base.closes != 1 || !joined {
					t.Fatal("regression missed selected GET or retained invocation/source ownership", source.triggered, base.closes, joined)
				}
				reader.Close()
				reader.Close()
				if closed != 1 || base.closes != 1 {
					t.Fatal("canceled receipt read did not close exactly once", closed, base.closes)
				}
				if result.StateResult != PublicQueryRefused || result.FailureReason != contract.ReasonCancelled || result.Result != refused(AdmissionInvalid) || payload || validation != nil {
					t.Fatal("selected GET cancellation lost its exact safe result", result, payload, validation)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledReceiptSourceCheckCancellationTakesPrecedenceOverSourceError(t *testing.T) {
	for _, operation := range []string{ReceiptListOperation, ReceiptDetailOperation} {
		for _, boundary := range []struct {
			name  string
			check int
		}{{"initial", 1}, {"final", 2}} {
			t.Run(operation+"/"+boundary.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
				windows, err := f.selected.receiptWindows(ctx)
				if err != nil || len(windows.Successes) == 0 {
					t.Fatal("fixture omitted original retained receipt", err)
				}
				readCtx, stop := context.WithCancel(ctx)
				defer stop()
				base := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
				input := installedReceiptInput(f, base)
				checks, closed := 0, 0
				input.CheckSource = func(context.Context) error {
					checks++
					if checks == boundary.check {
						stop()
						return errors.New("captured source check interrupted")
					}
					return nil
				}
				input.CloseInstalled = func() { closed++ }
				reader, err := NewInstalledReceiptReader(input)
				if err != nil {
					t.Fatal(err)
				}
				var result PublicQueryResult
				var validation error
				var payload bool
				if operation == ReceiptListOperation {
					out := reader.List(readCtx, ReceiptListRequest{testID("source check canceled list " + boundary.name)})
					result, validation, payload = out.PublicQueryResult, out.Validate(), out.Payload != nil
				} else {
					out := reader.Detail(readCtx, ReceiptDetailRequest{testID("source check canceled detail " + boundary.name), windows.Successes[0].OperationID})
					result, validation, payload = out.PublicQueryResult, out.Validate(), out.Payload != nil
				}
				reader.reader.mu.Lock()
				joined := reader.reader.activeDone == nil
				reader.reader.mu.Unlock()
				if checks != boundary.check || !joined || boundary.check == 1 && base.reads != 0 || base.closes != boundary.check-1 {
					t.Fatal("regression missed exact source-check boundary or retained invocation ownership", checks, joined, base.reads, base.closes)
				}
				reader.Close()
				reader.Close()
				if closed != 1 || base.closes != boundary.check-1 {
					t.Fatal("source-check cancellation did not close exactly once", closed, base.closes)
				}
				if result.StateResult != PublicQueryRefused || result.FailureReason != contract.ReasonCancelled || result.Result != refused(AdmissionInvalid) || payload || validation != nil {
					t.Fatal("source-check error replaced cancellation", result, payload, validation)
				}
			})
		}
	}
}

// full_only: false
func TestInstalledReceiptGenesisRequiresExactRecoveryChallenge(t *testing.T) {
	for _, condition := range []string{"recovery-disabled", "recovery-enabled", "invalid-challenge"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, condition != "recovery-disabled")
			if f.selected.head.AuthKind != format.GenesisAuth || f.selected.head.Genesis == nil {
				t.Fatal("fixture has no selected Genesis")
			}
			operation := f.selected.head.Genesis.Subject.InitID
			memory := requireAdmittedMemoryStore(t, f.env.Store)
			if condition == "invalid-challenge" {
				head := f.selected.head
				genesis := *head.Genesis
				head.Genesis = &genesis
				genesis.K3Challenge = bytes.Clone(genesis.K3Challenge)
				genesis.K3Challenge[len(genesis.K3Challenge)-1] ^= 1
				if !contract.P256SignatureEncodingValid(genesis.K3Challenge) {
					t.Fatal("damage broke signature framing")
				}
				encoded, err := format.EncodeHead(head)
				if err != nil {
					t.Fatal("well-framed challenge damage changed HEAD shape", err)
				}
				memory.put(memory.desc.HeadKey, encoded)
			}
			public, private := f.keys.Calls()
			signs, creates, swaps := f.env.Trust.(*fixtureTrust).signs, memory.creates, memory.cas
			reader, source := installedReceiptFixture(t, f)
			listed := reader.List(ctx, ReceiptListRequest{testID("Genesis receipt list " + condition)})
			detail := reader.Detail(ctx, ReceiptDetailRequest{testID("Genesis receipt detail " + condition), operation})
			if condition == "invalid-challenge" {
				if listed.Result.Outcome != IntegrityFailure || listed.Result.Reason != InvalidProof || listed.Payload != nil ||
					detail.Result.Outcome != IntegrityFailure || detail.Result.Reason != InvalidProof || detail.Payload != nil {
					t.Error("invalid Genesis recovery challenge disclosed a receipt", listed.Result, listed.Payload != nil, detail.Result, detail.Payload != nil)
				}
			} else if listed.StateResult != PublicQuerySuccess || listed.Payload == nil || len(listed.Payload.Receipts) != 1 ||
				listed.Payload.Receipts[0].OperationID != operation || detail.StateResult != PublicQuerySuccess || detail.Payload == nil || detail.Payload.Receipt.OperationID != operation || len(detail.Payload.EncodedReceipt) != 471 {
				t.Error("valid Genesis receipt did not survive public list and detail", listed.StateResult, detail.StateResult)
			}
			reader.Close()
			gotPublic, gotPrivate := f.keys.Calls()
			if public != gotPublic || private != gotPrivate || signs != f.env.Trust.(*fixtureTrust).signs || creates != memory.creates || swaps != memory.cas || source.reads == 0 || source.closes != 2 {
				t.Error("receipt query reached private work or did not close both GET sources", source.reads, source.closes)
			}
		})
	}
}
