package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

func installedInspectionInput(t testing.TB, f installedApplyTestFixture, source *installedGeneratedReadSource) InspectionReadInstallation {
	t.Helper()
	validator := NewPublicConfigurationValidator(nil)
	return InspectionReadInstallation{Candidate: source, Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return source, Result{}
	},
		ExpectedDomain: f.env.Domain, ExpectedStore: source.Descriptor(), PublicBasis: f.basis, Validator: validator,
		SourcePins: installedAdministrativeTestPins(), CheckSource: func(context.Context) error { return nil }, CloseInstalled: func() {}}
}

func installedInspectionFixture(t testing.TB, f installedApplyTestFixture) (*InstalledInspectionReader, *installedGeneratedReadSource) {
	t.Helper()
	source := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	reader, err := NewInstalledInspectionReader(installedInspectionInput(t, f, source))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if source.reads != 0 {
		t.Fatal("inspection constructor performed GET")
	}
	return reader, source
}

// full_only: false
func TestInstalledInspectionReadsCompleteSelectedClosureWithGETOnly(t *testing.T) {
	for _, condition := range []string{"empty", "generated-active", "generated-uncertain"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			if condition == "generated-active" {
				f.selected = configurationRecoveryGenerated(t, ctx, f.env, f.selected, condition)
			}
			if condition == "generated-uncertain" {
				f.selected = configurationRecoveryRetiring(t, ctx, f.env, f.selected, true)
			}
			reader, source := installedInspectionFixture(t, f)
			memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
			if !ok {
				t.Fatal("missing memory counters")
			}
			trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
			if !ok {
				t.Fatal("missing signing counters")
			}
			public, private := f.keys.Calls()
			creates, cas, signs := memory.creates, memory.cas, trust.signs
			got := reader.Inspect(ctx, DomainInspectionRequest{testID("complete inspection " + condition)})
			if got.StateResult != PublicQuerySuccess || got.View == nil || got.ValidateMetadataWorkOutput() != nil || source.closes != 1 {
				t.Fatal("complete GET inspection failed", got, source.closes)
			}
			v := got.View
			if v.Observation != (PublicObservation{DomainID: f.env.Domain, HeadRevisionID: f.selected.head.Core.Revision, SnapshotID: f.selected.root.Snapshot, RootDigest: f.selected.head.Core.Root.Digest}) || len(v.Entries) != len(f.selected.root.Names) || len(v.Recipients) != int(f.selected.root.RecipientCount) || len(v.Generated.Effects) != int(f.selected.root.Generated.Attempts) || len(v.Generated.Duties) != int(f.selected.root.Generated.Duties) || len(v.Generated.Hazards) != int(f.selected.root.Generated.Hazards) || len(v.Work.Groups) != len(f.selected.adminIndex.Groups) {
				t.Fatal("inspection omitted selected rows", v)
			}
			for i, row := range v.Work.Groups {
				if !reflect.DeepEqual(row, f.selected.adminIndex.Groups[i]) {
					t.Fatal("complete selected administrative group changed")
				}
			}
			if condition == "generated-active" && (v.ActiveOperation == nil || v.ActiveOperation.OperationID != f.selected.root.Generated.ActiveOwner) {
				t.Fatal("active canonical owner missing")
			}
			originalWarnings := v.Warnings
			v.Warnings.Generated.PossibleLiveResidue = !v.Warnings.Generated.PossibleLiveResidue
			if got.ValidateMetadataWorkOutput() == nil {
				t.Fatal("changed aggregate generated warning accepted")
			}
			v.Warnings = originalWarnings
			v.Warnings.PossibleStoreGarbage = !v.Warnings.PossibleStoreGarbage
			if got.ValidateMetadataWorkOutput() == nil {
				t.Fatal("changed aggregate Store garbage warning accepted")
			}
			v.Warnings = originalWarnings
			again := reader.Inspect(ctx, DomainInspectionRequest{testID("next complete inspection " + condition)})
			if again.View == nil || !reflect.DeepEqual(again.View, v) {
				t.Fatal("independent complete projection changed")
			}
			if p, q := f.keys.Calls(); p != public || q != private || memory.creates != creates || memory.cas != cas || trust.signs != signs {
				t.Fatal("inspection used KMS, signing or Store mutation")
			}
		})
	}
}

// full_only: false
func TestInstalledInspectionKeepsLoadedObservationAcrossHEADChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("missing memory source")
	}
	headKey := memory.Descriptor().HeadKey
	before := memory.objects[headKey]
	input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("successor")}}
	apply := f.engine(t, f.selected, input, nil)
	changed := apply.Apply(ctx, testID("inspection concurrent successor"), input)
	apply.Close()
	if changed.Result.Outcome != ObservedCurrent {
		t.Fatal(changed.Result)
	}
	after := memory.objects[headKey]
	memory.objects[headKey] = before
	defer func() { memory.objects[headKey] = after }()
	childKey, err := format.Key(memory.Descriptor().Prefix, *f.selected.root.Recipients[0])
	if err != nil {
		t.Fatal(err)
	}
	reader, source := installedInspectionFixture(t, f)
	switched := false
	source.afterRead = func(key string) {
		if key == childKey && !switched {
			switched = true
			memory.objects[headKey] = after
		}
	}
	first := reader.Inspect(ctx, DomainInspectionRequest{testID("fixed complete inspection")})
	if !switched || first.View == nil || first.View.Observation.HeadRevisionID != f.selected.head.Core.Revision || len(first.View.Entries) != 0 {
		t.Fatal("HEAD change spliced a later selected body", first)
	}
	second := reader.Inspect(ctx, DomainInspectionRequest{testID("fresh complete inspection")})
	if second.View == nil || second.View.Observation.HeadRevisionID != changed.Result.ObservedRevision || len(second.View.Entries) != 1 || first.View.Observation == second.View.Observation {
		t.Fatal("fresh inspection reused fixed old selection", second)
	}
}

// full_only: false
func TestInstalledRecipientInspectionReturnsOnlyGrantedMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	authority, recipient := f.selected.admission.recipient, fixtureID(f.env.Domain, "reader")
	membership := []contract.ID{authority, recipient}
	slices.SortFunc(membership, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input := []ApplyEntryInput{{Name: "", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: membership, InputBytes: []byte("visible")},
		{Name: "ungranted-name", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{authority}, InputBytes: []byte("ungranted-value")}}
	engine := f.engine(t, f.selected, input, nil)
	changed := engine.Apply(ctx, testID("recipient metadata selected input"), input)
	engine.Close()
	if changed.Result.Outcome != ObservedCurrent {
		t.Fatal(changed.Result)
	}
	f.selected = f.open(t, ctx)
	reader, source := installedInspectionFixture(t, f)
	recorder := telemetry.NewRecorder()
	observed := telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
	got := reader.InspectRecipient(observed, RecipientInspectionRequest{testID("recipient scoped inspection"), recipient})
	if got.StateResult != PublicQuerySuccess || got.View == nil || got.Validate() != nil || got.View.RecipientID != recipient || len(got.View.Entries) != 1 || got.View.Entries[0].Name != "" || got.View.Entries[0].RawLength != 7 || cap(got.View.Entries) != 1 {
		t.Fatal("recipient scope changed", got)
	}
	for _, row := range recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8)) {
		if strings.Contains(fmt.Sprint(row), "ungranted") {
			t.Fatal("scoped telemetry disclosed ungranted data")
		}
	}
	got.View.Entries[0].Name = "changed returned name"
	again := reader.InspectRecipient(ctx, RecipientInspectionRequest{testID("independent recipient metadata"), recipient})
	if again.View == nil || again.View.Entries[0].Name != "" {
		t.Fatal("recipient result changed selected facts")
	}
	absent := reader.InspectRecipient(ctx, RecipientInspectionRequest{testID("absent recipient metadata"), testID("absent recipient")})
	if absent.StateResult != PublicQueryRefused || absent.View != nil || absent.Query == nil || absent.FailureReason != contract.ReasonTargetAbsent || absent.Validate() != nil || source.closes != 3 {
		t.Fatal("absent recipient lost safe closed failure", absent)
	}
}

// full_only: false
func TestInstalledInspectionRejectsRequiredDamageAndSourceChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
	f.selected = configurationRecoveryGenerated(t, ctx, f.env, f.selected, "generated-active")
	var optional format.Ref
	for _, page := range f.selected.adminIndex.Pages {
		if !page.ReadRequired && !slices.ContainsFunc(page.Spans, func(span format.AdministrativeSpan) bool { return span.Mandatory }) {
			optional = page.Ref
			break
		}
	}
	if optional == (format.Ref{}) {
		t.Fatal("fixture has no optional work")
	}
	for _, condition := range []string{"optional-work", "mandatory-index", "source-before", "source-after", "cancel-final"} {
		t.Run(condition, func(t *testing.T) {
			readCtx, stop := context.WithCancel(ctx)
			defer stop()
			source := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
			installation := installedInspectionInput(t, f, source)
			checks := 0
			installation.CheckSource = func(context.Context) error {
				checks++
				if condition == "source-before" || condition == "source-after" && checks == 2 {
					return errors.New("ungranted-name must remain private")
				}
				if condition == "cancel-final" && checks == 2 {
					stop()
				}
				return nil
			}
			var err error
			if condition == "optional-work" {
				source.missingKey, err = format.Key(source.Descriptor().Prefix, optional)
			}
			if condition == "mandatory-index" {
				source.missingKey, err = format.Key(source.Descriptor().Prefix, f.selected.root.AdministrativeIndex)
			}
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewInstalledInspectionReader(installation)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			got := reader.Inspect(readCtx, DomainInspectionRequest{testID("inspection unavailable " + condition)})
			want := PublicQueryRefused
			if condition == "optional-work" || condition == "mandatory-index" {
				want = PublicQueryUnavailable
			}
			if got.StateResult != want || got.View != nil || got.ValidateMetadataWorkOutput() != nil {
				t.Fatal("incomplete inspection became successful payload", got)
			}
			if condition == "source-before" && source.reads != 0 {
				t.Fatal("source mismatch reached provider reads")
			}
			if condition == "optional-work" {
				receipt, receiptSource := installedReceiptFixture(t, f)
				receiptSource.missingKey = source.missingKey
				listed := receipt.List(ctx, ReceiptListRequest{testID("mandatory read tolerates unrelated work")})
				if listed.StateResult != PublicQuerySuccess || listed.Payload == nil {
					t.Fatal("complete inspection weakened narrow receipt purpose", listed)
				}
			}
		})
	}
}

type inspectionProjectionCancellationSource struct {
	*installedGeneratedReadSource
	recorder                *telemetry.Recorder
	cancel                  context.CancelFunc
	outputKey               string
	authenticated, canceled bool
	diagnostics             []telemetry.DiagnosticRecord
}

func (s *inspectionProjectionCancellationSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	rows := s.recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 8))
	s.diagnostics = append(s.diagnostics, rows...)
	for _, row := range rows {
		if row.Event == telemetry.DiagnosticCheckpoint && row.Stage == telemetry.DiagnosticAuthentication {
			s.authenticated = true
		}
	}
	if s.authenticated && key == s.outputKey && !s.canceled {
		s.canceled = true
		s.cancel()
		return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonLimit}
	}
	return s.installedGeneratedReadSource.Read(ctx, key, limit)
}

// full_only: false
func TestInstalledInspectionCancellationDuringOutputProjectionIsCanceled(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	base := &installedGeneratedReadSource{store: f.env.Store, configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	recorder := telemetry.NewRecorder()
	readCtx, stop := context.WithCancel(ctx)
	defer stop()
	source := &inspectionProjectionCancellationSource{installedGeneratedReadSource: base, recorder: recorder, cancel: stop}
	for i, page := range f.selected.support {
		if slices.ContainsFunc(page.Records, func(row contract.SupportRecordView) bool {
			return row.Kind == contract.OutputConfigurationSliceSupportKind
		}) {
			var err error
			source.outputKey, err = format.Key(base.Descriptor().Prefix, f.selected.root.RequiredSupport[i])
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if source.outputKey == "" {
		t.Fatal("fixture has no selected output configuration page")
	}
	installation := installedInspectionInput(t, f, base)
	installation.Construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		return source, Result{}
	}
	reader, err := NewInstalledInspectionReader(installation)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	observed := telemetry.WithCapability(readCtx, telemetry.NewCapability(nil, recorder))
	got := reader.Inspect(observed, DomainInspectionRequest{testID("canceled exact output projection")})
	if !source.authenticated || !source.canceled || base.closes != 1 {
		t.Fatal("regression did not cancel the post-selection exact output reread", source.authenticated, source.canceled, base.closes)
	}
	if got.StateResult != PublicQueryRefused || got.FailureReason != contract.ReasonCancelled || got.View != nil || got.ValidateMetadataWorkOutput() != nil {
		t.Fatal("post-selection cancellation was reported as a selected-data failure", got)
	}
}
