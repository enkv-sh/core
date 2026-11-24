package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type installedGeneratedReadSource struct {
	store                  contract.Store
	configuration          contract.StoreConfiguration
	reads, closes          int
	missingKey, corruptKey string
	afterRead              func(string)
}

func (s *installedGeneratedReadSource) CandidateLocation() contract.StoreLocation {
	c := s.configuration
	return contract.StoreLocation{Provider: c.Provider, Region: c.Region, Bucket: c.Bucket,
		PrefixBeforeHEAD: c.PrefixBeforeHEAD, ExpectedOwner: c.ExpectedOwner}
}
func (s *installedGeneratedReadSource) ReadHEAD(ctx context.Context) contract.ReadResult {
	return s.Read(ctx, s.Descriptor().HeadKey, contract.MaxHeadLength)
}
func (s *installedGeneratedReadSource) ReadHEADGuarded(ctx context.Context, owner string) contract.ReadResult {
	if owner != s.configuration.ExpectedOwner {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.ReadHEAD(ctx)
}
func (s *installedGeneratedReadSource) ReadConfiguration(ctx context.Context, domain, store contract.ID) contract.ReadResult {
	key, err := contract.StoreConfigurationKeyForID(s.configuration.Provider, s.configuration.PrefixBeforeHEAD, domain, store)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.Read(ctx, key, contract.MaxStoreConfigurationLength)
}
func (s *installedGeneratedReadSource) ReadRoot(ctx context.Context, ref contract.Ref) contract.ReadResult {
	key, err := format.Key(s.Descriptor().Prefix, ref)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return s.Read(ctx, key, ref.Length)
}
func (s *installedGeneratedReadSource) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.reads++
	if key == s.missingKey {
		return contract.ReadResult{Status: contract.ReadMissing}
	}
	result := s.store.Read(ctx, key, limit)
	if key == s.corruptKey && result.Status == contract.ReadOK {
		result.Body = bytes.Clone(result.Body)
		result.Body[len(result.Body)-1] ^= 1
	}
	if s.afterRead != nil {
		s.afterRead(key)
	}
	return result
}
func (s *installedGeneratedReadSource) Descriptor() contract.Descriptor { return s.store.Descriptor() }
func (s *installedGeneratedReadSource) StoreConfiguration() contract.StoreConfiguration {
	return s.configuration
}
func (s *installedGeneratedReadSource) Close() { s.closes++ }

func installedGeneratedReaderFixture(t testing.TB, f installedApplyTestFixture) (*InstalledGeneratedReader, *installedGeneratedReadSource) {
	t.Helper()
	source := &installedGeneratedReadSource{store: f.env.Store,
		configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	reader, err := NewInstalledGeneratedReader(GeneratedReadInstallation{
		Candidate: source, ExpectedDomain: f.env.Domain, ExpectedStore: source.Descriptor(), PublicBasis: f.basis,
		Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return source, Result{}
		},
		CloseInstalled: func() {},
	})
	if err != nil {
		t.Fatal("GET-only generated reader construction", err)
	}
	t.Cleanup(reader.Close)
	if source.reads != 0 {
		t.Fatal("generated reader constructor performed I/O")
	}
	return reader, source
}

// full_only: false
func TestInstalledGeneratedListEmptyObservationOwnsPublicBasisAndClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	source := &installedGeneratedReadSource{store: f.env.Store,
		configuration: f.env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	closed := 0
	input := GeneratedReadInstallation{Candidate: source, ExpectedDomain: f.env.Domain, ExpectedStore: source.Descriptor(), PublicBasis: f.basis,
		Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
			return source, Result{}
		},
		CloseInstalled: func() { closed++ }}
	reader, err := NewInstalledGeneratedReader(input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	if source.reads != 0 || closed != 0 {
		t.Fatal("public list constructor touched its dependencies")
	}
	before := bytes.Clone(input.PublicBasis.Descriptor)
	input.PublicBasis.Descriptor[0] ^= 1
	defer copy(input.PublicBasis.Descriptor, before)
	got := reader.List(ctx, testID("empty generated observation"))
	if got.StateResult != contract.ReaderSuccess || got.View == nil || got.View.DomainID != f.env.Domain ||
		got.View.RevisionID != f.selected.head.Core.Revision || got.View.SnapshotID != f.selected.root.Snapshot ||
		len(got.View.CurrentGenerations) != 0 || len(got.View.Effects) != 0 || len(got.View.Duties) != 0 || len(got.View.Hazards) != 0 ||
		len(got.View.PendingReleases) != 0 || len(got.View.NextActions) != 0 || got.View.ActiveOperation != nil || source.closes != 1 {
		t.Fatal("empty authenticated state or owned public basis changed", got, source.closes)
	}
	reader.Close()
	reader.Close()
	reads := source.reads
	if closed != 1 || reader.List(ctx, testID("closed generated reader")).StateResult != contract.ReaderRefused || source.reads != reads {
		t.Fatal("closed list installation was reused or closed twice", closed)
	}
}

// full_only: false
func TestInstalledGeneratedListKeepsFixedObservationAcrossHEADChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
	if !ok {
		t.Fatal("fixed observation fixture has no memory store")
	}
	headKey := memory.Descriptor().HeadKey
	beforeHead := memory.objects[headKey]
	input := []ApplyEntryInput{{Name: "plain", ValueSource: contract.Supplied, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, ConfidentialityClass: contract.Plain,
		Recipients: []contract.ID{f.selected.admission.recipient}, InputBytes: []byte("selected successor")}}
	apply := f.engine(t, f.selected, input, nil)
	changed := apply.Apply(ctx, testID("concurrent selected successor"), input)
	apply.Close()
	if changed.Result.Outcome != ObservedCurrent {
		t.Fatal("concurrent successor fixture failed", changed.Result)
	}
	afterHead := memory.objects[headKey]
	memory.objects[headKey] = beforeHead
	defer func() { memory.objects[headKey] = afterHead }()
	childKey, err := format.Key(memory.Descriptor().Prefix, *f.selected.root.Recipients[0])
	if err != nil {
		t.Fatal(err)
	}
	reader, source := installedGeneratedReaderFixture(t, f)
	switched := false
	source.afterRead = func(key string) {
		if key == childKey && !switched {
			switched = true
			memory.objects[headKey] = afterHead
		}
	}
	first := reader.List(ctx, testID("first fixed observation"))
	if !switched || first.View == nil || first.View.RevisionID != f.selected.head.Core.Revision || first.View.SnapshotID != f.selected.root.Snapshot {
		t.Fatal("concurrent HEAD change rewrote the fixed observation", first, switched)
	}
	second := reader.List(ctx, testID("next fixed observation"))
	if second.View == nil || second.View.RevisionID != changed.Result.ObservedRevision ||
		second.View.SnapshotID != changed.Result.ObservedSnapshotID || second.View.SnapshotID == first.View.SnapshotID {
		t.Fatal("new invocation reused the earlier observation", second)
	}
}

// full_only: false
func TestInstalledGeneratedListAuthenticatesCurrentAndRetainedWorkWithGETOnly(t *testing.T) {
	for _, condition := range []string{"generated-final", "generated-active", "generated-uncertain"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, true)
			var selected *StateSession
			if condition == "generated-uncertain" {
				selected = configurationRecoveryRetiring(t, ctx, f.env, f.selected, true)
			} else {
				selected = configurationRecoveryGenerated(t, ctx, f.env, f.selected, condition)
			}
			reader, source := installedGeneratedReaderFixture(t, f)
			memory, ok := underlyingAdmittedMemoryStore(f.env.Store)
			if !ok {
				t.Fatal("generated read fixture has no memory counters")
			}
			trust, ok := underlyingAdmittedFixtureTrust(f.env.Trust)
			if !ok {
				t.Fatal("generated read fixture has no signing counters")
			}
			public, private := f.keys.Calls()
			creates, cas, signs := memory.creates, memory.cas, trust.signs
			got := reader.List(ctx, testID(condition+" lost response discovery"))
			if got.StateResult != contract.ReaderSuccess || got.Result.Outcome != ObservedCurrent || got.View == nil ||
				got.Context.Operation != GeneratedListOperation || got.View.DomainID != f.env.Domain ||
				got.View.RevisionID != selected.head.Core.Revision || got.View.SnapshotID != selected.root.Snapshot ||
				uint32(len(got.View.CurrentGenerations)) != selected.root.Generated.GeneratedCurrent ||
				uint32(len(got.View.Effects)) != selected.root.Generated.Attempts ||
				uint32(len(got.View.Duties)) != selected.root.Generated.Duties ||
				uint32(len(got.View.Hazards)) != selected.root.Generated.Hazards || source.closes != 1 {
				t.Fatal("GET-only generated list did not expose the exact bounded observation", got, source.closes)
			}
			for _, row := range got.View.CurrentGenerations {
				_, entry := observeCurrentValueEntry(t, selected, row.Name)
				if row.EntryIncarnationID != entry.Incarnation || row.GenerationID != entry.Generated.GenerationID ||
					row.Epoch != entry.Generated.Epoch || row.OriginOperationID != entry.Generated.OriginOperationID ||
					row.OriginAttemptID != entry.Generated.OriginAttemptID || row.ResourceID != entry.Generated.ResourceIncarnationID {
					t.Fatal("list changed exact current generation facts", row)
				}
			}
			if condition == "generated-active" {
				if got.View.ActiveOperation == nil || got.View.ActiveOperation.OperationID != selected.root.Generated.ActiveOwner ||
					got.View.ActiveOperation.PhaseID != selected.root.Generated.ActivePhase || len(got.View.NextActions) != 1 ||
					got.View.NextActions[0] != (GeneratedNextAction{Command: "apply", OperationID: selected.root.Generated.ActiveOwner}) {
					t.Fatal("active operation lost its exact continuation selector", got.View)
				}
			}
			if condition == "generated-uncertain" {
				if len(got.View.NextActions) != 2 || got.View.NextActions[0].Command != "generated retire" ||
					got.View.NextActions[0].DutyID != got.View.Duties[0].Record.DutyID ||
					got.View.NextActions[1].Command != "generated accept-retirement-risk" ||
					got.View.NextActions[1].DutyID != got.View.Duties[0].Record.DutyID || got.View.NextActions[1].AttemptID.IsZero() {
					t.Fatal("retained work lost its exact duty/Attempt selectors", got.View.NextActions)
				}
			}
			again := reader.List(ctx, testID(condition+" independent second observation"))
			if again.View == nil || !reflect.DeepEqual(got.View, again.View) || source.closes != 2 {
				t.Fatal("fresh public list changed deterministic facts", again, source.closes)
			}
			if p, q := f.keys.Calls(); p != public || q != private || trust.signs != signs || memory.creates != creates || memory.cas != cas {
				t.Fatal("public generated read used KMS, signing or Store mutation")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedListRefusesIncompleteSelectedClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	selected := configurationRecoveryRetiring(t, ctx, f.env, f.selected, false)
	key, err := format.Key(f.env.Store.Descriptor().Prefix, selected.root.RequiredSupport[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"missing", "corrupt", "expired"} {
		t.Run(damage, func(t *testing.T) {
			reader, source := installedGeneratedReaderFixture(t, f)
			readCtx := ctx
			want := contract.ReaderUnavailable
			switch damage {
			case "missing":
				source.missingKey = key
			case "corrupt":
				source.corruptKey, want = key, contract.ReaderPositiveDefect
			case "expired":
				var stop context.CancelFunc
				readCtx, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				want = contract.ReaderRefused
			}
			out := reader.List(readCtx, testID("generated list "+damage))
			if out.StateResult != want || out.Result.Outcome == ObservedCurrent || out.View != nil {
				t.Fatal("incomplete evidence became empty successful inventory", out)
			}
			if damage == "expired" && source.reads != 0 {
				t.Fatal("expired list reached GET")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedListRechecksAdmissionAfterHazardQualification(t *testing.T) {
	for _, condition := range []string{"cancel", "deadline", "complete"} {
		t.Run(condition, func(t *testing.T) {
			env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				source := &installedGeneratedReadSource{store: env.Store, configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
				calls := 0
				reader, err := NewInstalledGeneratedReader(GeneratedReadInstallation{
					Candidate: source, ExpectedDomain: env.Domain, ExpectedStore: source.Descriptor(), PublicBasis: selected.admission.publicBasis(),
					Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
						return source, Result{}
					},
					CloseInstalled: func() {},
					ResolveImplementation: func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
						calls++
						switch condition {
						case "cancel":
							cancel()
						case "deadline":
							time.Sleep(time.Minute)
						}
						return contract.GeneratorImplementation{}, contract.ErrRecord
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				got := reader.List(ctx, testID("generated qualification admission"))
				if calls != 1 || source.closes != 1 {
					t.Fatal("hazard qualification or source join was absent", calls, source.closes)
				}
				if condition == "complete" {
					if got.StateResult != contract.ReaderSuccess || got.Result.Outcome != ObservedCurrent || got.View == nil || len(got.View.Hazards) != 1 || got.View.Hazards[0].CleanupImplementationQualified {
						t.Fatal("completed passive qualification changed the exact observation", got)
					}
					return
				}
				want := contract.ReasonCancelled
				if condition == "deadline" {
					want = contract.ReasonExpired
				}
				if got.StateResult != contract.ReaderRefused || got.FailureReason != want || got.Result != refused(AdmissionInvalid) || got.View != nil {
					t.Fatal("interrupted hazard qualification published a successful observation", got)
				}
			})
		})
	}
}

// full_only: false
func TestInstalledGeneratedListCloseJoinsHazardQualification(t *testing.T) {
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		source := &installedGeneratedReadSource{store: env.Store, configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
		entered, release, disposed := make(chan struct{}), make(chan struct{}), make(chan struct{})
		reader, err := NewInstalledGeneratedReader(GeneratedReadInstallation{
			Candidate: source, ExpectedDomain: env.Domain, ExpectedStore: source.Descriptor(), PublicBasis: selected.admission.publicBasis(),
			Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return source, Result{}
			},
			CloseInstalled: func() { close(disposed) },
			ResolveImplementation: func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
				close(entered)
				<-release
				return contract.GeneratorImplementation{}, contract.ErrRecord
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan PublicGeneratedListResult, 1)
		go func() { result <- reader.List(ctx, testID("generated qualification close join")) }()
		<-entered
		go reader.Close()
		synctest.Wait()
		select {
		case <-disposed:
			t.Error("Close disposed the resolver before its invocation joined")
		default:
		}
		close(release)
		got := <-result
		<-disposed
		if got.StateResult != contract.ReaderSuccess || source.closes != 1 {
			t.Fatal("joined finite observation did not complete", got, source.closes)
		}
	})
}
