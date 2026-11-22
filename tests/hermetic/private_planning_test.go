package core

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

func installedPlanningFixture(t *testing.T, env fixtureEnvironment, selected *StateSession, public contract.PublicConfiguration, inputs []contract.PlanningInput,
	factory func(context.Context, contract.PlanningAdmission) (PlanningCustody, error)) (*InstalledPlanning, *candidateReadProbe, *constructedReadProbe) {
	t.Helper()
	candidate := candidateProbeForSelected(t, env, selected)
	source := &constructedReadProbe{store: env.Store, descriptor: env.Store.Descriptor(), configuration: env.Store.(contract.StoreConfigurationSource).StoreConfiguration()}
	validator := NewPublicConfigurationValidator(nil)
	digest, err := PlanningInputDigest(public, inputs)
	if err != nil {
		t.Fatal(err)
	}
	pair := contract.PlanningSourcePair{FileIdentity: fixtureID(env.Domain, "source-file"), EditableDigest: fixtureID(env.Domain, "captured editable"),
		GeneratedDigest: fixtureID(env.Domain, "captured generated"), EditableLength: 1, GeneratedLength: 1}
	planner, err := NewInstalledPlanning(PlanningInstallation{
		Reader: ReaderInstallation{Candidate: candidate, ExpectedDomain: env.Domain, ExpectedStore: source.descriptor,
			PublicBasis: readerTypedBasisFixture(t, selected), Validator: validator,
			Construct: func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
				return source, Result{}
			}, CloseInstalled: func() {}},
		Sources: contract.PlanningSources{Trusted: pair, Proposed: pair}, FileIdentity: pair.FileIdentity, InputDigest: digest,
		CredentialRoute: env.Custody.PlanningCredentialRoute(), AdmitCustody: factory,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(planner.Close)
	return planner, candidate, source
}

type blockingPlanningCheck struct {
	PlanningCustody
	entered     chan context.Context
	release     <-chan struct{}
	returned    atomic.Bool
	closedEarly atomic.Bool
	checks      atomic.Int32
	displays    atomic.Int32
	closes      atomic.Int32
}

func (p *blockingPlanningCheck) Check(ctx context.Context) contract.PlanningCheckResult {
	p.checks.Add(1)
	p.entered <- ctx
	<-p.release
	result := p.PlanningCustody.Check(ctx)
	p.returned.Store(true)
	return result
}

func (p *blockingPlanningCheck) Display(ctx context.Context) contract.PlanningDisplayResult {
	p.displays.Add(1)
	return p.PlanningCustody.Display(ctx)
}

func (p *blockingPlanningCheck) Close() {
	if !p.returned.Load() {
		p.closedEarly.Store(true)
	}
	p.PlanningCustody.Close()
	p.closes.Add(1)
}

type planningCloseReadProbe struct {
	PublicSelectedReader
	private     *blockingPlanningCheck
	closes      atomic.Int32
	closedEarly atomic.Bool
}

func (p *planningCloseReadProbe) Close() {
	if !p.private.returned.Load() || p.private.closes.Load() != 1 {
		p.closedEarly.Store(true)
	}
	p.PublicSelectedReader.Close()
	p.closes.Add(1)
}

// full_only: false
func TestPlanningCloseCancelsAndJoinsActiveCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	sealed := suppliedSecret(t, env, "secret", "active planning close", custody.StandardValue)
	run.suppliedSelection(f, []ApplyEntryInput{sealed})
	public := comparisonCurrentInput(t, env, f.session)
	inputs := []contract.PlanningInput{{Name: sealed.Name, Form: contract.PlanningSealed, SealedInput: sealed.InputBytes}}
	release := make(chan struct{})
	private := &blockingPlanningCheck{entered: make(chan context.Context, 1), release: release}
	var factories, constructs, installedCloses atomic.Int32
	var installedClosedEarly, closeReturnedEarly atomic.Bool
	planner, candidate, source := installedPlanningFixture(t, env, f.session, public, inputs, func(c context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
		factories.Add(1)
		owner, err := env.Custody.NewPlanningCustody(c, q)
		if err != nil {
			return nil, err
		}
		private.PlanningCustody = owner
		return private, nil
	})
	read := &planningCloseReadProbe{PublicSelectedReader: source, private: private}
	planner.reader.construct = func(context.Context, contract.StoreConfiguration) (PublicSelectedReader, Result) {
		constructs.Add(1)
		return read, Result{}
	}
	planner.reader.closeInstalled = func() {
		if !private.returned.Load() || private.closes.Load() != 1 || read.closes.Load() != 1 {
			installedClosedEarly.Store(true)
		}
		installedCloses.Add(1)
	}
	planDone, closeDone := make(chan struct{}), make(chan struct{})
	releaseCheck := sync.OnceFunc(func() { close(release) })
	startClose := sync.OnceFunc(func() {
		go func() {
			planner.Close()
			if !private.returned.Load() || private.closes.Load() != 1 || read.closes.Load() != 1 || installedCloses.Load() != 1 {
				closeReturnedEarly.Store(true)
			}
			close(closeDone)
		}()
	})
	wait := func(done <-chan struct{}, name string) bool {
		t.Helper()
		select {
		case <-done:
			return true
		case <-time.After(5 * time.Second):
			t.Errorf("%s did not join", name)
			return false
		}
	}
	t.Cleanup(func() {
		cancel()
		releaseCheck()
		startClose()
		wait(planDone, "cleanup Plan")
		wait(closeDone, "cleanup Close")
	})
	var result PlanningResult
	go func() {
		result = planner.Plan(ctx, fixtureID(env.Domain, "active planning request"), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningEquality})
		close(planDone)
	}()
	var checkContext context.Context
	select {
	case checkContext = <-private.entered:
	case <-planDone:
		t.Fatal("valid planning fixture did not enter Check", result)
	case <-time.After(5 * time.Second):
		t.Fatal("Plan did not enter Check")
	}
	if factories.Load() != 1 || constructs.Load() != 1 || private.checks.Load() != 1 || checkContext.Err() != nil {
		t.Fatal("active Check fixture did not acquire one live private/read owner")
	}
	startClose()
	if !wait(checkContext.Done(), "Check cancellation") {
		return
	}
	if checkContext.Err() != context.Canceled || ctx.Err() != nil {
		t.Fatal("Close did not cancel the active Check independently of its caller")
	}
	if private.returned.Load() || private.closes.Load() != 0 || read.closes.Load() != 0 || installedCloses.Load() != 0 {
		t.Fatal("Close released resources while Check was blocked")
	}
	select {
	case <-closeDone:
		t.Fatal("Close returned while Check was blocked")
	default:
	}
	select {
	case <-planDone:
		t.Fatal("Plan returned while Check was blocked")
	default:
	}
	releaseCheck()
	if !wait(planDone, "Plan") || !wait(closeDone, "Close") {
		return
	}
	if result.StateResult != contract.ReaderRefused || result.Verdict != contract.ComparisonUnable || result.PrivateComplete ||
		!slices.ContainsFunc(result.Diagnostics, func(d contract.Diagnostic) bool { return d.Reason == contract.ReasonCancelled }) {
		t.Fatal("cancelled Check did not retain a refused incomplete plan", result)
	}
	if private.closedEarly.Load() || read.closedEarly.Load() || installedClosedEarly.Load() || closeReturnedEarly.Load() ||
		private.closes.Load() != 1 || read.closes.Load() != 1 || source.closes != 1 || installedCloses.Load() != 1 || private.displays.Load() != 0 {
		t.Fatal("Close did not join Check, custody and read resources in order exactly once")
	}
	candidateCalls, reads := len(candidate.calls), source.reads
	planner.Close()
	later := planner.Plan(ctx, fixtureID(env.Domain, "closed planning request"), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningEquality})
	if later.StateResult != contract.ReaderRefused || later.Verdict != contract.ComparisonUnable || later.PrivateComplete ||
		factories.Load() != 1 || constructs.Load() != 1 || private.checks.Load() != 1 || private.displays.Load() != 0 ||
		len(candidate.calls) != candidateCalls || source.reads != reads || private.closes.Load() != 1 || read.closes.Load() != 1 || source.closes != 1 || installedCloses.Load() != 1 {
		t.Fatal("closed planner acquired resources or repeated resource release", later)
	}
}

// full_only: false
func TestPlanningUsesOneAuthenticatedObservation(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			env, keys := genesisEnvironment(t, family, true)
			run := newScenarioRun(t, ctx, env)
			f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
			sealed := suppliedSecret(t, env, "secret", "planning original", custody.StandardValue)
			input := append(f.session.currentEntryInputs(), sealed)
			run.suppliedSelection(f, input)
			original := bytes.Clone(sealed.InputBytes)
			public := comparisonCurrentInput(t, env, f.session)
			private := []contract.PlanningInput{{Name: sealed.Name, Form: contract.PlanningSealed, SealedInput: sealed.InputBytes}}
			observed := f.session.root.Snapshot
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			var creates, cas, signs, reads, publicCalls int
			calls := 0
			var source *constructedReadProbe
			factory := func(c context.Context, q contract.PlanningAdmission) (PlanningCustody, error) {
				calls++
				if q.SnapshotID != observed || len(q.Targets) != 1 || q.Targets[0].Current == nil {
					t.Fatal("private source lost fixed selection")
				}
				changed := slices.DeleteFunc(f.session.currentEntryInputs(), func(row ApplyEntryInput) bool { return row.Name == "secret" })
				changed = append(changed, suppliedSecret(t, env, "secret", "planning later current", custody.AlternateStandardValue))
				run.suppliedSelection(f, changed)
				creates, cas, signs, reads = store.creates, store.cas, trust.signs, source.reads
				publicCalls, _ = keys.Calls()
				return env.Custody.NewPlanningCustody(c, q)
			}
			planner, candidate, opened := installedPlanningFixture(t, env, f.session, public, private, factory)
			candidate.configuration = contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonAccess}
			source = opened
			got := planner.Plan(ctx, fixtureID(env.Domain, "planning request"), public, private, contract.PlanningOptions{Purpose: contract.PlanningEquality})
			if slices.Contains(candidate.calls, "configuration") {
				t.Fatal("ordinary plan requested the recovery helper")
			}
			if got.StateResult != contract.ReaderSuccess || got.Verdict != contract.ComparisonMatch || !got.PrivateComplete || got.Observation == nil || got.Observation.SnapshotID != observed || f.session.root.Snapshot == observed ||
				len(got.PrivateEntries) != 1 || got.PrivateEntries[0].Relation != contract.PlanningEqual || calls != 1 {
				t.Fatalf("fixed planning observation failed: state=%s verdict=%s operation=%t observation=%t private_rows=%d complete=%t factory_calls=%d diagnostics=%+v",
					got.StateResult, got.Verdict, !got.Context.OperationID.IsZero(), got.Observation != nil, len(got.PrivateEntries), got.PrivateComplete, calls, got.Diagnostics)
			}
			if store.creates != creates || store.cas != cas || trust.signs != signs || source.reads != reads || !bytes.Equal(original, sealed.InputBytes) {
				t.Fatal("planning changed state/source or reread a later selection")
			}
			if p, _ := keys.Calls(); p != publicCalls {
				t.Fatal("planning qualified a recipient key")
			}
			planner.Close()
			if source.closes != 1 {
				t.Fatal("planning did not join and close the read source once", source.closes)
			}
			parent := admitSuppliedComparison(t, f.session, env.Custody, input)
			comparison, result := f.session.Compare(ctx, input, parent)
			if comparison == nil || result.Outcome != ObservedCurrent || !slices.ContainsFunc(comparison.secretRows, func(row contract.CryptoComparisonRow) bool {
				return row.Name == "secret" && row.Relation == contract.CryptoChanged
			}) {
				t.Fatal("later apply reused a planning equality fact", result)
			}
			env.Custody.RetireApply()
		})
	}
}

// full_only: false
func TestPlanningRejectsChangedCapturedSourceContent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	sealed := suppliedSecret(t, env, "secret", "source-bound original", custody.StandardValue)
	run.suppliedSelection(f, []ApplyEntryInput{sealed})
	public := comparisonCurrentInput(t, env, f.session)
	entry := f.session.valueEntry(namedSlot(t, f.session, "secret"))
	for _, name := range []string{"public", "sealed", "retained", "missing-input", "display-without-sink", "feasibility"} {
		t.Run(name, func(t *testing.T) {
			inputs := []contract.PlanningInput{{Name: "secret", Form: contract.PlanningSealed, SealedInput: bytes.Clone(sealed.InputBytes)}}
			if name == "retained" {
				inputs[0] = contract.PlanningInput{Name: "secret", Form: contract.PlanningRetained, Retained: contract.RetainedSecretInput{Incarnation: entry.Incarnation, Material: entry.ValueState}}
			}
			if name == "missing-input" {
				inputs = nil
			}
			calls := 0
			planner, candidate, _ := installedPlanningFixture(t, env, f.session, public, inputs, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
				calls++
				t.Fatal("invalid source reached private factory")
				return nil, nil
			})
			desired := ownPublicConfiguration(public)
			options := contract.PlanningOptions{Purpose: contract.PlanningEquality}
			switch name {
			case "public":
				desired.Recipients.Value[0].DisplayName.Value = "substituted"
			case "sealed":
				inputs[0].SealedInput[len(inputs[0].SealedInput)-1] ^= 1
			case "retained":
				inputs[0].Retained.Material[0] ^= 1
			case "display-without-sink":
				options = contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: []string{"secret"}}
			case "feasibility":
				options.Purpose = contract.PlanningRetirementFeasibility
			}
			got := planner.Plan(ctx, fixtureID(env.Domain, "changed source request"), desired, inputs, options)
			if got.StateResult != contract.ReaderRefused || got.Verdict != contract.ComparisonUnable || got.PrivateComplete || calls != 0 || len(candidate.calls) != 0 {
				t.Fatal("substituted captured-source request admitted", got)
			}
		})
	}
}

// full_only: false
func TestPlanningFactoryFailureKeepsTypedOutcome(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	sealed := suppliedSecret(t, env, "secret", "typed planning source", custody.StandardValue)
	run.suppliedSelection(f, []ApplyEntryInput{sealed})
	public := comparisonCurrentInput(t, env, f.session)
	inputs := []contract.PlanningInput{{Name: "secret", Form: contract.PlanningSealed, SealedInput: sealed.InputBytes}}
	for _, item := range []struct {
		name  string
		code  contract.CryptoResultCode
		state contract.ReaderStateResult
	}{
		{"wrong-route", contract.CryptoInvalidAdmission, contract.ReaderRefused},
		{"wrong-context", contract.CryptoCancelled, contract.ReaderRefused},
		{"unavailable", contract.CryptoCustodyUnavailable, contract.ReaderUnavailable},
	} {
		t.Run(item.name, func(t *testing.T) {
			calls := 0
			planner, _, source := installedPlanningFixture(t, env, f.session, public, inputs, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
				calls++
				return nil, contract.PlanningAdmissionError{Code: item.code}
			})
			got := planner.Plan(ctx, fixtureID(env.Domain, "factory failure"), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningEquality})
			if got.StateResult != item.state || got.PrivateComplete || got.Verdict != contract.ComparisonUnable || calls != 1 || len(got.PrivateEntries) != 1 || got.PrivateEntries[0].Relation != contract.PlanningUnchecked {
				t.Fatal("typed factory failure changed meaning", got)
			}
			planner.Close()
			if source.closes != 1 {
				t.Fatal("failed factory lost read ownership")
			}
		})
	}
}

// full_only: false
func TestPlanningEmptyScopeDoesNotAcquirePrivateRoute(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	f := newEnvironmentFixture(t, ctx, env, nil, false)
	public := comparisonGenesisInput(t, env, f.session)
	planner, _, _ := installedPlanningFixture(t, env, f.session, public, nil, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) {
		t.Fatal("empty scope constructed private custody")
		return nil, nil
	})
	got := planner.Plan(ctx, fixtureID(env.Domain, "empty plan"), public, nil, contract.PlanningOptions{Purpose: contract.PlanningEquality})
	if got.StateResult != contract.ReaderSuccess || got.Verdict != contract.ComparisonMatch || !got.PrivateComplete || len(got.PrivateEntries) != 0 {
		t.Fatal("empty private scope is incomplete", got)
	}
}

// full_only: false
func TestPlanningDisplaySelectorsRefuseBeforePrivateAcquisition(t *testing.T) {
	ctx, cancel, env, selected, public := comparisonGeneratedFixture(t)
	defer cancel()
	validator := NewPublicConfigurationValidator(nil)
	plain := ""
	found := false
	for _, entry := range public.Entries.Value {
		if entry.Class.Value == contract.Plain {
			plain = entry.Name
			found = true
			break
		}
	}
	if !found {
		t.Fatal("plain fixture missing")
	}
	for _, item := range []struct {
		name  string
		names []string
	}{
		{"plain", []string{plain}}, {"generated", []string{"generated"}}, {"missing", []string{"absent"}}, {"duplicate", []string{"generated", "generated"}},
	} {
		t.Run(item.name, func(t *testing.T) {
			calls := 0
			planner, candidate, _ := installedPlanningFixture(t, env, selected, public, nil, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) { calls++; return nil, nil })
			planner.reader.validator = validator
			got := planner.Plan(ctx, fixtureID(env.Domain, "display selector"), public, nil, contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: item.names, SinkID: fixtureID(env.Domain, "sink")})
			if got.StateResult != contract.ReaderRefused || got.Verdict != contract.ComparisonUnable || got.PrivateComplete || calls != 0 || len(candidate.calls) != 0 {
				t.Fatal("non-supplied selector reached read/private admission")
			}
		})
	}
}

// full_only: false
func TestPlanningDisplayIncompletePublicReadNeverAcquiresPrivateCustody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	env, _ := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	sealed := suppliedSecret(t, env, "secret", "display public barrier", custody.StandardValue)
	run.suppliedSelection(f, []ApplyEntryInput{sealed})
	public := comparisonCurrentInput(t, env, f.session)
	inputs := []contract.PlanningInput{{Name: sealed.Name, Form: contract.PlanningSealed, SealedInput: sealed.InputBytes}}
	calls := 0
	planner, candidate, source := installedPlanningFixture(t, env, f.session, public, inputs, func(context.Context, contract.PlanningAdmission) (PlanningCustody, error) { calls++; return nil, nil })
	source.missingKey = mustKey(t, source.descriptor.Prefix, *f.session.root.ValueEntryPages[0])
	got := planner.Plan(ctx, fixtureID(env.Domain, "display missing public value"), public, inputs, contract.PlanningOptions{Purpose: contract.PlanningDisplay, SelectedNames: []string{sealed.Name}, SinkID: fixtureID(env.Domain, "sink")})
	if got.StateResult != contract.ReaderUnavailable || got.PrivateComplete || got.Verdict != contract.ComparisonUnable || got.DisplayDelivery != contract.PlanningDeliveryNone || got.CompletedRecords != 0 || calls != 0 || len(candidate.calls) == 0 || source.reads == 0 {
		t.Fatal("incomplete selected public read reached private admission")
	}
}
