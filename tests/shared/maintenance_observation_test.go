package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func maintenanceObserverFixture(t *testing.T, ctx context.Context, generated bool) (installedApplyTestFixture, MaintenanceReadback, PublicApplyResult) {
	t.Helper()
	var f installedApplyTestFixture
	name := "target"
	if generated {
		retained := newRetainedReaderFixture(t, true, 2)
		selected := retained.selected
		f = installedApplyTestFixture{env: retained.env, keys: retained.keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition, admitted: OpenContext{admission: &selected.admission}, selected: selected}
		name = "generated"
	} else {
		f = newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
		input := []ApplyEntryInput{suppliedSecret(t, f.env, name, "maintenance observation source", custody.StandardValue, f.selected.admission.recipient),
			{Name: "plain", Recipients: []contract.ID{f.selected.admission.recipient}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("before")}}
		engine := f.engine(t, f.selected, input, nil)
		if got := engine.Apply(ctx, fixtureID(f.env.Domain, "maintenance observer setup"), input); got.Result.Outcome != ObservedCurrent {
			t.Fatal("setup", got.Result)
		}
		engine.Close()
		f.selected = f.open(t, ctx)
	}
	installation := installedSecretAccessTestInstallation(t, f, f.selected, installedApplyGeneratedValidator(t, f.selected), nil, nil)
	publish := installation.Maintenance.PublishSuccessor
	var delivered MaintenanceReadback
	installation.Maintenance.PublishSuccessor = func(ctx context.Context, successor MaintenanceSuccessor) (MaintenanceReadback, error) {
		readback, err := publish(ctx, successor)
		if err == nil {
			delivered = readback
		}
		return readback, err
	}
	engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	result := engine.Rekey(ctx, fixtureID(f.env.Domain, "maintenance observation rekey"))
	engine.Close()
	if result.Result.Outcome != ObservedCurrent || len(result.Receipt) == 0 || delivered.Correlation.OperationID != result.OperationID {
		t.Fatal("rekey did not deliver and select exact candidate", result.Result)
	}
	return f, delivered, result
}

func maintenanceObserverInput(f installedApplyTestFixture, delivered MaintenanceReadback, source PublicSelectedReader) MaintenanceObservationInstallation {
	return MaintenanceObservationInstallation{ExpectedDomain: f.env.Domain, ExpectedStore: f.env.Store.Descriptor(), PublicBasis: f.basis,
		SourcePins: delivered.SourcePins, OutputPins: delivered.OutputPins, OutputPath: delivered.OutputPath, CompositionID: f.composition,
		Correlation: delivered.Correlation, Configuration: delivered.Configuration, Inputs: delivered.Inputs, Recipients: delivered.Recipients,
		Source: source, CheckSourceOutput: func(ctx context.Context) error { return ctx.Err() }}
}

// full_only: false
func TestMaintenanceObservationSeparatesReceiptFromCandidateMaterial(t *testing.T) {
	for _, condition := range []string{"advanced-candidate-unavailable", "generated-current", "correlated-later-pin", "input-only-later-pin"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			f, delivered, original := maintenanceObserverFixture(t, ctx, condition == "generated-current")
			source := &replacementObservationSource{store: f.env.Store}
			oldReads := 0
			if condition == "advanced-candidate-unavailable" {
				candidate, err := format.DecodeHead(delivered.Correlation.SignedCandidate)
				if err != nil {
					t.Fatal(err)
				}
				oldRoot, err := format.Key(f.env.Store.Descriptor().Prefix, candidate.Core.Root)
				if err != nil {
					t.Fatal(err)
				}
				selected := f.open(t, ctx)
				input := installedApplyCurrentInput(selected)
				for i := range input {
					if input[i].Name == "plain" {
						input[i].InputBytes = []byte("after")
					}
				}
				engine := f.engine(t, selected, input, nil)
				if result := engine.Apply(ctx, fixtureID(f.env.Domain, "advance maintenance observation"), input); result.Result.Outcome != ObservedCurrent {
					t.Fatal(result.Result)
				}
				engine.Close()
				source.hook = func(_ context.Context, key string) (contract.ReadResult, bool) {
					if key == oldRoot {
						oldReads++
						return contract.ReadResult{Status: contract.ReadMissing}, true
					}
					return contract.ReadResult{}, false
				}
			}
			if condition == "correlated-later-pin" || condition == "input-only-later-pin" {
				selected := f.open(t, ctx)
				installation := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, nil)
				engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
				if err != nil {
					t.Fatal(err)
				}
				if later := engine.Rekey(ctx, fixtureID(f.env.Domain, "later maintenance material")); later.Result.Outcome != ObservedCurrent {
					t.Fatal(later.Result)
				}
				engine.Close()
				_, current := lifecycleEntry(t, f.open(t, ctx), "target")
				delivered.Correlation = ownMaintenanceSuccessor(delivered.Correlation)
				if len(delivered.Correlation.PinDeltas) != 1 {
					t.Fatal("one original supplied material delta required")
				}
				if condition == "correlated-later-pin" {
					delivered.Correlation.PinDeltas[0].After.Material = current.ValueState
				}
				delivered.Inputs = slices.Clone(delivered.Inputs)
				for i := range delivered.Inputs {
					if delivered.Inputs[i].Name == "target" {
						delivered.Inputs[i].Retained.Material = current.ValueState
					}
				}
				delivered.OutputPins.GeneratedDigest = contract.Hash([]byte("captured correlated later-material transplant"))
			}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			_, private := f.keys.Calls()
			observer, err := NewInstalledMaintenanceObserver(maintenanceObserverInput(f, delivered, source))
			if err != nil {
				if condition == "correlated-later-pin" || condition == "input-only-later-pin" {
					source.Close()
					_, afterPrivate := f.keys.Calls()
					if observer != nil || store.cas != cas || private != afterPrivate || source.reads.Load() != 0 {
						t.Fatal("tampered output refusal used private or selected state")
					}
					return
				}
				t.Fatal(err)
			}
			if condition == "input-only-later-pin" {
				if err := observer.Close(); err != nil {
					t.Error("maintenance observer close failed", err)
				}
				t.Fatal("output retained pin unrelated to candidate delta was admitted")
			}
			got := observer.Observe(ctx, fixtureID(f.env.Domain, condition+" observer"))
			if err := observer.Close(); err != nil {
				t.Fatal(err)
			}
			_, afterPrivate := f.keys.Calls()
			if got.Result.Outcome != ObservedCurrent || !bytes.Equal(got.Receipt, original.Receipt) || got.Query == nil || !got.Query.Valid() || store.cas != cas || private != afterPrivate || source.closes.Load() != 1 {
				t.Fatalf("exact retained receipt must remain self-contained and GET-only: result=%+v receipt=%t private=%d CAS=%d", got.Result, bytes.Equal(got.Receipt, original.Receipt), afterPrivate-private, store.cas-cas)
			}
			if condition == "advanced-candidate-unavailable" && (oldReads != 0 || got.CandidateCurrent) {
				t.Fatal("historical receipt depended on obsolete candidate state", oldReads, got.CandidateCurrent)
			}
			if condition == "generated-current" && !got.CandidateCurrent {
				t.Fatal("exact current generated candidate lost its currentness")
			}
			if condition == "correlated-later-pin" && got.SourceUsabilityChecked && got.SourceUsable {
				t.Fatal("later material qualified the original candidate's successor output")
			}
		})
	}
}

// full_only: false
func TestMaintenanceRefusesUnusableRegistryBeforePrivateCustody(t *testing.T) {
	for _, condition := range []string{"changed-current-binding", "omitted-current-recipient"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			prepared := installedApplyPreparedRecipient(t, f.selected, "unrelated current maintenance reader")
			input := []ApplyEntryInput{suppliedSecret(t, f.env, "target", "maintenance registry source", custody.StandardValue, f.selected.admission.recipient)}
			setup := f.engineWithValidator(t, f.selected, input, prepared, installedApplyGeneratedValidator(t, f.selected), nil)
			if result := setup.Apply(ctx, fixtureID(f.env.Domain, "maintenance registry setup"), input); result.Result.Outcome != ObservedCurrent {
				t.Fatal(result.Result)
			}
			setup.Close()
			selected := f.open(t, ctx)
			private := 0
			installation := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, &private)
			m := installation.Maintenance
			reader := slices.IndexFunc(m.Recipients, func(row contract.ApplyRecipientInput) bool {
				return row.Recipient.RecipientID != selected.admission.recipient
			})
			if reader < 0 {
				t.Fatal("extra current registry row absent")
			}
			id := m.Recipients[reader].Recipient.RecipientID
			if condition == "changed-current-binding" {
				binding := *m.Recipients[reader].Recipient.CurrentBinding
				binding.BindingSerial++
				m.Recipients[reader].Recipient.CurrentBinding = &binding
			} else {
				m.Recipients = slices.Delete(m.Recipients, reader, reader+1)
				m.Configuration.Recipients.Value = slices.DeleteFunc(m.Configuration.Recipients.Value, func(row contract.PublicRecipient) bool { return row.RecipientID == id })
			}
			var err error
			m.InputDigest, err = PlanningInputDigest(m.Configuration, m.Inputs)
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
			if err != nil {
				t.Fatal(err)
			}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			result := engine.Rekey(ctx, fixtureID(f.env.Domain, condition))
			engine.Close()
			if result.Result.Outcome != AdmissionRefused || private != 0 || store.cas != cas || result.Successor != nil {
				t.Fatal("unusable successor registry reached mutation custody", result.Result, private, store.cas-cas)
			}
		})
	}
}

// full_only: false
func TestMaintenanceCandidateMaterialRejectsTransplants(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, original, _ := maintenanceObserverFixture(t, ctx, false)
	for _, condition := range []string{"root", "page", "missing-page", "extra-page", "after-pin", "generation-on-supplied", "missing-input", "predecessor-head", "predecessor-root", "predecessor-page", "missing-predecessor-page", "extra-predecessor-page"} {
		t.Run(condition, func(t *testing.T) {
			delivered := original
			delivered.Correlation = ownMaintenanceSuccessor(original.Correlation)
			switch condition {
			case "root":
				delivered.Correlation.CandidateRoot[0] ^= 1
			case "page":
				delivered.Correlation.CandidatePages[0].Body[0] ^= 1
			case "missing-page":
				delivered.Correlation.CandidatePages = nil
			case "extra-page":
				delivered.Correlation.CandidatePages = append(delivered.Correlation.CandidatePages, delivered.Correlation.CandidatePages[0])
			case "after-pin":
				delivered.Correlation.PinDeltas[0].After.Material = fixtureID(f.env.Domain, "unbound candidate material")
			case "generation-on-supplied":
				delivered.Correlation.BeforeGeneration = fixtureID(f.env.Domain, "unbound generation")
			case "predecessor-head":
				delivered.Correlation.PredecessorHead[0] ^= 1
			case "predecessor-root":
				delivered.Correlation.PredecessorRoot[0] ^= 1
			case "predecessor-page":
				delivered.Correlation.PredecessorPages[0].Body[0] ^= 1
			case "missing-predecessor-page":
				delivered.Correlation.PredecessorPages = nil
			case "extra-predecessor-page":
				delivered.Correlation.PredecessorPages = append(delivered.Correlation.PredecessorPages, delivered.Correlation.PredecessorPages[0])
			case "missing-input":
				delivered.Inputs = nil
			}
			source := &replacementObservationSource{store: f.env.Store}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			_, private := f.keys.Calls()
			observer, err := NewInstalledMaintenanceObserver(maintenanceObserverInput(f, delivered, source))
			if observer != nil {
				if err := observer.Close(); err != nil {
					t.Error("maintenance observer close failed", err)
				}
			}
			source.Close()
			_, after := f.keys.Calls()
			if err == nil || observer != nil || source.reads.Load() != 0 || store.cas != cas || private != after {
				t.Fatal("unbound candidate output admitted or used selected/private state", condition, err)
			}
		})
	}
}

// full_only: false
func TestMaintenanceCurrentSourceRejectsCrossContextEnvelopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, delivered, _ := maintenanceObserverFixture(t, ctx, false)
	selected := f.open(t, ctx)
	for _, condition := range []string{"name", "file", "compatibility", "support", "omitted-input", "omitted-recipient"} {
		t.Run(condition, func(t *testing.T) {
			public := ownPublicConfiguration(delivered.Configuration)
			recipients := slices.Clone(delivered.Recipients)
			input := suppliedSecret(t, f.env, "target", "observer cross context", custody.StandardValue, selected.admission.recipient)
			envelope, err := contract.DecodeSealedInputEnvelope(input.InputBytes)
			if err != nil {
				t.Fatal(err)
			}
			envelope.Core.FileIdentity = delivered.SourcePins.FileID
			switch condition {
			case "name":
				envelope.Core.Name = "another"
			case "file":
				envelope.Core.FileIdentity = fixtureID(f.env.Domain, "another source file")
			case "compatibility":
				envelope.Core.CompatibilityID = fixtureID(f.env.Domain, "another compatibility")
			case "support":
				envelope.Core.CryptoSupportID = fixtureID(f.env.Domain, "another support")
			case "omitted-recipient":
				recipients = recipients[:len(recipients)-1]
			}
			body, err := contract.EncodeSealedInputEnvelope(envelope)
			if err != nil {
				t.Fatal(err)
			}
			inputs := []contract.PlanningInput{{Name: "target", Form: contract.PlanningSealed, SealedInput: body}}
			if condition == "omitted-input" {
				inputs = nil
			}
			if maintenanceCurrentSourceUsable(selected, delivered.SourcePins.FileID, public, inputs, recipients) {
				t.Fatal("cross-context or incomplete source advertised usable", condition)
			}
		})
	}
}

// full_only: false
func TestMaintenanceObservationBindsBeforeMaterialToActualPredecessor(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, first, _ := maintenanceObserverFixture(t, ctx, false)
	older := first.Correlation.PinDeltas[0].Before
	olderTarget := *first.Correlation.RekeyTarget
	selected := f.open(t, ctx)
	installation := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, nil)
	publish := installation.Maintenance.PublishSuccessor
	var delivered MaintenanceReadback
	installation.Maintenance.PublishSuccessor = func(ctx context.Context, successor MaintenanceSuccessor) (MaintenanceReadback, error) {
		readback, err := publish(ctx, successor)
		if err == nil {
			delivered = readback
		}
		return readback, err
	}
	engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
	if err != nil {
		t.Fatal(err)
	}
	original := engine.Rekey(ctx, fixtureID(f.env.Domain, "second exact maintenance rekey"))
	engine.Close()
	if original.Result.Outcome != ObservedCurrent || len(original.Receipt) == 0 || len(delivered.Correlation.PinDeltas) != 1 || delivered.Correlation.PinDeltas[0].Before != first.Correlation.PinDeltas[0].After || delivered.Correlation.PinDeltas[0].Before == older {
		t.Fatal("two genuine rekeys did not retain distinct same-incarnation materials", original.Result)
	}
	for _, condition := range []string{"exact", "older-before", "wrong-before-entry-digest"} {
		t.Run(condition, func(t *testing.T) {
			input := delivered
			input.Correlation = ownMaintenanceSuccessor(delivered.Correlation)
			switch condition {
			case "older-before":
				input.Correlation.PinDeltas[0].Before = older
				input.Correlation.RekeyTarget.Material = older.Material
				input.Correlation.RekeyTarget.BeforePublicEntryDigest = olderTarget.BeforePublicEntryDigest
			case "wrong-before-entry-digest":
				input.Correlation.RekeyTarget.BeforePublicEntryDigest = fixtureID(f.env.Domain, "unrelated before public entry")
			}
			source := &replacementObservationSource{store: f.env.Store}
			observer, err := NewInstalledMaintenanceObserver(maintenanceObserverInput(f, input, source))
			if condition != "exact" {
				if observer != nil {
					if closeErr := observer.Close(); closeErr != nil {
						t.Error(closeErr)
					}
				} else {
					source.Close()
				}
				if err == nil || observer != nil || source.reads.Load() != 0 {
					t.Fatal("mutually matching before aliases replaced authenticated predecessor evidence", condition, err)
				}
				return
			}
			if err != nil {
				t.Fatal("exact before-to-after candidate refused", err)
			}
			out := observer.Observe(ctx, fixtureID(f.env.Domain, "exact second rekey observation"))
			if err := observer.Close(); err != nil {
				t.Fatal(err)
			}
			if out.Result.Outcome != ObservedCurrent || !out.CandidateCurrent || !bytes.Equal(out.Receipt, original.Receipt) || !out.SourceUsabilityChecked || !out.SourceUsable || out.Query == nil || !out.Query.Valid() {
				t.Fatal("exact predecessor/candidate relation was not observable", out.Result)
			}
		})
	}
}

// full_only: false
func TestMaintenanceObservationFinalGuardClearsEveryObservedFact(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, delivered, original := maintenanceObserverFixture(t, ctx, false)
	for _, lateFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("late-failure=%v", lateFailure), func(t *testing.T) {
			source := &replacementObservationSource{store: f.env.Store}
			input := maintenanceObserverInput(f, delivered, source)
			checks := 0
			changed := errors.New("controlled final maintenance qualification failure")
			input.CheckSourceOutput = func(context.Context) error {
				checks++
				if lateFailure && checks == 2 {
					return changed
				}
				return nil
			}
			observer, err := NewInstalledMaintenanceObserver(input)
			if err != nil {
				t.Fatal(err)
			}
			out := observer.Observe(ctx, fixtureID(f.env.Domain, "final maintenance qualification"))
			closeErr := observer.Close()
			if checks != 2 || source.heads.Load() != 1 || source.reads.Load() <= 1 || source.closes.Load() != 1 {
				t.Fatal("final qualification did not follow a complete selected read", checks, source.reads.Load())
			}
			if lateFailure {
				if !errors.Is(closeErr, changed) || out.Result.Outcome != AdmissionRefused || out.StateResult != contract.ReaderRefused || len(out.Receipt) != 0 || out.CandidateCurrent || out.CurrentWarningBits != 0 || out.SourceUsabilityChecked || out.SourceUsable || out.Query == nil || out.Query.Observation != nil || !out.Query.Valid() || out.RequestIdentity != out.Query.Digest {
					t.Fatal("late source failure retained authenticated observation facts", out.Result, out.CandidateCurrent, out.Query)
				}
			} else if closeErr != nil || out.Result.Outcome != ObservedCurrent || !out.CandidateCurrent || !bytes.Equal(out.Receipt, original.Receipt) || !out.SourceUsabilityChecked || !out.SourceUsable || out.Query == nil || out.Query.Observation == nil || !out.Query.Valid() || out.RequestIdentity != out.Query.Digest {
				t.Fatal("positive observation did not establish the facts later invalidated", out.Result)
			}
		})
	}
}

// full_only: false
func TestMaintenanceObservationFinalGuardClearsCurrentWarnings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, delivered, original := maintenanceObserverFixture(t, ctx, true)
	selected := f.open(t, ctx)
	var owner contract.ID
	for _, group := range selected.adminIndex.Groups {
		if group.OwnerKind == format.AdministrativeGeneratedHazard {
			owner = group.GroupID
			break
		}
	}
	if owner.IsZero() {
		t.Fatal("retained generated obligation absent")
	}
	selected = retainedReaderEndWork(t, selected, owner, f.env.Trust)
	if selected.root.WarningBits == 0 {
		t.Fatal("actual work ending did not establish a current warning")
	}
	for _, lateFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("late-failure=%v", lateFailure), func(t *testing.T) {
			source := &replacementObservationSource{store: f.env.Store}
			input := maintenanceObserverInput(f, delivered, source)
			checks := 0
			changed := errors.New("controlled final qualification with current warning")
			input.CheckSourceOutput = func(context.Context) error {
				checks++
				if lateFailure && checks == 2 {
					return changed
				}
				return nil
			}
			observer, err := NewInstalledMaintenanceObserver(input)
			if err != nil {
				t.Fatal(err)
			}
			out := observer.Observe(ctx, fixtureID(f.env.Domain, "warning final qualification"))
			closeErr := observer.Close()
			if checks != 2 || source.heads.Load() != 1 || source.closes.Load() != 1 {
				t.Fatal("warning qualification lost its actual read or Close", checks)
			}
			if lateFailure {
				if !errors.Is(closeErr, changed) || out.Result.Outcome != AdmissionRefused || out.CurrentWarningBits != 0 || out.CandidateCurrent || out.Query == nil || out.Query.Observation != nil || !out.Query.Valid() || len(out.Receipt) != 0 || out.SourceUsabilityChecked || out.SourceUsable {
					t.Fatal("late source failure retained current warning or observation", out.Result, out.CurrentWarningBits)
				}
			} else if closeErr != nil || out.Result.Outcome != ObservedCurrent || out.CurrentWarningBits != selected.root.WarningBits || out.Query == nil || out.Query.Observation == nil || !bytes.Equal(out.Receipt, original.Receipt) || out.CandidateCurrent {
				t.Fatal("positive current warning/receipt observation was not established", out.Result, out.CurrentWarningBits)
			}
		})
	}
}

// full_only: false
func TestMaintenanceObservationOwnsAndCommitsBothMaterialSides(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, delivered, original := maintenanceObserverFixture(t, ctx, false)
	for _, change := range []struct {
		name string
		edit func(*MaintenanceSuccessor)
	}{
		{"predecessor-head", func(c *MaintenanceSuccessor) { c.PredecessorHead[0] ^= 1 }},
		{"predecessor-root", func(c *MaintenanceSuccessor) { c.PredecessorRoot[0] ^= 1 }},
		{"predecessor-page-row", func(c *MaintenanceSuccessor) { c.PredecessorPages[0].Index++ }},
		{"predecessor-page-body", func(c *MaintenanceSuccessor) { c.PredecessorPages[0].Body[0] ^= 1 }},
		{"candidate-root", func(c *MaintenanceSuccessor) { c.CandidateRoot[0] ^= 1 }},
		{"candidate-page-row", func(c *MaintenanceSuccessor) { c.CandidatePages[0].Index++ }},
		{"candidate-page-body", func(c *MaintenanceSuccessor) { c.CandidatePages[0].Body[0] ^= 1 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			input := delivered
			input.Correlation = ownMaintenanceSuccessor(delivered.Correlation)
			before := ownMaintenanceSuccessor(input.Correlation)
			source := &replacementObservationSource{store: f.env.Store}
			observer, err := NewInstalledMaintenanceObserver(maintenanceObserverInput(f, input, source))
			if err != nil {
				source.Close()
				t.Fatal(err)
			}
			change.edit(&input.Correlation)
			if maintenanceSuccessorEqual(before, input.Correlation) {
				t.Fatal("changed material field retained correlation equality")
			}
			out := observer.Observe(ctx, fixtureID(f.env.Domain, "owned material "+change.name))
			if err := observer.Close(); err != nil {
				t.Fatal(err)
			}
			if out.Result.Outcome != ObservedCurrent || !bytes.Equal(out.Receipt, original.Receipt) || !maintenanceSuccessorEqual(out.Correlation, before) || out.Query == nil || !out.Query.Valid() || !maintenanceSuccessorEqual(out.Query.Correlation, before) {
				t.Fatal("caller mutation changed admitted material or query", out.Result)
			}
			change.edit(&out.Correlation)
			if !maintenanceSuccessorEqual(out.Query.Correlation, before) || !out.Query.Valid() {
				t.Fatal("returned result and query borrowed the same material backing")
			}
			change.edit(&out.Query.Correlation)
			if out.Query.Valid() {
				t.Fatal("changed exact material retained the query commitment")
			}
		})
	}
}

// full_only: false
func TestMaintenanceObservationRefusesCapacityBeforeDecodingMaterial(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f, delivered, _ := maintenanceObserverFixture(t, ctx, false)
	source := &replacementObservationSource{store: f.env.Store}
	observer, err := NewInstalledMaintenanceObserver(maintenanceObserverInput(f, delivered, source))
	if err != nil {
		t.Fatal(err)
	}
	out := observer.Observe(ctx, fixtureID(f.env.Domain, "capacity control query"))
	if err := observer.Close(); err != nil || out.Result.Outcome != ObservedCurrent || out.Query == nil || !out.Query.Valid() {
		t.Fatal("valid complete material control refused", out.Result, err)
	}
	for _, condition := range []string{"aggregate-one-over", "head-one-over", "root-one-over", "page-count-one-over"} {
		t.Run(condition, func(t *testing.T) {
			q := *out.Query
			q.Correlation = ownMaintenanceSuccessor(out.Query.Correlation)
			switch condition {
			case "aggregate-one-over":
				padded := func(n int) uint64 { return 4 * ((uint64(n) + 2) / 3) }
				reserved := uint64(8192) + 6*(uint64(len(q.OutputPath))+256) + 512 + 18*uint64(len(q.Correlation.Name))
				for _, body := range [][]byte{q.Correlation.SignedCandidate, q.Correlation.PredecessorHead, q.Correlation.PredecessorRoot, q.Correlation.CandidateRoot} {
					reserved += padded(len(body))
				}
				for _, pages := range [][]MaintenanceValuePage{q.Correlation.PredecessorPages, q.Correlation.CandidatePages} {
					for _, page := range pages {
						reserved += padded(len(page.Body)) + 128
					}
				}
				q.SourcePins.GeneratedLength = 268435456 - q.SourcePins.EditableLength - reserved + 1
			case "head-one-over":
				q.Correlation.PredecessorHead = make([]byte, 65537)
			case "root-one-over":
				q.Correlation.PredecessorRoot = make([]byte, 262145)
			case "page-count-one-over":
				q.Correlation.PredecessorPages = make([]MaintenanceValuePage, 33)
			}
			accepted := false
			allocations := testing.AllocsPerRun(1, func() {
				_, accepted = q.digest()
			})
			if accepted || allocations != 0 {
				t.Fatal("query decoded or owned material before cheap capacity refusal", accepted, allocations)
			}
			input := delivered
			input.SourcePins, input.Correlation = q.SourcePins, q.Correlation
			rejectedSource := &replacementObservationSource{store: f.env.Store}
			installation := maintenanceObserverInput(f, input, rejectedSource)
			var admitted *MaintenanceObserver
			var admissionErr error
			allocations = testing.AllocsPerRun(1, func() {
				admitted, admissionErr = NewInstalledMaintenanceObserver(installation)
			})
			rejectedSource.Close()
			if admitted != nil || admissionErr == nil || allocations != 0 || rejectedSource.reads.Load() != 0 {
				t.Fatal("observer copied or decoded material before cheap capacity refusal", admissionErr, allocations)
			}
		})
	}
}

// full_only: false
func TestMaintenanceRetirementWitnessKeepsExactRequiredPageSets(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	authority := f.selected.admission.recipient
	var reader contract.ID
	for _, row := range f.selected.registry() {
		if row.RecipientID != authority {
			reader = row.RecipientID
			break
		}
	}
	if reader.IsZero() {
		t.Fatal("retirement recipient missing")
	}
	var input []ApplyEntryInput
	for i := range 15 {
		input = append(input, ApplyEntryInput{Name: fmt.Sprintf("plain-%02d", i), Recipients: []contract.ID{authority}, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("unrelated"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
	}
	for _, name := range []string{"target-a", "target-b", "target-c"} {
		input = append(input, suppliedSecret(t, f.env, name, name+" material", custody.StandardValue, authority, reader))
	}
	setup := f.engine(t, f.selected, input, nil)
	if got := setup.Apply(ctx, fixtureID(f.env.Domain, "two required maintenance pages"), input); got.Result.Outcome != ObservedCurrent {
		t.Fatal(got.Result)
	}
	setup.Close()
	selected := f.open(t, ctx)
	installation := installedRetirementTestInstallation(t, f, selected, installedSecretAccessTestRef(t, selected, reader), nil)
	publish := installation.Maintenance.PublishSuccessor
	var delivered MaintenanceReadback
	installation.Maintenance.PublishSuccessor = func(ctx context.Context, c MaintenanceSuccessor) (MaintenanceReadback, error) {
		out, err := publish(ctx, c)
		if err == nil {
			delivered = out
		}
		return out, err
	}
	engine, err := NewInstalledRecipientRetirement(installation)
	if err != nil {
		t.Fatal(err)
	}
	original := engine.Retire(ctx, fixtureID(f.env.Domain, "retire across required pages"))
	engine.Close()
	c := delivered.Correlation
	if original.Result.Outcome != ObservedCurrent || len(c.PinDeltas) != 3 || len(c.PredecessorPages) != 2 || len(c.CandidatePages) != 2 {
		t.Fatal("retirement did not produce three deltas and exactly two pages per side", original.Result)
	}
	for i, name := range []string{"target-a", "target-b", "target-c"} {
		if c.PinDeltas[i].Name != name {
			t.Fatal("exact target delta order changed", c.PinDeltas)
		}
	}
	for _, pages := range [][]MaintenanceValuePage{c.PredecessorPages, c.CandidatePages} {
		if pages[0].Index != 0 || pages[1].Index != 1 {
			t.Fatal("page set was not sorted, unique and derived from actual slots", pages)
		}
	}
	source := &replacementObservationSource{store: f.env.Store}
	observer, err := NewInstalledMaintenanceObserver(maintenanceObserverInput(f, delivered, source))
	if err != nil {
		t.Fatal(err)
	}
	out := observer.Observe(ctx, fixtureID(f.env.Domain, "two-page retirement receipt"))
	if err := observer.Close(); err != nil || out.Result.Outcome != ObservedCurrent || !bytes.Equal(out.Receipt, original.Receipt) || !out.SourceUsabilityChecked || !out.SourceUsable {
		t.Fatal("exact multi-page retirement witness did not survive observation", out.Result, err)
	}
}
