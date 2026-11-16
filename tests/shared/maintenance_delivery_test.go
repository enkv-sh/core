package core

import (
	"context"
	"enkv.sh/core/contract"
	"testing"
	"time"
)

// full_only: false
func TestMaintenanceDeliveryRequiresExactReadbackBeforeCAS(t *testing.T) {
	for _, condition := range []string{"source-pins", "output-file", "output-path", "candidate", "configuration", "input", "recipients", "basis", "publication-error", "source-changed", "pre-cas-token"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f, _, _ := maintenanceObserverFixture(t, ctx, false)
			selected := f.open(t, ctx)
			installation := installedSecretAccessTestInstallation(t, f, selected, installedApplyGeneratedValidator(t, selected), nil, nil)
			m := installation.Maintenance
			publish := m.PublishSuccessor
			sourceChanged := false
			m.SourceUnchanged = func(ctx context.Context) error {
				if sourceChanged {
					return contract.ErrRecord
				}
				return ctx.Err()
			}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			published := 0
			m.PublishSuccessor = func(ctx context.Context, c MaintenanceSuccessor) (MaintenanceReadback, error) {
				published++
				r, err := publish(ctx, c)
				if err != nil {
					return r, err
				}
				switch condition {
				case "source-pins":
					r.SourcePins.GeneratedDigest = fixtureID(f.env.Domain, "transplanted source pins")
				case "output-file":
					r.OutputPins.FileID = fixtureID(f.env.Domain, "transplanted output file")
				case "output-path":
					r.OutputPath += ".other"
				case "candidate":
					r.Correlation = ownMaintenanceSuccessor(r.Correlation)
					r.Correlation.SignedCandidate[0] ^= 1
				case "configuration":
					r.Configuration = contract.PublicConfiguration{}
				case "input":
					r.Inputs[0].Retained.Material = fixtureID(f.env.Domain, "transplanted readback pin")
				case "recipients":
					r.Recipients = r.Recipients[:len(r.Recipients)-1]
				case "basis":
					r.Basis = PublicBasis{}
				case "publication-error":
					return MaintenanceReadback{}, contract.ErrRecord
				case "source-changed":
					sourceChanged = true
				case "pre-cas-token":
					store.mu.Lock()
					store.put(store.desc.HeadKey, selected.body)
					store.mu.Unlock()
				}
				return r, nil
			}
			engine, err := NewInstalledEnvelopeRekey(EnvelopeRekeyInstallation{AccessMutationInstallation: installation.AccessMutationInstallation, AdmitCustody: installation.AdmitCustody, Name: "target"})
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Rekey(ctx, fixtureID(f.env.Domain, condition))
			engine.Close()
			if published != 1 || store.cas != cas || got.Result.Outcome == ObservedCurrent || len(got.Receipt) != 0 {
				t.Fatal("readback defect reached canonical CAS", condition, got.Result, published, store.cas-cas)
			}
			if condition == "pre-cas-token" {
				if got.Result.Outcome != Contention || got.Successor == nil || got.Payload == nil || got.Payload.RequestedRevisionID.IsZero() {
					t.Fatal("pre-CAS contention lost delivered candidate facts", got.Result)
				}
			} else if got.Successor != nil {
				t.Fatal("invalid delivery was admitted as a successor", condition)
			}
		})
	}
}

// full_only: false
func TestMaintenanceGeneratedCandidatePageLengthBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f, delivered, _ := maintenanceObserverFixture(t, ctx, true)
	if len(delivered.Correlation.CandidatePages) == 0 {
		t.Fatal("generated target witness missing")
	}
	for _, page := range delivered.Correlation.CandidatePages {
		before := f.selected.root.ValueEntryPages[page.Index]
		if before == nil || uint64(len(page.Body)) > uint64(before.Length) {
			t.Fatal("generated rekey page grew beyond admitted codec bound")
		}
	}
}
