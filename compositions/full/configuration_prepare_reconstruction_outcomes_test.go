package compositionfull

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type prepareFinalHEADReader struct {
	*configurationReconstructionArchive
	change, verifierClosed bool
	finalReads, closes     int
}

func (r *prepareFinalHEADReader) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	read := r.configurationReconstructionArchive.Read(ctx, key, limit)
	if key == r.descriptor.HeadKey && r.verifierClosed {
		r.finalReads++
		if r.change {
			read.Token.Value = "999999999"
		}
	}
	return read
}

func (r *prepareFinalHEADReader) Close() {
	r.closes++
	r.configurationReconstructionArchive.Close()
}

type prepareFinalHEADVerifier struct {
	configurationReconstructionVerifier
	reader *prepareFinalHEADReader
}

func (v *prepareFinalHEADVerifier) Close() {
	v.configurationReconstructionVerifier.Close()
	v.reader.verifierClosed = true
}

// full_only: false
func TestPrepareFinalHEADRestartsBeforePairDelivery(t *testing.T) {
	for _, changes := range []int{1, 3} {
		t.Run(fmt.Sprintf("changed-final-observations-%d", changes), func(t *testing.T) {
			projection, _, selected := configurationReconstructionProjection(t, "gcp")
			projection.Close()
			selected.selectedCloses, selected.verifierCloses = 0, 0
			selected.verified = map[string]int{}
			request := prepareRecoveryRequestForTest(configurationReaderSource{archive: selected.archive}, filepath.Join(t.TempDir(), "recovered.json"), configuration.JSON)
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var readers []*prepareFinalHEADReader
			constructions := 0
			result, err := prepareConfiguration(ctx, request, func(_ context.Context, config ReconstructionConfig) (*core.ReconstructionEngine, error) {
				constructions++
				if config.Family != contract.GCP || config.GCP == nil || config.GCP.Normal.KeyVersion != selected.archive.SignerSelector {
					t.Fatal("preparation changed independent reconstruction inputs")
				}
				return core.NewInstalledReconstruction(core.ReconstructionInstallation{Candidate: selected, Normal: selected,
					Construct: func(_ context.Context, configuration contract.StoreConfiguration) (core.PublicSelectedReader, core.Result) {
						if configuration != selected.configuration || len(readers) != 0 && readers[len(readers)-1].closes != 1 {
							t.Fatal("restart changed Store or entered before prior reader joined")
						}
						reader := &prepareFinalHEADReader{configurationReconstructionArchive: selected, change: len(readers) < changes}
						readers = append(readers, reader)
						return reader, core.Result{}
					},
					Verify: func(_ context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (core.ReconstructionVerifier, error) {
						original, _ := ctx.Deadline()
						if !deadline.Equal(original) {
							t.Fatal("restart renewed preparation deadline")
						}
						return &prepareFinalHEADVerifier{configurationReconstructionVerifier: configurationReconstructionVerifier{source: selected, pins: pins}, reader: readers[len(readers)-1]}, nil
					}, CloseInstalled: func() {}})
			})
			record := prepareResultWire(t, result)
			attempts := min(changes+1, 3)
			if constructions != 1 || len(readers) != attempts || selected.selectedCloses != attempts || selected.verifierCloses != attempts || !reflect.DeepEqual(selected.verified, map[string]int{"encoded": attempts, "secret": attempts}) {
				t.Fatal("preparation did not retain exact finite attempt and join counts")
			}
			for _, reader := range readers {
				if reader.finalReads != 1 || reader.closes != 1 || !reader.verifierClosed {
					t.Fatal("attempt skipped final observation or failed to join")
				}
			}
			recovery := record["recovery"].(map[string]any)
			delivery := record["local_delivery"].(map[string]any)
			if changes == 1 {
				requirements := []PrepareDependencyRequirement{}
				for i, profile := range readerFixtureProfiles() {
					requirements = append(requirements, PrepareDependencyRequirement{Role: "output", Subjects: []uint16{uint16(i)}, Contract: readerFixtureDestination(profile).ConfigContractID, ProtocolVersion: 6, Status: "missing", Reason: "selection-required"})
				}
				slices.SortFunc(requirements, func(a, b PrepareDependencyRequirement) int { return strings.Compare(a.Contract, b.Contract) })
				wantDependencies := PrepareDependencyAssessment{Assessment: "complete", MinimumAdministrativeReady: true, Requirements: requirements, Installations: []plugininstallation.Installation{}}

				if err != nil || record["branch"] != "reconstruction" || record["outcome"] != "incomplete" || recovery["status"] != "complete" || delivery["outcome"] != "recorded" || delivery["cleanup_failed"] != false || delivery["recovery_source"] != nil || PrepareExitCode(result, nil) != 2 || !reflect.DeepEqual(result.facts.Dependencies, wantDependencies) || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "dependency-missing", "subject": "dependencies"}}) {
					t.Fatal("stable final attempt did not deliver before bounded dependency assessment", record, err)
				}
				pair, err := configuration.Capture(ctx, request.Source, configuration.JSON)
				if err != nil {
					t.Fatal("stable final attempt did not install its complete pair", err)
				}
				if err := pair.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || record["branch"] != "reconstruction" || record["outcome"] != "incomplete" || PrepareExitCode(result, nil) != 3 || !reflect.DeepEqual(recovery, map[string]any{"status": "failed"}) || !reflect.DeepEqual(delivery, map[string]any{"outcome": "not-recorded", "cleanup_failed": false}) || !reflect.DeepEqual(record["diagnostics"], []any{map[string]any{"reason": "contention", "subject": "recovery"}}) {
				t.Fatal("exhausted final observations lost contention or claimed delivery", record, err)
			}
			dependencies := record["dependencies"].(map[string]any)
			if dependencies["assessment"] != "not-attempted" || dependencies["minimum_administrative_ready"] != false || dependencies["all_declared_ready"] != false {
				t.Fatal("contention entered dependency preparation")
			}
			for _, path := range []string{request.Source, filepath.Join(filepath.Dir(request.Source), ".enkv", "restored.generated.json")} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("contention installed a partial configuration pair", err)
				}
			}
		})
	}
}
