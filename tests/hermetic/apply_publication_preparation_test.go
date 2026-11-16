package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// full_only: false
func TestApplyPreparationExcludesPublicationImmutableWrites(t *testing.T) {
	for _, changed := range []bool{false, true} {
		name := "unchanged"
		if changed {
			name = "changed"
		}
		t.Run(name, func(t *testing.T) {
			f, env, selection, private, staging := nativePublicationFixture(t, false)
			recorder := newPublicationDiagnosticCapture()
			ctx, cancel := context.WithTimeout(telemetry.WithCapability(t.Context(), telemetry.NewCapability(nil, recorder.recorder)), time.Minute)
			defer cancel()
			private = applyPublicationNativeDeadline(t, ctx, private)
			if changed {
				seed := installedPublicationEngine(t, f, private, recorder).Publish(ctx, fixtureID(env.Domain, "preparation prior target birth"), PublicationRequest{Names: selection.names})
				assertInstalledPublicationVector(t, seed, contract.PublicationSummaryComplete, 1)
				assertNativePublicationJoined(t, recorder, staging, 1)
				publicationEngineReopen(t, f)
			}
			ledger := func(base contract.Store) (*applyPreparationTestStore, *[2]uint64) {
				counts := new([2]uint64)
				pending := make(map[string][]byte)
				store := &applyPreparationTestStore{Store: base, memory: f.store}
				store.create = func(ctx context.Context, key string, body []byte) contract.WriteResult {
					written := base.Create(ctx, key, body)
					if written.Status == contract.WriteAcknowledged {
						counts[0]++
					}
					pending[key] = bytes.Clone(body)
					return written
				}
				store.read = func(ctx context.Context, key string, limit uint32) contract.ReadResult {
					read := base.Read(ctx, key, limit)
					if expected, present := pending[key]; present && read.Status == contract.ReadOK && bytes.Equal(read.Body, expected) {
						counts[1]++
						delete(pending, key)
					}
					return read
				}
				return store, counts
			}
			applyStore, applyCounts := ledger(env.Store)
			env.Store = applyStore
			input := installedApplyCurrentInput(f.session)
			if changed {
				input[0].InputBytes = []byte("updated plain data")
			}
			a := publicPublicationApplyFixture(env, f)
			apply := a.engineWithValidator(t, f.session, input, currentApplyRecipients(f.session.registry()), installedOutputValidator(t, f.session), nil)
			publication := installedPublicationEngine(t, f, private, recorder)
			publicationStore, publicationCounts := ledger(publication.installation.Store)
			publication.installation.Store = publicationStore
			joined := apply.ApplyAndPublish(ctx, fixtureID(env.Domain, "preparation combined apply "+name), fixtureID(env.Domain, "preparation combined publication "+name), input, publication, nil)
			apply.Close()
			publication.Close()
			result := applyPublicationAssertStage(t, joined, contract.PublicationSummaryComplete, 1)
			assertNativePublicationJoined(t, recorder, staging, 1)
			wantOutcome, wantAction := Unchanged, uint8(contract.PublicationCreateWithValue)
			if changed {
				wantOutcome, wantAction = ObservedCurrent, contract.PublicationWriteValue
			}
			if joined.Apply.Result.Outcome != wantOutcome || result.Output.Entries[0].Actions[0].Action != wantAction || result.Output.Entries[0].Actions[0].Disposition != contract.PublicationOutcomeAcknowledged || publicationStore.puts == 0 || publicationCounts[0] == 0 || publicationCounts[1] == 0 {
				t.Fatal("combined phase controls did not perform one publication after apply", joined.Apply.Result, applyStore.puts, publicationStore.puts, *publicationCounts)
			}
			if changed && (applyStore.puts == 0 || applyCounts[0] == 0 || applyCounts[1] == 0 || len(joined.Apply.Receipt) == 0) || !changed && (applyStore.puts != 0 || *applyCounts != [2]uint64{} || len(joined.Apply.Receipt) != 0) {
				t.Fatal("apply phase ledger does not match its actual transition", changed, applyStore.puts, *applyCounts)
			}
			ack, verified, possible, present := readApplyPreparation(t, joined.Apply)
			if !present || ack != applyCounts[0] || verified != applyCounts[1] || possible {
				t.Fatal("Apply preparation included publication metadata or lost its own phase", ack, verified, possible, *applyCounts, *publicationCounts)
			}
		})
	}
}
