package core

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type packagedRecoveryCase struct {
	phase                           string
	replies                         []string
	retirement                      bool
	signs, heads, decrypts, inboxes int
	active, done                    bool
	served                          int
}

// full_only: false
func TestInstalledPackagedNativeRecoveryCandidateCharges(t *testing.T) {
	for _, phase := range []string{"A0", "A1", "B2"} {
		for _, script := range []struct {
			name                            string
			replies                         []string
			signs, heads, decrypts, inboxes int
		}{
			{"residue-then-value", []string{"unknown", "complete"}, 7, 6, 6, 1},
			{"two-unknowns", []string{"unknown", "unknown"}, 6, 5, 3, 0},
			{"residue-then-owned", []string{"unknown", "owned"}, 6, 5, 4, 1},
			{"owned-without-value", []string{"owned"}, 4, 3, 3, 1},
		} {
			t.Run(phase+"/"+script.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()
				fault := packagedRecoveryCase{phase: phase, replies: slices.Clone(script.replies), signs: script.signs, heads: script.heads, decrypts: script.decrypts, inboxes: script.inboxes}
				if phase == "A0" && script.name == "residue-then-value" {
					fault.replies[0] = "rejected"
				}
				packagedGeneratedSequenceWithRecovery(t, ctx, &fault)
				if !fault.done || fault.served != len(fault.replies) {
					t.Fatal("controlled recovery did not stop at its complete terminal")
				}
			})
		}
	}
	for _, phase := range []string{"retire A0 under B selection", "retire A1 with B", "retire detached B2"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
			defer cancel()
			fault := packagedRecoveryCase{phase: phase, replies: []string{"unknown"}, retirement: true, signs: 3, heads: 2, decrypts: 1}
			packagedGeneratedSequenceWithRecovery(t, ctx, &fault)
			if !fault.done || fault.served != 1 {
				t.Fatal("original retirement ambiguity did not stop after one send")
			}
		})
	}
}

// Called only while the sequence server's mutex is held.
func (c *packagedRecoveryCase) reply(t *testing.T, w http.ResponseWriter, method string, token int) bool {
	if c == nil || !c.active {
		return false
	}
	if c.served >= len(c.replies) || (method == http.MethodDelete) != c.retirement {
		t.Error("controlled recovery exceeded its native send entitlement")
		w.WriteHeader(http.StatusBadRequest)
		return true
	}
	reply := c.replies[c.served]
	c.served++
	switch reply {
	case "complete":
		return false
	case "unknown":
		w.WriteHeader(http.StatusOK)
	case "rejected":
		w.WriteHeader(http.StatusForbidden)
		if _, err := fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"controlled rejection"}],"messages":[],"result":null}`); err != nil {
			t.Error(err)
		}
	case "owned":
		if _, err := fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%032x","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, token, hermeticCloudflarePermission, hermeticCloudflareAccount); err != nil {
			t.Error(err)
		}
	default:
		t.Error("unknown controlled native reply")
		w.WriteHeader(http.StatusBadRequest)
	}
	return true
}

func (c *packagedRecoveryCase) checkWindow(t *testing.T, ctx context.Context, f installedApplyTestFixture, observation *packagedSequenceObservation, command packagedSequenceCommand, firstHead int) {
	t.Helper()
	if command.SignEnd-command.SignStart != c.signs || command.DecryptCalls != c.decrypts || command.QualificationCalls != 0 || len(observation.heads)-firstHead != c.heads {
		t.Fatal("recovery signing, selection or custody count differs", command)
	}
	shapes := packagedSequenceCandidateShapes(t, ctx, f, observation.heads[firstHead:])
	if len(shapes) != c.heads || c.signs-c.heads != 1 {
		t.Fatal("recovery lost its single repeated original reservation")
	}
	for _, shape := range shapes {
		if shape.ChildCount > 21 || shape.selectedReadBound() > 210 {
			t.Fatal("recovery candidate exceeds independent conservative read bound", shape)
		}
	}
	results := map[string]packagedSequenceWrite{}
	resultSends := map[string]int{}
	start := command.WriteStart
	for _, sign := range observation.signs[command.SignStart:command.SignEnd] {
		if !slices.ContainsFunc(shapes, func(s packagedSequenceShape) bool { return s.SignDigest == sign.Digest }) {
			t.Fatal("recovery signing subject has no authenticated selected candidate")
		}
		seen := map[string]bool{}
		var objects, bodyBytes uint64
		for _, write := range observation.writes[start:sign.Writes] {
			if write.Identity.Namespace == contract.StoreResultObject {
				old, repeated := results[write.Key]
				if repeated {
					if resultSends[write.Key] != 1 || old.Identity != write.Identity || old.Digest != write.Digest || old.Length != write.Length || write.Status != contract.WritePrecondition {
						t.Fatal("recovery repeated or changed its original result inbox")
					}
				} else if write.Status != contract.WriteAcknowledged {
					t.Fatal("recovery original inbox was not acknowledged")
				}
				results[write.Key] = write
				resultSends[write.Key]++
				continue
			}
			if seen[write.Key] {
				t.Fatal("recovery repeated an immutable send inside one persistence episode")
			}
			seen[write.Key] = true
			objects++
			bodyBytes += write.Length
		}
		if objects > 18 || bodyBytes > 459131 {
			t.Fatal("recovery persistence exceeds independent conservative object/byte bound", objects, bodyBytes)
		}
		start = sign.Writes
	}
	if start != command.WriteEnd || len(results) != c.inboxes {
		t.Fatal("recovery writes or result set differ")
	}
	for _, sends := range resultSends {
		if sends != 2 {
			t.Fatal("recovery result did not retain both persistence episodes")
		}
	}
}

func (c *packagedRecoveryCase) checkCreate(t *testing.T, ctx context.Context, f installedApplyTestFixture, heads []packagedSequenceHead, before, closed *StateSession, result PublicApplyResult, implementation contract.GeneratorImplementation) {
	t.Helper()
	g := result.Generated
	if result.Result.Outcome != ObservedCurrent || g == nil || result.Payload == nil || !g.EffectsAvailable || !g.RelatedWorkAvailable || !g.SummaryCountsAvailable || len(g.Effects) != len(c.replies) {
		t.Fatal("native recovery terminal is incomplete", result.Result)
	}
	work := mustSelectedGeneratedWork(t, closed)
	if len(heads) < 2 || closed.head.Generator == nil || closed.head.Generator.Purpose != contract.GeneratorAuthorityFinal {
		t.Fatal("native recovery has no authenticated terminal Final")
	}
	preFinal, opened := Open(ctx, f.admitted, packagedSequenceHeadStore{Store: requireAdmittedMemoryStore(t, f.env.Store), head: heads[len(heads)-2]})
	if preFinal == nil || opened.Outcome != ObservedCurrent {
		t.Fatal("native recovery pre-Final authentication", opened)
	}
	original := mustSelectedGeneratedWork(t, preFinal)
	if original.parent == nil || original.parent.OperationID != result.OperationID || original.parent.RequestIdentityDigest != result.RequestIdentity || original.phase == nil || original.phase.NoEffectUsed != 0 {
		t.Fatal("native recovery changed its original parent identity")
	}
	if work.parent != nil || work.phase != nil || !closed.root.Generated.ActiveOwner.IsZero() || !closed.root.Generated.ActivePhase.IsZero() || !closed.root.Generated.ActiveGraph.IsZero() {
		t.Fatal("native recovery left an active parent")
	}
	last := c.replies[len(c.replies)-1]
	selected := last == "complete"
	canonical, state := uint8(contract.ReceiptCanonicalNotSelected), "effect-terminal-failure"
	if last == "unknown" {
		state = "effect-unknown"
	}
	wantDuties := 0
	if selected {
		canonical, state = contract.ReceiptCanonicalSelected, "success"
		if c.phase != "A0" {
			wantDuties, state = 1, "retirement-pending"
		}
	}
	wantHazards := len(c.replies)
	if selected {
		wantHazards--
	}
	if g.CanonicalOutcome != canonical || g.StateResult != state || len(g.Duties) != wantDuties || len(g.Hazards) != wantHazards || int(closed.root.Generated.Hazards) != wantHazards {
		t.Fatal("native recovery selected the wrong canonical or residue terminal", g.StateResult)
	}
	var hazards []contract.ID
	var effectRows, dutyRows, hazardRows []contract.SupportRecord
	var lineage contract.ID
	unknown := uint32(0)
	for at, effect := range g.Effects {
		actual, present := original.attempts[effect.Record.AttemptID]
		branch := uint8(contract.GeneratorBranchInitial)
		if at == 1 {
			branch = contract.GeneratorBranchResidue
		}
		x := actual.expected.Template
		if !present || actual.record != effect.Record || x.Branch != branch || x.AttemptID != effect.Record.AttemptID || x.TransmissionID != effect.Record.TransmissionID || x.ResultID != effect.Record.ResultID || x.InboxID != effect.Record.InboxID || effect.Record.OperationID != result.OperationID || effect.Record.ExecutorID != implementation.ExecutorID || effect.Record.CredentialRouteID != implementation.CredentialRouteID || effect.Record.DescriptorID != implementation.DescriptorID || effect.Action != contract.GeneratorActionCreate || effect.Name != "generated" || effect.Record.Stage != contract.GeneratedStageTerminal {
			t.Fatal("native recovery lost an original authenticated Attempt tuple")
		}
		if at == 0 {
			lineage = x.LineageID
		} else if x.LineageID != lineage || x.AttemptID == g.Effects[0].Record.AttemptID || x.TransmissionID == g.Effects[0].Record.TransmissionID || x.ResultID == g.Effects[0].Record.ResultID || x.InboxID == g.Effects[0].Record.InboxID {
			t.Fatal("native recovery did not use distinct original identities in one lineage")
		}
		effectRows = append(effectRows, original.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, x.AttemptID}])
		if c.replies[at] == "complete" {
			if _, present := work.attempts[x.AttemptID]; present {
				t.Fatal("selected Final retained its completed create Attempt")
			}
			if _, present := work.releases[x.AttemptID]; present {
				t.Fatal("selected Final invented a completed CREATE release mapping")
			}
			if effect.Record.State != contract.GeneratedEffectSucceeded || effect.Target == nil {
				t.Fatal("native recovery success has no exact owned target")
			}
			_, value := observeCurrentValueEntry(t, closed, "generated")
			m := value.Generated
			if m.OriginOperationID != result.OperationID || m.OriginAttemptID != x.AttemptID || m.CreateResultID != x.ResultID || m.ResourceIncarnationID != x.ResourceIncarnationID || m.GenerationID != effect.GenerationID || value.Incarnation != effect.EntryIncarnationID {
				t.Fatal("selected recovery value lost its original create relation")
			}
			evidence, err := contract.InspectGeneratedCreateEvidence(work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, x.ResultID}].Body)
			if err != nil {
				t.Fatal("selected recovery create evidence is absent", err)
			}
			core, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
			if err != nil || core.OperationID != result.OperationID || core.AttemptID != x.AttemptID || core.TransmissionID != x.TransmissionID || core.ResultID != x.ResultID || core.ExecutorID != implementation.ExecutorID || core.RequestDigest != effect.Record.RequestDigest {
				t.Fatal("selected recovery create evidence changed its original tuple", err)
			}
			wantTarget := contract.GeneratorTarget{Schema: contract.GeneratorTargetSchema, Name: value.Name, IncarnationID: value.Incarnation, Epoch: m.Epoch, ResourceID: m.ResourceIncarnationID, LifecycleMode: m.LifecycleMode, ResourceDigest: m.ResourceDigest, ConfigContractID: m.ConfigContractID, ResourceContractID: m.ResourceContractID, OriginalOperationID: m.OriginOperationID, OriginalAttemptID: m.OriginAttemptID, ResultContractID: core.ResultContractID, CompletionClass: m.CompletionClass}
			if *effect.Target != wantTarget {
				t.Fatal("accepted recovery effect target differs from the selected value")
			}
			continue
		}
		coldAttempt, present := work.attempts[x.AttemptID]
		if !present || coldAttempt.record != effect.Record {
			t.Fatal("terminal recovery lost an unresolved original Attempt")
		}
		hazardAt := slices.IndexFunc(g.Hazards, func(h GeneratedHazardFact) bool { return h.Record.OriginalAttemptID == x.AttemptID })
		if hazardAt < 0 {
			t.Fatal("native recovery omitted an original residue owner")
		}
		hazard := g.Hazards[hazardAt]
		cold, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.Record.HazardID}].Body)
		if err != nil || cold != hazard.Record || cold.OriginalOperationID != result.OperationID || cold.ResourceID != x.ResourceIncarnationID || cold.ExecutorID != implementation.ExecutorID || cold.CredentialRouteID != implementation.CredentialRouteID || cold.Fenced != 1 {
			t.Fatal("native recovery cold Hazard differs from its original Attempt", err)
		}
		if c.replies[at] == "owned" {
			targetRows, err := work.vectors.resolve(contract.GeneratedHazardSupportKind, cold.HazardID, contract.GeneratorVectorTargets, cold.Target)
			if err != nil || len(targetRows) != 1 {
				t.Fatal("owned recovery Hazard target is absent", err)
			}
			target, err := contract.InspectGeneratorTarget(targetRows[0])
			if err != nil || hazard.Target == nil || *hazard.Target != target || effect.Target == nil || *effect.Target != target || target.OriginalAttemptID != x.AttemptID || target.ResourceID != x.ResourceIncarnationID {
				t.Fatal("owned recovery public target differs from authenticated original", err)
			}
			if effect.Record.State != contract.GeneratedEffectFailedTerminal || hazard.Target == nil || cold.Target.Count != 1 || cold.OriginalResults.Count != 1 || cold.Exposure != contract.GeneratedExposureLateEffect || cold.Eligibility != contract.GeneratedExposureLateEffect {
				t.Fatal("owned unusable result lost its exact late-effect target")
			}
		} else {
			unknown++
			if effect.Record.State != contract.GeneratedEffectClosedWithResidue || hazard.Target != nil || cold.Target.Count != 0 || cold.OriginalResults.Count != 0 || cold.Exposure != contract.GeneratedExposurePossibleLive || effect.Record.Facts.Count != 0 {
				t.Fatal("unknown result became known effect or no-effect evidence")
			}
		}
		hazards = append(hazards, cold.HazardID)
		hazardRows = append(hazardRows, work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, cold.HazardID}])
	}
	slices.SortFunc(hazards, compareGeneratedIDs)
	if !slices.Equal(hazards, g.RelatedHazardIDs) || !slices.Equal(hazards, result.Payload.LiveHazardIDs) || g.UnknownCount != unknown || g.SummaryCounts[contract.ReceiptNoEffectPredecessorCount] != 0 {
		t.Fatal("native recovery residue set or uncertainty count differs")
	}
	if !selected {
		packagedRecoveryCurrentUnchanged(t, before, closed)
	} else {
		_, value := observeCurrentValueEntry(t, closed, "generated")
		if value.ValueSource != contract.Generated || value.Generated.GenerationID.IsZero() || value.Generated.RetiringDutyPresent != uint8(wantDuties) {
			t.Fatal("recovery value lost its exact retirement requirement")
		}
		if wantDuties == 1 {
			_, prior := observeCurrentValueEntry(t, before, "generated")
			duty := g.Duties[0]
			dutyRows = append(dutyRows, work.records[generatedRecordKey{contract.GeneratedDutySupportKind, duty.Record.DutyID}])
			cold, err := contract.InspectGeneratedDutyRecord(dutyRows[0].Body)
			if err != nil || cold != duty.Record {
				t.Fatal("recovery public retirement Duty differs from its cold record", err)
			}
			matched := 0
			for _, graph := range original.bundles {
				if graph.Header.OperationID != result.OperationID {
					continue
				}
				for _, lineage := range graph.Lineages {
					for _, template := range lineage.Templates[:lineage.TemplateCount] {
						if lineage.Purpose != contract.GeneratorLineageRetirement || template.DutyID != cold.DutyID {
							continue
						}
						matched++
						if cold.ExecutorID != template.ExecutorID || cold.CredentialRouteID != template.CredentialRouteID || cold.DescriptorID != template.DescriptorID || cold.ResultContractID != template.ResultContractID {
							t.Fatal("new recovery Duty lost its admitted retirement implementation")
						}
					}
				}
			}
			if matched != 1 {
				t.Fatal("new recovery Duty does not have one original retirement template")
			}
			target, err := work.retirementTarget(ctx, cold)
			if err != nil || duty.Target == nil || *duty.Target != target || target.OriginalOperationID != prior.Generated.OriginOperationID || target.OriginalAttemptID != prior.Generated.OriginAttemptID || target.ConfigContractID != prior.Generated.ConfigContractID || target.ResourceContractID != prior.Generated.ResourceContractID || target.CompletionClass != prior.Generated.CompletionClass || target.Name != prior.Name || target.ResourceID != prior.Generated.ResourceIncarnationID || target.LifecycleMode != prior.Generated.LifecycleMode || target.ResourceDigest != prior.Generated.ResourceDigest || target.IncarnationID != prior.Incarnation || target.Epoch != prior.Generated.Epoch {
				t.Fatal("recovery retirement changed the exact predecessor target", err)
			}
			if duty.Record.Kind != contract.GeneratedDutyRetirement || duty.Record.DutyID != value.Generated.RetiringDutyID || duty.Record.ResourceID != prior.Generated.ResourceIncarnationID || duty.Record.ExecutorID != implementation.ExecutorID || duty.Target == nil {
				t.Fatal("recovery selected a foreign original retirement obligation")
			}
		}
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationID != result.OperationID || receipt.RequestIdentityDigest != result.RequestIdentity || receipt.OperationKind != contract.OperationApplyDeclaration || receipt.CanonicalOutcome != canonical || receipt.SummaryCounts != g.SummaryCounts || receipt.UnknownCount != unknown {
		t.Fatal("native recovery receipt differs from authenticated terminal facts", err)
	}
	wantCounts := [contract.ReceiptSummaryCount]uint32{}
	wantCounts[contract.ReceiptEffectCount], wantCounts[contract.ReceiptDutyCount], wantCounts[contract.ReceiptHazardCount] = uint32(len(c.replies)), uint32(wantDuties), uint32(wantHazards)
	if len(c.replies) == 2 {
		wantCounts[contract.ReceiptPreservedResidueCount] = 1
	}
	class := contract.ReceiptSummaryFailureCount
	if selected {
		class = contract.ReceiptSummarySuccessCount
	} else if last == "unknown" {
		class = contract.ReceiptSummaryUnknownCount
	}
	wantCounts[class] = 1
	for at, effect := range g.Effects {
		wantClass := class
		if at == 0 && len(c.replies) == 2 {
			wantClass = contract.ReceiptPreservedResidueCount
		}
		if effect.SummaryClass != wantClass {
			t.Fatal("native recovery changed an entered effect summary class")
		}
	}
	if g.Warnings.PossibleLiveResidue != (len(c.replies) == 2) || g.Warnings.LateEffect != (last == "owned") || g.Warnings.InvalidationNotConfirmed {
		t.Fatal("native recovery current warning classes differ", g.Warnings)
	}
	wantWarnings, err := contract.EncodeReceiptWarningBits(contract.OperationApplyDeclaration, preFinal.root.WarningBits, contract.ReceiptWarningPossibleLive)
	if err != nil || receipt.WarningBits != wantWarnings {
		t.Fatal("native recovery historical warning encoding differs", err)
	}
	if g.SummaryCounts != wantCounts {
		t.Fatal("native recovery receipt summary differs", g.SummaryCounts, wantCounts)
	}
	var duties []contract.ID
	for _, row := range dutyRows {
		duties = append(duties, row.RecordID)
	}
	if !slices.Equal(duties, g.RelatedDutyIDs) || !slices.Equal(duties, result.Payload.LiveDutyIDs) {
		t.Fatal("native recovery retirement identity set differs")
	}
	packagedRecoveryReceipt(t, preFinal, closed, result, original.parent.RequestCoreDigest, effectRows, dutyRows, hazardRows)
	c.done = true
}

func (c *packagedRecoveryCase) checkRetirement(t *testing.T, ctx context.Context, before, closed *StateSession, result PublicApplyResult, dutyID, executor contract.ID) {
	t.Helper()
	prior := mustSelectedGeneratedWork(t, before)
	original, err := contract.InspectGeneratedDutyRecord(prior.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}].Body)
	if err != nil {
		t.Fatal(err)
	}
	oldTarget, err := prior.retirementTarget(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	g := result.Generated
	if result.Result.Outcome != ObservedCurrent || g == nil || g.StateResult != "effect-unknown" || g.CanonicalOutcome != contract.ReceiptCanonicalNotSelected || len(g.Effects) != 1 || len(g.Duties) != 1 || len(g.Hazards) != 0 || g.UnknownCount != 1 || g.AcknowledgedCount != 0 || g.ConfirmedCount != 0 || result.Payload == nil || !g.EffectsAvailable || !g.RelatedWorkAvailable || !g.SummaryCountsAvailable {
		t.Fatal("original retirement ambiguity terminal differs", result.Result)
	}
	work := mustSelectedGeneratedWork(t, closed)
	current, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}].Body)
	if err != nil || current.DutyID != original.DutyID || current.Target != original.Target || current.ExecutorID != executor || current.CredentialRouteID != original.CredentialRouteID || current.DescriptorID != original.DescriptorID || current.ResultContractID != original.ResultContractID || current.Status != contract.GeneratedEffectUnknown || work.parent != nil || work.phase != nil {
		t.Fatal("original retirement ambiguity lost its frozen Duty tuple", err)
	}
	newTarget, err := work.retirementTarget(ctx, current)
	if err != nil || !reflect.DeepEqual(oldTarget, newTarget) {
		t.Fatal("original retirement ambiguity changed its target or canonical value", err)
	}
	if g.Duties[0].Record != current || g.Duties[0].Target == nil || *g.Duties[0].Target != newTarget || !slices.Equal(g.RelatedDutyIDs, []contract.ID{dutyID}) || !slices.Equal(result.Payload.LiveDutyIDs, []contract.ID{dutyID}) || len(g.RelatedHazardIDs) != 0 || len(result.Payload.LiveHazardIDs) != 0 || closed.root.Generated.Duties != 1 || closed.root.Generated.Hazards != 0 || !closed.root.Generated.ActiveOwner.IsZero() || !closed.root.Generated.ActivePhase.IsZero() || !closed.root.Generated.ActiveGraph.IsZero() {
		t.Fatal("original retirement ambiguity work set differs")
	}
	packagedRecoveryCurrentUnchanged(t, before, closed)
	effect := g.Effects[0]
	actual, present := work.attempts[effect.Record.AttemptID]
	if !present || actual.record != effect.Record || actual.record.State != contract.GeneratedEffectUnknown || actual.record.Stage != contract.GeneratedStageTerminal || actual.record.ExecutorID != executor || actual.record.CredentialRouteID != original.CredentialRouteID || len(actual.result) != 0 {
		t.Fatal("original retirement ambiguity gained acknowledgement evidence")
	}
	if _, present := work.releases[actual.record.AttemptID]; present {
		t.Fatal("unknown retirement gained an inbox release")
	}
	if actual.record.OperationID != result.OperationID || actual.record.OwnerID != dutyID || actual.record.ResourceID != original.ResourceID || actual.record.ConfigContractID != original.ConfigContractID || actual.record.ResourceContractID != original.ResourceContractID || actual.record.DescriptorID != original.DescriptorID || actual.record.ResultContractID != original.ResultContractID || actual.expected.Template.Action != contract.GeneratorActionDelete || actual.expected.Template.DutyID != dutyID {
		t.Fatal("unknown retirement changed its original execution tuple")
	}
	receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
	if err != nil || receipt.OperationKind != contract.OperationRetireGeneratedGeneration || receipt.OperationID != result.OperationID || receipt.RequestIdentityDigest != result.RequestIdentity || receipt.UnknownCount != 1 || receipt.SummaryCounts[contract.ReceiptSummaryUnknownCount] != 1 || receipt.SummaryCounts[contract.ReceiptDutyCount] != 1 || receipt.SummaryCounts[contract.ReceiptHazardCount] != 0 || receipt.SummaryCounts != g.SummaryCounts {
		t.Fatal("original retirement ambiguity receipt differs", err)
	}
	wantWarnings, err := contract.EncodeReceiptWarningBits(contract.OperationRetireGeneratedGeneration, before.root.WarningBits, 0)
	if err != nil || receipt.WarningBits != wantWarnings || g.Warnings != (GeneratedResultWarnings{}) {
		t.Fatal("unknown retirement invented completion or residue warnings", err)
	}
	wantCounts := [contract.ReceiptSummaryCount]uint32{}
	wantCounts[contract.ReceiptEffectCount], wantCounts[contract.ReceiptDutyCount], wantCounts[contract.ReceiptSummaryUnknownCount] = 1, 1, 1
	if g.SummaryCounts != wantCounts || effect.SummaryClass != contract.ReceiptSummaryUnknownCount || effect.Target == nil || *effect.Target != oldTarget {
		t.Fatal("original retirement ambiguity summary or effect target differs")
	}
	graphAt := slices.IndexFunc(work.bundles, func(graph contract.GeneratorPlanBundle) bool { return graph.Header.OperationID == result.OperationID })
	if graphAt < 0 || work.bundles[graphAt].Request.OperationKind != contract.OperationRetireGeneratedGeneration || work.bundles[graphAt].Request.PredecessorRevisionID != before.head.Core.Revision {
		t.Fatal("original retirement ambiguity lost its original request")
	}
	packagedRecoveryReceipt(t, before, closed, result, work.bundles[graphAt].Header.RequestCoreDigest,
		[]contract.SupportRecord{work.records[generatedRecordKey{contract.GeneratedAttemptSupportKind, effect.Record.AttemptID}]},
		[]contract.SupportRecord{work.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}]}, nil)
	c.done = true
}

func packagedRecoveryCurrentUnchanged(t *testing.T, before, closed *StateSession) {
	t.Helper()
	if !reflect.DeepEqual(before.currentEntryInputs(), closed.currentEntryInputs()) || !reflect.DeepEqual(before.root.Names, closed.root.Names) {
		t.Fatal("failed native operation changed prior canonical values")
	}
	if len(before.root.Names) != 0 {
		_, old := observeCurrentValueEntry(t, before, "generated")
		_, current := observeCurrentValueEntry(t, closed, "generated")
		if !reflect.DeepEqual(old, current) {
			t.Fatal("failed native operation changed prior value metadata")
		}
	}
}

func packagedRecoveryReceipt(t *testing.T, before, closed *StateSession, result PublicApplyResult, requestCore contract.ID, effects, duties, hazards []contract.SupportRecord) {
	t.Helper()
	receipt, raw, found, err := closed.retainedMutationReceipt(result.OperationID)
	if err != nil || !found || !bytes.Equal(raw, result.Receipt) {
		t.Fatal("native recovery terminal receipt is not retained exactly", err)
	}
	for _, a := range before.accessRecords() {
		for _, b := range closed.accessRecords() {
			if a.MaterialKind == b.MaterialKind && a.MaterialID == b.MaterialID && !reflect.DeepEqual(a, b) {
				t.Fatal("fixed recovery changed common access material")
			}
		}
	}
	access, err := contract.AccessChangeDescriptor(closed.root.Domain, nil)
	if err != nil {
		t.Fatal(err)
	}
	var descriptors [3]contract.GeneratorDescriptor
	for at, rows := range [][]contract.SupportRecord{effects, duties, hazards} {
		kind := []contract.MutationResultRecordKind{contract.MutationResultEffects, contract.MutationResultDuties, contract.MutationResultHazards}[at]
		descriptors[at], err = contract.MutationResultRecordDescriptor(kind, closed.root.Domain, rows)
		if err != nil {
			t.Fatal("native recovery exact result record commitment", err)
		}
	}
	g := result.Generated
	if g.EffectsCommitment == nil || *g.EffectsCommitment != descriptors[0] || g.RelatedDutiesCommitment == nil || *g.RelatedDutiesCommitment != descriptors[1] || g.RelatedHazardsCommitment == nil || *g.RelatedHazardsCommitment != descriptors[2] {
		t.Fatal("native recovery public commitments differ from authenticated rows")
	}
	plan := receipt
	plan.RequestIdentityDigest, plan.CompleteResult = contract.ID{}, contract.GeneratorDescriptor{}
	complete, err := contract.CompleteMutationResultDescriptor(contract.MutationResultProjection{Receipt: contract.CompactMutationReceiptPlan(plan), RequestCoreDigest: requestCore, ChangedAccess: access, Effects: descriptors[0], Outputs: contract.EmptyMutationResultDescriptors()[2], Duties: descriptors[1], Hazards: descriptors[2]})
	if err != nil || complete != receipt.CompleteResult {
		t.Fatal("native recovery complete result is not bound by its cold receipt", err)
	}
}
