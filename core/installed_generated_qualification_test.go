package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

func generatedQualificationImplementation(t *testing.T) contract.GeneratorImplementation {
	t.Helper()
	id := generatedVectorID(220)
	// Independent public route: schema1, contract ID, environment mode1,
	// zero names and empty public data; identity binds the complete blob32.
	route := []byte{0, 1}
	route = append(route, id[:]...)
	route = append(route, 1, 0, 0, 0, 0, 0)
	preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(route)))...)
	preimage = append(preimage, route...)
	row := contract.GeneratorImplementation{Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind, ConfigContractID: id, ProtocolID: id, ExecutorID: id, ArtifactContractID: id, DescriptorID: id, DependencyManifestID: id, ArtifactSHA256: id, CredentialRoute: route, CredentialRouteID: sha256.Sum256(preimage), ArtifactLength: 1, Module: "fixture", Command: ".", Version: "1.0.0", GoVersion: "go1.27.3", NativeTuple: "darwin/arm64"}
	if err := row.Validate(); err != nil {
		t.Fatal(err)
	}
	return row
}

// full_only: false
func TestGeneratedHazardQualificationRequiresExactPassiveMetadata(t *testing.T) {
	implementation := generatedQualificationImplementation(t)
	resultContract, err := contract.GeneratedResultContractID(implementation, contract.GeneratorActionDelete, contract.GeneratedCompletionAcknowledged, 0, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
	if err != nil {
		t.Fatal(err)
	}
	id := generatedVectorID(221)
	resource := generatedVectorID(219)
	base := GeneratedHazardFact{CleanupResultContractID: resultContract, CleanupImplementationQualified: true,
		Record: contract.GeneratedHazardRecord{ResourceID: id, ConfigContractID: implementation.ConfigContractID, ResourceContractID: resource, ExecutorID: implementation.ExecutorID, CredentialRouteID: implementation.CredentialRouteID, DescriptorID: implementation.DescriptorID, CompletionClass: contract.GeneratedCompletionAcknowledged},
		Target: &contract.GeneratorTarget{ResourceID: id, ResourceDigest: generatedVectorID(218), ConfigContractID: implementation.ConfigContractID, ResourceContractID: resource, CompletionClass: contract.GeneratedCompletionAcknowledged}}
	for _, damage := range []string{"none", "changed-default-config", "missing-resolver", "resolver-unavailable", "descriptor", "target-contract", "target-config", "executor", "route", "protocol", "route-body", "invalid-row", "result-contract", "missing-target", "target-identity"} {
		t.Run(damage, func(t *testing.T) {
			row, fact := implementation, base
			row.CredentialRoute = bytes.Clone(implementation.CredentialRoute)
			target := *base.Target
			fact.Target = &target
			bad := generatedVectorID(222)
			switch damage {
			case "changed-default-config":
				row.ConfigContractID = bad
			case "descriptor":
				row.DescriptorID = bad
			case "target-contract":
				target.ResourceContractID = bad
			case "target-config":
				target.ConfigContractID = bad
			case "executor":
				row.ExecutorID = bad
			case "route":
				row.CredentialRouteID = bad
			case "protocol":
				row.ProtocolID = bad
			case "route-body":
				row.CredentialRoute[0] = 1
			case "invalid-row":
				row.ArtifactLength = 0
			case "result-contract":
				fact.CleanupResultContractID = bad
			case "missing-target":
				fact.Target = nil
			case "target-identity":
				target.ResourceID = bad
			}
			calls := 0
			resolver := func(request GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
				calls++
				if request.Retained == nil || request.ConfigContractID != base.Record.ConfigContractID || request.ResourceContractID != resource || request.LifecycleMode != contract.GeneratorLifecycleManaged || request.Retained.Action != contract.GeneratorActionDelete || request.Retained.CompletionClass != contract.GeneratedCompletionAcknowledged || request.Retained.MaxSecret != 0 || request.Retained.InputEncoding != contract.InputEncodingRaw || request.Retained.MaxFacts != contract.GeneratorSafeFactsEnvelopeLength {
					t.Fatal("exact retained Delete meaning changed")
				}
				if damage == "resolver-unavailable" {
					return row, contract.ErrRecord
				}
				return row, nil
			}
			if damage == "missing-resolver" {
				resolver = nil
			}
			out := PublicApplyResult{Result: Result{Outcome: UnresolvedCommit, CommitMayHaveOccurred: true}, Generated: &GeneratedInvocationResult{Hazards: []GeneratedHazardFact{fact}}}
			before := out.Result
			qualifyGeneratedInvocationResult(ApplyInstallation{Generated: &GeneratedApplyInstallation{ResolveImplementation: resolver}}, &out)
			want := damage == "none" || damage == "changed-default-config"
			if out.Generated.Hazards[0].CleanupImplementationQualified != want || !reflect.DeepEqual(out.Result, before) {
				t.Fatal("passive qualification changed actual evidence or retained support", damage, out)
			}
			expectedCalls := 1
			if damage == "missing-resolver" || damage == "missing-target" || damage == "target-identity" || damage == "target-contract" || damage == "target-config" {
				expectedCalls = 0
			}
			if calls != expectedCalls {
				t.Fatal("passive lookup count", calls, expectedCalls)
			}
		})
	}
}

// full_only: false
func TestGeneratedHazardCleanupContractUsesExactRetainedDelete(t *testing.T) {
	state, _, hazard, target := generatedDeleteHazardForOperation(t, generatedVectorID(224), 1)
	work := mustSelectedGeneratedWork(t, state)
	row := work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.HazardID}]
	source, err := contract.InspectGeneratedDeleteSource(row)
	if err != nil {
		t.Fatal(err)
	}
	got, err := generatedCleanupResultContract(work, source, target)
	if err != nil || got != hazard.ResultContractID {
		t.Fatal("retained Delete contract was reclassified through a Create template", got, err)
	}
	target.ResourceID = generatedVectorID(225)
	if _, err := generatedCleanupResultContract(work, source, target); err == nil {
		t.Fatal("different actual resource borrowed retained Delete contract")
	}
}

// full_only: false
func TestGeneratedHazardCleanupContractUsesRetainedCreateCleanupTemplate(t *testing.T) {
	state, _, hazard := generatedCreateHazardState(t, 0, 1)
	work := mustSelectedGeneratedWork(t, state)
	source, err := contract.InspectGeneratedDeleteSource(work.records[generatedRecordKey{contract.GeneratedHazardSupportKind, hazard.HazardID}])
	if err != nil {
		t.Fatal(err)
	}
	target, err := work.generatedCleanupTarget(source.Record.Kind, source.SourceID, source.Target)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("retained cleanup", func(t *testing.T) {
		fact, err := generatedHazardFact(t.Context(), work, hazard.HazardID)
		if err != nil || fact.Target == nil || fact.CleanupResultContractID != generatedVectorID(49) || fact.CleanupResultContractID == hazard.ResultContractID || fact.CleanupImplementationQualified {
			t.Fatal("Create result contract replaced exact retained Delete cleanup contract", fact, err)
		}
	})
	for _, damage := range []string{"missing cleanup", "wrong result slot", "owned resource", "resolved digest", "actual digest"} {
		t.Run(damage, func(t *testing.T) {
			damaged := *work
			damaged.bundles = slices.Clone(work.bundles)
			for i := range damaged.bundles {
				damaged.bundles[i] = cloneGeneratorPlanBundle(damaged.bundles[i])
			}
			actual := target
			switch damage {
			case "missing cleanup":
				damaged.bundles[0].Lineages = slices.DeleteFunc(damaged.bundles[0].Lineages, func(row contract.GeneratorLineageTemplate) bool {
					return row.Purpose == contract.GeneratorLineageCleanup
				})
			case "actual digest":
				actual.ResourceDigest = generatedVectorID(225)
			default:
				for i := range damaged.bundles[0].Lineages {
					lineage := &damaged.bundles[0].Lineages[i]
					if lineage.Purpose != contract.GeneratorLineageCleanup {
						continue
					}
					for j := range lineage.Templates[:lineage.TemplateCount] {
						x := &lineage.Templates[j]
						switch damage {
						case "wrong result slot":
							x.TargetSourceID = generatedVectorID(225)
						case "owned resource":
							x.TargetKind, x.TargetSourceID = contract.GeneratorTargetOwnedResource, target.ResourceID
						case "resolved digest":
							x.ResourceDigest = target.ResourceDigest
						}
					}
				}
			}
			if _, err := generatedCleanupResultContract(&damaged, source, actual); err == nil {
				t.Fatal("changed retained cleanup binding was accepted")
			}
		})
	}
}

// full_only: false
func TestGeneratedHistoricalHazardKeepsUnavailableCleanupContract(t *testing.T) {
	for _, fenced := range []uint8{0, 1} {
		state, hazard, _ := generatedDetachedHazardState(t, "absent", 0, contract.GeneratorDispositionOwnedUnusableCreate, fenced)
		work := mustSelectedGeneratedWork(t, state)
		if len(work.attempts) != 0 || len(work.bundles) != 0 {
			t.Fatal("fixture retained operational authority")
		}
		fact, err := generatedHazardFact(t.Context(), work, hazard.HazardID)
		if err != nil || fact.Target == nil || !fact.CleanupResultContractID.IsZero() || fact.CleanupImplementationQualified || fact.Record != hazard {
			t.Fatal("historical target without a retained Delete contract could not be listed", fact, err)
		}
	}
	state, _, hazard := generatedCreateHazardState(t, 0, 0)
	fact, err := generatedHazardFact(t.Context(), mustSelectedGeneratedWork(t, state), hazard.HazardID)
	if err != nil || fact.Target != nil || !fact.CleanupResultContractID.IsZero() || fact.CleanupImplementationQualified {
		t.Fatal("unowned Hazard acquired cleanup qualification", fact, err)
	}
}

// full_only: false
func TestGeneratedMixedApplyReclassifiesRetainedPlainInput(t *testing.T) {
	for _, beforeInput := range []uint8{contract.InputEncodingRaw, contract.InputEncodingBase64} {
		for _, changeClass := range []bool{false, true} {
			t.Run(fmt.Sprintf("input=%d/change=%t", beforeInput, changeClass), func(t *testing.T) {
				s, _ := observationTestSession(t)
				current := observationPlainEntry("plain", generatedVectorID(201), []contract.ID{s.admission.recipient})
				current.InputEncoding, current.ValueBytes, current.RetainedLength = beforeInput, []byte("QUJD"), 4
				current.ContentLength = 4
				afterInput := contract.InputEncodingBase64
				if beforeInput == contract.InputEncodingBase64 {
					current.ContentLength, afterInput = 3, contract.InputEncodingRaw
				}
				if !changeClass {
					afterInput = beforeInput
				}
				observationInstallEntries(s, []contract.ValueEntry{current})
				generatedSealSelectedFixture(t, s)
				if _, err := s.selectedGeneratedWork(t.Context()); err != nil {
					t.Fatal("selected work baseline", err)
				}
				if _, err := s.closureIDsMode(t.Context(), false); err != nil {
					t.Fatal("selected identity baseline", err)
				}
				implementation := generatedQualificationImplementation(t)
				intent := generatedFixtureCanonicalIntent(t, []byte("{}"), generatedFixtureProfile{ConfigContractID: implementation.ConfigContractID, LifecycleMode: contract.GeneratorLifecycleNone})
				meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, Epoch: 0,
					ConfigContractID: implementation.ConfigContractID, LifecycleMode: contract.GeneratorLifecycleNone, Intent: intent}
				calls := 0
				installation := ApplyInstallation{DesiredRecipients: currentApplyRecipients(s.registry()), Generated: &GeneratedApplyInstallation{
					ResolveImplementation: func(GeneratedImplementationRequest) (contract.GeneratorImplementation, error) {
						return implementation, nil
					},
					CheckCreateReadiness: func(context.Context, string, contract.GeneratorImplementation, []byte) error { calls++; return nil },
					RequestDigest: func(context.Context, contract.GeneratorImplementation, uint8, []byte, *contract.GeneratorTarget) (contract.ID, error) {
						return generatedVectorID(202), nil
					},
				}}
				entries := []ApplyEntryInput{{Name: current.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: current.Recipients,
					InputEncoding: afterInput, OutputEncoding: contract.OutputEncodingRaw, InputBytes: bytes.Clone(current.ValueBytes)},
					{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: current.Recipients,
						InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Generated: &meta}}
				if _, err := contract.EncodeGeneratorDeclaredGeneration(meta); err != nil {
					t.Fatal("declared generation baseline", err)
				}
				if _, err := installedGeneratedContext(s, time.Now().Add(time.Minute)); err != nil {
					t.Fatal("installed context baseline", err)
				}
				if _, err := s.generatedOutputTransitionWithRecipients(t.Context(), s.registry(), entries, nil); err != nil {
					t.Fatal("selected output baseline", err)
				}
				plan, err := s.installedGeneratedPlan(t.Context(), installation, entries, nil, time.Now().Add(time.Minute))
				if err != nil || plan == nil {
					t.Fatal("mixed representation plan refused", err, "readiness calls", calls)
				}
				at := slices.IndexFunc(plan.input.graph.ValueEntryPlans, func(p contract.GeneratorValueEntryPlan) bool { return p.Name == current.Name })
				if at < 0 || plan.input.graph.ValueEntryPlans[at].InputEncoding != afterInput || (plan.input.graph.ValueEntryPlans[at].ChangeMask&contract.GeneratorValueChangeContent != 0) != changeClass {
					t.Fatal("same retained bytes hid changed input representation")
				}
				if calls != 1 {
					t.Fatal("representation change created another generator request", calls)
				}
			})
		}
	}
}
