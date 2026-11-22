package main

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact/credentialroute"
)

func assertCompleteStockPluginEvidencePredicates(t *testing.T, artifact records.StockPluginArtifact, provider string) {
	t.Helper()
	t.Run("complete-evidence", func(t *testing.T) {
		// These are in-memory identities, not captured provider observations.
		// The lineage follows the independent three-epoch acceptance example.
		id := func(n int) string { return fmt.Sprintf("%064x", n) }
		run := strings.Repeat("a", 32)
		input := records.StockPluginAcceptanceInput{
			Artifact: artifact,
			Fixture:  records.StockPluginFixture{Schema: 1, Purpose: "stock-plugin-acceptance", FixtureID: "0123456789abcdef0123456789abcdef", Provider: provider, Region: "us-east-1", Bucket: "fixture-pa-0123456789abcdef0123456789abcdef", Account: "123456789012"},
		}
		switch provider {
		case "aws":
		case "gcp":
			input.Fixture.Region, input.Fixture.Account, input.Fixture.Project, input.Fixture.ProjectNumber = "us-central1", "", "fixture-project", "123456789012"
		default:
			t.Fatal("unknown provider", provider)
		}
		before := records.StockPluginEvidence{
			Schema: 1, RunID: run, Scenario: records.StockPluginScenario, Provider: provider, Prefix: "enkv-test/" + run + "/stock-case", FixtureID: input.Fixture.FixtureID, CLISHA256: artifact.CLI.SHA256,
			Assertions: []string{"a0-created", "a1-pending-a", "b-same-epoch-reused", "missing-a-refused", "exact-a-retired", "b2-created", "b-retired-a1", "outputs-published", "cloud-output-values-equal", "manifest-complete", "reconstruction-canonical", "final-generation-retired", "post-exit-reader"},
			Generations: []records.StockPluginGeneration{
				{Phase: "a0-created", Epoch: 0, GenerationID: id(10), ResourceID: id(20), ResourceDigest: id(30), OriginOperationID: id(40), OriginAttemptID: id(50)},
				{Phase: "a1-pending-a", Epoch: 1, GenerationID: id(11), ResourceID: id(21), ResourceDigest: id(31), OriginOperationID: id(41), OriginAttemptID: id(51)},
				{Phase: "b2-created", Epoch: 2, GenerationID: id(12), ResourceID: id(22), ResourceDigest: id(32), OriginOperationID: id(42), OriginAttemptID: id(52)},
			},
			ProviderTokenIDs: []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)},
		}
		if provider == "aws" {
			before.Assertions = append(before.Assertions, "github-metadata-checked")
		}
		// Build identities come only from the real public artifact. Resource and
		// result contracts are independent nonzero fixture identities.
		for i, build := range []records.StockPluginBuild{artifact.GeneratorA, artifact.GeneratorA, artifact.GeneratorB} {
			facts, err := build.Metadata.GeneratorFacts()
			if err != nil {
				t.Fatal(err)
			}
			route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
			if err != nil {
				t.Fatal(err)
			}
			routeID, err := credentialroute.Identity(route)
			if err != nil {
				t.Fatal(err)
			}
			g := before.Generations[i]
			before.Creates = append(before.Creates, records.StockPluginCreate{Phase: g.Phase, OperationID: g.OriginOperationID, AttemptID: g.OriginAttemptID, GenerationID: g.GenerationID, ResourceID: g.ResourceID, ResourceDigest: g.ResourceDigest, DescriptorID: facts.DescriptorID.String(), ExecutorID: facts.ExecutorID.String(), CredentialRouteID: hex.EncodeToString(routeID[:]), ConfigContractID: facts.Descriptor.Generator.ConfigContractID.String(), ResourceContractID: id(60), ResultContractID: id(61)})
		}
		for i, support := range []int{0, 2, 2} {
			g, create := before.Generations[i], before.Creates[support]
			duty := records.StockPluginDuty{Phase: []string{"a1-pending-a", "b2-created", "final-generation-retired"}[i], DutyID: id(70 + i), ResourceID: g.ResourceID, DescriptorID: create.DescriptorID, ExecutorID: create.ExecutorID, CredentialRouteID: create.CredentialRouteID, ResultContractID: id(62), OriginalOperationID: g.OriginOperationID, OriginalAttemptID: g.OriginAttemptID}
			before.Duties = append(before.Duties, duty)
			before.Retirements = append(before.Retirements, records.StockPluginRetirement{Phase: []string{"exact-a-retired", "b-retired-a1", "final-generation-retired"}[i], DutyID: duty.DutyID, DeletionAcknowledgedCount: 1, InvalidationNotConfirmed: true, EffectInvalidationNotConfirmed: true})
		}
		targets := []struct{ service, contract, target string }{
			{"ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1", "arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture-"},
			{"github-actions/service/v1", "github-actions/target/v1", "repos/fixture/repository/actions/secrets/"},
			{"github-actions/service/v1", "github-actions/target/v1", "orgs/fixture/actions/secrets/"},
			{"github-actions/service/v1", "github-actions/target/v1", "repos/fixture/repository/environments/test/secrets/"},
		}
		if provider == "gcp" {
			targets = []struct{ service, contract, target string }{{"ENKV/OUTPUT/GCP-SECRET-MANAGER/v1", "ENKV/OUTPUT/GCP-SECRET-MANAGER/TARGET/v1", "projects/fixture-project/secrets/fixture-"}}
		}
		for scope, target := range targets {
			for entry, name := range []string{"TOKEN", "STATIC"} {
				row := records.StockPluginOutput{Coordinate: records.PublicOutputCoordinate{ServiceContractID: target.service, TargetContractID: target.contract, PhysicalTarget: target.target + name, CoordinateID: id(100 + 2*scope + entry), BindingID: id(110 + scope)}, Published: true, Deletion: "acknowledged", MetadataVerified: scope != 0}
				if scope == 0 {
					row.Instance, row.ValueEqual, row.Deletion = row.Coordinate.PhysicalTarget, true, "scheduled"
					if provider == "gcp" {
						row.Instance, row.Deletion = row.Instance+"/versions/1", "absent"
					}
				}
				before.Outputs = append(before.Outputs, row)
			}
		}
		before.ServiceVerifications = uint32(3 + len(before.Outputs))
		lastOutput := len(before.Outputs) - 1
		actors := map[string]string{"authority": "signer", "apply": "publisher", "consumer": "consumer", "reader": "reader", "cleanup": "cleaner"}
		joins := []records.PublicConfigurationWorkerJoin{
			{Worker: "writer", Nonce: strings.Repeat("b", 32), Role: "writer", Actor: "signer", InvocationSHA256: id(120), ResultSHA256: id(121), Started: true, Joined: true, Process: "passed"},
			{Worker: "fresh", Nonce: strings.Repeat("c", 32), Role: "fresh_after", Actor: "reader", InvocationSHA256: id(122), ResultSHA256: id(123), Started: true, Joined: true, Process: "passed"},
			{Worker: "cleanup", Nonce: strings.Repeat("d", 32), Role: "cleanup", Actor: "cleaner", InvocationSHA256: id(124), ResultSHA256: id(125), Started: true, Joined: true, Process: "passed"},
		}
		for i, command := range []struct {
			phase, role string
			exit        int
		}{
			{"init", "authority", 0}, {"set-secret", "authority", 0},
			{"a0-created", "apply", 0}, {"a1-pending-a", "apply", 3}, {"b-same-epoch-reused", "apply", 3}, {"missing-a-refused", "apply", 2}, {"exact-a-retired", "apply", 0}, {"b2-created", "apply", 3}, {"b-retired-a1", "apply", 0},
			{"prepare", "consumer", 0}, {"publish", "consumer", 0}, {"manifest", "consumer", 0}, {"remove-generated", "authority", 0}, {"final-generation-retired", "apply", 0}, {"post-exit-reader", "reader", 0},
		} {
			join := joins[0]
			if command.role == "reader" {
				join = joins[1]
			}
			before.Commands = append(before.Commands, records.StockPluginCommand{Ordinal: uint32(i), Worker: join.Worker, Nonce: join.Nonce, Role: command.role, Actor: actors[command.role], Phase: command.phase, Started: true, Joined: true, ExitCode: command.exit, ResultSHA256: id(130 + i)})
		}
		clone := func(v records.StockPluginEvidence) records.StockPluginEvidence {
			v.Assertions, v.Commands = slices.Clone(v.Assertions), slices.Clone(v.Commands)
			v.Generations, v.Creates = slices.Clone(v.Generations), slices.Clone(v.Creates)
			v.Duties, v.Retirements = slices.Clone(v.Duties), slices.Clone(v.Retirements)
			v.Outputs, v.ProviderTokenIDs = slices.Clone(v.Outputs), slices.Clone(v.ProviderTokenIDs)
			return v
		}
		complete := clone(before)
		complete.Assertions = append(complete.Assertions, "store-prefix-observed-empty")
		t.Run("encoded-index-reserves-terminal-and-diagnostics", func(t *testing.T) {
			maximum := clone(complete)
			coordinates := make([]records.PublicOutputCoordinate, len(maximum.Outputs))
			for i := range maximum.Outputs {
				coordinates[i] = maximum.Outputs[i].Coordinate
				coordinates[i].PhysicalTarget += strings.Repeat("<\x00", 32)
				maximum.Outputs[i].Instance = strings.Repeat("\x00", 512)
			}
			maximum.Prefix += strings.Repeat("<\x00", 32)
			maximum.Commands = make([]records.StockPluginCommand, records.MaximumStockPluginCommands)
			for i := range maximum.Commands {
				maximum.Commands[i] = records.StockPluginCommand{Ordinal: uint32(i), Worker: strings.Repeat("w", 96), Nonce: strings.Repeat("a", 32), Role: strings.Repeat("r", 96), Actor: strings.Repeat("a", 96), Phase: strings.Repeat("p", 96), ExitCode: -int(^uint(0)>>1) - 1, ResultSHA256: id(130), DiagnosticSHA256: id(131), DiagnosticBytes: ^uint32(0), DiagnosticStatus: strings.Repeat("s", 96)}
			}
			maximum.ServiceVerifications = records.MaximumStockPluginVerifications
			size, fits := records.StockPluginEvidenceReservationBytes(maximum, coordinates)
			if !fits || size <= 0 || size > records.MaximumStockPluginEvidenceBytes {
				t.Fatal("complete bounded index did not fit its reservation", size)
			}
			t.Logf("reserved maximum index bytes: %d", size)
			maximum.Prefix = strings.Repeat("x", records.MaximumStockPluginEvidenceBytes)
			if _, fits := records.StockPluginEvidenceReservationBytes(maximum, coordinates); fits {
				t.Fatal("oversized existing evidence was admitted")
			}
		})
		t.Run("before-cleanup", func(t *testing.T) {
			if err := before.ValidateBeforeCleanup(input); err != nil {
				t.Fatal("complete provider tuple refused cleanup admission", err)
			}
			if before.ValidateComplete(input) == nil {
				t.Fatal("missing prefix observation accepted as complete")
			}
		})
		t.Run("complete", func(t *testing.T) {
			if err := complete.ValidateComplete(input); err != nil {
				t.Fatal("exact final tuple refused", err)
			}
			if complete.ValidateBeforeCleanup(input) == nil {
				t.Fatal("final acknowledgement re-entered pre-cleanup admission")
			}
			if err := validateStockCommandJoins(complete, joins, actors); err != nil {
				t.Fatal("original joined workers refused", err)
			}
		})
		if provider == "aws" {
			t.Run("historical-retirements", func(t *testing.T) {
				proof := input
				proof.Fixture.Purpose = records.StockRetirementProofPurpose
				proof.Fixture.Bucket = "enkv-" + proof.Fixture.Account + "-pa-" + proof.Fixture.FixtureID
				observed := clone(complete)
				if observed.ValidateComplete(proof) == nil {
					t.Fatal("missing historical proof accepted")
				}
				for i := range observed.Retirements {
					observed.Retirements[i].CloseDigest = id(330 + i)
					observed.Retirements[i].ResultDigest = id(340 + i)
					observed.Retirements[i].ResultLength = 1024
				}
				if observed.ValidateComplete(proof) != nil || observed.ValidateComplete(input) == nil {
					t.Fatal("historical evidence is not bound to its profile")
				}
				for i := range observed.Retirements {
					damaged := clone(observed)
					damaged.Retirements[i].ResultLength = 0
					if damaged.ValidateComplete(proof) == nil {
						t.Fatal("one incomplete retirement accepted")
					}
				}
			})
		}
		t.Run("complete-with-diagnostic-reference", func(t *testing.T) {
			value := clone(complete)
			value.Commands[0].DiagnosticSHA256 = id(300)
			value.Commands[0].DiagnosticBytes = 123
			value.Commands[0].DiagnosticStatus = "observed"
			if err := value.ValidateComplete(input); err != nil {
				t.Fatal("complete paired diagnostic reference was refused", err)
			}
		})
		damages := []struct {
			name   string
			change func(*records.StockPluginEvidence)
		}{
			{"diagnostic-missing-digest", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticBytes, v.Commands[0].DiagnosticStatus = 123, "observed"
			}},
			{"diagnostic-missing-bytes", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticSHA256, v.Commands[0].DiagnosticStatus = id(300), "observed"
			}},
			{"diagnostic-missing-status", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticSHA256, v.Commands[0].DiagnosticBytes = id(300), 123
			}},
			{"diagnostic-invalid-digest", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticSHA256, v.Commands[0].DiagnosticBytes, v.Commands[0].DiagnosticStatus = "bad", 123, "observed"
			}},
			{"diagnostic-invalid-status", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticSHA256, v.Commands[0].DiagnosticBytes, v.Commands[0].DiagnosticStatus = id(300), 123, "unexpected"
			}},
			{"diagnostic-partial", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticSHA256, v.Commands[0].DiagnosticBytes, v.Commands[0].DiagnosticStatus = id(300), 123, "partial"
			}},
			{"diagnostic-write-failed", func(v *records.StockPluginEvidence) { v.Commands[0].DiagnosticStatus = "write-failed" }},
			{"diagnostic-oversized", func(v *records.StockPluginEvidence) {
				v.Commands[0].DiagnosticSHA256, v.Commands[0].DiagnosticBytes, v.Commands[0].DiagnosticStatus = id(300), records.MaximumStockPluginDiagnosticBytes+1, "observed"
			}},
			{"original-run", func(v *records.StockPluginEvidence) { v.RunID = strings.Repeat("e", 32) }},
			{"fixture", func(v *records.StockPluginEvidence) { v.FixtureID = strings.Repeat("f", 32) }},
			{"cli", func(v *records.StockPluginEvidence) { v.CLISHA256 = id(999) }},
			{"later-generation-epoch", func(v *records.StockPluginEvidence) { v.Generations[2].Epoch = 1 }},
			{"later-create-executor", func(v *records.StockPluginEvidence) { v.Creates[2].ExecutorID = v.Creates[0].ExecutorID }},
			{"later-create-route", func(v *records.StockPluginEvidence) { v.Creates[2].CredentialRouteID = v.Creates[0].CredentialRouteID }},
			{"later-create-origin", func(v *records.StockPluginEvidence) { v.Creates[2].AttemptID = v.Creates[1].AttemptID }},
			{"later-create-resource", func(v *records.StockPluginEvidence) { v.Creates[2].ResourceID = v.Creates[1].ResourceID }},
			{"later-create-contract", func(v *records.StockPluginEvidence) { v.Creates[2].ResultContractID = "" }},
			{"new-duty-executor", func(v *records.StockPluginEvidence) { v.Duties[1].ExecutorID = v.Duties[0].ExecutorID }},
			{"new-duty-route", func(v *records.StockPluginEvidence) { v.Duties[1].CredentialRouteID = v.Duties[0].CredentialRouteID }},
			{"later-duty-original-attempt", func(v *records.StockPluginEvidence) { v.Duties[2].OriginalAttemptID = v.Duties[1].OriginalAttemptID }},
			{"later-duty-resource", func(v *records.StockPluginEvidence) { v.Duties[2].ResourceID = v.Duties[1].ResourceID }},
			{"later-retirement-duty", func(v *records.StockPluginEvidence) { v.Retirements[2].DutyID = v.Duties[1].DutyID }},
			{"later-retirement-no-ack", func(v *records.StockPluginEvidence) { v.Retirements[2].DeletionAcknowledgedCount = 0 }},
			{"later-retirement-excess-ack", func(v *records.StockPluginEvidence) { v.Retirements[2].DeletionAcknowledgedCount = 2 }},
			{"later-retirement-unknown", func(v *records.StockPluginEvidence) { v.Retirements[2].UnknownCount = 1 }},
			{"later-retirement-invalidation-claim", func(v *records.StockPluginEvidence) { v.Retirements[2].InvalidationConfirmedCount = 1 }},
			{"later-retirement-warning", func(v *records.StockPluginEvidence) { v.Retirements[2].InvalidationNotConfirmed = false }},
			{"later-retirement-effect-warning", func(v *records.StockPluginEvidence) { v.Retirements[2].EffectInvalidationNotConfirmed = false }},
			{"cloud-instance", func(v *records.StockPluginEvidence) { v.Outputs[1].Instance = "" }},
			{"cloud-value", func(v *records.StockPluginEvidence) { v.Outputs[1].ValueEqual = false }},
			{"later-output-unknown-delete", func(v *records.StockPluginEvidence) { v.Outputs[lastOutput].Deletion = "unknown" }},
			{"later-output-scheduled-delete", func(v *records.StockPluginEvidence) { v.Outputs[lastOutput].Deletion = "scheduled" }},
			{"later-output-scope", func(v *records.StockPluginEvidence) {
				v.Outputs[lastOutput].Coordinate.ServiceContractID = "unknown/service/v1"
			}},
			{"duplicate-output", func(v *records.StockPluginEvidence) { v.Outputs[lastOutput] = v.Outputs[lastOutput-1] }},
			{"duplicate-provider-token", func(v *records.StockPluginEvidence) { v.ProviderTokenIDs[2] = v.ProviderTokenIDs[1] }},
			{"later-command-unjoined", func(v *records.StockPluginEvidence) { v.Commands[14].Joined = false }},
			{"later-command-result", func(v *records.StockPluginEvidence) { v.Commands[14].ResultSHA256 = "" }},
			{"missing-obligation", func(v *records.StockPluginEvidence) { v.Assertions = slices.Delete(v.Assertions, 10, 11) }},
			{"unknown-obligation", func(v *records.StockPluginEvidence) {
				v.Assertions = append(v.Assertions, "provider-globally-invalidated")
			}},
		}
		if provider == "aws" {
			damages = append(damages, struct {
				name   string
				change func(*records.StockPluginEvidence)
			}{"later-output-metadata", func(v *records.StockPluginEvidence) { v.Outputs[lastOutput].MetadataVerified = false }})
		} else {
			damages = append(damages, struct {
				name   string
				change func(*records.StockPluginEvidence)
			}{"unrelated-github-claim", func(v *records.StockPluginEvidence) { v.Assertions = append(v.Assertions, "github-metadata-checked") }})
		}
		for _, damage := range damages {
			t.Run("reject-"+damage.name, func(t *testing.T) {
				v := clone(before)
				damage.change(&v)
				if v.ValidateBeforeCleanup(input) == nil {
					t.Fatal("damaged provider tuple acquired cleanup admission")
				}
				v = clone(complete)
				damage.change(&v)
				if v.ValidateComplete(input) == nil {
					t.Fatal("damaged final tuple accepted")
				}
			})
		}
		for _, field := range []string{"worker", "nonce", "actor", "joined"} {
			t.Run("reject-original-join-"+field, func(t *testing.T) {
				v, workers := clone(complete), slices.Clone(joins)
				switch field {
				case "worker":
					v.Commands[14].Worker = "foreign"
				case "nonce":
					v.Commands[14].Nonce = workers[0].Nonce
				case "actor":
					v.Commands[14].Actor = actors["authority"]
				case "joined":
					workers[1].Joined = false
				}
				if validateStockCommandJoins(v, workers, actors) == nil {
					t.Fatal("substitute original worker facts accepted")
				}
			})
		}
	})
}
