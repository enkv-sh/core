package records

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

// full_only: false
func TestPublicOutputRecoveryPairRequiresCanonicalUnselectedOutputContracts(t *testing.T) {
	// Independently framed Binding/v2: cloud, config/service/settings, empty
	// policy, six action bits, and a zero target count.
	const source = `{"generated":"generated.json","outputs":{"destinations":{"cloud":{"plugin":null,"canonical":{"settings":{}}}}}}`
	const generated = `{"canonical_records":{"generators":{},"outputs":{"cloud":"AAIAAAAFY2xvdWQAAAA2AAAAEWZpeHR1cmUvY29uZmlnL3YxAAAAEmZpeHR1cmUvc2VydmljZS92MQAAAAJ7fQAAAAA/AAA="}}}`
	for _, change := range []struct{ name, file, before, after string }{
		{"none", "", "", ""},
		{"plugin", "source", `"plugin":null`, `"plugin":"local-available"`},
		{"missing-plugin", "source", `"plugin":null,`, ``},
		{"missing-binding", "generated", `"outputs":`, `"other":`},
		{"binding-name", "generated", `"cloud":`, `"other":`},
		{"malformed-binding", "generated", `AAIAAAAF`, `AAEAAAAF`},
		{"extra-source-field", "source", `"plugin":null`, `"plugin":null,"settings":{}`},
		{"duplicate-source-field", "source", `"plugin":null`, `"plugin":null,"plugin":null`},
		{"changed-settings", "source", `"settings":{}`, `"settings":{"name":"other"}`},
		{"missing-companion", "source", `"generated.json"`, `"other.json"`},
	} {
		t.Run(change.name, func(t *testing.T) {
			files := []PublicOutputRecoveryPairFile{{Path: "configuration.json", Data: []byte(source)}, {Path: "generated.json", Data: []byte(generated)}}
			if change.file != "" {
				at := 0
				if change.file == "generated" {
					at = 1
				}
				original := files[at].Data
				files[at].Data = bytes.Replace(original, []byte(change.before), []byte(change.after), 1)
				if bytes.Equal(original, files[at].Data) {
					t.Fatal("fixture mutation missed its field")
				}
			}
			pair := PublicOutputRecoveryPair{Files: files}
			contracts, err := pair.OutputContracts()
			if change.name == "none" {
				if err != nil || len(contracts) != 1 || contracts[0] != "fixture/config/v1" {
					t.Fatal("canonical pair lost its exact output contract", contracts, err)
				}
			} else if err == nil {
				t.Fatal("unselected canonical output contract accepted damaged pair")
			}
		})
	}
	pair := PublicOutputRecoveryPair{Files: []PublicOutputRecoveryPairFile{
		{Path: "configuration.json", Data: []byte(`{"generated":"generated.json","outputs":{"destinations":{}}}`)},
		{Path: "generated.json", Data: []byte(`{}`)},
	}}
	if contracts, err := pair.OutputContracts(); err != nil || contracts == nil || len(contracts) != 0 {
		t.Fatal("empty canonical output set was refused", contracts, err)
	}
}

func recoveryCoordinateID(domain contract.ID, service, target string) contract.ID {
	body := append([]byte("ENKV/PUBLICATION/COORDINATE/v3\x00"), domain[:]...)
	for _, value := range []string{service, target} {
		body = binary.BigEndian.AppendUint32(body, uint32(len(value)))
		body = append(body, value...)
	}
	return sha256.Sum256(body)
}

// Projection/v4 commits its 419-byte encoding: schema, six IDs, action, seven
// IDs. Owned-instance/v2 commits six IDs and one u32-length-prefixed resource.
func recoveryProjectionCommitment(p contract.PublicationProjection) contract.ID {
	body := append([]byte("ENKV/PUBLICATION/PROJECTION/v4\x00"), 0, 4)
	for _, id := range []contract.ID{p.DomainID, p.ConfigurationDigest, p.CoordinateID, p.BindingIncarnationID, p.EntryIncarnationID, p.TargetRowDigest} {
		body = append(body, id[:]...)
	}
	body = append(body, p.Action)
	for _, id := range []contract.ID{p.OwnedBirthAttemptID, p.UncertainCreateAttemptID, p.ExclusiveNamespaceDigest, p.ValueBasisDigest, p.PolicyDigest, p.RequestContractDigest, p.ActingRecipientID} {
		body = append(body, id[:]...)
	}
	return sha256.Sum256(body)
}

func recoveryAcknowledgedFixture() PublicOutputRecoveryDisposition {
	domain, binding, entry, incarnation, birthID, deleteID := contract.ID{1}, contract.ID{2}, contract.ID{3}, contract.ID{4}, contract.ID{5}, contract.ID{6}
	service, targetContract, target := "ENKV/OUTPUT/AWS-SECRETS-MANAGER/v1", "ENKV/OUTPUT/AWS-SECRETS-MANAGER/TARGET/v1", "arn:aws:secretsmanager:us-east-1:123456789012:secret:ENKV_ORIGINAL"
	id := recoveryCoordinateID(domain, service, target)
	projection := contract.PublicationProjection{Schema: 4, DomainID: domain, ConfigurationDigest: contract.ID{7}, CoordinateID: id, BindingIncarnationID: binding, EntryIncarnationID: entry,
		TargetRowDigest: contract.ID{8}, Action: contract.PublicationCreateWithValue, ValueBasisDigest: contract.ID{9}, RequestContractDigest: contract.ID{10}, ActingRecipientID: contract.ID{11}}
	resource := target + "-AbCd12"
	locator := resource + "?stage=AWSCURRENT"
	birth := contract.PublicationMarker{Schema: 5, DomainID: domain, OperationID: contract.ID{12}, AttemptID: birthID, CoordinateID: id, PublicationIncarnationID: incarnation, AdmissionOrdinal: 1,
		Projection: projection, ProjectionCommitment: recoveryProjectionCommitment(projection), AuthoritySubjectDigest: contract.ID{13}, ExecutorID: "executor", CredentialRouteID: "route",
		State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: contract.ID{14}, NormalizedStatus: 200, SafeResourceID: resource, ConsumerLocator: locator},
		BirthServiceContractID: service, BirthTargetContractID: targetContract}
	projection.Action, projection.OwnedBirthAttemptID, projection.ValueBasisDigest = contract.PublicationDeleteOwned, birthID, contract.ID{}
	deleted := contract.PublicationMarker{Schema: 5, DomainID: domain, OperationID: contract.ID{15}, AttemptID: deleteID, CoordinateID: id, PublicationIncarnationID: incarnation, AdmissionOrdinal: 2,
		Projection: projection, ProjectionCommitment: recoveryProjectionCommitment(projection), AuthoritySubjectDigest: contract.ID{13}, ExecutorID: "executor", CredentialRouteID: "route",
		State: contract.PublicationAcknowledged, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationRequestAcknowledged, ResponseContractDigest: contract.ID{16}, NormalizedStatus: 200}}
	body := []byte("ENKV/PUBLICATION/OWNED-INSTANCE/v2\x00")
	for _, value := range []contract.ID{domain, id, binding, entry, projection.TargetRowDigest, birthID} {
		body = append(body, value[:]...)
	}
	body = binary.BigEndian.AppendUint32(body, uint32(len(resource)))
	body = append(body, resource...)
	c := contract.PublicationCoordinate{Schema: 5, DomainID: domain, CoordinateID: id, ServiceContractID: service, CanonicalTarget: target, BindingState: contract.PublicationBindingRetired, OwnerState: contract.PublicationOwnerQualified,
		LastBindingIncarnationID: binding, LastEntryIncarnationID: entry, OwnedBirthAttemptID: birthID, OwnedInstanceDigest: sha256.Sum256(body), CurrentPublicationIncarnationID: incarnation, LastAdmissionOrdinal: 2,
		LastDeleteAckAttemptID: deleteID, LastDeleteAckIncarnationID: incarnation, LastDeleteAckOrdinal: 2, PossibleRemoteObject: 1, DeletionDestinationID: "aws-secrets-manager", DeletionConsumerLocator: locator,
		DeletionTargetContractID: targetContract, DeletionConfigContractID: "config/v1", DeletionCredentialRouteContractID: "route/v1", DeletionPayloadEncoding: contract.OutputEncodingRaw, DeletionTargetRowDigest: projection.TargetRowDigest}
	return PublicOutputRecoveryDisposition{Target: PublicOutputCoordinate{ServiceContractID: service, TargetContractID: targetContract, PhysicalTarget: target, CoordinateID: hex.EncodeToString(id[:]), BindingID: hex.EncodeToString(binding[:])}, Coordinate: c, Disposition: "deletion-acknowledged", Markers: []contract.PublicationMarker{birth, deleted}, Incarnations: []contract.ID{incarnation}}
}

// full_only: false
func TestPublicOutputRecoveryAcknowledgementRequiresExactCurrentOwnerAndOrder(t *testing.T) {
	for _, damage := range []string{"none", "cross-incarnation", "missing-delete", "missing-birth", "coordinate", "binding", "entry", "target-row", "birth-resource", "unknown", "late", "blocker", "remote-ceiling", "later-value-ack", "later-policy-ack", "extra-order", "reverse-order", "duplicate-marker"} {
		t.Run(damage, func(t *testing.T) {
			v := recoveryAcknowledgedFixture()
			switch damage {
			case "cross-incarnation":
				v.Markers[0].AdmissionOrdinal = 9
				v.Markers[1].PublicationIncarnationID = contract.ID{40}
				v.Markers[1].AdmissionOrdinal = 1
				v.Coordinate.CurrentPublicationIncarnationID = contract.ID{40}
				v.Coordinate.LastAdmissionOrdinal = 1
				v.Coordinate.LastDeleteAckIncarnationID = contract.ID{40}
				v.Coordinate.LastDeleteAckOrdinal = 1
				v.Incarnations = append(v.Incarnations, contract.ID{40})
			case "missing-delete":
				v.Markers = v.Markers[:1]
			case "missing-birth":
				v.Markers = v.Markers[1:]
			case "coordinate":
				v.Target.CoordinateID = strings.Repeat("f", 64)
			case "binding":
				v.Coordinate.LastBindingIncarnationID = contract.ID{40}
			case "entry":
				v.Coordinate.LastEntryIncarnationID = contract.ID{40}
			case "target-row":
				v.Coordinate.DeletionTargetRowDigest = contract.ID{40}
			case "birth-resource":
				v.Markers[0].Evidence.SafeResourceID = "other-instance"
			case "unknown":
				v.Markers[1].State = contract.PublicationUnknown
				v.Markers[1].Evidence.Class = contract.PublicationUnproved
			case "late":
				v.Coordinate.LateEffectRisk = 1
			case "blocker":
				v.Markers[1].BlockerCount = 1
				v.Markers[1].BlockerDigest = contract.ID{40}
			case "remote-ceiling":
				v.Coordinate.PossibleRemoteObject = 0
			case "later-value-ack", "later-policy-ack":
				c := &v.Coordinate
				c.CurrentPublicationIncarnationID = contract.ID{41}
				c.LastAdmissionOrdinal = 1
				v.Incarnations = append(v.Incarnations, c.CurrentPublicationIncarnationID)
				if damage == "later-value-ack" {
					c.LastValueAckAttemptID, c.LastValueDigest, c.LastValueAckIncarnationID, c.LastValueAckOrdinal = contract.ID{42}, contract.ID{43}, c.CurrentPublicationIncarnationID, 1
				} else {
					c.LastPolicyAckAttemptID, c.LastPolicyDigest, c.LastPolicyAckIncarnationID, c.LastPolicyAckOrdinal = contract.ID{42}, contract.ID{43}, c.CurrentPublicationIncarnationID, 1
				}
			case "extra-order":
				v.Incarnations = append([]contract.ID{{41}}, v.Incarnations...)
			case "reverse-order":
				v.Markers[0].AdmissionOrdinal = 3
			case "duplicate-marker":
				v.Markers = append(v.Markers, v.Markers[0])
			}
			if (v.Validate(v.Coordinate.DomainID, true, PublicOutputRecoveryInput{Provider: "aws", OriginalEntry: catalog.Entry{Scenario: "public-configuration.output-combined/output_combined"}}) == nil) != (damage == "none" || damage == "cross-incarnation") {
				t.Fatal("incomplete or superseded ACK acquired Store cleanup authority")
			}
		})
	}
}

func recoveryInputFixture(t *testing.T) PublicOutputRecoveryInput {
	t.Helper()
	return recoveryInputFixtureForScenario(t, "public-configuration.output-standalone/output_standalone")
}

func recoveryInputFixtureForScenario(t *testing.T, scenario string) PublicOutputRecoveryInput {
	t.Helper()
	r := PublicOutputRecoveryInput{Version: 1, OriginalRunID: strings.Repeat("1", 32), RecoveryRunID: strings.Repeat("2", 32), OriginalEntry: catalog.Entry{Scenario: scenario},
		Provider: "gcp", RecoveryMode: "disabled", Binding: strings.Repeat("3", 64), OriginalRunSHA256: strings.Repeat("4", 64), OriginalCaseSHA256: strings.Repeat("5", 64), OriginalInputSHA256: strings.Repeat("6", 64), OriginalBuildSHA256: strings.Repeat("7", 64), LimitsSHA256: strings.Repeat("8", 64), ProjectNumber: "123456789"}
	token, err := catalog.CaseDirectoryToken(r.OriginalEntry.Scenario)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "tests/live/runs")
	r.OriginalState = filepath.Join(base, r.OriginalRunID, "private", "0000-"+token)
	r.StateDir = filepath.Join(base, r.RecoveryRunID, "private", "0000-"+token, "state")
	r.Prefix = "enkv-test/" + r.OriginalRunID + "/" + filepath.Base(r.OriginalState)
	r.Source = filepath.Join(r.OriginalState, "public-source/configuration.json")
	r.Generated = filepath.Join(r.OriginalState, "public-source/.enkv/prod.generated.json")
	r.Outputs = &PublicOutputScopes{Repository: PublicOutputScope{Owner: "owner", Repository: "repository"}, Organization: PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101}}, Environment: PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"}}
	worker := PublicOutputRecoveryWorker{PublicConfigurationWorkerJoin: PublicConfigurationWorkerJoin{Worker: "original-writer", Nonce: strings.Repeat("a", 32), Role: "writer", Actor: "authority", Started: true, Joined: true, Process: "process_failed", InvocationSHA256: strings.Repeat("b", 64), ResultSHA256: strings.Repeat("c", 64)}, RunID: r.OriginalRunID, StateDir: r.OriginalState, OutputDir: filepath.Join(r.OriginalState, "workers/writer"), Input: filepath.Join(r.OriginalState, "input.json"), SourceMap: filepath.Join(r.OriginalState, "failure-sources.json")}
	r.Workers = []PublicOutputRecoveryWorker{worker}
	for _, path := range []string{r.Source, r.Generated, worker.Input, worker.SourceMap, filepath.Join(r.OriginalState, "public-ownership.json"), filepath.Join(worker.OutputDir, "invocation.json"), filepath.Join(worker.OutputDir, "worker.json"), filepath.Join(r.OriginalState, "public-command-1/capture.jsonl")} {
		body := []byte("{}\n")
		if filepath.Base(path) == "capture.jsonl" {
			body = []byte("{\"kind\":\"footer\"}\n")
		}
		if os.MkdirAll(filepath.Dir(path), 0700) != nil || os.WriteFile(path, body, 0600) != nil {
			t.Fatal("local protocol fixture unavailable")
		}
		sum := sha256.Sum256(body)
		r.Files = append(r.Files, PublicOutputRecoveryFile{Path: path, SHA256: hex.EncodeToString(sum[:]), Bytes: uint64(len(body)), Mode: 0600})
		if filepath.Base(path) == "capture.jsonl" {
			r.Captures = []PublicConfigurationCaptureRegistration{{Path: path, SHA256: hex.EncodeToString(sum[:]), Bytes: uint64(len(body)), Complete: true, ParentWorker: worker.Worker, ParentNonce: worker.Nonce, ParentRole: worker.Role, Actor: "authority", NativeKind: "cli"}}
		}
	}
	return r
}

// full_only: false
func TestPublicOutputRecoveryInputRetainsWholeOriginalSet(t *testing.T) {
	for _, damage := range []string{"none", "changed-file", "missing-file", "symlink", "mode", "same-owner", "wrong-sequence", "missing-capture", "foreign-parent", "ordinal"} {
		t.Run(damage, func(t *testing.T) {
			r := recoveryInputFixture(t)
			switch damage {
			case "changed-file":
				if os.WriteFile(r.Generated, []byte("changed"), 0600) != nil {
					t.Fatal("change failed")
				}
			case "missing-file":
				if os.Remove(r.Generated) != nil {
					t.Fatal("remove failed")
				}
			case "symlink":
				if os.Remove(r.Generated) != nil || os.Symlink(r.Source, r.Generated) != nil {
					t.Fatal("alias failed")
				}
			case "mode":
				if os.Chmod(r.Generated, 0644) != nil {
					t.Fatal("mode failed")
				}
			case "same-owner":
				r.StateDir = r.OriginalState
			case "wrong-sequence":
				r.OriginalEntry.Sequence = 1
			case "missing-capture":
				r.Captures = nil
			case "foreign-parent":
				r.Captures[0].ParentNonce = strings.Repeat("f", 32)
			case "ordinal":
				r.Captures[0].Ordinal = 1
			}
			if (r.VerifyFiles() == nil) != (damage == "none") {
				t.Fatal("original evidence damage crossed recovery intake")
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryMutationAllowanceKeepsExactCleanupCaseDebits(t *testing.T) {
	for _, damage := range []string{"none", "duplicate", "missing", "unmatched", "underflow", "create", "retire", "reset"} {
		t.Run(damage, func(t *testing.T) {
			r := recoveryInputFixture(t)
			r.Workers[0].Role = "cleanup"
			r.CleanupObjectsRemaining, r.CleanupObjectBytesRemaining = 4408, 390000000
			r.CleanupDebits = []PublicOutputRecoveryDebit{{RunID: r.OriginalRunID, Worker: r.Workers[0].Worker, Nonce: r.Workers[0].Nonce, Reserved: BudgetReservation{Objects: 184, ObjectBytes: 10000000}}}
			switch damage {
			case "duplicate":
				r.CleanupDebits = append(r.CleanupDebits, r.CleanupDebits[0])
			case "missing":
				r.CleanupDebits = nil
			case "unmatched":
				r.CleanupDebits[0].Nonce = strings.Repeat("f", 32)
			case "underflow":
				r.CleanupDebits[0].Reserved.Objects = 4593
			case "create":
				r.CleanupDebits[0].Reserved.GeneratorCreates = 1
			case "retire":
				r.CleanupDebits[0].Reserved.GeneratorRetires = 1
			case "reset":
				r.CleanupObjectsRemaining = 4592
			}
			if r.MutationAllowance(4592, 400000000) != (damage == "none") {
				t.Fatal("cleanup guard omitted, duplicated or reset an exact prior cleanup debit")
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryProofRequiresAllCurrentDispositions(t *testing.T) {
	r := recoveryInputFixture(t)
	for _, damage := range []string{"none", "missing", "extra", "duplicate", "active", "effect", "stage", "target", "late"} {
		t.Run(damage, func(t *testing.T) {
			v := recoveryProofFixture(r)
			switch damage {
			case "missing":
				v.Initial = v.Initial[:7]
				v.Final = v.Final[:7]
			case "extra":
				v.Initial = append(v.Initial, v.Initial[0])
				v.Final = append(v.Final, v.Final[0])
			case "duplicate":
				v.Initial[1] = v.Initial[0]
				v.Final[1] = v.Final[0]
			case "active":
				v.Final[0].Coordinate.BindingState = contract.PublicationBindingActive
				v.Final[0].Coordinate.ActiveBindingIncarnationID = v.Final[0].Coordinate.LastBindingIncarnationID
			case "effect":
				v.Final[0].Coordinate.LastAdmissionOrdinal = 1
			case "stage":
				v.Stages[5].Outcome = "entered"
			case "target":
				v.Final[0].Target.PhysicalTarget += "_OTHER"
			case "late":
				v.Final[0].Coordinate.LateEffectRisk = 1
			}
			if (v.Validate(r) == nil) != (damage == "none") {
				t.Fatal("incomplete current output disposition acquired Store cleanup authority")
			}
		})
	}
}

func recoveryProofFixture(r PublicOutputRecoveryInput) PublicOutputRecoveryProof {
	body, _ := json.Marshal(r)
	sum := sha256.Sum256(body)
	v := PublicOutputRecoveryProof{Version: 1, InputSHA256: hex.EncodeToString(sum[:]), Domain: contract.ID{1}, Revision: contract.ID{2}, Snapshot: contract.ID{3}, HeadSHA256: strings.Repeat("d", 64)}
	for _, name := range []string{"intake", "authenticated-discovery", "prepare-pair", "retire-bindings", "remaining-deletions", "current-disposition", "store-cleanup"} {
		v.Stages = append(v.Stages, PublicOutputRecoveryStage{Name: name, Outcome: "complete"})
	}
	rows := PublicOutputFixtureCoordinates(r.Provider, r.Region, r.Account, r.ProjectNumber, r.Prefix, r.Outputs, []string{"gcp-secret-manager", "github-repository", "github-organization", "github-environment"})
	for i, target := range rows {
		id := recoveryCoordinateID(v.Domain, target.ServiceContractID, target.PhysicalTarget)
		binding, entry, inc := contract.ID{byte(10 + i/2)}, contract.ID{byte(20 + i%2)}, contract.ID{byte(30 + i)}
		target.CoordinateID, target.BindingID = hex.EncodeToString(id[:]), hex.EncodeToString(binding[:])
		c := contract.PublicationCoordinate{Schema: 5, DomainID: v.Domain, CoordinateID: id, ServiceContractID: target.ServiceContractID, CanonicalTarget: target.PhysicalTarget, BindingState: contract.PublicationBindingRetired, LastBindingIncarnationID: binding, LastEntryIncarnationID: entry, CurrentPublicationIncarnationID: inc}
		row := PublicOutputRecoveryDisposition{Target: target, Coordinate: c, Disposition: "passive", Incarnations: []contract.ID{inc}}
		v.Initial = append(v.Initial, row)
		v.Final = append(v.Final, row)
	}
	v.Store = &PublicConfigurationInventoryEvidence{RunID: r.OriginalRunID, Prefix: r.Prefix, Binding: r.Binding, Domain: v.Domain, OriginalTokenSourceSHA256: strings.Repeat("e", 64), TokenSource: &PublicConfigurationTokenSource{Version: 1, RunID: r.OriginalRunID, Prefix: r.Prefix, Binding: r.Binding, Domain: v.Domain}}
	return v
}

func recoveryAcknowledgedForTarget(target PublicOutputCoordinate) PublicOutputRecoveryDisposition {
	v := recoveryAcknowledgedFixture()
	id := recoveryCoordinateID(v.Coordinate.DomainID, target.ServiceContractID, target.PhysicalTarget)
	target.CoordinateID, target.BindingID = hex.EncodeToString(id[:]), v.Target.BindingID
	v.Target = target
	c := &v.Coordinate
	c.CoordinateID, c.ServiceContractID, c.CanonicalTarget = id, target.ServiceContractID, target.PhysicalTarget
	c.DeletionTargetContractID = target.TargetContractID
	for i := range v.Markers {
		m := &v.Markers[i]
		m.CoordinateID, m.Projection.CoordinateID = id, id
		m.ProjectionCommitment = recoveryProjectionCommitment(m.Projection)
	}
	v.Markers[0].BirthServiceContractID, v.Markers[0].BirthTargetContractID = target.ServiceContractID, target.TargetContractID
	c.OwnedInstanceDigest, _ = contract.PublicationOwnedInstanceDigest(c.DomainID, id, c.LastBindingIncarnationID, c.LastEntryIncarnationID, c.DeletionTargetRowDigest, c.OwnedBirthAttemptID, v.Markers[0].Evidence.SafeResourceID)
	return v
}

// full_only: false
func TestPublicOutputRecoveryManifestProofRejectsGithubEffects(t *testing.T) {
	for _, scenario := range []string{"public-configuration.manifest/atomic_public_file", "public-configuration.output-standalone/output_standalone", "public-configuration.output-combined/output_combined"} {
		for _, disposition := range []string{"passive", "absent-no-effect", "remaining", "deletion-acknowledged"} {
			t.Run(scenario+"/"+disposition, func(t *testing.T) {
				r := recoveryInputFixtureForScenario(t, scenario)
				v := recoveryProofFixture(r)
				for i, row := range v.Initial {
					if row.Target.ServiceContractID != "github-actions/service/v1" {
						continue
					}
					if disposition == "absent-no-effect" {
						row.Target.BindingID = ""
						row.Coordinate, row.Incarnations, row.Disposition = contract.PublicationCoordinate{}, nil, disposition
						v.Initial[i], v.Final[i] = row, row
					} else if disposition != "passive" {
						ack := recoveryAcknowledgedForTarget(row.Target)
						v.Initial[i], v.Final[i] = ack, ack
						if disposition == "remaining" {
							initial := ack
							initial.Disposition, initial.Markers = "remaining", ack.Markers[:1]
							initial.Coordinate.LastDeleteAckAttemptID, initial.Coordinate.LastDeleteAckIncarnationID, initial.Coordinate.LastDeleteAckOrdinal = contract.ID{}, contract.ID{}, 0
							initial.Coordinate.LastAdmissionOrdinal = 1
							v.Initial[i] = initial
						}
					}
				}
				manifest := scenario == "public-configuration.manifest/atomic_public_file"
				want := !manifest || disposition == "passive" || disposition == "absent-no-effect"
				if (v.Validate(r) == nil) != want {
					t.Fatal("current proof changed the catalog's exact publication effect scope", disposition)
				}
			})
		}
	}
}

// full_only: false
func TestPublicOutputRecoveryCommandRequiresDurablePairAndStage(t *testing.T) {
	r := recoveryInputFixture(t)
	proof := recoveryProofFixture(r)
	prepared := PublicOutputRecoveryPair{Version: 1, Source: filepath.Join(r.StateDir, "public-source/configuration.json")}
	for _, file := range []struct{ path, data string }{
		{".enkv/cleanup.generated.json", "{}"},
		{"configuration.json", "{\"generated\":\".enkv/cleanup.generated.json\",\"entries\":{\"plain\":\"init.files/plain\"},\"outputs\":{\"destinations\":{\"original\":{}},\"routing\":{}}}"},
		{"init.files/plain", "retained value"},
	} {
		data := []byte(file.data)
		sum := sha256.Sum256(data)
		prepared.Files = append(prepared.Files, PublicOutputRecoveryPairFile{Path: file.path, SHA256: hex.EncodeToString(sum[:]), Bytes: uint64(len(data)), Mode: 0600, Data: data})
	}
	for _, damage := range []string{"none", "missing-pair", "missing-bytes", "wrong-hash", "escape", "mode", "oversize", "stage", "stage-binding", "args", "objects", "generator", "dependency", "non-output"} {
		t.Run(damage, func(t *testing.T) {
			pair := prepared
			pair.Files = append([]PublicOutputRecoveryPairFile(nil), prepared.Files...)
			data := []byte("{\"generated\":\".enkv/cleanup.generated.json\",\"entries\":{\"plain\":\"init.files/plain\"},\"outputs\":{\"destinations\":{},\"routing\":{}}}")
			sum := sha256.Sum256(data)
			pair.Files[1].Data, pair.Files[1].Bytes, pair.Files[1].SHA256 = data, uint64(len(data)), hex.EncodeToString(sum[:])
			command := PublicOutputRecoveryCommand{Version: 1, InputSHA256: proof.InputSHA256, Stage: "retire-bindings", Role: "apply", Args: []string{"apply", "--source", pair.Source, "--source-format", "json", "--json"}, Reservation: BudgetReservation{Requests: 1, BodyBytes: 1}, Pair: &pair}
			command.StageSHA256 = PublicOutputRecoveryStageBinding(command.InputSHA256, command.Stage)
			switch damage {
			case "missing-pair":
				command.Pair = nil
			case "missing-bytes":
				pair.Files[2].Data = nil
			case "wrong-hash":
				pair.Files[2].SHA256 = strings.Repeat("f", 64)
			case "escape":
				pair.Files[0].Path = "../outside"
			case "mode":
				pair.Files[0].Mode = 0444
			case "oversize":
				pair.Files[2].Data = make([]byte, 8<<20+1)
				pair.Files[2].Bytes = uint64(len(pair.Files[2].Data))
				sum := sha256.Sum256(pair.Files[2].Data)
				pair.Files[2].SHA256 = hex.EncodeToString(sum[:])
			case "stage":
				command.Stage = "authenticated-discovery"
			case "stage-binding":
				command.StageSHA256 = strings.Repeat("f", 64)
			case "args":
				command.Args[0] = "init"
			case "objects":
				command.Reservation.Objects = 1
			case "generator":
				command.Reservation.GeneratorCreates = 1
			case "dependency":
				data := []byte("different value")
				sum := sha256.Sum256(data)
				pair.Files[2].Data, pair.Files[2].Bytes, pair.Files[2].SHA256 = data, uint64(len(data)), hex.EncodeToString(sum[:])
			case "non-output":
				data := []byte("{\"generated\":\".enkv/cleanup.generated.json\",\"entries\":{},\"outputs\":{\"destinations\":{},\"routing\":{}}}")
				sum := sha256.Sum256(data)
				pair.Files[1].Data, pair.Files[1].Bytes, pair.Files[1].SHA256 = data, uint64(len(data)), hex.EncodeToString(sum[:])
			}
			valid := command.Validate(r, proof) == nil && command.Pair != nil && command.Pair.OutputsRemovedFrom(prepared)
			if valid != (damage == "none") {
				t.Fatal("command acquired authority without exact finite input bytes and stage ownership", damage)
			}
		})
	}
	for _, damage := range []string{"none", "store-entered", "inventory", "wrong-input", "missing-stage"} {
		t.Run("prior/"+damage, func(t *testing.T) {
			prior := proof
			prior.Stages = append([]PublicOutputRecoveryStage(nil), proof.Stages[:6]...)
			prior.Store = nil
			switch damage {
			case "store-entered":
				prior.Stages = append(prior.Stages, PublicOutputRecoveryStage{Name: "store-cleanup", Outcome: "entered"})
			case "inventory":
				prior.Store = proof.Store
			case "wrong-input":
				prior.InputSHA256 = strings.Repeat("f", 64)
			case "missing-stage":
				prior.Stages = prior.Stages[1:]
			}
			if prior.BeforeStore(r) != (damage == "none") {
				t.Fatal("prior direct Store history was discarded or inferred", damage)
			}
		})
	}
}
