package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"

	records "enkv.sh/core/internal/testrecords"
)

type stockPluginEvidenceManifest struct {
	Schema              uint16                                  `json:"schema"`
	RunID               string                                  `json:"run_id"`
	CaseIdentitySHA256  string                                  `json:"case_identity_sha256"`
	BuildClosureSHA256  string                                  `json:"build_closure_sha256"`
	Source              records.Source                          `json:"source"`
	Fixture             records.StockPluginFixture              `json:"fixture"`
	GrantSHA256         string                                  `json:"grant_sha256"`
	Grant               records.StockPluginGrant                `json:"grant"`
	PrefixCleanupSHA256 string                                  `json:"prefix_cleanup_sha256"`
	PrefixCleanup       records.StockPluginPrefixCleanup        `json:"prefix_cleanup"`
	Workers             []records.PublicConfigurationWorkerJoin `json:"workers"`
	Evidence            records.StockPluginEvidence             `json:"evidence"`
}

func (v stockPluginEvidenceManifest) validatePrefixCleanup(runID, prefix string, allowance *limits) error {
	if allowance == nil || !allowance.valid() || v.Grant.Validate() != nil || v.PrefixCleanup.Validate(v.Grant) != nil ||
		v.Grant.RunID != runID || v.Grant.Prefix != prefix || !reflect.DeepEqual(v.Grant.Fixture, v.Fixture) {
		return errPublicConfigurationEvidence
	}
	limitBody, limitErr := json.Marshal(allowance)
	grantBody, grantErr := json.Marshal(v.Grant)
	cleanupBody, cleanupErr := json.Marshal(v.PrefixCleanup)
	if limitErr != nil || grantErr != nil || cleanupErr != nil || v.Grant.LimitsSHA256 != digestBytes(limitBody) ||
		v.GrantSHA256 != digestBytes(append(grantBody, '\n')) || v.PrefixCleanupSHA256 != digestBytes(append(cleanupBody, '\n')) {
		return errPublicConfigurationEvidence
	}
	return nil
}

func stockPluginEvidencePath(sequence int) string {
	return fmt.Sprintf("evidence/stock-plugin/%04d/manifest.json", sequence)
}

func stockOutputDigest(evidence records.StockPluginEvidence) string {
	body, err := json.Marshal(evidence.Outputs)
	if err != nil {
		return ""
	}
	return digestBytes(body)
}

func stockScheduledOutputs(evidence records.StockPluginEvidence) uint32 {
	var scheduled uint32
	for _, row := range evidence.Outputs {
		if row.Deletion == "scheduled" {
			scheduled++
		}
	}
	return scheduled
}

func validateStockCommandJoins(evidence records.StockPluginEvidence, joins []records.PublicConfigurationWorkerJoin, actors map[string]string) error {
	if len(joins) != 3 {
		return errPublicConfigurationEvidence
	}
	byWorker := map[string]records.PublicConfigurationWorkerJoin{}
	nonces := map[string]bool{}
	for _, join := range joins {
		if !telemetryLabel.MatchString(join.Worker) || !hexString(join.Nonce, 32) || nonces[join.Nonce] || !join.Started || !join.Joined || join.Process != "passed" || !hexString(join.InvocationSHA256, 64) || !hexString(join.ResultSHA256, 64) || byWorker[join.Worker].Worker != "" {
			return errPublicConfigurationEvidence
		}
		byWorker[join.Worker] = join
		nonces[join.Nonce] = true
	}
	used := map[string]bool{}
	for _, command := range evidence.Commands {
		join, ok := byWorker[command.Worker]
		if !ok || command.Nonce != join.Nonce || command.Actor != actors[command.Role] {
			return errPublicConfigurationEvidence
		}
		used[command.Worker] = true
	}
	// Cleanup performs provider SDK teardown, not a fabricated CLI command.
	for _, join := range joins {
		if join.Role != "cleanup" && !used[join.Worker] {
			return errPublicConfigurationEvidence
		}
	}
	return nil
}

func readStockPluginGrant(path string) (records.StockPluginGrant, []byte, error) {
	body, _, err := readPublicConfigurationFile(path, records.MaximumJSONBytes, 0400)
	var grant records.StockPluginGrant
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&grant) != nil || decoder.Decode(new(any)) != io.EOF || grant.Validate() != nil {
		return records.StockPluginGrant{}, nil, errPublicConfigurationEvidence
	}
	return grant, body, nil
}

func (s *runState) retainStockPluginEvidence(result *scenarioResult, participants *scenarioParticipants) error {
	if result.Scenario != records.StockPluginScenario || participants == nil || participants.input.PublicConfiguration == nil || participants.input.PublicConfiguration.Stock == nil ||
		s.record.BuildClosure == nil || s.record.BuildClosure.StockPlugins == nil || s.privateOwner.verify() != nil || !scenarioCleanupPassed(*result) {
		return errPublicConfigurationEvidence
	}
	input := participants.input
	stock := *input.PublicConfiguration.Stock
	closure, err := stockPluginClosureFromArtifact(filepath.Join(s.private, "build"), stock.Artifact)
	if err != nil || !reflect.DeepEqual(closure, s.record.BuildClosure.StockPlugins) || !sameSource(stock.Artifact.Source, s.record.Source) || input.RunID != s.record.RunID || len(input.Scenarios) != 1 || input.Scenarios[0] != records.StockPluginScenario {
		return errPublicConfigurationEvidence
	}
	originalBody, _, err := readPublicConfigurationFile(participants.writer.Input, records.MaximumJSONBytes, 0400)
	encoded, marshalErr := json.Marshal(input)
	if err != nil || marshalErr != nil || !bytes.Equal(originalBody, append(encoded, '\n')) {
		return errPublicConfigurationEvidence
	}
	joins, _, err := publicConfigurationWorkerJoins(participants.writer, *result)
	if err != nil {
		return err
	}
	evidence, err := records.ReadStockPluginEvidence(filepath.Join(participants.state, "stock-plugin-evidence.json"))
	if err != nil || evidence.ValidateComplete(stock) != nil || evidence.RunID != input.RunID || evidence.Prefix != input.Prefix ||
		stockOutputDigest(evidence) != result.OutputsSHA256 || stockScheduledOutputs(evidence) != result.OutputScheduled || validateStockCommandJoins(evidence, joins, input.Participants) != nil {
		return errPublicConfigurationEvidence
	}
	grant, grantBody, err := readStockPluginGrant(filepath.Join(participants.state, "stock-plugin-grant.json"))
	limitsBody, limitsErr := json.Marshal(input.Limits)
	if err != nil || limitsErr != nil || !reflect.DeepEqual(grant.Fixture, stock.Fixture) || grant.RunID != input.RunID || grant.Prefix != input.Prefix || grant.LimitsSHA256 != digestBytes(limitsBody) {
		return errPublicConfigurationEvidence
	}
	cleanupBody, _, err := readPublicConfigurationFile(filepath.Join(participants.state, "stock-prefix-cleanup.json"), records.MaximumJSONBytes, 0600)
	var prefix records.StockPluginPrefixCleanup
	if err != nil || json.Unmarshal(cleanupBody, &prefix) != nil || prefix.Validate(grant) != nil {
		return errPublicConfigurationEvidence
	}
	identity, err := caseIdentitySHA256(s.record)
	closureBody, closureErr := json.Marshal(s.record.BuildClosure)
	if err != nil || closureErr != nil {
		return errPublicConfigurationEvidence
	}
	manifest := stockPluginEvidenceManifest{Schema: 1, RunID: s.record.RunID, CaseIdentitySHA256: identity, BuildClosureSHA256: digestBytes(closureBody), Source: s.record.Source, Fixture: stock.Fixture, GrantSHA256: digestBytes(grantBody), Grant: grant, PrefixCleanupSHA256: digestBytes(cleanupBody), PrefixCleanup: prefix, Workers: joins, Evidence: evidence}
	if manifest.validatePrefixCleanup(input.RunID, input.Prefix, input.Limits) != nil {
		return errPublicConfigurationEvidence
	}
	body, err := json.Marshal(manifest)
	body = append(body, '\n')
	if err != nil || len(body) > records.MaximumStockPluginEvidenceBytes || s.retainPublicConfigurationFile(stockPluginEvidencePath(result.Sequence), body) != nil {
		return errPublicConfigurationEvidence
	}
	result.StockPluginEvidence = &records.StockPluginEvidenceRef{SchemaVersion: 1, Path: stockPluginEvidencePath(result.Sequence), SHA256: digestBytes(body), Bytes: uint64(len(body))}
	return readStockPluginEvidence(s.directory, s.record, *result)
}

func readStockPluginEvidence(directory string, parent runRecord, result scenarioResult) error {
	ref := result.StockPluginEvidence
	if result.Scenario != records.StockPluginScenario || result.Sequence < 0 || ref == nil || ref.SchemaVersion != 1 || ref.Path != stockPluginEvidencePath(result.Sequence) || !hexString(ref.SHA256, 64) || ref.Bytes == 0 || ref.Bytes > records.MaximumStockPluginEvidenceBytes ||
		parent.BuildClosure == nil || parent.BuildClosure.StockPlugins == nil || parent.BuildClosure.PublicConfiguration != nil || parent.Resolved == nil {
		return errPublicConfigurationEvidence
	}
	body, _, err := readRetainedEvidenceBytes(directory, ref.Path, records.MaximumStockPluginEvidenceBytes)
	var manifest stockPluginEvidenceManifest
	if err != nil || uint64(len(body)) != ref.Bytes || digestBytes(body) != ref.SHA256 || json.Unmarshal(body, &manifest) != nil {
		return errPublicConfigurationEvidence
	}
	name, nameErr := currentCaseDirectory(result.Entry)
	prefix := "enkv-test/" + parent.RunID + "/" + name
	if nameErr != nil || manifest.validatePrefixCleanup(parent.RunID, prefix, parent.Limits) != nil || manifest.Evidence.Prefix != prefix {
		return errPublicConfigurationEvidence
	}
	canonical, err := json.Marshal(manifest)
	identity, identityErr := caseIdentitySHA256(parent)
	closureBody, closureErr := json.Marshal(parent.BuildClosure)
	if err != nil || identityErr != nil || closureErr != nil || !bytes.Equal(body, append(canonical, '\n')) || manifest.Schema != 1 || manifest.RunID != parent.RunID ||
		manifest.CaseIdentitySHA256 != identity || manifest.BuildClosureSHA256 != digestBytes(closureBody) || !sameSource(manifest.Source, parent.Source) || !hexString(manifest.GrantSHA256, 64) {
		return errPublicConfigurationEvidence
	}
	// Pure schema validation needs absolute paths, but does not read this
	// placeholder. Original private paths were validated during retention.
	artifact, err := stockPluginArtifactFromClosure(filepath.Join(string(filepath.Separator), "stock-acceptance-build"), parent.BuildClosure.StockPlugins)
	input := records.StockPluginAcceptanceInput{Fixture: manifest.Fixture, Artifact: artifact}
	if err != nil || !sameSource(artifact.Source, parent.Source) || manifest.Evidence.ValidateComplete(input) != nil || manifest.Evidence.RunID != parent.RunID || manifest.Evidence.Provider != parent.Provider ||
		stockOutputDigest(manifest.Evidence) != result.OutputsSHA256 || stockScheduledOutputs(manifest.Evidence) != result.OutputScheduled {
		return errPublicConfigurationEvidence
	}
	workers, _, err := publicConfigurationWorkerRoutes(result)
	if err != nil || len(workers) != len(manifest.Workers) {
		return errPublicConfigurationEvidence
	}
	for i, worker := range workers {
		join := manifest.Workers[i]
		if join.Worker != worker.Worker || join.Role != worker.Role || join.Actor != worker.Actor || join.Process != worker.Process || join.Started != worker.Started || join.Joined != worker.Joined {
			return errPublicConfigurationEvidence
		}
	}
	if err := validateStockCommandJoins(manifest.Evidence, manifest.Workers, parent.Resolved.RoleBindings); err != nil {
		return err
	}
	return nil
}

func (s *runState) stockCleanupEvidence(inv records.Invocation, raw *records.Cleanup) (records.StockPluginEvidence, error) {
	var input workerInput
	if raw == nil || raw.Outcome != "passed" || raw.Failure != nil || raw.HarnessFailure != nil || raw.RemainingOwnedObjects == nil || raw.UnknownEffects == nil || *raw.UnknownEffects != 0 ||
		records.ReadJSON(inv.Input, &input) != nil || input.PublicConfiguration == nil || input.PublicConfiguration.Stock == nil || input.RunID != s.record.RunID || input.Prefix == "" {
		return records.StockPluginEvidence{}, errors.New("stock cleanup evidence unavailable")
	}
	evidence, err := records.ReadStockPluginEvidence(filepath.Join(inv.StateDir, "stock-plugin-evidence.json"))
	if err != nil || evidence.ValidateComplete(*input.PublicConfiguration.Stock) != nil || evidence.RunID != input.RunID || evidence.Prefix != input.Prefix ||
		*raw.RemainingOwnedObjects != int64(stockScheduledOutputs(evidence)) {
		return records.StockPluginEvidence{}, errors.New("stock cleanup evidence refused")
	}
	grant, _, grantErr := readStockPluginGrant(filepath.Join(inv.StateDir, "stock-plugin-grant.json"))
	var prefix records.StockPluginPrefixCleanup
	limitsBody, limitsErr := json.Marshal(input.Limits)
	if grantErr != nil ||
		records.ReadJSON(filepath.Join(inv.StateDir, "stock-prefix-cleanup.json"), &prefix) != nil || prefix.Validate(grant) != nil ||
		grant.RunID != input.RunID || grant.Prefix != input.Prefix || !reflect.DeepEqual(grant.Fixture, input.PublicConfiguration.Stock.Fixture) ||
		limitsErr != nil || grant.LimitsSHA256 != digestBytes(limitsBody) {
		return records.StockPluginEvidence{}, errors.New("stock original prefix observation refused")
	}
	return evidence, nil
}
