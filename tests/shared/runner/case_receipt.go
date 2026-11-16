package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

// A case receipt is an immutable public leaf. Its path and digest in run.json
// make a later continuation refer to this exact terminal result, while the
// static identity digest avoids copying the full schedule into every leaf.
type caseReceiptRef struct {
	Sequence int    `json:"sequence"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

type nativeTuple struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

// This public link identifies a cleanup-only recovery without disclosing its
// private provider key or conditional delete token.
type cleanupRecoveryBasis struct {
	StockRecoveryClaimSHA256  string        `json:"stock_recovery_claim_sha256,omitempty"`
	OriginalRunID             string        `json:"original_run_id"`
	OriginalRunSHA256         string        `json:"original_run_sha256,omitempty"`
	OriginalCaseReceiptSHA256 string        `json:"original_case_receipt_sha256"`
	Entry                     catalog.Entry `json:"entry"`
	TargetIndex               uint32        `json:"target_index"`
	Decision                  string        `json:"decision"`
}

type caseReceipt struct {
	SchemaVersion  int            `json:"schema_version"`
	RunID          string         `json:"run_id"`
	IdentitySHA256 string         `json:"identity_sha256"`
	Entry          catalog.Entry  `json:"entry"`
	Fixture        catalog.Shape  `json:"fixture"`
	Result         scenarioResult `json:"result"`
}

type caseStaticIdentity struct {
	SchemaVersion         int                    `json:"schema_version"`
	RunID                 string                 `json:"run_id"`
	Native                nativeTuple            `json:"native"`
	StartedAt             time.Time              `json:"started_at"`
	Source                records.Source         `json:"source"`
	Suite                 string                 `json:"suite"`
	Provider              string                 `json:"provider"`
	Target                string                 `json:"target"`
	Profile               string                 `json:"profile"`
	CoverageScope         string                 `json:"coverage_scope"`
	Schedule              catalog.Schedule       `json:"schedule"`
	Resolved              *resolvedRequest       `json:"resolved_request,omitempty"`
	ActorIdentities       *actorIdentityEvidence `json:"actor_identities,omitempty"`
	Toolchain             string                 `json:"toolchain"`
	BuildClosure          *assemblyClosure       `json:"build_closure,omitempty"`
	Context               *runContext            `json:"context,omitempty"`
	Limits                *limits                `json:"limits,omitempty"`
	RecoveryRunID         string                 `json:"recovery_run_id,omitempty"`
	ContinuationRootRunID string                 `json:"continuation_root_run_id,omitempty"`
	CleanupRecoveryBasis  *cleanupRecoveryBasis  `json:"cleanup_recovery_basis,omitempty"`
}

func caseIdentitySHA256(parent runRecord) (string, error) {
	if !records.ValidRunID(parent.RunID) || parent.SchemaVersion != records.SchemaVersion ||
		parent.Suite != "live" && parent.Suite != "hermetic" || parent.Provider == "" ||
		parent.CoverageScope != parent.Suite+"_scenarios" || len(parent.Schedule.Entries) == 0 ||
		parent.Native.GOOS == "" || parent.Native.GOARCH == "" {
		return "", errors.New("case identity unavailable")
	}
	body, err := json.Marshal(caseStaticIdentityFor(parent))
	if err == nil {
		body, err = restoreCleanupLimits(body, parent.Limits, parent.historicalLimits)
	}
	if err != nil || len(body) > records.MaximumJSONBytes {
		return "", errors.New("case identity unavailable")
	}
	return digestBytes(body), nil
}

func caseStaticIdentityFor(parent runRecord) caseStaticIdentity {
	return caseStaticIdentity{
		SchemaVersion: parent.SchemaVersion, RunID: parent.RunID, Native: parent.Native, StartedAt: parent.StartedAt,
		Source: parent.Source, Suite: parent.Suite, Provider: parent.Provider, Target: parent.Target,
		Profile: parent.Profile, CoverageScope: parent.CoverageScope, Schedule: parent.Schedule,
		Resolved: parent.Resolved, ActorIdentities: parent.ActorIdentities, Toolchain: parent.Toolchain,
		BuildClosure: parent.BuildClosure, Context: parent.Context, Limits: parent.Limits,
		RecoveryRunID:         parent.RecoveryRunID,
		ContinuationRootRunID: parent.ContinuationRootRunID,
		CleanupRecoveryBasis:  parent.CleanupRecoveryBasis,
	}
}

func caseReceiptPath(sequence int) string {
	return filepath.Join("cases", fmt.Sprintf("%04d.json", sequence))
}

func (s *runState) writeCaseReceipt(result scenarioResult, identitySHA256 string) error {
	if !hexString(identitySHA256, sha256HexLength) || result.Outcome != "passed" && result.Outcome != "failed" ||
		result.Sequence < 0 || result.Sequence >= len(s.record.Schedule.Entries) ||
		result.Entry != s.record.Schedule.Entries[result.Sequence] ||
		len(s.record.CaseReceipts) >= len(s.record.Schedule.Entries) {
		return errors.New("terminal case receipt refused")
	}
	if result.StockPluginRecovery != nil {
		if validateStockRecoveryCase(s.record, result) != nil {
			return errPublicConfigurationEvidence
		}
	} else if result.StockPluginEvidence != nil || result.Outcome == "passed" && result.Scenario == records.StockPluginScenario {
		if s.verifyPublicConfigurationEvidence() != nil || readStockPluginEvidence(s.directory, s.record, result) != nil {
			return errPublicConfigurationEvidence
		}
	}
	if result.PublicConfigurationEvidence != nil || result.Outcome == "passed" && publicConfigurationEvidenceRequired(s.record, result) {
		if s.verifyPublicConfigurationEvidence() != nil || readPublicConfigurationEvidence(s.directory, s.record, result) != nil {
			return errPublicConfigurationEvidence
		}
	}
	shape, err := recordedFixture(result.Scenario, result.Members)
	if err != nil || !reflect.DeepEqual(shape, result.Fixture) {
		return errors.New("terminal case fixture refused")
	}
	leaf := caseReceipt{SchemaVersion: records.SchemaVersion, RunID: s.record.RunID,
		IdentitySHA256: identitySHA256, Entry: result.Entry, Fixture: result.Fixture, Result: result}
	body, err := json.Marshal(leaf)
	if err != nil || len(body)+1 > records.MaximumJSONBytes {
		return errors.New("terminal case receipt too large")
	}
	cases, err := records.SafePath(s.directory, "cases")
	if err != nil {
		return errors.New("terminal case directory refused")
	}
	if err := os.Mkdir(cases, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("terminal case directory unavailable")
	}
	info, err := os.Lstat(cases)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("terminal case directory refused")
	}
	relative := caseReceiptPath(result.Sequence)
	path, err := records.SafePath(s.directory, relative)
	if err != nil || records.WriteJSONExclusive(path, leaf, records.MaximumJSONBytes) != nil {
		return errors.New("terminal case receipt unavailable")
	}
	s.record.CaseReceipts = append(s.record.CaseReceipts, caseReceiptRef{
		Sequence: result.Sequence, Path: filepath.ToSlash(relative), SHA256: digestBytes(append(body, '\n')),
	})
	return nil
}

// validateCaseReceipt binds one immutable leaf to its original run record.
// directory is the original run directory, not the implementation root.
func validateCaseReceipt(directory string, parent runRecord, ref caseReceiptRef, expected catalog.Entry) (scenarioResult, error) {
	if len(parent.CaseReceipts) > len(parent.Schedule.Entries) {
		return scenarioResult{}, errors.New("case receipt refused")
	}
	matches := 0
	for _, linked := range parent.CaseReceipts {
		if linked == ref {
			matches++
		}
	}
	if matches != 1 {
		return scenarioResult{}, errors.New("case receipt refused")
	}
	identity, err := caseIdentitySHA256(parent)
	if err != nil {
		return scenarioResult{}, errors.New("case receipt refused")
	}
	for _, result := range parent.Scenarios {
		if result.Sequence == ref.Sequence {
			return validateCaseReceiptWithIdentity(directory, parent, ref, expected, identity, result)
		}
	}
	return scenarioResult{}, errors.New("case receipt refused")
}

func validateCaseReceiptWithIdentity(directory string, parent runRecord, ref caseReceiptRef, expected catalog.Entry, identity string, claimed scenarioResult) (scenarioResult, error) {
	refused := errors.New("case receipt refused")
	if ref.Sequence != expected.Sequence || ref.Sequence < 0 || ref.Sequence >= len(parent.Schedule.Entries) ||
		parent.Schedule.Entries[ref.Sequence] != expected || claimed.Entry != expected ||
		ref.Path != filepath.ToSlash(caseReceiptPath(ref.Sequence)) || !hexString(ref.SHA256, sha256HexLength) {
		return scenarioResult{}, refused
	}
	path, err := records.SafePath(directory, filepath.FromSlash(ref.Path))
	if err != nil {
		return scenarioResult{}, refused
	}
	body, err := readRecordBytes(path)
	if err != nil || len(body) > records.MaximumJSONBytes || digestBytes(body) != ref.SHA256 {
		return scenarioResult{}, refused
	}
	var leaf caseReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&leaf) != nil || decoder.Decode(new(any)) != io.EOF {
		return scenarioResult{}, refused
	}
	canonical, err := json.Marshal(leaf)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
		return scenarioResult{}, refused
	}
	if leaf.SchemaVersion != records.SchemaVersion || leaf.RunID != parent.RunID ||
		leaf.IdentitySHA256 != identity || leaf.Entry != expected || leaf.Result.Entry != expected ||
		leaf.Result.Outcome != "passed" && leaf.Result.Outcome != "failed" ||
		!reflect.DeepEqual(leaf.Fixture, leaf.Result.Fixture) ||
		!reflect.DeepEqual(leaf.Result, claimed) {
		return scenarioResult{}, refused
	}
	shape, err := recordedFixture(expected.Scenario, expected.Members)
	if err != nil || !reflect.DeepEqual(shape, leaf.Fixture) {
		return scenarioResult{}, refused
	}
	if recordedHasFixture(expected.Scenario, catalog.FixtureConfigurationRecovery) && leaf.Result.Outcome == "passed" && !reconstructionScenarioComplete(leaf.Result, parent) {
		return scenarioResult{}, refused
	}
	if leaf.Result.StockPluginRecovery != nil {
		if validateStockRecoveryCase(parent, leaf.Result) != nil {
			return scenarioResult{}, refused
		}
	} else if leaf.Result.StockPluginEvidence != nil || leaf.Result.Outcome == "passed" && leaf.Result.Scenario == records.StockPluginScenario {
		if readStockPluginEvidence(directory, parent, leaf.Result) != nil {
			return scenarioResult{}, refused
		}
	}
	if leaf.Result.PublicConfigurationEvidence != nil || leaf.Result.Outcome == "passed" && publicConfigurationEvidenceRequired(parent, leaf.Result) {
		if readPublicConfigurationEvidence(directory, parent, leaf.Result) != nil {
			return scenarioResult{}, refused
		}
	}
	return leaf.Result, nil
}

// validateCaseReceiptSet is the admission check for a claimed original case
// prefix. Older unlinked records stay readable, but cannot contribute to a
// continuation claim. A missing, duplicate, or incomplete leaf refuses it.
func validateCaseReceiptSet(directory string, parent runRecord) error {
	refused := errors.New("case receipt set refused")
	if len(parent.Scenarios) > len(parent.Schedule.Entries) || len(parent.CaseReceipts) != len(parent.Scenarios) {
		return refused
	}
	identity, err := caseIdentitySHA256(parent)
	if err != nil {
		return refused
	}
	cases, err := records.SafePath(directory, "cases")
	if err != nil {
		return refused
	}
	directoryHandle, err := os.Open(cases)
	if errors.Is(err, os.ErrNotExist) && len(parent.CaseReceipts) == 0 {
		return nil
	}
	if err != nil {
		return refused
	}
	info, statErr := directoryHandle.Stat()
	if statErr != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		directoryHandle.Close()
		return refused
	}
	files, readErr := directoryHandle.ReadDir(len(parent.Schedule.Entries) + 1)
	closeErr := directoryHandle.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(files) != len(parent.CaseReceipts) {
		return refused
	}
	seen := make([]bool, len(parent.Schedule.Entries))
	names := make(map[string]bool, len(parent.CaseReceipts))
	results := make(map[int]scenarioResult, len(parent.Scenarios))
	lastSequence := -1
	for _, result := range parent.Scenarios {
		if result.Sequence <= lastSequence || result.Sequence < 0 || result.Sequence >= len(parent.Schedule.Entries) ||
			result.Entry != parent.Schedule.Entries[result.Sequence] ||
			result.Outcome != "passed" && result.Outcome != "failed" {
			return refused
		}
		results[result.Sequence] = result
		lastSequence = result.Sequence
	}
	for index, ref := range parent.CaseReceipts {
		result, present := results[ref.Sequence]
		if !present || ref.Sequence != parent.Scenarios[index].Sequence || seen[ref.Sequence] {
			return refused
		}
		seen[ref.Sequence] = true
		names[filepath.Base(ref.Path)] = true
		if _, err := validateCaseReceiptWithIdentity(directory, parent, ref, parent.Schedule.Entries[ref.Sequence], identity, result); err != nil {
			return refused
		}
	}
	for _, file := range files {
		if file.IsDir() || file.Type()&os.ModeSymlink != 0 {
			return refused
		}
		if !names[file.Name()] {
			return refused
		}
	}
	return nil
}

func (s *runState) saveLiveCase(result scenarioResult, identitySHA256 string) error {
	if s.recovery == nil {
		return nil
	}
	return s.writeCaseReceipt(result, identitySHA256)
}
