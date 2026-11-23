package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/core/testsupport/nativeprocess"
)

var errPublicConfigurationEvidence = errors.New("public configuration private evidence retained: handoff unavailable")

type retainedPublicConfigurationFile struct {
	sha256   string
	bytes    uint64
	identity os.FileInfo
}

func publicConfigurationEvidenceRequired(parent runRecord, result scenarioResult) bool {
	return parent.Suite == "live" && result.Scenario != records.StockPluginScenario && recordedHasFixture(result.Scenario, catalog.FixturePublicConfiguration)
}

// Read the exact local image through one descriptor. Identity checks also reject
// an equal-byte replacement; the returned identity belongs to this read only.
func readPublicConfigurationFile(path string, limit uint64, mode os.FileMode) ([]byte, os.FileInfo, error) {
	return readPublicConfigurationFileContext(context.Background(), path, limit, mode)
}

func readPublicConfigurationFileContext(ctx context.Context, path string, limit uint64, mode os.FileMode) (body []byte, identity os.FileInfo, resultErr error) {
	if ctx == nil {
		return nil, nil, errPublicConfigurationEvidence
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, errors.Join(errPublicConfigurationEvidence, err)
	}
	if limit > max(records.MaximumJSONBytes, nativeprocess.MaxCaptureBytes) {
		return nil, nil, errPublicConfigurationEvidence
	}
	if _, err := records.SafePath(filepath.Dir(path), filepath.Base(path)); err != nil {
		return nil, nil, errPublicConfigurationEvidence
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != mode || before.Size() < 0 || uint64(before.Size()) > limit {
		return nil, nil, errPublicConfigurationEvidence
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, errPublicConfigurationEvidence
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			body, identity = nil, nil
			resultErr = errors.Join(resultErr, errPublicConfigurationEvidence, closeErr)
		}
	}()
	opened, err := file.Stat()
	if err != nil || !samePublicConfigurationFile(before, opened) {
		return nil, nil, errPublicConfigurationEvidence
	}
	// All callers supply fixed schema or capture bounds, never an input length.
	body, err = io.ReadAll(io.LimitReader(&stockCLIReader{ctx: ctx, reader: file}, int64(limit)+1))
	after, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if err := ctx.Err(); err != nil {
		return nil, nil, errors.Join(errPublicConfigurationEvidence, err)
	}
	if err != nil || statErr != nil || pathErr != nil || uint64(len(body)) > limit ||
		int64(len(body)) != before.Size() || !samePublicConfigurationFile(before, after) || !samePublicConfigurationFile(before, current) {
		return nil, nil, errPublicConfigurationEvidence
	}
	return body, before, nil
}

func samePublicConfigurationFile(first, second os.FileInfo) bool {
	return first != nil && second != nil && records.SameLocalFile(first, second) && first.Mode() == second.Mode() &&
		first.Size() == second.Size() && first.ModTime().Equal(second.ModTime())
}

func readRetainedEvidenceBytes(directory, relative string, limit uint64) ([]byte, os.FileInfo, error) {
	path, err := records.SafePath(directory, filepath.FromSlash(relative))
	if err != nil {
		return nil, nil, errPublicConfigurationEvidence
	}
	return readPublicConfigurationFile(path, limit, 0600)
}

func (s *runState) retainPublicConfigurationFile(relative string, body []byte) error {
	identity, err := s.retainEvidenceBytes(filepath.FromSlash(filepath.Dir(relative)), filepath.Base(relative), body)
	if err != nil {
		return errors.Join(errPublicConfigurationEvidence, err)
	}
	if s.publicConfigurationFiles == nil {
		s.publicConfigurationFiles = map[string]retainedPublicConfigurationFile{}
	}
	if _, present := s.publicConfigurationFiles[relative]; present {
		return errPublicConfigurationEvidence
	}
	s.publicConfigurationFiles[relative] = retainedPublicConfigurationFile{sha256: digestBytes(body), bytes: uint64(len(body)), identity: identity}
	return nil
}

// These are the existing worker output routes. A receipt cannot nominate a new
// input, state or output path merely by declaring a plausible worker name.
func publicConfigurationWorkerRoutes(result scenarioResult) ([]workerEvidence, []string, error) {
	var workers []workerEvidence
	var routes []string
	add := func(worker *workerEvidence, route string) {
		if worker != nil {
			workers, routes = append(workers, *worker), append(routes, route)
		}
	}
	add(result.Writer, filepath.Join("workers", "writer"))
	add(result.Rerun, filepath.Join("workers", "rerun"))
	for index := range result.Children {
		add(&result.Children[index], filepath.Join("workers", "writer", fmt.Sprintf("fresh-before-%d", index)))
	}
	for index := range result.PostExit {
		add(&result.PostExit[index], filepath.Join("workers", fmt.Sprintf("fresh-%04d-after", index)))
	}
	if len(result.CleanupAttempts) == 0 {
		add(result.CleanupWorker, filepath.Join("workers", "cleanup"))
	} else {
		for index, attempt := range result.CleanupAttempts {
			if attempt.Worker == nil || int(attempt.Ordinal) != index+1 {
				return nil, nil, errPublicConfigurationEvidence
			}
			route := filepath.Join("workers", "cleanup")
			if attempt.Ordinal > 1 {
				route = filepath.Join("workers", fmt.Sprintf("cleanup-retry-%d", attempt.Ordinal))
			}
			add(attempt.Worker, route)
		}
		if result.CleanupWorker == nil || !reflect.DeepEqual(*result.CleanupWorker, workers[len(workers)-1]) {
			return nil, nil, errPublicConfigurationEvidence
		}
	}
	if result.Writer == nil || result.CleanupWorker == nil {
		return nil, nil, errPublicConfigurationEvidence
	}
	return workers, routes, nil
}

func publicConfigurationEvidenceBinding(parent runRecord, result scenarioResult) (records.PublicConfigurationEvidenceBinding, error) {
	if !publicConfigurationEvidenceRequired(parent, result) || parent.Resolved == nil || parent.BuildClosure == nil ||
		parent.BuildClosure.PublicConfiguration == nil || parent.Resolved.RecoveryMode != parent.Schedule.RecoveryMode {
		return records.PublicConfigurationEvidenceBinding{}, errPublicConfigurationEvidence
	}
	if catalog.HasFixtureCapability(result.Scenario, catalog.FixtureGeneratedProcess) {
		g := parent.BuildClosure.PublicConfiguration
		if len(g.GeneratorSHA256) != 64 || g.GeneratorLength <= 0 || len(g.GeneratorManifest) != 64 {
			return records.PublicConfigurationEvidenceBinding{}, errPublicConfigurationEvidence
		}
	}
	identity, err := caseIdentitySHA256(parent)
	if err != nil {
		return records.PublicConfigurationEvidenceBinding{}, errPublicConfigurationEvidence
	}
	name, err := currentCaseDirectory(result.Entry)
	if err != nil {
		return records.PublicConfigurationEvidenceBinding{}, errPublicConfigurationEvidence
	}
	body, err := json.Marshal(parent.BuildClosure)
	if err != nil || len(body) > records.MaximumJSONBytes {
		return records.PublicConfigurationEvidenceBinding{}, errPublicConfigurationEvidence
	}
	return records.PublicConfigurationEvidenceBinding{
		RunID: parent.RunID, Scenario: result.Scenario, Provider: parent.Provider, RecoveryMode: parent.Resolved.RecoveryMode,
		Prefix: "enkv-test/" + parent.RunID + "/" + name, Source: parent.Source, CaseIdentitySHA256: identity,
		BuildClosureSHA256: digestBytes(body), OverlaySHA256: parent.BuildClosure.PublicConfiguration.OverlaySHA256,
	}, nil
}

func publicConfigurationWorkerJoins(original records.Invocation, result scenarioResult) ([]records.PublicConfigurationWorkerJoin, string, error) {
	state := original.StateDir
	workers, routes, err := publicConfigurationWorkerRoutes(result)
	if err != nil {
		return nil, "", err
	}
	var joins []records.PublicConfigurationWorkerJoin
	seen := map[string]bool{}
	finalCleanup := ""
	for index, evidence := range workers {
		if !evidence.Joined || seen[evidence.Worker] {
			return nil, "", errPublicConfigurationEvidence
		}
		seen[evidence.Worker] = true
		output, err := records.SafePath(state, routes[index])
		if err != nil {
			return nil, "", errPublicConfigurationEvidence
		}
		invBody, _, err := readPublicConfigurationFile(filepath.Join(output, "invocation.json"), records.MaximumJSONBytes, 0400)
		if err != nil {
			return nil, "", err
		}
		var inv records.Invocation
		decoder := json.NewDecoder(bytes.NewReader(invBody))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&inv) != nil || decoder.Decode(new(any)) != io.EOF || inv.Validate() != nil ||
			inv.OutputDir != output || inv.StateDir != state || inv.Worker != evidence.Worker || inv.Role != evidence.Role || inv.Scenario != result.Scenario {
			return nil, "", errPublicConfigurationEvidence
		}
		if index == 0 {
			originalBody, marshalErr := json.Marshal(original)
			if marshalErr != nil || !bytes.Equal(invBody, append(originalBody, '\n')) {
				return nil, "", errPublicConfigurationEvidence
			}
		}
		resultBody, _, err := readPublicConfigurationFile(filepath.Join(output, "worker.json"), records.MaximumJSONBytes, 0600)
		if err != nil {
			return nil, "", err
		}
		var raw records.WorkerResult
		decoder = json.NewDecoder(bytes.NewReader(resultBody))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&raw) != nil || decoder.Decode(new(any)) != io.EOF || raw.SchemaVersion != records.SchemaVersion ||
			raw.RunID != inv.RunID || raw.Scenario != inv.Scenario || raw.Worker != inv.Worker || raw.Role != inv.Role ||
			raw.Actor != evidence.Actor || raw.Outcome != evidence.Outcome && !(evidence.Outcome == "failed" && raw.Outcome == "incomplete") {
			return nil, "", errPublicConfigurationEvidence
		}
		assertions := records.InspectAssertions(inv, evidence.Process == "passed" || raw.Outcome == "passed")
		if evidence.Assertions == nil || !reflect.DeepEqual(*evidence.Assertions, assertions) {
			return nil, "", errPublicConfigurationEvidence
		}
		joins = append(joins, records.PublicConfigurationWorkerJoin{
			Worker: inv.Worker, Nonce: inv.Nonce, Role: inv.Role, Actor: raw.Actor,
			InvocationSHA256: digestBytes(invBody), ResultSHA256: digestBytes(resultBody),
			Started: evidence.Started, Joined: evidence.Joined, Process: evidence.Process,
		})
		if result.CleanupWorker != nil && evidence.Worker == result.CleanupWorker.Worker {
			finalCleanup = output
		}
	}
	if finalCleanup == "" {
		return nil, "", errPublicConfigurationEvidence
	}
	return joins, finalCleanup, nil
}

func (s *runState) verifyPublicConfigurationEvidence() error {
	if len(s.publicConfigurationFiles) != 0 && (s.privateOwner.verify() != nil || s.verifyEvidenceDirectories() != nil) {
		return errPublicConfigurationEvidence
	}
	for relative, owned := range s.publicConfigurationFiles {
		body, identity, err := readRetainedEvidenceBytes(s.directory, relative, owned.bytes)
		if err != nil || !samePublicConfigurationFile(owned.identity, identity) || digestBytes(body) != owned.sha256 {
			return errPublicConfigurationEvidence
		}
	}
	for _, result := range s.record.Scenarios {
		if result.Outcome == "passed" && result.Scenario == records.StockPluginScenario {
			ref := result.StockPluginEvidence
			if ref == nil {
				return errPublicConfigurationEvidence
			}
			owned, present := s.publicConfigurationFiles[ref.Path]
			if !present || owned.sha256 != ref.SHA256 || owned.bytes != ref.Bytes || readStockPluginEvidence(s.directory, s.record, result) != nil {
				return errPublicConfigurationEvidence
			}
			continue
		}
		if result.Outcome != "passed" || !publicConfigurationEvidenceRequired(s.record, result) {
			continue
		}
		if result.PublicConfigurationEvidence == nil {
			return errPublicConfigurationEvidence
		}
		owned, present := s.publicConfigurationFiles[result.PublicConfigurationEvidence.Path]
		if !present || owned.sha256 != result.PublicConfigurationEvidence.SHA256 || owned.bytes != result.PublicConfigurationEvidence.Bytes ||
			readPublicConfigurationEvidence(s.directory, s.record, result) != nil {
			return errPublicConfigurationEvidence
		}
	}
	return nil
}

func readPublicConfigurationEvidence(directory string, parent runRecord, result scenarioResult) error {
	if parent.RecoveryRunID != "" {
		if publicOutputRecoveryCase(result.Scenario) {
			return readPublicOutputRecoveryEvidence(directory, parent, result)
		}
		return readPublicConfigurationCleanupEvidence(directory, parent, result)
	}
	expected, err := publicConfigurationEvidenceBinding(parent, result)
	if err != nil || result.PublicConfigurationEvidence == nil || result.PublicConfigurationEvidence.Validate(result.Sequence) != nil {
		return errPublicConfigurationEvidence
	}
	ref := result.PublicConfigurationEvidence
	body, _, err := readRetainedEvidenceBytes(directory, ref.Path, records.MaximumPublicConfigurationManifestBytes)
	if err != nil || uint64(len(body)) != ref.Bytes || digestBytes(body) != ref.SHA256 {
		return errPublicConfigurationEvidence
	}
	manifest, err := records.ReadPublicConfigurationEvidenceManifestBytes(body, expected)
	if err != nil {
		return errPublicConfigurationEvidence
	}
	workers, _, err := publicConfigurationWorkerRoutes(result)
	if err != nil || len(manifest.Workers) != len(workers) {
		return errPublicConfigurationEvidence
	}
	for index, worker := range workers {
		join := manifest.Workers[index]
		if join.Worker != worker.Worker || join.Role != worker.Role || join.Actor != worker.Actor ||
			join.Started != worker.Started || join.Joined != worker.Joined || join.Process != worker.Process {
			return errPublicConfigurationEvidence
		}
	}
	expected.Workers = manifest.Workers
	base := filepath.Dir(ref.Path)
	snapshotBody, _, err := readRetainedEvidenceBytes(directory, filepath.ToSlash(filepath.Join(base, manifest.Snapshot.Path)), records.MaximumPublicConfigurationSnapshotBytes)
	if err != nil || uint64(len(snapshotBody)) != manifest.Snapshot.Bytes || digestBytes(snapshotBody) != manifest.Snapshot.SHA256 {
		return errPublicConfigurationEvidence
	}
	snapshot, err := records.ReadPublicConfigurationEvidenceSnapshotBytes(snapshotBody, expected)
	if err != nil || len(snapshot.Captures) != len(manifest.Captures) {
		return errPublicConfigurationEvidence
	}
	var generatorCaptures []nativeprocess.Capture
	for index, file := range manifest.Captures {
		receipt := snapshot.Captures[index]
		if file.Ordinal != receipt.Ordinal || file.Bytes != receipt.Bytes || file.SHA256 != receipt.SHA256 {
			return errPublicConfigurationEvidence
		}
		body, _, err := readRetainedEvidenceBytes(directory, filepath.ToSlash(filepath.Join(base, file.Path)), nativeprocess.MaxCaptureBytes)
		if err != nil || uint64(len(body)) != file.Bytes || digestBytes(body) != file.SHA256 {
			return errPublicConfigurationEvidence
		}
		capture, captureErr := nativeprocess.InspectCapture(body)
		if captureErr != nil || len(capture.Events) == 0 || capture.Events[len(capture.Events)-1].Code != receipt.ExitCode {
			return errPublicConfigurationEvidence
		}
		if snapshot.Generator == nil {
			for _, event := range capture.Events {
				if strings.HasPrefix(event.Kind, "generator-") {
					return errPublicConfigurationEvidence
				}
			}
		} else {
			for _, event := range capture.Events {
				if strings.HasPrefix(event.Kind, "generator-") && (receipt.ParentRole != "writer" || receipt.NativeKind != "cli") {
					return errPublicConfigurationEvidence
				}
			}
			generatorCaptures = append(generatorCaptures, capture)
		}
	}
	if snapshot.Generator != nil && snapshot.Generator.ValidateCaptures(generatorCaptures) != nil {
		return errPublicConfigurationEvidence
	}
	return nil
}

func (s *runState) retainPublicConfigurationEvidence(result *scenarioResult, participants *scenarioParticipants) error {
	if participants == nil || s.privateOwner.verify() != nil || participants.writer.RunID != s.record.RunID ||
		participants.writer.StateDir != participants.state || !scenarioCleanupPassed(*result) {
		return errPublicConfigurationEvidence
	}
	expected, err := publicConfigurationEvidenceBinding(s.record, *result)
	if err != nil || participants.input.RunID != expected.RunID || len(participants.input.Scenarios) != 1 ||
		participants.input.Scenarios[0] != expected.Scenario || participants.input.Prefix != expected.Prefix || participants.input.RecoveryMode != expected.RecoveryMode ||
		participants.input.PublicConfiguration == nil || !reflect.DeepEqual(participants.input.PublicConfiguration.Artifact.closure(), s.record.BuildClosure.PublicConfiguration) {
		return errPublicConfigurationEvidence
	}
	inputBody, _, inputErr := readPublicConfigurationFile(participants.writer.Input, records.MaximumJSONBytes, 0400)
	originalInput, marshalErr := json.Marshal(participants.input)
	if inputErr != nil || marshalErr != nil || !bytes.Equal(inputBody, append(originalInput, '\n')) {
		return errPublicConfigurationEvidence
	}
	name, err := currentCaseDirectory(result.Entry)
	if err != nil {
		return errPublicConfigurationEvidence
	}
	state, err := records.SafePath(s.private, name)
	if err != nil || state != participants.state {
		return errPublicConfigurationEvidence
	}
	joins, cleanupOutput, err := publicConfigurationWorkerJoins(participants.writer, *result)
	if err != nil {
		return err
	}
	expected.Workers = joins
	path := filepath.Join(cleanupOutput, "public-configuration-evidence.json")
	body, identity, err := readPublicConfigurationFile(path, records.MaximumPublicConfigurationSnapshotBytes, 0600)
	if err != nil {
		return err
	}
	snapshot, err := records.ReadPublicConfigurationEvidenceSnapshotBytes(body, expected)
	if err != nil || verifyOriginalPublicConfigurationEvidence(state, snapshot) != nil {
		return errPublicConfigurationEvidence
	}
	current, err := os.Lstat(path)
	if err != nil || !samePublicConfigurationFile(identity, current) {
		return errPublicConfigurationEvidence
	}
	base := filepath.Join("evidence", "public-configuration", fmt.Sprintf("%04d", result.Sequence))
	manifest := records.PublicConfigurationEvidenceManifest{
		Version: records.PublicConfigurationEvidenceVersion, RunID: expected.RunID, Scenario: expected.Scenario,
		Provider: expected.Provider, RecoveryMode: expected.RecoveryMode, Source: expected.Source,
		CaseIdentitySHA256: expected.CaseIdentitySHA256, BuildClosureSHA256: expected.BuildClosureSHA256,
		OverlaySHA256: expected.OverlaySHA256, Workers: joins,
		Snapshot: records.PublicConfigurationEvidenceFile{Kind: "snapshot", Ordinal: 0, Path: "ownership.json", SHA256: digestBytes(body), Bytes: uint64(len(body))},
	}
	if s.retainPublicConfigurationFile(filepath.ToSlash(filepath.Join(base, manifest.Snapshot.Path)), body) != nil {
		return errPublicConfigurationEvidence
	}
	for _, receipt := range snapshot.Captures {
		source, err := records.SafePath(state, filepath.FromSlash(receipt.SourceRelative))
		if err != nil {
			return errPublicConfigurationEvidence
		}
		captureBody, captureIdentity, err := readPublicConfigurationFile(source, nativeprocess.MaxCaptureBytes, 0600)
		if err != nil || uint64(len(captureBody)) != receipt.Bytes || digestBytes(captureBody) != receipt.SHA256 {
			return errPublicConfigurationEvidence
		}
		capture, sum, err := nativeprocess.ReadCaptureWithDigest(source)
		current, statErr := os.Lstat(source)
		if err != nil || statErr != nil || !samePublicConfigurationFile(captureIdentity, current) ||
			fmt.Sprintf("%x", sum) != receipt.SHA256 || len(capture.Events) == 0 || capture.Events[len(capture.Events)-1].Code != receipt.ExitCode {
			return errPublicConfigurationEvidence
		}
		file := records.PublicConfigurationEvidenceFile{Kind: "native-capture", Ordinal: receipt.Ordinal,
			Path: fmt.Sprintf("captures/%04d.jsonl", receipt.Ordinal), SHA256: receipt.SHA256, Bytes: receipt.Bytes}
		if s.retainPublicConfigurationFile(filepath.ToSlash(filepath.Join(base, file.Path)), captureBody) != nil {
			return errPublicConfigurationEvidence
		}
		manifest.Captures = append(manifest.Captures, file)
	}
	manifestBody, err := json.Marshal(manifest)
	if err != nil || len(manifestBody)+1 > records.MaximumPublicConfigurationManifestBytes {
		return errPublicConfigurationEvidence
	}
	manifestBody = append(manifestBody, '\n')
	if _, err := records.ReadPublicConfigurationEvidenceManifestBytes(manifestBody, expected); err != nil {
		return errPublicConfigurationEvidence
	}
	ref := &records.PublicConfigurationEvidenceRef{SchemaVersion: records.PublicConfigurationEvidenceVersion,
		Path: filepath.ToSlash(filepath.Join(base, "manifest.json")), SHA256: digestBytes(manifestBody), Bytes: uint64(len(manifestBody))}
	current, sourceErr := os.Lstat(path)
	if sourceErr != nil || !samePublicConfigurationFile(identity, current) || verifyOriginalPublicConfigurationEvidence(state, snapshot) != nil ||
		ref.Validate(result.Sequence) != nil || s.retainPublicConfigurationFile(ref.Path, manifestBody) != nil || s.privateOwner.verify() != nil {
		return errPublicConfigurationEvidence
	}
	// Publish the reference only after its complete exported set reopens. The
	// per-file identities remain private in the original coordinator owner.
	candidate := *result
	candidate.PublicConfigurationEvidence = ref
	if readPublicConfigurationEvidence(s.directory, s.record, candidate) != nil || s.verifyPublicConfigurationEvidence() != nil {
		return errPublicConfigurationEvidence
	}
	result.PublicConfigurationEvidence = ref
	return nil
}

func verifyOriginalPublicConfigurationEvidence(state string, snapshot records.PublicConfigurationEvidenceSnapshot) error {
	return verifyOriginalPublicConfigurationEvidenceAt(state, state, snapshot)
}

// Copies retain original path metadata. Reads use the physical evidence owner;
// comparisons continue to use the unchanged logical original StateDir.
func verifyOriginalPublicConfigurationEvidenceAt(state, originalState string, snapshot records.PublicConfigurationEvidenceSnapshot) error {
	if generated := snapshot.Generator; generated != nil {
		ledgerPath := filepath.Join(state, "generator-cleanup.json")
		body, _, err := readPublicConfigurationFile(ledgerPath, records.MaximumJSONBytes, 0600)
		if err != nil || digestBytes(body) != generated.OriginalLedgerSHA256 {
			return errPublicConfigurationEvidence
		}
		var original records.GeneratorFixtureLedger
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&original) != nil || decoder.Decode(new(any)) != io.EOF || original.SchemaVersion != 1 || original.RunID != snapshot.RunID || original.Provider != "cloudflare" || original.Account != generated.Account || !original.Clean() || !reflect.DeepEqual(original.Resources, generated.Resources) {
			return errPublicConfigurationEvidence
		}
		joinedBody, _, err := readPublicConfigurationFile(filepath.Join(state, "generator-writer-joined.json"), 4096, 0400)
		if err != nil || digestBytes(joinedBody) != generated.OriginalJoinedSHA256 {
			return errPublicConfigurationEvidence
		}
		var joined records.GeneratorFixtureJoined
		decoder = json.NewDecoder(bytes.NewReader(joinedBody))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&joined) != nil || decoder.Decode(new(any)) != io.EOF || joined != generated.WriterJoined || generated.Validate(snapshot.RunID, snapshot.Scenario) != nil {
			return errPublicConfigurationEvidence
		}
		fixturePath := filepath.Join(state, records.PublicGeneratorFixtureCleanupName)
		if generated.FixtureCleanup != nil {
			body, _, err := readPublicConfigurationFile(fixturePath, records.MaximumPublicGeneratorFixtureCleanupBytes, 0600)
			if err != nil || digestBytes(body) != generated.OriginalFixtureCleanupSHA256 {
				return errPublicConfigurationEvidence
			}
			original, err := records.ReadPublicGeneratorFixtureCleanupBytes(body, snapshot.RunID, snapshot.Scenario, generated.Account)
			if err != nil || !reflect.DeepEqual(original, *generated.FixtureCleanup) {
				return errPublicConfigurationEvidence
			}
		} else if _, err := os.Lstat(fixturePath); !errors.Is(err, os.ErrNotExist) {
			return errPublicConfigurationEvidence
		}
	}
	body, _, err := readPublicConfigurationFile(filepath.Join(state, "public-ownership.json"), records.MaximumJSONBytes, 0600)
	if err != nil || digestBytes(body) != snapshot.OriginalOwnershipSHA256 {
		return errPublicConfigurationEvidence
	}
	var ownership records.PublicConfigurationOwnership
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ownership) != nil || decoder.Decode(new(any)) != io.EOF || ownership.Version != 1 ||
		ownership.RunID != snapshot.RunID || ownership.Prefix != snapshot.Prefix || ownership.Binding != snapshot.Binding ||
		!ownership.PreflightEmpty || ownership.Source != filepath.Join(originalState, "public-source", "configuration.json") ||
		len(ownership.Captures) != len(snapshot.Captures) || !reflect.DeepEqual(ownership.Outputs, snapshot.Outputs) {
		return errPublicConfigurationEvidence
	}
	if ownership.Domain != "" {
		found := false
		for _, domain := range snapshot.Domains {
			found = found || fmt.Sprintf("%x", domain) == ownership.Domain
		}
		if !found {
			return errPublicConfigurationEvidence
		}
	}
	for index, registration := range ownership.Captures {
		receipt := snapshot.Captures[index]
		path, err := records.SafePath(state, filepath.FromSlash(receipt.SourceRelative))
		if err != nil || filepath.Base(path) != "capture.jsonl" || registration.Path != filepath.Join(originalState, filepath.FromSlash(receipt.SourceRelative)) || registration.Ordinal != receipt.Ordinal ||
			registration.ParentWorker != receipt.ParentWorker || registration.ParentNonce != receipt.ParentNonce ||
			registration.ParentRole != receipt.ParentRole || registration.Actor != receipt.Actor || registration.NativeKind != receipt.NativeKind ||
			registration.Complete != receipt.Complete || registration.ExitCode != receipt.ExitCode ||
			registration.SHA256 != receipt.SHA256 || registration.Bytes != receipt.Bytes {
			return errPublicConfigurationEvidence
		}
	}
	controlledPath := filepath.Join(state, "public-controlled-inventory.json")
	if snapshot.Controlled == nil {
		if ownership.ControlledInventory != "" {
			return errPublicConfigurationEvidence
		}
		for _, path := range []string{controlledPath, controlledPath + ".token-evidence.json"} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return errPublicConfigurationEvidence
			}
		}
	} else if ownership.ControlledInventory != filepath.Join(originalState, "public-controlled-inventory.json") || verifyOriginalPublicConfigurationInventory(controlledPath, snapshot.OriginalControlledSHA256, *snapshot.Controlled) != nil {
		return errPublicConfigurationEvidence
	}
	return verifyOriginalPublicConfigurationInventory(filepath.Join(state, "public-cleanup-inventory.json"), snapshot.OriginalCleanupSHA256, snapshot.Cleanup)
}

func verifyOriginalPublicConfigurationInventory(path, expectedSHA256 string, projection records.PublicConfigurationInventoryEvidence) error {
	body, _, err := readPublicConfigurationFile(path, records.MaximumJSONBytes, 0600)
	if err != nil || digestBytes(body) != expectedSHA256 || projection.TokenSource == nil {
		return errPublicConfigurationEvidence
	}
	sourceBody, _, err := readPublicConfigurationFile(path+".token-evidence.json", records.MaximumJSONBytes, 0600)
	if err != nil || digestBytes(sourceBody) != projection.OriginalTokenSourceSHA256 {
		return errPublicConfigurationEvidence
	}
	var source records.PublicConfigurationTokenSource
	decoder := json.NewDecoder(bytes.NewReader(sourceBody))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&source) != nil || decoder.Decode(new(any)) != io.EOF || source.Validate() != nil ||
		!reflect.DeepEqual(source, *projection.TokenSource) {
		return errPublicConfigurationEvidence
	}
	// The original worker qualifies the complete inventory-to-source projection
	// before it publishes the snapshot. This reader pins those original images;
	// it neither reimplements cleanup policy nor grants another delete.
	return nil
}
