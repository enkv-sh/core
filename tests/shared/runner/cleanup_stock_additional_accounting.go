package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	observer "enkv.sh/core/testsupport/nativeprocess"
	"enkv.sh/sdk/artifact/credentialroute"
)

type stockRecoveryDiagnosticFacts struct {
	File                    records.StockPluginFile
	Accounting              records.StockPluginRecoveryAdditionalAccounting
	Files                   []records.StockPluginRecoveryPinnedFile
	Reservation             records.BudgetReservation
	Elapsed                 time.Duration
	Commands, Verifications uint32
	Before, After           records.LiveLimits
	Fixture                 limits
}

type stockRecoveryReadProbe struct {
	Name                   string                   `json:"name"`
	Provider               string                   `json:"provider"`
	Actor                  string                   `json:"actor"`
	OriginalRun            string                   `json:"original_run"`
	FailedSuccessor        string                   `json:"failed_successor"`
	Context                observer.StandardContext `json:"context"`
	Operation              string                   `json:"operation"`
	CaptureOperation       string                   `json:"capture_operation"`
	CaptureRole            string                   `json:"capture_role"`
	KeySHA256              string                   `json:"key_sha256"`
	ForceAbsentCredentials bool                     `json:"force_absent_credentials"`
	CredentialRoutes       [][]byte                 `json:"credential_routes"`
	Args                   []string                 `json:"args"`
	Policy                 observer.Policy          `json:"policy"`
}

type stockRecoveryReadCompletion struct {
	Started        *bool
	Joined         *bool
	ExitCode       *int
	ElapsedNanos   *int64
	Deadline       *bool
	StdoutOverflow *bool
	StderrOverflow *bool
}

type stockRecoveryReadResult struct {
	Schema     string `json:"schema"`
	Operation  string `json:"operation"`
	ReadStatus *uint8 `json:"read_status"`
	Reason     *uint8 `json:"reason"`
}

type stockRecoveryReadRecordedResult struct {
	Result                    stockRecoveryReadResult
	Sent                      *uint32
	OriginalEvidenceUnchanged *bool
}

type stockRecoveryReadDebit struct {
	Requests       uint64 `json:"requests"`
	BodyBytes      uint64 `json:"body_bytes"`
	ElapsedSeconds uint64 `json:"elapsed_seconds"`
}

type stockRecoveryReadSettlement struct {
	Owner        string `json:"owner"`
	Kind         string `json:"kind"`
	Status       string `json:"status"`
	RecordedAt   string `json:"recorded_at"`
	PacketSHA256 string `json:"packet_sha256"`
	SourceSHA256 string `json:"temporary_source_sha256"`
	Probes       []struct {
		Name           string `json:"name"`
		Funding        string `json:"funding"`
		Requests       uint64 `json:"requests"`
		BodyBytes      uint64 `json:"body_bytes"`
		ElapsedSeconds uint64 `json:"elapsed_seconds"`
	} `json:"probes"`
	FromCorrection records.LiveLimits     `json:"from_correction_reserve"`
	Original       string                 `json:"stock_original_run"`
	Successor      string                 `json:"stock_successor_record"`
	Before         records.LiveLimits     `json:"stock_remaining_before"`
	Reservation    stockRecoveryReadDebit `json:"stock_reservation"`
	Fixture        struct {
		Requests uint64 `json:"cleanup_requests"`
		Bytes    uint64 `json:"cleanup_bytes"`
		Seconds  uint64 `json:"cleanup_seconds"`
	} `json:"stock_fixture_remaining_unchanged"`
	CommandsBefore         uint32                 `json:"stock_command_slots_before"`
	CommandsReserved       uint32                 `json:"stock_command_slots_reserved"`
	VerificationsBefore    uint32                 `json:"stock_verification_slots_before"`
	VerificationsReserved  uint32                 `json:"stock_verification_slots_reserved"`
	Review                 string                 `json:"review"`
	Scope                  string                 `json:"scope"`
	SettledAt              string                 `json:"settled_at"`
	ConsumedFromCorrection records.LiveLimits     `json:"consumed_from_correction"`
	Consumed               stockRecoveryReadDebit `json:"stock_consumed"`
	After                  records.LiveLimits     `json:"stock_remaining_after"`
	CommandsAfter          uint32                 `json:"stock_command_slots_after"`
	VerificationsAfter     uint32                 `json:"stock_verification_slots_after"`
	NativeTerminal         string                 `json:"native_terminal"`
	Results                []struct {
		Name       string                          `json:"name"`
		Directory  string                          `json:"directory"`
		Result     stockRecoveryReadRecordedResult `json:"result"`
		Completion stockRecoveryReadCompletion     `json:"completion"`
		Consumed   stockRecoveryReadDebit          `json:"consumed"`
	} `json:"diagnostic_results"`
	ReplayPermitted *bool `json:"replay_permitted"`
}

// This decoder owns only the retained read-diagnostic format. The caller must
// separately require its reviewed producer before granting historical recovery.
func stockRecoveryAdditionalDiagnostic(state string, input records.StockPluginRecoveryInput) (stockRecoveryDiagnosticFacts, error) {
	refused := errors.New("stock recovery additional diagnostic unavailable")
	var facts stockRecoveryDiagnosticFacts
	path, err := records.SafePath(state, records.StockPluginRecoveryAdditionalAccountingName)
	if err != nil {
		return facts, refused
	}
	facts.File, _, err = stockRecoveryFile(path)
	var prior records.StockPluginRecoveryInput
	if err != nil || records.ReadJSON(filepath.Join(state, "stock-recovery-successor-claim.json"), &prior) != nil || prior.Predecessor == nil || prior.PreAdmission != nil ||
		records.ReadStockPluginRecoveryAdditionalAccounting(path, &facts.Accounting) != nil || facts.Accounting.Validate(input.OriginalRunID, prior.RecoveryRunID, input.Accounting) != nil {
		return facts, refused
	}
	a := facts.Accounting
	bodies := map[string][]byte{}
	add := func(file records.StockPluginFile, empty bool) error {
		if previous, ok := bodies[file.Path]; ok {
			digest := sha256.Sum256(previous)
			if hex.EncodeToString(digest[:]) != file.SHA256 || uint64(len(previous)) != file.Length {
				return refused
			}
			return nil
		}
		pin, body, err := records.ReadStockPluginRecoveryPin(file, empty)
		if err != nil {
			return refused
		}
		facts.Files = append(facts.Files, pin)
		bodies[file.Path] = body
		return nil
	}
	for _, file := range append(a.Files(), facts.File) {
		if add(file, file == a.Stderr) != nil {
			return facts, refused
		}
	}
	decode := func(file records.StockPluginFile, value any) error {
		if jsonv2.Unmarshal(bodies[file.Path], value, jsonv2.RejectUnknownMembers(true)) != nil {
			return refused
		}
		return nil
	}
	var packet struct {
		OutputDirectory string `json:"output_directory"`
		References      []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  uint64 `json:"bytes"`
		} `json:"references"`
		Probes []stockRecoveryReadProbe `json:"probes"`
	}
	if decode(a.Packet, &packet) != nil || len(packet.References) == 0 || len(packet.References) > 32 || len(packet.Probes) == 0 || len(packet.Probes) > 3 || filepath.Join(packet.OutputDirectory, "stock-head") != filepath.Dir(a.Intent.Path) {
		return facts, refused
	}
	seen := map[string]bool{}
	for _, ref := range packet.References {
		if seen[ref.Path] || add(records.StockPluginFile{Path: ref.Path, SHA256: ref.SHA256, Length: ref.Bytes}, false) != nil {
			return facts, refused
		}
		seen[ref.Path] = true
	}
	var original workerInput
	body, err := readRecordBytes(input.OriginalInput.Path)
	if err != nil || decodeCleanupRecord(body, &original) != nil || original.PublicConfiguration == nil || original.PublicConfiguration.Stock == nil || original.RunID != input.OriginalRunID {
		return facts, refused
	}
	_, runs, _, err := records.PrivateOwner(state)
	if err != nil {
		return facts, refused
	}
	directory, err := records.ResolveRun(runs, prior.RecoveryRunID)
	if errors.Is(err, os.ErrNotExist) {
		directory, err = records.SafePath(runs, prior.RecoveryRunID)
	}
	if err != nil {
		return facts, refused
	}
	var inv records.Invocation
	if records.ReadJSON(filepath.Join(directory, "private", filepath.Base(state), "cleanup", "invocation.json"), &inv) != nil || inv.ValidateEvidence() != nil || inv.RunID != prior.RecoveryRunID || inv.StateDir != state {
		return facts, refused
	}
	for _, required := range input.Sources {
		if !slices.ContainsFunc(packet.References, func(ref struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  uint64 `json:"bytes"`
		}) bool {
			return ref.Path == required.Path && ref.SHA256 == required.SHA256 && ref.Bytes == required.Length
		}) {
			return facts, refused
		}
	}
	if !seen[filepath.Join(directory, "run.json")] || !seen[inv.Input] {
		return facts, refused
	}
	var intent struct {
		Probe                               stockRecoveryReadProbe
		BinarySHA256                        string
		ReservedRequests, ReservedBodyBytes *uint64
		MaximumSeconds                      *uint64
	}
	if decode(a.Intent, &intent) != nil || !hexString(intent.BinarySHA256, 64) || intent.BinarySHA256 == string(bytes.Repeat([]byte{'0'}, 64)) || intent.ReservedRequests == nil || *intent.ReservedRequests != 1 || intent.ReservedBodyBytes == nil || *intent.ReservedBodyBytes != 65537 || intent.MaximumSeconds == nil || *intent.MaximumSeconds != 120 {
		return facts, refused
	}
	probe := intent.Probe
	selected := 0
	seenProbe := map[string]bool{}
	for _, p := range packet.Probes {
		if seenProbe[p.Name] || !slices.Contains([]string{"recipient-object", "gcp-normal-public-key", "stock-head"}, p.Name) {
			return facts, refused
		}
		seenProbe[p.Name] = true
		if p.Name == "stock-head" {
			if !reflect.DeepEqual(p, probe) {
				return facts, refused
			}
			selected++
		}
	}
	fixture := original.PublicConfiguration.Stock.Fixture
	expectedContext := standardContext(original.PublicConfiguration.Actors["apply"])
	expectedContext.Home = filepath.Join(inv.OutputDir, "stock-homes", inv.Worker, "apply")
	key := sha256.Sum256([]byte(original.Prefix + "/HEAD"))
	expectedPolicy := observer.Policy{Version: 1, Bucket: fixture.Bucket, Prefix: original.Prefix, MaxRequests: 1, MaxBytes: 65537, NoKMS: true, ExpectedSourceKind: expectedContext.Mode, RequireStandardSource: true}
	if selected != 1 || probe.Provider != "aws" || fixture.Provider != "aws" || probe.Actor != "apply" || probe.OriginalRun != input.OriginalRunID || probe.FailedSuccessor != prior.RecoveryRunID ||
		probe.Context != expectedContext || probe.Context.Validate("aws") != nil || probe.Operation != "aws-candidate-head" || probe.CaptureOperation != "head-read" || probe.CaptureRole != "" || probe.KeySHA256 != hex.EncodeToString(key[:]) || !probe.ForceAbsentCredentials ||
		!reflect.DeepEqual(probe.Policy, expectedPolicy) || !slices.Equal(probe.Args, []string{"--probe-read-transport", "--operation", "aws-candidate-head", "--region", fixture.Region, "--bucket", fixture.Bucket, "--prefix", original.Prefix, "--expected-owner", fixture.Account}) {
		return facts, refused
	}
	for _, route := range probe.CredentialRoutes {
		decoded, err := credentialroute.Decode(route)
		if err != nil || len(decoded.Names) != 1 {
			return facts, refused
		}
	}
	var policy observer.Policy
	expectedPolicy.RecordPath = a.Capture.Path
	if decode(a.Policy, &policy) != nil || !reflect.DeepEqual(policy, expectedPolicy) {
		return facts, refused
	}
	for name, file := range map[string]records.StockPluginFile{"completion.json": a.Completion, "result.json": a.Result, "capture.jsonl": a.Capture, "stdout.json": a.Stdout, "stderr.bin": a.Stderr, "policy.json": a.Policy} {
		if file.Path != filepath.Join(filepath.Dir(a.Intent.Path), name) {
			return facts, refused
		}
	}
	var completion stockRecoveryReadCompletion
	if decode(a.Completion, &completion) != nil || completion.Started == nil || !*completion.Started || completion.Joined == nil || !*completion.Joined || completion.ExitCode == nil || *completion.ExitCode != 0 || completion.ElapsedNanos == nil || *completion.ElapsedNanos <= 0 || *completion.ElapsedNanos > int64(126*time.Second) {
		return facts, refused
	}
	for _, flag := range []*bool{completion.Deadline, completion.StdoutOverflow, completion.StderrOverflow} {
		if flag == nil || *flag {
			return facts, refused
		}
	}
	var stdout stockRecoveryReadResult
	var result stockRecoveryReadRecordedResult
	if decode(a.Stdout, &stdout) != nil || decode(a.Result, &result) != nil || stdout.Schema != "ReadTransportDiagnostic/v1" || stdout.Operation != "aws-candidate-head" || stdout.ReadStatus == nil || stdout.Reason == nil ||
		!reflect.DeepEqual(stdout, result.Result) || result.Sent == nil || *result.Sent > 1 || result.OriginalEvidenceUnchanged == nil || !*result.OriginalEvidenceUnchanged || len(bodies[a.Stderr.Path]) != 0 {
		return facts, refused
	}
	capture, err := observer.ReadCapture(a.Capture.Path)
	if err != nil {
		return facts, refused
	}
	// The exact retained stock read has no HTTP events. This only closes this
	// diagnostic's recording; it says nothing about the earlier failed cleanup.
	if *result.Sent != 0 || len(capture.Events) != 1 || capture.Events[0].Kind != "footer" || capture.Events[0].Code != 0 || *stdout.ReadStatus != uint8(contract.ReadUnavailable) || *stdout.Reason != uint8(contract.ReasonAccess) {
		return facts, refused
	}
	if validateStockReadDiagnosticTerminal(a, bodies) != nil {
		return facts, refused
	}
	var settlement stockRecoveryReadSettlement
	if decode(a.Settlement, &settlement) != nil || settlement.Owner != "read-transport-live" || settlement.Status != "settled" || settlement.Original != input.OriginalRunID || settlement.Successor != prior.RecoveryRunID || settlement.PacketSHA256 != a.Packet.SHA256 || settlement.SourceSHA256 != a.SourceArchive.SHA256 || settlement.NativeTerminal != a.Terminal.Path || settlement.ReplayPermitted == nil || *settlement.ReplayPermitted {
		return facts, refused
	}
	seconds := elapsedSeconds(time.Duration(*completion.ElapsedNanos))
	wantDebit := stockRecoveryReadDebit{Requests: 1, BodyBytes: 65537, ElapsedSeconds: seconds}
	if settlement.Reservation != (stockRecoveryReadDebit{Requests: 1, BodyBytes: 65537, ElapsedSeconds: 126}) || settlement.Consumed != wantDebit ||
		settlement.CommandsReserved != 1 || settlement.VerificationsReserved != 1 || settlement.CommandsBefore != prior.PriorCommands+1 || settlement.VerificationsBefore != prior.PriorVerifications || settlement.CommandsAfter != settlement.CommandsBefore+1 || settlement.VerificationsAfter != settlement.VerificationsBefore+1 {
		return facts, refused
	}
	matched := 0
	for _, row := range settlement.Results {
		if row.Name == "stock-head" {
			if row.Directory != filepath.Dir(a.Intent.Path) || !reflect.DeepEqual(row.Completion, completion) || !reflect.DeepEqual(row.Result, result) || row.Consumed != wantDebit {
				return facts, refused
			}
			matched++
		}
	}
	if matched != 1 {
		return facts, refused
	}
	remaining := limits(settlement.Before)
	reservation := records.BudgetReservation{Requests: 1, BodyBytes: 65537}
	elapsed := time.Duration(seconds) * time.Second
	if debitBudget(&remaining, &reservation, &records.BudgetReservation{}, elapsed, 0) != nil || records.LiveLimits(remaining) != settlement.After {
		return facts, refused
	}
	facts.Reservation, facts.Elapsed, facts.Commands, facts.Verifications = reservation, elapsed, 1, 1
	facts.Before, facts.After = settlement.Before, settlement.After
	facts.Fixture.CleanupRequests, facts.Fixture.CleanupBytes, facts.Fixture.CleanupSeconds = settlement.Fixture.Requests, settlement.Fixture.Bytes, settlement.Fixture.Seconds
	return facts, nil
}

func validateStockReadDiagnosticTerminal(a records.StockPluginRecoveryAdditionalAccounting, bodies map[string][]byte) error {
	refused := errors.New("stock read diagnostic native completion unavailable")
	decode := func(file records.StockPluginFile, v any) bool {
		return jsonv2.Unmarshal(bodies[file.Path], v, jsonv2.RejectUnknownMembers(true)) == nil
	}
	var terminal struct {
		Type     string               `json:"type"`
		Step     string               `json:"step"`
		Activity string               `json:"activity"`
		Outcome  string               `json:"outcome"`
		Ordinary ordinaryStepEvidence `json:"ordinary"`
	}
	const owner, pkg, parent = "compositions/full/testsupport/nativeprocess", "enkv.sh/compositions/full/testsupport/nativeprocess", "TestRetainedReadTransportDiagnostic"
	if !decode(a.Terminal, &terminal) || terminal.Type != "test_result" || terminal.Step != "retained-read-diagnostics" || terminal.Activity != "unit" || terminal.Outcome != "passed" || !validOrdinaryFocusedEvidence(terminal.Ordinary) {
		return refused
	}
	e := terminal.Ordinary
	if e.Profile != "full" || e.Race == nil || *e.Race || e.RaceOptions != "" || e.Focus == nil || e.Focus.Package != pkg || e.Focus.Artifact != owner || !slices.Equal(e.Focus.Tests, []string{parent}) || e.Diagnostics == nil || e.Diagnostics.Preparation != "passed" || len(e.Diagnostics.Commands) != 2 {
		return refused
	}
	for i, c := range e.Diagnostics.Commands {
		phase := "test"
		if i == 1 {
			phase = "conversion"
		}
		if c.Phase != phase || c.Scope != pkg || !c.Started || !c.Joined || c.Process != "passed" || c.Events != "valid" || c.ToolCleanup != "not_required" || c.WallSeconds == nil || *c.WallSeconds <= 0 || math.IsInf(*c.WallSeconds, 0) || c.RaceObservation != "not_observed" || i == 0 && c.RequestedNode != "passed" {
			return refused
		}
	}
	for _, name := range []string{parent, parent + "/stock-head"} {
		count := 0
		for _, row := range e.Tests {
			if row.Package == pkg && row.Name == name && row.Outcome == "pass" {
				count++
			}
		}
		if count != 1 {
			return refused
		}
	}
	var provenance struct {
		Source       string `json:"source"`
		SourceBytes  uint64 `json:"source_bytes"`
		SourceSHA256 string `json:"source_sha256"`
		ExitCode     *int   `json:"supervisor_exit_code"`
		Events       []struct {
			Path    string `json:"path"`
			Line    uint64 `json:"line_1_based"`
			Start   uint64 `json:"byte_start"`
			End     uint64 `json:"byte_end"`
			Bytes   uint64 `json:"bytes"`
			SHA256  string `json:"sha256"`
			Step    string `json:"step"`
			Outcome string `json:"outcome"`
		} `json:"events"`
	}
	if !decode(a.TerminalProvenance, &provenance) || provenance.Source != a.TerminalLog.Path || provenance.SourceBytes != a.TerminalLog.Length || provenance.SourceSHA256 != a.TerminalLog.SHA256 || provenance.ExitCode == nil || *provenance.ExitCode != 0 || len(provenance.Events) != 1 {
		return refused
	}
	p, log := provenance.Events[0], bodies[a.TerminalLog.Path]
	if p.Path != a.Terminal.Path || p.Start > p.End || p.End > uint64(len(log)) || p.End-p.Start != a.Terminal.Length || p.Bytes != a.Terminal.Length || p.SHA256 != a.Terminal.SHA256 || p.Step != terminal.Step || p.Outcome != "passed" || p.Line != uint64(bytes.Count(log[:p.Start], []byte{'\n'})+1) || !bytes.Equal(log[p.Start:p.End], bodies[a.Terminal.Path]) {
		return refused
	}
	var timing struct {
		Kind     string    `json:"kind"`
		Started  time.Time `json:"started_at"`
		Finished time.Time `json:"finished_at"`
		Elapsed  float64   `json:"elapsed_seconds"`
		ExitCode *int      `json:"exit_code"`
	}
	if !decode(a.Timing, &timing) || timing.Kind != "live" || timing.Started.IsZero() || !timing.Finished.After(timing.Started) || timing.Elapsed <= 0 || math.IsInf(timing.Elapsed, 0) || timing.ExitCode == nil || *timing.ExitCode != 0 {
		return refused
	}
	return nil
}
