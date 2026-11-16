package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
)

type publicOutputRecoveryObservation struct {
	Version         uint16                                   `json:"version"`
	RunID           string                                   `json:"run_id"`
	OriginalRunID   string                                   `json:"original_run_id"`
	Worker          string                                   `json:"worker"`
	Nonce           string                                   `json:"nonce"`
	InputSHA256     string                                   `json:"input_sha256"`
	Stage           string                                   `json:"stage"`
	Domain          string                                   `json:"domain"`
	Revision        string                                   `json:"revision"`
	Snapshot        string                                   `json:"snapshot"`
	HeadSHA256      string                                   `json:"head_sha256"`
	WarningBits     uint8                                    `json:"warning_bits"`
	ActiveGenerated string                                   `json:"active_generated_owner"`
	ActiveGC        string                                   `json:"active_gc"`
	Coordinates     []publicOutputRecoveryObservedCoordinate `json:"coordinates"`
	Markers         []publicOutputRecoveryObservedMarker     `json:"markers"`
}

type publicOutputRecoveryObservedCoordinate struct {
	CoordinateID            string `json:"coordinate_id"`
	BindingState            uint8  `json:"binding_state"`
	OwnerState              uint8  `json:"owner_state"`
	LatestUnresolvedAttempt string `json:"latest_unresolved_attempt_id"`
	LateEffectRisk          uint8  `json:"late_effect_risk"`
}

type publicOutputRecoveryObservedMarker struct {
	CoordinateID   string `json:"coordinate_id"`
	OperationID    string `json:"operation_id"`
	AttemptID      string `json:"attempt_id"`
	State          uint8  `json:"state"`
	LateEffectRisk uint8  `json:"late_effect_risk"`
}

func publicOutputRecoverySaveObservation(t testing.TB, inv records.Invocation, input liveRunInput, stage string, selected *StateSession, coordinates map[string]contract.PublicationCoordinate, markers map[contract.ID]contract.PublicationMarker) {
	t.Helper()
	if !slices.Contains([]string{"authenticated-discovery", "remaining-deletions", "current-disposition"}, stage) || len(coordinates) > contract.MaxPublicationCoordinates || len(markers) > contract.MaxPublicationMarkers {
		t.Fatal("public output recovery selected observation exceeds its fixed stage or capacity")
	}
	body, err := json.Marshal(input.OutputRecovery)
	if err != nil || input.OutputRecovery == nil {
		t.Fatal("public output recovery observation input unavailable")
	}
	observation := publicOutputRecoveryObservation{
		Version: 1, RunID: inv.RunID, OriginalRunID: input.RunID, Worker: inv.Worker, Nonce: inv.Nonce, InputSHA256: bodyDigest(body), Stage: stage,
		Domain: hex.EncodeToString(selected.root.Domain[:]), Revision: hex.EncodeToString(selected.head.Core.Revision[:]), Snapshot: hex.EncodeToString(selected.root.Snapshot[:]), HeadSHA256: bodyDigest(selected.body),
		WarningBits: selected.root.WarningBits, ActiveGenerated: hex.EncodeToString(selected.root.Generated.ActiveOwner[:]), ActiveGC: hex.EncodeToString(selected.root.ActiveGC[:]),
		Coordinates: make([]publicOutputRecoveryObservedCoordinate, 0, len(coordinates)), Markers: make([]publicOutputRecoveryObservedMarker, 0, len(markers)),
	}
	for _, coordinate := range coordinates {
		observation.Coordinates = append(observation.Coordinates, publicOutputRecoveryObservedCoordinate{
			CoordinateID: hex.EncodeToString(coordinate.CoordinateID[:]), BindingState: coordinate.BindingState, OwnerState: coordinate.OwnerState,
			LatestUnresolvedAttempt: hex.EncodeToString(coordinate.LatestUnresolvedAttemptID[:]), LateEffectRisk: coordinate.LateEffectRisk,
		})
	}
	for _, marker := range markers {
		observation.Markers = append(observation.Markers, publicOutputRecoveryObservedMarker{
			CoordinateID: hex.EncodeToString(marker.CoordinateID[:]), OperationID: hex.EncodeToString(marker.OperationID[:]), AttemptID: hex.EncodeToString(marker.AttemptID[:]), State: marker.State, LateEffectRisk: marker.LateEffectRisk,
		})
	}
	slices.SortFunc(observation.Coordinates, func(a, b publicOutputRecoveryObservedCoordinate) int {
		return strings.Compare(a.CoordinateID, b.CoordinateID)
	})
	slices.SortFunc(observation.Markers, func(a, b publicOutputRecoveryObservedMarker) int { return strings.Compare(a.AttemptID, b.AttemptID) })
	path := filepath.Join(inv.OutputDir, "public-output-recovery-observed-"+stage+".json")
	if records.WriteJSONExclusive(path, observation, records.MaximumJSONBytes) != nil {
		t.Fatal("public output recovery authenticated selection could not be retained")
	}
}

func publicOutputRecoveryObservationFixture(t *testing.T) (records.Invocation, liveRunInput, *StateSession, map[string]contract.PublicationCoordinate, map[contract.ID]contract.PublicationMarker) {
	t.Helper()
	inv, input := liveProtocolInvocation(t, "cleanup")
	inv = liveProtocolRecoveryOutput(t, inv)
	input.Settings.Region, input.Settings.Account, input.Settings.ProjectNumber = "us-east-1", "123456789012", "123456789"
	input.PublicConfiguration = &publicConfigurationInput{Outputs: &records.PublicOutputScopes{
		Repository:   records.PublicOutputScope{Owner: "owner", Repository: "repository"},
		Organization: records.PublicOutputScope{Owner: "organization", Visibility: "selected", Repositories: []uint64{101}},
		Environment:  records.PublicOutputScope{Owner: "owner", Repository: "repository", Environment: "prod"},
	}}
	input.OutputRecovery = &records.PublicOutputRecoveryInput{Version: 1, OriginalRunID: input.RunID, RecoveryRunID: inv.RunID, OriginalState: inv.StateDir}
	selected := &StateSession{body: []byte("authenticated selection HEAD")}
	selected.root.Domain, selected.root.Snapshot, selected.head.Core.Revision = contract.ID{1}, contract.ID{2}, contract.ID{3}
	selected.root.Generated = format.EmptyGeneratedClosure()
	ledger := publicOwnership{Version: 1, RunID: input.RunID, PreflightEmpty: true, Domain: hex.EncodeToString(selected.root.Domain[:])}
	if records.WriteJSON(filepath.Join(inv.StateDir, "public-ownership.json"), ledger, 0600) != nil {
		t.Fatal("original ownership fixture unavailable")
	}
	cloud := "aws-secrets-manager"
	if input.Settings.Provider == "gcp" {
		cloud = "gcp-secret-manager"
	}
	targets := publicExpectedOutputCoordinatesForScopes(input, []string{cloud, "github-repository", "github-organization", "github-environment"})
	if len(targets) != 8 {
		t.Fatal("complete selected fixture targets unavailable")
	}
	coordinates := map[string]contract.PublicationCoordinate{}
	markers := map[contract.ID]contract.PublicationMarker{}
	for index, target := range targets[:2] {
		coordinateID, attemptID := contract.ID{22}, contract.ID{44}
		if index == 1 {
			coordinateID, attemptID = contract.ID{11}, contract.ID{33}
		}
		coordinate := contract.PublicationCoordinate{DomainID: selected.root.Domain, CoordinateID: coordinateID,
			ServiceContractID: target.ServiceContractID, CanonicalTarget: target.PhysicalTarget,
			BindingState: contract.PublicationBindingRetired, OwnerState: contract.PublicationOwnerUncertainCreate,
			LatestUnresolvedAttemptID: attemptID, LateEffectRisk: 1, DeletionCredentialRouteContractID: "private-route", DeletionTargetData: []byte("private-target")}
		coordinates[target.ServiceContractID+"\x00"+target.PhysicalTarget] = coordinate
		markers[attemptID] = contract.PublicationMarker{DomainID: selected.root.Domain, CoordinateID: coordinateID,
			OperationID: contract.ID{55}, AttemptID: attemptID, State: contract.PublicationUnknown, LateEffectRisk: 1,
			ExecutorID: "private-executor", CredentialRouteID: "private-credential", Evidence: contract.PublicationEvidence{SafeResourceID: "private-provider-evidence"}}
	}
	return inv, input, selected, coordinates, markers
}

func publicOutputRecoveryObservationRefusal(t *testing.T, inv records.Invocation, input liveRunInput, stage string, selected *StateSession, coordinates map[string]contract.PublicationCoordinate, markers map[contract.ID]contract.PublicationMarker) string {
	t.Helper()
	var refusal any
	func() {
		defer func() { refusal = recover() }()
		publicOutputRecoveryClassify(recoveryCustodyRefusalTB{TB: t}, inv, input, stage, selected, contract.OutputConfiguration{}, coordinates, markers)
	}()
	message, ok := refusal.(recoveryCustodyRefusal)
	if !ok {
		t.Fatal("selected-state classifier did not return its controlled refusal", refusal)
	}
	return string(message)
}

// full_only: false
func TestPublicOutputRecoveryObservationSurvivesSelectionRefusal(t *testing.T) {
	inv, input, selected, coordinates, markers := publicOutputRecoveryObservationFixture(t)
	inputBody, err := json.Marshal(input.OutputRecovery)
	if err != nil {
		t.Fatal(err)
	}
	inputDigest, headDigest := sha256.Sum256(inputBody), sha256.Sum256(selected.body)
	id := func(value byte) string { return hex.EncodeToString(append([]byte{value}, make([]byte, 31)...)) }
	for _, stage := range []string{"authenticated-discovery", "remaining-deletions", "current-disposition"} {
		t.Run(stage, func(t *testing.T) {
			if got := publicOutputRecoveryObservationRefusal(t, inv, input, stage, selected, coordinates, markers); got != "public output recovery target has unresolved publication blockers" {
				t.Fatal("unknown publication marker was not kept as the original blocker", got)
			}
			path := filepath.Join(inv.OutputDir, "public-output-recovery-observed-"+stage+".json")
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("authenticated selection was lost before the blocker refusal", err)
			}
			var actual map[string]any
			if json.Unmarshal(body, &actual) != nil {
				t.Fatal("selected-state observation is not JSON")
			}
			want := map[string]any{
				"version": 1, "run_id": inv.RunID, "original_run_id": input.RunID, "worker": inv.Worker, "nonce": inv.Nonce, "input_sha256": hex.EncodeToString(inputDigest[:]), "stage": stage,
				"domain": id(1), "revision": id(3), "snapshot": id(2), "head_sha256": hex.EncodeToString(headDigest[:]), "warning_bits": 0, "active_generated_owner": id(0), "active_gc": id(0),
				"coordinates": []any{
					map[string]any{"coordinate_id": id(11), "binding_state": 2, "owner_state": 1, "latest_unresolved_attempt_id": id(33), "late_effect_risk": 1},
					map[string]any{"coordinate_id": id(22), "binding_state": 2, "owner_state": 1, "latest_unresolved_attempt_id": id(44), "late_effect_risk": 1},
				},
				"markers": []any{
					map[string]any{"coordinate_id": id(11), "operation_id": id(55), "attempt_id": id(33), "state": 4, "late_effect_risk": 1},
					map[string]any{"coordinate_id": id(22), "operation_id": id(55), "attempt_id": id(44), "state": 4, "late_effect_risk": 1},
				},
			}
			gotJSON, gotErr := json.Marshal(actual)
			wantJSON, wantErr := json.Marshal(want)
			info, statErr := os.Stat(path)
			if gotErr != nil || wantErr != nil || statErr != nil || info.Mode().Perm() != 0600 || !bytes.Equal(gotJSON, wantJSON) {
				t.Fatal("selected-state observation lost its private owner, exact set or safe projection")
			}
			for _, private := range []string{"private-route", "private-target", "cHJpdmF0ZS10YXJnZXQ=", "private-executor", "private-credential", "private-provider-evidence"} {
				if bytes.Contains(body, []byte(private)) {
					t.Fatal("provider, executor or target details escaped the closed observation")
				}
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryObservationPersistenceStopsClassification(t *testing.T) {
	for _, condition := range []string{"existing", "missing-directory", "unknown-stage", "coordinate-capacity", "marker-capacity"} {
		t.Run(condition, func(t *testing.T) {
			inv, input, selected, coordinates, markers := publicOutputRecoveryObservationFixture(t)
			stage := "authenticated-discovery"
			path := filepath.Join(inv.OutputDir, "public-output-recovery-observed-"+stage+".json")
			expected := "public output recovery authenticated selection could not be retained"
			var original []byte
			switch condition {
			case "existing":
				original = []byte("previous immutable diagnostic\n")
				if os.WriteFile(path, original, 0600) != nil {
					t.Fatal("existing observation fixture unavailable")
				}
			case "missing-directory":
				if os.Remove(inv.OutputDir) != nil {
					t.Fatal("private output fixture could not be removed")
				}
			case "unknown-stage":
				stage = "../other"
				expected = "public output recovery selected observation exceeds its fixed stage or capacity"
			case "coordinate-capacity":
				coordinates = make(map[string]contract.PublicationCoordinate, contract.MaxPublicationCoordinates+1)
				for index := 0; index <= contract.MaxPublicationCoordinates; index++ {
					coordinates[fmt.Sprint(index)] = contract.PublicationCoordinate{}
				}
				expected = "public output recovery selected observation exceeds its fixed stage or capacity"
			case "marker-capacity":
				markers = make(map[contract.ID]contract.PublicationMarker, contract.MaxPublicationMarkers+1)
				for index := 0; index <= contract.MaxPublicationMarkers; index++ {
					var id contract.ID
					binary.BigEndian.PutUint32(id[:4], uint32(index))
					markers[id] = contract.PublicationMarker{}
				}
				expected = "public output recovery selected observation exceeds its fixed stage or capacity"
			}
			if got := publicOutputRecoveryObservationRefusal(t, inv, input, stage, selected, coordinates, markers); got != expected {
				t.Fatal("failed observation reached later blocker classification", got)
			}
			if original != nil {
				body, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(body, original) {
					t.Fatal("later observation replaced an earlier failure record")
				}
			} else if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("failed observation published a partial record")
			}
		})
	}
}

// full_only: false
func TestPublicOutputRecoveryObservationRetainsFullCapacity(t *testing.T) {
	inv, input, selected, _, _ := publicOutputRecoveryObservationFixture(t)
	selected.root.WarningBits = 1
	selected.root.Generated.ActiveOwner = contract.ID{66}
	coordinates := make(map[string]contract.PublicationCoordinate, contract.MaxPublicationCoordinates)
	markers := make(map[contract.ID]contract.PublicationMarker, contract.MaxPublicationMarkers)
	for index := 0; index < contract.MaxPublicationMarkers; index++ {
		var id contract.ID
		binary.BigEndian.PutUint32(id[:4], uint32(index+1))
		markers[id] = contract.PublicationMarker{CoordinateID: contract.ID{1}, OperationID: contract.ID{2}, AttemptID: id, State: contract.PublicationUnknown}
		if index < contract.MaxPublicationCoordinates {
			coordinates[fmt.Sprint(index)] = contract.PublicationCoordinate{CoordinateID: id, LatestUnresolvedAttemptID: id}
		}
	}
	if got := publicOutputRecoveryObservationRefusal(t, inv, input, "authenticated-discovery", selected, coordinates, markers); got != "public output recovery has selected warnings or unfinished work" {
		t.Fatal("selected warning refusal changed", got)
	}
	body, err := os.ReadFile(filepath.Join(inv.OutputDir, "public-output-recovery-observed-authenticated-discovery.json"))
	var observation struct {
		WarningBits     uint8             `json:"warning_bits"`
		ActiveGenerated string            `json:"active_generated_owner"`
		ActiveGC        string            `json:"active_gc"`
		Coordinates     []json.RawMessage `json:"coordinates"`
		Markers         []json.RawMessage `json:"markers"`
	}
	if err != nil || json.Unmarshal(body, &observation) != nil || observation.WarningBits != 1 || observation.ActiveGenerated != "42"+strings.Repeat("00", 31) || observation.ActiveGC != strings.Repeat("00", 32) || len(observation.Coordinates) != contract.MaxPublicationCoordinates || len(observation.Markers) != contract.MaxPublicationMarkers {
		t.Fatal("selected observation truncated its complete bounded set or active work")
	}
}
