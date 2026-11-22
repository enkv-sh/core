package records

import (
	"encoding/json"
	"strings"
)

// StockPluginEvidenceReservationBytes reserves the largest remaining fixed stock index in memory.
// The encoded current index is added as well, so prior partial facts cannot be
// hidden by the synthetic maximum. No synthetic record is persisted.
func StockPluginEvidenceReservationBytes(current StockPluginEvidence, coordinates []PublicOutputCoordinate) (int, bool) {
	want := 8
	if current.Provider == "gcp" {
		want = 2
	} else if current.Provider != "aws" {
		return 0, false
	}
	if len(coordinates) != want {
		return 0, false
	}
	identity, label := strings.Repeat("a", 64), strings.Repeat("x", 96)
	maximum := current
	maximum.Commands = make([]StockPluginCommand, MaximumStockPluginCommands)
	for i := range maximum.Commands {
		maximum.Commands[i] = StockPluginCommand{Ordinal: uint32(i), Worker: label, Nonce: strings.Repeat("a", 32), Role: label, Actor: label, Phase: label, ExitCode: -int(^uint(0)>>1) - 1, ResultSHA256: identity, DiagnosticSHA256: identity, DiagnosticBytes: ^uint32(0), DiagnosticStatus: label}
	}
	maximum.Assertions = StockPluginAssertions(current.Provider)
	maximum.Generations = make([]StockPluginGeneration, 3)
	maximum.Creates = make([]StockPluginCreate, 3)
	maximum.Duties = make([]StockPluginDuty, 3)
	maximum.Retirements = make([]StockPluginRetirement, 3)
	maximum.ProviderTokenIDs = []string{identity, identity, identity}
	for i := 0; i < 3; i++ {
		maximum.Generations[i] = StockPluginGeneration{Phase: label, Epoch: ^uint64(0), GenerationID: identity, ResourceID: identity, ResourceDigest: identity, OriginOperationID: identity, OriginAttemptID: identity}
		maximum.Creates[i] = StockPluginCreate{Phase: label, OperationID: identity, AttemptID: identity, GenerationID: identity, ResourceID: identity, ResourceDigest: identity, DescriptorID: identity, ExecutorID: identity, CredentialRouteID: identity, ConfigContractID: identity, ResourceContractID: identity, ResultContractID: identity}
		maximum.Duties[i] = StockPluginDuty{Phase: label, DutyID: identity, ResourceID: identity, DescriptorID: identity, ExecutorID: identity, CredentialRouteID: identity, ResultContractID: identity, OriginalOperationID: identity, OriginalAttemptID: identity}
		maximum.Retirements[i] = StockPluginRetirement{CloseDigest: identity, ResultDigest: identity, ResultLength: ^uint32(0), Phase: label, DutyID: identity, DeletionAcknowledgedCount: ^uint32(0), InvalidationConfirmedCount: ^uint32(0), UnknownCount: ^uint32(0)}
	}
	maximum.Outputs = make([]StockPluginOutput, len(coordinates))
	for i, coordinate := range coordinates {
		coordinate.CoordinateID, coordinate.BindingID = identity, identity
		maximum.Outputs[i] = StockPluginOutput{Instance: strings.Repeat("\x00", 512), Coordinate: coordinate, Deletion: "acknowledged"}
	}
	maximum.ServiceVerifications = MaximumStockPluginVerifications
	before, beforeErr := json.Marshal(current)
	reserved, reservedErr := json.Marshal(maximum)
	if beforeErr != nil || reservedErr != nil {
		return 0, false
	}
	size := len(before) + len(reserved) + 1
	return size, size <= MaximumStockPluginEvidenceBytes
}
