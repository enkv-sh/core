package compositionfull

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func maintenanceRequestedTargetFixture(t *testing.T, name string) MaintenanceCommandResult {
	t.Helper()
	result := MaintenanceCommandResult{PublicApplyResult: secretAccessResultFixture(t, contract.OperationEnvelopeRekey), Delivery: ReplacementCommandDelivery{Path: "/successor.json", Status: "delivered"}, SourceUsability: "unchecked"}
	result.Successor = &core.MaintenanceSuccessor{OperationKind: contract.OperationEnvelopeRekey, DomainID: result.DomainID, OperationID: result.OperationID, RequestIdentity: result.RequestIdentity, Name: name, RekeyTarget: &contract.SecretAccessTarget{Name: name, Incarnation: contract.ID{1}, Material: contract.ID{2}, BeforePublicEntryDigest: contract.ID{3}}}
	return result
}

// full_only: false
func TestMaintenanceRequestedTargetHasBothProjectionsAndClosedBounds(t *testing.T) {
	t.Run("recipient-retirement", func(t *testing.T) {
		operation := uint16(contract.OperationRetireRecipientIdentity)
		result := MaintenanceCommandResult{PublicApplyResult: secretAccessResultFixture(t, operation), Delivery: ReplacementCommandDelivery{Status: "delivered", Path: "/successor.json"}, SourceUsability: "unchecked"}
		result.Successor = &core.MaintenanceSuccessor{OperationKind: operation, DomainID: result.DomainID, OperationID: result.OperationID, RequestIdentity: result.RequestIdentity, Recipient: contract.RecipientBindingReference{RecipientID: contract.ID{8}, PublicBindingDigest: contract.ID{9}}, Retirement: &contract.RecipientRetirementRow{RecipientID: contract.ID{8}}}
		machine, err := RenderMaintenanceCommandJSON(operation, result)
		var wire struct {
			Target struct {
				EntryName   *string `json:"entry_name"`
				RecipientID *string `json:"recipient_id"`
			} `json:"requested_target"`
		}
		if err != nil || json.Unmarshal(machine, &wire) != nil || wire.Target.EntryName != nil || wire.Target.RecipientID == nil || *wire.Target.RecipientID != readerID(contract.ID{8}) {
			t.Fatal("retirement target changed its exact recipient", err, string(machine))
		}
		human, err := RenderMaintenanceCommandHuman(operation, result)
		if err != nil || !bytes.Contains(human, []byte("Requested recipient: "+readerID(contract.ID{8}))) {
			t.Fatal("human retirement target differs", err, string(human))
		}
		result.Successor.Retirement.RecipientID = contract.ID{10}
		for _, render := range []func(uint16, MaintenanceCommandResult) ([]byte, error){RenderMaintenanceCommandJSON, RenderMaintenanceCommandHuman} {
			if body, err := render(operation, result); err == nil || body != nil {
				t.Fatal("mismatched retirement target reached output")
			}
		}
	})
	for _, name := range []string{"", "entry/\n雪", strings.Repeat("\x01", 256)} {
		t.Run(strconv.Itoa(len(name)), func(t *testing.T) {
			result := maintenanceRequestedTargetFixture(t, name)
			machine, err := RenderMaintenanceCommandJSON(contract.OperationEnvelopeRekey, result)
			var wire struct {
				Target struct {
					EntryName   *string `json:"entry_name"`
					RecipientID *string `json:"recipient_id"`
				} `json:"requested_target"`
			}
			if err != nil || json.Unmarshal(machine, &wire) != nil || wire.Target.EntryName == nil || *wire.Target.EntryName != name || wire.Target.RecipientID != nil {
				t.Fatal("requested target changed nullable semantics", err, string(machine))
			}
			human, err := RenderMaintenanceCommandHuman(contract.OperationEnvelopeRekey, result)
			if err != nil || !bytes.Contains(human, []byte("Requested entry: "+strconv.Quote(name)+"\n")) || bytes.Contains(human, []byte("Completed entry:")) || bytes.Count(human, []byte("/successor.json")) != 1 {
				t.Fatal("human target is not the same requested fact", err, string(human))
			}
			projection, err := maintenanceCommandProjection(contract.OperationEnvelopeRekey, result)
			if err != nil {
				t.Fatal(err)
			}
			target, err := json.Marshal(projection.RequestedTarget)
			if err != nil || len(target)+len(`,"requested_target":`) > 1600 {
				t.Fatal("target exceeded independent compact account", len(target), err)
			}
		})
	}
	for _, condition := range []string{"oversized", "invalid-unicode", "wrong-operation", "wrong-domain", "wrong-identity", "wrong-request", "missing-rekey-target", "different-name", "recipient-arm"} {
		t.Run(condition, func(t *testing.T) {
			result := maintenanceRequestedTargetFixture(t, "entry")
			s := result.Successor
			switch condition {
			case "oversized":
				s.Name = strings.Repeat("x", 257)
				s.RekeyTarget.Name = s.Name
			case "invalid-unicode":
				s.Name, s.RekeyTarget.Name = string([]byte{0xff}), string([]byte{0xff})
			case "wrong-operation":
				s.OperationKind = contract.OperationRetireRecipientIdentity
			case "wrong-domain":
				s.DomainID = contract.ID{90}
			case "wrong-identity":
				s.OperationID = contract.ID{90}
			case "wrong-request":
				s.RequestIdentity = contract.ID{90}
			case "missing-rekey-target":
				s.RekeyTarget = nil
			case "different-name":
				s.RekeyTarget.Name = "other"
			case "recipient-arm":
				s.Recipient.RecipientID = contract.ID{1}
			}
			for _, render := range []func(uint16, MaintenanceCommandResult) ([]byte, error){RenderMaintenanceCommandJSON, RenderMaintenanceCommandHuman} {
				if body, err := render(contract.OperationEnvelopeRekey, result); err == nil || body != nil {
					t.Fatal("invalid asserted target reached output")
				}
			}
		})
	}
}

// full_only: false
func TestMaintenanceHumanRetainsDeliveryPathAndObservationIdentity(t *testing.T) {
	operation := uint16(contract.OperationEnvelopeRekey)
	t.Run("delivery", func(t *testing.T) {
		fresh := MaintenanceCommandResult{PublicApplyResult: secretAccessResultFixture(t, operation), Delivery: ReplacementCommandDelivery{Path: "/confirmed/successor.json", Status: "delivered", CleanupFailed: true}, SourceUsability: "unchecked"}
		body, err := RenderMaintenanceCommandHuman(operation, fresh)
		if err != nil {
			t.Fatal("valid mutation/delivery control refused", err)
		}
		for _, want := range []string{"Successor file: " + strconv.Quote(fresh.Delivery.Path), "Warning: local cleanup failed"} {
			if !bytes.Contains(body, []byte(want)) {
				t.Fatal("maintenance lost a known delivery fact", want, string(body))
			}
		}
	})
	t.Run("observation", func(t *testing.T) {
		observed := maintenanceObservationRefusal(t.Context(), contract.ID{1}, operation, configuration.JSON, "capture", nil)
		result := MaintenanceCommandResult{Observation: &observed, Delivery: ReplacementCommandDelivery{Status: "existing"}, SourceUsability: "unchecked"}
		body, err := RenderMaintenanceCommandHuman(operation, result)
		if err != nil || !bytes.Contains(body, []byte("Operation ID: "+readerID(observed.OperationID))) {
			t.Fatal("maintenance observation lost its exact identity", err, string(body))
		}
	})
}

// full_only: false
func TestMaintenanceUsabilityResultsStateEvidenceLimits(t *testing.T) {
	const limit = "Checked current source relations only; later apply and private access require admission."
	for _, operation := range []uint16{contract.OperationEnvelopeRekey, contract.OperationRetireRecipientIdentity} {
		result := MaintenanceCommandResult{PublicApplyResult: secretAccessResultFixture(t, operation), Delivery: ReplacementCommandDelivery{Path: filepath.Join(t.TempDir(), "successor.json"), Status: "delivered"}, SourceUsability: "confirmed"}
		result.OutputPins = &core.AdministrativeSourcePins{FileID: contract.ID{1}, Format: 1, EditableDigest: contract.ID{2}, EditableLength: 1, GeneratedDigest: contract.ID{3}, GeneratedLength: 1, HasGenerated: true}
		result.Successor = &core.MaintenanceSuccessor{OperationKind: operation, DomainID: result.DomainID, OperationID: result.OperationID, RequestIdentity: result.RequestIdentity, FileIdentity: result.OutputPins.FileID}
		if operation == contract.OperationEnvelopeRekey {
			result.Successor.RekeyTarget = &contract.SecretAccessTarget{Incarnation: contract.ID{1}, Material: contract.ID{2}, BeforePublicEntryDigest: contract.ID{3}}
		} else {
			result.Successor.Recipient = contract.RecipientBindingReference{RecipientID: contract.ID{1}, PublicBindingDigest: contract.ID{2}}
			result.Successor.Retirement = &contract.RecipientRetirementRow{RecipientID: contract.ID{1}}
		}
		t.Run(fmt.Sprintf("%d/json", operation), func(t *testing.T) {
			body, err := RenderMaintenanceCommandJSON(operation, result)
			var wire struct {
				Limit string `json:"source_usability_evidence_limit"`
			}
			if err != nil || json.Unmarshal(body, &wire) != nil || wire.Limit != limit {
				t.Fatal("source usability lacks the required public relation evidence limit", err)
			}
		})
		t.Run(fmt.Sprintf("%d/human", operation), func(t *testing.T) {
			body, err := RenderMaintenanceCommandHuman(operation, result)
			if err != nil || !bytes.Contains(body, []byte(limit)) {
				t.Fatal("human source usability lacks the required public relation evidence limit", err)
			}
		})
	}
}

// full_only: false
func TestMaintenanceObservationRendererRejectsUnboundSuccess(t *testing.T) {
	operation := uint16(contract.OperationEnvelopeRekey)
	original := secretAccessResultFixture(t, operation)
	observed := &core.PublicMaintenanceObservationResult{RequestID: original.RequestID, OperationID: original.OperationID, RequestIdentity: original.RequestIdentity, DomainID: original.DomainID, Result: original.Result, StateResult: contract.ReaderSuccess, Receipt: original.Receipt, CandidateCurrent: true, SourceUsabilityChecked: true, SourceUsable: true, Correlation: core.MaintenanceSuccessor{OperationKind: operation, OperationID: original.OperationID, RequestIdentity: original.RequestIdentity}}
	result := MaintenanceCommandResult{Observation: observed, Delivery: ReplacementCommandDelivery{Status: "existing"}, SourceUsability: "confirmed"}
	if _, err := RenderMaintenanceCommandJSON(operation, result); err == nil {
		t.Fatal("successful maintenance observation rendered without its exact bound query")
	}
	if _, err := RenderMaintenanceCommandHuman(operation, result); err == nil {
		t.Fatal("successful human observation rendered without its exact bound query")
	}
}

// full_only: false
func TestMaintenanceObservationResultsPreserveCurrentWarnings(t *testing.T) {
	observed := maintenanceObservationRefusal(t.Context(), contract.ID{1}, contract.OperationEnvelopeRekey, configuration.JSON, "capture", nil)
	observed.CurrentWarningBits = core.WarningLateDestructiveEffect
	result := MaintenanceCommandResult{Observation: &observed, Delivery: ReplacementCommandDelivery{Status: "existing"}, SourceUsability: "unchecked"}
	body, err := RenderMaintenanceCommandJSON(contract.OperationEnvelopeRekey, result)
	const warning = "An old destructive request may act after this exit."
	if err != nil || !bytes.Contains(body, []byte(warning)) {
		t.Fatal("current maintenance warning was omitted", err)
	}
	human, err := RenderMaintenanceCommandHuman(contract.OperationEnvelopeRekey, result)
	if err != nil || !bytes.Contains(human, []byte(warning)) {
		t.Fatal("current maintenance warning was omitted from human output", err)
	}
}

// full_only: false
func TestMaintenanceObservationPreAdmissionIsBoundAndSafe(t *testing.T) {
	nonce := contract.ID{1}
	kind := uint16(contract.OperationEnvelopeRekey)
	makeResult := func() MaintenanceCommandResult {
		observed := maintenanceObservationRefusal(t.Context(), nonce, kind, configuration.JSON, "construction", errors.New("private-source-sentinel"))
		observed.Result = core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		observed.StateResult = contract.ReaderUnavailable
		observed.PreAdmission.Code = string(contract.ReasonEvidenceUnavailable)
		return MaintenanceCommandResult{Observation: &observed, Delivery: ReplacementCommandDelivery{Status: "existing"}, SourceUsability: "unchecked"}
	}
	result := makeResult()
	body := append([]byte("ENKV/maintenance-read-pre-admission/v1\x00"), nonce[:]...)
	body = append(body, 0, 11)
	if result.Observation.OperationID != contract.ID(sha256.Sum256(body)) {
		t.Fatal("read refusal did not bind nonce and exact operation")
	}
	for _, render := range []func(uint16, MaintenanceCommandResult) ([]byte, error){RenderMaintenanceCommandJSON, RenderMaintenanceCommandHuman} {
		body, err := render(kind, result)
		if err != nil || bytes.Contains(body, []byte("private-source-sentinel")) {
			t.Fatal("safe read pre-admission result could not be delivered", err)
		}
	}
	for _, condition := range []string{"nonce", "profile", "operation", "state", "successful-pre-admission", "source-claim"} {
		t.Run(condition, func(t *testing.T) {
			result := makeResult()
			switch condition {
			case "nonce":
				result.Observation.PreAdmission.RequestNonce = contract.ID{2}
			case "profile":
				result.Observation.PreAdmission.SourceProfile = "direct-candidate"
			case "operation":
				result.Observation.OperationID = contract.ID{2}
			case "state":
				result.Observation.StateResult = contract.ReaderSuccess
			case "successful-pre-admission":
				result.Observation.Result.Outcome = core.ObservedCurrent
				result.Observation.StateResult = contract.ReaderSuccess
			case "source-claim":
				result.Observation.SourceUsabilityChecked = true
				result.Observation.SourceUsable = true
				result.SourceUsability = "confirmed"
			}
			if _, err := RenderMaintenanceCommandJSON(kind, result); err == nil {
				t.Fatal("transplanted or unsupported read pre-admission result rendered")
			}
		})
	}
}
