package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/credentialroute"
	"enkv.sh/telemetry"
)

const stockVerificationBytes = 16 << 10

type stockCloudOutputRead struct {
	Bytes    []byte
	Instance string
}

type stockCloudOutputDeletion struct{ Disposition, Instance string }

type stockGeneratedCurrent struct {
	Name             string `json:"name"`
	Incarnation      string `json:"entry_incarnation_id"`
	Generation       string `json:"generation_id"`
	Epoch            uint64 `json:"epoch"`
	Resource         string `json:"resource_incarnation_id"`
	Digest           string `json:"resource_digest"`
	OriginOperation  string `json:"origin_operation_id"`
	OriginAttempt    string `json:"origin_attempt_id"`
	ConfigContract   string `json:"config_contract_id"`
	ResourceContract string `json:"resource_contract_id"`
	Lifecycle        string `json:"lifecycle_mode"`
	Completion       string `json:"completion_class"`
	RetirementPolicy string `json:"retirement_policy"`
}

type stockGeneratedSupport struct {
	Result            string                 `json:"result_id"`
	Transmission      string                 `json:"transmission_id"`
	ValueSlot         string                 `json:"planned_value_slot_id"`
	Stage             uint8                  `json:"stage"`
	Duty              string                 `json:"duty_id"`
	Hazard            string                 `json:"hazard_id"`
	Lineage           string                 `json:"lineage_id"`
	Operation         string                 `json:"operation_id"`
	Attempt           string                 `json:"attempt_id"`
	Generation        string                 `json:"generation_id"`
	ResourceDigest    string                 `json:"resource_digest"`
	Resource          string                 `json:"resource_incarnation_id"`
	PlannedResource   string                 `json:"planned_resource_incarnation_id"`
	Name              string                 `json:"name"`
	Incarnation       string                 `json:"entry_incarnation_id"`
	Epoch             uint64                 `json:"epoch"`
	ConfigContract    string                 `json:"config_contract_id"`
	ResourceContract  string                 `json:"resource_contract_id"`
	Lifecycle         string                 `json:"lifecycle_mode"`
	Descriptor        string                 `json:"descriptor_id"`
	Executor          string                 `json:"executor_id"`
	CredentialRoute   string                 `json:"credential_route_id"`
	ResultContract    string                 `json:"result_contract_id"`
	OriginalOperation string                 `json:"original_operation_id"`
	OriginalAttempt   string                 `json:"original_attempt_id"`
	Kind              string                 `json:"kind"`
	State             string                 `json:"state"`
	Status            string                 `json:"status"`
	Action            string                 `json:"action"`
	Completion        string                 `json:"completion_class"`
	Evidence          string                 `json:"evidence_ceiling"`
	Warnings          stockGeneratedWarnings `json:"warnings"`
}

type stockGeneratedRelease struct {
	Inbox           string `json:"inbox_id"`
	Result          string `json:"original_result_id"`
	HandoffDigest   string `json:"selected_handoff_digest"`
	HandoffRevision string `json:"handoff_revision_id"`
	State           string `json:"state"`
	ObjectLength    uint32 `json:"object_length"`
}

type stockGeneratedWarnings struct {
	PossibleLive             bool `json:"possible_live_residue"`
	LateEffect               bool `json:"late_effect"`
	InvalidationNotConfirmed bool `json:"invalidation_not_confirmed"`
}

type stockGeneratedFact struct {
	Facts  stockGeneratedSupport `json:"facts"`
	Target struct {
		Name              string `json:"name"`
		Incarnation       string `json:"entry_incarnation_id"`
		Epoch             uint64 `json:"epoch"`
		Resource          string `json:"resource_incarnation_id"`
		ConfigContract    string `json:"config_contract_id"`
		ResourceContract  string `json:"resource_contract_id"`
		Lifecycle         string `json:"lifecycle_mode"`
		Completion        string `json:"completion_class"`
		Digest            string `json:"resource_digest"`
		OriginalOperation string `json:"original_operation_id"`
		OriginalAttempt   string `json:"original_attempt_id"`
		ResultContract    string `json:"result_contract_id"`
	} `json:"target"`
}

type stockGeneratedResult struct {
	PendingReleases            []stockGeneratedRelease `json:"pending_releases"`
	Schema                     string                  `json:"schema"`
	Operation                  string                  `json:"operation_kind"`
	Domain                     string                  `json:"domain_id"`
	OperationID                string                  `json:"operation_id"`
	Revision                   string                  `json:"observed_revision_id"`
	Snapshot                   string                  `json:"snapshot_id"`
	Attempts                   []json.RawMessage       `json:"attempts"`
	State                      string                  `json:"state_result"`
	CommitUnknown              bool                    `json:"commit_may_have_occurred"`
	Warnings                   stockGeneratedWarnings  `json:"effect_warnings"`
	DeletionAcknowledgedCount  uint32                  `json:"deletion_acknowledged_count"`
	InvalidationConfirmedCount uint32                  `json:"invalidation_confirmed_count"`
	UnknownCount               uint32                  `json:"unknown_count"`
	Current                    []stockGeneratedCurrent `json:"current_generations"`
	Duties                     []stockGeneratedFact    `json:"duties"`
	Effects                    []stockGeneratedFact    `json:"effects"`
	Hazards                    []json.RawMessage       `json:"hazards"`
	Counts                     struct {
		Unknown uint32 `json:"unknown"`
		Residue uint32 `json:"preserved_residue"`
	} `json:"summary_counts"`
}

func stockGeneratedDecode(body []byte, code int, state string) (stockGeneratedResult, error) {
	var out stockGeneratedResult
	wantCode := 0
	if state == "retirement-pending" {
		wantCode = 3
	}
	if state == "refused" {
		wantCode = 2
	}
	if len(body) == 0 || len(body) > 4<<20 || jsonv2.Unmarshal(body, &out) != nil ||
		out.Schema != "ProductResult/v1" || out.State != state || code != wantCode ||
		out.CommitUnknown || len(out.Hazards) != 0 || out.Counts.Unknown != 0 || out.Counts.Residue != 0 {
		return stockGeneratedResult{}, errInventory
	}
	var fields map[string]json.RawMessage
	if jsonv2.Unmarshal(body, &fields) != nil {
		return stockGeneratedResult{}, errInventory
	}
	if out.Operation != "generated-list" && out.Operation != "apply-declaration" && out.Operation != "retire-generated-generation" {
		return stockGeneratedResult{}, errInventory
	}
	if out.Operation == "generated-list" {
		if state != "success" || !publicIdentityHex(out.Revision) || !publicIdentityHex(out.Snapshot) ||
			!stockWarningsKnown(fields["effect_warnings"]) ||
			!bytes.Equal(bytes.TrimSpace(fields["active_operation"]), []byte("null")) {
			return stockGeneratedResult{}, errInventory
		}
		for _, name := range []string{"current_generations", "attempts", "duties", "hazards", "pending_releases", "next_actions"} {
			if !stockArrayPresent(fields[name]) {
				return stockGeneratedResult{}, errInventory
			}
		}
		if jsonv2.Unmarshal(fields["attempts"], &out.Effects) != nil {
			return stockGeneratedResult{}, errInventory
		}
	} else {
		if !stockFalsePresent(fields["commit_may_have_occurred"]) {
			return stockGeneratedResult{}, errInventory
		}
		var product publicProductResult
		if jsonv2.Unmarshal(body, &product) != nil || !publicRequestIdentityValid(product) {
			return stockGeneratedResult{}, errInventory
		}
		if _, generated := fields["effects_available"]; generated {
			for _, name := range []string{"effects_available", "summary_counts_available", "related_work_available"} {
				if !bytes.Equal(bytes.TrimSpace(fields[name]), []byte("true")) {
					return stockGeneratedResult{}, errInventory
				}
			}
			if !stockWarningsKnown(fields["effect_warnings"]) {
				return stockGeneratedResult{}, errInventory
			}
			for _, name := range []string{"effects", "duties", "hazards"} {
				if !stockArrayPresent(fields[name]) {
					return stockGeneratedResult{}, errInventory
				}
			}
			var counts map[string]json.RawMessage
			if jsonv2.Unmarshal(fields["summary_counts"], &counts) != nil {
				return stockGeneratedResult{}, errInventory
			}
			for _, name := range []string{"effects", "outputs", "duties", "hazards", "changed_access", "succeeded", "failed", "neutral", "pending", "unknown", "preserved_residue", "no_effect_predecessors"} {
				raw, present := counts[name]
				var count *uint32
				if !present || jsonv2.Unmarshal(raw, &count) != nil || count == nil {
					return stockGeneratedResult{}, errInventory
				}
			}
			if !bytes.Equal(bytes.TrimSpace(fields["unknown_count"]), []byte("0")) {
				return stockGeneratedResult{}, errInventory
			}
			for _, name := range []string{"deletion_acknowledged_count", "invalidation_confirmed_count", "unknown_count"} {
				var count *uint32
				if jsonv2.Unmarshal(fields[name], &count) != nil || count == nil {
					return stockGeneratedResult{}, errInventory
				}
			}
		} else if (state != "no-op" && state != "refused") || !stockArrayPresent(fields["warning_summary"]) {
			// A pre-admission refusal or ordinary unchanged apply has the common
			// transition result, rather than invented generated-work arrays.
			return stockGeneratedResult{}, errInventory
		} else {
			var warnings []string
			if jsonv2.Unmarshal(fields["warning_summary"], &warnings) != nil ||
				!bytes.Equal(bytes.TrimSpace(fields["payload"]), []byte("null")) {
				return stockGeneratedResult{}, errInventory
			}
		}
	}
	for _, fact := range append(append([]stockGeneratedFact{}, out.Duties...), out.Effects...) {
		if fact.Facts.Warnings.PossibleLive || fact.Facts.Warnings.LateEffect || fact.Facts.State == "unknown" || fact.Facts.Status == "unknown" {
			return stockGeneratedResult{}, errInventory
		}
	}
	for _, name := range []string{"duties", "effects", "attempts"} {
		if raw, present := fields[name]; present && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			var rows []struct {
				Facts  map[string]json.RawMessage `json:"facts"`
				Target map[string]json.RawMessage `json:"target"`
			}
			if jsonv2.Unmarshal(raw, &rows) != nil {
				return stockGeneratedResult{}, errInventory
			}
			for _, row := range rows {
				if out.Operation == "retire-generated-generation" && out.State == "success" && name == "effects" &&
					(!bytes.Equal(bytes.TrimSpace(row.Facts["duty_id"]), []byte("null")) || !bytes.Equal(bytes.TrimSpace(row.Facts["hazard_id"]), []byte("null"))) {
					return stockGeneratedResult{}, errInventory
				}
				if !stockWarningsKnown(row.Facts["warnings"]) ||
					(name != "duties" && !stockEpochPresent(row.Facts["epoch"])) ||
					(row.Target != nil && !stockEpochPresent(row.Target["epoch"])) {
					return stockGeneratedResult{}, errInventory
				}
			}
		}
	}
	if out.Operation == "retire-generated-generation" && out.State == "success" {
		for _, name := range []string{"current_domain_duty_ids", "current_domain_hazard_ids", "related_duty_ids", "related_hazard_ids"} {
			var ids []json.RawMessage
			if !stockArrayPresent(fields[name]) || jsonv2.Unmarshal(fields[name], &ids) != nil || len(ids) != 0 {
				return stockGeneratedResult{}, errInventory
			}
		}
	}
	if raw, present := fields["current_generations"]; present {
		var current []map[string]json.RawMessage
		if jsonv2.Unmarshal(raw, &current) != nil {
			return stockGeneratedResult{}, errInventory
		}
		for _, row := range current {
			if !stockEpochPresent(row["epoch"]) {
				return stockGeneratedResult{}, errInventory
			}
		}
	}
	if out.Operation == "generated-list" && !stockPendingReleasesKnown(out) {
		return stockGeneratedResult{}, errInventory
	}
	return out, nil
}

func stockPendingReleasesKnown(result stockGeneratedResult) bool {
	if uint64(len(result.PendingReleases)) > GeneratedResultAttemptLimit {
		return false
	}
	seen := make(map[string]bool, len(result.PendingReleases))
	for i, release := range result.PendingReleases {
		if release.State != "pending" || release.ObjectLength == 0 || release.ObjectLength > uint32(contract.GeneratedResultRecordMaxLength) ||
			!publicIdentityHex(release.Inbox) || !publicIdentityHex(release.Result) || !publicIdentityHex(release.HandoffDigest) || !publicIdentityHex(release.HandoffRevision) ||
			i > 0 && result.PendingReleases[i-1].Inbox >= release.Inbox || seen[release.Result] {
			return false
		}
		seen[release.Result] = true
		matches := 0
		for at, effect := range result.Effects {
			if effect.Facts.Result != release.Result {
				continue
			}
			if !stockReleasedAttemptKnown(result.Domain, release, effect, result.Attempts[at]) {
				return false
			}
			matches++
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

func stockReleasedAttemptKnown(domain string, release stockGeneratedRelease, effect stockGeneratedFact, raw json.RawMessage) bool {
	f := effect.Facts
	if f.State != "succeeded" || f.Stage != contract.GeneratedStageTerminal || f.Lifecycle != "managed" || f.Completion != "deletion-acknowledged" ||
		f.Name != "generated" || f.Warnings.PossibleLive || f.Warnings.LateEffect {
		return false
	}
	for _, id := range []string{domain, f.Operation, f.Lineage, f.Attempt, f.Result, f.Transmission, f.ValueSlot, f.Incarnation, f.PlannedResource, f.Descriptor, f.Executor, f.CredentialRoute, f.ConfigContract, f.ResourceContract, f.ResultContract} {
		if !publicIdentityHex(id) {
			return false
		}
	}
	var row struct {
		Facts    map[string]json.RawMessage `json:"facts"`
		Target   json.RawMessage            `json:"target"`
		Progress json.RawMessage            `json:"progress"`
	}
	if jsonv2.Unmarshal(raw, &row) != nil || !stockFalsePresent(row.Facts["retry_consumed"]) ||
		!bytes.Equal(bytes.TrimSpace(row.Facts["duty_id"]), []byte("null")) || !bytes.Equal(bytes.TrimSpace(row.Facts["hazard_id"]), []byte("null")) ||
		!bytes.Equal(bytes.TrimSpace(row.Facts["generation_id"]), []byte("null")) || !bytes.Equal(bytes.TrimSpace(row.Target), []byte("null")) {
		return false
	}
	var progress []json.RawMessage
	if !stockArrayPresent(row.Progress) || jsonv2.Unmarshal(row.Progress, &progress) != nil || len(progress) != 0 {
		return false
	}
	domainID, _ := artifact.ParseDigest(domain)
	operationID, _ := artifact.ParseDigest(f.Operation)
	attemptID, _ := artifact.ParseDigest(f.Attempt)
	resultID, _ := artifact.ParseDigest(f.Result)
	inbox, err := contract.GeneratorInboxID(contract.ID(domainID), contract.ID(operationID), contract.ID(attemptID), contract.ID(resultID))
	if err != nil || artifact.Digest(inbox).String() != release.Inbox {
		return false
	}
	switch f.Action {
	case "create":
		return bytes.Equal(bytes.TrimSpace(row.Facts["resource_digest"]), []byte("null")) && f.Evidence == "canonical" && !f.Warnings.InvalidationNotConfirmed
	case "delete":
		return publicIdentityHex(f.ResourceDigest) && f.Evidence == "deletion-acknowledged" && f.Warnings.InvalidationNotConfirmed
	default:
		return false
	}
}

func stockEpochPresent(raw json.RawMessage) bool {
	var value *uint64
	return jsonv2.Unmarshal(raw, &value) == nil && value != nil
}

func stockFalsePresent(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("false"))
}
func stockArrayPresent(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '['
}
func stockWarningsKnown(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if jsonv2.Unmarshal(raw, &fields) != nil || !stockFalsePresent(fields["possible_live_residue"]) || !stockFalsePresent(fields["late_effect"]) {
		return false
	}
	value := bytes.TrimSpace(fields["invalidation_not_confirmed"])
	return bytes.Equal(value, []byte("true")) || bytes.Equal(value, []byte("false"))
}

func stockCurrentValid(v stockGeneratedCurrent, epoch uint64) bool {
	if v.Name != "generated" || v.Epoch != epoch || v.Lifecycle != "managed" ||
		v.Completion != "deletion-acknowledged" || v.RetirementPolicy != "manual" {
		return false
	}
	for _, id := range []string{v.Incarnation, v.Generation, v.Resource, v.Digest, v.OriginOperation, v.OriginAttempt, v.ConfigContract, v.ResourceContract} {
		if !publicIdentityHex(id) {
			return false
		}
	}
	return true
}

func stockDutyMatches(v stockGeneratedFact, generation stockGeneratedCurrent, created stockGeneratedFact, metadata artifact.Metadata) bool {
	facts, err := metadata.GeneratorFacts()
	if err != nil || facts.Descriptor.Generator.ConfigContractID.String() != generation.ConfigContract {
		return false
	}
	route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
	if err != nil {
		return false
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		return false
	}
	protocolID, err := artifact.ParseDigest(facts.Descriptor.Wire.Identity)
	if err != nil || generation.Completion != "deletion-acknowledged" {
		return false
	}
	implementation := contract.GeneratorImplementation{
		Schema: contract.GeneratorImplementationSchema, Kind: contract.GeneratorComponentKind,
		DescriptorID: contract.ID(facts.DescriptorID), ProtocolID: contract.ID(protocolID),
		ExecutorID: contract.ID(facts.ExecutorID), ArtifactContractID: contract.ID(facts.ArtifactContractID),
		DependencyManifestID: contract.ID(facts.DependencyManifestID), ArtifactSHA256: contract.ID(facts.ArtifactSHA256),
		ConfigContractID: contract.ID(facts.Descriptor.Generator.ConfigContractID), CredentialRouteID: contract.ID(routeID),
		CredentialRoute: facts.Descriptor.Generator.CredentialRoute, ArtifactLength: facts.ArtifactLength,
		Module: facts.Module, Command: facts.Command, Version: facts.Descriptor.Version, GoVersion: facts.GoVersion, NativeTuple: facts.NativeTuple,
	}
	retirement, err := contract.GeneratedResultContractID(implementation, contract.GeneratorActionDelete, contract.GeneratedCompletionAcknowledged, 0, contract.GeneratorSafeFactsEnvelopeLength, contract.InputEncodingRaw)
	return err == nil && stockDutyMatchesSupport(v, generation, created, facts.DescriptorID.String(), facts.ExecutorID.String(), artifact.Digest(routeID).String(), artifact.Digest(retirement).String())
}

func stockDutyMatchesSupport(v stockGeneratedFact, generation stockGeneratedCurrent, created stockGeneratedFact, descriptor, executor, route, retirement string) bool {
	return publicIdentityHex(v.Facts.Duty) && v.Facts.Kind == "retirement" &&
		v.Facts.Completion == generation.Completion && v.Target.Completion == generation.Completion &&
		v.Facts.ConfigContract == generation.ConfigContract && v.Facts.ResourceContract == generation.ResourceContract && v.Facts.Lifecycle == generation.Lifecycle &&
		v.Target.Name == generation.Name && v.Target.Incarnation == generation.Incarnation && v.Target.Epoch == generation.Epoch &&
		v.Target.ConfigContract == generation.ConfigContract && v.Target.ResourceContract == generation.ResourceContract && v.Target.Lifecycle == generation.Lifecycle &&
		v.Facts.Resource == generation.Resource && v.Target.Resource == generation.Resource && v.Target.Digest == generation.Digest &&
		v.Facts.OriginalOperation == generation.OriginOperation && v.Facts.OriginalAttempt == generation.OriginAttempt &&
		v.Target.OriginalOperation == generation.OriginOperation && v.Target.OriginalAttempt == generation.OriginAttempt &&
		v.Facts.Descriptor == descriptor && v.Facts.Executor == executor && v.Facts.CredentialRoute == route &&
		publicIdentityHex(retirement) && v.Facts.ResultContract == retirement &&
		publicIdentityHex(created.Facts.ResultContract) && created.Target.ResultContract == created.Facts.ResultContract && v.Target == created.Target
}

func stockRetirementMatches(result stockGeneratedResult, duty stockGeneratedFact) bool {
	if len(result.Effects) != 1 || len(result.Duties) != 0 ||
		!result.Warnings.InvalidationNotConfirmed || result.DeletionAcknowledgedCount != 1 ||
		result.InvalidationConfirmedCount != 0 || result.UnknownCount != 0 {
		return false
	}
	domain, domainErr := artifact.ParseDigest(result.Domain)
	operation, operationErr := artifact.ParseDigest(result.OperationID)
	originalOperation, originalOperationErr := artifact.ParseDigest(duty.Target.OriginalOperation)
	originalAttempt, originalAttemptErr := artifact.ParseDigest(duty.Target.OriginalAttempt)
	resource, resourceErr := artifact.ParseDigest(duty.Target.Resource)
	if domainErr != nil || operationErr != nil || originalOperationErr != nil || originalAttemptErr != nil || resourceErr != nil || operation == originalOperation {
		return false
	}
	requestedDuty, err := contract.GeneratorDutyID(contract.ID(domain), contract.ID(originalOperation), contract.ID(originalAttempt), contract.GeneratedDutyRetirement)
	if err != nil || artifact.Digest(requestedDuty).String() != duty.Facts.Duty {
		return false
	}
	lineage, err := contract.GeneratorObligationLineageID(contract.ID(domain), contract.ID(operation), contract.ID(resource), contract.GeneratorLineageRetirement)
	if err != nil {
		return false
	}
	attempt, err := contract.GeneratorAttemptID(lineage, contract.GeneratorBranchInitial)
	if err != nil {
		return false
	}
	v := result.Effects[0]
	return v.Facts.Duty == "" && v.Facts.Hazard == "" && v.Facts.Operation == result.OperationID &&
		v.Facts.Lineage == artifact.Digest(lineage).String() && v.Facts.Attempt == artifact.Digest(attempt).String() &&
		v.Facts.Descriptor == duty.Facts.Descriptor && v.Facts.Executor == duty.Facts.Executor &&
		v.Facts.Name == duty.Target.Name && v.Facts.Incarnation == duty.Target.Incarnation && v.Facts.Epoch == duty.Target.Epoch &&
		v.Facts.PlannedResource == duty.Facts.Resource && v.Facts.ConfigContract == duty.Facts.ConfigContract && v.Facts.ResourceContract == duty.Facts.ResourceContract && v.Facts.Lifecycle == duty.Facts.Lifecycle &&
		v.Facts.ResourceDigest == duty.Target.Digest &&
		v.Facts.CredentialRoute == duty.Facts.CredentialRoute && v.Facts.ResultContract == duty.Facts.ResultContract &&
		v.Facts.Action == "delete" && v.Facts.State == "succeeded" && v.Facts.Completion == "deletion-acknowledged" &&
		v.Facts.Evidence == "deletion-acknowledged" && v.Facts.Warnings.InvalidationNotConfirmed && v.Target == duty.Target
}

func stockRetirementEvidence(phase string, result stockGeneratedResult, duty stockGeneratedFact) records.StockPluginRetirement {
	return records.StockPluginRetirement{
		Phase: phase, DutyID: duty.Facts.Duty,
		DeletionAcknowledgedCount: result.DeletionAcknowledgedCount, InvalidationConfirmedCount: result.InvalidationConfirmedCount,
		UnknownCount: result.UnknownCount, InvalidationNotConfirmed: result.Warnings.InvalidationNotConfirmed,
		EffectInvalidationNotConfirmed: result.Effects[0].Facts.Warnings.InvalidationNotConfirmed,
	}
}

func stockCreateMatches(result stockGeneratedResult, current stockGeneratedCurrent, descriptor, executor, route string) (stockGeneratedFact, bool) {
	var created stockGeneratedFact
	count := 0
	for _, effect := range result.Effects {
		if effect.Facts.Action != "create" || effect.Facts.State != "succeeded" {
			continue
		}
		count++
		created = effect
	}
	if count != 1 {
		return stockGeneratedFact{}, false
	}
	facts, target := created.Facts, created.Target
	valid := facts.Operation == current.OriginOperation && facts.Attempt == current.OriginAttempt &&
		facts.Generation == current.Generation && facts.PlannedResource == current.Resource && facts.ResourceDigest == current.Digest &&
		facts.Name == current.Name && facts.Incarnation == current.Incarnation && facts.Epoch == current.Epoch &&
		facts.ConfigContract == current.ConfigContract && facts.ResourceContract == current.ResourceContract && facts.Lifecycle == current.Lifecycle &&
		facts.Descriptor == descriptor && facts.Executor == executor && facts.CredentialRoute == route && publicIdentityHex(facts.ResultContract) &&
		target.Name == current.Name && target.Incarnation == current.Incarnation && target.Epoch == current.Epoch &&
		target.Resource == current.Resource && target.Digest == current.Digest && target.ConfigContract == current.ConfigContract &&
		target.ResourceContract == current.ResourceContract && target.Lifecycle == current.Lifecycle && target.ResultContract == facts.ResultContract &&
		target.Completion == current.Completion &&
		target.OriginalOperation == current.OriginOperation && target.OriginalAttempt == current.OriginAttempt
	return created, valid
}

func stockCreateForBuild(result stockGeneratedResult, current stockGeneratedCurrent, metadata artifact.Metadata) (stockGeneratedFact, bool) {
	facts, err := metadata.GeneratorFacts()
	if err != nil || facts.Descriptor.Generator.ConfigContractID.String() != current.ConfigContract {
		return stockGeneratedFact{}, false
	}
	route, err := credentialroute.Decode(facts.Descriptor.Generator.CredentialRoute)
	if err != nil {
		return stockGeneratedFact{}, false
	}
	routeID, err := credentialroute.Identity(route)
	if err != nil {
		return stockGeneratedFact{}, false
	}
	return stockCreateMatches(result, current, facts.DescriptorID.String(), facts.ExecutorID.String(), artifact.Digest(routeID).String())
}

func stockCreateEvidence(phase string, effect stockGeneratedFact) records.StockPluginCreate {
	facts := effect.Facts
	return records.StockPluginCreate{
		Phase: phase, OperationID: facts.Operation, AttemptID: facts.Attempt, GenerationID: facts.Generation,
		ResourceID: facts.PlannedResource, ResourceDigest: facts.ResourceDigest, DescriptorID: facts.Descriptor,
		ExecutorID: facts.Executor, CredentialRouteID: facts.CredentialRoute, ConfigContractID: facts.ConfigContract,
		ResourceContractID: facts.ResourceContract, ResultContractID: facts.ResultContract,
	}
}

func stockGenerationEvidence(phase string, v stockGeneratedCurrent) records.StockPluginGeneration {
	return records.StockPluginGeneration{Phase: phase, Epoch: v.Epoch, GenerationID: v.Generation, ResourceID: v.Resource, ResourceDigest: v.Digest, OriginOperationID: v.OriginOperation, OriginAttemptID: v.OriginAttempt}
}
func stockDutyEvidence(phase string, v stockGeneratedFact) records.StockPluginDuty {
	return records.StockPluginDuty{Phase: phase, DutyID: v.Facts.Duty, ResourceID: v.Facts.Resource, DescriptorID: v.Facts.Descriptor, ExecutorID: v.Facts.Executor, CredentialRouteID: v.Facts.CredentialRoute, ResultContractID: v.Facts.ResultContract, OriginalOperationID: v.Facts.OriginalOperation, OriginalAttemptID: v.Facts.OriginalAttempt}
}

func stockTokenBytes(body []byte) ([]byte, error) {
	value, ok := bytes.CutPrefix(body, []byte("generated="))
	if !ok || len(value) < 11 || len(value) > 257 || value[len(value)-1] != '\n' {
		return nil, errInventory
	}
	value = value[:len(value)-1]
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return nil, errInventory
		}
	}
	return bytes.Clone(value), nil
}

// This independent read uses the selected token, not the account administration
// bearer. Its returned ID identifies that known selected token only.
func stockVerifyCloudflare(ctx context.Context, client *http.Client, account string, token []byte) (string, error) {
	call := telemetry.Start(ctx, telemetry.ProviderWorker, telemetry.OpSetupVerifyCloudflare)
	ctx = telemetry.CallContext(ctx, call)
	if ctx == nil || ctx.Err() != nil || client == nil || !validCloudflareFixtureID(account) || len(token) < 10 || len(token) > 256 {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return "", errInventory
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
			return "", errInventory
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/accounts/"+account+"/tokens/verify", nil)
	if err != nil {
		call.FinishReason(telemetry.ResultAdmissionRefused, telemetry.DiagnosticReasonAdmissionInvalid)
		return "", errInventory
	}
	request.Header.Set("Authorization", "Bearer "+string(token))
	response, err := client.Do(request)
	if err != nil {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable)
		return "", errInventory
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, stockVerificationBytes+1))
	closeErr := response.Body.Close()
	defer clear(body)
	if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || ctx.Err() != nil {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonReadUnavailable)
		return "", errInventory
	}
	if len(body) > stockVerificationBytes {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonCapacityExceeded)
		return "", errInventory
	}
	var out struct {
		Success bool              `json:"success"`
		Errors  []json.RawMessage `json:"errors"`
		Result  struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"result"`
	}
	if jsonv2.Unmarshal(body, &out) != nil || !out.Success || out.Errors == nil || len(out.Errors) != 0 || !validCloudflareFixtureID(out.Result.ID) || out.Result.Status != "active" {
		call.FinishReason(telemetry.ResultFailure, telemetry.DiagnosticReasonInvalidFormat)
		return "", errInventory
	}
	call.Finish(telemetry.ResultSuccess)
	return out.Result.ID, nil
}

func stockVerificationClient() (*http.Client, func()) {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: stockVerificationBytes, DisableCompression: true}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport.CloseIdleConnections
}

type stockVerificationTransport func(*http.Request) (*http.Response, error)

func (f stockVerificationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// full_only: false
func TestStockCloudflareVerificationBindsSelectedTokenAndCompleteReply(t *testing.T) {
	const account = "0123456789abcdef0123456789abcdef"
	const token = "selected_private_token"
	for _, tc := range []struct {
		name, body string
		status     int
		failure    bool
	}{
		{"active", `{"success":true,"errors":[],"result":{"id":"abcdef0123456789abcdef0123456789","status":"active"}}`, 200, false},
		{"disabled", `{"success":true,"errors":[],"result":{"id":"abcdef0123456789abcdef0123456789","status":"disabled"}}`, 200, true},
		{"missing-id", `{"success":true,"errors":[],"result":{"status":"active"}}`, 200, true},
		{"provider-error", `{"success":true,"errors":[{"code":1000}],"result":{"id":"abcdef0123456789abcdef0123456789","status":"active"}}`, 200, true},
		{"second-document", `{"success":true,"errors":[],"result":{"id":"abcdef0123456789abcdef0123456789","status":"active"}} {}`, 200, true},
		{"denied", `{"success":false}`, 403, true},
		{"oversized", strings.Repeat("x", stockVerificationBytes+1), 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: stockVerificationTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "GET" || r.URL.String() != "https://api.cloudflare.com/client/v4/accounts/"+account+"/tokens/verify" || r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("verification changed account, token or method")
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			id, err := stockVerifyCloudflare(t.Context(), client, account, []byte(token))
			if (err != nil) != tc.failure || calls != 1 || !tc.failure && id != "abcdef0123456789abcdef0123456789" {
				t.Fatal("bounded selected-token verification outcome differs")
			}
		})
	}
	client := &http.Client{Transport: stockVerificationTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("controlled unavailable") })}
	if _, err := stockVerifyCloudflare(t.Context(), client, account, []byte(token)); err == nil {
		t.Fatal("transport failure became successful verification")
	}
}

// full_only: false
func TestStockGeneratedResultRejectsUncertaintyAndLaterMemberDamage(t *testing.T) {
	const warnings = `{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":false}`
	const base = `{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"retirement-pending",` +
		`"request_identity":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"commit_may_have_occurred":false,"effect_warnings":` + warnings +
		`,"effects_available":true,"summary_counts_available":true,"related_work_available":true,` +
		`"deletion_acknowledged_count":0,"invalidation_confirmed_count":0,"unknown_count":0,` +
		`"summary_counts":{"effects":0,"outputs":0,"duties":2,"hazards":0,"changed_access":0,"succeeded":0,` +
		`"failed":0,"neutral":0,"pending":2,"unknown":0,"preserved_residue":0,"no_effect_predecessors":0},` +
		`"effects":[],"hazards":[],"duties":[{"facts":{"duty_id":"first","warnings":` + warnings +
		`}},{"facts":{"duty_id":"second","warnings":` + warnings + `}}]}`
	for _, condition := range []string{"exact", "unknown-count", "hazard", "late-second-duty", "unknown-second-effect", "wrong-exit", "unknown-commit", "missing-commit", "null-commit", "duplicate-commit", "null-counts", "missing-count", "missing-warning", "null-effects", "missing-availability"} {
		t.Run(condition, func(t *testing.T) {
			body := base
			code := 3
			switch condition {
			case "unknown-count":
				body = strings.Replace(body, `"unknown":0`, `"unknown":1`, 1)
			case "hazard":
				body = strings.Replace(body, `"hazards":[]`, `"hazards":[{}]`, 1)
			case "late-second-duty":
				body = strings.Replace(body, `"duty_id":"second","warnings":`+warnings, `"duty_id":"second","warnings":{"possible_live_residue":false,"late_effect":true,"invalidation_not_confirmed":false}`, 1)
			case "unknown-second-effect":
				body = strings.Replace(body, `"effects":[]`, `"effects":[{"facts":{"state":"succeeded","warnings":`+warnings+`}},{"facts":{"state":"unknown","warnings":`+warnings+`}}]`, 1)
			case "wrong-exit":
				code = 0
			case "unknown-commit":
				body = strings.Replace(body, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true`, 1)
			case "missing-commit":
				body = strings.Replace(body, `"commit_may_have_occurred":false,`, ``, 1)
			case "null-commit":
				body = strings.Replace(body, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":null`, 1)
			case "duplicate-commit":
				body = strings.Replace(body, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":true,"commit_may_have_occurred":false`, 1)
			case "null-counts":
				body = strings.Replace(body, `"summary_counts":{"effects":0,"outputs":0,"duties":2,"hazards":0,"changed_access":0,"succeeded":0,"failed":0,"neutral":0,"pending":2,"unknown":0,"preserved_residue":0,"no_effect_predecessors":0}`, `"summary_counts":null`, 1)
			case "missing-count":
				body = strings.Replace(body, `"unknown":0,`, ``, 1)
			case "missing-warning":
				body = strings.Replace(body, `"duty_id":"second","warnings":`+warnings, `"duty_id":"second"`, 1)
			case "null-effects":
				body = strings.Replace(body, `"effects":[]`, `"effects":null`, 1)
			case "missing-availability":
				body = strings.Replace(body, `"summary_counts_available":true,`, ``, 1)
			}
			_, err := stockGeneratedDecode([]byte(body), code, "retirement-pending")
			if (err == nil) != (condition == "exact") {
				t.Fatal("generated uncertainty or later-member damage was accepted")
			}
		})
	}
}

// full_only: false
func TestStockGeneratedListRequiresItsReadOnlySafetyFields(t *testing.T) {
	const base = `{"schema":"ProductResult/v1","operation_kind":"generated-list","state_result":"success","observed_revision_id":"1111111111111111111111111111111111111111111111111111111111111111","snapshot_id":"2222222222222222222222222222222222222222222222222222222222222222","effect_warnings":{"possible_live_residue":false,"late_effect":false,"invalidation_not_confirmed":true},"active_operation":null,"current_generations":[],"attempts":[],"duties":[],"hazards":[],"pending_releases":[],"next_actions":[]}`
	for _, condition := range []string{"exact", "missing-attempts", "null-duties", "missing-warning", "active-operation", "pending-release", "missing-releases", "null-releases", "missing-revision", "null-snapshot"} {
		t.Run(condition, func(t *testing.T) {
			body := base
			switch condition {
			case "missing-attempts":
				body = strings.Replace(body, `"attempts":[],`, ``, 1)
			case "null-duties":
				body = strings.Replace(body, `"duties":[]`, `"duties":null`, 1)
			case "missing-warning":
				body = strings.Replace(body, `"late_effect":false,`, ``, 1)
			case "active-operation":
				body = strings.Replace(body, `"active_operation":null`, `"active_operation":{}`, 1)
			case "missing-releases":
				body = strings.Replace(body, `"pending_releases":[],`, "", 1)
			case "null-releases":
				body = strings.Replace(body, `"pending_releases":[]`, `"pending_releases":null`, 1)
			case "pending-release":
				body = strings.Replace(body, `"pending_releases":[]`, `"pending_releases":[{"state":"unknown"}]`, 1)
			case "missing-revision":
				body = strings.Replace(body, `"observed_revision_id":"1111111111111111111111111111111111111111111111111111111111111111",`, ``, 1)
			case "null-snapshot":
				body = strings.Replace(body, `"snapshot_id":"2222222222222222222222222222222222222222222222222222222222222222"`, `"snapshot_id":null`, 1)
			}
			_, err := stockGeneratedDecode([]byte(body), 0, "success")
			if (err == nil) != (condition == "exact") {
				t.Fatal("stock list accepted an unavailable or unresolved safety field")
			}
		})
	}
}

// full_only: false
func TestStockTokenMaterializationAcceptsOnlyOneExactPrivateValue(t *testing.T) {
	for _, body := range []string{"generated=token_0123456789\n", "generated='token_0123456789'\n", "other=token_0123456789\n", "generated=token_0123456789\nother=value\n", "generated=short\n"} {
		value, err := stockTokenBytes([]byte(body))
		if (err == nil) != (body == "generated=token_0123456789\n") {
			t.Fatal("token materialization accepted another private projection")
		}
		clear(value)
	}
}

func stockSameGeneratedSelection(a, b stockGeneratedResult) bool {
	return a.Revision == b.Revision && a.Snapshot == b.Snapshot &&
		reflect.DeepEqual(a.Current, b.Current) && reflect.DeepEqual(a.Duties, b.Duties) &&
		reflect.DeepEqual(a.Hazards, b.Hazards) && reflect.DeepEqual(a.PendingReleases, b.PendingReleases) && reflect.DeepEqual(a.Attempts, b.Attempts) && reflect.DeepEqual(a.Effects, b.Effects)
}

// full_only: false
func TestStockNoOpAndMissingSupportPreserveAnchorsAndCompleteAttempts(t *testing.T) {
	before := stockGeneratedResult{
		Revision:        "1111111111111111111111111111111111111111111111111111111111111111",
		Snapshot:        "2222222222222222222222222222222222222222222222222222222222222222",
		Current:         []stockGeneratedCurrent{{Name: "generated", Generation: "unchanged"}},
		Duties:          []stockGeneratedFact{{Facts: stockGeneratedSupport{Duty: "accepted"}}},
		Attempts:        []json.RawMessage{json.RawMessage(`{"facts":{"attempt_id":"first","stage":1}}`), json.RawMessage(`{"facts":{"attempt_id":"second","stage":2}}`)},
		PendingReleases: []stockGeneratedRelease{{Inbox: "first", Result: "first", HandoffDigest: "first", HandoffRevision: "first", State: "pending", ObjectLength: 1505}, {Inbox: "second", Result: "second", HandoffDigest: "second", HandoffRevision: "second", State: "pending", ObjectLength: 1505}},
	}
	for _, condition := range []string{"exact", "revision", "snapshot", "later-attempt", "missing-attempt", "extra-attempt", "later-release-inbox", "later-release-result", "later-release-digest", "later-release-revision", "later-release-state", "later-release-length", "missing-release", "extra-release"} {
		t.Run(condition, func(t *testing.T) {
			after := before
			after.Attempts = append([]json.RawMessage{}, before.Attempts...)
			after.PendingReleases = append([]stockGeneratedRelease{}, before.PendingReleases...)
			switch condition {
			case "revision":
				after.Revision = before.Snapshot
			case "snapshot":
				after.Snapshot = before.Revision
			case "later-attempt":
				after.Attempts[1] = json.RawMessage(`{"facts":{"attempt_id":"second","stage":3}}`)
			case "missing-attempt":
				after.Attempts = after.Attempts[:1]
			case "extra-attempt":
				after.Attempts = append(after.Attempts, after.Attempts[0])
			case "later-release-inbox":
				after.PendingReleases[1].Inbox = "changed"
			case "later-release-result":
				after.PendingReleases[1].Result = "changed"
			case "later-release-digest":
				after.PendingReleases[1].HandoffDigest = "changed"
			case "later-release-revision":
				after.PendingReleases[1].HandoffRevision = "changed"
			case "later-release-state":
				after.PendingReleases[1].State = "unknown"
			case "later-release-length":
				after.PendingReleases[1].ObjectLength++
			case "missing-release":
				after.PendingReleases = after.PendingReleases[:1]
			case "extra-release":
				after.PendingReleases = append(after.PendingReleases, after.PendingReleases[0])
			}
			if stockSameGeneratedSelection(before, after) != (condition == "exact") {
				t.Fatal("unchanged value and Duty hid a changed selected anchor or attempt history")
			}
		})
	}
}

// full_only: false
func TestStockSelectedCreateRequiresBExecutorIndependentlyOfRetirementDuty(t *testing.T) {
	const one = "1111111111111111111111111111111111111111111111111111111111111111"
	const two = "2222222222222222222222222222222222222222222222222222222222222222"
	const three = "3333333333333333333333333333333333333333333333333333333333333333"
	current := stockGeneratedCurrent{
		Name: "generated", Incarnation: one, Generation: two, Epoch: 2,
		Resource: three, Digest: one, OriginOperation: two, OriginAttempt: three,
		ConfigContract: one, ResourceContract: two, Lifecycle: "managed", RetirementPolicy: "manual",
	}
	base := stockGeneratedFact{Facts: stockGeneratedSupport{
		Action: "create", State: "succeeded", Operation: two, Attempt: three, Generation: two,
		PlannedResource: three, ResourceDigest: one, Name: "generated", Incarnation: one, Epoch: 2,
		ConfigContract: one, ResourceContract: two, Lifecycle: "managed",
		Descriptor: three, Executor: two, CredentialRoute: one, ResultContract: three,
	}}
	base.Target.Name, base.Target.Incarnation, base.Target.Epoch = "generated", one, 2
	base.Target.Resource, base.Target.Digest = three, one
	base.Target.ConfigContract, base.Target.ResourceContract, base.Target.Lifecycle = one, two, "managed"
	base.Target.OriginalOperation, base.Target.OriginalAttempt, base.Target.ResultContract = two, three, three
	for _, condition := range []string{"exact-b", "a-executor", "a-route", "wrong-origin", "wrong-resource", "wrong-target-epoch", "wrong-contract", "missing-result-contract", "two-successful-creates"} {
		t.Run(condition, func(t *testing.T) {
			fact := base
			switch condition {
			case "a-executor":
				fact.Facts.Executor = one
			case "a-route":
				fact.Facts.CredentialRoute = three
			case "wrong-origin":
				fact.Facts.Operation = one
			case "wrong-resource":
				fact.Facts.PlannedResource = two
			case "wrong-target-epoch":
				fact.Target.Epoch = 1
			case "wrong-contract":
				fact.Facts.ResourceContract = three
			case "missing-result-contract":
				fact.Facts.ResultContract = ""
			}
			result := stockGeneratedResult{Effects: []stockGeneratedFact{fact}}
			if condition == "two-successful-creates" {
				result.Effects = append(result.Effects, fact)
			}
			_, matched := stockCreateMatches(result, current, three, two, one)
			if matched != (condition == "exact-b") {
				t.Fatal("selected B creation was inferred from an unrelated retirement Duty")
			}
		})
	}
}

// full_only: false
func TestStockRetirementPreservesDeletionAcknowledgementCeiling(t *testing.T) {
	var selected, base stockGeneratedResult
	if json.Unmarshal([]byte(stockWireListA1), &selected) != nil || len(selected.Duties) != 1 || json.Unmarshal([]byte(stockWireRetirementACK), &base) != nil {
		t.Fatal("fixed retirement acknowledgement input was refused")
	}
	duty := selected.Duties[0]
	for _, condition := range []string{"exact-ack", "global-warning-lost", "effect-warning-lost", "zero-ack", "two-acks", "confirmed-counter", "unknown-counter", "confirmed-class", "wrong-route"} {
		t.Run(condition, func(t *testing.T) {
			result := base
			result.Effects = append([]stockGeneratedFact{}, base.Effects...)
			switch condition {
			case "global-warning-lost":
				result.Warnings.InvalidationNotConfirmed = false
			case "effect-warning-lost":
				result.Effects[0].Facts.Warnings.InvalidationNotConfirmed = false
			case "zero-ack":
				result.DeletionAcknowledgedCount = 0
			case "two-acks":
				result.DeletionAcknowledgedCount = 2
			case "confirmed-counter":
				result.InvalidationConfirmedCount = 1
			case "unknown-counter":
				result.UnknownCount = 1
			case "confirmed-class":
				result.Effects[0].Facts.Completion = "invalidation-confirmed"
			case "wrong-route":
				result.Effects[0].Facts.CredentialRoute = "different"
			}
			if stockRetirementMatches(result, duty) != (condition == "exact-ack") {
				t.Fatal("stock retirement erased an acknowledgement warning or claimed confirmed invalidation")
			}
		})
	}
}

// full_only: false
func TestStockGeneratedCommonNoOpRequiresExplicitNoCommitAndValidIdentity(t *testing.T) {
	const base = `{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"no-op","request_identity":"1111111111111111111111111111111111111111111111111111111111111111","commit_may_have_occurred":false,"warning_summary":[],"payload":null}`
	t.Run("retirement-refusal", func(t *testing.T) {
		body := strings.NewReplacer(`"operation_kind":"apply-declaration"`, `"operation_kind":"retire-generated-generation"`, `"state_result":"no-op"`, `"state_result":"refused"`).Replace(base)
		if _, err := stockGeneratedDecode([]byte(body), 2, "refused"); err != nil {
			t.Fatal("common retirement refusal required completed effect fields", err)
		}
	})
	for _, condition := range []string{"exact", "missing-commit", "null-commit", "missing-identity", "null-warnings", "missing-payload", "wrong-operation"} {
		t.Run(condition, func(t *testing.T) {
			body := base
			switch condition {
			case "missing-commit":
				body = strings.Replace(body, `"commit_may_have_occurred":false,`, ``, 1)
			case "null-commit":
				body = strings.Replace(body, `"commit_may_have_occurred":false`, `"commit_may_have_occurred":null`, 1)
			case "missing-identity":
				body = strings.Replace(body, `"request_identity":"1111111111111111111111111111111111111111111111111111111111111111",`, ``, 1)
			case "null-warnings":
				body = strings.Replace(body, `"warning_summary":[]`, `"warning_summary":null`, 1)
			case "missing-payload":
				body = strings.Replace(body, `,"payload":null`, ``, 1)
			case "wrong-operation":
				body = strings.Replace(body, "apply-declaration", "unknown-operation", 1)
			}
			_, err := stockGeneratedDecode([]byte(body), 0, "no-op")
			if (err == nil) != (condition == "exact") {
				t.Fatal("stock common no-op treated unavailable safety facts as known absence")
			}
		})
	}
}

// full_only: false
func TestStockCLIProductExitsRequirePositiveProcessJoin(t *testing.T) {
	privateState := func(t *testing.T) string {
		t.Helper()
		state, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(state, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := records.SafePath(state, "stock-result-00.json"); err != nil {
			t.Fatal("controlled diagnostic directory is not canonical", err)
		}
		return state
	}
	t.Run("bounded-diagnostic-projection", func(t *testing.T) {
		const id = "1111111111111111111111111111111111111111111111111111111111111111"
		row := `{"facts":{"attempt_id":"` + id + `","state":"unknown","fenced":false},"target":{"resource_digest":"` + id + `"}}`
		prefix := `{"schema":"ProductResult/v1","operation_kind":"generated-list","state_result":"success","effects":[`
		body := prefix
		for len(body)+len(row)+2 < operatorCLICaptureLimit-300 {
			if body != prefix {
				body += ","
			}
			body += row
		}
		body += `],"local_delivery":{"path":"","destination":"not-a-safe-output"}}`
		projection, fault := stockProjectDiagnostic([]byte(body))
		if fault != "" || len(projection) == 0 || bytes.Contains(projection, []byte("not-a-safe-output")) {
			t.Fatal("bounded projection failed or disclosed an excluded path", fault)
		}
		var value map[string]json.RawMessage
		var delivery map[string]json.RawMessage
		if json.Unmarshal(projection, &value) != nil || json.Unmarshal(value["local_delivery"], &delivery) != nil || string(delivery["path_present"]) != "false" || string(delivery["destination_present"]) != "true" {
			t.Fatal("path presence was not retained")
		}
		record := stockDiagnostic{Schema: 1, RunID: "20261031T123456Z-" + strings.Repeat("a", 32), Ordinal: 63, Worker: strings.Repeat("w", 96), Nonce: strings.Repeat("b", 32), Phase: strings.Repeat("p", 96), CLISHA256: id, ResultSHA256: id, DigestScope: "captured-prefix", CapturedBytes: operatorCLICaptureLimit, StderrCapturedBytes: operatorCLICaptureLimit, Status: "unavailable", Fault: "unsupported-container", Uncaptured: []string{"names", "filesystem-paths", "locators", "values", "warning-text", "source-identifiers", "semantic-completeness"}}
		header, err := json.Marshal(record)
		if err != nil || !stockDiagnosticMetadata(record) || len(header)+1 > stockDiagnosticHeaderAllowance {
			t.Fatal("maximum diagnostic header exceeded its fixed allowance", len(header), err)
		}
		record.Result = projection
		encoded, err := json.Marshal(record)
		if err != nil || len(encoded)+1 > 3*len(body)+stockDiagnosticHeaderAllowance || len(encoded)+1 > stockDiagnosticFileLimit {
			t.Fatal("encoded diagnostic exceeded its bound", len(encoded), len(body), err)
		}
		for _, key := range []string{"path", "destination", "target_path", "editable_path", "generated_path", "manifest_path", "recovery_source", "residue_path"} {
			for _, path := range []string{`""`, `"\\\"\u003c"`, `null`} {
				body := `{"schema":"ProductResult/v1","local_delivery":{"` + key + `":` + path + `}}`
				projection, fault := stockProjectDiagnostic([]byte(body))
				if fault != "" || len(projection) > 3*len(body) {
					t.Fatal("path presence exceeded the projection bound", key, fault)
				}
			}
		}
		for _, body := range []string{`{"schema":"ProductResult/v1","receipt_hex":""}`, `{"schema":"ProductResult/v1","outputs":[]}`, `{"schema":"ProductResult/v1","outputs":["none","authority"]}`, `{"schema":"ProductResult/v1","payload":{"format_contract_id":""}}`, `{"schema":"ProductResult/v1","payload":{"format_contract_id":null}}`} {
			projection, fault := stockProjectDiagnostic([]byte(body))
			if fault != "" || len(projection) > 3*len(body) {
				t.Fatal("fixed presence or count substitution exceeded its bound", fault)
			}
		}
		bad := `{"schema":"ProductResult/v1","effects":[` + row + `,{"facts":{"attempt_id":"secret-token"}}]}`
		partial, fault := stockProjectDiagnostic([]byte(bad))
		if fault != "invalid-id" || !bytes.Contains(partial, []byte(id)) || bytes.Contains(partial, []byte("secret-token")) {
			t.Fatal("invalid later row did not retain only the approved prefix", fault)
		}
		preAdmission, fault := stockProjectDiagnostic([]byte(publicPreAdmissionJSON))
		if fault != "" || !bytes.Contains(preAdmission, []byte(`"stage":"capture"`)) || !bytes.Contains(preAdmission, []byte(`"code":"missing-required-field"`)) || !bytes.Contains(preAdmission, []byte(`"request_nonce":`)) {
			t.Fatal("pre-admission identity was not retained", fault)
		}
		manifestRefusal := `{"schema":"ManifestFileResult/v2","issuance":` + strings.ReplaceAll(publicPreAdmissionJSON, "apply-declaration", "issue-consumption-manifest") + `,"delivery":null}`
		manifestRefusalProjection, fault := stockProjectDiagnostic([]byte(manifestRefusal))
		if fault != "" || !bytes.Contains(manifestRefusalProjection, []byte(`"request_identity":{`)) || !bytes.Contains(manifestRefusalProjection, []byte(`"stage":"capture"`)) || !bytes.Contains(manifestRefusalProjection, []byte(`"code":"missing-required-field"`)) || !bytes.Contains(manifestRefusalProjection, []byte(`"operation_id":"4444444444444444444444444444444444444444444444444444444444444444"`)) {
			t.Fatal("nested manifest pre-admission identity was not retained", fault)
		}
		publication := `{"schema":"ProductResult/v1","operation_kind":"publish","state_result":"effect-unknown","effect_summary":"effect-unknown","output_summary":"output-unknown","reason_code":3,"entry":"generated","outputs":[{"facts":{"attempt_id":"` + id + `","state":"unknown"}}],"result":{"outcome":"unknown","commit_may_have_occurred":false},"payload":{"schema":"OutputPayload/v3","selection_digest":"` + id + `","entries":[{"coordinate_id":"` + id + `","target":{"origin":"retained-deletion","entry_name":null,"destination_id":"PRIVATE DESTINATION","service_contract_id":"PRIVATE SERVICE","canonical_target":"PRIVATE TARGET"},"actions":[{"action":"delete-owned","blocker_ids":["` + id + `"],"evidence":{"schema":"PublicationEvidence/v3","entry":"may-have-entered","class":"unproved","normalized_status":0}}]}]}}`
		publicationProjection, fault := stockProjectDiagnostic([]byte(publication))
		if fault != "" || bytes.Contains(publicationProjection, []byte("PRIVATE")) || bytes.Contains(publicationProjection, []byte(`"entry":"generated"`)) || !bytes.Contains(publicationProjection, []byte(`"entry":"may-have-entered"`)) || !bytes.Contains(publicationProjection, []byte(`"outputs":[`)) || !bytes.Contains(publicationProjection, []byte(`"result":{`)) || !bytes.Contains(publicationProjection, []byte(`"reason_code":3`)) || !bytes.Contains(publicationProjection, []byte(`"selection_digest":"`+id+`"`)) {
			t.Fatal("publication facts or private-name exclusion differ", fault)
		}
		badNested := `{"schema":"ProductResult/v1","payload":{"entries":[{"coordinate_id":"` + id + `","actions":[{"action":"write-value","attempt_id":"` + id + `"},{"action":"secret-token"}]}]}}`
		nestedPrefix, fault := stockProjectDiagnostic([]byte(badNested))
		if fault != "invalid-enum" || !bytes.Contains(nestedPrefix, []byte(`"action":"write-value"`)) || !bytes.Contains(nestedPrefix, []byte(`"attempt_id":`)) || bytes.Contains(nestedPrefix, []byte("secret-token")) {
			t.Fatal("nested partial result lost earlier action facts", fault)
		}
		manifest := `{"schema":"ManifestFileResult/v2","issuance":{"schema":"ProductResult/v1","operation_kind":"issue-consumption-manifest","state_result":"unavailable","effect_summary":"not-applicable","output_summary":"not-applicable","failure_reason":"selected-object-unavailable"},"delivery":{"replacement":"not-attempted","candidate_verification":"not-observed","installed_verification":"not-observed","native_completion":"incomplete","candidate_cleanup":"not-created","residue_path":null,"failure":null},"source_cleanup":"complete","result_delivery":"not-observed"}`
		manifestProjection, fault := stockProjectDiagnostic([]byte(manifest))
		if fault != "" || !bytes.Contains(manifestProjection, []byte(`"source_cleanup":"complete"`)) || !bytes.Contains(manifestProjection, []byte(`"failure_reason":"selected-object-unavailable"`)) || !bytes.Contains(manifestProjection, []byte(`"residue_path_present":null`)) {
			t.Fatal("manifest result facts differ", fault)
		}
		prepare := `{"schema":"enkv/prepare-result/v2","operation":"prepare","branch":"reconstruction","outcome":"incomplete","recovery":{"status":"failed"},"local_delivery":{"outcome":"not-recorded","cleanup_failed":false},"dependencies":{"assessment":"not-attempted","minimum_administrative_ready":false,"all_declared_ready":false,"requirements":[],"installations":[]},"diagnostics":[{"reason":"state-invalid","subject":"recovery"}]}`
		prepareProjection, fault := stockProjectDiagnostic([]byte(prepare))
		if fault != "" || !bytes.Contains(prepareProjection, []byte(`"requirements":[]`)) || !bytes.Contains(prepareProjection, []byte(`"cleanup_failed":false`)) || !bytes.Contains(prepareProjection, []byte(`"subject":"recovery"`)) {
			t.Fatal("prepare result facts differ", fault)
		}
		selectionRequired := strings.Replace(prepare, `"requirements":[]`, `"requirements":[{"role":"output","plugin":null,"contract":"PRIVATE CONTRACT","protocol_version":6,"artifact":null,"status":"missing","reason":"selection-required","subjects":[0]}]`, 1)
		selectionProjection, fault := stockProjectDiagnostic([]byte(selectionRequired))
		if fault != "" || !bytes.Contains(selectionProjection, []byte(`"reason":"selection-required"`)) || bytes.Contains(selectionProjection, []byte("PRIVATE")) {
			t.Fatal("prepare selection-required reason or disclosure differs", fault)
		}
		set := `{"schema":"ProductResult/v1","operation_kind":"set-confidential","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","evidence_ceiling":"exact-local-pair-readback","operation_payload":"SealedArtifactPayload/v1","request_identity":{"schema":"ArtifactRequestIdentity/v1","input_file_id":"` + id + `","target":{"domain_id":"` + id + `","name":"authority"}},"outputs":["/private/secret"],"payload":{"schema":"SealedArtifactPayload/v1","input_file_id":"` + id + `","target":{"domain_id":"` + id + `","name":"generated"}}}`
		setProjection, fault := stockProjectDiagnostic([]byte(set))
		if fault != "" || !bytes.Contains(setProjection, []byte(`"outputs_count":1`)) || !bytes.Contains(setProjection, []byte(`"input_file_id":`)) || bytes.Contains(setProjection, []byte("/private/secret")) || bytes.Contains(setProjection, []byte(`"name":`)) {
			t.Fatal("set result did not keep private paths and names out", fault)
		}
		material := `{"schema":"ProductResult/v1","operation_kind":"materialize","state_result":"unavailable","effect_summary":"not-applicable","output_summary":"not-applicable","operation_payload":"MaterializationPayload/v1","result":{"outcome":2,"reason":3,"evidence":1},"payload":{"schema":"MaterializationPayload/v1","facts":{"replacement":1,"native_completion":2,"cleanup_failure":{"stage":3,"reason":4},"residue_path":"/private/residue"}}}`
		materialProjection, fault := stockProjectDiagnostic([]byte(material))
		if fault != "" || !bytes.Contains(materialProjection, []byte(`"outcome":2`)) || !bytes.Contains(materialProjection, []byte(`"cleanup_failure":{"reason":4,"stage":3}`)) || !bytes.Contains(materialProjection, []byte(`"residue_path_present":true`)) || bytes.Contains(materialProjection, []byte("/private/residue")) {
			t.Fatal("materialization result facts differ", fault)
		}
		preview := `{"schema":"ProductResult/v1","operation_kind":"plan","state_result":"success","operation_payload":"ComparisonPayload/v1","payload":{"schema":"ComparisonPayload/v1","publication":{"schema":"PublicationPreview/v2","complete":true,"entries":[{"coordinate_id":"` + id + `","entry_name":"authority","actions":["write-value","delete-owned"],"blocker_ids":[]}]}}}`
		previewProjection, fault := stockProjectDiagnostic([]byte(preview))
		if fault != "" || !bytes.Contains(previewProjection, []byte(`"actions":["write-value","delete-owned"]`)) || bytes.Contains(previewProjection, []byte(`"entry_name"`)) {
			t.Fatal("preview action vector differs", fault)
		}
		privateWords := `{"schema":"ProductResult/v1","warning_summary":["generated","PRIVATE WARNING"],"payload":{"schema":"ComparisonPayload/v1","entries":[{"entry_name":"generated","consumer_locator":"authority","physical_target":"none"}]},"local_delivery":{"editable_path":"none","generated_path":"authority"}}`
		privateProjection, fault := stockProjectDiagnostic([]byte(privateWords))
		if fault != "" || bytes.Contains(privateProjection, []byte(`"entry_name"`)) || bytes.Contains(privateProjection, []byte(`"consumer_locator"`)) || bytes.Contains(privateProjection, []byte(`"physical_target"`)) || bytes.Contains(privateProjection, []byte(`"warning_summary"`)) || bytes.Contains(privateProjection, []byte("PRIVATE WARNING")) || !bytes.Contains(privateProjection, []byte(`"editable_path_present":true`)) || !bytes.Contains(privateProjection, []byte(`"generated_path_present":true`)) {
			t.Fatal("private enum-looking text was retained", fault)
		}
		generated := `{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"effect-unknown","replay_identity":"` + id + `","receipt_hex":"secret-receipt","effects_available":true,"effects_commitment":{"count":1,"length":2,"digest":"` + id + `"},"effects":[{"facts":{"attempt_id":"` + id + `","state":"unknown"}}]}`
		generatedProjection, fault := stockProjectDiagnostic([]byte(generated))
		if fault != "" || !bytes.Contains(generatedProjection, []byte(`"receipt_hex_present":true`)) || !bytes.Contains(generatedProjection, []byte(`"effects_commitment":`)) || bytes.Contains(generatedProjection, []byte("secret-receipt")) {
			t.Fatal("generated work or receipt presence differs", fault)
		}
		for _, schema := range []string{"InitPayload/v1", "ComparisonPayload/v1", "ManifestPayload/v3"} {
			body := `{"schema":"ProductResult/v1","payload":{"schema":"` + schema + `"}}`
			_, fault := stockProjectDiagnostic([]byte(body))
			if fault != "" {
				t.Fatal("known payload schema refused", schema, fault)
			}
		}
		for _, sample := range []string{publicApplySelectedJSON, publicMaterializationSuccessJSON, stockWireMutationA1, stockWireListA1} {
			projection, fault := stockProjectDiagnostic([]byte(sample))
			if fault != "" || len(projection) == 0 || bytes.Contains(projection, []byte(`"name":`)) {
				t.Fatal("known stock result literal was not projected safely", fault)
			}
		}
		families := []string{"entries", "plain_values", "secret_settings", "memberships", "recipients", "encryption", "generated", "outputs", "routing", "domain_store", "authority_recovery", "compatibility_profiles"}
		var scopes []string
		for _, family := range families {
			scopes = append(scopes, `{"family":"`+family+`","status":"complete"}`)
		}
		comparison := `{"schema":"ProductResult/v1","operation_kind":"compare-public-configuration","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","context":{"operation":"compare-public-configuration","operation_id":"` + id + `","request_id":"` + id + `","expected_domain_id":"` + id + `"},"observation":{"domain_id":"` + id + `","head_revision_id":"` + id + `","snapshot_id":"` + id + `"},"payload":{"schema":"ComparisonPayload/v1","verdict":"match","diagnostics_complete":true,"evidence_limit":"PRIVATE TEXT","checked_scope":[` + strings.Join(scopes, ",") + `],"diagnostics":[{"subject":{"kind":"entry","name":"authority"},"outcome":"difference","reason":"field-differs","path":[{"field":"generated"},{"field":"epoch"}],"source_location":{"source_id":"PRIVATE SOURCE","line":4,"column":2}}],"generated_entries":[{"name":"generated","requested_action":"unchanged","current_source":"generated","requested_source":"generated","current_confidentiality":"secret","requested_confidentiality":"secret","current_incarnation_id":"` + id + `","current_generation_id":"` + id + `","current_epoch":1,"requested_epoch":1,"current_lifecycle_mode":"managed","requested_lifecycle_mode":"managed","current_retirement_policy":"manual","requested_retirement_policy":"manual","changed_public_fields":[],"retirement_consequence":"none","observed_blockers":[],"active_operation_id":null,"retiring_duty_id":null,"retiring_epoch":null,"future_content":"unavailable","public_secret_content":"unchecked"}],"publication":{"schema":"PublicationPreview/v2","complete":true,"reason_code":0,"domain_wide_warning":false,"entries":[{"coordinate_id":"` + id + `","binding_id":"` + id + `","origin":"observed","basis":"warning","entry_name":"authority","actions":["write-value"],"conditional":false,"reason_code":0,"blocker_ids":[],"remote_value_may_remain":false,"late_write_risk":false}]}}}`
		comparisonProjection, fault := stockProjectDiagnostic([]byte(comparison))
		var observed struct {
			Observation map[string]string `json:"observation"`
			Context     map[string]string `json:"context"`
			Payload     struct {
				Verdict     string                            `json:"verdict"`
				Scopes      []struct{ Family, Status string } `json:"checked_scope"`
				Diagnostics []struct {
					Subject         map[string]string
					Outcome, Reason string
					Path            []struct{ Field string }
					SourceLocation  struct{ Line, Column uint64 } `json:"source_location"`
				} `json:"diagnostics"`
				Generated []struct {
					Action   string   `json:"requested_action"`
					Current  string   `json:"current_generation_id"`
					Changed  []string `json:"changed_public_fields"`
					Blockers []string `json:"observed_blockers"`
				} `json:"generated_entries"`
				Publication struct {
					ReasonCode uint64 `json:"reason_code"`
					Entries    []struct {
						Coordinate string   `json:"coordinate_id"`
						Actions    []string `json:"actions"`
					} `json:"entries"`
				} `json:"publication"`
			} `json:"payload"`
		}
		if fault != "" || json.Unmarshal(comparisonProjection, &observed) != nil || observed.Payload.Verdict != "match" || len(observed.Observation) != 3 || len(observed.Context) != 4 || observed.Context["request_id"] != id || len(observed.Payload.Scopes) != len(families) || len(observed.Payload.Diagnostics) != 1 || observed.Payload.Diagnostics[0].Subject["kind"] != "entry" || len(observed.Payload.Diagnostics[0].Subject) != 1 || observed.Payload.Diagnostics[0].Outcome != "difference" || observed.Payload.Diagnostics[0].Reason != "field-differs" || len(observed.Payload.Diagnostics[0].Path) != 2 || observed.Payload.Diagnostics[0].Path[0].Field != "generated" || observed.Payload.Diagnostics[0].Path[1].Field != "epoch" || observed.Payload.Diagnostics[0].SourceLocation.Line != 4 || observed.Payload.Diagnostics[0].SourceLocation.Column != 2 || len(observed.Payload.Generated) != 1 || observed.Payload.Generated[0].Action != "unchanged" || observed.Payload.Generated[0].Current != id || len(observed.Payload.Generated[0].Changed) != 0 || len(observed.Payload.Generated[0].Blockers) != 0 || observed.Payload.Publication.ReasonCode != 0 || len(observed.Payload.Publication.Entries) != 1 || observed.Payload.Publication.Entries[0].Coordinate != id || !reflect.DeepEqual(observed.Payload.Publication.Entries[0].Actions, []string{"write-value"}) || bytes.Contains(comparisonProjection, []byte("PRIVATE")) || bytes.Contains(comparisonProjection, []byte(`"name":`)) || bytes.Contains(comparisonProjection, []byte(`"entry_name":`)) {
			t.Fatal("full comparison view differs or discloses private text", fault)
		}
		for i, scope := range observed.Payload.Scopes {
			if scope.Family != families[i] || scope.Status != "complete" {
				t.Fatal("comparison scope order differs")
			}
		}
		successfulManifest := `{"schema":"ManifestFileResult/v2","issuance":{"schema":"ProductResult/v1","operation_kind":"issue-consumption-manifest","state_result":"success","effect_summary":"not-applicable","output_summary":"not-applicable","observation":{"domain_id":"` + id + `","head_revision_id":"` + id + `","snapshot_id":"` + id + `"},"payload":{"schema":"ManifestPayload/v3","format_contract_id":"example/ini-reference/v1","renderer":{"name":"PRIVATE RENDERER","protocol_id":"` + id + `","descriptor_id":"` + id + `","executor_id":"` + id + `","artifact_contract_id":"` + id + `","dependency_manifest_id":"` + id + `","artifact_id":"` + id + `","artifact_sha256":"` + id + `","artifact_length":7},"artifact_length":8,"artifact_digest":"` + id + `","included_entries":[{"name":"PRIVATE ENTRY","entry_incarnation_id":"` + id + `"}],"excluded_entries":[{"name":"PRIVATE EXCLUDED","entry_incarnation_id":"` + id + `","reason":"no-output"}]}},"delivery":{"target_path":"/private/target","artifact":{"format_contract_id":"example/ini-reference/v1","renderer_artifact_id":"` + id + `","length":8,"digest":"` + id + `"},"replacement":"replaced","candidate_verification":"verified","installed_verification":"verified","native_completion":"complete","candidate_cleanup":"renamed","residue_path":null,"failure":null},"source_cleanup":"complete","result_delivery":"not-observed"}`
		manifestSuccessProjection, fault := stockProjectDiagnostic([]byte(successfulManifest))
		if fault != "" || !bytes.Contains(manifestSuccessProjection, []byte(`"observation":{`)) || !bytes.Contains(manifestSuccessProjection, []byte(`"artifact_digest":"`+id+`"`)) || !bytes.Contains(manifestSuccessProjection, []byte(`"artifact_length":8`)) || !bytes.Contains(manifestSuccessProjection, []byte(`"included_entries":[{"entry_incarnation_id":"`+id+`"}]`)) || !bytes.Contains(manifestSuccessProjection, []byte(`"excluded_entries":[{"entry_incarnation_id":"`+id+`","reason":"no-output"}]`)) || !bytes.Contains(manifestSuccessProjection, []byte(`"format_contract_id_stock_match":true`)) || !bytes.Contains(manifestSuccessProjection, []byte(`"target_path_present":true`)) || bytes.Contains(manifestSuccessProjection, []byte("PRIVATE")) || bytes.Contains(manifestSuccessProjection, []byte("/private/target")) {
			t.Fatal("successful manifest facts differ or disclose private text", fault)
		}
		for _, body := range []string{`{"schema":"ProductResult/v1","effects":1}`, `{"schema":"ProductResult/v1","duties":1}`, `{"schema":"ProductResult/v1","summary_counts":{"effects":1e3}}`, `{"schema":"ProductResult/v1","epoch":1,"epoch":2}`, `{"schema":"ProductResult/v1","epoch":`} {
			_, fault := stockProjectDiagnostic([]byte(body))
			if fault == "" {
				t.Fatal("invalid or noncanonical input was treated as available")
			}
		}
	})
	t.Run("joined-result-is-retained-before-consumer", func(t *testing.T) {
		const result = `{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"effect-unknown","request_identity":"1111111111111111111111111111111111111111111111111111111111111111","commit_may_have_occurred":false,"warning_summary":[],"payload":null}`
		cli := "/bin/cat"
		cliBytes, err := os.ReadFile(cli)
		if err != nil {
			t.Fatal(err)
		}
		inv := records.Invocation{StateDir: privateState(t), Worker: "writer", Nonce: strings.Repeat("a", 32)}
		input := liveRunInput{RunID: strings.Repeat("a", 32), PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Artifact: records.StockPluginArtifact{CLI: records.StockPluginFile{Path: cli, SHA256: bodyDigest(cliBytes), Length: uint64(len(cliBytes))}}}}}
		run := stockPluginRun{t: t, inv: inv, input: input, evidence: records.StockPluginEvidence{Commands: []records.StockPluginCommand{{Ordinal: 0, Worker: inv.Worker, Nonce: inv.Nonce, Phase: "a0-created", Started: true, ExitCode: -1}}}}
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, cli)
		command.Stdin = strings.NewReader(result)
		var stdout, stderr operatorCLIOutput
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cancel()
			if command.ProcessState == nil {
				_ = command.Wait()
			}
		}()
		child := run.completeCommand(ctx, cancel, command, &stdout, &stderr, nil)
		defer clear(child.Body)
		index, err := records.ReadStockPluginEvidence(stockEvidencePath(inv))
		if err != nil || len(index.Commands) != 1 || !index.Commands[0].Joined || index.Commands[0].ResultSHA256 != bodyDigest([]byte(result)) {
			t.Fatal("joined result index was not retained")
		}
		// Reopen the private observation before a caller can assert on the body.
		body, err := os.ReadFile(filepath.Join(inv.StateDir, "stock-result-00.json"))
		if err != nil {
			t.Fatal("joined result diagnostic was not retained", err)
		}
		if index.Commands[0].DiagnosticStatus != "observed" || index.Commands[0].DiagnosticBytes != uint32(len(body)) || index.Commands[0].DiagnosticSHA256 != bodyDigest(body) {
			t.Fatal("diagnostic reference did not bind the verified bytes")
		}
		var observation struct {
			Result struct {
				Operation string `json:"operation_kind"`
				State     string `json:"state_result"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &observation) != nil || observation.Result.Operation != "apply-declaration" || observation.Result.State != "effect-unknown" {
			t.Fatal("retained diagnostic lost approved result facts")
		}
		if child.Code != 0 || string(child.Body) != result {
			t.Fatal("consumer did not receive the joined result")
		}
	})
	t.Run("start-evidence-write-failure-cancels-and-waits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/bin/sh", "-c", "exec sleep 60")
		if err := command.Start(); err != nil {
			t.Fatal("controlled child did not start", err)
		}
		defer func() {
			cancel()
			if command.ProcessState == nil {
				_ = command.Wait()
			}
			if command.ProcessState == nil {
				t.Error("controlled child did not settle during fixture cleanup")
			}
		}()
		// The existing directory cannot be replaced by an evidence file.
		writeErr := records.WriteStockPluginEvidence(t.TempDir(), records.StockPluginEvidence{})
		if writeErr == nil {
			cancel()
			_ = command.Wait()
			t.Fatal("controlled evidence write unexpectedly succeeded")
		}
		waitErr := stockWaitAfterStart(command, writeErr, cancel)
		if waitErr == nil || ctx.Err() != context.Canceled || command.ProcessState == nil {
			t.Fatal("evidence failure returned before the started child settled")
		}
	})
	t.Run("diagnostic-admission-refuses-before-start", func(t *testing.T) {
		for _, condition := range []string{"name-collision", "directory-mode", "index-capacity"} {
			t.Run(condition, func(t *testing.T) {
				base, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				runID := strings.Repeat("b", 32)
				state := filepath.Join(base, "runs", runID, "private", "state")
				if err := os.MkdirAll(state, 0700); err != nil {
					t.Fatal(err)
				}
				guard := &publicGeneratedCleanupTB{TB: t}
				inv := records.Invocation{StateDir: state, Worker: "writer", Nonce: strings.Repeat("a", 32)}
				input := liveRunInput{RunID: runID, Prefix: "enkv-test/fixture", Scenarios: []string{records.StockPluginScenario}, Settings: liveSettings{Provider: "gcp", ProjectNumber: "123456789012"}, Participants: map[string]string{"apply": "apply"}, PublicConfiguration: &publicConfigurationInput{}}
				run := stockPluginRun{t: guard, inv: inv, input: input, evidence: records.StockPluginEvidence{Provider: "gcp"}}
				if !run.diagnosticAdmission("apply", "init") {
					t.Fatal("valid protected fixture refused before damage")
				}
				switch condition {
				case "name-collision":
					if err := os.WriteFile(stockDiagnosticPath(inv, 0), []byte("owned sentinel"), 0600); err != nil {
						t.Fatal(err)
					}
				case "directory-mode":
					if err := os.Chmod(state, 0755); err != nil {
						t.Fatal(err)
					}
				case "index-capacity":
					run.evidence.Prefix = strings.Repeat("x", records.MaximumStockPluginEvidenceBytes)
				}
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							if _, ok := recovered.(publicGeneratedCleanupStop); !ok {
								panic(recovered)
							}
						}
					}()
					run.command(t.Context(), "init", "apply", "", nil)
				}()
				children, err := filepath.Glob(filepath.Join(state, "stock-command-*"))
				if !guard.stopped || guard.message != "stock command diagnostic admission refused" || len(run.evidence.Commands) != 0 || err != nil || len(children) != 0 {
					t.Fatal("diagnostic admission did not stop before child setup")
				}
				if condition == "name-collision" {
					value, err := os.ReadFile(stockDiagnosticPath(inv, 0))
					if err != nil || string(value) != "owned sentinel" {
						t.Fatal("existing diagnostic changed")
					}
				}
			})
		}
	})
	t.Run("start-failure-retains-unavailable", func(t *testing.T) {
		inv := records.Invocation{StateDir: privateState(t), Worker: "writer", Nonce: strings.Repeat("a", 32)}
		input := liveRunInput{RunID: strings.Repeat("b", 32), PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Artifact: records.StockPluginArtifact{CLI: records.StockPluginFile{SHA256: strings.Repeat("c", 64)}}}}}
		run := stockPluginRun{t: t, inv: inv, input: input, evidence: records.StockPluginEvidence{Commands: []records.StockPluginCommand{{Ordinal: 0, Worker: inv.Worker, Nonce: inv.Nonce, Phase: "init", ExitCode: -1}}}}
		command := exec.Command(filepath.Join(inv.StateDir, "absent-executable"))
		if err := command.Start(); err == nil {
			_ = command.Wait()
			t.Fatal("missing controlled executable started")
		}
		if err := run.recordStartFailure(false); err != nil {
			t.Fatal("start failure was not retained", err)
		}
		content, err := records.ReadJSONBytes(stockDiagnosticPath(inv, 0), stockDiagnosticFileLimit)
		var diagnostic stockDiagnostic
		index, indexErr := records.ReadStockPluginEvidence(stockEvidencePath(inv))
		if err != nil || json.Unmarshal(content, &diagnostic) != nil || diagnostic.Started || diagnostic.WaitReturned || diagnostic.Fault != "start-failed" || diagnostic.Status != "unavailable" || indexErr != nil || index.Commands[0].DiagnosticStatus != "unavailable" {
			t.Fatal("start failure acquired a process or available result")
		}
	})
	t.Run("diagnostic-failures-stop-after-wait", func(t *testing.T) {
		for _, condition := range []string{"stdout-overflow", "stderr-overflow", "timeout", "start-save", "name-collision", "index-save", "malformed"} {
			t.Run(condition, func(t *testing.T) {
				cli := "/bin/cat"
				if condition == "timeout" || condition == "start-save" {
					cli = "/bin/sleep"
				}
				cliBytes, err := os.ReadFile(cli)
				if err != nil {
					t.Fatal(err)
				}
				guard := &publicGeneratedCleanupTB{TB: t}
				inv := records.Invocation{StateDir: privateState(t), Worker: "writer", Nonce: strings.Repeat("a", 32)}
				input := liveRunInput{RunID: strings.Repeat("b", 32), PublicConfiguration: &publicConfigurationInput{Stock: &records.StockPluginAcceptanceInput{Artifact: records.StockPluginArtifact{CLI: records.StockPluginFile{Path: cli, SHA256: bodyDigest(cliBytes), Length: uint64(len(cliBytes))}}}}}
				run := stockPluginRun{t: guard, inv: inv, input: input, evidence: records.StockPluginEvidence{Commands: []records.StockPluginCommand{{Ordinal: 0, Worker: inv.Worker, Nonce: inv.Nonce, Phase: "a0-created", Started: true, ExitCode: -1}}}}
				duration := 2 * time.Second
				if condition == "timeout" {
					duration = 100 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(t.Context(), duration)
				defer cancel()
				var command *exec.Cmd
				if cli == "/bin/sleep" {
					command = exec.CommandContext(ctx, cli, "60")
				} else {
					command = exec.CommandContext(ctx, cli)
				}
				body := `{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"effect-unknown"}`
				if condition == "stdout-overflow" || condition == "stderr-overflow" {
					body = strings.Repeat("x", operatorCLICaptureLimit+1)
				}
				if condition == "malformed" {
					body = `{"schema":"ProductResult/v1","secret":"PRIVATE VALUE"`
				}
				command.Stdin = strings.NewReader(body)
				var stdout, stderr operatorCLIOutput
				if condition == "stderr-overflow" {
					command.Stdout = &stderr
				} else {
					command.Stdout = &stdout
				}
				command.Stderr = &stderr
				if err := command.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					cancel()
					if command.ProcessState == nil {
						_ = command.Wait()
					}
				}()
				if condition == "name-collision" {
					if err := os.WriteFile(stockDiagnosticPath(inv, 0), []byte("owned sentinel"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if condition == "index-save" {
					if err := os.Mkdir(stockEvidencePath(inv), 0700); err != nil {
						t.Fatal(err)
					}
				}
				var startErr error
				if condition == "start-save" {
					startErr = errors.New("controlled write failure")
				}
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							if _, ok := recovered.(publicGeneratedCleanupStop); !ok {
								panic(recovered)
							}
						}
					}()
					run.completeCommand(ctx, cancel, command, &stdout, &stderr, startErr)
				}()
				wantStop := "stock child did not return a bounded joined result"
				switch condition {
				case "start-save":
					wantStop = "stock child start could not be retained"
				case "name-collision":
					wantStop = "stock child diagnostic could not be retained"
				case "index-save":
					wantStop = "stock plugin evidence could not be retained"
				}
				if !guard.stopped || guard.message != wantStop || command.ProcessState == nil {
					t.Fatal("failure did not stop for its intended reason after waiting", guard.message, wantStop)
				}
				if condition == "name-collision" {
					content, err := os.ReadFile(stockDiagnosticPath(inv, 0))
					index, indexErr := records.ReadStockPluginEvidence(stockEvidencePath(inv))
					if err != nil || string(content) != "owned sentinel" || indexErr != nil || index.Commands[0].DiagnosticStatus != "write-failed" || index.Commands[0].DiagnosticSHA256 != "" {
						t.Fatal("exclusive diagnostic failure was replaced or hidden")
					}
					return
				}
				content, err := records.ReadJSONBytes(stockDiagnosticPath(inv, 0), stockDiagnosticFileLimit)
				var diagnostic stockDiagnostic
				if err != nil || json.Unmarshal(content, &diagnostic) != nil || !diagnostic.Started || !diagnostic.WaitReturned || !diagnostic.WaitHasProcessState || condition != "index-save" && diagnostic.Status == "observed" || bytes.Contains(content, []byte("PRIVATE VALUE")) {
					t.Fatal("failure diagnostic is missing or claims completion")
				}
				switch condition {
				case "stdout-overflow":
					if !diagnostic.StdoutOverflow || diagnostic.DigestScope != "captured-prefix" || diagnostic.CapturedBytes != operatorCLICaptureLimit {
						t.Fatal("stdout prefix was not identified")
					}
				case "stderr-overflow":
					if !diagnostic.StderrOverflow || diagnostic.StderrCapturedBytes != operatorCLICaptureLimit {
						t.Fatal("stderr capture bound was not identified")
					}
				case "timeout":
					if !diagnostic.TimedOut || diagnostic.ProductJoined {
						t.Fatal("timeout became a joined Product result")
					}
				case "start-save":
					if !diagnostic.StartSaveFailed || diagnostic.ProductJoined {
						t.Fatal("start-save failure was not retained")
					}
				case "malformed":
					if diagnostic.Fault != "malformed" || diagnostic.Status != "unavailable" {
						t.Fatal("malformed output became available")
					}
				case "index-save":
					var raw map[string]json.RawMessage
					if json.Unmarshal(content, &raw) != nil || raw["index_save_failed"] != nil {
						t.Fatal("diagnostic claimed a future index outcome")
					}
				}
			})
		}
	})
	for _, expected := range []int{0, 2, 3} {
		t.Run(strconv.Itoa(expected), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/sh", "-c", "exit "+strconv.Itoa(expected))
			waitErr := command.Run()
			code, joined := stockChildExit(waitErr, ctx.Err(), command.ProcessState != nil)
			if !joined || code != expected {
				t.Fatal("normal Product exit was confused with an unjoined process")
			}
			if _, joined := stockChildExit(waitErr, context.DeadlineExceeded, true); joined {
				t.Fatal("deadline failure became a joined Product result")
			}
			if _, joined := stockChildExit(waitErr, nil, false); joined {
				t.Fatal("missing Wait evidence became a joined Product result")
			}
		})
	}
	if _, joined := stockChildExit(errors.New("controlled process failure"), nil, true); joined {
		t.Fatal("unclassified child failure became a Product exit")
	}
}
