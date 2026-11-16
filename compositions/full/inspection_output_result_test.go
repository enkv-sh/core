package compositionfull

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func inspectionOutputObject(t *testing.T, emit func(*queryObject)) []byte {
	t.Helper()
	var out bytes.Buffer
	w := &resultStreamWriter{ctx: t.Context(), out: &out, limit: publicQueryOutputLimit}
	q := queryBegin(w)
	emit(q)
	q.end()
	if w.err != nil || !json.Valid(out.Bytes()) {
		t.Fatal("public output projection refused", w.err)
	}
	return out.Bytes()
}

// full_only: false
func TestInspectionOutputGenericProjection(t *testing.T) {
	id := contract.ID{1}
	hexID := "01" + strings.Repeat("00", 31)
	policy := contract.OutputPolicy{ContractID: "private/policy/v7", Data: []byte{0, 255, 128}}
	destination := contract.OutputDestination{ConfigContractID: "private/config/v9", ServiceContractID: "private/service/v3", CanonicalSettings: []byte(`{"mode":7}`), Policy: policy, Capabilities: contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy}
	target := contract.OutputTarget{EntryIncarnationID: id, ServiceContractID: destination.ServiceContractID, TargetContractID: "private/target/v5", CanonicalTarget: "room/slot", TargetData: []byte{0, 255, 128}, PayloadEncoding: 2, LocatorRequiresCreation: true, Capabilities: contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy, CreateValueBounds: contract.OutputPayloadBounds{Minimum: 3, Maximum: 37}, WriteValueBounds: contract.OutputPayloadBounds{Minimum: 5, Maximum: 41}, Policy: policy}
	for _, test := range []struct {
		name string
		emit func(*queryObject)
		want string
	}{
		{"destination", func(q *queryObject) { inspectionDestination(q, destination) }, `{"config_contract_id":"private/config/v9","service_contract_id":"private/service/v3","canonical_settings_base64":"eyJtb2RlIjo3fQ==","capabilities":198,"policy":{"contract_id":"private/policy/v7","data_base64":"AP+A"}}`},
		{"target", func(q *queryObject) { inspectionOutputTarget(q, target) }, `{"entry_incarnation_id":"` + hexID + `","service_contract_id":"private/service/v3","target_contract_id":"private/target/v5","canonical_target":"room/slot","consumer_locator":"","target_data_base64":"AP+A","payload_encoding":2,"locator_requires_creation":true,"capabilities":198,"create_value_bounds":{"minimum":3,"maximum":37},"write_value_bounds":{"minimum":5,"maximum":41},"policy":{"contract_id":"private/policy/v7","data_base64":"AP+A"}}`},
		{"empty policy", func(q *queryObject) { inspectionPolicy(q, contract.OutputPolicy{}) }, `{"contract_id":"","data_base64":""}`},
		{"declared routing", func(q *queryObject) {
			inspectionOutputConfiguration(q, contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: id, DefaultDestinations: []string{"a"},
				Routes: []contract.OutputRoute{{EntryIncarnationID: contract.ID{2}}, {EntryIncarnationID: contract.ID{3}, Destinations: []string{"a"}}}})
		}, `{"schema":5,"domain_id":"` + hexID + `","bindings":[],"default_destinations":["a"],"routes":[{"entry_incarnation_id":"02` + strings.Repeat("00", 31) + `","destinations":[]},{"entry_incarnation_id":"03` + strings.Repeat("00", 31) + `","destinations":["a"]}],"groups":[]}`},
		{"empty routing", func(q *queryObject) {
			inspectionOutputConfiguration(q, contract.OutputConfiguration{Schema: contract.OutputConfigurationSchema, DomainID: id})
		}, `{"schema":5,"domain_id":"` + hexID + `","bindings":[],"default_destinations":[],"routes":[],"groups":[]}`},
		{"evidence", func(q *queryObject) {
			inspectionPublicationEvidence(q, contract.PublicationEvidence{Schema: 3, Entry: 2, Class: 1, ResponseContractDigest: id, NormalizedStatus: 201, SafeRequestID: "safe/request", SafeResourceID: "safe/resource", ConsumerLocator: "assigned/consumer"})
		}, `{"schema":3,"entry":2,"class":1,"response_contract_digest":"` + hexID + `","normalized_status":201,"safe_request_id":"safe/request","safe_resource_id":"safe/resource","consumer_locator":"assigned/consumer"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := inspectionOutputObject(t, test.emit)
			if !bytes.Equal(got, []byte(test.want)) {
				t.Fatal("complete generic output fields differ", string(got))
			}
		})
	}
	t.Run("retained deletion", func(t *testing.T) {
		coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: id, CoordinateID: id, ServiceContractID: destination.ServiceContractID, CanonicalTarget: target.CanonicalTarget,
			DeletionDestinationID: "local-output", DeletionConsumerLocator: "assigned/consumer", DeletionTargetContractID: target.TargetContractID, DeletionConfigContractID: destination.ConfigContractID,
			DeletionCredentialRouteContractID: "private/credentials/v2", DeletionTargetData: target.TargetData, DeletionPayloadEncoding: target.PayloadEncoding, LocatorRequiresCreation: true, DeletionTargetRowDigest: id}
		got := localResultObject(t, inspectionOutputObject(t, func(q *queryObject) { inspectionCoordinate(q, coordinate) }))
		want := map[string]any{"schema": 5, "domain_id": hexID, "coordinate_id": hexID, "service_contract_id": "private/service/v3", "canonical_target": "room/slot", "deletion_destination_id": "local-output", "deletion_consumer_locator": "assigned/consumer", "deletion_target_contract_id": "private/target/v5", "deletion_config_contract_id": "private/config/v9", "deletion_credential_route_contract_id": "private/credentials/v2", "deletion_target_data_base64": "AP+A", "deletion_payload_encoding": 2, "locator_requires_creation": true, "deletion_target_row_digest": hexID}
		for _, key := range []string{"active_binding_incarnation_id", "last_binding_incarnation_id", "last_entry_incarnation_id", "owned_birth_attempt_id", "owned_instance_digest", "current_publication_incarnation_id", "latest_unresolved_attempt_id", "last_value_ack_attempt_id", "last_value_digest", "last_policy_ack_attempt_id", "last_policy_digest", "last_delete_ack_attempt_id", "last_value_ack_incarnation_id", "last_policy_ack_incarnation_id", "last_delete_ack_incarnation_id"} {
			want[key] = strings.Repeat("0", 64)
		}
		for _, key := range []string{"binding_state", "owner_state", "last_admission_ordinal", "last_value_ack_ordinal", "last_policy_ack_ordinal", "last_delete_ack_ordinal"} {
			want[key] = 0
		}
		want["possible_remote_object"], want["late_effect_risk"] = false, false
		encoded, err := json.Marshal(want)
		if err != nil || !reflect.DeepEqual(got, localResultObject(t, encoded)) {
			t.Fatal("complete retained deletion projection differs", err)
		}
	})
	t.Run("birth identity", func(t *testing.T) {
		marker := contract.PublicationMarker{BirthServiceContractID: "private/service/v3", BirthTargetContractID: "private/target/v5", ExecutorID: "local-build", CredentialRouteID: "local-route", Evidence: contract.PublicationEvidence{ConsumerLocator: "assigned/consumer"}}
		got := localResultObject(t, inspectionOutputObject(t, func(q *queryObject) { inspectionMarker(q, marker) }))
		if len(got) != 19 || string(got["birth_service_contract_id"]) != `"private/service/v3"` || string(got["birth_target_contract_id"]) != `"private/target/v5"` || string(got["executor_id"]) != `"local-build"` || string(got["credential_route_id"]) != `"local-route"` || string(localResultObject(t, got["evidence"])["consumer_locator"]) != `"assigned/consumer"` {
			t.Fatal("marker lost exact selected support or assigned locator")
		}
	})
	t.Run("maximum retained coordinate", func(t *testing.T) {
		text := func(n int) string { return strings.Repeat("\x00", n) }
		coordinateID, err := contract.PublicationCoordinateID(id, text(256), text(1024))
		if err != nil {
			t.Fatal(err)
		}
		p := contract.PublicationCoordinate{Schema: 5, DomainID: id, CoordinateID: coordinateID, ServiceContractID: text(256), CanonicalTarget: text(1024), BindingState: 1, OwnerState: 2,
			ActiveBindingIncarnationID: id, LastBindingIncarnationID: id, LastEntryIncarnationID: id, OwnedBirthAttemptID: id, OwnedInstanceDigest: id, CurrentPublicationIncarnationID: id,
			LastAdmissionOrdinal: math.MaxUint64, LatestUnresolvedAttemptID: id, LastValueAckAttemptID: id, LastValueDigest: id, LastPolicyAckAttemptID: id, LastPolicyDigest: id, LastDeleteAckAttemptID: id,
			LastValueAckIncarnationID: id, LastPolicyAckIncarnationID: id, LastDeleteAckIncarnationID: id, LastValueAckOrdinal: math.MaxUint64, LastPolicyAckOrdinal: math.MaxUint64, LastDeleteAckOrdinal: math.MaxUint64,
			DeletionDestinationID: text(256), DeletionConsumerLocator: text(1024), DeletionTargetContractID: text(256), DeletionConfigContractID: text(256), DeletionCredentialRouteContractID: text(256), DeletionTargetData: bytes.Repeat([]byte{255}, 4096), DeletionPayloadEncoding: 2, DeletionTargetRowDigest: id}
		body, err := contract.EncodePublicationCoordinate(p)
		if err != nil || len(body) != 8072 {
			t.Fatal("maximum retained coordinate does not fit", len(body), err)
		}
		got := inspectionOutputObject(t, func(q *queryObject) { inspectionCoordinate(q, p) })
		// Independent JSON field count: 3,328 source text bytes escape to
		// 19,968 bytes; 4,096 opaque bytes use 5,464 Base64 bytes. The
		// remaining 2,296 bytes are closed field names, IDs, numbers and syntax.
		// Python json.dumps(separators=(",",":")) preserves the listed field
		// order. All IDs use 01 then 31 zero bytes, except the coordinate:
		// SHA256("ENKV/PUBLICATION/COORDINATE/v3\0" || domain ||
		// u32be(256) || 256 zero bytes || u32be(1024) || 1024 zero bytes).
		if len(got) != 27728 || len(got)+1 > 32768 || fmt.Sprintf("%x", sha256.Sum256(got)) != "95c35a242ff65fb0baa8a90177217d74b32bb247982b5996aa79512bc0108321" {
			t.Fatal("coordinate exceeds its complete output account", len(got))
		}
	})
}
