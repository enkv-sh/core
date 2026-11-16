package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func publicIdentityHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value && value != strings.Repeat("0", 64)
}

func publicAdmittedRequestIdentity(product publicProductResult) (string, bool) {
	var value string
	if len(product.RequestIdentity) > 66 || json.Unmarshal(product.RequestIdentity, &value) != nil || !publicIdentityHex(value) {
		return "", false
	}
	return value, true
}

func publicRequestIdentityValid(product publicProductResult) bool {
	// Successful Reader results do not carry a mutation request identity.
	if len(product.RequestIdentity) == 0 {
		return product.Operation == contract.ReaderCompareOperation
	}
	if _, admitted := publicAdmittedRequestIdentity(product); admitted {
		return true
	}
	if len(product.RequestIdentity) > 4096 {
		return false
	}
	var value struct {
		Schema        string `json:"schema"`
		OperationID   string `json:"operation_id"`
		OperationKind string `json:"operation_kind"`
		Stage         string `json:"stage"`
		Code          string `json:"code"`
		SourceSchema  string `json:"source_schema"`
		SourceProfile string `json:"source_profile"`
		Format        string `json:"format"`
		RequestNonce  string `json:"request_nonce"`
	}
	decoder := json.NewDecoder(bytes.NewReader(product.RequestIdentity))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Schema != "PreAdmissionRequestIdentity/v1" || !publicIdentityHex(value.OperationID) || value.OperationID != product.OperationID || value.OperationKind != product.Operation || value.SourceSchema != "enkv/configuration/v2" || value.SourceProfile != "direct-candidate" || product.ReplayIdentity != "none" {
		return false
	}
	if value.Format != "" && value.Format != "json" && value.Format != "yaml" || value.RequestNonce != "" && !publicIdentityHex(value.RequestNonce) {
		return false
	}
	for _, token := range []string{value.Stage, value.Code} {
		if token == "" || len(token) > 64 || strings.Trim(token, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return product.State != "success" && product.State != "exact-resume" && product.State != "no-op"
}

const publicPreAdmissionJSON = `{"schema":"ProductResult/v1","operation_kind":"apply-declaration","state_result":"refused","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","request_identity":{"schema":"PreAdmissionRequestIdentity/v1","operation_id":"4444444444444444444444444444444444444444444444444444444444444444","operation_kind":"apply-declaration","stage":"capture","code":"missing-required-field","source_schema":"enkv/configuration/v2","source_profile":"direct-candidate","format":"json","request_nonce":"5555555555555555555555555555555555555555555555555555555555555555"},"replay_identity":"none","payload":null}`

// full_only: false
func TestPublicConfigurationRequestIdentityConsumer(t *testing.T) {
	for _, operation := range []string{"apply-declaration", "initialize-empty-domain", "compare-public-configuration"} {
		t.Run(operation, func(t *testing.T) {
			body := strings.ReplaceAll(publicPreAdmissionJSON, "apply-declaration", operation)
			product := publicProduct(t, publicChildResult{Code: 2, Body: []byte(body)}, operation)
			if _, admitted := publicAdmittedRequestIdentity(product); admitted {
				t.Fatal("pre-admission identity acquired admitted identity")
			}
		})
	}
	t.Run("admitted", func(t *testing.T) {
		product := publicProduct(t, publicChildResult{Body: []byte(publicApplySelectedJSON)}, "apply-declaration")
		identity, admitted := publicAdmittedRequestIdentity(product)
		if !admitted || identity != "5555555555555555555555555555555555555555555555555555555555555555" {
			t.Fatal("admitted request identity differs")
		}
	})
	for _, row := range []struct{ name, from, to string }{
		{"wrong-schema", "PreAdmissionRequestIdentity/v1", "ArtifactRequestIdentity/v1"},
		{"wrong-operation", `"operation_kind":"apply-declaration","stage"`, `"operation_kind":"initialize-empty-domain","stage"`},
		{"wrong-id", `"operation_id":"4444444444444444444444444444444444444444444444444444444444444444","operation_kind"`, `"operation_id":"6666666666666666666666666666666666666666666666666666666666666666","operation_kind"`},
		{"wrong-replay", `"replay_identity":"none"`, `"replay_identity":"5555555555555555555555555555555555555555555555555555555555555555"`},
		{"wrong-format", `"format":"json"`, `"format":"toml"`},
		{"wrong-profile", "direct-candidate", "trusted-baseline"},
		{"wrong-source-schema", "enkv/configuration/v2", "other/v1"},
		{"missing-stage", `"stage":"capture"`, `"stage":""`},
		{"invalid-code", `"code":"missing-required-field"`, `"code":"private path"`},
		{"invalid-nonce", `"request_nonce":"5555555555555555555555555555555555555555555555555555555555555555"`, `"request_nonce":"bad"`},
		{"oversized-code", "missing-required-field", strings.Repeat("x", 4097)},
		{"authority-field", `"stage":"capture"`, `"stage":"capture","predecessor":"forbidden"`},
		{"pre-admission-success", `"state_result":"refused"`, `"state_result":"success"`},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := strings.Replace(publicPreAdmissionJSON, row.from, row.to, 1)
			if body == publicPreAdmissionJSON {
				t.Fatal("identity damage fixture did not change")
			}
			var product publicProductResult
			if json.Unmarshal([]byte(body), &product) != nil {
				t.Fatal("identity damage fixture is not JSON")
			}
			if publicRequestIdentityValid(product) {
				t.Fatal("malformed request identity accepted")
			}
		})
	}
	for _, row := range []struct{ name, identity string }{
		{"missing", ``},
		{"null", `null`},
		{"array", `[]`},
		{"number", `0`},
		{"none-text", `"none"`},
		{"malformed-text", `"bad"`},
	} {
		t.Run("invalid-identity-"+row.name, func(t *testing.T) {
			var product publicProductResult
			if json.Unmarshal([]byte(publicPreAdmissionJSON), &product) != nil {
				t.Fatal("pre-admission fixture is not JSON")
			}
			product.RequestIdentity = json.RawMessage(row.identity)
			if publicRequestIdentityValid(product) {
				t.Fatal("invalid identity union variant accepted")
			}
		})
	}
}
