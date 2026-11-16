package core

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"os"
	"strings"
	"testing"
)

type stockManifestResult struct {
	Schema   string `json:"schema"`
	Issuance struct {
		Schema    string `json:"schema"`
		State     string `json:"state_result"`
		Operation string `json:"operation_kind"`
		Payload   struct {
			Schema   string `json:"schema"`
			Format   string `json:"format_contract_id"`
			Evidence string `json:"evidence_limit"`
			Length   uint64 `json:"artifact_length"`
			Digest   string `json:"artifact_digest"`
			Renderer struct {
				Artifact string `json:"artifact_id"`
			} `json:"renderer"`
			Included []struct {
				Name string `json:"name"`
				ID   string `json:"entry_incarnation_id"`
			} `json:"included_entries"`
			Excluded []json.RawMessage `json:"excluded_entries"`
		} `json:"payload"`
	} `json:"issuance"`
	Delivery struct {
		Artifact struct {
			Digest   string `json:"digest"`
			Length   uint64 `json:"length"`
			Renderer string `json:"renderer_artifact_id"`
			Format   string `json:"format_contract_id"`
		} `json:"artifact"`
		Replacement string          `json:"replacement"`
		Candidate   string          `json:"candidate_verification"`
		Installed   string          `json:"installed_verification"`
		Completion  string          `json:"native_completion"`
		Cleanup     string          `json:"candidate_cleanup"`
		Residue     json.RawMessage `json:"residue_path"`
		Failure     json.RawMessage `json:"failure"`
	} `json:"delivery"`
	Source string `json:"source_cleanup"`
}

func stockManifestDecode(child publicChildResult, body []byte, mode os.FileMode, renderer string) (stockManifestResult, error) {
	var result stockManifestResult
	if child.Code != 0 || len(child.Body) > 1<<20 || jsonv2.Unmarshal(child.Body, &result) != nil ||
		result.Schema != "ManifestFileResult/v2" || result.Issuance.Schema != "ProductResult/v1" ||
		result.Issuance.State != "success" || result.Issuance.Operation != "issue-consumption-manifest" ||
		result.Issuance.Payload.Schema != "ManifestPayload/v3" || result.Issuance.Payload.Format != "example/ini-reference/v1" ||
		result.Issuance.Payload.Evidence != "authorized-input-and-exact-bytes" ||
		!publicIdentityHex(renderer) || result.Issuance.Payload.Renderer.Artifact != renderer || result.Source != "complete" {
		return stockManifestResult{}, errInventory
	}
	payload, delivery := result.Issuance.Payload, result.Delivery
	if !mode.IsRegular() || mode.Perm() != 0600 || len(body) > 1<<20 || payload.Length != uint64(len(body)) ||
		payload.Digest != bodyDigest(body) || payload.Included == nil || payload.Excluded == nil {
		return stockManifestResult{}, errInventory
	}
	if delivery.Artifact.Digest != payload.Digest || delivery.Artifact.Length != uint64(len(body)) ||
		delivery.Artifact.Renderer != renderer || delivery.Artifact.Format != "example/ini-reference/v1" ||
		delivery.Replacement != "replaced" || delivery.Candidate != "verified" || delivery.Installed != "verified" ||
		delivery.Completion != "complete" || delivery.Cleanup != "renamed" ||
		!bytes.Equal(delivery.Residue, []byte("null")) || !bytes.Equal(delivery.Failure, []byte("null")) {
		return stockManifestResult{}, errInventory
	}
	return result, nil
}

// full_only: false
func TestStockManifestWireRequiresCompleteNativeDelivery(t *testing.T) {
	// SHA-256 of the six literal bytes "fixed\n", derived with Python hashlib.
	// The test owns common byte delivery; separate INI checks own its meaning.
	const renderer = "1111111111111111111111111111111111111111111111111111111111111111"
	const digest = "0c3071418e6356e614898c84ed064ca95e88551bc0811b534bdf1952ecdae534"
	const document = `{"schema":"ManifestFileResult/v2","issuance":{"schema":"ProductResult/v1","operation_kind":"issue-consumption-manifest","state_result":"success","payload":{"schema":"ManifestPayload/v3","format_contract_id":"example/ini-reference/v1","evidence_limit":"authorized-input-and-exact-bytes","artifact_length":6,"artifact_digest":"` + digest + `","renderer":{"artifact_id":"` + renderer + `"},"included_entries":[],"excluded_entries":[]}},"delivery":{"artifact":{"renderer_artifact_id":"` + renderer + `","format_contract_id":"example/ini-reference/v1","length":6,"digest":"` + digest + `"},"replacement":"replaced","candidate_verification":"verified","installed_verification":"verified","native_completion":"complete","candidate_cleanup":"renamed","residue_path":null,"failure":null},"source_cleanup":"complete"}`
	for _, condition := range []string{"exact", "candidate", "installed", "completion", "cleanup", "wrong-renderer", "wrong-length", "wrong-digest", "missing-residue", "failure", "mode", "missing-partition"} {
		t.Run(condition, func(t *testing.T) {
			body := document
			mode := os.FileMode(0600)
			switch condition {
			case "candidate":
				body = strings.Replace(body, `"candidate_verification":"verified"`, `"candidate_verification":"unavailable"`, 1)
			case "installed":
				body = strings.Replace(body, `"installed_verification":"verified"`, `"installed_verification":"unavailable"`, 1)
			case "completion":
				body = strings.Replace(body, `"native_completion":"complete"`, `"native_completion":"incomplete"`, 1)
			case "cleanup":
				body = strings.Replace(body, `"candidate_cleanup":"renamed"`, `"candidate_cleanup":"unknown"`, 1)
			case "wrong-renderer":
				body = strings.Replace(body, `"renderer_artifact_id":"`+renderer+`"`, `"renderer_artifact_id":"2222222222222222222222222222222222222222222222222222222222222222"`, 1)
			case "wrong-length":
				body = strings.Replace(body, `"length":6`, `"length":7`, 1)
			case "wrong-digest":
				body = strings.Replace(body, `"digest":"`+digest+`"`, `"digest":"2222222222222222222222222222222222222222222222222222222222222222"`, 1)
			case "missing-residue":
				body = strings.Replace(body, `"residue_path":null,`, ``, 1)
			case "failure":
				body = strings.Replace(body, `"failure":null`, `"failure":{}`, 1)
			case "mode":
				mode = 0644
			case "missing-partition":
				body = strings.Replace(body, `"included_entries":[],`, ``, 1)
			}
			_, err := stockManifestDecode(publicChildResult{Code: 0, Body: []byte(body)}, []byte("fixed\n"), mode, renderer)
			if (err == nil) != (condition == "exact") {
				t.Fatal("stock manifest wire accepted incomplete or changed native delivery")
			}
		})
	}
}
