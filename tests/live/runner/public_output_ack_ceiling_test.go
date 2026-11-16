package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"enkv.sh/core/testsupport/nativeprocess"
)

// full_only: false
func TestPublicOutputNoOpSeparatesApplyComparisonFromPublication(t *testing.T) {
	id := strings.Repeat("a", 64)
	expected := []publicOutputCoordinate{{CoordinateID: id, ServiceContractID: "service", PhysicalTarget: "account/target"}}
	const publication = `{"schema":"ProductResult/v1","operation_kind":"publish","state_result":"no-op","output_summary":"output-no-change","evidence_ceiling":"canonical","payload":{"schema":"OutputPayload/v3","domain_wide_warning":false,"entries":[{"coordinate_id":"%s","target":{"origin":"current","entry_name":"entry","destination_id":"destination","service_contract_id":"service","canonical_target":"account/target"},"actions":[{"action":null,"projection_commitment":null,"attempt_id":null,"disposition":"no-op","reason_code":0,"remote_value_may_remain":false,"late_write_risk":false,"blocker_ids":[],"evidence":null}]}]}}`
	for _, condition := range []string{"standalone", "combined", "combined-comparison", "standalone-decrypt", "combined-head-write", "combined-store-write", "combined-changed-apply", "action", "projection_commitment", "attempt_id", "evidence", "target-missing", "target-service", "target-coordinate", "target-origin", "target-name", "target-destination"} {
		t.Run(condition, func(t *testing.T) {
			combined := condition != "standalone" && condition != "standalone-decrypt"
			body := fmt.Sprintf(publication, id)
			switch condition {
			case "target-missing":
				body = strings.Replace(body, `"target":{`, `"ignored_target":{`, 1)
			case "target-service":
				body = strings.Replace(body, `"service_contract_id":"service"`, `"service_contract_id":"different"`, 1)
			case "target-coordinate":
				body = strings.Replace(body, `"canonical_target":"account/target"`, `"canonical_target":"different"`, 1)
			case "target-origin":
				body = strings.Replace(body, `"origin":"current"`, `"origin":"retained-deletion"`, 1)
			case "target-name":
				body = strings.Replace(body, `"entry_name":"entry"`, `"entry_name":null`, 1)
			case "target-destination":
				body = strings.Replace(body, `"destination_id":"destination"`, `"destination_id":null`, 1)
			}
			apply := publicApplyNoOpJSON
			if condition == "combined-changed-apply" {
				apply = publicApplySelectedJSON
			}
			for _, field := range []string{"action", "projection_commitment", "attempt_id", "evidence"} {
				if condition == field {
					value := `"` + id + `"`
					if field == "evidence" {
						value = `{}`
					}
					body = strings.Replace(body, `"`+field+`":null`, `"`+field+`":`+value, 1)
				}
			}
			if combined {
				body = fmt.Sprintf(`{"schema":"ApplyPublicationResult/v1","apply":%s,"publication":{"stage":"evaluated","reason":null,"result":%s}}`, apply, body)
			}
			if !json.Valid([]byte(body)) {
				t.Fatal("invalid independent result fixture")
			}
			result := publicChildResult{Code: 0, Body: []byte(body)}
			switch condition {
			case "combined-comparison", "standalone-decrypt":
				result.Capture.Events = []nativeprocess.Event{{Kind: "http-start", Operation: "kms-decrypt"}}
			case "combined-head-write":
				result.Capture.Events = []nativeprocess.Event{{Kind: "http-start", Operation: "head-write"}}
			case "combined-store-write":
				result.Capture.Events = []nativeprocess.Event{{Kind: "http-start", Operation: "store-write"}}
			}
			refused := false
			func() {
				defer func() {
					if failure := recover(); failure != nil {
						if _, ok := failure.(recoveryCustodyRefusal); !ok {
							panic(failure)
						}
						refused = true
					}
				}()
				publicOutputPublication(recoveryCustodyRefusalTB{t}, result, expected, combined, true, false)
			}()
			wantRefused := condition != "standalone" && condition != "combined" && condition != "combined-comparison"
			if refused != wantRefused {
				t.Fatalf("no-op result admission refused=%t, want %t", refused, wantRefused)
			}
		})
	}
}

// full_only: false
func TestPublicOutputAcknowledgementPreservesRemotePossibility(t *testing.T) {
	id, binding := strings.Repeat("a", 64), strings.Repeat("b", 64)
	expected := []publicOutputCoordinate{{ServiceContractID: "github-actions/service/v1", PhysicalTarget: "repos/owner/repo/actions/secrets/ENKV_RUN_SECRET", TargetContractID: "github-actions/target/v1", CoordinateID: id}}
	t.Run("exact-delete-acknowledgement", func(t *testing.T) {
		body := fmt.Sprintf(`{"schema":"ProductResult/v1","operation_kind":"publish","state_result":"success","output_summary":"output-complete","evidence_ceiling":"canonical","payload":{"schema":"OutputPayload/v3","domain_wide_warning":false,"entries":[{"coordinate_id":"%s","target":{"origin":"retained-deletion","entry_name":null,"destination_id":null,"service_contract_id":"github-actions/service/v1","canonical_target":"repos/owner/repo/actions/secrets/ENKV_RUN_SECRET"},"actions":[{"action":"delete-owned","projection_commitment":"%s","attempt_id":"%s","disposition":"acknowledged","reason_code":0,"remote_value_may_remain":true,"late_write_risk":false,"blocker_ids":[],"evidence":{"schema":"PublicationEvidence/v3","entry":"may-have-entered","class":"acknowledged","response_contract_digest":"%s","normalized_status":204,"consumer_locator":""}}]}]}}`, id, binding, strings.Repeat("c", 64), strings.Repeat("d", 64))
		publicOutputPublication(t, publicChildResult{Code: 0, Body: []byte(body)}, expected, false, false, true)
	})
	t.Run("complete-retired-acknowledgement-ceiling", func(t *testing.T) {
		positive, negative, reason := true, false, uint8(0)
		preview := publicOutputPreview{Schema: "PublicationPreview/v2", Complete: &positive, Reason: &reason, Warning: &negative, Entries: []publicOutputPreviewRow{{ServiceContractID: expected[0].ServiceContractID, PhysicalTarget: expected[0].PhysicalTarget, TargetContractID: expected[0].TargetContractID, Coordinate: &id, Binding: &binding, Origin: "observed", Basis: "warning", Actions: []string{}, Blockers: []string{}, Conditional: &negative, Reason: &reason, Remote: &positive, Late: &negative}}}
		if !publicOutputPreviewMatches(preview, expected, true) {
			t.Fatal("acknowledged deletion was confused with proved remote absence")
		}
	})
}
