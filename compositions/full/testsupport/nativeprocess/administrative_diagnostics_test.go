package nativeprocess

import (
	"strings"
	"testing"
)

// full_only: false
func TestAdministrativeReplacementDiagnosticsRejectUnexpectedConsoleOutput(t *testing.T) {
	const stamp = "2026-10-21T03:40:00.123456789Z "
	const plainDetails = ` trace_id="" span_id="" trace_sampled=false invocation_id="" worker_id="" member="" key_id="" command_id="" attempt_id="" path_kind="" path="" config_field="" error_status="" error=""` + "\n"
	const headDetails = ` trace_id="" span_id="" trace_sampled=false invocation_id="" worker_id="" member="" key_id="" command_id="" attempt_id="" path_kind="state_head" path="HEAD" config_field="" error_status="unavailable" error=""` + "\n"
	const refused = stamp + `WARN (13) component="application" operation="application.invocation" event="return" result="admission_refused" reason="admission_refused"` + plainDetails
	const uncertain = stamp + `WARN (13) component="application" operation="application.invocation" event="return" result="unresolved_commit" reason="uncertain"` + plainDetails
	const coreWrite = stamp + `WARN (13) component="core" operation="core.store.compare_and_swap" event="return" result="write_unknown" reason="uncertain"` + plainDetails
	const coreRead = stamp + `ERROR (17) component="core" operation="core.store.read" event="return" result="read_unavailable" reason="evidence_unavailable"` + plainDetails
	const unresolved = stamp + `WARN (13) component="core" operation="core.replace_authority_keys" event="return" result="unresolved_commit" reason="read_unavailable"` + plainDetails
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			providerWrite := stamp + `WARN (13) component="` + family + `" operation="store.compare_and_swap" event="return" result="write_unknown" reason="uncertain"` + headDetails
			providerRead := stamp + `ERROR (17) component="` + family + `" operation="store.read" event="return" result="read_unavailable" reason="evidence_unavailable"` + headDetails
			if !administrativeReplacementDiagnostics(nil, family, true, "") || !administrativeReplacementDiagnostics([]byte(refused), family, false, "") || !administrativeReplacementDiagnostics([]byte(providerWrite+coreWrite), family, true, "lose-head-reply") || !administrativeReplacementDiagnostics([]byte(providerWrite+coreWrite+providerRead+coreRead+unresolved+uncertain), family, true, "lose-head-reply-and-observation") {
				t.Fatal("required default console records were refused")
			}
			for _, damaged := range []string{
				"", strings.TrimSuffix(providerWrite, "\n"), "\n" + providerWrite,
				providerWrite + "telemetry delivery incomplete\n", providerWrite + "telemetry setup failed\n",
				providerWrite + "unreviewed provider diagnostic\n", strings.Replace(providerWrite, stamp, "not-a-time ", 1),
				strings.Replace(providerWrite, "WARN (13)", "WARN (17)", 1),
				strings.Replace(providerWrite, `event="return"`, `event="checkpoint"`, 1),
				strings.Replace(providerWrite, `result="write_unknown"`, `result="failure"`, 1),
				strings.Replace(providerWrite, `reason="uncertain"`, `reason="invalid"`, 1),
				strings.Replace(providerWrite, `operation="store.compare_and_swap"`, `operation="key.decrypt"`, 1),
				strings.Replace(providerWrite, `path="HEAD"`, `path="private-selector-sentinel"`, 1),
				strings.Replace(providerWrite, `error=""`, `error="private-error-sentinel"`, 1),
				strings.Replace(providerWrite, `member=""`, `member="private-member-sentinel"`, 1),
				strings.Replace(providerWrite, `key_id=""`, `key_id="private-selector-sentinel"`, 1),
				strings.Replace(providerWrite, `trace_id=""`, `trace_id="01234567890123456789012345678901"`, 1),
				strings.Replace(providerWrite, `error=""`, `error="" unexpected="private-extra-sentinel"`, 1),
			} {
				if administrativeReplacementDiagnostics([]byte(damaged), family, true, "lose-head-reply") {
					t.Fatal("unexpected, incomplete or private diagnostic content was accepted")
				}
			}
			if administrativeReplacementDiagnostics([]byte(providerWrite), family, false, "") || administrativeReplacementDiagnostics([]byte(refused), family, true, "") || administrativeReplacementDiagnostics([]byte(providerRead), family, true, "lose-head-reply") || administrativeReplacementDiagnostics([]byte(unresolved), family, true, "lose-head-reply") {
				t.Fatal("a record from another disposition was accepted")
			}
			if administrativeReplacementDiagnostics([]byte(uncertain), family, false, "") || administrativeReplacementDiagnostics([]byte(refused), family, true, "lose-head-reply-and-observation") {
				t.Fatal("admission refusal and unresolved commit must use distinct application records")
			}
			other := "gcp"
			if family == "gcp" {
				other = "aws"
			}
			if administrativeReplacementDiagnostics([]byte(strings.Replace(providerWrite, `component="`+family+`"`, `component="`+other+`"`, 1)), family, true, "lose-head-reply") {
				t.Fatal("another provider's record was accepted")
			}
		})
	}
}
