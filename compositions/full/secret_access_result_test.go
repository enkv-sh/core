package compositionfull

import (
	"bytes"
	"encoding/json"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func secretAccessResultFixture(t testing.TB, operation uint16) core.PublicApplyResult {
	t.Helper()
	r := suppliedApplyRetainedWorkResultFixture(t, []contract.ID{{10}, {11}}, []contract.ID{{12}, {13}}, 0)
	row, err := contract.InspectCompactMutationReceipt(r.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	row.OperationKind, row.EffectSummary = operation, contract.ReceiptEffectNotApplicable
	r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// full_only: false
func TestSecretAccessResultsPinOperationAndReceiptFacts(t *testing.T) {
	for _, operation := range []struct {
		name           string
		kind           uint16
		machine, human func(core.PublicApplyResult) ([]byte, error)
	}{{"envelope-rekey", contract.OperationEnvelopeRekey, RenderEnvelopeRekeyJSON, RenderEnvelopeRekeyHuman}, {"retire-recipient-identity", contract.OperationRetireRecipientIdentity, RenderRecipientRetirementJSON, RenderRecipientRetirementHuman}} {
		t.Run(operation.name, func(t *testing.T) {
			for _, outcome := range []core.Outcome{core.ObservedCurrent, core.Contention, core.UnresolvedCommit, core.AdmissionRefused, core.EvidenceUnavailable, core.IntegrityFailure} {
				r := secretAccessResultFixture(t, operation.kind)
				r.Result.Outcome = outcome
				if outcome != core.ObservedCurrent {
					r.Receipt = nil
				}
				if outcome == core.UnresolvedCommit {
					r.Result.CommitMayHaveOccurred = true
				}
				if outcome == core.AdmissionRefused || outcome == core.EvidenceUnavailable || outcome == core.IntegrityFailure {
					r.Payload = nil
				}
				body, err := operation.machine(r)
				if err != nil {
					t.Fatal("valid standalone result refused", outcome, err)
				}
				var v struct {
					Operation string                 `json:"operation_kind"`
					State     string                 `json:"state_result"`
					Effect    string                 `json:"effect_summary"`
					Output    string                 `json:"output_summary"`
					Payload   *applyTransitionRecord `json:"payload"`
					Warnings  []string               `json:"warning_summary"`
				}
				if err := json.Unmarshal(body, &v); err != nil || v.Operation != operation.name || v.Effect != "not-applicable" || v.Output != "not-applicable" || v.State == "no-op" || v.State == "retirement-pending" {
					t.Fatal("standalone operation facts changed", err, string(body))
				}
				human, err := operation.human(r)
				if err != nil || !bytes.Contains(human, []byte(map[string]string{"envelope-rekey": "Envelope rekey", "retire-recipient-identity": "Recipient retirement"}[operation.name]+": "+v.State+"\n")) || !bytes.Contains(human, []byte("Operation ID: "+readerID(r.OperationID)+"\n")) {
					t.Fatal("human standalone facts differ", err)
				}
				if r.Payload != nil && (v.Payload == nil || len(v.Payload.Duties) != 2 || len(v.Payload.Hazards) != 2 || len(v.Warnings) != 1 || !bytes.Contains(human, []byte("An old generated effect may still be live."))) {
					t.Fatal("standalone result lost retained work")
				}
			}
			for _, condition := range []string{"apply-receipt", "other-operation", "effect", "output", "pending", "exact-resume", "request", "revision", "subject", "duty-count", "hazard-count", "missing-warning", "extra-warning", "domain-warning", "duty-order", "hazard-duplicate", "missing-receipt", "no-op"} {
				t.Run(condition, func(t *testing.T) {
					r := secretAccessResultFixture(t, operation.kind)
					row, err := contract.InspectCompactMutationReceipt(r.Receipt)
					if err != nil {
						t.Fatal(err)
					}
					switch condition {
					case "apply-receipt":
						r.Receipt = suppliedApplyRetainedWorkResultFixture(t, []contract.ID{{10}, {11}}, []contract.ID{{12}, {13}}, 0).Receipt
					case "other-operation":
						other := uint16(contract.OperationEnvelopeRekey)
						if operation.kind == other {
							other = contract.OperationRemoveSecretValueEntryAccess
						}
						r.Receipt = secretAccessResultFixture(t, other).Receipt
					case "effect":
						row.EffectSummary = contract.ReceiptEffectNoChange
					case "output":
						// An unsupported output summary must fail at the receipt codec.
						row.OutputSummary++
					case "pending":
						row.StateResult = contract.ReceiptStateRetirementPending
					case "exact-resume":
						row.StateResult = contract.ReceiptStateExactResume
					case "request":
						r.RequestIdentity = contract.ID{30}
					case "revision":
						r.Payload.PredecessorRevisionID = contract.ID{30}
					case "subject":
						r.Payload.ChangedSubjects.IdentityRootDigest = contract.ID{30}
					case "duty-count":
						r.Payload.LiveDutyIDs = r.Payload.LiveDutyIDs[:1]
					case "hazard-count":
						r.Payload.LiveHazardIDs = r.Payload.LiveHazardIDs[:1]
					case "missing-warning":
						row.WarningBits = 0
					case "extra-warning":
						row.WarningBits |= contract.ReceiptWarningInvalidationNotConfirmed
					case "domain-warning":
						r.WarningBits = core.WarningLateDestructiveEffect
					case "duty-order":
						r.Payload.LiveDutyIDs[0], r.Payload.LiveDutyIDs[1] = r.Payload.LiveDutyIDs[1], r.Payload.LiveDutyIDs[0]
					case "hazard-duplicate":
						r.Payload.LiveHazardIDs[1] = r.Payload.LiveHazardIDs[0]
					case "missing-receipt":
						r.Receipt = nil
					case "no-op":
						r = suppliedApplyNoopResultFixture()
					}
					if condition == "effect" || condition == "output" || condition == "pending" || condition == "exact-resume" || condition == "missing-warning" || condition == "extra-warning" {
						r.Receipt, err = contract.EncodeCompactMutationReceipt(row)
						if condition == "output" || condition == "pending" || condition == "extra-warning" {
							if err == nil {
								t.Fatal("unsupported receipt facts accepted")
							}
							return
						}
						if err != nil {
							t.Fatal("receipt shape refused before renderer", err)
						}
					}
					for _, render := range []func(core.PublicApplyResult) ([]byte, error){operation.machine, operation.human} {
						if _, err := render(r); err == nil {
							t.Fatal("inconsistent standalone result accepted")
						}
					}
				})
			}
		})
	}
}
