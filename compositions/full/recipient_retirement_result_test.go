package compositionfull

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func retirementBlockedResultFixture(t testing.TB) core.PublicApplyResult {
	t.Helper()
	r, err := NewRecipientRetirementRefusal(configuration.JSON)
	if err != nil {
		t.Fatal(err)
	}
	r.RequestID, r.DomainID = contract.ID{77}, contract.ID{78}
	r.PreAdmission.Stage = "retire"
	r.PreAdmission.RequestNonce = r.RequestID
	r.RetirementBlockers = &core.RecipientRetirementBlockers{Total: 3, Rows: []core.RecipientRetirementBlocker{
		{MaterialID: contract.ID{1}, OwnerKind: contract.GeneratedParentSupportKind, OwnerID: contract.ID{4}},
		{MaterialID: contract.ID{1}, OwnerKind: contract.GeneratedDutySupportKind, OwnerID: contract.ID{5}},
		{MaterialID: contract.ID{2}, OwnerKind: contract.GeneratedHazardSupportKind, OwnerID: contract.ID{6}},
	}}
	return r
}

// full_only: false
func TestRecipientRetirementBlockerResultsAreBoundedCanonicalAndSeparate(t *testing.T) {
	r := retirementBlockedResultFixture(t)
	body, err := RenderRecipientRetirementJSON(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf(`{"total":3,"rows":[{"material_id":%q,"owner_kind":"parent","owner_id":%q},{"material_id":%q,"owner_kind":"duty","owner_id":%q},{"material_id":%q,"owner_kind":"hazard","owner_id":%q}]}`, readerID(contract.ID{1}), readerID(contract.ID{4}), readerID(contract.ID{1}), readerID(contract.ID{5}), readerID(contract.ID{2}), readerID(contract.ID{6}))
	if !resultJSONFactsEqual(fields["recipient_retirement_blockers"], []byte(expected)) || string(fields["state_result"]) != `"refused"` || string(fields["payload"]) != "null" || fields["receipt_hex"] != nil || string(fields["replay_identity"]) != `"none"` || string(fields["effect_summary"]) != `"not-applicable"` {
		t.Fatal("blocked retirement invented selection or changed exact blocker facts", string(body))
	}
	human, err := RenderRecipientRetirementHuman(r)
	if err != nil || !bytes.Contains(human, []byte("Retirement blockers: 3\n")) || !bytes.Contains(human, []byte("Material "+readerID(contract.ID{1})+"; parent "+readerID(contract.ID{4})+"\n")) || !bytes.Contains(human, []byte("Material "+readerID(contract.ID{1})+"; duty "+readerID(contract.ID{5})+"\n")) || !bytes.Contains(human, []byte("Material "+readerID(contract.ID{2})+"; hazard "+readerID(contract.ID{6})+"\n")) || !bytes.Contains(human, []byte("No transition details are available.\n")) {
		t.Fatal("human blockers differ", err)
	}
	t.Run("complete-total-bounded-rows", func(t *testing.T) {
		r := retirementBlockedResultFixture(t)
		r.RetirementBlockers.Total = 65
		r.RetirementBlockers.Rows = make([]core.RecipientRetirementBlocker, core.RecipientRetirementBlockerLimit)
		for i := range r.RetirementBlockers.Rows {
			r.RetirementBlockers.Rows[i] = core.RecipientRetirementBlocker{MaterialID: contract.ID{byte(i + 1)}, OwnerKind: contract.GeneratedParentSupportKind, OwnerID: contract.ID{100}}
		}
		body, err := RenderRecipientRetirementJSON(r)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Blockers struct {
				Total uint32
				Rows  []recipientRetirementBlockerRecord
			} `json:"recipient_retirement_blockers"`
		}
		if json.Unmarshal(body, &v) != nil || v.Blockers.Total != 65 || len(v.Blockers.Rows) != 64 || v.Blockers.Rows[63].Material != readerID(contract.ID{64}) {
			t.Fatal("complete total was confused with returned rows")
		}
	})
	for _, condition := range []string{"zero-total", "no-rows", "count-short", "too-many-rows", "bounded-short", "material-zero", "owner-zero", "kind", "material-order", "kind-order", "owner-order", "duplicate", "success", "contention", "unknown", "receipt", "payload"} {
		t.Run(condition, func(t *testing.T) {
			r := retirementBlockedResultFixture(t)
			switch condition {
			case "zero-total":
				r.RetirementBlockers.Total = 0
			case "no-rows":
				r.RetirementBlockers.Rows = nil
			case "count-short":
				r.RetirementBlockers.Rows = r.RetirementBlockers.Rows[:2]
			case "too-many-rows":
				r.RetirementBlockers.Total = 65
				r.RetirementBlockers.Rows = make([]core.RecipientRetirementBlocker, 65)
			case "bounded-short":
				r.RetirementBlockers.Total = 65
			case "material-zero":
				r.RetirementBlockers.Rows[0].MaterialID = contract.ID{}
			case "owner-zero":
				r.RetirementBlockers.Rows[0].OwnerID = contract.ID{}
			case "kind":
				r.RetirementBlockers.Rows[0].OwnerKind = contract.OperationMaterialSupportKind
			case "material-order":
				slices.Reverse(r.RetirementBlockers.Rows)
			case "kind-order":
				r.RetirementBlockers.Rows[0], r.RetirementBlockers.Rows[1] = r.RetirementBlockers.Rows[1], r.RetirementBlockers.Rows[0]
			case "owner-order":
				r.RetirementBlockers.Rows[1].OwnerKind = contract.GeneratedParentSupportKind
				r.RetirementBlockers.Rows[1].OwnerID = contract.ID{3}
			case "duplicate":
				r.RetirementBlockers.Rows[1] = r.RetirementBlockers.Rows[0]
			case "success":
				r.Result.Outcome = core.ObservedCurrent
			case "contention":
				r.Result.Outcome = core.Contention
			case "unknown":
				r.Result.Outcome = core.UnresolvedCommit
				r.Result.CommitMayHaveOccurred = true
			case "receipt":
				r.Receipt = secretAccessResultFixture(t, contract.OperationRetireRecipientIdentity).Receipt
			case "payload":
				r.Payload = secretAccessResultFixture(t, contract.OperationRetireRecipientIdentity).Payload
			}
			for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderRecipientRetirementJSON, RenderRecipientRetirementHuman} {
				if _, err := render(r); err == nil {
					t.Fatal("invalid blocker result accepted")
				}
			}
		})
	}
	for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderApplyJSON, RenderApplyHuman, RenderEnvelopeRekeyJSON, RenderEnvelopeRekeyHuman} {
		if _, err := render(retirementBlockedResultFixture(t)); err == nil {
			t.Fatal("another operation accepted retirement-only facts")
		}
	}
	for _, render := range []func(core.PublicApplyResult) ([]byte, error){RenderRecipientRetirementJSON, RenderRecipientRetirementHuman, RenderApplyJSON, RenderApplyHuman, RenderEnvelopeRekeyJSON, RenderEnvelopeRekeyHuman} {
		r := retirementBlockedResultFixture(t)
		r.RetirementBlockers = nil
		body, err := render(r)
		if err != nil || bytes.Contains(body, []byte("recipient_retirement_blockers")) {
			t.Fatal("absent blocker facts were invented", err)
		}
	}
}
