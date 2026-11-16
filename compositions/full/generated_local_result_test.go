package compositionfull

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func localResultID(n byte) contract.ID { return contract.ID(bytes.Repeat([]byte{n}, 32)) }

// These are public DTO fixtures, not selected-state or producer proofs. Core's
// installed local tests separately establish the authenticated source relation.
func localResultCurrent() core.GeneratedCurrentGeneration {
	id := localResultID
	return core.GeneratedCurrentGeneration{Name: "local", EntryIncarnationID: id(1), GenerationID: id(2), Epoch: 7,
		OriginOperationID: id(3), OriginAttemptID: id(4), ResourceID: id(5), ConfigContractID: id(6),
		LifecycleMode: contract.GeneratorLifecycleNone}
}

func localResultEffect() core.GeneratedEffectFact {
	id := localResultID
	e := contract.GeneratorDescriptor{Digest: id(20), Length: 4}
	r := contract.GeneratedAttemptRecord{Schema: contract.GeneratedAttemptRecordSchema, LifecycleMode: contract.GeneratorLifecycleNone,
		DomainID: contract.ID{1}, OperationID: id(3), LineageID: id(9), AttemptID: id(4), TemplateDigest: id(10), OwnerID: id(14), ResourceID: id(5),
		TransmissionID: id(11), ResultID: id(12), InboxID: id(13), ConfigContractID: id(6), DescriptorID: id(7), ExecutorID: id(15), CredentialRouteID: id(19), ResultContractID: id(16), RequestDigest: id(17),
		State: contract.GeneratedEffectSucceeded, Stage: contract.GeneratedStageTerminal, Facts: e, Progress: e, Support: e, History: e}
	return core.GeneratedEffectFact{Record: r, Action: contract.GeneratorActionCreate, Name: "local", EntryIncarnationID: id(1), Epoch: 7,
		PlannedValueSlotID: id(18), GenerationID: id(2), DutyID: id(14), EvidenceCeiling: contract.ReceiptEvidenceCanonical}
}

func localResultDuty() core.GeneratedDutyFact {
	id := localResultID
	e := contract.GeneratorDescriptor{Digest: id(20), Length: 4}
	return core.GeneratedDutyFact{Record: contract.GeneratedDutyRecord{Schema: contract.GeneratedDutyRecordSchema, LifecycleMode: contract.GeneratorLifecycleNone,
		DomainID: contract.ID{1}, DutyID: id(14), OriginalOperationID: id(3), OriginalAttemptID: id(4), OwnerID: id(14), ResourceID: id(5),
		ConfigContractID: id(6), DescriptorID: id(7), ExecutorID: id(15), CredentialRouteID: id(19), ResultContractID: id(16), Kind: contract.GeneratedDutyCreate, Step: 1,
		Status: contract.GeneratedEffectTransmitted, CapacityReservation: e, Target: e, Progress: e, History: e, Support: e, Consumers: e}, EvidenceCeiling: contract.ReceiptEvidenceCanonical}
}

func localResultList() core.PublicGeneratedListResult {
	id := contract.ID{1}
	return core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id},
		Result:      core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id},
		StateResult: contract.ReaderSuccess, View: &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id,
			CurrentGenerations: []core.GeneratedCurrentGeneration{localResultCurrent()}}}
}

// full_only: false
func TestGeneratedLocalFailureHumanUsesLocalReasonDomain(t *testing.T) {
	r := localResultList()
	p := localResultEffect()
	p.Record.State, p.Record.FailureReason, p.Reason = contract.GeneratedEffectFailedTerminal, contract.GeneratorFailureUnavailable, contract.GeneratorFailureUnavailable
	p.GenerationID = contract.ID{}
	r.View.Effects = []core.GeneratedEffectFact{p}
	body, err := RenderGeneratedListHuman(r)
	if err != nil {
		t.Fatal("local failure fixture must be valid", err)
	}
	if !bytes.Contains(body, []byte("Reason: unavailable\n")) || bytes.Contains(body, []byte("Reason: invalid-value\n")) {
		t.Fatal("local generator failure used the remote safe-facts reason domain", string(body))
	}
}

func localResultInspection(t *testing.T) core.PublicDomainInspectionResult {
	t.Helper()
	r := publicQueryRendererDomain(t)
	p := localResultCurrent()
	id := localResultID
	r.View.Recipients = []core.InspectionRecipient{{RecipientID: id(21), Status: contract.CurrentRecipient, BindingID: id(22), BindingSerial: 1, BindingFingerprint: id(23)}}
	r.View.Entries = []core.InspectionEntry{{Name: p.Name, IncarnationID: p.EntryIncarnationID, ValueStateID: p.GenerationID,
		ValueSource: contract.Generated, Confidential: true, RawLength: 43, RecipientIDs: []contract.ID{id(21)}, GenerationID: p.GenerationID, Epoch: p.Epoch}}
	r.View.Generated.CurrentGenerations = []core.GeneratedCurrentGeneration{p}
	return r
}

func localResultObject(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var out map[string]json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal("malformed public result", err)
	}
	return out
}

func localResultFirst(t *testing.T, body json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var rows []json.RawMessage
	if err := json.Unmarshal(body, &rows); err != nil || len(rows) == 0 {
		t.Fatal("missing public result rows", err)
	}
	return localResultObject(t, rows[0])
}

func localResultNulls(t *testing.T, row map[string]json.RawMessage, fields ...string) {
	t.Helper()
	for _, name := range fields {
		if got, present := row[name]; !present || !bytes.Equal(got, []byte("null")) {
			t.Fatal("absent local field must retain its null key", name, string(got))
		}
	}
}

// full_only: false
func TestGeneratedLocalPresentation(t *testing.T) {
	t.Run("current and older managed duty", func(t *testing.T) {
		r := localResultList()
		old := generatedRendererDuty()
		old.Record.DutyID = localResultID(8)
		old.Record.OwnerID = old.Record.DutyID
		old.Target.Name = r.View.CurrentGenerations[0].Name
		r.View.CurrentGenerations[0].RetiringDutyID = old.Record.DutyID
		r.View.Duties = []core.GeneratedDutyFact{old}
		body, err := RenderGeneratedListJSON(r)
		if err != nil {
			t.Fatal("local current with independent old Duty refused", err)
		}
		doc := localResultObject(t, body)
		row := localResultFirst(t, doc["current_generations"])
		localResultNulls(t, row, "resource_contract_id", "resource_digest", "completion_class", "retirement_policy")
		for name, id := range map[string]contract.ID{"generation_id": localResultID(2), "origin_operation_id": localResultID(3), "origin_attempt_id": localResultID(4), "resource_incarnation_id": localResultID(5), "retiring_duty_id": localResultID(8)} {
			if string(row[name]) != `"`+readerID(id)+`"` {
				t.Fatal("local current identity changed", name)
			}
		}
		// Independent Python json.dumps(sort_keys=True,separators=(",",":"))
		// over these 14 named scalar fields and fixed repeated-byte IDs.
		// The local row has seven identities, four nulls and lifecycle "none".
		var current []json.RawMessage
		if json.Unmarshal(doc["current_generations"], &current) != nil || len(localResultCompact(t, current[0])) != 766 || fmt.Sprintf("%x", sha256.Sum256(localResultCompact(t, current[0]))) != "aaab2e0d3a64407fa376cbc8ac01867d17496eebd351df1ccecc44f7140b8b8b" {
			t.Fatal("local scalar row changed its independently counted length")
		}
		duty := localResultFirst(t, doc["duties"])
		target := localResultObject(t, duty["target"])
		if string(target["resource_contract_id"]) != `"`+readerID(old.Target.ResourceContractID)+`"` || string(target["resource_digest"]) != `"`+readerID(old.Target.ResourceDigest)+`"` {
			t.Fatal("local current changed the older managed target")
		}
		human, err := RenderGeneratedListHuman(r)
		if err != nil || !bytes.Contains(human, []byte("Current generation ")) || !bytes.Contains(human, []byte(readerID(r.View.CurrentGenerations[0].GenerationID))) || !bytes.Contains(human, []byte(readerID(old.Record.DutyID))) {
			t.Fatal("human rendering changed local or older Duty facts", err)
		}
	})
	t.Run("managed resource exact bytes", func(t *testing.T) {
		r := localResultList()
		p := &r.View.CurrentGenerations[0]
		p.LifecycleMode, p.ResourceContractID, p.ResourceDigest = contract.GeneratorLifecycleManaged, localResultID(9), localResultID(10)
		p.CompletionClass, p.RetirementMode, p.RetiringDutyID = contract.GeneratedCompletionAcknowledged, contract.GeneratedRetirementManual, localResultID(8)
		body, err := RenderGeneratedListJSON(r)
		if err != nil {
			t.Fatal("managed current refused", err)
		}
		var rows []json.RawMessage
		// Independent Python json.dumps(sort_keys=True,separators=(",",":"))
		// over the named fixed IDs and all 14 generic scalar fields.
		if json.Unmarshal(localResultObject(t, body)["current_generations"], &rows) != nil || len(rows) != 1 || len(localResultCompact(t, rows[0])) != 916 || fmt.Sprintf("%x", sha256.Sum256(localResultCompact(t, rows[0]))) != "de1ef7790fd249fa7949e24e1ef7ef361d7a9be18c44f13877ce872ffce435b3" {
			t.Fatal("managed current bytes changed")
		}

		human, err := RenderGeneratedListHuman(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Resource contract: " + readerID(localResultID(9)), "Remote completion: deletion-acknowledged", "retirement manual", "Retiring duty: " + readerID(localResultID(8))} {
			if !bytes.Contains(human, []byte(want)) {
				t.Fatal("managed human generation lost semantic fact", want)
			}
		}
		for _, field := range []string{"resource contract", "resource digest", "completion", "retirement"} {
			invalid := *r.View
			invalid.CurrentGenerations = []core.GeneratedCurrentGeneration{*p}
			switch field {
			case "resource contract":
				invalid.CurrentGenerations[0].ResourceContractID = contract.ID{}
			case "resource digest":
				invalid.CurrentGenerations[0].ResourceDigest = contract.ID{}
			case "completion":
				invalid.CurrentGenerations[0].CompletionClass = 0
			case "retirement":
				invalid.CurrentGenerations[0].RetirementMode = 0
			}
			bad := r
			bad.View = &invalid
			if body, err := RenderGeneratedListJSON(bad); err == nil || body != nil {
				t.Fatal("managed lost its required remote field", field)
			}
		}
	})
	t.Run("effect and create Duty", func(t *testing.T) {
		r := localResultList()
		r.View.Effects, r.View.Duties = []core.GeneratedEffectFact{localResultEffect()}, []core.GeneratedDutyFact{localResultDuty()}
		body, err := RenderGeneratedListJSON(r)
		if err != nil {
			t.Fatal("local effect or create Duty refused", err)
		}
		doc := localResultObject(t, body)
		for _, field := range []string{"attempts", "duties"} {
			row := localResultFirst(t, doc[field])
			localResultNulls(t, row, "target")
			if string(row["progress"]) != "[]" {
				t.Fatal("local row invented retirement progress")
			}
			facts := localResultObject(t, row["facts"])
			localResultNulls(t, facts, "resource_contract_id", "completion_class")
			for name, id := range map[string]contract.ID{"config_contract_id": localResultID(6), "descriptor_id": localResultID(7), "executor_id": localResultID(15), "credential_route_id": localResultID(19), "result_contract_id": localResultID(16)} {
				if string(facts[name]) != `"`+readerID(id)+`"` {
					t.Fatal("local work lost exact installed identity", name)
				}
			}
			if field == "attempts" {
				localResultNulls(t, facts, "resource_digest", "hazard_id")
				if string(facts["generation_id"]) != `"`+readerID(localResultID(2))+`"` {
					t.Fatal("local effect lost its selected generation without a target")
				}
			} else {
				localResultNulls(t, facts, "generation_id", "retirement_policy")
			}
		}
		human, err := RenderGeneratedListHuman(r)
		if err != nil || !bytes.Contains(human, []byte(readerID(r.View.Effects[0].Record.AttemptID))) || !bytes.Contains(human, []byte(readerID(r.View.Duties[0].Record.DutyID))) || bytes.Contains(human, []byte("Warning")) {
			t.Fatal("human local work changed facts or invented a remote warning", err)
		}
	})
	t.Run("create Duty absences", func(t *testing.T) {
		for _, field := range []string{"target", "progress", "generation", "retirement", "warning", "completion evidence"} {
			t.Run(field, func(t *testing.T) {
				r := localResultList()
				duty := localResultDuty()
				switch field {
				case "target":
					target := generatedRendererTarget()
					duty.Target = &target
				case "progress":
					duty.Progress = []contract.GeneratorProgress{{}}
				case "generation":
					duty.GenerationID = localResultID(2)
				case "retirement":
					duty.RetirementMode = contract.GeneratedRetirementManual
				case "warning":
					duty.Warnings.LateEffect = true
				case "completion evidence":
					duty.EvidenceCeiling = contract.ReceiptEvidenceAcknowledged
				}
				r.View.Duties = []core.GeneratedDutyFact{duty}
				if body, err := RenderGeneratedListJSON(r); err == nil || body != nil {
					t.Fatal("local Duty invented remote or selected-value facts")
				}
			})
		}
	})
	t.Run("inspection", func(t *testing.T) {
		r := localResultInspection(t)
		if err := r.ValidateMetadataWorkOutput(); err != nil {
			t.Fatal("local inspection DTO invalid before Full rendering", err)
		}
		var machine, human bytes.Buffer
		if err := WriteInspectionJSON(t.Context(), &machine, r); err != nil {
			t.Fatal("local inspection refused", err)
		}
		payload := localResultObject(t, localResultObject(t, machine.Bytes())["payload"])
		localResultNulls(t, localResultFirst(t, payload["entries"]), "retirement_mode")
		generated := localResultObject(t, payload["generated"])
		localResultNulls(t, localResultFirst(t, generated["current_generations"]), "resource_contract_id", "resource_digest", "completion_class", "retirement_policy", "retiring_duty_id")
		if err := WriteInspectionHuman(t.Context(), &human, r); err != nil {
			t.Fatal("human inspection refused local current facts", err)
		}
		current := r.View.Generated.CurrentGenerations[0]
		for _, want := range []string{fmt.Sprintf("Current generation %q: %s; epoch %d; lifecycle none; retirement not-applicable\n", current.Name, readerID(current.GenerationID), current.Epoch), "Original operation: " + readerID(current.OriginOperationID), "original attempt: " + readerID(current.OriginAttemptID), "resource incarnation: " + readerID(current.ResourceID), "Configuration contract: " + readerID(current.ConfigContractID)} {
			if !bytes.Contains(human.Bytes(), []byte(want)) {
				t.Fatal("human inspection lost local current fact or absence", want)
			}
		}
		for _, absent := range []string{"Remote completion:", "Retiring duty:", "Resource contract:", "Resource digest:", "retirement manual", "retirement auto"} {
			if bytes.Contains(human.Bytes(), []byte(absent)) {
				t.Fatal("local inspection invented managed generation facts", absent)
			}
		}
	})
	t.Run("managed inspection fields", func(t *testing.T) {
		r := localResultInspection(t)
		p := &r.View.Generated.CurrentGenerations[0]
		p.LifecycleMode, p.ResourceContractID, p.ResourceDigest = contract.GeneratorLifecycleManaged, localResultID(9), localResultID(10)
		p.CompletionClass, p.RetirementMode = contract.GeneratedCompletionAcknowledged, contract.GeneratedRetirementManual
		r.View.Entries[0].RetirementMode = p.RetirementMode
		var out bytes.Buffer
		if err := WriteInspectionJSON(t.Context(), &out, r); err != nil {
			t.Fatal("managed inspection refused", err)
		}
		payload := localResultObject(t, localResultObject(t, out.Bytes())["payload"])
		if string(localResultFirst(t, payload["entries"])["retirement_mode"]) != "1" {
			t.Fatal("managed inspection changed numeric retirement mode")
		}
		current := localResultFirst(t, localResultObject(t, payload["generated"])["current_generations"])
		for name, want := range map[string]string{"resource_contract_id": `"` + readerID(p.ResourceContractID) + `"`, "resource_digest": `"` + readerID(p.ResourceDigest) + `"`, "completion_class": `"deletion-acknowledged"`, "retirement_policy": `"manual"`} {
			if string(current[name]) != want {
				t.Fatal("managed inspection changed its remote fields", name)
			}
		}
	})
	t.Run("closed current kind and remote fields", func(t *testing.T) {
		for _, field := range []string{"lifecycle", "resource contract", "resource digest", "completion", "retirement"} {
			t.Run(field, func(t *testing.T) {
				r := localResultList()
				p := &r.View.CurrentGenerations[0]
				switch field {
				case "lifecycle":
					p.LifecycleMode = 0
				case "resource contract":
					p.ResourceContractID = localResultID(24)
				case "resource digest":
					p.ResourceDigest = localResultID(24)
				case "completion":
					p.CompletionClass = contract.GeneratedCompletionAcknowledged
				case "retirement":
					p.RetirementMode = contract.GeneratedRetirementManual
				}
				if body, err := RenderGeneratedListJSON(r); err == nil || body != nil {
					t.Fatal("contradictory local current row escaped preflight")
				}
			})
		}
	})
	t.Run("closed effect absence and failure reason", func(t *testing.T) {
		for _, field := range []string{"valid failure", "reason", "target", "progress", "resource digest", "route", "descriptor", "completion", "hazard", "warning"} {
			t.Run(field, func(t *testing.T) {
				r := localResultList()
				v := localResultEffect()
				v.Record.State, v.Record.FailureReason, v.Reason, v.GenerationID = contract.GeneratedEffectFailedTerminal, 2, 2, contract.ID{}
				switch field {
				case "reason":
					v.Reason = 3
				case "target":
					target := generatedRendererTarget()
					v.Target = &target
				case "progress":
					v.Progress = []contract.GeneratorProgress{{}}
				case "resource digest":
					v.ResourceDigest = localResultID(24)
				case "route":
					v.Record.CredentialRouteID = contract.ID{}
				case "descriptor":
					v.Record.DescriptorID = contract.ID{}
				case "completion":
					v.Record.CompletionClass = contract.GeneratedCompletionAcknowledged
				case "hazard":
					v.HazardID = localResultID(24)
				case "warning":
					v.Warnings.PossibleLiveResidue = true
				}
				r.View.Effects = []core.GeneratedEffectFact{v}
				body, err := RenderGeneratedListJSON(r)
				if field == "valid failure" {
					if err != nil || !bytes.Contains(body, []byte(`"reason": 2`)) {
						t.Fatal("authenticated local failure reason refused", err)
					}
				} else if err == nil || body != nil {
					t.Fatal("contradictory local effect escaped preflight")
				}
			})
		}
	})
	t.Run("inspection late refusal writes nothing", func(t *testing.T) {
		r := localResultInspection(t)
		r.View.Generated.Effects = []core.GeneratedEffectFact{localResultEffect()}
		r.View.Generated.Effects[0].Warnings.LateEffect = true
		for _, render := range []func(*bytes.Buffer) error{
			func(out *bytes.Buffer) error { return WriteInspectionJSON(t.Context(), out, r) },
			func(out *bytes.Buffer) error { return WriteInspectionHuman(t.Context(), out, r) },
		} {
			var out bytes.Buffer
			if err := render(&out); err == nil || out.Len() != 0 {
				t.Fatal("invalid last local row wrote partial output")
			}
		}
	})
	t.Run("maximum current scalar rows", func(t *testing.T) {
		for _, local := range []bool{true, false} {
			r := localResultList()
			p := &r.View.CurrentGenerations[0]
			p.Name, p.Epoch, p.RetiringDutyID = strings.Repeat("\x00", 256), math.MaxUint64, localResultID(8)
			want := 2317
			if !local {
				p.LifecycleMode, p.ResourceContractID, p.ResourceDigest, p.CompletionClass, p.RetirementMode = contract.GeneratorLifecycleManaged, localResultID(9), localResultID(10), contract.GeneratedCompletionConfirmed, contract.GeneratedRetirementManual
				want = 2468
			}
			body, err := RenderGeneratedListJSON(r)
			if err != nil {
				t.Fatal("maximum current row refused", err)
			}
			var rows []json.RawMessage
			if json.Unmarshal(localResultObject(t, body)["current_generations"], &rows) != nil || len(rows) != 1 || len(localResultCompact(t, rows[0]))+1 != want {
				t.Fatal("maximum current row differs from independent field count", local, len(localResultCompact(t, rows[0]))+1, want)
			}
		}
	})
}

// Scalar-row byte commitments cover compact JSON independently of presentation.
func localResultCompact(t *testing.T, body []byte) []byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		t.Fatal(err)
	}
	return compact.Bytes()
}
