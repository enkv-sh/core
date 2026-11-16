package compositionfull

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// full_only: false
func TestInspectionHumanSemanticProjection(t *testing.T) {
	t.Run("empty-observation", func(t *testing.T) {
		r := publicQueryRendererDomain(t)
		var out bytes.Buffer
		if err := WriteInspectionHuman(t.Context(), &out, r); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		for _, want := range []string{"Domain inspection: success", "Current publication blockers: 0 across 0 coordinates", "Active operation: none", "No generated work or current generations were observed."} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing semantic fact %q in %s", want, text)
			}
		}
		for _, absent := range []string{"Configuration descriptor:", "Pages:", "Root digest:", "No supported next action is available."} {
			if strings.Contains(text, absent) {
				t.Fatalf("unexpected physical or unscoped fact %q", absent)
			}
		}
	})
	t.Run("empty-blocker-indexes", func(t *testing.T) {
		r := publicQueryRendererDomain(t)
		for i, target := range []string{"retained/a", "retained/b"} {
			id, err := contract.PublicationCoordinateID(r.DomainID, "service", target)
			if err != nil {
				t.Fatal(err)
			}
			r.View.Output.Coordinates = append(r.View.Output.Coordinates, contract.PublicationCoordinate{Schema: 5, DomainID: r.DomainID, CoordinateID: id, ServiceContractID: "service", CanonicalTarget: target, BindingState: contract.PublicationBindingRetired, LastBindingIncarnationID: contract.ID{2}, LastEntryIncarnationID: contract.ID{3}, CurrentPublicationIncarnationID: contract.ID{4, byte(i)}})
		}
		slices.SortFunc(r.View.Output.Coordinates, func(a, b contract.PublicationCoordinate) int {
			return bytes.Compare(a.CoordinateID[:], b.CoordinateID[:])
		})
		for i, row := range r.View.Output.Coordinates {
			r.View.Output.CurrentBlockers = append(r.View.Output.CurrentBlockers, core.InspectionCurrentBlockers{CoordinateIndex: uint16(i)})
			r.View.Work.PublicationOrder = append(r.View.Work.PublicationOrder, format.PublicationCoordinateOrder{CoordinateID: row.CoordinateID, Incarnations: []contract.ID{row.CurrentPublicationIncarnationID}})
		}
		var out bytes.Buffer
		if err := WriteInspectionHuman(t.Context(), &out, r); err != nil {
			t.Fatal("fixture/render", err)
		}
		if !strings.Contains(out.String(), "Current publication blockers: 0 across 2 coordinates") {
			t.Fatal("empty index counted as blocker", out.String())
		}
		for _, row := range r.View.Output.Coordinates {
			if !strings.Contains(out.String(), readerID(row.CoordinateID)) || !strings.Contains(out.String(), row.CanonicalTarget) {
				t.Fatal("retained target lost")
			}
		}
	})
	t.Run("selected-work-relations", func(t *testing.T) {
		r := publicQueryRendererDomain(t)
		d := contract.GeneratorDescriptor{Digest: contract.ID{9}, Length: 4}
		r.View.Work.Groups = []format.AdministrativeGroup{
			{GroupID: contract.ID{2}, OwnerID: contract.ID{3}, TargetID: contract.ID{3}, OwnerKind: contract.AdministrativeGeneratedParent, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: d, Dependencies: d, Disposable: d},
			{GroupID: contract.ID{4}, OwnerID: contract.ID{5}, TargetID: contract.ID{5}, OwnerKind: contract.AdministrativeGeneratedDuty, DutyKind: contract.GeneratedDutyCreate, SelectedEvidenceSummary: contract.AdministrativeEvidenceMissing, Affected: d, Dependencies: d, Disposable: d, RelatedGroupIndexes: []uint16{0}},
		}
		r.View.ActiveOperation = &core.GeneratedActiveOperation{OperationID: contract.ID{2}, PhaseID: contract.ID{6}, OperationKind: contract.OperationApplyDeclaration, Stage: contract.GeneratedStageRetainedResult}
		parent := uint16(0)
		r.View.Work.GroupSelections = []core.InspectionGroupSelection{{Selectable: true}, {Selectable: false, RequiredParentIndex: &parent}}
		var out bytes.Buffer
		if err := WriteInspectionJSON(t.Context(), &out, r); err != nil {
			t.Fatal("valid work fixture refused", err)
		}
		out.Reset()
		if err := WriteInspectionHuman(t.Context(), &out, r); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		for _, want := range []string{"generated-parent", "generated-duty", "Required parent: " + readerID(contract.ID{2}), "Related group: " + readerID(contract.ID{2}), "Selectable: false", "Target: " + readerID(contract.ID{5})} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing work relation %q in %s", want, text)
			}
		}
		r.View.Work.GroupSelections[1].RequiredParentIndex = new(uint16)
		*r.View.Work.GroupSelections[1].RequiredParentIndex = 4
		out.Reset()
		if err := WriteInspectionHuman(t.Context(), &out, r); err == nil || out.Len() != 0 {
			t.Fatal("late invalid work produced output", err, out.String())
		}
	})
	t.Run("generated-work-scope", func(t *testing.T) {
		id := contract.ID{1}
		view := &core.GeneratedListView{DomainID: id, RevisionID: id, SnapshotID: id}
		r := core.PublicGeneratedListResult{Context: core.ReaderOperationContext{Operation: core.GeneratedListOperation, RequestID: id, ExpectedDomain: id}, Result: core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure, ObservedRevision: id, ObservedSnapshotID: id}, StateResult: contract.ReaderSuccess, View: view}
		body, err := RenderGeneratedListHuman(r)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(body, []byte("No generated work or current generations were observed.")) || bytes.Contains(body, []byte("No supported next action is available.")) {
			t.Fatal("empty generated result is ambiguous", string(body))
		}
		view.ActiveOperation = &core.GeneratedActiveOperation{OperationID: id, PhaseID: id, OperationKind: contract.OperationApplyDeclaration, Stage: contract.GeneratedStageObservation}
		body, err = RenderGeneratedListHuman(r)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte("No generated work or current generations were observed.")) || !bytes.Contains(body, []byte("stage observation")) {
			t.Fatal("active operation omitted or numeric", string(body))
		}
	})
	t.Run("original-receipt", func(t *testing.T) {
		r := publicQueryRendererDetail(t)
		var out bytes.Buffer
		if err := WriteReceiptDetailHuman(t.Context(), &out, r); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		for _, want := range []string{"Original receipt:", "State result: success", "Canonical outcome: selected", "Evidence ceiling: canonical", "Operation kind: apply-declaration"} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing original fact %q in %s", want, text)
			}
		}
		if strings.Contains(text, "Encoded receipt:") {
			t.Fatal("human receipt printed encoded backing")
		}
	})
}

func inspectionPublicationEvidenceFixture(t *testing.T, unresolved, late bool) core.PublicDomainInspectionResult {
	t.Helper()
	r := publicQueryRendererDomain(t)
	coordinateID, err := contract.PublicationCoordinateID(r.DomainID, "service", "retained/target")
	if err != nil {
		t.Fatal(err)
	}
	coordinate := contract.PublicationCoordinate{Schema: 5, DomainID: r.DomainID, CoordinateID: coordinateID, ServiceContractID: "service", CanonicalTarget: "retained/target", BindingState: contract.PublicationBindingRetired, LastBindingIncarnationID: contract.ID{3}, LastEntryIncarnationID: contract.ID{12}, CurrentPublicationIncarnationID: contract.ID{40}, LastAdmissionOrdinal: 1, PossibleRemoteObject: 1, DeletionDestinationID: "destination", DeletionConsumerLocator: "resource/locator", DeletionTargetContractID: "target-contract", DeletionConfigContractID: "configuration-contract", DeletionCredentialRouteContractID: "credential-route-contract", DeletionPayloadEncoding: contract.OutputEncodingRaw, DeletionTargetRowDigest: contract.ID{14}}
	if late {
		coordinate.LateEffectRisk = 1
	}
	r.View.Work.PublicationOrder = []format.PublicationCoordinateOrder{{CoordinateID: coordinateID, Incarnations: []contract.ID{{40}}}}
	r.View.Output.CurrentBlockers = []core.InspectionCurrentBlockers{{}}
	if unresolved {
		coordinate.OwnerState = contract.PublicationOwnerUncertainCreate
		coordinate.LatestUnresolvedAttemptID = contract.ID{20}
		projection := contract.PublicationProjection{Schema: 4, DomainID: r.DomainID, ConfigurationDigest: contract.ID{13}, CoordinateID: coordinateID, BindingIncarnationID: contract.ID{3}, EntryIncarnationID: contract.ID{12}, TargetRowDigest: contract.ID{14}, Action: contract.PublicationCreateEmpty, PolicyDigest: contract.ID{15}, RequestContractDigest: contract.ID{16}, ActingRecipientID: contract.ID{5}}
		commitment, err := contract.PublicationProjectionCommitment(projection)
		if err != nil {
			t.Fatal(err)
		}
		marker := contract.PublicationMarker{Schema: 5, DomainID: r.DomainID, OperationID: contract.ID{8}, AttemptID: contract.ID{20}, CoordinateID: coordinateID, PublicationIncarnationID: contract.ID{40}, AdmissionOrdinal: 1, Projection: projection, ProjectionCommitment: commitment, AuthoritySubjectDigest: contract.ID{10}, ExecutorID: "executor", CredentialRouteID: "route", State: contract.PublicationUnknown, Evidence: contract.PublicationEvidence{Schema: 3, Entry: contract.PublicationMayHaveEnteredEntry, Class: contract.PublicationUnproved, ResponseContractDigest: contract.ID{11}}, BirthServiceContractID: "service", BirthTargetContractID: "target-contract"}
		if late {
			marker.LateEffectRisk = 1
		}
		r.View.Output.Markers = []contract.PublicationMarker{marker}
		r.View.Output.CurrentBlockers[0].MarkerIndexes = []uint16{0}
	}
	r.View.Output.Coordinates = []contract.PublicationCoordinate{coordinate}
	r.View.Output.Warnings = core.InspectionOutputWarnings{UnresolvedPublication: unresolved, LateWriteRisk: late}
	r.View.Warnings.Output = r.View.Output.Warnings
	return r
}

// full_only: false
func TestInspectionHumanPreservesAcknowledgementStatusWithoutOptionalIdentifiers(t *testing.T) {
	r := inspectionPublicationEvidenceFixture(t, true, false)
	coordinate := &r.View.Output.Coordinates[0]
	coordinate.OwnerState = contract.PublicationOwnerNone
	coordinate.LatestUnresolvedAttemptID = contract.ID{}
	coordinate.LastAdmissionOrdinal = 2
	birth := &r.View.Output.Markers[0]
	birth.State = contract.PublicationAcknowledged
	birth.Evidence.Class = contract.PublicationRequestAcknowledged
	birth.Evidence.NormalizedStatus = 201
	birth.Evidence.SafeResourceID = "created-resource"
	birth.Evidence.ConsumerLocator = "resource/locator"
	policy := *birth
	policy.OperationID, policy.AttemptID = contract.ID{9}, contract.ID{21}
	policy.AdmissionOrdinal = 2
	policy.Projection.Action = contract.PublicationUpdatePolicy
	policy.BirthServiceContractID, policy.BirthTargetContractID = "", ""
	policy.Projection.OwnedBirthAttemptID = birth.AttemptID
	commitment, err := contract.PublicationProjectionCommitment(policy.Projection)
	if err != nil {
		t.Fatal(err)
	}
	policy.ProjectionCommitment = commitment
	policy.Evidence.NormalizedStatus = 204
	policy.Evidence.SafeRequestID, policy.Evidence.SafeResourceID, policy.Evidence.ConsumerLocator = "", "", ""
	r.View.Output.Markers = append(r.View.Output.Markers, policy)
	r.View.Output.CurrentBlockers[0].MarkerIndexes = nil
	r.View.Output.Warnings = core.InspectionOutputWarnings{}
	r.View.Warnings.Output = r.View.Output.Warnings
	var machine, human bytes.Buffer
	if err := WriteInspectionJSON(t.Context(), &machine, r); err != nil {
		t.Fatal("valid acknowledged policy fixture refused", err)
	}
	var decoded struct {
		Payload struct {
			Output struct {
				Markers []struct {
					Evidence struct {
						Status   uint16 `json:"normalized_status"`
						Request  string `json:"safe_request_id"`
						Resource string `json:"safe_resource_id"`
						Locator  string `json:"consumer_locator"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Payload.Output.Markers) != 2 {
		t.Fatal("complete marker vector lost")
	}
	evidence := decoded.Payload.Output.Markers[1].Evidence
	if evidence.Status != 204 || evidence.Request != "" || evidence.Resource != "" || evidence.Locator != "" {
		t.Fatal("JSON acknowledgement facts changed", evidence)
	}
	if err := WriteInspectionHuman(t.Context(), &human, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Publication action update-policy: acknowledged", readerID(contract.ID{21}), "normalized status 204"} {
		if !strings.Contains(human.String(), want) {
			t.Fatal("human acknowledgement lost recorded fact", want, human.String())
		}
	}
}

// full_only: false
func TestInspectionHumanPublicationWarningConditions(t *testing.T) {
	for _, cell := range []struct {
		name             string
		bits             uint8
		unresolved, late bool
	}{
		{"none", 0, false, false},
		{"domain-only", core.WarningPublicationOrderValue, false, false},
		{"discarded-only", core.WarningDiscardedExactEvidence, false, false},
		{"unresolved-only", 0, true, false},
		{"late-only", 0, false, true},
		{"combined", core.WarningPublicationOrderValue, true, true},
	} {
		t.Run(cell.name, func(t *testing.T) {
			r := publicQueryRendererDomain(t)
			if cell.unresolved || cell.late {
				r = inspectionPublicationEvidenceFixture(t, cell.unresolved, cell.late)
			}
			r.View.DomainWarningBits = cell.bits
			r.View.Warnings.Domain = core.PublicDomainWarnings{PublicationOrderValue: cell.bits&core.WarningPublicationOrderValue != 0, DiscardedExactEvidence: cell.bits&core.WarningDiscardedExactEvidence != 0}
			r.View.Output.Warnings.DomainWideWarning = cell.bits != 0
			r.View.Warnings.Output = r.View.Output.Warnings
			var machine, human bytes.Buffer
			if err := WriteInspectionJSON(t.Context(), &machine, r); err != nil {
				t.Fatal("valid warning fixture refused", err)
			}
			var decoded struct {
				Payload struct {
					Output struct {
						Warnings struct {
							Domain     bool `json:"domain_wide_warning"`
							Unresolved bool `json:"unresolved_publication"`
							Late       bool `json:"late_write_risk"`
						}
					}
				}
			}
			if err := json.Unmarshal(machine.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			warnings := decoded.Payload.Output.Warnings
			if warnings.Domain != (cell.bits != 0) || warnings.Unresolved != cell.unresolved || warnings.Late != cell.late {
				t.Fatal("JSON warning facts changed", warnings)
			}
			if err := WriteInspectionHuman(t.Context(), &human, r); err != nil {
				t.Fatal(err)
			}
			for _, fact := range []struct {
				text    string
				present bool
			}{
				{"Domain-wide publication warning:", cell.bits != 0},
				{"Unresolved publication attempts remain", cell.unresolved},
				{"A late write can still change the destination.", cell.bits != 0 || cell.late},
				{"Retained publication late-write risk:", cell.late},
				{"Publication acknowledgement does not prove current remote order or value.", cell.bits != 0 || cell.unresolved || cell.late},
				{"Discarded exact evidence cannot be recovered", cell.bits&core.WarningDiscardedExactEvidence != 0},
			} {
				if strings.Contains(human.String(), fact.text) != fact.present {
					t.Fatal("human warning changed independent fact", fact.text, fact.present, human.String())
				}
			}
		})
	}
}
