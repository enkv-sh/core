package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

var preservationCaptureNames = []string{"supplied-recovery-disabled", "supplied-recovery-enabled", "retiring-release-unknown-publication", "active-residue", "final-hazards", "discarded-publication-warning"}

var preservationCaptureHashes = map[string]string{
	"active-residue":                       "7c4bc661586859c35939e2b074178d25e4d4dc13f84ada421cbeba1884ff3f77",
	"discarded-publication-warning":        "f2696eca62da070947031bf55ae074627ce8c7b3e34079620686e42c0fb48db0",
	"final-hazards":                        "b48628ec521255a13e940c25d4570b094731d16adad8e815c00af65ec6068c3e",
	"retiring-release-unknown-publication": "98b45069a50e44d2be4f3238b8bc46415aa9702bc40c94f47ce26b8d29470832",
	"supplied-recovery-disabled":           "273ac23bfc08f35c53f716965c7914c42df5ffc690267761083e4c2ee228b61b",
	"supplied-recovery-enabled":            "83345de2b0e4f88efbb262ff17cb1098371ed7ac756afc7e53680cab35fcd623",
}

func readPreservationCapture(t testing.TB, name string) processFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("tests/shared/testdata/preservation", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", contract.Hash(body)) != preservationCaptureHashes[name] {
		t.Fatal("preserved capture bytes changed")
	}
	var input processFixture
	if err := json.Unmarshal(body, &input); err != nil {
		t.Fatal(err)
	}
	if input.PreservationCase != name || input.ObjectDirectory != "" || len(input.Objects) == 0 || input.Generation == 0 || len(input.ExpectedRecipients) != 2 || len(input.ExpectedReceiptOrder) == 0 || input.GeneratedRecord != nil || input.GeneratedFinal || input.GeneratedWriter != nil || len(input.WriterObjects) != 0 {
		t.Fatal("preserved capture is not a self-contained read-only state")
	}
	return input
}

// full_only: false
func TestPreservedSyntheticStatesColdReplay(t *testing.T) {
	for _, name := range preservationCaptureNames {
		t.Run(name, func(t *testing.T) { checkFreshProcessInput(t, readPreservationCapture(t, name)) })
	}
}

// full_only: false
func TestPreservedSyntheticStatesRefuseDamagedClosure(t *testing.T) {
	for _, name := range preservationCaptureNames {
		t.Run(name, func(t *testing.T) {
			for _, damage := range []string{"missing-head", "changed-head", "missing-root", "changed-root"} {
				t.Run(damage, func(t *testing.T) {
					input := readPreservationCapture(t, name)
					key := input.Descriptor.HeadKey
					if damage == "missing-root" || damage == "changed-root" {
						key = mustKey(t, input.Descriptor.Prefix, input.ExpectedImage.RootRef)
					}
					object, present := input.Objects[key]
					if !present || len(object.Body) == 0 {
						t.Fatal("damage target absent")
					}
					if damage == "missing-head" || damage == "missing-root" {
						delete(input.Objects, key)
					} else {
						object.Body[len(object.Body)/2] ^= 1
						input.Objects[key] = object
					}
					store := &memoryStore{desc: input.Descriptor, configuration: input.Configuration, objects: input.Objects, generation: input.Generation}
					admission := processPublicAdmission(input.Domain, input.Trust, input.Descriptor, input.PublicKey, input.DomainBasis)
					if input.CurrentBasis != nil {
						admission.admission.current = input.CurrentBasis.owned()
						admission.admission.epoch = input.Epoch
					}
					session, result := Open(t.Context(), admission, store)
					want := IntegrityFailure
					if damage == "missing-head" {
						want = RootLossUnsupported
					}
					if damage == "missing-root" {
						want = EvidenceUnavailable
					}
					if session != nil || result.Outcome != want || store.creates != 0 || store.cas != 0 {
						t.Fatal("damaged preserved closure did not refuse without writes", result)
					}
				})
			}
		})
	}
}

// The expectations below follow the producer operations and their inputs. They
// are separate from ExpectedImage, which records the producer's observed bytes.
func assertPreservationSemantics(t testing.TB, s *StateSession, name string) {
	t.Helper()
	authority, reader := fixtureID(s.root.Domain, "recipient"), fixtureID(s.root.Domain, "reader")
	control := currentControlOf(s)
	recovery := name == "supplied-recovery-enabled" || name == "retiring-release-unknown-publication"
	if control.AuthorityRecipientID != authority || (control.Recovery != nil) != recovery || s.root.RecipientCount != 2 {
		t.Fatal("preserved authority or Recovery mode differs")
	}
	registry := s.registry()
	ids := make([]contract.ID, len(registry))
	for i, row := range registry {
		ids[i] = row.RecipientID
	}
	wantIDs := []contract.ID{authority, reader}
	sortIDs := func(ids []contract.ID) {
		slices.SortFunc(ids, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	}
	sortIDs(ids)
	sortIDs(wantIDs)
	if !slices.Equal(ids, wantIDs) {
		t.Fatal("preserved complete recipient set differs")
	}
	wantNames := []string{}
	var secretCount, members uint32
	var warnings uint8
	var counts [8]uint32
	var groups int
	var kinds []uint16
	failures := 0
	switch name {
	case "supplied-recovery-disabled", "supplied-recovery-enabled":
		wantNames = []string{"alpha", "beta"}
		secretCount, members = 1, 4
		kinds = []uint16{contract.OperationInitializeDomain, contract.OperationApplyDeclaration, contract.OperationEnvelopeRekey}
	case "retiring-release-unknown-publication":
		wantNames = []string{"a-seed", "current-b", "later-b"}
		secretCount, members = 2, 3
		warnings = WarningOrphanGeneratedEffect | WarningLateDestructiveEffect | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
		counts = [8]uint32{2, 2, 1, 2, 0, 0, 0, 1}
		groups = 5
		failures = 1
		kinds = []uint16{contract.OperationInitializeDomain, contract.OperationApplyDeclaration, contract.OperationApplyDeclaration, contract.OperationEndSelectedWork, contract.OperationEndSelectedWork, contract.OperationApplyDeclaration}
	case "active-residue":
		counts = [8]uint32{0, 0, 2, 1, 1, 0, 1, 0}
		groups = 3
		kinds = []uint16{contract.OperationInitializeDomain}
	case "final-hazards":
		counts = [8]uint32{0, 0, 2, 0, 2, 1, 1, 0}
		groups = 2
		failures = 1
		kinds = []uint16{contract.OperationInitializeDomain, contract.OperationApplyDeclaration}
	case "discarded-publication-warning":
		wantNames = []string{"member-000"}
		members = 1
		groups = 4
		warnings = WarningPublicationOrderValue | WarningDiscardedExactEvidence | WarningPossibleStoreGarbage
		kinds = []uint16{contract.OperationInitializeDomain, contract.OperationEndSelectedWork}
	default:
		t.Fatal("unknown preserved semantic case")
	}
	names := make([]string, len(s.root.Names))
	for i, row := range s.root.Names {
		names[i] = row.Name
	}
	g := s.root.Generated
	gotCounts := [8]uint32{g.GeneratedCurrent, g.Retiring, g.Attempts, g.Duties, g.Hazards, g.Results, g.Materials, g.PendingReleases}
	if !slices.Equal(names, wantNames) || s.root.ValueEntryCount != uint32(len(wantNames)) || s.root.SecretCount != secretCount || s.root.MembershipCount != members || s.root.WarningBits != warnings || gotCounts != counts || len(s.adminIndex.Groups) != groups {
		t.Fatal("preserved names, counts, work or warnings differ", names, gotCounts)
	}
	for _, named := range s.root.Names {
		entry := s.valueEntry(named.Slot)
		wantMembers := []contract.ID{authority}
		if name == "supplied-recovery-disabled" || name == "supplied-recovery-enabled" {
			wantMembers = wantIDs
		}
		if !slices.Equal(entry.Recipients, wantMembers) {
			t.Fatal("preserved complete membership differs", entry.Name)
		}
		switch entry.Name {
		case "beta":
			if entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, []byte("preserved plain value")) {
				t.Fatal("preserved plain input differs")
			}
		case "a-seed", "member-000":
			if entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Plain || !bytes.Equal(entry.ValueBytes, []byte{0}) {
				t.Fatal("preserved seed input differs")
			}
		case "alpha":
			if entry.ValueSource != contract.Supplied || entry.ConfidentialityClass != contract.Secret || s.root.SecretOrdinaryWrapCount != 2 {
				t.Fatal("preserved supplied secret access differs")
			}
			row := s.recipientRecord(authority)
			checkSuccessorConsumer(t, s, successorConsumerInput{Binding: contract.BindingTableRow{SubjectKind: 1, SubjectID: authority, Binding: *row.CurrentBinding}, Name: "alpha", Value: custody.StandardValue})
		case "current-b", "later-b":
			if entry.ValueSource != contract.Generated || entry.ConfidentialityClass != contract.Secret || entry.Generated.OriginAttemptID.IsZero() {
				t.Fatal("preserved current generation differs")
			}
		}
	}
	windows, err := s.receiptWindows(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(windows.Order) != len(kinds) || len(windows.Failures) != failures || len(windows.Successes) != len(kinds)-failures {
		t.Fatal("preserved receipt windows differ")
	}
	for i, id := range windows.Order {
		var found *contract.CompactMutationReceipt
		for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
			for j := range rows {
				if rows[j].OperationID == id {
					row := rows[j]
					found = &row
				}
			}
		}
		failed := slices.ContainsFunc(windows.Failures, func(row contract.CompactMutationReceipt) bool { return row.OperationID == id })
		wantFailed := name == "retiring-release-unknown-publication" && i == 2 || name == "final-hazards" && i == 1
		if found == nil || found.OperationKind != kinds[i] || failed != wantFailed {
			t.Fatal("preserved terminal operation order differs", i)
		}
	}
	publication, err := selectedPublicationRelation(s.selectedImage())
	if err != nil {
		t.Fatal(err)
	}
	switch name {
	case "retiring-release-unknown-publication":
		if len(publication.markers) != 1 || len(publication.coordinates) != 1 {
			t.Fatal("preserved unknown publication set differs")
		}
		for _, marker := range publication.markers {
			if marker.State != contract.PublicationUnknown {
				t.Fatal("preserved publication uncertainty differs")
			}
		}
		work, err := s.selectedGeneratedWork(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if work.parent != nil || len(work.releases) != 1 {
			t.Fatal("preserved release lifetime differs")
		}
		for _, mapping := range work.releases {
			if mapping.release.State != contract.GeneratedReleasePending || mapping.release.InboxID != mapping.attempt.InboxID || mapping.release.OriginalResultID != mapping.attempt.ResultID {
				t.Fatal("preserved original release ancestry differs")
			}
		}
		duties := 0
		for key, row := range work.records {
			if key.kind == contract.GeneratedDutySupportKind {
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil || duty.Kind != contract.GeneratedDutyRetirement {
					t.Fatal("preserved retirement Duty differs", err)
				}
				duties++
			}
		}
		if duties != 2 {
			t.Fatal("preserved retirement Duty set differs")
		}
	case "discarded-publication-warning":
		if len(publication.markers) != 2 || len(publication.coordinates) != 2 {
			t.Fatal("preserved post-discard publication set differs")
		}
		actions := []uint8{}
		var create, write contract.PublicationMarker
		for _, marker := range publication.markers {
			if marker.State != contract.PublicationAcknowledged {
				t.Fatal("post-discard acknowledgement differs")
			}
			actions = append(actions, marker.Projection.Action)
			if marker.Projection.Action == contract.PublicationCreateEmpty {
				create = marker
			}
			if marker.Projection.Action == contract.PublicationWriteValue {
				write = marker
			}
			if marker.Projection.Action == contract.PublicationWriteValue && marker.LateEffectRisk != 1 {
				t.Fatal("post-discard late write warning lost")
			}
		}
		slices.Sort(actions)
		want := []uint8{contract.PublicationCreateEmpty, contract.PublicationWriteValue}
		slices.Sort(want)
		if create.AdmissionOrdinal != 1 || write.AdmissionOrdinal != 2 || create.CoordinateID != write.CoordinateID || create.Projection.TargetRowDigest != write.Projection.TargetRowDigest || write.Projection.OwnedBirthAttemptID != create.AttemptID {
			t.Fatal("post-discard action order or exact target differs")
		}
		if !slices.Equal(actions, want) {
			t.Fatal("post-discard fixed action chain differs")
		}
		for _, coordinate := range publication.coordinates {
			if coordinate.LateEffectRisk != 1 {
				t.Fatal("post-discard coordinate risk lost")
			}
		}
	default:
		if len(publication.markers) != 0 || len(publication.coordinates) != 0 {
			t.Fatal("unexpected preserved publication state")
		}
	}
	if name == "active-residue" || name == "final-hazards" {
		assertPreservedCreateLineage(t, s, name == "final-hazards")
	}
}

func assertPreservedCreateLineage(t testing.TB, s *StateSession, final bool) {
	t.Helper()
	work, err := s.selectedGeneratedWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(work.attempts) != 2 || len(work.releases) != 0 || (work.parent == nil) != final || (work.phase == nil) != final {
		t.Fatal("preserved Create lifetime differs")
	}
	var original, successor generatedAttempt
	for _, attempt := range work.attempts {
		if attempt.record.PredecessorAttemptID.IsZero() {
			original = attempt
		} else {
			successor = attempt
		}
	}
	if original.record.AttemptID.IsZero() || successor.record.AttemptID.IsZero() || original.record.State != contract.GeneratedEffectClosedWithResidue || original.record.Stage != contract.GeneratedStageTerminal || len(original.result) != 0 || successor.record.LineageID != original.record.LineageID {
		t.Fatal("preserved residue ancestry differs")
	}
	packet, present, outcome := s.ReadGeneratedResult(t.Context(), original.record.AttemptID)
	if outcome != (Result{}) || !present || len(packet) == 0 {
		t.Fatal("preserved original returned packet missing", outcome)
	}
	result, err := contract.InspectGeneratedResultRecord(packet)
	if err != nil || result.Core.AttemptID != original.record.AttemptID || result.Core.ResultID != original.record.ResultID || result.SafeFacts.Disposition != contract.GeneratorDispositionCompleteCreate || len(packet) != 1357 || fmt.Sprintf("%x", contract.Hash(packet)) != "5a42bae328ff694abbe1be1a620ba7e221289c0cadd0fc0a1c9dc04faa1bd3a3" {
		t.Fatal("preserved original inbox correlation differs", err)
	}
	if fmt.Sprintf("%x", original.record.AttemptID) != "acad767b058872ce90698733860fa976379da96f41c21001e96b1c97df7e7575" || fmt.Sprintf("%x", original.record.InboxID) != "1bd27c141f2709f48461a5885bd42ba5f00593e9df45dd36861b65d9910ec520" {
		t.Fatal("preserved original result coordinate differs")
	}
	wantState, wantHistory := uint8(contract.GeneratedEffectTransmitted), uint32(2)
	if final {
		wantState, wantHistory = contract.GeneratedEffectFailedTerminal, 3
	}
	if successor.record.State != wantState || successor.record.History.Count != wantHistory {
		t.Fatal("preserved successor state or history length differs")
	}
	history, err := work.vectors.resolve(contract.GeneratedAttemptSupportKind, successor.record.AttemptID, contract.GeneratorVectorHistory, successor.record.History)
	if err != nil || len(history) != int(wantHistory) {
		t.Fatal("preserved complete lineage history differs", err)
	}
	rows := make([]contract.GeneratorHistory, len(history))
	for i, body := range history {
		rows[i], err = contract.InspectGeneratorHistory(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	if rows[0].PredecessorAttemptID != original.record.AttemptID || rows[0].Outcome != contract.GeneratedEffectClosedWithResidue || rows[0].Edge != contract.GeneratorGuardResidue || rows[0].NextAttemptID != rows[1].PredecessorAttemptID {
		t.Fatal("preserved residue history differs")
	}
	if final {
		if rows[1].Outcome != contract.GeneratedEffectConfirmedNoEffect || rows[1].NextAttemptID != successor.record.AttemptID || rows[2].PredecessorAttemptID != successor.record.AttemptID || rows[2].Outcome != contract.GeneratedEffectFailedTerminal || !rows[2].NextAttemptID.IsZero() || successor.record.PredecessorAttemptID != rows[1].PredecessorAttemptID || len(successor.result) == 0 {
			t.Fatal("preserved final three-entry ancestry differs")
		}
		if _, kept := work.attempts[rows[1].PredecessorAttemptID]; kept {
			t.Fatal("qualified-no-effect Attempt retained an owner")
		}
		if _, kept := work.records[generatedRecordKey{contract.GeneratedResultSupportKind, rows[1].ResultID}]; kept {
			t.Fatal("qualified-no-effect result retained without an owner")
		}
	} else if successor.record.PredecessorAttemptID != original.record.AttemptID || rows[1].PredecessorAttemptID != successor.record.AttemptID || rows[1].Outcome != contract.GeneratedEffectTransmitted || len(successor.result) != 0 {
		t.Fatal("preserved entered successor differs")
	}
}
