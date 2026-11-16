package core

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// The child receives only the selected group and public current basis. It
// generates its own proposal identities after a fresh authenticated open.
type processEndWorkFacts struct {
	GroupID      contract.ID
	CurrentBasis *successionBasisInput
	Epoch        uint64
	Installed    bool
	NormalSigner contract.PublicSigningBinding
}

// full_only: false
func TestEndWorkFreshProcessSelectsAndReopens(t *testing.T) {
	testEndWorkFreshProcessSelectsAndReopens(t, t.Context(), false)
}

// full_only: false
func TestEndWorkFreshInstalledAuthorityProcessSelectsAndReopens(t *testing.T) {
	testEndWorkFreshProcessSelectsAndReopens(t, t.Context(), true)
}

func testEndWorkFreshProcessSelectsAndReopens(t *testing.T, operationCtx context.Context, installed bool) {
	env, selected, _, _ := generatedAuthenticatedDeleteHazardFixture(t, false, 0)
	selected = generatedLifecycleReopen(t, operationCtx, selected, env.Store)
	if len(selected.adminIndex.Groups) != 1 {
		t.Fatal("process exit fixture has no exact selected owner")
	}
	t.Run("cold_administrative_receipt_windows", func(t *testing.T) {
		blob, err := selected.receiptIndexID()
		if err != nil || blob.IsZero() {
			t.Fatal("cold exit fixture has no receipt index", err)
		}
		fragments := 0
		for _, location := range selected.root.Generated.Fragments {
			if location.BlobID != blob {
				continue
			}
			found := false
			for _, page := range selected.support {
				if page.Index != location.SupportPageIndex {
					continue
				}
				if int(location.RowSlot) >= len(page.Records) ||
					page.Records[location.RowSlot].Kind != contract.GeneratedFragmentSupportKind ||
					len(page.Records[location.RowSlot].Body) != 0 {
					t.Fatal("cold Open retained receipt-index fragment bytes")
				}
				found = true
			}
			if !found {
				t.Fatal("cold receipt-index fragment has no selected page")
			}
			fragments++
		}
		windows, found, err := selected.retainedSelectedReceiptWindows()
		if fragments == 0 || !found || err != nil || len(windows.Successes)+len(windows.Failures) == 0 {
			t.Fatal("cold Open lost its authenticated receipt windows", fragments, found, err)
		}
		actual, err := selected.receiptWindowsFromAdministrativeSupport()
		if err != nil || !reflect.DeepEqual(actual, windows) {
			t.Fatal("administrative extraction lost cold selected receipts", err)
		}
		for _, damage := range []func(*StateSession){
			func(s *StateSession) { s.root.Snapshot[0] ^= 1 },
			func(s *StateSession) { s.head.Core.Root.Digest[0] ^= 1 },
		} {
			changed := *selected
			damage(&changed)
			if _, found, err := changed.retainedSelectedReceiptWindows(); found || err != nil {
				t.Fatal("changed selected root reused cached receipt windows", found, err)
			}
			if _, err := changed.receiptWindowsFromAdministrativeSupport(); !errors.Is(err, contract.ErrRecord) {
				t.Fatal("stale-root receipt extraction bypassed mandatory fragment validation", err)
			}
		}
		changed := *selected
		changed.mutationReceipts = nil
		if _, found, err := changed.retainedSelectedReceiptWindows(); !found || !errors.Is(err, contract.ErrRecord) {
			t.Fatal("incomplete exact-root receipt facts were accepted", found, err)
		}
		if _, err := changed.receiptWindowsFromAdministrativeSupport(); !errors.Is(err, contract.ErrRecord) {
			t.Fatal("administrative extraction hid invalid exact-root receipt facts", err)
		}
	})
	t.Run("fresh_process", func(t *testing.T) {
		f := selectedProcessFacts(t, OpenContext{admission: &selected.admission}, selected)
		childFacts := processStoreFacts{Domain: f.Domain, Trust: f.Trust, Descriptor: f.Descriptor,
			PublicKey: f.PublicKey, DomainBasis: f.DomainBasis, ExpectedImage: f.ExpectedImage,
			EndWork: &processEndWorkFacts{GroupID: selected.adminIndex.Groups[0].GroupID,
				CurrentBasis: f.CurrentBasis, Epoch: f.Epoch}}
		role := "end-work"
		if installed {
			role = "end-work-installed"
			childFacts.EndWork.Installed = true
			control, ok := selected.selectedControl()
			if !ok {
				t.Fatal("installed process input has no selected Normal signer")
			}
			childFacts.EndWork.NormalSigner = control.NormalSigning
		}
		store := env.Store.(*memoryStore)
		beforeCreates, beforeCAS := store.creates, store.cas
		public, private := env.Custody.Calls()
		beforeValue := *selected.valueEntry(0)
		beforeWork, err := selected.workSupportRecords(t.Context())
		if err != nil || len(beforeWork) == 0 {
			t.Fatal("process exit fixture has no selected work", err)
		}
		beforeWork = ownedProcessWorkRows(t, selected, beforeWork)
		child := startProcessStoreChild(t, processStoreDiagnostics(t), role, childFacts)
		if err := serveEndWorkProcess(t, child, store, selected, childFacts.EndWork.GroupID, installed); err != nil {
			t.Fatal(err)
		}
		if err := child.join(); err != nil || !child.joined {
			t.Fatal("fresh end-work process did not join", err)
		}
		open, result := Open(context.Background(), OpenContext{admission: &selected.admission}, store)
		if open == nil || result.Outcome != ObservedCurrent || len(open.adminIndex.Groups) != 0 ||
			open.head.EndWork == nil || open.head.EndWork.TargetGroupID != childFacts.EndWork.GroupID {
			t.Fatal("fresh end-work successor did not reopen", result)
		}
		if open.root.Generated.Slices == selected.root.Generated.Slices ||
			open.adminIndex.SliceSnapshot != open.root.Snapshot {
			t.Fatal("fresh end-work did not rebind its changed Slice vector")
		}
		afterWork, err := open.workSupportRecords(t.Context())
		if err != nil || len(afterWork) != 4 ||
			!reflect.DeepEqual(*open.valueEntry(0), beforeValue) || open.root.AccessRecordCount != 1 ||
			store.cas-beforeCAS != 1 || store.creates-beforeCreates == 0 {
			t.Fatalf("fresh end-work changed current state or selected support: err=%v rows=%d valueSame=%t access=%d creates=%d cas=%d",
				err, len(afterWork), reflect.DeepEqual(*open.valueEntry(0), beforeValue), open.root.AccessRecordCount,
				store.creates-beforeCreates, store.cas-beforeCAS)
		}
		afterWork = ownedProcessWorkRows(t, open, afterWork)
		beforeRows := make(map[generatedRecordKey]contract.SupportRecord, len(beforeWork))
		for _, row := range beforeWork {
			beforeRows[generatedRecordKey{kind: row.Kind, id: row.RecordID}] = row
		}
		seen := make(map[contract.SupportRecordKind]bool)
		var intentBlob contract.ID
		var fragmentBlob contract.ID
		for _, row := range afterWork {
			if seen[row.Kind] {
				t.Fatal("fresh end-work duplicated current generated proof", row.Kind)
			}
			seen[row.Kind] = true
			switch row.Kind {
			case contract.OutputConfigurationSliceSupportKind:
				if open.root.OutputConfiguration != selected.root.OutputConfiguration ||
					!reflect.DeepEqual(beforeRows[generatedRecordKey{kind: row.Kind, id: row.RecordID}], row) {
					t.Fatal("fresh end-work changed exact mandatory configuration")
				}
			case contract.GeneratedFragmentSupportKind:
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil || !reflect.DeepEqual(beforeRows[generatedRecordKey{kind: row.Kind, id: row.RecordID}], row) {
					t.Fatal("retained current intent fragment changed", err)
				}
				fragmentBlob = fragment.BlobID
			case contract.GeneratedCreateEvidenceSupportKind:
				if row.RecordID != beforeValue.Generated.CreateResultID ||
					!reflect.DeepEqual(beforeRows[generatedRecordKey{kind: row.Kind, id: row.RecordID}], row) {
					t.Fatal("retained current result is not the selected value proof")
				}
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				location, locationErr := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil || locationErr != nil || carrier.OwnerKind != contract.GeneratorSnapshotOwner ||
					carrier.OwnerID != open.adminIndex.SliceSnapshot || carrier.VectorKind != contract.GeneratorVectorSlices ||
					location.ContentKind != contract.GeneratorContentIntent ||
					location.ContentID != beforeValue.Generated.IntentDigest {
					t.Fatal("successor snapshot lost the current intent location", err, locationErr)
				}
				intentBlob = location.BlobID
			default:
				t.Fatal("fresh end-work retained exclusive selected work", row.Kind)
			}
		}
		if intentBlob.IsZero() || intentBlob != fragmentBlob {
			t.Fatal("successor intent location lost its exact retained fragment")
		}
		if p, k := env.Custody.Calls(); p != public || k != private {
			t.Fatal("effect or decryption custody was used during administrative exit", p-public, k-private)
		}
		q := open.head.EndWork
		if q.AdmissionID.IsZero() || q.AdmissionID == selected.admission.endWorkInvocation ||
			q.TargetOwnerID != selected.adminIndex.Groups[0].OwnerID || q.TargetID != selected.adminIndex.Groups[0].TargetID ||
			q.SelectedEvidenceSummary != selected.adminIndex.Groups[0].SelectedEvidenceSummary ||
			q.BeforeChildCount != uint16(selected.root.ChildCount) || q.AfterChildCount != uint16(open.root.ChildCount) ||
			q.BeforeChildBytes != selected.root.ChildEncodedBytes || q.AfterChildBytes != open.root.ChildEncodedBytes ||
			q.AfterWarningBits&WarningDiscardedExactEvidence == 0 || q.AfterWarningBits&WarningOrphanGeneratedEffect == 0 {
			t.Fatal("fresh end-work lost its selected target, original evidence or bounded warning")
		}
		if window, err := open.receiptWindows(t.Context()); err != nil || len(window.Successes) == 0 ||
			window.Successes[len(window.Successes)-1].OperationID != q.OperationID ||
			window.Successes[len(window.Successes)-1].RequestIdentityDigest != q.RequestCoreDigest ||
			window.Successes[len(window.Successes)-1].AdministrativeOriginalEvidence != q.SelectedEvidenceSummary {
			t.Fatal("fresh end-work receipt lost the original selected evidence", err)
		}
		prior := *open.valueEntry(0)
		input := generatedStatePlanInput(t, open, generatedVectorID(201), []string{prior.Name},
			defaultGeneratedFixtureProfile(), prior.Generated.Epoch+1,
			map[string]contract.ID{prior.Name: prior.Incarnation}, map[string]contract.ValueEntry{prior.Name: prior})
		continued := selectPrivateGeneratedOperation(t, env, open, input, "ordinary work after fresh-process exit")
		continued = generatedLifecycleReopen(t, operationCtx, continued, env.Store)
		if continued == nil || continued.valueEntry(0).Generated.Epoch != prior.Generated.Epoch+1 {
			t.Fatal("fresh-process exit did not restore ordinary generated admission")
		}
		if continued.adminIndex.SliceSnapshot != continued.root.Snapshot {
			t.Fatal("ordinary generated successor did not rebind the retained Slice owner")
		}
	})
}

func ownedProcessWorkRows(t testing.TB, session *StateSession, work []contract.SupportRecord) []contract.SupportRecord {
	t.Helper()
	owned := make(map[generatedRecordKey]contract.SupportRecord)
	for _, row := range selectedSupportRecordsForCustodyFixture(t, session) {
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		if _, duplicate := owned[key]; duplicate {
			t.Fatal("process fixture duplicated selected support", key)
		}
		owned[key] = row
	}
	rows := make([]contract.SupportRecord, len(work))
	for i, row := range work {
		key := generatedRecordKey{kind: row.Kind, id: row.RecordID}
		var found bool
		rows[i], found = owned[key]
		if !found || len(rows[i].Body) == 0 {
			t.Fatal("process fixture lost exact selected work body", key)
		}
	}
	return rows
}

func serveEndWorkProcess(t *testing.T, child *processStoreChild, store *memoryStore, before *StateSession, groupID contract.ID, installed bool) error {
	t.Helper()
	var pending processStoreRequest
	var hasPending bool
	if installed {
		allowed := make(map[string]uint32)
		for _, read := range processReadRequests(t, store.desc, sessionStateImage(t, before)) {
			allowed[read.Key] = read.Maximum
		}
		var heads int
		for i := 0; i < 5*(contract.MaxChildPages+8); i++ {
			request, err := child.next()
			if err != nil {
				return err
			}
			if request.Method != "read" {
				pending, hasPending = request, true
				break
			}
			if allowed[request.Key] != request.Maximum || request.Maximum == 0 {
				return errors.New("installed process read escaped the selected predecessor")
			}
			if request.Key == store.desc.HeadKey {
				heads++
			}
			reply, err := processStoreOperation(store, request, true)
			if err != nil || reply.Read.Status != contract.ReadOK {
				return errors.New("installed process selected predecessor read failed")
			}
			if err := child.reply(reply); err != nil {
				return err
			}
		}
		if !hasPending || heads < 3 {
			return errors.New("installed process did not independently admit inspect, preview and end")
		}
	} else {
		for _, expected := range processReadRequests(t, store.desc, sessionStateImage(t, before)) {
			if err := serveProcessRead(child, store, expected); err != nil {
				return err
			}
		}
		var err error
		pending, err = serveProcessFragmentReads(t, child, store, sessionStateImage(t, before), nil)
		if err != nil {
			return err
		}
		hasPending = true
	}
	created := make(map[string]bool)
	for i := 0; i < contract.MaxChildPages+8; i++ {
		var request processStoreRequest
		if hasPending {
			request, hasPending = pending, false
		} else {
			var err error
			request, err = child.next()
			if err != nil {
				return err
			}
		}
		if request.Method == "cas" {
			head, err := format.DecodeHead(request.Body)
			if err != nil || request.Key != store.desc.HeadKey || request.Token != before.token ||
				head.AuthKind != format.AdministrativeAuth || head.EndWork == nil ||
				head.EndWork.TargetGroupID != groupID || head.EndWork.PredecessorRevisionID != before.head.Core.Revision ||
				head.EndWork.PredecessorFullHEADDigest != contract.Hash(before.body) ||
				head.EndWork.PredecessorToken != before.token {
				return errors.New("fresh process end-work CAS changed its selected predecessor or owner")
			}
			reply, err := processStoreOperation(store, request, false)
			if err != nil || reply.Write.Status != contract.WriteAcknowledged {
				return errors.New("fresh process end-work CAS was not acknowledged")
			}
			// An independent complete read must accept the selected result before
			// the child receives its CAS reply.
			after, result := Open(context.Background(), OpenContext{admission: &before.admission}, store)
			if after == nil || result.Outcome != ObservedCurrent || after.head.EndWork == nil ||
				after.head.EndWork.TargetGroupID != groupID {
				return errors.New("end-work CAS did not select a complete authenticated successor")
			}
			if err := child.reply(reply); err != nil {
				return err
			}
			allowed := make(map[string]uint32)
			for _, read := range processReadRequests(t, store.desc, sessionStateImage(t, after)) {
				allowed[read.Key] = read.Maximum
			}
			seenHead := false
			for readCount := 0; readCount < 4*(contract.MaxChildPages+8); readCount++ {
				read, err := child.next()
				if err != nil {
					return err
				}
				if processStoreMarker(read, "authenticated-end-work") {
					if !seenHead {
						return errors.New("fresh process did not observe the selected HEAD")
					}
					return child.reply(processStoreReply{})
				}
				if read.Method != "read" || allowed[read.Key] != read.Maximum || read.Maximum == 0 {
					return fmt.Errorf("fresh process end-work read escaped selected successor: %s %s", read.Method, read.Key)
				}
				seenHead = seenHead || read.Key == store.desc.HeadKey
				reply, err := processStoreOperation(store, read, true)
				if err != nil || reply.Read.Status != contract.ReadOK {
					return errors.New("fresh process end-work selected read failed")
				}
				if err := child.reply(reply); err != nil {
					return err
				}
			}
			return errors.New("fresh process end-work observation exceeded child bound")
		}
		if request.Method != "create" || created[request.Key] || len(request.Body) == 0 {
			return fmt.Errorf("fresh process end-work object plan changed: %s %s", request.Method, request.Key)
		}
		created[request.Key] = true
		reply, err := processStoreOperation(store, request, false)
		if err != nil || reply.Write.Status != contract.WriteAcknowledged {
			return errors.New("fresh process end-work immutable create failed")
		}
		if err := child.reply(reply); err != nil {
			return err
		}
		read, err := child.next()
		if err != nil {
			return err
		}
		if read.Method != "read" || read.Key != request.Key || read.Maximum != uint32(len(request.Body)) {
			return errors.New("fresh process end-work did not read back its exact immutable object")
		}
		reply, err = processStoreOperation(store, read, true)
		if err != nil || reply.Read.Status != contract.ReadOK {
			return errors.New("fresh process end-work readback failed")
		}
		if err := child.reply(reply); err != nil {
			return err
		}
	}
	return errors.New("fresh process end-work create count exceeded child bound")
}
