package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func assertFullReceiptHistoryBytes(t *testing.T, selected *StateSession, want contract.MutationReceiptWindows, bodies map[contract.ID][]byte) {
	t.Helper()
	got, err := selected.receiptWindows(t.Context())
	if err != nil || len(want.Successes) != 256 || len(want.Failures) != 256 || len(want.Order) != 512 || !slices.Equal(got.Successes, want.Successes) || !slices.Equal(got.Failures, want.Failures) || !slices.Equal(got.Order, want.Order) {
		t.Fatal("complete full-window receipt history", err)
	}
	assertRetainedReceiptBytes(t, selected, bodies)
	// Three vectors have one length frame and one count each. Every ID has
	// its own four-byte length frame; the index begins with a two-byte schema.
	expected := binary.BigEndian.AppendUint16(nil, 2)
	var successes, failures []contract.ID
	for _, row := range want.Successes {
		successes = append(successes, row.OperationID)
	}
	for _, row := range want.Failures {
		failures = append(failures, row.OperationID)
	}
	for _, ids := range [][]contract.ID{successes, failures, want.Order} {
		expected = binary.BigEndian.AppendUint32(expected, uint32(4+36*len(ids)))
		expected = binary.BigEndian.AppendUint32(expected, uint32(len(ids)))
		for _, id := range ids {
			expected = binary.BigEndian.AppendUint32(expected, 32)
			expected = append(expected, id[:]...)
		}
	}
	index, err := selected.receiptIndexID()
	if err != nil {
		t.Fatal("selected receipt index identity", err)
	}
	var actual []byte
	if selected.fragmentFacts == nil {
		actual, err = selected.administrativeSupportBlob(index, 36890)
	} else {
		matched := 0
		for _, location := range selected.root.Generated.Fragments {
			if location.BlobID != index {
				continue
			}
			state, readErr := selected.withSelectedFragment(t.Context(), location, func(payload []byte) error {
				actual = bytes.Clone(payload)
				return nil
			})
			if state.Outcome != 0 || readErr != nil {
				t.Fatal("full receipt index selected fragment", state, readErr)
			}
			matched++
		}
		if matched != 1 {
			t.Fatal("full receipt index fragment count", matched)
		}
	}
	if err != nil || len(actual) != 36890 || !bytes.Equal(actual, expected) || selected.root.Generated.ReceiptOrder.Count != 512 || selected.root.Generated.ReceiptOrder.Length != 18436 {
		t.Fatal("full receipt ordering bytes or root descriptor", len(actual), err)
	}
	var receiptRows, receiptFramedBytes, receiptPages int
	for i, page := range selected.support {
		pageReceipts, pageBytes := 0, 0
		for _, row := range page.Records {
			if row.Kind == contract.MutationReceiptSupportKind {
				receiptRows++
				receiptFramedBytes += 37 + len(row.Body)
				pageReceipts++
				pageBytes += 37 + len(row.Body)
			}
		}
		if pageReceipts != 0 {
			receiptPages++
			if pageReceipts != len(page.Records) || selected.root.RequiredSupport[i].Length != uint32(75+pageBytes) {
				t.Fatal("full receipt physical page byte account", i, pageReceipts, selected.root.RequiredSupport[i].Length)
			}
		}
	}
	if receiptRows != 512 || receiptFramedBytes != 260096 || receiptPages != 1 {
		t.Fatal("full receipt support row byte account", receiptRows, receiptFramedBytes, receiptPages)
	}
}

func assertPublicFullReceiptHistory(t *testing.T, env fixtureEnvironment, selected *StateSession, want contract.MutationReceiptWindows, bodies map[contract.ID][]byte, label string) {
	t.Helper()
	deadline, finite := t.Deadline()
	if !finite || !time.Now().Before(deadline) || t.Context().Err() != nil {
		t.Fatal("full public receipt history requires the original live finite test deadline")
	}
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	f := installedApplyTestFixture{env: env, basis: selected.admission.publicBasis(), composition: selected.admission.composition, selected: selected}
	reader, source := installedReceiptFixture(t, f)
	defer reader.Close()
	store := env.Store.(*memoryStore)
	creates, cas, signs := store.creates, store.cas, env.Trust.(*fixtureTrust).Calls()
	public, private := env.Custody.Calls()
	observation := PublicObservation{selected.root.Domain, selected.head.Core.Revision, selected.root.Snapshot, selected.head.Core.Root.Digest}
	warnings := PublicDomainWarnings{
		OrphanGeneratedEffect:  selected.root.WarningBits&WarningOrphanGeneratedEffect != 0,
		LateDestructiveEffect:  selected.root.WarningBits&WarningLateDestructiveEffect != 0,
		PublicationOrderValue:  selected.root.WarningBits&WarningPublicationOrderValue != 0,
		DiscardedExactEvidence: selected.root.WarningBits&WarningDiscardedExactEvidence != 0,
		PossibleStoreGarbage:   selected.root.WarningBits&WarningPossibleStoreGarbage != 0,
	}
	listed := reader.List(ctx, ReceiptListRequest{fixtureID(env.Domain, label+" list")})
	if listed.StateResult != PublicQuerySuccess || listed.Payload == nil || listed.Validate() != nil || listed.Payload.Observation != observation || listed.Payload.CurrentDomainWarningBits != selected.root.WarningBits || listed.Payload.CurrentWarnings != warnings || len(listed.Payload.Receipts) != 512 {
		t.Fatal("full retained public receipt list", label, listed.StateResult, listed.Result.Outcome, listed.Result.Reason, listed.FailureReason, listed.Result.StoreReason)
	}
	byID := make(map[contract.ID]contract.CompactMutationReceipt, 512)
	for _, rows := range [][]contract.CompactMutationReceipt{want.Successes, want.Failures} {
		for _, row := range rows {
			byID[row.OperationID] = row
		}
	}
	for i, id := range want.Order {
		row := byID[id]
		expected := ReceiptSummary{row.OperationID, row.OperationKind, row.CanonicalOutcome, row.StateResult, row.ObservedRevisionID, row.RequestedRevisionID, row.WarningBits, row.EvidenceCeiling}
		if listed.Payload.Receipts[511-i] != expected {
			t.Fatal("full public list changed independently recorded selection order", label, i)
		}
		detail := reader.Detail(ctx, ReceiptDetailRequest{fixtureID(env.Domain, fmt.Sprintf("%s detail %03d", label, i)), id})
		if detail.StateResult != PublicQuerySuccess || detail.Payload == nil || detail.Validate() != nil || detail.Payload.Observation != observation || detail.Payload.CurrentDomainWarningBits != selected.root.WarningBits || detail.Payload.CurrentWarnings != warnings || detail.Payload.Receipt != row || !bytes.Equal(detail.Payload.EncodedReceipt, bodies[id]) {
			t.Fatal("full public detail changed original result bytes or current observation", label, i, detail.StateResult, detail.Result.Outcome, detail.Result.Reason, detail.FailureReason, detail.Result.StoreReason)
		}
	}
	p, k := env.Custody.Calls()
	if source.closes != 513 || store.creates != creates || store.cas != cas || env.Trust.(*fixtureTrust).Calls() != signs || p != public || k != private {
		t.Fatal("full public receipt reads used non-GET authority or lost source joins", label, source.closes)
	}
}

func assertReconstructedFullReceiptHistory(t *testing.T, env fixtureEnvironment, selected *StateSession, want contract.MutationReceiptWindows, bodies map[contract.ID][]byte) {
	t.Helper()
	store := env.Store.(*memoryStore)
	projection := reconstructProjectionFixture(t, env, selected, store)
	defer projection.Close()
	assertReconstructionProjectionExact(t, projection, selected, store)
	returned := reconstructedReceiptHistorySession(t, projection, selected)
	assertFullReceiptHistoryBytes(t, returned, want, bodies)
	if returned.root.WarningBits != selected.root.WarningBits || !reflect.DeepEqual(returned.adminIndex.Groups, selected.adminIndex.Groups) {
		t.Fatal("reconstructed full history changed current warnings or remaining work")
	}
}

func reconstructedReceiptHistorySession(t *testing.T, projection *ReconstructionProjection, selected *StateSession) *StateSession {
	t.Helper()
	returned := reconstructionReturnedSession(t, projection, selected)
	var pages []format.AdministrativeIndexPage
	for i := 0; i < projection.PartCount(); i++ {
		part, ok := projection.CopyPart(i)
		if !ok {
			t.Fatal("returned receipt-history projection part missing", i)
		}
		if part.Kind == ReconstructionIndexPagePart {
			pages = append(pages, format.AdministrativeIndexPage{Ref: part.Ref, Body: part.Body})
		}
	}
	index, err := format.DecodeAdministrativeIndexPages(pages)
	if err != nil {
		t.Fatal("returned receipt-history administrative index", err)
	}
	returned.adminIndex = index
	// Receipt and work checks must use decoded projection parts, not facts
	// inherited from the basis session used by the private value oracle.
	returned.mutationReceipts = nil
	returned.selectedReceiptIndexes = contract.MutationReceiptIndexes{}
	returned.selectedReceiptRoot = format.Ref{}
	returned.clearSelectedSupportFacts()
	return returned
}
