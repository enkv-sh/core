package contract

import (
	"bytes"
	"fmt"
	"testing"
)

func generatedCryptoValueEntryBatchFixture(t *testing.T, count int) (ApplyContext, []CryptoGeneratedValueEntryPlan, []CryptoGeneratedValueEntryResult) {
	t.Helper()
	context, input, output := generatedCryptoValueEntryFixture(t)
	plans := make([]CryptoGeneratedValueEntryPlan, count)
	results := make([]CryptoGeneratedValueEntryResult, count)
	for i := range plans {
		name := fmt.Sprintf("member-%03d", i)
		plan, result := input, output
		plan.Slot, plan.ValueCore.Name = uint16(i), name
		result.Slot, result.ValueCore.Name, result.Entry.Name = uint16(i), name, name
		material, err := ValueMaterialContextDigest(result.ValueCore)
		if err != nil {
			t.Fatal(err)
		}
		result.Access.MaterialContextDigest = material
		plans[i], results[i] = plan, result
	}
	return context, plans, results
}

// full_only: false
func TestGeneratedSourceProtectionStorageIsIndependentOfSeedAccess(t *testing.T) {
	v := generatedCryptoFinishResultFixture(t)
	b, err := EncodeGeneratedSourceProtections(v.Material, v.SourceProtections)
	// Independent Node concatenation: count, framed 510-byte row containing
	// three literal IDs and a framed 410-byte source transfer.
	if err != nil || len(b) != 518 || Hash(b) != generatedCryptoHexID(t, "86f847c2e9896ce2462fbabbdaefa837a2a8e23c10372b4db9a6242cebada0d4") {
		t.Fatal("source protection storage vector", len(b), Hash(b), err)
	}
	view, err := InspectGeneratedSourceProtections(v.Material, b)
	if err != nil || view.Count() != 1 {
		t.Fatal("stored source protection", err)
	}
	row, err := view.Row(0)
	if err != nil || row.SourceID != v.SourceProtections[0].SourceID || !bytes.Equal(row.Transfer.Ciphertext, v.SourceProtections[0].Transfer.Ciphertext) {
		t.Fatal("stored source identity", err)
	}
	if _, err := view.Row(1); err == nil {
		t.Fatal("out-of-range source accepted")
	}
	changed := v.Material
	changed.Core.UsePlanDigest = generatedRecordID(99)
	if _, err := InspectGeneratedSourceProtections(changed, b); err == nil {
		t.Fatal("source protection accepted for another material use")
	}
	changed = v.Material
	changed.Core.Schema--
	if _, err := InspectGeneratedSourceProtections(changed, b); err == nil {
		t.Fatal("invalid stored material accepted")
	}
	for n := 0; n < len(b); n++ {
		if _, err := InspectGeneratedSourceProtections(v.Material, b[:n]); err == nil {
			t.Fatalf("truncated source protection accepted at %d", n)
		}
	}
	if _, err := InspectGeneratedSourceProtections(v.Material, append(bytes.Clone(b), 0)); err == nil {
		t.Fatal("trailing storage bytes accepted")
	}
	if _, err := EncodeGeneratedSourceProtections(v.Material, append(v.SourceProtections, v.SourceProtections[0])); err == nil {
		t.Fatal("duplicate source protection accepted")
	}
	empty, err := EncodeGeneratedSourceProtections(v.Material, nil)
	if err != nil || !bytes.Equal(empty, []byte{0, 0, 0, 0}) {
		t.Fatal("empty source set", err)
	}
	finish, err := EncodeCryptoGeneratedFinishPlanResult(v)
	if err != nil {
		t.Fatal(err)
	}
	finished, err := InspectCryptoGeneratedFinishPlanResult(finish)
	if err != nil || !bytes.Equal(finished.SourceProtections, b) {
		t.Fatal("finish output differs from stored vector", err)
	}
}

// full_only: false
func TestCryptoGeneratedMembersPreflightBoundsWholeOutput(t *testing.T) {
	c, input, output := generatedCryptoValueEntryFixture(t)
	request := CryptoGeneratedValueEntriesRequest{OperationRef: generatedRecordID(27), Context: c, PhaseID: generatedRecordID(28), Final: 1, Rows: []CryptoGeneratedValueEntryPlan{input}}
	inspect := func(q CryptoGeneratedValueEntriesRequest) CryptoGeneratedValueEntriesRequestView {
		t.Helper()
		b, err := EncodeCryptoGeneratedValueEntriesRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		view, err := InspectCryptoGeneratedValueEntriesRequest(b)
		if err != nil {
			t.Fatal(err)
		}
		return view
	}
	encoded, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: []CryptoGeneratedValueEntryResult{output}})
	if err != nil {
		t.Fatal(err)
	}
	view := inspect(request)
	for _, recovery := range []bool{false, true} {
		want := len(encoded) - 10
		if recovery {
			want += 489
		}
		got, err := CryptoGeneratedValueEntriesResultBound(view, recovery)
		if err != nil || got != want {
			t.Fatalf("preflight recovery=%t: %d want %d: %v", recovery, got, want, err)
		}
	}
	input.Recipients = make([]ID, CryptoMaxValueEntryRecipients)
	for i := range input.Recipients {
		input.Recipients[i] = generatedRecordID(byte(i + 1))
	}
	request.Rows = make([]CryptoGeneratedValueEntryPlan, 28)
	for i := range request.Rows {
		row := input
		row.Slot, row.ValueCore.Name = uint16(i), fmt.Sprintf("%03d", i)
		request.Rows[i] = row
	}
	// The typed input fits, but RSA recipient wraps make the output exceed the
	// same whole-region limit. No ciphertext or access package is needed here.
	view = inspect(request)
	if _, err := CryptoGeneratedValueEntriesResultBound(view, false); err != ErrCryptoCapacity {
		t.Fatal("oversize output accepted", err)
	}
	for _, recovery := range []bool{false, true} {
		var last int
		for n := 1; n <= len(request.Rows); n++ {
			q := request
			q.Rows = q.Rows[:n]
			got, err := CryptoGeneratedValueEntriesResultBound(inspect(q), recovery)
			if err == ErrCryptoCapacity {
				if last == 0 || last > CryptoGeneratedMaterialLimit {
					t.Fatal("incorrect capacity frontier", last)
				}
				break
			}
			if err != nil || got <= last || got > CryptoGeneratedMaterialLimit {
				t.Fatal("legal output bound", n, got, err)
			}
			last = got
		}
	}
	view.Rows = append(view.Rows, 0)
	if _, err := CryptoGeneratedValueEntriesResultBound(view, false); err == nil {
		t.Fatal("invalid input accepted by output preflight")
	}
	request.Rows = nil
	if got, err := CryptoGeneratedValueEntriesResultBound(inspect(request), true); err != nil || got != 4 {
		t.Fatal("empty final output", got, err)
	}
}

// full_only: false
func TestCryptoGeneratedForwardTraversalsConsumeEachRowOnceInOrder(t *testing.T) {
	request := generatedSuppliedCryptoFixture(t)
	identityRows := generatedSuppliedIdentityRows(3)
	request.IdentityPlan = generatedSuppliedIdentityBody(t, identityRows)
	request.SealedInputs = make([]CryptoSealedInput, len(identityRows))
	prepared := make([]CryptoPreparedSecret, len(identityRows))
	for i := range identityRows {
		request.SealedInputs[i] = generatedSuppliedSourceFixture(t, request, identityRows[i].Name)
		prepared[i] = generatedSuppliedPreparedFixture(t, request, identityRows[i])
	}
	requestBody, err := EncodeCryptoGeneratedSuppliedRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestView, err := InspectCryptoGeneratedSuppliedRequest(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	sources := requestView.forwardSealedInputs()
	for i, want := range identityRows {
		before := sources.reader.i
		row, ok, err := sources.next()
		if err != nil || !ok || string(row.name) != want.Name || sources.reader.i <= before {
			t.Fatal("supplied source traversal", i, ok, sources.reader.i, before, err)
		}
	}
	if _, ok, err := sources.next(); err != nil || ok || sources.reader.i != len(requestView.sealedInputs) {
		t.Fatal("supplied source traversal end", ok, sources.reader.i, len(requestView.sealedInputs), err)
	}

	identity, err := InspectIdentityPlan(request.IdentityPlan)
	if err != nil {
		t.Fatal(err)
	}
	identities := identity.forwardRows()
	for i, want := range identityRows {
		before := identities.reader.i
		row, ok, err := identities.next()
		if err != nil || !ok || string(row.name) != want.Name || row.row.Slot != want.Slot || identities.reader.i <= before {
			t.Fatal("identity traversal", i, ok, identities.reader.i, before, err)
		}
	}
	if _, ok, err := identities.next(); err != nil || ok || identities.reader.i != len(identity.Rows) {
		t.Fatal("identity traversal end", ok, identities.reader.i, len(identity.Rows), err)
	}

	responseBody, err := EncodeCryptoGeneratedSuppliedResult(CryptoGeneratedSuppliedResult{Rows: prepared})
	if err != nil {
		t.Fatal(err)
	}
	response, err := InspectCryptoGeneratedSuppliedResult(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	preparedRows := response.forwardRows()
	for i, want := range prepared {
		before := preparedRows.reader.i
		row, ok, err := preparedRows.next()
		if err != nil || !ok || string(row.name) != want.Name || row.current.slot != want.Slot || preparedRows.reader.i <= before {
			t.Fatal("prepared traversal", i, ok, preparedRows.reader.i, before, err)
		}
	}
	if _, ok, err := preparedRows.next(); err != nil || ok || preparedRows.reader.i != len(response.Rows) {
		t.Fatal("prepared traversal end", ok, preparedRows.reader.i, len(response.Rows), err)
	}

	context, plans, results := generatedCryptoValueEntryBatchFixture(t, 3)
	requestRows, err := EncodeCryptoGeneratedValueEntriesRequest(CryptoGeneratedValueEntriesRequest{OperationRef: generatedRecordID(27),
		Context: context, PhaseID: generatedRecordID(28), Final: 1, Rows: plans})
	if err != nil {
		t.Fatal(err)
	}
	entryRequest, err := InspectCryptoGeneratedValueEntriesRequest(requestRows)
	if err != nil {
		t.Fatal(err)
	}
	resultRows, err := EncodeCryptoGeneratedValueEntriesResult(CryptoGeneratedValueEntriesResult{Final: 1, Rows: results})
	if err != nil {
		t.Fatal(err)
	}
	entryResult, err := InspectCryptoGeneratedValueEntriesResult(resultRows)
	if err != nil {
		t.Fatal(err)
	}
	planTraversal, resultTraversal := entryRequest.forwardRows(), entryResult.forwardRows()
	for i := range plans {
		planBefore, resultBefore := planTraversal.reader.i, resultTraversal.reader.i
		plan, planOK, planErr := planTraversal.next()
		result, resultOK, resultErr := resultTraversal.next()
		if planErr != nil || resultErr != nil || !planOK || !resultOK || plan.Slot != uint16(i) || result.Slot != uint16(i) ||
			planTraversal.reader.i <= planBefore || resultTraversal.reader.i <= resultBefore {
			t.Fatal("member traversal", i, planOK, resultOK, planErr, resultErr)
		}
	}
	if _, ok, err := planTraversal.next(); err != nil || ok || planTraversal.reader.i != len(entryRequest.Rows) {
		t.Fatal("member plan traversal end", ok, planTraversal.reader.i, len(entryRequest.Rows), err)
	}
	if _, ok, err := resultTraversal.next(); err != nil || ok || resultTraversal.reader.i != len(entryResult.Rows) {
		t.Fatal("member result traversal end", ok, resultTraversal.reader.i, len(entryResult.Rows), err)
	}
}
