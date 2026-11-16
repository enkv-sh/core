package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

const operatorCLICaptureLimit = 64 << 10

type operatorCLIOutput struct {
	mu       sync.Mutex
	body     []byte
	overflow bool
}

// This writer has no promoted ReaderFrom method. os/exec can drain the whole
// pipe, but it retains only the fixed allowance even on a failed child.
func (o *operatorCLIOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := len(p)
	room := operatorCLICaptureLimit - len(o.body)
	if room < n {
		o.overflow = true
		n = room
	}
	o.body = append(o.body, p[:n]...)
	return len(p), nil
}

func (o *operatorCLIOutput) result() ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return bytes.Clone(o.body), o.overflow
}

// full_only: false
func TestOperatorCLIOutputDrainsProcessPipeAtBound(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	written := make(chan error, 1)
	const extra = 4096
	go func() {
		_, writeErr := writer.Write(bytes.Repeat([]byte{'x'}, operatorCLICaptureLimit+extra))
		written <- errors.Join(writeErr, writer.Close())
	}()
	var output operatorCLIOutput
	n, copyErr := io.Copy(&output, reader)
	var writeErr error
	select {
	case writeErr = <-written:
	case <-time.After(5 * time.Second):
		t.Fatal("process-pipe writer did not join")
	}
	body, overflow := output.result()
	if copyErr != nil || writeErr != nil || n != operatorCLICaptureLimit+extra || !overflow ||
		len(body) != operatorCLICaptureLimit {
		t.Fatal("process-pipe capture did not drain and enforce the bound", n, copyErr, writeErr, overflow, len(body))
	}
}

type operatorRefusingOldTrust struct {
	contract.Trust
	signCalls int
}

func (r *operatorRefusingOldTrust) Sign(context.Context, contract.SignRequest) contract.SignResult {
	r.signCalls++
	return contract.SignResult{Reason: contract.ReasonProof}
}

// full_only: false
func TestOperatorFreshCurrentBasisUsesSelectedSuccessorWithoutOldSigner(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(map[contract.Family]string{contract.AWS: "aws", contract.GCP: "gcp"}[family], func(t *testing.T) {
			fixture := newCurrentBasisFixture(t, family, true)
			old := &operatorRefusingOldTrust{Trust: fixture.env.Trust}
			backend := &liveBackend{Store: fixture.env.Store, Trust: old, PublicKey: bytes.Clone(fixture.old.admission.publicKey)}
			basis := successionBasisTransport(fixture.current.admission.current)
			facts := freshFacts{Domain: fixture.current.admission.domain, CurrentBasis: &basis}
			admission := liveFreshAdmission(facts, fixture.control, backend)
			if !bytes.Equal(admission.admission.publicKey, fixture.control.NormalSigning.SPKI) ||
				bytes.Equal(admission.admission.publicKey, backend.PublicKey) {
				t.Fatal("fresh current admission retained the old Normal verifier")
			}
			selected, result := Open(context.Background(), admission, backend.Store)
			if selected == nil || result.Outcome != ObservedCurrent || old.signCalls != 0 {
				t.Fatal("fresh successor public read used the old Normal signing route", result, old.signCalls)
			}
			wrong := fixture.control
			wrong.NormalSigning.SPKI = bytes.Clone(backend.PublicKey)
			wrongAdmission := liveFreshAdmission(facts, wrong, backend)
			if other, result := Open(context.Background(), wrongAdmission, backend.Store); other != nil ||
				result.Outcome == ObservedCurrent || old.signCalls != 0 {
				t.Fatal("old Normal verifier was accepted for the signed successor", result, old.signCalls)
			}
		})
	}
}

func operatorCLIReservation(selected *StateSession, command string, afterCount uint16, afterBytes uint64) (budgetReservation, bool) {
	if selected == nil || selected.root.ChildCount == 0 || selected.root.ChildCount > 32 || selected.root.ChildEncodedBytes == 0 || selected.root.ChildEncodedBytes > contract.MaxChildPages*contract.MaxRequiredSupportPageLength {
		return budgetReservation{}, false
	}
	before := uint64(selected.root.ChildCount)
	// One authenticated image reads HEAD, root and all selected children. A Store
	// read can make three physical attempts. Receipt lookup uses that same image.
	calls := 3 * (before + 2)
	switch command {
	case "list", "plan", "receipt", "stale-apply":
		if afterCount != 0 || afterBytes != 0 {
			return budgetReservation{}, false
		}
		return budgetReservation{Requests: 2 * calls, BodyBytes: calls * operationBodyAllowance}, true
	case "apply", "keys-replace":
	default:
		return budgetReservation{}, false
	}
	if afterCount == 0 || afterCount > 32 || afterBytes == 0 || afterBytes > contract.MaxChildPages*contract.MaxRequiredSupportPageLength {
		return budgetReservation{}, false
	}
	after := uint64(afterCount)
	observed := max(before, after)
	candidate, ok := candidateStoreReservation(after+1, afterBytes+contract.MaxRootLength, observed+2)
	if !ok {
		return budgetReservation{}, false
	}
	if command == "keys-replace" {
		// Two public lookups and four signatures each allow three attempts.
		calls += 2*3 + 4*3
	} else {
		calls++
	}
	candidate.Requests += 2 * calls
	candidate.BodyBytes += calls * operationBodyAllowance
	return candidate, true
}
func operatorReserveCLI(budget *runBudget, selected *StateSession, command string, afterCount uint16, afterBytes uint64) bool {
	if budget == nil {
		return false
	}
	charge, ok := operatorCLIReservation(selected, command, afterCount, afterBytes)
	return ok && budget.absorbChild(charge)
}

// full_only: false
func TestOperatorCLIShapeReservationCoversRetriesBeforeEntry(t *testing.T) {
	selected := &StateSession{}
	selected.root.ChildCount = 32
	selected.root.ChildEncodedBytes = 32 << 20
	tests := []struct {
		command                            string
		count                              uint16
		bytes, calls, objects, objectBytes uint64
	}{
		{"list", 0, 0, 102, 0, 0}, {"plan", 0, 0, 102, 0, 0}, {"receipt", 0, 0, 102, 0, 0}, {"stale-apply", 0, 0, 102, 0, 0},
		// Open102 +31 immutable images*12 +threeCAS +3*(35reads*3) +oneSign.
		{"apply", 30, 30 << 20, 793, 31, 3*(30<<20+contract.MaxRootLength) + 3*contract.MaxHeadLength},
		// Open102 +33 immutable images*12 +threeCAS +315observation +18KMS attempts.
		{"keys-replace", 32, 32 << 20, 834, 33, 3*(32<<20+contract.MaxRootLength) + 3*contract.MaxHeadLength},
	}
	for _, row := range tests {
		t.Run(row.command, func(t *testing.T) {
			charge, ok := operatorCLIReservation(selected, row.command, row.count, row.bytes)
			if !ok || charge.Requests != 2*row.calls || charge.BodyBytes != row.calls*operationBodyAllowance || charge.Objects != row.objects || charge.ObjectBytes != row.objectBytes {
				t.Fatal("source-derived native command allowance changed", charge, ok)
			}
			limits := liveLimits{Requests: charge.Requests, BodyBytes: charge.BodyBytes, Objects: charge.Objects, ObjectBytes: charge.ObjectBytes}
			budget := &runBudget{limits: limits}
			if !operatorReserveCLI(budget, selected, row.command, row.count, row.bytes) || budget.snapshot() != charge {
				t.Fatal("exact allowance refused before child entry")
			}
			for _, short := range []string{"requests", "body", "objects", "object_bytes"} {
				if short == "objects" && charge.Objects == 0 || short == "object_bytes" && charge.ObjectBytes == 0 {
					continue
				}
				reduced := limits
				switch short {
				case "requests":
					reduced.Requests--
				case "body":
					reduced.BodyBytes--
				case "objects":
					reduced.Objects--
				case "object_bytes":
					reduced.ObjectBytes--
				}
				budget := &runBudget{limits: reduced}
				if operatorReserveCLI(budget, selected, row.command, row.count, row.bytes) || !budget.exhausted || budget.snapshot() != (budgetReservation{}) {
					t.Fatal("underfunded command was not refused before child entry", short)
				}
			}
		})
	}
	for _, row := range []struct {
		command string
		count   uint16
		bytes   uint64
	}{{"apply", 0, 1}, {"apply", 33, 1}, {"apply", 30, 0}, {"keys-replace", 0, 1}, {"keys-replace", 33, 1}, {"keys-replace", 32, 0}, {"list", 1, 1}, {"stale-apply", 1, 1}, {"unknown", 0, 0}, {"inspect", 0, 0}, {"restore-signer", 32, 32 << 20}} {
		if _, ok := operatorCLIReservation(selected, row.command, row.count, row.bytes); ok {
			t.Fatal("unqualified before/after shape admitted", row)
		}
	}
}

func operatorIDText(id contract.ID) string { return hex.EncodeToString(id[:]) }

// These images are owned before a command can select a successor. Final fresh
// consumption cannot replace this exact predecessor-to-successor comparison.
type publicOperatorSlice struct {
	Location   contract.GeneratorSliceLocation
	Disposable bool
}

type publicOperatorBefore struct {
	Image      stateImage
	Control    contract.ControlCore
	Windows    contract.MutationReceiptWindows
	Support    []contract.SupportRecord
	Slices     []publicOperatorSlice
	Disposable map[generatedRecordKey]bool
	Intents    map[contract.ID][]byte
	Token      contract.Token
	HEAD       []byte
}

func publicOperatorFreeze(t testing.TB, ctx context.Context, selected *StateSession) publicOperatorBefore {
	t.Helper()
	windows, err := selected.receiptWindows(ctx)
	if err != nil {
		t.Fatal("operator predecessor receipt windows unavailable", err)
	}
	windows.Successes, windows.Failures = slices.Clone(windows.Successes), slices.Clone(windows.Failures)
	body, err := contract.EncodeControlCore(currentControlOf(selected))
	if err != nil {
		t.Fatal("operator predecessor control unavailable", err)
	}
	control, err := contract.DecodeControlCore(body)
	if err != nil {
		t.Fatal(err)
	}
	support, err := observePreservedGeneratedSupport(ctx, selected)
	if err != nil {
		t.Fatal("operator predecessor support unavailable", err)
	}
	before := publicOperatorBefore{Image: sessionStateImage(t, selected), Control: control, Windows: windows,
		Support: support, Intents: map[contract.ID][]byte{}, Token: selected.token, HEAD: bytes.Clone(selected.body)}
	before.Disposable = map[generatedRecordKey]bool{}
	for _, page := range before.Image.AdministrativeIndex.Pages {
		if page.ReadRequired {
			view, err := selected.administrativeSelectedSupportPage(page)
			if err != nil {
				t.Fatal("operator predecessor slice ownership unavailable", err)
			}
			position := 0
			for _, span := range page.Spans {
				for range span.Count {
					if position >= len(view.Records) {
						t.Fatal("operator predecessor slice ownership is incomplete")
					}
					row := view.Records[position]
					position++
					carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
					if err != nil || row.Kind != contract.GeneratorVectorSupportKind || carrier.OwnerKind != contract.GeneratorSnapshotOwner || carrier.VectorKind != contract.GeneratorVectorSlices {
						t.Fatal("operator predecessor is not a snapshot slice carrier", err)
					}
					location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
					if err != nil || len(span.GroupIndexes) != 0 && !slices.Equal(span.GroupIndexes, []uint16{0}) {
						t.Fatal("operator predecessor slice has another work owner", err)
					}
					before.Slices = append(before.Slices, publicOperatorSlice{location, !span.Mandatory && len(span.GroupIndexes) != 0})
				}
			}
			if position != len(view.Records) {
				t.Fatal("operator predecessor slice ownership has extra rows")
			}
			continue
		}
		position := 0
		for _, span := range page.Spans {
			end := position + int(span.Count)
			if end > len(page.Rows) {
				t.Fatal("operator predecessor support ownership is incomplete")
			}
			if len(span.GroupIndexes) != 0 {
				if !slices.Equal(span.GroupIndexes, []uint16{0}) || len(before.Image.AdministrativeIndex.Groups) != 1 {
					t.Fatal("operator predecessor is not one independent work owner")
				}
				if !span.Mandatory {
					for _, row := range page.Rows[position:end] {
						before.Disposable[generatedRecordKey{row.Kind, row.RecordID}] = true
					}
				}
			}
			position = end
		}
		if position != len(page.Rows) {
			t.Fatal("operator predecessor support ownership has extra rows")
		}
	}
	work := mustSelectedGeneratedWork(t, selected)
	for _, named := range before.Image.Root.Names {
		entry := selected.valueEntry(named.Slot)
		if entry.ValueSource == contract.Generated {
			body, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
			if err != nil {
				t.Fatal("operator predecessor current Intent unavailable", err)
			}
			before.Intents[entry.Generated.IntentDigest] = bytes.Clone(body)
		}
	}
	return before
}

func publicOperatorCurrentPreserved(before, after stateImage, ended contract.ID) bool {
	a, b := before.Root, after.Root
	if a.Domain != b.Domain || !reflect.DeepEqual(a.Names, b.Names) || !reflect.DeepEqual(a.Recipients, b.Recipients) ||
		a.ValueEntryCount != b.ValueEntryCount || a.SecretCount != b.SecretCount || a.RawBytes != b.RawBytes ||
		a.MembershipCount != b.MembershipCount || a.SecretOrdinaryWrapCount != b.SecretOrdinaryWrapCount || a.RecipientCount != b.RecipientCount ||
		a.AccessRecordCount != b.AccessRecordCount || a.Unsupported != b.Unsupported || !reflect.DeepEqual(a.OutputConfiguration, b.OutputConfiguration) || !reflect.DeepEqual(before.Recipient, after.Recipient) || !reflect.DeepEqual(before.Access, after.Access) {
		return false
	}
	for _, named := range a.Names {
		page, slot := named.Slot/format.PageSlots, named.Slot%format.PageSlots
		if before.Pages[page] == nil || after.Pages[page] == nil || before.Pages[page].Slots[slot] == nil || after.Pages[page].Slots[slot] == nil {
			return false
		}
		want := *before.Pages[page].Slots[slot]
		if !ended.IsZero() && want.Generated.RetiringDutyID == ended {
			want.Generated.RetiringDutyPresent, want.Generated.RetiringDutyID = 0, contract.ID{}
		}
		if !reflect.DeepEqual(want, *after.Pages[page].Slots[slot]) {
			return false
		}
	}
	return true
}

func publicOperatorReceiptWindowsEqual(before, after contract.MutationReceiptWindows) bool {
	return before.DomainID == after.DomainID && slices.Equal(before.Successes, after.Successes) && slices.Equal(before.Failures, after.Failures) && slices.Equal(before.Order, after.Order)
}

// full_only: false
func TestPublicOperatorReceiptWindowsRequireExactOrderedValues(t *testing.T) {
	domain := contract.Hash([]byte("receipt-window equality domain"))
	t.Run("nil-and-empty", func(t *testing.T) {
		before := contract.MutationReceiptWindows{DomainID: domain}
		after := contract.MutationReceiptWindows{DomainID: domain, Successes: []contract.CompactMutationReceipt{}, Failures: []contract.CompactMutationReceipt{}}
		if !publicOperatorReceiptWindowsEqual(before, after) || !publicOperatorReceiptWindowsEqual(after, before) {
			t.Fatal("empty receipt classes changed canonical receipt-window meaning")
		}
	})
	row := func(name string, class uint8) contract.CompactMutationReceipt {
		return contract.CompactMutationReceipt{DomainID: domain, OperationID: contract.Hash([]byte(name)), CanonicalOutcome: class}
	}
	before := contract.MutationReceiptWindows{DomainID: domain,
		Successes: []contract.CompactMutationReceipt{row("success-one", 1), row("success-two", 1)},
		Failures:  []contract.CompactMutationReceipt{row("failure-one", 2), row("failure-two", 2)}}
	before.Order = []contract.ID{before.Successes[0].OperationID, before.Failures[0].OperationID, before.Successes[1].OperationID, before.Failures[1].OperationID}
	clone := func() contract.MutationReceiptWindows {
		return contract.MutationReceiptWindows{DomainID: before.DomainID, Successes: slices.Clone(before.Successes), Failures: slices.Clone(before.Failures), Order: slices.Clone(before.Order)}
	}
	if !publicOperatorReceiptWindowsEqual(before, clone()) {
		t.Fatal("owned copies changed exact ordered receipt values")
	}
	for _, name := range []string{"domain", "class", "success-order", "failure-order", "common-order", "count", "field"} {
		t.Run(name, func(t *testing.T) {
			after := clone()
			switch name {
			case "domain":
				after.DomainID[0] ^= 1
			case "class":
				after.Successes, after.Failures = after.Failures, after.Successes
			case "success-order":
				after.Successes[0], after.Successes[1] = after.Successes[1], after.Successes[0]
			case "common-order":
				after.Order[0], after.Order[1] = after.Order[1], after.Order[0]
			case "failure-order":
				after.Failures[0], after.Failures[1] = after.Failures[1], after.Failures[0]
			case "count":
				after.Successes = after.Successes[:1]
			case "field":
				after.Successes[0].SummaryCounts[0]++
			}
			if publicOperatorReceiptWindowsEqual(before, after) || publicOperatorReceiptWindowsEqual(after, before) {
				t.Fatal("changed receipt-window value was accepted", name)
			}
		})
	}
}

func publicOperatorCheckRestore(t testing.TB, ctx context.Context, before publicOperatorBefore, after *StateSession, next contract.PublicSigningBinding) {
	t.Helper()
	want := before.Control
	want.NormalSigning, want.AccessGeneration = next, want.AccessGeneration+1
	image := sessionStateImage(t, after)
	windows, err := after.receiptWindows(ctx)
	support, supportErr := observePreservedGeneratedSupport(ctx, after)
	if !publicOperatorCurrentPreserved(before.Image, image, contract.ID{}) || !controlEqual(currentControlOf(after), want) ||
		!reflect.DeepEqual(before.Image.Pages, image.Pages) || !reflect.DeepEqual(before.Image.Root.ValueEntryPages, image.Root.ValueEntryPages) ||
		!reflect.DeepEqual(before.Image.Root.Generated, image.Root.Generated) || before.Image.Root.WarningBits != image.Root.WarningBits ||
		!reflect.DeepEqual(before.Image.AdministrativeIndex.Groups, image.AdministrativeIndex.Groups) ||
		err != nil || !publicOperatorReceiptWindowsEqual(before.Windows, windows) || supportErr != nil || !reflect.DeepEqual(before.Support, support) {
		t.Fatal("signer restoration changed frozen current values, access, work, control or receipt windows", err, supportErr)
	}
}

// The fixture has one current logical Intent and one independent retirement.
// Derive its compact fragment and normalized one-row Slice carrier directly from
// the documented wire framing; production projection and encoders are not oracles.
func publicOperatorEndCurrentSupport(t testing.TB, before publicOperatorBefore) (contract.SupportRecord, contract.SupportRecord, contract.ID) {
	t.Helper()
	if len(before.Intents) != 1 {
		t.Fatal("operator End fixture needs exactly one current Intent")
	}
	var intentID contract.ID
	var intent []byte
	for intentID, intent = range before.Intents {
	}
	var current contract.GeneratorSliceLocation
	retained := 0
	for _, slice := range before.Slices {
		if !slice.Disposable {
			current = slice.Location
			retained++
		}
	}
	contentHash := contract.ID(sha256.Sum256(intent))
	if retained != 1 || current.ContentKind != contract.GeneratorContentIntent || current.ContentID != intentID ||
		current.Length != uint32(len(intent)) || current.Digest != contentHash || len(intent) == 0 || len(intent) > 393216 {
		t.Fatal("operator End fixture has other surviving slices or invalid frozen Intent")
	}
	oldBlob := current.BlobID
	// No other surviving Slice can reference oldBlob: the exact retained set
	// above consists only of this Intent, which moves to contentHash at offset 0.
	digest := func(label string, body []byte) contract.ID {
		preimage := append([]byte("ENKV/GENERATOR/v1/"+label+"\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(body)))...)
		return contract.ID(sha256.Sum256(append(preimage, body...)))
	}
	part := binary.BigEndian.AppendUint16(nil, 1)
	part = append(part, contentHash[:]...)
	part = binary.BigEndian.AppendUint16(part, 0)
	part = binary.BigEndian.AppendUint16(part, 1)
	part = binary.BigEndian.AppendUint64(part, uint64(len(intent)))
	part = append(part, contentHash[:]...)
	part = binary.BigEndian.AppendUint32(part, 0)
	part = binary.BigEndian.AppendUint32(part, uint32(len(intent)))
	part = append(part, intent...)
	fragmentID := digest("fragment", binary.BigEndian.AppendUint16(bytes.Clone(contentHash[:]), 0))
	fragment := contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: fragmentID, Body: part}
	location := binary.BigEndian.AppendUint16(nil, 1)
	location = append(location, 1)
	location = append(location, intentID[:]...)
	location = append(location, contentHash[:]...)
	location = binary.BigEndian.AppendUint64(location, 0)
	location = binary.BigEndian.AppendUint32(location, uint32(len(intent)))
	location = append(location, contentHash[:]...)
	vectorBody := binary.BigEndian.AppendUint32(nil, 1)
	vectorBody = binary.BigEndian.AppendUint32(vectorBody, uint32(len(location)))
	vectorBody = append(vectorBody, location...)
	vector := digest("slice-index", vectorBody)
	descriptor := append([]byte(nil), vector[:]...)
	descriptor = binary.BigEndian.AppendUint64(descriptor, uint64(len(vectorBody)))
	descriptor = binary.BigEndian.AppendUint32(descriptor, 1)
	domain := before.Image.Root.Domain
	identity := append([]byte(nil), domain[:]...)
	identity = append(identity, 128)
	identity = append(identity, domain[:]...)
	identity = append(identity, 7)
	identity = append(identity, descriptor...)
	identity = binary.BigEndian.AppendUint32(identity, 0)
	carrierID := digest("support-vector-row", identity)
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, domain[:]...)
	body = append(body, 128)
	body = append(body, domain[:]...)
	body = append(body, 7)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, descriptor...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(location)))
	body = append(body, location...)
	return fragment, contract.SupportRecord{Kind: contract.GeneratorVectorSupportKind, RecordID: carrierID, Body: body}, oldBlob
}

func publicOperatorCheckEnd(t testing.TB, ctx context.Context, before publicOperatorBefore, after *StateSession, group format.AdministrativeGroup) {
	t.Helper()
	image := sessionStateImage(t, after)
	if !publicOperatorCurrentPreserved(before.Image, image, group.GroupID) || !controlEqual(before.Control, currentControlOf(after)) ||
		len(before.Image.AdministrativeIndex.Groups) != 1 || len(image.AdministrativeIndex.Groups) != 0 ||
		after.root.Generated.Duties != 0 || after.root.Generated.Retiring != 0 {
		t.Fatal("End changed frozen current values, access, control or an unrelated work owner")
	}
	work := mustSelectedGeneratedWork(t, after)
	support, err := observePreservedGeneratedSupport(ctx, after)
	if err != nil {
		t.Fatal("End current support unavailable", err)
	}
	receiptSupport := func(row contract.SupportRecord, root format.Root) bool {
		if row.Kind == contract.MutationReceiptSupportKind {
			return true
		}
		if row.Kind != contract.GeneratedFragmentSupportKind {
			return false
		}
		blob, err := contract.MutationReceiptIndexBlobID(root.Domain, root.Generated.SuccessWindow, root.Generated.FailureWindow, root.Generated.ReceiptOrder)
		fragment, fragmentErr := contract.InspectGeneratedFragment(row.Body)
		if err != nil || fragmentErr != nil {
			t.Fatal("operator receipt support cannot be identified", err, fragmentErr)
		}
		return fragment.BlobID == blob
	}
	fragment, carrier, oldBlob := publicOperatorEndCurrentSupport(t, before)
	prior := map[generatedRecordKey][]byte{}
	for _, row := range before.Support {
		prior[generatedRecordKey{row.Kind, row.RecordID}] = row.Body
	}
	oldIntentFragment := func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratedFragmentSupportKind {
			return false
		}
		part, err := contract.InspectGeneratedFragment(row.Body)
		if err != nil {
			t.Fatal("operator current Intent fragment unavailable", err)
		}
		return part.BlobID == oldBlob
	}
	snapshotSlice := func(row contract.SupportRecord) bool {
		if row.Kind != contract.GeneratorVectorSupportKind {
			return false
		}
		v, err := contract.InspectGeneratorVectorCarrier(row.Body)
		if err != nil {
			t.Fatal(err)
		}
		return v.VectorKind == contract.GeneratorVectorSlices && v.OwnerKind == contract.GeneratorSnapshotOwner
	}
	kept := map[generatedRecordKey]bool{}
	fragmentCount, carrierCount := 0, 0
	for _, row := range support {
		if receiptSupport(row, image.Root) {
			continue
		}
		key := generatedRecordKey{row.Kind, row.RecordID}
		if snapshotSlice(row) {
			if row.RecordID != carrier.RecordID || !bytes.Equal(row.Body, carrier.Body) {
				t.Fatal("End changed its exact complete current Intent slice vector")
			}
			carrierCount++
			continue
		}
		if row.Kind == fragment.Kind && row.RecordID == fragment.RecordID {
			if !bytes.Equal(row.Body, fragment.Body) {
				t.Fatal("End changed its exact compact current Intent fragment")
			}
			fragmentCount++
			continue
		}
		body, known := prior[key]
		if before.Disposable[key] || oldIntentFragment(row) || !known || !bytes.Equal(body, row.Body) || kept[key] {
			t.Fatalf("End added, changed or retained disposed generated support: kind=%d id=%x known=%t disposable=%t body_equal=%t duplicate=%t", row.Kind, row.RecordID, known, before.Disposable[key], bytes.Equal(body, row.Body), kept[key])
		}
		kept[key] = true
	}
	if fragmentCount != 1 || carrierCount != 1 {
		t.Fatalf("End current Intent support is incomplete or duplicated: fragments=%d carriers=%d", fragmentCount, carrierCount)
	}
	for _, row := range before.Support {
		if receiptSupport(row, before.Image.Root) || snapshotSlice(row) || oldIntentFragment(row) {
			continue
		}
		key := generatedRecordKey{row.Kind, row.RecordID}
		if !before.Disposable[key] && !kept[key] {
			t.Fatalf("End removed support outside its original exclusive ownership: kind=%d id=%x", row.Kind, row.RecordID)
		}
	}
	if _, present := work.records[generatedRecordKey{contract.GeneratedDutySupportKind, group.OwnerID}]; present {
		t.Fatal("End retained its disposed Duty")
	}
	for _, named := range before.Image.Root.Names {
		entry := after.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		intent, err := work.readSelectedSlice(ctx, contract.GeneratorContentIntent, entry.Generated.IntentDigest, contract.GeneratorIntentMaxLength)
		key := generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}
		if err != nil || !bytes.Equal(intent, before.Intents[entry.Generated.IntentDigest]) || len(prior[key]) == 0 || !bytes.Equal(prior[key], work.records[key].Body) {
			t.Fatal("End changed exact current Intent or create provenance", err)
		}
	}
	body := binary.BigEndian.AppendUint32(nil, 1)
	body = binary.BigEndian.AppendUint32(body, 32)
	body = append(body, group.GroupID[:]...)
	digest := sha256.Sum256(append([]byte("ENKV/admin-descriptor/v1/ended-groups\x00"), body...))
	ended := contract.GeneratorDescriptor{Digest: contract.ID(digest), Length: 40, Count: 1}
	warning := before.Image.Root.WarningBits | WarningDiscardedExactEvidence | WarningOrphanGeneratedEffect | WarningPossibleStoreGarbage
	q := after.head.EndWork
	if q == nil || q.DomainID != before.Image.Root.Domain || q.TargetGroupID != group.GroupID || q.TargetKind != group.OwnerKind || q.DutyKind != group.DutyKind ||
		q.TargetOwnerID != group.OwnerID || q.TargetID != group.TargetID || q.SelectedEvidenceSummary != group.SelectedEvidenceSummary || q.DependentGroups != ended ||
		q.PredecessorRevisionID != before.Image.Revision || q.PredecessorFullHEADDigest != contract.Hash(before.HEAD) || q.PredecessorToken != before.Token ||
		q.BeforeAccessRoot != before.Image.Root.CurrentAccess.AccessRoot || q.AfterAccessRoot != before.Image.Root.CurrentAccess.AccessRoot ||
		q.BeforeAccessIncarnationID != before.Control.AccessIncarnationID || q.AfterAccessIncarnationID != before.Control.AccessIncarnationID ||
		q.BeforeAccessGeneration != before.Control.AccessGeneration || q.AfterAccessGeneration != before.Control.AccessGeneration ||
		q.BeforeWarningBits != before.Image.Root.WarningBits || q.AfterWarningBits != warning || after.root.WarningBits != warning ||
		q.BeforeChildCount != uint16(before.Image.Root.ChildCount) || q.AfterChildCount != uint16(after.root.ChildCount) ||
		q.BeforeChildBytes != before.Image.Root.ChildEncodedBytes || q.AfterChildBytes != after.root.ChildEncodedBytes {
		t.Fatal("End envelope changed its original predecessor, exact scope or warnings")
	}
	windows, err := after.receiptWindows(ctx)
	if err != nil || len(windows.Successes) != len(before.Windows.Successes)+1 || windows.DomainID != before.Windows.DomainID ||
		!slices.Equal(windows.Successes[:len(before.Windows.Successes)], before.Windows.Successes) || !slices.Equal(windows.Failures, before.Windows.Failures) {
		t.Fatal("End changed original complete receipt windows", err)
	}
	r := windows.Successes[len(windows.Successes)-1]
	if r.DomainID != q.DomainID || r.OperationID != q.OperationID || r.OperationKind != contract.OperationEndSelectedWork || r.StateResult != contract.ReceiptStateWorkEnded ||
		r.CanonicalOutcome != contract.ReceiptCanonicalSelected || r.EffectSummary != contract.ReceiptEffectNotApplicable || r.AdministrativeDisposition != q.RequestCoreDigest ||
		r.AdministrativeTargetKind != group.OwnerKind || r.AdministrativeTargetID != group.TargetID || r.AdministrativeOriginalEvidence != group.SelectedEvidenceSummary ||
		r.WarningBits != uint64(warning) || r.AdministrativeWarningChanges != warning&^before.Image.Root.WarningBits ||
		r.PredecessorRevisionID != before.Image.Revision || r.ObservedRevisionID != after.head.Core.Revision ||
		r.AdministrativePageDelta != int16(q.AfterChildCount)-int16(q.BeforeChildCount) || r.AdministrativeByteDelta != int64(q.AfterChildBytes)-int64(q.BeforeChildBytes) {
		t.Fatal("End did not append its one exact independently checked disposition receipt")
	}
}

func operatorReopenCurrent(run *scenarioRun, after *StateSession, activeTrust contract.Trust, disabled bool) *StateSession {
	t, ctx := run.t, run.ctx
	t.Helper()
	if after.valueEntry(0) == nil || run.env.FreshCurrent == nil {
		t.Fatal("operator reopen lacks the current generated value or fresh reader")
	}
	current := run.open(OpenContext{admission: &after.admission})
	if current.head.Core != after.head.Core || current.token != after.token ||
		!bytes.Equal(current.body, after.body) || current.root.Snapshot != after.root.Snapshot {
		t.Fatal("ordinary admission did not reopen the selected operator state")
	}
	if !disabled {
		wanted := append(current.currentEntryInputs(), ApplyEntryInput{Name: "ordinary-after-operator",
			Recipients: []contract.ID{current.admission.recipient}, ValueSource: format.Supplied,
			ConfidentialityClass: format.Plain, InputBytes: []byte("selected after operator exit"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		continuation := *run
		if observed, ok := activeTrust.(scenarioTrust); !ok || observed.spy != run.spy {
			activeTrust = scenarioTrust{Trust: activeTrust, spy: run.spy}
		}
		continuation.env.Trust = activeTrust
		candidate := continuation.suppliedCandidate(current, wanted)
		continued, result := current.selectCandidate(ctx, candidate)
		if continued == nil || result.Outcome != ObservedCurrent || continued.root.ChildCount > 32 ||
			continued.root.SecretCount != after.root.SecretCount || len(continued.root.Names) != len(after.root.Names)+1 {
			t.Fatal("new ordinary work was not selected after exit", result)
		}
		for _, name := range after.root.Names {
			if !reflect.DeepEqual(continued.valueEntry(name.Slot), after.valueEntry(name.Slot)) {
				t.Fatal("ordinary continuation changed a retained current value entry")
			}
		}
		current = continued
	}
	run.env.FreshCurrent(t, OpenContext{admission: &current.admission}, current)
	return current
}

func operatorParseID(value string) (contract.ID, bool) {
	var id contract.ID
	if len(value) != 64 {
		return id, false
	}
	body, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(body) != value {
		return id, false
	}
	copy(id[:], body)
	return id, !id.IsZero()
}

// full_only: false
func TestOperatorReopenCurrentPreservesSelectionAndUsesCurrentSigner(t *testing.T) {
	for _, test := range []struct {
		name              string
		restore, disabled bool
	}{
		{"normal", false, false},
		{"restored-normal", true, false},
		{"disabled-recovery", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			restore, disabled := test.restore, test.disabled
			ctx := t.Context()
			env, _ := genesisEnvironment(t, contract.GCP, !disabled)
			env = syntheticAuthorityScenarioEnvironment(t, env)
			defer env.Custody.RetireGenerated()
			seed := newEnvironmentFixture(t, ctx, env, nil, false).session
			profile := defaultGeneratedFixtureProfile()
			selected := selectPrivateGeneratedOperation(t, env, seed,
				generatedPlanInputForGenerations(t, seed, generatedVectorID(230), []string{"generated"}, profile), "operator initial")
			old := *selected.valueEntry(0)
			selected = selectPrivateGeneratedOperation(t, env, selected,
				generatedStatePlanInput(t, selected, generatedVectorID(231), []string{old.Name}, profile, old.Generated.Epoch+1,
					map[string]contract.ID{old.Name: old.Incarnation}, map[string]contract.ValueEntry{old.Name: old}), "operator rotation")
			if len(selected.adminIndex.Groups) != 1 {
				t.Fatal("fixture lacks one selected retirement")
			}
			activeTrust := env.Trust
			var oldTrust *operatorRefusingOldTrust
			if restore {
				restoreBefore := publicOperatorFreeze(t, ctx, selected)
				replacement := syntheticFreshAuthorityReplacementEnvironment(t, env)
				actors := replacement.ReplacementActors(t, ctx, selected, contract.SuccessionReplaceAuthority,
					contract.SuccessionChangeNormalSigner, contract.RecoverySigningRole)
				permit := admitAuthorityReplacement(t, selected, actors.Keys, actors.After, contract.SuccessionReplaceAuthority,
					contract.RecoverySigningRole, contract.SuccessionChangeNormalSigner, actors.Source)
				candidate, result := selected.PrepareSuccession(ctx, permit, actors.Signers)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("restoration preparation", result)
				}
				admission := deliverSuccessionBasis(t, candidate)
				if result := selected.Select(ctx, candidate); result.Outcome != ObservedCurrent {
					t.Fatal("restoration selection", result)
				}
				selected, result = Open(ctx, admission, env.Store)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("restored read", result)
				}
				selected = operatorAuthenticatedRead(t, ctx, selected, env.Store)
				publicOperatorCheckRestore(t, ctx, restoreBefore, selected, actors.After.NormalSigning)
				activeTrust = actors.Signers.NormalSuccessor
				oldTrust = &operatorRefusingOldTrust{Trust: env.Trust}
				env.Trust = oldTrust
			}
			after := selected
			if !disabled {
				endBefore := publicOperatorFreeze(t, ctx, selected)
				group := selected.adminIndex.Groups[0]
				operatorEndFixture(t, ctx, selected, env.Store, activeTrust)
				after = operatorAuthenticatedRead(t, ctx, selected, env.Store)
				publicOperatorCheckEnd(t, ctx, endBefore, after, group)
			} else {
				before := publicOperatorFreeze(t, ctx, selected)
				after = operatorAuthenticatedRead(t, ctx, selected, env.Store)
				windows, err := after.receiptWindows(ctx)
				if err != nil || !publicOperatorReceiptWindowsEqual(before.Windows, windows) {
					t.Fatal("cold complete reopen changed frozen receipt windows", err)
				}
			}
			kept := *after.valueEntry(0)
			beforeHead, beforeToken, beforeBody := after.head.Core, after.token, bytes.Clone(after.body)
			beforeImage := sessionStateImage(t, after)
			for _, change := range []string{"identity", "ciphertext", "recipient", "origin", "membership", "access"} {
				altered := copyStateImage(t, beforeImage)
				entry := altered.Pages[0].Slots[0]
				switch change {
				case "identity":
					entry.ValueState[0] ^= 1
				case "ciphertext":
					entry.ValueBytes = append(entry.ValueBytes, 1)
				case "recipient":
					entry.Recipients[0][0] ^= 1
				case "origin":
					entry.OriginSnapshot[0] ^= 1
				case "membership":
					altered.Root.MembershipCount++
				case "access":
					altered.Root.AccessRecordCount++
				}
				if publicOperatorCurrentPreserved(beforeImage, altered, contract.ID{}) {
					t.Fatal("frozen predecessor accepted changed current state", change)
				}
			}
			wanted := append(after.currentEntryInputs(), ApplyEntryInput{Name: "ordinary-after-operator",
				Recipients: []contract.ID{after.admission.recipient}, ValueSource: format.Supplied,
				ConfidentialityClass: format.Plain, InputBytes: []byte("selected after operator exit"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			complete, result := Open(ctx, OpenContext{admission: &after.admission}, env.Store)
			if complete == nil || result.Outcome != ObservedCurrent {
				t.Fatal("complete post-exit read", result)
			}
			if comparison, result := complete.Compare(ctx, wanted, nil); comparison != nil || result.Outcome != AdmissionRefused {
				t.Fatal("generated secret accepted absent private comparison admission", result)
			}
			var charges []int
			env.ReserveCustody = func(operation string, count int) bool {
				if operation != "compare" {
					t.Fatal("unchanged secret requested preparation custody", operation)
				}
				charges = append(charges, count)
				return true
			}
			freshCalls := 0
			env.FreshCurrent = func(tb testing.TB, admission OpenContext, current *StateSession) {
				tb.Helper()
				freshCalls++
				facts := liveGeneratedFreshFacts(tb, admission, current, current.admission.domain, "operator-prefix")
				cold, result := Open(ctx, admission, env.Store)
				if cold == nil || result.Outcome != ObservedCurrent || cold.head.Core != current.head.Core ||
					cold.token != current.token || !bytes.Equal(cold.body, current.body) || cold.root.Snapshot != current.root.Snapshot ||
					!reflect.DeepEqual(*cold.valueEntry(0), kept) || !reflect.DeepEqual(cold.adminIndex.Groups, current.adminIndex.Groups) {
					tb.Fatal("fresh reader lost the exact current selection")
				}
				assertStateImage(tb, cold, facts.Expected)
			}
			run := newScenarioRun(t, ctx, env)
			if !restore {
				activeTrust = run.env.Trust
			}
			continued := operatorReopenCurrent(run, after, activeTrust, disabled)
			if freshCalls != 1 {
				t.Fatal("current selection did not receive exactly one fresh reader check", freshCalls)
			}
			if disabled {
				if continued.head.Core != beforeHead || continued.token != beforeToken ||
					!bytes.Equal(continued.body, beforeBody) || !reflect.DeepEqual(sessionStateImage(t, continued), beforeImage) ||
					len(continued.adminIndex.Groups) != 1 ||
					run.spy.StoreCreate != 0 || run.spy.StoreCAS != 0 || run.spy.TrustSign != 0 || len(charges) != 0 {
					t.Fatal("disabled Recovery reopen changed selected state or entered ordinary mutation")
				}
				return
			}
			if run.spy.TrustSign != 1 {
				t.Fatal("ordinary continuation did not record exactly one Sign", run.spy.TrustSign)
			}
			if !reflect.DeepEqual(*continued.valueEntry(0), kept) || continued.root.WarningBits != after.root.WarningBits ||
				len(continued.adminIndex.Groups) != 0 || !slices.Equal(charges, []int{2}) ||
				oldTrust != nil && oldTrust.signCalls != 0 {
				t.Fatal("ordinary continuation changed generated state, warnings, custody charge or signer")
			}
			cold, result := Open(ctx, OpenContext{admission: &continued.admission}, env.Store)
			if cold == nil || result.Outcome != ObservedCurrent || !reflect.DeepEqual(*cold.valueEntry(0), kept) {
				t.Fatal("ordinary continuation did not retain the generated secret on cold read", result)
			}
		})
	}
}
