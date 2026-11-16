package format

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

func receiptSupportFixture(t testing.TB, count int) RequiredSupportPage {
	t.Helper()
	rows := make([]contract.SupportRecord, count)
	for i := range rows {
		row := contract.CompactMutationReceipt{Schema: contract.MutationReceiptSchema, OperationKind: 36,
			DomainID: fid(1), OperationID: contract.Hash(binary.BigEndian.AppendUint32(nil, uint32(i))),
			RequestIdentityDigest: fid(6), PredecessorRevisionID: fid(7), RequestedRevisionID: fid(8), ObservedRevisionID: fid(8),
			StateResult: 1, EvidenceCeiling: 1, CanonicalOutcome: 1,
			ChangedSubjects: contract.GeneratorDescriptor{Digest: fid(9), Length: 80, Count: 2}, CompleteResult: contract.GeneratorDescriptor{Digest: fid(10), Length: 655, Count: 1}}
		body, err := contract.EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal(err)
		}
		rows[i] = contract.SupportRecord{Kind: 7, RecordID: row.OperationID, Body: body}
	}
	return RequiredSupportPage{Domain: fid(1), Object: fid(40), Index: 255, Records: rows}
}

// full_only: false
func TestRequiredSupportPageExactContainerAndLimits(t *testing.T) {
	for _, count := range []int{1, 256, 512} {
		p := receiptSupportFixture(t, count)
		body, err := EncodeRequiredSupportPage(p)
		if err != nil || len(body) != 75+508*count {
			t.Fatalf("page length=%d error=%v", len(body), err)
		}
		// The container vector is built independently of its production writer.
		want := []byte{'E', 'N', 'K', 'V', 8, 0, 11}
		want = append(want, p.Domain[:]...)
		want = append(want, p.Object[:]...)
		want = append(want, 0, 255)
		want = binary.BigEndian.AppendUint16(want, uint16(count))
		for _, row := range p.Records {
			want = append(want, 7)
			want = append(want, row.RecordID[:]...)
			want = binary.BigEndian.AppendUint32(want, contract.CompactMutationReceiptLength)
			want = append(want, row.Body...)
		}
		if !bytes.Equal(body, want) {
			t.Fatal("support container differs")
		}
		if cap(body) != len(body) {
			t.Errorf("support page length=%d capacity=%d", len(body), cap(body))
		}
		view, err := InspectRequiredSupportPage(want)
		if err != nil || view.Domain != p.Domain || view.Object != p.Object || view.Index != p.Index || len(view.Records) != count {
			t.Fatalf("independent support container refused: %v", err)
		}
		for i, row := range view.Records {
			if row.Kind != p.Records[i].Kind || row.RecordID != p.Records[i].RecordID || !bytes.Equal(row.Body, p.Records[i].Body) {
				t.Fatal("support container changed a retained receipt", i)
			}
		}
		if count == 512 && (len(body) != 260171 || 262144-len(body) != 1973) {
			t.Fatal("full receipt page bound changed", len(body))
		}
		ref, err := Reference(contract.RequiredSupportKind, p.Domain, p.Object, p.Index, body)
		if err != nil {
			t.Fatal(err)
		}
		key, err := Key("fixture", ref)
		if err != nil || !strings.Contains(key, "/support/255/") {
			t.Fatal("support coordinate unavailable", err)
		}
		for _, offset := range []int{4, 6, 71, 73, 74, 75, 76, 108} {
			bad := bytes.Clone(body)
			bad[offset] ^= 1
			if _, err := InspectRequiredSupportPage(bad); err == nil {
				t.Fatalf("changed container field %d accepted", offset)
			}
		}
		if _, err := InspectRequiredSupportPage(body[:len(body)-1]); err == nil {
			t.Fatal("truncated support accepted")
		}
		if _, err := InspectRequiredSupportPage(append(bytes.Clone(body), 0)); err == nil {
			t.Fatal("support suffix accepted")
		}
	}
	p := receiptSupportFixture(t, 0)
	if _, err := EncodeRequiredSupportPage(p); err == nil {
		t.Fatal("stored empty window accepted")
	}
	p = receiptSupportFixture(t, 1)
	for _, kind := range []uint8{0, 1, 2, 3, 4, 5, 6, 8, 255} {
		p.Records[0].Kind = kind
		if _, err := EncodeRequiredSupportPage(p); err == nil {
			t.Fatalf("unsupported record kind %d accepted", kind)
		}
	}
}

// full_only: false
func TestRequiredSupportRootAndTypedIdentityPlan(t *testing.T) {
	p := receiptSupportFixture(t, 1)
	body, err := EncodeRequiredSupportPage(p)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Reference(contract.RequiredSupportKind, p.Domain, p.Object, p.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	root := rootFixture(t)
	root.RequiredSupport = append(root.RequiredSupport, ref)
	root.RequiredSupportRecordCount++
	root.ChildCount++
	root.ChildEncodedBytes += uint64(len(body))
	if _, err := EncodeRoot(root); err != nil {
		t.Fatal("generic support reference refused without recovery", err)
	}
	recovery := root.CurrentAccess.Core.NormalSigning
	recovery.Role = contract.RecoverySigningRole
	recovery.BindingID = fid(90)
	recovery.KeySelector = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000003"
	page := recipientFixture(t)
	root.CurrentAccess.Core.Recovery = &contract.RecoveryBindings{RoleID: fid(91), Signing: recovery, KMS: *page.Slots[2].CurrentBinding}
	root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRoot(encoded)
	if err != nil || len(decoded.RequiredSupport) != 2 || decoded.RequiredSupport[1] != ref || decoded.RequiredSupportRecordCount != 2 {
		t.Fatal("root lost receipt support", err)
	}
	root.RequiredSupport = append(root.RequiredSupport, ref)
	if _, err := EncodeRoot(root); err == nil {
		t.Fatal("duplicate support page reference accepted")
	}
	next, err := contract.InspectCompactMutationReceipt(p.Records[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	next.OperationID = fid(92)
	next.RequestIdentityDigest = ID{}
	plan := contract.CompactMutationReceiptPlan(next)
	body, err = contract.AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil {
		t.Fatal(err)
	}
	p.Object, p.Index = fid(93), 0
	p.Records = append(p.Records, contract.SupportRecord{Kind: 7, RecordID: next.OperationID, Body: body})
	planBytes, err := EncodeRequiredSupportReceiptPlan(p, plan)
	if err != nil || len(planBytes) != 75+2*508 {
		t.Fatal("typed receipt page plan refused", err)
	}
	if _, err := InspectRequiredSupportPage(planBytes); err == nil {
		t.Fatal("typed plan entered stored support decoder")
	}
	if _, err := Reference(contract.RequiredSupportKind, p.Domain, fid(93), 0, planBytes); err == nil {
		t.Fatal("typed plan received actual child reference")
	}
}

// full_only: false
func TestMutationReceiptPlanPreservesAcceptedSupportPrefix(t *testing.T) {
	p := receiptSupportFixture(t, 1)
	work := contract.PendingInboxReleaseRecord{Schema: 1, DomainID: p.Domain, InboxID: fid(50), OriginalResultID: fid(51),
		SelectedHandoffDigest: fid(52), HandoffRevisionID: fid(53),
		CapacityReservation: contract.GeneratorDescriptor{Digest: fid(49), Length: 8, Count: 1}, ObjectLength: 100, State: 1}
	body, err := contract.EncodePendingInboxReleaseRecord(work)
	if err != nil {
		t.Fatal(err)
	}
	accepted := contract.SupportRecord{Kind: 12, RecordID: work.InboxID, Body: body}
	next, err := contract.InspectCompactMutationReceipt(p.Records[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	next.OperationID, next.RequestIdentityDigest = fid(54), ID{}
	plan := contract.CompactMutationReceiptPlan(next)
	planBody, err := contract.AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil {
		t.Fatal(err)
	}
	p.Records = append([]contract.SupportRecord{accepted}, p.Records...)
	p.Records = append(p.Records, contract.SupportRecord{Kind: 7, RecordID: next.OperationID, Body: planBody})
	planned, err := EncodeRequiredSupportReceiptPlan(p, plan)
	if err != nil {
		t.Fatal(err)
	}
	next.RequestIdentityDigest = fid(55)
	p.Records[2].Body, err = contract.EncodeCompactMutationReceipt(next)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := EncodeRequiredSupportPage(p)
	prefixLength := 75 + 37 + len(body)
	if err != nil || len(actual) != len(planned) || !bytes.Equal(actual[:prefixLength], planned[:prefixLength]) {
		t.Fatal("receipt plan altered accepted support", err)
	}
	// Existing receipt (508), record frame (37), then six uint16 fields
	// and domain/operation IDs (76) precede the sole request-identity hole.
	want := bytes.Clone(planned)
	hole := prefixLength + 508 + 37 + 76
	copy(want[hole:hole+32], next.RequestIdentityDigest[:])
	if !bytes.Equal(actual, want) {
		t.Fatal("filling receipt request changed another byte")
	}
	if cap(planned) != len(planned) || cap(actual) != len(actual) {
		t.Errorf("receipt page plan length=%d capacity=%d; actual length=%d capacity=%d", len(planned), cap(planned), len(actual), cap(actual))
	}
	decoded, err := InspectRequiredSupportPage(actual)
	if err != nil || len(decoded.Records) != 3 || !bytes.Equal(decoded.Records[0].Body, body) {
		t.Fatal("mixed selected support lost exact work body", err)
	}
	p.Records[2].Body = planBody
	p.Records = append(p.Records, p.Records[2])
	if _, err := EncodeRequiredSupportReceiptPlan(p, plan); err == nil {
		t.Fatal("receipt admitted twice through accepted-support prefix")
	}
}
