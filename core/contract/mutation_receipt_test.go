package contract

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mutationReceiptFixture() CompactMutationReceipt {
	v := CompactMutationReceipt{Schema: MutationReceiptSchema, OperationKind: 36, StateResult: 1, EvidenceCeiling: 1,
		DomainID: generatedRecordID(1), OperationID: generatedRecordID(2),
		RequestIdentityDigest: generatedRecordID(5), PredecessorRevisionID: generatedRecordID(6), RequestedRevisionID: generatedRecordID(7), ObservedRevisionID: generatedRecordID(7),
		CanonicalOutcome: 1, ChangedSubjects: GeneratorDescriptor{Digest: generatedRecordID(21), Length: 80, Count: 2},
		CompleteResult: GeneratorDescriptor{Digest: generatedRecordID(22), Length: 655, Count: 1}}
	v.SummaryCounts[4] = 1
	return v
}

func administrativeReceiptFixture() CompactMutationReceipt {
	v := mutationReceiptFixture()
	v.OperationKind, v.StateResult, v.EffectSummary = OperationEndSelectedWork, ReceiptStateWorkEnded, ReceiptEffectNotApplicable
	v.ChangedSubjects = GeneratorDescriptor{Digest: generatedRecordID(21), Length: 42, Count: 1}
	v.SummaryCounts = [ReceiptSummaryCount]uint32{}
	v.WarningBits, v.AdministrativeWarningChanges = 0x1f, 0x1f
	v.AdministrativeTargetKind, v.AdministrativeTargetID = 2, generatedRecordID(31)
	v.AdministrativeDisposition = generatedRecordID(32)
	v.AdministrativeOriginalEvidence = AdministrativeEvidenceMissing
	v.AdministrativePageDelta, v.AdministrativeByteDelta = -1, -8192
	v.AdministrativeGroupID = generatedRecordID(33)
	return v
}

// full_only: false
func TestAdministrativeReceiptFixedBoundAndFullWindows(t *testing.T) {
	v := administrativeReceiptFixture()
	body, err := EncodeCompactMutationReceipt(v)
	if err != nil || len(body) != CompactMutationReceiptLength || len(body) > 4096 {
		t.Fatal("administrative receipt bound", len(body), err)
	}
	decoded, err := InspectCompactMutationReceipt(body)
	if err != nil || decoded != v {
		t.Fatal("administrative receipt round trip", err)
	}
	const fullWindowRows = 2 * MutationReceiptWindowLimit
	framed := RequiredSupportPageHeaderLength + fullWindowRows*(CompactMutationReceiptLength+SupportRecordOverhead)
	if framed != 260171 || framed > 262144 || framed > MaxRequiredSupportPageLength {
		t.Fatal("full success and failure windows no longer fit one receipt page", framed)
	}
	v.AdministrativeTargetID = ID{}
	if _, err := EncodeCompactMutationReceipt(v); err == nil {
		t.Fatal("administrative receipt accepted no target")
	}
}

// full_only: false
func TestCompactMutationReceiptSchemaAndAdministrativeGroupAreExact(t *testing.T) {
	ordinary := mutationReceiptFixture()
	wire, err := EncodeCompactMutationReceipt(ordinary)
	if err != nil || len(wire) != 471 || binary.BigEndian.Uint16(wire[:2]) != 3 {
		t.Fatal("current compact receipt layout differs", err)
	}
	old := bytes.Clone(wire[:439])
	binary.BigEndian.PutUint16(old[:2], 2)
	binary.BigEndian.PutUint64(old[281:289], 623)
	for name, body := range map[string][]byte{
		"schema-two-old-length":   old,
		"schema-two-new-length":   append(bytes.Clone(old), make([]byte, 32)...),
		"schema-three-old-length": bytes.Clone(wire[:439]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := InspectCompactMutationReceipt(body); err == nil {
				t.Fatal("superseded or truncated layout accepted")
			}
		})
	}
	for name, row := range map[string]CompactMutationReceipt{
		"ordinary-group":          ordinary,
		"administrative-no-group": administrativeReceiptFixture(),
	} {
		t.Run(name, func(t *testing.T) {
			body, err := EncodeCompactMutationReceipt(row)
			if err != nil {
				t.Fatal("valid group control refused", err)
			}
			if row.OperationKind == OperationEndSelectedWork {
				row.AdministrativeGroupID = ID{}
			} else {
				row.AdministrativeGroupID = generatedRecordID(33)
			}
			copy(body[439:], row.AdministrativeGroupID[:])
			if _, err := InspectCompactMutationReceipt(body); err == nil {
				t.Error("inapplicable administrative group decoded")
			}
			if _, err := EncodeCompactMutationReceipt(row); err == nil {
				t.Error("inapplicable administrative group encoded")
			}
			plan := CompactMutationReceiptPlan(row)
			plan.RequestIdentityDigest = ID{}
			if _, err := AppendCompactMutationReceiptPlan(nil, plan); err == nil {
				t.Error("inapplicable administrative group planned")
			}
			plan.CompleteResult = GeneratorDescriptor{}
			empty := mutationEmptyResults(t)
			access := empty[0]
			if row.SummaryCounts[ReceiptChangedAccessCount] != 0 {
				access = GeneratorDescriptor{Digest: generatedRecordID(22), Length: 106, Count: 1}
			}
			if _, err := CompleteMutationResultDescriptor(MutationResultProjection{Receipt: plan, RequestCoreDigest: generatedRecordID(23),
				ChangedAccess: access, Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]}); err == nil {
				t.Error("inapplicable administrative group entered result projection")
			}
		})
	}
	first := administrativeReceiptFixture()
	second := first
	second.AdministrativeGroupID = generatedRecordID(34)
	firstWire, err := EncodeCompactMutationReceipt(first)
	if err != nil {
		t.Fatal(err)
	}
	secondWire, err := EncodeCompactMutationReceipt(second)
	if err != nil || !bytes.Equal(firstWire[:439], secondWire[:439]) || !bytes.Equal(firstWire[439:], first.AdministrativeGroupID[:]) || !bytes.Equal(secondWire[439:], second.AdministrativeGroupID[:]) {
		t.Fatal("administrative group did not append without changing scalar offsets", err)
	}
	var previousResult GeneratorDescriptor
	var previousDelta ID
	// Independent big-endian writes and SHA-256 pin both nonzero group values
	// after the five result descriptors, not just the ordinary zero-group case.
	completeHashes := []string{"a80fb9862e94e2d1605ca9075e0309f1f7ee73703ae712b70ba138cb7f8ee42c", "473d2e018abe3229a09f4196118f9f8e32d48a9c006fbcdaaad1c7be85e8b0d8"}
	receiptHashes := []string{"1282b3c40e9dd6c6fa87a4bc5d15afddd212ef2c892d3ca9556f19aa396d2ecf", "84afd9bde553be2e46dcf985e158e1d8f3841fb9e5429c6da27e71d1f4832618"}
	for i, row := range []CompactMutationReceipt{first, second} {
		body, err := EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := InspectCompactMutationReceipt(body)
		if err != nil || decoded != row {
			t.Fatal("administrative receipt did not retain exact group", err)
		}
		encoded, err := EncodeCompactMutationReceipt(decoded)
		if err != nil || !bytes.Equal(encoded, body) {
			t.Fatal("administrative receipt changed original bytes", err)
		}
		plan := CompactMutationReceiptPlan(row)
		plan.RequestIdentityDigest = ID{}
		planned, err := AppendCompactMutationReceiptPlan(nil, plan)
		if err != nil || !bytes.Equal(planned[439:], body[439:]) {
			t.Fatal("receipt identity hole erased administrative group", err)
		}
		delta, err := MutationReceiptDeltaPlanDigest(MutationReceiptDeltaPlan{DomainID: row.DomainID, OperationKind: row.OperationKind, AddedCount: 1,
			Before: MutationReceiptWindows{DomainID: row.DomainID}, NewReceipt: plan})
		if err != nil || i != 0 && delta == previousDelta {
			t.Fatal("receipt delta omitted exact administrative group", err)
		}
		previousDelta = delta
		plan.CompleteResult = GeneratorDescriptor{}
		empty := mutationEmptyResults(t)
		result, err := CompleteMutationResultDescriptor(MutationResultProjection{Receipt: plan, RequestCoreDigest: generatedRecordID(23),
			ChangedAccess: empty[0], Effects: empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]})
		if err != nil || result.Length != 655 || hex.EncodeToString(result.Digest[:]) != completeHashes[i] || i != 0 && result == previousResult {
			t.Fatal("complete result omitted exact administrative group", err)
		}
		previousResult = result
		row.CompleteResult = result
		completed, err := EncodeCompactMutationReceipt(row)
		if err != nil {
			t.Fatal("independent administrative result receipt refused", err)
		}
		digest := Hash(completed)
		if hex.EncodeToString(digest[:]) != receiptHashes[i] {
			t.Fatal("administrative receipt differs from independent scalar traversal")
		}
	}
}

func mutationEmptyResults(t testing.TB) [5]GeneratorDescriptor {
	t.Helper()
	var out [5]GeneratorDescriptor
	for i, literal := range []string{
		"48314ad098b2bfe3230c4ad29c7a4ed63f159b2c1684e27510ae65769156afcd",
		"be54ac5f1cf1023df0ed2f4b19c71a2faf5a6e854bca3b3671e5f6b5b3bed2ec",
		"be1b0ee1add31614a1d8771eb71db6a5b3e3ceecc00a276b403a0aabedfba30f",
		"e2ab39afe9e8535504ee660ae490602d8aeee85cd02da66f97a759f591821f6f",
		"9512f0e6ecdba44c741255fde13c477499e5976ffefda21be7fd46d0f19392b1",
	} {
		body, err := hex.DecodeString(literal)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = GeneratorDescriptor{Digest: ID(body), Length: 4}
	}
	return out
}

// full_only: false
func TestCompleteMutationResultIndependentProjection(t *testing.T) {
	// Python standard SHA-256 over the explicit 655-byte scalar traversal and
	// count/B framing produced these literals; no implementation encoder ran.
	v := mutationReceiptFixture()
	plan := CompactMutationReceiptPlan(v)
	plan.RequestIdentityDigest, plan.CompleteResult = ID{}, GeneratorDescriptor{}
	empty := mutationEmptyResults(t)
	if EmptyMutationResultDescriptors() != empty {
		t.Fatal("empty result descriptor families differ from independent hashes")
	}
	p := MutationResultProjection{Receipt: plan, RequestCoreDigest: generatedRecordID(23),
		ChangedAccess: GeneratorDescriptor{Digest: generatedRecordID(22), Length: 106, Count: 1},
		Effects:       empty[1], Outputs: empty[2], Duties: empty[3], Hazards: empty[4]}
	got, err := CompleteMutationResultDescriptor(p)
	if err != nil || got.Count != 1 || got.Length != 655 || hex.EncodeToString(got.Digest[:]) != "da067f8ec4c2196ad254f3f44ec3e676d76b9fb94bd2d4798854ee13a23d75a1" {
		t.Fatalf("complete result: %+v %v", got, err)
	}
	v.CompleteResult = got
	body, err := EncodeCompactMutationReceipt(v)
	if err != nil {
		t.Fatal(err)
	}
	digest := Hash(body)
	if hex.EncodeToString(digest[:]) != "29380696f5f0b955e4b699dc513345ae6bd4e779ecea25175fa997783693327d" {
		t.Fatalf("receipt traversal: %x", digest)
	}
	changed := p
	changed.ChangedAccess.Digest = generatedRecordID(24)
	other, err := CompleteMutationResultDescriptor(changed)
	if err != nil || got == other {
		t.Fatal("lost exact changed-access commitment")
	}
	for _, mutate := range []func(*MutationResultProjection){
		func(v *MutationResultProjection) { v.RequestCoreDigest = ID{} },
		func(v *MutationResultProjection) { v.Receipt.RequestIdentityDigest = generatedRecordID(1) },
		func(v *MutationResultProjection) { v.Receipt.CompleteResult = got },
		func(v *MutationResultProjection) { v.ChangedAccess = empty[0] },
		func(v *MutationResultProjection) { v.Effects.Count = 1; v.Effects.Length = 8 },
	} {
		x := p
		mutate(&x)
		if _, err := CompleteMutationResultDescriptor(x); err == nil {
			t.Fatal("inconsistent result projection accepted")
		}
	}
}

// full_only: false
func TestCompactMutationReceiptClosedResultAndIdentityPlan(t *testing.T) {
	v := mutationReceiptFixture()
	b, err := EncodeCompactMutationReceipt(v)
	if err != nil || len(b) != CompactMutationReceiptLength {
		t.Fatalf("encode: %d %v", len(b), err)
	}
	got, err := InspectCompactMutationReceipt(b)
	if err != nil || got != v {
		t.Fatalf("round trip: %v", err)
	}
	p := CompactMutationReceiptPlan(v)
	p.RequestIdentityDigest = ID{}
	planned, err := AppendCompactMutationReceiptPlan(nil, p)
	if err != nil || len(planned) != len(b) || !bytes.Equal(planned[:76], b[:76]) || !bytes.Equal(planned[108:], b[108:]) || !bytes.Equal(planned[76:108], make([]byte, 32)) {
		t.Fatalf("named identity hole changed another field: %v", err)
	}
	if _, err := InspectCompactMutationReceipt(planned); err == nil {
		t.Fatal("stored receipt accepted the request identity plan")
	}
	p.RequestIdentityDigest = v.RequestIdentityDigest
	if _, err := AppendCompactMutationReceiptPlan(nil, p); err == nil {
		t.Fatal("plan accepted a completed request identity")
	}
	for n := 0; n < len(b); n++ {
		if _, err := InspectCompactMutationReceipt(b[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
	if _, err := InspectCompactMutationReceipt(append(bytes.Clone(b), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}

// full_only: false
func TestCompactMutationReceiptCanonicalOutcomeIsNotEffectOutcome(t *testing.T) {
	v := mutationReceiptFixture()
	v.OperationKind, v.StateResult, v.EffectSummary, v.EvidenceCeiling = 39, 6, 5, 2
	v.WarningBits = 1
	v.SummaryCounts[0], v.SummaryCounts[3], v.SummaryCounts[9], v.UnknownCount = 1, 1, 1, 1
	if !CompactMutationReceiptValid(v) {
		t.Fatal("selected fence with possible-live evidence refused")
	}
	v = mutationReceiptFixture()
	v.OperationKind, v.StateResult, v.EffectSummary, v.EvidenceCeiling = 2, 1, 2, 2
	v.WarningBits = 1
	v.SummaryCounts[0], v.SummaryCounts[3], v.SummaryCounts[5], v.SummaryCounts[10], v.UnknownCount = 2, 1, 1, 1, 1
	if !CompactMutationReceiptValid(v) {
		t.Fatal("successful frontier with excluded residue refused")
	}
	v.WarningBits = 0
	if CompactMutationReceiptValid(v) {
		t.Fatal("omitted possible-live warning accepted")
	}
	v = mutationReceiptFixture()
	v.OperationKind, v.StateResult, v.EffectSummary, v.EvidenceCeiling = 2, 10, 5, 2
	v.CanonicalOutcome, v.ObservedRevisionID = 2, v.PredecessorRevisionID
	v.SummaryCounts[0], v.SummaryCounts[9], v.UnknownCount = 1, 1, 1
	if !CompactMutationReceiptValid(v) {
		t.Fatal("closed nonselecting result with uncertainty refused")
	}
	v.StateResult = 8
	if CompactMutationReceiptValid(v) {
		t.Fatal("unresolved parent received a terminal receipt")
	}
}

// full_only: false
func TestCompactMutationReceiptCompletionCeilingsAndSummaryCounts(t *testing.T) {
	v := mutationReceiptFixture()
	v.OperationKind, v.EffectSummary, v.EvidenceCeiling, v.WarningBits = 38, 2, 3, 2
	v.SummaryCounts[0], v.SummaryCounts[5], v.AcknowledgedCount = 1, 1, 1
	if !CompactMutationReceiptValid(v) {
		t.Fatal("acknowledgement ceiling refused")
	}
	for _, mutate := range []func(*CompactMutationReceipt){
		func(v *CompactMutationReceipt) { v.WarningBits = 0 },
		func(v *CompactMutationReceipt) { v.EvidenceCeiling = 4 },
		func(v *CompactMutationReceipt) { v.ConfirmedCount = 1 },
		func(v *CompactMutationReceipt) { v.SummaryCounts[0]++ },
		func(v *CompactMutationReceipt) { v.CompleteResult.Count = 0 },
		func(v *CompactMutationReceipt) { v.CompleteResult.Length++ },
		func(v *CompactMutationReceipt) { v.ChangedSubjects.Length++ },
		func(v *CompactMutationReceipt) { v.OperationID = ID{} },
		func(v *CompactMutationReceipt) { v.EvidenceCeiling = 6 },
		func(v *CompactMutationReceipt) { v.SummaryCounts[7] = 1 },
		func(v *CompactMutationReceipt) { v.SummaryCounts[5] = ^uint32(0) },
	} {
		x := v
		mutate(&x)
		if CompactMutationReceiptValid(x) {
			t.Fatalf("accepted inconsistent receipt: %+v", x)
		}
	}
	v.AcknowledgedCount, v.ConfirmedCount, v.WarningBits, v.EvidenceCeiling = 0, 1, 0, 4
	if !CompactMutationReceiptValid(v) {
		t.Fatal("confirmed ceiling refused")
	}
	v.AcknowledgedCount, v.WarningBits, v.EvidenceCeiling = 1, 2, 5
	v.SummaryCounts[0], v.SummaryCounts[5] = 2, 2
	if !CompactMutationReceiptValid(v) {
		t.Fatal("mixed completion ceilings refused")
	}
}

// full_only: false
func TestCompactMutationReceiptOperationSetIsClosed(t *testing.T) {
	accepted := map[uint16]bool{1: true, 2: true, 8: true, 9: true, 10: true, 11: true, 12: true, 26: true, 32: true, 36: true, 38: true, 39: true, OperationEndSelectedWork: true}
	base, err := EncodeCompactMutationReceipt(mutationReceiptFixture())
	if err != nil {
		t.Fatal(err)
	}
	for operation := uint16(0); operation <= OperationEndSelectedWork; operation++ {
		value := mutationReceiptFixture()
		value.OperationKind = operation
		wire := bytes.Clone(base)
		binary.BigEndian.PutUint16(wire[2:4], operation)
		if operation == OperationEndSelectedWork {
			value = administrativeReceiptFixture()
			wire, err = EncodeCompactMutationReceipt(value)
			if err != nil {
				t.Fatal(err)
			}
		}
		if operation == 1 {
			value.PredecessorRevisionID = ID{}
			// Five scalar u16 fields follow schema; three IDs precede the predecessor.
			clear(wire[108:140])
		}
		_, encodeErr := EncodeCompactMutationReceipt(value)
		_, decodeErr := InspectCompactMutationReceipt(wire)
		if (encodeErr == nil) != accepted[operation] || (decodeErr == nil) != accepted[operation] {
			t.Fatalf("operation %d: encoder %v, reader %v, accepted %t", operation, encodeErr, decodeErr, accepted[operation])
		}
	}
}

// full_only: false
func TestAdministrativeReceiptAcceptsPublicationAndGCOwners(t *testing.T) {
	for _, kind := range []uint8{5, 6, 7} {
		receipt := administrativeReceiptFixture()
		receipt.AdministrativeTargetKind = kind
		body, err := EncodeCompactMutationReceipt(receipt)
		if err != nil {
			t.Fatalf("publication or GC owner kind=%d receipt: %v", kind, err)
		}
		if got, err := InspectCompactMutationReceipt(body); err != nil || got != receipt {
			t.Fatalf("publication or GC owner kind=%d roundtrip: %v", kind, err)
		}
	}
	for _, kind := range []uint8{0, 8} {
		receipt := administrativeReceiptFixture()
		receipt.AdministrativeTargetKind = kind
		if _, err := EncodeCompactMutationReceipt(receipt); err == nil {
			t.Fatalf("invalid owner kind=%d entered receipt", kind)
		}
	}
}

// full_only: false
func TestCompactMutationReceiptRefusesRetiredOperation(t *testing.T) {
	v := mutationReceiptFixture()
	v.OperationKind = 36
	wire, err := EncodeCompactMutationReceipt(v)
	if err != nil {
		t.Fatal("supported recovery replacement receipt refused", err)
	}
	v.OperationKind = 35
	binary.BigEndian.PutUint16(wire[2:4], 35)
	if _, err := EncodeCompactMutationReceipt(v); err == nil {
		t.Error("retired receipt operation encoded")
	}
	if _, err := InspectCompactMutationReceipt(wire); err == nil {
		t.Error("valid-length retired receipt operation decoded")
	}
	plan := CompactMutationReceiptPlan(v)
	plan.RequestIdentityDigest = ID{}
	if _, err := AppendCompactMutationReceiptPlan(nil, plan); err == nil {
		t.Error("retired receipt operation planned")
	}
}
