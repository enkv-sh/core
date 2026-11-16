package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

// The same actual-capacity interval union as the Core hermetic counter stays
// within Crypto here: no private byte slice or address leaves this package.
type accessMemoryRange struct{ start, end uintptr }
type accessMemoryBuffers []accessMemoryRange

func (b *accessMemoryBuffers) add(v []byte) {
	if cap(v) != 0 {
		start := reflect.ValueOf(v).Pointer()
		*b = append(*b, accessMemoryRange{start, start + uintptr(cap(v))})
	}
}
func (b accessMemoryBuffers) capacity() uint64 {
	slices.SortFunc(b, func(a, c accessMemoryRange) int {
		if a.start < c.start {
			return -1
		}
		if a.start > c.start {
			return 1
		}
		return 0
	})
	var total uint64
	var end uintptr
	for _, r := range b {
		if r.end > max(r.start, end) {
			total += uint64(r.end - max(r.start, end))
		}
		end = max(end, r.end)
	}
	return total
}
func (b *accessMemoryBuffers) record(r contract.AccessRecord) {
	for _, w := range r.Wraps {
		b.add(w.RSACiphertext)
	}
}

func accessMemoryFixture(t *testing.T, ordinaryWraps int) (contract.CryptoAccessPrepareRequest, []contract.BindingTableRow, *consumerTestRoute) {
	t.Helper()
	selection, route := consumerFixture(t)
	table := []contract.BindingTableRow{selection.Binding}
	for i := 1; i < 258; i++ {
		row := selection.Binding
		row.SubjectID = consumerID(fmt.Sprintf("memory subject %d", i))
		row.Binding.BindingID = consumerID(fmt.Sprintf("memory binding %d", i))
		row.Binding.KeySelector = fmt.Sprintf("projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/key-%d/cryptoKeyVersions/1", i)
		row.Binding.SPKI = bytes.Clone(row.Binding.SPKI)
		if i >= 256 {
			row.SubjectKind = 2
			row.SubjectID = consumerID("memory recovery")
		}
		if i == 257 {
			row.Binding.BindingSerial = 2
		}
		table = append(table, row)
	}
	slices.SortFunc(table, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
			return n
		}
		if a.Binding.BindingSerial < b.Binding.BindingSerial {
			return -1
		}
		return 1
	})
	// This is a row-allocation component fixture, not succession admission or
	// independent-key qualification. Distinct public bindings share one test RSA
	// key; the real route must still open each exact source packet and context.
	encodedTable, err := contract.EncodeBindingTable(table)
	if err != nil {
		t.Fatal(err)
	}
	ownedTable, err := contract.DecodeBindingTable(encodedTable)
	if err != nil {
		t.Fatal(err)
	}
	source := slices.IndexFunc(ownedTable, func(row contract.BindingTableRow) bool {
		return row.Binding.BindingID == selection.Binding.Binding.BindingID
	})
	target := len(ownedTable) - 1
	ordinary := []int{source}
	for i := 0; len(ordinary) < ordinaryWraps; i++ {
		if i != source {
			ordinary = append(ordinary, i)
		}
	}
	indices := append(ordinary, target-1)
	slices.Sort(indices)
	c := contract.ApplyContext{OperationClass: contract.CryptoAccessReplacementClass, AdmissionID: consumerID("memory admission"), SessionID: consumerID("memory session"), DomainID: selection.DomainID, CompatibilityID: contract.CompatibilityID(), Expiry: 1, PredecessorHEADDigest: selection.HEADDigest, OriginalConditionDigest: consumerID("memory condition"), IntentDescriptor: contract.DescriptorVector{Digest: consumerID("memory request"), Length: uint64(contract.RequestCoreMaxLength), Count: 1}, CurrentAccessRoot: selection.AccessRoot}
	ref, err := contract.AppendRef(nil, selection.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	copy(c.PredecessorRootRef[:], ref)
	consumer, err := contract.CurrentValueConsumerDigest(selection.DomainID)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.CryptoAccessPrepareRequest{OperationRef: consumerID("memory operation"), Context: c, Final: 1}
	for i := 0; i < 512; i++ {
		core := selection.Core
		core.Name = fmt.Sprintf("%03d", i) + strings.Repeat("x", 253)
		core.ValueStateID = consumerID(core.Name + " value")
		core.DataKeyID = consumerID(core.Name + " data")
		core.CommitmentKeyID = consumerID(core.Name + " commitment")
		keys := make([]byte, 64)
		if _, err := rand.Read(keys); err != nil {
			t.Fatal(err)
		}
		check, err := custody.PackageCheck(core, keys)
		if err != nil {
			t.Fatal(err)
		}
		material, err := contract.ValueMaterialContextDigest(core)
		if err != nil {
			t.Fatal(err)
		}
		access := contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: material, PackageCheck: check}
		for _, index := range indices {
			wrapCore, err := custody.ValueWrapCore(core, ownedTable[index])
			if err != nil {
				t.Fatal(err)
			}
			wrap, err := custody.Wrap(wrapCore, ownedTable[index].Binding, keys)
			if err != nil {
				t.Fatal(err)
			}
			access.Wraps = append(access.Wraps, wrap)
		}
		clear(keys[:cap(keys)])
		digest, err := contract.AccessRecordDigest(access)
		if err != nil {
			t.Fatal(err)
		}
		q.Rows = append(q.Rows, contract.CompactRow{ValueCore: core, BeforeAccessRecord: access, Coverage: contract.CoverageRow{MaterialKind: 1, MaterialID: core.ValueStateID, MaterialContextDigest: material, ImmutableBodyDigest: consumerID(core.Name + " body"), BeforeAccessDigest: digest, RequiredConsumerDigest: consumer, SourceBindingIndex: uint16(source), TargetBindingIndices: []uint16{uint16(target)}}})
	}
	slices.SortFunc(q.Rows, func(a, b contract.CompactRow) int {
		return bytes.Compare(a.Coverage.MaterialID[:], b.Coverage.MaterialID[:])
	})
	input, output, count := 4, 4, 0
	for _, row := range q.Rows {
		in, out, err := contract.AccessInputRowLengths(row)
		if err != nil {
			t.Fatal(err)
		}
		if input+in > contract.AccessBatchLimit || output+out > contract.AccessBatchLimit {
			break
		}
		input += in
		output += out
		count++
	}
	if count == 0 || count == len(q.Rows) {
		t.Fatal("component fixture does not cross a batch boundary")
	}
	q.Rows, q.Final = q.Rows[:count], 0
	return q, ownedTable, route
}

// full_only: false
func TestAccessReplacementByteOwners(t *testing.T) {
	for _, ordinaryWraps := range []int{8, 64} {
		t.Run(fmt.Sprintf("ordinary-wraps-%d", ordinaryWraps), func(t *testing.T) {
			checkAccessReplacementByteOwners(t, ordinaryWraps)
		})
	}
}

func checkAccessReplacementByteOwners(t *testing.T, ordinaryWraps int) {
	t.Helper()
	input, bindings, route := accessMemoryFixture(t, ordinaryWraps)
	body, err := contract.EncodeCryptoAccessPrepareRequest(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contract.DecodeCryptoAccessPrepareRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	var owned accessMemoryBuffers
	for _, binding := range bindings {
		owned.add(binding.Binding.SPKI)
	}
	bindingBytes := owned.capacity()
	for _, row := range decoded.Rows {
		owned.record(row.BeforeAccessRecord)
	}
	decodedBytes := owned.capacity() - bindingBytes
	before := owned.capacity()
	a := &accessAdmission{session: &session{ctx: context.Background()}, request: contract.CryptoAccessReplaceRequest{BindingTable: bindings}}
	result := contract.CryptoAccessPrepareResult{BatchIndex: decoded.BatchIndex, Final: decoded.Final}
	var maxPrivate uint64
	for _, row := range decoded.Rows {
		var response contract.CryptoResponse
		after, code := a.rewrap(context.Background(), route, row, &response)
		if code != contract.CryptoSuccess {
			t.Fatal("component rewrap", code)
		}
		maxPrivate = max(maxPrivate, uint64(cap(route.returned)))
		if !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
			t.Fatal("rewrap retained private packet capacity")
		}
		result.Rows = append(result.Rows, after)
		owned.record(after.AfterAccessRecord)
	}
	outputBytes := owned.capacity() - before
	if want := uint64(384 * len(decoded.Rows)); outputBytes != want {
		t.Fatalf("new output byte union %d, want one RSA allocation per row %d", outputBytes, want)
	}
	result.InputBatchDescriptor, err = contract.AccessInputBatchDescriptor(decoded.Rows)
	if err != nil {
		t.Fatal(err)
	}
	result.OutputBatchDescriptor, err = contract.AccessOutputBatchDescriptor(result.Rows)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := contract.EncodeCryptoAccessPrepareResult(result)
	if err != nil {
		t.Fatal(err)
	}
	owned.add(body)
	owned.add(encoded)
	coreDecoded, err := contract.DecodeCryptoAccessPrepareResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	coreCopyBefore := owned.capacity()
	for _, row := range coreDecoded.Rows {
		owned.record(row.AfterAccessRecord)
	}
	coreCopy := owned.capacity() - coreCopyBefore
	if coreCopy != uint64(len(decoded.Rows)*(ordinaryWraps+1)*384) {
		t.Fatal("Core result decoder capacity changed", coreCopy)
	}
	// This uses the same production packet constructor called inside Wrap.
	// The source decrypt packet is still live when Wrap creates this second
	// packet. PacketKeys borrows its 64-byte key suffix, so it adds no owner.
	packet, err := custody.EncodePacket(1, [32]byte{1}, make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	wrapPacket := uint64(cap(packet))
	clear(packet[:cap(packet)])
	if maxPrivate != 132 || wrapPacket != 100 {
		t.Fatal("controlled packet capacity changed", maxPrivate, wrapPacket)
	}
	privatePeak := maxPrivate + wrapPacket
	// Binding/decoded/output owners are disjoint from the transport bodies.
	// Unchanged wraps alias decoded input and are already unioned above.
	extra := bindingBytes + decodedBytes + outputBytes + privatePeak
	if extra > 3*(2<<20)+1024 {
		t.Fatal("Crypto component owners exceed their composed regions", extra)
	}
	if total := owned.capacity() + privatePeak; total > 8<<20 {
		t.Fatal("complete batch component exceeds its composed envelope", total)
	}
	t.Logf("rows=%d bindings=%d binding_spki_capacity=%d decoded_input_capacity=%d distinct_output_capacity=%d transport_request_capacity=%d transport_response_capacity=%d private_packet_peak=%d crypto_extra_capacity=%d core_result_decode_capacity=%d full_component_union_envelope=%d", len(decoded.Rows), len(bindings), bindingBytes, decodedBytes, outputBytes, cap(body), cap(encoded), privatePeak, extra, coreCopy, owned.capacity()+privatePeak)
	runtime.KeepAlive(bindings)
	runtime.KeepAlive(decoded)
	runtime.KeepAlive(result)
	runtime.KeepAlive(body)
	runtime.KeepAlive(encoded)
	runtime.KeepAlive(route)
	runtime.KeepAlive(coreDecoded)
}
