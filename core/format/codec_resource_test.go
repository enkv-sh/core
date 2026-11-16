package format

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
)

type hostileRecord struct {
	name           string
	body           []byte
	decode         func([]byte) error
	allocationBase uint64
}

func hostileRecords(t testing.TB) []hostileRecord {
	t.Helper()
	// Four schema copies allow the decoded value, return value, encoder scratch,
	// and allocator rounding. The fixed allowance covers maps and error paths;
	// the input multiplier covers bounded blob copies and canonical re-encoding.
	const fixedOverhead = 4 << 10
	bases := map[string]uint64{
		"member":    fixedOverhead + 4*uint64(unsafe.Sizeof(ValueEntryPage{})+PageSlots*unsafe.Sizeof(ValueEntry{})),
		"recipient": fixedOverhead + 4*uint64(unsafe.Sizeof(RecipientPage{})),
		"root":      fixedOverhead + 4*uint64(unsafe.Sizeof(Root{})+(contract.MaxValueEntryPages+contract.MaxRecipientPages)*unsafe.Sizeof(Ref{})),
		"head-core": fixedOverhead + 4*uint64(unsafe.Sizeof(HeadCore{})),
		"head":      fixedOverhead + 4*uint64(unsafe.Sizeof(Head{})),
		"lifecycle": fixedOverhead + 4*uint64(unsafe.Sizeof(contract.LifecycleSubject{})),
	}
	entryPage := start(byte(ValueEntryPageKind))
	entryPage.id(fid(1))
	entryPage.id(fid(2))
	entryPage.u16(0)
	entryPage.u16(1)
	recipient := start(byte(RecipientKind))
	recipient.id(fid(1))
	recipient.id(fid(2))
	recipient.u16(0)
	recipient.u8(0)
	recipient.id(fid(3))
	recipient.u8(Current)
	recipient.id(fid(4))
	recipient.u64(1)
	recipient.u16(2)
	root := start(byte(RootKind))
	root.id(fid(1))
	root.id(fid(2))
	root.id(fid(3))
	for i := 0; i < (contract.MaxValueEntryPages + contract.MaxRecipientPages); i++ {
		root.u8(0)
	}
	root.u32(0)
	core := start(coreTag)
	core.u8(1)
	for i := byte(1); i <= 4; i++ {
		core.id(fid(i))
	}
	core.u8(byte(contract.AWS))
	head := start(byte(HeadKind))
	lifecycle, err := contract.LifecycleBytes(headFixture(t).Subject)
	if err != nil {
		t.Fatal(err)
	}
	// Schema 8 removes the Caller and Admission IDs. Prefix widths are
	// unchanged, so each hostile scalar below moves 64 bytes earlier.
	if len(lifecycle) != 715 {
		t.Fatal("independent lifecycle framing changed", len(lifecycle))
	}
	var cases []hostileRecord
	for _, spec := range []struct {
		name   string
		prefix []byte
		decode func([]byte) error
	}{
		{"member", entryPage.b, func(b []byte) error { _, e := DecodeValueEntryPage(b); return e }},
		{"recipient", recipient.b, func(b []byte) error { _, e := DecodeRecipientPage(b); return e }},
		{"root", root.b, func(b []byte) error { _, e := DecodeRoot(b); return e }},
		{"head-core", core.b, func(b []byte) error { _, e := DecodeHeadCore(b); return e }},
		{"head", head.b, func(b []byte) error { _, e := DecodeHead(b); return e }},
	} {
		for _, declared := range []uint32{1 << 20, 1 << 31, ^uint32(0)} {
			body := binary.BigEndian.AppendUint32(bytes.Clone(spec.prefix), declared)
			cases = append(cases, hostileRecord{fmt.Sprintf("%s/%d", spec.name, declared), body, spec.decode, bases[spec.name]})
		}
	}
	for _, field := range []struct {
		name          string
		offset, width int
	}{
		{"identity-plan-length", 223, 8},
		{"head-core-length", 263, 4},
		{"before-count", 299, 4},
		{"after-count", 305, 4},
		{"before-raw", 311, 8},
		{"after-raw", 319, 8},
		{"intent-length", 449, 8},
		{"public-state-length", 489, 8},
		{"union-length", 529, 8},
		{"union-count", 537, 4},
		{"changed-count", 541, 4},
		{"grant-length", 594, 8},
		{"grant-count", 602, 4},
		{"exclusion-length", 659, 8},
		{"exclusion-count", 667, 4},
		{"retirement-length", 703, 8},
		{"retirement-count", 711, 4},
	} {
		body := bytes.Clone(lifecycle)
		for i := 0; i < field.width; i++ {
			body[field.offset+i] = 255
		}
		cases = append(cases, hostileRecord{"lifecycle/" + field.name, body, func(b []byte) error { _, e := DecodeLifecycleSubject(b); return e }, bases["lifecycle"]})
	}
	return cases
}

// full_only: false
func TestHostileDeclaredSizesHaveBoundedAllocation(t *testing.T) {
	for _, tc := range hostileRecords(t) {
		t.Run(tc.name, func(t *testing.T) {
			ceiling := tc.allocationBase + 8*uint64(len(tc.body))
			if err := tc.decode(tc.body); err == nil {
				t.Fatal("hostile declared size accepted")
			}
			const repetitions = 128
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for i := 0; i < repetitions; i++ {
				if tc.decode(tc.body) == nil {
					t.Fatal("hostile declared size accepted")
				}
			}
			runtime.ReadMemStats(&after)
			allocated := (after.TotalAlloc - before.TotalAlloc) / repetitions
			if allocated > ceiling {
				t.Fatalf("allocated %d bytes per decode; schema/input ceiling %d", allocated, ceiling)
			}
		})
	}
}

// full_only: false
func TestHostileDeclaredSizesHaveBoundedWork(t *testing.T) {
	const marker = "ENKV_CODEC_WORK_CHILD"
	if os.Getenv(marker) == "1" {
		for _, tc := range hostileRecords(t) {
			for i := 0; i < 256; i++ {
				if tc.decode(tc.body) == nil {
					t.Fatalf("%s accepted", tc.name)
				}
			}
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// This is a generous termination bound for finite tiny inputs, not a
	// decoder speed threshold. Allocation assertions run in a separate test.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHostileDeclaredSizesHaveBoundedWork$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), marker+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bounded decoder work did not complete and join: %v\n%s", err, output)
	}
}
