package contract

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestGeneratorAttemptIdentityVectors(t *testing.T) {
	// SHA-256 of the documented domain label, u32(33), 32 bytes of
	// 0x22 and the branch byte. Expected values use no product encoder.
	lineage := ID(bytes.Repeat([]byte{0x22}, 32))
	want := []string{
		"56860e17babebab321cc7cd7ff78a6d26db82bd2d56d7c4dc6587b2550f96a2c",
		"0db16a23ca25bc7e79e4a0aca9b64dae934f8e8d39437fc3a6b5e8d63ca02267",
		"62ec0389614990274583a4a9127d2054ed8c3452328801cca5e33488f63cd01d",
		"a3e5834daa3f7bd9f77ca5ee58aa9d940acf0aadc92cd7860f0ea4b33e2dc0a1",
		"14f6a11ff0d6561827199e46fd81b44ce10ba33366dab46c4e800b1fe3f5968d",
	}
	for branch, encoded := range want {
		got, err := GeneratorAttemptID(lineage, uint8(branch))
		if err != nil || hex.EncodeToString(got[:]) != encoded {
			t.Fatalf("branch %d: %x, %v", branch, got, err)
		}
	}
	for _, branch := range []uint8{5, 255} {
		if _, err := GeneratorAttemptID(lineage, branch); err == nil {
			t.Fatalf("accepted branch %d", branch)
		}
	}
	if _, err := GeneratorAttemptID(ID{}, 0); err == nil {
		t.Fatal("accepted missing lineage")
	}
}

// full_only: false
func TestGeneratorOriginalResultIdentityVectors(t *testing.T) {
	domain, operation := ID(bytes.Repeat([]byte{0x11}, 32)), ID(bytes.Repeat([]byte{0x33}, 32))
	lineage := ID(bytes.Repeat([]byte{0x22}, 32))
	attempt, err := GeneratorAttemptID(lineage, 0)
	if err != nil {
		t.Fatal(err)
	}
	transmission, err := GeneratorTransmissionID(attempt, 1)
	if err != nil || hex.EncodeToString(transmission[:]) != "86fdadf21c6364fc271b43455f18dd2730e28c375c8a8e7905f834a403861c6c" {
		t.Fatalf("transmission: %x, %v", transmission, err)
	}
	result, err := GeneratorResultID(domain, operation, attempt, transmission, 1)
	if err != nil || hex.EncodeToString(result[:]) != "df69c448a22b0ae73d603be124dc8533bbf03c00ea34ae09fd057ef87b129250" {
		t.Fatalf("result: %x, %v", result, err)
	}
	inbox, err := GeneratorInboxID(domain, operation, attempt, result)
	if err != nil || hex.EncodeToString(inbox[:]) != "d89ad7d708f5236fd342f645a20e8aca153370a5b585deb0635083a63a60d6bb" {
		t.Fatalf("inbox: %x, %v", inbox, err)
	}
	successor, err := GeneratorAttemptID(lineage, 2)
	if err != nil {
		t.Fatal(err)
	}
	other, err := GeneratorInboxID(domain, operation, successor, result)
	if err != nil || other == inbox {
		t.Fatal("successor reused the original inbox")
	}
	if _, err := GeneratorTransmissionID(attempt, 3); err == nil {
		t.Fatal("accepted an unknown interaction")
	}
}

// full_only: false
func TestGeneratorBranchBudgets(t *testing.T) {
	for _, order := range [][]uint8{{1, 2}, {2, 1}} {
		branch := uint8(0)
		for _, gate := range order {
			next, present, err := GeneratorSuccessorBranch(branch, gate)
			if err != nil || !present || next == branch {
				t.Fatalf("branch %d gate %d: %d, %t, %v", branch, gate, next, present, err)
			}
			branch = next
		}
		for _, gate := range []uint8{1, 2} {
			if _, present, err := GeneratorSuccessorBranch(branch, gate); err != nil || present {
				t.Fatalf("exhausted branch %d gate %d: %t, %v", branch, gate, present, err)
			}
		}
	}
	for _, item := range [][2]uint8{{1, 1}, {2, 2}} {
		if _, present, err := GeneratorSuccessorBranch(item[0], item[1]); err != nil || present {
			t.Fatalf("reused allowance %v", item)
		}
	}
	for _, item := range [][2]uint8{{5, 1}, {0, 0}, {0, 3}} {
		if _, _, err := GeneratorSuccessorBranch(item[0], item[1]); err == nil {
			t.Fatalf("accepted invalid branch/gate %v", item)
		}
	}
}

// full_only: false
func TestGeneratorLineagePreservesMemberNameRules(t *testing.T) {
	id := ID{1}
	for _, name := range []string{"", "a", string(bytes.Repeat([]byte{'x'}, 256))} {
		first, err := GeneratorLineageID(id, id, name, id, 0, id)
		if err != nil || first.IsZero() {
			t.Fatalf("name length %d: %v", len(name), err)
		}
		second, err := GeneratorLineageID(id, id, name, id, 1, id)
		if err != nil || first == second {
			t.Fatal("generation epoch did not change lineage")
		}
	}
	for _, name := range []string{string([]byte{0xff}), string(bytes.Repeat([]byte{'x'}, 257))} {
		if _, err := GeneratorLineageID(id, id, name, id, 0, id); err == nil {
			t.Fatal("accepted invalid member name")
		}
	}
}

// full_only: false
func TestGeneratedRetirementAmbiguityCoordinate(t *testing.T) {
	// Independent SHA-256 over the NUL-terminated label, big-endian u32(32)
	// and 32 bytes of 0x44.
	inbox := ID(bytes.Repeat([]byte{0x44}, 32))
	got, err := GeneratorRetirementAmbiguityID(inbox)
	if err != nil || hex.EncodeToString(got[:]) != "8078a84de6ce3af9b3beef1e2c813db521bc720e853c1a5fdd08d36e23a7ecc8" || got == inbox {
		t.Fatal("retirement evidence coordinate", got, err)
	}
	if _, err := GeneratorRetirementAmbiguityID(ID{}); err == nil {
		t.Fatal("accepted missing original inbox")
	}
}
