package core

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func assertReconstructionJointMaximum(t *testing.T, env fixtureEnvironment, selected *StateSession, store *memoryStore) {
	t.Helper()
	if selected.root.Generated.GeneratedCurrent != 128 || selected.root.SecretCount != 128 || selected.root.ValueEntryCount != 129 || selected.root.OutputConfiguration.TotalLength != 36<<20 || selected.root.OutputConfiguration.SliceCount != 37 || len(selected.adminIndex.PublicationOrder) != 1024 {
		t.Fatal("joint reconstruction dimensions", selected.root.Generated, selected.root.OutputConfiguration, len(selected.adminIndex.PublicationOrder))
	}
	env.Custody.SetDenied(env.Custody.RecoveryID(), true)
	defer env.Custody.SetDenied(env.Custody.RecoveryID(), false)
	for _, row := range env.Bindings {
		if row.SubjectID != selected.admission.recipient {
			env.Custody.SetDenied(row.SubjectID, true)
			defer env.Custody.SetDenied(row.SubjectID, false)
		}
	}
	beforePublic, beforePrivate := env.Custody.Calls()
	beforeWindows, beforeBodies, err := selected.retainedMutationReceiptBodies()
	if err != nil {
		t.Fatal("joint reconstruction retained receipt baseline", err)
	}
	originalBodies := make(map[contract.ID][]byte, len(beforeBodies))
	for id, body := range beforeBodies {
		originalBodies[id] = bytes.Clone(body)
	}
	projection := reconstructProjectionFixture(t, env, selected, store)
	afterPublic, afterPrivate := env.Custody.Calls()
	if afterPublic != beforePublic || afterPrivate != beforePrivate+128 {
		t.Fatal("joint reconstruction did not verify every current secret", afterPublic-beforePublic, afterPrivate-beforePrivate)
	}
	assertReconstructionProjectionExact(t, projection, selected, store)
	returned := reconstructedReceiptHistorySession(t, projection, selected)
	afterWindows, err := returned.receiptWindows(t.Context())
	domainEqual := afterWindows.DomainID == beforeWindows.DomainID
	successesEqual := slices.Equal(afterWindows.Successes, beforeWindows.Successes)
	failuresEqual := slices.Equal(afterWindows.Failures, beforeWindows.Failures)
	orderEqual := slices.Equal(afterWindows.Order, beforeWindows.Order)
	if err != nil || !domainEqual || !successesEqual || !failuresEqual || !orderEqual {
		t.Fatal("joint reconstruction changed exact retained receipt windows or common order", err,
			"domain_equal", domainEqual, "successes_equal", successesEqual, "failures_equal", failuresEqual, "order_equal", orderEqual,
			"before_lengths", [3]int{len(beforeWindows.Successes), len(beforeWindows.Failures), len(beforeWindows.Order)},
			"after_lengths", [3]int{len(afterWindows.Successes), len(afterWindows.Failures), len(afterWindows.Order)})
	}
	assertRetainedReceiptBytes(t, returned, originalBodies)
	assertReconstructionReturnedIntents(t, returned, 128, 48<<20)
	for _, named := range returned.root.Names {
		entry := returned.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		choice := sessionConsumerSelection(t, returned, returned.admission.recipient, named.Name)
		if check := env.Custody.Consume(t.Context(), choice, custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
			t.Fatal("returned maximum private content", named.Name, check)
		}
	}
	projection.Close()
	if projection.PartCount() != 0 {
		t.Fatal("maximum projection retained buffers after Close")
	}
}

// full_only: false
func TestReconstructionProjectionCheckedBounds(t *testing.T) {
	ctx, cancel, selected, _ := selectedProjectionFixture(t)
	defer cancel()
	validChildEncodedBytes := selected.image.root.ChildEncodedBytes
	selected.image.root.ChildEncodedBytes = math.MaxUint64
	if owner, result := beginReconstructionProjection(&selected); owner != nil || result != failure(IntegrityFailure, InvalidRelation) {
		t.Fatal("wrapped observation sum accepted", result)
	}
	selected.image.root.ChildEncodedBytes = validChildEncodedBytes
	selected.image.root.RequiredSupportRecordCount++
	if owner, result := beginReconstructionProjection(&selected); owner != nil || result != failure(IntegrityFailure, InvalidRelation) {
		t.Fatal("unequal selected row count accepted", result)
	}
	for _, tc := range []struct {
		name  string
		limit uint64
		body  int
		want  Outcome
	}{{"exact byte limit", 4, 4, 0}, {"one byte overflow", 3, 4, AdmissionRefused}, {"empty part", 4, 0, AdmissionRefused}} {
		t.Run(tc.name, func(t *testing.T) {
			owner := &reconstructionProjectionAttempt{anchor: selected.basis.anchor, partLimit: 1, byteLimit: tc.limit}
			defer owner.Abort()
			result := owner.Accept(ctx, reconstructionProjectionPart{kind: reconstructionHEADPart, body: make([]byte, tc.body)})
			if result.Outcome != tc.want {
				t.Fatal("byte boundary", result)
			}
		})
	}
}

// full_only: true
func TestReconstructionMaximumRegistryMembershipAndRawSet(t *testing.T) {
	env, run, f, _, _ := successionMemoryRegistryFixture(t, true)
	recipients := capacityRecipients(t, f.session, 8)
	input := make([]ApplyEntryInput, contract.CryptoMaxValueEntries)
	for i := range input {
		input[i] = ApplyEntryInput{Name: "n" + strings.Repeat("界", 84) + fmt.Sprintf("%03d", i), Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: bytes.Repeat([]byte{byte(i)}, 16<<10), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
	}
	run.suppliedSelection(f, input)
	selected, store := f.session, env.Store.(*memoryStore)
	if selected.root.ValueEntryCount != 512 || selected.root.MembershipCount != 4096 || selected.root.RawBytes != 8<<20 {
		t.Fatal("maximum legal field dimensions")
	}
	projection := reconstructProjectionFixture(t, env, selected, store)
	assertReconstructionProjectionExact(t, projection, selected, store)
	returned := reconstructionReturnedSession(t, projection, selected)
	if !reflect.DeepEqual(returned.recipients, selected.recipients) {
		t.Fatal("maximum complete registry rows changed")
	}
	rows := 0
	for _, page := range returned.recipients {
		if page != nil {
			for _, row := range page.Slots {
				if row != nil {
					if len(row.DisplayName) != contract.CryptoMaxName || row.CurrentBinding == nil || len(row.CurrentBinding.KeySelector) != contract.MaxKeySelector {
						t.Fatal("maximum populated registry dimensions")
					}
					rows++
				}
			}
		}
	}
	if rows != 256 {
		t.Fatal("maximum complete registry rows", rows)
	}
	for _, want := range input {
		got := returned.valueEntry(namedSlot(t, returned, want.Name))
		if got == nil || len(got.Name) != 256 || !bytes.Equal(got.ValueBytes, want.InputBytes) {
			t.Fatal("maximum names/raw values changed")
		}
	}
}

func assertReconstructionReturnedIntents(t *testing.T, returned *StateSession, expectedCount int, expectedLength uint64) {
	t.Helper()
	assertReconstructionReturnedIntentBytes(t, returned, expectedCount, expectedLength, func(name string) []byte {
		return capacityIntentBytes(t, name)
	})
}

func assertReconstructionReturnedIntentBytes(t *testing.T, returned *StateSession, expectedCount int, expectedLength uint64, expectedIntent func(string) []byte) {
	t.Helper()
	fragments := map[contract.ID][]contract.GeneratedFragmentView{}
	locations := map[contract.ID]contract.GeneratorSliceLocation{}
	for _, page := range returned.support {
		for _, row := range page.Records {
			switch row.Kind {
			case contract.GeneratedFragmentSupportKind:
				fragment, err := contract.InspectGeneratedFragment(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				fragments[fragment.BlobID] = append(fragments[fragment.BlobID], fragment)
			case contract.GeneratorVectorSupportKind:
				carrier, err := contract.InspectGeneratorVectorCarrier(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if carrier.VectorKind != contract.GeneratorVectorSlices {
					continue
				}
				location, err := contract.InspectGeneratorSliceLocation(carrier.Row)
				if err != nil {
					t.Fatal(err)
				}
				if location.ContentKind == contract.GeneratorContentIntent {
					locations[location.ContentID] = location
				}
			}
		}
	}
	total := uint64(0)
	current := 0
	for _, named := range returned.root.Names {
		entry := returned.valueEntry(named.Slot)
		if entry.ValueSource != contract.Generated {
			continue
		}
		location, ok := locations[entry.Generated.IntentDigest]
		expected := expectedIntent(named.Name)
		if len(expected) == 0 {
			t.Fatal("unexpected returned generated name", named.Name)
		}
		if !ok || location.Length != uint32(len(expected)) || location.Digest != contract.Hash(expected) {
			t.Fatal("returned exact Intent location", named.Name)
		}
		rows := fragments[location.BlobID]
		slices.SortFunc(rows, func(a, b contract.GeneratedFragmentView) int {
			if a.Offset < b.Offset {
				return -1
			}
			if a.Offset > b.Offset {
				return 1
			}
			return 0
		})
		cursor, end := location.Offset, location.Offset+uint64(location.Length)
		for _, fragment := range rows {
			first := max(cursor, uint64(fragment.Offset))
			last := min(end, uint64(fragment.Offset)+uint64(len(fragment.Payload)))
			if first >= last {
				continue
			}
			if first != cursor || !bytes.Equal(fragment.Payload[first-uint64(fragment.Offset):last-uint64(fragment.Offset)], expected[first-location.Offset:last-location.Offset]) {
				t.Fatal("returned exact normalized Intent bytes", named.Name)
			}
			cursor = last
		}
		if cursor != end {
			t.Fatal("returned Intent incomplete", named.Name)
		}
		current++
		total += uint64(location.Length)
	}
	if current != expectedCount || total != expectedLength {
		t.Fatal("returned current Intent set", current, total)
	}
}
