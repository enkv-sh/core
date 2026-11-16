package catalog

import (
	"reflect"
	"testing"
)

// These witnesses use reviewed case paths directly. An executable case must
// retain its full identity while selecting the existing action and phases.
// full_only: false
func TestCurrentCatalogAdmitsFullCaseIdentities(t *testing.T) {
	for _, test := range []struct {
		name, mode string
	}{
		{"state.single-value-update-preserves-other-values/members_32", "hermetic"},
		{"capacity.fragmented-state-preserves-complete-update/members_64_fragmented", "hermetic"},
		{"access.normal-combined-k3-current-material/plain1_secret1_exact_successor", "hermetic"},
		{"generated.mixed-apply-selects-complete-set/plain1_supplied1_generated2", "hermetic"},
		{"reconstruction.complete/complete_loss_complete", "hermetic"},
		{"public-configuration.prepare-complete-loss/prepare_complete_loss", "live"},
		{"publication.lost-process/plain1_secret1_reservation_retired_without_send", "hermetic"},
		{"publication.github-repository.plain-secret-lifecycle/plain1_secret1_create_value_inherited_policy_delete", "live"},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, known := Name(test.name)
			if !known || name != test.name {
				t.Errorf("full case identity was not admitted unchanged: %q, known %v", name, known)
			}
			definition, known := DefinitionFor(test.name)
			if !known || definition.Name != test.name {
				t.Errorf("definition lost the full case identity: %q, known %v", definition.Name, known)
			}
			if _, known := ExecutionFor(test.name, test.mode); !known {
				t.Errorf("case has no declared %s execution", test.mode)
			}
			if roles := RolesForScenarios([]string{test.name}, "both"); len(roles) == 0 {
				t.Error("full case has no admitted participants")
			}
		})
	}
}

// full_only: false
func TestCurrentCatalogRejectsGroupExecution(t *testing.T) {
	for _, name := range []string{
		"state.single-value-update-preserves-other-values",
		"capacity.fragmented-state-preserves-complete-update",
		"access.normal-combined-k3-current-material",
		"generated.mixed-apply-selects-complete-set",
		"reconstruction.complete",
		"publication.lost-process",
		"publication.github-repository.plain-secret-lifecycle",
	} {
		t.Run(name, func(t *testing.T) {
			if _, known := Name(name); known {
				t.Error("group remains a current executable identity")
			}
			if _, known := DefinitionFor(name); known {
				t.Error("group remains a current case definition")
			}
			for _, mode := range []string{"hermetic", "live"} {
				if _, known := ExecutionFor(name, mode); known {
					t.Errorf("group still resolves a current %s execution", mode)
				}
			}
			if roles := RolesForScenarios([]string{name}, "both"); roles != nil {
				t.Error("group still admits current participants")
			}
			if _, err := Resolve(Request{Include: []string{name}, Repetitions: 1}); err == nil {
				t.Error("group still creates a current schedule")
			}
		})
	}
}

// full_only: false
func TestCurrentNamedCasesFixTheirFixtureShapes(t *testing.T) {
	for _, test := range []struct {
		name       string
		members    int
		smallBytes int
		largeCount int
		rawBytes   int
		fragmented bool
	}{
		{"state.single-value-update-preserves-other-values/members_1", 1, 1, 0, 1, false},
		{"state.single-value-update-preserves-other-values/members_2", 2, 1, 0, 2, false},
		{"state.single-value-update-preserves-other-values/members_16", 16, 1, 0, 16, false},
		{"state.single-value-update-preserves-other-values/members_32", 32, 1, 0, 32, false},
		{"state.single-value-update-preserves-other-values/members_64", 64, 1, 0, 64, false},
		{"capacity.compact-state-preserves-complete-update/members_64_compact", 64, 4096, 6, 630784, false},
		{"capacity.fragmented-state-preserves-complete-update/members_64_fragmented", 64, 4096, 6, 630784, true},
		{"capacity.maximum-member-count-preserves-complete-update/members_512_mixed_sizes", 512, 4096, 51, 5230592, false},
		{"capacity.maximum-size-state-refuses-growth-and-allows-update/members_512_value_16kib", 512, 16384, 0, 8388608, false},
		{"capacity.maximum-disjoint-replacement-reuses-successor-slots/members_512_names_256bytes_values_128x64kib", 512, 0, 128, 8388608, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkCurrentFixture(t, test.name, test.members, test.smallBytes, test.largeCount, test.rawBytes, test.fragmented)
			definition, known := DefinitionFor(test.name)
			if !known || definition.Fixture.Members != test.members || definition.Fixture.RawValueBytes != test.rawBytes {
				t.Fatal("definition does not describe its named fixed fixture", definition.Fixture)
			}
		})
	}
}

// The current public request and fixture signatures cannot express an override.
// Historical numeric interpretation remains explicit and independently checked.
// full_only: false
func TestCurrentCaseIdentityCannotBeDefinedByNumericOverride(t *testing.T) {
	for _, fixtureAPI := range []any{FixtureShape, FixtureSizes} {
		signature := reflect.TypeOf(fixtureAPI)
		if signature.NumIn() != 1 || signature.IsVariadic() {
			t.Fatal("fixture API accepts more than its fixed case identity")
		}
	}
	if _, exists := reflect.TypeOf(Request{}).FieldByName("Members"); exists {
		t.Error("current request still accepts numeric member selection")
	}
	for _, name := range []string{
		"state.single-value-update-preserves-other-values",
		"state.single-value-update-preserves-other-values/members_0",
		"state.single-value-update-preserves-other-values/members_032",
		"state.single-value-update-preserves-other-values/members_65",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FixtureShape(name); err == nil {
				t.Error("unnamed numeric fixture accepted")
			}
			if _, _, err := FixtureSizes(name); err == nil {
				t.Error("unnamed numeric fixture sizes accepted")
			}
			if _, err := Resolve(Request{Include: []string{name}, Repetitions: 1}); err == nil {
				t.Error("unnamed numeric schedule accepted")
			}
		})
	}
	shape, err := FixtureShape("state.single-value-update-preserves-other-values/members_32")
	if err != nil || shape.Members != 32 {
		t.Fatal("named case did not retain its fixed fixture", shape, err)
	}
	for _, members := range []int{1, 64} {
		historical, err := HistoricalFixtureShape(pointScenario, members)
		if err != nil || historical.Members != members {
			t.Fatal("historical numeric fixture interpretation lost", historical, err)
		}
	}
}

func checkCurrentFixture(t *testing.T, name string, members, smallBytes, largeCount, rawBytes int, fragmented bool) {
	t.Helper()
	shape, err := FixtureShape(name)
	if err != nil {
		t.Fatal(err)
	}
	if shape.Members != members || shape.SmallValueCount != members-largeCount || shape.SmallValueBytes != smallBytes || shape.LargeValueCount != largeCount || shape.RawValueBytes != rawBytes || shape.Fragmented != fragmented || shape.ValueSeed != "member_index_modulo_256" {
		t.Fatalf("fixture %s = %+v", name, shape)
	}
	if largeCount == 0 && shape.LargeValueBytes != nil || largeCount != 0 && (shape.LargeValueBytes == nil || *shape.LargeValueBytes != 65536) {
		t.Fatal("incorrect fixed large value size", shape)
	}
	sizes, gotFragmented, err := FixtureSizes(name)
	if err != nil || len(sizes) != members || gotFragmented != fragmented {
		t.Fatal("fixed fixture sizes differ", len(sizes), gotFragmented, err)
	}
	total := 0
	for i, size := range sizes {
		want := smallBytes
		if i >= members-largeCount {
			want = 65536
		}
		if size != want {
			t.Errorf("member %d size %d, want %d", i, size, want)
		}
		total += size
	}
	if total != rawBytes {
		t.Fatal("fixed fixture body byte count differs", total)
	}
	if len(sizes) > 0 {
		sizes[0] = -1
		fresh, _, err := FixtureSizes(name)
		if err != nil || fresh[0] < 0 {
			t.Fatal("fixed fixture sizes alias earlier output")
		}
	}
}
