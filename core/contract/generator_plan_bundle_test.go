package contract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

// full_only: false
func TestGeneratorBundleIndependentEmptyCarrier(t *testing.T) {
	// Independent Python SHA256 over literal field concatenation: schema3,
	// B(request348), B(header168), five uint32be(0) vectors, B(use-plan248).
	// Request IDs1/2/5..8, descriptors9/10 with length4/count0, IDs11/12;
	// material, graph, use descriptors and meaning use their specified D labels.
	v := generatorBundleFixture(t, false)
	body, err := EncodeGeneratorPlanBundle(v)
	if err != nil || len(body) != 798 || fmt.Sprintf("%x", Hash(body)) != "8e9e3bd5ed0a6f28085708f75596d3cf745defefd0f466e359215dbca8c8b59f" {
		t.Fatal("independent bundle bytes", len(body), err)
	}
	descriptor, err := GeneratorPlanBundleDescriptor(v)
	if err != nil || descriptor.Length != 806 || descriptor.Count != 1 || fmt.Sprintf("%x", descriptor.Digest) != "0cbbbfe87f09daf374ffa800407a5afe0c6c77f1d4ed6cf6eaec23d6953eb2ac" {
		t.Fatal("independent bundle descriptor", err)
	}
}

func generatorBundleFixture(t testing.TB, populated bool) GeneratorPlanBundle {
	t.Helper()
	var v GeneratorPlanBundle
	v.Request = generatorGraphRequestFixture()
	if populated {
		v.Header = generatorGraphHeaderFixture(t, 1, 1, 5)
		v.Lineages = []GeneratorLineageTemplate{generatorGraphCreateFixture(t, "generated")}
		v.ValueEntryPlans = []GeneratorValueEntryPlan{generatorGraphEntryPlanFixture(v.Lineages[0], 0)}
	} else {
		v.Header = generatorGraphHeaderFixture(t, 0, 0, 0)
	}
	v.Edges = generatorGraphEdgesFixture(t, v.Header, v.Lineages)
	v.ResultUses = generatorGraphUsesFixture(v.Header, v.Lineages)
	graph, err := GeneratorGraphID(v.Header, v.ValueEntryPlans, v.Lineages, v.Edges)
	if err != nil {
		t.Fatal(err)
	}
	uses, err := GeneratorResultUsesDescriptor(v.ResultUses)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := GeneratorSourceUsesDescriptor(nil)
	if err != nil {
		t.Fatal(err)
	}
	v.UsePlan = GeneratorUsePlanCore{DomainID: v.Header.DomainID, OperationID: v.Header.OperationID, MaterialID: v.Header.MaterialID,
		PlanGraphID: graph, ResultUses: uses, SourceUses: sources, ValueDerivationID: GeneratorValueDerivationID()}
	return v
}

// full_only: false
func TestGeneratorBundleCompleteOwnershipAndDamage(t *testing.T) {
	for _, populated := range []bool{false, true} {
		v := generatorBundleFixture(t, populated)
		body, err := EncodeGeneratorPlanBundle(v)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := DecodeGeneratorPlanBundle(body)
		if err != nil {
			t.Fatal(err)
		}
		reencoded, err := EncodeGeneratorPlanBundle(owned)
		if err != nil || !bytes.Equal(reencoded, body) {
			t.Fatal("bundle traversal", err)
		}
		for n := range body {
			if _, err := DecodeGeneratorPlanBundle(body[:n]); err == nil {
				t.Fatal("accepted incomplete bundle", n)
			}
		}
		for _, offset := range []int{1, 2, 6, 356, 360, 528} {
			bad := bytes.Clone(body)
			bad[offset] ^= 1
			if _, err := DecodeGeneratorPlanBundle(bad); err == nil {
				t.Fatal("accepted changed field", offset)
			}
		}
		bad := bytes.Clone(body)
		binary.BigEndian.PutUint32(bad[526:530], ^uint32(0))
		if _, err := DecodeGeneratorPlanBundle(bad); err == nil {
			t.Fatal("accepted excessive row count")
		}
		if _, err := DecodeGeneratorPlanBundle(append(bytes.Clone(body), 0)); err == nil {
			t.Fatal("accepted trailing field")
		}
		clear(body)
		after, err := DecodeGeneratorPlanBundle(reencoded)
		if err != nil || !reflect.DeepEqual(after, owned) {
			t.Fatal("bundle retained borrowed bytes", err)
		}
	}
}

// full_only: false
func TestGeneratorResultInputEncodingUsesOwningCreateLineage(t *testing.T) {
	for _, encoding := range []uint8{InputEncodingRaw, InputEncodingBase64} {
		v := generatorBundleFixture(t, true)
		v.ValueEntryPlans[0].InputEncoding = encoding
		lineage := v.Lineages[0]
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			t.Run(fmt.Sprintf("class%d/branch%d", encoding, template.Branch), func(t *testing.T) {
				actual, err := GeneratorResultInputEncoding(v, template)
				if err != nil || actual != encoding {
					t.Fatal("create branch lost owning input class", actual, err)
				}
			})
		}
		original := lineage.Templates[0]
		for _, field := range []string{"lineage", "slot", "class"} {
			t.Run(fmt.Sprintf("class%d/wrong %s", encoding, field), func(t *testing.T) {
				changed := original
				graph := v
				graph.ValueEntryPlans = append([]GeneratorValueEntryPlan(nil), v.ValueEntryPlans...)
				switch field {
				case "lineage":
					changed.LineageID[0] ^= 1
				case "slot":
					changed.PlannedValueSlotID[0] ^= 1
				case "class":
					graph.ValueEntryPlans[0].InputEncoding = 0
				}
				if _, err := GeneratorResultInputEncoding(graph, changed); err == nil {
					t.Fatal("different create owner supplied input class")
				}
			})
		}
		original.Action = GeneratorActionDelete
		if actual, err := GeneratorResultInputEncoding(v, original); err != nil || actual != InputEncodingRaw {
			t.Fatal("delete did not use fixed raw class", actual, err)
		}
	}
}
