package crypto

import (
	"bytes"
	"errors"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestInstalledGeneratedReservationChecksCommittedOutputBeforeQualification(t *testing.T) {
	for _, condition := range []string{"exact", "digest", "length", "different-group", "unknown-entry"} {
		t.Run(condition, func(t *testing.T) {
			f, input, construction, qualifier := generatedInstalledRegistryFixture(t)
			// This fixture starts with an empty value plan. Add a real, valid
			// declared plain entry so group damage changes known meaning rather
			// than indexing an absent row or testing an unknown-name refusal.
			member := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
				Name: "group-member", Recipients: []contract.ID{f.base.control.AuthorityRecipientID}, Payload: []byte("group source")}
			memberID := consumerID("committed group member incarnation")
			generatedAddDeclarationSource(t, &f, member, contract.GeneratorValueEntryPlan{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorValueEntryPlanSchema, Slot: 3,
				Name: member.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				EntryIncarnationID: memberID, ChangeMask: contract.GeneratorValueChangeContent})
			input.Plan.Declaration = f.declaration
			graph, err := contract.DecodeGeneratorPlanBundle(f.graph)
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := input.Session.Output.ConfigurationAfter(graph.Header.OperationID, graph.ValueEntryPlans)
			if err != nil {
				t.Fatal(err)
			}
			image, err := contract.EncodeOutputConfiguration(configuration)
			if err != nil {
				t.Fatal(err)
			}
			graph.Request.Schema = contract.GeneratorApplyRequestCoreSchema
			graph.Request.OutputConfiguration, _, err = contract.SplitOutputConfiguration(graph.Header.DomainID, image)
			if err != nil {
				t.Fatal(err)
			}
			switch condition {
			case "digest":
				graph.Request.OutputConfiguration.ConfigurationDigest = consumerID("other desired output image")
			case "length":
				graph.Request.OutputConfiguration.TotalLength++
			case "different-group":
				input.Session.Output.Groups = [][]string{{member.Name}}
				changed, groupErr := input.Session.Output.ConfigurationAfter(graph.Header.OperationID, graph.ValueEntryPlans)
				if groupErr != nil || len(changed.Groups) != 1 || len(changed.Groups[0]) != 1 || changed.Groups[0][0] != memberID {
					t.Fatal("group damage did not make a valid independent declared group", groupErr)
				}
				changedImage, groupErr := contract.EncodeOutputConfiguration(changed)
				if groupErr != nil || bytes.Equal(changedImage, image) {
					t.Fatal("group damage did not change the complete canonical image", groupErr)
				}
			case "unknown-entry":
				input.Session.Output.Groups = [][]string{{"absent"}}
			}
			graph.Header.RequestCoreDigest, err = contract.GeneratorRequestCoreDigest(graph.Request)
			if err != nil {
				t.Fatal(err)
			}
			graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(graph.Header, graph.ValueEntryPlans, graph.Lineages, graph.Edges)
			if err != nil {
				t.Fatal(err)
			}
			f.graph, err = contract.EncodeGeneratorPlanBundle(graph)
			if err != nil {
				t.Fatal(err)
			}
			f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(graph)
			if err != nil {
				t.Fatal(err)
			}
			f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(graph.UsePlan)
			if err != nil {
				t.Fatal(err)
			}
			parent := &f.compare.ParentPlan
			parent.Registry, parent.RequestCoreDigest, parent.PlanGraphID, parent.UsePlanDigest, parent.Graph = graph.Request.Registry, graph.Header.RequestCoreDigest, graph.UsePlan.PlanGraphID, f.compare.UsePlanDigest, f.compare.PlanGraph
			f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			input.Session.Graph = f.graph
			runtime := newConsumerRuntime(t, f.base.route)
			owner, err := NewGeneratedReservationCustody(runtime, f.compare, f.base.control, construction, input, f.base.deadline)
			if condition != "exact" {
				if owner != nil {
					owner.Close()
				}
				if owner != nil || !errors.Is(err, ErrAdmission) || qualifier.calls != 0 {
					t.Fatal("inconsistent desired output crossed independent custody admission", err, qualifier.calls)
				}
				return
			}
			if err != nil || owner == nil {
				t.Fatal("exact committed output refused", err)
			}
			defer owner.Close()
			if result := installedGeneratedTestCompare(t, owner, f); result.ResultCode != contract.CryptoSuccess || qualifier.calls != 1 {
				t.Fatal("exact output control did not qualify its intended key", result.ResultCode, qualifier.calls)
			}
		})
	}
}

// full_only: false
func TestGeneratedOutputCarrierChecksWholeImageAndExactOwner(t *testing.T) {
	domain, snapshot, operation := consumerID("output domain"), consumerID("output snapshot"), consumerID("output operation")
	image := bytes.Repeat([]byte{0x61}, 1048321)
	blob := contract.Hash(image)
	var fragments []contract.SupportRecord
	for index, start := range []int{0, 1048320} {
		body, err := contract.EncodeGeneratedFragment(contract.GeneratedFragment{Schema: 1, BlobID: blob, WholeDigest: blob, Index: uint16(index), Count: 2, TotalLength: 1048321, Offset: uint32(start), Payload: image[start:min(start+1048320, len(image))]})
		if err != nil {
			t.Fatal(err)
		}
		id, err := contract.GeneratorFragmentID(blob, uint16(index))
		if err != nil {
			t.Fatal(err)
		}
		fragments = append(fragments, contract.SupportRecord{Kind: contract.GeneratedFragmentSupportKind, RecordID: id, Body: body})
	}
	for _, condition := range []string{"exact", "missing", "duplicate", "other-operation", "later-fragment"} {
		t.Run(condition, func(t *testing.T) {
			location := contract.GeneratorSliceLocation{Schema: 1, ContentKind: contract.GeneratorContentOutputConfiguration, ContentID: operation, BlobID: blob, Length: 1048321, Digest: blob}
			if condition == "other-operation" {
				location.ContentID = consumerID("other output operation")
			}
			body, err := contract.EncodeGeneratorSliceLocation(location)
			if err != nil {
				t.Fatal(err)
			}
			rows := append([]contract.SupportRecord(nil), fragments...)
			carriers := generatedVectorSupport(t, domain, contract.GeneratorSnapshotOwner, snapshot, contract.GeneratorVectorSlices, [][]byte{body})
			if condition != "missing" {
				rows = append(rows, carriers...)
			}
			if condition == "duplicate" {
				rows = append(rows, carriers...)
			}
			if condition == "later-fragment" {
				rows[1].Body = bytes.Clone(rows[1].Body)
				rows[1].Body[len(rows[1].Body)-1] ^= 1
			}
			matched := generatedCandidateContentMatches(rows, domain, snapshot, contract.GeneratorContentOutputConfiguration, operation, contract.DigestLength{Digest: blob, Length: 1048321}, image, true)
			if matched != (condition == "exact") {
				t.Fatal("output carrier lost complete bytes, unique mapping or exact operation", condition, matched)
			}
			if condition == "exact" && generatedCandidateContentMatches(rows, domain, snapshot, contract.GeneratorContentOutputConfiguration, operation, contract.DigestLength{Digest: blob, Length: 1048321}, image, false) {
				t.Fatal("closed parent retained its desired output carrier")
			}
		})
	}
}
