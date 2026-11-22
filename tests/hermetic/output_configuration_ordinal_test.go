package core

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Place the single configuration slice inside the full, authenticated receipt
// history. Keep every receipt and the separate generated-index fragment.
func wideOutputReceiptFixture(t *testing.T, f installedApplyTestFixture, at int) *StateSession {
	t.Helper()
	source := f.selected
	store := requireAdmittedMemoryStore(t, f.env.Store)
	current := *source
	current.root.RequiredSupport, current.support = nil, nil
	current.root.Snapshot = fixtureID(f.env.Domain, "wide configuration snapshot")
	current.root.Transition = fixtureID(f.env.Domain, "wide configuration transition")
	var receipts []contract.SupportRecord
	var output contract.SupportRecord
	for _, ref := range source.root.RequiredSupport {
		body, r := source.readObject(t.Context(), ref)
		if r.Outcome != 0 {
			t.Fatal("read original receipt support", r)
		}
		page, err := format.InspectRequiredSupportPage(body)
		if err != nil {
			t.Fatal(err)
		}
		switch page.Records[0].Kind {
		case contract.OutputConfigurationSliceSupportKind:
			if len(page.Records) != 1 || output.Body != nil {
				t.Fatal("expected one independent configuration slice")
			}
			output = contract.SupportRecord(page.Records[0])
		case contract.MutationReceiptSupportKind:
			for _, row := range page.Records {
				if row.Kind != contract.MutationReceiptSupportKind {
					t.Fatal("unexpected row in receipt history")
				}
				receipts = append(receipts, contract.SupportRecord(row))
			}
		default:
			current.root.RequiredSupport = append(current.root.RequiredSupport, ref)
			current.support = append(current.support, page)
		}
	}
	if len(receipts) != 2*contract.MutationReceiptWindowLimit || output.Body == nil {
		t.Fatal("missing complete receipt history or configuration")
	}
	refIndex := generatedFixtureFreeSupportIndex(t, &current)
	mixed := format.RequiredSupportPage{Domain: f.env.Domain, Object: fixtureID(f.env.Domain, "wide mixed page"), Index: refIndex, Records: slices.Insert(receipts, at, output)}
	body, err := format.EncodeRequiredSupportPage(mixed)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := format.Reference(contract.RequiredSupportKind, f.env.Domain, mixed.Object, mixed.Index, body)
	if err != nil {
		t.Fatal(err)
	}
	page, err := format.InspectRequiredSupportPage(body)
	if err != nil {
		t.Fatal(err)
	}
	current.support = append(current.support, page)
	current.root.RequiredSupport = append(current.root.RequiredSupport, ref)
	slices.SortFunc(current.support, func(a, b format.RequiredSupportPageView) int { return int(a.Index) - int(b.Index) })
	slices.SortFunc(current.root.RequiredSupport, func(a, b format.Ref) int { return int(a.Index) - int(b.Index) })
	put := func(ref format.Ref, body []byte) {
		if err := store.putSelected(mustKey(t, store.desc.Prefix, ref), body); err != nil {
			t.Fatal(err)
		}
	}
	put(ref, body)
	for _, object := range installReceiptFixtureAdministrativeIndex(t, &current) {
		put(object.ref, object.body)
	}
	_, cold := writeSignedCurrentIntentImage(t, f.env, source, source, &current, store, "wide output", put)
	position, found := cold.selectedSupportPosition(ref)
	if !found || len(cold.supportFacts[position].rows) != len(mixed.Records) ||
		cold.supportFacts[position].rows[at].RecordID() != output.RecordID ||
		int(cold.supportFacts[position].ordinals[at]) != at || cold.support[position].Records[at].Body != nil {
		t.Fatal("cold reader did not authenticate the intended configuration ordinal", at)
	}
	return cold
}

// full_only: false
func TestInstalledApplyReadsWideOutputOrdinal(t *testing.T) {
	for _, at := range []int{255, 256, 2 * contract.MutationReceiptWindowLimit} {
		for _, mode := range []string{"ordinary", "generated"} {
			t.Run(fmt.Sprintf("%s/%d", mode, at), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
				defer cancel()
				f, _ := installedApplyFullWindows(t, ctx)
				selected := wideOutputReceiptFixture(t, f, at)
				input := []ApplyEntryInput{{Name: "alpha", InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Recipients: []contract.ID{selected.admission.recipient},
					ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("after")}}
				var engine *InstalledApply
				if mode == "generated" {
					process, _ := installedGeneratedRetirementProcess(t, "acknowledged")
					f.env.GeneratedProcess = process
					input = installedGeneratedRetirementEntries(process, selected.admission.recipient, 0, "after")
					engine = installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), installedGeneratedRetirementCallbacks(t, f, process))
				} else {
					engine = f.engine(t, selected, input, nil)
				}
				defer engine.Close()
				result := engine.Apply(ctx, fixtureID(f.env.Domain, "wide apply"), input)
				if result.Result.Outcome != ObservedCurrent || len(result.Receipt) == 0 {
					t.Fatal("apply from wide mixed page", result.Result)
				}
				cold := f.open(t, ctx)
				if cold.root.OutputConfiguration != selected.root.OutputConfiguration || cold.root.Snapshot == selected.root.Snapshot ||
					!cold.root.Generated.ActiveOwner.IsZero() || (cold.root.Generated.GeneratedCurrent == 1) != (mode == "generated") {
					t.Fatal("cold successor lost configuration or selected value")
				}
			})
		}
	}
}
