package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestInstalledGeneratedRetirementKeepsMixedCurrentValues(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
	author := buildInstalledLocalAuthor(t, false)
	f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
	f.env.GeneratedProcess = process
	member := f.selected.admission.recipient
	remote := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleManaged, ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(), RetirementMode: contract.GeneratedRetirementManual, CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
	local := &contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema, LifecycleMode: contract.GeneratorLifecycleNone, ConfigContractID: author.config.Artifact.ConfigContractID, ResourceContractID: contract.ID{}, Intent: installedLocalCanonicalIntent()}
	input := []ApplyEntryInput{
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{member}, Generated: remote},
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "local", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret, Recipients: []contract.ID{member}, Generated: local},
		{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{member}, InputBytes: []byte("unchanged plain sibling")},
		suppliedSecret(t, f.env, "supplied", "retirement supplied sibling", custody.StandardValue, member),
	}
	admissions := 0
	selected := f.selected
	for epoch := uint64(0); epoch < 2; epoch++ {
		remote.Epoch = epoch
		if epoch != 0 {
			_, supplied := observeCurrentValueEntry(t, selected, "supplied")
			input[3].InputBytes = nil
			input[3].Retained = &contract.RetainedSecretInput{Incarnation: supplied.Incarnation, Material: supplied.ValueState}
		}
		engine := installedLocalEngine(t, ctx, f, selected, input, author, &admissions)
		result := engine.Apply(ctx, fixtureID(f.env.Domain, []string{"mixed retirement generation zero", "mixed retirement generation one"}[epoch]), input)
		engine.Close()
		if result.Result.Outcome != ObservedCurrent {
			t.Fatal("mixed actual generation failed", epoch, result.Result)
		}
		selected = f.open(t, ctx)
	}
	_, current := observeCurrentValueEntry(t, selected, "")
	if current.ValueSource != contract.Generated || current.Generated.Schema != contract.GeneratedEntryMetadataSchema || current.Generated.RetiringDutyPresent != 1 {
		t.Fatal("empty-name original Duty absent")
	}
	before := make(map[string]contract.ValueEntry, len(selected.root.Names))
	for _, named := range selected.root.Names {
		v := *selected.valueEntry(named.Slot)
		v.ValueBytes = bytes.Clone(v.ValueBytes)
		v.Recipients = append([]contract.ID(nil), v.Recipients...)
		before[named.Name] = v
	}
	localBefore := captureInstalledLocalValue(t, ctx, f, selected, "local")
	engine := installedLocalEngine(t, ctx, f, selected, input, author, &admissions)
	work, err := selected.selectedGeneratedWork(ctx)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	plan, err := selected.installedGeneratedRetirementPlan(ctx, engine.installation, work, current.Generated.RetiringDutyID, testID("private retirement proposal nonce"), deadline)
	if err != nil {
		t.Fatal("installed retirement plan refused current mixed set", err)
	}
	graph := plan.input.graph
	if graph.Header.Schema != contract.GeneratorGraphHeaderSchema || graph.Header.LineageCount != 0 || graph.Header.TemplateCount != 1 || len(graph.Lineages) != 1 || graph.Lineages[0].Schema != contract.GeneratorLineageTemplateSchema {
		t.Fatal("fresh retirement graph framing differs")
	}
	x := graph.Lineages[0].Templates[0]
	if x.Schema != contract.GeneratorAttemptTemplateSchema || x.LifecycleMode != contract.GeneratorLifecycleManaged || x.ResultReaderID != contract.GeneratorResultReaderID() || x.ExecutorID != process.Implementation.ExecutorID || x.CredentialRouteID != process.Implementation.CredentialRouteID || x.Action != contract.GeneratorActionDelete || x.DutyID != current.Generated.RetiringDutyID {
		t.Fatal("fresh delete changed exact current implementation")
	}
	encoded, err := contract.EncodeGeneratorPlanBundle(graph)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contract.DecodeGeneratorPlanBundle(encoded)
	if err != nil || decoded.Header != graph.Header || decoded.UsePlan != graph.UsePlan || len(decoded.Lineages) != 1 || decoded.Lineages[0] != graph.Lineages[0] || len(decoded.ValueEntryPlans) != 4 || len(decoded.SourceUses) != 0 || len(decoded.ResultUses) != 1 || len(decoded.Edges) != 2 {
		t.Fatal("current retirement bundle changed on cold decode", err)
	}
	result := engine.RetireGenerated(ctx, fixtureID(f.env.Domain, "mixed empty-name retirement"), GeneratedRetirementRequest{DutyID: current.Generated.RetiringDutyID})
	engine.Close()
	creates, deletes := effects()
	if result.Result.Outcome != ObservedCurrent || creates != 2 || !reflect.DeepEqual(deletes, []string{"00000000000000000000000000000001"}) || admissions != 4 {
		t.Fatal("mixed retirement changed exact effects", result.Result, creates, deletes, admissions)
	}
	closed := f.open(t, ctx)
	if len(closed.root.Names) != len(before) {
		t.Fatal("retirement changed whole current name set")
	}
	for _, named := range closed.root.Names {
		want := before[named.Name]
		if named.Name == "" {
			want.Generated.RetiringDutyPresent = 0
			want.Generated.RetiringDutyID = contract.ID{}
		}
		if !reflect.DeepEqual(*closed.valueEntry(named.Slot), want) {
			t.Fatal("retirement rewrote current metadata, members or ciphertext", named.Name)
		}
	}
	if captureInstalledLocalValue(t, ctx, f, closed, "local") != localBefore {
		t.Fatal("retirement changed actual local value")
	}
	for _, cell := range []struct {
		name   string
		choice uint8
	}{{"", custody.HermeticCloudflareValue}, {"supplied", custody.StandardValue}} {
		selected := sessionConsumerSelection(t, closed, member, cell.name)
		consumed := f.keys.Consume(ctx, selected, cell.choice)
		if consumed.Code != contract.CryptoSuccess || !consumed.ValueMatched {
			t.Fatal("retirement lost an original current value", cell.name, consumed.Code)
		}
	}
}

// full_only: false
func TestInstalledGeneratedCurrentDeclarationKeepsActualHistoricalValue(t *testing.T) {
	f := newRetainedReaderFixture(t, false, 2)
	ctx := t.Context()
	selected := generatedLifecycleReopen(t, ctx, f.selected, f.env.Store)
	_, entry := observeCurrentValueEntry(t, selected, "generated")
	if entry.ValueSource != contract.Generated || entry.Generated.Schema != contract.GeneratedEntryMetadataSchema {
		t.Fatal("fixture did not select an actual original generated entry")
	}
	before := ownScenarioValueEntry(entry)
	consume := func(s *StateSession) {
		t.Helper()
		result := f.keys.Consume(ctx, sessionConsumerSelection(t, s, s.admission.recipient, "generated"), custody.StandardValue)
		if result.Code != contract.CryptoSuccess || result.Delivery != 1 || !result.ValueMatched {
			t.Fatal("actual original generated value is unreadable", result.Code)
		}
	}
	consume(selected)
	work := mustSelectedGeneratedWork(t, selected)
	row, ok := work.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}]
	if !ok {
		t.Fatal("actual original result evidence absent")
	}
	evidence, err := contract.InspectGeneratedCreateEvidence(row.Body)
	if err != nil || evidence.Schema != contract.GeneratedCreateEvidenceSchema || evidence.CredentialRouteID != defaultGeneratedFixtureProfile().CredentialRouteID {
		t.Fatal("fixture did not retain original create evidence", err)
	}
	result, err := contract.InspectGeneratedResultCore(evidence.ResultCore)
	if err != nil || result.Schema != contract.GeneratedResultCoreSchema {
		t.Fatal("fixture replaced the original reader interpretation", err)
	}
	declaration, plans, err := selected.installedGeneratedCurrentDeclaration(work, fixtureID(f.env.Domain, "historical current declaration"))
	if err != nil {
		t.Fatal("current declaration refused authenticated original current entry", err)
	}
	body, err := contract.EncodeGeneratorDeclaration(declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, err := contract.InspectGeneratorDeclaration(body)
	if err != nil || view.EntryCount() != len(selected.root.Names) {
		t.Fatal("current declaration lost complete selected name set", err)
	}
	found := false
	for at, plan := range plans {
		if plan.Name != "generated" {
			continue
		}
		found = true
		row, _, err := view.Entry(at)
		if err != nil || row.Schema != contract.GeneratorDeclarationEntrySchema || plan.Schema != contract.GeneratorValueEntryPlanSchema {
			t.Fatal("historical reference has wrong new framing", err)
		}
		reference, err := contract.InspectGeneratorDeclaredGenerationReferenceForEntry(row.Schema, row.Payload)
		if err != nil || reference.Epoch != before.Generated.Epoch || reference.ConfigContractID != before.Generated.ConfigContractID || reference.LifecycleMode != before.Generated.LifecycleMode || reference.ResourceContractID != before.Generated.ResourceContractID || reference.CompletionClass != before.Generated.CompletionClass || reference.RetirementMode != before.Generated.RetirementMode {
			t.Fatal("new framing changed authenticated old profile", err)
		}
		witness, err := selected.generatedCurrentIntentSelection(ctx, work, plan, reference.Intent)
		if err != nil || witness.Generated != before.Generated || witness.Incarnation != before.Incarnation {
			t.Fatal("new framing lost exact old current-intent admission", err)
		}
	}
	if !found {
		t.Fatal("new declaration omitted historical generated row")
	}
	cold := generatedLifecycleReopen(t, ctx, selected, f.env.Store)
	coldWork := mustSelectedGeneratedWork(t, cold)
	coldEvidence, ok := coldWork.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, entry.Generated.CreateResultID}]
	if !ok || !bytes.Equal(coldEvidence.Body, row.Body) {
		t.Fatal("cold current declaration changed original create evidence bytes")
	}
	_, after := observeCurrentValueEntry(t, cold, "generated")
	if !reflect.DeepEqual(after, before) {
		t.Fatal("new declaration rewrote original member, metadata, ciphertext or origin")
	}
	consume(cold)
}

// full_only: false
func TestInstalledNormalHandoffAddsRecipientAcrossPageBoundary(t *testing.T) {
	for _, name := range []string{"removal", "generated_to_plain", "generated_to_supplied_secret"} {
		t.Run(name, func(t *testing.T) {
			sourceChange := name == "generated_to_supplied_secret"
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
			defer cancel()
			process, effects := installedGeneratedRetirementProcess(t, "acknowledged")
			f := newInstalledApplyTestFixture(t, ctx, contract.GCP, false)
			f.env.GeneratedProcess = process
			selected := f.selected
			authority := selected.admission.recipient
			desired := currentApplyRecipients(selected.registry())
			for i := len(desired); i < 8; i++ {
				rows := installedApplyPreparedRecipient(t, selected, "handoff initial recipient "+strconv.Itoa(i))
				for _, row := range rows {
					if row.Creation != nil {
						desired = append(desired, row)
					}
				}
			}
			slices.SortFunc(desired, func(a, b contract.ApplyRecipientInput) int {
				return bytes.Compare(a.Recipient.RecipientID[:], b.Recipient.RecipientID[:])
			})
			plain := ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				Recipients: []contract.ID{authority}, InputBytes: []byte("unchanged plain sibling"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw}
			seed := f.engineWithRecipients(t, selected, []ApplyEntryInput{plain}, desired, nil)
			seeded := seed.Apply(ctx, fixtureID(f.env.Domain, "handoff eight recipient seed"), []ApplyEntryInput{plain})
			seed.Close()
			if seeded.Result.Outcome != ObservedCurrent {
				t.Fatal("eight-recipient seed", seeded.Result)
			}
			selected = f.open(t, ctx)
			if selected.root.RecipientCount != 8 || selected.root.Recipients[0] == nil || selected.root.Recipients[1] != nil {
				t.Fatal("seed did not select exactly one full recipient page")
			}
			meta := contract.GeneratorDeclaredGeneration{Schema: contract.GeneratorDeclaredGenerationSchema,
				LifecycleMode: contract.GeneratorLifecycleManaged, RetirementMode: contract.GeneratedRetirementManual,
				ConfigContractID: process.Implementation.ConfigContractID, ResourceContractID: hermeticCloudflareResourceContractID(),
				CompletionClass: contract.GeneratedCompletionAcknowledged, Intent: bytes.Clone(process.Intent)}
			input := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Generated, ConfidentialityClass: contract.Secret,
				Recipients: []contract.ID{authority}, Generated: &meta}, plain}
			callbacks := installedGeneratedRetirementCallbacks(t, f, process)
			creator := installedGeneratedTestEngine(t, ctx, f, selected, input, currentApplyRecipients(selected.registry()), callbacks)
			created := creator.Apply(ctx, fixtureID(f.env.Domain, "handoff actual generated predecessor"), input)
			creator.Close()
			if created.Result.Outcome != ObservedCurrent {
				t.Fatal("actual generated predecessor", created.Result)
			}
			selected = f.open(t, ctx)
			_, old := observeCurrentValueEntry(t, selected, "generated")
			desired = installedApplyPreparedRecipient(t, selected, "handoff ninth recipient")
			input = []ApplyEntryInput{plain}
			if sourceChange {
				input = append([]ApplyEntryInput{suppliedSecret(t, f.env, "generated", "handoff supplied replacement", custody.StandardValue, authority)}, input...)
			} else if name == "generated_to_plain" {
				input = append([]ApplyEntryInput{{Name: "generated", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
					Recipients: []contract.ID{authority}, InputBytes: []byte("selected replacement")}}, input...)
			}
			engine := installedGeneratedTestEngine(t, ctx, f, selected, input, desired, callbacks)
			changed := engine.Apply(ctx, fixtureID(f.env.Domain, "handoff adds ninth recipient"), input)
			engine.Close()
			cold := f.open(t, ctx)
			if name == "generated_to_plain" {
				_, unchanged := observeCurrentValueEntry(t, cold, "generated")
				creates, deletes := effects()
				if changed.Result != refused(InvalidIntent) || changed.Payload != nil || len(changed.Receipt) != 0 ||
					!reflect.DeepEqual(cold.root, selected.root) || !reflect.DeepEqual(cold.registry(), selected.registry()) ||
					!reflect.DeepEqual(unchanged, old) || creates != 1 || len(deletes) != 0 {
					t.Fatal("confidentiality change did not refuse the whole request without an effect", changed.Result, creates, deletes)
				}
				return
			}
			if changed.Result.Outcome != ObservedCurrent {
				t.Fatal("installed handoff refused complete successor recipient page", changed.Result)
			}
			want := make([]contract.RecipientRecord, len(desired))
			var rowBytes uint64
			for i, row := range desired {
				want[i] = row.Recipient
				rowBytes += uint64(41 + len(row.Recipient.DisplayName) + 534 + len(row.Recipient.CurrentBinding.KeySelector))
			}
			var pageBytes uint64
			pages := 0
			for _, ref := range cold.root.Recipients {
				if ref != nil {
					pages++
					pageBytes += uint64(ref.Length)
				}
			}
			if cold.root.RecipientCount != 9 || pages != 2 || pageBytes != rowBytes+2*74 || !reflect.DeepEqual(cold.registry(), want) {
				t.Fatal("cold successor lost complete recipient rows or exact page framing", cold.root.RecipientCount, pages, pageBytes, rowBytes)
			}
			if cold.root.Generated.GeneratedCurrent != 0 || cold.root.Generated.Retiring != 1 || !cold.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("normal handoff did not retain one detached old-resource obligation")
			}
			work := mustSelectedGeneratedWork(t, cold)
			var dutyID contract.ID
			var dutyBody []byte
			for _, row := range work.records {
				if row.Kind != contract.GeneratedDutySupportKind {
					continue
				}
				duty, err := contract.InspectGeneratedDutyRecord(row.Body)
				if err != nil {
					t.Fatal(err)
				}
				if duty.ResourceID == old.Generated.ResourceIncarnationID && duty.OriginalOperationID == old.Generated.OriginOperationID && duty.OriginalAttemptID == old.Generated.OriginAttemptID {
					if !dutyID.IsZero() {
						t.Fatal("duplicate old-resource obligation")
					}
					dutyID, dutyBody = row.RecordID, bytes.Clone(row.Body)
				}
			}
			if dutyID.IsZero() {
				t.Fatal("old exact generated resource was not handed off")
			}
			var replacement contract.ValueEntry
			if sourceChange {
				_, replacement = observeCurrentValueEntry(t, cold, "generated")
				if replacement.ValueSource != contract.Supplied || replacement.ConfidentialityClass != contract.Secret ||
					replacement.Incarnation == old.Incarnation || replacement.ValueState == old.ValueState || len(cold.root.Names) != 2 {
					t.Fatal("source change did not select a fresh supplied secret and its complete sibling set")
				}
				consumed := f.keys.Consume(ctx, sessionConsumerSelection(t, cold, authority, "generated"), custody.StandardValue)
				if consumed.Code != contract.CryptoSuccess || !consumed.ValueMatched || consumed.Delivery != 1 {
					t.Fatal("source change lost the exact supplied secret", consumed.Code)
				}
				input[0].InputBytes = nil
				input[0].Retained = &contract.RetainedSecretInput{Incarnation: replacement.Incarnation, Material: replacement.ValueState}
			} else if len(cold.root.Names) != 1 || cold.root.Names[0].Name != "plain" {
				t.Fatal("removal changed whole successor name set")
			}
			input[len(input)-1].InputBytes = []byte("subsequent plain operation")
			next := installedGeneratedTestEngine(t, ctx, f, cold, input, currentApplyRecipients(cold.registry()), callbacks)
			later := next.Apply(ctx, fixtureID(f.env.Domain, "handoff next permitted operation"), input)
			next.Close()
			if later.Result.Outcome != ObservedCurrent {
				t.Fatal("cold handoff blocked later ordinary operation", later.Result)
			}
			closed := f.open(t, ctx)
			laterWork := mustSelectedGeneratedWork(t, closed)
			if !bytes.Equal(laterWork.records[generatedRecordKey{contract.GeneratedDutySupportKind, dutyID}].Body, dutyBody) || !reflect.DeepEqual(closed.registry(), want) {
				t.Fatal("subsequent operation changed exact old-resource duty or recipient set")
			}
			_, nextPlain := observeCurrentValueEntry(t, closed, "plain")
			if !bytes.Equal(nextPlain.ValueBytes, []byte("subsequent plain operation")) {
				t.Fatal("subsequent operation lost its exact plain value")
			}
			if sourceChange {
				_, after := observeCurrentValueEntry(t, closed, "generated")
				consumed := f.keys.Consume(ctx, sessionConsumerSelection(t, closed, authority, "generated"), custody.StandardValue)
				if !reflect.DeepEqual(after, replacement) || consumed.Code != contract.CryptoSuccess || !consumed.ValueMatched || consumed.Delivery != 1 {
					t.Fatal("subsequent operation changed or lost the exact replacement secret", consumed.Code)
				}
			}
			creates, deletes := effects()
			if creates != 1 || len(deletes) != 0 {
				t.Fatal("normal handoff repeated a provider effect", creates, deletes)
			}
		})
	}
}
