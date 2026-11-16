package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/custody"
)

func normalHandoffGeneratedToken(ordinal int32) string {
	switch ordinal {
	case 1:
		return hermeticCloudflareToken
	case 2:
		return "ffeeddccbbaa00998877665544332211"
	default:
		return fmt.Sprintf("%032x", uint32(ordinal))
	}
}

// full_only: false
func TestNormalHandoffGeneratedTokenIdentities(t *testing.T) {
	cases := []struct {
		ordinal int32
		want    string
	}{
		{1, "22222222222222222222222222222222"},
		{2, "ffeeddccbbaa00998877665544332211"},
		{3, "00000000000000000000000000000003"},
		{4, "00000000000000000000000000000004"},
		{17, "00000000000000000000000000000011"},
		{65536, "00000000000000000000000000010000"},
		{2147483647, "0000000000000000000000007fffffff"},
	}
	seen := make(map[string]bool)
	for _, test := range cases {
		got := normalHandoffGeneratedToken(test.ordinal)
		if got != test.want || seen[got] {
			t.Fatal("fixture reused or changed token identity", test.ordinal)
		}
		seen[got] = true
	}
}

type normalHandoffGeneratedAuthor struct {
	process *generatedProcessFixture
	create  func(*StateSession, generatedPlanInput) *StateSession
}

func normalHandoffGeneratedFixture(t *testing.T, recovery bool, cold ...bool) (fixtureEnvironment, *custody.Fixture, *StateSession, contract.GeneratorImplementation, *atomic.Int32, normalHandoffGeneratedAuthor) {
	t.Helper()
	intent, requestBody := hermeticCloudflareIntent()
	effects := new(atomic.Int32)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := effects.Add(1)
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil || r.Method != http.MethodPost || !bytes.Equal(body, requestBody) || r.URL.Path != "/client/v4/accounts/"+hermeticCloudflareAccount+"/tokens" {
			t.Error("unexpected normal handoff provider effect")
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		token := normalHandoffGeneratedToken(n)
		_, err = fmt.Fprintf(w, `{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"generated","policies":[{"effect":"allow","permission_groups":[{"id":"%s"}],"resources":{"com.cloudflare.api.account.%s":"*"}}]}}`, token, hermeticCloudflareSecret, hermeticCloudflarePermission, hermeticCloudflareAccount)
		if err != nil {
			t.Error(err)
		}
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	artifact, row := buildHermeticCloudflareGenerator(t, server.URL+"/client/v4")
	env, keys := genesisEnvironment(t, contract.GCP, recovery)
	env = syntheticAuthorityScenarioEnvironment(t, env)
	f := newEnvironmentFixture(t, context.Background(), env, nil, false)
	profile := nativeGeneratedFixtureProfile(t, row)
	input := generatedPlanInputForGenerationsIntent(t, f.session, generatedVectorID(240), []string{"generated"}, intent, profile)
	input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
	selected := selectHermeticGeneratedProcessOperation(t, t.Context(), env, f.session, input, artifact, func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(t, path, server.URL+"/client/v4", row, expected)
	})
	if effects.Load() != 1 {
		t.Fatal("initial generation effect count", effects.Load())
	}
	create := func(s *StateSession, input generatedPlanInput) *StateSession {
		return selectHermeticGeneratedProcessOperation(t, t.Context(), env, s, input, artifact, func(t testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
			return hermeticCloudflareConfig(t, path, server.URL+"/client/v4", row, expected)
		}, cold...)
	}
	process := &generatedProcessFixture{Artifact: artifact, Implementation: row, Intent: bytes.Clone(intent), RequestDigest: hermeticCloudflareHTTPRequestDigest(requestBody), Configure: func(tb testing.TB, path string, expected contract.GeneratorResultExpectation) custody.GeneratedProcessConfig {
		return hermeticCloudflareConfig(tb, path, server.URL+"/client/v4", row, expected)
	}}
	return env, keys, selected, row, effects, normalHandoffGeneratedAuthor{process: process, create: create}
}

func generatedPlanInputWithCurrentGenerated(t *testing.T, s *StateSession, operation contract.ID, names []string,
	profile generatedFixtureProfile, intent ...[]byte) generatedPlanInput {
	t.Helper()
	requestedIntent := []byte(`{"name":"generated"}`)
	if len(intent) != 0 {
		requestedIntent = intent[0]
	}
	return generatedPlanInputForGenerationsIntent(t, s, operation, names, requestedIntent, profile,
		generatedWriterCurrentDeclarations(t, s, names)...)
}

func entrySlot(t *testing.T, s *StateSession, name string) uint16 {
	t.Helper()
	index := slices.IndexFunc(s.root.Names, func(entry format.NameEntry) bool { return entry.Name == name })
	if index < 0 {
		t.Fatal("member slot", name)
	}
	return s.root.Names[index].Slot
}

// full_only: false
func TestSuppliedToGeneratedKeepsPredecessorOnFailureAndStaleCAS(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, mode := range []string{"failure", "stale-producer", "stale-final"} {
			t.Run(fmt.Sprintf("recovery=%t/%s", recovery, mode), func(t *testing.T) {
				env, keys := genesisEnvironment(t, contract.GCP, recovery)
				env = syntheticAuthorityScenarioEnvironment(t, env)
				run := newScenarioRun(t, t.Context(), env)
				f := newEnvironmentFixture(t, t.Context(), run.env, nil, false)
				before := run.suppliedSelection(f, []ApplyEntryInput{suppliedSecret(t, env, "generated", "source predecessor", custody.StandardValue)})
				beforeReceipts, err := before.receiptWindows(t.Context())
				if err != nil {
					t.Fatal("source change predecessor receipt order", err)
				}
				old, access := ownScenarioValueEntry(*before.valueEntry(0)), before.root.CurrentAccess
				valueAccess, present := observeMaterialAccess(before, contract.ValueMaterialKind, old.ValueState)
				if !present {
					t.Fatal("supplied predecessor has no current material access")
				}
				input := generatedStatePlanInput(t, before, testID(t.Name()+" source change"), []string{old.Name}, defaultGeneratedFixtureProfile(), 0, nil, nil)
				store := env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				public, private := keys.Calls()
				declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
				if err != nil {
					t.Fatal(err)
				}
				work := mustSelectedGeneratedWork(t, before)
				for _, fault := range []string{"incarnation", "class", "content"} {
					bad := input
					bad.graph.ValueEntryPlans = slices.Clone(input.graph.ValueEntryPlans)
					switch fault {
					case "incarnation":
						bad.graph.ValueEntryPlans[0].EntryIncarnationID = old.Incarnation
					case "class":
						bad.graph.ValueEntryPlans[0].ConfidentialityClass = contract.Plain
					case "content":
						bad.graph.ValueEntryPlans[0].ChangeMask &^= contract.GeneratorValueChangeContent
					}
					if _, err := before.generatedAdmissionShape(t.Context(), bad.graph, declaration, work); err == nil {
						t.Fatal("source shape omitted fresh incarnation, stable class or content work", fault)
					}
					if _, err := before.generatedPlanRequest(t.Context(), bad); err == nil {
						t.Fatal("source change omitted fresh incarnation, stable class or content work", fault)
					}
				}
				if p, k := keys.Calls(); p != public || k != private || store.creates != creates || store.cas != cas {
					t.Fatal("refused source change reached custody or Store mutation")
				}
				prior, _ := preparePrivateGeneratedReservation(t, env, before, input, nil)
				var closed *StateSession
				var terminalOperation contract.ID
				if mode == "stale-producer" {
					producer, _ := preparePrivateGeneratedProducer(t, env, before, prior, nil)
					calls := 0
					if !producer.reservation.candidate.bindFirstSend(producer, func(context.Context, contract.ID) contract.CryptoResultCode {
						calls++
						return contract.CryptoSuccess
					}) {
						t.Fatal("source change first-send handoff")
					}
					store.mu.Lock()
					store.put(store.desc.HeadKey, before.body)
					store.mu.Unlock()
					selected, result := before.selectCandidate(t.Context(), producer.reservation.candidate)
					if selected != nil || result.Outcome != Contention || calls != 0 {
						t.Fatal("stale source change reached provider send", result, calls)
					}
					keys.RetireGenerated()
					closed = generatedLifecycleReopen(t, t.Context(), before, env.Store)
				} else {
					choice := uint8(custody.GeneratedTerminalFailure)
					if mode == "stale-final" {
						choice = custody.StandardValue
					}
					recorded, _, expected, packet := selectActualGeneratedPacketRecord(t, env, before, prior, choice, true, nil)
					assertGeneratedReceiptOrder(t, t.Context(), recorded, beforeReceipts.Order)
					terminalOperation = recorded.root.Generated.ActiveOwner
					if terminalOperation.IsZero() {
						t.Fatal("source change Final has no selected parent")
					}
					ctx := generatedPlanInputFixture(t, recorded).context
					ctx.AdmissionID, ctx.SessionID = testID(t.Name()+" final admission"), testID(t.Name()+" final session")
					plan, err := recorded.generatedFinalRequest(t.Context(), ctx)
					if err != nil || plan.selecting != (mode == "stale-final") {
						t.Fatal("source change Final selected the wrong outcome", err)
					}
					recorded, final := preparePrivateGeneratedFinal(t, env, recorded, plan)
					if mode == "stale-final" {
						store.mu.Lock()
						store.put(store.desc.HeadKey, recorded.body)
						store.mu.Unlock()
					}
					var result Result
					closed, result = recorded.selectCandidate(t.Context(), final.reservation.candidate)
					if mode == "stale-final" {
						if closed != nil || result.Outcome != Contention {
							t.Fatal("stale source change Final selected new values", result)
						}
						closed = recorded
					} else if closed == nil || result.Outcome != ObservedCurrent {
						t.Fatal("failed source change Final", result)
					}
					keys.RetireGenerated()
					closed = generatedLifecycleReopen(t, t.Context(), closed, env.Store)
					work := mustSelectedGeneratedWork(t, closed)
					if mode == "stale-final" {
						attempt, retained := work.attempts[expected.Template.AttemptID]
						if !retained || attempt.record.State != contract.GeneratedEffectSucceeded || attempt.record.ResourceID != expected.Template.ResourceIncarnationID ||
							!bytes.Equal(attempt.result, packet) || work.parent == nil || closed.root.Generated.ActiveOwner.IsZero() {
							t.Fatal("stale source change Final lost exact pending resource evidence")
						}
					} else {
						hazard, err := contract.InspectGeneratedHazardRecord(work.records[generatedRecordKey{11, expected.Template.HazardID}].Body)
						target, targetErr := work.generatedCleanupTarget(11, hazard.HazardID, hazard.Target)
						if err != nil || targetErr != nil || hazard.OriginalAttemptID != expected.Template.AttemptID ||
							target.OriginalAttemptID != expected.Template.AttemptID || target.ResourceID != expected.Template.ResourceIncarnationID ||
							!closed.root.Generated.ActiveOwner.IsZero() {
							t.Fatal("failed source change lost exact cleanup evidence", err, targetErr)
						}
					}
				}
				if mode == "failure" {
					wantOrder := append(slices.Clone(beforeReceipts.Order), terminalOperation)
					afterReceipts := assertGeneratedReceiptOrder(t, t.Context(), closed, wantOrder)
					if !slices.Equal(afterReceipts.Successes, beforeReceipts.Successes) || len(afterReceipts.Failures) != len(beforeReceipts.Failures)+1 || afterReceipts.Failures[len(afterReceipts.Failures)-1].OperationID != terminalOperation {
						t.Fatal("failed source change did not append only its parent failure receipt")
					}
				} else {
					assertGeneratedReceiptOrder(t, t.Context(), closed, beforeReceipts.Order)
				}
				if closed.root.ValueEntryCount != 1 || !reflect.DeepEqual(*closed.valueEntry(0), old) {
					t.Fatal("unselected source change changed supplied values")
				}
				currentAccess, present := observeMaterialAccess(closed, contract.ValueMaterialKind, old.ValueState)
				if !present || !reflect.DeepEqual(currentAccess, valueAccess) || !reflect.DeepEqual(closed.root.Recipients, before.root.Recipients) {
					t.Fatal("unselected source change changed supplied material access or recipient bindings")
				}
				if mode == "stale-producer" && !reflect.DeepEqual(closed.root.CurrentAccess, access) {
					t.Fatal("stale producer changed aggregate access")
				}
				if check := keys.Consume(t.Context(), sessionConsumerSelection(t, closed, closed.admission.recipient, old.Name), custody.StandardValue); check.Code != contract.CryptoSuccess || !check.ValueMatched || check.Delivery != 1 {
					t.Fatal("unselected source change lost supplied semantic value", check)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedNormalCapacityKeepsAbsentLateCreateInbox(t *testing.T) {
	s, original, hazard := generatedCreateHazardState(t, 0, 0)
	g, err := s.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := &Comparison{session: s, intent: []contract.CryptoIntentRow{{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, PayloadLength: 13, ContentLength: 13, InputEncoding: contract.InputEncodingRaw, RetainedLength: 13, OutputEncoding: contract.OutputEncodingRaw, PayloadDigest: contract.Hash([]byte("public change"))}}, slots: []uint16{0}, added: []uint16{0}}
	w, err := s.generatedSupportTransition(t.Context(), c, nil)
	if err != nil || w == nil {
		t.Fatal("normal capacity support witness", err)
	}
	groups, err := s.generatedNormalGroups(t.Context(), c, g, w)
	if err != nil {
		t.Fatal(err)
	}
	var locations []contract.GeneratorSliceLocation
	for _, location := range g.content.locations {
		locations = append(locations, location)
	}
	physical, err := generatedReservationGroupsForState(s, w.Records, locations, g.bundles)
	if err != nil {
		t.Fatal(err)
	}
	var owners, materials uint64
	for _, group := range physical {
		if group.Class != format.OwnerSupport && group.Class != format.MaterialSupport {
			continue
		}
		for _, row := range group.Records {
			if group.Class == format.OwnerSupport {
				owners += uint64(contract.SupportRecordOverhead + len(row.Body))
			} else {
				materials += uint64(contract.SupportRecordOverhead + len(row.Body))
			}
		}
	}
	if owners == 0 || materials == 0 || groups[contract.GeneratorCapacityOwners].MaxFramedBytes != owners ||
		groups[contract.GeneratorCapacityMaterial].MaxFramedBytes != materials {
		t.Fatal("normal capacity did not use selected owner/material encoded widths", groups[contract.GeneratorCapacityOwners], groups[contract.GeneratorCapacityMaterial])
	}
	resultGroup := groups[contract.GeneratorCapacityCreateResults]
	if resultGroup.MaxCount != 1 || resultGroup.MaxFramedBytes != uint64(format.RequiredSupportGroupLimit(format.ResultSupport)) {
		t.Fatal("absent adoptable create result capacity released", resultGroup)
	}
	a, ok := g.attempts[original.record.AttemptID]
	if !ok || a.record.InboxID != original.record.InboxID || len(a.result) != 0 || g.parent != nil || !g.hasRecord(generatedRecordKey{kind: 11, id: hazard.HazardID}) {
		t.Fatal("normal mutation lost exact absent late inbox")
	}
	packet := generatedPublicResultFixtureWithRaw(t, a, 1, 65536)
	if len(packet)+37 > int(resultGroup.MaxFramedBytes) {
		t.Fatal("reachable raw65536 result does not fit admitted owner", len(packet))
	}
	// This cell checks the typed capacity construction, not an authenticated
	// normal mutation or private late-return adoption. Those need real drivers.
}

// full_only: false
func TestGeneratedNormalPreparationKeepsLateIntentReadResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		read contract.ReadResult
		want Result
	}{
		{"missing", contract.ReadResult{Status: contract.ReadMissing}, Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}},
		{"unavailable", contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}, Result{Outcome: EvidenceUnavailable, Reason: ReadUnavailable, StoreReason: contract.ReasonTransport}},
		{"invalid", contract.ReadResult{Status: contract.ReadInvalid}, Result{Outcome: IntegrityFailure, Reason: InvalidFormat}},
		{"invalid-body", contract.ReadResult{Status: contract.ReadOK, Body: []byte{1}}, Result{Outcome: IntegrityFailure, Reason: InvalidReference}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			env, keys, selected, row, effects, _ := normalHandoffGeneratedFixture(t, false)
			keys.RetireGenerated()
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			input := selected.currentEntryInputs()
			input = append(input, ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
				Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("ordinary addition retains generated intent"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			parent := admitSuppliedComparison(t, selected, keys, input, row)
			comparison, result := selected.Compare(ctx, input, parent)
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("healthy retained generated comparison", result)
			}
			permit := admit(t, selected, comparison)
			defer keys.RetireApply()
			current := selected.valueEntry(selected.root.Names[0].Slot)
			if current == nil || current.ValueSource != contract.Generated {
				t.Fatal("fixture has no current generated entry")
			}
			locations, err := selected.resolveSelectedGeneratedSlices()
			if err != nil {
				t.Fatal(err)
			}
			var ref format.Ref
			for _, location := range locations {
				if location.ContentKind != contract.GeneratorContentIntent || location.ContentID != current.Generated.IntentDigest {
					continue
				}
				for fragmentLocation, fact := range selected.fragmentFacts {
					if fragmentLocation.BlobID == location.BlobID && uint64(fact.offset) <= location.Offset &&
						location.Offset < uint64(fact.offset)+uint64(fact.payloadLength) {
						ref = fact.ref
					}
				}
			}
			if ref.Kind != contract.RequiredSupportKind {
				t.Fatal("current intent has no exact cold fragment reference")
			}
			key, err := format.Key(selected.admission.store.Prefix, ref)
			if err != nil {
				t.Fatal(err)
			}
			store := requireAdmittedMemoryStore(t, env.Store)
			reads := 0
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
				}
				return read
			}
			t.Cleanup(func() { store.readHook = nil })
			next, err := selected.deriveSuccessor(ctx, comparison, permit.plan)
			if err != nil || next == nil || !slices.Contains(next.root.RequiredSupport, ref) || reads != 0 {
				t.Fatal("healthy successor did not retain the late intent reference", reads)
			}
			if next.checkNormalCapacity(ctx, comparison) != nil || reads != 0 {
				t.Fatal("healthy capacity reread the retained intent", reads)
			}
			trust, ok := underlyingAdmittedFixtureTrust(env.Trust)
			if !ok {
				t.Fatal("fixture has no signing counter")
			}
			creates, cas, signs, calls := store.creates, store.cas, trust.signs, effects.Load()
			public, private := keys.Calls()
			before, selectedRoot := contract.Hash(selected.body), selected.head.Core.Root
			prepared, used := selected.prepared, permit.used
			store.readHook = func(actual string, read contract.ReadResult) contract.ReadResult {
				if actual == key {
					reads++
					return tc.read
				}
				return read
			}
			candidate, result := selected.Prepare(ctx, comparison, permit, env.Trust)
			if candidate != nil || result != tc.want || reads == 0 {
				t.Fatal("late intent read lost its exact result", result, reads)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private ||
				store.creates != creates || store.cas != cas || trust.signs != signs || effects.Load() != calls ||
				selected.prepared != prepared || permit.used != used || contract.Hash(selected.body) != before || selected.head.Core.Root != selectedRoot {
				t.Fatal("late intent refusal changed ownership or caused effects", gotPublic, gotPrivate)
			}
		})
	}
}

// full_only: false
func TestGeneratedNormalCapacityCountsColdIntentFragmentBytes(t *testing.T) {
	ctx := t.Context()
	env, keys, selected, row, effects, _ := normalHandoffGeneratedFixture(t, false)
	keys.RetireGenerated()
	selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
	if selected.fragmentFacts == nil {
		t.Fatal("fixture did not cold-open selected fragments")
	}
	proposed := []ApplyEntryInput{suppliedSecret(t, env, "generated", "cold normal capacity", custody.StandardValue)}
	parent := admitSuppliedComparison(t, selected, keys, proposed, row)
	comparison, result := selected.Compare(ctx, proposed, parent)
	if comparison == nil || result.Outcome != ObservedCurrent {
		t.Fatal("cold normal capacity comparison", result)
	}
	permit := admit(t, selected, comparison)
	next, err := selected.deriveSuccessor(ctx, comparison, permit.plan)
	if err != nil {
		t.Fatal("cold normal capacity successor")
	}
	if projected, err := next.prospectiveNormalPublicState(comparison, permit.plan); err != nil || projected.Digest.IsZero() {
		t.Fatal("normal authority omitted the admitted prospective public state", err)
	}
	wrongFacts := *comparison
	wrongFacts.normalSupportRows = comparison.normalSupportRows
	wrongFacts.normalSupportRows.Facts = slices.Clone(comparison.normalSupportRows.Facts)
	if len(wrongFacts.normalSupportRows.Facts) == 0 {
		t.Fatal("normal authority fixture has no support facts")
	}
	wrongFacts.normalSupportRows.Facts[0] = contract.SupportRecordDigest{}
	if _, err := next.prospectiveNormalPublicState(&wrongFacts, permit.plan); err == nil {
		t.Fatal("normal authority accepted a mismatched SupportAfter fact")
	}
	wrongRef := *next
	wrongRef.supportFacts = slices.Clone(next.supportFacts)
	if len(wrongRef.supportFacts) == 0 {
		t.Fatal("normal authority fixture has no selected physical facts")
	}
	wrongRef.supportFacts[0].ref = format.Ref{}
	if _, err := wrongRef.prospectiveNormalPublicState(comparison, permit.plan); err == nil {
		t.Fatal("normal authority accepted a mismatched physical Ref")
	}
	locations, err := selected.resolveSelectedGeneratedSlices()
	if err != nil {
		t.Fatal("selected logical locations", err)
	}
	intentBlobs := make(map[contract.ID]bool)
	for _, location := range locations {
		if location.ContentKind == contract.GeneratorContentIntent {
			intentBlobs[location.BlobID] = true
		}
	}
	var wantCount, wantBytes uint64
	pages := make(map[uint16]bool)
	for _, location := range selected.root.Generated.Fragments {
		if !intentBlobs[location.BlobID] {
			continue
		}
		fact, found := selected.fragmentFacts[location]
		position := slices.IndexFunc(selected.root.RequiredSupport, func(ref format.Ref) bool {
			return ref.Index == location.SupportPageIndex
		})
		if !found || position < 0 || !slices.Contains(next.root.RequiredSupport, selected.root.RequiredSupport[position]) {
			t.Fatal("cold intent fragment lost its exact selected page")
		}
		ref := selected.root.RequiredSupport[position]
		key, err := format.Key(selected.admission.store.Prefix, ref)
		if err != nil {
			t.Fatal(err)
		}
		read := env.Store.Read(ctx, key, ref.Length)
		if read.Status != contract.ReadOK || format.CheckReference(ref, read.Body) != nil {
			t.Fatal("selected physical page did not match its reference", read.Status)
		}
		page, err := format.InspectRequiredSupportPage(read.Body)
		if err != nil || int(fact.physical) >= len(page.Records) {
			t.Fatal("selected physical fragment row", err)
		}
		fragment, err := contract.InspectGeneratedFragment(page.Records[fact.physical].Body)
		if err != nil || fragment.BlobID != location.BlobID || fragment.Index != location.FragmentIndex {
			t.Fatal("selected physical fragment identity", err)
		}
		wantCount++
		wantBytes += uint64(contract.SupportRecordOverhead + len(page.Records[fact.physical].Body))
		pages[ref.Index] = true
	}
	if wantCount == 0 || wantBytes == 0 || len(pages) == 0 {
		t.Fatal("fixture has no cold Intent fragment charge")
	}
	actual, err := next.normalCapacityUsage(ctx, comparison)
	if err != nil {
		t.Fatal("cold normal capacity census refused a provisional successor")
	}
	got := actual[contract.GeneratorCapacityIntents]
	if got.MaxCount != wantCount || got.MaxFramedBytes != wantBytes || got.MaxPages != uint32(len(pages)) {
		t.Fatal("cold Intent capacity differs from selected physical wire", got, wantCount, wantBytes, len(pages))
	}
	exact := *comparison
	exactWitness := *comparison.support
	exactWitness.Groups[contract.GeneratorCapacityIntents] = contract.GeneratorCapacityGroup{
		MaxCount: wantCount, MaxFramedBytes: wantBytes, MaxPages: uint32(len(pages)),
	}
	exact.support = &exactWitness
	if next.checkNormalCapacity(ctx, &exact) != nil {
		t.Fatal("admitted exact cold Intent capacity refused")
	}
	short := exact
	shortWitness := exactWitness
	shortWitness.Groups[contract.GeneratorCapacityIntents].MaxFramedBytes--
	short.support = &shortWitness
	store := requireAdmittedMemoryStore(t, env.Store)
	creates, cas, calls := store.creates, store.cas, effects.Load()
	public, private := keys.Calls()
	prepared, used := selected.prepared, permit.used
	if next.checkNormalCapacity(ctx, &short) == nil || store.creates != creates || store.cas != cas || effects.Load() != calls ||
		selected.prepared != prepared || permit.used != used {
		t.Fatal("one-byte-short Intent bound passed or caused effects")
	}
	if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
		t.Fatal("one-byte-short Intent bound reached custody", gotPublic, gotPrivate)
	}
	fragmentPosition := slices.IndexFunc(next.supportFacts, func(page selectedSupportPageFacts) bool {
		return slices.ContainsFunc(page.rows, func(row contract.SupportRecordDigest) bool {
			return row.Kind() == contract.GeneratedFragmentSupportKind
		})
	})
	if fragmentPosition < 0 {
		t.Fatal("cold successor lacks fragment facts")
	}
	otherPosition, otherSlot := -1, -1
	for i, page := range next.supportFacts {
		for j, row := range page.rows {
			if i != fragmentPosition || row.Kind() != contract.GeneratedFragmentSupportKind {
				otherPosition, otherSlot = i, j
				break
			}
		}
		if otherPosition >= 0 {
			break
		}
	}
	if otherPosition < 0 {
		t.Fatal("cold successor lacks a second selected fact")
	}
	fragmentSlot := slices.IndexFunc(next.supportFacts[fragmentPosition].rows, func(row contract.SupportRecordDigest) bool {
		return row.Kind() == contract.GeneratedFragmentSupportKind
	})
	for _, damage := range []string{"missing", "duplicate", "wrong-ref"} {
		t.Run(damage, func(t *testing.T) {
			bad := *next
			bad.supportFacts = slices.Clone(next.supportFacts)
			bad.supportFacts[fragmentPosition].rows = slices.Clone(next.supportFacts[fragmentPosition].rows)
			switch damage {
			case "missing":
				bad.supportFacts[fragmentPosition].rows = bad.supportFacts[fragmentPosition].rows[:len(bad.supportFacts[fragmentPosition].rows)-1]
			case "duplicate":
				bad.supportFacts[fragmentPosition].rows[fragmentSlot] = next.supportFacts[otherPosition].rows[otherSlot]
			case "wrong-ref":
				bad.supportFacts[fragmentPosition].ref = format.Ref{}
			}
			if _, err := bad.normalCapacityUsage(ctx, comparison); err == nil {
				t.Fatal("damaged selected facts produced a capacity census", damage)
			}
		})
	}
}

// full_only: false
func TestGeneratedNormalMutationKeepsOlderDeleteReaderUsable(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, s, old, packet := generatedAuthenticatedDeleteHazardFixture(t, recovery, 0)
			keys := env.Custody
			store := env.Store.(*memoryStore)
			cas := store.cas
			access, ok := s.materialAccess(3, old.material.Core.OperationMaterialID)
			if !ok {
				t.Fatal("old real delete reader absent")
			}
			beforeAccess, err := contract.EncodeAccessRecord(access)
			if err != nil {
				t.Fatal(err)
			}
			input := s.currentEntryInputs()
			input = append(input, ApplyEntryInput{Name: "plain", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{s.admission.recipient}, InputBytes: []byte("public change with old reader"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			parent := admitSuppliedComparison(t, s, keys, input)
			entryBackingDigest := contract.Hash(parent.support.CurrentGenerated[0].EntryBytes)
			wrapBacking := contract.Hash(parent.support.AccessRecords[0].Wraps[0].RSACiphertext)
			c, res := s.Compare(context.Background(), input, parent)
			if c == nil {
				t.Fatal("old reader comparison", res)
			}
			permit := admit(t, s, c)
			preview, err := s.deriveSuccessor(t.Context(), c, permit.plan)
			if err != nil {
				t.Fatal("old reader preview")
			}
			pages, err := normalSupportPacking(t.Context(), c, permit.plan)
			if err != nil || len(pages) == 0 {
				t.Fatal("old reader prospective packing groups", err)
			}
			usage, err := preview.normalCapacityUsage(t.Context(), c)
			if err != nil {
				t.Fatal("old reader physical capacity census")
			}
			for i, a := range usage {
				b := c.support.Groups[i]
				if a.MaxCount > b.MaxCount || a.MaxFramedBytes > b.MaxFramedBytes || a.MaxPages > b.MaxPages {
					t.Fatal("old reader contributor exceeds bound", i, a, b)
				}
			}
			candidate, res := s.Prepare(context.Background(), c, permit, env.Trust)
			if candidate == nil {
				t.Fatal("old reader preparation", res)
			}
			selected, res := s.selectCandidate(context.Background(), candidate)
			if selected == nil || store.cas != cas+1 {
				t.Fatal("old reader normal selection", res)
			}
			keys.RetireApply()
			if contract.Hash(parent.support.CurrentGenerated[0].EntryBytes) != entryBackingDigest || contract.Hash(parent.support.AccessRecords[0].Wraps[0].RSACiphertext) != wrapBacking {
				t.Fatal("ordinary disposal changed Core-owned member or selected wrap backing")
			}
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			selectedWork, err := selected.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			retained, ok := selectedWork.attempts[old.record.AttemptID]
			if !ok || retained.record != old.record || retained.expected != old.expected {
				t.Fatal("normal mutation changed exact original invocation or target")
			}
			access, ok = selected.materialAccess(3, old.material.Core.OperationMaterialID)
			if !ok {
				t.Fatal("normal mutation dropped real old delete reader")
			}
			afterAccess, err := contract.EncodeAccessRecord(access)
			if err != nil || !bytes.Equal(beforeAccess, afterAccess) {
				t.Fatal("normal mutation changed exact old reader wraps", err)
			}
			inbox, err := format.GeneratedResultKey(store.desc.Prefix, old.record.DomainID, old.record.InboxID)
			if err != nil {
				t.Fatal(err)
			}
			store.objects[inbox] = stored{Body: bytes.Clone(packet), Token: contract.Token{Family: store.desc.Family, Value: `"normal-old-delete"`}}
			observed := store.objects[inbox]
			if !bytes.Equal(observed.Body, packet) {
				t.Fatal("original packet differs at exact original inbox")
			}
			reflection := admitPrivateGeneratedOriginalReflection(t, keys, selected, old.record.ResultID, packet, generatedPlanInputFixture(t, selected).context)
			candidate, res = selected.PrepareGeneratedLifecycle(context.Background(), reflection, env.Trust)
			if candidate == nil {
				t.Fatal("old private reader unusable after normal mutation", res)
			}
			closed, res := selected.selectCandidate(context.Background(), candidate)
			if closed == nil || res.Outcome != ObservedCurrent {
				t.Fatal("old private reflection selection", res)
			}
			keys.RetireGenerated()
			generatedLifecycleReopen(t, t.Context(), closed, env.Store)
		})
	}
}

// full_only: false
func TestGeneratedMixedCreateKeepsOlderDeleteReader(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, s, old, _ := generatedAuthenticatedDeleteHazardFixture(t, recovery, 0)
			beforeRows := s.supportRecords()
			profile := defaultGeneratedFixtureProfile()
			input := generatedPlanInputWithCurrentGenerated(t, s, generatedVectorID(247), []string{"new"}, profile)
			prior, _ := preparePrivateGeneratedReservation(t, env, s, input, nil)
			producer, expected := preparePrivateGeneratedProducer(t, env, s, prior, nil)
			var packet []byte
			if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
				var code contract.CryptoResultCode
				packet, _, code = env.Custody.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
				return code
			}) {
				t.Fatal("mixed old reader handoff")
			}
			entered, res := s.selectCandidate(context.Background(), producer.reservation.candidate)
			if entered == nil || len(packet) == 0 {
				t.Fatal("mixed old reader entry", res)
			}
			env.Custody.RetireGenerated()
			recorded := env.FreshGeneratedRecord(t, entered, expected.Template.AttemptID, packet)
			admitted := generatedPlanInputFixture(t, recorded).context
			admitted.AdmissionID, admitted.SessionID = testID("mixed old reader final"), testID("mixed old reader session")
			finalPlan, err := recorded.generatedFinalRequest(t.Context(), admitted)
			if err != nil {
				t.Fatal(err)
			}
			capture := &normalGeneratedEntryCapture{Crypto: env.Custody.Crypto(), session: recorded, plan: finalPlan, retained: old.material.Core.OperationMaterialID, t: t}
			recorded, final := preparePrivateGeneratedFinal(t, env, recorded, finalPlan, capture)
			selected, res := recorded.selectCandidate(context.Background(), final.reservation.candidate)
			if selected == nil {
				t.Fatal("mixed old reader final selection", res)
			}
			env.Custody.RetireGenerated()
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			if _, ok := selected.materialAccess(3, old.material.Core.OperationMaterialID); !ok {
				t.Fatal("mixed create dropped unrelated real old reader")
			}
			for _, before := range beforeRows {
				if before.Kind != 11 && before.Kind != contract.MutationReceiptSupportKind {
					continue
				}
				after := selected.supportRecords()
				i := slices.IndexFunc(after, func(row contract.SupportRecord) bool {
					return row.Kind == before.Kind && row.RecordID == before.RecordID
				})
				if i < 0 || !bytes.Equal(before.Body, after[i].Body) {
					t.Fatal("mixed create changed older Hazard or frozen receipt")
				}
			}
		})
	}
}

type normalGeneratedEntryCapture struct {
	contract.Crypto
	session  *StateSession
	plan     *generatedFinalPlan
	retained contract.ID
	t        *testing.T
}

func (c *normalGeneratedEntryCapture) Exchange(ctx context.Context, q contract.CryptoRequest) contract.CryptoResponse {
	reply := c.Crypto.Exchange(ctx, q)
	if q.Kind == contract.CryptoPrepare && reply.ResultCode == contract.CryptoSuccess {
		view, err := contract.InspectCryptoGeneratedValueEntriesResult(reply.Body)
		if err == nil {
			owned, err := view.Own()
			if err != nil {
				c.t.Fatal(err)
			}
			candidate, err := c.session.deriveGeneratedFinal(ctx, c.plan, owned.Rows)
			if err != nil {
				c.t.Fatal("actual mixed member reply closure", err)
			}
			if _, ok := candidate.state.materialAccess(3, c.retained); !ok {
				c.t.Fatal("actual member reply dropped independently retained reader")
			}
		}
	}
	return reply
}

// full_only: false
func TestGeneratedNormalCapacityNoopAndAdmissionOwnership(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, row, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			input := s.currentEntryInputs()
			c, result := s.compareEntryInputs(input)
			if c == nil {
				t.Fatal(result)
			}
			w, err := s.generatedSupportTransition(context.Background(), c, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, fault := range []string{"slot", "entry", "evidence-index", "carrier-index", "intent-location", "target", "handoff", "reader-index", "reader-current", "reader-binding", "support-metadata", "support-fact", "extra-fact", "nonfragment-without-body", "access-metadata", "control", "slice-owner-zero", "slice-owner-wrong", "root-snapshot"} {
				t.Run(fault, func(t *testing.T) {
					bad, err := w.CopyMetadata()
					if err != nil {
						t.Fatal(err)
					}
					switch fault {
					case "slot":
						bad.CurrentGenerated[0].Slot++
					case "entry":
						bad.CurrentGenerated[0].EntryBytes[0] ^= 1
					case "evidence-index":
						bad.CurrentGenerated[0].EvidenceRecord = 0
					case "carrier-index":
						bad.CurrentGenerated[0].CarrierRecord = 0
					case "intent-location":
						bad.CurrentGenerated[0].Intent.Offset++
					case "target":
						bad.CurrentGenerated[0].Target.ResourceDigest = testID("wrong target")
					case "handoff":
						bad.Handoffs = append(bad.Handoffs, contract.GeneratedSupportHandoff{Current: 0, Implementation: row})
					case "reader-index":
						bad.Readers[0].Access++
					case "reader-current":
						bad.Readers[0].Current = nil
					case "reader-binding":
						bad.Readers[0].Bindings[0].PublicBindingDigest = testID("wrong reader")
					case "support-metadata":
						bad.Records[0].RecordID = testID("wrong record")
					case "support-fact":
						bad.RecordFacts[0] = bad.RecordFacts[1]
					case "extra-fact":
						bad.RecordFacts = append(bad.RecordFacts, bad.RecordFacts[0])
					case "nonfragment-without-body":
						for i := range bad.Records {
							if bad.Records[i].Kind != contract.GeneratedFragmentSupportKind {
								bad.Records[i].Body = nil
								break
							}
						}
					case "access-metadata":
						bad.AccessRecords[0].MaterialID = testID("wrong material")
					case "control":
						bad.BeforeAccess.AccessGeneration++
					case "slice-owner-zero":
						bad.BeforeSliceSnapshot = contract.ID{}
					case "slice-owner-wrong":
						bad.BeforeSliceSnapshot = testID("wrong Slice owner")
					case "root-snapshot":
						bad.BeforeSnapshot = testID("wrong Root snapshot")
					}
					if (fault == "slice-owner-zero" || fault == "slice-owner-wrong") && bad.Inspect() == nil {
						t.Fatal("private current proof accepted the wrong Slice owner")
					}
					parent := admitSuppliedComparison(t, s, keys, input)
					parent.support = bad
					defer keys.RetireApply()
					before := env.Store.(*memoryStore).cas
					if got, res := s.Compare(context.Background(), input, parent); got != nil || res != refused(AdmissionInvalid) || env.Store.(*memoryStore).cas != before || effects.Load() != 1 {
						t.Fatal("changed private witness admitted", res)
					}
					keys.RetireApply()
				})
			}
			t.Run("noop-at-hypothetical-capacity", func(t *testing.T) {
				parent := admitSuppliedComparison(t, s, keys, input)
				defer keys.RetireApply()
				// The capacity envelope is immutable authority, but a hypothetical
				// mutation that cannot fit must not turn an exact Noop into refusal.
				parent.support.Groups[contract.GeneratorCapacityAuxiliary] = contract.GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: 1, MaxPages: 257}
				if got, res := s.Compare(context.Background(), input, parent); got != nil || res.Outcome != Unchanged {
					t.Fatal("hypothetical overfit refused true Noop", res)
				}
				keys.RetireApply()
			})
			t.Run("changed-input-refusal-before-effects", func(t *testing.T) {
				changed := []ApplyEntryInput{suppliedSecret(t, env, "generated", "normal overfit changed", custody.StandardValue)}
				parent := admitSuppliedComparison(t, s, keys, changed, row)
				defer keys.RetireApply()
				parent.support.Groups[contract.GeneratorCapacityAuxiliary] = contract.GeneratorCapacityGroup{MaxCount: 1, MaxFramedBytes: 1, MaxPages: 257}
				entropy := bytes.NewReader(bytes.Repeat([]byte{0x72}, 32))
				previousEntropy := s.admission.entropy
				s.admission.entropy = entropy
				defer func() { s.admission.entropy = previousEntropy }()
				store := env.Store.(*memoryStore)
				creates, cas := store.creates, store.cas
				if got, res := s.Compare(context.Background(), changed, parent); got != nil || res != refused(CapacityExceeded) || entropy.Len() != 32 || store.creates != creates || store.cas != cas || effects.Load() != 1 {
					t.Fatal("non-Noop overfit reached identities or effects", res)
				}
				keys.RetireApply()
			})
			t.Run("admitted-metadata-ownership", func(t *testing.T) {
				caller, err := w.CopyMetadata()
				if err != nil {
					t.Fatal(err)
				}
				owned, err := caller.CopyMetadata()
				if err != nil {
					t.Fatal(err)
				}
				before := owned.CurrentGenerated[0]
				oldGroup := owned.Groups
				oldReader := owned.Readers[0].Bindings[0]
				oldFact := owned.RecordFacts[0]
				caller.CurrentGenerated[0].Slot++
				caller.CurrentGenerated[0].Target.ResourceDigest = testID("later metadata")
				caller.RecordFacts[0] = caller.RecordFacts[1]
				caller.Readers[0].Bindings[0].PublicBindingDigest = testID("later binding")
				caller.Groups[0].MaxCount++
				if owned.CurrentGenerated[0].Slot != before.Slot || owned.CurrentGenerated[0].Target != before.Target || owned.RecordFacts[0] != oldFact || owned.Groups != oldGroup || owned.Readers[0].Bindings[0] != oldReader {
					t.Fatal("admitted metadata retained mutable caller aliases")
				}
			})
		})
	}
}

// full_only: false
func TestGeneratedNormalPublicOnlyBacklogAndReadd(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, row, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			old := *s.valueEntry(0)
			ctx := context.Background()
			parent := admitSuppliedComparison(t, s, keys, nil, row)
			c, res := s.Compare(ctx, nil, parent)
			if c == nil {
				t.Fatal(res)
			}
			candidate, res := s.Prepare(ctx, c, admit(t, s, c), env.Trust)
			if candidate == nil {
				t.Fatal(res)
			}
			removed, res := s.selectCandidate(ctx, candidate)
			if removed == nil {
				t.Fatal(res)
			}
			keys.RetireApply()
			removed = generatedLifecycleReopen(t, ctx, removed, env.Store)
			keys.SetUnavailable(true)
			defer keys.SetUnavailable(false)
			public, private := keys.Calls()
			input := []ApplyEntryInput{{Name: old.Name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: old.Recipients, InputBytes: []byte("readded plain")}}
			parent = admitSuppliedComparison(t, removed, keys, input)
			if parent == nil || parent.crypto != nil || !time.Now().Before(parent.deadline) {
				t.Fatal("public-only backlog acquired Crypto custody")
			}
			c, res = removed.Compare(ctx, input, parent)
			if c == nil {
				t.Fatal("public-only comparison", res)
			}
			candidate, res = removed.Prepare(ctx, c, admit(t, removed, c), env.Trust)
			if candidate == nil {
				t.Fatal("public-only preparation", res)
			}
			added, res := removed.selectCandidate(ctx, candidate)
			if added == nil {
				t.Fatal(res)
			}
			added = generatedLifecycleReopen(t, ctx, added, env.Store)
			p, k := keys.Calls()
			if p != public || k != private || effects.Load() != 1 || added.root.Generated.Retiring != 1 || added.valueEntry(0).Incarnation == old.Incarnation {
				t.Fatal("public-only work needed KEK or lost old retirement")
			}
			work, err := added.selectedGeneratedWork(context.Background())
			if err != nil || len(work.attempts) != 0 || work.parent != nil {
				t.Fatal("public-only work fabricated generated owner", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedNormalRefusesMissingOriginalRowAndPresentPlain(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, row, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			c, res := s.compareEntryInputs(nil)
			if c == nil {
				t.Fatal(res)
			}
			store, trust := env.Store.(*memoryStore), env.Trust.(*fixtureTrust)
			creates, cas, signs := store.creates, store.cas, trust.signs
			public, private := keys.Calls()
			baseline := fixtureGeneratedSupportHandoffs(t, s, c, []contract.GeneratorImplementation{row})
			if witness, err := s.generatedSupportTransition(t.Context(), c, baseline); err != nil || witness == nil {
				t.Fatal("valid passive support baseline", err)
			}
			for _, fault := range []string{"missing", "input-bytes", "response-digest", "negative-response", "route-binding"} {
				registry := fixtureGeneratedSupportHandoffs(t, s, c, []contract.GeneratorImplementation{row})
				handoff := registry["generated"]
				switch fault {
				case "missing":
					delete(registry, "generated")
				case "input-bytes":
					handoff.CompatibilityRequest[len(handoff.CompatibilityRequest)-1] ^= 1
				case "response-digest":
					handoff.CompatibilityResponse[2] ^= 1
				case "negative-response":
					handoff.CompatibilityResponse[len(handoff.CompatibilityResponse)-1] = 0
				case "route-binding":
					handoff.Support[0].PublicBindingDigest = testID("wrong selected route")
				}
				if fault != "missing" {
					registry["generated"] = handoff
				}
				if _, err := s.generatedSupportTransition(t.Context(), c, registry); err == nil {
					t.Fatal("unqualified passive support admitted", fault)
				}
			}

			plain := []ApplyEntryInput{{Name: "generated", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: s.valueEntry(0).Recipients, InputBytes: []byte("must remove first")}}
			if got, res := s.Compare(context.Background(), plain, nil); got != nil || res.Outcome != AdmissionRefused {
				t.Fatal("present Secret to Plain admitted", res)
			}
			p, k := keys.Calls()
			if creates != store.creates || cas != store.cas || signs != trust.signs || p != public || k != private || effects.Load() != 1 {
				t.Fatal("construction refusal reached custody or effects")
			}
		})
	}
}

// full_only: false
func TestGeneratedNormalRemovalThenGeneratedReaddKeepsOldDuty(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, row, effects, author := normalHandoffGeneratedFixture(t, recovery)
			old := *s.valueEntry(0)
			parent := admitSuppliedComparison(t, s, keys, nil, row)
			c, res := s.Compare(context.Background(), nil, parent)
			if c == nil {
				t.Fatal(res)
			}
			candidate, res := s.Prepare(context.Background(), c, admit(t, s, c), env.Trust)
			if candidate == nil {
				t.Fatal(res)
			}
			removed, res := s.selectCandidate(context.Background(), candidate)
			if removed == nil {
				t.Fatal(res)
			}
			keys.RetireApply()
			removed = generatedLifecycleReopen(t, t.Context(), removed, env.Store)
			dutyID, err := contract.GeneratorDutyID(s.root.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
			if err != nil {
				t.Fatal(err)
			}
			intent, body := hermeticCloudflareIntent()
			profile := nativeGeneratedFixtureProfile(t, row)
			input := generatedPlanInputForGenerationsIntent(t, removed, generatedVectorID(248), []string{old.Name}, intent, profile)
			input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(body)
			readded := author.create(removed, input)
			readded = generatedLifecycleReopen(t, t.Context(), readded, env.Store)
			fresh := readded.valueEntry(0)
			if fresh.Incarnation == old.Incarnation || fresh.Generated.RetiringDutyPresent != 1 || fresh.Generated.RetiringDutyID != dutyID || readded.root.Generated.Retiring != 1 || effects.Load() != 2 {
				t.Fatal("readd lost original retirement or membership freshness")
			}
			work, err := readded.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			duty, err := contract.InspectGeneratedDutyRecord(work.records[generatedRecordKey{10, dutyID}].Body)
			if err != nil {
				t.Fatal(err)
			}
			target, err := work.retirementTarget(t.Context(), duty)
			if err != nil || target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest {
				t.Fatal("readd redirected old exact target", err)
			}
			changed := []ApplyEntryInput{suppliedSecret(t, env, old.Name, "further displacement", custody.StandardValue)}
			comparison, res := readded.compareEntryInputs(changed)
			if comparison == nil {
				t.Fatal(res)
			}
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			if _, err := readded.generatedSupportTransition(context.Background(), comparison, fixtureGeneratedSupportHandoffs(t, readded, comparison, []contract.GeneratorImplementation{row})); err == nil || creates != store.creates || cas != store.cas || effects.Load() != 2 {
				t.Fatal("further displacement reached effects")
			}
		})
	}
}

// full_only: false
func TestGeneratedNormalRemovalThenSuppliedSecretReaddKeepsOldDuty(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, row, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			old := *s.valueEntry(0)
			parent := admitSuppliedComparison(t, s, keys, nil, row)
			c, res := s.Compare(context.Background(), nil, parent)
			if c == nil {
				t.Fatal(res)
			}
			candidate, res := s.Prepare(context.Background(), c, admit(t, s, c), env.Trust)
			if candidate == nil {
				t.Fatal(res)
			}
			removed, res := s.selectCandidate(context.Background(), candidate)
			if removed == nil {
				t.Fatal(res)
			}
			keys.RetireApply()
			removed = generatedLifecycleReopen(t, t.Context(), removed, env.Store)
			dutyID, err := contract.GeneratorDutyID(s.root.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
			if err != nil {
				t.Fatal(err)
			}
			before, err := removed.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			dutyBody := contract.Hash(before.records[generatedRecordKey{10, dutyID}].Body)
			input := []ApplyEntryInput{suppliedSecret(t, env, old.Name, "separate supplied readd", custody.StandardValue)}
			parent = admitSuppliedComparison(t, removed, keys, input)
			c, res = removed.Compare(context.Background(), input, parent)
			if c == nil {
				t.Fatal(res)
			}
			candidate, res = removed.Prepare(context.Background(), c, admit(t, removed, c), env.Trust)
			if candidate == nil {
				t.Fatal(res)
			}
			added, res := removed.selectCandidate(context.Background(), candidate)
			if added == nil {
				t.Fatal(res)
			}
			keys.RetireApply()
			added = generatedLifecycleReopen(t, t.Context(), added, env.Store)
			after, err := added.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			fresh := added.valueEntry(0)
			if fresh.ValueSource != contract.Supplied || fresh.Incarnation == old.Incarnation || fresh.ValueState == old.ValueState || added.root.Generated.Retiring != 1 || contract.Hash(after.records[generatedRecordKey{10, dutyID}].Body) != dutyBody || effects.Load() != 1 {
				t.Fatal("separate Supplied readd changed exact old Duty")
			}
		})
	}
}

// full_only: false
func TestGeneratedFinalReceiptRequiresExactOwnHazards(t *testing.T) {
	for _, fault := range []string{"exact", "missing-warning", "missing-count", "extra-count", "wrong-id", "wrong-domain"} {
		t.Run(fault, func(t *testing.T) {
			s, input := generatedTerminalMutationFixture(t, false)
			input.RequestedRevisionID = s.head.Core.Revision
			delta, retained, err := s.generatedTerminalMutation(t.Context(), input)
			if err != nil || !retained {
				t.Fatal(err)
			}
			subject := contract.GeneratorAuthoritySubject{OperationID: input.Parent.OperationID, RequestIdentityDigest: input.Parent.RequestIdentityDigest, ResultVector: contract.GeneratorDescriptor{Count: uint32(len(input.Effects))}}
			switch fault {
			case "missing-warning":
				delta.NewReceipt.WarningBits &^= contract.ReceiptWarningPossibleLive
			case "missing-count":
				delta.NewReceipt.SummaryCounts[contract.ReceiptHazardCount] = 0
			case "extra-count":
				delta.NewReceipt.SummaryCounts[contract.ReceiptHazardCount]++
			case "wrong-id":
				input.Hazards[0].RecordID = testID("wrong own Hazard ID")
			case "wrong-domain":
				h, err := contract.InspectGeneratedHazardRecord(input.Hazards[0].Body)
				if err != nil {
					t.Fatal(err)
				}
				h.DomainID = testID("wrong own Hazard domain")
				input.Hazards[0].Body, err = contract.EncodeGeneratedHazardRecord(h)
				if err != nil {
					t.Fatal(err)
				}
			}
			rows, successes, failures, order, err := s.generatedReceiptSupport(input.Hazards, delta, input.Parent.RequestIdentityDigest)
			if err != nil {
				if fault == "exact" {
					t.Fatal(err)
				}
				return
			}
			for _, row := range s.supportRecords() {
				if row.Kind == contract.OutputConfigurationSliceSupportKind {
					rows = append(rows, row)
				}
			}
			slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
				if a.Kind != b.Kind {
					return int(a.Kind) - int(b.Kind)
				}
				return bytes.Compare(a.RecordID[:], b.RecordID[:])
			})
			for _, row := range rows {
				domain, err := contract.SupportRecordDomain(row)
				if err != nil || (!domain.IsZero() && domain != s.root.Domain) {
					if fault == "wrong-id" || fault == "wrong-domain" {
						return
					}
					t.Fatal("receipt validator row setup", row.Kind, err, domain, s.root.Domain)
				}
			}
			var records, fragments []contract.SupportRecord
			for _, row := range rows {
				if row.Kind == 3 {
					fragments = append(fragments, row)
				} else {
					records = append(records, row)
				}
			}
			// These complete candidate rows replace the selected image and its facts.
			s.clearSelectedSupportFacts()
			s.selectedReceiptRoot = format.Ref{}
			s.support = nil
			s.root.RequiredSupport = nil
			s.root.RequiredSupportRecordCount = 0
			var pages []format.RequiredSupportPage
			for i, group := range [][]contract.SupportRecord{records, fragments} {
				page := format.RequiredSupportPage{Domain: s.root.Domain, Object: testID(fmt.Sprint("own Hazard receipt page", i)), Index: uint16(i), Records: group}
				body, err := format.EncodeRequiredSupportPage(page)
				if err != nil {
					if fault == "wrong-id" || fault == "wrong-domain" {
						return
					}
					t.Fatal(err)
				}
				view, err := format.InspectRequiredSupportPage(body)
				if err != nil {
					t.Fatal(err)
				}
				ref, err := format.Reference(contract.RequiredSupportKind, page.Domain, page.Object, page.Index, body)
				if err != nil {
					t.Fatal(err)
				}
				s.support = append(s.support, view)
				s.root.RequiredSupport = append(s.root.RequiredSupport, ref)
				s.root.RequiredSupportRecordCount += uint32(len(group))
				pages = append(pages, page)
			}
			s.root.Generated.Fragments, err = generatedFragmentDirectory(pages)
			if err != nil {
				t.Fatal(err)
			}
			s.root.Generated.SuccessWindow, s.root.Generated.FailureWindow, s.root.Generated.ReceiptOrder = successes, failures, order
			if err := s.validateGeneratedFinalReceipt(t.Context(), subject, false); (err == nil) != (fault == "exact") {
				t.Fatal("terminal own Hazard receipt validation", fault, err)
			}
		})
	}
}

// full_only: false
func TestGeneratedOrdinaryCurrentNoopGrantAndExclusion(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, _, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			ctx := context.Background()
			old := *s.valueEntry(0)
			store := env.Store.(*memoryStore)
			cas := store.cas
			input := s.currentEntryInputs()
			parent := admitSuppliedComparison(t, s, keys, input)
			if c, result := s.Compare(ctx, input, parent); c != nil || result.Outcome != Unchanged || store.cas != cas || effects.Load() != 1 {
				t.Fatal("Source2 exact current no-op", result)
			}
			keys.RetireApply()
			reader := fixtureID(env.Domain, "reader")
			input[0].Recipients = append(input[0].Recipients, reader)
			slices.SortFunc(input[0].Recipients, func(a, b contract.ID) int { return compareMaterial(1, a, 1, b) })
			parent = admitSuppliedComparison(t, s, keys, input)
			c, result := s.Compare(ctx, input, parent)
			if c == nil {
				t.Fatal("Source2 grant comparison", result)
			}
			candidate, result := s.Prepare(ctx, c, admit(t, s, c), env.Trust)
			if candidate == nil {
				t.Fatal("Source2 grant preparation", result)
			}
			granted, result := s.selectCandidate(ctx, candidate)
			if granted == nil || result.Outcome != ObservedCurrent {
				t.Fatal("Source2 grant selection", result)
			}
			keys.RetireApply()
			granted = generatedLifecycleReopen(t, ctx, granted, env.Store)
			entry := *granted.valueEntry(0)
			if entry.Incarnation != old.Incarnation || entry.ValueState != old.ValueState || entry.Generated != old.Generated || !bytes.Equal(entry.ValueBytes, old.ValueBytes) || granted.root.Generated.Retiring != 0 || effects.Load() != 1 {
				t.Fatal("Source2 grant changed generated resource/material")
			}
			input = granted.currentEntryInputs()
			input[0].Recipients = []contract.ID{granted.admission.recipient}
			parent = admitSuppliedComparison(t, granted, keys, input)
			c, result = granted.Compare(ctx, input, parent)
			if c == nil {
				t.Fatal("Source2 exclusion comparison", result)
			}
			candidate, result = granted.Prepare(ctx, c, admit(t, granted, c), env.Trust)
			if candidate == nil {
				t.Fatal("Source2 exclusion preparation", result)
			}
			excluded, result := granted.selectCandidate(ctx, candidate)
			if excluded == nil || result.Outcome != ObservedCurrent {
				t.Fatal("Source2 exclusion selection", result)
			}
			keys.RetireApply()
			excluded = generatedLifecycleReopen(t, ctx, excluded, env.Store)
			fresh := *excluded.valueEntry(0)
			meta := entry.Generated
			meta.GenerationID = fresh.ValueState
			if fresh.Incarnation != old.Incarnation || fresh.ValueState == old.ValueState || fresh.Generated != meta || fresh.OriginSnapshot != excluded.root.Snapshot || fresh.OriginTransition != excluded.root.Transition || bytes.Equal(fresh.ValueBytes, old.ValueBytes) || excluded.root.Generated.Retiring != 0 || effects.Load() != 1 || store.cas != cas+2 {
				t.Fatal("Source2 exclusion did not rekey only current generated material")
			}
		})
	}
}

// full_only: false
func TestInstalledGeneratedNormalHandoffPreservesExactOldDuty(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, ending := range []string{"remove", "supplied"} {
			t.Run(fmt.Sprintf("recovery=%t/%s", recovery, ending), func(t *testing.T) {
				env, keys, selected, _, effects, author := normalHandoffGeneratedFixture(t, recovery)
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				f := installedApplyTestFixture{env: env, keys: keys, basis: selected.admission.publicBasis(), composition: selected.admission.composition,
					admitted: OpenContext{admission: &selected.admission}, selected: selected}
				native := installedGeneratedTestCallbacks(t, f, author.process)
				support := &GeneratedApplyInstallation{ResolveImplementation: native.ResolveImplementation, CheckRetirementCompatibility: native.CheckRetirementCompatibility}
				validator := NewPublicConfigurationValidator(nil)
				old := *selected.valueEntry(0)
				apply := func(label string, input []ApplyEntryInput) PublicApplyResult {
					t.Helper()
					engine := f.engineWithValidator(t, selected, input, currentApplyRecipients(selected.registry()), validator, nil, support)
					defer engine.Close()
					result := engine.Apply(ctx, fixtureID(env.Domain, label), input)
					if result.Result.Outcome == ObservedCurrent {
						selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
					}
					if effects.Load() != 1 {
						t.Fatal("normal installed handoff started another generation")
					}
					return result
				}
				if result := apply("installed generated repeat", selected.currentEntryInputs()); result.Result.Outcome != Unchanged {
					t.Fatal("unchanged generated declaration refused", result.Result)
				}
				input := selected.currentEntryInputs()
				input[0].Recipients = append(input[0].Recipients, fixtureID(env.Domain, "reader"))
				slices.SortFunc(input[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				if result := apply("installed generated grant", input); result.Result.Outcome != ObservedCurrent {
					t.Fatal("generated grant refused", result.Result)
				}
				if granted := selected.valueEntry(0); granted.ValueState != old.ValueState || !bytes.Equal(granted.ValueBytes, old.ValueBytes) {
					t.Fatal("grant changed generated material")
				}
				input = selected.currentEntryInputs()
				input[0].Recipients = []contract.ID{selected.admission.recipient}
				if result := apply("installed generated exclusion", input); result.Result.Outcome != ObservedCurrent {
					t.Fatal("generated exclusion refused", result.Result)
				}
				current := *selected.valueEntry(0)
				if current.ValueState == old.ValueState || current.Generated.ResourceIncarnationID != old.Generated.ResourceIncarnationID || bytes.Equal(current.ValueBytes, old.ValueBytes) {
					t.Fatal("exclusion did not refresh protection for the same generated resource")
				}
				input = nil
				if ending == "supplied" {
					input = []ApplyEntryInput{suppliedSecret(t, env, current.Name, "installed generated source change", custody.StandardValue)}
				}
				result := apply("installed generated ending", input)
				if result.Result.Outcome != ObservedCurrent {
					t.Fatal("generated removal or source conversion refused", result.Result)
				}
				retained, observed := selected.MutationReceipt(ctx, result.OperationID)
				if observed.Outcome != ObservedCurrent || !bytes.Equal(retained, result.Receipt) {
					t.Fatal("normal handoff returned a different retained receipt", observed)
				}
				receipt, err := contract.InspectCompactMutationReceipt(result.Receipt)
				if err != nil || receipt.StateResult != contract.ReceiptStateRetirementPending || receipt.SummaryCounts[contract.ReceiptDutyCount] != 1 || receipt.SummaryCounts[contract.ReceiptEffectCount] != 0 || receipt.EffectSummary != contract.ReceiptEffectNoChange {
					t.Fatal("new retirement duty did not report retirement-pending with zero dispatched effects", receipt.StateResult, receipt.SummaryCounts, receipt.EffectSummary, err)
				}
				work, err := selected.selectedGeneratedWork(ctx)
				if err != nil || selected.root.Generated.Retiring != 1 {
					t.Fatal("old generated retirement obligation lost", err)
				}
				var duties []contract.SupportRecord
				for key, record := range work.records {
					if key.kind == contract.GeneratedDutySupportKind {
						duties = append(duties, record)
					}
				}
				if len(duties) != 1 || result.Payload == nil || !slices.Equal(result.Payload.LiveDutyIDs, []contract.ID{duties[0].RecordID}) || len(result.Payload.LiveHazardIDs) != 0 {
					t.Fatal("normal result omitted or added live work")
				}
				if result.Generated == nil || !result.Generated.EffectsAvailable || len(result.Generated.Effects) != 0 || !result.Generated.RelatedWorkAvailable ||
					!slices.Equal(result.Generated.RelatedDutyIDs, []contract.ID{duties[0].RecordID}) || len(result.Generated.RelatedHazardIDs) != 0 || len(result.Generated.Duties) != 1 ||
					result.Generated.Duties[0].Record.DutyID != duties[0].RecordID || result.Generated.StateResult != "retirement-pending" || result.Generated.EffectSummary != contract.ReceiptEffectNoChange {
					t.Fatal("normal handoff lost its exact invocation-related duty")
				}
				record := duties[0]
				duty, err := contract.InspectGeneratedDutyRecord(record.Body)
				if err != nil || duty.Kind != contract.GeneratedDutyRetirement || duty.ResourceID != old.Generated.ResourceIncarnationID || duty.OriginalOperationID != old.Generated.OriginOperationID || duty.OriginalAttemptID != old.Generated.OriginAttemptID {
					t.Fatal("retirement duty changed its original resource")
				}
				if ending == "remove" && len(selected.root.Names) != 0 {
					t.Fatal("removal did not select absence")
				}
				if ending == "supplied" {
					next := selected.valueEntry(0)
					if next.ValueSource != contract.Supplied || next.Incarnation == old.Incarnation {
						t.Fatal("source conversion did not start a fresh supplied incarnation")
					}
				}
				afterInput := slices.Clone(input)
				afterInput = append(afterInput, ApplyEntryInput{Name: "after", ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("ordinary change preserves an older retirement"), InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
				slices.SortFunc(afterInput, func(a, b ApplyEntryInput) int { return strings.Compare(a.Name, b.Name) })
				after := apply("installed ordinary change with inherited retirement", afterInput)
				if after.Result.Outcome != ObservedCurrent || after.Payload == nil || !slices.Equal(after.Payload.LiveDutyIDs, []contract.ID{duties[0].RecordID}) || after.Generated != nil && len(after.Generated.RelatedDutyIDs) != 0 {
					t.Fatal("ordinary successor reclassified inherited work as its own handoff", after.Result)
				}
				afterReceipt, err := contract.InspectCompactMutationReceipt(after.Receipt)
				if err != nil || afterReceipt.StateResult != contract.ReceiptStateSuccess || afterReceipt.EffectSummary != contract.ReceiptEffectNoChange || afterReceipt.SummaryCounts[contract.ReceiptDutyCount] != 1 {
					t.Fatal("inherited retirement changed ordinary success", err)
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedToSuppliedSecretStartsFreshEntryIncarnation(t *testing.T) {
	for _, choice := range []uint8{custody.StandardValue, custody.HermeticCloudflareValue} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/%t", choice, recovery), func(t *testing.T) {
				env, keys, s, row, effects, _ := normalHandoffGeneratedFixture(t, recovery)
				old := *s.valueEntry(0)
				input := []ApplyEntryInput{suppliedSecret(t, env, old.Name, "normal changed source", choice)}
				parent := admitSuppliedComparison(t, s, keys, input, row)
				c, result := s.Compare(context.Background(), input, parent)
				if c == nil {
					t.Fatal("source-kind comparison", result)
				}
				if len(c.secretRows) != 1 || choice == custody.HermeticCloudflareValue && c.secretRows[0].Relation != contract.CryptoEqual || choice == custody.StandardValue && c.secretRows[0].Relation != contract.CryptoChanged {
					t.Fatal("source-kind value characterization", c.secretRows)
				}
				permit := admit(t, s, c)
				if permit.plan.incarnations[0].IsZero() {
					t.Fatal("source-kind plan omitted fresh incarnation")
				}
				candidate, result := s.Prepare(context.Background(), c, permit, env.Trust)
				if candidate == nil {
					t.Fatal("source-kind preparation", result)
				}
				selected, result := s.selectCandidate(context.Background(), candidate)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("source-kind selection", result)
				}
				keys.RetireApply()
				selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
				fresh := selected.valueEntry(0)
				if fresh.ValueSource != contract.Supplied || fresh.Incarnation == old.Incarnation || fresh.ValueState == old.ValueState || fresh.OriginSnapshot != selected.root.Snapshot || fresh.OriginTransition != selected.root.Transition || selected.root.Generated.Retiring != 1 || effects.Load() != 1 || selected.head.Subject.Grant.Grants.Count != 1 || selected.head.Subject.Exclusion.Exclusions.Count != 1 {
					t.Fatal("source-kind did not start a fresh supplied entry incarnation and value state")
				}
			})
		}
	}
}

// full_only: false
func TestGeneratedNormalHandoffUsesProspectiveCurrentIntents(t *testing.T) {
	for _, full := range []bool{false, true} {
		label := "partial"
		if full {
			label = "full"
		}
		t.Run(label, func(t *testing.T) {
			ctx := t.Context()
			env, keys, selected, row, effects, author := normalHandoffGeneratedFixture(t, false)
			intent, requestBody := hermeticCloudflareIntent()
			profile := nativeGeneratedFixtureProfile(t, row)
			input := generatedPlanInputWithCurrentGenerated(t, selected,
				fixtureID(env.Domain, "two-current normal handoff"), []string{"second"}, profile, intent)
			input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
			selected = author.create(selected, input)
			keys.RetireGenerated()
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			if selected.root.Generated.GeneratedCurrent != 2 || effects.Load() != 2 {
				t.Fatal("normal handoff fixture lacks two real current generated entries")
			}
			before := make(map[string]contract.ValueEntry, 2)
			originReceipts := make(map[contract.ID][]byte, 2)
			for _, named := range selected.root.Names {
				entry := selected.valueEntry(named.Slot)
				if entry == nil || entry.ValueSource != contract.Generated || entry.Generated.OriginOperationID.IsZero() {
					t.Fatal("normal predecessor lacks a generated origin", named.Name)
				}
				origin := entry.Generated.OriginOperationID
				if _, duplicate := originReceipts[origin]; duplicate {
					t.Fatal("normal predecessors share an origin operation")
				}
				receipt, observed := selected.MutationReceipt(ctx, origin)
				if observed.Outcome != ObservedCurrent || len(receipt) == 0 {
					t.Fatal("normal predecessor lacks its selected receipt", observed)
				}
				originReceipts[origin] = bytes.Clone(receipt)
				before[named.Name] = *entry
			}
			if len(before) != 2 || len(originReceipts) != 2 {
				t.Fatal("normal predecessor lacks two distinct generated origins")
			}
			proposed := selected.currentEntryInputs()
			for i := range proposed {
				if proposed[i].Name == "generated" || full {
					proposed[i] = suppliedSecret(t, env, proposed[i].Name, label+" normal source", custody.StandardValue)
				}
			}
			parent := admitSuppliedComparison(t, selected, keys, proposed, row)
			comparison, result := selected.Compare(ctx, proposed, parent)
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("two-current normal comparison", result)
			}
			permit := admit(t, selected, comparison)
			if !full {
				// A retained current value and a retiring value occupy distinct
				// OldValueSupport partitions. Count encoded pages independently
				// of the capacity calculator before Prepare can spend authority.
				work, err := selected.selectedGeneratedWork(ctx)
				if err != nil {
					t.Fatal("normal predecessor work", err)
				}
				output, err := generatedNormalSupportRows(comparison, permit.plan)
				if err != nil {
					t.Fatal("normal successor support rows", err)
				}
				var locations []contract.GeneratorSliceLocation
				for _, location := range work.content.locations {
					locations = append(locations, location)
				}
				entryMetadata, err := prospectiveNormalGeneratedEntryMetadata(comparison)
				if err != nil {
					t.Fatal("normal prospective generated entries", err)
				}
				groups, err := generatedReservationGroupsFromEntries(entryMetadata, selected, output.Records, locations, work.bundles)
				if err != nil {
					t.Fatal("normal physical owner groups", err)
				}
				oldRows := make(map[generatedRecordKey]bool)
				var mandatory, disposable bool
				for _, group := range groups {
					if group.Class != format.OldValueSupport {
						continue
					}
					for _, record := range group.Records {
						oldRows[generatedRecordKey{kind: record.Kind, id: record.RecordID}] = group.Mandatory
					}
					if group.Mandatory {
						mandatory = true
					} else {
						disposable = true
					}
				}
				packed, err := normalSupportPacking(ctx, comparison, permit.plan)
				if err != nil {
					t.Fatal("normal physical support packing", err)
				}
				oldPages := 0
				for _, page := range packed {
					pageOld := false
					for _, record := range page.records {
						_, isOld := oldRows[generatedRecordKey{kind: record.Kind, id: record.RecordID}]
						if isOld {
							pageOld = true
						}
					}
					if pageOld {
						oldPages++
					}
				}
				wantOldRows := map[generatedRecordKey]bool{
					{kind: contract.GeneratedCreateEvidenceSupportKind, id: before["second"].Generated.CreateResultID}:    true,
					{kind: contract.GeneratedCreateEvidenceSupportKind, id: before["generated"].Generated.CreateResultID}: false,
				}
				bound := comparison.support.Groups[contract.GeneratorCapacityOldValues]
				if !mandatory || !disposable || !reflect.DeepEqual(oldRows, wantOldRows) || oldPages != 2 || bound.MaxCount != uint64(len(oldRows)) || bound.MaxPages != uint32(oldPages) {
					t.Fatal("normal old-value bound lost exact owners or a physical page", oldRows, wantOldRows, oldPages, bound)
				}
			}
			candidate, result := selected.Prepare(ctx, comparison, permit, env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("two-current normal preparation", result)
			}
			changed, result := selected.selectCandidate(ctx, candidate)
			if changed == nil || result.Outcome != ObservedCurrent {
				t.Fatal("two-current normal selection", result)
			}
			keys.RetireApply()
			cold := generatedLifecycleReopen(t, ctx, changed, env.Store)
			wantCurrent := uint32(1)
			if full {
				wantCurrent = 0
			}
			if cold.root.Generated.GeneratedCurrent != wantCurrent || cold.root.Generated.Retiring != uint32(1+boolInt(full)) || effects.Load() != 2 {
				t.Fatal("normal handoff changed current values or provider effects", cold.root.Generated, effects.Load())
			}
			for _, named := range cold.root.Names {
				entry := cold.valueEntry(named.Slot)
				prior := before[named.Name]
				if entry == nil {
					t.Fatal("normal handoff lost a value", named.Name)
				}
				if named.Name == "second" && !full {
					if entry.ValueSource != contract.Generated || entry.Generated.IntentDigest != prior.Generated.IntentDigest ||
						entry.Generated.OriginAttemptID != prior.Generated.OriginAttemptID {
						t.Fatal("partial handoff changed the surviving generated owner")
					}
					check := keys.Consume(ctx, sessionConsumerSelection(t, cold, cold.admission.recipient, named.Name),
						custody.HermeticCloudflareValue)
					if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched {
						t.Fatal("partial handoff lost the surviving private value", check)
					}
				} else if entry.ValueSource != contract.Supplied || entry.Incarnation == prior.Incarnation {
					t.Fatal("normal handoff did not replace the intended generated owner", named.Name)
				}
			}
			for origin, want := range originReceipts {
				receipt, observed := cold.MutationReceipt(ctx, origin)
				if observed.Outcome != ObservedCurrent || !bytes.Equal(receipt, want) {
					t.Fatal("normal handoff changed an origin receipt", observed)
				}
			}
			if _, err := cold.selectedGeneratedWork(context.Background()); err != nil {
				t.Fatal("normal handoff lost complete generated ownership", err)
			}
		})
	}
}

// full_only: false
func TestGeneratedNormalHandoffHistoryPreservesCompleteBacklog(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := context.Background()
			env, keys, selected, implementation, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			profile := nativeGeneratedFixtureProfile(t, implementation)
			input := generatedPlanInputWithCurrentGenerated(t, selected, fixtureID(env.Domain, "normal history protected backlog"), []string{"alpha", "omega"}, profile)
			selected, failed := selectPrivateOwnedUnusableAggregateFromInput(t, env, selected, []string{"alpha", "omega"}, input, nil)
			selected = generatedLifecycleReopen(t, ctx, selected, env.Store)
			old := *selected.valueEntry(0)
			store := env.Store.(*memoryStore)
			startCAS := store.cas
			baseline := mustSelectedGeneratedWork(t, selected)
			baselineRows, err := selected.preservedWorkSupportRecords(t.Context())
			if err != nil {
				t.Fatal("normal history protected backlog", err)
			}
			var protectedDuty, protectedHazard contract.ID
			for key := range baseline.records {
				switch key.kind {
				case 10:
					row := baseline.records[key]
					duty, dutyErr := contract.InspectGeneratedDutyRecord(row.Body)
					if dutyErr == nil && duty.Kind == contract.GeneratedDutyUnselectedCleanup {
						protectedDuty = key.id
					}
				case 11:
					protectedHazard = key.id
				}
			}
			if protectedDuty.IsZero() || protectedHazard != failed.expected.Template.HazardID {
				t.Fatal("normal history fixture lacks real Duty and Hazard", protectedDuty, protectedHazard)
			}
			baselineAttempts := make(map[contract.ID]generatedAttempt, len(baseline.attempts))
			baselineResults := make(map[string]stored)
			for id, attempt := range baseline.attempts {
				baselineAttempts[id] = attempt
				if len(attempt.result) == 0 {
					continue
				}
				key, keyErr := format.GeneratedResultKey(selected.admission.store.Prefix, selected.root.Domain, attempt.record.InboxID)
				object := store.objects[key]
				if keyErr != nil || len(object.Body) == 0 || !bytes.Equal(object.Body, attempt.result) {
					t.Fatal("normal history missing protected late-result coordinate", keyErr)
				}
				object.Body = bytes.Clone(object.Body)
				baselineResults[key] = object
			}
			baselineAccess := make(map[materialIdentity][]byte, len(baseline.consumers))
			baselineConsumers := make(map[materialIdentity][][]byte, len(baseline.consumers))
			encodeConsumers := func(rows []contract.GeneratorConsumer) [][]byte {
				bodies := make([][]byte, len(rows))
				for i, row := range rows {
					var encodeErr error
					bodies[i], encodeErr = contract.EncodeGeneratorConsumer(row)
					if encodeErr != nil {
						t.Fatal("normal history consumer", encodeErr)
					}
				}
				slices.SortFunc(bodies, bytes.Compare)
				return bodies
			}
			for material, consumers := range baseline.consumers {
				access, present := selected.materialAccess(material.kind, material.id)
				body, accessErr := contract.EncodeAccessRecord(access)
				if !present || accessErr != nil {
					t.Fatal("normal history missing protected reader", present, accessErr)
				}
				baselineAccess[material] = body
				baselineConsumers[material] = encodeConsumers(consumers)
			}
			var stableWork []contract.SupportRecord
			var dutyID contract.ID
			name := selected.valueEntry(0).Name

			for i := 0; i < 128; i++ {
				var input []ApplyEntryInput
				switch i {
				case 0:
					input = []ApplyEntryInput{suppliedSecret(t, env, name, "normal history source-kind", custody.StandardValue)}
				case 1:
					input = nil
				case 2:
					input = []ApplyEntryInput{{Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
						Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte("normal history re-add")}}
				default:
					input = []ApplyEntryInput{{Name: name, ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain,
						Recipients: []contract.ID{selected.admission.recipient}, InputBytes: []byte(fmt.Sprintf("normal history %03d", i))}}
				}
				parent := admitSuppliedComparison(t, selected, keys, input, implementation)
				comparison, result := selected.Compare(ctx, input, parent)
				if comparison == nil {
					t.Fatal("normal history comparison", i, result)
				}
				candidate, result := selected.Prepare(ctx, comparison, admit(t, selected, comparison), env.Trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("normal history preparation", i, result)
				}
				next, result := selected.selectCandidate(ctx, candidate)
				if next == nil || result.Outcome != ObservedCurrent || store.cas != startCAS+i+1 {
					t.Fatal("normal history selection", i, result, store.cas-startCAS)
				}
				keys.RetireApply()
				selected = generatedLifecycleReopen(t, ctx, next, env.Store)
				current, currentErr := selected.selectedGeneratedWork(context.Background())
				if currentErr != nil || effects.Load() != 1 {
					t.Fatal("normal history selected work", i, currentErr)
				}
				assertGeneratedWorkRowsRemain(t, selected, baselineRows)
				for id, before := range baselineAttempts {
					after, present := current.attempts[id]
					if !present || !reflect.DeepEqual(before, after) {
						t.Fatal("normal history changed protected Attempt or late-result coordinate", i, id)
					}
				}
				for material, before := range baselineAccess {
					after, present := selected.materialAccess(material.kind, material.id)
					body, accessErr := contract.EncodeAccessRecord(after)
					if !present || accessErr != nil || !bytes.Equal(before, body) || !reflect.DeepEqual(baselineConsumers[material], encodeConsumers(current.consumers[material])) {
						t.Fatal("normal history changed protected reader or consumed right", i, material, accessErr)
					}
				}
				for key, before := range baselineResults {
					after := store.objects[key]
					if before.Token != after.Token || !bytes.Equal(before.Body, after.Body) {
						t.Fatal("normal history changed protected result object", i, key)
					}
				}
				if i == 0 {
					stableWork, err = selected.preservedWorkSupportRecords(t.Context())
					if err != nil {
						t.Fatal("normal history backlog", err)
					}
					dutyID, err = contract.GeneratorDutyID(env.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
					row, present := current.records[generatedRecordKey{kind: 10, id: dutyID}]
					duty, dutyErr := contract.InspectGeneratedDutyRecord(row.Body)
					target, targetErr := current.retirementTarget(t.Context(), duty)
					if err != nil || dutyErr != nil || targetErr != nil || !present || selected.root.Generated.Retiring != 1 ||
						target.ResourceID != old.Generated.ResourceIncarnationID || target.ResourceDigest != old.Generated.ResourceDigest ||
						target.OriginalAttemptID != old.Generated.OriginAttemptID || target.OriginalOperationID != old.Generated.OriginOperationID {
						t.Fatal("normal history source-kind backlog", err, selected.root.Generated)
					}
				} else {
					retained, retainedErr := selected.preservedWorkSupportRecords(t.Context())
					if retainedErr != nil || !reflect.DeepEqual(stableWork, retained) {
						t.Fatal("normal history changed immutable backlog", i, retainedErr)
					}
					row, present := current.records[generatedRecordKey{kind: 10, id: dutyID}]
					if !present || slices.IndexFunc(stableWork, func(want contract.SupportRecord) bool {
						return want.Kind == row.Kind && want.RecordID == row.RecordID && bytes.Equal(want.Body, row.Body)
					}) < 0 {
						t.Fatal("normal history changed exact retirement Duty", i)
					}
				}
			}
			if store.cas != startCAS+128 {
				t.Fatal("normal history selection count", store.cas-startCAS)
			}
		})
	}
}

func normalHandoffExpectedSupport(t testing.TB, parent *AdmittedParentComparison, old contract.ValueEntry, implementation contract.GeneratorImplementation) contract.GeneratorDescriptor {
	t.Helper()
	if parent == nil || parent.support == nil || len(parent.support.Handoffs) != 1 {
		t.Fatal("normal retirement requires one admitted handoff")
	}
	handoff := parent.support.Handoffs[0]
	if int(handoff.Current) >= len(parent.support.CurrentGenerated) || !reflect.DeepEqual(handoff.Implementation, implementation) {
		t.Fatal("normal retirement changed selected implementation or current row")
	}
	current := parent.support.CurrentGenerated[handoff.Current]
	entry, err := contract.InspectValueEntry(current.EntryBytes)
	if err != nil || string(entry.Name) != old.Name || entry.Incarnation != old.Incarnation || entry.Generated != old.Generated ||
		current.Target.Name != old.Name || current.Target.IncarnationID != old.Incarnation ||
		current.Target.OriginalOperationID != old.Generated.OriginOperationID || current.Target.OriginalAttemptID != old.Generated.OriginAttemptID {
		t.Fatal("normal retirement changed original entry or create identity", err)
	}
	route := implementation.CredentialRoute
	if len(route) < 40 || binary.BigEndian.Uint16(route[:2]) != 1 {
		t.Fatal("normal retirement lacks its exact credential route")
	}
	var routeContract contract.ID
	copy(routeContract[:], route[2:34])
	preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(route)))...)
	preimage = append(preimage, route...)
	routeID := contract.ID(sha256.Sum256(preimage))
	binding := contract.GeneratorSupportBinding{Schema: 2, Role: 7, ContractID: routeContract,
		ImplementationID: implementation.ExecutorID, PublicBindingDigest: routeID, Binding: route}
	if routeID != implementation.CredentialRouteID || !reflect.DeepEqual(handoff.Support, []contract.GeneratorSupportBinding{binding}) {
		t.Fatal("normal retirement changed the exact selected credential support")
	}

	// Frame the authored support row independently of SupportAfter and its codec.
	row := binary.BigEndian.AppendUint16(nil, 2)
	row = append(row, 7)
	for _, id := range []contract.ID{routeContract, implementation.ExecutorID, routeID} {
		row = append(row, id[:]...)
	}
	row = binary.BigEndian.AppendUint32(row, uint32(len(route)))
	row = append(row, route...)
	preimage = []byte("ENKV/GENERATOR/v1/support-bindings\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, 4)
	preimage = binary.BigEndian.AppendUint32(preimage, 0)
	empty := contract.GeneratorDescriptor{Length: 4, Digest: contract.ID(sha256.Sum256(preimage))}
	if old.Generated.RequiredSupport != empty {
		t.Fatal("fixture original Create support is not empty")
	}
	length := uint32(8 + len(row))
	preimage = []byte("ENKV/GENERATOR/v1/support-bindings\x00")
	preimage = binary.BigEndian.AppendUint32(preimage, length)
	preimage = binary.BigEndian.AppendUint32(preimage, 1)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(row)))
	preimage = append(preimage, row...)
	return contract.GeneratorDescriptor{Count: 1, Length: uint64(length), Digest: contract.ID(sha256.Sum256(preimage))}
}

// full_only: false
func TestGeneratedNormalRemovalRootsExactCleanDuty(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := context.Background()
			env, keys, selected, implementation, effects, _ := normalHandoffGeneratedFixture(t, recovery)
			old := *selected.valueEntry(0)
			beforeRows := selected.supportRecords()
			beforeSuccess, beforeFailure, beforeOrder := selected.root.Generated.SuccessWindow, selected.root.Generated.FailureWindow, selected.root.Generated.ReceiptOrder
			store := env.Store.(*memoryStore)
			cas := store.cas
			parent := admitSuppliedComparison(t, selected, keys, nil, implementation)
			wantSupport := normalHandoffExpectedSupport(t, parent, old, implementation)
			comparison, result := selected.Compare(ctx, nil, parent)
			if comparison == nil {
				t.Fatal("normal generated removal comparison", result)
			}
			permit := admit(t, selected, comparison)
			preview, err := selected.deriveSuccessor(t.Context(), comparison, permit.plan)
			if err != nil {
				t.Fatal("normal removal derivation")
			}
			pages, err := normalSupportPacking(ctx, comparison, permit.plan)
			if err != nil || len(pages) == 0 {
				t.Fatal("normal removal prospective packing", err)
			}
			usage, err := preview.normalCapacityUsage(ctx, comparison)
			if err != nil {
				t.Fatal("normal removal prospective capacity census")
			}
			for i, actual := range usage {
				bound := comparison.support.Groups[i]
				if actual.MaxCount > bound.MaxCount || actual.MaxFramedBytes > bound.MaxFramedBytes || actual.MaxPages > bound.MaxPages {
					t.Fatal("normal removal contributor exceeds bound", i, actual, bound)
				}
			}
			candidate, result := selected.Prepare(ctx, comparison, permit, env.Trust)
			if candidate == nil {
				t.Fatal("normal generated removal preparation", result)
			}
			removed, result := selected.selectCandidate(ctx, candidate)
			if removed == nil || result.Outcome != ObservedCurrent || store.cas != cas+1 || effects.Load() != 1 {
				t.Fatal("normal removal needs one whole selection", result, store.cas-cas)
			}
			keys.RetireApply()
			removed = generatedLifecycleReopen(t, ctx, removed, env.Store)
			if _, err := removed.validateRelationsMode(ctx, false); err != nil {
				t.Fatal("normal removal complete relations", err)
			}
			if removed.root.Generated.SuccessWindow != beforeSuccess || removed.root.Generated.FailureWindow != beforeFailure || removed.root.Generated.ReceiptOrder != beforeOrder {
				t.Fatal("normal handoff mutated terminal receipt windows")
			}
			for _, r := range beforeRows {
				if r.Kind != contract.MutationReceiptSupportKind {
					continue
				}
				after := removed.supportRecords()
				i := slices.IndexFunc(after, func(row contract.SupportRecord) bool { return row.Kind == r.Kind && row.RecordID == r.RecordID })
				if i < 0 || !bytes.Equal(after[i].Body, r.Body) {
					t.Fatal("normal handoff changed immutable receipt")
				}
			}
			work, err := removed.selectedGeneratedWork(context.Background())
			if err != nil || work.parent != nil || len(work.attempts) != 0 || removed.root.ValueEntryCount != 0 ||
				removed.root.Generated.GeneratedCurrent != 0 || removed.root.Generated.Retiring != 1 || !removed.root.Generated.ActiveOwner.IsZero() {
				t.Fatal("normal removal omitted clean detached retirement", err, removed.root.Generated)
			}
			id, err := contract.GeneratorDutyID(env.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
			if err != nil {
				t.Fatal(err)
			}
			row, ok := work.records[generatedRecordKey{kind: 10, id: id}]
			if !ok {
				t.Fatal("exact original retirement Duty absent")
			}
			duty, err := contract.InspectGeneratedDutyRecord(row.Body)
			if err != nil || duty.Support != wantSupport || duty.CompletionClass != old.Generated.CompletionClass || duty.Step != 1 || duty.Status != 1 {
				t.Fatal("normal handoff changed selected support/original class or started delete", err, duty)
			}
			target, err := work.retirementTarget(t.Context(), duty)
			if err != nil || target.ResourceDigest != old.Generated.ResourceDigest || target.ResourceID != old.Generated.ResourceIncarnationID ||
				target.Name != old.Name || target.IncarnationID != old.Incarnation {
				t.Fatal("normal handoff changed exact original resource", err, target)
			}
		})
	}
}

// full_only: false
func TestGeneratedMixedRealCreateSourceKind(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			env, keys, s, row, effects, author := normalHandoffGeneratedFixture(t, recovery)
			old := *s.valueEntry(0)
			source := suppliedSecret(t, env, old.Name, "mixed source kind", custody.StandardValue)
			entry := contract.GeneratorDeclarationEntry{InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw, Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationSealed, Name: source.Name, Recipients: source.Recipients, Payload: source.InputBytes}
			intent, requestBody := hermeticCloudflareIntent()
			profile := nativeGeneratedFixtureProfile(t, row)
			operation := generatedVectorID(241)
			state := generatedReservationInputForStateIntent(t, s, operation, []string{"new"}, intent, profile, 0, nil, map[string]contract.ValueEntry{old.Name: old}, entry)
			// The ordinary whole-set fixture preserves every present incarnation.
			// This source-kind change instead ends that membership and starts a new one.
			for i := range state.graph.ValueEntryPlans {
				if state.graph.ValueEntryPlans[i].Name == old.Name {
					state.graph.ValueEntryPlans[i].EntryIncarnationID = testID("mixed fresh supplied incarnation")
				}
			}
			var err error
			state.graph.UsePlan.PlanGraphID, err = contract.GeneratorGraphID(state.graph.Header, state.graph.ValueEntryPlans, state.graph.Lineages, state.graph.Edges)
			if err != nil {
				t.Fatal(err)
			}
			input := generatedPlanInputForGenerationsIntent(t, s, operation, []string{"new"}, intent, profile, entry)
			input.graph, input.declaration, input.registry = state.graph, state.declaration, state.graph.Request.Registry
			input.requestBindings[0].Digest = hermeticCloudflareHTTPRequestDigest(requestBody)
			selectedWork, err := s.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			declaration, err := contract.InspectGeneratorDeclaration(input.declaration)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.generatedAdmissionShape(t.Context(), input.graph, declaration, selectedWork); err != nil {
				t.Fatal("actual mixed source-kind shape", err)
			}
			membership, err := s.generatedMembershipPlan(input.graph, input.declaration)
			if err != nil {
				t.Fatal(err)
			}
			if generatedMembershipAuthority(membership) != 7 {
				t.Fatal("mixed source-kind omitted grant/exclusion authority", generatedMembershipAuthority(membership))
			}
			selected := author.create(s, input)
			keys.RetireGenerated()
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			receiptBody, receiptResult := selected.MutationReceipt(context.Background(), operation)
			receipt, err := contract.InspectCompactMutationReceipt(receiptBody)
			if receiptResult.Outcome != ObservedCurrent || err != nil ||
				receipt.SummaryCounts[contract.ReceiptChangedAccessCount] != 0 {
				t.Fatal("mixed fresh materials counted as same-material access changes", receiptResult, err)
			}
			var fresh *contract.ValueEntry
			for _, name := range selected.root.Names {
				if name.Name == old.Name {
					fresh = selected.valueEntry(name.Slot)
				}
			}
			if fresh == nil || fresh.ValueSource != contract.Supplied || fresh.Incarnation == old.Incarnation || fresh.ValueState == old.ValueState || selected.root.Generated.GeneratedCurrent != 1 || selected.root.Generated.Retiring != 1 || effects.Load() != 2 {
				t.Fatal("mixed source-kind whole selection", selected.root.Generated)
			}
			for _, name := range selected.root.Names {
				if name.Name == "new" && selected.valueEntry(name.Slot).Generated.ResourceDigest == old.Generated.ResourceDigest {
					t.Fatal("mixed response reused old live token")
				}
			}
			work, err := selected.selectedGeneratedWork(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			dutyID, err := contract.GeneratorDutyID(env.Domain, old.Generated.OriginOperationID, old.Generated.OriginAttemptID, 2)
			if err != nil {
				t.Fatal(err)
			}
			dutyRow, ok := work.records[generatedRecordKey{kind: 10, id: dutyID}]
			if !ok {
				t.Fatal("mixed old retirement absent")
			}
			duty, err := contract.InspectGeneratedDutyRecord(dutyRow.Body)
			if err != nil || duty.Support != old.Generated.RequiredSupport {
				t.Fatal("mixed original support changed", err)
			}
			target, err := work.retirementTarget(t.Context(), duty)
			if err != nil || target.ResourceDigest != old.Generated.ResourceDigest || target.ResourceID != old.Generated.ResourceIncarnationID {
				t.Fatal("mixed old target changed", err)
			}
		})
	}
}
