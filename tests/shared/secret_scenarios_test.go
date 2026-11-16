package core

import (
	"bytes"
	stdcontext "context"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
)

// This test-only parent starts with an authenticated selected session and the
// producer facade's independently retained source admission. Public request
// bytes alone cannot construct either private admission.
func admitSuppliedComparison(t testing.TB, s *StateSession, keys *custody.Fixture, input []ApplyEntryInput, registry ...contract.GeneratorImplementation) *AdmittedParentComparison {
	return admitSuppliedOutputComparison(t, s, keys, input, nil, registry...)
}

func admitSuppliedOutputComparison(t testing.TB, s *StateSession, keys *custody.Fixture, input []ApplyEntryInput, output *outputApplyInput, registry ...contract.GeneratorImplementation) *AdmittedParentComparison {
	t.Helper()
	installOutputFixtureSource(t, s, output)
	return admitSuppliedOutputComparisonWithInstalledProfiles(t, s, keys, input, output, registry...)
}

// Native profile callers retain their independently installed passive table.
func admitSuppliedOutputComparisonWithInstalledProfiles(t testing.TB, s *StateSession, keys *custody.Fixture, input []ApplyEntryInput, output *outputApplyInput, registry ...contract.GeneratorImplementation) *AdmittedParentComparison {
	t.Helper()
	c, result := s.compareEntryInputs(input)
	if c == nil {
		t.Fatal("supplied public comparison", result)
	}
	if output != nil {
		recipients := make([]contract.ID, 0, len(s.registry()))
		for _, recipient := range s.registry() {
			if recipient.Status == contract.CurrentRecipient {
				recipients = append(recipients, recipient.RecipientID)
			}
		}
		normalized, err := normalizeOutputApply(t.Context(), c.desiredEntries, recipients, s.admission.recipient, output, s.admission.outputInterpreter)
		if err != nil {
			t.Fatal("output parent normalization", err)
		}
		changed, result := s.outputApplyChangesSelected(t.Context(), c, normalized)
		if result.Outcome != 0 {
			t.Fatal("output parent meaning", result)
		}
		c.outputIntent, c.outputChanged = normalized, changed
	}
	deadline := time.Now().Add(time.Minute)
	if enclosing, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if callerDeadline, finite := enclosing.Deadline(); finite {
			deadline = callerDeadline
		}
	}
	if s.admission.expires.Before(deadline) {
		deadline = s.admission.expires
	}
	witness, err := s.generatedSupportTransition(stdcontext.Background(), c, fixtureGeneratedSupportHandoffs(t, s, c, registry))
	if err != nil {
		t.Fatal("generated normal predecessor admission", err)
	}
	if witness != nil {
		witness, err = witness.CopyMetadata()
		if err != nil {
			t.Fatal("generated normal predecessor metadata", err)
		}
	}
	secret := s.root.SecretCount != 0 || slices.ContainsFunc(c.desiredEntries, func(v ApplyEntryInput) bool { return v.ConfidentialityClass == contract.Secret })
	if !secret {
		if witness == nil {
			return nil
		}
		return &AdmittedParentComparison{session: s, support: witness, deadline: deadline}
	}
	root, err := contract.AppendRef(nil, s.head.Core.Root, contract.CanonicalSchema)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := contract.CryptoConditionDigest(matchedCondition(s.token))
	if err != nil {
		t.Fatal(err)
	}
	var admissionID, sessionID contract.ID
	if _, err := rand.Read(admissionID[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(sessionID[:]); err != nil {
		t.Fatal(err)
	}
	if admissionID.IsZero() || sessionID.IsZero() || admissionID == sessionID {
		t.Fatal("invalid fresh private comparison identities")
	}
	context := contract.ApplyContext{
		OperationClass: contract.CryptoOrdinaryLifecycle, AdmissionID: admissionID, SessionID: sessionID,
		DomainID: s.admission.domain, CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()),
		PredecessorHEADDigest: contract.Hash(s.body), OriginalConditionDigest: condition, IntentDescriptor: contract.DescriptorVector{Digest: c.desired, Length: c.desiredLength, Count: uint32(len(c.desiredEntries))}, CurrentAccessRoot: s.root.CurrentAccess.AccessRoot,
	}
	copy(context.PredecessorRootRef[:], root)
	request, ok := s.comparisonRequest(c, context)
	if !ok {
		t.Fatal("supplied comparison parent request differs from selected state")
	}
	var plain []contract.MembershipRow
	for _, entry := range s.root.Names {
		valueEntry := s.valueEntry(entry.Slot)
		if valueEntry == nil {
			t.Fatal("predecessor member is missing")
		}
		if valueEntry.ConfidentialityClass == format.Secret {
			continue
		}
		digest, err := contract.PublicValueEntryDigest(s.admission.domain, entry.Slot, *valueEntry)
		if err != nil {
			t.Fatal(err)
		}
		plain = append(plain, contract.MembershipRow{Name: valueEntry.Name, Slot: entry.Slot, Incarnation: valueEntry.Incarnation, Recipients: slices.Clone(valueEntry.Recipients), EntryDigest: digest})
	}
	control := contract.ControlCore{CurrentControl: s.root.CurrentAccess.Core.CurrentControl, AuthorityKMSBinding: *s.authority().CurrentBinding}
	support, err := s.supportDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.AdmitApply(request, control, s.registry(), plain, support, deadline, witness); err != nil {
		t.Fatal("supplied comparison custody admission", err)
	}
	body, err := contract.EncodeCryptoCompareRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	return &AdmittedParentComparison{session: s, crypto: keys.Crypto(), instance: keys.Crypto().InstanceID(), context: context, requestDigest: contract.Hash(body), requestLength: len(body), deadline: deadline, support: witness}
}

type suppliedAdmissionDeadlineTB struct {
	testing.TB
	deadline time.Time
}

func (t suppliedAdmissionDeadlineTB) Deadline() (time.Time, bool) { return t.deadline, true }

type suppliedAdmissionWithoutDeadlineTB struct{ testing.TB }

// full_only: false
func TestSuppliedComparisonUsesOriginalCallerDeadline(t *testing.T) {
	for _, path := range []string{"supplied", "output"} {
		t.Run(path, func(t *testing.T) {
			for _, boundary := range []string{"test_deadline", "selected_expiry", "no_test_deadline", "fallback_selected_expiry"} {
				t.Run(boundary, func(t *testing.T) {
					env, keys := genesisEnvironment(t, contract.GCP, false)
					f := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
					input := firstSecretInput(t, env, f.session)
					var output *outputApplyInput
					if path == "output" {
						output = &outputApplyInput{bindings: []outputApplyBinding{{destinationID: "app", targets: []outputApplyTarget{outputConfigurationTarget("secret", "app")}}}}
					}
					// The given caller budget exceeds the old one-minute cutoff
					// without waiting for a real minute to pass.
					now := time.Now()
					callerDeadline := now.Add(90 * time.Second)
					f.session.admission.expires = now.Add(3 * time.Minute)
					var admittedTB testing.TB = suppliedAdmissionDeadlineTB{TB: t, deadline: callerDeadline}
					want := callerDeadline
					switch boundary {
					case "selected_expiry":
						f.session.admission.expires = now.Add(45 * time.Second)
						want = f.session.admission.expires
					case "no_test_deadline":
						admittedTB = suppliedAdmissionWithoutDeadlineTB{TB: t}
						want = time.Time{}
					case "fallback_selected_expiry":
						admittedTB = suppliedAdmissionWithoutDeadlineTB{TB: t}
						f.session.admission.expires = now.Add(45 * time.Second)
						want = f.session.admission.expires
					}
					fallbackEarliest := time.Now().Add(time.Minute)
					var parent *AdmittedParentComparison
					if path == "supplied" {
						parent = admitSuppliedComparison(admittedTB, f.session, keys, input)
					} else {
						parent = admitSuppliedOutputComparison(admittedTB, f.session, keys, input, output)
					}
					defer keys.RetireApply()
					fallbackLatest := time.Now().Add(time.Minute)
					if parent == nil {
						t.Fatal("real secret admission returned no parent")
					}
					if want.IsZero() {
						if parent.deadline.Before(fallbackEarliest) || parent.deadline.After(fallbackLatest) {
							t.Fatal("no-deadline caller lost its finite one-minute fallback")
						}
					} else if !parent.deadline.Equal(want) {
						t.Fatalf("private admission deadline differs from given boundary: got %v want %v", parent.deadline, want)
					}
					if parent.deadline.After(f.session.admission.expires) || parent.context.Expiry != uint64(parent.deadline.UnixNano()) {
						t.Fatal("context/parent deadline differs or exceeds selected admission")
					}
					comparison, result := f.session.compareWithOutput(t.Context(), input, output, parent)
					if comparison == nil || result.Outcome != ObservedCurrent {
						t.Fatal("Crypto refused the original admitted context", result)
					}
					if comparison.operation == nil || !comparison.operation.deadline.Equal(parent.deadline) || comparison.operation.context != parent.context {
						t.Fatal("comparison changed the original parent/context deadline")
					}
					candidate, result := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), env.Trust)
					if candidate == nil || result.Outcome != ObservedCurrent {
						t.Fatal("Crypto preparation/Freeze/Claim refused the original context", result)
					}
					if !comparison.operation.deadline.Equal(parent.deadline) || comparison.operation.context != parent.context {
						t.Fatal("preparation renewed the original admitted deadline")
					}
				})
			}
		})
	}
}

// full_only: false
func TestInternalFirstSecretSelectionAndReader(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, recovery := range []bool{false, true} {
			for _, choice := range []uint8{custody.StandardValue, custody.EmptyValue, custody.MaximumValue} {
				t.Run(fmt.Sprintf("%d/%t/%d", family, recovery, choice), func(t *testing.T) {
					ctx := stdcontext.Background()
					env, keys := genesisEnvironment(t, family, recovery)
					f := newEnvironmentFixture(t, ctx, env, []int{1}, false)
					authority, reader := f.session.admission.recipient, fixtureID(env.Domain, "reader")
					recipients := []contract.ID{authority, reader}
					slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
					core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{
						Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain,
						FileIdentity: fixtureID(env.Domain, "source-file"), SourceID: fixtureID(env.Domain, "source"), DataKeyID: fixtureID(env.Domain, "source-data-key"), DataKeyEpoch: 1,
						InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "secret"}
					sealed, code := keys.SealInput(stdcontext.Background(), core, recipients, choice)
					if code != contract.CryptoSuccess {
						t.Fatal("source sealing", code)
					}
					input := f.session.currentEntryInputs()
					plain := bytes.Clone(input[0].InputBytes)
					input = append(input, ApplyEntryInput{Name: core.Name, Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: sealed, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
					parent := admitSuppliedComparison(t, f.session, keys, input)
					comparison, result := f.session.Compare(ctx, input, parent)
					if comparison == nil {
						t.Fatal("secret comparison", result)
					}
					permit := admit(t, f.session, comparison)
					candidate, result := f.session.Prepare(ctx, comparison, permit, env.Trust)
					if candidate == nil {
						t.Fatal("secret preparation", result)
					}
					if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
						t.Fatal("secret selection", result)
					}
					keys.RetireApply()
					keys.SetUnavailable(true)
					env.Trust.(*fixtureTrust).SetUnavailable(true)
					public, private := keys.Calls()
					selection := fixtureConsumerSelection(t, ctx, env, reader, core.Name)
					if selection.Core.ValueStateID == core.SourceID || bytes.Equal(selection.Entry.ValueBytes, sealed) || selection.Entry.ConfidentialityClass != format.Secret || !slices.Equal(selection.Entry.Recipients, recipients) {
						t.Fatal("source was not canonicalized for exact membership")
					}
					opened, result := Open(ctx, f.admission, env.Store)
					if opened == nil || opened.root.ValueEntryCount != 2 || opened.root.SecretCount != 1 || opened.root.AccessRecordCount != 1 || !bytes.Equal(opened.valueEntry(0).ValueBytes, plain) {
						t.Fatal("first secret changed the existing plain member", result)
					}
					if opened.root.CurrentAccess.Core.AccessGeneration != 2 || f.session.root.CurrentAccess.Core.AccessGeneration != 1 {
						t.Fatal("first secret must advance access generation exactly once and preserve its predecessor")
					}
					if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
						t.Fatal("public reader used private custody")
					}
					keys.SetUnavailable(false)
					keys.SetDenied(authority, true)
					check := keys.Consume(stdcontext.Background(), selection, choice)
					if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 || len(check.KeyUses) != 1 || check.KeyUses[0].SubjectID != reader {
						t.Fatalf("separate recipient delivery: %+v", check)
					}
				})
			}
		}
	}
}

// full_only: false
func TestFirstSecretSelectionAtCapacity(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			ctx := stdcontext.Background()
			env, _ := genesisEnvironment(t, contract.GCP, recovery)
			authority := fixtureID(env.Domain, "recipient")
			enrolled := []contract.ID{authority}
			for i := 1; i < 256; i++ {
				enrolled = append(enrolled, fixtureID(env.Domain, fmt.Sprintf("reader-%03d", i)))
			}
			keys := custody.New(t, contract.GCP, fixtureID(env.Domain, "capacity-custody"), recovery, enrolled)
			env.Bindings, env.Crypto, env.Custody = keys.Bindings(), keys.Crypto(), keys
			env.AdmitInit, env.RetireInit = keys.AdmitInit, keys.RetireInit
			f := newEnvironmentFixture(t, ctx, env, nil, false)
			var input []ApplyEntryInput
			var sources []contract.SealedInputCore
			for i := 0; i < 128; i++ {
				count := 32
				if i == 0 {
					count = 64
				} else if i >= 126 {
					count = 16
				}
				recipients := slices.Clone(enrolled[:count])
				slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
				name := fmt.Sprintf("secret-%03d", i)
				source := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{
					Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain,
					FileIdentity: fixtureID(env.Domain, name+"-file"), SourceID: fixtureID(env.Domain, name+"-source"), DataKeyID: fixtureID(env.Domain, name+"-key"), DataKeyEpoch: 1,
					InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: name}
				sealed, code := keys.SealInput(stdcontext.Background(), source, recipients, custody.MaximumValue)
				if code != contract.CryptoSuccess {
					t.Fatal("capacity source", i, code)
				}
				sources = append(sources, source)
				input = append(input, ApplyEntryInput{Name: name, Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: sealed, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
			}
			// 128 maximum values occupy eight MiB. Recipient counts are
			// 64 + 125*32 + 2*16 = 4096, including the per-entry maximum.
			public, private := keys.Calls()
			store := env.Store.(*memoryStore)
			creates, cas := store.creates, store.cas
			for _, boundary := range []string{"member-recipients", "total-memberships", "raw-bytes"} {
				t.Run(boundary, func(t *testing.T) {
					over := slices.Clone(input)
					want := refused(CapacityExceeded)
					switch boundary {
					case "member-recipients":
						over[0].Recipients = slices.Clone(enrolled[:65])
						slices.SortFunc(over[0].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
						want = refused(InvalidIntent)
					case "total-memberships":
						over = append(over, ApplyEntryInput{Name: "zz-extra", Recipients: []contract.ID{authority}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
					case "raw-bytes":
						last := len(over) - 1
						over[last].Recipients = slices.Clone(enrolled[:15])
						slices.SortFunc(over[last].Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
						sealed, code := keys.SealInput(stdcontext.Background(), sources[last], over[last].Recipients, custody.MaximumValue)
						if code != contract.CryptoSuccess {
							t.Fatal("raw boundary source", code)
						}
						over[last].InputBytes = sealed
						over = append(over, ApplyEntryInput{Name: "zz-extra", Recipients: []contract.ID{authority}, ValueSource: format.Supplied, ConfidentialityClass: format.Plain, InputBytes: []byte{1}, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
					}
					comparison, result := f.session.Compare(ctx, over, nil)
					if comparison != nil || result != want {
						t.Fatalf("capacity refusal=%+v want=%+v", result, want)
					}
				})
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private || store.creates != creates || store.cas != cas {
				t.Fatal("capacity refusal used custody or changed selected state")
			}
			parent := admitSuppliedComparison(t, f.session, keys, input)
			comparison, result := f.session.Compare(ctx, input, parent)
			if comparison == nil {
				t.Fatal("capacity comparison", result)
			}
			candidate, result := f.session.Prepare(ctx, comparison, admit(t, f.session, comparison), env.Trust)
			if candidate == nil {
				t.Fatal("capacity preparation", result)
			}
			if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
				t.Fatal("capacity selection", result)
			}
			keys.RetireApply()
			keys.SetUnavailable(true)
			opened, result := Open(ctx, f.admission, env.Store)
			if opened == nil || result.Outcome != ObservedCurrent || opened.root.RecipientCount != 256 || opened.root.ValueEntryCount != 128 || opened.root.SecretCount != 128 || opened.root.RawBytes != 8<<20 || opened.root.MembershipCount != 4096 {
				t.Fatal("capacity public reopen", result)
			}
			keys.SetUnavailable(false)
			creates, cas = store.creates, store.cas
			public, private = keys.Calls()
			parent = admitSuppliedComparison(t, opened, keys, input)
			comparison, result = opened.Compare(ctx, input, parent)
			if comparison != nil || result.Outcome != Unchanged || store.creates != creates || store.cas != cas {
				t.Fatal("joint current secret bounds did not admit exact equality", result)
			}
			if p, k := keys.Calls(); p != public || k != private+2*len(input) {
				t.Fatal("joint current comparison did not validate every current and supplied value")
			}
			keys.RetireApply()
			for _, index := range []int{0, 127} {
				recipient := input[index].Recipients[len(input[index].Recipients)-1]
				selection := sessionConsumerSelection(t, opened, recipient, input[index].Name)
				check := keys.Consume(stdcontext.Background(), selection, custody.MaximumValue)
				if check.Code != contract.CryptoSuccess || check.Delivery != 1 || !check.ValueMatched || check.SinkCalls != 1 {
					t.Fatalf("capacity selected delivery %d: %+v", index, check)
				}
			}
		})
	}
}

func runFirstFlowScenario(t testing.TB, ctx stdcontext.Context, env fixtureEnvironment, name string) {
	t.Helper()
	if env.Custody == nil {
		t.Fatal("first flow has no admitted private fixture")
	}
	run := newScenarioRun(t, ctx, env)
	var f *environmentFixture
	run.phase("setup", func() {
		sizes, fragmented, err := catalog.FixtureSizes(name)
		if err != nil {
			t.Fatal(err)
		}
		f = newEnvironmentFixture(t, ctx, run.env, sizes, fragmented)
		if len(sizes) == 0 && (f.session.root.ValueEntryCount != 0 || f.session.head.AuthKind != format.GenesisAuth) {
			t.Fatal("empty first-flow predecessor is not genesis")
		}
	})
	var expected stateImage
	run.phase("transition", func() {
		if !catalog.HasFixtureCapability(name, catalog.FixtureSecretState) {
			selected, result := Open(ctx, f.admission, run.env.Store)
			if selected == nil || result.Outcome != ObservedCurrent || selected.root.ValueEntryCount != 0 || selected.head.AuthKind != format.GenesisAuth {
				t.Fatal("empty initializer selected another state")
			}
			f.session = selected
			return
		}
		recipients := []contract.ID{fixtureID(env.Domain, "recipient")}
		execution, known := catalog.ExecutionFor(name, "hermetic")
		if !known {
			t.Fatal("first-flow execution facts unavailable")
		}
		if execution.FreshAfter[0].Role != "authority" {
			recipients = append(recipients, fixtureID(env.Domain, "reader"))
		}
		slices.SortFunc(recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		source := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: 2, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: env.Domain, FileIdentity: fixtureID(env.Domain, "source-file"), SourceID: fixtureID(env.Domain, "source"), DataKeyID: fixtureID(env.Domain, "source-key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "secret"}
		sealed, code := env.Custody.SealInput(ctx, source, recipients, custody.StandardValue)
		if code != contract.CryptoSuccess {
			t.Fatal("first source sealing", code)
		}
		input := f.session.currentEntryInputs()
		input = append(input, ApplyEntryInput{Name: "secret", Recipients: recipients, ValueSource: format.Supplied, ConfidentialityClass: format.Secret, InputBytes: sealed, InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw})
		parent := admitSuppliedComparison(t, f.session, env.Custody, input)
		if env.ReserveCustody != nil && !env.ReserveCustody("compare", 1) {
			t.Fatal("comparison custody budget exhausted")
		}
		comparison, result := f.session.Compare(ctx, input, parent)
		if comparison == nil {
			t.Fatal("first secret comparison", result)
		}
		if env.ReserveCustody != nil && !env.ReserveCustody("prepare", 1) {
			t.Fatal("preparation custody budget exhausted")
		}
		permit := admit(t, f.session, comparison)
		candidate, result := f.session.Prepare(ctx, comparison, permit, run.env.Trust)
		if candidate == nil {
			t.Fatal("first secret preparation", result)
		}
		if result = f.session.Select(ctx, candidate); result.Outcome != ObservedCurrent {
			t.Fatal("first secret selection", result)
		}
		env.Custody.RetireApply()
		selected, result := Open(ctx, f.admission, run.env.Store)
		if selected == nil || result.Outcome != ObservedCurrent || int(selected.root.ValueEntryCount) != len(input) || selected.root.SecretCount != 1 || selected.root.AccessRecordCount != 1 {
			t.Fatal("first secret selected an incomplete image", result)
		}
		if selected.root.CurrentAccess.Core.AccessGeneration != f.session.root.CurrentAccess.Core.AccessGeneration+1 {
			t.Fatal("first secret did not advance access generation exactly once")
		}
		for _, entry := range f.session.root.Names {
			before, after := f.session.valueEntry(entry.Slot), selected.valueEntry(entry.Slot)
			if after == nil || after.ConfidentialityClass != format.Plain || !bytes.Equal(before.ValueBytes, after.ValueBytes) {
				t.Fatal("first secret changed an existing plain member")
			}
		}
		selection := sessionConsumerSelection(t, selected, recipients[0], "secret")
		if !slices.Equal(selection.Entry.Recipients, recipients) || bytes.Equal(selection.Entry.ValueBytes, sealed) || selection.Core.ValueStateID == source.SourceID {
			t.Fatal("first source was not canonicalized for exact membership")
		}
		f.session = selected
	})
	run.phase("verification", func() {
		beforePublic, beforePrivate := env.Custody.Calls()
		opened, result := Open(ctx, f.admission, run.env.Store)
		if opened == nil || result.Outcome != ObservedCurrent {
			t.Fatal("first flow public verification", result)
		}
		afterPublic, afterPrivate := env.Custody.Calls()
		if beforePublic != afterPublic || beforePrivate != afterPrivate {
			t.Fatal("public open used custody")
		}
		expected = sessionStateImage(t, opened)
		f.session = opened
	})
	run.phase("reopen", func() {
		assertStateImage(t, f.session, expected)
		if env.FreshCurrent != nil {
			env.FreshCurrent(t, f.admission, f.session)
		} else if env.FreshOpen != nil {
			env.FreshOpen(t, expected)
		} else {
			t.Fatal("first flow requires a fresh reader")
		}
	})
}

func firstFlowConsumerOutcome(check custody.ConsumerCheck, selection contract.ConsumerSelection, denied bool) string {
	if len(check.KeyUses) != 1 {
		return "invalid-consumer-evidence"
	}
	use := check.KeyUses[0]
	digest, err := contract.PublicBindingDigest(selection.Binding.Binding)
	if err != nil || use.BindingID != selection.Binding.Binding.BindingID || use.PublicBindingDigest != digest || use.SubjectKind != 1 || use.SubjectID != selection.Binding.SubjectID || use.Provider != selection.Binding.Binding.Provider || use.Purpose != contract.KeyUseMaterialOpen || use.Count != 1 {
		return "invalid-consumer-evidence"
	}
	if denied {
		if check.Code == contract.CryptoPrivateRouteUnavailable && check.Delivery == 0 && check.SinkCalls == 0 && !check.ValueMatched && use.Outcome == contract.KeyUseDenied {
			return "secret-access-refused"
		}
	} else if check.Code == contract.CryptoSuccess && check.Delivery == 1 && check.SinkCalls == 1 && check.ValueMatched && use.Outcome == contract.KeyUseCompleted {
		return "success"
	}
	return "invalid-consumer-evidence"
}
