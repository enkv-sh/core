package core

import (
	"context"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// This test-only admission retains the existing selected/custody/request checks.
// Its explicit successor groups are independent of the production change detector.
func admitGroupsOnlySourceComparison(t testing.TB, s *StateSession, keys *custody.Fixture, input []ApplyEntryInput, output *outputApplyInput, registry ...contract.GeneratorImplementation) *AdmittedParentComparison {
	t.Helper()
	installOutputFixtureSource(t, s, output)
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
		// The expected source is independently authored. Do not use the
		// output change detector under test to construct its admission witness.
		c.outputIntent, c.outputChanged = normalized, true
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
	witness, err := s.generatedSupportTransition(context.Background(), c, fixtureGeneratedSupportHandoffs(t, s, c, registry))
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
		if valueEntry.ConfidentialityClass == contract.Secret {
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

// full_only: false
func TestOutputConfigurationGroupsOnlyDeletion(t *testing.T) {
	for _, count := range []int{1, 2} {
		for _, explicit := range []bool{false, true} {
			name := "last_member"
			if count == 2 {
				name = "surviving_member"
			}
			if explicit {
				name += "_explicit"
			} else {
				name += "_omitted"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t, count, false, 1)
				entries := f.session.currentEntryInputs()
				group := make([]string, len(entries))
				for i := range entries {
					group[i] = entries[i].Name
				}
				slices.Sort(group)
				initial := selectOutputConfiguration(t, f, entries, &outputApplyInput{groups: [][]string{group}})
				old := f.session.valueEntry(entrySlot(t, f.session, entries[0].Name)).Incarnation
				if len(initial.Bindings) != 0 || len(initial.Routes) != 0 || len(initial.Groups) != 1 || len(initial.Groups[0]) != count || !slices.Contains(initial.Groups[0], old) {
					t.Fatal("initial groups-only state does not have its selected members")
				}
				desired := entries[1:]
				var want contract.ID
				expected := &outputApplyInput{}
				var output *outputApplyInput
				if explicit {
					output = expected
				}
				if count == 2 {
					want = f.session.valueEntry(entrySlot(t, f.session, desired[0].Name)).Incarnation
					expected.groups = [][]string{{desired[0].Name}}
				}
				parent := admitSuppliedOutputComparison(t, f.session, nil, desired, expected)
				comparison, result := f.session.compareWithOutput(t.Context(), desired, output, parent)
				if comparison == nil || result.Outcome != ObservedCurrent || parent == nil || parent.support == nil || comparison.support != parent.support {
					t.Fatal("groups-only deletion comparison", result)
				}
				candidate, result := f.session.Prepare(t.Context(), comparison, admit(t, f.session, comparison), f.trust)
				if candidate == nil || result.Outcome != ObservedCurrent {
					t.Fatal("groups-only deletion preparation", result)
				}
				if result := f.session.Select(t.Context(), candidate); result.Outcome != ObservedCurrent {
					t.Fatal("groups-only deletion selection", result)
				}
				selected, result := Open(t.Context(), f.admission, f.store)
				if selected == nil || result.Outcome != ObservedCurrent {
					t.Fatal("groups-only deletion cold open", result)
				}
				after, result := selected.currentOutputConfigurationForApply(t.Context())
				if result.Outcome != 0 || len(after.Bindings) != 0 || len(after.Routes) != 0 || len(selected.root.Names) != count-1 || selected.publicationProof == nil || !selected.publicationProof.validFor(selected.selectedImage()) {
					t.Fatal("groups-only deletion selected relation", result)
				}
				if count == 1 {
					if len(after.Groups) != 0 {
						t.Fatal("deleted group member survived")
					}
				} else if len(after.Groups) != 1 || !slices.Equal(after.Groups[0], []contract.ID{want}) || selected.valueEntry(entrySlot(t, selected, desired[0].Name)).Incarnation != want {
					t.Fatal("surviving group member lost its original incarnation")
				}
			})
		}
	}
}

// full_only: false
func TestOutputConfigurationGroupsOnlySourceConversion(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "omitted"
		if explicit {
			name = "explicit"
		}
		t.Run(name, func(t *testing.T) {
			env, keys, selected, row, effects, _ := normalHandoffGeneratedFixture(t, false, true)
			old := *selected.valueEntry(entrySlot(t, selected, "generated"))
			expected := &outputApplyInput{groups: [][]string{{old.Name}}}
			selected = selectAdmittedOutputConfiguration(t, t.Context(), selected, env, keys, selected.currentEntryInputs(), expected)
			before, result := selected.currentOutputConfigurationForApply(t.Context())
			if result.Outcome != 0 || len(before.Bindings) != 0 || len(before.Routes) != 0 || len(before.Groups) != 1 || !slices.Equal(before.Groups[0], []contract.ID{old.Incarnation}) || effects.Load() != 1 {
				t.Fatal("initial generated groups-only selected state", result)
			}
			proposed := selected.currentEntryInputs()
			index := slices.IndexFunc(proposed, func(entry ApplyEntryInput) bool { return entry.Name == old.Name })
			if index < 0 {
				t.Fatal("generated predecessor missing")
			}
			proposed[index] = suppliedSecret(t, env, old.Name, "groups source conversion", custody.HermeticCloudflareValue, old.Recipients...)
			parent := admitGroupsOnlySourceComparison(t, selected, keys, proposed, expected, row)
			var output *outputApplyInput
			if explicit {
				output = expected
			}
			comparison, result := selected.compareWithOutput(t.Context(), proposed, output, parent)
			if comparison == nil || result.Outcome != ObservedCurrent {
				t.Fatal("groups-only source conversion comparison", result)
			}
			permit := admit(t, selected, comparison)
			planned := permit.plan.incarnations[comparison.slots[index]]
			if planned.IsZero() || planned == old.Incarnation {
				t.Fatal("source conversion has no fresh planned incarnation")
			}
			candidate, result := selected.Prepare(t.Context(), comparison, permit, env.Trust)
			if candidate == nil || result.Outcome != ObservedCurrent {
				t.Fatal("groups-only source conversion preparation", result)
			}
			selected, result = selected.selectCandidate(t.Context(), candidate)
			if selected == nil || result.Outcome != ObservedCurrent {
				t.Fatal("groups-only source conversion selection", result)
			}
			keys.RetireApply()
			selected = generatedLifecycleReopen(t, t.Context(), selected, env.Store)
			after, result := selected.currentOutputConfigurationForApply(t.Context())
			fresh := selected.valueEntry(entrySlot(t, selected, old.Name))
			if result.Outcome != 0 || fresh.ValueSource != contract.Supplied || fresh.Incarnation != planned || len(after.Bindings) != 0 || len(after.Routes) != 0 || len(after.Groups) != 1 || !slices.Equal(after.Groups[0], []contract.ID{planned}) || selected.publicationProof == nil || !selected.publicationProof.validFor(selected.selectedImage()) || effects.Load() != 1 {
				t.Fatal("groups-only conversion lost the fresh selected group member", result)
			}
		})
	}
}

// full_only: false
func TestOutputConfigurationGroupsOnlyClassConversionRefused(t *testing.T) {
	f := newFixture(t, 1, false, 1)
	entries := f.session.currentEntryInputs()
	selectOutputConfiguration(t, f, entries, &outputApplyInput{groups: [][]string{{entries[0].Name}}})
	creates, cas, signs := f.store.creates, f.store.cas, f.trust.signs
	entries[0].ConfidentialityClass = contract.Secret
	comparison, result := f.session.compareWithOutput(t.Context(), entries, nil, nil)
	if comparison != nil || result != refused(InvalidIntent) || f.store.creates != creates || f.store.cas != cas || f.trust.signs != signs || f.session.prepared {
		t.Fatal("ordinary same-name class conversion was admitted or caused effects", result)
	}
}
