package core

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
)

// full_only: false
func TestConsumerSelectionAdmitsWholeMixedSetBeforePrivateUse(t *testing.T) {
	ctx := context.Background()
	env, keys := genesisEnvironment(t, contract.GCP, false)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, []int{1}, false)
	authority, reader := f.session.admission.recipient, fixtureID(env.Domain, "reader")
	input := append(f.session.currentEntryInputs(), suppliedSecret(t, env, "secret", "selection source", custody.StandardValue))
	run.suppliedSelection(f, input)
	names := []string{input[0].Name, input[1].Name}
	t.Run("plain-consumer-record", func(t *testing.T) {
		public, private := keys.Calls()
		selected := sessionConsumerSelection(t, f.session, authority, names[0])
		if selected.Slot != 0 || selected.Entry.Name != names[0] || selected.Entry.ConfidentialityClass != contract.Plain ||
			!bytes.Equal(selected.Entry.ValueBytes, []byte{0}) || selected.Binding.SubjectID != authority ||
			!reflect.DeepEqual(selected.Core, contract.ValueCore{}) || !reflect.DeepEqual(selected.Payload, contract.CanonicalPayload{}) ||
			!reflect.DeepEqual(selected.Access, contract.AccessRecord{}) {
			t.Fatal("plain consumer record differs or contains secret-only material")
		}
		if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
			t.Fatal("plain consumer record entered private custody")
		}
	})
	t.Run("secret-consumer-record", func(t *testing.T) {
		selected := sessionConsumerSelection(t, f.session, authority, "secret")
		check := keys.Consume(ctx, selected, custody.StandardValue)
		if check.Code != contract.CryptoSuccess || check.Delivery != 1 || check.SinkCalls != 1 || !check.ValueMatched {
			t.Fatal("secret consumer record failed exact delivery", check)
		}
	})
	for _, acting := range []contract.ID{{}, authority} {
		public, private := keys.Calls()
		selection, result := f.session.admitConsumerSelection(ctx, names, acting)
		if selection == nil || result.Outcome != ObservedCurrent || selection.recipient != authority || !slices.Equal(selection.slots, []uint16{0, 1}) {
			t.Fatal("complete authority-only selection refused", result)
		}
		if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
			t.Fatal("public selection used private custody")
		}
	}
	shared := []contract.ID{authority, reader}
	slices.SortFunc(shared, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	input[1] = sharingSecret(t, env, "selection shared", shared)
	run.suppliedSelection(f, input)
	for _, acting := range []contract.ID{{}, authority} {
		before := run.spy.scenarioEffects
		public, private := keys.Calls()
		selection, result := f.session.admitConsumerSelection(ctx, names, acting)
		if selection == nil || result.Outcome != ObservedCurrent || selection.recipient != authority || !slices.Equal(selection.slots, []uint16{0, 1}) || run.spy.scenarioEffects != before {
			t.Fatal("complete shared selection did not use Authority", result)
		}
		if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
			t.Fatal("public shared selection entered private custody")
		}
	}
	for _, tc := range []struct {
		name   string
		names  []string
		acting contract.ID
		want   Result
	}{
		{"later-plain-unauthorized", []string{"secret", names[0]}, reader, refused(AdmissionInvalid)},
		{"earlier-plain-unauthorized", names, reader, refused(AdmissionInvalid)},
		{"duplicate", []string{"secret", "secret"}, authority, refused(InvalidIntent)},
		{"unknown-name", []string{"secret", "unknown"}, authority, refused(InvalidIntent)},
		{"unknown-recipient", names, testID("unregistered"), refused(AdmissionInvalid)},
		{"too-many", make([]string, contract.CryptoMaxValueEntries+1), authority, refused(CapacityExceeded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := run.spy.scenarioEffects
			public, private := keys.Calls()
			selection, result := f.session.admitConsumerSelection(ctx, tc.names, tc.acting)
			if selection != nil || result != tc.want || run.spy.scenarioEffects != before {
				t.Fatal("invalid selection returned partial admission or effects", result)
			}
			if gotPublic, gotPrivate := keys.Calls(); gotPublic != public || gotPrivate != private {
				t.Fatal("invalid whole selection entered private custody")
			}
		})
	}
	if selected, result := f.session.admitConsumerSelection(ctx, []string{"secret"}, reader); selected == nil || result.Outcome != ObservedCurrent || selected.recipient != reader {
		t.Fatal("explicit authorized reader refused", result)
	}
	if selected, result := f.session.admitConsumerSelection(ctx, []string{names[0]}, contract.ID{}); selected == nil || result.Outcome != ObservedCurrent || selected.recipient != authority {
		t.Fatal("plain authority selection depends on unselected shared member", result)
	}
	for _, name := range []string{"retired", "missing-binding", "invalid-binding"} {
		t.Run(name, func(t *testing.T) {
			row := f.session.recipientRecord(reader)
			old := *row
			defer func() { *row = old }()
			switch name {
			case "retired":
				row.Status = contract.RetiredRecipient
			case "missing-binding":
				row.CurrentBinding = nil
			case "invalid-binding":
				binding := *row.CurrentBinding
				binding.BindingSerial = 0
				row.CurrentBinding = &binding
			}
			if selected, result := f.session.admitConsumerSelection(ctx, []string{"secret"}, reader); selected != nil || result != refused(AdmissionInvalid) {
				t.Fatal("invalid current registry admitted reader", result)
			}
		})
	}
}
