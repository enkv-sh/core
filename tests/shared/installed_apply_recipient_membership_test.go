package core

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

// full_only: false
func TestInstalledApplyCreatesRecipientWithPlainAndSecretMembershipAtomically(t *testing.T) {
	for _, cell := range []struct {
		family   contract.Family
		recovery bool
	}{{contract.AWS, false}, {contract.GCP, true}} {
		t.Run(fmt.Sprintf("%d/recovery=%t", cell.family, cell.recovery), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			f := newInstalledApplyTestFixture(t, ctx, cell.family, cell.recovery)
			desired := installedApplyPreparedRecipient(t, f.selected, "atomic recipient nonce")
			created := slices.IndexFunc(desired, func(row contract.ApplyRecipientInput) bool { return row.Creation != nil })
			id := desired[created].Recipient.RecipientID
			authority := f.selected.admission.recipient
			readers := []contract.ID{authority, id}
			slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
			bindings := make([]contract.BindingTableRow, 0, len(desired)+1)
			registry := make([]contract.RecipientRecord, len(desired))
			var authorityBinding contract.BindingTableRow
			for i, row := range desired {
				registry[i] = row.Recipient
				binding := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: row.Recipient.RecipientID, Binding: *row.Recipient.CurrentBinding}
				bindings = append(bindings, binding)
				if binding.SubjectID == authority {
					authorityBinding = binding
				}
			}
			recovery := contract.ID{}
			if current := f.selected.root.CurrentAccess.Core.Recovery; current != nil {
				recovery = current.RoleID
				bindings = append(bindings, contract.BindingTableRow{SubjectKind: contract.RecoveryWrapSubject, SubjectID: current.RoleID, Binding: current.KMS})
				f.keys.SetDenied(recovery, true)
				f.env.Recovery.(*testtrust.Signer).SetUnavailable(true)
			}
			orderBindings(bindings)
			sealer := custody.NewCurrentConsumer(t, fixtureID(f.env.Domain, "atomic input producer"), authority, recovery, bindings, authorityBinding)
			core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: contract.SealedInputSchema, Profile: contract.RSAOAEPWrapProfile, CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), DomainID: f.env.Domain, FileIdentity: fixtureID(f.env.Domain, "source-file"), SourceID: fixtureID(f.env.Domain, "atomic secret source"), DataKeyID: fixtureID(f.env.Domain, "atomic source key"), DataKeyEpoch: 1, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "secret"}
			sealed, code := sealer.SealInput(ctx, core, readers, custody.StandardValue)
			if code != contract.CryptoSuccess {
				t.Fatal("prepared recipient source sealing", code)
			}
			source := bytes.Clone(sealed)
			input := []ApplyEntryInput{{Name: "plain", Recipients: slices.Clone(readers), ValueSource: contract.Supplied, ConfidentialityClass: contract.Plain, InputBytes: []byte("public value")}, {Name: "secret", Recipients: slices.Clone(readers), ValueSource: contract.Supplied, ConfidentialityClass: contract.Secret, InputBytes: sealed}}
			store := f.env.Store.(*memoryStore)
			cas := store.cas
			public, _ := f.keys.Calls()
			engine := f.engineWithRecipients(t, f.selected, input, desired, nil)
			result := engine.Apply(ctx, fixtureID(f.env.Domain, "atomic recipient and memberships"), input)
			engine.Close()
			if result.Result.Outcome != ObservedCurrent || result.Payload == nil || result.Payload.ChangedSubjects.Count != 7 || store.cas != cas+1 {
				t.Fatal("new recipient and plain/secret memberships were not selected once", result.Result, store.cas-cas)
			}
			selected := f.open(t, ctx)
			if !reflect.DeepEqual(selected.registry(), registry) || selected.root.ValueEntryCount != 2 || selected.root.SecretCount != 1 || selected.root.MembershipCount != 4 {
				t.Fatal("complete cold registry/value/membership set differs")
			}
			for _, named := range selected.root.Names {
				if named.Name == "plain" && !bytes.Equal(selected.valueEntry(named.Slot).ValueBytes, input[0].InputBytes) {
					t.Fatal("atomic plain value differs")
				}
				if !slices.Equal(selected.valueEntry(named.Slot).Recipients, readers) {
					t.Fatal("atomic entry lost Authority or created reader")
				}
			}
			selection := sessionConsumerSelection(t, selected, authority, "secret")
			if len(selection.Access.Wraps) != 2+boolInt(cell.recovery) {
				t.Fatal("atomic secret has inexact ordinary/Recovery wrap set")
			}
			for _, row := range bindings {
				wanted := row.SubjectKind == contract.RecoveryWrapSubject || slices.Contains(readers, row.SubjectID)
				at := slices.IndexFunc(selection.Access.Wraps, func(wrap contract.WrapRow) bool {
					return wrap.SubjectKind == row.SubjectKind && wrap.SubjectID == row.SubjectID
				})
				if !wanted {
					if at >= 0 {
						t.Fatal("unassigned existing recipient gained a wrap")
					}
					continue
				}
				digest, err := contract.PublicBindingDigest(row.Binding)
				if err != nil || at < 0 || selection.Access.Wraps[at].BindingID != row.Binding.BindingID || selection.Access.Wraps[at].BindingSerial != row.Binding.BindingSerial || selection.Access.Wraps[at].PublicBindingDigest != digest {
					t.Fatal("secret wrap does not match exact selected public binding")
				}
			}
			gotPublic, _ := f.keys.Calls()
			if gotPublic != public+1 || !bytes.Equal(source, sealed) {
				t.Fatal("creation qualification count or source ownership changed")
			}
			consumer := custody.NewCurrentConsumer(t, fixtureID(f.env.Domain, "atomic created consumer"), authority, recovery, bindings, contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: id, Binding: *desired[created].Recipient.CurrentBinding})
			check := consumer.Consume(ctx, sessionConsumerSelection(t, selected, id, "secret"), custody.StandardValue)
			if check.Code != contract.CryptoSuccess || !check.ValueMatched {
				t.Fatal("new recipient could not consume exact selected secret", check)
			}
			entryBytes, err := contract.EncodeValueEntry(selection.Entry)
			if err != nil {
				t.Fatal(err)
			}
			accessBytes, err := contract.EncodeAccessRecord(selection.Access)
			if err != nil {
				t.Fatal(err)
			}
			cas, public = store.cas, gotPublic
			repeat := f.engineWithRecipients(t, selected, input, desired, nil)
			repeated := repeat.Apply(ctx, fixtureID(f.env.Domain, "repeat atomic recipient and memberships"), input)
			repeat.Close()
			current := f.open(t, ctx)
			gotPublic, _ = f.keys.Calls()
			after := sessionConsumerSelection(t, current, authority, "secret")
			gotEntry, err := contract.EncodeValueEntry(after.Entry)
			if err != nil {
				t.Fatal(err)
			}
			gotAccess, err := contract.EncodeAccessRecord(after.Access)
			if err != nil {
				t.Fatal(err)
			}
			if repeated.Result.Outcome != Unchanged || store.cas != cas || gotPublic != public || !reflect.DeepEqual(current.registry(), registry) || !bytes.Equal(entryBytes, gotEntry) || !bytes.Equal(accessBytes, gotAccess) || !bytes.Equal(source, sealed) {
				t.Fatal("repeat creation/grants changed identity, protection or source", repeated.Result)
			}
		})
	}
}
