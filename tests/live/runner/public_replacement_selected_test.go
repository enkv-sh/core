package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	records "enkv.sh/core/internal/testrecords"
)

func publicReplacementSelected(t testing.TB, before, after *StateSession, cell catalog.PublicReplacementCase, signing, encryption string) {
	t.Helper()
	if !reflect.DeepEqual(before.pages, after.pages) || !reflect.DeepEqual(before.root.Names, after.root.Names) || before.root.ValueEntryCount != after.root.ValueEntryCount || before.root.SecretCount != after.root.SecretCount || before.root.MembershipCount != after.root.MembershipCount || before.root.RawBytes != after.root.RawBytes || before.root.WarningBits != after.root.WarningBits || before.root.OutputConfiguration != after.root.OutputConfiguration || len(after.adminIndex.Groups) != 0 {
		t.Fatal("replacement changed selected values, memberships, output, warnings or duties")
	}
	expected := currentControlOf(before)
	if expected.Recovery != nil {
		own := *expected.Recovery
		expected.Recovery = &own
	}
	current := currentControlOf(after)
	expected.AccessGeneration++
	if signing != "" {
		old, next := expected.NormalSigning, current.NormalSigning
		if cell.Target == "recovery" {
			old, next = expected.Recovery.Signing, current.Recovery.Signing
		}
		if next.BindingID.IsZero() || next.BindingID == old.BindingID || next.KeySelector != signing || len(next.SPKI) == 0 || next.Fingerprint != contract.Hash(next.SPKI) || next.Binding.PublicKey != next.Fingerprint {
			t.Fatal("selected signer differs from nominated qualified key")
		}
		old.BindingID = next.BindingID
		old.Binding.Epoch++
		old.KeySelector = signing
		old.SPKI = next.SPKI
		old.Fingerprint = next.Fingerprint
		old.Binding.PublicKey = next.Fingerprint
		if !reflect.DeepEqual(old, next) {
			t.Fatal("selected signer changed unrelated binding facts or epoch progression")
		}
		if cell.Target == "authority" {
			expected.NormalSigning = next
		} else {
			expected.Recovery.Signing = next
		}
	}
	targetID, targetKind := before.admission.recipient, uint8(contract.OrdinaryWrapSubject)
	if cell.Target == "recovery" {
		targetID = before.root.CurrentAccess.Core.Recovery.RoleID
		targetKind = contract.RecoveryWrapSubject
	}
	if cell.Target == "recipient" {
		for _, id := range before.valueEntry(before.root.Names[0].Slot).Recipients {
			if id != before.admission.recipient {
				targetID = id
			}
		}
	}
	if encryption != "" {
		if cell.Target == "recovery" {
			publicReplacementKMS(t, expected.Recovery.KMS, current.Recovery.KMS, encryption)
			expected.Recovery.KMS = current.Recovery.KMS
		}
		if cell.Target == "authority" {
			publicReplacementKMS(t, expected.AuthorityKMSBinding, current.AuthorityKMSBinding, encryption)
			expected.AuthorityKMSBinding = current.AuthorityKMSBinding
		}
	}
	if !sameControl(expected, current) {
		t.Fatal("replacement changed an untargeted control field")
	}
	if len(before.registry()) != len(after.registry()) {
		t.Fatal("replacement changed selected Recipient registry cardinality")
	}
	for _, page := range before.recipients {
		if page == nil {
			continue
		}
		for _, old := range page.Slots {
			if old == nil {
				continue
			}
			next := after.recipientRecord(old.RecipientID)
			if next == nil {
				t.Fatal("replacement removed an ordinary Recipient")
			}
			copy := *old
			if encryption != "" && old.RecipientID == targetID && cell.Target != "recovery" {
				if old.CurrentBinding == nil || next.CurrentBinding == nil {
					t.Fatal("target Recipient binding absent")
				}
				publicReplacementKMS(t, *old.CurrentBinding, *next.CurrentBinding, encryption)
				copy.CurrentBinding = next.CurrentBinding
			}
			if !reflect.DeepEqual(copy, *next) {
				t.Fatal("replacement changed untargeted Recipient facts")
			}
		}
	}
	oldAccess, nextAccess := before.accessRecords(), after.accessRecords()
	if len(oldAccess) != 1 || len(nextAccess) != 1 {
		t.Fatal("replacement fixture material coverage changed")
	}
	old, next := oldAccess[0], nextAccess[0]
	oldWraps, nextWraps := old.Wraps, next.Wraps
	old.Wraps, next.Wraps = nil, nil
	if !reflect.DeepEqual(old, next) || len(oldWraps) != len(nextWraps) {
		t.Fatal("replacement changed material identity, package or wrap coverage")
	}
	changed := 0
	var selectedBinding contract.KMSBinding
	if encryption != "" {
		if cell.Target == "recovery" {
			selectedBinding = current.Recovery.KMS
		} else {
			selectedBinding = *after.recipientRecord(targetID).CurrentBinding
		}
	}
	bindingDigest, err := contract.PublicBindingDigest(selectedBinding)
	if encryption != "" && err != nil {
		t.Fatal(err)
	}
	for i, wrap := range oldWraps {
		got := nextWraps[i]
		if encryption != "" && wrap.SubjectKind == targetKind && wrap.SubjectID == targetID {
			if got.SubjectKind != wrap.SubjectKind || got.SubjectID != wrap.SubjectID || got.BindingID != selectedBinding.BindingID || got.BindingSerial != selectedBinding.BindingSerial || got.PublicBindingDigest != bindingDigest || bytes.Equal(got.RSACiphertext, wrap.RSACiphertext) {
				t.Fatal("nominated material wrap was not replaced exactly")
			}
			changed++
		} else if !reflect.DeepEqual(wrap, got) {
			t.Fatal("replacement changed an untargeted material wrap")
		}
	}
	if encryption != "" && changed != 1 || encryption == "" && changed != 0 {
		t.Fatal("replacement changed the wrong material wrap set")
	}
}

func publicReplacementKMS(t testing.TB, before, after contract.KMSBinding, selector string) {
	t.Helper()
	if after.BindingID.IsZero() || after.BindingID == before.BindingID || after.KeySelector != selector || len(after.SPKI) == 0 || after.Fingerprint != contract.Hash(after.SPKI) {
		t.Fatal("selected encryption binding differs from exact nominated public key")
	}
	before.BindingID = after.BindingID
	before.BindingSerial++
	before.KeySelector = selector
	before.SPKI = after.SPKI
	before.Fingerprint = after.Fingerprint
	if !reflect.DeepEqual(before, after) {
		t.Fatal("replacement changed encryption profile, protection, incarnation or serial progression")
	}
}

func publicReplacementOutputFacts(t testing.TB, ctx context.Context, inv records.Invocation, input liveRunInput, budget *runBudget, source, output string, cell catalog.PublicReplacementCase) {
	t.Helper()
	before := publicParsedSourceFacts(t, ctx, inv, input, budget, source)
	after := publicParsedSourceFacts(t, ctx, inv, input, budget, output)
	if len(before.GeneratedRecipients) != len(after.GeneratedRecipients) {
		t.Fatal("replacement output discarded complete local generated rows")
	}
	for i, old := range before.GeneratedRecipients {
		next := after.GeneratedRecipients[i]
		if old.Reference != next.Reference || old.ID != next.ID || !reflect.DeepEqual(old.Creation, next.Creation) {
			t.Fatal("replacement output changed generated row order, reference or creation facts")
		}
		changed := cell.Target == "recipient" && old.Reference == "consumer"
		if !changed && (old.Encryption.Selector != next.Encryption.Selector || !bytes.Equal(old.Encryption.PublicKey, next.Encryption.PublicKey) || old.Encryption.Binding != next.Encryption.Binding) {
			t.Fatal("replacement output changed untargeted generated key facts")
		}
	}
	a, b := publicSourceDocument(t, source), publicSourceDocument(t, output)
	delete(a, "generated")
	delete(b, "generated")
	domainA, _ := a["domain"].(map[string]any)
	domainB, _ := b["domain"].(map[string]any)
	for _, key := range []string{"authority", "recovery"} {
		if key != cell.Target {
			continue
		}
		roleA, _ := domainA[key].(map[string]any)
		roleB, _ := domainB[key].(map[string]any)
		if cell.Change != "encryption" {
			delete(roleA, "signing_key")
			delete(roleB, "signing_key")
		}
		if cell.Change != "signing" {
			delete(roleA, "encryption_key")
			delete(roleB, "encryption_key")
		}
	}
	if cell.Target == "recipient" {
		rowsA, _ := a["recipients"].(map[string]any)
		rowsB, _ := b["recipients"].(map[string]any)
		rowA, _ := rowsA["consumer"].(map[string]any)
		rowB, _ := rowsB["consumer"].(map[string]any)
		delete(rowA, "encryption_key")
		delete(rowB, "encryption_key")
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("replacement output changed unrelated editable intent or sealed proposal bytes")
	}
}
