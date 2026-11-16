package custody

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

// full_only: false
func TestCurrentReplacementPreservesOccupiedOriginalRuntime(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, sourceKind := range []uint8{1, 2} {
			t.Run(fmt.Sprint(family, "/", sourceKind), func(t *testing.T) {
				id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
				original := New(t, family, id("occupied replacement"), true, []contract.ID{id("authority"), id("reader")})
				q, control, _ := facadeApplyRequest(t, original)
				current := original.Bindings()
				publicBefore, err := contract.EncodeBindingTable(current)
				if err != nil {
					t.Fatal(err)
				}
				var source, target, reader contract.BindingTableRow
				var ordinary []contract.BindingTableRow
				for _, row := range current {
					if row.SubjectKind == 1 {
						ordinary = append(ordinary, row)
					}
					if row.SubjectKind == sourceKind && (sourceKind == 2 || row.SubjectID == original.authority) {
						source = row
					} else if row.SubjectID == original.authority || row.SubjectKind == 2 {
						target = row
					} else {
						reader = row
					}
				}
				view, err := contract.InspectSealedInputEnvelope(q.SealedInputs[0].EnvelopeBytes)
				if err != nil {
					t.Fatal(err)
				}
				value, ok := syntheticValue(StandardValue)
				if !ok {
					t.Fatal("source fixture value")
				}
				admissionID := id("original occupied source")
				core, err := view.Core.Own()
				if err != nil {
					t.Fatal(err)
				}
				if err := privatecrypto.TestAdmitInputSeal(original.runtime, admissionID, core, original.authority, ordinary, &privateSource{value: value}, time.Now().Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				probe := &keyRoute{owner: original, subject: original.authority, id: id("blocked independent route")}
				if err := privatecrypto.TestInstallKeyRoute(original.runtime, probe); err != privatecrypto.ErrAdmission {
					t.Fatal("occupied original accepted another route", err)
				}
				fresh, err := NewCurrentReplacement(t, id("separate replacement"), control, current, source)
				if err != nil {
					t.Fatal(err)
				}
				if fresh == original || fresh.runtime == original.runtime || fresh.runtime.InstanceID() == original.runtime.InstanceID() || len(fresh.keys) != 1 || len(fresh.routes) != 1 || fresh.keys[source.Binding.BindingID] == original.keys[source.Binding.BindingID] {
					t.Fatal("replacement copied private custody or an unrelated route")
				}
				if got := fresh.PrivateWitness(context.Background(), source.Binding.BindingID, source.Binding, source.Binding); got != (RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}) {
					t.Fatal("replacement current source unavailable", got)
				}
				role := uint8(contract.SuccessorAuthorityKEK)
				if target.SubjectKind == 2 {
					role = contract.SuccessorRecoveryKEK
				}
				successor := fresh.KEKSuccessor(t, role)
				if len(fresh.keys) != 2 || len(fresh.routes) != 2 || !fresh.usedFingerprints[successor.Fingerprint] {
					t.Fatal("replacement omitted source or independent successor")
				}
				for _, row := range current {
					if !fresh.usedFingerprints[row.Binding.Fingerprint] || row.Binding.BindingID != source.Binding.BindingID && fresh.keys[row.Binding.BindingID] != nil {
						t.Fatal("replacement retained a private unrelated route or lost public history")
					}
				}
				stale := target
				stale.Binding.BindingSerial++
				if err := original.RetireCurrentPrivateRoute(stale); err != privatecrypto.ErrAdmission || original.keys[target.Binding.BindingID] == nil {
					t.Fatal("stale retirement removed a current private route", err)
				}
				if err := original.RetireCurrentPrivateRoute(target); err != nil {
					t.Fatal(err)
				}
				if err := fresh.ActivateSuccessor(target.SubjectID); err != nil {
					t.Fatal(err)
				}
				for _, keys := range []*Fixture{original, fresh} {
					if keys.keys[target.Binding.BindingID] != nil || !keys.usedFingerprints[target.Binding.Fingerprint] {
						t.Fatal("retirement kept the old private key or lost its public history")
					}
					if got := keys.PrivateWitness(context.Background(), target.Binding.BindingID, target.Binding, target.Binding); got != (RouteWitness{Outcome: contract.CryptoInvalidAdmission}) {
						t.Fatal("retired route did not refuse locally", got)
					}
				}
				if got := original.PrivateWitness(context.Background(), reader.Binding.BindingID, reader.Binding, reader.Binding); got != (RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}) {
					t.Fatal("retirement removed an unrelated original route", got)
				}
				publicAfter, err := contract.EncodeBindingTable(original.Bindings())
				if err != nil || !bytes.Equal(publicBefore, publicAfter) {
					t.Fatal("replacement changed original current public admission", err)
				}
				if err := privatecrypto.TestInstallKeyRoute(original.runtime, probe); err != privatecrypto.ErrAdmission {
					t.Fatal("replacement consumed the original occupied slot", err)
				}
				if body, code := privatecrypto.TestSealInput(original.runtime, context.Background(), admissionID); len(body) == 0 || code != contract.CryptoSuccess {
					t.Fatal("replacement changed the original admitted slot", code)
				}
			})
		}
	}
}

// full_only: false
func TestCurrentReplacementRefusesNoncurrentSources(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		original := New(t, family, id("replacement source bounds"), true, []contract.ID{id("authority"), id("reader")})
		_, control, _ := facadeApplyRequest(t, original)
		current := original.Bindings()
		var source, reader contract.BindingTableRow
		for _, row := range current {
			if row.SubjectID == original.authority {
				source = row
			}
			if row.SubjectID == id("reader") {
				reader = row
			}
		}
		for _, name := range []string{"invalid-control", "absent-table", "stale-source", "ordinary-reader", "wrong-source-kind", "wrong-recovery-role", "changed-authority-table", "changed-recovery-table", "missing-recovery-table", "disabled-recovery"} {
			t.Run(fmt.Sprint(family, "/", name), func(t *testing.T) {
				before, rows, selected := control, slices.Clone(current), source
				switch name {
				case "invalid-control":
					before.DomainID = contract.ID{}
				case "absent-table":
					rows = nil
				case "stale-source":
					selected.Binding.BindingSerial++
				case "ordinary-reader":
					selected = reader
				case "wrong-source-kind":
					selected.SubjectKind = 2
				case "wrong-recovery-role":
					selected = contract.BindingTableRow{SubjectKind: 2, SubjectID: id("not current recovery"), Binding: control.Recovery.KMS}
				case "changed-authority-table":
					for i := range rows {
						if rows[i].SubjectID == original.authority {
							rows[i].Binding.BindingSerial++
						}
					}
				case "changed-recovery-table":
					for i := range rows {
						if rows[i].SubjectKind == 2 {
							rows[i].Binding.BindingSerial++
						}
					}
				case "missing-recovery-table":
					rows = slices.DeleteFunc(rows, func(row contract.BindingTableRow) bool { return row.SubjectKind == 2 })
				case "disabled-recovery":
					before.Recovery = nil
				}
				if keys, err := NewCurrentReplacement(t, id("refused replacement"), before, rows, selected); keys != nil || err != privatecrypto.ErrAdmission {
					t.Fatal("noncurrent replacement source admitted", err)
				}
			})
		}
	}
}

// full_only: false
func TestSyntheticSuccessorNeverReusesFixtureKeys(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		for _, first := range []uint8{contract.SuccessorAuthorityKEK, contract.SuccessorRecoveryKEK} {
			t.Run(fmt.Sprint(family, "/", first), func(t *testing.T) {
				id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
				f := New(t, family, id("distinct successors"), true, []contract.ID{id("authority"), id("reader")})
				used := make(map[contract.ID]*rsa.PrivateKey)
				for _, row := range f.Bindings() {
					used[row.Binding.Fingerprint] = f.keys[row.Binding.BindingID]
				}
				for generation := 0; generation < 4; generation++ {
					role := first
					if generation%2 != 0 {
						role = contract.SuccessorAuthorityKEK + contract.SuccessorRecoveryKEK - first
					}
					subject := f.authority
					if role == contract.SuccessorRecoveryKEK {
						subject = f.recovery
					}
					f.LoseRecipientPredecessor(subject)
					after := f.KEKSuccessor(t, role)
					if used[after.Fingerprint] != nil {
						t.Fatalf("generation %d reused an initial, reader or retired fixture key", generation)
					}
					if again := f.KEKSuccessor(t, role); again.Fingerprint != after.Fingerprint || again.BindingID != after.BindingID {
						t.Fatal("repeated pending proposal consumed another key")
					}
					if len(f.usedFingerprints) != 4+generation || !f.usedFingerprints[after.Fingerprint] {
						t.Fatal("proposal did not retain the full issued key history")
					}
					key := f.keys[after.BindingID]
					ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte("successor-only challenge"), nil)
					if err != nil {
						t.Fatal(err)
					}
					for _, old := range used {
						plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, old, ciphertext, nil)
						clear(plaintext[:cap(plaintext)])
						if err == nil {
							t.Fatal("an already issued private key opened successor material")
						}
					}
					used[after.Fingerprint] = key
					if err := f.ActivateSuccessor(subject); err != nil {
						t.Fatal(err)
					}
					var authority contract.BindingTableRow
					for _, row := range f.Bindings() {
						if row.SubjectID == f.authority {
							authority = row
						}
					}
					fresh := NewCurrentConsumer(t, id("cold successor"), f.authority, f.recovery, f.Bindings(), authority)
					if len(fresh.keys) != 1 || len(fresh.routes) != 1 {
						t.Fatal("fresh consumer installed an unrelated private route")
					}
					for _, row := range fresh.Bindings() {
						if !fresh.usedFingerprints[row.Binding.Fingerprint] {
							t.Fatal("fresh consumer omitted a current public key from its fixture history")
						}
					}
					if got := fresh.PrivateWitness(context.Background(), authority.Binding.BindingID, authority.Binding, authority.Binding); got != (RouteWitness{Outcome: contract.CryptoSuccess, Completed: 1}) {
						t.Fatal("fresh consumer did not resolve its current corpus key", got)
					}
					for _, route := range f.routes {
						if privatecrypto.TestRuntimeRoutes(fresh.runtime, family, []contract.ID{route}) == nil {
							t.Fatal("fresh consumer retained another fixture route")
						}
					}
				}
				f.mu.Lock()
				key, spki := f.unusedSuccessorKey(t)
				f.mu.Unlock()
				if key != nil || spki != nil || len(f.usedFingerprints) != len(fixturePrivateKeys) || !f.successor.SubjectID.IsZero() {
					t.Fatal("exhausted corpus offered a previously issued key")
				}
			})
		}
	}
}

// full_only: false
func TestSyntheticSuccessorReaderDoesNotReuseRecoveryKey(t *testing.T) {
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	for _, recovery := range []bool{false, true} {
		f := New(t, contract.AWS, id("reader successor"), recovery, []contract.ID{id("authority"), id("reader")})
		before := f.Bindings()
		after := f.RecipientSuccessor(t, id("reader"))
		for _, row := range before {
			if row.Binding.Fingerprint == after.Fingerprint {
				t.Fatal("reader successor reused an initial fixture key")
			}
		}
	}
}
