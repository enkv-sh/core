package custody

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	primitive "enkv.sh/crypto/internal/custody"
)

func (f *Fixture) SetQualificationUses(count uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.qualificationUses = &count
}

// SetCurrentBindingSerial aligns the synthetic custody view with a signed
// selected-state counter fixture. It preserves the selected key and routes.
func (f *Fixture) SetCurrentBindingSerial(t testing.TB, recipient contract.ID, serial uint64) {
	t.Helper()
	if serial == 0 {
		t.Fatal("zero binding serial")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	index := slices.IndexFunc(f.bindings, func(row contract.BindingTableRow) bool {
		return row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == recipient
	})
	if index < 0 || !f.successor.SubjectID.IsZero() {
		t.Fatal("binding serial fixture requires a current recipient without a pending successor")
	}
	f.bindings[index].Binding.BindingSerial = serial
}

// RecipientSuccessor installs the pre-existing synthetic successor route.
// It does not change the current binding or admit a replacement operation.
func (f *Fixture) RecipientSuccessor(t testing.TB, recipient contract.ID) contract.KMSBinding {
	t.Helper()
	if recipient == f.authority {
		t.Fatal("ordinary successor target refused")
	}
	return f.currentSuccessor(t, 1, recipient, false)
}

func (f *Fixture) KEKSuccessor(t testing.TB, role uint8) contract.KMSBinding {
	t.Helper()
	switch role {
	case contract.SuccessorAuthorityKEK:
		return f.currentSuccessor(t, 1, f.authority, true)
	case contract.SuccessorRecoveryKEK:
		return f.currentSuccessor(t, 2, f.recovery, true)
	default:
		t.Fatal("successor role is not a KEK")
		return contract.KMSBinding{}
	}
}

func (f *Fixture) currentSuccessor(t testing.TB, kind uint8, subject contract.ID, independent bool) contract.KMSBinding {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys == nil {
		t.Fatal("live successor requires an explicit public binding and route")
	}
	index := slices.IndexFunc(f.bindings, func(row contract.BindingTableRow) bool { return row.SubjectKind == kind && row.SubjectID == subject })
	if index < 0 {
		t.Fatal("successor target is not current")
	}
	before := f.bindings[index]
	if f.successor.SubjectKind == kind && f.successor.SubjectID == subject {
		return f.successor.Binding
	}
	if !f.successor.SubjectID.IsZero() {
		t.Fatal("another successor is pending")
	}
	key, spki := f.unusedSuccessorKey(t)
	if key == nil {
		t.Fatal("synthetic successor key corpus exhausted")
	}
	binding := before.Binding
	binding.BindingID = fixtureID(before.Binding.BindingID, "successor", subject)
	if binding.BindingSerial == math.MaxUint64 {
		binding.BindingIncarnationID = fixtureID(before.Binding.BindingIncarnationID, "successor incarnation", binding.BindingID)
		binding.BindingSerial = 1
	} else {
		binding.BindingSerial++
	}
	binding.SPKI = spki
	binding.Fingerprint = contract.Hash(spki)
	selector := hex.EncodeToString(binding.BindingID[:16])
	if f.family == contract.AWS {
		binding.KeySelector = fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%s-%s-%s-%s-%s", selector[:8], selector[8:12], selector[12:16], selector[16:20], selector[20:])
	} else {
		binding.KeySelector = fmt.Sprintf("projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/key-%s/cryptoKeyVersions/%d", selector, binding.BindingSerial)
	}
	route := fixtureID(binding.BindingID, "route", subject)
	if err := privatecrypto.TestInstallKeyRoute(f.runtime, &keyRoute{owner: f, subject: subject, id: route}); err != nil {
		t.Fatal(err)
	}
	f.successor = contract.BindingTableRow{SubjectKind: kind, SubjectID: subject, Binding: binding}
	// A proposal consumes its key even after the predecessor route is retired.
	f.usedFingerprints[binding.Fingerprint] = true
	f.keys[binding.BindingID] = key
	f.routes[binding.BindingID] = route
	f.publicRoutes[binding.BindingID] = f.publicRoutes[before.Binding.BindingID]
	if independent {
		f.publicRoutes[binding.BindingID] = route
	}
	return binding
}

func (f *Fixture) unusedSuccessorKey(t testing.TB) (*rsa.PrivateKey, []byte) {
	t.Helper()
	for _, encoded := range fixturePrivateKeys {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("successor fixture key type")
		}
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !f.usedFingerprints[contract.Hash(spki)] {
			return key, spki
		}
	}
	return nil, nil
}

func (f *Fixture) InstallRecipientSuccessor(row contract.BindingTableRow, publicRoute, privateRoute contract.ID) error {
	if f == nil || row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID == f.authority || publicRoute.IsZero() {
		return privatecrypto.ErrAdmission
	}
	return f.installSuccessor(row, publicRoute, privateRoute)
}

func (f *Fixture) InstallKEKSuccessor(row contract.BindingTableRow, publicRoute, privateRoute contract.ID) error {
	if f == nil || publicRoute.IsZero() {
		return privatecrypto.ErrAdmission
	}
	authority := row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == f.authority
	recovery := row.SubjectKind == contract.RecoveryWrapSubject && !f.recovery.IsZero() && row.SubjectID == f.recovery
	if !authority && !recovery {
		return privatecrypto.ErrAdmission
	}
	return f.installSuccessor(row, publicRoute, privateRoute)
}

func (f *Fixture) installSuccessor(row contract.BindingTableRow, publicRoute, privateRoute contract.ID) error {
	routes := []contract.ID{publicRoute}
	if !privateRoute.IsZero() {
		routes = append(routes, privateRoute)
	}
	if err := privatecrypto.TestRuntimeRoutes(f.runtime, f.family, routes); err != nil {
		return err
	}
	if _, err := contract.PublicBindingDigest(row.Binding); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.successor.SubjectID.IsZero() {
		return privatecrypto.ErrAdmission
	}
	f.successor = row
	f.publicRoutes[row.Binding.BindingID] = publicRoute
	f.routes[row.Binding.BindingID] = privateRoute
	return nil
}

// MaterialPreserved is a synthetic-key oracle. It exposes only the equality
// assertion; key packets and both D/C pairs stay in the private fixture.
func (f *Fixture) MaterialPreserved(before, after contract.ConsumerSelection) bool {
	f.mu.Lock()
	beforeKey, afterKey := f.keys[before.Binding.Binding.BindingID], f.keys[after.Binding.Binding.BindingID]
	f.mu.Unlock()
	if beforeKey == nil || afterKey == nil {
		return false
	}
	a, err := contract.EncodeValueCore(before.Core)
	if err != nil {
		return false
	}
	b, err := contract.EncodeValueCore(after.Core)
	if err != nil || !bytes.Equal(a, b) {
		return false
	}
	open := func(selection contract.ConsumerSelection, key *rsa.PrivateKey) ([]byte, bool) {
		wc, err := primitive.ValueWrapCore(selection.Core, selection.Binding)
		if err != nil {
			return nil, false
		}
		packetContext, err := contract.RSAPacketContextDigest(wc)
		if err != nil {
			return nil, false
		}
		index := slices.IndexFunc(selection.Access.Wraps, func(w contract.WrapRow) bool { return w.BindingID == selection.Binding.Binding.BindingID })
		if index < 0 {
			return nil, false
		}
		packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, selection.Access.Wraps[index].RSACiphertext, nil)
		if err != nil {
			clear(packet)
			return nil, false
		}
		defer clear(packet)
		keys, err := primitive.PacketKeys(packet, 1, packetContext)
		if err != nil {
			return nil, false
		}
		check, err := primitive.PackageCheck(selection.Core, keys)
		if err != nil || check != selection.Access.PackageCheck {
			return nil, false
		}
		return bytes.Clone(keys), true
	}
	first, ok := open(before, beforeKey)
	defer clear(first)
	if !ok {
		return false
	}
	second, ok := open(after, afterKey)
	defer clear(second)
	return ok && subtle.ConstantTimeCompare(first, second) == 1
}

func (f *Fixture) LoseRecipientPredecessor(recipient contract.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lostBindings == nil {
		f.lostBindings = make(map[contract.ID]bool)
	}
	for _, row := range f.bindings {
		if row.SubjectID == recipient {
			f.lostBindings[row.Binding.BindingID] = true
		}
	}
}

// RetireCurrentPrivateRoute removes exactly one lost current private route.
// Its public binding and issued fingerprint remain, and its runtime's admitted
// operation is neither consumed nor retired.
func (f *Fixture) RetireCurrentPrivateRoute(selected contract.BindingTableRow) error {
	if f == nil {
		return privatecrypto.ErrAdmission
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	index := slices.IndexFunc(f.bindings, func(row contract.BindingTableRow) bool {
		return row.SubjectKind == selected.SubjectKind && row.SubjectID == selected.SubjectID && row.Binding.BindingID == selected.Binding.BindingID
	})
	if index < 0 || f.keys[selected.Binding.BindingID] == nil || f.routes[selected.Binding.BindingID].IsZero() {
		return privatecrypto.ErrAdmission
	}
	want, err := contract.PublicBindingDigest(f.bindings[index].Binding)
	if err != nil {
		return err
	}
	got, err := contract.PublicBindingDigest(selected.Binding)
	if err != nil || want != got {
		return privatecrypto.ErrAdmission
	}
	delete(f.keys, selected.Binding.BindingID)
	delete(f.routes, selected.Binding.BindingID)
	delete(f.publicRoutes, selected.Binding.BindingID)
	if f.lostBindings == nil {
		f.lostBindings = make(map[contract.ID]bool)
	}
	f.lostBindings[selected.Binding.BindingID] = true
	return nil
}

func (f *Fixture) ActivateRecipientSuccessor(recipient contract.ID) error {
	return f.ActivateSuccessor(recipient)
}

func (f *Fixture) ActivateSuccessor(subject contract.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.successor.SubjectID != subject {
		return privatecrypto.ErrAdmission
	}
	for i, row := range f.bindings {
		if row.SubjectID == subject {
			delete(f.keys, row.Binding.BindingID)
			delete(f.routes, row.Binding.BindingID)
			delete(f.publicRoutes, row.Binding.BindingID)
			f.bindings[i] = f.successor
			f.successor = contract.BindingTableRow{}
			return nil
		}
	}
	return privatecrypto.ErrAdmission
}

func (f *Fixture) AdmitAccess(q contract.CryptoAccessReplaceRequest, intent contract.RecipientReplacementIntent, request contract.RequestCore, control contract.ControlCore, rows []contract.CompactRow, deadline time.Time) error {
	f.mu.Lock()
	expected := slices.Clone(f.bindings)
	successor := f.successor
	route := f.routes[control.AuthorityKMSBinding.BindingID]
	public := f.publicRoutes[successor.Binding.BindingID]
	f.mu.Unlock()
	if successor.SubjectID != intent.RecipientID {
		return privatecrypto.ErrAdmission
	}
	expected = append(expected, successor)
	slices.SortFunc(expected, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
			return n
		}
		if a.Binding.BindingSerial < b.Binding.BindingSerial {
			return -1
		}
		return 1
	})
	want, err := contract.EncodeBindingTable(expected)
	if err != nil {
		return err
	}
	got, err := contract.EncodeBindingTable(q.BindingTable)
	if err != nil || !bytes.Equal(got, want) {
		return privatecrypto.ErrAdmission
	}
	return privatecrypto.TestAdmitAccess(f.runtime, q, intent, request, control, rows, route, public, deadline)
}

func (f *Fixture) AdmitSuccessionAccess(q contract.CryptoAccessReplaceRequest, request contract.SuccessionRequestCore, before contract.ControlCore, source contract.BindingTableRow, probe contract.SuccessorKEKProbeCore, rows []contract.CompactRow, deadline time.Time) error {
	f.mu.Lock()
	expected := append(slices.Clone(f.bindings), f.successor)
	successor := f.successor
	sourceRoute := f.routes[source.Binding.BindingID]
	publicRoute, privateRoute := f.publicRoutes[successor.Binding.BindingID], f.routes[successor.Binding.BindingID]
	f.mu.Unlock()
	if successor.SubjectID.IsZero() {
		return privatecrypto.ErrAdmission
	}
	slices.SortFunc(expected, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		if n := bytes.Compare(a.SubjectID[:], b.SubjectID[:]); n != 0 {
			return n
		}
		if a.Binding.BindingSerial < b.Binding.BindingSerial {
			return -1
		}
		if a.Binding.BindingSerial > b.Binding.BindingSerial {
			return 1
		}
		return bytes.Compare(a.Binding.BindingID[:], b.Binding.BindingID[:])
	})
	want, err := contract.EncodeBindingTable(expected)
	if err != nil {
		return err
	}
	got, err := contract.EncodeBindingTable(q.BindingTable)
	if err != nil || !bytes.Equal(want, got) {
		return privatecrypto.ErrAdmission
	}
	return privatecrypto.TestAdmitSuccessionAccess(f.runtime, q, request, before, source, probe, rows, sourceRoute, publicRoute, privateRoute, deadline)
}

func (f *Fixture) RetireAccess() { privatecrypto.TestRetireAccess(f.runtime) }

func (f *Fixture) RestoreRecipientSuccessor(t testing.TB, row contract.BindingTableRow) {
	t.Helper()
	expected := f.RecipientSuccessor(t, row.SubjectID)
	a, err := contract.PublicBindingDigest(expected)
	if err != nil {
		t.Fatal(err)
	}
	b, err := contract.PublicBindingDigest(row.Binding)
	if err != nil || a != b {
		t.Fatal("selected successor differs from independent fixture route")
	}
	f.LoseRecipientPredecessor(row.SubjectID)
	if err := f.ActivateRecipientSuccessor(row.SubjectID); err != nil {
		t.Fatal(err)
	}
}

// NewCurrentConsumer installs only the explicitly selected current private
// route. The complete public table is retained for exact admission checks;
// no predecessor or unrelated private route is created in a fresh process.
func NewCurrentConsumer(t testing.TB, identity, authority, recovery contract.ID, current []contract.BindingTableRow, selected contract.BindingTableRow) *Fixture {
	t.Helper()
	if selected.SubjectKind != contract.OrdinaryWrapSubject {
		t.Fatal("invalid current consumer fixture")
	}
	f, err := newCurrentRoute(t, identity, authority, recovery, current, selected)
	if err != nil {
		t.Fatal("invalid current consumer fixture", err)
	}
	return f
}

// NewCurrentReplacement installs only the exact current authority or recovery
// source in an independent fixture. No private inventories or live operations
// are copied from the fixture whose selected work needs replacement.
func NewCurrentReplacement(t testing.TB, identity contract.ID, control contract.ControlCore, current []contract.BindingTableRow, selected contract.BindingTableRow) (*Fixture, error) {
	t.Helper()
	if _, err := contract.EncodeControlCore(control); err != nil || control.CompatibilityID != contract.CompatibilityID() || control.CryptoSupportID != contract.CryptoSupportID() {
		return nil, privatecrypto.ErrAdmission
	}
	if _, err := contract.EncodeBindingTable(current); err != nil {
		return nil, privatecrypto.ErrAdmission
	}
	authorityFound, recoveryFound := false, false
	for _, row := range current {
		if row.Binding.Provider != control.Provider {
			return nil, privatecrypto.ErrAdmission
		}
		var expected contract.KMSBinding
		switch {
		case row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == control.AuthorityRecipientID:
			if authorityFound {
				return nil, privatecrypto.ErrAdmission
			}
			authorityFound, expected = true, control.AuthorityKMSBinding
		case row.SubjectKind == contract.RecoveryWrapSubject:
			if control.Recovery == nil || row.SubjectID != control.Recovery.RoleID || recoveryFound {
				return nil, privatecrypto.ErrAdmission
			}
			recoveryFound, expected = true, control.Recovery.KMS
		default:
			continue
		}
		want, err := contract.PublicBindingDigest(expected)
		if err != nil {
			return nil, privatecrypto.ErrAdmission
		}
		got, err := contract.PublicBindingDigest(row.Binding)
		if err != nil || got != want {
			return nil, privatecrypto.ErrAdmission
		}
	}
	if !authorityFound || recoveryFound != (control.Recovery != nil) {
		return nil, privatecrypto.ErrAdmission
	}
	recovery := contract.ID{}
	if control.Recovery != nil {
		recovery = control.Recovery.RoleID
	}
	if (selected.SubjectKind != contract.OrdinaryWrapSubject || selected.SubjectID != control.AuthorityRecipientID) &&
		(selected.SubjectKind != contract.RecoveryWrapSubject || recovery.IsZero() || selected.SubjectID != recovery) {
		return nil, privatecrypto.ErrAdmission
	}
	return newCurrentRoute(t, identity, control.AuthorityRecipientID, recovery, current, selected)
}

func newCurrentRoute(t testing.TB, identity, authority, recovery contract.ID, current []contract.BindingTableRow, selected contract.BindingTableRow) (*Fixture, error) {
	t.Helper()
	body, err := contract.EncodeBindingTable(current)
	if err != nil || identity.IsZero() || authority.IsZero() {
		return nil, privatecrypto.ErrAdmission
	}
	owned, err := contract.DecodeBindingTable(body)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(owned, func(row contract.BindingTableRow) bool {
		return row.SubjectKind == selected.SubjectKind && row.SubjectID == selected.SubjectID && row.Binding.BindingID == selected.Binding.BindingID
	})
	if index < 0 {
		return nil, privatecrypto.ErrAdmission
	}
	want, err := contract.PublicBindingDigest(owned[index].Binding)
	if err != nil {
		return nil, err
	}
	got, err := contract.PublicBindingDigest(selected.Binding)
	if err != nil || got != want {
		return nil, privatecrypto.ErrAdmission
	}
	f := &Fixture{family: selected.Binding.Provider, authority: authority, recovery: recovery, bindings: owned, keys: make(map[contract.ID]*rsa.PrivateKey), routes: make(map[contract.ID]contract.ID), publicRoutes: make(map[contract.ID]contract.ID), denied: make(map[contract.ID]bool), accepted: make(map[contract.ID]contract.SealedInputCore), usedFingerprints: make(map[contract.ID]bool)}
	for _, row := range owned {
		f.usedFingerprints[row.Binding.Fingerprint] = true
	}
	for _, encoded := range fixturePrivateKeys {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		clear(der)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("invalid fixture key type")
		}
		spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(spki, selected.Binding.SPKI) {
			f.keys[selected.Binding.BindingID] = key
			break
		}
	}
	if f.keys[selected.Binding.BindingID] == nil {
		return nil, privatecrypto.ErrAdmission
	}
	route := fixtureID(identity, "current-consumer-route", selected.Binding.BindingID)
	f.routes[selected.Binding.BindingID] = route
	f.runtime, err = privatecrypto.New(f.family, []privatecrypto.KeyAccess{&keyRoute{owner: f, subject: selected.SubjectID, id: route}})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		f.runtime.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.keys, f.routes, f.publicRoutes, f.bindings = nil, nil, nil, nil
		f.usedFingerprints = nil
	})
	return f, nil
}
