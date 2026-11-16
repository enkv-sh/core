// Package custody owns synthetic encryption keys and private test admission.
// Its exported surface carries only public records and safe test controls.
package custody

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/compositions/generatorhost"
	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

type Fixture struct {
	mu                        sync.Mutex
	family                    contract.Family
	authority, recovery       contract.ID
	bindings                  []contract.BindingTableRow
	keys                      map[contract.ID]*rsa.PrivateKey
	routes                    map[contract.ID]contract.ID
	publicRoutes              map[contract.ID]contract.ID
	runtime                   *privatecrypto.Runtime
	publicCalls, privateCalls int
	unavailable               bool
	sinkFailure               bool
	denied                    map[contract.ID]bool
	accepted                  map[contract.ID]contract.SealedInputCore
	successor                 contract.BindingTableRow
	lostBindings              map[contract.ID]bool
	usedFingerprints          map[contract.ID]bool
	qualificationUses         *uint32
	generatedProcess          *generatorhost.NativeLauncher
	publicationOutputs        map[string]publicationOutput
}

// ForkGenerated gives an independent producer its own Crypto session while
// retaining the same admitted key routes and selected public bindings.
func (f *Fixture) ForkGenerated(t testing.TB) *Fixture {
	t.Helper()
	if f == nil || f.runtime == nil {
		t.Fatal("generated custody unavailable")
	}
	runtime, err := f.runtime.Fork()
	if err != nil {
		t.Fatal("generated custody fork unavailable", err)
	}
	f.mu.Lock()
	child := &Fixture{family: f.family, authority: f.authority, recovery: f.recovery,
		bindings: slices.Clone(f.bindings), keys: maps.Clone(f.keys), routes: maps.Clone(f.routes), publicRoutes: maps.Clone(f.publicRoutes),
		runtime: runtime, denied: maps.Clone(f.denied), accepted: maps.Clone(f.accepted), successor: f.successor,
		lostBindings: maps.Clone(f.lostBindings), usedFingerprints: maps.Clone(f.usedFingerprints), qualificationUses: f.qualificationUses}
	f.mu.Unlock()
	t.Cleanup(runtime.Close)
	return child
}

// New fixes the first recipient as authority. Other ordinary recipients use a
// separate synthetic key; recovery has a third independent key and resource.
func New(t testing.TB, family contract.Family, identity contract.ID, recovery bool, recipients []contract.ID) *Fixture {
	t.Helper()
	if identity.IsZero() || len(recipients) < 1 || len(recipients) > 256 || (family != contract.AWS && family != contract.GCP) {
		t.Fatal("invalid custody fixture")
	}
	f := &Fixture{family: family, authority: recipients[0], keys: make(map[contract.ID]*rsa.PrivateKey), routes: make(map[contract.ID]contract.ID), publicRoutes: make(map[contract.ID]contract.ID), denied: make(map[contract.ID]bool), accepted: make(map[contract.ID]contract.SealedInputCore), usedFingerprints: make(map[contract.ID]bool)}
	if recovery {
		f.recovery = fixtureID(identity, "recovery", contract.ID{})
	}
	seen := make(map[contract.ID]bool, len(recipients))
	var accesses []privatecrypto.KeyAccess
	for i, subject := range append(slices.Clone(recipients), f.recovery) {
		if i == len(recipients) && !recovery {
			break
		}
		if subject.IsZero() || seen[subject] {
			t.Fatal("duplicate or zero fixture subject")
		}
		seen[subject] = true
		kind, keyIndex := contract.OrdinaryWrapSubject, 1
		if i == 0 {
			keyIndex = 0
		}
		if i == len(recipients) {
			kind, keyIndex = contract.RecoveryWrapSubject, 2
		}
		der, err := base64.StdEncoding.DecodeString(fixturePrivateKeys[keyIndex])
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
		binding := contract.KMSBinding{BindingID: fixtureID(identity, "binding", subject), BindingIncarnationID: fixtureID(identity, "binding incarnation", subject), BindingSerial: 1, Provider: family, WrapProfile: 2, ProtectionClass: 2, SPKI: spki, Fingerprint: contract.Hash(spki)}
		selector := hex.EncodeToString(binding.BindingID[:16])
		if family == contract.AWS {
			binding.ProtectionClass = 1
			binding.KeySelector = fmt.Sprintf("arn:aws:kms:us-east-1:123456789012:key/%s-%s-%s-%s-%s", selector[:8], selector[8:12], selector[12:16], selector[16:20], selector[20:])
		} else {
			binding.KeySelector = "projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/key-" + selector + "/cryptoKeyVersions/1"
		}
		if _, err := contract.PublicBindingDigest(binding); err != nil {
			t.Fatal(err)
		}
		f.bindings = append(f.bindings, contract.BindingTableRow{SubjectKind: kind, SubjectID: subject, Binding: binding})
		f.usedFingerprints[binding.Fingerprint] = true
		f.keys[binding.BindingID] = key
		route := fixtureID(identity, "route", subject)
		f.routes[binding.BindingID] = route
		f.publicRoutes[binding.BindingID] = fixtureID(identity, "route", f.authority)
		accesses = append(accesses, &keyRoute{owner: f, subject: subject, id: route})
	}
	slices.SortFunc(f.bindings, func(a, b contract.BindingTableRow) int {
		if a.SubjectKind != b.SubjectKind {
			return int(a.SubjectKind) - int(b.SubjectKind)
		}
		return bytes.Compare(a.SubjectID[:], b.SubjectID[:])
	})
	var err error
	f.runtime, err = privatecrypto.New(family, accesses)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.runtime.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.keys = nil
		f.routes = nil
		f.publicRoutes = nil
		f.bindings = nil
		f.accepted = nil
		f.usedFingerprints = nil
	})
	return f
}

// UseAuthoritySelector fixes the independently chosen authority resource before
// public qualification or private key use. Other recipient routes are unchanged.
func (f *Fixture) UseAuthoritySelector(t testing.TB, selector string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.publicCalls != 0 || f.privateCalls != 0 {
		t.Fatal("selector fixture already used")
	}
	for i := range f.bindings {
		if f.bindings[i].SubjectKind != contract.OrdinaryWrapSubject || f.bindings[i].SubjectID != f.authority {
			continue
		}
		binding := f.bindings[i].Binding
		binding.KeySelector = selector
		if _, err := contract.PublicBindingDigest(binding); err != nil {
			t.Fatal(err)
		}
		f.bindings[i].Binding = binding
		return
	}
	t.Fatal("authority selector fixture missing")
}

// UseMaximumSelectors fills the contract's public selector capacity before any
// key use. GCP routes retain public selector grammar; the locations are synthetic
// and do not establish that a provider region exists. AWS routes test storage.
func (f *Fixture) UseMaximumSelectors(t testing.TB) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.publicCalls != 0 || f.privateCalls != 0 {
		t.Fatal("selector fixture already used")
	}
	for i := range f.bindings {
		b := &f.bindings[i].Binding
		if f.family == contract.GCP {
			b.KeySelector = maximumGCPSelector(i)
		} else {
			b.KeySelector += strings.Repeat("x", contract.MaxKeySelector-len(b.KeySelector))
		}
		if _, err := contract.PublicBindingDigest(*b); err != nil {
			t.Fatal(err)
		}
	}
}

func maximumGCPSelector(index int) string {
	project := fmt.Sprintf("p%029d", index)
	keyRing := fmt.Sprintf("ring-%058d", index)
	key := fmt.Sprintf("key-%059d", index)
	version := "9223372036854775807"
	prefix := "projects/" + project + "/locations/"
	suffix := "/keyRings/" + keyRing + "/cryptoKeys/" + key + "/cryptoKeyVersions/" + version
	locationLength := contract.MaxKeySelector - len(prefix) - len(suffix)
	return prefix + "us-" + strings.Repeat("x", locationLength-4) + "1" + suffix
}

func fixtureID(identity contract.ID, purpose string, subject contract.ID) contract.ID {
	b := append([]byte("ENKV/TEST-CUSTODY/v2/"+purpose+"\x00"), identity[:]...)
	return contract.Hash(append(b, subject[:]...))
}

func (f *Fixture) Crypto() contract.Crypto { return f.runtime }

// ReconstructionVerifier owns a separate private runtime for one complete
// selected-state verification. Its surface carries only typed results.
type ReconstructionVerifier struct {
	fork     *privatecrypto.Runtime
	verifier *privatecrypto.ReconstructionVerifier
}

func (v *ReconstructionVerifier) Verify(ctx context.Context, selected contract.ConsumerSelection) contract.CryptoResultCode {
	if v == nil || v.verifier == nil {
		return contract.CryptoInvalidAdmission
	}
	return v.verifier.Verify(ctx, selected)
}

func (v *ReconstructionVerifier) Close() {
	if v == nil {
		return
	}
	if v.verifier != nil {
		v.verifier.Close()
	}
	if v.fork != nil {
		v.fork.Close()
	}
}

// ReconstructionVerifier uses the authority route installed in this private
// test fixture. Selected pins cannot choose a different route.
func (f *Fixture) ReconstructionVerifier(ctx context.Context, pins contract.ReconstructionVerificationPins, deadline time.Time) (*ReconstructionVerifier, error) {
	if f == nil || ctx == nil || ctx.Err() != nil {
		return nil, privatecrypto.ErrAdmission
	}
	f.mu.Lock()
	var route contract.ID
	authority := f.authority
	for _, row := range f.bindings {
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == authority {
			route = f.routes[row.Binding.BindingID]
			break
		}
	}
	runtime := f.runtime
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime == nil || route.IsZero() || pins.AuthorityRecipientID != authority {
		return nil, privatecrypto.ErrAdmission
	}
	fork, err := runtime.Fork()
	if err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	verifier, err := privatecrypto.NewReconstructionVerifier(fork, route, pins, deadline)
	if err != nil {
		fork.Close()
		return nil, errors.Join(err, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		verifier.Close()
		fork.Close()
		return nil, err
	}
	return &ReconstructionVerifier{fork: fork, verifier: verifier}, nil
}

func (f *Fixture) RecoveryID() contract.ID { return f.recovery }
func (f *Fixture) Bindings() []contract.BindingTableRow {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := slices.Clone(f.bindings)
	for i := range rows {
		rows[i].Binding.SPKI = slices.Clone(rows[i].Binding.SPKI)
	}
	return rows
}

// AdmitInit is called by the trusted test parent after it independently
// reconstructs the exact descriptor/request/plan relation. The runtime compares
// every stage field to this private admission; the request itself grants none.
func (f *Fixture) AdmitInit(q contract.CryptoQualifyInitKeysRequest, support contract.ID, deadline time.Time) error {
	public, private, err := f.initializationRouteMaps(q)
	if err != nil {
		return err
	}
	return privatecrypto.TestAdmitInit(f.runtime, q, support, public, private, deadline)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func (f *Fixture) RetireInit() { privatecrypto.TestRetireInit(f.runtime) }

// Calls counts key-route method invocations, including refused calls.
func (f *Fixture) Calls() (public, private int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publicCalls, f.privateCalls
}
func (f *Fixture) SetUnavailable(v bool) { f.mu.Lock(); defer f.mu.Unlock(); f.unavailable = v }
func (f *Fixture) SetDenied(subject contract.ID, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denied[subject] = v
}

type keyRoute struct {
	owner       *Fixture
	subject, id contract.ID
}

func (r *keyRoute) Family() contract.Family      { return r.owner.family }
func (r *keyRoute) CredentialRoute() contract.ID { return r.id }
func (r *keyRoute) binding(b contract.KMSBinding) (contract.BindingTableRow, bool) {
	for _, row := range append(slices.Clone(r.owner.bindings), r.owner.successor) {
		if row.Binding.BindingID != b.BindingID {
			continue
		}
		got, err := contract.PublicBindingDigest(b)
		if err != nil {
			return row, false
		}
		want, err := contract.PublicBindingDigest(row.Binding)
		return row, err == nil && got == want
	}
	return contract.BindingTableRow{}, false
}
func (r *keyRoute) Qualify(ctx context.Context, b contract.KMSBinding) privatecrypto.KeyResult {
	f := r.owner
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publicCalls++
	if ctx.Err() != nil {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyCancelled}
	}
	if _, ok := r.binding(b); !ok {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyInvalid}
	}
	if f.unavailable {
		return privatecrypto.KeyResult{Status: privatecrypto.KeyUnavailable, Uses: privatecrypto.KeyUses{Unknown: 1}}
	}
	completed := uint32(2)
	if f.family == contract.GCP {
		completed = 3
	}
	if f.qualificationUses != nil {
		completed = *f.qualificationUses
	}
	return privatecrypto.KeyResult{Status: privatecrypto.KeyOK, Uses: privatecrypto.KeyUses{Completed: completed}}
}
func (r *keyRoute) Decrypt(ctx context.Context, b contract.KMSBinding, ciphertext []byte, length uint16) privatecrypto.PrivateResult {
	f := r.owner
	f.mu.Lock()
	defer f.mu.Unlock()
	f.privateCalls++
	if ctx.Err() != nil {
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyCancelled}
	}
	row, ok := r.binding(b)
	if !ok || len(ciphertext) != 384 || (length != 68 && length != 100) {
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyInvalid}
	}
	if f.unavailable {
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyUnavailable, Uses: privatecrypto.KeyUses{Unknown: 1}}
	}
	if row.SubjectID != r.subject || f.routes[b.BindingID] != r.id || f.denied[row.SubjectID] || f.lostBindings[b.BindingID] {
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyDenied, Uses: privatecrypto.KeyUses{Denied: 1}}
	}
	packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, f.keys[b.BindingID], ciphertext, nil)
	if err != nil || len(packet) != int(length) {
		clear(packet[:cap(packet)])
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyAuthenticationFailed, Uses: privatecrypto.KeyUses{Failed: 1}}
	}
	if ctx.Err() != nil {
		clear(packet[:cap(packet)])
		return privatecrypto.PrivateResult{Status: privatecrypto.KeyCancelled, Uses: privatecrypto.KeyUses{Completed: 1}}
	}
	return privatecrypto.PrivateResult{Status: privatecrypto.KeyOK, Uses: privatecrypto.KeyUses{Completed: 1}, Packet: packet}
}
