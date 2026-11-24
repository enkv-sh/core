package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type testKeyAccess struct {
	mu                        sync.Mutex
	key                       *rsa.PrivateKey
	binding                   contract.KMSBinding
	publicCalls, privateCalls int
	returned                  []byte
	started                   chan struct{}
	release                   <-chan struct{}
}

func (a *testKeyAccess) Family() contract.Family { return contract.GCP }
func (a *testKeyAccess) CredentialRoute() contract.ID {
	return contract.Hash([]byte("test private route"))
}
func (a *testKeyAccess) Qualify(_ context.Context, b contract.KMSBinding) KeyResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.publicCalls++
	if b.BindingID != a.binding.BindingID || !bytes.Equal(b.SPKI, a.binding.SPKI) {
		return KeyResult{Status: KeyInvalid}
	}
	return KeyResult{Status: KeyOK, Uses: KeyUses{Completed: 3}}
}
func (a *testKeyAccess) Decrypt(ctx context.Context, b contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.privateCalls++
	if ctx.Err() != nil {
		return PrivateResult{Status: KeyCancelled}
	}
	if b.BindingID != a.binding.BindingID {
		return PrivateResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
	}
	if a.started != nil {
		close(a.started)
		<-a.release
	}
	packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, a.key, ciphertext, nil)
	if err != nil || len(packet) != int(length) {
		clear(packet)
		return PrivateResult{Status: KeyAuthenticationFailed, Uses: KeyUses{Failed: 1}}
	}
	owned := make([]byte, len(packet), len(packet)+32)
	copy(owned, packet)
	clear(packet[:cap(packet)])
	for i := len(owned); i < cap(owned); i++ {
		owned[:cap(owned)][i] = 0xa5
	}
	a.returned = owned[:cap(owned)]
	return PrivateResult{Status: KeyOK, Uses: KeyUses{Completed: 1}, Packet: owned}
}

func initializationCustodyFixture(t *testing.T) (*Runtime, *testKeyAccess, contract.CryptoQualifyInitKeysRequest, contract.CryptoRequest, time.Time) {
	t.Helper()
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := contract.KMSBinding{BindingID: id("binding"), BindingIncarnationID: id("binding incarnation"), BindingSerial: 1, Provider: contract.GCP, WrapProfile: 2, ProtectionClass: 2, KeySelector: "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/authority/cryptoKeyVersions/1", SPKI: spki, Fingerprint: contract.Hash(spki)}
	digest, err := contract.PublicBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	access := &testKeyAccess{key: key, binding: binding}
	runtime, err := New(contract.GCP, []KeyAccess{access})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Close)
	deadline := time.Now().Add(time.Minute)
	q := contract.CryptoQualifyInitKeysRequest{Context: contract.InitKeyContext{Schema: contract.CryptoSchema, GenesisProfile: 1, AdmissionID: id("admission"), SessionID: id("session"), DomainID: id("domain"), CompatibilityID: contract.CompatibilityID(), Expiry: uint64(deadline.UnixNano()), InitID: id("init"), DescriptorDigest: id("descriptor"), GenesisPlanDigest: id("plan"), RequestDescriptor: contract.DescriptorVector{Digest: id("request"), Length: contract.GenesisRequestCoreLength, Count: 1}}, Bindings: []contract.BindingTableRow{{SubjectKind: 1, SubjectID: id("authority"), Binding: binding}}, Probes: []contract.InitProbePlanRow{{ProbeID: id("probe"), SubjectKind: 1, SubjectID: id("authority"), BindingID: binding.BindingID, PublicBindingDigest: digest}}}
	body, err := contract.EncodeCryptoQualifyInitKeysRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	request := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoQualifyInitKeys, RequestID: id("message"), CustodyInstanceID: runtime.InstanceID(), Body: body}
	return runtime, access, q, request, deadline
}

// full_only: false
func TestInitQualificationRequiresPrivateAdmissionAndRunsOnce(t *testing.T) {
	metricContext, reader := cryptoTelemetryReader(t)
	id := func(s string) contract.ID { return contract.Hash([]byte(s)) }
	runtime, access, q, request, deadline := initializationCustodyFixture(t)
	binding := access.binding
	var err error
	if reply := runtime.Exchange(metricContext, request); reply.ResultCode != contract.CryptoInvalidAdmission {
		t.Fatalf("unadmitted request result %v", reply.ResultCode)
	}
	if access.publicCalls != 0 || access.privateCalls != 0 {
		t.Fatal("unadmitted request used private route")
	}
	routes := map[contract.ID]contract.ID{binding.BindingID: access.CredentialRoute()}
	if err := runtime.admitInit(q, contract.CryptoSupportID(), routes, routes, deadline); err != nil {
		t.Fatal(err)
	}
	reply := runtime.Exchange(metricContext, request)
	if reply.ResultCode != contract.CryptoSuccess {
		t.Fatalf("qualification result %v", reply.ResultCode)
	}
	if access.publicCalls != 1 || access.privateCalls != 1 {
		t.Fatal("qualification did not exercise exact routes once")
	}
	if len(reply.Body) == 0 || len(reply.KeyUseRows) != 2 {
		t.Fatal("qualification omitted public evidence")
	}
	if reply.KeyUseRows[0].Purpose != contract.KeyUsePublicKeyRead || reply.KeyUseRows[0].Count != 3 || reply.KeyUseRows[1].Purpose != contract.KeyUsePrivateRoleProbe || reply.KeyUseRows[1].Count != 1 {
		t.Fatal("qualification reported inexact provider key-use facts")
	}
	if !bytes.Equal(access.returned, make([]byte, len(access.returned))) {
		t.Fatal("qualification retained private packet backing capacity")
	}
	if second := runtime.Exchange(metricContext, request); second.ResultCode != contract.CryptoAlreadyUsed || len(second.Body) != 0 {
		t.Fatal("repeated qualification returned usable evidence")
	}
	if access.publicCalls != 1 || access.privateCalls != 1 {
		t.Fatal("repeated qualification reused a key")
	}
	assertCryptoTelemetry(t, reader, "crypto.qualify_init_keys", map[string]int64{"admission_refused": 1, "success": 1, "already_used": 1})
	t.Run("finished-session-releases-buffers", func(t *testing.T) {
		select {
		case <-runtime.init.done:
		case <-time.After(time.Second):
			t.Fatal("completed qualification retained its deadline observer")
		}
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		if runtime.init.body != nil || runtime.init.publicRoutes != nil || runtime.init.privateRoutes != nil {
			t.Fatal("completed qualification retained operation buffers")
		}
	})
	t.Run("expired-abandoned-session-clears-without-another-call", func(t *testing.T) {
		runtime.retireInit()
		q.Context.AdmissionID = id("expiring admission")
		deadline = time.Now().Add(50 * time.Millisecond)
		q.Context.Expiry = uint64(deadline.UnixNano())
		if err := runtime.admitInit(q, contract.CryptoSupportID(), routes, routes, deadline); err != nil {
			t.Fatal(err)
		}
		select {
		case <-runtime.init.done:
		case <-time.After(time.Second):
			t.Fatal("expired qualification retained its observer")
		}
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		if runtime.init.body != nil || runtime.init.publicRoutes != nil || runtime.init.privateRoutes != nil {
			t.Fatal("expired qualification retained operation buffers")
		}
		if access.publicCalls != 1 || access.privateCalls != 1 {
			t.Fatal("unused expired admission called a key")
		}
	})
	t.Run("cancelled-entry-consumes-admission-without-key-use", func(t *testing.T) {
		runtime.retireInit()
		q.Context.AdmissionID = id("cancelled admission")
		deadline = time.Now().Add(time.Minute)
		q.Context.Expiry = uint64(deadline.UnixNano())
		if err := runtime.admitInit(q, contract.CryptoSupportID(), routes, routes, deadline); err != nil {
			t.Fatal(err)
		}
		request.Body, err = contract.EncodeCryptoQualifyInitKeysRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if reply := runtime.Exchange(ctx, request); reply.ResultCode != contract.CryptoCancelled {
			t.Fatalf("cancelled request returned %v", reply.ResultCode)
		}
		if reply := runtime.Exchange(context.Background(), request); reply.ResultCode != contract.CryptoAlreadyUsed {
			t.Fatalf("cancelled admission reused: %v", reply.ResultCode)
		}
		if access.publicCalls != 1 || access.privateCalls != 1 {
			t.Fatal("cancelled request used a key")
		}
	})
	t.Run("overlapping-requests-accept-only-once", func(t *testing.T) {
		runtime.retireInit()
		q.Context.AdmissionID = id("concurrent admission")
		if err := runtime.admitInit(q, contract.CryptoSupportID(), routes, routes, deadline); err != nil {
			t.Fatal(err)
		}
		request.Body, err = contract.EncodeCryptoQualifyInitKeysRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		results := make(chan contract.CryptoResponse, 2)
		for range 2 {
			go func() { <-start; results <- runtime.Exchange(context.Background(), request) }()
		}
		close(start)
		codes := map[contract.CryptoResultCode]int{}
		for range 2 {
			result := <-results
			codes[result.ResultCode]++
		}
		if codes[contract.CryptoSuccess] != 1 || codes[contract.CryptoAlreadyUsed] != 1 {
			t.Fatalf("overlapping results %v", codes)
		}
		if access.publicCalls != 2 || access.privateCalls != 2 {
			t.Fatal("overlap reused a key")
		}
	})
	t.Run("cancellation-joins-late-private-response", func(t *testing.T) {
		runtime.retireInit()
		q.Context.AdmissionID = id("late response admission")
		if err := runtime.admitInit(q, contract.CryptoSupportID(), routes, routes, deadline); err != nil {
			t.Fatal(err)
		}
		request.Body, err = contract.EncodeCryptoQualifyInitKeysRequest(q)
		if err != nil {
			t.Fatal(err)
		}
		release := make(chan struct{})
		access.started = make(chan struct{})
		access.release = release
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan contract.CryptoResponse, 1)
		go func() { result <- runtime.Exchange(ctx, request) }()
		<-access.started
		cancel()
		select {
		case <-runtime.init.done:
			t.Fatal("session disposed before private response joined")
		default:
		}
		close(release)
		reply := <-result
		if reply.ResultCode != contract.CryptoCancelled || len(reply.Body) != 0 {
			t.Fatal("late private result became usable")
		}
		if len(reply.KeyUseRows) != 2 {
			t.Fatal("cancellation lost completed private-use evidence")
		}
		<-runtime.init.done
		if !bytes.Equal(access.returned, make([]byte, len(access.returned))) {
			t.Fatal("late packet retained private capacity")
		}
		access.started = nil
		access.release = nil
	})
}
