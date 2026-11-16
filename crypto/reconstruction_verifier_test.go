package crypto

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func reconstructionPins(s contract.ConsumerSelection) contract.ReconstructionVerificationPins {
	return contract.ReconstructionVerificationPins{
		DomainID:   s.DomainID,
		SnapshotID: s.SnapshotID, HEADDigest: s.HEADDigest, HEADRevision: s.HEADRevision,
		AccessRoot: s.AccessRoot, AuthorityRecipientID: s.Binding.SubjectID,
		Root: s.Root, HEADToken: s.HEADToken, AuthorityBinding: s.Binding,
	}
}

func anotherReconstructionSecret(t *testing.T, first contract.ConsumerSelection) contract.ConsumerSelection {
	t.Helper()
	second := first
	second.Slot++
	second.Core.Name, second.Entry.Name = "second secret", "second secret"
	second.Core.EntryIncarnationID, second.Entry.Incarnation = consumerID("second incarnation"), consumerID("second incarnation")
	second.Core.ValueStateID, second.Entry.ValueState = consumerID("second value"), consumerID("second value")
	payload, keys, err := custody.SealValue(second.Core, []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	wrapCore, err := custody.ValueWrapCore(second.Core, second.Binding)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := custody.Wrap(wrapCore, second.Binding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	second.Payload = payload
	second.Access = contract.AccessRecord{Schema: contract.CanonicalSchema, MaterialKind: contract.ValueMaterialKind,
		MaterialID: second.Core.ValueStateID, MaterialContextDigest: wrapCore.MaterialContextDigest,
		PackageCheck: payload.PackageCheck, Wraps: []contract.WrapRow{wrap}}
	refreshConsumerSelection(t, &second)
	return second
}

// full_only: false
func TestReconstructionVerifierPurposeIsSeparateFromStoredSignatures(t *testing.T) {
	if got := hex.EncodeToString(reconstructionVerifyPurpose[:]); got != "c427cf7c5c1b63fc49d252873ddc006f0e0b9af6d7c2548a65405129f927e1cb" {
		t.Fatalf("private purpose drifted: %s", got)
	}
}

// full_only: false
func TestReconstructionVerifierAuthenticatesAndDiscardsSelectedSecret(t *testing.T) {
	selection, route := consumerFixture(t)
	runtime := newConsumerRuntime(t, route)
	pins := reconstructionPins(selection)
	pins.AuthorityBinding.Binding.SPKI = slices.Clone(selection.Binding.Binding.SPKI)
	verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), pins, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	clear(pins.AuthorityBinding.Binding.SPKI)
	if got := verifier.Verify(context.Background(), selection); got != contract.CryptoSuccess {
		t.Fatalf("selected value verification: %v", got)
	}
	if route.privateCalls != 1 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
		t.Fatal("verification did not use one authority decrypt or clear its packet")
	}
	verifier.Close()
	if got := verifier.Verify(context.Background(), selection); got == contract.CryptoSuccess || route.privateCalls != 1 {
		t.Fatal("closed verifier reused private custody")
	}
}

// full_only: false
func TestReconstructionVerifierUsesOnlyAuthorityWrapForSharedSecret(t *testing.T) {
	selection, route := consumerFixture(t)
	other := selection.Binding
	other.SubjectID = consumerID("another enrolled reader")
	other.Binding.BindingID = consumerID("another reader binding")
	other.Binding.BindingIncarnationID = consumerID("another reader incarnation")
	other.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/other/cryptoKeyVersions/1"
	selection.Entry.Recipients = []contract.ID{selection.Binding.SubjectID, other.SubjectID}
	slices.SortFunc(selection.Entry.Recipients, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	payload, keys, err := custody.SealValue(selection.Core, []byte("secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keys[:cap(keys)])
	selection.Payload = payload
	selection.Access.PackageCheck = payload.PackageCheck
	authorityCore, err := custody.ValueWrapCore(selection.Core, selection.Binding)
	if err != nil {
		t.Fatal(err)
	}
	otherCore, err := custody.ValueWrapCore(selection.Core, other)
	if err != nil {
		t.Fatal(err)
	}
	authorityWrap, err := custody.Wrap(authorityCore, selection.Binding.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	otherWrap, err := custody.Wrap(otherCore, other.Binding, keys)
	if err != nil {
		t.Fatal(err)
	}
	selection.Access.Wraps = []contract.WrapRow{authorityWrap, otherWrap}
	slices.SortFunc(selection.Access.Wraps, func(a, b contract.WrapRow) int { return bytes.Compare(a.SubjectID[:], b.SubjectID[:]) })
	refreshConsumerSelection(t, &selection)
	runtime := newConsumerRuntime(t, route)
	verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	if got := verifier.Verify(context.Background(), selection); got != contract.CryptoSuccess || route.privateCalls != 1 {
		t.Fatalf("shared secret required another reader's private route: %v", got)
	}
}

// full_only: false
func TestReconstructionVerifierRejectsChangedSelectionBeforePrivateUse(t *testing.T) {
	selection, route := consumerFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*contract.ConsumerSelection)
	}{
		{"domain", func(s *contract.ConsumerSelection) { s.DomainID = consumerID("other domain") }},
		{"entry digest", func(s *contract.ConsumerSelection) { s.EntryDigest = consumerID("other entry") }},
		{"slot", func(s *contract.ConsumerSelection) { s.Slot++ }},
		{"snapshot", func(s *contract.ConsumerSelection) { s.SnapshotID = consumerID("other snapshot") }},
		{"head", func(s *contract.ConsumerSelection) { s.HEADDigest = consumerID("other HEAD") }},
		{"revision", func(s *contract.ConsumerSelection) { s.HEADRevision = consumerID("other revision") }},
		{"token", func(s *contract.ConsumerSelection) { s.HEADToken.Value = "2" }},
		{"root", func(s *contract.ConsumerSelection) { s.Root.Digest = consumerID("other root") }},
		{"access root", func(s *contract.ConsumerSelection) { s.AccessRoot = consumerID("other access root") }},
		{"authority", func(s *contract.ConsumerSelection) { s.Binding.SubjectID = consumerID("other recipient") }},
		{"binding generation", func(s *contract.ConsumerSelection) { s.Binding.Binding.BindingSerial++ }},
		{"binding selector", func(s *contract.ConsumerSelection) {
			s.Binding.Binding.KeySelector = "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/other/cryptoKeyVersions/1"
		}},
		{"missing authority member", func(s *contract.ConsumerSelection) { s.Entry.Recipients = []contract.ID{consumerID("other recipient")} }},
		{"missing authority wrap", func(s *contract.ConsumerSelection) { s.Access.Wraps = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ownedRoute := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: route.key, binding: route.binding}}
			runtime := newConsumerRuntime(t, ownedRoute)
			verifier, err := NewReconstructionVerifier(runtime, ownedRoute.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			defer verifier.Close()
			changed := selection
			tc.change(&changed)
			if got := verifier.Verify(context.Background(), changed); got == contract.CryptoSuccess || ownedRoute.privateCalls != 0 {
				t.Fatalf("changed selected state used private route: %v", got)
			}
			if got := verifier.Verify(context.Background(), selection); got == contract.CryptoSuccess || ownedRoute.privateCalls != 0 {
				t.Fatalf("refused verifier granted a later use: %v", got)
			}
		})
	}
}

// full_only: false
func TestReconstructionVerifierLateAuthenticationFailureIsTerminal(t *testing.T) {
	selection, route := consumerFixture(t)
	runtime := newConsumerRuntime(t, route)
	verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	if got := verifier.Verify(context.Background(), selection); got != contract.CryptoSuccess {
		t.Fatalf("first selected secret: %v", got)
	}
	bad := anotherReconstructionSecret(t, selection)
	bad.Payload.SemanticCommitment[0] ^= 1
	refreshConsumerSelection(t, &bad)
	if got := verifier.Verify(context.Background(), bad); got != contract.CryptoStoredAuthenticationFailed {
		t.Fatalf("later bad commitment: %v", got)
	}
	if got := verifier.Verify(context.Background(), selection); got == contract.CryptoSuccess || route.privateCalls != 2 {
		t.Fatalf("failure left reusable private permission: %v", got)
	}
}

// full_only: false
func TestReconstructionVerifierRejectsInvalidConstruction(t *testing.T) {
	selection, route := consumerFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*contract.ReconstructionVerificationPins)
	}{
		{"missing domain", func(p *contract.ReconstructionVerificationPins) { p.DomainID = contract.ID{} }},
		{"wrong root", func(p *contract.ReconstructionVerificationPins) { p.Root.Object = consumerID("other") }},
		{"wrong token family", func(p *contract.ReconstructionVerificationPins) { p.HEADToken.Family = contract.AWS }},
		{"wrong authority", func(p *contract.ReconstructionVerificationPins) { p.AuthorityBinding.SubjectID = consumerID("other") }},
		{"wrong provider", func(p *contract.ReconstructionVerificationPins) { p.AuthorityBinding.Binding.Provider = contract.AWS }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := newConsumerRuntime(t, route)
			pins := reconstructionPins(selection)
			tc.change(&pins)
			if verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), pins, time.Now().Add(time.Minute)); err == nil || verifier != nil {
				t.Fatal("invalid public pins acquired private slot")
			}
			if runtime.slot != nil || route.privateCalls != 0 {
				t.Fatal("invalid construction retained or used custody")
			}
		})
	}
}

// full_only: false
func TestReconstructionVerifierChecksPrivateLayersAndClearsPacket(t *testing.T) {
	base, originalRoute := consumerFixture(t)
	for _, damage := range []string{"package", "nonce", "ciphertext", "semantic", "packet context", "packet kind", "packet length", "denied", "unknown"} {
		t.Run(damage, func(t *testing.T) {
			selection := base
			selection.Payload.Ciphertext = slices.Clone(base.Payload.Ciphertext)
			selection.Access.Wraps = slices.Clone(base.Access.Wraps)
			route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
			want := contract.CryptoStoredAuthenticationFailed
			switch damage {
			case "package":
				selection.Payload.PackageCheck[0] ^= 1
				selection.Access.PackageCheck = selection.Payload.PackageCheck
			case "nonce":
				selection.Payload.Nonce[0] ^= 1
			case "ciphertext":
				selection.Payload.Ciphertext[0] ^= 1
			case "semantic":
				selection.Payload.SemanticCommitment[0] ^= 1
			case "denied":
				want = contract.CryptoPrivateRouteUnavailable
				route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					return PrivateResult{Status: KeyDenied, Uses: KeyUses{Denied: 1}}
				}
			case "unknown":
				want = contract.CryptoResponseUnknown
				route.override = func(context.Context, contract.KMSBinding, []byte, uint16) PrivateResult {
					return PrivateResult{Status: KeyUnknown, Uses: KeyUses{Unknown: 1}}
				}
			default:
				route.override = func(ctx context.Context, b contract.KMSBinding, c []byte, n uint16) PrivateResult {
					got := route.testKeyAccess.Decrypt(ctx, b, c, n)
					switch damage {
					case "packet context":
						got.Packet[4] ^= 1
					case "packet kind":
						got.Packet[3] = 2
					case "packet length":
						got.Packet = got.Packet[:len(got.Packet)-1]
					}
					return got
				}
			}
			refreshConsumerSelection(t, &selection)
			runtime := newConsumerRuntime(t, route)
			verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if got := verifier.Verify(context.Background(), selection); got != want {
				t.Fatalf("bad private layer result %v, want %v", got, want)
			}
			verifier.Close()
			if route.returned != nil && !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("bad packet backing retained")
			}
			if got := verifier.Verify(context.Background(), base); got == contract.CryptoSuccess {
				t.Fatal("bad private layer left reusable verifier")
			}
		})
	}
}

// full_only: false
func TestReconstructionVerifierCancellationAndCloseJoin(t *testing.T) {
	selection, originalRoute := consumerFixture(t)
	t.Run("nil context refuses", func(t *testing.T) {
		route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
		runtime := newConsumerRuntime(t, route)
		verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		defer verifier.Close()
		var nilContext context.Context
		if got := verifier.Verify(nilContext, selection); got != contract.CryptoInvalidAdmission || route.privateCalls != 0 {
			t.Fatalf("nil context entered private route: %v", got)
		}
	})
	t.Run("cancel before private use", func(t *testing.T) {
		route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
		runtime := newConsumerRuntime(t, route)
		verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		defer verifier.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got := verifier.Verify(ctx, selection); got != contract.CryptoCancelled || route.privateCalls != 0 {
			t.Fatalf("cancel entered private route: %v", got)
		}
	})
	t.Run("caller cancellation reaches private route", func(t *testing.T) {
		started := make(chan struct{})
		route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
		route.override = func(ctx context.Context, _ contract.KMSBinding, _ []byte, _ uint16) PrivateResult {
			close(started)
			<-ctx.Done()
			return PrivateResult{Status: KeyCancelled}
		}
		runtime := newConsumerRuntime(t, route)
		verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		defer verifier.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan contract.CryptoResultCode, 1)
		go func() { done <- verifier.Verify(ctx, selection) }()
		<-started
		cancel()
		select {
		case got := <-done:
			if got != contract.CryptoCancelled {
				t.Fatalf("caller cancellation result %v", got)
			}
		case <-time.After(2 * time.Second):
			verifier.session.cancel()
			<-done
			t.Fatal("caller cancellation did not reach private route")
		}
	})
	t.Run("original deadline expires", func(t *testing.T) {
		route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
		runtime := newConsumerRuntime(t, route)
		verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(25*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		defer verifier.Close()
		select {
		case <-verifier.session.done:
		case <-time.After(5 * time.Second):
			t.Fatal("deadline did not retire private work")
		}
		if got := verifier.Verify(context.Background(), selection); got != contract.CryptoExpired || route.privateCalls != 0 {
			t.Fatalf("expired verification entered private route: %v", got)
		}
	})
	t.Run("close joins active decrypt", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding, started: make(chan struct{}), release: release}}
			runtime := newConsumerRuntime(t, route)
			verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan contract.CryptoResultCode, 1)
			go func() { done <- verifier.Verify(context.Background(), selection) }()
			<-route.started
			joined := make(chan struct{})
			go func() { verifier.Close(); close(joined) }()
			synctest.Wait()
			select {
			case <-joined:
				t.Fatal("Close returned before private decrypt joined")
			default:
			}
			close(release)
			if got := <-done; got == contract.CryptoSuccess {
				t.Fatal("cancelled private decrypt verified a value")
			}
			<-joined
			if route.privateCalls != 1 || !bytes.Equal(route.returned, make([]byte, len(route.returned))) {
				t.Fatal("joined private owner retained packet")
			}
		})
	})
	t.Run("concurrent verify cannot start second decrypt", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			release := make(chan struct{})
			route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding, started: make(chan struct{}), release: release}}
			runtime := newConsumerRuntime(t, route)
			verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			first := make(chan contract.CryptoResultCode, 1)
			go func() { first <- verifier.Verify(context.Background(), selection) }()
			<-route.started
			if got := verifier.Verify(context.Background(), selection); got != contract.CryptoAlreadyUsed {
				t.Fatalf("concurrent verify result %v", got)
			}
			close(release)
			if got := <-first; got == contract.CryptoSuccess {
				t.Fatal("concurrent use allowed first verification to succeed")
			}
			verifier.Close()
			if route.privateCalls != 1 {
				t.Fatalf("concurrent use issued %d decrypts", route.privateCalls)
			}
		})
	})
}

// finalizationCutContext holds cancellation propagation until AfterFunc's
// stop function runs. This is an allowed scheduling cut: Done closes after an
// Err call samples nil but before its caller makes the final success decision.
type finalizationCutContext struct {
	context.Context
	privateReturned    atomic.Bool
	afterPrivateErr    atomic.Int32
	finalErrRead       chan struct{}
	releaseFinalErr    chan struct{}
	callbackRegistered chan struct{}
	callbackGate       chan struct{}
	callbackDone       chan struct{}
	mu                 sync.Mutex
	callbackStarted    bool
	callbackStopped    bool
}

func (c *finalizationCutContext) Value(any) any { return nil }

func (c *finalizationCutContext) Err() error {
	err := c.Context.Err()
	if c.privateReturned.Load() && c.afterPrivateErr.Add(1) == 2 {
		close(c.finalErrRead)
		<-c.releaseFinalErr
	}
	return err
}

func (c *finalizationCutContext) AfterFunc(f func()) func() bool {
	close(c.callbackRegistered)
	go func() {
		<-c.Done()
		<-c.callbackGate
		c.mu.Lock()
		start := !c.callbackStopped
		if start {
			c.callbackStarted = true
		}
		c.mu.Unlock()
		if start {
			f()
		}
		close(c.callbackDone)
	}()
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.callbackStarted {
			return false
		}
		c.callbackStopped = true
		return true
	}
}

// full_only: false
func TestReconstructionVerifierFinalizationObservesCallerCancellation(t *testing.T) {
	selection, originalRoute := consumerFixture(t)
	route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
	runtime := newConsumerRuntime(t, route)
	verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	base, cancel := context.WithCancel(context.Background())
	cut := &finalizationCutContext{Context: base, finalErrRead: make(chan struct{}), releaseFinalErr: make(chan struct{}),
		callbackRegistered: make(chan struct{}), callbackGate: make(chan struct{}), callbackDone: make(chan struct{})}
	route.override = func(ctx context.Context, binding contract.KMSBinding, ciphertext []byte, length uint16) PrivateResult {
		result := route.testKeyAccess.Decrypt(ctx, binding, ciphertext, length)
		cut.privateReturned.Store(true)
		return result
	}
	done := make(chan contract.CryptoResultCode, 1)
	go func() { done <- verifier.Verify(cut, selection) }()
	joined, finalErrReleased := false, false
	defer func() {
		cancel()
		if !finalErrReleased {
			close(cut.releaseFinalErr)
		}
		close(cut.callbackGate)
		if !joined {
			verifier.session.cancel()
			select {
			case <-done:
				joined = true
			case <-time.After(2 * time.Second):
				t.Error("Verify did not join after cancellation and gate release")
			}
		}
		callbackJoined := false
		select {
		case <-cut.callbackRegistered:
			select {
			case <-cut.callbackDone:
				callbackJoined = true
			case <-time.After(2 * time.Second):
				t.Error("registered cancellation callback did not join")
			}
		default:
			// An early Verify return did not register a callback.
			callbackJoined = joined
		}
		if joined && callbackJoined {
			closed := make(chan struct{})
			go func() { verifier.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Error("verifier Close did not join")
			}
		} else {
			t.Error("private or callback work remained unjoined; verifier was not retired")
		}
	}()
	select {
	case <-cut.finalErrRead:
	case got := <-done:
		joined = true
		t.Errorf("finalization cut was not reached: %v", got)
		return
	case <-time.After(5 * time.Second):
		t.Error("final caller Err read was not reached")
		return
	}
	cancel()
	close(cut.releaseFinalErr)
	finalErrReleased = true
	var got contract.CryptoResultCode
	select {
	case got = <-done:
		joined = true
	case <-time.After(5 * time.Second):
		t.Error("finalization did not join before teardown")
		return
	}
	cut.mu.Lock()
	stoppedBeforeStart := cut.callbackStopped && !cut.callbackStarted
	cut.mu.Unlock()
	if !stoppedBeforeStart {
		t.Fatal("callback ran before the verifier's stop won")
	}
	if got != contract.CryptoCancelled || route.privateCalls != 1 || cut.afterPrivateErr.Load() != 2 {
		t.Fatalf("cancellation before final decision: result %v, decrypts %d, later Err calls %d", got, route.privateCalls, cut.afterPrivateErr.Load())
	}
	// A later cancellation cannot change a result already returned to the caller.
	otherRoute := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
	otherRuntime := newConsumerRuntime(t, otherRoute)
	other, err := NewReconstructionVerifier(otherRuntime, otherRoute.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	completed, cancelCompleted := context.WithCancel(context.Background())
	if got := other.Verify(completed, selection); got != contract.CryptoSuccess {
		t.Fatalf("uncancelled completed result: %v", got)
	}
	cancelCompleted()
}

// full_only: false
func TestReconstructionVerifierTelemetryEnabledAndDisabledAgree(t *testing.T) {
	selection, originalRoute := consumerFixture(t)
	metricContext, reader := cryptoTelemetryReader(t)
	for _, ctx := range []context.Context{context.Background(), metricContext} {
		route := &consumerTestRoute{testKeyAccess: &testKeyAccess{key: originalRoute.key, binding: originalRoute.binding}}
		runtime := newConsumerRuntime(t, route)
		verifier, err := NewReconstructionVerifier(runtime, route.CredentialRoute(), reconstructionPins(selection), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if got := verifier.Verify(ctx, selection); got != contract.CryptoSuccess {
			t.Fatalf("telemetry changed custody result: %v", got)
		}
		changed := selection
		changed.HEADDigest = consumerID("wrong selected HEAD")
		if got := verifier.Verify(ctx, changed); got != contract.CryptoInvalidAdmission {
			t.Fatalf("telemetry changed refusal: %v", got)
		}
		verifier.Close()
	}
	assertCryptoTelemetry(t, reader, "crypto.reconstruction.verify_discard", map[string]int64{"success": 1, "admission_refused": 1})
}
