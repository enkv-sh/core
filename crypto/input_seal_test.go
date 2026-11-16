package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
)

type sourceReader struct {
	*bytes.Reader
	reads, closes int
	failure       error
	closeFailure  error
	stall         bool
}

func (s *sourceReader) Read(p []byte) (int, error) {
	s.reads++
	if s.stall {
		return 0, nil
	}
	n, err := s.Reader.Read(p)
	if s.failure != nil {
		err = s.failure
	}
	return n, err
}
func (s *sourceReader) Close() error { s.closes++; return s.closeFailure }

type blockedSource struct {
	started, closed chan struct{}
	start, close    sync.Once
}

func (s *blockedSource) Read([]byte) (int, error) {
	s.start.Do(func() { close(s.started) })
	<-s.closed
	return 0, io.ErrClosedPipe
}
func (s *blockedSource) Close() error { s.close.Do(func() { close(s.closed) }); return nil }

func sourceID(s string) contract.ID { return contract.Hash([]byte(s)) }

func sourceFixture(t *testing.T) (contract.SealedInputCore, contract.BindingTableRow) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := contract.BindingTableRow{SubjectKind: 1, SubjectID: sourceID("authority"), Binding: contract.KMSBinding{BindingID: sourceID("binding"), BindingIncarnationID: sourceID("binding incarnation"), BindingSerial: 1, Provider: contract.GCP, WrapProfile: 2, ProtectionClass: 2, KeySelector: "projects/test-project/locations/us-central1/keyRings/test/cryptoKeys/authority/cryptoKeyVersions/1", SPKI: spki, Fingerprint: contract.Hash(spki)}}
	digest, err := contract.PublicBindingDigest(binding.Binding)
	if err != nil {
		t.Fatal(err)
	}
	set, err := contract.IntendedRecipientBindingSetDigest(sourceID("domain"), binding.SubjectID, []contract.RecipientBindingReference{{RecipientID: binding.SubjectID, PublicBindingDigest: digest}})
	if err != nil {
		t.Fatal(err)
	}
	core := contract.SealedInputCore{SealedInputCoreFields: contract.SealedInputCoreFields{Schema: 4, Profile: 2, CompatibilityID: contract.CompatibilityID(), DomainID: sourceID("domain"), FileIdentity: sourceID("file"), SourceID: sourceID("source"), CryptoSupportID: contract.CryptoSupportID(), DataKeyID: sourceID("data"), DataKeyEpoch: 1, IntendedRecipientBindingSetDigest: set, InputEncoding: contract.InputEncodingRaw, RetainedLength: 0}, Name: "secret"}
	return core, binding
}

// full_only: false
func TestSourcePrivateAdmissionBoundsAndSingleUse(t *testing.T) {
	core, binding := sourceFixture(t)
	newRuntime := func(t *testing.T) *Runtime {
		t.Helper()
		r, err := New(contract.GCP, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Close)
		return r
	}
	for _, tc := range []struct {
		name         string
		size, raw    int
		failure      error
		closeFailure error
		stall        bool
		want         contract.CryptoResultCode
	}{
		{name: "empty", want: contract.CryptoSuccess},
		{name: "maximum", size: 65536, raw: 65536, want: contract.CryptoSuccess},
		{name: "overflow", size: 65537, raw: 65536, want: contract.CryptoCapacityExceeded},
		{name: "short-target", size: 1, raw: 2, want: contract.CryptoInvalidInput},
		{name: "error-after-prefix", size: 1, raw: 1, failure: errors.New("private source error"), want: contract.CryptoCustodyUnavailable},
		{name: "stalled-stream", stall: true, want: contract.CryptoCustodyUnavailable},
		{name: "close-error", closeFailure: errors.New("private source close error"), want: contract.CryptoCustodyUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metricContext, reader := cryptoTelemetryReader(t)
			r := newRuntime(t)
			input := &sourceReader{Reader: bytes.NewReader(bytes.Repeat([]byte{0x5a}, tc.size)), failure: tc.failure, closeFailure: tc.closeFailure, stall: tc.stall}
			target := core
			target.ContentLength = uint32(tc.raw)
			target.RetainedLength = uint32(tc.raw)
			if err := r.admitInputSeal(sourceID(tc.name), target, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			if input.reads != 0 {
				t.Fatal("source read during admission")
			}
			body, code := r.sealInput(metricContext, sourceID(tc.name))
			if code != tc.want {
				t.Fatalf("source result %v, want %v", code, tc.want)
			}
			if code == contract.CryptoSuccess {
				envelope, err := contract.DecodeSealedInputEnvelope(body)
				if err != nil || envelope.Core != target {
					t.Fatal("source omitted fixed target")
				}
			} else if len(body) != 0 {
				t.Fatal("failed source returned material")
			}
			label := map[string]string{"empty": "success", "maximum": "success", "overflow": "capacity_exceeded", "short-target": "invalid", "error-after-prefix": "evidence_unavailable", "stalled-stream": "evidence_unavailable", "close-error": "evidence_unavailable"}[tc.name]
			assertCryptoTelemetry(t, reader, "crypto.seal_source", map[string]int64{label: 1})
			<-r.inputSeal.done
			if input.closes != 1 {
				t.Fatal("source owner was not closed exactly once")
			}
			if r.inputSeal.input != nil {
				t.Fatal("source owner retained after completion")
			}
			if body, code := r.sealInput(context.Background(), sourceID(tc.name)); len(body) != 0 || code != contract.CryptoAlreadyUsed {
				t.Fatal("source admission reused")
			}
		})
	}
	t.Run("cancelled-before-read-keeps-input-private", func(t *testing.T) {
		r := newRuntime(t)
		input := &sourceReader{Reader: bytes.NewReader(nil)}
		if err := r.admitInputSeal(sourceID("early cancel"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		body, code := r.sealInput(ctx, sourceID("early cancel"))
		<-r.inputSeal.done
		if code != contract.CryptoCancelled || body != nil || input.reads != 0 || input.closes != 1 || r.inputSeal.input != nil {
			t.Fatal("early cancellation changed custody or read the source")
		}
		if body, code := r.sealInput(context.Background(), sourceID("early cancel")); body != nil || code != contract.CryptoAlreadyUsed {
			t.Fatal("cancelled source admission reused")
		}
	})
	t.Run("deadline-validation-precedes-input-ownership", func(t *testing.T) {
		r := newRuntime(t)
		input := &sourceReader{Reader: bytes.NewReader(nil)}
		for _, deadline := range []time.Time{{}, time.Unix(-1, 0), time.Unix(0, 0), time.Unix(0, 1), time.Date(2263, 1, 1, 0, 0, 0, 0, time.UTC)} {
			if err := r.admitInputSeal(sourceID("bad deadline"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, deadline); err == nil {
				t.Fatal("invalid deadline admitted")
			}
		}
		if input.reads != 0 || input.closes != 0 {
			t.Fatal("invalid admission touched source")
		}
	})
	t.Run("abandoned-expiry-closes-without-a-call", func(t *testing.T) {
		r := newRuntime(t)
		input := &sourceReader{Reader: bytes.NewReader(nil)}
		if err := r.admitInputSeal(sourceID("expiry"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(25*time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		select {
		case <-r.inputSeal.done:
		case <-time.After(time.Second):
			t.Fatal("expired source retained input")
		}
		if input.reads != 0 || input.closes != 1 {
			t.Fatal("expired source ownership incorrect")
		}
	})
	t.Run("cancelled-stream-is-closed-and-joined", func(t *testing.T) {
		r := newRuntime(t)
		input := &blockedSource{started: make(chan struct{}), closed: make(chan struct{})}
		if err := r.admitInputSeal(sourceID("blocking"), core, binding.SubjectID, []contract.BindingTableRow{binding}, input, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		result := make(chan contract.CryptoResultCode, 1)
		go func() {
			body, code := r.sealInput(ctx, sourceID("blocking"))
			if len(body) > 0 {
				code = contract.CryptoSuccess
			}
			result <- code
		}()
		<-input.started
		cancel()
		select {
		case code := <-result:
			if code != contract.CryptoCancelled {
				t.Fatalf("cancelled source result %v", code)
			}
		case <-time.After(time.Second):
			t.Fatal("source did not join after cancel")
		}
		<-r.inputSeal.done
	})
	t.Run("slot-refuses-overlap-and-retirement-allows-next-operation", func(t *testing.T) {
		r := newRuntime(t)
		first := &sourceReader{Reader: bytes.NewReader(nil)}
		second := &sourceReader{Reader: bytes.NewReader(nil)}
		deadline := time.Now().Add(time.Minute)
		if err := r.admitInputSeal(sourceID("first"), core, binding.SubjectID, []contract.BindingTableRow{binding}, first, deadline); err != nil {
			t.Fatal(err)
		}
		if err := r.admitInputSeal(sourceID("second"), core, binding.SubjectID, []contract.BindingTableRow{binding}, second, deadline); err == nil {
			t.Fatal("concurrent source admitted")
		}
		r.retireInputSeal()
		if first.closes != 1 {
			t.Fatal("retirement did not close old input")
		}
		if err := r.admitInputSeal(sourceID("second"), core, binding.SubjectID, []contract.BindingTableRow{binding}, second, deadline); err != nil {
			t.Fatal(err)
		}
		if _, code := r.sealInput(context.Background(), sourceID("first")); code != contract.CryptoInvalidAdmission {
			t.Fatal("retired context admitted to new operation")
		}
	})
}
