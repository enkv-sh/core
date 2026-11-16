package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func configurationInputFixture(t *testing.T) (ConfigurationInputTarget, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	row := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: sourceID("configuration authority"), Binding: contract.KMSBinding{BindingID: sourceID("configuration binding"), BindingIncarnationID: sourceID("configuration binding incarnation"), BindingSerial: 1, Provider: contract.AWS, WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: contract.SoftwareProtection, KeySelector: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111", SPKI: spki, Fingerprint: contract.Hash(spki)}}
	return ConfigurationInputTarget{DomainID: sourceID("configuration domain"), FileIdentity: sourceID("configuration file"), FilePredecessorDigest: sourceID("configuration predecessor"), Name: "secret", AuthorityRecipientID: row.SubjectID, Bindings: []contract.BindingTableRow{row}}, key
}

// full_only: false
func TestConfigurationInputPreparation(t *testing.T) {
	target, key := configurationInputFixture(t)
	identities := map[contract.ID]bool{}
	for _, tc := range []struct {
		name, input string
		base64      bool
		want        []byte
	}{{"empty", "", false, []byte{}}, {"literal-base64-text", "QUJD", false, []byte("QUJD")}, {"one-decode", "QUJD", true, []byte("ABC")}, {"no-second-decode", "UVVKRA==", true, []byte("QUJD")}, {"binary", "AAH/", true, []byte{0, 1, 255}}, {"exact-line-breaks", "first\r\nsecond\n", false, []byte("first\r\nsecond\n")}} {
		t.Run(tc.name, func(t *testing.T) {
			input := &sourceReader{Reader: bytes.NewReader([]byte(tc.input))}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			body, err := SealConfigurationInput(ctx, target, input, ConfigurationInputOptions{Base64: tc.base64, MaximumRawLength: contract.CryptoMaxRawValue})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := contract.DecodeSealedInputEnvelope(body)
			if err != nil {
				t.Fatal(err)
			}
			core := envelope.Core
			if core.DomainID != target.DomainID || core.FileIdentity != target.FileIdentity || core.FilePredecessorDigest != target.FilePredecessorDigest || core.Name != target.Name || core.ContentLength != uint32(len(tc.want)) || core.DataKeyEpoch != 1 || core.CompatibilityID != contract.CompatibilityID() || core.CryptoSupportID != contract.CryptoSupportID() {
				t.Fatal("sealed source context differs")
			}
			for _, id := range []contract.ID{core.SourceID, core.DataKeyID} {
				if id.IsZero() || identities[id] {
					t.Fatal("sealing identity was reused")
				}
				identities[id] = true
			}
			packet, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, envelope.AuthorityWrap.RSACiphertext, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(packet[:cap(packet)])
			if len(packet) != 68 || !bytes.Equal(packet[:4], []byte{0, 2, 0, 2}) {
				t.Fatal("wrong source key packet")
			}
			plain, err := custody.OpenSealedInput(core, envelope, packet[36:])
			if err != nil || !bytes.Equal(plain, []byte(tc.input)) {
				t.Fatal("sealed input changed exact bytes")
			}
			clear(plain[:cap(plain)])
			if input.reads == 0 || input.closes != 1 {
				t.Fatal("admitted input ownership did not join")
			}
		})
	}
}

// full_only: false
func TestConfigurationInputBoundsAndRefusals(t *testing.T) {
	target, _ := configurationInputFixture(t)
	for _, tc := range []struct {
		name, input string
		base64      bool
		limit       uint32
		want        contract.CryptoResultCode
	}{{"raw-maximum", strings.Repeat("x", 65536), false, 65536, contract.CryptoSuccess}, {"raw-one-over", strings.Repeat("x", 65537), false, 65536, contract.CryptoCapacityExceeded}, {"remaining-joint-maximum", "abc", false, 3, contract.CryptoSuccess}, {"remaining-joint-one-over", "abcd", false, 3, contract.CryptoCapacityExceeded}, {"base64-maximum", strings.Repeat("eHh4", 21845) + "eA==", true, 65536, contract.CryptoSuccess}, {"canonical-padding", "YQ==", true, 65536, contract.CryptoSuccess}, {"nonzero-pad-bits", "YR==", true, 65536, contract.CryptoInvalidInput}, {"missing-padding", "YQ", true, 65536, contract.CryptoInvalidInput}, {"newline", "YQ==\n", true, 65536, contract.CryptoInvalidInput}, {"internal-space", "Y Q==", true, 65536, contract.CryptoInvalidInput}, {"url-alphabet", "____", true, 65536, contract.CryptoInvalidInput}, {"encoded-one-over", strings.Repeat("A", 87385), true, 65536, contract.CryptoCapacityExceeded}, {"decoded-one-over", strings.Repeat("A", 87384), true, 65536, contract.CryptoCapacityExceeded}, {"zero-budget-empty", "", false, 0, contract.CryptoSuccess}, {"zero-budget-one-over", "x", false, 0, contract.CryptoCapacityExceeded}} {
		t.Run(tc.name, func(t *testing.T) {
			input := &sourceReader{Reader: bytes.NewReader([]byte(tc.input))}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			body, err := SealConfigurationInput(ctx, target, input, ConfigurationInputOptions{Base64: tc.base64, MaximumRawLength: tc.limit})
			if tc.want == contract.CryptoSuccess {
				if err != nil || body == nil {
					t.Fatal("valid bounded input refused", err)
				}
			} else {
				var preparation *ConfigurationInputError
				if !errors.As(err, &preparation) || preparation.Code != tc.want || body != nil {
					t.Fatalf("wrong safe preparation result %v", err)
				}
			}
			if input.closes != 1 {
				t.Fatal("admitted input was not closed exactly once")
			}
		})
	}
	for _, damage := range []string{"domain", "file", "predecessor", "authority", "key", "recovery-subject", "duplicate-recipient", "deadline"} {
		t.Run("invalid-"+damage, func(t *testing.T) {
			bad := target
			bad.Bindings = append([]contract.BindingTableRow{}, target.Bindings...)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			switch damage {
			case "domain":
				bad.DomainID = contract.ID{}
			case "file":
				bad.FileIdentity = contract.ID{}
			case "predecessor":
				bad.FilePredecessorDigest = contract.ID{}
			case "authority":
				bad.AuthorityRecipientID = sourceID("absent authority")
			case "key":
				bad.Bindings[0].Binding.SPKI = []byte("invalid key")
			case "recovery-subject":
				bad.Bindings[0].SubjectKind = contract.RecoveryWrapSubject
			case "duplicate-recipient":
				bad.Bindings = append(bad.Bindings, bad.Bindings[0])
			case "deadline":
				ctx = context.Background()
			}
			input := &sourceReader{Reader: bytes.NewReader([]byte("private"))}
			if body, err := SealConfigurationInput(ctx, bad, input, ConfigurationInputOptions{MaximumRawLength: 65536}); err == nil || body != nil || input.reads != 0 || input.closes != 0 {
				t.Fatal("invalid target acquired input custody")
			}
		})
	}
}

// full_only: false
func TestConfigurationInputCancellationJoins(t *testing.T) {
	target, _ := configurationInputFixture(t)
	input := &blockedSource{started: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		body, err := SealConfigurationInput(ctx, target, input, ConfigurationInputOptions{MaximumRawLength: 65536})
		if body != nil {
			done <- errors.New("cancelled preparation returned bytes")
			return
		}
		done <- err
	}()
	select {
	case <-input.started:
	case <-time.After(5 * time.Second):
		t.Fatal("source read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("source read and Close did not join")
	}
	select {
	case <-input.closed:
	default:
		t.Fatal("cancelled source remained open")
	}
}
