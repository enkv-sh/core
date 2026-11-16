package credentials

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

type serviceAccountTokenProviderFunc func(context.Context) (*auth.Token, error)

func (f serviceAccountTokenProviderFunc) Token(ctx context.Context) (*auth.Token, error) {
	return f(ctx)
}

// full_only: false
func TestServiceAccountCaptureRejectsOtherSources(t *testing.T) {
	var typedNil *ManagedSource
	var callbackCalls int
	for _, source := range []CredentialSource{nil, typedNil, &ManagedSource{}, credentialCallback(func(context.Context) (string, error) {
		callbackCalls++
		return "unused", nil
	})} {
		value, expiry, err := CaptureServiceAccountTokenForTest(context.Background(), source)
		if err != ErrCredentials || value != "" || !expiry.IsZero() {
			t.Fatal("unadmitted source supplied token facts")
		}
		if email, err := ServiceAccountEmailForTest(source); err != ErrCredentials || email != "" {
			t.Fatal("unadmitted source supplied an identity")
		}
	}
	if callbackCalls != 0 {
		t.Fatal("capture called another credential implementation")
	}
	if source, err := LoadServiceAccountFileForTest(context.Background(), "", nil); source != nil || err != ErrCredentials {
		t.Fatal("missing explicit transport was accepted")
	}
}

// full_only: false
func TestServiceAccountCaptureReturnsExactExpiryAndClearsFailures(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	for _, mode := range []string{"valid", "nil", "empty", "zero-expiry", "expired", "wrong-type", "provider-error", "canceled-during"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := &ManagedSource{gate: make(chan struct{}, 1), email: "fixture@example.iam.gserviceaccount.com", tokens: serviceAccountTokenProviderFunc(func(context.Context) (*auth.Token, error) {
				token := &auth.Token{Value: "fixture-token", Type: "Bearer", Expiry: expiry}
				switch mode {
				case "nil":
					return nil, nil
				case "empty":
					token.Value = ""
				case "zero-expiry":
					token.Expiry = time.Time{}
				case "expired":
					token.Expiry = time.Now().Add(-time.Second)
				case "wrong-type":
					token.Type = "other"
				case "provider-error":
					return token, errors.New("private provider error")
				case "canceled-during":
					cancel()
				}
				return token, nil
			})}
			value, gotExpiry, err := CaptureServiceAccountTokenForTest(ctx, source)
			if mode == "valid" {
				if err != nil || value != "fixture-token" || !gotExpiry.Equal(expiry) {
					t.Fatal("capture changed source token facts")
				}
				return
			}
			wantErr := ErrCredentials
			if mode == "canceled-during" {
				wantErr = context.Canceled
			}
			if !errors.Is(err, wantErr) || value != "" || !gotExpiry.IsZero() {
				t.Fatal("failed capture retained token facts or changed the error")
			}
		})
	}
}

type credentialCallback func(context.Context) (string, error)

func (c credentialCallback) Token(ctx context.Context) (string, error) { return c(ctx) }
