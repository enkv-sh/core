package credentials

import (
	"context"
	"errors"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// full_only: false
func TestCaptureCredentialsReturnsFixedProviderFacts(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	for _, mode := range []string{"valid", "expired", "denied", "canceled", "malformed-token", "malformed-quota"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls int
			source := &ManagedSource{gate: make(chan struct{}, 1), quotaProject: "fixture-project", tokens: serviceAccountTokenProviderFunc(func(context.Context) (*auth.Token, error) {
				calls++
				token := &auth.Token{Value: "fixture-token", Type: "Bearer", Expiry: expiry}
				switch mode {
				case "expired":
					token.Expiry = time.Now().Add(-time.Second)
				case "denied":
					return token, errors.New("private provider diagnostic")
				case "canceled":
					cancel()
				case "malformed-token":
					token.Value = "private\r\nheader"
				}
				return token, nil
			})}
			if mode == "malformed-quota" {
				source.quotaProject = "private project"
			}
			got, err := CaptureCredentials(ctx, source)
			if mode == "valid" {
				if err != nil || got.Token != "fixture-token" || !got.Expiry.Equal(expiry) || got.QuotaProject != "fixture-project" || calls != 1 {
					t.Fatal("capture changed selected provider facts")
				}
				return
			}
			if err == nil || got != (CapturedCredentials{}) {
				t.Fatal("failed capture retained credential facts")
			}
			if mode == "malformed-quota" && calls != 0 {
				t.Fatal("malformed quota reached token capture")
			}
		})
	}
	var callbackCalls int
	for _, source := range []CredentialSource{nil, (*ManagedSource)(nil), &ManagedSource{}, credentialCallback(func(context.Context) (string, error) { callbackCalls++; return "private-token", nil })} {
		if got, err := CaptureCredentials(context.Background(), source); err != ErrCredentials || got != (CapturedCredentials{}) {
			t.Fatal("unowned source supplied provider metadata")
		}
	}
	if callbackCalls != 0 {
		t.Fatal("capture invoked an unowned source")
	}
}
