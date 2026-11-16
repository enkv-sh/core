package gcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"testing"
)

// full_only: false
func TestRegisteredProtocolCannotEnterOwnedTransport(t *testing.T) {
	hiddenCalls := 0
	supplied := &http.Transport{}
	supplied.RegisterProtocol("https", roundTripFunc(func(*http.Request) (*http.Response, error) { hiddenCalls++; return response(200, "hidden"), nil }))
	client, err := NewClient(supplied, &credentials{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, ok := client.begin(context.Background(), "127.0.0.1:1", 32)
	if !ok {
		t.Fatal("credential")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://127.0.0.1:1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.http.Do(request)
	if result != nil {
		if err := result.Body.Close(); err != nil {
			t.Error(err)
		}
	}
	if hiddenCalls != 0 || err == nil {
		t.Fatalf("unadmitted registered protocol ran %d times", hiddenCalls)
	}
}

// full_only: false
func TestAmbientDiscoveryModeRefusedBeforeSDKConstruction(t *testing.T) {
	for _, name := range []string{"GOOGLE_API_USE_CLIENT_CERTIFICATE", "EXPERIMENTAL_GOOGLE_API_USE_S2A"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "TrUe")
			creds := &credentials{}
			client, err := NewClient(&http.Transport{}, creds)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewStore(context.Background(), config(client)); err != ErrConstruction {
				t.Fatal("ambient discovery was admitted", err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewTrust(context.Background(), trustConfig(client, der)); err != ErrConstruction {
				t.Fatal("ambient trust discovery was admitted", err)
			}
			if creds.calls != 0 {
				t.Fatal("construction accessed credentials")
			}
		})
	}
}
