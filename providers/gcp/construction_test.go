package gcp

import (
	"context"
	"net/http"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestRejectUnadmittedConstruction(t *testing.T) {
	if _, err := NewStore(context.Background(), StoreConfig{}); err == nil {
		t.Fatal("empty store construction accepted")
	}
	if _, err := NewTrust(context.Background(), TrustConfig{}); err == nil {
		t.Fatal("empty trust construction accepted")
	}
	if _, err := ParseVerifier(nil); err == nil {
		t.Fatal("empty verifier accepted")
	}
	creds := &credentials{}
	if _, err := NewClient(http.DefaultTransport.(*http.Transport), creds); err == nil {
		t.Fatal("default proxy/dial construction accepted")
	}
	client, err := NewClient(&http.Transport{}, creds)
	if err != nil {
		t.Fatal(err)
	}
	c := config(client)
	for _, mutate := range []func(*StoreConfig){func(c *StoreConfig) { c.Endpoint = "https://storage.googleapis.com/storage/v1/" }, func(c *StoreConfig) { c.CredentialRoute = "" }, func(c *StoreConfig) { c.Prefix = "../elsewhere" }, func(c *StoreConfig) { c.Domain = contract.ID{} }} {
		bad := c
		mutate(&bad)
		if _, err := NewStore(context.Background(), bad); err == nil {
			t.Fatal("bad construction accepted")
		}
	}
	if creds.calls != 0 {
		t.Fatal("constructor accessed credentials")
	}
}
