package trust

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// full_only: false
func TestPublicHTTPSTransportKeepsServerKeyPrivateAndVerifiesHost(t *testing.T) {
	transport := PublicHTTPSTransport(t, []string{"fixture.example"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "fixture.example" {
			t.Error("unexpected public request host")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	c := transport.TLSClientConfig
	if c == nil || c.InsecureSkipVerify || c.RootCAs == nil || len(c.Certificates) != 0 || c.GetCertificate != nil || c.GetClientCertificate != nil || c.GetConfigForClient != nil {
		t.Fatal("client configuration exposes server custody or disables authentication")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, host := range []string{"fixture.example", "wrong.example"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := transport.RoundTrip(request)
		if host == "wrong.example" {
			if err == nil {
				_ = response.Body.Close()
				t.Fatal("wrong certificate host accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusNoContent || readErr != nil || closeErr != nil {
			t.Fatal("public TLS exchange failed")
		}
	}
}
