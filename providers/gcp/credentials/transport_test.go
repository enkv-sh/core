package credentials

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
)

// full_only: false
func TestTokenTransportExcludesCallerTracing(t *testing.T) {
	var hooks atomic.Int32
	parent := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		WroteHeaderField: func(string, []string) { hooks.Add(1) },
		ConnectStart:     func(string, string) { hooks.Add(1) },
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			t.Error("wrong token path")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"access_token":"dummy-bearer","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport)
	// tokenTransport still admits only the exact token URL. The controlled
	// loopback certificate cannot authenticate that service hostname.
	transport.TLSClientConfig.InsecureSkipVerify = true
	transport.DialContext = func(c context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, network, server.Listener.Addr().String())
	}
	// Positive control uses the same real transport and caller hooks.
	control, err := http.NewRequestWithContext(parent, "POST", server.URL+"/token", strings.NewReader("dummy-assertion"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(control)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if hooks.Load() == 0 {
		t.Fatal("control did not execute caller hooks")
	}
	hooks.Store(0)
	request, err := http.NewRequestWithContext(parent, "POST", tokenURL, strings.NewReader("dummy-assertion"))
	if err != nil {
		t.Fatal(err)
	}
	response, err = (tokenTransport{next: transport}).RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if hooks.Load() != 0 {
		t.Fatal("token request invoked caller hooks")
	}
}
