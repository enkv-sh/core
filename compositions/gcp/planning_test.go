package compositiongcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	gcpprovider "enkv.sh/providers/gcp"
)

type planningCredentials struct{}

func (planningCredentials) Token(context.Context) (string, error) { return "local-planning-token", nil }

func planningTransport(t *testing.T, host string, handler http.Handler) *http.Transport {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{host}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

// full_only: false
func TestPlanningUsesOnlyCurrentAuthorityDecryptRoute(t *testing.T) {
	_, reader := readerConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	control, err := reader.PublicBasis.ControlCore(reader.ExpectedDomain, reader.ExpectedStore)
	if err != nil {
		t.Fatal(err)
	}
	binding := control.AuthorityKMSBinding
	key, ok := contract.ParseGCPKeySelector(binding.KeySelector, false)
	if !ok {
		t.Fatal("fixture Authority selector refused")
	}
	var decrypts, forbidden int
	host := key.Region + "-cloudkms.googleapis.com"
	transport := planningTransport(t, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Host != host || r.URL.Path != "/v1/"+binding.KeySelector+":asymmetricDecrypt" || r.Header.Get("Authorization") != "Bearer local-planning-token" {
			forbidden++
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		decrypts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if _, err := io.WriteString(w, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`); err != nil {
			t.Error(err)
		}
	}))
	client, err := gcpprovider.NewLocalResponderClient(transport, planningCredentials{})
	if err != nil {
		t.Fatal(err)
	}
	installed := gcpprovider.KeyAccessConfig{Client: client, Region: key.Region, Project: key.Project, Endpoint: "https://" + host + "/", CredentialRoute: contract.Hash([]byte("planning Authority route"))}
	source := contract.PlanningSourcePair{FileIdentity: contract.Hash([]byte("file")), EditableDigest: contract.Hash([]byte("editable")), GeneratedDigest: contract.Hash([]byte("generated")), EditableLength: 1, GeneratedLength: 1}
	config := PlanningConfig{Reader: reader, KeyAccess: installed, Sources: contract.PlanningSources{Trusted: source, Proposed: source}, FileIdentity: source.FileIdentity, InputDigest: contract.Hash([]byte("inputs"))}
	engine, err := NewPlanning(ctx, config)
	if err != nil || engine == nil {
		t.Fatal("fixed planning installation refused", err)
	}
	engine.Close()
	if decrypts != 0 || forbidden != 0 {
		t.Fatal("installation used a private resource")
	}
	for _, condition := range []string{"project", "region", "endpoint", "route", "source", "inputs", "context"} {
		t.Run(condition, func(t *testing.T) {
			bad, callCtx := config, ctx
			switch condition {
			case "project":
				bad.KeyAccess.Project = "different-project"
			case "region":
				bad.KeyAccess.Region = "us-central1-other"
			case "endpoint":
				bad.KeyAccess.Endpoint = "https://example.invalid/"
			case "route":
				bad.KeyAccess.CredentialRoute = contract.ID{}
			case "source":
				bad.Sources.Proposed.GeneratedDigest = contract.ID{}
			case "inputs":
				bad.InputDigest = contract.ID{}
			case "context":
				callCtx = context.Background()
			}
			engine, err := NewPlanning(callCtx, bad)
			if engine != nil {
				engine.Close()
			}
			if err == nil || engine != nil {
				t.Fatal("unfixed planning configuration admitted")
			}
		})
	}
	access, err := gcpprovider.NewKeyAccess(ctx, installed)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := contract.EncodeKMSBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	decryptor := &bindingDecryptor{route: access, binding: encoded}
	if reflect.TypeOf(decryptor).NumMethod() != 3 {
		t.Fatal("planning route gained a non-decrypt capability")
	}
	wrong := binding
	wrong.BindingID = contract.Hash([]byte("another current binding"))
	if result := decryptor.Decrypt(ctx, wrong, bytes.Repeat([]byte{1}, contract.RSACiphertextLength), contract.SingleKeyMaterialPacketLength); result.Status != privatecrypto.KeyInvalid || decrypts != 0 {
		t.Fatal("another binding reached the private route")
	}
	result := decryptor.Decrypt(ctx, binding, bytes.Repeat([]byte{1}, contract.RSACiphertextLength), contract.SingleKeyMaterialPacketLength)
	defer clear(result.Packet)
	if result.Status != privatecrypto.KeyDenied || decrypts != 1 || forbidden != 0 {
		t.Fatal("Authority refusal used another route or capability", result.Status, decrypts, forbidden)
	}
	snapshot := contract.Hash([]byte("planning snapshot"))
	admission := contract.PlanningAdmission{
		RequestID: contract.Hash([]byte("planning request")), SessionID: contract.Hash([]byte("planning session")), DomainID: control.DomainID,
		HEADDigest: contract.Hash([]byte("planning HEAD")), HEADRevision: contract.Hash([]byte("planning revision")), SnapshotID: snapshot,
		AccessRoot: contract.Hash([]byte("planning access root")), CredentialRoute: installed.CredentialRoute,
		Root:      contract.Ref{Kind: contract.RootKind, Domain: control.DomainID, Object: snapshot, Digest: contract.Hash([]byte("planning root")), Format: contract.CanonicalSchema, Length: 1},
		HEADToken: contract.Token{Family: contract.GCP, Value: "1"}, Sources: config.Sources, Control: control,
		Authority: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: control.AuthorityRecipientID, Binding: binding},
		Options:   contract.PlanningOptions{Purpose: contract.PlanningEquality},
	}
	baseline, err := newPlanningCustody(ctx, installed, admission, nil)
	if baseline != nil {
		baseline.Close()
	}
	if err != nil || baseline == nil || decrypts != 1 || forbidden != 0 {
		t.Fatal("complete admission did not construct and close without private use", err)
	}
	unavailable := installed
	unavailable.Client = nil
	construction, err := newPlanningCustody(ctx, unavailable, admission, nil)
	if construction != nil {
		construction.Close()
	}
	var constructionError contract.PlanningAdmissionError
	if !errors.As(err, &constructionError) || constructionError.Code != contract.CryptoCustodyUnavailable || construction != nil || decrypts != 1 || forbidden != 0 {
		t.Fatal("invalid provider construction lost unavailable classification", err)
	}
	for _, condition := range []string{"binding", "subject", "provider", "route"} {
		q := admission
		switch condition {
		case "binding":
			q.Authority.Binding.BindingID = wrong.BindingID
		case "subject":
			q.Authority.SubjectID = wrong.BindingID
		case "provider":
			q.Authority.Binding.Provider = contract.AWS
		case "route":
			q.CredentialRoute = wrong.BindingID
		}
		custody, err := newPlanningCustody(ctx, unavailable, q, nil)
		if custody != nil {
			custody.Close()
		}
		var admissionError contract.PlanningAdmissionError
		if !errors.As(err, &admissionError) || admissionError.Code != contract.CryptoInvalidAdmission || custody != nil || decrypts != 1 || forbidden != 0 {
			t.Fatal("invalid admission constructed or used private custody or lost typed refusal", condition)
		}
	}
}
