package compositionaws

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
	awsprovider "enkv.sh/providers/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func localReconstructionTransport(t *testing.T, handler http.Handler) *http.Transport {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Subject: pkix.Name{CommonName: "local reconstruction provider"}, DNSNames: []string{"s3.us-east-1.amazonaws.com", "kms.us-east-1.amazonaws.com", "kms.us-west-2.amazonaws.com"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
}

// full_only: false
func TestInstalledAWSReconstructionSelectsEncryptedStateWithoutEffects(t *testing.T) {
	installedAWSReconstruction(t, false, false)
}

// full_only: false
func TestInstalledAWSReconstructionUsesAuthenticatedPrivateScopeWithMinimalInputs(t *testing.T) {
	installedAWSReconstruction(t, true, false)
}

func installedAWSReconstruction(t *testing.T, minimal, mismatch bool) {
	t.Helper()
	archive := installedarchive.Load(t, "aws")
	expected, err := archive.SelectedParts()
	if err != nil {
		t.Fatal("installed AWS selected fixture refused", err)
	}
	head, err := format.DecodeHead(expected[1].Body)
	if err != nil {
		t.Fatal("installed AWS selected HEAD refused", err)
	}
	configurationKey, err := contract.StoreConfigurationKeyForID(archive.Family, archive.Location.PrefixBeforeHEAD, archive.Domain, head.Core.Store)
	if err != nil {
		t.Fatal("installed AWS selected configuration key refused", err)
	}
	pendingReads := map[string]struct{}{archive.Location.PrefixBeforeHEAD + "/HEAD": {}, configurationKey: {}}
	for _, part := range expected[2:] {
		key, err := format.Key(archive.Location.PrefixBeforeHEAD, part.Ref)
		if err != nil {
			t.Fatal("installed AWS selected physical key refused", err)
		}
		pendingReads[key] = struct{}{}
	}
	var s3Reads, publicLookups, privateDecrypts, mutations int
	var order []string
	transport := localReconstructionTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.Host+" "+r.Method+" "+r.URL.Path+" "+r.Header.Get("X-Amz-Target"))
		if r.Host == "s3.us-east-1.amazonaws.com" {
			if r.Method != http.MethodGet {
				mutations++
				http.Error(w, "mutation", http.StatusMethodNotAllowed)
				return
			}
			if (r.Header.Get("X-Amz-Expected-Bucket-Owner") != archive.Location.ExpectedOwner && (!minimal || s3Reads >= 3 || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "")) || r.Header.Get("Authorization") == "" {
				http.Error(w, "wrong owner or credential", http.StatusForbidden)
				return
			}
			prefix := "/" + archive.Location.Bucket + "/"
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			key := strings.TrimPrefix(r.URL.Path, prefix)
			item, ok := archive.Object(key)
			if !ok {
				http.NotFound(w, r)
				return
			}
			s3Reads++
			delete(pendingReads, key)
			w.Header().Set("ETag", item.Token.Value)
			w.Header().Set("Content-Length", strconv.Itoa(len(item.Body)))
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(item.Body)
			return
		}
		if r.Host != "kms.us-east-1.amazonaws.com" && r.Host != "kms.us-west-2.amazonaws.com" || r.Method != http.MethodPost || r.Header.Get("Authorization") == "" {
			mutations++
			http.Error(w, "unknown target", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var q struct {
			KeyId          string
			CiphertextBlob string
		}
		if json.Unmarshal(body, &q) != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		var reply any
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			if r.Host != "kms.us-east-1.amazonaws.com" || q.KeyId != archive.SignerSelector {
				http.Error(w, "wrong signer", http.StatusForbidden)
				return
			}
			if s3Reads != 3 || privateDecrypts != 0 {
				t.Error("signer lookup before bounded public selection or after private use")
			}
			publicLookups++
			reply = map[string]any{"KeyId": archive.SignerSelector, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY",
				"PublicKey": base64.StdEncoding.EncodeToString(archive.SignerPublicKey), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
		case "TrentService.Decrypt":
			if r.Host != "kms.us-west-2.amazonaws.com" || !strings.Contains(r.Header.Get("Authorization"), "/us-west-2/kms/aws4_request") || q.KeyId != archive.AuthorityBinding.KeySelector {
				http.Error(w, "wrong private route", http.StatusForbidden)
				return
			}
			ciphertext, err := base64.StdEncoding.DecodeString(q.CiphertextBlob)
			if err != nil {
				http.Error(w, "bad ciphertext", http.StatusBadRequest)
				return
			}
			packet, err := archive.DecryptAuthority(ciphertext)
			if err != nil {
				http.Error(w, "wrong wrap", http.StatusForbidden)
				return
			}
			defer clear(packet)
			if publicLookups != 1 || len(pendingReads) != 0 {
				t.Error("private use before complete public reads")
			}
			privateDecrypts++
			reply = map[string]any{"KeyId": archive.AuthorityBinding.KeySelector, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
				"Plaintext": base64.StdEncoding.EncodeToString(packet)}
		default:
			mutations++
			http.Error(w, "forbidden KMS operation", http.StatusMethodNotAllowed)
			return
		}
		encoded, _ := json.Marshal(reply)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write(encoded)
	}))
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "AKIDFIXTURE", SecretAccessKey: "fixture-secret", Source: "local-test"}, nil
	})
	route := contract.Hash([]byte("installed-authority-route"))
	normal := &awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: archive.Location.Region,
		KeyARN: archive.SignerSelector, CredentialRoute: contract.Hash([]byte("installed-public-route")), Credentials: credentials,
		Transport: transport, Timeout: time.Second * 10}
	private := ReconstructionKeyAccessConfig{CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Second * 10}
	expectedKEK := archive.AuthorityBinding.KeySelector
	expectedOwner := archive.Location.ExpectedOwner
	if minimal {
		expectedKEK, expectedOwner = "", ""
	}
	if mismatch {
		expectedKEK = "different-independent-key"
	}
	engine, err := NewReconstruction(ReconstructionConfig{Candidate: awsprovider.CandidateReadConfig{Region: archive.Location.Region,
		Bucket: archive.Location.Bucket, Prefix: archive.Location.PrefixBeforeHEAD, ExpectedBucketOwner: expectedOwner,
		CredentialRoute: contract.Hash([]byte("installed-read-route")), Credentials: credentials, Transport: transport, Timeout: time.Second * 10},
		Normal: normal, KeyAccess: private, ExpectedKEK: expectedKEK, ExpectedDomain: archive.Domain})
	if err != nil {
		t.Fatal("installed AWS composition refused", err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	projection, result := engine.Reconstruct(ctx)
	if mismatch {
		if projection != nil || result != (core.Result{Outcome: core.AdmissionRefused, Reason: core.ConstructionMismatch}) || privateDecrypts != 0 || publicLookups != 1 || mutations != 0 {
			t.Fatal("expected KEK mismatch used private route or returned projection", result, privateDecrypts, publicLookups, mutations)
		}
		return
	}
	if projection == nil || result.Outcome != core.ObservedCurrent || result.Evidence != core.AuthenticatedClosure {
		t.Fatal("installed AWS reconstruction did not select current state", result, "s3", s3Reads, "public", publicLookups, "private", privateDecrypts, "mutations", mutations)
	}
	defer projection.Close()
	provenance, ok := projection.Provenance()
	if !ok || provenance.Domain != archive.Domain || provenance.Revision != archive.Revision || provenance.HEADDigest != archive.HeadDigest {
		t.Fatal("installed AWS projection changed signed provenance")
	}
	parts := make([]core.ReconstructionPart, 0, projection.PartCount())
	for i := 0; i < projection.PartCount(); i++ {
		part, ok := projection.CopyPart(i)
		if !ok {
			t.Fatal("installed projection lost a part")
		}
		parts = append(parts, part)
	}
	matches := len(expected) == len(parts)
	kinds := map[core.ReconstructionPartKind]string{
		core.ReconstructionConfigurationPart: "configuration", core.ReconstructionHEADPart: "HEAD",
		core.ReconstructionRootPart: "root", core.ReconstructionValuePagePart: "value page",
		core.ReconstructionRecipientPagePart: "recipient page", core.ReconstructionAccessPagePart: "access page",
		core.ReconstructionIndexPagePart: "index page", core.ReconstructionSupportRowPart: "support row",
	}
	for i, want := range expected {
		if i >= len(parts) {
			matches = false
			break
		}
		got := parts[i]
		if kinds[got.Kind] != want.Kind || got.Ref != want.Ref || got.PhysicalOrdinal != want.PhysicalOrdinal ||
			got.SupportKind != want.SupportKind || got.RecordID != want.RecordID || !bytes.Equal(got.Body, want.Body) {
			matches = false
			break
		}
	}
	if !matches {
		t.Fatal("installed AWS projection differs from exact signed selected set", len(parts))
	}
	if len(order) < 5 || !strings.HasSuffix(order[0], "/HEAD ") || !strings.HasSuffix(order[3], "TrentService.GetPublicKey") || !strings.HasSuffix(order[len(order)-2], "TrentService.Decrypt") || !strings.HasSuffix(order[len(order)-1], "/HEAD ") {
		t.Fatal("provider read/private/final-HEAD order", order)
	}
	if len(pendingReads) != 0 || publicLookups != 1 || privateDecrypts != 1 || mutations != 0 {
		t.Fatal("installed AWS reconstruction made an effect or skipped provider proof", s3Reads, publicLookups, privateDecrypts, mutations)
	}
}

// full_only: false
func TestInstalledAWSReconstructionExpectedKEKMismatchStopsBeforeDecrypt(t *testing.T) {
	installedAWSReconstruction(t, true, true)
}
