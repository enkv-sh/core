package recovery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"hash/crc32"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type RecoveryCounts = installedarchive.RecoveryCounts
type Archive = installedarchive.Archive

// RecoveryResponder owns the synthetic remote objects and private KMS keys.
// Only official provider read, public-key and authority-decrypt requests exist.
type RecoveryResponder struct {
	mu                sync.Mutex
	archive           Archive
	resources         installedarchive.RecoveryResources
	counts            RecoveryCounts
	server            *httptest.Server
	certificate       []byte
	privateRegion     string
	requests          []string
	policy            ResponderPolicy
	externalMutations uint8
	removal           *ExactRemoval
}

func NewRecoveryResponder(t testing.TB, archive Archive, resources installedarchive.RecoveryResources) *RecoveryResponder {
	return newRecoveryResponder(t, archive, resources, archive.Family == contract.AWS)
}

func newRecoveryResponder(t testing.TB, archive Archive, resources installedarchive.RecoveryResources, tls bool) *RecoveryResponder {
	t.Helper()
	r := &RecoveryResponder{archive: archive, resources: resources}
	if archive.Family == contract.AWS {
		parts := strings.Split(archive.AuthorityBinding.KeySelector, ":")
		if len(parts) != 6 {
			t.Fatal("fixture Authority selector")
		}
		r.privateRegion = parts[3]
	} else {
		parts := strings.Split(archive.AuthorityBinding.KeySelector, "/")
		if len(parts) != 10 {
			t.Fatal("fixture Authority selector")
		}
		r.privateRegion = parts[3]
	}

	var server *httptest.Server
	if archive.Family == contract.AWS {
		server, r.certificate = startAWSRecoveryServer(t, []string{"s3." + archive.Location.Region + ".amazonaws.com", "kms.us-east-1.amazonaws.com", "kms." + r.privateRegion + ".amazonaws.com"}, http.HandlerFunc(r.serve))
	} else if tls {
		hosts := []string{"storage." + archive.Location.Region + ".rep.googleapis.com", r.privateRegion + "-cloudkms.googleapis.com"}
		for _, resource := range []installedarchive.SigningResource{resources.Normal, resources.Recovery} {
			if resource.Selector != "" {
				hosts = append(hosts, resource.Region+"-cloudkms.googleapis.com")
			}
		}
		server, r.certificate = startAWSRecoveryServer(t, hosts, http.HandlerFunc(r.serve))
	} else {
		server = httptest.NewServer(http.HandlerFunc(r.serve))
		t.Cleanup(server.Close)
	}

	r.server = server
	return r
}

func (r *RecoveryResponder) Address() string { return r.server.Listener.Addr().String() }

func (r *RecoveryResponder) SetPolicy(policy ResponderPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy = policy
}
func (r *RecoveryResponder) AllowRemoval(removal ExactRemoval) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !removal.valid(r.archive.Family, r.archive.Location.PrefixBeforeHEAD) || r.removal != nil {
		return errors.New("private fixture removal refused")
	}
	for _, object := range r.archive.Objects {
		if object.Key == removal.Key && object.Token == removal.Token {
			r.removal = &removal
			return nil
		}
	}
	return errors.New("private fixture target unavailable")
}
func (r *RecoveryResponder) Certificate() []byte { return append([]byte(nil), r.certificate...) }
func (r *RecoveryResponder) Counts() RecoveryCounts {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.counts
}
func (r *RecoveryResponder) Requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requests...)
}
func remoteBytes(a Archive, resources installedarchive.RecoveryResources, policy ResponderPolicy) ([]byte, error) {
	return json.Marshal(struct {
		Archive   Archive
		Resources installedarchive.RecoveryResources
		Policy    ResponderPolicy
	}{a, resources, policy})
}

func (r *RecoveryResponder) RemoteBytes() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return remoteBytes(r.archive, r.resources, r.policy)
}

func (r *RecoveryResponder) serve(w http.ResponseWriter, q *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.archive
	if len(r.requests) >= 4096 {
		r.counts.Unknown++
		http.Error(w, "request inventory exceeds bound", http.StatusForbidden)
		return
	}
	r.requests = append(r.requests, q.Method+" "+q.Host+" "+q.URL.Path+" "+q.Header.Get("X-Amz-Target"))
	deny := func() { r.counts.Unknown++; http.Error(w, "request refused", http.StatusForbidden) }
	if q.Header.Get("Authorization") == "" {
		deny()
		return
	}
	if q.Method == http.MethodDelete && r.removal != nil {
		removal := r.removal
		matched := a.Family == contract.AWS && q.Host == "s3."+a.Location.Region+".amazonaws.com" && q.URL.Path == "/"+a.Location.Bucket+"/"+removal.Key && q.URL.RawQuery == "x-id=DeleteObject" && q.Header.Get("If-Match") == removal.Token.Value && q.Header.Get("X-Amz-Expected-Bucket-Owner") == a.Location.ExpectedOwner
		if a.Family == contract.GCP {
			query := q.URL.Query()
			matched = q.Host == "storage."+a.Location.Region+".rep.googleapis.com" && q.URL.Path == "/storage/v1/b/"+a.Location.Bucket+"/o/"+removal.Key && len(query) == 3 && query.Get("alt") == "json" && query.Get("ifGenerationMatch") == removal.Token.Value && query.Get("prettyPrint") == "false"
		}
		if !matched || q.ContentLength != 0 || r.externalMutations != 0 {
			deny()
			return
		}
		r.counts.Delete++
		r.archive = withoutRemoteObject(r.archive, removal.Key)
		r.externalMutations = 1
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var objectKey string
	if a.Family == contract.AWS && q.Host == "s3."+a.Location.Region+".amazonaws.com" {
		if q.Method != http.MethodGet {
			r.counts.StoreWrites++
			deny()
			return
		}
		owner := q.Header.Get("X-Amz-Expected-Bucket-Owner")
		if owner != a.Location.ExpectedOwner && (owner != "" || r.counts.Reads >= 3) {
			http.Error(w, "owner refused", http.StatusForbidden)
			return
		}
		prefix := "/" + a.Location.Bucket + "/"
		if !strings.HasPrefix(q.URL.Path, prefix) {
			http.NotFound(w, q)
			return
		}
		objectKey = strings.TrimPrefix(q.URL.Path, prefix)
	} else if a.Family == contract.GCP && q.Host == "storage."+a.Location.Region+".rep.googleapis.com" {
		if q.Method != http.MethodGet || q.URL.Query().Get("alt") != "media" {
			deny()
			return
		}
		prefix := "/download/storage/v1/b/" + a.Location.Bucket + "/o/"
		if !strings.HasPrefix(q.URL.Path, prefix) {
			http.NotFound(w, q)
			return
		}
		objectKey = strings.TrimPrefix(q.URL.Path, prefix)
	}
	if objectKey != "" {
		r.counts.Reads++
		item, ok := a.Object(objectKey)
		if !ok {
			if a.Family == contract.AWS {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				if _, err := io.WriteString(w, "<Error><Code>NoSuchKey</Code></Error>"); err != nil {
					r.counts.Unknown++
				}
			} else {
				http.NotFound(w, q)
			}
			return
		}
		if a.Family == contract.AWS {
			w.Header().Set("ETag", item.Token.Value)
		} else {
			w.Header().Set("X-Goog-Generation", item.Token.Value)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(item.Body)))
		if _, err := w.Write(item.Body); err != nil {
			r.counts.Unknown++
		}
		return
	}
	crc := func(b []byte) string {
		return strconv.FormatUint(uint64(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))), 10)
	}
	var reply any
	if a.Family == contract.AWS {
		if q.Method != http.MethodPost {
			deny()
			return
		}
		var body struct{ KeyId, CiphertextBlob string }
		if json.NewDecoder(io.LimitReader(q.Body, 16<<10)).Decode(&body) != nil {
			deny()
			return
		}
		switch q.Header.Get("X-Amz-Target") {
		case "TrentService.GetPublicKey":
			r.counts.PublicLookups++
			r.externalRemoval()
			resource, denied := r.resources.Normal, r.policy.DenyNormal
			r.counts.NormalLookups++
			if body.KeyId == r.resources.Recovery.Selector {
				resource, denied = r.resources.Recovery, r.policy.DenyRecovery
				r.counts.NormalLookups--
				r.counts.RecoveryLookups++
			}
			if q.Host != "kms."+resource.Region+".amazonaws.com" || body.KeyId != resource.Selector || denied {
				http.Error(w, "signer refused", http.StatusForbidden)
				return
			}
			reply = map[string]any{"KeyId": resource.Selector, "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY", "PublicKey": base64.StdEncoding.EncodeToString(resource.PublicKey), "SigningAlgorithms": []string{"ECDSA_SHA_256"}}
		case "TrentService.DescribeKey":
			r.counts.RecoveryMetadata++
			resource := r.resources.Recovery
			if q.Host != "kms."+resource.Region+".amazonaws.com" || body.KeyId != resource.Selector || r.policy.DenyRecovery {
				http.Error(w, "metadata refused", http.StatusForbidden)
				return
			}
			reply = map[string]any{"KeyMetadata": map[string]any{"Arn": resource.Selector, "Enabled": true, "KeyState": "Enabled", "Origin": "AWS_KMS", "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}}
		case "TrentService.Decrypt":
			if body.KeyId != a.AuthorityBinding.KeySelector {
				r.counts.OtherDecrypts++
				http.Error(w, "non-authority private route refused", http.StatusForbidden)
				return
			}
			r.counts.AuthorityDecrypts++
			if q.Host != "kms."+r.privateRegion+".amazonaws.com" || body.KeyId != a.AuthorityBinding.KeySelector || r.policy.DenyAuthority || r.policy.DenySecretOrdinal == r.counts.AuthorityDecrypts {
				http.Error(w, "private route refused", http.StatusForbidden)
				return
			}
			ciphertext, err := base64.StdEncoding.DecodeString(body.CiphertextBlob)
			if err != nil {
				deny()
				return
			}
			packet, err := a.DecryptAuthority(ciphertext)
			if err != nil {
				http.Error(w, "decrypt refused", http.StatusForbidden)
				return
			}
			defer clear(packet)
			reply = map[string]any{"KeyId": a.AuthorityBinding.KeySelector, "EncryptionAlgorithm": "RSAES_OAEP_SHA_256", "Plaintext": base64.StdEncoding.EncodeToString(packet)}
		default:
			deny()
			return
		}
	} else if q.Method == http.MethodGet && (q.URL.Path == "/v1/"+r.resources.Normal.Selector+"/publicKey" || q.URL.Path == "/v1/"+r.resources.Recovery.Selector+"/publicKey") {
		r.counts.PublicLookups++
		r.externalRemoval()
		resource, denied := r.resources.Normal, r.policy.DenyNormal
		r.counts.NormalLookups++
		if q.URL.Path == "/v1/"+r.resources.Recovery.Selector+"/publicKey" {
			resource, denied = r.resources.Recovery, r.policy.DenyRecovery
			r.counts.NormalLookups--
			r.counts.RecoveryLookups++
		}
		if q.Host != resource.Region+"-cloudkms.googleapis.com" || denied {
			http.Error(w, "public route refused", http.StatusForbidden)
			return
		}
		key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: resource.PublicKey})
		reply = map[string]any{"name": resource.Selector, "algorithm": "EC_SIGN_P256_SHA256", "protectionLevel": "SOFTWARE", "pem": string(key), "pemCrc32c": crc(key)}
	} else if q.Method == http.MethodGet && q.URL.Path == "/v1/"+r.resources.Recovery.Selector && q.Host == r.resources.Recovery.Region+"-cloudkms.googleapis.com" {
		r.counts.RecoveryMetadata++
		if r.policy.DenyRecovery {
			http.Error(w, "metadata refused", http.StatusForbidden)
			return
		}
		reply = map[string]any{"name": r.resources.Recovery.Selector, "algorithm": "EC_SIGN_P256_SHA256", "state": "ENABLED", "protectionLevel": "SOFTWARE", "generateTime": "2026-01-01T00:00:00Z"}
	} else if q.Host == r.privateRegion+"-cloudkms.googleapis.com" && q.Method == http.MethodPost && q.URL.Path == "/v1/"+a.AuthorityBinding.KeySelector+":asymmetricDecrypt" {
		r.counts.AuthorityDecrypts++
		if r.policy.DenyAuthority || r.policy.DenySecretOrdinal == r.counts.AuthorityDecrypts {
			http.Error(w, "private route refused", http.StatusForbidden)
			return
		}
		var body struct{ Ciphertext, CiphertextCrc32c string }
		if json.NewDecoder(io.LimitReader(q.Body, 16<<10)).Decode(&body) != nil {
			deny()
			return
		}
		ciphertext, err := base64.StdEncoding.DecodeString(body.Ciphertext)
		if err != nil || body.CiphertextCrc32c != crc(ciphertext) {
			deny()
			return
		}
		packet, err := a.DecryptAuthority(ciphertext)
		if err != nil {
			http.Error(w, "decrypt refused", http.StatusForbidden)
			return
		}
		defer clear(packet)
		reply = map[string]any{"plaintext": base64.StdEncoding.EncodeToString(packet), "plaintextCrc32c": crc(packet), "verifiedCiphertextCrc32c": true, "protectionLevel": "SOFTWARE"}
	} else {
		if q.Method == http.MethodPost && strings.HasSuffix(q.URL.Path, ":asymmetricDecrypt") {
			r.counts.OtherDecrypts++
		}
		deny()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(reply); err != nil {
		r.counts.Unknown++
	}
}

func withoutRemoteObject(a Archive, key string) Archive {
	objects := make([]installedarchive.Object, 0, len(a.Objects))
	var fileBytes uint64
	for _, object := range a.Objects {
		if object.Key != key {
			objects = append(objects, object)
			fileBytes += uint64(28) + uint64(len(object.Key)) + uint64(len(object.TokenWire)) + uint64(len(object.Body))
		}
	}
	a.Objects, a.ObjectCount, a.ObjectFileBytes = objects, len(objects), fileBytes
	return a
}

func (r *RecoveryResponder) externalRemoval() {
	if r.policy.RemoveObjectAfterPublic != "" && r.externalMutations == 0 {
		r.archive = withoutRemoteObject(r.archive, r.policy.RemoveObjectAfterPublic)
		r.externalMutations = 1
	}
}

func (r *RecoveryResponder) ExternalMutations() uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.externalMutations
}

func startAWSRecoveryServer(t testing.TB, hosts []string, handler http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: hosts, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, der
}

func (r *RecoveryResponder) StartOracleEpoch() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts = RecoveryCounts{}
	r.requests = nil
}
