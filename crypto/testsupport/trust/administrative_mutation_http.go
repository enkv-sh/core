package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// AdministrativeMutationHTTP is a bounded local native-provider fixture. It
// permits only the administrative Store writes and current Normal signature.
// No key lookup, decryption, cleanup, listing or effect API is implemented.
type AdministrativeMutationHTTP struct {
	*AdministrativeReadHTTP
	signing             contract.PublicSigningBinding
	signer              *Signer
	creates, cas, signs int
	sequence            uint64
	dropCASReply        bool
}

func NewAdministrativeMutationHTTP(t testing.TB, location contract.StoreLocation, objects []AdministrativeReadObject, signing contract.PublicSigningBinding) (*AdministrativeMutationHTTP, *http.Transport) {
	t.Helper()
	// The archive exporter fixes this synthetic material route independently
	// of the native provider TrustID. Validate all public facts below.
	signer := NewWithIdentity(t, location.Provider, contract.Hash([]byte("fixture/trust")), signing.Binding.Trust, contract.NormalSigningRole)
	if signing.Provider != location.Provider || signing.Role != contract.NormalSigningRole || signer.KeySelector() != signing.KeySelector || !bytes.Equal(signer.PublicKey(), signing.SPKI) {
		t.Fatal("administrative fixture signer mismatch")
	}
	h := &AdministrativeMutationHTTP{AdministrativeReadHTTP: &AdministrativeReadHTTP{location: location, objects: objects, principals: make(map[string]bool)}, signing: signing, signer: signer, sequence: 1 << 40}
	var host string
	if location.Provider == contract.GCP {
		selector, ok := contract.ParseGCPKeySelector(signing.KeySelector, true)
		if !ok {
			t.Fatal("fixture signer resource")
		}
		host = selector.Region + "-cloudkms.googleapis.com"
	} else {
		selector, ok := contract.ParseAWSKeySelector(signing.KeySelector, true)
		if !ok {
			t.Fatal("fixture signer resource")
		}
		host = "kms." + selector.Region + ".amazonaws.com"
	}
	transport := PublicHTTPSTransport(t, []string{"s3." + location.Region + ".amazonaws.com", "storage." + location.Region + ".rep.googleapis.com", host}, http.HandlerFunc(h.serveAdministrative))
	return h, transport
}

// DropNextCASReply preserves the selected Store image and aborts only its reply.
func (h *AdministrativeMutationHTTP) DropNextCASReply() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropCASReply = true
}
func (h *AdministrativeMutationHTTP) MutationCounts() (creates, cas, signs int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.creates, h.cas, h.signs
}
func (h *AdministrativeMutationHTTP) Objects() []AdministrativeReadObject {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]AdministrativeReadObject, len(h.objects))
	for i, o := range h.objects {
		out[i] = AdministrativeReadObject{o.Key, o.Token, bytes.Clone(o.Body)}
	}
	return out
}
func (h *AdministrativeMutationHTTP) serveAdministrative(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		h.serveHTTP(w, r)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Header.Get("Authorization") == "" {
		h.forbidden++
		http.Error(w, "fixture authorization missing", http.StatusForbidden)
		return
	}
	if strings.Contains(r.Host, "kms.") || strings.HasSuffix(r.Host, "-cloudkms.googleapis.com") {
		h.sign(w, r)
		return
	}
	location := h.location
	key := ""
	condition := ""
	var body []byte
	if location.Provider == contract.AWS {
		prefix := "/" + location.Bucket + "/"
		if r.Method != http.MethodPut || r.Host != "s3."+location.Region+".amazonaws.com" || !strings.HasPrefix(r.URL.Path, prefix) || r.Header.Get("x-amz-expected-bucket-owner") != location.ExpectedOwner {
			h.refuse(w)
			return
		}
		key = strings.TrimPrefix(r.URL.Path, prefix)
		condition = r.Header.Get("If-Match")
		if condition == "" && r.Header.Get("If-None-Match") != "*" {
			h.refuse(w)
			return
		}
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
		if err != nil {
			h.refuse(w)
			return
		}
	} else {
		if r.Method != http.MethodPost || r.Host != "storage."+location.Region+".rep.googleapis.com" || r.URL.Path != "/upload/storage/v1/b/"+location.Bucket+"/o" || r.URL.Query().Get("uploadType") != "multipart" {
			h.refuse(w)
			return
		}
		kind, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || kind != "multipart/related" {
			h.refuse(w)
			return
		}
		wire, err := io.ReadAll(io.LimitReader(r.Body, 2<<20+4097))
		if err != nil || len(wire) > 2<<20+4096 {
			h.refuse(w)
			return
		}
		reader := multipart.NewReader(bytes.NewReader(wire), params["boundary"])
		metadata, err := reader.NextPart()
		if err != nil {
			h.refuse(w)
			return
		}
		var m struct {
			Name    string `json:"name"`
			CRC     string `json:"crc32c"`
			Cache   string `json:"cacheControl"`
			Content string `json:"contentType"`
		}
		if json.NewDecoder(metadata).Decode(&m) != nil {
			h.refuse(w)
			return
		}
		media, err := reader.NextPart()
		if err != nil {
			h.refuse(w)
			return
		}
		body, err = io.ReadAll(media)
		if err != nil {
			h.refuse(w)
			return
		}
		if _, err = reader.NextPart(); err != io.EOF || m.CRC != administrativeCRC(body) || m.Cache != "private, no-store, no-transform" || m.Content != "application/octet-stream" {
			h.refuse(w)
			return
		}
		key = m.Name
		condition = r.URL.Query().Get("ifGenerationMatch")
		if condition == "0" {
			condition = ""
		}
	}
	if len(body) == 0 || len(body) > 2<<20 || len(h.objects) > 256 || !strings.HasPrefix(key, location.PrefixBeforeHEAD+"/") {
		h.refuse(w)
		return
	}
	position := -1
	for i, o := range h.objects {
		if o.Key == key {
			position = i
			break
		}
	}
	head := key == location.PrefixBeforeHEAD+"/HEAD"
	if head && (condition == "" || position < 0 || h.objects[position].Token.Value != condition) || !head && (condition != "" || position >= 0) {
		if location.Provider == contract.AWS {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, writeErr := io.WriteString(w, "<Error><Code>PreconditionFailed</Code></Error>")
			if writeErr != nil {
				h.forbidden++
			}
		} else {
			h.failureResponse(w, http.StatusPreconditionFailed)
		}
		return
	}
	if head {
		if h.cas != 0 {
			h.refuse(w)
			return
		}
		h.cas++
	} else {
		h.creates++
	}
	h.sequence++
	token := strconv.FormatUint(h.sequence, 10)
	if location.Provider == contract.AWS {
		token = `"administrative-` + token + `"`
	}
	object := AdministrativeReadObject{key, contract.Token{Family: location.Provider, Value: token}, bytes.Clone(body)}
	if position >= 0 {
		h.objects[position] = object
	} else {
		h.objects = append(h.objects, object)
	}
	if head && h.dropCASReply {
		h.dropCASReply = false
		panic(http.ErrAbortHandler)
	}
	if location.Provider == contract.AWS {
		w.Header().Set("ETag", token)
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
		return
	}
	h.json(w, map[string]string{"bucket": location.Bucket, "name": key, "generation": token, "size": strconv.Itoa(len(body)), "crc32c": administrativeCRC(body)})
}
func (h *AdministrativeMutationHTTP) sign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || h.signs != 0 {
		h.refuse(w)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(wire) > 4096 {
		h.refuse(w)
		return
	}
	digestText := ""
	if h.location.Provider == contract.AWS {
		selector, ok := contract.ParseAWSKeySelector(h.signing.KeySelector, true)
		if !ok || r.Host != "kms."+selector.Region+".amazonaws.com" || r.Header.Get("X-Amz-Target") != "TrentService.Sign" {
			h.refuse(w)
			return
		}
		var input struct {
			Key       string `json:"KeyId"`
			Message   string `json:"Message"`
			Type      string `json:"MessageType"`
			Algorithm string `json:"SigningAlgorithm"`
		}
		if json.Unmarshal(wire, &input) != nil || input.Key != h.signing.KeySelector || input.Type != "DIGEST" || input.Algorithm != "ECDSA_SHA_256" {
			h.refuse(w)
			return
		}
		digestText = input.Message
	} else {
		selector, ok := contract.ParseGCPKeySelector(h.signing.KeySelector, true)
		if !ok || r.Host != selector.Region+"-cloudkms.googleapis.com" || r.URL.Path != "/v1/"+h.signing.KeySelector+":asymmetricSign" {
			h.refuse(w)
			return
		}
		var input struct {
			Digest struct {
				SHA string `json:"sha256"`
			} `json:"digest"`
			CRC string `json:"digestCrc32c"`
		}
		if json.Unmarshal(wire, &input) != nil {
			h.refuse(w)
			return
		}
		digestText = input.Digest.SHA
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(digestText)
	if err != nil || len(digest) != 32 {
		h.refuse(w)
		return
	}
	signature, err := ecdsa.SignASN1(rand.Reader, h.signer.key, digest)
	if err != nil {
		h.refuse(w)
		return
	}
	h.signs++
	if h.location.Provider == contract.AWS {
		h.json(w, map[string]string{"KeyId": h.signing.KeySelector, "Signature": base64.StdEncoding.EncodeToString(signature), "SigningAlgorithm": "ECDSA_SHA_256"})
		return
	}
	h.json(w, map[string]any{"name": h.signing.KeySelector, "signature": base64.StdEncoding.EncodeToString(signature), "signatureCrc32c": strconv.FormatUint(uint64(crc32.Checksum(signature, crc32.MakeTable(crc32.Castagnoli))), 10), "verifiedDigestCrc32c": true})
}
func (h *AdministrativeMutationHTTP) refuse(w http.ResponseWriter) {
	h.forbidden++
	http.Error(w, "unexpected administrative fixture request", http.StatusForbidden)
}
func (h *AdministrativeMutationHTTP) json(w http.ResponseWriter, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		h.refuse(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if _, err := w.Write(body); err != nil {
		h.forbidden++
	}
}
func administrativeCRC(body []byte) string {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)))
	return base64.StdEncoding.EncodeToString(out[:])
}
