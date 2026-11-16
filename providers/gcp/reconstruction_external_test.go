package gcp_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
	gcp "enkv.sh/providers/gcp"
)

type installedRoundTrip func(*http.Request) (*http.Response, error)

func (f installedRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func installedReply(code int, body []byte) *http.Response {
	return &http.Response{StatusCode: code, Status: strconv.Itoa(code) + " local", Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}
func installedCRC(body []byte) uint32 { return crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)) }

// This signed v8-policy selection retains its original bytes. Its older
// intent layout is refused before current trust-policy qualification.
//
//go:embed testdata/trust-v8-gcp.json
var obsoleteTrustArchive []byte

func installedObsoleteTrustCandidate(t *testing.T, archive installedarchive.Archive) (installedarchive.Archive, []string) {
	t.Helper()
	headKey := archive.Location.PrefixBeforeHEAD + "/HEAD"
	head, err := format.DecodeHead(archive.MustObject(t, headKey).Body)
	if err != nil || head.AuthKind != format.LifecycleAuth {
		t.Fatal("current trust fixture HEAD refused", err)
	}
	rootKey, err := format.Key(archive.Location.PrefixBeforeHEAD, head.Core.Root)
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.DecodeRoot(archive.MustObject(t, rootKey).Body)
	if err != nil || root.CurrentAccess.Core.TrustInterpretationID != contract.TrustInterpretationID() {
		t.Fatal("current trust fixture Root refused", err)
	}
	// The independent archive resource owner chooses this material before
	// the provider construction assigns its separate TrustID.
	signer := testtrust.NewWithIdentity(t, archive.Family, contract.Hash([]byte("fixture/trust")), archive.SignerID, contract.NormalSigningRole)
	binding := root.CurrentAccess.Core.NormalSigning
	if signer.Identity() != binding.Binding.Trust || signer.KeySelector() != binding.KeySelector ||
		signer.KeySelector() != archive.SignerSelector || !bytes.Equal(signer.PublicKey(), binding.SPKI) ||
		!bytes.Equal(signer.PublicKey(), archive.SignerPublicKey) {
		t.Fatal("current trust fixture signing resource differs")
	}
	obsolete, err := hex.DecodeString("719f88c954b8254d24e0fc673b1977e867e4432096dd6d8bc0924ef0b4e2b754")
	if err != nil {
		t.Fatal(err)
	}
	copy(root.CurrentAccess.Core.TrustInterpretationID[:], obsolete)
	root.CurrentAccess.AccessRoot, err = contract.AccessRoot(root.CurrentAccess.Core)
	if err != nil {
		t.Fatal(err)
	}
	rootBody, err := format.EncodeRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	head.Core.Root, err = format.Reference(contract.RootKind, root.Domain, root.Snapshot, 0, rootBody)
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.AfterAccessRoot = root.CurrentAccess.AccessRoot
	coreBody, err := format.EncodeHeadCore(head.Core)
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.HeadCore, head.Subject.HeadCoreLength = contract.Hash(coreBody), uint32(len(coreBody))
	condition, err := contract.MatchHeadCondition(head.Core.PreviousToken)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := format.EncodeConditionalPlan(format.ConditionalPlan{Family: archive.Family, Store: head.Core.Store,
		Coordinate: head.Core.Coordinate, NonBody: head.Core.NonBody, Condition: condition,
		HeadCore: head.Subject.HeadCore, HeadCoreLength: head.Subject.HeadCoreLength})
	if err != nil {
		t.Fatal(err)
	}
	head.Subject.ConditionalPlan = contract.Hash(plan)
	request, err := contract.NewLifecycleRequest(head.Subject)
	if err != nil {
		t.Fatal(err)
	}
	signed := signer.Sign(t.Context(), request)
	publicKey, err := x509.ParsePKIXPublicKey(archive.SignerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := publicKey.(*ecdsa.PublicKey)
	digest := request.Digest()
	if signed.Reason != contract.ReasonNone || !ok || !ecdsa.VerifyASN1(public, digest[:], signed.Signature) {
		t.Fatal("current-format obsolete trust fixture signature refused")
	}
	head.AuthorizationSignature = signed.Signature
	headBody, err := format.EncodeHead(head)
	if err != nil {
		t.Fatal(err)
	}
	archive.Objects = append([]installedarchive.Object(nil), archive.Objects...)
	archive.ObjectFileBytes = 0
	for i := range archive.Objects {
		object := &archive.Objects[i]
		switch object.Key {
		case headKey:
			object.Body = headBody
		case rootKey:
			object.Body = rootBody
		}
		digest := contract.Hash(object.Body)
		object.BodySHA256 = hex.EncodeToString(digest[:])
		archive.ObjectFileBytes += uint64(28 + len(object.Key) + len(object.TokenWire) + len(object.Body))
	}
	archive.HeadDigest = contract.Hash(headBody)
	configurationKey, err := contract.StoreConfigurationKeyForID(archive.Family, archive.Location.PrefixBeforeHEAD, archive.Domain, head.Core.Store)
	if err != nil {
		t.Fatal(err)
	}
	return archive, []string{headKey, configurationKey, rootKey}
}

// full_only: false
func TestInstalledGCPReconstructionSelectsEncryptedStateWithoutEffects(t *testing.T) {
	installedGCPReconstruction(t, false, false)
}

// full_only: false
func TestInstalledGCPReconstructionUsesAuthenticatedPrivateScopeWithMinimalInputs(t *testing.T) {
	installedGCPReconstruction(t, true, false)
}
func installedGCPReconstruction(t *testing.T, minimal, mismatch bool, failures ...string) {
	failure := ""
	if len(failures) > 0 {
		failure = failures[0]
	}
	t.Helper()
	archive := installedarchive.Load(t, "gcp")
	var expectedPublicKeys []string
	switch failure {
	case "obsolete-format":
		if err := json.Unmarshal(obsoleteTrustArchive, &archive); err != nil {
			t.Fatal(err)
		}
		for i := range archive.Objects {
			token, n, err := contract.ParseToken(archive.Objects[i].TokenWire)
			if err != nil || n != len(archive.Objects[i].TokenWire) {
				t.Fatal("obsolete fixture token")
			}
			archive.Objects[i].Token = token
		}
		expectedPublicKeys = []string{archive.Location.PrefixBeforeHEAD + "/HEAD"}
	case "obsolete-trust":
		archive, expectedPublicKeys = installedObsoleteTrustCandidate(t, archive)
	}
	var gcsReads, publicLookups, privateDecrypts, mutations int
	var order []string
	client := gcp.NewReconstructionTransportTestClient(installedRoundTrip(func(r *http.Request) (*http.Response, error) {
		order = append(order, r.URL.Host+" "+r.Method+" "+r.URL.Path)
		if r.URL.Host == "storage."+archive.Location.Region+".rep.googleapis.com" {
			if r.Method != http.MethodGet {
				mutations++
				return installedReply(405, []byte(`{"error":{"code":405}}`)), nil
			}
			prefix := "/download/storage/v1/b/" + archive.Location.Bucket + "/o/"
			if !strings.HasPrefix(r.URL.Path, prefix) || r.URL.Query().Get("alt") != "media" || r.Header.Get("Authorization") == "" {
				return installedReply(403, []byte(`{"error":{"code":403}}`)), nil
			}
			key := strings.TrimPrefix(r.URL.Path, prefix)
			item, ok := archive.Object(key)
			if !ok {
				return installedReply(404, []byte(`{"error":{"code":404}}`)), nil
			}
			gcsReads++
			reply := installedReply(200, item.Body)
			reply.Header.Set("X-Goog-Generation", item.Token.Value)
			reply.Header.Set("Content-Type", "application/octet-stream")
			return reply, nil
		}
		if r.URL.Host != "us-central1-cloudkms.googleapis.com" && r.URL.Host != "europe-west1-cloudkms.googleapis.com" || r.Header.Get("Authorization") == "" {
			mutations++
			return installedReply(405, []byte(`{"error":{"code":405}}`)), nil
		}
		if r.URL.Host == "us-central1-cloudkms.googleapis.com" && r.Method == http.MethodGet && r.URL.Path == "/v1/"+archive.SignerSelector+"/publicKey" {
			if gcsReads != 3 || privateDecrypts != 0 {
				t.Error("signer lookup before bounded selection or after private use")
			}
			publicLookups++
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: archive.SignerPublicKey})
			body, _ := json.Marshal(map[string]any{"name": archive.SignerSelector, "algorithm": "EC_SIGN_P256_SHA256",
				"protectionLevel": "SOFTWARE", "pem": string(pemBytes), "pemCrc32c": strconv.FormatUint(uint64(installedCRC(pemBytes)), 10)})
			return installedReply(200, body), nil
		}
		if r.URL.Host == "europe-west1-cloudkms.googleapis.com" && r.Method == http.MethodPost && r.URL.Path == "/v1/"+archive.AuthorityBinding.KeySelector+":asymmetricDecrypt" {
			var q struct{ Ciphertext, CiphertextCrc32c string }
			if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&q) != nil {
				return installedReply(400, []byte(`{"error":{"code":400}}`)), nil
			}
			ciphertext, err := base64.StdEncoding.DecodeString(q.Ciphertext)
			if err != nil || q.CiphertextCrc32c != strconv.FormatUint(uint64(installedCRC(ciphertext)), 10) {
				return installedReply(400, []byte(`{"error":{"code":400}}`)), nil
			}
			packet, err := archive.DecryptAuthority(ciphertext)
			if err != nil {
				return installedReply(403, []byte(`{"error":{"code":403}}`)), nil
			}
			defer clear(packet)
			if publicLookups != 1 || gcsReads < archive.ObjectCount {
				t.Error("private use before complete public reads")
			}
			privateDecrypts++
			if failure == "invalid-argument" {
				return installedReply(400, []byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT"}}`)), nil
			}
			if failure == "unavailable" {
				return installedReply(503, []byte(`{"error":{"code":503,"status":"UNAVAILABLE"}}`)), nil
			}
			if failure == "malformed" {
				return installedReply(200, []byte(`{"plaintext":`)), nil
			}
			if failure == "packet-context" {
				packet[4] ^= 1
			}
			checksum := installedCRC(packet)
			if failure == "crc" {
				checksum ^= 1
			}
			verified := failure != "unverified"
			body, _ := json.Marshal(map[string]any{"plaintext": base64.StdEncoding.EncodeToString(packet),
				"plaintextCrc32c":          strconv.FormatUint(uint64(checksum), 10),
				"verifiedCiphertextCrc32c": verified, "protectionLevel": "SOFTWARE"})
			return installedReply(200, body), nil
		}
		mutations++
		return installedReply(405, []byte(`{"error":{"code":405}}`)), nil
	}))
	private := compositiongcp.ReconstructionKeyAccessConfig{Client: client, CredentialRoute: contract.Hash([]byte("installed-authority-route"))}
	expectedKEK := archive.AuthorityBinding.KeySelector
	if minimal {
		expectedKEK = ""
	}
	normal := &gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Client: client, Region: "us-central1",
		KeyVersion: archive.SignerSelector, CredentialRoute: "installed-sign-route"}
	if mismatch {
		expectedKEK = "different-independent-key"
	}
	engine, err := compositiongcp.NewReconstruction(context.Background(), compositiongcp.ReconstructionConfig{
		Candidate: gcp.CandidateReadConfig{Client: client, Region: archive.Location.Region, Bucket: archive.Location.Bucket,
			Prefix: archive.Location.PrefixBeforeHEAD, CredentialRoute: "installed-read-route"}, Normal: normal,
		KeyAccess: private, ExpectedKEK: expectedKEK, ExpectedDomain: archive.Domain})
	if err != nil {
		t.Fatal("installed GCP composition refused", err)
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
	if failure != "" {
		// A service INVALID_ARGUMENT does not establish an invalid local
		// admission or stored ciphertext. Reconstruction still lacks private
		// proof, so a qualified public closure remains unavailable to it.
		want := core.Result{Outcome: core.EvidenceUnavailable, Reason: core.CustodyUnavailable}
		if failure == "obsolete-trust" || failure == "packet-context" {
			want = core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidProof}
		}
		if failure == "obsolete-format" {
			want = core.Result{Outcome: core.IntegrityFailure, Reason: core.InvalidFormat}
		}
		wantDecrypts, wantLookups := 1, 1
		if len(expectedPublicKeys) != 0 {
			wantDecrypts, wantLookups = 0, 0
			if gcsReads != len(expectedPublicKeys) || len(order) != len(expectedPublicKeys) {
				t.Fatal("obsolete fixture refused at an unexpected public-read gate", gcsReads, order)
			}
			for i, key := range expectedPublicKeys {
				want := "storage." + archive.Location.Region + ".rep.googleapis.com GET /download/storage/v1/b/" + archive.Location.Bucket + "/o/" + key
				if order[i] != want {
					t.Fatal("obsolete fixture public-read order differs", order)
				}
			}
		}
		if projection != nil || result != want || privateDecrypts != wantDecrypts || publicLookups != wantLookups || mutations != 0 {
			t.Fatalf("failure %s result=%+v want=%+v decrypts=%d lookups=%d effects=%d", failure, result, want, privateDecrypts, publicLookups, mutations)
		}
		return
	}

	if projection == nil || result.Outcome != core.ObservedCurrent || result.Evidence != core.AuthenticatedClosure {
		t.Fatal("installed GCP reconstruction did not select current state", result, "gcs", gcsReads, "public", publicLookups, "private", privateDecrypts, "mutations", mutations)
	}
	defer projection.Close()
	provenance, ok := projection.Provenance()
	if !ok || provenance.Domain != archive.Domain || provenance.Revision != archive.Revision || provenance.HEADDigest != archive.HeadDigest {
		t.Fatal("installed GCP projection changed signed provenance")
	}
	parts := make([]core.ReconstructionPart, 0, projection.PartCount())
	for i := 0; i < projection.PartCount(); i++ {
		part, ok := projection.CopyPart(i)
		if !ok {
			t.Fatal("installed projection lost a part")
		}
		parts = append(parts, part)
	}
	expected, err := archive.SelectedParts()
	matches := err == nil && len(expected) == len(parts)
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
	if err != nil || !matches {
		t.Fatal("installed GCP projection differs from exact signed selected set", len(parts), err)
	}
	if len(order) < 5 || !strings.HasSuffix(order[0], "/HEAD") || !strings.HasSuffix(order[3], "/publicKey") || !strings.HasSuffix(order[len(order)-2], ":asymmetricDecrypt") || !strings.HasSuffix(order[len(order)-1], "/HEAD") {
		t.Fatal("provider order", order)
	}
	if gcsReads < archive.ObjectCount || publicLookups != 1 || privateDecrypts != 1 || mutations != 0 {
		t.Fatal("installed GCP reconstruction made an effect or skipped provider proof", gcsReads, publicLookups, privateDecrypts, mutations)
	}
}

// full_only: false
func TestInstalledGCPReconstructionExpectedKEKMismatchStopsBeforeDecrypt(t *testing.T) {
	installedGCPReconstruction(t, true, true)
}

// full_only: false
func TestInstalledGCPReconstructionKeepsPrivateFailureMeaning(t *testing.T) {
	for _, failure := range []string{"malformed", "crc", "unverified", "invalid-argument", "unavailable", "packet-context"} {
		t.Run(failure, func(t *testing.T) { installedGCPReconstruction(t, true, false, failure) })
	}
}

// full_only: false
func TestInstalledGCPReconstructionRefusesObsoleteTrustInterpretation(t *testing.T) {
	t.Run("original-format-refusal", func(t *testing.T) { installedGCPReconstruction(t, true, false, "obsolete-format") })
	t.Run("current-format-obsolete-trust", func(t *testing.T) { installedGCPReconstruction(t, true, false, "obsolete-trust") })
}
