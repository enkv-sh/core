package compositiongcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"

	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	privatecrypto "enkv.sh/crypto"
	"enkv.sh/crypto/testsupport/installedarchive"
	provider "enkv.sh/providers/gcp"
)

func materializationConfig(t *testing.T) MaterializationConfig {
	t.Helper()
	_, reader := readerConfig(t)
	route := contract.Hash([]byte("materialization route"))
	reader.Candidate.CredentialRoute = hex.EncodeToString(route[:])
	reader.Validator = nil
	target, err := privatecrypto.NewMaterializationFileTarget(contract.MaterializationTarget{Path: filepath.Join(t.TempDir(), "values.env"), SurfaceID: contract.Hash([]byte("materialization surface")), Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return MaterializationConfig{Reader: reader, SourcePins: core.AdministrativeSourcePins{FileID: contract.ID{1}, Format: 1, EditableDigest: contract.ID{2}, GeneratedDigest: contract.ID{3}, EditableLength: 1, GeneratedLength: 1, HasGenerated: true}, CheckSource: func(context.Context) error { return nil }, Target: target}
}

func materializationPlainAdmission(t *testing.T, ctx context.Context, c MaterializationConfig, basis, route contract.ID) contract.MaterializationAdmission {
	t.Helper()
	fixture, _ := installedarchive.LoadReader(t, "gcp")
	a := fixture.Archive
	headObject := a.MustObject(t, a.Location.PrefixBeforeHEAD+"/HEAD")
	head, err := format.DecodeHead(headObject.Body)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := format.Key(a.Location.PrefixBeforeHEAD, head.Core.Root)
	if err != nil {
		t.Fatal(err)
	}
	root, err := format.DecodeRoot(a.MustObject(t, rootKey).Body)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	admission := contract.MaterializationAdmission{Purpose: contract.MaterializationOperation, RequestID: contract.Hash([]byte("materialization request")), SessionID: contract.Hash([]byte("materialization session")), DomainID: a.Domain, HEADDigest: contract.Hash(headObject.Body), HEADRevision: head.Core.Revision, SnapshotID: root.Snapshot, AccessRoot: root.CurrentAccess.AccessRoot, CredentialRoute: route, PublicBasisDigest: basis, Store: c.Reader.ExpectedStore, Root: head.Core.Root, HEADToken: headObject.Token, SourcePins: materializationSourcePins(c.SourcePins), Recipient: contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: a.AuthorityID, Binding: a.AuthorityBinding}, Target: c.Target.Target(), ExpiresAt: deadline}
	for _, ref := range root.ValueEntryPages {
		if ref == nil {
			continue
		}
		key, err := format.Key(a.Location.PrefixBeforeHEAD, *ref)
		if err != nil {
			t.Fatal(err)
		}
		page, err := format.DecodeValueEntryPage(a.MustObject(t, key).Body)
		if err != nil {
			t.Fatal(err)
		}
		for slot, entry := range page.Slots {
			if entry != nil && entry.ConfidentialityClass == contract.Plain {
				admission.Entries = []contract.MaterializationEntry{{Name: entry.Name, Slot: uint16(page.Index)*format.PageSlots + uint16(slot), Entry: *entry}}
				return admission
			}
		}
	}
	t.Fatal("plain current fixture unavailable")
	return contract.MaterializationAdmission{}
}

// full_only: false
func TestMaterializationRejectsUnfixedPublicInstallation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	for _, condition := range []string{"valid", "source", "generated", "check", "target", "domain", "Store", "basis", "route", "route-uppercase", "route-zero", "route-legacy", "route-short", "route-invalid", "route-long", "context"} {
		t.Run(condition, func(t *testing.T) {
			c := materializationConfig(t)
			callCtx := ctx
			switch condition {
			case "source":
				c.SourcePins.EditableDigest = contract.ID{}
			case "generated":
				c.SourcePins.HasGenerated = false
				c.SourcePins.GeneratedDigest = contract.ID{}
				c.SourcePins.GeneratedLength = 0
			case "check":
				c.CheckSource = nil
			case "target":
				c.Target = nil
			case "domain":
				c.Reader.ExpectedDomain = contract.ID{}
			case "Store":
				c.Reader.ExpectedStore = contract.Descriptor{}
			case "basis":
				c.Reader.PublicBasis = core.PublicBasis{}
			case "route":
				c.Reader.Candidate.CredentialRoute = ""
			case "route-uppercase":
				c.Reader.Candidate.CredentialRoute = strings.ToUpper(c.Reader.Candidate.CredentialRoute)
			case "route-zero":
				c.Reader.Candidate.CredentialRoute = strings.Repeat("0", 64)
			case "route-legacy":
				c.Reader.Candidate.CredentialRoute = "store-route"
			case "route-short":
				c.Reader.Candidate.CredentialRoute = c.Reader.Candidate.CredentialRoute[:62]
			case "route-invalid":
				c.Reader.Candidate.CredentialRoute = strings.Repeat("z", 64)
			case "route-long":
				c.Reader.Candidate.CredentialRoute += "00"
			case "context":
				callCtx = context.Background()
			}
			engine, err := NewMaterialization(callCtx, c)
			if engine != nil {
				engine.Close()
				engine.Close()
			}
			if condition == "valid" {
				if err != nil || engine == nil {
					t.Fatal("fixed public installation refused", err)
				}
			} else if err == nil || engine != nil {
				t.Fatal("unfixed public installation admitted", condition)
			}
			if condition != "valid" {
				engine, err = NewDefaultMaterialization(callCtx, c)
				if engine != nil {
					engine.Close()
				}
				if err == nil || engine != nil {
					t.Fatal("invalid fixed inputs reached default credential selection", condition)
				}
			}
		})
	}
}

// full_only: false
func TestMaterializationFactoryPinsCapturedTrustBeforePrivateConstruction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	c := materializationConfig(t)
	basis, route, err := materializationFixedConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}

	a := materializationPlainAdmission(t, ctx, c, basis, route)
	unavailable := c
	unavailable.Reader.Candidate.Client = nil
	// A valid plain handoff needs no private provider construction, even when
	// private construction could not succeed with the captured source.
	plain, err := newMaterializationCustody(ctx, unavailable, basis, route, a)
	if err != nil || plain == nil {
		t.Fatal("plain selection required a private route", err)
	}
	plain.Close()
	for _, condition := range []string{"purpose", "source", "basis", "domain", "Store", "route", "target", "subject", "binding", "deadline", "selection"} {
		t.Run(condition, func(t *testing.T) {
			bad := a
			bad.Entries = append([]contract.MaterializationEntry(nil), a.Entries...)
			if condition != "selection" {
				bad.Entries[0].Entry.ConfidentialityClass = contract.Secret
			}
			switch condition {
			case "purpose":
				bad.Purpose = contract.PlanningOperation
			case "source":
				bad.SourcePins.GeneratedDigest = contract.ID{9}
			case "basis":
				bad.PublicBasisDigest = contract.ID{9}
			case "domain":
				bad.DomainID = contract.ID{9}
			case "Store":
				bad.Store.NonBody = contract.ID{9}
			case "route":
				bad.CredentialRoute = contract.ID{9}
			case "target":
				bad.Target.SurfaceID = contract.ID{9}
			case "subject":
				bad.Recipient.SubjectID = contract.ID{}
			case "binding":
				bad.Recipient.Binding.SPKI = nil
			case "deadline":
				bad.ExpiresAt = bad.ExpiresAt.Add(time.Second)
			case "selection":
				bad.Entries[0].Entry.Recipients = nil
			}
			custody, err := newMaterializationCustody(ctx, unavailable, basis, route, bad)
			if custody != nil {
				custody.Close()
			}
			var typed contract.MaterializationAdmissionError
			if custody != nil || !errors.As(err, &typed) || typed.Code != contract.CryptoInvalidAdmission {
				t.Fatal("captured pin mismatch reached private construction or lost typed refusal", condition, err)
			}
		})
	}
}

func materializationTransport(t *testing.T, hosts []string, handler http.Handler) *http.Transport {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: hosts, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
func TestMaterializationPublicSelectionHasNoPrivateFallback(t *testing.T) {
	for _, condition := range []string{"plain-encoding-refusal", "secret-denied", "missing-selection", "unauthorized-selection", "source-refusal", "canceled", "deadline-exceeded"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			fixture, _ := installedarchive.LoadReader(t, "gcp")
			a := fixture.Archive
			key, ok := contract.ParseGCPKeySelector(a.AuthorityBinding.KeySelector, false)
			if !ok {
				t.Fatal("current Recipient selector refused")
			}
			var reads, decrypts, forbidden atomic.Int32
			storageHost, kmsHost := "storage."+a.Location.Region+".rep.googleapis.com", key.Region+"-cloudkms.googleapis.com"
			transport := materializationTransport(t, []string{storageHost, kmsHost}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == storageHost && r.Method == http.MethodGet {
					prefix := "/download/storage/v1/b/" + a.Location.Bucket + "/o/"
					if !strings.HasPrefix(r.URL.Path, prefix) || r.Header.Get("Authorization") != "Bearer local-planning-token" {
						forbidden.Add(1)
						http.Error(w, "refused", http.StatusForbidden)
						return
					}
					object, present := a.Object(strings.TrimPrefix(r.URL.Path, prefix))
					if !present {
						forbidden.Add(1)
						http.NotFound(w, r)
						return
					}
					reads.Add(1)
					w.Header().Set("X-Goog-Generation", object.Token.Value)
					w.Header().Set("Content-Length", strconv.Itoa(len(object.Body)))
					w.Header().Set("Content-Type", "application/octet-stream")
					if _, err := w.Write(object.Body); err != nil {
						t.Error(err)
					}
					return
				}
				if r.Method != http.MethodPost || r.Host != kmsHost || r.URL.Path != "/v1/"+a.AuthorityBinding.KeySelector+":asymmetricDecrypt" || r.Header.Get("Authorization") != "Bearer local-planning-token" {
					forbidden.Add(1)
				}
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
				}
				decrypts.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if _, err := io.WriteString(w, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"private-sentinel"}}`); err != nil {
					t.Error(err)
				}
			}))
			c := materializationConfig(t)
			client, err := provider.NewLocalResponderClient(transport, planningCredentials{})
			if err != nil {
				t.Fatal(err)
			}
			c.Reader.Candidate.Client = client
			if condition == "source-refusal" {
				c.CheckSource = func(context.Context) error { return errors.New("source-sentinel") }
			}
			engine, err := NewMaterialization(ctx, c)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			request := contract.MaterializationRequest{RequestNonce: contract.Hash([]byte("public materialization request")), Names: []string{""}, RecipientID: a.AuthorityID}
			switch condition {
			case "secret-denied":
				request.Names = []string{"secret"}
			case "missing-selection":
				request.Names = []string{"UNSELECTED"}
			case "unauthorized-selection":
				request.RecipientID = contract.Hash([]byte("unadmitted Recipient"))
			case "canceled":
				cancel()
			}
			callCtx := ctx
			if condition == "deadline-exceeded" {
				expired, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer stop()
				callCtx = expired
			}
			result := engine.Materialize(callCtx, request)
			if result.Validate() != nil || forbidden.Load() != 0 {
				t.Fatal("public selection returned unsafe facts or reached another capability", result.StateResult, forbidden.Load())
			}
			wantState, wantReason := contract.MaterializationRefused, contract.MaterializationUnrepresentableValue
			switch condition {
			case "secret-denied":
				wantState, wantReason = contract.MaterializationUnavailable, contract.MaterializationPrivateRouteUnavailable
			case "missing-selection":
				wantReason = contract.MaterializationMissingSelection
			case "unauthorized-selection":
				wantReason = contract.MaterializationUnauthorizedSelection
			case "source-refusal":
				wantReason = contract.MaterializationInvalidRequest
			case "canceled":
				wantState, wantReason = contract.MaterializationUnavailable, contract.MaterializationCanceled
			case "deadline-exceeded":
				wantReason = contract.MaterializationDeadlineExceeded
			}
			if result.StateResult != wantState || result.Failure == nil || result.Failure.Reason != wantReason {
				t.Fatal("wrong safe public refusal", condition, result.StateResult, result.Failure)
			}
			wantDecrypts := int32(0)
			if condition == "secret-denied" {
				wantDecrypts = 1
			}
			if decrypts.Load() != wantDecrypts {
				t.Fatal("selection constructed fallback private work", decrypts.Load())
			}
			if condition == "source-refusal" || condition == "canceled" || condition == "deadline-exceeded" {
				if reads.Load() != 0 {
					t.Fatal("refused invocation read Store")
				}
			} else if reads.Load() == 0 {
				t.Fatal("public selection bypassed Store admission")
			}
			if result.Payload != nil && (result.Payload.Facts.Disclosure != contract.MaterializationDisclosureNone || result.Payload.Facts.Cleanup != contract.MaterializationCandidateNotCreated || result.Payload.Facts.Replacement != contract.MaterializationNotReplaced) {
				t.Fatal("pre-staging failure claimed native effects")
			}
			entries, err := os.ReadDir(filepath.Dir(c.Target.Target().Path))
			if err != nil || len(entries) != 0 {
				t.Fatal("failed public selection created a candidate", err)
			}
			encoded, err := json.Marshal(result)
			if err != nil || strings.Contains(string(encoded), "private-sentinel") || strings.Contains(string(encoded), "source-sentinel") || strings.Contains(string(encoded), "enkv first secret test value") {
				t.Fatal("safe result retained private data")
			}
		})
	}
}
