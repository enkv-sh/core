package compositionaws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	"github.com/aws/aws-sdk-go-v2/aws"
)

func materializationConfig(t *testing.T) MaterializationConfig {
	t.Helper()
	reader := readerConfig(t)
	reader.Validator = nil
	target, err := privatecrypto.NewMaterializationFileTarget(contract.MaterializationTarget{Path: filepath.Join(t.TempDir(), "values.env"), SurfaceID: contract.Hash([]byte("materialization surface")), Format: contract.MaterializationDotenvFormat, NativeProfile: contract.MaterializationNativeFileProfile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return MaterializationConfig{Reader: reader, SourcePins: core.AdministrativeSourcePins{FileID: contract.ID{1}, Format: 1, EditableDigest: contract.ID{2}, GeneratedDigest: contract.ID{3}, EditableLength: 1, GeneratedLength: 1, HasGenerated: true}, CheckSource: func(context.Context) error { return nil }, Target: target}
}

// full_only: false
func TestMaterializationPublicSelectionHasNoPrivateFallback(t *testing.T) {
	for _, condition := range []string{"plain-encoding-refusal", "secret-denied", "missing-selection", "unauthorized-selection", "source-refusal", "canceled", "deadline-exceeded"} {
		t.Run(condition, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			fixture, _ := installedarchive.LoadReader(t, "aws")
			a := fixture.Archive
			key, ok := contract.ParseAWSKeySelector(a.AuthorityBinding.KeySelector, false)
			if !ok {
				t.Fatal("current Recipient selector refused")
			}
			var reads, decrypts, forbidden atomic.Int32
			transport := localReconstructionTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host == "s3."+a.Location.Region+".amazonaws.com" && r.Method == http.MethodGet {
					prefix := "/" + a.Location.Bucket + "/"
					if !strings.HasPrefix(r.URL.Path, prefix) || r.Header.Get("X-Amz-Expected-Bucket-Owner") != a.Location.ExpectedOwner || r.Header.Get("Authorization") == "" {
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
					w.Header().Set("ETag", object.Token.Value)
					w.Header().Set("Content-Length", strconv.Itoa(len(object.Body)))
					w.Header().Set("Content-Type", "application/octet-stream")
					if _, err := w.Write(object.Body); err != nil {
						t.Error(err)
					}
					return
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
				var request struct{ KeyId, EncryptionAlgorithm string }
				if err != nil || json.Unmarshal(body, &request) != nil || r.Method != http.MethodPost || r.Host != "kms."+key.Region+".amazonaws.com" || r.Header.Get("X-Amz-Target") != "TrentService.Decrypt" || request.KeyId != a.AuthorityBinding.KeySelector || request.EncryptionAlgorithm != "RSAES_OAEP_SHA_256" || !strings.Contains(r.Header.Get("Authorization"), "/"+key.Region+"/kms/aws4_request") {
					forbidden.Add(1)
				}
				decrypts.Add(1)
				w.Header().Set("Content-Type", "application/x-amz-json-1.1")
				w.WriteHeader(http.StatusForbidden)
				if _, err := io.WriteString(w, `{"__type":"AccessDeniedException","message":"private-sentinel"}`); err != nil {
					t.Error(err)
				}
			}))
			c := materializationConfig(t)
			c.Reader.Candidate.Transport = transport
			c.Reader.Candidate.Credentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "local-access", SecretAccessKey: "local-secret"}, nil
			})
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

func materializationPlainAdmission(t *testing.T, ctx context.Context, c MaterializationConfig, basis, route contract.ID) contract.MaterializationAdmission {
	t.Helper()
	fixture, _ := installedarchive.LoadReader(t, "aws")
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
	for _, condition := range []string{"valid", "source", "generated", "check", "target", "domain", "Store", "basis", "route", "context"} {
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
				c.Reader.Candidate.CredentialRoute = contract.ID{}
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
	basis, err := materializationFixedConfig(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	route := c.Reader.Candidate.CredentialRoute
	a := materializationPlainAdmission(t, ctx, c, basis, route)
	unavailable := c
	unavailable.Reader.Candidate.Credentials = nil
	// A valid plain handoff needs no private provider construction, even when
	// private construction could not succeed with the captured source.
	plain, err := newMaterializationCustody(ctx, unavailable, basis, a)
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
			custody, err := newMaterializationCustody(ctx, unavailable, basis, bad)
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
