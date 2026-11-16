package compositionaws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestPlanningUsesOnlyCurrentAuthorityDecryptRoute(t *testing.T) {
	reader := readerConfig(t)
	control, err := reader.PublicBasis.ControlCore(reader.ExpectedDomain, reader.ExpectedStore)
	if err != nil {
		t.Fatal(err)
	}
	binding := control.AuthorityKMSBinding
	key, ok := contract.ParseAWSKeySelector(binding.KeySelector, false)
	if !ok {
		t.Fatal("fixture Authority selector refused")
	}
	var decrypts, forbidden int
	transport := localReconstructionTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
		var request struct{ KeyId, EncryptionAlgorithm string }
		if err != nil || json.Unmarshal(body, &request) != nil || r.Method != http.MethodPost ||
			r.Host != "kms."+key.Region+".amazonaws.com" || r.Header.Get("X-Amz-Target") != "TrentService.Decrypt" ||
			!strings.Contains(r.Header.Get("Authorization"), "/"+key.Region+"/kms/aws4_request") ||
			request.KeyId != binding.KeySelector || request.EncryptionAlgorithm != "RSAES_OAEP_SHA_256" {
			forbidden++
		}
		decrypts++
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusForbidden)
		if _, err := io.WriteString(w, `{"__type":"AccessDeniedException","message":"private-sentinel"}`); err != nil {
			t.Error(err)
		}
	}))
	credentials := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "local-access", SecretAccessKey: "local-secret"}, nil
	})
	installed := awsprovider.KeyAccessConfig{Region: key.Region, Account: key.Account, CredentialRoute: contract.Hash([]byte("planning Authority route")), Credentials: credentials, Transport: transport, Timeout: time.Second * 10}
	source := contract.PlanningSourcePair{FileIdentity: contract.Hash([]byte("file")), EditableDigest: contract.Hash([]byte("editable")), GeneratedDigest: contract.Hash([]byte("generated")), EditableLength: 1, GeneratedLength: 1}
	config := PlanningConfig{Reader: reader, KeyAccess: installed, Sources: contract.PlanningSources{Trusted: source, Proposed: source}, FileIdentity: source.FileIdentity, InputDigest: contract.Hash([]byte("inputs"))}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	engine, err := NewPlanning(ctx, config)
	if err != nil || engine == nil {
		t.Fatal("fixed planning installation refused", err)
	}
	engine.Close()
	if decrypts != 0 || forbidden != 0 {
		t.Fatal("installation used a private resource")
	}
	for _, condition := range []string{"account", "region", "route", "source", "inputs", "context"} {
		t.Run(condition, func(t *testing.T) {
			bad, callCtx := config, ctx
			switch condition {
			case "account":
				bad.KeyAccess.Account = "999999999999"
			case "region":
				bad.KeyAccess.Region = "us-invalid-1"
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
	access, err := awsprovider.NewKeyAccess(installed)
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
		HEADToken: contract.Token{Family: contract.AWS, Value: `"planning-token"`}, Sources: config.Sources, Control: control,
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
	unavailable.Timeout = 0
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
			q.Authority.Binding.Provider = contract.GCP
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
