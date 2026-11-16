package gcp_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/crypto/testsupport/installedarchive"
	"enkv.sh/crypto/testsupport/installedarchive/recovery"
	gcp "enkv.sh/providers/gcp"
)

// full_only: false
func TestRestrictedGCPReconstructionFromConsoleInputs(t *testing.T) {
	if os.Getenv("ENKV_RESTRICTED_RECOVERY") == "1" {
		restrictedGCPReconstructionChild(t)
		return
	}
	if path := os.Getenv("ENKV_RECOVERY_LIVE_PARENT_CONTROL"); path != "" {
		recovery.RunLiveParentControl(t, contract.GCP, t.Name(), path, gcpLiveParentStore, gcpPrivateOracle)
		return
	}
	recovery.RunParentWithPrivateDecrypt(t, contract.GCP, t.Name(), gcpPrivateOracle, recovery.LiveParentConstructors{Store: gcpLiveParentStore})
}

func restrictedGCPReconstructionChild(t *testing.T) {
	input, err := recovery.DecodeRecoveryInput(os.Stdin)
	if err != nil || input.Provider != "gcp" {
		t.Fatal("restricted GCP input", err)
	}
	recovery.CheckRecoveryEnvironment(t)
	var client, normalClient, recoveryClient, privateClient *gcp.Client
	if input.ServiceAccountFile != "" {
		transport, err := recovery.NewGCPReadTransport(input.Bucket, input.Prefix, input.Region, input.NormalSigner, input.RecoverySigner, input.Requests, input.BodyBytes, input.ResponseBytes)
		if err == nil && input.Responder != "" {
			transport.CloseIdleConnections()
			transport, err = recovery.NewGCPResponderReadTransport(input.Bucket, input.Prefix, input.Region, input.NormalSigner, input.RecoverySigner, input.Requests, input.BodyBytes, input.ResponseBytes, input.Responder, input.TLSCertificate)
		}
		if err != nil {
			t.Fatal("restricted GCP transport refused")
		}
		defer transport.CloseIdleConnections()
		defer func() {
			if err := recovery.WriteReadTransportEvidence(input.Output+".calls.json", transport.Evidence()); err != nil {
				t.Error("restricted GCP call evidence refused")
			}
		}()
		makeClient := func(path string) *gcp.Client {
			credentials, err := gcp.LoadReconstructionServiceAccountTestSource(t.Context(), path, transport)
			if err != nil {
				t.Fatal("restricted GCP credentials refused")
			}
			return gcp.NewReconstructionCredentialTestClient(transport, credentials)
		}
		client = makeClient(input.ServiceAccountFile)
		normalClient, recoveryClient, privateClient = client, client, client
		if input.NormalServiceAccountFile != "" {
			normalClient = makeClient(input.NormalServiceAccountFile)
		}
		if input.RecoveryServiceAccountFile != "" {
			recoveryClient = makeClient(input.RecoveryServiceAccountFile)
		}
		if input.PrivateServiceAccountFile != "" {
			privateClient = makeClient(input.PrivateServiceAccountFile)
		}
	} else if len(input.TLSCertificate) != 0 {
		transport, err := recovery.NewGCPResponderReadTransport(input.Bucket, input.Prefix, input.Region, input.NormalSigner, input.RecoverySigner, input.Requests, input.BodyBytes, input.ResponseBytes, input.Responder, input.TLSCertificate)
		if err != nil {
			t.Fatal("restricted synthetic TLS transport refused")
		}
		defer transport.CloseIdleConnections()
		client = gcp.NewReconstructionTransportTestClientWithToken(transport, input.Token)
	} else {
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		client = gcp.NewReconstructionTransportTestClientWithToken(installedRoundTrip(func(request *http.Request) (*http.Response, error) {
			local := request.Clone(request.Context())
			url := *request.URL
			url.Scheme, url.Host = "http", input.Responder
			local.URL, local.Host = &url, request.URL.Host
			return transport.RoundTrip(local)
		}), input.Token)
	}
	if normalClient == nil {
		normalClient, recoveryClient, privateClient = client, client, client
	}
	timeout := time.Duration(input.TimeoutMillis) * time.Millisecond
	var normal, anchorRecovery *gcp.PublicSigningAnchorConfig
	if input.NormalSigner != "" {
		normal = &gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Client: normalClient, Region: input.NormalRegion, KeyVersion: input.NormalSigner, CredentialRoute: input.SignRoute}
	}
	if input.RecoverySigner != "" {
		anchorRecovery = &gcp.PublicSigningAnchorConfig{Role: contract.RecoverySigningRole, Client: recoveryClient, Region: input.RecoveryRegion, KeyVersion: input.RecoverySigner, CredentialRoute: input.SignRoute}
	}
	expectedDomain := contract.ID{}
	if input.ExpectedDomain != nil {
		expectedDomain = *input.ExpectedDomain
	}
	engine, err := compositiongcp.NewReconstruction(t.Context(), compositiongcp.ReconstructionConfig{
		Candidate: gcp.CandidateReadConfig{Client: client, Region: input.Region, Bucket: input.Bucket, Prefix: input.Prefix, CredentialRoute: input.ReadRoute}, Normal: normal, Recovery: anchorRecovery, ExpectedDomain: expectedDomain, ExpectedKEK: input.ExpectedKEK,
		KeyAccess: compositiongcp.ReconstructionKeyAccessConfig{Client: privateClient, CredentialRoute: contract.Hash([]byte(input.PrivateRoute))}})
	if err != nil {
		t.Fatal("restricted GCP construction", err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	projection, result := engine.Reconstruct(ctx)
	if projection == nil {
		if result.Outcome == core.ObservedCurrent || result.Evidence == core.AuthenticatedClosure {
			t.Fatal("refusal carries authenticated content", result)
		}
		if err := recovery.WriteRefusedResult(input.Output, recovery.ObservedResult{Outcome: uint8(result.Outcome), Reason: uint8(result.Reason), Evidence: uint8(result.Evidence)}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if result.Outcome != core.ObservedCurrent || result.Evidence != core.AuthenticatedClosure {
		projection.Close()
		t.Fatal("projection without authenticated success", result)
	}
	defer projection.Close()
	parts := make([]installedarchive.Part, 0, projection.PartCount())
	kinds := map[core.ReconstructionPartKind]string{core.ReconstructionConfigurationPart: "configuration", core.ReconstructionHEADPart: "HEAD", core.ReconstructionRootPart: "root", core.ReconstructionValuePagePart: "value page", core.ReconstructionRecipientPagePart: "recipient page", core.ReconstructionAccessPagePart: "access page", core.ReconstructionIndexPagePart: "index page", core.ReconstructionSupportRowPart: "support row"}
	for i := 0; i < projection.PartCount(); i++ {
		part, ok := projection.CopyPart(i)
		if !ok || kinds[part.Kind] == "" {
			t.Fatal("restricted GCP part missing", i)
		}
		parts = append(parts, installedarchive.Part{Kind: kinds[part.Kind], Ref: part.Ref, PhysicalOrdinal: part.PhysicalOrdinal, SupportKind: part.SupportKind, RecordID: part.RecordID, Body: part.Body})
	}
	provenance, ok := projection.Provenance()
	if !ok {
		t.Fatal("restricted child provenance missing")
	}
	if err := recovery.WriteReturnedParts(input.Output, recovery.Provenance{Domain: provenance.Domain, Revision: provenance.Revision, Snapshot: provenance.Snapshot, HEADDigest: provenance.HEADDigest, HEADToken: provenance.HEADToken}, parts); err != nil {
		t.Fatal("restricted GCP output", err)
	}
}

// full_only: false
func TestConfigurationRecoveryResourceOwner(t *testing.T) {
	input, resources, domain := recovery.ChooseResources(t, contract.GCP)
	var credentials, requests atomic.Uint64
	client := gcp.NewReconstructionSetupTestClient(installedRoundTrip(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("setup network call refused")
	}), "setup-token", &credentials)
	location := input.Location
	store, err := gcp.NewStore(t.Context(), gcp.StoreConfig{Client: client, Domain: domain, Region: location.Region, Endpoint: "https://storage." + location.Region + ".rep.googleapis.com/storage/v1/", Bucket: location.Bucket, Prefix: location.PrefixBeforeHEAD, CredentialRoute: "new-setup-route"})
	if err != nil {
		t.Fatal(err)
	}
	for role, resource := range map[uint8]*installedarchive.SigningResource{contract.NormalSigningRole: &resources.Normal, contract.RecoverySigningRole: &resources.Recovery} {
		trust, err := gcp.NewTrust(t.Context(), gcp.TrustConfig{Role: role, Client: client, Region: resource.Region, Endpoint: "https://" + resource.Region + "-cloudkms.googleapis.com/", CredentialRoute: "new-setup-sign-route", KeyVersion: resource.Selector, Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: resource.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		resource.TrustID = trust.Identity()
	}
	for i := range resources.NormalSuccessors {
		resources.NormalSuccessors[i].TrustID = resources.Normal.TrustID
	}
	for i := range resources.RecoverySuccessors {
		resources.RecoverySuccessors[i].TrustID = resources.Recovery.TrustID
	}
	if credentials.Load() != 0 || requests.Load() != 0 {
		t.Fatal("descriptor construction used I/O", credentials.Load(), requests.Load())
	}
	prior, err := gcp.NewStore(t.Context(), gcp.StoreConfig{Client: client, Domain: resources.PriorDomain, Region: location.Region, Endpoint: "https://storage." + location.Region + ".rep.googleapis.com/storage/v1/", Bucket: location.Bucket, Prefix: location.PrefixBeforeHEAD, CredentialRoute: "new-setup-route"})
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Load() != 0 || requests.Load() != 0 {
		t.Fatal("prior descriptor construction used I/O")
	}
	configuration := store.StoreConfiguration()
	recovery.WriteParentJSON(t, input.Resources, resources)
	recovery.WriteParentJSON(t, input.Setup, installedarchive.RecoverySetup{Domain: domain, Descriptor: store.Descriptor(), Configuration: configuration, PriorDescriptor: prior.Descriptor(), PriorConfiguration: prior.StoreConfiguration()})
}

func gcpPrivateOracle(ctx context.Context, a installedarchive.Archive, input installedarchive.RecoveryInput) (func([]byte) ([]byte, error), func(), error) {
	var client *gcp.Client
	var closeTransport func()
	if input.ServiceAccountFile != "" {
		transport, err := recovery.NewGCPReadTransport(input.Bucket, input.Prefix, input.Region, input.NormalSigner, input.RecoverySigner, input.Requests, input.BodyBytes, input.ResponseBytes)
		if err == nil && input.Responder != "" {
			transport.CloseIdleConnections()
			transport, err = recovery.NewGCPResponderReadTransport(input.Bucket, input.Prefix, input.Region, input.NormalSigner, input.RecoverySigner, input.Requests, input.BodyBytes, input.ResponseBytes, input.Responder, input.TLSCertificate)
		}
		if err != nil {
			return nil, nil, errors.New("private oracle transport refused")
		}
		path := input.PrivateServiceAccountFile
		if path == "" {
			path = input.ServiceAccountFile
		}
		credentials, err := gcp.LoadReconstructionServiceAccountTestSource(ctx, path, transport)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, nil, errors.New("private oracle credentials refused")
		}
		client = gcp.NewReconstructionCredentialTestClient(transport, credentials)
		closeTransport = transport.CloseIdleConnections
	} else if len(input.TLSCertificate) != 0 {
		transport, err := recovery.NewGCPResponderReadTransport(input.Bucket, input.Prefix, input.Region, input.NormalSigner, input.RecoverySigner, input.Requests, input.BodyBytes, input.ResponseBytes, input.Responder, input.TLSCertificate)
		if err != nil {
			return nil, nil, errors.New("private synthetic TLS transport refused")
		}
		client = gcp.NewReconstructionTransportTestClientWithToken(transport, input.Token)
		closeTransport = transport.CloseIdleConnections
	} else {
		transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true}
		client = gcp.NewReconstructionTransportTestClientWithToken(installedRoundTrip(func(request *http.Request) (*http.Response, error) {
			local := request.Clone(request.Context())
			url := *request.URL
			url.Scheme, url.Host = "http", input.Responder
			local.URL, local.Host = &url, request.URL.Host
			return transport.RoundTrip(local)
		}), input.Token)
		closeTransport = transport.CloseIdleConnections
	}
	selector := strings.Split(a.AuthorityBinding.KeySelector, "/")
	if len(selector) != 10 {
		closeTransport()
		return nil, nil, errors.New("private oracle selector refused")
	}
	key, err := gcp.NewKeyAccess(ctx, gcp.KeyAccessConfig{Client: client, Region: selector[3], Project: selector[1], Endpoint: "https://" + selector[3] + "-cloudkms.googleapis.com/", CredentialRoute: contract.Hash([]byte("new-parent-oracle-route"))})
	if err != nil {
		closeTransport()
		return nil, nil, errors.New("private oracle construction refused")
	}
	return func(ciphertext []byte) ([]byte, error) {
		result := key.Decrypt(ctx, a.AuthorityBinding, ciphertext, contract.ValueMaterialPacketLength)
		if result.Status != enkvcrypto.KeyOK {
			clear(result.Packet)
			return nil, errors.New("private oracle decryption refused")
		}
		return result.Packet, nil
	}, closeTransport, nil
}

func gcpLiveParentStore(ctx context.Context, input installedarchive.RecoveryInput, domain contract.ID) (contract.Store, func(), error) {
	transport, err := recovery.GCPResponderTransport(input.Responder, input.TLSCertificate)
	if err != nil {
		return nil, nil, errors.New("parent Store transport refused")
	}
	var client *gcp.Client
	if input.ServiceAccountFile != "" {
		credentials, err := gcp.LoadReconstructionServiceAccountTestSource(ctx, input.ServiceAccountFile, transport)
		if err != nil {
			transport.CloseIdleConnections()
			return nil, nil, errors.New("parent Store credentials refused")
		}
		client = gcp.NewReconstructionCredentialTestClient(transport, credentials)
	} else if input.Token != "" {
		client = gcp.NewReconstructionTransportTestClientWithToken(transport, input.Token)
	} else {
		transport.CloseIdleConnections()
		return nil, nil, errors.New("parent explicit credential source missing")
	}
	store, err := gcp.NewStore(ctx, gcp.StoreConfig{Client: client, Region: input.Region, Bucket: input.Bucket, Prefix: input.Prefix, Domain: domain, CredentialRoute: "parent-snapshot-route", Endpoint: "https://storage." + input.Region + ".rep.googleapis.com/storage/v1/"})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, errors.New("parent Store constructor refused")
	}
	return store, transport.CloseIdleConnections, nil
}

// full_only: false
func TestConfigurationRecoveryLiveParentControl(t *testing.T) {
	path := os.Getenv("ENKV_RECOVERY_LIVE_PARENT_CONTROL")
	if path == "" {
		t.Skip("owned by the joined local configuration-recovery parent control")
	}
	recovery.RunLiveParentControl(t, contract.GCP, "TestRestrictedGCPReconstructionFromConsoleInputs", path, gcpLiveParentStore, gcpPrivateOracle)
}

// full_only: false
func TestConfigurationRecoveryLiveParentInvokesControl(t *testing.T) {
	recovery.RunOrdinaryLiveParentInvocation(t, contract.GCP, "TestConfigurationRecoveryLiveParentControl")
}
