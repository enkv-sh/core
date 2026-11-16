package compositionaws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	"enkv.sh/crypto/testsupport/installedarchive"
	"enkv.sh/crypto/testsupport/installedarchive/recovery"
	awsprovider "enkv.sh/providers/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// full_only: false
func TestRestrictedAWSReconstructionFromConsoleInputs(t *testing.T) {
	if os.Getenv("ENKV_RESTRICTED_RECOVERY") == "1" {
		restrictedAWSReconstructionChild(t)
		return
	}
	if path := os.Getenv("ENKV_RECOVERY_LIVE_PARENT_CONTROL"); path != "" {
		recovery.RunLiveParentControl(t, contract.AWS, t.Name(), path, awsLiveParentStore, awsPrivateOracle)
		return
	}
	recovery.RunParentWithPrivateDecrypt(t, contract.AWS, t.Name(), awsPrivateOracle, recovery.LiveParentConstructors{Store: awsLiveParentStore, Credentials: awsLiveWorkingCredentials})
}

func restrictedAWSReconstructionChild(t *testing.T) {
	input, err := recovery.DecodeRecoveryInput(os.Stdin)
	if err != nil || input.Provider != "aws" {
		t.Fatal("restricted AWS input", err)
	}
	recovery.CheckRecoveryEnvironment(t)
	certificate, err := x509.ParseCertificate(input.TLSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", input.Responder)
	}}
	defer transport.CloseIdleConnections()
	credentials := reconstructionCredentials(input.AccessKey, input.SecretKey, input.SessionToken)
	normalCredentials, recoveryCredentials, privateCredentials := credentials, credentials, credentials
	if input.NormalAccessKey != "" {
		normalCredentials = reconstructionCredentials(input.NormalAccessKey, input.NormalSecretKey, input.NormalSessionToken)
	}
	if input.RecoveryAccessKey != "" {
		recoveryCredentials = reconstructionCredentials(input.RecoveryAccessKey, input.RecoverySecretKey, input.RecoverySessionToken)
	}
	if input.PrivateAccessKey != "" {
		privateCredentials = reconstructionCredentials(input.PrivateAccessKey, input.PrivateSecretKey, input.PrivateSessionToken)
	}
	timeout := time.Duration(input.TimeoutMillis) * time.Millisecond
	var normal, anchorRecovery *awsprovider.PublicSigningAnchorConfig
	if input.NormalSigner != "" {
		normal = &awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Region: input.NormalRegion, KeyARN: input.NormalSigner, CredentialRoute: contract.Hash([]byte(input.SignRoute)), Credentials: normalCredentials, Transport: transport, Timeout: timeout}
	}
	if input.RecoverySigner != "" {
		anchorRecovery = &awsprovider.PublicSigningAnchorConfig{Role: contract.RecoverySigningRole, Region: input.RecoveryRegion, KeyARN: input.RecoverySigner, CredentialRoute: contract.Hash([]byte(input.SignRoute)), Credentials: recoveryCredentials, Transport: transport, Timeout: timeout}
	}
	expectedDomain := contract.ID{}
	if input.ExpectedDomain != nil {
		expectedDomain = *input.ExpectedDomain
	}
	engine, err := NewReconstruction(ReconstructionConfig{Candidate: awsprovider.CandidateReadConfig{Region: input.Region, Bucket: input.Bucket, Prefix: input.Prefix, ExpectedBucketOwner: input.Owner, CredentialRoute: contract.Hash([]byte(input.ReadRoute)), Credentials: credentials, Transport: transport, Timeout: timeout}, Normal: normal, Recovery: anchorRecovery, ExpectedDomain: expectedDomain, ExpectedKEK: input.ExpectedKEK,
		KeyAccess: ReconstructionKeyAccessConfig{CredentialRoute: contract.Hash([]byte(input.PrivateRoute)), Credentials: privateCredentials, Transport: transport, Timeout: timeout}})
	if err != nil {
		t.Fatal("restricted AWS construction", err)
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
			t.Fatal("restricted AWS part missing", i)
		}
		parts = append(parts, installedarchive.Part{Kind: kinds[part.Kind], Ref: part.Ref, PhysicalOrdinal: part.PhysicalOrdinal, SupportKind: part.SupportKind, RecordID: part.RecordID, Body: part.Body})
	}
	provenance, ok := projection.Provenance()
	if !ok {
		t.Fatal("restricted child provenance missing")
	}
	if err := recovery.WriteReturnedParts(input.Output, recovery.Provenance{Domain: provenance.Domain, Revision: provenance.Revision, Snapshot: provenance.Snapshot, HEADDigest: provenance.HEADDigest, HEADToken: provenance.HEADToken}, parts); err != nil {
		t.Fatal("restricted AWS output", err)
	}
}

// full_only: false
func TestConfigurationRecoveryResourceOwner(t *testing.T) {
	input, resources, domain := recovery.ChooseResources(t, contract.AWS)
	var credentials, requests atomic.Uint64
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		requests.Add(1)
		return nil, errors.New("setup network call refused")
	}}
	defer transport.CloseIdleConnections()
	creds := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		credentials.Add(1)
		return aws.Credentials{}, errors.New("setup credential call refused")
	})
	location := input.Location
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: location.Region, Bucket: location.Bucket, Prefix: location.PrefixBeforeHEAD, ExpectedBucketOwner: location.ExpectedOwner, Domain: domain, CredentialRoute: contract.Hash([]byte("new-setup-route")), Credentials: creds, Transport: transport, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for role, resource := range map[uint8]*installedarchive.SigningResource{contract.NormalSigningRole: &resources.Normal, contract.RecoverySigningRole: &resources.Recovery} {
		trust, err := awsprovider.NewTrust(awsprovider.TrustConfig{Role: role, Region: resource.Region, KeyARN: resource.Selector, PublicKeyDER: resource.PublicKey, CredentialRoute: contract.Hash([]byte("new-setup-sign-route")), Credentials: creds, Transport: transport, Timeout: time.Second})
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
	prior, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: location.Region, Bucket: location.Bucket, Prefix: location.PrefixBeforeHEAD, ExpectedBucketOwner: location.ExpectedOwner, Domain: resources.PriorDomain, CredentialRoute: contract.Hash([]byte("new-setup-route")), Credentials: creds, Transport: transport, Timeout: time.Second})
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

func awsPrivateOracle(ctx context.Context, a installedarchive.Archive, input installedarchive.RecoveryInput) (func([]byte) ([]byte, error), func(), error) {
	certificate, err := x509.ParseCertificate(input.TLSCertificate)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", input.Responder)
	}}
	access, secret, session := input.PrivateAccessKey, input.PrivateSecretKey, input.PrivateSessionToken
	if access == "" {
		access, secret, session = input.AccessKey, input.SecretKey, input.SessionToken
	}
	credentials := reconstructionCredentials(access, secret, session)
	selector := strings.Split(a.AuthorityBinding.KeySelector, ":")
	if len(selector) != 6 {
		transport.CloseIdleConnections()
		return nil, nil, errors.New("private oracle selector refused")
	}
	key, err := awsprovider.NewKeyAccess(awsprovider.KeyAccessConfig{Region: selector[3], Account: selector[4], CredentialRoute: contract.Hash([]byte("new-parent-oracle-route")), Credentials: credentials, Transport: transport, Timeout: time.Duration(input.TimeoutMillis) * time.Millisecond})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, errors.New("private oracle construction refused")
	}
	return func(ciphertext []byte) ([]byte, error) {
		result := key.Decrypt(ctx, a.AuthorityBinding, ciphertext, contract.ValueMaterialPacketLength)
		if result.Status != enkvcrypto.KeyOK {
			clear(result.Packet)
			return nil, errors.New("private oracle decryption refused")
		}
		return result.Packet, nil
	}, transport.CloseIdleConnections, nil
}

func reconstructionCredentials(access, secret, session string) aws.CredentialsProvider {
	return aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: session, Source: "explicit-recovery-input"}, nil
	})
}

func awsLiveParentStore(ctx context.Context, input installedarchive.RecoveryInput, domain contract.ID) (contract.Store, func(), error) {
	certificate, err := x509.ParseCertificate(input.TLSCertificate)
	if err != nil {
		return nil, nil, errors.New("parent Store transport refused")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true, DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", input.Responder)
	}}
	store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: input.Region, Bucket: input.Bucket, Prefix: input.Prefix, ExpectedBucketOwner: input.Owner, Domain: domain, CredentialRoute: contract.Hash([]byte("parent-snapshot-route")), Credentials: reconstructionCredentials(input.AccessKey, input.SecretKey, input.SessionToken), Transport: transport, Timeout: time.Duration(input.TimeoutMillis) * time.Millisecond})
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
	recovery.RunLiveParentControl(t, contract.AWS, "TestRestrictedAWSReconstructionFromConsoleInputs", path, awsLiveParentStore, awsPrivateOracle)
}

func awsLiveWorkingCredentials(ctx context.Context, owner *installedarchive.LiveRecoveryParentInput) error {
	routes := []struct {
		file                    installedarchive.LiveCredentialFile
		access, secret, session *string
	}{
		{owner.Credentials.Read, &owner.Input.AccessKey, &owner.Input.SecretKey, &owner.Input.SessionToken},
		{owner.Credentials.Normal, &owner.Input.NormalAccessKey, &owner.Input.NormalSecretKey, &owner.Input.NormalSessionToken},
		{owner.Credentials.Recovery, &owner.Input.RecoveryAccessKey, &owner.Input.RecoverySecretKey, &owner.Input.RecoverySessionToken},
		{owner.Credentials.Private, &owner.Input.PrivateAccessKey, &owner.Input.PrivateSecretKey, &owner.Input.PrivateSessionToken},
	}
	for _, route := range routes {
		if route.file.Path == "" {
			continue
		}
		source, err := awsprovider.LoadSharedCredentialsFile(ctx, route.file.Path, route.file.Profile, route.file.Expires)
		if err != nil {
			return errors.New("explicit AWS source refused")
		}
		value, err := source.Retrieve(ctx)
		if err != nil {
			return errors.New("explicit AWS material refused")
		}
		*route.access, *route.secret, *route.session = value.AccessKeyID, value.SecretAccessKey, value.SessionToken
	}
	return nil
}

// full_only: false
func TestConfigurationRecoveryLiveParentInvokesControl(t *testing.T) {
	recovery.RunOrdinaryLiveParentInvocation(t, contract.AWS, "TestConfigurationRecoveryLiveParentControl")
}
