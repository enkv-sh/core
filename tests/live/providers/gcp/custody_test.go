package core

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/custody"
	testtrust "enkv.sh/crypto/testsupport/trust"
	"enkv.sh/providers/gcp"
)

func openLiveCustody(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget) (*custody.Fixture, contract.QualifyingTrust, error) {
	return openGCPCustody(t, ctx, input, domain, budget, "authority", true, gcp.LoadServiceAccountFile)
}

func openLiveReaderCustody(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget, role string) (*custody.Fixture, contract.QualifyingTrust, error) {
	if len(input.Scenarios) != 1 {
		return nil, nil, errGCPSetup
	}
	if definition, known := catalog.DefinitionFor(input.Scenarios[0]); !known || !slices.Contains(definition.Roles, role) {
		return nil, nil, errGCPSetup
	}
	return openGCPCustody(t, ctx, input, domain, budget, role, false, gcp.LoadServiceAccountFile)
}

func openGCPCustody(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget, role string, initialize bool, load func(context.Context, string) (gcp.CredentialSource, error)) (*custody.Fixture, contract.QualifyingTrust, error) {
	t.Helper()
	if ctx == nil || ctx.Err() != nil || input.RunID == "" || input.Settings.Provider != "gcp" || !liveRecoveryAdmitted(input) || initialize && role != "authority" || role != "authority" && role != "reader" && role != "denied-reader" {
		return nil, nil, errGCPSetup
	}
	actor := liveRoleSettings(input, role)
	if actor == nil || actor.CredentialsFile == "" || settingsBinding(*actor) != settingsBinding(input.Settings) || liveCredentialRoute(input, role).IsZero() {
		return nil, nil, errGCPSetup
	}
	bindings, err := liveCustodyBindings(input.Settings, domain)
	if err != nil {
		return nil, nil, err
	}
	recoveryID := contract.ID{}
	if input.RecoveryMode == "enabled" {
		recoveryID = fixtureID(domain, "recovery")
		if initialize && (input.RecoverySettings == nil || input.RecoverySettings.CredentialsFile == "" || settingsBinding(*input.RecoverySettings) != settingsBinding(input.Settings) || liveCredentialRoute(input, "recovery").IsZero()) {
			return nil, nil, errGCPSetup
		}
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	loadConfig := func(actor string) (gcp.KeyAccessConfig, error) {
		c := liveRoleSettings(input, actor)
		credentials, err := load(ctx, c.CredentialsFile)
		if err != nil {
			return gcp.KeyAccessConfig{}, err
		}
		client, err := gcp.NewClient(transport, credentials)
		if err != nil {
			return gcp.KeyAccessConfig{}, err
		}
		return gcp.KeyAccessConfig{Client: client, Project: c.Project, Region: c.Region, Endpoint: "https://" + c.Region + "-cloudkms.googleapis.com/", CredentialRoute: liveCredentialRoute(input, actor)}, nil
	}
	selected, err := loadConfig(role)
	if err != nil {
		return nil, nil, err
	}
	configs := []gcp.KeyAccessConfig{selected}
	var recovery contract.QualifyingTrust
	if initialize && !recoveryID.IsZero() {
		recoveryConfig, err := loadConfig("recovery")
		if err != nil {
			return nil, nil, err
		}
		c := input.Settings
		public, err := livePublicDER(c.RecoveryPublicKeyPEM)
		if err != nil {
			return nil, nil, err
		}
		trust, err := gcp.NewTrust(ctx, gcp.TrustConfig{Role: contract.RecoverySigningRole, Client: recoveryConfig.Client, Region: c.Region, Endpoint: recoveryConfig.Endpoint, CredentialRoute: fmt.Sprintf("%x", recoveryConfig.CredentialRoute), KeyVersion: c.RecoveryKeyID, Algorithm: "EC_SIGN_P256_SHA256", Purpose: "ASYMMETRIC_SIGN", PublicKey: public})
		if err != nil {
			return nil, nil, err
		}
		recovery = budgetTrust{Trust: trust, budget: budget}
		configs = append(configs, recoveryConfig)
	}
	adapter, err := gcp.NewCrypto(ctx, configs)
	if err != nil {
		return nil, nil, err
	}
	routes := liveCustodyRoutes(input, domain, bindings, role, initialize)
	return custody.NewLive(t, adapter, fixtureID(domain, "recipient"), recoveryID, bindings, routes), recovery, nil
}

type liveCustodyCredentials struct{ calls int }

func (c *liveCustodyCredentials) Token(context.Context) (string, error) {
	c.calls++
	return "", errors.New("construction must not retrieve credentials")
}

func liveCustodyConstructionInput(t *testing.T, recovery bool) (liveRunInput, contract.ID) {
	t.Helper()
	t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
	domain := contract.Hash([]byte("live-custody-construction"))
	authority, reader := fixtureID(domain, "recipient"), fixtureID(domain, "reader")
	keys := custody.New(t, contract.GCP, domain, recovery, []contract.ID{authority, reader})
	signer := testtrust.New(t, contract.GCP, contract.Hash([]byte("normal-live-signer")))
	publicPEM := func(der []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})) }
	c := liveSettings{Provider: "gcp", Project: "fixture", Region: "us-central1", RecoveryMode: "disabled", KeyID: signer.KeySelector(), PublicKeyPEM: publicPEM(signer.PublicKey()), CredentialsFile: "/fixture/authority", Profile: "authority"}
	for _, row := range keys.Bindings() {
		switch {
		case row.SubjectKind == 2:
			c.RecoveryKEKID, c.RecoveryKEKPublicKeyPEM = row.Binding.KeySelector, publicPEM(row.Binding.SPKI)
		case row.SubjectID == authority:
			c.AuthorityKEKID, c.AuthorityKEKPublicKeyPEM = row.Binding.KeySelector, publicPEM(row.Binding.SPKI)
		case row.SubjectID == reader:
			c.ReaderKEKID, c.ReaderKEKPublicKeyPEM = row.Binding.KeySelector, publicPEM(row.Binding.SPKI)
		}
	}
	if recovery {
		signer := testtrust.NewRecovery(t, contract.GCP, contract.Hash([]byte("recovery-live-signer")))
		c.RecoveryMode = "enabled"
		c.RecoveryKeyID, c.RecoveryPublicKeyPEM = signer.KeySelector(), publicPEM(signer.PublicKey())
	}
	input := liveRunInput{Settings: c, RecoveryMode: c.RecoveryMode, RunID: "live-custody-construction", Participants: map[string]string{"authority": "operator", "reader": "reader", "denied-reader": "denied-reader"}}
	readerSettings, deniedSettings := c, c
	readerSettings.CredentialsFile, readerSettings.Profile = "/fixture/reader", "reader"
	deniedSettings.CredentialsFile, deniedSettings.Profile = "/fixture/denied-reader", "denied-reader"
	input.ReaderSettings, input.DeniedReaderSettings = &readerSettings, &deniedSettings
	if recovery {
		recoverySettings := c
		recoverySettings.CredentialsFile, recoverySettings.Profile = "/fixture/recovery", "recovery"
		input.RecoverySettings = &recoverySettings
		input.Participants["recovery"] = "recovery"
	}
	return input, domain
}

// full_only: false
func TestLiveAssemblyCustodyConstructionRefusesUnknownReaderScenario(t *testing.T) {
	input, domain := liveCustodyConstructionInput(t, false)
	input.Scenarios = []string{"unknown-scenario"}
	fixture, signer, err := openLiveReaderCustody(t, context.Background(), input, domain, &runBudget{}, "authority")
	if err != errGCPSetup || fixture != nil || signer != nil {
		t.Fatal("unknown reader scenario selected a credential route")
	}
}

// full_only: false
func TestLiveAssemblyCustodyConstructionLoadsOnlySelectedCredentials(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, tc := range []struct {
			role       string
			initialize bool
		}{
			{"authority", true}, {"authority", false}, {"reader", false}, {"denied-reader", false},
		} {
			mode := "disabled"
			if recovery {
				mode = "enabled"
			}
			label := tc.role + "-fresh"
			if tc.initialize {
				label = "initializer"
			}
			t.Run(mode+"/"+label, func(t *testing.T) {
				input, domain := liveCustodyConstructionInput(t, recovery)
				if !tc.initialize {
					input.RecoverySettings = nil
					if tc.role != "authority" {
						input.Settings.CredentialsFile = ""
					}
				}
				want := []string{"/fixture/" + tc.role}
				if recovery && tc.initialize {
					want = append(want, "/fixture/recovery")
				}
				var paths []string
				credentials := &liveCustodyCredentials{}
				load := func(_ context.Context, path string) (gcp.CredentialSource, error) {
					paths = append(paths, path)
					return credentials, nil
				}
				budget := &runBudget{keys: make(map[string]bool)}
				fixture, signer, err := openGCPCustody(t, context.Background(), input, domain, budget, tc.role, tc.initialize, load)
				if err != nil || fixture == nil || (signer != nil) != (recovery && tc.initialize) {
					t.Fatalf("custody construction failed: %v", err)
				}
				if !reflect.DeepEqual(paths, want) || credentials.calls != 0 {
					t.Fatalf("credential loads=%v want=%v; provider credential calls=%d", paths, want, credentials.calls)
				}
				if fixture.Crypto().InstanceID().IsZero() || fixture.RecoveryID().IsZero() == recovery {
					t.Fatal("custody omitted the exact runtime or recovery mode")
				}
				q := contract.CryptoRequest{Schema: contract.CryptoSchema, Kind: contract.CryptoCompare, RequestID: contract.Hash([]byte("request")), CustodyInstanceID: fixture.Crypto().InstanceID()}
				if fixture.Crypto().Exchange(context.Background(), q).ResultCode != contract.CryptoInvalidAdmission || credentials.calls != 0 {
					t.Fatal("construction granted private admission or called the provider")
				}
			})
		}
	}
}

// full_only: false
func TestLiveAssemblyCustodyConstructionPreservesCredentialFailure(t *testing.T) {
	for _, failedRole := range []string{"authority", "recovery"} {
		t.Run(failedRole, func(t *testing.T) {
			input, domain := liveCustodyConstructionInput(t, true)
			want := []string{"/fixture/authority"}
			if failedRole == "recovery" {
				want = append(want, "/fixture/recovery")
			}
			var paths []string
			failure := errors.New("controlled credential failure")
			load := func(_ context.Context, path string) (gcp.CredentialSource, error) {
				paths = append(paths, path)
				if path == "/fixture/"+failedRole {
					return nil, failure
				}
				return &liveCustodyCredentials{}, nil
			}
			fixture, signer, err := openGCPCustody(t, context.Background(), input, domain, &runBudget{}, "authority", true, load)
			if err != failure || fixture != nil || signer != nil || !reflect.DeepEqual(paths, want) {
				t.Fatalf("credential failure changed route or result: error=%v paths=%v", err, paths)
			}
		})
	}
}

// full_only: false
func TestLiveAssemblyCustodyConstructionRefusesIncompleteAdmissionBeforeLoading(t *testing.T) {
	for _, change := range []string{"missing-authority", "missing-recovery", "recovery-resource-mismatch", "bad-public-key", "unknown-role"} {
		t.Run(change, func(t *testing.T) {
			input, domain := liveCustodyConstructionInput(t, true)
			role := "authority"
			switch change {
			case "missing-authority":
				delete(input.Participants, "authority")
			case "missing-recovery":
				input.RecoverySettings = nil
			case "recovery-resource-mismatch":
				input.RecoverySettings.Region = "other-region"
			case "bad-public-key":
				input.Settings.ReaderKEKPublicKeyPEM = "invalid"
			case "unknown-role":
				role = "unknown"
			}
			calls := 0
			load := func(_ context.Context, path string) (gcp.CredentialSource, error) {
				calls++
				return &liveCustodyCredentials{}, nil
			}
			fixture, signer, err := openGCPCustody(t, context.Background(), input, domain, &runBudget{}, role, true, load)
			if err == nil || fixture != nil || signer != nil || calls != 0 {
				t.Fatalf("incomplete admission accepted or loaded credentials: error=%v calls=%d", err, calls)
			}
		})
	}
}
