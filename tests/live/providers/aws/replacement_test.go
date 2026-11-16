package core

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/custody"
	awsprovider "enkv.sh/providers/aws"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func openLiveReplacementCustody(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget, bindings []contract.BindingTableRow, routes []custody.Route, roles []string) (*custody.Fixture, error) {
	return openAWSReplacementCustody(t, ctx, input, domain, budget, bindings, routes, roles, awsprovider.LoadSharedCredentialsFile)
}

func openAWSReplacementCustody(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget, bindings []contract.BindingTableRow, routes []custody.Route, roles []string, load func(context.Context, string, string, time.Time) (aws.CredentialsProvider, error)) (*custody.Fixture, error) {
	t.Helper()
	if ctx == nil || ctx.Err() != nil || budget == nil || load == nil || input.Settings.Provider != "aws" {
		return nil, errAWSSetup
	}
	bindings, routes, actors, err := liveReplacementCustodyInputs(input, domain, bindings, routes, roles)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	configs := make([]awsprovider.KeyAccessConfig, len(actors))
	for i, actor := range actors {
		c := actor.Settings
		credentials, err := load(ctx, c.CredentialsFile, c.Profile, c.CredentialExpires)
		if err != nil {
			return nil, err
		}
		configs[i] = awsprovider.KeyAccessConfig{Region: c.Region, Account: c.Account, CredentialRoute: actor.Route, Credentials: credentials, Transport: transport, Timeout: time.Minute}
	}
	adapter, err := awsprovider.NewCrypto(configs)
	if err != nil {
		return nil, err
	}
	recovery := contract.ID{}
	if input.RecoveryMode == "enabled" {
		recovery = fixtureID(domain, "recovery")
	}
	return custody.NewLive(t, adapter, fixtureID(domain, "recipient"), recovery, bindings, routes), nil
}

func openLiveReplacementSigner(ctx context.Context, input liveRunInput, budget *runBudget, role string, binding contract.PublicSigningBinding) (contract.QualifyingTrust, error) {
	return openAWSReplacementSigner(ctx, input, budget, role, binding, awsprovider.LoadSharedCredentialsFile)
}

func openAWSReplacementSigner(ctx context.Context, input liveRunInput, budget *runBudget, role string, binding contract.PublicSigningBinding, load func(context.Context, string, string, time.Time) (aws.CredentialsProvider, error)) (contract.QualifyingTrust, error) {
	if ctx == nil || ctx.Err() != nil || budget == nil || load == nil || input.Settings.Provider != "aws" {
		return nil, errAWSSetup
	}
	actor, err := liveReplacementSignerInput(input, role, binding)
	if err != nil {
		return nil, err
	}
	// Freeze public caller-owned bytes before the selected credential load.
	binding.SPKI = bytes.Clone(binding.SPKI)
	c := actor.Settings
	credentials, err := load(ctx, c.CredentialsFile, c.Profile, c.CredentialExpires)
	if err != nil {
		return nil, err
	}
	trust, err := awsprovider.NewTrust(awsprovider.TrustConfig{Role: binding.Role, Region: c.Region, KeyARN: binding.KeySelector, PublicKeyDER: binding.SPKI, CredentialRoute: actor.Route, Credentials: credentials, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, Timeout: time.Minute})
	if err != nil {
		return nil, err
	}
	if trust.Identity() != binding.Binding.Trust {
		return nil, errAWSSetup
	}
	return budgetTrust{Trust: trust, budget: budget}, nil
}

// full_only: false
func TestLiveAssemblyReplacementCustodySelectedLoads(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		input, domain, bindings := liveReplacementConstructionInput(t, recovery)
		for role := range input.ReplacementSettings {
			t.Run(input.RecoveryMode+"/"+role, func(t *testing.T) {
				calls := 0
				credentials := &liveCustodyCredentials{}
				load := func(_ context.Context, path, profile string, expires time.Time) (aws.CredentialsProvider, error) {
					calls++
					actor := input.ReplacementSettings[role]
					if path != actor.CredentialsFile || profile != actor.Profile || expires != actor.CredentialExpires {
						t.Error("selected credential reference changed")
					}
					return credentials, nil
				}
				routes := liveReplacementConstructionRoutes(input, domain, bindings, role)
				f, err := openAWSReplacementCustody(t, context.Background(), input, domain, &runBudget{}, bindings, routes, []string{role}, load)
				if err != nil || f == nil || calls != 1 || credentials.calls != 0 {
					t.Fatalf("replacement construction failed: err=%v loads=%d provider calls=%d", err, calls, credentials.calls)
				}
			})
		}
	}
}

func liveReplacementProviderTestBinding(t *testing.T, input liveRunInput, role string) contract.PublicSigningBinding {
	b := liveReplacementTestSigningBinding(t, input, role, contract.Hash([]byte("placeholder-trust")))
	c := input.Settings
	trust, err := awsprovider.NewTrust(awsprovider.TrustConfig{Role: b.Role, Region: c.Region, KeyARN: b.KeySelector, PublicKeyDER: b.SPKI, CredentialRoute: liveCredentialRoute(input, role), Credentials: &liveCustodyCredentials{}, Transport: &http.Transport{}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	b.Binding.Trust = trust.Identity()
	return b
}

// full_only: false
func TestLiveAssemblyReplacementSignerConstruction(t *testing.T) {
	input, _, _ := liveReplacementConstructionInput(t, true)
	for _, role := range []string{"normal-signer-0", "normal-signer-1", "normal-signer-2", "recovery-signer-0", "recovery-signer-1"} {
		t.Run(role, func(t *testing.T) {
			binding := liveReplacementProviderTestBinding(t, input, role)
			calls := 0
			credentials := &liveCustodyCredentials{}
			load := func(_ context.Context, path, profile string, expires time.Time) (aws.CredentialsProvider, error) {
				calls++
				if path != input.ReplacementSettings[role].CredentialsFile {
					t.Error("signer loaded another credential route")
				}
				return credentials, nil
			}
			signer, err := openAWSReplacementSigner(context.Background(), input, &runBudget{}, role, binding, load)
			if err != nil || signer == nil || signer.Identity() != binding.Binding.Trust || credentials.calls != 0 {
				t.Fatalf("signer construction err=%v provider calls=%d", err, credentials.calls)
			}
			if calls != 1 {
				t.Fatal("signer did not load exactly its selected reference")
			}
		})
	}
}

// full_only: false
func TestLiveAssemblyReplacementSignerRefusals(t *testing.T) {
	for _, change := range []string{"role", "selector", "public-key", "fingerprint", "provider", "trust", "missing-actor", "load-failure"} {
		t.Run(change, func(t *testing.T) {
			input, _, _ := liveReplacementConstructionInput(t, true)
			role := "recovery-signer-0"
			binding := liveReplacementProviderTestBinding(t, input, role)
			wantLoads := 0
			failure := errors.New("controlled credential load failure")
			switch change {
			case "role":
				binding.Role = contract.NormalSigningRole
			case "selector":
				binding.KeySelector = input.Settings.RecoverySuccessorKeyID
			case "public-key":
				binding.SPKI = []byte("invalid-public-key")
			case "fingerprint":
				binding.Fingerprint = contract.Hash([]byte("another-key"))
			case "provider":
				if binding.Provider == contract.AWS {
					binding.Provider = contract.GCP
				} else {
					binding.Provider = contract.AWS
				}
			case "trust":
				binding.Binding.Trust = contract.Hash([]byte("wrong-trust"))
				wantLoads = 1
			case "missing-actor":
				delete(input.ReplacementSettings, role)
			case "load-failure":
				wantLoads = 1
			}
			calls := 0
			credentials := &liveCustodyCredentials{}
			load := func(_ context.Context, path, profile string, expires time.Time) (aws.CredentialsProvider, error) {
				calls++
				if change == "load-failure" {
					return nil, failure
				}
				return credentials, nil
			}
			signer, err := openAWSReplacementSigner(context.Background(), input, &runBudget{}, role, binding, load)
			if err == nil || signer != nil || calls != wantLoads || credentials.calls != 0 {
				t.Fatalf("signer refusal err=%v loads=%d want=%d provider calls=%d", err, calls, wantLoads, credentials.calls)
			}
			if change == "load-failure" && err != failure {
				t.Fatal("credential load failure was replaced")
			}
		})
	}
}

// full_only: false
func TestLiveAssemblyReplacementCustodyFailureBoundaries(t *testing.T) {
	for _, change := range []string{"wrong-private-key", "unknown-route", "broad-role", "missing-row", "duplicate-role", "load-failure"} {
		t.Run(change, func(t *testing.T) {
			input, domain, bindings := liveReplacementConstructionInput(t, true)
			roles := []string{"authority-decrypter-0", "reader-successor"}
			routes := liveReplacementConstructionRoutes(input, domain, bindings, roles[0])
			wantLoads := 0
			switch change {
			case "wrong-private-key":
				for i, row := range bindings {
					if row.SubjectID == fixtureID(domain, "reader") {
						routes[i].PrivateRoute = liveCredentialRoute(input, roles[0])
					}
				}
			case "unknown-route":
				routes[0].PublicRoute = contract.Hash([]byte("unknown-route"))
			case "broad-role":
				roles[1] = "authority"
			case "missing-row":
				bindings = bindings[:len(bindings)-1]
			case "duplicate-role":
				roles[1] = roles[0]
			case "load-failure":
				wantLoads = 2
			}
			calls := 0
			failure := errors.New("controlled second credential load failure")
			credentials := &liveCustodyCredentials{}
			load := func(_ context.Context, path, profile string, expires time.Time) (aws.CredentialsProvider, error) {
				calls++
				if calls == 2 {
					return nil, failure
				}
				return credentials, nil
			}
			f, err := openAWSReplacementCustody(t, context.Background(), input, domain, &runBudget{}, bindings, routes, roles, load)
			if err == nil || f != nil || calls != wantLoads || credentials.calls != 0 {
				t.Fatalf("custody refusal err=%v loads=%d want=%d provider calls=%d", err, calls, wantLoads, credentials.calls)
			}
			if change == "load-failure" && err != failure {
				t.Fatal("selected credential failure was replaced")
			}
		})
	}
}

// full_only: false
func TestLiveAssemblyReplacementCustodyPendingSuccessor(t *testing.T) {
	for _, successor := range []string{"reader-successor", "authority-decrypter-1", "authority-decrypter-2", "recovery-decrypter-1", "recovery-decrypter-2"} {
		t.Run(successor, func(t *testing.T) {
			input, domain, bindings := liveReplacementConstructionInput(t, true)
			source := "authority-decrypter-0"
			if successor == "authority-decrypter-1" || successor == "authority-decrypter-2" {
				source = "recovery-decrypter-0"
			}
			roles := []string{source, successor}
			routes := liveReplacementConstructionRoutes(input, domain, bindings, source)
			calls := 0
			credentials := &liveCustodyCredentials{}
			load := func(_ context.Context, path, profile string, expires time.Time) (aws.CredentialsProvider, error) {
				if calls >= len(roles) || path != input.ReplacementSettings[roles[calls]].CredentialsFile {
					t.Error("pending construction changed selected load order")
				}
				calls++
				return credentials, nil
			}
			f, err := openAWSReplacementCustody(t, context.Background(), input, domain, &runBudget{}, bindings, routes, roles, load)
			if err != nil || f == nil || calls != 2 || credentials.calls != 0 {
				t.Fatalf("pending construction err=%v loads=%d provider calls=%d", err, calls, credentials.calls)
			}
			kind, label, selector, public := liveReplacementKEK(input.Settings, successor)
			var pending contract.BindingTableRow
			for _, row := range bindings {
				if row.SubjectKind == kind && row.SubjectID == fixtureID(domain, label) {
					pending = row
				}
			}
			pending.Binding.BindingID = fixtureID(domain, "pending-"+successor)
			pending.Binding.BindingSerial++
			pending.Binding.KeySelector = selector
			pending.Binding.SPKI, err = livePublicDER(public)
			if err != nil {
				t.Fatal(err)
			}
			pending.Binding.Fingerprint = contract.Hash(pending.Binding.SPKI)
			route := liveCredentialRoute(input, successor)
			if successor == "reader-successor" {
				err = f.InstallRecipientSuccessor(pending, route, route)
			} else {
				err = f.InstallKEKSuccessor(pending, route, route)
			}
			if err != nil || credentials.calls != 0 {
				t.Fatal("selected pending route unavailable", err)
			}
		})
	}
}

// full_only: false
func TestLiveAssemblyReplacementCustodyOwnsInputsBeforeLoad(t *testing.T) {
	input, domain, bindings := liveReplacementConstructionInput(t, true)
	roles := []string{"authority-decrypter-0"}
	routes := liveReplacementConstructionRoutes(input, domain, bindings, roles[0])
	credentials := &liveCustodyCredentials{}
	load := func(_ context.Context, path, profile string, expires time.Time) (aws.CredentialsProvider, error) {
		bindings[0].Binding.SPKI[0] ^= 1
		routes[0].BindingID = contract.ID{}
		return credentials, nil
	}
	f, err := openAWSReplacementCustody(t, context.Background(), input, domain, &runBudget{}, bindings, routes, roles, load)
	if err != nil || f == nil || credentials.calls != 0 {
		t.Fatal("caller mutation changed the validated custody inputs", err)
	}
}
