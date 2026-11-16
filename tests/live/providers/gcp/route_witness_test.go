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
	"enkv.sh/providers/gcp"
)

func openLiveRouteWitness(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget, target contract.BindingTableRow, wrappedUnder contract.KMSBinding, role string) custody.RouteWitness {
	return openGCPRouteWitness(t, ctx, input, domain, budget, target, wrappedUnder, role, gcp.LoadServiceAccountFile)
}

func openGCPRouteWitness(t testing.TB, ctx context.Context, input liveRunInput, domain contract.ID, budget *runBudget, target contract.BindingTableRow, wrappedUnder contract.KMSBinding, role string, load func(context.Context, string) (gcp.CredentialSource, error)) custody.RouteWitness {
	t.Helper()
	if ctx == nil || input.Settings.Provider != "gcp" || budget == nil || load == nil {
		return custody.RouteWitness{Outcome: contract.CryptoInvalidAdmission}
	}
	if ctx.Err() != nil {
		return custody.RouteWitness{Outcome: contract.CryptoCancelled}
	}
	actors, err := liveReplacementActors(input, []string{role})
	if err != nil {
		return custody.RouteWitness{Outcome: contract.CryptoInvalidAdmission}
	}
	c := actors[0].Settings
	targetRole := livePrivateKeyRole(c, target)
	wrappedRow := contract.BindingTableRow{SubjectKind: 1, Binding: wrappedUnder}
	wrappedRole := livePrivateKeyRole(c, wrappedRow)
	wrappedRow.SubjectKind = 2
	recoveryRole := livePrivateKeyRole(c, wrappedRow)
	if domain.IsZero() || targetRole == "" || !liveReplacementKEKMatches(c, domain, target, targetRole) || wrappedRole == "" && recoveryRole == "" || wrappedRole != "" && recoveryRole != "" || target.Binding.Provider != contract.GCP || wrappedUnder.Provider != contract.GCP || target.Binding.ProtectionClass != contract.SoftwareProtection || wrappedUnder.ProtectionClass != contract.SoftwareProtection {
		return custody.RouteWitness{Outcome: contract.CryptoInvalidInput}
	}
	if _, err := contract.PublicBindingDigest(target.Binding); err != nil {
		return custody.RouteWitness{Outcome: contract.CryptoInvalidInput}
	}
	if _, err := contract.PublicBindingDigest(wrappedUnder); err != nil {
		return custody.RouteWitness{Outcome: contract.CryptoInvalidInput}
	}
	target.Binding.SPKI, wrappedUnder.SPKI = bytes.Clone(target.Binding.SPKI), bytes.Clone(wrappedUnder.SPKI)
	if !budget.reserve(2, operationBodyAllowance, "", 0) {
		return custody.RouteWitness{Outcome: contract.CryptoCapacityExceeded}
	}

	credentials, err := load(ctx, c.CredentialsFile)
	if err != nil {
		return custody.RouteWitness{Outcome: contract.CryptoCustodyUnavailable}
	}
	client, err := gcp.NewClient(&http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}, credentials)
	if err != nil {
		return custody.RouteWitness{Outcome: contract.CryptoCustodyUnavailable}
	}
	adapter, err := gcp.NewCrypto(ctx, []gcp.KeyAccessConfig{{Client: client, Project: c.Project, Region: c.Region, Endpoint: "https://" + c.Region + "-cloudkms.googleapis.com/", CredentialRoute: actors[0].Route}})

	if err != nil {
		return custody.RouteWitness{Outcome: contract.CryptoCustodyUnavailable}
	}
	return custody.PrivateRouteWitness(ctx, adapter, actors[0].Route, target.Binding, wrappedUnder)
}

type routeWitnessCredentials struct{ calls int }

func (c *routeWitnessCredentials) Token(context.Context) (string, error) {
	c.calls++
	return "", errors.New("controlled credential refusal before transport")
}

// full_only: false
func TestLiveAssemblyRouteWitnessConstruction(t *testing.T) {
	for _, choice := range []string{"positive", "wrong-binding", "denied"} {
		t.Run(choice, func(t *testing.T) {
			input, domain, bindings := liveReplacementConstructionInput(t, true)
			var target, recovery contract.BindingTableRow
			for _, row := range bindings {
				if row.SubjectID == fixtureID(domain, "recipient") {
					target = row
				}
				if row.SubjectKind == 2 {
					recovery = row
				}
			}
			wrapped, role := target.Binding, "authority-decrypter-0"
			if choice == "wrong-binding" {
				wrapped = recovery.Binding
			}
			if choice == "denied" {
				role = "recovery-decrypter-0"
			}
			credentials := &routeWitnessCredentials{}
			loads := 0
			load := func(_ context.Context, path string) (gcp.CredentialSource, error) {
				loads++
				if path != input.ReplacementSettings[role].CredentialsFile {
					t.Error("witness loaded another actor")
				}
				return credentials, nil
			}
			budget := &runBudget{limits: liveLimits{Requests: 2, BodyBytes: operationBodyAllowance}}
			got := openGCPRouteWitness(t, context.Background(), input, domain, budget, target, wrapped, role, load)
			// The controlled source stops before HTTP. This proves construction and
			// route selection, not an authenticated provider denial.
			if got != (custody.RouteWitness{Outcome: contract.CryptoPrivateRouteUnavailable}) || loads != 1 || credentials.calls != 1 {
				t.Fatalf("construction witness=%+v loads=%d credential calls=%d", got, loads, credentials.calls)
			}
			if budget.snapshot() != (budgetReservation{Requests: 2, BodyBytes: operationBodyAllowance}) {
				t.Fatal("witness budget reservation differs")
			}
		})
	}
}

// full_only: false
func TestLiveAssemblyRouteWitnessLocalRefusals(t *testing.T) {
	for _, change := range []string{"target-key", "wrapped-key", "subject", "role", "credentials", "budget", "load-failure"} {
		t.Run(change, func(t *testing.T) {
			input, domain, bindings := liveReplacementConstructionInput(t, true)
			var target contract.BindingTableRow
			for _, row := range bindings {
				if row.SubjectID == fixtureID(domain, "recipient") {
					target = row
				}
			}
			wrapped, role := target.Binding, "authority-decrypter-0"
			budget := &runBudget{limits: liveLimits{Requests: 2, BodyBytes: operationBodyAllowance}}
			want := contract.CryptoInvalidInput
			wantLoads := 0
			switch change {
			case "target-key":
				target.Binding.KeySelector = "projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/unconfigured/cryptoKeyVersions/1"
			case "wrapped-key":
				wrapped.KeySelector = "projects/fixture/locations/us-central1/keyRings/fixture/cryptoKeys/unconfigured/cryptoKeyVersions/1"
			case "subject":
				target.SubjectID = contract.Hash([]byte("wrong-subject"))
			case "role":
				role = "authority"
				want = contract.CryptoInvalidAdmission
			case "credentials":
				actor := input.ReplacementSettings[role]
				actor.CredentialsFile = ""
				input.ReplacementSettings[role] = actor
				want = contract.CryptoInvalidAdmission
			case "budget":
				budget.limits.Requests = 1
				want = contract.CryptoCapacityExceeded
			case "load-failure":
				want = contract.CryptoCustodyUnavailable
				wantLoads = 1
			}
			credentials := &routeWitnessCredentials{}
			loads := 0
			load := func(_ context.Context, path string) (gcp.CredentialSource, error) {
				loads++
				if change == "load-failure" {
					return nil, errors.New("controlled credential load failure")
				}
				return credentials, nil
			}
			got := openGCPRouteWitness(t, context.Background(), input, domain, budget, target, wrapped, role, load)
			if got != (custody.RouteWitness{Outcome: want}) || loads != wantLoads || credentials.calls != 0 {
				t.Fatalf("local witness=%+v want=%v loads=%d want=%d credential calls=%d", got, want, loads, wantLoads, credentials.calls)
			}
		})
	}
}
