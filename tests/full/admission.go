package compositionfull

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	gcpprovider "enkv.sh/providers/gcp"
)

// AbandonAdministrativeLocalFixture changes only native provider construction.
// It is assembled only by the existing local-test source overlay.
func AbandonAdministrativeLocalFixture(ctx context.Context, nonce contract.ID, path string, format configuration.Format, request AbandonmentRequest, transport *http.Transport) AbandonmentResult {
	return abandonConfigurationFile(ctx, nonce, path, format, request, func(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool) (abandonmentResources, error) {
		return nativeAbandonmentResources(ctx, m, s, mutation, transport, func(ctx context.Context, m *configuration.Model, s abandonmentSource, mutation bool, transport *http.Transport, out abandonmentResources) (abandonmentResources, error) {
			if m.Provider == contract.GCP {
				return openGCPNativeAbandonmentResources(ctx, m, s, mutation, transport, out, gcpprovider.NewLocalResponderClient)
			}
			return openNativeAbandonmentResources(ctx, m, s, mutation, transport, out)
		})
	}, nativeAbandonPlanIO())
}

// WriteAdministrativeFixtureSource writes public configuration inputs, not an
// admission grant. Their basis is verified by the production source adapter.
func WriteAdministrativeFixtureSource(t testing.TB, fixture installedarchive.AdministrativeFixture, directory string) string {
	t.Helper()
	var basis struct {
		Descriptor []byte `json:"descriptor"`
	}
	if json.Unmarshal(fixture.Basis, &basis) != nil {
		t.Fatal("fixture public basis unavailable")
	}
	d, err := contract.DecodeGenesisDescriptorCore(basis.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	key := func(k contract.KMSBinding) map[string]any {
		protection := "software"
		if k.ProtectionClass == contract.HardwareProtection {
			protection = "hardware"
		}
		return map[string]any{"selector": k.KeySelector, "public_key": k.SPKI, "binding": map[string]any{"id": readerID(k.BindingID), "incarnation": readerID(k.BindingIncarnationID), "serial": k.BindingSerial, "protection": protection}}
	}
	authority := map[string]any{}
	generatedAuthority := map[string]any{}
	recipients := map[string]any{}
	generatedRecipients := map[string]any{}
	for i, r := range d.Recipients {
		if r.CurrentBinding == nil {
			t.Fatal("fixture current binding missing")
		}
		if r.RecipientID == d.AuthorityRecipientID {
			authority = map[string]any{"display_name": r.DisplayName, "signing_key": d.NormalSigning.KeySelector, "encryption_key": r.CurrentBinding.KeySelector}
			generatedAuthority = map[string]any{"id": readerID(r.RecipientID), "signing": map[string]any{"selector": d.NormalSigning.KeySelector, "public_key": d.NormalSigning.SPKI}, "encryption": key(*r.CurrentBinding)}
		} else {
			ref := fmt.Sprintf("recipient%d", i)
			recipients[ref] = map[string]any{"id": readerID(r.RecipientID), "display_name": r.DisplayName, "encryption_key": r.CurrentBinding.KeySelector}
			generatedRecipients[ref] = map[string]any{"id": readerID(r.RecipientID), "encryption": key(*r.CurrentBinding)}
		}
	}
	recovery := map[string]any{"enabled": false}
	generatedRecovery := map[string]any{"enabled": false}
	if d.Recovery != nil {
		recovery = map[string]any{"enabled": true, "signing_key": d.Recovery.Signing.KeySelector, "encryption_key": d.Recovery.KMS.KeySelector}
		generatedRecovery = map[string]any{"enabled": true, "id": readerID(d.Recovery.RoleID), "signing": map[string]any{"selector": d.Recovery.Signing.KeySelector, "public_key": d.Recovery.Signing.SPKI}, "encryption": key(d.Recovery.KMS)}
	}
	a := fixture.Before.Archive
	family := "aws"
	if d.Provider == contract.GCP {
		family = "gcp"
	}
	store := map[string]any{"region": a.Location.Region, "bucket": a.Location.Bucket, "prefix": a.Location.PrefixBeforeHEAD}
	if a.Location.ExpectedOwner != "" {
		store["expected_owner"] = a.Location.ExpectedOwner
	}
	generated := map[string]any{"schema": "enkv/generated/v1", "file_id": readerID(contract.Hash(append([]byte("administrative CLI fixture file"), d.DomainID[:]...))), "domain": map[string]any{"id": readerID(d.DomainID), "authority": generatedAuthority, "recovery": generatedRecovery}, "recipients": generatedRecipients, "secrets": map[string]any{}, "public_basis": map[string]any{"kind": "genesis", "descriptor": basis.Descriptor}}
	body, err := json.Marshal(generated)
	if err != nil {
		t.Fatal(err)
	}
	reference := ".enkv/prod.generated.json"
	if err := os.Mkdir(filepath.Join(directory, ".enkv"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, reference), body, 0600); err != nil {
		t.Fatal(err)
	}
	editable := map[string]any{"schema": "enkv/configuration/v2", "generated": reference, "domain": map[string]any{"name": "prod", "provider": family, "store": store, "authority": authority, "recovery": recovery}, "recipients": recipients, "entries": map[string]any{}, "outputs": map[string]any{"destinations": map[string]any{}, "routing": map[string]any{}}}
	body, err = json.Marshal(editable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "source.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
