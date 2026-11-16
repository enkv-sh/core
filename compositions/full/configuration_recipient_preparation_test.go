package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationRecipientPreparationUsesPublicCurrentRegistry(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		for _, format := range []configuration.Format{configuration.JSON, configuration.YAML} {
			for _, mode := range []RecipientPreparationMode{RecipientPreparationCurrent, RecipientPreparationCreate} {
				t.Run(fmt.Sprintf("%s/%d/%s", family, format, mode), func(t *testing.T) {
					t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
					t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
					source := configurationReaderPair(t, family, format, nil)
					configurationSetWritable(t, source)
					before := configurationSetModel(t, source.path, format)
					selected := before.Recipients[0]
					before = localEditOpaquePlugins(t, source, format, selected.Reference)
					reference := selected.Reference
					options := RecipientPreparationOptions{Mode: mode}
					if mode == RecipientPreparationCreate {
						reference = "new-reader"
						options.Declaration = &configuration.RecipientDeclaration{DisplayName: selected.DisplayName, EncryptionSelector: selected.Selector}
					}
					h := &readerHTTPFixture{archive: source.archive, reads: map[string]int{}}
					opens, lookups := 0, 0
					open := configurationReaderOpener(t, source, h, &opens)
					resolve := func(ctx context.Context, m *configuration.Model, selector string) ([]byte, uint8, error) {
						lookups++
						if m.Provider != before.Provider || selector != selected.Selector || ctx.Err() != nil {
							t.Fatal("public lookup changed provider or exact resource")
						}
						return bytes.Clone(selected.Encryption.PublicKey), selected.Encryption.Binding.Protection, nil
					}
					nonce := bytes.Repeat([]byte{0x63}, 32)
					ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
					defer cancel()
					selector := RecipientSelector{Reference: reference}
					if mode == RecipientPreparationCurrent && format == configuration.YAML {
						selector = RecipientSelector{ID: selected.ID}
					}
					result, err := prepareConfigurationSelectedRecipient(ctx, source.path, format, selector, options, open, resolve, bytes.NewReader(nonce))
					if err != nil || LocalEditExitCode(result, err) != 0 {
						t.Fatal("public-only recipient preparation refused", err)
					}
					localEditReadbackMatches(t, result, err, source.path, source.generated)
					after := configurationSetModel(t, source.path, format)
					assertLocalEditPluginPreservation(t, before, after)
					if !reflect.DeepEqual(before.Basis, after.Basis) {
						t.Fatal("recipient preparation changed the public basis")
					}
					for _, name := range []string{"encoded", "secret"} {
						old, changed := configurationSetEntry(t, before, name), configurationSetEntry(t, after, name)
						if !bytes.Equal(old.Sealed, changed.Sealed) || !reflect.DeepEqual(old.Retained, changed.Retained) || !reflect.DeepEqual(old.Recipients, changed.Recipients) {
							t.Fatal("recipient preparation changed encrypted input or existing membership")
						}
					}
					if opens != 1 || lookups != 1 {
						t.Fatal("preparation omitted authenticated selection or exact public lookup")
					}
					h.assertNoEffects(t)
					if mode == RecipientPreparationCurrent {
						if !reflect.DeepEqual(before.Public, after.Public) {
							t.Fatal("current refresh changed public domain facts")
						}
						return
					}
					var created *configuration.Recipient
					for i := range after.Recipients {
						if after.Recipients[i].Reference == reference {
							created = &after.Recipients[i]
						}
					}
					if created == nil || created.Creation == nil || created.ID == selected.ID || created.Creation.Nonce != contract.ID(nonce) {
						t.Fatal("creation inferred identity from reused label or encryption resource")
					}
					preimage := append([]byte("ENKV/recipient-creation/v1\x00"), after.DomainID[:]...)
					preimage = append(preimage, created.Creation.Snapshot[:]...)
					preimage = append(preimage, nonce...)
					if created.ID != contract.ID(sha256.Sum256(preimage)) {
						t.Fatal("creation did not bind exact domain, authenticated predecessor and fresh nonce")
					}
				})
			}
		}
	}
}
