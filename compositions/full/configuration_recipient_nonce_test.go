package compositionfull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

func preparationLiteralID(t *testing.T, text string) contract.ID {
	t.Helper()
	body, err := hex.DecodeString(text)
	if err != nil || len(body) != 32 {
		t.Fatal("invalid independent identity literal", err)
	}
	return contract.ID(body)
}

// Independent literals are derived by the retained recipient_creation_vectors.py.
// full_only: false
func TestRecipientNonceCollisionChecksWholeCurrentAndProposedRegistry(t *testing.T) {
	domain := contract.ID(bytes.Repeat([]byte{1}, 32))
	snapshot := contract.ID(bytes.Repeat([]byte{2}, 32))
	id := preparationLiteralID(t, "1e0f632de874daa81aee1329862f853523752d968f470b92a94f56f45033f601")
	for _, collision := range []string{"none", "current", "proposed", "generated", "zero"} {
		t.Run(collision, func(t *testing.T) {
			model := &configuration.Model{DomainID: domain}
			registry := &core.PublicRecipientRegistry{DomainID: domain, SnapshotID: snapshot}
			first, second := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
			input := append(bytes.Clone(first), second...)
			switch collision {
			case "current":
				registry.Recipients = []contract.RecipientRecord{{RecipientID: id}}
			case "proposed":
				model.Recipients = []configuration.Recipient{{ID: id}}
			case "generated":
				model.GeneratedRecipients = []configuration.Recipient{{ID: id}}
			case "zero":
				input = append(make([]byte, 32), first...)
			}
			material, err := freshConfigurationRecipient(t.Context(), model, registry, bytes.NewReader(input))
			if err != nil {
				t.Fatal("eligible fresh nonce refused", err)
			}
			if collision == "none" || collision == "zero" {
				if material.RecipientID != id || material.Encryption.BindingID != preparationLiteralID(t, "1335f7894345cceb330d579a02243aeae81ae5d6025d02304861ebf6a9bf34c6") || material.Encryption.BindingIncarnationID != preparationLiteralID(t, "1e34b1961d9a9f318d85f0c4357dbae41ce1cde49a340899d4e7660b45e1d581") {
					t.Fatal("fresh material differs from independent D3 literals")
				}
			} else {
				preimage := append([]byte("ENKV/recipient-creation/v1\x00"), domain[:]...)
				preimage = append(preimage, snapshot[:]...)
				preimage = append(preimage, second...)
				if material.RecipientID != contract.ID(sha256.Sum256(preimage)) || material.Creation.Nonce != contract.ID(second) {
					t.Fatal("collision saved the colliding identity or changed its target")
				}
			}
			if material.Creation.Snapshot != snapshot || material.Encryption.BindingSerial != 1 {
				t.Fatal("fresh preparation lost original predecessor or initial serial")
			}
		})
	}
	reader := bytes.NewReader(bytes.Repeat([]byte{3}, 32*9))
	model := &configuration.Model{DomainID: domain, Recipients: []configuration.Recipient{{ID: id}}}
	registry := &core.PublicRecipientRegistry{DomainID: domain, SnapshotID: snapshot}
	if _, err := freshConfigurationRecipient(t.Context(), model, registry, reader); err == nil || reader.Len() != 32 {
		t.Fatal("nonce collision attempts were not bounded to eight")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	reader = bytes.NewReader(bytes.Repeat([]byte{3}, 32))
	if _, err := freshConfigurationRecipient(ctx, model, registry, reader); err == nil || reader.Len() != 32 {
		t.Fatal("cancelled nonce acquisition consumed new input")
	}
}
