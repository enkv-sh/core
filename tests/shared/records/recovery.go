package records

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

func (h RecoveryHandoff) Validate(runID, scenario, prefix string) error {
	if h.Version != 1 || h.RunID != runID || h.Scenario != scenario || h.Prefix != prefix || h.Domain.IsZero() || h.Genesis.Domain != h.Domain || h.Genesis.Init.IsZero() || h.Genesis.DescriptorArtifact.IsZero() || h.Genesis.ManifestArtifact.IsZero() || len(h.Desired) == 0 || len(h.Desired) > contract.CryptoMaxValueEntries {
		return errors.New("recovery handoff refused")
	}
	ids := []contract.ID{h.Genesis.Init, h.Genesis.Domain, h.Genesis.DescriptorArtifact, h.Genesis.ManifestArtifact}
	for i, id := range ids {
		for _, prior := range ids[:i] {
			if id == prior {
				return errors.New("recovery handoff identities overlap")
			}
		}
	}
	basis, err := contract.DecodeGenesisDescriptorCore(h.Basis)
	if err != nil || basis.DomainID != h.Domain || basis.InitID != h.Genesis.Init || basis.DescriptorArtifactID != h.Genesis.DescriptorArtifact || basis.ManifestArtifactID != h.Genesis.ManifestArtifact {
		return errors.New("recovery handoff basis refused")
	}
	canonical, err := contract.EncodeGenesisDescriptorCore(basis)
	if err != nil || !bytes.Equal(canonical, h.Basis) {
		return errors.New("recovery handoff basis changed")
	}
	for i, value := range h.Desired {
		if value.Name == "" || !utf8.ValidString(value.Name) || len(value.Name) > contract.CryptoMaxName || i > 0 && h.Desired[i-1].Name >= value.Name || len(value.Value) > contract.CryptoMaxRawValue || len(value.Recipients) == 0 || len(value.Recipients) > contract.CryptoMaxValueEntryRecipients {
			return errors.New("recovery handoff goal refused")
		}
		for j, recipient := range value.Recipients {
			if recipient.IsZero() || j > 0 && bytes.Compare(value.Recipients[j-1][:], recipient[:]) >= 0 {
				return errors.New("recovery handoff recipient refused")
			}
		}
	}
	return nil
}
