package core

import (
	"crypto/rand"
	"io"

	"enkv.sh/core/contract"
)

// These Core outputs precede Store construction and durable descriptor writing.
// Possession of the IDs does not admit initialization or any provider effect.
type genesisIDs struct {
	Init, Domain, DescriptorArtifact, ManifestArtifact contract.ID
}

func allocateGenesisIDs(entropy io.Reader) (genesisIDs, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	var result genesisIDs
	seen := make(map[contract.ID]bool, 4)
	for _, id := range []*contract.ID{&result.Init, &result.Domain, &result.DescriptorArtifact, &result.ManifestArtifact} {
		if _, err := io.ReadFull(entropy, id[:]); err != nil {
			return genesisIDs{}, err
		}
		if id.IsZero() || seen[*id] {
			return genesisIDs{}, contract.ErrSubject
		}
		seen[*id] = true
	}
	return result, nil
}
