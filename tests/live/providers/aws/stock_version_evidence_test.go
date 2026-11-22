package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"path/filepath"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

type stockVersionProof struct {
	Key     string `json:"key"`
	Version string `json:"version"`
	Latest  bool   `json:"latest"`
	Marker  bool   `json:"delete_marker"`
	ETag    string `json:"etag,omitempty"`
	Length  uint32 `json:"length,omitempty"`
	Digest  string `json:"sha256,omitempty"`
	// Only signed HEADs and the three original retirement acknowledgements.
	ProofBytes []byte `json:"proof_bytes,omitempty"`
}

type stockTeardownProof struct {
	Schema   uint16                     `json:"schema"`
	RunID    string                     `json:"run_id"`
	Fixture  records.StockPluginFixture `json:"fixture"`
	Prefix   string                     `json:"prefix"`
	Domain   string                     `json:"domain"`
	Genesis  string                     `json:"genesis_head"`
	Final    string                     `json:"final_head"`
	Versions []stockVersionProof        `json:"versions"`
}

// Keep exact version coordinates and content hashes for inspection after an
// interrupted purge. The resulting private record grants no deletion authority.
func stockS3RetainQualifiedHistory(ctx context.Context, selected *StateSession, input records.StockPluginAcceptanceInput, e records.StockPluginEvidence, items []stockS3Version, directory string, read stockS3ReadOriginal) error {
	if selected == nil || !filepath.IsAbs(directory) || len(items) == 0 || len(items) > operatorPrefixObjects {
		return errInventory
	}
	proof := stockTeardownProof{Schema: 1, RunID: e.RunID, Fixture: input.Fixture, Prefix: e.Prefix, Domain: hex.EncodeToString(selected.root.Domain[:]), Genesis: e.GenesisHEAD, Final: e.FinalHEAD, Versions: make([]stockVersionProof, len(items))}
	index := make(map[stockS3VersionID]int, len(items))
	for i, item := range items {
		if _, seen := index[item.stockS3VersionID]; seen {
			return errInventory
		}
		index[item.stockS3VersionID] = i
		proof.Versions[i] = stockVersionProof{Key: item.key, Version: item.version, Latest: item.latest, Marker: item.marker, ETag: item.token.Value, Length: item.length}
	}
	retired := make(map[string]bool)
	for _, r := range e.Retirements {
		retired[r.ResultDigest] = true
	}
	proofBytes := 0
	capture := func(ctx context.Context, item stockS3Version) (contract.ReadResult, error) {
		r, err := read(ctx, item)
		if err != nil {
			return r, err
		}
		row := &proof.Versions[index[item.stockS3VersionID]]
		row.Digest = bodyDigest(r.Body)
		if item.key == selected.store.Descriptor().HeadKey || retired[row.Digest] {
			proofBytes += len(r.Body)
			if proofBytes > records.MaximumJSONBytes {
				clear(r.Body)
				return contract.ReadResult{}, errRunLimit
			}
			row.ProofBytes = bytes.Clone(r.Body)
		}
		return r, nil
	}
	if err := stockS3QualifyVersions(ctx, selected, input, e, items, capture); err != nil {
		return err
	}
	if err := records.WriteJSONExclusive(filepath.Join(directory, "stock-version-proof.json"), proof, records.MaximumJSONBytes); err != nil {
		return errInventory
	}
	return nil
}
