package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
)

// full_only: false
func TestStockAWSVersionOwnershipRequiresSignedRunAndOriginalResults(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	data := make(map[string]contract.ReadResult)
	f, observation, _ := packagedGeneratedSequenceWithHandoff(t, ctx, true, nil, data)
	store := requireAdmittedMemoryStore(t, f.env.Store)
	key := store.Descriptor().HeadKey
	for k, v := range store.objects {
		if k != key {
			data[k] = readFixtureStoredBody(v, 2<<20)
		}
	}
	e := records.StockPluginEvidence{GenesisHEAD: bodyDigest(observation.genesis.body), FinalHEAD: bodyDigest(f.selected.body), Creates: make([]records.StockPluginCreate, 3), Duties: make([]records.StockPluginDuty, 3), Retirements: make([]records.StockPluginRetirement, 3)}
	for i := 1; i <= 3; i++ {
		e.ProviderTokenIDs = append(e.ProviderTokenIDs, fmt.Sprintf("%032x", i))
	}
	input := records.StockPluginAcceptanceInput{CloudflareAccount: hermeticCloudflareAccount}
	originals := make(map[stockS3VersionID]contract.ReadResult)
	var versions []stockS3Version
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	add := func(k string, r contract.ReadResult, latest bool) {
		item := stockS3Version{stockS3VersionID: stockS3VersionID{k, fmt.Sprintf("version-%d", len(versions))}, token: r.Token, length: uint32(len(r.Body)), latest: latest}
		originals[item.stockS3VersionID] = r
		versions = append(versions, item)
	}
	closeByResult := make(map[contract.ID]records.StockPluginRetirement)
	for _, v := range append([]packagedSequenceHead{observation.genesis}, observation.heads...) {
		h, err := format.DecodeHead(v.body)
		if err != nil {
			t.Fatal(err)
		}
		if s := h.Generator; s != nil && s.Purpose == contract.GeneratorAuthorityRetireClose {
			closeByResult[s.ResultDigest] = records.StockPluginRetirement{CloseDigest: bodyDigest(v.body), ResultDigest: id(s.ResultDigest), DutyID: id(s.OwnerID)}
		}
		add(key, contract.ReadResult{Status: contract.ReadOK, Token: v.token, Body: v.body}, bytes.Equal(v.body, f.selected.body))
	}
	for k, r := range data {
		_, present := store.objects[k]
		add(k, r, present)
		if !present {
			versions = append(versions, stockS3Version{stockS3VersionID: stockS3VersionID{k, "release"}, marker: true, latest: true})
		}
		obj, err := contract.ParseStoreObjectKey(store.desc.Prefix, f.env.Domain, k)
		if err != nil {
			t.Fatal(err)
		}
		if obj.Namespace != contract.StoreResultObject {
			continue
		}
		result, err := contract.InspectGeneratedResultRecord(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		facts := result.SafeFacts.GeneratorSafeFacts
		i := slices.Index(e.ProviderTokenIDs, string(facts.ResourceData))
		if i < 0 {
			t.Fatal("fixture returned an unknown resource")
		}
		core := result.Core
		switch result.Disposition() {
		case contract.GeneratorDispositionCompleteCreate:
			e.Creates[i] = records.StockPluginCreate{OperationID: id(core.OperationID), AttemptID: id(core.AttemptID), ExecutorID: id(core.ExecutorID), DescriptorID: id(core.DescriptorID), ConfigContractID: id(core.ConfigContractID), ResultContractID: id(core.ResultContractID), ResourceDigest: id(generatedFactsResourceDigest(facts)), ResourceContractID: id(facts.ResourceContractID)}
		case contract.GeneratorDispositionRetirementAcknowledged:
			ret := closeByResult[contract.Hash(r.Body)]
			ret.ResultLength = uint32(len(r.Body))
			e.Retirements[i] = ret
			e.Duties[i] = records.StockPluginDuty{ExecutorID: id(core.ExecutorID), DescriptorID: id(core.DescriptorID), ResultContractID: id(core.ResultContractID)}
		}
	}
	read := func(ctx context.Context, v stockS3Version) (contract.ReadResult, error) {
		r, ok := originals[v.stockS3VersionID]
		if !ok {
			return contract.ReadResult{}, errInventory
		}
		r.Body = bytes.Clone(r.Body)
		return r, nil
	}
	t.Run("reconstructed-observation", func(t *testing.T) {
		image := stockTestObservation(t, f.selected, store)
		basis := PublicBasis{SigningAnchor: image.SigningAnchor, StoreConfiguration: image.StoreConfiguration,
			HEAD: image.HEAD, Root: image.Root, RecipientPages: image.RecipientPages}
		reopened := publicOperatorOpen(t, ctx, f.env.Domain, basis, store)
		if err := stockS3RetainQualifiedHistory(ctx, reopened, input, e, versions, stockProofDirectory(t), read); err != nil {
			t.Fatal("reconstructed final observation could not qualify its original history", err)
		}
		t.Run("missing-genesis-root", func(t *testing.T) {
			head, err := format.DecodeHead(observation.genesis.body)
			if err != nil {
				t.Fatal(err)
			}
			key, err := contract.StoreObjectKey(store.desc.Prefix, f.env.Domain, gcPageIdentity(head.Core.Root))
			if err != nil {
				t.Fatal(err)
			}
			original, present := store.objects[key]
			if !present {
				t.Fatal("fixture has no original root")
			}
			delete(store.objects, key)
			defer func() { store.objects[key] = original }()
			directory := stockProofDirectory(t)
			if err := stockS3RetainQualifiedHistory(ctx, reopened, input, e, versions, directory, read); err == nil {
				t.Fatal("qualified absent genesis root")
			}
			if _, err := os.Lstat(filepath.Join(directory, "stock-version-proof.json")); !os.IsNotExist(err) {
				t.Fatal("left a proof for missing history")
			}
		})
		for _, proof := range []string{"authorization", "recovery-challenge"} {
			t.Run(proof, func(t *testing.T) {
				head, err := format.DecodeHead(bytes.Clone(observation.genesis.body))
				if err != nil {
					t.Fatal(err)
				}
				signature := head.AuthorizationSignature
				if proof == "recovery-challenge" {
					signature = head.Genesis.K3Challenge
				}
				if len(signature) == 0 {
					t.Fatal("missing original signature")
				}
				signature[len(signature)-1] ^= 1
				body, err := format.EncodeHead(head)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stockGenesisHistorySession(ctx, reopened, body); err == nil {
					t.Fatal("accepted altered genesis proof")
				}
			})
		}
	})
	for _, mode := range []string{"exact", "extra-version", "missing-head", "wrong-genesis", "wrong-final", "damaged-head", "changed-etag", "damaged-result", "unreleased-marker", "missing-marker", "other-registered-token", "wrong-close", "wrong-length", "foreign-key", "missing-current-root"} {
		t.Run(mode, func(t *testing.T) {
			items := slices.Clone(versions)
			proof := e
			fetch := read
			proof.Retirements = slices.Clone(e.Retirements)
			proof.ProviderTokenIDs = slices.Clone(e.ProviderTokenIDs)
			switch mode {
			case "extra-version":
				items = append(items, items[0])
			case "missing-head":
				items = items[1:]
			case "wrong-genesis":
				proof.GenesisHEAD = proof.FinalHEAD
			case "wrong-final":
				proof.FinalHEAD = proof.GenesisHEAD
			case "damaged-head", "changed-etag", "damaged-result":
				fetch = func(ctx context.Context, v stockS3Version) (contract.ReadResult, error) {
					r, err := read(ctx, v)
					if err == nil && v.key == key && !v.latest {
						if mode == "damaged-head" {
							r.Body[len(r.Body)-1] ^= 1
						}
						if mode == "changed-etag" {
							r.Token.Value = `"different"`
						}
					}
					if err == nil && mode == "damaged-result" && !v.latest && v.key != key {
						r.Body[len(r.Body)-1] ^= 1
					}
					return r, err
				}
			case "unreleased-marker":
				items = append(items, stockS3Version{stockS3VersionID: stockS3VersionID{key, "unrelated"}, marker: true, latest: true})
			case "missing-marker":
				for i, v := range items {
					if v.marker {
						items = slices.Delete(items, i, i+1)
						break
					}
				}
			case "other-registered-token":
				proof.ProviderTokenIDs[0], proof.ProviderTokenIDs[1] = proof.ProviderTokenIDs[1], proof.ProviderTokenIDs[0]
			case "wrong-close":
				proof.Retirements[0].CloseDigest = proof.Retirements[1].CloseDigest
			case "wrong-length":
				proof.Retirements[0].ResultLength++
			case "foreign-key":
				items = append(items, stockS3Version{stockS3VersionID: stockS3VersionID{"sibling/HEAD", "v"}, latest: true})
			case "missing-current-root":
				for i, v := range items {
					if v.key != key && !v.marker && bodyDigest(originals[v.stockS3VersionID].Body) == id(f.selected.head.Core.Root.Digest) {
						items = slices.Delete(items, i, i+1)
						break
					}
				}
			}
			directory := stockProofDirectory(t)
			path := filepath.Join(directory, "stock-version-proof.json")
			err := stockS3RetainQualifiedHistory(ctx, f.selected, input, proof, items, directory, fetch)
			if (err == nil) != (mode == "exact") {
				t.Fatal("unexpected ownership result", err)
			}
			if mode != "exact" {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("unqualified history left a proof record")
				}
				return
			}
			var retained stockTeardownProof
			info, statErr := os.Stat(path)
			if statErr != nil || info.Mode().Perm() != 0600 || records.ReadJSON(path, &retained) != nil || retained.Genesis != proof.GenesisHEAD || retained.Final != proof.FinalHEAD || retained.Domain != id(f.selected.root.Domain) || len(retained.Versions) != len(items) {
				t.Fatal("complete private proof unavailable")
			}
			for i, v := range retained.Versions {
				item := items[i]
				if v.Version != item.version || v.Key != item.key || v.Marker != item.marker || v.Latest != item.latest || v.Length != item.length || v.ETag != item.token.Value {
					t.Fatal("retained coordinates differ")
				}
				if item.marker {
					if v.Digest != "" || len(v.ProofBytes) != 0 {
						t.Fatal("marker has invented content")
					}
					continue
				}
				original := originals[item.stockS3VersionID].Body
				wantProof := item.key == key || slices.ContainsFunc(proof.Retirements, func(r records.StockPluginRetirement) bool { return r.ResultDigest == bodyDigest(original) })
				if v.Digest != bodyDigest(original) || wantProof && !bytes.Equal(v.ProofBytes, original) || !wantProof && len(v.ProofBytes) != 0 {
					t.Fatal("retained proof content differs")
				}
			}
			if err := stockS3RetainQualifiedHistory(ctx, f.selected, input, proof, items, directory, fetch); err == nil {
				t.Fatal("existing proof was overwritten")
			}
		})
	}
}

func stockProofDirectory(t *testing.T) string {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(base, "private")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}
