package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"enkv.sh/core/contract"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// full_only: false
func TestOperatorPrefixScanBoundsAndCompletePages(t *testing.T) {
	const prefix = "enkv-test/0123456789abcdef0123456789abcdef/0001/"
	key := func(i int) string { return fmt.Sprintf("%ssupport/0/%064x", prefix, i+1) }
	for _, tc := range []struct {
		name  string
		pages []livePrefixPage
		want  int
		fail  bool
	}{
		{"empty", []livePrefixPage{{}}, 0, false},
		{"short_first_page_continues", []livePrefixPage{{Keys: []string{key(0)}, Next: "next"}, {Keys: []string{key(1)}}}, 2, false},
		{"repeat_token", []livePrefixPage{{Next: "next"}, {Next: "next"}}, 0, true},
		{"duplicate_key", []livePrefixPage{{Keys: []string{key(0)}, Next: "next"}, {Keys: []string{key(0)}}}, 0, true},
		{"outside_prefix", []livePrefixPage{{Keys: []string{"enkv-test/another/HEAD"}}}, 0, true},
		{"invalid_key", []livePrefixPage{{Keys: []string{prefix + "other"}}}, 0, true},
		{"oversize_token", []livePrefixPage{{Next: strings.Repeat("a", operatorPrefixTokenMax+1)}}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			cleaner := &livePrefixCleaner{ValidKey: func(s string) bool { return strings.HasPrefix(s, prefix+"support/") },
				List: func(_ context.Context, gotPrefix, token string) (livePrefixPage, error) {
					if gotPrefix != prefix || calls >= len(tc.pages) || calls > 0 && token != "next" {
						t.Fatal("LIST request escaped exact cursor")
					}
					out := tc.pages[calls]
					calls++
					return out, nil
				}}
			budget := &runBudget{limits: liveLimits{Requests: 6, BodyBytes: 6 * operatorPrefixBodyLimit}, keys: map[string]bool{}}
			keys, err := scanOperatorPrefix(context.Background(), cleaner, budget, prefix)
			if (err != nil) != tc.fail || err == nil && len(keys) != tc.want || budget.snapshot().Requests != uint64(2*calls) {
				t.Fatalf("scan result keys=%d calls=%d err=%v", len(keys), calls, err)
			}
		})
	}
}

// full_only: false
func TestLiveFixtureKeyValidMatchesCurrentStoreNames(t *testing.T) {
	const prefix = "enkv-test/0123456789abcdef0123456789abcdef/0001"
	const domain = "1111111111111111111111111111111111111111111111111111111111111111"
	const object = "2222222222222222222222222222222222222222222222222222222222222222"
	head, objects := prefix+"/HEAD", prefix+"/"+domain+"/"
	for _, suffix := range []string{"member/31/" + object, "recipient/31/" + object, "access/255/" + object,
		"support/255/" + object, "admin-index/255/" + object, "root/0/" + object, "result/" + object} {
		if !liveFixtureKeyValid(head, objects, objects+suffix) {
			t.Fatalf("current Store key refused: %s", suffix)
		}
	}
	if !liveFixtureKeyValid(head, objects, head) {
		t.Fatal("HEAD refused")
	}
	for _, provider := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(fmt.Sprint(provider), func(t *testing.T) {
			var domainID, storeID contract.ID
			for index := range domainID {
				domainID[index], storeID[index] = 0x11, 0x22
			}
			key, err := contract.StoreConfigurationKeyForID(provider, prefix, domainID, storeID)
			want := objects + "configuration/" + object
			if err != nil || key != want {
				t.Fatal("configuration key differs from its literal physical name", err)
			}
			if !liveFixtureKeyValid(head, objects, key) || liveFixtureKeyLimit(head, objects, key) != contract.MaxStoreConfigurationLength {
				t.Fatal("current configuration key or its exact body limit refused")
			}
			for _, bad := range []string{objects + "configuration/0/" + object, objects + "configuration/" + object + "/extra",
				objects + "configuration/" + strings.Repeat("A", 64), objects + "configuration/" + strings.Repeat("0", 64),
				objects + "configuration/" + object[:63], objects + "configuration/", prefix + "-sibling/" + domain + "/configuration/" + object,
				prefix + "/" + object + "/configuration/" + object} {
				if liveFixtureKeyValid(head, objects, bad) || liveFixtureKeyLimit(head, objects, bad) != 0 {
					t.Fatal("malformed or foreign configuration key admitted")
				}
			}
		})
	}
	for _, suffix := range []string{"foreign/0/" + object, "admin-index/256/" + object, "support/00/" + object,
		"root/1/" + object, "result/" + strings.Repeat("A", 64), "result/" + strings.Repeat("0", 64),
		"support/0/" + object + "/extra", "support//" + object} {
		if liveFixtureKeyValid(head, objects, objects+suffix) {
			t.Fatalf("foreign-shaped Store key admitted: %s", suffix)
		}
	}
}

type publicCleanupBoundStore struct {
	contract.Store
	limits []uint32
}

func (s *publicCleanupBoundStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	s.limits = append(s.limits, limit)
	return s.Store.Read(ctx, key, limit)
}

func checkPublicCapturedCleanupProvider(t *testing.T, makeCleaner func(*testing.T, string, contract.ID, string, []byte) *livePrefixCleaner) {
	t.Helper()
	const prefix = "enkv-test/0123456789abcdef0123456789abcdef/point"
	domain := contract.Hash([]byte("operator-scan-domain"))
	objects := fmt.Sprintf("%s/%x/", prefix, domain)
	object := strings.Repeat("2", 64)
	for _, tc := range []struct {
		name, key string
		limit     uint32
	}{
		{"HEAD", prefix + "/HEAD", contract.MaxHeadLength},
		{"root", objects + "root/0/" + object, contract.MaxRootLength},
		{"result", objects + "result/" + object, uint32(contract.GeneratedResultRecordMaxLength)},
		{"admin-index", objects + "admin-index/255/" + object, contract.MaxRequiredSupportPageLength},
		{"access", objects + "access/255/" + object, contract.MaxAccessPageLength},
		{"recipient", objects + "recipient/31/" + object, contract.MaxRecipientPageLength},
		{"support", objects + "support/255/" + object, contract.MaxRequiredSupportPageLength},
		{"member", objects + "member/31/" + object, contract.MaxValueEntryPageLength},
		{"foreign-prefix", "foreign/HEAD", 0},
		{"foreign-domain", prefix + "/" + strings.Repeat("3", 64) + "/root/0/" + object, 0},
		{"foreign-kind", objects + "foreign/0/" + object, 0},
		{"invalid-index", objects + "member/32/" + object, 0},
		{"invalid-object", objects + "result/" + strings.Repeat("0", 64), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte("exact observed " + tc.name)
			cleaner := makeCleaner(t, prefix, domain, tc.key, body)
			store := &publicCleanupBoundStore{Store: cleaner.Store}
			cleaner.Store = store
			directory, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			inventory := &objectInventory{path: filepath.Join(directory, "inventory.json"), stopped: true,
				image: inventoryImage{Version: 1, RunID: liveProtocolRun, Prefix: prefix, Domain: domain, Deleted: map[string]int{}}}
			budget := &runBudget{limits: liveLimits{Requests: 10, BodyBytes: 1 << 28, Objects: 1, ObjectBytes: 1 << 22}, keys: map[string]bool{}}
			sum := sha256.Sum256([]byte(tc.key))
			err = publicAdoptCapturedObjects(context.Background(), inventory, cleaner, budget, []string{tc.key}, map[string]bool{hex.EncodeToString(sum[:]): true})
			if tc.limit == 0 {
				if err == nil || len(store.limits) != 0 || len(inventory.image.Intents) != 0 {
					t.Fatal("invalid key reached ownership read", err, store.limits)
				}
				return
			}
			if err != nil {
				t.Fatal("provider refused captured cleanup observation", err, store.limits)
			}
			if len(store.limits) != 1 || store.limits[0] != tc.limit {
				t.Fatal("cleanup observation did not use the object kind bound", store.limits, tc.limit)
			}
			if len(inventory.image.Intents) != 1 {
				t.Fatal("exact scanned body was not adopted")
			}
			intent := inventory.image.Intents[0]
			if intent.Key != tc.key || intent.Digest != bodyDigest(body) || intent.Bytes != uint64(len(body)) || intent.State != "acknowledged" {
				t.Fatal("ownership changed the exact observed body", intent)
			}
			if err := inventory.cleanup(context.Background(), store, cleaner.Delete); err != nil {
				t.Fatal("exact conditional cleanup failed", err)
			}
			if inventory.image.Deleted[tc.key] != 1 || len(inventory.image.CleanupAttempts) != 1 || inventory.image.CleanupAttempts[0].State != "settled" {
				t.Fatal("conditional delete was not settled")
			}
			if unknown, err := inventory.image.unknownEffects(); err != nil || unknown != 0 {
				t.Fatal("settled cleanup has unknown effects", unknown, err)
			}
		})
	}
}
