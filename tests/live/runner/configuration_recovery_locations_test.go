package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
	"enkv.sh/crypto/testsupport/installedarchive"
)

type recoveryLocationStore struct {
	contract.Store
	locations installedarchive.RecoveryLocations
	family    contract.Family
	prefix    string
	domain    contract.ID
	open      func(context.Context, string, contract.ID) (*liveBackend, error)
}

func (s recoveryLocationStore) StoreConfiguration() contract.StoreConfiguration {
	return fixtureStoreConfiguration(s.Store)
}
func (s recoveryLocationStore) backend(ctx context.Context, key string) (contract.Store, *liveBackend, error) {
	prefix, domain, ok := s.locations.Target(s.family, s.prefix, s.domain, key)
	if !ok {
		return nil, nil, errors.New("recovery recorded target refused")
	}
	if prefix == s.prefix && domain == s.domain {
		return s.Store, nil, nil
	}
	backend, err := s.open(ctx, prefix, domain)
	if err != nil || backend == nil || backend.Store == nil {
		return nil, nil, errors.New("recovery owned Store unavailable")
	}
	configuration := fixtureStoreConfiguration(backend.Store)
	if configuration.Provider != s.family || configuration.DomainID != domain || configuration.PrefixBeforeHEAD != prefix {
		return nil, nil, errInventory
	}
	return backend.Store, backend, nil
}
func (s recoveryLocationStore) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	store, _, err := s.backend(ctx, key)
	if err != nil {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return store.Read(ctx, key, limit)
}
func liveRecoveryLocationBackend(input liveRunInput, image inventoryImage, base *liveBackend, open func(context.Context, string, contract.ID) (*liveBackend, error)) (*liveBackend, error) {
	if len(input.Scenarios) != 1 {
		return nil, errInventory
	}
	row, known := catalog.ConfigurationRecovery(input.Scenarios[0])
	if image.RecoveryLocations == nil {
		if known && (row.Condition == "new-domain-no-pin" || row.Condition == "prior-domain-pin" || row.Condition == "copied-location") {
			return nil, errInventory
		}
		return base, nil
	}
	if !known || base == nil || base.Store == nil || open == nil || !image.RecoveryLocations.Valid(row.Condition, image.Prefix, image.Domain) {
		return nil, errInventory
	}
	configuration := fixtureStoreConfiguration(base.Store)
	if configuration.DomainID != image.Domain || configuration.PrefixBeforeHEAD != image.Prefix {
		return nil, errInventory
	}
	for _, intent := range image.Intents {
		if _, _, ok := image.RecoveryLocations.Target(liveFamily, image.Prefix, image.Domain, intent.Key); !ok {
			return nil, errInventory
		}
	}
	router := recoveryLocationStore{Store: base.Store, locations: *image.RecoveryLocations, family: liveFamily, prefix: image.Prefix, domain: image.Domain, open: open}
	result := *base
	result.Store = router
	result.Put = func(ctx context.Context, key string, body []byte) contract.WriteResult {
		_, chosen, err := router.backend(ctx, key)
		if err != nil {
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
		}
		if chosen == nil {
			chosen = base
		}
		if chosen.Put == nil {
			return contract.WriteResult{Status: contract.WriteRefused, Reason: contract.ReasonConstruction}
		}
		return chosen.Put(ctx, key, body)
	}
	result.Delete = func(ctx context.Context, key string, token contract.Token) error {
		_, chosen, err := router.backend(ctx, key)
		if err != nil {
			return err
		}
		if chosen == nil {
			chosen = base
		}
		if chosen.Delete == nil {
			return errInventory
		}
		return chosen.Delete(ctx, key, token)
	}
	return &result, nil
}

// full_only: false
func TestLiveRecoveryLocationsRefuseBeforeProviderAccess(t *testing.T) {
	ctx := t.Context()
	fixture := newFixture(t, 1, false, 1)
	baseStore := fixture.store
	current := baseStore.configuration.DomainID
	prefix := baseStore.configuration.PrefixBeforeHEAD
	prior := contract.Hash([]byte("independently retained prior Domain"))
	object := contract.Hash([]byte("recorded object"))
	for _, condition := range []string{"new-domain-no-pin", "copied-location"} {
		t.Run(condition, func(t *testing.T) {
			facts := installedarchive.RecoveryLocations{PriorDomain: prior}
			chosenPrefix, chosenDomain := prefix, prior
			if condition == "copied-location" {
				facts = installedarchive.RecoveryLocations{CopiedPrefix: prefix + "/copied"}
				chosenPrefix, chosenDomain = facts.CopiedPrefix, current
			}
			chosen := &memoryStore{desc: baseStore.desc, objects: make(map[string]stored)}
			chosen.desc.Prefix, chosen.desc.HeadKey = chosenPrefix, chosenPrefix+"/HEAD"
			chosen.configure(t, liveFamily, chosenDomain)
			key, err := contract.StoreConfigurationKeyForID(liveFamily, chosenPrefix, chosenDomain, object)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte("small configuration")
			if chosen.Create(ctx, key, body).Status != contract.WriteAcknowledged {
				t.Fatal("owned object unavailable")
			}
			base := &liveBackend{Store: baseStore}
			opened, deleted := 0, 0
			open := func(context.Context, string, contract.ID) (*liveBackend, error) {
				opened++
				return &liveBackend{Store: chosen, Delete: func(context.Context, string, contract.Token) error { deleted++; return nil }}, nil
			}
			input := liveRunInput{Scenarios: []string{configurationCaseForCondition(t, condition)}}
			image := inventoryImage{Domain: current, Prefix: prefix, Deleted: map[string]int{}, RecoveryLocations: &facts, Intents: []objectIntent{{Key: key, Digest: bodyDigest(body), Bytes: uint64(len(body)), Kind: "create", State: "acknowledged"}}}
			router, err := liveRecoveryLocationBackend(input, image, base, open)
			if err != nil {
				t.Fatal("exact recorded owner refused")
			}
			read := router.Store.Read(ctx, key, uint32(len(body)))
			if read.Status != contract.ReadOK || !bytes.Equal(read.Body, body) || opened != 1 {
				t.Fatal("owned location read differs")
			}
			if err := router.Delete(ctx, key, read.Token); err != nil || opened != 2 || deleted != 1 {
				t.Fatal("owned exact deletion was not routed")
			}
			for _, bad := range []string{prefix + "-sibling/HEAD", prefix + "/%2F/HEAD", fmt.Sprintf("%s/%x/configuration/%x", prefix, contract.Hash([]byte("unknown Domain")), object)} {
				reads, opens, deletes := chosen.reads, opened, deleted
				if router.Store.Read(ctx, bad, 1).Status != contract.ReadInvalid || router.Delete(ctx, bad, read.Token) == nil || chosen.reads != reads || opened != opens || deleted != deletes {
					t.Fatal("forged target reached provider")
				}
				forged := image
				forged.Intents = append(append([]objectIntent(nil), image.Intents...), objectIntent{Key: bad, Digest: bodyDigest(body), Bytes: 1, Kind: "create", State: "acknowledged"})
				if _, err := liveRecoveryLocationBackend(input, forged, base, open); err == nil || opened != opens || chosen.reads != reads {
					t.Fatal("late forged recorded target admitted")
				}
				if _, err := forged.unknownEffects(); err == nil {
					t.Fatal("forged inventory reported known zero")
				}
			}
			unrelated := input
			unrelated.Scenarios = []string{"reconstruction.complete/complete_loss_complete"}
			if _, err := liveRecoveryLocationBackend(unrelated, image, base, open); err == nil {
				t.Fatal("historical facts admitted for unrelated case")
			}
			if _, err := liveRecoveryLocationBackend(input, inventoryImage{Domain: current, Prefix: prefix}, base, open); err == nil {
				t.Fatal("missing historical facts admitted")
			}
			forged := image
			invalid := installedarchive.RecoveryLocations{PriorDomain: current}
			forged.RecoveryLocations, forged.Intents = &invalid, nil
			if _, err := forged.unknownEffects(); err == nil {
				t.Fatal("empty forged inventory reported known zero")
			}
		})
	}
}
