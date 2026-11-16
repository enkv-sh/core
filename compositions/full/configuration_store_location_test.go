package compositionfull

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// full_only: false
func TestConfigurationGeneratedViewsRetainConfiguredStoreLocation(t *testing.T) {
	source := configurationReaderPair(t, "aws", configuration.JSON, nil)
	defer source.assertUnchanged(t)
	server := &readerHTTPFixture{archive: source.archive, reads: make(map[string]int)}
	transport, stop := readerHTTPTransport(t, server, []string{"s3.us-east-1.amazonaws.com"})
	defer stop()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	configure := func(c ReaderConfig) ReaderConfig {
		c.AWS.Candidate.Credentials = readerFixtureCredentials{}
		c.AWS.Candidate.Transport = transport
		return c
	}
	inspected := inspectConfiguration(ctx, contract.ID{1}, source.pair, func(ctx context.Context, c InspectionReaderConfig) (*core.InstalledInspectionReader, error) {
		c.ReaderConfig = configure(c.ReaderConfig)
		return NewInspectionReader(ctx, c)
	})
	listed := listConfigurationGenerated(ctx, contract.ID{2}, source.pair, func(ctx context.Context, c ReaderConfig) (*core.InstalledGeneratedReader, error) {
		return NewGeneratedReader(ctx, configure(c))
	})
	if inspected.StateResult != core.PublicQuerySuccess || listed.StateResult != contract.ReaderSuccess {
		t.Fatal("authenticated owner control failed", inspected.PublicQueryResult, listed.PublicGeneratedListResult)
	}
	var inspection bytes.Buffer
	if err := inspected.WriteJSON(ctx, &inspection); err != nil {
		t.Fatal(err)
	}
	list, err := listed.RenderJSON()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"inspection": inspection.Bytes(), "generated-list": list} {
		var wire struct {
			Location map[string]string `json:"store_location"`
		}
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(name, err)
		}
		if len(wire.Location) != 4 || wire.Location["provider"] != "aws" || wire.Location["region"] != source.archive.Location.Region || wire.Location["bucket"] != source.archive.Location.Bucket || wire.Location["prefix"] != source.archive.Location.PrefixBeforeHEAD || bytes.Count(body, []byte(`"store_location"`)) != 1 {
			t.Fatal(name, "configured Store location missing or repeated", wire.Location)
		}
		if bytes.Contains(body, []byte(`"expected_owner"`)) || bytes.Contains(body, []byte(`"credentials"`)) {
			t.Fatal(name, "nonlocation construction details entered the result")
		}
	}
	server.assertNoEffects(t)
}

// full_only: false
func TestResultStoreLocationRequiresAuthenticatedDomainAndOwnedBound(t *testing.T) {
	id := contract.ID{1}
	m := &configuration.Model{Provider: contract.AWS, DomainID: id, Resolved: true}
	m.Store.Region, m.Store.Bucket, m.Store.PrefixBeforeHEAD, m.Store.ExpectedOwner = "us-east-1", "fixture-bucket", "fixture", "123456789012"
	result := core.Result{Outcome: core.ObservedCurrent, Evidence: core.AuthenticatedClosure}
	location := newResultStoreLocation(m, id, result)
	if location == nil || !location.valid(id, result) || unsafe.Sizeof(*location) != 104 || unsafe.Sizeof(location) != 8 {
		t.Fatal("location ownership or typed account changed")
	}
	before := location.configuration
	m.Store.Region, m.Store.Bucket, m.Store.PrefixBeforeHEAD, m.Store.ExpectedOwner = "changed", "changed", "changed", "changed"
	if location.configuration != before {
		t.Fatal("source mutation changed an owned result location")
	}
	m.Store = contract.StoreLocation{Provider: before.Provider, Region: before.Region, Bucket: before.Bucket, PrefixBeforeHEAD: before.PrefixBeforeHEAD, ExpectedOwner: before.ExpectedOwner}
	encoded, err := json.Marshal(location.fields())
	if err != nil || len(encoded)+32 > 1024 {
		t.Fatal("complete location compact reserve exceeded", len(encoded), err)
	}
	for _, condition := range []string{"wrong-domain", "no-authenticated-state", "no-current-observation"} {
		t.Run(condition, func(t *testing.T) {
			domain, observed := id, result
			switch condition {
			case "wrong-domain":
				domain = contract.ID{2}
			case "no-authenticated-state":
				observed.Evidence = core.NoEvidence
			case "no-current-observation":
				observed.Outcome = core.EvidenceUnavailable
			}
			if location.valid(domain, observed) || newResultStoreLocation(m, domain, observed) != nil {
				t.Fatal("location attached without its exact authenticated Domain")
			}
			list := ConfigurationGeneratedListResult{PublicGeneratedListResult: localResultList(), storeLocation: location}
			list.Context.ExpectedDomain, list.Result = domain, observed
			wrongLocation := *location
			if condition == "wrong-domain" {
				list.PublicGeneratedListResult = localResultList()
				wrongLocation.configuration.DomainID = domain
				list.storeLocation = &wrongLocation
				if validateGeneratedList(list.PublicGeneratedListResult) != nil {
					t.Fatal("raw generated control must remain valid")
				}
			}
			if body, err := list.RenderJSON(); err == nil || body != nil {
				t.Fatal("generated consumer accepted location with wrong observation")
			}
			direct := publicQueryRendererDomain(t)
			direct.DomainID, direct.Result = domain, observed
			inspectionLocation := location
			if condition == "wrong-domain" {
				direct = publicQueryRendererDomain(t)
				inspectionLocation = &wrongLocation
				if validateInspection(direct) != nil {
					t.Fatal("raw inspection control must remain valid")
				}
			}
			var out bytes.Buffer
			if err := (ConfigurationInspectionResult{PublicDomainInspectionResult: direct, storeLocation: inspectionLocation}).WriteJSON(t.Context(), &out); err == nil || out.Len() != 0 {
				t.Fatal("inspection consumer accepted location with wrong observation")
			}
		})
	}
}

// full_only: false
func TestGeneratedCleanupMutationRetainsConfiguredStoreLocation(t *testing.T) {
	source := configurationApplyPair(t, "aws", configuration.JSON, nil)
	t.Cleanup(func() {
		if err := source.pair.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	var out ConfigurationApplyResult
	var expected contract.StoreLocation
	var domain contract.ID
	out.PublicApplyResult = configurationGeneratedMutation(ctx, contract.ID{1}, source.pair, func(*core.InstalledApply) core.PublicApplyResult {
		r := generatedCleanupResultFixture(t)
		r.DomainID, r.Cleanup.RemainingWorkBasis.Snapshot.Domain = domain, domain
		r.Result.Evidence = core.AuthenticatedClosure
		if err := core.RefreshGeneratedCleanupResult(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}, func(_ context.Context, model *configuration.Model, _ core.ApplyInstallation) (*core.InstalledApply, error) {
		domain, expected = model.DomainID, model.Store
		return &core.InstalledApply{}, nil
	}, configurationMutationResultFacts{&out.SourceFailure, &out.storeLocation})
	if out.Result.Outcome != core.Contention || validateGeneratedInvocation(out.PublicApplyResult, contract.OperationCleanOwnedFailureResidue) != nil {
		t.Fatal("authenticated contention cleanup control invalid")
	}
	body, err := out.RenderGeneratedJSON(contract.OperationCleanOwnedFailureResidue)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Location map[string]string `json:"store_location"`
	}
	if json.Unmarshal(body, &wire) != nil || len(wire.Location) != 4 || wire.Location["region"] != expected.Region || wire.Location["bucket"] != expected.Bucket || wire.Location["prefix"] != expected.PrefixBeforeHEAD || bytes.Count(body, []byte(`"store_location"`)) != 1 {
		t.Fatal("cleanup mutation lost its exact configured Store location", wire.Location)
	}
	for _, condition := range []string{"wrong-domain", "no-authenticated-state"} {
		t.Run(condition, func(t *testing.T) {
			bad := out
			cleanup := *out.Cleanup
			bad.Cleanup = &cleanup
			if condition == "wrong-domain" {
				bad.DomainID, cleanup.RemainingWorkBasis.Snapshot.Domain = contract.ID{77}, contract.ID{77}
			} else {
				bad.Result.Evidence = core.NoEvidence
			}
			if err := core.RefreshGeneratedCleanupResult(&bad.PublicApplyResult); err != nil {
				t.Fatal(err)
			}
			if validateGeneratedInvocation(bad.PublicApplyResult, contract.OperationCleanOwnedFailureResidue) != nil {
				t.Fatal("raw Core negative control must remain valid")
			}
			if body, err := bad.RenderGeneratedJSON(contract.OperationCleanOwnedFailureResidue); err == nil || body != nil {
				t.Fatal("mutation location survived a mismatched authenticated tuple")
			}
		})
	}
}
