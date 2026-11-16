package compositionfull

import (
	"strings"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

// The result owns only durable construction strings, with no route or credential.
// On the target architecture the configuration is 104 bytes; four cloned ASCII
// strings total at most 810 bytes and the result pointer adds eight. The four
// rendered fields, including their framing, fit in one 1024-byte compact reserve.
type resultStoreLocation struct{ configuration contract.StoreConfiguration }

func newResultStoreLocation(m *configuration.Model, authenticatedDomain contract.ID, result core.Result) *resultStoreLocation {
	if result.Outcome != core.ObservedCurrent {
		return nil
	}
	return ownAuthenticatedResultStoreLocation(m, authenticatedDomain, result)
}

func newMutationResultStoreLocation(m *configuration.Model, result core.PublicApplyResult) *resultStoreLocation {
	if result.Generated == nil || validateGeneratedInvocation(result, result.Generated.OperationKind) != nil {
		return nil
	}
	return ownAuthenticatedResultStoreLocation(m, result.DomainID, result.Result)
}

func ownAuthenticatedResultStoreLocation(m *configuration.Model, authenticatedDomain contract.ID, result core.Result) *resultStoreLocation {
	if m == nil || !m.Resolved || authenticatedDomain != m.DomainID || authenticatedDomain.IsZero() || result.Evidence != core.AuthenticatedClosure {
		return nil
	}
	c := contract.StoreConfiguration{Provider: m.Provider, ConstructionProfile: contract.StoreConstructionProfile, DomainID: m.DomainID, Region: m.Store.Region, Bucket: m.Store.Bucket, PrefixBeforeHEAD: m.Store.PrefixBeforeHEAD, ExpectedOwner: m.Store.ExpectedOwner}
	if _, err := contract.StoreConfigurationID(c); err != nil {
		return nil
	}
	c.Region, c.Bucket, c.PrefixBeforeHEAD, c.ExpectedOwner = strings.Clone(c.Region), strings.Clone(c.Bucket), strings.Clone(c.PrefixBeforeHEAD), strings.Clone(c.ExpectedOwner)
	return &resultStoreLocation{configuration: c}
}

func (p *resultStoreLocation) valid(domain contract.ID, result core.Result) bool {
	if p == nil {
		return true
	}
	return result.Outcome == core.ObservedCurrent && p.validAuthenticatedDomain(domain, result)
}

func (p *resultStoreLocation) validAuthenticatedDomain(domain contract.ID, result core.Result) bool {
	if p == nil {
		return true
	}
	if domain.IsZero() || p.configuration.DomainID != domain || result.Evidence != core.AuthenticatedClosure {
		return false
	}
	_, err := contract.StoreConfigurationID(p.configuration)
	return err == nil
}

func (p *resultStoreLocation) fields() map[string]string {
	provider := "aws"
	if p.configuration.Provider == contract.GCP {
		provider = "gcp"
	}
	return map[string]string{"provider": provider, "region": p.configuration.Region, "bucket": p.configuration.Bucket, "prefix": p.configuration.PrefixBeforeHEAD}
}
