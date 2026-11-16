package gcp

import (
	"context"
	"enkv.sh/core/contract"
)

// PublicReader owns only keyed GET reach and independent construction facts.
type PublicReader struct {
	reader        *CandidateReader
	descriptor    contract.Descriptor
	configuration contract.StoreConfiguration
}

func NewPublicReader(ctx context.Context, c StoreConfig) (*PublicReader, error) {
	descriptor, err := storeDescriptor(c)
	if err != nil {
		return nil, err
	}
	reader, err := NewCandidateReader(ctx, CandidateReadConfig{Client: c.Client, Region: c.Region, Bucket: c.Bucket, Prefix: c.Prefix, CredentialRoute: c.CredentialRoute})
	if err != nil {
		return nil, err
	}
	return &PublicReader{reader: reader, descriptor: descriptor, configuration: storeConfiguration(c)}, nil
}
func (r *PublicReader) Descriptor() contract.Descriptor {
	if r == nil {
		return contract.Descriptor{}
	}
	return r.descriptor
}
func (r *PublicReader) StoreConfiguration() contract.StoreConfiguration {
	if r == nil {
		return contract.StoreConfiguration{}
	}
	return r.configuration
}
func (r *PublicReader) Close() {
	if r != nil {
		r.reader = nil
	}
}
func (r *PublicReader) Read(ctx context.Context, key string, limit uint32) contract.ReadResult {
	if r == nil || r.reader == nil || limit == 0 || int(limit) > storeKeyLimit(key, r.configuration.PrefixBeforeHEAD, r.descriptor.HeadKey, r.configuration.DomainID) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.reader.read(ctx, key, "state_object", limit)
}
