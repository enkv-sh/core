package awsprovider

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

func NewPublicReader(c StoreConfig) (*PublicReader, error) {
	descriptor, err := storeDescriptor(c)
	if err != nil {
		return nil, err
	}
	reader, err := NewCandidateReader(CandidateReadConfig{Region: c.Region, Bucket: c.Bucket, Prefix: c.Prefix, ExpectedBucketOwner: c.ExpectedBucketOwner, CredentialRoute: c.CredentialRoute, Credentials: c.Credentials, Transport: c.Transport, Timeout: c.Timeout})
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
	if r == nil || r.reader == nil || limit == 0 || int(limit) > keyLimit(r.descriptor.Prefix, r.configuration.DomainID, key) {
		return contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
	}
	return r.reader.read(ctx, key, r.configuration.ExpectedOwner, "state_object", limit)
}
