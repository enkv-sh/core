package compositionfull

import (
	"testing"

	compositionaws "enkv.sh/compositions/aws"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	gcp "enkv.sh/providers/gcp"
)

// full_only: false
func TestNewReconstructionSelectsExactlyOneInstalledProvider(t *testing.T) {
	ctx, awsCell, gcpCell := localConfigs(t)
	awsNormal := awsprovider.PublicSigningAnchorConfig{Role: contract.NormalSigningRole,
		Region: awsCell.Trust.Region, KeyARN: awsCell.Trust.KeyARN,
		CredentialRoute: awsCell.Trust.CredentialRoute, Credentials: awsCell.Trust.Credentials,
		Transport: awsCell.Trust.Transport, Timeout: awsCell.Trust.Timeout}
	awsConfig := compositionaws.ReconstructionConfig{Candidate: awsprovider.CandidateReadConfig{
		Region: awsCell.Store.Region, Bucket: awsCell.Store.Bucket, Prefix: awsCell.Store.Prefix,
		ExpectedBucketOwner: awsCell.Store.ExpectedBucketOwner,
		CredentialRoute:     awsCell.Store.CredentialRoute, Credentials: awsCell.Store.Credentials,
		Transport: awsCell.Store.Transport, Timeout: awsCell.Store.Timeout},
		Normal: &awsNormal, KeyAccess: compositionaws.ReconstructionKeyAccessConfig{CredentialRoute: awsCell.KeyAccess[0].CredentialRoute, Credentials: awsCell.KeyAccess[0].Credentials, Transport: awsCell.KeyAccess[0].Transport, Timeout: awsCell.KeyAccess[0].Timeout}}
	gcpNormal := gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole,
		Client: gcpCell.Trust.Client, Region: gcpCell.Trust.Region,
		KeyVersion: gcpCell.Trust.KeyVersion, CredentialRoute: gcpCell.Trust.CredentialRoute}
	gcpConfig := compositiongcp.ReconstructionConfig{Candidate: gcp.CandidateReadConfig{
		Client: gcpCell.Store.Client, Region: gcpCell.Store.Region,
		Bucket: gcpCell.Store.Bucket, Prefix: gcpCell.Store.Prefix,
		CredentialRoute: gcpCell.Store.CredentialRoute},
		Normal: &gcpNormal, KeyAccess: compositiongcp.ReconstructionKeyAccessConfig{Client: gcpCell.KeyAccess[0].Client, CredentialRoute: gcpCell.KeyAccess[0].CredentialRoute}}
	for _, c := range []ReconstructionConfig{{Family: contract.AWS, AWS: &awsConfig},
		{Family: contract.GCP, GCP: &gcpConfig}} {
		engine, err := NewReconstruction(ctx, c)
		if err != nil || engine == nil {
			t.Fatal("selected reconstruction composition did not construct", c.Family, err)
		}
		engine.Close()
	}
	for _, c := range []ReconstructionConfig{{Family: contract.AWS},
		{Family: contract.GCP}, {Family: contract.AWS, AWS: &awsConfig, GCP: &gcpConfig},
		{Family: contract.GCP, AWS: &awsConfig, GCP: &gcpConfig}} {
		if engine, err := NewReconstruction(ctx, c); err != ErrCell || engine != nil {
			if engine != nil {
				engine.Close()
			}
			t.Fatal("full composition admitted a missing or second provider", c.Family, err)
		}
	}
}
