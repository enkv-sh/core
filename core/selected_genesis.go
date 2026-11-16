package core

import (
	"bytes"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedGenesisDescriptor derives public descriptor fields from one selected
// image and its signed Genesis proof. It does not replace ordinary enrollment
// or qualify the signature on that proof.
func selectedGenesisDescriptor(head format.Head, image *selectedImage) (contract.GenesisDescriptorCore, []byte, bool) {
	if image == nil || head.AuthKind != format.GenesisAuth || head.Genesis == nil {
		return contract.GenesisDescriptorCore{}, nil, false
	}
	g := head.Genesis
	current := image.root.CurrentAccess.Core.CurrentControl
	recipients := selectedRecipientRegistry(&image.recipients, image.root.RecipientCount)
	if len(recipients) != int(image.root.RecipientCount) {
		return contract.GenesisDescriptorCore{}, nil, false
	}
	c := g.Closure
	d := contract.GenesisDescriptorCore{
		InitID: g.Subject.InitID, DomainID: image.root.Domain,
		DescriptorArtifactID: c.DescriptorReadbackFact.ArtifactID,
		ManifestArtifactID:   c.ManifestReadbackFact.ArtifactID,
		Provider:             current.Provider, StoreID: head.Core.Store,
		CoordinateID: head.Core.Coordinate, NonBodyID: head.Core.NonBody,
		TrustID: head.Core.Trust, InterpretationID: head.Core.Interpretation,
		TrustInterpretationID: current.TrustInterpretationID,
		CompatibilityID:       current.CompatibilityID, CryptoSupportID: current.CryptoSupportID,
		AuthorityRecipientID: current.AuthorityRecipientID,
		NormalSigning:        current.NormalSigning, Recovery: current.Recovery,
		Recipients: recipients,
	}
	selectedControl, ok := selectedControlFrom(image.root, &image.recipients, d.AuthorityRecipientID)
	if !ok {
		return contract.GenesisDescriptorCore{}, nil, false
	}
	authority := selectedRecipientRecord(&image.recipients, d.AuthorityRecipientID)
	if authority == nil || authority.CurrentBinding == nil ||
		!controlEqual(selectedControl, contract.ControlCore{CurrentControl: d.CurrentControl(), AuthorityKMSBinding: *authority.CurrentBinding}) {
		return contract.GenesisDescriptorCore{}, nil, false
	}
	encoded, err := contract.EncodeGenesisDescriptorCore(d)
	return d, encoded, err == nil && contract.Hash(encoded) == g.Subject.DescriptorDigest
}

// selectedGenesisClosure validates the public selected Genesis relation. The
// caller must separately authenticate the complete image and signing proof.
func selectedGenesisClosure(head format.Head, image *selectedImage, configuration contract.StoreConfiguration) (contract.GenesisDescriptorCore, bool) {
	var empty contract.GenesisDescriptorCore
	if image == nil || head.Genesis == nil || image.root.ValueEntryCount != 0 {
		return empty, false
	}
	d, descriptor, ok := selectedGenesisDescriptor(head, image)
	if !ok || head.Genesis.Subject.InitID != d.InitID {
		return empty, false
	}
	configurationBytes, err := contract.EncodeStoreConfiguration(configuration)
	if err != nil || configuration.DomainID != d.DomainID || configuration.Provider != d.Provider || contract.Hash(configurationBytes) != d.StoreID {
		return empty, false
	}
	g := head.Genesis
	p, err := reconstructGenesisPlan(d, g.Plan.IdentityPlan, g.Plan.Probes, g.Plan.K3ChallengeID, g.Request.SetupDigest, g.Request.Expiry)
	if err != nil || !bytes.Equal(descriptor, p.descriptorBytes) || !selectedGenesisPreparation(head, p) || len(p.objects) == 0 {
		return empty, false
	}
	rootBytes, err := format.EncodeRoot(image.root)
	if err != nil || !bytes.Equal(rootBytes, p.objects[len(p.objects)-1].body) {
		return empty, false
	}
	c := g.Closure
	if !artifactMatches(c.DescriptorReadbackFact, 1, d.DescriptorArtifactID, p.descriptorBytes) ||
		!artifactMatches(c.ManifestReadbackFact, 2, d.ManifestArtifactID, p.manifestBytes) ||
		!artifactMatches(c.ConfigurationReadbackFact, 3, d.StoreID, configurationBytes) ||
		c.NormalBindingSubjectDigest != p.manifest.NormalBindingSubjectDigest ||
		c.K3BasisSubjectDigest != p.manifest.K3BasisSubjectDigest ||
		c.K3InitChallengeCoreDigest != p.manifest.K3InitChallengeCoreDigest ||
		len(c.Signers) != len(p.manifest.Signers) || len(c.Immutable) != len(p.objects) {
		return empty, false
	}
	for i, row := range c.Signers {
		expected := p.manifest.Signers[i]
		if row.TargetRole != expected.TargetRole || row.SigningBindingDigest != expected.SigningBindingDigest ||
			row.Provider != d.Provider || row.Qualified != 1 || row.Reason != contract.ReasonNone {
			return empty, false
		}
	}
	for i, row := range c.Immutable {
		if row.Ref != p.objects[i].ref || row.ReadbackObservation != 1 {
			return empty, false
		}
	}
	bindings, err := d.BindingTable()
	if err != nil || len(c.QualifiedKeys.Public) != len(bindings) ||
		len(c.QualifiedKeys.Private) != len(p.plan.Probes) || c.QualifiedKeys.InitID != d.InitID {
		return empty, false
	}
	for i, b := range bindings {
		digest, err := contract.PublicBindingDigest(b.Binding)
		if err != nil {
			return empty, false
		}
		want := contract.QualifiedBindingFields{SubjectKind: b.SubjectKind, SubjectID: b.SubjectID,
			BindingID: b.Binding.BindingID, PublicBindingDigest: digest, Provider: d.Provider, Qualified: 1}
		if c.QualifiedKeys.Public[i] != want {
			return empty, false
		}
	}
	for i, probe := range p.plan.Probes {
		row := c.QualifiedKeys.Private[i]
		if row.ProbeID != probe.ProbeID || row.SubjectKind != probe.SubjectKind ||
			row.SubjectID != probe.SubjectID || row.BindingID != probe.BindingID ||
			row.PublicBindingDigest != probe.PublicBindingDigest || row.Provider != d.Provider || row.Qualified != 1 {
			return empty, false
		}
	}
	return d, true
}
