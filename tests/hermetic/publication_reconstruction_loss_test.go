package core

import (
	"bytes"
	"testing"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	testtrust "enkv.sh/crypto/testsupport/trust"
)

func publicationLossAdmissionFixture(t *testing.T, family contract.Family) installedarchive.PublicationLossContinuation {
	t.Helper()
	env, _ := genesisEnvironment(t, family, false, 3)
	env.GenesisIDs = publicationLossAuthorityData(env.Domain)
	store := env.Store.(*memoryStore)
	descriptor, err := publicationLossDescriptor(store.configuration)
	if err != nil {
		t.Fatal(err)
	}
	store.desc = descriptor
	trust := testtrust.NewWithIdentity(t, family, testID("trust"), publicationLossTrustID(family, contract.NormalSigningRole), contract.NormalSigningRole)
	env.Trust = &fixtureTrust{Signer: trust}
	env.PublicKey, env.SigningSelector = trust.PublicKey(), trust.KeySelector()
	fixture := newEnvironmentFixture(t, t.Context(), env, nil, false)
	archive := configurationRecoveryArchive(t, env, fixture.session, store)
	parts, err := archive.SelectedParts()
	if err != nil {
		t.Fatal(err)
	}
	head, ok := archive.Object(store.desc.HeadKey)
	token, n, tokenError := contract.ParseToken(head.TokenWire)
	if !ok || tokenError != nil || n != len(head.TokenWire) || token != fixture.session.token || contract.Hash(head.Body) != archive.HeadDigest || !bytes.Equal(head.Body, fixture.session.body) || store.objects[store.desc.HeadKey].Token != fixture.session.token {
		t.Fatal("actual selected HEAD backing differs")
	}
	return installedarchive.PublicationLossContinuation{Location: archive.Location, Domain: env.Domain, Revision: archive.Revision, Snapshot: fixture.session.root.Snapshot, HEADDigest: archive.HeadDigest, HEADToken: fixture.session.token, Objects: archive.Objects, Parts: parts, Result: installedarchive.RecoveryResult{Outcome: 2, Evidence: 1}}
}

// full_only: false
func TestPublicationLossFreshNormalAdmission(t *testing.T) {
	for _, family := range []contract.Family{contract.AWS, contract.GCP} {
		t.Run(map[contract.Family]string{contract.AWS: "aws", contract.GCP: "gcp"}[family], func(t *testing.T) {
			returned := publicationLossAdmissionFixture(t, family)
			history := "owned_active_then_delete"
			grant := publicationLossGrant{Composition: fixtureID(returned.Domain, "new explicit composition"), Expires: time.Now().Add(50 * time.Second), NamespaceDomain: returned.Domain, NamespaceProvider: "test-output/service/v1", NamespaceSlot: publicationLossTarget(history).target.CanonicalTarget, NamespacePremise: fixtureID(returned.Domain, "new independent namespace grant")}
			for _, damage := range []string{"missing_grant", "expired_grant", "refused_recovery", "stale_HEAD", "wrong_authority", "wrong_namespace_domain", "wrong_namespace_slot"} {
				t.Run(damage, func(t *testing.T) {
					candidate, g := returned, grant
					switch damage {
					case "missing_grant":
						g = publicationLossGrant{}
					case "expired_grant":
						g.Expires = time.Now().Add(-time.Second)
					case "refused_recovery":
						candidate.Result = installedarchive.RecoveryResult{Outcome: 5}
					case "stale_HEAD":
						candidate = publicationLossChangedRemoteHEAD(t, returned)
					case "wrong_namespace_domain":
						g.NamespaceDomain = testID("different domain")
					case "wrong_namespace_slot":
						g.NamespaceSlot = "other slot"
					}
					env, _, selected, err := publicationLossOpen(t, t.Context(), candidate, g, history, family, false, damage == "wrong_authority")
					if err == nil || selected != nil {
						t.Fatal("invalid new normal grant admitted")
					}
					if env.Store != nil {
						m := env.Store.(*memoryStore)
						if m.creates != 0 || m.cas != 0 {
							t.Fatal("refused admission mutated store")
						}
					}
					if env.Trust != nil && env.Trust.(*fixtureTrust).Calls() != 0 {
						t.Fatal("refused admission signed")
					}
				})
			}
			env, admitted, selected, err := publicationLossOpen(t, t.Context(), returned, grant, history, family, false, false)
			if err != nil || selected == nil {
				t.Fatal("independently granted normal admission refused", err)
			}
			if admitted.admission.composition != grant.Composition || !admitted.admission.endWorkInvocation.IsZero() || admitted.admission.current != nil || admitted.admission.entropy == nil || !bytes.Equal(selected.body, env.Store.(*memoryStore).objects[env.Store.Descriptor().HeadKey].Body) {
				t.Fatal("new grant identity or observed selection differs")
			}
			if env.Store.(*memoryStore).creates != 0 || env.Store.(*memoryStore).cas != 0 || env.Trust.(*fixtureTrust).Calls() != 0 {
				t.Fatal("new observation acquired mutation effects")
			}
			d, err := contract.DecodeGenesisDescriptorCore(admitted.admission.descriptor)
			if err != nil || d.InitID != publicationLossAuthorityData(returned.Domain).Init || d.DescriptorArtifactID != publicationLossAuthorityData(returned.Domain).DescriptorArtifact || d.ManifestArtifactID != publicationLossAuthorityData(returned.Domain).ManifestArtifact {
				t.Fatal("independent original authority recipe differs", err)
			}
		})
	}
}
