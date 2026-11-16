package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Inspect the already observed HEAD and native deliveries. Public Reader still
// owns selected-state authentication; these checks make no additional call.
func publicAssertInitialization(t testing.TB, ctx context.Context, input liveRunInput, source string, setupDigest contract.ID, product publicProductResult, head format.Head) {
	t.Helper()
	image := publicSourceImage(t, source)
	document := publicSourceDocument(t, source)
	reference, ok := document["generated"].(string)
	if !ok || reference == "" {
		t.Fatal("ready initialization generated reference unavailable")
	}
	generatedPath := filepath.Join(filepath.Dir(source), filepath.FromSlash(reference))
	generated := image.Files[generatedPath]
	var emitted struct {
		Basis struct {
			Kind       string
			Descriptor []byte
		} `json:"public_basis"`
	}
	if json.Unmarshal(generated, &emitted) != nil || emitted.Basis.Kind != "genesis" || reference != ".enkv/prod.generated.json" {
		t.Fatal("ready initialization did not deliver the exact genesis dependency")
	}
	d, err := contract.DecodeGenesisDescriptorCore(emitted.Basis.Descriptor)
	if err != nil || head.Core.Form != format.GenesisHead || head.AuthKind != format.GenesisAuth || head.Genesis == nil {
		t.Fatal("ready initialization descriptor or selected genesis is invalid")
	}
	mode := uint8(0)
	family := contract.AWS
	if input.Settings.Provider == "gcp" {
		family = contract.GCP
	}
	if input.RecoveryMode == "enabled" {
		mode = 1
	}
	g := head.Genesis
	root := g.Plan.Root
	if d.RecoveryMode() != mode || d.Provider != family || d.DomainID != head.Core.Domain || d.StoreID != head.Core.Store || d.CoordinateID != head.Core.Coordinate || d.NonBodyID != head.Core.NonBody || d.NormalSigning.KeySelector != input.Settings.KeyID ||
		g.Request.InitID != d.InitID || g.Request.DomainID != d.DomainID || g.Request.SetupDigest != setupDigest || g.Request.RecoveryMode != mode ||
		root.Domain != d.DomainID || root.Snapshot != head.Core.Root.Object || root.ValueEntryCount != 0 || root.SecretCount != 0 || root.RawBytes != 0 || root.MembershipCount != 0 || root.AccessRecordCount != 0 ||
		!reflect.DeepEqual(root.CurrentAccess.Core.CurrentControl, d.CurrentControl()) || len(d.Recipients) != 2 {
		t.Fatal("selected initialization differs from the exact empty setup and generated public basis")
	}
	selectors := map[string]bool{}
	for _, row := range d.Recipients {
		if row.Status != contract.CurrentRecipient || row.CurrentBinding == nil || selectors[row.CurrentBinding.KeySelector] {
			t.Fatal("initialization recipient enrollment is incomplete")
		}
		selectors[row.CurrentBinding.KeySelector] = true
	}
	if !selectors[input.Settings.AuthorityKEKID] || !selectors[input.Settings.ReaderKEKID] || mode == 1 && (d.Recovery.Signing.KeySelector != input.Settings.RecoveryKeyID || d.Recovery.KMS.KeySelector != input.Settings.RecoveryKEKID) {
		t.Fatal("initialization enrolled a different nominated public key")
	}
	identifier := func(id contract.ID) string { return hex.EncodeToString(id[:]) }
	descriptorDigest := contract.Hash(emitted.Basis.Descriptor)
	p := product.Payload
	if product.State != "success" || product.CommitUnknown || product.OperationPayload != "InitPayload/v1" || p.Schema != "InitPayload/v1" ||
		p.Init != identifier(d.InitID) || p.Domain != identifier(d.DomainID) || p.DescriptorArtifact != identifier(d.DescriptorArtifactID) || p.ManifestArtifact != identifier(d.ManifestArtifactID) ||
		p.DescriptorDigest != identifier(descriptorDigest) || p.Store != identifier(d.StoreID) || p.Revision != identifier(head.Core.Revision) || p.Snapshot != identifier(root.Snapshot) {
		t.Fatal("initialization result public identities differ from the selected genesis")
	}
	if len(product.Receipt) != 2*contract.CompactMutationReceiptLength {
		t.Fatal("ready initialization compact receipt is missing or unbounded")
	}
	receiptBody, err := hex.DecodeString(product.Receipt)
	if err != nil {
		t.Fatal("initialization receipt encoding refused")
	}
	requestIdentity, admittedIdentity := publicAdmittedRequestIdentity(product)
	receipt, err := contract.InspectCompactMutationReceipt(receiptBody)
	if err != nil || receipt.OperationKind != contract.OperationInitializeDomain || receipt.DomainID != d.DomainID || receipt.OperationID != d.InitID ||
		receipt.RequestIdentityDigest != g.Subject.RequestCoreDigest || !admittedIdentity || requestIdentity != identifier(receipt.RequestIdentityDigest) ||
		receipt.RequestedRevisionID != head.Core.Revision || receipt.ObservedRevisionID != head.Core.Revision || receipt.StateResult != contract.ReceiptStateSuccess || receipt.EffectSummary != contract.ReceiptEffectNoChange || receipt.CanonicalOutcome != contract.ReceiptCanonicalSelected {
		t.Fatal("initialization receipt does not bind the exact selected success")
	}
	manifestPath := filepath.Join(filepath.Dir(source), ".enkv", identifier(d.ManifestArtifactID)+".init")
	if product.Delivery.Outcome != "recorded" || product.Delivery.Editable != source || product.Delivery.Generated != generatedPath || product.Delivery.Manifest != manifestPath {
		t.Fatal("initialization native delivery paths differ from its original source")
	}
	manifestBody, err := ReadLocalProtectedFile(ctx, manifestPath, contract.GenesisBootstrapLimit)
	if err != nil {
		t.Fatal("exact bounded initialization manifest readback unavailable")
	}
	defer clear(manifestBody[:cap(manifestBody)])
	manifest, err := contract.DecodeGenesisBootstrapManifestCore(manifestBody)
	manifestDigest := contract.Hash(manifestBody)
	if err != nil || manifest.DescriptorDigest != descriptorDigest || manifestDigest != g.Subject.ManifestDigest || manifestDigest != g.Closure.ManifestDigest ||
		manifest.RequestCoreDigest != g.Subject.RequestCoreDigest || manifest.GenesisPlanDigest != g.Subject.GenesisPlanDigest || manifest.RecoveryMode != mode ||
		manifest.HeadCoreDigest != g.Subject.HeadCoreDigest || manifest.HeadCoreLength != g.Subject.HeadCoreLength || manifest.ConditionalPlanDigest != g.Subject.ConditionalPlanDigest ||
		len(manifest.Immutable) == 0 || manifest.Immutable[len(manifest.Immutable)-1] != head.Core.Root {
		t.Fatal("delivered initialization manifest differs from the selected bootstrap closure")
	}
	// These are selected facts issued by the existing native readback owners;
	// this assertion cannot create either durability receipt or init admission.
	wantDescriptor := contract.GenesisArtifactFact{Kind: 1, ArtifactID: d.DescriptorArtifactID, BodyDigest: descriptorDigest, BodyLength: uint64(len(emitted.Basis.Descriptor)), DurabilityProfile: 1, Outcome: 1}
	wantManifest := contract.GenesisArtifactFact{Kind: 2, ArtifactID: d.ManifestArtifactID, BodyDigest: manifestDigest, BodyLength: uint64(len(manifestBody)), DurabilityProfile: 1, Outcome: 1}
	if g.Closure.DescriptorReadbackFact != wantDescriptor || g.Closure.ManifestReadbackFact != wantManifest {
		t.Fatal("selected initialization does not bind the exact descriptor and manifest readback facts")
	}
	publicImageUnchanged(t, image)
}
