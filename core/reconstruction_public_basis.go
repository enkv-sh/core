package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

func observationImage(p PublicBasis) (format.Head, selectedImage, contract.StoreConfiguration, bool) {
	var image selectedImage
	config, err := contract.DecodeStoreConfiguration(p.StoreConfiguration)
	if err != nil {
		return format.Head{}, image, config, false
	}
	canonical, err := contract.EncodeStoreConfiguration(config)
	if err != nil || !bytes.Equal(canonical, p.StoreConfiguration) {
		return format.Head{}, image, config, false
	}
	head, err := format.DecodeHead(p.HEAD)
	if err != nil {
		return head, image, config, false
	}
	canonical, err = format.EncodeHead(head)
	if err != nil || !bytes.Equal(canonical, p.HEAD) {
		return head, image, config, false
	}
	image.root, err = format.DecodeRoot(p.Root)
	if err != nil || format.CheckReference(head.Core.Root, p.Root) != nil || head.Core.Root.Kind != contract.RootKind || head.Core.Root.Index != 0 || image.root.Domain != head.Core.Domain || image.root.Snapshot != head.Core.Root.Object {
		return head, image, config, false
	}
	selected := 0
	for index, ref := range image.root.Recipients {
		if ref == nil {
			continue
		}
		if selected >= len(p.RecipientPages) || ref.Kind != contract.RecipientKind || int(ref.Index) != index || ref.Domain != image.root.Domain || format.CheckReference(*ref, p.RecipientPages[selected]) != nil {
			return head, image, config, false
		}
		page, err := format.DecodeRecipientPage(p.RecipientPages[selected])
		if err != nil || page.Domain != image.root.Domain || page.Object != ref.Object || int(page.Index) != index {
			return head, image, config, false
		}
		image.recipients[index] = &page
		selected++
	}
	return head, image, config, selected == len(p.RecipientPages)
}

func qualifyObservationBasis(p PublicBasis, domain contract.ID, store contract.Descriptor) (readerPublicBasis, contract.DiagnosticReason) {
	invalid := func() (readerPublicBasis, contract.DiagnosticReason) {
		return readerPublicBasis{}, contract.ReasonTrustBasisInvalid
	}
	head, image, config, ok := observationImage(p)
	if !ok {
		return invalid()
	}
	configID, err := contract.StoreConfigurationID(config)
	if err != nil || !store.Valid() || configID != store.Identity || config.DomainID != domain || config.Provider != store.Family || config.PrefixBeforeHEAD != store.Prefix || store.HeadKey != config.PrefixBeforeHEAD+"/HEAD" || head.Core.Domain != domain || head.Core.Store != store.Identity || head.Core.Coordinate != store.Coordinate || head.Core.NonBody != store.NonBody {
		return readerPublicBasis{}, contract.ReasonStoreBasisInvalid
	}
	anchor, err := contract.DecodePublicSigningBinding(p.SigningAnchor)
	if err != nil {
		return invalid()
	}
	canonical, err := contract.EncodePublicSigningBinding(anchor)
	if err != nil || !bytes.Equal(canonical, p.SigningAnchor) {
		return invalid()
	}
	selected, ok := candidateSelectionSignature(head, image.root, anchor.Role)
	if !ok || !signingBindingEqual(selected, anchor) {
		return invalid()
	}
	ids := make(map[contract.ID]bool)
	add := func(id contract.ID) bool {
		if id.IsZero() || ids[id] {
			return false
		}
		ids[id] = true
		return true
	}
	if !add(image.root.Snapshot) || !add(image.root.Transition) || !add(head.Core.Revision) {
		return invalid()
	}
	if !selectedRegistryIdentities(image.root, &image.recipients, add) {
		return invalid()
	}
	enrollment := make([]recipientEnrollment, 0, image.root.RecipientCount)
	for _, page := range image.recipients {
		if page == nil {
			continue
		}
		for _, row := range page.Slots {
			if row == nil {
				continue
			}
			enrollment = append(enrollment, recipientEnrollment{id: row.RecipientID, status: row.Status, name: row.DisplayName})
		}
	}
	control, ok := selectedControlFrom(image.root, &image.recipients, image.root.CurrentAccess.Core.AuthorityRecipientID)
	if !ok {
		return invalid()
	}
	basis := readerPublicBasis{control: control, enrollment: enrollment, observation: &p}
	var genesis *contract.GenesisDescriptorCore
	if head.AuthKind == format.GenesisAuth {
		derived, ok := selectedGenesisClosure(head, &image, config)
		if !ok {
			return invalid()
		}
		genesis = &derived
		basis.genesis = true
		basis.genesisDigest = head.Genesis.Subject.DescriptorDigest
	}
	if !selectedHeadProofs(head, control, genesis) || head.AuthKind == format.SuccessionAuth && !intrinsicSuccessionSelection(head, image.root, control) {
		return invalid()
	}
	h := sha256.New()
	h.Write([]byte("ENKV/public-basis-observation/v1\x00"))
	for _, body := range append([][]byte{p.SigningAnchor, p.StoreConfiguration, p.HEAD, p.Root}, p.RecipientPages...) {
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(len(body)))
		h.Write(length[:])
		h.Write(body)
	}
	copy(basis.digest[:], h.Sum(nil))
	return basis, ""
}

func (b readerPublicBasis) successionSelected(head format.Head) bool {
	if b.observation != nil {
		return savedSuccessionSelected(b.observation.HEAD, head)
	}
	return qualifiedPredecessorSelected(b.current, head)
}
func (b readerPublicBasis) genesisSelected(head format.Head) bool {
	return b.genesis && head.Genesis != nil && head.Genesis.Subject.DescriptorDigest == b.genesisDigest
}
func (p *PublicBasis) clear() {
	if p == nil {
		return
	}
	for _, body := range [][]byte{p.Descriptor, p.Control, p.Selection, p.SigningAnchor, p.StoreConfiguration, p.HEAD, p.Root} {
		clear(body)
	}
	for _, body := range p.RecipientPages {
		clear(body)
	}
	clear(p.Enrollment)
	*p = PublicBasis{}
}
