package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// selectedImage lends only selected public facts. It has no caller, Store,
// admission, write permission or discovery behavior.
type selectedImage struct {
	root                     format.Root
	pages                    [contract.MaxValueEntryPages]*format.ValueEntryPage
	recipients               [contract.MaxRecipientPages]*format.RecipientPage
	support                  []format.RequiredSupportPageView
	supportFacts             []selectedSupportPageFacts
	adminIndex               format.AdministrativeIndex
	administrativeIndexFacts *selectedAdministrativeIndexFacts
	publicationProof         *selectedPublicationProof
	publicationFacts         map[generatedRecordKey]selectedPublicationRecord
	access                   [contract.MaxChildPages]*format.AccessPage
	accessFacts              map[format.Ref]*format.AccessPage
	fragmentFacts            map[format.FragmentLocation]selectedFragmentFact
	generatedSliceLocations  []contract.GeneratorSliceLocation
	selectedReceiptIndexes   contract.MutationReceiptIndexes
	receiptWindows           contract.MutationReceiptWindows
	receiptsValidated        bool
	cache                    map[format.Ref][]byte
	outputConfigurationRoot  contract.ID
	generatedSlicesRoot      contract.ID
}

func (s *StateSession) selectedImage() *selectedImage {
	if s == nil {
		return nil
	}
	image := &selectedImage{root: s.root, pages: s.pages, recipients: s.recipients, support: s.support,
		supportFacts: s.supportFacts, adminIndex: s.adminIndex, administrativeIndexFacts: s.administrativeIndexFacts, publicationProof: s.publicationProof, publicationFacts: s.publicationFacts,
		access: s.access, accessFacts: s.accessFacts, fragmentFacts: s.fragmentFacts, generatedSliceLocations: s.generatedSliceLocations,
		selectedReceiptIndexes: s.selectedReceiptIndexes, cache: s.cache, outputConfigurationRoot: s.outputConfigurationRoot, generatedSlicesRoot: s.generatedSlicesRoot}
	if windows, found, err := s.retainedSelectedReceiptWindows(); found && err == nil {
		image.receiptWindows, image.receiptsValidated = windows, true
	}
	return image
}

func (s *StateSession) selectedImageView() selectedImage {
	if s == nil {
		return selectedImage{}
	}
	return *s.selectedImage()
}

func (s *StateSession) completeSelectedImage(ctx context.Context) (*selectedImage, error) {
	windows, err := s.receiptWindows(ctx)
	if err != nil {
		return nil, err
	}
	image := s.selectedImage()
	image.receiptWindows, image.receiptsValidated = windows, true
	return image, nil
}

func selectedSupportRecords(pages []format.RequiredSupportPageView) []contract.SupportRecord {
	var rows []contract.SupportRecord
	for _, page := range pages {
		for _, row := range page.Records {
			rows = append(rows, contract.SupportRecord(row))
		}
	}
	slices.SortFunc(rows, func(a, b contract.SupportRecord) int {
		if a.Kind < b.Kind {
			return -1
		}
		if a.Kind > b.Kind {
			return 1
		}
		return bytes.Compare(a.RecordID[:], b.RecordID[:])
	})
	return rows
}

func (s *selectedImage) valueEntry(slot uint16) *format.ValueEntry {
	return selectedValueEntry(&s.pages, slot)
}
func (s *selectedImage) recipientRecord(id contract.ID) *contract.RecipientRecord {
	return selectedRecipientRecord(&s.recipients, id)
}
func (s *selectedImage) supportRecords() []contract.SupportRecord {
	return selectedSupportRecords(s.support)
}
func (s *selectedImage) generatedCoverageRecords() []contract.AccessRecord {
	var rows []contract.AccessRecord
	for _, p := range s.access {
		if p != nil {
			rows = append(rows, p.Records...)
		}
	}
	return rows
}
func (s *selectedImage) resolveSelectedGeneratedSlices() ([]contract.GeneratorSliceLocation, error) {
	if s.generatedSliceLocations != nil {
		return s.generatedSliceLocations, nil
	}
	if s.fragmentFacts != nil {
		return format.ResolveGeneratedSliceLocations(s.root.Domain, s.adminIndex.SliceSnapshot, s.root.Generated.Slices, s.support)
	}
	return format.ResolveGeneratedSlices(s.root.Domain, s.adminIndex.SliceSnapshot, s.root.Generated, s.support)
}
