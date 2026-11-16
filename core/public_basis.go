package core

import (
	"encoding/binary"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// PublicEnrollment contains historical public recipient facts retained with a
// genesis or succession basis. The authenticated current registry can differ.
type PublicEnrollment struct {
	RecipientID contract.ID
	Status      uint8
	DisplayName string
}

// PublicBasis carries one complete genesis, successor or independently anchored
// selected observation. It contains no credential or admission capability.
type PublicBasis struct {
	Descriptor, Control, Selection                []byte
	Enrollment                                    []PublicEnrollment
	SigningAnchor, StoreConfiguration, HEAD, Root []byte
	RecipientPages                                [][]byte
}

// OwnedCopy returns bounded evidence with independent mutable backing.
func (p PublicBasis) OwnedCopy() (PublicBasis, error) { return p.own() }

func (p PublicBasis) check() error {
	if len(p.Descriptor) > contract.GenesisDescriptorLimit || len(p.Control) > contract.ControlCoreMaxLength || len(p.Selection) > contract.MaxHeadLength || len(p.Enrollment) > contract.CryptoMaxRecipients {
		return contract.ErrRecordCapacity
	}
	observationEmpty := len(p.SigningAnchor) == 0 && len(p.StoreConfiguration) == 0 && len(p.HEAD) == 0 && len(p.Root) == 0 && len(p.RecipientPages) == 0
	if len(p.SigningAnchor) > contract.PublicSigningBindingMaxLength || len(p.StoreConfiguration) > contract.MaxStoreConfigurationLength || len(p.HEAD) > contract.MaxHeadLength || len(p.Root) > contract.MaxRootLength || len(p.RecipientPages) > contract.MaxRecipientPages {
		return contract.ErrRecordCapacity
	}
	for _, page := range p.RecipientPages {
		if len(page) == 0 || len(page) > format.MaxRecipientPage {
			return contract.ErrRecordCapacity
		}
	}
	genesis := observationEmpty && len(p.Descriptor) != 0 && len(p.Control) == 0 && len(p.Selection) == 0 && len(p.Enrollment) == 0
	successor := observationEmpty && len(p.Descriptor) == 0 && len(p.Control) != 0 && len(p.Selection) != 0 && len(p.Enrollment) != 0
	observation := len(p.Descriptor) == 0 && len(p.Control) == 0 && len(p.Selection) == 0 && len(p.Enrollment) == 0 && len(p.SigningAnchor) != 0 && len(p.StoreConfiguration) != 0 && len(p.HEAD) != 0 && len(p.Root) != 0 && len(p.RecipientPages) != 0
	if !genesis && !successor && !observation {
		return contract.ErrRecord
	}
	seen := make(map[contract.ID]bool, len(p.Enrollment))
	for _, row := range p.Enrollment {
		if row.RecipientID.IsZero() || seen[row.RecipientID] || len(row.DisplayName) > contract.CryptoMaxName || !utf8.ValidString(row.DisplayName) || row.Status != contract.CurrentRecipient && row.Status != contract.RetiredRecipient {
			return contract.ErrRecord
		}
		seen[row.RecipientID] = true
	}
	return nil
}

func (p PublicBasis) own() (PublicBasis, error) {
	if err := p.check(); err != nil {
		return PublicBasis{}, err
	}
	owned := PublicBasis{Descriptor: copyPublicBasisBytes(p.Descriptor), Control: copyPublicBasisBytes(p.Control), Selection: copyPublicBasisBytes(p.Selection), Enrollment: make([]PublicEnrollment, len(p.Enrollment))}
	owned.SigningAnchor, owned.StoreConfiguration, owned.HEAD, owned.Root = copyPublicBasisBytes(p.SigningAnchor), copyPublicBasisBytes(p.StoreConfiguration), copyPublicBasisBytes(p.HEAD), copyPublicBasisBytes(p.Root)
	if len(p.RecipientPages) != 0 {
		owned.RecipientPages = make([][]byte, len(p.RecipientPages))
		for i, page := range p.RecipientPages {
			owned.RecipientPages[i] = copyPublicBasisBytes(page)
		}
	}
	for i, row := range p.Enrollment {
		owned.Enrollment[i] = row
		owned.Enrollment[i].DisplayName = strings.Clone(row.DisplayName)
	}
	return owned, nil
}

func ReadLocalPublicBasis(path string) (PublicBasis, error) {
	image, err := readLocalReaderPublicBasis(path)
	if err != nil {
		return PublicBasis{}, err
	}
	basis := PublicBasis{Descriptor: image.Descriptor, Control: image.Control, Selection: image.Selection, SigningAnchor: image.SigningAnchor, StoreConfiguration: image.StoreConfiguration, HEAD: image.HEAD, Root: image.Root, RecipientPages: image.RecipientPages}
	if len(image.Enrollment) != 0 {
		rows, err := localEnrollment(image.Enrollment)
		if err != nil {
			return PublicBasis{}, err
		}
		basis.Enrollment = make([]PublicEnrollment, len(rows))
		for i, row := range rows {
			basis.Enrollment[i] = PublicEnrollment{RecipientID: row.id, Status: row.status, DisplayName: row.name}
		}
	}
	if err := basis.check(); err != nil {
		return PublicBasis{}, err
	}
	return basis, nil
}

// Control verifies all independently supplied basis facts before returning an
// owned public control. Parsing a key or a provider response cannot replace it.
func (p PublicBasis) ControlCore(domain contract.ID, store contract.Descriptor) (contract.ControlCore, error) {
	basis, reason := qualifyBorrowedReaderPublicBasis(p, domain, store)
	if reason != "" {
		return contract.ControlCore{}, ErrLocalAuthorityAdmission
	}
	body, err := contract.EncodeControlCore(basis.control)
	if err != nil {
		return contract.ControlCore{}, err
	}
	return contract.DecodeControlCore(body)
}

// MatchesCurrentControl checks an already authenticated current control against
// this independent basis. Access progress may advance; fixed control facts must
// remain exact. This comparison grants no current-state admission.
func (p PublicBasis) MatchesCurrentControl(domain contract.ID, store contract.Descriptor, current contract.ControlCore) bool {
	expected, err := p.ControlCore(domain, store)
	return err == nil && CurrentControlMatches(current, expected)
}

func publicBasisEnrollmentDigest(rows []recipientEnrollment) contract.ID {
	body := []byte("ENKV/public-basis-enrollment/v1\x00")
	body = binary.LittleEndian.AppendUint16(body, uint16(len(rows)))
	for _, row := range rows {
		body = append(body, row.id[:]...)
		body = append(body, row.status)
		body = binary.LittleEndian.AppendUint16(body, uint16(len(row.name)))
		body = append(body, row.name...)
	}
	return contract.Hash(body)
}

func copyPublicBasisBytes(body []byte) []byte {
	if body == nil {
		return nil
	}
	owned := make([]byte, len(body))
	copy(owned, body)
	return owned
}
