package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type materialIdentity struct {
	kind contract.MaterialKind
	id   contract.ID
}

type materialLocation struct{ page, row int }

type selectedMaterialFacts struct {
	accessLocations map[materialIdentity]materialLocation
	valueReaders    map[contract.ID][]contract.ID
}

// Indexes retain positions and public recipient IDs only. The authenticated
// page owners remain the sole ciphertext image. Rebuild for every candidate.
func (s *StateSession) indexSelectedMaterials() bool {
	facts, ok := indexSelectedMaterialFacts(s.root, &s.pages, &s.access, s.support)
	if !ok {
		return false
	}
	s.accessLocations, s.valueReaders = facts.accessLocations, facts.valueReaders
	return true
}

// Administrative admission proves current reader coverage and the binding of
// every present wrap. A skipped, authenticated canonical row can require extra
// readers; EndWork must read that row if its consumers survive the disposition.
func (s *StateSession) indexAdministrativeMaterials() bool {
	facts, ok := indexSelectedMaterialFacts(s.root, &s.pages, &s.access, s.support)
	if !ok || !s.adminIndex.Valid() || len(s.support) != len(s.adminIndex.Pages) {
		return false
	}
	incomplete := make(map[contract.ID]bool)
	for i, page := range s.adminIndex.Pages {
		logical := 0
		for _, span := range page.Spans {
			for range span.Count {
				if !page.ReadRequired && page.Rows[logical].Kind == contract.RetainedCanonicalSupportKind && len(s.support[i].Records) == 0 {
					if span.Mandatory || len(span.GroupIndexes) == 0 {
						return false
					}
					for _, owner := range span.GroupIndexes {
						kind := s.adminIndex.Groups[owner].OwnerKind
						if kind != format.AdministrativeGeneratedParent && kind != format.AdministrativeGeneratedDuty && kind != format.AdministrativeGeneratedHazard {
							return false
						}
					}
					incomplete[page.Rows[logical].RetainedMaterialID()] = true
				}
				logical++
			}
		}
	}
	for _, page := range s.access {
		if page == nil {
			continue
		}
		for _, row := range page.Records {
			readers := facts.valueReaders[row.MaterialID]
			if row.MaterialKind == contract.OperationSeedMaterialKind {
				readers = []contract.ID{s.root.CurrentAccess.Core.AuthorityRecipientID}
			} else if incomplete[row.MaterialID] {
				var present []contract.ID
				for _, wrap := range row.Wraps {
					if wrap.SubjectKind == contract.OrdinaryWrapSubject {
						present = append(present, wrap.SubjectID)
					}
				}
				for _, required := range readers {
					if !slices.Contains(present, required) {
						return false
					}
				}
				readers = present
			}
			if !s.validateMaterialWraps(row, readers) {
				return false
			}
			if row.MaterialKind == contract.ValueMaterialKind {
				facts.valueReaders[row.MaterialID] = readers
			}
		}
	}
	s.accessLocations, s.valueReaders = facts.accessLocations, facts.valueReaders
	return true
}

// indexSelectedMaterialFacts derives access positions and exact selected
// readers without using an ordinary caller admission.
func indexSelectedMaterialFacts(root format.Root, pages *[contract.MaxValueEntryPages]*format.ValueEntryPage, access *[contract.MaxChildPages]*format.AccessPage, support []format.RequiredSupportPageView) (selectedMaterialFacts, bool) {
	facts := selectedMaterialFacts{
		accessLocations: make(map[materialIdentity]materialLocation),
		valueReaders:    make(map[contract.ID][]contract.ID),
	}
	for i, page := range access {
		if page == nil {
			continue
		}
		for j, row := range page.Records {
			key := materialIdentity{row.MaterialKind, row.MaterialID}
			if _, exists := facts.accessLocations[key]; exists {
				return selectedMaterialFacts{}, false
			}
			facts.accessLocations[key] = materialLocation{i, j}
		}
	}
	for _, entry := range root.Names {
		m := selectedValueEntry(pages, entry.Slot)
		if m != nil && m.ConfidentialityClass == format.Secret {
			facts.valueReaders[m.ValueState] = append(facts.valueReaders[m.ValueState], m.Recipients...)
		}
	}
	for _, page := range support {
		for _, record := range page.Records {
			if record.Kind != contract.RetainedCanonicalSupportKind {
				continue
			}
			retained, err := contract.InspectRetainedCanonicalRecord(record.Body)
			if err != nil {
				return selectedMaterialFacts{}, false
			}
			for i := 0; i < retained.Entry.RecipientCount(); i++ {
				id, ok := retained.Entry.RecipientID(i)
				if !ok {
					return selectedMaterialFacts{}, false
				}
				facts.valueReaders[retained.Entry.ValueState] = append(facts.valueReaders[retained.Entry.ValueState], id)
			}
		}
	}
	for id, readers := range facts.valueReaders {
		slices.SortFunc(readers, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
		facts.valueReaders[id] = slices.Compact(readers)
	}
	return facts, true
}

func (s *StateSession) materialAccess(kind contract.MaterialKind, id contract.ID) (contract.AccessRecord, bool) {
	return selectedMaterialAccess(&s.access, s.accessLocations, kind, id)
}

func selectedMaterialAccess(access *[contract.MaxChildPages]*format.AccessPage, locations map[materialIdentity]materialLocation, kind contract.MaterialKind, id contract.ID) (contract.AccessRecord, bool) {
	location, ok := locations[materialIdentity{kind, id}]
	if !ok || location.page >= len(access) {
		return contract.AccessRecord{}, false
	}
	page := access[location.page]
	if page == nil || location.row >= len(page.Records) {
		return contract.AccessRecord{}, false
	}
	row := page.Records[location.row]
	return row, row.MaterialKind == kind && row.MaterialID == id
}

func sameRetainedEntryValue(a, b contract.ValueEntry) bool {
	ag, bg := a.Generated, b.Generated
	ag.RetirementMode, ag.RetiringDutyPresent, ag.RetiringDutyID = 0, 0, contract.ID{}
	bg.RetirementMode, bg.RetiringDutyPresent, bg.RetiringDutyID = 0, 0, contract.ID{}
	return a.Name == b.Name && a.Incarnation == b.Incarnation && a.ValueState == b.ValueState && a.OriginSnapshot == b.OriginSnapshot &&
		a.OriginTransition == b.OriginTransition && a.InputEncoding == b.InputEncoding && a.ContentLength == b.ContentLength && a.RetainedLength == b.RetainedLength && a.ValueSource == b.ValueSource && a.ConfidentialityClass == b.ConfidentialityClass && ag == bg && bytes.Equal(a.ValueBytes, b.ValueBytes)
}

func (s *StateSession) validateValueAccess(core contract.ValueCore, payload contract.CanonicalPayload, access contract.AccessRecord, readers []contract.ID) bool {
	return selectedValueAccess(s.root, &s.recipients, core, payload, access, readers)
}

func selectedValueAccess(root format.Root, recipients *[contract.MaxRecipientPages]*format.RecipientPage, core contract.ValueCore, payload contract.CanonicalPayload, access contract.AccessRecord, readers []contract.ID) bool {
	context, err := contract.ValueMaterialContextDigest(core)
	return err == nil && access.MaterialKind == contract.ValueMaterialKind && access.MaterialID == core.ValueStateID && access.MaterialContextDigest == context &&
		access.PackageCheck == payload.PackageCheck && selectedMaterialWraps(root, recipients, access, readers)
}

func (s *StateSession) validateMaterialWraps(access contract.AccessRecord, readers []contract.ID) bool {
	return selectedMaterialWraps(s.root, &s.recipients, access, readers)
}

func selectedMaterialWraps(root format.Root, recipients *[contract.MaxRecipientPages]*format.RecipientPage, access contract.AccessRecord, readers []contract.ID) bool {
	if _, err := contract.AccessRecordLength(access); err != nil || len(readers) == 0 {
		return false
	}
	recovery := root.CurrentAccess.Core.Recovery
	if len(access.Wraps) != len(readers)+boolInt(recovery != nil) {
		return false
	}
	for i, wrap := range access.Wraps {
		var binding *contract.KMSBinding
		if i < len(readers) {
			r := selectedRecipientRecord(recipients, readers[i])
			if r == nil || r.Status != format.Current || r.CurrentBinding == nil || wrap.SubjectKind != contract.OrdinaryWrapSubject || wrap.SubjectID != r.RecipientID {
				return false
			}
			binding = r.CurrentBinding
		} else {
			if recovery == nil || wrap.SubjectKind != contract.RecoveryWrapSubject || wrap.SubjectID != recovery.RoleID {
				return false
			}
			binding = &recovery.KMS
		}
		digest, err := contract.PublicBindingDigest(*binding)
		if err != nil || wrap.BindingID != binding.BindingID || wrap.BindingSerial != binding.BindingSerial || wrap.PublicBindingDigest != digest {
			return false
		}
	}
	return true
}
