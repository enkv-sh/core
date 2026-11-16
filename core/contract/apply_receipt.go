package contract

import (
	"bytes"
	"slices"
)

// CryptoApplyReceiptAdmission is private-parent installation input. It is not
// a Crypto request, serializable fact, or replacement support body.
type CryptoApplyReceiptAdmission struct {
	OperationKind                      uint16
	ChangedSubjects                    GeneratorDescriptor
	LiveDuties, LiveHazards            GeneratorDescriptor
	Context                            ApplyContext
	OperationRef                       ID
	IdentityPlanDescriptor             DescriptorVector
	Delta                              MutationReceiptDelta
	AfterSupport, CandidatePublicState DescriptorVector
}

// RequiredSupportReceiptPlanDescriptor permits exactly one new receipt's
// request-identity hole. It returns a plan digest, never inspected row facts.
func RequiredSupportReceiptPlanDescriptor(domain ID, rows []SupportRecord, facts []SupportRecordDigest, plan CompactMutationReceiptPlan) (DescriptorVector, error) {
	body, err := AppendCompactMutationReceiptPlan(nil, plan)
	if err != nil || plan.DomainID != domain || len(rows) != len(facts) {
		return DescriptorVector{}, ErrRecord
	}
	projected := slices.Clone(facts)
	found := false
	for i, row := range rows {
		if row.Kind == MutationReceiptSupportKind && row.RecordID == plan.OperationID {
			if found || !bytes.Equal(row.Body, body) || facts[i] != (SupportRecordDigest{}) {
				return DescriptorVector{}, ErrRecord
			}
			found = true
			projected[i] = SupportRecordDigest{kind: row.Kind, recordID: row.RecordID, bodyDigest: Hash(body), bodyLength: uint32(len(body)), domain: domain, inspected: true}
			continue
		}
		fact := facts[i]
		if fact.Kind() != row.Kind || fact.RecordID() != row.RecordID {
			return DescriptorVector{}, ErrRecord
		}
		if row.Body != nil {
			actual, err := InspectSupportRecordDigest(domain, row)
			if err != nil || actual != fact {
				return DescriptorVector{}, ErrRecord
			}
		} else if row.Kind != GeneratedFragmentSupportKind && row.Kind != OutputConfigurationSliceSupportKind {
			return DescriptorVector{}, ErrRecord
		}
	}
	if !found {
		return DescriptorVector{}, ErrRecord
	}
	return RequiredSupportDescriptorFromDigests(domain, projected)
}
