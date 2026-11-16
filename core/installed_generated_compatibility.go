package core

import (
	"bytes"
	"context"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/sdk/artifact/credentialroute"
	protocol "enkv.sh/sdk/protocols/generator"
)

func (s *StateSession) installedGeneratedRetirementCompatibility(ctx context.Context, i ApplyInstallation, row contract.GeneratorImplementation, meta contract.GeneratedEntryMetadata) (contract.GeneratedSupportHandoff, error) {
	if i.Generated == nil || i.Generated.CheckRetirementCompatibility == nil || meta.LifecycleMode != contract.GeneratorLifecycleManaged {
		return contract.GeneratedSupportHandoff{}, contract.ErrRecord
	}
	selected, err := s.selectedGeneratedWork(ctx)
	if err != nil {
		return contract.GeneratedSupportHandoff{}, err
	}
	evidence, ok := selected.records[generatedRecordKey{contract.GeneratedCreateEvidenceSupportKind, meta.CreateResultID}]
	if !ok {
		return contract.GeneratedSupportHandoff{}, contract.ErrRecord
	}
	original, err := contract.InspectGeneratedCreateEvidence(evidence.Body)
	if err != nil {
		return contract.GeneratedSupportHandoff{}, err
	}
	facts, err := contract.DecodeGeneratorSafeFacts(original.SafeFacts)
	if err != nil || !generatedResourceFactsMatch(facts, meta.ResourceDigest) {
		return contract.GeneratedSupportHandoff{}, contract.ErrRecord
	}
	intent, err := selected.readSelectedSlice(ctx, contract.GeneratorContentIntent, meta.IntentDigest, contract.GeneratorIntentMaxLength)
	if err != nil {
		return contract.GeneratedSupportHandoff{}, err
	}
	request, response, err := i.Generated.CheckRetirementCompatibility(ctx, row, intent, facts, meta.CompletionClass)
	if err != nil {
		return contract.GeneratedSupportHandoff{}, err
	}
	decoded, err := protocol.DecodeRetirementCompatibilityRequest(request)
	if err != nil {
		return contract.GeneratedSupportHandoff{}, err
	}
	accepted, err := protocol.DecodeValidationResponse(response)
	native, factsErr := contract.EncodeNativeGeneratorSafeFacts(facts)
	digest, digestErr := protocol.RetirementCompatibilityInputDigest(decoded)
	if err != nil || factsErr != nil || digestErr != nil || !accepted.Accepted || accepted.InputDigest != decoded.InputDigest || decoded.InputDigest != digest || decoded.CompletionClass != meta.CompletionClass || !bytes.Equal(decoded.Intent, intent) || !bytes.Equal(decoded.OriginalFacts, native) {
		return contract.GeneratedSupportHandoff{}, contract.ErrRecord
	}
	request, response = bytes.Clone(request), bytes.Clone(response)
	row.CredentialRoute = slices.Clone(row.CredentialRoute)
	route, err := credentialroute.Decode(row.CredentialRoute)
	if err != nil {
		return contract.GeneratedSupportHandoff{}, err
	}
	handoff := contract.GeneratedSupportHandoff{Implementation: row, CompatibilityRequest: request, CompatibilityResponse: response,
		Support: []contract.GeneratorSupportBinding{{Schema: contract.GeneratorSupportBindingSchema, Role: 7, ContractID: contract.ID(route.ContractID), ImplementationID: row.ExecutorID, PublicBindingDigest: row.CredentialRouteID, Binding: row.CredentialRoute}}}
	return handoff, nil
}
