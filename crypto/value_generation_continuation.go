package crypto

import (
	"bytes"
	"context"
	"crypto/subtle"
	"slices"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

type generatedResultAdmission struct {
	Expected  contract.GeneratorResultExpectation
	Reference contract.GeneratorResultReference
}

func (a *generatedAdmission) admitSeed(material contract.OperationMaterialRecord, body []byte) bool {
	m := material.Core
	if _, err := contract.OperationMaterialRecordLength(material); err != nil || m.Schema != contract.CanonicalSchema || m.Profile != 2 || m.SeedEpoch != 1 ||
		m.DomainID != a.request.Context.DomainID || m.CompatibilityID != a.request.Context.CompatibilityID || m.CryptoSupportID != a.control.CryptoSupportID ||
		m.OperationID != a.graph.Header.OperationID || m.OperationMaterialID != a.request.MaterialID || m.UsePlanDigest != a.request.UsePlanDigest {
		return false
	}
	access, err := contract.DecodeAccessRecord(body)
	if err != nil || !a.accessBindingsValid(access) {
		return false
	}
	materialContext, err := contract.OperationMaterialContextDigest(m)
	if err != nil || access.MaterialKind != contract.OperationSeedMaterialKind || access.MaterialID != m.OperationMaterialID || access.MaterialContextDigest != materialContext || access.PackageCheck != material.SeedCheck {
		return false
	}
	want := 1
	if a.control.Recovery != nil {
		want++
	}
	if len(access.Wraps) != want || access.Wraps[0].SubjectKind != contract.OrdinaryWrapSubject || access.Wraps[0].SubjectID != a.control.AuthorityRecipientID ||
		a.control.Recovery != nil && (access.Wraps[1].SubjectKind != contract.RecoveryWrapSubject || access.Wraps[1].SubjectID != a.control.Recovery.RoleID) {
		return false
	}
	a.material, a.access = material, access
	return true
}

func (a *generatedAdmission) expectedResultMatches(expected contract.GeneratorResultExpectation) bool {
	input, err := contract.GeneratorResultInputEncoding(a.graph, expected.Template)
	if err != nil || expected.InputEncoding != input || expected.Validate(a.material) != nil || expected.Plan != a.graph.UsePlan {
		return false
	}
	matched := false
	for _, lineage := range a.graph.Lineages {
		for _, template := range lineage.Templates[:lineage.TemplateCount] {
			if template.AttemptID == expected.Template.AttemptID {
				matched = template == expected.Template
			}
		}
	}
	return matched && slices.Contains(a.graph.ResultUses, expected.Use)
}

func (a *generatedAdmission) openContinuation(ctx context.Context, route KeyAccess, out *contract.CryptoResponse) contract.CryptoResultCode {
	index := applyBindingIndex(a.bindings, a.control.AuthorityRecipientID)
	if index < 0 {
		return contract.CryptoInvalidAdmission
	}
	binding := a.bindings[index]
	core, err := custody.SeedWrapCore(a.material.Core, binding)
	if err != nil {
		return contract.CryptoInvalidAdmission
	}
	seed, code := openMaterialPacket(ctx, route, binding, core, a.access.Wraps[0], contract.CryptoStoredAuthenticationFailed, out)
	if code != contract.CryptoSuccess {
		return code
	}
	a.seed = seed
	check, err := custody.SeedCheck(a.material.Core, a.seed)
	if err != nil || subtle.ConstantTimeCompare(check[:], a.material.SeedCheck[:]) != 1 {
		return contract.CryptoStoredAuthenticationFailed
	}
	plan := a.purpose.plan()
	if plan != nil && len(plan.protections) > 0 {
		protections, err := contract.InspectGeneratedSourceProtections(a.material, plan.protections)
		if err != nil {
			return contract.CryptoInvalidAdmission
		}
		for i := 0; i < protections.Count(); i++ {
			row, err := protections.Row(i)
			if err != nil {
				return contract.CryptoInvalidAdmission
			}
			keys, err := custody.OpenTransfer(row.Transfer.Core, contract.TransferEnvelope(row.Transfer), a.seed)
			if err != nil {
				return contract.CryptoStoredAuthenticationFailed
			}
			clear(keys[:cap(keys)])
		}
	}
	if code := a.compareContinuationSources(ctx, route, out); code != contract.CryptoSuccess {
		return code
	}
	if final := a.purpose.final; final != nil {
		if len(final.results) != len(final.resultBodies) || len(final.validated) != 0 {
			return contract.CryptoInvalidAdmission
		}
		for i, body := range final.resultBodies {
			selected := final.results[i]
			if len(body) != int(selected.Reference.ResultLength) || contract.Hash(body) != selected.Reference.ResultBodyDigest {
				return contract.CryptoInvalidAdmission
			}
			result, err := contract.DecodeGeneratedResultRecord(body)
			if err != nil {
				return contract.CryptoInvalidAdmission
			}
			plain, err := custody.OpenGeneratedResult(selected.Expected, a.material, a.seed, result)
			clear(plain[:cap(plain)])
			if err != nil {
				return contract.CryptoStoredAuthenticationFailed
			}
			final.validated = append(final.validated, selected.Reference)
		}
		slices.SortFunc(final.validated, func(x, y contract.GeneratorResultReference) int { return bytes.Compare(x.ResultID[:], y.ResultID[:]) })
		if _, err := contract.GeneratorResultReferencesDescriptor(final.validated); err != nil {
			return contract.CryptoInvalidAdmission
		}
	}
	if final := a.purpose.final; final != nil && final.preparedImage != nil {
		var err error
		final.openedGrants, err = a.openCheckpointGrants(final.preparedImage)
		if err != nil {
			return contract.CryptoStoredAuthenticationFailed
		}
		return a.openFinalPreparation(ctx, route, out)
	}
	if final := a.purpose.final; final != nil && final.qualificationImage != nil {
		opened, err := a.openCheckpointGrants(final.qualificationImage)
		clear(opened)
		if err != nil {
			return contract.CryptoStoredAuthenticationFailed
		}
		return a.qualifyHistoricalPreparation(ctx, route, out)
	}
	return contract.CryptoSuccess
}

func (a *generatedAdmission) adoptResult(v contract.CryptoGeneratedAdoptRequestView, out *contract.CryptoResponse) contract.CryptoResultCode {
	adoption := a.purpose.adoption
	if adoption == nil || len(adoption.results) != 1 {
		return contract.CryptoInvalidAdmission
	}
	selected := adoption.results[0]
	if v.ExpectedResult.Digest != selected.Reference.ResultBodyDigest || v.ExpectedResult.Length != uint64(selected.Reference.ResultLength) ||
		v.ExpectedResult.Count != 1 || contract.Hash(v.Result) != selected.Reference.ResultBodyDigest || len(v.Result) != int(selected.Reference.ResultLength) {
		return contract.CryptoInvalidAdmission
	}
	result, err := contract.DecodeGeneratedResultRecord(v.Result)
	if err != nil {
		return contract.CryptoInvalidInput
	}
	plaintext, err := custody.OpenGeneratedResult(selected.Expected, a.material, a.seed, result)
	if err != nil {
		return contract.CryptoStoredAuthenticationFailed
	}
	clear(plaintext[:cap(plaintext)])
	out.Body, err = contract.EncodeCryptoGeneratedAdoptResult(contract.CryptoGeneratedAdoptResult{Result: v.Result})
	if err != nil {
		return contract.CryptoCustodyUnavailable
	}
	adoption.validated = []contract.GeneratorResultReference{selected.Reference}
	a.stage = contract.CryptoFreeze
	return contract.CryptoSuccess
}
