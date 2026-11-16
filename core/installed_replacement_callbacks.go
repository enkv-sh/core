package core

import (
	"bytes"
	"slices"

	"enkv.sh/core/contract"
)

func replacementCallbackAccess(q contract.CryptoAccessReplaceRequest) (contract.CryptoAccessReplaceRequest, error) {
	body, err := contract.EncodeCryptoAccessReplaceRequest(q)
	if err != nil {
		return contract.CryptoAccessReplaceRequest{}, err
	}
	return contract.DecodeCryptoAccessReplaceRequest(body)
}
func replacementCallbackControl(control contract.ControlCore) (contract.ControlCore, error) {
	body, err := contract.EncodeControlCore(control)
	if err != nil {
		return contract.ControlCore{}, err
	}
	return contract.DecodeControlCore(body)
}
func replacementCallbackRows(rows []contract.CompactRow) []contract.CompactRow {
	owned := slices.Clone(rows)
	for i := range owned {
		owned[i].Coverage.TargetBindingIndices = slices.Clone(rows[i].Coverage.TargetBindingIndices)
		owned[i].BeforeAccessRecord.Wraps = slices.Clone(rows[i].BeforeAccessRecord.Wraps)
		for j := range owned[i].BeforeAccessRecord.Wraps {
			owned[i].BeforeAccessRecord.Wraps[j].RSACiphertext = bytes.Clone(rows[i].BeforeAccessRecord.Wraps[j].RSACiphertext)
		}
	}
	return owned
}
func replacementCallbackRoleRequest(request contract.SuccessionRequestCore) (contract.SuccessionRequestCore, error) {
	owned := request
	var err error
	owned.BeforeControl, err = replacementCallbackControl(request.BeforeControl)
	if err != nil {
		return contract.SuccessionRequestCore{}, err
	}
	owned.ProposedAfterControl, err = replacementCallbackControl(request.ProposedAfterControl)
	if err != nil {
		return contract.SuccessionRequestCore{}, err
	}
	owned.IdentityPlan.Rows = slices.Clone(request.IdentityPlan.Rows)
	owned.IdentityPlan.Pages = slices.Clone(request.IdentityPlan.Pages)
	owned.ReplacementPlan.Rows = slices.Clone(request.ReplacementPlan.Rows)
	for i, row := range owned.ReplacementPlan.Rows {
		row.BeforeSigning.SPKI = bytes.Clone(row.BeforeSigning.SPKI)
		row.AfterSigning.SPKI = bytes.Clone(row.AfterSigning.SPKI)
		row.BeforeKMS.SPKI = bytes.Clone(row.BeforeKMS.SPKI)
		row.AfterKMS.SPKI = bytes.Clone(row.AfterKMS.SPKI)
		owned.ReplacementPlan.Rows[i] = row
	}
	return owned, nil
}
