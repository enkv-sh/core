package crypto

import (
	"bytes"
	"context"

	"enkv.sh/core/contract"
)

func controlBindingsValid(control contract.ControlCore, bindings []contract.BindingTableRow) bool {
	if _, err := contract.ControlCoreLength(control); err != nil {
		return false
	}
	if _, err := contract.BindingTableLength(bindings); err != nil {
		return false
	}
	authority, recovery := 0, 0
	for _, row := range bindings {
		if row.Binding.Provider != control.Provider {
			return false
		}
		if row.SubjectKind == contract.OrdinaryWrapSubject && row.SubjectID == control.AuthorityRecipientID {
			if !sameApplyBinding(row.Binding, control.AuthorityKMSBinding) {
				return false
			}
			authority++
		}
		if row.SubjectKind == contract.RecoveryWrapSubject {
			if control.Recovery == nil || row.SubjectID != control.Recovery.RoleID || !sameApplyBinding(row.Binding, control.Recovery.KMS) {
				return false
			}
			recovery++
		}
	}
	return authority == 1 && (control.Recovery == nil && recovery == 0 || control.Recovery != nil && recovery == 1)
}

func sameAccessRecord(a, b contract.AccessRecord) bool {
	x, err := contract.EncodeAccessRecord(a)
	if err != nil {
		return false
	}
	y, err := contract.EncodeAccessRecord(b)
	return err == nil && bytes.Equal(x, y)
}

func openMaterialPacket(ctx context.Context, route KeyAccess, binding contract.BindingTableRow, core contract.WrapCore, wrap contract.WrapRow, authenticationFailure contract.CryptoResultCode, out *contract.CryptoResponse) ([]byte, contract.CryptoResultCode) {
	if ctx.Err() != nil {
		return nil, contract.CryptoCancelled
	}
	if route == nil || !applyWrapMatches(wrap, core) {
		return nil, contract.CryptoInvalidAdmission
	}
	context, err := contract.RSAPacketContextDigest(core)
	if err != nil {
		return nil, contract.CryptoInvalidInput
	}
	private := route.Decrypt(ctx, binding.Binding, wrap.RSACiphertext, core.PacketLength)
	defer clear(private.Packet[:cap(private.Packet)])
	if !appendKeyUses(out, binding, contract.KeyUseMaterialOpen, private.Uses, 1) {
		return nil, contract.CryptoResponseUnknown
	}
	if ctx.Err() != nil {
		return nil, contract.CryptoCancelled
	}
	keys, code := privatePacketKeys(private, core.PacketKind, context, authenticationFailure)
	if code != contract.CryptoSuccess {
		return nil, code
	}
	return bytes.Clone(keys), contract.CryptoSuccess
}
