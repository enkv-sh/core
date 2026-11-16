package core

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// Only the installed reconstruction composition supplies this private factory
// after completePublicSelection. It has no plaintext sink or ordinary
// operation admission. The public candidate input cannot supply one.
type reconstructionVerifier = ReconstructionVerifier

type reconstructionVerifierFactory func(context.Context, contract.ReconstructionVerificationPins, time.Time) (reconstructionVerifier, error)

// WithValue wrappers keep the original cancellation domain. An unrelated
// context with an earlier deadline cannot inherit cancellation while a Store
// read or Crypto Verify blocks, so it cannot continue this private invocation.
func reconstructionInvocationCurrent(ctx context.Context, anchor anchoredPublicCandidate) bool {
	return !anchor.deadline.IsZero() && publicReadInvocationCurrent(ctx, anchor)
}

func (s *publicSelection) authorityBinding() (contract.BindingTableRow, bool) {
	if s == nil || s.authorityID.IsZero() || s.image.root.CurrentAccess.Core.AuthorityRecipientID != s.authorityID {
		return contract.BindingTableRow{}, false
	}
	r := selectedRecipientRecord(&s.image.recipients, s.authorityID)
	if r == nil || r.Status != format.Current || r.CurrentBinding == nil {
		return contract.BindingTableRow{}, false
	}
	row := contract.BindingTableRow{SubjectKind: contract.OrdinaryWrapSubject, SubjectID: s.authorityID, Binding: *r.CurrentBinding}
	if _, err := contract.BindingTableLength([]contract.BindingTableRow{row}); err != nil {
		return contract.BindingTableRow{}, false
	}
	return row, true
}

func (s *publicSelection) currentSecretSelection(slot uint16, pins contract.ReconstructionVerificationPins) (contract.ConsumerSelection, bool) {
	m := selectedValueEntry(&s.image.pages, slot)
	if m == nil || m.ConfidentialityClass != format.Secret || !slices.Contains(m.Recipients, s.authorityID) {
		return contract.ConsumerSelection{}, false
	}
	core, payload, access, ok := selectedValueFrom(s.image.root.Domain, s.image.root, &s.image.pages,
		&s.image.recipients, &s.image.access, s.materials.accessLocations, s.materials.valueReaders, slot)
	if !ok {
		return contract.ConsumerSelection{}, false
	}
	digest, err := contract.PublicValueEntryDigest(s.image.root.Domain, slot, *m)
	if err != nil {
		return contract.ConsumerSelection{}, false
	}
	return contract.ConsumerSelection{DomainID: pins.DomainID,
		SnapshotID: pins.SnapshotID, HEADDigest: pins.HEADDigest, HEADRevision: pins.HEADRevision,
		HEADToken: pins.HEADToken, Root: pins.Root, AccessRoot: pins.AccessRoot,
		Slot: slot, EntryDigest: digest, Entry: *m, Core: core, Payload: payload, Access: access,
		Binding: pins.AuthorityBinding}, true
}

func reconstructionVerifyFailure(code contract.CryptoResultCode) Result {
	switch code {
	case contract.CryptoStoredAuthenticationFailed:
		return failure(IntegrityFailure, InvalidProof)
	case contract.CryptoInvalidInput, contract.CryptoInvalidAdmission:
		return custodyFailure(code)
	case contract.CryptoCapacityExceeded:
		return refused(CapacityExceeded)
	case contract.CryptoAlreadyUsed:
		return refused(AlreadyUsed)
	default:
		return failure(EvidenceUnavailable, CustodyUnavailable)
	}
}

// verifyReconstructionSelection gives Crypto every current secret under one
// exact, verified selection. It returns no plaintext and no partial result.
// The final HEAD read is a separate observation after the verifier is joined.
func verifyReconstructionSelection(ctx context.Context, selected *publicSelection, factory reconstructionVerifierFactory) Result {
	if ctx == nil || selected == nil || !selected.complete || factory == nil || selected.basis.reader.source == nil ||
		selected.image.root.Domain != selected.basis.anchor.configuration.DomainID ||
		selected.image.root.Snapshot != selected.basis.anchor.root.Snapshot {
		return refused(AdmissionInvalid)
	}
	if !reconstructionInvocationCurrent(ctx, selected.basis.anchor) {
		return failure(EvidenceUnavailable, CustodyUnavailable)
	}
	deadline, _ := ctx.Deadline()
	binding, ok := selected.authorityBinding()
	if !ok {
		return failure(IntegrityFailure, InvalidRelation)
	}
	pins := contract.ReconstructionVerificationPins{DomainID: selected.image.root.Domain,
		SnapshotID: selected.image.root.Snapshot,
		HEADDigest: contract.Hash(selected.basis.anchor.headBody), HEADRevision: selected.basis.anchor.head.Core.Revision,
		HEADToken: selected.basis.anchor.headToken, Root: selected.basis.anchor.head.Core.Root,
		AccessRoot: selected.image.root.CurrentAccess.AccessRoot, AuthorityRecipientID: selected.authorityID,
		AuthorityBinding: binding}
	var secretCount uint32
	for _, named := range selected.image.root.Names {
		entry := selectedValueEntry(&selected.image.pages, named.Slot)
		if entry == nil {
			return failure(IntegrityFailure, InvalidRelation)
		}
		if entry.ConfidentialityClass != format.Secret {
			continue
		}
		if _, ok := selected.currentSecretSelection(named.Slot, pins); !ok {
			return failure(IntegrityFailure, InvalidRelation)
		}
		secretCount++
	}
	if secretCount != selected.image.root.SecretCount {
		return failure(IntegrityFailure, InvalidRelation)
	}
	verifier, err := factory(ctx, pins, deadline)
	if !reconstructionInvocationCurrent(ctx, selected.basis.anchor) {
		if verifier != nil {
			verifier.Close()
		}
		return failure(EvidenceUnavailable, CustodyUnavailable)
	}
	if err != nil || verifier == nil {
		if verifier != nil {
			verifier.Close()
		}
		if errors.Is(err, ErrReconstructionKeyMismatch) {
			return refused(ConstructionMismatch)
		}
		return failure(EvidenceUnavailable, CustodyUnavailable)
	}
	closed := false
	defer func() {
		if !closed {
			verifier.Close()
		}
	}()
	for _, named := range selected.image.root.Names {
		entry := selectedValueEntry(&selected.image.pages, named.Slot)
		if entry.ConfidentialityClass != format.Secret {
			continue
		}
		if !reconstructionInvocationCurrent(ctx, selected.basis.anchor) {
			return failure(EvidenceUnavailable, CustodyUnavailable)
		}
		choice, ok := selected.currentSecretSelection(named.Slot, pins)
		if !ok {
			return failure(IntegrityFailure, InvalidRelation)
		}
		if code := verifier.Verify(ctx, choice); code != contract.CryptoSuccess {
			return reconstructionVerifyFailure(code)
		}
	}
	verifier.Close()
	closed = true
	if !reconstructionInvocationCurrent(ctx, selected.basis.anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	read := selected.basis.reader.source.Read(ctx, selected.basis.reader.descriptor.HeadKey, contract.MaxHeadLength)
	if !reconstructionInvocationCurrent(ctx, selected.basis.anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	checked := ownCandidateRead(read, contract.MaxHeadLength, nil, 0)
	if checked.Status != contract.ReadOK {
		return candidateReadFailure(checked, true)
	}
	if checked.Token != selected.basis.anchor.headToken || !bytes.Equal(checked.Body, selected.basis.anchor.headBody) {
		return failure(Contention, DifferentSelection)
	}
	if !reconstructionInvocationCurrent(ctx, selected.basis.anchor) {
		return failure(EvidenceUnavailable, ReadUnavailable)
	}
	return Result{Outcome: ObservedCurrent, ObservedRevision: selected.basis.anchor.head.Core.Revision,
		ObservedSnapshotID: selected.image.root.Snapshot, Evidence: AuthenticatedClosure}
}
