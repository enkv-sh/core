package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"enkv.sh/compositions/configuration"
	compositionfull "enkv.sh/compositions/full"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

var errPublicSuccessor = errors.New("public successor preparation refused")

// Keep only public predecessor facts from the committed reconstruction. The
// projection's exact HEAD pin must also be the restored selection's predecessor.
type publicSuccessorPredecessor struct {
	Control    contract.CurrentControl
	AccessRoot contract.ID
	Provenance core.ReconstructionProvenance
}

func successorProjectionPredecessor(ctx context.Context, projection *core.ReconstructionProjection) (publicSuccessorPredecessor, error) {
	var out publicSuccessorPredecessor
	provenance, ok := projection.Provenance()
	if ctx == nil || ctx.Err() != nil || !ok {
		return out, errPublicSuccessor
	}
	roots := 0
	for i, count := 0, projection.PartCount(); i < count; i++ {
		if ctx.Err() != nil {
			return publicSuccessorPredecessor{}, errPublicSuccessor
		}
		part, ok := projection.CopyPart(i)
		if !ok {
			return publicSuccessorPredecessor{}, errPublicSuccessor
		}
		if part.Kind != core.ReconstructionRootPart {
			clear(part.Body[:cap(part.Body)])
			continue
		}
		root, err := format.DecodeRoot(part.Body)
		valid := err == nil && roots == 0 && part.Ref.Kind == format.RootKind && part.Ref.Index == 0 &&
			part.Ref.Domain == provenance.Domain && part.Ref.Object == provenance.Snapshot &&
			root.Domain == provenance.Domain && root.Snapshot == provenance.Snapshot &&
			root.CurrentAccess.Core.DomainID == provenance.Domain && format.CheckReference(part.Ref, part.Body) == nil
		clear(part.Body[:cap(part.Body)])
		if !valid {
			return publicSuccessorPredecessor{}, errPublicSuccessor
		}
		roots++
		// DecodeRoot owns these public key bytes independently of part.Body.
		out.Control, out.AccessRoot = root.CurrentAccess.Core.CurrentControl, root.CurrentAccess.AccessRoot
	}
	current, ok := projection.Provenance()
	if roots != 1 || !ok || current != provenance || ctx.Err() != nil {
		return publicSuccessorPredecessor{}, errPublicSuccessor
	}
	out.Provenance = provenance
	return out, nil
}

// replacePublicSuccessor uses the same public installed operation as keys
// replace. The captured source remains intact; only the returned output pair is
// portable successor input. No connection, basis or proposal carrier is made.
type publicSuccessorOutcome struct {
	DomainID, OperationID, Revision contract.ID
	OutputPath                      string
	Result                          core.Result
}

func replacePublicSuccessor(ctx context.Context, absSource string, representation configuration.Format, original publicPairImage, model *configuration.Model, predecessor publicSuccessorPredecessor, nextSelector, scratchDir string) (outcome publicSuccessorOutcome, err error) {
	stage := preparationSuccessorSource
	defer func() {
		if err != nil {
			err = publicPreparationFailure{stage: stage, cause: err}
		}
	}()
	if ctx == nil || ctx.Err() != nil || representation != configuration.JSON || model == nil || !model.Resolved || !model.RecoveryEnabled ||
		!filepath.IsAbs(absSource) || filepath.Clean(absSource) != absSource || !filepath.IsAbs(scratchDir) || filepath.Clean(scratchDir) != scratchDir ||
		nextSelector == "" || nextSelector == model.Authority.SigningSelector {
		return outcome, errPublicSuccessor
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return outcome, errPublicSuccessor
	}
	for _, entry := range model.Entries {
		if entry.Generated != nil || entry.Secret && (entry.Retained == nil || len(entry.Sealed) != 0) {
			return outcome, errPublicSuccessor
		}
	}
	stage = preparationSuccessorCapture
	source, err := configuration.Capture(ctx, absSource, representation)
	if err != nil {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	locked, err := configuration.Parse(ctx, source)
	if err != nil || !original.matches(source) {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	stage = preparationSuccessorBasis
	_, descriptor, before, err := publicSourceBasis(locked)
	if err != nil || !successorSameLocation(locked.Provider, locked.Authority.SigningSelector, nextSelector) {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	stable := before.CurrentControl
	stable.AccessIncarnationID, stable.AccessGeneration = predecessor.Control.AccessIncarnationID, predecessor.Control.AccessGeneration
	if predecessor.Provenance.Domain != locked.DomainID || predecessor.Provenance.Revision.IsZero() || predecessor.AccessRoot.IsZero() || !reflect.DeepEqual(stable, predecessor.Control) {
		return outcome, errPublicSuccessor
	}
	before.CurrentControl = predecessor.Control
	stage = preparationSuccessorFiles
	if err := os.Mkdir(scratchDir, 0700); err != nil {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	outputPath := filepath.Join(scratchDir, "successor.json")
	var nonce contract.ID
	if _, err := rand.Read(nonce[:]); err != nil || nonce.IsZero() {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	stage = preparationSuccessorRestore
	command := compositionfull.ReplaceKeysConfiguration(ctx, nonce, absSource, representation, configuration.ReplacementRequest{
		Target: configuration.ReplaceAuthority, SigningSelector: nextSelector, Authorizer: contract.RecoverySigningRole}, outputPath)
	if command.Authority == nil || command.Recovery != nil || command.Recipient != nil || command.Observation != nil {
		return outcome, errPublicSuccessor
	}
	result := command.Authority
	outcome = publicSuccessorOutcome{DomainID: result.DomainID, OperationID: result.OperationID, Revision: result.Result.ObservedRevision, OutputPath: outputPath, Result: result.Result}
	if result.Result.Outcome != core.ObservedCurrent || result.DomainID != locked.DomainID || result.OperationID.IsZero() || result.RequestIdentity.IsZero() || outcome.Revision.IsZero() || command.Delivery.Status != "delivered" || command.Delivery.Failed || command.Delivery.CleanupFailed {
		return outcome, errPublicSuccessor
	}
	stage = preparationSuccessorDelivery
	if err := source.CheckUnchanged(ctx); err != nil {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	delivered, err := configuration.Capture(ctx, outputPath, representation)
	if err != nil {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	defer func() { err = errors.Join(err, delivered.Close()) }()
	parsed, err := configuration.Parse(ctx, delivered)
	if err != nil || parsed == nil || !parsed.Resolved || parsed.DomainID != locked.DomainID || parsed.Replacement == nil || parsed.Replacement.Request.Target != configuration.ReplaceAuthority || parsed.Replacement.Request.SigningSelector != nextSelector || parsed.Replacement.Request.Authorizer != contract.RecoverySigningRole || parsed.Replacement.RequestIdentity != result.RequestIdentity || !bytes.Equal(parsed.Replacement.SignedCandidate, parsed.Basis.Selection) {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	basis, _, after, err := publicSourceBasis(parsed)
	if err != nil || after.NormalSigning.KeySelector != nextSelector || bytes.Equal(after.NormalSigning.SPKI, before.NormalSigning.SPKI) || !successorPreservesControl(before, after) {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	selected, err := format.DecodeHead(basis.Selection)
	beforeDigest, digestErr := contract.ControlCoreDigest(before)
	if err != nil || digestErr != nil || selected.AuthKind != format.SuccessionAuth || selected.Succession == nil || selected.Core.Revision != outcome.Revision || selected.Core.PreviousRevision != predecessor.Provenance.Revision || selected.Core.PreviousDigest != predecessor.Provenance.HEADDigest || selected.Core.PreviousToken != predecessor.Provenance.HEADToken || selected.Succession.Subject.OperationID != outcome.OperationID || selected.Succession.Subject.ApprovalRole != contract.RecoverySigningRole || selected.Succession.Subject.ChangeMask != contract.SuccessionChangeNormalSigner || selected.Succession.Subject.BeforeAccessRoot != predecessor.AccessRoot || selected.Succession.Subject.BeforeControlDigest != beforeDigest || descriptor.Family != after.Provider {
		return outcome, errors.Join(errPublicSuccessor, err, digestErr)
	}
	if err := delivered.CheckUnchanged(ctx); err != nil {
		return outcome, errors.Join(errPublicSuccessor, err)
	}
	return outcome, nil
}

func successorSameLocation(family contract.Family, old, next string) bool {
	switch family {
	case contract.AWS:
		a, aok := contract.ParseAWSKeySelector(old, true)
		b, bok := contract.ParseAWSKeySelector(next, true)
		return aok && bok && a.Account == b.Account && a.Region == b.Region
	case contract.GCP:
		a, aok := contract.ParseGCPKeySelector(old, true)
		b, bok := contract.ParseGCPKeySelector(next, true)
		return aok && bok && a.Project == b.Project && a.Region == b.Region
	}
	return false
}

func successorPreservesControl(before, after contract.ControlCore) bool {
	if !contract.IncarnationCounterStep(before.AccessIncarnationID, before.AccessGeneration, after.AccessIncarnationID, after.AccessGeneration) ||
		!contract.IncarnationCounterStep(before.NormalSigning.Binding.ControlIncarnationID, before.NormalSigning.Binding.Epoch, after.NormalSigning.Binding.ControlIncarnationID, after.NormalSigning.Binding.Epoch) {
		return false
	}
	before.NormalSigning = after.NormalSigning
	before.AccessIncarnationID, before.AccessGeneration = after.AccessIncarnationID, after.AccessGeneration
	return reflect.DeepEqual(before, after)
}
