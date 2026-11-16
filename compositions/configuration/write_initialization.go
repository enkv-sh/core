package configuration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"

	"enkv.sh/core/contract"
	"enkv.sh/telemetry"
)

// InitializationDescriptor can be issued only by the operation-specific native
// pair commit. The trusted composition still checks it against Core's exact
// expected artifact before granting initialization admission.
type InitializationDescriptor struct {
	delivery   *PairDelivery
	fact       contract.GenesisArtifactFact
	manifestID contract.ID
}

func (d *InitializationDescriptor) Fact() (contract.GenesisArtifactFact, error) {
	if d == nil || d.delivery == nil || d.fact.Kind != 1 {
		return contract.GenesisArtifactFact{}, ErrArtifact
	}
	if _, err := contract.EncodeGenesisArtifactFact(d.fact); err != nil {
		return contract.GenesisArtifactFact{}, ErrArtifact
	}
	return d.fact, nil
}
func (d *InitializationDescriptor) Paths() (string, string) {
	if d == nil {
		return "", ""
	}
	return d.delivery.Paths()
}

// CommitInitialization binds the decoded descriptor fixed by Stage to exact
// expected artifact facts, then performs the ordinary native transaction. A
// caller-supplied model or success flag cannot manufacture this receipt.
func (s *EditSession) CommitInitialization(ctx context.Context, c *EditCandidate, artifactID contract.ID, length uint64, digest contract.ID) (*InitializationDescriptor, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpConfigurationWrite)
	d, err := s.commitInitialization(editCallContext(ctx, call), c, artifactID, length, digest, call)
	finishEditCall(call, err)
	return d, err
}

func (s *EditSession) commitInitialization(ctx context.Context, c *EditCandidate, artifactID contract.ID, length uint64, digest contract.ID, call *telemetry.Call) (*InitializationDescriptor, error) {
	if c == nil || c.descriptor.Kind != 1 || c.descriptor.ArtifactID != artifactID || c.descriptor.BodyLength != length || c.descriptor.BodyDigest != digest || c.manifestID.IsZero() {
		return nil, ErrArtifact
	}
	delivery, err := s.commit(ctx, c, call)
	if err != nil {
		return nil, err
	}
	return &InitializationDescriptor{delivery: delivery, fact: c.descriptor, manifestID: c.manifestID}, nil
}

// InitializationManifest certifies one exact decoded and read-back manifest.
// It has no exported mutable fields and grants no Core operation authority.
type InitializationManifest struct {
	fact             contract.GenesisArtifactFact
	descriptorDigest contract.ID
	path             string
}

func (m *InitializationManifest) Fact() (contract.GenesisArtifactFact, error) {
	if m == nil || m.path == "" || m.fact.Kind != 2 || m.descriptorDigest.IsZero() {
		return contract.GenesisArtifactFact{}, ErrArtifact
	}
	if _, err := contract.EncodeGenesisArtifactFact(m.fact); err != nil {
		return contract.GenesisArtifactFact{}, ErrArtifact
	}
	return m.fact, nil
}
func (m *InitializationManifest) Path() string {
	if m == nil {
		return ""
	}
	return m.path
}

// CaptureInitializationManifest fixes a bounded regular manifest for an exact
// restart observation. Decoding grants no persistence receipt or init authority.
func CaptureInitializationManifest(ctx context.Context, path string) ([]byte, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpInitializationManifest)
	body, err := captureInitializationManifest(editCallContext(ctx, call), path)
	finishEditCall(call, err)
	return body, err
}

func captureInitializationManifest(ctx context.Context, path string) (body []byte, resultErr error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrArtifact
	}
	image, err := capture(ctx, path, contract.GenesisBootstrapLimit)
	if err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	defer func() {
		if err := image.Close(); err != nil {
			body = nil
			resultErr = errors.Join(resultErr, err)
		}
	}()
	body = make([]byte, int(image.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(image, 0, image.Size()), body); err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	if _, err := contract.DecodeGenesisBootstrapManifestCore(body); err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	return body, nil
}

func PersistInitializationManifest(ctx context.Context, path string, artifactID contract.ID, body []byte, descriptor *InitializationDescriptor) (*InitializationManifest, error) {
	call := telemetry.Start(ctx, telemetry.ProviderApplication, telemetry.OpInitializationManifest)
	m, err := persistInitializationManifest(editCallContext(ctx, call), path, artifactID, body, descriptor, nativeEditIO(), call)
	finishEditCall(call, err)
	return m, err
}

func persistInitializationManifest(ctx context.Context, path string, artifactID contract.ID, body []byte, descriptor *InitializationDescriptor, operations editIO, call *telemetry.Call) (manifest *InitializationManifest, resultErr error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(body) == 0 || len(body) > contract.GenesisBootstrapLimit {
		return nil, ErrArtifact
	}
	descriptorFact, err := descriptor.Fact()
	if err != nil || artifactID != descriptor.manifestID {
		return nil, ErrArtifact
	}
	// The manifest is separately bounded and caller-owned; freeze it before its
	// decoded identity and the bytes sent to disk can diverge.
	fixed := bytes.Clone(body)
	decoded, err := contract.DecodeGenesisBootstrapManifestCore(fixed)
	if err != nil || decoded.DescriptorDigest != descriptorFact.BodyDigest {
		return nil, ErrArtifact
	}
	s := &EditSession{io: operations}
	image, err := s.emit(ctx, filepath.Dir(path), ".enkv-manifest-*", contract.GenesisBootstrapLimit, func(w io.Writer) error { _, err := w.Write(fixed); return err })
	if err != nil {
		return nil, err
	}
	temp := image.file.Name()
	defer func() {
		if err := closeEditImage(image, temp); err != nil {
			manifest = nil
			resultErr = errors.Join(resultErr, err)
		}
	}()
	image.path = path
	call.Checkpoint(telemetry.DiagnosticCandidatePersistence, telemetry.DiagnosticReasonNone)
	if err := s.flushCandidate(image); err != nil {
		return nil, err
	}
	if err := s.installInitializationArtifact(ctx, image); err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	call.Checkpoint(telemetry.DiagnosticCommitObservation, telemetry.DiagnosticReasonNone)
	if err := operations.readback(ctx, path, image, false); err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrArtifact, err)
	}
	fact := contract.GenesisArtifactFact{Kind: 2, ArtifactID: artifactID, BodyDigest: contract.Hash(fixed), BodyLength: uint64(len(fixed)), DurabilityProfile: 1, Outcome: 1}
	return &InitializationManifest{fact: fact, descriptorDigest: decoded.DescriptorDigest, path: path}, nil
}
