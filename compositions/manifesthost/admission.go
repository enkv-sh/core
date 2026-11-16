// Package manifesthost admits and runs a separate native manifest executable.
// It grants no Reader authority and does not verify artifact correspondence.
package manifesthost

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
	protocol "enkv.sh/sdk/protocols/manifest-generator"
	"enkv.sh/telemetry"
)

// These sentinels support errors.Is. Only ErrUnsupported identifies a valid
// but unsupported family protocol; invalid evidence remains ErrAdmission.
var (
	ErrAdmission   = errors.New("manifest executable admission refused")
	ErrUnsupported = errors.New("manifest protocol unsupported")
	ErrProcess     = errors.New("manifest child incomplete")
)

// Native retains an authenticated executable expectation and scalar format
// declarations. Each settings or render call runs a separate child and rechecks
// its launch copy. Construct it with NewNative; the zero value is not usable.
type Native struct {
	path           string
	identity       artifact.DigestLength
	descriptor     manifest.ID
	format, config string
}

// Check validates measured family and dependency facts without executing a plugin.
// Only ErrUnsupported permits a release selector's semantic fallback.
func Check(ctx context.Context, m artifact.Metadata, dependency []byte) error {
	call := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostCheck)
	err := check(ctx, m, dependency)
	finishCall(call, err)
	return err
}
func check(ctx context.Context, m artifact.Metadata, dependency []byte) error {
	if ctx == nil {
		return ErrAdmission
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := artifact.EncodeMetadata(m); err != nil {
		return errors.Join(ErrAdmission, err)
	}
	facts, err := m.ManifestFacts()
	if err != nil || m.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		return ErrAdmission
	}
	encoded, err := artifact.EncodeDependency(m.BuildFacts())
	if err != nil || !bytes.Equal(encoded, dependency) || m.Family.Dependency.Length != uint64(len(dependency)) || m.Family.Dependency.SHA256 != artifact.Hash(dependency) {
		return ErrAdmission
	}
	dependencyID, err := artifact.DependencyID("manifest-generator", dependency)
	if err != nil || dependencyID != facts.DependencyManifestID {
		return ErrAdmission
	}
	if facts.Descriptor.Wire != (artifact.Contract{Kind: "wire", Identity: artifact.Digest(protocol.ProtocolID()).String(), Version: protocol.Version}) {
		return ErrUnsupported
	}
	return ctx.Err()
}

// NewNative authenticates exact bytes and retains only launch and declaration
// facts, without retaining mutable metadata or dependency backing. The context
// must be nonnil with a finite deadline. Metadata source trust belongs to the caller.
func NewNative(ctx context.Context, executable string, m artifact.Metadata, dependency []byte) (*Native, error) {
	call := telemetry.Start(ctx, telemetry.ProviderManifestHost, telemetry.OpManifestHostCheck)
	result, err := func() (*Native, error) {
		if err := check(ctx, m, dependency); err != nil {
			return nil, err
		}
		if executable == "" || len(executable) > 4096 || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable || strings.ContainsRune(executable, 0) {
			return nil, ErrAdmission
		}
		if _, finite := ctx.Deadline(); !finite {
			return nil, ErrAdmission
		}
		if err := artifact.VerifyExecutable(ctx, executable, m); err != nil {
			return nil, errors.Join(ErrAdmission, err)
		}
		facts, err := m.ManifestFacts()
		if err != nil {
			return nil, ErrAdmission
		}
		return &Native{path: strings.Clone(executable), identity: m.Executable, descriptor: manifest.ID(facts.DescriptorID), format: strings.Clone(facts.Descriptor.Manifest.FormatContractID), config: strings.Clone(facts.Descriptor.Manifest.ConfigContractID)}, nil
	}()
	finishCall(call, err)
	return result, err
}
