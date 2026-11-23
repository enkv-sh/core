package plugininstallation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"enkv.sh/sdk/artifact"
)

type retainedLocator struct {
	Schema   string           `json:"schema"`
	Executor artifact.Digest  `json:"executor"`
	Artifact artifact.Digest  `json:"artifact"`
	Proof    *artifact.Digest `json:"proof"`
}

func encodeLocator(v retainedLocator) ([]byte, error) {
	if v.Schema != "enkv/plugin-retained/v1" || v.Executor.IsZero() || v.Artifact.IsZero() || v.Proof != nil && v.Proof.IsZero() {
		return nil, ErrInvalid
	}
	body, err := json.Marshal(v)
	if err != nil || len(body) > 1024 {
		return nil, errors.Join(ErrInvalid, err)
	}
	return body, nil
}
func decodeLocator(body []byte) (retainedLocator, error) {
	var v retainedLocator
	if len(body) > 1024 || json.Unmarshal(body, &v) != nil {
		return v, ErrInvalid
	}
	canonical, err := encodeLocator(v)
	if err != nil || !bytes.Equal(canonical, body) {
		return retainedLocator{}, ErrInvalid
	}
	return v, nil
}
func (c *Coordinator) locatorPath(executor artifact.Digest) string {
	return filepath.Join(c.store, "retained", "generator", executor.String()+".json")
}

func (c *Coordinator) fromLocator(ctx context.Context, locator retainedLocator) (*Installed, error) {
	if locator.Proof != nil {
		return c.official(ctx, artifact.Selection{Artifact: locator.Artifact, Proof: *locator.Proof}, true)
	}
	path := filepath.Join(c.store, "builds", locator.Artifact.String())
	contents, err := localContents(ctx, path, locator.Artifact)
	if err != nil {
		return nil, err
	}
	if err := c.validate(ctx, path, contents, true); err != nil {
		return nil, err
	}
	return &Installed{path: filepath.Join(path, "plugin"), metadata: contents.MetadataBytes, dependency: contents.DependencyBytes, identity: locator.Artifact, source: "local"}, nil
}

func (c *Coordinator) remember(ctx context.Context, installed *Installed) (err error) {
	metadata, err := installed.Metadata()
	if err != nil {
		return err
	}
	if metadata.Role != "generator" {
		return nil
	}
	family, err := metadata.GeneratorFacts()
	if err != nil {
		return err
	}
	locator := retainedLocator{Schema: "enkv/plugin-retained/v1", Executor: family.ExecutorID, Artifact: installed.identity, Proof: installed.proof}
	body, err := encodeLocator(locator)
	if err != nil {
		return err
	}
	path := c.locatorPath(locator.Executor)
	if err := ensureDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	unlock, err := lock(ctx, path+".lock")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	verified, err := c.fromLocator(ctx, locator)
	if err != nil {
		return err
	}
	if !bytes.Equal(verified.metadata, installed.metadata) || !bytes.Equal(verified.dependency, installed.dependency) || verified.path != installed.path {
		return ErrIdentity
	}
	previous, readErr := readFile(ctx, path, 1024)
	if readErr == nil {
		prior, err := decodeLocator(previous)
		if err != nil || prior.Executor != locator.Executor {
			return errors.Join(ErrIdentity, err)
		}
		old, err := c.fromLocator(ctx, prior)
		if err != nil {
			return err
		}
		oldMetadata, err := old.Metadata()
		if err != nil {
			return err
		}
		oldFamily, err := oldMetadata.GeneratorFacts()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(oldFamily, family) || !bytes.Equal(old.dependency, installed.dependency) || !reflect.DeepEqual(oldMetadata.Executable, metadata.Executable) {
			return ErrIdentity
		}
		if bytes.Equal(previous, body) {
			return nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	_, err = atomicRecord(ctx, path, body, nil)
	return err
}

// RetainedSupportRefused reports a conclusive failure to match the retained
// installation. A joined read, close or cancellation error keeps the lookup
// inconclusive even when another cause identifies damaged or absent support.
func RetainedSupportRefused(err error) bool {
	return onlyCauses(err, func(cause error) bool {
		switch cause {
		case ErrMissing, ErrInvalid, ErrIdentity, ErrIncompatible, ErrSignature, artifact.ErrSignature, artifact.ErrRecord:
			return true
		}
		return errors.Is(cause, os.ErrNotExist)
	})
}

// ResolveRetained accepts an exact check supplied only by the trusted
// composition from Core's authenticated original tuple. The check must use the
// original dependency decoder/domain, exact descriptor and credential-route
// facts. A request/configuration tuple is not an authentication source. This
// method does not select a fresh-work installation.
func (c *Coordinator) ResolveRetained(ctx context.Context, executor artifact.Digest, check Check) (installed *Installed, err error) {
	ctx, call := startCall(ctx, opRetained)
	installed, err = c.resolveRetained(ctx, executor, check)
	finishCall(call, err)
	return installed, err
}

func (c *Coordinator) resolveRetained(ctx context.Context, executor artifact.Digest, check Check) (installed *Installed, err error) {
	if c == nil || executor.IsZero() || check == nil {
		return nil, ErrInvalid
	}
	body, err := readFile(ctx, c.locatorPath(executor), 1024)
	if err != nil {
		return nil, missing(err)
	}
	locator, err := decodeLocator(body)
	if err != nil || locator.Executor != executor {
		return nil, errors.Join(ErrInvalid, err)
	}
	installed, err = c.fromLocator(ctx, locator)
	if err != nil {
		return nil, err
	}
	metadata, err := installed.Metadata()
	if err != nil {
		return nil, err
	}
	family, err := metadata.GeneratorFacts()
	if err != nil || family.ExecutorID != executor {
		return nil, errors.Join(ErrIdentity, err)
	}
	if err := check(ctx, metadata, installed.DependencyBytes()); err != nil {
		return nil, err
	}
	return installed, nil
}

// RestoreRetainedOfficial uses independently restored exact packaging/proof
// coordinates and the same authenticated-original-tuple check as retained use.
// It does not consult latest releases, local settings or current selections.
func (c *Coordinator) RestoreRetainedOfficial(ctx context.Context, artifactID, proofID artifact.Digest, check Check) (*Installed, error) {
	if artifactID.IsZero() || proofID.IsZero() || check == nil {
		return nil, ErrInvalid
	}
	selection := artifact.Selection{Artifact: artifactID, Proof: proofID}
	installed, err := c.official(ctx, selection, true)
	if errors.Is(err, ErrMissing) {
		installed, err = c.acquireChecked(ctx, "artifacts/"+artifactID.String()+"/", selection, true, check)
	}
	if err != nil {
		return nil, err
	}
	metadata, _ := installed.Metadata()
	if err := check(ctx, metadata, installed.DependencyBytes()); err != nil {
		return nil, err
	}
	if err := c.remember(ctx, installed); err != nil {
		return nil, err
	}
	return installed, nil
}

// RestoreRetainedLocal captures operator-supplied original metadata, executable
// and dependency bytes. The trusted original-tuple check supplies the authority
// for retained use; no current local setting, source tag or marker substitutes
// for it. This cannot make the build available for fresh work.
func (c *Coordinator) RestoreRetainedLocal(ctx context.Context, path string, identity artifact.Digest, check Check) (installed *Installed, err error) {
	if identity.IsZero() || check == nil {
		return nil, ErrInvalid
	}
	path, err = canonicalDirectory(path)
	if err != nil {
		return nil, err
	}
	contents, err := localContents(ctx, path, identity)
	if err != nil {
		return nil, err
	}
	if err := c.validate(ctx, path, contents, true); err != nil {
		return nil, err
	}
	if err := check(ctx, contents.Metadata, append([]byte(nil), contents.DependencyBytes...)); err != nil {
		return nil, err
	}
	stage, err := makeStage(filepath.Join(c.store, "builds"))
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := stage.finish(); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		if err != nil {
			installed = nil
		}
	}()
	if err := stage.writeBytes(ctx, "metadata.json", contents.MetadataBytes); err != nil {
		return nil, err
	}
	if err := stage.writeBytes(ctx, "dependencies.bin", contents.DependencyBytes); err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.Join(path, "plugin"))
	if err != nil {
		return nil, err
	}
	copyErr := stage.write(ctx, "plugin", file, int64(contents.Metadata.Executable.Length), 0500)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return nil, err
	}
	if err := publishStage(ctx, stage, identity.String(), func(path string) error {
		actual, err := localContents(ctx, path, identity)
		if err != nil {
			return err
		}
		if err := c.validate(ctx, path, actual, true); err != nil {
			return err
		}
		return check(ctx, actual.Metadata, append([]byte(nil), actual.DependencyBytes...))
	}); err != nil {
		return nil, err
	}
	installed = &Installed{path: filepath.Join(c.store, "builds", identity.String(), "plugin"), metadata: contents.MetadataBytes, dependency: contents.DependencyBytes, identity: identity, source: "local"}
	if err := c.remember(ctx, installed); err != nil {
		return nil, err
	}
	return installed, nil
}
