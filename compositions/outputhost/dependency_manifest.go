package outputhost

import (
	"errors"
	"runtime/debug"
	"strings"
	"unicode/utf8"

	"enkv.sh/sdk/artifact"
	protocol "enkv.sh/sdk/protocols/output"
)

const maximumDependencyStringBytes = 1024

// DependencyManifest holds the canonical complete build graph for one output.
// Facts is mutable caller-owned data; a zero manifest cannot be encoded.
type DependencyManifest struct{ Facts *artifact.BuildFacts }

func validManifestString(s string, required bool) bool {
	return (!required || s != "") && len(s) <= maximumDependencyStringBytes && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// EncodeDependencyManifest checks the output role and encodes owned canonical
// bytes. It borrows Facts only for the call.
func EncodeDependencyManifest(m DependencyManifest) ([]byte, error) {
	if m.Facts == nil || m.Facts.Role != "output" {
		return nil, ErrAdmission
	}
	return artifact.EncodeDependency(*m.Facts)
}

// DecodeDependencyManifest returns an owned output build graph, independent
// of body. A different family or invalid encoding returns ErrAdmission.
func DecodeDependencyManifest(body []byte) (DependencyManifest, error) {
	facts, err := artifact.DecodeDependency(body)
	if err != nil || facts.Role != "output" {
		return DependencyManifest{}, errors.Join(ErrAdmission, err)
	}
	return DependencyManifest{Facts: &facts}, nil
}

// DependencyManifestID validates canonical output dependency bytes and
// computes their family-domain identity; it does not authenticate their source.
func DependencyManifestID(body []byte) (protocol.ID, error) {
	id, err := artifact.DependencyID("output", body)
	if err != nil {
		return protocol.ID{}, errors.Join(ErrAdmission, err)
	}
	return protocol.ID(id), nil
}
func verifyArtifactInfo(info *debug.BuildInfo, manifest DependencyManifest) error {
	if manifest.Facts == nil {
		return ErrArtifactIncompatible
	}
	if err := artifact.VerifyBuildInfo(info, *manifest.Facts); err != nil {
		return errors.Join(ErrArtifactIncompatible, err)
	}
	return nil
}

// VerifyDependencyBuildInfo compares actual compiled build information with
// the complete decoded dependency expectation. Mismatch matches ErrArtifactIncompatible.
func VerifyDependencyBuildInfo(info *debug.BuildInfo, body []byte) error {
	manifest, err := DecodeDependencyManifest(body)
	if err != nil {
		return err
	}
	return verifyArtifactInfo(info, manifest)
}
