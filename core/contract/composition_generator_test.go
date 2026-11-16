package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

func generatorImplementationFixture() GeneratorImplementation {
	// Public route fixture: u16 schema1, contract R80, environment mode1,
	// zero variable names and zero public-data length. Identity uses blob32.
	route := binary.BigEndian.AppendUint16(nil, 1)
	contract := generatedRecordID(80)
	route = append(route, contract[:]...)
	route = append(route, 1, 0, 0, 0, 0, 0)
	preimage := append([]byte("ENKV/CREDENTIAL-ROUTE/v1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(route)))...)
	preimage = append(preimage, route...)
	return GeneratorImplementation{Schema: GeneratorImplementationSchema, Kind: GeneratorComponentKind,
		DescriptorID: Hash([]byte("descriptor")), ProtocolID: Hash([]byte("protocol")),
		ConfigContractID: Hash([]byte("config")), ExecutorID: Hash([]byte("executor")), ArtifactContractID: Hash([]byte("artifact contract")),
		DependencyManifestID: Hash([]byte("dependencies")), ArtifactSHA256: Hash([]byte("artifact")),
		CredentialRoute: route, CredentialRouteID: ID(sha256.Sum256(preimage)), ArtifactLength: 4096,
		Module: "private.local/author/generator", Command: ".", Version: "1.0.0", GoVersion: "go1.27.3", NativeTuple: "darwin/arm64"}
}

// full_only: false
func TestGeneratorImplementationIsClosedAndArtifactBound(t *testing.T) {
	v := generatorImplementationFixture()
	if err := v.Validate(); err != nil || v.ValidateArtifact() != nil || !v.ArtifactBound() {
		t.Fatal("valid generator implementation refused", err)
	}
	changes := []func(*GeneratorImplementation){
		func(v *GeneratorImplementation) { v.Schema++ },
		func(v *GeneratorImplementation) { v.Kind = TrustComponentKind },
		func(v *GeneratorImplementation) { v.DescriptorID = ID{} },
		func(v *GeneratorImplementation) { v.ProtocolID = ID{} },
		func(v *GeneratorImplementation) { v.ExecutorID = ID{} },
		func(v *GeneratorImplementation) { v.CredentialRouteID = ID{} },
		func(v *GeneratorImplementation) { v.ArtifactSHA256 = ID{} },
		func(v *GeneratorImplementation) { v.ArtifactLength = 0 },
		func(v *GeneratorImplementation) { v.ArtifactContractID = ID{} },
		func(v *GeneratorImplementation) { v.Module = strings.Repeat("x", 1025) },
		func(v *GeneratorImplementation) { v.NativeTuple = "windows/amd64" },
	}
	for i, change := range changes {
		bad := v
		change(&bad)
		if bad.Validate() == nil {
			t.Fatalf("change %d passed", i)
		}
	}
	unbound := v
	unbound.ArtifactSHA256, unbound.ArtifactLength = ID{}, 0
	if unbound.ArtifactBound() || unbound.Validate() == nil {
		t.Fatal("unbound static row passed admission")
	}
	artifact := v
	artifact.CredentialRoute, artifact.CredentialRouteID = nil, ID{}
	if artifact.ValidateArtifact() != nil || artifact.Validate() == nil {
		t.Fatal("artifact-only validation granted runtime authority")
	}
	for i, change := range changes {
		if i == 5 {
			continue // The credential route belongs to runtime validation.
		}
		bad := artifact
		change(&bad)
		if bad.ValidateArtifact() == nil {
			t.Fatal("damaged immutable artifact metadata passed validation")
		}
	}
}
