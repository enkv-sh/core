package contract

import (
	"crypto/ecdsa"
	"strconv"
	"strings"

	"enkv.sh/sdk/artifact/credentialroute"
)

const CoreVersion = "v0.0.0"
const EngineVersion = "state-session/v9"
const FormatVersion = "canonical-state/v14"
const ComponentContractVersion = "store-trust-crypto/v9"
const CryptoVersion = "supplied-secret/v4"
const CryptoProfile = "rsa3072-oaep-sha256-aes256gcm-hmacsha256/v2"

// Static metadata changes invalidate admission even when persisted structures
// retain their schema number. These constants describe the selected assembly.
const supportMetadata = "go=1.27.0\x00crypto=" + CryptoVersion + "\x00profile=" + CryptoProfile + "\x00rsa=3072,e65537,oaep-sha256,mgf1-sha256,label-empty\x00value=aes256-gcm,key32,nonce12,tag16\x00key-check=hmac-sha256\x00packets=value-key-v2,genesis-kek-probe-v1\x00aws-sdk=1.39.0,kms=1.45.2,smithy=1.23.0\x00gcp-api=0.222.0,auth=0.14.1\x00selectors=aws-exact-key-arn,gcp-exact-crypto-key-version\x00fallback=none"

func CryptoSupportID() ID { return Hash([]byte("ENKV/CRYPTO-SUPPORT/v2\x00" + supportMetadata)) }
func CompatibilityID() ID {
	return Hash([]byte("ENKV/COMPATIBILITY/v8\x00" + FormatVersion + "\x00" + CryptoProfile))
}
func TrustInterpretationID() ID {
	return Hash([]byte("ENKV/TRUST-INTERPRETATION/v9\x00p256-ecdsa-sha256-asn1\x00normal=" + trustPurposeMetadata(NormalSigningRole) + "\x00recovery=" + trustPurposeMetadata(RecoverySigningRole) + "\x00" + supportMetadata))
}

func trustPurposeMetadata(role uint8) string {
	var text strings.Builder
	for purpose := 0; purpose < 256; purpose++ {
		if !SigningPurposeAllowed(role, Purpose(purpose)) {
			continue
		}
		if text.Len() != 0 {
			text.WriteByte(',')
		}
		text.WriteString(strconv.Itoa(purpose))
	}
	return text.String()
}

func InterpretationID() ID {
	return Hash([]byte("ENKV/INTERPRETATION\x00" + CoreVersion + "\x00" + EngineVersion + "\x00" + FormatVersion + "\x00" + ComponentContractVersion + "\x00" + supportMetadata))
}

type ComponentKind uint8

const (
	StoreComponentKind     ComponentKind = 1
	TrustComponentKind     ComponentKind = 2
	GeneratorComponentKind ComponentKind = 3
)

// These are the three closed registry row types. Compositions own static rows;
// no runtime registration or discovery entry point exists.
type ComponentImplementation struct {
	Family                 Family
	Kind                   ComponentKind
	Class, Module, Version string
}
type VerifierParser struct {
	Family Family
	Class  string
	Parse  func([]byte) (*ecdsa.PublicKey, error)
}
type ConstructionClass struct {
	Family Family
	Kind   ComponentKind
	Class  string
}

// GeneratorImplementation identifies one exact admitted artifact and public route.
type GeneratorImplementation struct {
	Schema                                                                    uint16
	Kind                                                                      ComponentKind
	DescriptorID, ProtocolID, ExecutorID, ArtifactContractID                  ID
	DependencyManifestID, ArtifactSHA256, ConfigContractID, CredentialRouteID ID
	CredentialRoute                                                           []byte
	ArtifactLength                                                            uint64
	Module, Command, Version, GoVersion, NativeTuple                          string
}

func (v GeneratorImplementation) ArtifactBound() bool {
	return !v.ArtifactSHA256.IsZero() && v.ArtifactLength > 0
}
func (v GeneratorImplementation) ValidateArtifact() error {
	if v.Schema != GeneratorImplementationSchema || v.Kind != GeneratorComponentKind || !v.ArtifactBound() || !publicIDsValid(v.DescriptorID, v.ProtocolID, v.ExecutorID, v.ArtifactContractID, v.DependencyManifestID, v.ConfigContractID) {
		return ErrRecord
	}
	for _, s := range []string{v.Module, v.Command, v.Version, v.GoVersion, v.NativeTuple} {
		if s == "" || len(s) > 1024 {
			return ErrRecordCapacity
		}
	}
	if v.NativeTuple != "darwin/arm64" && v.NativeTuple != "linux/amd64" {
		return ErrRecord
	}
	return nil
}
func (v GeneratorImplementation) Validate() error {
	if err := v.ValidateArtifact(); err != nil {
		return err
	}
	route, err := credentialroute.Decode(v.CredentialRoute)
	if err != nil {
		return ErrRecord
	}
	id, err := credentialroute.Identity(route)
	if err != nil || ID(id) != v.CredentialRouteID {
		return ErrRecord
	}
	return nil
}

type CompatibilityManifest struct {
	Identity                                ID
	Core, Engine, Format, ComponentContract string
	Crypto, CryptoProfile                   string
	Components                              []ComponentImplementation
	Generators                              []GeneratorImplementation
	Verifiers                               []VerifierParser
	Constructions                           []ConstructionClass
}

// Cell holds one exact provider pair and its private Crypto runtime. It cannot
// supply Core, source, operation or consumer admission.
type Cell struct {
	Store    Store
	Trust    Trust
	Crypto   Crypto
	Identity ID
}
