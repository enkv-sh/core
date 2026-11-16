package configuration

import (
	"bytes"
	"strconv"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

type ReplacementTarget string

const (
	ReplaceAuthority ReplacementTarget = "authority"
	ReplaceRecovery  ReplacementTarget = "recovery"
	ReplaceRecipient ReplacementTarget = "recipient"
)

// ReplacementRequest fixes selectors and routes. It grants no operation power.
type ReplacementRequest struct {
	Target                                                  ReplacementTarget
	RecipientReference, SigningSelector, EncryptionSelector string
	Authorizer                                              uint8
	MaterialSource                                          string
}

type SourcePairIdentity struct {
	Format              Format
	Editable, Generated contract.DigestLength
}

// ReplacementMetadata is inert in a source. Only an explicitly named output
// selects observation. SignedCandidate supplies domain, Store, predecessor and
// mutation facts; those fields are not repeated here.
type ReplacementMetadata struct {
	Request                      ReplacementRequest
	Source                       SourcePairIdentity
	RecipientID, RequestIdentity contract.ID
	SignedCandidate              []byte
}

func pairIdentity(p *Pair) (SourcePairIdentity, error) {
	if p == nil || p.Editable == nil || p.Generated == nil || p.Editable.file == nil || p.Generated.file == nil {
		return SourcePairIdentity{}, ErrEdit
	}
	return SourcePairIdentity{Format: p.Format, Editable: contract.DigestLength{Digest: contract.ID(p.Editable.digest), Length: uint64(p.Editable.size)}, Generated: contract.DigestLength{Digest: contract.ID(p.Generated.digest), Length: uint64(p.Generated.size)}}, nil
}

func (r ReplacementRequest) valid(provider contract.Family, recovery bool) bool {
	if r.Authorizer != contract.NormalSigningRole && r.Authorizer != contract.RecoverySigningRole || r.Authorizer == contract.RecoverySigningRole && !recovery {
		return false
	}
	if r.SigningSelector == "" && r.EncryptionSelector == "" || r.SigningSelector != "" && !contract.PublicKeySelectorValid(provider, r.SigningSelector, true) || r.EncryptionSelector != "" && !contract.PublicKeySelectorValid(provider, r.EncryptionSelector, false) {
		return false
	}
	if r.EncryptionSelector == "" {
		if r.MaterialSource != "" {
			return false
		}
	} else if r.MaterialSource != "authority" && (r.MaterialSource != "recovery" || !recovery) {
		return false
	}
	switch r.Target {
	case ReplaceAuthority:
		return r.RecipientReference == ""
	case ReplaceRecovery:
		return recovery && r.RecipientReference == ""
	case ReplaceRecipient:
		return r.RecipientReference != "" && len(r.RecipientReference) <= 256 && r.SigningSelector == "" && r.Authorizer == contract.NormalSigningRole && r.MaterialSource == "authority"
	}
	return false
}

// Candidate decodes the exact stored signed candidate. Authentication and
// selected-currentness remain Core checks under independent source trust.
func (m *ReplacementMetadata) Candidate() (format.Head, error) {
	if m == nil || m.RequestIdentity.IsZero() || m.Source.Format != JSON && m.Source.Format != YAML || m.Source.Editable.Digest.IsZero() || m.Source.Generated.Digest.IsZero() || m.Source.Editable.Length == 0 || m.Source.Generated.Length == 0 || m.Source.Editable.Length > uint64(MaxPairBytes) || m.Source.Generated.Length > uint64(MaxPairBytes)-m.Source.Editable.Length {
		return format.Head{}, ErrEdit
	}
	h, err := format.DecodeHead(m.SignedCandidate)
	if err != nil || h.Core.Form != format.SuccessorHead {
		return format.Head{}, ErrEdit
	}
	switch m.Request.Target {
	case ReplaceAuthority, ReplaceRecovery:
		if !m.RecipientID.IsZero() || h.AuthKind != format.SuccessionAuth || h.Succession == nil {
			return format.Head{}, ErrEdit
		}
		subject := h.Succession.Subject
		material := uint8(contract.SuccessionMaterialNone)
		switch m.Request.MaterialSource {
		case "authority":
			material = contract.SuccessionMaterialAuthority
		case "recovery":
			material = contract.SuccessionMaterialRecovery
		case "":
		default:
			return format.Head{}, ErrEdit
		}
		if subject.RequestIdentityDigest != m.RequestIdentity || subject.MaterialSourceRole != material {
			return format.Head{}, ErrEdit
		}
		kind, mask := uint8(contract.SuccessionReplaceAuthority), uint8(0)
		if m.Request.Target == ReplaceAuthority {
			if m.Request.SigningSelector != "" {
				mask |= contract.SuccessionChangeNormalSigner
			}
			if m.Request.EncryptionSelector != "" {
				mask |= contract.SuccessionChangeAuthorityKEK
			}
		} else {
			kind = contract.SuccessionReplaceRecoveryBasis
			if m.Request.SigningSelector != "" {
				mask |= contract.SuccessionChangeRecoverySigner
			}
			if m.Request.EncryptionSelector != "" {
				mask |= contract.SuccessionChangeRecoveryKEK
			}
		}
		if subject.OperationKind != kind || subject.ApprovalRole != m.Request.Authorizer || subject.ChangeMask == 0 || subject.ChangeMask & ^mask != 0 {
			return format.Head{}, ErrEdit
		}
	case ReplaceRecipient:
		if m.RecipientID.IsZero() || h.AuthKind != format.LifecycleAuth {
			return format.Head{}, ErrEdit
		}
	default:
		return format.Head{}, ErrEdit
	}
	if _, err := contract.MatchHeadCondition(h.Core.PreviousToken); err != nil {
		return format.Head{}, ErrEdit
	}
	return h, nil
}

func parseReplacementMetadata(p *parser) *ReplacementMetadata {
	m := new(ReplacementMetadata)
	seen := 0
	p.object(11, func(k string) {
		switch k {
		case "kind":
			seen |= 1
			if p.text(32, false, false) != "key-replacement/v1" {
				p.fail("invalid-replacement")
			}
		case "source":
			seen |= 2
			mask := 0
			p.object(5, func(k string) {
				switch k {
				case "format":
					mask |= 1
					switch p.text(4, false, false) {
					case "json":
						m.Source.Format = JSON
					case "yaml":
						m.Source.Format = YAML
					default:
						p.fail("invalid-replacement")
					}
				case "editable_digest":
					mask |= 2
					m.Source.Editable.Digest = id(p)
				case "editable_length":
					mask |= 4
					m.Source.Editable.Length = p.integer()
				case "generated_digest":
					mask |= 8
					m.Source.Generated.Digest = id(p)
				case "generated_length":
					mask |= 16
					m.Source.Generated.Length = p.integer()
				default:
					p.fail("unknown-field")
				}
			})
			required(p, mask, 31)
		case "target":
			seen |= 4
			m.Request.Target = ReplacementTarget(p.text(9, false, false))
		case "recipient":
			seen |= 8
			m.Request.RecipientReference = p.text(256, false, false)
		case "recipient_id":
			seen |= 16
			m.RecipientID = id(p)
		case "signing":
			seen |= 32
			m.Request.SigningSelector = p.text(1024, false, false)
		case "encryption":
			seen |= 64
			m.Request.EncryptionSelector = p.text(1024, false, false)
		case "authorizer":
			seen |= 128
			switch p.text(9, false, false) {
			case "authority":
				m.Request.Authorizer = contract.NormalSigningRole
			case "recovery":
				m.Request.Authorizer = contract.RecoverySigningRole
			default:
				p.fail("invalid-replacement")
			}
		case "material_source":
			seen |= 256
			m.Request.MaterialSource = p.text(9, false, false)
		case "request_identity":
			seen |= 512
			m.RequestIdentity = id(p)
		case "candidate":
			seen |= 1024
			m.SignedCandidate = p.base64(contract.MaxHeadLength)
		default:
			p.fail("unknown-field")
		}
	})
	want := 1 | 2 | 4 | 128 | 512 | 1024
	if m.Request.Target == ReplaceRecipient {
		want |= 8 | 16
	}
	if m.Request.SigningSelector != "" {
		want |= 32
	}
	if m.Request.EncryptionSelector != "" {
		want |= 64 | 256
	}
	required(p, seen, want)
	if _, err := m.Candidate(); err != nil {
		p.fail("invalid-replacement")
	}
	return m
}

func (w *generatedWriter) replacement(m *ReplacementMetadata) {
	if _, err := m.Candidate(); err != nil {
		w.err = ErrEdit
		return
	}
	w.write(`{"kind":"key-replacement/v1","source":{"format":`)
	if m.Source.Format == JSON {
		w.quote("json", 4)
	} else {
		w.quote("yaml", 4)
	}
	w.write(`,"editable_digest":`)
	w.id(m.Source.Editable.Digest)
	w.write(`,"editable_length":`)
	w.write(strconv.FormatUint(m.Source.Editable.Length, 10))
	w.write(`,"generated_digest":`)
	w.id(m.Source.Generated.Digest)
	w.write(`,"generated_length":`)
	w.write(strconv.FormatUint(m.Source.Generated.Length, 10))
	w.write(`},"target":`)
	w.quote(string(m.Request.Target), 9)
	if m.Request.Target == ReplaceRecipient {
		w.write(`,"recipient":`)
		w.quote(m.Request.RecipientReference, 256)
		w.write(`,"recipient_id":`)
		w.id(m.RecipientID)
	}
	if m.Request.SigningSelector != "" {
		w.write(`,"signing":`)
		w.quote(m.Request.SigningSelector, 1024)
	}
	if m.Request.EncryptionSelector != "" {
		w.write(`,"encryption":`)
		w.quote(m.Request.EncryptionSelector, 1024)
	}
	w.write(`,"authorizer":`)
	if m.Request.Authorizer == contract.NormalSigningRole {
		w.quote("authority", 9)
	} else {
		w.quote("recovery", 9)
	}
	if m.Request.MaterialSource != "" {
		w.write(`,"material_source":`)
		w.quote(m.Request.MaterialSource, 9)
	}
	w.write(`,"request_identity":`)
	w.id(m.RequestIdentity)
	w.write(`,"candidate":`)
	w.blob(m.SignedCandidate, contract.MaxHeadLength)
	w.write(`}`)
}

func (m *ReplacementMetadata) matches(source SourcePairIdentity, request ReplacementRequest, recipient contract.ID) bool {
	return m != nil && m.Source == source && m.Request == request && m.RecipientID == recipient
}
func replacementMetadataBytes(m *ReplacementMetadata) ([]byte, error) {
	var out bytes.Buffer
	w := &generatedWriter{out: &out, multiline: true, baseDepth: 1}
	w.replacement(m)
	return out.Bytes(), w.err
}
