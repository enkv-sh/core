package configuration

import (
	"bytes"
	"context"
	"io"
	"sort"

	"enkv.sh/core/contract"
)

type ReplacementRecipientFact struct {
	RecipientID contract.ID
	Encryption  contract.KMSBinding
}
type SuccessorMaterial struct {
	Control         contract.ControlCore
	Recipients      []ReplacementRecipientFact
	Basis           Basis
	RequestIdentity contract.ID
	SignedCandidate []byte
}

func kmsKey(binding contract.KMSBinding) Key {
	return Key{Selector: binding.KeySelector, PublicKey: bytes.Clone(binding.SPKI), Binding: Binding{ID: binding.BindingID, Incarnation: binding.BindingIncarnationID, Serial: binding.BindingSerial, Protection: binding.ProtectionClass}}
}
func generatedKeyBytes(key Key, signing bool) ([]byte, error) {
	var out bytes.Buffer
	w := &generatedWriter{out: &out, multiline: true, baseDepth: 3}
	w.key(key, key.Selector, signing)
	return out.Bytes(), w.err
}
func generatedBasisBytes(basis Basis) ([]byte, error) {
	var out bytes.Buffer
	w := &generatedWriter{out: &out, multiline: true, baseDepth: 1}
	w.basis(basis)
	return out.Bytes(), w.err
}

func (s *SuccessorOutput) successorEdits(material SuccessorMaterial) ([]Edit, []Edit, error) {
	m := s.model
	if material.Control.DomainID != m.DomainID || material.Control.AuthorityRecipientID != m.Authority.ID || material.RequestIdentity.IsZero() {
		return nil, nil, ErrEdit
	}
	if _, err := contract.ControlCoreLength(material.Control); err != nil {
		return nil, nil, ErrEdit
	}
	metadata := &ReplacementMetadata{Request: s.request, Source: s.identity, RecipientID: s.recipient, RequestIdentity: material.RequestIdentity, SignedCandidate: bytes.Clone(material.SignedCandidate)}
	h, err := metadata.Candidate()
	if err != nil || h.Core.Domain != m.DomainID || h.Core.Store != material.Control.StoreID {
		return nil, nil, ErrEdit
	}
	after := *m
	after.Basis, after.Replacement = material.Basis, metadata
	switch s.request.Target {
	case ReplaceAuthority, ReplaceRecovery:
		role := &after.Authority
		signing := material.Control.NormalSigning
		encryption := material.Control.AuthorityKMSBinding
		if s.request.Target == ReplaceRecovery {
			if material.Control.Recovery == nil {
				return nil, nil, ErrEdit
			}
			role = &after.Recovery
			signing = material.Control.Recovery.Signing
			encryption = material.Control.Recovery.KMS
		}
		if s.request.SigningSelector != "" {
			if signing.KeySelector != s.request.SigningSelector {
				return nil, nil, ErrEdit
			}
			role.Signing = Key{Selector: signing.KeySelector, PublicKey: bytes.Clone(signing.SPKI)}
		}
		if s.request.EncryptionSelector != "" {
			if encryption.KeySelector != s.request.EncryptionSelector {
				return nil, nil, ErrEdit
			}
			role.Encryption = kmsKey(encryption)
		}
	case ReplaceRecipient:
		if int(s.recipientRow) >= len(material.Recipients) || material.Recipients[s.recipientRow].RecipientID != s.recipient {
			return nil, nil, ErrEdit
		}
		encryption := material.Recipients[s.recipientRow].Encryption
		if encryption.KeySelector != s.request.EncryptionSelector {
			return nil, nil, ErrEdit
		}
		after.Recipients = append([]Recipient(nil), m.Recipients...)
		found := false
		for i := range after.Recipients {
			if after.Recipients[i].Reference == s.request.RecipientReference {
				after.Recipients[i].Encryption = kmsKey(encryption)
				found = true
				break
			}
		}
		if !found {
			return nil, nil, ErrEdit
		}
	default:
		return nil, nil, ErrEdit
	}
	return s.projectionEdits(&after)
}

// The same exact projection validates existing output and emits new output.
// Every unrelated source byte, including inactive rows, is outside these edits.
func (s *SuccessorOutput) projectionEdits(after *Model) ([]Edit, []Edit, error) {
	m := s.model
	var editable, generated []Edit
	add := func(edits *[]Edit, index uint32, body []byte) error {
		if int(index) >= len(m.Spans) {
			return ErrEdit
		}
		v := m.Spans[index]
		*edits = append(*edits, Edit{Offset: v.Offset, Length: v.Length, Replacement: body})
		return nil
	}
	key := func(editableSpan uint32, before Key, next Key, signing bool) error {
		body, err := generatedKeyBytes(next, signing)
		if err != nil {
			return err
		}
		if err := add(&generated, before.GeneratedSpan, body); err != nil {
			return err
		}
		span, err := modelSpan(m, editableSpan)
		if err != nil {
			return err
		}
		selector, err := editableStringBytes(next.Selector, s.source.Format, span, false)
		if err != nil {
			return err
		}
		return add(&editable, editableSpan, selector)
	}
	switch s.request.Target {
	case ReplaceAuthority, ReplaceRecovery:
		before, next := m.Authority, after.Authority
		if s.request.Target == ReplaceRecovery {
			before, next = m.Recovery, after.Recovery
		}
		if s.request.SigningSelector != "" {
			if err := key(before.SigningSpan, before.Signing, next.Signing, true); err != nil {
				return nil, nil, err
			}
		}
		if s.request.EncryptionSelector != "" {
			if err := key(before.EncryptionSpan, before.Encryption, next.Encryption, false); err != nil {
				return nil, nil, err
			}
		}
	case ReplaceRecipient:
		var before, next *Recipient
		for i := range m.Recipients {
			if m.Recipients[i].Reference == s.request.RecipientReference {
				before = &m.Recipients[i]
				break
			}
		}
		for i := range after.Recipients {
			if after.Recipients[i].Reference == s.request.RecipientReference {
				next = &after.Recipients[i]
				break
			}
		}
		if before == nil || next == nil || before.ID != s.recipient || next.ID != s.recipient {
			return nil, nil, ErrEdit
		}
		if err := key(before.SelectorSpan, before.Encryption, next.Encryption, false); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, ErrEdit
	}
	basis, err := generatedBasisBytes(after.Basis)
	if err != nil {
		return nil, nil, err
	}
	if err := add(&generated, m.BasisSpan, basis); err != nil {
		return nil, nil, err
	}
	body, err := replacementMetadataBytes(after.Replacement)
	if err != nil {
		return nil, nil, err
	}
	if m.Replacement != nil {
		if err := add(&generated, m.ReplacementSpan, body); err != nil {
			return nil, nil, err
		}
	} else {
		if int(m.GeneratedRootSpan) >= len(m.Spans) {
			return nil, nil, ErrEdit
		}
		root := m.Spans[m.GeneratedRootSpan]
		if root.Length < 2 {
			return nil, nil, ErrEdit
		}
		end := root.Offset + root.Length - 1
		insertion := end
		buffer := make([]byte, WindowBytes)
		for insertion > root.Offset {
			start := max(root.Offset, insertion-int64(len(buffer)))
			n, err := s.source.Generated.ReadAt(buffer[:insertion-start], start)
			if err != nil {
				return nil, nil, err
			}
			for n > 0 && (buffer[n-1] == ' ' || buffer[n-1] == '\n' || buffer[n-1] == '\r' || buffer[n-1] == '\t') {
				n--
			}
			insertion = start + int64(n)
			if n > 0 {
				break
			}
		}
		replacement := append([]byte(",\n  \"replacement\": "), body...)
		replacement = append(replacement, '\n')
		generated = append(generated, Edit{Offset: insertion, Length: end - insertion, Replacement: replacement})
	}
	sort.Slice(editable, func(i, j int) bool { return editable[i].Offset < editable[j].Offset })
	sort.Slice(generated, func(i, j int) bool { return generated[i].Offset < generated[j].Offset })
	return editable, generated, nil
}

func successorEditable(ctx context.Context, writer io.Writer, pair *Pair, m *Model, edits []Edit, reference string) error {
	if reference != generatedPath(m.DomainName) || int(m.GeneratedSpan) >= len(m.Spans) {
		return ErrEdit
	}
	span := m.Spans[m.GeneratedSpan]
	body, err := editableStringBytes(reference, pair.Format, span, false)
	if err != nil {
		return err
	}
	edits = append(append([]Edit(nil), edits...), Edit{Offset: span.Offset, Length: span.Length, Replacement: body})
	sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
	return CopyEdits(ctx, writer, pair.Editable, edits)
}
