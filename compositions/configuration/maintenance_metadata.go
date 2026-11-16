package configuration

import (
	"bytes"
	"strconv"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// MaintenanceRequest fixes an exact target without granting operation authority.
type MaintenanceRequest struct {
	OperationKind              uint16
	RecipientReference         string
	RecipientID, BindingDigest contract.ID
	Name                       string
}

type MaintenancePinDelta struct {
	Name          string
	Before, After contract.RetainedSecretInput
}

// MaintenanceMetadata is inert in an ordinary source. Only its explicitly named
// output admits observation; authentication remains the Core owner's task.
type MaintenanceMetadata struct {
	Request                                         MaintenanceRequest
	Source                                          SourcePairIdentity
	FileID                                          contract.ID
	OutputPath                                      string
	RequestIdentity, RequestCoreDigest, OperationID contract.ID
	SignedCandidate                                 []byte
	PinDeltas                                       []MaintenancePinDelta
	Retirement                                      *contract.RecipientRetirementRow
	RekeyTarget                                     *contract.SecretAccessTarget
	PredecessorHead, PredecessorRoot                []byte
	PredecessorPages                                []MaintenanceValuePage
	CandidateRoot                                   []byte
	CandidatePages                                  []MaintenanceValuePage
	BeforeGeneration, AfterGeneration               contract.ID
}

func (r MaintenanceRequest) valid() bool {
	switch r.OperationKind {
	case contract.OperationRetireRecipientIdentity:
		return referenceValid(r.RecipientReference) && !r.RecipientID.IsZero() && !r.BindingDigest.IsZero() && r.Name == ""
	case contract.OperationEnvelopeRekey:
		return r.RecipientReference == "" && r.RecipientID.IsZero() && r.BindingDigest.IsZero() && len(r.Name) <= contract.CryptoMaxName && utf8.ValidString(r.Name)
	}
	return false
}

// Candidate checks structural correlations, not signatures or currentness.
func (m *MaintenanceMetadata) Candidate() (format.Head, error) {
	if m == nil || !m.materialCapacity() || !m.Request.valid() || m.FileID.IsZero() || !SuccessorOutputPathValid(m.OutputPath) || m.RequestIdentity.IsZero() || m.RequestCoreDigest.IsZero() || m.OperationID.IsZero() || m.Source.Format != JSON && m.Source.Format != YAML || m.Source.Editable.Digest.IsZero() || m.Source.Generated.Digest.IsZero() || m.Source.Editable.Length == 0 || m.Source.Generated.Length == 0 || m.Source.Editable.Length > uint64(MaxPairBytes) || m.Source.Generated.Length > uint64(MaxPairBytes)-m.Source.Editable.Length || len(m.PinDeltas) > contract.CryptoMaxValueEntries {
		return format.Head{}, ErrEdit
	}
	h, err := format.DecodeHead(m.SignedCandidate)
	if err != nil || h.Core.Form != format.SuccessorHead || h.AuthKind != format.LifecycleAuth || h.Subject.OperationKind != m.Request.OperationKind || h.Subject.Operation != m.OperationID || h.Subject.Request != m.RequestCoreDigest {
		return format.Head{}, ErrEdit
	}
	if _, err := contract.MatchHeadCondition(h.Core.PreviousToken); err != nil {
		return format.Head{}, ErrEdit
	}
	if m.Request.OperationKind == contract.OperationRetireRecipientIdentity {
		if m.Retirement == nil || m.RekeyTarget != nil || m.Retirement.RecipientID != m.Request.RecipientID {
			return format.Head{}, ErrEdit
		}
		descriptor, err := contract.RetirementDescriptor(h.Core.Domain, []contract.RecipientRetirementRow{*m.Retirement})
		if err != nil || descriptor != h.Subject.Exclusion.Retirements {
			return format.Head{}, ErrEdit
		}
	} else {
		target := m.RekeyTarget
		if m.Retirement != nil || target == nil || target.Name != m.Request.Name || target.Slot >= contract.CryptoMaxValueEntries || target.Incarnation.IsZero() || target.Material.IsZero() || target.BeforePublicEntryDigest.IsZero() {
			return format.Head{}, ErrEdit
		}
	}
	for i, delta := range m.PinDeltas {
		if len(delta.Name) > contract.CryptoMaxName || !utf8.ValidString(delta.Name) || i > 0 && m.PinDeltas[i-1].Name >= delta.Name || delta.Before.Incarnation.IsZero() || delta.Before.Material.IsZero() || delta.After.Incarnation.IsZero() || delta.After.Material.IsZero() || delta.Before.Incarnation != delta.After.Incarnation || delta.Before.Material == delta.After.Material {
			return format.Head{}, ErrEdit
		}
	}
	if err := m.checkCandidateMaterial(h); err != nil {
		return format.Head{}, err
	}
	return h, nil
}

func parseMaintenanceSource(p *parser) SourcePairIdentity {
	var source SourcePairIdentity
	mask := 0
	p.object(5, func(k string) {
		switch k {
		case "format":
			mask |= 1
			switch p.text(4, false, false) {
			case "json":
				source.Format = JSON
			case "yaml":
				source.Format = YAML
			default:
				p.fail("invalid-maintenance")
			}
		case "editable_digest":
			mask |= 2
			source.Editable.Digest = id(p)
		case "editable_length":
			mask |= 4
			source.Editable.Length = p.integer()
		case "generated_digest":
			mask |= 8
			source.Generated.Digest = id(p)
		case "generated_length":
			mask |= 16
			source.Generated.Length = p.integer()
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 31)
	return source
}

func parseMaintenanceMetadata(p *parser) *MaintenanceMetadata {
	m := new(MaintenanceMetadata)
	seen := 0
	p.object(19, func(k string) {
		switch k {
		case "kind":
			seen |= 1
			if p.text(32, false, false) != "maintenance-successor/v1" {
				p.fail("invalid-maintenance")
			}
		case "source":
			seen |= 2
			m.Source = parseMaintenanceSource(p)
		case "operation_kind":
			seen |= 4
			n := p.integer()
			if n > 65535 {
				p.fail("invalid-maintenance")
			}
			m.Request.OperationKind = uint16(n)
		case "recipient":
			seen |= 8
			m.Request.RecipientReference = p.text(256, false, false)
		case "recipient_id":
			seen |= 16
			m.Request.RecipientID = id(p)
		case "binding_digest":
			seen |= 32
			m.Request.BindingDigest = id(p)
		case "name":
			seen |= 64
			m.Request.Name = p.text(contract.CryptoMaxName, false, false)
		case "file_id":
			seen |= 128
			m.FileID = id(p)
		case "output_path":
			seen |= 256
			m.OutputPath = p.text(4096, false, false)
		case "request_identity":
			seen |= 512
			m.RequestIdentity = id(p)
		case "request_core_digest":
			seen |= 1024
			m.RequestCoreDigest = id(p)
		case "operation_id":
			seen |= 2048
			m.OperationID = id(p)
		case "candidate":
			seen |= 4096
			m.SignedCandidate = p.base64(contract.MaxHeadLength)
		case "pin_deltas":
			seen |= 8192
			p.array(contract.CryptoMaxValueEntries, func(_ int) {
				var d MaintenancePinDelta
				mask := 0
				p.object(3, func(k string) {
					switch k {
					case "name":
						mask |= 1
						d.Name = p.text(contract.CryptoMaxName, false, false)
					case "before":
						mask |= 2
						d.Before = parseMaintenancePin(p)
					case "after":
						mask |= 4
						d.After = parseMaintenancePin(p)
					default:
						p.fail("unknown-field")
					}
				})
				required(p, mask, 7)
				m.PinDeltas = append(m.PinDeltas, d)
			})
		case "candidate_material":
			seen |= 65536
			mask := 0
			p.object(2, func(k string) {
				switch k {
				case "root":
					mask |= 1
					m.CandidateRoot = p.base64(contract.MaxRootLength)
				case "pages":
					mask |= 2
					m.CandidatePages = parseMaintenancePages(p)
				default:
					p.fail("unknown-field")
				}
			})
			required(p, mask, 3)
		case "predecessor_material":
			seen |= 262144
			mask := 0
			p.object(3, func(k string) {
				switch k {
				case "head":
					mask |= 1
					m.PredecessorHead = p.base64(contract.MaxHeadLength)
				case "root":
					mask |= 2
					m.PredecessorRoot = p.base64(contract.MaxRootLength)
				case "pages":
					mask |= 4
					m.PredecessorPages = parseMaintenancePages(p)
				default:
					p.fail("unknown-field")
				}
			})
			required(p, mask, 7)
		case "rekey_generations":
			seen |= 131072
			mask := 0
			p.object(2, func(k string) {
				switch k {
				case "before":
					mask |= 1
					m.BeforeGeneration = id(p)
				case "after":
					mask |= 2
					m.AfterGeneration = id(p)
				default:
					p.fail("unknown-field")
				}
			})
			required(p, mask, 3)
		case "retirement":
			seen |= 16384
			row := new(contract.RecipientRetirementRow)
			mask := 0
			p.object(4, func(k string) {
				switch k {
				case "slot":
					mask |= 1
					n := p.integer()
					if n >= contract.CryptoMaxRecipients {
						p.fail("invalid-maintenance")
					}
					row.Slot = uint16(n)
				case "recipient_id":
					mask |= 2
					row.RecipientID = id(p)
				case "before_record_digest":
					mask |= 4
					row.BeforeRecordDigest = id(p)
				case "before_record_length":
					mask |= 8
					n := p.integer()
					if n > uint64(contract.RecipientRecordMaxLength) {
						p.fail("invalid-maintenance")
					}
					row.BeforeRecordLength = uint32(n)
				default:
					p.fail("unknown-field")
				}
			})
			required(p, mask, 15)
			m.Retirement = row
		case "rekey_target":
			seen |= 32768
			target := new(contract.SecretAccessTarget)
			mask := 0
			p.object(5, func(k string) {
				switch k {
				case "slot":
					mask |= 1
					n := p.integer()
					if n >= contract.CryptoMaxValueEntries {
						p.fail("invalid-maintenance")
					}
					target.Slot = uint16(n)
				case "name":
					mask |= 2
					target.Name = p.text(contract.CryptoMaxName, false, false)
				case "incarnation":
					mask |= 4
					target.Incarnation = id(p)
				case "material":
					mask |= 8
					target.Material = id(p)
				case "before_public_entry_digest":
					mask |= 16
					target.BeforePublicEntryDigest = id(p)
				default:
					p.fail("unknown-field")
				}
			})
			required(p, mask, 31)
			m.RekeyTarget = target
		default:
			p.fail("unknown-field")
		}
	})
	want := 1 | 2 | 4 | 128 | 256 | 512 | 1024 | 2048 | 4096 | 8192
	if m.Request.OperationKind == contract.OperationRetireRecipientIdentity {
		want |= 8 | 16 | 32 | 16384
	} else {
		want |= 64 | 32768
	}
	if len(m.PinDeltas) > 0 || m.Request.OperationKind == contract.OperationEnvelopeRekey {
		want |= 65536 | 262144
	}
	if !m.BeforeGeneration.IsZero() || !m.AfterGeneration.IsZero() {
		want |= 131072
	}
	required(p, seen, want)
	if _, err := m.Candidate(); err != nil {
		p.fail("invalid-maintenance")
	}
	return m
}

func parseMaintenancePages(p *parser) []MaintenanceValuePage {
	var pages []MaintenanceValuePage
	p.array(contract.MaxValueEntryPages, func(_ int) {
		var page MaintenanceValuePage
		fields := 0
		p.object(2, func(k string) {
			switch k {
			case "index":
				fields |= 1
				n := p.integer()
				if n >= contract.MaxValueEntryPages {
					p.fail("invalid-maintenance")
				}
				page.Index = uint16(n)
			case "body":
				fields |= 2
				page.Body = p.base64(contract.MaxValueEntryPageLength)
			default:
				p.fail("unknown-field")
			}
		})
		required(p, fields, 3)
		pages = append(pages, page)
	})
	return pages
}

func parseMaintenancePin(p *parser) contract.RetainedSecretInput {
	var pin contract.RetainedSecretInput
	mask := 0
	p.object(2, func(k string) {
		switch k {
		case "incarnation":
			mask |= 1
			pin.Incarnation = id(p)
		case "material":
			mask |= 2
			pin.Material = id(p)
		default:
			p.fail("unknown-field")
		}
	})
	required(p, mask, 3)
	return pin
}

func (w *generatedWriter) maintenancePin(pin contract.RetainedSecretInput) {
	w.write(`{"incarnation":`)
	w.id(pin.Incarnation)
	w.write(`,"material":`)
	w.id(pin.Material)
	w.write(`}`)
}

func (w *generatedWriter) maintenance(m *MaintenanceMetadata) {
	if _, err := m.Candidate(); err != nil {
		w.err = ErrEdit
		return
	}
	w.write(`{"kind":"maintenance-successor/v1","source":{"format":`)
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
	w.write(`},"operation_kind":`)
	w.write(strconv.FormatUint(uint64(m.Request.OperationKind), 10))
	if m.Request.OperationKind == contract.OperationRetireRecipientIdentity {
		w.write(`,"recipient":`)
		w.quote(m.Request.RecipientReference, 256)
		w.write(`,"recipient_id":`)
		w.id(m.Request.RecipientID)
		w.write(`,"binding_digest":`)
		w.id(m.Request.BindingDigest)
	} else {
		w.write(`,"name":`)
		w.quote(m.Request.Name, contract.CryptoMaxName)
	}
	w.write(`,"file_id":`)
	w.id(m.FileID)
	w.write(`,"output_path":`)
	w.quote(m.OutputPath, 4096)
	w.write(`,"request_identity":`)
	w.id(m.RequestIdentity)
	w.write(`,"request_core_digest":`)
	w.id(m.RequestCoreDigest)
	w.write(`,"operation_id":`)
	w.id(m.OperationID)
	w.write(`,"candidate":`)
	w.blob(m.SignedCandidate, contract.MaxHeadLength)
	w.write(`,"pin_deltas":[`)
	for i, delta := range m.PinDeltas {
		if i > 0 {
			w.write(`,`)
		}
		w.write(`{"name":`)
		w.quote(delta.Name, contract.CryptoMaxName)
		w.write(`,"before":`)
		w.maintenancePin(delta.Before)
		w.write(`,"after":`)
		w.maintenancePin(delta.After)
		w.write(`}`)
	}
	w.write(`]`)
	if len(m.CandidateRoot) > 0 {
		w.write(`,"candidate_material":{"root":`)
		w.blob(m.CandidateRoot, contract.MaxRootLength)
		w.write(`,"pages":`)
		w.maintenancePages(m.CandidatePages)
		w.write(`}`)
		w.write(`,"predecessor_material":{"head":`)
		w.blob(m.PredecessorHead, contract.MaxHeadLength)
		w.write(`,"root":`)
		w.blob(m.PredecessorRoot, contract.MaxRootLength)
		w.write(`,"pages":`)
		w.maintenancePages(m.PredecessorPages)
		w.write(`}`)
	}
	if !m.BeforeGeneration.IsZero() || !m.AfterGeneration.IsZero() {
		w.write(`,"rekey_generations":{"before":`)
		w.id(m.BeforeGeneration)
		w.write(`,"after":`)
		w.id(m.AfterGeneration)
		w.write(`}`)
	}
	if row := m.Retirement; row != nil {
		w.write(`,"retirement":{"slot":`)
		w.write(strconv.FormatUint(uint64(row.Slot), 10))
		w.write(`,"recipient_id":`)
		w.id(row.RecipientID)
		w.write(`,"before_record_digest":`)
		w.id(row.BeforeRecordDigest)
		w.write(`,"before_record_length":`)
		w.write(strconv.FormatUint(uint64(row.BeforeRecordLength), 10))
		w.write(`}`)
	} else if target := m.RekeyTarget; target != nil {
		w.write(`,"rekey_target":{"slot":`)
		w.write(strconv.FormatUint(uint64(target.Slot), 10))
		w.write(`,"name":`)
		w.quote(target.Name, contract.CryptoMaxName)
		w.write(`,"incarnation":`)
		w.id(target.Incarnation)
		w.write(`,"material":`)
		w.id(target.Material)
		w.write(`,"before_public_entry_digest":`)
		w.id(target.BeforePublicEntryDigest)
		w.write(`}`)
	}
	w.write(`}`)
}

func (w *generatedWriter) maintenancePages(pages []MaintenanceValuePage) {
	w.write(`[`)
	for i, page := range pages {
		if i > 0 {
			w.write(`,`)
		}
		w.write(`{"index":`)
		w.write(strconv.FormatUint(uint64(page.Index), 10))
		w.write(`,"body":`)
		w.blob(page.Body, contract.MaxValueEntryPageLength)
		w.write(`}`)
	}
	w.write(`]`)
}

func maintenanceMetadataBytes(m *MaintenanceMetadata) ([]byte, error) {
	var out bytes.Buffer
	w := &generatedWriter{out: &out, multiline: true, baseDepth: 1}
	w.maintenance(m)
	return out.Bytes(), w.err
}
