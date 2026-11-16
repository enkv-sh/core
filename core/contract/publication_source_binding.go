package contract

import (
	"bytes"
	"unicode/utf8"
)

// Source carriers add bounded names and blob framing to stored binding facts.
const MaxNormalOutputBindingBytes = MaxOutputDeclarationBytes + 492*MaxOutputTargetsPerBinding

func outputEntryNameValid(name string) bool {
	return len(name) <= CryptoMaxName && utf8.ValidString(name)
}

// EncodeNormalOutputBinding preserves source meaning before operation identities
// are assigned. Its canonical bytes grant no trust or publication permission.
func EncodeNormalOutputBinding(v NormalOutputBinding) ([]byte, error) {
	w, _, err := normalOutputBinding(v, true)
	return w.b, err
}

// NormalOutputBindingDeclarationLength returns this binding's exact stored
// contribution. The enclosing declaration separately owns its six count/schema
// bytes and every explicit group.
func NormalOutputBindingDeclarationLength(v NormalOutputBinding) (int, error) {
	_, length, err := normalOutputBinding(v, false)
	return length, err
}

func normalOutputBinding(v NormalOutputBinding, encode bool) (outputWriter, int, error) {
	invalid := func(err error) (outputWriter, int, error) { return outputWriter{}, 0, err }
	if !outputIdentifierValid(v.DestinationID) || len(v.Targets) > MaxOutputTargetsPerBinding {
		return invalid(ErrRecord)
	}
	w := newOutputWriter(encode, 256)
	w.u16(2)
	w.text(v.DestinationID)
	destinationLength, err := OutputDestinationLength(v.Destination)
	if err != nil {
		return invalid(err)
	}
	w.u32(uint32(destinationLength))
	if encode {
		if err := writeOutputDestinationTo(v.Destination, &w); err != nil {
			return invalid(err)
		}
	} else {
		w.length += destinationLength
	}
	stored := 4 + len(v.DestinationID) + 32 + destinationLength + 2
	if stored > MaxOutputDeclarationBytes-6 {
		return invalid(ErrRecordCapacity)
	}
	w.u16(uint16(len(v.Targets)))
	physical := make(map[string]bool, len(v.Targets))
	for i, row := range v.Targets {
		t := row.Target
		if !outputEntryNameValid(row.Name) || i > 0 && v.Targets[i-1].Name >= row.Name || !t.EntryIncarnationID.IsZero() || t.ServiceContractID != v.Destination.ServiceContractID || t.Capabilities & ^v.Destination.Capabilities != 0 || !outputPoliciesEqual(t.Policy, v.Destination.Policy) || physical[t.CanonicalTarget] {
			return invalid(ErrRecord)
		}
		target := newOutputWriter(false, 0)
		if err := writeOutputTargetFactsTo(t, &target); err != nil {
			return invalid(err)
		}
		if target.length > MaxOutputDeclarationBytes-6-stored {
			return invalid(ErrRecordCapacity)
		}
		stored += target.length
		w.text(row.Name)
		w.u32(uint32(target.length))
		if encode {
			if err := writeOutputTargetFactsTo(t, &w); err != nil {
				return invalid(err)
			}
		} else {
			w.length += target.length
		}
		physical[t.CanonicalTarget] = true
		if w.length > MaxNormalOutputBindingBytes {
			return invalid(ErrRecordCapacity)
		}
	}
	if w.length > MaxNormalOutputBindingBytes {
		return invalid(ErrRecordCapacity)
	}
	return w, stored, nil
}

func InspectNormalOutputBinding(body []byte) (NormalOutputBinding, error) {
	if len(body) > MaxNormalOutputBindingBytes {
		return NormalOutputBinding{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	schema := r.u16()
	v := NormalOutputBinding{DestinationID: outputBlobString(&r, 256)}
	destination := r.blob(MaxOutputDeclarationBytes)
	d := outputImageReader{source: bytes.NewReader(destination), remaining: len(destination), section: -1}
	v.Destination = d.destination(true)
	if d.err != nil || d.remaining != 0 || schema != 2 {
		return NormalOutputBinding{}, ErrRecord
	}
	count := int(r.u16())
	if r.err != nil || count > MaxOutputTargetsPerBinding || count > (len(body)-r.i)/8 {
		return NormalOutputBinding{}, ErrRecord
	}
	if count > 0 {
		v.Targets = make([]NormalOutputTarget, count)
	}
	for i := range v.Targets {
		v.Targets[i].Name = string(r.blob(CryptoMaxName))
		if !outputEntryNameValid(v.Targets[i].Name) {
			return NormalOutputBinding{}, ErrRecord
		}
		row := r.blob(MaxOutputDeclarationBytes)
		t := newRecordReader(row)
		target := OutputTarget{EntryIncarnationID: t.id(), ServiceContractID: outputBlobString(&t, 256), TargetContractID: outputBlobString(&t, 256), CanonicalTarget: outputBlobString(&t, 1024)}
		locator := t.blob(1024)
		if !utf8.Valid(locator) {
			return NormalOutputBinding{}, ErrRecord
		}
		target.ConsumerLocator = string(locator)
		target.TargetData = append([]byte(nil), t.blob(MaxOutputTargetDataBytes)...)
		target.PayloadEncoding = t.u8()
		target.Capabilities = OutputActionCapabilities(t.u8())
		flag := t.u8()
		target.LocatorRequiresCreation = flag == 1
		target.CreateValueBounds = OutputPayloadBounds{Minimum: t.u32(), Maximum: t.u32()}
		target.WriteValueBounds = OutputPayloadBounds{Minimum: t.u32(), Maximum: t.u32()}
		policy, err := InspectOutputPolicy(t.blob(MaxOutputPolicyRecordBytes))
		if err != nil || t.end() != nil || flag > 1 {
			return NormalOutputBinding{}, ErrRecord
		}
		target.Policy = policy
		v.Targets[i].Target = target
	}
	if r.end() != nil {
		return NormalOutputBinding{}, ErrRecord
	}
	encoded, err := EncodeNormalOutputBinding(v)
	if err != nil || !bytes.Equal(encoded, body) {
		return NormalOutputBinding{}, ErrRecord
	}
	return v, nil
}
