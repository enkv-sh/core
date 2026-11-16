package compositionfull

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"enkv.sh/core/contract"
)

const comparisonValueBackingLimit = 2 * (contract.MaxPublicConfigurationBytes + contract.MaxPublicTypedConfigurationBytes)

func validComparisonFacts(payload contract.ComparisonPayload) bool {
	if len(payload.Diagnostics) > contract.MaxPublicDiagnostics || len(payload.Changes) > contract.MaxPublicDiagnostics-len(payload.Diagnostics) || len(payload.Changes) != 0 && payload.Observation == nil {
		return false
	}
	for _, diagnostic := range payload.Diagnostics {
		if diagnostic.Outcome != contract.DiagnosticUnable {
			return false
		}
	}
	remaining := uint64(comparisonValueBackingLimit)
	charge := func(n uint64) bool {
		if n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	for _, labels := range [][]contract.ComparisonRecipientLabel{payload.BeforeRecipients, payload.AfterRecipients} {
		if len(labels) > contract.CryptoMaxRecipients || len(labels) != 0 && payload.Observation == nil || cap(labels) != len(labels) || !charge(uint64(cap(labels))*uint64(unsafe.Sizeof(contract.ComparisonRecipientLabel{}))) {
			return false
		}
		for at, label := range labels {
			if label.RecipientID.IsZero() || at > 0 && bytes.Compare(labels[at-1].RecipientID[:], label.RecipientID[:]) >= 0 {
				return false
			}
			for _, text := range []*string{label.Name, label.DisplayName} {
				if text != nil && (!boundedReaderText(*text, contract.CryptoMaxName) || !charge(uint64(len(*text))+uint64(unsafe.Sizeof("")))) {
					return false
				}
			}
		}
	}
	var memberships [2]int
	for at, change := range payload.Changes {
		if at > 0 && compareChangeKeys(payload.Changes[at-1], change) >= 0 {
			return false
		}
		if change.Subject.Kind == contract.SubjectRecipient && change.Subject.RecipientID.IsZero() || change.Subject.Kind == contract.SubjectOutputBinding && change.Subject.DestinationID == "" || change.Subject.Kind == contract.SubjectRoutingRule && change.Subject.RoutingKey.EntrySelector == 0 {
			return false
		}
		kind := contract.ComparisonFieldValueType(change.Subject.Kind, change.Path)
		if kind == "" {
			return false
		}
		if _, ok := readerDiagnostic(contract.Diagnostic{Subject: change.Subject, Path: change.Path, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable, SourceLocation: change.SourceLocation}); !ok {
			return false
		}
		before, after := change.Before, change.After
		switch change.Action {
		case contract.ComparisonAdded:
			if before.State != contract.ComparisonAbsent || after.State != contract.ComparisonPresent {
				return false
			}
		case contract.ComparisonRemoved:
			if before.State != contract.ComparisonPresent || after.State != contract.ComparisonAbsent {
				return false
			}
		case contract.ComparisonChanged:
			if before.State != contract.ComparisonPresent || after.State != contract.ComparisonPresent || comparisonValuesEqual(before.Value, after.Value) {
				return false
			}
		default:
			return false
		}
		for index, side := range []contract.ComparisonSide{before, after} {
			if side.State == contract.ComparisonAbsent {
				if side.Value != nil {
					return false
				}
				continue
			}
			if side.State != contract.ComparisonPresent || contract.ComparisonValueTypeOf(side.Value) != kind || !validComparisonValue(change.Path[len(change.Path)-1], side.Value, charge) {
				return false
			}
			if members, ok := side.Value.(contract.ComparisonIDSet); ok {
				if len(members) > contract.CryptoMaxMemberships-memberships[index] {
					return false
				}
				memberships[index] += len(members)
			}
		}
		if kind == contract.ComparisonTypeIDSet && !validComparisonMemberships(before, after) {
			return false
		}
	}
	return true
}

func compareChangeKeys(a, b contract.ComparisonChange) int {
	if order := strings.Compare(string(a.Subject.Kind), string(b.Subject.Kind)); order != 0 {
		return order
	}
	x, y := a.Subject, b.Subject
	if order := strings.Compare(x.DestinationID, y.DestinationID); order != 0 {
		return order
	}
	if order := strings.Compare(x.Name, y.Name); order != 0 {
		return order
	}
	if order := bytes.Compare(x.RecipientID[:], y.RecipientID[:]); order != 0 {
		return order
	}
	if x.RoutingKey.EntrySelector != y.RoutingKey.EntrySelector {
		if x.RoutingKey.EntrySelector < y.RoutingKey.EntrySelector {
			return -1
		}
		return 1
	}
	if order := strings.Compare(x.RoutingKey.EntryName, y.RoutingKey.EntryName); order != 0 {
		return order
	}
	return slices.Compare(a.Path, b.Path)
}

func validComparisonValue(field contract.DiagnosticField, value contract.ComparisonValue, charge func(uint64) bool) bool {
	switch value := value.(type) {
	case contract.ComparisonBoolean:
		return (field != contract.FieldPresence || bool(value)) && charge(1)
	case contract.ComparisonUint:
		return charge(8)
	case contract.ComparisonText:
		maximum := 1024
		switch field {
		case contract.FieldName, contract.FieldDisplayName, contract.FieldServiceContract, contract.FieldTargetContract:
			maximum = contract.CryptoMaxName
		case contract.FieldRegion:
			maximum = 64
		case contract.FieldBucket:
			maximum = 222
		case contract.FieldPrefix:
			maximum = contract.MaxStorePrefixLength
		case contract.FieldExpectedOwner:
			maximum = 12
		}
		return boundedReaderText(string(value), maximum) && charge(uint64(len(value))+uint64(unsafe.Sizeof(value)))
	case contract.ComparisonBytes:
		maximum := contract.MaxPublicConfigurationBytes
		switch field {
		case contract.FieldPlainValue:
			maximum = contract.CryptoMaxRawValue
		case contract.FieldTargetData:
			maximum = contract.MaxOutputTargetDataBytes
		case contract.FieldSigningPublicKey:
			maximum = contract.MaxPublicKey
		case contract.FieldEncryptionPublicKey:
			maximum = contract.KMSPublicKeyLength
		case contract.FieldContentIntent:
			maximum = contract.GeneratorIntentMaxLength
		}
		return len(value) <= maximum && cap(value) == len(value) && charge(uint64(cap(value))+uint64(unsafe.Sizeof(value)))
	case contract.ComparisonID:
		if contract.ID(value).IsZero() && field != contract.FieldResourceContract {
			return false
		}
		return charge(uint64(unsafe.Sizeof(value)))
	case contract.ComparisonIDSet:
		if len(value) == 0 {
			return false
		}
		if len(value) > contract.CryptoMaxValueEntryRecipients || cap(value) != len(value) || !charge(uint64(cap(value))*uint64(unsafe.Sizeof(contract.ComparisonMember{}))) {
			return false
		}
		for at, member := range value {
			if member.ID.IsZero() || at > 0 && bytes.Compare(value[at-1].ID[:], member.ID[:]) >= 0 {
				return false
			}
			switch member.Change {
			case contract.ComparisonMemberUnchanged, contract.ComparisonMemberAdded, contract.ComparisonMemberRemoved:
			default:
				return false
			}
		}
		return true
	case contract.ComparisonTextSet:
		maximum := contract.CryptoMaxValueEntries
		if field == contract.FieldDestinations {
			maximum = contract.MaxOutputRouteDestinations
		}
		if len(value) > maximum || cap(value) != len(value) || !charge(uint64(cap(value))*uint64(unsafe.Sizeof(""))) {
			return false
		}
		for at, text := range value {
			if !boundedReaderText(text, contract.CryptoMaxName) || at > 0 && value[at-1] >= text || !charge(uint64(len(text))) {
				return false
			}
		}
		return true
	case contract.ComparisonGroups:
		if len(value) > contract.CryptoMaxValueEntries || cap(value) != len(value) || !charge(uint64(cap(value))*uint64(unsafe.Sizeof([]string{}))) {
			return false
		}
		members := 0
		seen := make(map[string]bool)
		for at, group := range value {
			if len(group) == 0 || len(group) > contract.CryptoMaxValueEntries-members || cap(group) != len(group) || !charge(uint64(cap(group))*uint64(unsafe.Sizeof(""))) {
				return false
			}
			members += len(group)
			if at > 0 && slices.Compare(value[at-1], group) >= 0 {
				return false
			}
			for member, text := range group {
				if seen[text] || !boundedReaderText(text, contract.CryptoMaxName) || member > 0 && group[member-1] >= text || !charge(uint64(len(text))) {
					return false
				}
				seen[text] = true
			}
		}
		return true
	case contract.ComparisonDestination:
		v := contract.OutputDestination(value)
		if _, err := contract.OutputDestinationLength(v); err != nil {
			return false
		}
		return cap(v.CanonicalSettings) == len(v.CanonicalSettings) && charge(uint64(unsafe.Sizeof(value))+uint64(len(v.ConfigContractID)+len(v.ServiceContractID)+cap(v.CanonicalSettings))) && validComparisonPolicy(v.Policy, charge)
	case contract.ComparisonPolicy:
		return validComparisonPolicy(contract.OutputPolicy(value), charge)
	case contract.ComparisonBounds:
		return value.Minimum <= value.Maximum && value.Maximum <= contract.CryptoMaxRawValue && charge(uint64(unsafe.Sizeof(value)))
	}
	return false
}

func validComparisonPolicy(value contract.OutputPolicy, charge func(uint64) bool) bool {
	if _, err := contract.OutputPolicyLength(value); err != nil {
		return false
	}
	return cap(value.Data) == len(value.Data) && charge(uint64(unsafe.Sizeof(value))+uint64(len(value.ContractID)+cap(value.Data)))
}

func comparisonValuesEqual(a, b contract.ComparisonValue) bool {
	if contract.ComparisonValueTypeOf(a) != contract.ComparisonValueTypeOf(b) {
		return false
	}
	switch x := a.(type) {
	case contract.ComparisonBytes:
		return bytes.Equal(x, b.(contract.ComparisonBytes))
	case contract.ComparisonTextSet:
		return slices.Equal(x, b.(contract.ComparisonTextSet))
	case contract.ComparisonGroups:
		return slices.EqualFunc(x, b.(contract.ComparisonGroups), func(a, b []string) bool { return slices.Equal(a, b) })
	case contract.ComparisonPolicy:
		y := b.(contract.ComparisonPolicy)
		return x.ContractID == y.ContractID && bytes.Equal(x.Data, y.Data)
	case contract.ComparisonDestination:
		y := b.(contract.ComparisonDestination)
		return x.ConfigContractID == y.ConfigContractID && x.ServiceContractID == y.ServiceContractID && x.Capabilities == y.Capabilities && bytes.Equal(x.CanonicalSettings, y.CanonicalSettings) && x.Policy.ContractID == y.Policy.ContractID && bytes.Equal(x.Policy.Data, y.Policy.Data)
	case contract.ComparisonIDSet:
		return slices.EqualFunc(x, b.(contract.ComparisonIDSet), func(a, b contract.ComparisonMember) bool { return a.ID == b.ID })
	default:
		return reflect.DeepEqual(a, b)
	}
}

func validComparisonMemberships(before, after contract.ComparisonSide) bool {
	var a, b contract.ComparisonIDSet
	if before.State == contract.ComparisonPresent {
		a = before.Value.(contract.ComparisonIDSet)
	}
	if after.State == contract.ComparisonPresent {
		b = after.Value.(contract.ComparisonIDSet)
	}
	for _, pair := range []struct {
		members, other contract.ComparisonIDSet
		changed        contract.ComparisonMemberChange
	}{{a, b, contract.ComparisonMemberRemoved}, {b, a, contract.ComparisonMemberAdded}} {
		for _, member := range pair.members {
			_, found := slices.BinarySearchFunc(pair.other, member.ID, func(member contract.ComparisonMember, id contract.ID) int { return bytes.Compare(member.ID[:], id[:]) })
			want := pair.changed
			if found {
				want = contract.ComparisonMemberUnchanged
			}
			if member.Change != want {
				return false
			}
		}
	}
	return true
}

func (w *readerResultWriter) comparisonString(text string) {
	w.literal(`"`)
	start := 0
	const hexDigits = "0123456789abcdef"
	for at := 0; at < len(text); at++ {
		b := text[at]
		if b >= 0x20 && b != '"' && b != '\\' {
			continue
		}
		w.literal(text[start:at])
		switch b {
		case '"':
			w.literal(`\"`)
		case '\\':
			w.literal(`\\`)
		case '\b':
			w.literal(`\b`)
		case '\f':
			w.literal(`\f`)
		case '\n':
			w.literal(`\n`)
		case '\r':
			w.literal(`\r`)
		case '\t':
			w.literal(`\t`)
		default:
			escaped := [6]byte{'\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&15]}
			w.literal(string(escaped[:]))
		}
		start = at + 1
	}
	w.literal(text[start:])
	w.literal(`"`)
}

func (w *readerResultWriter) comparisonBytes(body []byte) {
	w.literal(`{"base64":"`)
	var encoded [4096]byte
	for len(body) != 0 {
		n := min(len(body), 3072)
		size := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(encoded[:size], body[:n])
		w.literal(string(encoded[:size]))
		body = body[n:]
	}
	w.literal(`","byte_length":`)
}

func (w *readerResultWriter) comparisonByteValue(body []byte) {
	length := len(body)
	w.comparisonBytes(body)
	w.literal(strconv.Itoa(length) + "}")
}

func (w *readerResultWriter) comparisonHumanString(text string) {
	w.literal(strconv.Quote(text))
}

func (w *readerResultWriter) comparisonValue(value contract.ComparisonValue, human bool) {
	quote := w.comparisonString
	if human {
		quote = w.comparisonHumanString
	}
	switch value := value.(type) {
	case contract.ComparisonNull:
		w.literal("null")
	case contract.ComparisonBoolean:
		w.literal(strconv.FormatBool(bool(value)))
	case contract.ComparisonUint:
		quote(strconv.FormatUint(uint64(value), 10))
	case contract.ComparisonText:
		quote(string(value))
	case contract.ComparisonBytes:
		w.comparisonByteValue(value)
	case contract.ComparisonID:
		id := contract.ID(value)
		quote(hex.EncodeToString(id[:]))
	case contract.ComparisonIDSet:
		w.literal("[")
		for at, member := range value {
			if at != 0 {
				w.literal(",")
			}
			w.literal(`{"id":`)
			quote(hex.EncodeToString(member.ID[:]))
			w.literal(`,"change":`)
			quote(string(member.Change))
			w.literal("}")
		}
		w.literal("]")
	case contract.ComparisonTextSet:
		w.literal("[")
		for at, text := range value {
			if at != 0 {
				w.literal(",")
			}
			quote(text)
		}
		w.literal("]")
	case contract.ComparisonGroups:
		w.literal("[")
		for at, group := range value {
			if at != 0 {
				w.literal(",")
			}
			w.comparisonValue(contract.ComparisonTextSet(group), human)
		}
		w.literal("]")
	case contract.ComparisonDestination:
		w.literal(`{"config_contract":`)
		quote(value.ConfigContractID)
		w.literal(`,"service_contract":`)
		quote(value.ServiceContractID)
		w.literal(`,"settings":`)
		w.comparisonByteValue(value.CanonicalSettings)
		w.literal(`,"policy":`)
		w.comparisonValue(contract.ComparisonPolicy(value.Policy), human)
		w.literal(`,"capabilities":`)
		w.comparisonValue(contract.ComparisonUint(value.Capabilities), human)
		w.literal("}")
	case contract.ComparisonPolicy:
		w.literal(`{"contract":`)
		quote(value.ContractID)
		w.literal(`,"data":`)
		w.comparisonByteValue(value.Data)
		w.literal("}")
	case contract.ComparisonBounds:
		w.literal(`{"minimum":`)
		quote(strconv.FormatUint(uint64(value.Minimum), 10))
		w.literal(`,"maximum":`)
		quote(strconv.FormatUint(uint64(value.Maximum), 10))
		w.literal("}")
	default:
		w.failed = true
	}
}

func (w *readerResultWriter) comparisonSide(side contract.ComparisonSide) {
	w.literal(`{"state":`)
	w.comparisonString(string(side.State))
	if side.State == contract.ComparisonPresent {
		w.literal(`,"type":`)
		w.comparisonString(string(contract.ComparisonValueTypeOf(side.Value)))
		w.literal(`,"value":`)
		w.comparisonValue(side.Value, false)
	}
	w.literal("}")
}

func renderProposedChanges(w *readerResultWriter, payload contract.ComparisonPayload, human bool) {
	if !human {
		w.literal(`,"changes":[`)
	}
	for at, change := range payload.Changes {
		if human {
			if at == 0 || payload.Changes[at-1].Subject != change.Subject {
				writeProposedSubjectHuman(w, change.Subject)
			}
			writeProposedChangeHuman(w, change, payload)
			continue
		}
		if at != 0 {
			w.literal(",")
		}
		record, ok := readerDiagnostic(contract.Diagnostic{Subject: change.Subject, Path: change.Path, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable, SourceLocation: change.SourceLocation})
		if !ok {
			w.failed = true
			return
		}
		w.literal(`{"subject":`)
		w.json(record.Subject, 4096)
		w.literal(`,"path":`)
		w.json(record.Path, 4096)
		w.literal(`,"action":`)
		w.comparisonString(string(change.Action))
		w.literal(`,"before":`)
		w.comparisonSide(change.Before)
		w.literal(`,"after":`)
		w.comparisonSide(change.After)
		if record.Source != nil {
			w.literal(`,"source_location":`)
			w.json(record.Source, 4096)
		}
		w.literal("}")
	}
	if !human {
		w.literal(`],"recipient_labels":{"before":`)
	}
	for side, labels := range [][]contract.ComparisonRecipientLabel{payload.BeforeRecipients, payload.AfterRecipients} {
		if !human {
			if side == 1 {
				w.literal(`,"after":`)
			}
			w.literal("[")
		}
		for at, label := range labels {
			if human {
				w.literal("Recipient ")
				if side == 0 {
					w.literal("before ")
				} else {
					w.literal("after ")
				}
				w.literal(hex.EncodeToString(label.RecipientID[:]))
			} else {
				if at != 0 {
					w.literal(",")
				}
				w.literal(`{"recipient_id":`)
				w.comparisonString(hex.EncodeToString(label.RecipientID[:]))
			}
			for _, field := range []struct {
				name  string
				value *string
			}{{"name", label.Name}, {"display_name", label.DisplayName}} {
				if field.value == nil {
					continue
				}
				if human {
					w.literal("; " + field.name + " ")
				} else {
					w.literal(`,"` + field.name + `":`)
				}
				if human {
					w.comparisonHumanString(*field.value)
				} else {
					w.comparisonString(*field.value)
				}
			}
			if human {
				w.literal("\n")
			} else {
				w.literal("}")
			}
		}
		if !human {
			w.literal("]")
		}
	}
	if !human {
		w.literal("}")
	}
}

type comparisonTextView struct {
	text string
	body []byte
}

func (v comparisonTextView) length() int {
	if v.body != nil {
		return len(v.body)
	}
	return len(v.text)
}
func (v comparisonTextView) at(at int) byte {
	if v.body != nil {
		return v.body[at]
	}
	return v.text[at]
}
func (v comparisonTextView) window(start, end int) string {
	if v.body != nil {
		return string(v.body[start:end])
	}
	return v.text[start:end]
}
func comparisonTextual(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for len(body) != 0 {
		r, size := utf8.DecodeRune(body)
		body = body[size:]
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
func comparisonTextWindow(v comparisonTextView, center int) (int, int) {
	start := max(0, center-80)
	end := min(v.length(), start+160)
	start = max(0, end-160)
	for start < end && !utf8.RuneStart(v.at(start)) {
		start++
	}
	for end > start && end < v.length() && !utf8.RuneStart(v.at(end)) {
		end--
	}
	return start, end
}
func writeComparisonTextHuman(w *readerResultWriter, value, other comparisonTextView) {
	length := value.length()
	if length <= 160 {
		w.comparisonHumanString(value.window(0, length))
		w.literal("; " + strconv.Itoa(length) + " bytes\n")
		return
	}
	prefix := 0
	for prefix < min(length, other.length()) && value.at(prefix) == other.at(prefix) {
		prefix++
	}
	suffix := 0
	for suffix < min(length-prefix, other.length()-prefix) && value.at(length-suffix-1) == other.at(other.length()-suffix-1) {
		suffix++
	}
	firstStart, firstEnd := comparisonTextWindow(value, prefix)
	lastStart, lastEnd := comparisonTextWindow(value, length-suffix)
	w.literal("preview bytes " + strconv.Itoa(firstStart) + ":" + strconv.Itoa(firstEnd) + " of " + strconv.Itoa(length) + ": ")
	w.comparisonHumanString(value.window(firstStart, firstEnd))
	if lastEnd > firstEnd && lastStart != firstStart {
		w.literal("; preview bytes " + strconv.Itoa(lastStart) + ":" + strconv.Itoa(lastEnd) + " of " + strconv.Itoa(length) + ": ")
		w.comparisonHumanString(value.window(lastStart, lastEnd))
	}
	w.literal("\n")
}
func writeProposedSubjectHuman(w *readerResultWriter, s contract.DiagnosticSubject) {
	kind := strings.ReplaceAll(string(s.Kind), "_", " ")
	w.literal(strings.ToUpper(kind[:1]) + kind[1:] + " ")
	if s.Kind == contract.SubjectEntry || s.Kind == contract.SubjectOutputTarget {
		w.comparisonHumanString(s.Name)
		w.literal(" ")
	}
	if s.DestinationID != "" {
		w.literal("destination ")
		w.comparisonHumanString(s.DestinationID)
		w.literal(" ")
	}
	if !s.RecipientID.IsZero() {
		w.literal("recipient " + readerID(s.RecipientID) + " ")
	}
	if s.Kind == contract.SubjectRoutingRule {
		if s.RoutingKey.EntrySelector == contract.PublicDefaultRoute {
			w.literal("default ")
		} else {
			w.literal("entry ")
			w.comparisonHumanString(s.RoutingKey.EntryName)
			w.literal(" ")
		}
	}
	w.literal("\n")
}

func writeProposedChangeHuman(w *readerResultWriter, change contract.ComparisonChange, payload contract.ComparisonPayload) {
	w.literal("  ")
	for at, field := range change.Path {
		if at != 0 {
			w.literal(".")
		}
		w.literal(string(field))
	}
	w.literal(" (" + string(change.Action) + ")\n")
	for index, pair := range []struct {
		name        string
		side, other contract.ComparisonSide
	}{{"before", change.Before, change.After}, {"after", change.After, change.Before}} {
		w.literal("    " + pair.name + ": ")
		if pair.side.State == contract.ComparisonAbsent {
			w.literal("absent\n")
			continue
		}
		switch value := pair.side.Value.(type) {
		case contract.ComparisonText:
			other, _ := pair.other.Value.(contract.ComparisonText)
			writeComparisonTextHuman(w, comparisonTextView{text: string(value)}, comparisonTextView{text: string(other)})
		case contract.ComparisonBytes:
			other, _ := pair.other.Value.(contract.ComparisonBytes)
			if change.Path[len(change.Path)-1] == contract.FieldPlainValue && comparisonTextual(value) {
				writeComparisonTextHuman(w, comparisonTextView{body: value}, comparisonTextView{body: other})
			} else {
				w.literal("bytes; " + strconv.Itoa(len(value)) + " bytes\n")
			}
		case contract.ComparisonDestination:
			w.literal("destination ")
			w.comparisonHumanString(value.ConfigContractID)
			w.literal("; service ")
			w.comparisonHumanString(value.ServiceContractID)
			w.literal("; settings " + strconv.Itoa(len(value.CanonicalSettings)) + " bytes; policy ")
			w.comparisonHumanString(value.Policy.ContractID)
			w.literal(" " + strconv.Itoa(len(value.Policy.Data)) + " bytes; capabilities " + strconv.Itoa(int(value.Capabilities)) + "\n")
		case contract.ComparisonPolicy:
			w.literal("policy ")
			w.comparisonHumanString(value.ContractID)
			w.literal("; " + strconv.Itoa(len(value.Data)) + " bytes\n")
		case contract.ComparisonIDSet:
			if len(value) == 0 {
				w.literal("empty membership\n")
				continue
			}
			w.literal("\n")
			labels := payload.BeforeRecipients
			if index == 1 {
				labels = payload.AfterRecipients
			}
			for _, member := range value {
				w.literal("      " + readerID(member.ID) + " (" + string(member.Change) + ")")
				if at, found := slices.BinarySearchFunc(labels, member.ID, func(label contract.ComparisonRecipientLabel, id contract.ID) int {
					return bytes.Compare(label.RecipientID[:], id[:])
				}); found {
					if labels[at].Name != nil {
						w.literal("; name ")
						w.comparisonHumanString(*labels[at].Name)
					}
					if labels[at].DisplayName != nil {
						w.literal("; display name ")
						w.comparisonHumanString(*labels[at].DisplayName)
					}
				}
				w.literal("\n")
			}
		default:
			w.comparisonValue(pair.side.Value, true)
			w.literal("\n")
		}
	}
	if change.SourceLocation != nil {
		w.literal("    Source ")
		w.comparisonHumanString(change.SourceLocation.SourceID)
		w.literal(" location " + strconv.FormatUint(change.SourceLocation.Line, 10) + ":" + strconv.FormatUint(change.SourceLocation.Column, 10) + "\n")
	}
}

func renderComparisonResultBound(maximum int, readable bool, write func(*readerResultWriter)) ([]byte, error) {
	if readable {
		return renderReaderResultJSONBound(maximum, maximum, write)
	}
	return renderReaderResultBound(maximum, write)
}
