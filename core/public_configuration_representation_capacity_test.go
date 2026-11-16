package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: true
func TestPublicConfigurationMaximumBase64Capacity(t *testing.T) {
	t.Run("joint-desired-axes", func(t *testing.T) {
		input := publicCapacityDesiredFixture(t)
		content, retained, encodedEntries := 0, 0, 0
		for at := range input.Entries.Value {
			entry := &input.Entries.Value[at]
			if entry.Class.Value != contract.Plain {
				continue
			}
			plain := entry.PlainValue.Value
			content += len(plain)
			body := make([]byte, 4*((len(plain)+2)/3))
			base64.StdEncoding.Encode(body, plain)
			entry.InputEncoding, entry.PlainValue = publicPresent(contract.InputEncodingBase64), publicPresent(body)
			retained += len(body)
			encodedEntries++
		}
		// The existing joint image has128 full65536-byte plain values,
		// 256 empty plain values and128 complete generated declarations.
		const maximumRetained = 128 * 4 * ((65536 + 2) / 3)
		const semantic = 99577838 + maximumRetained - 8388608
		if maximumRetained != 11185152 || semantic != 102374382 || semantic > contract.MaxPublicConfigurationBytes {
			t.Fatal("independent joint representation account changed")
		}
		if content != 8388608 || retained != maximumRetained || encodedEntries != 384 {
			t.Fatal("joint fixture differs from independent representation account", content, retained, encodedEntries)
		}
		outputs, generators := 0, 0
		v := publicFixtureValidator(t, &outputs, &generators)
		publicFixtureInstallSources(v, input.OutputBindings.Value...)
		got := v.Validate(t.Context(), input)
		if !got.Valid || !got.Complete || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || outputs != 0 || generators != 0 || len(got.Configuration.Entries.Value) != 512 || len(got.Configuration.OutputBindings.Value) != 64 || len(got.Configuration.Routing.Value) != 513 {
			t.Fatal("joint Base64 maximum refused or changed logical counts", got.Diagnostics)
		}
		for _, entry := range input.Entries.Value {
			if entry.Class.Value != contract.Plain {
				continue
			}
			at := slices.IndexFunc(got.Configuration.Entries.Value, func(row contract.PublicEntry) bool { return row.Name == entry.Name })
			if at < 0 || got.Configuration.Entries.Value[at].InputEncoding.Value != contract.InputEncodingBase64 || !bytes.Equal(got.Configuration.Entries.Value[at].PlainValue.Value, entry.PlainValue.Value) || cap(got.Configuration.Entries.Value[at].PlainValue.Value) != len(entry.PlainValue.Value) {
				t.Fatal("captured maximum changed retained representation or capacity", entry.Name)
			}
		}
	})
	// Release the preceding maximum fixture before constructing a different
	// independent maximum. This is not an RSS or allocator qualification.
	runtime.GC()
	t.Run("retained-set-and-logical-one-over", func(t *testing.T) {
		input := publicConfigurationFixture(t)
		// 5461 complete zero sextet groups plusAA== encode16384 zero bytes.
		// All512 entry lengths are1mod3, attaining the joint padding maximum.
		body := []byte(strings.Repeat("AAAA", 5461) + "AA==")
		if len(body) != 21848 || 512*len(body) != 11186176 || 512*16384 != 8388608 || contract.CryptoMaxRetainedSet != 11186176 || contract.CryptoMaxRawSet != 8388608 {
			t.Fatal("independent retained-set account changed")
		}
		input.Entries.Value = make([]contract.PublicEntry, 512)
		for at := range input.Entries.Value {
			entry := publicFixtureEntry(input, fmt.Sprintf("plain-%03d", at))
			entry.Class, entry.InputEncoding, entry.OutputEncoding, entry.PlainValue = publicPresent(contract.Plain), publicPresent(contract.InputEncodingBase64), publicPresent(contract.OutputEncodingRaw), publicPresent(body)
			input.Entries.Value[at] = entry
		}
		v := NewPublicConfigurationValidator(nil)
		got := v.Validate(t.Context(), input)
		if !got.Valid || !got.Complete || !got.DiagnosticsComplete || len(got.Diagnostics) != 0 || len(got.Configuration.Entries.Value) != 512 {
			t.Fatal("exact retained-set maximum refused", got.Diagnostics)
		}
		for _, entry := range got.Configuration.Entries.Value {
			if entry.InputEncoding.Value != contract.InputEncodingBase64 || !bytes.Equal(entry.PlainValue.Value, body) || cap(entry.PlainValue.Value) != 21848 {
				t.Fatal("maximum retained value changed")
			}
		}
		// AAA= encodes one additional zero byte at exactly the same retained
		// length. The logical and retained quotas cannot substitute for each other.
		input.Entries.Value[511].PlainValue = publicPresent([]byte(strings.Repeat("AAAA", 5461) + "AAA="))
		if len(input.Entries.Value[511].PlainValue.Value) != len(body) {
			t.Fatal("one-over changed retained length")
		}
		refused := v.Validate(t.Context(), input)
		if refused.Valid || refused.Complete || !reflect.DeepEqual(refused.Configuration, contract.PublicConfiguration{}) || len(refused.Diagnostics) != 1 || refused.Diagnostics[0].Reason != contract.ReasonLimitExceeded {
			t.Fatal("logical one-over reached capture at unchanged retained maximum", refused.Diagnostics)
		}
	})
}
