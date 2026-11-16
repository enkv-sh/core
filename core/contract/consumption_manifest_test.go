package contract

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"enkv.sh/sdk/artifact"
	manifest "enkv.sh/sdk/manifest-generator"
)

func manifestRequestFixture() ManifestRequest {
	return ManifestRequest{
		Renderer: ManifestRendererSelection{
			Name: "private-ini", Version: "1.2.3", ProtocolID: ID{1}, DescriptorID: ID{2}, ExecutorID: ID{3},
			ArtifactContractID: ID{4}, DependencyManifestID: ID{5}, ArtifactID: ID{6}, ArtifactSHA256: ID{7}, ArtifactLength: 123,
		},
		FormatContractID: "PRIVATE/INI/v1", ConfigContractID: "PRIVATE/INI-CONFIG/v1", Settings: []byte(`{"prefix":"app"}`),
		TargetMode: manifest.CurrentAuthority, EntryMode: manifest.AllAuthorized,
	}
}

// full_only: false
func TestManifestRequestOwnsExplicitExactSelection(t *testing.T) {
	request := manifestRequestFixture()
	request.TargetMode, request.EntryMode, request.TargetRecipientID = manifest.ExactRecipient, manifest.ExactNames, ID{9}
	request.EntryNames = []string{"a/\n雪", ""}
	want := request
	want.EntryNames = []string{"", "a/\n雪"}
	owned, err := OwnManifestRequest(request)
	if err != nil || !reflect.DeepEqual(owned, want) {
		t.Fatal("exact canonical request", owned, err)
	}
	request.EntryNames[0] = "changed"
	if owned.EntryNames[1] != "a/\n雪" {
		t.Fatal("request borrows caller collection")
	}
	request.EntryNames = []string{}
	empty, err := OwnManifestRequest(request)
	if err != nil || empty.EntryNames == nil || len(empty.EntryNames) != 0 {
		t.Fatal("explicit empty selection lost", empty, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*ManifestRequest)
		reason DiagnosticReason
	}{
		{"omitted-target", func(r *ManifestRequest) { r.TargetMode = "" }, ReasonMissingRequiredField},
		{"omitted-selection", func(r *ManifestRequest) { r.EntryNames = nil }, ReasonMissingRequiredField},
		{"duplicate", func(r *ManifestRequest) { r.EntryNames = []string{"", ""} }, ReasonDuplicateEntry},
		{"invalid-utf8", func(r *ManifestRequest) { r.EntryNames = []string{string([]byte{0xff})} }, ReasonInvalidUTF8},
		{"long-name", func(r *ManifestRequest) { r.EntryNames = []string{strings.Repeat("n", CryptoMaxName+1)} }, ReasonLimitExceeded},
		{"too-many", func(r *ManifestRequest) { r.EntryNames = make([]string, CryptoMaxValueEntries+1) }, ReasonLimitExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := request
			tc.change(&input)
			assertManifestRequestRefused(t, input, tc.reason)
		})
	}
}

// full_only: false
func TestManifestRequestOwnsTaggedScope(t *testing.T) {
	filter := "PRIVATE/value-service/v2"
	defaults := manifestRequestFixture()
	defaults.ServiceFilter = &filter
	got, err := OwnManifestRequest(defaults)
	if err != nil || got.TargetMode != manifest.CurrentAuthority || got.EntryMode != manifest.AllAuthorized || got.ServiceFilter == nil || *got.ServiceFilter != filter || got.EntryNames != nil {
		t.Fatal("valid default scope", got, err)
	}
	filter = "PRIVATE/other-service/v1"
	if *got.ServiceFilter != "PRIVATE/value-service/v2" {
		t.Fatal("filter borrows caller")
	}
	for _, tc := range []struct {
		name   string
		change func(*ManifestRequest)
	}{
		{"missing-target-mode", func(r *ManifestRequest) { r.TargetMode = "" }},
		{"unknown-target-mode", func(r *ManifestRequest) { r.TargetMode = "CURRENT-AUTHORITY" }},
		{"default-with-target", func(r *ManifestRequest) { r.TargetRecipientID = ID{1} }},
		{"exact-without-target", func(r *ManifestRequest) { r.TargetMode = manifest.ExactRecipient }},
		{"missing-entry-mode", func(r *ManifestRequest) { r.EntryMode = "" }},
		{"unknown-entry-mode", func(r *ManifestRequest) { r.EntryMode = "ALL-AUTHORIZED" }},
		{"all-with-empty-names", func(r *ManifestRequest) { r.EntryNames = []string{} }},
		{"all-with-names", func(r *ManifestRequest) { r.EntryNames = []string{""} }},
		{"exact-with-nil", func(r *ManifestRequest) { r.EntryMode = manifest.ExactNames }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := defaults
			tc.change(&input)
			if owned, err := OwnManifestRequest(input); err == nil || !reflect.DeepEqual(owned, ManifestRequest{}) {
				t.Fatal("invalid tagged scope admitted", owned, err)
			}
		})
	}
}

// full_only: false
func TestManifestRequestOwnsOpenRendererAndSettings(t *testing.T) {
	callerText := func(value string) string {
		const padding = 1 << 20
		backing := strings.Repeat("x", padding) + value + strings.Repeat("x", padding)
		return backing[padding : padding+len(value)]
	}
	for _, scope := range []struct {
		target manifest.TargetMode
		entry  manifest.EntryMode
		filter string
	}{
		{manifest.CurrentAuthority, manifest.AllAuthorized, "PRIVATE/another-service/v1"},
		{manifest.ExactRecipient, manifest.ExactNames, "PRIVATE/雪-service/v1"},
		{manifest.CurrentAuthority, manifest.ExactNames, "PRIVATE/value-service/v2"},
	} {
		input := manifestRequestFixture()
		input.Renderer.Name, input.Renderer.Version = callerText(input.Renderer.Name), callerText(input.Renderer.Version)
		input.FormatContractID, input.ConfigContractID = callerText(input.FormatContractID), callerText(input.ConfigContractID)
		input.TargetMode, input.EntryMode = manifest.TargetMode(callerText(string(scope.target))), manifest.EntryMode(callerText(string(scope.entry)))
		filter := callerText(scope.filter)
		input.ServiceFilter = &filter
		if scope.target == manifest.ExactRecipient {
			input.TargetRecipientID = ID{9}
		}
		if scope.entry == manifest.ExactNames {
			input.EntryNames = []string{callerText("a/\n雪")}
		}
		owned, err := OwnManifestRequest(input)
		if err != nil || !reflect.DeepEqual(owned, input) {
			t.Fatal("open renderer request changed meaning", owned, err)
		}
		for _, field := range []struct{ name, input, owned string }{
			{"renderer name", input.Renderer.Name, owned.Renderer.Name},
			{"renderer version", input.Renderer.Version, owned.Renderer.Version},
			{"format contract", input.FormatContractID, owned.FormatContractID},
			{"config contract", input.ConfigContractID, owned.ConfigContractID},
			{"target mode", string(input.TargetMode), string(owned.TargetMode)},
			{"entry mode", string(input.EntryMode), string(owned.EntryMode)},
			{"service filter", *input.ServiceFilter, *owned.ServiceFilter},
		} {
			if unsafe.StringData(field.owned) == unsafe.StringData(field.input) {
				t.Errorf("%s retains oversized caller backing", field.name)
			}
		}
		if len(input.EntryNames) != 0 && unsafe.StringData(input.EntryNames[0]) == unsafe.StringData(owned.EntryNames[0]) {
			t.Fatal("entry name retains oversized caller backing")
		}
		input.Settings[0] = '['
		if string(owned.Settings) != `{"prefix":"app"}` || len(owned.Settings) != cap(owned.Settings) {
			t.Fatal("settings ownership differs")
		}
	}
	// These sizes follow from seven 32-byte IDs, two string descriptors and
	// one uint64 in the selection, plus the declared request/scope fields.
	if unsafe.Sizeof(ManifestRendererSelection{}) != 264 || unsafe.Sizeof(ManifestRequest{}) != 416 || unsafe.Sizeof(ManifestRequestScope{}) != 360 {
		t.Fatal("open request descriptor account differs")
	}
}

// full_only: false
func TestManifestRequestRejectsInvalidRendererAndSettings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ManifestRequest)
		reason DiagnosticReason
	}{
		{"no-renderer", func(r *ManifestRequest) { r.Renderer = ManifestRendererSelection{} }, ReasonMissingRequiredField},
		{"invalid-name", func(r *ManifestRequest) { r.Renderer.Name = "private/ini" }, ReasonInvalidInput},
		{"long-name", func(r *ManifestRequest) { r.Renderer.Name = strings.Repeat("x", 256) }, ReasonLimitExceeded},
		{"invalid-version", func(r *ManifestRequest) { r.Renderer.Version = "latest" }, ReasonInvalidInput},
		{"long-version", func(r *ManifestRequest) { r.Renderer.Version = strings.Repeat("1", 129) }, ReasonLimitExceeded},
		{"zero-length", func(r *ManifestRequest) { r.Renderer.ArtifactLength = 0 }, ReasonMissingRequiredField},
		{"excess-length", func(r *ManifestRequest) { r.Renderer.ArtifactLength = artifact.MaxExecutableBytes + 1 }, ReasonLimitExceeded},
		{"no-format", func(r *ManifestRequest) { r.FormatContractID = "" }, ReasonMissingRequiredField},
		{"no-config", func(r *ManifestRequest) { r.ConfigContractID = "" }, ReasonMissingRequiredField},
		{"long-format", func(r *ManifestRequest) { r.FormatContractID = strings.Repeat("x", 257) }, ReasonLimitExceeded},
		{"long-config", func(r *ManifestRequest) { r.ConfigContractID = strings.Repeat("x", 257) }, ReasonLimitExceeded},
		{"invalid-format-utf8", func(r *ManifestRequest) { r.FormatContractID = string([]byte{0xff}) }, ReasonInvalidUTF8},
		{"invalid-config-utf8", func(r *ManifestRequest) { r.ConfigContractID = string([]byte{0xff}) }, ReasonInvalidUTF8},
		{"no-settings", func(r *ManifestRequest) { r.Settings = nil }, ReasonInvalidInput},
		{"invalid-settings-json", func(r *ManifestRequest) { r.Settings = []byte(`{"x":}`) }, ReasonInvalidInput},
		{"invalid-settings-utf8", func(r *ManifestRequest) { r.Settings = []byte{0xff} }, ReasonInvalidUTF8},
		{"long-settings", func(r *ManifestRequest) { r.Settings = []byte(`"` + strings.Repeat("s", 16383) + `"`) }, ReasonLimitExceeded},
		{"empty-filter", func(r *ManifestRequest) { s := ""; r.ServiceFilter = &s }, ReasonMissingRequiredField},
		{"long-filter", func(r *ManifestRequest) { s := strings.Repeat("x", 257); r.ServiceFilter = &s }, ReasonLimitExceeded},
		{"invalid-filter-utf8", func(r *ManifestRequest) { s := string([]byte{0xff}); r.ServiceFilter = &s }, ReasonInvalidUTF8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := manifestRequestFixture()
			tc.change(&input)
			assertManifestRequestRefused(t, input, tc.reason)
		})
	}
	for _, field := range []string{"protocol", "descriptor", "executor", "artifact-contract", "dependency", "artifact", "executable"} {
		t.Run("missing-"+field, func(t *testing.T) {
			input := manifestRequestFixture()
			ids := map[string]*ID{
				"protocol": &input.Renderer.ProtocolID, "descriptor": &input.Renderer.DescriptorID, "executor": &input.Renderer.ExecutorID,
				"artifact-contract": &input.Renderer.ArtifactContractID, "dependency": &input.Renderer.DependencyManifestID,
				"artifact": &input.Renderer.ArtifactID, "executable": &input.Renderer.ArtifactSHA256,
			}
			*ids[field] = ID{}
			assertManifestRequestRefused(t, input, ReasonMissingRequiredField)
		})
	}
}

// full_only: false
func TestManifestRequestAcceptsCommonBoundsWithoutFormatInterpretation(t *testing.T) {
	request := manifestRequestFixture()
	request.Renderer.Name = strings.Repeat("n", 255)
	request.Renderer.Version = "1.2.3+" + strings.Repeat("b", 122)
	request.Renderer.ArtifactLength = artifact.MaxExecutableBytes
	request.FormatContractID, request.ConfigContractID = strings.Repeat("f", 256), strings.Repeat("c", 256)
	filter := strings.Repeat("s", 256)
	request.ServiceFilter = &filter
	request.Settings = []byte(`"` + strings.Repeat("x", 16382) + `"`)
	request.EntryMode = manifest.ExactNames
	request.EntryNames = make([]string, 512)
	for i := range request.EntryNames {
		request.EntryNames[i] = strings.Repeat("n", 254) + string([]byte{byte(i / 128), byte(i % 128)})
	}
	owned, err := OwnManifestRequest(request)
	if err != nil || len(owned.EntryNames) != 512 || !bytes.Equal(owned.Settings, request.Settings) || owned.Renderer != request.Renderer {
		t.Fatal("common bounds refused", owned.Renderer, err)
	}
	// Core preserves syntactically valid author bytes; only the selected
	// implementation can decide their semantic meaning and canonical form.
	request = manifestRequestFixture()
	request.Settings = []byte(" {\"unknown-author-setting\" : true} ")
	owned, err = OwnManifestRequest(request)
	if err != nil || !bytes.Equal(owned.Settings, request.Settings) || owned.FormatContractID != "PRIVATE/INI/v1" {
		t.Fatal("Core interpreted or rewrote author settings", err)
	}
}

func assertManifestRequestRefused(t *testing.T, request ManifestRequest, reason DiagnosticReason) {
	t.Helper()
	got, err := OwnManifestRequest(request)
	var failure ManifestRequestError
	if !errors.As(err, &failure) || failure.Reason != reason || !reflect.DeepEqual(got, ManifestRequest{}) {
		t.Fatal("invalid request exposed partial facts", got, err, "want", reason)
	}
}
