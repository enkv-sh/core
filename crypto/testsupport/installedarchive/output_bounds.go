package installedarchive

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// This fixture has one empty Genesis and one selection of 64 empty plain
// values and a 32 MiB output declaration. It contains no secret oracle.
const OutputBoundsArchiveBodyBytes = 36 << 20
const OutputBoundsArchiveJSONBytes = 4*((OutputBoundsArchiveBodyBytes+2)/3) + 4*64 + (1 << 20)
const OutputBoundsArchiveGZIPBytes = 64 << 20

func checkOutputBoundsArchive(fixture RecoveryFixture) (string, bool) {
	a := fixture.Archive
	if fixture.Secrets != 0 || len(fixture.Oracles) != 0 || len(fixture.Values) != 64 || len(a.Objects) > 64 || a.Family != contract.AWS || len(a.SignerSelector) > 1024 || len(a.SignerPublicKey) > 256 || len(a.AuthorityBinding.SPKI) > 422 || len(a.AuthorityBinding.KeySelector) > 1024 {
		return fmt.Sprintf("stage=header secrets=%d oracles=%d values=%d objects=%d family=%d signing_selector_bytes=%d signing_key_bytes=%d encryption_key_bytes=%d encryption_selector_bytes=%d", fixture.Secrets, len(fixture.Oracles), len(fixture.Values), len(a.Objects), a.Family, len(a.SignerSelector), len(a.SignerPublicKey), len(a.AuthorityBinding.SPKI), len(a.AuthorityBinding.KeySelector)), false
	}
	parts, err := a.SelectedParts()
	if err != nil {
		return "stage=selected-parts", false
	}
	var root format.Root
	for _, part := range parts {
		if part.Kind == "root" {
			root, err = format.DecodeRoot(part.Body)
		}
	}
	if err != nil || root.ValueEntryCount != 64 || root.SecretCount != 0 || root.RawBytes != 0 || root.MembershipCount != 64 || root.RecipientCount != 3 || root.Generated.GeneratedCurrent != 0 || root.OutputConfiguration.BindingCount != 1 || root.OutputConfiguration.TotalLength != 33554446 || root.OutputConfiguration.RoutingLength != 10 || root.OutputConfiguration.SliceCount != 33 {
		return fmt.Sprintf("stage=root decode_failed=%t values=%d secrets=%d raw_bytes=%d memberships=%d recipients=%d generated=%d bindings=%d output_bytes=%d routing_bytes=%d slices=%d", err != nil, root.ValueEntryCount, root.SecretCount, root.RawBytes, root.MembershipCount, root.RecipientCount, root.Generated.GeneratedCurrent, root.OutputConfiguration.BindingCount, root.OutputConfiguration.TotalLength, root.OutputConfiguration.RoutingLength, root.OutputConfiguration.SliceCount), false
	}
	for _, value := range fixture.Values {
		if len(value.Name) != 256 || len(value.Bytes) != 0 {
			return fmt.Sprintf("stage=value-shape name_bytes=%d value_bytes=%d", len(value.Name), len(value.Bytes)), false
		}
	}
	counts := map[string]int{}
	var total, output, otherSupport uint64
	outputRows := 0
	for _, object := range a.Objects {
		if len(object.Key) > contract.MaxStoreObjectKeyLength || len(object.TokenWire) > 261 {
			return fmt.Sprintf("stage=object-metadata key_bytes=%d token_bytes=%d", len(object.Key), len(object.TokenWire)), false
		}
		total += uint64(len(object.Body))
		kind, maximum, countLimit := "", 0, 0
		switch {
		case object.Key == a.Location.PrefixBeforeHEAD+"/HEAD":
			kind, maximum, countLimit = "head", 64<<10, 1
		case strings.Contains(object.Key, "/configuration/"):
			kind, maximum, countLimit = "configuration", 4<<10, 1
		case strings.Contains(object.Key, "/root/"):
			kind, maximum, countLimit = "root", 256<<10, 2
		case strings.Contains(object.Key, "/recipient/"):
			kind, maximum, countLimit = "recipient", 96<<10, 1
		case strings.Contains(object.Key, "/member/"):
			kind, maximum, countLimit = "value", 75+16*(154+256+32), 4
		case strings.Contains(object.Key, "/admin-index/"):
			kind, maximum, countLimit = "index", 32<<10, 2
		case strings.Contains(object.Key, "/support/"):
			kind, maximum, countLimit = "support", 2<<20, 38
			page, err := format.InspectRequiredSupportPage(object.Body)
			if err != nil {
				return "stage=support-page", false
			}
			outputPage := false
			for _, row := range page.Records {
				if row.Kind == contract.OutputConfigurationSliceSupportKind {
					slice, err := contract.InspectOutputConfigurationSlice(row.Body)
					if err != nil {
						return "stage=output-slice", false
					}
					if slice.ConfigurationDigest == root.OutputConfiguration.ConfigurationDigest {
						outputRows++
						output += uint64(len(row.Body) + 37)
						outputPage = true
						continue
					}
				}
				otherSupport += uint64(len(row.Body) + 37)
			}
			if outputPage {
				output += 75
			} else {
				otherSupport += 75
			}
		default:
			return fmt.Sprintf("stage=object-kind kind=unknown object_bytes=%d total_bytes=%d counts=%v", len(object.Body), total, counts), false
		}
		counts[kind]++
		if len(object.Body) > maximum || counts[kind] > countLimit {
			return fmt.Sprintf("stage=object-bound kind=%s object_bytes=%d maximum_bytes=%d count=%d count_limit=%d total_bytes=%d counts=%v", kind, len(object.Body), maximum, counts[kind], countLimit, total, counts), false
		}
	}
	return fmt.Sprintf("stage=aggregate objects=%d body_bytes=%d output_rows=%d output_bytes=%d other_support_bytes=%d counts=%v", len(a.Objects), total, outputRows, output, otherSupport, counts), outputRows == 33 && output <= 33560716 && otherSupport <= 109707 && total <= OutputBoundsArchiveBodyBytes
}

// WriteOutputBoundsFixture retains the actual signed archive produced by the
// ordinary local test selection. Expected value names remain public metadata.
func WriteOutputBoundsFixture(t testing.TB, path string, fixture RecoveryFixture) {
	t.Helper()
	inventory, valid := checkOutputBoundsArchive(fixture)
	t.Logf("output bounds fixture inventory: %s", inventory)
	if !valid {
		t.Fatal("output bounds fixture inventory refused")
	}
	body, err := json.Marshal(fixture)
	if err != nil || len(body) > OutputBoundsArchiveJSONBytes {
		t.Fatal("output bounds fixture JSON refused")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("output bounds fixture output unavailable")
	}
	compressed := gzip.NewWriter(file)
	_, writeErr := compressed.Write(body)
	gzipErr := compressed.Close()
	closeErr := file.Close()
	clear(body)
	info, statErr := os.Stat(path)
	if writeErr != nil || gzipErr != nil || closeErr != nil || statErr != nil || info.Size() > OutputBoundsArchiveGZIPBytes {
		t.Fatal("output bounds fixture compression incomplete")
	}
}

func ReadOutputBoundsFixture(t testing.TB, path string) Archive {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("output bounds fixture unavailable")
	}
	archive, readErr := decodeOutputBoundsFixture(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("output bounds fixture bounded archive refused")
	}
	return archive
}

func decodeOutputBoundsFixture(reader io.Reader) (Archive, error) {
	refused := errors.New("output bounds fixture bounded archive refused")
	limited := &io.LimitedReader{R: reader, N: OutputBoundsArchiveGZIPBytes + 1}
	buffered := bufio.NewReader(limited)
	compressed, err := gzip.NewReader(buffered)
	if err != nil {
		return Archive{}, errors.Join(refused, err)
	}
	compressed.Multistream(false)
	fixture, readErr := decodeRecoveryFixtureBounded(compressed, OutputBoundsArchiveJSONBytes, OutputBoundsArchiveBodyBytes, false)
	gzipErr := compressed.Close()
	_, trailing := buffered.Peek(1)
	_, valid := checkOutputBoundsArchive(fixture)
	if readErr != nil || gzipErr != nil || trailing != io.EOF || limited.N <= 0 || !valid {
		return Archive{}, errors.Join(refused, readErr, gzipErr)
	}
	return fixture.Archive, nil
}
