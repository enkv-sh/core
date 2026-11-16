package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// These bytes independently encode the schema5 grammar. Altering a flag or
// encoding does not ask the production writer to create a malformed image.
func outputShapeImage(encoding uint8, flag uint8, locator string) ([]byte, OutputConfigurationDescriptor, OutputConfigurationSlice, OutputConfiguration) {
	blob := func(dst []byte, s string) []byte {
		dst = binary.BigEndian.AppendUint32(dst, uint32(len(s)))
		return append(dst, s...)
	}
	body := blob([]byte{0, 5, 0, 1}, "d")
	body = append(body, bytes.Repeat([]byte{2}, 32)...)
	for _, v := range []string{"config", "p", "{}", ""} {
		body = blob(body, v)
	}
	body = append(body, 63, 0, 1)
	body = append(body, bytes.Repeat([]byte{3}, 32)...)
	for _, v := range []string{"p", "q", "s", locator, ""} {
		body = blob(body, v)
	}
	body = append(body, encoding, 63, flag)
	body = append(body, make([]byte, 16)...) // Four zero u32 interval endpoints.
	body = blob(body, "")
	body = append(body, 0, 0)
	body = blob(body, string([]byte{0, 3, 0, 0, 0}))
	preimage := append([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"), bytes.Repeat([]byte{1}, 32)...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(body)))
	digest := sha256.Sum256(append(preimage, body...))
	descriptor := OutputConfigurationDescriptor{Schema: 5, ConfigurationDigest: digest, TotalLength: uint32(len(body)), SliceCount: 1, BindingCount: 1, RoutingLength: 5}
	part := OutputConfigurationSlice{Schema: 5, DomainID: publicationTestID(1), ConfigurationDigest: digest, SliceCount: 1, TotalLength: uint32(len(body)), SliceBytes: body}
	configuration := OutputConfiguration{Schema: 5, DomainID: publicationTestID(1), Bindings: []OutputBinding{{DestinationID: "d", IncarnationID: publicationTestID(2), Destination: OutputDestination{ConfigContractID: "config", ServiceContractID: "p", CanonicalSettings: []byte("{}"), Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}, Targets: []OutputTarget{{EntryIncarnationID: publicationTestID(3), ServiceContractID: "p", TargetContractID: "q", CanonicalTarget: "s", ConsumerLocator: locator, PayloadEncoding: encoding, LocatorRequiresCreation: flag == 1, Capabilities: OutputCapabilityCreateEmpty | OutputCapabilityCreateWithValue | OutputCapabilityWriteValue | OutputCapabilityUpdatePolicy | OutputCapabilityDeleteOwned | OutputCapabilityDeleteReservedSlot}}}}}
	return body, descriptor, part, configuration
}

// full_only: false
func TestOutputConfigurationTypedEncodingAndLocatorAcrossCodecs(t *testing.T) {
	for _, test := range []struct {
		name           string
		encoding, flag uint8
		locator        string
		valid          bool
	}{{"static", 1, 0, "l", true}, {"assigned", 1, 1, "", true}, {"missing-static", 1, 0, "", false}, {"assigned-text", 1, 1, "l", false}, {"invalid-flag", 1, 2, "", false}, {"invalid-encoding", 0, 0, "l", false}, {"unsupported-encoding", 3, 0, "l", false}} {
		t.Run(test.name, func(t *testing.T) {
			body, descriptor, part, configuration := outputShapeImage(test.encoding, test.flag, test.locator)
			source := func(uint16) (OutputConfigurationSlice, error) { return part, nil }
			paths := map[string]func() error{"complete": func() error { _, _, err := InspectOutputConfiguration(configuration.DomainID, body); return err }, "split": func() error { _, _, err := SplitOutputConfiguration(configuration.DomainID, body); return err }, "stream validation": func() error { return ValidateOutputConfigurationSource(configuration.DomainID, descriptor, source) }, "stream materialization": func() error {
				_, err := InspectOutputConfigurationSource(configuration.DomainID, descriptor, source)
				return err
			}}
			if test.flag <= 1 {
				paths["writer"] = func() error { _, err := EncodeOutputConfiguration(configuration); return err }
				paths["counter"] = func() error { _, err := OutputConfigurationLength(configuration); return err }
				paths["comparison"] = func() error { return matchOutputConfiguration(configuration, descriptor, [][]byte{body}) }
			}
			for name, check := range paths {
				t.Run(name, func(t *testing.T) {
					if err := check(); (err == nil) != test.valid {
						t.Fatal("codec admission", err)
					}
				})
			}
			if test.valid {
				got, err := EncodeOutputConfiguration(configuration)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatal("independent framing", err)
				}
			}
		})
	}
}
