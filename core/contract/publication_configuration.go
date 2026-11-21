package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	outputprotocol "enkv.sh/sdk/protocols/output"
	"hash"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	OutputConfigurationSchema              = 5
	MaxOutputDestinationSettings           = outputprotocol.MaximumSettingsBytes
	MaxOutputTargetDataBytes               = outputprotocol.MaximumTargetDataBytes
	MaxOutputPolicyRecordBytes             = 524812
	MaxOutputBindings                      = 64
	MaxOutputTargets                       = 1024
	MaxOutputTargetsPerBinding             = CryptoMaxValueEntries
	MaxOutputRouteDestinations             = 8
	MaxOutputPolicyBytes                   = outputprotocol.MaximumPolicyBytes
	MaxOutputRoutingBytes                  = 4 << 20
	MaxOutputDeclarationBytes              = 32 << 20
	MaxOutputConfigurationBytes            = (32 + 4) << 20
	MaxOutputConfigurationSliceBytes       = 1048423
	MaxOutputConfigurationSlices           = 37
	OutputConfigurationSliceBodyOverhead   = 78
	OutputConfigurationSliceFramedOverhead = OutputConfigurationSliceBodyOverhead + SupportRecordOverhead
)

const (
	OutputEncodingRaw    uint8 = outputprotocol.EncodingRaw
	OutputEncodingBase64 uint8 = outputprotocol.EncodingBase64
)

// OutputActionCapabilities carries the public family's action and policy
// flags. Capabilities describe plugin support and grant no effect permission.
type OutputActionCapabilities uint8

const (
	OutputCapabilityCreateEmpty        OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityCreateEmpty)
	OutputCapabilityCreateWithValue    OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityCreateWithValue)
	OutputCapabilityWriteValue         OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityWriteValue)
	OutputCapabilityUpdatePolicy       OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityUpdatePolicy)
	OutputCapabilityDeleteOwned        OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityDeleteOwned)
	OutputCapabilityDeleteReservedSlot OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityDeleteReservedSlot)
	OutputCapabilityCreateSetsPolicy   OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityCreateSetsPolicy)
	OutputCapabilityWriteSetsPolicy    OutputActionCapabilities = OutputActionCapabilities(outputprotocol.CapabilityWriteSetsPolicy)
)

// CreateSetsPolicy reports whether an advertised create also applies policy.
func (v OutputActionCapabilities) CreateSetsPolicy() bool {
	return outputprotocol.ActionCapabilities(v).CreateSetsPolicy()
}

// WriteSetsPolicy reports whether the advertised value write also applies policy.
func (v OutputActionCapabilities) WriteSetsPolicy() bool {
	return outputprotocol.ActionCapabilities(v).WriteSetsPolicy()
}

// Valid checks the family's legal action and policy-flag combinations.
func (v OutputActionCapabilities) Valid() bool { return outputprotocol.ActionCapabilities(v).Valid() }

// Has reports support for one typed family action; invalid action values
// return false rather than selecting a flag.
func (v OutputActionCapabilities) Has(action uint8) bool {
	return outputprotocol.ActionCapabilities(v).Has(outputprotocol.Action(action))
}

// OutputPolicy holds public plugin-owned canonical policy bytes. Empty
// ContractID and empty Data together mean no declared policy. Copies share
// Data backing unless the enclosing owner explicitly clones it.
type OutputPolicy struct {
	ContractID string
	Data       []byte
}

// OutputPayloadBounds limits encoded value bytes for one advertised action.
// It does not bound raw value bytes before an encoding expands them.
type OutputPayloadBounds struct{ Minimum, Maximum uint32 }

// OutputTarget is one normalized public service target, including exact opaque
// target and policy backing. It is not authenticated service state. Ordinary
// struct copies share slices; keep backing immutable while a host borrows it.
type OutputTarget struct {
	EntryIncarnationID                                                    ID
	ServiceContractID, TargetContractID, CanonicalTarget, ConsumerLocator string
	TargetData                                                            []byte
	PayloadEncoding                                                       uint8
	LocatorRequiresCreation                                               bool
	Capabilities                                                          OutputActionCapabilities
	CreateValueBounds, WriteValueBounds                                   OutputPayloadBounds
	Policy                                                                OutputPolicy
}

// Equal compares all target facts, including both opaque byte fields.
func (a OutputTarget) Equal(b OutputTarget) bool {
	return normalOutputTargetsEqual(a, b)
}

type OutputBinding struct {
	IncarnationID ID
	DestinationID string
	Destination   OutputDestination

	Targets []OutputTarget
}

// OutputDestination contains the plugin's canonical destination settings and
// declared semantics. Struct copies share settings and policy slices; normalization
// and validation callers retain their owner through the passive exchange.
type OutputDestination struct {
	ConfigContractID, ServiceContractID string
	CanonicalSettings                   []byte
	Policy                              OutputPolicy
	Capabilities                        OutputActionCapabilities
}

type OutputRoute struct {
	EntryIncarnationID ID
	Destinations       []string
}

type OutputConfiguration struct {
	Schema              uint16
	DomainID            ID
	Bindings            []OutputBinding
	DefaultDestinations []string
	Routes              []OutputRoute
	Groups              [][]ID
}

type OutputConfigurationDescriptor struct {
	Schema                   uint16
	ConfigurationDigest      ID
	TotalLength              uint32
	SliceCount, BindingCount uint16
	RoutingLength            uint32
}

type OutputConfigurationSlice struct {
	Schema                        uint16
	DomainID, ConfigurationDigest ID
	SliceIndex, SliceCount        uint16
	TotalLength                   uint32
	SliceBytes                    []byte
}

func outputIdentifierValid(s string) bool { return len(s) >= 1 && len(s) <= 256 && utf8.ValidString(s) }
func outputCoordinateValid(s string) bool {
	return len(s) >= 1 && len(s) <= 1024 && utf8.ValidString(s)
}

// outputWriter traverses the same canonical fields with or without retaining
// bytes. Routing validation needs the exact section bounds, not an encoded image.
type outputWriter struct {
	cryptoWriter
	length     int
	encode     bool
	comparison *outputConfigurationComparison
	hash       hash.Hash
}

func newOutputWriter(encode bool, capacity int) outputWriter {
	w := outputWriter{encode: encode}
	if encode {
		w.b = make([]byte, 0, capacity)
	}
	return w
}

func (w *outputWriter) raw(v []byte) {
	w.length += len(v)
	if w.encode {
		w.cryptoWriter.raw(v)
	}
	if w.comparison != nil {
		w.comparison.write(v)
	}
	if w.hash != nil {
		_, _ = w.hash.Write(v)
	}
}
func (w *outputWriter) u8(v uint8) {
	if !w.encode && w.comparison == nil && w.hash == nil {
		w.length++
		return
	}
	w.raw([]byte{v})
}
func (w *outputWriter) u16(v uint16) {
	if !w.encode && w.comparison == nil && w.hash == nil {
		w.length += 2
		return
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.raw(b[:])
}
func (w *outputWriter) u32(v uint32) {
	if !w.encode && w.comparison == nil && w.hash == nil {
		w.length += 4
		return
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.raw(b[:])
}
func (w *outputWriter) id(v ID) {
	if !w.encode && w.comparison == nil && w.hash == nil {
		w.length += len(v)
		return
	}
	w.raw(v[:])
}
func (w *outputWriter) text(v string) {
	if !w.encode && w.comparison == nil && w.hash == nil {
		w.length += 4 + len(v)
		return
	}
	w.u32(uint32(len(v)))
	w.raw([]byte(v))
}

type outputBlobStart struct {
	prefix       int
	actualLength uint32
}

func (w *outputWriter) beginBlob(length uint32) outputBlobStart {
	start := outputBlobStart{prefix: w.length}
	if w.comparison != nil {
		start.actualLength = w.comparison.readLength()
		w.length += 4
	} else {
		w.u32(length)
	}
	return start
}

func (w *outputWriter) endBlob(start outputBlobStart) uint32 {
	length := uint32(w.length - start.prefix - 4)
	if w.encode {
		binary.BigEndian.PutUint32(w.b[start.prefix:start.prefix+4], length)
	} else if w.comparison != nil && start.actualLength != length {
		w.comparison.invalid = true
	}
	return length
}

// Comparison borrows the selected slices only during the checked traversal.
type outputConfigurationComparison struct {
	parts        [][]byte
	part, offset int
	invalid      bool
}

func (c *outputConfigurationComparison) write(body []byte) {
	if c.invalid {
		return
	}
	for len(body) != 0 {
		if c.part == len(c.parts) {
			c.invalid = true
			return
		}
		source := c.parts[c.part][c.offset:]
		n := min(len(body), len(source))
		if !bytes.Equal(body[:n], source[:n]) {
			c.invalid = true
			return
		}
		c.offset += n
		body = body[n:]
		if c.offset == len(c.parts[c.part]) {
			c.part++
			c.offset = 0
		}
	}
}

func (c *outputConfigurationComparison) readLength() uint32 {
	var prefix [4]byte
	for i := range prefix {
		if c.invalid {
			return 0
		}
		for c.part < len(c.parts) && c.offset == len(c.parts[c.part]) {
			c.part++
			c.offset = 0
		}
		if c.part == len(c.parts) {
			c.invalid = true
			return 0
		}
		prefix[i] = c.parts[c.part][c.offset]
		c.offset++
		if c.offset == len(c.parts[c.part]) {
			c.part++
			c.offset = 0
		}
	}
	return binary.BigEndian.Uint32(prefix[:])
}

func EncodeOutputPolicy(p OutputPolicy) ([]byte, error) {
	w, err := writeOutputPolicy(p, true)
	return w.b, err
}

func writeOutputPolicy(p OutputPolicy, encode bool) (outputWriter, error) {
	w := newOutputWriter(encode, 64)
	if err := writeOutputPolicyTo(p, &w); err != nil {
		return outputWriter{}, err
	}
	return w, nil
}

func writeOutputPolicyTo(p OutputPolicy, w *outputWriter) error {
	if len(p.Data) > MaxOutputPolicyBytes {
		return ErrRecordCapacity
	}
	if !outputPolicyValid(p) {
		return ErrRecord
	}
	if outputPolicyAbsent(p) {
		return nil
	}
	w.u16(3)
	w.text(p.ContractID)
	w.text(string(p.Data))
	return nil
}
func outputPolicyValid(p OutputPolicy) bool {
	return len(p.Data) <= MaxOutputPolicyBytes && (outputIdentifierValid(p.ContractID) || p.ContractID == "" && len(p.Data) == 0)
}
func InspectOutputPolicy(body []byte) (OutputPolicy, error) {
	if len(body) == 0 {
		return OutputPolicy{}, nil
	}
	if len(body) > MaxOutputPolicyRecordBytes {
		return OutputPolicy{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	schema := r.u16()
	p := OutputPolicy{ContractID: outputBlobString(&r, 256), Data: append([]byte(nil), r.blob(MaxOutputPolicyBytes)...)}
	if r.end() != nil || schema != 3 || !outputPolicyValid(p) {
		return OutputPolicy{}, ErrRecord
	}
	return p, nil
}
func OutputPolicyDigest(domain ID, p OutputPolicy) (ID, error) {
	digest, err := outputprotocol.PolicyDigest(outputprotocol.ID(domain), outputprotocol.Policy{ContractID: p.ContractID, Data: p.Data})
	if err != nil {
		return ID{}, ErrRecord
	}
	return ID(digest), nil
}
func outputTargetFactsValid(t OutputTarget) bool {
	return (outputprotocol.Target{ServiceContractID: t.ServiceContractID, TargetContractID: t.TargetContractID,
		CanonicalTarget: t.CanonicalTarget, ConsumerLocator: t.ConsumerLocator, TargetData: t.TargetData,
		PayloadEncoding: t.PayloadEncoding, LocatorRequiresCreation: t.LocatorRequiresCreation,
		Capabilities:      outputprotocol.ActionCapabilities(t.Capabilities),
		CreateValueBounds: outputprotocol.PayloadBounds(t.CreateValueBounds),
		WriteValueBounds:  outputprotocol.PayloadBounds(t.WriteValueBounds)}).Valid()
}
func outputTargetCoreValid(t OutputTarget) bool {
	return !t.EntryIncarnationID.IsZero() && outputTargetFactsValid(t)
}
func outputPolicyAbsent(p OutputPolicy) bool { return p.ContractID == "" && len(p.Data) == 0 }
func PublicationPayloadLength(encoding uint8, rawLength uint32) (uint32, error) {
	length, err := DeliveredValueLength(encoding, rawLength)
	if err != nil {
		return 0, err
	}
	if length > CryptoMaxRawValue {
		return 0, ErrRecordCapacity
	}
	return length, nil
}
func encodeOutputTargetRow(target OutputTarget) ([]byte, error) {
	w, err := writeOutputTargetRow(target, true)
	return w.b, err
}
func writeOutputTargetRow(target OutputTarget, encode bool) (outputWriter, error) {
	w := newOutputWriter(encode, 128)
	err := writeOutputTargetRowTo(target, &w)
	return w, err
}
func writeOutputTargetRowTo(target OutputTarget, w *outputWriter) error {
	if !outputTargetCoreValid(target) {
		return ErrRecord
	}
	return writeOutputTargetFactsTo(target, w)
}
func writeOutputTargetFactsTo(target OutputTarget, w *outputWriter) error {
	if !outputTargetFactsValid(target) {
		return ErrRecord
	}
	return writeOutputTargetFieldsTo(target, w)
}

func writeOutputTargetFieldsTo(target OutputTarget, w *outputWriter) error {
	w.id(target.EntryIncarnationID)
	for _, field := range []string{target.ServiceContractID, target.TargetContractID, target.CanonicalTarget, target.ConsumerLocator} {
		w.text(field)
	}
	w.text(string(target.TargetData))
	w.u8(target.PayloadEncoding)
	w.u8(uint8(target.Capabilities))
	if target.LocatorRequiresCreation {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.u32(target.CreateValueBounds.Minimum)
	w.u32(target.CreateValueBounds.Maximum)
	w.u32(target.WriteValueBounds.Minimum)
	w.u32(target.WriteValueBounds.Maximum)
	return writeOutputPolicyBlobTo(target.Policy, w)
}

func outputRouteValid(r OutputRoute, destinations map[string]bool) bool {
	if len(r.Destinations) > MaxOutputRouteDestinations {
		return false
	}
	for i, name := range r.Destinations {
		if !destinations[name] || i > 0 && r.Destinations[i-1] >= name {
			return false
		}
	}
	return true
}

func outputRouteBefore(a, b OutputRoute) bool {
	return bytes.Compare(a.EntryIncarnationID[:], b.EntryIncarnationID[:]) < 0
}

func outputBlobString(r *cryptoReader, max int) string {
	body := r.blob(max)
	if len(body) == 0 || !utf8.Valid(body) {
		r.err = ErrRecord
	}
	return string(body)
}

func writeOutputRoutingTo(defaults []string, routes []OutputRoute, destinations map[string]bool, w *outputWriter) error {
	start := w.length
	if len(routes) > CryptoMaxValueEntries {
		return ErrRecordCapacity
	}
	if !outputRouteValid(OutputRoute{Destinations: defaults}, destinations) {
		return ErrRecord
	}
	w.u16(3)
	w.u8(uint8(len(defaults)))
	for _, name := range defaults {
		w.text(name)
	}
	w.u16(uint16(len(routes)))
	for i, r := range routes {
		if r.EntryIncarnationID.IsZero() || !outputRouteValid(r, destinations) || i > 0 && !outputRouteBefore(routes[i-1], r) {
			return ErrRecord
		}
		w.id(r.EntryIncarnationID)
		w.u8(uint8(len(r.Destinations)))
		for _, name := range r.Destinations {
			w.text(name)
		}
		if w.length-start > MaxOutputRoutingBytes {
			return ErrRecordCapacity
		}
	}
	return nil
}

func EncodeOutputConfiguration(v OutputConfiguration) ([]byte, error) {
	w, _, err := writeOutputConfiguration(v, true)
	return w.b, err
}

// OutputConfigurationLength validates the complete typed declaration with the
// same writer as encoding, without allocating a wire image.
func OutputConfigurationLength(v OutputConfiguration) (int, error) {
	w, _, err := writeOutputConfiguration(v, false)
	return w.length, err
}

// ValidateOutputConfigurationAgainstDescriptor checks the complete typed image
// without retaining an encoded copy. It does not authenticate the descriptor.
func ValidateOutputConfigurationAgainstDescriptor(v OutputConfiguration, descriptor OutputConfigurationDescriptor) error {
	if _, err := EncodeOutputConfigurationDescriptor(descriptor); err != nil {
		return err
	}
	counted, routing, err := writeOutputConfiguration(v, false)
	if err != nil {
		return err
	}
	if counted.length != int(descriptor.TotalLength) || routing != descriptor.RoutingLength || len(v.Bindings) != int(descriptor.BindingCount) {
		return ErrRecord
	}
	h := sha256.New()
	_, _ = h.Write([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"))
	_, _ = h.Write(v.DomainID[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], descriptor.TotalLength)
	_, _ = h.Write(length[:])
	w := outputWriter{hash: h}
	if _, err := writeOutputConfigurationTo(v, &w); err != nil {
		return err
	}
	var digest ID
	copy(digest[:], h.Sum(nil))
	if digest != descriptor.ConfigurationDigest {
		return ErrRecord
	}
	return nil
}

func writeOutputPolicyBlobTo(policy OutputPolicy, w *outputWriter) error {
	var length uint32
	if w.hash != nil {
		counter, err := writeOutputPolicy(policy, false)
		if err != nil {
			return err
		}
		length = uint32(counter.length)
	}
	start := w.beginBlob(length)
	if err := writeOutputPolicyTo(policy, w); err != nil {
		return err
	}
	w.endBlob(start)
	return nil
}

// OutputTargetRowLength checks one complete stored target row before its public
// policy backing is captured by a bounded declaration owner.
func OutputTargetRowLength(v OutputTarget) (int, error) {
	w := newOutputWriter(false, 0)
	err := writeOutputTargetRowTo(v, &w)
	return w.length, err
}

func writeOutputConfiguration(v OutputConfiguration, encode bool) (outputWriter, uint32, error) {
	w := newOutputWriter(encode, 4096)
	routing, err := writeOutputConfigurationTo(v, &w)
	if err != nil {
		return outputWriter{}, 0, err
	}
	return w, routing, nil
}

func writeOutputConfigurationTo(v OutputConfiguration, w *outputWriter) (uint32, error) {
	if v.Schema != OutputConfigurationSchema || v.DomainID.IsZero() || len(v.Bindings) > MaxOutputBindings {
		return 0, ErrRecord
	}
	destinations := make(map[string]bool, len(v.Bindings))
	incarnations := make(map[ID]bool, len(v.Bindings))
	physical := make(map[ID]bool)
	targetCount := 0
	w.u16(OutputConfigurationSchema)
	w.u16(uint16(len(v.Bindings)))
	for i, b := range v.Bindings {
		if b.IncarnationID.IsZero() || !outputIdentifierValid(b.DestinationID) ||
			len(b.Targets) > MaxOutputTargetsPerBinding || destinations[b.DestinationID] || incarnations[b.IncarnationID] ||
			i > 0 && v.Bindings[i-1].DestinationID >= b.DestinationID {
			return 0, ErrRecord
		}
		targetCount += len(b.Targets)
		if targetCount > MaxOutputTargets {
			return 0, ErrRecordCapacity
		}
		destinations[b.DestinationID], incarnations[b.IncarnationID] = true, true
		w.text(b.DestinationID)
		w.id(b.IncarnationID)
		if err := writeOutputDestinationTo(b.Destination, w); err != nil {
			return 0, err
		}

		w.u16(uint16(len(b.Targets)))
		for j, target := range b.Targets {
			if !outputTargetCoreValid(target) || target.ServiceContractID != b.Destination.ServiceContractID || target.Capabilities & ^b.Destination.Capabilities != 0 || j > 0 && bytes.Compare(b.Targets[j-1].EntryIncarnationID[:], target.EntryIncarnationID[:]) >= 0 {
				return 0, ErrRecord
			}
			if !outputPoliciesEqual(b.Destination.Policy, target.Policy) {
				return 0, ErrRecord
			}
			coordinate, err := PublicationCoordinateID(v.DomainID, target.ServiceContractID, target.CanonicalTarget)
			if err != nil || physical[coordinate] {
				return 0, ErrRecord
			}
			physical[coordinate] = true
			if err := writeOutputTargetRowTo(target, w); err != nil {
				return 0, err
			}
			if w.length > MaxOutputDeclarationBytes {
				return 0, ErrRecordCapacity
			}
		}

	}
	if err := writeOutputGroupsTo(v.Groups, w); err != nil {
		return 0, err
	}
	if w.length > MaxOutputDeclarationBytes {
		return 0, ErrRecordCapacity
	}
	var routingSize uint32
	if w.hash != nil {
		counter := newOutputWriter(false, 0)
		if err := writeOutputRoutingTo(v.DefaultDestinations, v.Routes, destinations, &counter); err != nil {
			return 0, err
		}
		routingSize = uint32(counter.length)
	}
	start := w.beginBlob(routingSize)
	if err := writeOutputRoutingTo(v.DefaultDestinations, v.Routes, destinations, w); err != nil {
		return 0, err
	}
	routingLength := w.endBlob(start)
	if w.length > MaxOutputConfigurationBytes {
		return 0, ErrRecordCapacity
	}
	return routingLength, nil
}

func outputPoliciesEqual(a, b OutputPolicy) bool {
	return a.ContractID == b.ContractID && bytes.Equal(a.Data, b.Data)
}

func matchOutputConfiguration(v OutputConfiguration, descriptor OutputConfigurationDescriptor, parts [][]byte) error {
	comparison := outputConfigurationComparison{parts: parts}
	w := outputWriter{comparison: &comparison}
	routing, err := writeOutputConfigurationTo(v, &w)
	if err != nil {
		return err
	}
	if comparison.invalid || comparison.part != len(parts) || comparison.offset != 0 ||
		w.length != int(descriptor.TotalLength) || uint16(len(v.Bindings)) != descriptor.BindingCount || routing != descriptor.RoutingLength {
		return ErrRecord
	}
	if outputConfigurationPartsDigest(v.DomainID, descriptor.TotalLength, parts) != descriptor.ConfigurationDigest {
		return ErrRecord
	}
	return nil
}

func InspectOutputConfiguration(domain ID, body []byte) (OutputConfiguration, uint32, error) {
	return parseOutputConfiguration(domain, bytes.NewReader(body), len(body), true, nil, nil)
}

func outputConfigurationDigest(domain ID, image []byte) ID {
	return outputConfigurationPartsDigest(domain, uint32(len(image)), [][]byte{image})
}

func outputConfigurationPartsDigest(domain ID, total uint32, parts [][]byte) ID {
	w := cryptoHashWriter("ENKV/OUTPUT/CONFIGURATION/v5\x00")
	w.id(domain)
	w.u32(total)
	w.flushHash()
	for _, part := range parts {
		w.n += len(part)
		_, _ = w.h.Write(part)
	}
	return w.result(0).Digest
}

func OutputConfigurationSliceID(domain, digest ID, index uint16) (ID, error) {
	if domain.IsZero() || digest.IsZero() || index >= MaxOutputConfigurationSlices {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/OUTPUT/CONFIGURATION-SLICE/v5\x00")
	w.id(domain)
	w.id(digest)
	w.u16(index)
	return w.result(0).Digest, nil
}

func SplitOutputConfiguration(domain ID, image []byte) (OutputConfigurationDescriptor, []OutputConfigurationSlice, error) {
	var bindingCount uint16
	_, routingLength, err := parseOutputConfiguration(domain, bytes.NewReader(image), len(image), false, &bindingCount, nil)
	if err != nil {
		return OutputConfigurationDescriptor{}, nil, err
	}
	return splitOutputConfiguration(domain, image, bindingCount, routingLength)
}

// encodedOutputConfiguration only accepts typed configuration checked by the
// encoder in this call. Public Split still parses every untrusted image.
func encodedOutputConfiguration(v OutputConfiguration) (OutputConfigurationDescriptor, []OutputConfigurationSlice, error) {
	w, routingLength, err := writeOutputConfiguration(v, true)
	if err != nil {
		return OutputConfigurationDescriptor{}, nil, err
	}
	return splitOutputConfiguration(v.DomainID, w.b, uint16(len(v.Bindings)), routingLength)
}

func splitOutputConfiguration(domain ID, image []byte, bindingCount uint16, routingLength uint32) (OutputConfigurationDescriptor, []OutputConfigurationSlice, error) {
	count := (len(image) + MaxOutputConfigurationSliceBytes - 1) / MaxOutputConfigurationSliceBytes
	if count < 1 || count > MaxOutputConfigurationSlices {
		return OutputConfigurationDescriptor{}, nil, ErrRecordCapacity
	}
	descriptor := outputConfigurationImageDescriptor(domain, image, bindingCount, routingLength)
	digest := descriptor.ConfigurationDigest
	rows := make([]OutputConfigurationSlice, count)
	for i := range rows {
		start := i * MaxOutputConfigurationSliceBytes
		end := min(start+MaxOutputConfigurationSliceBytes, len(image))
		rows[i] = OutputConfigurationSlice{Schema: OutputConfigurationSchema, DomainID: domain, ConfigurationDigest: digest, SliceIndex: uint16(i), SliceCount: uint16(count), TotalLength: uint32(len(image)), SliceBytes: slices.Clone(image[start:end])}
	}
	return descriptor, rows, nil
}

func outputConfigurationImageDescriptor(domain ID, image []byte, bindingCount uint16, routingLength uint32) OutputConfigurationDescriptor {
	return OutputConfigurationDescriptor{Schema: OutputConfigurationSchema, ConfigurationDigest: outputConfigurationDigest(domain, image), TotalLength: uint32(len(image)),
		SliceCount: uint16((len(image) + MaxOutputConfigurationSliceBytes - 1) / MaxOutputConfigurationSliceBytes), BindingCount: bindingCount, RoutingLength: routingLength}
}

func EncodeOutputConfigurationDescriptor(v OutputConfigurationDescriptor) ([]byte, error) {
	if v.Schema != OutputConfigurationSchema || v.ConfigurationDigest.IsZero() || v.TotalLength < 15 || v.TotalLength > MaxOutputConfigurationBytes || v.SliceCount == 0 || v.SliceCount > MaxOutputConfigurationSlices || v.BindingCount > MaxOutputBindings || v.RoutingLength < 5 || v.RoutingLength > MaxOutputRoutingBytes || v.TotalLength < v.RoutingLength+10 || v.TotalLength-4-v.RoutingLength > MaxOutputDeclarationBytes || uint32(v.SliceCount) != (v.TotalLength+MaxOutputConfigurationSliceBytes-1)/MaxOutputConfigurationSliceBytes {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, 46)}
	writeOutputConfigurationDescriptor(&w, v)
	return w.b, nil
}

func writeOutputConfigurationDescriptor(w *cryptoWriter, v OutputConfigurationDescriptor) {
	w.u16(v.Schema)
	w.id(v.ConfigurationDigest)
	w.u32(v.TotalLength)
	w.u16(v.SliceCount)
	w.u16(v.BindingCount)
	w.u32(v.RoutingLength)
}

func InspectOutputConfigurationDescriptor(body []byte) (OutputConfigurationDescriptor, error) {
	r := newRecordReader(body)
	v := OutputConfigurationDescriptor{Schema: r.u16(), ConfigurationDigest: r.id(), TotalLength: r.u32(), SliceCount: r.u16(), BindingCount: r.u16(), RoutingLength: r.u32()}
	if r.end() != nil {
		return OutputConfigurationDescriptor{}, ErrRecord
	}
	if _, err := EncodeOutputConfigurationDescriptor(v); err != nil {
		return OutputConfigurationDescriptor{}, err
	}
	return v, nil
}

func EncodeOutputConfigurationSlice(v OutputConfigurationSlice) ([]byte, error) {
	if !outputConfigurationSliceValid(v) {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: make([]byte, 0, OutputConfigurationSliceBodyOverhead+len(v.SliceBytes))}
	w.u16(v.Schema)
	w.id(v.DomainID)
	w.id(v.ConfigurationDigest)
	w.u16(v.SliceIndex)
	w.u16(v.SliceCount)
	w.u32(v.TotalLength)
	w.blob(v.SliceBytes)
	return w.b, nil
}

func outputConfigurationSliceValid(v OutputConfigurationSlice) bool {
	if v.Schema != OutputConfigurationSchema || v.DomainID.IsZero() || v.ConfigurationDigest.IsZero() || v.SliceCount == 0 || v.SliceCount > MaxOutputConfigurationSlices || v.SliceIndex >= v.SliceCount || v.TotalLength < 15 || v.TotalLength > MaxOutputConfigurationBytes || uint32(v.SliceCount) != (v.TotalLength+MaxOutputConfigurationSliceBytes-1)/MaxOutputConfigurationSliceBytes || len(v.SliceBytes) == 0 || len(v.SliceBytes) > MaxOutputConfigurationSliceBytes {
		return false
	}
	start := uint32(v.SliceIndex) * MaxOutputConfigurationSliceBytes
	length := min(uint32(MaxOutputConfigurationSliceBytes), v.TotalLength-start)
	return uint32(len(v.SliceBytes)) == length
}

func InspectOutputConfigurationSlice(body []byte) (OutputConfigurationSlice, error) {
	if len(body) < OutputConfigurationSliceBodyOverhead || len(body) > OutputConfigurationSliceBodyOverhead+MaxOutputConfigurationSliceBytes {
		return OutputConfigurationSlice{}, ErrRecordCapacity
	}
	r := newRecordReader(body)
	v := OutputConfigurationSlice{Schema: r.u16(), DomainID: r.id(), ConfigurationDigest: r.id(), SliceIndex: r.u16(), SliceCount: r.u16(), TotalLength: r.u32(), SliceBytes: r.blob(MaxOutputConfigurationSliceBytes)}
	if r.end() != nil {
		return OutputConfigurationSlice{}, ErrRecord
	}
	if !outputConfigurationSliceValid(v) {
		return OutputConfigurationSlice{}, ErrRecord
	}
	return v, nil
}

func JoinOutputConfiguration(domain ID, descriptor OutputConfigurationDescriptor, rows []OutputConfigurationSlice) ([]byte, error) {
	if _, err := EncodeOutputConfigurationDescriptor(descriptor); err != nil || domain.IsZero() || len(rows) != int(descriptor.SliceCount) {
		return nil, ErrRecord
	}
	image := make([]byte, 0, descriptor.TotalLength)
	for i, row := range rows {
		if row.DomainID != domain || row.ConfigurationDigest != descriptor.ConfigurationDigest || row.SliceIndex != uint16(i) || row.SliceCount != descriptor.SliceCount || row.TotalLength != descriptor.TotalLength {
			return nil, ErrRecord
		}
		if _, err := EncodeOutputConfigurationSlice(row); err != nil {
			return nil, err
		}
		image = append(image, row.SliceBytes...)
	}
	if len(image) != int(descriptor.TotalLength) || outputConfigurationDigest(domain, image) != descriptor.ConfigurationDigest {
		return nil, ErrRecord
	}
	v, routingLength, err := InspectOutputConfiguration(domain, image)
	if err != nil || len(v.Bindings) != int(descriptor.BindingCount) || routingLength != descriptor.RoutingLength {
		return nil, ErrRecord
	}
	return image, nil
}

func cloneOutputPolicy(p OutputPolicy) OutputPolicy {
	p.ContractID = strings.Clone(p.ContractID)
	p.Data = bytes.Clone(p.Data)
	return p
}
func cloneOutputTarget(t OutputTarget) OutputTarget {
	t.ServiceContractID = strings.Clone(t.ServiceContractID)
	t.TargetContractID = strings.Clone(t.TargetContractID)
	t.CanonicalTarget = strings.Clone(t.CanonicalTarget)
	t.ConsumerLocator = strings.Clone(t.ConsumerLocator)
	t.TargetData = bytes.Clone(t.TargetData)
	t.Policy = cloneOutputPolicy(t.Policy)
	return t
}

func cloneOutputConfiguration(v OutputConfiguration) OutputConfiguration {
	bindings := make([]OutputBinding, len(v.Bindings))
	copy(bindings, v.Bindings)
	v.Bindings = bindings
	for i := range v.Bindings {
		b := &v.Bindings[i]
		b.DestinationID = strings.Clone(b.DestinationID)
		b.Destination = cloneOutputDestination(b.Destination)
		b.Targets = slices.Clone(b.Targets)
		for j := range b.Targets {
			b.Targets[j] = cloneOutputTarget(b.Targets[j])
		}
	}
	v.Groups = cloneOutputGroups(v.Groups)
	v.DefaultDestinations = slices.Clone(v.DefaultDestinations)
	for i := range v.DefaultDestinations {
		v.DefaultDestinations[i] = strings.Clone(v.DefaultDestinations[i])
	}
	routes := make([]OutputRoute, len(v.Routes))
	copy(routes, v.Routes)
	v.Routes = routes
	for i := range v.Routes {
		v.Routes[i].Destinations = slices.Clone(v.Routes[i].Destinations)
		for j := range v.Routes[i].Destinations {
			v.Routes[i].Destinations[j] = strings.Clone(v.Routes[i].Destinations[j])
		}
	}
	return v
}
