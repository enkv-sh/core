package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"unicode/utf8"

	protocol "enkv.sh/sdk/protocols/output"
)

// outputImageReader is the sole decoder for complete output configuration
// grammar. Its validation mode retains only bounded field scratch and the
// identities needed for cross-record checks.
type outputImageReader struct {
	source       io.Reader
	remaining    int
	section      int // -1 before the routing body; otherwise bytes left in it.
	consumed     int
	err          error
	policyHash   hash.Hash
	policyDigest ID
	scratch      [2048]byte
	primitive    [32]byte
}

func (r *outputImageReader) read(b []byte) {
	if r.err != nil {
		return
	}
	if len(b) > r.remaining || r.section >= 0 && len(b) > r.section {
		r.err = ErrRecord
		return
	}
	if _, err := io.ReadFull(r.source, b); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			r.err = ErrRecord
		} else {
			r.err = err
		}
		return
	}
	r.remaining -= len(b)
	if r.policyHash != nil {
		_, _ = r.policyHash.Write(b)
	}
	r.consumed += len(b)
	if r.section >= 0 {
		r.section -= len(b)
	}
}

func (r *outputImageReader) u8() uint8 {
	r.read(r.primitive[:1])
	return r.primitive[0]
}
func (r *outputImageReader) u16() uint16 {
	r.read(r.primitive[:2])
	return binary.BigEndian.Uint16(r.primitive[:2])
}
func (r *outputImageReader) u32() uint32 {
	r.read(r.primitive[:4])
	return binary.BigEndian.Uint32(r.primitive[:4])
}
func (r *outputImageReader) id() ID {
	var id ID
	r.read(r.primitive[:32])
	copy(id[:], r.primitive[:32])
	return id
}
func (r *outputImageReader) string(limit int) string {
	n := r.u32()
	if r.err != nil {
		return ""
	}
	if n == 0 || n > uint32(limit) {
		r.err = ErrRecord
		return ""
	}
	r.read(r.scratch[:int(n)])
	if r.err != nil || !utf8.Valid(r.scratch[:int(n)]) {
		r.err = ErrRecord
		return ""
	}
	return string(r.scratch[:int(n)])
}

func (r *outputImageReader) blob(limit int, materialize bool) []byte {
	n := int(r.u32())
	if r.err != nil || n > limit || n > r.remaining || r.section >= 0 && n > r.section {
		r.err = ErrRecord
		return nil
	}
	if materialize {
		if n == 0 {
			return nil
		}
		b := make([]byte, n)
		r.read(b)
		return b
	}
	for n > 0 && r.err == nil {
		size := min(n, len(r.scratch))
		r.read(r.scratch[:size])
		n -= size
	}
	return nil
}
func (r *outputImageReader) optionalString(limit int) string {
	b := r.blob(limit, true)
	if !utf8.Valid(b) {
		r.err = ErrRecord
	}
	return string(b)
}
func (r *outputImageReader) policy(materialize bool) OutputPolicy {
	r.policyDigest = ID{}
	length := r.u32()
	if length == 0 && r.err == nil {
		return OutputPolicy{}
	}
	if r.err != nil || length < 11 || length > MaxOutputPolicyRecordBytes || int(length) > r.remaining {
		r.err = ErrRecord
		return OutputPolicy{}
	}
	r.section = int(length)
	r.policyHash = sha256.New()
	defer func() { r.policyHash = nil }()
	schema := r.u16()
	p := OutputPolicy{ContractID: r.string(256)}
	p.Data = r.blob(MaxOutputPolicyBytes, materialize)
	if schema != 3 || !outputIdentifierValid(p.ContractID) || r.section != 0 || r.err != nil {
		r.err = ErrRecord
		return OutputPolicy{}
	}
	r.section = -1
	copy(r.policyDigest[:], r.policyHash.Sum(nil))
	return p
}

// OutputConfigurationVisit observes one complete configuration. Calls are
// provisional: their results are usable only after the full source validates.
// TargetFields receives owned strings and policy slices; it may retain them.
// Binding and TargetFields receive owned policy byte slices. Other visitors
// validate opaque policy bytes without materializing them.
type OutputConfigurationVisit struct {
	Binding      func(binding ID, destination string, facts OutputDestination) error
	Group        func(members []ID) error
	Target       func(binding, entry, coordinate ID, destination string) error
	TargetFields func(binding ID, destination string, target OutputTarget) error
	Route        func(entry ID, destinations []string) error
}

func (r *outputImageReader) destination(materialize bool) OutputDestination {
	v := OutputDestination{ConfigContractID: r.string(256), ServiceContractID: r.string(256)}
	settings := r.blob(MaxOutputDestinationSettings, true)
	if !protocol.ValidCanonicalSettings(settings) {
		r.err = ErrRecord
	}
	if materialize {
		v.CanonicalSettings = settings
	}
	v.Policy = r.policy(materialize)
	v.Capabilities = OutputActionCapabilities(r.u8())
	if !v.Capabilities.Valid() {
		r.err = ErrRecord
	}
	return v
}

func parseOutputConfiguration(domain ID, source io.Reader, length int, materialize bool,
	bindingCount *uint16, visit *OutputConfigurationVisit) (OutputConfiguration, uint32, error) {
	if domain.IsZero() || length < 15 || length > MaxOutputConfigurationBytes || source == nil {
		return OutputConfiguration{}, 0, ErrRecordCapacity
	}
	r := outputImageReader{source: source, remaining: length, section: -1}
	v := OutputConfiguration{Schema: r.u16(), DomainID: domain}
	count := int(r.u16())
	if r.err != nil || v.Schema != OutputConfigurationSchema || count > MaxOutputBindings {
		return OutputConfiguration{}, 0, ErrRecord
	}
	if bindingCount != nil {
		*bindingCount = uint16(count)
	}
	if materialize {
		v.Bindings = make([]OutputBinding, 0, count)
	}
	destinations := make(map[string]bool, count)
	incarnations := make(map[ID]bool, count)
	physical := make(map[ID]bool)
	targetCount := 0
	previousDestination := ""
	for i := 0; i < count; i++ {
		b := OutputBinding{DestinationID: ""}
		b.DestinationID = r.string(256)
		b.IncarnationID = r.id()
		if r.err != nil || b.IncarnationID.IsZero() || !outputIdentifierValid(b.DestinationID) || destinations[b.DestinationID] ||
			incarnations[b.IncarnationID] || i > 0 && previousDestination >= b.DestinationID {
			return OutputConfiguration{}, 0, ErrRecord
		}
		b.Destination = r.destination(materialize || visit != nil && visit.Binding != nil)
		if r.err != nil {
			return OutputConfiguration{}, 0, r.err
		}
		destinationPolicyDigest := r.policyDigest
		if visit != nil && visit.Binding != nil {
			if err := visit.Binding(b.IncarnationID, b.DestinationID, b.Destination); err != nil {
				return OutputConfiguration{}, 0, err
			}
		}
		rows := int(r.u16())
		if r.err != nil || rows > MaxOutputTargetsPerBinding || rows > (MaxOutputTargets-targetCount) || rows > r.remaining/78 {
			return OutputConfiguration{}, 0, ErrRecord
		}
		targetCount += rows
		if materialize {
			b.Targets = make([]OutputTarget, rows)
		}
		var previousEntry ID
		for j := 0; j < rows; j++ {
			target := OutputTarget{EntryIncarnationID: r.id(), ServiceContractID: r.string(256), TargetContractID: r.string(256), CanonicalTarget: r.string(1024), ConsumerLocator: r.optionalString(1024)}
			target.TargetData = r.blob(MaxOutputTargetDataBytes, materialize || visit != nil && visit.TargetFields != nil)
			target.PayloadEncoding = r.u8()
			target.Capabilities = OutputActionCapabilities(r.u8())
			flag := r.u8()
			target.LocatorRequiresCreation = flag == 1
			target.CreateValueBounds = OutputPayloadBounds{Minimum: r.u32(), Maximum: r.u32()}
			target.WriteValueBounds = OutputPayloadBounds{Minimum: r.u32(), Maximum: r.u32()}
			if r.err != nil || flag > 1 || !outputTargetCoreValid(target) || target.ServiceContractID != b.Destination.ServiceContractID || target.Capabilities & ^b.Destination.Capabilities != 0 || j > 0 && bytes.Compare(previousEntry[:], target.EntryIncarnationID[:]) >= 0 {
				return OutputConfiguration{}, 0, ErrRecord
			}

			coordinate, err := PublicationCoordinateID(domain, target.ServiceContractID, target.CanonicalTarget)
			if err != nil || physical[coordinate] {
				return OutputConfiguration{}, 0, ErrRecord
			}
			target.Policy = r.policy(materialize || visit != nil && visit.TargetFields != nil)
			if r.err != nil || r.policyDigest != destinationPolicyDigest {
				if r.err == nil {
					r.err = ErrRecord
				}
				return OutputConfiguration{}, 0, r.err
			}
			if visit != nil && visit.Target != nil {
				if err := visit.Target(b.IncarnationID, target.EntryIncarnationID, coordinate, b.DestinationID); err != nil {
					return OutputConfiguration{}, 0, err
				}
			}
			if visit != nil && visit.TargetFields != nil {
				if err := visit.TargetFields(b.IncarnationID, b.DestinationID, target); err != nil {
					return OutputConfiguration{}, 0, err
				}
			}
			if materialize {
				b.Targets[j] = target
			}
			physical[coordinate] = true
			previousEntry = target.EntryIncarnationID
			if r.consumed > MaxOutputDeclarationBytes {
				return OutputConfiguration{}, 0, ErrRecordCapacity
			}
		}

		destinations[b.DestinationID], incarnations[b.IncarnationID] = true, true
		previousDestination = b.DestinationID
		if materialize {
			v.Bindings = append(v.Bindings, b)
		}
	}
	groupCount := int(r.u16())
	if groupCount > CryptoMaxValueEntries {
		return OutputConfiguration{}, 0, ErrRecordCapacity
	}
	if materialize && groupCount > 0 {
		v.Groups = make([][]ID, 0, groupCount)
	}
	groupMembers := make(map[ID]bool)
	var previousGroup ID
	for i := 0; i < groupCount; i++ {
		n := int(r.u16())
		if n == 0 || n > CryptoMaxValueEntries-len(groupMembers) || n > r.remaining/32 {
			return OutputConfiguration{}, 0, ErrRecord
		}
		members := make([]ID, n)
		for j := range members {
			members[j] = r.id()
			if r.err != nil || members[j].IsZero() || groupMembers[members[j]] || j > 0 && bytes.Compare(members[j-1][:], members[j][:]) >= 0 {
				return OutputConfiguration{}, 0, ErrRecord
			}
			groupMembers[members[j]] = true
		}
		if i > 0 && bytes.Compare(previousGroup[:], members[0][:]) >= 0 {
			return OutputConfiguration{}, 0, ErrRecord
		}
		previousGroup = members[0]
		if materialize {
			v.Groups = append(v.Groups, members)
		}
		if visit != nil && visit.Group != nil {
			if err := visit.Group(members); err != nil {
				return OutputConfiguration{}, 0, err
			}
		}
	}
	if r.consumed > MaxOutputDeclarationBytes {
		return OutputConfiguration{}, 0, ErrRecordCapacity
	}
	routingLength := r.u32()
	if r.err != nil {
		return OutputConfiguration{}, 0, ErrRecord
	}
	if routingLength < 5 || routingLength > MaxOutputRoutingBytes {
		return OutputConfiguration{}, 0, ErrRecordCapacity
	}
	if r.remaining != int(routingLength) {
		return OutputConfiguration{}, 0, ErrRecord
	}
	r.section = int(routingLength)
	if r.u16() != 3 || r.err != nil {
		return OutputConfiguration{}, 0, ErrRecord
	}
	readDestinations := func() ([]string, error) {
		n := int(r.u8())
		if r.err != nil || n > MaxOutputRouteDestinations {
			return nil, ErrRecord
		}
		var names []string
		if n > 0 {
			names = make([]string, n)
		}
		for i := range names {
			names[i] = r.string(256)
		}
		if r.err != nil || !outputRouteValid(OutputRoute{Destinations: names}, destinations) {
			return nil, ErrRecord
		}
		return names, nil
	}
	defaults, err := readDestinations()
	if err != nil {
		return OutputConfiguration{}, 0, err
	}
	if visit != nil && visit.Route != nil {
		if err := visit.Route(ID{}, defaults); err != nil {
			return OutputConfiguration{}, 0, err
		}
	}
	if materialize {
		v.DefaultDestinations = defaults
	}
	routeCount := int(r.u16())
	if r.err != nil || routeCount > CryptoMaxValueEntries || routeCount > r.remaining/33 {
		return OutputConfiguration{}, 0, ErrRecord
	}
	if materialize {
		v.Routes = make([]OutputRoute, 0, routeCount)
	}
	var previousRoute OutputRoute
	for i := 0; i < routeCount; i++ {
		route := OutputRoute{EntryIncarnationID: r.id()}
		route.Destinations, err = readDestinations()
		if err != nil || route.EntryIncarnationID.IsZero() || i > 0 && !outputRouteBefore(previousRoute, route) {
			return OutputConfiguration{}, 0, ErrRecord
		}
		if visit != nil && visit.Route != nil {
			if err := visit.Route(route.EntryIncarnationID, route.Destinations); err != nil {
				return OutputConfiguration{}, 0, err
			}
		}
		previousRoute = route
		if materialize {
			v.Routes = append(v.Routes, route)
		}
	}
	if r.err != nil || r.section != 0 || r.remaining != 0 {
		return OutputConfiguration{}, 0, ErrRecord
	}
	return v, routingLength, nil
}

// outputConfigurationSourceReader accepts each borrowed slice only until its
// bytes are consumed. It drops the prior backing before it asks for the next.
type outputConfigurationSourceReader struct {
	domain      ID
	descriptor  OutputConfigurationDescriptor
	next        func(uint16) (OutputConfigurationSlice, error)
	callbackErr error
	index       uint16
	current     []byte
}

func (r *outputConfigurationSourceReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.current) == 0 {
		r.current = nil
		if r.index == r.descriptor.SliceCount {
			return 0, io.EOF
		}
		row, err := r.next(r.index)
		if err != nil {
			r.callbackErr = err
			return 0, err
		}
		if !outputConfigurationSliceValid(row) || row.DomainID != r.domain ||
			row.ConfigurationDigest != r.descriptor.ConfigurationDigest || row.SliceIndex != r.index ||
			row.SliceCount != r.descriptor.SliceCount || row.TotalLength != r.descriptor.TotalLength {
			return 0, ErrRecord
		}
		r.current = row.SliceBytes
		r.index++
	}
	n := copy(p, r.current)
	r.current = r.current[n:]
	if len(r.current) == 0 {
		r.current = nil
	}
	return n, nil
}

// inspectOutputConfigurationSource checks one ordered source and returns its
// typed contents only after the complete descriptor digest and framing match.
// next is called once per required index and must not retain a prior page body.
func inspectOutputConfigurationSource(domain ID, descriptor OutputConfigurationDescriptor,
	next func(index uint16) (OutputConfigurationSlice, error), materialize bool,
	visit *OutputConfigurationVisit) (OutputConfiguration, error) {
	if domain.IsZero() || next == nil {
		return OutputConfiguration{}, ErrRecord
	}
	if _, err := EncodeOutputConfigurationDescriptor(descriptor); err != nil {
		return OutputConfiguration{}, err
	}
	source := &outputConfigurationSourceReader{domain: domain, descriptor: descriptor, next: next}
	h := sha256.New()
	_, _ = h.Write([]byte("ENKV/OUTPUT/CONFIGURATION/v5\x00"))
	_, _ = h.Write(domain[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], descriptor.TotalLength)
	_, _ = h.Write(length[:])
	var bindingCount uint16
	v, routingLength, err := parseOutputConfiguration(domain, io.TeeReader(source, h), int(descriptor.TotalLength), materialize, &bindingCount, visit)
	if err != nil {
		if source.callbackErr != nil {
			return OutputConfiguration{}, source.callbackErr
		}
		return OutputConfiguration{}, err
	}
	var digest ID
	copy(digest[:], h.Sum(nil))
	if digest != descriptor.ConfigurationDigest || source.index != descriptor.SliceCount ||
		len(source.current) != 0 || bindingCount != descriptor.BindingCount || v.Schema != OutputConfigurationSchema ||
		v.DomainID != domain || routingLength != descriptor.RoutingLength {
		return OutputConfiguration{}, ErrRecord
	}
	return v, nil
}

// ValidateOutputConfigurationSource checks an authenticated, ordered source
// without joining its pages or materializing binding policies.
func ValidateOutputConfigurationSource(domain ID, descriptor OutputConfigurationDescriptor,
	next func(index uint16) (OutputConfigurationSlice, error)) error {
	_, err := inspectOutputConfigurationSource(domain, descriptor, next, false, nil)
	return err
}

// VisitOutputConfigurationSource uses the same bounded parser without joining
// source bodies. It materializes one target policy only when TargetFields is
// present. Visitor results are usable only after this function returns nil.
func VisitOutputConfigurationSource(domain ID, descriptor OutputConfigurationDescriptor,
	next func(index uint16) (OutputConfigurationSlice, error), visit OutputConfigurationVisit) error {
	_, err := inspectOutputConfigurationSource(domain, descriptor, next, false, &visit)
	return err
}

// InspectOutputConfigurationSource uses the same complete validator to own the
// typed declaration for one mutation. It never retains the source slice bytes.
func InspectOutputConfigurationSource(domain ID, descriptor OutputConfigurationDescriptor,
	next func(index uint16) (OutputConfigurationSlice, error)) (OutputConfiguration, error) {
	return inspectOutputConfigurationSource(domain, descriptor, next, true, nil)
}
