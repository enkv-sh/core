package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/macho"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	records "enkv.sh/core/internal/testrecords"
	"enkv.sh/crypto/testsupport/custody"
)

type byteInterval struct{ start, end uintptr }

type byteBuffers []byteInterval

func (buffers *byteBuffers) add(b []byte) {
	if cap(b) != 0 {
		start := reflect.ValueOf(b).Pointer()
		*buffers = append(*buffers, byteInterval{start, start + uintptr(cap(b))})
	}
}

func (buffers *byteBuffers) addSupportRows(rows contract.GeneratedSupportRows) {
	for _, row := range rows.Records {
		buffers.add(row.Body)
	}
}

func (buffers *byteBuffers) addGeneratedPreparation(prepared *generatedPreparation) {
	if prepared == nil {
		return
	}
	if op := prepared.operation; op != nil {
		for _, binding := range op.bindings {
			buffers.add(binding.Binding.SPKI)
		}
		if op.accessSource != nil {
			buffers.add(op.accessSource.Binding.SPKI)
		}
	}
	for _, result := range prepared.resultWrites {
		buffers.add(result.body)
	}
}

func (buffers *byteBuffers) addGeneratedOutput(output *contract.GeneratedOutputTransition) {
	if output == nil {
		return
	}
	for _, body := range output.EntryBodies {
		buffers.add(body)
	}
	buffers.addSupportRows(output.Rows)
}

// Strings have lengths, not exposed capacities. Count their actual accessible
// backing intervals without allocating byte conversions. Heap measures include
// the typed containers and allocator metadata separately.
func (buffers *byteBuffers) addString(value string) {
	if len(value) != 0 {
		start := uintptr(unsafe.Pointer(unsafe.StringData(value)))
		*buffers = append(*buffers, byteInterval{start, start + uintptr(len(value))})
	}
}

func visitOutputTargetStrings(target contract.OutputTarget, add func(string)) {
	for _, value := range []string{target.ServiceContractID, target.TargetContractID, target.CanonicalTarget, target.ConsumerLocator, target.Policy.ContractID} {
		add(value)
	}
}

func visitOutputConfigurationStrings(configuration contract.OutputConfiguration, add func(string)) {
	for _, destination := range configuration.DefaultDestinations {
		add(destination)
	}
	for _, binding := range configuration.Bindings {
		add(binding.DestinationID)
		for _, value := range []string{binding.Destination.ConfigContractID, binding.Destination.ServiceContractID, binding.Destination.Policy.ContractID} {
			add(value)
		}
		for _, target := range binding.Targets {
			visitOutputTargetStrings(target, add)
		}
	}
	for _, route := range configuration.Routes {
		for _, destination := range route.Destinations {
			add(destination)
		}
	}
}

func visitNormalOutputStrings(output *contract.NormalOutputTransition, add func(string)) {
	if output == nil {
		return
	}
	visitOutputConfigurationStrings(output.Before, add)
	for _, row := range output.EntriesBefore {
		add(row.Name)
	}
	for _, row := range output.Intent {
		add(row.Name)
	}
	for _, binding := range output.Bindings {
		add(binding.DestinationID)
		for _, value := range []string{binding.Destination.ConfigContractID, binding.Destination.ServiceContractID, binding.Destination.Policy.ContractID} {
			add(value)
		}
		for _, target := range binding.Targets {
			add(target.Name)
			visitOutputTargetStrings(target.Target, add)
		}
	}
	for _, group := range output.Groups {
		for _, member := range group {
			add(member)
		}
	}
	for _, route := range output.Routes {
		add(route.Name)
		for _, destination := range route.Destinations {
			add(destination)
		}
	}
}

func visitRetainedOutputStrings(c *Comparison, add func(string)) {
	if c == nil {
		return
	}
	if input := c.outputIntent; input != nil {
		for _, binding := range input.bindings {
			add(binding.destinationID)
			for _, value := range []string{binding.destination.ConfigContractID, binding.destination.ServiceContractID, binding.destination.Policy.ContractID} {
				add(value)
			}
			for _, target := range binding.targets {
				add(target.entryName)
				visitOutputTargetStrings(target.target, add)
			}
		}
		for _, group := range input.groups {
			for _, member := range group {
				add(member)
			}
		}
		for _, route := range input.routes {
			add(route.entryName)
			for _, destination := range route.destinations {
				add(destination)
			}
		}
	}
	if after := c.outputAfter; after != nil {
		visitNormalOutputStrings(after.transition, add)
		for _, target := range after.departedTargets {
			add(target.destinationID)
			visitOutputTargetStrings(target.target, add)
		}
	}
	if c.support != nil && (c.outputAfter == nil || c.support.Output != c.outputAfter.transition) {
		visitNormalOutputStrings(c.support.Output, add)
	}
}

func (buffers *byteBuffers) addOutputDestination(destination contract.OutputDestination) {
	buffers.add(destination.CanonicalSettings)
	buffers.add(destination.Policy.Data)
}
func (buffers *byteBuffers) addOutputTarget(target contract.OutputTarget) {
	buffers.add(target.TargetData)
	buffers.add(target.Policy.Data)
}
func (buffers *byteBuffers) addOutputConfiguration(configuration contract.OutputConfiguration) {
	for _, binding := range configuration.Bindings {
		buffers.addOutputDestination(binding.Destination)
		for _, target := range binding.Targets {
			buffers.addOutputTarget(target)
		}
	}
}
func (buffers *byteBuffers) addNormalOutput(output *contract.NormalOutputTransition) {
	if output == nil {
		return
	}
	buffers.addOutputConfiguration(output.Before)
	for _, binding := range output.Bindings {
		buffers.addOutputDestination(binding.Destination)
		for _, target := range binding.Targets {
			buffers.addOutputTarget(target.Target)
		}
	}
}
func (buffers *byteBuffers) addRetainedOutput(c *Comparison) {
	if c == nil {
		return
	}
	if input := c.outputIntent; input != nil {
		for _, binding := range input.bindings {
			buffers.addOutputDestination(binding.destination)
			for _, target := range binding.targets {
				buffers.addOutputTarget(target.target)
			}
		}
	}
	if after := c.outputAfter; after != nil {
		buffers.addNormalOutput(after.transition)
		for _, target := range after.departedTargets {
			buffers.addOutputTarget(target.target)
		}
	}
	if c.support != nil && (c.outputAfter == nil || c.support.Output != c.outputAfter.transition) {
		buffers.addNormalOutput(c.support.Output)
	}
}

func (buffers *byteBuffers) observeOutputStrings(c *Comparison) {
	count := 0
	visitRetainedOutputStrings(c, func(value string) {
		if len(value) != 0 {
			count++
		}
	})
	if cap(*buffers) < count {
		*buffers = make(byteBuffers, 0, count)
	} else {
		*buffers = (*buffers)[:0]
	}
	visitRetainedOutputStrings(c, buffers.addString)
}

func retainedOutputStrings(c *Comparison) byteBuffers {
	var buffers byteBuffers
	buffers.observeOutputStrings(c)
	return buffers
}

func (buffers *byteBuffers) addControl(control contract.CurrentControl) {
	buffers.add(control.NormalSigning.SPKI)
	if control.Recovery != nil {
		buffers.add(control.Recovery.Signing.SPKI)
		buffers.add(control.Recovery.KMS.SPKI)
	}
}

func (buffers *byteBuffers) addControlCore(control contract.ControlCore) {
	buffers.addControl(control.CurrentControl)
	buffers.add(control.AuthorityKMSBinding.SPKI)
}

func (buffers *byteBuffers) addAdmission(a openAdmission) {
	buffers.add(a.publicKey)
	buffers.add(a.descriptor)
	buffers.addBasis(a.current)
	if basis := a.observation; basis != nil {
		buffers.addControlCore(basis.control)
		if witness := basis.observation; witness != nil {
			buffers.add(witness.SigningAnchor)
			buffers.add(witness.StoreConfiguration)
			buffers.add(witness.HEAD)
			buffers.add(witness.Root)
			for _, page := range witness.RecipientPages {
				buffers.add(page)
			}
		}
	}
}

func (buffers *byteBuffers) addReplacementSource(source *ReplacementInstallation) {
	if source == nil {
		return
	}
	buffers.addControlCore(source.ExpectedControl)
	for _, row := range source.CapturedRecipients {
		buffers.add(row.Encryption.SPKI)
	}
	buffers.addPublicBasis(source.PublicBasis)
}

func (buffers *byteBuffers) addPublicBasis(basis PublicBasis) {
	for _, body := range [][]byte{basis.Descriptor, basis.Control, basis.Selection, basis.SigningAnchor, basis.StoreConfiguration, basis.HEAD, basis.Root} {
		buffers.add(body)
	}
	for _, body := range basis.RecipientPages {
		buffers.add(body)
	}
}

func (buffers *byteBuffers) addReplacementSuccessor(output *ReplacementSuccessor) {
	if output == nil {
		return
	}
	buffers.addControlCore(output.Control)
	buffers.addPublicBasis(output.Basis)
	for _, row := range output.Recipients {
		buffers.add(row.Encryption.SPKI)
	}
	buffers.add(output.Correlation.SignedCandidate)
}

func (buffers *byteBuffers) addReplacementReadback(readback *ReplacementReadback) {
	if readback == nil {
		return
	}
	buffers.addControlCore(readback.Control)
	buffers.addPublicBasis(readback.Basis)
	for _, row := range readback.Recipients {
		buffers.add(row.Encryption.SPKI)
	}
	buffers.add(readback.Correlation.SignedCandidate)
}

func (buffers *byteBuffers) addBasis(b *qualifiedCurrentBasis) {
	if b != nil {
		buffers.add(b.control)
		buffers.add(b.selection)
	}
}

func (buffers *byteBuffers) addGeneratedSelection(g *generatedSelection) {
	if g == nil {
		return
	}
	for _, record := range g.records {
		buffers.add(record.Body)
	}
	if g.content != nil {
		for _, fragments := range g.content.fragments {
			for _, fragment := range fragments {
				buffers.add(fragment.Payload)
			}
		}
	}
	for _, vector := range g.vectors.entries {
		for _, row := range vector.rows {
			buffers.add(row)
		}
	}
	for _, attempt := range g.attempts {
		buffers.add(attempt.result)
	}
	for _, body := range g.protected {
		buffers.add(body)
	}
	for _, retained := range g.canonical {
		buffers.add(retained.record.Entry.ValueBytes)
		buffers.add(retained.payload.Ciphertext)
		for _, wrap := range retained.access.Wraps {
			buffers.add(wrap.RSACiphertext)
		}
	}
}

func (buffers *byteBuffers) addHead(h format.Head) {
	buffers.add(h.K1)
	buffers.add(h.AuthorizationSignature)
	buffers.add(h.K3)
	if h.Genesis != nil {
		buffers.add(h.Genesis.K3Challenge)
		buffers.addControl(h.Genesis.Plan.Root.CurrentAccess.Core.CurrentControl)
	}
	if h.Succession != nil {
		buffers.add(h.Succession.Authorizer.SPKI)
		for _, row := range h.Succession.Evidence {
			buffers.add(row.Trust.Signature)
		}
		for _, acceptance := range h.Succession.Acceptances {
			buffers.add(acceptance.Signature)
		}
	}
}

func (buffers *byteBuffers) addSuccessionRequest(q contract.SuccessionRequestCore) {
	buffers.addControlCore(q.BeforeControl)
	buffers.addControlCore(q.ProposedAfterControl)
	for _, row := range q.ReplacementPlan.Rows {
		buffers.add(row.BeforeSigning.SPKI)
		buffers.add(row.AfterSigning.SPKI)
		buffers.add(row.BeforeKMS.SPKI)
		buffers.add(row.AfterKMS.SPKI)
	}
}

func (buffers byteBuffers) capacity() uint64 {
	slices.SortFunc(buffers, func(a, b byteInterval) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})
	var total uint64
	var end uintptr
	for _, b := range buffers {
		start := max(b.start, end)
		if b.end > start {
			total += uint64(b.end - start)
		}
		end = max(end, b.end)
	}
	return total
}

// Count the union of actual []byte capacity ranges, including empty slices with
// capacity and overlapping aliases. These fixtures retain full byte allocations;
// this does not infer inaccessible prefixes or suffixes of arbitrary subslices.
// It excludes strings, typed slices, maps, structs, and allocator metadata. The
// separate Go heap bound includes those heap allocations without estimating them.
func (buffers *byteBuffers) addRetainedByteBuffers(s *StateSession, c *Comparison, p *Candidate, observation *StateSession) {
	sessions := [5]*StateSession{s, observation}
	if p != nil {
		sessions[2] = p.session
		sessions[4] = p.replacementState
		if g := p.generated; g != nil && g.reservation != nil {
			sessions[3] = g.reservation.state
		}
	}
	for i, session := range sessions {
		if session == nil || slices.Contains(sessions[:i], session) {
			continue
		}
		buffers.add(session.body)
		buffers.addAdmission(session.admission)
		buffers.addHead(session.head)
		buffers.addControl(session.root.CurrentAccess.Core.CurrentControl)
		if cached := session.generatedWork; cached != nil {
			buffers.addGeneratedSelection(cached.selection)
		}
		for _, fact := range session.publicationFacts {
			if fact.coordinate != nil {
				buffers.add(fact.coordinate.DeletionTargetData)
			}
		}
		for _, page := range session.support {
			for _, record := range page.Records {
				buffers.add(record.Body)
			}
		}
		for _, page := range session.recipients {
			if page != nil {
				for _, row := range page.Slots {
					if row != nil && row.CurrentBinding != nil {
						buffers.add(row.CurrentBinding.SPKI)
					}
				}
			}
		}
		for _, page := range session.access {
			if page != nil {
				for _, record := range page.Records {
					for _, wrap := range record.Wraps {
						buffers.add(wrap.RSACiphertext)
					}
				}
			}
		}
		for _, page := range session.accessFacts {
			if page == nil {
				continue
			}
			for _, record := range page.Records {
				for _, wrap := range record.Wraps {
					buffers.add(wrap.RSACiphertext)
				}
			}
		}
		for _, b := range session.cache {
			buffers.add(b)
		}
		for _, page := range session.pages {
			if page != nil {
				for _, entry := range page.Slots {
					if entry != nil {
						buffers.add(entry.ValueBytes)
					}
				}
			}
		}
	}
	if c != nil {
		buffers.addRetainedOutput(c)
		buffers.addSupportRows(c.normalSupportRows)
		for _, page := range c.normalPackedPages {
			for _, row := range page.records {
				buffers.add(row.Body)
			}
		}
		if c.outputAfter != nil {
			for _, row := range c.outputAfter.records {
				buffers.add(row.Body)
			}
		}
		for _, value := range c.desiredEntries {
			buffers.add(value.InputBytes)
		}
		for _, object := range c.normalSupportObjects {
			buffers.add(object.body)
		}
		for _, row := range c.preparedRows {
			buffers.add(row.EntryBytes)
			buffers.add(row.AccessRecord)
		}
		if op := c.operation; op != nil {
			for _, binding := range op.bindings {
				buffers.add(binding.Binding.SPKI)
			}
			if op.accessSource != nil {
				buffers.add(op.accessSource.Binding.SPKI)
			}
		}
		if support := c.support; support != nil {
			buffers.addControl(support.BeforeAccess.CurrentControl)
			for _, record := range support.Records {
				buffers.add(record.Body)
			}
			for _, access := range support.AccessRecords {
				for _, wrap := range access.Wraps {
					buffers.add(wrap.RSACiphertext)
				}
			}
			for _, current := range support.CurrentGenerated {
				buffers.add(current.EntryBytes)
			}
		}
	}
	if p != nil {
		buffers.add(p.body)
		buffers.addHead(p.head)
		if p.succession != nil {
			buffers.addBasis(p.succession.basis)
			if p.succession.selectionAdmission != nil {
				buffers.addAdmission(*p.succession.selectionAdmission)
			}
		}
		for _, object := range p.objects {
			buffers.add(object.body)
		}
		buffers.addGeneratedPreparation(p.producer)
		for _, producer := range p.originalProducers {
			buffers.addGeneratedPreparation(producer)
		}
	}
}

func retainedByteBuffers(s *StateSession, c *Comparison, p *Candidate, observation *StateSession) byteBuffers {
	var buffers byteBuffers
	buffers.addRetainedByteBuffers(s, c, p, observation)
	return buffers
}

func retainedByteCapacity(s *StateSession, c *Comparison, p *Candidate, observation *StateSession) uint64 {
	total := retainedByteBuffers(s, c, p, observation).capacity()
	// Address intervals do not themselves keep the referenced allocations alive.
	runtime.KeepAlive(s)
	runtime.KeepAlive(c)
	runtime.KeepAlive(p)
	runtime.KeepAlive(observation)
	return total
}

// Missing or damaged last support can discard an otherwise complete decoded
// observation before selectCandidate returns it. The injected observation has
// the same entry, recipient and access byte-field lengths as its predecessor;
// identical decoders therefore allocate these same backing capacities. Its
// HEAD, support and page read/validation scratch are charged separately.
func decodedMemoryObservationCapacity(s *StateSession) uint64 {
	decoded := *s
	decoded.body, decoded.cache = nil, nil
	decoded.admission, decoded.head = openAdmission{}, format.Head{}
	return retainedByteCapacity(&decoded, nil, nil, nil)
}

// These test-only owner coefficients follow the maintained current-value
// replacement memory account. They do not constrain Product admission.
const replacementPhysicalChildUpper = uint64(contract.MaxChildPages * contract.MaxRequiredSupportPageLength)

type replacementImageMemorySource struct {
	ChildBytes           uint64 `json:"child_ref_bytes"`
	LogicalLocations     uint64 `json:"logical_locations"`
	LogicalBytes         uint64 `json:"logical_bytes"`
	LargestLogical       uint64 `json:"largest_logical_bytes"`
	LogicalEncodingUpper uint64 `json:"logical_encoding_upper_bytes"`
}

func replacementAppendUpper(length uint64) uint64 {
	if length == 0 {
		return 0
	}
	return 2*length + 8192
}

func replacementImageMemoryDimensions(root format.Root, locations []contract.GeneratorSliceLocation) replacementImageMemorySource {
	source := replacementImageMemorySource{ChildBytes: uint64(root.AdministrativeIndex.Length), LogicalLocations: uint64(len(locations))}
	for _, ref := range root.AdministrativeIndexShards {
		source.ChildBytes += uint64(ref.Length)
	}
	for _, table := range [][]*format.Ref{root.ValueEntryPages[:], root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				source.ChildBytes += uint64(ref.Length)
			}
		}
	}
	for _, table := range [][]format.Ref{root.CurrentAccess.Core.AccessPageRefs, root.RequiredSupport} {
		for _, ref := range table {
			source.ChildBytes += uint64(ref.Length)
		}
	}
	for _, location := range locations {
		length := uint64(location.Length)
		source.LogicalBytes += length
		source.LargestLogical = max(source.LargestLogical, length)
		source.LogicalEncodingUpper += replacementAppendUpper(length)
	}
	return source
}

func replacementUnknownImageMemorySource() replacementImageMemorySource {
	// Different logical locations can overlap one physical fragment. Charge
	// every permitted location at the largest existing allocation limit.
	const carrierBytes = contract.SupportRecordOverhead + contract.GeneratorCarrierFixedLength + contract.GeneratorSliceLocationLength
	count := uint64(contract.MaxChildPages * (contract.MaxRequiredSupportPageLength - contract.RequiredSupportPageHeaderLength) / carrierBytes)
	length := uint64(max(contract.GeneratorIntentMaxLength, contract.GeneratorDeclarationMaxLength,
		contract.GeneratorGraphMaxLength, contract.GeneratorDeclarationEntryMaxLength, 1<<20,
		contract.GeneratedRecipientRegistryMaxLength, contract.MaxOutputConfigurationBytes,
		contract.GeneratedFinalPreparationMaxLength))
	return replacementImageMemorySource{ChildBytes: replacementPhysicalChildUpper, LogicalLocations: count,
		LogicalBytes: count * length, LargestLogical: length, LogicalEncodingUpper: count * replacementAppendUpper(length)}
}

func (source replacementImageMemorySource) logicalUpper() uint64 {
	return 9*source.LogicalBytes + source.LogicalEncodingUpper + 2*source.LargestLogical + 2*replacementAppendUpper(source.LargestLogical)
}

func replacementIndexMemoryUpper(length uint64) uint64 {
	const payload = uint64(2097036)
	var encoded, largest uint64
	for remaining := length; remaining != 0; {
		part := min(remaining, payload)
		shard := replacementAppendUpper(part + 116)
		encoded += shard
		largest = max(largest, shard)
		remaining -= part
	}
	return length + encoded + largest + 65535 + 3*(150+256*34)
}

func replacementFixedMemoryUpper() uint64 {
	return 16*replacementAppendUpper(262144) + 16*replacementAppendUpper(65536) +
		32*replacementAppendUpper(6697) + 64*replacementAppendUpper(1613) +
		4*replacementAppendUpper(819832) + 4*replacementAppendUpper(1<<20) +
		4*replacementAppendUpper(256<<10) + 4*replacementAppendUpper(512<<10) +
		4*replacementAppendUpper(1<<20) + 4*514*422 + 64<<10
}

func replacementRecipientFixedMemoryUpper(captured uint64) uint64 {
	return 5*422*captured + 10*11939958 + replacementFixedMemoryUpper()
}

func replacementNativeAdapterDesignUpper() uint64 {
	// This controlled design account retains its separate native layout,
	// heap and platform qualification obligations.
	return 5*(724782326+69632) + 2*289753848 + 10*11186176 +
		4*replacementAppendUpper(8<<20) + 16*(64<<10)
}

type replacementMemorySourceAccount struct {
	Predecessor                replacementImageMemorySource `json:"predecessor"`
	Candidate                  replacementImageMemorySource `json:"candidate"`
	Observation                replacementImageMemorySource `json:"observation"`
	CapturedRecipients         uint64                       `json:"captured_recipients"`
	RecipientCopiesUpper       uint64                       `json:"recipient_copies_upper_bytes"`
	RecipientFixedOwnersUpper  uint64                       `json:"recipient_and_fixed_owner_upper_bytes"`
	CandidateObjectsUpper      uint64                       `json:"candidate_objects_upper_bytes"`
	IndexAndRewriteUpper       uint64                       `json:"index_and_rewrite_upper_bytes"`
	CoreUpper                  uint64                       `json:"core_upper_bytes"`
	NativeAdapterDesignUpper   uint64                       `json:"native_adapter_design_upper_bytes"`
	NativeQualificationPending bool                         `json:"native_qualification_pending"`
}

func replacementCoreMemoryAccount(predecessor, candidate, observation replacementImageMemorySource, objectRefs []format.Ref, captured uint64) replacementMemorySourceAccount {
	var objects uint64
	for _, ref := range objectRefs {
		objects += replacementAppendUpper(uint64(ref.Length))
	}
	if objectRefs == nil {
		objects = contract.MaxChildPages*replacementAppendUpper(contract.MaxRequiredSupportPageLength) + replacementAppendUpper(contract.MaxRootLength)
	}
	pageWork := 4 * replacementAppendUpper(2<<20)
	work := max(8*predecessor.ChildBytes+replacementIndexMemoryUpper(replacementPhysicalChildUpper)+pageWork,
		8<<20+8*candidate.ChildBytes+pageWork)
	recipients := 5 * 422 * captured
	core := replacementRecipientFixedMemoryUpper(captured) + 9*(predecessor.ChildBytes+candidate.ChildBytes+observation.ChildBytes) +
		objects + candidate.ChildBytes + work + predecessor.logicalUpper() + candidate.logicalUpper() + observation.logicalUpper()
	return replacementMemorySourceAccount{Predecessor: predecessor, Candidate: candidate, Observation: observation,
		CapturedRecipients: captured, RecipientCopiesUpper: recipients, RecipientFixedOwnersUpper: replacementRecipientFixedMemoryUpper(captured), CandidateObjectsUpper: objects, IndexAndRewriteUpper: work,
		CoreUpper: core, NativeAdapterDesignUpper: replacementNativeAdapterDesignUpper(), NativeQualificationPending: true}
}

func assertReplacementMemorySourceAccount(t *testing.T) {
	t.Helper()
	t.Run("declared-references-and-logical-locations", func(t *testing.T) {
		root := format.Root{AdministrativeIndex: format.Ref{Length: 101}, AdministrativeIndexShards: []format.Ref{{Length: 103}},
			RequiredSupport: []format.Ref{{Length: 127}, {Length: 131}}}
		root.ValueEntryPages[0], root.Recipients[0] = &format.Ref{Length: 107}, &format.Ref{Length: 109}
		root.CurrentAccess.Core.AccessPageRefs = []format.Ref{{Length: 113}}
		source := replacementImageMemoryDimensions(root, []contract.GeneratorSliceLocation{{Length: 11}, {Length: 13}})
		if source.ChildBytes != 791 || source.LogicalLocations != 2 || source.LogicalBytes != 24 || source.LargestLogical != 13 || source.LogicalEncodingUpper != 16432 || source.logicalUpper() != 33110 {
			t.Fatal("source dimensions differ from declared Ref and logical lengths", source)
		}
	})
	t.Run("overlapping-locations-own-independent-logical-bytes", func(t *testing.T) {
		source := replacementImageMemoryDimensions(format.Root{RequiredSupport: []format.Ref{{Length: 1809}}},
			[]contract.GeneratorSliceLocation{{BlobID: contract.ID{1}, Length: 1000}, {BlobID: contract.ID{1}, Length: 1000}})
		if source.LogicalLocations != 2 || source.LogicalBytes != 2000 || source.LogicalBytes <= source.ChildBytes || source.LogicalEncodingUpper != 20384 {
			t.Fatal("overlap incorrectly reduced logical owner account", source)
		}
	})
	t.Run("fixed-policy-arithmetic", func(t *testing.T) {
		if replacementAppendUpper(0) != 0 || replacementAppendUpper(7) != 8206 || replacementIndexMemoryUpper(10) != 108995 || replacementIndexMemoryUpper(replacementPhysicalChildUpper) != 1617072297 || replacementFixedMemoryUpper() != 42893744 || replacementRecipientFixedMemoryUpper(65536) != 300574284 || replacementNativeAdapterDesignUpper() != 4383819454 {
			t.Fatal("replacement source policy arithmetic differs from independently summed owner slots")
		}
		before := replacementImageMemorySource{ChildBytes: 7, LogicalLocations: 2, LogicalBytes: 24, LargestLogical: 13, LogicalEncodingUpper: 16432}
		account := replacementCoreMemoryAccount(before, replacementImageMemorySource{ChildBytes: 11}, replacementImageMemorySource{ChildBytes: 13}, []format.Ref{{Length: 17}, {Length: 19}}, 2)
		if account.CoreUpper != 1796229737 || account.CandidateObjectsUpper != 16456 || account.RecipientCopiesUpper != 4220 || !account.NativeQualificationPending {
			t.Fatal("replacement source account differs from independent literal calculation", account)
		}
	})
	t.Run("unknown-observation-and-recipient-maximum", func(t *testing.T) {
		unknown := replacementUnknownImageMemorySource()
		if unknown.ChildBytes != 536870912 || unknown.LogicalBytes <= unknown.ChildBytes || unknown.LogicalLocations == 0 || unknown.logicalUpper() <= 9*unknown.ChildBytes {
			t.Fatal("unknown observation lost permitted logical overlap", unknown)
		}
		known := replacementCoreMemoryAccount(replacementImageMemorySource{}, replacementImageMemorySource{}, replacementImageMemorySource{}, []format.Ref{}, 0)
		larger := replacementCoreMemoryAccount(replacementImageMemorySource{}, replacementImageMemorySource{}, unknown, []format.Ref{}, 65536)
		if larger.CoreUpper <= known.CoreUpper || larger.RecipientCopiesUpper != 138280960 || larger.Observation.ChildBytes != 536870912 {
			t.Fatal("unknown observation or captured source maximum was narrowed", larger)
		}
	})
}

type memorySample struct {
	Phase                   string               `json:"phase"`
	StringBacking           uint64               `json:"retained_output_string_backing_bytes"`
	ByteCapacity            uint64               `json:"retained_byte_capacity_bytes"`
	GoHeapUpperBound        uint64               `json:"go_heap_upper_bound_bytes"`
	GoHeapAllocated         uint64               `json:"go_heap_allocated_bytes"`
	GoSystemBytes           uint64               `json:"go_system_bytes"`
	GoTotalAlloc            uint64               `json:"go_total_alloc_bytes"`
	GoHeapSys               uint64               `json:"go_heap_sys_bytes"`
	GoStackInuse            uint64               `json:"go_stack_inuse_bytes"`
	GoGCSys                 uint64               `json:"go_gc_sys_bytes"`
	ArenaUpper              uint64               `json:"ordinary_arena_upper_bytes,omitempty"`
	SourceOwnedUpper        uint64               `json:"source_owned_upper_bytes,omitempty"`
	ContractUpper           uint64               `json:"ordinary_contract_upper_bytes,omitempty"`
	OrdinaryProof           *ordinaryOutputProof `json:"ordinary_native_proof,omitempty"`
	ResultStoreCapacity     uint64               `json:"result_store_body_capacity_bytes,omitempty"`
	ResultUnobservedReserve uint64               `json:"result_unobserved_owner_reserve_bytes,omitempty"`
}

type memoryAccounting struct {
	sourceOwnedUpper  uint64
	sourceOwnedBefore *StateSession
	baseline          runtime.MemStats
	samples           []memorySample
	ordinary          *ordinaryOutputProof
	byteBuffers       byteBuffers
	stringBuffers     byteBuffers
	replacementSource *ReplacementInstallation
}

// The live process heap at baseline plus all later allocations is an upper bound
// on Go heap at every intervening instant, including between samples and after
// collection. Do not subtract fixture, harness or transient allocations: retaining
// that overcount is what makes this a bound on session heap without private APIs.
func startMemoryAccounting() *memoryAccounting {
	m := &memoryAccounting{samples: make([]memorySample, 0, 5)}
	runtime.GC()
	runtime.ReadMemStats(&m.baseline)
	return m
}

func (m *memoryAccounting) sample(phase string, s *StateSession, c *Comparison, p *Candidate, observation *StateSession, extra ...[]byte) {
	m.byteBuffers = m.byteBuffers[:0]
	m.byteBuffers.addRetainedByteBuffers(s, c, p, observation)
	m.byteBuffers.addReplacementSource(m.replacementSource)
	for _, body := range extra {
		m.byteBuffers.add(body)
	}
	capacity := m.byteBuffers.capacity()
	m.stringBuffers.observeOutputStrings(c)
	owners := []*StateSession{s, observation}
	if p != nil {
		owners = append(owners, p.session, p.replacementState)
		if p.generated != nil && p.generated.reservation != nil {
			owners = append(owners, p.generated.reservation.state)
		}
	}
	for i, owner := range owners {
		if owner == nil || slices.Contains(owners[:i], owner) {
			continue
		}
		for _, fact := range owner.publicationFacts {
			if v := fact.coordinate; v != nil {
				for _, value := range []string{v.ServiceContractID, v.CanonicalTarget, v.DeletionDestinationID, v.DeletionConsumerLocator, v.DeletionTargetContractID, v.DeletionConfigContractID, v.DeletionCredentialRouteContractID} {
					m.stringBuffers.addString(value)
				}
			}
			if v := fact.marker; v != nil {
				for _, value := range []string{v.ExecutorID, v.CredentialRouteID, v.Evidence.SafeRequestID, v.Evidence.SafeResourceID, v.Evidence.ConsumerLocator, v.BirthServiceContractID, v.BirthTargetContractID} {
					m.stringBuffers.addString(value)
				}
			}
		}
	}
	stringBacking := m.stringBuffers.capacity()
	var now runtime.MemStats
	runtime.ReadMemStats(&now)
	m.samples = append(m.samples, memorySample{
		Phase: phase, ByteCapacity: capacity, StringBacking: stringBacking,
		GoHeapUpperBound: m.baseline.HeapAlloc + now.TotalAlloc - m.baseline.TotalAlloc,
		GoHeapAllocated:  now.HeapAlloc, GoSystemBytes: now.Sys, GoTotalAlloc: now.TotalAlloc,
		GoHeapSys: now.HeapSys, GoStackInuse: now.StackInuse, GoGCSys: now.GCSys,
	})
	runtime.KeepAlive(s)
	runtime.KeepAlive(c)
	runtime.KeepAlive(p)
	runtime.KeepAlive(observation)
	runtime.KeepAlive(extra)
	runtime.KeepAlive(m.replacementSource)
}

// This proof is native and source-bound to the audited ordinary Go arena
// path. Native race/system storage is a separate process observation.
type ordinaryOutputProof struct {
	GoVersion, GOOS, GOARCH, GODEBUG, BuildIdentity string
	ImagePath, ImageSHA256                          string
	ImageBytes, PageBytes, StaticUpper              uint64
	EffectiveEfence, EffectiveSbrk                  uint8
	Segments                                        []macho.SegmentHeader
	file                                            os.FileInfo
}

func sameOrdinaryOutputImage(first, second ordinaryOutputProof) bool {
	return first.ImagePath == second.ImagePath && first.ImageSHA256 == second.ImageSHA256 &&
		records.SameLocalFile(first.file, second.file) && first.ImageBytes == second.ImageBytes && first.file.ModTime().Equal(second.file.ModTime())
}

func checkedOutputMemorySum(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if value > ^uint64(0)-total {
			return 0, fmt.Errorf("ordinary memory sum overflow")
		}
		total += value
	}
	return total, nil
}

func ordinaryOutputArenaUpper(sample memorySample) (uint64, error) {
	return checkedOutputMemorySum(sample.GoHeapSys, sample.GoStackInuse, sample.GoGCSys)
}

func ordinaryOutputEligibility(version, goos, arch, environment string, build *debug.BuildInfo) error {
	if version != "go1.27.3" || goos != "darwin" || arch != "arm64" || build == nil || build.GoVersion != version {
		return fmt.Errorf("requires Go1.27.3 darwin/arm64 build")
	}
	settings := make(map[string]string)
	for _, setting := range build.Settings {
		settings[setting.Key] = setting.Value
	}
	race, racePresent := settings["-race"]
	if settings["GOOS"] != goos || settings["GOARCH"] != arch || racePresent && race != "true" ||
		settings["-compiler"] != "gc" || settings["-buildmode"] != "exe" || settings["CGO_ENABLED"] != "1" ||
		settings["-asan"] == "true" || settings["-msan"] == "true" || settings["GOEXPERIMENT"] != "" {
		return fmt.Errorf("unknown ordinary native build settings")
	}
	// Runtime startup parses defaults, then environment, left-to-right. An
	// explicit unknown value fails closed instead of assuming runtime fallback.
	efence, sbrk := "0", "0"
	for _, source := range []string{settings["DefaultGODEBUG"], environment} {
		for _, field := range strings.Split(source, ",") {
			if key, value, present := strings.Cut(field, "="); present {
				switch key {
				case "efence":
					efence = value
				case "sbrk":
					sbrk = value
				}
			}
		}
	}
	if efence != "0" {
		return fmt.Errorf("ordinary arena proof requires effective efence=0")
	}
	// sbrk routes mallocgc payloads to persistentalloc charged to OtherSys.
	if sbrk != "0" {
		return fmt.Errorf("ordinary arena proof requires effective sbrk=0")
	}
	return nil
}

func ordinaryOutputSegmentUpper(segments []macho.SegmentHeader, fileBytes, pageBytes uint64) (uint64, error) {
	if pageBytes == 0 || pageBytes&(pageBytes-1) != 0 {
		return 0, fmt.Errorf("unknown native image page size: %d", pageBytes)
	}
	var total uint64
	seen := make(map[string]bool)
	for _, segment := range segments {
		if seen[segment.Name] || segment.Name == "" || segment.Cmd != macho.LoadCmdSegment64 ||
			uint64(segment.Len) != 72+80*uint64(segment.Nsect) || segment.Maxprot & ^uint32(7) != 0 ||
			segment.Prot & ^segment.Maxprot != 0 || segment.Offset > fileBytes || segment.Filesz > fileBytes-segment.Offset ||
			segment.Memsz > ^uint64(0)-segment.Addr {
			return 0, fmt.Errorf("unknown main image segment shape: %+v", segment)
		}
		seen[segment.Name] = true
		// Go's Mach-O linker retains file-backed DWARF with zero VM size and
		// initial protection. The native loader maps no zero VM extent,
		// regardless of maximum protection; Filesz need not fit Memsz here.
		if segment.Name == "__DWARF" {
			if segment.Memsz != 0 || segment.Filesz == 0 || segment.Prot != 0 || segment.Nsect == 0 || segment.Flag != 0 {
				return 0, fmt.Errorf("unknown file-only debug segment: %+v", segment)
			}
			continue
		}
		if segment.Memsz == 0 || segment.Filesz > segment.Memsz {
			return 0, fmt.Errorf("unknown mapped main image segment: %+v", segment)
		}
		if segment.Name == "__PAGEZERO" {
			if segment.Addr != 0 || segment.Filesz != 0 || segment.Offset != 0 || segment.Prot != 0 || segment.Maxprot != 0 || segment.Nsect != 0 {
				return 0, fmt.Errorf("PAGEZERO is not an inaccessible reservation: %+v", segment)
			}
			continue
		}
		if segment.Prot == 0 {
			return 0, fmt.Errorf("unmapped main image segment: %+v", segment)
		}
		// The loader maps the page-rounded VM interval, including BSS and
		// partial end pages. Native ASLR slides by whole pages, preserving
		// these offsets. Sum each full interval conservatively, even if
		// malformed intervals overlap; never omit its first or last page.
		end, err := checkedOutputMemorySum(segment.Addr, segment.Memsz, pageBytes-1)
		if err != nil {
			return 0, err
		}
		mappedEnd := end & ^(pageBytes - 1)
		mappedStart := segment.Addr & ^(pageBytes - 1)
		mapped := mappedEnd - mappedStart
		total, err = checkedOutputMemorySum(total, mapped)
		if err != nil {
			return 0, err
		}
	}
	if !seen["__PAGEZERO"] || !seen["__TEXT"] || total == 0 {
		return 0, fmt.Errorf("incomplete main image segments")
	}
	return total, nil
}

func startOrdinaryOutputAccounting(proof *ordinaryOutputProof) *memoryAccounting {
	m := &memoryAccounting{ordinary: proof, samples: make([]memorySample, 0, 5)}
	runtime.ReadMemStats(&m.baseline)
	return m
}

func (m *memoryAccounting) restartOrdinaryOutputAccounting() {
	// Diagnostic baselines do not reset the mapped arena or observer workspace.
	m.samples = m.samples[:0]
	m.byteBuffers = m.byteBuffers[:0]
	m.stringBuffers = m.stringBuffers[:0]
	runtime.ReadMemStats(&m.baseline)
}

func (m *memoryAccounting) checkMaximumOutputMemory(sample memorySample, before *StateSession, emptyState bool) error {
	if sample.ByteCapacity > sample.ArenaUpper {
		return fmt.Errorf("visible bytes exceed arena: bytes=%d arena=%d", sample.ByteCapacity, sample.ArenaUpper)
	}
	var static uint64
	if m.ordinary != nil {
		static = m.ordinary.StaticUpper
	}
	outer, err := maximumOutputOuterUpper(static)
	if err != nil {
		return fmt.Errorf("outer source allowance unavailable: %w", err)
	}
	if before == nil {
		if !emptyState || m.sourceOwnedBefore != nil || m.sourceOwnedUpper != 0 || sample.SourceOwnedUpper != 0 || sample.ContractUpper > outer {
			return fmt.Errorf("native-only arena proof insufficient: empty=%t contract=%d", emptyState, sample.ContractUpper)
		}
		return nil
	}
	if m.ordinary == nil || m.sourceOwnedBefore != before || m.sourceOwnedUpper == 0 || sample.SourceOwnedUpper != m.sourceOwnedUpper || sample.SourceOwnedUpper > outer {
		return fmt.Errorf("source proof missing, mismatched or insufficient: bound=%d attached=%d predecessor=%t", sample.SourceOwnedUpper, m.sourceOwnedUpper, m.sourceOwnedBefore == before)
	}
	return checkVisibleOutputSource(sample, m.ordinary.StaticUpper)
}

// This arithmetic alone does not qualify the runtime image, arena or an
// intervening lifetime. Native qualification additionally checks those owners.
func checkVisibleOutputSource(sample memorySample, static uint64) error {
	outer, err := maximumOutputOuterUpper(static)
	if err != nil || sample.SourceOwnedUpper == 0 || sample.SourceOwnedUpper > outer {
		return fmt.Errorf("visible source allowance unavailable: bound=%d", sample.SourceOwnedUpper)
	}
	parent, child := custody.GeneratorProcessOwnedByteCeilings()
	outside, err := checkedOutputMemorySum(static, parent, child)
	if err != nil || outside > sample.SourceOwnedUpper {
		return fmt.Errorf("source outside-owner subtraction unavailable: static=%d parent=%d child=%d bound=%d", static, parent, child, sample.SourceOwnedUpper)
	}
	visible, err := checkedOutputMemorySum(sample.ByteCapacity, sample.StringBacking)
	if err != nil || visible > sample.SourceOwnedUpper-outside {
		return fmt.Errorf("visible owners exceed source envelope: bytes=%d strings=%d available=%d", sample.ByteCapacity, sample.StringBacking, sample.SourceOwnedUpper-outside)
	}
	return nil
}

// full_only: false
func TestOrdinaryOutputMemoryProof(t *testing.T) {
	t.Run("image-identity", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "image")
		body := []byte("ordinary output image identity control")
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		original, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := original.Close(); err != nil {
				t.Error(err)
			}
		})
		observe := func() ordinaryOutputProof {
			t.Helper()
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			return ordinaryOutputProof{ImagePath: path, ImageSHA256: fmt.Sprintf("%x", sha256.Sum256(content)), ImageBytes: uint64(info.Size()), file: info}
		}
		before := observe()
		if !sameOrdinaryOutputImage(before, observe()) {
			t.Fatal("unchanged image identity refused")
		}
		for _, damage := range []struct {
			name   string
			change func(*ordinaryOutputProof)
		}{
			{"path", func(proof *ordinaryOutputProof) { proof.ImagePath += "-other" }},
			{"hash", func(proof *ordinaryOutputProof) { proof.ImageSHA256 = "different" }},
			{"length", func(proof *ordinaryOutputProof) { proof.ImageBytes++ }},
			{"missing-identity", func(proof *ordinaryOutputProof) { proof.file = nil }},
		} {
			t.Run(damage.name, func(t *testing.T) {
				after := before
				damage.change(&after)
				if sameOrdinaryOutputImage(before, after) || sameOrdinaryOutputImage(after, before) {
					t.Fatal("changed image identity admitted")
				}
			})
		}
		changedTime := before.file.ModTime().Add(2 * time.Hour)
		if err := os.Chtimes(path, changedTime, changedTime); err != nil {
			t.Fatal(err)
		}
		after := observe()
		if !records.SameLocalFile(before.file, after.file) || before.ImagePath != after.ImagePath || before.ImageSHA256 != after.ImageSHA256 ||
			before.ImageBytes != after.ImageBytes || before.file.ModTime().Equal(after.file.ModTime()) {
			t.Fatal("modtime control did not isolate a changed observed modification time")
		}
		if sameOrdinaryOutputImage(before, after) {
			t.Fatal("changed image modification time admitted")
		}
		if err := os.Chtimes(path, before.file.ModTime(), before.file.ModTime()); err != nil {
			t.Fatal(err)
		}
		if !sameOrdinaryOutputImage(before, observe()) {
			t.Fatal("restored image modification time refused")
		}
		replacement := filepath.Join(directory, "replacement")
		if err := os.WriteFile(replacement, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(replacement, before.file.ModTime(), before.file.ModTime()); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
		after = observe()
		if records.SameLocalFile(before.file, after.file) || before.ImagePath != after.ImagePath || before.ImageSHA256 != after.ImageSHA256 ||
			before.ImageBytes != after.ImageBytes || !before.file.ModTime().Equal(after.file.ModTime()) {
			t.Fatal("replacement control did not isolate a different native file identity")
		}
		if sameOrdinaryOutputImage(before, after) {
			t.Fatal("byte-identical replacement image admitted")
		}
	})
	t.Run("source-decision", func(t *testing.T) {
		before := &StateSession{}
		memory := &memoryAccounting{ordinary: &ordinaryOutputProof{StaticUpper: 116572160}, sourceOwnedBefore: before, sourceOwnedUpper: 1774033480}
		sample := memorySample{ArenaUpper: 1684219248, ContractUpper: 1814561473, SourceOwnedUpper: 1774033480, ByteCapacity: 400 << 20, StringBacking: 36 << 20}
		if err := memory.checkMaximumOutputMemory(sample, before, false); err != nil {
			t.Fatal("complete source proof below limit must survive an insufficient arena proof", err)
		}
	})

	t.Run("source-arithmetic", func(t *testing.T) {
		for _, row := range []struct {
			c, output, intents, static uint64
			want                       [4]uint64
			refuse                     bool
		}{
			{103608337, 37748736, 50331648, 116572160, [4]uint64{1738454245, 1731801653, 1774077176, 1592533797}, false},
			{103612433, 37748736, 50331648, 116572160, [4]uint64{1738467557, 1731819061, 1774098680, 1592547109}, false},
			{103608337, 37748736, 50331648, 116588544, [4]uint64{1738470629, 1731818037, 1774093560, 1592550181}, false},
			{1, 2, 0, 1, [4]uint64{}, true}, {4, 2, 3, 1, [4]uint64{}, true},
			{^uint64(0), 0, 0, 1, [4]uint64{}, true}, {^uint64(0) / 2, 0, 0, 1, [4]uint64{}, true},
			{103608337, 37748736, 50331648, ^uint64(0), [4]uint64{}, true},
		} {
			got, err := maximumOutputOwnedRows(row.c, row.output, row.intents, row.static)
			if got != row.want || (err != nil) != row.refuse {
				t.Fatalf("source rows c=%d static=%d got=%v want=%v refused=%t", row.c, row.static, got, row.want, err != nil)
			}
		}
		if outer, err := maximumOutputOuterUpper(116572160); err != nil || outer != 4239169694 {
			t.Fatal("full retained outer allowance", outer, err)
		}
		// The precise routing diagnosis adds two 260-byte shortenings to the
		// old equal-length row. Omitting all successor-output subtraction
		// plus the revised owners still leave 167,608,282 bytes above that row.
		rows, err := maximumOutputOwnedRows(103608337, 37748736, 50331648, 116572160)
		if err != nil || rows[2]-(1606468374+2*260) != 167608282 {
			t.Fatal("routing shortening envelope", rows[2], err)
		}
	})
	t.Run("source-refusals", func(t *testing.T) {
		before := &StateSession{}
		memory := &memoryAccounting{ordinary: &ordinaryOutputProof{StaticUpper: 116572160}, sourceOwnedBefore: before, sourceOwnedUpper: 1774033480}
		sample := memorySample{ArenaUpper: 1684219248, ContractUpper: 1814561473, SourceOwnedUpper: 1774033480, ByteCapacity: 400 << 20, StringBacking: 36 << 20}
		for _, damage := range []struct {
			name   string
			change func(*memoryAccounting, *memorySample)
		}{
			{"missing", func(m *memoryAccounting, s *memorySample) { m.sourceOwnedUpper = 0 }},
			{"wrong-predecessor", func(m *memoryAccounting, s *memorySample) { m.sourceOwnedBefore = &StateSession{prepared: true} }},
			{"missing-predecessor", func(m *memoryAccounting, s *memorySample) { m.sourceOwnedBefore = nil }},
			{"wrong-sample", func(m *memoryAccounting, s *memorySample) { s.SourceOwnedUpper-- }},
			{"missing-image", func(m *memoryAccounting, s *memorySample) { m.ordinary = nil }},
			{"source-limit", func(m *memoryAccounting, s *memorySample) {
				outer, err := maximumOutputOuterUpper(m.ordinary.StaticUpper)
				if err != nil {
					t.Fatal(err)
				}
				m.sourceOwnedUpper = outer + 1
				s.SourceOwnedUpper = m.sourceOwnedUpper
			}},
			{"visible-limit", func(m *memoryAccounting, s *memorySample) { s.StringBacking = 1600 << 20 }},
			{"visible-overflow", func(m *memoryAccounting, s *memorySample) { s.StringBacking = ^uint64(0) }},
			{"arena-limit", func(m *memoryAccounting, s *memorySample) { s.ArenaUpper = 1 }},
			{"outside-underflow", func(m *memoryAccounting, s *memorySample) { m.ordinary = &ordinaryOutputProof{StaticUpper: 1774033480} }},
		} {
			t.Run(damage.name, func(t *testing.T) {
				m, s := *memory, sample
				damage.change(&m, &s)
				if m.checkMaximumOutputMemory(s, before, false) == nil {
					t.Fatal("unsupported proof accepted")
				}
			})
		}
		native := &memoryAccounting{}
		if native.checkMaximumOutputMemory(memorySample{ArenaUpper: 100, ContractUpper: 200}, nil, true) != nil {
			t.Fatal("small native arena control")
		}
		outer, err := maximumOutputOuterUpper(0)
		if err != nil {
			t.Fatal(err)
		}
		if native.checkMaximumOutputMemory(memorySample{ArenaUpper: 100, ContractUpper: outer + 1}, nil, true) == nil || native.checkMaximumOutputMemory(memorySample{}, nil, false) == nil {
			t.Fatal("native control admitted missing scope or excessive arena")
		}
	})
	t.Run("source-configured-fixture", func(t *testing.T) {
		seed := newConfiguredSuccessionMemorySeed(t, false)
		env, f, keys := seed.openCase(t)
		defer keys.RetireApply()
		before := f.session
		// Fixed scalar allowance tests method admission, not a runtime image or arena.
		proof := &ordinaryOutputProof{StaticUpper: 116572160}
		entries := maximumOutputEntryInputs(t, env, before, "")
		var generated []int
		for i, entry := range entries {
			if entry.ValueSource == contract.Generated {
				generated = append(generated, i)
			}
		}
		if len(generated) != 2 || len(before.generatedSliceLocations) != 2 {
			t.Fatal("small fixture requires two authenticated intents")
		}
		upper, err := maximumOutputOwnedUpper(proof, before, entries)
		if err != nil {
			t.Fatal("small configured h0 source proof", err)
		}
		conversion := maximumOutputEntryInputs(t, env, before, entries[generated[0]].Name)
		convertedUpper, err := maximumOutputOwnedUpper(proof, before, conversion)
		if err != nil || convertedUpper != upper {
			t.Fatal("small configured h1 source proof", err, upper, convertedUpper)
		}
		// Arithmetic uses authenticated predecessor dimensions, independent
		// of the input conversion or any observed successor.
		var omitted uint64
		for _, location := range before.generatedSliceLocations {
			omitted += uint64(location.Length)
		}
		if omitted == 0 {
			t.Fatal("small fixture omitted no intent bytes")
		}
		rows, err := maximumOutputOwnedRows(before.root.ChildEncodedBytes+uint64(before.head.Core.Root.Length)+uint64(len(before.body)), uint64(before.root.OutputConfiguration.TotalLength), omitted, proof.StaticUpper)
		if err != nil || upper != max(rows[0], rows[1], rows[2], rows[3]) {
			t.Fatal("authenticated predecessor bound", err)
		}
		t.Run("two-departures", func(t *testing.T) {
			damaged := slices.Clone(conversion)
			damaged[generated[1]].ValueSource = contract.Supplied
			if _, err := maximumOutputOwnedUpper(proof, before, damaged); err == nil {
				t.Fatal("h2 admitted")
			}
		})
		t.Run("new-original", func(t *testing.T) {
			damaged := slices.Clone(entries)
			for i := range damaged {
				if damaged[i].ValueSource == contract.Supplied {
					damaged[i].ValueSource = contract.Generated
					break
				}
			}
			if _, err := maximumOutputOwnedUpper(proof, before, damaged); err == nil {
				t.Fatal("new original admitted")
			}
		})
		t.Run("retained-intent", func(t *testing.T) {
			damaged := *before
			damaged.generatedSliceLocations = slices.Clone(before.generatedSliceLocations)
			damaged.generatedSliceLocations[0].ContentKind = contract.GeneratorContentDeclaration
			if _, err := maximumOutputOwnedUpper(proof, &damaged, entries); err == nil {
				t.Fatal("declaration admitted")
			}
		})
	})
	t.Run("source-shape", func(t *testing.T) {
		ref := format.Ref{Length: 1024}
		fresh := func() *StateSession {
			s := &StateSession{store: &memoryStore{fileBodies: &fixtureBodyFiles{}}, support: []format.RequiredSupportPageView{{Records: []contract.SupportRecordView{{Kind: contract.OutputConfigurationSliceSupportKind}}}}, supportFacts: []selectedSupportPageFacts{{ref: ref}}}
			s.root.ChildEncodedBytes = 1024
			s.root.RequiredSupport = []format.Ref{ref}
			s.root.OutputConfiguration = contract.OutputConfigurationDescriptor{Schema: contract.OutputConfigurationSchema, TotalLength: 16, RoutingLength: 6, SliceCount: 1}
			return s
		}
		proof := &ordinaryOutputProof{StaticUpper: 116572160}
		if _, err := maximumOutputOwnedUpper(proof, fresh(), nil); err != nil {
			t.Fatal("small scalar shape", err)
		}
		for _, damage := range []struct {
			name   string
			change func(*StateSession)
		}{
			{"resident-store", func(s *StateSession) { s.store.(*memoryStore).fileBodies = nil }},
			{"resident-object", func(s *StateSession) {
				s.store.(*memoryStore).objects = map[string]stored{"immutable": {Body: []byte{1}, bodyPath: "unused"}}
			}},
			{"active-work", func(s *StateSession) { s.root.Generated.Attempts = 1 }},
			{"graph", func(s *StateSession) { s.root.Generated.Graphs.Count = 1 }},
			{"declaration", func(s *StateSession) {
				s.root.Generated.Slices.Count = 1
				s.generatedSliceLocations = []contract.GeneratorSliceLocation{{ContentKind: contract.GeneratorContentDeclaration, Length: 1}}
			}},
			{"schema", func(s *StateSession) { s.root.OutputConfiguration.Schema = 3 }},
			{"descriptor", func(s *StateSession) { s.root.OutputConfiguration.TotalLength = 36<<20 + 1 }},
			{"opaque-body", func(s *StateSession) { s.support[0].Records[0].Body = []byte{1} }},
			{"opaque-cache", func(s *StateSession) { s.cache = map[format.Ref][]byte{ref: {1}} }},
			{"support-proof", func(s *StateSession) { s.supportFacts = nil }},
			{"too-many-slices", func(s *StateSession) { s.root.Generated.Slices.Count = 129 }},
		} {
			t.Run(damage.name, func(t *testing.T) {
				s := fresh()
				damage.change(s)
				if _, err := maximumOutputOwnedUpper(proof, s, nil); err == nil {
					t.Fatal("unsupported fixture shape accepted")
				}
			})
		}
	})
	t.Run("arithmetic", func(t *testing.T) {
		for _, row := range []struct {
			values   []uint64
			want     uint64
			overflow bool
		}{
			{nil, 0, false}, {[]uint64{17, 23, 5, 7, 11}, 63, false},
			{[]uint64{^uint64(0), 1}, 0, true}, {[]uint64{^uint64(0) - 1, 1}, ^uint64(0), false},
		} {
			got, err := checkedOutputMemorySum(row.values...)
			if got != row.want || (err != nil) != row.overflow {
				t.Fatal("independent checked sum", got, err, row)
			}
		}
		// Transfer 40 bytes from free heap to GC work buffers. The mapped
		// arena stays 125, but omitting GCSys incorrectly lowers 120 to 80.
		before, beforeErr := ordinaryOutputArenaUpper(memorySample{GoHeapSys: 100, GoStackInuse: 20, GoGCSys: 5})
		after, afterErr := ordinaryOutputArenaUpper(memorySample{GoHeapSys: 60, GoStackInuse: 20, GoGCSys: 45})
		if beforeErr != nil || afterErr != nil || before != 125 || after != 125 {
			t.Fatal("GC work-buffer transfer bound", before, after)
		}
	})
	t.Run("segments", func(t *testing.T) {
		segments := []macho.SegmentHeader{
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__PAGEZERO", Memsz: 1 << 32},
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__TEXT", Addr: 1 << 32, Memsz: 4096, Filesz: 2048, Maxprot: 7, Prot: 5},
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__DATA", Addr: 1<<32 + 4096, Memsz: 12288, Offset: 2048, Filesz: 1024, Maxprot: 3, Prot: 3},
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__LINKEDIT", Addr: 1<<32 + 16384, Memsz: 4096, Offset: 3072, Filesz: 1024, Maxprot: 1, Prot: 1},
		}
		if got, err := ordinaryOutputSegmentUpper(segments, 4096, 4096); err != nil || got != 20480 {
			t.Fatal("text/bss/read-only envelope", got, err)
		}
		for _, damage := range []func([]macho.SegmentHeader){
			func(v []macho.SegmentHeader) { v[0].Prot, v[0].Maxprot = 1, 1 },
			func(v []macho.SegmentHeader) { v[1].Prot = 0 },
			func(v []macho.SegmentHeader) { v[1].Cmd = macho.LoadCmdSegment },
			func(v []macho.SegmentHeader) { v[2].Filesz = 4097 },
			func(v []macho.SegmentHeader) { v[2].Addr = ^uint64(0) - 4096 },
			func(v []macho.SegmentHeader) { v[1].Addr, v[1].Memsz = 1, ^uint64(0)-1 },
			func(v []macho.SegmentHeader) { v[2].Name = "__TEXT" },
		} {
			changed := slices.Clone(segments)
			damage(changed)
			if _, err := ordinaryOutputSegmentUpper(changed, 4096, 4096); err == nil {
				t.Fatal("unsupported segment shape passed", changed)
			}
		}
	})
	t.Run("file-only-debug", func(t *testing.T) {
		segments := []macho.SegmentHeader{
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__PAGEZERO", Memsz: 1 << 32},
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__TEXT", Addr: 1 << 32, Memsz: 4096, Filesz: 4096, Maxprot: 7, Prot: 5},
			{Cmd: macho.LoadCmdSegment64, Len: 152, Name: "__DWARF", Addr: 1<<32 + 4096, Offset: 4096, Filesz: 4096, Nsect: 1},
		}
		for _, address := range []uint64{0, 1<<32 + 4096} {
			for maxprot := uint32(0); maxprot <= 7; maxprot++ {
				changed := slices.Clone(segments)
				changed[2].Addr, changed[2].Maxprot = address, maxprot
				if got, err := ordinaryOutputSegmentUpper(changed, 8192, 4096); err != nil || got != 4096 {
					t.Fatal("internal/external linker file-only debug image", address, maxprot, got, err)
				}
			}
		}
		for _, damage := range []struct {
			name   string
			change func([]macho.SegmentHeader)
		}{
			{"unknown-name", func(v []macho.SegmentHeader) { v[2].Name = "__OTHER" }},
			{"mapped-debug", func(v []macho.SegmentHeader) { v[2].Memsz, v[2].Prot, v[2].Maxprot = 4096, 1, 1 }},
			{"initial-protection", func(v []macho.SegmentHeader) { v[2].Maxprot, v[2].Prot = 7, 1 }},
			{"maximum-protection", func(v []macho.SegmentHeader) { v[2].Maxprot = 8 }},
			{"flags", func(v []macho.SegmentHeader) { v[2].Flag = 1 }},
			{"empty-file", func(v []macho.SegmentHeader) { v[2].Filesz = 0 }},
			{"no-sections", func(v []macho.SegmentHeader) { v[2].Nsect, v[2].Len = 0, 72 }},
			{"section-envelope", func(v []macho.SegmentHeader) { v[2].Len = 72 }},
			{"file-offset", func(v []macho.SegmentHeader) { v[2].Offset = 8193 }},
			{"file-end", func(v []macho.SegmentHeader) { v[2].Filesz = 4097 }},
			{"file-end-overflow", func(v []macho.SegmentHeader) { v[2].Offset, v[2].Filesz = ^uint64(0), 1 }},
			{"duplicate-debug", func(v []macho.SegmentHeader) { v[1] = v[2] }},
			{"missing-text", func(v []macho.SegmentHeader) { v[1].Name = "__DATA" }},
		} {
			t.Run(damage.name, func(t *testing.T) {
				changed := slices.Clone(segments)
				damage.change(changed)
				if _, err := ordinaryOutputSegmentUpper(changed, 8192, 4096); err == nil {
					t.Fatal("unsupported file-only image passed", changed)
				}
			})
		}
	})
	t.Run("mapped-pages", func(t *testing.T) {
		const base = 1 << 32
		for _, row := range []struct {
			name                      string
			address, size, page, want uint64
			refuse                    bool
		}{
			{"aligned", base, 4096, 4096, 4096, false},
			{"partial-end", base, 4097, 4096, 8192, false},
			{"partial-start", base + 1, 4095, 4096, 4096, false},
			{"partial-start-and-end", base + 1, 4096, 4096, 8192, false},
			{"native-page", base, 16385, 16384, 32768, false},
			{"page-aligned-slide", base + 11*16384, 16385, 16384, 32768, false},
			{"address-overflow", ^uint64(0) - 4095, 4096, 4096, 0, true},
			{"round-up-overflow", ^uint64(0) - 4095, 1, 4096, 0, true},
			{"zero-page", base, 4096, 0, 0, true},
			{"non-power-two-page", base, 4096, 4095, 0, true},
		} {
			t.Run(row.name, func(t *testing.T) {
				segments := []macho.SegmentHeader{
					{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__PAGEZERO", Memsz: base},
					{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__TEXT", Addr: row.address, Memsz: row.size, Maxprot: 7, Prot: 5},
				}
				got, err := ordinaryOutputSegmentUpper(segments, 0, row.page)
				if got != row.want || (err != nil) != row.refuse {
					t.Fatal("independent mapped-page envelope", got, err, row)
				}
			})
		}
	})

	t.Run("mapped-sum-overflow", func(t *testing.T) {
		segments := []macho.SegmentHeader{
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__PAGEZERO", Memsz: 1 << 32},
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__TEXT", Addr: 4096, Memsz: 1 << 63, Maxprot: 7, Prot: 5},
			{Cmd: macho.LoadCmdSegment64, Len: 72, Name: "__DATA", Addr: 4096, Memsz: 1 << 63, Maxprot: 3, Prot: 3},
		}
		if _, err := ordinaryOutputSegmentUpper(segments, 0, 4096); err == nil {
			t.Fatal("overflow in conservative mapped interval sum passed", segments)
		}
	})

	t.Run("eligibility", func(t *testing.T) {
		build := &debug.BuildInfo{GoVersion: "go1.27.3", Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "darwin"}, {Key: "GOARCH", Value: "arm64"}, {Key: "-race", Value: "true"},
			{Key: "-compiler", Value: "gc"}, {Key: "-buildmode", Value: "exe"}, {Key: "CGO_ENABLED", Value: "1"},
			{Key: "DefaultGODEBUG", Value: "efence=1"},
		}}
		t.Run("non-race", func(t *testing.T) {
			changed := *build
			changed.Settings = slices.DeleteFunc(slices.Clone(build.Settings), func(setting debug.BuildSetting) bool {
				return setting.Key == "-race"
			})
			if err := ordinaryOutputEligibility("go1.27.3", "darwin", "arm64", "efence=0", &changed); err != nil {
				t.Fatal("supported non-race build with omitted race setting", err)
			}
		})
		for _, env := range []string{"efence=0", "efence=1,efence=0"} {
			if err := ordinaryOutputEligibility("go1.27.3", "darwin", "arm64", env, build); err != nil {
				t.Fatal("effective zero", err)
			}
		}
		for _, env := range []string{"", "efence=1", "efence=0,efence=1", "efence=unknown"} {
			if err := ordinaryOutputEligibility("go1.27.3", "darwin", "arm64", env, build); err == nil {
				t.Fatal("unsupported effective efence", env)
			}
		}
		for _, test := range []struct {
			defaults, environment string
			refuse                bool
		}{
			{"sbrk=1", "", true},
			{"", "", false}, {"sbrk=0", "", false}, {"", "sbrk=0", false},
			{"sbrk=1", "sbrk=0", false}, {"sbrk=0", "sbrk=1", true},
			{"sbrk=1,sbrk=0", "", false}, {"sbrk=0,sbrk=1", "", true},
			{"", "sbrk=1,sbrk=0", false}, {"", "sbrk=0,sbrk=1", true},
			{"sbrk=unknown", "", true}, {"", "sbrk=unknown", true},
			{"", "sbrk=", true}, {"", "sbrk=-1", true},
		} {
			changed := *build
			changed.Settings = append(slices.Clone(build.Settings), debug.BuildSetting{Key: "DefaultGODEBUG", Value: "efence=0," + test.defaults})
			err := ordinaryOutputEligibility("go1.27.3", "darwin", "arm64", test.environment, &changed)
			if (err != nil) != test.refuse {
				t.Fatalf("effective sbrk eligibility defaults=%q environment=%q refuse=%t: %v", test.defaults, test.environment, test.refuse, err)
			}
		}
		for _, tuple := range [][3]string{{"go1.27.0", "darwin", "arm64"}, {"go1.27.3", "linux", "arm64"}, {"go1.27.3", "darwin", "amd64"}} {
			if err := ordinaryOutputEligibility(tuple[0], tuple[1], tuple[2], "efence=0", build); err == nil {
				t.Fatal("unsupported tuple", tuple)
			}
		}
		for _, setting := range []debug.BuildSetting{
			{Key: "-race", Value: "false"}, {Key: "-race", Value: ""}, {Key: "-race", Value: "unknown"},
			{Key: "CGO_ENABLED", Value: "0"}, {Key: "-compiler", Value: "gccgo"},
			{Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"},
			{Key: "-asan", Value: "true"}, {Key: "-msan", Value: "true"},
			{Key: "-buildmode", Value: "plugin"}, {Key: "GOEXPERIMENT", Value: "arenas"},
		} {
			changed := *build
			changed.Settings = slices.Clone(build.Settings)
			if i := slices.IndexFunc(changed.Settings, func(existing debug.BuildSetting) bool { return existing.Key == setting.Key }); i >= 0 {
				changed.Settings[i] = setting
			} else {
				changed.Settings = append(changed.Settings, setting)
			}
			if err := ordinaryOutputEligibility("go1.27.3", "darwin", "arm64", "efence=0", &changed); err == nil {
				t.Fatal("unsupported build", setting)
			}
		}
	})
}

// full_only: false
func TestRetainedByteCapacitySharedBacking(t *testing.T) {
	backing := make([]byte, 64)
	separate := make([]byte, 17)
	var buffers byteBuffers
	// Different starting addresses and restricted capacities must not double count.
	for _, b := range [][]byte{backing[8:16:32], backing[:0], backing[24:48], separate, separate[:0]} {
		buffers.add(b)
	}
	if got, want := buffers.capacity(), uint64(cap(backing)+cap(separate)); got != want {
		t.Fatalf("shared byte capacity = %d, want %d", got, want)
	}
	runtime.KeepAlive(backing)
	runtime.KeepAlive(separate)
}

// full_only: false
func TestRetainedByteCapacitySelectionAcceptances(t *testing.T) {
	first, second, separate := make([]byte, 71), make([]byte, 73), make([]byte, 79)
	head := format.Head{Succession: &format.SuccessionProof{Acceptances: []format.SelectionAcceptanceProof{
		{Signature: first}, {Signature: second}, {Signature: first[8:16:32]},
	}}}
	state := &StateSession{head: head}
	candidate := &Candidate{head: head}
	observation := &StateSession{head: format.Head{Succession: &format.SuccessionProof{Acceptances: []format.SelectionAcceptanceProof{
		{Signature: second[:0]}, {Signature: separate},
	}}}}
	if got, want := retainedByteCapacity(state, nil, candidate, observation), uint64(71+73+79); got != want {
		t.Fatalf("acceptance signature backing union = %d, want %d", got, want)
	}
}

// full_only: false
func TestRetainedByteCapacityObservationBasis(t *testing.T) {
	// These owners exercise byte accounting only; they carry no authenticated state.
	for _, length := range []int{1, 0} {
		t.Run(fmt.Sprintf("separate_backing_length_%d", length), func(t *testing.T) {
			witness := PublicBasis{
				SigningAnchor:      make([]byte, length, 19),
				StoreConfiguration: make([]byte, length, 23),
				HEAD:               make([]byte, length, 29),
				Root:               make([]byte, length, 31),
				RecipientPages:     make([][]byte, 32),
			}
			for i := range witness.RecipientPages {
				witness.RecipientPages[i] = make([]byte, length, 37+i)
			}
			control := contract.ControlCore{
				CurrentControl: contract.CurrentControl{
					NormalSigning: contract.PublicSigningBinding{SPKI: make([]byte, length, 79)},
					Recovery: &contract.RecoveryBindings{
						Signing: contract.PublicSigningBinding{SPKI: make([]byte, length, 83)},
						KMS:     contract.KMSBinding{SPKI: make([]byte, length, 89)},
					},
				},
				AuthorityKMSBinding: contract.KMSBinding{SPKI: make([]byte, length, 97)},
			}
			state := &StateSession{admission: openAdmission{
				publicKey:   control.NormalSigning.SPKI,
				observation: &readerPublicBasis{control: control, observation: &witness},
			}}
			// Four witness fields, 32 page capacities (37 through 68), and four
			// derived keys. The admission public key aliases the normal signing key.
			const want = uint64(19 + 23 + 29 + 31 + 32*(37+68)/2 + 79 + 83 + 89 + 97)
			if got := retainedByteCapacity(state, nil, nil, nil); got != want {
				t.Fatalf("observation byte backing = %d, want %d", got, want)
			}
		})
	}
	t.Run("shared_backing", func(t *testing.T) {
		backing := make([]byte, 128)
		witness := PublicBasis{
			SigningAnchor:      backing[:3:19],
			StoreConfiguration: backing[11:13:31],
			HEAD:               backing[23:27:47],
			Root:               backing[39:42:61],
			RecipientPages:     [][]byte{backing[57:58:89], backing[80:81:128], backing[80:80:128]},
		}
		admission := openAdmission{
			publicKey: backing[7:8:17],
			observation: &readerPublicBasis{
				control:     contract.ControlCore{AuthorityKMSBinding: contract.KMSBinding{SPKI: backing[8:9:21]}},
				observation: &witness,
			},
		}
		state := &StateSession{admission: admission}
		observation := &StateSession{admission: admission}
		candidate := &Candidate{session: state, succession: &successionPreparation{selectionAdmission: &admission}}
		// The witness ranges overlap and together cover all 128 bytes, across
		// both sessions and the candidate's separately visited admission.
		if got := retainedByteCapacity(state, nil, candidate, observation); got != 128 {
			t.Fatalf("shared observation byte backing = %d, want 128", got)
		}
	})
}

// full_only: false
func TestCurrentValuePageOwnedRetention(t *testing.T) {
	f := newFixture(t, 1, false, 4097)
	before := f.session
	slot := before.root.Names[0].Slot
	ref := *before.root.ValueEntryPages[slot/format.PageSlots]
	encoded := f.store.objects[mustKey(t, f.store.desc.Prefix, ref)].Body
	value := before.valueEntry(slot).ValueBytes
	if len(encoded) == 0 || !bytes.Equal(value, make([]byte, 4097)) {
		t.Fatal("cold value or its persisted encoded source differs")
	}
	valueStart, encodedStart := reflect.ValueOf(value).Pointer(), reflect.ValueOf(encoded).Pointer()
	if valueStart < encodedStart+uintptr(cap(encoded)) && encodedStart < valueStart+uintptr(cap(value)) {
		t.Fatal("cold decoded value aliases Store page backing")
	}
	t.Run("cold-page", func(t *testing.T) {
		if len(before.cache[ref]) != 0 {
			t.Fatal("cold authenticated image retains duplicate encoded current value page")
		}
	})
	t.Run("exact-ref-observation", func(t *testing.T) {
		var reads []string
		f.store.readHook = func(key string, result contract.ReadResult) contract.ReadResult {
			reads = append(reads, key)
			return result
		}
		observation, result := before.readCurrent(context.Background())
		if observation == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure ||
			result.ObservedRevision != before.head.Core.Revision || !bytes.Equal(observation.valueEntry(slot).ValueBytes, make([]byte, 4097)) {
			t.Fatal("exact-ref observation changed authenticated selection", result)
		}
		if slices.Contains(reads, mustKey(t, f.store.desc.Prefix, ref)) {
			t.Fatal("exact-ref observation fetched the unchanged current value page")
		}
		if len(observation.cache[ref]) != 0 {
			t.Error("observation retains duplicate encoded current value page")
		}
		observedValue := observation.valueEntry(slot).ValueBytes
		if observation.pages[slot/format.PageSlots] != before.pages[slot/format.PageSlots] {
			t.Error("exact-ref observation duplicates immutable owned typed page")
		}
		var buffers byteBuffers
		buffers.add(value)
		buffers.add(observedValue)
		if got := buffers.capacity(); got != 4097 {
			t.Errorf("exact-ref payload backing union = %d, want 4097", got)
		}
		runtime.KeepAlive(observation)
	})
	runtime.KeepAlive(before)
	runtime.KeepAlive(encoded)
}

// full_only: false
func TestCurrentValuePageReuseRequiresCompleteReference(t *testing.T) {
	f := newFixture(t, 1, false, 4097)
	before := f.session
	slot := before.root.Names[0].Slot
	index := slot / format.PageSlots
	ref := *before.root.ValueEntryPages[index]
	key := mustKey(t, f.store.desc.Prefix, ref)
	for _, field := range []string{"kind", "format", "domain", "object", "digest", "length", "index", "absent-reference", "absent-page"} {
		t.Run(field, func(t *testing.T) {
			// Change only the predecessor's reuse basis. The real selected HEAD
			// and Store page remain valid and must be read and owned afresh.
			source := *before
			previous := ref
			source.root.ValueEntryPages[index] = &previous
			switch field {
			case "kind":
				previous.Kind = format.RecipientKind
			case "format":
				previous.Format++
			case "domain":
				previous.Domain = testID("different predecessor domain")
			case "object":
				previous.Object = testID("different predecessor object")
			case "digest":
				previous.Digest = testID("different predecessor digest")
			case "length":
				previous.Length++
			case "index":
				previous.Index++
			case "absent-reference":
				source.root.ValueEntryPages[index] = nil
			case "absent-page":
				source.pages[index] = nil
			}
			pageReads := 0
			f.store.readHook = func(readKey string, result contract.ReadResult) contract.ReadResult {
				if readKey == key {
					pageReads++
				}
				return result
			}
			observation, result := source.readCurrent(context.Background())
			if observation == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure || pageReads != 1 ||
				!bytes.Equal(observation.valueEntry(slot).ValueBytes, make([]byte, 4097)) {
				t.Fatal("different reuse basis did not read and authenticate selected page", result, pageReads)
			}
			var buffers byteBuffers
			buffers.add(before.valueEntry(slot).ValueBytes)
			buffers.add(observation.valueEntry(slot).ValueBytes)
			if got := buffers.capacity(); got != 2*4097 || observation.pages[index] == before.pages[index] {
				t.Fatal("different reuse basis borrowed predecessor payload backing", got)
			}
			if len(observation.cache[ref]) != 0 {
				t.Fatal("changed page retained redundant encoded backing")
			}
			runtime.KeepAlive(observation)
		})
	}
	runtime.KeepAlive(before)
}

// full_only: false
func TestCurrentValuePageChangedSelectionRefusesDamagedEvidence(t *testing.T) {
	for _, fault := range []string{"valid", "missing", "digest", "length", "page-object", "relation", "unchanged-page-relation"} {
		t.Run(fault, func(t *testing.T) {
			f := newFixture(t, 2, false, 4097)
			before := f.session
			state := fixtureStateImage(t, f)
			if fault == "unchanged-page-relation" {
				state.Root.Names[0].Slot, state.Root.Names[1].Slot = state.Root.Names[1].Slot, state.Root.Names[0].Slot
				storeContractRoot(t, f, state.Root, state.entryInputs())
			} else {
				state.Pages[0].Object = testID("new selected value page/" + fault)
				if fault == "relation" {
					state.Pages[0].Slots[0].Recipients[0] = testID("unregistered recipient")
				}
				storeContractClosure(t, f, state)
			}
			selectedHead, result := before.readAuthenticatedHead(context.Background())
			if result.Outcome != 0 {
				t.Fatal("signed test selection", result)
			}
			rootBody := f.store.objects[mustKey(t, f.store.desc.Prefix, selectedHead.head.Core.Root)].Body
			root, err := format.DecodeRoot(rootBody)
			if err != nil {
				t.Fatal(err)
			}
			ref := *root.ValueEntryPages[0]
			key := mustKey(t, f.store.desc.Prefix, ref)
			if fault == "page-object" {
				body := f.store.objects[key].Body
				ref.Object = testID("incorrect selected page identity")
				root.ValueEntryPages[0] = &ref
				key = mustKey(t, f.store.desc.Prefix, ref)
				f.store.put(key, body)
				storeContractRoot(t, f, root, state.entryInputs())
			}
			pageReads := 0
			f.store.readHook = func(readKey string, read contract.ReadResult) contract.ReadResult {
				if readKey == key {
					pageReads++
					switch fault {
					case "missing":
						return contract.ReadResult{Status: contract.ReadMissing}
					case "digest":
						read.Body = bytes.Clone(read.Body)
						read.Body[len(read.Body)-1] ^= 1
					case "length":
						read.Body = read.Body[:len(read.Body)-1]
					}
				}
				return read
			}
			observation, result := before.readCurrent(context.Background())
			wantReads := 1
			if fault == "unchanged-page-relation" {
				wantReads = 0
			}
			if pageReads != wantReads {
				t.Fatal("selected value page fetch count", pageReads, wantReads)
			}
			if fault == "valid" {
				if observation == nil || result.Outcome != ObservedCurrent || result.Evidence != AuthenticatedClosure ||
					!reflect.DeepEqual(observation.pages[0].Slots, before.pages[0].Slots) {
					t.Fatal("fresh selected Ref changed value facts", result)
				}
				var buffers byteBuffers
				buffers.add(before.pages[0].Slots[0].ValueBytes)
				buffers.add(observation.pages[0].Slots[0].ValueBytes)
				if got := buffers.capacity(); got != 2*4097 || observation.pages[0] == before.pages[0] {
					t.Fatal("fresh selected Ref borrowed predecessor payload", got)
				}
				encoded := f.store.objects[key].Body
				var decodedAndEncoded byteBuffers
				decodedAndEncoded.add(observation.pages[0].Slots[0].ValueBytes)
				decodedAndEncoded.add(encoded)
				if len(encoded) == 0 || decodedAndEncoded.capacity() != uint64(4097+cap(encoded)) {
					t.Fatal("fresh selected Ref borrowed Store encoded page backing")
				}
				runtime.KeepAlive(observation)
				runtime.KeepAlive(encoded)
			} else {
				want := Result{Outcome: IntegrityFailure, Reason: InvalidReference}
				switch fault {
				case "missing":
					want = Result{Outcome: EvidenceUnavailable, Reason: MissingSelectedObject}
				case "relation", "unchanged-page-relation":
					want.Reason = InvalidRelation
				}
				if observation != nil || result != want {
					t.Fatal("damaged changed selection used predecessor facts", result, want)
				}
			}
			runtime.KeepAlive(before)
		})
	}
}

// full_only: false
func TestCurrentValuePageSharedObservationsKeepPriorUpdateFacts(t *testing.T) {
	f := newFixture(t, 17, false, 4097)
	before := f.session
	observation, result := before.readCurrent(context.Background())
	if observation == nil || result.Outcome != ObservedCurrent || observation.pages[0] != before.pages[0] || observation.pages[1] != before.pages[1] {
		t.Fatal("original observations do not share selected immutable pages", result)
	}
	prior := fixtureStateImage(t, f)
	candidate := prepare(t, f, changed(t, before, 0))
	selected, result := before.selectCandidate(context.Background(), candidate)
	if selected == nil || result.Outcome != ObservedCurrent || result.ObservedRevision != candidate.head.Core.Revision {
		t.Fatal("ordinary update selection", result)
	}
	assertStateImage(t, before, prior)
	assertStateImage(t, observation, prior)
	for i, name := range selected.root.Names {
		want := bytes.Repeat([]byte{byte(i)}, 4097)
		if i == 0 {
			want = append(want, 99)
		}
		if !bytes.Equal(selected.valueEntry(name.Slot).ValueBytes, want) {
			t.Fatal("ordinary update changed another value", i)
		}
	}
	if selected.pages[0] == before.pages[0] || selected.pages[1] != before.pages[1] {
		t.Fatal("ordinary update did not copy only the touched shared page")
	}
}

// full_only: false
func TestGeneratedByteCapacityIncludesPreparationOwners(t *testing.T) {
	owned := make([][]byte, 26)
	var want uint64
	for i := range owned {
		owned[i] = make([]byte, 11+2*i)
		want += uint64(cap(owned[i]))
	}
	before := &StateSession{body: owned[0]}
	next := &StateSession{body: owned[1], support: []format.RequiredSupportPageView{{Records: []contract.SupportRecordView{{Body: owned[2]}}}}}
	next.pages[0] = &format.ValueEntryPage{}
	next.pages[0].Slots[0] = &contract.ValueEntry{ValueBytes: owned[3]}
	next.access[0] = &format.AccessPage{Records: []contract.AccessRecord{{Wraps: []contract.WrapRow{{RSACiphertext: owned[4]}}}}}
	next.recipients[0] = &format.RecipientPage{}
	next.recipients[0].Slots[0] = &contract.RecipientRecord{CurrentBinding: &contract.KMSBinding{SPKI: owned[5]}}
	next.root.CurrentAccess.Core.NormalSigning.SPKI = owned[6]
	next.cache = map[format.Ref][]byte{{}: owned[7]}
	candidate := &Candidate{session: before, body: owned[8], head: format.Head{K1: owned[9]}, objects: []objectImage{{body: owned[10]}, {body: owned[2]}}}
	candidate.producer = &generatedPreparation{
		reservation: &generatedReservation{state: next, candidate: candidate},
		operation: &cryptoOperation{
			bindings:     []contract.BindingTableRow{{Binding: contract.KMSBinding{SPKI: owned[11]}}},
			accessSource: &contract.BindingTableRow{Binding: contract.KMSBinding{SPKI: owned[12]}},
		},
		resultWrites: []generatedResultWrite{{body: owned[13]}, {body: owned[2]}},
	}
	candidate.generated = &generatedCandidateFacts{reservation: candidate.producer.reservation}
	recovery := &contract.RecoveryBindings{Signing: contract.PublicSigningBinding{SPKI: owned[23]}, KMS: contract.KMSBinding{SPKI: owned[24]}}
	comparison := &Comparison{
		desiredEntries:       []ApplyEntryInput{{InputBytes: owned[25]}},
		normalSupportObjects: []objectImage{{body: owned[16]}, {body: owned[2]}},
		preparedRows:         []contract.CryptoPreparedSecret{{EntryBytes: owned[17], AccessRecord: owned[18]}},
		operation: &cryptoOperation{
			bindings:     []contract.BindingTableRow{{Binding: contract.KMSBinding{SPKI: owned[14]}}},
			accessSource: &contract.BindingTableRow{Binding: contract.KMSBinding{SPKI: owned[15]}},
		},
		support: &contract.GeneratedSupportTransition{
			Records:          []contract.SupportRecord{{Body: owned[19]}},
			AccessRecords:    []contract.AccessRecord{{Wraps: []contract.WrapRow{{RSACiphertext: owned[20]}}}},
			CurrentGenerated: []contract.GeneratedSupportCurrent{{EntryBytes: owned[21]}},
			BeforeAccess: contract.CurrentAccessCore{CurrentControl: contract.CurrentControl{
				NormalSigning: contract.PublicSigningBinding{SPKI: owned[22]}, Recovery: recovery,
			}},
		},
	}
	for _, explicit := range []bool{false, true} {
		var s, observation *StateSession
		if explicit {
			s, observation = before, next
		}
		if got := retainedByteCapacity(s, comparison, candidate, observation); got != want {
			t.Fatalf("generated backing union (explicit states %v) = %d, want %d", explicit, got, want)
		}
	}
	runtime.KeepAlive(owned)
	runtime.KeepAlive(comparison)
	runtime.KeepAlive(candidate)
}

// full_only: false
func TestGeneratedByteCapacityIncludesValidatedSelectedFacts(t *testing.T) {
	owned := make([][]byte, 8)
	var want uint64
	for i := range owned {
		owned[i] = make([]byte, 13+2*i)
		want += uint64(cap(owned[i]))
	}
	key := generatedRecordKey{kind: contract.OperationMaterialSupportKind, id: generatedVectorID(1)}
	contentKey := generatedVectorID(2)
	vectorKey := generatedVectorKey{ownerKind: 9, owner: generatedVectorID(3), kind: contract.GeneratorVectorFacts,
		vector: contract.GeneratorDescriptor{Digest: generatedVectorID(4), Length: uint64(len(owned[2])), Count: 1}}
	material := materialIdentity{kind: contract.ValueMaterialKind, id: generatedVectorID(5)}
	selection := &generatedSelection{
		records: map[generatedRecordKey]contract.SupportRecord{key: {Body: owned[0]}},
		content: &generatedContent{fragments: map[contract.ID][]contract.GeneratedFragmentView{
			contentKey: {{Payload: owned[1]}},
		}},
		vectors: generatedVectorSet{entries: map[generatedVectorKey]generatedVector{
			vectorKey: {rows: [][]byte{owned[2]}},
		}},
		attempts:  map[contract.ID]generatedAttempt{generatedVectorID(6): {result: owned[3]}},
		protected: map[contract.ID][]byte{generatedVectorID(7): owned[4]},
		canonical: map[contract.ID]generatedCanonical{generatedVectorID(8): {
			record:  contract.RetainedCanonicalRecord{Entry: contract.ValueEntry{ValueBytes: owned[5]}},
			payload: contract.CanonicalPayload{Ciphertext: owned[6]},
			access:  contract.AccessRecord{MaterialKind: material.kind, MaterialID: material.id, Wraps: []contract.WrapRow{{RSACiphertext: owned[7]}}},
		}},
	}
	s := &StateSession{generatedWork: &validatedGeneratedSelection{session: nil, selection: selection}}
	if got := retainedByteCapacity(s, nil, nil, nil); got != want {
		t.Fatalf("validated selected-fact backing union = %d, want %d", got, want)
	}
	runtime.KeepAlive(owned)
}

// full_only: true
// Maximum-capacity or accumulated-history proof; smaller behavior checks remain in dev.
// exclusive: true
func TestGeneratedMaximumDeclarationReservationMemory(t *testing.T) {
	ctx := context.Background()
	timing := startCapacityTimer(t)
	defer timing.finish()
	env, f, keys := maximumSuccessionMemoryFixture(t)
	timing.next("operation")
	before := f.session
	input := generatedPlanInputFixture(t, before)
	input.context.Expiry = uint64(time.Now().Add(5 * time.Minute).UnixNano())
	names := maximumLifecycleNames("generated-memory")
	sources := make([]contract.GeneratorDeclarationEntry, 384)
	for i := range sources {
		sources[i] = contract.GeneratorDeclarationEntry{Schema: contract.GeneratorDeclarationEntrySchema, Kind: contract.GeneratorDeclarationPlain,
			InputEncoding: contract.InputEncodingRaw, OutputEncoding: contract.OutputEncodingRaw,
			Name: names[i+128], Recipients: []contract.ID{before.admission.recipient}}
	}
	// The independent framing sum is header + entry envelopes + generation
	// metadata + 128 equal intents. The unused remainder is less than 128 bytes.
	const declarationLimit = 32<<20 - 8
	const generatedMetadataBytes = 2 + 8 + 1 + 32 + 32 + 1 + 1 + 4
	const fixedBytes = 70 + 512*(19+256+32) + 128*generatedMetadataBytes
	const intentLength = (declarationLimit - fixedBytes) / 128
	intent := hermeticSizedGeneratorIntent("", 'x', intentLength)
	graph, declaration, _ := generatedEffectPlanForGenerationIntent(t, &input.graph.Request, before.admission.recipient, names[:128], intent, sources...)
	input.graph = graph
	input.requestBindings = generatedFixtureRequestBindings(graph, input.requestBindings[0].Digest)
	var err error
	input.declaration, err = contract.EncodeGeneratorDeclaration(declaration)
	if err != nil || len(input.declaration) != fixedBytes+128*intentLength || declarationLimit-len(input.declaration) >= 128 {
		t.Fatal("maximum declaration framing", len(input.declaration), err)
	}
	memory := startMemoryAccounting()
	prepared, permit := preparePrivateGeneratedReservation(t, env, before, input, nil)
	candidate := prepared.reservation.candidate
	var reservedPages uint32
	for _, group := range permit.plan.capacity.Groups {
		reservedPages += group.MaxPages
	}
	if reservedPages > 256 || candidate.producer != prepared || prepared.reservation.state.root.ValueEntryCount != 512 {
		t.Fatal("maximum reservation lost its capacity or current image", reservedPages)
	}
	var returned []byte
	var recordPlan *generatedRecordPlan
	var recording *generatedPreparation
	sample := func(phase string, observed *StateSession) {
		t.Helper()
		buffers := retainedByteBuffers(before, nil, candidate, observed)
		buffers.add(permit.plan.input.declaration)
		buffers.add(returned)
		if recordPlan != nil {
			buffers.add(recordPlan.result)
		}
		if recording != nil {
			buffers = append(buffers, retainedByteBuffers(nil, nil, recording.reservation.candidate, nil)...)
		}
		memory.sample(phase, before, nil, candidate, observed)
		memory.samples[len(memory.samples)-1].ByteCapacity = buffers.capacity()
	}
	sample("prepared", nil)
	producer, expected := preparePrivateGeneratedProducerValue(t, env, before, prepared, custody.MaximumValue, nil)
	effects := 0
	if !producer.reservation.candidate.bindFirstSend(producer, func(ctx context.Context, authority contract.ID) contract.CryptoResultCode {
		effects++
		var code contract.CryptoResultCode
		returned, _, code = keys.InvokeGeneratedProducer(ctx, producer.operation.context.AdmissionID, producer.producerLocator, authority)
		return code
	}) {
		t.Fatal("maximum producer handoff")
	}
	selected, result := before.selectCandidate(ctx, candidate)
	if selected == nil || result.Outcome != ObservedCurrent || effects != 1 {
		t.Fatal("maximum reservation selection", result)
	}
	sealed, err := contract.InspectGeneratedResultRecord(returned)
	if err != nil || sealed.Payload.ContentLength != 65536 || sealed.Payload.InputEncoding != contract.InputEncodingRaw || sealed.Payload.RetainedLength != 65536 || sealed.Core.AttemptID != expected.Template.AttemptID {
		t.Fatal("maximum returned result", err)
	}
	sample("selected", selected)
	keys.RetireGenerated()
	cold, result := Open(ctx, f.admission, env.Store)
	if cold == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum reservation cold selection", result)
	}
	g, err := cold.selectedGeneratedWork(context.Background())
	if err != nil || g.parent == nil || g.parent.LineageCount != 128 || g.parent.ValueEntryPlanCount != 512 || len(g.attempts) != 128 {
		t.Fatal("maximum reservation changed its exact planned work", err)
	}
	if !reflect.DeepEqual(cold.pages, before.pages) || cold.root.MembershipCount != 4096 || cold.root.RawBytes != 8<<20 || cold.root.RecipientCount != 256 {
		t.Fatal("reservation changed maximum current values or membership")
	}
	sample("cold-observation", cold)
	admitted := generatedPlanInputFixture(t, cold).context
	admitted.AdmissionID, admitted.SessionID = testID("maximum generated record admission"), testID("maximum generated record session")
	recordPlan, err = cold.generatedRecordRequest(context.Background(), expected.Template.AttemptID, returned, admitted)
	if err != nil {
		t.Fatal("maximum record admission", err)
	}
	recording = preparePrivateGeneratedRecord(t, env, cold, recordPlan)
	sample("record-prepared", cold)
	recorded, result := cold.selectCandidate(ctx, recording.reservation.candidate)
	if recorded == nil || result.Outcome != ObservedCurrent || recorded.root.ChildCount > reservedPages {
		t.Fatal("maximum record selection exceeded its reservation", result)
	}
	sample("record-selected", recorded)
	keys.RetireGenerated()
	recorded = nil
	reopened, result := Open(ctx, f.admission, env.Store)
	if reopened == nil || result.Outcome != ObservedCurrent {
		t.Fatal("maximum record cold selection", result)
	}
	g, err = reopened.selectedGeneratedWork(context.Background())
	if err != nil {
		t.Fatal("maximum record selected work", err)
	}
	frontier := g.attempts[g.phase.FrontierAttemptID]
	if len(g.attempts) != 128 || g.phase.FrontierAttemptID == expected.Template.AttemptID ||
		!bytes.Equal(g.attempts[expected.Template.AttemptID].result, returned) ||
		frontier.record.State != contract.GeneratedEffectTransmitted || len(frontier.result) != 0 ||
		!reflect.DeepEqual(reopened.pages, before.pages) || effects != 1 {
		t.Fatal("maximum record changed its result, current values or effect count")
	}
	sample("record-cold-observation", reopened)
	for _, sample := range memory.samples {
		parent, child := custody.GeneratorProcessOwnedByteCeilings()
		if sample.ByteCapacity+parent+child > 1664<<20 || sample.GoHeapUpperBound < sample.ByteCapacity {
			t.Fatal("generated owned-buffer bound", sample)
		}
	}
	report, err := json.Marshal(memory.samples)
	if err != nil {
		t.Fatal(err)
	}
	parent, child := custody.GeneratorProcessOwnedByteCeilings()
	t.Logf("generated declaration bytes %d; result bytes %d; reserved pages %d; selected/recorded pages %d/%d; process parent/child fixed bytes %d/%d; memory %s",
		len(input.declaration), len(returned), reservedPages, cold.root.ChildCount, reopened.root.ChildCount, parent, child, report)
	runtime.KeepAlive(permit)
	runtime.KeepAlive(cold)
	runtime.KeepAlive(recordPlan)
	runtime.KeepAlive(recording)
	runtime.KeepAlive(reopened)
}

// full_only: false
func TestRetainedByteCapacityDecoded4097(t *testing.T) {
	memory := startMemoryAccounting()
	f := newFixture(t, 1, false, 4096)
	c := changed(t, f.session, 0)
	candidate := prepare(t, f, c)
	if r := f.session.Select(context.Background(), candidate); r.Outcome != ObservedCurrent {
		t.Fatal(r)
	}
	observation, r := f.session.readCurrent(context.Background())
	if observation == nil || r.ObservedRevision != candidate.head.Core.Revision {
		t.Fatal(r)
	}
	value := observation.valueEntry(observation.root.Names[0].Slot).ValueBytes
	if len(value) != 4097 {
		t.Fatalf("decoded value length = %d, want 4097", len(value))
	}
	// A changed Ref must own decoded bytes independently of the persisted page.
	page := f.session.cache[*observation.root.ValueEntryPages[observation.root.Names[0].Slot/format.PageSlots]]
	if len(page) == 0 {
		t.Fatal("persisted candidate encoded page source is absent")
	}
	valueStart, pageStart := reflect.ValueOf(value).Pointer(), reflect.ValueOf(page).Pointer()
	if valueStart < pageStart+uintptr(cap(page)) && pageStart < valueStart+uintptr(cap(value)) {
		t.Fatal("decoded member value aliases its encoded page")
	}
	fresh := [][]byte{value, observation.body, observation.head.K1, observation.head.AuthorizationSignature, observation.root.CurrentAccess.Core.NormalSigning.SPKI}
	for _, row := range observation.recipient.Slots {
		if row != nil && row.CurrentBinding != nil {
			fresh = append(fresh, row.CurrentBinding.SPKI)
		}
	}
	var expected, lengths uint64
	for _, b := range fresh {
		expected += uint64(cap(b))
		lengths += uint64(len(b))
	}
	before := retainedByteCapacity(f.session, c, candidate, nil)
	after := retainedByteCapacity(f.session, c, candidate, observation)
	if got := after - before; got != expected {
		t.Fatalf("decoded observation adds %d bytes, want actual capacities %d (lengths %d, value capacity %d)", got, expected, lengths, cap(value))
	}
	memory.sample("retained-observation-accounting", f.session, c, candidate, observation)
	if memory.samples[0].GoHeapUpperBound < after {
		t.Fatal("Go heap bound does not cover retained byte capacities")
	}
	t.Logf("4097-byte decoded value capacity: %d; observation capacities: %d; lengths: %d", cap(value), expected, lengths)
}

// full_only: true
// exclusive: true
func TestMaximumReplacementPartialPreparationMemory(t *testing.T) {
	for _, tc := range []struct {
		name, target, fault string
		proof               contract.Reason
		outcome             Outcome
		reason              Reason
	}{
		{"first-large-page-unavailable", "first-large-page", "readback-unavailable", contract.ReasonNone, EvidenceUnavailable, ReadUnavailable},
		{"last-large-page-corrupt", "last-large-page", "readback-different-equal-length", contract.ReasonNone, IntegrityFailure, ImmutableConflict},
		{"root-unavailable", "root", "readback-unavailable", contract.ReasonNone, EvidenceUnavailable, ReadUnavailable},
		{"signing-unavailable", "signing", "", contract.ReasonTransport, EvidenceUnavailable, SigningUnavailable},
		{"signing-refused", "signing", "", contract.ReasonProof, IntegrityFailure, InvalidProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			memory := startMemoryAccounting()
			sizes := make([]int, 512)
			for i := 384; i < len(sizes); i++ {
				sizes[i] = 65536
			}
			env := memoryScenarioEnvironment(t)
			base := newNamedEnvironmentFixture(t, ctx, env, sizes, false, maximumLifecycleNames("before"))
			f := &fixture{store: env.Store.(*memoryStore), trust: env.Trust.(*fixtureTrust), admission: base.admission, session: base.session}
			f.trust.signs = 0
			f.store.reads, f.store.creates, f.store.cas = 0, 0, 0
			before := fixtureStateImage(t, f)
			input := before.entryInputs()
			for i, name := range maximumLifecycleNames("after") {
				input[i].Name = name
			}
			comparison, result := f.session.Compare(context.Background(), input, admitSuppliedComparison(t, f.session, nil, input))
			if comparison == nil {
				t.Fatal(result)
			}
			permit := admit(t, f.session, comparison)
			want := expectedSuccessorImage(t, before, input, observeAllocatedTransitionInputs(permit))
			objects := expectedImmutableObjects(t, before, want)
			created, obsolete := successorObjectCounts(before, want)
			if created != 34 || obsolete != 34 || before.Root.RawBytes != 8<<20 || want.Root.RawBytes != 8<<20 {
				t.Fatal("partial failure fixture does not reach both joint limits")
			}
			var encoded uint64
			targetIndex := -1
			for i, object := range objects {
				encoded += uint64(len(object.body))
				if len(object.body) > 1<<20 && (targetIndex < 0 || tc.target == "last-large-page") {
					targetIndex = i
				}
			}
			// Independent schema-11 field accounting for 512 maximum names,
			// eight MiB of plain values and one retained recipient page.
			// The replacement creates 32 entry pages, the index and Root.
			const valueEntryPageBytes = 32*75 + 512*(154+32+256) + (8 << 20)
			const generatedWithReceipt = 1 + 2*32 + 8*4 + 6*contract.GeneratorDescriptorLength + 2 + 37
			const indexBytes = 115 + 3*(105+1+2+7+37) + 116
			const gcTail = 32 + (32 + 8 + 4) // ActiveGC and GCPlans.
			const rootFixed = 7 + 3*32 + 64 + 33*105 + 105 + 2 + 1 + 2 + 3*105 + 46 + 4 + 512*(4+256+2) + 48 + generatedWithReceipt + gcTail
			const signingFixed = 2 + 1 + 1 + 2 + 32 + 4 + 4 + 32 + 4 + 251
			control := want.Root.CurrentAccess.Core
			if control.Recovery != nil || len(control.AccessPageRefs) != 0 {
				t.Fatal("plain replacement ledger requires disabled recovery and no access pages")
			}
			accessBytes := 4 + 396 + signingFixed + len(control.NormalSigning.KeySelector) + len(control.NormalSigning.SPKI) + 32
			if expected := uint64(valueEntryPageBytes + indexBytes + rootFixed + accessBytes); encoded != expected {
				t.Fatalf("maximum immutable image is %d bytes, want field ledger %d", encoded, expected)
			}
			if tc.target == "root" || tc.target == "signing" {
				targetIndex = len(objects) - 1
			}
			if targetIndex < 0 {
				t.Fatal("maximum-page failure target missing")
			}
			store := &preparationFaultStore{memoryStore: f.store, target: mustKey(t, f.store.desc.Prefix, objects[targetIndex].ref), mode: tc.fault}
			if !slices.Equal(before.Root.RequiredSupport, want.Root.RequiredSupport) || before.Root.OutputConfiguration != want.Root.OutputConfiguration {
				t.Fatal("plain replacement did not retain its exact configuration")
			}
			f.session.store = store
			var trust contract.Trust = f.trust
			var rejected *signResultTrust
			if tc.proof != contract.ReasonNone {
				rejected = &signResultTrust{Trust: f.trust, result: contract.SignResult{Reason: tc.proof}}
				trust = rejected
			}
			memory.sample("before-preparation", f.session, comparison, nil, nil)
			oldCache := make(map[contract.ID]bool)
			for ref := range f.session.cache {
				oldCache[ref.Object] = true
			}
			selected := f.store.objects[f.store.desc.HeadKey]
			reads := f.store.reads
			candidate, result := f.session.Prepare(ctx, comparison, permit, trust)
			wantResult := Result{Outcome: tc.outcome, Reason: tc.reason}
			wantReads := targetIndex + 1
			if tc.fault == "readback-unavailable" {
				wantResult.StoreReason = contract.ReasonTransport
				wantReads += 2
			}
			if candidate != nil || result != wantResult {
				t.Fatalf("Prepare = %+v, candidate present=%v", result, candidate != nil)
			}
			attempted, verified := targetIndex+1, targetIndex
			if tc.target == "signing" {
				attempted, verified = len(objects), len(objects)
			}
			preparationReads := append(processConfigurationReadRequests(t, f.store.desc, before, false), processPlainReceiptIndexReadRequests(t, f.store.desc, want)...)
			for index, expected := range preparationReads {
				event := store.events[index]
				if event.key != expected.Key || event.maximum != expected.Maximum || event.read != contract.ReadOK || event.write != 0 || !bytes.Equal(event.body, f.store.objects[expected.Key].Body) {
					t.Fatal("prospective image authentication changed its exact key, bound, bytes or order")
				}
			}
			if f.store.creates != attempted || f.store.reads-reads-len(preparationReads) != wantReads || f.store.cas != 0 || f.trust.signs != 0 || !permit.used || !f.session.prepared {
				t.Fatalf("partial preparation boundary: image reads=%d creates=%d want=%d readbacks=%d want=%d CAS=%d signs=%d permit-used=%t prepared=%t", len(preparationReads), f.store.creates, attempted, f.store.reads-reads-len(preparationReads), wantReads, f.store.cas, f.trust.signs, permit.used, f.session.prepared)
			}
			if rejected != nil && rejected.calls != 1 {
				t.Fatal("unavailable signing was retried")
			}
			var addedBuffers byteBuffers
			cached := 0
			for ref, body := range f.session.cache {
				if !oldCache[ref.Object] {
					cached++
					addedBuffers.add(body)
				}
			}
			memory.sample("failed-preparation-returned", f.session, comparison, candidate, nil)
			if cached != verified || memory.samples[1].ByteCapacity-memory.samples[0].ByteCapacity != addedBuffers.capacity() {
				t.Fatal("failed preparation retained bytes outside verified immutable readbacks")
			}
			after := f.store.objects[f.store.desc.HeadKey]
			if after.Token != selected.Token || !bytes.Equal(after.Body, selected.Body) {
				t.Fatal("partial preparation changed the selected HEAD")
			}
			observation, result := f.session.readCurrent(ctx)
			if observation == nil || result.ObservedRevision != before.Revision {
				t.Fatal(result)
			}
			assertStateImage(t, observation, before)
			memory.sample("retained-predecessor-observation", f.session, comparison, candidate, observation)
			for _, sample := range memory.samples {
				if sample.ByteCapacity > 77987224 || sample.GoHeapUpperBound < sample.ByteCapacity {
					t.Fatalf("partial preparation exceeds memory ledger: %+v", sample)
				}
			}
			evidence := struct {
				AttemptedObjects, VerifiedObjects                 int
				PossibleSuccessorObjects, PossibleObsoleteObjects uint64
				MaximumCandidateEncodedBytes                      uint64
				Memory                                            []memorySample
			}{attempted, verified, created, obsolete, encoded, memory.samples}
			encodedEvidence, err := json.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("partial preparation accounting: %s", encodedEvidence)
		})
	}
}

// full_only: false
func TestRetainedByteCapacityIncludesReplacementState(t *testing.T) {
	shared, changedWrap, support, cached, target, cachedWrap := make([]byte, 17), make([]byte, 384), make([]byte, 23), make([]byte, 29), make([]byte, 67), make([]byte, 31)
	before := &StateSession{body: shared}
	next := &StateSession{body: shared, support: []format.RequiredSupportPageView{{Records: []contract.SupportRecordView{{Body: support}}}},
		cache: map[format.Ref][]byte{{}: cached}}
	next.access[0] = &format.AccessPage{Records: []contract.AccessRecord{{Wraps: []contract.WrapRow{{RSACiphertext: changedWrap}}}}}
	next.accessFacts = map[format.Ref]*format.AccessPage{{}: {Records: []contract.AccessRecord{{Wraps: []contract.WrapRow{{RSACiphertext: cachedWrap}}}}}}
	next.publicationFacts = map[generatedRecordKey]selectedPublicationRecord{{kind: contract.PublicationCoordinateSupportKind}: {coordinate: &contract.PublicationCoordinate{DeletionTargetData: target, ServiceContractID: "retained-service"}}}
	candidate := &Candidate{session: before, replacementState: next}
	if got, want := retainedByteCapacity(before, nil, candidate, nil), uint64(17+384+23+29+67+31); got != want {
		t.Fatalf("replacement state's byte backing union = %d, want %d", got, want)
	}
	memory := startMemoryAccounting()
	memory.sample("replacement-facts", before, nil, candidate, nil)
	if got, want := memory.samples[0].StringBacking, uint64(len("retained-service")); got != want {
		t.Fatalf("replacement publication string backing = %d, want %d", got, want)
	}
	candidate.replacementState = before
	if got := retainedByteCapacity(before, nil, candidate, before); got != 17 {
		t.Fatalf("aliased replacement state counted more than once: %d", got)
	}
	runtime.KeepAlive(next)
}

// full_only: false
func TestSelectionReleasesPrivateReplacementStateAfterLastConsumer(t *testing.T) {
	for _, condition := range []string{"selected", "cancelled"} {
		t.Run(condition, func(t *testing.T) {
			f := newFixture(t, 1, false, 7)
			before := f.session
			candidate := prepare(t, f, changed(t, before, 0))
			private := *before
			private.access[0] = &format.AccessPage{Records: []contract.AccessRecord{{Wraps: []contract.WrapRow{{RSACiphertext: make([]byte, 384)}}}}}
			candidate.replacementState = &private
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if condition == "cancelled" {
				cancel()
			}
			_, result := before.selectCandidate(ctx, candidate)
			if condition == "selected" && result.Outcome != ObservedCurrent || condition == "cancelled" && result.Outcome != EvidenceUnavailable {
				t.Fatal("selection outcome changed", result)
			}
			if candidate.replacementState != nil {
				t.Error("one-use selection retains private prepared replacement state")
			}
			if before.valueEntry(0) == nil || len(private.access[0].Records[0].Wraps[0].RSACiphertext) != 384 {
				t.Fatal("release mutated reusable predecessor or borrowed private state")
			}
		})
	}
}

// full_only: false
func TestCurrentAccessPageRetainsOwnedFactsWithoutEncodedCache(t *testing.T) {
	ctx := t.Context()
	env := memoryScenarioEnvironment(t)
	run := newScenarioRun(t, ctx, env)
	f := newEnvironmentFixture(t, ctx, run.env, nil, false)
	input := sharingSecretNamed(t, env, "retained-access", "retained-access-source", []contract.ID{f.session.admission.recipient})
	run.suppliedSelection(f, []ApplyEntryInput{input})
	before, result := Open(ctx, f.admission, run.env.Store)
	if before == nil || result.Outcome != ObservedCurrent || len(before.root.CurrentAccess.Core.AccessPageRefs) == 0 {
		t.Fatal("selected access fixture", result)
	}
	ref := before.root.CurrentAccess.Core.AccessPageRefs[0]
	store := env.Store.(*memoryStore)
	key := mustKey(t, store.desc.Prefix, ref)
	encoded, result := before.readObjectUncached(ctx, ref)
	if result != (Result{}) || len(encoded) == 0 {
		t.Fatal("selected encoded access", result)
	}
	if len(before.cache[ref]) != 0 {
		t.Error("complete selected session retains encoded access beside owned RSA facts")
	}
	reads := 0
	store.readHook = func(readKey string, result contract.ReadResult) contract.ReadResult {
		if readKey == key {
			reads++
			return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
		}
		return result
	}
	for _, readCtx := range []context.Context{nil, ctx} {
		body, result := before.readObject(readCtx, ref)
		if result != (Result{}) || !bytes.Equal(body, encoded) || reads != 0 {
			t.Fatal("exact authenticated access read acquired a new Store failure or changed canonical bytes", result, reads)
		}
	}
	observed, result := before.readCurrent(ctx)
	if observed == nil || result.Outcome != ObservedCurrent || reads != 0 || observed.access[ref.Index] != before.access[ref.Index] || len(observed.cache[ref]) != 0 {
		t.Fatal("exact selected access observation did not reuse immutable owned page", result, reads)
	}
	if body, result := before.readObjectUncached(ctx, ref); body != nil || result.Outcome != EvidenceUnavailable || result.StoreReason != contract.ReasonTransport || reads != 3 {
		t.Fatal("explicit uncached access read did not reach Store", result, reads)
	}
	changed := before.root
	changed.CurrentAccess.Core.AccessPageRefs = slices.Clone(changed.CurrentAccess.Core.AccessPageRefs)
	changed.CurrentAccess.Core.AccessPageRefs[0].Digest = testID("different access digest")
	reader := before.selectedObjectReader()
	reader.cache = nil
	if _, result := scanSelectedImage(ctx, reader, changed, false, selectedComplete, before.selectedImage()); result.Outcome == 0 {
		t.Fatal("changed access reference reused authenticated facts for another page")
	}
}

// full_only: false
func TestPrivateReplacementSessionRetainsFactsThroughObservation(t *testing.T) {
	for _, administrative := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "administrative"}[administrative], func(t *testing.T) {
			_, fixture, _, _ := signedPublicationSelectionFixture(t, format.OutputReserveAuth, false)
			original := fixture.session
			privateAdmission := original.admission
			privateAdmission.outputInterpreter = nil
			admission := OpenContext{admission: &privateAdmission}
			opened, result := openReplacementSession(t.Context(), admission, original.store, administrative)
			if opened == nil || result.Outcome != ObservedCurrent || !opened.replacementRead || opened.admission.outputInterpreter != nil || len(opened.publicationFacts) == 0 {
				t.Fatal("private replacement opener lost selected publication facts", result)
			}
			var observed *StateSession
			if administrative {
				observed, result = opened.readAdministrativeImage(t.Context())
			} else {
				observed, result = opened.readCurrentImage(t.Context(), false)
			}
			if observed == nil || result.Outcome != ObservedCurrent || !observed.replacementRead || len(observed.publicationFacts) != len(opened.publicationFacts) {
				t.Fatal("private replacement observation changed lifetime", result)
			}
			if administrative && observed.publicationProof != nil {
				t.Fatal("private administrative observation minted a complete publication proof")
			}
			for i, page := range observed.support {
				for _, row := range page.Records {
					if publicationSupportKind(row.Kind) && (row.Body != nil || observed.cache[observed.root.RequiredSupport[i]] != nil) {
						t.Fatal("private replacement observation retained encoded publication backing")
					}
				}
			}
			if original.replacementRead || len(original.publicationFacts) != 0 {
				t.Fatal("private replacement changed caller-owned reusable session")
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementBorrowsConstructorOwnedBasis(t *testing.T) {
	for _, arm := range []string{"genesis", "successor", "observation"} {
		t.Run(arm, func(t *testing.T) {
			h := newInstalledReplacementFixture(t, contract.GCP, ReplacementTargetAuthority, 1, contract.NormalSigningRole, 0)
			selected := h.fixture.session
			input := h.installation
			if arm == "successor" {
				ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
				defer cancel()
				if result := h.engine(t).Replace(ctx, fixtureID(h.env.Domain, "basis source succession")); result.Result.Outcome != ObservedCurrent {
					t.Fatal("source succession", result.Result)
				}
				input.PublicBasis = h.output.Basis
				admission, result := admitPublicNormal(ctx, h.env.Domain, h.env.Store.Descriptor(), input.PublicBasis, h.env.Store, input.CompositionID, nil)
				if result.Outcome != ObservedCurrent {
					t.Fatal(result)
				}
				selected, result = Open(ctx, admission, h.env.Store)
				if selected == nil {
					t.Fatal(result)
				}
			}
			input.ExpectedControl = currentControlOf(selected)
			if arm == "observation" {
				anchor, err := contract.EncodePublicSigningBinding(input.ExpectedControl.NormalSigning)
				if err != nil {
					t.Fatal(err)
				}
				configuration, err := contract.EncodeStoreConfiguration(h.env.Store.(contract.StoreConfigurationSource).StoreConfiguration())
				if err != nil {
					t.Fatal(err)
				}
				root, err := format.EncodeRoot(selected.root)
				if err != nil {
					t.Fatal(err)
				}
				input.PublicBasis = PublicBasis{SigningAnchor: anchor, StoreConfiguration: configuration, HEAD: bytes.Clone(selected.body), Root: root}
				for _, page := range selected.recipients {
					if page == nil {
						continue
					}
					body, err := format.EncodeRecipientPage(*page)
					if err != nil {
						t.Fatal(err)
					}
					input.PublicBasis.RecipientPages = append(input.PublicBasis.RecipientPages, body)
				}
			}
			owner, err := newInstalledReplacement(input, ReplacementTargetAuthority, h.goal, contract.ID{}, 0)
			if err != nil {
				t.Fatal("owned source constructor", err)
			}
			defer owner.close()
			source := owner.installation.PublicBasis
			original := input.PublicBasis
			inputRows := [][]byte{original.Descriptor, original.Control, original.Selection, original.SigningAnchor, original.StoreConfiguration, original.HEAD, original.Root}
			ownedRows := [][]byte{source.Descriptor, source.Control, source.Selection, source.SigningAnchor, source.StoreConfiguration, source.HEAD, source.Root}
			inputRows = append(inputRows, original.RecipientPages...)
			ownedRows = append(ownedRows, source.RecipientPages...)
			for i, row := range inputRows {
				if len(row) == 0 {
					continue
				}
				if &row[0] == &ownedRows[i][0] {
					t.Fatal("constructor borrowed caller-owned basis")
				}
				row[0] ^= 0x80
				isolated := ownedRows[i][0] != row[0]
				row[0] ^= 0x80
				if !isolated {
					t.Fatal("caller mutation changed constructor-owned basis")
				}
			}
			admission, result := admitReplacementPublicNormal(t.Context(), input.ExpectedDomain, input.ExpectedStore, source, input.Store, input.CompositionID)
			if result.Outcome != ObservedCurrent {
				t.Fatal("owned source admission", result)
			}
			private, result := openReplacementSession(t.Context(), admission, input.Store, false)
			if private == nil || result.Outcome != ObservedCurrent {
				t.Fatal("private source open", result)
			}
			genericAdmission, result := admitBorrowedPublicNormal(t.Context(), input.ExpectedDomain, input.ExpectedStore, source, input.Store, input.CompositionID, nil)
			if result.Outcome != ObservedCurrent {
				t.Fatal("generic source admission", result)
			}
			generic, result := Open(t.Context(), genericAdmission, input.Store)
			if generic == nil || result.Outcome != ObservedCurrent {
				t.Fatal("generic source control", result)
			}
			switch arm {
			case "genesis":
				if &private.admission.descriptor[0] != &source.Descriptor[0] {
					t.Error("private open duplicated its immutable constructor-owned descriptor")
				}
				if &generic.admission.descriptor[0] == &source.Descriptor[0] {
					t.Error("generic open lost its independent descriptor owner")
				}
			case "successor":
				if &private.admission.current.control[0] != &source.Control[0] || &private.admission.current.selection[0] != &source.Selection[0] {
					t.Error("private open duplicated its immutable constructor-owned successor basis")
				}
				if &generic.admission.current.control[0] == &source.Control[0] || &generic.admission.current.selection[0] == &source.Selection[0] {
					t.Error("generic open lost its independent successor owner")
				}
			case "observation":
				if private.admission.observation == nil || &private.admission.observation.observation.Root[0] != &source.Root[0] {
					t.Error("private observation did not share immutable constructor witness")
				}
			}
		})
	}
}

func verifiedReplacementCacheFixture(t *testing.T, path string, private bool) (*StateSession, *Candidate) {
	t.Helper()
	var session *StateSession
	var candidate *Candidate
	if path == "ordinary_persistence" {
		fixture := newFixture(t, 1, false, 7)
		if private {
			opened, result := openReplacementSession(t.Context(), fixture.admission, fixture.store, false)
			if opened == nil {
				t.Fatal("private fixture open", result)
			}
			fixture.session = opened
		}
		session = fixture.session
		candidate = prepare(t, fixture, changed(t, session, 0))
	} else {
		env, _ := genesisEnvironment(t, contract.GCP, true)
		fixture := newEnvironmentFixture(t, t.Context(), env, []int{1}, false)
		session = fixture.session
		if private {
			opened, result := openReplacementSession(t.Context(), fixture.admission, env.Store, false)
			if opened == nil {
				t.Fatal("private succession fixture open", result)
			}
			session = opened
		}
		env = syntheticAuthorityScenarioEnvironment(t, env)
		actors := env.ReplacementActors(t, t.Context(), session, contract.SuccessionReplaceAuthority, contract.SuccessionChangeAuthorityKEK, contract.NormalSigningRole)
		permit := admitAuthorityReplacement(t, session, actors.Keys, actors.After, contract.SuccessionReplaceAuthority, contract.NormalSigningRole, contract.SuccessionChangeAuthorityKEK, actors.Source)
		var result Result
		candidate, result = session.PrepareSuccession(t.Context(), permit, actors.Signers)
		if candidate == nil || result.Outcome != ObservedCurrent {
			t.Fatal("private succession preparation", result)
		}
	}
	return session, candidate
}

// full_only: false
func TestPrivateReplacementVerifiedCacheOwnsExactCapacity(t *testing.T) {
	for _, path := range []string{"ordinary_persistence", "succession_persistence"} {
		for _, private := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/reusable", true: "/private"}[private], func(t *testing.T) {
				session, candidate := verifiedReplacementCacheFixture(t, path, private)
				if len(candidate.objects) == 0 {
					t.Fatal("persisted candidate objects missing")
				}
				for _, object := range candidate.objects {
					if private && object.ref.Kind == contract.AdministrativeIndexKind {
						// Private index reuse is qualified by the complete ordered
						// shard set. The scanner owns that separate contract.
						continue
					}
					body := session.cache[object.ref]
					if !bytes.Equal(body, object.body) || len(body) == 0 || &body[0] == &object.body[0] {
						t.Fatal("verified cache lost independent exact bytes")
					}
					if private && cap(body) != len(body) {
						t.Errorf("private verified cache retains unused backing: kind=%d length=%d capacity=%d", object.ref.Kind, len(body), cap(body))
					}
					want := body[0]
					for _, readContext := range []context.Context{nil, t.Context()} {
						object.body[0] ^= 0x80
						cached, result := session.readObject(readContext, object.ref)
						object.body[0] ^= 0x80
						if result != (Result{}) || len(cached) == 0 || cached[0] != want {
							t.Fatal("cached read acquired new context/Store failure or candidate alias", result)
						}
					}
				}
			})
		}
	}
}

// full_only: false
func TestPrivateReplacementCandidateIndexCacheReusesAuthenticatedTuple(t *testing.T) {
	for _, path := range []string{"ordinary_persistence", "succession_persistence"} {
		for _, private := range []bool{false, true} {
			t.Run(path+map[bool]string{false: "/reusable", true: "/private"}[private], func(t *testing.T) {
				session, candidate := verifiedReplacementCacheFixture(t, path, private)
				previous := session.administrativeIndexFacts
				body := session.cache[candidate.head.Core.Root]
				root, err := format.DecodeRoot(body)
				if err != nil {
					t.Fatal(err)
				}
				refs := append([]format.Ref{root.AdministrativeIndex}, root.AdministrativeIndexShards...)
				if private {
					for _, object := range candidate.objects {
						if slices.Contains(refs, object.ref) && object.body != nil {
							t.Error("private candidate retains its original verified index body")
						}
					}
				}
				store := requireAdmittedMemoryStore(t, session.store)
				keys := make(map[string]bool)
				for _, ref := range refs {
					key := mustKey(t, session.admission.store.Prefix, ref)
					keys[key] = true
					if private && len(session.cache[ref]) != 0 {
						t.Error("private persisted index retains encoded bytes beside an authenticated tuple")
					}
					if !private && len(session.cache[ref]) == 0 {
						t.Fatal("generic persisted index lost whole-byte cache")
					}
					delete(store.objects, key)
				}
				if private {
					if session.cachedAdministrativeIndexFacts == nil || !session.cachedAdministrativeIndexFacts.exact(refs) {
						t.Error("private persisted index has no whole authenticated cached tuple")
					}
					if session.administrativeIndexFacts != previous || previous == nil || previous.exact(refs) {
						t.Fatal("candidate retagged predecessor selected index facts")
					}
					changed := root
					changed.AdministrativeIndex.Digest[0] ^= 0x80
					if _, result := scanSelectedImage(t.Context(), session.selectedObjectReader(), changed, false, selectedComplete, session.selectedImage()); result.Outcome != EvidenceUnavailable || result.Reason != MissingSelectedObject {
						t.Fatal("changed candidate index tuple did not use ordinary read failure", result)
					}
				}
				if candidate.succession != nil {
					_ = deliverSuccessionBasis(t, candidate)
				}
				prior := store.readHook
				indexReads := 0
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					if keys[key] {
						indexReads++
					}
					if prior != nil {
						return prior(key, read)
					}
					return read
				}
				defer func() { store.readHook = prior }()
				observed, result := session.selectCandidate(t.Context(), candidate)
				store.readHook = prior
				if observed == nil || result.Outcome != ObservedCurrent || indexReads != 0 {
					t.Fatal("exact persisted candidate index acquired a new Store dependency", result, indexReads)
				}
				if private && (session.administrativeIndexFacts != previous || observed.administrativeIndexFacts == previous || !observed.administrativeIndexFacts.exact(refs)) {
					t.Fatal("observed candidate did not keep old and new selected index facts separate")
				}
			})
		}
	}
}

// full_only: false
func TestPrivateReplacementReleasesVerifiedIndexBeforeLaterPersistFailure(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(map[bool]string{false: "reusable", true: "private"}[private], func(t *testing.T) {
			session, prepared := verifiedReplacementCacheFixture(t, "ordinary_persistence", private)
			candidate := *prepared
			candidate.objects = slices.Clone(prepared.objects)
			fact := session.cachedAdministrativeIndexFacts
			if private {
				if fact == nil {
					t.Fatal("verified candidate tuple missing")
				}
				pages, err := format.EncodeAdministrativeIndexPages(fact.index)
				if err != nil {
					t.Fatal(err)
				}
				for i := range candidate.objects {
					for _, page := range pages {
						if candidate.objects[i].ref == page.Ref {
							candidate.objects[i].body = page.Body
						}
					}
				}
			}
			store := requireAdmittedMemoryStore(t, session.store)
			rootKey := mustKey(t, session.admission.store.Prefix, candidate.head.Core.Root)
			prior := store.readHook
			defer func() { store.readHook = prior }()
			store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
				if key == rootKey {
					return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
				}
				if prior != nil {
					return prior(key, read)
				}
				return read
			}
			attempt, result := session.persistCandidate(t.Context(), &candidate, nil)
			if attempt != nil || result.Outcome != EvidenceUnavailable || result.Reason != ReadUnavailable {
				t.Fatal("later Root readback did not fail before signing", result)
			}
			indexes := 0
			for _, object := range candidate.objects {
				if object.ref.Kind != contract.AdministrativeIndexKind {
					continue
				}
				indexes++
				cached := session.cache[object.ref]
				if len(cached) == 0 || contract.Hash(cached) != object.ref.Digest {
					t.Fatal("partial persistence lost its verified index cache")
				}
				if private && object.body != nil {
					t.Error("private partial persistence retains original verified index backing")
				}
				if !private && !bytes.Equal(object.body, cached) {
					t.Fatal("reusable partial persistence lost original index bytes")
				}
			}
			if indexes == 0 || session.cachedAdministrativeIndexFacts != fact {
				t.Fatal("partial persistence published a new tuple fact or had no index")
			}
		})
	}
}

// full_only: false
func TestPrivateReplacementCandidateIndexCacheWaitsForVerifiedTuple(t *testing.T) {
	for _, fault := range []string{"root_readback_unavailable", "corrupt_cache_tuple"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newFixture(t, 1, false, 7)
			session, result := openReplacementSession(t.Context(), fixture.admission, fixture.store, false)
			if session == nil {
				t.Fatal("private tuple fixture open", result)
			}
			previous := session.administrativeIndexFacts
			if previous == nil {
				t.Fatal("predecessor index proof missing")
			}
			store := fixture.store
			prior := store.readHook
			defer func() { store.readHook = prior }()
			if fault == "root_readback_unavailable" {
				store.readHook = func(key string, read contract.ReadResult) contract.ReadResult {
					identity, err := contract.ParseStoreObjectKey(session.admission.store.Prefix, session.root.Domain, key)
					if err == nil && identity.Kind == contract.RootKind && identity.ObjectID != session.root.Snapshot {
						return contract.ReadResult{Status: contract.ReadUnavailable, Reason: contract.ReasonTransport}
					}
					if prior != nil {
						return prior(key, read)
					}
					return read
				}
			} else {
				session.store = boundaryStore{Store: store, after: func(method, key string) {
					identity, err := contract.ParseStoreObjectKey(session.admission.store.Prefix, session.root.Domain, key)
					if method != "CREATE" || err != nil || identity.Kind != contract.RootKind || identity.ObjectID == session.root.Snapshot {
						return
					}
					for ref, body := range session.cache {
						if ref.Kind == contract.AdministrativeIndexKind && len(body) != 0 {
							body[0] ^= 0x80
						}
					}
				}}
			}
			comparison := changed(t, session, 0)
			permit := admit(t, session, comparison)
			creates, cas, signs := store.creates, store.cas, fixture.trust.signs
			candidate, result := session.Prepare(t.Context(), comparison, permit, fixture.trust)
			want := failure(EvidenceUnavailable, ReadUnavailable)
			if fault == "corrupt_cache_tuple" {
				want = failure(IntegrityFailure, InvalidRelation)
			}
			if candidate != nil || result.Outcome != want.Outcome || result.Reason != want.Reason {
				t.Fatal("incomplete or corrupt verified tuple produced a candidate", result)
			}
			if session.cachedAdministrativeIndexFacts != nil || session.administrativeIndexFacts != previous {
				t.Fatal("failed tuple construction published or retagged index facts")
			}
			verified := 0
			for ref := range session.cache {
				if ref.Kind == contract.AdministrativeIndexKind {
					verified++
				}
			}
			if verified == 0 || store.creates <= creates || store.cas != cas || fixture.trust.signs != signs {
				t.Fatal("tuple failure did not retain prior verified objects before signing/CAS")
			}
			for _, ref := range previous.refs {
				delete(store.objects, mustKey(t, store.desc.Prefix, ref))
			}
			current, result := session.readCurrentImage(t.Context(), false)
			if current == nil || result.Outcome != ObservedCurrent || current.root.Snapshot != session.root.Snapshot {
				t.Fatal("failed candidate lost predecessor exact index reuse", result)
			}
		})
	}
}
