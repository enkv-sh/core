package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"sync"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// AdmittedParentTransition can only be supplied by the enclosing Core admission
// boundary. Its synthetic parent exists only in test assemblies.
type AdmittedParentTransition struct {
	session                                *StateSession
	comparison                             *Comparison
	predecessorDigest, predecessorRevision contract.ID
	predecessorToken                       contract.Token
	plan                                   transitionPlan
	authority                              lifecycleAuthority
	used                                   bool
}
type transitionPlan struct {
	operation, transition, snapshot, revision contract.ID
	pages                                     [contract.MaxValueEntryPages]contract.ID
	recipientPages                            [contract.MaxRecipientPages]contract.ID
	accessPages                               [contract.MaxChildPages]contract.ID
	supportPages                              [contract.MaxChildPages]contract.ID
	values, incarnations                      map[uint16]contract.ID
	outputBindings                            map[string]contract.ID
}
type authorityContext struct {
	Domain, Store, Trust, Coordinate, NonBody, Interpretation contract.ID
	Epoch                                                     uint64
	PreviousRevision, PreviousDigest                          contract.ID
	PreviousToken                                             contract.Token
	Operation, Transition, Snapshot, Revision, Request        contract.ID
	Recipient, KeyBinding, Fingerprint                        contract.ID
	BindingVersion                                            uint64
	OperationKind                                             uint16
	IdentityPlan                                              contract.DigestLength
	BeforeValueEntryCount, AfterValueEntryCount               uint32
	BeforeSecretCount, AfterSecretCount                       uint16
	BeforeRawBytes, AfterRawBytes                             uint64
	BeforeAccessRoot, AfterAccessRoot                         contract.ID
	BeforeMembershipCount, AfterMembershipCount               uint32
}
type normalAuthorization struct {
	Context authorityContext
	Section contract.NormalSection
}
type grantAuthorization struct {
	Context authorityContext
	Rows    []membershipRow
}
type exclusionAuthorization struct {
	Context     authorityContext
	Rows        []exclusionRow
	Retirements contract.DescriptorVector
}
type lifecycleAuthority struct {
	normal    *normalAuthorization
	grant     *grantAuthorization
	exclusion *exclusionAuthorization
}
type objectImage struct {
	ref  format.Ref
	body []byte
}
type candidateFirstSend struct {
	mu      sync.Mutex
	handoff func(context.Context, contract.ID) contract.CryptoResultCode
}

func (f *candidateFirstSend) take() func(context.Context, contract.ID) contract.CryptoResultCode {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	handoff := f.handoff
	f.handoff = nil
	return handoff
}

type Candidate struct {
	requestIdentity   contract.ID
	replacementState  *StateSession
	observation       *operationObservation
	observationSource observationSource
	observationBound  bool
	session           *StateSession
	endWorkReceipt    contract.CompactMutationReceipt
	head              format.Head
	body              []byte
	objects           []objectImage
	used              bool
	firstSend         *candidateFirstSend
	succession        *successionPreparation
	generated         *generatedCandidateFacts
	publication       *publicationCandidateFacts
	producer          *generatedPreparation
	originalProducers map[contract.ID]*generatedPreparation
}

// Ordinary successors leave four selected child slots for an Authority exit.
// Exit candidates use a separate administrative constructor and may use the
// full format ceiling after it has proved its own successor packing.
const ordinaryChildPageLimit = contract.MaxChildPages - 4

func ordinaryCandidateCapacity(candidate *Candidate) bool {
	if candidate == nil {
		return false
	}
	for _, object := range candidate.objects {
		if object.ref.Kind != format.RootKind || object.ref != candidate.head.Core.Root {
			continue
		}
		root, err := format.DecodeRoot(object.body)
		if err != nil || format.CheckReference(object.ref, object.body) != nil {
			return false
		}
		if proof := candidate.head.Succession; candidate.head.AuthKind == format.SuccessionAuth && proof != nil &&
			proof.Subject.OperationKind == contract.SuccessionReplaceAuthority &&
			proof.Subject.ChangeMask == contract.SuccessionChangeNormalSigner &&
			proof.Subject.ApprovalRole == contract.RecoverySigningRole {
			if candidate.session == nil {
				return false
			}
			before := candidate.session.root
			return root.ChildCount <= contract.MaxChildPages && root.ChildCount == before.ChildCount &&
				root.AdministrativeIndex == before.AdministrativeIndex &&
				slices.Equal(root.AdministrativeIndexShards, before.AdministrativeIndexShards) &&
				slices.Equal(root.RequiredSupport, before.RequiredSupport)
		}
		if candidate.head.AuthKind == format.AdministrativeAuth {
			return root.ChildCount <= contract.MaxChildPages && root.ChildEncodedBytes <= contract.MaxChildPages*contract.MaxRequiredSupportPageLength
		}
		return root.ChildCount <= ordinaryChildPageLimit
	}
	return false
}

func conditional(h format.HeadCore, body []byte) format.ConditionalPlan {
	return format.ConditionalPlan{Family: h.PreviousToken.Family, Store: h.Store, Coordinate: h.Coordinate, NonBody: h.NonBody, Condition: matchedCondition(h.PreviousToken), HeadCore: contract.Hash(body), HeadCoreLength: uint32(len(body))}
}

// Signer restoration uses only the authenticated administrative index for
// disposable work. It does not read selected payload bodies.
func (s *StateSession) signerOnlyClosureIDs() map[contract.ID]bool {
	used := make(map[contract.ID]bool)
	if !s.adminIndex.Valid() || s.adminIndex.Domain != s.root.Domain || len(s.adminIndex.Pages) != len(s.root.RequiredSupport) {
		return nil
	}
	used[s.adminIndex.Object] = true
	for i, page := range s.adminIndex.Pages {
		if page.Ref != s.root.RequiredSupport[i] {
			return nil
		}
		used[page.Ref.Object] = true
		for _, row := range page.Rows {
			used[row.RecordID] = true
		}
	}
	for _, group := range s.adminIndex.Groups {
		used[group.GroupID], used[group.OwnerID], used[group.TargetID] = true, true, true
	}
	return s.completeClosureIDs(used)
}

func (s *StateSession) closureIDsMode(ctx context.Context, signerOnly bool) (map[contract.ID]bool, error) {
	if signerOnly {
		used := s.signerOnlyClosureIDs()
		if used == nil {
			return nil, contract.ErrRecord
		}
		return used, nil
	}
	used := make(map[contract.ID]bool)
	if err := s.retainGeneratedIdentities(ctx, used); err != nil {
		return nil, err
	}
	windows, err := s.receiptWindows(ctx)
	if err != nil {
		return nil, err
	}
	for _, rows := range [][]contract.CompactMutationReceipt{windows.Successes, windows.Failures} {
		for _, row := range rows {
			used[row.OperationID] = true
		}
	}
	used = s.completeClosureIDs(used)
	if used == nil {
		return nil, contract.ErrRecord
	}
	return used, nil
}

func (s *StateSession) completeClosureIDs(used map[contract.ID]bool) map[contract.ID]bool {
	if s == nil || used == nil || s.authority() == nil || s.authority().CurrentBinding == nil {
		return nil
	}
	used[s.root.AdministrativeIndex.Object] = true
	for _, shard := range s.root.AdministrativeIndexShards {
		used[shard.Object] = true
	}
	a := s.admission
	for _, id := range []contract.ID{a.domain, a.trust, a.recipient, a.composition, a.interpretation, a.store.Identity, a.store.Coordinate, a.store.NonBody, s.root.Snapshot, s.root.Transition, s.head.Core.Revision, s.head.Core.PreviousRevision, s.head.Subject.Operation, s.recipient.Object, s.authority().CurrentBinding.BindingID} {
		used[id] = true
	}
	if basis, ok := s.admission.domainBasis(); ok {
		for _, id := range []contract.ID{basis.InitID, basis.DescriptorArtifactID, basis.ManifestArtifactID} {
			used[id] = true
		}
		for _, row := range basis.Recipients {
			used[row.RecipientID] = true
			used[row.CurrentBinding.BindingID] = true
		}
		if basis.Recovery != nil {
			used[basis.Recovery.RoleID] = true
			used[basis.Recovery.KMS.BindingID] = true
		}
	}
	control := s.root.CurrentAccess.Core
	used[control.NormalSigning.BindingID] = true
	if control.Recovery != nil {
		used[control.Recovery.RoleID] = true
		used[control.Recovery.Signing.BindingID] = true
		used[control.Recovery.KMS.BindingID] = true
	}
	if s.head.Succession != nil {
		used[s.head.Succession.Subject.OperationID] = true
	}
	for _, page := range s.support {
		used[page.Object] = true
		for _, record := range page.Records {
			used[record.RecordID] = true
		}
	}
	for _, page := range s.support {
		for _, row := range page.Records {
			record := contract.SupportRecord(row)
			if record.Body == nil && publicationSupportKind(record.Kind) {
				fact, err := s.publicationRecord(record)
				if err != nil {
					return nil
				}
				record.Body, err = fact.body()
				if err != nil {
					return nil
				}
			}
			if err := contract.CollectPublicationRecordIdentities(record, used); err != nil {
				return nil
			}

		}
	}
	for _, page := range s.recipients {
		if page != nil {
			used[page.Object] = true
			for _, row := range page.Slots {
				if row != nil {
					used[row.RecipientID], used[row.CurrentBinding.BindingID], used[row.CurrentBinding.BindingIncarnationID] = true, true, true
				}
			}
		}
	}
	for _, page := range s.access {
		if page != nil {
			used[page.Object] = true
		}
	}
	for _, page := range s.pages {
		if page == nil {
			continue
		}
		used[page.Object] = true
		for _, m := range page.Slots {
			if m != nil {
				for _, id := range []contract.ID{m.Incarnation, m.ValueState, m.OriginSnapshot, m.OriginTransition} {
					used[id] = true
				}
				for _, id := range m.Recipients {
					used[id] = true
				}
				if m.ConfidentialityClass == format.Secret {
					payload, err := contract.InspectCanonicalPayload(m.ValueBytes)
					if err != nil {
						return nil
					}
					used[payload.DataKeyID], used[payload.CommitmentKeyID] = true, true
				}
			}
		}
	}
	return used
}
func (c *Comparison) nonemptyPages() [contract.MaxValueEntryPages]bool {
	var pages [contract.MaxValueEntryPages]bool
	for _, slot := range c.slots {
		pages[slot/format.PageSlots] = true
	}
	return pages
}
func planTransition(ctx context.Context, c *Comparison) (transitionPlan, error) {
	p := transitionPlan{values: make(map[uint16]contract.ID), incarnations: make(map[uint16]contract.ID), outputBindings: make(map[string]contract.ID)}
	if c == nil || c.session == nil || !c.session.root.Generated.ActiveOwner.IsZero() || !c.session.root.ActiveGC.IsZero() || len(c.changed)+len(c.removed)+len(c.recipientChanges) == 0 && !c.outputChanged && !c.entryConfigurationChanged || c.outputChanged && c.outputIntent == nil {
		return p, contract.ErrRecord
	}
	c.outputAfter = nil
	complete := false
	defer func() {
		if !complete {
			c.outputAfter = nil
		}
	}()
	entropy := c.session.admission.entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	used, err := c.session.closureIDsMode(ctx, false)
	if err != nil {
		return p, err
	}
	for _, row := range c.recipients {
		if c.session.recipientRecord(row.Recipient.RecipientID) == nil {
			for _, id := range []contract.ID{row.Recipient.RecipientID, row.Recipient.CurrentBinding.BindingID, row.Recipient.CurrentBinding.BindingIncarnationID} {
				if used[id] {
					return p, contract.ErrRecord
				}
				used[id] = true
			}
		}
	}
	var beforeOutput contract.OutputConfiguration
	if c.outputChanged {
		var result Result
		beforeOutput, result = c.session.currentOutputConfigurationForApply(ctx)
		if result.Outcome != 0 {
			return p, selectedReadFailure(result)
		}
		for _, binding := range beforeOutput.Bindings {
			used[binding.IncarnationID] = true
		}
	}
	next := func() (contract.ID, bool) {
		var id contract.ID
		_, err := io.ReadFull(entropy, id[:])
		if err != nil || id.IsZero() || used[id] {
			return contract.ID{}, false
		}
		used[id] = true
		return id, true
	}
	var ok bool
	for _, id := range []*contract.ID{&p.operation, &p.transition, &p.snapshot, &p.revision} {
		*id, ok = next()
		if !ok {
			return transitionPlan{}, contract.ErrRecord
		}
	}
	for _, slot := range c.freshIncarnationSlots() {
		id, ok := next()
		if !ok {
			return transitionPlan{}, contract.ErrRecord
		}
		p.incarnations[slot] = id
	}
	for _, slot := range c.changed {
		if !c.needsFreshValue(slot) {
			continue
		}
		id, ok := next()
		if !ok {
			return transitionPlan{}, contract.ErrRecord
		}
		p.values[slot] = id
	}
	if c.outputChanged {
		selection, err := c.session.outputProjectionForPlan(ctx, c, p, beforeOutput)
		if err != nil {
			return transitionPlan{}, err
		}
		c.outputAfter = selection
		after, _, _, err := selection.transition.ConfigurationAfter(identityPlan(c, p))
		if err != nil {
			return transitionPlan{}, err
		}
		for _, binding := range after.Bindings {
			if contract.OutputBindingIncarnationPreserved(beforeOutput.Bindings, binding) {
				continue
			}
			if used[binding.IncarnationID] || binding.IncarnationID.IsZero() {
				return transitionPlan{}, contract.ErrRecord
			}
			used[binding.IncarnationID] = true
			p.outputBindings[binding.DestinationID] = binding.IncarnationID
		}
	}
	if len(c.recipientChanges) != 0 {
		for i := 0; i < (len(c.recipients)+format.RecipientSlots-1)/format.RecipientSlots; i++ {
			p.recipientPages[i], ok = next()
			if !ok {
				return transitionPlan{}, contract.ErrRecord
			}
		}
	}
	nonempty := c.nonemptyPages()
	for i, touched := range c.touched {
		if touched && nonempty[i] {
			p.pages[i], ok = next()
			if !ok {
				return transitionPlan{}, contract.ErrRecord
			}
		}
	}
	accessRequired := [contract.MaxChildPages]bool{}
	if c.support != nil {
		count, _, err := normalAccessShape(c, p)
		if err != nil {
			return transitionPlan{}, err
		}
		for i := 0; i < count; i++ {
			accessRequired[i] = true
		}
	} else {
		for i, v := range c.secretPages() {
			accessRequired[i] = v
		}
	}
	for i, required := range accessRequired {
		if required {
			p.accessPages[i], ok = next()
			if !ok {
				return transitionPlan{}, contract.ErrRecord
			}
		}
	}
	if c.applyReceipt != nil {
		indexes, err := c.session.installedApplyReceiptPageIndexes(ctx, c, p)
		if err != nil {
			return p, err
		}
		for _, index := range indexes {
			p.supportPages[index], ok = next()
			if !ok {
				return p, contract.ErrRecord
			}
		}
	} else if c.support != nil || c.outputChanged {
		packed, err := normalSupportPacking(ctx, c, p)
		if err != nil {
			return transitionPlan{}, err
		}
		for _, page := range packed {
			if !page.retained.ref.Object.IsZero() {
				continue
			}
			p.supportPages[page.index], ok = next()
			if !ok {
				return transitionPlan{}, contract.ErrRecord
			}
		}
	}
	if err := c.session.validPlan(ctx, c, p); err != nil {
		return p, err
	}
	complete = true
	return p, nil
}
func (s *StateSession) validPlan(ctx context.Context, c *Comparison, p transitionPlan) error {
	if s == nil || c == nil || c.session != s || !s.root.Generated.ActiveOwner.IsZero() ||
		len(p.incarnations) != len(c.freshIncarnationSlots()) {
		return contract.ErrRecord
	}
	used, err := s.closureIDsMode(ctx, false)
	if err != nil {
		return err
	}
	for _, row := range c.recipients {
		if s.recipientRecord(row.Recipient.RecipientID) == nil {
			for _, id := range []contract.ID{row.Recipient.RecipientID, row.Recipient.CurrentBinding.BindingID, row.Recipient.CurrentBinding.BindingIncarnationID} {
				if used[id] {
					return contract.ErrRecord
				}
				used[id] = true
			}
		}
	}
	add := func(id contract.ID) bool {
		if id.IsZero() || used[id] {
			return false
		}
		used[id] = true
		return true
	}
	for i, id := range p.recipientPages {
		required := len(c.recipientChanges) != 0 && i < (len(c.recipients)+format.RecipientSlots-1)/format.RecipientSlots
		if required {
			if !add(id) {
				return contract.ErrRecord
			}
		} else if !id.IsZero() {
			return contract.ErrRecord
		}
	}
	for _, id := range []contract.ID{p.operation, p.transition, p.snapshot, p.revision} {
		if !add(id) {
			return contract.ErrRecord
		}
	}
	for _, slot := range c.freshIncarnationSlots() {
		if !add(p.incarnations[slot]) {
			return contract.ErrRecord
		}
	}
	fresh := 0
	for _, slot := range c.changed {
		if !c.needsFreshValue(slot) {
			continue
		}
		fresh++
		if !add(p.values[slot]) {
			return contract.ErrRecord
		}
	}
	if len(p.values) != fresh {
		return contract.ErrRecord
	}
	nonempty := c.nonemptyPages()
	for i, touched := range c.touched {
		if touched && nonempty[i] {
			if !add(p.pages[i]) {
				return contract.ErrRecord
			}
		} else if !p.pages[i].IsZero() {
			return contract.ErrRecord
		}
	}
	accessRequired := [contract.MaxChildPages]bool{}
	if c.support != nil {
		count, _, err := normalAccessShape(c, p)
		if err != nil {
			return err
		}
		for i := 0; i < count; i++ {
			accessRequired[i] = true
		}
	} else {
		for i, v := range c.secretPages() {
			accessRequired[i] = v
		}
	}
	for i, required := range accessRequired {
		if required {
			if !add(p.accessPages[i]) {
				return contract.ErrRecord
			}
		} else if !p.accessPages[i].IsZero() {
			return contract.ErrRecord
		}
	}
	if c.outputChanged {
		if c.outputAfter == nil || c.outputAfter.transition == nil {
			return contract.ErrRecord
		}
		expected, err := s.normalOutputTransition(ctx, c)
		if err != nil {
			return err
		}
		if !expected.Equal(c.outputAfter.transition) {
			return contract.ErrRecord
		}
		after, descriptor, _, err := c.outputAfter.transition.ConfigurationAfter(identityPlan(c, p))
		if err != nil {
			return err
		}
		if descriptor != c.outputAfter.descriptor {
			return contract.ErrRecord
		}
		freshBindings := 0
		for _, binding := range after.Bindings {
			if contract.OutputBindingIncarnationPreserved(c.outputAfter.transition.Before.Bindings, binding) {
				continue
			}
			freshBindings++
			if p.outputBindings[binding.DestinationID] != binding.IncarnationID || !add(binding.IncarnationID) {
				return contract.ErrRecord
			}
		}
		if freshBindings != len(p.outputBindings) {
			return contract.ErrRecord
		}
		beforeRows, err := s.selectedNormalSupportRows()
		if err != nil {
			return err
		}
		rows, err := c.outputAfter.transition.SupportAfter(identityPlan(c, p), beforeRows)
		if err != nil {
			return err
		}
		for _, row := range rows.Records {
			if row.Kind != contract.PublicationCoordinateSupportKind {
				continue
			}
			if slices.ContainsFunc(beforeRows.Records, func(old contract.SupportRecord) bool { return old.Kind == row.Kind && old.RecordID == row.RecordID }) {
				continue
			}
			coordinate, err := contract.InspectPublicationCoordinate(row.Body)
			if err != nil {
				return err
			}
			if !add(coordinate.CurrentPublicationIncarnationID) || !add(coordinate.CoordinateID) {
				return contract.ErrRecord
			}
		}
	} else if len(p.outputBindings) != 0 {
		return contract.ErrRecord
	}
	if c.applyReceipt != nil {
		indexes, err := s.installedApplyReceiptPageIndexes(ctx, c, p)
		if err != nil {
			return err
		}
		var required [contract.MaxChildPages]bool
		for _, index := range indexes {
			required[index] = true
			if !add(p.supportPages[index]) {
				return contract.ErrRecord
			}
		}
		for index, id := range p.supportPages {
			if !required[index] && !id.IsZero() {
				return contract.ErrRecord
			}
		}
		return nil
	}
	var packed []normalSupportPage
	if c.support != nil || c.outputChanged {
		var err error
		packed, err = normalSupportPacking(ctx, c, p)
		if err != nil {
			return err
		}
	}
	var supportIndexes [contract.MaxChildPages]bool
	for _, page := range packed {
		index := page.index
		if supportIndexes[index] {
			return contract.ErrRecord
		}
		supportIndexes[index] = true
		if !page.retained.ref.Object.IsZero() {
			if page.retained.ref.Index != index || !p.supportPages[index].IsZero() {
				return contract.ErrRecord
			}
		} else if !add(p.supportPages[index]) {
			return contract.ErrRecord
		}
	}
	for i, id := range p.supportPages {
		if !supportIndexes[i] && !id.IsZero() {
			return contract.ErrRecord
		}
	}
	return nil
}

// Derivation fixes the candidate records and current-access commitments before
// lifecycle authority. Access references commit encrypted public records only.
func (s *StateSession) deriveSuccessor(ctx context.Context, c *Comparison, p transitionPlan) (*StateSession, error) {
	if c == nil || c.session != s || len(c.changed)+len(c.removed)+len(c.recipientChanges) == 0 && !c.outputChanged && !c.entryConfigurationChanged {
		return nil, contract.ErrRecord
	}
	if err := s.validPlan(ctx, c, p); err != nil {
		return nil, err
	}

	next := &StateSession{admission: s.admission, store: s.store, root: s.root, adminIndex: s.adminIndex, recipient: s.recipient,
		recipients: s.recipients, pages: s.pages, accessFacts: s.accessFacts, support: s.support, supportFacts: s.supportFacts, fragmentFacts: s.fragmentFacts, publicationFacts: s.publicationFacts}
	next.head.Core.Revision = p.revision
	next.root.GrantPages = nil
	next.root.Snapshot, next.root.Transition = p.snapshot, p.transition
	next.root.ValueEntryCount = uint32(len(c.desiredEntries))
	next.root.RawBytes = 0
	if err := next.installApplyRecipientPages(c, p); err != nil {
		return nil, err
	}
	next.root.ChildCount = 1 + uint32(len(next.root.AdministrativeIndexShards)) + uint32(len(s.root.RequiredSupport))
	for _, ref := range next.root.Recipients {
		if ref != nil {
			next.root.ChildCount++
		}
	}
	next.root.MembershipCount = 0
	next.root.SecretCount, next.root.SecretOrdinaryWrapCount = 0, 0
	next.root.Names = make([]format.NameEntry, len(c.desiredEntries))
	nonempty := c.nonemptyPages()
	for i, touched := range c.touched {
		if !touched {
			continue
		}
		next.root.ValueEntryPages[i] = nil
		next.pages[i] = nil
		if nonempty[i] {
			next.pages[i] = &format.ValueEntryPage{Domain: s.admission.domain, Object: p.pages[i], Index: uint16(i)}
		}
	}
	for i, v := range c.desiredEntries {
		slot := c.slots[i]
		next.root.Names[i] = format.NameEntry{Name: v.Name, Slot: slot}
		next.root.RawBytes += uint64(c.intent[i].ContentLength)
		next.root.MembershipCount += uint32(len(v.Recipients))
		if v.ConfidentialityClass == format.Secret {
			next.root.SecretCount++
			next.root.SecretOrdinaryWrapCount += uint32(len(v.Recipients))
		}
		if !c.touched[slot/format.PageSlots] {
			continue
		}
		m := s.valueEntry(slot)
		if incarnation, added := p.incarnations[slot]; added {
			m = &format.ValueEntry{Name: v.Name, Incarnation: incarnation, Recipients: slices.Clone(v.Recipients), ValueSource: v.ValueSource, ConfidentialityClass: v.ConfidentialityClass, InputEncoding: v.InputEncoding, OutputEncoding: v.OutputEncoding, ContentLength: c.intent[i].ContentLength, RetainedLength: c.intent[i].RetainedLength}
		}
		if value, changed := p.values[slot]; changed {
			entryCopy := *m
			entryCopy.ValueState = value
			entryCopy.OriginSnapshot = p.snapshot
			entryCopy.OriginTransition = p.transition
			entryCopy.ValueBytes = v.InputBytes
			entryCopy.InputEncoding, entryCopy.ContentLength, entryCopy.RetainedLength = c.intent[i].InputEncoding, c.intent[i].ContentLength, c.intent[i].RetainedLength
			entryCopy.Recipients = slices.Clone(v.Recipients)
			m = &entryCopy
		}
		if m.OutputEncoding != v.OutputEncoding {
			entryCopy := *m
			entryCopy.OutputEncoding = v.OutputEncoding
			m = &entryCopy
		}
		if !slices.Equal(m.Recipients, v.Recipients) {
			entryCopy := *m
			entryCopy.Recipients = slices.Clone(v.Recipients)
			m = &entryCopy
		}
		if v.ConfidentialityClass == format.Secret && slices.Contains(c.changed, slot) {
			row := slices.IndexFunc(c.preparedRows, func(row contract.CryptoPreparedSecret) bool { return row.Slot == slot && row.Name == v.Name })
			if row < 0 {
				return nil, contract.ErrRecord
			}
			decoded, err := contract.DecodeValueEntry(c.preparedRows[row].EntryBytes)
			if err != nil {
				return nil, err
			}
			m = &decoded
		}
		next.pages[slot/format.PageSlots].Slots[slot%format.PageSlots] = m
	}
	for _, page := range next.pages {
		if page != nil {
			next.root.ChildCount++
		}
	}
	if !next.deriveAccess(c, p) {
		return nil, contract.ErrRecord
	}
	if c.applyReceipt == nil && (c.support != nil || c.outputChanged) {
		if err := next.deriveNormalGeneratedSupport(ctx, c, p); err != nil {
			return nil, err
		}
	}
	if !next.indexSelectedMaterials() {
		return nil, contract.ErrRecord
	}
	if next.root.ValueEntryCount > contract.CryptoMaxValueEntries || next.root.RawBytes > contract.CryptoMaxRawSet || next.root.ChildCount > ordinaryChildPageLimit {
		return nil, contract.ErrRecord
	}
	return next, nil
}
func (s *StateSession) successorCore(p transitionPlan) format.HeadCore {
	h := s.head.Core
	h.GrantDigest = contract.ID{}
	h.Form = format.SuccessorHead
	h.Revision = p.revision
	h.PreviousRevision = s.head.Core.Revision
	h.PreviousDigest = contract.Hash(s.body)
	h.PreviousToken = s.token
	return h
}
func (s *StateSession) authorityFrom(next *StateSession, c *Comparison, p transitionPlan) (lifecycleAuthority, error) {
	if s == nil || next == nil || c == nil || c.session != s {
		return lifecycleAuthority{}, contract.ErrRecord
	}
	var public contract.DigestLength
	if c.applyReceipt == nil && (c.support != nil || c.outputChanged) {
		var err error
		public, err = next.prospectiveNormalPublicState(c, p)
		if err != nil {
			return lifecycleAuthority{}, err
		}
	} else {
		projection, err := next.publicStateProjection()
		if err != nil {
			return lifecycleAuthority{}, err
		}
		descriptor, err := contract.PublicStateDescriptor(projection)
		if err != nil {
			return lifecycleAuthority{}, err
		}
		public = contract.DigestLength{Digest: descriptor.Digest, Length: descriptor.Length}
	}
	return s.authorityWithPublicState(next, c, p, public)
}

func (s *StateSession) authorityWithPublicState(next *StateSession, c *Comparison, p transitionPlan, public contract.DigestLength) (lifecycleAuthority, error) {
	union, grants, exclusions, changed := s.lifecycleVectors(next)
	for i := range exclusions {
		if s.valueEntry(exclusions[i].Slot).ConfidentialityClass != format.Secret {
			continue
		}
		exclusions[i].Path = contract.ID{}
		for _, row := range c.secretRows {
			if row.Name == exclusions[i].Name {
				exclusions[i].Path = row.ExclusionPathDigest
				break
			}
		}
	}
	normal := contract.NormalSection{Intent: contract.DigestLength{Digest: c.desired, Length: c.desiredLength}, PublicState: public, Union: union, Changed: changed}
	r := *s.authority().CurrentBinding
	h := s.successorCore(p)
	identity := identityCommitment(c, p)
	request := requestCommitment(h, contract.LifecycleSubject{IdentityPlan: identity, Normal: normal})
	kind := c.lifecycleOperationKind()
	common := authorityContext{OperationKind: kind, Domain: h.Domain, Store: h.Store, Trust: h.Trust, Coordinate: h.Coordinate, NonBody: h.NonBody, Interpretation: h.Interpretation, Epoch: h.Epoch, PreviousRevision: h.PreviousRevision, PreviousDigest: h.PreviousDigest, PreviousToken: h.PreviousToken, Operation: p.operation, Transition: p.transition, Snapshot: p.snapshot, Revision: p.revision, Request: request, Recipient: s.admission.recipient, KeyBinding: r.BindingID, Fingerprint: r.Fingerprint, BindingVersion: r.BindingSerial, IdentityPlan: identity, BeforeValueEntryCount: s.root.ValueEntryCount, AfterValueEntryCount: next.root.ValueEntryCount, BeforeSecretCount: uint16(s.root.SecretCount), AfterSecretCount: uint16(next.root.SecretCount), BeforeRawBytes: s.root.RawBytes, AfterRawBytes: next.root.RawBytes, BeforeAccessRoot: s.root.CurrentAccess.AccessRoot, AfterAccessRoot: next.root.CurrentAccess.AccessRoot, BeforeMembershipCount: s.root.MembershipCount, AfterMembershipCount: next.root.MembershipCount}
	return lifecycleAuthority{normal: &normalAuthorization{Context: common, Section: normal}, grant: &grantAuthorization{Context: common, Rows: grants}, exclusion: &exclusionAuthorization{Context: common, Rows: exclusions, Retirements: c.retirementCommitment()}}, nil
}
func (a lifecycleAuthority) equal(b lifecycleAuthority) bool {
	return a.normal != nil && a.grant != nil && a.exclusion != nil && b.normal != nil && b.grant != nil && b.exclusion != nil && *a.normal == *b.normal && a.grant.Context == b.grant.Context && slices.EqualFunc(a.grant.Rows, b.grant.Rows, membershipEqual) && a.exclusion.Context == b.exclusion.Context && a.exclusion.Retirements == b.exclusion.Retirements && slices.EqualFunc(a.exclusion.Rows, b.exclusion.Rows, exclusionEqual)
}
func (a lifecycleAuthority) subject() contract.LifecycleSubject {
	c := a.normal.Context
	return contract.LifecycleSubject{OperationKind: c.OperationKind, Operation: c.Operation, Request: c.Request, Recipient: c.Recipient, KeyBinding: c.KeyBinding, Fingerprint: c.Fingerprint, BindingVersion: c.BindingVersion, IdentityPlan: c.IdentityPlan, BeforeValueEntryCount: c.BeforeValueEntryCount, AfterValueEntryCount: c.AfterValueEntryCount, BeforeSecretCount: c.BeforeSecretCount, AfterSecretCount: c.AfterSecretCount, BeforeRawBytes: c.BeforeRawBytes, AfterRawBytes: c.AfterRawBytes, BeforeAccessRoot: c.BeforeAccessRoot, AfterAccessRoot: c.AfterAccessRoot, BeforeMembershipCount: c.BeforeMembershipCount, AfterMembershipCount: c.AfterMembershipCount, Normal: a.normal.Section, Grant: contract.GrantSection{Grants: grantCommitment(c.Domain, a.grant.Rows)}, Exclusion: contract.ExclusionSection{Exclusions: exclusionCommitment(c.Domain, a.exclusion.Rows), Retirements: a.exclusion.Retirements}}
}

func (s *StateSession) encodeSuccessorChildren(next *StateSession, p transitionPlan, comparison *Comparison, supportImages ...[]objectImage) (*Candidate, Result) {
	candidate := &Candidate{session: s}
	next.root.GrantPages = nil
	var grants map[contract.ID][]contract.ID
	var grantCount int
	if comparison != nil {
		var err error
		grants, grantCount, err = comparison.existingSecretGrants(p)
		if err != nil {
			return nil, installedApplyPreparationFailure(err)
		}
	}
	for i, id := range p.recipientPages {
		if id.IsZero() {
			continue
		}
		if next.recipients[i] == nil {
			return nil, refused(InvalidReference)
		}
		body, err := format.EncodeRecipientPage(*next.recipients[i])
		if err != nil {
			return nil, refused(InvalidFormat)
		}
		ref, err := format.Reference(format.RecipientKind, s.admission.domain, id, uint16(i), body)
		if err != nil {
			return nil, refused(InvalidReference)
		}
		next.root.Recipients[i] = &ref
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	for i, id := range p.pages {
		if id.IsZero() {
			continue
		}
		body, err := format.EncodeValueEntryPage(*next.pages[i])
		if err != nil {
			return nil, refused(InvalidFormat)
		}
		ref, err := format.Reference(format.ValueEntryPageKind, s.admission.domain, id, uint16(i), body)
		if err != nil {
			return nil, refused(InvalidReference)
		}
		next.root.ValueEntryPages[i] = &ref
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	for _, ref := range next.root.CurrentAccess.Core.AccessPageRefs {
		if p.accessPages[ref.Index].IsZero() {
			continue
		}
		body, err := format.EncodeAccessPage(*next.access[ref.Index])
		if err != nil || format.CheckReference(ref, body) != nil {
			return nil, refused(InvalidReference)
		}
		if grantCount != 0 {
			base, rows, err := format.SplitGrantPage(*next.access[ref.Index], grants)
			if err != nil {
				return nil, refused(InvalidRelation)
			}
			if len(rows) != 0 {
				body, err = format.EncodeAccessPage(base)
				if err != nil {
					return nil, refused(InvalidFormat)
				}
				ref, err = format.Reference(format.AccessKind, base.Domain, base.Object, base.Index, body)
				if err != nil {
					return nil, refused(InvalidReference)
				}
				next.root.GrantPages = append(next.root.GrantPages, ref)
				candidate.head.GrantWraps = append(candidate.head.GrantWraps, rows...)
			}
		}
		candidate.objects = append(candidate.objects, objectImage{ref: ref, body: body})
	}
	if len(candidate.head.GrantWraps) != grantCount*format.GrantWrapLength {
		return nil, refused(InvalidRelation)
	}
	if len(supportImages) > 1 {
		return nil, refused(AdmissionInvalid)
	}
	if len(supportImages) == 1 {
		expected := 0
		for _, id := range p.supportPages {
			if !id.IsZero() {
				expected++
			}
		}
		if len(supportImages[0]) != expected {
			return nil, refused(InvalidReference)
		}
		seen := make(map[uint16]bool, expected)
		for _, object := range supportImages[0] {
			i := object.ref.Index
			position := slices.IndexFunc(next.root.RequiredSupport, func(ref format.Ref) bool { return ref.Index == i })
			if position < 0 || seen[i] {
				return nil, refused(InvalidReference)
			}
			seen[i] = true
			ref := next.root.RequiredSupport[position]
			if object.ref != ref || p.supportPages[i] != ref.Object || format.CheckReference(ref, object.body) != nil {
				return nil, refused(InvalidReference)
			}
			candidate.objects = append(candidate.objects, object)
		}
	}
	return candidate, Result{}
}

// encodeSuccessor finishes the complete immutable image before Store or Trust effects.
func (s *StateSession) encodeSuccessor(ctx context.Context, next *StateSession, p transitionPlan, authority lifecycleAuthority, comparison *Comparison, supportImages ...[]objectImage) (*Candidate, Result) {
	candidate, result := s.encodeSuccessorChildren(next, p, comparison, supportImages...)
	if candidate == nil {
		return nil, result
	}
	if err := s.installAdministrativeIndex(ctx, next, candidate); err != nil {
		if result, ok := selectedReadResult(err); ok {
			return nil, result
		}
		if errors.Is(err, contract.ErrRecordCapacity) {
			return nil, refused(CapacityExceeded)
		}
		return nil, refused(InvalidRelation)
	}
	next.root.ChildEncodedBytes = uint64(next.root.AdministrativeIndex.Length)
	for _, ref := range next.root.AdministrativeIndexShards {
		next.root.ChildEncodedBytes += uint64(ref.Length)
	}
	for _, table := range [][]*format.Ref{next.root.ValueEntryPages[:], next.root.Recipients[:]} {
		for _, ref := range table {
			if ref != nil {
				next.root.ChildEncodedBytes += uint64(ref.Length)
			}
		}
	}
	for _, ref := range next.root.CurrentAccess.Core.AccessPageRefs {
		next.root.ChildEncodedBytes += uint64(ref.Length)
	}
	for _, ref := range next.root.RequiredSupport {
		next.root.ChildEncodedBytes += uint64(ref.Length)
	}
	if len(s.fragmentFacts) != 0 {
		var err error
		if len(supportImages) == 1 {
			err = s.bindReceiptSuccessorSlices(next)
		} else {
			err = s.bindReboundGeneratedSlices(next)
		}
		if err != nil {
			return nil, refused(InvalidRelation)
		}
	}
	if _, err := next.validateRelationsMode(ctx, false); err != nil {
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(InvalidRelation)
	}
	// The authority was formed from the admitted prospective row/fact plan.
	// The completed index must now produce the same strict selected projection.
	completed, err := next.publicStateProjection()
	if err != nil {
		if readFailure, ok := selectedReadResult(err); ok {
			return nil, readFailure
		}
		return nil, refused(InvalidRelation)
	}
	descriptor, err := contract.PublicStateDescriptor(completed)
	if err != nil || authority.normal == nil ||
		authority.normal.Section.PublicState != (contract.DigestLength{Digest: descriptor.Digest, Length: descriptor.Length}) {
		return nil, refused(InvalidProof)
	}
	rootBody, err := format.EncodeRoot(next.root)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	rootRef, err := format.Reference(format.RootKind, s.admission.domain, p.snapshot, 0, rootBody)
	if err != nil {
		return nil, refused(InvalidReference)
	}
	candidate.objects = append(candidate.objects, objectImage{ref: rootRef, body: rootBody})
	h := s.successorCore(p)
	h.Root = rootRef
	if len(candidate.head.GrantWraps) != 0 {
		h.GrantDigest = contract.Hash(candidate.head.GrantWraps)
	}
	coreBody, err := format.EncodeHeadCore(h)
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	planBody, err := format.EncodeConditionalPlan(conditional(h, coreBody))
	if err != nil {
		return nil, refused(InvalidFormat)
	}
	subject := authority.subject()
	subject.HeadCore = contract.Hash(coreBody)
	subject.HeadCoreLength = uint32(len(coreBody))
	subject.ConditionalPlan = contract.Hash(planBody)
	if _, err := contract.NewLifecycleRequest(subject); err != nil {
		return nil, refused(InvalidProof)
	}
	candidate.head = format.Head{Core: h, K1: bytes.Clone(s.head.K1), K3: bytes.Clone(s.head.K3), AuthKind: format.LifecycleAuth, Subject: subject, GrantWraps: candidate.head.GrantWraps}
	next.head = candidate.head
	if !next.validLifecycleSelection() {
		return nil, refused(InvalidProof)
	}
	return candidate, Result{}
}
func (s *StateSession) prepare(ctx context.Context, c *Comparison, permit *AdmittedParentTransition, trust contract.Trust) (*Candidate, Result) {
	if s == nil || s.prepared || !s.admission.valid(s.store) || c == nil || c.session != s || permit == nil || permit.used || permit.session != s || permit.comparison != c || permit.predecessorDigest != contract.Hash(s.body) || permit.predecessorRevision != s.head.Core.Revision || permit.predecessorToken != s.token {
		return nil, refused(AdmissionInvalid)
	}
	if trust == nil || trust.Identity() != s.admission.trust || trust.Family() != s.admission.store.Family {
		return nil, refused(ConstructionMismatch)
	}
	if c.operation != nil && (c.operation.terminal || c.preparedPlan.Digest.IsZero()) {
		return nil, refused(AdmissionInvalid)
	}
	// Recompute the complete image, diff, capacity and exact authority subject.
	recomputed, res := s.compareResolvedEntryInputsForMutation(ctx, c.desiredEntries, c.recipients, c.secretAccess, c.retirement)
	if recomputed != nil && c.operation != nil {
		d, err := contract.CryptoComparisonDescriptor(c.secretRows)
		if err != nil || d.Digest != c.operation.comparisonDigest || !comparisonMatches(recomputed, contract.CryptoCompareResult{OperationRef: c.operation.operationRef, Rows: c.secretRows, ComparisonDigest: d.Digest}) {
			return nil, refused(AdmissionInvalid)
		}
		recomputed.applySecretComparison(c.secretRows)
	}
	if recomputed == nil || res.Outcome == AdmissionRefused || recomputed.desired != c.desired || recomputed.desiredLength != c.desiredLength || !slices.Equal(recomputed.changed, c.changed) || !slices.Equal(recomputed.slots, c.slots) || !slices.Equal(recomputed.added, c.added) || !slices.Equal(recomputed.removed, c.removed) || recomputed.touched != c.touched || recomputed.entryConfigurationChanged != c.entryConfigurationChanged || !slices.Equal(recomputed.recipientChanges, c.recipientChanges) {
		return nil, refused(AdmissionInvalid)
	}
	var candidate *Candidate
	var next *StateSession
	var authority lifecycleAuthority
	if c.applyReceipt != nil {
		candidate, next, authority, res = s.encodeInstalledApply(ctx, c, permit.plan)
		if candidate == nil {
			return nil, res
		}
		if !authority.equal(permit.authority) {
			return nil, refused(AdmissionInvalid)
		}
	} else {
		var err error
		next, err = s.deriveSuccessor(ctx, c, permit.plan)
		if err != nil {
			if readFailure, ok := selectedReadResult(err); ok {
				return nil, readFailure
			}
			return nil, refused(AdmissionInvalid)
		}
		if c.support != nil {
			if err := next.checkNormalCapacity(ctx, c); err != nil {
				if readFailure, ok := selectedReadResult(err); ok {
					return nil, readFailure
				}
				return nil, refused(CapacityExceeded)
			}
		}
		authority, err = s.authorityFrom(next, c, permit.plan)
		if err != nil {
			if readFailure, ok := selectedReadResult(err); ok {
				return nil, readFailure
			}
			return nil, refused(InvalidRelation)
		}
		if !authority.equal(permit.authority) {
			return nil, refused(AdmissionInvalid)
		}
		if c.support != nil || c.outputChanged {
			candidate, res = s.encodeSuccessor(ctx, next, permit.plan, authority, c, c.normalSupportObjects)
		} else {
			candidate, res = s.encodeSuccessor(ctx, next, permit.plan, authority, c)
		}
		if candidate == nil {
			return nil, res
		}
	}

	source := observationSource{OperationID: permit.plan.operation}
	owner := c.observation
	if c.operation != nil {
		source = c.operation.source
		source.OperationID = permit.plan.operation
	}
	candidate.bindObservation(owner, source)
	if candidate.observation.enabled() {
		detail := ordinaryCandidateObservation(s, next)
		detail.Source, detail.Candidate = candidate.observationSource, candidateObservationIdentity(candidate)
		detail.Source.Stage = observationCandidate
		candidate.observation.offerChange(ctx, detail)
	}
	permit.used = true
	s.prepared = true
	defer func() {
		c.outputIntent = nil
		if c.outputAfter != nil {
			c.outputAfter.transition = nil
		}
	}()
	if c.operation != nil {
		if c.applyReceipt != nil {
			if err := s.bindInstalledApplyReceipt(ctx, c, next, permit.plan); err != nil {
				return nil, refused(AdmissionInvalid)
			}
		}
		if res := s.freezeAndClaim(ctx, c, permit.plan, next, authority); res.Outcome != 0 {
			return nil, res
		}
	}
	return s.persistCandidate(ctx, candidate, trust)
}

func (s *StateSession) persistCandidate(ctx context.Context, candidate *Candidate, trust contract.Trust) (*Candidate, Result) {
	if s == nil || candidate == nil || candidate.session != s || candidate.used ||
		(candidate.head.AuthKind == format.GeneratorAuth && !candidate.generatedReady()) ||
		(candidate.head.AuthKind != format.GeneratorAuth && candidate.generated != nil) || !publicationCandidateFamilyReady(candidate) {
		return nil, refused(AdmissionInvalid)
	}
	if !ordinaryCandidateCapacity(candidate) {
		return nil, refused(CapacityExceeded)
	}
	for i, object := range candidate.objects {
		if !s.admission.valid(s.store) {
			return nil, refused(AdmissionInvalid)
		}
		key, err := format.Key(s.admission.store.Prefix, object.ref)
		if err != nil {
			return nil, refused(InvalidReference)
		}
		if res := s.persistImmutable(ctx, key, object.body, object.ref.Length); res.Outcome != 0 {
			return nil, res
		}
		if format.CheckReference(object.ref, object.body) != nil {
			return nil, failure(IntegrityFailure, ImmutableConflict)
		}
		s.cacheVerifiedObject(object.ref, object.body)
		if s.replacementRead && object.ref.Kind == contract.AdministrativeIndexKind {
			candidate.objects[i].body = nil
		}
	}
	if err := s.cacheCandidateAdministrativeIndex(candidate); err != nil {
		return nil, failure(IntegrityFailure, InvalidRelation)
	}
	request, err := ordinaryHeadRequest(candidate.head)
	if candidate.head.AuthKind == format.GCAuth {
		if candidate.head.GC == nil {
			return nil, refused(InvalidProof)
		}
		request, err = contract.NewGCRequest(*candidate.head.GC)
	}
	if err != nil {
		return nil, refused(InvalidProof)
	}
	if !s.admission.valid(s.store) {
		return nil, refused(AdmissionInvalid)
	}
	proof := s.trustSign(ctx, trust, request)
	if proof.Reason == contract.ReasonProof {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	if len(proof.Signature) == 0 {
		return nil, failure(EvidenceUnavailable, SigningUnavailable)
	}
	if proof.Reason != contract.ReasonNone || !verify(s.key, request, proof.Signature) {
		return nil, failure(IntegrityFailure, InvalidProof)
	}
	candidate.head.AuthorizationSignature = bytes.Clone(proof.Signature)
	candidate.body, err = format.EncodeHead(candidate.head)
	if err != nil {
		return nil, failure(IntegrityFailure, InvalidFormat)
	}
	res := s.observed(ObservedCurrent)
	res.RequestedRevision = candidate.head.Core.Revision
	return candidate, res
}

func (s *StateSession) selectCandidate(ctx context.Context, candidate *Candidate) (selected *StateSession, result Result) {
	observe := s.candidateObservationReady(candidate)
	if observe {
		defer func() { candidate.offerSelection(ctx, result) }()
	}
	if s == nil || ctx == nil || !s.admission.valid(s.store) || candidate == nil || candidate.session != s || candidate.used || len(candidate.body) == 0 {
		return nil, refused(AdmissionInvalid)
	}
	if candidate.head.AuthKind == format.GeneratorAuth && !candidate.generatedReady() ||
		candidate.head.AuthKind != format.GeneratorAuth && candidate.generated != nil || !publicationCandidateFamilyReady(candidate) {
		return nil, refused(AdmissionInvalid)
	}
	observer := s
	administrativeObservation := false
	if candidate.head.AuthKind == format.SuccessionAuth {
		if !candidate.successionSelectionReady() {
			return nil, refused(AdmissionInvalid)
		}
		next := *s
		next.admission = *candidate.succession.selectionAdmission
		var ok bool
		next.key, ok = publicKey(next.admission.publicKey)
		if !ok || !next.admission.valid(s.store) {
			return nil, refused(AdmissionInvalid)
		}
		observer = &next
		administrativeObservation = candidate.head.Succession != nil &&
			candidate.head.Succession.Subject.OperationKind == contract.SuccessionReplaceAuthority &&
			candidate.head.Succession.Subject.ChangeMask == contract.SuccessionChangeNormalSigner &&
			candidate.head.Succession.Subject.ApprovalRole == contract.RecoverySigningRole
	} else if candidate.succession != nil {
		return nil, refused(AdmissionInvalid)
	} else if candidate.head.AuthKind == format.AdministrativeAuth {
		administrativeObservation = true
	}
	if result := s.persistSelectedGrantPages(ctx); result.Outcome != 0 {
		return nil, result
	}
	candidate.used = true
	firstSend := candidate.firstSend.take()
	candidate.firstSend = nil
	// The one-use selection needs HEAD and the authenticated cache only. Release
	// the independent write images before reading any competing closure.
	candidate.objects = nil
	candidate.replacementState = nil
	requested := candidate.head.Core.Revision
	episode := &storeEpisode{}
	ctx = context.WithValue(ctx, storeEpisodeKey{}, episode)
	possiblePriorCommit := false
	hadTransport := false
	for send := 0; send < 3; send++ {
		if !episode.active(ctx) || !s.admission.valid(s.store) {
			return nil, selectionStopped(requested, possiblePriorCommit, contract.ReasonLimit)
		}
		episode.writes++
		callCtx, cancel := episode.callContext(ctx)
		w := s.storeCompareAndSwap(callCtx, s.admission.store.HeadKey, s.token, bytes.Clone(candidate.body))
		cancel()
		if w.Status == contract.WritePrecondition && !possiblePriorCommit {
			r := s.observed(Contention)
			r.Reason = StalePrecondition
			r.RequestedRevision = requested
			return nil, r
		}
		if w.Status == contract.WriteRefused && !possiblePriorCommit {
			r := refusedStoreWrite(w)
			r.RequestedRevision = requested
			return nil, r
		}
		if w.Status == contract.WriteUnknown && !w.NotSent || w.Status == contract.WriteConflict {
			possiblePriorCommit = true
		}
		if w.Status == contract.WriteUnknown && w.Reason == contract.ReasonTransport {
			hadTransport = true
			episode.startFailure(ctx, s.admission.expires)
		}
		if !episode.beginStage(headObservationLimit()) {
			return nil, selectionStopped(requested, possiblePriorCommit, contract.ReasonLimit)
		}
		callCtx, cancel = episode.callContext(ctx)
		current, res, predecessor := s.observeSelection(callCtx, observer, w.Status == contract.WriteUnknown && w.Reason == contract.ReasonTransport, administrativeObservation)
		cancel()
		res.RequestedRevision = requested
		if current != nil && candidateMatches(current, candidate) {
			if w.Status == contract.WriteAcknowledged && !possiblePriorCommit && firstSend != nil {
				request, err := ordinaryHeadRequest(current.head)
				if err != nil || firstSend(ctx, request.Digest()) != contract.CryptoSuccess {
					res.Reason = CustodyUnavailable
				}
			}
			return current, res
		}
		if predecessor && w.Status == contract.WriteUnknown && w.Reason == contract.ReasonTransport && send < 2 {
			if waitForStoreRetry(ctx, episode.deadline, storeRetryWait[send]) {
				continue
			}
			res.StoreReason = contract.ReasonLimit
		}
		if w.Status == contract.WriteUnknown && w.NotSent && !possiblePriorCommit {
			if predecessor {
				res = failure(EvidenceUnavailable, WriteUncertain)
				res.RequestedRevision = requested
				res.StoreReason = contract.ReasonTransport
				return current, res
			}
			if current != nil {
				res.Outcome, res.Reason = Contention, DifferentSelection
			}
			return current, res
		}
		if hadTransport && res.StoreReason == contract.ReasonNone && res.Outcome != IntegrityFailure && res.Outcome != AdmissionRefused {
			res.StoreReason = contract.ReasonTransport
		}
		res.Outcome = UnresolvedCommit
		res.CommitMayHaveOccurred = true
		if current != nil && (current.token != s.token || current.head.Core.Revision != s.head.Core.Revision) {
			res.Reason = DifferentSelection
		} else if res.Reason == NoReason {
			res.Reason = WriteUncertain
		}
		return current, res
	}
	return nil, selectionStopped(requested, possiblePriorCommit, contract.ReasonTransport)
}

func selectionStopped(requested contract.ID, possibleCommit bool, reason contract.Reason) Result {
	if possibleCommit {
		result := failure(UnresolvedCommit, WriteUncertain)
		result.RequestedRevision = requested
		result.CommitMayHaveOccurred = true
		result.StoreReason = reason
		return result
	}
	result := failure(EvidenceUnavailable, WriteUncertain)
	result.RequestedRevision = requested
	result.StoreReason = reason
	return result
}

func candidateMatches(current *StateSession, candidate *Candidate) bool {
	if current == nil || candidate == nil || current.head.Core != candidate.head.Core || current.head.AuthKind != candidate.head.AuthKind || current.head.Subject != candidate.head.Subject {
		return false
	}
	if candidate.head.AuthKind == format.GCAuth {
		return current.head.GC != nil && candidate.head.GC != nil && *current.head.GC == *candidate.head.GC
	}
	if candidate.head.AuthKind == format.GeneratorAuth {
		return current.head.Generator != nil && *current.head.Generator == *candidate.head.Generator
	}
	if candidate.head.AuthKind == format.SuccessionAuth {
		return current.head.Succession != nil && current.head.Succession.Subject == candidate.head.Succession.Subject && signingBindingEqual(current.head.Succession.Authorizer, candidate.head.Succession.Authorizer)
	}
	if candidate.head.AuthKind == format.AdministrativeAuth {
		return current.head.EndWork != nil && candidate.head.EndWork != nil && *current.head.EndWork == *candidate.head.EndWork
	}
	return true
}

func (s *StateSession) observeSelection(ctx context.Context, observer *StateSession, possibleTransportWrite, administrative bool) (*StateSession, Result, bool) {
	read := func(session *StateSession) (*StateSession, Result) {
		if administrative {
			return session.readAdministrativeImage(ctx)
		}
		return session.readCurrentImage(ctx, false)
	}
	if possibleTransportWrite {
		stored := s.storeRead(ctx, s.admission.store.HeadKey, contract.MaxHeadLength)
		if stored.Status != contract.ReadOK {
			switch stored.Status {
			case contract.ReadMissing:
				return nil, failure(RootLossUnsupported, MissingSelectedObject), false
			case contract.ReadInvalid:
				return nil, failure(IntegrityFailure, InvalidFormat), false
			default:
				return nil, unavailableStoreRead(stored), false
			}
		}
		if stored.Token == s.token && bytes.Equal(stored.Body, s.body) {
			current, res := read(s)
			if current != nil && current.token == s.token && bytes.Equal(current.body, s.body) {
				return current, res, true
			}
			return current, res, false
		}
	}
	current, res := read(observer)
	return current, res, false
}
