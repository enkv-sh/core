package core

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// ApplyEntryInput carries plain supplied bytes, a sealed supplied secret, an
// exact current supplied-secret pin, or a normalized generated declaration.
// Ordinary comparison requires the exact current generated payload. The installed
// owner admits new generation separately; a declaration grants no effect authority.
type ApplyEntryInput struct {
	Name                              string
	Recipients                        []contract.ID
	ValueSource, ConfidentialityClass uint8
	InputEncoding, OutputEncoding     uint8
	InputBytes                        []byte
	Retained                          *contract.RetainedSecretInput
	Generated                         *contract.GeneratorDeclaredGeneration
}

// AdmittedParentComparison has no public constructor. The private parent pins
// an independently admitted request and installed Crypto instance.
type AdmittedParentComparison struct {
	observation               *operationObservation
	session                   *StateSession
	recipients                []contract.ApplyRecipientInput
	secretAccess              *contract.CryptoSecretAccessIntent
	retirement                *contract.RecipientRetirementRow
	crypto                    contract.Crypto
	instance                  contract.ID
	context                   contract.ApplyContext
	requestDigest             contract.ID
	requestLength             int
	deadline                  time.Time
	support                   *contract.GeneratedSupportTransition
	output                    *outputApplyInput
	used                      bool
	trackNoWork               bool
	noWorkBasis, noWorkIntent contract.DescriptorVector
}

type Comparison struct {
	observation               *operationObservation
	session                   *StateSession
	desiredEntries            []ApplyEntryInput
	recipients                []contract.ApplyRecipientInput
	recipientChanges          []contract.ID
	operationKind             uint16
	secretAccess              *contract.CryptoSecretAccessIntent
	retirement                *contract.RecipientRetirementRow
	intent                    []contract.CryptoIntentRow
	desired                   contract.ID
	desiredLength             uint64
	slots                     []uint16
	changed, added, removed   []uint16
	touched                   [contract.MaxValueEntryPages]bool
	entryConfigurationChanged bool
	operation                 *cryptoOperation
	preparedRows              []contract.CryptoPreparedSecret
	preparedPlan              contract.DescriptorVector
	secretRows                []contract.CryptoComparisonRow
	equalOnlySources          []string
	support                   *contract.GeneratedSupportTransition
	normalSupportObjects      []objectImage
	normalSupportPlan         contract.DescriptorVector
	normalSupportRows         contract.GeneratedSupportRows
	normalSupportSnapshot     contract.ID
	normalSupportTransition   contract.ID
	normalPackedPages         []normalSupportPage
	normalPackedChildren      uint32
	outputIntent              *outputApplyInput
	outputAfter               *outputApplySelection
	applyReceipt              *installedApplyReceipt
	outputChanged             bool
}

func (s *StateSession) valueEntry(slot uint16) *format.ValueEntry {
	return selectedValueEntry(&s.pages, slot)
}
func selectedValueEntry(pages *[contract.MaxValueEntryPages]*format.ValueEntryPage, slot uint16) *format.ValueEntry {
	page := pages[int(slot)/format.PageSlots]
	if page == nil {
		return nil
	}
	return page.Slots[int(slot)%format.PageSlots]
}

// compareEntryInputs checks the complete input and computes only public differences.
// Private source authentication occurs before the comparison can escape Core.
func (s *StateSession) compareEntryInputs(input []ApplyEntryInput) (*Comparison, Result) {
	if s == nil {
		return nil, refused(AdmissionInvalid)
	}
	return s.compareEntryInputsWithRecipients(context.Background(), input, currentApplyRecipients(s.registry()))
}

func (s *StateSession) compareEntryInputsWithRecipients(ctx context.Context, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput) (*Comparison, Result) {
	return s.compareEntryInputsWithRetirement(ctx, input, recipients, nil, nil)
}

func (s *StateSession) compareEntryInputsWithRetirement(ctx context.Context, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput, retirement *contract.RecipientRetirementRow, refusalDiagnostic **contract.Diagnostic) (*Comparison, Result) {
	if refusalDiagnostic != nil {
		*refusalDiagnostic = nil
	}
	if s == nil || !s.admission.valid(s.store) || s.authority() == nil || s.authority().Status != format.Current {
		return nil, refused(AdmissionInvalid)
	}
	proposal, err := s.admitRecipientProposal(ctx, recipients, retirement)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	c := &Comparison{session: s, recipients: proposal.inputs, recipientChanges: proposal.changed}
	if len(input) > contract.CryptoMaxValueEntries {
		return nil, refused(CapacityExceeded)
	}
	for _, entry := range s.root.Names {
		if s.valueEntry(entry.Slot) == nil {
			return nil, refused(AdmissionInvalid)
		}
	}
	desiredEntries := slices.Clone(input)
	sort.Slice(desiredEntries, func(i, j int) bool { return desiredEntries[i].Name < desiredEntries[j].Name })
	var raw uint64
	var memberships int
	for i, v := range desiredEntries {
		if (v.InputEncoding != contract.InputEncodingRaw && v.InputEncoding != contract.InputEncodingBase64) || (v.OutputEncoding != contract.OutputEncodingRaw && v.OutputEncoding != contract.OutputEncodingBase64) || len(v.Name) > contract.CryptoMaxName || !utf8.ValidString(v.Name) || (v.ValueSource != format.Supplied && v.ValueSource != contract.Generated) || (v.ConfidentialityClass != format.Plain && v.ConfidentialityClass != format.Secret) || v.ValueSource == contract.Generated && v.ConfidentialityClass != format.Secret || i > 0 && desiredEntries[i-1].Name == v.Name {
			return nil, refused(InvalidIntent)
		}
		if v.Generated != nil && (v.ValueSource != contract.Generated || v.Retained != nil) {
			return nil, refused(InvalidIntent)
		}
		if len(v.Recipients) == 0 || len(v.Recipients) > contract.CryptoMaxValueEntryRecipients {
			return nil, refused(InvalidIntent)
		}
		authority := false
		for j, id := range v.Recipients {
			r := c.proposedRecipient(id)
			if id.IsZero() || j > 0 && bytes.Compare(v.Recipients[j-1][:], id[:]) >= 0 || r == nil || r.Status != format.Current || r.CurrentBinding == nil {
				return nil, refused(InvalidIntent)
			}
			authority = authority || id == s.admission.recipient
		}
		if !authority {
			return nil, refused(InvalidIntent)
		}
		memberships += len(v.Recipients)
		if memberships > contract.CryptoMaxMemberships {
			return nil, refused(CapacityExceeded)
		}
		var n int
		if v.ConfidentialityClass == contract.Plain {
			content, err := contract.InputContentLength(v.InputEncoding, v.InputBytes)
			if err == contract.ErrRecordCapacity {
				return nil, refused(CapacityExceeded)
			}
			if err != nil {
				return nil, refused(InvalidIntent)
			}
			n = int(content)
		}
		if v.Retained != nil {
			if v.ValueSource != contract.Supplied || v.ConfidentialityClass != contract.Secret || len(v.InputBytes) != 0 || v.Retained.Incarnation.IsZero() || v.Retained.Material.IsZero() {
				return nil, refused(InvalidIntent)
			}
			entry := slices.IndexFunc(s.root.Names, func(row format.NameEntry) bool { return row.Name == v.Name })
			if entry < 0 {
				return nil, refused(InvalidIntent)
			}
			old := s.valueEntry(s.root.Names[entry].Slot)
			payload, err := contract.InspectCanonicalPayload(old.ValueBytes)
			if err != nil || old.ValueSource != contract.Supplied || old.ConfidentialityClass != contract.Secret || old.InputEncoding != v.InputEncoding || old.Incarnation != v.Retained.Incarnation || old.ValueState != v.Retained.Material {
				return nil, refused(InvalidIntent)
			}
			pin := *v.Retained
			desiredEntries[i].Retained = &pin
			desiredEntries[i].InputBytes = old.ValueBytes
			n = int(payload.ContentLength)
		} else if v.ValueSource == contract.Generated {
			entry := slices.IndexFunc(s.root.Names, func(row format.NameEntry) bool { return row.Name == v.Name })
			if entry < 0 {
				return nil, refused(InvalidIntent)
			}
			old := s.valueEntry(s.root.Names[entry].Slot)
			payload, err := contract.InspectCanonicalPayload(v.InputBytes)
			if err != nil || old.ValueSource != contract.Generated || old.InputEncoding != v.InputEncoding || !bytes.Equal(v.InputBytes, old.ValueBytes) {
				return nil, refused(InvalidIntent)
			}
			if v.Generated != nil {
				intent, err := contract.GeneratorIntentDigest(v.Generated.Intent)
				if err != nil || !generatedEpochValid(old, contract.GeneratorValueEntryPlan{Epoch: v.Generated.Epoch, IntentDigest: intent, InputEncoding: v.InputEncoding, OutputEncoding: v.OutputEncoding}, *v.Generated) {
					return nil, refused(InvalidIntent)
				}
			}
			n = int(payload.ContentLength)
		} else if v.ConfidentialityClass == format.Secret {
			source, err := contract.InspectSealedInputEnvelope(v.InputBytes)
			if err != nil {
				return nil, refused(InvalidIntent)
			}
			if source.Core.DomainID != s.admission.domain || source.Core.CompatibilityID != contract.CompatibilityID() || !bytes.Equal(source.Core.Name, []byte(v.Name)) {
				return nil, refused(InvalidIntent)
			}
			refs := make([]contract.RecipientBindingReference, len(v.Recipients))
			for i, recipient := range v.Recipients {
				r := c.proposedRecipient(recipient)
				if r == nil || r.CurrentBinding == nil {
					return nil, refused(InvalidIntent)
				}
				digest, err := contract.PublicBindingDigest(*r.CurrentBinding)
				if err != nil {
					return nil, refused(InvalidIntent)
				}
				refs[i] = contract.RecipientBindingReference{RecipientID: recipient, PublicBindingDigest: digest}
			}
			bindingSet, err := contract.IntendedRecipientBindingSetDigest(s.admission.domain, s.admission.recipient, refs)
			if err != nil {
				return nil, refused(InvalidIntent)
			}
			if bindingSet != source.Core.IntendedRecipientBindingSetDigest {
				current := slices.IndexFunc(s.root.Names, func(row format.NameEntry) bool { return row.Name == v.Name })
				if current < 0 {
					return nil, refuseSealedInputBinding(v.Name, refusalDiagnostic)
				}
				before := s.valueEntry(s.root.Names[current].Slot)
				if before.ValueSource != contract.Supplied || before.ConfidentialityClass != contract.Secret || slices.ContainsFunc(v.Recipients, func(id contract.ID) bool { return !slices.Contains(before.Recipients, id) }) {
					return nil, refuseSealedInputBinding(v.Name, refusalDiagnostic)
				}
				c.equalOnlySources = append(c.equalOnlySources, v.Name)
			}
			n = int(source.Core.ContentLength)
		}
		if n > contract.CryptoMaxRawValue {
			return nil, refused(CapacityExceeded)
		}
		raw += uint64(n)
		if raw > contract.CryptoMaxRawSet {
			return nil, refused(CapacityExceeded)
		}
	}
	intent, d, err := buildEntryIntent(s.admission.domain, desiredEntries)
	if err != nil {
		return nil, refused(InvalidIntent)
	}
	d, err = contract.CompleteApplyIntentDescriptor(s.admission.domain, intent, recipients)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	c.desiredEntries, c.intent, c.desired, c.desiredLength, c.slots = desiredEntries, intent, d.Digest, d.Length, make([]uint16, len(desiredEntries))
	before := make(map[string]uint16, len(s.root.Names))
	for _, entry := range s.root.Names {
		before[entry.Name] = entry.Slot
	}
	var occupied [contract.CryptoMaxValueEntries]bool
	var additions []int
	for i, v := range desiredEntries {
		slot, retained := before[v.Name]
		if !retained {
			additions = append(additions, i)
			continue
		}
		c.slots[i] = slot
		occupied[slot] = true
		delete(before, v.Name)
		m := s.valueEntry(slot)
		if m.ConfidentialityClass != v.ConfidentialityClass {
			return nil, refused(InvalidIntent)
		}
		if m.OutputEncoding != v.OutputEncoding {
			c.entryConfigurationChanged = true
			c.touched[slot/format.PageSlots] = true
		}
		if v.InputEncoding != m.InputEncoding || v.ValueSource != m.ValueSource || !bytes.Equal(v.InputBytes, m.ValueBytes) || !slices.Equal(v.Recipients, m.Recipients) {
			c.changed = append(c.changed, slot)
			c.touched[slot/format.PageSlots] = true
		}
	}
	for _, entry := range s.root.Names {
		if _, removed := before[entry.Name]; removed {
			c.removed = append(c.removed, entry.Slot)
			c.touched[entry.Slot/format.PageSlots] = true
		}
	}
	free := 0
	for _, i := range additions {
		for occupied[free] {
			free++
		}
		slot := uint16(free)
		occupied[slot] = true
		c.slots[i] = slot
		c.added = append(c.added, slot)
		c.changed = append(c.changed, slot)
		c.touched[slot/format.PageSlots] = true
	}
	return c, s.observed(ObservedCurrent)
}

func (s *StateSession) compareResolvedEntryInputs(ctx context.Context, input []ApplyEntryInput, recipients []contract.ApplyRecipientInput) (*Comparison, Result) {
	return s.compareResolvedEntryInputsForPurpose(ctx, input, recipients, nil)
}

func (s *StateSession) compare(ctx context.Context, input []ApplyEntryInput, parent *AdmittedParentComparison) (*Comparison, Result) {
	var output *outputApplyInput
	if parent != nil {
		output = parent.output
		defer func() { parent.output = nil }()
	}
	return s.compareWithOutput(ctx, input, output, parent)
}

// compareWithOutput is the private complete-intent path. A nil output keeps
// the selected configuration when the parent supplies no desired declaration.
func (s *StateSession) compareWithOutput(ctx context.Context, input []ApplyEntryInput, output *outputApplyInput, parent *AdmittedParentComparison) (*Comparison, Result) {
	return s.compareWithOutputObserved(ctx, input, output, parent, nil)
}

func (s *StateSession) compareObserved(ctx context.Context, input []ApplyEntryInput, parent *AdmittedParentComparison) (*Comparison, Result) {
	if parent == nil || parent.used || parent.session != s || parent.crypto != nil || !validPrivateDeadline(parent.deadline) || parent.observation == nil || s == nil || parent.observation.source.DomainID != s.admission.domain || !parent.observation.source.AdmissionID.IsZero() || !parent.observation.source.SessionID.IsZero() {
		return nil, refused(AdmissionInvalid)
	}
	parent.used = true
	return s.compareWithOutputObserved(ctx, input, nil, nil, parent.observation)
}

func (s *StateSession) compareWithOutputObserved(ctx context.Context, input []ApplyEntryInput, output *outputApplyInput, parent *AdmittedParentComparison, owner *operationObservation) (*Comparison, Result) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, refused(AdmissionInvalid)
	}
	recipients := currentApplyRecipients(s.registry())
	if parent != nil && parent.recipients != nil {
		recipients = parent.recipients
	}
	var access *contract.CryptoSecretAccessIntent
	var retirement *contract.RecipientRetirementRow
	if parent != nil {
		access, retirement = parent.secretAccess, parent.retirement
	}
	c, res := s.compareEntryInputsForMutation(ctx, input, recipients, access, retirement, nil)
	if c == nil {
		return nil, res
	}
	if result := s.compareOutput(ctx, c, output); result.Outcome != 0 {
		return nil, result
	}
	if parent != nil && parent.support != nil {
		support, err := s.supportDescriptor()
		access, accessErr := contract.AccessRoot(parent.support.BeforeAccess)
		if err != nil || accessErr != nil || access != s.root.CurrentAccess.AccessRoot || len(parent.support.CurrentGenerated) != int(s.root.Generated.GeneratedCurrent) || parent.session != s || parent.support.BeforeRootDigest != s.head.Core.Root.Digest || parent.support.BeforeSnapshot != s.root.Snapshot || parent.support.BeforeSliceSnapshot != s.adminIndex.SliceSnapshot || parent.support.BeforeSupport != support || parent.support.IntentError(c.intent) != nil {
			return nil, refused(AdmissionInvalid)
		}
		if c.outputChanged {
			expected, err := s.normalOutputTransition(ctx, c)
			if err != nil || parent.support.Output == nil || !expected.Equal(parent.support.Output) {
				return nil, refused(AdmissionInvalid)
			}
		} else if parent.support.Output != nil {
			return nil, refused(AdmissionInvalid)
		}
		c.support = parent.support
	} else if !s.onlyOutputConfigurationSupport() {
		return nil, refused(AdmissionInvalid)
	}
	secret := c.requiresCrypto()
	if secret {
		if parent == nil || parent.used || parent.session != s || parent.crypto == nil || parent.instance.IsZero() || parent.instance != parent.crypto.InstanceID() || !validPrivateDeadline(parent.deadline) || parent.context.Expiry != uint64(parent.deadline.UnixNano()) {
			return nil, refused(AdmissionInvalid)
		}
		q, ok := s.comparisonRequest(c, parent.context)
		if !ok || c.support != nil && c.support.CurrentError(q.Current) != nil {
			return nil, refused(AdmissionInvalid)
		}
		body, err := contract.EncodeCryptoCompareRequest(q)
		if err != nil || len(body) != parent.requestLength || contract.Hash(body) != parent.requestDigest {
			return nil, refused(AdmissionInvalid)
		}
		parent.used = true
		op := &cryptoOperation{observation: parent.observation, source: exchangeSource(q.Context), adapter: parent.crypto, instance: parent.instance, context: q.Context, deadline: parent.deadline, bindings: q.Bindings, authority: s.admission.recipient, sourceCount: comparisonPrivateSourceCount(q), qualificationCounts: c.qualificationCounts()}
		reply, result := op.exchange(ctx, contract.CryptoCompare, body)
		if result.Outcome != 0 {
			return nil, result
		}
		compared, err := contract.DecodeCryptoCompareResult(reply.Body)
		if err != nil || !comparisonMatches(c, compared) {
			op.terminal = true
			return nil, refused(AdmissionInvalid)
		}
		op.operationRef, op.comparisonDigest = compared.OperationRef, compared.ComparisonDigest
		c.operation = op
		c.applySecretComparison(compared.Rows)
	} else if parent != nil && (c.support == nil || parent.used || parent.crypto != nil || !validPrivateDeadline(parent.deadline)) {
		return nil, refused(AdmissionInvalid)
	} else if parent != nil {
		parent.used = true
	}
	if parent != nil {
		c.observation = parent.observation
	} else {
		c.observation = owner
	}
	if c.observation.enabled() {
		c.observation.offerChange(ctx, comparisonObservation(c))
	}
	unchanged := len(c.changed)+len(c.removed)+len(c.recipientChanges) == 0 && !c.outputChanged && !c.entryConfigurationChanged
	if unchanged || !s.root.Generated.ActiveOwner.IsZero() {
		if c.operation != nil {
			body, err := contract.EncodeCryptoDiscardRequest(contract.CryptoDiscardRequest{OperationRef: c.operation.operationRef, Context: c.operation.context})
			if err != nil {
				return nil, refused(AdmissionInvalid)
			}
			if _, result := c.operation.exchange(ctx, contract.CryptoDiscard, body); result.Outcome != 0 {
				return nil, result
			}
		}
		if unchanged {
			if parent != nil && parent.trackNoWork {
				public, err := s.publicStateProjection()
				if err != nil {
					return nil, installedApplyPreparationFailure(err)
				}
				current, err := contract.PublicStateDescriptor(public)
				if err != nil {
					return nil, installedApplyPreparationFailure(err)
				}
				intent := contract.DescriptorVector{Digest: c.desired, Length: c.desiredLength, Count: uint32(len(c.intent))}
				basis, err := contract.SuppliedApplyNoWorkBasis(s.admission.domain, intent, current, c.secretRows)
				if err != nil {
					return nil, installedApplyPreparationFailure(err)
				}
				parent.noWorkBasis, parent.noWorkIntent = basis, intent
			}
			return nil, s.observed(Unchanged)
		}
		result := s.observed(Contention)
		result.Reason = DifferentSelection
		return nil, result
	}
	if c.support != nil {
		if _, err := contract.GeneratedNormalCapacityDescriptor(contract.GeneratedNormalCapacity{Schema: 1, BeforeRootDigest: c.support.BeforeRootDigest, TransitionID: s.root.Transition, Intent: contract.DescriptorVector{Digest: c.desired, Length: c.desiredLength, Count: uint32(len(c.intent))}, Groups: c.support.Groups}); err != nil {
			return nil, refused(CapacityExceeded)
		}
	}
	owned, err := ownApplyRecipients(c.recipients)
	if err != nil {
		return nil, installedApplyPreparationFailure(err)
	}
	c.recipients = owned
	for i := range c.desiredEntries {
		c.desiredEntries[i].Name = strings.Clone(c.desiredEntries[i].Name)
		c.desiredEntries[i].Recipients = slices.Clone(c.desiredEntries[i].Recipients)
		c.desiredEntries[i].InputBytes = bytes.Clone(c.desiredEntries[i].InputBytes)
		c.intent[i].Name = c.desiredEntries[i].Name
		c.intent[i].Recipients = c.desiredEntries[i].Recipients
	}
	return c, res
}

func (c *Comparison) applySecretComparison(rows []contract.CryptoComparisonRow) {
	s := c.session
	c.secretRows = rows
	c.changed = slices.DeleteFunc(c.changed, func(slot uint16) bool {
		m := s.valueEntry(slot)
		if m == nil || slices.Contains(c.added, slot) {
			return false
		}
		return slices.ContainsFunc(rows, func(row contract.CryptoComparisonRow) bool {
			if c.secretAccess != nil && c.secretAccess.OperationKind == contract.OperationEnvelopeRekey && c.secretAccess.Target.Slot == slot || row.Name != m.Name || row.Relation != contract.CryptoEqual {
				return false
			}
			i := slices.IndexFunc(c.desiredEntries, func(v ApplyEntryInput) bool { return v.Name == row.Name })
			return i >= 0 && m.ValueSource == c.desiredEntries[i].ValueSource && slices.Equal(m.Recipients, c.desiredEntries[i].Recipients)
		})
	})
	c.touched = [contract.MaxValueEntryPages]bool{}
	for _, slot := range c.changed {
		c.touched[slot/format.PageSlots] = true
	}
	for _, slot := range c.removed {
		c.touched[slot/format.PageSlots] = true
	}
	for i, after := range c.desiredEntries {
		before := s.valueEntry(c.slots[i])
		if before != nil && before.OutputEncoding != after.OutputEncoding {
			c.touched[c.slots[i]/format.PageSlots] = true
		}
	}
}

func (c *Comparison) needsFreshValue(slot uint16) bool {
	if c.secretAccess != nil && c.secretAccess.Target.Slot == slot {
		return true
	}
	if c.retirement != nil {
		before := c.session.valueEntry(slot)
		if before != nil && before.ConfidentialityClass == contract.Secret && slices.Contains(before.Recipients, c.retirement.RecipientID) {
			return true
		}
	}
	if slices.Contains(c.added, slot) {
		return true
	}
	before := c.session.valueEntry(slot)
	for _, after := range c.desiredEntries {
		if after.Name != before.Name {
			continue
		}
		if after.ValueSource != before.ValueSource || after.InputEncoding != before.InputEncoding {
			return true
		}
		if after.ConfidentialityClass == format.Plain {
			return !bytes.Equal(before.ValueBytes, after.InputBytes)
		}
		return slices.ContainsFunc(c.secretRows, func(row contract.CryptoComparisonRow) bool {
			return row.Name == after.Name && (row.Relation == contract.CryptoChanged || !row.ExclusionPathDigest.IsZero())
		})
	}
	return false
}

func comparisonMatches(c *Comparison, got contract.CryptoCompareResult) bool {
	if c.secretAccess != nil {
		return secretAccessComparisonMatches(c, got)
	}
	wants := make(map[string]contract.CryptoComparisonRow)
	for _, entry := range c.session.root.Names {
		m := c.session.valueEntry(entry.Slot)
		if m.ConfidentialityClass == format.Secret && (c.retirement == nil || slices.Contains(m.Recipients, c.retirement.RecipientID)) {
			wants[m.Name] = contract.CryptoComparisonRow{Name: m.Name, BeforePresent: true, Relation: contract.CryptoRemoved, BeforePublicEntryDigest: publicEntryDigest(c.session.admission.domain, entry.Slot, m)}
		}
	}
	for _, intent := range c.intent {
		if intent.ConfidentialityClass != format.Secret {
			continue
		}
		if c.retirement != nil {
			if _, target := wants[intent.Name]; !target {
				continue
			}
		}
		row := wants[intent.Name]
		row.Name, row.AfterPresent, row.SourceDigest, row.AfterRawLength = intent.Name, true, intent.PayloadDigest, intent.ContentLength
		row.Relation = contract.CryptoAdded
		wants[intent.Name] = row
	}
	if len(wants) != len(got.Rows) || got.OperationRef.IsZero() {
		return false
	}
	for _, row := range got.Rows {
		if slices.Contains(c.equalOnlySources, row.Name) && row.Relation != contract.CryptoEqual {
			return false
		}
		if c.retirement != nil && row.Relation != contract.CryptoEqual {
			return false
		}
		want, ok := wants[row.Name]
		if !ok {
			return false
		}
		if want.BeforePresent && want.AfterPresent {
			if row.Relation != contract.CryptoEqual && row.Relation != contract.CryptoChanged {
				return false
			}
			want.Relation = row.Relation
			if slices.ContainsFunc(c.intent, func(v contract.CryptoIntentRow) bool {
				return v.Name == row.Name && v.ValueSource == contract.Generated
			}) && row.Relation != contract.CryptoEqual {
				return false
			}
		}
		if want.BeforePresent {
			var after []contract.ID
			for _, v := range c.desiredEntries {
				if v.Name == row.Name {
					after = v.Recipients
					break
				}
			}
			for _, entry := range c.session.root.Names {
				if entry.Name != row.Name {
					continue
				}
				old := c.session.valueEntry(entry.Slot)
				sourceChange := slices.ContainsFunc(c.desiredEntries, func(v ApplyEntryInput) bool { return v.Name == old.Name && v.ValueSource != old.ValueSource })
				excluded := sourceChange || slices.ContainsFunc(old.Recipients, func(id contract.ID) bool { return !slices.Contains(after, id) })
				if excluded == row.ExclusionPathDigest.IsZero() {
					return false
				}
				want.ExclusionPathDigest = row.ExclusionPathDigest
			}
		}
		if row != want {
			return false
		}
		delete(wants, row.Name)
	}
	return len(wants) == 0
}
