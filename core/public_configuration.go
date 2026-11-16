package core

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"enkv.sh/core/contract"
)

// PublicOutputInterpreter receives bounded public source facts after the
// composition admits the selected installed implementation. It grants no effect
// permission and is unnecessary for complete canonical or stored targets.
type PublicOutputInterpreter func(context.Context, string, contract.OutputDestination, string, uint8) (contract.OutputTarget, error)

// ErrPublicOutputUnavailable reports required target facts that the selected
// interpreter could not supply.
var ErrPublicOutputUnavailable = errors.New("public output interpretation unavailable")

type PublicOutputError struct{ Field contract.DiagnosticField }

func (e PublicOutputError) Error() string { return "public output field refused" }

type PublicConfigurationValidator struct{ interpret PublicOutputInterpreter }

// The result owns all returned mutable bytes and collections. Valid/Complete
// report this call only and cannot serve as Reader admission or trusted state.
type PublicConfigurationValidation struct {
	Configuration       contract.PublicConfiguration
	Diagnostics         []contract.Diagnostic
	Valid, Complete     bool
	DiagnosticsComplete bool
}

func NewPublicConfigurationValidator(interpret PublicOutputInterpreter) *PublicConfigurationValidator {
	return &PublicConfigurationValidator{interpret: interpret}
}

type publicConfigurationCheck struct {
	ctx                                                               context.Context
	result                                                            PublicConfigurationValidation
	seen                                                              map[publicDiagnosticFieldKey]bool
	invalidEntries, invalidRecipients, invalidOutputs, invalidRouting bool
}

func (c *publicConfigurationCheck) add(subject contract.DiagnosticSubject, field contract.DiagnosticField, reason contract.DiagnosticReason, location *contract.SourceLocation) {
	path := []contract.DiagnosticField{field}
	if subject.Kind == contract.SubjectEntry && (field == contract.FieldEpoch || field == contract.FieldResourceContract || field == contract.FieldConfigContract || field == contract.FieldLifecycle || field == contract.FieldContentIntent || field == contract.FieldRetirement || field == contract.FieldCompletion) {
		path = []contract.DiagnosticField{contract.FieldGenerated, field}
	}
	key := publicDiagnosticFieldKey{subject: subject, field: field}
	invalid := reason != contract.ReasonPublicFactUnavailable && reason != contract.ReasonUnsupportedProfile && reason != contract.ReasonUnsupportedSchema
	if invalid {
		c.result.Valid = false
	}
	priorInvalid, reported := c.seen[key]
	if reported && (!invalid || priorInvalid) {
		return
	}
	var source *contract.SourceLocation
	if publicSourceLocationValid(location) && location != nil {
		owned := *location
		owned.SourceID = strings.Clone(owned.SourceID)
		source = &owned
	}
	if reported {
		c.seen[key] = true
		for i := range c.result.Diagnostics {
			row := &c.result.Diagnostics[i]
			if row.Subject == subject && slices.Equal(row.Path, path) && row.Reason != contract.ReasonDiagnosticsIncomplete {
				row.Reason, row.SourceLocation = reason, source
				break
			}
		}
		return
	}
	if c.seen == nil {
		c.seen = make(map[publicDiagnosticFieldKey]bool)
	}
	c.seen[key] = invalid
	c.result.Complete = false
	if len(c.result.Diagnostics) == contract.MaxPublicDiagnostics {
		c.result.Valid = false
		c.result.DiagnosticsComplete = false
		c.result.Diagnostics[len(c.result.Diagnostics)-1] = contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDiagnosticsIncomplete}
		return
	}
	subject.Name = strings.Clone(subject.Name)
	subject.DestinationID = strings.Clone(subject.DestinationID)
	subject.RoutingKey.EntryName = strings.Clone(subject.RoutingKey.EntryName)
	// Controlled growth keeps descriptor backing below twice the current row
	// count. A later Reader comparison transfers the owned bodies into one exact
	// result allocation; validation and result backing share one diagnostic account.
	if len(c.result.Diagnostics) == cap(c.result.Diagnostics) {
		capacity := max(1, 2*len(c.result.Diagnostics))
		capacity = min(capacity, contract.MaxPublicDiagnostics)
		next := make([]contract.Diagnostic, len(c.result.Diagnostics), capacity)
		copy(next, c.result.Diagnostics)
		c.result.Diagnostics = next
	}
	c.result.Diagnostics = append(c.result.Diagnostics, contract.Diagnostic{Subject: subject, Path: path, Outcome: contract.DiagnosticUnable, Reason: reason, SourceLocation: source})
}

type publicDiagnosticFieldKey struct {
	subject contract.DiagnosticSubject
	field   contract.DiagnosticField
}

func publicSourceLocationValid(v *contract.SourceLocation) bool {
	if v == nil {
		return true
	}
	if len(v.SourceID) == 0 || len(v.SourceID) > 64 || v.Line == 0 || v.Column == 0 {
		return false
	}
	for _, b := range []byte(v.SourceID) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '-' && b != '.' {
			return false
		}
	}
	return true
}

func checkPublicField[T any](c *publicConfigurationCheck, subject contract.DiagnosticSubject, field contract.DiagnosticField, v contract.PublicField[T], check func(T) contract.DiagnosticReason) bool {
	if !publicSourceLocationValid(v.SourceLocation) {
		c.add(subject, field, contract.ReasonInvalidInput, nil)
		return false
	}
	switch v.State {
	case contract.PublicMissing, contract.PublicUnavailable:
		if !reflect.ValueOf(&v.Value).Elem().IsZero() {
			c.add(subject, field, contract.ReasonInvalidFieldCombination, v.SourceLocation)
			return false
		}
		reason := contract.ReasonMissingRequiredField
		if v.State == contract.PublicUnavailable {
			reason = contract.ReasonPublicFactUnavailable
		}
		c.add(subject, field, reason, v.SourceLocation)
		return false
	case contract.PublicPresent:
		if check != nil {
			if reason := check(v.Value); reason != "" {
				c.add(subject, field, reason, v.SourceLocation)
				return false
			}
		}
		return true
	default:
		c.add(subject, field, contract.ReasonInvalidInput, v.SourceLocation)
		return false
	}
}

func publicIdentifier(s string) bool {
	return len(s) > 0 && len(s) <= contract.CryptoMaxName && utf8.ValidString(s)
}
func publicNameReason(s string) contract.DiagnosticReason {
	if len(s) > contract.CryptoMaxName {
		return contract.ReasonLimitExceeded
	}
	if !utf8.ValidString(s) {
		return contract.ReasonInvalidUTF8
	}
	return ""
}
func publicIdentifierReason(s string) contract.DiagnosticReason {
	if r := publicNameReason(s); r != "" {
		return r
	}
	if s == "" {
		return contract.ReasonInvalidInput
	}
	return ""
}
func publicCoordinateReason(s string) contract.DiagnosticReason {
	if len(s) > 1024 {
		return contract.ReasonLimitExceeded
	}
	if !utf8.ValidString(s) {
		return contract.ReasonInvalidUTF8
	}
	if s == "" {
		return contract.ReasonInvalidInput
	}
	return ""
}
func publicOutputBoundsReason(bounds contract.OutputPayloadBounds) contract.DiagnosticReason {
	if bounds.Maximum > contract.CryptoMaxRawValue {
		return contract.ReasonLimitExceeded
	}
	if bounds.Minimum > bounds.Maximum {
		return contract.ReasonInvalidInput
	}
	return ""
}

func publicIDReason(id contract.ID) contract.DiagnosticReason {
	if id.IsZero() {
		return contract.ReasonInvalidInput
	}
	return ""
}
func publicFamilyReason(f contract.Family) contract.DiagnosticReason {
	if !f.Valid() {
		return contract.ReasonInvalidInput
	}
	return ""
}
func publicContextReason(err error) contract.DiagnosticReason {
	if errors.Is(err, context.DeadlineExceeded) {
		return contract.ReasonExpired
	}
	return contract.ReasonCancelled
}

func publicErrorReason(err error) contract.DiagnosticReason {
	if errors.Is(err, contract.ErrRecordCapacity) {
		return contract.ReasonLimitExceeded
	}
	if err != nil {
		return contract.ReasonInvalidInput
	}
	return ""
}

func publicIDsReason(ids []contract.ID) contract.DiagnosticReason {
	for i, id := range ids {
		if id.IsZero() {
			return contract.ReasonInvalidInput
		}
		if i > 0 && id == ids[i-1] {
			return contract.ReasonDuplicateMember
		}
	}
	return ""
}

// Validate borrows stable input through capture and returns independently owned
// public facts. Callers must not change its backing while this call runs.
func (v *PublicConfigurationValidator) Validate(ctx context.Context, input contract.PublicConfiguration) PublicConfigurationValidation {
	c := publicConfigurationCheck{ctx: ctx, result: PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}}
	configuration := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
	if ctx == nil {
		c.add(configuration, contract.FieldPresence, contract.ReasonCancelled, nil)
		return c.result
	}
	if err := ctx.Err(); err != nil {
		c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
		return c.result
	}
	if v == nil {
		c.add(configuration, contract.FieldPresence, contract.ReasonUnsupportedProfile, nil)
		return c.result
	}
	if !publicConfigurationInputLimits(&c, input) {
		slices.SortFunc(c.result.Diagnostics, comparePublicDiagnostics)
		return c.result
	}
	if !publicConfigurationBounded(input) || !publicConfigurationBackingBounded(input) {
		c.add(configuration, contract.FieldPresence, contract.ReasonLimitExceeded, nil)
		return c.result
	}
	return v.validateOwned(ctx, ownPublicConfiguration(input))
}

// validateOwned consumes exclusively owned, bounded backing. It runs the same
// field owners as Validate without making a second complete projection.
func (v *PublicConfigurationValidator) validateOwned(ctx context.Context, owned contract.PublicConfiguration) PublicConfigurationValidation {
	c := publicConfigurationCheck{ctx: ctx, result: PublicConfigurationValidation{Valid: true, Complete: true, DiagnosticsComplete: true}}
	configuration := contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}
	if ctx == nil {
		c.add(configuration, contract.FieldPresence, contract.ReasonCancelled, nil)
		return c.result
	}
	if err := ctx.Err(); err != nil {
		c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)
		return c.result
	}
	if v == nil {
		c.add(configuration, contract.FieldPresence, contract.ReasonUnsupportedProfile, nil)
		return c.result
	}
	c.checkStore(owned.Store)
	authority := contract.DiagnosticSubject{Kind: contract.SubjectAuthority}
	authorityOK := checkPublicField(&c, authority, contract.FieldRecipientID, owned.Authority.RecipientID, publicIDReason)
	c.checkSigning(authority, owned.Authority.Signing, contract.NormalSigningRole)
	c.checkRecovery(owned.Recovery)
	entriesOK := checkPublicField(&c, configuration, contract.FieldPresence, owned.Entries, nil)
	if !entriesOK && (owned.Entries.State != contract.PublicUnavailable || owned.Entries.Value != nil || !publicSourceLocationValid(owned.Entries.SourceLocation)) {
		c.invalidEntries = true
	}
	recipientsSubject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient}
	recipientsOK := checkPublicField(&c, recipientsSubject, contract.FieldPresence, owned.Recipients, nil)
	bindingsOK := checkPublicField(&c, contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding}, contract.FieldPresence, owned.OutputBindings, nil)
	routesOK := checkPublicField(&c, contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule}, contract.FieldPresence, owned.Routing, nil)
	if owned.Groups.State != contract.PublicMissing {
		checkPublicField(&c, configuration, contract.FieldGroups, owned.Groups, nil)
	}
	recipients := make(map[contract.ID]bool)
	if recipientsOK {
		c.checkRecipients(owned.Recipients.Value, recipients)
	}
	c.checkRelations(owned)
	if authorityOK && recipientsOK && !recipients[owned.Authority.RecipientID.Value] {
		c.add(authority, contract.FieldRecipientID, contract.ReasonUnresolvedReference, owned.Authority.RecipientID.SourceLocation)
	}
	entries := make(map[string]bool)
	if entriesOK {
		v.checkEntries(&c, owned.Entries.Value, entries, recipients, recipientsOK, owned.Authority.RecipientID, authorityOK)
	}
	targets := make(map[string]map[string]bool)
	if bindingsOK {
		v.checkOutputs(&c, owned.OutputBindings.Value, entries, entriesOK, targets)
	}
	if routesOK {
		c.checkRoutes(owned.Routing.Value, entries, entriesOK, targets, bindingsOK)
		if !c.invalidRouting {
			normalizePublicDefaultRoute(&c, &owned)
		}
	}
	if c.result.Valid && c.result.Complete && ctx.Err() == nil {
		if !v.normalizePublicOutputs(&c, &owned) {
			slices.SortFunc(c.result.Diagnostics, comparePublicDiagnostics)
			return c.result
		}
	}
	if err := ctx.Err(); err != nil {
		c.add(configuration, contract.FieldPresence, publicContextReason(err), nil)

	}
	slices.SortFunc(c.result.Diagnostics, comparePublicDiagnostics)
	c.cleanConfiguration(&owned)
	c.result.Configuration = owned
	return c.result
}

func (c *publicConfigurationCheck) checkStore(s contract.PublicStoreSettings) {
	domain := contract.DiagnosticSubject{Kind: contract.SubjectDomain}
	store := contract.DiagnosticSubject{Kind: contract.SubjectStore}
	checkPublicField(c, domain, contract.FieldDomainID, s.DomainID, publicIDReason)
	providerOK := checkPublicField(c, store, contract.FieldProvider, s.Provider, publicFamilyReason)
	checkPublicField(c, store, contract.FieldConstructionProfile, s.ConstructionProfile, func(p uint16) contract.DiagnosticReason {
		if p != contract.StoreConstructionProfile {
			return contract.ReasonUnsupportedProfile
		}
		return ""
	})
	for _, field := range []struct {
		name  contract.DiagnosticField
		value contract.PublicField[string]
	}{{contract.FieldRegion, s.Region}, {contract.FieldBucket, s.Bucket}, {contract.FieldPrefix, s.Prefix}, {contract.FieldExpectedOwner, s.ExpectedOwner}} {
		ready := checkPublicField(c, store, field.name, field.value, nil)
		if !ready {
			continue
		}
		accepts := func(provider contract.Family) bool {
			switch field.name {
			case contract.FieldRegion:
				return contract.StoreRegionValid(provider, field.value.Value)
			case contract.FieldBucket:
				return contract.StoreBucketValid(provider, field.value.Value)
			case contract.FieldPrefix:
				return contract.StorePrefixValid(provider, field.value.Value)
			case contract.FieldExpectedOwner:
				return contract.StoreExpectedOwnerValid(provider, field.value.Value) && (provider != contract.AWS || field.value.Value != "")
			default:
				return false
			}
		}
		valid := false
		if providerOK {
			valid = accepts(s.Provider.Value)
		} else {
			valid = accepts(contract.AWS) || accepts(contract.GCP)
		}

		if !valid {
			c.add(store, field.name, contract.ReasonInvalidInput, field.value.SourceLocation)
		}
	}

}

func (c *publicConfigurationCheck) checkSigning(subject contract.DiagnosticSubject, s contract.PublicSigningSettings, role uint8) {
	providerOK := checkPublicField(c, subject, contract.FieldSigningProvider, s.Provider, publicFamilyReason)
	selectorOK := checkPublicField(c, subject, contract.FieldSigningSelector, s.Selector, publicCoordinateReason)
	keyOK := checkPublicField(c, subject, contract.FieldSigningPublicKey, s.PublicKey, func(b []byte) contract.DiagnosticReason {
		return publicErrorReason(contract.ValidateSigningPublicKey(b))
	})
	fingerprintOK := checkPublicField(c, subject, contract.FieldSigningFingerprint, s.Fingerprint, publicIDReason)
	checkPublicField(c, subject, contract.FieldSigningRole, s.Role, func(v uint8) contract.DiagnosticReason {
		if v != role {
			return contract.ReasonInvalidInput
		}
		return ""
	})
	checkPublicField(c, subject, contract.FieldSigningProfile, s.Profile, func(v uint16) contract.DiagnosticReason {
		if v != contract.P256SigningProfile {
			return contract.ReasonUnsupportedProfile
		}
		return ""
	})
	if providerOK && selectorOK && !contract.PublicKeySelectorValid(s.Provider.Value, s.Selector.Value, true) {
		c.add(subject, contract.FieldSigningSelector, contract.ReasonInvalidInput, s.Selector.SourceLocation)
	}
	if keyOK && fingerprintOK && contract.Hash(s.PublicKey.Value) != s.Fingerprint.Value {
		c.add(subject, contract.FieldSigningFingerprint, contract.ReasonInvalidInput, s.Fingerprint.SourceLocation)
	}
}

func (c *publicConfigurationCheck) checkEncryption(subject contract.DiagnosticSubject, s contract.PublicEncryptionSettings) {
	providerOK := checkPublicField(c, subject, contract.FieldEncryptionProvider, s.Provider, publicFamilyReason)
	selectorOK := checkPublicField(c, subject, contract.FieldEncryptionSelector, s.Selector, publicCoordinateReason)
	keyOK := checkPublicField(c, subject, contract.FieldEncryptionPublicKey, s.PublicKey, func(b []byte) contract.DiagnosticReason {
		return publicErrorReason(contract.ValidateEncryptionPublicKey(b))
	})
	fingerprintOK := checkPublicField(c, subject, contract.FieldEncryptionFingerprint, s.Fingerprint, publicIDReason)
	checkPublicField(c, subject, contract.FieldWrapProfile, s.WrapProfile, func(v uint16) contract.DiagnosticReason {
		if v != contract.RSAOAEPWrapProfile {
			return contract.ReasonUnsupportedProfile
		}
		return ""
	})
	checkPublicField(c, subject, contract.FieldProtectionClass, s.ProtectionClass, func(v uint8) contract.DiagnosticReason {
		if v != contract.HardwareProtection && v != contract.SoftwareProtection {
			return contract.ReasonInvalidInput
		}
		return ""
	})
	if providerOK && selectorOK && !contract.PublicKeySelectorValid(s.Provider.Value, s.Selector.Value, false) {
		c.add(subject, contract.FieldEncryptionSelector, contract.ReasonInvalidInput, s.Selector.SourceLocation)
	}
	if keyOK && fingerprintOK && contract.Hash(s.PublicKey.Value) != s.Fingerprint.Value {
		c.add(subject, contract.FieldEncryptionFingerprint, contract.ReasonInvalidInput, s.Fingerprint.SourceLocation)
	}
}

func (c *publicConfigurationCheck) checkRecovery(r contract.PublicRecoverySettings) {
	subject := contract.DiagnosticSubject{Kind: contract.SubjectRecovery}
	enabledReady := checkPublicField(c, subject, contract.FieldEnabled, r.Enabled, nil)
	if enabledReady && !r.Enabled.Value {
		if r.Signing != nil || r.Encryption != nil {
			c.add(subject, contract.FieldEnabled, contract.ReasonInvalidFieldCombination, r.Enabled.SourceLocation)
		}
		return
	}
	if r.Signing == nil {
		if enabledReady {
			c.add(subject, contract.FieldSigningPublicKey, contract.ReasonMissingRequiredField, nil)
		}
	} else {
		c.checkSigning(subject, *r.Signing, contract.RecoverySigningRole)
	}
	if r.Encryption == nil {
		if enabledReady {
			c.add(subject, contract.FieldEncryptionPublicKey, contract.ReasonMissingRequiredField, nil)
		}
	} else {
		c.checkEncryption(subject, *r.Encryption)
	}
}

func (c *publicConfigurationCheck) checkRecipients(rows []contract.PublicRecipient, ids map[contract.ID]bool) {
	for _, row := range rows {
		subject := contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: row.RecipientID}
		if row.RecipientID.IsZero() {
			c.invalidRecipients = true
			c.add(subject, contract.FieldPresence, contract.ReasonInvalidInput, nil)
		} else if ids[row.RecipientID] {
			c.invalidRecipients = true
			c.add(subject, contract.FieldPresence, contract.ReasonDuplicateKey, nil)
		}
		ids[row.RecipientID] = true
		checkPublicField(c, subject, contract.FieldDisplayName, row.DisplayName, publicNameReason)
		c.checkEncryption(subject, row.Encryption)
	}
}

func (v *PublicConfigurationValidator) checkEntries(c *publicConfigurationCheck, rows []contract.PublicEntry, names map[string]bool, recipients map[contract.ID]bool, recipientsOK bool, authority contract.PublicField[contract.ID], authorityOK bool) {
	for index := range rows {
		row := &rows[index]
		if c.ctx.Err() != nil {
			return
		}
		subject := contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: row.Name}
		if reason := publicNameReason(row.Name); reason != "" {
			c.add(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence, reason, nil)
			c.invalidEntries = true
			continue
		}
		if names[row.Name] {
			c.invalidEntries = true
			c.add(subject, contract.FieldPresence, contract.ReasonDuplicateKey, nil)
		}
		names[row.Name] = true
		if row.PlainValue.State != contract.PublicMissing && row.PlainValue.State != contract.PublicPresent && row.PlainValue.State != contract.PublicUnavailable {
			c.add(subject, contract.FieldPlainValue, contract.ReasonInvalidFieldCombination, row.PlainValue.SourceLocation)
		}
		if !publicSourceLocationValid(row.PlainValue.SourceLocation) {
			c.add(subject, contract.FieldPlainValue, contract.ReasonInvalidInput, nil)
		}
		for _, field := range []struct {
			value       *contract.PublicField[uint8]
			name        contract.DiagnosticField
			raw, base64 uint8
		}{
			{&row.InputEncoding, contract.FieldInputEncoding, contract.InputEncodingRaw, contract.InputEncodingBase64},
			{&row.OutputEncoding, contract.FieldOutputEncoding, contract.OutputEncodingRaw, contract.OutputEncodingBase64},
		} {
			if field.value.State == contract.PublicMissing && field.value.Value == 0 && field.value.SourceLocation == nil {
				field.value.State, field.value.Value = contract.PublicPresent, field.raw
			}
			checkPublicField(c, subject, field.name, *field.value, func(tag uint8) contract.DiagnosticReason {
				if tag != field.raw && tag != field.base64 {
					return contract.ReasonInvalidInput
				}
				return ""
			})
		}
		classOK := checkPublicField(c, subject, contract.FieldClass, row.Class, func(v uint8) contract.DiagnosticReason {
			if v != contract.Plain && v != contract.Secret {
				return contract.ReasonInvalidInput
			}
			return ""
		})
		sourceOK := checkPublicField(c, subject, contract.FieldSource, row.Source, func(v uint8) contract.DiagnosticReason {
			if v != contract.Supplied && v != contract.Generated {
				return contract.ReasonInvalidInput
			}
			return ""
		})
		membersOK := checkPublicField(c, subject, contract.FieldMemberships, row.Memberships, func(ids []contract.ID) contract.DiagnosticReason {
			if len(ids) == 0 {
				return contract.ReasonUnresolvedReference
			}
			return publicIDsReason(ids)
		})
		if membersOK {
			if authorityOK && !slices.Contains(row.Memberships.Value, authority.Value) {
				c.add(subject, contract.FieldMemberships, contract.ReasonUnresolvedReference, row.Memberships.SourceLocation)
			}
			if recipientsOK {
				for _, id := range row.Memberships.Value {
					if !recipients[id] {
						c.add(subject, contract.FieldMemberships, contract.ReasonUnresolvedReference, row.Memberships.SourceLocation)
					}
				}
			}
		}
		if classOK && sourceOK && !contract.ValidatePublicEntryTags(row.Source.Value, row.Class.Value) {
			c.add(subject, contract.FieldSource, contract.ReasonInvalidFieldCombination, row.Source.SourceLocation)
		}
		if classOK && row.Class.Value == contract.Plain {
			checkPublicField(c, subject, contract.FieldPlainValue, row.PlainValue, func(body []byte) contract.DiagnosticReason {
				if _, err := contract.InputContentLength(row.InputEncoding.Value, body); err != nil {
					return contract.ReasonInvalidInput
				}
				return ""
			})
		} else if classOK && (row.PlainValue.State != contract.PublicMissing || row.PlainValue.Value != nil || row.PlainValue.SourceLocation != nil) {
			c.add(subject, contract.FieldPlainValue, contract.ReasonInvalidFieldCombination, row.PlainValue.SourceLocation)
		}
		if sourceOK && row.Source.Value == contract.Generated {
			if row.Generated == nil {
				c.add(subject, contract.FieldContentIntent, contract.ReasonMissingRequiredField, nil)
			} else {
				v.checkGenerated(c, subject, *row.Generated)
			}
		} else if sourceOK && row.Generated != nil {
			c.add(subject, contract.FieldSource, contract.ReasonInvalidFieldCombination, row.Source.SourceLocation)
		} else if !sourceOK && row.Generated != nil {
			v.checkGenerated(c, subject, *row.Generated)
		}
	}
}

func (v *PublicConfigurationValidator) checkGenerated(c *publicConfigurationCheck, subject contract.DiagnosticSubject, g contract.PublicGeneratedSettings) {
	checkPublicField(c, subject, contract.FieldEpoch, g.Epoch, nil)
	configOK := checkPublicField(c, subject, contract.FieldConfigContract, g.ConfigContractID, publicIDReason)
	resourceOK := checkPublicField(c, subject, contract.FieldResourceContract, g.ResourceContractID, nil)
	lifecycleOK := checkPublicField(c, subject, contract.FieldLifecycle, g.LifecycleMode, func(mode contract.GeneratorLifecycleMode) contract.DiagnosticReason {
		if mode != contract.GeneratorLifecycleNone && mode != contract.GeneratorLifecycleManaged {
			return contract.ReasonInvalidInput
		}
		return ""
	})
	var intent contract.GeneratorIntent
	intentOK := checkPublicField(c, subject, contract.FieldContentIntent, g.ContentIntent, func(body []byte) contract.DiagnosticReason {
		var err error
		intent, err = contract.InspectGeneratorIntent(body)
		return publicErrorReason(err)
	})
	if lifecycleOK {
		if resourceOK && (g.LifecycleMode.Value == contract.GeneratorLifecycleNone) != g.ResourceContractID.Value.IsZero() {
			c.add(subject, contract.FieldResourceContract, contract.ReasonInvalidFieldCombination, g.ResourceContractID.SourceLocation)
		}
		if g.LifecycleMode.Value == contract.GeneratorLifecycleNone {
			if g.Retirement != (contract.PublicField[uint8]{}) {
				c.add(subject, contract.FieldRetirement, contract.ReasonInvalidFieldCombination, g.Retirement.SourceLocation)
			}
			if g.Completion != (contract.PublicField[uint8]{}) {
				c.add(subject, contract.FieldCompletion, contract.ReasonInvalidFieldCombination, g.Completion.SourceLocation)
			}
		} else {
			checkPublicField(c, subject, contract.FieldRetirement, g.Retirement, func(x uint8) contract.DiagnosticReason {
				if x < contract.GeneratedRetirementManual || x > contract.GeneratedRetirementAuto {
					return contract.ReasonInvalidInput
				}
				return ""
			})
			checkPublicField(c, subject, contract.FieldCompletion, g.Completion, func(x uint8) contract.DiagnosticReason {
				if x != contract.GeneratedCompletionAcknowledged && x != contract.GeneratedCompletionConfirmed {
					return contract.ReasonInvalidInput
				}
				return ""
			})
		}
	}
	if intentOK {
		if configOK && intent.ConfigContractID != g.ConfigContractID.Value {
			c.add(subject, contract.FieldConfigContract, contract.ReasonInvalidFieldCombination, g.ConfigContractID.SourceLocation)
		}
		if resourceOK && intent.ResourceContractID != g.ResourceContractID.Value {
			c.add(subject, contract.FieldResourceContract, contract.ReasonInvalidFieldCombination, g.ResourceContractID.SourceLocation)
		}
		if lifecycleOK && intent.LifecycleMode != g.LifecycleMode.Value {
			c.add(subject, contract.FieldLifecycle, contract.ReasonInvalidFieldCombination, g.LifecycleMode.SourceLocation)
		}
	}
}

func (v *PublicConfigurationValidator) checkOutputs(c *publicConfigurationCheck, bindings []contract.PublicOutputBinding, entries map[string]bool, entriesOK bool, targets map[string]map[string]bool) {
	physical := make(map[struct{ service, target string }]bool)
	for _, binding := range bindings {
		subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputBinding, DestinationID: binding.DestinationID}
		if reason := publicIdentifierReason(binding.DestinationID); reason != "" {
			c.invalidOutputs = true
			c.add(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence, reason, nil)
			continue
		}
		if _, duplicate := targets[binding.DestinationID]; duplicate {
			c.invalidOutputs = true
			c.add(subject, contract.FieldPresence, contract.ReasonDuplicateKey, nil)
		}
		entryTargets := make(map[string]bool)
		targets[binding.DestinationID] = entryTargets
		destinationOK := checkPublicField(c, subject, contract.FieldDestination, binding.Destination, func(d contract.OutputDestination) contract.DiagnosticReason {
			_, err := contract.OutputDestinationLength(d)
			return publicErrorReason(err)
		})

		if binding.Targets.Value == nil && binding.Targets.State == contract.PublicUnavailable && v.interpret != nil && publicSourceLocationValid(binding.Targets.SourceLocation) {
			continue
		}
		if !checkPublicField(c, subject, contract.FieldTargets, binding.Targets, nil) {
			continue
		}
		for index := range binding.Targets.Value {
			target := &binding.Targets.Value[index]
			subject := contract.DiagnosticSubject{Kind: contract.SubjectOutputTarget, DestinationID: binding.DestinationID, Name: target.EntryName}
			if reason := publicNameReason(target.EntryName); reason != "" {
				c.invalidOutputs = true
				c.add(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence, reason, nil)
				continue
			}
			if entryTargets[target.EntryName] {
				c.invalidOutputs = true
				c.add(subject, contract.FieldPresence, contract.ReasonDuplicateKey, nil)
			}
			entryTargets[target.EntryName] = true
			if entriesOK && !entries[target.EntryName] {
				c.add(subject, contract.FieldPresence, contract.ReasonUnresolvedReference, nil)
			}
			serviceOK := checkPublicField(c, subject, contract.FieldServiceContract, target.ServiceContractID, publicIdentifierReason)
			targetOK := checkPublicField(c, subject, contract.FieldCanonicalTarget, target.CanonicalTarget, publicCoordinateReason)
			checkPublicField(c, subject, contract.FieldTargetContract, target.TargetContractID, publicIdentifierReason)
			locatorOK := checkPublicField(c, subject, contract.FieldConsumerLocator, target.ConsumerLocator, func(x string) contract.DiagnosticReason {
				if len(x) > 1024 {
					return contract.ReasonLimitExceeded
				}
				if !utf8.ValidString(x) {
					return contract.ReasonInvalidUTF8
				}
				return ""
			})
			flagOK := checkPublicField(c, subject, contract.FieldLocatorRequiresCreation, target.LocatorRequiresCreation, nil)
			if locatorOK && flagOK && target.LocatorRequiresCreation.Value != (target.ConsumerLocator.Value == "") {
				c.add(subject, contract.FieldConsumerLocator, contract.ReasonInvalidFieldCombination, target.ConsumerLocator.SourceLocation)
			}
			checkPublicField(c, subject, contract.FieldTargetData, target.TargetData, func(x []byte) contract.DiagnosticReason {
				if len(x) > contract.MaxOutputTargetDataBytes {
					return contract.ReasonLimitExceeded
				}
				return ""
			})
			checkPublicField(c, subject, contract.FieldPayloadEncoding, target.PayloadEncoding, func(x uint8) contract.DiagnosticReason {
				if x != contract.OutputEncodingRaw && x != contract.OutputEncodingBase64 {
					return contract.ReasonInvalidInput
				}
				return ""
			})
			checkPublicField(c, subject, contract.FieldCapabilities, target.Capabilities, func(x contract.OutputActionCapabilities) contract.DiagnosticReason {
				if !x.Valid() {
					return contract.ReasonInvalidInput
				}
				return ""
			})
			createBoundsOK := checkPublicField(c, subject, contract.FieldCreateValueBounds, target.CreateValueBounds, publicOutputBoundsReason)
			writeBoundsOK := checkPublicField(c, subject, contract.FieldWriteValueBounds, target.WriteValueBounds, publicOutputBoundsReason)
			if publicFieldReady(c, subject, contract.FieldCapabilities, target.Capabilities) {
				if createBoundsOK && !target.Capabilities.Value.Has(contract.PublicationCreateWithValue) && target.CreateValueBounds.Value != (contract.OutputPayloadBounds{}) {
					c.add(subject, contract.FieldCreateValueBounds, contract.ReasonInvalidFieldCombination, target.CreateValueBounds.SourceLocation)
				}
				if writeBoundsOK && !target.Capabilities.Value.Has(contract.PublicationWriteValue) && target.WriteValueBounds.Value != (contract.OutputPayloadBounds{}) {
					c.add(subject, contract.FieldWriteValueBounds, contract.ReasonInvalidFieldCombination, target.WriteValueBounds.SourceLocation)
				}
			}
			checkPublicField(c, subject, contract.FieldConsumerPolicy, target.ConsumerPolicy, func(x contract.OutputPolicy) contract.DiagnosticReason {
				_, err := contract.OutputPolicyLength(x)
				return publicErrorReason(err)
			})
			if destinationOK {
				d := binding.Destination.Value
				if serviceOK && target.ServiceContractID.Value != d.ServiceContractID {
					c.add(subject, contract.FieldServiceContract, contract.ReasonInvalidFieldCombination, target.ServiceContractID.SourceLocation)
				}
				if publicFieldReady(c, subject, contract.FieldCapabilities, target.Capabilities) && target.Capabilities.Value & ^d.Capabilities != 0 {
					c.add(subject, contract.FieldCapabilities, contract.ReasonInvalidFieldCombination, target.Capabilities.SourceLocation)
				}
				if publicFieldReady(c, subject, contract.FieldConsumerPolicy, target.ConsumerPolicy) && !outputPoliciesEqual(target.ConsumerPolicy.Value, d.Policy) {
					c.add(subject, contract.FieldConsumerPolicy, contract.ReasonInvalidFieldCombination, target.ConsumerPolicy.SourceLocation)
				}
			}
			if serviceOK && targetOK {
				key := struct{ service, target string }{target.ServiceContractID.Value, target.CanonicalTarget.Value}
				if physical[key] {
					c.add(subject, contract.FieldCanonicalTarget, contract.ReasonDuplicateKey, target.CanonicalTarget.SourceLocation)
				}
				physical[key] = true
			}
		}
	}
}

func (c *publicConfigurationCheck) checkRoutes(routes []contract.PublicRoutingRule, entries map[string]bool, entriesOK bool, targets map[string]map[string]bool, bindingsOK bool) {
	seen := make(map[contract.PublicRoutingKey]bool)
	for _, route := range routes {
		key := route.Key
		subject := contract.DiagnosticSubject{Kind: contract.SubjectRoutingRule, RoutingKey: key}
		if publicNameReason(key.EntryName) != "" {
			c.invalidRouting = true
			c.add(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence, publicNameReason(key.EntryName), nil)
			continue
		}
		if !publicRoutingKeyValid(key) {
			c.invalidRouting = true
			c.add(contract.DiagnosticSubject{Kind: contract.SubjectConfiguration}, contract.FieldPresence, contract.ReasonInvalidFieldCombination, nil)
			continue
		}
		if seen[key] {
			c.invalidRouting = true
			c.add(subject, contract.FieldPresence, contract.ReasonDuplicateKey, nil)
		}
		seen[key] = true
		if entriesOK && key.EntrySelector == contract.PublicNamedEntry && !entries[key.EntryName] {
			c.add(subject, contract.FieldPresence, contract.ReasonUnresolvedReference, nil)
		}
		if !checkPublicField(c, subject, contract.FieldDestinations, route.Destinations, func(names []string) contract.DiagnosticReason {
			for i, name := range names {
				if r := publicIdentifierReason(name); r != "" {
					return r
				}
				if i > 0 && name == names[i-1] {
					return contract.ReasonDuplicateMember
				}
			}
			return ""
		}) {
			continue
		}
		if bindingsOK {
			for _, name := range route.Destinations.Value {
				_, exists := targets[name]
				if !exists {
					c.add(subject, contract.FieldDestinations, contract.ReasonUnresolvedReference, route.Destinations.SourceLocation)
				}
			}
		}
	}
}

func comparePublicDiagnostics(a, b contract.Diagnostic) int {
	if c := strings.Compare(string(a.Subject.Kind), string(b.Subject.Kind)); c != 0 {
		return c
	}
	if c := comparePublicSubjects(a.Subject, b.Subject); c != 0 {
		return c
	}
	if c := slices.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	if c := strings.Compare(string(a.Outcome), string(b.Outcome)); c != 0 {
		return c
	}
	return strings.Compare(string(a.Reason), string(b.Reason))
}

func comparePublicSubjects(a, b contract.DiagnosticSubject) int {
	switch a.Kind {
	case contract.SubjectEntry:
		return strings.Compare(a.Name, b.Name)
	case contract.SubjectRecipient:
		return comparePublicIDs(a.RecipientID, b.RecipientID)
	case contract.SubjectOutputBinding:
		return strings.Compare(a.DestinationID, b.DestinationID)
	case contract.SubjectOutputTarget:
		if c := strings.Compare(a.DestinationID, b.DestinationID); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	case contract.SubjectRoutingRule:
		return comparePublicRoutingKeys(a.RoutingKey, b.RoutingKey)
	default:
		return 0
	}
}

func comparePublicIDs(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) }

func publicRoutingKeyValid(key contract.PublicRoutingKey) bool {
	return key.EntrySelector == contract.PublicNamedEntry || key.EntrySelector == contract.PublicDefaultRoute && key.EntryName == ""
}
