package core

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/telemetry"
)

// AccessMutationInstallation fixes the authenticated selection and the installed
// custody route. The validator interprets only the selected public state.
type AccessMutationInstallation struct {
	Maintenance            *MaintenanceInstallation
	ExpectedDomain         contract.ID
	ExpectedStore          contract.Descriptor
	PublicBasis            PublicBasis
	ExpectedControl        contract.ControlCore
	Store                  contract.Store
	Trust                  contract.Trust
	CompositionID          contract.ID
	ConfigurationValidator *PublicConfigurationValidator
	CloseInstalled         func()
}

type installedAccessCustodyAdmitter = func(context.Context, contract.CryptoCompareRequest, contract.ControlCore, []contract.RecipientRecord, []contract.MembershipRow, contract.DescriptorVector, *contract.GeneratedSupportTransition, contract.ID, contract.MutationReceiptWindows, uint8, time.Time) (*InstalledApplyCustody, error)

type EnvelopeRekeyInstallation struct {
	AccessMutationInstallation
	Name         string
	AdmitCustody installedAccessCustodyAdmitter
}

type installedSecretAccess struct {
	name string
}

type InstalledEnvelopeRekey struct{ engine *InstalledApply }

func NewInstalledEnvelopeRekey(i EnvelopeRekeyInstallation) (*InstalledEnvelopeRekey, error) {
	engine, err := newInstalledSecretAccess(i.AccessMutationInstallation, &installedSecretAccess{name: i.Name}, i.AdmitCustody)
	if err != nil {
		return nil, err
	}
	return &InstalledEnvelopeRekey{engine: engine}, nil
}

func newInstalledSecretAccess(i AccessMutationInstallation, access *installedSecretAccess, admit installedAccessCustodyAdmitter) (*InstalledApply, error) {
	if len(access.name) > contract.CryptoMaxName || !utf8.ValidString(access.name) {
		return nil, contract.ErrRecord
	}
	access.name = strings.Clone(access.name)
	return newInstalledApply(ApplyInstallation{ExpectedDomain: i.ExpectedDomain, ExpectedStore: i.ExpectedStore, PublicBasis: i.PublicBasis, ExpectedControl: i.ExpectedControl,
		Store: i.Store, Trust: i.Trust, CompositionID: i.CompositionID, ConfigurationValidator: i.ConfigurationValidator, AdmitCustody: admit, CloseInstalled: i.CloseInstalled, Maintenance: i.Maintenance}, access, nil)
}

func (e *InstalledEnvelopeRekey) Rekey(ctx context.Context, requestID contract.ID) PublicApplyResult {
	var engine *InstalledApply
	if e != nil {
		engine = e.engine
	}
	return installedSecretAccessRun(ctx, requestID, engine, telemetry.OpCoreRekeyEnvelope)
}

func installedSecretAccessRun(ctx context.Context, requestID contract.ID, engine *InstalledApply, operation telemetry.Operation) PublicApplyResult {
	ctx, preparation := beginApplyPreparation(ctx)
	call := telemetry.Start(ctx, telemetry.ProviderCore, operation)
	call.Checkpoint(telemetry.DiagnosticAdmission, telemetry.DiagnosticReasonNone)
	out := engine.apply(ctx, requestID, nil, call, nil)
	preparation.attach(&out)
	appendApplyInterruptionDiagnostic(ctx, &out)
	finishCore(call, out.Result)
	return out
}

func (e *InstalledEnvelopeRekey) Close() {
	if e != nil {
		e.engine.Close()
	}
}

func (s *StateSession) installedSecretAccessInputs(ctx context.Context, i ApplyInstallation, access *installedSecretAccess) ([]ApplyEntryInput, *contract.CryptoSecretAccessIntent, Result) {
	fail := func(reason Reason) ([]ApplyEntryInput, *contract.CryptoSecretAccessIntent, Result) {
		return nil, nil, refused(reason)
	}
	if s == nil || access == nil || !CurrentControlMatches(currentControlOf(s), i.ExpectedControl) {
		return fail(AdmissionInvalid)
	}
	if !s.root.Generated.ActiveOwner.IsZero() {
		result := s.observed(Contention)
		result.Reason = DifferentSelection
		return nil, nil, result
	}
	if result := s.installedAccessSelectionResult(ctx, i); result.Outcome != 0 {
		return nil, nil, result
	}
	var input []ApplyEntryInput
	var target *format.ValueEntry
	var slot uint16
	for _, named := range s.root.Names {
		old := s.valueEntry(named.Slot)
		if old == nil {
			return fail(AdmissionInvalid)
		}
		entry := ApplyEntryInput{Name: old.Name, Recipients: slices.Clone(old.Recipients), ValueSource: old.ValueSource, ConfidentialityClass: old.ConfidentialityClass, InputEncoding: old.InputEncoding, OutputEncoding: old.OutputEncoding, InputBytes: old.ValueBytes}
		if old.ValueSource == contract.Supplied && old.ConfidentialityClass == contract.Secret {
			entry.Retained = &contract.RetainedSecretInput{Incarnation: old.Incarnation, Material: old.ValueState}
			entry.InputBytes = nil
		}
		if named.Name == access.name {
			target, slot = old, named.Slot
			if old.ConfidentialityClass != contract.Secret {
				return fail(InvalidIntent)
			}
		}
		input = append(input, entry)
	}
	if target == nil {
		return fail(InvalidIntent)
	}
	intent := &contract.CryptoSecretAccessIntent{OperationKind: contract.OperationEnvelopeRekey, Target: contract.SecretAccessTarget{Slot: slot, Name: target.Name, Incarnation: target.Incarnation, Material: target.ValueState, BeforePublicEntryDigest: publicEntryDigest(s.root.Domain, slot, target)}}
	return input, intent, Result{}
}

func (c *Comparison) lifecycleOperationKind() uint16 {
	if c.operationKind != 0 {
		return c.operationKind
	}
	return contract.OperationApplyDeclaration
}

func (s *StateSession) installedAccessSelectionResult(ctx context.Context, i ApplyInstallation) Result {
	if ctx == nil || ctx.Err() != nil || s == nil || i.ConfigurationValidator == nil || !CurrentControlMatches(currentControlOf(s), i.ExpectedControl) {
		return refused(AdmissionInvalid)
	}
	configured, ok := i.Store.(contract.StoreConfigurationSource)
	if !ok || i.Store.Descriptor() != s.admission.store {
		return refused(ConstructionMismatch)
	}
	stored := configured.StoreConfiguration()
	identity, err := contract.StoreConfigurationID(stored)
	if err != nil || identity != s.head.Core.Store || identity != s.admission.store.Identity || stored.DomainID != s.root.Domain || stored.Provider != s.admission.store.Family || stored.PrefixBeforeHEAD != s.admission.store.Prefix {
		return refused(ConstructionMismatch)
	}
	actual, failed := projectSelectedPublicConfiguration(ctx, s.selectedImage(), s.selectedObjectReader(), stored, s.admission.recipient, i.ConfigurationValidator)
	if failed.Outcome != 0 {
		return failed.Result
	}
	if !actual.Valid || !actual.Complete || !actual.DiagnosticsComplete {
		return refused(InvalidIntent)
	}
	return Result{}
}
