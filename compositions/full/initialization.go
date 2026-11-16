package compositionfull

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type InitializationResult struct {
	core.PublicInitializationResult
	PreAdmission                              *core.PreAdmissionRequestIdentity
	EditablePath, GeneratedPath, ManifestPath string
	DeliveryAttempted                         bool
}

// InitializeConfiguration owns one native setup transaction and one finite
// initialization invocation. Its returned paths remain relevant on remote failure.
func InitializeConfiguration(ctx context.Context, path string, format configuration.Format) (InitializationResult, error) {
	return initializeConfiguration(ctx, path, format, defaultInitializationResources)
}

func initializeConfiguration(ctx context.Context, path string, format configuration.Format,
	open func(context.Context, *configuration.Model) (initializationResources, error)) (out InitializationResult, resultErr error) {
	var err error
	out, err = NewInitializationRefusal(format)
	if err != nil {
		return out, err
	}
	operation, preAdmission := out.OperationID, out.PreAdmission
	defer func() {
		resultErr = closeConfigurationDelivery(resultErr)
		var unknown *configuration.UnknownEdit
		if errors.As(resultErr, &unknown) {
			if delivery, valid := unknown.Readback(); valid {
				out.EditablePath, out.GeneratedPath = delivery.Paths()
			}
		}
		finishInitializationPreAdmission(&out, operation, preAdmission)
		if out.PreAdmission != nil && resultErr != nil {
			out.PreAdmission.Code = configurationFailureCode(ctx, resultErr)
		}
	}()
	preAdmission.Stage = "context"
	if ctx == nil || ctx.Err() != nil || open == nil {
		return out, errInitializationConfiguration
	}
	deadline, finite := ctx.Deadline()
	if !finite || !time.Now().Before(deadline) {
		return out, errInitializationConfiguration
	}
	preAdmission.Stage = "capture"
	session, err := configuration.BeginEdit(ctx, path, format)
	if err != nil {
		return out, err
	}
	defer func() { resultErr = errors.Join(resultErr, session.Close()) }()
	pair := session.Pair()
	preAdmission.Stage = "parse"
	m, err := configuration.Parse(ctx, pair)
	if err != nil {
		return out, err
	}
	// Init cannot adopt application values, including an empty supplied value.
	preAdmission.Stage = "declaration"
	if len(m.Entries) != 0 {
		return out, errInitializationConfiguration
	}
	if m.Resolved {
		return observeConfigurationInitializationWithIdentity(ctx, path, m, open, out)
	}
	allocation, err := core.AllocateInitialization(uint16(len(m.Recipients)), m.RecoveryEnabled)
	if err != nil {
		return out, errInitializationConfiguration
	}
	ids := allocation.Identities()
	m.DomainID = ids.DomainID
	if _, err = rand.Read(m.FileID[:]); err != nil || m.FileID.IsZero() {
		return out, errInitializationConfiguration
	}
	if !validInitializationSetup(ctx, m, ids) {
		return out, errInitializationConfiguration
	}
	m.Public = contract.PublicConfiguration{}
	m.Routes = nil
	preAdmission.Stage = "construction"
	resources, err := open(ctx, m)
	if err != nil {
		return out, errInitializationConfiguration
	}
	preAdmission.Stage = "resolution"
	installation, err := resolveInitialization(ctx, m, ids, resources)
	if err != nil {
		return out, err
	}
	installation.SetupDigest = pair.Editable.Digest()
	var descriptor *configuration.InitializationDescriptor
	var deliveryErr error
	installation.PersistDescriptor = func(ctx context.Context, id contract.ID, body []byte) (fact contract.GenesisArtifactFact, err error) {
		out.DeliveryAttempted = true
		defer func() {
			if err != nil {
				deliveryErr = errors.Join(deliveryErr, err)
			}
		}()
		m.Basis = configuration.Basis{Descriptor: body}
		candidate, normalized, err := session.Stage(ctx, func(w io.Writer) error { return configuration.EmitGenerated(w, m) },
			func(w io.Writer, ref string) error {
				return emitInitializationReference(ctx, w, pair.Editable, format, m, ref)
			})
		if err != nil {
			return contract.GenesisArtifactFact{}, err
		}
		if !validResolvedInitializationConfiguration(ctx, normalized) {
			return contract.GenesisArtifactFact{}, errInitializationConfiguration
		}
		descriptor, err = session.CommitInitialization(ctx, candidate, id, uint64(len(body)), contract.Hash(body))
		if err != nil {
			return contract.GenesisArtifactFact{}, err
		}
		out.EditablePath, out.GeneratedPath = descriptor.Paths()
		return descriptor.Fact()
	}
	installation.PersistManifest = func(ctx context.Context, id contract.ID, body []byte) (fact contract.GenesisArtifactFact, err error) {
		out.DeliveryAttempted = true
		defer func() {
			if err != nil {
				deliveryErr = errors.Join(deliveryErr, err)
			}
		}()
		manifest, err := configuration.PersistInitializationManifest(ctx, initializationManifestPath(path, id), id, body, descriptor)
		if err != nil {
			return contract.GenesisArtifactFact{}, err
		}
		out.ManifestPath = manifest.Path()
		return manifest.Fact()
	}
	preAdmission.Stage = "installation"
	engine, err := core.NewInstalledInitializer(allocation, installation)
	if err != nil {
		return out, errInitializationConfiguration
	}
	defer engine.Close()
	preAdmission.Stage = "initialize"
	out.PublicInitializationResult = engine.Initialize(ctx)
	return out, deliveryErr
}

func initializationManifestPath(source string, id contract.ID) string {
	return filepath.Join(filepath.Dir(source), ".enkv", hex.EncodeToString(id[:])+".init")
}

func observeConfigurationInitialization(ctx context.Context, path string, m *configuration.Model,
	open func(context.Context, *configuration.Model) (initializationResources, error)) (InitializationResult, error) {
	out, err := NewInitializationRefusal(0)
	if err != nil {
		return out, err
	}
	return observeConfigurationInitializationWithIdentity(ctx, path, m, open, out)
}

func observeConfigurationInitializationWithIdentity(ctx context.Context, path string, m *configuration.Model,
	open func(context.Context, *configuration.Model) (initializationResources, error), out InitializationResult) (result InitializationResult, resultErr error) {
	operation, preAdmission := out.OperationID, out.PreAdmission
	defer func() {
		finishInitializationPreAdmission(&result, operation, preAdmission)
		if result.PreAdmission != nil && resultErr != nil {
			result.PreAdmission.Code = configurationFailureCode(ctx, resultErr)
		}
	}()
	preAdmission.Stage = "observation"
	if !validResolvedInitializationConfiguration(ctx, m) || len(m.Basis.Descriptor) == 0 {
		return out, errInitializationConfiguration
	}
	d, err := contract.DecodeGenesisDescriptorCore(m.Basis.Descriptor)
	if err != nil {
		return out, errInitializationConfiguration
	}
	if _, err := configurationReaderConfig(m); err != nil {
		return out, errInitializationConfiguration
	}
	manifestPath := initializationManifestPath(path, d.ManifestArtifactID)
	manifest, err := configuration.CaptureInitializationManifest(ctx, manifestPath)
	if err != nil {
		return out, err
	}
	if !validInitializationObservationBasis(m, d, manifest) {
		return out, errInitializationConfiguration
	}
	preAdmission.Stage = "construction"
	resources, err := open(ctx, m)
	if err != nil {
		return out, errInitializationConfiguration
	}
	preAdmission.Stage = "installation"
	engine, err := core.NewInstalledInitializationObserver(core.InitializationObservationInstallation{Descriptor: m.Basis.Descriptor, Manifest: manifest, Store: resources.store,
		CompositionID: CompatibilityManifest().Identity, CloseInstalled: func() {}})
	if err != nil {
		return out, errInitializationConfiguration
	}
	defer engine.Close()
	out.EditablePath, out.GeneratedPath, out.ManifestPath = path, filepath.Join(filepath.Dir(path), m.Generated), manifestPath
	preAdmission.Stage = "initialize"
	out.PublicInitializationResult = engine.Initialize(ctx)
	return out, nil
}

func finishInitializationPreAdmission(out *InitializationResult, operation contract.ID, q *core.PreAdmissionRequestIdentity) {
	if !out.RequestIdentity.IsZero() {
		out.PreAdmission = nil
		return
	}
	if out.OperationID.IsZero() {
		out.OperationID = operation
	}
	out.PreAdmission = q
}

func validResolvedConfiguration(ctx context.Context, m *configuration.Model) bool {
	if m == nil || !m.Resolved {
		return false
	}
	result := validateInstalledConfiguration(ctx, m.Public)
	return result.Valid && result.Complete && result.DiagnosticsComplete
}

// Setup checks declared source facts before provider construction. Plugin-owned
// output meaning remains unavailable until a later operation needs that plugin.
func validInitializationSetup(ctx context.Context, m *configuration.Model, ids core.InitializationIDs) bool {
	if m == nil || m.Resolved || len(m.Entries) != 0 || len(m.Recipients) != len(ids.Recipients) {
		return false
	}
	p := m.Public
	p.Entries = initializationField([]contract.PublicEntry{})
	p.Store = contract.PublicStoreSettings{DomainID: initializationField(ids.DomainID), Provider: initializationField(m.Provider),
		ConstructionProfile: initializationField(contract.StoreConstructionProfile), Region: initializationField(m.Store.Region),
		Bucket: initializationField(m.Store.Bucket), Prefix: initializationField(m.Store.PrefixBeforeHEAD), ExpectedOwner: initializationField(m.Store.ExpectedOwner)}
	unresolvedSigning := func(selector string, role uint8) contract.PublicSigningSettings {
		return contract.PublicSigningSettings{Provider: initializationField(m.Provider), Selector: initializationField(selector),
			Role: initializationField(role), Profile: initializationField(contract.P256SigningProfile),
			PublicKey: contract.PublicField[[]byte]{State: contract.PublicUnavailable}, Fingerprint: contract.PublicField[contract.ID]{State: contract.PublicUnavailable}}
	}
	unresolvedEncryption := func(selector string) contract.PublicEncryptionSettings {
		return contract.PublicEncryptionSettings{Provider: initializationField(m.Provider), Selector: initializationField(selector),
			WrapProfile: initializationField(contract.RSAOAEPWrapProfile), PublicKey: contract.PublicField[[]byte]{State: contract.PublicUnavailable},
			Fingerprint: contract.PublicField[contract.ID]{State: contract.PublicUnavailable}, ProtectionClass: contract.PublicField[uint8]{State: contract.PublicUnavailable}}
	}
	p.Authority = contract.PublicAuthoritySettings{RecipientID: initializationField(ids.Authority.RecipientID), Signing: unresolvedSigning(m.Authority.SigningSelector, contract.NormalSigningRole)}
	recipients := make([]contract.PublicRecipient, 0, len(m.Recipients)+1)
	recipients = append(recipients, contract.PublicRecipient{RecipientID: ids.Authority.RecipientID, DisplayName: initializationField(m.Authority.DisplayName), Encryption: unresolvedEncryption(m.Authority.EncryptionSelector)})
	for i, r := range m.Recipients {
		recipients = append(recipients, contract.PublicRecipient{RecipientID: ids.Recipients[i].RecipientID, DisplayName: initializationField(r.DisplayName), Encryption: unresolvedEncryption(r.Selector)})
	}
	p.Recipients = initializationField(recipients)
	p.Recovery = contract.PublicRecoverySettings{Enabled: initializationField(m.RecoveryEnabled)}
	if m.RecoveryEnabled {
		s := unresolvedSigning(m.Recovery.SigningSelector, contract.RecoverySigningRole)
		e := unresolvedEncryption(m.Recovery.EncryptionSelector)
		p.Recovery.Signing, p.Recovery.Encryption = &s, &e
	}
	routes := make([]contract.PublicRoutingRule, 0, len(m.Routes))
	for _, r := range m.Routes {
		key := contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: r.EntryName}
		if r.Default {
			key.EntrySelector = contract.PublicDefaultRoute
		}
		routes = append(routes, contract.PublicRoutingRule{Key: key, Destinations: initializationField(r.Destinations)})
	}
	p.Routing = initializationField(routes)
	return validInitializationPublic(ctx, m, p)
}

func validResolvedInitializationConfiguration(ctx context.Context, m *configuration.Model) bool {
	return m != nil && m.Resolved && len(m.Entries) == 0 && validInitializationPublic(ctx, m, m.Public)
}

func validInitializationPublic(ctx context.Context, m *configuration.Model, p contract.PublicConfiguration) bool {
	checked := validateInstalledConfiguration(ctx, p)
	if !checked.DiagnosticsComplete {
		return false
	}
	for _, d := range checked.Diagnostics {
		if d.Reason != contract.ReasonPublicFactUnavailable || len(d.Path) != 1 {
			return false
		}
		if !m.Resolved {
			switch d.Path[0] {
			case contract.FieldSigningPublicKey, contract.FieldSigningFingerprint, contract.FieldEncryptionPublicKey, contract.FieldEncryptionFingerprint, contract.FieldProtectionClass:
				continue
			}
		}
		if d.Subject.Kind != contract.SubjectOutputBinding {
			return false
		}
		unavailable := false
		for _, output := range m.Outputs {
			if output.DestinationID != d.Subject.DestinationID || output.Settings == nil {
				continue
			}
			switch d.Path[0] {
			case contract.FieldDestination:
				unavailable = output.Binding.Destination.ConfigContractID == ""
			case contract.FieldTargets:
				unavailable = output.Binding.Targets == nil
			}
			break
		}
		if !unavailable {
			return false
		}
	}
	return true
}

func initializationField[T any](value T) contract.PublicField[T] {
	return contract.PublicField[T]{State: contract.PublicPresent, Value: value}
}

func emitInitializationReference(ctx context.Context, w io.Writer, image *configuration.Image, format configuration.Format, m *configuration.Model, ref string) error {
	edits, err := configuration.RecipientIdentityEdits(ctx, m)
	if err != nil {
		return err
	}
	copyWithReference := func(reference configuration.Edit) error {
		edits = append(edits, reference)
		sort.Slice(edits, func(i, j int) bool { return edits[i].Offset < edits[j].Offset })
		return configuration.CopyEdits(ctx, w, image, edits)
	}
	quoted, err := json.Marshal(ref)
	if err != nil {
		return errInitializationConfiguration
	}
	if m.Generated != "" {
		span := m.Spans[m.GeneratedSpan]
		return copyWithReference(configuration.Edit{Offset: span.Offset, Length: span.Length, Replacement: quoted})
	}
	root := m.Spans[m.RootSpan]
	if format == configuration.JSON {
		return copyWithReference(configuration.Edit{Offset: root.Offset + root.Length - 1, Replacement: append([]byte(`,"generated":`), quoted...)})
	}
	// A YAML root may use flow mapping syntax; inspect its already-indexed opener.
	var opener [1]byte
	if _, err := image.ReadAt(opener[:], root.Offset); err != nil {
		return errInitializationConfiguration
	}
	if opener[0] == '{' {
		separator, err := configuration.YAMLFlowMappingSeparator(ctx, image, root)
		if err != nil {
			return err
		}
		return copyWithReference(configuration.Edit{Offset: root.Offset + root.Length - 1, Replacement: append([]byte(separator+` generated: `), quoted...)})
	}
	replacement := append([]byte("generated: "), quoted...)
	replacement = append(replacement, '\n')
	indent := int64(root.Column - 1)
	return copyWithReference(configuration.Edit{Offset: root.Offset, Emit: func(out io.Writer) error {
		if written, err := out.Write(replacement); err != nil || written != len(replacement) {
			return errors.Join(err, io.ErrShortWrite)
		}
		_, err := io.CopyN(out, io.NewSectionReader(image, root.Offset-indent, indent), indent)
		return err
	}})
}
