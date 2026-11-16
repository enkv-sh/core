package compositionfull

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
)

var errInitializationConfiguration = errors.New("initialization configuration refused")

type initializationResources struct {
	store      contract.Store
	signing    func(context.Context, string, uint8) (contract.QualifyingTrust, []byte, error)
	encryption func(context.Context, string, contract.ID) ([]byte, uint8, enkvcrypto.KeyAccess, error)
}

// The selected provider source is shared by the Store and every nominated key.
// The callbacks are installed here; source fields cannot supply implementations.
func defaultInitializationResources(ctx context.Context, m *configuration.Model) (initializationResources, error) {
	route := contract.Hash(append([]byte("enkv/initialization/default-credential-route/v1\x00"), m.DomainID[:]...))
	return selectDefaultInitializationResources(ctx, m, route, configurationProviderTransport())
}

func configurationProviderTransport() *http.Transport {
	return &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
}

func resolveInitialization(ctx context.Context, m *configuration.Model, ids core.InitializationIDs, resources initializationResources) (core.InitializationInstallation, error) {
	if resources.store == nil || resources.signing == nil || resources.encryption == nil {
		return core.InitializationInstallation{}, errInitializationConfiguration
	}
	s := resources.store.Descriptor()
	d := contract.GenesisDescriptorCore{InitID: ids.InitID, DomainID: ids.DomainID, DescriptorArtifactID: ids.DescriptorArtifactID, ManifestArtifactID: ids.ManifestArtifactID,
		Provider: m.Provider, StoreID: s.Identity, CoordinateID: s.Coordinate, NonBodyID: s.NonBody, InterpretationID: contract.InterpretationID(), TrustInterpretationID: contract.TrustInterpretationID(),
		CompatibilityID: contract.CompatibilityID(), CryptoSupportID: contract.CryptoSupportID(), AuthorityRecipientID: ids.Authority.RecipientID}
	normal, public, err := resources.signing(ctx, m.Authority.SigningSelector, contract.NormalSigningRole)
	if err != nil {
		return core.InitializationInstallation{}, err
	}
	d.TrustID = normal.Identity()
	d.NormalSigning = initialSigningBinding(d, normal, public, m.Authority.SigningSelector, contract.NormalSigningRole, ids.NormalSigning)
	m.Authority.Signing = configuration.Key{Selector: m.Authority.SigningSelector, PublicKey: public}
	family := m.Provider
	var routes []enkvcrypto.KeyAccess
	publicRoutes, privateRoutes := map[contract.ID]contract.ID{}, map[contract.ID]contract.ID{}
	resolve := func(selector string, ids core.InitializationEncryptionIDs, private bool) (contract.KMSBinding, configuration.Key, error) {
		public, protection, route, err := resources.encryption(ctx, selector, ids.BindingID)
		if err != nil || route == nil {
			return contract.KMSBinding{}, configuration.Key{}, errInitializationConfiguration
		}
		binding := contract.KMSBinding{BindingID: ids.BindingID, BindingIncarnationID: ids.BindingIncarnationID, BindingSerial: 1, Provider: m.Provider,
			WrapProfile: contract.RSAOAEPWrapProfile, ProtectionClass: protection, KeySelector: selector, SPKI: public, Fingerprint: contract.Hash(public)}
		if _, err := contract.EncodeKMSBinding(binding); err != nil {
			return contract.KMSBinding{}, configuration.Key{}, errInitializationConfiguration
		}
		routes = append(routes, route)
		publicRoutes[binding.BindingID] = route.CredentialRoute()
		if private {
			privateRoutes[binding.BindingID] = route.CredentialRoute()
		}
		key := configuration.Key{Selector: selector, PublicKey: public, Binding: configuration.Binding{ID: binding.BindingID, Incarnation: binding.BindingIncarnationID, Serial: 1, Protection: protection}}
		return binding, key, nil
	}
	authority, key, err := resolve(m.Authority.EncryptionSelector, ids.Authority.Encryption, true)
	if err != nil {
		return core.InitializationInstallation{}, err
	}
	m.Authority.ID, m.Authority.Encryption = ids.Authority.RecipientID, key
	d.Recipients = append(d.Recipients, contract.RecipientRecord{RecipientID: m.Authority.ID, Status: contract.CurrentRecipient, DisplayName: m.Authority.DisplayName, CurrentBinding: &authority})
	for i := range m.Recipients {
		r := &m.Recipients[i]
		binding, key, err := resolve(r.Selector, ids.Recipients[i].Encryption, false)
		if err != nil {
			return core.InitializationInstallation{}, err
		}
		r.ID, r.Encryption = ids.Recipients[i].RecipientID, key
		d.Recipients = append(d.Recipients, contract.RecipientRecord{RecipientID: r.ID, Status: contract.CurrentRecipient, DisplayName: r.DisplayName, CurrentBinding: &binding})
	}
	var recovery contract.QualifyingTrust
	if m.RecoveryEnabled {
		if ids.Recovery == nil {
			return core.InitializationInstallation{}, errInitializationConfiguration
		}
		recovery, public, err = resources.signing(ctx, m.Recovery.SigningSelector, contract.RecoverySigningRole)
		if err != nil {
			return core.InitializationInstallation{}, err
		}
		m.Recovery.ID = ids.Recovery.RoleID
		m.Recovery.Signing = configuration.Key{Selector: m.Recovery.SigningSelector, PublicKey: public}
		binding, key, err := resolve(m.Recovery.EncryptionSelector, ids.Recovery.Encryption, true)
		if err != nil || !contract.IndependentKMSBindings(authority, binding) {
			return core.InitializationInstallation{}, errInitializationConfiguration
		}
		m.Recovery.Encryption = key
		d.Recovery = &contract.RecoveryBindings{RoleID: ids.Recovery.RoleID, Signing: initialSigningBinding(d, recovery, public, m.Recovery.SigningSelector, contract.RecoverySigningRole, ids.Recovery.Signing), KMS: binding}
	}
	slices.SortFunc(d.Recipients, func(a, b contract.RecipientRecord) int { return bytes.Compare(a.RecipientID[:], b.RecipientID[:]) })
	if _, err := contract.EncodeGenesisDescriptorCore(d); err != nil {
		return core.InitializationInstallation{}, errInitializationConfiguration
	}
	return core.InitializationInstallation{Descriptor: d, Store: resources.store, Normal: normal, Recovery: recovery, CompositionID: CompatibilityManifest().Identity,
		CloseInstalled: func() {}, AdmitCustody: func(ctx context.Context, request contract.CryptoQualifyInitKeysRequest) (contract.Crypto, func(), error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return nil, nil, errInitializationConfiguration
			}
			runtime, err := enkvcrypto.New(family, routes)
			if err != nil {
				return nil, nil, errInitializationConfiguration
			}
			custody, err := enkvcrypto.NewInitializationCustody(runtime, request, publicRoutes, privateRoutes, deadline)
			if err != nil {
				runtime.Close()
				return nil, nil, errInitializationConfiguration
			}
			return custody, func() { custody.Close(); runtime.Close() }, nil
		}}, nil
}

func initialSigningBinding(d contract.GenesisDescriptorCore, trust contract.QualifyingTrust, public []byte, selector string, role uint8, ids core.InitializationSigningIDs) contract.PublicSigningBinding {
	return contract.PublicSigningBinding{Schema: contract.PublicSigningBindingSchema, Role: role, Provider: d.Provider, SigningProfile: contract.P256SigningProfile,
		BindingID: ids.BindingID, KeySelector: selector, SPKI: public, Fingerprint: contract.Hash(public), Binding: contract.BindingSubject{Domain: d.DomainID, Coordinate: d.CoordinateID, Store: d.StoreID,
			Trust: trust.Identity(), PublicKey: contract.Hash(public), Interpretation: d.InterpretationID, ControlIncarnationID: ids.ControlIncarnationID, Epoch: 1}}
}
