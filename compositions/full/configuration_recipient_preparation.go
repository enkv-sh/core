package compositionfull

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"unicode/utf8"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core"
	"enkv.sh/core/contract"
)

type RecipientPreparationMode string

const (
	RecipientPreparationCurrent RecipientPreparationMode = "current"
	RecipientPreparationCreate  RecipientPreparationMode = "create"
)

type RecipientPreparationOptions struct {
	Mode        RecipientPreparationMode
	Declaration *configuration.RecipientDeclaration
}

type recipientPublicKeyResolver func(context.Context, *configuration.Model, string) ([]byte, uint8, error)

// PrepareConfigurationRecipient changes only the selected local pair. It uses
// authenticated public state and public-key lookup, with no private key route.
// The selected unresolved row cannot form a complete public declaration yet:
// strict source parsing precedes public reads, and known public facts are
// validated before the staged candidate's first visible change. Unrelated plugin
// settings retain their opaque source form without installed plugin code.
func PrepareConfigurationRecipient(ctx context.Context, path string, format configuration.Format, reference string, options RecipientPreparationOptions) (*LocalEditResult, error) {
	return PrepareConfigurationSelectedRecipient(ctx, path, format, RecipientSelector{Reference: reference}, options)
}

// PrepareConfigurationSelectedRecipient resolves an existing ID under the edit
// lock. Creating a recipient requires a local reference and allocates its ID.
func PrepareConfigurationSelectedRecipient(ctx context.Context, path string, format configuration.Format, selector RecipientSelector, options RecipientPreparationOptions) (*LocalEditResult, error) {
	return prepareConfigurationSelectedRecipient(ctx, path, format, selector, options, NewDefaultReader, resolveConfigurationRecipientPublicKey, rand.Reader)
}

func prepareConfigurationRecipient(ctx context.Context, path string, format configuration.Format, reference string, options RecipientPreparationOptions,
	open func(context.Context, ReaderConfig) (*core.ReaderEngine, error), resolve recipientPublicKeyResolver, nonce io.Reader) (*LocalEditResult, error) {
	return prepareConfigurationSelectedRecipient(ctx, path, format, RecipientSelector{Reference: reference}, options, open, resolve, nonce)
}

func prepareConfigurationSelectedRecipient(ctx context.Context, path string, format configuration.Format, selector RecipientSelector, options RecipientPreparationOptions,
	open func(context.Context, ReaderConfig) (*core.ReaderEngine, error), resolve recipientPublicKeyResolver, nonce io.Reader) (*LocalEditResult, error) {
	return runLocalConfigurationEdit(ctx, "recipient-preparation", func(ctx context.Context, result *LocalEditResult) (resultErr error) {
		if !selector.valid() || selector.Reference == "" && selector.ID.IsZero() || options.Mode == RecipientPreparationCreate && selector.Reference == "" || open == nil || resolve == nil || nonce == nil ||
			options.Mode != RecipientPreparationCurrent && options.Mode != RecipientPreparationCreate ||
			options.Declaration != nil && options.Mode != RecipientPreparationCreate {
			return ErrLocalEdit
		}
		session, err := configuration.BeginEdit(ctx, path, format)
		if err != nil {
			return err
		}
		defer closeLocalEditSession(session, result, &resultErr)
		reference, err := selector.localReference(ctx, session.Pair())
		if err != nil {
			return err
		}
		model, err := configuration.ParseForRecipientPreparation(ctx, session.Pair(), reference)
		if err != nil || model == nil || !model.Resolved {
			return errors.Join(ErrLocalEdit, err)
		}
		var selected *configuration.Recipient
		for i := range model.Recipients {
			if model.Recipients[i].Reference == reference {
				selected = &model.Recipients[i]
				break
			}
		}
		if (selected == nil) != (options.Declaration != nil) {
			return ErrLocalEdit
		}
		selector := ""
		if selected != nil {
			selector = selected.Selector
		} else {
			declaration := options.Declaration
			if len(declaration.DisplayName) > 256 || !utf8.ValidString(declaration.DisplayName) {
				return ErrLocalEdit
			}
			selector = declaration.EncryptionSelector
		}
		if !contract.PublicKeySelectorValid(model.Provider, selector, false) {
			return ErrLocalEdit
		}
		basis, store, err := configurationPublicBasis(model)
		if err != nil {
			return err
		}
		control, err := basis.ControlCore(model.DomainID, store)
		if err != nil || !configurationReplacementRoleFacts(model, control) {
			return errors.Join(ErrLocalEdit, err)
		}
		installed, err := configurationReaderConfig(model)
		if err != nil {
			return err
		}
		reader, err := open(ctx, installed)
		if err != nil || reader == nil {
			return errors.Join(ErrLocalEdit, err)
		}
		defer reader.Close()
		var request contract.ID
		if _, err := rand.Read(request[:]); err != nil || request.IsZero() {
			return errors.Join(ErrLocalEdit, err)
		}
		selection := reader.ReadRecipientRegistry(ctx, request)
		reader.Close()
		registry := selection.Registry
		if selection.StateResult != contract.ReaderSuccess || registry == nil || registry.DomainID != model.DomainID ||
			registry.SnapshotID.IsZero() || registry.AuthorityRecipientID != model.Authority.ID {
			return ErrLocalEdit
		}
		var current *contract.RecipientRecord
		if selected != nil {
			for i := range registry.Recipients {
				if registry.Recipients[i].RecipientID == selected.ID {
					current = &registry.Recipients[i]
					break
				}
			}
		}
		material := configuration.RecipientPreparationMaterial{}
		switch options.Mode {
		case RecipientPreparationCurrent:
			if current == nil || current.Status != contract.CurrentRecipient || current.CurrentBinding == nil ||
				current.CurrentBinding.Provider != model.Provider || current.CurrentBinding.KeySelector != selector || current.RecipientID == registry.AuthorityRecipientID {
				return ErrLocalEdit
			}
			material.RecipientID, material.Encryption = current.RecipientID, *current.CurrentBinding
			material.Creation = selected.Creation
		case RecipientPreparationCreate:
			if current != nil {
				return ErrLocalEdit
			}
			material, err = freshConfigurationRecipient(ctx, model, registry, nonce)
			if err != nil {
				return err
			}
			material.Encryption.Provider = model.Provider
			material.Encryption.WrapProfile = contract.RSAOAEPWrapProfile
			material.Encryption.KeySelector = selector
		}
		public, protection, err := resolve(ctx, model, selector)
		if err != nil {
			return err
		}
		if options.Mode == RecipientPreparationCurrent && (!bytes.Equal(public, material.Encryption.SPKI) || protection != material.Encryption.ProtectionClass) {
			return ErrLocalEdit
		}
		material.Encryption.SPKI, material.Encryption.ProtectionClass = public, protection
		material.Encryption.Fingerprint = contract.Hash(public)
		if _, err := contract.KMSBindingLength(material.Encryption); err != nil {
			return err
		}
		edit, err := configuration.PrepareRecipientEdit(ctx, session.Pair(), model, reference, options.Declaration, material)
		if err != nil {
			return err
		}
		result.target = recipientPreparationTarget{Reference: reference, Mode: options.Mode}
		admitLocalEditPaths(result, session.Pair())
		*model = configuration.Model{}
		registry, selection.Registry, current, selected = nil, nil, nil, nil
		candidate, candidateModel, err := session.Stage(ctx, func(out io.Writer) error { return edit.EmitGenerated(ctx, out) },
			func(out io.Writer, reference string) error { return edit.EmitEditable(ctx, out, reference) })
		if err != nil {
			return err
		}
		return commitLocalEditCandidate(ctx, result, session, candidate, candidateModel)
	})
}

func freshConfigurationRecipient(ctx context.Context, model *configuration.Model, registry *core.PublicRecipientRegistry, nonce io.Reader) (configuration.RecipientPreparationMaterial, error) {
	for attempt := 0; attempt < 8; attempt++ {
		if ctx.Err() != nil {
			return configuration.RecipientPreparationMaterial{}, ctx.Err()
		}
		var value contract.ID
		if _, err := io.ReadFull(nonce, value[:]); err != nil {
			return configuration.RecipientPreparationMaterial{}, err
		}
		id, err := contract.RecipientCreationID(model.DomainID, registry.SnapshotID, value)
		if err != nil || configurationRecipientCollision(id, model, registry) {
			continue
		}
		binding, incarnation, err := contract.RecipientInitialBindingIDs(model.DomainID, id)
		if err != nil {
			return configuration.RecipientPreparationMaterial{}, err
		}
		return configuration.RecipientPreparationMaterial{RecipientID: id, Creation: &configuration.Creation{Snapshot: registry.SnapshotID, Nonce: value},
			Encryption: contract.KMSBinding{BindingID: binding, BindingIncarnationID: incarnation, BindingSerial: 1}}, nil
	}
	return configuration.RecipientPreparationMaterial{}, ErrLocalEdit
}

func configurationRecipientCollision(id contract.ID, model *configuration.Model, registry *core.PublicRecipientRegistry) bool {
	if id.IsZero() || id == model.Authority.ID {
		return true
	}
	for _, row := range registry.Recipients {
		if id == row.RecipientID {
			return true
		}
	}
	for _, rows := range [][]configuration.Recipient{model.Recipients, model.GeneratedRecipients} {
		for _, row := range rows {
			if id == row.ID {
				return true
			}
		}
	}
	return false
}
