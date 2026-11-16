package contract

import outputprotocol "enkv.sh/sdk/protocols/output"

// OutputConfigContractDigest commits one bounded plugin configuration
// identity. It does not validate settings or authenticate the declaration.
func OutputConfigContractDigest(identity string) (ID, error) {
	if !outputIdentifierValid(identity) {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/OUTPUT/CONFIG-CONTRACT/v1\x00")
	w.blob([]byte(identity))
	return w.result(0).Digest, nil
}

// PublicationRequestContractDigest binds the supported wire, configuration,
// service, target contract and action. Semantic identifiers are plugin-owned;
// their presence is not proof that a provider supports the request.
func PublicationRequestContractDigest(protocol, config ID, service, target string, action uint8) (ID, error) {
	if protocol != ID(outputprotocol.ProtocolID()) || config.IsZero() || !outputIdentifierValid(service) || !outputIdentifierValid(target) || action < PublicationCreateEmpty || action > PublicationDeleteReservedSlot {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/OUTPUT/REQUEST-CONTRACT/v2\x00")
	w.id(protocol)
	w.id(config)
	w.blob([]byte(service))
	w.blob([]byte(target))
	w.u8(action)
	return w.result(0).Digest, nil
}

// PublicationResponseContractDigest binds the response schemas and selected
// artifact contract to a request contract. It supplies correlation, not provider truth.
func PublicationResponseContractDigest(request, artifact ID) (ID, error) {
	if request.IsZero() || artifact.IsZero() {
		return ID{}, ErrRecord
	}
	w := cryptoHashWriter("ENKV/OUTPUT/RESPONSE-CONTRACT/v2\x00")
	w.id(request)
	w.id(artifact)
	w.u16(outputprotocol.Version)
	w.u16(outputprotocol.ResultSchema)
	w.u16(PublicationEvidenceSchema)
	return w.result(0).Digest, nil
}
