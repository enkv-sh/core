package crypto

import (
	"encoding/base64"
	"errors"

	"enkv.sh/core/contract"
)

const maximumPublicationPayloadBytes = 65536

var errPublicationPayload = errors.New("publication payload refused")

// A zero-length value has an owned, nonnil payload; nil is reserved for metadata
// actions. Base64 consumes the complete original bytes without content detection.
func encodePublicationPayload(input, output uint8, content uint32, retained []byte) ([]byte, error) {
	if _, err := contract.PublicationPayloadLength(output, content); err != nil {
		return nil, err
	}
	return encodeDeliveryValue(input, output, content, retained)
}

func encodeDeliveryValue(input, output uint8, content uint32, retained []byte) ([]byte, error) {
	actual, err := contract.InputContentLength(input, retained)
	if err != nil || actual != content {
		return nil, errPublicationPayload
	}
	length, err := contract.DeliveredValueLength(output, content)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, int(length))
	switch {
	case input == output:
		copy(payload, retained)
	case output == contract.OutputEncodingBase64:
		base64.StdEncoding.Encode(payload, retained)
	default:
		n, err := base64.StdEncoding.Strict().Decode(payload, retained)
		if err != nil || n != len(payload) {
			clear(payload[:cap(payload)])
			return nil, errPublicationPayload
		}
	}
	return payload, nil
}
