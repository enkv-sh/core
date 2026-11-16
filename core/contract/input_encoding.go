package contract

import "encoding/base64"

const (
	InputEncodingRaw       uint8 = 1
	InputEncodingBase64    uint8 = 2
	CryptoMaxRetainedValue       = 87384
	CryptoMaxRetainedSet         = 11186176
)

// InputLengths validates public representation metadata without inspecting content.
func InputLengths(encoding uint8, content, retained uint32) error {
	if content > CryptoMaxRawValue || retained > CryptoMaxRetainedValue {
		return ErrRecordCapacity
	}
	switch encoding {
	case InputEncodingRaw:
		if retained == content {
			return nil
		}
	case InputEncodingBase64:
		if retained == 4*((content+2)/3) {
			return nil
		}
	}
	return ErrRecord
}

// InputContentLength validates exact retained bytes and returns logical content
// length. The decoder uses a fixed buffer, including for confidential callers.
func InputContentLength(encoding uint8, retained []byte) (uint32, error) {
	if len(retained) > CryptoMaxRetainedValue {
		return 0, ErrRecordCapacity
	}
	if encoding == InputEncodingRaw {
		if len(retained) > CryptoMaxRawValue {
			return 0, ErrRecordCapacity
		}
		return uint32(len(retained)), nil
	}
	if encoding != InputEncodingBase64 || len(retained)%4 != 0 {
		return 0, ErrRecord
	}
	var decoded [3]byte
	defer clear(decoded[:])
	var content uint32
	for i := 0; i < len(retained); i += 4 {
		chunk := retained[i : i+4]
		for _, b := range chunk {
			if b == '\r' || b == '\n' || b == '\t' || b == ' ' || b == '=' && i+4 != len(retained) {
				return 0, ErrRecord
			}
		}
		n, err := base64.StdEncoding.Strict().Decode(decoded[:], chunk)
		if err != nil {
			return 0, ErrRecord
		}
		content += uint32(n)
	}
	if err := InputLengths(encoding, content, uint32(len(retained))); err != nil {
		return 0, err
	}
	return content, nil
}

// DeliveredValueLength counts application bytes before any output-specific limit.
func DeliveredValueLength(encoding uint8, content uint32) (uint32, error) {
	if content > CryptoMaxRawValue {
		return 0, ErrRecordCapacity
	}
	switch encoding {
	case OutputEncodingRaw:
		return content, nil
	case OutputEncodingBase64:
		return 4 * ((content + 2) / 3), nil
	default:
		return 0, ErrRecord
	}
}
