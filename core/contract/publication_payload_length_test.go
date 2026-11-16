package contract

import (
	"errors"
	"math"
	"testing"
)

// full_only: false
func TestPublicationPayloadLength(t *testing.T) {
	for _, test := range []struct {
		encoding  uint8
		raw, want uint32
	}{
		{OutputEncodingRaw, 0, 0}, {OutputEncodingRaw, 1, 1}, {OutputEncodingRaw, 65536, 65536},
		{OutputEncodingBase64, 0, 0}, {OutputEncodingBase64, 1, 4}, {OutputEncodingBase64, 2, 4}, {OutputEncodingBase64, 3, 4}, {OutputEncodingBase64, 4, 8}, {OutputEncodingBase64, 49152, 65536},
	} {
		got, err := PublicationPayloadLength(test.encoding, test.raw)
		if err != nil || got != test.want {
			t.Fatalf("%d raw%d length%d want%d err%v", test.encoding, test.raw, got, test.want, err)
		}
	}
	for _, raw := range []uint32{49153, 65536, 65537, math.MaxUint32} {
		if _, err := PublicationPayloadLength(OutputEncodingBase64, raw); !errors.Is(err, ErrRecordCapacity) {
			t.Fatalf("unbounded raw%d admitted: %v", raw, err)
		}
	}
	for _, encoding := range []uint8{0, 3, 255} {
		if _, err := PublicationPayloadLength(encoding, 0); !errors.Is(err, ErrRecord) {
			t.Fatal("unsupported representation admitted", encoding, err)
		}
	}
}
