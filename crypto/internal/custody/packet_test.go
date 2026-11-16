package custody

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// full_only: false
func TestPrivatePacketBytesAndContext(t *testing.T) {
	// Independent concatenation: big-endian version 2, proof kind 4, 32 bytes
	// of context 0x11, then 32 challenge bytes 0x22.
	want, err := hex.DecodeString("0002000411111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	var context [32]byte
	copy(context[:], bytes.Repeat([]byte{0x11}, 32))
	challenge := bytes.Repeat([]byte{0x22}, 32)
	packet, err := EncodePacket(4, context, challenge)
	if err != nil || !bytes.Equal(packet, want) {
		t.Fatal("private packet differs from independent bytes")
	}
	keys, err := PacketKeys(packet, 4, context)
	if err != nil || !bytes.Equal(keys, challenge) {
		t.Fatal("matching private packet refused")
	}
	for _, test := range []struct {
		name   string
		change func([]byte) []byte
	}{
		{"wrong-version", func(b []byte) []byte { b[1] = 1; return b }},
		{"wrong-purpose", func(b []byte) []byte { b[3] = 2; return b }},
		{"wrong-context", func(b []byte) []byte { b[4] ^= 1; return b }},
		{"short", func(b []byte) []byte { return b[:len(b)-1] }},
		{"trailing", func(b []byte) []byte { return append(b, 0) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if keys, err := PacketKeys(test.change(bytes.Clone(packet)), 4, context); err == nil || keys != nil {
				t.Fatal("invalid packet returned private material")
			}
		})
	}
}

// full_only: false
func TestPrivatePacketClosedKindsAndLengths(t *testing.T) {
	context := [32]byte{1}
	for _, kind := range []uint16{0, 1, 2, 3, 4, 5, 6, 7, 65535} {
		for _, length := range []int{0, 31, 32, 33, 63, 64, 65} {
			keys := make([]byte, length)
			packet, err := EncodePacket(kind, context, keys)
			valid := (kind == 1 || kind == 6) && length == 64 || (kind == 2 || kind == 3 || kind == 4 || kind == 5) && length == 32
			if (err == nil) != valid {
				t.Fatalf("kind %d length %d admission differs", kind, length)
			}
			if !valid && packet != nil {
				t.Fatal("invalid input returned a packet")
			}
		}
	}
}
