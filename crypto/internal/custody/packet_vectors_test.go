package custody

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPrivatePacketIndependentVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/private-packets-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Name, ContextHex, PacketContextDigest, PublicTestKeyBytes string
			PacketKind                                                uint16
			ExpectedPacket                                            struct {
				Hex, SHA256 string
				Length      int
			}
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Cases) == 0 {
		t.Fatal("empty private packet fixture")
	}
	for _, vector := range fixture.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			core, err := contract.DecodeWrapCore(hexBytes(t, vector.ContextHex))
			if err != nil {
				t.Fatal(err)
			}
			context, err := contract.RSAPacketContextDigest(core)
			if err != nil || !bytes.Equal(context[:], hexBytes(t, vector.PacketContextDigest)) {
				t.Fatal("packet context differs from independent digest")
			}
			keys := hexBytes(t, vector.PublicTestKeyBytes)
			defer clear(keys)
			want := hexBytes(t, vector.ExpectedPacket.Hex)
			defer clear(want)
			packet, err := EncodePacket(vector.PacketKind, context, keys)
			defer clear(packet)
			if err != nil || !bytes.Equal(packet, want) || len(packet) != vector.ExpectedPacket.Length || fmt.Sprintf("%x", sha256.Sum256(packet)) != vector.ExpectedPacket.SHA256 {
				t.Fatal("packet differs from independent bytes")
			}
			opened, err := PacketKeys(want, vector.PacketKind, context)
			if err != nil || !bytes.Equal(opened, keys) || cap(opened) != len(keys) {
				t.Fatal("independent packet did not expose the exact key region")
			}
			for i := 0; i < packetHeader; i++ {
				damaged := bytes.Clone(want)
				damaged[i] ^= 1
				got, err := PacketKeys(damaged, vector.PacketKind, context)
				clear(damaged)
				if err == nil || got != nil {
					t.Fatalf("changed packet header byte %d exposed keys", i)
				}
			}
		})
	}
}
