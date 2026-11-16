package custody

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var ErrPacket = errors.New("private packet refused")

const packetHeader = 36

func keyLength(kind uint16) int {
	switch kind {
	case 1, 6:
		return 64
	case 2, 3, 4, 5:
		return 32
	default:
		return 0
	}
}

func EncodePacket(kind uint16, context [32]byte, keys []byte) ([]byte, error) {
	length := keyLength(kind)
	if length == 0 || len(keys) != length {
		return nil, ErrPacket
	}
	packet := make([]byte, packetHeader+length)
	binary.BigEndian.PutUint16(packet, 2)
	binary.BigEndian.PutUint16(packet[2:], kind)
	copy(packet[4:packetHeader], context[:])
	copy(packet[packetHeader:], keys)
	return packet, nil
}

// PacketKeys borrows only the checked key region. Its caller owns and clears
// the packet after the private operation completes.
func PacketKeys(packet []byte, kind uint16, context [32]byte) ([]byte, error) {
	length := keyLength(kind)
	if length == 0 || len(packet) != packetHeader+length || binary.BigEndian.Uint16(packet) != 2 ||
		binary.BigEndian.Uint16(packet[2:]) != kind || subtle.ConstantTimeCompare(packet[4:packetHeader], context[:]) != 1 {
		return nil, ErrPacket
	}
	return packet[packetHeader:len(packet):len(packet)], nil
}
