package core

import (
	"encoding/base64"

	"enkv.sh/core/contract"
)

type comparisonPlainValue struct {
	inputEncoding uint8
	retained      []byte
}

func (value comparisonPlainValue) contentLength() (int, error) {
	length, err := contract.InputContentLength(value.inputEncoding, value.retained)
	return int(length), err
}

func (value comparisonPlainValue) ownApplicationBytes() contract.ComparisonValue {
	length, err := value.contentLength()
	if err != nil {
		return nil
	}
	owned := make(contract.ComparisonBytes, length)
	if value.inputEncoding == contract.InputEncodingRaw {
		copy(owned, value.retained)
		return owned
	}
	n, err := base64.StdEncoding.Strict().Decode(owned, value.retained)
	if err != nil || n != length {
		clear(owned)
		return nil
	}
	return owned
}

type comparisonPlainCursor struct {
	value             comparisonPlainValue
	offset, at, count int
	decoded           [3]byte
}

func (cursor *comparisonPlainCursor) next() (byte, bool) {
	if cursor.value.inputEncoding == contract.InputEncodingRaw {
		if cursor.offset == len(cursor.value.retained) {
			return 0, false
		}
		value := cursor.value.retained[cursor.offset]
		cursor.offset++
		return value, true
	}
	if cursor.at == cursor.count {
		if cursor.offset == len(cursor.value.retained) {
			return 0, false
		}
		if len(cursor.value.retained)-cursor.offset < 4 {
			return 0, false
		}
		n, err := base64.StdEncoding.Strict().Decode(cursor.decoded[:], cursor.value.retained[cursor.offset:cursor.offset+4])
		if err != nil {
			return 0, false
		}
		cursor.offset += 4
		cursor.at, cursor.count = 0, n
	}
	value := cursor.decoded[cursor.at]
	cursor.at++
	return value, true
}

func plainComparisonEqual(a, b comparisonPlainValue) bool {
	left, leftErr := a.contentLength()
	right, rightErr := b.contentLength()
	if leftErr != nil || rightErr != nil || left != right {
		return false
	}
	x, y := comparisonPlainCursor{value: a}, comparisonPlainCursor{value: b}
	for i := 0; i < left; i++ {
		av, aOK := x.next()
		bv, bOK := y.next()
		if !aOK || !bOK || av != bv {
			return false
		}
	}
	return true
}

func publicPlainComparisonField(encoding contract.PublicField[uint8], value contract.PublicField[[]byte]) contract.PublicField[comparisonPlainValue] {
	state := value.State
	if state == contract.PublicPresent && encoding.State != contract.PublicPresent {
		state = encoding.State
	}
	return contract.PublicField[comparisonPlainValue]{State: state, SourceLocation: value.SourceLocation, Value: comparisonPlainValue{inputEncoding: encoding.Value, retained: value.Value}}
}
