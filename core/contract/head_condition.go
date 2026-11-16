package contract

const HeadConditionMaxLength = 1 + 4 + 256

// HeadCondition is either absence or a strict matching Token. Its zero value
// means absence; it never creates a matching token from an empty value.
type HeadCondition struct {
	match Token
}

func AbsentHeadCondition() HeadCondition { return HeadCondition{} }

func MatchHeadCondition(token Token) (HeadCondition, error) {
	if !token.Valid() {
		return HeadCondition{}, ErrRecord
	}
	return HeadCondition{match: token}, nil
}

func (c HeadCondition) IsAbsent() bool { return c.match == (Token{}) }

func (c HeadCondition) Token() (Token, bool) {
	if !c.match.Valid() {
		return Token{}, false
	}
	return c.match, true
}

func HeadConditionLength(c HeadCondition) (int, error) {
	if c.IsAbsent() {
		return 1, nil
	}
	if !c.match.Valid() {
		return 0, ErrRecord
	}
	return 1 + 4 + len(c.match.Value), nil
}

func writeHeadCondition(w *cryptoWriter, c HeadCondition) {
	if c.IsAbsent() {
		w.u8(0)
		return
	}
	writeToken(w, c.match)
}

func AppendHeadCondition(dst []byte, c HeadCondition) ([]byte, error) {
	if _, err := HeadConditionLength(c); err != nil {
		return nil, err
	}
	w := cryptoWriter{b: dst}
	writeHeadCondition(&w, c)
	return w.b, nil
}

func EncodeHeadCondition(c HeadCondition) ([]byte, error) {
	n, err := HeadConditionLength(c)
	if err != nil {
		return nil, err
	}
	w := cryptoWriter{b: make([]byte, 0, n)}
	writeHeadCondition(&w, c)
	return w.b, nil
}

// ParseHeadCondition consumes one condition and leaves an enclosing suffix.
// The returned matching token owns its bounded value bytes.
func ParseHeadCondition(b []byte) (HeadCondition, int, error) {
	if len(b) == 0 {
		return HeadCondition{}, 0, ErrRecord
	}
	if b[0] == 0 {
		return AbsentHeadCondition(), 1, nil
	}
	if !Family(b[0]).Valid() {
		return HeadCondition{}, 0, ErrRecord
	}
	token, n, err := ParseToken(b)
	if err != nil {
		return HeadCondition{}, 0, err
	}
	return HeadCondition{match: token}, n, nil
}

// InspectHeadCondition requires a complete condition. Its matching token owns
// at most 256 value bytes; it does not retain the input buffer.
func InspectHeadCondition(b []byte) (HeadCondition, error) {
	if len(b) > HeadConditionMaxLength {
		return HeadCondition{}, ErrRecordCapacity
	}
	c, n, err := ParseHeadCondition(b)
	if err != nil {
		return HeadCondition{}, err
	}
	if n != len(b) {
		return HeadCondition{}, ErrRecord
	}
	return c, nil
}

func DecodeHeadCondition(b []byte) (HeadCondition, error) {
	return InspectHeadCondition(b)
}
