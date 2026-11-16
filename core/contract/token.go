package contract

const maxTokenValue = 256

// Token is an opaque concurrency token. A GCP token is a canonical API int64.
type Token struct {
	Family Family
	Value  string
}

type TokenView struct {
	Family Family
	Value  []byte
}

func tokenValid[S ~string | ~[]byte](family Family, value S) bool {
	if !family.Valid() || len(value) == 0 || len(value) > maxTokenValue {
		return false
	}
	if family == GCP {
		if len(value) > 19 || value[0] == '0' {
			return false
		}
		var n uint64
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return false
			}
			n = n*10 + uint64(value[i]-'0')
		}
		return n <= 1<<63-1
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for i := 1; i < len(value)-1; i++ {
		b := value[i]
		if b != 0x21 && (b < 0x23 || b > 0x7e) && b < 0x80 {
			return false
		}
	}
	return true
}

func (t Token) Valid() bool     { return tokenValid(t.Family, t.Value) }
func (t TokenView) Valid() bool { return tokenValid(t.Family, t.Value) }

func (t TokenView) Own() (Token, error) {
	if !t.Valid() {
		return Token{}, ErrRecord
	}
	return Token{Family: t.Family, Value: string(t.Value)}, nil
}

func writeToken(w *cryptoWriter, v Token) {
	w.u8(uint8(v.Family))
	w.blob([]byte(v.Value))
}

func readToken(r *cryptoReader) TokenView {
	v := TokenView{Family: Family(r.u8()), Value: r.blob(maxTokenValue)}
	if r.err == nil && !v.Valid() {
		r.err = ErrRecord
	}
	return v
}

func AppendToken(dst []byte, v Token) ([]byte, error) {
	if !v.Valid() {
		return nil, ErrRecord
	}
	w := cryptoWriter{b: dst}
	writeToken(&w, v)
	return w.b, nil
}

func ParseToken(b []byte) (Token, int, error) {
	r := newRecordReader(b)
	v := readToken(&r)
	if r.err != nil {
		return Token{}, 0, r.failure()
	}
	return Token{Family: v.Family, Value: string(v.Value)}, r.i, nil
}
