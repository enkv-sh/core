package custody

import (
	"context"
	"io"
	"sync"
	"time"

	"enkv.sh/core/contract"
	privatecrypto "enkv.sh/crypto"
)

const (
	StandardValue            uint8 = 1
	EmptyValue               uint8 = 2
	MaximumValue             uint8 = 3
	HermeticCloudflareValue  uint8 = 4
	AlternateStandardValue   uint8 = 5
	AlternateMaximumValue    uint8 = 6
	SyntheticCloudflareValue uint8 = 7
)

func syntheticValue(choice uint8) ([]byte, bool) {
	switch choice {
	case StandardValue:
		return []byte("enkv first secret test value"), true
	case AlternateStandardValue:
		return []byte("enkv other secret test value"), true
	case EmptyValue:
		return []byte{}, true
	case HermeticCloudflareValue, SyntheticCloudflareValue:
		return []byte("Generated_secret_0123456789_ABCDEFGHIJKLMN"), true
	case MaximumValue, AlternateMaximumValue:
		v := make([]byte, contract.CryptoMaxRawValue)
		xor := byte(0)
		if choice == AlternateMaximumValue {
			xor = 1
		}
		for i := range v {
			v[i] = byte(i%251) ^ xor
		}
		return v, true
	default:
		return nil, false
	}
}

type privateSource struct {
	mu       sync.Mutex
	value    []byte
	position int
	closed   bool
}

func (s *privateSource) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, io.ErrClosedPipe
	}
	if s.position == len(s.value) {
		return 0, io.EOF
	}
	n := copy(p, s.value[s.position:])
	s.position += n
	return n, nil
}
func (s *privateSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.value[:cap(s.value)])
	s.value = nil
	return nil
}

// SealInput gives the trusted test producer its own short-lived runtime. The
// selected synthetic value and reader remain inside this facade. The complete
// target and recipient binding set are fixed before the first private read.
func (f *Fixture) SealInput(ctx context.Context, core contract.SealedInputCore, recipients []contract.ID, choice uint8) (body []byte, code contract.CryptoResultCode) {
	if len(recipients) < 1 || len(recipients) > contract.CryptoMaxValueEntryRecipients {
		return nil, contract.CryptoInvalidInput
	}
	var selected []contract.BindingTableRow
	refs := make([]contract.RecipientBindingReference, len(recipients))
	rows := f.Bindings()
	for i, id := range recipients {
		found := false
		for _, row := range rows {
			if row.SubjectKind != contract.OrdinaryWrapSubject || row.SubjectID != id {
				continue
			}
			digest, err := contract.PublicBindingDigest(row.Binding)
			if err != nil {
				return nil, contract.CryptoInvalidInput
			}
			selected = append(selected, row)
			refs[i] = contract.RecipientBindingReference{RecipientID: id, PublicBindingDigest: digest}
			found = true
			break
		}
		if !found {
			return nil, contract.CryptoInvalidInput
		}
	}
	digest, err := contract.IntendedRecipientBindingSetDigest(core.DomainID, f.authority, refs)
	if err != nil {
		return nil, contract.CryptoInvalidInput
	}
	value, ok := syntheticValue(choice)
	if !ok {
		return nil, contract.CryptoInvalidInput
	}
	input := &privateSource{value: value}
	defer func() {
		if err := input.Close(); err != nil {
			body, code = nil, contract.CryptoCustodyUnavailable
		}
	}()
	core.ContentLength = uint32(len(value))
	core.InputEncoding = contract.InputEncodingRaw
	core.RetainedLength = uint32(len(value))
	core.IntendedRecipientBindingSetDigest = digest
	runtime, err := privatecrypto.New(f.family, nil)
	if err != nil {
		return nil, contract.CryptoCustodyUnavailable
	}
	defer runtime.Close()
	admission := fixtureID(runtime.InstanceID(), "source", core.SourceID)
	if err := privatecrypto.TestAdmitInputSeal(runtime, admission, core, f.authority, selected, input, time.Now().Add(time.Minute)); err != nil {
		return nil, contract.CryptoInvalidAdmission
	}
	body, code = privatecrypto.TestSealInput(runtime, ctx, admission)
	if code != contract.CryptoSuccess {
		return nil, code
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted[contract.Hash(body)] = core
	return body, code
}
