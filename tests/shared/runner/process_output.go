package main

import "bytes"

const maximumToolOutputBytes = 32 << 20

type limitedOutput struct {
	buffer               bytes.Buffer
	overflow             bool
	privateErrorOutput   []byte
	privateErrorStart    int
	privateErrorOverflow bool
}

func (b *limitedOutput) Len() int       { return b.buffer.Len() }
func (b *limitedOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitedOutput) String() string { return b.buffer.String() }

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maximumToolOutputBytes - b.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}
