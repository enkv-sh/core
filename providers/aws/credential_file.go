package awsprovider

import (
	"context"
	"io"
	"os"
)

type credentialFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
}

func captureCredentialFile(ctx context.Context, path string, limit int64) ([]byte, bool) {
	f, err := openCredentialFile(ctx, path)
	if err != nil {
		return nil, false
	}
	body, accepted := captureOpenedCredentialFile(f, limit)
	if ctx != nil && ctx.Err() != nil {
		clearCredentialBytes(body)
		return nil, false
	}
	return body, accepted
}

func captureOpenedCredentialFile(f credentialFile, limit int64) ([]byte, bool) {
	if f == nil || limit <= 0 {
		if f != nil {
			_ = f.Close()
		}
		return nil, false
	}

	var (
		before os.FileInfo
		after  os.FileInfo
		b      []byte
		err    error
	)
	before, err = f.Stat()
	if err == nil && before.Mode().IsRegular() && before.Size() > 0 && before.Size() <= limit {
		b = make([]byte, int(before.Size())+1)
		var n int
		n, err = io.ReadFull(f, b)
		if n == int(before.Size()) && (err == io.EOF || err == io.ErrUnexpectedEOF) {
			b = b[:n]
			err = nil
		} else if err == nil {
			err = ErrCredentials
		}
		if err == nil {
			after, err = f.Stat()
		}
		if err == nil && (len(b) == 0 || int64(len(b)) > limit || int64(len(b)) != before.Size() || !credentialFileInfoStable(before, after)) {
			err = ErrCredentials
		}
	} else if err == nil {
		err = ErrCredentials
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		clearCredentialBytes(b)
		return nil, false
	}
	return b, true
}

func clearCredentialBytes(b []byte) {
	clear(b[:cap(b)])
}
