package configuration

import "os"

type capturedImage struct {
	image  *Image
	file   *os.File
	size   int64
	digest [32]byte
	path   string
}

type capturedPair struct {
	pair      *Pair
	format    Format
	locks     *pathLocks
	editable  capturedImage
	generated capturedImage
}

func imageIdentity(image *Image) capturedImage {
	if image == nil {
		return capturedImage{}
	}
	return capturedImage{image: image, file: image.file, size: image.size, digest: image.digest, path: image.path}
}

// sealPair is restricted to the owners that freeze both images together.
func sealPair(pair *Pair) error {
	if pair == nil || pair.Editable == nil || pair.Editable.file == nil || pair.Format != JSON && pair.Format != YAML || pair.Generated != nil && pair.Generated.file == nil {
		return ErrCapture
	}
	pair.captured = &capturedPair{pair: pair, format: pair.Format, locks: pair.ownedLocks, editable: imageIdentity(pair.Editable), generated: imageIdentity(pair.Generated)}
	return nil
}

func (pair *Pair) validateCaptured() error {
	if pair == nil || pair.captured == nil {
		return ErrCapture
	}
	fixed := pair.captured
	if fixed.pair != pair || fixed.format != pair.Format || fixed.locks != pair.ownedLocks || fixed.locks != nil && fixed.locks.closed || fixed.editable != imageIdentity(pair.Editable) || fixed.generated != imageIdentity(pair.Generated) || pair.Editable == nil || pair.Editable.file == nil || pair.Generated != nil && pair.Generated.file == nil {
		return ErrCapture
	}
	// A caller can close an exposed image's owner through Image.Close; checking
	// the native descriptor also rejects an independently closed file owner.
	for _, image := range []*Image{pair.Editable, pair.Generated} {
		if image != nil {
			if _, err := image.file.Stat(); err != nil {
				return captureCause(err)
			}
		}
	}
	return nil
}
