package compositionfull

import "os"

func syncManifestFile(file *os.File) error { return file.Sync() }
