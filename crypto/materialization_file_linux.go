package crypto

import "os"

func syncMaterializationFile(f *os.File) error { return f.Sync() }
