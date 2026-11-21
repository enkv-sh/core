package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"enkv.sh/compositions/configuration"
)

type planStream struct {
	writer io.Writer
	file   *os.File
	info   os.FileInfo
}

func holdPlanStream(w io.Writer) planStream {
	native, ok := w.(*os.File)
	if !ok {
		// Native process dispatch supplies files. Other writers are injected
		// by the in-process caller and have no native descriptor to redirect.
		return planStream{writer: w}
	}
	file, err := duplicatePlanStream(native)
	if err != nil {
		return planStream{}
	}
	info, err := file.Stat()
	if err != nil {
		return planStream{file: file}
	}
	return planStream{writer: file, file: file, info: info}
}

func (s planStream) regular() bool { return s.info != nil && s.info.Mode().IsRegular() }

func (s planStream) allowed(trusted, candidate *configuration.Pair, complete bool) bool {
	if !s.regular() {
		return s.writer != nil
	}
	return complete && trusted.AllowsOutputFile(s.info) && (candidate == nil || candidate.AllowsOutputFile(s.info))
}

func (s planStream) close() error {
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}

type planDisplaySources struct{ trusted, candidate *configuration.Pair }

func (p *planDisplaySources) capture(ctx context.Context, trusted string, format configuration.Format, candidate string, candidateFormat configuration.Format) bool {
	var err error
	p.trusted, err = configuration.Capture(ctx, trusted, format)
	if err == nil && candidate != "" {
		p.candidate, err = configuration.Capture(ctx, candidate, candidateFormat)
	}
	return err == nil
}

func (p planDisplaySources) close() error {
	return errors.Join(p.candidate.Close(), p.trusted.Close())
}

// A failed flag parse can stop before Set sees a requested selector. Use the
// spelling only to protect early output. It cannot select a source or a value.
func mayRequestPlanDisplay(args, remaining []string) bool {
	// The parser has consumed the offending flag, including a value-less
	// show-secret at end of input. Earlier consumed values are not flags.
	first := len(args) - len(remaining) - 1
	if first < 0 {
		return false
	}
	for _, arg := range args[first:] {
		name, _, _ := strings.Cut(arg, "=")
		if name == "-show-secret" || name == "--show-secret" {
			return true
		}
	}
	return false
}
