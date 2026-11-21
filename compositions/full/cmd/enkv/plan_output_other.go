//go:build !unix

package main

import "os"

func duplicatePlanStream(*os.File) (*os.File, error) { return nil, os.ErrInvalid }
