// Package credentials owns AWS default credential discovery and authentication observation.
package credentials

import "errors"

var ErrCredentials = errors.New("AWS credential file refused")
