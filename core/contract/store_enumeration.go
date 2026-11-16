package contract

import "context"

const (
	StoreListPageEntries   = 256
	StoreListKeyLength     = 1024
	StoreListCursorLength  = 4096
	StoreListResponseBytes = 2 << 20
)

type ListPageStatus uint8

const (
	ListPageOK ListPageStatus = iota + 1
	ListPageUnavailable
	ListPageInvalid
)

// ListPageResult owns its key strings and cursor. Names are candidates, not
// evidence of ownership, currentness, absence or enumeration completeness.
type ListPageResult struct {
	Status     ListPageStatus
	Keys       []string
	NextCursor string
	Reason     Reason
}

// BoundedEnumerationStore lists one page in the Store's fixed domain prefix.
// The caller cannot select another bucket, prefix or page size.
type BoundedEnumerationStore interface {
	ListPage(context.Context, string) ListPageResult
}
