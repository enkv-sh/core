package core

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"enkv.sh/core/contract"
)

const (
	operatorPrefixPageKeys  = 128
	operatorPrefixPages     = 256
	operatorPrefixObjects   = 4096
	operatorPrefixBodyLimit = 512 << 10
	operatorPrefixTokenMax  = 8192
)

// Fixture cleanup admits only object names that the current Store format can
// construct. Both provider test routes use this grammar before read or delete.
func liveFixtureKeyLimit(head, objects, key string) uint32 {
	if key == head {
		return contract.MaxHeadLength
	}
	if len(key) > 1024 || !strings.HasPrefix(key, objects) {
		return 0
	}
	limit := uint32(contract.GeneratedResultRecordMaxLength)
	parts := strings.Split(strings.TrimPrefix(key, objects), "/")
	switch len(parts) {
	case 2:
		switch parts[0] {
		case "result":
		case "configuration":
			limit = contract.MaxStoreConfigurationLength
		default:
			return 0
		}
	case 3:
		index, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil || strconv.FormatUint(index, 10) != parts[1] {
			return 0
		}
		switch parts[0] {
		case "member":
			limit = contract.MaxValueEntryPageLength
			if index >= contract.MaxValueEntryPages {
				return 0
			}
		case "recipient":
			limit = contract.MaxRecipientPageLength
			if index >= contract.MaxRecipientPages {
				return 0
			}
		case "access", "support", "admin-index":
			limit = contract.MaxRequiredSupportPageLength
			if parts[0] == "access" {
				limit = contract.MaxAccessPageLength
			}
			if index >= contract.MaxChildPages {
				return 0
			}
		case "root":
			limit = contract.MaxRootLength
			if index != 0 {
				return 0
			}
		default:
			return 0
		}
	default:
		return 0
	}
	object := parts[len(parts)-1]
	if len(object) != 64 {
		return 0
	}
	bytes, err := hex.DecodeString(object)
	if err != nil || hex.EncodeToString(bytes) != object {
		return 0
	}
	var id contract.ID
	copy(id[:], bytes)
	if id.IsZero() {
		return 0
	}
	return limit
}

func liveFixtureKeyValid(head, objects, key string) bool {
	return liveFixtureKeyLimit(head, objects, key) != 0
}

// This is a test-fixture capability. It is not a Product Store operation.
type livePrefixCleaner struct {
	Store    contract.Store
	Check    func(context.Context) error
	List     func(context.Context, string, string) (livePrefixPage, error)
	Delete   func(context.Context, string, contract.Token) error
	ValidKey func(string) bool
}

type livePrefixPage struct {
	Keys []string
	Next string
}

// A completed scan proves only what the service listed during this scan.
// It does not prove that an unknown earlier create cannot arrive later.
func scanOperatorPrefix(ctx context.Context, cleaner *livePrefixCleaner, budget *runBudget, prefix string) ([]string, error) {
	if cleaner == nil || cleaner.List == nil || cleaner.ValidKey == nil ||
		!strings.HasPrefix(prefix, "enkv-test/") || !strings.HasSuffix(prefix, "/") || len(prefix) > 256 {
		return nil, errInventory
	}
	seenKeys := make(map[string]bool)
	seenTokens := make(map[string]bool)
	keys := make([]string, 0)
	token := ""
	for page := 0; page < operatorPrefixPages; page++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !budget.reserve(2, 2*operatorPrefixBodyLimit, "", 0) {
			return nil, errRunLimit
		}
		result, err := cleaner.List(ctx, prefix, token)
		if err != nil {
			return nil, err
		}
		if len(result.Keys) > operatorPrefixPageKeys || len(result.Next) > operatorPrefixTokenMax ||
			result.Next == token && result.Next != "" || result.Next != "" && seenTokens[result.Next] ||
			len(keys)+len(result.Keys) > operatorPrefixObjects {
			return nil, errInventory
		}
		for _, key := range result.Keys {
			if !strings.HasPrefix(key, prefix) || !cleaner.ValidKey(key) || seenKeys[key] {
				return nil, errInventory
			}
			seenKeys[key] = true
			keys = append(keys, key)
		}
		if result.Next == "" {
			return keys, nil
		}
		seenTokens[result.Next] = true
		token = result.Next
	}
	return nil, errors.Join(errInventory, errRunLimit)
}
