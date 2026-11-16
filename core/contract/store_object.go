package contract

import (
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

type StoreObjectNamespace uint8

const (
	StorePageObject StoreObjectNamespace = iota + 1
	StoreResultObject
	StoreConfigurationObject
	MaxStoreObjectKeyLength = 658
)

type StoreObjectIdentity struct {
	Namespace StoreObjectNamespace
	Kind      Kind
	Index     uint16
	ObjectID  ID
}

func StoreObjectLimit(v StoreObjectIdentity) uint32 {
	if v.ObjectID.IsZero() {
		return 0
	}
	switch v.Namespace {
	case StoreResultObject:
		if v.Kind == 0 && v.Index == 0 {
			return uint32(GeneratedResultRecordMaxLength)
		}
	case StoreConfigurationObject:
		if v.Kind == 0 && v.Index == 0 {
			return MaxStoreConfigurationLength
		}
	case StorePageObject:
		if v.Index >= childPageIndexCount(v.Kind) && v.Kind != RootKind {
			return 0
		}
		if v.Kind == RootKind && v.Index != 0 {
			return 0
		}
		switch v.Kind {
		case ValueEntryPageKind:
			return MaxValueEntryPageLength
		case RecipientKind:
			return MaxRecipientPageLength
		case RootKind:
			return MaxRootLength
		case AccessKind:
			return MaxAccessPageLength
		case RequiredSupportKind, AdministrativeIndexKind:
			return MaxRequiredSupportPageLength
		}
	}
	return 0
}
func storeObjectPrefixValid(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > MaxStorePrefixLength || !utf8.ValidString(prefix) {
		return false
	}
	for _, p := range strings.Split(prefix, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	for _, c := range prefix {
		if c < 32 || c == 127 || c == '\\' || c == '?' || c == '#' {
			return false
		}
	}
	return true
}
func StoreObjectKey(prefix string, domain ID, v StoreObjectIdentity) (string, error) {
	if !storeObjectPrefixValid(prefix) || domain.IsZero() || StoreObjectLimit(v) == 0 {
		return "", ErrRecord
	}
	base := prefix + "/" + hex.EncodeToString(domain[:]) + "/"
	object := hex.EncodeToString(v.ObjectID[:])
	if v.Namespace == StoreResultObject {
		return base + "result/" + object, nil
	}
	if v.Namespace == StoreConfigurationObject {
		return base + "configuration/" + object, nil
	}
	var kind string
	switch v.Kind {
	case ValueEntryPageKind:
		kind = "member"
	case RecipientKind:
		kind = "recipient"
	case RootKind:
		kind = "root"
	case AccessKind:
		kind = "access"
	case RequiredSupportKind:
		kind = "support"
	case AdministrativeIndexKind:
		kind = "admin-index"
	default:
		return "", ErrRecord
	}
	return base + kind + "/" + strconv.Itoa(int(v.Index)) + "/" + object, nil
}
func ParseStoreObjectKey(prefix string, domain ID, key string) (StoreObjectIdentity, error) {
	var v StoreObjectIdentity
	base := prefix + "/" + hex.EncodeToString(domain[:]) + "/"
	if !storeObjectPrefixValid(prefix) || domain.IsZero() || len(key) > MaxStoreObjectKeyLength || !strings.HasPrefix(key, base) {
		return v, ErrRecord
	}
	parts := strings.Split(strings.TrimPrefix(key, base), "/")
	if len(parts) == 2 {
		switch parts[0] {
		case "result":
			v.Namespace = StoreResultObject
		case "configuration":
			v.Namespace = StoreConfigurationObject
		default:
			return v, ErrRecord
		}
	} else if len(parts) == 3 {
		v.Namespace = StorePageObject
		switch parts[0] {
		case "member":
			v.Kind = ValueEntryPageKind
		case "recipient":
			v.Kind = RecipientKind
		case "root":
			v.Kind = RootKind
		case "access":
			v.Kind = AccessKind
		case "support":
			v.Kind = RequiredSupportKind
		case "admin-index":
			v.Kind = AdministrativeIndexKind
		default:
			return v, ErrRecord
		}
		n, e := strconv.ParseUint(parts[1], 10, 16)
		if e != nil || strconv.FormatUint(n, 10) != parts[1] {
			return v, ErrRecord
		}
		v.Index = uint16(n)
	} else {
		return v, ErrRecord
	}
	text := parts[len(parts)-1]
	if len(text) != 64 {
		return v, ErrRecord
	}
	b, e := hex.DecodeString(text)
	if e != nil || hex.EncodeToString(b) != text {
		return v, ErrRecord
	}
	copy(v.ObjectID[:], b)
	exact, e := StoreObjectKey(prefix, domain, v)
	if e != nil || exact != key {
		return StoreObjectIdentity{}, ErrRecord
	}
	return v, nil
}
