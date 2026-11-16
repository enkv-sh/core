package installedarchive

import (
	"encoding/hex"
	"strconv"
	"strings"

	"enkv.sh/core/contract"
	"enkv.sh/core/format"
)

// RecoveryLocations are private setup and cleanup facts. Reconstruction receives
// only its console locator; no historical locator or Domain crosses that boundary.
type RecoveryLocations struct {
	PriorDomain  contract.ID
	CopiedPrefix string
}

func (l RecoveryLocations) Valid(condition, prefix string, current contract.ID) bool {
	if current.IsZero() || prefix == "" {
		return false
	}
	switch condition {
	case "new-domain-no-pin", "prior-domain-pin":
		return !l.PriorDomain.IsZero() && l.PriorDomain != current && l.CopiedPrefix == ""
	case "copied-location":
		return l.PriorDomain.IsZero() && l.CopiedPrefix == prefix+"/copied"
	default:
		return l == (RecoveryLocations{})
	}
}

// Target selects only an explicitly owned location and validates the complete
// key through the existing physical-key constructors before any provider call.
func (l RecoveryLocations) Target(family contract.Family, prefix string, current contract.ID, key string) (string, contract.ID, bool) {
	if current.IsZero() || prefix == "" || l.PriorDomain == current || l.CopiedPrefix != "" && l.CopiedPrefix != prefix+"/copied" || !l.PriorDomain.IsZero() && l.CopiedPrefix != "" {
		return "", contract.ID{}, false
	}
	selected := prefix
	if l.CopiedPrefix != "" && strings.HasPrefix(key, l.CopiedPrefix+"/") {
		selected = l.CopiedPrefix
	}
	if key == selected+"/HEAD" {
		return selected, current, !current.IsZero()
	}
	rest, ok := strings.CutPrefix(key, selected+"/")
	if !ok {
		return "", contract.ID{}, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return "", contract.ID{}, false
	}
	decode := func(value string) (contract.ID, bool) {
		var id contract.ID
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != len(id) || hex.EncodeToString(b) != value {
			return id, false
		}
		copy(id[:], b)
		return id, !id.IsZero()
	}
	domain, ok := decode(parts[0])
	if !ok || domain != current && (domain != l.PriorDomain || l.PriorDomain.IsZero() || selected != prefix) {
		return "", contract.ID{}, false
	}
	object, ok := decode(parts[len(parts)-1])
	if !ok {
		return "", contract.ID{}, false
	}
	var expected string
	var err error
	if len(parts) == 3 {
		switch parts[1] {
		case "configuration":
			expected, err = contract.StoreConfigurationKeyForID(family, selected, domain, object)
		case "result":
			expected, err = format.GeneratedResultKey(selected, domain, object)
		default:
			return "", contract.ID{}, false
		}
	} else {
		kinds := map[string]contract.Kind{"member": format.ValueEntryPageKind, "recipient": format.RecipientKind, "root": format.RootKind, "access": format.AccessKind, "support": contract.RequiredSupportKind, "admin-index": contract.AdministrativeIndexKind}
		kind, known := kinds[parts[1]]
		index, indexErr := strconv.ParseUint(parts[2], 10, 16)
		if !known || indexErr != nil || strconv.FormatUint(index, 10) != parts[2] {
			return "", contract.ID{}, false
		}
		expected, err = format.Key(selected, format.Ref{Kind: kind, Domain: domain, Object: object, Index: uint16(index), Format: format.Version, Length: 1, Digest: object})
	}
	if err != nil || expected != key {
		return "", contract.ID{}, false
	}
	return selected, domain, true
}
