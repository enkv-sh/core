package core

import (
	"unsafe"

	"enkv.sh/core/contract"
)

// The semantic account includes canonical field framing. This separate account
// charges owned Go rows, collection descriptors and text descriptors' additional
// twelve bytes beyond their canonical four-byte length. Allocator rounding and
// runtime indexing capacity are outside the application backing account.
func publicConfigurationBackingBounded(v contract.PublicConfiguration) bool {
	typed := uint64(unsafe.Sizeof(v))
	typed += uint64(len(v.Entries.Value)) * uint64(unsafe.Sizeof(contract.PublicEntry{}))
	typed += uint64(len(v.Recipients.Value)) * uint64(unsafe.Sizeof(contract.PublicRecipient{}))
	typed += uint64(len(v.OutputBindings.Value)) * uint64(unsafe.Sizeof(contract.PublicOutputBinding{}))
	typed += uint64(len(v.Routing.Value)) * uint64(unsafe.Sizeof(contract.PublicRoutingRule{}))
	sources := uint64(32 + 6*len(v.Entries.Value) + 7*len(v.Recipients.Value) + 2*len(v.OutputBindings.Value) + len(v.Routing.Value))
	for _, entry := range v.Entries.Value {
		typed += uint64(32 * len(entry.Memberships.Value))
		if entry.Generated != nil {
			typed += uint64(unsafe.Sizeof(contract.PublicGeneratedSettings{}))
			sources += 7
		}
	}
	for _, binding := range v.OutputBindings.Value {

		typed += uint64(len(binding.Targets.Value)) * uint64(unsafe.Sizeof(contract.PublicOutputTarget{}))
		sources += uint64(11 * len(binding.Targets.Value))
	}
	for _, group := range v.Groups.Value {
		typed += uint64(unsafe.Sizeof(group)) + uint64(len(group))*uint64(unsafe.Sizeof(""))
	}
	for _, route := range v.Routing.Value {
		typed += uint64(len(route.Destinations.Value)) * uint64(unsafe.Sizeof(""))
	}
	if v.Recovery.Signing != nil {
		typed += uint64(unsafe.Sizeof(*v.Recovery.Signing))
	}
	if v.Recovery.Encryption != nil {
		typed += uint64(unsafe.Sizeof(*v.Recovery.Encryption))
	}
	return typed <= contract.MaxPublicTypedConfigurationBytes && sources*(uint64(unsafe.Sizeof(contract.SourceLocation{}))+64) <= contract.MaxPublicSourceLocationBytes
}
