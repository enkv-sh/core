package contract

// GeneratorDeclaredGenerationReference names unchanged logical intent content.
// Selected-state admission, not this carrier, establishes its currentness.
type GeneratorDeclaredGenerationReference struct {
	Schema                               uint16
	Epoch                                uint64
	RetirementMode                       uint8
	ConfigContractID, ResourceContractID ID
	LifecycleMode                        GeneratorLifecycleMode
	CompletionClass                      uint8
	Intent                               GeneratorLogicalSlice
}
