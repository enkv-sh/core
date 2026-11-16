# Output contract test child

The contract-test child accepts fixed private test credentials, complete fixed
policy sets and fixed payload bytes. It returns a distinct qualified instance
for each create attempt and requires that exact birth instance for later value,
policy and owned deletion requests. Retained deletion accepts the canonical
empty policy. The child is a local conformance fixture and does not call a
production service.

The child uses the public output SDK's `Run` and `RunPublic` adapters for its
ordinary exchanges. Its local owner closes the borrowed descriptors. Deliberate
refusal-frame corruption, extra frames, process exits and cleanup faults remain
private fixture controls; they are absent from the public SDK and source kits.
