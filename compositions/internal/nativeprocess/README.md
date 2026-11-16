# Native process launch mechanics

This private module serves the output and manifest hosts. It owns descriptor
duplication and native process launch, cancellation callback settlement, and
process Wait. It supports the existing Darwin/Linux cgo construction and pinned
`golang.org/x/sys` dependency.

Each host owns its protocol, credentials, executable authentication and staging,
deadline, result qualification, and final resource disposal. This module grants
no effect authority and does not change the native plugin trust model.
