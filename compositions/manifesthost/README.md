# Native manifest host

This private module admits a trusted installed manifest executable through
`manifest-wire-v2`. It accepts bounded author-declared format and settings
identities. It has no credential input, Store client or effect authority.

`NewNative` checks exact executable bytes, measured family facts and dependency
bytes. The returned host retains the executable path, digest and length,
descriptor identity and declared format/settings identities.

Call `Native.ValidateSettings` before dependent Reader admission. It runs one
bounded settings exchange and returns owned canonical bytes. Use that same
captured host for `Native.Render`, under the original finite context deadline.
Each call owns and joins its separate child and transport. The render borrows
its View until all users join, then transfers one exact-capacity artifact.

Runtime success checks authorized input at Core, selected build, correlation,
framing, byte bounds, deadline, process closure and exact delivered bytes.
Format correctness and semantic correspondence belong to plugin tests and
qualification. The evidence limit is `authorized-input-and-exact-bytes` for
every format. Format and service identities do not select a host parser or
provider catalog. Core selects the complete authorized projection and exact
semantic service filter from stored facts before rendering, then finishes final
Reader admission before artifact delivery.

Native launch supports Darwin arm64 and Linux amd64 with cgo. Linux requires
glibc 2.34 or later. The child has an empty environment, null standard streams
and three assigned request/artifact/status descriptors. Installed code remains
trusted code with its declared filesystem and network reach.

Run focused module tests through the implementation repository's existing test
launcher. Maximum projection/artifact tests require the full profile and
exclusive memory placement. Results on another platform do not qualify native
execution here.
