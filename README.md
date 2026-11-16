# ENKV

ENKV manages application secrets through an authenticated state stored in AWS
S3 or Google Cloud Storage. AWS KMS or Google Cloud KMS supplies signing and
secret-encryption keys. Each domain uses one cloud provider for storage, trust,
encryption and optional Recovery.

The full CLI supports both cloud providers on native macOS/arm64 and
Linux/x86_64. Use it to store supplied or generated secrets, control application
access and deliver current values to files or supported services. ENKV uses your
cloud credentials; it does not create cloud resources or an ENKV account.

## Use ENKV

Start with the [operator guide](docs/README.md). It explains the concepts before
the commands and takes you through one secret from setup to application use.

- [Install a binary](docs/install.md): no source checkout, Go or Git required.
- [Set up AWS](docs/quickstart-aws.md) or [set up GCP](docs/quickstart-gcp.md).
- [Store and consume your first secret](docs/first-secret.md).
- [Daily operations](docs/operations.md), [recovery](docs/recovery.md) and
  [troubleshooting](docs/troubleshooting.md).

Use the [command reference](docs/commands.md) to find a task. Developers can use
the [full CLI reference](compositions/full/README.md) and
[configuration library reference](compositions/full/library.md).

Official generators, output plugins, manifest generators, public protocols and
SDKs live in [enkv-sh/extensions](https://github.com/enkv-sh/extensions).
Plugins are separate native executables. Preparation authenticates an official
build or captures an explicitly trusted local author build before use. Plugin
installation does not grant cloud permissions or authorize effects.

Report ordinary bugs through [GitHub Issues](https://github.com/enkv-sh/core/issues).
Use the [security reporting procedure](SECURITY.md) for suspected vulnerabilities.

## Source layout

| Directory | Responsibility |
|---|---|
| `core/` | State authentication, operation admission, transitions and lifecycle contracts. |
| `crypto/` | Secret custody, encryption, decryption and private key operations. |
| `providers/` | AWS and GCP Store/KMS adapters. |
| `compositions/` | CLI, configuration, native plugin hosts and assembled provider dependencies. |
| `telemetry/` | Shared telemetry interfaces and helpers. |
| `tests/` | Component scenarios, native test runner, synthetic fixtures and opt-in live tests. |
| `distribution/` | Native CLI packaging instructions. |

## Licensing

Copyright 2026 Ruslan Akchurin. First-party material in this repository uses
[PolyForm Shield 1.0.0](LICENSE), except where separate terms are stated.
The packaging documentation in `distribution/` uses
[Apache License 2.0](distribution/LICENSE). Public SDKs, protocols, author tools
and official plugins use Apache 2.0 in the extensions repository. Third-party
material retains its own licenses and notices.

Shield permits use subject to its terms, including its noncompete restriction.
It is a source-available license. Read the license before reuse or redistribution.
The [copyright notice](NOTICE) accompanies each core module. Binary archives
include `LICENSE`, `NOTICE` and `THIRD_PARTY_NOTICES.md`; retain these files
when you distribute an archive or its executable.

## Build from source

Use stock Go 1.27.3, Git and a native C toolchain. Supported artifact targets
are macOS/arm64 and Linux/x86_64; Linux requires glibc 2.34 or later.
The native hosts use cgo. Cross-compilation does not establish native support.

Keep the source repositories in sibling directories named `enkv-core` and
`enkv-extensions`. From the extensions directory, generate the coordinated
workspace and module source tables:

```sh
GOWORK=off go run distribution/generate.go -root .
GOWORK=off go run distribution/generate.go -root . -check
```

Then build the full CLI from the core directory:

```sh
GOWORK=/absolute/enkv-extensions/go.work go -C compositions/full build -o /absolute/tools/enkv ./cmd/enkv
```

Create the output tools directory first. A plain source build does not supply
production release trust roots. Use the [CLI packaging guide](distribution/cli-packaging.md)
for an archive with explicit CLI and plugin verification roots. The
[source distribution guide](https://github.com/enkv-sh/extensions/blob/main/distribution/README.md)
describes exact versioned dependencies, detached SDK source and Go mappings.

## Tests

The [test instructions](tests/README.md) define native supervisor setup,
module-cache preparation, focused selection and result records. Setup needs
stock Go 1.27.3, a native C toolchain and the pinned dependencies in the module
cache. From this repository:

```sh
tests/scripts/setup-supervisor
tests/scripts/test run --workflow tests/workflows/dev.json --step components --test TestInstalledApplyReservationPreservesSelectedReadFailureCategory --parallel 1
```

Select checks for the changed behavior. `dev` and `check` are available workflows;
a focused change does not require running both. Results establish only the
selected source, native platform and behavior. Provider-live tests need explicit
resources, limited credentials and authorization; ordinary local tests need no
cloud account.

`make fmt` formats maintained Go source. `make lint` checks formatting, registered
module dependencies and the configured linters. Lint also needs the standalone
golangci-lint v2.14.0 binary on `PATH`. Materialization consumer checks need Node
v24.19.0 and dotenv 18.0.9; follow the
[consumer fixture instructions](tests/fixtures/dotenv-consumer/README.md).
