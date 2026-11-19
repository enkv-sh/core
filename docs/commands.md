# Command reference

Run `enkv --help` to list commands and `enkv COMMAND --help` for accepted flags.
For nested commands, use a form such as `enkv generated retire --help`.
The CLI has no `--version` command; use the release archive records and checksums
to identify the installed release.

Most commands read `enkv.yaml` in the current directory by default. They do not
search parent directories. Use `--source PATH` to choose another file. `plan`
uses `--trusted PATH` and optionally `--candidate PATH` instead. An explicit
`.yaml`, `.yml` or `.json` suffix selects syntax; use the corresponding
`--source-format`, `--trusted-format` or `--candidate-format` option for another
suffix. Each selects `yaml` or `json`.

`--json` selects the complete structured result. Put it before other options
when scripts need structured argument errors. Command output goes to stdout;
diagnostics go to stderr. A truncated or missing result is not a successful
operation record.

## Recipient selection

`--recipient REF` selects a local alias such as `recipient`. `--recipient-id ID`
selects an exact nonzero 64-character lowercase hexadecimal ID. Use only one
flag. An unknown alias or invalid ID fails; neither falls back to Authority.
Even an alias that looks like a hexadecimal ID is treated only as an alias.

Inspection, materialization and manifests support both forms. Rename,
retirement, recipient-key replacement and `recipients add --mode current` also
support both forms and require an explicit target in the local declaration.
`recipients add --mode create` requires the new or existing local alias; ENKV
generates the new identity, so `--recipient-id` is invalid for create mode.

## Setup and local changes

| Command | Purpose | Changes remote state? |
|---|---|---|
| `prepare` | Acquire or assess declared plugins for an existing pair; explicit cloud reconstruction inputs support lost-file preparation. | No. Reconstruction reads authenticated state. |
| `init` | Initialize an empty domain using existing keys and an explicit Recovery choice. | Yes. |
| `set --name NAME` | Read supplied bytes from stdin and prepare the local entry; confidential by default. | No. |
| `rename --name NAME` | Change the local domain name and companion path together. | No. |
| `recipients add --recipient REF --mode create\|current` | Prepare or refresh public recipient data locally. | No. |
| `recipients rename --recipient REF --new-reference REF` | Rename the local reference in both files. | No. |
| `recover` | Complete an exact saved local file transaction. | No. |

See [configuration](configuration.md), [access](access.md) and [recovery](recovery.md).
These local edits do not apply themselves. Installing a plugin does not grant
cloud permission or authority to run its effects.

## Review, apply and consume

| Command | Purpose |
|---|---|
| `plan` | Compare the complete proposed declaration with an authenticated current observation. |
| `plan --check-secrets` | Also authenticate and compare supplied secrets through Authority decryption. |
| `plan --check-secrets --show-secret NAME` | Deliberately display a selected proposed supplied secret; repeat for distinct names. |
| `apply` | Apply the complete declaration as Authority, including requested generated work. |
| `apply --operation ID` | Continue selected accepted generated apply work using its original intent. |
| `publish --name NAME` | Publish selected current values to configured outputs; repeat for distinct names. |
| `apply --publish` | Complete apply, then evaluate publication if apply completes. |
| `inspect` | Read current domain metadata without value bytes. |
| `inspect --recipient REF` | Read entry metadata granted to one exact recipient. |
| `inspect --capacity [--cursor TOKEN]` | Read bounded capacity and storage-candidate information. |
| `receipt [--operation ID]` | List retained receipts or read one exact receipt. |
| `materialize --name NAME [--recipient REF] --out PATH` | Write selected current values to a private dotenv file. Repeat names explicitly. |
| `manifest --plugin LOCAL-ID --out PATH` | Render secret-free consumption wiring for the selected recipient and entries. |

`plan --publish` also previews publication. Standalone `publish` requires
explicit names or `--delete-coordinate ID=LOCAL-PLUGIN-ID`; it does not apply
pending edits. Uncertain publication has explicit
`--republish-after-unknown ATTEMPT-ID` rules. Review these in
[plugins and outputs](plugins.md) before authorizing another send.

`materialize` requires at least one name and an existing output directory.
Omitting both recipient flags selects current Authority for `materialize` and
`manifest`, including shared entries. Membership and the operation's cloud
permissions are still checked. Plain `inspect` keeps the domain overview.
For `manifest`, repeat `--name` to narrow its selection, or use
`--empty-selection`. Its optional `--service` filters an exact stored semantic
service identity.

## Generated work and maintenance

| Command | Purpose |
|---|---|
| `generated list` | Read selected generations, operations, attempts and remaining work. |
| `generated retire --duty ID` or `--operation ID` | Retire exact accepted managed-resource work. |
| `generated accept-retirement-risk --duty ID --attempt ID` | Record an explicit risk decision; it sends no provider request. |
| `generated cleanup [--operation ID]` | Process eligible original results and select owned residue cleanup. |
| `rekey --name NAME --out PATH` | Refresh a current secret's protection while keeping its value. |
| `recipients retire --recipient REF --out PATH` | Retire an ordinary recipient and its memberships. |
| `keys replace --target authority\|recovery\|recipient --out PATH ...` | Replace an existing cloud key binding. |
| `gc plan --out PATH [--cursor TOKEN]` | Deliver a protected exact garbage-collection preview. |
| `gc apply --plan PATH` or `--operation ID` | Apply that GC plan or continue its selected operation. |
| `abandon list` | Read legal selected-work targets and retained abandonment results. |
| `abandon plan --target ID --out PATH` | Deliver a protected work-ending disposition for review. |
| `abandon apply --plan PATH` | Apply that exact disposition as Authority. |
| `abandon receipt --operation ID` | Read an exact retained abandonment result. |

See [maintenance](maintenance.md) and [plugins and outputs](plugins.md) before
using these commands. There is no separate `rotate` or `succession` command.
Change a generated entry's epoch and apply to request a new generation; use
`keys replace` for supported key changes.

## Exit codes and result handling

| Exit | Meaning |
|---|---|
| `0` | Complete success or the command's admitted no-op. For plan, a complete match in its stated scope. |
| `1` | Plan found a complete verified difference. |
| `2` | Input, admission, integrity, local cleanup or result delivery failure. |
| `3` | Unavailable required evidence, contention, pending delivery or unresolved selection. |

Read the operation-specific result as well as the exit code. A failure can
follow a known remote selection or confirmed local delivery. For combined
apply/publication, read both stages; publication failure does not undo apply.
State selection, external effects, warnings and remaining work are separate.
An exit code alone cannot authorize a retry.

Ordinary `--json` output is one safe JSON result. Explicit secret display uses
NDJSON with secret-display records followed by the final plan result. Protect
that stream as secret data. Commands use a five-minute deadline.

For less common selectors and detailed result fields, see the
[full CLI reference](../compositions/full/README.md). Return to the
[operator guide](README.md).
