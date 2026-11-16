# Work with configuration files

An initialized application has two related files:

```text
demo/
  enkv.yaml
  .enkv/
    demo.generated.json
```

`enkv.yaml` is editable. ENKV writes the companion file and the `generated`
reference in the editable file. `domain.name: demo` determines the companion
path; the editable filename does not. Initialization can also write a separate
`.init` record in `.enkv/`. Preserve ENKV-written records after a failure.

## Select a file

Commands use `enkv.yaml` in the current directory by default. ENKV does not
search parent directories. Most commands accept an explicit source:

```sh
enkv inspect --source /path/to/demo/enkv.yaml --json
enkv inspect --source /path/to/demo/config.json --json
```

The suffix selects YAML or JSON. For a different suffix, supply
`--source-format yaml` or `--source-format json`. Planning uses `--trusted`
and `--trusted-format` for the trusted pair, with separate `--candidate` and
`--candidate-format` options. `--json` changes result presentation, not the
configuration format.

The companion path is relative to the editable file's directory. Keep that
relationship when you copy or move a pair. Use regular files, not symlinks.

## Understand the editable fields

| Field | Purpose |
|---|---|
| `schema` | The configuration format, `enkv/configuration/v3`. |
| `domain` | Local name, cloud provider, Store, Authority keys and Recovery choice. |
| `recipients` | Additional recipients, keyed by local references such as `app`. |
| `entries` | The complete desired set of values and their memberships. |
| `outputs` | Complete output destinations and routing. |
| `plugins` | Optional plugin requirements and exact artifact-version pins. |
| `generated` | The ENKV-managed reference to the companion. |

Use the [AWS](quickstart-aws.md) or [GCP](quickstart-gcp.md) guide for a complete
empty setup file. Do not add a `generated` field or fabricate IDs before init.
Cloud profiles, credential files and endpoint overrides do not belong in this
configuration.

For an initialized pair, this is a plain entry inside `entries`:

```yaml
  APPLICATION_MODE:
    confidentiality: plain
    recipients: [app]
    source:
      kind: supplied
      value: production
```

This example assumes `app` has been prepared. Use `recipients: []` for
Authority-only access. Authority is included implicitly; do not add an
invented Authority reference to the list.

A supplied secret's editable declaration contains no plaintext:

```yaml
  API_TOKEN:
    confidentiality: secret
    recipients: [app]
    source:
      kind: supplied
```

`enkv set --name API_TOKEN` reads stdin and writes its protected input record to
the companion. A new declaration is incomplete until that step succeeds.
Do not put `value`, `bytes` or an invented encrypted record into a secret's
editable source. See [Your first secret](first-secret.md).

## Edit without losing data

Stop other writers and close manual editors while an ENKV local edit runs.
Keep both files from the same accepted edit. Do not hand-edit the companion,
copy a protected record to another name, or replace ENKV-managed recipient IDs.

Membership changes and new secret input must agree. Set the intended membership
before sealing a new input. If you change a pending secret proposal's bindings,
prepare valid bindings and run `set` again with the intended input. Existing
committed values have their own access-change rules; see [Access](access.md).

`apply` uses the whole declaration and does not rewrite either source file.
Omitting an existing entry requests its removal. Omitting a recipient does not
retire that recipient. Output edits also need apply before they become current.

You can keep an approved pair in a suitably controlled version-control system.
The companion contains encrypted inputs but also operational metadata; decide
who may read it. Never include plaintext input files, materialized `.env`
files, credentials or private keys. When merging, preserve complete matching
records in both files. A pair that parses successfully is not proof that its
requested change is safe.

## Encoding

Input and output encoding default to `raw`. `set --base64` expects canonical
padded Base64 input and retains that representation; it does not guess the
encoding. An entry's `output_encoding: base64` requests Base64 delivery after
apply. Keep binary values in a format the intended consumer supports.

The builtin dotenv writer accepts a defined UTF-8 representation. It does not
silently switch unsupported raw bytes to Base64. See [Outputs](outputs.md).

## Rename and recover

Use `enkv rename --name NEW_NAME` to change the local domain name and companion
path together. Use `recipients rename` for a local recipient reference. Neither
operation changes the cloud resources or substitutes a new RecipientID.

If the companion is missing or a local edit was interrupted, preserve the
remaining files and follow [Recovery](recovery.md). Deleting `.enkv/` is not a
reset procedure.

Next: [Daily operations](operations.md) or [Command reference](commands.md).
