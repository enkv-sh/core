# Troubleshoot an ENKV command

Keep the command's complete result before changing files or issuing another
mutation. A nonzero exit can coexist with a selected remote change or a delivered
local file. Start with the outcome and the failed stage, then correct that
specific cause.

Use `enkv COMMAND --help` for the installed command's grammar. For structured
errors, put `--json` before other command options, for example
`enkv apply --json --source enkv.yaml`. Configuration-reading commands otherwise
default to `enkv.yaml` in the current directory; they do not search parents.

## Find the right class of problem

| Symptom | What to check | Next step |
|---|---|---|
| Source cannot be read or parsed | Working directory, selected path, format, both configuration files and file permissions | Correct the path or syntax. Use [configuration](configuration.md). |
| A generated companion is missing | Whether a local transaction is pending and whether the companion is confirmed absent | Use the appropriate [recovery path](recovery.md). |
| `plugins.json` cannot be read or validated | The user settings file named in the diagnostic | Correct that file; preparation will not use an alternative plugin as fallback. |
| Plugin selection or installation is missing | Required local ID, version pin, platform and prior exact selection | Run `prepare` after checking [plugin setup](plugins.md). |
| Credential discovery fails | Which command role and service need credentials; the active AWS profile or GCP ADC context | Restore that limited credential context. |
| Provider denies access | Exact bucket, prefix, key or external destination and the acting principal | Check [AWS](aws-permissions.md) or [GCP permissions](gcp-permissions.md), or the output plugin's guide. |
| An operation is refused or blocked | Complete result reason, current work and warnings | Inspect current state before a new mutation. |
| A command or effect is unknown | Operation/Attempt IDs and any confirmed state or delivery | Preserve evidence and use [recovery](recovery.md); do not automatically resend. |

An AWS CLI login and GCP `gcloud` login do not by themselves establish every
credential route ENKV needs. AWS uses its standard SDK chain; GCP uses
Application Default Credentials. Domain Store/KMS credentials and plugin service
credentials can be different. The command's permissions remain separate from
installation readiness.

## Read the complete result

Omit `--json` for the shorter human summary. Use JSON when you need the complete
safe facts for diagnosis or automation. Read state, effect, warnings, evidence
and local delivery separately. In a combined `apply --publish` response, read
both stages: publication can fail after apply has completed.

Common exit meanings are:

- `0`: the operation completed or returned an admitted no-op.
- `2`: an input, admission, integrity or output failure; local cleanup or delivery
  can also fail after a known operation result.
- `3`: unavailable evidence, contention or an unresolved commit/delivery.

The command-specific result is decisive. A result-output or telemetry failure
can change the exit status without undoing an earlier state change. Keep the
bytes that were delivered and inspect current state rather than rerunning the
mutation to obtain another response.

These reads can help when the source pair is valid:

```sh
enkv inspect --json
enkv generated list --json
enkv receipt --json
```

To inspect a known operation, use `enkv receipt --operation "$operation_id"
--json`. Receipts have bounded retention. A missing receipt is not proof of no
effect, and public inspection does not expose secret value bytes.

## Local delivery and file access

Create output parent directories before `materialize`, `manifest` and commands
that deliver a successor pair. Use distinct paths; a successor pair in the same
directory with the same domain name can alias the original companion. Keep
source and output paths free of symlinks where the command requires native
regular files.

If a result names `local_delivery.recovery_source`, preserve the files and run
`recover` with that exact source and original format. If it reports uncertainty
without a confirmed saved source, retain the transaction state for inspection.
Do not delete lock or transaction files merely to make a command proceed.

Materialization can report a late failure after the new plaintext file was
installed. Check its installed verification and cleanup facts. Do not attach
that file or a private candidate to an issue report.

## Collect useful diagnostic information

For an ordinary bug report, include:

- The command name and flags, with private names and resource identifiers
  redacted where needed.
- The CLI archive/release name, operating system and architecture. The CLI has
  no `--version` command; use the archive and release records.
- The safe result, exit status, failed stage and relevant operation IDs.
- Whether the configuration pair changed, a file was delivered or a remote
  selection was confirmed.
- A small synthetic example that reproduces a parsing or configuration issue,
  when you can make one without secret material.

Review diagnostics before sharing them. Do not include cloud tokens, private
keys, plaintext inputs, materialized dotenv files, secret display output,
credential home directories or the generated companion by default. The
companion can contain encrypted proposals and local operational data even when
it has no plaintext secret.

Use [ordinary issue reporting](../README.md) for bugs. For a possible security
problem or secret disclosure, follow [the security policy](../SECURITY.md)
instead of a public issue.

[Operator guide](README.md) · [Recovery](recovery.md) · [Commands](commands.md)
