# Daily operations

Use this guide after [your first secret](first-secret.md). The examples use the
complete `enkv.yaml` configuration pair for the `demo` domain. Run them from
Authority's workspace with the Authority credentials for domain changes.

The editable file describes the **complete desired state**. `set` and manual
edits prepare changes locally. `apply` makes accepted changes current in the
domain. Keep `enkv.yaml` and `.enkv/demo.generated.json` together. See
[configuration files](configuration.md) before moving or merging them.

## Change a supplied secret

Place the exact new value in a protected file, supplied by your password manager
or another trusted source. The file must contain only the intended value: a
final newline is part of the input. Then run:

```sh
enkv set --json --source enkv.yaml --name API_TOKEN < /protected/new-api-token
```

`set` reads standard input once. Confidential input is the default. It seals the
value for this configuration and writes the local pair; it makes no cloud state
change. Do not put the secret in command arguments or paste it into YAML.

Check the local delivery result before continuing. If it identifies a
`recovery_source`, follow [local edit recovery](recovery.md). Keep any confirmed
delivered files even when a later cleanup step fails.

Review the proposed change:

```sh
enkv plan --json --trusted enkv.yaml --check-secrets
```

This compares the declaration with one authenticated current state and checks
supplied-secret equality using the current Authority decryption route. It makes
no mutation. Exit `1` means a complete verified difference; this is expected for
a changed value. Exit `0` means a match within the checked scope. Resolve exit
`2` or `3` before proceeding.

Apply the complete declaration as Authority:

```sh
enkv apply --json --source enkv.yaml
```

Read the result's state, warnings and remaining work. Successful apply leaves
both input files unchanged. When the worker needs the new value, the Recipient can
[materialize it again](first-secret.md#5-materialize-as-the-recipient). The worker
must reload the file to use the new value.

## Add a secret or plain value

For a new secret, prepare any additional recipients through
[access management](access.md), then add the entry declaration with its intended
recipient list before running `set`. Follow [your first secret](first-secret.md)
for the complete sequence. Authority is always included. An empty additional
recipient list selects Authority only. The seal binds the intended recipients;
adding a new recipient after sealing can require preparing the input again.

For a non-secret value, use:

```sh
printf '%s' 'info' | enkv set --json --source enkv.yaml \
  --name LOG_LEVEL --confidential=false
```

Plain values are visible in the editable declaration and authenticated state.
Use them for content such as log levels, not passwords. Quoting in this example
produces `info` without a newline.

`--base64` declares that the input stream is canonical padded Base64. ENKV
retains those exact encoded bytes. It does not detect Base64 automatically.
The entry's separate `output_encoding` controls bytes delivered to applications
or output services after apply. See [configuration files](configuration.md).

## Review another candidate

Keep a trusted pair separate from a proposed pair. Use the trusted file for
cloud location, credentials and trust, and explicitly select the candidate:

```sh
enkv plan --json --trusted /trusted/demo/enkv.yaml \
  --candidate /review/demo/enkv.yaml --check-secrets
```

A public plan without `--check-secrets` needs only object reads. It does not prove
secret equality. A successful plan does not reserve state or guarantee that a
later apply will be admitted.

`--show-secret API_TOKEN` also requires `--check-secrets` and deliberately sends
the proposed supplied-secret bytes to stdout. Use it only when that disclosure
is required and the output destination is protected. With `--json`, this is an
NDJSON stream containing secret-display records, followed by the final plan
result; ordinary plan JSON contains no secret values.

## Remove a value

Remove that entry's complete declaration from `entries` in `enkv.yaml`, leaving
all other desired entries present. Review with `plan`, then use `apply`.
Omitting an existing entry requests its removal; applying a partial example can
therefore remove unrelated entries.

Removing a generated value can leave work to retire its external resource.
Removing a value with published outputs can leave remote deletion work. Read
[plugins and outputs](plugins.md) and the returned work and warning fields before
calling the change complete. Removing an entry does not erase copies already
held by applications or external services.

## Read state and publish values

Use inspection to see authenticated current metadata without value bytes:

```sh
enkv inspect --json --source enkv.yaml
enkv receipt --json --source enkv.yaml
```

Receipts are a bounded retained record, not a complete audit history. A missing
receipt does not establish that a mutation never happened.

Publication sends selected current values to configured external destinations.
It requires Authority and each destination's credentials:

```sh
enkv plan --json --trusted enkv.yaml --publish
```

Review the plan before the send. Its exit `1` indicates verified differences;
stop on other nonzero outcomes. After approval, run:

```sh
enkv publish --json --source enkv.yaml --name API_TOKEN
```

`publish` uses current state, not pending edits. `apply --publish` first applies,
then evaluates publication if apply completes. Publication failure does not
roll back a completed apply. For generated values and publication with uncertain
outcomes, use the specific procedures in [plugins and outputs](plugins.md) and
[recovery](recovery.md); do not put effect commands in a blind retry loop.

Return to the [operator guide](README.md).
