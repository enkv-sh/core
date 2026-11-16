# Deliver values to applications

ENKV supports three delivery paths. Choose the path your application needs:

| Path | What it creates | Required access |
|---|---|---|
| `materialize` | A local dotenv file containing selected current values, including secrets | Store reads and the selected Recipient's decryption access |
| `manifest` | A local reference document with plain values and secret locations | Authorized public Store reads and a manifest plugin |
| `publish` | Values or deletions at configured external destinations | Authority access and the selected output service credentials |

These paths use authenticated current state. Editing `enkv.yaml` alone does not
change the values, routes or output encoding that they use. Apply the intended
configuration first. Start with [your first secret](first-secret.md) if the
domain and `app` recipient are not ready.

## Write a local application file

Use the application's credential context, the `app` alias from your
configuration, and an existing private output directory:

```sh
enkv materialize --name API_TOKEN --recipient app \
  --out /absolute/private/demo.env --json
```

Repeat `--name` to select more entries. The command requires at least one name.
Omitting both recipient flags selects current Authority, including for shared
entries. To use an exact ID instead of an alias, supply `--recipient-id ID`.
The flags cannot be combined. The selected recipient must be authorized for
every entry, and the credentials must permit decryption with its current key.
An unknown alias or failed recipient request does not fall back to Authority.

The command checks all selected values before replacing the destination. It
writes a private `0600` candidate, verifies it, replaces the destination in the
same directory and verifies the installed file. It creates no parent directory
and refuses symlinks, stdout `-` and paths that alias ENKV source files. A
failure before replacement preserves the old file; a later failure can leave
the new file installed. Read the delivery and cleanup facts before another run.

The file is for UTF-8 `motdotla/dotenv` 18.0.9 default `parse`. Do not assume it
is a shell script, Docker env file or input for another parser. Supported names
use letters, digits and `_`, with a letter or `_` first; `__proto__` is refused.
Some raw byte values cannot be represented. ENKV refuses the whole file rather
than silently changing its encoding. See [configuration](configuration.md) for
`output_encoding: base64` when your consumer expects Base64.

The installed file contains plaintext secrets. Give it to the intended consumer,
keep it out of version control and remove it when no longer needed. Removal
does not prove physical erasure or remove copies held by the application.

## Publish to an external service

The official outputs support AWS Secrets Manager, Google Cloud Secret Manager,
and GitHub Actions repository, organization and environment secrets. Output
services are independent of the cloud used by the ENKV domain.

For AWS Secrets Manager, merge this `outputs` section into your complete
configuration. Replace the account and region:

```yaml
outputs:
  destinations:
    primary:
      plugin: aws-secrets-manager
      settings:
        account: '123456789012'
        region: ap-southeast-2
  routing:
    default: []
    entries:
      API_TOKEN: [primary]
```

This routes only `API_TOKEN` to `primary`. Its entry name becomes the remote
secret name. Reserve that name for this ENKV workflow. Preparation and a
successful identity lookup do not establish the permissions needed to write it.

Read the chosen plugin's settings and permission guide before applying:

- [AWS Secrets Manager](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/aws-secrets-manager/README.md): account and region settings; standard AWS SDK credentials.
- [GCP Secret Manager](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/gcp-secret-manager/README.md): a decimal project **number**, not project ID; Application Default Credentials.
- [GitHub Actions](https://github.com/enkv-sh/extensions/blob/main/plugins/outputs/github-actions/README.md): scope-specific settings; `GITHUB_TOKEN`, with no `GH_TOKEN` fallback.

Then prepare, review and select the configuration before publishing:

```sh
enkv prepare --json
enkv plan --publish --json
```

Read the plan. Exit `1` means complete verified differences, and `0` means a
complete match. Stop on other nonzero results. For a shell with `set -e`, use
the [plan exit handling](first-secret.md#4-review-and-apply) with `--publish`
added. After approving the changes, apply them:

```sh
enkv apply --json
```

Only after apply reports completion, publish the selected value:

```sh
enkv publish --name API_TOKEN --json
```

Plain `apply` changes ENKV state without publishing. `apply --publish` is an
alternative that performs apply, then evaluates all applicable selected writes
and retained deletions after confirmed completion. Publication failure does not
roll back a completed apply.

A standalone publish needs explicit names. For an explicit output group,
select all its members. An omitted routing override inherits the default;
`API_TOKEN: []` explicitly suppresses that entry's publication. Routing does
not grant Recipient membership. Each entry has its own remote container, even
when entries share a destination or group.

## Read publication outcomes

Publication admits at most one application-level mutation request for each
Attempt. A lost reply can leave its effect unknown. Read the result and
`enkv inspect --json`; do not repeat the command as an automatic retry.

A separately reviewed new publication can use `--republish-after-unknown` with
every current blocking Attempt ID. It creates new Attempts and retains the old
warning and possible late-write risk. It neither retries nor closes the old
request. A newer acknowledgement cannot prove an older request will not arrive.

Removing an output binding can leave an exact deletion coordinate. Review it
with `plan --publish`, then use its ID and an explicit compatible output plugin:

```sh
enkv publish --delete-coordinate "$coordinate_id=aws-secrets-manager" --json
```

Acknowledgement describes that request's result. It does not prove permanent
erasure, current remote contents or exclusive ownership. In particular, do not
manually delete and recreate a managed GCP secret while retained operations
could still affect that name.

## Write a consumption manifest

A manifest tells a consumer where selected values belong. It carries plain
values and secret references; it does not contain secret value bytes or fetch
secrets for an application.

Add `generic-json: {}` under the top-level `plugins` map, run `enkv prepare`,
then write to an absent path in an existing directory:

```sh
enkv manifest --plugin generic-json --settings '{}' \
  --recipient app --name API_TOKEN \
  --out /absolute/private/demo.references.json --json
```

The same recipient flags apply to manifests. Omitting both selects current
Authority; this needs authorized public reads, not Authority signing or private
key access. Omitting names selects all entries granted to that recipient.

Use `opentofu-tfvars-json` for a reference-only `.tfvars.json` artifact. It does
not apply infrastructure. Follow the
[generic JSON](https://github.com/enkv-sh/extensions/blob/main/plugins/manifest-generators/generic-json/README.md)
or [OpenTofu renderer](https://github.com/enkv-sh/extensions/blob/main/plugins/manifest-generators/opentofu-tfvars-json/README.md)
guide for format and consumer details. Protect a manifest's integrity: its
recipient and IDs are not an independent signature for an untrusted file.

[Operator guide](README.md) · [Plugins](plugins.md) · [Recovery](recovery.md)
