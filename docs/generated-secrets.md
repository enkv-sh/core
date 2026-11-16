# Generate and rotate secrets

ENKV can ask a generator plugin to create a value, then store that value for its
recipients. The plugin can obtain random bytes locally or create a resource in
an external service. This guide assumes that you have initialized the `demo`
domain and added the `app` recipient. Start with [your first secret](first-secret.md)
if you have not done that.

Run these commands from the directory that contains `enkv.yaml`. Use the normal
Authority credentials for `apply`.

## Create a local random secret

Add `SESSION_SECRET` to the existing `entries` map in `enkv.yaml`. Preserve your
other entries and domain settings:

```yaml
  SESSION_SECRET:
    confidentiality: secret
    recipients: [app]
    source:
      kind: generated
      plugin: local-random-secret
      settings: {}
      epoch: 0
```

This example is a fragment under `entries`, not a complete configuration file.
The official `local-random-secret` generator returns 32 random bytes represented
as a 43-byte unpadded base64url string. Its only settings are `{}`. It needs no
service credential and creates no external resource to retire. The domain still
needs its normal Store and Authority access.

Prepare the plugin and review the requested change:

```sh
enkv prepare --json
enkv plan --json
```

Read the plan before applying. Exit `1` means complete verified differences;
exit `0` means a complete match. Other nonzero results require investigation.
For a shell with `set -e`, use the explicit
[plan exit handling](first-secret.md#4-review-and-apply).

Check that the plan includes creation of `SESSION_SECRET` and the intended
recipient membership. A plan cannot show a value that has not been generated.
Then apply the declaration:

```sh
enkv apply --json
enkv generated list --json
```

A successful apply selects the generated value. It does not print the secret or
publish it to another service. Consume it through
[materialization](outputs.md#write-a-local-application-file), using the `app`
recipient's credentials and `--recipient app`. Use `--recipient-id ID` if you
need to select an exact identity instead.

Repeating apply with unchanged settings and the same epoch reuses the current
value. A newer compatible plugin build alone does not request a new value.
See the [plugin reference](https://github.com/enkv-sh/extensions/blob/main/plugins/generators/local-random-secret/README.md)
for its complete contract.

## Rotate deliberately

Increase `SESSION_SECRET.source.epoch` from `0` to `1`, review with `enkv plan`,
then run `enkv apply`. Later rotations must advance the epoch again. Coordinate
application reloads and any consumers of the old value.

If you change a generator's canonical settings, advance the epoch for the new
generation. Changing intent at the same epoch is refused. Do not advance the
epoch just to work around a failed or unknown operation: that is a new request,
and the earlier work can still require action.

## Generate a Cloudflare account token

The `cloudflare-account-token` plugin creates a managed Cloudflare resource.
Its management credential is separate from the credentials used for the ENKV
domain. Supply `CLOUDFLARE_API_TOKEN` through your credential manager before an
effect command. Keep the bearer value out of `enkv.yaml` and command arguments.

For example, add this fragment under `entries`, replacing every example ID with
the account and permission-group ID that you intend to use:

```yaml
  CLOUDFLARE_TOKEN:
    confidentiality: secret
    recipients: [app]
    source:
      kind: generated
      plugin: cloudflare-account-token
      epoch: 0
      retirement: manual
      settings:
        account: '0123456789abcdef0123456789abcdef'
        name: demo-token
        policies:
          - effect: allow
            permission_groups: ['1234567890abcdef1234567890abcdef']
            resources:
              - kind: account
                id: '0123456789abcdef0123456789abcdef'
```

The IDs above are syntax examples. Obtain the correct permissions and resource
scope before applying. Follow the
[Cloudflare plugin guide](https://github.com/enkv-sh/extensions/blob/main/plugins/generators/cloudflare-account-token/README.md)
for credential requirements, policy grammar and service limits. Run `prepare`,
review `plan`, then apply only after those inputs are correct.

## Handle retirement and interrupted generation

A managed generator can leave a **retirement Duty**: recorded work to retire an
exact old resource. With `retirement: manual`, rotation selects the successor
and leaves that work for you. With `auto`, apply selects the successor before
attempting retirement. A retirement failure does not restore the old value.
The local random generator has no external retirement work.

Read the selected work before taking another action:

```sh
enkv generated list --json
```

Use the exact IDs and supported next actions from that result. For example:

```sh
enkv apply --operation "$operation_id" --json
enkv generated retire --duty "$duty_id" --json
```

The first command continues an admitted apply; the second requests retirement
of one Duty. They are alternatives for different recorded work, not a sequence
to run blindly. Continuation preserves the original accepted intent and target.
It does not use pending edits to replace that work.

Removing a managed generated entry, or changing it to supplied input, can need
an explicit plugin choice for a new retirement Duty:

```sh
enkv apply --retire-generator CLOUDFLARE_TOKEN=cloudflare-account-token --json
```

Review the removal in `plan` first. Keep the original exact plugin builds needed
by accepted work. A missing result or build is not permission to send again.

`generated accept-retirement-risk` records a decision to retain possible-live
resource risk; it does not delete the resource. `generated cleanup` performs
eligible recorded cleanup; it does not discover or adopt arbitrary resources.
Use [recovery](recovery.md) when an operation is interrupted or uncertain.

[Operator guide](README.md) · [Plugins](plugins.md) · [Outputs](outputs.md)
