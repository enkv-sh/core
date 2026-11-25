# Prepare and manage plugins

Plugins are separate native programs used for generation, remote output and
manifest rendering. A downloaded CLI archive contains no plugins. ENKV checks
plugin identity and compatibility before use; installation does not grant cloud
permissions or authorize a service operation.

Use this guide after you have a valid `enkv.yaml` and its generated companion.
See [configuration](configuration.md) for the file pair and
[generated secrets](generated-secrets.md) or [outputs](outputs.md) for tasks.

## Prepare required official plugins

From the application's directory, run:

```sh
enkv prepare --json
```

For an existing valid pair, preparation reads the declared requirements and
prepares their trusted installations. It can download missing official builds
and run passive settings validation. It does not apply values, create a domain,
create external resources or check your future service permissions.

Read both readiness fields. `minimum_administrative_ready` can be true while
`all_declared_ready` is false. That can allow administrative work while a
missing effect plugin still prevents the operation that needs it. A delivered
configuration pair remains useful when a later dependency check fails.

Generator and output declarations imply their own plugin requirement. A
manifest renderer needs an explicit top-level requirement because it is chosen
when you request a manifest. Merge this map into `enkv.yaml`:

```yaml
plugins:
  generic-json: {}
  opentofu-tfvars-json: {}
```

Keep any existing plugin entries. A name with `{}` selects the ordinary
compatible official policy; it is not an executable path or download URL.

## Keep or update an official selection

The first unpinned preparation selects a compatible official stable release.
Later preparation retains a valid exact selection. Ordinary dependent commands
verify and reuse that installation without contacting the release service.
They do not download missing official bytes.

To ask for newer compatible releases for unpinned requirements:

```sh
enkv prepare --upgrade --json
```

This is a deliberate plugin update. It does not replace the CLI or change an
entry's generated epoch. A failed update retains the previous valid selection
and reports the failure. An exact version pin is retained during upgrades:

```yaml
plugins:
  local-random-secret:
    version: '0.1.1'
  generic-json: {}
```

Use the exact published plugin version without a leading `v`. Ranges and
wildcards are refused. A version pin selects a release; it does not make an
untrusted local executable safe. CLI and plugin versions are independent.

If selected official bytes are missing, run preparation to reacquire that exact
artifact. If an integrity check or signature fails, preserve the report and
inspect the cause. Do not disable verification, substitute a file or delete
records to make the command accept it.

## Trust a private or modified build

Use this route only when you intend to trust the plugin's native code. A plugin
is not an operating-system sandbox. A project file cannot grant this trust.
The plugin author supplies a complete build made by the public artifact tools;
ordinary operators do not need to compile official plugins.

User trust settings are held in `enkv/plugins.json` below the operating system's
user configuration directory:

| Platform | Usual settings path |
|---|---|
| macOS | `$HOME/Library/Application Support/enkv/plugins.json` |
| Linux | `$XDG_CONFIG_HOME/enkv/plugins.json`, or `$HOME/.config/enkv/plugins.json` when `XDG_CONFIG_HOME` is unset |

For a new settings file, use this structure with your real existing absolute
paths. The application directory is the canonical directory containing the
editable configuration; it is not the domain name or source filename:

```json
{
  "schema": "enkv/plugin-settings/v1",
  "applications": [
    {
      "directory": "/absolute/demo",
      "plugins": [
        {
          "name": "private-local-token",
          "directory": "/absolute/builds/local-token"
        }
      ]
    }
  ]
}
```

Preserve other applications and plugins when editing an existing file. Resolve
symlinks in the application path before recording it. Then declare that plugin
by name in the project's generated source, output destination or `plugins` map.
A trusted local override takes precedence over an official pin for the same
plugin name in that application only.

The next command that needs the plugin verifies and captures its immutable
build bytes into installation storage. It does not execute from the mutable
build folder. A later complete rebuild is captured by the next dependent
command; a running invocation keeps its already captured bytes. Invalid local
settings or an incomplete rebuild stop dependent work without switching to an
official fallback.

Follow the full [local trust procedure](https://github.com/enkv-sh/extensions/blob/main/distribution/local-installation.md#trust-a-local-author-build)
for author build verification and settings limits.

## Preserve support for retained work

Accepted generated work records its exact original executor and credential
route. Changing your current plugin selection does not replace that support.
Keep the original builds needed by unfinished operations and retirement Duties.
After machine loss, restore the exact official artifact and proof or the
original local artifact bytes. Missing support grants no replacement send.

A new retirement Duty can use an explicitly selected implementation only after
compatibility checks for the original resource. See
[generated-secret retirement](generated-secrets.md#handle-retirement-and-interrupted-generation).
Output publication markers preserve history and uncertainty without retaining
an old output executable or granting permission to replay its payload.

Credentials belong in the service's normal credential context, not in public
plugin settings. Examples include AWS profiles, GCP Application Default
Credentials, `CLOUDFLARE_API_TOKEN` and `GITHUB_TOKEN`. Installing a plugin grants
none of those capabilities.

[Operator guide](README.md) · [Updates](updates.md) · [Troubleshooting](troubleshooting.md)
