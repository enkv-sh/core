# Update ENKV and its plugins

The CLI and plugins have separate versions. Replacing the CLI does not update
every application plugin. Preparing a newer plugin does not replace the CLI.

## Before an update

Read the target release notes, supported platform requirements and compatibility
instructions. Record the installed CLI archive/version and the plugin selections
used by each application. Keep the approved configuration pair and existing
operational records in protected storage.

Check unresolved operations before changing the tools used to inspect them.
An uncertain result does not become safe to retry after an update. Keep the
exact original build and records needed for retained work. Use
[Recovery](recovery.md) or [Troubleshooting](troubleshooting.md) when necessary.

Do not assume that arbitrary binary replacement or downgrade is compatible with
stored domain data. Use the target release's supported upgrade procedure. If no
procedure covers your source version, stop and request guidance.

## Update the CLI

1. Download the new native **full** archive through the
   [installation route](install.md). Perform optional signature verification
   before extracting if that is part of your process.
2. Keep the original archive and records. Extract the new archive into a separate
   directory and retain its licenses and notices.
3. Stop active ENKV commands and coordinate the change with other operators.
   Install the new executable at the intended PATH location.
4. Run `command -v enkv` and `enkv --help`. These checks need no cloud access.
5. Follow the release's domain checks before ordinary work. A successful help
   command alone does not establish domain compatibility.

ENKV has no builtin `update` or `--version` command. Use the retained archive,
version records and checksums to identify a build. Do not overwrite your only
copy of an older build while work still depends on it. Returning to an older
binary after a newer one changed the domain is not a general rollback method.

## Update official plugins for an application

Run preparation from the directory containing the application's complete pair:

```sh
enkv prepare --upgrade --json
```

This requests newer compatible official stable builds for unpinned requirements.
Review the plugin's release notes and the returned readiness result before
using it. Preparation can run passive validation, but it does not generate a
secret, publish a value or prove that service credentials are valid.

An exact version in the editable `plugins` map is a pin. `--upgrade` does not
change it. To select another version, deliberately edit that pin to the desired
published version, then run ordinary preparation:

```sh
enkv prepare --json
```

An ordinary `prepare` reuses a valid existing selection and does not implicitly
ask for the newest release. Commands that need an official plugin do not fetch
a missing one automatically. See [Plugins](plugins.md) for exact selection and
local-author behavior.

## Keep support for retained work

An update affects new selection. Previously accepted generated work can still
require an exact older executor and its supported credential route. Preserve
those installed builds. Do not clear plugin directories as an update step.

Changing the selected generator build alone does not rotate a current secret
with unchanged canonical intent and epoch. Use the explicit
[generated-secret rotation procedure](generated-secrets.md). Output publication
and its uncertain results have separate rules; a plugin upgrade does not replay
an earlier send.

Next: [Daily operations](operations.md) or [Troubleshooting](troubleshooting.md).
