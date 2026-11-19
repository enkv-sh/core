# ENKV operator guide

ENKV stores application values in a domain backed by your AWS or Google Cloud
resources. It encrypts secrets for ENKV recipients. The CLI can write a file
for a local worker or publish values to a configured service. Your deployment
controls access to the file. For AWS and GCP outputs, cloud IAM controls access
to the published secret. There is no ENKV server or ENKV account to create.

These guides cover the full CLI on macOS with Apple silicon and Linux x86_64.
They assume basic terminal use. You do not need the source code, Go or Git to
use a released binary.

## Start with one secret

Follow this route in order. Authority grants the Recipient access to `API_TOKEN`
in the `demo` domain. The Recipient runs ENKV to write a file. A local worker reads it.

1. Read [How ENKV works](concepts.md). Learn which files and keys you must keep.
2. [Install ENKV](install.md). Check the platform requirements and release notes.
3. Choose **one** cloud guide: [AWS](quickstart-aws.md) or [GCP](quickstart-gcp.md).
   The cloud resource owner creates storage, keys and permissions. Authority
   then initializes an empty domain. One domain uses one provider.
4. Follow [Your first secret](first-secret.md) to store a value and read the file
   with a local worker.
5. Use [Daily operations](operations.md) for later changes.

Cloud resources can incur charges. An ordinary cloud login does not grant all
the permissions in these guides. If another team owns your resources, give
them the relevant [AWS](aws-permissions.md) or [GCP](gcp-permissions.md)
permissions guide before you start.

## Find a task

| I need to… | Read |
|---|---|
| Understand or move the configuration files | [Configuration](configuration.md) |
| Change, add or remove a supplied value | [Daily operations](operations.md) |
| Grant or remove a recipient's access to an ENKV entry | [Access and recipients](access.md) |
| Create or rotate a generated secret | [Generated secrets](generated-secrets.md) |
| Prepare or select a plugin | [Plugins](plugins.md) |
| Deliver values to a file or an external service | [Outputs and manifests](outputs.md) |
| Replace keys, retire a recipient or reclaim storage | [Maintenance](maintenance.md) |
| Recover local files or use configured Recovery | [Recovery](recovery.md) |
| Understand a failure or an uncertain result | [Troubleshooting](troubleshooting.md) |
| Update the CLI or plugins | [Updates](updates.md) |
| Check a command name or its purpose | [Command reference](commands.md) |
| Report a suspected security problem | [Security reporting](../SECURITY.md) |

## How to use the examples

Commands run from the directory that contains `enkv.yaml`, unless a guide says
otherwise. Replace each placeholder with your own resource identifier. A shell
variable such as `$RECIPIENT_ENCRYPTION_KEY` must contain the exact value established
by the cloud guide; it is not an ENKV configuration variable.

Stop a sequence when a command fails. `plan` has one special result: exit `1`
means a complete comparison found differences, not a failure. Read those
differences before applying. Other nonzero results need attention before the
next action. Some failures can occur after a file was written or a remote request
was sent. [Troubleshooting](troubleshooting.md) explains the next steps.

Keep the editable configuration and its `.enkv/` companion together. Use a
protected directory for plaintext inputs and materialized output. Do not put
plaintext secrets, cloud credentials or private keys in a public issue.

For deeper implementation details, use the
[full CLI reference](../compositions/full/README.md). Plugin authors should use
the [extensions SDK guide](https://github.com/enkv-sh/extensions/blob/main/sdk/README.md).
