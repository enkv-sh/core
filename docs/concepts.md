# How ENKV works

ENKV manages named values such as `API_TOKEN` or `DATABASE_URL`. A value can be
plain or secret. A secret is encrypted before it enters the domain's storage.
ENKV can accept a value you supply or ask a trusted generator plugin to create
one. You decide who can read it and how to deliver it to an application.

## The parts you operate

| Part | What it means |
|---|---|
| Domain | One independent set of values, recipients and current configuration. It has a stable DomainID. |
| Store | The S3 or Cloud Storage bucket and prefix that hold the domain's state. |
| Authority | The role that can apply normal changes. It uses a signing key and a separate encryption key. Authority is also a recipient of every value. |
| Recipient | A stable identity inside the domain that can read the values granted to it.  |
| Recovery | An optional role with its own signing and encryption keys, selected at initialization. It can perform specified key replacements. |
| Configuration pair | Your editable YAML or JSON file and the generated JSON companion that ENKV manages. |
| Plugin | A separate trusted executable used for generation, publication or manifest formatting. |

One domain uses AWS for its Store and keys, or GCP for both. A domain's storage
provider does not restrict all output services: an AWS domain can, for example,
use a supported output plugin for another service.

ENKV does not create cloud accounts, buckets, keys, identities or IAM grants.
The resource owner prepares them. ENKV uses the AWS SDK credential chain or GCP
Application Default Credentials to access the permitted resources.

## Keys, identities and permissions are different

The cloud principal is the user, role or service account whose credentials are
available to the process. Its IAM permissions determine which cloud operations
it can perform.

The **RecipientID** is a 64-character identifier inside ENKV. It is not an AWS
profile, GCP service account, key identifier, local reference or display name.
For example, `app` can be the local alias for an application recipient. Use
`--recipient app` to select that alias, or `--recipient-id ID` for its exact
nonzero 64-character lowercase hexadecimal ID. Use only one flag. ENKV does not
infer the recipient from your AWS profile or GCP login.

`materialize` and `manifest` select current Authority when both recipient flags
are omitted, including for shared values. The credentials still need the access
required by the operation. Plain `inspect` shows the domain overview.

Reading a secret requires both ENKV membership and access to the recipient's
current encryption key. Store access alone does not decrypt it. Access to a
recipient key does not grant Authority signing or permission to change state.
Cloud administrators who can change these permissions are part of your trust
boundary.

An operator can also act as a **Proposer**: prepare local changes for Authority
to apply. The **Reader** role supports public comparison and consumption
manifests. Neither role is an extra account that ENKV creates.

## Local intent and current state

The editable file describes what you want. The authenticated Store state
describes what is current. They can differ.

```text
edit configuration / set a value
             |
             v
       plan the change
             |
             v
     Authority runs apply
             |
             v
       current Store state
          /           \
         v             v
 recipient file    Authority publication
 materialize       to external services
```

`set` prepares a supplied secret locally. `apply` submits the complete desired
entry set. Removing an entry from that declaration asks ENKV to remove it from
current state. A small file with only your changed entry is not a partial
update file.

`materialize` reads current values and writes an application file. `publish`
sends selected values through configured output plugins. Ordinary `apply` does
not publish; `apply --publish` explicitly requests the additional operation.

## What to preserve

Keep `enkv.yaml` with `.enkv/demo.generated.json` for a domain named `demo`.
The generated file contains public bindings and protected input records. It is
not a disposable build cache. Preserve initialization records and pending local
transaction files too. See [Configuration](configuration.md).

Record the exact bucket, prefix, provider, signing key resources and DomainID
in a protected operational record independent of the local pair. These are
needed to authenticate reconstruction after local file loss.

Enabled Recovery has secret-decryption capability; protect that route
separately. Disabled Recovery means loss of the normal keys can cause permanent
loss. Recovery does not replace Store backups or undo a remote service effect.
Read [Recovery](recovery.md) before choosing the mode.

ENKV reports uncertain outcomes when it cannot establish what happened. An
uncertain result is not permission to repeat a mutation. Retain the result and
follow the relevant [troubleshooting route](troubleshooting.md).

Next: [Install ENKV](install.md).
