# Manage recipient access

A recipient is an ENKV identity with a current cloud encryption key binding.
The name `app` in a configuration is a local reference to that identity. It is
not a cloud account or IAM role. Cloud permissions let a process use a key;
ENKV membership determines which entries that recipient may consume.

Authority is a mandatory recipient of every current entry. An ordinary
recipient can consume granted entries but cannot change state or publish them.
Recovery, when enabled at initialization, has a separate key replacement role.
See [concepts](concepts.md) for these responsibilities and the
[AWS](aws-permissions.md) or [GCP](gcp-permissions.md) permission guide for cloud
access.

## Prepare a new application recipient

First have the resource owner create an appropriate encryption key in the same
cloud provider as the domain. Use its exact immutable AWS key ARN or GCP key
version resource. Grant the application decryption permission on that key and
object-read access to the domain. The preparation operator and Authority also
need the public key and metadata permissions described in the cloud guide.

Set `APP_ENCRYPTION_KEY` to that real selector, then prepare the local binding:

```sh
enkv recipients add --json --source enkv.yaml --recipient app \
  --mode create --display-name 'Demo application' \
  --encryption-key "$APP_ENCRYPTION_KEY"
```

The result must confirm local delivery. This step reads authenticated state and
public key information and writes the configuration pair. It does not enroll
the recipient remotely or grant entry access. A display name or a reused cloud
key is not proof of an existing recipient identity.

If the declaration already exists locally, `--mode create` takes that
existing declaration without repeating `--display-name` or `--encryption-key`.
It still requires that the intended recipient is absent from current state.
To refresh public information for an exact already-current declaration, use:

```sh
enkv recipients add --json --source enkv.yaml --recipient app --mode current
```

`--mode` is required. Create mode requires an alias. For current mode, you can
instead use `--recipient-id ID` to select an existing local declaration by its
managed ID. The same alternative is available for rename, retirement and
recipient-key replacement. These commands require an explicit target.

Do not use create mode as an automatic retry of a stale preparation. Inspect
the result and current state first.

## Grant an entry to the recipient

Add the reference to the entry's additional recipient list in `enkv.yaml`:

```yaml
entries:
  API_TOKEN:
    confidentiality: secret
    recipients: [app]
    source:
      kind: supplied
```

This is an entry fragment, not a replacement configuration. Keep the remaining
root fields, entries and generated companion. An empty list means Authority
only; Authority must not be added as an ordinary extra reference.

A sealed proposal binds its intended recipient keys. After adding a recipient
to a supplied secret, prepare its input again when the previous seal does not
cover that binding:

```sh
enkv set --json --source enkv.yaml --name API_TOKEN < /protected/api-token
enkv plan --json --trusted enkv.yaml --check-secrets
```

Read the plan before proceeding. Exit `1` means complete verified differences;
exit `0` means a complete match. Stop on other nonzero results. For a shell with
`set -e`, use the explicit [plan exit handling](first-secret.md#4-review-and-apply).
After approving the change, run:

```sh
enkv apply --json --source enkv.yaml
```

Authority applies the recipient enrollment and its requested memberships
together. Check that the selected state contains the intended recipient and
entry. Inspection reports the exact RecipientID:

```sh
enkv inspect --json --source enkv.yaml
```

Use `--recipient app` to select the local alias. ENKV reads its managed ID from
the configuration pair, then checks that identity against authenticated current
state. To select an exact ID directly, use `--recipient-id ID` instead. The ID
must be nonzero and contain 64 lowercase hexadecimal characters. The flags
cannot be combined; an unknown alias does not select Authority or fall back to
ID parsing.

Verify application access under the application's cloud credentials:

```sh
enkv materialize --json --source enkv.yaml --recipient app \
  --name API_TOKEN --out /protected/application.env
```

Create the destination directory first. This writes plaintext to a private
application file. Follow [your first secret](first-secret.md) for consumption
and cleanup. A metadata inspection alone does not prove private decryption
permission.

## Remove access to one entry

Remove `app` from that entry's `recipients`, review with `plan`, and apply as
Authority. Preserve all other intended memberships. The recipient remains
enrolled and can retain access to other entries.

For an unchanged supplied secret, ENKV can accept a valid original seal for a
recipient subset only after its private equality checks succeed. If the seal is
unusable or the pending value changed, supply a fresh input with `set`.
Removing access cannot recall bytes the application already obtained. Change
the value too when the application must stop using the old secret.

## Rename or retire a recipient

To change only the local reference, use:

```sh
enkv recipients rename --json --source enkv.yaml \
  --recipient app --new-reference worker
```

This changes references in both files and preserves the RecipientID and current
access. Editing only the YAML map key breaks the join. To change the human
label, edit `display_name` and apply.

Omitting a recipient declaration does **not** retire it. To permanently retire
an ordinary recipient and remove all its current memberships, use the separate
operation described in [maintenance](maintenance.md). It creates a successor
configuration pair. Retained work can block retirement. A later re-enrollment
needs a fresh identity, even if it reuses the old display name or cloud key.

Use `keys replace` to change an existing recipient's encryption key. Editing its
selector and running ordinary apply does not replace the binding.

Return to the [operator guide](README.md).
