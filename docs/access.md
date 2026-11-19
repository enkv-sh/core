# Manage recipient access

A recipient is an ENKV identity with a current cloud encryption key binding.
The alias `recipient` refers to that identity in the walkthrough configuration.
The person running ENKV signs in with their cloud credentials. Cloud permissions
let the process use a key. ENKV membership determines which entries the selected
recipient may consume.

Authority is a mandatory recipient of every current entry. An ordinary
recipient can consume granted entries but cannot change state or publish them.
Recovery, when enabled at initialization, has a separate key replacement role.
See [concepts](concepts.md) for these responsibilities and the
[AWS](aws-permissions.md) or [GCP](gcp-permissions.md) permission guide for cloud
access.

## Prepare the Recipient binding

First have the resource owner create an appropriate encryption key in the same
cloud provider as the domain. Use its exact immutable AWS key ARN or GCP key
version resource. The resource owner grants the Recipient's cloud identity
decryption on that key and object-read access to the domain. Authority needs
public-key and metadata reads on the Recipient key for preparation.

Authority sets `RECIPIENT_ENCRYPTION_KEY` to that key ARN or version name and
prepares the local alias `recipient`.

```sh
enkv recipients add --json --source enkv.yaml --recipient recipient \
  --mode create --display-name 'Demo Recipient' \
  --encryption-key "$RECIPIENT_ENCRYPTION_KEY"
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
enkv recipients add --json --source enkv.yaml --recipient recipient --mode current
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
    recipients: [recipient]
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

Use `--recipient recipient` to select the local alias. ENKV reads its managed ID from
the configuration pair, then checks that identity against authenticated current
state. To select an exact ID directly, use `--recipient-id ID` instead. The ID
must be nonzero and contain 64 lowercase hexadecimal characters. The flags
cannot be combined; an unknown alias does not select Authority or fall back to
ID parsing.

Give the Recipient the approved pair as in [the first-secret guide](first-secret.md#5-materialize-as-the-recipient).
In their own directory and cloud login, the Recipient runs the following commands.

```sh
umask 077
mkdir -p .private
enkv materialize --json --source enkv.yaml --recipient recipient \
  --name API_TOKEN --out .private/worker.env
```

Success verifies that the Recipient could materialize this entry. The
[local worker](first-secret.md#6-read-the-file-with-a-local-worker) can then
read the file. For the following changes, return to Authority's workspace and login.

## Remove access to one entry

Remove `recipient` from that entry's `recipients`, review with `plan`, and apply as
Authority. Preserve all other intended memberships. The recipient remains
enrolled and can retain access to other entries.

For an unchanged supplied secret, ENKV can accept a valid original seal for a
recipient subset only after its private equality checks succeed. If the seal is
unusable or the pending value changed, supply a fresh input with `set`.
Removing membership prevents future materialization of the current entry as
that recipient. Existing files and copies remain readable. If a deployed worker
reads a published secret, the operator manages its access separately in the
destination service. To invalidate a copied credential, revoke or rotate it at
the service that issued it.

## Rename or retire a recipient

For example, to change only the local reference, use the following command.
The other guides continue to use the original alias `recipient`.

```sh
enkv recipients rename --json --source enkv.yaml \
  --recipient recipient --new-reference reviewer
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
