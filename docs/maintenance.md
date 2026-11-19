# Maintain keys, protection and stored work

Maintenance changes authenticated domain state. Run it with the required
Authority or enabled Recovery capabilities, after checking
[recovery and uncertain outcomes](recovery.md). Do not remove cloud keys, local
plugin builds or Store objects merely because a newer configuration exists.
Current values and accepted work can still require them.

## Keep a separate successor configuration

`rekey`, `recipients retire` and `keys replace` require `--out`. They deliver a
new editable/generated pair before attempting the state change. Create a
separate protected application directory for that output:

```sh
mkdir -m 700 ../demo-next
```

The successor keeps the logical name `demo`, so its companion is
`../demo-next/.enkv/demo.generated.json`. A second editable filename in the
original directory would share the original companion and is refused. There
is no overwrite option. Use a fresh directory for each new operation.

Read three separate facts in the result: whether the successor files were
delivered, whether the state change selected, and whether the successor is
usable against the observed current state. Delivered files alone do not prove
successful selection.

After a confirmed successful change and usable successor, use its editable
file as `--source` for later commands. Preserve the pair together. Pending
unrelated edits are preserved; maintenance does not apply them.

If the response is uncertain, keep the output and repeat the **exact original
command with the original source, target and output paths** to observe that
operation. A recognized existing output selects a read-only observation; it
cannot repeat the state mutation. Do not choose a fresh output path as a retry.
Missing evidence is not proof that the earlier change failed.

## Refresh a secret's encryption protection

Rekeying keeps the selected plaintext and recipients while replacing its
protected material. It does not generate a new application secret. For a
generated entry it preserves the external resource and does not call the
generator.

```sh
enkv rekey --json --source enkv.yaml --name API_TOKEN \
  --out ../demo-next/enkv.yaml
```

This is an Authority operation. A stale proposal, stale retained input or
required unavailable evidence can prevent it. Follow the result before
adopting the successor. To change the actual value, use `set` and `apply`
instead; see [daily operations](operations.md).

## Retire an ordinary recipient

Use retirement when the identity itself must leave the domain, rather than
removing its access to just one entry:

```sh
enkv recipients retire --json --source enkv.yaml --recipient recipient \
  --out ../demo-next/enkv.yaml
```

Retirement removes that exact current recipient and all its current memberships
in one state change, with fresh protection for affected secrets. Authority
cannot be retired this way. A recipient still needed by retained work can be
blocked; inspect `recipient_retirement_blockers`. Resolve the named work through
its own procedure. Do not delete its supporting records to bypass the blocker.

Retirement does not erase copies already read. Re-enrollment uses
`recipients add --mode create` and a fresh identity. See [access](access.md).

## Replace a cloud key binding

The resource owner first creates the successor cloud key and permissions. Use
an exact AWS key ARN or GCP key version resource. ENKV does not create the key
or IAM policy, and accepts no replacement PEM or fingerprint argument.

To replace an ordinary recipient key, Authority uses:

```sh
enkv keys replace --json --source enkv.yaml --target recipient \
  --recipient recipient --encryption "$successor_encryption_key" \
  --out ../demo-next/enkv.yaml
```

For recipient retirement and key replacement, `--recipient recipient` selects the
local alias. Use `--recipient-id ID` instead to select an existing local
recipient by exact ID. These operations require an explicit target; the two
flags cannot be combined.

Recipient-key replacement preserves the RecipientID and memberships. It requires Authority's
material route, not the old or new recipient's private decryption permission.

To replace the Authority signer using the current Authority signer:

```sh
enkv keys replace --json --source enkv.yaml --target authority \
  --authorizer authority --signing "$successor_signing_key" \
  --out ../demo-next/enkv.yaml
```

For Authority or enabled Recovery, select `--signing`, `--encryption`, or both.
Set `--authorizer authority|recovery` explicitly. If encryption changes,
`--decrypt-with authority|recovery` selects the surviving current decryption
route; omission uses the named authorizer. That flag is invalid for a
signing-only change. A failed route does not trigger fallback.

When Recovery is enabled and its signer survives, replace an unavailable
Authority signer with `--target authority --authorizer recovery --signing ...`.
Recovery cannot be added to a domain initialized without it. Replacing Recovery
uses `--target recovery` and the same explicit authorizer and key rules.

Sealed pending proposals are preserved byte-for-byte. A proposal bound to a
replaced key can need a new `set` before future apply. Do not disable or destroy
old keys until you have assessed all required current and retained access.

## Inspect capacity and plan garbage collection

Start with a bounded authenticated capacity view:

```sh
enkv inspect --json --source enkv.yaml --capacity
```

Capacity inspection needs object reads and a bounded list operation, but no
signer or effect plugin. Follow its opaque cursor for another page when one is
returned. The view reports specific limits and obligations; it is not a general
promise that a new operation will fit.

GC removes only objects admitted as disposable by its exact plan. It does not
retire generated service resources. Create a protected directory, then review
a plan before applying it:

```sh
mkdir -m 700 ../demo-maintenance
enkv gc plan --json --source enkv.yaml --out ../demo-maintenance/gc-plan.bin
enkv gc apply --json --source enkv.yaml --plan ../demo-maintenance/gc-plan.bin
```

Keep the plan file private and unchanged. Planning uses public reads and writes
only the local protected artifact. Apply requires Authority signing and Store
mutation permissions. A stale plan is not rebased automatically. If the result
requires continuation of a selected GC operation, use its exact ID:

```sh
enkv gc apply --json --source enkv.yaml --operation "$operation_id"
```

Do not remove Store objects through cloud commands to imitate GC.

## End selected work only after reviewing its risk

`abandon` releases local work rights and exclusive capacity. It does not cancel
a process, delete an external resource or prove that an old request had no
effect. Use it only after reviewing the complete disposition:

```sh
enkv abandon list --json --source enkv.yaml
enkv abandon plan --json --source enkv.yaml --target "$group_id" \
  --out ../demo-maintenance/abandon-plan.json
enkv abandon apply --json --source enkv.yaml \
  --plan ../demo-maintenance/abandon-plan.json
```

Use an exact legal GroupID from the list. Read the plan's scope, preserved
state and warnings before apply. Changed state requires a new reviewed plan.
Permanent warnings and possible external effects can remain after work ends.
See the [detailed maintenance reference](../compositions/full/README.md#abandon-selected-work)
for receipt lookup and exact observation limits.

Return to the [operator guide](README.md).
