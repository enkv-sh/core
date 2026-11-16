# Recover files and resolve interrupted work

Start by identifying what is missing or uncertain. ENKV has several distinct
recovery paths; each one preserves a different kind of recorded work.

| Situation | Start here |
|---|---|
| A local edit reports a saved transaction | Complete that exact transaction with `recover`. |
| The editable file survives but its generated companion is missing | Use `prepare` with independent domain recovery inputs. |
| Both configuration files are lost | Reconstruct a new pair with `prepare`. |
| An apply or generator operation is incomplete or unknown | Read current selected work and exact receipts before choosing an action. |
| An Authority key is unavailable and domain Recovery was enabled | Use the supported key replacement path with surviving keys. |

Keep the original command result, operation IDs and surviving files. An absent
response does not prove that a change failed. Do not rerun initialization,
manually edit stored state or restore an old Store image to resolve uncertainty.

## Complete a saved local transaction

Local commands can save a candidate when file delivery is interrupted. If the
result contains `local_delivery.recovery_source`, use that exact source path
and its original format:

```sh
enkv recover --source /absolute/path/from-the-result.yaml \
  --source-format yaml --json
```

For a JSON source, use `--source-format json`. Do not substitute another file.
`recover` checks the saved old and new file states and completes that candidate.
It does not read a secret again, create a new proposal or repeat a cloud effect.
Foreign edits can cause refusal. Keep the transaction files for inspection.

Exit `0` confirms delivery and complete cleanup. Exit `2` can report refusal,
cleanup failure or result-output failure; exit `3` reports pending or uncertain
delivery. Readback can be confirmed while cleanup is incomplete. Inspect those
separate facts rather than using the exit status as a rollback decision.

## Restore a missing companion

For the `demo` domain, the companion is `.enkv/demo.generated.json` beside the
editable source directory. If `enkv.yaml` survives, keep its path and bytes.
Use its declared name, cloud and Store location together with an independently
known signing resource. For AWS:

```sh
enkv prepare --source enkv.yaml --name demo \
  --provider aws --bucket "$state_bucket" --region "$region" \
  --prefix enkv/demo --normal-signing-key "$authority_signing_key" --json
```

For GCP, select `--provider gcp` and use the exact signing CryptoKeyVersion
resource. An AWS key must be an exact KMS key ARN. Obtain the key and location
from trusted records, not from an untrusted replacement configuration.

Preparation confirms that the declared companion is absent, authenticates
current state and installs only that file. It preserves comments, pending
public edits and managed recipient IDs in the editable source. An existing,
unsafe or uncertain companion refuses. Pending local transactions require the
saved-transaction path above.

Committed supplied values can be recovered from authenticated state. Secret
input that was never applied is not stored in the domain. Read the complete
`missing_inputs` list; prepare each missing supplied value again with `set`,
then run ordinary `prepare`. Reconstruction does not apply pending edits.

## Reconstruct after complete local loss

Choose an absent destination in an existing directory and a new local name.
Supply the known cloud, bucket, region, exact prefix and independent current
signer. For example:

```sh
enkv prepare --source /absolute/restored/enkv.yaml --name demo \
  --provider aws --bucket "$state_bucket" --region "$region" \
  --prefix enkv/demo --normal-signing-key "$authority_signing_key" --json
```

The same command accepts GCP with its provider and exact key-version resource.
Both destination files and coordination state must be absent. A concurrent
creator is preserved. ENKV installs the satellite before the editable file;
they are not one atomic filesystem rename.

Keep independent records of the DomainID and expected key resources. You can
add `--expected-domain "$domain_id"`, AWS-only
`--expected-owner "$account_id"`, and
`--expected-authority-encryption-key "$authority_encryption_key"` as equality
checks. Without a domain pin, the command authenticates the domain at the
selected location and key; it does not prove continuity with an earlier known
domain or detect a coherent Store rollback.

This path verifies every current secret through the current normal Authority
encryption key. It creates no keys, IAM grants or remote state. Recovery-only
decryption access is not a substitute for that key. An independently selected
Recovery signer can be supplied with `--recovery-signing-key` when its proof is
adequate; that does not change the decryption requirement.

Keep any delivered pair even if plugin preparation later fails. Run ordinary
`enkv prepare --json` on that existing pair after correcting the dependency.
Recovered canonical plugin settings retain their exact meaning, while local
plugin selections are unset. Select trusted compatible plugins before the
operations that need them, and restore exact builds required by retained work.

## Resolve incomplete or unknown remote work

Use read commands with the same trusted pair and Store read access:

```sh
enkv inspect --json
enkv generated list --json
enkv receipt --operation "$operation_id" --json
```

A receipt reports an original stored result; it is not permission to repeat the
operation. Receipt retention is bounded, so an unavailable exact ID cannot
prove that the operation never happened.

For generated work, follow the listed exact continuation or retirement action.
For publication, inspect current blocking Attempt IDs and retained warnings.
A deliberate republish creates a new Attempt and keeps old late-write risk.
Neither a later success nor ending selected work proves remote cleanup.
See [generated secrets](generated-secrets.md) and [publication](outputs.md#read-publication-outcomes).

## Use configured domain Recovery

Domain Recovery is an optional key role chosen at initialization. It has a
separate signing key and encryption key. It can authorize supported key
replacement; it does not directly apply application values or grant general
service access. Enabling it in a local file after a failure cannot add that
protection to an existing domain.

If it was enabled and its necessary keys and permissions survive, follow
[key replacement](maintenance.md) to deliver a separate successor pair. Confirm
the selected result and local delivery before switching operators to that pair.
Do not delete old keys or support while accepted work still requires them.

[Operator guide](README.md) · [Troubleshooting](troubleshooting.md)
