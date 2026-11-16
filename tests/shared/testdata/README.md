# Public wire fixtures

The current contract tests read these schema-11 fixtures:

| File | Consumer and scope | SHA-256 |
|---|---|---|
| `value-access-wire-schema11.json` | `TestValueAccessIndependentWireVectors`: value, payload, wrap and access bytes; accepted and refused encodings | `04ef51f2e515a25202a3c800bac0de0245fedabf327cf1355d9a7ceded456c05` |
| `lifecycle-projections-schema11.json` | `TestLifecycleIndependentProjectionVectors`: comparison, membership, grant, exclusion and prepared-secret projections | `c253220bebee4282acf3f6fbbb88b0f602e949155693bf61e862752613153caf` |
| `stored-closure-v11.json` | `TestIndependentStoredGenesisAndFirstSecretClosures`: empty genesis and first-secret closures with Recovery disabled and enabled | `d619ec197d4924c5c1adb2dc98147b3ca9acf741d02a00ea8ba1ece9dcc0b4fc` |

The stored-closure hash above is checked against the exact file bytes. Canonical
records use schema 11; compact mutation receipts retain schema 3 and receipt
indexes use schema 2. Output configuration uses schema 5 and routing schema 3.
The value and payload fields include input encoding and retained length; stored
entries also include output encoding. The current stored fixture keeps the
output-configuration support row, common receipt order, administrative index
and empty GC relation. Tests declare the complete expected fields independently
of decoder output.

These fixtures establish structural wire behavior: exact fields and bytes,
commitments, truncation, trailing-byte refusal and buffer ownership. Synthetic
ciphertext and public keys do not establish valid signatures, successful private
decryption or an authenticated domain. Empty generated closures do not establish
preservation of live or retiring work. A released preservation baseline also
needs synthetic state and retained-work evidence, exact source/build identities
and required executable support.

Schema-11 derivation used independently framed preimages and recalculated their
dependent commitments. This does not establish a new independent origin for
every inherited leaf. The provenance limits below remain applicable. Keep all
historical fixtures unchanged; current tests do not use them as positive decoder
alternatives. Historical sections describe the versions named in their headings,
not the current format.

## Authenticated synthetic states

[`preservation/provenance.json`](preservation/provenance.json) identifies six
fixed, self-contained source states and their exact hashes. They cover supplied
secret/plain state in both Recovery modes, current and retiring generated work,
active residue and final Hazards, and discarded-publication warnings.

`TestPreservedSyntheticStatesColdReplay` reads these fixed bytes in a fresh
process. It checks the captured image and separate case-authored semantic
expectations, common receipt order and synthetic private consumption.
`TestPreservedSyntheticStatesRefuseDamagedClosure` checks damaged HEAD/root
refusal without writes. The observed image is not an independent semantic
oracle. All private consumption uses fixed repository test keys and test values.

Keep these source bytes immutable. Do not regenerate them with a later producer
to make a replay pass. Their provenance separates known capture inputs from
later replay-source observations and states the missing complete capture-time
tree. They establish small synthetic replay, not migration, platform/cloud
qualification or the identity of a released official plugin. Released source,
build and required plugin-support identities have separate release ownership.

## Historical schema 10 derivation

The current fixture files supply fixed public bytes and expected fields for
ordinary contract and format tests. Canonical records use schema 10; compact
mutation receipts retain schema 3 and receipt indexes use schema 2.

| File | Covered records |
|---|---|
| `value-access-wire.json` | Value, wrap and access records; accepted and refused encodings |
| `lifecycle-projections.json` | Comparison, membership, grant, exclusion and prepared-secret projections |
| `stored-closure-v10.json` | Empty genesis and first-secret closures in both recovery modes |

The current stored closure has the mandatory output-configuration descriptor,
its selected kind-17 row, initialization receipt and common-order indexes,
index fragment, two genesis support pages, and the administrative index.
Its GeneratedClosure commits ReceiptOrder between FailureWindow and Slices.
The root appends zero ActiveGC and the exact 44-byte empty GCPlans descriptor;
these fields add 76 bytes in both recovery modes.
The canonical empty order descriptor is present even when no index fragment
is needed. Administrative nested index revision 3 remains unchanged. Output
configuration images, descriptors and slices use schema 5 and the v5
configuration and slice commitment domains. Current codecs refuse older stored
schemas and two-window indexes.

Independent Python big-endian framing and SHA-256 calculations derive the
current stored literals from verified schema-8 public inputs. They change only
named canonical schema fields in fixed leaves, then recalculate enclosing
references, access commitments, initialization receipt results, common order,
fragment, root and HEAD, then append the independently framed empty GC
relation. The preceding schema-9 stored closure is reproduced byte for byte
before the new derivation. No production encoder supplies expected bytes.
The empty output image is `000500000000000000050003000000`. Its
configuration commitment hashes `ENKV/OUTPUT/CONFIGURATION/v5`, NUL,
DomainID, its u32 byte length and those bytes. Its slice identity hashes
`ENKV/OUTPUT/CONFIGURATION-SLICE/v5`, NUL, DomainID, that commitment and
u16 slice index zero. Dependent support, administrative, root, initialization
receipt, HEAD and transition identity literals use the resulting exact bytes.
The current routing derivation first reproduced all preceding schema-10
literals, including all six initial-reservation digests. It then replaced only
the 16-byte empty image with the 15-byte schema-5/routing-3 image above and
recalculated its configuration digest, slice identity, 93-byte slice, 205-byte
support page and 46-byte descriptor. The slice body is `u16(5) || DomainID ||
ConfigurationDigest || u16(0) || u16(1) || u32(15) || blob(image)`.
References retain canonical schema 10. Administrative row summaries bind the
new slice identity and 93-byte body length. Each owning root's child-byte
account decreases by one. Genesis normalized identity includes `blob(image)`;
its request digest changes the complete result, receipt and selected support
page before the administrative, root, HEAD, condition and plan hashes are
recalculated. Unaffected public keys, value/access leaves, receipt indexes,
fragments, empty descriptors and compatibility identifiers retain exact bytes.
The initial-reservation calculation uses the explicit prior field recipe with
the new output leaf: its plan remains 2,898 bytes, vector 2,906 bytes; initial
access and material hashes remain unchanged, while its plan, request, filled
root and HEAD hashes change. Ordinary Python `struct` and `hashlib` supply
framing and hashes; no production codec supplies expected values. The local
one-shot records are `tests/work-evidences/090/routing-stored-derivation.py`,
`routing-initial-derivation.py` and their retained preceding literal input.
They record this specific change and are not maintained fixture generators.

The historical one-shot derivations were named `derive-stored-closure.py`
for closure traversal, `derive-canonical-leaves.py` for fixed leaf hashes, and
`derive-public-fixtures.py` for the 22 leaf schema fields and five prepared-access
schema fields. Those scripts are not available at their originally cited local
paths. The fixed inputs, expected literals and the field recipes below remain
maintained; see the provenance limits below.
Five prepared-secret AccessRecord spans and their expected base64 values use
schema 10. Their other bytes and the other lifecycle cases stay unchanged.

Synthetic encrypted bytes and public keys establish wire behavior. They do not
establish signatures, private decryption, provider qualification or an admitted
domain. Ordinary tests check exact decoded fields and bytes, truncation,
trailing data, prior-schema refusal and buffer ownership.

`stored-closure-v5.json`, `stored-closure-v6.json`, `stored-closure-v8.json`
and `stored-closure-v9.json` remain historical derivation inputs. No current executable consumer uses them
as positive fixtures or decoder alternatives.

| Schema-10 fixture | SHA-256 |
|---|---|
| `value-access-wire.json` | `b2bcbd71fd0a2263283fe84b451589491b3c11b946cb4907ffc33c731a811bf0` |
| `lifecycle-projections.json` | `98ddf323e3cdb88deb7ac5e45d6e3889f0f388a970fa5744c6b97db18601277d` |
| `stored-closure-v10.json` | `af334e35c363be0f80946e49dd6d1816cb792f432bd56a5f34533caa1b96cc97` |

## Derivation provenance and limits

Fixed literals and their declared inputs remain the expected results. The
one-shot derivations used ordinary unsigned big-endian framing, byte
concatenation, standard-library SHA-256 and, where stated, manual public-key DER.
They are not maintained fixture generators. Their original cited local script
paths are unavailable; a script name or checksum does not replace a field recipe.

A retained independent framing check matched 19 current outer records using
explicit child bytes and CurrentAccessCore bytes as inputs. It did not derive
the independent origin of every inherited leaf. The earlier schema-6 derivation
below likewise distinguishes encoded leaves from independently checked framing.
Full inherited-leaf provenance remains incomplete; no enclosing hash comparison
changes that limit.

The test comments retain the following recipes and provenance facts:

| Expected-field owner | Retained derivation scope |
|---|---|
| Supplied apply and cleanup no-work identities | Explicit test inputs, independent big-endian/SHA-256 framing and fixed lengths. Supplied apply uses a 201-byte basis, 357-byte request and 403-byte observation; cleanup uses a 110-byte basis, 350-byte request and 403-byte observation. |
| Recipient creation | SHA-256 of `ENKV/recipient-creation/v1`, NUL, domain, selected snapshot and nonce, in that order. Test inputs are 32 repeated bytes of 1, 2 and 3. Initial binding/incarnation use their distinct purpose labels followed by domain and the created recipient ID. |
| Signing-purpose interpretation | SHA-256 of the v9 domain, exact normal/recovery numeric purpose lists and fixed support metadata. The calculation reproduced the prior hash before adding normal purpose 17; the recovery list stayed unchanged. |
| Supplied transition, succession and initial reservation | Explicit typed test fields, fixed component bytes, local frame equations and lengths, schema changes, receipt order and empty output image commitments. Inherited fixture leaves remain inputs rather than a new independent derivation. |
| Recipient replacement | Independent outer frames use kind 9 after the lifecycle prefix, replacement intent length 1500, zero changed values and before-access ID 88. The recorded stdlib source SHA-256 is `c6361746d4de1dbb654c87213a2ff0c3fcd247306f1cb64fb393330929881c8a`; that source is unavailable at its old local path. |
| Administrative descriptor, preview and query | The recorded stdlib source SHA-256 is `cf588214b7fcac3e8d2cc8b4ae09df69f7163696c69e10f80de96f91925c74aa`. It used no Go codec and recorded a 149-byte descriptor, prior 623-byte preview and closed query frames. The current tests retain exact inputs and literals; the absent source cannot establish a new complete field derivation. |
| GC no-work result | Exact public fixture inputs and fixed hashes; lengths are 553-byte plan, 21-byte empty targets descriptor, 403-byte observation and 661-byte empty sibling result. The original one-shot source is unavailable at its old local path. |

This record preserves the available recipes while exposing missing source and
leaf provenance. It does not claim that every expected field has a complete
independent derivation. Keep the original literals and assertions; recover or
independently derive any specifically required missing field before enlarging
that claim.

The current focused record checks also retain these independent field equations:

| Expected field | Derivation |
|---|---|
| Common generator SafeFacts fixed bytes | Schema `u16` (2), four `u8` fields (4), three IDs (96), three `blob32` prefixes (12), and presence (1): 115 bytes. |
| Scoped generator SafeFacts fixed bytes | The common 115 bytes plus six IDs (192): 307 bytes. The 4096-byte envelope leaves 3981 ordinary or 3789 scoped bytes for target, resource and provider fields together. |
| Generator capacity record | Own prefix 114 = schema (2), two IDs (64), descriptor (44), group count (4); 17 groups each contain tag (1), count (8), bytes (8), pages (4). Total: `114 + 17 * 21 = 471`; descriptor framing adds 8, giving 479. Normal and reservation labels, schemas and prefix owners remain separate. |
| Access projection bases | Coverage label 34 + IDs 96 + plan descriptor 44 + count 4 = 178. Output label 37 + IDs 96 + plan descriptor 44 + count 4 = 181. Unchanged label 44 + IDs 96 + count 4 = 144. |
| Nonempty access projections | One row adds 168 coverage bytes, `70 + access-record bytes` output bytes, and 162 unchanged bytes. A two-wrap record has `102 + 2 * 489 = 1080` bytes. The complete lengths are therefore 346, 1331 and 306. |
| Raw value-entry page | ENKV magic (4), kind (1), schema (2), two IDs (64), index (2), mask (2): 75 header bytes. Individually valid record leaves are explicit inputs; raw duplicate fields test decoder rejection without using the page encoder. |

These equations establish the named lengths and framing. They do not establish
new independent provenance for inherited record leaves or recover the absent
historical derivation receipts.

## Historical schema 8 derivation

The following records describe the prior schema-8 fixture and its derivation.

The genesis receipt literals derive from the prior revision-3 fixture with hash
`ef0a6d270fdd5a30d3eab54ead507b29469a8843183c6b0be3f5a564d248af68`.
Independent Python `struct` and `hashlib` calculations construct the named-hole
identity plan, request-v2 core, changed-subject and complete-result commitments,
compact receipt, receipt windows, administrative fragment and enclosing root/HEAD
relations for both Recovery modes. The first-secret literals and fixed current
access inputs stay byte-for-byte unchanged. The JSON fixture schema is 4; the
stored wire schema remains 8. Only named plan holes can be zero; selected records
retain their complete hashes. The genesis HeadCore form tag is 2.

The one-shot source is
`tests/workflows/runs/053-genesis-receipt-vector-derivation/derive_genesis_receipts.py`,
SHA-256 `c6c2a1e6635d51e02fb21ddfe677d3225f1333d757e05e3384a3effebe56434d`.
No production codec supplies its expected bytes. Ordinary tests own the exact
literal, truncation, decoded-field and round-trip assertions.

The preceding revision-3 closure derivation starts from the checked schema-8,
revision-2 public bytes with SHA-256
`b011388fc351652e5fbd170e439627501fe309436d461be0b2a69bf7757f5fc8`.
It changes the nested revision, recalculates the physical logical-body hash,
and recalculates every dependent administrative/root reference, root, head,
conditional plan and genesis plan. All widths stay fixed because groups are
empty. Fixed synthetic interpretation IDs remain unchanged; these format
vectors do not establish the finite role policy or its interpretation hash.
The one-shot Python source and checked inputs are local evidence in
`tests/workflows/runs/043-format-vector-derivation`; production encoders were
not used to obtain the expected bytes. The source SHA-256 is
`719e53c7d17f7f2e771895c8f156c14bd7ed8805d606f5dadf67b957b51e88db`. Only the fixture literals and ordinary assertions are maintained.

The earlier schema-7 stored-closure derivation input has SHA-256
`539a9d79518705b94894affd9810fa7e74364e7862121522e2c57ec83f91e9f2`.
The original independent stored-configuration derivation script has SHA-256
`040bf9c10bc4bc67b49cbabe5c6031de1af9a7b5edf61591fca4e8857498f85b`;
the one-off nested-index revision-2 transformation script has SHA-256
`9d5ff3c45e8aad92eb9ad4c6268a2bfc5fc28a6c63dd62f3176c6d2940ade25f`.
Only the resulting literals and ordinary Go assertions are maintained.


## Historical schema 6 derivation

`value-access-wire.json` retains 20 accepted and 24 refused public wire images
from `tests/shared/testdata/value-access-oracles.json` at commit
`ba1345cd1ab92b19e56ba3ad1f34a6e1b92887f3`.
The source file SHA-256 is
`3a59385c09133fcb54e07cbc63e876d6b78ab9d7714f5f67bec511a1734bc316`.

The v4 predecessor's `Hex` was copied from each source case's independent
`Expected.Hex`. The v6 literals apply the fixed v5 transformations below
and then change the first schema `u16` from 5 to 6 in all 22 `ValueCore`,
`WrapCore` and `AccessRecord` cases. Accepted expected fields use schema 6.
The remaining 22 cases keep their bytes. This v6 transformation changes no
other field or refusal condition.

`lifecycle-projections.json` uses the same schema 6 transition: nine union,
grant and exclusion cases change only their purpose label from `v5` to `v6`.
Five prepared cases keep their outer label and change each nested access
record's schema `u16` from 5 to 6. The expected `AccessRecord` base64 field
changes by the same two bytes. The 13 comparison cases keep their bytes.
For accepted cases, `Value` maps the source `Input` to the current Go field names:
fixed octets use JSON integer arrays, variable octets use base64, and integers
remain exact JSON integer tokens. No production encoder produced expected data.
The ordinary contract test checks decoded fields, encoding, refusal, truncation,
trailing bytes and ownership. It does not interpret the old field-map or mutation
metadata.

The expected classification fields use `ValueSource` and
`ConfidentialityClass`. These are Go field-name changes only; all wire
bytes, expected values and exact integer tokens are unchanged. Stored entry
fields use `ValueBytes`, and `ValueCore` uses `EntryIncarnationID`.
The v6 whole-file hashes and independent expected-field key derivation
are recorded below. The v5 derivation hashes describe earlier transformations.

Cases cover empty and UTF-8 names, exact large epochs and binding serials,
plain and encrypted value entries, authority/reader/recovery access, invalid lengths,
recipient ordering and nested refusals. Synthetic ciphertext and public checks
establish wire behavior only; they do not establish cryptographic validity.
Routine maximum payloads remain covered by ordinary boundary tests. Seed,
transfer and generated-value cases are outside this fixture family.

`stored-closure-v6.json` fixes two public empty-genesis container closures and
two first-secret closures with schema 6. It adds an authenticated empty
administrative-index child to each Root, fresh incarnation IDs to current
control and key bindings, and the index page to the genesis identity plan.
The first-secret Root has its own index for its selected snapshot. Its
SHA-256 is
`58bda2d7b6b1d8061cc66d5dfb4f917477debbe003fd3e49cb873f163cd79f10`.

The v6 literal bytes were emitted once from the typed public fixture with
the current Go encoders. A separate Python calculation verified every
literal length and SHA-256, all exact child and Root Ref bytes, both
recipient projections, all four AccessRoot values, the unchanged payload,
the ValueCore schema change from v5, and its new material digest. The
format test now fixes those bytes and checks complete decoding and encoding.
The new v6 bytes do not provide independent encoder derivation for every
field; the independent HeadCore, LifecycleSubject and initial reservation
vectors cover those separate field tables.

`stored-closure-v5.json` is the historical predecessor. It fixes two public empty-genesis container closures and
two public first-secret container closures, with recovery disabled and enabled.
The schema 5 format tests compared fixed bytes with complete typed fields. They check the
recipient, value-entry and access children, Root, genesis HeadCore, identity plan,
create-only conditional plan, GenesisPlanCore, exact Ref commitments, access
descriptors and AccessRoot. They also check every truncation, trailing bytes,
owned decoding and incorrect counters or unsupported flags.

The predecessor literals were calculated once with Python `struct.pack` for
unsigned big-endian fields and `hashlib.sha256` for commitments, from the stored
v4 field tables. One local Node.js calculation applied the fixed v5 changes
below. No Go production encoder or decoder produced the expected bytes.
Each record has a fixed byte length and SHA-256. IDs use one stated first byte
and 31 zero bytes; expected semantic fields are declared in the Go test.
An exact Ref is its kind, version 5, domain, object, body SHA-256, body length
and index. The recipient descriptor hashes its domain-tagged ref vector;
the access descriptor hashes its domain-tagged complete record vector.
AccessRoot hashes `ENKV/CRYPTO/v2/current-access\0` followed by the length and
bytes of CurrentAccessCore. Genesis uses generation 1 and first selection uses
generation 2. The plan commits the independently calculated Root and Head bytes.

The public P-256 points are G and -G. The public RSA moduli are
`2^3071 + 12345` and `2^3071 + 54321`, with exponent 65537; their SPKIs use
canonical DER. No private key is present. Repeated synthetic ciphertext and
check values establish structural behavior only. These containers do not prove
signature validity, successful decryption, provider qualification or current
state, and were not used to create an admitted domain.

The v5 calculation used `Buffer` big-endian writes and standard SHA-256. It
changed each stored header, Ref and nested canonical schema from 4 to 5,
including normal and recovery public signing bindings. It changed the identity
plan label to `ENKV/LIFECYCLE-ID-PLAN/v5\0`. The supplied member adds an empty
`B(Generated)`, and `ValueCore` adds `Source: 1`. The member page is now 471
bytes and `ValueCore` is 323 bytes. The canonical payload, KMS bindings and
synthetic key bytes do not change.

Every Root adds this 319-byte generated closure after `Unsupported`:
`OwnerAbsent:u8 || PhaseID:32 || GraphID:32 || 8*u32 || 5*Descriptor44 ||
FragmentCount:u16`. The owner, IDs, counters and fragment count are zero.
Each present-empty descriptor has length 4 and count 0. Its digest is
`SHA256("ENKV/GENERATOR/v1/" || label || NUL || B(u32be(0)))`, with labels
`graph-set`, `live-owner-set`, `success-window`, `failure-window` and `slice-index`, in that
order. These are committed empty vectors, not zero-byte descriptor holes.
Genesis Root lengths are 1512 and 2596; first-secret Root lengths are 1734 and
2818, for recovery disabled and enabled. Genesis plan lengths are 2420 and
3665. First-secret child-byte totals also increase by four for the member.

The calculation checked each original record's length and digest before it
changed the bytes. It then recalculated the ValueCore material context, access
records, recipient/access descriptors, AccessRoot, child Refs, HeadCore and
conditional-plan commitments, and each enclosing GenesisPlanCore length. The
unsupported-flag refusal still changes `Unsupported`, before the new extension;
it does not change the fragment count. Both recovery modes and all structural,
truncation, trailing-byte and owned-decoding assertions remain.

The original v4 fixture SHA-256 is
`157b79c8f03ceddfb648a2cd057b04f38a212f80e58efa2fb6e450c4cec5ea77`.
The v5 fixture SHA-256 is
`c03a2e3ac877ec64eac71fea9a3fc0fbd795d30b9e31984c9fd508c23f539e89`.
The original one-off derivation script SHA-256 was
`e3d9f93034249aec08fca25c0dc9509778c25f0a82bcf2d9d0c4e1ddbe7ca060`.
The initial v5 transformation script SHA-256 was
`620568c1ab0500483fc32e9ba9ee5106015d76ede3b3698d38424b1d318cdc75`.
Only the fixed literals and ordinary Go assertions are maintained.

The slice-index addition was calculated separately with Node Buffer and
SHA-256. It verified every source length/hash, inserted the exact 44-byte
empty descriptor before the fragment count, and recalculated Root Refs,
HeadCore, conditional-plan and enclosing GenesisPlanCore bytes and hashes.
It did not call the production encoder.

`lifecycle-projections.json` contains 27 fixed comparison, comparison-result,
membership-union, grant, exclusion and prepared-secret vectors selected from
`archive/supplied-secret-lifecycle-2026-09-12`. Its v4 predecessor copied expected
hex from these independently derived source files; the current literals apply
the fixed v5 transformations below:

| Source file | SHA-256 |
|---|---|
| `comparison-projection-oracles.json` | `4008006709ff39f2c19097717650063076e647a472c62d72061b69f17e2ef89f` |
| `membership-lifecycle-projection-oracles.json` | `12a7cba274101edd72981a9d2e5fd5ee767fdc8724a4ea8c7315b049f2717d00` |
| `prepared-secret-projection-oracles.json` | `8118ae5bce333d4f89a5b7edb85b116d5e58db24c6fc05008438cc52b8daf96f` |

`Value` maps the source's stated inputs to the current Go fields. Fixed IDs use
integer arrays, names use the source's exact UTF-8 bytes, and prepared entry
and access bytes use base64 of their migrated source-literal spans. Original
span hashes were checked during selection. No production encoder or decoder supplied expected
bytes or fields. The source equations use explicit unsigned big-endian fields
and SHA-256 over the complete purpose-prefixed projection.

Cases include all value relations, retained-entry exclusion with equal or
changed values, empty values, UTF-8 ordering, opaque zero digests, grant and
exclusion on retained entries, membership-only preparation with no fresh value,
and exact large unsigned counters. Ordinary tests verify bytes, fields,
descriptors, every truncation, trailing data and owned decoding. They do not
execute the frozen metadata, field maps, mutation descriptions or owner model.
Synthetic encrypted bytes prove structural behavior, not private validation or
authorization. Large aggregate boundaries remain ordinary generated test cases.

## Supplied apply request identity derivation

The fixed literals in `core/format/apply_identity_test.go` were derived with a
one-shot Python standard-library calculation. It reads the independently derived
`stored-closure-v8.json` literal with SHA-256
`137f413ad39b2708497ea1d1c58cc2fafcd69c6d4dcd3d7b6a35b4f1e4957070`,
inserts the exact receipt support reference and adjusts its named count and byte
slots. All other request, receipt, public-state and authorization fields use
explicit unsigned big-endian frames and SHA-256. No production codec supplies
expected bytes or hashes.

The resulting request identity is
`c7f043a18d5fb796d347fea7099697393afd0a71f59f2a9f02a54bf7b0a40f4e`.
The local derivation and component length/hash record are retained under
`tests/workflows/runs/053-supplied-apply-vector-derivation/`; the script SHA-256 is
`9f2fbc611bd9426ff9c32e115fc69c749bccca658e2dd75c1ca708a92df65328`.
Only the fixed literals and ordinary Go assertions are maintained. The tests also
damage individual cross-part bindings and opaque commitments, and distinguish
the named request holes from complete stored records.

## Historical expected-field key derivation

The current expected-field keys are derived from the prior fixed fixtures by
schema-specific text replacements:

| Fixture and expected-field owner | Key replacement | Count |
|---|---|---:|
| `value-access-wire.json`, accepted `Member` record | `Value` → `ValueBytes` | 6 |
| `value-access-wire.json`, accepted `ValueCore` record | `MemberIncarnationID` → `EntryIncarnationID` | 3 |
| `lifecycle-projections.json`, comparison rows | `BeforePublicMemberDigest` → `BeforePublicEntryDigest` | 27 |
| `lifecycle-projections.json`, membership rows and sides | `Member` → `EntryDigest` | 25 |
| `lifecycle-projections.json`, prepared records | `Member` → `EntryBytes` | 5 |

No production codec supplies these replacements. Reversing them restores each
prior file byte for byte. Parsed cases and values match after applying only the
specified key map. Outer `Value` fields, schema labels including `Member`, case
names, acceptance flags, `Hex`, base64 spans and all number tokens stay exact.
The text operation preserves integers above `2^53` without numeric conversion.
The stored-closure fixture is unchanged; its explicit `member_page` and
`member_ref` tags do not follow Go field-name changes.

| Fixture | Prior whole-file SHA-256 | Schema-6 whole-file SHA-256 |
|---|---|---|
| `value-access-wire.json` | `7d65f2dc2125f7164e3f2ef9de31f941cafb839384c9715e8a4a57abee88be59` | `2e01bd774a002520a653adca3798b98a27419bb590d2e21b83496f669b18527f` |
| `lifecycle-projections.json` | `6e8527295ebd93ae9b59d8a818484a56c14caa553b55e39c7b3d41f9268fd5c9` | `0e70ff24e86bbcf7b2f419fd6c6f3e1e4648411f6a3039718c69d83411d18dd4` |

## Value/access and lifecycle v5 derivation

One local Node.js calculation applied these byte transformations to the fixed
v4 literals. It used `Buffer` big-endian writes and the standard SHA-256 function;
it did not import, execute or ask a production codec for expected output.

- `ValueCore`: change its initial schema `u16` from 4 to 5 and append the supplied
  `Source` octet `01`. Its accepted lengths become 317, 324 and 573 bytes. Add
  `Source: 1` to the corresponding expected fields.
- `Member`: append `00000000`, the empty `B(Generated)` field. Do not change the
  name, recipient vector, value bytes or embedded canonical payload.
- `WrapCore` and `AccessRecord`: change only the initial schema `u16` to 5,
  except for context digests derived from the migrated `ValueCore`. Recalculate
  those digests as `SHA256("ENKV/CRYPTO/v2/material\0" || u32be(length) || core)`.
  Replace each matching digest in both the wire and its expected field array.
  `WrapRow` and `CanonicalPayload` bytes do not change. The canonical payload
  profile stays 2.
- Union, grant and exclusion projections: change only their initial purpose
  labels from `lifecycle-union-v4`, `grants-v4` and `exclusions-v4` to the v5
  labels. The Crypto prefix remains `ENKV/CRYPTO/v2/`; row fields do not change.
- Prepared rows: preserve the v2 purpose label, count, names and slots. Each row
  remains `B(Name) || Slot:u16 || B(Member) || B(AccessRecord)`. Append the empty
  generated field to each member, increase its enclosing length by four, and
  change each access schema to 5. Replace the two expected base64 spans with
  these same transformed bytes. Nonempty projection lengths become 2057, 1046,
  1555 and 3080 bytes. Comparison and comparison-result literals do not change.

Every refused value/access image receives the same schema and framing changes
as its valid counterpart. Its original invalid count, ordering, UTF-8, epoch,
packet kind, packet length or nested ciphertext remains unchanged. Thus refusal
does not depend on an obsolete schema. All 20 accepted and 24 refused cases and
all 27 lifecycle cases remain. Numeric JSON tokens, including values above
`2^53`, were edited as text and never re-serialized through a floating-point
number. The ordinary Go vector assertions are unchanged.

| Fixture | v4 input SHA-256 | v5 output SHA-256 |
|---|---|---|
| `value-access-wire.json` | `4a3e9d93b6b3bfca1debeebdc7ec16f8fc8675318ce834ba1b69f90b21e7fabe` | `159c6e0003a42c987aeda5d9b367100917b1fce8b8b59d08209e96fb584bc1a6` |
| `lifecycle-projections.json` | `0ac0c397e26fc0ac2fc57cfde7abfef902a896b73a3a9371c0e9763f1a0db974` | `6e8527295ebd93ae9b59d8a818484a56c14caa553b55e39c7b3d41f9268fd5c9` |

The one-off transformation script SHA-256 is
`4857ce6da5d99125f876f733f77428d703c4dfa45968800732415bd6498b3999`.
Only the resulting literals and ordinary tests are maintained.
