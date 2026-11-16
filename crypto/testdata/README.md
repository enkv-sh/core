# Private packet fixtures

`private-packets-v2.json` retains the four implemented value-authority,
value-recovery, source and qualification-proof cases from the file with the same
path at commit `ba1345cd1ab92b19e56ba3ad1f34a6e1b92887f3`.
The original file SHA-256 is
`5e496824102d09d010787efe26c34f104708183e8ae81ecb5511594bad5ec8d0`.

Contexts use canonical schema-10 `WrapCore` literals. All public field
facts, test key bytes, packet kinds and lengths are unchanged. The WrapCore
layout is still 278 bytes; wrap profile and private packet version remain 2.

The original schema-7 packet file SHA-256 was
`d00dccfbb48880e2e446c3953d47c274ebc04efae61d9cb8e1885b8590a1291f`.
A one-time local Python calculation read each literal's fixed big-endian fields
in this order: schema, profile, DomainID, CompatibilityID, CryptoSupportID,
MaterialKind, MaterialID, MaterialContextDigest, SubjectKind, SubjectID,
BindingID, BindingSerial, PublicBindingDigest, Provider, WrapProfile, PacketKind
and PacketLength. It wrote those fields independently and first reproduced all
four schema-7 cores, context digests, packets and packet hashes exactly. It then
changed only the canonical schema to 8 and calculated:

`C = SHA256("ENKV/CRYPTO/v2/rsa-packet\0" || u32be(len(W)) || W)`

`packet = u16be(2) || u16be(kind) || C || test-key-bytes`

The schema-8 packet file SHA-256 was
`d013be192d1b4070ba2567a3f6a2c2e0638d5f6d85b84afa25111bb78957727a`.
The schema-10 calculation used Node/OpenSSL with the same explicit field
widths. It first reproduced all four schema-8 contexts, packets and hashes,
then changed the canonical schema to 10 and repeated the formulas above.
The current packet file SHA-256 is
`a32452f0a9b7197e2bbf10e187712686685e958e8bd9b008db153a59b1bd3525`.
Expected packets remain 100 bytes for value-authority/value-recovery and 68
bytes for source/proof. No production encoder supplies expected bytes.

These public test keys stay at the Crypto test owner. Tests establish packet
framing, exact context binding and refusal of changed headers. They do not prove
RSA validity, cloud KMS permission or recovery execution. Seed and transfer
packet kinds have separate fixed vectors in `internal/custody/value_generation_vectors_test.go`.

## Supplied value primitive vector

`internal/custody/payload_test.go` uses an independently transcribed 318-byte
ValueCore: schema 10, profile 2, the displayed repeated-byte IDs, name `n`,
epochs 3 and 4, length 12, and the final supplied-source octet `01`. Its SHA-256
is `78ca1f2aa005062c2fecdf685f009000b7774265f6672f0bc07352013a799a98`.

The one-time Node/OpenSSL calculation used `D || C = 00..3f`, nonce `00..0b`,
and UTF-8 plaintext `secret-value`. With `B(x) = u32be(len(x)) || x` and
`L(x) = "ENKV/CRYPTO/v2/" || x || NUL`, it computed:

- AES-256-GCM with D, that nonce and AAD `L("value-aad") || B(core)`;
- HMAC-SHA-256 with C over `L("semantic") || B(core) || B(plaintext)`;
- HKDF-SHA-256 over D/C, salt `L("package-hkdf-salt")`, info
  `L("package-hkdf-info") || B(core)`, length 32; then HMAC-SHA-256 with that
  derived key over `L("package-check") || B(core)`.

The test stores the resulting ciphertext/tag and two hashes as fixed literals.
The calculation used only Node's `Buffer` and `node:crypto`; it imported no
production codec or custody code. All key bytes in these fixtures are public
synthetic test inputs.

## Generated material, result and member vectors

The generated vectors use canonical schema 10 for the 204-byte
OperationMaterialCore, 452-byte GeneratedResultCore and 354-byte generated
ValueCore. Generator identity labels remain `ENKV/GENERATOR/v1/`; transfer and
private-packet versions remain 2. The seed is 32 bytes of `80`; result keys are
`00..3f`; result and transfer nonces are `00..0b` and `0c..17`.

The independent calculation writes the displayed fixed fields in wire order.
Generator identities use SHA-256 over their label, NUL and `B(fields)`. The
material context uses `L("material") || B(MaterialCore)`; the immutable seed
body uses `L("immutable-material-body-v1") || u16be(3) || B(MaterialCore) ||
SeedCheck`. Seed and result checks use their specified HKDF/HMAC purpose labels.
Result ciphertext uses `L("result-aad") || B(ResultCore)` as AAD. The result
transfer binds SHA-256 of ResultCore; its packet is version 2, kind 6, the
transfer packet-context digest and the 64 result-key bytes. Its key and AAD
use the transfer HKDF/AAD labels and `B(TransferCore)`.

Three malformed private-packet vectors change byte 0, 2 or 4 of that plaintext
packet, then encrypt it with a valid GCM tag. Their tests first require GCM
authentication to succeed before checking refusal of the inner version, kind
or context. The source-transfer vector has no canonical-schema field and
remains byte-identical.

The generated-member fixture uses name `token`, incarnation `15` repeated,
phase `14` repeated, and the result fixture's fixed public fields. Its binding
contains profile, assumption, intent, resource, account, token and completion
class. Its value/origin/key IDs follow the generator identity recipes. With
`C = B(ValueCore) || ResultID || SHA256(B(ResultCore) || ResultSemanticCommitment)`,
the generated-member salt and data/commitment/nonce labels derive its two keys
and nonce. Ordinary value AAD, semantic and package formulas then apply.

The Node 24.19.0/OpenSSL calculation reproduced every prior schema-8 primitive,
complete result record, malformed-packet and generated-member answer before
changing the canonical headers and recomputing their dependent answers. It
also reproduced the unchanged use-plan digest and source-transfer bytes. No
production encoder, derivation or sealing routine supplied expected answers.
The current complete generated result is 1,338 bytes with SHA-256
`5e572c1e3a36456a85867e0820bd7b3148944068741a570c738fd33580c92fda`.
