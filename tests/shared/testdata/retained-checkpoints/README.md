# Retained preparation checkpoints

These exact schema-8 checkpoints were captured from the real historical producer
at `751198f2f50ef0f202665f4c26b665582056913e`. The capture stopped after the first
selected preparation, before actual Final. The source manifest SHA-256 is
`b49f5552ef47393a37105f72533869a12f8e098c9c3469368347087729cc721e`;
the source archive SHA-256 is
`8ab1be6fb6861715b3c6689cf43c101c9bf84a19abf4febe7ac6ebc26f4fe6e0`.
The capture checked all 1,629 source files against that manifest, then stopped
after private preparation, candidate binding, Claim and selection of the first
checkpoint. A cold Open checked its image association. Store objects, image bytes
and immutable checkpoint artifacts were retained. It did not capture actual Final.
These are historical inputs, not synthetic expected outputs. They use local test
Store, Trust and key fixtures; they do not contact a provider.

| File | SHA-256 | Prepared ordinary readers | Surviving older owners |
|---|---|---|---:|
| `content-surviving-owner.json` | `29075a7c6896260c0a62957a22dd1cc4bf29eeef465974c6d526bb85b4656f2d` | Intended current readers only | 1 |
| `membership-last-owner.json` | `18c33438f815eee0062089ec05f83a3deff5546bb517393f123f4141083b5ef3` | Current and predecessor readers | 0 |

The tests require cold public Open, exact preparation bytes and immutable objects,
fresh-process private continuation without a replacement preparation, exact Final
readers and actual private consumption. Do not regenerate these inputs with the
current implementation. Preserve their original captured bytes.
