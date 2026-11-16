# Shared Intent retirement fixture

`retirement.json` is an exact schema-8 capture of a full local test Store after
an actual historical retirement. It contains 281 Store objects and 1,580,763
bytes. The captured state retains a release-only obsolete Intent carrier beside
a surviving retirement and current generated values. Store, Trust and keys are
local test fixtures; they do not contact a provider.

| File | SHA-256 |
|---|---|
| `retirement.json` | `a1bbd6939112ea79c8b3e725ae86381651376e062656cb725433f6e6d0fcdd7a` |

The producer used the source archive for
`751198f2f50ef0f202665f4c26b665582056913e`. The archive manifest is
`tests/workflows/runs/046-retained-access-trial/historical-source.json`, with
SHA-256 `b49f5552ef47393a37105f72533869a12f8e098c9c3469368347087729cc721e`.
The added local capture test was `TestCaptureHistoricalSharedIntentRetirement`.
The runner recorded revision
`cf56674d7faabf70a04994779ad492aa4e998b2d` and dirty diff SHA-256
`45d93e71cc140819343ca422b1c3e26a4393dfddb604b25f4714d57fe18949c6`.
The retained capture metadata is
`tests/workflows/runs/051-post-correction-security-triage/historical-shared-intent-v4/capture-artifact.json`.

The replay requires exact administrative cold Open, receipt bytes, signer
restoration, preserved work commitments, and actual publication EndWork.
Preserve the original captured bytes. Do not trim the Store or regenerate this
historical input with the current implementation.
