# Configuration input

This provider-neutral module captures one explicitly selected absolute YAML or
JSON file and its generated JSON satellite. `domain.name` selects the stable
relative path `.enkv/<name>.generated.json`; the editable filename is independent.
It parses the common `enkv/configuration/v3` envelope without provider access.
Plugins own public settings and normalization. Parsing grants no installation
trust or Core basis authentication.

`Capture` owns private disk images until `Pair.Close`. `Parse` reads only those
images. Neither operation changes the source files or repairs missing generated
data. JSON and YAML selection is explicit. The pair has an aggregate 256 MiB
limit, a 64 KiB scanner window and sixteen structural levels.

The CLI resolves its default `enkv.yaml`, relative paths and syntax before
calling this module. Library callers still supply an exact absolute path and
explicit format. Fresh and changed YAML strings use plain spelling only when
their position permits the exact bytes and string type. Other strings remain
quoted. Span edits preserve comments, field order and unrelated bytes; JSON and
unchanged encrypted records retain their own representations.

Generated source selects `plugin` and exactly one of `settings` or `canonical`.
Ordinary settings require a safe nonempty installed plugin name. Recovered
source uses nested `canonical.settings` and may have `plugin: null`. The
`enkv/generated/v2` companion retains the exact complete records under
`canonical_records.generators`, keyed by entry name, and
`canonical_records.outputs`, keyed by destination name. Each canonical view
requires its matching saved record; missing backing refuses.

Output destinations use the same settings arms. Each entry has a
`source.encoding` for its retained input and an `output_encoding` for delivery.
Both default to `raw`; `base64` input must be canonical padded Base64. Input
bytes are retained exactly. Publication and local materialization use the same
selected entry output encoding, converting only when it differs from the input
encoding. Destination encoding lists are not accepted. Local output edits take
effect only after successful apply.

Canonical settings require unique decoded object keys and valid Unicode scalar
strings. Scalar roots and exact JSON numeric tokens remain supported. Settings
traversal has its own 10,000-level depth limit. Parsing compares the editable
view with the saved settings and preserves unchanged token spans. A changed
view produces proposed canonical settings; it does not authenticate them or
apply plugin defaults. Installed plugin validation remains the composition's
responsibility.

Current generated intent has a 393,216-byte per-entry bound and a 50,331,648-byte
aggregate bound for 128 entries. This complete source content is distinct from
the 32 MiB compiled value declaration. Authenticated unchanged rows can later
compile to exact selected references; parsing never drops their expected bytes.
Canonical output bindings share the existing 32 MiB decoded declaration budget.
Base64 text and all surrounding syntax count toward the complete source-pair
limit.

`outputs.routing.default` is a destination list. `outputs.routing.entries` maps
exact entry names to replacement destination lists. An omitted entry override
inherits the default; an explicit empty list selects no destination. Destination
names refer to `outputs.destinations`. Routing is independent of recipient
membership.

`Model.Outputs` retains source selections and input arms. Composition supplies
trusted passive normalization, fills `Generator.Intent` or the output's
`Binding.Destination`, then calls `RefreshPublic`. Ordinary target derivation
remains unavailable until its operation supplies the complete routed set.
Unchanged canonical records contain complete target facts and need no installed
interpreter to parse or emit. An output settings edit clears proposed targets
for later interpretation. Recovery emits null local selections and preserves
exact canonical settings, including an empty creation-assigned locator.
`RefreshPublic` does not authenticate a build or admit an effect. Local
preservation edits, including Set and rename, keep unrelated opaque plugin
settings without installing or normalizing those plugins. The operation still
checks its selected target, custody, public bindings, source joins and budgets.

A trusted Reader baseline must be selected independently of an untrusted
candidate. File readability and successful parsing do not establish trust.

The local name has 1–64 ASCII characters matching
`[a-z0-9][a-z0-9_-]{0,63}`. It does not change DomainID, keys or Store settings.
Renaming the editable file within its directory leaves the satellite path
unchanged. A logical-name rename uses `BeginRename` and `StageRename` to change
the name, reference and satellite path together.

New YAML uses block collections with two-space indentation; nonempty generated
JSON records use deterministic multiline formatting. YAML accepts optional
single-document start and end markers. Additional documents refuse. Edits copy
unchanged encrypted records byte-for-byte. Ordinary Git merges can combine changes to
different existing records; additions at the same location can conflict.
Resolve conflicts by selecting complete compatible records in both files.
Parsing rejects incomplete joins and records moved to a different target.

`BeginEdit`, `Stage` and `Commit` share one native transaction owner. Cooperating
writers lock the affected paths in a fixed order and retain the exact candidate
before changing visible files. Keep manual editors idle until the operation
returns. Read-only capture never creates locks, repairs a pair or finishes a
pending transaction. A pending edit prevents ordinary consumers from accepting
the pair.

`BeginReconstruction` admits a source-free absent pair, fixes its explicit local
name and holds both destination namespaces. It supplies no cryptographic
admission. `ReconstructionOutput.Stage` consumes the complete normalized model,
releases it after emission and returns the parsed staged model borrowed until
`Commit` or `Close`. The full composition must qualify its public basis and
validate its complete meaning before commit. `Commit` preserves confirmed
readback facts through later cleanup failure. After clean delivery, `Capture`
borrows the exact delivered pair and parsed model under the same locks, checking
both digests and native install identities. Close the output after all borrowers
finish. Native installation never replaces a foreign file or infers ownership
from matching bytes.

`BeginCompanionReconstruction` captures a surviving YAML or JSON declaration
and holds its source and absent companion namespaces under ordered locks.
`MergeReconstructedCompanion` consumes that source model and an independently
authenticated reconstruction model. It preserves surviving public intent and
joins current public recipient facts by their managed IDs. It restores committed
supplied-secret input and enumerates input absent from authenticated state.
Staging retains the exact source image and installs only the missing companion.
A changed source or a concurrently created companion refuses. The operation
preserves source bytes and native identity; its models grant no authentication.

`ErrSourceImageMissing` identifies exact selected-image absence observed by
native intake. Temporary snapshot failures do not carry it. `ErrSourceInvalid`
identifies a positive grammar or shape refusal. Reader failures retain their
original causes and safe diagnostics; they are not proof of invalid source.
`ErrSourceChanged` identifies an observed difference from captured source bytes
or native identity. An unavailable inspection alone does not establish a change.
`OccupiedEditTarget` identifies a destination observed present when absence is
required. The prepare coordinator combines confirmed companion absence with
complete independent recovery inputs; the error alone grants no recovery right.

`RecoverEdit` completes only the saved candidate after checking every recorded
old, new or absent path. It accepts no new value and does not reseal, roll back
or apply. Preserve pending transaction files after interruption. Recovery
refuses foreign edits or a live writer. Native readback and cleanup are separate
facts: a delivery can retain exact paths and digests while cleanup fails.
`RecoverySource` is present only when exact pending ownership was established.
Closing a local observation releases handles without deleting durable recovery
evidence. This protocol does not strengthen macOS power-loss durability.

Native capture supports Darwin and Linux regular files. Other platforms refuse
capture because the required native change metadata is not available here.
Capture makes one typed editable scan and discards plaintext and complete
intents and plugin settings before retaining source rows. Parse reads each captured
image once.
A preservation emitter can make the third bounded pass; no extra semantic scan
is required. Plain and sealed values share one raw budget during normalization;
counts are reserved before retaining the next member or generator payload.

`ParseForPreparation` validates every present record and source join, then
returns the complete ordered missing supplied-secret set in `Model.MissingInputs`.
It does not admit that incomplete pair to ordinary consumers. Repeated preparation
with the companion present re-enumerates this set without reconstruction.

`ParseForSet` uses the same admission and adds the selected entry's source spans.
Set may fill one missing input while preserving all others. Its staged missing
set must equal the original set minus that exact target. Present records and
unrelated joins keep their checks. A fully supplied candidate must pass ordinary
`Parse`; plan, apply, read and materialize remain strict. Map and selected-row
span indices are zero-based; use `SelectedSecretPresent` to distinguish an absent
selected generated row.

Retirement and rekey deliver a separate successor pair in the source format
and with the same logical domain name. Its directory must be separate so
neither output member aliases the source. The transform preserves unrelated
pending declarations and sealed records. Retirement removes only the retired
live row and its declaration joins; historical public-basis evidence remains.
Changed retained pins must match the exact predecessor material. The delivered
pair is reopened and checked before domain selection.

Successor metadata identifies the exact prepared operation for later GET-only
observation. It does not grant a replay or local repair permission. Local
recovery completes only saved pair writes and never performs a deferred domain
selection. Metadata in an ordinary source remains inert.
