# Format version history

The specification is [FORMAT.md](FORMAT.md). This file is its version history. Each export names its version in `manifest.export_version`. A version change updates the specification, the vectors and both verifiers in the same commit, and the tests in `test/open-release.test.mjs` fail if they disagree (see [CONTRIBUTING.md](CONTRIBUTING.md)).

How versions work: a **minor** version only adds things a reader may ignore (an optional file, an optional field). Everything valid under an earlier minor version stays valid. A **major** version may change what an existing field means; there has not been one, and [STABILITY.md](STABILITY.md) says what a reader can rely on until there is.

## 1.1 (2026-11)

Adds, all optional:

- `reconciliation.json`: what the destination system's own record says about each action, the state of each result, approval binding, and later outcomes linked to an action. The verifier recomputes each state from the destination record the export carries.
- `authority.jsonl`: the authority in force at the time of each action, when the history recorded it.
- `README.txt`, and `caveats` and `scope_statement` in the manifest: the two caveats, and what the export was checked against and for which period.

Also in this period, without a version change because they are optional and ignorable: an `anchor` field on a transparency log head (an outside RFC 3161 time-stamp; see FORMAT.md, "The anchor"), and the `anchors/` fixture in `vectors/`.

Also additive, with no version change: **decision evidence** in records (`ext.decision` and `ext.decision_ref`, see FORMAT.md) and two new checks that appear only when an export has a decision record or a pointer. Conformance vectors `decision-*` cover them. A decision may also carry two optional references, `intent_ref` (the instruction it answers) and `model_ref` (the model invocation behind it); when present they are checked as part of "decisions are well formed", and a decision without them is unchanged.

Also additive, with no version change: **control decision evidence** in records (`ext.control` and `ext.control_ref`, see FORMAT.md) and two new checks that appear only when an export has a control record or a pointer: `control evidence: every control decision agrees with the action that cites it` and `control evidence: control decisions are well formed`. Six conformance vectors (`control-*`) cover them. A reader that does not know about them verifies the same exports as before.

Also additive, with no version change: **exact-change approvals**. An approval's binding accepts `environment`, `resource`, `operation`, `change_digest`, `risk_ref` and `break_glass`, the action's record can carry `ext.mutation`, and an approval entry can carry `path`. The existing check `approval binding: results recompute from the records` recomputes them, and also fails on a hidden emergency path. See FORMAT.md, "Exact-change approvals". A binding that states none of the new fields is checked as before. A verifier that predates this will not apply the new rules and may report that check as failed on an export whose approvals use them. Five conformance vectors (`exact-change-*`) cover it.

Also additive, with no version change: **cost statement** files (`statement/statement.json`, `statement/cells.json` and companions, see FORMAT.md) and the checks that recompute a statement's totals from its cells. They appear only when `statement/statement.json` is listed in the manifest. Conformance vectors `statement-valid`, `statement-cell-altered`, `statement-total-altered` and `statement-chargeback-altered`. Both verifiers implement them. A verifier that predates them still passes the file hashes and the signature of a statement bundle and does not add the figures up.

A 1.0 export is still valid, and a 1.1 export without the new files verifies as before.

## 1.0 (2026-10)

The first published version: `manifest.json` and `manifest.sig.json`, records with their hashes and chains, daily roots, the emitter proof (optional), the transparency log proof (optional), and the two verifiers.
