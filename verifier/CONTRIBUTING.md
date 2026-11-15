# Contributing

This is the open part of Provantix: the export format, the verifiers that check it, and the vectors that say what a correct verifier does. It is open so that a reviewer can check evidence with tools that are not ours. Contributions that make that easier are welcome.

## What helps most

- **A third verifier**, in any language, built from [FORMAT.md](FORMAT.md) alone. Run it with `conformance-run.mjs` ([CONFORMANCE.md](CONFORMANCE.md)). Where the specification was unclear and you had to guess, tell us: that is a bug in the specification, and the most valuable kind of report.
- **A vector** for a case that is not covered, with the reason it matters.
- **A correction** to the wording of the specification, or to something a verifier prints.

## How a change is made

1. Open an issue or a pull request. Say what you want to change and why.
2. A change to the **format** (a new field, file or check, or a different meaning) touches four things together, and a pull request that changes one without the others will not pass:
   - [FORMAT.md](FORMAT.md): the rule, in words.
   - `vectors/`: at least one vector that fails without the change and passes with it, and its entry in `vectors/expected.json`.
   - **both** verifiers: `verify-export.mjs` and `python/verify_export.py`, so they agree.
   - [CHANGES.md](CHANGES.md): the version it belongs to, and whether it is additive (a minor version) or changes a meaning (a major version, see [STABILITY.md](STABILITY.md)).
3. Regenerate the vector table in CONFORMANCE.md: `node conformance-run.mjs --table`, and paste it between the markers.
4. Run `node --test test/*.test.mjs` from this folder. It checks both verifiers against every vector, the specification's version against the history and the vectors, the vector table, and that the shared token check embedded in each verifier is identical.

## Rules the tests hold you to

- `verify-export.mjs` imports only `node:` modules. It is meant to be copied and read on its own, so it stays one file with no installs.
- The token check in `rfc3161.mjs` is embedded in `verify-export.mjs` and `verify-log.mjs` between `<<< rfc3161-check` and `>>> rfc3161-check`. If you change it, change all three the same way.
- A published vector's expected result is not edited. See STABILITY.md.

## What this project does not take

Changes to the platform that makes exports are not made here, because the platform is not part of this project. The format it writes is, and a proposal that the format should change is welcome as an issue.

## Reporting a security problem

If you find a way to make a verifier pass something it should refuse, or refuse something it should pass, treat it as a security problem: tell us privately first (security contact in the repository's README), and we will credit you when it is fixed.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, the same as this project (see [LICENSE](LICENSE)).
