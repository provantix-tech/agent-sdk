# What is stable, and what is not

This says what you can build on. It is part of the specification's release, and a change to it is a version change.

## Stable (a change needs a new major version)

- The meaning of every field in a version of the format that has been published, and the algorithms that use them: record hashing, chain links, daily roots, canonical JSON, the signature over the manifest, the Merkle tree of the transparency log and its proofs.
- The vectors in `vectors/`: a published vector is never edited to change its expected result. If a result was wrong, the vector is replaced under a new name and the reason is written in CHANGES.md.
- The command-line contract that `conformance-run.mjs` relies on: `<command> <dir> [--emitter-keys <file>] --json` printing `ok` and `checks[].name, ok`.
- The check names. Verifiers report failures by name and the vectors list those names, so renaming one is a change to the specification.

## Additive (may happen in a minor version, and a reader should ignore what it does not know)

- New optional files in an export, new optional fields in a file, new optional checks.
- New vectors.
- More explanation in the wording a verifier prints. Wording is not part of the contract; the check names and the pass or fail are.

## Not stable

- The code of the two verifiers beyond their command-line behaviour. Read it, copy it, learn from it; do not import it as a library and expect its internal functions to stay.
- The `anchors/` fixture's authority: it is a real token from a public authority, kept as an example. The authority's certificate will expire, and the token's check that it was valid when stamped will keep passing.
- The platform that produces exports. It is not part of this project and may change without notice. What it produces is described by the specification, and only the specification is the contract.

## Support

A version of the format is supported by these verifiers as long as the vectors for it pass. A reader built from FORMAT.md that passes all the vectors agrees with ours, by definition of this project; see [CONFORMANCE.md](CONFORMANCE.md).
