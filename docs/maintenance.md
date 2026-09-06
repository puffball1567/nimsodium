# Maintenance Policy

After the initial feature set, `nimsodium` maintenance is mainly about keeping
safe workflows stable while tracking Nim and libsodium changes.

## Maintenance Goals

- keep the default API small enough to choose confidently
- keep raw FFI private
- preserve stored-data formats or provide migration paths
- track libsodium security releases
- keep tests aligned with every public workflow
- keep docs, audit notes, and license notices current

## Version Tracking

For every release, record:

- Nim compiler version used for CI and local verification
- linked libsodium runtime from `sodiumVersion()`
- operating systems tested
- any newly used libsodium symbols
- any changed binary formats

## libsodium Updates

When libsodium changes:

1. Review libsodium release notes and security advisories.
2. Check whether any used symbols changed behavior, parameters, or status.
3. Run the full test suite against the new libsodium version.
4. Update `AUDIT.md` if new symbols are used or assumptions changed.
5. Update `licenses/libsodium/` if redistributed license material changed.
6. Add a changelog entry if user-visible behavior or supported versions
   changed.

CI currently builds libsodium 1.0.22 from the official release archive and
checks its SHA-256 digest before running the complete workflow and C ABI test
suites. The distribution-provided libsodium remains a separate compatibility
lane.

## API Expansion

Prefer workflow additions over raw symbol exposure.

A new workflow is a good fit when it:

- removes nonce, salt, output buffer, state, or return-code handling from
  callers
- validates structured input before using it
- uses typed key material
- has clear tests for wrong keys, wrong associated data, tampering, malformed
  inputs, and empty inputs where relevant
- can be explained in the workflow guide

Do not add a public API only to improve raw symbol coverage.

## Stored Format Changes

Before changing an encrypted or signed storage format:

1. Add or increment a magic/version marker.
2. Keep the previous parser if practical.
3. Add tests for old and new payloads.
4. Document migration behavior in `docs/formats.md`.
5. Mention the compatibility impact in `CHANGELOG.md`.

Silent reinterpretation of an old format as a new format is a bug.

## Release Verification

Run:

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

Also run every example listed in `README.md`.

## Audit Updates

Update `AUDIT.md` when:

- a new raw libsodium symbol is used
- a binary format changes
- a workflow starts accepting a new kind of structured input
- a security assumption changes
- a dependency or platform support assumption changes

## Documentation Updates

Keep these files aligned:

- `README.md`: quick adoption path and workflow matrix
- `docs/workflows.md`: which API to use
- `docs/formats.md`: stored formats and migration policy
- `docs/release.md`: release checklist
- `AUDIT.md`: current pre-release audit status
- `CHANGELOG.md`: user-visible changes
