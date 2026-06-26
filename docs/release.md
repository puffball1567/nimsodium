# Release Checklist

Use this checklist before publishing a `nimsodium` release.

## Package Metadata

- Confirm the repository URL and issue tracker are final.
- Confirm `nimsodium.nimble` has the intended version, author, description,
  license, source directory, and skipped directories.
- Confirm `docs/`, `licenses/`, `README.md`, `CHANGELOG.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, and `THIRD_PARTY_NOTICES.md` are included in the package.
- Confirm `LICENSE`, `THIRD_PARTY_NOTICES.md`, and `licenses/` are included in
  the package.
- Confirm the README install instructions match the published package name.

## API Review

- Public APIs should stay task-oriented and high-level.
- Raw FFI under `src/nimsodium/private/raw/` must remain undocumented and
  unsupported for application code.
- Public key material should use distinct types and checked `...FromBytes`
  constructors.
- New encryption APIs must generate nonces internally or otherwise remove
  nonce reuse from normal caller control.
- New workflows should be documented in `docs/workflows.md`.
- Stored binary formats should be documented in `docs/formats.md`.

## Verification

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

Run every example listed in `README.md`.
Review `docs/testing.md` and confirm the workflow coverage matrix still
matches the test suite.

## Security Notes

- Review `AUDIT.md` for newly used libsodium symbols.
- Review `SECURITY.md` for the current private reporting channel.
- Review `docs/maintenance.md` for version tracking expectations.
- Review `licenses/libsodium/` against the libsodium version or binary being
  redistributed.
- Confirm file decryption tests still cover authentication failure without
  replacing existing output.

## Format Compatibility

- Confirm stored formats still match `docs/formats.md`.
- If a format changed, add or update magic/version handling.
- Add migration notes and tests for old payloads when practical.
- Mention compatibility impact in `CHANGELOG.md`.

## Publishing

- Confirm CI is green on the release commit.
- Tag the release after verification.
- Publish to Nimble only from a clean working tree.
- After publication, install in a temporary project and run the quickstart.
- Confirm the published package includes documentation and license notices.
