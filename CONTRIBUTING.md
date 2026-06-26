# Contributing

Keep `nimsodium` small, high-level, and hard to misuse.

Translations: [日本語](docs/CONTRIBUTING.ja.md),
[Français](docs/CONTRIBUTING.fr.md), [Deutsch](docs/CONTRIBUTING.de.md),
[中文](docs/CONTRIBUTING.zh.md), [한국어](docs/CONTRIBUTING.ko.md).

Contributions are welcome, especially tests, documentation, examples,
platform verification, CI improvements, packaging fixes, and maintenance
updates. Security-sensitive API changes need maintainer review and a documented
rationale.

## Good First Contributions

- improve examples for existing workflows
- add tests for malformed input and failure paths
- verify installation on a specific OS or Nim version
- improve docs, translations, or release notes
- add known-answer tests from stable upstream references
- update maintenance notes for a new libsodium or Nim release

## Security-Sensitive Changes

Open an issue or design note before changing:

- public cryptographic API shape
- binary storage formats
- password encryption parameters
- nonce, salt, tag, or header handling
- key derivation contexts or typed key behavior
- raw FFI declarations
- authentication failure behavior
- file output replacement behavior

Do not submit a security-sensitive change as a drive-by refactor. Explain the
use case, the raw libsodium symbols involved, the expected failure modes, and
the tests that prove misuse resistance.

## Design Rules

- Do not invent cryptography.
- Do not expose the complete raw libsodium API as the main API.
- Do not make callers manage nonces, MAC tags, or output buffers for common tasks.
- Do not use generic hashing for password storage.
- Do not return plaintext when authentication fails.
- Do not expose string-based key parameters for new public high-level APIs.
  Use a distinct key type plus a checked `...FromBytes` constructor.
- Check every libsodium return code that can fail.
- Raise package-specific exceptions from `nimsodium/errors.nim`.
- Prefer safe workflow coverage over raw symbol coverage.

## Adding a Feature

1. Put the high-level API in a focused module under `src/nimsodium/`.
2. Keep dependencies narrow: `private/raw/sodium`, `private/internal/init`, `errors`, and small helpers.
3. Re-export the new module from `src/nimsodium.nim`.
4. Add tests for success, invalid input, and failure paths.
5. Add or update an example when the feature maps to an application workflow.
6. Update `AUDIT.md` when a new libsodium symbol is used.
7. Update `docs/workflows.md` when the feature adds a user-facing workflow.
8. Update `docs/formats.md` if a stored format is added or changed.
9. Update `docs/testing.md` when the workflow coverage matrix changes.
10. Update `CHANGELOG.md` for user-visible changes.

Raw bindings are implementation details. Expose only safe high-level APIs from
`nimsodium`.

FFI is not automatically trusted. Before using a raw symbol in a public wrapper,
compare it with `sodium.h`, especially pointer, output length, state, and
key-generation parameters.

File or stream APIs must avoid replacing caller-visible output until
authentication has succeeded. Use temporary output and cleanup tests for
failure paths.

## Stored Formats

Stored encrypted payloads and file formats are compatibility commitments.

Before changing one:

1. Add or increment a magic/version marker.
2. Keep old parsing behavior when practical.
3. Add compatibility tests.
4. Update `docs/formats.md`.
5. Mention migration or compatibility impact in `CHANGELOG.md`.

## Running Tests

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
```

Before a release, also generate docs:

```sh
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```
