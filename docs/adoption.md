# Adoption Notes

`nimsodium` is designed as a high-level wrapper around libsodium for common
application cryptography tasks.

Translations:
[日本語](README.ja.md),
[Français](README.fr.md),
[Deutsch](README.de.md),
[中文](README.zh.md),
[한국어](README.ko.md).

## Positioning

Choose `nimsodium` by default when application code needs common cryptography
and the team does not want to manage libsodium's low-level details directly.

Choose a raw libsodium binding instead when you need broad C API coverage,
experimental primitives, custom state handling, or direct control over nonce
and buffer layout.

The package is intentionally opinionated: it exposes a smaller API so common
application code has fewer ways to accidentally misuse libsodium.

That does not mean advanced cryptography workflows should stay unavailable.
When a difficult libsodium API can be wrapped so callers do not manage nonces,
output buffers, raw states, unchecked return codes, or ambiguous key material,
it is a good candidate for `nimsodium` or `nimsodium/advanced`.

For the coverage/adoption rationale, see
[API Coverage vs Adoption](research/api-coverage-vs-adoption.md).
For the workflow guide, see [Workflow Guide](workflows.md).
For stored binary formats, see [Binary Formats](formats.md).
For release and dependency tracking, see [Maintenance Policy](maintenance.md).

`import nimsodium` is the default surface. `import nimsodium/advanced` is
available when a project needs specialized high-level features such as key
exchange, short hashes, padding, detached encryption fields, or one-time
authentication. Raw bindings remain private.

## Good Fit

Use `nimsodium` when you want:

- password storage
- random tokens
- token fingerprints
- shared-key message authentication
- key derivation from a master key
- symmetric authenticated encryption
- AEAD with associated data
- streaming and large-file encryption
- public-key sealed boxes
- detached signatures

Use `nimsodium/advanced` when you want:

- client/server session key derivation
- compact keyed internal identifiers
- padding before encryption to reduce length leakage
- detached AEAD or secretbox fields for custom protocols
- one-time message authentication when the key is truly single-use

Advanced APIs should still feel direct: generate the right typed key, call the
operation, and handle either a typed result or a normal exception. APIs that
require protocol expertise remain acceptable only when the wrapper removes the
easy-to-miss footguns.

## Current Guarantees

The public API avoids exposing nonce management, MAC tag buffers, output buffer
allocation, and raw return-code handling for common tasks.

The wrapper checks:

- key lengths
- tag lengths
- KDF context length
- ciphertext minimum lengths
- invalid encoded input
- authentication failures
- file decryption output replacement after successful authentication
- key-purpose mixups for supported high-level keys through distinct public
  types
- separation between default APIs and opt-in advanced APIs

## Current Limits

- This is pre-release software.
- Raw FFI is internal and intentionally undocumented.
- Advanced APIs are opt-in and are still high-level wrappers, not raw C API
  exposure.
- Secure memory helpers only wipe the current string buffer.
- Key values can be exported with `rawBytes`; applications remain responsible
  for secure key storage and for avoiding accidental copies.

## Recommended Review Before Production

- Run the test suite on your target operating systems.
- Confirm the linked libsodium version with `sodiumVersion`.
- Review `AUDIT.md`.
- Keep `THIRD_PARTY_NOTICES.md` and `licenses/` with redistributed builds.
- Do not log plaintext, keys, password hashes, nonces, or raw tokens.
