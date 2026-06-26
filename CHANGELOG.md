# Changelog

## 0.2.1 - Unreleased

- Make libsodium opaque state declarations incomplete structs instead of
  incorrectly sized value objects.
- Add selectable password hashing profiles while keeping the interactive
  profile as the default.
- Move high-level secret key storage to libsodium secure heap allocation with
  memory locking, read-only protection after initialization, and zeroing on
  free.
- Keep `rawBytes` as an explicit export operation. Default encryption,
  authentication, signing, and key-exchange paths no longer use it internally.

## 0.2.0 - 2026-06-27

- Add high-level password hashing and verification.
- Add password-derived encryption that wraps password KDF, salt handling, and
  AEAD encryption in one workflow.
- Add password-derived file encryption that wraps password KDF, salt handling,
  and secretstream file encryption in one workflow.
- Add random byte, hex, base64, and bounded integer helpers.
- Add generic hash and keyed hash helpers with validated output lengths.
- Add shared-key message authentication tags.
- Add KDF helpers with checked 8-byte contexts.
- Add typed KDF helpers for AEAD, secretbox, auth, keyed hash, and stream keys.
- Add typed key base64 import/export helpers for symmetric key material.
- Add secretbox encryption with automatic nonce handling.
- Add AEAD XChaCha20-Poly1305-IETF with associated data.
- Add secretstream file encryption with associated data.
- Add distinct public key types for high-level key material.
- Add opt-in advanced APIs for key exchange, short hashes, padding, detached
  encryption fields, and one-time authentication.
- Add public-key sealed boxes, authenticated public-key encryption, seeded box
  key-pair generation, and hex key helpers.
- Add Ed25519 attached and detached signatures, seeded signing key-pair
  generation, file signature helpers, and hex key helpers.
- Add SHA-256 and SHA-512 file checksum helpers.
- Add application token generation, fingerprinting, and verification helpers.
- Add constant-time comparison.
- Add hex and URL-safe base64 encoding.
- Add linked libsodium version helpers.
- Add secure zeroing helpers for current string buffers.
- Add audit notes, third-party notices, adoption notes, release checklist, and
  initial tests.
