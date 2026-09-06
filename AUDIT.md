# nimsodium Audit Notes

This file records the current pre-release audit status.

## Scope

Reviewed areas:

- public API shape
- high-level wrapper misuse resistance
- internal libsodium FFI used by v0.1
- binary string handling
- password hashing behavior
- password-derived encryption behavior
- password-derived file encryption behavior
- secretbox encryption/decryption behavior
- AEAD encryption/decryption behavior
- secretstream file encryption/decryption behavior
- sealed box public-key encryption behavior
- authenticated public-key encryption behavior
- detached and attached signature behavior
- file signature behavior
- key derivation behavior
- typed key derivation behavior
- typed key text import/export behavior
- application token workflow behavior
- file checksum hash behavior
- advanced key exchange behavior
- advanced short hash behavior
- advanced padding behavior
- advanced detached AEAD/secretbox behavior
- advanced one-time authentication behavior
- shared-key message authentication behavior
- random integer behavior
- URL-safe base64 encoding/decoding behavior
- current-buffer secret zeroing behavior
- distinct public key types for high-level key material
- package and OSS readiness

## Security Posture

`nimsodium` does not implement cryptographic primitives itself. It delegates to
libsodium and focuses on preventing common wrapper-level mistakes.

Current high-level behavior:

- secretbox nonces are generated automatically
- secretbox nonce is stored with ciphertext
- secretbox keys are length-checked
- secretbox authentication failure raises `CryptoError`
- AEAD uses XChaCha20-Poly1305-IETF with automatic nonce generation
- AEAD associated data is authenticated but not stored
- file encryption uses libsodium secretstream XChaCha20-Poly1305
- file encryption and decryption authenticate associated data but do not store
  it
- file output is written through a package-owned temporary path and replaces
  the requested output path only after the operation succeeds
- generated keys and key pairs use distinct public types for supported
  high-level APIs; `rawBytes` is required for persistence or transport
- sealed boxes use libsodium public-key sealed boxes for anonymous sender
  encryption
- sealed box and signing seed APIs validate exact seed lengths before
  deterministic key-pair derivation
- authenticated public-key encryption uses automatic nonces and verifies sender
  identity through typed sender public keys
- password-derived encryption stores format version, cost profile, salt, nonce,
  and ciphertext together; associated data is authenticated but not stored
- password-derived file encryption stores format version, cost profile, salt,
  and a secretstream payload together; output replacement only happens after
  successful encryption/decryption
- signatures use Ed25519 detached signatures and attached signed-message
  helpers
- file signatures read file contents and reuse the same detached signature
  verification rules without exposing streaming state
- attached signed-message verification rejects short or modified inputs
- KDF requires exact 8-byte contexts and checked output lengths
- typed KDF helpers derive purpose-specific public key types so callers do not
  manually wrap raw subkey bytes
- typed key text import/export decodes through URL-safe base64 and existing
  key-length validators
- token fingerprints use keyed generic hash and constant-time comparison
- advanced key exchange derives typed receive/transmit session keys for client
  and server roles
- advanced short hash uses typed keys and is documented for compact keyed
  identifiers, not general MAC replacement
- advanced padding validates block sizes and rejects invalid padding
- advanced detached encryption validates nonce/MAC part lengths and rejects
  modified ciphertext, modified MACs, wrong keys, and wrong associated data
- advanced one-time authentication uses typed keys and rejects wrong messages,
  wrong keys, and invalid tag lengths
- message authentication checks key and tag lengths
- randomInt rejects non-positive bounds and delegates uniform sampling to
  libsodium
- Base64 uses libsodium URL-safe no-padding encoding
- secureZero/secureClear call `sodium_memzero` on the current string buffer,
  but cannot wipe copies that already exist
- password storage uses `crypto_pwhash_str`
- generic/keyed hash APIs warn against password storage
- SHA-256/SHA-512 file helpers are documented for checksums and
  interoperability, not password storage
- keyed hash and secretbox provide key-generation helpers
- raw FFI is kept under `src/nimsodium/private/raw/`
- libsodium initialization is delegated to `sodium_init` on each operation,
  avoiding wrapper-level first-call races

## FFI Checked For v0.2.3

The current high-level API directly uses this libsodium surface:

```text
sodium_init
randombytes_buf
sodium_bin2hex
sodium_hex2bin
sodium_memcmp
crypto_generichash
crypto_hash_sha256
crypto_hash_sha512
crypto_pwhash_str
crypto_pwhash_str_verify
crypto_pwhash
crypto_secretbox_easy
crypto_secretbox_open_easy
crypto_secretbox_detached
crypto_secretbox_open_detached
crypto_aead_xchacha20poly1305_ietf_encrypt
crypto_aead_xchacha20poly1305_ietf_decrypt
crypto_aead_xchacha20poly1305_ietf_encrypt_detached
crypto_aead_xchacha20poly1305_ietf_decrypt_detached
crypto_secretstream_xchacha20poly1305_statebytes
crypto_secretstream_xchacha20poly1305_keygen
crypto_secretstream_xchacha20poly1305_init_push
crypto_secretstream_xchacha20poly1305_push
crypto_secretstream_xchacha20poly1305_init_pull
crypto_secretstream_xchacha20poly1305_pull
crypto_box_keypair
crypto_box_seed_keypair
crypto_box_easy
crypto_box_open_easy
crypto_box_seal
crypto_box_seal_open
crypto_sign_keypair
crypto_sign_seed_keypair
crypto_sign
crypto_sign_open
crypto_sign_detached
crypto_sign_verify_detached
crypto_sign_ed25519_sk_to_pk
crypto_sign_ed25519_sk_to_seed
crypto_kdf_keygen
crypto_kdf_derive_from_key
crypto_kx_keypair
crypto_kx_client_session_keys
crypto_kx_server_session_keys
crypto_shorthash_keygen
crypto_shorthash
crypto_onetimeauth_keygen
crypto_onetimeauth
crypto_onetimeauth_verify
sodium_pad
sodium_unpad
crypto_auth
crypto_auth_verify
randombytes_uniform
sodium_base64_encoded_len
sodium_bin2base64
sodium_base642bin
sodium_version_string
sodium_library_version_major
sodium_library_version_minor
sodium_memzero
```

The complete high-level workflow suite and experimental C ABI were compiled,
linked, and executed against a source build of libsodium 1.0.22 with Nim
2.2.10. The same suite remains tested against the distribution-provided
libsodium as a compatibility lane. No stored format changed in this update.

libsodium 1.0.22 adds new cryptographic families, including SHA-3 and
post-quantum key encapsulation. They are not exposed automatically: each new
public nimsodium workflow still requires a separate API and misuse-resistance
review.

## Known FFI Caveat

Some raw declarations need writable `cstring` parameters instead of the more
awkward generated shapes. Compatibility overloads are kept at the bottom of
`src/nimsodium/private/raw/sodium.nim` for:

```text
crypto_pwhash_str
crypto_pwhash_str_alg
crypto_pwhash_str_verify
crypto_pwhash_str_needs_rehash
crypto_kdf_keygen
crypto_kdf_derive_from_key
crypto_kx_keypair
crypto_kx_client_session_keys
crypto_kx_server_session_keys
crypto_shorthash_keygen
crypto_onetimeauth_keygen
crypto_secretstream_xchacha20poly1305_keygen
crypto_secretstream_xchacha20poly1305_init_push
crypto_secretstream_xchacha20poly1305_init_pull
crypto_secretstream_xchacha20poly1305_pull
```

Do not assume every raw symbol is ready for safe direct use. Before a new
high-level module calls a raw symbol, compare that symbol against `sodium.h`,
add wrapper tests, and check buffer lengths.

Additional FFI patterns to treat as suspicious before future use:

- keygen procs with `k: uint8` instead of a byte pointer/array
- state aliases represented as `cint`
- out-length parameters represented as plain `pointer`
- end-pointer parameters represented as `cstring`
- fixed arrays in C headers that need writable buffers in Nim

## Open Items Before Publishing

- Add more known-answer tests where libsodium publishes vectors or examples.
- Confirm final repository URL and issue tracker before publishing.
- Keep raw bindings out of public examples and compatibility promises.
- Audit future raw functions before exposing new high-level modules.

## Dependency License

`nimsodium` links against libsodium. libsodium is distributed under the ISC
license, with additional notices for bundled components in its upstream
distribution. Keep this dependency license visible in release documentation and
`THIRD_PARTY_NOTICES.md`.
