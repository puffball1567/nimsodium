# nimsodium

`nimsodium` is a workflow-safe high-level libsodium wrapper for Nim applications.

Translations: [日本語](docs/README.ja.md), [Français](docs/README.fr.md),
[Deutsch](docs/README.de.md), [中文](docs/README.zh.md),
[한국어](docs/README.ko.md).

Use it when you want password hashing, token fingerprints, authenticated
encryption, file encryption, wallet-secret protection, public-key sealed boxes, or signatures without
managing nonces, MAC tags, output buffers, or raw return codes.

Use a raw libsodium binding instead when you need direct access to the full C
API. `nimsodium` is intentionally a high-level application API, not a complete
binding.

Need more than the default surface? `import nimsodium/advanced` exposes
additional high-level APIs for key exchange, short hashes, padding, detached
encryption fields, and one-time authentication while still keeping raw C
buffers and return codes private.

## Why nimsodium?

- Safer workflows: nonces are generated internally and stored with ciphertexts.
- Misuse-resistant API: secret key material uses distinct Nim types backed by
  libsodium secure heap allocation instead of plain strings at public call
  sites.
- Practical coverage: passwords, tokens, AEAD, file encryption, wallet-secret
  protection, public-key encryption, signatures, KDF, random values, encoding,
  and cleanup helpers.
- Clear layering: `import nimsodium` is the safe default; `import
  nimsodium/advanced` is available for specialized high-level workflows.
- libsodium underneath: cryptographic primitives are delegated to libsodium.
- OSS-ready surface: tests, examples, audit notes, security policy, and
  third-party notices are included.

## Install

System libsodium must be available to the C linker.

Ubuntu/Debian:

```sh
sudo apt-get install libsodium-dev
```

macOS:

```sh
brew install libsodium
```

Verify that the linker can find libsodium:

```sh
pkg-config --modversion libsodium
```

Then add `nimsodium` to your Nimble project:

```nim
requires "nimsodium >= 0.2.1"
```

For local development before publication:

```sh
nimble develop
```

## Status

This project is a `v0.2` pre-release. It is intended for evaluation and early
adoption, but API names and stored formats may still change before `v1.0`.
The high-level API is intentionally small and the raw libsodium FFI is treated
as an implementation detail.

## Quickstart

```nim
import nimsodium

let passwordHash = hashPassword("correct horse battery staple")
doAssert verifyPassword(passwordHash, "correct horse battery staple")

let key = generateAeadKey()
let ciphertext = encryptAead("secret payload", key, "record:42")
doAssert decryptAead(ciphertext, key, "record:42") == "secret payload"

let token = randomBase64(32)
let hashKey = generateKeyedHashKey()
let fingerprint = keyedHashHex(token, hashKey)
```

Run the same flow locally:

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
```

## Which API Should I Use?

```text
I need to...                         Use...
Store passwords                      hashPassword / verifyPassword
Generate API keys or raw tokens      randomBase64 / randomHex
Issue and verify app tokens          generateToken / fingerprintToken / verifyTokenFingerprint
Hash binary data with custom length  genericHash / genericHashHex
Hash files for checksums             sha256FileHex / sha512FileHex
Encrypt with a password              encryptWithPassword / decryptWithPassword
Encrypt files with a password        encryptFileWithPassword / decryptFileWithPassword
Protect wallet/application secrets   protectWalletSecret / openProtectedWalletSecret
Protect secret files                 encryptWalletSecretFile / decryptWalletSecretFile
Encrypt database fields              generateAeadKey / encryptAead / decryptAead
Encrypt small local secrets          generateSecretBoxKey / encryptSecretBox / decryptSecretBox
Encrypt large files                  generateStreamKey / encryptFile / decryptFile
Send encrypted data to a public key  generateBoxKeyPair / sealBox / openBox
Authenticate public-key sender       generateBoxKeyPair / encryptBox / decryptBox
Regenerate public-key pairs          generateBoxSeed / generateSigningSeed
Sign and verify messages             generateSigningKeyPair / sign / openSigned
Sign off-chain app messages          signOffchainMessage / verifyOffchainMessage
Sign and verify files                signFileDetached / verifyFileDetached
Handle detached signatures           signDetached / verifyDetached
Derive per-purpose keys              deriveAeadKey / deriveSecretBoxKey / deriveAuthKey
Store symmetric keys as text         aeadKeyToBase64 / aeadKeyFromBase64
Compare secret values                constantTimeEquals
Clear a current string buffer        secureZero / secureClear
Encode binary data                   toHex / fromHex / toBase64 / fromBase64
```

Workflow coverage:

```text
Workflow                              Status
Password storage                      default
Password-based message encryption     default
Password-based file encryption        default
Random tokens                         default
Server-side token fingerprints        default
Generic/keyed hashing                 default
Checksum file hashing                 default
Shared-key authentication             default
Secret-key encryption                 default
AEAD with associated data             default
Streaming/file encryption             default
Anonymous public-key encryption       default
Authenticated public-key encryption   default
Message signatures                    default
File signatures                       default
Purpose-specific key derivation       default
Typed key text import/export          default
Client/server key exchange            advanced
Padding for length hiding             advanced
Detached encryption fields            advanced
One-time authentication               advanced
```

Advanced APIs:

```text
I need to...                         Use...
Derive client/server session keys    nimsodium/advanced: generateKeyExchangeKeyPair / clientSessionKeys / serverSessionKeys
Compute compact keyed identifiers    nimsodium/advanced: generateShortHashKey / shortHashHex
Pad before encryption                nimsodium/advanced: padMessage / unpadMessage
Handle detached AEAD fields          nimsodium/advanced: encryptAeadDetached / decryptAeadDetached
Handle detached secretbox fields     nimsodium/advanced: encryptSecretBoxDetached / decryptSecretBoxDetached
One-time message authentication      nimsodium/advanced: generateOneTimeAuthKey / oneTimeAuthenticate / verifyOneTimeAuthentication
```

## More Examples

```nim
import nimsodium

let secretKey = generateSecretBoxKey()
let secretCiphertext = encryptSecretBox("secret payload", secretKey)
doAssert decryptSecretBox(secretCiphertext, secretKey) == "secret payload"

let authKey = generateAuthKey()
let tag = authenticate("message", authKey)
doAssert verifyAuthentication("message", tag, authKey)

let aeadKey = generateAeadKey()
let sealed = encryptAead("secret payload", aeadKey, "record:42")
doAssert decryptAead(sealed, aeadKey, "record:42") == "secret payload"

let recipient = generateBoxKeyPair()
let anonymousCiphertext = sealBox("hello", recipient.publicKey)
doAssert openBox(anonymousCiphertext, recipient.publicKey, recipient.secretKey) == "hello"

let sender = generateBoxKeyPair()
let authenticatedCiphertext = encryptBox("hello", recipient.publicKey, sender.secretKey)
doAssert decryptBox(authenticatedCiphertext, sender.publicKey, recipient.secretKey) == "hello"

let passwordCiphertext = encryptWithPassword("private note", "passphrase", "note:42")
doAssert decryptWithPassword(passwordCiphertext, "passphrase", "note:42") == "private note"

let appToken = generateToken()
let tokenKey = generateKeyedHashKey()
let storedTokenFingerprint = fingerprintTokenHex(appToken, tokenKey)
doAssert verifyTokenFingerprintHex(appToken, storedTokenFingerprint, tokenKey)

let signer = generateSigningKeyPair()
let signedMessage = sign("message", signer.secretKey)
doAssert openSigned(signedMessage, signer.publicKey) == "message"

let signature = signDetached("message", signer.secretKey)
doAssert verifyDetached("message", signature, signer.publicKey)

let streamKey = generateStreamKey()
encryptFile("plain.dat", "plain.dat.enc", streamKey, "backup:v1")
decryptFile("plain.dat.enc", "plain.dat.out", streamKey, "backup:v1")

let masterKey = generateKdfKey()
let derivedAeadKey = deriveAeadKey(masterKey, "AEADv001", 1'u64)
let tokenHashKey = deriveKeyedHashKey(masterKey, "TOKNv001", 1'u64)

let fileDigest = sha256FileHex("plain.dat")

var temporarySecret = rawBytes(generateSecretBoxKey())
secureClear(temporarySecret)
```

## Module Layout

```text
src/nimsodium.nim                 public aggregate import
src/nimsodium/errors.nim          package exception types
src/nimsodium/random.nim          random byte helpers
src/nimsodium/hash.nim            generic and keyed hashing
src/nimsodium/file_hash.nim       file checksum hashing
src/nimsodium/auth.nim            shared-key message authentication
src/nimsodium/kdf.nim             key derivation
src/nimsodium/key_formats.nim     typed key text import/export
src/nimsodium/password.nim        password hashing and verification
src/nimsodium/password_encryption.nim password-based message encryption
src/nimsodium/password_file_encryption.nim password-based file encryption
src/nimsodium/aead.nim            AEAD encryption with associated data
src/nimsodium/secretstream.nim    streaming/file encryption
src/nimsodium/sealedbox.nim       public-key sealed boxes
src/nimsodium/signatures.nim      detached signatures
src/nimsodium/secretbox.nim       authenticated secret-key encryption
src/nimsodium/compare.nim         constant-time comparison
src/nimsodium/encoding.nim        hex encoding
src/nimsodium/base64.nim          URL-safe base64 encoding
src/nimsodium/tokens.nim          application token workflow
src/nimsodium/wallets.nim         wallet/application secret protection workflows
src/nimsodium/version.nim         linked libsodium version helpers
src/nimsodium/memory.nim          current-buffer zeroing helpers
src/nimsodium/advanced.nim        opt-in advanced high-level API aggregate
src/nimsodium/private/raw/        internal libsodium FFI
src/nimsodium/private/internal/   shared private helpers
```

Feature modules should stay small and mostly independent. New public
functionality should usually live in a new module, use `private/raw/sodium`
through a narrow wrapper, then be re-exported from `src/nimsodium.nim`.

See `docs/README.md` for the documentation index.
See `AUDIT.md` for the current pre-release audit notes.
See `CONTRIBUTING.md` for contribution rules.
See `SECURITY.md` for private vulnerability reporting.

## Adoption Notes

`nimsodium` delegates cryptographic primitives to libsodium. The wrapper's job
is to keep common application code away from nonce reuse, tag handling, raw
output buffers, and unchecked return codes.

The current public API intentionally exposes only high-level operations. Raw
FFI is internal and should not be used by application code.

Current limitations:

- This is pre-release software.
- Raw FFI is intentionally undocumented and not a public API.
- Secure memory helpers only wipe the current string buffer. Nim or application
  code may have already made copies.
- Key values use distinct public types for supported high-level key material.
  Use `rawBytes` only when an application needs to persist or transmit a key.
- High-level secret key types use libsodium secure heap allocation with memory
  locking and read-only protection after initialization. `rawBytes` still
  creates a normal Nim string and should be used only for explicit key export.

Production checklist:

- Install and update libsodium through your operating system or trusted package
  manager.
- Check the linked runtime with `sodiumVersion()` in diagnostics or startup
  logs.
- Store keys outside source code and logs. When a key must be persisted, export
  it with `rawBytes` and protect it with your application's key-management
  mechanism.
- Treat associated data as part of the protocol. Decryption must use the exact
  same associated data used for encryption.
- Handle `CryptoError` as authentication failure, not as recoverable plaintext.
- Keep `THIRD_PARTY_NOTICES.md` and `licenses/` with redistributed builds so
  the libsodium license material remains visible.

API stability:

- `0.x` releases may still adjust names and types.
- The raw FFI under `src/nimsodium/private/raw/` is not supported API.
- High-level modules are the compatibility surface intended for users.
- `nimsodium/advanced` is opt-in and may grow with carefully reviewed
  high-level wrappers, but it should not become a raw binding.

## Examples

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_passwords examples/passwords.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_secret_data examples/secret_data.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_public_key examples/public_key.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_signatures examples/signatures.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_authentication examples/authentication.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_key_derivation examples/key_derivation.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_file_encryption examples/file_encryption.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_advanced examples/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_tokens examples/tokens.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_example_cleanup examples/cleanup.nim
```

## API Docs

```sh
nim doc --project --index:on --outdir:htmldocs --path:src src/nimsodium.nim
nim doc --outdir:htmldocs --path:src src/nimsodium/advanced.nim
```

## License

`nimsodium` is licensed under the MIT license.

This package links against libsodium. libsodium is distributed under the ISC
license, with additional notices for bundled components in its upstream
distribution. See `THIRD_PARTY_NOTICES.md` and `licenses/libsodium/`.

## Tests

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
```
