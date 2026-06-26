# nimsodium design notes

## Goal

`nimsodium` is a proposed Nim package that provides a small, safe-by-default
high-level wrapper around libsodium.

The purpose is not to expose every libsodium function. The purpose is to give
Nim users a clear, tested, hard-to-misuse entry point for common cryptographic
tasks.

## Positioning

Existing Nim libsodium wrappers exist. This package should only be worth making
if it improves the developer experience:

- Nim 2.x focused
- high-level public API
- opt-in advanced high-level API for specialized but still safe workflows
- internal raw FFI isolated under `private/raw/`
- misuse-resistant defaults
- clear API documentation
- known-answer tests and integration tests
- practical examples for common application needs

## Non-Goals

- Do not invent cryptography.
- Do not expose the full raw libsodium API as the main API.
- Do not let advanced APIs become raw C bindings.
- Do not make users choose low-level nonce/tag/buffer details for common tasks.
- Do not use SHA-style hashing for password storage.
- Do not silently return invalid plaintext on verification failure.

## Expansion Rule

Advanced or low-level libsodium features may be exposed when the wrapper can
make them straightforward and hard to misuse. The public Nim API should remove
or validate difficult choices such as nonce generation, output allocation, raw
state management, tag sizes, key lengths, and return-code checks.

If a feature still requires callers to manually manage protocol-critical
details, keep it private or place a safer workflow-oriented wrapper in
`nimsodium/advanced` instead of exposing the raw symbol.

## Proposed Layout

```text
src/
  nimsodium.nim

  nimsodium/
    errors.nim
    random.nim
    hash.nim
    auth.nim
    kdf.nim
    password.nim
    aead.nim
    secretstream.nim
    sealedbox.nim
    signatures.nim
    secretbox.nim
    compare.nim
    memory.nim
    encoding.nim
    base64.nim
    version.nim
    advanced.nim
    advanced_keyexchange.nim
    advanced_shorthash.nim
    advanced_padding.nim

    private/
      internal/
        init.nim
        bytes.nim

      raw/
        sodium.nim        # internal libsodium FFI
```

## Public API v0.1

```nim
randomBytes(length: int): string
randomHex(length: int): string
randomBase64(length: int): string
randomInt(upperBound: int): int

genericHash(data: string; length = GenericHashBytes): string
genericHashHex(data: string; length = GenericHashBytes): string
type KeyedHashKey = distinct string
keyedHash(data: string; key: KeyedHashKey; length = GenericHashBytes): string
keyedHashHex(data: string; key: KeyedHashKey; length = GenericHashBytes): string
generateKeyedHashKey(): KeyedHashKey

type AuthKey = distinct string
generateAuthKey(): AuthKey
authenticate(message: string; key: AuthKey): string
verifyAuthentication(message, tag: string; key: AuthKey): bool

type KdfKey = distinct string
generateKdfKey(): KdfKey
deriveKey(masterKey: KdfKey; context: string; subkeyId: uint64; length: int): string
deriveAeadKey(masterKey: KdfKey; context: string; subkeyId: uint64): AeadKey
deriveSecretBoxKey(masterKey: KdfKey; context: string; subkeyId: uint64): SecretBoxKey
deriveAuthKey(masterKey: KdfKey; context: string; subkeyId: uint64): AuthKey
deriveKeyedHashKey(masterKey: KdfKey; context: string; subkeyId: uint64): KeyedHashKey
deriveStreamKey(masterKey: KdfKey; context: string; subkeyId: uint64): StreamKey

hashPassword(password: string): string
verifyPassword(hash, password: string): bool
needsRehashPassword(hash: string): bool
encryptWithPassword(plaintext, password: string; associatedData = ""; profile = pepInteractive): string
decryptWithPassword(encrypted, password: string; associatedData = ""): string
encryptFileWithPassword(inputPath, outputPath, password: string; associatedData = ""; profile = pepInteractive; chunkSize = DefaultStreamChunkBytes)
decryptFileWithPassword(inputPath, outputPath, password: string; associatedData = ""; chunkSize = DefaultStreamChunkBytes)

type AeadKey = distinct string
generateAeadKey(): AeadKey
encryptAead(plaintext: string; key: AeadKey; associatedData = ""): string
decryptAead(ciphertext: string; key: AeadKey; associatedData = ""): string

type StreamKey = distinct string
generateStreamKey(): StreamKey
encryptFile(inputPath, outputPath: string; key: StreamKey; associatedData = ""; chunkSize = DefaultStreamChunkBytes)
decryptFile(inputPath, outputPath: string; key: StreamKey; associatedData = ""; chunkSize = DefaultStreamChunkBytes)

type BoxSeed = distinct string
generateBoxSeed(): BoxSeed
generateBoxKeyPair(): BoxKeyPair
generateBoxKeyPair(seed: BoxSeed): BoxKeyPair
sealBox(plaintext: string; publicKey: BoxPublicKey): string
openBox(ciphertext: string; publicKey: BoxPublicKey; secretKey: BoxSecretKey): string
encryptBox(plaintext: string; recipientPublicKey: BoxPublicKey; senderSecretKey: BoxSecretKey): string
decryptBox(ciphertext: string; senderPublicKey: BoxPublicKey; recipientSecretKey: BoxSecretKey): string

type SigningSeed = distinct string
generateSigningSeed(): SigningSeed
generateSigningKeyPair(): SigningKeyPair
generateSigningKeyPair(seed: SigningSeed): SigningKeyPair
sign(message: string; secretKey: SigningSecretKey): string
openSigned(signedMessage: string; publicKey: SigningPublicKey): string
signDetached(message: string; secretKey: SigningSecretKey): string
verifyDetached(message, signature: string; publicKey: SigningPublicKey): bool
signFileDetached(path: string; secretKey: SigningSecretKey): string
verifyFileDetached(path, signature: string; publicKey: SigningPublicKey): bool

type SecretBoxKey = distinct string
generateSecretBoxKey(): SecretBoxKey
encryptSecretBox(plaintext: string; key: SecretBoxKey): string
decryptSecretBox(ciphertext: string; key: SecretBoxKey): string

constantTimeEquals(a, b: string): bool

sha256File(path: string): string
sha256FileHex(path: string): string
sha512File(path: string): string
sha512FileHex(path: string): string

generateToken(length = 32): string
fingerprintToken(token: string; key: KeyedHashKey): TokenFingerprint
verifyTokenFingerprint(token: string; fingerprint: TokenFingerprint; key: KeyedHashKey): bool

secureZero(data: var string)
secureClear(data: var string)

toHex(data: string): string
fromHex(hex: string): string

toBase64(data: string): string
fromBase64(encoded: string): string
randomBase64(length: int): string

sodiumVersion(): string
sodiumVersionMajor(): int
sodiumVersionMinor(): int
```

## Advanced API v0.1

`nimsodium/advanced` is opt-in. It is for specialized workflows that are still
wrapped as high-level Nim APIs.

```nim
type KeyExchangePublicKey = distinct string
type KeyExchangeSecretKey = distinct string
type KeyExchangeKeyPair = object
type ReceiveSessionKey = distinct string
type TransmitSessionKey = distinct string
type SessionKeys = object

generateKeyExchangeKeyPair(): KeyExchangeKeyPair
clientSessionKeys(clientPublicKey: KeyExchangePublicKey; clientSecretKey: KeyExchangeSecretKey; serverPublicKey: KeyExchangePublicKey): SessionKeys
serverSessionKeys(serverPublicKey: KeyExchangePublicKey; serverSecretKey: KeyExchangeSecretKey; clientPublicKey: KeyExchangePublicKey): SessionKeys

type ShortHashKey = distinct string
generateShortHashKey(): ShortHashKey
shortHash(data: string; key: ShortHashKey): string
shortHashHex(data: string; key: ShortHashKey): string

padMessage(message: string; blockSize: int): string
unpadMessage(padded: string; blockSize: int): string

type DetachedAeadCiphertext = object
type DetachedSecretBoxCiphertext = object
detachedAeadCiphertextFromParts(nonce, ciphertext, mac: string): DetachedAeadCiphertext
encryptAeadDetached(plaintext: string; key: AeadKey; associatedData = ""): DetachedAeadCiphertext
decryptAeadDetached(detached: DetachedAeadCiphertext; key: AeadKey; associatedData = ""): string
detachedSecretBoxCiphertextFromParts(nonce, ciphertext, mac: string): DetachedSecretBoxCiphertext
encryptSecretBoxDetached(plaintext: string; key: SecretBoxKey): DetachedSecretBoxCiphertext
decryptSecretBoxDetached(detached: DetachedSecretBoxCiphertext; key: SecretBoxKey): string

type OneTimeAuthKey = distinct string
generateOneTimeAuthKey(): OneTimeAuthKey
oneTimeAuthenticate(message: string; key: OneTimeAuthKey): string
verifyOneTimeAuthentication(message, tag: string; key: OneTimeAuthKey): bool
```

## Documentation Strategy

Use three layers:

1. README for short task-oriented guidance.
2. Public API doc comments for misuse warnings.
3. API design that removes dangerous choices where possible.

README should stay short and canonical:

```text
Password storage      -> hashPassword / verifyPassword
API token fingerprint -> keyedHashHex
Message auth tag      -> authenticate / verifyAuthentication
Key derivation        -> generateKdfKey / deriveKey
Secret data           -> encryptSecretBox / decryptSecretBox
Secret data + AD      -> encryptAead / decryptAead
File encryption       -> generateStreamKey / encryptFile / decryptFile
Public-key encryption -> generateBoxKeyPair / sealBox / openBox
Signatures            -> generateSigningKeyPair / signDetached / verifyDetached
Random tokens         -> randomBytes / randomHex / randomBase64
Random integers       -> randomInt
Comparison            -> constantTimeEquals
Advanced              -> import nimsodium/advanced
```

## API Comment Examples

```nim
proc hashPassword*(password: string): string
  ## Hashes a password using libsodium password hashing.
  ## Do not use genericHash or keyedHash for password storage.

proc encryptSecretBox*(plaintext: string; key: SecretBoxKey): string
  ## Encrypts and authenticates data.
  ## A nonce is generated automatically and stored with the ciphertext.
  ## Do not design APIs that reuse nonces with the same key.

proc constantTimeEquals*(a, b: string): bool
  ## Compares secrets without early exit.
  ## Use this for MACs, fingerprints, and tokens.
```

## Testing Plan

- known-answer tests from libsodium documentation where available
- roundtrip tests for encryption/decryption
- wrong-key and corrupted-ciphertext tests
- invalid length tests for keys and nonces
- password hash/verify success and failure tests
- constant-time compare behavior tests for equal and unequal lengths
- hex encode/decode roundtrip and invalid input tests
- integration test against system libsodium

## Safety Rules

- Always check libsodium return codes.
- Raise package-specific exceptions on failure.
- Do not return plaintext when authentication fails.
- Generate nonces automatically for high-level encryption.
- Write file decryption output only after authentication succeeds.
- Keep public keys and secret keys distinct at the type level where exposed.
- Keep raw bindings under `private/` and out of the main import path.
- Keep advanced APIs opt-in and high-level; do not re-export them from
  `src/nimsodium.nim`.
- Avoid logging raw secrets, keys, nonces, or plaintext.
- Prefer application-provided secret keys for keyed hashing and fingerprints.

## Relationship To FlowBrigade

FlowBrigade should not depend on this package.

If `nimsodium` exists, FlowBrigade can show an example using
`opaqueRateLimitKey`:

```nim
let key = opaqueRateLimitKey(
  ["email", email],
  proc(value: string): string = keyedHashHex(value, appSecret)
)
```

This should remain an example, not a core dependency.
