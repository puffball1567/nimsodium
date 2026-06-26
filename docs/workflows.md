# Workflow Guide

`nimsodium` optimizes for safe cryptographic workflow coverage, not raw
libsodium symbol coverage.

Use `import nimsodium` first. Use `import nimsodium/advanced` only when the
workflow is explicitly listed as advanced.

## Default Workflows

| Need | Use |
| --- | --- |
| Store passwords | `hashPassword`, `verifyPassword`, `needsRehashPassword` |
| Encrypt a message with a password | `encryptWithPassword`, `decryptWithPassword` |
| Encrypt a file with a password | `encryptFileWithPassword`, `decryptFileWithPassword` |
| Generate app tokens | `generateToken` |
| Store token fingerprints | `fingerprintTokenHex`, `verifyTokenFingerprintHex` |
| Generate random bytes or text | `randomBytes`, `randomHex`, `randomBase64` |
| Hash data for identifiers | `genericHash`, `genericHashHex` |
| Hash files for checksums | `sha256FileHex`, `sha512FileHex` |
| Authenticate messages with a shared key | `authenticate`, `verifyAuthentication` |
| Encrypt with a shared secret key | `encryptSecretBox`, `decryptSecretBox` |
| Encrypt with associated data | `encryptAead`, `decryptAead` |
| Encrypt large files with a key | `encryptFile`, `decryptFile` |
| Encrypt anonymously to a public key | `sealBox`, `openBox` |
| Encrypt with sender authentication | `encryptBox`, `decryptBox` |
| Sign messages | `sign`, `openSigned` |
| Use detached signatures | `signDetached`, `verifyDetached` |
| Sign files | `signFileDetached`, `verifyFileDetached` |
| Derive purpose-specific keys | `deriveAeadKey`, `deriveSecretBoxKey`, `deriveAuthKey`, `deriveKeyedHashKey`, `deriveStreamKey` |
| Store symmetric keys as text | `...KeyToBase64`, `...KeyFromBase64` |
| Compare secret values | `constantTimeEquals` |
| Clear the current string buffer | `secureZero`, `secureClear` |

## Advanced Workflows

| Need | Use |
| --- | --- |
| Client/server session keys | `nimsodium/advanced`: `generateKeyExchangeKeyPair`, `clientSessionKeys`, `serverSessionKeys` |
| Compact keyed internal identifiers | `nimsodium/advanced`: `generateShortHashKey`, `shortHash`, `shortHashHex` |
| Padding before encryption | `nimsodium/advanced`: `padMessage`, `unpadMessage` |
| Detached AEAD fields | `nimsodium/advanced`: `encryptAeadDetached`, `decryptAeadDetached` |
| Detached secretbox fields | `nimsodium/advanced`: `encryptSecretBoxDetached`, `decryptSecretBoxDetached` |
| One-time authentication | `nimsodium/advanced`: `generateOneTimeAuthKey`, `oneTimeAuthenticate`, `verifyOneTimeAuthentication` |

## Avoid

Do not use:

- `genericHash`, `sha256FileHex`, or `sha512FileHex` for password storage
- detached encryption fields unless a protocol requires separate nonce, MAC,
  and ciphertext fields
- one-time authentication with a reused key
- raw key bytes in logs, URLs, diagnostics, or source code
- `rawBytes` unless the application must persist or transmit key material
- `nimsodium/private/raw` from application code

## Default vs Advanced

Default APIs should be safe for common application code. They generate nonces,
validate lengths, wrap key material in typed values, and raise normal
exceptions for invalid input or authentication failure.

Advanced APIs are still high-level, but they expose workflows that require more
protocol knowledge. They are separated so new users do not have to choose among
specialized options.

## Versioned Stored Data

Use the format documentation before storing long-lived encrypted payloads:

- `docs/formats.md`

Formats with magic/version markers are designed to support migration. Formats
without markers should be treated as tied to the current `nimsodium` API
contract.
