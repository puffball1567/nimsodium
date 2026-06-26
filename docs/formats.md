# Binary Formats

This document records the current `nimsodium` v0.2 binary formats.

These formats are part of the high-level workflow contract. They are not raw
libsodium formats unless explicitly stated.

## Stability Policy

Pre-1.0 releases may change formats, but any format that is meant to be stored
long term must include enough version information to support migration.

When changing a stored format:

- add a new magic/version marker
- keep the old parser when practical
- document the migration behavior
- add tests for both old and new formats
- treat silent reinterpretation as a bug

## AEAD Message Encryption

Produced by:

- `encryptAead`

Consumed by:

- `decryptAead`

Format:

```text
nonce || ciphertext_with_mac
```

Fields:

```text
nonce                AeadNonceBytes
ciphertext_with_mac  plaintext length + AeadMacBytes
```

Associated data is authenticated but not stored. The caller must provide the
same associated data during decryption.

## Secretbox Message Encryption

Produced by:

- `encryptSecretBox`

Consumed by:

- `decryptSecretBox`

Format:

```text
nonce || ciphertext_with_mac
```

Fields:

```text
nonce                SecretBoxNonceBytes
ciphertext_with_mac  plaintext length + SecretBoxMacBytes
```

## Authenticated Public-Key Encryption

Produced by:

- `encryptBox`

Consumed by:

- `decryptBox`

Format:

```text
nonce || ciphertext_with_mac
```

Fields:

```text
nonce                BoxNonceBytes
ciphertext_with_mac  plaintext length + BoxMacBytes
```

The sender is authenticated by verifying with the sender public key during
decryption.

## Sealed Public-Key Encryption

Produced by:

- `sealBox`

Consumed by:

- `openBox`

Format:

```text
libsodium sealed box ciphertext
```

This is libsodium's sealed-box format. The sender is anonymous.

## Password Message Encryption

Produced by:

- `encryptWithPassword`

Consumed by:

- `decryptWithPassword`

Format:

```text
"NSPW1" || profile || salt || aead_payload
```

Fields:

```text
magic         5 bytes: NSPW1
profile       1 byte
salt          PasswordEncryptionSaltBytes
aead_payload  encryptAead output: nonce || ciphertext_with_mac
```

Profile bytes:

```text
1  pepInteractive
2  pepModerate
3  pepSensitive
```

Associated data is authenticated by the AEAD payload but not stored.

## Secretstream File Encryption

Produced by:

- `encryptFile`

Consumed by:

- `decryptFile`

Format:

```text
secretstream_header || encrypted_chunks
```

The header and chunks are produced by libsodium secretstream
XChaCha20-Poly1305. Associated data is authenticated for each chunk but not
stored.

Output files are written through a temporary path and replace the target only
after success.

## Password File Encryption

Produced by:

- `encryptFileWithPassword`

Consumed by:

- `decryptFileWithPassword`

Format:

```text
"NSPF1" || profile || salt || secretstream_payload
```

Fields:

```text
magic                 5 bytes: NSPF1
profile               1 byte
salt                  PasswordEncryptionSaltBytes
secretstream_payload  encryptFile output
```

Profile bytes:

```text
1  pepInteractive
2  pepModerate
3  pepSensitive
```

Wrong passwords, wrong associated data, and modified ciphertext raise
`CryptoError` and must not replace an existing output file.

## Signatures

`sign` produces:

```text
signature || message
```

`signDetached` and `signFileDetached` produce raw Ed25519 detached signatures:

```text
signature
```

Detached signatures are `SignatureBytes` bytes.

## Token Fingerprints

`fingerprintToken` produces raw keyed generic-hash bytes.

`fingerprintTokenHex` produces lowercase hexadecimal text. Verification uses
constant-time comparison after decoding and recomputing the fingerprint.
