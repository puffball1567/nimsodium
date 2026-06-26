import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random

const
  SecretBoxKeyBytes* = sodium.crypto_secretbox_KEYBYTES
  SecretBoxNonceBytes* = sodium.crypto_secretbox_NONCEBYTES
  SecretBoxMacBytes* = sodium.crypto_secretbox_MACBYTES

type
  SecretBoxKey* = distinct string

proc rawBytes*(key: SecretBoxKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc secretBoxKeyFromBytes*(key: string): SecretBoxKey =
  ## Wraps an existing secretbox key.
  if key.len != SecretBoxKeyBytes:
    raise newException(
      InvalidKeyError,
      "secretbox key must be " & $SecretBoxKeyBytes & " bytes"
    )
  SecretBoxKey(key)

proc generateSecretBoxKey*(): SecretBoxKey =
  ## Returns a new secretbox key.
  SecretBoxKey(randomBytes(SecretBoxKeyBytes))

proc encryptSecretBox(plaintext, key: string): string =
  ## Encrypts and authenticates data.
  ##
  ## A nonce is generated automatically and stored with the ciphertext.
  ## Do not design APIs that reuse nonces with the same key.
  init.ensureInitialized()

  if key.len != SecretBoxKeyBytes:
    raise newException(
      InvalidKeyError,
      "secretbox key must be " & $SecretBoxKeyBytes & " bytes"
    )

  let nonce = randomBytes(SecretBoxNonceBytes)
  var sealed = newString(SecretBoxMacBytes + plaintext.len)
  let rc = sodium.Sodium.crypto_secretbox_easy(
    bytes.unsafeCString(sealed),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(key)
  )
  if rc != 0:
    raise newException(CryptoError, "secretbox encryption failed")

  nonce & sealed

proc encryptSecretBox*(plaintext: string; key: SecretBoxKey): string =
  ## Encrypts and authenticates data using a typed secretbox key.
  encryptSecretBox(plaintext, string(key))

proc decryptSecretBox(ciphertext, key: string): string =
  ## Decrypts and verifies data produced by encryptSecretBox.
  ##
  ## Raises CryptoError on authentication failure. It never returns plaintext
  ## from unauthenticated input.
  init.ensureInitialized()

  if key.len != SecretBoxKeyBytes:
    raise newException(
      InvalidKeyError,
      "secretbox key must be " & $SecretBoxKeyBytes & " bytes"
    )
  if ciphertext.len < SecretBoxNonceBytes + SecretBoxMacBytes:
    raise newException(InvalidInputError, "secretbox ciphertext is too short")

  let nonce = ciphertext[0 ..< SecretBoxNonceBytes]
  let sealed = ciphertext[SecretBoxNonceBytes .. ^1]
  result = newString(sealed.len - SecretBoxMacBytes)

  let rc = sodium.Sodium.crypto_secretbox_open_easy(
    bytes.unsafeCString(result),
    bytes.unsafeCString(sealed),
    culonglong(sealed.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(key)
  )
  if rc != 0:
    raise newException(CryptoError, "secretbox authentication failed")

proc decryptSecretBox*(ciphertext: string; key: SecretBoxKey): string =
  ## Decrypts and verifies data using a typed secretbox key.
  decryptSecretBox(ciphertext, string(key))
