import ./errors
import ./private/internal/[bytes, init, secure_bytes]
import ./private/raw/sodium
import ./random

const
  AeadKeyBytes* = sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
  AeadNonceBytes* = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  AeadMacBytes* = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

type
  AeadKey* = object
    bytes: SecureBytes

proc rawBytes*(key: AeadKey): string =
  ## Returns the raw bytes for storage by the application.
  secure_bytes.rawBytes(key.bytes)

proc keyBytes(key: AeadKey): SecureBytes =
  if key.bytes.len != AeadKeyBytes:
    raise newException(
      InvalidKeyError,
      "AEAD key must be " & $AeadKeyBytes & " bytes"
    )
  key.bytes

proc aeadKeyFromBytes*(key: string): AeadKey =
  ## Wraps an existing AEAD key.
  if key.len != AeadKeyBytes:
    raise newException(
      InvalidKeyError,
      "AEAD key must be " & $AeadKeyBytes & " bytes"
    )
  AeadKey(bytes: secureBytesFromBytes(key))

proc generateAeadKey*(): AeadKey =
  ## Returns a new key suitable for encryptAead and decryptAead.
  AeadKey(bytes: randomSecureBytes(AeadKeyBytes))

proc encryptAead(plaintext, key: string; associatedData = ""): string =
  ## Encrypts and authenticates data with XChaCha20-Poly1305-IETF.
  ##
  ## A nonce is generated automatically and stored with the ciphertext.
  ## Associated data is authenticated but not encrypted or stored.
  init.ensureInitialized()

  if key.len != AeadKeyBytes:
    raise newException(
      InvalidKeyError,
      "AEAD key must be " & $AeadKeyBytes & " bytes"
    )

  let nonce = randomBytes(AeadNonceBytes)
  var sealed = newString(plaintext.len + AeadMacBytes)
  var sealedLen: culonglong

  let rc = sodium.Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    bytes.unsafeCString(sealed),
    cast[pointer](addr sealedLen),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(associatedData),
    culonglong(associatedData.len),
    nil,
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(key)
  )
  if rc != 0 or sealedLen != culonglong(sealed.len):
    raise newException(CryptoError, "AEAD encryption failed")

  nonce & sealed

proc encryptAead*(plaintext: string; key: AeadKey; associatedData = ""): string =
  ## Encrypts and authenticates data using a typed AEAD key.
  let keyData = key.keyBytes()
  init.ensureInitialized()

  let nonce = randomBytes(AeadNonceBytes)
  var sealed = newString(plaintext.len + AeadMacBytes)
  var sealedLen: culonglong

  let rc = sodium.Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    bytes.unsafeCString(sealed),
    cast[pointer](addr sealedLen),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(associatedData),
    culonglong(associatedData.len),
    nil,
    bytes.unsafeCString(nonce),
    secure_bytes.unsafeCString(keyData)
  )
  if rc != 0 or sealedLen != culonglong(sealed.len):
    raise newException(CryptoError, "AEAD encryption failed")

  nonce & sealed

proc decryptAead(ciphertext, key: string; associatedData = ""): string =
  ## Decrypts and verifies data produced by encryptAead.
  ##
  ## Raises CryptoError on authentication failure. Associated data must match
  ## the value used for encryption.
  init.ensureInitialized()

  if key.len != AeadKeyBytes:
    raise newException(
      InvalidKeyError,
      "AEAD key must be " & $AeadKeyBytes & " bytes"
    )
  if ciphertext.len < AeadNonceBytes + AeadMacBytes:
    raise newException(InvalidInputError, "AEAD ciphertext is too short")

  let nonce = ciphertext[0 ..< AeadNonceBytes]
  let sealed = ciphertext[AeadNonceBytes .. ^1]
  result = newString(sealed.len - AeadMacBytes)
  var plaintextLen: culonglong

  let rc = sodium.Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    bytes.unsafeCString(result),
    cast[pointer](addr plaintextLen),
    nil,
    bytes.unsafeCString(sealed),
    culonglong(sealed.len),
    bytes.unsafeCString(associatedData),
    culonglong(associatedData.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(key)
  )
  if rc != 0 or plaintextLen != culonglong(result.len):
    raise newException(CryptoError, "AEAD authentication failed")

proc decryptAead*(ciphertext: string; key: AeadKey; associatedData = ""): string =
  ## Decrypts and verifies data using a typed AEAD key.
  let keyData = key.keyBytes()
  init.ensureInitialized()

  if ciphertext.len < AeadNonceBytes + AeadMacBytes:
    raise newException(InvalidInputError, "AEAD ciphertext is too short")

  let nonce = ciphertext[0 ..< AeadNonceBytes]
  let sealed = ciphertext[AeadNonceBytes .. ^1]
  result = newString(sealed.len - AeadMacBytes)
  var plaintextLen: culonglong

  let rc = sodium.Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    bytes.unsafeCString(result),
    cast[pointer](addr plaintextLen),
    nil,
    bytes.unsafeCString(sealed),
    culonglong(sealed.len),
    bytes.unsafeCString(associatedData),
    culonglong(associatedData.len),
    bytes.unsafeCString(nonce),
    secure_bytes.unsafeCString(keyData)
  )
  if rc != 0 or plaintextLen != culonglong(result.len):
    raise newException(CryptoError, "AEAD authentication failed")
