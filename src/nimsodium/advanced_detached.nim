import ./aead
import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random
import ./secretbox

type
  DetachedAeadCiphertext* = object
    nonce*: string
    ciphertext*: string
    mac*: string

  DetachedSecretBoxCiphertext* = object
    nonce*: string
    ciphertext*: string
    mac*: string

proc detachedAeadCiphertextFromParts*(
  nonce, ciphertext, mac: string
): DetachedAeadCiphertext =
  ## Wraps detached AEAD parts received from storage or a protocol.
  if nonce.len != AeadNonceBytes:
    raise newException(InvalidInputError, "AEAD nonce must be " & $AeadNonceBytes & " bytes")
  if mac.len != AeadMacBytes:
    raise newException(InvalidInputError, "AEAD MAC must be " & $AeadMacBytes & " bytes")
  DetachedAeadCiphertext(nonce: nonce, ciphertext: ciphertext, mac: mac)

proc encryptAeadDetached*(
  plaintext: string;
  key: AeadKey;
  associatedData = ""
): DetachedAeadCiphertext =
  ## Encrypts with AEAD and returns nonce, ciphertext, and MAC separately.
  ##
  ## Prefer encryptAead unless a protocol explicitly needs detached fields.
  init.ensureInitialized()

  let nonce = randomBytes(AeadNonceBytes)
  var ciphertext = newString(plaintext.len)
  var mac = newString(AeadMacBytes)
  var macLen: culonglong
  let rc = sodium.Sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
    bytes.unsafeCString(ciphertext),
    bytes.unsafeCString(mac),
    cast[pointer](addr macLen),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(associatedData),
    culonglong(associatedData.len),
    nil,
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(rawBytes(key))
  )
  if rc != 0 or macLen != culonglong(AeadMacBytes):
    raise newException(CryptoError, "detached AEAD encryption failed")

  DetachedAeadCiphertext(nonce: nonce, ciphertext: ciphertext, mac: mac)

proc decryptAeadDetached*(
  detached: DetachedAeadCiphertext;
  key: AeadKey;
  associatedData = ""
): string =
  ## Decrypts and verifies detached AEAD fields.
  init.ensureInitialized()

  if detached.nonce.len != AeadNonceBytes:
    raise newException(InvalidInputError, "AEAD nonce must be " & $AeadNonceBytes & " bytes")
  if detached.mac.len != AeadMacBytes:
    raise newException(InvalidInputError, "AEAD MAC must be " & $AeadMacBytes & " bytes")

  result = newString(detached.ciphertext.len)
  let rc = sodium.Sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
    bytes.unsafeCString(result),
    nil,
    bytes.unsafeCString(detached.ciphertext),
    culonglong(detached.ciphertext.len),
    bytes.unsafeCString(detached.mac),
    bytes.unsafeCString(associatedData),
    culonglong(associatedData.len),
    bytes.unsafeCString(detached.nonce),
    bytes.unsafeCString(rawBytes(key))
  )
  if rc != 0:
    raise newException(CryptoError, "detached AEAD authentication failed")

proc detachedSecretBoxCiphertextFromParts*(
  nonce, ciphertext, mac: string
): DetachedSecretBoxCiphertext =
  ## Wraps detached secretbox parts received from storage or a protocol.
  if nonce.len != SecretBoxNonceBytes:
    raise newException(InvalidInputError, "secretbox nonce must be " & $SecretBoxNonceBytes & " bytes")
  if mac.len != SecretBoxMacBytes:
    raise newException(InvalidInputError, "secretbox MAC must be " & $SecretBoxMacBytes & " bytes")
  DetachedSecretBoxCiphertext(nonce: nonce, ciphertext: ciphertext, mac: mac)

proc encryptSecretBoxDetached*(
  plaintext: string;
  key: SecretBoxKey
): DetachedSecretBoxCiphertext =
  ## Encrypts with secretbox and returns nonce, ciphertext, and MAC separately.
  ##
  ## Prefer encryptSecretBox unless a protocol explicitly needs detached fields.
  init.ensureInitialized()

  let nonce = randomBytes(SecretBoxNonceBytes)
  var ciphertext = newString(plaintext.len)
  var mac = newString(SecretBoxMacBytes)
  let rc = sodium.Sodium.crypto_secretbox_detached(
    bytes.unsafeCString(ciphertext),
    bytes.unsafeCString(mac),
    bytes.unsafeCString(plaintext),
    culonglong(plaintext.len),
    bytes.unsafeCString(nonce),
    bytes.unsafeCString(rawBytes(key))
  )
  if rc != 0:
    raise newException(CryptoError, "detached secretbox encryption failed")

  DetachedSecretBoxCiphertext(nonce: nonce, ciphertext: ciphertext, mac: mac)

proc decryptSecretBoxDetached*(
  detached: DetachedSecretBoxCiphertext;
  key: SecretBoxKey
): string =
  ## Decrypts and verifies detached secretbox fields.
  init.ensureInitialized()

  if detached.nonce.len != SecretBoxNonceBytes:
    raise newException(InvalidInputError, "secretbox nonce must be " & $SecretBoxNonceBytes & " bytes")
  if detached.mac.len != SecretBoxMacBytes:
    raise newException(InvalidInputError, "secretbox MAC must be " & $SecretBoxMacBytes & " bytes")

  result = newString(detached.ciphertext.len)
  let rc = sodium.Sodium.crypto_secretbox_open_detached(
    bytes.unsafeCString(result),
    bytes.unsafeCString(detached.ciphertext),
    bytes.unsafeCString(detached.mac),
    culonglong(detached.ciphertext.len),
    bytes.unsafeCString(detached.nonce),
    bytes.unsafeCString(rawBytes(key))
  )
  if rc != 0:
    raise newException(CryptoError, "detached secretbox authentication failed")
