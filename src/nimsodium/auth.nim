import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random

const
  AuthBytes* = sodium.crypto_auth_BYTES
  AuthKeyBytes* = sodium.crypto_auth_KEYBYTES

type
  AuthKey* = distinct string

proc rawBytes*(key: AuthKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc authKeyFromBytes*(key: string): AuthKey =
  ## Wraps an existing authentication key.
  if key.len != AuthKeyBytes:
    raise newException(
      InvalidKeyError,
      "authentication key must be " & $AuthKeyBytes & " bytes"
    )
  AuthKey(key)

proc generateAuthKey*(): AuthKey =
  ## Returns a new key suitable for authenticate and verifyAuthentication.
  AuthKey(randomBytes(AuthKeyBytes))

proc authenticate(message, key: string): string =
  ## Computes a message authentication tag.
  ##
  ## Use this when a shared secret key should authenticate a message without
  ## encrypting it.
  init.ensureInitialized()

  if key.len != AuthKeyBytes:
    raise newException(
      InvalidKeyError,
      "authentication key must be " & $AuthKeyBytes & " bytes"
    )

  result = newString(AuthBytes)
  let rc = sodium.Sodium.crypto_auth(
    bytes.unsafeCString(result),
    bytes.unsafeCString(message),
    culonglong(message.len),
    bytes.unsafeCString(key)
  )
  if rc != 0:
    raise newException(CryptoError, "message authentication failed")

proc authenticate*(message: string; key: AuthKey): string =
  ## Computes a message authentication tag using a typed key.
  authenticate(message, string(key))

proc verifyAuthentication(message, tag, key: string): bool =
  ## Verifies a message authentication tag.
  init.ensureInitialized()

  if key.len != AuthKeyBytes:
    raise newException(
      InvalidKeyError,
      "authentication key must be " & $AuthKeyBytes & " bytes"
    )
  if tag.len != AuthBytes:
    return false

  sodium.Sodium.crypto_auth_verify(
    bytes.unsafeCString(tag),
    bytes.unsafeCString(message),
    culonglong(message.len),
    bytes.unsafeCString(key)
  ) == 0

proc verifyAuthentication*(message, tag: string; key: AuthKey): bool =
  ## Verifies a message authentication tag using a typed key.
  verifyAuthentication(message, tag, string(key))
