import ./errors
import ./private/internal/[bytes, init, secure_bytes]
import ./private/raw/sodium

const
  OneTimeAuthBytes* = sodium.crypto_onetimeauth_BYTES
  OneTimeAuthKeyBytes* = sodium.crypto_onetimeauth_KEYBYTES

type
  OneTimeAuthKey* = object
    bytes: SecureBytes

proc rawBytes*(key: OneTimeAuthKey): string =
  ## Returns the raw bytes for storage by the application.
  secure_bytes.rawBytes(key.bytes)

proc keyBytes(key: OneTimeAuthKey): SecureBytes =
  if key.bytes.len != OneTimeAuthKeyBytes:
    raise newException(
      InvalidKeyError,
      "one-time authentication key must be " & $OneTimeAuthKeyBytes & " bytes"
    )
  key.bytes

proc oneTimeAuthKeyFromBytes*(key: string): OneTimeAuthKey =
  ## Wraps an existing one-time authentication key.
  if key.len != OneTimeAuthKeyBytes:
    raise newException(
      InvalidKeyError,
      "one-time authentication key must be " & $OneTimeAuthKeyBytes & " bytes"
    )
  OneTimeAuthKey(bytes: secureBytesFromBytes(key))

proc generateOneTimeAuthKey*(): OneTimeAuthKey =
  ## Returns a new key for exactly one one-time authentication use.
  ##
  ## Do not reuse this key for multiple messages. Prefer authenticate for
  ## normal reusable-key message authentication.
  init.ensureInitialized()

  result = OneTimeAuthKey(bytes: newSecureBytes(OneTimeAuthKeyBytes))
  sodium.Sodium.crypto_onetimeauth_keygen(secure_bytes.unsafeCString(result.bytes))
  result.bytes.protectReadOnly()

proc oneTimeAuthenticate*(message: string; key: OneTimeAuthKey): string =
  ## Computes a one-time authentication tag.
  init.ensureInitialized()

  result = newString(OneTimeAuthBytes)
  let rc = sodium.Sodium.crypto_onetimeauth(
    bytes.unsafeCString(result),
    bytes.unsafeCString(message),
    culonglong(message.len),
    secure_bytes.unsafeCString(key.keyBytes())
  )
  if rc != 0:
    raise newException(CryptoError, "one-time authentication failed")

proc verifyOneTimeAuthentication*(
  message, tag: string;
  key: OneTimeAuthKey
): bool =
  ## Verifies a one-time authentication tag.
  init.ensureInitialized()

  if tag.len != OneTimeAuthBytes:
    return false

  sodium.Sodium.crypto_onetimeauth_verify(
    bytes.unsafeCString(tag),
    bytes.unsafeCString(message),
    culonglong(message.len),
    secure_bytes.unsafeCString(key.keyBytes())
  ) == 0
