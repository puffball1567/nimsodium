import ./encoding
import ./errors
import ./private/internal/[bytes, init, secure_bytes]
import ./private/raw/sodium

const
  ShortHashBytes* = sodium.crypto_shorthash_BYTES
  ShortHashKeyBytes* = sodium.crypto_shorthash_KEYBYTES

type
  ShortHashKey* = object
    bytes: SecureBytes

proc rawBytes*(key: ShortHashKey): string =
  ## Returns the raw bytes for storage by the application.
  secure_bytes.rawBytes(key.bytes)

proc keyBytes(key: ShortHashKey): SecureBytes =
  if key.bytes.len != ShortHashKeyBytes:
    raise newException(
      InvalidKeyError,
      "short hash key must be " & $ShortHashKeyBytes & " bytes"
    )
  key.bytes

proc shortHashKeyFromBytes*(key: string): ShortHashKey =
  ## Wraps an existing short-hash key.
  if key.len != ShortHashKeyBytes:
    raise newException(
      InvalidKeyError,
      "short hash key must be " & $ShortHashKeyBytes & " bytes"
    )
  ShortHashKey(bytes: secureBytesFromBytes(key))

proc generateShortHashKey*(): ShortHashKey =
  ## Returns a new key suitable for shortHash and shortHashHex.
  init.ensureInitialized()

  result = ShortHashKey(bytes: newSecureBytes(ShortHashKeyBytes))
  sodium.Sodium.crypto_shorthash_keygen(secure_bytes.unsafeCString(result.bytes))
  result.bytes.protectReadOnly()

proc shortHash*(data: string; key: ShortHashKey): string =
  ## Computes a keyed short hash.
  ##
  ## Use this for hash-table keys or compact internal fingerprints, not for
  ## general cryptographic message authentication. Use authenticate for MACs.
  init.ensureInitialized()

  result = newString(ShortHashBytes)
  let rc = sodium.Sodium.crypto_shorthash(
    bytes.unsafeCString(result),
    bytes.unsafeCString(data),
    culonglong(data.len),
    secure_bytes.unsafeCString(key.keyBytes())
  )
  if rc != 0:
    raise newException(CryptoError, "short hash failed")

proc shortHashHex*(data: string; key: ShortHashKey): string =
  ## Computes a keyed short hash and returns hexadecimal output.
  shortHash(data, key).toHex()
