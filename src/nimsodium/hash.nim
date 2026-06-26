import ./encoding
import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random

const
  GenericHashBytesMin* = sodium.crypto_generichash_BYTES_MIN
  GenericHashBytesMax* = sodium.crypto_generichash_BYTES_MAX
  GenericHashBytes* = sodium.crypto_generichash_BYTES
  GenericHashKeyBytesMin* = sodium.crypto_generichash_KEYBYTES_MIN
  GenericHashKeyBytesMax* = sodium.crypto_generichash_KEYBYTES_MAX
  GenericHashKeyBytes* = sodium.crypto_generichash_KEYBYTES

type
  KeyedHashKey* = distinct string

proc rawBytes*(key: KeyedHashKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc keyedHashKeyFromBytes*(key: string): KeyedHashKey =
  ## Wraps an existing keyed-hash key.
  if key.len != GenericHashKeyBytes:
    raise newException(
      InvalidKeyError,
      "keyedHash key must be " & $GenericHashKeyBytes & " bytes"
    )
  KeyedHashKey(key)

proc genericHash*(data: string; length = GenericHashBytes): string =
  ## Hashes data with libsodium's generic hash function.
  ##
  ## Do not use this for password storage. Use hashPassword instead.
  init.ensureInitialized()

  if length < GenericHashBytesMin or length > GenericHashBytesMax:
    raise newException(
      InvalidInputError,
      "generic hash length must be between " & $GenericHashBytesMin &
        " and " & $GenericHashBytesMax & " bytes"
    )

  result = newString(length)
  let rc = sodium.Sodium.crypto_generichash(
    bytes.unsafeCString(result),
    csize_t(result.len),
    bytes.unsafeCString(data),
    culonglong(data.len),
    nil,
    0
  )
  if rc != 0:
    raise newException(CryptoError, "generic hash failed")

proc genericHashHex*(data: string; length = GenericHashBytes): string =
  ## Hashes data and returns the digest encoded as hexadecimal.
  genericHash(data, length).toHex()

proc generateKeyedHashKey*(): KeyedHashKey =
  ## Returns a new key suitable for keyedHash and keyedHashHex.
  KeyedHashKey(randomBytes(GenericHashKeyBytes))

proc keyedHash(data, key: string; length = GenericHashBytes): string =
  ## Hashes data with an application-provided secret key.
  ##
  ## Prefer this for token fingerprints and keyed identifiers. Do not use this
  ## for password storage.
  init.ensureInitialized()

  if key.len != GenericHashKeyBytes:
    raise newException(
      InvalidKeyError,
      "keyedHash key must be " & $GenericHashKeyBytes & " bytes"
    )
  if length < GenericHashBytesMin or length > GenericHashBytesMax:
    raise newException(
      InvalidInputError,
      "keyed hash length must be between " & $GenericHashBytesMin &
        " and " & $GenericHashBytesMax & " bytes"
    )

  result = newString(length)
  let rc = sodium.Sodium.crypto_generichash(
    bytes.unsafeCString(result),
    csize_t(result.len),
    bytes.unsafeCString(data),
    culonglong(data.len),
    bytes.unsafeCString(key),
    csize_t(key.len)
  )
  if rc != 0:
    raise newException(CryptoError, "keyed hash failed")

proc keyedHash*(data: string; key: KeyedHashKey; length = GenericHashBytes): string =
  ## Hashes data with a typed secret key.
  keyedHash(data, string(key), length)

proc keyedHashHex(data, key: string; length = GenericHashBytes): string =
  ## Hashes data with a key and returns the digest encoded as hexadecimal.
  keyedHash(data, key, length).toHex()

proc keyedHashHex*(data: string; key: KeyedHashKey; length = GenericHashBytes): string =
  ## Hashes data with a typed key and returns the digest encoded as hexadecimal.
  keyedHashHex(data, string(key), length)
