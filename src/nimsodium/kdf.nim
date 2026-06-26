import ./aead
import ./auth
import ./errors
import ./hash
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./secretbox
import ./secretstream

const
  KdfKeyBytes* = sodium.crypto_kdf_KEYBYTES
  KdfContextBytes* = sodium.crypto_kdf_CONTEXTBYTES
  KdfBytesMin* = sodium.crypto_kdf_BYTES_MIN
  KdfBytesMax* = sodium.crypto_kdf_BYTES_MAX

type
  KdfKey* = distinct string

proc rawBytes*(key: KdfKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc kdfKeyFromBytes*(key: string): KdfKey =
  ## Wraps an existing KDF master key.
  if key.len != KdfKeyBytes:
    raise newException(
      InvalidKeyError,
      "KDF master key must be " & $KdfKeyBytes & " bytes"
    )
  KdfKey(key)

proc generateKdfKey*(): KdfKey =
  ## Returns a new master key suitable for deriveKey.
  init.ensureInitialized()

  var key = newString(KdfKeyBytes)
  sodium.Sodium.crypto_kdf_keygen(bytes.unsafeCString(key))
  result = KdfKey(key)

proc deriveKey(masterKey, context: string; subkeyId: uint64; length: int): string =
  ## Derives a subkey from a master key.
  ##
  ## Context must be exactly 8 bytes and should identify the key purpose, such
  ## as "AEADv001" or "TOKNhash". Use different contexts or subkey IDs for
  ## different application purposes.
  init.ensureInitialized()

  if masterKey.len != KdfKeyBytes:
    raise newException(
      InvalidKeyError,
      "KDF master key must be " & $KdfKeyBytes & " bytes"
    )
  if context.len != KdfContextBytes:
    raise newException(
      InvalidInputError,
      "KDF context must be exactly " & $KdfContextBytes & " bytes"
    )
  if length < KdfBytesMin or length > KdfBytesMax:
    raise newException(
      InvalidInputError,
      "KDF output length must be between " & $KdfBytesMin & " and " & $KdfBytesMax & " bytes"
    )

  result = newString(length)
  let rc = sodium.Sodium.crypto_kdf_derive_from_key(
    bytes.unsafeCString(result),
    csize_t(result.len),
    subkeyId,
    bytes.unsafeCString(context),
    bytes.unsafeCString(masterKey)
  )
  if rc != 0:
    raise newException(CryptoError, "key derivation failed")

proc deriveKey*(masterKey: KdfKey; context: string; subkeyId: uint64; length: int): string =
  ## Derives a subkey from a typed master key.
  deriveKey(string(masterKey), context, subkeyId, length)

proc deriveAeadKey*(masterKey: KdfKey; context: string; subkeyId: uint64): AeadKey =
  ## Derives a typed AEAD key from a KDF master key.
  aeadKeyFromBytes(deriveKey(masterKey, context, subkeyId, AeadKeyBytes))

proc deriveSecretBoxKey*(
    masterKey: KdfKey; context: string; subkeyId: uint64
): SecretBoxKey =
  ## Derives a typed secretbox key from a KDF master key.
  secretBoxKeyFromBytes(deriveKey(masterKey, context, subkeyId, SecretBoxKeyBytes))

proc deriveAuthKey*(masterKey: KdfKey; context: string; subkeyId: uint64): AuthKey =
  ## Derives a typed authentication key from a KDF master key.
  authKeyFromBytes(deriveKey(masterKey, context, subkeyId, AuthKeyBytes))

proc deriveKeyedHashKey*(
    masterKey: KdfKey; context: string; subkeyId: uint64
): KeyedHashKey =
  ## Derives a typed keyed-hash key from a KDF master key.
  keyedHashKeyFromBytes(deriveKey(masterKey, context, subkeyId, GenericHashKeyBytes))

proc deriveStreamKey*(masterKey: KdfKey; context: string; subkeyId: uint64): StreamKey =
  ## Derives a typed stream/file encryption key from a KDF master key.
  streamKeyFromBytes(deriveKey(masterKey, context, subkeyId, StreamKeyBytes))
