import ./aead
import ./auth
import ./base64
import ./hash
import ./kdf
import ./secretbox
import ./secretstream

proc aeadKeyToBase64*(key: AeadKey): string =
  ## Encodes an AEAD key as URL-safe base64 without padding.
  rawBytes(key).toBase64()

proc aeadKeyFromBase64*(encoded: string): AeadKey =
  ## Decodes an AEAD key from URL-safe base64 without padding.
  aeadKeyFromBytes(fromBase64(encoded))

proc secretBoxKeyToBase64*(key: SecretBoxKey): string =
  ## Encodes a secretbox key as URL-safe base64 without padding.
  rawBytes(key).toBase64()

proc secretBoxKeyFromBase64*(encoded: string): SecretBoxKey =
  ## Decodes a secretbox key from URL-safe base64 without padding.
  secretBoxKeyFromBytes(fromBase64(encoded))

proc authKeyToBase64*(key: AuthKey): string =
  ## Encodes an authentication key as URL-safe base64 without padding.
  rawBytes(key).toBase64()

proc authKeyFromBase64*(encoded: string): AuthKey =
  ## Decodes an authentication key from URL-safe base64 without padding.
  authKeyFromBytes(fromBase64(encoded))

proc kdfKeyToBase64*(key: KdfKey): string =
  ## Encodes a KDF master key as URL-safe base64 without padding.
  rawBytes(key).toBase64()

proc kdfKeyFromBase64*(encoded: string): KdfKey =
  ## Decodes a KDF master key from URL-safe base64 without padding.
  kdfKeyFromBytes(fromBase64(encoded))

proc streamKeyToBase64*(key: StreamKey): string =
  ## Encodes a stream/file encryption key as URL-safe base64 without padding.
  rawBytes(key).toBase64()

proc streamKeyFromBase64*(encoded: string): StreamKey =
  ## Decodes a stream/file encryption key from URL-safe base64 without padding.
  streamKeyFromBytes(fromBase64(encoded))

proc keyedHashKeyToBase64*(key: KeyedHashKey): string =
  ## Encodes a keyed-hash key as URL-safe base64 without padding.
  rawBytes(key).toBase64()

proc keyedHashKeyFromBase64*(encoded: string): KeyedHashKey =
  ## Decodes a keyed-hash key from URL-safe base64 without padding.
  keyedHashKeyFromBytes(fromBase64(encoded))
