import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random

proc toBase64*(data: string): string =
  ## Encodes binary data as URL-safe base64 without padding.
  init.ensureInitialized()

  let maxLen = sodium.Sodium.sodium_base64_encoded_len(
    csize_t(data.len),
    sodium.sodium_base64_VARIANT_URLSAFE_NO_PADDING
  )
  var outBuf = newString(int(maxLen))
  discard sodium.Sodium.sodium_bin2base64(
    cstring(outBuf),
    maxLen,
    bytes.unsafeCString(data),
    csize_t(data.len),
    sodium.sodium_base64_VARIANT_URLSAFE_NO_PADDING
  )
  result = $cstring(outBuf)

proc fromBase64*(encoded: string): string =
  ## Decodes URL-safe base64 without padding.
  ##
  ## Raises InvalidInputError if the input is invalid.
  init.ensureInitialized()

  result = newString(encoded.len)
  if encoded.len == 0:
    return

  var decodedLen: csize_t
  let rc = sodium.Sodium.sodium_base642bin(
    bytes.unsafeCString(result),
    csize_t(result.len),
    bytes.unsafeCString(encoded),
    csize_t(encoded.len),
    nil,
    cast[pointer](addr decodedLen),
    nil,
    sodium.sodium_base64_VARIANT_URLSAFE_NO_PADDING
  )
  if rc != 0:
    raise newException(InvalidInputError, "invalid base64 input")

  result.setLen(int(decodedLen))

proc randomBase64*(length: int): string =
  ## Returns cryptographically secure random bytes encoded as URL-safe base64.
  ##
  ## The length is measured in bytes before encoding.
  randomBytes(length).toBase64()
