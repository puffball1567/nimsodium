import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium

proc toHex*(data: string): string =
  ## Encodes binary data as lowercase hexadecimal.
  init.ensureInitialized()

  result = newString(data.len * 2)
  if data.len == 0:
    return

  let hexLen = result.len + 1
  var outBuf = newString(hexLen)
  discard sodium.Sodium.sodium_bin2hex(
    cstring(outBuf),
    csize_t(hexLen),
    bytes.unsafeCString(data),
    csize_t(data.len)
  )
  result = outBuf[0 ..< result.len]

proc fromHex*(hex: string): string =
  ## Decodes hexadecimal input.
  ##
  ## Raises InvalidInputError if the input contains invalid characters or does
  ## not consume exactly the full input.
  init.ensureInitialized()

  if hex.len mod 2 != 0:
    raise newException(InvalidInputError, "hex input must have an even length")

  result = newString(hex.len div 2)
  if hex.len == 0:
    return

  var decodedLen: csize_t
  let rc = sodium.Sodium.sodium_hex2bin(
    bytes.unsafeCString(result),
    csize_t(result.len),
    bytes.unsafeCString(hex),
    csize_t(hex.len),
    nil,
    cast[pointer](addr decodedLen),
    nil
  )

  if rc != 0 or decodedLen != csize_t(result.len):
    raise newException(InvalidInputError, "invalid hexadecimal input")
