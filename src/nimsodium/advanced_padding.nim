import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium

proc padMessage*(message: string; blockSize: int): string =
  ## Pads a message to a multiple of blockSize using libsodium padding.
  ##
  ## Padding can reduce ciphertext length leakage when callers encrypt the
  ## padded message afterwards.
  init.ensureInitialized()

  if blockSize <= 0:
    raise newException(ValueError, "blockSize must be positive")

  var paddedLen: csize_t
  let maxLen = message.len + blockSize
  result = message & newString(blockSize)
  let rc = sodium.Sodium.sodium_pad(
    cast[pointer](addr paddedLen),
    bytes.unsafeCString(result),
    csize_t(message.len),
    csize_t(blockSize),
    csize_t(maxLen)
  )
  if rc != 0:
    raise newException(CryptoError, "message padding failed")
  result.setLen(int(paddedLen))

proc unpadMessage*(padded: string; blockSize: int): string =
  ## Removes padding produced by padMessage.
  init.ensureInitialized()

  if blockSize <= 0:
    raise newException(ValueError, "blockSize must be positive")

  var unpaddedLen: csize_t
  let rc = sodium.Sodium.sodium_unpad(
    cast[pointer](addr unpaddedLen),
    bytes.unsafeCString(padded),
    csize_t(padded.len),
    csize_t(blockSize)
  )
  if rc != 0:
    raise newException(InvalidInputError, "message padding is invalid")
  result = padded[0 ..< int(unpaddedLen)]
