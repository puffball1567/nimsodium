import ./encoding
import ./private/internal/init
import ./private/raw/sodium

proc randomBytes*(length: int): string =
  ## Returns cryptographically secure random bytes.
  init.ensureInitialized()

  if length < 0:
    raise newException(ValueError, "length must be non-negative")

  result = newString(length)
  if length > 0:
    sodium.Sodium.randombytes_buf(addr result[0], csize_t(length))

proc randomHex*(length: int): string =
  ## Returns cryptographically secure random bytes encoded as hexadecimal.
  ##
  ## The length is measured in bytes before encoding, so the returned string is
  ## twice as long.
  randomBytes(length).toHex()

proc randomInt*(upperBound: int): int =
  ## Returns a cryptographically secure random integer in 0 ..< upperBound.
  init.ensureInitialized()

  if upperBound <= 0:
    raise newException(ValueError, "upperBound must be positive")
  if upperBound > int(high(uint32)):
    raise newException(ValueError, "upperBound must fit in uint32")

  int(sodium.Sodium.randombytes_uniform(uint32(upperBound)))
