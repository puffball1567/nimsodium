import ./private/internal/[bytes, init]
import ./private/raw/sodium

proc constantTimeEquals*(a, b: string): bool =
  ## Compares secrets without early exit.
  ##
  ## Use this for MACs, fingerprints, and tokens.
  init.ensureInitialized()

  if a.len != b.len:
    return false
  if a.len == 0:
    return true

  sodium.Sodium.sodium_memcmp(
    bytes.unsafeAddr(a),
    bytes.unsafeAddr(b),
    csize_t(a.len)
  ) == 0
