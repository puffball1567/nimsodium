import ../../errors
import ../raw/sodium

proc ensureInitialized*() =
  if sodium.Sodium.sodium_init() < 0:
    raise newException(SodiumInitError, "libsodium initialization failed")
