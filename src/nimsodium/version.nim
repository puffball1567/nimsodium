import ./private/internal/init
import ./private/raw/sodium

proc sodiumVersion*(): string =
  ## Returns the linked libsodium version string.
  init.ensureInitialized()
  $sodium.Sodium.sodium_version_string()

proc sodiumVersionMajor*(): int =
  ## Returns the linked libsodium major version.
  init.ensureInitialized()
  int(sodium.Sodium.sodium_library_version_major())

proc sodiumVersionMinor*(): int =
  ## Returns the linked libsodium minor version.
  init.ensureInitialized()
  int(sodium.Sodium.sodium_library_version_minor())
