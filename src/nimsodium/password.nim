import ./errors
import ./private/internal/init
import ./private/raw/sodium

type
  PasswordHashProfile* = enum
    ## Resource profile for password hashing.
    ##
    ## `phpInteractive` remains the default for login-style password checks.
    ## `phpModerate` and `phpSensitive` raise the libsodium work factors for
    ## deployments that can afford higher memory and CPU costs.
    phpInteractive
    phpModerate
    phpSensitive

proc limits(profile: PasswordHashProfile): tuple[ops: culonglong, mem: csize_t] =
  case profile
  of phpInteractive:
    (
      culonglong(sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE),
      csize_t(sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
    )
  of phpModerate:
    (
      culonglong(sodium.crypto_pwhash_OPSLIMIT_MODERATE),
      csize_t(sodium.crypto_pwhash_MEMLIMIT_MODERATE)
    )
  of phpSensitive:
    (
      culonglong(sodium.crypto_pwhash_OPSLIMIT_SENSITIVE),
      csize_t(sodium.crypto_pwhash_MEMLIMIT_SENSITIVE)
    )

proc hashPassword*(password: string; profile = phpInteractive): string =
  ## Hashes a password using libsodium password hashing.
  ##
  ## Do not use genericHash or keyedHash for password storage.
  init.ensureInitialized()

  let selected = limits(profile)
  var outBuf = newString(sodium.crypto_pwhash_STRBYTES)
  let rc = sodium.Sodium.crypto_pwhash_str(
    cstring(outBuf),
    cstring(password),
    culonglong(password.len),
    selected.ops,
    selected.mem
  )
  if rc != 0:
    raise newException(CryptoError, "password hashing failed")

  result = $cstring(outBuf)

proc verifyPassword*(hash, password: string): bool =
  ## Verifies a password against a hash created by hashPassword.
  init.ensureInitialized()

  if hash.len == 0 or hash.len >= sodium.crypto_pwhash_STRBYTES or hash.contains('\0'):
    return false

  sodium.Sodium.crypto_pwhash_str_verify(
    cstring(hash),
    cstring(password),
    culonglong(password.len)
  ) == 0

proc needsRehashPassword*(hash: string; profile = phpInteractive): bool =
  ## Returns true if a stored password hash should be recomputed.
  ##
  ## Raises InvalidInputError if the hash is not a valid libsodium password
  ## hash.
  init.ensureInitialized()

  if hash.len == 0 or hash.len >= sodium.crypto_pwhash_STRBYTES or hash.contains('\0'):
    raise newException(InvalidInputError, "invalid password hash")

  let selected = limits(profile)
  let rc = sodium.Sodium.crypto_pwhash_str_needs_rehash(
    cstring(hash),
    selected.ops,
    selected.mem
  )
  if rc < 0:
    raise newException(InvalidInputError, "invalid password hash")

  rc == 1
