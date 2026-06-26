import ./errors
import ./private/internal/init
import ./private/raw/sodium

proc hashPassword*(password: string): string =
  ## Hashes a password using libsodium password hashing.
  ##
  ## Do not use genericHash or keyedHash for password storage.
  init.ensureInitialized()

  var outBuf = newString(sodium.crypto_pwhash_STRBYTES)
  let rc = sodium.Sodium.crypto_pwhash_str(
    cstring(outBuf),
    cstring(password),
    culonglong(password.len),
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    csize_t(sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
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

proc needsRehashPassword*(hash: string): bool =
  ## Returns true if a stored password hash should be recomputed.
  ##
  ## Raises InvalidInputError if the hash is not a valid libsodium password
  ## hash.
  init.ensureInitialized()

  if hash.len == 0 or hash.len >= sodium.crypto_pwhash_STRBYTES or hash.contains('\0'):
    raise newException(InvalidInputError, "invalid password hash")

  let rc = sodium.Sodium.crypto_pwhash_str_needs_rehash(
    cstring(hash),
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    csize_t(sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
  )
  if rc < 0:
    raise newException(InvalidInputError, "invalid password hash")

  rc == 1
