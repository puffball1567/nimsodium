import ./aead
import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random

const
  PasswordEncryptionSaltBytes* = sodium.crypto_pwhash_SALTBYTES
  PasswordEncryptionHeaderBytes* = 6

const Magic = "NSPW1"

type
  PasswordEncryptionProfile* = enum
    pepInteractive
    pepModerate
    pepSensitive

proc profileByte(profile: PasswordEncryptionProfile): char =
  case profile
  of pepInteractive: '\1'
  of pepModerate: '\2'
  of pepSensitive: '\3'

proc profileFromByte(value: char): PasswordEncryptionProfile =
  case value
  of '\1': pepInteractive
  of '\2': pepModerate
  of '\3': pepSensitive
  else:
    raise newException(InvalidInputError, "unknown password encryption profile")

proc limits(profile: PasswordEncryptionProfile): tuple[ops: culonglong, mem: csize_t] =
  case profile
  of pepInteractive:
    (
      culonglong(sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE),
      csize_t(sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE)
    )
  of pepModerate:
    (
      culonglong(sodium.crypto_pwhash_OPSLIMIT_MODERATE),
      csize_t(sodium.crypto_pwhash_MEMLIMIT_MODERATE)
    )
  of pepSensitive:
    (
      culonglong(sodium.crypto_pwhash_OPSLIMIT_SENSITIVE),
      csize_t(sodium.crypto_pwhash_MEMLIMIT_SENSITIVE)
    )

proc derivePasswordAeadKey(
    password, salt: string; profile: PasswordEncryptionProfile
): AeadKey =
  init.ensureInitialized()

  if salt.len != PasswordEncryptionSaltBytes:
    raise newException(
      InvalidInputError,
      "password encryption salt must be " & $PasswordEncryptionSaltBytes & " bytes"
    )

  let selected = limits(profile)
  var key = newString(AeadKeyBytes)
  let rc = sodium.Sodium.crypto_pwhash(
    bytes.unsafeCString(key),
    culonglong(key.len),
    bytes.unsafeCString(password),
    culonglong(password.len),
    bytes.unsafeCString(salt),
    selected.ops,
    selected.mem,
    sodium.crypto_pwhash_ALG_DEFAULT
  )
  if rc != 0:
    raise newException(CryptoError, "password key derivation failed")

  aeadKeyFromBytes(key)

proc encryptWithPassword*(
    plaintext, password: string;
    associatedData = "";
    profile = pepInteractive
): string =
  ## Encrypts data with a password-derived AEAD key.
  ##
  ## The returned binary string stores the format version, profile, salt, nonce,
  ## and ciphertext. Associated data is authenticated but not stored.
  let salt = randomBytes(PasswordEncryptionSaltBytes)
  let key = derivePasswordAeadKey(password, salt, profile)
  Magic & profileByte(profile) & salt & encryptAead(plaintext, key, associatedData)

proc decryptWithPassword*(
    encrypted, password: string; associatedData = ""
): string =
  ## Decrypts data produced by encryptWithPassword.
  ##
  ## Raises InvalidInputError for malformed data and CryptoError for wrong
  ## passwords, wrong associated data, or modified ciphertext.
  if encrypted.len < PasswordEncryptionHeaderBytes + PasswordEncryptionSaltBytes +
      AeadNonceBytes + AeadMacBytes:
    raise newException(InvalidInputError, "password-encrypted payload is too short")
  if encrypted[0 ..< Magic.len] != Magic:
    raise newException(InvalidInputError, "unknown password-encrypted payload format")

  let profile = profileFromByte(encrypted[Magic.len])
  let saltStart = PasswordEncryptionHeaderBytes
  let saltEnd = saltStart + PasswordEncryptionSaltBytes
  let salt = encrypted[saltStart ..< saltEnd]
  let ciphertext = encrypted[saltEnd .. ^1]
  let key = derivePasswordAeadKey(password, salt, profile)

  decryptAead(ciphertext, key, associatedData)
