import ./encoding
import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium

const
  Sha256Bytes* = sodium.crypto_hash_sha256_BYTES
  Sha512Bytes* = sodium.crypto_hash_sha512_BYTES

proc sha256File*(path: string): string =
  ## Hashes a file with SHA-256 and returns raw digest bytes.
  ##
  ## Use this for checksums and external interoperability, not password
  ## storage.
  init.ensureInitialized()

  let data = readFile(path)
  result = newString(Sha256Bytes)
  let rc = sodium.Sodium.crypto_hash_sha256(
    bytes.unsafeCString(result),
    bytes.unsafeCString(data),
    culonglong(data.len)
  )
  if rc != 0:
    raise newException(CryptoError, "SHA-256 hashing failed")

proc sha256FileHex*(path: string): string =
  ## Hashes a file with SHA-256 and returns a hexadecimal digest.
  sha256File(path).toHex()

proc sha512File*(path: string): string =
  ## Hashes a file with SHA-512 and returns raw digest bytes.
  ##
  ## Use this for checksums and external interoperability, not password
  ## storage.
  init.ensureInitialized()

  let data = readFile(path)
  result = newString(Sha512Bytes)
  let rc = sodium.Sodium.crypto_hash_sha512(
    bytes.unsafeCString(result),
    bytes.unsafeCString(data),
    culonglong(data.len)
  )
  if rc != 0:
    raise newException(CryptoError, "SHA-512 hashing failed")

proc sha512FileHex*(path: string): string =
  ## Hashes a file with SHA-512 and returns a hexadecimal digest.
  sha512File(path).toHex()
