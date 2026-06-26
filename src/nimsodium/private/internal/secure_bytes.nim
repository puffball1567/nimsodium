import ../raw/sodium
import ./init
import ../../errors

type
  SecureBytes* = ref object
    data: pointer
    size: int

proc finalizeSecureBytes(data: SecureBytes) =
  if not data.isNil and data.data != nil:
    sodium.Sodium.sodium_free(data.data)
    data.data = nil
    data.size = 0

proc newSecureBytes*(size: int): SecureBytes =
  init.ensureInitialized()
  if size <= 0:
    raise newException(ValueError, "secure byte length must be positive")

  {.push warning[Deprecated]: off.}
  new(result, finalizeSecureBytes)
  {.pop.}
  result.data = sodium.Sodium.sodium_malloc(csize_t(size))
  if result.data == nil:
    raise newException(CryptoError, "secure memory allocation failed")
  if sodium.Sodium.sodium_mlock(result.data, csize_t(size)) != 0:
    sodium.Sodium.sodium_free(result.data)
    result.data = nil
    raise newException(CryptoError, "secure memory lock failed")
  result.size = size

proc len*(data: SecureBytes): int =
  if data.isNil:
    0
  else:
    data.size

proc unsafePtr*(data: SecureBytes): pointer =
  if data.isNil:
    nil
  else:
    data.data

proc unsafeCString*(data: SecureBytes): cstring =
  cast[cstring](unsafePtr(data))

proc protectReadOnly*(data: SecureBytes) =
  if data.isNil or data.data == nil:
    raise newException(InvalidKeyError, "secure bytes are not initialized")
  let rc = sodium.Sodium.sodium_mprotect_readonly(data.data)
  if rc != 0:
    raise newException(CryptoError, "secure memory protection failed")

proc protectReadWrite*(data: SecureBytes) =
  if data.isNil or data.data == nil:
    raise newException(InvalidKeyError, "secure bytes are not initialized")
  let rc = sodium.Sodium.sodium_mprotect_readwrite(data.data)
  if rc != 0:
    raise newException(CryptoError, "secure memory protection failed")

proc secureBytesFromBytes*(bytes: string): SecureBytes =
  result = newSecureBytes(bytes.len)
  if bytes.len > 0:
    copyMem(result.data, unsafeAddr bytes[0], bytes.len)
  result.protectReadOnly()

proc randomSecureBytes*(size: int): SecureBytes =
  result = newSecureBytes(size)
  sodium.Sodium.randombytes_buf(result.data, csize_t(size))
  result.protectReadOnly()

proc rawBytes*(data: SecureBytes): string =
  if data.isNil or data.data == nil:
    raise newException(InvalidKeyError, "secure bytes are not initialized")
  result = newString(data.size)
  if data.size > 0:
    copyMem(addr result[0], data.data, data.size)
