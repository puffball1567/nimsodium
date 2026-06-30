## C ABI for nimsodium high-level workflows.
##
## This module exports a small, exception-free ABI for other languages. It does
## not expose the internal libsodium FFI.

import nimsodium/errors
import nimsodium/memory
import nimsodium/password
import nimsodium/password_encryption
import nimsodium/private/internal/init
import nimsodium/signatures
import nimsodium/version
import nimsodium/wallets

const
  NimsodiumCVersion* = "0.1.0"

type
  NimsodiumBuffer* {.exportc: "nimsodium_buffer".} = object
    data*: pointer
    len*: csize_t

{.pragma: cexport, exportc, cdecl, dynlib.}

var lastError {.threadvar.}: string

proc setError(message: string): cint =
  lastError = message
  -1

proc clearError() =
  lastError = ""

proc inputBytes(data: pointer; len: csize_t; name: string): string =
  if len > 0 and data == nil:
    raise newException(InvalidInputError, name & " pointer is null")
  result = newString(int(len))
  if len > 0:
    copyMem(addr result[0], data, int(len))

proc inputText(data: pointer; len: csize_t; name: string): string =
  inputBytes(data, len, name)

proc inputCString(value: cstring; name: string): string =
  if value == nil:
    raise newException(InvalidInputError, name & " is null")
  $value

proc profileFromInt(profile: cint): PasswordEncryptionProfile =
  case profile
  of 0: pepInteractive
  of 1: pepModerate
  of 2: pepSensitive
  else:
    raise newException(InvalidInputError, "unknown password encryption profile")

proc passwordHashProfileFromInt(profile: cint): PasswordHashProfile =
  case profile
  of 0: phpInteractive
  of 1: phpModerate
  of 2: phpSensitive
  else:
    raise newException(InvalidInputError, "unknown password hash profile")

proc writeBuffer(data: string; outBuffer: ptr NimsodiumBuffer) =
  if outBuffer == nil:
    raise newException(InvalidInputError, "output buffer pointer is null")
  outBuffer[].data = nil
  outBuffer[].len = csize_t(data.len)
  if data.len == 0:
    return
  outBuffer[].data = allocShared(data.len)
  if outBuffer[].data == nil:
    raise newException(CryptoError, "C ABI output allocation failed")
  copyMem(outBuffer[].data, unsafeAddr data[0], data.len)

proc nimsodium_c_abi_version*(): cstring {.cexport.} =
  cstring(NimsodiumCVersion)

proc nimsodium_package_version*(): cstring {.cexport.} =
  cstring("0.2.1")

proc nimsodium_libsodium_version*(): cstring {.cexport.} =
  try:
    clearError()
    cstring(sodiumVersion())
  except CatchableError as err:
    discard setError(err.msg)
    nil

proc nimsodium_last_error*(): cstring {.cexport.} =
  cstring(lastError)

proc nimsodium_init*(): cint {.cexport.} =
  try:
    clearError()
    init.ensureInitialized()
    0
  except CatchableError as err:
    setError(err.msg)

proc nimsodium_free_buffer*(buffer: ptr NimsodiumBuffer) {.cexport.} =
  if buffer == nil:
    return
  if buffer[].data != nil and buffer[].len > 0:
    zeroMem(buffer[].data, int(buffer[].len))
    deallocShared(buffer[].data)
  buffer[].data = nil
  buffer[].len = 0

proc nimsodium_hash_password*(
    password: pointer;
    passwordLen: csize_t;
    profile: cint;
    outHash: ptr NimsodiumBuffer
): cint {.cexport.} =
  try:
    clearError()
    let passwordText = inputText(password, passwordLen, "password")
    writeBuffer(hashPassword(passwordText, passwordHashProfileFromInt(profile)), outHash)
    0
  except CatchableError as err:
    setError(err.msg)

proc nimsodium_verify_password*(
    hash: pointer;
    hashLen: csize_t;
    password: pointer;
    passwordLen: csize_t;
    verified: ptr cint
): cint {.cexport.} =
  try:
    clearError()
    if verified == nil:
      raise newException(InvalidInputError, "verified output pointer is null")
    let hashText = inputText(hash, hashLen, "hash")
    let passwordText = inputText(password, passwordLen, "password")
    verified[] =
      if verifyPassword(hashText, passwordText):
        1
      else:
        0
    0
  except CatchableError as err:
    setError(err.msg)

proc nimsodium_protect_wallet_secret*(
    secret: pointer;
    secretLen: csize_t;
    password: pointer;
    passwordLen: csize_t;
    label: pointer;
    labelLen: csize_t;
    profile: cint;
    outProtected: ptr NimsodiumBuffer
): cint {.cexport.} =
  var secretBytes = ""
  try:
    clearError()
    secretBytes = inputBytes(secret, secretLen, "secret")
    let passwordText = inputText(password, passwordLen, "password")
    let labelText = inputText(label, labelLen, "label")
    let protected = protectWalletSecret(
      walletSecretFromBytes(secretBytes),
      passwordText,
      labelText,
      profileFromInt(profile)
    )
    writeBuffer(rawBytes(protected), outProtected)
    0
  except CatchableError as err:
    setError(err.msg)
  finally:
    secureClear(secretBytes)

proc nimsodium_open_protected_wallet_secret*(
    protectedSecret: pointer;
    protectedSecretLen: csize_t;
    password: pointer;
    passwordLen: csize_t;
    label: pointer;
    labelLen: csize_t;
    outSecret: ptr NimsodiumBuffer
): cint {.cexport.} =
  try:
    clearError()
    let protectedBytes = inputBytes(protectedSecret, protectedSecretLen, "protected secret")
    let passwordText = inputText(password, passwordLen, "password")
    let labelText = inputText(label, labelLen, "label")
    let opened = openProtectedWalletSecret(
      protectedWalletSecretFromBytes(protectedBytes),
      passwordText,
      labelText
    )
    var secretBytes = rawBytes(opened)
    try:
      writeBuffer(secretBytes, outSecret)
      0
    finally:
      secureClear(secretBytes)
  except CatchableError as err:
    setError(err.msg)

proc nimsodium_encrypt_wallet_secret_file*(
    inputPath: cstring;
    outputPath: cstring;
    password: pointer;
    passwordLen: csize_t;
    label: pointer;
    labelLen: csize_t;
    profile: cint;
    chunkSize: csize_t
): cint {.cexport.} =
  try:
    clearError()
    let passwordText = inputText(password, passwordLen, "password")
    let labelText = inputText(label, labelLen, "label")
    encryptWalletSecretFile(
      inputCString(inputPath, "input path"),
      inputCString(outputPath, "output path"),
      passwordText,
      labelText,
      profileFromInt(profile),
      int(chunkSize)
    )
    0
  except CatchableError as err:
    setError(err.msg)

proc nimsodium_decrypt_wallet_secret_file*(
    inputPath: cstring;
    outputPath: cstring;
    password: pointer;
    passwordLen: csize_t;
    label: pointer;
    labelLen: csize_t;
    chunkSize: csize_t
): cint {.cexport.} =
  try:
    clearError()
    let passwordText = inputText(password, passwordLen, "password")
    let labelText = inputText(label, labelLen, "label")
    decryptWalletSecretFile(
      inputCString(inputPath, "input path"),
      inputCString(outputPath, "output path"),
      passwordText,
      labelText,
      int(chunkSize)
    )
    0
  except CatchableError as err:
    setError(err.msg)

proc nimsodium_generate_signing_keypair*(
    outPublicKey: ptr NimsodiumBuffer;
    outSecretKey: ptr NimsodiumBuffer
): cint {.cexport.} =
  var secretKeyBytes = ""
  try:
    clearError()
    let keys = generateSigningKeyPair()
    secretKeyBytes = rawBytes(keys.secretKey)
    writeBuffer(rawBytes(keys.publicKey), outPublicKey)
    try:
      writeBuffer(secretKeyBytes, outSecretKey)
    except CatchableError:
      nimsodium_free_buffer(outPublicKey)
      raise
    0
  except CatchableError as err:
    setError(err.msg)
  finally:
    secureClear(secretKeyBytes)

proc nimsodium_sign_offchain_message*(
    message: pointer;
    messageLen: csize_t;
    domain: pointer;
    domainLen: csize_t;
    secretKey: pointer;
    secretKeyLen: csize_t;
    outSignature: ptr NimsodiumBuffer
): cint {.cexport.} =
  var secretKeyBytes = ""
  try:
    clearError()
    let messageText = inputBytes(message, messageLen, "message")
    let domainText = inputText(domain, domainLen, "domain")
    secretKeyBytes = inputBytes(secretKey, secretKeyLen, "secret key")
    writeBuffer(
      signOffchainMessage(
        messageText,
        domainText,
        signingSecretKeyFromBytes(secretKeyBytes)
      ),
      outSignature
    )
    0
  except CatchableError as err:
    setError(err.msg)
  finally:
    secureClear(secretKeyBytes)

proc nimsodium_verify_offchain_message*(
    message: pointer;
    messageLen: csize_t;
    domain: pointer;
    domainLen: csize_t;
    signature: pointer;
    signatureLen: csize_t;
    publicKey: pointer;
    publicKeyLen: csize_t;
    verified: ptr cint
): cint {.cexport.} =
  try:
    clearError()
    if verified == nil:
      raise newException(InvalidInputError, "verified output pointer is null")
    let messageText = inputBytes(message, messageLen, "message")
    let domainText = inputText(domain, domainLen, "domain")
    let signatureBytes = inputBytes(signature, signatureLen, "signature")
    let publicKeyBytes = inputBytes(publicKey, publicKeyLen, "public key")
    verified[] =
      if verifyOffchainMessage(
        messageText,
        domainText,
        signatureBytes,
        signingPublicKeyFromBytes(publicKeyBytes)
      ):
        1
      else:
        0
    0
  except CatchableError as err:
    setError(err.msg)
