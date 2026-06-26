import std/[os, streams]

import ./errors
import ./memory
import ./password_encryption
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random
import ./secretstream

const FileMagic = "NSPF1"
const PasswordFileHeaderBytes* = 6

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
    raise newException(InvalidInputError, "unknown password file encryption profile")

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

proc derivePasswordStreamKey(
    password, salt: string; profile: PasswordEncryptionProfile
): StreamKey =
  init.ensureInitialized()

  if salt.len != PasswordEncryptionSaltBytes:
    raise newException(
      InvalidInputError,
      "password file encryption salt must be " & $PasswordEncryptionSaltBytes & " bytes"
    )

  let selected = limits(profile)
  var key = newString(StreamKeyBytes)
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
    raise newException(CryptoError, "password file key derivation failed")

  result = streamKeyFromBytes(key)
  secureClear(key)

proc tempPathFor(outputPath: string): string =
  outputPath & "." & randomHex(8) & ".nimsodium.tmp"

proc replaceOutput(tempPath, outputPath: string) =
  if fileExists(outputPath):
    removeFile(outputPath)
  moveFile(tempPath, outputPath)

proc encryptFileWithPassword*(
    inputPath, outputPath, password: string;
    associatedData = "";
    profile = pepInteractive;
    chunkSize = DefaultStreamChunkBytes
) =
  ## Encrypts a file with a password-derived stream key.
  ##
  ## The output stores format version, profile, salt, and a libsodium
  ## secretstream payload. The requested output path is replaced only after the
  ## operation succeeds.
  if chunkSize <= 0:
    raise newException(ValueError, "chunkSize must be positive")

  let salt = randomBytes(PasswordEncryptionSaltBytes)
  let key = derivePasswordStreamKey(password, salt, profile)
  let tempEncrypted = tempPathFor(outputPath)
  var completed = false

  try:
    encryptFile(inputPath, tempEncrypted, key, associatedData, chunkSize)

    let tempOutput = tempPathFor(outputPath)
    var outputCompleted = false
    var outStream = newFileStream(tempOutput, fmWrite)
    if outStream.isNil:
      raise newException(IOError, "cannot open output file: " & tempOutput)
    try:
      outStream.write(FileMagic)
      outStream.write($profileByte(profile))
      outStream.write(salt)

      var encryptedStream = newFileStream(tempEncrypted, fmRead)
      if encryptedStream.isNil:
        raise newException(IOError, "cannot open temporary encrypted file: " & tempEncrypted)
      defer: encryptedStream.close()

      while true:
        let chunk = encryptedStream.readStr(chunkSize)
        if chunk.len == 0:
          break
        outStream.write(chunk)
      outputCompleted = true
    finally:
      outStream.close()
      if not outputCompleted and fileExists(tempOutput):
        removeFile(tempOutput)

    replaceOutput(tempOutput, outputPath)
    completed = true
  finally:
    if fileExists(tempEncrypted):
      removeFile(tempEncrypted)
    if not completed:
      discard

proc decryptFileWithPassword*(
    inputPath, outputPath, password: string;
    associatedData = "";
    chunkSize = DefaultStreamChunkBytes
) =
  ## Decrypts a file produced by encryptFileWithPassword.
  ##
  ## Wrong passwords, wrong associated data, or modified ciphertext raise
  ## CryptoError and do not replace the requested output path.
  if chunkSize <= 0:
    raise newException(ValueError, "chunkSize must be positive")

  var input = newFileStream(inputPath, fmRead)
  if input.isNil:
    raise newException(IOError, "cannot open input file: " & inputPath)
  defer: input.close()

  let header = input.readStr(PasswordFileHeaderBytes)
  if header.len != PasswordFileHeaderBytes:
    raise newException(InvalidInputError, "password-encrypted file is too short")
  if header[0 ..< FileMagic.len] != FileMagic:
    raise newException(InvalidInputError, "unknown password-encrypted file format")

  let profile = profileFromByte(header[FileMagic.len])
  let salt = input.readStr(PasswordEncryptionSaltBytes)
  if salt.len != PasswordEncryptionSaltBytes:
    raise newException(InvalidInputError, "password-encrypted file is missing salt")

  let key = derivePasswordStreamKey(password, salt, profile)
  let tempEncrypted = tempPathFor(outputPath)
  var tempStream = newFileStream(tempEncrypted, fmWrite)
  if tempStream.isNil:
    raise newException(IOError, "cannot open temporary file: " & tempEncrypted)
  try:
    while true:
      let chunk = input.readStr(chunkSize)
      if chunk.len == 0:
        break
      tempStream.write(chunk)
  finally:
    tempStream.close()

  try:
    decryptFile(tempEncrypted, outputPath, key, associatedData, chunkSize)
  finally:
    if fileExists(tempEncrypted):
      removeFile(tempEncrypted)
