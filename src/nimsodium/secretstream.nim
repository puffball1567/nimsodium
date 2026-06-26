import std/[os, streams]

import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium
import ./random

const
  StreamKeyBytes* = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES
  StreamHeaderBytes* = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
  StreamMacBytes* = sodium.crypto_secretstream_xchacha20poly1305_ABYTES
  DefaultStreamChunkBytes* = 64 * 1024

type
  StreamKey* = distinct string

proc rawBytes*(key: StreamKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc streamKeyFromBytes*(key: string): StreamKey =
  ## Wraps an existing stream key.
  if key.len != StreamKeyBytes:
    raise newException(
      InvalidKeyError,
      "stream key must be " & $StreamKeyBytes & " bytes"
    )
  StreamKey(key)

proc generateStreamKey*(): StreamKey =
  ## Returns a new key for stream and file encryption.
  init.ensureInitialized()

  var key = newString(StreamKeyBytes)
  sodium.Sodium.crypto_secretstream_xchacha20poly1305_keygen(bytes.unsafeCString(key))
  StreamKey(key)

proc newState(): string =
  let stateBytes = int(sodium.Sodium.crypto_secretstream_xchacha20poly1305_statebytes())
  result = newString(stateBytes)

proc tempPathFor(outputPath: string): string =
  outputPath & "." & randomHex(8) & ".nimsodium.tmp"

proc replaceOutput(tempPath, outputPath: string) =
  if fileExists(outputPath):
    removeFile(outputPath)
  moveFile(tempPath, outputPath)

proc encryptFile*(
  inputPath, outputPath: string;
  key: StreamKey;
  associatedData = "";
  chunkSize = DefaultStreamChunkBytes
) =
  ## Encrypts a file using libsodium secretstream.
  ##
  ## The output format is a libsodium secretstream header followed by encrypted
  ## chunks. Associated data is authenticated but not stored.
  init.ensureInitialized()

  if chunkSize <= 0:
    raise newException(ValueError, "chunkSize must be positive")

  var input = newFileStream(inputPath, fmRead)
  if input.isNil:
    raise newException(IOError, "cannot open input file: " & inputPath)
  defer: input.close()

  let tempPath = tempPathFor(outputPath)
  var completed = false
  var output = newFileStream(tempPath, fmWrite)
  if output.isNil:
    raise newException(IOError, "cannot open output file: " & tempPath)
  defer:
    output.close()
    if not completed and fileExists(tempPath):
      removeFile(tempPath)

  var state = newState()
  var header = newString(StreamHeaderBytes)
  let initRc = sodium.Sodium.crypto_secretstream_xchacha20poly1305_init_push(
    bytes.unsafeAddr(state),
    bytes.unsafeCString(header),
    bytes.unsafeCString(string(key))
  )
  if initRc != 0:
    raise newException(CryptoError, "stream encryption initialization failed")
  output.write(header)

  while true:
    let plaintext = input.readStr(chunkSize)
    let isFinal = plaintext.len < chunkSize or input.atEnd()
    var ciphertext = newString(plaintext.len + StreamMacBytes)
    var ciphertextLen: culonglong
    let tag =
      if isFinal: uint8(sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL)
      else: uint8(sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE)

    let rc = sodium.Sodium.crypto_secretstream_xchacha20poly1305_push(
      bytes.unsafeAddr(state),
      bytes.unsafeCString(ciphertext),
      cast[pointer](addr ciphertextLen),
      bytes.unsafeCString(plaintext),
      culonglong(plaintext.len),
      bytes.unsafeCString(associatedData),
      culonglong(associatedData.len),
      tag
    )
    if rc != 0 or ciphertextLen != culonglong(ciphertext.len):
      raise newException(CryptoError, "stream encryption failed")
    output.write(ciphertext)

    if isFinal:
      break

  output.close()
  replaceOutput(tempPath, outputPath)
  completed = true

proc decryptFile*(
  inputPath, outputPath: string;
  key: StreamKey;
  associatedData = "";
  chunkSize = DefaultStreamChunkBytes
) =
  ## Decrypts and verifies a file produced by encryptFile.
  init.ensureInitialized()

  if chunkSize <= 0:
    raise newException(ValueError, "chunkSize must be positive")

  var input = newFileStream(inputPath, fmRead)
  if input.isNil:
    raise newException(IOError, "cannot open input file: " & inputPath)
  defer: input.close()

  let header = input.readStr(StreamHeaderBytes)
  if header.len != StreamHeaderBytes:
    raise newException(InvalidInputError, "stream ciphertext is missing header")

  var state = newState()
  let initRc = sodium.Sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    bytes.unsafeAddr(state),
    bytes.unsafeCString(header),
    bytes.unsafeCString(string(key))
  )
  if initRc != 0:
    raise newException(CryptoError, "stream decryption initialization failed")

  let tempPath = tempPathFor(outputPath)
  var completed = false
  var output = newFileStream(tempPath, fmWrite)
  if output.isNil:
    raise newException(IOError, "cannot open output file: " & tempPath)
  defer:
    output.close()
    if not completed and fileExists(tempPath):
      removeFile(tempPath)

  let encryptedChunkSize = chunkSize + StreamMacBytes
  while true:
    let ciphertext = input.readStr(encryptedChunkSize)
    if ciphertext.len == 0:
      raise newException(CryptoError, "stream ended without final tag")
    if ciphertext.len < StreamMacBytes:
      raise newException(InvalidInputError, "stream ciphertext chunk is too short")

    var plaintext = newString(ciphertext.len - StreamMacBytes)
    var plaintextLen: culonglong
    var tag: uint8
    let rc = sodium.Sodium.crypto_secretstream_xchacha20poly1305_pull(
      bytes.unsafeAddr(state),
      bytes.unsafeCString(plaintext),
      cast[pointer](addr plaintextLen),
      addr tag,
      bytes.unsafeCString(ciphertext),
      culonglong(ciphertext.len),
      bytes.unsafeCString(associatedData),
      culonglong(associatedData.len)
    )
    if rc != 0 or plaintextLen != culonglong(plaintext.len):
      raise newException(CryptoError, "stream authentication failed")

    output.write(plaintext)

    if tag == uint8(sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL):
      if not input.atEnd():
        raise newException(CryptoError, "stream has data after final tag")
      break

  output.close()
  replaceOutput(tempPath, outputPath)
  completed = true
