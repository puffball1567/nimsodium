import std/[os, unittest]
import std/strutils except fromHex, toHex

import nimsodium
import nimsodium/advanced
import nimsodium/errors

suite "encoding":
  test "hex roundtrip":
    let data = "abc" & '\0' & "xyz"
    check fromHex(toHex(data)) == data

  test "generic hash known-answer vectors":
    check genericHashHex("") == "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    check genericHashHex("abc") == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"

  test "invalid hex is rejected":
    expect InvalidInputError:
      discard fromHex("abc")
    expect InvalidInputError:
      discard fromHex("zz")

suite "base64":
  test "base64 roundtrip":
    let data = "abc" & '\0' & "xyz"
    check fromBase64(toBase64(data)) == data

  test "base64 known-answer vector":
    check toBase64("abc" & '\0' & "xyz") == "YWJjAHh5eg"
    check fromBase64("YWJjAHh5eg") == "abc" & '\0' & "xyz"

  test "base64 empty roundtrip":
    check toBase64("") == ""
    check fromBase64("") == ""

  test "randomBase64 encodes requested random byte length":
    let encoded = randomBase64(32)
    check fromBase64(encoded).len == 32

  test "invalid base64 is rejected":
    expect InvalidInputError:
      discard fromBase64("not valid!")

suite "random":
  test "randomBytes length":
    check randomBytes(16).len == 16
    check randomBytes(0).len == 0
    expect ValueError:
      discard randomBytes(-1)

  test "randomHex length":
    check randomHex(16).len == 32
    expect ValueError:
      discard randomHex(-1)

  test "randomInt bounds":
    for _ in 0 ..< 32:
      let value = randomInt(10)
      check value >= 0
      check value < 10
    expect ValueError:
      discard randomInt(0)

suite "hash":
  test "generic hash is stable":
    check genericHash("hello") == genericHash("hello")
    check genericHash("hello").len == GenericHashBytes

  test "generic hash supports validated output lengths":
    check genericHash("hello", GenericHashBytesMin).len == GenericHashBytesMin
    check genericHashHex("hello", GenericHashBytesMax).len == GenericHashBytesMax * 2
    expect InvalidInputError:
      discard genericHash("hello", GenericHashBytesMin - 1)
    expect InvalidInputError:
      discard genericHash("hello", GenericHashBytesMax + 1)

  test "keyed hash checks key length":
    expect InvalidKeyError:
      discard keyedHashKeyFromBytes("short")

  test "keyed hash is stable":
    let key = generateKeyedHashKey()
    check keyedHash("hello", key) == keyedHash("hello", key)
    check rawBytes(key).len == GenericHashKeyBytes
    check keyedHash("hello", key, GenericHashBytesMin).len == GenericHashBytesMin
    expect InvalidInputError:
      discard keyedHash("hello", key, GenericHashBytesMax + 1)

suite "auth":
  test "authentication tag verifies":
    let key = generateAuthKey()
    let message = "message" & '\0' & "payload"
    let tag = authenticate(message, key)
    check rawBytes(key).len == AuthKeyBytes
    check tag.len == AuthBytes
    check verifyAuthentication(message, tag, key)

  test "authentication rejects modified message, tag, and wrong key":
    let key = generateAuthKey()
    var tag = authenticate("message", key)
    check not verifyAuthentication("different", tag, key)
    tag[^1] = char(ord(tag[^1]) xor 1)
    check not verifyAuthentication("message", tag, key)
    check not verifyAuthentication("message", authenticate("message", key), generateAuthKey())

  test "authentication invalid inputs are rejected":
    expect InvalidKeyError:
      discard authKeyFromBytes("short")
    expect InvalidKeyError:
      discard authKeyFromBytes("short")
    check not verifyAuthentication("message", "short", generateAuthKey())

suite "kdf":
  test "KDF derives stable subkeys":
    let masterKey = generateKdfKey()
    let a = deriveKey(masterKey, "AEADv001", 1'u64, AeadKeyBytes)
    let b = deriveKey(masterKey, "AEADv001", 1'u64, AeadKeyBytes)
    check rawBytes(masterKey).len == KdfKeyBytes
    check a == b
    check a.len == AeadKeyBytes

  test "KDF separates context and subkey id":
    let masterKey = generateKdfKey()
    let a = deriveKey(masterKey, "AEADv001", 1'u64, AeadKeyBytes)
    let b = deriveKey(masterKey, "AEADv001", 2'u64, AeadKeyBytes)
    let c = deriveKey(masterKey, "TOKNv001", 1'u64, AeadKeyBytes)
    check a != b
    check a != c

  test "KDF invalid inputs are rejected":
    let masterKey = generateKdfKey()
    expect InvalidKeyError:
      discard kdfKeyFromBytes("short")
    expect InvalidInputError:
      discard deriveKey(masterKey, "short", 1'u64, AeadKeyBytes)
    expect InvalidInputError:
      discard deriveKey(masterKey, "AEADv001", 1'u64, KdfBytesMin - 1)

  test "KDF derives typed workflow keys":
    let masterKey = generateKdfKey()

    let aeadKey = deriveAeadKey(masterKey, "AEADv001", 1'u64)
    let aeadCiphertext = encryptAead("secret", aeadKey, "record:42")
    check decryptAead(aeadCiphertext, aeadKey, "record:42") == "secret"

    let secretBoxKey = deriveSecretBoxKey(masterKey, "SECBv001", 1'u64)
    let secretBoxCiphertext = encryptSecretBox("secret", secretBoxKey)
    check decryptSecretBox(secretBoxCiphertext, secretBoxKey) == "secret"

    let authKey = deriveAuthKey(masterKey, "AUTHv001", 1'u64)
    let tag = authenticate("message", authKey)
    check verifyAuthentication("message", tag, authKey)

    let hashKey = deriveKeyedHashKey(masterKey, "HASHv001", 1'u64)
    check keyedHash("message", hashKey).len == GenericHashBytes

    let streamKey = deriveStreamKey(masterKey, "STRMv001", 1'u64)
    check rawBytes(streamKey).len == StreamKeyBytes

suite "key formats":
  test "symmetric keys roundtrip through base64":
    let aeadKey = generateAeadKey()
    check rawBytes(aeadKeyFromBase64(aeadKeyToBase64(aeadKey))) == rawBytes(aeadKey)

    let secretBoxKey = generateSecretBoxKey()
    check rawBytes(secretBoxKeyFromBase64(secretBoxKeyToBase64(secretBoxKey))) ==
      rawBytes(secretBoxKey)

    let authKey = generateAuthKey()
    check rawBytes(authKeyFromBase64(authKeyToBase64(authKey))) == rawBytes(authKey)

    let kdfKey = generateKdfKey()
    check rawBytes(kdfKeyFromBase64(kdfKeyToBase64(kdfKey))) == rawBytes(kdfKey)

    let streamKey = generateStreamKey()
    check rawBytes(streamKeyFromBase64(streamKeyToBase64(streamKey))) == rawBytes(streamKey)

    let hashKey = generateKeyedHashKey()
    check rawBytes(keyedHashKeyFromBase64(keyedHashKeyToBase64(hashKey))) ==
      rawBytes(hashKey)

    expect InvalidInputError:
      discard aeadKeyFromBase64("not valid!")
    expect InvalidKeyError:
      discard aeadKeyFromBase64(toBase64("short"))
    expect InvalidKeyError:
      discard secretBoxKeyFromBase64(toBase64("short"))
    expect InvalidKeyError:
      discard authKeyFromBase64(toBase64("short"))
    expect InvalidKeyError:
      discard kdfKeyFromBase64(toBase64("short"))
    expect InvalidKeyError:
      discard streamKeyFromBase64(toBase64("short"))
    expect InvalidKeyError:
      discard keyedHashKeyFromBase64(toBase64("short"))

suite "tokens":
  test "token workflow generates, fingerprints, and verifies":
    let key = generateKeyedHashKey()
    let token = generateToken()
    let fingerprint = fingerprintToken(token, key)
    let fingerprintHex = fingerprintTokenHex(token, key)

    check fromBase64(token).len == 32
    check rawBytes(fingerprint).len == GenericHashBytes
    check verifyTokenFingerprint(token, fingerprint, key)
    check verifyTokenFingerprintHex(token, fingerprintHex, key)
    check not verifyTokenFingerprint("wrong", fingerprint, key)
    check not verifyTokenFingerprintHex(token, "not hex", key)
    expect InvalidInputError:
      discard tokenFingerprintFromBytes("short")
    expect InvalidInputError:
      discard tokenFingerprintFromHex(toHex("short"))

suite "password":
  test "password hash verifies":
    let hash = hashPassword("correct horse battery staple")
    check verifyPassword(hash, "correct horse battery staple")
    check not verifyPassword(hash, "wrong password")

  test "password hash profile can request stronger rehash":
    let hash = hashPassword("correct horse battery staple", phpInteractive)
    check not needsRehashPassword(hash, phpInteractive)
    check needsRehashPassword(hash, phpModerate)

  test "passwords are length-aware":
    let password = "abc" & '\0' & "def"
    let hash = hashPassword(password)
    check verifyPassword(hash, password)
    check not verifyPassword(hash, "abc")

  test "empty password verifies":
    let hash = hashPassword("")
    check verifyPassword(hash, "")
    check not verifyPassword(hash, "not empty")

  test "invalid password hash returns false":
    check not verifyPassword("not a libsodium hash", "password")

  test "password rehash check":
    let hash = hashPassword("password")
    check not needsRehashPassword(hash)
    expect InvalidInputError:
      discard needsRehashPassword("not a libsodium hash")

suite "password encryption":
  test "password encryption roundtrip with associated data":
    let plaintext = "secret" & '\0' & "payload"
    let encrypted = encryptWithPassword(plaintext, "passphrase", "record:42")

    check encrypted.len > plaintext.len
    check decryptWithPassword(encrypted, "passphrase", "record:42") == plaintext

  test "password encryption rejects wrong password, AD, and corruption":
    let encrypted = encryptWithPassword("secret", "passphrase", "record:42")

    expect CryptoError:
      discard decryptWithPassword(encrypted, "wrong", "record:42")
    expect CryptoError:
      discard decryptWithPassword(encrypted, "passphrase", "record:43")

    var tampered = encrypted
    tampered[^1] = char(ord(tampered[^1]) xor 1)
    expect CryptoError:
      discard decryptWithPassword(tampered, "passphrase", "record:42")

    var tamperedSalt = encrypted
    tamperedSalt[PasswordEncryptionHeaderBytes] =
      char(ord(tamperedSalt[PasswordEncryptionHeaderBytes]) xor 1)
    expect CryptoError:
      discard decryptWithPassword(tamperedSalt, "passphrase", "record:42")

  test "password encryption rejects malformed payloads":
    expect InvalidInputError:
      discard decryptWithPassword("short", "passphrase")

    var encrypted = encryptWithPassword("secret", "passphrase")
    encrypted[0] = 'x'
    expect InvalidInputError:
      discard decryptWithPassword(encrypted, "passphrase")

    var badProfile = encryptWithPassword("secret", "passphrase")
    badProfile[5] = '\9'
    expect InvalidInputError:
      discard decryptWithPassword(badProfile, "passphrase")

    let truncated = encryptWithPassword("secret", "passphrase")[0 ..< PasswordEncryptionHeaderBytes]
    expect InvalidInputError:
      discard decryptWithPassword(truncated, "passphrase")

suite "password file encryption":
  let basePath = getCurrentDir() / "tests" / "tmp_password_file"
  let plainPath = basePath & ".plain"
  let encryptedPath = basePath & ".enc"
  let decryptedPath = basePath & ".dec"
  let tamperedPath = basePath & ".tampered"

  teardown:
    for path in [plainPath, encryptedPath, decryptedPath, tamperedPath]:
      if fileExists(path):
        removeFile(path)

  test "password file encryption roundtrip with associated data":
    writeFile(plainPath, "secret" & '\0' & "payload")

    encryptFileWithPassword(plainPath, encryptedPath, "passphrase", "backup:42", chunkSize = 7)
    decryptFileWithPassword(encryptedPath, decryptedPath, "passphrase", "backup:42", chunkSize = 7)

    check readFile(decryptedPath) == "secret" & '\0' & "payload"

  test "password file encryption rejects wrong password without replacing output":
    writeFile(plainPath, "secret data")
    writeFile(decryptedPath, "existing")
    encryptFileWithPassword(plainPath, encryptedPath, "passphrase", chunkSize = 5)

    expect CryptoError:
      decryptFileWithPassword(encryptedPath, decryptedPath, "wrong", chunkSize = 5)
    check readFile(decryptedPath) == "existing"

  test "password file encryption rejects wrong AD and tampering without replacing output":
    writeFile(plainPath, "secret data")
    writeFile(decryptedPath, "existing")
    encryptFileWithPassword(plainPath, encryptedPath, "passphrase", "expected", chunkSize = 5)

    expect CryptoError:
      decryptFileWithPassword(encryptedPath, decryptedPath, "passphrase", "different", chunkSize = 5)
    check readFile(decryptedPath) == "existing"

    var ciphertext = readFile(encryptedPath)
    ciphertext[^1] = char(ord(ciphertext[^1]) xor 1)
    writeFile(tamperedPath, ciphertext)

    expect CryptoError:
      decryptFileWithPassword(tamperedPath, decryptedPath, "passphrase", "expected", chunkSize = 5)
    check readFile(decryptedPath) == "existing"

  test "password file encryption rejects malformed input":
    writeFile(encryptedPath, "short")
    expect InvalidInputError:
      decryptFileWithPassword(encryptedPath, decryptedPath, "passphrase")

    writeFile(plainPath, "secret data")
    encryptFileWithPassword(plainPath, encryptedPath, "passphrase")

    var badMagic = readFile(encryptedPath)
    badMagic[0] = 'x'
    writeFile(tamperedPath, badMagic)
    expect InvalidInputError:
      decryptFileWithPassword(tamperedPath, decryptedPath, "passphrase")

    var badProfile = readFile(encryptedPath)
    badProfile[5] = '\9'
    writeFile(tamperedPath, badProfile)
    expect InvalidInputError:
      decryptFileWithPassword(tamperedPath, decryptedPath, "passphrase")

    var missingSalt = readFile(encryptedPath)[0 ..< PasswordFileHeaderBytes]
    writeFile(tamperedPath, missingSalt)
    expect InvalidInputError:
      decryptFileWithPassword(tamperedPath, decryptedPath, "passphrase")

suite "compare":
  test "constant time compare behavior":
    check constantTimeEquals("abc", "abc")
    check not constantTimeEquals("abc", "abd")
    check not constantTimeEquals("abc", "abcd")
    check constantTimeEquals("", "")

suite "file hash":
  let hashPath = getCurrentDir() / "tests" / "tmp_hash_input"

  teardown:
    if fileExists(hashPath):
      removeFile(hashPath)

  test "file SHA hashes known-answer vectors":
    writeFile(hashPath, "abc")

    check sha256File(hashPath).len == Sha256Bytes
    check sha512File(hashPath).len == Sha512Bytes
    check sha256FileHex(hashPath) ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    check sha512FileHex(hashPath) ==
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

suite "memory":
  test "secureZero overwrites current string":
    var secret = "secret"
    secureZero(secret)
    check secret == "\0\0\0\0\0\0"

  test "secureClear overwrites and clears current string":
    var secret = "secret"
    secureClear(secret)
    check secret.len == 0

suite "secretbox":
  test "secretbox roundtrip":
    let key = generateSecretBoxKey()
    let plaintext = "secret" & '\0' & "payload"
    let ciphertext = encryptSecretBox(plaintext, key)
    check ciphertext.len == SecretBoxNonceBytes + SecretBoxMacBytes + plaintext.len
    check decryptSecretBox(ciphertext, key) == plaintext

  test "secretbox empty plaintext roundtrip":
    let key = generateSecretBoxKey()
    let ciphertext = encryptSecretBox("", key)
    check ciphertext.len == SecretBoxNonceBytes + SecretBoxMacBytes
    check decryptSecretBox(ciphertext, key) == ""

  test "wrong key is rejected":
    let ciphertext = encryptSecretBox("secret", generateSecretBoxKey())
    expect CryptoError:
      discard decryptSecretBox(ciphertext, generateSecretBoxKey())

  test "corrupted ciphertext is rejected":
    let key = generateSecretBoxKey()
    var ciphertext = encryptSecretBox("secret", key)
    ciphertext[^1] = char(ord(ciphertext[^1]) xor 1)
    expect CryptoError:
      discard decryptSecretBox(ciphertext, key)

  test "corrupted secretbox nonce is rejected":
    let key = generateSecretBoxKey()
    var ciphertext = encryptSecretBox("secret", key)
    ciphertext[0] = char(ord(ciphertext[0]) xor 1)
    expect CryptoError:
      discard decryptSecretBox(ciphertext, key)

  test "invalid secretbox inputs are rejected":
    expect InvalidKeyError:
      discard secretBoxKeyFromBytes("short")
    expect InvalidInputError:
      discard decryptSecretBox("short", generateSecretBoxKey())

suite "aead":
  test "AEAD roundtrip with associated data":
    let key = generateAeadKey()
    let plaintext = "secret" & '\0' & "payload"
    let ad = "route:/v1/resource"
    let ciphertext = encryptAead(plaintext, key, ad)
    check ciphertext.len == AeadNonceBytes + AeadMacBytes + plaintext.len
    check decryptAead(ciphertext, key, ad) == plaintext

  test "AEAD empty plaintext roundtrip":
    let key = generateAeadKey()
    let ciphertext = encryptAead("", key, "metadata")
    check ciphertext.len == AeadNonceBytes + AeadMacBytes
    check decryptAead(ciphertext, key, "metadata") == ""

  test "AEAD rejects wrong associated data":
    let key = generateAeadKey()
    let ciphertext = encryptAead("secret", key, "expected")
    expect CryptoError:
      discard decryptAead(ciphertext, key, "different")

  test "AEAD rejects wrong key and corruption":
    let key = generateAeadKey()
    var ciphertext = encryptAead("secret", key)
    expect CryptoError:
      discard decryptAead(ciphertext, generateAeadKey())
    ciphertext[^1] = char(ord(ciphertext[^1]) xor 1)
    expect CryptoError:
      discard decryptAead(ciphertext, key)

  test "AEAD rejects corrupted nonce":
    let key = generateAeadKey()
    var ciphertext = encryptAead("secret", key, "metadata")
    ciphertext[0] = char(ord(ciphertext[0]) xor 1)
    expect CryptoError:
      discard decryptAead(ciphertext, key, "metadata")

  test "AEAD invalid inputs are rejected":
    expect InvalidKeyError:
      discard aeadKeyFromBytes("short")
    expect InvalidInputError:
      discard decryptAead("short", generateAeadKey())

suite "secretstream":
  let basePath = getCurrentDir() / "tests" / "tmp_secretstream"
  let plainPath = basePath & ".plain"
  let encryptedPath = basePath & ".enc"
  let decryptedPath = basePath & ".dec"
  let tamperedPath = basePath & ".tampered"

  teardown:
    for path in [plainPath, encryptedPath, decryptedPath, tamperedPath,
                 decryptedPath & ".nimsodium.tmp"]:
      if fileExists(path):
        removeFile(path)

  test "stream key wraps raw bytes":
    let key = generateStreamKey()
    let raw = rawBytes(key)
    check raw.len == StreamKeyBytes
    check rawBytes(streamKeyFromBytes(raw)) == raw
    expect InvalidKeyError:
      discard streamKeyFromBytes("short")

  test "file encryption roundtrip with associated data":
    let key = generateStreamKey()
    let plaintext = "secret" & '\0' & "payload:" & repeat("x", 37)
    writeFile(plainPath, plaintext)

    encryptFile(plainPath, encryptedPath, key, "tenant:42", chunkSize = 7)
    check fileExists(encryptedPath)
    check readFile(encryptedPath) != plaintext

    decryptFile(encryptedPath, decryptedPath, key, "tenant:42", chunkSize = 7)
    check readFile(decryptedPath) == plaintext

  test "empty file encryption roundtrip":
    let key = generateStreamKey()
    writeFile(plainPath, "")

    encryptFile(plainPath, encryptedPath, key, chunkSize = 8)
    decryptFile(encryptedPath, decryptedPath, key, chunkSize = 8)

    check readFile(decryptedPath) == ""

  test "wrong key and associated data are rejected without replacing output":
    let key = generateStreamKey()
    writeFile(plainPath, "secret data")
    writeFile(decryptedPath, "existing")
    encryptFile(plainPath, encryptedPath, key, "expected", chunkSize = 5)

    expect CryptoError:
      decryptFile(encryptedPath, decryptedPath, generateStreamKey(), "expected", chunkSize = 5)
    check readFile(decryptedPath) == "existing"

    expect CryptoError:
      decryptFile(encryptedPath, decryptedPath, key, "different", chunkSize = 5)
    check readFile(decryptedPath) == "existing"

  test "tampered stream ciphertext is rejected":
    let key = generateStreamKey()
    writeFile(plainPath, "secret data")
    encryptFile(plainPath, encryptedPath, key, chunkSize = 6)

    var ciphertext = readFile(encryptedPath)
    ciphertext[^1] = char(ord(ciphertext[^1]) xor 1)
    writeFile(tamperedPath, ciphertext)

    expect CryptoError:
      decryptFile(tamperedPath, decryptedPath, key, chunkSize = 6)
    check not fileExists(decryptedPath)

  test "tampered stream header is rejected":
    let key = generateStreamKey()
    writeFile(plainPath, "secret data")
    encryptFile(plainPath, encryptedPath, key, chunkSize = 6)

    var ciphertext = readFile(encryptedPath)
    ciphertext[0] = char(ord(ciphertext[0]) xor 1)
    writeFile(tamperedPath, ciphertext)

    expect CryptoError:
      decryptFile(tamperedPath, decryptedPath, key, chunkSize = 6)
    check not fileExists(decryptedPath)

  test "short stream ciphertext is rejected":
    let key = generateStreamKey()
    writeFile(encryptedPath, "short")

    expect InvalidInputError:
      decryptFile(encryptedPath, decryptedPath, key)

suite "sealedbox":
  test "sealed box roundtrip":
    let keys = generateBoxKeyPair()
    let plaintext = "secret" & '\0' & "payload"
    let ciphertext = sealBox(plaintext, keys.publicKey)
    check rawBytes(keys.publicKey).len == BoxPublicKeyBytes
    check rawBytes(keys.secretKey).len == BoxSecretKeyBytes
    check ciphertext.len == BoxSealBytes + plaintext.len
    check openBox(ciphertext, keys.publicKey, keys.secretKey) == plaintext

  test "authenticated box roundtrip":
    let sender = generateBoxKeyPair()
    let recipient = generateBoxKeyPair()
    let plaintext = "secret" & '\0' & "payload"
    let ciphertext = encryptBox(plaintext, recipient.publicKey, sender.secretKey)

    check ciphertext.len == BoxNonceBytes + BoxMacBytes + plaintext.len
    check decryptBox(ciphertext, sender.publicKey, recipient.secretKey) == plaintext

  test "authenticated box rejects wrong peer and corruption":
    let sender = generateBoxKeyPair()
    let recipient = generateBoxKeyPair()
    let other = generateBoxKeyPair()
    var ciphertext = encryptBox("secret", recipient.publicKey, sender.secretKey)

    expect CryptoError:
      discard decryptBox(ciphertext, other.publicKey, recipient.secretKey)
    expect CryptoError:
      discard decryptBox(ciphertext, sender.publicKey, other.secretKey)

    ciphertext[^1] = char(ord(ciphertext[^1]) xor 1)
    expect CryptoError:
      discard decryptBox(ciphertext, sender.publicKey, recipient.secretKey)

  test "authenticated box rejects corrupted nonce and short ciphertext":
    let sender = generateBoxKeyPair()
    let recipient = generateBoxKeyPair()
    var ciphertext = encryptBox("secret", recipient.publicKey, sender.secretKey)

    ciphertext[0] = char(ord(ciphertext[0]) xor 1)
    expect CryptoError:
      discard decryptBox(ciphertext, sender.publicKey, recipient.secretKey)

    expect InvalidInputError:
      discard decryptBox("short", sender.publicKey, recipient.secretKey)

  test "sealed box keys support hex and seeded generation":
    let seed = generateBoxSeed()
    let a = generateBoxKeyPair(seed)
    let b = generateBoxKeyPair(boxSeedFromBytes(rawBytes(seed)))

    check rawBytes(seed).len == BoxSeedBytes
    check toHex(seed).len == BoxSeedBytes * 2
    check rawBytes(a.publicKey) == rawBytes(b.publicKey)
    check rawBytes(a.secretKey) == rawBytes(b.secretKey)
    check rawBytes(boxPublicKeyFromHex(toHex(a.publicKey))) == rawBytes(a.publicKey)
    check rawBytes(boxSecretKeyFromHex(toHex(a.secretKey))) == rawBytes(a.secretKey)
    check rawBytes(boxSeedFromHex(toHex(seed))) == rawBytes(seed)
    expect InvalidKeyError:
      discard boxSeedFromBytes("short")
    expect InvalidKeyError:
      discard boxSecretKeyFromBytes("short")
    expect InvalidInputError:
      discard boxPublicKeyFromHex("not hex")

  test "sealed box empty plaintext roundtrip":
    let keys = generateBoxKeyPair()
    let ciphertext = sealBox("", keys.publicKey)
    check ciphertext.len == BoxSealBytes
    check openBox(ciphertext, keys.publicKey, keys.secretKey) == ""

  test "sealed box rejects wrong key and corruption":
    let keys = generateBoxKeyPair()
    let other = generateBoxKeyPair()
    var ciphertext = sealBox("secret", keys.publicKey)
    expect CryptoError:
      discard openBox(ciphertext, other.publicKey, other.secretKey)
    ciphertext[^1] = char(ord(ciphertext[^1]) xor 1)
    expect CryptoError:
      discard openBox(ciphertext, keys.publicKey, keys.secretKey)

  test "sealed box invalid inputs are rejected":
    expect InvalidKeyError:
      discard boxPublicKeyFromBytes("short")
    let keys = generateBoxKeyPair()
    expect InvalidInputError:
      discard openBox("short", keys.publicKey, keys.secretKey)

suite "signatures":
  test "detached signature verifies":
    let keys = generateSigningKeyPair()
    let message = "message" & '\0' & "payload"
    let signature = signDetached(message, keys.secretKey)
    check rawBytes(keys.publicKey).len == SigningPublicKeyBytes
    check rawBytes(keys.secretKey).len == SigningSecretKeyBytes
    check signature.len == SignatureBytes
    check verifyDetached(message, signature, keys.publicKey)

  test "signing keys support hex, seed extraction, and seeded generation":
    let seed = generateSigningSeed()
    let a = generateSigningKeyPair(seed)
    let b = generateSigningKeyPair(signingSeed(a.secretKey))

    check rawBytes(seed).len == SigningSeedBytes
    check toHex(seed).len == SigningSeedBytes * 2
    check rawBytes(a.publicKey) == rawBytes(b.publicKey)
    check rawBytes(a.secretKey) == rawBytes(b.secretKey)
    check rawBytes(signingPublicKey(a.secretKey)) == rawBytes(a.publicKey)
    check rawBytes(signingPublicKeyFromHex(toHex(a.publicKey))) == rawBytes(a.publicKey)
    check rawBytes(signingSecretKeyFromHex(toHex(a.secretKey))) == rawBytes(a.secretKey)
    check rawBytes(signingSeedFromHex(toHex(seed))) == rawBytes(seed)
    expect InvalidKeyError:
      discard signingSeedFromBytes("short")

  test "signed message opens to original message":
    let keys = generateSigningKeyPair()
    let message = "message" & '\0' & "payload"
    var signedMessage = sign(message, keys.secretKey)

    check signedMessage.len == SignatureBytes + message.len
    check openSigned(signedMessage, keys.publicKey) == message
    check openSigned(signedMessage, signingPublicKey(keys.secretKey)) == message

    signedMessage[^1] = char(ord(signedMessage[^1]) xor 1)
    expect CryptoError:
      discard openSigned(signedMessage, keys.publicKey)
    expect InvalidInputError:
      discard openSigned("short", keys.publicKey)

  test "signed message rejects wrong public key":
    let keys = generateSigningKeyPair()
    let other = generateSigningKeyPair()
    let signedMessage = sign("message", keys.secretKey)

    expect CryptoError:
      discard openSigned(signedMessage, other.publicKey)

  test "file detached signature verifies and rejects tampering":
    let path = getCurrentDir() / "tests" / "tmp_signed_file"
    defer:
      if fileExists(path):
        removeFile(path)

    let keys = generateSigningKeyPair()
    writeFile(path, "file" & '\0' & "payload")
    let signature = signFileDetached(path, keys.secretKey)

    check signature.len == SignatureBytes
    check verifyFileDetached(path, signature, keys.publicKey)
    check not verifyFileDetached(path, "short", keys.publicKey)

    writeFile(path, "modified")
    check not verifyFileDetached(path, signature, keys.publicKey)

  test "empty message signature verifies":
    let keys = generateSigningKeyPair()
    let signature = signDetached("", keys.secretKey)
    check verifyDetached("", signature, keys.publicKey)

  test "signature rejects modified message and signature":
    let keys = generateSigningKeyPair()
    var signature = signDetached("message", keys.secretKey)
    check not verifyDetached("different", signature, keys.publicKey)
    signature[^1] = char(ord(signature[^1]) xor 1)
    check not verifyDetached("message", signature, keys.publicKey)

  test "signature invalid inputs are rejected":
    let keys = generateSigningKeyPair()
    expect InvalidKeyError:
      discard signingSecretKeyFromBytes("short")
    expect InvalidKeyError:
      discard signingPublicKeyFromBytes("short")
    expect InvalidInputError:
      discard signingPublicKeyFromHex("not hex")
    expect InvalidKeyError:
      discard signingSecretKeyFromHex(toHex("short"))
    check not verifyDetached("message", "short", keys.publicKey)

suite "wallet workflows":
  test "wallet secret protection roundtrip keeps label as associated data":
    let secret = walletSecretFromBytes("seed" & '\0' & "material")
    let protected = protectWalletSecret(secret, "passphrase", "wallet:primary")
    let opened = openProtectedWalletSecret(protected, "passphrase", "wallet:primary")

    check rawBytes(opened) == "seed" & '\0' & "material"
    check rawBytes(protected).len > rawBytes(secret).len

    expect CryptoError:
      discard openProtectedWalletSecret(protected, "wrong passphrase", "wallet:primary")
    expect CryptoError:
      discard openProtectedWalletSecret(protected, "passphrase", "wallet:other")

  test "wallet secret generation and invalid inputs":
    let secret = generateWalletSecret()
    check rawBytes(secret).len == DefaultWalletSecretBytes
    check generateWalletSecret(48).rawBytes().len == 48

    expect InvalidInputError:
      discard walletSecretFromBytes("")
    expect ValueError:
      discard generateWalletSecret(0)
    expect InvalidInputError:
      discard protectedWalletSecretFromBytes("")

  test "wallet secret file protection rejects wrong label without replacing output":
    let basePath = getCurrentDir() / "tests" / "tmp_wallet_secret"
    let plainPath = basePath & ".plain"
    let encryptedPath = basePath & ".enc"
    let outPath = basePath & ".out"
    defer:
      for path in [plainPath, encryptedPath, outPath]:
        if fileExists(path):
          removeFile(path)

    writeFile(plainPath, "wallet-file-secret" & '\0' & "payload")
    encryptWalletSecretFile(plainPath, encryptedPath, "passphrase", "wallet:file")
    writeFile(outPath, "existing")

    expect CryptoError:
      decryptWalletSecretFile(encryptedPath, outPath, "passphrase", "wallet:other")
    check readFile(outPath) == "existing"

    decryptWalletSecretFile(encryptedPath, outPath, "passphrase", "wallet:file")
    check readFile(outPath) == "wallet-file-secret" & '\0' & "payload"

  test "off-chain signatures are domain separated":
    let keys = generateSigningKeyPair()
    let signature = signOffchainMessage("approve payload", "example-wallet", keys.secretKey)

    check signature.len == SignatureBytes
    check verifyOffchainMessage("approve payload", "example-wallet", signature, keys.publicKey)
    check not verifyOffchainMessage("approve payload", "other-domain", signature, keys.publicKey)
    check not verifyOffchainMessage("other payload", "example-wallet", signature, keys.publicKey)
    check not verifyDetached("approve payload", signature, keys.publicKey)
    expect InvalidInputError:
      discard signOffchainMessage("message", "", keys.secretKey)
    check not verifyOffchainMessage("message", "", signature, keys.publicKey)

suite "version":
  test "libsodium version is available":
    check sodiumVersion().len > 0
    check sodiumVersionMajor() >= 0
    check sodiumVersionMinor() >= 0

suite "advanced":
  test "key exchange derives matching client and server session keys":
    let client = generateKeyExchangeKeyPair()
    let server = generateKeyExchangeKeyPair()

    let clientKeys = clientSessionKeys(
      client.publicKey,
      client.secretKey,
      server.publicKey
    )
    let serverKeys = serverSessionKeys(
      server.publicKey,
      server.secretKey,
      client.publicKey
    )

    check rawBytes(client.publicKey).len == KeyExchangePublicKeyBytes
    check rawBytes(client.secretKey).len == KeyExchangeSecretKeyBytes
    check rawBytes(clientKeys.receiveKey).len == KeyExchangeSessionKeyBytes
    check rawBytes(clientKeys.receiveKey) == rawBytes(serverKeys.transmitKey)
    check rawBytes(clientKeys.transmitKey) == rawBytes(serverKeys.receiveKey)
    check rawBytes(clientKeys.receiveKey) != rawBytes(clientKeys.transmitKey)

  test "key exchange rejects invalid key bytes":
    expect InvalidKeyError:
      discard keyExchangePublicKeyFromBytes("short")
    expect InvalidKeyError:
      discard keyExchangeSecretKeyFromBytes("short")

  test "short hash is keyed and stable":
    let key = generateShortHashKey()
    let other = generateShortHashKey()

    check rawBytes(key).len == ShortHashKeyBytes
    check shortHash("table-key", key).len == ShortHashBytes
    check shortHash("table-key", key) == shortHash("table-key", key)
    check shortHash("table-key", key) != shortHash("table-key", other)
    check shortHashHex("table-key", key).len == ShortHashBytes * 2

  test "short hash rejects invalid key bytes":
    expect InvalidKeyError:
      discard shortHashKeyFromBytes("short")

  test "padding roundtrip":
    let message = "secret" & '\0' & "payload"
    let padded = padMessage(message, 16)

    check padded.len mod 16 == 0
    check padded.len > message.len
    check unpadMessage(padded, 16) == message
    check unpadMessage(padMessage("", 16), 16) == ""

  test "padding rejects invalid input":
    expect ValueError:
      discard padMessage("message", 0)
    expect ValueError:
      discard unpadMessage("message", 0)
    expect InvalidInputError:
      discard unpadMessage("not padded", 16)

  test "detached AEAD roundtrip and authentication failures":
    let key = generateAeadKey()
    let plaintext = "secret" & '\0' & "payload"
    let detached = encryptAeadDetached(plaintext, key, "record:42")

    check detached.nonce.len == AeadNonceBytes
    check detached.ciphertext.len == plaintext.len
    check detached.mac.len == AeadMacBytes
    check decryptAeadDetached(detached, key, "record:42") == plaintext

    expect CryptoError:
      discard decryptAeadDetached(detached, key, "record:43")

    var tampered = detached
    tampered.ciphertext[^1] = char(ord(tampered.ciphertext[^1]) xor 1)
    expect CryptoError:
      discard decryptAeadDetached(tampered, key, "record:42")

  test "detached AEAD rejects invalid parts":
    expect InvalidInputError:
      discard detachedAeadCiphertextFromParts("short", "", repeat("m", AeadMacBytes))
    expect InvalidInputError:
      discard detachedAeadCiphertextFromParts(repeat("n", AeadNonceBytes), "", "short")

  test "detached secretbox roundtrip and authentication failures":
    let key = generateSecretBoxKey()
    let plaintext = "secret" & '\0' & "payload"
    let detached = encryptSecretBoxDetached(plaintext, key)

    check detached.nonce.len == SecretBoxNonceBytes
    check detached.ciphertext.len == plaintext.len
    check detached.mac.len == SecretBoxMacBytes
    check decryptSecretBoxDetached(detached, key) == plaintext

    expect CryptoError:
      discard decryptSecretBoxDetached(detached, generateSecretBoxKey())

    var tampered = detached
    tampered.mac[^1] = char(ord(tampered.mac[^1]) xor 1)
    expect CryptoError:
      discard decryptSecretBoxDetached(tampered, key)

  test "detached secretbox rejects invalid parts":
    expect InvalidInputError:
      discard detachedSecretBoxCiphertextFromParts("short", "", repeat("m", SecretBoxMacBytes))
    expect InvalidInputError:
      discard detachedSecretBoxCiphertextFromParts(repeat("n", SecretBoxNonceBytes), "", "short")

  test "one-time authentication verifies and rejects modifications":
    let key = generateOneTimeAuthKey()
    let tag = oneTimeAuthenticate("message", key)

    check rawBytes(key).len == OneTimeAuthKeyBytes
    check tag.len == OneTimeAuthBytes
    check verifyOneTimeAuthentication("message", tag, key)
    check not verifyOneTimeAuthentication("different", tag, key)
    check not verifyOneTimeAuthentication("message", tag, generateOneTimeAuthKey())
    check not verifyOneTimeAuthentication("message", "short", key)

  test "one-time authentication rejects invalid key bytes":
    expect InvalidKeyError:
      discard oneTimeAuthKeyFromBytes("short")
