import ./base64
import ./compare
import ./encoding
import ./errors
import ./hash

type
  TokenFingerprint* = distinct string

proc rawBytes*(fingerprint: TokenFingerprint): string =
  ## Returns the raw fingerprint bytes for storage by the application.
  string(fingerprint)

proc tokenFingerprintFromBytes*(fingerprint: string): TokenFingerprint =
  ## Wraps an existing token fingerprint.
  if fingerprint.len != GenericHashBytes:
    raise newException(
      InvalidInputError,
      "token fingerprint must be " & $GenericHashBytes & " bytes"
    )
  TokenFingerprint(fingerprint)

proc tokenFingerprintToHex*(fingerprint: TokenFingerprint): string =
  ## Encodes a token fingerprint as hexadecimal for storage.
  rawBytes(fingerprint).toHex()

proc tokenFingerprintFromHex*(hex: string): TokenFingerprint =
  ## Decodes a token fingerprint from hexadecimal.
  tokenFingerprintFromBytes(fromHex(hex))

proc generateToken*(length = 32): string =
  ## Generates a URL-safe base64 token.
  ##
  ## The length is measured in random bytes before base64 encoding.
  randomBase64(length)

proc fingerprintToken*(token: string; key: KeyedHashKey): TokenFingerprint =
  ## Computes a keyed token fingerprint for server-side storage.
  TokenFingerprint(keyedHash(token, key))

proc fingerprintTokenHex*(token: string; key: KeyedHashKey): string =
  ## Computes a keyed token fingerprint and returns hexadecimal storage text.
  tokenFingerprintToHex(fingerprintToken(token, key))

proc verifyTokenFingerprint*(
    token: string; fingerprint: TokenFingerprint; key: KeyedHashKey
): bool =
  ## Verifies a token against a stored keyed fingerprint.
  constantTimeEquals(rawBytes(fingerprintToken(token, key)), rawBytes(fingerprint))

proc verifyTokenFingerprintHex*(
    token, fingerprintHex: string; key: KeyedHashKey
): bool =
  ## Verifies a token against a stored hexadecimal keyed fingerprint.
  try:
    verifyTokenFingerprint(token, tokenFingerprintFromHex(fingerprintHex), key)
  except InvalidInputError:
    false
