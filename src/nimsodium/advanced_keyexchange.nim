import ./errors
import ./private/internal/[bytes, init]
import ./private/raw/sodium

const
  KeyExchangePublicKeyBytes* = sodium.crypto_kx_PUBLICKEYBYTES
  KeyExchangeSecretKeyBytes* = sodium.crypto_kx_SECRETKEYBYTES
  KeyExchangeSessionKeyBytes* = sodium.crypto_kx_SESSIONKEYBYTES

type
  KeyExchangePublicKey* = distinct string
  KeyExchangeSecretKey* = distinct string
  KeyExchangeKeyPair* = object
    publicKey*: KeyExchangePublicKey
    secretKey*: KeyExchangeSecretKey

  ReceiveSessionKey* = distinct string
  TransmitSessionKey* = distinct string
  SessionKeys* = object
    receiveKey*: ReceiveSessionKey
    transmitKey*: TransmitSessionKey

proc rawBytes*(key: KeyExchangePublicKey): string =
  ## Returns the raw bytes for storage or transport by the application.
  string(key)

proc rawBytes*(key: KeyExchangeSecretKey): string =
  ## Returns the raw bytes for storage by the application.
  string(key)

proc rawBytes*(key: ReceiveSessionKey): string =
  ## Returns the raw bytes for use as symmetric key material.
  string(key)

proc rawBytes*(key: TransmitSessionKey): string =
  ## Returns the raw bytes for use as symmetric key material.
  string(key)

proc keyExchangePublicKeyFromBytes*(key: string): KeyExchangePublicKey =
  ## Wraps an existing key exchange public key.
  if key.len != KeyExchangePublicKeyBytes:
    raise newException(
      InvalidKeyError,
      "key exchange public key must be " & $KeyExchangePublicKeyBytes & " bytes"
    )
  KeyExchangePublicKey(key)

proc keyExchangeSecretKeyFromBytes*(key: string): KeyExchangeSecretKey =
  ## Wraps an existing key exchange secret key.
  if key.len != KeyExchangeSecretKeyBytes:
    raise newException(
      InvalidKeyError,
      "key exchange secret key must be " & $KeyExchangeSecretKeyBytes & " bytes"
    )
  KeyExchangeSecretKey(key)

proc generateKeyExchangeKeyPair*(): KeyExchangeKeyPair =
  ## Returns a new key pair for deriving client/server session keys.
  init.ensureInitialized()

  var publicKey = newString(KeyExchangePublicKeyBytes)
  var secretKey = newString(KeyExchangeSecretKeyBytes)
  let rc = sodium.Sodium.crypto_kx_keypair(
    bytes.unsafeCString(publicKey),
    bytes.unsafeCString(secretKey)
  )
  if rc != 0:
    raise newException(CryptoError, "key exchange key pair generation failed")

  result.publicKey = KeyExchangePublicKey(publicKey)
  result.secretKey = KeyExchangeSecretKey(secretKey)

proc clientSessionKeys*(
  clientPublicKey: KeyExchangePublicKey;
  clientSecretKey: KeyExchangeSecretKey;
  serverPublicKey: KeyExchangePublicKey
): SessionKeys =
  ## Derives receive/transmit keys for the client side of a connection.
  init.ensureInitialized()

  var receiveKey = newString(KeyExchangeSessionKeyBytes)
  var transmitKey = newString(KeyExchangeSessionKeyBytes)
  let rc = sodium.Sodium.crypto_kx_client_session_keys(
    bytes.unsafeCString(receiveKey),
    bytes.unsafeCString(transmitKey),
    bytes.unsafeCString(string(clientPublicKey)),
    bytes.unsafeCString(string(clientSecretKey)),
    bytes.unsafeCString(string(serverPublicKey))
  )
  if rc != 0:
    raise newException(CryptoError, "client key exchange failed")

  result.receiveKey = ReceiveSessionKey(receiveKey)
  result.transmitKey = TransmitSessionKey(transmitKey)

proc serverSessionKeys*(
  serverPublicKey: KeyExchangePublicKey;
  serverSecretKey: KeyExchangeSecretKey;
  clientPublicKey: KeyExchangePublicKey
): SessionKeys =
  ## Derives receive/transmit keys for the server side of a connection.
  init.ensureInitialized()

  var receiveKey = newString(KeyExchangeSessionKeyBytes)
  var transmitKey = newString(KeyExchangeSessionKeyBytes)
  let rc = sodium.Sodium.crypto_kx_server_session_keys(
    bytes.unsafeCString(receiveKey),
    bytes.unsafeCString(transmitKey),
    bytes.unsafeCString(string(serverPublicKey)),
    bytes.unsafeCString(string(serverSecretKey)),
    bytes.unsafeCString(string(clientPublicKey))
  )
  if rc != 0:
    raise newException(CryptoError, "server key exchange failed")

  result.receiveKey = ReceiveSessionKey(receiveKey)
  result.transmitKey = TransmitSessionKey(transmitKey)
