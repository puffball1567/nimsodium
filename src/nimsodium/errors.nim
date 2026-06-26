type
  NimsodiumError* = object of CatchableError
    ## Base exception for nimsodium failures.

  SodiumInitError* = object of NimsodiumError
    ## Raised when libsodium cannot be initialized.

  CryptoError* = object of NimsodiumError
    ## Raised when a cryptographic operation fails.

  InvalidKeyError* = object of CryptoError
    ## Raised when a key has the wrong length.

  InvalidInputError* = object of NimsodiumError
    ## Raised when encoded or structured input is invalid.
