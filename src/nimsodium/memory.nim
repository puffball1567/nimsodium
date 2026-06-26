import ./private/internal/init
import ./private/raw/sodium

proc secureZero*(data: var string) =
  ## Overwrites a string's current buffer with zero bytes.
  ##
  ## This only affects this string instance. Nim or application code may have
  ## created copies before this call.
  init.ensureInitialized()

  if data.len > 0:
    prepareMutation(data)
    sodium.Sodium.sodium_memzero(addr data[0], csize_t(data.len))

proc secureClear*(data: var string) =
  ## Overwrites a string's current buffer with zero bytes, then sets its length
  ## to zero.
  ##
  ## This only affects this string instance. Nim or application code may have
  ## created copies before this call.
  secureZero(data)
  data.setLen(0)
