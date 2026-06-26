proc unsafeAddr*(s: string): pointer =
  if s.len == 0:
    nil
  else:
    unsafeAddr s[0]

proc unsafeCString*(s: string): cstring =
  if s.len == 0:
    nil
  else:
    cast[cstring](unsafeAddr s[0])
