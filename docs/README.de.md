# nimsodium Deutscher Leitfaden

`nimsodium` ist ein standardmäßig sicherer libsodium-Wrapper für Nim-Anwendungen.

Verwenden Sie ihn für Passwort-Hashing, Token-Fingerprints, authentifizierte Verschlüsselung, Dateiverschlüsselung, Public-Key-Sealed-Boxes oder Signaturen, ohne Nonces, MAC-Tags, Ausgabepuffer oder rohe Rückgabecodes direkt zu verwalten.

Wenn Sie direkten Zugriff auf die gesamte C-API von libsodium benötigen, ist ein Raw-Binding die passendere Wahl. `nimsodium` ist eine High-Level-API für Anwendungen, kein vollständiges Binding.

## Warum nimsodium?

- Nonces werden intern erzeugt und zusammen mit dem Ciphertext gespeichert.
- Schlüsselmaterial nutzt in der öffentlichen API eigene Nim-Typen statt einfacher Strings.
- Praktische Abdeckung: Passwörter, Tokens, AEAD, Dateiverschlüsselung, Public-Key-Verschlüsselung, Signaturen, KDF, Zufallswerte, Encoding und Cleanup.
- Die kryptografischen Primitive werden an libsodium delegiert.
- Tests, Beispiele, Audit-Notizen, Security Policy und Third-Party Notices sind enthalten.

## Installation

libsodium muss für den C-Linker verfügbar sein.

Ubuntu/Debian:

```sh
sudo apt-get install libsodium-dev
```

macOS:

```sh
brew install libsodium
```

Prüfung:

```sh
pkg-config --modversion libsodium
```

Nach der Veröffentlichung fügen Sie `nimsodium` Ihrem Nimble-Projekt hinzu.

## Status

Das Projekt ist eine `v0.2`-Vorabversion. Es ist für Evaluation und frühe Nutzung gedacht, aber API-Namen und gespeicherte Formate können sich bis `v1.0` noch ändern. Das rohe libsodium-FFI ist ein Implementierungsdetail und keine öffentliche API.

## Mitwirken

Der [Leitfaden zum Mitwirken](CONTRIBUTING.de.md) beschreibt Beiträge zu zusätzlichen Tests, Funktionsprüfungen, Bugfixes auf Basis solcher Berichte, Übersetzungen, Dokumentation und Beispielen.

## Schnellstart

```nim
import nimsodium

let passwordHash = hashPassword("correct horse battery staple")
doAssert verifyPassword(passwordHash, "correct horse battery staple")

let key = generateAeadKey()
let ciphertext = encryptAead("secret payload", key, "record:42")
doAssert decryptAead(ciphertext, key, "record:42") == "secret payload"

let token = randomBase64(32)
let hashKey = generateKeyedHashKey()
let fingerprint = keyedHashHex(token, hashKey)
```

Ausführen:

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
```

## Welche API sollte ich verwenden?

```text
Aufgabe                                      API
Passwörter speichern                         hashPassword / verifyPassword
API-Keys oder Session-Tokens erzeugen        randomBase64 / randomHex
Token-Fingerprints speichern                 generateKeyedHashKey / keyedHashHex
Datenbankfelder verschlüsseln                generateAeadKey / encryptAead / decryptAead
Kleine lokale Secrets verschlüsseln          generateSecretBoxKey / encryptSecretBox / decryptSecretBox
Große Dateien verschlüsseln                  generateStreamKey / encryptFile / decryptFile
An einen öffentlichen Schlüssel verschlüsseln generateBoxKeyPair / sealBox / openBox
Nachrichten signieren und prüfen             generateSigningKeyPair / signDetached / verifyDetached
Zweckgebundene Subkeys ableiten              generateKdfKey / deriveKey
Geheime Werte vergleichen                    constantTimeEquals
Aktuellen String-Buffer löschen              secureZero / secureClear
Binärdaten encodieren                        toHex / fromHex / toBase64 / fromBase64
```

Advanced APIs sind opt-in mit `import nimsodium/advanced`.

```text
Client/Server-Session-Keys ableiten      generateKeyExchangeKeyPair / clientSessionKeys / serverSessionKeys
Kurze keyed Identifier berechnen         generateShortHashKey / shortHashHex
Vor Verschlüsselung padden               padMessage / unpadMessage
Detached AEAD-Felder verarbeiten          encryptAeadDetached / decryptAeadDetached
Detached secretbox-Felder verarbeiten     encryptSecretBoxDetached / decryptSecretBoxDetached
One-time Message Authentication           generateOneTimeAuthKey / oneTimeAuthenticate / verifyOneTimeAuthentication
```

## Hinweise für den Betrieb

- Installieren und aktualisieren Sie libsodium über Ihr Betriebssystem oder einen vertrauenswürdigen Paketmanager.
- Nutzen Sie `sodiumVersion()` für Diagnosen oder Start-Logs.
- Speichern Sie Schlüssel nicht im Quellcode und nicht in Logs.
- Verwenden Sie `rawBytes` nur, wenn ein Schlüssel persistiert oder übertragen werden muss, und schützen Sie ihn mit Ihrem Key-Management.
- Associated data sind Teil des Protokolls. Beim Entschlüsseln muss exakt derselbe Wert verwendet werden wie beim Verschlüsseln.
- Behandeln Sie `CryptoError` als Authentifizierungsfehler, nicht als wiederherstellbaren Plaintext.
- Legen Sie `THIRD_PARTY_NOTICES.md` und `licenses/` bei Weiterverteilung bei.

## Grenzen

- `0.x`-Versionen können noch Namen und Typen ändern.
- `src/nimsodium/private/raw/` ist keine unterstützte API.
- `secureZero` und `secureClear` löschen nur den aktuellen String-Buffer. Kopien, die Nim oder die Anwendung bereits erstellt haben, werden nicht gelöscht.
