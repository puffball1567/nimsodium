# Leitfaden zum Mitwirken

`nimsodium` soll klein, high-level und schwer falsch zu verwenden bleiben.

Beiträge sind willkommen, besonders zusätzliche Tests, Dokumentation, Beispiele, Berichte zur Funktionsprüfung auf verschiedenen OS/Nim/libsodium-Kombinationen, CI-Verbesserungen, Packaging-Fixes und Wartungsupdates. Berichte über beobachtetes Verhalten und Bugfixes auf Basis solcher Berichte sind ebenfalls willkommen.

## Gute Einstiege

- Beispiele für bestehende Workflows verbessern
- Tests für fehlerhafte Eingaben und Fehlerpfade ergänzen
- Installation und Tests auf einem OS, einer Nim-Version oder einer libsodium-Version prüfen
- Dokumentation, Übersetzungen oder Release Notes verbessern
- Known-answer tests aus stabilen Upstream-Referenzen ergänzen
- Wartungsnotizen fur neue libsodium- oder Nim-Releases aktualisieren

## Sicherheitsrelevante Änderungen

Öffnen Sie zuerst ein Issue oder eine Design-Notiz, bevor Sie Folgendes ändern:

- Form der offentlichen kryptografischen API
- gespeicherte Binärformate
- Parameter für Passwortverschlüsselung
- Umgang mit Nonces, Salts, Tags oder Headern
- Key-derivation contexts oder Verhalten typisierter Schlüssel
- rohe FFI-Deklarationen
- Verhalten bei Authentifizierungsfehlern
- Ersetzen von Ausgabedateien

Senden Sie sicherheitsrelevante Änderungen nicht als beiläufiges Refactoring. Beschreiben Sie den Anwendungsfall, die verwendeten rohen libsodium-Symbole, erwartete Fehlerfälle und die Tests, die Fehlverwendung erschweren.

## Designregeln

- Keine eigene Kryptografie erfinden.
- Nicht die komplette rohe libsodium-API als Haupt-API freigeben.
- Nutzer für typische Aufgaben keine Nonces, MAC-Tags oder Ausgabepuffer verwalten lassen.
- Für Passwortspeicherung keinen generischen Hash verwenden.
- Bei fehlgeschlagener Authentifizierung keinen Plaintext zurückgeben.
- Für neue öffentliche High-Level-APIs keine string-basierten Key-Parameter ergänzen. Verwenden Sie einen eigenen Schlüsseltyp und einen geprüften Konstruktor.
- Jeden fehlbaren libsodium-Rückgabecode prüfen.
- Package-spezifische Exceptions aus `nimsodium/errors.nim` werfen.
- Sichere Workflow-Abdeckung vor rohe Symbolabdeckung stellen.

## Tests

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
```

Vor einem Release auch die Dokumentation generieren.

```sh
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

Für mögliche Schwachstellen folgen Sie der [Security Policy](../SECURITY.md). Echte Secrets, Tokens, Passwörter oder private Schlüssel gehören nicht in Issues oder Pull Requests.
