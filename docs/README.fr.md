# Guide français de nimsodium

`nimsodium` est un wrapper libsodium sûr par défaut pour les applications Nim.

Utilisez-le pour le hachage de mots de passe, les empreintes de jetons, le chiffrement authentifié, le chiffrement de fichiers, les sealed boxes à clé publique ou les signatures, sans gérer directement les nonces, les tags MAC, les buffers de sortie ni les codes de retour bruts.

Si vous avez besoin d'un accès direct à toute l'API C de libsodium, utilisez plutôt un binding brut. `nimsodium` est une API applicative de haut niveau, pas un binding complet.

## Pourquoi nimsodium ?

- Les nonces sont générés en interne et stockés avec les ciphertexts.
- Les clés exposées par l'API publique utilisent des types Nim distincts au lieu de simples strings.
- Couverture pratique : mots de passe, jetons, AEAD, chiffrement de fichiers, chiffrement à clé publique, signatures, KDF, valeurs aléatoires, encodage et nettoyage.
- Les primitives cryptographiques sont déléguées à libsodium.
- Tests, exemples, notes d'audit, politique de sécurité et notices tierces sont inclus.

## Installation

libsodium doit être disponible pour le linker C.

Ubuntu/Debian:

```sh
sudo apt-get install libsodium-dev
```

macOS:

```sh
brew install libsodium
```

Vérification:

```sh
pkg-config --modversion libsodium
```

Après publication, ajoutez `nimsodium` à votre projet Nimble.

## Statut

Le projet est en préversion `v0.2`. Il est destiné à l'évaluation et à l'adoption précoce, mais les noms d'API et les formats stockés peuvent encore changer avant `v1.0`. Le FFI brut vers libsodium est un détail d'implémentation, pas une API publique.

## Contributions

Le [guide de contribution](CONTRIBUTING.fr.md) explique comment contribuer avec des tests supplémentaires, des rapports de vérification, des corrections de bugs issues de ces rapports, des traductions, de la documentation et des exemples.

## Démarrage rapide

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

Exécution:

```sh
nim c -r --path:src --nimcache:/tmp/nimsodium_example_quickstart examples/quickstart.nim
```

## Quelle API utiliser ?

```text
Besoin                                    API
Stocker des mots de passe                 hashPassword / verifyPassword
Générer des API keys ou jetons de session randomBase64 / randomHex
Stocker des empreintes de jetons          generateKeyedHashKey / keyedHashHex
Chiffrer des champs de base de données    generateAeadKey / encryptAead / decryptAead
Chiffrer de petits secrets locaux         generateSecretBoxKey / encryptSecretBox / decryptSecretBox
Chiffrer de gros fichiers                 generateStreamKey / encryptFile / decryptFile
Chiffrer vers une clé publique            generateBoxKeyPair / sealBox / openBox
Signer et vérifier des messages           generateSigningKeyPair / signDetached / verifyDetached
Dériver des sous-clés par usage           generateKdfKey / deriveKey
Comparer des valeurs secrètes             constantTimeEquals
Effacer le buffer string courant          secureZero / secureClear
Encoder des données binaires              toHex / fromHex / toBase64 / fromBase64
```

Les API avancées sont opt-in avec `import nimsodium/advanced`.

```text
Dériver des clés de session client/serveur generateKeyExchangeKeyPair / clientSessionKeys / serverSessionKeys
Calculer des identifiants courts signés    generateShortHashKey / shortHashHex
Ajouter du padding avant chiffrement       padMessage / unpadMessage
Gérer des champs AEAD détachés             encryptAeadDetached / decryptAeadDetached
Gérer des champs secretbox détachés        encryptSecretBoxDetached / decryptSecretBoxDetached
Authentification de message à usage unique generateOneTimeAuthKey / oneTimeAuthenticate / verifyOneTimeAuthentication
```

## Notes de production

- Installez et mettez à jour libsodium via votre OS ou un gestionnaire de paquets fiable.
- Utilisez `sodiumVersion()` dans les diagnostics ou les logs de démarrage.
- Ne stockez pas les clés dans le code source ni dans les logs.
- Utilisez `rawBytes` uniquement lorsqu'une clé doit être persistée ou transmise, puis protégez-la avec votre mécanisme de gestion de clés.
- Les associated data font partie du protocole. Le déchiffrement doit utiliser exactement la même valeur que le chiffrement.
- Traitez `CryptoError` comme un échec d'authentification, pas comme du plaintext récupérable.
- Incluez `THIRD_PARTY_NOTICES.md` et `licenses/` lors d'une redistribution.

## Limites

- Les versions `0.x` peuvent encore modifier des noms ou des types.
- `src/nimsodium/private/raw/` n'est pas une API prise en charge.
- `secureZero` et `secureClear` n'effacent que le buffer string courant. Les copies déjà créées par Nim ou l'application ne sont pas effacées.
