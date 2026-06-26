# Guide de contribution

`nimsodium` doit rester petit, de haut niveau et difficile à mal utiliser.

Les contributions sont bienvenues, en particulier l'ajout de tests, la documentation, les exemples, les rapports de vérification sur différentes combinaisons OS/Nim/libsodium, les améliorations CI, les corrections de packaging et les mises à jour de maintenance. Les rapports de comportement observé et les corrections de bugs issues de ces rapports sont aussi les bienvenus.

## Contributions accessibles

- améliorer les exemples pour les workflows existants
- ajouter des tests pour les entrées invalides et les chemins d'échec
- vérifier l'installation et les tests sur un OS, une version de Nim ou une version de libsodium
- améliorer la documentation, les traductions ou les notes de version
- ajouter des known-answer tests depuis des references upstream stables
- mettre à jour les notes de maintenance pour une nouvelle version de libsodium ou de Nim

## Changements sensibles pour la sécurité

Ouvrez d'abord une issue ou une note de conception avant de modifier:

- la forme de l'API cryptographique publique
- les formats binaires stockés
- les paramètres de chiffrement par mot de passe
- la gestion des nonces, salts, tags ou headers
- les contextes de dérivation de clé ou le comportement des clés typées
- les déclarations FFI brutes
- le comportement en cas d'échec d'authentification
- le remplacement des fichiers de sortie

N'envoyez pas un changement sensible pour la sécurité comme un simple refactor. Expliquez le cas d'usage, les symboles libsodium bruts utilisés, les modes d'échec attendus et les tests qui prouvent la résistance aux erreurs d'utilisation.

## Regles de conception

- N'inventez pas de cryptographie.
- N'exposez pas toute l'API brute de libsodium comme API principale.
- Ne demandez pas aux utilisateurs de gérer les nonces, tags MAC ou buffers de sortie pour les usages courants.
- N'utilisez pas de hash générique pour stocker des mots de passe.
- Ne retournez jamais de plaintext apres un echec d'authentification.
- Pour les nouvelles API publiques de haut niveau, n'ajoutez pas de paramètres de clé en string. Utilisez un type de clé distinct et un constructeur vérifié.
- Vérifiez chaque code de retour libsodium qui peut échouer.
- Levez les exceptions propres au package depuis `nimsodium/errors.nim`.
- Privilégiez la couverture des workflows sûrs plutôt que la couverture des symboles bruts.

## Tests

```sh
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium.nim
nim check --path:src --nimcache:/tmp/nimsodium_nimcache src/nimsodium/advanced.nim
nim c -r --path:src --nimcache:/tmp/nimsodium_nimcache tests/test_nimsodium.nim
env NIMBLE_DIR=/tmp/nimble nimble check
```

Avant une release, vérifiez aussi la génération de documentation.

```sh
nim doc --project --index:on --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium.nim
nim doc --outdir:/tmp/nimsodium_htmldocs --path:src src/nimsodium/advanced.nim
```

Pour un problème qui pourrait être une vulnérabilité, suivez la [Security Policy](../SECURITY.md). N'incluez pas de vrais secrets, tokens, mots de passe ou clés privées dans les issues ou pull requests.
