# quarkus-brotli-audit

> Audit préventif de l'exposition d'une application **Quarkus** au décodeur **Brotli** vulnérable
> (**CVE-2026-111497**), par analyse **statique** de configuration et de code.

[![CI](https://github.com/hayupisama/quarkus-brotli-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/hayupisama/quarkus-brotli-audit/actions/workflows/ci.yml)

> 🤖 **Projet généré avec [Claude Code](https://claude.com/claude-code)** (assistant IA d'Anthropic),
> à partir d'une investigation pas-à-pas de la chaîne de (dé)compression Quarkus/Vert.x/Netty. Voir
> [`NOTICE`](NOTICE). Relisez le code avant tout usage en production : vous en restez responsable.

---

## Pourquoi cet outil

`brotli4j` (le wrapper Java de Brotli embarqué par de nombreuses extensions Quarkus) est vulnérable à
CVE-2026-111497 jusqu'à la version **1.23.0** incluse (écriture hors-limites dans le décodeur natif,
corrigée en **1.24.0**). Mais **la simple présence** de la dépendance ne rend pas l'application
exploitable : encore faut-il qu'un **décodeur Brotli soit effectivement câblé** et atteignable par une
entrée non fiable.

Cet outil répond à une question précise, utile pour **documenter une dérogation** en attendant la mise à
jour :

> « Au regard des configurations et des chemins d'activation analysés, l'application permet-elle
> actuellement d'**atteindre** le décodeur Brotli vulnérable, ou peut-on montrer que ces chemins sont
> **neutralisés** ? »

> ⚠️ **Ce que l'outil NE fait PAS.** Il ne reproduit pas la CVE, ne génère aucun flux déclencheur, et
> **ne prouve pas l'inexploitabilité**. Un `PASS` signifie seulement : « les chemins **analysés** sont
> neutralisés **dans le périmètre audité** ». Ce n'est **pas** un certificat d'immunité.

## Installation / prérequis

- Python **3.8+** (bibliothèque standard uniquement). `PyYAML` est utilisé **s'il est présent** pour une
  analyse YAML complète ; sinon un parseur minimal prend le relais (YAML complexes → `INCONCLUSIVE`).

```bash
git clone https://github.com/hayupisama/quarkus-brotli-audit.git
cd quarkus-brotli-audit
python brotli_audit.py /chemin/vers/mon-app-quarkus
```

## Utilisation

```bash
# Audit du projet courant -> target/brotli-security-audit.{md,json}
python brotli_audit.py .

# Auditer un autre dépôt, sortie ailleurs
python brotli_audit.py /chemin/app --out-dir /tmp/audit

# Déclarer que la config de PRODUCTION a été vérifiée et est reflétée dans le dépôt
python brotli_audit.py . --prod-config-available
```

### Codes de sortie (pour la CI)

| Code | Statut | Sens |
|---|---|---|
| 0 | `PASS` | Chemins analysés neutralisés dans le périmètre audité |
| 2 | `FAIL` | Au moins un chemin d'activation présent/activé |
| 3 | `INCONCLUSIVE` | Information manquante (config prod, env, activation dynamique, client non audité…) |

## Ce qui est contrôlé

1. **Serveur entrant** — `quarkus.http.enable-decompression` (défaut `false`).
2. **REST clients** — résolution effective **par client**, selon l'ordre **vérifié sur le code source
   Quarkus 3.33.x–3.40.x** :
   `builder.enableCompression(...)` **>** `rest-client."<clé>".enable-response-decompression`
   **>** `rest-client.enable-compression` (global) **>** fallback `quarkus.http.enable-compression`.
3. **Activation programmatique** — `enableCompression(true)`, `setDecompressionSupported(true)`,
   `HttpContentDecompressor`, `BrotliDecoder`, usage direct de l'API `brotli4j` (hors tests).
4. **Support Brotli (compression)** — `br` dans `quarkus.http.compressors` : signalé **séparément**
   (compression ≠ décodeur vulnérable accessible), non bloquant en soi.
5. **Sources de config externes** — `application.properties/yaml`, profils `%prof`, Dockerfile,
   docker-compose, manifests Kubernetes, ConfigMaps, Helm `values*.yaml`, scripts `.sh/.env`.
6. **Autres clients HTTP** — Vert.x `WebClient`/`HttpClient` direct, OkHttp, Apache HttpClient, JDK
   HttpClient → `INCONCLUSIVE` (ils n'héritent pas du fallback Quarkus et s'auditent à part).

## Règles de décision (garde-fous)

- **Jamais** « propriété absente » = `false` : l'absence suit la vraie règle de résolution (fallback inclus).
- **Jamais** `INCONCLUSIVE → PASS`. Une information manquante ne devient pas une garantie.
- Sans `--prod-config-available`, le statut global plafonne à `INCONCLUSIVE` (une valeur `false` locale peut
  être surchargée en production par une variable d'environnement / un ConfigMap).
- `enableCompression(<variable>)` non résolvable statiquement → `INCONCLUSIVE`, pas `PASS`.

## Limites de détection (à lire pour une dérogation)

- Analyse **statique** : l'outil ne voit que ce qui est dans le dépôt et ce qu'il sait reconnaître.
- **Config de production** réelle (env/ConfigMap/args JVM des pods) souvent hors dépôt → `INCONCLUSIVE`.
- **Activation dynamique** (valeur calculée à l'exécution, réflexion, SPI) non résolue → `INCONCLUSIVE`.
- **Clients HTTP tiers** : gestion de `Content-Encoding` non modélisée → `INCONCLUSIVE`.
- **Versions Quarkus hors 3.33.x–3.40.x** : la règle de résolution doit être reconfirmée sur le code source
  de la version ciblée ; l'outil le signale.
- `brotli4j` **transitif** non déclaré dans `pom.xml` → version reportée « inconnue » (lancer
  `mvn dependency:tree` pour la version effective **et l'architecture native** de l'image déployée).
- Un `PASS` concerne l'**accessibilité** du décodeur, **pas** la sûreté mémoire du composant natif : il ne
  prouve pas que la corruption mémoire de la CVE est non déclenchable.

## Intégration CI

- **GitHub Actions** : voir [`.github/workflows/ci.yml`](.github/workflows/ci.yml) (tests + auto-audit).
- **GitLab CI** : voir [`.gitlab-ci.yml`](.gitlab-ci.yml).

## Tests

```bash
python tests/test_brotli_audit.py
```

16 tests (stdlib `unittest`) couvrant les 13 scénarios de référence + la priorité de résolution et le cas
« version non vérifiée ».

## Remédiation définitive

`PASS` sert à **argumenter une dérogation**, pas à clore le sujet. La correction reste la mise à jour de
`brotli4j` (et de **tous** les artefacts natifs embarqués) vers **≥ 1.24.0**, suivie d'une vérification du
**SBOM de l'image déployée**.

## Licence

[MIT](LICENSE).
